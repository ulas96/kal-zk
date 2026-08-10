package tests

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-pg/pg/v10"
	"github.com/ulas96/luima/luimaerr"

	"github.com/ulas96/kal-zk/zkauthn"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
)

func configuredZK(t *testing.T, f *zkFixture, rootGrace time.Duration,
	authorizer zkauthn.CredentialIssueAuthorizer) *zkauthn.ZK {
	t.Helper()
	service, err := zkauthn.New(zkauthn.Options{
		KnowledgeVK: f.keys.knowledgeVK, MembershipVK: f.keys.membershipVK,
		Sessions: f.sessions, Hasher: f.hasher, ProofSink: f.claims.Add, Schema: testSchema,
		RootGrace: rootGrace, MaxConcurrentVerifications: 4,
		AuthorizeCredentialIssue: authorizer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func principalContext(t *testing.T, f *zkFixture, userID string) (context.Context, string) {
	t.Helper()
	token := issueSession(t, f, userID)
	principal, err := f.sessions.Lookup(context.Background(), f.db, token)
	if err != nil {
		t.Fatal(err)
	}
	return authz.WithPrincipal(context.Background(), principal), token
}

// TestDBZKENR001IssuanceAuthorization proves nil and denied callbacks fail before touching a DB,
// while an explicit issuer role receives the operator-chosen issued_to and attribute unchanged.
// Covers: ZK-ENR-001, ZK-ENR-004
func TestDBZKENR001IssuanceAuthorization(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	verifierOnly := configuredZK(t, f, 0, nil)
	if _, err := verifierOnly.IssueCredential(ctx, nil, "person", 21); err == nil {
		t.Fatal("verifier-only service allowed credential issuance")
	} else {
		requireErrorCode(t, err, kalerr.CodeForbidden)
	}

	wantIssuedTo := createUser(t, f.db, "authorized-issuer-target@example.com")
	wantAttribute := uint64(42)
	authorizer := func(ctx context.Context, issuedTo string, attribute uint64) error {
		principal, err := authz.Require(ctx)
		if err != nil {
			return err
		}
		allowed := false
		for _, role := range principal.Roles {
			allowed = allowed || role == "credential_issuer"
		}
		if !allowed {
			return &kalerr.Error{Code: kalerr.CodeForbidden, Message: "issuer role required"}
		}
		if issuedTo != wantIssuedTo || attribute != wantAttribute {
			return fmt.Errorf("authorizer got issuedTo=%q attribute=%d", issuedTo, attribute)
		}
		return nil
	}
	service := configuredZK(t, f, 0, authorizer)
	if _, err := service.IssueCredential(ctx, nil, wantIssuedTo, wantAttribute); err == nil {
		t.Fatal("anonymous issuance reached the database")
	}
	ordinary := authz.WithPrincipal(ctx, &authz.Principal{UserID: wantIssuedTo, Roles: []string{"member"}})
	if _, err := service.IssueCredential(ordinary, nil, wantIssuedTo, wantAttribute); err == nil {
		t.Fatal("ordinary principal issuance reached the database")
	} else {
		requireErrorCode(t, err, kalerr.CodeForbidden)
	}
	issuer := authz.WithPrincipal(ctx, &authz.Principal{UserID: wantIssuedTo, Roles: []string{"credential_issuer"}})
	credential, err := service.IssueCredential(issuer, f.db, wantIssuedTo, wantAttribute)
	if err != nil {
		t.Fatal(err)
	}
	if credential.Attribute != wantAttribute {
		t.Fatalf("issued attribute = %d, want %d", credential.Attribute, wantAttribute)
	}
	var issuedTo string
	if _, err := f.db.QueryOne(pg.Scan(&issuedTo),
		`select issued_to from auth_zk_credentials where leaf_index = ?`, credential.LeafIndex); err != nil {
		t.Fatal(err)
	}
	if issuedTo != wantIssuedTo {
		t.Fatalf("stored issued_to = %s, want %s", issuedTo, wantIssuedTo)
	}
}

// TestDBZKChallengeRandomnessBindingAndRerandomization exercises independent proof randomness,
// anonymous-vs-session challenge entry points, uniqueness, and cross-session refusal.
// Covers: ZK-CHL-002, ZK-CHL-007, ZK-CHL-008, ZK-CHL-009
func TestDBZKChallengeRandomnessBindingAndRerandomization(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		challenge, err := f.zk.LoginChallenge(ctx, f.db)
		if err != nil {
			t.Fatal(err)
		}
		if seen[challenge] {
			t.Fatalf("duplicate challenge at issuance %d", i)
		}
		seen[challenge] = true
	}
	if _, err := f.zk.KnowledgeChallenge(ctx, f.db); err == nil {
		t.Fatal("knowledge challenge did not require a session")
	} else {
		requireErrorCode(t, err, kalerr.CodeUnauthenticated)
	}

	issuer := createUser(t, f.db, "challenge-rerandomize@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "rerandomized", Audience: zkauthn.NewAudience("tests", "rerandomized", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	challenge, err := f.zk.LoginChallenge(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	first, err := f.memberRequest(*credential, credential.Path, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.memberRequest(*credential, credential.Path, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Proof, second.Proof) {
		t.Fatal("two independently randomized Groth16 proofs were byte-identical")
	}
	if _, err := f.request("", func(ctx context.Context) error {
		_, err := f.zk.Login(ctx, f.db, first)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.request("", func(ctx context.Context) error {
		_, err := f.zk.Login(ctx, f.db, second)
		return err
	}); err == nil {
		t.Fatal("rerandomized proof replayed after the challenge burn")
	} else {
		requireErrorCode(t, err, kalerr.CodeInvalidProof)
	}

	userA := createUser(t, f.db, "challenge-a@example.com")
	userB := createUser(t, f.db, "challenge-b@example.com")
	ctxA, _ := principalContext(t, f, userA)
	ctxB, _ := principalContext(t, f, userB)
	secretA, err := f.zk.EnrollKnowledge(ctxA, f.db, "")
	if err != nil {
		t.Fatal(err)
	}
	bound, err := f.zk.KnowledgeChallenge(ctxA, f.db)
	if err != nil {
		t.Fatal(err)
	}
	field, _ := zkauthn.ChallengeField(bound)
	commitmentA, _ := zkauthn.KnowledgeCommitment(secretA)
	proofA, err := f.keys.knowledgePK.ProveKnowledge(zkauthn.KnowledgeWitness{
		Secret: secretA, Commitment: commitmentA, Challenge: field,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.zk.VerifyKnowledge(ctxB, f.db,
		zkauthn.KnowledgeRequest{Proof: proofA, Challenge: bound}); err == nil {
		t.Fatal("knowledge challenge transferred between sessions")
	} else {
		requireErrorCode(t, err, kalerr.CodeInvalidProof)
	}
}

// TestDBZKINP002CommitmentFromSession submits B's honest proof through A's session and asserts
// neither session is elevated, followed by A's accepting control.
// Covers: ZK-INP-002
func TestDBZKINP002CommitmentFromSession(t *testing.T) {
	f := newZKFixture(t)
	userA := createUser(t, f.db, "commitment-a@example.com")
	userB := createUser(t, f.db, "commitment-b@example.com")
	ctxA, tokenA := principalContext(t, f, userA)
	ctxB, _ := principalContext(t, f, userB)
	secretA, err := f.zk.EnrollKnowledge(ctxA, f.db, "")
	if err != nil {
		t.Fatal(err)
	}
	secretB, err := f.zk.EnrollKnowledge(ctxB, f.db, "")
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := f.zk.KnowledgeChallenge(ctxA, f.db)
	if err != nil {
		t.Fatal(err)
	}
	field, _ := zkauthn.ChallengeField(challenge)
	commitmentB, _ := zkauthn.KnowledgeCommitment(secretB)
	proofB, err := f.keys.knowledgePK.ProveKnowledge(zkauthn.KnowledgeWitness{
		Secret: secretB, Commitment: commitmentB, Challenge: field,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.zk.VerifyKnowledge(ctxA, f.db,
		zkauthn.KnowledgeRequest{Proof: proofB, Challenge: challenge}); err == nil {
		t.Fatal("A's session accepted B's commitment")
	}
	var elevated int
	if _, err := f.db.QueryOne(pg.Scan(&elevated),
		`select count(*) from auth_sessions where user_id in (?, ?) and mfa_at is not null`, userA, userB); err != nil {
		t.Fatal(err)
	}
	if elevated != 0 {
		t.Fatalf("cross-user proof elevated %d sessions", elevated)
	}

	// The wrong proof did not burn A's challenge; A can use the exact same challenge honestly.
	commitmentA, _ := zkauthn.KnowledgeCommitment(secretA)
	proofA, err := f.keys.knowledgePK.ProveKnowledge(zkauthn.KnowledgeWitness{
		Secret: secretA, Commitment: commitmentA, Challenge: field,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.request(tokenA, func(ctx context.Context) error {
		return f.zk.VerifyKnowledge(ctx, f.db, zkauthn.KnowledgeRequest{Proof: proofA, Challenge: challenge})
	}); err != nil {
		t.Fatal(err)
	}
}

// TestDBZKAUZ005ClaimsLoadOnce deletes and inserts session-claim rows after middleware entry, then
// performs 10,000 authorization checks against the snapshot.
// Covers: ZK-AUZ-005
func TestDBZKAUZ005ClaimsLoadOnce(t *testing.T) {
	f := newZKFixture(t)
	userID := createUser(t, f.db, "claims-load-once@example.com")
	ctx, _ := principalContext(t, f, userID)
	principal, _ := authz.From(ctx)
	claim := zkauthn.Claim{Name: "loaded_once", Audience: zkauthn.NewAudience("tests", "loaded-once", "v1"),
		Kind: zkauthn.ClaimRecurring}
	late := zkauthn.Claim{Name: "inserted_late", Audience: zkauthn.NewAudience("tests", "inserted-late", "v1"),
		Kind: zkauthn.ClaimRecurring}
	for _, item := range []zkauthn.Claim{claim, late} {
		if err := f.zk.EnsureClaim(context.Background(), f.db, item); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.Exec(`insert into auth_zk_session_claims (session_id, claim) values (?, ?)`,
		principal.SessionID, claim.Name); err != nil {
		t.Fatal(err)
	}

	var requestErr error
	h := f.claims.Middleware(f.db)(httpHandler(func(ctx context.Context) {
		if _, err := f.db.Exec(`delete from auth_zk_session_claims where session_id = ?`, principal.SessionID); err != nil {
			requestErr = err
			return
		}
		for i := 0; i < 10000; i++ {
			if err := f.claims.Proofs(ctx, []string{claim.Name}); err != nil {
				requestErr = fmt.Errorf("snapshot claim failed at check %d: %w", i, err)
				return
			}
		}
		if _, err := f.db.Exec(`insert into auth_zk_session_claims (session_id, claim) values (?, ?)`,
			principal.SessionID, late.Name); err != nil {
			requestErr = err
			return
		}
		if err := f.claims.Proofs(ctx, []string{late.Name}); err == nil {
			requestErr = errors.New("claim inserted after middleware entry appeared without a reload")
		}
	}))
	request := httptestRequest(ctx)
	h.ServeHTTP(request.recorder, request.request)
	if requestErr != nil {
		t.Fatal(requestErr)
	}
}

type zkHTTPCall func(context.Context)

func httpHandler(call zkHTTPCall) http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) { call(request.Context()) })
}

type zkHTTPRequest struct {
	request  *http.Request
	recorder *httptest.ResponseRecorder
}

func httptestRequest(ctx context.Context) zkHTTPRequest {
	request := httptest.NewRequest(http.MethodPost, "/graphql", nil).WithContext(ctx)
	return zkHTTPRequest{request: request, recorder: httptest.NewRecorder()}
}

// TestDBZKAUZ010ClaimsBindToSession proves two credentials can contribute distinct recurring
// claims to one session and that the conjunction is over that session, not one credential.
// Covers: ZK-AUZ-010
func TestDBZKAUZ010ClaimsBindToSession(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "session-conjunction-issuer@example.com")
	first, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.zk.IssueCredential(ctx, f.db, issuer, 7)
	if err != nil {
		t.Fatal(err)
	}
	x := zkauthn.Claim{Name: "claim_x", Audience: zkauthn.NewAudience("tests", "claim-x", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring}
	y := zkauthn.Claim{Name: "claim_y", Audience: zkauthn.NewAudience("tests", "claim-y", "v1"),
		Threshold: 7, Kind: zkauthn.ClaimRecurring}
	for _, claim := range []zkauthn.Claim{x, y} {
		if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
			t.Fatal(err)
		}
	}
	holder := createUser(t, f.db, "session-conjunction-holder@example.com")
	cookie := issueSession(t, f, holder)
	if _, err := f.request(cookie, func(ctx context.Context) error {
		if err := zkProveClaimIn(ctx, f, *first, x); err != nil {
			return err
		}
		if err := zkProveClaimIn(ctx, f, *second, y); err != nil {
			return err
		}
		return f.claims.Proofs(ctx, []string{x.Name, y.Name})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.request(cookie, func(ctx context.Context) error {
		return f.claims.Proofs(ctx, []string{x.Name, y.Name})
	}); err != nil {
		t.Fatalf("session did not retain its two-credential conjunction: %v", err)
	}
}

// TestDBZKNullifierSchemaShape reads the live PK, exercises both legal and both illegal row
// shapes, and checks claim-kind constraints through real PostgreSQL SQLSTATE values.
// Covers: ZK-NUL-003, ZK-NUL-005, ZK-NUL-006
func TestDBZKNullifierSchemaShape(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	var definition string
	if _, err := f.db.QueryOne(pg.Scan(&definition), `
		select pg_get_constraintdef(oid)
		  from pg_constraint
		 where conrelid = 'auth_zk_nullifiers'::regclass and contype = 'p'`); err != nil {
		t.Fatal(err)
	}
	if strings.ReplaceAll(definition, " ", "") != "PRIMARYKEY(nullifier)" {
		t.Fatalf("nullifier PK = %s", definition)
	}
	userID := createUser(t, f.db, "nullifier-shape@example.com")
	value := func(last byte) []byte { raw := make([]byte, 32); raw[31] = last; return raw }
	if _, err := f.db.Exec(`insert into auth_zk_nullifiers (nullifier, audience, user_id) values (?, ?, ?)`,
		value(1), value(101), userID); err != nil {
		t.Fatalf("legal recurring row: %v", err)
	}
	if _, err := f.db.Exec(`insert into auth_zk_nullifiers (nullifier, audience, consumed_at) values (?, ?, now())`,
		value(2), value(102)); err != nil {
		t.Fatalf("legal one-shot row: %v", err)
	}
	for name, query := range map[string]string{
		"neither": `insert into auth_zk_nullifiers (nullifier, audience) values (decode(repeat('03',32),'hex'), decode(repeat('67',32),'hex'))`,
		"both":    `insert into auth_zk_nullifiers (nullifier, audience, user_id, consumed_at) values (decode(repeat('04',32),'hex'), decode(repeat('68',32),'hex'), '` + userID + `'::uuid, now())`,
	} {
		if _, err := f.db.ExecContext(ctx, query); err == nil || luimaerr.SQLState(err) != "23514" {
			t.Errorf("illegal nullifier shape %s: err=%v state=%s", name, err, luimaerr.SQLState(err))
		}
	}
	if _, err := f.db.Exec(`insert into auth_zk_nullifiers (nullifier, audience, consumed_at) values (?, ?, now())`,
		value(1), value(103)); err == nil || luimaerr.SQLState(err) != "23505" {
		t.Fatalf("same nullifier under a second audience: err=%v state=%s", err, luimaerr.SQLState(err))
	}
	for i, kind := range []any{"Recurring", "oneshot", "", "one_shot ", nil} {
		_, err := f.db.Exec(`insert into auth_zk_claims (claim, audience, threshold, kind) values (?, ?, 0, ?)`,
			fmt.Sprintf("bad_kind_%d", i), value(byte(110+i)), kind)
		if err == nil || (luimaerr.SQLState(err) != "23514" && kind != nil) || (kind == nil && luimaerr.SQLState(err) != "23502") {
			t.Errorf("claim kind %#v: err=%v state=%s", kind, err, luimaerr.SQLState(err))
		}
	}
}

// TestDBZKSQL005Classification drives real unique/input violations through operator APIs and
// verifies an unrelated infrastructure error remains unclassified.
// Covers: ZK-SQL-005
func TestDBZKSQL005Classification(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	audience := zkauthn.NewAudience("tests", "classification", "v1")
	if err := f.zk.EnsureClaim(ctx, f.db, zkauthn.Claim{
		Name: "classification_a", Audience: audience, Kind: zkauthn.ClaimRecurring,
	}); err != nil {
		t.Fatal(err)
	}
	err := f.zk.EnsureClaim(ctx, f.db, zkauthn.Claim{
		Name: "classification_b", Audience: audience, Kind: zkauthn.ClaimRecurring,
	})
	requireErrorCode(t, err, kalerr.CodeConflict)

	if _, err := f.zk.IssueCredential(ctx, f.db, "not-a-uuid", 21); err == nil {
		t.Fatal("invalid issued_to was accepted")
	} else {
		requireErrorCode(t, err, kalerr.CodeInvalidInput)
	}
	var rows int
	if _, err := f.db.QueryOne(pg.Scan(&rows), `select count(*) from auth_zk_credentials`); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("invalid issuance left %d credential rows", rows)
	}
	if _, err := f.zk.IssueCredential(ctx, noTxDB{f.db}, "", 21); err == nil {
		t.Fatal("database handle without transactions was accepted")
	} else {
		var typed *kalerr.Error
		if errors.As(err, &typed) {
			t.Fatalf("unrelated infrastructure failure was classified as %s", typed.Code)
		}
	}
}

// TestDBZKSQL006Cascades exercises the live foreign keys: credentials survive user deletion with
// issued_to cleared, nullifiers cascade, and the orphaned leaf remains revocable by index.
// Covers: ZK-SQL-006
func TestDBZKSQL006Cascades(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	userID := createUser(t, f.db, "cascade-owner@example.com")
	otherID := createUser(t, f.db, "cascade-other@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, userID, 21)
	if err != nil {
		t.Fatal(err)
	}
	nullifier := bytes.Repeat([]byte{0x31}, 32)
	audience := bytes.Repeat([]byte{0x41}, 32)
	if _, err := f.db.Exec(`insert into auth_zk_nullifiers (nullifier, audience, user_id) values (?, ?, ?)`,
		nullifier, audience, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`delete from auth_users where id = ?`, userID); err != nil {
		t.Fatal(err)
	}
	var credentialRows, nullifierRows, otherRows int
	if _, err := f.db.QueryOne(pg.Scan(&credentialRows),
		`select count(*) from auth_zk_credentials where leaf_index = ? and issued_to is null`, credential.LeafIndex); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.QueryOne(pg.Scan(&nullifierRows),
		`select count(*) from auth_zk_nullifiers where nullifier = ?`, nullifier); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.QueryOne(pg.Scan(&otherRows), `select count(*) from auth_users where id = ?`, otherID); err != nil {
		t.Fatal(err)
	}
	if credentialRows != 1 || nullifierRows != 0 || otherRows != 1 {
		t.Fatalf("cascade state credential=%d nullifier=%d unrelated=%d", credentialRows, nullifierRows, otherRows)
	}
	if err := f.zk.RevokeCredential(ctx, f.db, credential.LeafIndex); err != nil {
		t.Fatalf("orphaned credential was not revocable by leaf index: %v", err)
	}
}

// TestDBZKTREE002003LockDiscipline pins statement order in source and checks that lock keys are
// stable within a schema and distinct across two schemas in the same database.
// Covers: ZK-TRE-002, ZK-TRE-003
func TestDBZKTREE002003LockDiscipline(t *testing.T) {
	f := newZKFixture(t)
	source := readRepositoryFile(t, "zkauthn", "tree.go")
	lockAt := strings.Index(source, "z.sql.lockTree")
	readAt := strings.Index(source, "z.sql.nextLeaf")
	if lockAt < 0 || readAt < 0 || lockAt > readAt {
		t.Fatalf("issuance order lock=%d first-read=%d", lockAt, readAt)
	}
	sqlSource := readRepositoryFile(t, "zkauthn", "sql.go")
	for _, required := range []string{"pg_advisory_xact_lock", "hashtextextended", "github.com/ulas96/kal-zk/zkauthn/tree|", "current_schema()"} {
		if !strings.Contains(sqlSource, required) {
			t.Errorf("lock SQL lacks namespace component %q", required)
		}
	}
	var first, same, other int64
	namespace := "github.com/ulas96/kal-zk/zkauthn/tree|"
	if _, err := f.db.QueryOne(pg.Scan(&first, &same, &other),
		`select hashtextextended(? || ?, 0), hashtextextended(? || ?, 0), hashtextextended(? || ?, 0)`,
		namespace, "schema_a", namespace, "schema_a", namespace, "schema_b"); err != nil {
		t.Fatal(err)
	}
	if first != same || first == other {
		t.Fatalf("namespaced lock keys first=%d same=%d other=%d", first, same, other)
	}
}

// TestDBZKTREE008GraceCloses accepts a genuine retired root inside a short configured grace and
// refuses a fresh proof against that same root after the window.
// Covers: ZK-TRE-008
func TestDBZKTREE008GraceCloses(t *testing.T) {
	f := newZKFixture(t)
	const grace = 30 * time.Second
	service := configuredZK(t, f, grace,
		func(context.Context, string, uint64) error { return nil })
	ctx := context.Background()
	issuer := createUser(t, f.db, "root-grace@example.com")
	first, err := service.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := first.Path
	if _, err := service.IssueCredential(ctx, f.db, issuer, 22); err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "root_grace", Audience: zkauthn.NewAudience("tests", "root-grace", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := service.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	challenge, _ := service.LoginChallenge(ctx, f.db)
	req, err := f.memberRequest(*first, oldPath, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.request("", func(requestCtx context.Context) error {
		_, loginErr := service.Login(requestCtx, f.db, req)
		return loginErr
	}); err != nil {
		t.Fatalf("retired root inside grace was refused: %v", err)
	}
	// Move the database timestamp beyond the boundary instead of sleeping. Under -race, proof
	// generation can itself take longer than a one-second grace, making the "inside" assertion
	// scheduler-dependent rather than a test of rootAccepted.
	if _, err := f.db.Exec(`update auth_zk_roots
		set retired_at = now() - make_interval(secs => ?)
		where root = ?`, grace.Seconds()+1, oldPath.Root[:]); err != nil {
		t.Fatal(err)
	}
	challenge, _ = service.LoginChallenge(ctx, f.db)
	req, err = f.memberRequest(*first, oldPath, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.request("", func(requestCtx context.Context) error {
		_, loginErr := service.Login(requestCtx, f.db, req)
		return loginErr
	}); err == nil {
		t.Fatal("retired root remained accepted after grace")
	} else {
		requireErrorCode(t, err, kalerr.CodeInvalidProof)
	}
}

type tableCounts struct{ users, sessions, nullifiers int }

func zkTableCounts(t *testing.T, f *zkFixture) tableCounts {
	t.Helper()
	var out tableCounts
	for query, target := range map[string]*int{
		`select count(*) from auth_users`:         &out.users,
		`select count(*) from auth_sessions`:      &out.sessions,
		`select count(*) from auth_zk_nullifiers`: &out.nullifiers,
	} {
		if _, err := f.db.QueryOne(pg.Scan(target), query); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// TestDBZKORCUniformFailures compares malformed input, unknown claims, retired roots and wrong
// proofs by public code/message and by database side effects.
// Covers: ZK-ORC-001, ZK-ORC-003, ZK-ORC-004, ZK-ORC-006, ZK-ORC-007
func TestDBZKORCUniformFailures(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "uniform-oracle@example.com")
	first, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := first.Path
	second, err := f.zk.IssueCredential(ctx, f.db, issuer, 22)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "uniform_failure", Audience: zkauthn.NewAudience("tests", "uniform", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	challenge, _ := f.zk.LoginChallenge(ctx, f.db)
	current, err := f.memberRequest(*second, second.Path, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	retiredChallenge, _ := f.zk.LoginChallenge(ctx, f.db)
	retired, err := f.memberRequest(*first, oldPath, claim, retiredChallenge)
	if err != nil {
		t.Fatal(err)
	}
	unknown := current
	unknown.Claim = "unknown_claim"
	wrongProof := current
	wrongProof.Proof = bytes.Clone(current.Proof)
	wrongProof.Proof[0] ^= 0xff
	badRoot := current
	badRoot.Root = badRoot.Root[:31]
	badNullifier := current
	badNullifier.Nullifier = badNullifier.Nullifier[:31]
	badChallenge := current
	badChallenge.Challenge = strings.Repeat("x", 1<<20)
	badLength := current
	badLength.Proof = make([]byte, 1<<20)

	cases := map[string]zkauthn.MembershipRequest{
		"unknown claim": unknown, "retired root": retired, "wrong proof": wrongProof,
		"short root": badRoot, "short nullifier": badNullifier,
		"oversized challenge": badChallenge, "oversized proof": badLength,
	}
	baseline := zkTableCounts(t, f)
	wantMessage := ""
	for name, request := range cases {
		_, err := f.zk.Login(ctx, f.db, request)
		var typed *kalerr.Error
		if !errors.As(err, &typed) || typed.Code != kalerr.CodeInvalidProof {
			t.Errorf("%s: error=%v, want INVALID_PROOF", name, err)
			continue
		}
		if wantMessage == "" {
			wantMessage = typed.Message
		}
		presented := kalerr.PresentError(ctx, err)
		if typed.Message != wantMessage || presented.Message != wantMessage ||
			presented.Extensions["code"] != kalerr.CodeInvalidProof {
			t.Errorf("%s exposed distinct public detail: typed=%q presented=%q code=%v want=%q",
				name, typed.Message, presented.Message, presented.Extensions["code"], wantMessage)
		}
		if after := zkTableCounts(t, f); after != baseline {
			t.Errorf("%s changed state: before=%+v after=%+v", name, baseline, after)
		}
	}
}

// TestDBZKPSD002ConcurrentFirstSight drives eight valid first logins for one recurring pseudonym
// and requires all eight sessions to converge on one account and one nullifier row.
// Covers: ZK-PSD-002
func TestDBZKPSD002ConcurrentFirstSight(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "concurrent-pseudonym@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "concurrent_pseudonym", Audience: zkauthn.NewAudience("tests", "concurrent-pseudonym", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	const callers = 8
	requests := make([]zkauthn.MembershipRequest, callers)
	for i := range callers {
		challenge, err := f.zk.LoginChallenge(ctx, f.db)
		if err != nil {
			t.Fatal(err)
		}
		requests[i], err = f.memberRequest(*credential, credential.Path, claim, challenge)
		if err != nil {
			t.Fatal(err)
		}
	}
	var ready, start, done sync.WaitGroup
	ready.Add(callers)
	start.Add(1)
	done.Add(callers)
	principals := make([]*authz.Principal, callers)
	errs := make([]error, callers)
	for i := range callers {
		go func() {
			defer done.Done()
			ready.Done()
			start.Wait()
			_, errs[i] = f.request("", func(ctx context.Context) error {
				principals[i], errs[i] = f.zk.Login(ctx, f.db, requests[i])
				return errs[i]
			})
		}()
	}
	ready.Wait()
	start.Done()
	done.Wait()
	for i, err := range errs {
		if err != nil || principals[i] == nil {
			t.Fatalf("caller %d principal=%+v error=%v", i, principals[i], err)
		}
		if principals[i].UserID != principals[0].UserID {
			t.Errorf("caller %d user=%s, want %s", i, principals[i].UserID, principals[0].UserID)
		}
	}
	var pseudonyms, nullifiers int
	if _, err := f.db.QueryOne(pg.Scan(&pseudonyms), `select count(*) from auth_users where email like 'zk-%@invalid'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.QueryOne(pg.Scan(&nullifiers), `select count(*) from auth_zk_nullifiers`); err != nil {
		t.Fatal(err)
	}
	if pseudonyms != 1 || nullifiers != 1 {
		t.Fatalf("concurrent first sight pseudonyms=%d nullifiers=%d", pseudonyms, nullifiers)
	}
}

// TestDBZKPSD004PseudonymAccountShape asserts the generated account is an unverified, passwordless
// ordinary account and that login created no recovery/verification token.
// Covers: ZK-PSD-004
func TestDBZKPSD004PseudonymAccountShape(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "pseudonym-shape-issuer@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "pseudonym_shape", Audience: zkauthn.NewAudience("tests", "pseudonym-shape", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	challenge, _ := f.zk.LoginChallenge(ctx, f.db)
	req, _ := f.memberRequest(*credential, credential.Path, claim, challenge)
	var principal *authz.Principal
	if _, err := f.request("", func(ctx context.Context) error {
		principal, err = f.zk.Login(ctx, f.db, req)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if principal == nil {
		t.Fatal("login returned no pseudonym principal")
	}
	var passwordNil, verified bool
	var email string
	if _, err := f.db.QueryOne(pg.Scan(&email, &passwordNil, &verified),
		`select email, password_hash is null, email_verified from auth_users where id = ?`, principal.UserID); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(email, "@invalid") || !passwordNil || verified {
		t.Fatalf("pseudonym email=%s password_null=%v verified=%v", email, passwordNil, verified)
	}
	var tokens int
	if _, err := f.db.QueryOne(pg.Scan(&tokens), `select count(*) from auth_tokens where user_id = ?`, principal.UserID); err != nil {
		t.Fatal(err)
	}
	if tokens != 0 {
		t.Fatalf("pseudonym login created %d recovery tokens", tokens)
	}
}

// TestDBZKNUL004AudienceUnlinkability logs one credential into two audiences and requires two
// nullifiers with no schema link and two distinct pseudonymous accounts.
// Covers: ZK-NUL-004
func TestDBZKNUL004AudienceUnlinkability(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "unlinkability-issuer@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	claims := []zkauthn.Claim{
		{Name: "audience_x", Audience: zkauthn.NewAudience("tests", "audience-x", "v1"), Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true},
		{Name: "audience_y", Audience: zkauthn.NewAudience("tests", "audience-y", "v1"), Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true},
	}
	principals := make([]*authz.Principal, len(claims))
	for i, claim := range claims {
		if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
			t.Fatal(err)
		}
		challenge, _ := f.zk.LoginChallenge(ctx, f.db)
		req, err := f.memberRequest(*credential, credential.Path, claim, challenge)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.request("", func(ctx context.Context) error {
			principals[i], err = f.zk.Login(ctx, f.db, req)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if principals[0].UserID == principals[1].UserID {
		t.Fatal("two audiences resolved to one global pseudonym")
	}
	firstNullifier, _ := zkauthn.Nullifier(credential.Secret, claims[0].Audience)
	secondNullifier, _ := zkauthn.Nullifier(credential.Secret, claims[1].Audience)
	if firstNullifier == secondNullifier {
		t.Fatal("two audiences produced one nullifier")
	}
	var columns []string
	if _, err := f.db.QueryOne(pg.Scan(pg.Array(&columns)), `
		select array_agg(column_name order by ordinal_position)
		  from information_schema.columns
		 where table_schema = ? and table_name = 'auth_zk_nullifiers'`, testSchema); err != nil {
		t.Fatal(err)
	}
	for _, linking := range []string{"credential_id", "leaf_index", "commitment", "issued_to"} {
		for _, column := range columns {
			if column == linking {
				t.Errorf("nullifier rows gain a cross-audience link through %s", linking)
			}
		}
	}
}

// TestDBZKNUL007EpochRateLimit proves one action per credential per server-derived epoch and a new,
// unlinkable one-shot row in the next epoch.
// Covers: ZK-NUL-007
func TestDBZKNUL007EpochRateLimit(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "epoch-issuer@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	epochs := []zkauthn.Claim{
		{Name: "vote_2026", Audience: zkauthn.NewAudience("tests", "vote", "2026"), Kind: zkauthn.ClaimOneShot},
		{Name: "vote_2027", Audience: zkauthn.NewAudience("tests", "vote", "2027"), Kind: zkauthn.ClaimOneShot},
	}
	for _, claim := range epochs {
		if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
			t.Fatal(err)
		}
	}
	holder := createUser(t, f.db, "epoch-holder@example.com")
	cookie := issueSession(t, f, holder)
	act := func(claim zkauthn.Claim) error {
		_, err := f.request(cookie, func(ctx context.Context) error {
			return zkProveClaimIn(ctx, f, *credential, claim)
		})
		return err
	}
	if err := act(epochs[0]); err != nil {
		t.Fatal(err)
	}
	if err := act(epochs[0]); err == nil {
		t.Fatal("second action in one epoch succeeded")
	} else {
		requireErrorCode(t, err, kalerr.CodeInvalidProof)
	}
	if err := act(epochs[1]); err != nil {
		t.Fatal(err)
	}
	var rows, linked int
	if _, err := f.db.QueryOne(pg.Scan(&rows, &linked), `
		select count(*), count(user_id) from auth_zk_nullifiers where consumed_at is not null`); err != nil {
		t.Fatal(err)
	}
	if rows != 2 || linked != 0 {
		t.Fatalf("epoch one-shot rows=%d linked=%d", rows, linked)
	}
}

// TestDBZKPSD006ReissueChangesPseudonym records the recovery tradeoff: revoke/reissue creates a new
// secret, nullifier and account while the old account remains distinct.
// Covers: ZK-PSD-006
func TestDBZKPSD006ReissueChangesPseudonym(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	issuer := createUser(t, f.db, "reissue-issuer@example.com")
	claim := zkauthn.Claim{Name: "reissue", Audience: zkauthn.NewAudience("tests", "reissue", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	login := func(credential *zkauthn.Credential) *authz.Principal {
		challenge, _ := f.zk.LoginChallenge(ctx, f.db)
		path, err := f.zk.Path(ctx, f.db, credential.LeafIndex)
		if err != nil {
			t.Fatal(err)
		}
		req, err := f.memberRequest(*credential, *path, claim, challenge)
		if err != nil {
			t.Fatal(err)
		}
		var principal *authz.Principal
		if _, err := f.request("", func(ctx context.Context) error {
			principal, err = f.zk.Login(ctx, f.db, req)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return principal
	}
	first, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	oldPrincipal := login(first)
	if err := f.zk.RevokeCredential(ctx, f.db, first.LeafIndex); err != nil {
		t.Fatal(err)
	}
	second, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	newPrincipal := login(second)
	if oldPrincipal.UserID == newPrincipal.UserID || first.Secret == second.Secret {
		t.Fatalf("reissue old_user=%s new_user=%s same_secret=%v",
			oldPrincipal.UserID, newPrincipal.UserID, first.Secret == second.Secret)
	}
	var oldStillExists int
	if _, err := f.db.QueryOne(pg.Scan(&oldStillExists), `select count(*) from auth_users where id = ?`, oldPrincipal.UserID); err != nil {
		t.Fatal(err)
	}
	if oldStillExists != 1 {
		t.Fatal("reissue implicitly merged or removed the old pseudonym")
	}
}
