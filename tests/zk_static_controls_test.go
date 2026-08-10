package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ulas96/kal-zk/zkauthn"
	"github.com/ulas96/kal-zk/zkauthz"
	"github.com/ulas96/kal/authn"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/migrations"
	"github.com/ulas96/kal/session"
)

func bareZK(t *testing.T, schema string, authorizer zkauthn.CredentialIssueAuthorizer) *zkauthn.ZK {
	t.Helper()
	keys := testZKArtifacts(t)
	sessions, err := session.NewSessions(session.Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := zkauthz.New(schema)
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := authn.NewHasher(authn.Params{Memory: 8192, Time: 1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	service, err := zkauthn.New(zkauthn.Options{
		KnowledgeVK: keys.knowledgeVK, MembershipVK: keys.membershipVK,
		Sessions: sessions, Hasher: hasher, ProofSink: claims.Add, Schema: schema,
		AuthorizeCredentialIssue: authorizer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// TestZKPublicInputSurface pins every attacker-controlled request field by name and type, while
// expression-shaped claim names fail as opaque lookup keys rather than becoming policy syntax.
// Covers: ZK-INP-005, ZK-AUZ-013
func TestZKPublicInputSurface(t *testing.T) {
	enroll := reflect.TypeOf((*zkauthn.ZK).EnrollKnowledge)
	if enroll.NumIn() != 4 || enroll.IsVariadic() {
		t.Fatalf("EnrollKnowledge signature = %s; a caller-controlled user id must not exist", enroll)
	}
	type fieldPin struct {
		name   string
		typeOf reflect.Type
	}
	pins := map[reflect.Type][]fieldPin{
		reflect.TypeOf(zkauthn.MembershipRequest{}): {
			{"Proof", reflect.TypeOf([]byte{})}, {"Root", reflect.TypeOf([]byte{})},
			{"Nullifier", reflect.TypeOf([]byte{})}, {"Challenge", reflect.TypeOf("")},
			{"Claim", reflect.TypeOf("")},
		},
		reflect.TypeOf(zkauthn.KnowledgeRequest{}): {
			{"Proof", reflect.TypeOf([]byte{})}, {"Challenge", reflect.TypeOf("")},
		},
	}
	for typ, want := range pins {
		if typ.NumField() != len(want) {
			t.Fatalf("%s fields = %d, want %d", typ, typ.NumField(), len(want))
		}
		for i, pin := range want {
			field := typ.Field(i)
			if field.Name != pin.name || field.Type != pin.typeOf {
				t.Errorf("%s field %d = %s %s, want %s %s", typ, i,
					field.Name, field.Type, pin.name, pin.typeOf)
			}
		}
	}
	for _, forbidden := range []string{"Threshold", "Audience", "Commitment", "PublicInputs"} {
		if _, ok := reflect.TypeOf(zkauthn.MembershipRequest{}).FieldByName(forbidden); ok {
			t.Errorf("MembershipRequest exposes server-owned %s", forbidden)
		}
	}
	if _, ok := reflect.TypeOf(&zkauthn.ZK{}).MethodByName("EnrollKnowledgeForUser"); ok {
		t.Fatal("knowledge enrolment exposes a caller-selected user")
	}
	enrollSource := readRepositoryFile(t, "zkauthn", "protocol.go")
	if strings.Contains(enrollSource, "EnrollKnowledgeForUser") {
		t.Fatal("knowledge enrolment source exposes a caller-selected user")
	}
	service := bareZK(t, "", nil)
	for _, name := range []string{"age>18", "age<18", "age=18", "age>=18"} {
		err := service.EnsureClaim(context.Background(), nil, zkauthn.Claim{
			Name: name, Kind: zkauthn.ClaimRecurring,
		})
		if err == nil {
			t.Errorf("expression-shaped claim %q was accepted", name)
		}
	}
}

// TestZKINP006EarlyShapesAndDeploymentBinding supplies oversized/malformed request fields to a
// service with no database, proving shape rejection occurs first, then pins deployment audiences.
// Covers: ZK-INP-006, ZK-NUL-008
func TestZKINP006EarlyShapesAndDeploymentBinding(t *testing.T) {
	service := bareZK(t, "", nil)
	honest := testZKHonestProofs(t)
	validField := make([]byte, 32)
	cases := map[string]zkauthn.MembershipRequest{
		"proof empty":     {Proof: nil, Root: validField, Nullifier: validField, Claim: "known"},
		"proof huge":      {Proof: make([]byte, 64<<20), Root: validField, Nullifier: validField, Claim: "known"},
		"root short":      {Proof: honest.membershipProof, Root: make([]byte, 31), Nullifier: validField, Claim: "known"},
		"root huge":       {Proof: honest.membershipProof, Root: make([]byte, 1<<20), Nullifier: validField, Claim: "known"},
		"nullifier short": {Proof: honest.membershipProof, Root: validField, Nullifier: make([]byte, 31), Claim: "known"},
		"claim huge":      {Proof: honest.membershipProof, Root: validField, Nullifier: validField, Claim: strings.Repeat("x", 1<<20)},
		"claim non-utf8":  {Proof: honest.membershipProof, Root: validField, Nullifier: validField, Claim: string([]byte{0xff})},
	}
	for name, request := range cases {
		if _, err := service.Login(context.Background(), nil, request); err == nil {
			t.Errorf("%s reached the nil database", name)
		} else {
			var typed *kalerr.Error
			if !errors.As(err, &typed) || typed.Code != kalerr.CodeInvalidProof {
				t.Errorf("%s error=%v, want INVALID_PROOF", name, err)
			}
		}
	}
	keys := testZKArtifacts(t)
	if err := keys.membershipVK.VerifyMembership(honest.membershipProof, honest.membershipPublic); err != nil {
		t.Fatal(err)
	}
	deploymentB := honest.membershipPublic
	deploymentB.Audience = zkauthn.NewAudience("a-different-deployment", "membership-proof", "v1")
	if err := keys.membershipVK.VerifyMembership(honest.membershipProof, deploymentB); err == nil {
		t.Fatal("membership proof crossed deployment-bound audiences")
	}
}

// TestZKDOS003ProofFraming rejects every wrong length before parsing with work independent of blob
// size, then verifies the genuine fixed-length control.
// Covers: ZK-DOS-003
func TestZKDOS003ProofFraming(t *testing.T) {
	proofSource := readRepositoryFile(t, "zkauthn", "proof.go")
	if strings.Count(proofSource, "if len(raw) != CompressedProofSize {") != 1 {
		t.Fatal("proof parser does not have one exact-length guard before deserialization")
	}
	if strings.Index(proofSource, "if len(raw) != CompressedProofSize {") > strings.Index(proofSource, "proof.ReadFrom") {
		t.Fatal("proof framing guard runs after deserialization")
	}
	keys := testZKArtifacts(t)
	honest := testZKHonestProofs(t)
	if zkauthn.ProofSize() != zkauthn.CompressedProofSize || len(honest.knowledgeProof) != zkauthn.CompressedProofSize {
		t.Fatalf("proof framing accessor=%d constant=%d actual=%d", zkauthn.ProofSize(),
			zkauthn.CompressedProofSize, len(honest.knowledgeProof))
	}
	if err := keys.knowledgeVK.VerifyKnowledge(honest.knowledgeProof,
		honest.knowledgeCommitment, honest.knowledgeChallenge); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1, zkauthn.CompressedProofSize - 1,
		zkauthn.CompressedProofSize + 1, 1 << 20, 64 << 20} {
		blob := make([]byte, size)
		start := time.Now()
		if err := keys.knowledgeVK.VerifyKnowledge(blob,
			honest.knowledgeCommitment, honest.knowledgeChallenge); err == nil {
			t.Errorf("proof length %d was accepted", size)
		}
		if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
			t.Errorf("proof length %d took %v to reject before parsing", size, elapsed)
		}
	}
}

// TestZKKEY001RepositoryArtifacts scans both the worktree and complete git object-name history for
// ceremony artifacts. CI checks out full history so a deleted key cannot disappear from this gate.
// Covers: ZK-KEY-001
func TestZKKEY001RepositoryArtifacts(t *testing.T) {
	root := repositoryRoot(t)
	forbidden := regexp.MustCompile(`(?i)(^|[._-])(proving|verifying)?[._-]?(key|pk|vk)|\.(r1cs|proof|ptau|zkey|pk|vk)$`)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "vendor") {
			return filepath.SkipDir
		}
		if !entry.IsDir() && forbidden.MatchString(filepath.ToSlash(path)) {
			t.Errorf("ceremony-shaped artifact in worktree: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("git", "log", "--all", "--name-only", "--pretty=format:")
	command.Dir = root
	raw, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range strings.Fields(string(raw)) {
		if forbidden.MatchString(name) {
			t.Errorf("ceremony-shaped artifact in git history: %s", name)
		}
	}
}

// TestZKKEY005SafeDeserialization pins safe ReadFrom use and rejects correct-length off-curve and
// degenerate encodings without a panic while the honest control verifies.
// Covers: ZK-KEY-005
func TestZKKEY005SafeDeserialization(t *testing.T) {
	root := repositoryRoot(t)
	keySource := readRepositoryFile(t, "zkauthn", "keys.go")
	hashCheck := strings.Index(keySource, "if !bytes.Equal(got[:], wantSHA256)")
	parseStart := strings.Index(keySource, "groth16.NewVerifyingKey")
	if hashCheck < 0 || parseStart < 0 || hashCheck > parseStart {
		t.Fatal("verifying-key bytes are parsed before their pinned hash is accepted")
	}
	for _, pkg := range []string{"zkauthn", "zkauthz", "tests"} {
		files, err := filepath.Glob(filepath.Join(root, pkg, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range files {
			if filepath.Base(name) == "zk_case_manifest_test.go" {
				continue // coverage prose names the forbidden API; executable helpers may not use it.
			}
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			unsafeName := "Unsafe" + "ReadFrom"
			if strings.Contains(string(raw), unsafeName) {
				t.Errorf("unsafe group-element parser referenced by %s", name)
			}
		}
	}
	keys := testZKArtifacts(t)
	honest := testZKHonestProofs(t)
	if err := keys.knowledgeVK.VerifyKnowledge(honest.knowledgeProof,
		honest.knowledgeCommitment, honest.knowledgeChallenge); err != nil {
		t.Fatal(err)
	}
	malformed := [][]byte{
		make([]byte, zkauthn.CompressedProofSize),
		bytes.Repeat([]byte{0xff}, zkauthn.CompressedProofSize),
		append(bytes.Repeat([]byte{0xff}, 32), honest.knowledgeProof[32:]...),
	}
	for i, proof := range malformed {
		if err := keys.knowledgeVK.VerifyKnowledge(proof,
			honest.knowledgeCommitment, honest.knowledgeChallenge); err == nil {
			t.Errorf("malformed proof encoding %d verified", i)
		}
	}
}

// TestZKKEY007IndependentCeremonies proves setup is randomized, its artifacts are not
// interchangeable, and verification requires no proving key.
// Covers: ZK-KEY-007, ZK-KEY-008
func TestZKKEY007IndependentCeremonies(t *testing.T) {
	first := testZKArtifacts(t)
	var pkRaw, vkRaw bytes.Buffer
	if err := zkauthn.Setup(zkauthn.CircuitKnowledge, &pkRaw, &vkRaw); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.knowledgeRaw, vkRaw.Bytes()) {
		t.Fatal("two setup ceremonies emitted the same verifying key")
	}
	secondPK, err := zkauthn.LoadProvingKey(zkauthn.CircuitKnowledge, bytes.NewReader(pkRaw.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	secondHash := sha256.Sum256(vkRaw.Bytes())
	secondVK, err := zkauthn.LoadVerifyingKey(zkauthn.CircuitKnowledge,
		bytes.NewReader(vkRaw.Bytes()), secondHash[:])
	if err != nil {
		t.Fatal(err)
	}
	secret := zkauthn.Secret{7, 8, 9}
	commitment, _ := zkauthn.KnowledgeCommitment(secret)
	challenge := zkauthn.NewAudience("ceremony", "challenge", "v1")
	proof, err := secondPK.ProveKnowledge(zkauthn.KnowledgeWitness{
		Secret: secret, Commitment: commitment, Challenge: challenge,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := secondVK.VerifyKnowledge(proof, commitment, challenge); err != nil {
		t.Fatalf("same-ceremony proof failed: %v", err)
	}
	if err := first.knowledgeVK.VerifyKnowledge(proof, commitment, challenge); err == nil {
		t.Fatal("proof crossed independent setup ceremonies")
	}
	setupType := reflect.TypeOf(zkauthn.Setup)
	if setupType.NumIn() != 3 || setupType.In(1).String() != "io.Writer" || setupType.In(2).String() != "io.Writer" {
		t.Fatalf("Setup signature = %s; expected circuit and two writers with no seed source", setupType)
	}
}

// TestZKR1CSFingerprintProcess repeats the compiled identity in a fresh test process. CI runs this
// on every supported Go/Postgres job and release-check compares the emitted pins.
// Covers: ZK-KEY-004
func TestZKR1CSFingerprintProcess(t *testing.T) {
	if os.Getenv("KAL_ZK_FINGERPRINT_HELPER") == "1" {
		for _, kind := range []zkauthn.Circuit{zkauthn.CircuitKnowledge, zkauthn.CircuitMembership} {
			n, id, err := zkauthn.CircuitInfo(kind)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("FINGERPRINT %s %d %x", kind, n, id)
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestZKR1CSFingerprintProcess$", "-test.v")
	command.Env = append(os.Environ(), "KAL_ZK_FINGERPRINT_HELPER=1")
	raw, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fingerprint subprocess: %v\n%s", err, raw)
	}
	for _, expected := range []string{zkauthn.KnowledgeCircuitID, zkauthn.MembershipCircuitID} {
		if !strings.Contains(string(raw), expected) {
			t.Errorf("subprocess omitted R1CS identity %s:\n%s", expected, raw)
		}
	}
	t.Logf("toolchain=%s fingerprints=%s,%s", runtime.Version(),
		zkauthn.KnowledgeCircuitID, zkauthn.MembershipCircuitID)
}

// TestZKRepositorySecurityControls pins migration isolation, schema validation, SQL locality,
// absence of request-side proving, per-replica documentation, and reasoned audit suppressions.
// Covers: ZK-SQL-001, ZK-SQL-003, ZK-SQL-004, ZK-SQL-007, ZK-SQL-008, ZK-DOS-005, ZK-DOS-006, ZK-KEY-009, ZK-KEY-010, ZK-INV-008
func TestZKRepositorySecurityControls(t *testing.T) {
	migration, err := migrations.FS.ReadFile("0002_zk.sql")
	if err != nil {
		t.Fatal(err)
	}
	lowerMigration := strings.ToLower(string(migration))
	if strings.Contains(lowerMigration, "alter table auth_users") || strings.Contains(lowerMigration, "alter table auth_sessions") {
		t.Fatal("0002_zk.sql alters a core table")
	}
	for _, required := range []string{"create table auth_zk_commitments", "create table auth_zk_nullifiers"} {
		if !strings.Contains(lowerMigration, required) {
			t.Errorf("0002_zk.sql lacks %q", required)
		}
	}
	files := migrations.Files()
	if len(files) < 4 || files[0] != "0001_core.sql" || files[1] != "0002_zk.sql" || files[len(files)-1] != "0004_zk_hardening.sql" {
		t.Fatalf("migration order = %v", files)
	}

	for _, invalid := range []string{"Public", `x\";drop_table`, "pg.catalog", "a-b", strings.Repeat("a", 200)} {
		keys := testZKArtifacts(t)
		sessions, _ := session.NewSessions(session.Options{})
		claims, _ := zkauthz.New("")
		hasher, _ := authn.NewHasher(authn.Params{Memory: 8192, Time: 1}, 0)
		if _, err := zkauthn.New(zkauthn.Options{KnowledgeVK: keys.knowledgeVK,
			MembershipVK: keys.membershipVK, Sessions: sessions, Hasher: hasher,
			ProofSink: claims.Add, Schema: invalid}); err == nil {
			t.Errorf("invalid schema %q accepted", invalid)
		}
		if _, err := zkauthz.New(invalid); err == nil {
			t.Errorf("zkauthz accepted invalid schema %q", invalid)
		}
	}

	root := repositoryRoot(t)
	for _, pkg := range []string{"zkauthn", "zkauthz"} {
		entries, err := os.ReadDir(filepath.Join(root, pkg))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || entry.Name() == "sql.go" {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(root, pkg, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if regexp.MustCompile(`(?i)\b(select|insert into|update|delete from|alter table)\s+auth_`).Match(raw) {
				t.Errorf("SQL statement outside %s/sql.go: %s", pkg, entry.Name())
			}
		}
	}
	protocol := readRepositoryFile(t, "zkauthn", "protocol.go") + readRepositoryFile(t, "zkauthn", "service.go")
	if strings.Contains(protocol, "groth16.Prove") {
		t.Fatal("a request-side service path invokes server-side proving")
	}
	allProduction := protocol + readRepositoryFile(t, "zkauthn", "tree.go") +
		readRepositoryFile(t, "zkauthn", "sql.go") + readRepositoryFile(t, "zkauthz", "zkauthz.go")
	if strings.Contains(allProduction, "pg.Connect(") {
		t.Fatal("ZK opened a privileged/separate pool instead of using the caller's RLS-subject DB")
	}
	serviceSource := readRepositoryFile(t, "zkauthn", "service.go")
	for _, phrase := range []string{"per-replica", "shared limiter"} {
		if !strings.Contains(serviceSource, phrase) {
			t.Errorf("verification bound documentation lacks %q", phrase)
		}
	}
	sqlSource := readRepositoryFile(t, "zkauthn", "sql.go")
	if strings.Count(sqlSource, "and expires_at > now()") != 2 {
		t.Fatal("both challenge peek and atomic consume must enforce expiry")
	}
	makefile := readRepositoryFile(t, "Makefile")
	for _, target := range []string{"bench-zk:", "audit:", "govulncheck", "gosec"} {
		if !strings.Contains(makefile, target) {
			t.Errorf("Makefile lacks %q", target)
		}
	}
	for _, file := range []string{"CHANGELOG.md", "SECURITY.md"} {
		if !strings.Contains(readRepositoryFile(t, file), "[Unreleased]") && file == "CHANGELOG.md" {
			t.Error("CHANGELOG.md lacks [Unreleased]")
		}
	}
	for _, name := range []string{"zkauthn", "zkauthz", "tests"} {
		suppression := "#no" + "sec"
		_ = filepath.WalkDir(filepath.Join(root, name), func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || filepath.Ext(path) != ".go" {
				return err
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.Contains(line, suppression) && !strings.Contains(line, " -- ") {
					t.Errorf("reasonless security suppression in %s: %s", path, line)
				}
			}
			return nil
		})
	}
}

// TestZKPrivacyShape pins that ordinary principals and sessions gain no configurable ZK metadata,
// and that production package source has no logging surface for proof artifacts.
// Covers: ZK-PSD-005, ZK-SES-002, ZK-SES-003, ZK-SES-007, ZK-SES-009
func TestZKPrivacyShape(t *testing.T) {
	principalFields := []string{"UserID", "SessionID", "Roles", "AuthAt", "MFAAt", "Email", "Verified"}
	principalType := reflect.TypeOf(authz.Principal{})
	if principalType.NumField() != len(principalFields) {
		t.Fatalf("authz.Principal fields = %d, want %d", principalType.NumField(), len(principalFields))
	}
	for i, want := range principalFields {
		if got := principalType.Field(i).Name; got != want {
			t.Errorf("authz.Principal field %d = %s, want %s", i, got, want)
		}
	}
	metaType := reflect.TypeOf(session.Meta{})
	metaFields := map[string]bool{"IP": true, "UserAgent": true}
	if metaType.NumField() != len(metaFields) {
		t.Fatalf("session.Meta changed shape: %v", metaType)
	}
	for i := 0; i < metaType.NumField(); i++ {
		if !metaFields[metaType.Field(i).Name] {
			t.Errorf("session.Meta gained %s", metaType.Field(i).Name)
		}
	}
	options := reflect.TypeOf(zkauthn.Options{})
	for _, field := range []string{"SessionMeta", "IP", "UserAgent", "LogProofs", "LogNullifier"} {
		if _, ok := options.FieldByName(field); ok {
			t.Errorf("Options exposes privacy-weakening %s", field)
		}
	}
	root := repositoryRoot(t)
	for _, pkg := range []string{"zkauthn", "zkauthz"} {
		entries, _ := filepath.Glob(filepath.Join(root, pkg, "*.go"))
		for _, name := range entries {
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"log.", "slog.", "zerolog", "fmt.Printf", "fmt.Println"} {
				if strings.Contains(string(raw), forbidden) {
					t.Errorf("privacy-sensitive package logging in %s: %s", name, forbidden)
				}
			}
		}
	}
	security := readRepositoryFile(t, "SECURITY.md")
	for _, phrase := range []string{"issued_to", "threshold"} {
		if !strings.Contains(strings.ToLower(security), phrase) {
			t.Errorf("SECURITY.md does not document %s disclosure", phrase)
		}
	}
}

// BenchmarkZKKnowledge reports the prove and verify wall-time sides used by make bench-zk.
func BenchmarkZKKnowledge(b *testing.B) {
	keys := testZKArtifacts(b)
	secret := zkauthn.Secret{1, 2, 3}
	commitment, _ := zkauthn.KnowledgeCommitment(secret)
	challenge := zkauthn.NewAudience("bench", "knowledge", "v1")
	witness := zkauthn.KnowledgeWitness{Secret: secret, Commitment: commitment, Challenge: challenge}
	proof, _ := keys.knowledgePK.ProveKnowledge(witness)
	b.Run("prove", func(b *testing.B) {
		for range b.N {
			if _, err := keys.knowledgePK.ProveKnowledge(witness); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("verify", func(b *testing.B) {
		for range b.N {
			if err := keys.knowledgeVK.VerifyKnowledge(proof, commitment, challenge); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkZKMembership reports the membership prove and verify wall-time sides.
func BenchmarkZKMembership(b *testing.B) {
	keys := testZKArtifacts(b)
	secret := zkauthn.Secret{1, 2, 3}
	attribute := uint64(21)
	commitment, _ := zkauthn.MembershipCommitment(secret, attribute)
	path, _ := zkauthn.SingleLeafPath(commitment)
	audience := zkauthn.NewAudience("bench", "membership", "v1")
	challenge := zkauthn.NewAudience("bench", "challenge", "v1")
	nullifier, _ := zkauthn.Nullifier(secret, audience)
	witness := zkauthn.MembershipWitness{Secret: secret, Attribute: attribute,
		Path: path.Path, Index: path.Index, Root: path.Root, Audience: audience,
		Threshold: 18, Nullifier: nullifier, Challenge: challenge}
	proof, _ := keys.membershipPK.ProveMembership(witness)
	public := zkauthn.MembershipPublic{Root: path.Root, Audience: audience, Threshold: 18,
		Nullifier: nullifier, Challenge: challenge}
	b.Run("prove", func(b *testing.B) {
		for range b.N {
			if _, err := keys.membershipPK.ProveMembership(witness); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("verify", func(b *testing.B) {
		for range b.N {
			if err := keys.membershipVK.VerifyMembership(proof, public); err != nil {
				b.Fatal(err)
			}
		}
	})
}
