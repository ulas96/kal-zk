//go:build zkaudit

package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/go-pg/pg/v10"

	"github.com/ulas96/kal-zk/zkauthn"
	"github.com/ulas96/kal/authz"
	"github.com/ulas96/kal/kalerr"
)

type failingEntropy struct{ err error }

func (f failingEntropy) Read([]byte) (int, error) { return 0, f.err }

func credentialCount(t *testing.T, f *zkFixture) int {
	t.Helper()
	var count int
	if _, err := f.db.QueryOne(pg.Scan(&count), `select count(*) from auth_zk_credentials`); err != nil {
		t.Fatal(err)
	}
	return count
}

// TestDBZKAuditEntropyFailure exercises exact-read, error, short-read, all-zero rejection and the
// fact that issuance returns the secret without persisting it.
// Covers: ZK-HSH-003, ZK-HSH-004, ZK-HSH-005, ZK-ENR-005
func TestDBZKAuditEntropyFailure(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	before := credentialCount(t, f)

	for name, source := range map[string]io.Reader{
		"error": failingEntropy{errors.New("injected entropy failure")},
		"short": bytes.NewReader([]byte{1}),
		"zero":  bytes.NewReader(make([]byte, 3*zkauthn.SecretSize)),
	} {
		t.Run(name, func(t *testing.T) {
			restore := f.zk.AuditSetRandomSource(source)
			defer restore()
			if _, err := f.zk.IssueCredential(ctx, f.db, "", 18); err == nil {
				t.Fatal("credential issuance accepted a broken entropy source")
			}
			if got := credentialCount(t, f); got != before {
				t.Fatalf("credential rows after entropy failure = %d, want %d", got, before)
			}
		})
	}

	challengeBefore := 0
	if _, err := f.db.QueryOne(pg.Scan(&challengeBefore), `select count(*) from auth_zk_challenges`); err != nil {
		t.Fatal(err)
	}
	restore := f.zk.AuditSetRandomSource(bytes.NewReader([]byte{1}))
	if _, err := f.zk.LoginChallenge(ctx, f.db); err == nil {
		t.Fatal("challenge issuance accepted a short entropy read")
	}
	restore()
	var challengeAfter int
	if _, err := f.db.QueryOne(pg.Scan(&challengeAfter), `select count(*) from auth_zk_challenges`); err != nil {
		t.Fatal(err)
	}
	if challengeAfter != challengeBefore {
		t.Fatalf("challenge rows changed on entropy failure: before=%d after=%d", challengeBefore, challengeAfter)
	}

	// 31 bytes of 0xff are still below the BN254 modulus. This reaches the upper edge of Secret's
	// representable domain and proves io.ReadFull returns exactly the bytes the caller receives.
	want := bytes.Repeat([]byte{0xff}, zkauthn.SecretSize)
	restore = f.zk.AuditSetRandomSource(bytes.NewReader(want))
	credential, err := f.zk.IssueCredential(ctx, f.db, "", ^uint64(0))
	restore()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(credential.Secret[:], want) {
		t.Fatalf("returned secret = %x, want %x", credential.Secret, want)
	}
	var stored int
	if _, err := f.db.QueryOne(pg.Scan(&stored),
		`select count(*) from auth_zk_credentials where commitment = ?`, credential.Secret[:]); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatal("the raw credential secret was persisted as a commitment")
	}
}

// TestDBZKAuditVerificationBound proves the exact per-replica ceiling and that both real and dummy
// verification paths preserve RATE_LIMITED while leaving challenges and application state intact.
// Covers: ZK-DOS-001, ZK-DOS-002
func TestDBZKAuditVerificationBound(t *testing.T) {
	f := newZKFixture(t)
	ctx := context.Background()
	restoreWait := f.zk.AuditSetVerifyWait(10 * time.Millisecond)
	defer restoreWait()
	release, err := f.zk.AuditHoldVerificationSlots(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()

	honest := testZKHonestProofs(t)
	unknown := zkauthn.MembershipRequest{
		Proof: honest.membershipProof, Root: make([]byte, 32), Nullifier: make([]byte, 32),
		Claim: "claim-that-does-not-exist",
	}
	_, err = f.zk.Login(ctx, f.db, unknown)
	requireErrorCode(t, err, kalerr.CodeRateLimited)

	issuer := createUser(t, f.db, "audit-bound@example.com")
	credential, err := f.zk.IssueCredential(ctx, f.db, issuer, 21)
	if err != nil {
		t.Fatal(err)
	}
	claim := zkauthn.Claim{Name: "audit-bound", Audience: zkauthn.NewAudience("audit", "bound", "v1"),
		Threshold: 18, Kind: zkauthn.ClaimRecurring, AllowsLogin: true}
	if err := f.zk.EnsureClaim(ctx, f.db, claim); err != nil {
		t.Fatal(err)
	}
	challenge, err := f.zk.LoginChallenge(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	req, err := f.memberRequest(*credential, credential.Path, claim, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.zk.Login(ctx, f.db, req); err == nil {
		t.Fatal("real verification passed through a full semaphore")
	} else {
		requireErrorCode(t, err, kalerr.CodeRateLimited)
	}
	hash := sha256.Sum256([]byte(challenge))
	var consumed bool
	if _, err := f.db.QueryOne(pg.Scan(&consumed),
		`select consumed_at is not null from auth_zk_challenges where challenge = ?`, hash[:]); err != nil {
		t.Fatal(err)
	}
	if consumed {
		t.Fatal("rate-limited verification consumed its challenge")
	}
	// The same request succeeds after capacity returns, proving the failure was admission alone.
	release()
	released = true
	if _, err := f.request("", func(requestCtx context.Context) error {
		_, loginErr := f.zk.Login(requestCtx, f.db, req)
		return loginErr
	}); err != nil {
		t.Fatalf("verification did not recover after capacity returned: %v", err)
	}
}

// TestDBZKAuditChallengeTableBound shortens the private TTL and drives issuance for several
// lifetimes. Every issuance deletes expired rows in its own statement.
// Covers: ZK-CHL-005, ZK-CHL-006, ZK-CHL-010, ZK-DOS-004
func TestDBZKAuditChallengeTableBound(t *testing.T) {
	f := newZKFixture(t)
	restore := f.zk.AuditSetChallengeTTL(30 * time.Millisecond)
	defer restore()
	ctx := context.Background()
	for i := 0; i < 120; i++ {
		if _, err := f.zk.LoginChallenge(ctx, f.db); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(35 * time.Millisecond)
	if _, err := f.zk.LoginChallenge(ctx, f.db); err != nil {
		t.Fatal(err)
	}
	var count int
	if _, err := f.db.QueryOne(pg.Scan(&count), `select count(*) from auth_zk_challenges`); err != nil {
		t.Fatal(err)
	}
	if count > 2 {
		t.Fatalf("challenge table retained %d rows after several TTLs, want at most 2", count)
	}
}

func medianDuration(values []time.Duration) time.Duration {
	copyOfValues := append([]time.Duration(nil), values...)
	sort.Slice(copyOfValues, func(i, j int) bool { return copyOfValues[i] < copyOfValues[j] })
	return copyOfValues[len(copyOfValues)/2]
}

// medianFloat sorts a copy so the caller's round order survives for the failure message.
func medianFloat(values []float64) float64 {
	copyOfValues := append([]float64(nil), values...)
	sort.Float64s(copyOfValues)
	return copyOfValues[len(copyOfValues)/2]
}

func cliffsDelta(a, b []time.Duration) float64 {
	var greater, less int64
	for _, x := range a {
		for _, y := range b {
			switch {
			case x > y:
				greater++
			case x < y:
				less++
			}
		}
	}
	return float64(greater-less) / float64(len(a)*len(b))
}

// TestDBZKAuditORCTiming compares an enrolled-but-wrong knowledge proof with the same proof for an
// unenrolled account using 100 warmups and 1000 randomly interleaved measurements per class.
// Covers: ZK-ORC-002
func TestDBZKAuditORCTiming(t *testing.T) {
	f := newZKFixture(t)
	makeSubject := func(email string, enroll bool) (context.Context, string) {
		userID := createUser(t, f.db, email)
		token := issueSession(t, f, userID)
		principal, err := f.sessions.Lookup(context.Background(), f.db, token)
		if err != nil {
			t.Fatal(err)
		}
		ctx := authz.WithPrincipal(context.Background(), principal)
		if enroll {
			if _, err := f.zk.EnrollKnowledge(ctx, f.db, ""); err != nil {
				t.Fatal(err)
			}
		}
		challenge, err := f.zk.KnowledgeChallenge(ctx, f.db)
		if err != nil {
			t.Fatal(err)
		}
		return ctx, challenge
	}
	enrolledCtx, enrolledChallenge := makeSubject("timing-enrolled@example.com", true)
	missingCtx, missingChallenge := makeSubject("timing-missing@example.com", false)
	proof := testZKHonestProofs(t).knowledgeProof
	measure := func(ctx context.Context, challenge string) time.Duration {
		start := time.Now()
		err := f.zk.VerifyKnowledge(ctx, f.db, zkauthn.KnowledgeRequest{Proof: proof, Challenge: challenge})
		if err == nil {
			t.Fatal("wrong proof unexpectedly verified")
		}
		return time.Since(start)
	}
	for i := 0; i < 100; i++ {
		_ = measure(enrolledCtx, enrolledChallenge)
		_ = measure(missingCtx, missingChallenge)
	}
	// One round is 1000 interleaved measurements per class. Rounds are repeated and the assertion
	// is on the median, because a single round cannot separate a timing oracle from the host
	// drifting underneath it. Cliff's delta over 1000 samples has a standard error near 0.026 when
	// the samples are independent, so the 0.147 bound is roughly 5.7 of those out and unreachable
	// by chance — but timing samples are autocorrelated, and a runner that slows partway through
	// biases whichever class the interleaving happened to place late. That is how CI once measured
	// 0.150 on a tree where this leg had already passed at the same commit.
	//
	// The median of the *signed* deltas is what distinguishes the two: a real oracle keeps its sign
	// every round, because one branch genuinely does less work, while drift changes sign freely.
	// Taking the median of absolute values instead would preserve exactly the noise this removes.
	// Each round reseeds so the rounds do not share one interleaving pattern; the audit stays
	// reproducible because the seeds derive from defaultZKSeed.
	const rounds = 3
	deltas := make([]float64, 0, rounds)
	ratios := make([]float64, 0, rounds)
	for round := 0; round < rounds; round++ {
		a, b := make([]time.Duration, 0, 1000), make([]time.Duration, 0, 1000)
		random := rand.New(rand.NewSource(defaultZKSeed + int64(round))) // #nosec G404 -- randomized order, fixed audit seed
		for len(a) < 1000 || len(b) < 1000 {
			if (random.Intn(2) == 0 && len(a) < 1000) || len(b) == 1000 {
				a = append(a, measure(enrolledCtx, enrolledChallenge))
			} else {
				b = append(b, measure(missingCtx, missingChallenge))
			}
		}
		ratios = append(ratios, float64(medianDuration(a))/float64(medianDuration(b)))
		deltas = append(deltas, cliffsDelta(a, b))
	}
	ratio, delta := medianFloat(ratios), medianFloat(deltas)
	if ratio < 0.80 || ratio > 1.25 {
		t.Errorf("median timing ratio enrolled/missing = %.3f, want 0.80..1.25 (rounds %v)", ratio, ratios)
	}
	if delta < -0.147 || delta > 0.147 {
		t.Errorf("absolute Cliff's delta = %.3f, want <= 0.147 (rounds %v)", delta, deltas)
	}
}
