package tests

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ulas96/kal-zk/zkauthn"
	"github.com/ulas96/kal-zk/zkauthz"
)

// TestZKINV002ZeroConfig pins strict zero values without constructing a database-backed service.
//
// The subject used to be kal.Config and kal.ZKConfig; after the module split the configuration
// this module owns is zkauthn.Options, which is what the case always meant — the zero value is the
// production posture, and no environment variable may move it.
// Covers: ZK-INV-002
func TestZKINV002ZeroConfig(t *testing.T) {
	var opts zkauthn.Options
	if opts.RootGrace != 0 || opts.MaxConcurrentVerifications != 0 || opts.MFAWindow != 0 {
		t.Fatalf("zero Options has permissive defaults: %+v", opts)
	}
	if opts.KnowledgeVK != nil || opts.MembershipVK != nil {
		t.Fatal("zero Options arrives with a verifying key")
	}
	if _, err := zkauthn.New(opts); err == nil {
		t.Error("New accepted the zero Options — a service with no verifying key verifies nothing")
	}
	for _, pkg := range []string{"zkauthn", "zkauthz"} {
		files, err := filepath.Glob(filepath.Join(repositoryRoot(t), pkg, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, filename := range files {
			raw, err := os.ReadFile(filename)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "os.Getenv(") {
				t.Errorf("%s reads an environment variable", filename)
			}
		}
	}
}

// TestZKINV005Gotchas checks that the gotcha register precedes and names the documented controls.
// Covers: ZK-INV-005
func TestZKINV005Gotchas(t *testing.T) {
	gotchas := readRepositoryFile(t, "docs", "gotchas.md")
	// The register writes an entry as `**40 · An under-constrained circuit …`. Anchoring on the
	// bare number at line start instead would never match — the leading `**` defeats it — and the
	// whole loop would report all 24 entries missing while every one of them is present.
	for i := 40; i <= 63; i++ {
		if !regexp.MustCompile(`(?m)^\*\*`+regexp.QuoteMeta(strconv.Itoa(i))+` · `).MatchString(gotchas) && !strings.Contains(gotchas, "Gotcha "+strconv.Itoa(i)) {
			t.Errorf("gotcha %d is missing", i)
		}
	}
}

// TestZKINV007ReadmeDependencyClaims checks the repository's dependency statement against the
// module declarations that actually exist.
// Covers: ZK-INV-007
func TestZKINV007ReadmeDependencyClaims(t *testing.T) {
	readme := readRepositoryFile(t, "README.md")
	goMod := readRepositoryFile(t, "go.mod")
	for _, dependency := range []string{"github.com/consensys/gnark", "github.com/consensys/gnark-crypto"} {
		if !strings.Contains(goMod, dependency) {
			t.Errorf("go.mod does not declare %s", dependency)
		}
		if !strings.Contains(readme, dependency) && !strings.Contains(readme, "gnark") {
			t.Errorf("README does not describe %s", dependency)
		}
	}
	if !strings.Contains(readme, "go.mod") || !strings.Contains(readme, "go.sum") {
		t.Error("README does not explain module-graph dependency behavior")
	}
}

// Covers: ZK-DOC-001
func TestZKDOC001AnonymitySet(t *testing.T) {
	security := readRepositoryFile(t, "SECURITY.md")
	if !strings.Contains(security, "anonymity") || !strings.Contains(security, "non-revoked") || !strings.Contains(security, "one-in-one") {
		t.Error("SECURITY.md does not state the anonymity-set qualification")
	}
}

// Covers: ZK-DOC-002
func TestZKDOC002OperatorTrustBoundary(t *testing.T) {
	security := readRepositoryFile(t, "SECURITY.md")
	for _, term := range []string{"operator", "verifier", "PLONK", "different parties"} {
		if !strings.Contains(strings.ToLower(security), strings.ToLower(term)) {
			t.Errorf("SECURITY.md does not state operator trust boundary term %q", term)
		}
	}
}

// Covers: ZK-DOC-003
func TestZKDOC003ProverPackagingBoundary(t *testing.T) {
	readme := readRepositoryFile(t, "README.md")
	security := readRepositoryFile(t, "SECURITY.md")
	for _, document := range []string{readme, security} {
		lower := strings.ToLower(document)
		if !strings.Contains(lower, "javascript") && !strings.Contains(lower, "client") {
			t.Error("document does not explain the prover/client trust boundary")
		}
	}
}

// Covers: ZK-DOC-004
func TestZKDOC004TimingDisclosure(t *testing.T) {
	security := readRepositoryFile(t, "SECURITY.md")
	if !strings.Contains(strings.ToLower(security), "first use") || !strings.Contains(strings.ToLower(security), "timestamp") {
		t.Error("SECURITY.md does not document enrollment-to-first-use timing correlation")
	}
}

// Covers: ZK-DOC-005
func TestZKDOC005IssuedToDisclosure(t *testing.T) {
	security := readRepositoryFile(t, "SECURITY.md")
	if !strings.Contains(security, "issued_to") || !strings.Contains(strings.ToLower(security), "revocation") {
		t.Error("SECURITY.md does not document issued_to disclosure and revocation tradeoff")
	}
}

// Covers: ZK-DOC-006
func TestZKDOC006SessionClaimBoundary(t *testing.T) {
	security := readRepositoryFile(t, "SECURITY.md")
	if !strings.Contains(strings.ToLower(security), "session") || !strings.Contains(strings.ToLower(security), "credential") {
		t.Error("SECURITY.md does not document session-bound claims")
	}
}

// TestZKINV001NoRootFacade @notice This module has no root package, so every exported symbol has
// exactly one way to reach it.
//
// @dev The case this covers was written against kal, where the root package re-exported roughly
// fifty ZK* names by hand and the obligation was that each one had a matching alias or wrapper.
// The module split deleted that shim, and with it the failure the case existed to prevent: a
// symbol nobody added to the root, reached directly in the sub-package instead, bypassing whatever
// the wrapper did. There is no wrapper to bypass now.
//
// What has to stay true is that nobody adds one back. A convenience facade — kalzk.Install(&cfg),
// a root package re-exporting both — would restore exactly the hand-maintained surface the split
// removed, and the first symbol somebody forgot to add would be the second, unguarded API again.
// Asserting the module root holds no Go files is what makes that a failing build rather than a
// judgement call in review.
//
// @param t the test handle
// Covers: ZK-INV-001
func TestZKINV001NoRootFacade(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repositoryRoot(t), "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("the module root declares Go files %v — kal-zk ships no facade package, and one "+
			"would reintroduce the hand-maintained re-export surface the split removed", files)
	}
}

// TestZKTreeDepthIsCompileTime @notice Merkle depth is fixed at compile time and unreachable from
// configuration.
//
// @dev A configurable depth is a different circuit, a different R1CS, a different setup and a
// different verifying key. Making it a field would let a consumer change it and get a verifying
// key that silently no longer matches its circuit: universal proof rejection nobody connects to
// the config change, or — if the key is regenerated — a working system whose already-stored tree
// is at the old depth and whose paths are one level short.
//
// The Path length is asserted alongside the constant because a hard-coded 32 in the path walk
// while MerkleDepth sits unread is the same bug with a decoy. Options is checked by reflection
// rather than by reading the struct, so a depth field added later fails here instead of being
// noticed in review.
//
// @param t the test handle
// Covers: ZK-TRE-013
func TestZKTreeDepthIsCompileTime(t *testing.T) {
	if zkauthn.MerkleDepth != 32 {
		t.Errorf("MerkleDepth = %d, want 32", zkauthn.MerkleDepth)
	}
	if got := len(zkauthn.MembershipCircuit{}.Path); got != zkauthn.MerkleDepth+1 {
		t.Errorf("MembershipCircuit.Path has %d elements, want MerkleDepth+1 = %d",
			got, zkauthn.MerkleDepth+1)
	}
	for _, f := range reflect.VisibleFields(reflect.TypeOf(zkauthn.Options{})) {
		if strings.Contains(strings.ToLower(f.Name), "depth") {
			t.Errorf("Options.%s makes tree depth settable; it is the circuit's identity, not a "+
				"tuning parameter", f.Name)
		}
	}
}

// TestZKSensitiveFieldsMatchEntryPoints @notice Every name in SensitiveFields fronts a real entry
// point on *ZK.
//
// @dev SensitiveFields is what a consumer appends to kal.Config.SensitiveFields to keep the
// anti-batching guard over the proof mutations, and kal no longer knows these names exist. So the
// list has no compiler behind it: a method renamed here, or a name dropped from the list, leaves a
// guard that protects a resolver nobody calls while the real one is unguarded — and nothing errors.
//
// The assertion is a correspondence, deliberately not a count. A length check passes after a
// rename, which is the exact edit that breaks this.
//
// @param t the test handle
// Covers: ZK-AUZ-012
func TestZKSensitiveFieldsMatchEntryPoints(t *testing.T) {
	// resolver name -> the *ZK method it fronts.
	want := map[string]string{
		"enrollZKKnowledge":  "EnrollKnowledge",
		"verifyZKKnowledge":  "VerifyKnowledge",
		"zkLogin":            "Login",
		"proveZKClaim":       "ProveClaim",
		"issueZKCredential":  "IssueCredential",
		"revokeZKCredential": "RevokeCredential",
	}
	zk := reflect.TypeOf(&zkauthn.ZK{})

	if len(zkauthn.SensitiveFields) != len(want) {
		t.Errorf("SensitiveFields = %v, want the %d names below", zkauthn.SensitiveFields, len(want))
	}
	listed := map[string]bool{}
	for _, name := range zkauthn.SensitiveFields {
		listed[name] = true
		method, ok := want[name]
		if !ok {
			t.Errorf("SensitiveFields names %q, which fronts no known entry point", name)
			continue
		}
		if _, exists := zk.MethodByName(method); !exists {
			t.Errorf("SensitiveFields protects %q but (*ZK).%s no longer exists — the guard now "+
				"covers a resolver nobody calls", name, method)
		}
	}
	for name, method := range want {
		if !listed[name] {
			t.Errorf("(*ZK).%s is an entry point and %q is missing from SensitiveFields — every "+
				"deployment appending the list is unguarded on it", method, name)
		}
	}
}

var _ = zkauthn.CircuitKnowledge
var _ = zkauthz.New
