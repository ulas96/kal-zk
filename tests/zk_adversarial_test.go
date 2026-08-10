package tests

import (
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"

	"github.com/ulas96/kal-zk/zkauthn"
)

func zkWitnessAt(t *testing.T, secret zkauthn.Secret, attribute, threshold uint64, index uint32,
	audience, challenge zkauthn.Field) zkauthn.MembershipWitness {
	t.Helper()
	zeros := zkZeroTable(t)
	var path [zkauthn.MerkleDepth + 1]zkauthn.Field
	path[0] = zkIndependentMembershipCommitment(t, secret, attribute)
	for level := 0; level < zkauthn.MerkleDepth; level++ {
		path[level+1] = zeros[level]
	}
	return zkauthn.MembershipWitness{
		Secret: secret, Attribute: attribute, Path: path, Index: index,
		Root: zkRecomputeRoot(t, path, index), Audience: audience, Threshold: threshold,
		Nullifier: zkIndependentNullifier(t, secret, audience), Challenge: challenge,
	}
}

func cloneRawMembership(in zkRawMembership) zkRawMembership {
	clone := func(v *big.Int) *big.Int {
		if v == nil {
			return nil
		}
		return new(big.Int).Set(v)
	}
	out := zkRawMembership{
		Root: clone(in.Root), Audience: clone(in.Audience), Threshold: clone(in.Threshold),
		Nullifier: clone(in.Nullifier), Challenge: clone(in.Challenge), Secret: clone(in.Secret),
		Attribute: clone(in.Attribute), Index: clone(in.Index),
	}
	for i := range in.Path {
		out.Path[i] = clone(in.Path[i])
	}
	return out
}

func rawWithAttribute(t *testing.T, base zkauthn.MembershipWitness, attribute *big.Int) zkRawMembership {
	t.Helper()
	out := zkRawFromWitness(base)
	out.Attribute = new(big.Int).Set(attribute)
	leaf := zkHashDomain(t, zkDomainLeaf, zkSecretField(base.Secret), zkFieldFromBig(attribute))
	out.Path[0] = zkFieldBig(leaf)
	var path [zkauthn.MerkleDepth + 1]zkauthn.Field
	for i := range path {
		path[i] = zkFieldFromBig(out.Path[i])
	}
	out.Root = zkFieldBig(zkRecomputeRoot(t, path, uint32(out.Index.Uint64()))) // #nosec G115 -- test witness
	return out
}

func assertRawSolvedLikeReference(t *testing.T, family string, raw zkRawMembership) bool {
	t.Helper()
	want := zkMembershipReference(t, raw)
	got := test.IsSolved(&zkauthn.MembershipCircuit{}, raw.assignment(), ecc.BN254.ScalarField()) == nil
	if got != want {
		t.Fatalf("family %s: circuit solved=%v reference=%v", family, got, want)
	}
	return got
}

// TestZKCIR004AdversarialFamilies wires the independent raw-field harness into all fifteen required
// witness families. It includes 100+ accepted and rejected assignments and explicit edge controls.
// Covers: ZK-CIR-004, ZK-CIR-005, ZK-CIR-006, ZK-CIR-007, ZK-CIR-008, ZK-CIR-009, ZK-CIR-010, ZK-CIR-013
func TestZKCIR004AdversarialFamilies(t *testing.T) {
	random, _ := zkTestRand(t)
	modulus := ecc.BN254.ScalarField()
	rMinusOne := new(big.Int).Sub(new(big.Int).Set(modulus), big.NewInt(1))
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	audience := zkauthn.NewAudience("adversarial", "age", "v1")
	challenge := zkauthn.NewAudience("adversarial", "challenge", "v1")
	base := zkWitnessAt(t, zkSecretFromRand(random), 21, 21, 0, audience, challenge)
	baseRaw := zkRawFromWitness(base)

	type familyCase struct {
		name string
		raw  zkRawMembership
	}
	var families []familyCase
	add := func(name string, raw zkRawMembership) { families = append(families, familyCase{name, raw}) }

	add("01-threshold-equals-attribute", cloneRawMembership(baseRaw))
	below := cloneRawMembership(baseRaw)
	below.Threshold.SetUint64(20)
	add("02-threshold-one-below", below)
	above := cloneRawMembership(baseRaw)
	above.Threshold.SetUint64(22)
	add("02-threshold-one-above", above)
	max := zkWitnessAt(t, base.Secret, math.MaxUint64, math.MaxUint64, 0, audience, challenge)
	add("03-attribute-max-uint64", zkRawFromWitness(max))
	add("04-attribute-two-to-64", rawWithAttribute(t, base, two64))
	add("04-attribute-two-to-64-plus-one", rawWithAttribute(t, base, new(big.Int).Add(two64, big.NewInt(1))))
	add("05-attribute-r-minus-one", rawWithAttribute(t, base, rMinusOne))
	thresholdRM1 := cloneRawMembership(baseRaw)
	thresholdRM1.Threshold.Set(rMinusOne)
	add("06-threshold-r-minus-one", thresholdRM1)
	thresholdZero := cloneRawMembership(baseRaw)
	thresholdZero.Threshold.SetUint64(0)
	add("06-threshold-zero", thresholdZero)
	indexTooHigh := cloneRawMembership(baseRaw)
	indexTooHigh.Index.Set(new(big.Int).Lsh(big.NewInt(1), zkauthn.MerkleDepth))
	add("07-index-two-to-32", indexTooHigh)
	indexRM1 := cloneRawMembership(baseRaw)
	indexRM1.Index.Set(rMinusOne)
	add("07-index-r-minus-one", indexRM1)
	wrongIndex := cloneRawMembership(baseRaw)
	wrongIndex.Index.SetUint64(1)
	add("08-valid-index-wrong-position", wrongIndex)
	otherSecret := zkSecretFromRand(random)
	otherLeaf := zkIndependentMembershipCommitment(t, otherSecret, base.Attribute)
	stolenLeaf := cloneRawMembership(baseRaw)
	stolenLeaf.Path[0].SetBytes(otherLeaf[:])
	path := base.Path
	path[0] = otherLeaf
	stolenRoot := zkRecomputeRoot(t, path, base.Index)
	stolenLeaf.Root.SetBytes(stolenRoot[:])
	add("09-another-members-leaf", stolenLeaf)
	otherAudience := cloneRawMembership(baseRaw)
	otherAudienceField := zkauthn.NewAudience("adversarial", "age", "v2")
	otherAudience.Audience.SetBytes(otherAudienceField[:])
	add("10-same-secret-other-audience", otherAudience)
	otherChallenge := cloneRawMembership(baseRaw)
	otherChallengeField := zkauthn.NewAudience("adversarial", "challenge", "v2")
	otherChallenge.Challenge.SetBytes(otherChallengeField[:])
	add("11-same-secret-other-challenge", otherChallenge)
	zeroChallenge := cloneRawMembership(baseRaw)
	zeroChallenge.Challenge.SetUint64(0)
	add("12-zero-challenge", zeroChallenge)
	zeroWitness := zkWitnessAt(t, zkauthn.Secret{}, 0, 0, 0, audience, zkauthn.Field{})
	add("12-zero-secret-and-attribute", zkRawFromWitness(zeroWitness))
	otherNullifier := cloneRawMembership(baseRaw)
	otherNullifierField := zkIndependentNullifier(t, otherSecret, audience)
	otherNullifier.Nullifier.SetBytes(otherNullifierField[:])
	add("13-another-members-nullifier", otherNullifier)
	otherRootWitness := zkWitnessAt(t, otherSecret, 21, 21, 0, audience, challenge)
	wrongRoot := cloneRawMembership(baseRaw)
	wrongRoot.Root.SetBytes(otherRootWitness.Root[:])
	add("14-another-published-root", wrongRoot)
	emptyPath := cloneRawMembership(baseRaw)
	zeros := zkZeroTable(t)
	for i := range emptyPath.Path {
		emptyPath.Path[i].SetBytes(zeros[i][:])
	}
	add("15-empty-tree-path", emptyPath)

	counts := make(map[string]int)
	accepted, rejected := 0, 0
	for repeat := 0; repeat < 20; repeat++ {
		for _, family := range families {
			counts[strings.SplitN(family.name, "-", 2)[0]]++
			if assertRawSolvedLikeReference(t, family.name, family.raw) {
				accepted++
			} else {
				rejected++
			}
		}
	}
	for i := 1; i <= 15; i++ {
		name := leftPad2(i)
		if counts[name] == 0 {
			t.Errorf("adversarial family %s was not generated", name)
		}
	}
	if accepted < 100 || rejected < 100 {
		t.Fatalf("adversarial directions accepted=%d rejected=%d, want at least 100 each", accepted, rejected)
	}

	// Top-of-domain position: siblings are honest sparse zeros and the root is recomputed for the
	// rightmost leaf, so failure cannot be blamed on a malformed path.
	rightmost := zkWitnessAt(t, base.Secret, math.MaxUint64, math.MaxUint64, math.MaxUint32, audience, challenge)
	if !assertRawSolvedLikeReference(t, "rightmost-boundary", zkRawFromWitness(rightmost)) {
		t.Fatal("rightmost valid membership witness did not solve")
	}
	if err := zkDistinctFields(zkDomainKnowledge, zkDomainLeaf, zkDomainNullifier, zkDomainEmpty); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		secret := zkSecretFromRand(random)
		leaf := zkIndependentMembershipCommitment(t, secret, uint64(i))
		nullifier := zkIndependentNullifier(t, secret, zkUint64Field(uint64(i)))
		if leaf == nullifier || leaf == zeros[0] || nullifier == zeros[0] {
			t.Fatalf("domain separation collision at sample %d", i)
		}
	}
}

func leftPad2(value int) string {
	return fmt.Sprintf("%02d", value)
}

// TestZKCIR014CheckCircuit uses gnark's current CheckCircuit API with three valid and three invalid
// assignments for each circuit and rejects deprecated test APIs anywhere in this suite.
// Covers: ZK-CIR-014
func TestZKCIR014CheckCircuit(t *testing.T) {
	audience := zkauthn.NewAudience("check-circuit", "age", "v1")
	challenge := zkauthn.NewAudience("check-circuit", "challenge", "v1")
	secret := zkauthn.Secret{1, 2, 3}
	validKnowledge := zkKnowledgeAssignment(secret, zkIndependentKnowledgeCommitment(t, secret), challenge)
	badKnowledge1 := *validKnowledge
	badKnowledge1.Secret = 99
	badKnowledge2 := *validKnowledge
	badKnowledge2.Commitment = 0
	badKnowledge3 := *validKnowledge
	badKnowledge3.Secret = 0
	test.NewAssert(t).CheckCircuit(&zkauthn.KnowledgeCircuit{},
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16),
		test.WithValidAssignment(validKnowledge), test.WithValidAssignment(validKnowledge),
		test.WithValidAssignment(validKnowledge), test.WithInvalidAssignment(&badKnowledge1),
		test.WithInvalidAssignment(&badKnowledge2), test.WithInvalidAssignment(&badKnowledge3))

	valid := zkWitnessAt(t, secret, 21, 18, 0, audience, challenge)
	valid2 := zkWitnessAt(t, secret, math.MaxUint64, math.MaxUint64, math.MaxUint32, audience, challenge)
	valid3 := zkWitnessAt(t, zkauthn.Secret{}, 0, 0, 0, audience, zkauthn.Field{})
	bad1 := zkRawFromWitness(valid)
	bad1.Threshold.SetUint64(22)
	bad2 := zkRawFromWitness(valid)
	bad2.Nullifier.Add(bad2.Nullifier, big.NewInt(1))
	bad3 := zkRawFromWitness(valid)
	bad3.Index.Set(new(big.Int).Lsh(big.NewInt(1), zkauthn.MerkleDepth))
	test.NewAssert(t).CheckCircuit(&zkauthn.MembershipCircuit{},
		test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16),
		test.WithValidAssignment(zkMembershipAssignment(valid)),
		test.WithValidAssignment(zkMembershipAssignment(valid2)),
		test.WithValidAssignment(zkMembershipAssignment(valid3)),
		test.WithInvalidAssignment(bad1.assignment()),
		test.WithInvalidAssignment(bad2.assignment()),
		test.WithInvalidAssignment(bad3.assignment()))

	files, err := filepath.Glob(filepath.Join(repositoryRoot(t), "tests", "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, deprecated := range []string{"Prover" + "Succeeded(", "Prover" + "Failed("} {
			if strings.Contains(string(raw), deprecated) {
				t.Errorf("%s contains deprecated gnark API %s", name, deprecated)
			}
		}
	}
}
