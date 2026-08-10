package tests

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

type zkCaseDisposition struct {
	kind   string
	reason string
}

// Stable release policy: every case is backed by executable coverage or by a versioned evidence
// assertion. A non-empty roadmap, partial, blocked or informal exception bucket blocks release.
var (
	zkNonAutomatedCases = map[string]zkCaseDisposition{}
	zkRoadmapCases      = map[string]zkCaseDisposition{}
)

const zkRoadmapPinned = 0

// The group is [A-Z0-9]+, not [A-Z]+: the E2E group carries a digit, and a letters-only class
// silently drops all six ZK-E2E cases — four of them CRITICAL — from the register the manifest
// believes it is reconciling. The disposition map then names an id the test cannot see, which is
// the only reason ZK-E2E-006 ever read as `extra`.
var zkCaseHeadingRE = regexp.MustCompile(`^### (ZK-[A-Z0-9]+-[0-9]{3})\b`)

// Matched against ast.CommentGroup.Text(), which strips the `// ` markers. Anchoring on a literal
// `// Covers:` therefore never matches, `covered` stays empty for every id, and the reconciliation
// below reports the entire register as uncovered no matter how many tests cite a case.
var zkCaseCoverRE = regexp.MustCompile(`(?m)^Covers: ((?:ZK-[A-Z0-9]+-[0-9]{3})(?:, ZK-[A-Z0-9]+-[0-9]{3})*)$`)

func documentedZKCases(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "docs", "vulnurability-test-cases.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]bool)
	for _, line := range strings.Split(string(raw), "\n") {
		match := zkCaseHeadingRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if out[match[1]] {
			t.Fatalf("duplicate vulnerability case heading %s", match[1])
		}
		out[match[1]] = true
	}
	return out
}

// Covers: ZK-INV-003, ZK-INV-004
func TestZKINV003ExternalCaseCoverage(t *testing.T) {
	documented := documentedZKCases(t)
	if len(documented) != 147 {
		t.Fatalf("documented ZK cases = %d, want the pinned register of 147", len(documented))
	}

	root := repositoryRoot(t)
	for _, pkg := range []string{"zkauthn", "zkauthz"} {
		files, err := filepath.Glob(filepath.Join(root, pkg, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 0 {
			t.Errorf("internal test files violate the external-package invariant: %v", files)
		}
	}

	testFiles, err := filepath.Glob(filepath.Join(root, "tests", "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	covered := make(map[string][]string)
	fset := token.NewFileSet()
	for _, name := range testFiles {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(fset, name, raw, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if parsed.Name.Name != "tests" {
			t.Errorf("%s uses package %s, want tests", name, parsed.Name.Name)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Doc == nil {
				continue
			}
			matches := zkCaseCoverRE.FindAllStringSubmatch(fn.Doc.Text(), -1)
			for _, match := range matches {
				for _, id := range strings.Split(match[1], ", ") {
					covered[id] = append(covered[id], fn.Name.Name)
					if strings.Contains(fn.Name.Name, "DB") && !strings.HasPrefix(fn.Name.Name, "TestDBZK") {
						t.Errorf("database ZK test %s does not use the TestDBZK prefix", fn.Name.Name)
					}
				}
			}
		}
	}

	if len(zkRoadmapCases) != zkRoadmapPinned {
		t.Fatalf("roadmap holds %d cases, want the pinned %d — moving one out is progress, and it "+
			"is meant to be visible in the diff", len(zkRoadmapCases), zkRoadmapPinned)
	}

	var missing, extra []string
	for id := range documented {
		if len(covered[id]) != 0 {
			continue
		}
		_, excused := zkNonAutomatedCases[id]
		_, scheduled := zkRoadmapCases[id]
		if excused && scheduled {
			t.Errorf("%s is both excused and scheduled; it is one or the other", id)
		}
		if !excused && !scheduled {
			missing = append(missing, id)
		}
	}
	for id, disposition := range zkRoadmapCases {
		if !documented[id] {
			extra = append(extra, id)
		}
		if disposition.reason == "" {
			t.Errorf("%s has an empty roadmap rationale", id)
		}
		if len(covered[id]) != 0 {
			t.Errorf("%s is on the roadmap but %v already covers it", id, covered[id])
		}
	}
	for id := range covered {
		if !documented[id] {
			extra = append(extra, id)
		}
	}
	for id, disposition := range zkNonAutomatedCases {
		if !documented[id] {
			extra = append(extra, id)
		}
		if disposition.reason == "" {
			t.Errorf("%s has an empty %s rationale", id, disposition.kind)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("case register mismatch: missing=%v extra=%v", missing, extra)
	}
}
