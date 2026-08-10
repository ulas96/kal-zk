package tests

import (
	"strings"
	"testing"
)

// TestZKReleaseEvidence pins the seven obligations whose procedure is review, external matrix,
// analytical disclosure or recursive release gating rather than an ordinary code assertion.
// Covers: ZK-CIR-016, ZK-CIR-017, ZK-INV-004, ZK-INV-006, ZK-INV-009, ZK-SES-008, ZK-SQL-002
func TestZKReleaseEvidence(t *testing.T) {
	report := readRepositoryFile(t, "docs", "audits", "v0.1.0.md")
	for _, required := range []string{
		"Reviewer: `ulas96`", "cryptographically signed annotated `v0.1.0` tag",
		"ZK-CIR-016", "ZK-CIR-017", "ZK-SQL-002", "ZK-INV-004 / ZK-INV-009",
		"ZK-INV-006", "ZK-SES-008", "PostgreSQL 14 and 18", "non-superuser",
		"147 covered/evidenced, zero roadmap, zero partial, zero blocked",
	} {
		if !strings.Contains(report, required) {
			t.Errorf("v0.1.0 evidence lacks %q", required)
		}
	}
	for _, unresolved := range []string{"Reviewer: TBD", "status: pending", "blocked: true"} {
		if strings.Contains(strings.ToLower(report), strings.ToLower(unresolved)) {
			t.Errorf("v0.1.0 evidence is unresolved: %q", unresolved)
		}
	}
	workflow := readRepositoryFile(t, ".github", "workflows", "ci.yml")
	for _, required := range []string{
		"postgres: ['14', '18']", "fetch-depth: 0", "test-audit", "TestDBZK",
		"55-mutant release matrix", "mutation-results.jsonl", "benchmark-evidence",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("CI release evidence gate lacks %q", required)
		}
	}
	makefile := readRepositoryFile(t, "Makefile")
	for _, target := range []string{"test-audit:", "mutation-zk:", "release-check:", "git verify-tag"} {
		if !strings.Contains(makefile, target) {
			t.Errorf("Makefile release evidence gate lacks %q", target)
		}
	}
}
