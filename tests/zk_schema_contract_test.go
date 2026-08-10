package tests

import (
	"testing"

	"github.com/go-pg/pg/v10"
)

// coreColumn @notice A column in one of kal's own tables that zkauthn/sql.go depends on.
type coreColumn struct {
	table, column, kind string
	// why names the statement and the operation, so a failure reads as a consequence rather than
	// as a missing column.
	why string
}

// coreColumns @notice Every column zkauthn writes to or reads from a table it does not own.
//
// @dev Three statements, and only three. v0.4.0's session.Sessions.RecordMFA took over the
// auth_sessions.mfa_at update that used to be setMFASQL in this package, so auth_sessions is now
// reached through a Go method the compiler checks. That is one fewer uncheckable edge; do not
// reintroduce the statement.
//
// auth_zk_credentials.issued_to and auth_zk_challenges.session_id also carry foreign keys into
// auth_users(id) and auth_sessions(id), but those constraints are declared in kal's own
// 0002_zk.sql and move with it — the database enforces them, so they need no test here.
var coreColumns = []coreColumn{
	{"auth_users", "id", "uuid",
		"passwordHashByUserSQL and resolveNullifierSQL both key on it; knowledge enrolment and pseudonymous login fail"},
	{"auth_users", "password_hash", "text",
		"passwordHashByUserSQL reads it to re-verify the password that gates replacing a commitment; enrolment will fail at runtime"},
	{"auth_users", "deleted_at", "timestamp with time zone",
		"passwordHashByUserSQL and resolveNullifierSQL both exclude soft-deleted accounts; a revoked account could log in"},
	{"auth_users", "email", "text",
		"resolveNullifierSQL confines a recurring login to its own pseudonym by email, and createNullifierSQL inserts one; without it a nullifier resolves to a real password-holding account"},
	{"auth_users", "email_verified", "boolean",
		"createNullifierSQL inserts a pseudonym with it false; pseudonym creation will fail at runtime"},
}

// TestDBZKSchemaContract @notice The core columns this module's SQL depends on still exist in
// kal's migrations.
//
// @dev This test could not fail before the module split, which is why it did not exist. Inside one
// module a rename in 0001_core.sql and the SQL depending on it are reviewed in the same diff.
// Across two modules they are not, and SQL is not compile-checked: kal can rename
// auth_users.password_hash in an ordinary minor release, kal-zk's go.mod will happily accept it,
// every test that does not touch enrolment stays green, and the failure arrives at runtime, on the
// enrolment path, in production.
//
// Asserted against information_schema rather than by grepping the migration text, because the
// question is what the applied schema actually holds — a column renamed by a later migration is
// the case a grep of 0001_core.sql would miss.
//
// The type check is deliberately loose: a widened varchar or a text/varchar swap is compatible and
// must not fail this. What must fail is a column that is gone, or that changed to a class the
// statement cannot bind — a uuid turned text, a timestamp turned bigint.
//
// @param t the test handle
func TestDBZKSchemaContract(t *testing.T) {
	db := testDB(t)
	var commitmentPK string
	if _, err := db.QueryOne(pg.Scan(&commitmentPK), `
		select pg_get_constraintdef(oid)
		  from pg_constraint
		 where conrelid = 'auth_zk_commitments'::regclass and contype = 'p'`); err != nil {
		t.Fatal(err)
	}
	if commitmentPK != "PRIMARY KEY (user_id)" {
		t.Fatalf("auth_zk_commitments primary key = %s, want user_id", commitmentPK)
	}

	for _, c := range coreColumns {
		t.Run(c.table+"."+c.column, func(t *testing.T) {
			var kind string
			_, err := db.QueryOne(pg.Scan(&kind), `
				select data_type from information_schema.columns
				 where table_schema = ? and table_name = ? and column_name = ?`,
				testSchema, c.table, c.column)
			if err != nil {
				t.Fatalf("kal no longer has %s.%s, which zkauthn/sql.go depends on: %s\n"+
					"(lookup: %v)", c.table, c.column, c.why, err)
			}
			if !compatibleType(c.kind, kind) {
				t.Errorf("kal changed %s.%s from %s to %s: %s",
					c.table, c.column, c.kind, kind, c.why)
			}
		})
	}
}

// compatibleType @notice Whether an observed information_schema data_type still binds where the
// expected one did.
//
// @dev text and character varying are interchangeable for every statement here; nothing else is.
func compatibleType(want, got string) bool {
	if want == got {
		return true
	}
	textual := map[string]bool{"text": true, "character varying": true, "character": true}
	return textual[want] && textual[got]
}
