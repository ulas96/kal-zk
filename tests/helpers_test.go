// Package tests @notice Holds every test in the module.
//
// @dev The tests live here rather than beside their packages, so each one exercises kal-zk across
// a real package boundary — exactly as a consumer does. Nothing in this directory can reach an
// unexported symbol, which means a test passing here proves the exported surface is sufficient.
// For a proof library that rule has teeth: if a security property cannot be asserted from out
// here, a consumer cannot rely on it either, and the exported surface — not the test — is what
// has to change. zk_case_manifest_test.go asserts zkauthn/ and zkauthz/ hold no test files at all.
//
// These helpers are copied from kal rather than imported. `package tests` is external and they are
// unexported, so there is nothing to import; the alternative is exporting test helpers from a
// library, which is worse than duplicating forty lines across two repositories.
package tests

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-pg/pg/v10"

	"github.com/ulas96/kal/kalerr"
	"github.com/ulas96/kal/migrations"
	"github.com/ulas96/kal/session"
)

// testSchema @notice The scratch Postgres schema every DB-backed test runs in.
//
// @dev A dedicated schema rather than the connection's default: dropping and recreating it
// wholesale gives each test a clean slate without touching anything else in the database. And
// because the harness applies the migrations through search_path, it exercises the same
// mechanism a consumer isolating kal's tables uses — the harness is itself a test of that path.
const testSchema = "kal_test"

// testDB @notice Connects to DATABASE_URL, rebuilds the scratch schema, applies every migration
// and returns the pool — or skips the calling test when no database is configured.
//
// @dev The migrations come from kal. kal-zk ships none: 0002_zk.sql stays in kal under kal's
// numbering, because production databases have already applied it and their migration trackers
// hold a row for it. SQL text carries no Go dependency, so leaving it there costs kal-zk nothing
// and gives this harness a complete schema from one import.
//
// Skipping rather than failing keeps `go test ./...` green on a machine without Postgres.
// That mercy is why CI greps the -v output for `--- PASS: TestDB`: a skip still reports ok, and
// in a proof library that silence would swallow every property the schema enforces — the
// nullifier primary key, the credential tree's advisory lock, root retirement.
//
// This is the only t.Skip for DATABASE_URL in the suite. Do not add a second one.
//
// search_path is set in OnConnect, not with a one-off Exec: go-pg is a pool, and an Exec lands
// the setting on one arbitrary connection while later queries run on others. OnConnect is the
// only hook that reaches every connection.
//
// @param t the test handle
// @return *pg.DB a pool whose every connection resolves unqualified names to the scratch schema
func testDB(t *testing.T) *pg.DB {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set — see .env.example")
	}
	opt, err := pg.ParseURL(url)
	if err != nil {
		t.Fatalf("DATABASE_URL: %v", err)
	}
	opt.OnConnect = func(_ context.Context, cn *pg.Conn) error {
		_, err := cn.Exec("set search_path to ?", pg.Ident(testSchema))
		return err
	}
	db := pg.Connect(opt)
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec("drop schema if exists ? cascade", pg.Ident(testSchema)); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := db.Exec("create schema ?", pg.Ident(testSchema)); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	for _, name := range migrations.Files() {
		sql, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := db.Exec(string(sql)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec("drop schema if exists ? cascade", pg.Ident(testSchema))
	})
	return db
}

// createUser @notice Inserts a verified user row directly and returns its id.
//
// @dev A fixture, deliberately not the registration flow — registration lives in kal and has its
// own tests there.
func createUser(t *testing.T, db *pg.DB, email string) string {
	t.Helper()
	var id string
	if _, err := db.QueryOne(pg.Scan(&id),
		`insert into auth_users (email, email_verified) values (?, true) returning id`, email); err != nil {
		t.Fatal(err)
	}
	return id
}

// repositoryRoot @notice The module root, for the tests that assert about files rather than code.
//
// @dev `tests/` is one level down and `go test` runs each package in its own directory, so the
// parent of the working directory is the root regardless of where the `go test` invocation was
// typed.
//
// @param t the test handle
// @return string an absolute path to the module root
func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// readRepositoryFile @notice Reads a file relative to the module root, failing the test if absent.
//
// @param t the test handle
// @param parts path segments below the module root
// @return string the file's contents
func readRepositoryFile(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{repositoryRoot(t)}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// sessionCookie @notice The session token from a recorder's Set-Cookie, or "".
//
// @dev Reads the cookie kal's session middleware actually wrote rather than a value the test
// chose, which is what makes a rotation assertion meaningful: a test that carried its own token
// forward would pass against a middleware that had stopped rotating.
func sessionCookie(rec *httptest.ResponseRecorder) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.DefaultCookieName {
			return c.Value
		}
	}
	return ""
}

// doc @notice A domain table standing in for whatever a consumer owns rows in.
//
// @dev Here so a pseudonymous session can be shown to scope exactly like an ordinary one — the
// property is that authz.Scope needs no branch for a caller who arrived through a proof.
type doc struct {
	tableName struct{} `pg:"docs"` //nolint:unused // go-pg reads this by reflection
	ID        string   `pg:"id,pk"`
	OwnerID   string   `pg:"owner_id"`
	Title     string   `pg:"title"`
}

// requireErrorCode @notice Asserts an error carries a specific [kalerr.Error] code.
//
// @dev errors.As rather than a type assertion: the contract wraps, and a bare assertion that
// silently never matches would pass this helper's nil check and then compare a zero Code. It
// matters more here than in kal: every verification failure is deliberately one code, so a test
// that asserted on messages would pass while the module leaked which check rejected the proof.
//
// @param t the test handle
// @param err the error under test
// @param code the expected kalerr code
func requireErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var typed *kalerr.Error
	if err == nil || !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}
