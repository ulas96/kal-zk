# Contributing

## Before a pull request

```sh
make check   # gofmt + vet + lint + test-db + audit
```

`make test` alone is not enough. The `TestDB*` tests skip without `DATABASE_URL`, and a skipped test
still reports `ok` — in this library that silence covers session revocation, token single-use and the
unique index. Copy `.env.example` to `.env` (values unquoted) and use `make test-db`, or start one:

```sh
docker run -d --name kal-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
```

`make audit` runs `govulncheck`, which reports standard-library vulnerabilities against **the
toolchain that built the code** — so it fails on an out-of-date local Go even when kal and its
dependencies are clean. That is the tool working correctly; upgrade Go rather than suppressing it.

## The rules

**A behaviour change needs a test that fails without it.** For a security control, the test should
read as *the thing that goes wrong* rather than as the implementation — `TestDBScope` asserts the row
is still in the table, not that a function returned false, because a delete that reports failure while
succeeding would pass the weaker version.

**New public API needs a runnable example or a test in `tests/`.** Every test lives in one
`package tests` outside the packages it exercises, so it can only reach the exported surface — the
same view a consumer has. If a security property cannot be asserted from out there, a consumer cannot
rely on it either, and the exported surface is what has to change.

**There is no root package and none should be added.** kal carried a hand-written re-export shim of
roughly fifty `ZK*` names, and every symbol somebody forgot to add to it was a second, unguarded way
into the same code. Splitting this module out is what deleted that surface;
`TestZKINV001NoRootFacade` is what keeps it deleted. A consumer imports `zkauthn` and `zkauthz`
directly.

**A change to `zkauthn.SensitiveFields` or to the entry points it names must move together.** kal no
longer knows these mutation names exist, so nothing but `TestZKSensitiveFieldsMatchEntryPoints`
connects the two. Renaming a method and leaving the list alone produces a guard over a resolver
nobody calls.

**SQL that touches a table this module does not own belongs in `TestDBZKSchemaContract`.** Three
statements read and write kal's `auth_users`. That contract crosses a module boundary with no
compiler on it, and the test is the only thing that turns a kal-side rename into a red build here
rather than a runtime failure on the enrolment path.

**All SQL lives in one `sql.go` per package.** go-pg is in maintenance mode by its own README, so
confining the SQL to one greppable file per package is the migration plan if a driver swap ever
becomes real. Note also that a driver swap changes the error-classification seam — `pg.Error` is an
*interface*, not pgx's `*pgconn.PgError` — which is why every 23505 check goes through
`luimaerr.SQLState` rather than a type assertion.

**Update `CHANGELOG.md` under `## [Unreleased]`.**

## Doc comments

NatSpec tags inside ordinary godoc comments: open with the symbol name, then `@notice` (what),
`@dev` (why it is written this way), `@param` / `@return`.

Comments explain **what breaks if the line is removed**. `// #nosec G115 -- bounded to [8,64] just
above` is a comment; `// convert to uint32` is noise. If code moves, its comment moves with it. The
existing files are the register to aim for — they are dense because most of what they record was
expensive to learn.

Two things not to do: do not write a comment that describes what the next line does, and do not write
one that argues the change is correct. Both are addressed to a reviewer rather than to the next
reader, and they become noise the moment the pull request merges.

## Style

`golangci-lint` enforces the rest, including `errorlint` — which catches the
`errors.As`-versus-type-assertion class that produced luima's finding E-01. In an error contract that
decides what a client may see, a type assertion that silently never matches is a redaction bypass,
not a style issue.
