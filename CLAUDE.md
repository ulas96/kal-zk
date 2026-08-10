# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Development may use a sibling `../kal` checkout through a temporary Go workspace. Published source
requires kal v0.5.1 directly and contains no `replace`; `release-check` rejects both a replace and a
dirty worktree. The mutation matrix needs editable source for both modules, so `KAL_REPO` defaults to
`../kal` locally and CI checks out `v0.5.1` explicitly.

```sh
make test      # go test ./...            — the TestDB* tests SKIP without a database
make test-db   # same, with .env exported — they run
make test-audit # zkaudit-only entropy, semaphore, TTL and timing controls
make mutation-zk # all 55 exact mutants in isolated source snapshots
make check     # gofmt + vet + lint + test-db + audit; run this before any PR
make audit     # govulncheck + gosec
make cover     # coverage profile + summary
```

One test, with the database:

```sh
set -a && . ./.env && set +a && go test -v -count=1 -run TestDBZKChallengeReplay ./tests/
```

`make test` alone proves less than it looks: `TestDB*` skips without `DATABASE_URL`, and a skip still
reports `ok` — that silence would cover the nullifier primary key, root retirement and the credential
tree's advisory lock. Copy `.env.example` to `.env` (values **unquoted**) or `docker run -d -e
POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:18`. CI discovers every top-level `TestDBZK*`
name and requires exactly one pass and zero skips for each.

The suite is slow by the standards of the rest of the stack: `TestZKDifferential` runs 2 000
witnesses (~8s) and the round-trip test runs a real setup ceremony. CI passes an explicit
`-timeout 30m`, because a default-timeout kill reads as a hung build rather than a slow one.

`make audit`'s govulncheck reports stdlib vulnerabilities against the *toolchain that built the code*,
so it fails on an out-of-date local Go even when this module is clean. Upgrade Go, don't suppress.

## Architecture

kal-zk is zero-knowledge authentication for [kal](https://github.com/ulas96/kal) ≥ v0.5.1, shipped as
a **separate module** rather than a package inside kal. That is the whole point of the repository: in
kal, `consensys/gnark` was a direct require and entered the module graph of every consumer whether or
not they issued a proof — 116 packages for a feature most deployments do not use. A build tag cannot
fix that, because build tags select which files compile and do not change what `go.mod` requires.

| package | role |
|---|---|
| `zkauthn` | Groth16/BN254 knowledge and membership proofs, the sparse Merkle credential tree, pseudonymous login |
| `zkauthz` | request-local proven claims behind kal's `@auth(proves:)` |

It plugs into kal through three seams and nothing else: `kal.Config.Proofs` (a plain func — kal
carries no dependency on this module), `kal.Config.ExtraMiddleware`, and
`kal.DefaultSensitiveFields()`. Read `README.md` for the wiring.

## Invariants

**There is no root package, and adding one would be a regression.** kal used to carry a hand-written
re-export shim of roughly fifty `ZK*` names; a symbol nobody remembered to add to it was reachable
only in the sub-package, bypassing whatever the wrapper did. `TestZKINV001NoRootFacade` fails if a
`.go` file appears at the module root.

**The zero `Options` is the production posture.** No environment variable, no development mode, no
field whose zero value relaxes a check. `zkauthn.New` refuses an `Options` without both verifying
keys.

**All SQL lives in one `sql.go` per package.** One greppable file per package is the migration plan
if the go-pg dependency ever has to be swapped. SQLSTATE classification goes through
`luimaerr.SQLState`; never assert a concrete driver error type.

**Tests live outside the packages they exercise**, in one external `package tests`. Nothing there can
reach an unexported symbol, so a passing test proves the *exported* surface is sufficient — which for
a proof library is the only claim worth making. `zk_case_manifest_test.go` asserts `zkauthn/` and
`zkauthz/` contain zero `*_test.go` files.

**This module ships no migrations.** The eight `auth_zk_*` tables stay in kal's `0002_zk.sql`,
byte-unchanged, because production databases have applied it under kal's numbering. SQL text carries
no Go dependency, so keeping it there removes nothing from anyone's graph. The test harness reads the
schema from `kal/migrations`.

**Three statements in `zkauthn/sql.go` read and write kal's own `auth_users`.** That contract crosses
a module boundary with no compiler on it. `TestDBZKSchemaContract` is what catches a kal-side rename;
add to it whenever a statement reaches a table this module does not own.

**`zkauthn.SensitiveFields` and the entry points it names move together.** kal no longer knows these
mutation names exist, so `TestZKSensitiveFieldsMatchEntryPoints` is the only thing connecting them.

## The registers

**`docs/gotchas.md` is a register of 26 silent failures.** Entries **40–63** were written in kal and
**keep their original numbers** — they are cited from code comments (`zkauthn/protocol.go` cites 63)
and from `tests/`. New entries here start at **200**, so the two repositories allocate from disjoint
ranges. Nothing is ever renumbered.

**`docs/vulnurability-test-cases.md` is the 147-case register**, reconciled against the suite by
`zk_case_manifest_test.go`, which AST-parses every `Covers: ZK-…` doc line. There are 140 executable
cases and seven signed, versioned review/analytical evidence cases; roadmap, partial and blocked are
all pinned to zero. The historical 75 rows remain as a closed implementation ledger. The misspelled
filename is cited by name from the test; leave it.

## Doc comments

NatSpec tags inside ordinary godoc comments: open with the symbol name, then `@notice` (what),
`@dev` (why it is written this way), `@param` / `@return`.

Comments explain **what breaks if the line is removed**. The existing files are the register to aim
for — they are dense because most of what they record was expensive to learn.

## One thing that looks like a bug and is not

`zkauthn/sql.go`'s `bindRecurringNullifierSQL` takes the `%[1]s` schema prefix on its `insert into`
target but **not** on the references inside `on conflict … do update`. That is correct and is the
only form that works: Postgres refers to the conflict target by its unqualified relation name, and
schema-qualifying it raises *invalid reference to FROM-clause entry*. The whole DB suite runs at
`testSchema = "kal_test"`, not `public`, and `TestDBZKPseudonymRecurs` exercises this statement.
"Fixing" the inconsistency breaks recurring pseudonyms in every deployment that uses a schema —
silently, on a path that returns `nil` rather than erroring. `kal/e2ee/sql.go` has the same shape for
the same reason.
