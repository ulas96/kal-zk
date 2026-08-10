# kal-zk

Zero-knowledge authentication for [kal](https://github.com/ulas96/kal): Groth16/BN254 knowledge and
membership proofs over a Postgres sparse Merkle credential tree, pseudonymous login, and
request-local proven claims behind `@auth(proves:)`.

**Depending on this module is what puts `gnark` in your build graph — and depending on kal no longer
does.** These two packages used to live in kal, where `consensys/gnark` and `consensys/gnark-crypto`
were *direct* requires. They entered the module graph of every consumer and were recorded in every
consumer's `go.sum` — 116 packages and four modules compiled into applications that never issued a
proof. Leaving the feature switched off did not help, because a nil config field turns a feature off
at runtime and does not change what `go.mod` requires. Neither would a build tag: build tags select
which files compile. A separate module is the only thing that removes it, and this is that module.
The cost now falls on the deployments that asked for it.

## Install

Requires **kal ≥ v0.5.1**. v0.5.0 introduced the `Config.Proofs` and `Config.ExtraMiddleware`
seams; v0.5.1 adds the nullifier-shape hardening migration required by this release.

```sh
go get github.com/ulas96/kal-zk
```

## Wiring

`kal.New` used to construct the proof service for you. It does not know this module exists any more,
so the wiring is explicit — twelve lines, and no `kalzk.Install(&cfg)` that mutates a config it does
not own.

```go
import (
    "github.com/ulas96/kal"
    "github.com/ulas96/kal-zk/zkauthn"
    "github.com/ulas96/kal-zk/zkauthz"
)

claims, err := zkauthz.New(schema)

knowledgeVK, err := zkauthn.LoadVerifyingKey(zkauthn.CircuitKnowledge, kvkReader, kvkPin)
membershipVK, err := zkauthn.LoadVerifyingKey(zkauthn.CircuitMembership, mvkReader, mvkPin)

auth, err := kal.New(kal.Config{
    DB: db, BaseURL: base, Mailer: mailer,
    TableSchema: schema, CookieName: cookieName, MFAWindow: window,

    Proofs:          claims.Proofs,
    ExtraMiddleware: []func(http.Handler) http.Handler{claims.Middleware(db)},
    SensitiveFields: append(kal.DefaultSensitiveFields(), zkauthn.SensitiveFields...),
})

zk, err := zkauthn.New(zkauthn.Options{
    KnowledgeVK: knowledgeVK, MembershipVK: membershipVK,
    Sessions: auth.Sessions, Hasher: auth.Hasher, ProofSink: claims.Add,
    CookieName: cookieName, Schema: schema, MFAWindow: window,
    RootGrace: 30 * time.Second, MaxConcurrentVerifications: 8,
    AuthorizeCredentialIssue: func(ctx context.Context, issuedTo string, attribute uint64) error {
        return requireCredentialIssuer(ctx, issuedTo, attribute)
    },
})
```

Six things worth saying out loud, because each of them is something kal used to do for you:

- **`kal.LoadZKVerifyingKey` is now `zkauthn.LoadVerifyingKey`.** Same function. v0.4.0 already made
  key loading the consumer's call, so this line is a rename, not a redesign.
- **`MFAWindow` is passed twice and the two must agree.** `kal.New` guaranteed it. Two windows let a
  deployment tighten step-up for its directive-guarded fields while a stale elevation still replaces
  the second factor. Assert the equality in your own wiring.
- **`TableSchema` is passed twice too**, to `kal.Config` and to `zkauthz.New`/`zkauthn.Options`. A
  mismatch is not an error: each package renders its own prefix and both succeed, against different
  tables. Nothing reports it.
- **`SensitiveFields` replaces kal's defaults rather than extending them.** Without the `append`
  above, `mutation { a: zkLogin(…) b: zkLogin(…) … ×500 }` is one HTTP request and five hundred proof
  attempts, and nothing errors. Entry 200 in `docs/gotchas.md`.
- **`auth.ZK` is gone.** Hold the `zk` value yourself.
- **Credential issuance fails closed.** A nil `AuthorizeCredentialIssue` is verifier-only and
  `IssueCredential` returns `FORBIDDEN` before entropy or database access. The callback receives the
  operator-selected `issuedTo` and `attribute`; enforce your issuer role there.

`auth.Sessions` and `auth.Hasher` are already exported by kal, which is why the service itself needed
no new kal API — only the two middleware and directive seams did.

`zkauthn.Login` returns a `*authz.Principal`, so `github.com/ulas96/kal/authz` is in this module's
public API and not merely an internal detail: naming the result requires that import in your own
code.

## What it costs you to depend on kal-zk

| module | why | size |
|---|---|---|
| `github.com/consensys/gnark` | the Groth16 circuits, prover and verifier | with gnark-crypto, 116 packages and four modules |
| `github.com/consensys/gnark-crypto` | BN254 field arithmetic, pairing and MiMC | — |
| `golang.org/x/sync` | the verification semaphore | already in kal's graph |
| `github.com/go-pg/pg/v10` | the credential tree and nullifier tables | already in kal's graph |
| `github.com/ulas96/luima` | `luimaerr.SQLState` classifies operator writes | already in kal's graph |
| `github.com/99designs/gqlgen` | **test-only** — see below | nothing; pruned out of your build |

The four modules `go list -m all` reports are `gnark`, `gnark-crypto`, `gnark-solidity-checker` and
`ingonyama-zk/icicle-gnark`. Between them they pull in assembly and `unsafe`. This is honest here in
a way it could not be in kal: an application that imports this module has asked for proofs.

`gqlgen` is a direct require that no package in this module imports. It is reached only by
`tests/zkauthz_test.go`, which drives `zkauthz` through a real `graphql.FieldContext` rather than a
stand-in, because the claim worth testing is that the `@auth(proves:)` seam works against the
framework kal actually runs. Since Go 1.17's module-graph pruning, a dependency of an external test
package does not enter a consumer's build list: it costs you no packages and no compile time. It is
named here rather than hidden because a zero-knowledge library whose `go.mod` mentions a GraphQL
framework should explain itself.

## The schema

**kal-zk ships no migrations.** The eight `auth_zk_*` tables live in kal's `migrations/0002_zk.sql`,
byte-unchanged, and their names stay in `kal/migrations.Tables()`. kal v0.5.1 adds
`migrations/0004_zk_hardening.sql`, which enforces that recurring nullifier rows have `user_id`
while one-shot rows have `consumed_at`, never both or neither. Run the preflight query documented in
that migration before applying it to an existing database.

That looks backwards and is deliberate. Production databases have already applied `0002_zk.sql` under
kal's numbering and their migration trackers hold a row for it; moving the file would either strand
that row against a file that no longer exists or force a renumber. Keeping it costs nothing, because
**SQL text carries no Go dependency** — `gnark` leaves kal's module graph either way — and it means
`kal.Auth.Migrate` still produces a complete schema from one call.

Three statements in `zkauthn/sql.go` read and write kal's *own* tables (`auth_users`), which is a
contract that now crosses a module boundary with no compiler on it. `TestDBZKSchemaContract` is what
watches it: it applies kal's migrations and asserts every core column those statements depend on
still exists. A column renamed in a kal minor release fails that test rather than the enrolment path
in production.

## Operating the ZK module

The proving key is a client artifact and this module never loads one: the server holds only verifying
keys, pinned by SHA-256 in your own source. Packaging and shipping the prover — a JavaScript/WASM
bundle, a mobile client, a CLI — is your responsibility and your trust boundary. A client that
computes proofs also holds the member's secret, so a compromised prover bundle is a compromised
credential for every member who loads it; version and pin it the way you would any other
credential-handling code.

**Recovery.** A Knowledge secret is returned exactly once and is not recoverable. Re-enrolment is
the recovery path: `EnrollKnowledge` replaces the commitment after re-verifying the account's
password, or recent MFA when the account has no password, and revokes every other session when it
does. An account with neither factor cannot self-serve and needs an operator.

**Revocation.** Disabling an account does not revoke its membership credential. A credential is
deliberately not joined to the account that received it, so soft-deleting a user leaves their leaf
live and they can still log in under a fresh pseudonym for any audience they have not used.
`RevokeCredentialsForUser` is the operation that revokes it, and calling it is a deployment
decision this module does not make for you.

Credential revocation prevents new proofs after `RootGrace`; it does not revoke an already-issued
unlinkable pseudonymous session. Reissue also creates a new secret, nullifier and pseudonymous
account, so old application rows do not follow it automatically. If continuity is required, migrate
those rows explicitly—never use `issued_to` as an implicit authentication link.

**Issuance delivery.** Internal failures roll the issuance transaction back. Network/response
delivery cannot be atomic with the database commit: if delivery fails after a credential was
returned to the resolver, compensate with its `LeafIndex` and `RevokeCredential`.

**Audience identity.** `deploymentID` inputs to `NewAudience` must be stable and globally unique.
Changing one rotates nullifiers and pseudonyms. Each public threshold result also reveals one bit
about the private attribute; several thresholds compose into a narrower bracket.

## Development

```sh
make check        # gofmt + vet + lint + exact DB suite + dependency/security audit
make test-audit   # zkaudit-only entropy, saturation, TTL and timing distributions
make bench-zk     # one prove/verify measurement and the pinned constraint identities
make mutation-zk  # 55 isolated exact mutants; every unmutated named test must pass first
```

`make test` alone proves less than it looks: the `TestDB*` tests skip without `DATABASE_URL` and a
skipped test still reports `ok`. Copy `.env.example` to `.env` (values unquoted) or start one:

```sh
docker run -d --name kal-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:18
```

No proving or verifying key is ever committed. `zkauthn.Setup` generates them at runtime and the
test harness runs its own ephemeral ceremony, so there is nothing in `testdata/` and no build step.

`KAL_ZK_TEST_SEED` reseeds the differential test; CI prints the seed it used, so a failure is
replayable.

## Release order

A public stable release is intentionally two-stage. First publish kal `v0.5.1`, including
`0004_zk_hardening.sql`; then remove every local `replace`, require that version here, run
`go mod tidy` to record the published module checksum, and commit the result before signing the
annotated kal-zk `v0.1.0` tag. Run `make release-check RELEASE_TAG=v0.1.0` on that tag. CI
reruns PostgreSQL 14/18, the audit-tag suite, benchmarks and all 55 mutants. The historical 75-item
list in `docs/vulnurability-test-cases.md` is a closed implementation ledger, not a post-release
roadmap; any non-zero roadmap/partial/blocked count prevents a stable tag.

`docs/gotchas.md` carries entries **40–63** with their original kal numbering, because they are cited
from code comments and from `tests/`. New entries here start at **200**.

## Licence

MIT. See [LICENSE](LICENSE).
