# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the major version is `0`, the public API may change in a minor release. Every such change
will be listed here under **Changed** with the migration in one line.

## [Unreleased]

## [0.1.0] - 2026-08-10

### Security

- Credential issuance now fails closed through `Options.AuthorizeCredentialIssue`. A nil callback
  leaves a verifier-only service: `IssueCredential` returns `FORBIDDEN` before reading entropy or
  touching the database. The callback receives the operator-selected subject and attribute.
- Membership now range-constrains both `Attribute` and public `Threshold` to 64 bits before the
  comparison. The adversarial `Threshold = r-1` witness exposed the missing constraint; the measured
  membership R1CS is now 23,066 constraints with circuit identity
  `630cc13d2bc8fa313b94cead3f0e45674c9bc0daba28b26a4fe0afafbb9e4a50`.
- Secrets and challenges use exact reads from `crypto/rand.Reader`, reject repeated all-zero output,
  and expose failure/short-read controls only under the `zkaudit` build tag. Compressed proof framing
  is a public protocol constant, `CompressedProofSize = 164`, checked before parsing or database work.
- Tree advisory locks are derived from a subsystem namespace and configured schema rather than a
  database-global integer. Dummy verifications now preserve `RATE_LIMITED` when the shared
  per-replica verification semaphore is full.
- kal v0.5.1's additive `0004_zk_hardening.sql` enforces disjoint recurring/one-shot nullifier row
  shapes. `0002_zk.sql` remains unchanged; its preflight query must return no rows before upgrade.
- The 147-case vulnerability register is audit-complete: zero roadmap, partial or blocked cases.
  Analytical/manual evidence is versioned in `docs/audits/v0.1.0.md` and public release requires a
  cryptographically signed annotated tag. CI tests PostgreSQL 14 and 18 as non-superuser owners and
  reconciles every discovered `TestDBZK*` test exactly. The executable 55-entry mutation manifest
  first proves each named control green, then requires that exact test—not compilation or setup—to
  kill its isolated kal/kal-zk mutant; the release run is 55/55.

### Added

- Initial release, extracted from `github.com/ulas96/kal` at v0.4.0 and hardened before publication:
  `zkauthn` (Groth16/BN254 knowledge and membership proofs over a Postgres sparse Merkle credential
  tree, pseudonymous login) and `zkauthz` (request-local proven claims behind `@auth(proves:)`).
  Requires kal ≥ 0.5.1.

  The move is why the module exists. In kal these two packages made `consensys/gnark` a direct
  require of every consumer's module graph — 116 packages compiled by applications that never issued
  a proof. Here, the cost falls on the deployments that asked for it.

  There is **no root facade package** and none should be added. kal carried roughly fifty `ZK*`
  aliases and wrappers by hand, and a symbol nobody remembered to add was reachable only in the
  sub-package, bypassing whatever the wrapper did. Twelve lines of explicit wiring in your own code
  beats a `kalzk.Install(&cfg)` that mutates a config it does not own.

  **Rollout.** Consumers of kal ≤ 0.4.0 with `Config.ZK` set: add this module and rewire; the full
  before-and-after is in `README.md`. Four things are easy to get wrong.
  `kal.LoadZKVerifyingKey` becomes `zkauthn.LoadVerifyingKey`. `MFAWindow` and `TableSchema` are now
  passed to both `kal.Config` and the kal-zk constructors and each pair must agree — kal used to
  guarantee that, and two MFA windows let a stale elevation replace a second factor while two
  schemas silently address different tables. `auth.ZK` is gone; hold the service yourself. And
  `kal.Config.SensitiveFields` **replaces** kal's defaults rather than extending them, so the
  aliasing guard no longer covers your ZK mutations unless you say
  `SensitiveFields: append(kal.DefaultSensitiveFields(), zkauthn.SensitiveFields...)`. Without that
  line, `mutation { a: zkLogin(…) b: zkLogin(…) … ×500 }` is one HTTP request and five hundred proof
  attempts, and nothing errors.

- `zkauthn.SensitiveFields`: the six mutation names kal's aliasing guard used to protect by default
  and no longer knows about. Append it to `kal.Config.SensitiveFields`; the reason is entry 200 in
  `docs/gotchas.md`. `TestZKSensitiveFieldsMatchEntryPoints` pins each name to the `*ZK` method it
  fronts — a correspondence and deliberately not a count, because a length check passes after a
  rename, which is the exact edit that breaks it.

- `TestDBZKSchemaContract`: asserts that the core columns `zkauthn/sql.go` reads and writes —
  `auth_users.id`, `password_hash`, `deleted_at`, `email`, `email_verified` — still exist in kal's
  migrations with a compatible type. New here because it could not fail before: inside one module a
  column rename and its dependent SQL were reviewed together, and across two they are not. SQL is
  not compile-checked, so without this the failure arrives at runtime, on the enrolment path, in
  production.

- `TestZKINV001NoRootFacade` and `TestZKTreeDepthIsCompileTime`. Both cases were previously covered
  by kal's `TestZKReExportedConstants`, which asserted the re-export shim's constants matched their
  sources. The shim is what the split deleted, so ZK-INV-001's obligation is restated as the
  invariant that replaced it — the module root holds no Go files, so there is exactly one way to
  reach every symbol and no second unguarded API is possible. ZK-TRE-013 carries over unchanged:
  `MerkleDepth` is a constant, `MembershipCircuit.Path` is `MerkleDepth+1` long, and no `Options`
  field can move either.

- `docs/gotchas.md` carries entries 40–63 with their original kal numbering, because they are cited
  from code comments and from `tests/`. New entries in this repository start at 200: **200** on
  `SensitiveFields` replacing rather than extending, **201** on `MFAWindow` and `TableSchema` being
  passed to two libraries with nothing reconciling them.

### Note

- **This module ships no migrations.** The eight `auth_zk_*` tables stay in kal's
  `migrations/0002_zk.sql`, byte-unchanged, and their names stay in `kal/migrations.Tables()`.
  Production databases have applied that file under kal's numbering and their migration trackers
  hold a row for it; moving it would strand that row or force a renumber. SQL text carries no Go
  dependency, so leaving it in kal removes nothing from anyone's module graph — `gnark` leaves
  either way. The test harness reads the schema from `kal/migrations` and gets a complete one.
