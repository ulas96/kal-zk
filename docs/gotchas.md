# Gotchas

Things that fail silently. Each entry is here because the failure produces no error, no log line and
a passing test suite — which is the only kind of bug worth a register like this.

Entries 40–63 were written in `github.com/ulas96/kal` and keep their original numbers, because they
are cited from code comments and from `tests/`. New entries in this repository start at **200**, so
the two registers allocate from disjoint ranges and neither has to ask the other for a number.

## Circuits

**40 · An under-constrained circuit proves a false statement.** Honest witnesses also satisfy an
under-constrained system, so tests must compare a plain-Go oracle with the circuit in both directions.

**41 · `Path[0]` is prover-supplied.** Merkle verification without binding it to the prover's
secret proves that some public leaf exists, not that the prover knows its secret.

**42 · A public input the circuit never reads is not bound to the proof.** Both ZK circuits spend
one explicit multiplication binding the challenge; removing it turns a proof into a replayable token.

**43 · Groth16 proofs are malleable.** Deduplicating proof bytes is not replay protection. A
server challenge must be a public input consumed by the circuit and atomically burned.

**44 · One hash domain for two purposes is a domain-crossing bug.** Knowledge commitments,
membership leaves, nullifiers and empty leaves use separate versioned domain elements.

**45 · Values at or above the field modulus wrap silently.** Secrets and audiences are 31 bytes,
attributes are range-checked to 64 bits, and all field encodings are canonical before gnark sees them.

**46 · Comparing an attribute that was never range-checked is not the policy comparison.** The
membership circuit bounds the attribute to 64 bits before checking its threshold.

**47 · `test.IsSolved` proves only that one witness satisfies the system.** The false-to-reject
half of a differential test is the part that catches a missing constraint.

## The gnark surface

**48 · `merkle.VerifyProof` calls its leaf-index parameter `leaf`.** The leaf value is `Path[0]`;
passing those two field elements in the opposite positions compiles and proves a different tree.

**49 · Reordering circuit fields changes the public-witness layout.** The declaration order is
part of the protocol and is pinned by the circuit identity, not merely by the constraint count.

**50 · `UnsafeReadFrom` skips curve and subgroup checks.** Proofs and keys use `ReadFrom`; verification
does not repair an unsafe deserialization performed earlier.

**51 · Native and in-circuit MiMC are separate implementations.** A cross-implementation test pins
their byte and field-element conventions before a mismatch makes every valid proof fail.

## The tree and the protocol

**52 · An empty leaf of zero is a credential target.** Empty leaves are a domain-separated MiMC
constant, so finding a credential equal to one requires a collision rather than a preimage for zero.

**53 · An in-memory tree is a different root per replica.** Sparse nodes and roots live in Postgres,
so restarts and multiple pods observe one tree.

**54 · Concurrent appends can publish a root no path verifies against.** A transaction-scoped
advisory lock is acquired before the first tree read and held through node and root publication.

**55 · A retired root that still verifies is a revoked credential that still authenticates.**
`RootGrace` is explicitly revocation latency and defaults to accepting only the current root.

**56 · A nullifier that is both a pseudonym and single-use is neither.** Recurring audiences keep
their nullifier as a stable account key; one-shot audiences burn it for exactly one action.

**57 · A nullifier checked by `SELECT` then `INSERT` is not single-use.** The primary key and one
atomic insert decide the winner under concurrency.

**58 · A public input copied from the request is attacker policy.** Roots are validated, challenges
are server rows, and audiences and thresholds come from the named claim row.

**59 · A proof not bound to an audience replays at another endpoint.** The nullifier circuit input
includes the policy-supplied audience.

## Proving keys and operations

**60 · A swapped verifying key is a universal bypass.** Key bytes are hashed and compared with a
consumer-pinned SHA-256 before parsing; no proving or verifying keys live in this repository.

**61 · Verification is unauthenticated CPU.** Proof length is checked before parsing and a short-
timeout semaphore bounds pairing work; challenge issuance also cleans up its 60-second rows.

**62 · Session IP and user-agent metadata undo a pseudonym with one join.** ZK login always calls
session issuance with a zero `Meta`; this is deliberately not configurable.

**63 · A fast "no commitment enrolled" path is an enrolment oracle.** Knowledge verification uses
one public error and performs a real dummy pairing check while holding the same semaphore slot.


## Depending on kal

**200 · A config field that replaces a default list silently drops what the default protected.**
`kal.Config.SensitiveFields` replaces kal's aliasing-guard list rather than extending it. A
deployment that sets its own names, or that upgraded across the module split without appending
`zkauthn.SensitiveFields`, loses the guard on every ZK mutation — five hundred proof attempts in
one document, one hit on any request-counting limiter. Nothing errors and no test fails, because
the guard's job is to reject documents nobody legitimate sends. Say
`SensitiveFields: append(kal.DefaultSensitiveFields(), zkauthn.SensitiveFields...)`.

**201 · `MFAWindow` and `TableSchema` are passed twice, and nothing reconciles them.** `kal.New`
used to guarantee both agreed because it constructed the ZK service itself. Now the consumer sets
them on `kal.Config` and again on `zkauthn.Options`/`zkauthz.New`. Two MFA windows let a deployment
tighten step-up for its directive-guarded fields while a stale elevation still replaces the second
factor. Two schemas is worse and quieter: each package renders its own prefix and both succeed,
against different sets of tables. Assert the equality in your own wiring — neither library can.
