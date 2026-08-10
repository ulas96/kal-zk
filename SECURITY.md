# Security

## Reporting a vulnerability

Open a private security advisory on the GitHub repository. Please do not open a public issue for
anything exploitable.

A vulnerability in a proof system is often a soundness bug rather than a memory-safety one: it looks
like a proof that verifies and should not, or a nullifier that links two sessions that should be
unlinkable. Those are in scope and are the ones worth reporting first.

## What kal-zk defends against, and how

Each control names the test that fails without it. They live in `tests/`, and the DB-backed ones need
`DATABASE_URL` — a skipped test still reports `ok`, which is why CI discovers every top-level
`TestDBZK*` name and requires exactly one pass and zero skips for each.

kal-zk sits on top of `github.com/ulas96/kal` and inherits its session, password and transport
controls unchanged; this document covers only what this module adds. kal's own `SECURITY.md` is the
other half.

Only depend on this module if you have read the rest of this section. Each row names a test that
exists and runs; a row whose test you cannot point at is a control that is not there.

| control | the test that fails without it |
|---|---|
| Public-input binding | `TestZKCIR001PublicInputBinding` — a tampered root, audience, threshold, nullifier or challenge is refused against a real proof |
| Native/in-circuit hash agreement | `TestZKHSH001NativeAndCircuitMiMCAgreement` — two independent MiMC implementations agree, and disagree on a perturbed output |
| Circuit identity | `TestZKCircuitID` — the pinned constraint counts and R1CS hashes, so a key cannot outlive its circuit |
| Under- and over-constraining | `TestZKDifferential` — 2000 witnesses, circuit against a plain-Go oracle, in both directions |
| Challenge freshness | `TestDBZKChallengeReplay` — a proof is not a bearer token; the same one fails twice |
| Challenge survives a bad proof | `TestDBZKChallengeSurvivesFailedProof` — a failed verification does not burn the honest holder's challenge |
| One-shot single use | `TestDBZKNullifierSingleUse` — eight concurrent valid proofs, one allowance spent |
| One-shot not burned on delivery failure | `TestDBZKOneShotSurvivesUnmountedMiddleware` — no nullifier row for an action that never ran |
| Duplicate claim counting | `TestZKRequestClaimsCountsDuplicates` — one grant does not satisfy `proves: ["vote","vote"]` |
| Pseudonym confinement | `TestDBZKLoginRejectsBoundAccount` — a credential cannot mint a session on a real account, and leaves no session row trying |
| Bounded account growth | `TestDBZKLoginDoesNotGrowUsers` — five logins, one `auth_users` row |
| Recurring pseudonym stability | `TestDBZKPseudonymRecurs` — the same credential returns the same pseudonym |
| Enrolment step-up | `TestDBZKEnrolmentNeedsStepUp` — a wrong password leaves the stored commitment byte-identical |
| Factor replacement revokes sessions | `TestDBZKReenrolmentRevokesSessions` — a session held elsewhere stops resolving |
| Login eligibility is explicit | `TestDBZKLoginNeedsLoginClaim` — a recurring step-up claim mints no session |
| Server-side policy | `TestDBZKThresholdFromPolicy` — a request-supplied threshold does not override the claim row |
| Revocation removes membership | `TestDBZKRevokedCredential` — a revoked leaf no longer proves against the current root |
| Revocation is not rolled back | `TestDBZKRevokeRepublishesRoot` — revoking the highest live leaf still sets `revoked_at` |
| Tree write serialization | `TestDBZKConcurrentEnroll` — concurrent issuance publishes a root every path verifies against |
| Verification holds no transaction | `TestDBZKVerifyHoldsNoTransaction` — a bad proof is refused without a transaction ever being opened |
| Session-bound claims | `TestDBZKE2E002KnowledgeFillsMFASeam` — elevation belongs to the session, not the user, and does not survive re-login |
| No cross-satisfaction between claims | `TestDBZKE2E003MembershipSatisfiesProvesAndOnlyThat` — proving `is_member` does not grant `age_over_18` |
| Pseudonymous sessions carry no attribution | `TestDBZKE2E001LoginYieldsScopedSession` — no `ip`, no `user_agent`, from a request that supplied both |
| Replica agreement | `TestDBZKE2E005TwoReplicasAgree` — two instances, one database, symmetric behaviour |
| Anonymity at the database | `TestDBZKE2E006AnonymousAtTheDatabase` — twelve members, no column or join narrows below twelve |
| Adversarial circuit boundaries | `TestZKCIR004AdversarialFamilies` — all fifteen raw-field families, both directions, including `r-1`, `2^64` and the rightmost leaf |
| Fail-closed issuance | `TestDBZKENR001IssuanceAuthorization` — nil, anonymous and ordinary callers cannot reach entropy or the database; an explicit issuer callback can |
| Verification admission | `TestDBZKAuditVerificationBound` — real and dummy paths share the exact per-replica semaphore and preserve `RATE_LIMITED` |
| Nullifier row shape | `TestDBZKNullifierSchemaShape` — the live primary key and recurring/one-shot disjunction reject illegal raw SQL |
| Uniform failures | `TestDBZKORCUniformFailures` — malformed proof, unknown claim and retired root share code/message and leave state unchanged |
| Full register | `TestZKINV003ExternalCaseCoverage` plus [`docs/audits/v0.1.0.md`](docs/audits/v0.1.0.md) — 147 unique cases, zero roadmap/partial/blocked |

### What the ZK module's anonymity claim actually means

**The anonymity set is the intersection of non-revoked leaves and leaves present at the client-named
root, and nothing larger.** A proof says "some member of this version of the tree satisfies this
policy". With twelve live credentials present at that root it is one-in-twelve. With one it is
one-in-one and identifies its holder exactly. An older root accepted during `RootGrace` excludes
credentials enrolled later and can disclose a synchronization/enrollment window.

**The operator is the verifier, and they are not different parties.** kal runs verification inside
your process, on your database. Nothing here constrains an operator who wants to lie: they can return
`true` for a proof that did not verify, log what they like, or add a column tomorrow that joins a
nullifier to a member. Groth16 gives the *member* assurance against a *third party* reading the
database later; it gives nobody assurance against the party running the code. (Also worth stating
plainly: these are Groth16 circuits with a per-circuit trusted setup, not PLONK with a universal
one. Whoever ran `Setup` could forge proofs for that circuit if they kept the toxic waste. If that
matters to your threat model, the ceremony is the thing to scrutinise, not the verifier.)

**The prover is a client you package.** kal ships verifying keys and circuits, not a prover bundle.
Whatever JavaScript, WASM or native client you ship computes proofs *and holds the member's secret*.
A compromised prover is a compromised credential, and no server-side control in this file reaches it.

**Enrolment-to-first-use timing correlates.** `auth_zk_credentials.created_at` and
`auth_zk_nullifiers.first_seen_at` are both timestamps in the operator's own database. A member who
is issued a credential and immediately uses it links the two rows by nothing more than clock
proximity. The narrower the issuance window, the sharper the correlation; issuing in batches and
expecting delayed first use is the mitigation, and it is operational, not cryptographic.

**`issued_to` is a deliberate disclosure.** `auth_zk_credentials.issued_to` records which account
received which leaf, which means the operator can revoke a specific member's credential — and means
the credential is not anonymous *at issuance*. Only its *use* is anonymous: nothing links `issued_to`
to the nullifier a proof presents. Dropping the column would buy anonymity at issuance and would take
`RevokeCredentialsForUser` with it. kal keeps revocation. If your threat model prefers the other
trade, do not set `issued_to`, and accept that revocation becomes per-leaf and manual.

**The hashed challenge primary key is not a defence against a database reader.**
`auth_zk_challenges.challenge` stores `sha256(token)` rather than the token, the way
`auth_sessions` stores a session token. That analogy does not carry: the adjacent `field` column
holds the same 31 random bytes the token base64-encodes, because it is the public circuit input a
proof commits to, so anyone who can read the table recovers the token by re-encoding `field`. It
does not need to be secret. A challenge is a nonce, not a bearer credential — it is bound to a
purpose and a session, it is single-use through one atomic UPDATE, it expires in sixty seconds, and
holding it still buys nothing without a proof that verifies against it. Do not reason about
`challenge` as if the hash confined the token; the reader who can see one can see the other.

**Credential revocation and session revocation are separate.** Removing a leaf prevents new proofs
once its accepted-root grace closes. It cannot retroactively identify and revoke an already-issued
unlinkable pseudonymous session. If policy needs both, call the session revocation operation too.

**Reissue changes identity.** A replacement membership credential has a new generated secret, hence
a new nullifier and a new pseudonymous account. Old application rows remain owned by the old account.
Continuity requires an explicit application-level migration; using `issued_to` implicitly would turn
the operator's revocation map into the authentication link the protocol is designed not to have.

**Thresholds compose.** Each public threshold result reveals one policy bit about the private
attribute. Several claims over the same attribute can narrow it to a bracket; N thresholds disclose
up to N such bits.

**Claims bind to sessions.** Two distinct credentials can contribute two recurring claims to one
session. `proves: ["x", "y"]` is a conjunction over that session, not proof that one secret satisfied
both. One-shot claims exist only in the request that proves them and are not inherited by later
requests or new sessions.


## What kal-zk does not defend against — your responsibility

**The prover is a client and its bundle is your trust boundary.** The server never loads a proving
key; packaging and shipping the prover — a JavaScript/WASM bundle, a mobile client, a CLI — is
yours. A client that computes proofs also holds the member's secret, so a compromised prover bundle
is a compromised credential for every member who loads it. Version and pin it the way you would any
other credential-handling code.

**The anti-batching guard is opt-in now.** kal's default list no longer knows these mutations
exist. Append `zkauthn.SensitiveFields` to `kal.Config.SensitiveFields` or five hundred proof
attempts fit in one HTTP request. Entry 200 in `docs/gotchas.md`.

**`MFAWindow` and `TableSchema` are passed to both libraries and nothing reconciles them.** Entry
201.

## Supported versions

The latest minor release, with PostgreSQL 14 through 18. The CI compatibility endpoints are 14 and
18 under non-superuser database owners. While the major version is `0`, security fixes land on
`main` and in the next minor rather than being backported.
