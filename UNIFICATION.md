# Unification: One Stack, One Truth

This document records the consolidation of AlephNet Node from **three parallel,
non-interoperating stacks** into a single TypeScript codebase, and the decisions
taken along the way.

## The problem

A deep review found the repository contained three implementations of the same
product, none of which fully worked:

| Stack | Status before unification |
|---|---|
| `lib/` (legacy CommonJS, ~70k lines) | Feature-complete on paper, but the semantic engine ran entirely on stub fallbacks, and the server layer **could not boot at all** |
| `src/` (TypeScript rewrite) | The npm `main`, cleanest architecture, but largely unwired: security not enforced, several core paths were mocks |
| `lib/app/` (HTTP server) | Contained ESM `import`/`export` syntax inside a CommonJS package — `SyntaxError` on load |

Symptoms that mattered most:

- The flagship "sentient" math never executed. `@aleph-ai/tinyaleph` is ESM-only;
  the legacy code `require()`d it synchronously *and* defeated its own lazy
  loader by destructuring getters at import time. Every metric was a hardcoded
  `0.5` or a `NaN`.
- HTTP authentication was forgeable: the verify path never checked the signature
  field, never bound the fingerprint to the public key, and never covered the
  request body.
- The token economy was simultaneously exploitable (uncapped mint, replayable
  credits) and non-functional (stakes never left the spendable balance, rewards
  were credited through a mismatched API and silently dropped).
- Consensus had no signatures, a 3-vote quorum over self-declared identities,
  and a verification path that could never accept a wire proposal.

## The decision

**Unify on TypeScript (`src/`), port the good ideas out of `lib/`, delete the
duplicates.**

Rationale: `src/` was already the published `main`, had the only working test
suite, real Ed25519 primitives, clean module boundaries and strict typing. The
legacy stack's value was its *feature surface* and *domain ideas*, not its
implementation — so features were re-implemented rather than copied.

157 legacy files were deleted (`lib/`, root `index.js`, `scripts/`, the
migration plan). Nothing in `src/` ever imported `lib/`, so removal was clean.

## What was kept, from where

| Feature | Origin | Where it lives now |
|---|---|---|
| Prime oscillators, 16-axis SMF, holographic memory, emergent moments, safety monitor | `lib/prsc.js`, `smf.js`, `hqe.js`, `sentient-core.js`, `safety.js` | `src/semantic/` |
| Identity, friends, profiles, groups, feed, DMs, content store | `lib/identity.js`, `friends.js`, `groups.js`, `direct-message.js`, `content-store.js` | `src/social/` |
| Token units, gas, staking tiers, faucet | `lib/wallet.js`, `aleph-token/`, `actions/faucet.js` | `src/economy/` |
| Claims, staked verification market | `lib/coherence/` | `src/coherence/` |
| HTTP server, auth, SSE streaming, actions API | `lib/app/`, `lib/auth-middleware.js` | `src/app/` |
| Consensus, GMF, DSN node, SRIA, wallet ledger, trust services | already in `src/` | hardened in place |
| Composition root, CLI entrypoint | new | `src/node/` |

Dropped deliberately: `express`, `body-parser`, `cors`, `node-fetch` (the app
layer needs only `http` + `ws`); the "quantum" KeyTriplet resonance theater
(`Math.random()` phases contributing no security); the mock formal-verification
"proofs"; four dead modules (`memory-broker`, `memory-manager`,
`binary-serializer`, `snapshot-integrity`) and the unmounted Express routers.

## Bugs fixed during the port

### Semantic engine
- **ESM loading**: `src/semantic/tinyaleph.ts` performs a genuine dynamic
  `import()` via `new Function` so TypeScript cannot downlevel it to `require`,
  memoizes the module, validates the export surface, and exposes an explicit
  `degraded` flag. It never substitutes fake numbers.
- **Inverted damping sign**: legacy `evolve()` damped high-energy cells *less*,
  so the field grew without bound. Corrected, with a test asserting total energy
  is non-increasing under pure dissipation.
- **Fake inverse DFT**: legacy used golden-ratio/log-prime frequencies that are
  not an orthogonal basis, so encode→reconstruct never round-tripped. Now uses
  integer wavenumbers; round-trip is asserted.
- **Phase-blind similarity**: legacy correlated `|H|²`, scoring a pattern and its
  phase-inverse as identical. Now the signed real part of the complex correlation.
- **Dead entropy lock**: trace entropy was hardwired to `1.0` against a `0.8`
  threshold, so "locked memories" were permanently empty. Replaced with a
  working consolidation rule; prune no longer double-counts removals.
- **Fail-open safety**: the safety layer returned `safe: true` unconditionally.
  Now **fail-closed** — unknown actions, unknown constraints and non-finite
  metrics all deny.
- **Process-killing events**: the legacy emitted `'error'` on an EventEmitter
  with no listener from inside a `catch`. Replaced with typed Subjects.

### Security
- **Request authentication** (`src/app/AuthMiddleware.ts`): mandatory Ed25519
  verification over method, path, timestamp, nonce **and a hash of the body**;
  the fingerprint is recomputed from the verified key and compared; replays are
  rejected by a bounded, evicting nonce cache. The `ALEPH_DEV_NO_AUTH` env
  backdoor is gone — a bypass now requires an explicit constructor
  acknowledgement and refuses to construct under `NODE_ENV=production`.
- **Path traversal**: `path.resolve` + `path.relative` containment (the legacy
  `startsWith` check accepted sibling directories), re-validated after the
  directory→`index.html` join, with symlink realpath checks.
- **Consensus** (`src/core/Consensus.ts`): votes deduplicated by voter, weights
  **recomputed locally** instead of trusted from the wire, exact 2/3 threshold,
  minimum 3 distinct voters, invalid tick proofs and sub-threshold coherence
  rejected before tallying, and `computeSmfHash` is a real SHA-256.
- **GMF** (`src/core/GMF.ts`): inserts require `consensusAchieved`, deltas are
  validated against the hash chain with replay rejection, snapshots commit to
  SMF and normal form rather than just `id:weight`.
- **Trust pipeline**: the cache is no longer consulted before signature
  verification, and cache keys include the verified author fingerprint, so
  copied content hashes cannot inherit another author's trust. Endorsement
  signatures are actually verified. `TrustGate.checkAll` computes assessments
  internally instead of accepting caller-supplied ones.
- **Social layer**: every mutation requires a verified `SignedAction`; actor
  identity always comes from the signature, never from an input field (the
  legacy accepted `authorId: 'system'`). Private keys are encrypted with a
  per-identity random salt and written `0600`. DM bodies are genuinely
  AES-256-GCM encrypted, or honestly reported as `encrypted: false`.
- **Content store**: requester identity is required on reads and visibility is
  enforced; content hashes must be 64 lowercase hex before any path operation.

### Economy
- All amounts are `bigint` base units (18 decimals). No floating-point money
  anywhere; HTTP callers pass decimal strings, parsed via `parseTokens`.
- The faucet drip is server-fixed (callers cannot choose an amount), the
  treasury is finite and capped, the HMAC secret is injected rather than
  hardcoded, the challenge and Ed25519 claim signature are actually verified,
  proof-of-work uses configurable leading-zero bits, and cooldown is keyed on
  the **verified** fingerprint.
- Staking moves real funds, slashing really debits, rewards really credit, tier
  thresholds use `>=` (a stake of exactly 100 now reaches Adept), and restaking
  cannot shorten an existing longer lock.
- Self-verification is rejected; rewards are paid only on the correct outcome
  and require verifier stake at risk.
- `RewardCalculator` no longer throws `BigInt(NaN)` when `lastRewardClaim` is
  absent; `unstake` bounds-checks against staked balance; `transfer` serializes
  per-address to prevent double-spend.

### Reliability
- `DSNNode` persists its identity (previously a fresh keypair every restart),
  never writes the private key to the mesh graph, and refuses to double-start.
- `SRIAEngine` runs the full perceive→decide→act→learn cycle, enforces legal
  state transitions, and its policy objective is no longer **inverted** —
  previously the expected-free-energy sign meant policies *farther* from the
  goal were preferred.
- `TaskManager` awaits executions, supports an injectable executor and result
  sink instead of returning `"Simulated output"`, fixes the day-of-month
  off-by-one, and clears retry timers on `stop()`.
- `SemanticStore.query` returns real results from a live index (it previously
  always returned zero) and enforces visibility.

## Architecture

```
src/
  common/      crypto (Ed25519, AES-GCM), math, hashing, logging, patterns
  semantic/    oscillators, SMF, holographic memory, observer, safety
  social/      identity, signed actions, friends, profiles, groups, DMs, content
  economy/     bigint units, gas, staking, faucet
  coherence/   claims, staked verification market
  core/        DSN node, consensus, GMF, SRIA, tasks, skills, Gun bridge
  services/    embeddings, trust, reputation, routing, domains, health
  infra/       wallet ledger, security, event bus, errors
  storage/     semantic content store
  app/         HTTP server, auth, router, SSE, static, action registry
  node/        composition root (AlephNode), action modules, CLI entrypoint
```

Dependency direction is one-way: `node → app → {semantic, social, economy,
coherence, core, services, infra, storage} → common`. Domain modules never
import each other; they are composed in `src/node/`.

## Explicit degradation

The legacy code's worst habit was pretending to work. Optional dependencies now
degrade **loudly**:

| Subsystem | Requires | Without it |
|---|---|---|
| `semantic` | `@aleph-ai/tinyaleph` | loads or reports `degraded: true`; never fabricates metrics |
| `economy` | a Gun instance (ledger) | disabled with reason; actions return `SUBSYSTEM_UNAVAILABLE` |
| `faucet` | Gun ledger **and** `ALEPH_FAUCET_SECRET` | disabled, listing every missing prerequisite |
| identity persistence | `ALEPH_IDENTITY_PASSWORD` + `--data` | ephemeral identity with a startup warning; the key is never written in plaintext |

`GET /status` and the startup banner report this matrix.

## Running it

```bash
npm install
npm run build
npm start -- --port 31337 --host 127.0.0.1     # or: npm run dev
```

Requests must be signed. `createSignedRequestHeaders` in `src/app` produces the
headers; unsigned calls to authenticated actions return 401.

## Verification

- `npx tsc --noEmit` — clean under `strict`, `noImplicitOverride`,
  `noFallthroughCasesInSwitch`
- `npm test` — 44 suites, 694 tests passing (was 81 tests with a suite that
  could not compile)
- `node dist/node/bin.js` — boots, serves, enforces auth, shuts down gracefully

## Known limitations

- The token economy is an internal ledger over Gun, not a blockchain. Transfers
  are serialized per-address in-process; cross-node atomicity is not solved.
  `StoreBackedNonceStore` similarly guarantees single-process atomicity only —
  multi-process deployments must provide their own CAS.
- `src/core/network` message transport is still a thin layer; signed messages
  have no full receive/verify path across peers yet.
- Embeddings require `OPENAI_API_KEY`; without it, embedding-backed search is
  unavailable rather than approximated.
- WebSocket support is present but disabled unless a path is configured.
- Identity fingerprints are 64-bit (first 8 bytes of SHA-256) — adequate for
  display and in-mesh lookups, not for adversarial collision resistance.
- Consensus (`Consensus.ts`) requires an operator-supplied `voterRegistry` to
  anchor voter identities, and `GlobalMemoryField` requires a
  `GMFConsensusVerifier` to accept peer deltas — without them both fail closed.
- Endorsement scoring in `TrustEvaluator` is dampened against minted-identity
  farming but does not yet anchor endorser reputation to a network-wide trust
  root.

## Post-review hardening

After the first review of the unified stack, a second pass closed the remaining
findings across all nine modules (coherence, economy, wallet/tasks/events, app,
social, core/services, semantic, node, storage). Headlines:

- **Coherence market**: settlement outcome is derived from stake-weighted
  verifier majority (or an injected authority) — never caller-supplied;
  `expireTask` requires the deadline and authority; per-task escrow accounting
  eliminates cross-task theft; state-first settlement makes payouts
  exactly-once; claims are backed only through real escrow (`backClaim`).
- **Auth**: the nonce cache is partitioned per identity so an attacker cannot
  force-evict a victim's live nonce; an aggregate per-IP rate limit closes the
  path-spray evasion; error writes are headers-sent-safe; the TTL-vs-freshness
  invariant is validated at construction; static serving pins dev/ino against
  the opened handle (TOCTOU closed) and caps file size.
- **Social**: DM membership re-validates the friend/block graph on every
  access; the profile cache is requester-scoped; content-store mutations
  require verified signed envelopes (no bare owner parameters); KDF parameters
  are bounded against downgrade attacks; identity saves are atomic.
- **Economy**: faucet claims commit their single-use reservation before any
  await (concurrent double-claims rejected); `parseTokens` accepts only
  canonical forms; staking positions reconcile from the ledger and serialize
  through a mutex.
- **Wallet**: every balance mutation is per-address serialized; corrupt stake
  records reject instead of hanging; `executeTask` resolves only with the
  final settled execution; event sequences survive restarts.
- **Consensus/GMF**: voter ids are normalized and anonymous ballots cannot
  contribute weight or quorum; peer GMF deltas require a consensus verifier
  (fail closed); snapshot hashes are length-prefixed.
- **Semantic**: the loader reports degraded status truthfully and always tries
  the fallback; holographic bases follow the primes actually encoded;
  `clampRange` throws instead of fabricating values; similarity math is
  overflow/underflow-stable; pre-init metrics throw; recall no longer mutates
  observer state.
- **Node**: every optional subsystem declares an `availability` gate so an
  outage reports `SUBSYSTEM_UNAVAILABLE` before any tier check; a Gun ledger
  is validated structurally; wallet/staking caches are LRU-bounded; tier
  resolution is memoized; `submitClaim` escrows stakes for real.
