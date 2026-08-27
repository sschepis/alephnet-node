/**
 * Node Layer — Types
 *
 * Configuration, subsystem wiring and status types for the composition root.
 *
 * This layer is the ONLY place that imports domain modules together. The
 * domain layers never import each other; `AlephNode` builds every subsystem
 * here and hands typed bundles to the action module factories.
 *
 * Degradation is explicit and typed: every optional subsystem
 * (semantic/tinyaleph, economy/Gun, faucet/secret) carries a boolean
 * `enabled` plus the exact reason it is off. There is no silent stub
 * anywhere in this layer — the single biggest sin of the deleted legacy
 * code.
 */

import type { Logger } from '../common/logging';
import type { ClaimRegistry, VerificationMarket } from '../coherence';
import type { Faucet, StakingService } from '../economy';
import type { AlephWallet } from '../infra/Wallet';
import type { SemanticObserver } from '../semantic';
import type {
  ActionVerifier,
  ContentStore,
  FeedManager,
  FriendGraph,
  Groups,
  Profiles,
  SignedAction,
  SocialStore
} from '../social';
import type { AuthenticatedIdentity } from '../app';

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Raised when an AlephNode cannot be created or started. Always carries a
 * stable machine-readable code and a readable message — raw stacks are for
 * logs, never for stderr.
 */
export class AlephNodeStartupError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'AlephNodeStartupError';
    this.code = code;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

/** Options controlling semantic kernel failure behaviour. */
export interface AlephNodeSemanticOptions {
  /**
   * When true (the default) a failed tinyaleph load DEGRADES the semantic
   * subsystem (disabled + recorded reason) instead of failing startup.
   * When false, `AlephNode.create()` rejects with an
   * `AlephNodeStartupError`.
   */
  readonly degradedOk?: boolean;
}

/**
 * Everything `AlephNode.create()` needs.
 *
 * Optional dependencies are genuinely optional: omitting `gun` disables the
 * economy, coherence market and faucet; omitting `faucetSecret` disables the
 * faucet; omitting `identityPassword` yields an EPHEMERAL identity (the
 * private key is never written to disk in plaintext).
 */
export interface AlephNodeConfig {
  /** TCP port. Defaults to 0 (ephemeral) — bind a real port in deployment. */
  readonly port?: number;
  /** Bind host. Defaults to 127.0.0.1. */
  readonly host?: string;
  /** Persistence directory for the identity and social store. */
  readonly dataDir?: string;
  /** When set, static files are served for non-API GET/HEAD requests. */
  readonly staticPath?: string;
  /** Exact-match CORS Origin allowlist. Empty = same-origin only, never `*`. */
  readonly corsOrigins?: readonly string[];
  /**
   * Optional Gun instance. Required by `AlephWallet` (its ledger), so without
   * it the economy, faucet and coherence verification market are DISABLED.
   */
  readonly gun?: unknown;
  /**
   * HMAC secret for the faucet. Accepted as a Buffer or a utf8 string; must
   * be >= 32 bytes (enforced by `Faucet`). Without it the faucet is DISABLED.
   */
  readonly faucetSecret?: Buffer | string;
  /** Lifetime payout ceiling for the faucet, in base units. */
  readonly treasuryCap?: bigint;
  /**
   * Password for the persisted node identity. When set together with
   * `dataDir` the identity is loaded (or created and saved, encrypted).
   * When unset an EPHEMERAL identity is generated and a warning is logged.
   */
  readonly identityPassword?: string;
  /** Semantic kernel failure behaviour. */
  readonly semantic?: AlephNodeSemanticOptions;
  /**
   * Explicit, non-production auth bypass. Refused outright when
   * NODE_ENV=production.
   */
  readonly devAuthBypass?: boolean;
  /** Register the (one-time) SIGINT/SIGTERM shutdown step. Default false. */
  readonly installSignalHandlers?: boolean;
  /** Optional logger override (tests). */
  readonly logger?: Logger;
}

// ═══════════════════════════════════════════════════════════════════════════
// SUBSYSTEMS
// ═══════════════════════════════════════════════════════════════════════════

/** Names of the subsystems a node reports on. */
export type SubsystemName =
  | 'semantic'
  | 'social'
  | 'content'
  | 'economy'
  | 'faucet'
  | 'coherence';

/**
 * One subsystem's state. `enabled === false` implies a non-null `reason`;
 * a disabled subsystem is never silently faked.
 */
export interface SubsystemStatus {
  readonly name: SubsystemName;
  readonly enabled: boolean;
  /** Why the subsystem is disabled; null when enabled. */
  readonly reason: string | null;
  readonly detail?: Record<string, unknown>;
}

/** The semantic subsystem, degraded or not. */
export interface SemanticSubsystem {
  readonly enabled: boolean;
  readonly reason: string | null;
  /** null while disabled — no observer, no fake metrics. */
  readonly observer: SemanticObserver | null;
}

/** The social subsystem (always available; needs only a local store). */
export interface SocialSubsystem {
  readonly enabled: boolean;
  readonly reason: string | null;
  readonly store: SocialStore;
  /** Shared verifier used by every social domain component. */
  readonly verifier: ActionVerifier;
  /**
   * Separate verifier used ONLY to bind a client-supplied envelope to the
   * HTTP-authenticated caller before the domain re-verifies it. Keeping a
   * private nonce store here avoids burning the domain verifier's nonce.
   */
  readonly bindVerifier: ActionVerifier;
  readonly friends: FriendGraph;
  readonly profiles: Profiles;
  readonly groups: Groups;
  readonly feed: FeedManager;
  readonly content: ContentStore;
  /**
   * Build a node-attested `SignedAction` envelope carrying the
   * HTTP-authenticated caller as the author. The node signs with its own
   * key (it never holds client private keys); the stores consuming these
   * envelopes verify the node signature plus the recorded attestation.
   */
  signFor<P>(identity: AuthenticatedIdentity, action: string, payload: P): SignedAction<P>;
}

/**
 * The economy subsystem. Only present when a Gun instance was supplied —
 * `AlephWallet` moves funds through a Gun ledger and there is no in-memory
 * fallback that would be honest.
 */
export interface EconomySubsystem {
  readonly enabled: boolean;
  readonly reason: string | null;
  /** null when disabled. */
  readonly faucet: Faucet | null;
  /** Why the faucet is off when the economy itself is on; null when usable. */
  readonly faucetReason: string | null;
  /**
   * Wallet view for an authenticated caller, derived from the VERIFIED
   * public key (never from a body field). Returns null when disabled.
   */
  walletFor(identity: AuthenticatedIdentity): AlephWallet | null;
  /** Wallet view for a bare ledger address (fingerprint). */
  walletForAddress(address: string): AlephWallet | null;
  /**
   * Per-caller StakingService (position tracking is per-wallet). Resolves
   * asynchronously because a freshly-created service reconciles its cold
   * position cache from the on-ledger stakes subtree before first use.
   */
  stakingFor(identity: AuthenticatedIdentity): Promise<StakingService | null>;
}

/** The coherence subsystem: registry always; market only with a Gun ledger. */
export interface CoherenceSubsystem {
  readonly registry: ClaimRegistry;
  readonly market: VerificationMarket | null;
  /** Why the market is off; null when available. */
  readonly marketReason: string | null;
}

/** The complete wiring bundle handed to the action module factories. */
export interface NodeSubsystems {
  readonly semantic: SemanticSubsystem;
  readonly social: SocialSubsystem;
  readonly economy: EconomySubsystem;
  readonly coherence: CoherenceSubsystem;
}

// ═══════════════════════════════════════════════════════════════════════════
// STATUS
// ═══════════════════════════════════════════════════════════════════════════

/** Semantic kernel state as reported by `AlephNode.getStatus()`. */
export interface SemanticStatus {
  readonly enabled: boolean;
  /** True when disabled after a load failure OR running a degraded kernel. */
  readonly degraded: boolean;
  readonly kernel: { readonly loaded: boolean; readonly degraded: boolean } | null;
}

/** Aggregate counts reported by `AlephNode.getStatus()`. */
export interface NodeCounts {
  readonly actions: number;
  readonly memoryTraces: number | null;
  readonly claims: number;
  readonly claimEdges: number;
}

/**
 * Everything `AlephNode.getStatus()` reports. Plain JSON: no bigints, no
 * class instances.
 */
export interface AlephNodeStatus {
  readonly nodeId: string;
  readonly fingerprint: string;
  readonly identityPersistent: boolean;
  readonly identityCanSign: boolean;
  readonly startedAt: number | null;
  readonly uptimeMs: number;
  readonly listening: boolean;
  readonly port: number | null;
  readonly semantic: SemanticStatus;
  readonly subsystems: Record<SubsystemName, SubsystemStatus>;
  readonly counts: NodeCounts;
}
