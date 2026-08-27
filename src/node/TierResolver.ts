/**
 * Tier Resolver
 *
 * Implements the application layer's `TierResolver` interface, backed by the
 * live staked balance on the Gun ledger.
 *
 * The registry hands this resolver only a fingerprint (the ledger address).
 * `AlephWallet` reads balances by address and never needs the private key, so
 * the resolver builds a public-only wallet view from the fingerprint alone.
 *
 * When the economy is unavailable (no Gun instance) the resolver falls back
 * to `'Neophyte'` — the default tier for an unauthenticated-by-stake caller.
 * Nothing is faked: an absent ledger IS a Neophyte tier.
 *
 * Tier resolution is MEMOIZED per fingerprint with a short TTL: every action
 * invocation used to trigger a full Gun round-trip for the caller's balance,
 * so a burst of requests multiplied the ledger load. A successful read is
 * cached for `ttlMs` (default 5s); a failed read never poisons the cache
 * (the entry is dropped and the error propagates to the registry, which
 * degrades to Neophyte and logs).
 */

import type { StakingTier } from '../common/types';
import type { TierResolver } from '../app';
import { AlephWallet } from '../infra/Wallet';
import type { KeyTriplet } from '../common/crypto';
import { calculateTier } from '../economy';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Reads the live staked balance for a ledger address (base units).
 * Returning null means "the economy is unavailable".
 */
export type StakedBalanceReader = (fingerprint: string) => Promise<bigint | null>;

export interface StakingTierResolverOptions {
  readonly readStaked: StakedBalanceReader;
  /** Memoized tier cache TTL per fingerprint, in ms. Default 5000. */
  readonly ttlMs?: number;
  /** Injectable clock, for deterministic tests. */
  readonly now?: () => number;
  /** Hard cap on cached fingerprints (LRU eviction). Default 500. */
  readonly maxEntries?: number;
}

const DEFAULT_TIER_CACHE_TTL_MS = 5_000;
const DEFAULT_TIER_CACHE_MAX_ENTRIES = 500;

interface CachedTier {
  readonly tier: StakingTier;
  readonly expiresAt: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// RESOLVER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * `TierResolver` backed by real staked balances, degrading to `'Neophyte'`
 * when the economy is unavailable.
 */
export class StakingTierResolver implements TierResolver {
  private readonly readStaked: StakedBalanceReader;
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;
  private readonly cache = new Map<string, CachedTier>();

  constructor(options: StakingTierResolverOptions) {
    this.readStaked = options.readStaked;
    this.ttlMs = options.ttlMs ?? DEFAULT_TIER_CACHE_TTL_MS;
    this.maxEntries = options.maxEntries ?? DEFAULT_TIER_CACHE_MAX_ENTRIES;
    this.now = options.now ?? (() => Date.now());
  }

  async resolveTier(fingerprint: string): Promise<StakingTier> {
    const now = this.now();
    const cached = this.cache.get(fingerprint);
    if (cached !== undefined && cached.expiresAt > now) {
      // Refresh recency so the LRU keeps hot fingerprints and evicts cold ones.
      this.cache.delete(fingerprint);
      this.cache.set(fingerprint, cached);
      return cached.tier;
    }

    let staked: bigint | null;
    try {
      staked = await this.readStaked(fingerprint);
    } catch (error) {
      // A failed read must never leave a stale/poisoned entry behind.
      this.cache.delete(fingerprint);
      throw error;
    }

    // null means "economy unavailable" — degrade without caching so a
    // transient outage is not pinned for the TTL.
    if (staked === null) return 'Neophyte';

    const tier = calculateTier(staked);
    this.cache.set(fingerprint, { tier, expiresAt: now + this.ttlMs });
    while (this.cache.size > this.maxEntries) {
      const oldest = this.cache.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.cache.delete(oldest);
    }
    return tier;
  }

  /** Alias satisfying the social layer's `StakingTierOracle` shape. */
  async getTier(fingerprint: string): Promise<StakingTier> {
    return this.resolveTier(fingerprint);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// WALLET-BACKED FACTORY
// ═══════════════════════════════════════════════════════════════════════════

const ZERO_SMF = new Array<number>(16).fill(0) as KeyTriplet['resonance'];

/**
 * A read-only wallet view for a bare ledger address.
 *
 * `AlephWallet` uses only `keyTriplet.fingerprint` (the ledger address); no
 * signing happens inside the wallet, so the public-key material is left
 * empty. This is deliberately a VIEW over the ledger, never a minting or
 * signing path.
 */
export function walletForAddress(gun: unknown, fingerprint: string): AlephWallet {
  const triplet: KeyTriplet = {
    pub: '',
    priv: '',
    resonance: ZERO_SMF,
    fingerprint,
    bodyPrimes: []
  };
  return new AlephWallet(triplet, gun);
}

/**
 * Build the canonical resolver over a Gun ledger.
 *
 * Balance-read failures propagate: the action registry catches tier
 * resolution errors, logs them, and falls back to 'Neophyte' itself — this
 * resolver never silently swallows a ledger failure.
 */
export function createWalletTierResolver(gun: unknown): StakingTierResolver {
  return new StakingTierResolver({
    readStaked: async (fingerprint: string): Promise<bigint> => {
      const balance = await walletForAddress(gun, fingerprint).getBalance();
      return balance.staked;
    }
  });
}
