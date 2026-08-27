/**
 * Tier resolver memoization tests (M4).
 *
 * Tier resolution used to perform a full Gun round-trip per action; the
 * resolver now memoizes each fingerprint's tier for a short TTL and drops
 * the entry when a read fails, so a ledger outage can never poison the
 * cache with a stale tier.
 */

import { describe, it, expect } from '@jest/globals';
import { StakingTierResolver } from '../../src/node';

const ADEPT_STAKED = 500n * 10n ** 18n;

describe('StakingTierResolver memoization', () => {
  it('caches a successful read for the TTL and re-reads after expiry', async () => {
    let now = 1_000_000;
    let reads = 0;
    const resolver = new StakingTierResolver({
      ttlMs: 100,
      now: () => now,
      readStaked: async () => {
        reads += 1;
        return ADEPT_STAKED;
      }
    });

    expect(await resolver.resolveTier('fp')).toBe('Adept');
    expect(await resolver.resolveTier('fp')).toBe('Adept');
    expect(reads).toBe(1);

    // Inside the TTL: still served from the cache.
    now += 50;
    expect(await resolver.resolveTier('fp')).toBe('Adept');
    expect(reads).toBe(1);

    // Past the TTL: a fresh read.
    now += 51;
    expect(await resolver.resolveTier('fp')).toBe('Adept');
    expect(reads).toBe(2);
  });

  it('never caches a failed read', async () => {
    let reads = 0;
    const resolver = new StakingTierResolver({
      ttlMs: 60_000,
      readStaked: async () => {
        reads += 1;
        if (reads === 1) throw new Error('ledger down');
        return 0n;
      }
    });

    await expect(resolver.resolveTier('fp')).rejects.toThrow('ledger down');
    // The error entry was dropped: the next call reads again instead of
    // serving a poisoned cache entry.
    expect(await resolver.resolveTier('fp')).toBe('Neophyte');
    expect(reads).toBe(2);
  });

  it('degrading null reads (economy unavailable) are not cached', async () => {
    let reads = 0;
    const resolver = new StakingTierResolver({
      ttlMs: 60_000,
      readStaked: async () => {
        reads += 1;
        return null;
      }
    });

    expect(await resolver.resolveTier('fp')).toBe('Neophyte');
    expect(await resolver.resolveTier('fp')).toBe('Neophyte');
    expect(reads).toBe(2);
  });
});
