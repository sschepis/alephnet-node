/**
 * Staking tests.
 *
 * Focus:
 *  - FLAW #4: exact-threshold stakes must reach the tier (>= not >)
 *  - lock durations are honoured and a restake never shortens an existing lock
 *  - FLAW #3: staking REALLY moves funds (available shrinks, staked grows)
 */

import { beforeEach, describe, expect, it } from '@jest/globals';
import { LOCK_PERIOD_MS, LockPeriod, TIER_THRESHOLDS } from '../../src/common/types';
import {
  StakingError,
  StakingService,
  calculateTier,
  capabilitiesFor,
  hasCapability,
  lockBonusBps,
  resolveLockPeriod,
  rewardMultiplierBps,
  stakeToNextTier,
  tierAtLeast
} from '../../src/economy/Staking';
import { ONE_TOKEN, parseTokens, wholeTokens } from '../../src/economy/units';
import { createTestLedger, TestLedger } from './fakeLedger';

describe('calculateTier', () => {
  it('reaches Adept at EXACTLY the threshold (legacy off-by-one regression)', () => {
    expect(calculateTier(TIER_THRESHOLDS.Adept)).toBe('Adept');
    expect(calculateTier(TIER_THRESHOLDS.Adept - 1n)).toBe('Neophyte');
  });

  it('reaches every tier at exactly its threshold', () => {
    expect(calculateTier(TIER_THRESHOLDS.Neophyte)).toBe('Neophyte');
    expect(calculateTier(TIER_THRESHOLDS.Magus)).toBe('Magus');
    expect(calculateTier(TIER_THRESHOLDS.Archon)).toBe('Archon');
    expect(calculateTier(TIER_THRESHOLDS.Archon + 1n)).toBe('Archon');
  });

  it('is monotonic and never jumps', () => {
    const half = TIER_THRESHOLDS.Adept / 2n;
    expect(calculateTier(half)).toBe('Neophyte');
    expect(tierAtLeast('Adept', 'Adept')).toBe(true);
    expect(tierAtLeast('Archon', 'Adept')).toBe(true);
    expect(tierAtLeast('Adept', 'Archon')).toBe(false);
  });

  it('honours the lock duration in the bonus (legacy ignored it)', () => {
    expect(lockBonusBps('365d')).toBeGreaterThan(lockBonusBps('180d'));
    expect(lockBonusBps('180d')).toBeGreaterThan(lockBonusBps('90d'));
    expect(lockBonusBps('90d')).toBeGreaterThan(lockBonusBps('30d'));
    expect(lockBonusBps('30d')).toBeGreaterThan(lockBonusBps('7d'));
    expect(lockBonusBps('7d')).toBeGreaterThan(0);

    // Longer locks and higher tiers multiply together.
    expect(rewardMultiplierBps('Adept', '365d')).toBeGreaterThan(rewardMultiplierBps('Adept', '7d'));
    expect(rewardMultiplierBps('Archon', '7d')).toBeGreaterThan(rewardMultiplierBps('Adept', '7d'));
  });
});

describe('resolveLockPeriod', () => {
  it('never shrinks an existing lock (legacy restake overwrote 365d with 30d)', () => {
    const now = 1_000_000_000;
    const existing = { lockPeriod: '365d' as LockPeriod, lockedUntil: now + LOCK_PERIOD_MS['365d'] };

    const resolution = resolveLockPeriod('30d', existing, now);

    expect(resolution.lockPeriod).toBe('365d');
    expect(resolution.lockedUntil).toBe(existing.lockedUntil);
    expect(resolution.retainedExisting).toBe(true);
  });

  it('extends a shorter lock when a longer one is requested', () => {
    const now = 1_000_000_000;
    const existing = { lockPeriod: '30d' as LockPeriod, lockedUntil: now + LOCK_PERIOD_MS['30d'] };

    const resolution = resolveLockPeriod('90d', existing, now);

    expect(resolution.lockPeriod).toBe('90d');
    expect(resolution.lockedUntil).toBe(now + LOCK_PERIOD_MS['90d']);
    expect(resolution.extended).toBe(true);
  });

  it('honours an expiry that outlives the requested period', () => {
    const now = 1_000_000_000;
    const farFuture = now + 10 * 365 * 24 * 60 * 60 * 1000;
    const resolution = resolveLockPeriod('30d', { lockPeriod: '30d', lockedUntil: farFuture }, now);
    expect(resolution.lockedUntil).toBe(farFuture);
  });

  it('survives backwards clock skew without shortening the lock', () => {
    const now = 1_000_000_000;
    const existing = { lockPeriod: '365d' as LockPeriod, lockedUntil: now + LOCK_PERIOD_MS['365d'] };
    // The clock jumps backwards an hour between stakes.
    const skewedBack = now - 60 * 60 * 1000;

    const resolution = resolveLockPeriod('7d', existing, skewedBack);

    expect(resolution.lockPeriod).toBe('365d');
    expect(resolution.lockedUntil).toBe(existing.lockedUntil);
    expect(resolution.retainedExisting).toBe(true);
  });

  it('survives forwards clock skew without unlocking early', () => {
    const now = 1_000_000_000;
    const existing = { lockPeriod: '7d' as LockPeriod, lockedUntil: now + LOCK_PERIOD_MS['7d'] };
    // The clock jumps forward past the old lock end.
    const skewedForward = now + 10 * 24 * 60 * 60 * 1000;

    const resolution = resolveLockPeriod('30d', existing, skewedForward);

    expect(resolution.lockPeriod).toBe('30d');
    expect(resolution.lockedUntil).toBe(skewedForward + LOCK_PERIOD_MS['30d']);
    expect(resolution.extended).toBe(true);
  });
});

describe('stakeToNextTier', () => {
  it('returns zero at the top tier (Archon)', () => {
    expect(stakeToNextTier(TIER_THRESHOLDS.Archon)).toBe(0n);
    expect(stakeToNextTier(TIER_THRESHOLDS.Archon + ONE_TOKEN)).toBe(0n);
  });

  it('reports the exact gap one base unit below the Archon threshold', () => {
    expect(stakeToNextTier(TIER_THRESHOLDS.Archon - 1n)).toBe(1n);
    expect(stakeToNextTier(TIER_THRESHOLDS.Adept)).toBe(TIER_THRESHOLDS.Magus - TIER_THRESHOLDS.Adept);
  });
});

describe('capabilities', () => {
  it('grants capabilities cumulatively by tier', () => {
    expect(hasCapability('Neophyte', 'read_claims')).toBe(true);
    expect(hasCapability('Neophyte', 'verify_claims')).toBe(false);
    expect(hasCapability('Adept', 'verify_claims')).toBe(true);
    expect(hasCapability('Adept', 'create_synthesis')).toBe(false);
    expect(hasCapability('Magus', 'create_synthesis')).toBe(true);
    expect(hasCapability('Archon', 'governance')).toBe(true);
    expect(hasCapability('Adept', 'read_claims')).toBe(true); // inherited
    expect(capabilitiesFor('Adept').length).toBeGreaterThan(capabilitiesFor('Neophyte').length);
  });
});

describe('StakingService', () => {
  let ledger: TestLedger;

  beforeEach(() => {
    ledger = createTestLedger();
  });

  it('reaches Adept when staking exactly the threshold (off-by-one regression)', async () => {
    const holder = ledger.createWallet({ available: TIER_THRESHOLDS.Adept });
    const service = new StakingService(holder.wallet);

    const result = await service.stake(TIER_THRESHOLDS.Adept, '30d');

    expect(result.tier).toBe('Adept');
    expect(result.previousTier).toBe('Neophyte');
    expect((await holder.wallet.getBalance()).staked).toBe(TIER_THRESHOLDS.Adept);
  });

  it('staking actually reduces the available balance (funds really move)', async () => {
    const holder = ledger.createWallet({ available: wholeTokens(200) });
    const service = new StakingService(holder.wallet);

    const before = await holder.wallet.getBalance();
    const amount = wholeTokens(120);

    await service.stake(amount, '90d');
    await ledger.flush();

    const after = await holder.wallet.getBalance();
    expect(after.available).toBe(before.available - amount);
    expect(after.staked).toBe(before.staked + amount);
    // The ledger record itself must show the debit.
    expect(ledger.available(holder.address)).toBe(before.available - amount);
    expect(ledger.staked(holder.address)).toBe(before.staked + amount);
  });

  it('restaking does not shorten an existing lock', async () => {
    const holder = ledger.createWallet({ available: wholeTokens(500) });
    const service = new StakingService(holder.wallet);

    const first = await service.stake(wholeTokens(100), '365d');

    // The staker tops up with a 30-day request shortly after.
    const second = await service.stake(wholeTokens(50), '30d');

    expect(second.retainedExistingLock).toBe(true);
    expect(second.lockPeriod).toBe('365d');
    expect(second.lockedUntil).toBeGreaterThanOrEqual(first.lockedUntil);
    // The on-ledger stake record must carry the long lock too.
    expect(ledger.stakeRecord(second.stakeId)?.lockPeriod).toBe('365d');
  });

  it('rejects staking more than the available balance', async () => {
    const holder = ledger.createWallet({ available: wholeTokens(5) });
    const service = new StakingService(holder.wallet);

    await expect(service.stake(wholeTokens(10), '7d')).rejects.toBeInstanceOf(StakingError);
    await expect(service.stake(wholeTokens(10), '7d')).rejects.toMatchObject({
      code: 'INSUFFICIENT_FUNDS'
    });
  });

  it('rejects unknown lock periods', async () => {
    const holder = ledger.createWallet({ available: wholeTokens(100) });
    const service = new StakingService(holder.wallet);

    await expect(service.stake(wholeTokens(10), 'fortnight' as LockPeriod)).rejects.toMatchObject({
      code: 'INVALID_LOCK'
    });
  });

  it('computes tier gating from the live staked balance', async () => {
    const holder = ledger.createWallet({
      available: wholeTokens(120),
      staked: TIER_THRESHOLDS.Adept
    });

    const service = new StakingService(holder.wallet);
    await expect(service.requireCapability('verify_claims')).resolves.toBe('Adept');
    await expect(service.requireTier('Magus')).rejects.toMatchObject({ code: 'TIER_TOO_LOW' });

    const summary = await service.summary();
    expect(summary.tier).toBe('Adept');
    expect(summary.stakeToNextTier).toBe(TIER_THRESHOLDS.Magus - TIER_THRESHOLDS.Adept);
  });

  it('keeps a young stake locked (funds are genuinely time-bound)', async () => {
    const holder = ledger.createWallet({ available: wholeTokens(200) });
    const service = new StakingService(holder.wallet);

    const stake = await service.stake(wholeTokens(100), '7d');
    await expect(holder.wallet.unstake(stake.stakeId)).rejects.toThrow('Stake is still locked');
  });

  it('serializes concurrent stakes: no stakeId is lost and the lock is not downgraded', async () => {
    const holder = ledger.createWallet({ available: wholeTokens(300) });
    const service = new StakingService(holder.wallet);

    const [long, short] = await Promise.all([
      service.stake(wholeTokens(100), '90d'),
      service.stake(wholeTokens(50), '7d')
    ]);

    expect(long.stakeId).not.toBe(short.stakeId);
    expect(short.retainedExistingLock).toBe(true);

    const position = service.getPosition();
    expect(position?.stakeIds).toHaveLength(2);
    expect(position?.staked).toBe(wholeTokens(150));
    expect(position?.lockPeriod).toBe('90d');
  });

  it('reconciles on-ledger records so the lock ratchet survives a restart', async () => {
    const holder = ledger.createWallet({ available: wholeTokens(500) });
    // A fresh service: the in-memory cache is cold, as after a restart.
    const service = new StakingService(holder.wallet);
    const now = Date.now();

    const position = await service.reconcile([
      { stakeId: 'ledger-stake-1', amount: wholeTokens(100), lockPeriod: '365d', lockedUntil: now + LOCK_PERIOD_MS['365d'] }
    ]);

    expect(position?.lockPeriod).toBe('365d');
    expect(position?.lockedUntil).toBe(now + LOCK_PERIOD_MS['365d']);
    expect(position?.staked).toBe(wholeTokens(100));
    expect(position?.stakeIds).toEqual(['ledger-stake-1']);

    // Restaking 7d must report the retained 365d lock, not overwrite it.
    const restake = await service.stake(wholeTokens(10), '7d');
    expect(restake.retainedExistingLock).toBe(true);
    expect(restake.lockPeriod).toBe('365d');
    expect(restake.lockedUntil).toBeGreaterThanOrEqual(now + LOCK_PERIOD_MS['365d']);
  });

  it('reconcile with no records clears the position', async () => {
    const holder = ledger.createWallet({ available: wholeTokens(100) });
    const service = new StakingService(holder.wallet);
    await service.stake(wholeTokens(10), '30d');

    expect(await service.reconcile([])).toBeNull();
    expect(service.getPosition()).toBeNull();
  });
});
