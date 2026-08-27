/**
 * Staking
 *
 * Tier calculation, lock-period handling and tier capabilities — all in
 * bigint base units, all funds moved through the real wallet.
 *
 * Legacy bugs closed here:
 *  - `aleph-token/staking.js` used strict `>` (`if (stakeAmount > 100) return 'Adept'`),
 *    so a stake of exactly the 100-token minimum stayed Neophyte. Thresholds
 *    are now compared with `>=` against TIER_THRESHOLDS.
 *  - the same function took `lockDurationDays` and ignored it entirely
 *    ("Mock implementation"). Lock duration now drives a real bonus
 *    ({@link lockBonusBps}) derived from LOCK_PERIOD_MS.
 *  - restaking overwrote a long lock with a short one. {@link resolveLockPeriod}
 *    never shrinks an existing lock.
 *  - `coherence/stakes.js#lockStake` recorded a stake without debiting anything.
 *    {@link StakingService.stake} calls the wallet's real `stake()`, which
 *    moves available -> staked.
 */

import { Mutex } from '../common/async';
import { TIER_MULTIPLIERS } from '../common/constants';
import {
  LOCK_PERIOD_MS,
  LockPeriod,
  StakingTier,
  TIER_ORDER,
  TIER_THRESHOLDS,
  Timestamp
} from '../common/types';
import type { RewardReceipt, StakeReceipt, UnstakeReceipt } from '../core/economics/types';
import type { EconomyWallet } from './WalletPort';
import {
  BPS_DENOMINATOR,
  TokenAmount,
  TokenMathError,
  ZERO,
  assertPositive,
  formatAleph,
  multiplierToBps,
  mulRatio,
  safeAdd,
  safeSub
} from './units';

// ═══════════════════════════════════════════════════════════════════════════
// TIER MULTIPLIERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Reward multiplier of a tier in integer bps (Neophyte = 10_000 == 1.0x).
 *
 * TIER_MULTIPLIERS is authored with `number` literals; it is converted to
 * integer bps exactly once, here, so no float ever touches an amount.
 */
export function tierRewardBps(tier: StakingTier): number {
  return multiplierToBps(TIER_MULTIPLIERS.REWARD[tier], `TIER_MULTIPLIERS.REWARD.${tier}`);
}

/** Vote weight of a tier in integer bps. */
export function tierVoteWeightBps(tier: StakingTier): number {
  return multiplierToBps(TIER_MULTIPLIERS.VOTE_WEIGHT[tier], `TIER_MULTIPLIERS.VOTE_WEIGHT.${tier}`);
}

/** Maximum lock bonus, awarded at the longest lock period (+100%). */
export const MAX_LOCK_BONUS_BPS = 10_000;

/** Longest supported lock, used to normalise the lock bonus. */
export const LONGEST_LOCK: LockPeriod = '365d';

/**
 * Bonus for committing to a lock period, in bps, linear in the lock duration.
 * 7d -> +1.91%, 30d -> +8.21%, 365d -> +100%.
 */
export function lockBonusBps(lockPeriod?: LockPeriod): number {
  if (!lockPeriod) return 0;
  const duration = LOCK_PERIOD_MS[lockPeriod];
  if (duration === undefined) return 0;
  const longest = LOCK_PERIOD_MS[LONGEST_LOCK];
  return Number((BigInt(duration) * BigInt(MAX_LOCK_BONUS_BPS)) / BigInt(longest));
}

/** Combined tier x lock reward multiplier, in bps. */
export function rewardMultiplierBps(tier: StakingTier, lockPeriod?: LockPeriod): number {
  const tierBps = BigInt(tierRewardBps(tier));
  const lockBps = BigInt(Number(BPS_DENOMINATOR) + lockBonusBps(lockPeriod));
  return Number((tierBps * lockBps) / BPS_DENOMINATOR);
}

/** Apply the tier x lock reward multiplier to a base amount. */
export function applyRewardMultiplier(
  base: TokenAmount,
  tier: StakingTier,
  lockPeriod?: LockPeriod
): TokenAmount {
  return mulRatio(base, BigInt(rewardMultiplierBps(tier, lockPeriod)), BPS_DENOMINATOR, 'reward');
}

// ═══════════════════════════════════════════════════════════════════════════
// TIERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Tier reached by a staked amount.
 *
 * Uses `>=`: staking exactly TIER_THRESHOLDS.Adept reaches Adept. The legacy
 * `>` comparison left a wallet holding precisely the advertised minimum one
 * tier below where it belonged.
 */
export function calculateTier(staked: TokenAmount): StakingTier {
  if (typeof staked !== 'bigint') {
    throw new TokenMathError('NOT_BIGINT', `staked must be a bigint, received ${typeof staked}`);
  }
  let tier: StakingTier = 'Neophyte';
  for (const candidate of TIER_ORDER) {
    if (staked >= TIER_THRESHOLDS[candidate]) {
      tier = candidate;
    }
  }
  return tier;
}

/** Index of a tier in TIER_ORDER. */
export function tierRank(tier: StakingTier): number {
  const rank = TIER_ORDER.indexOf(tier);
  if (rank < 0) throw new TokenMathError('RANGE', `unknown staking tier: ${String(tier)}`);
  return rank;
}

/** True when `tier` meets or exceeds `required`. */
export function tierAtLeast(tier: StakingTier, required: StakingTier): boolean {
  return tierRank(tier) >= tierRank(required);
}

/** The next tier up, or null at the top. */
export function nextTier(tier: StakingTier): StakingTier | null {
  const rank = tierRank(tier);
  return rank + 1 < TIER_ORDER.length ? TIER_ORDER[rank + 1] : null;
}

/** Additional stake needed to reach the next tier (0 at the top). */
export function stakeToNextTier(staked: TokenAmount): TokenAmount {
  const upcoming = nextTier(calculateTier(staked));
  if (!upcoming) return ZERO;
  return safeSub(TIER_THRESHOLDS[upcoming], staked, 'stakeToNextTier');
}

// ═══════════════════════════════════════════════════════════════════════════
// CAPABILITIES
// ═══════════════════════════════════════════════════════════════════════════

/** Every capability gated by staking tier. */
export type StakingCapability =
  | 'read_claims'
  | 'create_edges'
  | 'join_rooms'
  | 'submit_claims'
  | 'verify_claims'
  | 'claim_tasks'
  | 'create_synthesis'
  | 'create_rooms'
  | 'lead_verification'
  | 'security_review'
  | 'governance'
  | 'dispute_resolution';

/** Capabilities *introduced* by each tier (cumulative via {@link capabilitiesFor}). */
export const TIER_CAPABILITIES: Record<StakingTier, readonly StakingCapability[]> = {
  Neophyte: ['read_claims', 'create_edges', 'join_rooms'],
  Adept: ['submit_claims', 'verify_claims', 'claim_tasks'],
  Magus: ['create_synthesis', 'create_rooms', 'lead_verification'],
  Archon: ['security_review', 'governance', 'dispute_resolution']
};

/** All capabilities available at a tier, including inherited ones. */
export function capabilitiesFor(tier: StakingTier): StakingCapability[] {
  const rank = tierRank(tier);
  const capabilities: StakingCapability[] = [];
  for (let i = 0; i <= rank; i++) {
    capabilities.push(...TIER_CAPABILITIES[TIER_ORDER[i]]);
  }
  return capabilities;
}

/** True when a tier grants a capability (directly or by inheritance). */
export function hasCapability(tier: StakingTier, capability: StakingCapability): boolean {
  return capabilitiesFor(tier).includes(capability);
}

/** The lowest tier granting a capability, or null if none does. */
export function tierRequiredFor(capability: StakingCapability): StakingTier | null {
  for (const tier of TIER_ORDER) {
    if (TIER_CAPABILITIES[tier].includes(capability)) return tier;
  }
  return null;
}

/** Throw unless the tier grants the capability. */
export function requireCapability(tier: StakingTier, capability: StakingCapability): void {
  if (!hasCapability(tier, capability)) {
    const required = tierRequiredFor(capability);
    throw new StakingError(
      'CAPABILITY_DENIED',
      `${tier} cannot ${capability}${required ? `; requires ${required}` : ''}`
    );
  }
}

/** Human-readable description of a tier. */
export interface TierProfile {
  tier: StakingTier;
  minStake: TokenAmount;
  capabilities: StakingCapability[];
  rewardMultiplierBps: number;
  voteWeightBps: number;
}

/** Everything about a tier in one object. */
export function describeTier(tier: StakingTier): TierProfile {
  return {
    tier,
    minStake: TIER_THRESHOLDS[tier],
    capabilities: capabilitiesFor(tier),
    rewardMultiplierBps: tierRewardBps(tier),
    voteWeightBps: tierVoteWeightBps(tier)
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// LOCK PERIODS
// ═══════════════════════════════════════════════════════════════════════════

/** An existing lock commitment. */
export interface LockCommitment {
  lockPeriod: LockPeriod;
  lockedUntil: Timestamp;
}

/** Outcome of merging a requested lock with an existing one. */
export interface LockResolution extends LockCommitment {
  /** The lock actually applied. */
  lockPeriod: LockPeriod;
  /** Unlock timestamp, never earlier than the existing one. */
  lockedUntil: Timestamp;
  /** True when the caller's shorter request was overridden. */
  retainedExisting: boolean;
  /** True when the request extended the commitment. */
  extended: boolean;
}

/**
 * Merge a requested lock period with any existing commitment.
 *
 * Locks are ratchets: they may be extended but never shortened. Legacy
 * restaking replaced a 365-day commitment with a 30-day one, letting a staker
 * unlock a year-locked position after a month by staking one extra token.
 */
export function resolveLockPeriod(
  requested: LockPeriod,
  existing?: LockCommitment | null,
  now: Timestamp = Date.now()
): LockResolution {
  const requestedMs = LOCK_PERIOD_MS[requested];
  if (requestedMs === undefined) {
    throw new StakingError('INVALID_LOCK', `unknown lock period: ${String(requested)}`);
  }

  if (!existing) {
    return {
      lockPeriod: requested,
      lockedUntil: now + requestedMs,
      retainedExisting: false,
      extended: true
    };
  }

  const existingMs = LOCK_PERIOD_MS[existing.lockPeriod] ?? 0;
  const lockPeriod: LockPeriod = existingMs > requestedMs ? existing.lockPeriod : requested;
  const candidateUntil = now + (LOCK_PERIOD_MS[lockPeriod] ?? requestedMs);
  const lockedUntil = Math.max(existing.lockedUntil, candidateUntil);

  return {
    lockPeriod,
    lockedUntil,
    retainedExisting: lockPeriod !== requested,
    extended: lockedUntil > existing.lockedUntil
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

export type StakingErrorCode =
  | 'INSUFFICIENT_FUNDS'
  | 'INVALID_LOCK'
  | 'CAPABILITY_DENIED'
  | 'TIER_TOO_LOW'
  | 'NO_POSITION';

export class StakingError extends Error {
  public readonly code: StakingErrorCode;

  constructor(code: StakingErrorCode, message: string) {
    super(message);
    this.name = 'StakingError';
    this.code = code;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// SERVICE
// ═══════════════════════════════════════════════════════════════════════════

/** Locally tracked aggregate position for one wallet. */
export interface StakingPosition {
  owner: string;
  staked: TokenAmount;
  tier: StakingTier;
  lockPeriod: LockPeriod;
  lockedUntil: Timestamp;
  stakeIds: string[];
  updatedAt: Timestamp;
}

/** Receipt returned by {@link StakingService.stake}. */
export interface StakeResult {
  stakeId: string;
  amount: TokenAmount;
  /** Lock actually applied (>= the requested one). */
  lockPeriod: LockPeriod;
  lockedUntil: Timestamp;
  /** True when a longer existing lock overrode the request. */
  retainedExistingLock: boolean;
  tier: StakingTier;
  previousTier: StakingTier;
  totalStaked: TokenAmount;
  availableAfter: TokenAmount;
  transactionId: string;
  receipt: StakeReceipt;
}

/** Aggregate view of a wallet's staking state. */
export interface StakingSummary {
  owner: string;
  available: TokenAmount;
  staked: TokenAmount;
  tier: StakingTier;
  nextTier: StakingTier | null;
  stakeToNextTier: TokenAmount;
  capabilities: StakingCapability[];
  rewardMultiplierBps: number;
  position: StakingPosition | null;
}

export interface StakingServiceOptions {
  /** Injected clock, for deterministic tests. */
  now?: () => Timestamp;
}

/**
 * One ACTIVE stake record as stored on the ledger, as consumed by
 * {@link StakingService.reconcile}.
 */
export interface StakingReconcileRecord {
  stakeId: string;
  amount: TokenAmount;
  lockPeriod: LockPeriod;
  lockedUntil: Timestamp;
}

/**
 * Staking operations for a single wallet.
 *
 * Every mutation delegates to the wallet, so staked tokens genuinely leave
 * the available balance instead of remaining spendable. Position mutations
 * are serialized through a local mutex: concurrent `stake` calls cannot
 * interleave their read-check-write of `this.position`, so no stakeId is
 * lost and the lock ratchet is never downgraded by a racing short lock.
 */
export class StakingService {
  private readonly wallet: EconomyWallet;
  private readonly now: () => Timestamp;
  private readonly mutex = new Mutex();
  private position: StakingPosition | null = null;

  constructor(wallet: EconomyWallet, options: StakingServiceOptions = {}) {
    this.wallet = wallet;
    this.now = options.now ?? (() => Date.now());
  }

  /** Ledger address this service stakes for. */
  public get address(): string {
    return this.wallet.address;
  }

  /** Locally tracked position, or null before the first stake. */
  public getPosition(): StakingPosition | null {
    return this.position ? { ...this.position, stakeIds: [...this.position.stakeIds] } : null;
  }

  /** Spendable balance, in base units. */
  public async getAvailable(): Promise<TokenAmount> {
    return (await this.wallet.getBalance()).available;
  }

  /** Staked balance, in base units. */
  public async getStaked(): Promise<TokenAmount> {
    return (await this.wallet.getBalance()).staked;
  }

  /** Tier implied by the on-ledger staked balance (recomputed, never trusted). */
  public async getTier(): Promise<StakingTier> {
    return calculateTier(await this.getStaked());
  }

  /**
   * Stake `amount` for at least `lockPeriod`.
   *
   * Funds really move: the wallet debits `available` and credits `staked`.
   * If a longer lock is already in force it is retained.
   */
  public async stake(amount: TokenAmount, lockPeriod: LockPeriod): Promise<StakeResult> {
    assertPositive(amount, 'stake amount');
    if (!(lockPeriod in LOCK_PERIOD_MS)) {
      throw new StakingError('INVALID_LOCK', `unknown lock period: ${String(lockPeriod)}`);
    }

    return this.mutex.runExclusive(async () => {
      const before = await this.wallet.getBalance();
      if (before.available < amount) {
        throw new StakingError(
          'INSUFFICIENT_FUNDS',
          `cannot stake ${formatAleph(amount)}: only ${formatAleph(before.available)} available`
        );
      }

      const resolution = resolveLockPeriod(lockPeriod, this.position, this.now());

      // Real fund movement (available -> staked) happens here.
      const receipt = await this.wallet.stake(amount, resolution.lockPeriod);

      const totalStaked = safeAdd(before.staked, amount, 'staked');
      const previousTier = calculateTier(before.staked);
      const tier = calculateTier(totalStaked);
      const lockedUntil = Math.max(resolution.lockedUntil, receipt.lockEndsAt);

      this.position = {
        owner: this.wallet.address,
        staked: totalStaked,
        tier,
        lockPeriod: resolution.lockPeriod,
        lockedUntil,
        stakeIds: [...(this.position?.stakeIds ?? []), receipt.stakeId],
        updatedAt: this.now()
      };

      return {
        stakeId: receipt.stakeId,
        amount,
        lockPeriod: resolution.lockPeriod,
        lockedUntil,
        retainedExistingLock: resolution.retainedExisting,
        tier,
        previousTier,
        totalStaked,
        availableAfter: safeSub(before.available, amount, 'available'),
        transactionId: receipt.transactionId,
        receipt
      };
    });
  }

  /** Release a matured stake back to available. */
  public async unstake(stakeId: string): Promise<UnstakeReceipt & { tier: StakingTier }> {
    return this.mutex.runExclusive(async () => {
      const receipt = await this.wallet.unstake(stakeId);

      if (this.position) {
        const staked =
          this.position.staked > receipt.amount ? this.position.staked - receipt.amount : ZERO;
        this.position = {
          ...this.position,
          staked,
          tier: calculateTier(staked),
          stakeIds: this.position.stakeIds.filter(id => id !== stakeId),
          updatedAt: this.now()
        };
      }

      return { ...receipt, tier: calculateTier(await this.getStaked()) };
    });
  }

  /**
   * Rebuild the tracked position from on-ledger stake records.
   *
   * The composition layer calls this on startup (or whenever the in-memory
   * cache is cold) with the wallet's ACTIVE stake records. The rebuilt
   * position takes the strongest lock among the records and the latest
   * `lockedUntil`, so the lock ratchet holds across restarts: a subsequent
   * short-lock stake cannot shorten a long lock that exists on the ledger
   * but was not yet in memory.
   *
   * Returns the rebuilt position, or null when there are no records.
   */
  public async reconcile(stakeRecords: StakingReconcileRecord[]): Promise<StakingPosition | null> {
    return this.mutex.runExclusive(async () => {
      if (stakeRecords.length === 0) {
        this.position = null;
        return null;
      }

      let staked = ZERO;
      let lockPeriod: LockPeriod | null = null;
      let lockPeriodMs = 0;
      let lockedUntil = 0;

      for (const record of stakeRecords) {
        if (!(record.lockPeriod in LOCK_PERIOD_MS)) {
          throw new StakingError(
            'INVALID_LOCK',
            `unknown lock period in stake record ${record.stakeId}: ${String(record.lockPeriod)}`
          );
        }
        if (!Number.isInteger(record.lockedUntil) || record.lockedUntil < 0) {
          throw new TokenMathError(
            'RANGE',
            `stake record ${record.stakeId} lockedUntil must be a non-negative integer, ` +
              `received ${record.lockedUntil}`
          );
        }
        staked = safeAdd(staked, record.amount, 'staked');
        const ms = LOCK_PERIOD_MS[record.lockPeriod];
        if (ms > lockPeriodMs) {
          lockPeriodMs = ms;
          lockPeriod = record.lockPeriod;
        }
        if (record.lockedUntil > lockedUntil) lockedUntil = record.lockedUntil;
      }

      this.position = {
        owner: this.wallet.address,
        staked,
        tier: calculateTier(staked),
        lockPeriod: lockPeriod ?? '7d',
        lockedUntil,
        stakeIds: stakeRecords.map(record => record.stakeId),
        updatedAt: this.now()
      };

      return this.getPosition();
    });
  }

  /** Credit accrued staking rewards to the available balance. */
  public async claimRewards(stakeId: string): Promise<RewardReceipt> {
    return this.wallet.claimRewards(stakeId);
  }

  /** Throw unless the wallet's current tier grants `capability`. */
  public async requireCapability(capability: StakingCapability): Promise<StakingTier> {
    const tier = await this.getTier();
    requireCapability(tier, capability);
    return tier;
  }

  /** Throw unless the wallet's current tier is at least `required`. */
  public async requireTier(required: StakingTier): Promise<StakingTier> {
    const tier = await this.getTier();
    if (!tierAtLeast(tier, required)) {
      throw new StakingError('TIER_TOO_LOW', `tier ${tier} is below the required ${required}`);
    }
    return tier;
  }

  /** Aggregate staking view for UIs and gating decisions. */
  public async summary(): Promise<StakingSummary> {
    const balance = await this.wallet.getBalance();
    const tier = calculateTier(balance.staked);
    return {
      owner: this.wallet.address,
      available: balance.available,
      staked: balance.staked,
      tier,
      nextTier: nextTier(tier),
      stakeToNextTier: stakeToNextTier(balance.staked),
      capabilities: capabilitiesFor(tier),
      rewardMultiplierBps: rewardMultiplierBps(tier, this.position?.lockPeriod),
      position: this.getPosition()
    };
  }
}
