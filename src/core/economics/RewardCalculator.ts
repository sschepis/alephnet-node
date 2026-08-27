/**
 * Reward Calculator
 * 
 * Logic for calculating staking rewards based on lock periods and tiers.
 */

import { StakeRecord, LOCK_MULTIPLIERS, BASE_APY } from './types';
import { LockPeriod } from '../../common/types';

/**
 * Coerce untrusted numeric input (Gun records are loosely typed) to a finite number
 */
function toFiniteNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === '') return null;
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

/**
 * Coerce untrusted amounts (Gun stores bigints as strings) to a bigint.
 *
 * Lenient by default: garbage coerces to `0n` (e.g. a corrupted Gun record
 * must not take the calculator down). Pass `strict = true` to instead throw
 * on garbage, so tampered/corrupt values cannot silently masquerade as zero.
 * `null`/`undefined` still map to `0n` in both modes (they mean "absent",
 * not "tampered").
 */
function toBigIntSafe(value: unknown, strict: boolean = false): bigint {
  if (typeof value === 'bigint') return value;
  if (value === null || value === undefined) return 0n;
  try {
    return BigInt(typeof value === 'number' ? Math.trunc(value) : String(value));
  } catch (error) {
    if (strict) {
      throw new Error(`Invalid numeric value for bigint conversion: ${String(value)}`);
    }
    return 0n;
  }
}

/**
 * Strict variant of the amount coercion: throws on garbage instead of
 * silently coercing it to `0n`. Use when tampered records must be surfaced
 * rather than masked (e.g. validating stake records before unstaking).
 */
export function toBigIntStrict(value: unknown): bigint {
  return toBigIntSafe(value, true);
}

export class RewardCalculator {
  /**
   * Calculate accrued rewards for a stake
   *
   * Rewards accrue from the last claim, falling back to the stake creation time
   * for stakes that have never been claimed (or whose record is missing the field).
   */
  static calculateRewards(stake: StakeRecord, now: number = Date.now()): bigint {
    if (!stake || stake.status !== 'ACTIVE') return 0n;
    
    const nowMs = toFiniteNumber(now);
    if (nowMs === null) return 0n;
    
    // lastRewardClaim may be missing on stakes created before it was tracked
    const since = toFiniteNumber(stake.lastRewardClaim) ?? toFiniteNumber(stake.createdAt);
    if (since === null) return 0n;
    
    const timeStaked = nowMs - since;
    if (!Number.isFinite(timeStaked) || timeStaked <= 0) return 0n;
    
    const yearsStaked = timeStaked / (365 * 24 * 60 * 60 * 1000);
    const multiplier = LOCK_MULTIPLIERS[stake.lockPeriod] || 1.0;
    const apy = BASE_APY * multiplier;
    if (!Number.isFinite(yearsStaked) || !Number.isFinite(apy)) return 0n;
    
    // Reward = Principal * APY * Years
    // Using BigInt math with precision scaling
    const PRECISION = 1000000000n; // 9 decimals of precision
    const amount = toBigIntSafe(stake.amount);
    if (amount <= 0n) return 0n;
    
    const apyBig = BigInt(Math.floor(apy * Number(PRECISION)));
    const yearsBig = BigInt(Math.floor(yearsStaked * Number(PRECISION)));
    if (apyBig <= 0n || yearsBig <= 0n) return 0n;
    
    const reward = (amount * apyBig * yearsBig) / (PRECISION * PRECISION);
    
    return reward;
  }
  
  /**
   * Calculate projected APY for a lock period
   */
  static getProjectedAPY(lockPeriod: LockPeriod): number {
    return BASE_APY * (LOCK_MULTIPLIERS[lockPeriod] || 1.0);
  }
}
