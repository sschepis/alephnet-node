/**
 * Gas Schedule
 *
 * Deterministic gas costing in bigint BASE UNITS.
 *
 * Legacy bugs closed here:
 *  - `types.js` priced gas at `baseGasPrice: 0.000001` and multiplied it by
 *    float gas units, so every quote drifted. Prices are now integer base
 *    units per gas unit.
 *  - `gas-station.js` had the signature
 *    `calculateGasCost(gasUnits, userCoherence, hasAlephBalance, userCredits)`
 *    and `wallet.js` called it as `(gasUnits, coherence, balance > 0, balance)`
 *    — the wallet BALANCE was passed where CREDITS were expected, corrupting
 *    the payment recommendation. Inputs are now a single named
 *    {@link GasPayerContext} and credits carry a distinct branded type, so a
 *    token balance can no longer be passed as credits.
 */

import { StakingTier } from '../common/types';
import { tierRewardBps } from './Staking';
import {
  BPS_DENOMINATOR,
  ONE_TOKEN,
  TokenAmount,
  TokenMathError,
  ZERO,
  applyBps,
  assertNonNegative,
  formatAleph,
  saturatingSub
} from './units';

// ═══════════════════════════════════════════════════════════════════════════
// UNITS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Prepaid gas credits, in CREDIT units.
 *
 * Branded so that `gasCredits: someTokenBalance` is a compile error — the
 * exact confusion that broke the legacy recommendation logic. Build one with
 * {@link creditUnits}.
 */
export type CreditUnits = bigint & { readonly __brand: 'CreditUnits' };

/** Tag a bigint as credit units (validates non-negativity). */
export function creditUnits(value: bigint): CreditUnits {
  return assertNonNegative(value, 'credits') as CreditUnits;
}

/** Zero credits. */
export const NO_CREDITS: CreditUnits = creditUnits(ZERO);

/** Gas units are dimensionless integer work counts. */
export type GasUnits = bigint;

// ═══════════════════════════════════════════════════════════════════════════
// OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════

/** Every metered network operation. */
export type GasOperation =
  | 'contract_deploy'
  | 'contract_call'
  | 'token_transfer'
  | 'stake'
  | 'unstake'
  | 'memory_store'
  | 'memory_retrieve'
  | 'mesh_propagate'
  | 'consensus_vote'
  | 'claim_submit'
  | 'claim_verify'
  | 'edge_create'
  | 'synthesis_publish'
  | 'faucet_claim';

/** Base gas per operation, before size metering. */
export const GAS_UNITS: Record<GasOperation, GasUnits> = {
  contract_deploy: 100_000n,
  contract_call: 21_000n,
  token_transfer: 5_000n,
  stake: 10_000n,
  unstake: 10_000n,
  memory_store: 50_000n,
  memory_retrieve: 1_000n,
  mesh_propagate: 2_000n,
  consensus_vote: 5_000n,
  claim_submit: 8_000n,
  claim_verify: 12_000n,
  edge_create: 3_000n,
  synthesis_publish: 40_000n,
  faucet_claim: 1_000n
};

/** Fallback for operations absent from the table (defensive: input may be untyped). */
export const DEFAULT_GAS_UNITS: GasUnits = 10_000n;

/** Gas charged per byte of payload. */
export const GAS_PER_BYTE: GasUnits = 16n;

/** How the payer settles a gas bill. */
export type GasPaymentMethod = 'direct' | 'subsidized' | 'credits' | 'none';

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

export interface GasScheduleConfig {
  /** Base units charged per gas unit. 10^12 == 1 µℵ per gas. */
  gasPrice: TokenAmount;
  /** Discount for paying directly in ℵ, in bps. */
  directPaymentDiscountBps: number;
  /** Credits granted per whole token, used for credit conversion. */
  creditsPerToken: bigint;
  /** Hard ceiling on any combined subsidy, in bps. */
  maxSubsidyBps: number;
  /** Ceiling on the staking-tier component of the subsidy, in bps. */
  maxTierSubsidyBps: number;
  /** Ceiling on the coherence component of the subsidy, in bps. */
  maxCoherenceSubsidyBps: number;
  /** Minimum coherence (bps of 1.0) before the coherence subsidy applies. */
  coherenceSubsidyThresholdBps: number;
  /** Fee split — must sum to exactly 10_000 bps. */
  burnBps: number;
  rewardPoolBps: number;
  treasuryBps: number;
}

export const DEFAULT_GAS_CONFIG: GasScheduleConfig = {
  gasPrice: 10n ** 12n,
  directPaymentDiscountBps: 1_000,
  creditsPerToken: 100n,
  maxSubsidyBps: 5_000,
  maxTierSubsidyBps: 4_000,
  maxCoherenceSubsidyBps: 2_000,
  coherenceSubsidyThresholdBps: 8_000,
  burnBps: 5_000,
  rewardPoolBps: 3_000,
  treasuryBps: 2_000
};

/**
 * Who is paying, and with what.
 *
 * `tokenBalance` and `gasCredits` are deliberately different types so they
 * cannot be transposed.
 */
export interface GasPayerContext {
  /** Staking tier, drives the tier subsidy. */
  tier: StakingTier;
  /** Spendable ℵ, in BASE UNITS. Never credits. */
  tokenBalance: TokenAmount;
  /** Prepaid gas credits, in CREDIT UNITS. Never a token balance. */
  gasCredits: CreditUnits;
  /** Coherence score in [0, 1]; converted to integer bps internally. */
  coherence?: number;
}

/** Where a paid fee goes. Parts sum EXACTLY to the fee. */
export interface GasDistribution {
  burned: TokenAmount;
  rewardPool: TokenAmount;
  treasury: TokenAmount;
  total: TokenAmount;
}

/** Full costing breakdown for one operation. */
export interface GasQuote {
  operation: GasOperation;
  gasUnits: GasUnits;
  sizeBytes: number;
  /** Undiscounted cost in base units. */
  baseCost: TokenAmount;
  /** Cost when paying directly in ℵ. */
  directCost: TokenAmount;
  /** Cost after the tier + coherence subsidy. */
  subsidizedCost: TokenAmount;
  subsidy: TokenAmount;
  tierSubsidyBps: number;
  coherenceSubsidyBps: number;
  totalSubsidyBps: number;
  /** Credits required if paying with credits. */
  creditEquivalent: CreditUnits;
  recommended: GasPaymentMethod;
  /** Cost of the recommended method (0 credits-priced methods excluded). */
  payable: TokenAmount;
  affordable: boolean;
  distribution: GasDistribution;
}

// ═══════════════════════════════════════════════════════════════════════════
// TIER SUBSIDY (derived from TIER_MULTIPLIERS)
// ═══════════════════════════════════════════════════════════════════════════

/** Reward multiplier of a tier expressed in bps (Neophyte 10_000 == 1.0x). */
export const tierMultiplierBps = tierRewardBps;

const NEOPHYTE_BPS = BigInt(tierRewardBps('Neophyte'));
const ARCHON_BPS = BigInt(tierRewardBps('Archon'));

/**
 * Map a tier onto a share of `maxTierSubsidyBps`, linear in the tier's reward
 * multiplier: Neophyte pays full price, Archon receives the whole allowance.
 */
export function tierSubsidyBps(tier: StakingTier, maxTierSubsidyBps: number): number {
  const span = ARCHON_BPS - NEOPHYTE_BPS;
  if (span <= 0n) return 0;
  const above = BigInt(tierMultiplierBps(tier)) - NEOPHYTE_BPS;
  if (above <= 0n) return 0;
  const scaled = (above * BigInt(Math.max(0, Math.round(maxTierSubsidyBps)))) / span;
  return Number(scaled);
}

/** Convert a coherence score in [0,1] into integer bps, rejecting NaN. */
export function coherenceToBps(coherence: number | undefined): number {
  if (coherence === undefined || !Number.isFinite(coherence)) return 0;
  const clamped = Math.min(1, Math.max(0, coherence));
  return Math.round(clamped * Number(BPS_DENOMINATOR));
}

// ═══════════════════════════════════════════════════════════════════════════
// SCHEDULE
// ═══════════════════════════════════════════════════════════════════════════

export class GasSchedule {
  public readonly config: GasScheduleConfig;

  constructor(overrides: Partial<GasScheduleConfig> = {}) {
    const config: GasScheduleConfig = { ...DEFAULT_GAS_CONFIG, ...overrides };

    assertNonNegative(config.gasPrice, 'gasPrice');
    if (config.gasPrice <= ZERO) {
      throw new TokenMathError('RANGE', 'gasPrice must be positive base units per gas unit');
    }
    assertNonNegative(config.creditsPerToken, 'creditsPerToken');
    if (config.creditsPerToken <= ZERO) {
      throw new TokenMathError('RANGE', 'creditsPerToken must be positive');
    }

    for (const key of [
      'directPaymentDiscountBps',
      'maxSubsidyBps',
      'maxTierSubsidyBps',
      'maxCoherenceSubsidyBps',
      'coherenceSubsidyThresholdBps',
      'burnBps',
      'rewardPoolBps',
      'treasuryBps'
    ] as const) {
      const value = config[key];
      if (!Number.isInteger(value) || value < 0 || value > Number(BPS_DENOMINATOR)) {
        throw new TokenMathError('RANGE', `${key} must be an integer in [0, 10000], received ${value}`);
      }
    }

    const split = config.burnBps + config.rewardPoolBps + config.treasuryBps;
    if (split !== Number(BPS_DENOMINATOR)) {
      throw new TokenMathError(
        'RANGE',
        `fee distribution must sum to 10000 bps (burn + rewardPool + treasury), got ${split}`
      );
    }

    this.config = config;
  }

  // ─── Gas metering ───────────────────────────────────────────────────────

  /** Gas units for an operation of `sizeBytes` payload. */
  public estimateGasUnits(operation: GasOperation, sizeBytes = 0): GasUnits {
    if (!Number.isInteger(sizeBytes) || sizeBytes < 0) {
      throw new TokenMathError('RANGE', `sizeBytes must be a non-negative integer, received ${sizeBytes}`);
    }
    const base = GAS_UNITS[operation] ?? DEFAULT_GAS_UNITS;
    return base + BigInt(sizeBytes) * GAS_PER_BYTE;
  }

  /** Undiscounted cost of an operation, in BASE UNITS. */
  public estimate(operation: GasOperation, sizeBytes = 0): TokenAmount {
    return this.estimateGasUnits(operation, sizeBytes) * this.config.gasPrice;
  }

  /** Cost of arbitrary gas units, in BASE UNITS. */
  public costOf(gasUnits: GasUnits): TokenAmount {
    return assertNonNegative(gasUnits, 'gasUnits') * this.config.gasPrice;
  }

  // ─── Credits ────────────────────────────────────────────────────────────

  /** Credits required to cover a base-unit cost (rounded up: never undercharge). */
  public toCredits(cost: TokenAmount): CreditUnits {
    const amount = assertNonNegative(cost, 'cost');
    const numerator = amount * this.config.creditsPerToken;
    const rounded = (numerator + ONE_TOKEN - 1n) / ONE_TOKEN;
    return creditUnits(rounded);
  }

  /** Base-unit value of a credit balance (floored: never overcredit). */
  public fromCredits(credits: CreditUnits): TokenAmount {
    return (assertNonNegative(credits, 'credits') * ONE_TOKEN) / this.config.creditsPerToken;
  }

  // ─── Subsidy ────────────────────────────────────────────────────────────

  /** Combined tier + coherence subsidy for a payer, in bps. */
  public subsidyBpsFor(payer: Pick<GasPayerContext, 'tier' | 'coherence'>): {
    tierSubsidyBps: number;
    coherenceSubsidyBps: number;
    totalSubsidyBps: number;
  } {
    const { config } = this;
    const tierBps = tierSubsidyBps(payer.tier, config.maxTierSubsidyBps);

    let coherenceBps = 0;
    const scoreBps = coherenceToBps(payer.coherence);
    if (scoreBps > config.coherenceSubsidyThresholdBps) {
      const span = BigInt(Number(BPS_DENOMINATOR) - config.coherenceSubsidyThresholdBps);
      if (span > 0n) {
        const above = BigInt(scoreBps - config.coherenceSubsidyThresholdBps);
        coherenceBps = Number((above * BigInt(config.maxCoherenceSubsidyBps)) / span);
      }
    }

    const total = Math.min(config.maxSubsidyBps, tierBps + coherenceBps);
    return { tierSubsidyBps: tierBps, coherenceSubsidyBps: coherenceBps, totalSubsidyBps: total };
  }

  // ─── Quoting ────────────────────────────────────────────────────────────

  /**
   * Full quote for one operation.
   *
   * The payer's token balance and credit balance are read from distinct,
   * differently-typed fields — they cannot be swapped by accident.
   */
  public quote(operation: GasOperation, payer: GasPayerContext, sizeBytes = 0): GasQuote {
    assertNonNegative(payer.tokenBalance, 'tokenBalance');
    assertNonNegative(payer.gasCredits, 'gasCredits');

    const gasUnits = this.estimateGasUnits(operation, sizeBytes);
    const baseCost = gasUnits * this.config.gasPrice;

    const directCost = saturatingSub(
      baseCost,
      applyBps(baseCost, this.config.directPaymentDiscountBps, 'directDiscount'),
      'directCost'
    );

    const { tierSubsidyBps: tierBps, coherenceSubsidyBps, totalSubsidyBps } = this.subsidyBpsFor(payer);
    const subsidy = applyBps(baseCost, totalSubsidyBps, 'subsidy');
    const subsidizedCost = saturatingSub(baseCost, subsidy, 'subsidizedCost');

    const creditEquivalent = this.toCredits(baseCost);

    const canPayDirect = payer.tokenBalance >= directCost;
    const canPaySubsidized = subsidy > ZERO && payer.tokenBalance >= subsidizedCost;
    const canPayCredits = payer.gasCredits >= creditEquivalent;

    let recommended: GasPaymentMethod = 'none';
    let payable: TokenAmount = ZERO;

    if (canPaySubsidized && subsidizedCost <= directCost) {
      recommended = 'subsidized';
      payable = subsidizedCost;
    } else if (canPayDirect) {
      recommended = 'direct';
      payable = directCost;
    } else if (canPayCredits) {
      recommended = 'credits';
      payable = ZERO;
    }

    return {
      operation,
      gasUnits,
      sizeBytes,
      baseCost,
      directCost,
      subsidizedCost,
      subsidy,
      tierSubsidyBps: tierBps,
      coherenceSubsidyBps,
      totalSubsidyBps,
      creditEquivalent,
      recommended,
      payable,
      affordable: recommended !== 'none',
      distribution: this.distribute(payable)
    };
  }

  /** Assert a payer can settle the quote, with a legible error. */
  public requireAffordable(quote: GasQuote, payer: GasPayerContext): GasQuote {
    if (!quote.affordable) {
      // Quote the method that actually applies: the cheapest token method
      // (direct vs subsidized) or the credit equivalent. The old message
      // quoted the subsidized cost as if it were the universal token price.
      const method = quote.subsidizedCost < quote.directCost ? 'subsidized' : 'direct';
      const tokenCost = quote.subsidizedCost < quote.directCost ? quote.subsidizedCost : quote.directCost;
      throw new TokenMathError(
        'RANGE',
        `insufficient gas funds for ${quote.operation}: ${method} token payment costs ` +
          `${formatAleph(tokenCost)}, credit payment costs ${quote.creditEquivalent} credits; ` +
          `payer has ${formatAleph(payer.tokenBalance)} tokens and ${payer.gasCredits} credits`
      );
    }
    return quote;
  }

  // ─── Fee distribution ───────────────────────────────────────────────────

  /** Split a collected fee into burn / reward pool / treasury, losing nothing. */
  public distribute(fee: TokenAmount): GasDistribution {
    const total = assertNonNegative(fee, 'fee');
    const burned = applyBps(total, this.config.burnBps, 'burn');
    const rewardPool = applyBps(total, this.config.rewardPoolBps, 'rewardPool');
    // Remainder (including floor dust) goes to the treasury so parts sum exactly.
    const treasury = total - burned - rewardPool;
    return { burned, rewardPool, treasury, total };
  }
}

/** Shared default schedule. */
export const defaultGasSchedule = new GasSchedule();
