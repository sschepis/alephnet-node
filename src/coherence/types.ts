/**
 * Coherence Types
 *
 * Claims, edges, verification tasks and their economics.
 *
 * Legacy bugs closed here (lib/coherence/types.js):
 *  - stakes and rewards were `number` (`minStake: 100`, `baseReward: 10`), mixed
 *    with token balances. Every amount here is a bigint in base units.
 *  - tier tables were re-declared with their own thresholds and multipliers,
 *    diverging from the canonical ones. Tiers, thresholds, capabilities and
 *    multipliers are imported from `common` / `economy`.
 *  - claim status was a bag of strings with no legal transitions.
 *    {@link CLAIM_TRANSITIONS} makes the lifecycle explicit and enforceable.
 */

import { StakingTier, TIER_ORDER, TIER_THRESHOLDS, Timestamp } from '../common/types';
import {
  StakingCapability,
  capabilitiesFor,
  rewardMultiplierBps,
  tierRewardBps
} from '../economy/Staking';
import { TokenAmount, wholeTokens } from '../economy/units';

// ═══════════════════════════════════════════════════════════════════════════
// CLAIM LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════════

export type ClaimStatus =
  | 'draft'
  | 'submitted'
  | 'under_review'
  | 'verified'
  | 'disputed'
  | 'rejected'
  | 'archived';

/** Legal claim status transitions. Anything else is rejected. */
export const CLAIM_TRANSITIONS: Record<ClaimStatus, readonly ClaimStatus[]> = {
  draft: ['submitted', 'archived'],
  submitted: ['under_review', 'rejected', 'archived'],
  under_review: ['verified', 'rejected', 'disputed', 'submitted'],
  verified: ['disputed', 'archived'],
  disputed: ['under_review', 'verified', 'rejected'],
  rejected: ['disputed', 'archived'],
  archived: []
};

/** Terminal-ish statuses that no longer accept verification work. */
export const SETTLED_CLAIM_STATUSES: readonly ClaimStatus[] = ['verified', 'rejected', 'archived'];

// ═══════════════════════════════════════════════════════════════════════════
// EDGES
// ═══════════════════════════════════════════════════════════════════════════

export type EdgeType = 'supports' | 'contradicts' | 'refines' | 'derives_from' | 'equivalent';

export const EDGE_TYPES: readonly EdgeType[] = [
  'supports',
  'contradicts',
  'refines',
  'derives_from',
  'equivalent'
];

/** Per-type inbound edge counts for a claim. */
export type EdgeCounts = Record<EdgeType, number>;

export function emptyEdgeCounts(): EdgeCounts {
  return { supports: 0, contradicts: 0, refines: 0, derives_from: 0, equivalent: 0 };
}

export interface ClaimEdge {
  id: string;
  fromClaimId: string;
  toClaimId: string;
  edgeType: EdgeType;
  authorId: string;
  /** Author's stated confidence in [0, 1]. */
  confidence: number;
  /** Semantic similarity in [0, 1]. */
  semanticSimilarity: number;
  evidence?: string;
  createdAt: Timestamp;
}

// ═══════════════════════════════════════════════════════════════════════════
// CLAIMS
// ═══════════════════════════════════════════════════════════════════════════

export type VerificationVerdict = 'VERIFIED' | 'REJECTED';

export const VERIFICATION_VERDICTS: readonly VerificationVerdict[] = ['VERIFIED', 'REJECTED'];

/** One verifier's recorded opinion on a claim. */
export interface ClaimVerification {
  verifierId: string;
  verdict: VerificationVerdict;
  /** Verifier's confidence in [0, 1]. */
  confidence: number;
  /** Stake the verifier had at risk, in base units. */
  stake: TokenAmount;
  /** Set at settlement: did this verdict match the settled outcome? */
  correct?: boolean;
  timestamp: Timestamp;
  settledAt?: Timestamp;
}

/** One escrowed backing of a claim, in base units. */
export interface ClaimBacking {
  stakerId: string;
  amount: TokenAmount;
  timestamp: Timestamp;
}

export interface Claim {
  id: string;
  title: string;
  statement: string;
  authorId: string;
  status: ClaimStatus;
  /** Aggregate confidence in [0, 1]. */
  confidence: number;
  semanticHash?: string;
  roomId?: string;
  edges: EdgeCounts;
  verifications: ClaimVerification[];
  /**
   * Backing escrowed through {@link VerificationMarket.backClaim}, in base
   * units. Only REAL escrowed funds appear here — a caller-supplied `stake`
   * at submit time never moves money and is ignored.
   */
  stake: TokenAmount;
  /** Every escrowed backing behind `stake`, oldest first. */
  backings: ClaimBacking[];
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

// ═══════════════════════════════════════════════════════════════════════════
// TIER CAPABILITIES
// ═══════════════════════════════════════════════════════════════════════════

/** Coherence capabilities are the canonical staking capabilities. */
export type CoherenceCapability = StakingCapability;

export interface CoherenceTierProfile {
  tier: StakingTier;
  minStake: TokenAmount;
  capabilities: CoherenceCapability[];
  /** Reward multiplier in bps (10_000 == 1.0x), from TIER_MULTIPLIERS. */
  rewardMultiplierBps: number;
}

/** Tier table built from the canonical thresholds, capabilities and multipliers. */
export const COHERENCE_TIERS: Record<StakingTier, CoherenceTierProfile> = TIER_ORDER.reduce(
  (table, tier) => {
    table[tier] = {
      tier,
      minStake: TIER_THRESHOLDS[tier],
      capabilities: capabilitiesFor(tier),
      rewardMultiplierBps: tierRewardBps(tier)
    };
    return table;
  },
  {} as Record<StakingTier, CoherenceTierProfile>
);

/** Reward weight of a tier, in bps. Re-exported for reward splitting. */
export function coherenceRewardBps(tier: StakingTier): number {
  return rewardMultiplierBps(tier);
}

// ═══════════════════════════════════════════════════════════════════════════
// TASKS
// ═══════════════════════════════════════════════════════════════════════════

export type CoherenceTaskType = 'VERIFY' | 'COUNTEREXAMPLE' | 'SYNTHESIZE' | 'SECURITY_REVIEW';

export interface CoherenceTaskSpec {
  name: string;
  /** Stake a verifier must put at risk, in base units. */
  requiredStake: TokenAmount;
  /** Default reward pool for the task, in base units. */
  baseReward: TokenAmount;
  /** Minimum staking tier permitted to take the task. */
  requiredTier: StakingTier;
  /** Capability the tier must grant. */
  capability: CoherenceCapability;
  /** How long a claimed task may run before it times out. */
  timeoutMs: number;
  /** Portion of an incorrect verifier's stake that is slashed, in bps. */
  slashBps: number;
}

const MINUTE = 60 * 1000;

export const COHERENCE_TASK_SPECS: Record<CoherenceTaskType, CoherenceTaskSpec> = {
  VERIFY: {
    name: 'Verify Claim',
    requiredStake: wholeTokens(25),
    baseReward: wholeTokens(10),
    requiredTier: 'Adept',
    capability: 'verify_claims',
    timeoutMs: 60 * MINUTE,
    slashBps: 5_000
  },
  COUNTEREXAMPLE: {
    name: 'Find Counterexample',
    requiredStake: wholeTokens(50),
    baseReward: wholeTokens(25),
    requiredTier: 'Adept',
    capability: 'verify_claims',
    timeoutMs: 120 * MINUTE,
    slashBps: 2_500
  },
  SYNTHESIZE: {
    name: 'Create Synthesis',
    requiredStake: wholeTokens(100),
    baseReward: wholeTokens(50),
    requiredTier: 'Magus',
    capability: 'create_synthesis',
    timeoutMs: 240 * MINUTE,
    slashBps: 3_000
  },
  SECURITY_REVIEW: {
    name: 'Security Review',
    requiredStake: wholeTokens(500),
    baseReward: wholeTokens(100),
    requiredTier: 'Archon',
    capability: 'security_review',
    timeoutMs: 480 * MINUTE,
    slashBps: 2_000
  }
};

/** Task timeouts, derived from the specs. */
export const COHERENCE_TASK_TIMEOUTS: Record<CoherenceTaskType, number> = Object.fromEntries(
  (Object.keys(COHERENCE_TASK_SPECS) as CoherenceTaskType[]).map(type => [
    type,
    COHERENCE_TASK_SPECS[type].timeoutMs
  ])
) as Record<CoherenceTaskType, number>;

export type VerificationTaskStatus =
  | 'OPEN'
  | 'CLAIMED'
  | 'SETTLING'
  | 'SETTLED'
  | 'EXPIRED'
  | 'CANCELLED';

/** A verifier who has staked into a task. */
export interface VerifierAssignment {
  address: string;
  /** Tier at claim time, drives reward weighting. */
  tier: StakingTier;
  /** Stake genuinely transferred into escrow, in base units. */
  stake: TokenAmount;
  claimedAt: Timestamp;
  verdict?: VerificationVerdict;
  confidence?: number;
  evidence?: string;
  submittedAt?: Timestamp;
  /** Set at settlement: did this verdict match the settled outcome? */
  correct?: boolean;
}

export interface VerificationTask {
  id: string;
  type: CoherenceTaskType;
  claimId: string;
  /** Claim author — may never verify their own claim. */
  authorId: string;
  status: VerificationTaskStatus;
  requiredStake: TokenAmount;
  requiredTier: StakingTier;
  slashBps: number;
  /** Reward pool held in escrow, in base units. */
  rewardPool: TokenAmount;
  /** Address that funded the reward pool, refunded on expiry. */
  funderAddress?: string;
  minVerifiers: number;
  maxVerifiers: number;
  verifiers: VerifierAssignment[];
  deadline: Timestamp;
  createdAt: Timestamp;
  settledAt?: Timestamp;
  /** Settled outcome; undefined when inconclusive. */
  outcome?: VerificationVerdict;
}

// ═══════════════════════════════════════════════════════════════════════════
// SETTLEMENT
// ═══════════════════════════════════════════════════════════════════════════

/** Per-verifier settlement detail. All amounts in base units. */
export interface VerifierSettlement {
  address: string;
  verdict?: VerificationVerdict;
  /** True only when the verdict matched the settled outcome. */
  correct: boolean;
  /** Stake returned from escrow. */
  stakeReturned: TokenAmount;
  /** Stake permanently forfeited. */
  slashed: TokenAmount;
  /** Reward paid — non-zero ONLY for correct verifiers. */
  reward: TokenAmount;
  /** Net balance delta for this verifier across claim + settle. */
  netDelta: TokenAmount;
}

export interface SettlementResult {
  taskId: string;
  claimId: string;
  outcome?: VerificationVerdict;
  /** True when no majority could be established; all stakes were returned. */
  inconclusive: boolean;
  settledAt: Timestamp;
  rewardPool: TokenAmount;
  totalSlashed: TokenAmount;
  totalDistributed: TokenAmount;
  /**
   * Escrow returned to the funder instead of verifiers: the whole reward
   * pool on an inconclusive settlement, or the unallocated remainder when
   * nobody was correct.
   */
  refundedToFunder: TokenAmount;
  claimStatus: ClaimStatus;
  settlements: VerifierSettlement[];
}

/** Outcome of expiring one overdue task. */
export interface TaskExpiryResult {
  taskId: string;
  releasedStake: TokenAmount;
  refundedRewardPool: TokenAmount;
  releasedTo: string[];
  /** Stake forfeited by verifiers whose verdict was wrong on timeout. */
  slashed: TokenAmount;
  /** Slashes distributed to the correct verifiers on timeout. */
  rewards: TokenAmount;
}

// ═══════════════════════════════════════════════════════════════════════════
// REWARD ACTIONS
// ═══════════════════════════════════════════════════════════════════════════

export type RewardAction =
  | 'CLAIM_SUBMITTED'
  | 'CLAIM_VERIFIED'
  | 'COUNTEREXAMPLE_FOUND'
  | 'SYNTHESIS_CREATED'
  | 'SECURITY_REVIEW_COMPLETED';

export interface RewardActionSpec {
  baseAmount: TokenAmount;
  stakeRequired: TokenAmount;
  slashBps: number;
}

export const REWARD_ACTIONS: Record<RewardAction, RewardActionSpec> = {
  CLAIM_SUBMITTED: { baseAmount: wholeTokens(5), stakeRequired: wholeTokens(10), slashBps: 5_000 },
  CLAIM_VERIFIED: { baseAmount: wholeTokens(10), stakeRequired: wholeTokens(25), slashBps: 5_000 },
  COUNTEREXAMPLE_FOUND: { baseAmount: wholeTokens(25), stakeRequired: wholeTokens(50), slashBps: 2_500 },
  SYNTHESIS_CREATED: { baseAmount: wholeTokens(50), stakeRequired: wholeTokens(100), slashBps: 3_000 },
  SECURITY_REVIEW_COMPLETED: {
    baseAmount: wholeTokens(100),
    stakeRequired: wholeTokens(500),
    slashBps: 2_000
  }
};

/** Weights for the agent coherence score. */
export const COHERENCE_WEIGHTS = {
  verificationAccuracy: 0.3,
  claimAcceptance: 0.25,
  synthesisQuality: 0.25,
  networkTrust: 0.2
} as const;

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

export type CoherenceErrorCode =
  | 'CLAIM_NOT_FOUND'
  | 'CLAIM_INVALID'
  | 'INVALID_TRANSITION'
  | 'EDGE_INVALID'
  | 'TASK_NOT_FOUND'
  | 'TASK_NOT_OPEN'
  | 'TASK_FULL'
  | 'TASK_EXPIRED'
  | 'TASK_NOT_EXPIRED'
  | 'EXPIRY_IN_PROGRESS'
  | 'SELF_VERIFICATION'
  | 'ALREADY_ASSIGNED'
  | 'NOT_ASSIGNED'
  | 'VERDICT_ALREADY_SUBMITTED'
  | 'INVALID_VERDICT'
  | 'TIER_TOO_LOW'
  | 'INSUFFICIENT_FUNDS'
  | 'SETTLEMENT_PREMATURE'
  | 'ESCROW_FAILURE'
  | 'UNAUTHORIZED'
  | 'INVALID_CONFIG';

export class CoherenceError extends Error {
  public readonly code: CoherenceErrorCode;

  constructor(code: CoherenceErrorCode, message: string) {
    super(message);
    this.name = 'CoherenceError';
    this.code = code;
  }
}
