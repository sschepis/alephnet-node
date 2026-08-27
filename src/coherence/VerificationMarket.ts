/**
 * Verification Market
 *
 * Staked, adversarial verification of claims:
 *   - a task is funded with a reward pool held in an escrow wallet
 *   - verifiers put real stake at risk before they may judge
 *   - the outcome is settled by stake-weighted majority (or injected ground truth)
 *   - correct verifiers are paid from the slashed stakes of incorrect
 *     verifiers plus the reward pool; incorrect verifiers lose part of their stake
 *   - timeouts release every stake
 *
 * Legacy bugs closed here (lib/actions/coherence.js, lib/coherence/*):
 *  - a node could verify its OWN claim: now rejected at claim, verdict and
 *    registry level.
 *  - `verificationsCorrect` was incremented unconditionally and rewards were
 *    paid for BOTH 'VERIFIED' and 'REJECTED' outcomes. Here `correct` is
 *    derived from the settled outcome and only correct verifiers earn.
 *  - `stakes.js#lockStake` never debited the wallet and `slashStake` called a
 *    non-existent `wallet.send()`. Stakes are now REAL transfers into escrow
 *    and slashes are real withheld payouts.
 *  - `rewards.js` called `wallet.receive(number)` where the wallet expected a
 *    Transaction object, so nothing was ever credited. Payouts go through
 *    `wallet.transfer()`, which actually credits the recipient ledger.
 *
 * Escrow is conserved by construction: it receives `Σ stakes + rewardPool` and
 * pays out `Σ (stake - slash) + Σ reward`, where the rewards are exactly
 * `rewardPool + Σ slash` split with {@link splitProportional} so not a single
 * base unit is minted or lost. Escrow accounting is PER TASK (and per claim
 * for backings): a settlement can only ever move what its own task escrowed,
 * never the aggregate wallet balance, so a funderless or polluted wallet can
 * not be drained through another task.
 */

import { randomBytes } from '../common/crypto';
import { StakingTier, Timestamp } from '../common/types';
import { calculateTier, tierAtLeast } from '../economy/Staking';
import {
  TokenAmount,
  ZERO,
  applyBps,
  assertNonNegative,
  assertPositive,
  formatAleph,
  safeAdd,
  safeSub,
  splitProportional,
  sumAmounts
} from '../economy/units';
import type { EconomyWallet } from '../economy/WalletPort';
import { ClaimRegistry } from './ClaimRegistry';
import {
  COHERENCE_TASK_SPECS,
  Claim,
  ClaimStatus,
  CoherenceError,
  CoherenceTaskType,
  SETTLED_CLAIM_STATUSES,
  SettlementResult,
  TaskExpiryResult,
  VERIFICATION_VERDICTS,
  VerificationTask,
  VerificationTaskStatus,
  VerificationVerdict,
  VerifierAssignment,
  VerifierSettlement,
  coherenceRewardBps
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION & INPUTS
// ═══════════════════════════════════════════════════════════════════════════

export interface VerificationMarketConfig {
  /** Verdicts required before a task may settle. */
  minVerifiers: number;
  /** Ceiling on verifiers per task. */
  maxVerifiers: number;
}

export const DEFAULT_MARKET_CONFIG: VerificationMarketConfig = {
  minVerifiers: 2,
  maxVerifiers: 16
};

/**
 * Injected settlement authority.
 *
 * The market NEVER accepts an outcome from whoever calls {@link settle} —
 * the outcome is derived from the stake-weighted majority of submitted
 * verdicts, optionally overridden by this injected authority.
 */
export interface VerificationAuthority {
  /**
   * Authoritative resolution, invoked with the task and its submitted
   * verdicts. Return a verdict to force that outcome, `null` to force an
   * inconclusive settlement, or `undefined` to defer to the stake-weighted
   * majority. Must be deterministic for a given task state: expiry retries
   * re-invoke it to resume interrupted refunds.
   */
  settleOutcome?: (
    task: VerificationTask,
    verdicts: readonly VerifierAssignment[]
  ) =>
    | Promise<VerificationVerdict | null | undefined>
    | VerificationVerdict
    | null
    | undefined;

  /** When true, settle/expire require an authorized caller. */
  requireAuthorized?: boolean;

  /** Resolve whether a caller address is authorized to settle/expire. */
  isAuthorizedCaller?: (address: string) => boolean;
}

export interface VerificationMarketOptions {
  config?: Partial<VerificationMarketConfig>;
  /** Injected settlement authority; see {@link VerificationAuthority}. */
  authority?: VerificationAuthority;
  /** Resolve a ledger address to its wallet, so stakes can actually move. */
  resolveWallet?: (address: string) => EconomyWallet | undefined;
  /** Injected clock, for deterministic tests. */
  now?: () => Timestamp;
}

export interface CreateTaskInput {
  type: CoherenceTaskType;
  claimId: string;
  /** Reward pool to escrow, in base units; defaults to the spec base reward. */
  rewardPool?: TokenAmount;
  /**
   * Wallet funding the reward pool. REQUIRED — its balance is really debited
   * before the task exists. Address-only funding is not accepted: a task
   * must hold its own escrow before anyone can be paid out of it.
   */
  funderWallet: EconomyWallet;
  /** Override the spec timeout. */
  timeoutMs?: number;
}

export interface SubmitVerdictInput {
  taskId: string;
  verifierAddress: string;
  verdict: VerificationVerdict;
  confidence?: number;
  evidence?: string;
}

export interface TaskQuery {
  status?: VerificationTaskStatus | readonly VerificationTaskStatus[];
  claimId?: string;
  verifierAddress?: string;
  limit?: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// ESCROW LEDGERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Per-task escrow ledger. Every base unit a task may ever pay out was
 * recorded here when it physically entered escrow, and every payout
 * decrements it. The aggregate wallet balance is deliberately never used as
 * a payout cap — another task's escrow (or out-of-band pollution) can not
 * be spent through this task.
 */
interface TaskEscrowLedger {
  /** Base units escrowed for this task: reward pool + Σ verifier stakes. */
  escrowed: TokenAmount;
  /** Base units already paid back out of this task's escrow. */
  released: TokenAmount;
  /** Stake refunds completed during expiry, per verifier (idempotency). */
  stakeRefunded: Map<string, TokenAmount>;
  /** True once the reward pool was refunded to the funder on expiry. */
  poolRefunded: boolean;
  /** True while an expiry pass is mid-flight (concurrency guard). */
  expiryInProgress: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function requireAddress(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new CoherenceError('CLAIM_INVALID', `${field} is required`);
  }
  return value;
}

function clampUnit(value: number | undefined, fallback = 0): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.min(1, Math.max(0, value));
}

function isVerdict(value: unknown): value is VerificationVerdict {
  return typeof value === 'string' && (VERIFICATION_VERDICTS as readonly string[]).includes(value);
}

// ═══════════════════════════════════════════════════════════════════════════
// MARKET
// ═══════════════════════════════════════════════════════════════════════════

export class VerificationMarket {
  public readonly config: VerificationMarketConfig;

  private readonly registry: ClaimRegistry;
  private readonly escrow: EconomyWallet;
  private readonly authority?: VerificationAuthority;
  private readonly resolveWallet: (address: string) => EconomyWallet | undefined;
  private readonly now: () => Timestamp;
  private readonly tasks = new Map<string, VerificationTask>();
  /** Per-task escrow accounting: what each task really holds. */
  private readonly taskEscrow = new Map<string, TaskEscrowLedger>();
  /** Per-claim escrowed backing, in base units (fed by backClaim). */
  private readonly claimEscrow = new Map<string, TokenAmount>();

  constructor(registry: ClaimRegistry, escrow: EconomyWallet, options: VerificationMarketOptions = {}) {
    if (!registry || !escrow || typeof escrow.transfer !== 'function') {
      throw new CoherenceError(
        'INVALID_CONFIG',
        'VerificationMarket requires a ClaimRegistry and an escrow wallet'
      );
    }
    if (options.authority?.requireAuthorized && typeof options.authority.isAuthorizedCaller !== 'function') {
      throw new CoherenceError(
        'INVALID_CONFIG',
        'an authority that requires authorization must provide isAuthorizedCaller'
      );
    }

    this.registry = registry;
    this.escrow = escrow;
    this.authority = options.authority;
    this.resolveWallet = options.resolveWallet ?? (() => undefined);
    this.now = options.now ?? (() => Date.now());

    const config: VerificationMarketConfig = { ...DEFAULT_MARKET_CONFIG, ...options.config };
    if (
      !Number.isInteger(config.minVerifiers) ||
      !Number.isInteger(config.maxVerifiers) ||
      config.minVerifiers < 1 ||
      config.maxVerifiers < config.minVerifiers
    ) {
      throw new CoherenceError(
        'INVALID_CONFIG',
        `verifier bounds invalid: min ${config.minVerifiers}, max ${config.maxVerifiers}`
      );
    }
    this.config = config;
  }

  /** Escrow address: the single place task funds live. */
  public get escrowAddress(): string {
    return this.escrow.address;
  }

  // ─── Tasks ──────────────────────────────────────────────────────────────

  /**
   * Create a verification task.
   *
   * The reward pool is REALLY escrowed before the task exists — without a
   * funded pool there would be nothing to pay correct verifiers with. The
   * task's own escrow ledger is opened at the same moment, so payouts can
   * only ever draw from THIS task's funds.
   */
  public async createTask(input: CreateTaskInput): Promise<VerificationTask> {
    const spec = COHERENCE_TASK_SPECS[input.type];
    if (!spec) {
      throw new CoherenceError('TASK_NOT_FOUND', `unknown task type: ${String(input.type)}`);
    }

    const claim = this.registry.require(input.claimId);
    // Tasks may only be opened on claims that still accept review work:
    // drafts never, and claims already settled (verified/rejected/archived)
    // are done.
    if (claim.status === 'draft' || SETTLED_CLAIM_STATUSES.includes(claim.status)) {
      throw new CoherenceError(
        'CLAIM_INVALID',
        `cannot verify claim ${claim.id} while it is ${claim.status}`
      );
    }

    const rewardPool = assertNonNegative(input.rewardPool ?? spec.baseReward, 'rewardPool');
    if (rewardPool <= ZERO) {
      throw new CoherenceError('CLAIM_INVALID', 'reward pool must be positive');
    }

    // A non-zero reward pool MUST come from a real wallet. A bare funder
    // address moves no funds, so the task would have nothing of its own in
    // escrow and payouts would silently draw on OTHER tasks' escrow.
    if (!input.funderWallet || typeof input.funderWallet.transfer !== 'function') {
      throw new CoherenceError(
        'CLAIM_INVALID',
        'createTask requires funderWallet: the reward pool must be really escrowed; ' +
          'a bare funder address cannot fund a non-zero reward pool'
      );
    }

    const timeoutMs = input.timeoutMs ?? spec.timeoutMs;
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new CoherenceError('INVALID_CONFIG', `timeoutMs must be a positive integer, got ${timeoutMs}`);
    }

    await this.escrowFrom(input.funderWallet, rewardPool, `reward pool for claim ${claim.id}`);

    const createdAt = this.now();
    const task: VerificationTask = {
      id: `tsk_${randomBytes(8).toString('hex')}`,
      type: input.type,
      claimId: claim.id,
      authorId: claim.authorId,
      status: 'OPEN',
      requiredStake: spec.requiredStake,
      requiredTier: spec.requiredTier,
      slashBps: spec.slashBps,
      rewardPool,
      funderAddress: input.funderWallet.address,
      minVerifiers: this.config.minVerifiers,
      maxVerifiers: this.config.maxVerifiers,
      verifiers: [],
      deadline: createdAt + timeoutMs,
      createdAt
    };

    this.tasks.set(task.id, task);
    this.taskEscrow.set(task.id, {
      escrowed: rewardPool,
      released: ZERO,
      stakeRefunded: new Map(),
      poolRefunded: false,
      expiryInProgress: false
    });

    // A claim under active verification is under review, so the settlement
    // transition ('under_review' -> verified/rejected) stays legal.
    if (claim.status === 'submitted') {
      this.registry.transition(claim.id, 'under_review');
    }

    return this.snapshot(task);
  }

  /** Get a task, or undefined. */
  public getTask(taskId: string): VerificationTask | undefined {
    const task = this.tasks.get(taskId);
    return task ? this.snapshot(task) : undefined;
  }

  /** List tasks, newest first. */
  public listTasks(query: TaskQuery = {}): VerificationTask[] {
    const statuses = query.status === undefined
      ? undefined
      : Array.isArray(query.status)
        ? query.status
        : [query.status as VerificationTaskStatus];

    let results = [...this.tasks.values()];
    if (statuses) results = results.filter(task => statuses.includes(task.status));
    if (query.claimId) results = results.filter(task => task.claimId === query.claimId);
    if (query.verifierAddress) {
      results = results.filter(task =>
        task.verifiers.some(assignment => assignment.address === query.verifierAddress)
      );
    }

    results.sort((a, b) => b.createdAt - a.createdAt || a.id.localeCompare(b.id));
    if (query.limit !== undefined && query.limit >= 0) results = results.slice(0, query.limit);

    return results.map(task => this.snapshot(task));
  }

  // ─── Claiming ───────────────────────────────────────────────────────────

  /**
   * Assign a verifier to a task.
   *
   * The verifier must not be the claim author, must hold a staking tier of at
   * least `requiredTier` (computed from the live staked balance), and their
   * stake is REALLY transferred into escrow before the assignment exists.
   */
  public async claimTask(taskId: string, verifierAddress: string): Promise<VerificationTask> {
    const address = requireAddress(verifierAddress, 'verifierAddress');
    const task = this.mutableTask(taskId);

    if (task.status !== 'OPEN' && task.status !== 'CLAIMED') {
      throw new CoherenceError('TASK_NOT_OPEN', `task ${taskId} is ${task.status}`);
    }
    if (this.now() > task.deadline) {
      throw new CoherenceError('TASK_EXPIRED', `task ${taskId} passed its deadline`);
    }

    // FLAW #5: self-verification is rejected outright.
    if (address === task.authorId) {
      throw new CoherenceError(
        'SELF_VERIFICATION',
        `the claim author ${address} may not verify their own claim`
      );
    }
    if (task.verifiers.some(assignment => assignment.address === address)) {
      throw new CoherenceError('ALREADY_ASSIGNED', `${address} is already assigned to task ${taskId}`);
    }
    if (task.verifiers.length >= task.maxVerifiers) {
      throw new CoherenceError('TASK_FULL', `task ${taskId} has reached its verifier cap`);
    }

    const wallet = this.requireWallet(address, 'verifier');
    const balance = await wallet.getBalance();

    if (balance.available < task.requiredStake) {
      throw new CoherenceError(
        'INSUFFICIENT_FUNDS',
        `verifier ${address} has ${formatAleph(balance.available)} available; ` +
          `task requires a ${formatAleph(task.requiredStake)} stake at risk`
      );
    }

    // Tier gate uses the live staked balance and `>=` thresholds.
    const tier: StakingTier = calculateTier(balance.staked);
    if (!tierAtLeast(tier, task.requiredTier)) {
      throw new CoherenceError(
        'TIER_TOO_LOW',
        `verifier ${address} is ${tier}; task requires ${task.requiredTier}`
      );
    }

    // FLAW #3: the stake genuinely leaves the verifier's wallet.
    await this.escrowFrom(wallet, task.requiredStake, `verification stake for task ${task.id}`);

    const ledger = this.requireTaskEscrow(task.id);
    ledger.escrowed = safeAdd(ledger.escrowed, task.requiredStake, 'task escrow');

    task.verifiers.push({
      address,
      tier,
      stake: task.requiredStake,
      claimedAt: this.now()
    });
    task.status = 'CLAIMED';

    return this.snapshot(task);
  }

  // ─── Backing ────────────────────────────────────────────────────────────

  /**
   * Back a claim with REAL money: `amount` leaves the wallet into escrow
   * under per-claim accounting, and only then is the backing recorded on
   * the claim. This replaces the legacy submit-time `stake`, which never
   * moved a single base unit.
   */
  public async backClaim(
    claimId: string,
    wallet: EconomyWallet,
    amount: TokenAmount,
    stakerFingerprint: string
  ): Promise<Claim> {
    const id = requireAddress(claimId, 'claimId');
    const stakerId = requireAddress(stakerFingerprint, 'stakerFingerprint');
    const value = assertPositive(amount, 'backing');
    if (!wallet || typeof wallet.transfer !== 'function') {
      throw new CoherenceError('CLAIM_INVALID', 'backClaim requires a wallet that can move funds');
    }
    if (wallet.address === this.escrow.address) {
      throw new CoherenceError('CLAIM_INVALID', 'the escrow wallet cannot back claims');
    }

    this.registry.require(id);

    await this.escrowFrom(wallet, value, `backing for claim ${id}`, 'COHERENCE_BACKING');
    this.claimEscrow.set(id, safeAdd(this.claimEscrow.get(id) ?? ZERO, value, 'claim escrow'));
    return this.registry.recordBacking(id, stakerId, value);
  }

  /** Total base units really escrowed as backing for a claim. */
  public backingEscrowed(claimId: string): TokenAmount {
    return this.claimEscrow.get(claimId) ?? ZERO;
  }

  // ─── Verdicts ───────────────────────────────────────────────────────────

  /** Record a verifier's verdict. No payout happens until settlement. */
  public submitVerdict(input: SubmitVerdictInput): VerificationTask {
    const address = requireAddress(input.verifierAddress, 'verifierAddress');
    const task = this.mutableTask(input.taskId);

    if (task.status !== 'CLAIMED' && task.status !== 'OPEN') {
      throw new CoherenceError('TASK_NOT_OPEN', `task ${task.id} is ${task.status}`);
    }
    if (this.now() > task.deadline) {
      throw new CoherenceError('TASK_EXPIRED', `task ${task.id} passed its deadline`);
    }
    if (address === task.authorId) {
      throw new CoherenceError(
        'SELF_VERIFICATION',
        `the claim author ${address} may not verify their own claim`
      );
    }
    if (!isVerdict(input.verdict)) {
      throw new CoherenceError(
        'INVALID_VERDICT',
        `verdict must be one of ${VERIFICATION_VERDICTS.join(', ')}`
      );
    }

    const assignment = task.verifiers.find(candidate => candidate.address === address);
    if (!assignment) {
      throw new CoherenceError('NOT_ASSIGNED', `${address} has not staked into task ${task.id}`);
    }
    if (assignment.verdict !== undefined) {
      throw new CoherenceError(
        'VERDICT_ALREADY_SUBMITTED',
        `${address} already submitted a verdict for task ${task.id}`
      );
    }

    assignment.verdict = input.verdict;
    assignment.confidence = clampUnit(input.confidence, 0);
    assignment.evidence = input.evidence;
    assignment.submittedAt = this.now();

    return this.snapshot(task);
  }

  // ─── Settlement ─────────────────────────────────────────────────────────

  /**
   * Settle a task.
   *
   * The outcome is NEVER taken from the caller. It is derived from the
   * stake-weighted majority of submitted verdicts; an injected
   * {@link VerificationAuthority} may override or force an inconclusive
   * result, but a caller-supplied outcome simply does not exist.
   *
   * `caller` is the address invoking settlement, required when the market
   * is configured with an authority that demands authorization.
   *
   * An inconclusive settlement (tie, or the authority declining) refunds
   * every stake AND the reward pool to the funder — nothing is stranded.
   */
  public async settle(taskId: string, caller?: string): Promise<SettlementResult> {
    const task = this.mutableTask(taskId);
    const now = this.now();

    if (task.status !== 'OPEN' && task.status !== 'CLAIMED') {
      throw new CoherenceError('TASK_NOT_OPEN', `task ${taskId} is already ${task.status}`);
    }
    if (now > task.deadline) {
      throw new CoherenceError(
        'TASK_EXPIRED',
        `task ${taskId} passed its deadline; expire it to release the stakes`
      );
    }
    this.assertAuthorized(caller, 'settle');

    // FLAW #4 (re-entrancy): the state is committed FIRST, synchronously,
    // before any await. A concurrent settle sees 'SETTLING' and is rejected,
    // so payouts execute exactly once.
    const previousStatus = task.status;
    task.status = 'SETTLING';

    const submitted = task.verifiers.filter(assignment => assignment.verdict !== undefined);
    if (submitted.length < task.minVerifiers) {
      task.status = previousStatus;
      throw new CoherenceError(
        'SETTLEMENT_PREMATURE',
        `task ${taskId} needs ${task.minVerifiers} verdict(s) to settle, has ${submitted.length}`
      );
    }

    let resolved: VerificationVerdict | undefined;
    try {
      resolved = await this.resolveOutcome(task, submitted);
    } catch (error) {
      // No funds have moved; release the state so a later settle can retry.
      task.status = previousStatus;
      throw error;
    }
    const inconclusive = resolved === undefined;

    // FLAW #5: correctness is DERIVED from the settled outcome, never assumed.
    for (const assignment of task.verifiers) {
      assignment.correct = resolved !== undefined && assignment.verdict === resolved;
    }

    const settlements: VerifierSettlement[] = task.verifiers.map(assignment => {
      const correct = assignment.correct === true;
      const slashed = inconclusive || correct
        ? ZERO
        : applyBps(assignment.stake, task.slashBps, 'slash');
      return {
        address: assignment.address,
        verdict: assignment.verdict,
        correct,
        stakeReturned: safeSub(assignment.stake, slashed, 'stakeReturned'),
        slashed,
        reward: ZERO,
        netDelta: ZERO
      };
    });

    const totalSlashed = sumAmounts(settlements.map(settlement => settlement.slashed), 'slashed');

    if (!inconclusive) {
      // Reward pool + slashed stakes fund the payouts, weighted by
      // stake x tier multiplier. Nothing is minted.
      const distributable = safeAdd(task.rewardPool, totalSlashed, 'distributable');
      const winners = task.verifiers.filter(assignment => assignment.correct === true);
      const weights = winners.map(
        assignment => assignment.stake * BigInt(coherenceRewardBps(assignment.tier))
      );
      const shares = splitProportional(distributable, weights);

      winners.forEach((assignment, index) => {
        const settlement = settlements.find(candidate => candidate.address === assignment.address);
        if (settlement) settlement.reward = shares[index] ?? ZERO;
      });
    }

    for (const settlement of settlements) {
      const stake = task.verifiers.find(a => a.address === settlement.address)?.stake ?? ZERO;
      settlement.netDelta = settlement.stakeReturned + settlement.reward - stake;
    }

    const claimStatus: ClaimStatus = inconclusive
      ? 'disputed'
      : resolved === 'VERIFIED'
        ? 'verified'
        : 'rejected';

    // Registry transition is VALIDATED before any fund movement.
    const claim = this.registry.require(task.claimId);
    if (claim.status !== claimStatus && !this.registry.canTransition(claim.status, claimStatus)) {
      throw new CoherenceError(
        'INVALID_TRANSITION',
        `cannot move claim ${task.claimId} from ${claim.status} to ${claimStatus} while settling ${taskId}`
      );
    }

    const verifierPayout = sumAmounts(
      settlements.map(settlement => safeAdd(settlement.stakeReturned, settlement.reward, 'payout')),
      'payout'
    );

    // Every settlement path drains the task escrow to zero: winners are
    // paid, or — inconclusive / all-wrong — the unclaimed remainder goes
    // back to the funder.
    const unallocated = inconclusive
      ? ZERO
      : safeSub(
          safeAdd(task.rewardPool, totalSlashed, 'distributable'),
          sumAmounts(settlements.map(settlement => settlement.reward), 'allocated'),
          'unallocated'
        );
    const funderRefund = inconclusive ? task.rewardPool : unallocated;

    this.ensureTaskEscrow(task.id, safeAdd(verifierPayout, funderRefund, 'settlement total'));

    // FLAW #3 (rewards): payouts use wallet.transfer(), which really credits
    // the recipient's ledger, instead of the legacy no-op wallet.receive().
    for (const settlement of settlements) {
      const payout = safeAdd(settlement.stakeReturned, settlement.reward, 'payout');
      if (payout > ZERO) {
        await this.payFromEscrow(task.id, settlement.address, payout, `settlement of task ${task.id}`);
      }
    }

    let refundedToFunder = ZERO;
    if (funderRefund > ZERO) {
      if (task.funderAddress && task.funderAddress !== this.escrow.address) {
        await this.payFromEscrow(
          task.id,
          task.funderAddress,
          funderRefund,
          inconclusive
            ? `inconclusive settlement: reward pool refund for task ${task.id}`
            : `unallocated pool refund for task ${task.id}`
        );
      }
      refundedToFunder = funderRefund;
    }

    for (const assignment of task.verifiers) {
      if (assignment.verdict !== undefined) {
        this.registry.recordVerification(task.claimId, {
          verifierId: assignment.address,
          verdict: assignment.verdict,
          confidence: assignment.confidence,
          stake: assignment.stake,
          correct: assignment.correct,
          settledAt: now
        });
      }
    }
    this.registry.updateConfidence(task.claimId, this.consensusConfidence(task, resolved));
    const settledClaim = this.registry.transition(task.claimId, claimStatus);

    task.status = 'SETTLED';
    task.outcome = resolved;
    task.settledAt = now;

    return {
      taskId: task.id,
      claimId: task.claimId,
      outcome: resolved,
      inconclusive,
      settledAt: now,
      rewardPool: task.rewardPool,
      totalSlashed,
      totalDistributed: sumAmounts(settlements.map(settlement => settlement.reward), 'reward'),
      refundedToFunder,
      claimStatus: settledClaim.status,
      settlements
    };
  }

  // ─── Expiry ─────────────────────────────────────────────────────────────

  /**
   * Expire one overdue task.
   *
   * The task must actually have reached its deadline. When an outcome can
   * be derived (authority, or stake-weighted majority), verifiers whose
   * verdict was wrong are slashed exactly like at settlement and the
   * slashed stakes go to the correct verifiers (or, when nobody was
   * correct, to the funder). When no outcome can be derived, everyone is
   * refunded in full. The reward pool always returns to its funder.
   *
   * Refunds are state-first and idempotent: the task commits to EXPIRED
   * before any await, and per-verifier refund flags make a retry after a
   * partial failure resume without double-paying.
   */
  public async expireTask(taskId: string, caller?: string): Promise<TaskExpiryResult> {
    const task = this.mutableTask(taskId);
    const now = this.now();

    if (task.status !== 'OPEN' && task.status !== 'CLAIMED' && task.status !== 'EXPIRED') {
      throw new CoherenceError('TASK_NOT_OPEN', `task ${taskId} is ${task.status}`);
    }
    // FLAW #2: the clock must really have run out — no early expiry.
    if (task.status !== 'EXPIRED' && now <= task.deadline) {
      throw new CoherenceError(
        'TASK_NOT_EXPIRED',
        `task ${taskId} has not reached its deadline (${task.deadline}); it cannot be expired at ${now}`
      );
    }
    this.assertAuthorized(caller, 'expire');

    const ledger = this.requireTaskEscrow(task.id);

    // FLAW #6 (state-first + idempotency): commit EXPIRED synchronously
    // before any await; a concurrent expiry is rejected and a retry after
    // a partial failure resumes through the refund flags.
    const resume = task.status === 'EXPIRED';
    if (!resume) task.status = 'EXPIRED';
    if (ledger.expiryInProgress) {
      throw new CoherenceError('EXPIRY_IN_PROGRESS', `expiry of task ${taskId} is already running`);
    }
    ledger.expiryInProgress = true;

    try {
      const submitted = task.verifiers.filter(assignment => assignment.verdict !== undefined);
      const outcome = await this.resolveOutcome(task, submitted);

      const outcomes = task.verifiers.map(assignment => {
        const slashed =
          outcome !== undefined &&
          assignment.verdict !== undefined &&
          assignment.verdict !== outcome
            ? applyBps(assignment.stake, task.slashBps, 'slash')
            : ZERO;
        return {
          assignment,
          slashed,
          stakeReturned: safeSub(assignment.stake, slashed, 'stakeReturned')
        };
      });
      const totalSlashed = sumAmounts(outcomes.map(entry => entry.slashed), 'slashed');

      let releasedStake = ZERO;
      const releasedTo: string[] = [];

      for (const entry of outcomes) {
        const already = ledger.stakeRefunded.get(entry.assignment.address) ?? ZERO;
        const due = safeSub(entry.stakeReturned, already, 'remaining stake refund');
        if (due <= ZERO) continue;
        await this.payFromEscrow(task.id, entry.assignment.address, due, `timeout release of task ${task.id}`);
        ledger.stakeRefunded.set(entry.assignment.address, safeAdd(already, due, 'refunded stake'));
        releasedStake = safeAdd(releasedStake, due, 'releasedStake');
        releasedTo.push(entry.assignment.address);
      }

      // Slashed stakes go to the verifiers who were right on timeout; when
      // nobody was right, they ride along with the funder's pool refund so
      // the task escrow still drains to zero.
      const correct = task.verifiers.filter(
        assignment => outcome !== undefined && assignment.verdict === outcome
      );
      let rewards = ZERO;
      if (totalSlashed > ZERO && correct.length > 0) {
        const weights = correct.map(
          assignment => assignment.stake * BigInt(coherenceRewardBps(assignment.tier))
        );
        const shares = splitProportional(totalSlashed, weights);
        for (let index = 0; index < correct.length; index++) {
          const share = shares[index] ?? ZERO;
          if (share <= ZERO) continue;
          await this.payFromEscrow(
            task.id,
            correct[index].address,
            share,
            `timeout slash share of task ${task.id}`
          );
          rewards = safeAdd(rewards, share, 'rewards');
        }
      }

      let refundedRewardPool = ZERO;
      if (!ledger.poolRefunded) {
        const extra = correct.length > 0 ? ZERO : totalSlashed;
        const total = safeAdd(task.rewardPool, extra, 'funder refund');
        if (total > ZERO) {
          if (task.funderAddress && task.funderAddress !== this.escrow.address) {
            await this.payFromEscrow(task.id, task.funderAddress, total, `reward pool refund for task ${task.id}`);
          }
          refundedRewardPool = total;
        }
        ledger.poolRefunded = true;
      }

      task.settledAt = this.now();

      // Release the claim back to the pool of work awaiting review.
      const claim = this.registry.get(task.claimId);
      if (claim && claim.status === 'under_review') {
        this.registry.transition(task.claimId, 'submitted');
      }

      return {
        taskId: task.id,
        releasedStake,
        refundedRewardPool,
        releasedTo,
        slashed: totalSlashed,
        rewards
      };
    } finally {
      ledger.expiryInProgress = false;
    }
  }

  /** Expire every overdue unsettled task. */
  public async expireOverdue(claimId?: string, caller?: string): Promise<TaskExpiryResult[]> {
    const now = this.now();
    const overdue = [...this.tasks.values()].filter(
      task =>
        (task.status === 'OPEN' || task.status === 'CLAIMED') &&
        now > task.deadline &&
        (claimId === undefined || task.claimId === claimId)
    );

    const results: TaskExpiryResult[] = [];
    for (const task of overdue) {
      results.push(await this.expireTask(task.id, caller));
    }
    return results;
  }

  // ─── Internals ──────────────────────────────────────────────────────────

  private mutableTask(taskId: string): VerificationTask {
    const task = this.tasks.get(taskId);
    if (!task) {
      throw new CoherenceError('TASK_NOT_FOUND', `task ${taskId} not found`);
    }
    return task;
  }

  private requireWallet(address: string, role: string): EconomyWallet {
    const wallet = this.resolveWallet(address);
    if (!wallet) {
      throw new CoherenceError(
        'CLAIM_INVALID',
        `no wallet is registered for ${role} address ${address}; stakes must be movable`
      );
    }
    return wallet;
  }

  /** Reject callers who may not settle/expire when the authority demands it. */
  private assertAuthorized(caller: string | undefined, action: string): void {
    const authority = this.authority;
    if (!authority?.requireAuthorized) return;
    if (!caller || !authority.isAuthorizedCaller?.(caller)) {
      throw new CoherenceError('UNAUTHORIZED', `${action} requires an authorized caller`);
    }
  }

  /**
   * Resolve the settlement outcome: injected authority first (which may
   * force an outcome, force inconclusiveness, or defer), otherwise the
   * stake-weighted majority. `undefined` means inconclusive.
   */
  private async resolveOutcome(
    task: VerificationTask,
    submitted: readonly VerifierAssignment[]
  ): Promise<VerificationVerdict | undefined> {
    const settleOutcome = this.authority?.settleOutcome;
    if (settleOutcome) {
      const decided = await settleOutcome(
        this.snapshot(task),
        submitted.map(assignment => ({ ...assignment }))
      );
      if (decided === null || decided === undefined) {
        // null: authority declares inconclusive; undefined: defer to majority.
        return decided === null ? undefined : this.weightedMajority(submitted);
      }
      if (!isVerdict(decided)) {
        throw new CoherenceError(
          'INVALID_VERDICT',
          `authority returned an invalid outcome; must be one of ${VERIFICATION_VERDICTS.join(', ')}`
        );
      }
      return decided;
    }
    return this.weightedMajority(submitted);
  }

  /** Stake-weighted majority verdict, or undefined on a tie. */
  private weightedMajority(verifiers: readonly VerifierAssignment[]): VerificationVerdict | undefined {
    let verifiedWeight = ZERO;
    let rejectedWeight = ZERO;

    for (const assignment of verifiers) {
      const weight = assignment.stake * BigInt(coherenceRewardBps(assignment.tier));
      if (assignment.verdict === 'VERIFIED') verifiedWeight += weight;
      else if (assignment.verdict === 'REJECTED') rejectedWeight += weight;
    }

    if (verifiedWeight === rejectedWeight) return undefined;
    return verifiedWeight > rejectedWeight ? 'VERIFIED' : 'REJECTED';
  }

  /** Move funds into escrow, surfacing wallet failures as CoherenceErrors. */
  private async escrowFrom(
    wallet: EconomyWallet,
    amount: TokenAmount,
    reason: string,
    purpose: string = 'COHERENCE_STAKE'
  ): Promise<void> {
    try {
      await wallet.transfer(this.escrow.address, amount, { purpose, memo: reason });
    } catch (error) {
      throw new CoherenceError(
        'ESCROW_FAILURE',
        `could not escrow ${formatAleph(amount)} (${reason}): ` +
          `${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /** The per-task escrow ledger, or a typed error when absent. */
  private requireTaskEscrow(taskId: string): TaskEscrowLedger {
    const ledger = this.taskEscrow.get(taskId);
    if (!ledger) {
      throw new CoherenceError(
        'ESCROW_FAILURE',
        `no escrow ledger for task ${taskId}; the task was never funded`
      );
    }
    return ledger;
  }

  /**
   * Verify the TASK'S OWN escrow can cover the whole settlement before
   * paying anyone. The aggregate wallet balance is never consulted — funds
   * escrowed by other tasks (or dropped into the wallet out of band) are
   * not spendable here.
   */
  private ensureTaskEscrow(taskId: string, required: TokenAmount): void {
    const ledger = this.requireTaskEscrow(taskId);
    const remaining = safeSub(ledger.escrowed, ledger.released, 'task escrow');
    if (remaining < required) {
      throw new CoherenceError(
        'ESCROW_FAILURE',
        `task ${taskId} holds ${formatAleph(remaining)} in escrow but the settlement ` +
          `requires ${formatAleph(required)}`
      );
    }
  }

  /**
   * Pay out of the task's own escrow. `transfer` really credits the
   * recipient ledger; the per-task ledger is only decremented after the
   * transfer succeeds, so a failed transfer can be retried safely.
   */
  private async payFromEscrow(
    taskId: string,
    to: string,
    amount: TokenAmount,
    reason: string
  ): Promise<void> {
    if (amount <= ZERO) return;
    const ledger = this.requireTaskEscrow(taskId);
    const remaining = safeSub(ledger.escrowed, ledger.released, 'task escrow');
    if (amount > remaining) {
      throw new CoherenceError(
        'ESCROW_FAILURE',
        `task ${taskId} escrow holds ${formatAleph(remaining)}; cannot pay ` +
          `${formatAleph(amount)} (${reason})`
      );
    }
    try {
      await this.escrow.transfer(to, amount, { purpose: 'COHERENCE_REWARD', memo: reason });
    } catch (error) {
      throw new CoherenceError(
        'ESCROW_FAILURE',
        `${reason}: transfer of ${formatAleph(amount)} failed: ` +
          `${error instanceof Error ? error.message : String(error)}`
      );
    }
    ledger.released = safeAdd(ledger.released, amount, 'released escrow');
  }

  /**
   * Aggregate confidence: the agreeing share of submitted stake.
   *
   * Computed in pure bigint — the ratio is scaled to six fraction digits
   * and converted through its exact decimal expansion, so no astronomical
   * amount is ever pushed through a floating-point conversion.
   */
  private consensusConfidence(
    task: VerificationTask,
    outcome: VerificationVerdict | undefined
  ): number {
    if (outcome === undefined) return 0.5;

    let submitted = ZERO;
    let agreeing = ZERO;
    for (const assignment of task.verifiers) {
      if (assignment.verdict === undefined) continue;
      submitted = safeAdd(submitted, assignment.stake, 'submitted stake');
      if (assignment.verdict === outcome) agreeing = safeAdd(agreeing, assignment.stake, 'agreeing stake');
    }
    if (submitted === ZERO) return 0.5;

    const SCALE = 1_000_000n;
    const scaled = (agreeing * SCALE) / submitted;
    const whole = scaled / SCALE;
    const fraction = (scaled % SCALE).toString().padStart(6, '0');
    return Number(`${whole}.${fraction}`);
  }

  private snapshot(task: VerificationTask): VerificationTask {
    return { ...task, verifiers: task.verifiers.map(assignment => ({ ...assignment })) };
  }
}
