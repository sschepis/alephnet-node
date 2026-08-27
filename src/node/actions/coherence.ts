/**
 * Coherence Actions
 *
 * `coherence.submitClaim` / `coherence.listClaims` / `coherence.createTask` /
 * `coherence.claimTask` / `coherence.submitVerdict`.
 *
 * The claim registry is always available; the verification market moves real
 * stakes and rewards through wallets, so it exists only when a Gun ledger is
 * wired in. Without one, the market actions return the typed
 * `SUBSYSTEM_UNAVAILABLE` failure — never a bookkeeping-only fake.
 *
 * All bigint amounts in records are formatted as decimal strings on the way
 * out (JSON cannot carry bigint), and the author / verifier / funder is
 * ALWAYS the authenticated caller.
 */

import type { ActionModule } from '../../app';
import type { CoherenceSubsystem, EconomySubsystem } from '../types';
import type { VerificationVerdict, CoherenceTaskType } from '../../coherence';
import { CoherenceError } from '../../coherence';
import { TokenMathError, formatTokens, parseTokens } from '../../economy';
import {
  action,
  DomainActionError,
  requireActor,
  requireCallerWallet,
  unavailable
} from './helpers';

// ═══════════════════════════════════════════════════════════════════════════
// DEPS
// ═══════════════════════════════════════════════════════════════════════════

export interface CoherenceActionDeps {
  readonly coherence: CoherenceSubsystem;
  readonly economy: EconomySubsystem;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function requireMarket(deps: CoherenceActionDeps) {
  if (deps.coherence.market === null) {
    throw unavailable(
      'coherence',
      deps.coherence.marketReason ?? 'no Gun ledger supplied for the verification market'
    );
  }
  return deps.coherence.market;
}

/**
 * The verification market's availability gate, evaluated by the registry
 * BEFORE tier gating: a no-ledger node reports 503 SUBSYSTEM_UNAVAILABLE,
 * never a per-caller 403 TIER_REQUIRED.
 */
function marketAvailability(deps: CoherenceActionDeps): { available: boolean; reason?: string } {
  return deps.coherence.market !== null
    ? { available: true }
    : {
        available: false,
        reason:
          deps.coherence.marketReason ?? 'no Gun ledger supplied for the verification market'
      };
}

/** Bigint-free copies of domain records (JSON cannot serialize bigint). */
function sanitizeClaim(claim: {
  readonly id: string;
  readonly title: string;
  readonly statement: string;
  readonly authorId: string;
  readonly status: string;
  readonly confidence: number;
  readonly semanticHash?: string;
  readonly roomId?: string;
  readonly edges: Record<string, number>;
  readonly verifications: readonly {
    readonly verifierId: string;
    readonly verdict: string;
    readonly confidence: number;
    readonly stake: bigint;
    readonly correct?: boolean;
    readonly timestamp: number;
    readonly settledAt?: number;
  }[];
  readonly stake: bigint;
  readonly createdAt: number;
  readonly updatedAt: number;
}): Record<string, unknown> {
  return {
    id: claim.id,
    title: claim.title,
    statement: claim.statement,
    authorId: claim.authorId,
    status: claim.status,
    confidence: claim.confidence,
    ...(claim.semanticHash === undefined ? {} : { semanticHash: claim.semanticHash }),
    ...(claim.roomId === undefined ? {} : { roomId: claim.roomId }),
    edges: claim.edges,
    verifications: claim.verifications.map((verification) => ({
      verifierId: verification.verifierId,
      verdict: verification.verdict,
      confidence: verification.confidence,
      stake: formatTokens(verification.stake),
      ...(verification.correct === undefined ? {} : { correct: verification.correct }),
      timestamp: verification.timestamp,
      ...(verification.settledAt === undefined ? {} : { settledAt: verification.settledAt })
    })),
    stake: formatTokens(claim.stake),
    createdAt: claim.createdAt,
    updatedAt: claim.updatedAt
  };
}

function sanitizeTask(task: {
  readonly id: string;
  readonly type: string;
  readonly claimId: string;
  readonly authorId: string;
  readonly status: string;
  readonly requiredStake: bigint;
  readonly requiredTier: string;
  readonly slashBps: number;
  readonly rewardPool: bigint;
  readonly funderAddress?: string;
  readonly minVerifiers: number;
  readonly maxVerifiers: number;
  readonly verifiers: readonly {
    readonly address: string;
    readonly tier: string;
    readonly stake: bigint;
    readonly claimedAt: number;
    readonly verdict?: string;
    readonly confidence?: number;
    readonly evidence?: string;
    readonly submittedAt?: number;
    readonly correct?: boolean;
  }[];
  readonly deadline: number;
  readonly createdAt: number;
  readonly settledAt?: number;
  readonly outcome?: string;
}): Record<string, unknown> {
  return {
    id: task.id,
    type: task.type,
    claimId: task.claimId,
    authorId: task.authorId,
    status: task.status,
    requiredStake: formatTokens(task.requiredStake),
    requiredTier: task.requiredTier,
    slashBps: task.slashBps,
    rewardPool: formatTokens(task.rewardPool),
    ...(task.funderAddress === undefined ? {} : { funderAddress: task.funderAddress }),
    minVerifiers: task.minVerifiers,
    maxVerifiers: task.maxVerifiers,
    verifiers: task.verifiers.map((assignment) => ({
      address: assignment.address,
      tier: assignment.tier,
      stake: formatTokens(assignment.stake),
      claimedAt: assignment.claimedAt,
      ...(assignment.verdict === undefined ? {} : { verdict: assignment.verdict }),
      ...(assignment.confidence === undefined ? {} : { confidence: assignment.confidence }),
      ...(assignment.evidence === undefined ? {} : { evidence: assignment.evidence }),
      ...(assignment.submittedAt === undefined ? {} : { submittedAt: assignment.submittedAt }),
      ...(assignment.correct === undefined ? {} : { correct: assignment.correct })
    })),
    deadline: task.deadline,
    createdAt: task.createdAt,
    ...(task.settledAt === undefined ? {} : { settledAt: task.settledAt }),
    ...(task.outcome === undefined ? {} : { outcome: task.outcome })
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// MODULE
// ═══════════════════════════════════════════════════════════════════════════

export function createCoherenceActions(deps: CoherenceActionDeps): ActionModule {
  return {
    namespace: 'coherence',
    actions: [
      // ── coherence.submitClaim ────────────────────────────────────────────
      action({
        name: 'coherence.submitClaim',
        description:
          'Submit a claim to the registry; an optional stake is REALLY escrowed from the caller\'s wallet. The author is the authenticated caller.',
        input: {
          title: { type: 'string', required: true, minLength: 1, maxLength: 200 },
          statement: { type: 'string', required: true, minLength: 1, maxLength: 20_000 },
          roomId: { type: 'string', maxLength: 128 },
          semanticHash: { type: 'string', pattern: /^[0-9a-f]{64}$/ },
          confidence: { type: 'number', min: 0, max: 1 },
          stake: { type: 'string', minLength: 1, maxLength: 96, description: 'Decimal backing stake, e.g. "10"' }
        },
        requiredTier: 'Adept',
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          let stake: bigint | undefined;
          if (input.stake !== undefined) {
            try {
              stake = parseTokens(input.stake as string);
            } catch (error) {
              if (error instanceof TokenMathError) {
                throw new DomainActionError('INVALID_AMOUNT', error.message);
              }
              throw error;
            }
            if (stake <= 0n) {
              throw new DomainActionError('INVALID_AMOUNT', 'stake must be positive');
            }
          }

          // The registry IGNORES a caller-supplied stake (a claim's stake
          // only ever holds REAL escrowed backing). The bookkeeping-only fake
          // is gone: a requested stake must actually leave the caller's
          // ledger via the market's backClaim.
          const claim = deps.coherence.registry.submit({
            title: input.title as string,
            statement: input.statement as string,
            authorId: identity.fingerprint,
            roomId: input.roomId as string | undefined,
            semanticHash: input.semanticHash as string | undefined,
            confidence: input.confidence as number | undefined
          });

          if (stake === undefined) {
            return sanitizeClaim(claim);
          }

          // A stake without a ledger cannot move any funds — report the
          // missing prerequisite instead of recording a fake backing.
          if (!deps.economy.enabled) {
            throw new DomainActionError(
              'STAKE_REQUIRES_LEDGER',
              'stake requires a ledger',
              { subsystem: 'economy', details: { reason: deps.economy.reason ?? 'no Gun ledger supplied' } }
            );
          }

          const market = requireMarket(deps);
          const wallet = requireCallerWallet(deps.economy, identity);
          try {
            const backed = await market.backClaim(
              claim.id,
              wallet,
              stake,
              identity.fingerprint
            );
            return sanitizeClaim(backed);
          } catch (error) {
            if (error instanceof CoherenceError) {
              throw new DomainActionError(error.code, error.message);
            }
            throw error;
          }
        }
      }),

      // ── coherence.listClaims ─────────────────────────────────────────────
      action({
        name: 'coherence.listClaims',
        description: 'List claims in the registry, newest first, optionally filtered.',
        input: {
          status: { type: 'string', enum: ['draft', 'submitted', 'under_review', 'verified', 'disputed', 'rejected', 'archived'] },
          authorId: { type: 'string', pattern: /^[0-9a-f]{16}$/ },
          limit: { type: 'integer', min: 1, max: 500, default: 100 }
        },
        handler: (input) => {
          const claims = deps.coherence.registry.list({
            ...(input.status === undefined ? {} : { status: input.status as never }),
            ...(input.authorId === undefined ? {} : { authorId: input.authorId as string }),
            limit: input.limit as number
          });
          return { claims: claims.map(sanitizeClaim) };
        }
      }),

      // ── coherence.createTask ─────────────────────────────────────────────
      action({
        name: 'coherence.createTask',
        description:
          'Open a staked verification task on a claim. The reward pool is REALLY escrowed from the caller\'s wallet.',
        input: {
          type: { type: 'string', required: true, enum: ['VERIFY', 'COUNTEREXAMPLE', 'SYNTHESIZE', 'SECURITY_REVIEW'] },
          claimId: { type: 'string', required: true, minLength: 1, maxLength: 128 },
          rewardPool: { type: 'string', minLength: 1, maxLength: 96, description: 'Decimal reward pool, e.g. "10"' },
          timeoutMs: { type: 'integer', min: 1_000, max: 86_400_000 }
        },
        requiredTier: 'Adept',
        availability: () => marketAvailability(deps),
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          const market = requireMarket(deps);
          let rewardPool: bigint | undefined;
          if (input.rewardPool !== undefined) {
            try {
              rewardPool = parseTokens(input.rewardPool as string);
            } catch (error) {
              if (error instanceof TokenMathError) {
                throw new DomainActionError('INVALID_AMOUNT', error.message);
              }
              throw error;
            }
          }
          // The funder is the authenticated caller; their wallet is derived
          // from their verified public key and must cover the pool.
          const funderWallet = requireCallerWallet(deps.economy, identity);
          try {
            const task = await market.createTask({
              type: input.type as CoherenceTaskType,
              claimId: input.claimId as string,
              rewardPool,
              funderWallet,
              timeoutMs: input.timeoutMs as number | undefined
            });
            return sanitizeTask(task);
          } catch (error) {
            if (error instanceof CoherenceError) {
              throw new DomainActionError(error.code, error.message);
            }
            throw error;
          }
        }
      }),

      // ── coherence.claimTask ──────────────────────────────────────────────
      action({
        name: 'coherence.claimTask',
        description:
          'Stake into a verification task as a verifier. The stake REALLY leaves the caller\'s wallet into escrow.',
        input: {
          taskId: { type: 'string', required: true, minLength: 1, maxLength: 128 }
        },
        requiredTier: 'Adept',
        availability: () => marketAvailability(deps),
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          const market = requireMarket(deps);
          // Register the caller's wallet with the market's resolver so the
          // stake can actually move (address = verified fingerprint).
          requireCallerWallet(deps.economy, identity);
          try {
            const task = await market.claimTask(input.taskId as string, identity.fingerprint);
            return sanitizeTask(task);
          } catch (error) {
            if (error instanceof CoherenceError) {
              throw new DomainActionError(error.code, error.message);
            }
            throw error;
          }
        }
      }),

      // ── coherence.submitVerdict ──────────────────────────────────────────
      action({
        name: 'coherence.submitVerdict',
        description: 'Submit a verdict for a task the authenticated caller has staked into.',
        input: {
          taskId: { type: 'string', required: true, minLength: 1, maxLength: 128 },
          verdict: { type: 'string', required: true, enum: ['VERIFIED', 'REJECTED'] },
          confidence: { type: 'number', min: 0, max: 1 },
          evidence: { type: 'string', maxLength: 10_000 }
        },
        requiredTier: 'Adept',
        availability: () => marketAvailability(deps),
        handler: (input, ctx) => {
          const identity = requireActor(ctx);
          const market = requireMarket(deps);
          try {
            const task = market.submitVerdict({
              taskId: input.taskId as string,
              verifierAddress: identity.fingerprint,
              verdict: input.verdict as VerificationVerdict,
              confidence: input.confidence as number | undefined,
              evidence: input.evidence as string | undefined
            });
            return sanitizeTask(task);
          } catch (error) {
            if (error instanceof CoherenceError) {
              throw new DomainActionError(error.code, error.message);
            }
            throw error;
          }
        }
      })
    ]
  };
}
