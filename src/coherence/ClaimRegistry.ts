/**
 * Claim Registry
 *
 * In-memory store for claims and their typed edges, with an enforced
 * lifecycle.
 *
 * Legacy bugs closed here (lib/actions/coherence.js):
 *  - claim status was assigned directly (`claim.status = ...`) from anywhere,
 *    with no legal-transition check. {@link ClaimRegistry.transition} validates
 *    against CLAIM_TRANSITIONS.
 *  - `coherence.verifyClaim` let a node verify its OWN claim and pushed the
 *    verification unconditionally. {@link ClaimRegistry.recordVerification}
 *    rejects self-verification as a second line of defence behind the market.
 *  - ids came from `Date.now() + Math.random()`. Ids use crypto randomness.
 */

import { randomBytes } from '../common/crypto';
import { Timestamp } from '../common/types';
import { TokenAmount, ZERO, assertNonNegative, assertPositive, safeAdd } from '../economy/units';
import {
  CLAIM_TRANSITIONS,
  Claim,
  ClaimBacking,
  ClaimEdge,
  ClaimStatus,
  ClaimVerification,
  CoherenceError,
  EDGE_TYPES,
  EdgeCounts,
  EdgeType,
  VERIFICATION_VERDICTS,
  VerificationVerdict,
  emptyEdgeCounts
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// INPUTS
// ═══════════════════════════════════════════════════════════════════════════

export interface SubmitClaimInput {
  title: string;
  statement: string;
  authorId: string;
  roomId?: string;
  semanticHash?: string;
  /** Initial confidence in [0, 1]. */
  confidence?: number;
  /**
   * @deprecated A caller-supplied stake never moves funds and is IGNORED.
   * A claim's backing comes only from {@link VerificationMarket.backClaim},
   * which really escrows the amount before it appears on the claim.
   */
  stake?: TokenAmount;
  /** Defaults to 'submitted'. Only 'draft' or 'submitted' are legal here. */
  status?: Extract<ClaimStatus, 'draft' | 'submitted'>;
}

export interface CreateEdgeInput {
  fromClaimId: string;
  toClaimId: string;
  edgeType: EdgeType;
  authorId: string;
  confidence?: number;
  semanticSimilarity?: number;
  evidence?: string;
}

export interface ClaimFilter {
  status?: ClaimStatus | readonly ClaimStatus[];
  authorId?: string;
  roomId?: string;
  limit?: number;
}

export interface EdgeFilter {
  fromClaimId?: string;
  toClaimId?: string;
  edgeType?: EdgeType;
  authorId?: string;
  limit?: number;
}

export interface RecordVerificationInput {
  verifierId: string;
  verdict: ClaimVerification['verdict'];
  confidence?: number;
  stake?: TokenAmount;
  correct?: boolean;
  settledAt?: Timestamp;
}

export interface ClaimRegistryOptions {
  now?: () => Timestamp;
  idFactory?: (prefix: string) => string;
}

export interface RegistryStats {
  claims: number;
  edges: number;
  byStatus: Record<ClaimStatus, number>;
  totalStake: TokenAmount;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function clampUnit(value: number | undefined, fallback = 0): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.min(1, Math.max(0, value));
}

function requireNonEmpty(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new CoherenceError('CLAIM_INVALID', `${field} is required`);
  }
  return value.trim();
}

function isVerdict(value: unknown): value is VerificationVerdict {
  return typeof value === 'string' && (VERIFICATION_VERDICTS as readonly string[]).includes(value);
}

function isKnownStatus(value: unknown): value is ClaimStatus {
  return typeof value === 'string' && value in CLAIM_TRANSITIONS;
}

// ═══════════════════════════════════════════════════════════════════════════
// REGISTRY
// ═══════════════════════════════════════════════════════════════════════════

export class ClaimRegistry {
  private readonly claims = new Map<string, Claim>();
  private readonly edges = new Map<string, ClaimEdge>();
  private readonly now: () => Timestamp;
  private readonly idFactory: (prefix: string) => string;

  constructor(options: ClaimRegistryOptions = {}) {
    this.now = options.now ?? (() => Date.now());
    this.idFactory = options.idFactory ?? ((prefix: string) => `${prefix}_${randomBytes(8).toString('hex')}`);
  }

  // ─── Claims ─────────────────────────────────────────────────────────────

  /** Register a new claim. */
  public submit(input: SubmitClaimInput): Claim {
    const timestamp = this.now();

    // Runtime validation: untyped callers may smuggle any string in. Only
    // 'draft' and 'submitted' are legal starting points — a claim can never
    // be BORN 'verified'.
    const status = input.status ?? 'submitted';
    if (status !== 'draft' && status !== 'submitted') {
      throw new CoherenceError(
        'CLAIM_INVALID',
        `invalid claim status at submit time: ${String(input.status)}; ` +
          `only 'draft' or 'submitted' may be provided`
      );
    }

    const claim: Claim = {
      id: this.idFactory('clm'),
      title: requireNonEmpty(input.title, 'title'),
      statement: requireNonEmpty(input.statement, 'statement'),
      authorId: requireNonEmpty(input.authorId, 'authorId'),
      status,
      confidence: clampUnit(input.confidence, 0),
      semanticHash: input.semanticHash,
      roomId: input.roomId,
      edges: emptyEdgeCounts(),
      verifications: [],
      // A caller-supplied `stake` never moved any funds, so it is NOT
      // recorded. Backing appears only through recordBacking(), fed by
      // VerificationMarket.backClaim()'s real escrow transfer.
      stake: ZERO,
      backings: [],
      createdAt: timestamp,
      updatedAt: timestamp
    };

    this.claims.set(claim.id, claim);
    return this.snapshot(claim);
  }

  /** Look up a claim, or undefined. */
  public get(claimId: string): Claim | undefined {
    const claim = this.claims.get(claimId);
    return claim ? this.snapshot(claim) : undefined;
  }

  /** Look up a claim, throwing when absent. */
  public require(claimId: string): Claim {
    const claim = this.claims.get(claimId);
    if (!claim) {
      throw new CoherenceError('CLAIM_NOT_FOUND', `claim ${claimId} not found`);
    }
    return this.snapshot(claim);
  }

  /** List claims, newest first. */
  public list(filter: ClaimFilter = {}): Claim[] {
    const statuses = filter.status === undefined
      ? undefined
      : Array.isArray(filter.status)
        ? filter.status
        : [filter.status as ClaimStatus];

    let results = [...this.claims.values()];
    if (statuses) results = results.filter(claim => statuses.includes(claim.status));
    if (filter.authorId) results = results.filter(claim => claim.authorId === filter.authorId);
    if (filter.roomId) results = results.filter(claim => claim.roomId === filter.roomId);

    results.sort((a, b) => b.createdAt - a.createdAt || a.id.localeCompare(b.id));
    if (filter.limit !== undefined && filter.limit >= 0) results = results.slice(0, filter.limit);

    return results.map(claim => this.snapshot(claim));
  }

  /**
   * True when the transition is legal.
   *
   * Unknown statuses throw a typed {@link CoherenceError} instead of a bare
   * TypeError from indexing the transition table.
   */
  public canTransition(from: ClaimStatus, to: ClaimStatus): boolean {
    if (!isKnownStatus(from)) {
      throw new CoherenceError(
        'INVALID_TRANSITION',
        `unknown claim status: ${String(from)}; known statuses: ${Object.keys(CLAIM_TRANSITIONS).join(', ')}`
      );
    }
    if (!isKnownStatus(to)) {
      throw new CoherenceError(
        'INVALID_TRANSITION',
        `unknown claim status: ${String(to)}; known statuses: ${Object.keys(CLAIM_TRANSITIONS).join(', ')}`
      );
    }
    return CLAIM_TRANSITIONS[from].includes(to);
  }

  /** Move a claim through its lifecycle, validating the transition. */
  public transition(claimId: string, next: ClaimStatus): Claim {
    const claim = this.mutable(claimId);
    if (claim.status === next) return this.snapshot(claim);

    if (!this.canTransition(claim.status, next)) {
      throw new CoherenceError(
        'INVALID_TRANSITION',
        `INVALID_TRANSITION: cannot move claim ${claimId} from ${claim.status} to ${next}; ` +
          `allowed: ${CLAIM_TRANSITIONS[claim.status].join(', ') || 'none'}`
      );
    }

    claim.status = next;
    claim.updatedAt = this.now();
    return this.snapshot(claim);
  }

  /** Update the aggregate confidence of a claim. */
  public updateConfidence(claimId: string, confidence: number): Claim {
    const claim = this.mutable(claimId);
    claim.confidence = clampUnit(confidence, claim.confidence);
    claim.updatedAt = this.now();
    return this.snapshot(claim);
  }

  /**
   * Attach a verification to a claim.
   *
   * A claim's author can never verify it — the legacy action happily let a
   * node rubber-stamp its own claim and collect the reward. Each verifier
   * holds at most ONE verification record: a repeat replaces the previous
   * record instead of piling up duplicate verdicts.
   */
  public recordVerification(claimId: string, input: RecordVerificationInput): Claim {
    const claim = this.mutable(claimId);
    const verifierId = requireNonEmpty(input.verifierId, 'verifierId');

    if (verifierId === claim.authorId) {
      throw new CoherenceError(
        'SELF_VERIFICATION',
        `SELF_VERIFICATION: author ${verifierId} may not verify their own claim ${claimId}`
      );
    }
    if (!isVerdict(input.verdict)) {
      throw new CoherenceError(
        'INVALID_VERDICT',
        `verdict must be one of ${VERIFICATION_VERDICTS.join(', ')}`
      );
    }

    const verification: ClaimVerification = {
      verifierId,
      verdict: input.verdict,
      confidence: clampUnit(input.confidence, 0),
      stake: assertNonNegative(input.stake ?? ZERO, 'verification stake'),
      timestamp: this.now()
    };
    if (input.correct !== undefined) verification.correct = input.correct;
    if (input.settledAt !== undefined) verification.settledAt = input.settledAt;

    // Dedupe per verifier: one verdict record per verifier, ever.
    const existing = claim.verifications.findIndex(candidate => candidate.verifierId === verifierId);
    if (existing >= 0) claim.verifications[existing] = verification;
    else claim.verifications.push(verification);

    claim.updatedAt = verification.timestamp;
    return this.snapshot(claim);
  }

  /**
   * Record a REAL escrowed backing against a claim.
   *
   * This is the ONLY path by which `claim.stake` grows: the caller (the
   * verification market) must have escrowed `amount` before recording it.
   * Caller-supplied `stake` at {@link submit} time is ignored precisely
   * because it never moved funds.
   */
  public recordBacking(claimId: string, stakerId: string, amount: TokenAmount): Claim {
    const claim = this.mutable(claimId);
    const value = assertPositive(amount, 'backing');
    const backing: ClaimBacking = {
      stakerId: requireNonEmpty(stakerId, 'stakerId'),
      amount: value,
      timestamp: this.now()
    };

    claim.stake = safeAdd(claim.stake, value, 'claim stake');
    claim.backings.push(backing);
    claim.updatedAt = backing.timestamp;
    return this.snapshot(claim);
  }

  // ─── Edges ──────────────────────────────────────────────────────────────

  /** Create a typed edge between two existing claims. */
  public addEdge(input: CreateEdgeInput): ClaimEdge {
    if (!EDGE_TYPES.includes(input.edgeType)) {
      throw new CoherenceError('EDGE_INVALID', `unknown edge type: ${String(input.edgeType)}`);
    }
    if (input.fromClaimId === input.toClaimId) {
      throw new CoherenceError('EDGE_INVALID', 'a claim cannot be linked to itself');
    }

    const from = this.mutable(input.fromClaimId);
    const to = this.mutable(input.toClaimId);

    const edge: ClaimEdge = {
      id: this.idFactory('edg'),
      fromClaimId: from.id,
      toClaimId: to.id,
      edgeType: input.edgeType,
      authorId: requireNonEmpty(input.authorId, 'authorId'),
      confidence: clampUnit(input.confidence, 0),
      semanticSimilarity: clampUnit(input.semanticSimilarity, 0),
      evidence: input.evidence,
      createdAt: this.now()
    };

    this.edges.set(edge.id, edge);
    to.edges[edge.edgeType] += 1;
    to.updatedAt = edge.createdAt;

    return { ...edge };
  }

  public getEdge(edgeId: string): ClaimEdge | undefined {
    const edge = this.edges.get(edgeId);
    return edge ? { ...edge } : undefined;
  }

  /** List edges, newest first. */
  public listEdges(filter: EdgeFilter = {}): ClaimEdge[] {
    let results = [...this.edges.values()];
    if (filter.fromClaimId) results = results.filter(edge => edge.fromClaimId === filter.fromClaimId);
    if (filter.toClaimId) results = results.filter(edge => edge.toClaimId === filter.toClaimId);
    if (filter.edgeType) results = results.filter(edge => edge.edgeType === filter.edgeType);
    if (filter.authorId) results = results.filter(edge => edge.authorId === filter.authorId);

    results.sort((a, b) => b.createdAt - a.createdAt || a.id.localeCompare(b.id));
    if (filter.limit !== undefined && filter.limit >= 0) results = results.slice(0, filter.limit);

    return results.map(edge => ({ ...edge }));
  }

  /** Every edge touching a claim, in either direction. */
  public edgesFor(claimId: string): ClaimEdge[] {
    return [...this.edges.values()]
      .filter(edge => edge.fromClaimId === claimId || edge.toClaimId === claimId)
      .map(edge => ({ ...edge }));
  }

  /** Inbound edge counts of a claim. */
  public edgeCounts(claimId: string): EdgeCounts {
    return { ...this.require(claimId).edges };
  }

  // ─── Stats ──────────────────────────────────────────────────────────────

  public stats(): RegistryStats {
    const byStatus = {
      draft: 0,
      submitted: 0,
      under_review: 0,
      verified: 0,
      disputed: 0,
      rejected: 0,
      archived: 0
    } as Record<ClaimStatus, number>;

    let totalStake = ZERO;
    for (const claim of this.claims.values()) {
      byStatus[claim.status] += 1;
      // claim.stake only ever holds REAL escrowed backing (recordBacking),
      // so this total is money that actually moved.
      totalStake += claim.stake;
    }

    return { claims: this.claims.size, edges: this.edges.size, byStatus, totalStake };
  }

  // ─── Internals ──────────────────────────────────────────────────────────

  /** Live record, for internal mutation. */
  private mutable(claimId: string): Claim {
    const claim = this.claims.get(claimId);
    if (!claim) {
      throw new CoherenceError('CLAIM_NOT_FOUND', `claim ${claimId} not found`);
    }
    return claim;
  }

  /** Defensive copy handed to callers. */
  private snapshot(claim: Claim): Claim {
    return {
      ...claim,
      edges: { ...claim.edges },
      verifications: claim.verifications.map(verification => ({ ...verification })),
      backings: claim.backings.map(backing => ({ ...backing }))
    };
  }
}
