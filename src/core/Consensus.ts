import {
  DSNNodeConfig,
  GMFObject,
  SMFVector,
  SemanticDomain
} from '../core/types';
import { determineDomain, cosineSimilarity, clamp } from '../common/math';
import { smfHash } from '../common/hash';
import { CONSENSUS, NETWORK } from '../common/constants';

// Interface for a Proposal being voted on
export interface ConsensusProposal {
  id: string;
  targetObject: GMFObject; // The object being proposed
  proposerId: string;
  tickProof: {
    tickNumber: number;
    coherence: number; // 0.0 to 1.0
    valid: boolean;
  };
  smfHash: string;
  primeDomain?: number[]; // Optional prime factors if available
}

/**
 * A single ballot.
 *
 * NOTE: A vote deliberately carries NO weight field. Weight is a *derived*
 * property of the voter's published identity (staking tier, semantic domain,
 * prime domain, expertise axes) combined with their historical accuracy.
 * Accepting a caller supplied weight would let any peer mint unlimited
 * influence, so weight is always recomputed locally by `calculateVoteWeight`.
 */
export interface Vote {
  voterId: string;
  vote: 'SUPPORT' | 'CONTEST';
  /**
   * Stake locked behind this vote. Optional because not every transport
   * carries stake information; when present it must satisfy MIN_VOTE_STAKE.
   */
  stakeAmount?: number;
  timestamp: number;
  /**
   * The voter's published node config. This is the only trusted source of
   * tier / domain data used to derive the vote weight. Its `nodeId` must
   * match `voterId` or the ballot is discarded as spoofed.
   */
  voterConfig?: DSNNodeConfig;
  /** Historical accuracy multiplier in [0,1]. Defaults to 1.0 when unknown. */
  reputation?: number;
}

export interface ConsensusResult {
  accepted: boolean;
  totalSupport: number;
  totalContest: number;
  weightedRedundancy: number;
  /** Number of distinct voters that produced a counted ballot. */
  distinctVoters: number;
  /** Ballots discarded (duplicates, spoofed configs, under-staked, malformed). */
  rejectedVotes: number;
  reason: string;
}

/**
 * Coherent-Commit Protocol
 *
 * Implements the logic for semantic consensus in AlephNet.
 * Calculates vote weights based on domain expertise and historical accuracy.
 * Validates proposals against coherence proofs.
 *
 * Safety properties enforced here:
 *   1. Proposals are gated on their tick proof BEFORE any vote is counted.
 *   2. One counted ballot per voter (highest recomputed weight wins). Voter
 *      ids are normalized (trim + lowercase) so case/whitespace variants of
 *      the same id collapse into a single voter.
 *   3. Weights are never taken from the wire, always recomputed locally.
 *   4. A ballot with no resolvable identity carries ZERO weight and never
 *      counts toward the distinct-voter quorum.
 *   5. Acceptance requires an exact 2/3 weighted supermajority AND a minimum
 *      quorum of distinct voters.
 */
export class ConsensusProtocol {

  // Configuration (single source of truth: common/constants)
  private readonly MIN_COHERENCE_THRESHOLD = CONSENSUS.MIN_COHERENCE_THRESHOLD;
  private readonly CONSENSUS_THRESHOLD = CONSENSUS.CONSENSUS_THRESHOLD; // exact 2/3
  private readonly MIN_VOTE_STAKE = CONSENSUS.MIN_VOTE_STAKE;
  private readonly MIN_QUORUM_VOTERS = NETWORK.MIN_PEERS_QUORUM; // 3 distinct voters

  constructor(
    private localNodeId: string
    // In a real system, we'd inject a ReputationManager or HistoryService here
  ) {}

  /**
   * Create a new proposal for an object.
   */
  public createProposal(
    object: GMFObject,
    proposerId: string,
    currentTick: number,
    coherenceScore: number
  ): ConsensusProposal {
    // In reality, proof generation involves cryptographic signing
    return {
      id: `prop-${object.id}-${Date.now()}`,
      targetObject: object,
      proposerId,
      tickProof: {
        tickNumber: currentTick,
        coherence: coherenceScore,
        valid: coherenceScore >= this.MIN_COHERENCE_THRESHOLD
      },
      smfHash: this.computeSmfHash(object.smf)
    };
  }

  /**
   * Build a ballot for a voter.
   *
   * Provided so callers never have to construct (and therefore never get the
   * chance to fabricate) a weight: the protocol derives it at tally time.
   */
  public castVote(
    voter: DSNNodeConfig,
    choice: 'SUPPORT' | 'CONTEST',
    stakeAmount: number = this.MIN_VOTE_STAKE,
    reputation?: number
  ): Vote {
    return {
      voterId: voter.nodeId,
      vote: choice,
      stakeAmount,
      timestamp: Date.now(),
      voterConfig: voter,
      reputation
    };
  }

  /**
   * Calculate the semantic weight of a vote from a specific node.
   * Weight = (DomainOverlap * PrimeOverlap * AxisBonus * Tier) * Reputation
   *
   * @param reputation Historical accuracy in [0,1]. Defaults to 1.0 (neutral)
   *                   when no reputation record is available.
   */
  public calculateVoteWeight(
    voter: DSNNodeConfig,
    proposal: ConsensusProposal,
    reputation: number = 1.0
  ): number {
    // 1. Semantic Domain Alignment
    // Does the voter specialize in the proposal's domain?
    const proposalDomain: SemanticDomain = determineDomain(proposal.targetObject.smf as SMFVector);
    const domainMatch = voter.semanticDomain === proposalDomain ? 1.5 : 0.5;

    // 2. Prime Domain Overlap
    // Intersection of voter's known primes vs proposal's primes (if available)
    let primeOverlap = 1.0;
    if (proposal.primeDomain && voter.primeDomain) {
      const intersection = voter.primeDomain.filter(p => proposal.primeDomain!.includes(p));
      const union = new Set([...voter.primeDomain, ...proposal.primeDomain!]);
      const jaccard = union.size === 0 ? 0 : intersection.length / union.size;
      primeOverlap = 1.0 + jaccard; // 1.0 to 2.0 multiplier
    }

    // 3. SMF Alignment (Expertise Check)
    // If voter exposes their SMF expertise vector (e.g. in smfAxes which might be a vector or just indices)
    // Assuming smfAxes are indices of dimensions they are strong in.
    let axisBonus = 0;
    if (voter.smfAxes && voter.smfAxes.length > 0) {
        // Calculate average magnitude of proposal in voter's axes
        const propSmf = proposal.targetObject.smf;
        let axisMag = 0;
        voter.smfAxes.forEach(idx => {
            if (idx >= 0 && idx < 16) axisMag += Math.abs(propSmf[idx]);
        });
        axisBonus = axisMag / voter.smfAxes.length; // 0 to 1 approx
    }

    // 4. Staking Tier Multiplier
    const tierMultipliers = {
        'Neophyte': 1,
        'Adept': 2,
        'Magus': 5,
        'Archon': 10
    };
    const tierMult = tierMultipliers[voter.stakingTier] || 1;

    // 5. Historical accuracy. Unknown reputation is neutral (no penalty),
    //    a proven-bad voter collapses toward zero influence.
    const reputationFactor = Number.isFinite(reputation) ? clamp(reputation, 0, 1) : 1.0;

    // Final Calculation
    // Base weight 1.0
    const rawWeight = 1.0 * domainMatch * primeOverlap * (1 + axisBonus) * tierMult * reputationFactor;

    return parseFloat(rawWeight.toFixed(4));
  }

  /**
   * Evaluate a proposal given a set of votes.
   *
   * @param voterRegistry Optional authoritative directory of node configs.
   *                      Entries here take precedence over `vote.voterConfig`.
   */
  public evaluateProposal(
    proposal: ConsensusProposal,
    votes: Vote[],
    voterRegistry?: ReadonlyMap<string, DSNNodeConfig>
  ): ConsensusResult {
    // 1. Validate Pre-conditions.
    //    The tick proof gates the tally: an incoherent proposal is never
    //    eligible, no matter how much weight backs it.
    if (proposal.tickProof.valid !== true) {
      return this.reject('Invalid tick proof (low coherence)');
    }

    const coherence = proposal.tickProof.coherence;
    if (!Number.isFinite(coherence) || coherence < this.MIN_COHERENCE_THRESHOLD) {
      return this.reject(
        `Coherence below threshold (${coherence} < ${this.MIN_COHERENCE_THRESHOLD})`
      );
    }

    // 2. Deduplicate ballots by normalized voter id and recompute every
    //    weight locally. Normalizing keys means `v1`, `V1` and ` v1 ` are one
    //    voter, and a registry supplied by the caller is normalized too so
    //    registry lookups cannot be evaded by case/whitespace tricks.
    const registry = voterRegistry
      ? new Map(
          Array.from(voterRegistry, ([id, config]) => [this.normalizeVoterId(id), config])
        )
      : undefined;

    const tally = new Map<string, { vote: Vote; weight: number }>();
    let rejectedVotes = 0;

    for (const ballot of votes) {
      if (!this.isWellFormedVote(ballot)) {
        rejectedVotes++;
        continue;
      }

      // Stake floor is only enforceable when the ballot actually carries stake.
      // A non-finite stake (NaN / Infinity) is malformed and can never satisfy
      // the floor, so it is rejected outright.
      if (
        typeof ballot.stakeAmount === 'number' &&
        (!Number.isFinite(ballot.stakeAmount) || ballot.stakeAmount < this.MIN_VOTE_STAKE)
      ) {
        rejectedVotes++;
        continue;
      }

      const weight = this.resolveVoteWeight(ballot, proposal, registry);
      if (!(weight > 0)) {
        // Unresolvable identity (anonymous ballot, spoofed config, or an id
        // the registry does not list): zero influence, and it never counts
        // toward the distinct-voter quorum.
        rejectedVotes++;
        continue;
      }

      const voterKey = this.normalizeVoterId(ballot.voterId);
      const existing = tally.get(voterKey);
      if (existing) {
        // One voter, one counted ballot. Later duplicates are rejected; the
        // highest-weight ballot from that voter is the one that survives.
        rejectedVotes++;
        if (weight > existing.weight) {
          tally.set(voterKey, { vote: ballot, weight });
        }
        continue;
      }

      tally.set(voterKey, { vote: ballot, weight });
    }

    if (tally.size === 0) {
      return { ...this.reject('No votes'), rejectedVotes };
    }

    // 3. Quorum: a supermajority of two peers is not a network decision.
    if (tally.size < this.MIN_QUORUM_VOTERS) {
      return {
        ...this.reject(
          `Quorum not met (${tally.size}/${this.MIN_QUORUM_VOTERS} distinct voters)`
        ),
        distinctVoters: tally.size,
        rejectedVotes
      };
    }

    // 4. Tally recomputed weights.
    let supportWeight = 0;
    let contestWeight = 0;
    for (const { vote, weight } of tally.values()) {
      if (vote.vote === 'SUPPORT') supportWeight += weight;
      else contestWeight += weight;
    }

    const totalWeight = supportWeight + contestWeight;
    const supportRatio = supportWeight / totalWeight;

    // 5. Exact 2/3 supermajority. `2/3` is used verbatim so a ratio that is
    //    exactly two thirds (e.g. 3.0 / 4.5) passes, and anything below fails.
    const accepted = supportRatio >= this.CONSENSUS_THRESHOLD;

    return {
      accepted,
      totalSupport: supportWeight,
      totalContest: contestWeight,
      weightedRedundancy: supportRatio,
      distinctVoters: tally.size,
      rejectedVotes,
      reason: accepted
        ? 'Consensus achieved'
        : `Insufficient support (${(supportRatio * 100).toFixed(1)}%)`
    };
  }

  /**
   * Verify if a proposal is coherent with local state.
   * (Used by a voter to decide how to vote)
   */
  public verifyCoherence(
    proposal: ConsensusProposal,
    localSmfContext: SMFVector
  ): boolean {
    // Check semantic distance between proposal and local context
    // If too far, might be hallucination or irrelevant
    const similarity = cosineSimilarity(
        proposal.targetObject.smf as SMFVector,
        localSmfContext
    );

    // Threshold depends on domain strictness, here hardcoded for simplicity
    return similarity > 0.4;
  }

  // --- Internal Helpers ---

  /**
   * Resolve the weight of a ballot from trusted identity data only.
   * Returns 0 when the ballot's identity cannot be established.
   *
   * When `voterRegistry` is provided it is authoritative: only ids it lists
   * can contribute weight or quorum. Without a registry, every ballot must
   * carry a `voterConfig` whose `nodeId` matches the ballot's voter id
   * (compared normalized, so case/whitespace variants are one identity).
   */
  private resolveVoteWeight(
    ballot: Vote,
    proposal: ConsensusProposal,
    voterRegistry?: ReadonlyMap<string, DSNNodeConfig>
  ): number {
    const normalizedId = this.normalizeVoterId(ballot.voterId);

    if (voterRegistry) {
      // Registry-listed identities only. An unlisted id is an anonymous
      // ballot: weight zero, no quorum contribution.
      const registered = voterRegistry.get(normalizedId);
      if (!registered) return 0;
      if (this.normalizeVoterId(registered.nodeId) !== normalizedId) return 0;
      return this.calculateVoteWeight(registered, proposal, ballot.reputation);
    }

    // No registry: the ballot must prove its own identity with a
    // self-consistent voterConfig. Config-less ballots get zero weight.
    const config = ballot.voterConfig;
    if (!config) return 0;
    if (this.normalizeVoterId(config.nodeId) !== normalizedId) return 0;

    return this.calculateVoteWeight(config, proposal, ballot.reputation);
  }

  /**
   * Canonical voter id: trimmed and lowercased, so `v1`, `V1` and ` v1 `
   * are one voter.
   */
  private normalizeVoterId(voterId: string): string {
    return voterId.trim().toLowerCase();
  }

  private isWellFormedVote(ballot: Vote | undefined | null): ballot is Vote {
    if (!ballot || typeof ballot !== 'object') return false;
    if (
      typeof ballot.voterId !== 'string' ||
      ballot.voterId.trim().length === 0
    ) return false;
    if (ballot.vote !== 'SUPPORT' && ballot.vote !== 'CONTEST') return false;
    return true;
  }

  private reject(reason: string): ConsensusResult {
    return {
      accepted: false,
      totalSupport: 0,
      totalContest: 0,
      weightedRedundancy: 0,
      distinctVoters: 0,
      rejectedVotes: 0,
      reason
    };
  }

  /**
   * Content hash of an SMF vector (SHA-256 over fixed-precision components).
   */
  private computeSmfHash(smf: number[]): string {
    return smfHash(smf);
  }
}
