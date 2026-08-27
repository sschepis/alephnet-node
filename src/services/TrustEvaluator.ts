// ═══════════════════════════════════════════════════════════════════════════
// TrustEvaluator — Evaluates trust levels of signed envelopes
// See design/23-provenance-trust.md §4 (Phase 1)
// ═══════════════════════════════════════════════════════════════════════════

import type { StakingTier } from '../common/types';
import type {
  Endorsement,
  ITrustEvaluator,
  SignedEnvelope,
  TrustAssessment,
  TrustFactors,
  TrustLevel,
  TrustOverride,
  AuthorIdentity
} from '../common/trust-types';
import {
  TRUST_WEIGHTS,
  SOCIAL_DISTANCE_SCORES,
  STAKING_TIER_SCORES,
  TRUST_THRESHOLDS,
  TRUST_CACHE_TTL,
} from '../common/trust-types';
import {
  base64ToBuffer,
  reconstructKeyTriplet,
  verifyFromBase64,
} from '../common/crypto';
import type { SignedEnvelopeService } from './SignedEnvelopeService';

// ─── Provider Interfaces ─────────────────────────────────────────────────

/**
 * Provides social graph data for computing trust distance.
 */
export interface ISocialGraphProvider {
  getFriends(): Promise<Array<{ id: string; publicKey: string }>>;
  getFriendsOfFriend(friendPub: string): Promise<Array<{ id: string; publicKey: string }>>;
}

/**
 * Provides reputation, staking, and coherence data for trust scoring.
 */
export interface IReputationProvider {
  getReputation(publicKey: string): Promise<number>;
  getStakingTier(publicKey: string): Promise<StakingTier>;
  getCoherenceScore(contentHash: string): Promise<number>;
}

/**
 * Interface for DomainManager to decouple dependency.
 */
export interface IDomainManager {
    getCommonDomains(userId: string): Promise<string[]>;
}

// ─── Internal Cache Entry ────────────────────────────────────────────────

interface CacheEntry {
  assessment: TrustAssessment;
  expiresAt: number;
}

/**
 * Per-verified-endorsement contribution multiplier for the square-root
 * dampening in `computeEndorsementScore`.
 */
const ENDORSEMENT_SQRT_FACTOR = 0.3;

/** Hard cap on the endorsement-quality contribution (0.0–1.0). */
const ENDORSEMENT_MAX = 1.0;

// ═══════════════════════════════════════════════════════════════════════════
// TrustEvaluator
// ═══════════════════════════════════════════════════════════════════════════

export class TrustEvaluator implements ITrustEvaluator {
  private cache = new Map<string, CacheEntry>();
  private overrideMap = new Map<string, TrustOverride>();

  constructor(
    private readonly envelopeService: SignedEnvelopeService,
    private readonly ownIdentity: AuthorIdentity | null,
    private readonly socialGraph: ISocialGraphProvider,
    private readonly reputationProvider: IReputationProvider,
    private readonly domainManager: IDomainManager
  ) {}

  // ─── ITrustEvaluator ──────────────────────────────────────────────────

  /**
   * Evaluate the trust level of a signed envelope.
   *
   * Algorithm (design/23-provenance-trust.md §4.2):
   *   1. Signature gate — reject invalid signatures immediately
   *   2. Identity binding — author.fingerprint must derive from author.pub
   *   3. Cache lookup — keyed by VERIFIED author fingerprint + contentHash
   *   4. Self check — own artifacts get SELF/1.0
   *   5. Override check — user-defined trust/block overrides
   *   6. Weighted scoring — social distance, reputation, endorsements, staking, coherence
   *   7. Level mapping — score → TrustLevel via TRUST_THRESHOLDS
   *
   * SECURITY: the signature gate runs BEFORE any cache lookup, and the cache
   * key is scoped to the cryptographically verified author. A forged envelope
   * that merely copies a trusted contentHash therefore cannot inherit a cached
   * assessment, and no signer can reuse another author's assessment.
   */
  async evaluate<T>(envelope: SignedEnvelope<T>): Promise<TrustAssessment> {
    // ── Step 1: Signature Gate (BEFORE the cache) ────────────────────
    const verification = await this.envelopeService.verify(envelope);
    if (!verification.valid) {
      // Never cached: the identity of an unverifiable envelope is unknown, so
      // there is no key it could safely be stored under.
      return this.buildAssessment('REVOKED', -1, this.zeroFactors(false));
    }

    // ── Step 2: Identity Binding ─────────────────────────────────────
    // Only author.pub is covered by the signature. The fingerprint is a
    // derived value, so it must be recomputed from the verified key: a
    // mismatch means the envelope claims an identity it cannot prove and
    // would otherwise steal that identity's overrides, domains and cache.
    const authorFingerprint = this.deriveFingerprint(envelope.author.pub);
    if (!authorFingerprint || authorFingerprint !== envelope.author.fingerprint) {
      return this.buildAssessment('REVOKED', -1, this.zeroFactors(false));
    }

    const cacheKey = this.cacheKey(authorFingerprint, envelope.contentHash);

    // ── Step 3: Cache Check ──────────────────────────────────────────
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.assessment;
    }

    // ── Step 4: Self Check ───────────────────────────────────────────
    if (this.ownIdentity && envelope.author.pub === this.ownIdentity.pub) {
      return this.finalize(cacheKey, 'SELF', 1.0, {
        signatureValid: true,
        socialDistance: 1.0,
        authorReputation: 1.0,
        stakingTier: 1.0,
        endorsementQuality: 1.0,
        coherenceScore: 1.0,
      });
    }

    // ── Step 5: Override Check ───────────────────────────────────────
    const override =
      this.findOverrideForArtifact(envelope.contentHash) ??
      this.findOverrideForAuthor(authorFingerprint);

    if (override && override.trustLevel !== undefined) {
      if (override.trustLevel === 'REVOKED') {
        return this.finalize(cacheKey, 'REVOKED', -1.0, {
          signatureValid: true,
          socialDistance: 0,
          authorReputation: 0,
          stakingTier: 0,
          endorsementQuality: 0,
          coherenceScore: 0,
        });
      }
      // Any non-REVOKED trustLevel override → VOUCHED / 0.9
      return this.finalize(cacheKey, 'VOUCHED', 0.9, {
        signatureValid: true,
        socialDistance: 0.9,
        authorReputation: 0.9,
        stakingTier: 0.9,
        endorsementQuality: 0.9,
        coherenceScore: 0.9,
      });
    }

    // ── Step 6: Weighted Score Computation ───────────────────────────
    const friends = await this.socialGraph.getFriends();

    // 6a: Social Distance (weight 0.30)
    const socialDistanceScore = await this.computeSocialDistance(
      { pub: envelope.author.pub, fingerprint: authorFingerprint },
      friends
    );

    // 6b: Author Reputation (weight 0.20)
    const authorReputation = await this.reputationProvider.getReputation(
      envelope.author.pub
    );

    // 6c: Endorsements (weight 0.20) — only cryptographically verified ones
    const endorsementScore = this.computeEndorsementScore(
      this.verifiedEndorsements(envelope),
      friends
    );

    // 6d: Staking Tier (weight 0.15)
    const tier: StakingTier = await this.reputationProvider.getStakingTier(
      envelope.author.pub
    );
    const stakingScore = STAKING_TIER_SCORES[tier] ?? 0;

    // 6e: Coherence Score (weight 0.15)
    const coherenceScore = await this.reputationProvider.getCoherenceScore(
      envelope.contentHash
    );

    // ── Step 7: Final Score ──────────────────────────────────────────
    const finalScore =
      socialDistanceScore * TRUST_WEIGHTS.socialDistance +
      authorReputation * TRUST_WEIGHTS.authorReputation +
      endorsementScore * TRUST_WEIGHTS.endorsementQuality +
      stakingScore * TRUST_WEIGHTS.stakingTier +
      coherenceScore * TRUST_WEIGHTS.coherenceScore;

    // ── Step 8: Level Determination ──────────────────────────────────
    const level = this.scoreToLevel(finalScore);

    const factors: TrustFactors = {
      signatureValid: true,
      socialDistance: socialDistanceScore,
      authorReputation,
      stakingTier: stakingScore,
      endorsementQuality: endorsementScore,
      coherenceScore,
    };

    return this.finalize(cacheKey, level, finalScore, factors);
  }

  // ─── Override Management ──────────────────────────────────────────────

  async setOverride(override: TrustOverride): Promise<void> {
    const key = this.overrideKey(override);
    this.overrideMap.set(key, override);
  }

  async removeOverride(contentHash: string): Promise<void> {
    this.overrideMap.delete(contentHash);
  }

  async getOverrides(): Promise<TrustOverride[]> {
    return Array.from(this.overrideMap.values());
  }

  // ─── Cache Management ─────────────────────────────────────────────────

  clearCache(): void {
    this.cache.clear();
  }

  // ─── Private Helpers ──────────────────────────────────────────────────

  /**
   * Compute social distance score for an author.
   * Distance 1 (friend) → 0.8, distance 2 (FoF) → 0.5, else 0.0.
   */
  private async computeSocialDistance(
    author: { pub: string; fingerprint: string },
    friends: Array<{ id: string; publicKey: string }>
  ): Promise<number> {
    // Distance 1: direct friend
    const isFriend = friends.some(f => f.publicKey === author.pub);
    if (isFriend) {
      return SOCIAL_DISTANCE_SCORES[1] ?? 0;
    }

    // Check shared domains
    const commonDomains = await this.domainManager.getCommonDomains(author.fingerprint);
    if (commonDomains.length > 0) {
        return 0.6;
    }

    // Distance 2: friend-of-friend
    for (const friend of friends) {
      const fofs = await this.socialGraph.getFriendsOfFriend(friend.publicKey);
      if (fofs.some(fof => fof.publicKey === author.pub)) {
        return SOCIAL_DISTANCE_SCORES[2] ?? 0;
      }
    }

    // Unknown
    return 0;
  }

  /**
   * Return only the endorsements whose Ed25519 signature over the envelope's
   * contentHash verifies against the endorser's claimed public key.
   *
   * Endorsements are appendable by anyone, so an unverified endorsement is
   * just an unsigned claim: it is dropped rather than counted. Duplicate
   * endorsers and the author's own endorsement are also dropped so trust
   * cannot be inflated by replaying or self-vouching.
   */
  private verifiedEndorsements<T>(envelope: SignedEnvelope<T>): Endorsement[] {
    const endorsements = envelope.endorsements ?? [];
    const seen = new Set<string>();
    const verified: Endorsement[] = [];

    for (const endorsement of endorsements) {
      const pub = endorsement?.endorser?.pub;
      if (!pub || !endorsement.signature) continue;
      if (pub === envelope.author.pub) continue; // self-endorsement is not independent evidence
      if (seen.has(pub)) continue;               // one endorser counts once

      let signatureValid = false;
      try {
        signatureValid = verifyFromBase64(
          envelope.contentHash,
          endorsement.signature,
          base64ToBuffer(pub)
        );
      } catch {
        signatureValid = false;
      }
      if (!signatureValid) continue;

      seen.add(pub);
      verified.push(endorsement);
    }

    return verified;
  }

  /**
   * Compute endorsement quality score from already-verified endorsements.
   *
   * Anti-sybil design: every verified endorsement contributes, but with
   * square-root dampening — the contribution scales with sqrt(verifiedCount)
   * instead of linearly — and a hard cap bounds the total. A batch of N
   * freshly minted identities therefore cannot farm maximum endorsement
   * quality the way a linear `count / 5` formula allowed.
   *
   * Endorsements require at least one verified endorsement for any positive
   * contribution (zero endorsements => zero endorsement quality).
   *
   * Friend endorsers still carry a small bonus (+0.1 each, capped) because
   * they are anchored in the caller's social graph. Anchoring endorsement
   * weight to the ENDORSER'S own reputation is out of scope here: a
   * verified endorsement currently counts regardless of the endorser's
   * reputation, which is exactly why sqrt dampening and the cap exist.
   */
  private computeEndorsementScore(
    endorsements: Endorsement[],
    friends: Array<{ id: string; publicKey: string }>
  ): number {
    const count = endorsements.length;
    if (count < 1) return 0;

    // Square-root dampening: contribution ∝ sqrt(verifiedCount), so each
    // extra endorsement adds diminishing influence.
    let score = Math.sqrt(count) * ENDORSEMENT_SQRT_FACTOR;

    // Bonus for friend endorsers
    const friendPubs = new Set(friends.map(f => f.publicKey));
    const friendEndorsers = endorsements.filter(e =>
      friendPubs.has(e.endorser.pub)
    );
    score += friendEndorsers.length * 0.1;

    return Math.min(ENDORSEMENT_MAX, score);
  }

  /**
   * Map a numeric score to a TrustLevel using TRUST_THRESHOLDS.
   */
  private scoreToLevel(score: number): TrustLevel {
    if (score >= TRUST_THRESHOLDS.SELF) return 'SELF';
    if (score >= TRUST_THRESHOLDS.VOUCHED) return 'VOUCHED';
    if (score >= TRUST_THRESHOLDS.COMMUNITY) return 'COMMUNITY';
    if (score >= TRUST_THRESHOLDS.UNKNOWN) return 'UNKNOWN';
    return 'REVOKED';
  }

  /**
   * Build a TrustAssessment, cache it under the verified-author cache key,
   * and return it.
   */
  private finalize(
    cacheKey: string,
    level: TrustLevel,
    score: number,
    factors: TrustFactors
  ): TrustAssessment {
    const assessment = this.buildAssessment(level, score, factors);

    this.cache.set(cacheKey, {
      assessment,
      expiresAt:
        assessment.evaluatedAt +
        (assessment.ttlMs === Infinity ? Number.MAX_SAFE_INTEGER : assessment.ttlMs),
    });

    return assessment;
  }

  /**
   * Build a TrustAssessment without caching it.
   */
  private buildAssessment(
    level: TrustLevel,
    score: number,
    factors: TrustFactors
  ): TrustAssessment {
    return {
      score,
      level,
      factors,
      evaluatedAt: Date.now(),
      ttlMs: TRUST_CACHE_TTL[level],
    };
  }

  /**
   * Cache key: verified author fingerprint + contentHash.
   *
   * Including the verified author is what stops one signer from picking up an
   * assessment computed for a different signer's identical content.
   */
  private cacheKey(authorFingerprint: string, contentHash: string): string {
    return `${authorFingerprint}:${contentHash}`;
  }

  /**
   * Recompute an author's fingerprint from their Ed25519 public key.
   * Returns null when the key is unusable.
   */
  private deriveFingerprint(pub: string): string | null {
    if (!pub) return null;
    try {
      return reconstructKeyTriplet(pub).fingerprint;
    } catch {
      return null;
    }
  }

  /**
   * Factor breakdown for a rejected envelope.
   */
  private zeroFactors(signatureValid: boolean): TrustFactors {
    return {
      signatureValid,
      socialDistance: 0,
      authorReputation: 0,
      stakingTier: 0,
      endorsementQuality: 0,
      coherenceScore: 0,
    };
  }

  /**
   * Find an override targeting a specific artifact contentHash.
   */
  private findOverrideForArtifact(contentHash: string): TrustOverride | undefined {
    for (const override of this.overrideMap.values()) {
      if (override.target.type === 'artifact' && override.target.contentHash === contentHash) {
        return override;
      }
    }
    return undefined;
  }

  /**
   * Find an override targeting a specific author fingerprint.
   */
  private findOverrideForAuthor(fingerprint: string): TrustOverride | undefined {
    for (const override of this.overrideMap.values()) {
      if (override.target.type === 'author' && override.target.fingerprint === fingerprint) {
        return override;
      }
    }
    return undefined;
  }

  /**
   * Derive a stable map key from a TrustOverride's target.
   */
  private overrideKey(override: TrustOverride): string {
    if (override.target.type === 'artifact') {
      return override.target.contentHash;
    }
    return `author:${override.target.fingerprint}`;
  }
}
