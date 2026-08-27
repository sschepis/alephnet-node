import type {
  Capability,
  CapabilityCheckResult,
  CapabilityDecision,
  ITrustEvaluator,
  ITrustGate,
  SignedEnvelope,
  TrustAssessment,
  TrustLevel,
} from '../common/trust-types';

type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

/**
 * Hardened ITrustGate contract.
 *
 * `ITrustGate.checkAll(envelope, trust)` let the caller pass in a trust
 * assessment that was never bound to the envelope, which made capability
 * gating trivially bypassable. This variant drops that parameter: checkAll
 * derives the assessment from the envelope itself (hence async), so the only
 * way to influence the decision is to control the signed envelope.
 */
export interface ISecureTrustGate extends Omit<ITrustGate, 'checkAll'> {
  checkAll<T>(
    envelope: SignedEnvelope<T>,
    expectedAuthorFingerprint?: string
  ): Promise<Map<Capability, CapabilityCheckResult>>;
}

interface MatrixRule {
  decision: CapabilityDecision;
  risk?: RiskLevel;
}

const DEFAULT_RULES: Record<TrustLevel, MatrixRule> = {
  SELF: { decision: 'ALLOW' },
  VOUCHED: { decision: 'CONFIRM', risk: 'medium' },
  COMMUNITY: { decision: 'CONFIRM', risk: 'high' },
  UNKNOWN: { decision: 'DENY' },
  REVOKED: { decision: 'DENY' },
};

const CAPABILITY_MATRIX: Partial<Record<Capability, Partial<Record<TrustLevel, MatrixRule>>>> = {
  'ui:notification': {
    // SELF: ALLOW (default)
    // VOUCHED: ALLOW (override default confirm)
    VOUCHED: { decision: 'ALLOW' },
    // COMMUNITY: ALLOW (override default confirm)
    COMMUNITY: { decision: 'ALLOW' },
    UNKNOWN: { decision: 'CONFIRM', risk: 'low' },
    // REVOKED: DENY (default)
  },
  'ui:overlay': {
    VOUCHED: { decision: 'ALLOW' },
    COMMUNITY: { decision: 'ALLOW' },
    UNKNOWN: { decision: 'CONFIRM', risk: 'low' },
  },
  'network:http': {
    // SELF: ALLOW (default)
    VOUCHED: { decision: 'ALLOW' },
    COMMUNITY: { decision: 'CONFIRM', risk: 'medium' },
    UNKNOWN: { decision: 'CONFIRM', risk: 'high' },
  },
  'fs:read': {
    VOUCHED: { decision: 'ALLOW' },
    COMMUNITY: { decision: 'CONFIRM', risk: 'medium' },
    UNKNOWN: { decision: 'CONFIRM', risk: 'high' },
  },
  'fs:write': {
    // SELF: ALLOW (default)
    VOUCHED: { decision: 'CONFIRM', risk: 'medium' }, // Matches default
    COMMUNITY: { decision: 'CONFIRM', risk: 'high' }, // Matches default
    UNKNOWN: { decision: 'DENY' }, // Matches default
  },
  'dsn:register-tool': {
    VOUCHED: { decision: 'ALLOW' },
    COMMUNITY: { decision: 'CONFIRM', risk: 'medium' },
    UNKNOWN: { decision: 'DENY' },
  },
  'dsn:register-service': {
    VOUCHED: { decision: 'ALLOW' },
    COMMUNITY: { decision: 'CONFIRM', risk: 'medium' },
    UNKNOWN: { decision: 'DENY' },
  },
  'dsn:publish-observation': {
    VOUCHED: { decision: 'ALLOW' },
    COMMUNITY: { decision: 'CONFIRM', risk: 'medium' },
    UNKNOWN: { decision: 'DENY' },
  },
  'dsn:identity': {
    // SELF: ALLOW (default)
    VOUCHED: { decision: 'CONFIRM', risk: 'high' },
    COMMUNITY: { decision: 'DENY' },
    UNKNOWN: { decision: 'DENY' },
  },
  'dsn:gmf-write': {
    // SELF: ALLOW (default)
    VOUCHED: { decision: 'CONFIRM', risk: 'medium' },
    COMMUNITY: { decision: 'CONFIRM', risk: 'high' },
    UNKNOWN: { decision: 'DENY' },
  },
  'crypto:sign': {
    // SELF: ALLOW (default)
    VOUCHED: { decision: 'CONFIRM', risk: 'medium' },
    COMMUNITY: { decision: 'DENY' },
    UNKNOWN: { decision: 'DENY' },
  },
  'crypto:encrypt': {
    // SELF: ALLOW (default)
    VOUCHED: { decision: 'CONFIRM', risk: 'medium' },
    COMMUNITY: { decision: 'DENY' },
    UNKNOWN: { decision: 'DENY' },
  },
  'wallet:read': {
    VOUCHED: { decision: 'ALLOW' },
    COMMUNITY: { decision: 'CONFIRM', risk: 'medium' },
    UNKNOWN: { decision: 'DENY' },
  },
  'wallet:transfer': {
    SELF: { decision: 'CONFIRM', risk: 'high' },
    VOUCHED: { decision: 'CONFIRM', risk: 'critical' },
    COMMUNITY: { decision: 'DENY' },
    UNKNOWN: { decision: 'DENY' },
  },
  'system:shell': {
    SELF: { decision: 'CONFIRM', risk: 'medium' },
    VOUCHED: { decision: 'DENY' },
    COMMUNITY: { decision: 'DENY' },
    UNKNOWN: { decision: 'DENY' },
  },
};

export class TrustGate implements ISecureTrustGate {
  constructor(private readonly evaluator: ITrustEvaluator) {}

  /**
   * Evaluate the trust level of a signed envelope.
   * Delegates to the TrustEvaluator.
   */
  async evaluate<T>(envelope: SignedEnvelope<T>): Promise<TrustAssessment> {
    return this.evaluator.evaluate(envelope);
  }

  /**
   * Check if a requested capability is allowed for a given envelope.
   * Evaluates trust first, then checks the capability matrix.
   */
  async checkCapability<T>(
    envelope: SignedEnvelope<T>,
    capability: Capability
  ): Promise<CapabilityCheckResult> {
    const assessment = await this.evaluate(envelope);
    return this.check(capability, assessment);
  }

  /**
   * Check whether a capability is allowed for a given trust assessment.
   * Implements the Capability Matrix logic.
   *
   * This is the pure matrix lookup. Prefer checkCapability/checkAll, which
   * derive the assessment from the envelope themselves.
   */
  check(capability: Capability, trust: TrustAssessment): CapabilityCheckResult {
    if (trust.level === 'REVOKED') {
      return { decision: 'DENY', reason: 'Trust revoked' };
    }

    const levelRules = CAPABILITY_MATRIX[capability];
    const rule = levelRules?.[trust.level] ?? DEFAULT_RULES[trust.level];

    return {
      decision: rule.decision,
      reason: rule.risk ? `${rule.risk} risk capability` : undefined,
    };
  }

  /**
   * Check all requested capabilities for an envelope.
   *
   * The assessment is always computed here from the envelope via the
   * TrustEvaluator — it is never supplied by the caller, so a caller cannot
   * hand in a hand-written "SELF/1.0" assessment that is unrelated to (and
   * unbound from) the envelope being gated.
   *
   * @param envelope The envelope whose requestedCapabilities are gated.
   * @param expectedAuthorFingerprint Optional binding: when provided, the
   *   envelope must actually be authored by that fingerprint, otherwise every
   *   capability is denied.
   */
  async checkAll<T>(
    envelope: SignedEnvelope<T>,
    expectedAuthorFingerprint?: string
  ): Promise<Map<Capability, CapabilityCheckResult>> {
    const results = new Map<Capability, CapabilityCheckResult>();
    const capabilities = envelope?.requestedCapabilities ?? [];

    if (
      expectedAuthorFingerprint &&
      expectedAuthorFingerprint !== envelope?.author?.fingerprint
    ) {
      for (const cap of capabilities) {
        results.set(cap, {
          decision: 'DENY',
          reason: 'Envelope author does not match the expected author fingerprint',
        });
      }
      return results;
    }

    const trust = await this.evaluate(envelope);
    for (const cap of capabilities) {
      results.set(cap, this.check(cap, trust));
    }
    return results;
  }
}
