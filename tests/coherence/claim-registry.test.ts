/**
 * ClaimRegistry tests: submit/get/list, typed edges, enforced lifecycle,
 * escrowed backing.
 */

import { beforeEach, describe, expect, it } from '@jest/globals';
import { ClaimRegistry } from '../../src/coherence/ClaimRegistry';
import { CoherenceError, EdgeType } from '../../src/coherence/types';
import { TokenAmount, wholeTokens } from '../../src/economy/units';

describe('ClaimRegistry', () => {
  let registry: ClaimRegistry;

  beforeEach(() => {
    registry = new ClaimRegistry();
  });

  const submit = (overrides: Partial<Parameters<ClaimRegistry['submit']>[0]> = {}) =>
    registry.submit({
      title: 'Semantic grounding is real',
      statement: 'A model grounded in an external observation channel produces more coherent claims.',
      authorId: 'author-1',
      confidence: 0.8,
      ...overrides
    });

  it('submits, retrieves and lists claims', () => {
    const first = submit();
    const second = submit({ authorId: 'author-2', status: 'draft' });

    expect(registry.get(first.id)?.id).toBe(first.id);
    expect(registry.require(first.id).statement).toContain('coherent claims');
    expect(registry.list()).toHaveLength(2);
    expect(registry.list({ authorId: 'author-1' })).toHaveLength(1);
    expect(registry.list({ status: 'submitted' })).toHaveLength(1);
    expect(registry.list({ status: 'draft' })).toHaveLength(1);

    expect(() => registry.require('missing')).toThrow(CoherenceError);
    expect(registry.get('missing')).toBeUndefined();
  });

  it('validates status at runtime: untyped callers may only pass draft/submitted', () => {
    expect(submit({ status: 'draft' }).status).toBe('draft');
    expect(submit().status).toBe('submitted');

    // @ts-expect-error an untyped caller may smuggle any string in
    expect(() => submit({ status: 'verified' })).toThrow(CoherenceError);
    // @ts-expect-error nonsense is rejected too
    expect(() => submit({ status: 'nonsense' })).toThrow(/only 'draft' or 'submitted'/);
  });

  it('ignores caller-supplied stake: backing comes only from recordBacking', () => {
    const claim = submit({ stake: wholeTokens(10) });
    expect(claim.stake).toBe(0n);
    expect(registry.stats().totalStake).toBe(0n);

    registry.recordBacking(claim.id, 'staker-1', wholeTokens(7));
    expect(registry.require(claim.id).stake).toBe(wholeTokens(7));
    expect(registry.require(claim.id).backings).toHaveLength(1);
    expect(registry.stats().totalStake).toBe(wholeTokens(7));

    registry.recordBacking(claim.id, 'staker-2', wholeTokens(3));
    expect(registry.require(claim.id).stake).toBe(wholeTokens(10));
    expect(registry.stats().totalStake).toBe(wholeTokens(10));
  });

  it('rejects non-positive or non-bigint backing', () => {
    const claim = submit();
    expect(() => registry.recordBacking(claim.id, 'staker', 0n)).toThrow();
    expect(() => registry.recordBacking(claim.id, 'staker', wholeTokens(10))).not.toThrow();
    // @ts-expect-error floats are not money
    expect(() => registry.recordBacking(claim.id, 'staker', 1.5)).toThrow();
  });

  it('enforces the claim lifecycle with validated transitions', () => {
    const claim = submit(); // 'submitted'

    // Legal: submitted -> under_review
    expect(registry.transition(claim.id, 'under_review').status).toBe('under_review');

    // Illegal: under_review may not jump straight to archived
    expect(() => registry.transition(claim.id, 'archived')).toThrow(/INVALID_TRANSITION/);
    expect(registry.get(claim.id)?.status).toBe('under_review');

    // Legal paths onward
    expect(registry.transition(claim.id, 'verified').status).toBe('verified');
    expect(registry.transition(claim.id, 'disputed').status).toBe('disputed');
    expect(registry.transition(claim.id, 'rejected').status).toBe('rejected');
    expect(registry.transition(claim.id, 'archived').status).toBe('archived');
  });

  it('a draft claim may only be submitted or archived', () => {
    const draft = submit({ status: 'draft' });
    expect(() => registry.transition(draft.id, 'verified')).toThrow(CoherenceError);
    expect(registry.transition(draft.id, 'submitted').status).toBe('submitted');
  });

  it('canTransition throws a typed CoherenceError for unknown statuses', () => {
    // @ts-expect-error untyped callers
    expect(() => registry.canTransition('bogus', 'verified')).toThrow(CoherenceError);
    // @ts-expect-error untyped callers
    expect(() => registry.canTransition('submitted', 'bogus')).toThrow(CoherenceError);
    expect(registry.canTransition('submitted', 'under_review')).toBe(true);
    expect(registry.canTransition('submitted', 'verified')).toBe(false);
  });

  it('creates typed edges and counts them on the target claim', () => {
    const from = submit();
    const to = submit({ authorId: 'author-2' });

    const edge = registry.addEdge({
      fromClaimId: from.id,
      toClaimId: to.id,
      edgeType: 'contradicts',
      authorId: 'edge-author',
      confidence: 0.9,
      semanticSimilarity: 0.2
    });

    expect(edge.id).toBeTruthy();
    expect(registry.getEdge(edge.id)?.edgeType).toBe('contradicts');
    expect(registry.require(to.id).edges.contradicts).toBe(1);
    expect(registry.require(to.id).edges.supports).toBe(0);

    registry.addEdge({
      fromClaimId: from.id,
      toClaimId: to.id,
      edgeType: 'refines' as EdgeType,
      authorId: 'edge-author-2'
    });
    expect(registry.require(to.id).edges.refines).toBe(1);
    expect(registry.listEdges({ toClaimId: to.id })).toHaveLength(2);
    expect(registry.edgesFor(to.id)).toHaveLength(2);
  });

  it('rejects invalid and self-referential edges', () => {
    const claim = submit();
    expect(() =>
      registry.addEdge({
        fromClaimId: claim.id,
        toClaimId: claim.id,
        edgeType: 'supports',
        authorId: 'x'
      })
    ).toThrow(/linked to itself/);

    expect(() =>
      registry.addEdge({
        fromClaimId: claim.id,
        toClaimId: 'missing-claim',
        edgeType: 'supports',
        authorId: 'x'
      })
    ).toThrow(/not found/);
  });

  it('rejects self-verification at the registry level', () => {
    const claim = submit();
    expect(() =>
      registry.recordVerification(claim.id, {
        verifierId: claim.authorId,
        verdict: 'VERIFIED'
      })
    ).toThrow(/SELF_VERIFICATION/);

    registry.recordVerification(claim.id, { verifierId: 'someone-else', verdict: 'REJECTED' });
    expect(registry.require(claim.id).verifications).toHaveLength(1);
  });

  it('rejects invalid verdicts at the registry level', () => {
    const claim = submit();
    expect(() =>
      registry.recordVerification(claim.id, {
        verifierId: 'verifier-1',
        // @ts-expect-error untyped callers
        verdict: 'MAYBE'
      })
    ).toThrow(CoherenceError);
    expect(registry.require(claim.id).verifications).toHaveLength(0);
  });

  it('dedupes recordVerification: one record per verifier, latest wins', () => {
    const claim = submit();
    registry.recordVerification(claim.id, { verifierId: 'verifier-1', verdict: 'VERIFIED' });
    registry.recordVerification(claim.id, { verifierId: 'verifier-1', verdict: 'REJECTED' });
    registry.recordVerification(claim.id, { verifierId: 'verifier-2', verdict: 'VERIFIED' });

    const verifications = registry.require(claim.id).verifications;
    expect(verifications).toHaveLength(2);
    const first = verifications.find(v => v.verifierId === 'verifier-1')!;
    expect(first.verdict).toBe('REJECTED');
  });

  it('tracks stats', () => {
    submit();
    submit({ status: 'draft' });
    expect(registry.stats().claims).toBe(2);
    expect(registry.stats().totalStake).toBe(0n);
  });
});
