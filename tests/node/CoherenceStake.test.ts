/**
 * H1 fix: `coherence.submitClaim` stake escrow.
 *
 * The registry IGNORES a caller-supplied stake (claims are backed only via
 * `VerificationMarket.backClaim`). The node action therefore escrows a
 * requested stake for real: the caller's ledger is debited into the node's
 * escrow wallet before the backing appears on the claim. These tests prove
 * the funds actually move through the (in-memory) ledger, and that a stake
 * requested without a ledger is a typed error, never bookkeeping fiction.
 */

import { describe, it, expect, afterEach } from '@jest/globals';
import { wholeTokens } from '../../src/economy';
import { AlephNode } from '../../src/node';
import {
  FakeGun,
  authenticatedIdentity,
  createTestIdentity,
  fundAccount,
  readLedgerAccount,
  signedPost,
  startNode
} from './helpers';

describe('coherence.submitClaim stake escrow', () => {
  let node: AlephNode;

  afterEach(async () => {
    await node.stop();
  });

  it('a requested stake REALLY leaves the caller\'s ledger into escrow', async () => {
    const gun = new FakeGun();
    const identity = createTestIdentity();
    // Adept-tier staked balance (tier gate) + spendable available balance.
    fundAccount(gun, identity.fingerprint, wholeTokens(1000), wholeTokens(500));

    ({ node } = await startNode({ port: 0, gun }));

    const res = await signedPost(node, identity, '/actions/coherence.submitClaim', {
      title: 'The sky is blue',
      statement: 'A claim about the sky',
      stake: '50'
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.text).output;
    expect(body.ok).toBe(true);
    expect(body.value.stake).toBe('50');
    const claimId = body.value.id as string;
    expect(claimId).toMatch(/^clm_/);

    // The caller's available balance fell by exactly the stake.
    const callerLedger = await readLedgerAccount(gun, identity.fingerprint);
    expect(callerLedger?.available).toBe(wholeTokens(950).toString());

    // The node's escrow wallet received exactly the stake.
    const escrow = node.getStatus().fingerprint;
    const escrowLedger = await readLedgerAccount(gun, escrow);
    expect(escrowLedger?.available).toBe(wholeTokens(50).toString());

    // The market knows the backing is really escrowed.
    const listRes = await signedPost(node, identity, '/actions/coherence.listClaims', {
      limit: 10
    });
    const claims = JSON.parse(listRes.text).output.value.claims as Array<{
      id: string;
      stake: string;
    }>;
    const backed = claims.find(claim => claim.id === claimId);
    expect(backed?.stake).toBe('50');

    // wallet.balance reflects the debit end-to-end.
    const balanceRes = await signedPost(node, identity, '/actions/wallet.balance', {});
    const balance = JSON.parse(balanceRes.text).output.value;
    expect(balance.available).toBe('950');
  });

  it('a claim without a stake submits without backing and moves no funds', async () => {
    const gun = new FakeGun();
    const identity = createTestIdentity();
    fundAccount(gun, identity.fingerprint, wholeTokens(100), wholeTokens(500));

    ({ node } = await startNode({ port: 0, gun }));

    const res = await signedPost(node, identity, '/actions/coherence.submitClaim', {
      title: 'Unstaked claim',
      statement: 'No funds should move'
    });
    const body = JSON.parse(res.text).output;
    expect(body.ok).toBe(true);
    expect(body.value.stake).toBe('0');

    const callerLedger = await readLedgerAccount(gun, identity.fingerprint);
    expect(callerLedger?.available).toBe(wholeTokens(100).toString());
  });

  it('a stake requested without a ledger is a typed error, never fake bookkeeping', async () => {
    node = await AlephNode.create({ port: 0 });

    // Economy is disabled, so the resolver degrades to Neophyte and the
    // Adept tier gate would mask the ledger error. Override the resolver
    // (public registry API) to reach the handler and prove the typed error.
    node.getActionRegistry().setTierResolver({
      resolveTier: () => Promise.resolve('Adept' as const)
    });

    const identity = createTestIdentity();
    const result = await node.invokeAction(
      'coherence.submitClaim',
      { title: 'T', statement: 'S', stake: '10' },
      { identity: authenticatedIdentity(identity) }
    );
    expect(result.ok).toBe(true);
    const output = result.ok ? (result.value.output as { ok: boolean; code?: string; message?: string }) : null;
    expect(output?.ok).toBe(false);
    expect(output?.code).toBe('STAKE_REQUIRES_LEDGER');
    expect(output?.message).toBe('stake requires a ledger');
  });

  it('a stake larger than the caller\'s available balance fails without recording a backing', async () => {
    const gun = new FakeGun();
    const identity = createTestIdentity();
    fundAccount(gun, identity.fingerprint, wholeTokens(10), wholeTokens(500));

    ({ node } = await startNode({ port: 0, gun }));

    const res = await signedPost(node, identity, '/actions/coherence.submitClaim', {
      title: 'Over-funded claim',
      statement: 'The stake cannot move',
      stake: '500'
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.text).output;
    expect(body.ok).toBe(false);
    // The market surfaces wallet transfer failures as a typed escrow failure
    // carrying the underlying reason.
    expect(body.code).toBe('ESCROW_FAILURE');
    expect(body.message).toMatch(/Insufficient funds/);

    // The registry must not show a backing that never moved.
    const listRes = await signedPost(node, identity, '/actions/coherence.listClaims', {});
    const claims = JSON.parse(listRes.text).output.value.claims as Array<{
      title: string;
      stake: string;
    }>;
    const claim = claims.find(candidate => candidate.title === 'Over-funded claim');
    expect(claim?.stake).toBe('0');
  });
});
