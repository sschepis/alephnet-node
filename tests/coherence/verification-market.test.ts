/**
 * VerificationMarket tests.
 *
 * The assertions read REAL ledger state (AlephWallet over the fake Gun
 * ledger), proving the legacy "stakes never moved / rewards never credited"
 * flaws are closed:
 *  - claiming a task debits the verifier's available balance into escrow
 *  - settling credits correct verifiers and slashes incorrect ones
 *  - rewards are paid ONLY for the correct outcome
 *  - self-verification is rejected
 *  - timeouts release stakes back to the verifier
 *  - the outcome is DERIVED from the stake-weighted majority (or an injected
 *    authority), never accepted from the caller
 *  - settlement is state-first: a concurrent double settle is rejected and
 *    payouts execute exactly once
 *  - escrow accounting is per task: another task's funds or wallet pollution
 *    can never be paid out through this task
 */

import { describe, expect, it } from '@jest/globals';
import { ClaimRegistry } from '../../src/coherence/ClaimRegistry';
import { VerificationAuthority, VerificationMarket } from '../../src/coherence/VerificationMarket';
import { VerificationVerdict } from '../../src/coherence/types';
import { EconomyWallet } from '../../src/economy/WalletPort';
import { ONE_TOKEN, TokenAmount, parseTokens, wholeTokens } from '../../src/economy/units';
import { createTestLedger, TestLedger, TestWallet } from '../economy/fakeLedger';

const ADEPT_STAKE = 100n * ONE_TOKEN; // 100 tokens staked == Adept tier

interface MarketFixture {
  ledger: TestLedger;
  registry: ClaimRegistry;
  escrow: TestWallet;
  author: TestWallet;
  /** Author's available balance before the reward pool was funded. */
  authorInitialBalance: TokenAmount;
  market: VerificationMarket;
  claimId: string;
  taskId: string;
  advance: (ms: number) => void;
  /** Register a wallet so the market can resolve its address. */
  addWallet: (wallet: TestWallet) => void;
}

function verifier(ledger: TestLedger): TestWallet {
  return ledger.createWallet({ available: wholeTokens(75), staked: ADEPT_STAKE });
}

async function buildMarket(
  overrides: {
    minVerifiers?: number;
    timeoutMs?: number;
    authority?: VerificationAuthority;
    escrow?: EconomyWallet;
  } = {}
): Promise<MarketFixture> {
  const ledger = createTestLedger();
  const registry = new ClaimRegistry();
  const escrow = ledger.createWallet();

  let clock = 1_000_000_000;
  const advance = (ms: number) => {
    clock += ms;
  };

  const author = ledger.createWallet({ available: wholeTokens(100), staked: ADEPT_STAKE });
  const authorInitialBalance = ledger.available(author.address);
  const wallets = new Map<string, TestWallet['wallet']>([
    [author.address, author.wallet],
    [escrow.address, escrow.wallet]
  ]);

  const addWallet = (wallet: TestWallet) => {
    wallets.set(wallet.address, wallet.wallet);
  };

  const market = new VerificationMarket(registry, overrides.escrow ?? escrow.wallet, {
    now: () => clock,
    config: { minVerifiers: overrides.minVerifiers ?? 2, maxVerifiers: 8 },
    authority: overrides.authority,
    resolveWallet: address => wallets.get(address)
  });

  const claim = registry.submit({
    title: 'A claim in need of verification',
    statement: 'This statement is true.',
    authorId: author.address
  });

  const task = await market.createTask({
    type: 'VERIFY',
    claimId: claim.id,
    funderWallet: author.wallet,
    timeoutMs: overrides.timeoutMs ?? 60 * 1000
  });

  return {
    ledger,
    registry,
    escrow,
    author,
    authorInitialBalance,
    market,
    claimId: claim.id,
    taskId: task.id,
    advance,
    addWallet
  };
}

function expectBalanceNear(
  ledger: TestLedger,
  address: string,
  expected: TokenAmount,
  tolerance: TokenAmount = 2n
): void {
  const actual = ledger.available(address);
  const diff = actual > expected ? actual - expected : expected - actual;
  expect(diff).toBeLessThanOrEqual(tolerance);
}

describe('VerificationMarket', () => {
  it('requires stake to claim a task, and the stake REALLY moves into escrow', async () => {
    const fixture = await buildMarket();
    const { ledger, market, escrow, taskId } = fixture;
    const alice = verifier(ledger);
    fixture.addWallet(alice);

    const before = ledger.available(alice.address);
    await market.claimTask(taskId, alice.address);

    // The debit lands on Alice's ledger...
    expect(ledger.available(alice.address)).toBe(before - wholeTokens(25));
    await ledger.flush();
    // ...and the escrow ledger shows the stake alongside the reward pool.
    expect(ledger.available(escrow.address)).toBe(wholeTokens(35)); // 25 stake + 10 pool
  });

  it('rejects self-verification outright', async () => {
    const fixture = await buildMarket();
    const { market, author, taskId } = fixture;

    await expect(market.claimTask(taskId, author.address)).rejects.toMatchObject({
      code: 'SELF_VERIFICATION'
    });
    expect(() =>
      market.submitVerdict({ taskId, verifierAddress: author.address, verdict: 'VERIFIED' })
    ).toThrow(/may not verify their own claim/);
  });

  it('rejects verifiers below the required tier', async () => {
    const fixture = await buildMarket();
    const { ledger, market, taskId } = fixture;
    const neophyte = ledger.createWallet({ available: wholeTokens(75), staked: wholeTokens(10) });
    fixture.addWallet(neophyte);

    await expect(market.claimTask(taskId, neophyte.address)).rejects.toMatchObject({
      code: 'TIER_TOO_LOW'
    });
  });

  it('pays the correct verifier and slashes the incorrect one (real balance movement)', async () => {
    const fixture = await buildMarket({
      authority: { settleOutcome: async (): Promise<VerificationVerdict> => 'VERIFIED' }
    });
    const { ledger, market, escrow, taskId, claimId } = fixture;

    const right = verifier(ledger);
    const wrong = verifier(ledger);
    fixture.addWallet(right);
    fixture.addWallet(wrong);

    const rightBefore = ledger.available(right.address);
    const wrongBefore = ledger.available(wrong.address);

    await market.claimTask(taskId, right.address);
    await market.claimTask(taskId, wrong.address);
    await ledger.flush();

    // Stakes actually left both wallets.
    expect(ledger.available(right.address)).toBe(rightBefore - wholeTokens(25));
    expect(ledger.available(wrong.address)).toBe(wrongBefore - wholeTokens(25));
    expect(ledger.available(escrow.address)).toBe(wholeTokens(60)); // 10 pool + 2x25 stakes

    market.submitVerdict({ taskId, verifierAddress: right.address, verdict: 'VERIFIED', confidence: 0.9 });
    market.submitVerdict({ taskId, verifierAddress: wrong.address, verdict: 'REJECTED', confidence: 0.6 });

    // Ground truth comes from the injected authority, never from the caller.
    const result = await market.settle(taskId);
    await ledger.flush();

    const rightSettlement = result.settlements.find(s => s.address === right.address)!;
    const wrongSettlement = result.settlements.find(s => s.address === wrong.address)!;

    // Only the correct verifier earns; the incorrect one is slashed 50%.
    // Right's reward = 10 pool + 12.5 slashed from wrong = 22.5.
    expect(rightSettlement.correct).toBe(true);
    expect(rightSettlement.slashed).toBe(0n);
    expect(rightSettlement.reward).toBe(parseTokens('22.5'));

    expect(wrongSettlement.correct).toBe(false);
    expect(wrongSettlement.slashed).toBe(parseTokens('12.5'));
    expect(wrongSettlement.reward).toBe(0n);

    // Real balance movement: correct ends UP by reward, incorrect ends DOWN
    // by the slash — despite both having put identical stakes at risk.
    expectBalanceNear(ledger, right.address, rightBefore + parseTokens('22.5'));
    expectBalanceNear(ledger, wrong.address, wrongBefore - parseTokens('12.5'));

    // Escrow is drained to the last base unit: nothing minted, nothing lost.
    expect(ledger.available(escrow.address)).toBe(0n);

    // The claim reached VERIFIED through the legal lifecycle.
    expect(result.claimStatus).toBe('verified');
    expect(fixture.registry.require(claimId).status).toBe('verified');
    expect(fixture.registry.require(claimId).verifications).toHaveLength(2);
  });

  it('rewards only the correct outcome even when the majority is wrong', async () => {
    const fixture = await buildMarket({
      authority: { settleOutcome: async (): Promise<VerificationVerdict> => 'REJECTED' }
    });
    const { ledger, market, escrow, taskId } = fixture;

    const truthTeller = verifier(ledger);
    const sheep1 = verifier(ledger);
    const sheep2 = verifier(ledger);
    for (const v of [truthTeller, sheep1, sheep2]) fixture.addWallet(v);

    await market.claimTask(taskId, truthTeller.address);
    await market.claimTask(taskId, sheep1.address);
    await market.claimTask(taskId, sheep2.address);

    market.submitVerdict({ taskId, verifierAddress: truthTeller.address, verdict: 'REJECTED' });
    market.submitVerdict({ taskId, verifierAddress: sheep1.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: sheep2.address, verdict: 'VERIFIED' });

    // The authority overrides the (wrong) majority.
    const result = await market.settle(taskId);
    await ledger.flush();

    const truth = result.settlements.find(s => s.address === truthTeller.address)!;
    const wrongs = result.settlements.filter(s => s.address !== truthTeller.address);

    expect(truth.correct).toBe(true);
    expect(truth.reward).toBeGreaterThan(0n);
    expect(truth.slashed).toBe(0n);

    for (const wrong of wrongs) {
      expect(wrong.correct).toBe(false);
      expect(wrong.reward).toBe(0n);
      expect(wrong.slashed).toBeGreaterThan(0n);
    }

    expect(ledger.available(escrow.address)).toBe(0n);
    expect(fixture.registry.require(fixture.claimId).status).toBe('rejected');
  });

  it('derives the outcome from the stake-weighted majority — a caller-supplied outcome is ignored', async () => {
    const fixture = await buildMarket();
    const { ledger, market, escrow, taskId } = fixture;

    const one = verifier(ledger);
    const two = verifier(ledger);
    const three = verifier(ledger);
    for (const v of [one, two, three]) fixture.addWallet(v);

    await market.claimTask(taskId, one.address);
    await market.claimTask(taskId, two.address);
    await market.claimTask(taskId, three.address);

    market.submitVerdict({ taskId, verifierAddress: one.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: two.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: three.address, verdict: 'REJECTED' });

    // The second argument is a CALLER (for authorization), not an outcome —
    // a would-be attacker passing a verdict there changes nothing.
    const result = await market.settle(taskId, 'VERIFIED' as unknown as string);
    await ledger.flush();

    expect(result.outcome).toBe('VERIFIED'); // derived from the 2-of-3 majority
    expect(result.inconclusive).toBe(false);

    const wrong = result.settlements.find(s => s.address === three.address)!;
    expect(wrong.correct).toBe(false);
    expect(wrong.slashed).toBe(parseTokens('12.5'));

    expect(ledger.available(escrow.address)).toBe(0n);
    expect(fixture.registry.require(fixture.claimId).status).toBe('verified');
  });

  it('settles a tie as INCONCLUSIVE: every stake AND the reward pool are refunded', async () => {
    const fixture = await buildMarket();
    const { ledger, market, escrow, author, taskId } = fixture;

    const forIt = verifier(ledger);
    const againstIt = verifier(ledger);
    fixture.addWallet(forIt);
    fixture.addWallet(againstIt);

    const forBefore = ledger.available(forIt.address);
    const againstBefore = ledger.available(againstIt.address);

    await market.claimTask(taskId, forIt.address);
    await market.claimTask(taskId, againstIt.address);
    market.submitVerdict({ taskId, verifierAddress: forIt.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: againstIt.address, verdict: 'REJECTED' });

    const result = await market.settle(taskId);
    await ledger.flush();

    expect(result.inconclusive).toBe(true);
    expect(result.outcome).toBeUndefined();
    expect(result.totalSlashed).toBe(0n);
    expect(result.refundedToFunder).toBe(wholeTokens(10));

    // Nobody was slashed; everyone got their whole stake back.
    for (const settlement of result.settlements) {
      expect(settlement.slashed).toBe(0n);
      expect(settlement.stakeReturned).toBe(wholeTokens(25));
      expect(settlement.reward).toBe(0n);
      expect(settlement.netDelta).toBe(0n);
    }

    expectBalanceNear(ledger, forIt.address, forBefore);
    expectBalanceNear(ledger, againstIt.address, againstBefore);
    expectBalanceNear(ledger, author.address, fixture.authorInitialBalance);
    expect(ledger.available(escrow.address)).toBe(0n);
    expect(fixture.registry.require(fixture.claimId).status).toBe('disputed');
  });

  it('an authority may force an inconclusive settlement even with a clear majority', async () => {
    const fixture = await buildMarket({
      authority: { settleOutcome: async () => null }
    });
    const { ledger, market, escrow, taskId } = fixture;

    const one = verifier(ledger);
    const two = verifier(ledger);
    fixture.addWallet(one);
    fixture.addWallet(two);

    await market.claimTask(taskId, one.address);
    await market.claimTask(taskId, two.address);
    market.submitVerdict({ taskId, verifierAddress: one.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: two.address, verdict: 'VERIFIED' });

    const result = await market.settle(taskId);
    await ledger.flush();

    expect(result.inconclusive).toBe(true);
    expect(result.refundedToFunder).toBe(wholeTokens(10));
    expect(ledger.available(escrow.address)).toBe(0n);
  });

  it('when EVERY verifier is wrong, the stranded pool and slashes return to the funder', async () => {
    const fixture = await buildMarket({
      authority: { settleOutcome: async (): Promise<VerificationVerdict> => 'VERIFIED' }
    });
    const { ledger, market, escrow, author, taskId } = fixture;

    const sheep1 = verifier(ledger);
    const sheep2 = verifier(ledger);
    fixture.addWallet(sheep1);
    fixture.addWallet(sheep2);

    await market.claimTask(taskId, sheep1.address);
    await market.claimTask(taskId, sheep2.address);
    market.submitVerdict({ taskId, verifierAddress: sheep1.address, verdict: 'REJECTED' });
    market.submitVerdict({ taskId, verifierAddress: sheep2.address, verdict: 'REJECTED' });

    const result = await market.settle(taskId);
    await ledger.flush();

    // Everyone was wrong: every verifier is slashed, nobody earns a reward.
    expect(result.settlements.every(s => s.correct === false)).toBe(true);
    expect(result.totalSlashed).toBe(parseTokens('25')); // 2 x 12.5
    expect(result.totalDistributed).toBe(0n);
    // The unallocated remainder (pool + slashes) went back to the funder.
    expect(result.refundedToFunder).toBe(parseTokens('35'));

    expect(ledger.available(escrow.address)).toBe(0n);
    expectBalanceNear(ledger, author.address, fixture.authorInitialBalance + parseTokens('25'));
  });

  it('rejects settlement with too few verdicts', async () => {
    const fixture = await buildMarket();
    const { ledger, market, taskId } = fixture;

    const alice = verifier(ledger);
    fixture.addWallet(alice);

    await market.claimTask(taskId, alice.address);
    market.submitVerdict({ taskId, verifierAddress: alice.address, verdict: 'VERIFIED' });

    await expect(market.settle(taskId)).rejects.toMatchObject({ code: 'SETTLEMENT_PREMATURE' });
    // The failed settle left the task open for more verdicts.
    expect(market.getTask(taskId)?.status).toBe('CLAIMED');
  });

  it('rejects verdicts from anyone who has not staked', async () => {
    const fixture = await buildMarket();
    const { ledger, market, taskId } = fixture;

    const bystander = ledger.createWallet({ available: wholeTokens(200), staked: ADEPT_STAKE });
    fixture.addWallet(bystander);

    expect(() =>
      market.submitVerdict({ taskId, verifierAddress: bystander.address, verdict: 'VERIFIED' })
    ).toThrow(/has not staked/);
  });

  it('rejects settlement and expiry from unauthorized callers when the authority requires it', async () => {
    const fixture = await buildMarket({
      authority: {
        settleOutcome: async (): Promise<VerificationVerdict> => 'VERIFIED',
        requireAuthorized: true,
        isAuthorizedCaller: address => address === 'oracle'
      }
    });
    const { ledger, market, taskId, advance } = fixture;

    const alice = verifier(ledger);
    const bob = verifier(ledger);
    fixture.addWallet(alice);
    fixture.addWallet(bob);
    await market.claimTask(taskId, alice.address);
    await market.claimTask(taskId, bob.address);
    market.submitVerdict({ taskId, verifierAddress: alice.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: bob.address, verdict: 'VERIFIED' });

    await expect(market.settle(taskId)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(market.settle(taskId, 'attacker')).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect((await market.settle(taskId, 'oracle')).outcome).toBe('VERIFIED');

    advance(61 * 1000);
    // A new task for the expiry path.
    const claim2 = fixture.registry.submit({
      title: 'Second claim',
      statement: 'Also true.',
      authorId: fixture.author.address
    });
    const task2 = await market.createTask({
      type: 'VERIFY',
      claimId: claim2.id,
      funderWallet: fixture.author.wallet,
      timeoutMs: 60 * 1000
    });
    advance(61 * 1000);
    await expect(market.expireTask(task2.id)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    const expiry = await market.expireTask(task2.id, 'oracle');
    expect(expiry.refundedRewardPool).toBe(wholeTokens(10));
  });

  it('releases every stake when a task times out', async () => {
    const fixture = await buildMarket();
    const { ledger, market, escrow, author, taskId, advance } = fixture;

    const alice = verifier(ledger);
    fixture.addWallet(alice);

    // The pool funding REALLY debited the author.
    await ledger.flush();
    expect(ledger.available(author.address)).toBe(fixture.authorInitialBalance - wholeTokens(10));

    const aliceBefore = ledger.available(alice.address);

    await market.claimTask(taskId, alice.address);
    await ledger.flush();
    expect(ledger.available(alice.address)).toBe(aliceBefore - wholeTokens(25));

    // Clock runs past the deadline; Alice never submits a verdict.
    advance(61 * 1000);

    const results = await market.expireOverdue(fixture.claimId);
    await ledger.flush();

    expect(results).toHaveLength(1);
    expect(results[0].releasedStake).toBe(wholeTokens(25));
    expect(results[0].refundedRewardPool).toBe(wholeTokens(10));
    expect(results[0].releasedTo).toContain(alice.address);
    expect(results[0].slashed).toBe(0n);

    // Alice's stake came back whole; the author's reward pool was refunded,
    // restoring their ORIGINAL balance.
    expectBalanceNear(ledger, alice.address, aliceBefore);
    expectBalanceNear(ledger, author.address, fixture.authorInitialBalance);
    expect(ledger.available(escrow.address)).toBe(0n);

    expect(market.getTask(taskId)?.status).toBe('EXPIRED');
    expect(fixture.registry.require(fixture.claimId).status).toBe('submitted');
  });

  it('rejects early expiry: the deadline must really have passed', async () => {
    const fixture = await buildMarket();
    const { market, taskId } = fixture;

    await expect(market.expireTask(taskId)).rejects.toMatchObject({ code: 'TASK_NOT_EXPIRED' });
    expect(market.getTask(taskId)?.status).toBe('OPEN');
  });

  it('on timeout, wrong-verdict verifiers are slashed and correct ones refunded', async () => {
    const fixture = await buildMarket({ minVerifiers: 3 });
    const { ledger, market, escrow, taskId, advance } = fixture;

    const right1 = verifier(ledger);
    const right2 = verifier(ledger);
    const wrong = verifier(ledger);
    for (const v of [right1, right2, wrong]) fixture.addWallet(v);

    const rightBefore = ledger.available(right1.address);
    const wrongBefore = ledger.available(wrong.address);

    await market.claimTask(taskId, right1.address);
    await market.claimTask(taskId, right2.address);
    await market.claimTask(taskId, wrong.address);

    market.submitVerdict({ taskId, verifierAddress: right1.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: right2.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: wrong.address, verdict: 'REJECTED' });

    advance(61 * 1000);
    const result = await market.expireTask(taskId);
    await ledger.flush();

    // Majority derives VERIFIED; the REJECTED verifier is slashed 12.5 and
    // the slashes go to the two correct verifiers (6.25 each).
    expect(result.slashed).toBe(parseTokens('12.5'));
    expect(result.rewards).toBe(parseTokens('12.5'));
    expect(result.refundedRewardPool).toBe(wholeTokens(10));

    expectBalanceNear(ledger, wrong.address, wrongBefore - parseTokens('12.5'));
    expectBalanceNear(ledger, right1.address, rightBefore + parseTokens('6.25'));
    expect(ledger.available(escrow.address)).toBe(0n);
    expect(market.getTask(taskId)?.status).toBe('EXPIRED');
  });

  it('a timeout with no derivable outcome refunds everyone in full', async () => {
    const fixture = await buildMarket();
    const { ledger, market, escrow, taskId, advance } = fixture;

    const forIt = verifier(ledger);
    const againstIt = verifier(ledger);
    fixture.addWallet(forIt);
    fixture.addWallet(againstIt);

    const forBefore = ledger.available(forIt.address);
    const againstBefore = ledger.available(againstIt.address);

    await market.claimTask(taskId, forIt.address);
    await market.claimTask(taskId, againstIt.address);
    market.submitVerdict({ taskId, verifierAddress: forIt.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: againstIt.address, verdict: 'REJECTED' });

    advance(61 * 1000);
    const result = await market.expireTask(taskId);
    await ledger.flush();

    expect(result.slashed).toBe(0n);
    expect(result.rewards).toBe(0n);
    expectBalanceNear(ledger, forIt.address, forBefore);
    expectBalanceNear(ledger, againstIt.address, againstBefore);
    expect(ledger.available(escrow.address)).toBe(0n);
  });

  it('a concurrent double settle is rejected: payouts execute exactly once', async () => {
    const fixture = await buildMarket();
    const { ledger, market, escrow, taskId } = fixture;

    const alice = verifier(ledger);
    const bob = verifier(ledger);
    fixture.addWallet(alice);
    fixture.addWallet(bob);

    await market.claimTask(taskId, alice.address);
    await market.claimTask(taskId, bob.address);
    market.submitVerdict({ taskId, verifierAddress: alice.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: bob.address, verdict: 'VERIFIED' });

    // Post-stake snapshot: settlement returns the 25 stake + 5 reward.
    const aliceBefore = ledger.available(alice.address);

    const [first, second] = await Promise.allSettled([market.settle(taskId), market.settle(taskId)]);
    await ledger.flush();

    const fulfilled = [first, second].filter(r => r.status === 'fulfilled');
    const rejected = [first, second].filter(r => r.status === 'rejected');
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({ code: 'TASK_NOT_OPEN' });

    // Each correct verifier earned exactly once: stake back + half the pool.
    // A double payout would have credited a further 25 tokens.
    expectBalanceNear(ledger, alice.address, aliceBefore + wholeTokens(30));
    expect(ledger.available(escrow.address)).toBe(0n);
    expect(market.getTask(taskId)?.status).toBe('SETTLED');
  });

  it('rejects funderless tasks: a bare funder address cannot fund a non-zero reward pool', async () => {
    const fixture = await buildMarket();
    const { market, claimId } = fixture;

    await expect(
      // @ts-expect-error funderWallet is required; a bare address is rejected at runtime too
      market.createTask({ type: 'VERIFY', claimId, funderAddress: '0xdeadbeef' })
    ).rejects.toMatchObject({ code: 'CLAIM_INVALID' });

    // No task materialized, so nothing can ever be paid out of thin air.
    expect(market.listTasks({ claimId })).toHaveLength(1);
  });

  it('escrow is per task: settling one task cannot touch another task escrow or wallet pollution', async () => {
    const fixture = await buildMarket();
    const { ledger, market, escrow, taskId, advance } = fixture;

    // A second claim + task, funded by a different wallet.
    const otherAuthor = ledger.createWallet({ available: wholeTokens(50), staked: ADEPT_STAKE });
    fixture.addWallet(otherAuthor);
    const claimB = fixture.registry.submit({
      title: 'Second claim',
      statement: 'Independent.',
      authorId: otherAuthor.address
    });
    const taskB = await market.createTask({
      type: 'VERIFY',
      claimId: claimB.id,
      funderWallet: otherAuthor.wallet,
      timeoutMs: 60 * 1000
    });

    // Pollute the escrow wallet out of band with 1000 tokens.
    const polluter = ledger.createWallet({ available: wholeTokens(2_000), staked: ADEPT_STAKE });
    await polluter.wallet.transfer(escrow.address, wholeTokens(1_000));

    // Task A: two agreeing verifiers settle cleanly.
    const alice = verifier(ledger);
    const bob = verifier(ledger);
    fixture.addWallet(alice);
    fixture.addWallet(bob);
    await market.claimTask(taskId, alice.address);
    await market.claimTask(taskId, bob.address);
    market.submitVerdict({ taskId, verifierAddress: alice.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: bob.address, verdict: 'VERIFIED' });

    await market.settle(taskId);
    await ledger.flush();

    // Only task A's own 10-pool + 2x25 stakes left the wallet: task B's
    // pool and the 1000-token pollution are untouched.
    expect(ledger.available(escrow.address)).toBe(wholeTokens(10) + wholeTokens(1_000));

    // Task B can still draw its own escrow when its time comes.
    advance(61 * 1000);
    const expiry = await market.expireTask(taskB.id);
    await ledger.flush();
    expect(expiry.refundedRewardPool).toBe(wholeTokens(10));
    expect(ledger.available(escrow.address)).toBe(wholeTokens(1_000));
  });

  it('a partial expiry failure is resumable and refunds are idempotent', async () => {
    const ledger = createTestLedger();
    const registry = new ClaimRegistry();
    const escrow = ledger.createWallet();
    let clock = 1_000_000_000;
    const advance = (ms: number) => {
      clock += ms;
    };

    let failNextTransferTo: string | undefined;
    const flakyEscrow: EconomyWallet = {
      address: escrow.wallet.address,
      getBalance: () => escrow.wallet.getBalance(),
      transfer: async (to, amount, options) => {
        if (failNextTransferTo === to) {
          failNextTransferTo = undefined;
          throw new Error('simulated transfer failure');
        }
        return escrow.wallet.transfer(to, amount, options);
      },
      stake: (amount, lockPeriod) => escrow.wallet.stake(amount, lockPeriod),
      unstake: stakeId => escrow.wallet.unstake(stakeId),
      claimRewards: stakeId => escrow.wallet.claimRewards(stakeId)
    };

    const author = ledger.createWallet({ available: wholeTokens(100), staked: ADEPT_STAKE });
    const wallets = new Map<string, TestWallet['wallet']>([
      [author.address, author.wallet],
      [escrow.address, escrow.wallet]
    ]);
    const market = new VerificationMarket(registry, flakyEscrow, {
      now: () => clock,
      config: { minVerifiers: 2, maxVerifiers: 8 },
      resolveWallet: address => wallets.get(address)
    });

    const claim = registry.submit({
      title: 'Flaky expiry',
      statement: 'Still true.',
      authorId: author.address
    });
    const task = await market.createTask({
      type: 'VERIFY',
      claimId: claim.id,
      funderWallet: author.wallet,
      timeoutMs: 60 * 1000
    });

    const alice = verifier(ledger);
    const bob = verifier(ledger);
    wallets.set(alice.address, alice.wallet);
    wallets.set(bob.address, bob.wallet);
    const aliceBefore = ledger.available(alice.address);
    const bobBefore = ledger.available(bob.address);

    await market.claimTask(task.id, alice.address);
    await market.claimTask(task.id, bob.address);
    advance(61 * 1000);

    // The refund to bob (the second claimed) fails once.
    failNextTransferTo = bob.address;
    await expect(market.expireTask(task.id)).rejects.toMatchObject({ code: 'ESCROW_FAILURE' });
    await ledger.flush();

    // State was committed FIRST: the task is EXPIRED and alice's refund is
    // already on the ledger — bob's stake and the pool remain in escrow.
    expect(market.getTask(task.id)?.status).toBe('EXPIRED');
    expectBalanceNear(ledger, alice.address, aliceBefore);
    expect(ledger.available(escrow.address)).toBe(wholeTokens(35)); // bob 25 + pool 10

    // Retry: only the missing refunds execute. Alice is NOT paid twice.
    const retry = await market.expireTask(task.id);
    await ledger.flush();

    expect(retry.releasedStake).toBe(wholeTokens(25));
    expect(retry.releasedTo).toEqual([bob.address]);
    expect(retry.refundedRewardPool).toBe(wholeTokens(10));

    expectBalanceNear(ledger, alice.address, aliceBefore);
    expectBalanceNear(ledger, bob.address, bobBefore);
    expect(ledger.available(escrow.address)).toBe(0n);

    // A third call is a no-op: nothing more to refund.
    const third = await market.expireTask(task.id);
    expect(third.releasedStake).toBe(0n);
    expect(third.refundedRewardPool).toBe(0n);
  });

  it('backClaim escrows real money into per-claim escrow and records the backing', async () => {
    const fixture = await buildMarket();
    const { ledger, market, escrow, claimId, taskId } = fixture;

    const backer = verifier(ledger);
    fixture.addWallet(backer);
    const backerBefore = ledger.available(backer.address);

    const claim = await market.backClaim(claimId, backer.wallet, wholeTokens(30), backer.address);
    await ledger.flush();

    // The backing REALLY left the backer's wallet into escrow...
    expect(ledger.available(backer.address)).toBe(backerBefore - wholeTokens(30));
    expect(ledger.available(escrow.address)).toBe(wholeTokens(30) + wholeTokens(10)); // + task pool
    // ...and is recorded on the claim under per-claim escrow accounting.
    expect(claim.stake).toBe(wholeTokens(30));
    expect(claim.backings).toHaveLength(1);
    expect(claim.backings[0].stakerId).toBe(backer.address);
    expect(fixture.registry.require(claimId).stake).toBe(wholeTokens(30));
    expect(fixture.registry.stats().totalStake).toBe(wholeTokens(30));
    expect(market.backingEscrowed(claimId)).toBe(wholeTokens(30));

    // Task settlement only drains the TASK's escrow; the backing stays.
    const alice = verifier(ledger);
    const bob = verifier(ledger);
    fixture.addWallet(alice);
    fixture.addWallet(bob);
    await market.claimTask(taskId, alice.address);
    await market.claimTask(taskId, bob.address);
    market.submitVerdict({ taskId, verifierAddress: alice.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: bob.address, verdict: 'VERIFIED' });
    await market.settle(taskId);
    await ledger.flush();

    expect(ledger.available(escrow.address)).toBe(wholeTokens(30));
  });

  it('backClaim requires a real, positive transfer from a non-escrow wallet', async () => {
    const fixture = await buildMarket();
    const { ledger, market, escrow, claimId } = fixture;

    const backer = verifier(ledger);
    fixture.addWallet(backer);

    await expect(
      // @ts-expect-error floats are not money
      market.backClaim(claimId, backer.wallet, 1.5, backer.address)
    ).rejects.toThrow();
    await expect(market.backClaim(claimId, backer.wallet, 0n, backer.address)).rejects.toThrow();
    await expect(market.backClaim(claimId, escrow.wallet, wholeTokens(5), 'x')).rejects.toMatchObject({
      code: 'CLAIM_INVALID'
    });
    expect(fixture.registry.require(claimId).stake).toBe(0n);
  });

  it('rejects tasks on already-settled claims', async () => {
    const fixture = await buildMarket({
      authority: { settleOutcome: async (): Promise<VerificationVerdict> => 'VERIFIED' }
    });
    const { ledger, market, claimId, taskId } = fixture;

    const alice = verifier(ledger);
    const bob = verifier(ledger);
    fixture.addWallet(alice);
    fixture.addWallet(bob);
    await market.claimTask(taskId, alice.address);
    await market.claimTask(taskId, bob.address);
    market.submitVerdict({ taskId, verifierAddress: alice.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: bob.address, verdict: 'VERIFIED' });
    await market.settle(taskId);

    expect(fixture.registry.require(claimId).status).toBe('verified');
    await expect(
      market.createTask({
        type: 'VERIFY',
        claimId,
        funderWallet: fixture.author.wallet
      })
    ).rejects.toMatchObject({ code: 'CLAIM_INVALID' });
  });

  it('computes consensus confidence exactly from the agreeing stake share', async () => {
    const fixture = await buildMarket();
    const { ledger, market, claimId, taskId } = fixture;

    const one = verifier(ledger);
    const two = verifier(ledger);
    const three = verifier(ledger);
    for (const v of [one, two, three]) fixture.addWallet(v);

    await market.claimTask(taskId, one.address);
    await market.claimTask(taskId, two.address);
    await market.claimTask(taskId, three.address);
    market.submitVerdict({ taskId, verifierAddress: one.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: two.address, verdict: 'VERIFIED' });
    market.submitVerdict({ taskId, verifierAddress: three.address, verdict: 'REJECTED' });

    await market.settle(taskId);

    // 2 of 3 equal stakes agree: the exact six-decimal expansion of 2/3.
    expect(fixture.registry.require(claimId).confidence).toBe(0.666666);
  });
});
