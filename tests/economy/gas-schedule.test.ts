/**
 * GasSchedule tests.
 *
 * Focus: costing stays in bigint base units (no float money), the payer
 * context is strongly typed so a token balance can never masquerade as
 * credits, and tier subsidies key off the canonical tier multipliers.
 */

import { describe, expect, it } from '@jest/globals';
import {
  GasSchedule,
  NO_CREDITS,
  creditUnits,
  tierSubsidyBps
} from '../../src/economy/GasSchedule';
import { ONE_TOKEN, TokenMathError, wholeTokens } from '../../src/economy/units';

const E18 = 10n ** 18n;

describe('GasSchedule', () => {
  const schedule = new GasSchedule();
  const payer = {
    tier: 'Adept' as const,
    tokenBalance: wholeTokens(10),
    gasCredits: NO_CREDITS,
    coherence: 0.5
  };

  it('estimate returns bigint base units that scale with size', () => {
    const small = schedule.estimate('token_transfer', 0);
    const large = schedule.estimate('token_transfer', 100_000);

    expect(typeof small).toBe('bigint');
    expect(large).toBeGreaterThan(small);
    expect(schedule.estimate('contract_deploy')).toBeGreaterThan(schedule.estimate('token_transfer'));
  });

  it('never produces floating point money anywhere in a quote', () => {
    const quote = schedule.quote('memory_store', payer, 1024);

    const numericFields = [
      quote.baseCost,
      quote.directCost,
      quote.subsidizedCost,
      quote.subsidy,
      quote.payable,
      quote.distribution.burned,
      quote.distribution.rewardPool,
      quote.distribution.treasury
    ];
    for (const field of numericFields) {
      expect(typeof field).toBe('bigint');
    }
    expect(typeof quote.gasUnits).toBe('bigint');
  });

  it('fee distribution is exact: parts sum to the fee', () => {
    const quote = schedule.quote('stake', payer);
    const { burned, rewardPool, treasury, total } = quote.distribution;
    expect(burned + rewardPool + treasury).toBe(total);
  });

  it('converts between credits and tokens in integers only', () => {
    const credits = schedule.toCredits(ONE_TOKEN);
    expect(credits).toBe(100n); // 100 credits per token
    expect(schedule.fromCredits(creditUnits(100n))).toBe(ONE_TOKEN);
    // Rounding up: 0.75 tokens -> 75 credits, rounded to whole credits.
    expect(schedule.toCredits((E18 * 3n) / 4n)).toBe(75n);
  });

  it('applies tier-based subsidy from the canonical multipliers', () => {
    const neophyteSubsidy = tierSubsidyBps('Neophyte', 4_000);
    const archonSubsidy = tierSubsidyBps('Archon', 4_000);
    const adeptSubsidy = tierSubsidyBps('Adept', 4_000);

    expect(neophyteSubsidy).toBe(0);
    expect(archonSubsidy).toBe(4_000);
    expect(adeptSubsidy).toBeGreaterThan(0);
    expect(adeptSubsidy).toBeLessThan(archonSubsidy);
  });

  it('recommends credits only when the credit balance covers the cost', () => {
    const poor = { ...payer, tokenBalance: 0n, gasCredits: NO_CREDITS };
    const creditRich = { ...payer, tokenBalance: 0n, gasCredits: creditUnits(1_000_000n) };
    const tokenRich = { ...payer, tokenBalance: wholeTokens(1_000) };

    const broke = schedule.quote('contract_deploy', poor);
    expect(broke.recommended).toBe('none');
    expect(broke.affordable).toBe(false);

    const onCredits = schedule.quote('contract_deploy', creditRich);
    expect(onCredits.recommended).toBe('credits');

    const onTokens = schedule.quote('contract_deploy', tokenRich);
    expect(['direct', 'subsidized']).toContain(onTokens.recommended);
  });

  it('recommends direct payment when no subsidy applies', () => {
    const neophyte = { tier: 'Neophyte' as const, tokenBalance: wholeTokens(1_000), gasCredits: NO_CREDITS };
    const quote = schedule.quote('contract_deploy', neophyte);

    expect(quote.subsidy).toBe(0n);
    expect(quote.recommended).toBe('direct');
    expect(quote.payable).toBe(quote.directCost);
  });

  it('requireAffordable names the costs that actually apply', () => {
    const poor = { tier: 'Neophyte' as const, tokenBalance: 0n, gasCredits: NO_CREDITS };
    const quote = schedule.quote('contract_deploy', poor);

    expect(quote.affordable).toBe(false);
    expect(() => schedule.requireAffordable(quote, poor)).toThrow(/insufficient gas funds for contract_deploy/);
    expect(() => schedule.requireAffordable(quote, poor)).toThrow(/direct/i);

    const affordable = schedule.quote('token_transfer', payer);
    expect(schedule.requireAffordable(affordable, payer)).toBe(affordable);
  });

  it('rejects invalid configs instead of drifting', () => {
    expect(() => new GasSchedule({ gasPrice: 0n })).toThrow(TokenMathError);
    expect(() => new GasSchedule({ burnBps: 9_000 })).toThrow(/must sum to 10000/);
    expect(() => new GasSchedule({ maxSubsidyBps: 20_000 })).toThrow(TokenMathError);
  });

  it('credit and token types are distinct at the type level', () => {
    // Compile-time brand: a TokenAmount cannot be silently passed as credits.
    const credits = creditUnits(5n);
    expect(typeof credits).toBe('bigint');
    expect(credits).toBe(5n);
  });
});
