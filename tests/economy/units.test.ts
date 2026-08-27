/**
 * Unit tests for bigint token arithmetic.
 *
 * Focus: the float-money flaw. parse/format must round-trip exactly,
 * subtraction must refuse to underflow, and `number` inputs must be rejected
 * everywhere a monetary amount is expected.
 */

import { describe, expect, it } from '@jest/globals';
import {
  BPS_DENOMINATOR,
  ONE_TOKEN,
  TokenMathError,
  TokenParseError,
  TokenUnderflowError,
  ZERO,
  applyBps,
  assertBigInt,
  assertPositive,
  formatAleph,
  formatTokens,
  mulRatio,
  multiplierToBps,
  parseTokens,
  safeAdd,
  safeDiv,
  safeSub,
  splitProportional,
  sumAmounts,
  toBpsBigInt,
  wholeTokens
} from '../../src/economy/units';

describe('parseTokens', () => {
  it('parses whole tokens', () => {
    expect(parseTokens('10')).toBe(10n * ONE_TOKEN);
    expect(parseTokens('1')).toBe(ONE_TOKEN);
    expect(parseTokens('0')).toBe(0n);
  });

  it('parses fractional tokens exactly', () => {
    expect(parseTokens('1.5')).toBe(15n * 10n ** 17n);
    expect(parseTokens('0.1')).toBe(10n ** 17n);
    expect(parseTokens('0.000000000000000001')).toBe(1n);
    expect(parseTokens('123.456')).toBe(123n * ONE_TOKEN + 456n * 10n ** 15n);
  });

  it('round-trips formatTokens without drift', () => {
    for (const input of ['0', '1', '1.5', '0.1', '0.000000000000000001', '1234.56789', '1000000']) {
      const units = parseTokens(input);
      expect(formatTokens(units)).toBe(input);
    }
  });

  it('round-trips amounts with leading zeros in the fraction', () => {
    const units = parseTokens('1.000000000000000001');
    expect(formatTokens(units)).toBe('1.000000000000000001');
  });

  it('accepts bigint input unchanged (base units are already canonical)', () => {
    expect(parseTokens(7n)).toBe(7n);
    expect(parseTokens(0n)).toBe(0n);
  });

  it('rejects number input outright (the float-money flaw)', () => {
    expect(() => parseTokens(1.5 as unknown as string)).toThrow(TokenParseError);
    expect(() => parseTokens(0.1 as unknown as string)).toThrow(/floating point money is not supported/);
  });

  it('rejects exponents, separators and garbage', () => {
    expect(() => parseTokens('1e3')).toThrow(TokenParseError);
    expect(() => parseTokens('1,000')).toThrow(TokenParseError);
    expect(() => parseTokens('abc')).toThrow(TokenParseError);
    expect(() => parseTokens('')).toThrow(TokenParseError);
  });

  it('rejects every non-canonical form (plus, dangling point, whitespace)', () => {
    const rejected = ['+1', '1.', '.5', ' 1.5 ', '1.5 ', ' 1.5', '+1.5', '-.5', '-1.', '1..5', '.'];
    for (const form of rejected) {
      expect(() => parseTokens(form)).toThrow(TokenParseError);
    }
  });

  it('accepts only canonical decimal forms', () => {
    expect(parseTokens('1.5')).toBe(15n * 10n ** 17n);
    expect(parseTokens('0.5')).toBe(5n * 10n ** 17n);
    expect(parseTokens('123')).toBe(123n * ONE_TOKEN);
    expect(parseTokens('0')).toBe(0n);
    expect(parseTokens('-1.5')).toBe(-(15n * 10n ** 17n));
  });

  it('rejects precision loss instead of silently truncating', () => {
    expect(() => parseTokens('1.0000000000000000001')).toThrow(/more than 18 decimal places/);
    // 19 trailing zero decimals are fine: exact zeros
    expect(parseTokens('1.0000000000000000000')).toBe(ONE_TOKEN);
  });

  it('preserves the sign when parsing negatives (guarded elsewhere)', () => {
    expect(parseTokens('-1.5')).toBe(-(15n * 10n ** 17n));
  });
});

describe('formatTokens', () => {
  it('formats base units', () => {
    expect(formatTokens(ONE_TOKEN)).toBe('1');
    expect(formatTokens(1n)).toBe('0.000000000000000001');
    expect(formatTokens(0n)).toBe('0');
  });

  it('supports min/max fraction digits and separators', () => {
    expect(formatTokens(ONE_TOKEN, { minFractionDigits: 2 })).toBe('1.00');
    expect(formatTokens(15n * 10n ** 17n, { maxFractionDigits: 1 })).toBe('1.5');
    expect(formatTokens(1234n * ONE_TOKEN, { groupThousands: true })).toBe('1_234');
  });

  it('rejects minFractionDigits above maxFractionDigits instead of rendering garbage', () => {
    expect(() =>
      formatTokens(ONE_TOKEN, { minFractionDigits: 3, maxFractionDigits: 2 })
    ).toThrow(TokenMathError);
  });

  it('rejects fractional minimums when decimals is zero', () => {
    expect(() => formatTokens(5n, { decimals: 0, minFractionDigits: 1 })).toThrow(TokenMathError);
    expect(formatTokens(5n, { decimals: 0 })).toBe('5');
  });

  it('renders the aleph suffix', () => {
    expect(formatAleph(ONE_TOKEN)).toBe('1 ℵ');
  });
});

describe('guards', () => {
  it('assertBigInt rejects numbers and strings', () => {
    expect(() => assertBigInt(5)).toThrow(TokenMathError);
    expect(() => assertBigInt('5')).toThrow(TokenMathError);
    expect(() => assertBigInt(undefined)).toThrow(TokenMathError);
    expect(assertBigInt(5n)).toBe(5n);
  });

  it('assertPositive rejects zero and negatives', () => {
    expect(() => assertPositive(0n)).toThrow(TokenMathError);
    expect(() => assertPositive(-1n)).toThrow(TokenMathError);
    expect(assertPositive(1n)).toBe(1n);
  });

  it('wholeTokens only accepts integers', () => {
    expect(wholeTokens(10)).toBe(10n * ONE_TOKEN);
    expect(wholeTokens(10n)).toBe(10n * ONE_TOKEN);
    expect(() => wholeTokens(1.5)).toThrow(TokenParseError);
    expect(() => wholeTokens(Number.MAX_SAFE_INTEGER + 1)).toThrow(TokenParseError);
  });
});

describe('checked arithmetic', () => {
  it('safeSub rejects underflow instead of producing negatives', () => {
    expect(() => safeSub(5n, 6n)).toThrow(TokenUnderflowError);
    expect(() => safeSub(0n, 1n)).toThrow(/underflow/);
    expect(safeSub(6n, 5n)).toBe(1n);
  });

  it('safeAdd rejects negative operands', () => {
    expect(() => safeAdd(1n, -1n)).toThrow(TokenMathError);
    expect(safeAdd(2n, 3n)).toBe(5n);
  });

  it('safeDiv rejects division by zero and negative dividends', () => {
    expect(() => safeDiv(5n, 0n)).toThrow(/positive/);
    expect(() => safeDiv(-5n, 2n)).toThrow(TokenMathError);
    expect(safeDiv(5n, 2n)).toBe(2n);
  });

  it('mulRatio multiplies before dividing to preserve precision', () => {
    // 1 token * 1 / 3 floored
    expect(mulRatio(ONE_TOKEN, 1n, 3n)).toBe(ONE_TOKEN / 3n);
    expect(mulRatio(ONE_TOKEN, 3n, 1n)).toBe(3n * ONE_TOKEN);
  });

  it('applyBps works in integer basis points', () => {
    expect(applyBps(10_000n, 5_000)).toBe(5_000n); // 50% of 10k units
    expect(applyBps(ONE_TOKEN, 100)).toBe(ONE_TOKEN / 100n); // 1%
  });

  it('multiplierToBps converts float config multipliers once, to integers', () => {
    expect(multiplierToBps(1.5)).toBe(15_000);
    expect(multiplierToBps(2.5)).toBe(25_000);
    expect(multiplierToBps(1)).toBe(Number(BPS_DENOMINATOR));
    expect(() => multiplierToBps(Number.NaN)).toThrow(TokenMathError);
    expect(() => multiplierToBps(-1)).toThrow(TokenMathError);
  });

  it('toBpsBigInt rejects fractional bps instead of silently rounding', () => {
    expect(() => toBpsBigInt(1.5)).toThrow(TokenMathError);
    expect(() => toBpsBigInt(Number.NaN)).toThrow(TokenMathError);
    expect(() => toBpsBigInt(-1)).toThrow(TokenMathError);
    expect(toBpsBigInt(3333)).toBe(3333n);
    expect(applyBps(10_000n, 3333)).toBe(3333n);
  });

  it('sumAmounts totals a list', () => {
    expect(sumAmounts([1n, 2n, 3n])).toBe(6n);
    expect(sumAmounts([])).toBe(0n);
    expect(() => sumAmounts([1n, -1n])).toThrow(TokenMathError);
  });

  it('splitProportional conserves every base unit', () => {
    const parts = splitProportional(10n, [1n, 1n, 1n]);
    expect(parts).toEqual([4n, 3n, 3n]);
    expect(parts.reduce((a, b) => a + b, ZERO)).toBe(10n);

    const skewed = splitProportional(10n, [7n, 2n, 1n]);
    expect(skewed.reduce((a, b) => a + b, ZERO)).toBe(10n);
    expect(skewed[0]).toBeGreaterThan(skewed[2]);

    expect(splitProportional(0n, [1n, 2n])).toEqual([0n, 0n]);
    expect(splitProportional(10n, [0n, 1n])).toEqual([0n, 10n]);
  });
});

describe('no float leakage', () => {
  it('every arithmetic result is a bigint', () => {
    const results: unknown[] = [
      safeAdd(1n, 1n),
      safeSub(10n, 1n),
      safeDiv(10n, 3n),
      mulRatio(ONE_TOKEN, 1n, 7n),
      applyBps(ONE_TOKEN, 3333),
      splitProportional(ONE_TOKEN, [1n, 1n, 1n])
    ];
    for (const result of results.flat(1)) {
      expect(typeof result).toBe('bigint');
    }
  });
});
