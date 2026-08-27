/**
 * Token Unit Arithmetic
 *
 * Every monetary value in AlephNet is a `bigint` count of BASE UNITS
 * (1 ℵ = 10^18 base units = WALLET.ONE_TOKEN).
 *
 * Floating point is NEVER used for money. The legacy JS economy stored
 * balances as `number` and priced gas at 0.000001 ℵ, which guaranteed
 * rounding drift and silently unspendable dust. Here:
 *   - `number` inputs are rejected at runtime (`assertBigInt`, `parseTokens`)
 *   - decimal strings are parsed digit-by-digit, never via `parseFloat`
 *   - proportional splits are exact: every base unit is accounted for
 *   - subtraction is guarded, so balances can never wrap negative
 */

import { WALLET } from '../common/constants';

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS & TYPES
// ═══════════════════════════════════════════════════════════════════════════

/** A monetary amount, always expressed in base units. */
export type TokenAmount = bigint;

/** Zero base units. */
export const ZERO: TokenAmount = 0n;

/** One whole token in base units (10^18). */
export const ONE_TOKEN: TokenAmount = WALLET.ONE_TOKEN;

/** Number of decimals a whole token is divided into. */
export const TOKEN_DECIMALS: number = WALLET.TOKEN_DECIMALS;

/** Basis-point denominator: 10_000 bps == 100%. */
export const BPS_DENOMINATOR = 10_000n;

/** Options accepted by {@link formatTokens}. */
export interface FormatTokensOptions {
  /** Decimals of the amount (default: token decimals). */
  decimals?: number;
  /** Always render at least this many fraction digits (default 0). */
  minFractionDigits?: number;
  /** Truncate the rendered fraction to at most this many digits. */
  maxFractionDigits?: number;
  /** Insert `_` separators every three integer digits (default false). */
  groupThousands?: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

export type TokenMathErrorCode =
  | 'NOT_BIGINT'
  | 'PARSE'
  | 'PRECISION_LOSS'
  | 'NEGATIVE'
  | 'NOT_POSITIVE'
  | 'UNDERFLOW'
  | 'DIVIDE_BY_ZERO'
  | 'RANGE';

/** Base class for all money-arithmetic failures. */
export class TokenMathError extends Error {
  public readonly code: TokenMathErrorCode;

  constructor(code: TokenMathErrorCode, message: string) {
    super(message);
    this.name = 'TokenMathError';
    this.code = code;
  }
}

/** Thrown when a subtraction would drive an amount below zero. */
export class TokenUnderflowError extends TokenMathError {
  constructor(message: string) {
    super('UNDERFLOW', message);
    this.name = 'TokenUnderflowError';
  }
}

/** Thrown when a decimal string cannot be decoded losslessly. */
export class TokenParseError extends TokenMathError {
  constructor(code: 'PARSE' | 'PRECISION_LOSS' | 'NOT_BIGINT', message: string) {
    super(code, message);
    this.name = 'TokenParseError';
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// GUARDS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Assert a value really is a bigint.
 *
 * This is the primary defence against float leakage: passing a `number`
 * (e.g. `0.000001`) anywhere near money throws instead of silently
 * producing a drifting result.
 */
export function assertBigInt(value: unknown, label = 'amount'): TokenAmount {
  if (typeof value !== 'bigint') {
    throw new TokenMathError(
      'NOT_BIGINT',
      `${label} must be a bigint in base units, received ${typeof value} (${String(value)})`
    );
  }
  return value;
}

/** Assert an amount is a bigint and >= 0. */
export function assertNonNegative(value: unknown, label = 'amount'): TokenAmount {
  const amount = assertBigInt(value, label);
  if (amount < ZERO) {
    throw new TokenMathError('NEGATIVE', `${label} must not be negative, received ${amount}`);
  }
  return amount;
}

/** Assert an amount is a bigint and > 0. */
export function assertPositive(value: unknown, label = 'amount'): TokenAmount {
  const amount = assertBigInt(value, label);
  if (amount <= ZERO) {
    throw new TokenMathError('NOT_POSITIVE', `${label} must be positive, received ${amount}`);
  }
  return amount;
}

/** True when the value is a bigint >= 0. */
export function isTokenAmount(value: unknown): value is TokenAmount {
  return typeof value === 'bigint' && value >= ZERO;
}

/** Assert an integer decimals/precision argument. */
function assertDecimals(decimals: number, label = 'decimals'): number {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
    throw new TokenMathError('RANGE', `${label} must be an integer in [0, 36], received ${decimals}`);
  }
  return decimals;
}

/** 10^n as a bigint. */
export function pow10(exponent: number): bigint {
  return 10n ** BigInt(assertDecimals(exponent, 'exponent'));
}

// ═══════════════════════════════════════════════════════════════════════════
// PARSING & FORMATTING
// ═══════════════════════════════════════════════════════════════════════════

const DECIMAL_PATTERN = /^(-?)(\d+)(?:\.(\d+))?$/;

/**
 * Parse a human decimal token string into base units.
 *
 *   parseTokens('1.5')  -> 1500000000000000000n
 *   parseTokens('0.5')  -> 500000000000000000n
 *   parseTokens('123')  -> 123000000000000000000n
 *
 * Only the canonical decimal grammar is accepted: an optional leading `-`,
 * then one or more digits, then optionally `.` followed by one or more
 * digits. Non-canonical forms are REJECTED rather than silently normalised:
 * `'+1'` (explicit plus), `'1.'` (dangling point), `'.5'` (missing whole
 * part) and surrounding whitespace (`' 1.5 '`) all throw. Negative amounts
 * are allowed (the canonical form is `'-1.5'`) and guarded elsewhere.
 *
 * A `bigint` input is already in base units and is returned unchanged, which
 * makes the helper safe to apply to configuration values of either shape.
 * A `number` input is ALWAYS rejected: `0.1` cannot be represented exactly
 * in binary floating point and must never enter the ledger.
 */
export function parseTokens(value: string | bigint, decimals: number = TOKEN_DECIMALS): TokenAmount {
  assertDecimals(decimals);

  if (typeof value === 'bigint') return value;

  if (typeof value !== 'string') {
    throw new TokenParseError(
      'NOT_BIGINT',
      `parseTokens expects a decimal string or bigint, received ${typeof value} ` +
        `(${String(value)}) — floating point money is not supported`
    );
  }

  const raw = value;
  if (raw.length === 0) {
    throw new TokenParseError('PARSE', 'parseTokens received an empty string');
  }

  const match = DECIMAL_PATTERN.exec(raw);
  if (!match) {
    throw new TokenParseError(
      'PARSE',
      `"${raw}" is not a canonical decimal amount (a leading '-' and ` +
        `'<digits>[.<digits>]' only: no '+', no leading/trailing '.', no ` +
        `whitespace, exponents or separators)`
    );
  }

  const [, sign, wholePart, fractionPart] = match;
  const whole = wholePart ?? '';
  const fraction = fractionPart ?? '';

  let scaledFraction = fraction;
  if (scaledFraction.length > decimals) {
    const overflow = scaledFraction.slice(decimals);
    if (/[^0]/.test(overflow)) {
      throw new TokenParseError(
        'PRECISION_LOSS',
        `"${raw}" has more than ${decimals} decimal places and cannot be represented exactly`
      );
    }
    scaledFraction = scaledFraction.slice(0, decimals);
  }
  scaledFraction = scaledFraction.padEnd(decimals, '0');

  const digits = `${whole === '' ? '0' : whole}${scaledFraction}`;
  const magnitude = BigInt(digits);
  return sign === '-' ? -magnitude : magnitude;
}

/**
 * Render base units as a human decimal string.
 *
 *   formatTokens(1500000000000000000n) -> '1.5'
 *   formatTokens(ONE_TOKEN)            -> '1'
 *   formatTokens(1n)                   -> '0.000000000000000001'
 */
export function formatTokens(amount: TokenAmount, options: FormatTokensOptions = {}): string {
  assertBigInt(amount, 'amount');

  const decimals = assertDecimals(options.decimals ?? TOKEN_DECIMALS);
  const minFractionDigits = assertDecimals(options.minFractionDigits ?? 0, 'minFractionDigits');
  const maxFractionDigits = assertDecimals(options.maxFractionDigits ?? decimals, 'maxFractionDigits');

  if (minFractionDigits > maxFractionDigits) {
    throw new TokenMathError(
      'RANGE',
      `minFractionDigits (${minFractionDigits}) must not exceed maxFractionDigits (${maxFractionDigits})`
    );
  }
  if (decimals === 0 && minFractionDigits > 0) {
    throw new TokenMathError(
      'RANGE',
      `minFractionDigits (${minFractionDigits}) cannot be rendered with decimals 0 ` +
        `(the amount has no fractional precision)`
    );
  }

  const negative = amount < ZERO;
  const magnitude = negative ? -amount : amount;
  const divisor = pow10(decimals);

  const whole = magnitude / divisor;
  const fraction = magnitude % divisor;

  let fractionDigits = decimals === 0 ? '' : fraction.toString().padStart(decimals, '0');
  if (fractionDigits.length > maxFractionDigits) {
    fractionDigits = fractionDigits.slice(0, maxFractionDigits);
  }
  // Trim insignificant zeros, but never below minFractionDigits (which can
  // never exceed the rendered precision: digits beyond `decimals` do not
  // exist in the amount and are not fabricated).
  const minRendered = Math.min(minFractionDigits, decimals);
  let end = fractionDigits.length;
  while (end > minRendered && fractionDigits[end - 1] === '0') end--;
  fractionDigits = fractionDigits.slice(0, end).padEnd(minRendered, '0');

  let wholeDigits = whole.toString();
  if (options.groupThousands) {
    wholeDigits = wholeDigits.replace(/\B(?=(\d{3})+(?!\d))/g, '_');
  }

  const body = fractionDigits.length > 0 ? `${wholeDigits}.${fractionDigits}` : wholeDigits;
  return negative ? `-${body}` : body;
}

/** Format with the `ℵ` unit suffix, for logs and error messages. */
export function formatAleph(amount: TokenAmount, options?: FormatTokensOptions): string {
  return `${formatTokens(amount, options)} ℵ`;
}

/**
 * Convert a whole number of tokens into base units.
 * Only integers are accepted — this is a config helper, not a money parser.
 */
export function wholeTokens(count: number | bigint): TokenAmount {
  if (typeof count === 'bigint') return count * ONE_TOKEN;
  if (!Number.isSafeInteger(count)) {
    throw new TokenParseError(
      'PARSE',
      `wholeTokens expects a safe integer count of tokens, received ${count}; ` +
        `use parseTokens('${count}') for fractional amounts`
    );
  }
  return BigInt(count) * ONE_TOKEN;
}

// ═══════════════════════════════════════════════════════════════════════════
// CHECKED ARITHMETIC
// ═══════════════════════════════════════════════════════════════════════════

/** Add two non-negative amounts. */
export function safeAdd(a: TokenAmount, b: TokenAmount, label = 'amount'): TokenAmount {
  return assertNonNegative(a, `${label} (lhs)`) + assertNonNegative(b, `${label} (rhs)`);
}

/**
 * Subtract `b` from `a`, refusing to underflow.
 *
 * bigint subtraction happily returns negative numbers; an unguarded
 * `balance - amount` is exactly how a ledger acquires phantom funds.
 */
export function safeSub(a: TokenAmount, b: TokenAmount, label = 'amount'): TokenAmount {
  const lhs = assertNonNegative(a, `${label} (lhs)`);
  const rhs = assertNonNegative(b, `${label} (rhs)`);
  if (rhs > lhs) {
    throw new TokenUnderflowError(
      `${label} underflow: cannot subtract ${formatTokens(rhs)} from ${formatTokens(lhs)}`
    );
  }
  return lhs - rhs;
}

/** Subtract, clamping at zero instead of throwing. */
export function saturatingSub(a: TokenAmount, b: TokenAmount, label = 'amount'): TokenAmount {
  const lhs = assertNonNegative(a, `${label} (lhs)`);
  const rhs = assertNonNegative(b, `${label} (rhs)`);
  return rhs > lhs ? ZERO : lhs - rhs;
}

/** Multiply an amount by a non-negative integer factor. */
export function safeMul(a: TokenAmount, factor: TokenAmount, label = 'amount'): TokenAmount {
  return assertNonNegative(a, label) * assertNonNegative(factor, `${label} factor`);
}

/** Floor division of an amount by a positive integer divisor. */
export function safeDiv(a: TokenAmount, divisor: TokenAmount, label = 'amount'): TokenAmount {
  const lhs = assertNonNegative(a, label);
  const rhs = assertBigInt(divisor, `${label} divisor`);
  if (rhs <= ZERO) {
    throw new TokenMathError('DIVIDE_BY_ZERO', `${label} divisor must be positive, received ${rhs}`);
  }
  return lhs / rhs;
}

/**
 * amount * numerator / denominator, floored, without ever leaving bigint.
 * Multiplication happens first so precision is preserved.
 */
export function mulRatio(
  amount: TokenAmount,
  numerator: bigint,
  denominator: bigint,
  label = 'amount'
): TokenAmount {
  const value = assertNonNegative(amount, label);
  const num = assertNonNegative(numerator, `${label} numerator`);
  const den = assertBigInt(denominator, `${label} denominator`);
  if (den <= ZERO) {
    throw new TokenMathError('DIVIDE_BY_ZERO', `${label} denominator must be positive, received ${den}`);
  }
  return (value * num) / den;
}

/** Apply a basis-point rate (10_000 bps == 100%), floored. */
export function applyBps(amount: TokenAmount, bps: number | bigint, label = 'amount'): TokenAmount {
  const rate = typeof bps === 'bigint' ? bps : toBpsBigInt(bps, `${label} bps`);
  return mulRatio(amount, rate, BPS_DENOMINATOR, label);
}

/**
 * Convert a `number` rate into integer basis points.
 *
 * Basis points are integers by definition; a fractional bps input is a
 * caller bug (probably a multiplier that should have gone through
 * {@link multiplierToBps}), so it throws instead of silently rounding.
 */
export function toBpsBigInt(value: number, label = 'bps'): bigint {
  if (!Number.isInteger(value) || value < 0) {
    throw new TokenMathError(
      'RANGE',
      `${label} must be a non-negative integer number of basis points, received ${value} ` +
        `(use multiplierToBps for fractional multipliers)`
    );
  }
  return BigInt(value);
}

/** Convert a multiplier such as 1.5 into 15_000 bps. */
export function multiplierToBps(multiplier: number, label = 'multiplier'): number {
  if (!Number.isFinite(multiplier) || multiplier < 0) {
    throw new TokenMathError('RANGE', `${label} must be a finite non-negative number, received ${multiplier}`);
  }
  return Math.round(multiplier * Number(BPS_DENOMINATOR));
}

/** Sum a list of non-negative amounts. */
export function sumAmounts(amounts: Iterable<TokenAmount>, label = 'amount'): TokenAmount {
  let total = ZERO;
  for (const amount of amounts) {
    total += assertNonNegative(amount, label);
  }
  return total;
}

/** Smaller of two amounts. */
export function minAmount(a: TokenAmount, b: TokenAmount): TokenAmount {
  assertBigInt(a, 'a');
  assertBigInt(b, 'b');
  return a < b ? a : b;
}

/** Larger of two amounts. */
export function maxAmount(a: TokenAmount, b: TokenAmount): TokenAmount {
  assertBigInt(a, 'a');
  assertBigInt(b, 'b');
  return a > b ? a : b;
}

/** Clamp an amount into [lower, upper]. */
export function clampAmount(amount: TokenAmount, lower: TokenAmount, upper: TokenAmount): TokenAmount {
  return minAmount(maxAmount(amount, lower), upper);
}

/**
 * Split `total` across `weights` so the parts sum EXACTLY to `total`.
 *
 * Floor division loses up to `weights.length - 1` base units; the dust is
 * handed to the heaviest weights (ties broken by index) so payouts are
 * deterministic and the escrow always empties to the last base unit.
 */
export function splitProportional(
  total: TokenAmount,
  weights: readonly TokenAmount[]
): TokenAmount[] {
  assertNonNegative(total, 'total');
  if (weights.length === 0) return [];

  let totalWeight = ZERO;
  for (const weight of weights) {
    totalWeight += assertNonNegative(weight, 'weight');
  }
  if (totalWeight === ZERO || total === ZERO) {
    return weights.map(() => ZERO);
  }

  const shares = weights.map(weight => (total * weight) / totalWeight);
  let remainder = total - shares.reduce((acc, share) => acc + share, ZERO);

  const eligible = weights
    .map((weight, index) => ({ weight, index }))
    .filter(entry => entry.weight > ZERO)
    .sort((a, b) => (a.weight === b.weight ? a.index - b.index : a.weight > b.weight ? -1 : 1))
    .map(entry => entry.index);

  for (let i = 0; remainder > ZERO && eligible.length > 0; i++) {
    shares[eligible[i % eligible.length]] += 1n;
    remainder -= 1n;
  }

  return shares;
}
