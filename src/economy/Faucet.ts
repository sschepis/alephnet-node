/**
 * Resonance Faucet
 *
 * Issues a signed challenge, then pays a FIXED drip out of a FINITE treasury
 * to whoever proves work over that challenge and signs the result with the
 * Ed25519 key the challenge was issued to.
 *
 * Legacy bugs closed here (lib/actions/faucet.js, lib/wallet.js):
 *  - `wallet.claimFaucet(amount = 100)` credited a CALLER-SUPPLIED amount with
 *    no cap: unlimited mint. The drip is now server-defined
 *    ({@link FaucetConfig.dripAmount}) and {@link FaucetClaimRequest} has no
 *    amount field at all.
 *  - the faucet self-minted `this.treasury.balance = 1000000000`. Funds now
 *    come from a real wallet and are additionally capped by
 *    {@link FaucetConfig.treasuryCap}; the faucet can never mint.
 *  - step "6. Verify Identity Signature" was a comment followed by no code,
 *    and `verifyChallenge()` was dead code keyed on a hardcoded
 *    `'faucet-secret-salt'`. The HMAC secret is now injected (never
 *    hardcoded) and is actually verified, and the claim signature is really
 *    checked with Ed25519.
 *  - the cooldown was keyed on a client-supplied `fingerprint`, so rotating
 *    that string bypassed the limit. The cooldown key is now derived from the
 *    public key whose signature was just verified.
 *  - proof of work was `parseInt(hash.slice(-4), 16) % smallPrime === 0`
 *    (~2-4 bits). It is now a configurable leading-zero-bit target.
 */

import { hmacSha256, randomBytes, reconstructKeyTriplet, sha256Hex, verifyFromBase64 } from '../common/crypto';
import { Base64, Timestamp } from '../common/types';
import type { EconomyWallet } from './WalletPort';
import { TokenAmount, ZERO, assertPositive, formatAleph, safeAdd, safeSub, wholeTokens } from './units';

// ═══════════════════════════════════════════════════════════════════════════
// PROTOCOL CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/** Challenge envelope version. */
export const CHALLENGE_VERSION = 'af1';

/** Domain separator for the claim signature. */
export const CLAIM_DOMAIN = 'alephnet-faucet-claim.v1';

/** Minimum acceptable length of the injected HMAC secret. */
export const MIN_SECRET_BYTES = 32;

/** Raw Ed25519 public keys are 32 bytes. */
const ED25519_PUBLIC_KEY_BYTES = 32;

/** Upper bound on a submitted PoW nonce, to bound hashing work. */
const MAX_NONCE_LENGTH = 128;

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface FaucetConfig {
  /** Fixed amount paid per successful claim, in base units. Callers cannot change it. */
  dripAmount: TokenAmount;
  /** Lifetime ceiling on everything this faucet may ever pay out. */
  treasuryCap: TokenAmount;
  /** Per-fingerprint cooldown between claims. */
  cooldownMs: number;
  /** Challenge lifetime. */
  challengeTtlMs: number;
  /** Required leading zero BITS in the PoW hash. */
  difficultyBits: number;
  /** Rolling-window outflow ceiling. */
  windowOutflowCap: TokenAmount;
  /** Length of the outflow window. */
  windowMs: number;
}

export const DEFAULT_FAUCET_CONFIG: FaucetConfig = {
  dripAmount: wholeTokens(10),
  treasuryCap: wholeTokens(1_000_000),
  cooldownMs: 72 * 60 * 60 * 1000,
  challengeTtlMs: 5 * 60 * 1000,
  difficultyBits: 20,
  windowOutflowCap: wholeTokens(1_000),
  windowMs: 60 * 60 * 1000
};

export interface FaucetOptions extends Partial<FaucetConfig> {
  /**
   * HMAC secret for challenge authenticity. REQUIRED and injected — there is
   * deliberately no default and no hardcoded fallback.
   */
  secret: Buffer;
  /** Wallet the drip is paid from. Its balance is the hard funding limit. */
  treasury: EconomyWallet;
  /** Injected clock, for deterministic tests. */
  now?: () => Timestamp;
}

/** What a client receives from {@link Faucet.issueChallenge}. */
export interface FaucetChallenge {
  /** Opaque, HMAC-authenticated challenge string. */
  challenge: string;
  /** Required leading zero bits. */
  difficulty: number;
  issuedAt: Timestamp;
  expiresAt: Timestamp;
  /** Fingerprint the challenge is bound to (derived server-side from `pub`). */
  fingerprint: string;
}

/**
 * A claim submission.
 *
 * Note what is absent: no amount (the drip is fixed) and no fingerprint
 * (it is derived from `pub` after the signature verifies).
 */
export interface FaucetClaimRequest {
  challenge: string;
  nonce: string;
  /** Base64 Ed25519 signature over `CLAIM_DOMAIN|challenge|nonce`. */
  signature: Base64;
  /** Base64 raw 32-byte Ed25519 public key. */
  pub: Base64;
}

export interface FaucetClaimResult {
  success: true;
  /** Always exactly `config.dripAmount`. */
  amount: TokenAmount;
  /** Verified fingerprint, derived from the signing key. */
  fingerprint: string;
  transactionId: string;
  claimedAt: Timestamp;
  nextClaimAt: Timestamp;
  treasuryRemaining: TokenAmount;
}

export interface FaucetStats {
  dispensed: TokenAmount;
  treasuryCap: TokenAmount;
  treasuryRemaining: TokenAmount;
  dripAmount: TokenAmount;
  difficultyBits: number;
  claimants: number;
  windowOutflow: TokenAmount;
  windowResetsAt: Timestamp;
}

/** Decoded challenge envelope. */
interface DecodedChallenge {
  salt: string;
  fingerprint: string;
  difficulty: number;
  issuedAt: Timestamp;
  expiresAt: Timestamp;
}

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

export type FaucetErrorCode =
  | 'MISCONFIGURED'
  | 'BAD_REQUEST'
  | 'INVALID_PUBLIC_KEY'
  | 'CHALLENGE_MALFORMED'
  | 'CHALLENGE_FORGED'
  | 'CHALLENGE_EXPIRED'
  | 'CHALLENGE_NOT_YET_VALID'
  | 'CHALLENGE_CONSUMED'
  | 'CHALLENGE_KEY_MISMATCH'
  | 'POW_INSUFFICIENT'
  | 'SIGNATURE_INVALID'
  | 'COOLDOWN_ACTIVE'
  | 'TREASURY_EXHAUSTED'
  | 'RATE_LIMITED'
  | 'TRANSFER_FAILED';

export class FaucetError extends Error {
  public readonly code: FaucetErrorCode;

  constructor(code: FaucetErrorCode, message: string) {
    super(message);
    this.name = 'FaucetError';
    this.code = code;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// PROOF OF WORK
// ═══════════════════════════════════════════════════════════════════════════

/** The exact preimage a client must grind. */
export function powPreimage(challenge: string, nonce: string): string {
  return `${challenge}|${nonce}`;
}

/** PoW hash of a challenge/nonce pair. */
export function powHash(challenge: string, nonce: string): string {
  return sha256Hex(powPreimage(challenge, nonce));
}

/** Count leading zero bits of a hex digest. */
export function countLeadingZeroBits(hashHex: string): number {
  let bits = 0;
  for (let i = 0; i < hashHex.length; i++) {
    const nibble = parseInt(hashHex[i], 16);
    if (Number.isNaN(nibble)) return bits;
    if (nibble === 0) {
      bits += 4;
      continue;
    }
    if (nibble < 2) return bits + 3;
    if (nibble < 4) return bits + 2;
    if (nibble < 8) return bits + 1;
    return bits;
  }
  return bits;
}

/** True when the digest meets the leading-zero-bit target. */
export function meetsDifficulty(hashHex: string, difficultyBits: number): boolean {
  return countLeadingZeroBits(hashHex) >= difficultyBits;
}

/** Client-side helper: grind a nonce satisfying the challenge difficulty. */
export function solveFaucetChallenge(
  challenge: string,
  difficultyBits: number,
  maxAttempts = 50_000_000
): { nonce: string; hash: string; attempts: number } {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const nonce = attempt.toString(36);
    const hash = powHash(challenge, nonce);
    if (meetsDifficulty(hash, difficultyBits)) {
      return { nonce, hash, attempts: attempt + 1 };
    }
  }
  throw new FaucetError(
    'POW_INSUFFICIENT',
    `no nonce found for ${difficultyBits}-bit difficulty within ${maxAttempts} attempts`
  );
}

/** The message a claimant signs. */
export function claimMessage(challenge: string, nonce: string): string {
  return `${CLAIM_DOMAIN}|${challenge}|${nonce}`;
}

/** Length-safe, non-short-circuiting string comparison for MAC checks. */
function constantTimeEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// FAUCET
// ═══════════════════════════════════════════════════════════════════════════

export class Faucet {
  public readonly config: FaucetConfig;

  private readonly secret: Buffer;
  private readonly treasury: EconomyWallet;
  private readonly now: () => Timestamp;

  /** Cooldown keyed on the VERIFIED fingerprint, never on client input. */
  private readonly lastClaimAt = new Map<string, Timestamp>();
  /** Consumed challenge salts, for replay protection. */
  private readonly consumed = new Map<string, Timestamp>();

  private dispensed: TokenAmount = ZERO;
  private windowOutflow: TokenAmount = ZERO;
  private windowStart: Timestamp;

  constructor(options: FaucetOptions) {
    const { secret, treasury, now, ...overrides } = options;

    if (!treasury || typeof treasury.transfer !== 'function') {
      throw new FaucetError('MISCONFIGURED', 'faucet requires a funded treasury wallet');
    }
    if (!Buffer.isBuffer(secret) || secret.length < MIN_SECRET_BYTES) {
      throw new FaucetError(
        'MISCONFIGURED',
        `faucet requires an injected secret Buffer of at least ${MIN_SECRET_BYTES} bytes ` +
          `(none is hardcoded)`
      );
    }

    const config: FaucetConfig = { ...DEFAULT_FAUCET_CONFIG, ...overrides };
    assertPositive(config.dripAmount, 'dripAmount');
    assertPositive(config.treasuryCap, 'treasuryCap');
    assertPositive(config.windowOutflowCap, 'windowOutflowCap');
    if (config.treasuryCap < config.dripAmount) {
      throw new FaucetError(
        'MISCONFIGURED',
        `treasuryCap ${formatAleph(config.treasuryCap)} is below one drip of ${formatAleph(config.dripAmount)}`
      );
    }
    if (!Number.isInteger(config.difficultyBits) || config.difficultyBits < 1 || config.difficultyBits > 64) {
      throw new FaucetError(
        'MISCONFIGURED',
        `difficultyBits must be an integer in [1, 64], received ${config.difficultyBits}`
      );
    }
    for (const key of ['cooldownMs', 'challengeTtlMs', 'windowMs'] as const) {
      if (!Number.isInteger(config[key]) || config[key] < 0) {
        throw new FaucetError('MISCONFIGURED', `${key} must be a non-negative integer`);
      }
    }

    this.config = config;
    this.secret = secret;
    this.treasury = treasury;
    this.now = now ?? (() => Date.now());
    this.windowStart = this.now();
  }

  // ─── Challenge issuance ─────────────────────────────────────────────────

  /**
   * Issue a challenge bound to `pub`.
   *
   * The envelope is authenticated with the injected secret, so the server
   * keeps no per-challenge state it must trust, and a client cannot edit the
   * difficulty, expiry or bound fingerprint.
   */
  public issueChallenge(pub: Base64): FaucetChallenge {
    const fingerprint = this.fingerprintOf(pub);
    const issuedAt = this.now();
    const expiresAt = issuedAt + this.config.challengeTtlMs;
    const salt = randomBytes(16).toString('hex');

    const payload = this.challengePayload({
      salt,
      fingerprint,
      difficulty: this.config.difficultyBits,
      issuedAt,
      expiresAt
    });

    return {
      challenge: `${payload}.${this.mac(payload)}`,
      difficulty: this.config.difficultyBits,
      issuedAt,
      expiresAt,
      fingerprint
    };
  }

  // ─── Claiming ───────────────────────────────────────────────────────────

  /**
   * Verify a claim and pay exactly one drip.
   *
   * Order matters: cheap structural checks, then MAC, then expiry, then
   * key binding, then PoW, then the Ed25519 signature, then the cooldown
   * (keyed on the now-verified fingerprint), then treasury limits.
   *
   * Every piece of state (consumed salts, cooldown, counters) is reserved
   * SYNCHRONOUSLY, before the first await: the whole verification pipeline
   * runs in one microtask, so two interleaved claims of the same challenge
   * both observe the reservation and the second one fails
   * CHALLENGE_CONSUMED instead of double-paying. If the transfer itself
   * fails the reservation is released, so the claimant can retry without
   * losing their drip.
   */
  public async claim(request: FaucetClaimRequest): Promise<FaucetClaimResult> {
    if (!request || typeof request.challenge !== 'string' || typeof request.nonce !== 'string') {
      throw new FaucetError('BAD_REQUEST', 'claim requires challenge, nonce, signature and pub');
    }
    if (typeof request.signature !== 'string' || request.signature.length === 0) {
      throw new FaucetError('SIGNATURE_INVALID', 'claim signature is missing');
    }
    if (request.nonce.length === 0 || request.nonce.length > MAX_NONCE_LENGTH) {
      throw new FaucetError('BAD_REQUEST', `nonce must be 1..${MAX_NONCE_LENGTH} characters`);
    }

    const decoded = this.decodeChallenge(request.challenge);
    const now = this.now();

    if (now > decoded.expiresAt) {
      throw new FaucetError('CHALLENGE_EXPIRED', 'challenge has expired; request a new one');
    }
    if (now < decoded.issuedAt) {
      throw new FaucetError(
        'CHALLENGE_NOT_YET_VALID',
        `challenge issuedAt ${decoded.issuedAt} is in the future (now ${now}); ` +
          `rejecting claims from ahead of the server clock`
      );
    }

    this.pruneConsumed(now);
    this.pruneCooldown(now);
    if (this.consumed.has(decoded.salt)) {
      throw new FaucetError('CHALLENGE_CONSUMED', 'challenge has already been used');
    }

    // The challenge is bound to a key: derive the fingerprint from the
    // submitted public key and require it to match the signed envelope.
    const fingerprint = this.fingerprintOf(request.pub);
    if (!constantTimeEquals(fingerprint, decoded.fingerprint)) {
      throw new FaucetError(
        'CHALLENGE_KEY_MISMATCH',
        'challenge was issued to a different public key'
      );
    }

    // Proof of work over the authenticated challenge.
    const hash = powHash(request.challenge, request.nonce);
    if (!meetsDifficulty(hash, decoded.difficulty)) {
      throw new FaucetError(
        'POW_INSUFFICIENT',
        `proof of work failed: hash ${hash.slice(0, 16)}… has ` +
          `${countLeadingZeroBits(hash)} leading zero bits, need ${decoded.difficulty}`
      );
    }

    // Real Ed25519 verification, binding this key to this challenge+nonce.
    if (!this.verifyClaimSignature(request)) {
      throw new FaucetError('SIGNATURE_INVALID', 'claim signature does not verify for the given key');
    }

    // Cooldown keyed on the VERIFIED fingerprint. Nothing the caller sends
    // can influence this key.
    const previous = this.lastClaimAt.get(fingerprint);
    if (previous !== undefined && now - previous < this.config.cooldownMs) {
      const waitMs = this.config.cooldownMs - (now - previous);
      throw new FaucetError(
        'COOLDOWN_ACTIVE',
        `cooldown active for ${fingerprint}: ${Math.ceil(waitMs / 1000)}s remaining`
      );
    }

    const amount = this.config.dripAmount;

    // Finite treasury: cumulative payouts can never exceed the cap.
    if (safeAdd(this.dispensed, amount, 'dispensed') > this.config.treasuryCap) {
      throw new FaucetError(
        'TREASURY_EXHAUSTED',
        `faucet treasury exhausted: ${formatAleph(this.remaining())} of ` +
          `${formatAleph(this.config.treasuryCap)} left, drip is ${formatAleph(amount)}`
      );
    }

    this.rollWindow(now);
    if (safeAdd(this.windowOutflow, amount, 'windowOutflow') > this.config.windowOutflowCap) {
      throw new FaucetError(
        'RATE_LIMITED',
        `faucet window cap of ${formatAleph(this.config.windowOutflowCap)} reached; retry later`
      );
    }

    // Reserve the claim BEFORE the first await. Everything above ran in one
    // microtask, so an interleaved claim of the same challenge sees this
    // reservation and rejects CHALLENGE_CONSUMED instead of paying twice.
    this.dispensed = safeAdd(this.dispensed, amount, 'dispensed');
    this.windowOutflow = safeAdd(this.windowOutflow, amount, 'windowOutflow');
    this.lastClaimAt.set(fingerprint, now);
    this.consumed.set(decoded.salt, decoded.expiresAt);

    let transactionId: string;
    try {
      const receipt = await this.treasury.transfer(fingerprint, amount, {
        purpose: 'FAUCET_CLAIM',
        memo: `faucet drip ${formatAleph(amount)}`
      });
      transactionId = receipt.transactionId;
    } catch (error) {
      // Release the reservation: no funds moved, so the claim must not
      // consume the challenge, the cooldown or any counter budget.
      this.consumed.delete(decoded.salt);
      this.lastClaimAt.delete(fingerprint);
      this.dispensed = safeSub(this.dispensed, amount, 'dispensed');
      this.windowOutflow = safeSub(this.windowOutflow, amount, 'windowOutflow');
      throw new FaucetError(
        'TRANSFER_FAILED',
        `treasury transfer failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }

    return {
      success: true,
      amount,
      fingerprint,
      transactionId,
      claimedAt: now,
      nextClaimAt: now + this.config.cooldownMs,
      treasuryRemaining: this.remaining()
    };
  }

  // ─── Introspection ──────────────────────────────────────────────────────

  /** Base units still payable under the configured cap. */
  public remaining(): TokenAmount {
    return safeSub(this.config.treasuryCap, this.dispensed, 'treasuryRemaining');
  }

  /** Milliseconds until `pub` may claim again (0 when eligible). */
  public cooldownRemaining(pub: Base64): number {
    const previous = this.lastClaimAt.get(this.fingerprintOf(pub));
    if (previous === undefined) return 0;
    const elapsed = this.now() - previous;
    return elapsed >= this.config.cooldownMs ? 0 : this.config.cooldownMs - elapsed;
  }

  public stats(): FaucetStats {
    return {
      dispensed: this.dispensed,
      treasuryCap: this.config.treasuryCap,
      treasuryRemaining: this.remaining(),
      dripAmount: this.config.dripAmount,
      difficultyBits: this.config.difficultyBits,
      claimants: this.lastClaimAt.size,
      windowOutflow: this.windowOutflow,
      windowResetsAt: this.windowStart + this.config.windowMs
    };
  }

  // ─── Internals ──────────────────────────────────────────────────────────

  /**
   * Canonical fingerprint of a public key.
   *
   * Uses the same derivation as KeyTriplet identities, so the credited
   * address equals the claimant's wallet address.
   */
  private fingerprintOf(pub: Base64): string {
    if (typeof pub !== 'string' || pub.length === 0) {
      throw new FaucetError('INVALID_PUBLIC_KEY', 'pub must be a base64 Ed25519 public key');
    }
    const decoded = Buffer.from(pub, 'base64');
    if (decoded.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new FaucetError(
        'INVALID_PUBLIC_KEY',
        `pub must decode to ${ED25519_PUBLIC_KEY_BYTES} raw bytes, got ${decoded.length}`
      );
    }
    return reconstructKeyTriplet(pub).fingerprint;
  }

  private verifyClaimSignature(request: FaucetClaimRequest): boolean {
    try {
      return verifyFromBase64(
        claimMessage(request.challenge, request.nonce),
        request.signature,
        Buffer.from(request.pub, 'base64')
      );
    } catch {
      // Malformed signature or key bytes: a failed verification, not a crash.
      return false;
    }
  }

  private challengePayload(parts: DecodedChallenge): string {
    return [
      CHALLENGE_VERSION,
      parts.salt,
      parts.fingerprint,
      String(parts.difficulty),
      String(parts.issuedAt),
      String(parts.expiresAt)
    ].join('.');
  }

  private mac(payload: string): string {
    return hmacSha256(this.secret, payload).toString('hex');
  }

  /** Decode and authenticate a challenge envelope. */
  private decodeChallenge(challenge: string): DecodedChallenge {
    const segments = challenge.split('.');
    if (segments.length !== 7 || segments[0] !== CHALLENGE_VERSION) {
      throw new FaucetError('CHALLENGE_MALFORMED', 'challenge envelope is malformed');
    }

    const [, salt, fingerprint, difficultyRaw, issuedAtRaw, expiresAtRaw, mac] = segments;
    const payload = segments.slice(0, 6).join('.');

    // Authenticity before interpretation: a tampered field cannot be trusted
    // even to be well-formed.
    if (!constantTimeEquals(this.mac(payload), mac)) {
      throw new FaucetError('CHALLENGE_FORGED', 'challenge authentication failed (bad or tampered MAC)');
    }

    const difficulty = Number(difficultyRaw);
    const issuedAt = Number(issuedAtRaw);
    const expiresAt = Number(expiresAtRaw);
    if (
      !Number.isInteger(difficulty) ||
      !Number.isInteger(issuedAt) ||
      !Number.isInteger(expiresAt) ||
      salt.length === 0 ||
      fingerprint.length === 0
    ) {
      throw new FaucetError('CHALLENGE_MALFORMED', 'challenge fields are not well-formed');
    }

    return { salt, fingerprint, difficulty, issuedAt, expiresAt };
  }

  private pruneConsumed(now: Timestamp): void {
    for (const [salt, expiresAt] of this.consumed) {
      if (now > expiresAt) this.consumed.delete(salt);
    }
  }

  /** Drop cooldown entries whose window has fully elapsed. */
  private pruneCooldown(now: Timestamp): void {
    for (const [fingerprint, claimedAt] of this.lastClaimAt) {
      if (now - claimedAt >= this.config.cooldownMs) this.lastClaimAt.delete(fingerprint);
    }
  }

  private rollWindow(now: Timestamp): void {
    if (now - this.windowStart >= this.config.windowMs) {
      this.windowStart = now;
      this.windowOutflow = ZERO;
    }
  }
}
