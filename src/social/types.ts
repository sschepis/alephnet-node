/**
 * Social Layer — Shared Types
 *
 * Foundational types for the AlephNet social/identity layer. Everything in
 * `src/social` speaks in terms of *verified fingerprints*, never in terms of
 * caller-supplied user ids.
 *
 * The legacy `lib/` implementation accepted `authorId`/`requesterId` strings
 * straight from the caller, which allowed impersonation and access-control
 * bypass. In this port every mutating operation takes a `SignedAction`
 * envelope and derives the actor from the verified Ed25519 public key, and
 * every read takes an explicit requester fingerprint (no defaulting to the
 * store owner).
 */

import type { Base64, HexString, Timestamp } from '../common/types';

// ═══════════════════════════════════════════════════════════════════════════
// IDENTIFIERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A 16-character lowercase hex fingerprint derived from an Ed25519 public key
 * plus its resonance field (see `fingerprintFromPublicKey`).
 *
 * A fingerprint is only trustworthy when it has been *bound* to a verified
 * public key. Never accept one directly from untrusted input.
 */
export type Fingerprint = string;

/** SHA-256 content address: exactly 64 lowercase hex characters. */
export type ContentHash = HexString;

/** Matches a valid fingerprint (16 lowercase hex chars). */
export const FINGERPRINT_PATTERN = /^[0-9a-f]{16}$/;

/** Matches a valid content hash (64 lowercase hex chars). */
export const CONTENT_HASH_PATTERN = /^[0-9a-f]{64}$/;

/** Type guard for fingerprints. */
export function isFingerprint(value: unknown): value is Fingerprint {
  return typeof value === 'string' && FINGERPRINT_PATTERN.test(value);
}

/** Type guard for content hashes. */
export function isContentHash(value: unknown): value is ContentHash {
  return typeof value === 'string' && CONTENT_HASH_PATTERN.test(value);
}

// ═══════════════════════════════════════════════════════════════════════════
// VISIBILITY
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Visibility of a piece of content or profile field.
 *
 *   PUBLIC   — anyone may read
 *   FRIENDS  — only confirmed friends of the owner may read
 *   PRIVATE  — only the owner may read
 *   UNLISTED — readable by anyone holding the address, never enumerated
 */
export type Visibility = 'PUBLIC' | 'FRIENDS' | 'PRIVATE' | 'UNLISTED';

/** All visibility levels, ordered from most to least open. */
export const VISIBILITY_LEVELS: readonly Visibility[] = [
  'PUBLIC',
  'UNLISTED',
  'FRIENDS',
  'PRIVATE'
];

/** Type guard for visibility values. */
export function isVisibility(value: unknown): value is Visibility {
  return typeof value === 'string' && (VISIBILITY_LEVELS as readonly string[]).includes(value);
}

/**
 * Normalize a visibility value, accepting the lowercase spellings used by the
 * legacy JS layer (`'public'`, `'friends'`, ...). Unknown values fail closed
 * to `PRIVATE`.
 */
export function normalizeVisibility(value: unknown): Visibility {
  if (typeof value !== 'string') return 'PRIVATE';
  const upper = value.toUpperCase();
  return isVisibility(upper) ? upper : 'PRIVATE';
}

// ═══════════════════════════════════════════════════════════════════════════
// FRIENDSHIP ORACLE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The minimum contract the rest of the social layer needs from the friend
 * graph. `FriendGraph` implements this; tests and alternative backends can
 * supply their own.
 */
export interface FriendshipOracle {
  /** Whether `a` and `b` have a confirmed (signed) friendship. */
  areFriends(a: Fingerprint, b: Fingerprint): Promise<boolean>;
  /** Fingerprints `owner` has blocked, if the backend tracks blocking. */
  isBlocked?(owner: Fingerprint, target: Fingerprint): Promise<boolean>;
}

// ═══════════════════════════════════════════════════════════════════════════
// COMMON OPTION SHAPES
// ═══════════════════════════════════════════════════════════════════════════

/** Standard pagination options. */
export interface PageOptions {
  limit?: number;
  offset?: number;
}

/** A monotonic-ish clock, injectable so tests can control time. */
export type SocialClock = () => Timestamp;

/** Default clock. */
export const systemClock: SocialClock = () => Date.now();

/** Reference to media stored in the content store. */
export interface MediaRef {
  type: string;
  hash: ContentHash;
  mimeType?: string;
  metadata?: Record<string, unknown>;
}

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Base error for the social layer. Always carries a stable machine-readable
 * `code` so callers can branch without string matching on messages.
 */
export class SocialError extends Error {
  readonly code: string;
  readonly details?: Record<string, unknown>;

  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
    if (Error.captureStackTrace) Error.captureStackTrace(this, new.target);
  }
}

/** Raised when a caller is authenticated but not authorized. */
export class AccessDeniedError extends SocialError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('access_denied', message, details);
  }
}

/** Raised when input fails structural validation. */
export class ValidationError extends SocialError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('invalid_input', message, details);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Assert a value is a syntactically valid content hash.
 *
 * SECURITY: the legacy content store built filesystem paths directly from an
 * attacker-controlled `hash`, so `'../../etc/passwd'` escaped the blob
 * directory. Every hash MUST pass through here before it is used in a key or
 * path.
 */
export function assertContentHash(hash: unknown, label = 'hash'): ContentHash {
  if (!isContentHash(hash)) {
    throw new ValidationError(
      `Invalid ${label}: expected exactly 64 lowercase hex characters`,
      { received: typeof hash === 'string' ? hash.slice(0, 80) : typeof hash }
    );
  }
  return hash;
}

/**
 * Assert a value is a syntactically valid fingerprint. Used before any key or
 * path construction for the same traversal reason as `assertContentHash`.
 */
export function assertFingerprint(value: unknown, label = 'fingerprint'): Fingerprint {
  if (!isFingerprint(value)) {
    throw new ValidationError(
      `Invalid ${label}: expected exactly 16 lowercase hex characters`,
      { received: typeof value === 'string' ? value.slice(0, 80) : typeof value }
    );
  }
  return value;
}

/** Assert a non-empty string, trimming and enforcing a maximum length. */
export function assertText(
  value: unknown,
  label: string,
  maxLength: number,
  { allowEmpty = false }: { allowEmpty?: boolean } = {}
): string {
  if (typeof value !== 'string') {
    throw new ValidationError(`${label} must be a string`, { received: typeof value });
  }
  const trimmed = value.trim();
  if (!allowEmpty && trimmed.length === 0) {
    throw new ValidationError(`${label} must not be empty`);
  }
  if (value.length > maxLength) {
    throw new ValidationError(`${label} exceeds maximum length of ${maxLength}`, {
      length: value.length
    });
  }
  return trimmed;
}

/** Identifier pattern for generated ids (`grp_ab12...`, `msg_ab12...`). */
export const RECORD_ID_PATTERN = /^[a-z]{3,8}_[0-9a-f]{8,64}$/;

/**
 * Assert a record id is one we could have generated. Record ids are used as
 * storage key segments, so they are validated the same way hashes are.
 */
export function assertRecordId(value: unknown, label = 'id'): string {
  if (typeof value !== 'string' || !RECORD_ID_PATTERN.test(value)) {
    throw new ValidationError(`Invalid ${label}`, {
      received: typeof value === 'string' ? value.slice(0, 80) : typeof value
    });
  }
  return value;
}

// ═══════════════════════════════════════════════════════════════════════════
// RE-EXPORTED PRIMITIVE ALIASES
// ═══════════════════════════════════════════════════════════════════════════

export type { Base64, HexString, Timestamp };
