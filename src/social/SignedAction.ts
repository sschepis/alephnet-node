/**
 * SignedAction — the authentication primitive for the whole social layer
 *
 * Every mutation in `src/social` is expressed as a signed envelope:
 *
 *   { action, payload, authorPub, authorFingerprint, timestamp, nonce, signature }
 *
 * Verification is deliberately strict, and each check closes a hole that the
 * legacy `lib/` implementation left open:
 *
 *   1. Ed25519 signature over a canonical serialization of
 *      action + payload + timestamp + nonce (legacy: most mutations were
 *      unauthenticated entirely).
 *   2. The claimed fingerprint is *recomputed* from the verified public key and
 *      compared (legacy: fingerprints and keys were never bound, so any caller
 *      could claim any identity — including `'system'`).
 *   3. Freshness window on `timestamp` (legacy: no notion of freshness).
 *   4. Replay rejection via an injectable nonce store (legacy: a captured
 *      request could be replayed forever).
 *
 * The verified author is the ONLY source of actor identity downstream. No
 * social module may read an actor id out of a payload.
 */

import {
  KeyTriplet,
  base64ToBuffer,
  randomBytes,
  reconstructKeyTriplet,
  sha256Hex,
  signToBase64,
  verifyFromBase64
} from '../common/crypto';
import type { SocialStore } from './SocialStore';
import { getRecord, storeKey } from './SocialStore';
import {
  Base64,
  Fingerprint,
  SocialError,
  Timestamp,
  isFingerprint,
  systemClock,
  type SocialClock
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// ENVELOPE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A signed action envelope. Treat every field as untrusted until
 * `ActionVerifier.verify` has returned.
 */
export interface SignedAction<P = unknown> {
  /** Namespaced action name, e.g. `group.post.create`. */
  action: string;
  /** Action arguments. MUST NOT carry an actor id — the author is the actor. */
  payload: P;
  /** Author's raw Ed25519 public key, base64 (32 bytes decoded). */
  authorPub: Base64;
  /** Author's claimed fingerprint. Verified against `authorPub`. */
  authorFingerprint: Fingerprint;
  /** Milliseconds since epoch, checked against the freshness window. */
  timestamp: Timestamp;
  /** Single-use random value; replay protection. */
  nonce: string;
  /** Base64 Ed25519 signature over the canonical serialization. */
  signature: Base64;
}

/** The verified actor extracted from an envelope. */
export interface VerifiedAuthor {
  /** Verified raw Ed25519 public key, base64. */
  pub: Base64;
  /** Fingerprint recomputed from `pub` — safe to use as an identity. */
  fingerprint: Fingerprint;
}

/** A verified envelope: author is bound to the key that signed the payload. */
export interface VerifiedAction<P> {
  action: string;
  payload: P;
  author: VerifiedAuthor;
  timestamp: Timestamp;
  nonce: string;
  signature: Base64;
}

/** Machine-readable verification failure codes. */
export type SignedActionFailure =
  | 'malformed_envelope'
  | 'action_mismatch'
  | 'timestamp_out_of_window'
  | 'invalid_public_key'
  | 'invalid_signature'
  | 'fingerprint_mismatch'
  | 'replayed_nonce';

/** Raised by `ActionVerifier.verify`. */
export class SignedActionError extends SocialError {
  constructor(code: SignedActionFailure, message: string, details?: Record<string, unknown>) {
    super(code, message, details);
  }
}

/** Non-throwing verification result. */
export type VerifyResult<P> =
  | { valid: true; verified: VerifiedAction<P> }
  | { valid: false; code: SignedActionFailure; error: string };

// ═══════════════════════════════════════════════════════════════════════════
// CANONICAL SERIALIZATION
// ═══════════════════════════════════════════════════════════════════════════

/** Domain separator: signatures are valid only for this layer and version. */
export const SIGNED_ACTION_DOMAIN = 'alephnet.social.signed-action.v1';

/** Recursively sort object keys so serialization is deterministic. */
function sortKeysDeep(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value instanceof Date) return value.toISOString();
  // Binary payloads must serialize deterministically: JSON.stringify would
  // otherwise collapse every Buffer to `{}`, letting two different buffers
  // share one canonical form (a signature ambiguity).
  if (Buffer.isBuffer(value)) return { type: 'Buffer', data: Array.from(value) };
  if (ArrayBuffer.isView(value)) {
    return Array.from(value as unknown as ArrayLike<number>);
  }
  if (typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort()) {
      if (source[key] === undefined) continue;
      sorted[key] = sortKeysDeep(source[key]);
    }
    return sorted;
  }
  if (typeof value === 'bigint') return value.toString();
  return value;
}

/**
 * The exact bytes that get signed. Includes the domain separator so a
 * signature can never be lifted into another protocol.
 */
export function canonicalActionString(
  action: string,
  payload: unknown,
  timestamp: Timestamp,
  nonce: string
): string {
  const canonical = JSON.stringify({
    action,
    nonce,
    payload: sortKeysDeep(payload),
    timestamp
  });
  return `${SIGNED_ACTION_DOMAIN}\n${canonical}`;
}

/** Stable digest of an envelope's signed content (handy for derived ids). */
export function actionDigest(envelope: SignedAction<unknown>): string {
  return sha256Hex(
    canonicalActionString(
      envelope.action,
      envelope.payload,
      envelope.timestamp,
      envelope.nonce
    ) + `\n${envelope.signature}`
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// FINGERPRINT BINDING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Derive the canonical AlephNet fingerprint from a raw Ed25519 public key.
 *
 * Uses the same derivation as `generateKeyTriplet` (resonance field + SHA-256)
 * so a fingerprint from `KeyTriplet` always matches. This is the function that
 * *binds* a claimed fingerprint to a verified key.
 */
export function fingerprintFromPublicKey(publicKeyBase64: Base64): Fingerprint {
  return reconstructKeyTriplet(publicKeyBase64).fingerprint;
}

/** Raw public keys are 32 bytes for Ed25519. */
const ED25519_PUBLIC_KEY_BYTES = 32;

function decodePublicKey(publicKeyBase64: unknown): Buffer | null {
  if (typeof publicKeyBase64 !== 'string' || publicKeyBase64.length === 0) return null;
  let decoded: Buffer;
  try {
    decoded = base64ToBuffer(publicKeyBase64);
  } catch {
    return null;
  }
  if (decoded.length !== ED25519_PUBLIC_KEY_BYTES) return null;
  // Reject non-canonical base64 (which would let one key have many spellings).
  if (decoded.toString('base64') !== publicKeyBase64) return null;
  return decoded;
}

// ═══════════════════════════════════════════════════════════════════════════
// NONCE STORE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Replay protection backend. `claim` must be atomic: it records the nonce and
 * reports whether it was new.
 */
export interface NonceStore {
  /** Returns false when the nonce was already used (i.e. this is a replay). */
  claim(key: string, expiresAt: Timestamp): Promise<boolean>;
}

/** Process-local nonce store with lazy expiry pruning. */
export class MemoryNonceStore implements NonceStore {
  private readonly seen = new Map<string, Timestamp>();

  constructor(private readonly clock: SocialClock = systemClock) {}

  async claim(key: string, expiresAt: Timestamp): Promise<boolean> {
    const now = this.clock();
    this.prune(now);
    const existing = this.seen.get(key);
    if (existing !== undefined && existing > now) return false;
    this.seen.set(key, expiresAt);
    return true;
  }

  private prune(now: Timestamp): void {
    for (const [key, expiry] of this.seen) {
      if (expiry <= now) this.seen.delete(key);
    }
  }

  get size(): number {
    return this.seen.size;
  }
}

/**
 * Nonce store backed by a `SocialStore`, so replay protection survives
 * restarts.
 *
 * `claim` is atomic WITHIN a single process: claims for the same key are
 * serialized through an in-process mutex, so two concurrent claims of one
 * nonce can never both succeed.
 *
 * Multi-process boundary (honest statement): the mutex is process-local.
 * Two processes sharing one store (e.g. two nodes on one filesystem) need a
 * backend with an atomic compare-and-set — a plain `FileSocialStore` cannot
 * provide that across processes. Run a single writer per store, or pair this
 * with a CAS-capable backend, if cross-process safety matters.
 */
export class StoreBackedNonceStore implements NonceStore {
  /** Per-key promise chains implementing an in-process mutex. */
  private static readonly chains = new Map<string, Promise<unknown>>();

  constructor(
    private readonly store: SocialStore,
    private readonly prefix = 'nonce',
    private readonly clock: SocialClock = systemClock
  ) {}

  async claim(key: string, expiresAt: Timestamp): Promise<boolean> {
    const recordKey = storeKey(this.prefix, sha256Hex(key));
    return this.withLock(recordKey, async () => {
      const existing = await getRecord<{ expiresAt: Timestamp }>(this.store, recordKey);
      if (existing && existing.expiresAt > this.clock()) return false;
      await this.store.put(recordKey, { expiresAt });
      return true;
    });
  }

  /**
   * Run `fn` while holding an in-process mutex for `key`. The mutex is a
   * promise tail-chain: each holder runs only after the previous one settles,
   * so read-then-write sequences on the same key never interleave.
   */
  private withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = StoreBackedNonceStore.chains.get(key) ?? Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.then(
      () => undefined,
      () => undefined
    );
    StoreBackedNonceStore.chains.set(key, tail);
    void tail.then(() => {
      if (StoreBackedNonceStore.chains.get(key) === tail) {
        StoreBackedNonceStore.chains.delete(key);
      }
    });
    return run;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// SIGNING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Anything able to produce signatures for an identity. `Identity` implements
 * this; `keyTripletSigner` adapts a bare `KeyTriplet`.
 */
export interface ActionSigner {
  readonly publicKeyBase64: Base64;
  readonly fingerprint: Fingerprint;
  sign(data: string | Buffer): Base64;
}

/** Adapt a raw `KeyTriplet` (with private key) into an `ActionSigner`. */
export function keyTripletSigner(triplet: KeyTriplet): ActionSigner {
  const priv = base64ToBuffer(triplet.priv);
  return {
    publicKeyBase64: triplet.pub,
    fingerprint: triplet.fingerprint,
    sign: (data: string | Buffer): Base64 => signToBase64(data, priv)
  };
}

/** Fresh nonce (128 bits of randomness, hex encoded). */
export function createNonce(): string {
  return randomBytes(16).toString('hex');
}

export interface SignActionOptions {
  timestamp?: Timestamp;
  nonce?: string;
  clock?: SocialClock;
}

/**
 * Build a signed envelope. The author fields are taken from the signer, never
 * from the payload.
 */
export function signAction<P>(
  action: string,
  payload: P,
  signer: ActionSigner,
  options: SignActionOptions = {}
): SignedAction<P> {
  if (typeof action !== 'string' || action.length === 0) {
    throw new SignedActionError('malformed_envelope', 'action must be a non-empty string');
  }
  const timestamp = options.timestamp ?? (options.clock ?? systemClock)();
  const nonce = options.nonce ?? createNonce();
  const signature = signer.sign(canonicalActionString(action, payload, timestamp, nonce));

  return {
    action,
    payload,
    authorPub: signer.publicKeyBase64,
    authorFingerprint: signer.fingerprint,
    timestamp,
    nonce,
    signature
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════

export interface ActionVerifierOptions {
  /** Replay protection. Defaults to a process-local `MemoryNonceStore`. */
  nonceStore?: NonceStore;
  /** How far in the past a timestamp may be. Default 5 minutes. */
  maxAgeMs?: number;
  /** How far in the future a timestamp may be (clock skew). Default 60s. */
  maxFutureMs?: number;
  /** Injectable clock. */
  clock?: SocialClock;
}

/** Default freshness window. */
export const DEFAULT_MAX_AGE_MS = 5 * 60 * 1000;
export const DEFAULT_MAX_FUTURE_MS = 60 * 1000;

/**
 * Verifies signed actions. One instance is shared by every social component so
 * the freshness window and nonce store are consistent across the layer.
 */
export class ActionVerifier {
  private readonly nonceStore: NonceStore;
  private readonly maxAgeMs: number;
  private readonly maxFutureMs: number;
  private readonly clock: SocialClock;

  constructor(options: ActionVerifierOptions = {}) {
    this.clock = options.clock ?? systemClock;
    this.nonceStore = options.nonceStore ?? new MemoryNonceStore(this.clock);
    this.maxAgeMs = options.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
    this.maxFutureMs = options.maxFutureMs ?? DEFAULT_MAX_FUTURE_MS;
  }

  /**
   * Verify an envelope, returning a machine-readable result instead of
   * throwing. Checks run cheapest-first, and the nonce is only consumed once
   * everything else has passed — a failed verification never burns a nonce.
   */
  async check<P>(
    envelope: SignedAction<P>,
    expectedAction?: string | readonly string[]
  ): Promise<VerifyResult<P>> {
    const structural = validateStructure(envelope);
    if (structural) return fail(structural.code, structural.error);

    if (expectedAction !== undefined) {
      const allowed = typeof expectedAction === 'string' ? [expectedAction] : expectedAction;
      if (!allowed.includes(envelope.action)) {
        return fail(
          'action_mismatch',
          `Expected action ${allowed.join('|')} but envelope declares ${envelope.action}`
        );
      }
    }

    const now = this.clock();
    const age = now - envelope.timestamp;
    if (age > this.maxAgeMs) {
      return fail(
        'timestamp_out_of_window',
        `Envelope is stale: ${age}ms old, limit ${this.maxAgeMs}ms`
      );
    }
    if (age < -this.maxFutureMs) {
      return fail(
        'timestamp_out_of_window',
        `Envelope timestamp is ${-age}ms in the future, limit ${this.maxFutureMs}ms`
      );
    }

    const publicKey = decodePublicKey(envelope.authorPub);
    if (!publicKey) {
      return fail('invalid_public_key', 'authorPub is not a canonical 32-byte Ed25519 key');
    }

    const signed = canonicalActionString(
      envelope.action,
      envelope.payload,
      envelope.timestamp,
      envelope.nonce
    );

    let signatureValid = false;
    try {
      signatureValid = verifyFromBase64(signed, envelope.signature, publicKey);
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) {
      return fail('invalid_signature', 'Signature does not match action/payload/timestamp/nonce');
    }

    // Bind the claimed fingerprint to the key that actually signed. Without
    // this an attacker could sign with their own key while claiming to be
    // someone else — exactly the legacy impersonation path.
    const derived = fingerprintFromPublicKey(envelope.authorPub);
    if (derived !== envelope.authorFingerprint) {
      return fail(
        'fingerprint_mismatch',
        'authorFingerprint does not match the fingerprint derived from authorPub'
      );
    }

    const nonceKey = `${derived}:${envelope.nonce}`;
    const claimed = await this.nonceStore.claim(nonceKey, envelope.timestamp + this.maxAgeMs);
    if (!claimed) {
      return fail('replayed_nonce', 'Nonce has already been used by this author');
    }

    return {
      valid: true,
      verified: {
        action: envelope.action,
        payload: envelope.payload,
        author: { pub: envelope.authorPub, fingerprint: derived },
        timestamp: envelope.timestamp,
        nonce: envelope.nonce,
        signature: envelope.signature
      }
    };
  }

  /** Verify an envelope, throwing `SignedActionError` on any failure. */
  async verify<P>(
    envelope: SignedAction<P>,
    expectedAction?: string | readonly string[]
  ): Promise<VerifiedAction<P>> {
    const result = await this.check(envelope, expectedAction);
    if (!result.valid) {
      throw new SignedActionError(result.code, result.error, { action: envelope?.action });
    }
    return result.verified;
  }

  now(): Timestamp {
    return this.clock();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// STRUCTURAL VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

interface StructuralFailure {
  code: SignedActionFailure;
  error: string;
}

function validateStructure(envelope: unknown): StructuralFailure | null {
  if (typeof envelope !== 'object' || envelope === null) {
    return { code: 'malformed_envelope', error: 'Envelope must be an object' };
  }
  const e = envelope as Record<string, unknown>;

  if (typeof e.action !== 'string' || e.action.length === 0 || e.action.length > 128) {
    return { code: 'malformed_envelope', error: 'action must be a string of 1..128 chars' };
  }
  if (!('payload' in e)) {
    return { code: 'malformed_envelope', error: 'payload is required' };
  }
  if (typeof e.authorPub !== 'string' || e.authorPub.length === 0) {
    return { code: 'malformed_envelope', error: 'authorPub must be a base64 string' };
  }
  if (!isFingerprint(e.authorFingerprint)) {
    return {
      code: 'malformed_envelope',
      error: 'authorFingerprint must be 16 lowercase hex characters'
    };
  }
  if (typeof e.timestamp !== 'number' || !Number.isFinite(e.timestamp) || e.timestamp <= 0) {
    return { code: 'malformed_envelope', error: 'timestamp must be a positive finite number' };
  }
  if (typeof e.nonce !== 'string' || e.nonce.length < 8 || e.nonce.length > 128) {
    return { code: 'malformed_envelope', error: 'nonce must be a string of 8..128 chars' };
  }
  if (typeof e.signature !== 'string' || e.signature.length === 0) {
    return { code: 'malformed_envelope', error: 'signature must be a base64 string' };
  }
  return null;
}

function fail<P>(code: SignedActionFailure, error: string): VerifyResult<P> {
  return { valid: false, code, error };
}

// ═══════════════════════════════════════════════════════════════════════════
// PAYLOAD HYGIENE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Field names that would let a caller *claim* an actor identity. The legacy
 * layer read `authorId` out of the request body, so `authorId: 'system'`
 * bypassed membership checks. Payloads carrying any of these are rejected
 * outright rather than silently ignored, so impersonation attempts fail loudly.
 */
export const IMPERSONATION_FIELDS: readonly string[] = [
  'authorId',
  'author',
  'authorFingerprint',
  'authorPub',
  'from',
  'fromId',
  'ownerId',
  'owner',
  'requesterId',
  'nodeId',
  'userId',
  'senderId',
  'sender',
  'actor',
  'actorId'
];

/** Raised when a payload tries to declare its own actor. */
export class ImpersonationError extends SocialError {
  constructor(field: string, action: string) {
    super(
      'impersonation_attempt',
      `Payload for '${action}' may not declare '${field}': the actor is derived from the signature`,
      { field, action }
    );
  }
}

/**
 * Reject payloads that try to name their own actor. Call this on every
 * mutation payload before using it.
 */
export function assertNoImpersonation(action: string, payload: unknown): void {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return;
  for (const field of IMPERSONATION_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(payload, field)) {
      throw new ImpersonationError(field, action);
    }
  }
}
