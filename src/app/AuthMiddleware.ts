/**
 * Signed Request Authentication
 *
 * Replaces the legacy `lib/auth-middleware.js`, which was forgeable: it accepted
 * any object whose `contentHash` matched sha256(content) without ever checking a
 * signature, fell back to `{ fingerprint }` as the "signer" when no public key
 * was supplied, never bound the verified key to the claimed fingerprint, signed
 * only `METHOD:PATH:TIMESTAMP` (leaving the body unauthenticated), had no nonce
 * store (so anything replayed freely for five minutes) and could be switched off
 * entirely by an ambient `ALEPH_DEV_NO_AUTH` environment variable.
 *
 * This implementation:
 *  - performs mandatory real Ed25519 verification via `verifyFromBase64`
 *  - signs METHOD, request target (path + query), TIMESTAMP, NONCE and a
 *    SHA-256 hash of the exact request body bytes
 *  - recomputes the fingerprint from the verified public key and rejects any
 *    mismatch with the claimed fingerprint
 *  - consumes single-use nonces from a bounded cache PARTITIONED per identity,
 *    so one identity's traffic can never evict another's nonces
 *  - reads no environment variable to enable a bypass
 */

import * as crypto from 'crypto';
import { verifyFromBase64, sha256Hex, reconstructKeyTriplet, randomBytes, signToBase64 } from '../common/crypto';
import { ERROR_CODES } from '../common/constants';
import { createLogger, Logger } from '../common/logging';
import { Result, ok, err } from '../common/patterns/Result';
import {
  AUTH_HEADERS,
  AuthConfig,
  AuthConfigInput,
  AuthenticatedIdentity,
  DEV_BYPASS_ACKNOWLEDGEMENT,
  DEFAULT_NONCE_CACHE_CONFIG,
  DEFAULT_RATE_LIMITER_CONFIG,
  DevAuthBypass,
  HttpError,
  NonceCacheConfig,
  RateLimitRule,
  RateLimiterConfig,
  SIGNATURE_PAYLOAD_VERSION
} from './types';

export type { AuthenticatedIdentity } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/** Raw Ed25519 public keys are exactly 32 bytes */
const ED25519_PUBLIC_KEY_BYTES = 32;

/** Ed25519 signatures are exactly 64 bytes */
const ED25519_SIGNATURE_BYTES = 64;

/** Fingerprints are 8 bytes of hex (see common/crypto generateFingerprint) */
const FINGERPRINT_PATTERN = /^[0-9a-f]{16}$/;

/** Nonces must be URL-safe and long enough to be unguessable */
const NONCE_PATTERN = /^[A-Za-z0-9_-]{8,128}$/;

/** SHA-256 of an empty body, precomputed for GET/HEAD/DELETE requests */
export const EMPTY_BODY_HASH = sha256Hex(Buffer.alloc(0));

// ═══════════════════════════════════════════════════════════════════════════
// CANONICAL SIGNATURE PAYLOAD
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Everything the signature covers.
 *
 * `target` is the full request target including the query string, so query
 * tampering invalidates the signature. `bodyHash` binds the exact body bytes —
 * the gap that made every legacy write endpoint forgeable.
 */
export interface SignaturePayloadInput {
  readonly method: string;
  readonly target: string;
  readonly timestamp: number | string;
  readonly nonce: string;
  readonly bodyHash: string;
}

/**
 * Build the canonical string that gets signed and verified.
 *
 * Newline separated and version prefixed so no field can be shifted into
 * another (e.g. a path containing ':' cannot impersonate a timestamp).
 */
export function buildSignaturePayload(input: SignaturePayloadInput): string {
  return [
    SIGNATURE_PAYLOAD_VERSION,
    input.method.toUpperCase(),
    input.target,
    String(input.timestamp),
    input.nonce,
    input.bodyHash
  ].join('\n');
}

/**
 * Hash a request body exactly the way the verifier will
 */
export function hashRequestBody(body: Buffer | string | undefined): string {
  if (body === undefined) return EMPTY_BODY_HASH;
  return sha256Hex(Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8'));
}

/**
 * Generate a fresh single-use nonce
 */
export function generateNonce(): string {
  return randomBytes(16).toString('base64url');
}

// ═══════════════════════════════════════════════════════════════════════════
// CLIENT SIGNING HELPER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Input for producing signed request headers
 */
export interface SignRequestInput {
  readonly method: string;
  /** Path plus query string, exactly as it will appear on the wire */
  readonly target: string;
  readonly body?: Buffer | string;
  /** Base64 PKCS8 Ed25519 private key */
  readonly privateKey: string;
  /** Base64 raw 32-byte Ed25519 public key */
  readonly publicKey: string;
  readonly timestamp?: number;
  readonly nonce?: string;
  /**
   * Override the fingerprint sent to the server. Only useful for negative
   * tests — the server recomputes it and rejects mismatches.
   */
  readonly fingerprintOverride?: string;
}

/**
 * Produce the header set for a signed request.
 *
 * Exported so clients (and tests) cannot drift from the server's
 * canonicalisation.
 */
export function createSignedRequestHeaders(
  input: SignRequestInput
): Record<string, string> {
  const timestamp = input.timestamp ?? Date.now();
  const nonce = input.nonce ?? generateNonce();
  const bodyHash = hashRequestBody(input.body);

  const payload = buildSignaturePayload({
    method: input.method,
    target: input.target,
    timestamp,
    nonce,
    bodyHash
  });

  const signature = signToBase64(payload, Buffer.from(input.privateKey, 'base64'));
  const fingerprint =
    input.fingerprintOverride ?? reconstructKeyTriplet(input.publicKey).fingerprint;

  return {
    [AUTH_HEADERS.FINGERPRINT]: fingerprint,
    [AUTH_HEADERS.PUBLIC_KEY]: input.publicKey,
    [AUTH_HEADERS.SIGNATURE]: signature,
    [AUTH_HEADERS.TIMESTAMP]: String(timestamp),
    [AUTH_HEADERS.NONCE]: nonce
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// NONCE CACHE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Bounded single-use nonce store, PARTITIONED per identity.
 *
 * The first version of this cache was one global Map with global oldest-first
 * eviction: an attacker spraying ~50k distinct nonces (one per request) could
 * force the victim's live nonce out of the cache and replay it inside the
 * freshness window. Eviction is now scoped: each fingerprint owns a bucket
 * capped at `maxEntriesPerPartition`, and eviction inside a bucket drops only
 * THAT identity's nonces. Global memory stays bounded by `maxEntries` (the
 * total across buckets): when that is exceeded the largest bucket is evicted —
 * per-identity fairness that can never be driven by a single attacker whose
 * own bucket is already capped.
 */
export class NonceCache {
  private readonly partitions = new Map<string, Map<string, number>>();
  private readonly config: NonceCacheConfig;
  private sweepTimer: NodeJS.Timeout | null = null;
  private evictions = 0;
  private totalEntries = 0;

  constructor(config: Partial<NonceCacheConfig> = {}) {
    this.config = { ...DEFAULT_NONCE_CACHE_CONFIG, ...config };
    if (this.config.maxEntries <= 0) {
      throw new Error('NonceCache maxEntries must be positive');
    }
    if (this.config.maxEntriesPerPartition <= 0) {
      throw new Error('NonceCache maxEntriesPerPartition must be positive');
    }
    this.startSweep();
  }

  /**
   * Reserve a nonce inside `partition` (the derived fingerprint).
   * Returns false when it has already been used (replay).
   */
  consume(partition: string, nonce: string, now: number = Date.now()): boolean {
    let bucket = this.partitions.get(partition);
    if (bucket === undefined) {
      bucket = new Map<string, number>();
      this.partitions.set(partition, bucket);
    }

    const existing = bucket.get(nonce);
    if (existing !== undefined) {
      if (existing > now) {
        return false;
      }
      bucket.delete(nonce);
      this.totalEntries--;
    }

    bucket.set(nonce, now + this.config.ttlMs);
    this.totalEntries++;
    this.enforceBounds(now, partition);
    return true;
  }

  /**
   * True when the nonce is currently reserved inside `partition`
   */
  has(partition: string, nonce: string, now: number = Date.now()): boolean {
    const bucket = this.partitions.get(partition);
    if (bucket === undefined) return false;
    const expiry = bucket.get(nonce);
    if (expiry === undefined) return false;
    if (expiry <= now) {
      bucket.delete(nonce);
      this.totalEntries--;
      if (bucket.size === 0) this.partitions.delete(partition);
      return false;
    }
    return true;
  }

  /**
   * Enforce the per-partition cap (drops only that partition's own entries)
   * and the global cap (drops from the largest partition, i.e. per-identity
   * fairness — a capped attacker bucket can never force a victim eviction).
   */
  private enforceBounds(now: number, partition: string): void {
    const bucket = this.partitions.get(partition);
    if (bucket !== undefined && bucket.size > this.config.maxEntriesPerPartition) {
      // One insert can overshoot the cap by at most one entry
      const oldest = bucket.keys().next();
      if (oldest.done !== true) {
        bucket.delete(oldest.value);
        this.totalEntries--;
        this.evictions++;
        if (bucket.size === 0) this.partitions.delete(partition);
      }
    }

    if (this.totalEntries > this.config.maxEntries) {
      this.sweep(now);

      while (this.totalEntries > this.config.maxEntries) {
        let largest: Map<string, number> | null = null;
        for (const candidate of this.partitions.values()) {
          if (largest === null || candidate.size > largest.size) {
            largest = candidate;
          }
        }
        if (largest === null) break;
        const oldest = largest.keys().next();
        if (oldest.done === true) break;
        largest.delete(oldest.value);
        this.totalEntries--;
        this.evictions++;
      }
    }
  }

  /**
   * Remove every expired entry across all partitions
   */
  sweep(now: number = Date.now()): number {
    let removed = 0;
    for (const [partitionKey, bucket] of this.partitions) {
      for (const [nonce, expiry] of bucket) {
        if (expiry <= now) {
          bucket.delete(nonce);
          this.totalEntries--;
          removed++;
        }
      }
      if (bucket.size === 0) this.partitions.delete(partitionKey);
    }
    return removed;
  }

  get size(): number {
    return this.totalEntries;
  }

  /** Number of distinct identity partitions currently held */
  get partitionCount(): number {
    return this.partitions.size;
  }

  get evictionCount(): number {
    return this.evictions;
  }

  clear(): void {
    this.partitions.clear();
    this.totalEntries = 0;
  }

  /**
   * Stop the sweep timer and release memory. Must be called on shutdown so the
   * process can exit (flaw #3).
   */
  dispose(): void {
    if (this.sweepTimer !== null) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = null;
    }
    this.partitions.clear();
    this.totalEntries = 0;
  }

  private startSweep(): void {
    if (this.config.sweepIntervalMs <= 0) return;
    this.sweepTimer = setInterval(() => this.sweep(), this.config.sweepIntervalMs);
    this.sweepTimer.unref();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// RATE LIMITER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Outcome of a rate limit check
 */
export interface RateLimitDecision {
  readonly allowed: boolean;
  readonly remaining: number;
  readonly limit: number;
  readonly resetInMs: number;
}

interface RateLimitBucket {
  count: number;
  resetAt: number;
}

/**
 * Fixed-window rate limiter with a hard entry cap.
 *
 * Unlike the legacy `rateLimits` Map, this evicts: expired windows are swept on
 * a timer and on demand, and the oldest keys are dropped once `maxEntries` is
 * reached so a spoofed-source-IP flood cannot exhaust memory.
 */
export class BoundedRateLimiter {
  private readonly buckets = new Map<string, RateLimitBucket>();
  private readonly config: RateLimiterConfig;
  private sweepTimer: NodeJS.Timeout | null = null;
  private evictions = 0;

  constructor(config: Partial<RateLimiterConfig> = {}) {
    this.config = { ...DEFAULT_RATE_LIMITER_CONFIG, ...config };
    if (this.config.maxEntries <= 0) {
      throw new Error('BoundedRateLimiter maxEntries must be positive');
    }
    this.startSweep();
  }

  /**
   * Consume one unit against `key`
   */
  check(key: string, rule?: RateLimitRule, now: number = Date.now()): RateLimitDecision {
    const limit = rule?.limit ?? this.config.limit;
    const windowMs = rule?.windowMs ?? this.config.windowMs;

    let bucket = this.buckets.get(key);

    if (bucket === undefined || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      // Re-insert so Map ordering reflects recency for eviction
      this.buckets.delete(key);
      this.buckets.set(key, bucket);
      this.enforceBounds(now);
    }

    if (bucket.count >= limit) {
      return {
        allowed: false,
        remaining: 0,
        limit,
        resetInMs: Math.max(0, bucket.resetAt - now)
      };
    }

    bucket.count++;
    return {
      allowed: true,
      remaining: Math.max(0, limit - bucket.count),
      limit,
      resetInMs: Math.max(0, bucket.resetAt - now)
    };
  }

  private enforceBounds(now: number): void {
    if (this.buckets.size <= this.config.maxEntries) return;

    this.sweep(now);

    while (this.buckets.size > this.config.maxEntries) {
      const oldest = this.buckets.keys().next();
      if (oldest.done === true) break;
      this.buckets.delete(oldest.value);
      this.evictions++;
    }
  }

  /**
   * Remove every elapsed window
   */
  sweep(now: number = Date.now()): number {
    let removed = 0;
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAt <= now) {
        this.buckets.delete(key);
        removed++;
      }
    }
    return removed;
  }

  get size(): number {
    return this.buckets.size;
  }

  get evictionCount(): number {
    return this.evictions;
  }

  reset(): void {
    this.buckets.clear();
  }

  dispose(): void {
    if (this.sweepTimer !== null) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = null;
    }
    this.buckets.clear();
  }

  private startSweep(): void {
    if (this.config.sweepIntervalMs <= 0) return;
    this.sweepTimer = setInterval(() => this.sweep(), this.config.sweepIntervalMs);
    this.sweepTimer.unref();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Typed configuration error thrown at construction time when the auth config
 * violates an invariant (e.g. a nonce TTL that does not outlive the freshness
 * window, which would re-open the replay hole the nonce cache exists to close).
 */
export class AuthConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthConfigError';
  }
}

/**
 * Everything the verifier needs about an inbound request
 */
export interface AuthenticationInput {
  readonly method: string;
  /** Request target (path + query) exactly as received */
  readonly target: string;
  /** Lower-cased header map */
  readonly headers: Readonly<Record<string, string>>;
  /** Exact body bytes; empty buffer for bodyless methods */
  readonly rawBody: Buffer;
  readonly remoteAddress: string;
  readonly now?: number;
}

/**
 * Create the explicit dev bypass object.
 *
 * There is deliberately no environment variable, no boolean flag and no config
 * file field that can produce this. The caller must pass the acknowledgement
 * literal, and construction fails outright in any production-like
 * NODE_ENV (exact 'production', 'prod', or any casing of either).
 */
export function createDevAuthBypass(
  acknowledgement: typeof DEV_BYPASS_ACKNOWLEDGEMENT,
  fingerprint?: string
): DevAuthBypass {
  if (acknowledgement !== DEV_BYPASS_ACKNOWLEDGEMENT) {
    throw new Error('Invalid dev auth bypass acknowledgement');
  }
  return { enabled: true, acknowledgement, fingerprint };
}

/** True when NODE_ENV names a production environment, case-insensitively */
function isProductionEnv(): boolean {
  return /^prod(uction)?$/i.test(process.env.NODE_ENV ?? '');
}

/**
 * Verifies signed requests and enforces replay + rate limits.
 */
export class AuthMiddleware {
  private readonly config: AuthConfig;
  private readonly nonces: NonceCache;
  private readonly limiter: BoundedRateLimiter;
  private readonly aggregateLimiter: BoundedRateLimiter;
  private readonly logger: Logger;
  private readonly devBypass: DevAuthBypass | null;

  constructor(config: AuthConfigInput = {}, logger?: Logger) {
    this.logger = logger ?? createLogger('app:auth');

    const devBypass = config.devBypass ?? null;

    if (devBypass !== null) {
      // Impossible to enable in production, regardless of what the caller
      // passes. Any casing of 'production' (or the shorthand 'prod') counts:
      // an exact string comparison was evadable with 'Production', 'PROD', …
      if (isProductionEnv()) {
        throw new Error(
          `Refusing to construct AuthMiddleware with devBypass while NODE_ENV=${process.env.NODE_ENV}`
        );
      }
      if (devBypass.acknowledgement !== DEV_BYPASS_ACKNOWLEDGEMENT) {
        throw new Error('devBypass requires the explicit acknowledgement literal');
      }
      this.logger.warn(
        '════════ DEV AUTH BYPASS ENABLED — ALL REQUEST AUTHENTICATION IS DISABLED ════════'
      );
    }

    this.devBypass = devBypass;
    this.config = {
      freshnessMs: config.freshnessMs ?? 60_000,
      nonceCache: { ...DEFAULT_NONCE_CACHE_CONFIG, ...config.nonceCache },
      rateLimiter: { ...DEFAULT_RATE_LIMITER_CONFIG, ...config.rateLimiter },
      devBypass: devBypass ?? undefined
    };

    // Invariant: a nonce must stay reserved for AT LEAST the freshness window.
    // If the cache forgets a nonce while its signature is still fresh, the
    // request becomes replayable. (Nonce TTL vs freshness invariant.)
    if (this.config.nonceCache.ttlMs <= this.config.freshnessMs) {
      throw new AuthConfigError(
        `nonceCache.ttlMs (${String(this.config.nonceCache.ttlMs)}ms) must be greater than ` +
          `freshnessMs (${String(this.config.freshnessMs)}ms), otherwise nonces expire ` +
          'while their signatures are still fresh and replay protection is bypassed'
      );
    }

    this.nonces = new NonceCache(this.config.nonceCache);
    this.limiter = new BoundedRateLimiter(this.config.rateLimiter);
    this.aggregateLimiter = new BoundedRateLimiter(this.config.rateLimiter);
  }

  /**
   * True when the loud, non-production bypass is active
   */
  get bypassActive(): boolean {
    return this.devBypass !== null;
  }

  get nonceCache(): NonceCache {
    return this.nonces;
  }

  get rateLimiter(): BoundedRateLimiter {
    return this.limiter;
  }

  get aggregateRateLimiter(): BoundedRateLimiter {
    return this.aggregateLimiter;
  }

  /**
   * Enforce the rate limit for a request source. Applied to public routes too.
   */
  enforceRateLimit(
    sourceKey: string,
    rule?: RateLimitRule,
    now: number = Date.now()
  ): Result<RateLimitDecision, HttpError> {
    const decision = this.limiter.check(sourceKey, rule, now);
    if (!decision.allowed) {
      return err(
        HttpError.tooManyRequests(
          ERROR_CODES.E_SERVICE_RATE_LIMIT,
          'Too many requests',
          decision.resetInMs
        )
      );
    }
    return ok(decision);
  }

  /**
   * Aggregate per-source budget (total requests per window regardless of
   * path). Enforced for EVERY request — including OPTIONS preflights, CORS
   * rejections and WebSocket upgrade attempts — so a path spray cannot evade
   * the per-path buckets.
   */
  enforceAggregateRateLimit(
    sourceKey: string,
    now: number = Date.now()
  ): Result<RateLimitDecision, HttpError> {
    const decision = this.aggregateLimiter.check(
      sourceKey,
      { limit: this.config.rateLimiter.aggregateLimit, windowMs: this.config.rateLimiter.aggregateWindowMs },
      now
    );
    if (!decision.allowed) {
      return err(
        HttpError.tooManyRequests(
          ERROR_CODES.E_SERVICE_RATE_LIMIT,
          'Too many requests',
          decision.resetInMs
        )
      );
    }
    return ok(decision);
  }

  /**
   * Verify a signed request.
   *
   * Check order matters: the signature is validated BEFORE the nonce is
   * consumed, so an attacker cannot burn a legitimate caller's nonce with a
   * forged request, while a genuine replay (valid signature, reused nonce) is
   * still rejected.
   */
  authenticate(input: AuthenticationInput): Result<AuthenticatedIdentity, HttpError> {
    const now = input.now ?? Date.now();

    if (this.devBypass !== null) {
      // Prominent warning on EVERY bypassed request, not just at startup
      this.logger.warn('⚠  DEV AUTH BYPASS: request accepted with NO signature check', {
        method: input.method,
        target: input.target,
        remoteAddress: input.remoteAddress
      });
      return ok({
        fingerprint: this.devBypass.fingerprint ?? '0000000000000000',
        publicKey: '',
        timestamp: now,
        nonce: `dev-${String(now)}`,
        devBypass: true
      });
    }

    // ── 1. Required headers ────────────────────────────────────────────────
    const claimedFingerprint = input.headers[AUTH_HEADERS.FINGERPRINT];
    const publicKeyHeader =
      input.headers[AUTH_HEADERS.PUBLIC_KEY] ?? input.headers[AUTH_HEADERS.PUBLIC_KEY_LEGACY];
    const signature = input.headers[AUTH_HEADERS.SIGNATURE];
    const timestampHeader = input.headers[AUTH_HEADERS.TIMESTAMP];
    const nonce = input.headers[AUTH_HEADERS.NONCE];

    if (
      claimedFingerprint === undefined ||
      publicKeyHeader === undefined ||
      signature === undefined ||
      timestampHeader === undefined ||
      nonce === undefined
    ) {
      return err(
        HttpError.unauthorized(
          ERROR_CODES.E_AUTH_SIGNATURE_INVALID,
          'Missing AlephNet authentication headers'
        )
      );
    }

    if (!FINGERPRINT_PATTERN.test(claimedFingerprint)) {
      return err(
        HttpError.unauthorized(ERROR_CODES.E_AUTH_INVALID_KEY, 'Malformed fingerprint')
      );
    }

    // ── 2. Public key must be a real raw Ed25519 key ────────────────────────
    const publicKey = decodeBase64(publicKeyHeader);
    if (publicKey === null || publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
      return err(
        HttpError.unauthorized(
          ERROR_CODES.E_AUTH_INVALID_KEY,
          'Malformed or missing Ed25519 public key'
        )
      );
    }
    const canonicalPublicKey = publicKey.toString('base64');

    // ── 3. Bind the key to the claimed fingerprint ──────────────────────────
    // The legacy code trusted the fingerprint header outright, so any caller
    // could present their own key while claiming somebody else's identity.
    let derivedFingerprint: string;
    try {
      derivedFingerprint = reconstructKeyTriplet(canonicalPublicKey).fingerprint;
    } catch {
      return err(
        HttpError.unauthorized(ERROR_CODES.E_AUTH_INVALID_KEY, 'Unusable public key')
      );
    }

    if (!timingSafeEqualStrings(derivedFingerprint, claimedFingerprint)) {
      return err(
        HttpError.unauthorized(
          ERROR_CODES.E_AUTH_INVALID_KEY,
          'Fingerprint does not match the supplied public key'
        )
      );
    }

    // ── 4. Freshness ────────────────────────────────────────────────────────
    const timestamp = Number.parseInt(timestampHeader, 10);
    if (!Number.isFinite(timestamp) || String(timestamp) !== timestampHeader.trim()) {
      return err(
        HttpError.unauthorized(ERROR_CODES.E_AUTH_SIGNATURE_INVALID, 'Malformed timestamp')
      );
    }
    if (Math.abs(now - timestamp) > this.config.freshnessMs) {
      return err(
        HttpError.unauthorized(
          ERROR_CODES.E_AUTH_SIGNATURE_INVALID,
          'Request timestamp outside the accepted freshness window'
        )
      );
    }

    // ── 5. Nonce shape ──────────────────────────────────────────────────────
    if (!NONCE_PATTERN.test(nonce)) {
      return err(
        HttpError.unauthorized(ERROR_CODES.E_AUTH_SIGNATURE_INVALID, 'Malformed nonce')
      );
    }

    // ── 6. Real Ed25519 verification over method + target + ts + nonce + body ─
    const signatureBytes = decodeBase64(signature);
    if (signatureBytes === null || signatureBytes.length !== ED25519_SIGNATURE_BYTES) {
      return err(
        HttpError.unauthorized(ERROR_CODES.E_AUTH_SIGNATURE_INVALID, 'Malformed signature')
      );
    }

    const payload = buildSignaturePayload({
      method: input.method,
      target: input.target,
      timestamp,
      nonce,
      bodyHash: sha256Hex(input.rawBody)
    });

    let verified = false;
    try {
      verified = verifyFromBase64(payload, signatureBytes.toString('base64'), publicKey);
    } catch (error) {
      this.logger.debug('Signature verification threw', {
        reason: error instanceof Error ? error.name : 'unknown'
      });
      verified = false;
    }

    if (!verified) {
      return err(
        HttpError.unauthorized(ERROR_CODES.E_AUTH_SIGNATURE_INVALID, 'Invalid signature')
      );
    }

    // ── 7. Single-use nonce (replay protection) ──────────────────────────────
    // Partitioned per fingerprint: eviction inside one identity's bucket can
    // only drop that identity's own nonces, never a victim's (replay finding).
    if (!this.nonces.consume(derivedFingerprint, nonce, now)) {
      return err(
        HttpError.unauthorized(
          ERROR_CODES.E_AUTH_SIGNATURE_INVALID,
          'Nonce already used (replay rejected)'
        )
      );
    }

    return ok({
      fingerprint: derivedFingerprint,
      publicKey: canonicalPublicKey,
      timestamp,
      nonce,
      devBypass: false
    });
  }

  /**
   * Release timers and cached state (flaw #3)
   */
  dispose(): void {
    this.nonces.dispose();
    this.limiter.dispose();
    this.aggregateLimiter.dispose();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Strict-ish base64 decode that returns null instead of silently truncating
 */
function decodeBase64(value: string): Buffer | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(trimmed)) return null;
  try {
    const buffer = Buffer.from(trimmed, 'base64');
    return buffer.length === 0 ? null : buffer;
  } catch {
    return null;
  }
}

/**
 * Constant-time string comparison (length is not secret here, content is)
 */
function timingSafeEqualStrings(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}
