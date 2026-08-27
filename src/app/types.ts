/**
 * Application Layer Types
 *
 * Typed request/response contexts, route signatures and server configuration
 * for the AlephNet HTTP application layer.
 *
 * This layer is intentionally decoupled: it declares interfaces (see
 * ActionRegistry) that higher level domain modules are wired into by the
 * composition root. Nothing here imports a domain module.
 */

import type { IncomingMessage, ServerResponse } from 'http';
import type { Socket } from 'net';
import type { Logger } from '../common/logging';

// ═══════════════════════════════════════════════════════════════════════════
// HTTP PRIMITIVES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * HTTP methods handled by the router
 */
export type HttpMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS';

/**
 * All methods the router will accept for registration
 */
export const HTTP_METHODS: readonly HttpMethod[] = [
  'GET',
  'HEAD',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS'
];

/**
 * Parsed request body shapes produced by the body reader
 */
export type ParsedBody =
  | undefined
  | string
  | Buffer
  | Record<string, unknown>
  | unknown[];

// ═══════════════════════════════════════════════════════════════════════════
// AUTHENTICATED IDENTITY
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A verified caller identity.
 *
 * `fingerprint` is ALWAYS recomputed from `publicKey` — it is never taken from
 * a client supplied header, query parameter or body field.
 */
export interface AuthenticatedIdentity {
  /** Fingerprint derived from the verified public key */
  readonly fingerprint: string;
  /** Raw 32-byte Ed25519 public key, base64 encoded */
  readonly publicKey: string;
  /** Client supplied timestamp that was accepted as fresh */
  readonly timestamp: number;
  /** Nonce consumed by this request (single use) */
  readonly nonce: string;
  /** True when the identity came from the explicit, non-production dev bypass */
  readonly devBypass: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// REQUEST CONTEXT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Everything a handler needs about an inbound request.
 *
 * `rawBody` is the exact byte sequence covered by the request signature;
 * `body` is the parsed representation.
 */
export interface RequestContext<TBody = ParsedBody> {
  /** Correlation id echoed to the client and attached to every server log */
  readonly requestId: string;
  readonly method: HttpMethod;
  /** Pathname only, no query string */
  readonly path: string;
  /** Full request target (pathname + query) — this is what gets signed */
  readonly target: string;
  readonly query: Readonly<Record<string, string>>;
  readonly params: Readonly<Record<string, string>>;
  readonly headers: Readonly<Record<string, string>>;
  readonly rawBody: Buffer;
  readonly body: TBody;
  /** Non-null only when the route required auth and verification succeeded */
  readonly identity: AuthenticatedIdentity | null;
  readonly remoteAddress: string;
  readonly receivedAt: number;
  readonly logger: Logger;
  readonly raw: {
    readonly req: IncomingMessage;
    readonly res: ServerResponse;
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// RESPONSE WRITER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Minimal typed response surface.
 *
 * Every write path is idempotent-guarded via `sent` so a late error handler can
 * never trigger "headers already sent" crashes.
 */
export interface ResponseWriter {
  readonly sent: boolean;
  readonly statusCode: number;
  status(code: number): ResponseWriter;
  header(name: string, value: string): ResponseWriter;
  json(payload: unknown, status?: number): void;
  text(body: string, status?: number, contentType?: string): void;
  buffer(body: Buffer, contentType: string, status?: number): void;
  empty(status: number): void;
  readonly raw: ServerResponse;
}

// ═══════════════════════════════════════════════════════════════════════════
// ROUTING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Per-route auth requirement.
 *
 * Routes are REQUIRED by default; a route must explicitly opt out with
 * `'public'` to be reachable without a verified signature. `'optional'`
 * verifies when signature headers are present and rejects them if invalid,
 * but allows headerless requests through with `identity = null` — used by
 * surfaces (like the actions API) that enforce auth per operation.
 */
export type RouteAuth = 'required' | 'public' | 'optional';

/**
 * Route handler signature
 */
export type RouteHandler<TBody = ParsedBody> = (
  ctx: RequestContext<TBody>,
  res: ResponseWriter
) => void | Promise<void>;

/**
 * Optional per-route rate limit override
 */
export interface RateLimitRule {
  readonly limit: number;
  readonly windowMs: number;
}

/**
 * Route registration options
 */
export interface RouteOptions {
  /** Defaults to 'required' — secure by default */
  readonly auth?: RouteAuth;
  readonly rateLimit?: RateLimitRule;
  readonly description?: string;
  /** Skip the body reader entirely (used for SSE / long lived responses) */
  readonly streaming?: boolean;
}

/**
 * A registered route
 */
export interface RouteDefinition {
  readonly method: HttpMethod;
  readonly path: string;
  readonly auth: RouteAuth;
  readonly description: string;
  readonly streaming: boolean;
  readonly rateLimit: RateLimitRule | null;
  readonly handler: RouteHandler<never>;
}

/**
 * Result of resolving a method + path against the route table
 */
export interface RouteMatch {
  readonly route: RouteDefinition;
  readonly params: Readonly<Record<string, string>>;
  /** True when a HEAD request was served by a GET route */
  readonly suppressBody: boolean;
}

/**
 * Why a resolution failed — lets the server answer 404 vs 405 correctly
 */
export type RouteMissReason = 'no-path' | 'no-method';

/**
 * Route resolution outcome
 */
export interface RouteResolution {
  readonly match: RouteMatch | null;
  readonly reason: RouteMissReason | null;
  readonly allowedMethods: readonly HttpMethod[];
}

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * An error that is safe to surface to a client.
 *
 * Anything that is NOT an HttpError becomes a generic 500 carrying only a
 * correlation id — internal messages and stacks stay server-side (flaw #6).
 */
export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;
  readonly headers?: Readonly<Record<string, string>>;

  constructor(
    status: number,
    code: string,
    message: string,
    options?: { details?: unknown; headers?: Readonly<Record<string, string>> }
  ) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.details = options?.details;
    this.headers = options?.headers;
  }

  static badRequest(code: string, message: string, details?: unknown): HttpError {
    return new HttpError(400, code, message, { details });
  }

  static unauthorized(code: string, message: string): HttpError {
    return new HttpError(401, code, message, {
      headers: { 'WWW-Authenticate': 'AlephSignature' }
    });
  }

  static forbidden(code: string, message: string): HttpError {
    return new HttpError(403, code, message);
  }

  static notFound(code: string, message: string): HttpError {
    return new HttpError(404, code, message);
  }

  static payloadTooLarge(code: string, message: string): HttpError {
    return new HttpError(413, code, message);
  }

  static tooManyRequests(code: string, message: string, retryAfterMs: number): HttpError {
    return new HttpError(429, code, message, {
      headers: { 'Retry-After': String(Math.max(1, Math.ceil(retryAfterMs / 1000))) }
    });
  }
}

/**
 * Type guard for HttpError (survives cross-realm/instanceof edge cases)
 */
export function isHttpError(value: unknown): value is HttpError {
  return (
    value instanceof HttpError ||
    (typeof value === 'object' &&
      value !== null &&
      (value as { name?: unknown }).name === 'HttpError' &&
      typeof (value as { status?: unknown }).status === 'number')
  );
}

/**
 * Standard JSON error envelope
 */
export interface ErrorResponseBody {
  readonly error: string;
  readonly code: string;
  readonly requestId: string;
  readonly details?: unknown;
}

// ═══════════════════════════════════════════════════════════════════════════
// AUTH CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Canonical header names for signed requests
 */
export const AUTH_HEADERS = {
  FINGERPRINT: 'x-aleph-fingerprint',
  PUBLIC_KEY: 'x-aleph-public-key',
  /** Legacy spelling accepted for compatibility */
  PUBLIC_KEY_LEGACY: 'x-aleph-publickey',
  SIGNATURE: 'x-aleph-signature',
  TIMESTAMP: 'x-aleph-timestamp',
  NONCE: 'x-aleph-nonce'
} as const;

/**
 * Version tag that prefixes every signed payload. Bumping this invalidates all
 * signatures produced by an older canonicalisation.
 */
export const SIGNATURE_PAYLOAD_VERSION = 'ALEPHNET-REQUEST-V2';

/**
 * The exact string a caller must pass to enable the dev bypass. There is no
 * environment variable that can do this (the legacy ALEPH_DEV_NO_AUTH backdoor
 * is deliberately not read anywhere in this layer).
 */
export const DEV_BYPASS_ACKNOWLEDGEMENT =
  'i-understand-this-disables-all-request-authentication' as const;

/**
 * Explicit, loud, non-production-only auth bypass.
 */
export interface DevAuthBypass {
  readonly enabled: true;
  readonly acknowledgement: typeof DEV_BYPASS_ACKNOWLEDGEMENT;
  /** Identity handed to handlers while the bypass is active */
  readonly fingerprint?: string;
}

/**
 * Nonce cache bounds
 *
 * The cache is partitioned per identity (fingerprint). Each partition holds at
 * most `maxEntriesPerPartition` nonces and evicts only its OWN oldest entries,
 * so one identity hammering the cache can exhaust its own bucket but can never
 * evict another identity's live nonce (replay-protection finding #1).
 */
export interface NonceCacheConfig {
  /** Hard cap on retained nonces ACROSS all partitions; the largest partition
   *  is evicted past this (per-identity fairness, never a victim's bucket) */
  readonly maxEntries: number;
  /** Hard cap on entries one identity can hold; overflow drops that
   *  identity's own oldest nonces only */
  readonly maxEntriesPerPartition: number;
  /** How long a nonce stays reserved (must be > the auth freshness window) */
  readonly ttlMs: number;
  /** Background sweep interval; 0 disables the timer (lazy sweep only) */
  readonly sweepIntervalMs: number;
}

/**
 * Rate limiter bounds
 */
export interface RateLimiterConfig {
  readonly limit: number;
  readonly windowMs: number;
  /** Hard cap on tracked keys; oldest entries are evicted past this */
  readonly maxEntries: number;
  readonly sweepIntervalMs: number;
  /**
   * Aggregate per-source budget enforced in ADDITION to the per-path buckets
   * (`limit`/`windowMs`). Applies to every request regardless of path —
   * including OPTIONS preflights and CORS rejections — so a path spray cannot
   * evade overall limiting.
   */
  readonly aggregateLimit: number;
  readonly aggregateWindowMs: number;
}

/**
 * AuthMiddleware configuration
 */
export interface AuthConfig {
  /** Max allowed clock skew between client timestamp and server time */
  readonly freshnessMs: number;
  readonly nonceCache: NonceCacheConfig;
  readonly rateLimiter: RateLimiterConfig;
  /**
   * Present only when a developer explicitly constructed the bypass. Typed as
   * a discriminated object so `true` alone can never enable it.
   */
  readonly devBypass?: DevAuthBypass;
}

/**
 * AuthMiddleware constructor input: every nested config object may be partial;
 * defaults are merged inside the constructor.
 */
export interface AuthConfigInput {
  readonly freshnessMs?: number;
  readonly nonceCache?: Partial<NonceCacheConfig>;
  readonly rateLimiter?: Partial<RateLimiterConfig>;
  readonly devBypass?: DevAuthBypass;
}

// ═══════════════════════════════════════════════════════════════════════════
// SERVER CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Resolved server configuration
 */
export interface ServerConfig {
  readonly port: number;
  readonly host: string;
  /** When set, static files are served for non-API GET/HEAD requests */
  readonly staticPath?: string;
  /** Serve index.html for unknown non-API paths. Off by default so unmatched
   *  routes produce real 404s instead of a 200 index.html (flaw #2). */
  readonly staticSpaFallback: boolean;
  /** Exact Origin allowlist. `['*']` allows any origin without credentials. */
  readonly corsOrigins: readonly string[];
  /**
   * Production config can only ever be `false`. Enabling a bypass requires
   * constructing an AuthMiddleware with an explicit DevAuthBypass object.
   */
  readonly devAuthBypass?: false;
  readonly maxBodyBytes: number;
  readonly authFreshnessMs: number;
  /** Path prefixes that are API surface and must never fall through to static */
  readonly apiPrefixes: readonly string[];
  readonly nonceCache: NonceCacheConfig;
  readonly rateLimiter: RateLimiterConfig;
  readonly stream: StreamHubConfig;
  /** Register SIGINT/SIGTERM handlers (exactly once, removed on stop) */
  readonly installSignalHandlers: boolean;
  /** Enable the WebSocket upgrade path (requires the `ws` package) */
  readonly websocket: WebSocketConfig | null;
  readonly requestTimeoutMs: number;
  /** Deadline for receiving a request body before answering 408 */
  readonly bodyTimeoutMs: number;
  /** Hard size cap for any single static file (StaticServer TOCTOU fix) */
  readonly staticMaxFileBytes: number;
  readonly shutdownGraceMs: number;
}

/**
 * User supplied server options
 */
export interface ServerOptions {
  readonly port?: number;
  readonly host?: string;
  readonly staticPath?: string;
  readonly staticSpaFallback?: boolean;
  readonly corsOrigins?: readonly string[];
  readonly devAuthBypass?: false;
  readonly maxBodyBytes?: number;
  readonly authFreshnessMs?: number;
  readonly apiPrefixes?: readonly string[];
  readonly nonceCache?: Partial<NonceCacheConfig>;
  readonly rateLimiter?: Partial<RateLimiterConfig>;
  readonly stream?: Partial<StreamHubConfig>;
  readonly installSignalHandlers?: boolean;
  readonly websocket?: Partial<WebSocketConfig> | null;
  readonly requestTimeoutMs?: number;
  /** Deadline for receiving a request body before answering 408 */
  readonly bodyTimeoutMs?: number;
  /** Hard size cap for any single static file (default 10 MB) */
  readonly staticMaxFileBytes?: number;
  readonly shutdownGraceMs?: number;
}

/**
 * SSE hub configuration
 */
export interface StreamHubConfig {
  readonly heartbeatMs: number;
  readonly maxClients: number;
  /** Client reconnect hint in ms */
  readonly retryMs: number;
}

/**
 * WebSocket configuration
 */
export interface WebSocketConfig {
  readonly path: string;
  readonly maxConnections: number;
  readonly maxMessageBytes: number;
  /**
   * Origin allowlist for upgrades. Defaults to the server `corsOrigins`.
   * `'*'` is NOT honoured here — upgrades always require an explicit origin
   * match or no Origin header at all (non-browser client).
   */
  readonly allowedOrigins?: readonly string[];
}

// ═══════════════════════════════════════════════════════════════════════════
// DEFAULTS
// ═══════════════════════════════════════════════════════════════════════════

export const DEFAULT_NONCE_CACHE_CONFIG: NonceCacheConfig = {
  maxEntries: 50_000,
  maxEntriesPerPartition: 1_000,
  ttlMs: 120_000,
  sweepIntervalMs: 30_000
};

export const DEFAULT_RATE_LIMITER_CONFIG: RateLimiterConfig = {
  limit: 120,
  windowMs: 60_000,
  maxEntries: 20_000,
  sweepIntervalMs: 30_000,
  aggregateLimit: 600,
  aggregateWindowMs: 60_000
};

export const DEFAULT_STREAM_HUB_CONFIG: StreamHubConfig = {
  heartbeatMs: 15_000,
  maxClients: 500,
  retryMs: 3_000
};

export const DEFAULT_WEBSOCKET_CONFIG: WebSocketConfig = {
  path: '/ws',
  maxConnections: 200,
  maxMessageBytes: 256 * 1024
};

export const DEFAULT_API_PREFIXES: readonly string[] = [
  '/api',
  '/actions',
  '/health',
  '/status',
  '/stream',
  '/ws'
];

export const DEFAULT_SERVER_CONFIG: ServerConfig = {
  port: 0,
  host: '127.0.0.1',
  staticSpaFallback: false,
  corsOrigins: [],
  devAuthBypass: false,
  maxBodyBytes: 1_048_576,
  authFreshnessMs: 60_000,
  apiPrefixes: DEFAULT_API_PREFIXES,
  nonceCache: DEFAULT_NONCE_CACHE_CONFIG,
  rateLimiter: DEFAULT_RATE_LIMITER_CONFIG,
  stream: DEFAULT_STREAM_HUB_CONFIG,
  installSignalHandlers: false,
  websocket: null,
  requestTimeoutMs: 30_000,
  bodyTimeoutMs: 10_000,
  staticMaxFileBytes: 10 * 1024 * 1024,
  shutdownGraceMs: 5_000
};

/**
 * Merge user options over defaults, keeping the nested config objects complete
 */
export function resolveServerConfig(options: ServerOptions = {}): ServerConfig {
  const websocket: WebSocketConfig | null =
    options.websocket === null || options.websocket === undefined
      ? null
      : { ...DEFAULT_WEBSOCKET_CONFIG, ...options.websocket };

  const config: ServerConfig = {
    port: options.port ?? DEFAULT_SERVER_CONFIG.port,
    host: options.host ?? DEFAULT_SERVER_CONFIG.host,
    staticPath: options.staticPath,
    staticSpaFallback: options.staticSpaFallback ?? DEFAULT_SERVER_CONFIG.staticSpaFallback,
    corsOrigins: options.corsOrigins ?? DEFAULT_SERVER_CONFIG.corsOrigins,
    devAuthBypass: false,
    maxBodyBytes: options.maxBodyBytes ?? DEFAULT_SERVER_CONFIG.maxBodyBytes,
    authFreshnessMs: options.authFreshnessMs ?? DEFAULT_SERVER_CONFIG.authFreshnessMs,
    apiPrefixes: options.apiPrefixes ?? DEFAULT_SERVER_CONFIG.apiPrefixes,
    nonceCache: { ...DEFAULT_NONCE_CACHE_CONFIG, ...options.nonceCache },
    rateLimiter: { ...DEFAULT_RATE_LIMITER_CONFIG, ...options.rateLimiter },
    stream: { ...DEFAULT_STREAM_HUB_CONFIG, ...options.stream },
    installSignalHandlers:
      options.installSignalHandlers ?? DEFAULT_SERVER_CONFIG.installSignalHandlers,
    websocket,
    requestTimeoutMs: options.requestTimeoutMs ?? DEFAULT_SERVER_CONFIG.requestTimeoutMs,
    bodyTimeoutMs: options.bodyTimeoutMs ?? DEFAULT_SERVER_CONFIG.bodyTimeoutMs,
    staticMaxFileBytes:
      options.staticMaxFileBytes ?? DEFAULT_SERVER_CONFIG.staticMaxFileBytes,
    shutdownGraceMs: options.shutdownGraceMs ?? DEFAULT_SERVER_CONFIG.shutdownGraceMs
  };

  if (!Number.isInteger(config.port) || config.port < 0 || config.port > 65_535) {
    throw new Error(`Invalid server port: ${String(config.port)}`);
  }
  if (config.maxBodyBytes <= 0) {
    throw new Error('maxBodyBytes must be positive');
  }
  if (config.authFreshnessMs <= 0) {
    throw new Error('authFreshnessMs must be positive');
  }
  if (config.bodyTimeoutMs <= 0) {
    throw new Error('bodyTimeoutMs must be positive');
  }
  if (config.staticMaxFileBytes <= 0) {
    throw new Error('staticMaxFileBytes must be positive');
  }

  return config;
}

// ═══════════════════════════════════════════════════════════════════════════
// WEBSOCKET STRUCTURAL TYPES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Structural subset of a `ws` socket that this layer uses.
 *
 * Declared locally so the app layer compiles without @types/ws and stays
 * swappable for any compatible implementation.
 */
export interface WebSocketLike {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  terminate(): void;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
  once(event: string, listener: (...args: unknown[]) => void): unknown;
  removeAllListeners(event?: string): unknown;
}

/**
 * Structural subset of a `ws` WebSocketServer in `noServer` mode
 */
export interface WebSocketServerLike {
  handleUpgrade(
    request: IncomingMessage,
    socket: Socket,
    head: Buffer,
    callback: (ws: WebSocketLike) => void
  ): void;
  close(callback?: () => void): void;
  on(event: string, listener: (...args: unknown[]) => void): unknown;
}

/**
 * Constructor shape for a `noServer` WebSocket server
 */
export type WebSocketServerFactory = (options: {
  noServer: true;
  maxPayload?: number;
}) => WebSocketServerLike;

/**
 * A live, authenticated WebSocket peer
 */
export interface WebSocketPeer {
  readonly id: string;
  readonly identity: AuthenticatedIdentity;
  readonly socket: WebSocketLike;
  readonly connectedAt: number;
}

/**
 * Handler invoked for each authenticated WebSocket connection
 */
export type WebSocketHandler = (peer: WebSocketPeer) => void;
