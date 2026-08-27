/**
 * Application Layer
 *
 * Unified HTTP server, signed-request authentication and the actions API for an
 * AlephNet node. Replaces the legacy `lib/app/` server, which could not boot
 * (ESM syntax inside a CommonJS package) and whose authentication was forgeable.
 *
 * Wiring: build an `ActionRegistry`, register one `ActionModule` per domain
 * layer, hand it to `AlephServer`, then `start()`.
 *
 *   const actions = new ActionRegistry();
 *   actions.registerModule(createSemanticActions(deps));
 *   actions.setTierResolver(walletTierResolver);
 *   const server = new AlephServer({ port: 8080, actions });
 *   await server.start();
 */

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export {
  AUTH_HEADERS,
  DEFAULT_API_PREFIXES,
  DEFAULT_NONCE_CACHE_CONFIG,
  DEFAULT_RATE_LIMITER_CONFIG,
  DEFAULT_SERVER_CONFIG,
  DEFAULT_STREAM_HUB_CONFIG,
  DEFAULT_WEBSOCKET_CONFIG,
  DEV_BYPASS_ACKNOWLEDGEMENT,
  HTTP_METHODS,
  HttpError,
  SIGNATURE_PAYLOAD_VERSION,
  isHttpError,
  resolveServerConfig
} from './types';

export type {
  AuthConfig,
  AuthConfigInput,
  AuthenticatedIdentity,
  DevAuthBypass,
  ErrorResponseBody,
  HttpMethod,
  NonceCacheConfig,
  ParsedBody,
  RateLimitRule,
  RateLimiterConfig,
  RequestContext,
  ResponseWriter,
  RouteAuth,
  RouteDefinition,
  RouteHandler,
  RouteMatch,
  RouteMissReason,
  RouteOptions,
  RouteResolution,
  ServerConfig,
  ServerOptions,
  StreamHubConfig,
  WebSocketConfig,
  WebSocketHandler,
  WebSocketLike,
  WebSocketPeer,
  WebSocketServerFactory,
  WebSocketServerLike
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// AUTHENTICATION
// ═══════════════════════════════════════════════════════════════════════════

export {
  AuthConfigError,
  AuthMiddleware,
  BoundedRateLimiter,
  EMPTY_BODY_HASH,
  NonceCache,
  buildSignaturePayload,
  createDevAuthBypass,
  createSignedRequestHeaders,
  generateNonce,
  hashRequestBody
} from './AuthMiddleware';

export type {
  AuthenticationInput,
  RateLimitDecision,
  SignRequestInput,
  SignaturePayloadInput
} from './AuthMiddleware';

// ═══════════════════════════════════════════════════════════════════════════
// ROUTING
// ═══════════════════════════════════════════════════════════════════════════

export {
  Router,
  createResponseWriter,
  parseRequestBody,
  readRequestBody,
  writeErrorResponse
} from './Router';

// ═══════════════════════════════════════════════════════════════════════════
// STATIC FILES
// ═══════════════════════════════════════════════════════════════════════════

export {
  MIME_TYPES,
  StaticServer,
  contentTypeFor,
  decodeUrlPath,
  isContained
} from './StaticServer';

export type {
  ResolvedStaticFile,
  StaticServerConfig,
  StaticServerOptions
} from './StaticServer';

// ═══════════════════════════════════════════════════════════════════════════
// STREAMING
// ═══════════════════════════════════════════════════════════════════════════

export { StreamHub } from './StreamHub';

export type { SseClient, SseRegistration, StreamHubStats } from './StreamHub';

// ═══════════════════════════════════════════════════════════════════════════
// ACTIONS
// ═══════════════════════════════════════════════════════════════════════════

export {
  ActionRegistry,
  NeophyteTierResolver,
  isValidActionName,
  tierSatisfies,
  validateActionInput
} from './ActionRegistry';

export type {
  ActionContext,
  ActionDefinition,
  ActionDescriptor,
  ActionEmitter,
  ActionError,
  ActionErrorCode,
  ActionFieldError,
  ActionFieldSchema,
  ActionFieldType,
  ActionHandler,
  ActionInputSchema,
  ActionInvocation,
  ActionModule,
  TierResolver
} from './ActionRegistry';

// ═══════════════════════════════════════════════════════════════════════════
// SERVER
// ═══════════════════════════════════════════════════════════════════════════

export { AlephServer, registeredShutdownStepCount } from './Server';

export type { AlephServerOptions } from './Server';
