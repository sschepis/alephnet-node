/**
 * AlephNode HTTP Server
 *
 * Composition root for the application layer: Router + AuthMiddleware +
 * StreamHub + optional StaticServer + optional authenticated WebSocket
 * upgrades, all on a single plain `http` server (the legacy server mixed
 * Express Routers into a raw http callback where they were never invoked).
 *
 * Lifecycle guarantees (flaw #3):
 *  - the http server carries a permanent 'error' handler, so EADDRINUSE rejects
 *    start() with a typed error instead of crashing with a raw stack
 *  - 'error'/'aborted' events on every inbound request, response and socket are
 *    handled, so a dead client can never take the process down
 *  - signal handlers are installed exactly once per process, not once per
 *    start() call, and each server's shutdown step is deregistered on stop()
 *  - stop() closes WebSocket peers, shuts the StreamHub (SSE clients +
 *    heartbeat), disposes the auth cache timers and drains keep-alive sockets
 *
 * Information disclosure (flaw #6):
 *  - internal messages and stacks are logged server-side only; 500s carry a
 *    correlation id and nothing else
 *  - `req.headers.host` is never read, so it can never be reflected
 */

import * as crypto from 'crypto';
import * as http from 'http';
import type { IncomingMessage, ServerResponse } from 'http';
import type { Socket } from 'net';
import { ERROR_CODES } from '../common/constants';
import { createLogger, Logger } from '../common/logging';
import { isErr } from '../common/patterns/Result';
import { ActionRegistry } from './ActionRegistry';
import { AuthMiddleware } from './AuthMiddleware';
import { Router, createResponseWriter, readRequestBody, writeErrorResponse } from './Router';
import { StaticServer } from './StaticServer';
import { StreamHub } from './StreamHub';
import {
  AUTH_HEADERS,
  AuthenticatedIdentity,
  DevAuthBypass,
  HttpError,
  HttpMethod,
  ParsedBody,
  RequestContext,
  ResponseWriter,
  ServerConfig,
  ServerOptions,
  WebSocketConfig,
  WebSocketHandler,
  WebSocketLike,
  WebSocketPeer,
  WebSocketServerFactory,
  WebSocketServerLike,
  resolveServerConfig
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// ONE-TIME SIGNAL REGISTRATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The legacy server called `process.on('SIGINT', ...)` inside start(), so every
 * restart added another handler and another `process.exit(0)` racing the
 * others. Handlers here are installed at most once per process; individual
 * servers register and deregister a shutdown step instead.
 */
let signalsInstalled = false;
const shutdownSteps = new Set<() => Promise<void>>();

function installSignalHandlersOnce(logger: Logger): void {
  if (signalsInstalled) return;
  signalsInstalled = true;

  const onSignal = (signal: string): void => {
    logger.warn(`Received ${signal}; shutting down`, { steps: shutdownSteps.size });

    let finished = false;
    const forceTimer = setTimeout(() => {
      if (finished) return;
      logger.fatal('Forced exit: graceful shutdown timed out');
      process.exit(1);
    }, 30_000);
    forceTimer.unref();

    void (async () => {
      try {
        await Promise.allSettled([...shutdownSteps].map((step) => step()));
      } finally {
        finished = true;
        clearTimeout(forceTimer);
        process.exit(0);
      }
    })();
  };

  process.once('SIGINT', () => onSignal('SIGINT'));
  process.once('SIGTERM', () => onSignal('SIGTERM'));
}

/**
 * Number of registered shutdown steps — used by tests to prove that repeated
 * start()/stop() cycles do not accumulate handlers.
 */
export function registeredShutdownStepCount(): number {
  return shutdownSteps.size;
}

// ═══════════════════════════════════════════════════════════════════════════
// OPTIONS
// ═══════════════════════════════════════════════════════════════════════════

export interface AlephServerOptions extends ServerOptions {
  readonly logger?: Logger;
  /** Pre-built auth middleware (e.g. with a shared nonce cache) */
  readonly auth?: AuthMiddleware;
  readonly actions?: ActionRegistry;
  readonly router?: Router;
  readonly streamHub?: StreamHub;
  /**
   * Explicit, non-production auth bypass.
   *
   * This is a CONSTRUCTOR-ONLY option: `ServerConfig.devAuthBypass` is typed
   * `false`, so no configuration object — and no environment variable — can
   * express it. Building the value requires `createDevAuthBypass()` with its
   * acknowledgement literal, and AuthMiddleware refuses to construct with it
   * under NODE_ENV=production (flaw #1).
   */
  readonly unsafeDevAuthBypass?: DevAuthBypass;
  /** noServer WebSocket server constructor; defaults to lazily loading `ws` */
  readonly webSocketServerFactory?: WebSocketServerFactory;
  /** Invoked for every authenticated WebSocket peer */
  readonly onWebSocketConnection?: WebSocketHandler;
  readonly logRequests?: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// SERVER
// ═══════════════════════════════════════════════════════════════════════════

export class AlephServer {
  readonly config: ServerConfig;
  readonly logger: Logger;

  private readonly router: Router;
  private readonly auth: AuthMiddleware;
  private readonly streams: StreamHub;
  private readonly staticServer: StaticServer | null;
  private readonly actions: ActionRegistry | null;
  private readonly onWebSocketConnection: WebSocketHandler | null;
  private readonly webSocketServerFactory: WebSocketServerFactory | null;
  private readonly logRequests: boolean;

  private httpServer: http.Server | null = null;
  private wss: WebSocketServerLike | null = null;
  private readonly peers = new Map<string, WebSocketPeer>();
  private readonly sockets = new Set<Socket>();
  private shutdownStep: (() => Promise<void>) | null = null;
  private startedAt = 0;
  private stopping = false;
  private stopped = false;
  /** True when this server constructed its own AuthMiddleware */
  private readonly ownsAuth: boolean;
  /** Upgrade slots reserved but not yet attached (atomic connection cap) */
  private upgradeReservations = 0;

  constructor(options: AlephServerOptions = {}) {
    this.logger = options.logger ?? createLogger('app:server');
    this.config = resolveServerConfig(options);

    this.router = options.router ?? new Router();
    this.ownsAuth = options.auth === undefined;
    this.auth =
      options.auth ??
      new AuthMiddleware(
        {
          freshnessMs: this.config.authFreshnessMs,
          nonceCache: this.config.nonceCache,
          rateLimiter: this.config.rateLimiter,
          devBypass: options.unsafeDevAuthBypass
        },
        this.logger.child({ component: 'app:auth' })
      );
    this.streams =
      options.streamHub ??
      new StreamHub(this.config.stream, this.logger.child({ component: 'app:sse' }));
    this.staticServer =
      this.config.staticPath === undefined
        ? null
        : new StaticServer(
            {
              root: this.config.staticPath,
              spaFallback: this.config.staticSpaFallback,
              maxFileBytes: this.config.staticMaxFileBytes
            },
            this.logger.child({ component: 'app:static' })
          );
    this.actions = options.actions ?? null;
    this.onWebSocketConnection = options.onWebSocketConnection ?? null;
    this.webSocketServerFactory = options.webSocketServerFactory ?? null;
    this.logRequests = options.logRequests ?? false;

    this.registerSystemRoutes();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // ACCESSORS
  // ─────────────────────────────────────────────────────────────────────────

  /** Router, so the composition root (and tests) can add routes */
  get routes(): Router {
    return this.router;
  }

  get authMiddleware(): AuthMiddleware {
    return this.auth;
  }

  get streamHub(): StreamHub {
    return this.streams;
  }

  get actionRegistry(): ActionRegistry | null {
    return this.actions;
  }

  get webSocketPeers(): readonly WebSocketPeer[] {
    return [...this.peers.values()];
  }

  /** Actual bound port (resolves ephemeral port 0 once listening) */
  get port(): number {
    const address = this.httpServer?.address();
    if (address !== null && address !== undefined && typeof address === 'object') {
      return address.port;
    }
    return this.config.port;
  }

  get listening(): boolean {
    return this.httpServer?.listening ?? false;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // LIFECYCLE
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Bind and start serving. Rejects with a typed error if the port cannot be
   * bound; the raw EADDRINUSE stack never reaches stderr as an uncaught throw.
   */
  async start(): Promise<void> {
    if (this.stopped) {
      throw new Error('AlephServer instance was stopped and cannot be restarted');
    }
    if (this.httpServer !== null) {
      throw new Error('AlephServer is already started');
    }

    this.stopping = false;
    this.streams.reset();

    const server = http.createServer((req, res) => {
      void this.handleRequest(req, res);
    });
    this.httpServer = server;

    // Permanent handler: post-listen errors are logged, never thrown
    server.on('error', (error: NodeJS.ErrnoException) => {
      this.logger.error('HTTP server error', error, { code: error.code ?? 'unknown' });
    });

    server.on('clientError', (error: Error, socket: Socket) => {
      this.logger.debug('Client protocol error', { message: error.message });
      if (!socket.writable || socket.destroyed) {
        socket.destroy();
        return;
      }
      try {
        socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      } catch {
        socket.destroy();
      }
    });

    // Track sockets so shutdown can drain keep-alive connections
    server.on('connection', (socket: Socket) => {
      this.sockets.add(socket);
      socket.once('close', () => this.sockets.delete(socket));
      socket.on('error', (error: Error) => {
        this.logger.debug('Client socket error', { message: error.message });
      });
    });

    // Slow-loris protection for headers. `requestTimeout` is deliberately left
    // alone: it would abort long-lived SSE responses.
    server.headersTimeout = Math.max(1_000, this.config.requestTimeoutMs);
    server.keepAliveTimeout = 5_000;

    if (this.config.websocket !== null) {
      this.setupWebSocketServer();
      server.on('upgrade', (request, socket, head) => {
        void this.handleUpgrade(request, socket as Socket, head);
      });
    }

    await new Promise<void>((resolve, reject) => {
      const onError = (error: NodeJS.ErrnoException): void => {
        server.removeListener('listening', onListening);
        // Free the slot so stop() remains a harmless no-op after a failed bind
        if (this.httpServer === server) {
          this.httpServer = null;
        }
        const detail = error.code === 'EADDRINUSE' ? ' (address already in use)' : '';
        reject(
          new Error(
            `Failed to bind ${this.config.host}:${String(this.config.port)}${detail}`
          )
        );
      };
      const onListening = (): void => {
        server.removeListener('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(this.config.port, this.config.host);
    });

    this.startedAt = Date.now();

    if (this.config.installSignalHandlers) {
      installSignalHandlersOnce(this.logger);
      if (this.shutdownStep === null) {
        const step = (): Promise<void> => this.stop();
        this.shutdownStep = step;
        shutdownSteps.add(step);
      }
    }

    this.logger.info('AlephNode HTTP server listening', {
      host: this.config.host,
      port: this.port,
      staticPath: this.config.staticPath ?? null,
      websocketPath: this.config.websocket?.path ?? null,
      routes: this.router.size
    });
  }

  /**
   * Graceful shutdown. Idempotent, and safe to call before start().
   */
  async stop(): Promise<void> {
    const server = this.httpServer;
    if (server === null) {
      this.stopped = true;
      return;
    }
    if (this.stopping) {
      return;
    }
    this.stopping = true;
    this.httpServer = null;
    this.stopped = true;

    // Deregister the shutdown step so restart cycles cannot accumulate
    if (this.shutdownStep !== null) {
      shutdownSteps.delete(this.shutdownStep);
      this.shutdownStep = null;
    }

    // 1. WebSocket peers
    for (const peer of this.peers.values()) {
      try {
        peer.socket.close(1001, 'server shutting down');
      } catch {
        try {
          peer.socket.terminate();
        } catch {
          /* already gone */
        }
      }
    }
    this.peers.clear();

    if (this.wss !== null) {
      const wss = this.wss;
      this.wss = null;
      await new Promise<void>((resolve) => {
        try {
          wss.close(() => resolve());
        } catch {
          resolve();
        }
        setTimeout(resolve, 500).unref();
      });
    }

    // 2. SSE clients + heartbeat timer
    await this.streams.shutdown('server-shutdown');

    // 3. Nonce cache / rate limiter timers — ONLY when this server created the
    //    auth middleware. A shared AuthMiddleware passed in via options is
    //    owned by its creator: disposing it here would silently kill replay
    //    protection for every other server still using it.
    if (this.ownsAuth) {
      this.auth.dispose();
    }

    // 4. Stop accepting, then drain
    await new Promise<void>((resolve) => {
      let settled = false;
      const done = (): void => {
        if (settled) return;
        settled = true;
        resolve();
      };

      server.close(done);

      const drain = setTimeout(() => {
        for (const socket of this.sockets) {
          try {
            socket.destroy();
          } catch {
            /* already destroyed */
          }
        }
        this.sockets.clear();
        done();
      }, Math.max(1, this.config.shutdownGraceMs));
      drain.unref();

      // Idle keep-alive sockets are not closed by server.close()
      const closeIdle = (server as http.Server & { closeIdleConnections?: () => void })
        .closeIdleConnections;
      if (typeof closeIdle === 'function') {
        closeIdle.call(server);
      }
    });

    this.sockets.clear();
    this.stopping = false;
    this.logger.info('AlephNode HTTP server stopped');
  }

  // ─────────────────────────────────────────────────────────────────────────
  // SYSTEM ROUTES
  // ─────────────────────────────────────────────────────────────────────────

  private registerSystemRoutes(): void {
    this.router.get(
      '/health',
      (_ctx, res) => {
        res.json({
          status: this.stopping ? 'stopping' : 'ok',
          uptimeMs: this.startedAt === 0 ? 0 : Date.now() - this.startedAt
        });
      },
      { auth: 'public', description: 'Liveness probe' }
    );

    this.router.get(
      '/status',
      (_ctx, res) => {
        // Note: no Host header, no origin and no internal paths in this body
        res.json({
          status: this.stopping ? 'stopping' : 'running',
          uptimeMs: this.startedAt === 0 ? 0 : Date.now() - this.startedAt,
          routes: this.router.size,
          actions: this.actions?.size ?? 0,
          streams: this.streams.stats(),
          websocket: {
            enabled: this.config.websocket !== null,
            path: this.config.websocket?.path ?? null,
            peers: this.peers.size
          },
          staticEnabled: this.staticServer !== null,
          authBypassActive: this.auth.bypassActive,
          nonceCacheSize: this.auth.nonceCache.size
        });
      },
      { auth: 'public', description: 'Node status' }
    );

    this.router.get(
      '/whoami',
      (ctx, res) => {
        const identity = ctx.identity;
        res.json({
          authenticated: identity !== null,
          fingerprint: identity?.fingerprint ?? null,
          publicKey: identity?.publicKey ?? null,
          devBypass: identity?.devBypass ?? false
        });
      },
      { description: 'Echo the verified caller identity' }
    );

    // SSE: registers with the hub so broadcasts actually reach clients (flaw #5)
    this.router.get(
      '/stream/:channel',
      (ctx, res) => {
        const channel = ctx.params.channel ?? 'all';
        const registered = this.streams.register({
          req: ctx.raw.req,
          res: ctx.raw.res,
          channel,
          identity: ctx.identity
        });
        if (!registered.ok) {
          throw registered.error;
        }
        ctx.logger.debug('SSE stream opened', {
          channel,
          clientId: registered.value.id,
          fingerprint: ctx.identity?.fingerprint ?? null
        });
      },
      { streaming: true, description: 'Subscribe to a server-sent event channel' }
    );

    if (this.actions !== null) {
      this.registerActionRoutes(this.actions);
    }
  }

  private registerActionRoutes(actions: ActionRegistry): void {
    this.router.get(
      '/actions/list',
      (_ctx, res) => {
        res.json({ actions: actions.describe() });
      },
      { auth: 'public', description: 'Catalogue of available actions' }
    );

    this.router.post(
      '/actions/:name',
      async (ctx, res) => {
        const name = ctx.params.name;
        if (name === undefined || name.length === 0) {
          throw HttpError.badRequest(ERROR_CODES.E_VALIDATION_INPUT, 'Missing action name');
        }

        const input =
          typeof ctx.body === 'object' && ctx.body !== null && !Array.isArray(ctx.body)
            ? (ctx.body as Record<string, unknown>)
            : {};

        // Wire the documented ActionContext.signal: abort when the client
        // disconnects so long-running actions can stop early.
        const controller = new AbortController();
        const abort = (): void => controller.abort();
        ctx.raw.req.once('aborted', abort);
        ctx.raw.req.once('error', abort);
        ctx.raw.res.once('close', abort);

        // Wire the documented ActionContext.emit: streaming actions push
        // progress events to the caller's own SSE clients via the StreamHub.
        const fingerprint = ctx.identity?.fingerprint ?? null;
        const emit: (event: string, data: unknown) => void =
          fingerprint === null
            ? () => undefined
            : (event, data) => {
                this.streams.broadcastToFingerprint(fingerprint, event, data);
              };

        const result = await actions.invoke(name, input, {
          identity: ctx.identity,
          requestId: ctx.requestId,
          logger: ctx.logger,
          receivedAt: ctx.receivedAt,
          signal: controller.signal,
          emit
        });

        if (!result.ok) {
          throw ActionRegistry.toHttpError(result.error);
        }

        res.json(result.value);
      },
      {
        // Per-action auth: the registry enforces requiresAuth/tier per action,
        // so the route itself must not reject public actions upfront.
        auth: 'optional',
        description: 'Invoke a named action'
      }
    );
  }

  // ─────────────────────────────────────────────────────────────────────────
  // REQUEST PIPELINE
  // ─────────────────────────────────────────────────────────────────────────

  private isApiPath(pathname: string): boolean {
    return this.config.apiPrefixes.some(
      (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
    );
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Flaw #3: unhandled 'error' events on either stream used to crash the node
    req.on('error', (error: Error) => {
      this.logger.debug('Request stream error', { message: error.message });
    });
    res.on('error', (error: Error) => {
      this.logger.debug('Response stream error', { message: error.message });
    });

    const requestId = crypto.randomBytes(8).toString('hex');
    const receivedAt = Date.now();
    const logger = this.logger.child({ requestId });
    const writer = createResponseWriter(res, { requestId });
    // The signature must cover the ACTUAL method sent on the wire: a HEAD
    // request served by a GET route is still signed as 'HEAD' (the payload
    // builder upper-cases, so 'head' also verifies — but a client that signs
    // 'GET' while sending 'HEAD' is rejected even though the handler and
    // status are identical).
    const method = (req.method ?? 'GET').toUpperCase() as HttpMethod;

    // Fixed internal base: `req.headers.host` is untrusted and unused (flaw #6)
    let pathname: string;
    let search: string;
    const query: Record<string, string> = {};
    try {
      const url = new URL(req.url ?? '/', 'http://internal.invalid');
      pathname = url.pathname;
      search = url.search;
      for (const [key, value] of url.searchParams) {
        query[key] = value;
      }
    } catch {
      writeErrorResponse(
        writer,
        HttpError.badRequest(ERROR_CODES.E_VALIDATION_INPUT, 'Malformed request target'),
        requestId,
        logger
      );
      return;
    }

    // The WHATWG parser tolerates invalid percent-encoding in path/query, so
    // validate explicitly and 400 before any routing decision
    try {
      decodeURIComponent(pathname);
      decodeURIComponent(search);
    } catch {
      writeErrorResponse(
        writer,
        HttpError.badRequest(
          ERROR_CODES.E_VALIDATION_INPUT,
          'Malformed percent-encoding in request target'
        ),
        requestId,
        logger
      );
      return;
    }

    const target = `${pathname}${search}`;
    const remoteAddress = req.socket.remoteAddress ?? 'unknown';
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === undefined) continue;
      headers[name.toLowerCase()] = Array.isArray(value) ? value.join(',') : String(value);
    }

    try {
      if (this.stopping) {
        throw new HttpError(503, ERROR_CODES.E_SERVICE_UNAVAILABLE, 'Server is shutting down');
      }

      // ── Aggregate rate limit (per-IP total budget, ANY path) ─────────────
      // Enforced before CORS so OPTIONS preflights and CORS-403 rejections
      // also consume (and can be rejected by) the aggregate budget — a path
      // spray can no longer evade limiting by hitting unbounded distinct
      // paths or by flying through the preflight path.
      const aggregateDecision = this.auth.enforceAggregateRateLimit(
        `aggregate:${remoteAddress}`,
        receivedAt
      );
      if (isErr(aggregateDecision)) {
        throw aggregateDecision.error;
      }

      // ── CORS / preflight ─────────────────────────────────────────────────
      if (!this.applyCors(req, writer, method, requestId)) {
        return;
      }

      // ── Routing ──────────────────────────────────────────────────────────
      const resolution = this.router.resolve(method, pathname);

      // ── Per-(IP, path) rate limit (bounded; applies to public routes too) ─
      // The matched route's own `rateLimit` override is honoured when present;
      // unmatched paths keep the default bucket.
      const rateDecision = this.auth.enforceRateLimit(
        `${remoteAddress}:${pathname}`,
        resolution.match?.route.rateLimit ?? undefined,
        receivedAt
      );
      if (isErr(rateDecision)) {
        throw rateDecision.error;
      }

      if (resolution.match === null) {
        if (resolution.reason === 'no-method') {
          throw new HttpError(
            405,
            ERROR_CODES.E_SERVICE_NOT_FOUND,
            `Method ${method} is not allowed for this path`,
            { headers: { Allow: resolution.allowedMethods.join(', ') } }
          );
        }

        // Flaw #2: API paths must 404 rather than fall through to index.html
        if (
          this.staticServer !== null &&
          !this.isApiPath(pathname) &&
          (method === 'GET' || method === 'HEAD')
        ) {
          const served = await this.staticServer.serve(pathname, writer, {
            suppressBody: method === 'HEAD'
          });
          if (!served.ok) {
            throw served.error;
          }
          return;
        }

        throw HttpError.notFound(ERROR_CODES.E_SERVICE_NOT_FOUND, 'Not Found');
      }

      const match = resolution.match;

      // ── Body (flaw #4: one correct, bounded, non-throwing reader) ────────
      const bodyResult = await readRequestBody(
        req,
        this.config.maxBodyBytes,
        this.config.bodyTimeoutMs
      );
      if (isErr(bodyResult)) {
        // ANY body-read failure (413 oversized, 408 stalled, 400 aborted/erred)
        // leaves unread body bytes on the socket. Without Connection: close
        // those bytes would be parsed as the start of the NEXT request on the
        // keep-alive connection — request smuggling via response desync.
        writer.header('Connection', 'close');
        throw bodyResult.error;
      }
      const rawBody = bodyResult.value;

      // ── Auth (flaw #1) ───────────────────────────────────────────────────
      let identity: AuthenticatedIdentity | null = null;
      if (match.route.auth === 'required') {
        const authResult = this.auth.authenticate({
          method,
          target,
          headers,
          rawBody,
          remoteAddress,
          now: receivedAt
        });
        if (isErr(authResult)) {
          throw authResult.error;
        }
        identity = authResult.value;
      } else if (match.route.auth === 'optional') {
        // Verify when signature headers are present (invalid ones are
        // rejected); headerless requests continue with identity = null.
        // Exception: with the dev bypass active, EVERY request is verified
        // so optional routes receive the loud dev identity instead of null.
        const presented = [
          headers[AUTH_HEADERS.FINGERPRINT],
          headers[AUTH_HEADERS.SIGNATURE],
          headers[AUTH_HEADERS.TIMESTAMP],
          headers[AUTH_HEADERS.NONCE]
        ].some((value) => value !== undefined);
        if (presented || this.auth.bypassActive) {
          const authResult = this.auth.authenticate({
            method,
            target,
            headers,
            rawBody,
            remoteAddress,
            now: receivedAt
          });
          if (isErr(authResult)) {
            throw authResult.error;
          }
          identity = authResult.value;
        }
      }

      // ── Parse & dispatch ─────────────────────────────────────────────────
      let body: ParsedBody;
      if (!match.route.streaming) {
        const parsed = Router.parseBody(rawBody, headers['content-type']);
        if (isErr(parsed)) {
          throw parsed.error;
        }
        body = parsed.value;
      }

      const ctx: RequestContext = {
        requestId,
        method,
        path: pathname,
        target,
        query,
        params: match.params,
        headers,
        rawBody,
        body,
        identity,
        remoteAddress,
        receivedAt,
        logger,
        raw: { req, res }
      };

      await this.router.dispatch(match, ctx, writer);

      if (this.logRequests) {
        logger.info('Request completed', {
          method,
          path: pathname,
          status: writer.statusCode,
          durationMs: Date.now() - receivedAt,
          authenticated: identity !== null
        });
      }
    } catch (error) {
      writeErrorResponse(writer, error, requestId, logger);
    }
  }

  /**
   * CORS with an exact-match Origin allowlist.
   *
   * Returns false when this function has already written the response.
   * An empty allowlist means "no CORS headers" (same-origin only), never "*".
   */
  private applyCors(
    req: IncomingMessage,
    writer: ResponseWriter,
    method: HttpMethod,
    requestId: string
  ): boolean {
    const origin = req.headers.origin;
    const allowlist = this.config.corsOrigins;

    if (origin !== undefined && allowlist.length > 0) {
      const wildcard = allowlist.includes('*');
      if (!wildcard && !allowlist.includes(origin)) {
        writer.json(
          {
            error: 'Origin not allowed',
            code: ERROR_CODES.E_AUTH_PERMISSION_DENIED,
            requestId
          },
          403
        );
        return false;
      }

      writer.header('Access-Control-Allow-Origin', wildcard ? '*' : origin);
      if (!wildcard) {
        writer.header('Vary', 'Origin');
        writer.header('Access-Control-Allow-Credentials', 'true');
      }
      writer.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
      writer.header(
        'Access-Control-Allow-Headers',
        'Content-Type, X-Aleph-Fingerprint, X-Aleph-Public-Key, X-Aleph-Signature, X-Aleph-Timestamp, X-Aleph-Nonce'
      );
      writer.header('Access-Control-Max-Age', '600');
    }

    if (method === 'OPTIONS') {
      writer.empty(204);
      return false;
    }

    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // WEBSOCKETS (flaw #7)
  // ─────────────────────────────────────────────────────────────────────────

  private setupWebSocketServer(): void {
    const config = this.config.websocket;
    if (config === null) return;

    const factory = this.webSocketServerFactory ?? loadWsFactory(this.logger);
    if (factory === null) {
      this.logger.warn('WebSocket support unavailable: could not load `ws`');
      return;
    }

    const wss = factory({ noServer: true, maxPayload: config.maxMessageBytes });
    wss.on('error', (error: unknown) => {
      this.logger.error(
        'WebSocket server error',
        error instanceof Error ? error : new Error('unknown websocket error')
      );
    });
    this.wss = wss;
  }

  /**
   * Authenticated upgrade:
   *  - Origin validated against an explicit allowlist (never `*` by default).
   *    The ABSENCE of an Origin header is accepted: non-browser clients (the
   *    node CLI, agents, daemon-to-daemon links) do not send one, and rejecting
   *    them would break every programmatic peer. Browsers always send Origin,
   *    so cross-site WebSocket hijacking still requires an allowlist match.
   *  - upgrade attempts consume the aggregate per-IP rate budget, so a flood
   *    of upgrade handshakes is limited like any other request storm
   *  - the SAME signed-request verification as HTTP, over the upgrade target
   *    and the empty-body hash
   *  - identity derived from the verified public key, never from a `nodeId`
   *    query parameter
   *  - the connection cap is enforced atomically: a slot is RESERVED at check
   *    time and only converted into a peer (or released) later, so N
   *    interleaved upgrades can never all pass a check-and-add race
   */
  private async handleUpgrade(
    request: IncomingMessage,
    socket: Socket,
    head: Buffer
  ): Promise<void> {
    socket.on('error', () => {
      try {
        socket.destroy();
      } catch {
        /* already destroyed */
      }
    });

    const config = this.config.websocket;
    const wss = this.wss;
    if (config === null || wss === null) {
      rejectUpgrade(socket, 404);
      return;
    }

    if (this.stopping) {
      rejectUpgrade(socket, 503);
      return;
    }

    // Aggregate per-IP budget covers upgrade attempts too
    const aggregateDecision = this.auth.enforceAggregateRateLimit(
      `aggregate:${socket.remoteAddress ?? 'unknown'}`
    );
    if (isErr(aggregateDecision)) {
      this.logger.warn('Rejected WebSocket upgrade over rate budget', {
        remoteAddress: socket.remoteAddress ?? 'unknown'
      });
      rejectUpgrade(socket, 429);
      return;
    }

    let pathname: string;
    let target: string;
    try {
      const url = new URL(request.url ?? '/', 'http://internal.invalid');
      pathname = url.pathname;
      target = `${pathname}${url.search}`;
    } catch {
      rejectUpgrade(socket, 400);
      return;
    }

    if (pathname !== config.path) {
      rejectUpgrade(socket, 404);
      return;
    }

    const allowedOrigins = config.allowedOrigins ?? this.config.corsOrigins;
    const origin = request.headers.origin;
    if (origin !== undefined && !allowedOrigins.includes(origin)) {
      this.logger.warn('Rejected WebSocket upgrade from disallowed origin', { origin });
      rejectUpgrade(socket, 403);
      return;
    }

    // Atomic cap: reserve the slot BEFORE any async boundary so concurrent
    // upgrades cannot all observe "under the cap". The reservation is
    // released on every rejection path and converted into a real peer slot
    // synchronously inside the attach callback.
    if (this.peers.size + this.upgradeReservations >= config.maxConnections) {
      rejectUpgrade(socket, 503);
      return;
    }
    this.upgradeReservations++;
    const releaseReservation = (): void => {
      if (this.upgradeReservations > 0) {
        this.upgradeReservations--;
      }
    };
    // If the socket dies before wss.handleUpgrade attaches a peer, release
    let attached = false;
    const releaseIfUnattached = (): void => {
      if (attached) return;
      attached = true;
      releaseReservation();
    };
    socket.once('close', releaseIfUnattached);

    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      if (value === undefined) continue;
      headers[name.toLowerCase()] = Array.isArray(value) ? value.join(',') : String(value);
    }

    const authResult = this.auth.authenticate({
      method: 'GET',
      target,
      headers,
      rawBody: Buffer.alloc(0),
      remoteAddress: socket.remoteAddress ?? 'unknown'
    });
    if (isErr(authResult)) {
      this.logger.warn('Rejected unauthenticated WebSocket upgrade', {
        reason: authResult.error.code
      });
      releaseIfUnattached();
      rejectUpgrade(socket, 401);
      return;
    }

    const identity = authResult.value;
    const peerId = `ws_${crypto.randomBytes(8).toString('hex')}`;

    try {
      wss.handleUpgrade(request, socket, head, (ws: WebSocketLike) => {
        const peer: WebSocketPeer = {
          id: peerId,
          identity,
          socket: ws,
          connectedAt: Date.now()
        };
        // Reservation converts into a live peer slot in the same synchronous
        // tick, so the cap can never be oversubscribed.
        releaseIfUnattached();
        this.peers.set(peerId, peer);

        const detach = (): void => {
          this.peers.delete(peerId);
        };
        ws.once('close', detach);
        ws.on('error', () => {
          try {
            ws.terminate();
          } catch {
            /* already gone */
          }
          detach();
        });

        try {
          // Identity is echoed from the verified key, not from the query string
          ws.send(
            JSON.stringify({ type: 'welcome', peerId, fingerprint: identity.fingerprint })
          );
        } catch {
          detach();
          return;
        }

        this.logger.info('WebSocket peer connected', {
          peerId,
          fingerprint: identity.fingerprint
        });

        this.onWebSocketConnection?.(peer);
      });
    } catch {
      releaseIfUnattached();
      rejectUpgrade(socket, 500);
    }
  }

  /**
   * Send a frame to one authenticated peer
   */
  sendToPeer(peerId: string, message: string): boolean {
    const peer = this.peers.get(peerId);
    if (peer === undefined) return false;
    try {
      peer.socket.send(message);
      return true;
    } catch {
      return false;
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

const UPGRADE_REJECTION_REASONS: Readonly<Record<number, string>> = {
  400: 'Bad Request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not Found',
  429: 'Too Many Requests',
  500: 'Internal Server Error',
  503: 'Service Unavailable'
};

function rejectUpgrade(socket: Socket, status: number): void {
  if (socket.destroyed) return;
  const reason = UPGRADE_REJECTION_REASONS[status] ?? 'Bad Request';
  try {
    if (socket.writable) {
      socket.write(
        `HTTP/1.1 ${String(status)} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`
      );
    }
  } catch {
    /* socket already gone */
  }
  socket.destroy();
}

/**
 * Lazily load `ws` behind the locally declared structural interfaces, so this
 * layer compiles without @types/ws and degrades gracefully if the package is
 * missing.
 */
function loadWsFactory(logger: Logger): WebSocketServerFactory | null {
  try {
    const ws = require('ws') as {
      WebSocketServer?: new (options: {
        noServer: true;
        maxPayload?: number;
      }) => WebSocketServerLike;
      Server?: new (options: {
        noServer: true;
        maxPayload?: number;
      }) => WebSocketServerLike;
    };
    const Ctor = ws.WebSocketServer ?? ws.Server;
    if (Ctor === undefined) return null;
    return (options) => new Ctor(options);
  } catch (error) {
    logger.warn('Failed to load ws', {
      message: error instanceof Error ? error.message : 'unknown'
    });
    return null;
  }
}
