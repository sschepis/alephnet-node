/**
 * Typed HTTP Router
 *
 * A small router built directly on Node's `http` module. The legacy server
 * mixed Express Routers into a plain `http.createServer` callback, so those
 * routers were never invoked; this layer picks one model — plain `http` — and
 * implements matching, body parsing and error handling explicitly.
 *
 * Two deliberate behaviours:
 *  - routes require authentication unless they explicitly opt out with
 *    `auth: 'public'`, so a newly added route is secure by default
 *  - the body reader actually returns the parsed body (the legacy `readBody`
 *    resolved a string and never assigned `req.body`, so every consumer that
 *    destructured `req.body` threw a TypeError and 500'd)
 */

import type { IncomingMessage, ServerResponse } from 'http';
import { ERROR_CODES } from '../common/constants';
import { Logger } from '../common/logging';
import { Result, ok, err, isErr } from '../common/patterns/Result';
import {
  ErrorResponseBody,
  HTTP_METHODS,
  HttpError,
  HttpMethod,
  ParsedBody,
  RequestContext,
  ResponseWriter,
  RouteDefinition,
  RouteHandler,
  RouteMatch,
  RouteOptions,
  RouteResolution,
  isHttpError
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// BODY READING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Read the request body into a single Buffer, enforcing a hard byte limit and
 * an optional completion deadline.
 *
 * Never rejects: transport failures, oversized payloads and stalled uploads all
 * come back as typed HttpErrors so a malformed request can never take the
 * process down.
 */
export function readRequestBody(
  req: IncomingMessage,
  maxBytes: number,
  timeoutMs = 0
): Promise<Result<Buffer, HttpError>> {
  return new Promise<Result<Buffer, HttpError>>((resolve) => {
    const declared = req.headers['content-length'];
    if (declared !== undefined) {
      const declaredBytes = Number.parseInt(declared, 10);
      if (Number.isFinite(declaredBytes) && declaredBytes > maxBytes) {
        resolve(
          err(
            HttpError.payloadTooLarge(
              ERROR_CODES.E_RESOURCE_EXHAUSTED,
              `Request body exceeds ${String(maxBytes)} bytes`
            )
          )
        );
        return;
      }
    }

    const chunks: Buffer[] = [];
    let received = 0;
    let settled = false;
    let timer: NodeJS.Timeout | null = null;

    const finish = (value: Result<Buffer, HttpError>): void => {
      if (settled) return;
      settled = true;
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      req.removeListener('aborted', onAborted);
      resolve(value);
    };

    const onData = (chunk: Buffer | string): void => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      received += buf.length;
      if (received > maxBytes) {
        finish(
          err(
            HttpError.payloadTooLarge(
              ERROR_CODES.E_RESOURCE_EXHAUSTED,
              `Request body exceeds ${String(maxBytes)} bytes`
            )
          )
        );
        // Stop reading; the caller will answer 413 and close the connection
        req.pause();
        return;
      }
      chunks.push(buf);
    };

    const onEnd = (): void => {
      finish(ok(chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, received)));
    };

    const onError = (): void => {
      finish(
        err(
          new HttpError(
            400,
            ERROR_CODES.E_VALIDATION_INPUT,
            'Request stream failed before the body was fully received'
          )
        )
      );
    };

    const onAborted = (): void => {
      finish(
        err(
          new HttpError(
            400,
            ERROR_CODES.E_VALIDATION_INPUT,
            'Request aborted by client'
          )
        )
      );
    };

    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('aborted', onAborted);

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        finish(
          err(
            new HttpError(
              408,
              ERROR_CODES.E_NETWORK_TIMEOUT,
              'Timed out while reading the request body'
            )
          )
        );
      }, timeoutMs);
      timer.unref();
    }
  });
}

/**
 * Parse a raw body according to its content type.
 *
 * Malformed JSON produces a typed 400 — `JSON.parse` is never allowed to throw
 * out of this function.
 */
export function parseRequestBody(
  raw: Buffer,
  contentType: string | undefined
): Result<ParsedBody, HttpError> {
  if (raw.length === 0) {
    return ok(undefined);
  }

  const mime = (contentType ?? '').split(';')[0].trim().toLowerCase();

  if (mime === '' || mime === 'application/json' || mime.endsWith('+json')) {
    let text: string;
    try {
      text = raw.toString('utf8');
    } catch {
      return err(
        HttpError.badRequest(ERROR_CODES.E_VALIDATION_INPUT, 'Body is not valid UTF-8')
      );
    }
    try {
      const parsed = JSON.parse(text) as unknown;
      if (parsed === null) return ok(undefined);
      if (typeof parsed === 'object') {
        return ok(parsed as Record<string, unknown> | unknown[]);
      }
      // Scalars are legal JSON but not a useful request body shape
      return ok(String(parsed));
    } catch {
      return err(
        HttpError.badRequest(ERROR_CODES.E_VALIDATION_INPUT, 'Malformed JSON body')
      );
    }
  }

  if (mime === 'application/x-www-form-urlencoded') {
    try {
      const params = new URLSearchParams(raw.toString('utf8'));
      const result: Record<string, unknown> = {};
      for (const [key, value] of params) {
        result[key] = value;
      }
      return ok(result);
    } catch {
      return err(
        HttpError.badRequest(ERROR_CODES.E_VALIDATION_INPUT, 'Malformed form body')
      );
    }
  }

  if (mime.startsWith('text/')) {
    return ok(raw.toString('utf8'));
  }

  return ok(raw);
}

// ═══════════════════════════════════════════════════════════════════════════
// RESPONSE WRITER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Wrap a ServerResponse in the typed, write-once ResponseWriter surface
 */
export function createResponseWriter(
  res: ServerResponse,
  options: { suppressBody?: boolean; requestId?: string } = {}
): ResponseWriter {
  let status = 200;
  let sent = false;
  const suppressBody = options.suppressBody === true;

  if (options.requestId !== undefined && !res.headersSent) {
    res.setHeader('X-Request-Id', options.requestId);
  }

  const writer: ResponseWriter = {
    get sent(): boolean {
      return sent || res.writableEnded || res.headersSent;
    },
    get statusCode(): number {
      return status;
    },
    status(code: number): ResponseWriter {
      status = code;
      return writer;
    },
    header(name: string, value: string): ResponseWriter {
      if (!res.headersSent) {
        res.setHeader(name, value);
      }
      return writer;
    },
    json(payload: unknown, code?: number): void {
      if (writer.sent) return;
      sent = true;
      let serialized: string;
      try {
        serialized = JSON.stringify(payload ?? null);
      } catch {
        serialized = JSON.stringify({ error: 'Response serialization failed' });
      }
      const body = Buffer.from(serialized, 'utf8');
      res.writeHead(code ?? status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': String(body.length)
      });
      res.end(suppressBody ? undefined : body);
    },
    text(body: string, code?: number, contentType = 'text/plain; charset=utf-8'): void {
      if (writer.sent) return;
      sent = true;
      const buf = Buffer.from(body, 'utf8');
      res.writeHead(code ?? status, {
        'Content-Type': contentType,
        'Content-Length': String(buf.length)
      });
      res.end(suppressBody ? undefined : buf);
    },
    buffer(body: Buffer, contentType: string, code?: number): void {
      if (writer.sent) return;
      sent = true;
      res.writeHead(code ?? status, {
        'Content-Type': contentType,
        'Content-Length': String(body.length)
      });
      res.end(suppressBody ? undefined : body);
    },
    empty(code: number): void {
      if (writer.sent) return;
      sent = true;
      res.writeHead(code);
      res.end();
    },
    get raw(): ServerResponse {
      return res;
    }
  };

  return writer;
}

// ═══════════════════════════════════════════════════════════════════════════
// ERROR RESPONSES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Convert any thrown value into a client-safe response.
 *
 * Only HttpError messages reach the client. Everything else becomes a generic
 * 500 carrying just the correlation id — internal messages, stacks and codes
 * are logged server-side only (flaw #6).
 *
 * Safe even when the handler already started writing: if the response headers
 * are already on the wire (a streaming handler that threw mid-stream), a second
 * writeHead would throw and leave the connection hung. Instead the socket is
 * destroyed so the client observes a closed connection rather than a stall —
 * and this function never throws.
 */
export function writeErrorResponse(
  res: ResponseWriter,
  error: unknown,
  requestId: string,
  logger: Logger
): void {
  const raw = res.raw;

  // Headers already sent (e.g. a streaming handler wrote the SSE head and then
  // threw): writing another head would throw. End the connection instead of
  // hanging it. A fully-finished response needs nothing at all.
  if (raw.headersSent) {
    if (!raw.writableEnded) {
      logger.debug('Handler failed after headers were sent; closing connection', { requestId });
      try {
        raw.destroy();
      } catch {
        /* socket already gone */
      }
    }
    return;
  }

  if (res.sent || raw.destroyed) {
    return;
  }

  if (isHttpError(error)) {
    if (error.headers !== undefined) {
      for (const [name, value] of Object.entries(error.headers)) {
        res.header(name, value);
      }
    }
    const body: ErrorResponseBody = {
      error: error.message,
      code: error.code,
      requestId,
      ...(error.details === undefined ? {} : { details: error.details })
    };
    logger.debug('Request rejected', {
      requestId,
      status: error.status,
      code: error.code
    });
    res.json(body, error.status);
    return;
  }

  logger.error(
    'Unhandled error while serving request',
    error instanceof Error ? error : new Error('Non-Error thrown'),
    { requestId }
  );

  const body: ErrorResponseBody = {
    error: 'Internal Server Error',
    code: ERROR_CODES.E_INTERNAL_UNKNOWN,
    requestId
  };
  res.json(body, 500);
}

// ═══════════════════════════════════════════════════════════════════════════
// PATH COMPILATION
// ═══════════════════════════════════════════════════════════════════════════

type SegmentKind = 'literal' | 'param' | 'wildcard';

interface PathSegment {
  readonly kind: SegmentKind;
  readonly value: string;
}

interface CompiledRoute {
  readonly definition: RouteDefinition;
  readonly segments: readonly PathSegment[];
  readonly hasWildcard: boolean;
}

function compilePath(path: string): { segments: PathSegment[]; hasWildcard: boolean } {
  if (!path.startsWith('/')) {
    throw new Error(`Route path must start with '/': ${path}`);
  }

  const parts = path.split('/').filter((part) => part.length > 0);
  const segments: PathSegment[] = [];
  let hasWildcard = false;

  for (const part of parts) {
    if (part === '*') {
      hasWildcard = true;
      segments.push({ kind: 'wildcard', value: '*' });
      continue;
    }
    if (part.startsWith(':')) {
      const name = part.slice(1);
      if (name.length === 0) {
        throw new Error(`Route path has an unnamed parameter: ${path}`);
      }
      segments.push({ kind: 'param', value: name });
      continue;
    }
    segments.push({ kind: 'literal', value: part });
  }

  if (hasWildcard && segments[segments.length - 1].kind !== 'wildcard') {
    throw new Error(`Wildcard must be the final segment: ${path}`);
  }

  return { segments, hasWildcard };
}

function splitPath(path: string): string[] {
  return path.split('/').filter((part) => part.length > 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// ROUTER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Tiny typed router: method + path registration, path params, per-route auth.
 */
export class Router {
  private readonly routes = new Map<HttpMethod, CompiledRoute[]>();

  constructor() {
    for (const method of HTTP_METHODS) {
      this.routes.set(method, []);
    }
  }

  /**
   * Register a route. Authentication is REQUIRED unless explicitly opted out.
   */
  register<TBody = ParsedBody>(
    method: HttpMethod,
    path: string,
    handler: RouteHandler<TBody>,
    options: RouteOptions = {}
  ): this {
    const bucket = this.routes.get(method);
    if (bucket === undefined) {
      throw new Error(`Unsupported HTTP method: ${method}`);
    }

    const { segments, hasWildcard } = compilePath(path);

    const definition: RouteDefinition = {
      method,
      path,
      auth: options.auth ?? 'required',
      description: options.description ?? '',
      streaming: options.streaming ?? false,
      rateLimit: options.rateLimit ?? null,
      handler: handler as RouteHandler<never>
    };

    const duplicate = bucket.some((route) => route.definition.path === path);
    if (duplicate) {
      throw new Error(`Duplicate route: ${method} ${path}`);
    }

    bucket.push({ definition, segments, hasWildcard });
    // Literal-heavy routes first so '/actions/list' wins over '/actions/:name'
    bucket.sort((a, b) => specificity(b) - specificity(a));
    return this;
  }

  get<TBody = ParsedBody>(
    path: string,
    handler: RouteHandler<TBody>,
    options?: RouteOptions
  ): this {
    return this.register('GET', path, handler, options);
  }

  post<TBody = ParsedBody>(
    path: string,
    handler: RouteHandler<TBody>,
    options?: RouteOptions
  ): this {
    return this.register('POST', path, handler, options);
  }

  put<TBody = ParsedBody>(
    path: string,
    handler: RouteHandler<TBody>,
    options?: RouteOptions
  ): this {
    return this.register('PUT', path, handler, options);
  }

  patch<TBody = ParsedBody>(
    path: string,
    handler: RouteHandler<TBody>,
    options?: RouteOptions
  ): this {
    return this.register('PATCH', path, handler, options);
  }

  delete<TBody = ParsedBody>(
    path: string,
    handler: RouteHandler<TBody>,
    options?: RouteOptions
  ): this {
    return this.register('DELETE', path, handler, options);
  }

  /**
   * Resolve a method + pathname.
   *
   * Distinguishes "path unknown" from "method not allowed" so the server can
   * answer 404 vs 405 correctly instead of masking both.
   */
  resolve(method: string, pathname: string): RouteResolution {
    const upper = method.toUpperCase() as HttpMethod;
    const parts = splitPath(pathname);

    const direct = this.matchIn(upper, parts);
    if (direct !== null) {
      return { match: direct, reason: null, allowedMethods: [] };
    }

    // HEAD falls back to GET with the body suppressed
    if (upper === 'HEAD') {
      const viaGet = this.matchIn('GET', parts);
      if (viaGet !== null) {
        return {
          match: { ...viaGet, suppressBody: true },
          reason: null,
          allowedMethods: []
        };
      }
    }

    const allowed: HttpMethod[] = [];
    for (const candidate of HTTP_METHODS) {
      if (candidate === upper) continue;
      if (this.matchIn(candidate, parts) !== null) {
        allowed.push(candidate);
      }
    }

    if (allowed.length > 0) {
      return { match: null, reason: 'no-method', allowedMethods: allowed };
    }

    return { match: null, reason: 'no-path', allowedMethods: [] };
  }

  /**
   * All registered routes, for status/introspection endpoints
   */
  list(): readonly RouteDefinition[] {
    const all: RouteDefinition[] = [];
    for (const bucket of this.routes.values()) {
      for (const route of bucket) {
        all.push(route.definition);
      }
    }
    return all.sort((a, b) =>
      a.path === b.path ? a.method.localeCompare(b.method) : a.path.localeCompare(b.path)
    );
  }

  get size(): number {
    let total = 0;
    for (const bucket of this.routes.values()) {
      total += bucket.length;
    }
    return total;
  }

  /**
   * Invoke a matched route, converting any thrown value into a safe response.
   */
  async dispatch(
    match: RouteMatch,
    ctx: RequestContext,
    res: ResponseWriter
  ): Promise<void> {
    try {
      await match.route.handler(ctx as RequestContext<never>, res);
      if (!res.sent && !match.route.streaming) {
        // A handler that returned without writing is a bug, not a hang
        throw new Error(`Handler for ${match.route.method} ${match.route.path} sent no response`);
      }
    } catch (error) {
      writeErrorResponse(res, error, ctx.requestId, ctx.logger);
    }
  }

  /**
   * Parse a raw body into the shape handlers expect
   */
  static parseBody(raw: Buffer, contentType: string | undefined): Result<ParsedBody, HttpError> {
    const parsed = parseRequestBody(raw, contentType);
    if (isErr(parsed)) return parsed;
    return ok(parsed.value);
  }

  private matchIn(method: HttpMethod, parts: readonly string[]): RouteMatch | null {
    const bucket = this.routes.get(method);
    if (bucket === undefined) return null;

    for (const route of bucket) {
      const params = matchSegments(route, parts);
      if (params !== null) {
        return { route: route.definition, params, suppressBody: false };
      }
    }
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// MATCHING HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function specificity(route: CompiledRoute): number {
  let score = route.segments.length * 10;
  for (const segment of route.segments) {
    if (segment.kind === 'literal') score += 3;
    if (segment.kind === 'param') score += 1;
    if (segment.kind === 'wildcard') score -= 100;
  }
  return score;
}

function matchSegments(
  route: CompiledRoute,
  parts: readonly string[]
): Record<string, string> | null {
  const { segments } = route;

  if (!route.hasWildcard && segments.length !== parts.length) {
    return null;
  }
  if (route.hasWildcard && parts.length < segments.length - 1) {
    return null;
  }

  const params: Record<string, string> = {};

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];

    if (segment.kind === 'wildcard') {
      params['*'] = parts.slice(i).join('/');
      return params;
    }

    const part = parts[i];
    if (part === undefined) return null;

    if (segment.kind === 'literal') {
      if (segment.value !== part) return null;
      continue;
    }

    let decoded: string;
    try {
      decoded = decodeURIComponent(part);
    } catch {
      return null;
    }
    if (decoded.includes('\0')) return null;
    params[segment.value] = decoded;
  }

  return params;
}
