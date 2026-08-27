/**
 * Server-Sent Events Hub
 *
 * The legacy server declared `this.sseClients = new Set()` and then broadcast
 * over it forever without ever adding a client — every stream route wrote
 * directly to its own response and set up its own interval, so
 * `broadcastMoment()` iterated an empty set and shutdown never closed a single
 * stream. This hub is the registry that was missing: clients are registered on
 * connect, removed on disconnect (including on write failure), kept alive by a
 * single shared heartbeat, and closed deterministically on shutdown.
 */

import type { IncomingMessage, ServerResponse } from 'http';
import { randomBytes } from '../common/crypto';
import { createLogger, Logger } from '../common/logging';
import { Result, ok, err } from '../common/patterns/Result';
import { ERROR_CODES } from '../common/constants';
import {
  AuthenticatedIdentity,
  DEFAULT_STREAM_HUB_CONFIG,
  HttpError,
  StreamHubConfig
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * A live SSE connection
 */
export interface SseClient {
  readonly id: string;
  readonly channel: string;
  readonly fingerprint: string | null;
  readonly connectedAt: number;
  /** Number of events successfully written */
  readonly eventsSent: number;
  /** False once the connection is gone */
  readonly open: boolean;
  send(event: string, data: unknown, id?: string): boolean;
  comment(text: string): boolean;
  close(reason?: string): void;
}

/**
 * Registration input
 */
export interface SseRegistration {
  readonly req: IncomingMessage;
  readonly res: ServerResponse;
  readonly channel: string;
  readonly identity?: AuthenticatedIdentity | null;
  /** Extra headers merged into the SSE response */
  readonly headers?: Readonly<Record<string, string>>;
}

/**
 * Snapshot for status endpoints
 */
export interface StreamHubStats {
  readonly clients: number;
  readonly channels: Readonly<Record<string, number>>;
  readonly eventsSent: number;
  readonly heartbeatActive: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// CLIENT IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

class SseConnection implements SseClient {
  readonly id: string;
  readonly channel: string;
  readonly fingerprint: string | null;
  readonly connectedAt: number;

  private events = 0;
  private closed = false;

  constructor(
    id: string,
    channel: string,
    fingerprint: string | null,
    private readonly res: ServerResponse,
    private readonly onClose: (client: SseConnection) => void,
    private readonly logger: Logger
  ) {
    this.id = id;
    this.channel = channel;
    this.fingerprint = fingerprint;
    this.connectedAt = Date.now();
  }

  get eventsSent(): number {
    return this.events;
  }

  get open(): boolean {
    return !this.closed && !this.res.writableEnded && this.res.writable;
  }

  send(event: string, data: unknown, id?: string): boolean {
    if (!this.open) {
      this.dispose();
      return false;
    }

    let payload: string;
    try {
      payload = JSON.stringify(data ?? null);
    } catch {
      this.logger.warn('Dropped unserializable SSE payload', { clientId: this.id, event });
      return false;
    }

    const frame =
      (id === undefined ? '' : `id: ${id}\n`) +
      `event: ${sanitizeField(event)}\n` +
      `data: ${payload}\n\n`;

    return this.write(frame, () => {
      this.events++;
    });
  }

  comment(text: string): boolean {
    if (!this.open) {
      this.dispose();
      return false;
    }
    return this.write(`: ${sanitizeField(text)}\n\n`);
  }

  close(reason = 'server-shutdown'): void {
    if (this.closed) return;
    if (this.open) {
      this.write(`event: close\ndata: ${JSON.stringify({ reason })}\n\n`);
      try {
        this.res.end();
      } catch {
        /* connection already gone */
      }
    }
    this.dispose();
  }

  /**
   * Internal: mark as closed exactly once and notify the hub
   */
  dispose(): void {
    if (this.closed) return;
    this.closed = true;
    this.onClose(this);
  }

  private write(chunk: string, onSuccess?: () => void): boolean {
    try {
      this.res.write(chunk);
      onSuccess?.();
      return true;
    } catch {
      // A dead socket must evict the client instead of throwing into the
      // broadcast loop (the legacy loop mutated the set it was iterating).
      this.dispose();
      return false;
    }
  }
}

function sanitizeField(value: string): string {
  return value.replace(/[\r\n]+/g, ' ');
}

// ═══════════════════════════════════════════════════════════════════════════
// STREAM HUB
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Registry of SSE clients with a single shared heartbeat.
 */
export class StreamHub {
  private readonly clients = new Map<string, SseConnection>();
  private readonly config: StreamHubConfig;
  private readonly logger: Logger;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private totalEvents = 0;
  private stopped = false;

  constructor(config: Partial<StreamHubConfig> = {}, logger?: Logger) {
    this.config = { ...DEFAULT_STREAM_HUB_CONFIG, ...config };
    this.logger = logger ?? createLogger('app:sse');
  }

  get clientCount(): number {
    return this.clients.size;
  }

  get heartbeatActive(): boolean {
    return this.heartbeatTimer !== null;
  }

  /**
   * Register a new SSE client, writing the stream headers.
   */
  register(registration: SseRegistration): Result<SseClient, HttpError> {
    if (this.stopped) {
      return err(
        new HttpError(503, ERROR_CODES.E_SERVICE_UNAVAILABLE, 'Server is shutting down')
      );
    }

    if (this.clients.size >= this.config.maxClients) {
      return err(
        new HttpError(
          503,
          ERROR_CODES.E_RESOURCE_EXHAUSTED,
          'Stream capacity reached; retry later'
        )
      );
    }

    const { req, res, channel } = registration;
    const id = `sse_${randomBytes(8).toString('hex')}`;

    try {
      res.writeHead(200, {
        ...registration.headers,
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no'
      });
      res.write(`retry: ${String(this.config.retryMs)}\n\n`);
    } catch (error) {
      this.logger.warn('Failed to open SSE stream', { channel });
      return err(
        new HttpError(500, ERROR_CODES.E_INTERNAL_UNKNOWN, 'Could not open stream')
      );
    }

    const client = new SseConnection(
      id,
      channel,
      registration.identity?.fingerprint ?? null,
      res,
      (closed) => this.unregister(closed.id),
      this.logger
    );

    this.clients.set(id, client);

    // Cleanup on every disconnect path. The legacy code only handled 'close'
    // on the request, so socket errors leaked the interval and the response.
    const detach = (): void => client.dispose();
    req.once('close', detach);
    req.once('aborted', detach);
    req.once('error', detach);
    res.once('close', detach);
    res.once('error', detach);

    this.ensureHeartbeat();

    this.logger.debug('SSE client registered', {
      clientId: id,
      channel,
      clients: this.clients.size
    });

    client.send('open', { clientId: id, channel, retryMs: this.config.retryMs });

    return ok(client);
  }

  /**
   * Remove a client by id
   */
  unregister(clientId: string): boolean {
    const removed = this.clients.delete(clientId);
    if (removed) {
      this.logger.debug('SSE client removed', { clientId, clients: this.clients.size });
    }
    if (this.clients.size === 0) {
      this.stopHeartbeat();
    }
    return removed;
  }

  get(clientId: string): SseClient | undefined {
    return this.clients.get(clientId);
  }

  list(): readonly SseClient[] {
    return [...this.clients.values()];
  }

  /**
   * Send an event to every client on a channel. Returns the delivery count.
   */
  broadcast(channel: string, event: string, data: unknown): number {
    return this.deliver(event, data, (client) => client.channel === channel);
  }

  /**
   * Send an event to every connected client
   */
  broadcastAll(event: string, data: unknown): number {
    return this.deliver(event, data, () => true);
  }

  /**
   * Send an event to the clients of one identity
   */
  broadcastToFingerprint(fingerprint: string, event: string, data: unknown): number {
    return this.deliver(event, data, (client) => client.fingerprint === fingerprint);
  }

  /**
   * Send to a single client
   */
  send(clientId: string, event: string, data: unknown): boolean {
    const client = this.clients.get(clientId);
    if (client === undefined) return false;
    const delivered = client.send(event, data);
    if (delivered) this.totalEvents++;
    return delivered;
  }

  stats(): StreamHubStats {
    const channels: Record<string, number> = {};
    for (const client of this.clients.values()) {
      channels[client.channel] = (channels[client.channel] ?? 0) + 1;
    }
    return {
      clients: this.clients.size,
      channels,
      eventsSent: this.totalEvents,
      heartbeatActive: this.heartbeatActive
    };
  }

  /**
   * Close every stream and clear the heartbeat (flaw #3 / #5).
   */
  async shutdown(reason = 'server-shutdown'): Promise<void> {
    this.stopped = true;
    this.stopHeartbeat();

    const clients = [...this.clients.values()];
    for (const client of clients) {
      client.close(reason);
    }
    this.clients.clear();

    if (clients.length > 0) {
      this.logger.info('Closed SSE clients', { count: clients.length, reason });
    }

    // Yield once so the final frames flush before the http server closes
    await new Promise<void>((resolve) => setImmediate(resolve));
  }

  /**
   * Allow a stopped hub to be reused (start/stop/start cycles)
   */
  reset(): void {
    this.stopped = false;
  }

  private deliver(
    event: string,
    data: unknown,
    predicate: (client: SseConnection) => boolean
  ): number {
    let delivered = 0;
    // Snapshot: send() can evict clients, and mutating during iteration was one
    // of the legacy bugs.
    for (const client of [...this.clients.values()]) {
      if (!predicate(client)) continue;
      if (client.send(event, data)) {
        delivered++;
        this.totalEvents++;
      }
    }
    return delivered;
  }

  private ensureHeartbeat(): void {
    if (this.heartbeatTimer !== null) return;
    if (this.config.heartbeatMs <= 0) return;

    this.heartbeatTimer = setInterval(() => {
      const now = Date.now();
      for (const client of [...this.clients.values()]) {
        client.comment(`hb ${String(now)}`);
      }
      if (this.clients.size === 0) {
        this.stopHeartbeat();
      }
    }, this.config.heartbeatMs);

    // Never hold the event loop open
    this.heartbeatTimer.unref();
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer === null) return;
    clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = null;
  }
}
