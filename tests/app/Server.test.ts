/**
 * Server composition tests: static files (flaw #2), SSE (flaw #5), WebSocket
 * auth (flaw #7) and lifecycle hardening (flaw #3).
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import WebSocket from 'ws';
import { generateKeyTriplet } from '../../src/common/crypto';
import {
  AlephServer,
  AuthMiddleware,
  NonceCache,
  isContained,
  registeredShutdownStepCount
} from '../../src/app';
import { baseUrlOf, request, signRequest, signedGet, startServer } from './helpers';

let server: AlephServer | null = null;

function runningServer(): AlephServer {
  if (server === null) throw new Error('server not started');
  return server;
}

/**
 * Send an exact, unnormalised request line over a raw socket. Node's http
 * client normalises '.'/'..' segments before they reach the wire, which hides
 * traversal attempts; a real attacker controls the bytes directly.
 */
function rawHttpRequest(port: number, requestLine: string): Promise<{ status: number; body: string }> {
  const net = require('net') as typeof import('net');
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => {
      socket.write(`${requestLine}\r\nHost: localhost\r\nConnection: close\r\n\r\n`);
    });
    let data = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      data += chunk;
    });
    socket.on('close', () => {
      const statusLine = data.split('\r\n')[0] ?? '';
      const match = /HTTP\/1\.\d (\d{3})/.exec(statusLine);
      resolve({ status: match !== null ? Number.parseInt(match[1], 10) : 0, body: data });
    });
    socket.on('error', reject);
  });
}
let fixtureRoot: string | null = null;

beforeEach(() => {
  fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'alephnet-static-'));
});

afterEach(async () => {
  if (server !== null) {
    await server.stop();
    server = null;
  }
  if (fixtureRoot !== null) {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
    fixtureRoot = null;
  }
});

/**
 * static root at <fixture>/app, with a sibling directory sharing the prefix
 * (`app-data`) — the exact shape the legacy startsWith guard confused.
 */
function createStaticFixture(): { staticRoot: string; sibling: string } {
  const staticRoot = path.join(fixtureRoot as string, 'app');
  const sibling = path.join(fixtureRoot as string, 'app-data');
  fs.mkdirSync(staticRoot, { recursive: true });
  fs.mkdirSync(sibling, { recursive: true });
  fs.writeFileSync(path.join(staticRoot, 'index.html'), '<html>home</html>');
  fs.writeFileSync(path.join(staticRoot, 'style.css'), 'body { color: red }');
  fs.writeFileSync(path.join(staticRoot, 'secret.txt'), 'TOP-SECRET-CONTENT');
  fs.writeFileSync(path.join(staticRoot, '..-index.html'), 'not-the-index');
  fs.writeFileSync(path.join(sibling, 'leak.txt'), 'SIBLING-SECRET');
  return { staticRoot, sibling };
}

// ═══════════════════════════════════════════════════════════════════════════
// PATH CONTAINMENT (flaw #2)
// ═══════════════════════════════════════════════════════════════════════════

describe('StaticServer path containment', () => {
  it('isContained rejects the sibling-directory prefix case', () => {
    const root = path.join(fixtureRoot as string, 'app');
    expect(isContained(root, path.join(root, 'index.html'))).toBe(true);
    // '/.../app-data' startsWith '/.../app' — the legacy guard said "inside"
    expect(isContained(root, path.join(fixtureRoot as string, 'app-data', 'leak.txt'))).toBe(
      false
    );
  });

  it('serves real files with correct MIME types', async () => {
    const { staticRoot } = createStaticFixture();
    server = await startServer({ staticPath: staticRoot });

    const css = await request(baseUrlOf(server), 'GET', '/style.css');
    expect(css.status).toBe(200);
    expect(css.headers['content-type']).toContain('text/css');
    expect(css.text).toContain('color: red');
  });

  it('serves index.html for / and for directory paths', async () => {
    const { staticRoot } = createStaticFixture();
    server = await startServer({ staticPath: staticRoot });

    const home = await request(baseUrlOf(server), 'GET', '/');
    expect(home.status).toBe(200);
    expect(home.text).toContain('home');
  });

  it('returns 404 for a missing static file (no 200 index.html mask)', async () => {
    const { staticRoot } = createStaticFixture();
    server = await startServer({ staticPath: staticRoot });

    const missing = await request(baseUrlOf(server), 'GET', '/does-not-exist.html');
    expect(missing.status).toBe(404);
    expect(missing.text).not.toContain('home');
  });

  it('never lets ../ traversal escape the root', async () => {
    const { staticRoot } = createStaticFixture();
    server = await startServer({ staticPath: staticRoot });

    // Raw request line: the server sees the unnormalised target. The '..' is
    // clamped at the root during containment resolution, so whatever happens,
    // nothing OUTSIDE the root may be served. Files inside the root (here,
    // secret.txt, after the leading .. collapses onto the root) are legitimate.
    const response = await rawHttpRequest(runningServer().port, 'GET /../secret.txt HTTP/1.1');
    expect(response.body).not.toContain('SIBLING-SECRET');
    expect([200, 403, 404]).toContain(response.status);
  });

  it('rejects traversal that escapes the root from a deeper path', async () => {
    const { staticRoot } = createStaticFixture();
    fs.mkdirSync(path.join(staticRoot, 'sub'));
    fs.writeFileSync(path.join(staticRoot, 'sub', 'inner.txt'), 'INNER');
    server = await startServer({ staticPath: staticRoot });

    const response = await rawHttpRequest(
      runningServer().port,
      'GET /sub/../../../app-data/leak.txt HTTP/1.1'
    );
    expect([403, 404]).toContain(response.status);
    expect(response.body).not.toContain('SIBLING-SECRET');
  });

  it('rejects encoded ..%2f traversal', async () => {
    const { staticRoot } = createStaticFixture();
    server = await startServer({ staticPath: staticRoot });

    const response = await rawHttpRequest(runningServer().port, 'GET /..%2fapp-data%2fleak.txt HTTP/1.1');
    expect([403, 404]).toContain(response.status);
    expect(response.body).not.toContain('SIBLING-SECRET');
  });

  it('rejects double-encoded %252e%252e%252f traversal', async () => {
    const { staticRoot } = createStaticFixture();
    server = await startServer({ staticPath: staticRoot });

    const response = await rawHttpRequest(
      runningServer().port,
      'GET /%252e%252e%252fsecret.txt HTTP/1.1'
    );
    expect([400, 403, 404]).toContain(response.status);
    expect(response.body).not.toContain('TOP-SECRET-CONTENT');
  });

  it('rejects the sibling-directory prefix escape (the legacy startsWith hole)', async () => {
    const { staticRoot } = createStaticFixture();
    server = await startServer({ staticPath: staticRoot });

    // '/app-data' shares the '/app' prefix: the legacy guard passed this
    const response = await rawHttpRequest(
      runningServer().port,
      'GET /../app-data/leak.txt HTTP/1.1'
    );
    expect([403, 404]).toContain(response.status);
    expect(response.body).not.toContain('SIBLING-SECRET');
  });

  it('rejects absolute-path smuggling via a leading /', async () => {
    const { staticRoot } = createStaticFixture();
    server = await startServer({ staticPath: staticRoot });

    const response = await rawHttpRequest(runningServer().port, 'GET //etc/passwd HTTP/1.1');
    expect([403, 404]).toContain(response.status);
  });

  it('still serves a real file containing dots (..-index.html) without confusion', async () => {
    const { staticRoot } = createStaticFixture();
    server = await startServer({ staticPath: staticRoot });

    const response = await request(baseUrlOf(server), 'GET', '/..-index.html');
    expect(response.status).toBe(200);
    expect(response.text).toContain('not-the-index');
  });

  it('keeps API 404s strict even when a static root is configured', async () => {
    const { staticRoot } = createStaticFixture();
    server = await startServer({ staticPath: staticRoot });

    const api = await request(baseUrlOf(server), 'GET', '/api/unknown');
    expect(api.status).toBe(404);
    expect(api.text).not.toContain('home');
  });

  it('only enables the SPA fallback when explicitly requested', async () => {
    const { staticRoot } = createStaticFixture();
    server = await startServer({ staticPath: staticRoot, staticSpaFallback: true });

    const response = await request(baseUrlOf(server), 'GET', '/client/route/not-on-disk');
    expect(response.status).toBe(200);
    expect(response.text).toContain('home');
  });

  it('rejects a symlink inside the root that points outside it (opened-handle check)', async () => {
    const { staticRoot } = createStaticFixture();
    const outside = path.join(fixtureRoot as string, 'outside-secret.txt');
    fs.writeFileSync(outside, 'ESCAPED-SECRET-CONTENT');
    fs.symlinkSync(outside, path.join(staticRoot, 'escape.txt'));
    server = await startServer({ staticPath: staticRoot });

    const response = await request(baseUrlOf(server), 'GET', '/escape.txt');
    expect([403, 404]).toContain(response.status);
    expect(response.text).not.toContain('ESCAPED-SECRET-CONTENT');
  });

  it('rejects a symlink escape nested inside a subdirectory', async () => {
    const { staticRoot } = createStaticFixture();
    fs.mkdirSync(path.join(staticRoot, 'sub'));
    const outside = path.join(fixtureRoot as string, 'outside-secret.txt');
    fs.writeFileSync(outside, 'ESCAPED-SECRET-CONTENT');
    fs.symlinkSync(outside, path.join(staticRoot, 'sub', 'leak.txt'));
    server = await startServer({ staticPath: staticRoot });

    const response = await request(baseUrlOf(server), 'GET', '/sub/leak.txt');
    expect([403, 404]).toContain(response.status);
    expect(response.text).not.toContain('ESCAPED-SECRET-CONTENT');
  });

  it('rejects a static file larger than the configured size cap with 403', async () => {
    const { staticRoot } = createStaticFixture();
    fs.writeFileSync(path.join(staticRoot, 'huge.bin'), Buffer.alloc(2048, 7));
    server = await startServer({ staticPath: staticRoot, staticMaxFileBytes: 1024 });

    const oversized = await request(baseUrlOf(server), 'GET', '/huge.bin');
    expect(oversized.status).toBe(403);

    // Normal-size files are unaffected
    const css = await request(baseUrlOf(server), 'GET', '/style.css');
    expect(css.status).toBe(200);
    expect(css.text).toContain('color: red');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// SSE (flaw #5)
// ═══════════════════════════════════════════════════════════════════════════

describe('StreamHub over HTTP', () => {
  function openSse(
    url: string,
    headers: Record<string, string> = {}
  ): Promise<{ req: http.ClientRequest; res: http.IncomingMessage; frames: string[] }> {
    return new Promise((resolve, reject) => {
      const req = http.request(url, { headers }, (res) => {
        expect(res.statusCode).toBe(200);
        expect(res.headers['content-type']).toContain('text/event-stream');
        const frames: string[] = [];
        res.setEncoding('utf8');
        let buffer = '';
        res.on('data', (chunk: string) => {
          buffer += chunk;
          let idx: number;
          while ((idx = buffer.indexOf('\n\n')) !== -1) {
            frames.push(buffer.slice(0, idx));
            buffer = buffer.slice(idx + 2);
          }
        });
        res.on('error', reject);
        resolve({ req, res, frames });
      });
      req.on('error', reject);
      req.end();
    });
  }

  async function waitFor(
    frames: string[],
    predicate: (frame: string) => boolean,
    timeoutMs = 5_000
  ): Promise<string> {
    const started = Date.now();
    for (;;) {
      const found = frames.find(predicate);
      if (found !== undefined) return found;
      if (Date.now() - started > timeoutMs) {
        throw new Error(`Timed out waiting for SSE frame; got:\n${frames.join('\n---\n')}`);
      }
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  it('registers clients, delivers broadcasts and cleans up on disconnect', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();

    const headers = signRequest(server, identity, 'GET', '/stream/test-channel');
    const { req, frames } = await openSse(`${baseUrlOf(server)}/stream/test-channel`, headers);

    // Registered: the open frame proves the hub (not an empty set) got the client
    await waitFor(frames, (frame) => frame.includes('event: open'));
    expect(server.streamHub.clientCount).toBe(1);

    // Broadcast reaches the live client (the legacy broadcast loop was empty)
    server.streamHub.broadcast('test-channel', 'moment', { id: 42, glow: 0.99 });
    const frame = await waitFor(frames, (f) => f.includes('event: moment'));
    expect(frame).toContain('"id":42');
    expect(frame).toContain('"glow":0.99');

    // Disconnect -> hub evicts the client
    req.destroy();
    await new Promise((r) => setTimeout(r, 50));
    expect(server.streamHub.clientCount).toBe(0);

    // The hub stays usable afterwards
    const status = await request(baseUrlOf(server), 'GET', '/status');
    expect(status.status).toBe(200);
  });

  it('sends to one fingerprint but not another', async () => {
    server = await startServer();
    const alice = generateKeyTriplet();
    const bob = generateKeyTriplet();

    const aliceHeaders = signRequest(server, alice, 'GET', '/stream/private');
    const bobHeaders = signRequest(server, bob, 'GET', '/stream/private');

    const aliceConn = await openSse(`${baseUrlOf(server)}/stream/private`, aliceHeaders);
    const bobConn = await openSse(`${baseUrlOf(server)}/stream/private`, bobHeaders);
    await waitFor(aliceConn.frames, (f) => f.includes('event: open'));
    await waitFor(bobConn.frames, (f) => f.includes('event: open'));

    server.streamHub.broadcastToFingerprint(alice.fingerprint, 'direct', { to: 'alice' });

    await waitFor(aliceConn.frames, (f) => f.includes('event: direct'));
    expect(bobConn.frames.some((f) => f.includes('event: direct'))).toBe(false);

    aliceConn.req.destroy();
    bobConn.req.destroy();
  });

  it('requires auth for stream channels', async () => {
    server = await startServer();

    const res = await new Promise<{ status: number; text: string }>((resolve, reject) => {
      const req = http.request(`${baseUrlOf(runningServer())}/stream/any`, (r) => {
        let text = '';
        r.on('data', (c: Buffer) => (text += c.toString()));
        r.on('end', () => resolve({ status: r.statusCode ?? 0, text }));
        r.on('error', reject);
      });
      req.on('error', reject);
      req.end();
    });

    expect(res.status).toBe(401);
    expect(server.streamHub.clientCount).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// WEBSOCKETS (flaw #7)
// ═══════════════════════════════════════════════════════════════════════════

describe('WebSocket upgrades', () => {
  it('rejects an unsigned upgrade with 401', async () => {
    server = await startServer({ websocket: { path: '/ws' } });

    const outcome = await new Promise<'rejected' | 'open'>((resolve) => {
      const ws = new WebSocket(`ws://127.0.0.1:${String(runningServer().port)}/ws?nodeId=fake`);
      ws.on('open', () => resolve('open'));
      ws.on('error', () => resolve('rejected'));
      ws.on('unexpected-response', () => resolve('rejected'));
    });

    expect(outcome).toBe('rejected');
    expect(server.webSocketPeers.length).toBe(0);
  });

  it('accepts a signed upgrade and derives identity from the verified key', async () => {
    server = await startServer({
      websocket: { path: '/ws', allowedOrigins: ['https://ui.example'] }
    });
    const identity = generateKeyTriplet();

    const headers = signRequest(server, identity, 'GET', '/ws?room=alpha');
    headers.origin = 'https://ui.example';

    const welcome = await new Promise<{ peerId: string; fingerprint: string }>(
      (resolve, reject) => {
        const ws = new WebSocket(`ws://127.0.0.1:${String(runningServer().port)}/ws?room=alpha`, {
          headers
        });
        const timer = setTimeout(() => reject(new Error('welcome timeout')), 5_000);
        ws.on('message', (data: Buffer) => {
          clearTimeout(timer);
          const parsed = JSON.parse(data.toString()) as {
            type: string;
            peerId: string;
            fingerprint: string;
          };
          expect(parsed.type).toBe('welcome');
          ws.close();
          resolve({ peerId: parsed.peerId, fingerprint: parsed.fingerprint });
        });
        ws.on('error', reject);
      }
    );

    // The `?nodeId=` query param was ignored: identity came from the signature
    expect(welcome.fingerprint).toBe(identity.fingerprint);
    expect(welcome.peerId).toMatch(/^ws_[0-9a-f]{16}$/);

    await new Promise((r) => setTimeout(r, 50));
    expect(server.webSocketPeers.length).toBe(0);
  });

  it('rejects an upgrade from a disallowed Origin with 403', async () => {
    server = await startServer({
      websocket: { path: '/ws', allowedOrigins: ['https://ui.example'] }
    });
    const identity = generateKeyTriplet();

    const headers = signRequest(server, identity, 'GET', '/ws');
    headers.origin = 'https://attacker.example';

    const outcome = await new Promise<'rejected' | 'open'>((resolve) => {
      const ws = new WebSocket(`ws://127.0.0.1:${String(runningServer().port)}/ws`, { headers });
      ws.on('open', () => resolve('open'));
      ws.on('error', () => resolve('rejected'));
      ws.on('unexpected-response', () => resolve('rejected'));
    });

    expect(outcome).toBe('rejected');
    expect(server.webSocketPeers.length).toBe(0);
  });

  it('rejects upgrades on unknown paths with 404', async () => {
    server = await startServer({ websocket: { path: '/ws' } });
    const identity = generateKeyTriplet();
    const headers = signRequest(runningServer(), identity, 'GET', '/ws');
    delete headers.origin;

    const outcome = await new Promise<'rejected' | 'open'>((resolve) => {
      const ws = new WebSocket(
        `ws://127.0.0.1:${String(runningServer().port)}/other-path`,
        { headers }
      );
      ws.on('open', () => resolve('open'));
      ws.on('error', () => resolve('rejected'));
      ws.on('unexpected-response', () => resolve('rejected'));
    });

    expect(outcome).toBe('rejected');
  });

  it('never admits more than maxConnections peers under concurrent upgrade bursts', async () => {
    server = await startServer({ websocket: { path: '/ws', maxConnections: 2 } });
    const identity = generateKeyTriplet();
    const opened: WebSocket[] = [];

    const attempt = (): Promise<'open' | 'rejected'> =>
      new Promise((resolve) => {
        const ws = new WebSocket(
          `ws://127.0.0.1:${String(runningServer().port)}/ws`,
          { headers: signRequest(runningServer(), identity, 'GET', '/ws') }
        );
        ws.on('open', () => {
          opened.push(ws);
          resolve('open');
        });
        ws.on('error', () => resolve('rejected'));
        ws.on('unexpected-response', () => resolve('rejected'));
      });

    // Five upgrades racing at once: the atomic reservation must admit at
    // most two regardless of interleaving.
    const outcomes = await Promise.all([attempt(), attempt(), attempt(), attempt(), attempt()]);
    expect(outcomes.filter((o) => o === 'open').length).toBeLessThanOrEqual(2);
    expect(server.webSocketPeers.length).toBeLessThanOrEqual(2);

    for (const ws of opened) {
      ws.close();
    }
  });

  it('rate-limits upgrade attempts through the aggregate per-IP budget', async () => {
    server = await startServer({
      websocket: { path: '/ws' },
      rateLimiter: { aggregateLimit: 3, aggregateWindowMs: 60_000, limit: 10_000, maxEntries: 10_000 }
    });
    const identity = generateKeyTriplet();
    const statusCodes: number[] = [];

    for (let i = 0; i < 4; i++) {
      const headers = signRequest(runningServer(), identity, 'GET', '/ws');
      await new Promise<void>((resolve) => {
        const ws = new WebSocket(
          `ws://127.0.0.1:${String(runningServer().port)}/ws`,
          { headers }
        );
        ws.on('open', () => {
          ws.close();
          resolve();
        });
        ws.on('error', () => resolve());
        ws.on('unexpected-response', (_req: import('http').IncomingMessage, res: import('http').IncomingMessage) => {
          statusCodes.push(res.statusCode ?? 0);
          res.resume();
          resolve();
        });
      });
    }

    expect(statusCodes).toContain(429);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// LIFECYCLE (flaw #3)
// ═══════════════════════════════════════════════════════════════════════════

describe('server lifecycle', () => {
  it('rejects start() with a typed error when the port is taken (EADDRINUSE)', async () => {
    const blocker = http.createServer();
    await new Promise<void>((resolve) => blocker.listen(0, '127.0.0.1', resolve));
    const address = blocker.address();
    const port = typeof address === 'object' && address !== null ? address.port : 0;

    const colliding = new AlephServer({ port, host: '127.0.0.1' });
    await expect(colliding.start()).rejects.toThrow(/address already in use|Failed to bind/);

    await new Promise<void>((resolve) => blocker.close(() => resolve()));
  });

  it('start() after stop() is rejected rather than silently corrupting state', async () => {
    server = await startServer();
    await server.stop();
    await expect(server.start()).rejects.toThrow(/cannot be restarted/);
  });

  it('stop() is idempotent', async () => {
    server = await startServer();
    await server.stop();
    await server.stop();
    expect(server.listening).toBe(false);
  });

  it('never accumulates signal shutdown steps across start/stop cycles', async () => {
    expect(registeredShutdownStepCount()).toBe(0);

    server = await startServer({ installSignalHandlers: true });
    expect(registeredShutdownStepCount()).toBe(1);

    await server.stop();
    expect(registeredShutdownStepCount()).toBe(0);
  });

  it('drains idle keep-alive connections on stop()', async () => {
    server = await startServer();

    // Open a keep-alive connection and read one response
    const res = await new Promise<http.IncomingMessage>((resolve, reject) => {
      const req = http.request(`${baseUrlOf(runningServer())}/health`, { agent: false }, (r) =>
        resolve(r)
      );
      req.on('error', reject);
      req.end();
    });
    await new Promise<void>((resolve) => {
      res.resume();
      res.on('end', resolve);
    });

    await server.stop();
    // Reaching this point without a hang proves the socket was drained
    expect(server.listening).toBe(false);
  });

  it('still responds after a client mid-body abort', async () => {
    server = await startServer();

    // Open a connection and abort mid-request
    await new Promise<void>((resolve, reject) => {
      const socket = new (require('net') as typeof import('net')).Socket();
      socket.connect(runningServer().port, '127.0.0.1', () => {
        socket.write('POST /api/echo HTTP/1.1\r\nContent-Length: 1000\r\n\r\npartial');
        setTimeout(() => {
          socket.destroy();
          resolve();
        }, 20);
      });
      socket.on('error', reject);
    });

    const health = await request(baseUrlOf(server), 'GET', '/health');
    expect(health.status).toBe(200);
  });

  it('stopping one server never disposes a SHARED auth middleware', async () => {
    // Two servers sharing one AuthMiddleware: the nonce cache belongs to the
    // middleware's owner, so stop() on one server must not clear the other
    // server's replay protection.
    const sharedAuth = new AuthMiddleware();
    const first = new AlephServer({ port: 0, host: '127.0.0.1', auth: sharedAuth });
    const second = new AlephServer({ port: 0, host: '127.0.0.1', auth: sharedAuth });
    await first.start();
    await second.start();
    server = second;

    try {
      const identity = generateKeyTriplet();
      const headers = signRequest(first, identity, 'GET', '/whoami', {
        nonce: 'shared-live-nonce'
      });

      const initial = await request(baseUrlOf(first), 'GET', '/whoami', { headers });
      expect(initial.status).toBe(200);

      // Stopping the FIRST server used to dispose the shared cache...
      await first.stop();

      // ...so the replay against the SECOND server would have been accepted.
      const replay = await request(baseUrlOf(second), 'GET', '/whoami', { headers });
      expect(replay.status).toBe(401);
      expect(replay.text).toMatch(/replay rejected/i);
    } finally {
      await second.stop();
      server = null;
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// BOUNDED CACHES
// ═══════════════════════════════════════════════════════════════════════════

describe('NonceCache bounds', () => {
  it('evicts oldest entries past maxEntries within one partition', () => {
    const cache = new NonceCache({ maxEntries: 5, maxEntriesPerPartition: 5, sweepIntervalMs: 0 });
    for (let i = 0; i < 50; i++) {
      expect(cache.consume('fp-1', `nonce-${String(i)}`)).toBe(true);
    }
    expect(cache.size).toBeLessThanOrEqual(5);
    expect(cache.evictionCount).toBeGreaterThan(0);
    // The evicted earliest entries are no longer reserved
    expect(cache.has('fp-1', 'nonce-0')).toBe(false);
    cache.dispose();
  });

  it('expires nonces by ttl', async () => {
    const cache = new NonceCache({ maxEntries: 100, maxEntriesPerPartition: 100, ttlMs: 30, sweepIntervalMs: 0 });
    expect(cache.consume('fp-1', 'short-lived')).toBe(true);
    await new Promise((r) => setTimeout(r, 60));
    expect(cache.has('fp-1', 'short-lived')).toBe(false);
    // And after TTL the nonce is usable again (window is over)
    expect(cache.consume('fp-1', 'short-lived')).toBe(true);
    cache.dispose();
  });

  it('replay protection survives a 50k nonce flood from another identity', () => {
    // The pre-partition cache was one global oldest-first Map: an attacker
    // spraying distinct nonces forced the victim's live nonce out of the
    // cache and replayed it inside the freshness window. With per-identity
    // buckets the attacker can only exhaust their OWN bucket.
    const cache = new NonceCache({
      maxEntries: 200,
      maxEntriesPerPartition: 20,
      ttlMs: 120_000,
      sweepIntervalMs: 0
    });

    expect(cache.consume('victim-fp', 'victim-nonce-1')).toBe(true);

    for (let i = 0; i < 50_000; i++) {
      expect(cache.consume('attacker-fp', `attacker-nonce-${String(i)}`)).toBe(true);
    }

    // The victim's nonce is STILL reserved after the flood...
    expect(cache.has('victim-fp', 'victim-nonce-1')).toBe(true);
    // ...so its replay is STILL rejected.
    expect(cache.consume('victim-fp', 'victim-nonce-1')).toBe(false);
    // Global memory stays bounded
    expect(cache.size).toBeLessThanOrEqual(200);
    cache.dispose();
  });

  it('global-cap eviction is per-identity fair: it drains the largest bucket, never the victim', () => {
    const cache = new NonceCache({
      maxEntries: 10,
      maxEntriesPerPartition: 100,
      ttlMs: 120_000,
      sweepIntervalMs: 0
    });
    for (let i = 0; i < 5; i++) {
      expect(cache.consume('victim-fp', `victim-${String(i)}`)).toBe(true);
    }
    for (let i = 0; i < 100; i++) {
      expect(cache.consume('attacker-fp', `attacker-${String(i)}`)).toBe(true);
    }
    expect(cache.size).toBeLessThanOrEqual(10);
    for (let i = 0; i < 5; i++) {
      expect(cache.has('victim-fp', `victim-${String(i)}`)).toBe(true);
    }
    cache.dispose();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// RATE LIMITING (aggregate budget, OPTIONS/CORS coverage, per-route override)
// ═══════════════════════════════════════════════════════════════════════════

describe('rate limiting', () => {
  it('returns 429 once the aggregate per-IP budget is exhausted across distinct paths', async () => {
    server = await startServer({
      rateLimiter: { aggregateLimit: 25, aggregateWindowMs: 60_000, limit: 10_000, maxEntries: 10_000 }
    });

    let lastStatus = 0;
    // 30 DISTINCT paths: every per-(IP, path) bucket sees exactly one
    // request, so only the aggregate budget can trip.
    for (let i = 0; i < 30; i++) {
      const response = await request(baseUrlOf(server), 'GET', `/api/spray-${String(i)}`);
      lastStatus = response.status;
    }
    expect(lastStatus).toBe(429);
  });

  it('rate-limits OPTIONS preflights through the aggregate budget', async () => {
    server = await startServer({
      corsOrigins: ['https://ui.example'],
      rateLimiter: { aggregateLimit: 5, aggregateWindowMs: 60_000, limit: 10_000, maxEntries: 10_000 }
    });

    let lastStatus = 0;
    for (let i = 0; i < 6; i++) {
      const response = await request(baseUrlOf(server), 'OPTIONS', '/api/x', {
        headers: { origin: 'https://ui.example' }
      });
      lastStatus = response.status;
    }
    // Preflights used to bypass the limiter entirely (204 forever)
    expect(lastStatus).toBe(429);
  });

  it('rate-limits CORS-403 rejections through the aggregate budget', async () => {
    server = await startServer({
      corsOrigins: ['https://ui.example'],
      rateLimiter: { aggregateLimit: 5, aggregateWindowMs: 60_000, limit: 10_000, maxEntries: 10_000 }
    });

    let lastStatus = 0;
    for (let i = 0; i < 6; i++) {
      const response = await request(baseUrlOf(server), 'GET', '/health', {
        headers: { origin: 'https://evil.example' }
      });
      lastStatus = response.status;
    }
    expect(lastStatus).toBe(429);
  });

  it('applies the per-route rateLimit override', async () => {
    server = await startServer();
    server.routes.get(
      '/api/throttled',
      (_ctx, res) => {
        res.json({ ok: true });
      },
      { auth: 'public', rateLimit: { limit: 3, windowMs: 60_000 } }
    );

    let lastStatus = 0;
    for (let i = 0; i < 4; i++) {
      const response = await request(baseUrlOf(server), 'GET', '/api/throttled');
      lastStatus = response.status;
    }
    expect(lastStatus).toBe(429);

    // The override is per-route: other routes stay available
    const health = await request(baseUrlOf(server), 'GET', '/health');
    expect(health.status).toBe(200);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ERROR-PATH CONNECTION HYGIENE
// ═══════════════════════════════════════════════════════════════════════════

describe('error-path connection hygiene', () => {
  it('a streaming handler that throws after writing headers closes the connection instead of hanging', async () => {
    server = await startServer();
    server.routes.get(
      '/api/stream-boom',
      (ctx, res) => {
        // Headers hit the wire, then the handler dies mid-stream
        res.raw.writeHead(200, { 'Content-Type': 'text/event-stream' });
        res.raw.write('data: partial\n\n');
        throw new Error('boom after headers sent');
      },
      { streaming: true, auth: 'public' }
    );

    // Plain socket WITHOUT 'Connection: close': if the server hangs the
    // stream open, this promise never resolves and the test times out.
    const closed = await new Promise<boolean>((resolve) => {
      const net = require('net') as typeof import('net');
      const guard = setTimeout(() => resolve(false), 3_000);
      const finish = (value: boolean): void => {
        clearTimeout(guard);
        resolve(value);
      };
      const socket = net.connect(runningServer().port, '127.0.0.1', () => {
        socket.write('GET /api/stream-boom HTTP/1.1\r\nHost: localhost\r\n\r\n');
      });
      socket.setEncoding('utf8');
      socket.on('data', () => undefined);
      socket.on('close', () => finish(true));
      socket.on('error', () => finish(true));
    });
    expect(closed).toBe(true);

    // And the server keeps serving
    const health = await request(baseUrlOf(server), 'GET', '/health');
    expect(health.status).toBe(200);
  });

  it('a 408 body-read timeout carries Connection: close so leftover bytes cannot desync', async () => {
    server = await startServer({ bodyTimeoutMs: 200 });
    server.routes.post('/api/slow', (_ctx, res) => res.json({ ok: true }), { auth: 'public' });

    // Send headers promising 100 bytes but never deliver them: the server
    // must answer 408 (not hang) and close the connection.
    const outcome = await new Promise<{ status: number; headers: Record<string, string> }>(
      (resolve, reject) => {
        const net = require('net') as typeof import('net');
        const socket = net.connect(runningServer().port, '127.0.0.1', () => {
          socket.write(
            'POST /api/slow HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\npartial'
          );
        });
        socket.setEncoding('utf8');
        let data = '';
        socket.on('data', (chunk: string) => {
          data += chunk;
        });
        socket.on('close', () => {
          const statusMatch = /HTTP\/1\.\d (\d{3})/.exec(data);
          const closeMatch = /^Connection: close$/im.exec(data);
          resolve({
            status: statusMatch === null ? 0 : Number.parseInt(statusMatch[1], 10),
            headers: closeMatch === null ? {} : { connection: 'close' }
          });
        });
        socket.on('error', reject);
      }
    );

    expect(outcome.status).toBe(408);
    expect(outcome.headers.connection).toBe('close');
  });

  it('still serves normally after the 408', async () => {
    server = await startServer({ bodyTimeoutMs: 200 });
    const health = await request(baseUrlOf(server), 'GET', '/health');
    expect(health.status).toBe(200);
  });
});
