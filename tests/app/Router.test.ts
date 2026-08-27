/**
 * Router behaviour over HTTP: body parsing (flaw #4), error hygiene (flaw #6)
 * and real 404s for unmatched API routes (flaw #2).
 */

import { afterEach, describe, expect, it } from '@jest/globals';
import { AlephServer } from '../../src/app';
import { baseUrlOf, post, request, startServer } from './helpers';

let server: AlephServer | null = null;

afterEach(async () => {
  if (server !== null) {
    await server.stop();
    server = null;
  }
});

describe('body parsing', () => {
  it('delivers parsed JSON bodies to handlers (the legacy req.body TypeError is gone)', async () => {
    server = await startServer();
    server.routes.post('/api/echo', (ctx, res) => {
      res.json({ got: ctx.body });
    }, { auth: 'public' });

    const response = await post(baseUrlOf(server), '/api/echo', { a: 1, b: [2, 3] });
    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual({ got: { a: 1, b: [2, 3] } });
  });

  it('rejects an oversized body with 413 without crashing', async () => {
    server = await startServer({ maxBodyBytes: 64 });

    server.routes.post('/api/echo', (_ctx, res) => res.json({ ok: true }), { auth: 'public' });

    const payload = 'x'.repeat(1024);
    const response = await request(baseUrlOf(server), 'POST', '/api/echo', {
      headers: { 'content-type': 'application/json' },
      body: payload
    });

    expect(response.status).toBe(413);
    const tooLarge = JSON.parse(response.text) as { code: string };
    expect(tooLarge.code).toEqual('E8001');
  });

  it('rejects an oversized body declared via content-length before reading it', async () => {
    server = await startServer({ maxBodyBytes: 64 });

    server.routes.post('/api/echo', (_ctx, res) => res.json({ ok: true }), { auth: 'public' });

    const response = await request(baseUrlOf(server), 'POST', '/api/echo', {
      headers: { 'content-type': 'application/json', 'content-length': '100000' },
      body: '{}'
    });

    expect(response.status).toBe(413);
  });

  it('returns 400 for malformed JSON instead of crashing the process', async () => {
    server = await startServer();

    server.routes.post('/api/echo', (_ctx, res) => res.json({ ok: true }), { auth: 'public' });

    const response = await request(baseUrlOf(server), 'POST', '/api/echo', {
      headers: { 'content-type': 'application/json' },
      body: '{ this is : not json '
    });

    expect(response.status).toBe(400);
    const body = JSON.parse(response.text) as { error: string; requestId: string };
    expect(body.error).toMatch(/Malformed JSON/);
    expect(body.requestId).toBeTruthy();

    // The server must still be serving afterwards
    const health = await request(baseUrlOf(server), 'GET', '/health');
    expect(health.status).toBe(200);
  });

  it('returns 400 for an unparseable percent-encoded target', async () => {
    server = await startServer();

    const response = await request(baseUrlOf(server), 'GET', '/%ZZ');
    expect(response.status).toBe(400);
  });

  it('rejects array bodies for action-style endpoints without crashing', async () => {
    server = await startServer();
    server.routes.post('/api/echo', (ctx, res) => {
      res.json({ got: ctx.body });
    }, { auth: 'public' });

    const response = await post(baseUrlOf(server), '/api/echo', [1, 2, 3]);
    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual({ got: [1, 2, 3] });
  });

  it('parses urlencoded bodies', async () => {
    server = await startServer();
    server.routes.post('/api/form', (ctx, res) => {
      res.json({ got: ctx.body });
    }, { auth: 'public' });

    const response = await request(baseUrlOf(server), 'POST', '/api/form', {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'a=1&b=hello%20world'
    });

    expect(response.status).toBe(200);
    expect(JSON.parse(response.text)).toEqual({ got: { a: '1', b: 'hello world' } });
  });
});

describe('error hygiene (flaw #6)', () => {
  it('never leaks internal error messages on 500s', async () => {
    server = await startServer();

    const INTERNAL_SECRET = 'sqlite://admin:hunter2@db.internal:5432/production';
    const PATH_TRACE = '/Users/sschepis/Development/alephnet-node/lib/app/server.js:412';

    server.routes.get(
      '/api/explode',
      () => {
        const error = new Error(`Connection refused for ${INTERNAL_SECRET} at ${PATH_TRACE}`);
        error.name = 'SequelizeConnectionError';
        throw error;
      },
      { auth: 'public' }
    );

    const response = await request(baseUrlOf(server), 'GET', '/api/explode');

    expect(response.status).toBe(500);

    const body = JSON.parse(response.text) as {
      error: string;
      code: string;
      requestId: string;
    };
    expect(body.error).toBe('Internal Server Error');
    expect(body.code).toBe('E9001');
    expect(body.requestId).toMatch(/^[0-9a-f]{16}$/);

    const raw = response.text;
    expect(raw).not.toContain('hunter2');
    expect(raw).not.toContain('sqlite');
    expect(raw).not.toContain('SequelizeConnectionError');
    expect(raw).not.toContain('lib/app/server.js');
  });

  it('allows client-safe HttpError messages through', async () => {
    server = await startServer();
    server.routes.get(
      '/api/teapot2',
      () => {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { HttpError } = require('../../src/app') as typeof import('../../src/app');
        throw HttpError.badRequest('E7003', 'You asked for something silly');
      },
      { auth: 'public' }
    );

    const response = await request(baseUrlOf(server), 'GET', '/api/teapot2');
    expect(response.status).toBe(400);
    const body = JSON.parse(response.text) as { error: string };
    expect(body.error).toBe('You asked for something silly');
  });

  it('never reflects the Host header into response bodies', async () => {
    server = await startServer();

    const response = await request(baseUrlOf(server), 'GET', '/status', {
      headers: { host: 'evil.attacker.example' }
    });

    expect(response.status).toBe(200);
    expect(response.text).not.toContain('evil.attacker.example');
    // The request still worked — the Host header is simply ignored
    const statusBody = JSON.parse(response.text) as { status: string };
    expect(statusBody.status).toBe('running');
  });

  it('answers OPTIONS preflight without touching auth', async () => {
    server = await startServer({ corsOrigins: ['https://ui.example'] });

    const response = await request(baseUrlOf(server), 'OPTIONS', '/api/x', {
      headers: { origin: 'https://ui.example' }
    });

    expect(response.status).toBe(204);
    expect(response.headers['access-control-allow-origin']).toBe('https://ui.example');
  });

  it('rejects a disallowed CORS origin with 403 and never echoes it back', async () => {
    server = await startServer({ corsOrigins: ['https://ui.example'] });

    const response = await request(baseUrlOf(server), 'GET', '/health', {
      headers: { origin: 'https://evil.example' }
    });

    expect(response.status).toBe(403);
    expect(response.headers['access-control-allow-origin']).toBeUndefined();
    expect(response.text).not.toContain('https://evil.example');
  });
});

describe('unmatched API routes (flaw #2)', () => {
  it('returns a real 404 for an unknown API path', async () => {
    server = await startServer();

    const response = await request(baseUrlOf(server), 'GET', '/api/does-not-exist');
    expect(response.status).toBe(404);

    const body = JSON.parse(response.text) as { error: string; code: string };
    expect(body.error).toBe('Not Found');
    expect(body.code).toBe('E4002');
  });

  it('returns 405 with Allow for a known path with the wrong method', async () => {
    server = await startServer();

    const response = await request(baseUrlOf(server), 'DELETE', '/health');
    expect(response.status).toBe(405);
    expect(response.headers.allow).toContain('GET');
  });

  it('serves HEAD for GET routes without a body', async () => {
    server = await startServer();

    const response = await request(baseUrlOf(server), 'HEAD', '/health');
    expect(response.status).toBe(200);
    expect(response.body.length).toBe(0);
  });
});
