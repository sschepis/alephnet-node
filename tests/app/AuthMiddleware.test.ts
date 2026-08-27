/**
 * Signed Request Authentication Tests
 *
 * Every case here is a legacy failure mode: unsigned requests were accepted,
 * the body was outside the signature, the fingerprint was never bound to the
 * key, and there was no nonce store at all.
 */

import { afterEach, describe, expect, it } from '@jest/globals';
import { KeyTriplet, generateKeyTriplet, signToBase64 } from '../../src/common/crypto';
import {
  AUTH_HEADERS,
  ActionRegistry,
  AlephServer,
  AuthConfigError,
  AuthMiddleware,
  buildSignaturePayload,
  createDevAuthBypass,
  createSignedRequestHeaders,
  hashRequestBody
} from '../../src/app';
import {
  baseUrlOf,
  get,
  post,
  signRequest,
  signedGet,
  signedPost,
  startServer
} from './helpers';

let server: AlephServer | null = null;

afterEach(async () => {
  if (server !== null) {
    await server.stop();
    server = null;
  }
});

describe('AuthMiddleware over HTTP', () => {
  it('rejects an unsigned request to a protected route with 401', async () => {
    server = await startServer();
    const response = await get(baseUrlOf(server), '/whoami');

    expect(response.status).toBe(401);
    const body = JSON.parse(response.text) as { error: string; requestId: string };
    expect(body.error).toMatch(/authentication headers/i);
    expect(body.requestId).toHaveLength(16);
  });

  it('accepts a validly signed request and reports the derived identity', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();

    const response = await signedGet(server, identity, '/whoami');

    expect(response.status).toBe(200);
    const body = JSON.parse(response.text) as {
      authenticated: boolean;
      fingerprint: string;
      publicKey: string;
      devBypass: boolean;
    };
    expect(body.authenticated).toBe(true);
    expect(body.fingerprint).toBe(identity.fingerprint);
    expect(body.publicKey).toBe(identity.pub);
    expect(body.devBypass).toBe(false);
  });

  it('accepts a signed POST whose body hash matches', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();

    server.routes.post('/api/echo', (ctx, res) => {
      res.json({ received: ctx.body, from: ctx.identity?.fingerprint });
    });

    const response = await signedPost(server, identity, '/api/echo', { hello: 'world' });

    expect(response.status).toBe(200);
    const body = JSON.parse(response.text) as {
      received: { hello: string };
      from: string;
    };
    expect(body.received.hello).toBe('world');
    expect(body.from).toBe(identity.fingerprint);
  });

  it('rejects a signature computed over a DIFFERENT body (body is covered)', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();

    server.routes.post('/api/transfer', (_ctx, res) => {
      res.json({ ok: true });
    });

    // Sign the innocuous body...
    const signedBody = JSON.stringify({ amount: 1 });
    const headers = signRequest(server, identity, 'POST', '/api/transfer', {
      body: signedBody
    });

    // ...then send a different one. The legacy signature covered only
    // METHOD:PATH:TIMESTAMP, so this swap was completely undetectable.
    const tamperedBody = JSON.stringify({ amount: 1_000_000 });
    const response = await post(baseUrlOf(server), '/api/transfer', tamperedBody, headers);

    expect(response.status).toBe(401);
    expect(response.text).toMatch(/Invalid signature/);
  });

  it('rejects a request whose fingerprint does not match the public key', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();
    const impersonated = generateKeyTriplet();

    // Real key, real signature — but claiming somebody else's fingerprint.
    const headers = signRequest(server, identity, 'GET', '/whoami', {
      fingerprintOverride: impersonated.fingerprint
    });

    const response = await get(baseUrlOf(server), '/whoami', headers);

    expect(response.status).toBe(401);
    expect(response.text).toMatch(/Fingerprint does not match/);
  });

  it('rejects a malformed fingerprint', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();
    const headers = signRequest(server, identity, 'GET', '/whoami', {
      fingerprintOverride: 'not-a-fingerprint'
    });

    const response = await get(baseUrlOf(server), '/whoami', headers);
    expect(response.status).toBe(401);
    expect(response.text).toMatch(/Malformed fingerprint/);
  });

  it('rejects a stale timestamp even when the signature is valid', async () => {
    server = await startServer({ authFreshnessMs: 5_000 });
    const identity = generateKeyTriplet();

    const headers = signRequest(server, identity, 'GET', '/whoami', {
      timestamp: Date.now() - 60_000
    });

    const response = await get(baseUrlOf(server), '/whoami', headers);

    expect(response.status).toBe(401);
    expect(response.text).toMatch(/freshness window/);
  });

  it('rejects a future timestamp outside the freshness window', async () => {
    server = await startServer({ authFreshnessMs: 5_000 });
    const identity = generateKeyTriplet();

    const headers = signRequest(server, identity, 'GET', '/whoami', {
      timestamp: Date.now() + 120_000
    });

    const response = await get(baseUrlOf(server), '/whoami', headers);
    expect(response.status).toBe(401);
    expect(response.text).toMatch(/freshness window/);
  });

  it('rejects a replayed nonce', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();

    const headers = signRequest(server, identity, 'GET', '/whoami', {
      nonce: 'replay-nonce-0001'
    });

    const first = await get(baseUrlOf(server), '/whoami', headers);
    expect(first.status).toBe(200);

    // Byte-identical replay: valid signature, valid timestamp, used nonce
    const second = await get(baseUrlOf(server), '/whoami', headers);
    expect(second.status).toBe(401);
    expect(second.text).toMatch(/replay rejected/i);
  });

  it('rejects a signature bound to a different path', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();

    const headers = signRequest(server, identity, 'GET', '/status/other');
    const response = await get(baseUrlOf(server), '/whoami', headers);

    expect(response.status).toBe(401);
    expect(response.text).toMatch(/Invalid signature/);
  });

  it('rejects a signature bound to a different query string', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();

    server.routes.get('/api/query', (_ctx, res) => res.json({ ok: true }));

    const headers = signRequest(server, identity, 'GET', '/api/query?limit=1');
    const response = await get(baseUrlOf(server), '/api/query?limit=9999', headers);

    expect(response.status).toBe(401);
  });

  it('rejects a legacy-style forged "signature object" (contentHash only)', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();

    // The exact legacy forgery: an object whose contentHash matches the content.
    // verify() returned { valid: true } for this without touching a key.
    const timestamp = Date.now();
    const forged = JSON.stringify({
      contentHash: hashRequestBody('GET:/whoami:' + String(timestamp)),
      signatureHash: 'whatever'
    });

    const response = await get(baseUrlOf(server), '/whoami', {
      [AUTH_HEADERS.FINGERPRINT]: identity.fingerprint,
      [AUTH_HEADERS.PUBLIC_KEY]: identity.pub,
      [AUTH_HEADERS.SIGNATURE]: forged,
      [AUTH_HEADERS.TIMESTAMP]: String(timestamp),
      [AUTH_HEADERS.NONCE]: 'legacy-forgery-nonce'
    });

    expect(response.status).toBe(401);
  });

  it('rejects a request with no public key header (no fingerprint-only fallback)', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();

    const timestamp = Date.now();
    const nonce = 'no-pubkey-nonce-1';
    const payload = buildSignaturePayload({
      method: 'GET',
      target: '/whoami',
      timestamp,
      nonce,
      bodyHash: hashRequestBody(undefined)
    });
    const signature = signToBase64(payload, Buffer.from(identity.priv, 'base64'));

    const response = await get(baseUrlOf(server), '/whoami', {
      [AUTH_HEADERS.FINGERPRINT]: identity.fingerprint,
      [AUTH_HEADERS.SIGNATURE]: signature,
      [AUTH_HEADERS.TIMESTAMP]: String(timestamp),
      [AUTH_HEADERS.NONCE]: nonce
    });

    expect(response.status).toBe(401);
    expect(response.text).toMatch(/authentication headers/i);
  });

  it('rejects a public key of the wrong length', async () => {
    server = await startServer();
    const identity = generateKeyTriplet();
    const headers = signRequest(server, identity, 'GET', '/whoami');
    headers[AUTH_HEADERS.PUBLIC_KEY] = Buffer.alloc(16, 7).toString('base64');

    const response = await get(baseUrlOf(server), '/whoami', headers);
    expect(response.status).toBe(401);
    expect(response.text).toMatch(/public key/i);
  });

  it('allows public routes without any signature', async () => {
    server = await startServer();

    const health = await get(baseUrlOf(server), '/health');
    expect(health.status).toBe(200);

    const status = await get(baseUrlOf(server), '/status');
    expect(status.status).toBe(200);
  });

  it('does not read any environment variable to disable auth', async () => {
    const previous = process.env.ALEPH_DEV_NO_AUTH;
    process.env.ALEPH_DEV_NO_AUTH = 'true';
    try {
      server = await startServer();
      const response = await get(baseUrlOf(server), '/whoami');
      expect(response.status).toBe(401);
    } finally {
      if (previous === undefined) {
        delete process.env.ALEPH_DEV_NO_AUTH;
      } else {
        process.env.ALEPH_DEV_NO_AUTH = previous;
      }
    }
  });

  it('only bypasses auth via an explicit constructor option', async () => {
    server = await startServer({
      unsafeDevAuthBypass: createDevAuthBypass(
        'i-understand-this-disables-all-request-authentication',
        'aaaaaaaaaaaaaaaa'
      )
    });

    const response = await get(baseUrlOf(server), '/whoami');
    expect(response.status).toBe(200);

    const body = JSON.parse(response.text) as { devBypass: boolean; fingerprint: string };
    expect(body.devBypass).toBe(true);
    expect(body.fingerprint).toBe('aaaaaaaaaaaaaaaa');
  });

  it('refuses a dev bypass with a wrong acknowledgement literal', () => {
    expect(() =>
      createDevAuthBypass(
        'nope' as unknown as 'i-understand-this-disables-all-request-authentication'
      )
    ).toThrow(/acknowledgement/);
  });

  it('produces a signature payload that covers every request field', () => {
    const identity: KeyTriplet = generateKeyTriplet();
    const headers = createSignedRequestHeaders({
      method: 'post',
      target: '/api/x?y=1',
      body: '{"a":1}',
      privateKey: identity.priv,
      publicKey: identity.pub,
      timestamp: 1_700_000_000_000,
      nonce: 'fixed-nonce-value'
    });

    const expected = buildSignaturePayload({
      method: 'POST',
      target: '/api/x?y=1',
      timestamp: 1_700_000_000_000,
      nonce: 'fixed-nonce-value',
      bodyHash: hashRequestBody('{"a":1}')
    });

    expect(expected.split('\n')).toEqual([
      'ALEPHNET-REQUEST-V2',
      'POST',
      '/api/x?y=1',
      '1700000000000',
      'fixed-nonce-value',
      hashRequestBody('{"a":1}')
    ]);
    expect(headers[AUTH_HEADERS.SIGNATURE]).toEqual(
      signToBase64(expected, Buffer.from(identity.priv, 'base64'))
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// CONSTRUCTION INVARIANTS (nonce TTL vs freshness window)
// ═══════════════════════════════════════════════════════════════════════════

describe('AuthMiddleware construction invariants', () => {
  it('throws a typed AuthConfigError when nonceCache.ttlMs does not outlive freshnessMs', () => {
    expect(
      () => new AuthMiddleware({ freshnessMs: 60_000, nonceCache: { ttlMs: 30_000 } })
    ).toThrow(AuthConfigError);
    expect(
      () => new AuthMiddleware({ freshnessMs: 60_000, nonceCache: { ttlMs: 60_000 } })
    ).toThrow(/must be greater than/);
  });

  it('accepts a nonce TTL strictly greater than the freshness window', () => {
    const auth = new AuthMiddleware({
      freshnessMs: 30_000,
      nonceCache: { ttlMs: 60_000, sweepIntervalMs: 0 }
    });
    expect(auth.bypassActive).toBe(false);
    auth.dispose();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// DEV BYPASS PRODUCTION GUARD
// ═══════════════════════════════════════════════════════════════════════════

describe('dev bypass production guard', () => {
  const previousNodeEnv = process.env.NODE_ENV;

  afterEach(() => {
    if (previousNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = previousNodeEnv;
    }
  });

  it.each(['production', 'Production', 'PRODUCTION', 'prod', 'PROD', 'ProD'])(
    'refuses the bypass when NODE_ENV=%s',
    (variant: string) => {
      process.env.NODE_ENV = variant;
      expect(() =>
        new AuthMiddleware({
          devBypass: createDevAuthBypass(
            'i-understand-this-disables-all-request-authentication'
          )
        })
      ).toThrow(/Refusing to construct AuthMiddleware/);
    }
  );

  it('allows the bypass outside any production-like NODE_ENV', () => {
    process.env.NODE_ENV = 'development';
    const auth = new AuthMiddleware({
      devBypass: createDevAuthBypass('i-understand-this-disables-all-request-authentication')
    });
    expect(auth.bypassActive).toBe(true);
    auth.dispose();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// REPLAY-PROTECTION PARTITIONING OVER HTTP
// ═══════════════════════════════════════════════════════════════════════════

describe('nonce partitioning over HTTP', () => {
  it('a valid-signed request flood from one identity never evicts a victim nonce', async () => {
    // Small per-partition cap: the attacker's bucket fills to 40 and stays
    // there, while the victim's single nonce remains reserved.
    server = await startServer({
      nonceCache: { maxEntries: 100, maxEntriesPerPartition: 40, ttlMs: 120_000, sweepIntervalMs: 0 },
      rateLimiter: { limit: 10_000, maxEntries: 10_000 }
    });

    const victim = generateKeyTriplet();
    const victimHeaders = signRequest(server, victim, 'GET', '/whoami', {
      nonce: 'victim-live-nonce'
    });
    const first = await get(baseUrlOf(server), '/whoami', victimHeaders);
    expect(first.status).toBe(200);

    // Attacker sprays 150 VALID signed requests (each consumes a nonce) —
    // far beyond the old global cap, which forced the victim's nonce out.
    const attacker = generateKeyTriplet();
    for (let i = 0; i < 150; i++) {
      const headers = signRequest(server, attacker, 'GET', '/whoami', {
        nonce: `attacker-nonce-${String(i).padStart(4, '0')}`
      });
      await get(baseUrlOf(server), '/whoami', headers);
    }

    // The captured victim nonce must STILL be rejected as replayed
    const replay = await get(baseUrlOf(server), '/whoami', victimHeaders);
    expect(replay.status).toBe(401);
    expect(replay.text).toMatch(/replay rejected/i);
  });

  it('the dev-bypass identity carries devBypass=true so downstream handlers can distinguish it', async () => {
    const registry = new ActionRegistry();
    let seenDevBypass: boolean | null = null;
    let seenFingerprint: string | null = null;
    registry.register({
      name: 'test.flag',
      description: 'report the identity devBypass flag',
      input: {},
      handler: async (_input, ctx) => {
        seenDevBypass = ctx.identity?.devBypass ?? null;
        seenFingerprint = ctx.identity?.fingerprint ?? null;
        return { ok: true };
      }
    });

    server = new AlephServer({
      port: 0,
      host: '127.0.0.1',
      actions: registry,
      unsafeDevAuthBypass: createDevAuthBypass(
        'i-understand-this-disables-all-request-authentication',
        'beefbeefbeefbeef'
      )
    });
    await server.start();

    const response = await post(baseUrlOf(server), '/actions/test.flag', {});
    expect(response.status).toBe(200);
    expect(seenDevBypass).toBe(true);
    expect(seenFingerprint).toBe('beefbeefbeefbeef');
  });

  it('a real signed identity carries devBypass=false in action contexts', async () => {
    const registry = new ActionRegistry();
    let seenDevBypass: boolean | null = null;
    registry.register({
      name: 'test.flag',
      description: 'report the identity devBypass flag',
      input: {},
      handler: async (_input, ctx) => {
        seenDevBypass = ctx.identity?.devBypass ?? null;
        return { ok: true };
      }
    });

    server = new AlephServer({ port: 0, host: '127.0.0.1', actions: registry });
    await server.start();
    const identity = generateKeyTriplet();

    const response = await signedPost(server, identity, '/actions/test.flag', {});
    expect(response.status).toBe(200);
    expect(seenDevBypass).toBe(false);
  });
});
