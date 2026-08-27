/**
 * ActionRegistry integration over HTTP.
 *
 * Proves the seam the composition root will wire domain modules into:
 * auth-gated invocation, input validation, tier enforcement and catalogue.
 */

import { afterEach, describe, expect, it } from '@jest/globals';
import { generateKeyTriplet } from '../../src/common/crypto';
import { ActionRegistry, AlephServer, TierResolver } from '../../src/app';
import { StakingTier } from '../../src/common/types';
import { baseUrlOf, get, post, signedGet, signedPost, startServer } from './helpers';

let server: AlephServer | null = null;

afterEach(async () => {
  if (server !== null) {
    await server.stop();
    server = null;
  }
});

function buildServer(): { server: AlephServer; registry: ActionRegistry } {
  const registry = new ActionRegistry();

  registry.register({
    name: 'test.echo',
    description: 'Echo validated input back',
    input: {
      text: { type: 'string', required: true, minLength: 2 },
      times: { type: 'integer', required: false, min: 1, max: 10, default: 1 }
    },
    handler: async (input: { text: string; times?: number }, ctx) => ({
      echo: input.text.repeat(input.times ?? 1),
      from: ctx.identity?.fingerprint ?? null,
      tier: ctx.tier
    })
  });

  registry.register({
    name: 'wallet.stake',
    description: 'Stake tokens (Magus+)',
    input: {
      amount: { type: 'bigintString', required: true }
    },
    requiredTier: 'Magus',
    handler: async (input: { amount: string }) => ({ staked: input.amount })
  });

  registry.register({
    name: 'open.ping',
    description: 'Public action',
    requiresAuth: false,
    input: {},
    handler: async () => ({ pong: true })
  });

  const fixedTier: TierResolver = {
    resolveTier: () => 'Adept'
  };
  registry.setTierResolver(fixedTier);

  const srv = new AlephServer({
    port: 0,
    host: '127.0.0.1',
    actions: registry,
    logger: undefined
  });

  return { server: srv, registry };
}

describe('ActionRegistry over HTTP', () => {
  it('lists actions publicly without handlers leaking', async () => {
    server = buildServer().server;
    await server.start();

    const response = await get(baseUrlOf(server), '/actions/list');
    expect(response.status).toBe(200);

    const body = JSON.parse(response.text) as {
      actions: Array<{ name: string; requiresAuth: boolean; requiredTier: string }>;
    };
    const names = body.actions.map((a) => a.name);
    expect(names).toEqual(['open.ping', 'test.echo', 'wallet.stake']);

    const stake = body.actions.find((a) => a.name === 'wallet.stake');
    expect(stake?.requiredTier).toBe('Magus');
    expect(stake?.requiresAuth).toBe(true);
    expect(response.text).not.toContain('handler');
  });

  it('rejects unauthenticated invocation of an auth-required action', async () => {
    server = buildServer().server;
    await server.start();

    const response = await post(baseUrlOf(server), '/actions/test.echo', { text: 'hi' });
    expect(response.status).toBe(401);
  });

  it('invokes an action for an authenticated caller with validated input', async () => {
    const { server: srv } = buildServer();
    server = srv;
    await server.start();
    const identity = generateKeyTriplet();

    const response = await signedPost(server, identity, '/actions/test.echo', {
      text: 'ab',
      times: 3
    });

    expect(response.status).toBe(200);
    const body = JSON.parse(response.text) as {
      action: string;
      output: { echo: string; from: string; tier: StakingTier };
      durationMs: number;
    };
    expect(body.action).toBe('test.echo');
    expect(body.output.echo).toBe('ababab');
    expect(body.output.from).toBe(identity.fingerprint);
    expect(body.output.tier).toBe('Adept');
    expect(body.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('rejects invalid input with 400 and field errors', async () => {
    const { server: srv } = buildServer();
    server = srv;
    await server.start();
    const identity = generateKeyTriplet();

    const response = await signedPost(server, identity, '/actions/test.echo', {
      text: 'x',
      times: 99
    });

    expect(response.status).toBe(400);
    const body = JSON.parse(response.text) as { code: string; details: unknown[] };
    expect(body.code).toBe('E7001');
    expect(Array.isArray(body.details)).toBe(true);
    expect(JSON.stringify(body.details)).toContain('text');
    expect(JSON.stringify(body.details)).toContain('times');
  });

  it('rejects a tier-gated action for an under-tiered caller with 403', async () => {
    const { server: srv } = buildServer();
    server = srv;
    await server.start();
    const identity = generateKeyTriplet();

    const response = await signedPost(server, identity, '/actions/wallet.stake', {
      amount: '1000000000000000000'
    });

    expect(response.status).toBe(403);
    const body = JSON.parse(response.text) as { code: string; error: string; details: unknown };
    expect(body.code).toBe('E6004');
    expect(body.error).toMatch(/Magus/);
    expect((body.details as { currentTier: StakingTier }).currentTier).toBe('Adept');
  });

  it('returns 404 for an unknown action', async () => {
    const { server: srv } = buildServer();
    server = srv;
    await server.start();
    const identity = generateKeyTriplet();

    const response = await signedPost(server, identity, '/actions/does.not-exist', {});
    expect(response.status).toBe(404);
  });

  it('allows a declared-public action without auth', async () => {
    server = buildServer().server;
    await server.start();

    const response = await post(baseUrlOf(server), '/actions/open.ping', {});
    expect(response.status).toBe(200);
    const parsed = JSON.parse(response.text) as { output: { pong: boolean } };
    expect(parsed.output).toEqual({ pong: true });
  });

  it('masks handler failures as generic 500s', async () => {
    const registry = new ActionRegistry();
    registry.register({
      name: 'test.explode',
      description: 'Boom',
      input: {},
      handler: async () => {
        throw new Error('DATABASE-PASSWORD-DO-NOT-LEAK');
      }
    });
    server = new AlephServer({ port: 0, host: '127.0.0.1', actions: registry });
    await server.start();
    const identity = generateKeyTriplet();

    const response = await signedPost(server, identity, '/actions/test.explode', {});
    expect(response.status).toBe(500);
    expect(response.text).not.toContain('DATABASE-PASSWORD-DO-NOT-LEAK');
    expect(response.text).toContain('Internal Server Error');
  });

  it('rejects duplicate and mis-namespaced registrations', () => {
    const registry = new ActionRegistry();
    registry.register({
      name: 'ok.action',
      description: 'x',
      input: {},
      handler: async () => null
    });

    expect(() =>
      registry.register({
        name: 'ok.action',
        description: 'dup',
        input: {},
        handler: async () => null
      })
    ).toThrow(/already registered/);

    expect(() =>
      registry.register({
        name: 'no-namespace',
        description: 'bad',
        input: {},
        handler: async () => null
      })
    ).toThrow(/Invalid action name/);

    expect(() =>
      registry.registerModule({
        namespace: 'mod',
        actions: [
          {
            name: 'other.thing',
            description: 'wrong namespace',
            input: {},
            handler: async () => null
          }
        ]
      })
    ).toThrow(/must be namespaced under 'mod\.'/);
  });
});
