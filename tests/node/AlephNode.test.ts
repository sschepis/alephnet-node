/**
 * AlephNode lifecycle & subsystem degradation tests.
 *
 * Proves the composition root's contract:
 *   - create() succeeds on an ephemeral port and reports every subsystem;
 *   - start()/stop() are graceful and stop() is idempotent;
 *   - missing optional dependencies (Gun, faucet secret) DEGRADE EXPLICITLY:
 *     the subsystem is disabled with a stated reason and its actions return
 *     the typed `SUBSYSTEM_UNAVAILABLE` failure — never a fake success;
 *   - availability gates fire BEFORE tier gating, so a no-ledger node
 *     answers 503 SUBSYSTEM_UNAVAILABLE (never a personal 403) for actions
 *     whose subsystem is off;
 *   - a structurally broken Gun is never reported as "enabled".
 */

import { describe, it, expect, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AlephNode, AlephNodeStartupError } from '../../src/node';
import { FakeGun, createTestIdentity, get, post, signedPost, startNode } from './helpers';

describe('AlephNode lifecycle', () => {
  let node: AlephNode;

  afterEach(async () => {
    await node.stop();
  });

  it('creates, starts and reports status on an ephemeral port', async () => {
    node = await AlephNode.create({ port: 0, host: '127.0.0.1' });

    const before = node.getStatus();
    expect(before.listening).toBe(false);
    expect(before.port).toBeNull();
    expect(before.fingerprint).toMatch(/^[0-9a-f]{16}$/);
    expect(before.subsystems.semantic.enabled).toBe(true);
    expect(before.subsystems.social.enabled).toBe(true);
    expect(before.subsystems.content.enabled).toBe(true);
    expect(before.subsystems.coherence.enabled).toBe(true);
    expect(before.subsystems.economy.enabled).toBe(false);
    expect(before.subsystems.economy.reason).toMatch(/Gun/i);
    expect(before.subsystems.faucet.enabled).toBe(false);
    expect(before.subsystems.faucet.reason).toMatch(/faucet secret/i);
    expect(before.counts.actions).toBeGreaterThan(0);

    await node.start();

    const status = node.getStatus();
    expect(status.listening).toBe(true);
    expect(status.port).toBeGreaterThan(0);
    expect(status.startedAt).not.toBeNull();
    expect(status.uptimeMs).toBeGreaterThanOrEqual(0);
    expect(status.semantic.enabled).toBe(true);
    expect(status.semantic.kernel?.loaded).toBe(true);
    expect(status.identityCanSign).toBe(true);

    // The public /node/status route mirrors getStatus().
    const res = await get(`http://127.0.0.1:${String(status.port)}`, '/node/status');
    expect(res.status).toBe(200);
    const body = JSON.parse(res.text);
    expect(body.fingerprint).toBe(status.fingerprint);
    expect(body.subsystems.economy.enabled).toBe(false);
  });

  it('stop() is idempotent and a stopped node refuses to restart', async () => {
    node = await AlephNode.create({ port: 0 });
    await node.start();
    await node.stop();
    expect(node.getStatus().listening).toBe(false);
    expect(node.getStatus().startedAt).toBeNull();

    // Idempotent: a second stop() is a no-op, not an error.
    await node.stop();

    await expect(node.start()).rejects.toThrow(/stopped/i);
  });

  it('start() refuses to run twice', async () => {
    node = await AlephNode.create({ port: 0 });
    await node.start();
    await expect(node.start()).rejects.toThrow(/already started/i);
  });
});

describe('subsystem degradation', () => {
  let started: AlephNode[] = [];

  afterEach(async () => {
    // Every node here binds a real port; leaving one listening leaks a handle
    // and hangs the runner.
    await Promise.all(started.map(async n => n.stop()));
    started = [];
  });

  it('without Gun and faucet secret: subsystems disabled with reasons, availability gates answer 503', async () => {
    const { node, baseUrl } = await startNode({ port: 0 });
    started.push(node);
    const status = node.getStatus();

    expect(status.subsystems.economy.enabled).toBe(false);
    expect(status.subsystems.economy.reason).toBeTruthy();
    expect(status.subsystems.faucet.enabled).toBe(false);
    expect(status.subsystems.faucet.reason).toBeTruthy();
    expect(status.subsystems.coherence.detail?.marketAvailable).toBe(false);

    const identity = createTestIdentity();

    // Availability is evaluated BEFORE tier gating: a wallet action on a
    // no-ledger node is a subsystem outage (503 SUBSYSTEM_UNAVAILABLE), not
    // a per-caller tier refusal.
    const balanceRes = await signedPost(node, identity, '/actions/wallet.balance', {});
    expect(balanceRes.status).toBe(503);
    const balanceBody = JSON.parse(balanceRes.text);
    expect(balanceBody.code).toBe('E4001');
    expect(balanceBody.error).toMatch(/Gun/i);

    // Public faucet action -> typed faucet unavailability (no auth needed).
    // faucet.challenge is NOT tier-gated, so its typed failure arrives in the
    // handler output (200) rather than through the availability gate.
    const challengeRes = await post(baseUrl, '/actions/faucet.challenge', { pub: identity.pub });
    expect(challengeRes.status).toBe(200);
    const challengeBody = JSON.parse(challengeRes.text).output;
    expect(challengeBody.ok).toBe(false);
    expect(challengeBody.code).toBe('SUBSYSTEM_UNAVAILABLE');
    expect(challengeBody.subsystem).toBe('faucet');

    // Transfers must not fake success either.
    const transferRes = await signedPost(node, identity, '/actions/wallet.transfer', {
      to: 'a'.repeat(16),
      amount: '1'
    });
    expect(transferRes.status).toBe(503);

    // The coherence market depends on the ledger as well: the availability
    // gate fires BEFORE the Adept tier check, so this is a 503 subsystem
    // outage, never a 403 TIER_REQUIRED.
    const taskRes = await signedPost(node, identity, '/actions/coherence.createTask', {
      type: 'VERIFY',
      claimId: 'clm_missing'
    });
    expect(taskRes.status).toBe(503);
    const taskBody = JSON.parse(taskRes.text);
    expect(taskBody.code).toBe('E4001');
    expect(taskBody.error).toMatch(/Gun/i);
  });

  it('with a Gun ledger and faucet secret: economy and faucet are enabled', async () => {
    const fakeGun = new FakeGun();
    const secret = Buffer.from('x'.repeat(32), 'utf8');
    const { node } = await startNode({ port: 0, gun: fakeGun, faucetSecret: secret });
    started.push(node);
    const status = node.getStatus();
    expect(status.subsystems.economy.enabled).toBe(true);
    expect(status.subsystems.economy.reason).toBeNull();
    expect(status.subsystems.faucet.enabled).toBe(true);
    expect(status.subsystems.faucet.reason).toBeNull();
    expect(status.subsystems.coherence.detail?.marketAvailable).toBe(true);
  });

  it('reports a structurally invalid Gun as economy disabled with a clear reason', async () => {
    // A broken "Gun" (no get function) must never be claimed as enabled —
    // the wallet would throw mid-request instead.
    const { node } = await startNode({ port: 0, gun: { put: () => undefined } });
    started.push(node);
    const status = node.getStatus();
    expect(status.subsystems.economy.enabled).toBe(false);
    expect(status.subsystems.economy.reason).toMatch(/invalid Gun ledger supplied \(missing get\/put\/once\)/);

    // The availability gate surfaces the same reason over HTTP.
    const identity = createTestIdentity();
    const balanceRes = await signedPost(node, identity, '/actions/wallet.balance', {});
    expect(balanceRes.status).toBe(503);
    const body = JSON.parse(balanceRes.text);
    expect(body.error).toMatch(/invalid Gun ledger/);
  });

  it('reports a present-but-short faucet secret as too short, not as missing', async () => {
    const fakeGun = new FakeGun();
    const { node } = await startNode({ port: 0, gun: fakeGun, faucetSecret: Buffer.from('short') });
    started.push(node);
    const status = node.getStatus();
    expect(status.subsystems.economy.enabled).toBe(true);
    expect(status.subsystems.faucet.enabled).toBe(false);
    expect(status.subsystems.faucet.reason).toMatch(/faucet secret too short \(minimum 32 bytes\)/);
  });

  it('rejects corsOrigins ["*"] at startup (the contract is an exact-match allowlist)', async () => {
    await expect(AlephNode.create({ corsOrigins: ['*'] })).rejects.toThrow(/corsOrigins/);
  });

  it('maps a weak identity password to IDENTITY_PASSWORD_TOO_WEAK', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'alephnode-weak-pw-'));
    try {
      await expect(
        AlephNode.create({ dataDir: dir, identityPassword: 'tiny' })
      ).rejects.toMatchObject({
        code: 'IDENTITY_PASSWORD_TOO_WEAK'
      });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('dev auth bypass + Gun: wallet actions answer a typed identity-unavailable failure, not a 500', async () => {
    const fakeGun = new FakeGun();
    const { node, baseUrl } = await startNode({ port: 0, gun: fakeGun, devAuthBypass: true });
    started.push(node);

    // No signature headers at all: the bypass hands the request a loud
    // dev identity that carries NO public key, so no ledger address exists.
    const res = await post(baseUrl, '/actions/wallet.balance', {});
    expect(res.status).toBe(200);
    const body = JSON.parse(res.text).output;
    expect(body.ok).toBe(false);
    expect(body.code).toBe('IDENTITY_UNAVAILABLE');
    expect(body.message).toMatch(/identity unavailable/i);
  });
});

describe('AlephNodeStartupError codes', () => {
  it('exposes a stable code on every startup failure', () => {
    const error = new AlephNodeStartupError('STORE_INIT_FAILED', 'boom');
    expect(error.code).toBe('STORE_INIT_FAILED');
    expect(error.name).toBe('AlephNodeStartupError');
  });
});
