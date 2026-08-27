/**
 * Shared test helpers for the node composition suite.
 *
 * Not a spec file: jest only picks up *.test.ts under tests/.
 */

import * as http from 'http';
import type { IncomingMessage } from 'http';
import { generateKeyTriplet, KeyTriplet } from '../../src/common/crypto';
import { createSignedRequestHeaders, type AuthenticatedIdentity } from '../../src/app';
import { AlephNode, AlephNodeConfig } from '../../src/node';

// ═══════════════════════════════════════════════════════════════════════════
// FAKE GUN LEDGER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * One chain step of the fake Gun graph. Mirrors the subset of Gun's chain
 * API that `AlephWallet` and the node layer actually use.
 */
export class FakeGunChain {
  constructor(
    private readonly gun: FakeGun,
    private readonly path: readonly string[]
  ) {}

  get(key: string): FakeGunChain {
    return new FakeGunChain(this.gun, [...this.path, key]);
  }

  put(data: Record<string, unknown>): FakeGunChain {
    this.gun.putAt(this.path, data);
    return this;
  }

  set(data: Record<string, unknown>): FakeGunChain {
    return this.put(data);
  }

  map(): FakeGunChain {
    return this;
  }

  off(): void {
    return;
  }

  /**
   * Resolve asynchronously (like Gun): exact leaf record, or — when no leaf
   * exists at this path — the merged map of every immediate child record,
   * which is what Gun hands back for `once` on a map node.
   */
  once(callback?: (data: Record<string, unknown> | null, key?: string) => void): FakeGunChain {
    const data = this.gun.readAt(this.path);
    setTimeout(() => {
      callback?.(data, this.path.join('/'));
    }, 0);
    return this;
  }
}

/**
 * A working in-memory Gun stand-in: asynchronous `once` resolution, merging
 * `put` semantics and map-node reads — enough for the wallet's full
 * read-check-write lifecycle (the previous test fake never resolved `once`,
 * so no funds could ever move).
 */
export class FakeGun {
  private readonly store = new Map<string, Record<string, unknown>>();

  get(key: string): FakeGunChain {
    return new FakeGunChain(this, [key]);
  }

  /** Merge `data` into the record at `path` (Gun's put merges fields). */
  putAt(path: readonly string[], data: Record<string, unknown>): void {
    const key = path.join('/');
    const existing = this.store.get(key) ?? {};
    this.store.set(key, { ...existing, ...data });
  }

  /** Exact leaf record at `path`, or the merged children map one level down. */
  readAt(path: readonly string[]): Record<string, unknown> | null {
    const key = path.join('/');
    const exact = this.store.get(key);
    if (exact !== undefined) return { ...exact };
    const prefix = `${key}/`;
    const children: Record<string, unknown> = {};
    for (const [entryKey, data] of this.store) {
      if (!entryKey.startsWith(prefix)) continue;
      const rest = entryKey.slice(prefix.length);
      if (rest.length === 0 || rest.includes('/')) continue;
      children[rest] = { ...data };
    }
    return Object.keys(children).length > 0 ? children : null;
  }

  /** Direct synchronous snapshot of one record (test assertions only). */
  recordAt(path: readonly string[]): Record<string, unknown> | null {
    return this.readAt(path);
  }
}

/**
 * Seed an account on the fake ledger (base units), so tests can give a
 * caller funds and/or an Adept-tier staked balance before any action runs.
 */
export function fundAccount(
  gun: FakeGun,
  address: string,
  available: bigint,
  staked: bigint = 0n
): void {
  gun.get('ledger').get('accounts').get(address).put({
    total: (available + staked).toString(),
    available: available.toString(),
    staked: staked.toString(),
    pendingUnstake: '0',
    reserved: '0',
    unclaimedRewards: '0',
    stakingTier: 'Neophyte',
    updatedAt: Date.now()
  });
}

/** Await the ledger record for one account address. */
export function readLedgerAccount(
  gun: FakeGun,
  address: string
): Promise<Record<string, unknown> | null> {
  return new Promise((resolve) => {
    gun.get('ledger').get('accounts').get(address).once((data) => resolve(data));
  });
}

/** Await the full stakes subtree (as the node's reconcile read sees it). */
export function readLedgerStakes(
  gun: FakeGun
): Promise<Record<string, unknown> | null> {
  return new Promise((resolve) => {
    gun.get('ledger').get('stakes').once((data) => resolve(data));
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// IDENTITIES & NODES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create a fresh Ed25519 identity for signing test requests.
 */
export function createTestIdentity(): KeyTriplet {
  return generateKeyTriplet();
}

/** The `AuthenticatedIdentity` shape the registry expects for an identity. */
export function authenticatedIdentity(identity: KeyTriplet): AuthenticatedIdentity {
  return {
    fingerprint: identity.fingerprint,
    publicKey: identity.pub,
    timestamp: Date.now(),
    nonce: 'test-nonce',
    devBypass: false
  };
}

/**
 * Create AND start a node bound to an ephemeral port.
 */
export async function startNode(config: AlephNodeConfig = {}): Promise<{
  node: AlephNode;
  baseUrl: string;
}> {
  const node = await AlephNode.create({ port: 0, host: '127.0.0.1', ...config });
  await node.start();
  return { node, baseUrl: `http://127.0.0.1:${String(node.getStatus().port)}` };
}

/**
 * Headers for a signed request against a running node.
 */
export function signRequest(
  identity: KeyTriplet,
  method: string,
  target: string,
  options: { body?: string | Buffer; timestamp?: number; nonce?: string } = {}
): Record<string, string> {
  return createSignedRequestHeaders({
    method,
    target,
    body: options.body,
    privateKey: identity.priv,
    publicKey: identity.pub,
    timestamp: options.timestamp,
    nonce: options.nonce
  });
}

export interface RawResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  text: string;
}

/**
 * Minimal fetch-like helper that always drains the response body, so sockets
 * return to the pool and stop() never hangs.
 */
export function request(
  baseUrl: string,
  method: string,
  path: string,
  options: { headers?: Record<string, string>; body?: string | Buffer } = {}
): Promise<RawResponse> {
  return new Promise<RawResponse>((resolve, reject) => {
    const body =
      options.body === undefined
        ? undefined
        : Buffer.isBuffer(options.body)
          ? options.body
          : Buffer.from(options.body, 'utf8');
    const req = http.request(
      `${baseUrl}${path}`,
      {
        method,
        headers: {
          ...(body !== undefined && body.length > 0 ? { 'content-length': String(body.length) } : {}),
          ...options.headers
        }
      },
      (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer | string) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: buf,
            text: buf.toString('utf8')
          });
        });
        res.on('error', reject);
      }
    );
    req.on('error', reject);
    if (body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

export async function get(
  baseUrl: string,
  path: string,
  headers: Record<string, string> = {}
): Promise<RawResponse> {
  return request(baseUrl, 'GET', path, { headers });
}

export async function post(
  baseUrl: string,
  path: string,
  body: string | object,
  headers: Record<string, string> = {}
): Promise<RawResponse> {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  return request(baseUrl, 'POST', path, {
    headers: { 'content-type': 'application/json', ...headers },
    body: payload
  });
}

/**
 * Signed POST against a running node (the body IS covered by the signature).
 */
export async function signedPost(
  node: AlephNode,
  identity: KeyTriplet,
  path: string,
  body: string | object
): Promise<RawResponse> {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  const port = node.getStatus().port;
  const headers = signRequest(identity, 'POST', path, { body: payload });
  return post(`http://127.0.0.1:${String(port)}`, path, body, headers);
}
