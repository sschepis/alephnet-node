/**
 * Shared test helpers for the application layer suite.
 *
 * Not a spec file: jest only picks up *.test.ts under tests/.
 */

import * as http from 'http';
import type { IncomingMessage } from 'http';
import { generateKeyTriplet, KeyTriplet } from '../../src/common/crypto';
import {
  AlephServer,
  AlephServerOptions,
  buildSignaturePayload,
  createSignedRequestHeaders,
  hashRequestBody
} from '../../src/app';

/**
 * Create a fresh identity for signing test requests
 */
export function createTestIdentity(): KeyTriplet {
  return generateKeyTriplet();
}

/**
 * Start a server bound to an ephemeral port
 */
export async function startServer(options: AlephServerOptions = {}): Promise<AlephServer> {
  const server = new AlephServer({ port: 0, host: '127.0.0.1', ...options });
  await server.start();
  return server;
}

export function baseUrlOf(server: AlephServer): string {
  return `http://127.0.0.1:${String(server.port)}`;
}

/**
 * Headers for a signed request against a running server
 */
export function signRequest(
  server: AlephServer,
  identity: KeyTriplet,
  method: string,
  target: string,
  options: {
    body?: string | Buffer;
    timestamp?: number;
    nonce?: string;
    fingerprintOverride?: string;
  } = {}
): Record<string, string> {
  return createSignedRequestHeaders({
    method,
    target,
    body: options.body,
    privateKey: identity.priv,
    publicKey: identity.pub,
    timestamp: options.timestamp,
    nonce: options.nonce,
    fingerprintOverride: options.fingerprintOverride
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
 * return to the pool and afterEach(server.stop()) never hangs.
 */
export function request(
  baseUrl: string,
  method: string,
  path: string,
  options: { headers?: Record<string, string>; body?: string | Buffer } = {}
): Promise<RawResponse> {
  return new Promise<RawResponse>((resolve, reject) => {
    const body = options.body === undefined ? undefined : Buffer.isBuffer(options.body) ? options.body : Buffer.from(options.body, 'utf8');
    const req = http.request(
      `${baseUrl}${path}`,
      {
        method,
        headers: {
          // Every helper request closes its connection: pooled keep-alive
          // sockets otherwise linger past the last test and trip jest's
          // open-handle force-exit on full-suite runs.
          connection: 'close',
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

export async function get(baseUrl: string, path: string, headers: Record<string, string> = {}): Promise<RawResponse> {
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
 * Signed POST helper (body IS covered by the signature)
 */
export async function signedPost(
  server: AlephServer,
  identity: KeyTriplet,
  path: string,
  body: string | object
): Promise<RawResponse> {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  const headers = signRequest(server, identity, 'POST', path, { body: payload });
  return post(baseUrlOf(server), path, body, headers);
}

/**
 * Signed GET helper
 */
export async function signedGet(
  server: AlephServer,
  identity: KeyTriplet,
  path: string
): Promise<RawResponse> {
  const headers = signRequest(server, identity, 'GET', path);
  return get(baseUrlOf(server), path, headers);
}

/**
 * Build a signature over arbitrary payload fields (for negative tests)
 */
export function buildPayloadForVerification(fields: {
  method: string;
  target: string;
  timestamp: number | string;
  nonce: string;
  bodyHash: string;
}): string {
  return buildSignaturePayload(fields);
}

export { hashRequestBody };
