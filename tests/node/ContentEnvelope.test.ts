/**
 * Node-attested content envelopes: round-trip + forged-author rejection.
 *
 * `ContentStore` mutations now accept ONLY signed `content.put` envelopes.
 * The node never holds client private keys, so it attests envelopes with its
 * own key for HTTP-authenticated callers. These tests prove:
 *
 *   - a node-attested envelope stores content owned by the AUTHENTICATED
 *     caller and the blob round-trips back through the HTTP action;
 *   - an envelope signed by a third party (claiming to be the caller) is
 *     rejected — the signature must be the NODE's;
 *   - a node-signed envelope whose author fields were tampered (swapped to
 *     an identity with no HTTP-auth attestation) is rejected;
 *   - a captured envelope cannot be replayed (single-use nonce).
 */

import { describe, it, expect, afterEach } from '@jest/globals';
import { generateKeyTriplet, type KeyTriplet } from '../../src/common/crypto';
import {
  CONTENT_ACTIONS,
  ContentStore,
  Identity,
  MemorySocialStore,
  canonicalActionString,
  createNonce,
  keyTripletSigner,
  type SignedAction
} from '../../src/social';
import { NodeAttestedSigner } from '../../src/node/attestation';
import { AlephNode } from '../../src/node';
import {
  authenticatedIdentity,
  createTestIdentity,
  signedPost,
  startNode
} from './helpers';

describe('node-attested content envelopes (store level)', () => {
  it('accepts a node-attested envelope, owns the content to the caller, and rejects tampering', async () => {
    const nodeKey = generateKeyTriplet();
    const nodeIdentity = Identity.fromKeyTriplet(nodeKey);
    const signer = new NodeAttestedSigner(nodeIdentity);
    const store = new ContentStore({ store: new MemorySocialStore(), verifier: signer.verifier });

    const caller: KeyTriplet = createTestIdentity();
    const envelope = signer.signFor(authenticatedIdentity(caller), CONTENT_ACTIONS.put, {
      content: 'hello attested world',
      visibility: 'PUBLIC' as const
    });

    const result = await store.put(envelope);
    expect(result.hash).toMatch(/^[0-9a-f]{64}$/);

    const retrieved = await store.get(result.hash, caller.fingerprint);
    expect(retrieved).not.toBeNull();
    expect(retrieved?.content).toBe('hello attested world');
    expect(retrieved?.owner).toBe(caller.fingerprint);
    expect(retrieved?.visibility).toBe('PUBLIC');
  });

  it('rejects an envelope signed by a third party claiming to be the caller', async () => {
    const nodeIdentity = Identity.fromKeyTriplet(generateKeyTriplet());
    const signer = new NodeAttestedSigner(nodeIdentity);
    const store = new ContentStore({ store: new MemorySocialStore(), verifier: signer.verifier });

    const caller = createTestIdentity();
    signer.verifier.attest(authenticatedIdentity(caller));

    // The attacker signs with their OWN key but claims the caller's author
    // fields. The node's verifier must reject: it was not the node that signed.
    const attacker = keyTripletSigner(generateKeyTriplet());
    const timestamp = Date.now();
    const nonce = createNonce();
    const forged: SignedAction<{ content: string }> = {
      action: CONTENT_ACTIONS.put,
      payload: { content: 'forged' },
      authorPub: caller.pub,
      authorFingerprint: caller.fingerprint,
      timestamp,
      nonce,
      signature: attacker.sign(
        canonicalActionString(CONTENT_ACTIONS.put, { content: 'forged' }, timestamp, nonce)
      )
    };

    await expect(store.put(forged)).rejects.toMatchObject({
      name: 'SignedActionError',
      code: 'invalid_signature'
    });
  });

  it('rejects a node-signed envelope whose author fields were tampered to an unattested identity', async () => {
    const nodeIdentity = Identity.fromKeyTriplet(generateKeyTriplet());
    const signer = new NodeAttestedSigner(nodeIdentity);
    const store = new ContentStore({ store: new MemorySocialStore(), verifier: signer.verifier });

    const caller = createTestIdentity();
    const victim = createTestIdentity(); // never authenticated → no attestation

    const envelope = signer.signFor(authenticatedIdentity(caller), CONTENT_ACTIONS.put, {
      content: 'tampered'
    });

    // The node signature covers action/payload/timestamp/nonce only, so
    // swapping the author fields keeps the signature "valid" — the verifier
    // must still refuse because the victim has no HTTP-auth attestation.
    const tampered: SignedAction<{ content: string }> = {
      ...envelope,
      authorPub: victim.pub,
      authorFingerprint: victim.fingerprint
    };

    await expect(store.put(tampered)).rejects.toMatchObject({
      name: 'SignedActionError',
      code: 'fingerprint_mismatch'
    });
  });

  it('rejects a replayed envelope (single-use nonce)', async () => {
    const nodeIdentity = Identity.fromKeyTriplet(generateKeyTriplet());
    const signer = new NodeAttestedSigner(nodeIdentity);
    const store = new ContentStore({ store: new MemorySocialStore(), verifier: signer.verifier });

    const caller = createTestIdentity();
    const envelope = signer.signFor(authenticatedIdentity(caller), CONTENT_ACTIONS.put, {
      content: 'one-shot'
    });

    await expect(store.put(envelope)).resolves.toMatchObject({ hash: expect.any(String) });
    await expect(store.put(envelope)).rejects.toMatchObject({
      name: 'SignedActionError',
      code: 'replayed_nonce'
    });
  });
});

describe('node-attested content envelopes (HTTP round-trip)', () => {
  let node: AlephNode;

  afterEach(async () => {
    await node.stop();
  });

  it('content.put over HTTP stores the caller-owned blob and content.get round-trips it', async () => {
    ({ node } = await startNode({ port: 0 }));
    const identity = createTestIdentity();

    const putRes = await signedPost(node, identity, '/actions/content.put', {
      content: 'hello over http',
      visibility: 'PUBLIC',
      metadata: { tag: 'integration' }
    });
    expect(putRes.status).toBe(200);
    const putBody = JSON.parse(putRes.text).output;
    expect(putBody.ok).toBe(true);
    const hash = putBody.value.hash as string;
    expect(hash).toMatch(/^[0-9a-f]{64}$/);

    const getRes = await signedPost(node, identity, '/actions/content.get', { hash });
    expect(getRes.status).toBe(200);
    const getBody = JSON.parse(getRes.text).output;
    expect(getBody.ok).toBe(true);
    expect(getBody.value.found).toBe(true);
    expect(getBody.value.content).toBe('hello over http');
    // Ownership is the AUTHENTICATED caller — never an input field.
    expect(getBody.value.owner).toBe(identity.fingerprint);
  });

  it('PRIVATE content put by one caller is unreadable by another', async () => {
    ({ node } = await startNode({ port: 0 }));
    const alice = createTestIdentity();
    const bob = createTestIdentity();

    const putRes = await signedPost(node, alice, '/actions/content.put', {
      content: 'alice secret',
      visibility: 'PRIVATE'
    });
    const hash = JSON.parse(putRes.text).output.value.hash as string;

    const bobGet = await signedPost(node, bob, '/actions/content.get', { hash });
    expect(bobGet.status).toBe(200);
    const bobBody = JSON.parse(bobGet.text).output;
    expect(bobBody.ok).toBe(false);
    expect(bobBody.code).toBe('ACCESS_DENIED');

    const aliceGet = await signedPost(node, alice, '/actions/content.get', { hash });
    const aliceBody = JSON.parse(aliceGet.text).output;
    expect(aliceBody.ok).toBe(true);
    expect(aliceBody.value.content).toBe('alice secret');
  });
});
