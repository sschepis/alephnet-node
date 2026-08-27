/**
 * SignedAction — the shared authentication primitive.
 */

import { describe, it, expect } from '@jest/globals';
import { wire } from './helpers';
import {
  ActionVerifier,
  signAction,
  SignedAction,
  SignedActionError,
  fingerprintFromPublicKey,
  assertNoImpersonation,
  ImpersonationError,
  StoreBackedNonceStore
} from '../../src/social/SignedAction';
import { MemorySocialStore, SocialStore } from '../../src/social/SocialStore';
import { generateKeyTriplet } from '../../src/common/crypto';

interface TestPayload {
  groupId: string;
  content: string;
}

const PAYLOAD: TestPayload = { groupId: 'grp_0123456789abcdef01234567', content: 'hello' };
const ACTION = 'test.action';

describe('SignedAction', () => {
  it('verifies a valid envelope and binds the author', async () => {
    const { alice, clock } = wire();
    const envelope = signAction(ACTION, PAYLOAD, alice, { clock: clock.now });
    const verifier = new ActionVerifier({ clock: clock.now });

    const result = await verifier.verify(envelope, ACTION);
    expect(result.author.fingerprint).toBe(alice.fingerprint);
    expect(result.author.pub).toBe(alice.publicKeyBase64);
    expect(result.payload).toEqual(PAYLOAD);
  });

  it('rejects a tampered payload', async () => {
    const { alice, clock } = wire();
    const envelope = signAction(ACTION, PAYLOAD, alice, { clock: clock.now });
    const tampered: SignedAction<TestPayload> = {
      ...envelope,
      payload: { ...PAYLOAD, content: 'MALLORY WAS HERE' }
    };

    const verifier = new ActionVerifier({ clock: clock.now });
    const result = await verifier.check(tampered, ACTION);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('invalid_signature');
  });

  it('rejects a fingerprint that does not match the signing key', async () => {
    const { alice, clock } = wire();
    const envelope = signAction(ACTION, PAYLOAD, alice, { clock: clock.now });
    const someoneElse = generateKeyTriplet();
    const forged: SignedAction<TestPayload> = {
      ...envelope,
      authorFingerprint: fingerprintFromPublicKey(someoneElse.pub)
    };

    const verifier = new ActionVerifier({ clock: clock.now });
    const result = await verifier.check(forged, ACTION);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('fingerprint_mismatch');
  });

  it('rejects a fingerprint that is not syntactically valid', async () => {
    const { alice, clock } = wire();
    const envelope = signAction(ACTION, PAYLOAD, alice, { clock: clock.now });
    const forged = { ...envelope, authorFingerprint: 'zzzzzzzzzzzzzzzz' };

    const verifier = new ActionVerifier({ clock: clock.now });
    const result = await verifier.check(forged, ACTION);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('malformed_envelope');
  });

  it('rejects a stale timestamp', async () => {
    const { alice, clock } = wire();
    const staleAt = clock.nowMs - 10 * 60 * 1000; // 10 minutes old
    const envelope = signAction(ACTION, PAYLOAD, alice, { timestamp: staleAt });

    const verifier = new ActionVerifier({ clock: clock.now, maxAgeMs: 5 * 60 * 1000 });
    const result = await verifier.check(envelope, ACTION);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('timestamp_out_of_window');
  });

  it('rejects a timestamp too far in the future', async () => {
    const { alice, clock } = wire();
    const envelope = signAction(ACTION, PAYLOAD, alice, {
      timestamp: clock.nowMs + 10 * 60 * 1000
    });

    const verifier = new ActionVerifier({ clock: clock.now });
    const result = await verifier.check(envelope, ACTION);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('timestamp_out_of_window');
  });

  it('rejects a replayed nonce', async () => {
    const { alice, clock } = wire();
    const envelope = signAction(ACTION, PAYLOAD, alice, { clock: clock.now });

    const verifier = new ActionVerifier({ clock: clock.now });
    const first = await verifier.check(envelope, ACTION);
    expect(first.valid).toBe(true);

    const replay = await verifier.check(envelope, ACTION);
    expect(replay.valid).toBe(false);
    if (!replay.valid) expect(replay.code).toBe('replayed_nonce');
  });

  it('rejects a signature over the wrong action name', async () => {
    const { alice, clock } = wire();
    const envelope = signAction(ACTION, PAYLOAD, alice, { clock: clock.now });

    const verifier = new ActionVerifier({ clock: clock.now });
    const result = await verifier.check(envelope, 'other.action');
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.code).toBe('action_mismatch');
  });

  it('verify() throws SignedActionError for invalid envelopes', async () => {
    const { alice, clock } = wire();
    const envelope = signAction(ACTION, PAYLOAD, alice, { clock: clock.now });
    const verifier = new ActionVerifier({ clock: clock.now });

    await verifier.verify(envelope, ACTION); // burns the nonce
    await expect(verifier.verify(envelope, ACTION)).rejects.toThrow(SignedActionError);
    await expect(verifier.verify(envelope, ACTION)).rejects.toMatchObject({
      code: 'replayed_nonce'
    });
  });

  it('rejects payloads that declare their own actor', () => {
    for (const payload of [
      { groupId: 'grp_x', content: 'x', authorId: 'system' },
      { groupId: 'grp_x', content: 'x', authorFingerprint: 'a'.repeat(16) },
      { groupId: 'grp_x', content: 'x', from: 'someone' },
      { groupId: 'grp_x', content: 'x', ownerId: 'system' }
    ]) {
      expect(() => assertNoImpersonation('group.post.create', payload)).toThrow(
        ImpersonationError
      );
    }
  });

  it('accepts clean payloads', () => {
    expect(() => assertNoImpersonation('group.post.create', PAYLOAD)).not.toThrow();
  });

  it('makes StoreBackedNonceStore.claim atomic: concurrent claims of one nonce — exactly one wins', async () => {
    // A store that deliberately delays every operation, forcing the two
    // claims to interleave (both would read "missing" before either writes
    // without the internal mutex).
    class SlowStore implements SocialStore {
      private readonly inner = new MemorySocialStore();

      private delay(): Promise<void> {
        return new Promise((resolve) => setTimeout(resolve, 10));
      }

      async get(key: string) {
        await this.delay();
        return this.inner.get(key);
      }

      async put(key: string, value: unknown) {
        await this.delay();
        return this.inner.put(key, value);
      }

      async del(key: string) {
        await this.delay();
        return this.inner.del(key);
      }

      async list(prefix: string) {
        await this.delay();
        return this.inner.list(prefix);
      }
    }

    const nonces = new StoreBackedNonceStore(new SlowStore(), 'nonce', () => 1_000);
    const [first, second] = await Promise.all([
      nonces.claim('same-nonce', 5_000),
      nonces.claim('same-nonce', 5_000)
    ]);

    expect([first, second].filter(Boolean)).toHaveLength(1);

    // And once claimed, the nonce stays claimed until it expires.
    expect(await nonces.claim('same-nonce', 5_000)).toBe(false);
  });
});
