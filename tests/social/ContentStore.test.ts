/**
 * ContentStore — visibility enforcement, hash validation, dedup, and
 * signature-bound mutations.
 */

import { describe, it, expect } from '@jest/globals';
import { act, wire } from './helpers';
import {
  ContentStore,
  computeContentHash,
  CONTENT_ACTIONS
} from '../../src/social/ContentStore';
import { FriendGraph, FRIEND_ACTIONS } from '../../src/social/FriendGraph';
import { AccessDeniedError, SocialError } from '../../src/social/types';

describe('ContentStore', () => {
  it('PRIVATE content is readable by the owner but not by others', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const content = new ContentStore({ store, verifier, clock: clock.now });

    const { hash } = await content.put(
      act(CONTENT_ACTIONS.put, { content: 'my secret diary', visibility: 'PRIVATE' }, alice, clock)
    );

    const asOwner = await content.get(hash, alice.fingerprint);
    expect(asOwner?.content).toBe('my secret diary');

    await expect(content.get(hash, bob.fingerprint)).rejects.toThrow(AccessDeniedError);

    // Listing as a stranger leaks nothing.
    const listing = await content.list(alice.fingerprint, bob.fingerprint);
    expect(listing).toHaveLength(0);
  });

  it('FRIENDS content is readable only by a confirmed friend', async () => {
    const { store, verifier, clock, alice, bob, mallory } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });
    const content = new ContentStore({ store, verifier, friends: graph, clock: clock.now });

    const { hash } = await content.put(
      act(CONTENT_ACTIONS.put, { content: 'friends-only memes', visibility: 'FRIENDS' }, alice, clock)
    );

    // Not friends yet: denied.
    await expect(content.get(hash, bob.fingerprint)).rejects.toThrow(AccessDeniedError);
    expect(await content.list(alice.fingerprint, bob.fingerprint)).toHaveLength(0);

    // Establish a real (signed) friendship.
    const request = await graph.sendRequest(
      act(FRIEND_ACTIONS.request, { to: bob.fingerprint }, alice, clock)
    );
    await graph.acceptRequest(act(FRIEND_ACTIONS.accept, { requestId: request.id }, bob, clock));

    // Now bob can read it...
    const asFriend = await content.get(hash, bob.fingerprint);
    expect(asFriend?.content).toBe('friends-only memes');
    expect(await content.list(alice.fingerprint, bob.fingerprint)).toHaveLength(1);

    // ...but a stranger still cannot.
    await expect(content.get(hash, mallory.fingerprint)).rejects.toThrow(AccessDeniedError);
  });

  it('rejects invalid hashes: traversal attempts and wrong lengths', async () => {
    const { store, verifier, clock, alice } = wire();
    const content = new ContentStore({ store, verifier, clock: clock.now });

    for (const bad of ['../x', '../../etc/passwd', 'a'.repeat(63), 'A'.repeat(64), '', 'abc']) {
      await expect(content.get(bad, alice.fingerprint)).rejects.toThrow(SocialError);
      await expect(content.has(bad)).rejects.toThrow(SocialError);
    }
    expect(store.dump()).toEqual({});
  });

  it('validates hashes before any path operation in FileSocialStore too', async () => {
    const { store, verifier, clock, alice } = wire();
    const content = new ContentStore({ store, verifier, clock: clock.now });

    await expect(
      content.put(act(CONTENT_ACTIONS.put, { content: 'x' }, alice, clock))
    ).resolves.toBeDefined();
    // Storage keys themselves reject traversal segments.
    await expect(store.put('../escape', 'boom')).rejects.toThrow(SocialError);
    await expect(store.put('ok/../../boom', 'x')).rejects.toThrow(SocialError);
  });

  it('deduplicates identical content by hash', async () => {
    const { store, verifier, clock, alice } = wire();
    const content = new ContentStore({ store, verifier, clock: clock.now });

    const first = await content.put(
      act(CONTENT_ACTIONS.put, { content: 'identical bytes', visibility: 'PUBLIC' }, alice, clock)
    );
    const second = await content.put(
      act(CONTENT_ACTIONS.put, { content: 'identical bytes', visibility: 'PUBLIC' }, alice, clock)
    );

    expect(first.hash).toBe(second.hash);
    expect(first.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(second.duplicate).toBe(true);
    expect(second.alreadyOwned).toBe(true);
    expect(first.hash).toBe(computeContentHash('identical bytes'));
  });

  it('keeps per-owner visibility even when blobs are shared', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const content = new ContentStore({ store, verifier, clock: clock.now });

    const same = 'shared bytes';
    await content.put(act(CONTENT_ACTIONS.put, { content: same, visibility: 'PUBLIC' }, alice, clock));
    await content.put(act(CONTENT_ACTIONS.put, { content: same, visibility: 'PRIVATE' }, bob, clock));

    // Both addresses are the same hash...
    const hash = computeContentHash(same);
    // ...but the entries belong to their owners with their own visibility.
    const aliceMeta = await content.getMetadata(hash, alice.fingerprint);
    const bobMeta = await content.getMetadata(hash, bob.fingerprint);
    expect(aliceMeta?.owner).toBe(alice.fingerprint);
    expect(bobMeta?.owner).toBe(bob.fingerprint);

    // Alice may read (her entry is PUBLIC); bob's own entry is PRIVATE and
    // invisible to alice, which is fine — alice's PUBLIC entry grants access.
    const retrieved = await content.get(hash, alice.fingerprint);
    expect(retrieved?.content).toBe(same);
  });

  it('enforces verified ownership on setVisibility and delete', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const content = new ContentStore({ store, verifier, clock: clock.now });

    const { hash } = await content.put(
      act(CONTENT_ACTIONS.put, { content: 'flip me', visibility: 'PRIVATE' }, alice, clock)
    );

    // bob cannot delete alice's entry — he has no entry for that hash.
    await expect(
      content.delete(act(CONTENT_ACTIONS.delete, { hash }, bob, clock))
    ).rejects.toMatchObject({ code: 'not_found' });

    await content.setVisibility(
      act(CONTENT_ACTIONS.setVisibility, { hash, visibility: 'PUBLIC' }, alice, clock)
    );
    const asBob = await content.get(hash, bob.fingerprint);
    expect(asBob?.content).toBe('flip me');

    await content.delete(act(CONTENT_ACTIONS.delete, { hash }, alice, clock));
    expect(await content.has(hash)).toBe(false);
  });

  it('rejects a forged owner fingerprint inside the envelope', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const content = new ContentStore({ store, verifier, clock: clock.now });

    const { hash } = await content.put(
      act(CONTENT_ACTIONS.put, { content: 'alice secret', visibility: 'PRIVATE' }, alice, clock)
    );

    // bob signs the envelope himself but claims to be alice. The verifier
    // recomputes the fingerprint from the signing key and rejects it.
    const forged = act(CONTENT_ACTIONS.delete, { hash }, bob, clock);
    forged.authorFingerprint = alice.fingerprint;
    await expect(content.delete(forged)).rejects.toMatchObject({
      code: 'fingerprint_mismatch'
    });

    // bob's setVisibility with his own identity still finds no entry.
    await expect(
      content.setVisibility(
        act(CONTENT_ACTIONS.setVisibility, { hash, visibility: 'PUBLIC' }, bob, clock)
      )
    ).rejects.toMatchObject({ code: 'not_found' });

    // The content is untouched and still alice's.
    const meta = await content.getMetadata(hash, alice.fingerprint);
    expect(meta?.owner).toBe(alice.fingerprint);
    expect(meta?.visibility).toBe('PRIVATE');
  });

  it('rejects the unsigned legacy put signature outright', async () => {
    const { store, verifier, clock, alice } = wire();
    const content = new ContentStore({ store, verifier, clock: clock.now });

    await expect(content.put('bare bytes', alice.fingerprint, {})).rejects.toMatchObject({
      code: 'unsigned_mutation'
    });
    expect(store.dump()).toEqual({});
  });

  it('supports metadata search filtered by what the requester may see', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const content = new ContentStore({ store, verifier, clock: clock.now });

    await content.put(
      act(
        CONTENT_ACTIONS.put,
        { content: 'public note', visibility: 'PUBLIC', metadata: { tag: 'note', year: 2026 } },
        alice,
        clock
      )
    );
    await content.put(
      act(
        CONTENT_ACTIONS.put,
        { content: 'hidden note', visibility: 'PRIVATE', metadata: { tag: 'note', year: 2026 } },
        alice,
        clock
      )
    );

    const results = await content.search({ metadata: { tag: 'note' } }, bob.fingerprint);
    expect(results).toHaveLength(1);
    expect(results[0].hash).toBe(computeContentHash('public note'));
  });

  it('excludes UNLISTED content from every enumeration for non-owners', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const content = new ContentStore({ store, verifier, clock: clock.now });

    const { hash } = await content.put(
      act(CONTENT_ACTIONS.put, { content: 'unlisted secret', visibility: 'UNLISTED' }, alice, clock)
    );

    // The owner may enumerate it...
    expect(await content.list(alice.fingerprint, alice.fingerprint)).toHaveLength(1);

    // ...but a stranger never sees it in list/listPublic/search.
    expect(await content.list(alice.fingerprint, bob.fingerprint)).toHaveLength(0);
    expect(await content.listPublic(bob.fingerprint)).toHaveLength(0);
    expect(await content.search({}, bob.fingerprint)).toHaveLength(0);

    // Address-holder access still works: UNLISTED is unlisted, not unreadable.
    expect((await content.get(hash, bob.fingerprint))?.content).toBe('unlisted secret');
    expect(await content.canAccess(hash, bob.fingerprint)).toBe(true);
  });

  it('tracks access counts and stats', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const content = new ContentStore({ store, verifier, clock: clock.now });
    const { hash } = await content.put(
      act(CONTENT_ACTIONS.put, { content: 'stats!', visibility: 'PUBLIC' }, alice, clock)
    );

    await content.get(hash, bob.fingerprint);
    await content.get(hash, bob.fingerprint);

    const stats = await content.getStats();
    expect(stats.entries).toBe(1);
    expect(stats.byVisibility).toEqual({ PUBLIC: 1 });
  });
});
