/**
 * Profiles — visibility-aware reads, other users' profiles, link lists.
 */

import { describe, it, expect } from '@jest/globals';
import { act, wire } from './helpers';
import { Profiles, PROFILE_ACTIONS } from '../../src/social/Profiles';

describe('Profiles', () => {
  it('implements getProfile for OTHER users (no more null stub)', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const profiles = new Profiles({ store, verifier, clock: clock.now });

    await profiles.updateProfile(
      act(PROFILE_ACTIONS.update, { displayName: 'Alice', bio: 'agent' }, alice, clock)
    );

    // The legacy ProfileManager returned null here. It must return a real view.
    const view = await profiles.getProfile(alice.fingerprint, bob.fingerprint);
    expect(view).not.toBeNull();
    expect(view?.fingerprint).toBe(alice.fingerprint);
    expect(view?.displayName).toBe('Alice');
    expect(view?.bio).toBe('agent');
  });

  it('restricts PRIVATE profiles for other users', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const profiles = new Profiles({ store, verifier, clock: clock.now });

    await profiles.updateProfile(
      act(
        PROFILE_ACTIONS.update,
        { displayName: 'Secret Squirrel', bio: 'do not leak', visibility: 'PRIVATE' },
        alice,
        clock
      )
    );

    const view = await profiles.getProfile(alice.fingerprint, bob.fingerprint);
    expect(view?.restricted).toBe(true);
    expect(view?.bio).toBeUndefined();

    // Owner still sees everything.
    const own = await profiles.getProfile(alice.fingerprint, alice.fingerprint);
    expect(own?.restricted).toBe(false);
    expect(own?.bio).toBe('do not leak');
  });

  it('restricts FRIENDS profiles unless the requester is a friend', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const friends = {
      areFriends: async (a: string, b: string) => a === alice.fingerprint && b === bob.fingerprint
    };
    const profiles = new Profiles({ store, verifier, friends, clock: clock.now });

    await profiles.updateProfile(
      act(
        PROFILE_ACTIONS.update,
        { displayName: 'Alice', bio: 'only for friends', visibility: 'FRIENDS' },
        alice,
        clock
      )
    );

    expect((await profiles.getProfile(alice.fingerprint, bob.fingerprint))?.restricted).toBe(false);
    expect((await profiles.getProfile(alice.fingerprint, alice.fingerprint))?.restricted).toBe(false);

    const stranger = 'f'.repeat(16);
    const view = await profiles.getProfile(alice.fingerprint, stranger);
    expect(view?.restricted).toBe(true);
    expect(view?.bio).toBeUndefined();
  });

  it('filters links by their own visibility', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const profiles = new Profiles({ store, verifier, clock: clock.now });

    const publicLink = await profiles.addLink(
      act(PROFILE_ACTIONS.addLink, { type: 'url', url: 'https://example.com', title: 'Site', visibility: 'PUBLIC' }, alice, clock)
    );
    await profiles.addLink(
      act(PROFILE_ACTIONS.addLink, { type: 'url', url: 'https://secret.example.com', title: 'Secret', visibility: 'FRIENDS' }, alice, clock)
    );

    const strangerLinks = await profiles.getLinks(alice.fingerprint, bob.fingerprint);
    expect(strangerLinks.map((l) => l.id)).toEqual([publicLink.id]);

    const ownLinks = await profiles.getLinks(alice.fingerprint, alice.fingerprint);
    expect(ownLinks).toHaveLength(2);
  });

  it('supports link update, removal, and reordering', async () => {
    const { store, verifier, clock, alice } = wire();
    const profiles = new Profiles({ store, verifier, clock: clock.now });

    const first = await profiles.addLink(
      act(PROFILE_ACTIONS.addLink, { type: 'url', url: 'https://a.example', title: 'A' }, alice, clock)
    );
    const second = await profiles.addLink(
      act(PROFILE_ACTIONS.addLink, { type: 'url', url: 'https://b.example', title: 'B' }, alice, clock)
    );

    await profiles.reorderLinks(
      act(PROFILE_ACTIONS.reorderLinks, { linkIds: [second.id, first.id] }, alice, clock)
    );
    const ordered = await profiles.getLinks(alice.fingerprint, alice.fingerprint);
    expect(ordered.map((l) => l.id)).toEqual([second.id, first.id]);

    await profiles.updateLink(
      act(PROFILE_ACTIONS.updateLink, { linkId: first.id, title: 'A2' }, alice, clock)
    );
    expect((await profiles.getOwnProfile(alice.fingerprint))?.links.find((l) => l.id === first.id)?.title).toBe('A2');

    expect(
      await profiles.removeLink(act(PROFILE_ACTIONS.removeLink, { linkId: first.id }, alice, clock))
    ).toBe(true);
    expect(await profiles.getLinks(alice.fingerprint, alice.fingerprint)).toHaveLength(1);
  });

  it('maps content and profile links to aleph:// URLs', async () => {
    const { store, verifier, clock, alice } = wire();
    const profiles = new Profiles({ store, verifier, clock: clock.now });
    const hash = 'a'.repeat(64);

    await profiles.addLink(
      act(PROFILE_ACTIONS.addLink, { type: 'content', contentHash: hash, title: 'Doc' }, alice, clock)
    );
    const links = await profiles.getLinks(alice.fingerprint, alice.fingerprint);
    expect(links.find((l) => l.title === 'Doc')?.url).toBe(`aleph://content/${hash}`);
  });

  it('rejects invalid content hashes in link payloads', async () => {
    const { store, verifier, clock, alice } = wire();
    const profiles = new Profiles({ store, verifier, clock: clock.now });
    await expect(
      profiles.addLink(
        act(
          PROFILE_ACTIONS.addLink,
          { type: 'content', contentHash: '../escape', title: 'bad' },
          alice,
          clock
        )
      )
    ).rejects.toThrow();
  });

  it('searches profiles without leaking restricted ones', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const profiles = new Profiles({ store, verifier, clock: clock.now });

    await profiles.updateProfile(
      act(PROFILE_ACTIONS.update, { displayName: 'Alice Visible', bio: '' }, alice, clock)
    );
    await profiles.updateProfile(
      act(
        PROFILE_ACTIONS.update,
        { displayName: 'Bob Hidden', bio: '', visibility: 'PRIVATE' },
        bob,
        clock
      )
    );

    const results = await profiles.search('hidden', alice.fingerprint);
    // Bob's name matches, but his profile is PRIVATE to alice — so it must not
    // appear in search results.
    expect(results.map((r) => r.fingerprint)).not.toContain(bob.fingerprint);
  });

  it('never serves a cached FRIENDS view to a stranger and invalidates on visibility flips', async () => {
    const { store, verifier, clock, alice, bob, mallory } = wire();
    const friends = {
      areFriends: async (a: string, b: string) =>
        a === alice.fingerprint && b === bob.fingerprint
    };
    const profiles = new Profiles({ store, verifier, friends, clock: clock.now });

    // Simulate a remote-cached FRIENDS view of alice's profile, fetched for bob.
    // alice has no profile in the local store, so reads fall back to the cache.
    profiles.cacheRemoteProfile(
      {
        fingerprint: alice.fingerprint,
        restricted: false,
        visibility: 'FRIENDS',
        displayName: 'Alice',
        bio: 'friends only'
      },
      undefined,
      bob.fingerprint
    );

    // The requester the view was fetched for sees it...
    expect((await profiles.getProfile(alice.fingerprint, bob.fingerprint))?.bio).toBe(
      'friends only'
    );

    // ...but a stranger must not be served that cached view.
    expect(await profiles.getProfile(alice.fingerprint, mallory.fingerprint)).toBeNull();

    // A visibility flip invalidates the cache: alice publishes a PRIVATE
    // profile, and bob's cached FRIENDS view must not survive it.
    await profiles.updateProfile(
      act(
        PROFILE_ACTIONS.update,
        { displayName: 'Alice', bio: 'now private', visibility: 'PRIVATE' },
        alice,
        clock
      )
    );
    expect(profiles.cache.size).toBe(0);
    const after = await profiles.getProfile(alice.fingerprint, bob.fingerprint);
    expect(after?.restricted).toBe(true);
    expect(after?.bio).toBeUndefined();
  });

  it('serves wildcard-cached PUBLIC views to anyone but refuses unsafe anonymous caching', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const profiles = new Profiles({ store, verifier, clock: clock.now });

    // PUBLIC + unrestricted may be cached without a requester.
    profiles.cacheRemoteProfile({
      fingerprint: bob.fingerprint,
      restricted: false,
      visibility: 'PUBLIC',
      displayName: 'Bob Public'
    });
    expect(
      (await profiles.getProfile(bob.fingerprint, alice.fingerprint))?.displayName
    ).toBe('Bob Public');

    // A requester-scoped (FRIENDS) view without a requester is refused.
    expect(() =>
      profiles.cacheRemoteProfile({
        fingerprint: alice.fingerprint,
        restricted: false,
        visibility: 'FRIENDS',
        displayName: 'Alice'
      })
    ).toThrow(/requester/);
  });
});
