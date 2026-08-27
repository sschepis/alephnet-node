/**
 * Groups — membership enforcement, no impersonation, invite expiry.
 */

import { describe, it, expect } from '@jest/globals';
import { act, wire, FakeClock } from './helpers';
import {
  Groups,
  GroupsError,
  GROUP_ACTIONS,
  CreateGroupPayload,
  GroupRecord
} from '../../src/social/Groups';
import { Identity } from '../../src/social/Identity';
import { ImpersonationError } from '../../src/social/SignedAction';
import { AccessDeniedError } from '../../src/social/types';

async function createTestGroup(
  groups: Groups,
  identity: Identity,
  clock: FakeClock,
  visibility: 'PUBLIC' | 'INVISIBLE' | 'PRIVATE' = 'PUBLIC'
): Promise<GroupRecord> {
  return groups.createGroup(
    act<CreateGroupPayload>(
      GROUP_ACTIONS.create,
      { name: 'Test Group', visibility },
      identity,
      clock
    )
  );
}

describe('Groups', () => {
  it('creates a group with the verified author as owner (not "system")', async () => {
    const { store, verifier, clock, alice } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock);
    expect(group.ownerFingerprint).toBe(alice.fingerprint);
    expect(group.ownerFingerprint).not.toBe('system');
    expect(group.members).toEqual([alice.fingerprint]);
  });

  it('rejects an impersonation attempt via caller-supplied authorId', async () => {
    const { store, verifier, clock, alice, mallory } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock);

    // Legacy behavior: authorId: 'system' bypassed the membership check.
    // The payload field is rejected outright now — even with a valid signature.
    const envelope = act(
      GROUP_ACTIONS.post,
      { groupId: group.id, content: 'hello', authorId: 'system' },
      mallory,
      clock
    );
    await expect(groups.createPost(envelope)).rejects.toThrow(ImpersonationError);
  });

  it('rejects impersonation via a forged author fingerprint', async () => {
    const { store, verifier, clock, alice, mallory } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock);

    const envelope = act(
      GROUP_ACTIONS.post,
      { groupId: group.id, content: 'hello', authorFingerprint: alice.fingerprint },
      mallory,
      clock
    );
    await expect(groups.createPost(envelope)).rejects.toThrow(ImpersonationError);
  });

  it('rejects posts from non-members', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock);

    const envelope = act(GROUP_ACTIONS.post, { groupId: group.id, content: 'hi' }, bob, clock);
    await expect(groups.createPost(envelope)).rejects.toThrow(AccessDeniedError);
    expect(await groups.getPosts(group.id, bob.fingerprint)).toHaveLength(0);
  });

  it('lets members post, react, and comment', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock);
    await groups.joinGroup(act(GROUP_ACTIONS.join, { groupId: group.id }, bob, clock));

    const post = await groups.createPost(
      act(GROUP_ACTIONS.post, { groupId: group.id, content: 'first!' }, bob, clock)
    );
    expect(post.authorFingerprint).toBe(bob.fingerprint);

    await groups.addReaction(
      act(GROUP_ACTIONS.react, { groupId: group.id, postId: post.id, reaction: '👍' }, alice, clock)
    );
    const comment = await groups.addComment(
      act(GROUP_ACTIONS.comment, { groupId: group.id, postId: post.id, content: 'nice' }, alice, clock)
    );
    expect(comment.authorFingerprint).toBe(alice.fingerprint);

    const posts = await groups.getPosts(group.id, bob.fingerprint);
    expect(posts).toHaveLength(1);
    expect(posts[0].reactions).toEqual({ [alice.fingerprint]: '👍' });
    expect(posts[0].comments).toHaveLength(1);
  });

  it('keeps non-members from reacting or commenting', async () => {
    const { store, verifier, clock, alice, mallory } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock);
    const post = await groups.createPost(
      act(GROUP_ACTIONS.post, { groupId: group.id, content: 'hello' }, alice, clock)
    );

    await expect(
      groups.addReaction(
        act(GROUP_ACTIONS.react, { groupId: group.id, postId: post.id, reaction: 'x' }, mallory, clock)
      )
    ).rejects.toThrow(AccessDeniedError);
    await expect(
      groups.addComment(
        act(GROUP_ACTIONS.comment, { groupId: group.id, postId: post.id, content: 'x' }, mallory, clock)
      )
    ).rejects.toThrow(AccessDeniedError);
  });

  it('rejects joining a private group without an invitation', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock, 'PRIVATE');
    await expect(
      groups.joinGroup(act(GROUP_ACTIONS.join, { groupId: group.id }, bob, clock))
    ).rejects.toThrow(AccessDeniedError);
  });

  it('enforces invitation expiry on group invites', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock, 'PRIVATE');

    const invitation = await groups.invite(
      act(GROUP_ACTIONS.invite, { groupId: group.id, invitee: bob.fingerprint, ttlMs: 1000 }, alice, clock)
    );
    expect(invitation.expiresAt).toBeGreaterThan(invitation.createdAt);

    clock.advance(2000);
    await expect(
      groups.acceptInvite(
        act(GROUP_ACTIONS.acceptInvite, { inviteId: invitation.id }, bob, clock)
      )
    ).rejects.toMatchObject({ code: 'invite_expired' });

    expect(await groups.isMember(group.id, bob.fingerprint)).toBe(false);
  });

  it('accepts a live invitation and joins the invitee', async () => {
    const { store, verifier, clock, alice, bob, mallory } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock, 'PRIVATE');

    const invitation = await groups.invite(
      act(GROUP_ACTIONS.invite, { groupId: group.id, invitee: bob.fingerprint }, alice, clock)
    );
    // Invitation is bound to bob — mallory cannot ride it.
    await expect(
      groups.acceptInvite(act(GROUP_ACTIONS.acceptInvite, { inviteId: invitation.id }, mallory, clock))
    ).rejects.toThrow(AccessDeniedError);

    await groups.acceptInvite(
      act(GROUP_ACTIONS.acceptInvite, { inviteId: invitation.id }, bob, clock)
    );
    expect(await groups.isMember(group.id, bob.fingerprint)).toBe(true);
  });

  it('only admins can remove members; the owner is protected', async () => {
    const { store, verifier, clock, alice, bob, mallory } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock);
    await groups.joinGroup(act(GROUP_ACTIONS.join, { groupId: group.id }, bob, clock));

    await expect(
      groups.removeMember(
        act(GROUP_ACTIONS.removeMember, { groupId: group.id, member: bob.fingerprint }, bob, clock)
      )
    ).rejects.toThrow(AccessDeniedError);

    await groups.removeMember(
      act(GROUP_ACTIONS.removeMember, { groupId: group.id, member: bob.fingerprint }, alice, clock)
    );
    expect(await groups.isMember(group.id, bob.fingerprint)).toBe(false);

    await expect(
      groups.removeMember(
        act(GROUP_ACTIONS.removeMember, { groupId: group.id, member: alice.fingerprint }, alice, clock)
      )
    ).rejects.toThrow(GroupsError);

    // A removed member can no longer post.
    await expect(
      groups.createPost(act(GROUP_ACTIONS.post, { groupId: group.id, content: 'back?' }, bob, clock))
    ).rejects.toThrow(AccessDeniedError);
  });

  it('hides invisible groups from non-members in listings', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    await createTestGroup(groups, alice, clock, 'INVISIBLE');

    expect(await groups.listGroups(bob.fingerprint)).toHaveLength(0);
    expect(await groups.listGroups(alice.fingerprint)).toHaveLength(1);
  });

  it('creates default groups owned by a real signer, never "system"', async () => {
    const { store, verifier, clock, alice } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const created = await groups.ensureDefaultGroups(alice);

    expect(created.map((g) => g.name).sort()).toEqual(['Announcements', 'Public Square']);
    for (const group of created) {
      expect(group.ownerFingerprint).toBe(alice.fingerprint);
      expect(group.ownerFingerprint).not.toBe('system');
    }

    // Idempotent.
    expect(await groups.ensureDefaultGroups(alice)).toHaveLength(0);
  });

  it('paginates getAllPosts across the full union beyond 50 posts per group', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock);

    // 55 posts with distinct timestamps.
    for (let i = 0; i < 55; i += 1) {
      clock.advance(10);
      await groups.createPost(
        act(GROUP_ACTIONS.post, { groupId: group.id, content: `post ${i}` }, alice, clock)
      );
    }

    // The union is complete — no silent per-group truncation at 50.
    expect(await groups.getAllPosts(alice.fingerprint, { limit: 1000 })).toHaveLength(55);

    // Offset pagination reaches the posts beyond the first page.
    const firstPage = await groups.getAllPosts(alice.fingerprint, { limit: 50 });
    const secondPage = await groups.getAllPosts(alice.fingerprint, { limit: 10, offset: 50 });
    expect(firstPage).toHaveLength(50);
    expect(firstPage[0].content).toBe('post 54');
    expect(secondPage).toHaveLength(5);
    expect(secondPage[0].content).toBe('post 4');
    expect(secondPage[4].content).toBe('post 0');

    // before/after cursor pagination is reachable too.
    const newest = firstPage[0];
    const older = await groups.getAllPosts(alice.fingerprint, {
      before: newest.timestamp,
      limit: 1000
    });
    expect(older).toHaveLength(54);
    expect(older.some((post) => post.content === 'post 0')).toBe(true);

    // Per-group reads keep their default cap unless asked for more.
    expect(await groups.getPosts(group.id, bob.fingerprint)).toHaveLength(50);
    expect(await groups.getPosts(group.id, bob.fingerprint, { limit: 1000 })).toHaveLength(55);
  });

  it('banned members cannot remove reactions', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock);
    await groups.joinGroup(act(GROUP_ACTIONS.join, { groupId: group.id }, bob, clock));

    const post = await groups.createPost(
      act(GROUP_ACTIONS.post, { groupId: group.id, content: 'reactable' }, alice, clock)
    );
    await groups.addReaction(
      act(GROUP_ACTIONS.react, { groupId: group.id, postId: post.id, reaction: '👍' }, bob, clock)
    );

    // Admin removes (and bans) bob; his reaction is now untouchable by him.
    await groups.removeMember(
      act(GROUP_ACTIONS.removeMember, { groupId: group.id, member: bob.fingerprint }, alice, clock)
    );
    await expect(
      groups.removeReaction(
        act(GROUP_ACTIONS.unreact, { groupId: group.id, postId: post.id }, bob, clock)
      )
    ).rejects.toThrow(AccessDeniedError);

    // The reaction is still there — the banned member could not remove it.
    const posts = await groups.getPosts(group.id, alice.fingerprint);
    expect(posts[0].reactions).toEqual({ [bob.fingerprint]: '👍' });
  });

  it('strips member/admin/banned lists from non-member views of PUBLIC groups', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock);

    const view = await groups.getGroup(group.id, bob.fingerprint);
    expect(view).not.toBeNull();
    expect((view as Record<string, unknown>).members).toBeUndefined();
    expect((view as Record<string, unknown>).admins).toBeUndefined();
    expect((view as Record<string, unknown>).banned).toBeUndefined();
    expect(view?.name).toBe('Test Group');

    // Members still receive the full record.
    const own = (await groups.getGroup(group.id, alice.fingerprint)) as GroupRecord;
    expect(own.members).toContain(alice.fingerprint);

    // Listings strip for non-members as well.
    const listing = await groups.listGroups(bob.fingerprint);
    expect(listing).toHaveLength(1);
    expect((listing[0] as Record<string, unknown>).members).toBeUndefined();
  });

  it('revoking a group invitation blocks acceptance', async () => {
    const { store, verifier, clock, alice, bob, mallory } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const group = await createTestGroup(groups, alice, clock, 'PRIVATE');

    const invitation = await groups.invite(
      act(GROUP_ACTIONS.invite, { groupId: group.id, invitee: bob.fingerprint }, alice, clock)
    );

    // A stranger cannot revoke somebody else's invitation.
    await expect(
      groups.revokeInvite(
        act(GROUP_ACTIONS.revokeInvite, { inviteId: invitation.id }, mallory, clock)
      )
    ).rejects.toThrow(AccessDeniedError);

    // The issuer can, and afterwards acceptance fails.
    const revoked = await groups.revokeInvite(
      act(GROUP_ACTIONS.revokeInvite, { inviteId: invitation.id }, alice, clock)
    );
    expect(revoked.revokedAt).not.toBeNull();

    await expect(
      groups.acceptInvite(act(GROUP_ACTIONS.acceptInvite, { inviteId: invitation.id }, bob, clock))
    ).rejects.toMatchObject({ code: 'invite_revoked' });
    expect(await groups.isMember(group.id, bob.fingerprint)).toBe(false);
  });
});
