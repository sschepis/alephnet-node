/**
 * Feed — aggregation and unread tracking, with signed read markers.
 */

import { describe, it, expect } from '@jest/globals';
import { act, wire } from './helpers';
import { FeedManager, FEED_ACTIONS, MarkReadFeedPayload } from '../../src/social/Feed';
import { Groups, GROUP_ACTIONS } from '../../src/social/Groups';
import {
  DirectMessages,
  DM_ACTIONS,
  MemoryConversationKeys
} from '../../src/social/DirectMessages';

describe('FeedManager', () => {
  it('aggregates group posts and marks unread state per requester', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const feed = new FeedManager({ store, groups, verifier, clock: clock.now });

    const group = await groups.createGroup(
      act(GROUP_ACTIONS.create, { name: 'Square', visibility: 'PUBLIC' }, alice, clock)
    );
    await groups.createPost(
      act(GROUP_ACTIONS.post, { groupId: group.id, content: 'hello world' }, alice, clock)
    );

    const items = await feed.getFeed(bob.fingerprint);
    expect(items).toHaveLength(1);
    expect(items[0].type).toBe('group_post');
    expect(items[0].authorFingerprint).toBe(alice.fingerprint);
    expect(items[0].unread).toBe(true);

    const summary = await feed.getUnreadSummary(bob.fingerprint);
    expect(summary.totalUnread).toBe(1);

    await feed.markRead(act(FEED_ACTIONS.markRead, { source: items[0].source }, bob, clock));
    const after = await feed.getFeed(bob.fingerprint);
    expect(after[0].unread).toBe(false);
    expect((await feed.getUnreadSummary(bob.fingerprint)).totalUnread).toBe(0);
  });

  it('does not count your own posts as unread', async () => {
    const { store, verifier, clock, alice } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const feed = new FeedManager({ store, groups, verifier, clock: clock.now });

    const group = await groups.createGroup(
      act(GROUP_ACTIONS.create, { name: 'Square', visibility: 'PUBLIC' }, alice, clock)
    );
    await groups.createPost(
      act(GROUP_ACTIONS.post, { groupId: group.id, content: 'self post' }, alice, clock)
    );

    const items = await feed.getFeed(alice.fingerprint);
    expect(items[0].unread).toBe(false);
  });

  it('aggregates direct messages too', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const keys = new MemoryConversationKeys();
    const dms = new DirectMessages({ store, verifier, keys, clock: clock.now });
    const feed = new FeedManager({ store, messages: dms, verifier, clock: clock.now });

    const room = await dms.openConversation(
      act(DM_ACTIONS.openConversation, { peer: bob.fingerprint }, alice, clock)
    );
    keys.generate(room.id);
    await dms.sendMessage(
      act(DM_ACTIONS.send, { roomId: room.id, content: 'feed me' }, alice, clock)
    );

    const items = await feed.getFeed(bob.fingerprint);
    expect(items).toHaveLength(1);
    expect(items[0].type).toBe('message');
    expect(items[0].unread).toBe(true);
  });

  it('never shows content the requester may not see', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const feed = new FeedManager({ store, groups, verifier, clock: clock.now });

    // Private group; bob is not a member.
    const group = await groups.createGroup(
      act(GROUP_ACTIONS.create, { name: 'Inner Circle', visibility: 'PRIVATE' }, alice, clock)
    );
    await groups.createPost(
      act(GROUP_ACTIONS.post, { groupId: group.id, content: 'private post' }, alice, clock)
    );

    expect(await feed.getFeed(bob.fingerprint)).toHaveLength(0);
  });

  it('tracks unread totals across multiple sources', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const groups = new Groups({ store, verifier, clock: clock.now });
    const keys = new MemoryConversationKeys();
    const dms = new DirectMessages({ store, verifier, keys, clock: clock.now });
    const feed = new FeedManager({ store, groups, messages: dms, verifier, clock: clock.now });

    const group = await groups.createGroup(
      act(GROUP_ACTIONS.create, { name: 'Square', visibility: 'PUBLIC' }, alice, clock)
    );
    await groups.createPost(
      act(GROUP_ACTIONS.post, { groupId: group.id, content: 'post one' }, alice, clock)
    );
    const room = await dms.openConversation(
      act(DM_ACTIONS.openConversation, { peer: bob.fingerprint }, alice, clock)
    );
    keys.generate(room.id);
    await dms.sendMessage(
      act(DM_ACTIONS.send, { roomId: room.id, content: 'dm one' }, alice, clock)
    );

    const summary = await feed.getUnreadSummary(bob.fingerprint);
    expect(summary.totalUnread).toBe(2);
    expect(summary.bySource).toHaveLength(2);
  });

  it('rejects tampered markRead envelopes (unsigned read markers are impossible)', async () => {
    const { store, verifier, clock, bob } = wire();
    const feed = new FeedManager({ store, verifier, clock: clock.now });

    const envelope = act<MarkReadFeedPayload>(
      FEED_ACTIONS.markRead,
      { source: { id: 'grp_0000000000000000', name: null, kind: 'group' } },
      bob,
      clock
    );
    envelope.payload = { ...envelope.payload, upTo: 1 };
    await expect(feed.markRead(envelope)).rejects.toMatchObject({ code: 'invalid_signature' });
  });

  it('refuses markRead when no verifier is configured', async () => {
    const { store, clock, bob } = wire();
    const feed = new FeedManager({ store, clock: clock.now });

    await expect(
      feed.markRead(
        act(
          FEED_ACTIONS.markRead,
          { source: { id: 'grp_0000000000000000', name: null, kind: 'group' } },
          bob,
          clock
        )
      )
    ).rejects.toMatchObject({ code: 'verifier_required' });
  });
});
