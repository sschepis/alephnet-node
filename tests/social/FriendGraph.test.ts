/**
 * FriendGraph — signed requests, acceptance, blocking.
 */

import { describe, it, expect } from '@jest/globals';
import { act, wire } from './helpers';
import {
  FriendGraph,
  FriendGraphError,
  FRIEND_ACTIONS,
  FriendRequestPayload
} from '../../src/social/FriendGraph';
import { AccessDeniedError, SocialError } from '../../src/social/types';

describe('FriendGraph', () => {
  it('completes the signed request → accept round trip', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });

    const request = await graph.sendRequest(act(FRIEND_ACTIONS.request, { to: bob.fingerprint }, alice, clock));
    expect(request.status).toBe('pending');
    expect(request.from).toBe(alice.fingerprint);
    expect(request.to).toBe(bob.fingerprint);

    expect(await graph.areFriends(alice.fingerprint, bob.fingerprint)).toBe(false);

    const edges = await graph.acceptRequest(
      act(FRIEND_ACTIONS.accept, { requestId: request.id }, bob, clock)
    );
    expect(edges).toHaveLength(2);

    expect(await graph.areFriends(alice.fingerprint, bob.fingerprint)).toBe(true);
    expect(await graph.areFriends(bob.fingerprint, alice.fingerprint)).toBe(true);
    expect(await graph.getRelationship(alice.fingerprint, bob.fingerprint)).toBe('friends');

    const updated = await graph.getRequest(request.id);
    expect(updated?.status).toBe('accepted');
    expect(updated?.acceptanceSignature).toBeTruthy();
  });

  it('rejects acceptance for an unknown request id (no fabricated friendships)', async () => {
    const { store, verifier, clock, bob, mallory } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });

    // The legacy `handleRequestAccepted` created a Friend out of thin air when
    // the request id was unknown. That path must be gone.
    const forgedId = `req_${'ab'.repeat(16)}`;
    await expect(
      graph.acceptRequest(act(FRIEND_ACTIONS.accept, { requestId: forgedId }, bob, clock))
    ).rejects.toMatchObject({ code: 'unknown_request' });

    // And nothing changed in the graph.
    expect(await graph.areFriends(bob.fingerprint, mallory.fingerprint)).toBe(false);
    expect(await graph.listFriends(bob.fingerprint)).toHaveLength(0);
  });

  it('rejects acceptance by anyone but the addressee', async () => {
    const { store, verifier, clock, alice, bob, mallory } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });

    const request = await graph.sendRequest(
      act(FRIEND_ACTIONS.request, { to: bob.fingerprint }, alice, clock)
    );
    await expect(
      graph.acceptRequest(act(FRIEND_ACTIONS.accept, { requestId: request.id }, mallory, clock))
    ).rejects.toThrow(AccessDeniedError);

    // Still pending, still not friends.
    expect((await graph.getRequest(request.id))?.status).toBe('pending');
    expect(await graph.areFriends(alice.fingerprint, bob.fingerprint)).toBe(false);
  });

  it('rejects acceptance of an already-closed request', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });
    const request = await graph.sendRequest(
      act(FRIEND_ACTIONS.request, { to: bob.fingerprint }, alice, clock)
    );
    await graph.acceptRequest(act(FRIEND_ACTIONS.accept, { requestId: request.id }, bob, clock));
    await expect(
      graph.acceptRequest(act(FRIEND_ACTIONS.accept, { requestId: request.id }, bob, clock))
    ).rejects.toMatchObject({ code: 'request_closed' });
  });

  it('rejects unauthenticated request payloads (unsigned mutations fail)', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });

    const forged = act<FriendRequestPayload>(
      FRIEND_ACTIONS.request,
      { to: bob.fingerprint },
      alice,
      clock
    );
    forged.payload = { to: alice.fingerprint, message: '' }; // tamper with the payload
    await expect(graph.sendRequest(forged)).rejects.toMatchObject({ code: 'invalid_signature' });
  });

  it('rejects friend requests to yourself', async () => {
    const { store, verifier, clock, alice } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });
    await expect(
      graph.sendRequest(act(FRIEND_ACTIONS.request, { to: alice.fingerprint }, alice, clock))
    ).rejects.toMatchObject({ code: 'invalid_target' });
  });

  it('deduplicates pending requests between the same pair', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });
    await graph.sendRequest(act(FRIEND_ACTIONS.request, { to: bob.fingerprint }, alice, clock));
    clock.advance(1000);
    await expect(
      graph.sendRequest(act(FRIEND_ACTIONS.request, { to: bob.fingerprint }, alice, clock))
    ).rejects.toMatchObject({ code: 'request_pending' });
  });

  it('blocks a fingerprint and removes the friendship', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });
    const request = await graph.sendRequest(
      act(FRIEND_ACTIONS.request, { to: bob.fingerprint }, alice, clock)
    );
    await graph.acceptRequest(act(FRIEND_ACTIONS.accept, { requestId: request.id }, bob, clock));
    expect(await graph.areFriends(alice.fingerprint, bob.fingerprint)).toBe(true);

    await graph.block(act(FRIEND_ACTIONS.block, { target: bob.fingerprint }, alice, clock));
    expect(await graph.areFriends(alice.fingerprint, bob.fingerprint)).toBe(false);
    expect(await graph.getRelationship(alice.fingerprint, bob.fingerprint)).toBe('blocked');

    // And new requests from the blocked user are refused.
    await expect(
      graph.sendRequest(act(FRIEND_ACTIONS.request, { to: alice.fingerprint }, bob, clock))
    ).rejects.toThrow(AccessDeniedError);
  });

  it('annotates friends (nickname, favorite)', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });
    const request = await graph.sendRequest(
      act(FRIEND_ACTIONS.request, { to: bob.fingerprint }, alice, clock)
    );
    await graph.acceptRequest(act(FRIEND_ACTIONS.accept, { requestId: request.id }, bob, clock));

    await graph.annotateFriend(
      act(FRIEND_ACTIONS.annotate, { target: bob.fingerprint, nickname: 'Bobby', favorite: true }, alice, clock)
    );
    const edge = await graph.getFriend(alice.fingerprint, bob.fingerprint);
    expect(edge?.nickname).toBe('Bobby');
    expect(edge?.favorite).toBe(true);
  });

  it('rejects malformed request ids on every mutation', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });

    for (const requestId of ['../evil', 'req_!!', ''] as unknown as string[]) {
      await expect(
        graph.acceptRequest(act(FRIEND_ACTIONS.accept, { requestId }, bob, clock))
      ).rejects.toThrow(SocialError);
    }
  });

  it('exposes stats and pending lists', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });
    await graph.sendRequest(act(FRIEND_ACTIONS.request, { to: bob.fingerprint }, alice, clock));

    expect(await graph.getIncomingRequests(bob.fingerprint)).toHaveLength(1);
    expect(await graph.getOutgoingRequests(alice.fingerprint)).toHaveLength(1);

    const stats = await graph.getStats(alice.fingerprint);
    expect(stats.pendingOutgoing).toBe(1);
  });
});
