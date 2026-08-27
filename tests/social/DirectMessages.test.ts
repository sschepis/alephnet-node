/**
 * DirectMessages — real at-rest encryption, invitation expiry, read receipts,
 * live friendship/block revalidation.
 */

import { describe, it, expect } from '@jest/globals';
import { act, wire } from './helpers';
import { sha256Hex } from '../../src/common/crypto';
import {
  DirectMessages,
  DM_ACTIONS,
  MemoryConversationKeys,
  PassphraseConversationKeys,
  RoomRecord
} from '../../src/social/DirectMessages';
import { FriendGraph, FRIEND_ACTIONS } from '../../src/social/FriendGraph';
import { AccessDeniedError } from '../../src/social/types';

const CHEAP_SCRYPT = { N: 1024, r: 8, p: 1 };

async function openDM(
  dms: DirectMessages,
  alice: ReturnType<typeof wire>['alice'],
  bob: ReturnType<typeof wire>['bob'],
  clock: ReturnType<typeof wire>['clock']
): Promise<RoomRecord> {
  return dms.openConversation(act(DM_ACTIONS.openConversation, { peer: bob.fingerprint }, alice, clock));
}

describe('DirectMessages', () => {
  it('actually encrypts message bodies at rest and decrypts them correctly', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const keys = new MemoryConversationKeys();
    const dms = new DirectMessages({ store, verifier, keys, clock: clock.now });

    const room = await openDM(dms, alice, bob, clock);
    keys.generate(room.id);
    const sent = await dms.sendMessage(
      act(DM_ACTIONS.send, { roomId: room.id, content: 'TOP SECRET: meet at dawn' }, alice, clock)
    );
    expect(sent.encrypted).toBe(true);
    expect(sent.content).toBe('TOP SECRET: meet at dawn');

    // At rest: ciphertext only, no plaintext anywhere in the store.
    const stored = await dms.getStoredMessage(room.id, sent.id, bob.fingerprint);
    expect(stored?.encrypted).toBe(true);
    expect(stored?.sealed?.ciphertext).toBeTruthy();
    expect(stored?.sealed?.algorithm).toBe('AES-256-GCM');
    expect(stored?.plaintext).toBeNull();

    for (const raw of Object.values(store.dump())) {
      expect(raw).not.toContain('TOP SECRET: meet at dawn');
    }

    // Bob decrypts it back with the same conversation key.
    const views = await dms.getMessages(room.id, bob.fingerprint);
    expect(views).toHaveLength(1);
    expect(views[0].content).toBe('TOP SECRET: meet at dawn');
    expect(views[0].encrypted).toBe(true);
    expect(views[0].locked).toBe(false);
  });

  it('reports encrypted:false instead of lying when no key is available', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const dms = new DirectMessages({ store, verifier, clock: clock.now });

    const room = await openDM(dms, alice, bob, clock);
    const sent = await dms.sendMessage(
      act(DM_ACTIONS.send, { roomId: room.id, content: 'plaintext allowed here' }, alice, clock)
    );
    expect(sent.encrypted).toBe(false);
    expect(sent.content).toBe('plaintext allowed here');

    const stored = await dms.getStoredMessage(room.id, sent.id, alice.fingerprint);
    expect(stored?.encrypted).toBe(false);
    expect(stored?.plaintext).toBe('plaintext allowed here');
    expect(stored?.sealed).toBeNull();
  });

  it('refuses to send when the room requires encryption but no key exists', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    // No key provider, but force requireEncryption on.
    const dms = new DirectMessages({ store, verifier, clock: clock.now });

    const room = await dms.createRoom(
      act(
        DM_ACTIONS.createRoom,
        {
          name: 'Secret Room',
          type: 'GROUP',
          settings: { allowInvites: true, membersCanInvite: true, requireEncryption: true }
        },
        alice,
        clock
      )
    );

    await expect(
      dms.sendMessage(act(DM_ACTIONS.send, { roomId: room.id, content: 'nope' }, alice, clock))
    ).rejects.toMatchObject({ code: 'no_conversation_key' });
  });

  it('rejects expired invitations', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const dms = new DirectMessages({ store, verifier, clock: clock.now });

    const room = await dms.createRoom(
      act(DM_ACTIONS.createRoom, { name: 'Lounge', type: 'GROUP' }, alice, clock)
    );
    const invitation = await dms.createInvitation(
      act(
        DM_ACTIONS.createInvitation,
        { roomId: room.id, invitees: [bob.fingerprint], ttlMs: 1000 },
        alice,
        clock
      )
    );
    expect(invitation.expiresAt).toBeGreaterThan(invitation.createdAt);

    clock.advance(2000);
    await expect(
      dms.acceptInvitation(
        act(
          DM_ACTIONS.acceptInvitation,
          { invitationId: invitation.id, inviteCode: invitation.inviteCode },
          bob,
          clock
        )
      )
    ).rejects.toMatchObject({ code: 'invitation_expired' });
  });

  it('accepts a live invitation only with the right code and invitee', async () => {
    const { store, verifier, clock, alice, bob, mallory } = wire();
    const dms = new DirectMessages({ store, verifier, clock: clock.now });

    const room = await dms.createRoom(
      act(DM_ACTIONS.createRoom, { name: 'Lounge', type: 'GROUP' }, alice, clock)
    );
    const invitation = await dms.createInvitation(
      act(
        DM_ACTIONS.createInvitation,
        { roomId: room.id, invitees: [bob.fingerprint] },
        alice,
        clock
      )
    );

    // Wrong code.
    await expect(
      dms.acceptInvitation(
        act(
          DM_ACTIONS.acceptInvitation,
          { invitationId: invitation.id, inviteCode: 'definitely-wrong' },
          bob,
          clock
        )
      )
    ).rejects.toMatchObject({ code: 'access_denied' });

    // Wrong invitee.
    await expect(
      dms.acceptInvitation(
        act(
          DM_ACTIONS.acceptInvitation,
          { invitationId: invitation.id, inviteCode: invitation.inviteCode },
          mallory,
          clock
        )
      )
    ).rejects.toMatchObject({ code: 'access_denied' });

    // Correct invitee + code.
    await dms.acceptInvitation(
      act(
        DM_ACTIONS.acceptInvitation,
        { invitationId: invitation.id, inviteCode: invitation.inviteCode },
        bob,
        clock
      )
    );
    const joined = (await dms.getRoom(room.id, bob.fingerprint)) as RoomRecord;
    expect(joined.members).toContain(bob.fingerprint);

    // Single use per invitee.
    await expect(
      dms.acceptInvitation(
        act(
          DM_ACTIONS.acceptInvitation,
          { invitationId: invitation.id, inviteCode: invitation.inviteCode },
          bob,
          clock
        )
      )
    ).rejects.toMatchObject({ code: 'invitation_used' });
  });

  it('revoked invitations are rejected', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const dms = new DirectMessages({ store, verifier, clock: clock.now });

    const room = await dms.createRoom(
      act(DM_ACTIONS.createRoom, { name: 'Lounge', type: 'GROUP' }, alice, clock)
    );
    const invitation = await dms.createInvitation(
      act(
        DM_ACTIONS.createInvitation,
        { roomId: room.id, invitees: [bob.fingerprint] },
        alice,
        clock
      )
    );
    await dms.revokeInvitation(
      act(DM_ACTIONS.revokeInvitation, { invitationId: invitation.id }, alice, clock)
    );
    await expect(
      dms.acceptInvitation(
        act(
          DM_ACTIONS.acceptInvitation,
          { invitationId: invitation.id, inviteCode: invitation.inviteCode },
          bob,
          clock
        )
      )
    ).rejects.toMatchObject({ code: 'invitation_revoked' });
  });

  it('tracks read receipts and unread counts', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const keys = new MemoryConversationKeys();
    const dms = new DirectMessages({ store, verifier, keys, clock: clock.now });
    const room = await openDM(dms, alice, bob, clock);
    keys.generate(room.id);

    await dms.sendMessage(act(DM_ACTIONS.send, { roomId: room.id, content: 'ping 1' }, alice, clock));
    clock.advance(10);
    await dms.sendMessage(act(DM_ACTIONS.send, { roomId: room.id, content: 'ping 2' }, alice, clock));

    expect(await dms.getUnreadCount(room.id, bob.fingerprint)).toBe(2);

    const updated = await dms.markRead(act(DM_ACTIONS.markRead, { roomId: room.id }, bob, clock));
    expect(updated).toBe(2);
    expect(await dms.getUnreadCount(room.id, bob.fingerprint)).toBe(0);

    const messages = await dms.getMessages(room.id, bob.fingerprint);
    for (const message of messages) {
      expect(message.readBy).toContain(bob.fingerprint);
    }
  });

  it('binds message authorship to a signature and re-verifies it', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const keys = new MemoryConversationKeys();
    const dms = new DirectMessages({ store, verifier, keys, clock: clock.now });
    const room = await openDM(dms, alice, bob, clock);
    keys.generate(room.id);
    const sent = await dms.sendMessage(
      act(DM_ACTIONS.send, { roomId: room.id, content: 'signed body' }, alice, clock)
    );

    expect(await dms.verifyMessageAuthorship(room.id, sent.id, bob.fingerprint)).toBe(true);
  });

  it('derives per-conversation keys from a master secret (scrypt + room salt)', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const keys = new PassphraseConversationKeys('a-long-master-secret', CHEAP_SCRYPT);
    const dms = new DirectMessages({ store, verifier, keys, clock: clock.now });

    const roomA = await openDM(dms, alice, bob, clock);
    const roomB = await dms.createRoom(
      act(DM_ACTIONS.createRoom, { name: 'Other Room', type: 'GROUP' }, alice, clock)
    );
    expect(roomA.keySalt).not.toBe(roomB.keySalt);

    const keyA = await keys.getKey(roomA.id, {
      salt: roomA.keySalt,
      members: roomA.members,
      type: 'DM'
    });
    const keyB = await keys.getKey(roomB.id, {
      salt: roomB.keySalt,
      members: roomB.members,
      type: 'GROUP'
    });
    expect(keyA).not.toBeNull();
    expect(keyB).not.toBeNull();
    expect(keyA!.toString('hex')).not.toBe(keyB!.toString('hex'));
  });

  it('only members can send or read', async () => {
    const { store, verifier, clock, alice, bob, mallory } = wire();
    const dms = new DirectMessages({ store, verifier, clock: clock.now });
    const room = await openDM(dms, alice, bob, clock);

    await expect(
      dms.sendMessage(act(DM_ACTIONS.send, { roomId: room.id, content: 'intruder' }, mallory, clock))
    ).rejects.toMatchObject({ code: 'access_denied' });
    await expect(dms.getMessages(room.id, mallory.fingerprint)).rejects.toMatchObject({
      code: 'access_denied'
    });
    expect(await dms.getRoom(room.id, mallory.fingerprint)).toBeNull();
  });

  it('revokes DM access the moment a member is blocked or unfriended', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const graph = new FriendGraph({ store, verifier, clock: clock.now });
    const dms = new DirectMessages({ store, verifier, friends: graph, clock: clock.now });

    // Friends first, then open a DM.
    const request = await graph.sendRequest(
      act(FRIEND_ACTIONS.request, { to: bob.fingerprint }, alice, clock)
    );
    await graph.acceptRequest(act(FRIEND_ACTIONS.accept, { requestId: request.id }, bob, clock));
    const room = await openDM(dms, alice, bob, clock);
    await dms.sendMessage(
      act(DM_ACTIONS.send, { roomId: room.id, content: 'while we were friends' }, alice, clock)
    );

    // alice blocks bob (which also removes the friendship).
    await graph.block(act(FRIEND_ACTIONS.block, { target: bob.fingerprint }, alice, clock));

    // The blocked party can neither send nor read.
    await expect(
      dms.sendMessage(act(DM_ACTIONS.send, { roomId: room.id, content: 'still here?' }, bob, clock))
    ).rejects.toMatchObject({ code: 'access_denied' });
    await expect(dms.getMessages(room.id, bob.fingerprint)).rejects.toMatchObject({
      code: 'access_denied'
    });
    await expect(dms.getUnreadCount(room.id, bob.fingerprint)).rejects.toMatchObject({
      code: 'access_denied'
    });

    // The blocked member's rooms are dropped from listings and inbox too.
    expect(await dms.listRooms(bob.fingerprint)).toHaveLength(0);
    expect(await dms.getInbox(bob.fingerprint)).toHaveLength(0);
  });

  it('denies getUnreadCount to non-members', async () => {
    const { store, verifier, clock, alice, bob, mallory } = wire();
    const dms = new DirectMessages({ store, verifier, clock: clock.now });
    const room = await openDM(dms, alice, bob, clock);
    await dms.sendMessage(
      act(DM_ACTIONS.send, { roomId: room.id, content: 'ping' }, alice, clock)
    );

    await expect(dms.getUnreadCount(room.id, mallory.fingerprint)).rejects.toMatchObject({
      code: 'access_denied'
    });
  });

  it('cannot force-enroll members at room creation', async () => {
    const { store, verifier, clock, alice, mallory } = wire();
    const dms = new DirectMessages({ store, verifier, clock: clock.now });

    await expect(
      dms.createRoom(
        act(
          DM_ACTIONS.createRoom,
          { name: 'Trap Room', type: 'GROUP', members: [mallory.fingerprint] },
          alice,
          clock
        )
      )
    ).rejects.toMatchObject({ code: 'members_require_invitation' });

    // Rooms the creator makes alone start with exactly the creator.
    const room = await dms.createRoom(
      act(DM_ACTIONS.createRoom, { name: 'Solo Room', type: 'GROUP' }, alice, clock)
    );
    expect(room.members).toEqual([alice.fingerprint]);
  });

  it('strips member/admin/banned lists and keySalt from non-member views of PUBLIC rooms', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const dms = new DirectMessages({ store, verifier, clock: clock.now });
    const room = await dms.createRoom(
      act(DM_ACTIONS.createRoom, { name: 'Plaza', type: 'PUBLIC' }, alice, clock)
    );

    const view = await dms.getRoom(room.id, bob.fingerprint);
    expect(view).not.toBeNull();
    expect((view as Record<string, unknown>).members).toBeUndefined();
    expect((view as Record<string, unknown>).admins).toBeUndefined();
    expect((view as Record<string, unknown>).banned).toBeUndefined();
    expect((view as Record<string, unknown>).keySalt).toBeUndefined();
    expect((view as Record<string, unknown>).invitedBy).toBeUndefined();
    expect(view?.name).toBe('Plaza');

    // Members still receive the full record.
    const own = (await dms.getRoom(room.id, alice.fingerprint)) as RoomRecord;
    expect(own.members).toContain(alice.fingerprint);
    expect(own.keySalt).toBeTruthy();
  });

  it('getPendingInvitations returns only a digest, never the raw invite code', async () => {
    const { store, verifier, clock, alice, bob } = wire();
    const dms = new DirectMessages({ store, verifier, clock: clock.now });

    const room = await dms.createRoom(
      act(DM_ACTIONS.createRoom, { name: 'Lounge', type: 'GROUP' }, alice, clock)
    );
    const invitation = await dms.createInvitation(
      act(
        DM_ACTIONS.createInvitation,
        { roomId: room.id, invitees: [bob.fingerprint] },
        alice,
        clock
      )
    );

    const pending = await dms.getPendingInvitations(bob.fingerprint);
    expect(pending).toHaveLength(1);
    expect((pending[0] as unknown as Record<string, unknown>).inviteCode).toBeUndefined();
    expect(pending[0].inviteCodeDigest).toBe(sha256Hex(invitation.inviteCode));

    // A wrong code still fails, and the raw code still works end to end.
    await expect(
      dms.acceptInvitation(
        act(
          DM_ACTIONS.acceptInvitation,
          { invitationId: invitation.id, inviteCode: 'not-the-code' },
          bob,
          clock
        )
      )
    ).rejects.toMatchObject({ code: 'access_denied' });
    await dms.acceptInvitation(
      act(
        DM_ACTIONS.acceptInvitation,
        { invitationId: invitation.id, inviteCode: invitation.inviteCode },
        bob,
        clock
      )
    );
    expect(await dms.getPendingInvitations(bob.fingerprint)).toHaveLength(0);
  });
});
