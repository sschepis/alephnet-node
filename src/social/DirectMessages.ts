/**
 * DirectMessages — conversations, rooms, invitations, read receipts
 *
 * Legacy flaws fixed here:
 *   - Messages were flagged `encrypted: true` in the room settings while
 *     `sendMessage()` literally commented "For now, store unencrypted" and
 *     persisted plaintext. Here bodies are sealed with AES-256-GCM under a
 *     PER-CONVERSATION key, and when no key is available the message is stored
 *     with `encrypted: false` and reported as such. The flag never lies.
 *   - `acceptInvitation()` never looked at `expiresAt`. Expiry, revocation,
 *     single-use and invitee binding are all enforced now.
 *   - Sending/deleting/marking-read used the ambient local node id. Every
 *     mutation is a `SignedAction`, so the sender is cryptographically bound to
 *     the message, and the signature is retained for later re-verification.
 *
 * Key management is intentionally pluggable: `ConversationKeyProvider` is where
 * a real key-agreement protocol belongs. Two honest implementations ship here —
 * a scrypt-per-room derivation from a master secret, and an explicit in-memory
 * keyring for keys distributed out of band.
 */

import { timingSafeEqual } from 'crypto';
import {
  EncryptedData,
  decryptAES256GCM,
  deriveKeyFromPassword,
  encryptAES256GCM,
  randomBytes,
  sha256Hex,
  base64ToBuffer,
  verifyFromBase64
} from '../common/crypto';
import type { ActionVerifier, SignedAction, VerifiedAction } from './SignedAction';
import { assertNoImpersonation, canonicalActionString } from './SignedAction';
import type { SocialStore } from './SocialStore';
import { getRecord, listRecords, storeKey } from './SocialStore';
import {
  AccessDeniedError,
  Base64,
  ContentHash,
  Fingerprint,
  FriendshipOracle,
  PageOptions,
  SocialError,
  Timestamp,
  assertContentHash,
  assertFingerprint,
  assertRecordId,
  assertText,
  systemClock,
  type SocialClock
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// ACTIONS & PAYLOADS
// ═══════════════════════════════════════════════════════════════════════════

export const DM_ACTIONS = {
  openConversation: 'dm.conversation.open',
  createRoom: 'dm.room.create',
  send: 'dm.message.send',
  edit: 'dm.message.edit',
  delete: 'dm.message.delete',
  markRead: 'dm.message.read',
  leave: 'dm.room.leave',
  createInvitation: 'dm.invitation.create',
  acceptInvitation: 'dm.invitation.accept',
  revokeInvitation: 'dm.invitation.revoke',
  ban: 'dm.room.ban'
} as const;

export type MessageType = 'text' | 'image' | 'file' | 'link';
export type RoomType = 'DM' | 'GROUP' | 'PUBLIC';

export interface OpenConversationPayload {
  peer: Fingerprint;
}

export interface CreateRoomPayload {
  name: string;
  description?: string;
  members?: Fingerprint[];
  type?: Exclude<RoomType, 'DM'>;
  settings?: Partial<RoomSettings>;
}

export interface SendMessagePayload {
  roomId: string;
  content: string;
  type?: MessageType;
  replyTo?: string;
  contentHash?: ContentHash;
}

export interface EditMessagePayload {
  roomId: string;
  messageId: string;
  content: string;
}

export interface MessageIdPayload {
  roomId: string;
  messageId: string;
}

export interface MarkReadPayload {
  roomId: string;
  messageIds?: string[];
}

export interface RoomIdPayload {
  roomId: string;
}

export interface CreateInvitationPayload {
  roomId: string;
  invitees: Fingerprint[];
  ttlMs?: number;
}

export interface AcceptInvitationPayload {
  invitationId: string;
  inviteCode: string;
}

export interface InvitationIdPayload {
  invitationId: string;
}

export interface BanPayload {
  roomId: string;
  member: Fingerprint;
}

// ═══════════════════════════════════════════════════════════════════════════
// RECORDS
// ═══════════════════════════════════════════════════════════════════════════

export interface RoomSettings {
  allowInvites: boolean;
  membersCanInvite: boolean;
  /** Refuse to store a message at all if it cannot be encrypted. */
  requireEncryption: boolean;
}

export interface RoomRecord {
  id: string;
  type: RoomType;
  name: string | null;
  description: string;
  createdBy: Fingerprint;
  createdAt: Timestamp;
  updatedAt: Timestamp;
  members: Fingerprint[];
  admins: Fingerprint[];
  banned: Fingerprint[];
  invitedBy: Record<Fingerprint, Fingerprint>;
  /** Public per-conversation salt used to derive this room's key. */
  keySalt: Base64;
  settings: RoomSettings;
  lastMessageAt: Timestamp | null;
  messageCount: number;
  /** Sorted fingerprint pair, for DM de-duplication. */
  dmPair: string | null;
}

/**
 * A message as it exists at rest.
 *
 * When `encrypted` is true, `sealed` holds the AES-256-GCM ciphertext and
 * `plaintext` is null. When `encrypted` is false the reverse holds — and the
 * flag says so.
 */
export interface StoredMessage {
  id: string;
  roomId: string;
  from: Fingerprint;
  fromPub: Base64;
  type: MessageType;
  encrypted: boolean;
  sealed: EncryptedData | null;
  plaintext: string | null;
  contentHash: ContentHash | null;
  replyTo: string | null;
  timestamp: Timestamp;
  editedAt: Timestamp | null;
  deletedAt: Timestamp | null;
  readBy: Fingerprint[];
  /** Signature of the send envelope, kept so authorship stays provable. */
  signature: Base64;
  /** Everything needed to rebuild the signed bytes, minus the content. */
  provenance: MessageProvenance;
}

export interface MessageProvenance {
  action: string;
  nonce: string;
  timestamp: Timestamp;
  /** The signed payload with `content` removed (content lives encrypted). */
  payloadRest: Record<string, unknown>;
}

/** A message as returned to a member. */
export interface MessageView {
  id: string;
  roomId: string;
  from: Fingerprint;
  type: MessageType;
  encrypted: boolean;
  /** Decrypted body, or null when the conversation key is unavailable. */
  content: string | null;
  /** True when the body is encrypted and could not be opened. */
  locked: boolean;
  contentHash: ContentHash | null;
  replyTo: string | null;
  timestamp: Timestamp;
  editedAt: Timestamp | null;
  deletedAt: Timestamp | null;
  readBy: Fingerprint[];
  signature: Base64;
}

export interface InvitationRecord {
  id: string;
  roomId: string;
  roomName: string | null;
  invitedBy: Fingerprint;
  invitees: Fingerprint[];
  /** Random code; compared by digest, never logged. */
  inviteCode: string;
  createdAt: Timestamp;
  expiresAt: Timestamp;
  revokedAt: Timestamp | null;
  acceptedBy: Fingerprint[];
  signature: Base64;
}

export interface RoomSummary {
  id: string;
  type: RoomType;
  name: string | null;
  description: string;
  memberCount: number;
  createdBy: Fingerprint;
  createdAt: Timestamp;
  lastMessageAt: Timestamp | null;
  messageCount: number;
  unreadCount: number;
  encrypted: boolean;
}

/**
 * A room as shown to a NON-member requester. Member/admin/banned lists,
 * the invitee map and the key salt are stripped — disclosing them to
 * strangers would leak membership data and weaken the per-room key
 * derivation.
 */
export type RoomPublicView = Omit<
  RoomRecord,
  'members' | 'admins' | 'banned' | 'invitedBy' | 'keySalt'
>;

/**
 * A pending invitation as shown to the invitee. The raw invite code is
 * NEVER returned here — only its SHA-256 digest, which acts as a display
 * hint; the actual code must reach the invitee out of band (it is returned
 * once, to the issuer, from `createInvitation`).
 */
export interface PendingInvitationView {
  id: string;
  roomId: string;
  roomName: string | null;
  invitedBy: Fingerprint;
  invitees: Fingerprint[];
  inviteCodeDigest: string;
  createdAt: Timestamp;
  expiresAt: Timestamp;
  revokedAt: Timestamp | null;
  acceptedBy: Fingerprint[];
  signature: Base64;
}

export class MessagingError extends SocialError {}

// ═══════════════════════════════════════════════════════════════════════════
// CONVERSATION KEYS
// ═══════════════════════════════════════════════════════════════════════════

export interface ConversationKeyContext {
  /** The room's public per-conversation salt. */
  salt: Base64;
  members: Fingerprint[];
  type: RoomType;
}

/**
 * Source of per-conversation AES-256 keys. Returning null means "no key for
 * this conversation" — the caller then either refuses to send (when
 * `requireEncryption`) or stores the body in the clear with `encrypted: false`.
 */
export interface ConversationKeyProvider {
  getKey(roomId: string, context: ConversationKeyContext): Promise<Buffer | null>;
}

/**
 * Derives a distinct key per conversation from one master secret and the
 * room's random salt: `scrypt(master, salt)`.
 *
 * The master secret is held in memory by the caller and never written to the
 * store, so a compromised store yields ciphertext only.
 */
export class PassphraseConversationKeys implements ConversationKeyProvider {
  private readonly cache = new Map<string, Buffer>();

  constructor(
    private readonly masterSecret: string,
    private readonly scryptParams: { N: number; r: number; p: number } = { N: 16384, r: 8, p: 1 }
  ) {
    if (typeof masterSecret !== 'string' || masterSecret.length < 8) {
      throw new MessagingError(
        'weak_master_secret',
        'PassphraseConversationKeys requires a master secret of at least 8 characters'
      );
    }
  }

  async getKey(roomId: string, context: ConversationKeyContext): Promise<Buffer | null> {
    const cached = this.cache.get(roomId);
    if (cached) return cached;
    const salt = base64ToBuffer(context.salt);
    const key = await deriveKeyFromPassword(
      `${this.masterSecret}|${roomId}`,
      salt,
      32,
      this.scryptParams
    );
    this.cache.set(roomId, key);
    return key;
  }
}

/**
 * Explicit keyring for keys agreed out of band. Keys live only in memory.
 */
export class MemoryConversationKeys implements ConversationKeyProvider {
  private readonly keys = new Map<string, Buffer>();

  /** Install a 32-byte key for a conversation. */
  setKey(roomId: string, key: Buffer): void {
    if (key.length !== 32) {
      throw new MessagingError('invalid_key', 'Conversation keys must be exactly 32 bytes');
    }
    this.keys.set(roomId, key);
  }

  /** Generate and install a fresh random key. */
  generate(roomId: string): Buffer {
    const key = randomBytes(32);
    this.keys.set(roomId, key);
    return key;
  }

  async getKey(roomId: string): Promise<Buffer | null> {
    return this.keys.get(roomId) ?? null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// KEYS & LIMITS
// ═══════════════════════════════════════════════════════════════════════════

const K_ROOM = 'room';
const K_MSG = 'msg';
const K_DM_INDEX = 'dmpair';
const K_INVITE = 'dminvite';

const roomKey = (id: string): string => storeKey(K_ROOM, assertRecordId(id, 'roomId'));
const msgKey = (roomId: string, order: string): string =>
  storeKey(K_MSG, assertRecordId(roomId, 'roomId'), order);
const msgPrefix = (roomId: string): string => `${K_MSG}/${assertRecordId(roomId, 'roomId')}/`;
const dmPairKey = (pair: string): string => storeKey(K_DM_INDEX, pair);
const invitationKey = (id: string): string =>
  storeKey(K_INVITE, assertRecordId(id, 'invitationId'));

export const DM_LIMITS = {
  roomName: 120,
  description: 500,
  content: 8000,
  maxInvitees: 100,
  maxMessagesPerRoom: 5000
} as const;

const DEFAULT_INVITE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_INVITE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const MESSAGE_TYPES: readonly MessageType[] = ['text', 'image', 'file', 'link'];

// ═══════════════════════════════════════════════════════════════════════════
// DIRECT MESSAGES
// ═══════════════════════════════════════════════════════════════════════════

export interface DirectMessagesOptions {
  store: SocialStore;
  verifier: ActionVerifier;
  keys?: ConversationKeyProvider;
  friends?: FriendshipOracle;
  clock?: SocialClock;
  /** Require friendship to open a DM. Defaults to true when a graph is wired. */
  requireFriendshipForDM?: boolean;
}

export interface MessageQuery extends PageOptions {
  before?: Timestamp;
  includeDeleted?: boolean;
}

export class DirectMessages {
  private readonly store: SocialStore;
  private readonly verifier: ActionVerifier;
  private readonly keys?: ConversationKeyProvider;
  private readonly friends?: FriendshipOracle;
  private readonly clock: SocialClock;
  private readonly requireFriendshipForDM: boolean;

  constructor(options: DirectMessagesOptions) {
    this.store = options.store;
    this.verifier = options.verifier;
    this.keys = options.keys;
    this.friends = options.friends;
    this.clock = options.clock ?? systemClock;
    this.requireFriendshipForDM = options.requireFriendshipForDM ?? Boolean(options.friends);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Conversations & rooms
  // ─────────────────────────────────────────────────────────────────────────

  /** Open (or return) the 1:1 conversation between the author and `peer`. */
  async openConversation(envelope: SignedAction<OpenConversationPayload>): Promise<RoomRecord> {
    const verified = await this.verify(envelope, DM_ACTIONS.openConversation);
    const self = verified.author.fingerprint;
    const peer = assertFingerprint(verified.payload?.peer, 'peer');
    if (self === peer) {
      throw new MessagingError('invalid_peer', 'Cannot open a conversation with yourself');
    }
    if (this.friends && (await this.isBlockedEitherWay(self, peer))) {
      throw new AccessDeniedError('Conversation is not permitted');
    }
    if (this.requireFriendshipForDM) {
      if (!this.friends || !(await this.friends.areFriends(self, peer))) {
        throw new AccessDeniedError('You can only message confirmed friends', { peer });
      }
    }

    const pair = dmPair(self, peer);
    const existingId = await getRecord<{ roomId: string }>(this.store, dmPairKey(pair));
    if (existingId) {
      const existing = await getRecord<RoomRecord>(this.store, roomKey(existingId.roomId));
      if (existing) return existing;
    }

    const now = this.clock();
    const room: RoomRecord = {
      id: `room_${sha256Hex(`dm|${pair}`).slice(0, 24)}`,
      type: 'DM',
      name: null,
      description: '',
      createdBy: self,
      createdAt: now,
      updatedAt: now,
      members: [self, peer],
      admins: [self, peer],
      banned: [],
      invitedBy: {},
      keySalt: randomBytes(16).toString('base64'),
      settings: {
        allowInvites: false,
        membersCanInvite: false,
        requireEncryption: Boolean(this.keys)
      },
      lastMessageAt: null,
      messageCount: 0,
      dmPair: pair
    };
    await this.store.put(roomKey(room.id), room);
    await this.store.put(dmPairKey(pair), { roomId: room.id });
    return room;
  }

  /**
   * Create a multi-party room. The author becomes creator and admin.
   *
   * Other members can never be force-enrolled: the room starts with the
   * creator alone, and everyone else must join via invitation + acceptance.
   */
  async createRoom(envelope: SignedAction<CreateRoomPayload>): Promise<RoomRecord> {
    const verified = await this.verify(envelope, DM_ACTIONS.createRoom);
    const creator = verified.author.fingerprint;
    const payload = verified.payload ?? ({} as CreateRoomPayload);
    const now = this.clock();

    const members = new Set<Fingerprint>([creator]);
    const requested = (payload.members ?? []).map((member) =>
      assertFingerprint(member, 'member')
    );
    const extra = requested.filter((member) => member !== creator);
    if (extra.length > 0) {
      throw new MessagingError(
        'members_require_invitation',
        'Members beyond the creator cannot be enrolled at room creation; invite them and have them accept'
      );
    }
    for (const member of requested) members.add(member);

    const room: RoomRecord = {
      id: `room_${sha256Hex(`dm.room|${verified.signature}`).slice(0, 24)}`,
      type: payload.type === 'PUBLIC' ? 'PUBLIC' : 'GROUP',
      name: assertText(payload.name, 'name', DM_LIMITS.roomName),
      description: payload.description
        ? assertText(payload.description, 'description', DM_LIMITS.description, {
            allowEmpty: true
          })
        : '',
      createdBy: creator,
      createdAt: now,
      updatedAt: now,
      members: [...members],
      admins: [creator],
      banned: [],
      invitedBy: {},
      keySalt: randomBytes(16).toString('base64'),
      settings: {
        allowInvites: payload.settings?.allowInvites ?? true,
        membersCanInvite: payload.settings?.membersCanInvite ?? true,
        requireEncryption: payload.settings?.requireEncryption ?? Boolean(this.keys)
      },
      lastMessageAt: null,
      messageCount: 0,
      dmPair: null
    };

    await this.store.put(roomKey(room.id), room);
    return room;
  }

  /** Leave a room. DM rooms are kept so history survives. */
  async leaveRoom(envelope: SignedAction<RoomIdPayload>): Promise<RoomRecord> {
    const verified = await this.verify(envelope, DM_ACTIONS.leave);
    const room = await this.requireRoom(verified.payload?.roomId);
    const actor = verified.author.fingerprint;
    room.members = room.members.filter((m) => m !== actor);
    room.admins = room.admins.filter((m) => m !== actor);
    room.updatedAt = this.clock();
    await this.store.put(roomKey(room.id), room);
    return room;
  }

  /** Ban a member from a room. Admins only; the creator is protected. */
  async banMember(envelope: SignedAction<BanPayload>): Promise<RoomRecord> {
    const verified = await this.verify(envelope, DM_ACTIONS.ban);
    const room = await this.requireRoom(verified.payload?.roomId);
    const actor = verified.author.fingerprint;
    const member = assertFingerprint(verified.payload?.member, 'member');
    if (!room.admins.includes(actor)) {
      throw new AccessDeniedError('Only room admins may ban members');
    }
    if (member === room.createdBy) {
      throw new MessagingError('creator_protected', 'The room creator cannot be banned');
    }
    room.members = room.members.filter((m) => m !== member);
    room.admins = room.admins.filter((m) => m !== member);
    if (!room.banned.includes(member)) room.banned.push(member);
    room.updatedAt = this.clock();
    await this.store.put(roomKey(room.id), room);
    return room;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Messages
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Send a message. The body is sealed with the conversation key when one is
   * available; otherwise the message is stored (and reported) as unencrypted,
   * unless the room requires encryption, in which case sending fails.
   */
  async sendMessage(envelope: SignedAction<SendMessagePayload>): Promise<MessageView> {
    const verified = await this.verify(envelope, DM_ACTIONS.send);
    const room = await this.requireRoom(verified.payload?.roomId);
    const sender = verified.author.fingerprint;
    await this.assertRoomAccess(room, sender, 'send messages to');

    const content = assertText(verified.payload?.content, 'content', DM_LIMITS.content);
    const type = requireMessageType(verified.payload?.type ?? 'text');
    const replyTo = verified.payload?.replyTo
      ? assertRecordId(verified.payload.replyTo, 'replyTo')
      : null;
    const contentHash = verified.payload?.contentHash
      ? assertContentHash(verified.payload.contentHash, 'contentHash')
      : null;

    const key = await this.conversationKey(room);
    if (!key && room.settings.requireEncryption) {
      throw new MessagingError(
        'no_conversation_key',
        'This room requires encryption but no conversation key is available'
      );
    }

    const messageId = `msg_${sha256Hex(`dm.send|${verified.signature}`).slice(0, 24)}`;
    const stored: StoredMessage = {
      id: messageId,
      roomId: room.id,
      from: sender,
      fromPub: verified.author.pub,
      type,
      encrypted: key !== null,
      sealed: key ? encryptAES256GCM(Buffer.from(content, 'utf8'), key) : null,
      plaintext: key ? null : content,
      contentHash,
      replyTo,
      timestamp: verified.timestamp,
      editedAt: null,
      deletedAt: null,
      readBy: [sender],
      signature: verified.signature,
      provenance: {
        action: verified.action,
        nonce: verified.nonce,
        timestamp: verified.timestamp,
        payloadRest: payloadWithoutContent(verified.payload)
      }
    };

    await this.store.put(msgKey(room.id, orderToken(stored.timestamp, stored.id)), stored);
    room.messageCount += 1;
    room.lastMessageAt = stored.timestamp;
    room.updatedAt = this.clock();
    await this.store.put(roomKey(room.id), room);

    return this.toView(stored, content);
  }

  /** Edit your own message. Re-seals the new body. */
  async editMessage(envelope: SignedAction<EditMessagePayload>): Promise<MessageView> {
    const verified = await this.verify(envelope, DM_ACTIONS.edit);
    const room = await this.requireRoom(verified.payload?.roomId);
    const actor = verified.author.fingerprint;
    await this.assertRoomAccess(room, actor, 'edit messages in');

    const located = await this.locateMessage(room.id, verified.payload?.messageId);
    if (located.message.from !== actor) {
      throw new AccessDeniedError('Only the sender may edit a message');
    }
    if (located.message.deletedAt !== null) {
      throw new MessagingError('message_deleted', 'Cannot edit a deleted message');
    }

    const content = assertText(verified.payload?.content, 'content', DM_LIMITS.content);
    const key = await this.conversationKey(room);
    if (!key && room.settings.requireEncryption) {
      throw new MessagingError(
        'no_conversation_key',
        'This room requires encryption but no conversation key is available'
      );
    }

    located.message.encrypted = key !== null;
    located.message.sealed = key ? encryptAES256GCM(Buffer.from(content, 'utf8'), key) : null;
    located.message.plaintext = key ? null : content;
    located.message.editedAt = this.clock();
    // The stored signature covered the ORIGINAL body; provenance is no longer
    // re-verifiable after an edit, so mark it as such rather than lying.
    located.message.provenance.payloadRest = {
      ...located.message.provenance.payloadRest,
      edited: true
    };
    await this.store.put(located.key, located.message);
    return this.toView(located.message, content);
  }

  /** Soft-delete a message. Sender or room admin. */
  async deleteMessage(envelope: SignedAction<MessageIdPayload>): Promise<MessageView> {
    const verified = await this.verify(envelope, DM_ACTIONS.delete);
    const room = await this.requireRoom(verified.payload?.roomId);
    const actor = verified.author.fingerprint;
    await this.assertRoomAccess(room, actor, 'delete messages in');
    const located = await this.locateMessage(room.id, verified.payload?.messageId);

    if (located.message.from !== actor && !room.admins.includes(actor)) {
      throw new AccessDeniedError('Only the sender or a room admin may delete this message');
    }
    located.message.deletedAt = this.clock();
    located.message.sealed = null;
    located.message.plaintext = null;
    located.message.encrypted = false;
    await this.store.put(located.key, located.message);
    return this.toView(located.message, null);
  }

  /** Read receipts: mark messages read by the verified author. */
  async markRead(envelope: SignedAction<MarkReadPayload>): Promise<number> {
    const verified = await this.verify(envelope, DM_ACTIONS.markRead);
    const room = await this.requireRoom(verified.payload?.roomId);
    const reader = verified.author.fingerprint;
    await this.assertRoomAccess(room, reader, 'read');

    const wanted = verified.payload?.messageIds;
    const ids = Array.isArray(wanted)
      ? new Set(wanted.map((id) => assertRecordId(id, 'messageId')))
      : null;

    let updated = 0;
    for (const { key, message } of await this.allMessages(room.id)) {
      if (ids && !ids.has(message.id)) continue;
      if (message.readBy.includes(reader)) continue;
      message.readBy.push(reader);
      await this.store.put(key, message);
      updated += 1;
    }
    return updated;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Invitations
  // ─────────────────────────────────────────────────────────────────────────

  /** Create a room invitation with a real, enforced expiry. */
  async createInvitation(
    envelope: SignedAction<CreateInvitationPayload>
  ): Promise<InvitationRecord> {
    const verified = await this.verify(envelope, DM_ACTIONS.createInvitation);
    const room = await this.requireRoom(verified.payload?.roomId);
    const inviter = verified.author.fingerprint;

    if (!room.settings.allowInvites) {
      throw new AccessDeniedError('Invitations are disabled for this room');
    }
    this.assertMember(room, inviter, 'invite to');
    if (!room.admins.includes(inviter) && !room.settings.membersCanInvite) {
      throw new AccessDeniedError('Only room admins may invite');
    }

    const rawInvitees = verified.payload?.invitees ?? [];
    if (!Array.isArray(rawInvitees) || rawInvitees.length === 0) {
      throw new MessagingError('no_invitees', 'At least one invitee fingerprint is required');
    }
    if (rawInvitees.length > DM_LIMITS.maxInvitees) {
      throw new MessagingError('too_many_invitees', 'Too many invitees in one invitation');
    }
    const invitees = rawInvitees
      .map((invitee) => assertFingerprint(invitee, 'invitee'))
      .filter((invitee) => !room.members.includes(invitee) && !room.banned.includes(invitee));
    if (invitees.length === 0) {
      throw new MessagingError('no_invitees', 'All invitees are already members or banned');
    }

    const record: InvitationRecord = {
      id: `inv_${sha256Hex(`dm.invite|${verified.signature}`).slice(0, 24)}`,
      roomId: room.id,
      roomName: room.name,
      invitedBy: inviter,
      invitees,
      inviteCode: randomBytes(16).toString('base64url'),
      createdAt: verified.timestamp,
      expiresAt: verified.timestamp + clampTtl(verified.payload?.ttlMs),
      revokedAt: null,
      acceptedBy: [],
      signature: verified.signature
    };
    await this.store.put(invitationKey(record.id), record);
    return record;
  }

  /**
   * Accept an invitation.
   *
   * Enforces, in order: existence, revocation, EXPIRY, invitee binding, single
   * use per invitee, correct code, and bans. The legacy version checked only
   * the code.
   */
  async acceptInvitation(envelope: SignedAction<AcceptInvitationPayload>): Promise<RoomRecord> {
    const verified = await this.verify(envelope, DM_ACTIONS.acceptInvitation);
    const invitationId = assertRecordId(verified.payload?.invitationId, 'invitationId');
    const invitation = await getRecord<InvitationRecord>(
      this.store,
      invitationKey(invitationId)
    );
    const invitee = verified.author.fingerprint;

    if (!invitation) {
      throw new MessagingError('unknown_invitation', 'No such invitation', { invitationId });
    }
    if (invitation.revokedAt !== null) {
      throw new MessagingError('invitation_revoked', 'This invitation has been revoked');
    }
    if (this.clock() >= invitation.expiresAt) {
      throw new MessagingError('invitation_expired', 'This invitation has expired', {
        expiresAt: invitation.expiresAt
      });
    }
    if (!invitation.invitees.includes(invitee)) {
      throw new AccessDeniedError('This invitation was not issued to you');
    }
    if (invitation.acceptedBy.includes(invitee)) {
      throw new MessagingError('invitation_used', 'You have already accepted this invitation');
    }
    const provided = typeof verified.payload?.inviteCode === 'string' ? verified.payload.inviteCode : '';
    if (!inviteCodeMatches(provided, invitation.inviteCode)) {
      throw new AccessDeniedError('Invalid invite code');
    }

    const room = await this.requireRoom(invitation.roomId);
    if (room.banned.includes(invitee)) {
      throw new AccessDeniedError('You are banned from this room');
    }

    if (!room.members.includes(invitee)) {
      room.members.push(invitee);
      room.invitedBy[invitee] = invitation.invitedBy;
      room.updatedAt = this.clock();
      await this.store.put(roomKey(room.id), room);
    }
    invitation.acceptedBy.push(invitee);
    await this.store.put(invitationKey(invitation.id), invitation);
    return room;
  }

  /** Revoke an invitation. Issuer or room admin. */
  async revokeInvitation(envelope: SignedAction<InvitationIdPayload>): Promise<InvitationRecord> {
    const verified = await this.verify(envelope, DM_ACTIONS.revokeInvitation);
    const invitationId = assertRecordId(verified.payload?.invitationId, 'invitationId');
    const invitation = await getRecord<InvitationRecord>(this.store, invitationKey(invitationId));
    if (!invitation) {
      throw new MessagingError('unknown_invitation', 'No such invitation', { invitationId });
    }
    const room = await this.requireRoom(invitation.roomId);
    const actor = verified.author.fingerprint;
    if (invitation.invitedBy !== actor && !room.admins.includes(actor)) {
      throw new AccessDeniedError('Only the issuer or a room admin may revoke this invitation');
    }
    invitation.revokedAt = this.clock();
    await this.store.put(invitationKey(invitation.id), invitation);
    return invitation;
  }

  /**
   * Live invitations addressed to `requester`. The raw invite code is never
   * disclosed to a non-issuer: only its SHA-256 digest is returned, so the
   * full secret cannot leak through this read path.
   */
  async getPendingInvitations(requester: Fingerprint): Promise<PendingInvitationView[]> {
    assertFingerprint(requester, 'requester');
    const now = this.clock();
    const invitations = await listRecords<InvitationRecord>(this.store, `${K_INVITE}/`);
    return invitations
      .filter(
        (invitation) =>
          invitation.invitees.includes(requester) &&
          !invitation.acceptedBy.includes(requester) &&
          invitation.revokedAt === null &&
          invitation.expiresAt > now
      )
      .map((invitation) => ({
        id: invitation.id,
        roomId: invitation.roomId,
        roomName: invitation.roomName,
        invitedBy: invitation.invitedBy,
        invitees: [...invitation.invitees],
        inviteCodeDigest: sha256Hex(invitation.inviteCode),
        createdAt: invitation.createdAt,
        expiresAt: invitation.expiresAt,
        revokedAt: invitation.revokedAt,
        acceptedBy: [...invitation.acceptedBy],
        signature: invitation.signature
      }));
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Reads — requester is always explicit
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * A room, if `requester` is a member (or it is public).
   *
   * Non-members only ever receive a `RoomPublicView`: member/admin/banned
   * lists, the invitee map and the key salt are stripped, so PUBLIC rooms
   * do not disclose their membership or key material to strangers.
   */
  async getRoom(roomId: string, requester: Fingerprint): Promise<RoomRecord | RoomPublicView | null> {
    assertFingerprint(requester, 'requester');
    const room = await getRecord<RoomRecord>(this.store, roomKey(roomId));
    if (!room) return null;
    if (room.members.includes(requester)) return room;
    if (room.type === 'PUBLIC') return publicRoomView(room);
    return null;
  }

  /** Messages in a room, oldest→newest, decrypted where possible. */
  async getMessages(
    roomId: string,
    requester: Fingerprint,
    query: MessageQuery = {}
  ): Promise<MessageView[]> {
    assertFingerprint(requester, 'requester');
    const room = await this.requireRoom(roomId);
    await this.assertRoomAccess(room, requester, 'read');

    const key = await this.conversationKey(room);
    let entries = await this.allMessages(room.id);
    if (!query.includeDeleted) {
      entries = entries.filter((entry) => entry.message.deletedAt === null);
    }
    if (query.before !== undefined) {
      entries = entries.filter((entry) => entry.message.timestamp < query.before!);
    }

    const offset = query.offset ?? 0;
    const limit = query.limit ?? 50;
    const page = entries.slice(Math.max(0, entries.length - limit - offset), entries.length - offset);

    return page.map((entry) => this.toView(entry.message, this.open(entry.message, key)));
  }

  /** Raw stored message (still encrypted). Members only. */
  async getStoredMessage(
    roomId: string,
    messageId: string,
    requester: Fingerprint
  ): Promise<StoredMessage | null> {
    assertFingerprint(requester, 'requester');
    const room = await this.requireRoom(roomId);
    await this.assertRoomAccess(room, requester, 'read');
    const entries = await this.allMessages(room.id);
    return entries.find((entry) => entry.message.id === messageId)?.message ?? null;
  }

  /** Rooms `requester` belongs to, most recently active first. */
  async listRooms(requester: Fingerprint, type?: RoomType): Promise<RoomSummary[]> {
    assertFingerprint(requester, 'requester');
    const rooms = await listRecords<RoomRecord>(this.store, `${K_ROOM}/`);
    const mine: RoomRecord[] = [];
    for (const room of rooms) {
      if (await this.canAccessRoom(room, requester)) mine.push(room);
    }
    const filtered = type ? mine.filter((room) => room.type === type) : mine;
    filtered.sort((a, b) => (b.lastMessageAt ?? 0) - (a.lastMessageAt ?? 0));

    const out: RoomSummary[] = [];
    for (const room of filtered) {
      out.push({
        id: room.id,
        type: room.type,
        name: room.name,
        description: room.description,
        memberCount: room.members.length,
        createdBy: room.createdBy,
        createdAt: room.createdAt,
        lastMessageAt: room.lastMessageAt,
        messageCount: room.messageCount,
        unreadCount: await this.getUnreadCount(room.id, requester),
        encrypted: (await this.conversationKey(room)) !== null
      });
    }
    return out;
  }

  /**
   * Unread messages for `requester` in one room. The requester must be an
   * eligible member — non-members, banned users, and members who are no
   * longer friends with (or are blocked by) their counterparts are denied.
   */
  async getUnreadCount(roomId: string, requester: Fingerprint): Promise<number> {
    assertFingerprint(requester, 'requester');
    const room = await this.requireRoom(assertRecordId(roomId, 'roomId'));
    await this.assertRoomAccess(room, requester, 'read');
    const entries = await this.allMessages(room.id);
    return entries.filter(
      (entry) =>
        entry.message.from !== requester &&
        entry.message.deletedAt === null &&
        !entry.message.readBy.includes(requester)
    ).length;
  }

  /** Recent messages across every room `requester` belongs to. */
  async getInbox(requester: Fingerprint, limit = 50): Promise<MessageView[]> {
    assertFingerprint(requester, 'requester');
    const rooms = await listRecords<RoomRecord>(this.store, `${K_ROOM}/`);
    const out: MessageView[] = [];
    for (const room of rooms) {
      if (!(await this.canAccessRoom(room, requester))) continue;
      const key = await this.conversationKey(room);
      const entries = await this.allMessages(room.id);
      for (const entry of entries.slice(-limit)) {
        if (entry.message.deletedAt !== null) continue;
        out.push(this.toView(entry.message, this.open(entry.message, key)));
      }
    }
    out.sort((a, b) => b.timestamp - a.timestamp);
    return out.slice(0, limit);
  }

  /**
   * Re-verify that a stored message really was signed by its claimed sender.
   * Possible because the signed bytes are reconstructible: the body is opened
   * with the conversation key and recombined with the retained provenance.
   */
  async verifyMessageAuthorship(
    roomId: string,
    messageId: string,
    requester: Fingerprint
  ): Promise<boolean> {
    const stored = await this.getStoredMessage(roomId, messageId, requester);
    if (!stored) return false;
    if (stored.editedAt !== null || stored.deletedAt !== null) return false;
    const room = await this.requireRoom(roomId);
    const content = this.open(stored, await this.conversationKey(room));
    if (content === null) return false;

    const payload = { ...stored.provenance.payloadRest, content };
    const signed = canonicalActionString(
      stored.provenance.action,
      payload,
      stored.provenance.timestamp,
      stored.provenance.nonce
    );
    try {
      return verifyFromBase64(signed, stored.signature, base64ToBuffer(stored.fromPub));
    } catch {
      return false;
    }
  }

  /** Aggregate counters for `requester`. */
  async getStats(requester: Fingerprint): Promise<{
    rooms: number;
    dms: number;
    groups: number;
    messages: number;
    unread: number;
    pendingInvitations: number;
  }> {
    const rooms = await listRecords<RoomRecord>(this.store, `${K_ROOM}/`);
    const mine: RoomRecord[] = [];
    for (const room of rooms) {
      if (await this.canAccessRoom(room, requester)) mine.push(room);
    }
    let messages = 0;
    let unread = 0;
    for (const room of mine) {
      messages += room.messageCount;
      unread += await this.getUnreadCount(room.id, requester);
    }
    return {
      rooms: mine.length,
      dms: mine.filter((room) => room.type === 'DM').length,
      groups: mine.filter((room) => room.type !== 'DM').length,
      messages,
      unread,
      pendingInvitations: (await this.getPendingInvitations(requester)).length
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Internals
  // ─────────────────────────────────────────────────────────────────────────

  private async verify<P>(envelope: SignedAction<P>, action: string): Promise<VerifiedAction<P>> {
    const verified = await this.verifier.verify(envelope, action);
    assertNoImpersonation(action, verified.payload);
    return verified;
  }

  private async requireRoom(roomId: unknown): Promise<RoomRecord> {
    const id = assertRecordId(roomId, 'roomId');
    const room = await getRecord<RoomRecord>(this.store, roomKey(id));
    if (!room) throw new MessagingError('unknown_room', 'No such room', { roomId: id });
    return room;
  }

  private assertMember(room: RoomRecord, actor: Fingerprint, verb: string): void {
    if (room.banned.includes(actor)) {
      throw new AccessDeniedError('You are banned from this room', { roomId: room.id });
    }
    if (!room.members.includes(actor)) {
      throw new AccessDeniedError(`You must be a member to ${verb} this room`, {
        roomId: room.id
      });
    }
  }

  /**
   * Re-validate a requester's access to a room against the CURRENT social
   * graph, on top of the static membership/ban lists. A member who has
   * since been blocked by another member — or, in a 1:1 room, is no longer
   * friends with their counterpart — loses access immediately, without
   * relying on any cached membership snapshot.
   */
  private async assertRoomAccess(room: RoomRecord, requester: Fingerprint, verb: string): Promise<void> {
    this.assertMember(room, requester, verb);
    if (!(await this.relationAllowsAccess(room, requester))) {
      throw new AccessDeniedError(
        'You are no longer allowed to access this room',
        { roomId: room.id }
      );
    }
  }

  /** Non-throwing variant for listing: rooms the requester cannot use are skipped. */
  private async canAccessRoom(room: RoomRecord, requester: Fingerprint): Promise<boolean> {
    if (room.banned.includes(requester)) return false;
    if (!room.members.includes(requester)) return false;
    return this.relationAllowsAccess(room, requester);
  }

  /**
   * Live social-graph checks. Without a friend graph wired in, only static
   * membership/ban state exists, so access is granted on that basis.
   */
  private async relationAllowsAccess(room: RoomRecord, requester: Fingerprint): Promise<boolean> {
    if (!this.friends) return true;
    const others = room.members.filter((member) => member !== requester);
    for (const other of others) {
      if (await this.isBlockedEitherWay(requester, other)) return false;
    }
    if (room.type === 'DM' && this.requireFriendshipForDM) {
      for (const other of others) {
        if (!(await this.friends.areFriends(requester, other))) return false;
      }
    }
    return true;
  }

  private async conversationKey(room: RoomRecord): Promise<Buffer | null> {
    if (!this.keys) return null;
    const key = await this.keys.getKey(room.id, {
      salt: room.keySalt,
      members: room.members,
      type: room.type
    });
    if (key && key.length !== 32) {
      throw new MessagingError('invalid_key', 'Conversation keys must be exactly 32 bytes');
    }
    return key ?? null;
  }

  /** Decrypt a stored body, or return null when it cannot be opened. */
  private open(message: StoredMessage, key: Buffer | null): string | null {
    if (message.deletedAt !== null) return null;
    if (!message.encrypted) return message.plaintext;
    if (!key || !message.sealed) return null;
    try {
      return decryptAES256GCM(message.sealed, key).toString('utf8');
    } catch {
      return null;
    }
  }

  private toView(message: StoredMessage, content: string | null): MessageView {
    return {
      id: message.id,
      roomId: message.roomId,
      from: message.from,
      type: message.type,
      encrypted: message.encrypted,
      content,
      locked: message.encrypted && content === null && message.deletedAt === null,
      contentHash: message.contentHash,
      replyTo: message.replyTo,
      timestamp: message.timestamp,
      editedAt: message.editedAt,
      deletedAt: message.deletedAt,
      readBy: [...message.readBy],
      signature: message.signature
    };
  }

  private async allMessages(
    roomId: string
  ): Promise<Array<{ key: string; message: StoredMessage }>> {
    const keys = await this.store.list(msgPrefix(roomId));
    const out: Array<{ key: string; message: StoredMessage }> = [];
    for (const key of keys) {
      const message = await getRecord<StoredMessage>(this.store, key);
      if (message) out.push({ key, message });
    }
    return out;
  }

  private async locateMessage(
    roomId: string,
    messageId: unknown
  ): Promise<{ key: string; message: StoredMessage }> {
    const id = assertRecordId(messageId, 'messageId');
    const located = (await this.allMessages(roomId)).find((entry) => entry.message.id === id);
    if (!located) {
      throw new MessagingError('unknown_message', 'No such message', { messageId: id });
    }
    return located;
  }

  private async isBlockedEitherWay(a: Fingerprint, b: Fingerprint): Promise<boolean> {
    if (!this.friends?.isBlocked) return false;
    return (await this.friends.isBlocked(a, b)) || (await this.friends.isBlocked(b, a));
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/** Deterministic, order-independent key for a fingerprint pair. */
export function dmPair(a: Fingerprint, b: Fingerprint): string {
  return [assertFingerprint(a), assertFingerprint(b)].sort().join('-');
}

/** Constant-time invite code comparison over SHA-256 digests. */
function inviteCodeMatches(provided: string, expected: string): boolean {
  const providedDigest = Buffer.from(sha256Hex(provided), 'hex');
  const expectedDigest = Buffer.from(sha256Hex(expected), 'hex');
  if (providedDigest.length !== expectedDigest.length) return false;
  return timingSafeEqual(providedDigest, expectedDigest);
}

/** Strip membership and key material from a room before showing it to strangers. */
function publicRoomView(room: RoomRecord): RoomPublicView {
  return {
    id: room.id,
    type: room.type,
    name: room.name,
    description: room.description,
    createdBy: room.createdBy,
    createdAt: room.createdAt,
    updatedAt: room.updatedAt,
    settings: room.settings,
    lastMessageAt: room.lastMessageAt,
    messageCount: room.messageCount,
    dmPair: room.dmPair
  };
}

/** Sortable message key component: zero-padded timestamp + id. */
function orderToken(timestamp: Timestamp, messageId: string): string {
  return `${String(Math.max(0, Math.trunc(timestamp))).padStart(15, '0')}-${messageId}`;
}

function requireMessageType(value: unknown): MessageType {
  if (typeof value !== 'string' || !(MESSAGE_TYPES as readonly string[]).includes(value)) {
    throw new MessagingError('invalid_type', `Message type must be one of ${MESSAGE_TYPES.join('|')}`);
  }
  return value as MessageType;
}

function clampTtl(ttlMs: unknown): number {
  if (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs <= 0) {
    return DEFAULT_INVITE_TTL_MS;
  }
  return Math.min(Math.trunc(ttlMs), MAX_INVITE_TTL_MS);
}

/**
 * Copy the signed payload minus `content`, so the signed bytes can be rebuilt
 * later without ever storing the plaintext body next to the ciphertext.
 */
function payloadWithoutContent(payload: unknown): Record<string, unknown> {
  if (typeof payload !== 'object' || payload === null) return {};
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
    if (key === 'content') continue;
    out[key] = value;
  }
  return out;
}
