/**
 * FriendGraph — signed friend requests, acceptance, blocking
 *
 * Legacy flaws fixed here:
 *   - `receiveRequest()` accepted arbitrary unauthenticated objects off the
 *     wire, so anyone could inject a request "from" anyone. Every mutation here
 *     requires a verified `SignedAction`, and the requester/responder is the
 *     envelope's verified author.
 *   - `handleRequestAccepted()` FABRICATED a `Friend` whenever the request id
 *     was unknown, which let an attacker poison a victim's friend list and
 *     thereby unlock all FRIENDS-visibility content. Here an unknown request id
 *     is a hard error (`unknown_request`), and the acceptance must be signed by
 *     the exact fingerprint the request was addressed to.
 *   - Request ids were random and client-visible; they are now derived from the
 *     request signature, so an attacker cannot choose or guess one.
 */

import { sha256Hex } from '../common/crypto';
import type { SignedAction, ActionVerifier, VerifiedAction } from './SignedAction';
import { assertNoImpersonation } from './SignedAction';
import type { SocialStore } from './SocialStore';
import { getRecord, listRecords, storeKey } from './SocialStore';
import {
  AccessDeniedError,
  Base64,
  Fingerprint,
  FriendshipOracle,
  SocialError,
  Timestamp,
  assertFingerprint,
  assertRecordId,
  assertText,
  systemClock,
  type SocialClock
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// ACTIONS
// ═══════════════════════════════════════════════════════════════════════════

export const FRIEND_ACTIONS = {
  request: 'friend.request',
  accept: 'friend.accept',
  reject: 'friend.reject',
  cancel: 'friend.cancel',
  remove: 'friend.remove',
  block: 'friend.block',
  unblock: 'friend.unblock',
  annotate: 'friend.annotate'
} as const;

export interface FriendRequestPayload {
  /** Fingerprint the request is addressed to. */
  to: Fingerprint;
  message?: string;
}

export interface RequestIdPayload {
  requestId: string;
}

export interface TargetPayload {
  target: Fingerprint;
}

export interface AnnotatePayload {
  target: Fingerprint;
  nickname?: string | null;
  notes?: string;
  favorite?: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════
// RECORDS
// ═══════════════════════════════════════════════════════════════════════════

export type FriendRequestStatus = 'pending' | 'accepted' | 'rejected' | 'cancelled';

export type RelationshipStatus =
  | 'self'
  | 'none'
  | 'pending_sent'
  | 'pending_received'
  | 'friends'
  | 'blocked';

/** A friend request, always backed by the signature that created it. */
export interface FriendRequestRecord {
  id: string;
  from: Fingerprint;
  fromPub: Base64;
  to: Fingerprint;
  message: string;
  status: FriendRequestStatus;
  createdAt: Timestamp;
  respondedAt: Timestamp | null;
  /** Signature of the `friend.request` envelope. */
  requestSignature: Base64;
  /** Signature of the `friend.accept` envelope, once accepted. */
  acceptanceSignature: Base64 | null;
  acceptancePub: Base64 | null;
}

/** One direction of a confirmed friendship. */
export interface FriendEdge {
  owner: Fingerprint;
  peer: Fingerprint;
  peerPub: Base64 | null;
  requestId: string;
  addedAt: Timestamp;
  lastSeen: Timestamp | null;
  nickname: string | null;
  notes: string;
  favorite: boolean;
}

export interface BlockRecord {
  owner: Fingerprint;
  target: Fingerprint;
  blockedAt: Timestamp;
}

export interface FriendStats {
  friends: number;
  favorites: number;
  pendingIncoming: number;
  pendingOutgoing: number;
  blocked: number;
}

export class FriendGraphError extends SocialError {}

// ═══════════════════════════════════════════════════════════════════════════
// KEYS
// ═══════════════════════════════════════════════════════════════════════════

const K_REQUEST = 'friendreq';
const K_EDGE = 'friend';
const K_BLOCK = 'friendblock';

const requestKey = (id: string): string => storeKey(K_REQUEST, assertRecordId(id, 'requestId'));
const edgeKey = (owner: Fingerprint, peer: Fingerprint): string =>
  storeKey(K_EDGE, assertFingerprint(owner, 'owner'), assertFingerprint(peer, 'peer'));
const edgePrefix = (owner: Fingerprint): string =>
  `${K_EDGE}/${assertFingerprint(owner, 'owner')}/`;
const blockKey = (owner: Fingerprint, target: Fingerprint): string =>
  storeKey(K_BLOCK, assertFingerprint(owner, 'owner'), assertFingerprint(target, 'target'));
const blockPrefix = (owner: Fingerprint): string =>
  `${K_BLOCK}/${assertFingerprint(owner, 'owner')}/`;

/**
 * Deterministic request id derived from the request signature. Callers cannot
 * choose it, and the same signed request always maps to the same id.
 */
export function deriveRequestId(signature: Base64): string {
  return `req_${sha256Hex(`friend.request|${signature}`).slice(0, 32)}`;
}

// ═══════════════════════════════════════════════════════════════════════════
// FRIEND GRAPH
// ═══════════════════════════════════════════════════════════════════════════

export interface FriendGraphOptions {
  store: SocialStore;
  verifier: ActionVerifier;
  clock?: SocialClock;
  /** Max message length on a friend request. */
  maxMessageLength?: number;
}

/**
 * The friend graph for a whole node. Edges are keyed by fingerprint pairs, so a
 * single store can host several local identities.
 */
export class FriendGraph implements FriendshipOracle {
  private readonly store: SocialStore;
  private readonly verifier: ActionVerifier;
  private readonly clock: SocialClock;
  private readonly maxMessageLength: number;

  constructor(options: FriendGraphOptions) {
    this.store = options.store;
    this.verifier = options.verifier;
    this.clock = options.clock ?? systemClock;
    this.maxMessageLength = options.maxMessageLength ?? 500;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Mutations (all require a verified envelope)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Submit a friend request. The sender is the envelope author — the payload
   * only names the recipient.
   */
  async sendRequest(envelope: SignedAction<FriendRequestPayload>): Promise<FriendRequestRecord> {
    const verified = await this.verify(envelope, FRIEND_ACTIONS.request);
    const from = verified.author.fingerprint;
    const to = assertFingerprint(verified.payload?.to, 'to');
    const message = verified.payload?.message
      ? assertText(verified.payload.message, 'message', this.maxMessageLength, { allowEmpty: true })
      : '';

    if (from === to) {
      throw new FriendGraphError('invalid_target', 'Cannot send a friend request to yourself');
    }
    if (await this.areFriends(from, to)) {
      throw new FriendGraphError('already_friends', 'Already friends');
    }
    if (await this.isBlocked(to, from)) {
      // Fail closed but do not disclose the block.
      throw new AccessDeniedError('Friend request could not be delivered');
    }
    if (await this.isBlocked(from, to)) {
      throw new FriendGraphError('target_blocked', 'Unblock this user before sending a request');
    }

    const existing = await this.findPending(from, to);
    if (existing) {
      throw new FriendGraphError('request_pending', 'A pending request already exists', {
        requestId: existing.id
      });
    }

    const record: FriendRequestRecord = {
      id: deriveRequestId(verified.signature),
      from,
      fromPub: verified.author.pub,
      to,
      message,
      status: 'pending',
      createdAt: verified.timestamp,
      respondedAt: null,
      requestSignature: verified.signature,
      acceptanceSignature: null,
      acceptancePub: null
    };

    await this.store.put(requestKey(record.id), record);
    return record;
  }

  /**
   * Accept a friend request.
   *
   * Requires: (1) a verified envelope, (2) a request that actually EXISTS, and
   * (3) an author equal to the request's recipient. An unknown request id is
   * rejected — it never fabricates a friendship.
   */
  async acceptRequest(envelope: SignedAction<RequestIdPayload>): Promise<FriendEdge[]> {
    const verified = await this.verify(envelope, FRIEND_ACTIONS.accept);
    const requestId = assertRecordId(verified.payload?.requestId, 'requestId');
    const request = await getRecord<FriendRequestRecord>(this.store, requestKey(requestId));

    if (!request) {
      throw new FriendGraphError(
        'unknown_request',
        'No such friend request: refusing to create a friendship',
        { requestId }
      );
    }
    if (request.to !== verified.author.fingerprint) {
      throw new AccessDeniedError('Only the addressee may accept this friend request', {
        requestId
      });
    }
    if (request.status !== 'pending') {
      throw new FriendGraphError('request_closed', `Request already ${request.status}`, {
        requestId
      });
    }
    if (await this.isBlocked(request.to, request.from)) {
      throw new FriendGraphError('target_blocked', 'Unblock this user before accepting');
    }

    const now = this.clock();
    request.status = 'accepted';
    request.respondedAt = now;
    request.acceptanceSignature = verified.signature;
    request.acceptancePub = verified.author.pub;
    await this.store.put(requestKey(request.id), request);

    // Both directions are recorded, because acceptance is cryptographically
    // proven by the signature we just verified.
    const edges: FriendEdge[] = [
      makeEdge(request.from, request.to, verified.author.pub, request.id, now),
      makeEdge(request.to, request.from, request.fromPub, request.id, now)
    ];
    for (const edge of edges) {
      await this.store.put(edgeKey(edge.owner, edge.peer), edge);
    }
    return edges;
  }

  /** Reject a pending request. Only the addressee may reject. */
  async rejectRequest(envelope: SignedAction<RequestIdPayload>): Promise<FriendRequestRecord> {
    const verified = await this.verify(envelope, FRIEND_ACTIONS.reject);
    const request = await this.requirePending(verified.payload?.requestId);
    if (request.to !== verified.author.fingerprint) {
      throw new AccessDeniedError('Only the addressee may reject this friend request');
    }
    request.status = 'rejected';
    request.respondedAt = this.clock();
    await this.store.put(requestKey(request.id), request);
    return request;
  }

  /** Cancel a pending request. Only the sender may cancel. */
  async cancelRequest(envelope: SignedAction<RequestIdPayload>): Promise<FriendRequestRecord> {
    const verified = await this.verify(envelope, FRIEND_ACTIONS.cancel);
    const request = await this.requirePending(verified.payload?.requestId);
    if (request.from !== verified.author.fingerprint) {
      throw new AccessDeniedError('Only the sender may cancel this friend request');
    }
    request.status = 'cancelled';
    request.respondedAt = this.clock();
    await this.store.put(requestKey(request.id), request);
    return request;
  }

  /** Remove a friend. Drops both directions of the edge. */
  async removeFriend(envelope: SignedAction<TargetPayload>): Promise<boolean> {
    const verified = await this.verify(envelope, FRIEND_ACTIONS.remove);
    const owner = verified.author.fingerprint;
    const target = assertFingerprint(verified.payload?.target, 'target');
    const existed = (await getRecord<FriendEdge>(this.store, edgeKey(owner, target))) !== null;
    await this.store.del(edgeKey(owner, target));
    await this.store.del(edgeKey(target, owner));
    return existed;
  }

  /** Block a fingerprint: removes friendship and closes pending requests. */
  async block(envelope: SignedAction<TargetPayload>): Promise<BlockRecord> {
    const verified = await this.verify(envelope, FRIEND_ACTIONS.block);
    const owner = verified.author.fingerprint;
    const target = assertFingerprint(verified.payload?.target, 'target');
    if (owner === target) {
      throw new FriendGraphError('invalid_target', 'Cannot block yourself');
    }

    await this.store.del(edgeKey(owner, target));
    await this.store.del(edgeKey(target, owner));

    for (const request of await this.allRequests()) {
      if (request.status !== 'pending') continue;
      const involved =
        (request.from === owner && request.to === target) ||
        (request.from === target && request.to === owner);
      if (!involved) continue;
      request.status = request.from === owner ? 'cancelled' : 'rejected';
      request.respondedAt = this.clock();
      await this.store.put(requestKey(request.id), request);
    }

    const record: BlockRecord = { owner, target, blockedAt: this.clock() };
    await this.store.put(blockKey(owner, target), record);
    return record;
  }

  /** Unblock a fingerprint. */
  async unblock(envelope: SignedAction<TargetPayload>): Promise<boolean> {
    const verified = await this.verify(envelope, FRIEND_ACTIONS.unblock);
    const owner = verified.author.fingerprint;
    const target = assertFingerprint(verified.payload?.target, 'target');
    const existed = (await getRecord<BlockRecord>(this.store, blockKey(owner, target))) !== null;
    await this.store.del(blockKey(owner, target));
    return existed;
  }

  /** Set local-only annotations (nickname, notes, favorite) on a friend. */
  async annotateFriend(envelope: SignedAction<AnnotatePayload>): Promise<FriendEdge> {
    const verified = await this.verify(envelope, FRIEND_ACTIONS.annotate);
    const owner = verified.author.fingerprint;
    const target = assertFingerprint(verified.payload?.target, 'target');
    const edge = await getRecord<FriendEdge>(this.store, edgeKey(owner, target));
    if (!edge) {
      throw new FriendGraphError('not_friends', 'Not a friend');
    }
    const payload = verified.payload;
    if (payload.nickname !== undefined) {
      edge.nickname =
        payload.nickname === null ? null : assertText(payload.nickname, 'nickname', 64);
    }
    if (payload.notes !== undefined) {
      edge.notes = assertText(payload.notes, 'notes', 2000, { allowEmpty: true });
    }
    if (payload.favorite !== undefined) {
      edge.favorite = Boolean(payload.favorite);
    }
    await this.store.put(edgeKey(owner, target), edge);
    return edge;
  }

  /** Record that a peer was seen (presence bookkeeping, not security bearing). */
  async touchFriend(owner: Fingerprint, peer: Fingerprint): Promise<void> {
    const edge = await getRecord<FriendEdge>(this.store, edgeKey(owner, peer));
    if (!edge) return;
    edge.lastSeen = this.clock();
    await this.store.put(edgeKey(owner, peer), edge);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Reads
  // ─────────────────────────────────────────────────────────────────────────

  /** Confirmed friendship check (FriendshipOracle). */
  async areFriends(a: Fingerprint, b: Fingerprint): Promise<boolean> {
    if (a === b) return false;
    const edge = await getRecord<FriendEdge>(this.store, edgeKey(a, b));
    return edge !== null;
  }

  /** Whether `owner` has blocked `target`. */
  async isBlocked(owner: Fingerprint, target: Fingerprint): Promise<boolean> {
    return (await getRecord<BlockRecord>(this.store, blockKey(owner, target))) !== null;
  }

  /** Friend edges owned by `owner`. */
  async listFriends(
    owner: Fingerprint,
    options: { favoritesFirst?: boolean; recentFirst?: boolean } = {}
  ): Promise<FriendEdge[]> {
    const edges = await listRecords<FriendEdge>(this.store, edgePrefix(owner));
    if (options.recentFirst) {
      edges.sort((a, b) => (b.lastSeen ?? 0) - (a.lastSeen ?? 0));
    }
    if (options.favoritesFirst) {
      edges.sort((a, b) => Number(b.favorite) - Number(a.favorite));
    }
    return edges;
  }

  /** Set of `owner`'s friends, for access-control checks. */
  async getFriendFingerprints(owner: Fingerprint): Promise<Set<Fingerprint>> {
    const edges = await this.listFriends(owner);
    return new Set(edges.map((edge) => edge.peer));
  }

  /** One friend edge, or null. */
  async getFriend(owner: Fingerprint, peer: Fingerprint): Promise<FriendEdge | null> {
    return getRecord<FriendEdge>(this.store, edgeKey(owner, peer));
  }

  /** A single request by id. */
  async getRequest(requestId: string): Promise<FriendRequestRecord | null> {
    return getRecord<FriendRequestRecord>(this.store, requestKey(requestId));
  }

  /** Pending requests addressed to `owner`. */
  async getIncomingRequests(owner: Fingerprint): Promise<FriendRequestRecord[]> {
    const all = await this.allRequests();
    return all.filter((r) => r.to === owner && r.status === 'pending');
  }

  /** Pending requests sent by `owner`. */
  async getOutgoingRequests(owner: Fingerprint): Promise<FriendRequestRecord[]> {
    const all = await this.allRequests();
    return all.filter((r) => r.from === owner && r.status === 'pending');
  }

  /** Fingerprints `owner` has blocked. */
  async getBlocked(owner: Fingerprint): Promise<Fingerprint[]> {
    const records = await listRecords<BlockRecord>(this.store, blockPrefix(owner));
    return records.map((r) => r.target);
  }

  /** Relationship of `owner` towards `other`. */
  async getRelationship(owner: Fingerprint, other: Fingerprint): Promise<RelationshipStatus> {
    if (owner === other) return 'self';
    if (await this.isBlocked(owner, other)) return 'blocked';
    if (await this.areFriends(owner, other)) return 'friends';
    const all = await this.allRequests();
    for (const request of all) {
      if (request.status !== 'pending') continue;
      if (request.from === owner && request.to === other) return 'pending_sent';
      if (request.from === other && request.to === owner) return 'pending_received';
    }
    return 'none';
  }

  /** Counters for `owner`. */
  async getStats(owner: Fingerprint): Promise<FriendStats> {
    const [friends, incoming, outgoing, blocked] = await Promise.all([
      this.listFriends(owner),
      this.getIncomingRequests(owner),
      this.getOutgoingRequests(owner),
      this.getBlocked(owner)
    ]);
    return {
      friends: friends.length,
      favorites: friends.filter((f) => f.favorite).length,
      pendingIncoming: incoming.length,
      pendingOutgoing: outgoing.length,
      blocked: blocked.length
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Internals
  // ─────────────────────────────────────────────────────────────────────────

  private async verify<P>(
    envelope: SignedAction<P>,
    action: string
  ): Promise<VerifiedAction<P>> {
    const verified = await this.verifier.verify(envelope, action);
    assertNoImpersonation(action, verified.payload);
    return verified;
  }

  private async allRequests(): Promise<FriendRequestRecord[]> {
    return listRecords<FriendRequestRecord>(this.store, `${K_REQUEST}/`);
  }

  private async requirePending(requestId: unknown): Promise<FriendRequestRecord> {
    const id = assertRecordId(requestId, 'requestId');
    const request = await getRecord<FriendRequestRecord>(this.store, requestKey(id));
    if (!request) {
      throw new FriendGraphError('unknown_request', 'No such friend request', { requestId: id });
    }
    if (request.status !== 'pending') {
      throw new FriendGraphError('request_closed', `Request already ${request.status}`);
    }
    return request;
  }

  private async findPending(
    from: Fingerprint,
    to: Fingerprint
  ): Promise<FriendRequestRecord | null> {
    const all = await this.allRequests();
    return (
      all.find(
        (r) =>
          r.status === 'pending' &&
          ((r.from === from && r.to === to) || (r.from === to && r.to === from))
      ) ?? null
    );
  }
}

function makeEdge(
  owner: Fingerprint,
  peer: Fingerprint,
  peerPub: Base64 | null,
  requestId: string,
  now: Timestamp
): FriendEdge {
  return {
    owner,
    peer,
    peerPub,
    requestId,
    addedAt: now,
    lastSeen: null,
    nickname: null,
    notes: '',
    favorite: false
  };
}
