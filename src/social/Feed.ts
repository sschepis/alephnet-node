/**
 * Feed — aggregation across groups and direct messages, with unread tracking
 *
 * The legacy `FeedManager` trusted the group manager's own ambient node id for
 * membership filtering and treated every message as a feed item with the
 * reader implicitly the local node. Here the requester is explicit on every
 * call, and both sources already enforce their own access control.
 *
 * Unread state is per-requester, per-source: a read marker timestamp is kept
 * in the store, and an item is unread when it is newer than that marker and
 * was not authored by the requester.
 */

import type { GroupPostRecord, Groups } from './Groups';
import type { DirectMessages, MessageView } from './DirectMessages';
import type { ActionVerifier, SignedAction } from './SignedAction';
import { assertNoImpersonation } from './SignedAction';
import type { SocialStore } from './SocialStore';
import { getRecord, storeKey } from './SocialStore';
import {
  Fingerprint,
  PageOptions,
  SocialError,
  Timestamp,
  assertFingerprint,
  systemClock,
  type SocialClock
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export const FEED_ACTIONS = {
  markRead: 'feed.mark.read'
} as const;

export type FeedItemType = 'group_post' | 'message';

export interface FeedSource {
  id: string;
  name: string | null;
  kind: 'group' | 'conversation';
}

/** Signed payload for `feed.mark.read`. The requester is the verified author. */
export interface MarkReadFeedPayload {
  source: FeedSource;
  upTo?: Timestamp;
}

export interface FeedItem {
  id: string;
  type: FeedItemType;
  timestamp: Timestamp;
  authorFingerprint: Fingerprint;
  source: FeedSource;
  /** Content preview or message view. */
  content: string | MessageView | GroupPostRecord;
  unread: boolean;
}

export interface FeedSourceUnread {
  source: FeedSource;
  unread: number;
  lastItemAt: Timestamp | null;
}

export interface FeedUnreadSummary {
  totalUnread: number;
  bySource: FeedSourceUnread[];
}

export interface ReadMarker {
  requester: Fingerprint;
  source: string;
  lastReadAt: Timestamp;
  updatedAt: Timestamp;
}

export class FeedError extends SocialError {}

export interface FeedOptions {
  store: SocialStore;
  groups?: Groups;
  messages?: DirectMessages;
  /** Required for `markRead`, which is a signed mutation. */
  verifier?: ActionVerifier;
  clock?: SocialClock;
  /** Sources the requester follows; default `['groups', 'messages']`. */
  sources?: ('groups' | 'messages')[];
  /** Only include posts/messages authored by friends of the requester. */
  friends?: { areFriends(a: Fingerprint, b: Fingerprint): Promise<boolean> };
}

// ═══════════════════════════════════════════════════════════════════════════
// KEYS
// ═══════════════════════════════════════════════════════════════════════════

const K_READ = 'feedread';
const markerKey = (requester: Fingerprint, source: string): string =>
  storeKey(K_READ, assertFingerprint(requester, 'requester'), source);

/** Compact source identifiers stored in read markers. */
export function feedSourceId(source: FeedSource): string {
  return `${source.kind}.${source.id}`;
}

/** Validate an untrusted `source` from a signed payload into a FeedSource. */
function normalizeFeedSource(source: unknown): FeedSource {
  if (typeof source !== 'object' || source === null || Array.isArray(source)) {
    throw new FeedError('invalid_source', 'markRead payload requires a source');
  }
  const record = source as Record<string, unknown>;
  const kind = record.kind;
  if (kind !== 'group' && kind !== 'conversation') {
    throw new FeedError('invalid_source', 'source.kind must be "group" or "conversation"');
  }
  const id = typeof record.id === 'string' ? record.id.trim() : '';
  if (id.length === 0 || id.length > 256) {
    throw new FeedError('invalid_source', 'source.id must be a non-empty string');
  }
  const name =
    typeof record.name === 'string' && record.name.length > 0 && record.name.length <= 256
      ? record.name
      : null;
  return { id, name, kind };
}

// ═══════════════════════════════════════════════════════════════════════════
// FEED MANAGER
// ═══════════════════════════════════════════════════════════════════════════

export class FeedManager {
  private readonly store: SocialStore;
  private readonly groups?: Groups;
  private readonly messages?: DirectMessages;
  private readonly verifier?: ActionVerifier;
  private readonly clock: SocialClock;
  private readonly sources: ('groups' | 'messages')[];
  private readonly friends?: FeedOptions['friends'];

  constructor(options: FeedOptions) {
    this.store = options.store;
    this.groups = options.groups;
    this.messages = options.messages;
    this.verifier = options.verifier;
    this.clock = options.clock ?? systemClock;
    this.sources = options.sources ?? ['groups', 'messages'];
    this.friends = options.friends;
  }

  /**
   * Unified feed for `requester`: posts from groups they may read plus recent
   * messages from their conversations, newest first.
   */
  async getFeed(requester: Fingerprint, options: PageOptions = {}): Promise<FeedItem[]> {
    assertFingerprint(requester, 'requester');
    const items: FeedItem[] = [];

    if (this.sources.includes('groups') && this.groups) {
      for (const post of await this.groups.getAllPosts(requester, { limit: 200 })) {
        if (this.friends && !(await this.friends.areFriends(post.authorFingerprint, requester))) {
          continue;
        }
        const group = await this.groups.getGroup(post.groupId, requester);
        if (!group) continue;
        items.push({
          id: `feed_${post.id}`,
          type: 'group_post',
          timestamp: post.timestamp,
          authorFingerprint: post.authorFingerprint,
          source: { id: group.id, name: group.name, kind: 'group' },
          content: post,
          unread: false
        });
      }
    }

    if (this.sources.includes('messages') && this.messages) {
      for (const message of await this.messages.getInbox(requester, 200)) {
        items.push({
          id: `feed_${message.id}`,
          type: 'message',
          timestamp: message.timestamp,
          authorFingerprint: message.from,
          source: { id: message.roomId, name: null, kind: 'conversation' },
          content: message,
          unread: false
        });
      }
    }

    items.sort((a, b) => b.timestamp - a.timestamp);

    await this.decorateUnread(requester, items);

    const offset = options.offset ?? 0;
    const limit = options.limit ?? 50;
    return items.slice(offset, offset + limit);
  }

  /**
   * Mark a source as read by the VERIFIED envelope author, up to a timestamp
   * (default: now). After this, items at or before that time are no longer
   * unread for that requester.
   *
   * `markRead` is a mutation and therefore requires a signed
   * `feed.mark.read` envelope; the requester is derived from the signature,
   * never from a caller-supplied fingerprint.
   */
  async markRead(envelope: SignedAction<MarkReadFeedPayload>): Promise<ReadMarker> {
    if (!this.verifier) {
      throw new FeedError(
        'verifier_required',
        'FeedManager.markRead requires an ActionVerifier; pass one via FeedOptions'
      );
    }
    const verified = await this.verifier.verify(envelope, FEED_ACTIONS.markRead);
    assertNoImpersonation(FEED_ACTIONS.markRead, verified.payload);
    const requester = verified.author.fingerprint;
    const source = normalizeFeedSource(verified.payload?.source);
    const rawUpTo = verified.payload?.upTo;
    const upTo =
      typeof rawUpTo === 'number' && Number.isFinite(rawUpTo) && rawUpTo > 0
        ? rawUpTo
        : this.clock();
    const existing = await getRecord<ReadMarker>(
      this.store,
      markerKey(requester, feedSourceId(source))
    );
    const marker: ReadMarker = {
      requester,
      source: feedSourceId(source),
      lastReadAt: Math.max(existing?.lastReadAt ?? 0, upTo),
      updatedAt: this.clock()
    };
    await this.store.put(markerKey(requester, marker.source), marker);
    return marker;
  }

  /** Unread counts per source, plus a total. */
  async getUnreadSummary(requester: Fingerprint): Promise<FeedUnreadSummary> {
    assertFingerprint(requester, 'requester');
    const items = await this.getFeed(requester, { limit: 1000 });
    const bySource = new Map<string, FeedSourceUnread>();
    let total = 0;
    for (const item of items) {
      if (!item.unread) continue;
      total += 1;
      const key = feedSourceId(item.source);
      const entry = bySource.get(key) ?? {
        source: item.source,
        unread: 0,
        lastItemAt: null as Timestamp | null
      };
      entry.unread += 1;
      if (entry.lastItemAt === null || item.timestamp > entry.lastItemAt) {
        entry.lastItemAt = item.timestamp;
      }
      bySource.set(key, entry);
    }
    return { totalUnread: total, bySource: [...bySource.values()] };
  }

  /** Current read marker for one source. */
  async getReadMarker(requester: Fingerprint, source: FeedSource): Promise<ReadMarker | null> {
    return getRecord<ReadMarker>(this.store, markerKey(requester, feedSourceId(source)));
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Internals
  // ─────────────────────────────────────────────────────────────────────────

  private async decorateUnread(requester: Fingerprint, items: FeedItem[]): Promise<void> {
    const markers = new Map<string, Timestamp>();
    for (const item of items) {
      const key = feedSourceId(item.source);
      let lastRead = markers.get(key);
      if (lastRead === undefined) {
        const marker = await getRecord<ReadMarker>(this.store, markerKey(requester, key));
        lastRead = marker?.lastReadAt ?? 0;
        markers.set(key, lastRead);
      }
      item.unread =
        item.authorFingerprint !== requester && item.timestamp > lastRead;
    }
  }
}
