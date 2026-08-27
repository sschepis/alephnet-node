/**
 * Profiles — profile CRUD, link lists, and visibility-aware reads
 *
 * Legacy flaws fixed here:
 *   - `ProfileManager.getProfile()` for anyone other than the local node was a
 *     stub that always returned `null`, so remote profiles simply did not work.
 *     It is implemented: profiles are read from the shared store and, failing
 *     that, from a TTL cache of profiles fetched from the network.
 *   - Profile updates were unauthenticated local mutations. Every mutation now
 *     requires a `SignedAction`; the profile edited is always the envelope
 *     author's own.
 *   - Reads defaulted the requester to the owner, which meant `friends`/
 *     `private` visibility was never actually enforced. The requester
 *     fingerprint is now a REQUIRED argument on every read.
 */

import { sha256Hex } from '../common/crypto';
import type { ActionVerifier, SignedAction, VerifiedAction } from './SignedAction';
import { assertNoImpersonation } from './SignedAction';
import type { SocialStore } from './SocialStore';
import { getRecord, listRecords, storeKey } from './SocialStore';
import {
  Base64,
  ContentHash,
  Fingerprint,
  FriendshipOracle,
  SocialError,
  Timestamp,
  Visibility,
  assertContentHash,
  assertFingerprint,
  assertRecordId,
  assertText,
  isVisibility,
  normalizeVisibility,
  systemClock,
  type SocialClock
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// ACTIONS
// ═══════════════════════════════════════════════════════════════════════════

export const PROFILE_ACTIONS = {
  update: 'profile.update',
  addLink: 'profile.link.add',
  updateLink: 'profile.link.update',
  removeLink: 'profile.link.remove',
  reorderLinks: 'profile.link.reorder'
} as const;

export interface ProfileContact {
  email?: string | null;
  website?: string | null;
  twitter?: string | null;
  github?: string | null;
  [key: string]: string | null | undefined;
}

export interface ProfileUpdatePayload {
  displayName?: string;
  bio?: string;
  avatarHash?: ContentHash | null;
  coverHash?: ContentHash | null;
  theme?: string;
  visibility?: Visibility;
  contact?: ProfileContact;
  contactVisibility?: Visibility;
}

export type ProfileLinkType = 'url' | 'content' | 'profile' | 'custom';

export interface AddLinkPayload {
  type?: ProfileLinkType;
  url?: string;
  contentHash?: ContentHash;
  targetFingerprint?: Fingerprint;
  title: string;
  description?: string;
  icon?: string;
  visibility?: Visibility;
}

export interface UpdateLinkPayload {
  linkId: string;
  url?: string;
  title?: string;
  description?: string;
  icon?: string;
  order?: number;
  visibility?: Visibility;
}

export interface RemoveLinkPayload {
  linkId: string;
}

export interface ReorderLinksPayload {
  linkIds: string[];
}

// ═══════════════════════════════════════════════════════════════════════════
// RECORDS
// ═══════════════════════════════════════════════════════════════════════════

export interface ProfileLinkRecord {
  id: string;
  type: ProfileLinkType;
  url: string | null;
  contentHash: ContentHash | null;
  targetFingerprint: Fingerprint | null;
  title: string;
  description: string;
  icon: string | null;
  order: number;
  visibility: Visibility;
  createdAt: Timestamp;
  clicks: number;
}

export interface ProfileRecord {
  fingerprint: Fingerprint;
  /** Public key bound to the fingerprint by the signature that created it. */
  pub: Base64;
  displayName: string;
  bio: string;
  avatarHash: ContentHash | null;
  coverHash: ContentHash | null;
  theme: string;
  visibility: Visibility;
  contact: ProfileContact;
  contactVisibility: Visibility;
  links: ProfileLinkRecord[];
  views: number;
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

/** What a requester is allowed to see. */
export interface ProfileView {
  fingerprint: Fingerprint;
  restricted: boolean;
  visibility: Visibility;
  displayName?: string;
  bio?: string;
  avatarHash?: ContentHash | null;
  coverHash?: ContentHash | null;
  theme?: string;
  pub?: Base64;
  links?: ProfileLinkView[];
  contact?: ProfileContact;
  createdAt?: Timestamp;
  updatedAt?: Timestamp;
  stats?: { views: number; linkCount: number };
}

export interface ProfileLinkView extends Omit<ProfileLinkRecord, 'url'> {
  url: string | null;
}

export class ProfileError extends SocialError {}

// ═══════════════════════════════════════════════════════════════════════════
// KEYS & LIMITS
// ═══════════════════════════════════════════════════════════════════════════

const K_PROFILE = 'profile';
const profileKey = (fingerprint: Fingerprint): string =>
  storeKey(K_PROFILE, assertFingerprint(fingerprint));

export const PROFILE_LIMITS = {
  displayName: 64,
  bio: 2000,
  theme: 32,
  linkTitle: 120,
  linkDescription: 500,
  linkUrl: 2048,
  contactValue: 200,
  maxLinks: 100
} as const;

// ═══════════════════════════════════════════════════════════════════════════
// REMOTE PROFILE CACHE
// ═══════════════════════════════════════════════════════════════════════════

interface CacheEntry {
  view: ProfileView;
  fetchedAt: Timestamp;
  ttl: number;
}

/**
 * TTL + LRU-ish cache of profiles fetched from the network.
 *
 * Entries are keyed by `${target}:${requester}` — a view built for one
 * requester (e.g. a FRIENDS view served to a confirmed friend) is never
 * served to another. Views with no requester are only accepted when they are
 * safe for EVERYONE (PUBLIC and unrestricted) and are stored under the
 * `*` wildcard requester.
 */
export class ProfileCache {
  private readonly entries = new Map<string, CacheEntry>();

  constructor(
    private readonly defaultTTL = 5 * 60 * 1000,
    private readonly maxSize = 1000,
    private readonly clock: SocialClock = systemClock
  ) {}

  private static entryKey(target: Fingerprint, requester: Fingerprint | '*'): string {
    return `${target}:${requester}`;
  }

  get(fingerprint: Fingerprint, requester: Fingerprint): ProfileView | null {
    const target = assertFingerprint(fingerprint, 'fingerprint');
    const requesterKey = assertFingerprint(requester, 'requester');
    const exactKey = ProfileCache.entryKey(target, requesterKey);
    const wildcardKey = ProfileCache.entryKey(target, '*');
    const entry = this.entries.get(exactKey) ?? this.entries.get(wildcardKey) ?? null;
    if (!entry) return null;
    if (this.clock() - entry.fetchedAt > entry.ttl) {
      const hitKey = this.entries.has(exactKey) ? exactKey : wildcardKey;
      this.entries.delete(hitKey);
      return null;
    }
    return entry.view;
  }

  /**
   * Store a view. Pass an explicit `requester` for requester-scoped views;
   * pass `'*'` only for views that are safe for anyone (PUBLIC and
   * unrestricted) — callers should use `Profiles.cacheRemoteProfile`, which
   * enforces that.
   */
  set(fingerprint: Fingerprint, requester: Fingerprint | '*', view: ProfileView, ttl?: number): void {
    const target = assertFingerprint(fingerprint, 'fingerprint');
    const requesterKey = requester === '*' ? '*' : assertFingerprint(requester, 'requester');
    if (this.entries.size >= this.maxSize) {
      let oldestKey: string | null = null;
      let oldest = Number.POSITIVE_INFINITY;
      for (const [key, entry] of this.entries) {
        if (entry.fetchedAt < oldest) {
          oldest = entry.fetchedAt;
          oldestKey = key;
        }
      }
      if (oldestKey) this.entries.delete(oldestKey);
    }
    this.entries.set(ProfileCache.entryKey(target, requesterKey), {
      view,
      fetchedAt: this.clock(),
      ttl: ttl ?? this.defaultTTL
    });
  }

  /** Drop every cached view for `fingerprint`, for every requester. */
  invalidate(fingerprint: Fingerprint): void {
    const prefix = `${assertFingerprint(fingerprint, 'fingerprint')}:`;
    for (const key of this.entries.keys()) {
      if (key.startsWith(prefix)) this.entries.delete(key);
    }
  }

  /** Drop the cached view of `fingerprint` built for one requester. */
  invalidateFor(fingerprint: Fingerprint, requester: Fingerprint): void {
    this.entries.delete(
      ProfileCache.entryKey(
        assertFingerprint(fingerprint, 'fingerprint'),
        assertFingerprint(requester, 'requester')
      )
    );
  }

  clear(): void {
    this.entries.clear();
  }

  get size(): number {
    return this.entries.size;
  }

  /** All cached views visible to `requester` (exact matches plus wildcard). */
  values(requester: Fingerprint): ProfileView[] {
    const target = assertFingerprint(requester, 'requester');
    const now = this.clock();
    const out: ProfileView[] = [];
    for (const [key, entry] of this.entries) {
      if (now - entry.fetchedAt > entry.ttl) {
        this.entries.delete(key);
        continue;
      }
      const colon = key.lastIndexOf(':');
      const entryRequester = key.slice(colon + 1);
      if (entryRequester !== '*' && entryRequester !== target) continue;
      out.push(entry.view);
    }
    return out;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// PROFILE MANAGER
// ═══════════════════════════════════════════════════════════════════════════

export interface ProfilesOptions {
  store: SocialStore;
  verifier: ActionVerifier;
  friends?: FriendshipOracle;
  clock?: SocialClock;
  cache?: ProfileCache;
}

/**
 * Profiles for every identity known to this node — the local one(s) and any
 * remote profile that has been replicated into the store or cached.
 */
export class Profiles {
  private readonly store: SocialStore;
  private readonly verifier: ActionVerifier;
  private readonly friends?: FriendshipOracle;
  private readonly clock: SocialClock;
  readonly cache: ProfileCache;

  constructor(options: ProfilesOptions) {
    this.store = options.store;
    this.verifier = options.verifier;
    this.friends = options.friends;
    this.clock = options.clock ?? systemClock;
    this.cache = options.cache ?? new ProfileCache(undefined, undefined, this.clock);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Mutations
  // ─────────────────────────────────────────────────────────────────────────

  /** Create or update the author's own profile. */
  async updateProfile(envelope: SignedAction<ProfileUpdatePayload>): Promise<ProfileRecord> {
    const verified = await this.verify(envelope, PROFILE_ACTIONS.update);
    const record = await this.loadOrInit(verified.author.fingerprint, verified.author.pub);
    const payload = verified.payload ?? {};

    if (payload.displayName !== undefined) {
      record.displayName = assertText(
        payload.displayName,
        'displayName',
        PROFILE_LIMITS.displayName
      );
    }
    if (payload.bio !== undefined) {
      record.bio = assertText(payload.bio, 'bio', PROFILE_LIMITS.bio, { allowEmpty: true });
    }
    if (payload.avatarHash !== undefined) {
      record.avatarHash = payload.avatarHash === null ? null : assertContentHash(payload.avatarHash, 'avatarHash');
    }
    if (payload.coverHash !== undefined) {
      record.coverHash = payload.coverHash === null ? null : assertContentHash(payload.coverHash, 'coverHash');
    }
    if (payload.theme !== undefined) {
      record.theme = assertText(payload.theme, 'theme', PROFILE_LIMITS.theme);
    }
    if (payload.visibility !== undefined) {
      record.visibility = requireVisibility(payload.visibility, 'visibility');
    }
    if (payload.contactVisibility !== undefined) {
      record.contactVisibility = requireVisibility(payload.contactVisibility, 'contactVisibility');
    }
    if (payload.contact !== undefined) {
      record.contact = mergeContact(record.contact, payload.contact);
    }

    record.updatedAt = this.clock();
    await this.store.put(profileKey(record.fingerprint), record);
    this.cache.invalidate(record.fingerprint);
    return record;
  }

  /** Append a link to the author's own link list. */
  async addLink(envelope: SignedAction<AddLinkPayload>): Promise<ProfileLinkRecord> {
    const verified = await this.verify(envelope, PROFILE_ACTIONS.addLink);
    const record = await this.loadOrInit(verified.author.fingerprint, verified.author.pub);
    if (record.links.length >= PROFILE_LIMITS.maxLinks) {
      throw new ProfileError('too_many_links', `A profile may hold at most ${PROFILE_LIMITS.maxLinks} links`);
    }
    const payload = verified.payload ?? ({} as AddLinkPayload);
    const type: ProfileLinkType = payload.type ?? 'url';

    const link: ProfileLinkRecord = {
      id: `lnk_${sha256Hex(`profile.link|${verified.signature}`).slice(0, 16)}`,
      type,
      url: payload.url ? assertText(payload.url, 'url', PROFILE_LIMITS.linkUrl) : null,
      contentHash: payload.contentHash ? assertContentHash(payload.contentHash, 'contentHash') : null,
      targetFingerprint: payload.targetFingerprint
        ? assertFingerprint(payload.targetFingerprint, 'targetFingerprint')
        : null,
      title: assertText(payload.title, 'title', PROFILE_LIMITS.linkTitle),
      description: payload.description
        ? assertText(payload.description, 'description', PROFILE_LIMITS.linkDescription, {
            allowEmpty: true
          })
        : '',
      icon: payload.icon ? assertText(payload.icon, 'icon', 200) : null,
      order: record.links.length,
      visibility: payload.visibility ? requireVisibility(payload.visibility, 'visibility') : 'PUBLIC',
      createdAt: verified.timestamp,
      clicks: 0
    };

    if (type === 'url' && !link.url) {
      throw new ProfileError('invalid_link', "A link of type 'url' requires a url");
    }
    if (type === 'content' && !link.contentHash) {
      throw new ProfileError('invalid_link', "A link of type 'content' requires a contentHash");
    }
    if (type === 'profile' && !link.targetFingerprint) {
      throw new ProfileError('invalid_link', "A link of type 'profile' requires a targetFingerprint");
    }

    record.links.push(link);
    record.updatedAt = this.clock();
    await this.store.put(profileKey(record.fingerprint), record);
    this.cache.invalidate(record.fingerprint);
    return link;
  }

  /** Update one of the author's links. */
  async updateLink(envelope: SignedAction<UpdateLinkPayload>): Promise<ProfileLinkRecord> {
    const verified = await this.verify(envelope, PROFILE_ACTIONS.updateLink);
    const record = await this.requireProfile(verified.author.fingerprint);
    const linkId = assertRecordId(verified.payload?.linkId, 'linkId');
    const link = record.links.find((l) => l.id === linkId);
    if (!link) throw new ProfileError('unknown_link', 'No such link', { linkId });

    const payload = verified.payload;
    if (payload.url !== undefined) link.url = assertText(payload.url, 'url', PROFILE_LIMITS.linkUrl);
    if (payload.title !== undefined) {
      link.title = assertText(payload.title, 'title', PROFILE_LIMITS.linkTitle);
    }
    if (payload.description !== undefined) {
      link.description = assertText(
        payload.description,
        'description',
        PROFILE_LIMITS.linkDescription,
        { allowEmpty: true }
      );
    }
    if (payload.icon !== undefined) link.icon = assertText(payload.icon, 'icon', 200);
    if (payload.order !== undefined && Number.isFinite(payload.order)) {
      link.order = Math.trunc(payload.order);
    }
    if (payload.visibility !== undefined) {
      link.visibility = requireVisibility(payload.visibility, 'visibility');
    }

    record.updatedAt = this.clock();
    await this.store.put(profileKey(record.fingerprint), record);
    this.cache.invalidate(record.fingerprint);
    return link;
  }

  /** Remove one of the author's links. */
  async removeLink(envelope: SignedAction<RemoveLinkPayload>): Promise<boolean> {
    const verified = await this.verify(envelope, PROFILE_ACTIONS.removeLink);
    const record = await this.requireProfile(verified.author.fingerprint);
    const linkId = assertRecordId(verified.payload?.linkId, 'linkId');
    const before = record.links.length;
    record.links = record.links.filter((l) => l.id !== linkId);
    if (record.links.length === before) return false;
    record.updatedAt = this.clock();
    await this.store.put(profileKey(record.fingerprint), record);
    this.cache.invalidate(record.fingerprint);
    return true;
  }

  /** Reorder the author's links. */
  async reorderLinks(envelope: SignedAction<ReorderLinksPayload>): Promise<ProfileLinkRecord[]> {
    const verified = await this.verify(envelope, PROFILE_ACTIONS.reorderLinks);
    const record = await this.requireProfile(verified.author.fingerprint);
    const ids = Array.isArray(verified.payload?.linkIds) ? verified.payload.linkIds : [];
    let order = 0;
    for (const rawId of ids) {
      const link = record.links.find((l) => l.id === rawId);
      if (link) link.order = order++;
    }
    for (const link of record.links) {
      if (!ids.includes(link.id)) link.order = order++;
    }
    record.links.sort((a, b) => a.order - b.order);
    record.updatedAt = this.clock();
    await this.store.put(profileKey(record.fingerprint), record);
    this.cache.invalidate(record.fingerprint);
    return record.links;
  }

  /**
   * Cache a profile view fetched from the network.
   *
   * Views that depend on the requester's relationship (restricted, or any
   * visibility beyond PUBLIC) MUST name the requester they were fetched for;
   * without one the cache refuses them rather than risk serving them to a
   * stranger. PUBLIC + unrestricted views are cached for everyone.
   */
  cacheRemoteProfile(view: ProfileView, ttl?: number, requester?: Fingerprint): void {
    const target = assertFingerprint(view.fingerprint, 'view.fingerprint');
    if (requester !== undefined) {
      this.cache.set(target, requester, view, ttl);
      return;
    }
    if (view.restricted || view.visibility !== 'PUBLIC') {
      throw new ProfileError(
        'cache_requester_required',
        'Requester-scoped profile views must be cached for a specific requester'
      );
    }
    this.cache.set(target, '*', view, ttl);
  }

  /**
   * Invalidate every cached view for `target`. Wire this to friendship /
   * block changes: when a relationship flips, previously-cached FRIENDS
   * views must not survive.
   */
  invalidateCacheFor(target: Fingerprint): void {
    this.cache.invalidate(target);
  }

  /** Count a profile view. Self-views are not counted. */
  async recordView(target: Fingerprint, viewer: Fingerprint): Promise<void> {
    assertFingerprint(viewer, 'viewer');
    if (target === viewer) return;
    const record = await getRecord<ProfileRecord>(this.store, profileKey(target));
    if (!record) return;
    record.views += 1;
    await this.store.put(profileKey(target), record);
  }

  /** Count a link click. */
  async recordClick(target: Fingerprint, linkId: string): Promise<void> {
    const record = await getRecord<ProfileRecord>(this.store, profileKey(target));
    if (!record) return;
    const link = record.links.find((l) => l.id === assertRecordId(linkId, 'linkId'));
    if (!link) return;
    link.clicks += 1;
    await this.store.put(profileKey(target), record);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Reads — requester is always explicit
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Read a profile as `requester`. Works for the requester's own profile AND
   * for other users (locally stored or cached); returns null only when the
   * profile is genuinely unknown.
   */
  async getProfile(target: Fingerprint, requester: Fingerprint): Promise<ProfileView | null> {
    assertFingerprint(target, 'target');
    assertFingerprint(requester, 'requester');

    const record = await getRecord<ProfileRecord>(this.store, profileKey(target));
    if (record) {
      return this.toView(record, requester, await this.isFriend(target, requester));
    }
    // Not replicated locally: fall back to the network cache, keyed by
    // requester so a view built for one requester is never served to another.
    const cached = this.cache.get(target, requester);
    if (cached) return cached;
    return null;
  }

  /** The requester's own full profile record, or null if never created. */
  async getOwnProfile(owner: Fingerprint): Promise<ProfileRecord | null> {
    return getRecord<ProfileRecord>(this.store, profileKey(owner));
  }

  /** Links of `target` that `requester` may see, ordered. */
  async getLinks(target: Fingerprint, requester: Fingerprint): Promise<ProfileLinkView[]> {
    const view = await this.getProfile(target, requester);
    return view?.links ?? [];
  }

  /** Every locally stored profile `requester` may see, plus cached ones. */
  async list(requester: Fingerprint): Promise<ProfileView[]> {
    assertFingerprint(requester, 'requester');
    const records = await listRecords<ProfileRecord>(this.store, `${K_PROFILE}/`);
    const views: ProfileView[] = [];
    for (const record of records) {
      views.push(this.toView(record, requester, await this.isFriend(record.fingerprint, requester)));
    }
    return views;
  }

  /** Substring search over display name and bio, visibility-filtered. */
  async search(query: string, requester: Fingerprint): Promise<ProfileView[]> {
    const needle = String(query ?? '').toLowerCase().trim();
    const views = await this.list(requester);
    const cached = this.cache.values(requester);
    const merged = [...views];
    for (const view of cached) {
      if (!merged.some((v) => v.fingerprint === view.fingerprint)) merged.push(view);
    }
    if (needle.length === 0) return merged.filter((v) => !v.restricted);
    return merged.filter((view) => {
      if (view.restricted) return false;
      return (
        (view.displayName ?? '').toLowerCase().includes(needle) ||
        (view.bio ?? '').toLowerCase().includes(needle)
      );
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Internals
  // ─────────────────────────────────────────────────────────────────────────

  private async verify<P>(envelope: SignedAction<P>, action: string): Promise<VerifiedAction<P>> {
    const verified = await this.verifier.verify(envelope, action);
    assertNoImpersonation(action, verified.payload);
    return verified;
  }

  private async isFriend(owner: Fingerprint, other: Fingerprint): Promise<boolean> {
    if (owner === other) return false;
    if (!this.friends) return false;
    return this.friends.areFriends(owner, other);
  }

  private async loadOrInit(fingerprint: Fingerprint, pub: Base64): Promise<ProfileRecord> {
    const existing = await getRecord<ProfileRecord>(this.store, profileKey(fingerprint));
    if (existing) {
      // Keep the bound key fresh (it is verified on every envelope anyway).
      existing.pub = pub;
      return existing;
    }
    const now = this.clock();
    return {
      fingerprint,
      pub,
      displayName: 'Anonymous',
      bio: '',
      avatarHash: null,
      coverHash: null,
      theme: 'default',
      visibility: 'PUBLIC',
      contact: {},
      contactVisibility: 'FRIENDS',
      links: [],
      views: 0,
      createdAt: now,
      updatedAt: now
    };
  }

  private async requireProfile(fingerprint: Fingerprint): Promise<ProfileRecord> {
    const record = await getRecord<ProfileRecord>(this.store, profileKey(fingerprint));
    if (!record) throw new ProfileError('no_profile', 'Create a profile before editing links');
    return record;
  }

  /** Apply visibility rules for one requester. */
  private toView(record: ProfileRecord, requester: Fingerprint, isFriend: boolean): ProfileView {
    const isOwner = record.fingerprint === requester;

    if (!isOwner) {
      if (record.visibility === 'PRIVATE') {
        return { fingerprint: record.fingerprint, visibility: 'PRIVATE', restricted: true };
      }
      if (record.visibility === 'FRIENDS' && !isFriend) {
        return {
          fingerprint: record.fingerprint,
          visibility: 'FRIENDS',
          restricted: true,
          displayName: record.displayName
        };
      }
    }

    const links = record.links
      .filter((link) => canSeeLink(link.visibility, isOwner, isFriend))
      .sort((a, b) => a.order - b.order)
      .map((link) => ({ ...link, url: effectiveLinkUrl(link) }));

    const view: ProfileView = {
      fingerprint: record.fingerprint,
      restricted: false,
      visibility: record.visibility,
      displayName: record.displayName,
      bio: record.bio,
      avatarHash: record.avatarHash,
      coverHash: record.coverHash,
      theme: record.theme,
      pub: record.pub,
      links,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt
    };

    if (canSeeLink(record.contactVisibility, isOwner, isFriend)) {
      view.contact = { ...record.contact };
    }
    if (isOwner) {
      view.stats = { views: record.views, linkCount: record.links.length };
    }
    return view;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function canSeeLink(visibility: Visibility, isOwner: boolean, isFriend: boolean): boolean {
  if (isOwner) return true;
  switch (visibility) {
    case 'PUBLIC':
    case 'UNLISTED':
      return true;
    case 'FRIENDS':
      return isFriend;
    case 'PRIVATE':
    default:
      return false;
  }
}

function effectiveLinkUrl(link: ProfileLinkRecord): string | null {
  if (link.type === 'content' && link.contentHash) return `aleph://content/${link.contentHash}`;
  if (link.type === 'profile' && link.targetFingerprint) {
    return `aleph://profile/${link.targetFingerprint}`;
  }
  return link.url;
}

function requireVisibility(value: unknown, label: string): Visibility {
  if (!isVisibility(value)) {
    const normalized = normalizeVisibility(value);
    if (typeof value === 'string' && isVisibility(value.toUpperCase())) return normalized;
    throw new ProfileError('invalid_visibility', `${label} must be one of PUBLIC|FRIENDS|PRIVATE|UNLISTED`);
  }
  return value;
}

function mergeContact(current: ProfileContact, updates: ProfileContact): ProfileContact {
  const merged: ProfileContact = { ...current };
  for (const [key, value] of Object.entries(updates ?? {})) {
    if (!/^[a-zA-Z0-9_]{1,32}$/.test(key)) {
      throw new ProfileError('invalid_contact_field', `Illegal contact field name: ${key}`);
    }
    if (value === null || value === undefined) {
      merged[key] = null;
      continue;
    }
    merged[key] = assertText(value, `contact.${key}`, PROFILE_LIMITS.contactValue);
  }
  return merged;
}
