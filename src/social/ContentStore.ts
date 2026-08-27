/**
 * ContentStore — content-addressed storage with enforced visibility
 *
 * Legacy flaws fixed here:
 *   - `retrieve()` defaulted `requesterId` to the store owner, so 'private'
 *     visibility was never actually enforced through the action layer, and
 *     `listByOwner`/`search` leaked metadata for any user. Here the requester
 *     fingerprint is a REQUIRED parameter on every read, and FRIENDS checks go
 *     through the friend graph instead of a caller-supplied friend list.
 *   - Blob paths were built directly from an attacker-controlled `hash`
 *     (`'../../x'` walked straight out of the blob directory). Every hash is
 *     now validated as exactly 64 lowercase hex chars before it touches a key
 *     or path, and `FileSocialStore` re-checks containment as a second line of
 *     defence.
 *   - One global index meant the same blob's visibility was whatever the first
 *     uploader said. Entries are now keyed by (hash, owner), so identical
 *     content uploaded by different owners keeps its own visibility while the
 *     blob itself is deduplicated by hash.
 */

import { sha256Hex } from '../common/crypto';
import type { ActionVerifier, SignedAction, VerifiedAction } from './SignedAction';
import { assertNoImpersonation } from './SignedAction';
import type { SocialStore } from './SocialStore';
import { getRecord, listRecords, storeKey } from './SocialStore';
import {
  AccessDeniedError,
  ContentHash,
  Fingerprint,
  FriendshipOracle,
  PageOptions,
  SocialError,
  Timestamp,
  Visibility,
  assertContentHash,
  assertFingerprint,
  isVisibility,
  normalizeVisibility,
  systemClock,
  type SocialClock
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export type ContentKind = 'text' | 'json' | 'markdown' | 'html' | 'binary';

export const CONTENT_MIME_TYPES: Record<ContentKind, string> = {
  text: 'text/plain',
  json: 'application/json',
  markdown: 'text/markdown',
  html: 'text/html',
  binary: 'application/octet-stream'
};

/**
 * Mutation action names. Every mutation arrives as a `SignedAction` envelope
 * whose verified author IS the owner — the store never trusts a bare
 * caller-supplied fingerprint for writes.
 */
export const CONTENT_ACTIONS = {
  put: 'content.put',
  setVisibility: 'content.visibility.set',
  updateMetadata: 'content.metadata.update',
  delete: 'content.delete'
} as const;

/** Signed payload for `content.put`. `content` may be a string, Buffer or object. */
export interface PutContentPayload {
  content: string | Buffer | Record<string, unknown>;
  kind?: ContentKind;
  mimeType?: string;
  visibility?: Visibility;
  metadata?: Record<string, unknown>;
}

export interface SetVisibilityPayload {
  hash: ContentHash;
  visibility: Visibility;
}

export interface UpdateMetadataPayload {
  hash: ContentHash;
  metadata: Record<string, unknown>;
}

export interface DeleteContentPayload {
  hash: ContentHash;
}

export interface PutContentOptions {
  kind?: ContentKind;
  mimeType?: string;
  visibility?: Visibility;
  metadata?: Record<string, unknown>;
  clock?: SocialClock;
}

export interface ContentEntryRecord {
  hash: ContentHash;
  /** Fingerprint of the uploader. */
  owner: Fingerprint;
  kind: ContentKind;
  mimeType: string;
  size: number;
  visibility: Visibility;
  metadata: Record<string, unknown>;
  createdAt: Timestamp;
  updatedAt: Timestamp;
  accessCount: number;
  lastAccessed: Timestamp | null;
}

export interface StoredContentResult {
  hash: ContentHash;
  duplicate: boolean;
  size: number;
  kind: ContentKind;
  visibility: Visibility;
  createdAt: Timestamp;
  /** True when the same owner had already stored this exact content. */
  alreadyOwned: boolean;
}

export interface RetrievedContent {
  hash: ContentHash;
  content: string | Buffer;
  kind: ContentKind;
  mimeType: string;
  size: number;
  owner: Fingerprint;
  visibility: Visibility;
  metadata: Record<string, unknown>;
  createdAt: Timestamp;
}

export interface ContentMetadata {
  hash: ContentHash;
  owner: Fingerprint;
  kind: ContentKind;
  mimeType: string;
  size: number;
  visibility: Visibility;
  metadata: Record<string, unknown>;
  createdAt: Timestamp;
  updatedAt: Timestamp;
  accessCount: number;
  lastAccessed: Timestamp | null;
}

export interface ContentStats {
  entries: number;
  uniqueBlobs: number;
  totalSize: number;
  byKind: Record<string, number>;
  byVisibility: Record<string, number>;
  owners: number;
}

export class ContentStoreError extends SocialError {}

export interface SearchQuery {
  metadata?: Record<string, string | number | boolean>;
  kind?: ContentKind;
  owner?: Fingerprint;
}

export interface SearchOptions extends PageOptions {
  sortBy?: 'createdAt' | 'accessCount';
  sortOrder?: 'asc' | 'desc';
}

export interface ContentStoreOptions {
  store: SocialStore;
  /** Verifies mutation envelopes. Required for every write. */
  verifier?: ActionVerifier;
  friends?: FriendshipOracle;
  clock?: SocialClock;
  /** Maximum size of a single blob, in bytes. */
  maxBlobSize?: number;
  /** Maximum total size across all blobs, in bytes. */
  maxTotalSize?: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// HASHING & KEYS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Compute the content address of some bytes: SHA-256, 64 lowercase hex chars.
 */
export function computeContentHash(content: Buffer | string): ContentHash {
  const buffer = typeof content === 'string' ? Buffer.from(content, 'utf8') : content;
  return sha256Hex(buffer) as ContentHash;
}

const K_BLOB = 'blob';
const K_ENTRY = 'centry';
const K_OWNER = 'cowner';

const blobKey = (hash: ContentHash): string => storeKey(K_BLOB, hash);
const entryKey = (hash: ContentHash, owner: Fingerprint): string =>
  storeKey(K_ENTRY, hash, assertFingerprint(owner, 'owner'));
const entryPrefix = (hash: ContentHash): string => `${K_ENTRY}/${hash}/`;
const ownerKey = (owner: Fingerprint, hash: ContentHash): string =>
  storeKey(K_OWNER, assertFingerprint(owner, 'owner'), hash);
const ownerPrefix = (owner: Fingerprint): string =>
  `${K_OWNER}/${assertFingerprint(owner, 'owner')}/`;

// ═══════════════════════════════════════════════════════════════════════════
// CONTENT STORE
// ═══════════════════════════════════════════════════════════════════════════

export class ContentStore {
  private readonly store: SocialStore;
  private readonly verifier?: ActionVerifier;
  private readonly friends?: FriendshipOracle;
  private readonly clock: SocialClock;
  private readonly maxBlobSize: number;
  private readonly maxTotalSize: number;

  constructor(options: ContentStoreOptions) {
    this.store = options.store;
    this.verifier = options.verifier;
    this.friends = options.friends;
    this.clock = options.clock ?? systemClock;
    this.maxBlobSize = options.maxBlobSize ?? 10 * 1024 * 1024;
    this.maxTotalSize = options.maxTotalSize ?? 100 * 1024 * 1024;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Writing — mutations require a verified SignedAction envelope
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Store content and receive its 64-hex address.
   *
   * The owner is the VERIFIED author of the `content.put` envelope — a bare
   * caller-supplied owner fingerprint is no longer accepted (the legacy
   * `(content, ownerFingerprint, options)` form fails closed). The blob is
   * deduplicated by hash; the (hash, owner) entry records this owner's own
   * visibility and metadata.
   */
  async put(
    envelope: SignedAction<PutContentPayload>,
    options?: { clock?: SocialClock }
  ): Promise<StoredContentResult>;
  /**
   * @deprecated Unsigned legacy form. Rejected with `unsigned_mutation`:
   * `ownerFingerprint` is a bare caller parameter with no signature binding,
   * so it can no longer name an actor. Sign a `content.put` envelope instead.
   */
  async put(
    content: string | Buffer | Record<string, unknown>,
    ownerFingerprint: Fingerprint,
    options?: PutContentOptions
  ): Promise<StoredContentResult>;
  async put(
    contentOrEnvelope: string | Buffer | Record<string, unknown> | SignedAction<PutContentPayload>,
    ownerOrOptions?: Fingerprint | { clock?: SocialClock },
    legacyOptions?: PutContentOptions
  ): Promise<StoredContentResult> {
    if (isSignedAction(contentOrEnvelope)) {
      return this.putSigned(
        contentOrEnvelope as SignedAction<PutContentPayload>,
        (ownerOrOptions as { clock?: SocialClock } | undefined) ?? {}
      );
    }
    void legacyOptions;
    throw new ContentStoreError(
      'unsigned_mutation',
      'ContentStore.put requires a signed action envelope (content.put); ' +
        'the legacy (content, ownerFingerprint, options) form is no longer accepted'
    );
  }

  private async putSigned(
    envelope: SignedAction<PutContentPayload>,
    options: { clock?: SocialClock }
  ): Promise<StoredContentResult> {
    const verified = await this.verifyMutation(envelope, CONTENT_ACTIONS.put);
    const owner = verified.author.fingerprint;
    const payload = verified.payload ?? {};
    const buffer = serializeContent(payload.content, payload.kind);
    if (buffer.length > this.maxBlobSize) {
      throw new ContentStoreError('content_too_large', 'Content exceeds the maximum blob size', {
        size: buffer.length,
        max: this.maxBlobSize
      });
    }

    const hash = computeContentHash(buffer); // always 64 lowercase hex
    const now = (options.clock ?? this.clock)();
    const kind = payload.kind ?? inferKind(payload.content);
    const visibility = payload.visibility ? requireVisibility(payload.visibility) : 'PRIVATE';

    const existingBlob = await getRecord<{ size: number }>(this.store, blobKey(hash));
    const existingEntry = await getRecord<ContentEntryRecord>(
      this.store,
      entryKey(hash, owner)
    );

    if (!existingBlob) {
      const stats = await this.totalSize();
      if (stats + buffer.length > this.maxTotalSize) {
        throw new ContentStoreError(
          'store_full',
          'Total storage limit exceeded',
          { total: stats, max: this.maxTotalSize }
        );
      }
      await this.store.put(blobKey(hash), { hash, size: buffer.length, data: buffer.toString('base64') });
    }

    if (existingEntry) {
      // Same owner re-uploaded identical bytes: keep the original visibility,
      // refresh metadata and timestamp.
      existingEntry.metadata = { ...existingEntry.metadata, ...(payload.metadata ?? {}) };
      existingEntry.mimeType = payload.mimeType ?? existingEntry.mimeType;
      existingEntry.updatedAt = now;
      await this.store.put(entryKey(hash, owner), existingEntry);
      return {
        hash,
        duplicate: true,
        alreadyOwned: true,
        size: existingEntry.size,
        kind: existingEntry.kind,
        visibility: existingEntry.visibility,
        createdAt: existingEntry.createdAt
      };
    }

    const entry: ContentEntryRecord = {
      hash,
      owner,
      kind,
      mimeType: payload.mimeType ?? CONTENT_MIME_TYPES[kind],
      size: buffer.length,
      visibility,
      metadata: payload.metadata ?? {},
      createdAt: now,
      updatedAt: now,
      accessCount: 0,
      lastAccessed: null
    };
    await this.store.put(entryKey(hash, owner), entry);
    await this.store.put(ownerKey(owner, hash), { hash });

    return {
      hash,
      duplicate: existingBlob !== null,
      alreadyOwned: false,
      size: buffer.length,
      kind,
      visibility,
      createdAt: now
    };
  }

  /**
   * Change the visibility of one of your entries. The entry owner is the
   * verified envelope author — a forged owner is rejected before any write.
   */
  async setVisibility(envelope: SignedAction<SetVisibilityPayload>): Promise<ContentEntryRecord> {
    const verified = await this.verifyMutation(envelope, CONTENT_ACTIONS.setVisibility);
    const owner = verified.author.fingerprint;
    const entry = await this.requireOwnedEntry(verified.payload?.hash, owner);
    entry.visibility = requireVisibility(verified.payload?.visibility);
    entry.updatedAt = this.clock();
    await this.store.put(entryKey(entry.hash, entry.owner), entry);
    return entry;
  }

  /** Merge metadata into one of your entries. */
  async updateMetadata(envelope: SignedAction<UpdateMetadataPayload>): Promise<ContentEntryRecord> {
    const verified = await this.verifyMutation(envelope, CONTENT_ACTIONS.updateMetadata);
    const owner = verified.author.fingerprint;
    const entry = await this.requireOwnedEntry(verified.payload?.hash, owner);
    entry.metadata = { ...entry.metadata, ...(verified.payload?.metadata ?? {}) };
    entry.updatedAt = this.clock();
    await this.store.put(entryKey(entry.hash, entry.owner), entry);
    return entry;
  }

  /**
   * Remove one of your entries. The blob is deleted once no entry references
   * it anymore (content-addressed dedup stays correct).
   */
  async delete(envelope: SignedAction<DeleteContentPayload>): Promise<boolean> {
    const verified = await this.verifyMutation(envelope, CONTENT_ACTIONS.delete);
    const owner = verified.author.fingerprint;
    const entry = await this.requireOwnedEntry(verified.payload?.hash, owner);
    await this.store.del(entryKey(entry.hash, entry.owner));
    await this.store.del(ownerKey(entry.owner, entry.hash));

    const remaining = await listRecords<ContentEntryRecord>(this.store, entryPrefix(entry.hash));
    if (remaining.length === 0) {
      await this.store.del(blobKey(entry.hash));
    }
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Reading — requester is REQUIRED and visibility is enforced
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Fetch content by hash as `requesterFingerprint`.
   *
   * Throws `AccessDeniedError` when the requester may not see the content;
   * returns null only for unknown hashes.
   */
  async get(hash: unknown, requesterFingerprint: Fingerprint): Promise<RetrievedContent | null> {
    const valid = assertContentHash(hash, 'hash');
    const requester = assertFingerprint(requesterFingerprint, 'requesterFingerprint');

    const entries = await listRecords<ContentEntryRecord>(this.store, entryPrefix(valid));
    if (entries.length === 0) return null;

    const permitted = await this.firstPermitted(entries, requester);
    if (!permitted) {
      // Fail closed; do not confirm whether the hash exists at all.
      throw new AccessDeniedError('You may not access this content', { hash: valid });
    }

    const blob = await getRecord<{ data: string }>(this.store, blobKey(valid));
    if (!blob) return null;

    permitted.accessCount += 1;
    permitted.lastAccessed = this.clock();
    await this.store.put(entryKey(valid, permitted.owner), permitted);

    return {
      hash: valid,
      content: decodeContent(Buffer.from(blob.data, 'base64'), permitted.kind),
      kind: permitted.kind,
      mimeType: permitted.mimeType,
      size: permitted.size,
      owner: permitted.owner,
      visibility: permitted.visibility,
      metadata: { ...permitted.metadata },
      createdAt: permitted.createdAt
    };
  }

  /** Whether `requester` may read this hash. */
  async canAccess(hash: unknown, requesterFingerprint: Fingerprint): Promise<boolean> {
    const valid = assertContentHash(hash, 'hash');
    const requester = assertFingerprint(requesterFingerprint, 'requesterFingerprint');
    const entries = await listRecords<ContentEntryRecord>(this.store, entryPrefix(valid));
    return (await this.firstPermitted(entries, requester)) !== null;
  }

  /** Metadata for a hash, if `requester` may see it. */
  async getMetadata(
    hash: unknown,
    requesterFingerprint: Fingerprint
  ): Promise<ContentMetadata | null> {
    const valid = assertContentHash(hash, 'hash');
    const requester = assertFingerprint(requesterFingerprint, 'requesterFingerprint');
    const entries = await listRecords<ContentEntryRecord>(this.store, entryPrefix(valid));
    const permitted = await this.firstPermitted(entries, requester);
    if (!permitted) return null;
    return toMetadata(permitted);
  }

  /** Whether a hash is known to the store (visibility-independent). */
  async has(hash: unknown): Promise<boolean> {
    const valid = assertContentHash(hash, 'hash');
    return (await this.store.get(blobKey(valid))) !== null;
  }

  /**
   * List entries owned by `ownerFingerprint`, filtered to what
   * `requesterFingerprint` may actually see. PRIVATE, non-friend FRIENDS and
   * UNLISTED entries owned by someone else are simply absent — no metadata
   * leaks. (UNLISTED content is reachable only by its address, never by
   * enumeration.)
   */
  async list(
    ownerFingerprint: Fingerprint,
    requesterFingerprint: Fingerprint,
    options: PageOptions = {}
  ): Promise<ContentMetadata[]> {
    const owner = assertFingerprint(ownerFingerprint, 'ownerFingerprint');
    const requester = assertFingerprint(requesterFingerprint, 'requesterFingerprint');

    const markers = await listRecords<{ hash: ContentHash }>(this.store, ownerPrefix(owner));
    const out: ContentMetadata[] = [];
    for (const marker of markers) {
      const entry = await getRecord<ContentEntryRecord>(this.store, entryKey(marker.hash, owner));
      if (!entry) continue;
      if (!this.enumerable(entry, requester)) continue;
      if (!(await this.isPermitted(entry, requester))) continue;
      out.push(toMetadata(entry));
    }
    out.sort((a, b) => b.createdAt - a.createdAt);
    const offset = options.offset ?? 0;
    const limit = options.limit ?? 50;
    return out.slice(offset, offset + limit);
  }

  /** Content `requester` may see, sorted by popularity. UNLISTED is excluded. */
  async listPublic(requesterFingerprint: Fingerprint, options: PageOptions = {}): Promise<ContentMetadata[]> {
    const requester = assertFingerprint(requesterFingerprint, 'requesterFingerprint');
    const entries = await listRecords<ContentEntryRecord>(this.store, `${K_ENTRY}/`);
    const permitted: ContentMetadata[] = [];
    for (const entry of entries) {
      if (!this.enumerable(entry, requester)) continue;
      if (!(await this.isPermitted(entry, requester))) continue;
      permitted.push(toMetadata(entry));
    }
    permitted.sort((a, b) => b.accessCount - a.accessCount);
    const offset = options.offset ?? 0;
    const limit = options.limit ?? 50;
    return permitted.slice(offset, offset + limit);
  }

  /** Metadata search across content `requester` may see. UNLISTED is excluded. */
  async search(
    query: SearchQuery,
    requesterFingerprint: Fingerprint,
    options: SearchOptions = {}
  ): Promise<ContentMetadata[]> {
    const requester = assertFingerprint(requesterFingerprint, 'requesterFingerprint');
    const entries = await listRecords<ContentEntryRecord>(this.store, `${K_ENTRY}/`);
    const results: ContentMetadata[] = [];
    for (const entry of entries) {
      if (!this.enumerable(entry, requester)) continue;
      if (!(await this.isPermitted(entry, requester))) continue;
      if (query.kind && entry.kind !== query.kind) continue;
      if (query.owner && entry.owner !== query.owner) continue;
      if (query.metadata) {
        const matches = Object.entries(query.metadata).every(([key, value]) => {
          if (typeof value === 'string') {
            return String(entry.metadata[key] ?? '')
              .toLowerCase()
              .includes(value.toLowerCase());
          }
          return entry.metadata[key] === value;
        });
        if (!matches) continue;
      }
      results.push(toMetadata(entry));
    }
    const sortBy = options.sortBy ?? 'createdAt';
    const multiplier = (options.sortOrder ?? 'desc') === 'asc' ? 1 : -1;
    results.sort((a, b) => (a[sortBy] - b[sortBy]) * multiplier);
    const offset = options.offset ?? 0;
    const limit = options.limit ?? 50;
    return results.slice(offset, offset + limit);
  }

  /** Aggregate counters (visibility-independent; the store is not an oracle). */
  async getStats(): Promise<ContentStats> {
    const entries = await listRecords<ContentEntryRecord>(this.store, `${K_ENTRY}/`);
    const blobs = await this.store.list(`${K_BLOB}/`);
    let totalSize = 0;
    for (const entry of entries) totalSize += entry.size;
    const byKind: Record<string, number> = {};
    const byVisibility: Record<string, number> = {};
    const owners = new Set<Fingerprint>();
    for (const entry of entries) {
      byKind[entry.kind] = (byKind[entry.kind] ?? 0) + 1;
      byVisibility[entry.visibility] = (byVisibility[entry.visibility] ?? 0) + 1;
      owners.add(entry.owner);
    }
    return {
      entries: entries.length,
      uniqueBlobs: blobs.length,
      totalSize,
      byKind,
      byVisibility,
      owners: owners.size
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Internals
  // ─────────────────────────────────────────────────────────────────────────

  private async verifyMutation<P>(
    envelope: SignedAction<P>,
    action: string
  ): Promise<VerifiedAction<P>> {
    if (!this.verifier) {
      throw new ContentStoreError(
        'verifier_required',
        'ContentStore mutations require an ActionVerifier; pass one via ContentStoreOptions'
      );
    }
    const verified = await this.verifier.verify(envelope, action);
    assertNoImpersonation(action, verified.payload);
    return verified;
  }

  private async requireOwnedEntry(
    hash: unknown,
    owner: Fingerprint
  ): Promise<ContentEntryRecord> {
    const valid = assertContentHash(hash, 'hash');
    const entry = await getRecord<ContentEntryRecord>(this.store, entryKey(valid, owner));
    if (!entry) {
      throw new ContentStoreError('not_found', 'No such content entry for this owner', {
        hash: valid
      });
    }
    return entry;
  }

  /**
   * Whether an entry may appear in ANY enumeration (`list`/`listPublic`/
   * `search`) for this requester. UNLISTED content is contractually
   * "readable by anyone holding the address, never enumerated" — so it is
   * enumerable only for its owner.
   */
  private enumerable(entry: ContentEntryRecord, requester: Fingerprint): boolean {
    if (entry.visibility !== 'UNLISTED') return true;
    return entry.owner === requester;
  }

  private async isPermitted(entry: ContentEntryRecord, requester: Fingerprint): Promise<boolean> {
    if (entry.owner === requester) return true;
    switch (entry.visibility) {
      case 'PUBLIC':
      case 'UNLISTED':
        return true;
      case 'FRIENDS':
        if (!this.friends) return false;
        return this.friends.areFriends(entry.owner, requester);
      case 'PRIVATE':
      default:
        return false;
    }
  }

  /**
   * A hash may carry several (hash, owner) entries with different
   * visibilities; access is granted if ANY entry the requester can satisfy
   * permits it.
   */
  /**
   * The entry a requester should be served for a shared blob.
   *
   * A single blob may carry one entry per owner (dedup by hash, but visibility
   * is per-owner). The requester's OWN entry always wins so that callers see
   * their own ownership and visibility rather than a co-owner's; only then do
   * we fall back to any other entry they are permitted to read.
   */
  private async firstPermitted(
    entries: ContentEntryRecord[],
    requester: Fingerprint
  ): Promise<ContentEntryRecord | null> {
    const own = entries.find(entry => entry.owner === requester);
    if (own && (await this.isPermitted(own, requester))) return own;

    for (const entry of entries) {
      if (entry.owner === requester) continue;
      if (await this.isPermitted(entry, requester)) return entry;
    }
    return null;
  }

  private async totalSize(): Promise<number> {
    const entries = await listRecords<ContentEntryRecord>(this.store, `${K_ENTRY}/`);
    const seen = new Set<ContentHash>();
    let total = 0;
    for (const entry of entries) {
      if (seen.has(entry.hash)) continue;
      seen.add(entry.hash);
      total += entry.size;
    }
    return total;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function serializeContent(
  content: string | Buffer | Record<string, unknown>,
  kind?: ContentKind
): Buffer {
  if (typeof content === 'string') return Buffer.from(content, 'utf8');
  if (Buffer.isBuffer(content)) return content;
  if (typeof content === 'object') return Buffer.from(JSON.stringify(content), 'utf8');
  void kind;
  throw new ContentStoreError('invalid_content', 'Content must be a string, Buffer, or object');
}

function inferKind(content: string | Buffer | Record<string, unknown>): ContentKind {
  if (typeof content === 'string') return 'text';
  if (Buffer.isBuffer(content)) return 'binary';
  return 'json';
}

function decodeContent(buffer: Buffer, kind: ContentKind): string | Buffer {
  switch (kind) {
    case 'json':
      try {
        return JSON.parse(buffer.toString('utf8')) as string;
      } catch {
        return buffer.toString('utf8');
      }
    case 'binary':
      return buffer;
    default:
      return buffer.toString('utf8');
  }
}

function requireVisibility(value: unknown): Visibility {
  if (isVisibility(value)) return value;
  const normalized = normalizeVisibility(value);
  if (typeof value === 'string' && isVisibility(value.toUpperCase())) return normalized;
  throw new ContentStoreError(
    'invalid_visibility',
    'visibility must be one of PUBLIC|FRIENDS|PRIVATE|UNLISTED'
  );
}

function toMetadata(entry: ContentEntryRecord): ContentMetadata {
  return {
    hash: entry.hash,
    owner: entry.owner,
    kind: entry.kind,
    mimeType: entry.mimeType,
    size: entry.size,
    visibility: entry.visibility,
    metadata: { ...entry.metadata },
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
    accessCount: entry.accessCount,
    lastAccessed: entry.lastAccessed
  };
}

/** Structural check: does this value look like a signed action envelope? */
function isSignedAction(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Buffer.isBuffer(value) &&
    typeof (value as Record<string, unknown>).action === 'string' &&
    typeof (value as Record<string, unknown>).signature === 'string'
  );
}
