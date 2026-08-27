/**
 * Social Layer — Storage Abstraction
 *
 * The whole social layer persists through a minimal async key/value contract
 * so it never hard-depends on Gun (or any other backend). Two
 * implementations ship here:
 *
 *   MemorySocialStore — JSON-cloning in-memory KV (default, used by tests)
 *   FileSocialStore   — one JSON file per key, secrets written mode 0600
 *
 * Values must be JSON-serializable. `MemorySocialStore` deliberately clones
 * through JSON on both read and write so callers can never mutate persisted
 * state by holding onto a reference — the same guarantee a real backend gives.
 */

import * as fs from 'fs';
import * as fsp from 'fs/promises';
import * as path from 'path';
import { randomBytes } from '../common/crypto';
import { SocialError, ValidationError } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// CONTRACT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Minimal async KV store. Keys are `/`-separated ASCII paths
 * (e.g. `group/grp_1a2b/meta`).
 */
export interface SocialStore {
  get(key: string): Promise<unknown | null>;
  put(key: string, value: unknown): Promise<void>;
  del(key: string): Promise<void>;
  /** All keys beginning with `prefix`, in lexicographic order. */
  list(prefix: string): Promise<string[]>;
}

/** Raised for malformed keys and backend failures. */
export class StoreError extends SocialError {}

// ═══════════════════════════════════════════════════════════════════════════
// KEY VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

const SEGMENT_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

/**
 * Validate a storage key.
 *
 * SECURITY: keys become filesystem paths in `FileSocialStore`. Rejecting `..`,
 * absolute paths and exotic characters here is the second line of defence
 * behind `assertContentHash` / `assertFingerprint` at the call sites.
 */
export function assertStoreKey(key: unknown): string {
  if (typeof key !== 'string' || key.length === 0 || key.length > 1024) {
    throw new ValidationError('Store key must be a non-empty string (max 1024 chars)');
  }
  if (key.startsWith('/') || key.includes('\\') || key.includes('\0')) {
    throw new ValidationError('Store key contains illegal characters', { key });
  }
  const segments = key.split('/');
  for (const segment of segments) {
    if (segment === '.' || segment === '..' || !SEGMENT_PATTERN.test(segment)) {
      throw new ValidationError('Store key contains an illegal path segment', {
        key,
        segment
      });
    }
  }
  return key;
}

/** Join validated key segments. */
export function storeKey(...segments: string[]): string {
  return assertStoreKey(segments.join('/'));
}

// ═══════════════════════════════════════════════════════════════════════════
// TYPED HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/** Read a record with a caller-asserted shape. */
export async function getRecord<T>(store: SocialStore, key: string): Promise<T | null> {
  const raw = await store.get(assertStoreKey(key));
  return raw === null || raw === undefined ? null : (raw as T);
}

/** Read every record under a prefix, skipping keys that vanished mid-scan. */
export async function listRecords<T>(store: SocialStore, prefix: string): Promise<T[]> {
  const keys = await store.list(prefix);
  const out: T[] = [];
  for (const key of keys) {
    const record = await getRecord<T>(store, key);
    if (record !== null) out.push(record);
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// IN-MEMORY IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * In-memory store. Values are serialized on write, so the store owns its own
 * copy of every record.
 */
export class MemorySocialStore implements SocialStore {
  private readonly data = new Map<string, string>();

  async get(key: string): Promise<unknown | null> {
    const raw = this.data.get(assertStoreKey(key));
    return raw === undefined ? null : (JSON.parse(raw) as unknown);
  }

  async put(key: string, value: unknown): Promise<void> {
    this.data.set(assertStoreKey(key), JSON.stringify(value));
  }

  async del(key: string): Promise<void> {
    this.data.delete(assertStoreKey(key));
  }

  async list(prefix: string): Promise<string[]> {
    const out: string[] = [];
    for (const key of this.data.keys()) {
      if (key.startsWith(prefix)) out.push(key);
    }
    return out.sort();
  }

  /**
   * Raw serialized view of everything stored. Test-only affordance used to
   * assert that secrets (private keys, message bodies) are never at rest in
   * plaintext.
   */
  dump(): Record<string, string> {
    return Object.fromEntries(this.data.entries());
  }

  /** Raw serialized value for one key, or null. */
  raw(key: string): string | null {
    return this.data.get(assertStoreKey(key)) ?? null;
  }

  get size(): number {
    return this.data.size;
  }

  clear(): void {
    this.data.clear();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// FILESYSTEM IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

/** Default permissions: owner-only for both files and directories. */
export const SECURE_FILE_MODE = 0o600;
export const SECURE_DIR_MODE = 0o700;

export interface FileSocialStoreOptions {
  basePath: string;
  /** File mode for records. Defaults to 0600. */
  fileMode?: number;
  /** Directory mode. Defaults to 0700. */
  dirMode?: number;
}

/**
 * One JSON file per key under `basePath`, with owner-only permissions.
 *
 * Writes are atomic (temp file + rename) so a crash cannot leave a truncated
 * record behind, and the temp file is created with the same restrictive mode
 * as the final file.
 */
export class FileSocialStore implements SocialStore {
  private readonly basePath: string;
  private readonly fileMode: number;
  private readonly dirMode: number;
  /** Cached realpath of the base directory, resolved lazily on first write. */
  private realBasePath: string | null = null;

  constructor(options: FileSocialStoreOptions) {
    if (!options.basePath) {
      throw new ValidationError('FileSocialStore requires a basePath');
    }
    this.basePath = path.resolve(options.basePath);
    this.fileMode = options.fileMode ?? SECURE_FILE_MODE;
    this.dirMode = options.dirMode ?? SECURE_DIR_MODE;
  }

  /** Create the base directory (mode 0700) and return a ready store. */
  static async create(options: FileSocialStoreOptions): Promise<FileSocialStore> {
    const store = new FileSocialStore(options);
    await fsp.mkdir(store.basePath, { recursive: true, mode: store.dirMode });
    return store;
  }

  private pathFor(key: string): string {
    assertStoreKey(key);
    const filePath = path.join(this.basePath, ...key.split('/')) + '.json';
    const resolved = path.resolve(filePath);
    // Defence in depth: the resolved path must stay inside basePath.
    if (resolved !== this.basePath && !resolved.startsWith(this.basePath + path.sep)) {
      throw new ValidationError('Refusing to operate outside the store base path', { key });
    }
    return resolved;
  }

  /** Realpath of the base directory, created on demand and cached. */
  private async resolveRealBase(): Promise<string> {
    if (this.realBasePath === null) {
      await fsp.mkdir(this.basePath, { recursive: true, mode: this.dirMode });
      this.realBasePath = await fsp.realpath(this.basePath);
    }
    return this.realBasePath;
  }

  /**
   * SECURITY: before writing, verify that the record's parent directory —
   * after resolving every symlink — still lives inside the store base. This
   * closes the symlink redirection hole where a `base/sub` symlink pointing
   * at an arbitrary directory would redirect writes outside the store.
   */
  private async assertContainedParent(filePath: string, key: string): Promise<void> {
    const dir = path.dirname(filePath);
    await fsp.mkdir(dir, { recursive: true, mode: this.dirMode });
    const realBase = await this.resolveRealBase();
    const realDir = await fsp.realpath(dir);
    const relative = path.relative(realBase, realDir);
    if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
      throw new ValidationError(
        'Refusing to write through a symlinked directory outside the store base path',
        { key }
      );
    }
  }

  async get(key: string): Promise<unknown | null> {
    const filePath = this.pathFor(key);
    try {
      const text = await fsp.readFile(filePath, 'utf8');
      return JSON.parse(text) as unknown;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') return null;
      throw new StoreError('store_read_failed', `Failed to read ${key}: ${String(error)}`);
    }
  }

  async put(key: string, value: unknown): Promise<void> {
    const filePath = this.pathFor(key);
    await this.assertContainedParent(filePath, key);
    // Random suffix: pid + timestamp alone can collide when several writes
    // to the same key land in the same millisecond.
    const tempPath = `${filePath}.${process.pid}.${Date.now()}.${randomBytes(6).toString('hex')}.tmp`;
    await fsp.writeFile(tempPath, JSON.stringify(value), { mode: this.fileMode });
    // writeFile only applies `mode` when creating the file; be explicit.
    await fsp.chmod(tempPath, this.fileMode);
    await fsp.rename(tempPath, filePath);
    await fsp.chmod(filePath, this.fileMode);
  }

  async del(key: string): Promise<void> {
    const filePath = this.pathFor(key);
    try {
      await fsp.unlink(filePath);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') {
        throw new StoreError('store_delete_failed', `Failed to delete ${key}: ${String(error)}`);
      }
    }
  }

  async list(prefix: string): Promise<string[]> {
    const keys: string[] = [];
    await this.walk(this.basePath, '', keys);
    return keys.filter((key) => key.startsWith(prefix)).sort();
  }

  private async walk(dir: string, relative: string, out: string[]): Promise<void> {
    let entries: fs.Dirent[];
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') return;
      throw new StoreError('store_list_failed', `Failed to list ${dir}: ${String(error)}`);
    }
    for (const entry of entries) {
      const childRelative = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        await this.walk(path.join(dir, entry.name), childRelative, out);
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        out.push(childRelative.slice(0, -'.json'.length));
      }
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// PREFIXED VIEW
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Namespaces another store behind a fixed prefix, so several social
 * components can share one backend without key collisions.
 */
export class PrefixedSocialStore implements SocialStore {
  constructor(
    private readonly inner: SocialStore,
    private readonly prefix: string
  ) {
    assertStoreKey(prefix);
  }

  private full(key: string): string {
    return storeKey(this.prefix, ...assertStoreKey(key).split('/'));
  }

  async get(key: string): Promise<unknown | null> {
    return this.inner.get(this.full(key));
  }

  async put(key: string, value: unknown): Promise<void> {
    return this.inner.put(this.full(key), value);
  }

  async del(key: string): Promise<void> {
    return this.inner.del(this.full(key));
  }

  async list(prefix: string): Promise<string[]> {
    const scoped = `${this.prefix}/${prefix}`;
    const keys = await this.inner.list(scoped);
    return keys.map((key) => key.slice(this.prefix.length + 1));
  }
}
