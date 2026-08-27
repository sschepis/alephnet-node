/**
 * Safe Static File Server
 *
 * Replaces `lib/app/server/static-server.js`, whose traversal guard was
 * `filePath.startsWith(staticPath)`. That check is a prefix test on strings, not
 * on paths, so a root of `/app` also matched `/app-data`, `/app.bak` and every
 * other sibling sharing the prefix. It also served `index.html` with HTTP 200
 * for any unknown path, which hid genuine API 404s.
 *
 * Containment here is decided with `path.resolve` + `path.relative`: any result
 * that is absolute or begins with `..` is rejected. The check runs again after
 * the directory→index.html join and after symlink resolution, and the SPA
 * fallback is opt-in.
 */

import * as fs from 'fs';
import * as path from 'path';
import { ERROR_CODES } from '../common/constants';
import { createLogger, Logger } from '../common/logging';
import { Result, ok, err } from '../common/patterns/Result';
import { HttpError, ResponseWriter } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// MIME TYPES
// ═══════════════════════════════════════════════════════════════════════════

export const MIME_TYPES: Readonly<Record<string, string>> = {
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.cjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.eot': 'application/vnd.ms-fontobject',
  '.pdf': 'application/pdf',
  '.zip': 'application/zip',
  '.gz': 'application/gzip',
  '.wasm': 'application/wasm',
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.ogg': 'audio/ogg',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm'
};

/**
 * Content type for a file path, defaulting to a non-executable binary type
 */
export function contentTypeFor(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  return MIME_TYPES[ext] ?? 'application/octet-stream';
}

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

export interface StaticServerConfig {
  /** Directory that files are served from; resolved once at construction */
  readonly root: string;
  /** Real path of the root (symlink-resolved), used for containment checks */
  readonly realRoot: string;
  /** Serve `index.html` for unknown paths. Off by default (flaw #2). */
  readonly spaFallback: boolean;
  /** File served for a directory request */
  readonly indexFile: string;
  /** Cache-Control for successful responses */
  readonly cacheControl: string;
  /** Follow symlinks that point outside the root (never do this) */
  readonly allowSymlinkEscape: boolean;
  /** Hard cap on the size of any single served file (default 10 MB) */
  readonly maxFileBytes: number;
}

export interface StaticServerOptions {
  readonly root: string;
  readonly spaFallback?: boolean;
  readonly indexFile?: string;
  readonly cacheControl?: string;
  readonly allowSymlinkEscape?: boolean;
  /** Hard cap on the size of any single served file (default 10 MB) */
  readonly maxFileBytes?: number;
}

/**
 * A resolved, containment-checked file inside the static root
 */
export interface ResolvedStaticFile {
  readonly absolutePath: string;
  readonly relativePath: string;
  readonly size: number;
  readonly contentType: string;
  readonly mtimeMs: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// PATH CONTAINMENT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decode a URL path segment-safely.
 *
 * Encoded traversal (`..%2f`, `%2e%2e/`) is decoded BEFORE resolution so it is
 * subject to the same containment check as literal `../`.
 */
export function decodeUrlPath(pathname: string): Result<string, HttpError> {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return err(
      HttpError.badRequest(ERROR_CODES.E_VALIDATION_INPUT, 'Malformed percent-encoding in path')
    );
  }

  if (decoded.includes('\0')) {
    return err(HttpError.badRequest(ERROR_CODES.E_VALIDATION_INPUT, 'Illegal path'));
  }

  return ok(decoded);
}

/**
 * True when `candidate` is the root itself or lives strictly inside it.
 *
 * This is the fix for the sibling-directory bug: `path.relative('/app',
 * '/app-data')` is `'../app-data'`, which starts with `..` and is rejected —
 * whereas `'/app-data'.startsWith('/app')` was true.
 */
export function isContained(root: string, candidate: string): boolean {
  const resolvedRoot = path.resolve(root);
  const resolvedCandidate = path.resolve(candidate);
  const relative = path.relative(resolvedRoot, resolvedCandidate);

  if (relative === '') return true;
  if (path.isAbsolute(relative)) return false;
  if (relative === '..') return false;
  if (relative.startsWith(`..${path.sep}`)) return false;
  return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// STATIC SERVER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Serves files from a single directory with strict containment checks.
 */
export class StaticServer {
  private readonly config: StaticServerConfig;
  private readonly logger: Logger;

  constructor(options: StaticServerOptions, logger?: Logger) {
    const resolvedRoot = path.resolve(options.root);
    // Resolve the root to its real path at construction time so the symlink
    // containment check compares like with like. Without this, a static root
    // living under a symlinked directory (macOS /var -> /private/var, /tmp on
    // some systems) would have every legitimate file rejected as an escape.
    let realRoot = resolvedRoot;
    try {
      realRoot = fs.realpathSync(resolvedRoot);
    } catch {
      // Root does not exist yet; it will be realpathed lazily via the
      // per-file check using the resolved (non-real) base.
      realRoot = resolvedRoot;
    }

    this.config = {
      root: resolvedRoot,
      realRoot,
      spaFallback: options.spaFallback ?? false,
      indexFile: options.indexFile ?? 'index.html',
      cacheControl: options.cacheControl ?? 'public, max-age=0, must-revalidate',
      allowSymlinkEscape: options.allowSymlinkEscape ?? false,
      maxFileBytes: options.maxFileBytes ?? 10 * 1024 * 1024
    };
    this.logger = logger ?? createLogger('app:static');
  }

  get root(): string {
    return this.config.root;
  }

  get spaFallbackEnabled(): boolean {
    return this.config.spaFallback;
  }

  /**
   * Resolve a URL pathname to a readable file inside the root.
   *
   * Returns a typed HttpError for traversal (403), missing files (404) and
   * unreadable entries (404) — never a filesystem error message.
   */
  async resolveFile(pathname: string): Promise<Result<ResolvedStaticFile, HttpError>> {
    const decoded = decodeUrlPath(pathname);
    if (!decoded.ok) return decoded;

    // Backslashes are never legitimate in a served URL path and are a Windows
    // traversal vector, so they are rejected outright.
    if (decoded.value.includes('\\')) {
      this.logger.warn('Rejected static path containing a backslash', { pathname });
      return err(HttpError.forbidden(ERROR_CODES.E_AUTH_PERMISSION_DENIED, 'Forbidden'));
    }

    const requested =
      decoded.value === '/' || decoded.value === ''
        ? `/${this.config.indexFile}`
        : decoded.value.startsWith('/')
          ? decoded.value
          : `/${decoded.value}`;

    // Resolve relative to the root WITHOUT pre-normalising: `..` segments must
    // survive into path.resolve so the containment check below can see them.
    // (Normalising first would silently rewrite '/../sibling' to '/sibling'.)
    const candidate = path.resolve(this.config.root, `.${requested}`);

    if (!isContained(this.config.root, candidate)) {
      this.logger.warn('Rejected static path outside root', { pathname });
      return err(HttpError.forbidden(ERROR_CODES.E_AUTH_PERMISSION_DENIED, 'Forbidden'));
    }

    const stat = await statOrNull(candidate);
    if (stat === null) {
      return err(HttpError.notFound(ERROR_CODES.E_STORAGE_NOT_FOUND, 'Not Found'));
    }

    let target = candidate;

    if (stat.isDirectory()) {
      target = path.resolve(candidate, this.config.indexFile);
      // Re-validate AFTER the directory -> index.html join
      if (!isContained(this.config.root, target)) {
        this.logger.warn('Rejected index join outside root', { pathname });
        return err(HttpError.forbidden(ERROR_CODES.E_AUTH_PERMISSION_DENIED, 'Forbidden'));
      }
      const indexStat = await statOrNull(target);
      if (indexStat === null || !indexStat.isFile()) {
        return err(HttpError.notFound(ERROR_CODES.E_STORAGE_NOT_FOUND, 'Not Found'));
      }
      return this.finalize(target, indexStat.size, indexStat.mtimeMs, pathname);
    }

    if (!stat.isFile()) {
      return err(HttpError.notFound(ERROR_CODES.E_STORAGE_NOT_FOUND, 'Not Found'));
    }

    return this.finalize(target, stat.size, stat.mtimeMs, pathname);
  }

  /**
   * Serve a file, or the SPA fallback when enabled.
   *
   * TOCTOU hardening: the file is OPENED ONCE and everything afterwards —
   * size cap, symlink-escape check and the read itself — happens against the
   * opened handle. A symlink swapped between the path check and the read can
   * no longer redirect the read: the descriptor pins the exact inode that was
   * fstat-validated, a fresh realpath re-checks containment of the current
   * path state, and a dev/ino comparison proves the path still names the
   * pinned inode.
   */
  async serve(
    pathname: string,
    res: ResponseWriter,
    options: { suppressBody?: boolean } = {}
  ): Promise<Result<ResolvedStaticFile, HttpError>> {
    let resolved = await this.resolveFile(pathname);

    if (!resolved.ok && resolved.error.status === 404 && this.config.spaFallback) {
      resolved = await this.resolveFile(`/${this.config.indexFile}`);
    }

    if (!resolved.ok) {
      return resolved;
    }

    const file = resolved.value;
    let handle: fs.promises.FileHandle | null = null;
    try {
      handle = await fs.promises.open(file.absolutePath, 'r');

      // fstat the OPENED handle: the size cap and file-type check apply to
      // exactly the inode we are about to read, never to a stale path entry.
      const stat = await handle.stat();
      if (!stat.isFile()) {
        return err(HttpError.notFound(ERROR_CODES.E_STORAGE_NOT_FOUND, 'Not Found'));
      }

      if (stat.size > this.config.maxFileBytes) {
        this.logger.warn('Rejected oversized static file', {
          relativePath: file.relativePath,
          size: stat.size,
          maxFileBytes: this.config.maxFileBytes
        });
        return err(
          HttpError.forbidden(
            ERROR_CODES.E_RESOURCE_EXHAUSTED,
            'Static file exceeds the maximum allowed size'
          )
        );
      }

      if (!this.config.allowSymlinkEscape) {
        // Swap-proof containment for the OPENED handle:
        //
        // 1. Fresh realpath of the path AS IT IS NOW. `absolutePath` was
        //    already fully symlink-resolved in resolveFile(), so any new
        //    symlink introduced anywhere along the path (a middle directory
        //    renamed to a symlink, the final component replaced) makes the
        //    fresh realpath diverge to the NEW target — which is then
        //    containment-checked against the real root.
        const real = await realpathOrNull(file.absolutePath);
        if (real === null) {
          return err(HttpError.notFound(ERROR_CODES.E_STORAGE_NOT_FOUND, 'Not Found'));
        }
        const realRoot = await this.getRealRoot();
        if (realRoot !== null && !isContained(realRoot, real)) {
          this.logger.warn('Rejected symlink escaping static root', { pathname });
          return err(HttpError.forbidden(ERROR_CODES.E_AUTH_PERMISSION_DENIED, 'Forbidden'));
        }

        // 2. dev/ino pin: the path must STILL name the exact inode the
        //    opened handle refers to. A replacement between open() and now
        //    (rename swap, symlink swap) makes this comparison fail, and the
        //    read below comes from the pinned handle either way — so a
        //    post-check swap can never redirect the served bytes.
        const pathStat = await statOrNull(file.absolutePath);
        if (pathStat === null || pathStat.dev !== stat.dev || pathStat.ino !== stat.ino) {
          this.logger.warn('Rejected static file changed between open and read', {
            pathname
          });
          return err(HttpError.forbidden(ERROR_CODES.E_AUTH_PERMISSION_DENIED, 'Forbidden'));
        }
      }

      res.header('Cache-Control', this.config.cacheControl);
      res.header('X-Content-Type-Options', 'nosniff');

      if (options.suppressBody === true) {
        res.header('Content-Type', file.contentType);
        res.header('Content-Length', String(stat.size));
        res.empty(200);
      } else {
        // Read from the validated handle, never from the path
        const content = await handle.readFile();
        res.buffer(content, file.contentType, 200);
      }

      return ok({ ...file, size: stat.size });
    } catch (error) {
      this.logger.error(
        'Failed to read static file',
        error instanceof Error ? error : new Error('read failed'),
        { relativePath: file.relativePath }
      );
      return err(HttpError.notFound(ERROR_CODES.E_STORAGE_NOT_FOUND, 'Not Found'));
    } finally {
      if (handle !== null) {
        try {
          await handle.close();
        } catch {
          /* already closed */
        }
      }
    }
  }

  /**
   * Final containment check after symlink resolution, then build the descriptor
   */
  private async finalize(
    absolutePath: string,
    size: number,
    mtimeMs: number,
    pathname: string
  ): Promise<Result<ResolvedStaticFile, HttpError>> {
    let real = absolutePath;

    if (!this.config.allowSymlinkEscape) {
      try {
        real = await fs.promises.realpath(absolutePath);
      } catch {
        return err(HttpError.notFound(ERROR_CODES.E_STORAGE_NOT_FOUND, 'Not Found'));
      }
      // A symlink inside the root can still point outside it. Compare real
      // paths against the real path of the root so symlinked ROOT directories
      // (macOS /var, some /tmp mounts) do not produce false rejections.
      const realRoot = await this.getRealRoot();
      if (realRoot !== null && !isContained(realRoot, real)) {
        this.logger.warn('Rejected symlink escaping static root', { pathname });
        return err(HttpError.forbidden(ERROR_CODES.E_AUTH_PERMISSION_DENIED, 'Forbidden'));
      }
    }

    return ok({
      absolutePath: real,
      relativePath: path.relative(this.config.root, real),
      size,
      contentType: contentTypeFor(real),
      mtimeMs
    });
  }

  /**
   * Real path of the root, resolved lazily (the directory may not have existed
   * at construction time). Returns null when resolution is impossible.
   */
  private async getRealRoot(): Promise<string | null> {
    try {
      return await fs.promises.realpath(this.config.root);
    } catch {
      return null;
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

async function statOrNull(target: string): Promise<fs.Stats | null> {
  try {
    return await fs.promises.stat(target);
  } catch {
    return null;
  }
}

async function realpathOrNull(target: string): Promise<string | null> {
  try {
    return await fs.promises.realpath(target);
  } catch {
    return null;
  }
}
