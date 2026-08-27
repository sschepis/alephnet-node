/**
 * Identity — AlephNet cryptographic identity
 *
 * Wraps the existing `KeyTriplet` primitive (Ed25519 keypair + resonance field
 * + fingerprint) and adds persistence that is actually safe.
 *
 * Legacy flaws fixed here:
 *   - `Identity.save()` wrote the Ed25519 private key in PLAINTEXT whenever no
 *     password was passed. Here a password is mandatory: saving without one
 *     throws instead of silently writing a secret to disk.
 *   - Legacy used the FIXED salt `'alephnet-salt'` for scrypt, so every
 *     identity on earth shared one dictionary/rainbow table. Here each identity
 *     gets 16 fresh random bytes of salt, stored next to the ciphertext along
 *     with the scrypt parameters.
 *   - Identity files were written with default permissions. Here files are
 *     written 0600 and directories 0700.
 *   - Loading never checked that the stored public key and fingerprint agreed,
 *     nor that a decrypted private key belonged to the stored public key. Both
 *     are verified now.
 */

import * as fsp from 'fs/promises';
import * as path from 'path';
import {
  EncryptedData,
  KeyTriplet,
  base64ToBuffer,
  computeResonanceField,
  decryptAES256GCM,
  deriveKeyFromPassword,
  encryptAES256GCM,
  generateKeyTriplet,
  randomBytes,
  selectBodyPrimes,
  sha256Hex,
  signToBase64,
  verifyFromBase64
} from '../common/crypto';
import { SECURE_DIR_MODE, SECURE_FILE_MODE } from './SocialStore';
import { fingerprintFromPublicKey, type ActionSigner } from './SignedAction';
import {
  Base64,
  Fingerprint,
  FINGERPRINT_PATTERN,
  SocialError,
  Timestamp,
  ValidationError,
  assertFingerprint,
  systemClock,
  type SocialClock
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// ERRORS
// ═══════════════════════════════════════════════════════════════════════════

export type IdentityFailure =
  | 'password_required'
  | 'weak_password'
  | 'locked'
  | 'not_found'
  | 'corrupt_file'
  | 'bad_password'
  | 'key_mismatch'
  | 'insecure_permissions'
  | 'insecure_kdf';

export class IdentityError extends SocialError {
  constructor(code: IdentityFailure, message: string, details?: Record<string, unknown>) {
    super(code, message, details);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ON-DISK FORMAT
// ═══════════════════════════════════════════════════════════════════════════

/** Current identity file version. v1/v2 were the insecure legacy formats. */
export const IDENTITY_FILE_VERSION = 3;

/** Minimum password length accepted for at-rest encryption. */
export const MIN_PASSWORD_LENGTH = 8;

/** Default scrypt work factors (matches `deriveKeyFromPassword` defaults). */
export const DEFAULT_SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 } as const;

/**
 * Minimum acceptable scrypt work factor when LOADING an identity file.
 * Files sealed with weaker parameters are rejected as downgraded — the file
 * is untrusted input, so its KDF parameters are never taken at face value.
 */
export const MIN_SCRYPT_N = 16384;

/** Sane upper bounds for r and p in loaded files (scrypt requires ≥ 1). */
export const MAX_SCRYPT_R = 32;
export const MAX_SCRYPT_P = 32;

/** The only acceptable derived key length for AES-256-GCM sealing. */
export const REQUIRED_KEY_LEN = 32;

/**
 * An scrypt+AES-256-GCM sealed private key. Every parameter needed to reopen
 * it — most importantly the PER-IDENTITY random salt — travels with it.
 */
export interface SealedPrivateKey {
  kdf: 'scrypt';
  /** Random per-identity salt, base64. Never a shared constant. */
  salt: Base64;
  N: number;
  r: number;
  p: number;
  keyLen: number;
  cipher: 'AES-256-GCM';
  ciphertext: Base64;
  nonce: Base64;
  authTag: Base64;
}

/** Persisted identity. Contains no plaintext secret material. */
export interface IdentityFile {
  version: typeof IDENTITY_FILE_VERSION;
  nodeId: string;
  fingerprint: Fingerprint;
  pub: Base64;
  resonance: number[];
  bodyPrimes: number[];
  displayName: string;
  bio: string;
  createdAt: Timestamp;
  savedAt: Timestamp;
  sealedPrivateKey: SealedPrivateKey;
}

/** Shareable public identity bundle. */
export interface PublicIdentity {
  nodeId: string;
  fingerprint: Fingerprint;
  pub: Base64;
  resonance: number[];
  bodyPrimes: number[];
  displayName: string;
  bio: string;
  createdAt: Timestamp;
}

// ═══════════════════════════════════════════════════════════════════════════
// IDENTITY
// ═══════════════════════════════════════════════════════════════════════════

export interface IdentityCreateOptions {
  displayName?: string;
  bio?: string;
  nodeId?: string;
  clock?: SocialClock;
}

export interface IdentitySaveOptions {
  /** Override scrypt work factors (tests use cheaper parameters). */
  scrypt?: { N: number; r: number; p: number };
  /** Skip the minimum-length check. Off by default, and never skips the
   *  "password required" check. */
  allowShortPassword?: boolean;
}

export interface IdentityLoadOptions {
  /** Refuse to load a file whose mode grants access beyond the owner. */
  requireSecureFileMode?: boolean;
  /**
   * Minimum acceptable scrypt N in the loaded file. Defaults to
   * `MIN_SCRYPT_N`; lowering it is a test convenience and weakens the
   * downgrade protection.
   */
  minScryptN?: number;
}

/**
 * A node's cryptographic identity. Also an `ActionSigner`, so it can
 * authenticate any social mutation directly.
 */
export class Identity implements ActionSigner {
  readonly nodeId: string;
  readonly fingerprint: Fingerprint;
  readonly publicKeyBase64: Base64;
  readonly resonance: number[];
  readonly bodyPrimes: number[];
  readonly createdAt: Timestamp;

  displayName: string;
  bio: string;

  /** PKCS8 DER private key, or null when this identity is locked/public-only. */
  private privateKeyDer: Buffer | null;

  private constructor(params: {
    nodeId: string;
    fingerprint: Fingerprint;
    pub: Base64;
    resonance: number[];
    bodyPrimes: number[];
    displayName: string;
    bio: string;
    createdAt: Timestamp;
    privateKeyDer: Buffer | null;
  }) {
    this.nodeId = params.nodeId;
    this.fingerprint = params.fingerprint;
    this.publicKeyBase64 = params.pub;
    this.resonance = params.resonance;
    this.bodyPrimes = params.bodyPrimes;
    this.displayName = params.displayName;
    this.bio = params.bio;
    this.createdAt = params.createdAt;
    this.privateKeyDer = params.privateKeyDer;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Construction
  // ─────────────────────────────────────────────────────────────────────────

  /** Generate a brand new identity (fresh Ed25519 keypair + resonance). */
  static create(options: IdentityCreateOptions = {}): Identity {
    const triplet = generateKeyTriplet();
    return Identity.fromKeyTriplet(triplet, options);
  }

  /** Wrap an existing `KeyTriplet` (with private key) as an identity. */
  static fromKeyTriplet(triplet: KeyTriplet, options: IdentityCreateOptions = {}): Identity {
    const clock = options.clock ?? systemClock;
    const derived = fingerprintFromPublicKey(triplet.pub);
    if (derived !== triplet.fingerprint) {
      throw new IdentityError(
        'key_mismatch',
        'KeyTriplet fingerprint does not match its public key'
      );
    }
    return new Identity({
      nodeId: options.nodeId ?? deriveNodeIdFromPublicKey(triplet.pub),
      fingerprint: derived,
      pub: triplet.pub,
      resonance: [...triplet.resonance],
      bodyPrimes: [...triplet.bodyPrimes],
      displayName: options.displayName ?? 'Anonymous',
      bio: options.bio ?? '',
      createdAt: clock(),
      privateKeyDer: base64ToBuffer(triplet.priv)
    });
  }

  /**
   * Build a verify-only identity from a public key. Cannot sign; useful for
   * representing remote peers.
   *
   * The node id is derived DETERMINISTICALLY from the public key hash, so
   * repeated calls for the same key yield the same identity instead of a
   * fresh random node id every time.
   */
  static fromPublicKey(pub: Base64, meta: Partial<PublicIdentity> = {}): Identity {
    const publicKey = base64ToBuffer(pub);
    const resonance: number[] = meta.resonance ?? computeResonanceField(publicKey);
    return new Identity({
      nodeId: meta.nodeId ?? deriveNodeIdFromPublicKey(pub),
      fingerprint: fingerprintFromPublicKey(pub),
      pub,
      resonance: [...resonance],
      bodyPrimes: meta.bodyPrimes ?? selectBodyPrimes(publicKey),
      displayName: meta.displayName ?? 'Anonymous',
      bio: meta.bio ?? '',
      createdAt: meta.createdAt ?? 0,
      privateKeyDer: null
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Signing
  // ─────────────────────────────────────────────────────────────────────────

  /** Whether this identity holds a usable private key. */
  canSign(): boolean {
    return this.privateKeyDer !== null;
  }

  /** Sign data with the Ed25519 private key. Returns base64. */
  sign(data: string | Buffer): Base64 {
    if (!this.privateKeyDer) {
      throw new IdentityError(
        'locked',
        'Identity is locked: load it with a password before signing'
      );
    }
    return signToBase64(data, this.privateKeyDer);
  }

  /**
   * Verify a signature. Defaults to this identity's own public key; pass
   * `publicKeyBase64` to check somebody else's signature.
   */
  verify(data: string | Buffer, signature: Base64, publicKeyBase64?: Base64): boolean {
    const pub = publicKeyBase64 ?? this.publicKeyBase64;
    try {
      return verifyFromBase64(data, signature, base64ToBuffer(pub));
    } catch {
      return false;
    }
  }

  /** Drop the private key from memory. */
  lock(): void {
    if (this.privateKeyDer) this.privateKeyDer.fill(0);
    this.privateKeyDer = null;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Export
  // ─────────────────────────────────────────────────────────────────────────

  /** Public bundle, safe to publish. Never includes the private key. */
  exportPublic(): PublicIdentity {
    return {
      nodeId: this.nodeId,
      fingerprint: this.fingerprint,
      pub: this.publicKeyBase64,
      resonance: [...this.resonance],
      bodyPrimes: [...this.bodyPrimes],
      displayName: this.displayName,
      bio: this.bio,
      createdAt: this.createdAt
    };
  }

  /** `JSON.stringify(identity)` yields the public bundle only. */
  toJSON(): PublicIdentity {
    return this.exportPublic();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Persistence
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Encrypt and persist this identity.
   *
   * A password is REQUIRED. There is no code path that writes the private key
   * in plaintext — that was the legacy default and it is gone.
   */
  async save(
    filePath: string,
    password: string,
    options: IdentitySaveOptions = {}
  ): Promise<IdentityFile> {
    if (!this.privateKeyDer) {
      throw new IdentityError('locked', 'Cannot save a locked (public-only) identity');
    }
    assertUsablePassword(password, options);

    const salt = randomBytes(16); // per-identity, never a shared constant
    const params = options.scrypt ?? DEFAULT_SCRYPT_PARAMS;
    const key = await deriveKeyFromPassword(password, salt, 32, params);
    const sealed = encryptAES256GCM(this.privateKeyDer, key);
    key.fill(0);

    const file: IdentityFile = {
      version: IDENTITY_FILE_VERSION,
      nodeId: this.nodeId,
      fingerprint: this.fingerprint,
      pub: this.publicKeyBase64,
      resonance: [...this.resonance],
      bodyPrimes: [...this.bodyPrimes],
      displayName: this.displayName,
      bio: this.bio,
      createdAt: this.createdAt,
      savedAt: Date.now(),
      sealedPrivateKey: {
        kdf: 'scrypt',
        salt: salt.toString('base64'),
        N: params.N,
        r: params.r,
        p: params.p,
        keyLen: 32,
        cipher: 'AES-256-GCM',
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce,
        authTag: sealed.authTag
      }
    };

    const resolved = path.resolve(filePath);
    await fsp.mkdir(path.dirname(resolved), { recursive: true, mode: SECURE_DIR_MODE });
    // Atomic replace: write a unique temp file in the same directory, then
    // rename over the target. A crash at any point leaves either the old
    // file or the new file, never a truncated/partial one.
    const tempPath = `${resolved}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
    await fsp.writeFile(tempPath, JSON.stringify(file, null, 2), { mode: SECURE_FILE_MODE });
    // `mode` on writeFile only applies at creation time; enforce it always.
    await fsp.chmod(tempPath, SECURE_FILE_MODE);
    await fsp.rename(tempPath, resolved);
    await fsp.chmod(resolved, SECURE_FILE_MODE);

    return file;
  }

  /**
   * Load an identity from disk.
   *
   * Without a password the identity comes back LOCKED (public-only, cannot
   * sign) rather than failing — mirroring the legacy convenience, minus the
   * plaintext key. With a password the private key is decrypted and then
   * proven to belong to the stored public key.
   */
  static async load(
    filePath: string,
    password?: string,
    options: IdentityLoadOptions = {}
  ): Promise<Identity> {
    const resolved = path.resolve(filePath);

    let text: string;
    try {
      if (options.requireSecureFileMode) {
        const stat = await fsp.stat(resolved);
        const mode = stat.mode & 0o777;
        if ((mode & 0o077) !== 0) {
          throw new IdentityError(
            'insecure_permissions',
            `Identity file ${resolved} is readable beyond its owner (mode ${mode.toString(8)})`
          );
        }
      }
      text = await fsp.readFile(resolved, 'utf8');
    } catch (error) {
      if (error instanceof IdentityError) throw error;
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        throw new IdentityError('not_found', `Identity file not found: ${resolved}`);
      }
      throw new IdentityError('corrupt_file', `Cannot read identity file: ${String(error)}`);
    }

    const file = parseIdentityFile(text, options.minScryptN ?? MIN_SCRYPT_N);

    // Bind fingerprint to key: a tampered file cannot rename an identity.
    const derived = fingerprintFromPublicKey(file.pub);
    if (derived !== file.fingerprint) {
      throw new IdentityError(
        'corrupt_file',
        'Stored fingerprint does not match the stored public key'
      );
    }

    let privateKeyDer: Buffer | null = null;
    if (password !== undefined && password !== null && password !== '') {
      privateKeyDer = await unsealPrivateKey(file, password);
      // Prove the decrypted key really belongs to the stored public key.
      const probe = `identity-selfcheck:${file.fingerprint}`;
      const ok = verifyFromBase64(
        probe,
        signToBase64(probe, privateKeyDer),
        base64ToBuffer(file.pub)
      );
      if (!ok) {
        privateKeyDer.fill(0);
        throw new IdentityError(
          'key_mismatch',
          'Decrypted private key does not correspond to the stored public key'
        );
      }
    }

    return new Identity({
      nodeId: file.nodeId,
      fingerprint: derived,
      pub: file.pub,
      resonance: file.resonance,
      bodyPrimes: file.bodyPrimes,
      displayName: file.displayName,
      bio: file.bio,
      createdAt: file.createdAt,
      privateKeyDer
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/** Cryptographically random 32-char hex node id. */
export function generateNodeId(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Deterministic 32-char hex node id derived from an Ed25519 public key.
 * Same key → same node id, always. Used wherever an identity is built from
 * a key alone (e.g. `Identity.fromPublicKey`) so identity is stable instead
 * of minting a fresh random id per call.
 */
export function deriveNodeIdFromPublicKey(pub: Base64): string {
  return sha256Hex(`alephnet.nodeid|${pub}`).slice(0, 32);
}

function assertUsablePassword(password: unknown, options: IdentitySaveOptions): string {
  if (typeof password !== 'string' || password.length === 0) {
    throw new IdentityError(
      'password_required',
      'A password is required to save an identity: the Ed25519 private key is never written in plaintext'
    );
  }
  if (!options.allowShortPassword && password.length < MIN_PASSWORD_LENGTH) {
    throw new IdentityError(
      'weak_password',
      `Password must be at least ${MIN_PASSWORD_LENGTH} characters`
    );
  }
  return password;
}

function parseIdentityFile(text: string, minScryptN: number = MIN_SCRYPT_N): IdentityFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new IdentityError('corrupt_file', 'Identity file is not valid JSON');
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new IdentityError('corrupt_file', 'Identity file must contain an object');
  }
  const file = parsed as Record<string, unknown>;

  if (file.version !== IDENTITY_FILE_VERSION) {
    throw new IdentityError(
      'corrupt_file',
      `Unsupported identity file version ${String(file.version)}; expected ${IDENTITY_FILE_VERSION}. ` +
        'Legacy v1/v2 files stored private keys insecurely and are not loadable.'
    );
  }
  if (typeof file.pub !== 'string' || typeof file.fingerprint !== 'string') {
    throw new IdentityError('corrupt_file', 'Identity file is missing pub/fingerprint');
  }
  if (!FINGERPRINT_PATTERN.test(file.fingerprint)) {
    throw new IdentityError('corrupt_file', 'Identity file fingerprint is malformed');
  }
  const sealed = file.sealedPrivateKey as Record<string, unknown> | undefined;
  if (
    !sealed ||
    sealed.kdf !== 'scrypt' ||
    sealed.cipher !== 'AES-256-GCM' ||
    typeof sealed.salt !== 'string' ||
    typeof sealed.ciphertext !== 'string' ||
    typeof sealed.nonce !== 'string' ||
    typeof sealed.authTag !== 'string' ||
    typeof sealed.N !== 'number' ||
    typeof sealed.r !== 'number' ||
    typeof sealed.p !== 'number'
  ) {
    throw new IdentityError('corrupt_file', 'Identity file has no valid sealed private key');
  }

  // The KDF parameters come from the file itself, i.e. from UNTRUSTED input.
  // A downgraded file (tiny N, weird r/p, wrong key length) would let an
  // attacker weaken the at-rest protection; enforce bounds instead of
  // trusting the file.
  const N = sealed.N;
  const r = sealed.r;
  const p = sealed.p;
  const keyLen = typeof sealed.keyLen === 'number' ? sealed.keyLen : REQUIRED_KEY_LEN;
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) {
    throw new IdentityError('insecure_kdf', 'Identity file has non-integer scrypt parameters');
  }
  if (N < minScryptN || N <= 1 || (N & (N - 1)) !== 0) {
    throw new IdentityError(
      'insecure_kdf',
      `Identity file uses a downgraded scrypt work factor N=${N}; minimum is ${minScryptN} (power of two)`
    );
  }
  if (r < 1 || r > MAX_SCRYPT_R || p < 1 || p > MAX_SCRYPT_P) {
    throw new IdentityError(
      'insecure_kdf',
      `Identity file uses out-of-range scrypt parameters r=${r}, p=${p}`
    );
  }
  if (keyLen !== REQUIRED_KEY_LEN) {
    throw new IdentityError(
      'insecure_kdf',
      `Identity file uses key length ${keyLen}; only ${REQUIRED_KEY_LEN} is accepted`
    );
  }

  return {
    version: IDENTITY_FILE_VERSION,
    nodeId: typeof file.nodeId === 'string' ? file.nodeId : generateNodeId(),
    fingerprint: file.fingerprint,
    pub: file.pub,
    resonance: Array.isArray(file.resonance) ? (file.resonance as number[]) : [],
    bodyPrimes: Array.isArray(file.bodyPrimes) ? (file.bodyPrimes as number[]) : [],
    displayName: typeof file.displayName === 'string' ? file.displayName : 'Anonymous',
    bio: typeof file.bio === 'string' ? file.bio : '',
    createdAt: typeof file.createdAt === 'number' ? file.createdAt : 0,
    savedAt: typeof file.savedAt === 'number' ? file.savedAt : 0,
    sealedPrivateKey: {
      kdf: 'scrypt',
      salt: sealed.salt,
      N,
      r,
      p,
      keyLen,
      cipher: 'AES-256-GCM',
      ciphertext: sealed.ciphertext,
      nonce: sealed.nonce,
      authTag: sealed.authTag
    }
  };
}

async function unsealPrivateKey(file: IdentityFile, password: string): Promise<Buffer> {
  const sealed = file.sealedPrivateKey;
  const salt = base64ToBuffer(sealed.salt);
  const key = await deriveKeyFromPassword(password, salt, sealed.keyLen, {
    N: sealed.N,
    r: sealed.r,
    p: sealed.p
  });
  const payload: EncryptedData = {
    ciphertext: sealed.ciphertext,
    nonce: sealed.nonce,
    authTag: sealed.authTag,
    algorithm: 'AES-256-GCM'
  };
  try {
    return decryptAES256GCM(payload, key);
  } catch {
    // GCM auth failure: wrong password or tampered ciphertext.
    throw new IdentityError('bad_password', 'Invalid password or corrupted identity file');
  } finally {
    key.fill(0);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// IDENTITY MANAGER
// ═══════════════════════════════════════════════════════════════════════════

export interface IdentityManagerOptions {
  basePath: string;
  clock?: SocialClock;
}

/**
 * Manages a directory of identity files, one per fingerprint.
 *
 * Filenames are derived from the fingerprint and validated with
 * `assertFingerprint` before any path join — the same traversal guard the
 * content store needs.
 */
export class IdentityManager {
  private readonly basePath: string;
  private readonly clock: SocialClock;
  private readonly unlocked = new Map<Fingerprint, Identity>();

  constructor(options: IdentityManagerOptions) {
    if (!options.basePath) throw new ValidationError('IdentityManager requires a basePath');
    this.basePath = path.resolve(options.basePath);
    this.clock = options.clock ?? systemClock;
  }

  private fileFor(fingerprint: Fingerprint): string {
    return path.join(this.basePath, `${assertFingerprint(fingerprint)}.json`);
  }

  /** Create, encrypt and register a new identity. */
  async create(
    options: IdentityCreateOptions & { password: string; save?: IdentitySaveOptions }
  ): Promise<Identity> {
    const identity = Identity.create({ ...options, clock: this.clock });
    await identity.save(this.fileFor(identity.fingerprint), options.password, options.save);
    this.unlocked.set(identity.fingerprint, identity);
    return identity;
  }

  /** Public metadata for every identity on disk. No decryption performed. */
  async list(): Promise<PublicIdentity[]> {
    let names: string[];
    try {
      names = await fsp.readdir(this.basePath);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') return [];
      throw error;
    }
    const out: PublicIdentity[] = [];
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      const fingerprint = name.slice(0, -'.json'.length);
      if (!FINGERPRINT_PATTERN.test(fingerprint)) continue;
      try {
        const identity = await Identity.load(path.join(this.basePath, name));
        out.push(identity.exportPublic());
      } catch {
        // Skip unreadable/legacy files rather than failing the whole listing.
      }
    }
    return out.sort((a, b) => a.createdAt - b.createdAt);
  }

  /** Load and unlock an identity so it can sign. */
  async unlock(fingerprint: Fingerprint, password: string): Promise<Identity> {
    const identity = await Identity.load(this.fileFor(fingerprint), password);
    if (!identity.canSign()) {
      throw new IdentityError('bad_password', 'Identity could not be unlocked');
    }
    this.unlocked.set(identity.fingerprint, identity);
    return identity;
  }

  /** Already-unlocked identity, if any. */
  get(fingerprint: Fingerprint): Identity | null {
    return this.unlocked.get(assertFingerprint(fingerprint)) ?? null;
  }

  /** Public bundle for one identity, or null when unknown. */
  async getPublic(fingerprint: Fingerprint): Promise<PublicIdentity | null> {
    try {
      const identity = await Identity.load(this.fileFor(fingerprint));
      return identity.exportPublic();
    } catch (error) {
      if (error instanceof IdentityError && error.code === 'not_found') return null;
      throw error;
    }
  }
}
