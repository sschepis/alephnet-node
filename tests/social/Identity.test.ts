/**
 * Identity — encrypted-at-rest identities.
 */

import { describe, it, expect } from '@jest/globals';
import * as fsp from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import {
  Identity,
  IdentityError,
  IDENTITY_FILE_VERSION,
  MIN_SCRYPT_N
} from '../../src/social/Identity';
import { fingerprintFromPublicKey } from '../../src/social/SignedAction';

const CHEAP_SCRYPT = { N: 1024, r: 8, p: 1 };
/** Cheap files are below the default load-time floor: tests opt down explicitly. */
const CHEAP_LOAD = { minScryptN: CHEAP_SCRYPT.N };

function tempFile(name: string): string {
  return path.join(os.tmpdir(), name);
}

describe('Identity', () => {
  it('round-trips save/load with a password', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const identity = Identity.create({ displayName: 'Alice', bio: 'hi' });

    await identity.save(file, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });
    const loaded = await Identity.load(file, 'correct-horse-battery-staple', CHEAP_LOAD);

    expect(loaded.fingerprint).toBe(identity.fingerprint);
    expect(loaded.publicKeyBase64).toBe(identity.publicKeyBase64);
    expect(loaded.displayName).toBe('Alice');
    expect(loaded.canSign()).toBe(true);

    // The loaded identity must be able to sign, and the signature must verify.
    const message = 'the quick brown fox';
    const signature = loaded.sign(message);
    expect(identity.verify(message, signature)).toBe(true);
    expect(loaded.verify(message, signature, identity.publicKeyBase64)).toBe(true);
  });

  it('throws when saving without a password (never writes plaintext)', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const identity = Identity.create();
    await expect(identity.save(file, '')).rejects.toMatchObject({ code: 'password_required' });
    await expect(identity.save(file, undefined as never)).rejects.toMatchObject({
      code: 'password_required'
    });
    await expect(fsp.stat(file)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('rejects a weak password', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const identity = Identity.create();
    await expect(identity.save(file, 'short', { scrypt: CHEAP_SCRYPT })).rejects.toMatchObject({
      code: 'weak_password'
    });
  });

  it('never writes the private key in plaintext on disk', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const identity = Identity.create();
    await identity.save(file, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });

    const text = await fsp.readFile(file, 'utf8');
    expect(text).not.toContain(identity.sign('probe-material')); // a signature is random bytes
    expect(text).not.toContain('PRIVATE KEY');
    expect(text).not.toContain('privKey');
    expect(text).not.toContain('"priv"');

    const parsed = JSON.parse(text) as { sealedPrivateKey: { ciphertext: string } };
    expect(parsed.sealedPrivateKey.ciphertext).toBeTruthy();
  });

  it('gives every identity its own random salt', async () => {
    const fileA = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const fileB = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const a = Identity.create();
    const b = Identity.create();

    await a.save(fileA, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });
    await b.save(fileB, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });

    const dataA = JSON.parse(await fsp.readFile(fileA, 'utf8'));
    const dataB = JSON.parse(await fsp.readFile(fileB, 'utf8'));
    expect(dataA.sealedPrivateKey.salt).not.toBe(dataB.sealedPrivateKey.salt);
    expect(dataA.sealedPrivateKey.salt).not.toBe('alephnet-salt'); // the legacy constant
  });

  it('writes identity files with mode 0600', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const identity = Identity.create();
    await identity.save(file, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });
    const stat = await fsp.stat(file);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('loads locked (public-only) without a password and cannot sign', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const identity = Identity.create();
    await identity.save(file, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });

    const locked = await Identity.load(file, undefined, CHEAP_LOAD);
    expect(locked.fingerprint).toBe(identity.fingerprint);
    expect(locked.canSign()).toBe(false);
    expect(() => locked.sign('x')).toThrow(IdentityError);
  });

  it('rejects the wrong password', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const identity = Identity.create();
    await identity.save(file, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });
    await expect(
      Identity.load(file, 'wrong-password-here', CHEAP_LOAD)
    ).rejects.toMatchObject({
      code: 'bad_password'
    });
  });

  it('refuses to load legacy (plaintext-capable) file versions', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    await fsp.writeFile(
      file,
      JSON.stringify({ version: 2, nodeId: 'x', pub: 'y', privKey: 'secret' })
    );
    await expect(Identity.load(file, 'whatever-password')).rejects.toMatchObject({
      code: 'corrupt_file'
    });
  });

  it('binds fingerprint to public key: fromPublicKey derives the same fingerprint', () => {
    const identity = Identity.create();
    const derived = fingerprintFromPublicKey(identity.publicKeyBase64);
    expect(derived).toBe(identity.fingerprint);

    const publicOnly = Identity.fromPublicKey(identity.publicKeyBase64);
    expect(publicOnly.fingerprint).toBe(identity.fingerprint);
    expect(publicOnly.canSign()).toBe(false);
  });

  it('JSON serialization never exposes the private key', () => {
    const identity = Identity.create();
    const json = JSON.parse(JSON.stringify(identity)) as Record<string, unknown>;
    expect(json.priv).toBeUndefined();
    expect(json.privateKey).toBeUndefined();
    expect(json.fingerprint).toBe(identity.fingerprint);
  });

  it('persists the current file version', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const identity = Identity.create();
    await identity.save(file, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });
    const parsed = JSON.parse(await fsp.readFile(file, 'utf8')) as { version: number };
    expect(parsed.version).toBe(IDENTITY_FILE_VERSION);
  });

  it('rejects downgraded scrypt parameters in identity files', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const identity = Identity.create();
    await identity.save(file, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });

    // N below the default floor is a downgrade: rejected with a typed error.
    await expect(
      Identity.load(file, 'correct-horse-battery-staple')
    ).rejects.toMatchObject({ code: 'insecure_kdf' });

    // An explicit opt-down (test convenience) still loads it.
    const loaded = await Identity.load(file, 'correct-horse-battery-staple', CHEAP_LOAD);
    expect(loaded.canSign()).toBe(true);

    // A non-power-of-two N is rejected even with the floor lowered.
    const downgraded = JSON.parse(await fsp.readFile(file, 'utf8')) as {
      sealedPrivateKey: { N: number };
    };
    downgraded.sealedPrivateKey.N = 1000;
    await fsp.writeFile(file, JSON.stringify(downgraded));
    await expect(
      Identity.load(file, 'correct-horse-battery-staple', { minScryptN: 128 })
    ).rejects.toMatchObject({ code: 'insecure_kdf' });
  });

  it('rejects wrong key lengths in identity files', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const identity = Identity.create();
    await identity.save(file, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });

    const tampered = JSON.parse(await fsp.readFile(file, 'utf8')) as {
      sealedPrivateKey: { keyLen: number };
    };
    tampered.sealedPrivateKey.keyLen = 16;
    await fsp.writeFile(file, JSON.stringify(tampered));

    await expect(
      Identity.load(file, 'correct-horse-battery-staple', CHEAP_LOAD)
    ).rejects.toMatchObject({ code: 'insecure_kdf' });
  });

  it('saves atomically: the file is always either the old or the new identity', async () => {
    const file = tempFile(`${Math.random().toString(36).slice(2)}.json`);
    const identity = Identity.create();
    await identity.save(file, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });

    identity.displayName = 'Second Version';
    await identity.save(file, 'correct-horse-battery-staple', { scrypt: CHEAP_SCRYPT });

    // Whatever is on disk is a complete, parseable identity file — never a
    // truncated half-write — and it is the NEW one after a successful save.
    const text = await fsp.readFile(file, 'utf8');
    const parsed = JSON.parse(text) as { displayName: string; version: number };
    expect(parsed.version).toBe(IDENTITY_FILE_VERSION);
    expect(parsed.displayName).toBe('Second Version');

    // No temp litter next to the identity file.
    const dir = path.dirname(file);
    const base = path.basename(file);
    const names = await fsp.readdir(dir);
    expect(names.filter((name) => name.startsWith(`${base}.`) && name.endsWith('.tmp'))).toHaveLength(0);
  });

  it('derives a deterministic nodeId from the public key', () => {
    const identity = Identity.create();
    const first = Identity.fromPublicKey(identity.publicKeyBase64);
    const second = Identity.fromPublicKey(identity.publicKeyBase64);

    expect(first.nodeId).toBe(second.nodeId);
    expect(first.nodeId).toMatch(/^[0-9a-f]{32}$/);

    // A different key yields a different node id.
    const other = Identity.create();
    expect(Identity.fromPublicKey(other.publicKeyBase64).nodeId).not.toBe(first.nodeId);

    // An explicit override still wins.
    const overridden = Identity.fromPublicKey(identity.publicKeyBase64, {
      nodeId: 'a'.repeat(32)
    });
    expect(overridden.nodeId).toBe('a'.repeat(32));

    // A file saved from the same key keeps the same node id on reload.
    expect(identity.nodeId).toBe(first.nodeId);
  });

  it('honors the default minimum scrypt floor', () => {
    expect(MIN_SCRYPT_N).toBeGreaterThanOrEqual(16384);
  });
});
