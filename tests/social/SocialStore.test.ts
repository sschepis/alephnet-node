/**
 * SocialStore — KV contract, key guards, filesystem mode 0600.
 */

import { describe, it, expect } from '@jest/globals';
import * as fsp from 'fs/promises';
import * as os from 'os';
import * as path from 'path';
import {
  FileSocialStore,
  MemorySocialStore,
  PrefixedSocialStore
} from '../../src/social/SocialStore';
import { SocialError } from '../../src/social/types';

describe('MemorySocialStore', () => {
  it('round-trips values and lists by prefix', async () => {
    const store = new MemorySocialStore();
    await store.put('a/1', { x: 1 });
    await store.put('a/2', { x: 2 });
    await store.put('b/1', { x: 3 });

    expect(await store.get('a/1')).toEqual({ x: 1 });
    expect(await store.list('a/')).toEqual(['a/1', 'a/2']);
    expect(await store.get('missing')).toBeNull();

    await store.del('a/1');
    expect(await store.get('a/1')).toBeNull();
  });

  it('clones values so callers cannot mutate stored state', async () => {
    const store = new MemorySocialStore();
    const value = { nested: { count: 1 } };
    await store.put('k', value);
    value.nested.count = 999;

    const read = (await store.get('k')) as { nested: { count: number } };
    read.nested.count = 12345;
    const reread = (await store.get('k')) as { nested: { count: number } };
    expect(reread.nested.count).toBe(1);
  });

  it('rejects illegal keys (traversal, absolute, empty)', async () => {
    const store = new MemorySocialStore();
    for (const key of ['', '/abs', '../up', 'a/../../etc', 'a\\b', 'a/./b', 'bad key!']) {
      await expect(store.put(key, 'x')).rejects.toThrow(SocialError);
    }
  });

  it('exposes raw values for at-rest assertions', async () => {
    const store = new MemorySocialStore();
    await store.put('secret', 'PLAINTEXT-SECRET');
    expect(store.raw('secret')).toBe('"PLAINTEXT-SECRET"');
    expect(store.dump()['secret']).toContain('PLAINTEXT-SECRET');
  });
});

describe('PrefixedSocialStore', () => {
  it('namespaces keys transparently', async () => {
    const inner = new MemorySocialStore();
    const store = new PrefixedSocialStore(inner, 'social');

    await store.put('group/grp_a', { name: 'x' });
    expect(await store.get('group/grp_a')).toEqual({ name: 'x' });
    expect(await store.list('group/')).toEqual(['group/grp_a']);
    expect(await inner.get('social/group/grp_a')).toEqual({ name: 'x' });

    await store.del('group/grp_a');
    expect(await store.get('group/grp_a')).toBeNull();
  });
});

describe('FileSocialStore', () => {
  async function tempBase(): Promise<string> {
    const base = path.join(os.tmpdir(), `alephnet-filestore-${Math.random().toString(36).slice(2)}`);
    await fsp.mkdir(base, { recursive: true });
    return base;
  }

  it('round-trips values and writes records with mode 0600', async () => {
    const base = await tempBase();
    const store = await FileSocialStore.create({ basePath: base });

    await store.put('identity/alice', { fingerprint: 'a'.repeat(16), pub: 'k' });
    await store.put('identity/bob', { fingerprint: 'b'.repeat(16), pub: 'k' });

    expect(await store.get('identity/alice')).toEqual({ fingerprint: 'a'.repeat(16), pub: 'k' });
    expect(await store.list('identity/')).toEqual(['identity/alice', 'identity/bob']);

    const stat = await fsp.stat(path.join(base, 'identity', 'alice.json'));
    expect(stat.mode & 0o777).toBe(0o600);

    await store.del('identity/alice');
    expect(await store.get('identity/alice')).toBeNull();
  });

  it('rejects traversal keys before touching the filesystem', async () => {
    const base = await tempBase();
    const store = await FileSocialStore.create({ basePath: base });

    await expect(store.put('../../escape', 'boom')).rejects.toThrow(SocialError);
    await expect(store.get('../..')).rejects.toThrow(SocialError);

    const entries = await fsp.readdir(base);
    expect(entries).toHaveLength(0);
  });

  it('creates the base directory with mode 0700', async () => {
    const base = await tempBase();
    const store = await FileSocialStore.create({ basePath: path.join(base, 'nested', 'store') });
    await store.put('x', 1);
    const stat = await fsp.stat(path.join(base, 'nested', 'store'));
    expect(stat.mode & 0o777).toBe(0o700);
  });

  it('refuses to write through a symlinked subdirectory', async () => {
    const base = await tempBase();
    const store = await FileSocialStore.create({ basePath: base });

    const outside = path.join(
      os.tmpdir(),
      `alephnet-outside-${Math.random().toString(36).slice(2)}`
    );
    await fsp.mkdir(outside);
    await fsp.symlink(outside, path.join(base, 'evil'));

    await expect(store.put('evil/key', 'boom')).rejects.toThrow(SocialError);

    // Nothing was written outside the store.
    const entries = await fsp.readdir(outside);
    expect(entries).toHaveLength(0);
  });

  it('survives concurrent writes to one key and leaves no temp litter', async () => {
    const base = await tempBase();
    const store = await FileSocialStore.create({ basePath: base });

    await Promise.all([store.put('race/key', { n: 1 }), store.put('race/key', { n: 2 })]);

    const value = (await store.get('race/key')) as { n: number };
    expect([1, 2]).toContain(value.n);

    const dirEntries = await fsp.readdir(path.join(base, 'race'));
    expect(dirEntries).toEqual(['key.json']);
  });
});
