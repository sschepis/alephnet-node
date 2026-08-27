/**
 * Fake Gun ledger for economy / coherence tests.
 *
 * These tests exercise the REAL `AlephWallet` from src/infra/Wallet.ts against
 * an in-memory Gun stand-in, so every "balance changed" assertion is a real
 * ledger mutation rather than a mock expectation. The shape mirrors
 * tests/infra/Wallet.test.ts: chainable `get()`, merging `put()` and
 * asynchronous `once()` reads.
 */

import { KeyTriplet, generateKeyTriplet } from '../../src/common/crypto';
import { AlephWallet } from '../../src/infra/Wallet';
import { TokenAmount } from '../../src/economy/units';

export type GunNode = Record<string, any>;

export class FakeGunChain {
  constructor(
    private readonly store: Map<string, GunNode>,
    private readonly path: string = ''
  ) {}

  get(key: string): FakeGunChain {
    return new FakeGunChain(this.store, this.path ? `${this.path}/${key}` : key);
  }

  put(data: GunNode): FakeGunChain {
    const existing = this.store.get(this.path) || {};
    this.store.set(this.path, { ...existing, ...data });
    return this;
  }

  set(data: GunNode): FakeGunChain {
    const id = `${this.path}/${Math.random().toString(36).slice(2)}`;
    this.store.set(id, { ...data });
    return this;
  }

  once(cb: (data: GunNode | undefined) => void): FakeGunChain {
    const data = this.store.get(this.path);
    // Microtasks (not timers) match how real Gun callbacks interleave with
    // awaited promises: a recipient credit registered inside `transfer` is
    // applied before the awaiting code resumes. Timer-based callbacks leave
    // credits dangling until an explicit flush, which makes sequential
    // transfer chains race.
    queueMicrotask(() => cb(data ? { ...data } : undefined));
    return this;
  }
}

export interface SeedBalance {
  available?: TokenAmount;
  staked?: TokenAmount;
  reserved?: TokenAmount;
}

export interface TestWallet {
  wallet: AlephWallet;
  keyTriplet: KeyTriplet;
  address: string;
}

export interface TestLedger {
  store: Map<string, GunNode>;
  gun: FakeGunChain;
  /** Create a wallet with a fresh identity, optionally pre-funded. */
  createWallet(seed?: SeedBalance): TestWallet;
  /** Overwrite an account's buckets. */
  seed(address: string, balance: SeedBalance): void;
  /** Raw account node. */
  account(address: string): GunNode;
  /** Available balance straight out of the ledger. */
  available(address: string): TokenAmount;
  /** Staked balance straight out of the ledger. */
  staked(address: string): TokenAmount;
  /** Raw stake record. */
  stakeRecord(stakeId: string): GunNode | undefined;
  /** Drain pending Gun read callbacks (recipient credits land in those). */
  flush(): Promise<void>;
}

export function createTestLedger(): TestLedger {
  const store = new Map<string, GunNode>();
  const gun = new FakeGunChain(store);

  const seed = (address: string, balance: SeedBalance): void => {
    const existing = store.get(`ledger/accounts/${address}`) || {};
    store.set(`ledger/accounts/${address}`, {
      ...existing,
      available: (balance.available ?? 0n).toString(),
      staked: (balance.staked ?? 0n).toString(),
      reserved: (balance.reserved ?? 0n).toString(),
      updatedAt: Date.now()
    });
  };

  const readBucket = (address: string, bucket: string): TokenAmount => {
    const node = store.get(`ledger/accounts/${address}`);
    const raw = node?.[bucket];
    if (raw === undefined || raw === null || raw === '') return 0n;
    try {
      return BigInt(String(raw));
    } catch {
      return 0n;
    }
  };

  return {
    store,
    gun,
    createWallet(initial?: SeedBalance): TestWallet {
      const keyTriplet = generateKeyTriplet();
      const wallet = new AlephWallet(keyTriplet, gun);
      if (initial) seed(wallet.address, initial);
      return { wallet, keyTriplet, address: wallet.address };
    },
    seed,
    account: (address: string) => store.get(`ledger/accounts/${address}`) || {},
    available: (address: string) => readBucket(address, 'available'),
    staked: (address: string) => readBucket(address, 'staked'),
    stakeRecord: (stakeId: string) => store.get(`ledger/stakes/${stakeId}`),
    async flush(): Promise<void> {
      // Recipient credits happen inside `once` callbacks (one timer deep);
      // a few macrotask turns drain them all.
      for (let i = 0; i < 4; i++) {
        await new Promise(resolve => setTimeout(resolve, 1));
      }
    }
  };
}
