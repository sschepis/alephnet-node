import { describe, it, expect, beforeEach } from '@jest/globals';
import { AlephWallet } from '../../src/infra/Wallet';
import { generateKeyTriplet, KeyTriplet } from '../../src/common/crypto';
import { StakeRecord } from '../../src/core/economics/types';
import { RewardCalculator, toBigIntStrict } from '../../src/core/economics/RewardCalculator';

const E18 = 1000000000000000000n;
const DAY = 24 * 60 * 60 * 1000;

type GunNode = Record<string, any>;

/**
 * Minimal in-memory Gun stand-in: chainable get(), merging put() and
 * asynchronous once() reads (the async read is what makes concurrent
 * read-check-write races observable).
 */
class FakeGunChain {
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
    setTimeout(() => cb(data ? { ...data } : undefined), 0);
    return this;
  }
}

describe('AlephWallet', () => {
  let keyTriplet: KeyTriplet;
  let wallet: AlephWallet;
  let store: Map<string, GunNode>;
  let gun: FakeGunChain;
  let mockStake: StakeRecord;

  const seedAccount = (address: string, data: GunNode) => {
    store.set(`ledger/accounts/${address}`, { updatedAt: Date.now(), ...data });
  };

  const seedStake = (stake: Partial<StakeRecord> & { id: string }) => {
    store.set(`ledger/stakes/${stake.id}`, { ...stake });
  };

  const account = (address: string): GunNode => store.get(`ledger/accounts/${address}`) || {};

  beforeEach(() => {
    store = new Map();
    gun = new FakeGunChain(store);
    keyTriplet = generateKeyTriplet();
    wallet = new AlephWallet(keyTriplet, gun);

    mockStake = {
      id: 'stake-1',
      owner: wallet.address,
      amount: 1000n * E18, // 1000 tokens
      lockPeriod: '7d',
      lockedUntil: Date.now() - 1000, // Unlocked
      createdAt: Date.now() - 8 * DAY,
      lastRewardClaim: Date.now() - 7 * DAY,
      status: 'ACTIVE'
    };
  });

  describe('unstake', () => {
    it('should unstake if eligible', async () => {
      seedStake(mockStake);
      seedAccount(wallet.address, {
        available: (5n * E18).toString(),
        staked: (1000n * E18).toString()
      });

      const receipt = await wallet.unstake('stake-1');

      expect(receipt.stakeId).toBe('stake-1');
      expect(receipt.amount).toBe(1000n * E18);
      expect(store.get('ledger/stakes/stake-1')?.status).toBe('UNSTAKED');
      expect(account(wallet.address).available).toBe((1005n * E18).toString());
      expect(account(wallet.address).staked).toBe('0');
    });

    it('should fail if locked', async () => {
      mockStake.lockedUntil = Date.now() + 100000;
      seedStake(mockStake);

      await expect(wallet.unstake('stake-1')).rejects.toThrow('Stake is still locked');
    });

    it('should fail if the stake is unknown', async () => {
      await expect(wallet.unstake('missing')).rejects.toThrow('Stake not found or unauthorized');
    });

    it('should reject unstaking more than the staked balance (no bigint underflow)', async () => {
      seedStake(mockStake); // 1000 tokens staked in the record...
      seedAccount(wallet.address, {
        available: '0',
        staked: (10n * E18).toString() // ...but only 10 tokens on the account
      });

      await expect(wallet.unstake('stake-1')).rejects.toThrow(
        'Unstake amount exceeds staked balance'
      );

      // Balance must be untouched, never negative
      const balance = await wallet.getBalance();
      expect(balance.staked).toBe(10n * E18);
      expect(balance.available).toBe(0n);
      expect(store.get('ledger/stakes/stake-1')?.status).toBe('ACTIVE');
    });

    it('should reject (not hang) when the stake amount is garbage', async () => {
      seedStake({ ...mockStake, amount: 'not-a-number' as any });
      seedAccount(wallet.address, {
        available: '0',
        staked: (1000n * E18).toString()
      });

      // Corrupt amount must surface as a rejection instead of leaving the
      // returned promise unsettled forever.
      await expect(wallet.unstake('stake-1')).rejects.toThrow('Invalid stake amount');
      expect(store.get('ledger/stakes/stake-1')?.status).toBe('ACTIVE');
    });
  });

  describe('claimRewards', () => {
    it('should claim rewards', async () => {
      seedStake(mockStake);
      seedAccount(wallet.address, { available: (1000n * E18).toString() });

      const receipt = await wallet.claimRewards('stake-1');

      expect(receipt.amount).toBeGreaterThan(0n);
      expect(store.get('ledger/stakes/stake-1')?.lastRewardClaim).toEqual(expect.any(Number));
      expect(account(wallet.address).available).toBe((1000n * E18 + receipt.amount).toString());
    });

    it('should not throw when lastRewardClaim is missing (accrues from createdAt)', async () => {
      const { lastRewardClaim, ...withoutClaim } = mockStake;
      seedStake({ ...withoutClaim, createdAt: Date.now() - 30 * DAY });
      seedAccount(wallet.address, { available: '0' });

      const receipt = await wallet.claimRewards('stake-1');

      // 1000 tokens, 5% APY, 30 days => ~4.1 tokens
      expect(receipt.amount).toBeGreaterThan(0n);
      expect(receipt.amount).toBeLessThan(5n * E18);
      expect(receipt.amount).toBeGreaterThan(4n * E18);
    });

    it('should reject when the stake is not active', async () => {
      seedStake({ ...mockStake, status: 'UNSTAKED' });

      await expect(wallet.claimRewards('stake-1')).rejects.toThrow('Stake is not active');
    });
  });

  describe('stake', () => {
    it('should record lastRewardClaim and ACTIVE status so rewards can be claimed', async () => {
      seedAccount(wallet.address, { available: (1000n * E18).toString() });

      const receipt = await wallet.stake(1000n * E18, '30d');
      const record = store.get(`ledger/stakes/${receipt.stakeId}`);

      expect(record?.status).toBe('ACTIVE');
      expect(record?.lastRewardClaim).toEqual(expect.any(Number));
      expect(record?.createdAt).toEqual(expect.any(Number));
      expect(account(wallet.address).staked).toBe((1000n * E18).toString());

      // Freshly created stake has no accrued rewards yet, but must not throw
      await expect(wallet.claimRewards(receipt.stakeId)).rejects.toThrow('No rewards to claim');
    });

    it('should reject staking more than available', async () => {
      seedAccount(wallet.address, { available: '1' });

      await expect(wallet.stake(1000n * E18, '7d')).rejects.toThrow('Insufficient funds');
    });
  });

  describe('transfer', () => {
    it('should move funds between accounts', async () => {
      seedAccount(wallet.address, { available: (100n * E18).toString() });

      const receipt = await wallet.transfer('bob', 40n * E18);

      expect(receipt.status).toBe('CONFIRMED');
      expect(account(wallet.address).available).toBe((60n * E18).toString());
      // Recipient credit happens in a Gun read callback
      await new Promise(resolve => setTimeout(resolve, 5));
      expect(account('bob').available).toBe((40n * E18).toString());
    });

    it('should throw on insufficient funds', async () => {
      seedAccount(wallet.address, { available: (10n * E18).toString() });

      await expect(wallet.transfer('bob', 11n * E18)).rejects.toThrow('Insufficient funds');
      expect(account(wallet.address).available).toBe((10n * E18).toString());
    });

    it('should reject non-positive amounts', async () => {
      seedAccount(wallet.address, { available: (10n * E18).toString() });

      await expect(wallet.transfer('bob', 0n)).rejects.toThrow('Transfer amount must be positive');
      await expect(wallet.transfer('bob', -1n)).rejects.toThrow('Transfer amount must be positive');
    });

    it('should prevent double-spending on concurrent transfers', async () => {
      seedAccount(wallet.address, { available: (100n * E18).toString() });

      const results = await Promise.allSettled([
        wallet.transfer('bob', 60n * E18),
        wallet.transfer('carol', 60n * E18)
      ]);

      const fulfilled = results.filter(r => r.status === 'fulfilled');
      const rejected = results.filter(r => r.status === 'rejected');

      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect((rejected[0] as PromiseRejectedResult).reason.message).toContain('Insufficient funds');

      const balance = await wallet.getBalance();
      expect(balance.available).toBe(40n * E18);
    });

    it('should serialize per address across wallet instances', async () => {
      const other = new AlephWallet(keyTriplet, gun); // same address, same ledger
      seedAccount(wallet.address, { available: (100n * E18).toString() });

      const results = await Promise.allSettled([
        wallet.transfer('bob', 70n * E18),
        other.transfer('carol', 70n * E18)
      ]);

      expect(results.filter(r => r.status === 'rejected')).toHaveLength(1);

      const balance = await wallet.getBalance();
      expect(balance.available).toBe(30n * E18);
    });

    it('should serialize concurrent transfer+stake (exactly one debit survives)', async () => {
      seedAccount(wallet.address, { available: (100n * E18).toString() });

      const results = await Promise.allSettled([
        wallet.transfer('bob', 60n * E18),
        wallet.stake(60n * E18, '7d')
      ]);

      const fulfilled = results.filter(r => r.status === 'fulfilled');
      const rejected = results.filter(r => r.status === 'rejected');
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect((rejected[0] as PromiseRejectedResult).reason.message).toContain('Insufficient funds');

      // Exactly one operation's full effect lands: the account balance never
      // goes negative and one debit of 60 E18 total is observable.
      const balance = await wallet.getBalance();
      expect(balance.available).toBe(40n * E18);
      expect(balance.staked).toBeGreaterThanOrEqual(0n);
      const bobAvailable = BigInt(account('bob').available || '0');
      expect(balance.staked + bobAvailable).toBe(60n * E18);
    });

    it('should credit both concurrent transfers to the same recipient (no lost update)', async () => {
      seedAccount(wallet.address, { available: (100n * E18).toString() });
      seedAccount('bob', { available: (5n * E18).toString() });

      const results = await Promise.allSettled([
        wallet.transfer('bob', 30n * E18),
        wallet.transfer('bob', 40n * E18)
      ]);

      expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(2);
      // Both credits land: 5 + 30 + 40
      expect(account('bob').available).toBe((75n * E18).toString());

      const balance = await wallet.getBalance();
      expect(balance.available).toBe(30n * E18);
    });
  });

  describe('payments', () => {
    it('should reserve funds on authorization and settle on finalize', async () => {
      seedAccount(wallet.address, { available: (100n * E18).toString() });

      const auth = await wallet.authorizePayment('bob', 50n * E18, 'SERVICE');
      expect(account(wallet.address).reserved).toBe((50n * E18).toString());

      await wallet.finalizePayment(auth.id, 20n * E18);

      // 30 refunded to available, reserved emptied
      expect(account(wallet.address).reserved).toBe('0');
      expect(account(wallet.address).available).toBe((80n * E18).toString());
    });

    it('should reject an expired authorization', async () => {
      const now = Date.now();
      store.set('ledger/authorizations/auth-expired', {
        id: 'auth-expired',
        from: wallet.address,
        to: 'bob',
        maxAmount: (10n * E18).toString(),
        status: 'PENDING',
        createdAt: now - 120000,
        expiresAt: now - 1000
      });

      await expect(wallet.finalizePayment('auth-expired')).rejects.toThrow(
        'Authorization has expired'
      );
      expect(store.get('ledger/authorizations/auth-expired')?.status).toBe('EXPIRED');
    });

    it('should clamp reserved at zero when it was already drained', async () => {
      const now = Date.now();
      seedAccount(wallet.address, { available: '0', reserved: '0' });
      store.set('ledger/authorizations/auth-1', {
        id: 'auth-1',
        from: wallet.address,
        to: 'bob',
        maxAmount: (10n * E18).toString(),
        status: 'PENDING',
        createdAt: now,
        expiresAt: now + 60000
      });

      await wallet.finalizePayment('auth-1', 10n * E18);

      const balance = await wallet.getBalance();
      expect(balance.reserved).toBe(0n);
      expect(balance.available).toBe(0n);
    });

    it('should reject finalizing above the authorized maximum', async () => {
      seedAccount(wallet.address, { available: (100n * E18).toString() });
      const auth = await wallet.authorizePayment('bob', 5n * E18, 'SERVICE');

      await expect(wallet.finalizePayment(auth.id, 6n * E18)).rejects.toThrow(
        'Final amount exceeds authorized maximum'
      );
    });
  });

  describe('getBalance', () => {
    it('should return an empty balance for unknown accounts', async () => {
      const balance = await wallet.getBalance();

      expect(balance.available).toBe(0n);
      expect(balance.staked).toBe(0n);
      expect(balance.stakingTier).toBe('Neophyte');
    });

    it('should tolerate malformed ledger values', async () => {
      seedAccount(wallet.address, { available: 'not-a-number', staked: undefined });

      const balance = await wallet.getBalance();

      expect(balance.available).toBe(0n);
      expect(balance.staked).toBe(0n);
    });
  });

  describe('RewardCalculator amount parsing', () => {
    it('toBigIntStrict throws on garbage instead of masking it as zero', () => {
      expect(() => toBigIntStrict('not-a-number')).toThrow(/Invalid numeric value/);
      expect(() => toBigIntStrict({})).toThrow(/Invalid numeric value/);
    });

    it('toBigIntStrict accepts valid forms', () => {
      expect(toBigIntStrict('1000')).toBe(1000n);
      expect(toBigIntStrict(1000n)).toBe(1000n);
      expect(toBigIntStrict(null)).toBe(0n);
      expect(toBigIntStrict(undefined)).toBe(0n);
    });

    it('calculateRewards stays lenient by default (garbage amount -> 0n)', () => {
      const stake: any = { ...mockStake, amount: 'not-a-number' };
      expect(RewardCalculator.calculateRewards(stake)).toBe(0n);
    });
  });
});
