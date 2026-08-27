import { KeyTriplet } from '../core/types';
import * as crypto from 'crypto';
import { LockPeriod, StakingTier } from '../common/types';
import { 
  WalletBalance, 
  TransactionReceipt, 
  StakeReceipt, 
  UnstakeReceipt,
  RewardReceipt,
  PaymentAuthorization, 
  TransactionType, 
  Transaction,
  StakeRecord
} from '../core/economics/types';
import { RewardCalculator } from '../core/economics/RewardCalculator';
import { Mutex } from '../common/async';

// --- Implementation ---

/**
 * In-process serialization of balance mutations, keyed by account address.
 * Gun has no transactions, so concurrent read-check-write cycles on the same
 * address would otherwise be able to double-spend the available balance.
 */
const MAX_ADDRESS_LOCKS = 1000;
const addressLocks = new Map<string, { mutex: Mutex; lastUsed: number }>();

function getAddressLock(address: string): Mutex {
  const now = Date.now();
  let entry = addressLocks.get(address);
  if (!entry) {
    entry = { mutex: new Mutex(), lastUsed: now };
    addressLocks.set(address, entry);
    evictUnlockedLocks();
  } else {
    entry.lastUsed = now;
  }
  return entry.mutex;
}

/**
 * Bound the lock table: once it grows past the cap, evict the least recently
 * used entries that are not currently held. Locked entries can never be
 * evicted (their holder would lose exclusivity), so growth past the cap is
 * possible but bounded by the number of concurrently locked addresses.
 */
function evictUnlockedLocks(): void {
  if (addressLocks.size <= MAX_ADDRESS_LOCKS) return;
  const candidates = [...addressLocks.entries()]
    .filter(([, entry]) => !entry.mutex.isLocked())
    .sort((a, b) => a[1].lastUsed - b[1].lastUsed);
  for (const [address, entry] of candidates) {
    if (addressLocks.size <= MAX_ADDRESS_LOCKS) break;
    addressLocks.delete(address);
  }
}

/**
 * Shared helper: run a balance-mutating operation under the owning address's
 * mutex. Every read-check-write on `available`/`staked`/`reserved` for an
 * address must go through here. Never acquire two address locks at the same
 * time (would deadlock on crossed transfers).
 */
async function withAddressLock<T>(address: string, fn: () => Promise<T>): Promise<T> {
  return getAddressLock(address).runExclusive(fn);
}

/**
 * AlephWallet - Client-side wallet for managing Aleph tokens
 */
export class AlephWallet {
  public readonly address: string;

  constructor(
    public readonly keyTriplet: KeyTriplet,
    private gun: any
  ) {
    // Address is derived from fingerprint (usually identical or hashed)
    this.address = keyTriplet.fingerprint;
  }

  // ... (existing methods)

  // ═══════════════════════════════════════════════════════════════
  // UNSTAKING & REWARDS
  // ═══════════════════════════════════════════════════════════════

  public async unstake(stakeId: string): Promise<UnstakeReceipt> {
    return new Promise((resolve, reject) => {
        let settled = false;
        const settle = (fn: () => void) => { if (!settled) { settled = true; fn(); } };

        this.gun.get('ledger').get('stakes').get(stakeId).once(async (stake: StakeRecord) => {
            // Gun's `once` can re-fire when the record changes; only the first
            // invocation may settle the promise.
            if (settled) return;

            try {
                if (!stake || stake.owner !== this.address) {
                    throw new Error('Stake not found or unauthorized');
                }
                if (stake.status !== 'ACTIVE') {
                    throw new Error('Stake is not active');
                }
                if (Date.now() < stake.lockedUntil) {
                    throw new Error('Stake is still locked');
                }

                const amount = this.toBigInt(stake.amount);

                // Bounds check before subtracting: bigint arithmetic silently goes
                // negative and would corrupt the account balance.
                if (amount <= 0n) {
                    throw new Error('Invalid stake amount');
                }

                const now = Date.now();
                const txId = crypto.randomUUID();

                await withAddressLock(this.address, async () => {
                    const balance = await this.getBalance();
                    if (amount > balance.staked) {
                        throw new Error('Unstake amount exceeds staked balance');
                    }

                    // Update stake status
                    this.gun.get('ledger').get('stakes').get(stakeId).put({
                        status: 'UNSTAKED',
                        unstakedAt: now
                    });

                    const newAvailable = balance.available + amount;
                    const newStaked = balance.staked - amount;
                    const newTier = this.calculateTier(newStaked);

                    this.gun.get('ledger').get('accounts').get(this.address).put({
                        available: newAvailable.toString(),
                        staked: newStaked.toString(),
                        stakingTier: newTier,
                        updatedAt: now
                    });

                    // Log Transaction
                    this.gun.get('ledger').get('transactions').get(txId).put({
                        id: txId,
                        type: 'UNSTAKE',
                        from: 'STAKING_CONTRACT',
                        to: this.address,
                        amount: amount.toString(),
                        timestamp: now,
                        status: 'CONFIRMED'
                    });
                });

                settle(() => resolve({
                    stakeId,
                    amount,
                    releaseDate: now,
                    transactionId: txId
                }));
            } catch (error) {
                settle(() => reject(error));
            }
        });
    });
  }

  public async claimRewards(stakeId: string): Promise<RewardReceipt> {
      return new Promise((resolve, reject) => {
          let settled = false;
          const settle = (fn: () => void) => { if (!settled) { settled = true; fn(); } };

          this.gun.get('ledger').get('stakes').get(stakeId).once(async (stake: StakeRecord) => {
              if (settled) return;

              try {
                  if (!stake || stake.owner !== this.address) {
                      throw new Error('Stake not found or unauthorized');
                  }
                  if (stake.status !== 'ACTIVE') {
                      throw new Error('Stake is not active');
                  }

                  const reward = RewardCalculator.calculateRewards(stake);
                  if (reward <= 0n) {
                      throw new Error('No rewards to claim');
                  }

                  const now = Date.now();
                  const txId = crypto.randomUUID();

                  await withAddressLock(this.address, async () => {
                      // Update last claim time
                      this.gun.get('ledger').get('stakes').get(stakeId).put({
                          lastRewardClaim: now
                      });

                      // Add rewards to available balance.
                      // Rewards are minted (inflationary), so `unclaimedRewards` is not debited here.
                      const balance = await this.getBalance();
                      const newAvailable = balance.available + reward;

                      this.gun.get('ledger').get('accounts').get(this.address).put({
                          available: newAvailable.toString(),
                          updatedAt: now
                      });

                      // Log Transaction
                      this.gun.get('ledger').get('transactions').get(txId).put({
                          id: txId,
                          type: 'REWARD_CLAIM',
                          from: 'REWARD_POOL',
                          to: this.address,
                          amount: reward.toString(),
                          timestamp: now,
                          status: 'CONFIRMED'
                      });
                  });

                  settle(() => resolve({
                      amount: reward,
                      transactionId: txId,
                      timestamp: now
                  }));
              } catch (error) {
                  settle(() => reject(error));
              }
          });
      });
  }

  // ═══════════════════════════════════════════════════════════════
  // BALANCE
  // ═══════════════════════════════════════════════════════════════

  public async getBalance(): Promise<WalletBalance> {
    return new Promise((resolve) => {
      this.gun.get('ledger').get('accounts').get(this.address).once((data: any) => {
        if (!data || typeof data !== 'object') {
          // Initialize empty account
          resolve(this.emptyBalance());
        } else {
          resolve({
            total: this.toBigInt(data.total), // Derived usually
            available: this.toBigInt(data.available),
            staked: this.toBigInt(data.staked),
            pendingUnstake: this.toBigInt(data.pendingUnstake),
            reserved: this.toBigInt(data.reserved),
            unclaimedRewards: this.toBigInt(data.unclaimedRewards),
            stakingTier: (data.stakingTier as StakingTier) || 'Neophyte',
            updatedAt: data.updatedAt || Date.now()
          });
        }
      });
    });
  }

  // ═══════════════════════════════════════════════════════════════
  // TRANSFERS
  // ═══════════════════════════════════════════════════════════════

  public async transfer(
    to: string,
    amount: bigint,
    options?: { purpose?: any; memo?: string }
  ): Promise<TransactionReceipt> {
    if (amount <= 0n) {
      throw new Error('Transfer amount must be positive');
    }
    if (!to) {
      throw new Error('Transfer recipient is required');
    }

    // Serialize the sender's read-check-write for this address so two
    // concurrent operations cannot both observe the same available balance
    // (double-spend). The recipient credit happens AFTER the sender lock is
    // released, under the recipient's own lock: never hold two address locks
    // at the same time (would deadlock on crossed transfers).
    const receipt = await withAddressLock(this.address, async () => {
      const balance = await this.getBalance();
      if (balance.available < amount) {
        throw new Error('Insufficient funds');
      }

      const txId = crypto.randomUUID();
      const timestamp = Date.now();

      const transaction: any = {
        id: txId,
        type: 'TRANSFER',
        from: this.address,
        to,
        amount: amount.toString(),
        fee: '0', // Zero fee for now
        timestamp,
        purpose: options?.purpose,
        memo: options?.memo,
        status: 'CONFIRMED' // Optimistic confirmation
      };

      // Atomic-ish update (not real atomic in Gun)
      // 1. Write Transaction
      this.gun.get('ledger').get('transactions').get(txId).put(transaction);

      // 2. Update Sender Balance (self-transfers net to zero, so skip the
      //    debit-and-recredit round trip for them)
      if (to !== this.address) {
        const newAvailable = balance.available - amount;
        this.gun.get('ledger').get('accounts').get(this.address).put({
          available: newAvailable.toString(),
          updatedAt: timestamp
        });
      }

      return {
        transactionId: txId,
        status: 'CONFIRMED' as const,
        timestamp
      };
    });

    // 3. Credit the Recipient Balance under the recipient's own mutex so
    //    concurrent credits to the same recipient cannot lose an update.
    if (to !== this.address) {
      await this.creditAvailable(to, amount, receipt.timestamp);
    }

    return receipt;
  }

  // ═══════════════════════════════════════════════════════════════
  // PAYMENTS (ESCROW)
  // ═══════════════════════════════════════════════════════════════

  public async authorizePayment(
    to: string,
    maxAmount: bigint,
    purpose: any,
    expiresIn: number = 60000
  ): Promise<PaymentAuthorization> {
    return withAddressLock(this.address, async () => {
      const balance = await this.getBalance();
      if (balance.available < maxAmount) {
          throw new Error('Insufficient funds for authorization');
      }

      const authId = crypto.randomUUID();
      const now = Date.now();
      const expiresAt = now + expiresIn;

      const auth: any = {
          id: authId,
          from: this.address,
          to,
          maxAmount: maxAmount.toString(),
          purpose,
          status: 'PENDING',
          createdAt: now,
          expiresAt
      };

      // Reserve funds
      const newAvailable = balance.available - maxAmount;
      const newReserved = balance.reserved + maxAmount;

      this.gun.get('ledger').get('authorizations').get(authId).put(auth);
      this.gun.get('ledger').get('accounts').get(this.address).put({
          available: newAvailable.toString(),
          reserved: newReserved.toString(),
          updatedAt: now
      });

      // Return object with bigint
      return {
          ...auth,
          maxAmount: maxAmount
      };
    });
  }

  public async finalizePayment(
      authorizationId: string,
      actualAmount?: bigint
  ): Promise<TransactionReceipt> {
      // Fetch auth
      return new Promise((resolve, reject) => {
          let settled = false;
          const settle = (fn: () => void) => { if (!settled) { settled = true; fn(); } };

          this.gun.get('ledger').get('authorizations').get(authorizationId).once(async (authData: any) => {
              if (settled) return;

              try {
                  if (!authData || authData.status !== 'PENDING') {
                      throw new Error('Invalid or expired authorization');
                  }

                  const now = Date.now();

                  if (typeof authData.expiresAt === 'number' && authData.expiresAt < now) {
                      this.gun.get('ledger').get('authorizations').get(authorizationId).put({
                          status: 'EXPIRED'
                      });
                      throw new Error('Authorization has expired');
                  }

                  const maxAmount = BigInt(authData.maxAmount);
                  const finalAmount = actualAmount !== undefined ? actualAmount : maxAmount;

                  if (finalAmount < 0n) {
                      throw new Error('Final amount must not be negative');
                  }
                  if (finalAmount > maxAmount) {
                      throw new Error('Final amount exceeds authorized maximum');
                  }

                  const txId = crypto.randomUUID();
                  const to = String(authData.to);

                  // All balance mutation for the sender (reserved -> spent +
                  // refund) happens under the sender's mutex. The recipient is
                  // credited afterwards, under the recipient's own mutex.
                  await withAddressLock(this.address, async () => {
                      // 1. Update Auth Status
                      this.gun.get('ledger').get('authorizations').get(authorizationId).put({
                          status: 'FINALIZED',
                          finalizedAmount: finalAmount.toString(),
                          transactionId: txId
                      });

                      // 2. Create Transaction
                      const transaction = {
                          id: txId,
                          type: 'SERVICE_PAYMENT',
                          from: authData.from,
                          to: authData.to,
                          amount: finalAmount.toString(),
                          fee: '0',
                          timestamp: now,
                          purpose: authData.purpose,
                          status: 'CONFIRMED'
                      };
                      this.gun.get('ledger').get('transactions').get(txId).put(transaction);

                      // 3. Update Sender Balance (Reserved -> Spent + Refund)
                      // We reserved `maxAmount`. We spend `finalAmount`.
                      // Refund `maxAmount - finalAmount` to available.
                      const balance = await this.getBalance();

                      // Clamp: the reserved bucket may already have been drained by
                      // another writer, and bigint subtraction would silently go
                      // negative.
                      const newReserved = balance.reserved > maxAmount ? balance.reserved - maxAmount : 0n;
                      // Self-payment: reserved maxAmount is released back to the
                      // same account in full.
                      const refund = maxAmount - finalAmount;
                      const newAvailable = to === this.address
                          ? balance.available + maxAmount
                          : balance.available + refund;

                      this.gun.get('ledger').get('accounts').get(this.address).put({
                          reserved: newReserved.toString(),
                          available: newAvailable.toString(),
                          updatedAt: now
                      });
                  });

                  // 4. Credit the Recipient Balance under the recipient's own
                  //    mutex (self-payments were already settled above).
                  if (to !== this.address) {
                      await this.creditAvailable(to, finalAmount, now);
                  }

                  settle(() => resolve({
                      transactionId: txId,
                      status: 'CONFIRMED',
                      timestamp: now
                  }));
              } catch (error) {
                  settle(() => reject(error));
              }
          });
      });
  }

  // ═══════════════════════════════════════════════════════════════
  // STAKING
  // ═══════════════════════════════════════════════════════════════

  public async stake(amount: bigint, lockPeriod: LockPeriod): Promise<StakeReceipt> {
      if (amount <= 0n) throw new Error('Stake amount must be positive');

      return withAddressLock(this.address, async () => {
          const balance = await this.getBalance();
          if (balance.available < amount) throw new Error('Insufficient funds');

          const stakeId = crypto.randomUUID();
          const now = Date.now();

          // Calculate lock end
          const days = parseInt(lockPeriod); // 7, 30, etc.
          const lockDuration = days * 24 * 60 * 60 * 1000;
          const lockEndsAt = now + lockDuration;

          // Create Stake
          // `lastRewardClaim` and `status` must be seeded here: rewards accrue from
          // the last claim, and claim/unstake both require an ACTIVE record.
          const stakeRecord = {
              id: stakeId,
              owner: this.address,
              amount: amount.toString(),
              lockPeriod,
              lockedUntil: lockEndsAt,
              createdAt: now,
              lastRewardClaim: now,
              status: 'ACTIVE',
              rewards: '0'
          };

          this.gun.get('ledger').get('stakes').get(stakeId).put(stakeRecord);

          // Update Balance
          const newAvailable = balance.available - amount;
          const newStaked = balance.staked + amount;

          // Determine new tier
          const newTier = this.calculateTier(newStaked);

          this.gun.get('ledger').get('accounts').get(this.address).put({
              available: newAvailable.toString(),
              staked: newStaked.toString(),
              stakingTier: newTier,
              updatedAt: now
          });

          // Log Transaction
          const txId = crypto.randomUUID();
          this.gun.get('ledger').get('transactions').get(txId).put({
              id: txId,
              type: 'STAKE',
              from: this.address,
              to: 'STAKING_CONTRACT',
              amount: amount.toString(),
              timestamp: now,
              status: 'CONFIRMED'
          });

          return {
              stakeId,
              amount,
              lockPeriod,
              lockEndsAt,
              newTier,
              transactionId: txId
          };
      });
  }

  // --- Helpers ---

  /**
   * Credit `amount` to `address` under that address's own mutex, reading the
   * latest balance before writing so concurrent credits cannot lose an update.
   * Callers must NOT hold any other address lock when invoking this.
   */
  private async creditAvailable(address: string, amount: bigint, updatedAt: number): Promise<void> {
      if (amount <= 0n) return;
      await withAddressLock(address, async () => {
          const current = await this.readAvailable(address);
          this.gun.get('ledger').get('accounts').get(address).put({
              available: (current + amount).toString(),
              updatedAt
          });
      });
  }

  /**
   * Read only the `available` field for an arbitrary address.
   */
  private readAvailable(address: string): Promise<bigint> {
      return new Promise((resolve) => {
          this.gun.get('ledger').get('accounts').get(address).once((data: any) => {
              resolve(data ? this.toBigInt(data.available) : 0n);
          });
      });
  }

  /**
   * Gun stores bigints as strings and may hand back undefined/garbage.
   */
  private toBigInt(value: any): bigint {
    if (typeof value === 'bigint') return value;
    if (value === null || value === undefined || value === '') return 0n;
    try {
      return BigInt(typeof value === 'number' ? Math.trunc(value) : String(value));
    } catch {
      return 0n;
    }
  }

  private emptyBalance(): WalletBalance {
    return {
      total: 0n,
      available: 0n,
      staked: 0n,
      pendingUnstake: 0n,
      reserved: 0n,
      unclaimedRewards: 0n,
      stakingTier: 'Neophyte',
      updatedAt: Date.now()
    };
  }

  private calculateTier(stakedAmount: bigint): StakingTier {
      // 100, 1000, 10000 (assumed decimals handled by caller or units)
      // Assuming 18 decimals, 100 tokens = 100 * 10^18
      const E18 = 1000000000000000000n;
      if (stakedAmount >= 10000n * E18) return 'Archon';
      if (stakedAmount >= 1000n * E18) return 'Magus';
      if (stakedAmount >= 100n * E18) return 'Adept';
      return 'Neophyte';
  }
}
