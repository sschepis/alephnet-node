/**
 * Wallet Port
 *
 * The economy and coherence modules move REAL funds. They do so through this
 * narrow port, which is structurally satisfied by the canonical
 * `AlephWallet` in `src/infra/Wallet.ts` (see the compile-time assertion at
 * the bottom of this file).
 *
 * The legacy JS economy is the cautionary tale: `stakes.js` recorded a stake
 * but never debited anything, `slashStake` called a non-existent
 * `wallet.send()`, and `rewards.js` called `wallet.receive(number)` when the
 * wallet expected a Transaction object. None of it moved a single token.
 * Typing the port — and asserting that the real wallet implements it — makes
 * that class of bug a compile error.
 */

import type { LockPeriod } from '../common/types';
import type {
  RewardReceipt,
  StakeReceipt,
  TransactionReceipt,
  UnstakeReceipt,
  WalletBalance
} from '../core/economics/types';
import type { AlephWallet } from '../infra/Wallet';
import type { TokenAmount } from './units';

// ═══════════════════════════════════════════════════════════════════════════
// PORT
// ═══════════════════════════════════════════════════════════════════════════

/** Optional metadata accepted by a transfer. */
export interface TransferOptions {
  purpose?: any;
  memo?: string;
}

/**
 * The subset of the wallet API the economy needs.
 *
 * Every method here actually mutates the ledger — there are no
 * record-only bookkeeping calls.
 */
export interface EconomyWallet {
  /** Ledger address (the KeyTriplet fingerprint). */
  readonly address: string;

  /** Current balance buckets, all in base units. */
  getBalance(): Promise<WalletBalance>;

  /** Debit this account and credit `to`. */
  transfer(to: string, amount: TokenAmount, options?: TransferOptions): Promise<TransactionReceipt>;

  /** Move `amount` from available into staked, locked for `lockPeriod`. */
  stake(amount: TokenAmount, lockPeriod: LockPeriod): Promise<StakeReceipt>;

  /** Return a matured stake to available. */
  unstake(stakeId: string): Promise<UnstakeReceipt>;

  /** Credit accrued staking rewards to available. */
  claimRewards(stakeId: string): Promise<RewardReceipt>;
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPILE-TIME INTEGRATION CHECK
// ═══════════════════════════════════════════════════════════════════════════

/** Fails to compile if `T` is not assignable to `U`. */
type AssertAssignable<T extends U, U> = T;

/**
 * `AlephWallet` must remain a superset of {@link EconomyWallet}. If the
 * wallet's API drifts, `npx tsc --noEmit` breaks here rather than at runtime
 * in the middle of a settlement.
 */
export type AlephWalletSatisfiesEconomyPort = AssertAssignable<AlephWallet, EconomyWallet>;
