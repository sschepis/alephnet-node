/**
 * Economy Actions
 *
 * `wallet.balance` / `wallet.transfer` / `wallet.stake` / `wallet.tier` and
 * `faucet.challenge` / `faucet.claim`. Two `ActionModule`s (the registry
 * enforces that every action is namespaced under its module).
 *
 * Amounts cross the HTTP boundary as DECIMAL STRINGS and are parsed with
 * `parseTokens` into bigint base units; responses format with
 * `formatTokens`. A JSON number — even an integer-looking one — is rejected
 * by the schema, and `parseTokens` rejects floats, exponents, separators and
 * garbage. No float ever touches a balance.
 *
 * The caller's wallet is derived from the VERIFIED public key, never from a
 * body field. When the node has no Gun ledger (or no faucet secret) every
 * action here returns the typed `SUBSYSTEM_UNAVAILABLE` failure.
 */

import type { ActionModule } from '../../app';
import type { EconomySubsystem } from '../types';
import type { AuthenticatedIdentity } from '../../app';
import type { LockPeriod } from '../../common/types';
import type { AlephWallet } from '../../infra/Wallet';
import {
  FaucetError,
  StakingError,
  TokenMathError,
  formatTokens,
  parseTokens,
  type StakingService,
  type TokenAmount
} from '../../economy';
import { action, DomainActionError, requireActor, requireCallerWallet, unavailable } from './helpers';

// ═══════════════════════════════════════════════════════════════════════════
// DEPS
// ═══════════════════════════════════════════════════════════════════════════

export interface EconomyActionDeps {
  readonly economy: EconomySubsystem;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function requireEconomy(deps: EconomyActionDeps): EconomySubsystem {
  if (!deps.economy.enabled) {
    throw unavailable('economy', deps.economy.reason ?? 'no Gun ledger supplied');
  }
  return deps.economy;
}

/**
 * The economy subsystem's availability gate: the registry evaluates it
 * BEFORE tier gating, so a missing/broken ledger is a 503
 * SUBSYSTEM_UNAVAILABLE, never masked by a per-caller tier 403.
 */
function economyAvailability(deps: EconomyActionDeps): { available: boolean; reason?: string } {
  return deps.economy.enabled
    ? { available: true }
    : { available: false, reason: deps.economy.reason ?? 'no Gun ledger supplied' };
}

/**
 * The faucet needs BOTH a Gun ledger and a secret. Either absence is
 * reported as a `faucet` subsystem failure with the specific reason, so the
 * caller learns exactly which prerequisite is missing.
 */
function requireFaucet(economy: EconomySubsystem) {
  if (economy.faucet === null) {
    throw unavailable(
      'faucet',
      economy.faucetReason ??
        (economy.enabled ? 'no faucet secret configured' : economy.reason ?? 'no Gun ledger supplied')
    );
  }
  return economy.faucet;
}

/** The faucet's availability gate, evaluated before tier gating. */
function faucetAvailability(deps: EconomyActionDeps): { available: boolean; reason?: string } {
  const economy = deps.economy;
  return economy.faucet !== null
    ? { available: true }
    : {
        available: false,
        reason:
          economy.faucetReason ??
          (economy.enabled
            ? 'no faucet secret configured'
            : economy.reason ?? 'no Gun ledger supplied')
      };
}

/** Decimal string -> base units, with typed failures. */
function parseAmount(raw: unknown, label = 'amount'): TokenAmount {
  try {
    return parseTokens(raw as string | bigint);
  } catch (error) {
    if (error instanceof TokenMathError) {
      throw new DomainActionError('INVALID_AMOUNT', error.message);
    }
    throw error;
  }
}

/**
 * The caller's StakingService. Distinguishes a disabled economy from a
 * caller whose identity cannot derive a wallet (dev auth bypass).
 */
async function requireStaking(
  economy: EconomySubsystem,
  identity: AuthenticatedIdentity
): Promise<StakingService> {
  const service = await economy.stakingFor(identity);
  if (service !== null) return service;
  if (!economy.enabled) {
    throw unavailable('economy', economy.reason ?? 'no Gun ledger supplied');
  }
  throw new DomainActionError(
    'IDENTITY_UNAVAILABLE',
    'identity unavailable: the authenticated identity carries no public key ' +
      '(dev auth bypass), so no ledger wallet can be derived'
  );
}

/**
 * The authenticated caller's wallet, with the same disabled-vs-identity
 * distinction (a disabled economy and a dev-bypass identity must never
 * surface as a raw 500).
 */
function requireWallet(economy: EconomySubsystem, identity: AuthenticatedIdentity): AlephWallet {
  return requireCallerWallet(economy, identity);
}

// ═══════════════════════════════════════════════════════════════════════════
// WALLET MODULE
// ═══════════════════════════════════════════════════════════════════════════

export function createWalletActions(deps: EconomyActionDeps): ActionModule {
  return {
    namespace: 'wallet',
    actions: [
      // ── wallet.balance ───────────────────────────────────────────────────
      action({
        name: 'wallet.balance',
        description: 'The authenticated caller\'s balance buckets, formatted as decimal strings.',
        input: {},
        availability: () => economyAvailability(deps),
        handler: async (_input, ctx) => {
          const identity = requireActor(ctx);
          requireEconomy(deps);
          const wallet = requireWallet(deps.economy, identity);
          const balance = await wallet.getBalance();
          return {
            address: wallet.address,
            available: formatTokens(balance.available),
            staked: formatTokens(balance.staked),
            total: formatTokens(balance.total),
            pendingUnstake: formatTokens(balance.pendingUnstake),
            reserved: formatTokens(balance.reserved),
            unclaimedRewards: formatTokens(balance.unclaimedRewards),
            stakingTier: balance.stakingTier
          };
        }
      }),

      // ── wallet.transfer ──────────────────────────────────────────────────
      action({
        name: 'wallet.transfer',
        description: 'Transfer tokens from the authenticated caller to another address. Amount is a decimal string.',
        input: {
          to: { type: 'string', required: true, minLength: 16, maxLength: 64, description: 'Recipient ledger address (fingerprint)' },
          amount: { type: 'string', required: true, minLength: 1, maxLength: 96, description: 'Decimal token amount, e.g. "1.5"' },
          memo: { type: 'string', maxLength: 200 }
        },
        availability: () => economyAvailability(deps),
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          requireEconomy(deps);
          const wallet = requireWallet(deps.economy, identity);

          const amount = parseAmount(input.amount, 'amount');
          if (amount <= 0n) {
            throw new DomainActionError('INVALID_AMOUNT', 'transfer amount must be positive');
          }
          const receipt = await wallet.transfer(input.to as string, amount, {
            purpose: 'WALLET_TRANSFER',
            memo: input.memo as string | undefined
          });
          return {
            transactionId: receipt.transactionId,
            status: receipt.status,
            from: wallet.address,
            to: input.to,
            amount: formatTokens(amount)
          };
        }
      }),

      // ── wallet.stake ─────────────────────────────────────────────────────
      action({
        name: 'wallet.stake',
        description: 'Stake tokens for at least the requested lock period. Amount is a decimal string.',
        input: {
          amount: { type: 'string', required: true, minLength: 1, maxLength: 96, description: 'Decimal token amount, e.g. "100"' },
          lockPeriod: { type: 'string', required: true, enum: ['7d', '30d', '90d', '180d', '365d'] }
        },
        availability: () => economyAvailability(deps),
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          requireEconomy(deps);
          const service = await requireStaking(deps.economy, identity);

          const amount = parseAmount(input.amount, 'amount');
          try {
            const result = await service.stake(amount, input.lockPeriod as LockPeriod);
            return {
              stakeId: result.stakeId,
              amount: formatTokens(result.amount),
              lockPeriod: result.lockPeriod,
              lockedUntil: result.lockedUntil,
              retainedExistingLock: result.retainedExistingLock,
              tier: result.tier,
              previousTier: result.previousTier,
              totalStaked: formatTokens(result.totalStaked),
              availableAfter: formatTokens(result.availableAfter),
              transactionId: result.transactionId
            };
          } catch (error) {
            if (error instanceof StakingError) {
              throw new DomainActionError(error.code, error.message);
            }
            throw error;
          }
        }
      }),

      // ── wallet.tier ──────────────────────────────────────────────────────
      action({
        name: 'wallet.tier',
        description: 'The authenticated caller\'s staking tier and what it takes to advance.',
        input: {},
        availability: () => economyAvailability(deps),
        handler: async (_input, ctx) => {
          const identity = requireActor(ctx);
          requireEconomy(deps);
          const service = await requireStaking(deps.economy, identity);
          const summary = await service.summary();
          return {
            address: summary.owner,
            tier: summary.tier,
            available: formatTokens(summary.available),
            staked: formatTokens(summary.staked),
            nextTier: summary.nextTier,
            stakeToNextTier: formatTokens(summary.stakeToNextTier),
            capabilities: summary.capabilities,
            rewardMultiplierBps: summary.rewardMultiplierBps
          };
        }
      })
    ]
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// FAUCET MODULE
// ═══════════════════════════════════════════════════════════════════════════

export function createFaucetActions(deps: EconomyActionDeps): ActionModule {
  return {
    namespace: 'faucet',
    actions: [
      // ── faucet.challenge (public) ────────────────────────────────────────
      action({
        name: 'faucet.challenge',
        description:
          'Issue a PoW challenge bound to a public key. Public: the key is the input, and the claim itself is authenticated.',
        input: {
          pub: { type: 'string', required: true, minLength: 16, maxLength: 128, description: 'Base64 raw 32-byte Ed25519 public key' }
        },
        requiresAuth: false,
        handler: (input) => {
          const faucet = requireFaucet(deps.economy);
          try {
            return faucet.issueChallenge(input.pub as string);
          } catch (error) {
            if (error instanceof FaucetError) {
              throw new DomainActionError(error.code, error.message);
            }
            throw error;
          }
        }
      }),

      // ── faucet.claim ─────────────────────────────────────────────────────
      action({
        name: 'faucet.claim',
        description:
          'Submit proof of work for a challenge and receive the fixed drip. The claim must be signed by the authenticated caller\'s key.',
        input: {
          challenge: { type: 'string', required: true, minLength: 1, maxLength: 512 },
          nonce: { type: 'string', required: true, minLength: 1, maxLength: 128 },
          signature: { type: 'string', required: true, minLength: 1, maxLength: 256 },
          pub: { type: 'string', required: true, minLength: 16, maxLength: 128 }
        },
        availability: () => faucetAvailability(deps),
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          const faucet = requireFaucet(deps.economy);
          if (input.pub !== identity.publicKey) {
            throw new DomainActionError(
              'IDENTITY_MISMATCH',
              'faucet claim pub must be the authenticated caller\'s public key'
            );
          }
          try {
            const result = await faucet.claim({
              challenge: input.challenge as string,
              nonce: input.nonce as string,
              signature: input.signature as string,
              pub: input.pub as string
            });
            return {
              success: true,
              amount: formatTokens(result.amount),
              fingerprint: result.fingerprint,
              transactionId: result.transactionId,
              claimedAt: result.claimedAt,
              nextClaimAt: result.nextClaimAt,
              treasuryRemaining: formatTokens(result.treasuryRemaining)
            };
          } catch (error) {
            if (error instanceof FaucetError) {
              throw new DomainActionError(error.code, error.message);
            }
            throw error;
          }
        }
      })
    ]
  };
}

/**
 * Convenience: both economy modules, for `createActionModules`.
 */
export function createEconomyActions(deps: EconomyActionDeps): readonly ActionModule[] {
  return [createWalletActions(deps), createFaucetActions(deps)];
}
