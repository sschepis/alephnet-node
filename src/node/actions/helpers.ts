/**
 * Action Helpers
 *
 * Plumbing shared by every action module in this layer:
 *
 *   - a uniform result envelope: `{ ok: true, value } | { ok: false, code,
 *     message, subsystem }`. Domain failures (insufficient funds, denied
 *     access, invalid amounts, unavailable subsystems) are TYPED and
 *     client-visible; unexpected errors still throw so the registry logs the
 *     real cause and answers a generic 500 without leaking internals.
 *
 *   - `bindEnvelope`: the bridge between HTTP authentication and the social
 *     layer's SignedAction envelopes. The client signs the envelope with its
 *     own Ed25519 key; this layer verifies it and REQUIRES the envelope's
 *     author to be the HTTP-authenticated caller. The actor is therefore
 *     always `ctx.identity.fingerprint` — input fields can never name one.
 */

import type { StakingTier } from '../../common/types';
import type {
  ActionContext,
  ActionDefinition,
  ActionHandler,
  ActionInputSchema,
  AuthenticatedIdentity
} from '../../app';
import type { ActionVerifier, SignedAction, VerifiedAction } from '../../social';
import type { AlephWallet } from '../../infra/Wallet';
import type { EconomySubsystem } from '../types';

// ═══════════════════════════════════════════════════════════════════════════
// RESULT ENVELOPE
// ═══════════════════════════════════════════════════════════════════════════

/** A failed action. Never a fake success. */
export interface ActionFailure {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
  /** Subsystem this failure belongs to (set for unavailable subsystems). */
  readonly subsystem?: string;
  readonly details?: unknown;
}

/** A successful action. */
export interface ActionSuccess<T> {
  readonly ok: true;
  readonly value: T;
}

export type ActionResult<T> = ActionSuccess<T> | ActionFailure;

/**
 * A typed domain failure that is safe to surface to the caller.
 *
 * Throwing one of these produces `{ ok: false, code, message }`; throwing
 * anything else remains a server-side 500 (the registry logs the real error).
 */
export class DomainActionError extends Error {
  readonly code: string;
  readonly subsystem?: string;
  readonly details?: unknown;

  constructor(
    code: string,
    message: string,
    options: { subsystem?: string; details?: unknown } = {}
  ) {
    super(message);
    this.name = 'DomainActionError';
    this.code = code;
    this.subsystem = options.subsystem;
    this.details = options.details;
  }
}

/**
 * The typed "this subsystem is disabled" failure. Every optional subsystem
 * degrades through this — the caller always learns WHY, never a fabricated
 * result.
 */
export function unavailable(subsystem: string, reason: string): DomainActionError {
  return new DomainActionError('SUBSYSTEM_UNAVAILABLE', `${subsystem} is unavailable: ${reason}`, {
    subsystem
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// HANDLER WRAPPING
// ═══════════════════════════════════════════════════════════════════════════

type RawHandler<TInput, TOutput> = (
  input: TInput,
  ctx: ActionContext
) => TOutput | Promise<TOutput>;

/**
 * Wrap a raw handler so `DomainActionError`s become typed result failures.
 */
function guarded<TOutput>(handler: RawHandler<Record<string, unknown>, TOutput>): ActionHandler {
  return async (input, ctx) => {
    try {
      const value = await handler(input, ctx);
      return { ok: true, value } as ActionSuccess<TOutput>;
    } catch (error) {
      if (error instanceof DomainActionError) {
        const failure: ActionFailure = {
          ok: false,
          code: error.code,
          message: error.message,
          ...(error.subsystem === undefined ? {} : { subsystem: error.subsystem }),
          ...(error.details === undefined ? {} : { details: error.details })
        };
        return failure;
      }
      throw error;
    }
  };
}

/**
 * Build a single action definition with the uniform result envelope applied.
 */
export function action<TInput extends Record<string, unknown>, TOutput>(definition: {
  readonly name: string;
  readonly description: string;
  readonly input: ActionInputSchema;
  readonly requiresAuth?: boolean;
  readonly requiredTier?: StakingTier;
  /**
   * Optional subsystem availability gate, evaluated by the registry AFTER
   * auth but BEFORE the tier check, so an optional-subsystem outage is
   * reported as SUBSYSTEM_UNAVAILABLE (503) and can never be masked by a
   * tier-gating 403.
   */
  readonly availability?: ActionDefinition<Record<string, unknown>, unknown>['availability'];
  readonly streaming?: boolean;
  readonly handler: (input: TInput, ctx: ActionContext) => TOutput | Promise<TOutput>;
}): ActionDefinition<Record<string, unknown>, unknown> {
  return {
    name: definition.name,
    description: definition.description,
    input: definition.input,
    ...(definition.requiresAuth === undefined ? {} : { requiresAuth: definition.requiresAuth }),
    ...(definition.requiredTier === undefined ? {} : { requiredTier: definition.requiredTier }),
    ...(definition.availability === undefined ? {} : { availability: definition.availability }),
    ...(definition.streaming === undefined ? {} : { streaming: definition.streaming }),
    handler: guarded(definition.handler as RawHandler<Record<string, unknown>, TOutput>)
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// ACTOR IDENTITY
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The verified caller. Requires-auth actions always have one (the registry
 * enforces it); this turns the type into a runtime guarantee.
 */
export function requireActor(ctx: ActionContext): AuthenticatedIdentity {
  if (ctx.identity === null) {
    throw new DomainActionError(
      'AUTH_REQUIRED',
      'This action requires an authenticated caller'
    );
  }
  return ctx.identity;
}

/**
 * The authenticated caller's wallet.
 *
 * Fails with the typed economy unavailability when the subsystem is off, and
 * with a typed IDENTITY_UNAVAILABLE when the economy is on but the caller's
 * identity cannot produce a wallet — i.e. a dev-auth-bypass identity, which
 * carries no public key and therefore no derivable ledger address.
 */
export function requireCallerWallet(
  economy: EconomySubsystem,
  identity: AuthenticatedIdentity
): AlephWallet {
  const wallet = economy.walletFor(identity);
  if (wallet !== null) return wallet;
  if (!economy.enabled) {
    throw unavailable('economy', economy.reason ?? 'no Gun ledger supplied');
  }
  throw new DomainActionError(
    'IDENTITY_UNAVAILABLE',
    'identity unavailable: the authenticated identity carries no public key ' +
      '(dev auth bypass), so no ledger wallet can be derived'
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// SIGNED ENVELOPE BINDING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Verify a client-supplied SignedAction envelope and bind it to the
 * HTTP-authenticated caller.
 *
 * The envelope travels in the action input (the node never holds client
 * private keys, so it cannot sign on a caller's behalf). Checks:
 *
 *   1. the envelope signature, action name, freshness and nonce are valid;
 *   2. the envelope's verified author equals `ctx.identity.fingerprint`.
 *
 * Only after BOTH checks does the envelope reach the domain layer, which
 * re-verifies it with the shared verifier before mutating anything.
 *
 * `verifier` must be the node's dedicated binding verifier (its own nonce
 * store), not the shared one — otherwise the domain's own verification would
 * see the nonce as replayed.
 */
export async function bindEnvelope<P>(
  verifier: ActionVerifier,
  ctx: ActionContext,
  envelope: unknown,
  expectedActions: readonly string[]
): Promise<VerifiedAction<P>> {
  const actor = requireActor(ctx);
  const checked = await verifier.check(envelope as SignedAction<P>, expectedActions);
  if (!checked.valid) {
    throw new DomainActionError('SIGNED_ACTION_INVALID', checked.error, {
      details: { code: checked.code }
    });
  }
  const verified = checked.verified;
  if (verified.author.fingerprint !== actor.fingerprint) {
    throw new DomainActionError(
      'IDENTITY_MISMATCH',
      'Envelope author does not match the authenticated caller',
      {
        details: {
          envelopeAuthor: verified.author.fingerprint,
          caller: actor.fingerprint
        }
      }
    );
  }
  return verified;
}
