/**
 * Action Registry
 *
 * The "actions" API surface. An action is a named, schema-validated, auth- and
 * tier-gated operation (`semantic.think`, `social.friends.add`, `wallet.stake`).
 *
 * This module is the integration seam for the domain layers. It deliberately
 * imports NOTHING from src/semantic, src/social, src/economy or src/coherence:
 * those modules are wired in by the composition root, which builds
 * `ActionDefinition` objects (or an `ActionModule`) and registers them here.
 * The registry only knows about `ActionHandler` and `ActionContext`.
 */

import { ERROR_CODES } from '../common/constants';
import { createLogger, Logger } from '../common/logging';
import { Result, ok, err } from '../common/patterns/Result';
import { StakingTier, TIER_ORDER } from '../common/types';
import { AuthenticatedIdentity, HttpError } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// INPUT SCHEMA
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Supported field types. `bigintString` exists because token amounts cross the
 * wire as decimal strings, never as JSON numbers.
 */
export type ActionFieldType =
  | 'string'
  | 'number'
  | 'integer'
  | 'boolean'
  | 'object'
  | 'array'
  | 'bigintString'
  | 'unknown';

/**
 * Declarative constraint for one input field
 */
export interface ActionFieldSchema {
  readonly type: ActionFieldType;
  /** Defaults to false; a missing required field is a 400 */
  readonly required?: boolean;
  readonly description?: string;
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly min?: number;
  readonly max?: number;
  readonly pattern?: RegExp;
  readonly enum?: readonly string[];
  /** Element schema for `array` fields */
  readonly items?: ActionFieldSchema;
  readonly default?: unknown;
}

/**
 * Field name -> constraint
 */
export type ActionInputSchema = Readonly<Record<string, ActionFieldSchema>>;

/**
 * One validation failure
 */
export interface ActionFieldError {
  readonly field: string;
  readonly message: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// ACTION CONTEXT & HANDLER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Emitter handed to streaming actions so they can push progress without
 * knowing anything about SSE or WebSockets.
 */
export type ActionEmitter = (event: string, data: unknown) => void;

/**
 * Everything an action handler is allowed to know about its caller.
 *
 * `identity` is the verified identity — the fingerprint has already been
 * recomputed from the signing key, so handlers may treat it as authoritative.
 */
export interface ActionContext {
  readonly identity: AuthenticatedIdentity | null;
  readonly requestId: string;
  readonly logger: Logger;
  readonly receivedAt: number;
  /** Tier resolved for this caller, or null when unauthenticated */
  readonly tier: StakingTier | null;
  /** Aborted when the client disconnects or the server shuts down */
  readonly signal?: AbortSignal;
  /** Present for streaming actions */
  readonly emit?: ActionEmitter;
}

/**
 * An action implementation.
 *
 * Input is already validated against the declared schema when this is called.
 * Domain authors typically annotate the input parameter explicitly; the
 * registry coerces to `Record<string, unknown>` internally.
 */
export type ActionHandler<TInput = Record<string, unknown>, TOutput = unknown> = (
  input: TInput,
  ctx: ActionContext
) => TOutput | Promise<TOutput>;

/**
 * A registered action
 */
export interface ActionDefinition<TInput = Record<string, unknown>, TOutput = unknown> {
  /** Dotted, namespaced name, e.g. 'semantic.think' */
  readonly name: string;
  readonly description: string;
  readonly input: ActionInputSchema;
  /** Defaults to true — actions are authenticated unless declared otherwise */
  readonly requiresAuth?: boolean;
  /**
   * Minimum staking tier; defaults to 'Neophyte'.
   *
   * NOTE: when the tier's backing subsystem is disabled (e.g. the economy has
   * no ledger), tier resolution degrades to 'Neophyte', which would mask a
   * subsystem outage behind a personal 403. Declare `availability` for actions
   * that depend on an optional subsystem so that an outage is reported as
   * SUBSYSTEM_UNAVAILABLE *before* any tier check.
   */
  readonly requiredTier?: StakingTier;
  /**
   * Optional subsystem availability gate, evaluated AFTER auth but BEFORE the
   * tier check. Returning `{ available: false, reason }` produces a typed
   * SUBSYSTEM_UNAVAILABLE error that can never be masked by tier gating.
   */
  readonly availability?: () =>
    | Promise<{ available: boolean; reason?: string }>
    | { available: boolean; reason?: string };
  /** Declares that the handler will use ctx.emit */
  readonly streaming?: boolean;
  readonly handler: ActionHandler<TInput, TOutput>;
}

/**
 * A group of actions contributed by a domain module.
 *
 * This is the shape the lead should expose from each domain package:
 *
 *   export function createSemanticActions(deps): ActionModule
 */
export interface ActionModule {
  readonly namespace: string;
  readonly actions: readonly ActionDefinition<never, unknown>[];
}

/**
 * Public description of an action (safe to expose over HTTP)
 */
export interface ActionDescriptor {
  readonly name: string;
  readonly description: string;
  readonly requiresAuth: boolean;
  readonly requiredTier: StakingTier;
  readonly streaming: boolean;
  readonly input: Readonly<
    Record<
      string,
      {
        readonly type: ActionFieldType;
        readonly required: boolean;
        readonly description?: string;
      }
    >
  >;
}

// ═══════════════════════════════════════════════════════════════════════════
// TIER RESOLUTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Resolves a caller's staking tier.
 *
 * The economy layer implements this; the app layer only depends on the
 * interface so it never imports src/economy.
 */
export interface TierResolver {
  resolveTier(fingerprint: string): StakingTier | Promise<StakingTier>;
}

/**
 * Default resolver used until the economy module is wired in
 */
export class NeophyteTierResolver implements TierResolver {
  resolveTier(): StakingTier {
    return 'Neophyte';
  }
}

/**
 * True when `actual` satisfies `required`
 */
export function tierSatisfies(actual: StakingTier, required: StakingTier): boolean {
  return TIER_ORDER.indexOf(actual) >= TIER_ORDER.indexOf(required);
}

// ═══════════════════════════════════════════════════════════════════════════
// INVOCATION RESULTS
// ═══════════════════════════════════════════════════════════════════════════

export type ActionErrorCode =
  | 'ACTION_NOT_FOUND'
  | 'AUTH_REQUIRED'
  | 'SUBSYSTEM_UNAVAILABLE'
  | 'TIER_REQUIRED'
  | 'INVALID_INPUT'
  | 'HANDLER_FAILED';

/**
 * A failed invocation. `status` maps straight onto HTTP.
 */
export interface ActionError {
  readonly code: ActionErrorCode;
  readonly message: string;
  readonly status: number;
  readonly details?: unknown;
  /** Explicit AlephNet error code to surface over HTTP */
  readonly inputCode?: string;
}

/**
 * A successful invocation
 */
export interface ActionInvocation<TOutput = unknown> {
  readonly action: string;
  readonly output: TOutput;
  readonly durationMs: number;
  readonly tier: StakingTier | null;
}

// ═══════════════════════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Validate and coerce an action input against its schema.
 *
 * Unknown fields are dropped rather than rejected so a newer client cannot
 * break an older node, and no user value is ever passed through untyped.
 */
export function validateActionInput(
  schema: ActionInputSchema,
  input: unknown
): Result<Record<string, unknown>, readonly ActionFieldError[]> {
  const errors: ActionFieldError[] = [];

  if (input !== undefined && input !== null && (typeof input !== 'object' || Array.isArray(input))) {
    return err([{ field: '.', message: 'Input must be a JSON object' }]);
  }

  const source = (input ?? {}) as Record<string, unknown>;
  const output: Record<string, unknown> = {};

  for (const [field, spec] of Object.entries(schema)) {
    const raw = source[field];

    if (raw === undefined || raw === null) {
      if (spec.default !== undefined) {
        output[field] = spec.default;
        continue;
      }
      if (spec.required === true) {
        errors.push({ field, message: 'Field is required' });
      }
      continue;
    }

    const checked = validateField(field, spec, raw);
    if (checked.ok) {
      output[field] = checked.value;
    } else {
      errors.push(...checked.error);
    }
  }

  if (errors.length > 0) {
    return err(errors);
  }
  return ok(output);
}

function validateField(
  field: string,
  spec: ActionFieldSchema,
  raw: unknown
): Result<unknown, readonly ActionFieldError[]> {
  const fail = (message: string): Result<unknown, readonly ActionFieldError[]> =>
    err([{ field, message }]);

  switch (spec.type) {
    case 'string': {
      if (typeof raw !== 'string') return fail('Expected a string');
      if (spec.minLength !== undefined && raw.length < spec.minLength) {
        return fail(`Must be at least ${String(spec.minLength)} characters`);
      }
      if (spec.maxLength !== undefined && raw.length > spec.maxLength) {
        return fail(`Must be at most ${String(spec.maxLength)} characters`);
      }
      if (spec.pattern !== undefined && !spec.pattern.test(raw)) {
        return fail('Does not match the required format');
      }
      if (spec.enum !== undefined && !spec.enum.includes(raw)) {
        return fail(`Must be one of: ${spec.enum.join(', ')}`);
      }
      return ok(raw);
    }

    case 'number':
    case 'integer': {
      if (typeof raw !== 'number' || !Number.isFinite(raw)) return fail('Expected a number');
      if (spec.type === 'integer' && !Number.isInteger(raw)) return fail('Expected an integer');
      if (spec.min !== undefined && raw < spec.min) {
        return fail(`Must be >= ${String(spec.min)}`);
      }
      if (spec.max !== undefined && raw > spec.max) {
        return fail(`Must be <= ${String(spec.max)}`);
      }
      return ok(raw);
    }

    case 'boolean': {
      if (typeof raw !== 'boolean') return fail('Expected a boolean');
      return ok(raw);
    }

    case 'bigintString': {
      if (typeof raw !== 'string' || !/^\d{1,78}$/.test(raw)) {
        return fail('Expected a decimal integer string');
      }
      return ok(raw);
    }

    case 'object': {
      if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
        return fail('Expected an object');
      }
      return ok(raw);
    }

    case 'array': {
      if (!Array.isArray(raw)) return fail('Expected an array');
      if (spec.minLength !== undefined && raw.length < spec.minLength) {
        return fail(`Must contain at least ${String(spec.minLength)} items`);
      }
      if (spec.maxLength !== undefined && raw.length > spec.maxLength) {
        return fail(`Must contain at most ${String(spec.maxLength)} items`);
      }
      if (spec.items === undefined) return ok(raw);

      const items: unknown[] = [];
      const itemErrors: ActionFieldError[] = [];
      raw.forEach((element, index) => {
        const checked = validateField(`${field}[${String(index)}]`, spec.items as ActionFieldSchema, element);
        if (checked.ok) {
          items.push(checked.value);
        } else {
          itemErrors.push(...checked.error);
        }
      });
      if (itemErrors.length > 0) return err(itemErrors);
      return ok(items);
    }

    case 'unknown':
      return ok(raw);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ACTION NAME VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Action names are dotted and namespaced, with a lowercase leading namespace
 * and camelCase-or-snake_case leaf segments: 'wallet.stake',
 * 'coherence.submitClaim', 'social.friends.add'.
 *
 * camelCase leaves are permitted deliberately: the documented skill API uses
 * them (`coherence.submitClaim`, `wallet.claimRewards`), and the registry is
 * the public surface for those names.
 */
const ACTION_NAME_PATTERN = /^[a-z][a-z0-9]*(?:\.[a-z][a-zA-Z0-9_]*){1,4}$/;

/**
 * Action names must be dotted and namespaced, starting with a lowercase
 * namespace ('wallet.stake', 'coherence.submitClaim')
 */
export function isValidActionName(name: string): boolean {
  return ACTION_NAME_PATTERN.test(name);
}

// ═══════════════════════════════════════════════════════════════════════════
// REGISTRY
// ═══════════════════════════════════════════════════════════════════════════

interface NormalizedAction {
  readonly name: string;
  readonly description: string;
  readonly input: ActionInputSchema;
  readonly requiresAuth: boolean;
  readonly requiredTier: StakingTier;
  readonly availability?: ActionDefinition<Record<string, unknown>, unknown>['availability'];
  readonly streaming: boolean;
  readonly handler: ActionHandler<Record<string, unknown>, unknown>;
}

/**
 * Registry of named actions with auth, tier and schema gating.
 */
export class ActionRegistry {
  private readonly actions = new Map<string, NormalizedAction>();
  private readonly logger: Logger;
  private tierResolver: TierResolver;

  constructor(options: { logger?: Logger; tierResolver?: TierResolver } = {}) {
    this.logger = options.logger ?? createLogger('app:actions');
    this.tierResolver = options.tierResolver ?? new NeophyteTierResolver();
  }

  /**
   * Register a single action. Auth defaults to REQUIRED.
   */
  register<TInput, TOutput>(definition: ActionDefinition<TInput, TOutput>): this {
    if (!isValidActionName(definition.name)) {
      throw new Error(
        `Invalid action name '${definition.name}' (expected namespaced lowercase, e.g. 'wallet.stake')`
      );
    }
    if (this.actions.has(definition.name)) {
      throw new Error(`Action already registered: ${definition.name}`);
    }

    this.actions.set(definition.name, {
      name: definition.name,
      description: definition.description,
      input: definition.input,
      requiresAuth: definition.requiresAuth ?? true,
      requiredTier: definition.requiredTier ?? 'Neophyte',
      availability: definition.availability,
      streaming: definition.streaming ?? false,
      handler: definition.handler as ActionHandler<Record<string, unknown>, unknown>
    });

    return this;
  }

  /**
   * Register every action contributed by a domain module.
   *
   * Actions must be namespaced under `module.namespace`, which keeps ownership
   * obvious and prevents one domain from shadowing another's action.
   */
  registerModule(module: ActionModule): this {
    for (const action of module.actions) {
      if (!action.name.startsWith(`${module.namespace}.`)) {
        throw new Error(
          `Action '${action.name}' must be namespaced under '${module.namespace}.'`
        );
      }
      this.register(action);
    }
    this.logger.info('Registered action module', {
      namespace: module.namespace,
      actions: module.actions.length
    });
    return this;
  }

  /**
   * Replace the tier resolver (wired by the composition root once the economy
   * layer is available).
   */
  setTierResolver(resolver: TierResolver): this {
    this.tierResolver = resolver;
    return this;
  }

  has(name: string): boolean {
    return this.actions.has(name);
  }

  get size(): number {
    return this.actions.size;
  }

  /**
   * Public catalogue. Handlers and internal schema objects are not exposed.
   */
  describe(): readonly ActionDescriptor[] {
    return [...this.actions.values()]
      .map((action) => ({
        name: action.name,
        description: action.description,
        requiresAuth: action.requiresAuth,
        requiredTier: action.requiredTier,
        streaming: action.streaming,
        input: Object.fromEntries(
          Object.entries(action.input).map(([field, spec]) => [
            field,
            {
              type: spec.type,
              required: spec.required ?? false,
              ...(spec.description === undefined ? {} : { description: spec.description })
            }
          ])
        )
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  /**
   * Names only
   */
  list(): readonly string[] {
    return [...this.actions.keys()].sort();
  }

  /**
   * Invoke an action.
   *
   * Order: existence -> auth -> availability -> tier -> schema -> handler.
   * Handler failures are captured as `HANDLER_FAILED` with the real error
   * logged server-side and a generic message returned, so an action can never
   * leak internals.
   */
  async invoke(
    name: string,
    input: unknown,
    ctx: Omit<ActionContext, 'tier'>
  ): Promise<Result<ActionInvocation, ActionError>> {
    const action = this.actions.get(name);
    if (action === undefined) {
      return err({
        code: 'ACTION_NOT_FOUND',
        message: `Unknown action: ${name}`,
        status: 404
      });
    }

    if (action.requiresAuth && ctx.identity === null) {
      return err({
        code: 'AUTH_REQUIRED',
        message: 'This action requires an authenticated caller',
        status: 401
      });
    }

    // Subsystem availability is evaluated BEFORE tier gating so that an
    // optional-dependency outage is never masked as a personal tier shortage.
    if (action.availability !== undefined) {
      let availability: { available: boolean; reason?: string };
      try {
        availability = await action.availability();
      } catch (error) {
        this.logger.error(
          'Availability check failed',
          error instanceof Error ? error : new Error('availability check failed'),
          { requestId: ctx.requestId, action: name }
        );
        availability = { available: false, reason: 'availability check failed' };
      }
      if (!availability.available) {
        return err({
          code: 'SUBSYSTEM_UNAVAILABLE',
          message: availability.reason ?? `Action ${name} is unavailable`,
          status: 503
        });
      }
    }

    let tier: StakingTier | null = null;
    if (ctx.identity !== null) {
      try {
        tier = await this.tierResolver.resolveTier(ctx.identity.fingerprint);
      } catch (error) {
        this.logger.error(
          'Tier resolution failed',
          error instanceof Error ? error : new Error('tier resolution failed'),
          { requestId: ctx.requestId, action: name }
        );
        tier = 'Neophyte';
      }
    }

    if (action.requiredTier !== 'Neophyte') {
      if (tier === null || !tierSatisfies(tier, action.requiredTier)) {
        return err({
          code: 'TIER_REQUIRED',
          message: `Action requires the ${action.requiredTier} tier`,
          status: 403,
          details: { requiredTier: action.requiredTier, currentTier: tier }
        });
      }
    }

    const validated = validateActionInput(action.input, input);
    if (!validated.ok) {
      return err({
        code: 'INVALID_INPUT',
        message: 'Action input failed validation',
        status: 400,
        details: validated.error,
        inputCode: ERROR_CODES.E_VALIDATION_SCHEMA
      });
    }

    const startedAt = Date.now();
    try {
      const output = await action.handler(validated.value, { ...ctx, tier });
      return ok({
        action: name,
        output,
        durationMs: Date.now() - startedAt,
        tier
      });
    } catch (error) {
      this.logger.error(
        'Action handler failed',
        error instanceof Error ? error : new Error('handler failed'),
        { requestId: ctx.requestId, action: name, durationMs: Date.now() - startedAt }
      );
      return err({
        code: 'HANDLER_FAILED',
        message: 'Internal Server Error',
        status: 500
      });
    }
  }

  /**
   * Convert an ActionError into the HTTP error the router understands
   */
  static toHttpError(error: ActionError): HttpError {
    const codeMap: Record<ActionErrorCode, string> = {
      ACTION_NOT_FOUND: ERROR_CODES.E_SERVICE_NOT_FOUND,
      AUTH_REQUIRED: ERROR_CODES.E_AUTH_PERMISSION_DENIED,
      SUBSYSTEM_UNAVAILABLE: ERROR_CODES.E_SERVICE_UNAVAILABLE,
      TIER_REQUIRED: ERROR_CODES.E_AUTH_TIER_REQUIRED,
      INVALID_INPUT: ERROR_CODES.E_VALIDATION_INPUT,
      HANDLER_FAILED: ERROR_CODES.E_INTERNAL_UNKNOWN
    };

    return new HttpError(
      error.status,
      error.inputCode ?? codeMap[error.code],
      error.message,
      { details: error.details }
    );
  }
}
