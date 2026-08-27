/**
 * Semantic Actions
 *
 * `semantic.think` / `semantic.compare` / `semantic.remember` /
 * `semantic.recall` / `semantic.introspect`, wired to the real
 * `SemanticObserver` + `SemanticMemoryBank`.
 *
 * When the tinyaleph kernel could not be loaded the node degrades the whole
 * semantic subsystem; every action here then returns the typed
 * `SUBSYSTEM_UNAVAILABLE` failure instead of a fabricated metric.
 *
 * Every metric returned by these actions comes from a real computation —
 * non-finite values are a typed error, never rounded into place.
 */

import type { ActionModule } from '../../app';
import type { SemanticSubsystem } from '../types';
import { SedenionMemoryField, SemanticObserver, type SemanticInput } from '../../semantic';
import { action, DomainActionError, unavailable } from './helpers';

// ═══════════════════════════════════════════════════════════════════════════
// DEPS
// ═══════════════════════════════════════════════════════════════════════════

export interface SemanticActionDeps {
  readonly semantic: SemanticSubsystem;
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function requireObserver(deps: SemanticActionDeps): SemanticObserver {
  if (deps.semantic.observer === null) {
    throw unavailable('semantic', deps.semantic.reason ?? 'semantic kernel failed to load');
  }
  return deps.semantic.observer;
}

function assertFiniteMetrics(metrics: Record<string, number>): void {
  for (const [key, value] of Object.entries(metrics)) {
    if (!Number.isFinite(value)) {
      throw new DomainActionError(
        'NON_FINITE_METRICS',
        `semantic engine produced a non-finite ${key}; refusing to report it`
      );
    }
  }
}

/** Strip class instances (SMF / hologram) from a trace: JSON-safe only. */
function sanitizeTrace(trace: {
  readonly id: string;
  readonly content: string;
  readonly smf: { toArray(): number[] };
  readonly createdAt: number;
  readonly accessCount: number;
  readonly strength: number;
  readonly importance: number;
  readonly consolidated: boolean;
  readonly smfEntropy: number;
}): Record<string, unknown> {
  return {
    id: trace.id,
    content: trace.content,
    smf: trace.smf.toArray(),
    createdAt: trace.createdAt,
    accessCount: trace.accessCount,
    strength: trace.strength,
    importance: trace.importance,
    consolidated: trace.consolidated,
    smfEntropy: trace.smfEntropy
  };
}

/**
 * Encode one text in a THROWAWAY observer and return the resulting SMF
 * orientation. Independent observers keep `compare` from disturbing the
 * node's live observer state.
 */
async function encodeToSmf(text: string): Promise<SedenionMemoryField> {
  const observer = new SemanticObserver();
  await observer.initialize();
  try {
    observer.processInput(text as SemanticInput);
    observer.tick();
    return observer.getMemoryField().clone();
  } finally {
    observer.dispose();
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// MODULE
// ═══════════════════════════════════════════════════════════════════════════

export function createSemanticActions(deps: SemanticActionDeps): ActionModule {
  return {
    namespace: 'semantic',
    actions: [
      // ── think ────────────────────────────────────────────────────────────
      action({
        name: 'semantic.think',
        description:
          'Feed text through the semantic engine and advance the observer. Returns real oscillator metrics, the safety verdict and any coherence moment.',
        input: {
          text: { type: 'string', required: true, minLength: 1, maxLength: 8192 },
          ticks: { type: 'integer', min: 1, max: 100, default: 4, description: 'Integration steps to run' },
          amplitude: { type: 'number', min: 0.01, max: 5, default: 0.5, description: 'Excitation amplitude' }
        },
        handler: (input) => {
          const observer = requireObserver(deps);
          observer.processInput(input.text as string, input.amplitude as number);
          const events = observer.runTicks(input.ticks as number);
          const last = events[events.length - 1];
          if (last === undefined) {
            throw new DomainActionError('NO_TICK', 'semantic engine produced no tick');
          }
          if (last.safety === null) {
            throw new DomainActionError('NO_SAFETY_VERDICT', 'semantic engine produced no safety verdict');
          }
          const metrics = {
            coherence: last.metrics.coherence,
            entropy: last.metrics.entropy,
            orderParameter: last.metrics.orderParameter
          };
          assertFiniteMetrics(metrics);
          const state = observer.getState();
          return {
            metrics,
            tickCount: last.tick,
            time: last.time,
            smfNormalizedEntropy: last.smfNormalizedEntropy,
            holographicDrift: last.holographicDrift,
            holographicEnergy: state.holographicEnergy,
            safety: {
              allowed: last.safety.allowed,
              violations: last.safety.violations.map((violation) => ({
                severity: violation.severity,
                reason: violation.reason
              }))
            },
            moment: last.moment === null ? null : { id: last.moment.id, coherence: last.moment.coherence },
            kernel: state.kernel
          };
        }
      }),

      // ── compare ──────────────────────────────────────────────────────────
      action({
        name: 'semantic.compare',
        description:
          'Compare two texts: each is encoded into a fresh observer and the SMF cosine similarity in [-1, 1] is returned.',
        input: {
          a: { type: 'string', required: true, minLength: 1, maxLength: 8192 },
          b: { type: 'string', required: true, minLength: 1, maxLength: 8192 }
        },
        handler: async (input) => {
          requireObserver(deps);
          const smfA = await encodeToSmf(input.a as string);
          const smfB = await encodeToSmf(input.b as string);
          const similarity = smfA.coherenceWith(smfB);
          assertFiniteMetrics({ similarity });
          return { similarity };
        }
      }),

      // ── remember ─────────────────────────────────────────────────────────
      action({
        name: 'semantic.remember',
        description:
          'Excite the field with content and store the resulting orientation as a memory trace.',
        input: {
          content: { type: 'string', required: true, minLength: 1, maxLength: 8192 }
        },
        handler: (input) => {
          const observer = requireObserver(deps);
          observer.processInput(input.content as string);
          observer.tick();
          const trace = observer.storeMemory(input.content as string);
          if (trace === null) {
            return { stored: false, reason: 'field_quiescent' };
          }
          return { stored: true, trace: sanitizeTrace(trace) };
        }
      }),

      // ── recall ───────────────────────────────────────────────────────────
      action({
        name: 'semantic.recall',
        description: 'Similarity-search stored memory traces, optionally cued by content.',
        input: {
          content: { type: 'string', minLength: 0, maxLength: 8192, description: 'Optional recall cue' },
          topK: { type: 'integer', min: 1, max: 50, default: 5 }
        },
        handler: (input) => {
          const observer = requireObserver(deps);
          const cue = (input.content as string | undefined) ?? undefined;
          const results = observer.recallMemory(cue, input.topK as number);
          return {
            results: results.map((result) => ({
              score: result.score,
              smfScore: result.smfScore,
              holographicScore: result.holographicScore,
              consolidated: result.consolidated,
              trace: sanitizeTrace(result.trace)
            }))
          };
        }
      }),

      // ── introspect ───────────────────────────────────────────────────────
      action({
        name: 'semantic.introspect',
        description: 'Aggregate observer state: coherence, entropy, memory counts, kernel status.',
        input: {},
        handler: () => {
          const observer = requireObserver(deps);
          return observer.getState();
        }
      })
    ]
  };
}
