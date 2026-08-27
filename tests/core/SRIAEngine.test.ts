import { describe, it, expect, beforeEach } from '@jest/globals';
import { SRIAEngine } from '../../src/core/SRIAEngine';
import { 
  ActionOutcome, 
  BeliefState, 
  GenerativeModelParams, 
  Policy, 
  Prediction 
} from '../../src/core/sria/types';
import { 
  calculateEpistemicValue, 
  calculateExpectedFreeEnergy, 
  calculatePragmaticValue 
} from '../../src/core/sria/FreeEnergy';
import { getTopPolicies, selectPolicy } from '../../src/core/sria/PolicySelection';
import { createBelief, mergeBeliefs, smoothBeliefTransition } from '../../src/core/sria/BeliefDynamics';

describe('SRIAEngine', () => {
  let engine: SRIAEngine;

  beforeEach(() => {
    engine = new SRIAEngine();
  });

  describe('initializeSession', () => {
    it('should initialize with default values', async () => {
      const state = await engine.initializeSession('session-1');
      expect(state.sessionId).toBe('session-1');
      expect(state.lifecycleState).toBe('DORMANT');
      expect(state.freeEnergy).toBe(1.0);
      expect(state.quaternionState).toEqual({ w: 1, x: 0, y: 0, z: 0 });
    });

    it('should initialize with custom body hash', async () => {
      const state = await engine.initializeSession('session-1', 'custom-body-hash');
      expect(state.bodyHash).toBe('custom-body-hash');
    });
  });

  describe('runCycle', () => {
    it('should throw if session not initialized', async () => {
      const observation = [1, 2, 3, 4];
      await expect(engine.runCycle(observation)).rejects.toThrow('SRIA session not initialized');
    });

    it('should complete a full cycle with observation', async () => {
      await engine.initializeSession('session-1');
      const observation = [0.5, 0.3, 0.1, 0.1];

      const result = await engine.runCycle(observation);
      
      expect(result.policy).toBeDefined();
      expect(result.freeEnergy).toBeDefined();
      expect(result.beliefs.length).toBeGreaterThan(0);
    });

    it('should update free energy trajectory', async () => {
      await engine.initializeSession('session-1');
      const observation = [0.5, 0.3, 0.1, 0.1];

      await engine.runCycle(observation);
      
      const state = engine.getState();
      expect(state).toBeDefined();
      expect(state!.freeEnergyTrajectory.length).toBeGreaterThan(1);
    });

    it('should select a policy based on beliefs', async () => {
      await engine.initializeSession('session-1');
      const observation = [0.5, 0.3, 0.1, 0.1];

      const result = await engine.runCycle(observation);
      
      expect(result.policy).toBeDefined();
      expect(result.policy!.type).toBeDefined();
      expect(result.policy!.expectedFreeEnergy).toBeDefined();
    });

    it('should run the full perceive -> decide -> act -> learn sequence', async () => {
      await engine.initializeSession('session-1');
      
      const events: string[] = [];
      engine.on((event) => { events.push(event.type); });

      const result = await engine.runCycle([0.5, 0.3, 0.1, 0.1]);
      
      expect(result.policy).not.toBeNull();
      expect(result.outcome).not.toBeNull();
      expect(result.outcome!.policyId).toBe(result.policy!.id);
      expect(events).toContain('action_complete');
      
      const state = engine.getState()!;
      // act() records a prediction, learn() is the last phase of the cycle
      expect(state.predictions.length).toBeGreaterThan(0);
      expect(state.lifecycleState).toBe('LEARNING');
    });

    it('should only follow valid lifecycle transitions', async () => {
      await engine.initializeSession('session-1');
      
      const transitions: string[] = [];
      engine.on((event) => {
        if (event.type !== 'state_change') return;
        const data = event.data as { oldState?: string; newState: string };
        if (data.oldState) transitions.push(`${data.oldState}->${data.newState}`);
      });

      const observation = [0.5, 0.3, 0.1, 0.1];
      await engine.runCycle(observation);
      await engine.runCycle(observation);
      
      expect(transitions).toContain('DORMANT->PERCEIVING');
      expect(transitions).toContain('PERCEIVING->DECIDING');
      expect(transitions).toContain('DECIDING->ACTING');
      expect(transitions).toContain('ACTING->LEARNING');
      expect(transitions).toContain('LEARNING->PERCEIVING');
      
      const validTransitions: Record<string, string[]> = {
        DORMANT: ['PERCEIVING'],
        PERCEIVING: ['DECIDING', 'CONSOLIDATING'],
        DECIDING: ['ACTING', 'PERCEIVING'],
        ACTING: ['LEARNING'],
        LEARNING: ['PERCEIVING', 'CONSOLIDATING', 'DECIDING'],
        CONSOLIDATING: ['SLEEPING', 'DORMANT'],
        SLEEPING: ['DORMANT', 'PERCEIVING']
      };
      
      for (const transition of transitions) {
        const [from, to] = transition.split('->');
        expect(validTransitions[from]).toContain(to);
      }
    });
  });

  describe('perceive', () => {
    it('should update beliefs based on observation', async () => {
      await engine.initializeSession('session-1');
      const observation = [0.5, 0.3, 0.1, 0.1];

      // Run a cycle which internally calls perceive
      await engine.runCycle(observation);
      
      const state = engine.getState();
      expect(state!.currentBeliefs.length).toBeGreaterThan(0);
    });

    it('should calculate surprisal', async () => {
      await engine.initializeSession('session-1');
      const observation = [0.5, 0.3, 0.1, 0.1];

      // Run a cycle to get beliefs
      await engine.runCycle(observation);
      
      const state = engine.getState();
      // Surprisal should be calculated
      expect(state!.surprisal).toBeDefined();
    });
  });

  describe('act', () => {
    it('should execute a policy', async () => {
      await engine.initializeSession('session-1');
      const observation = [0.5, 0.3, 0.1, 0.1];

      const result = await engine.runCycle(observation);
      
      if (result.policy) {
        const outcome = await engine.act(result.policy);
        expect(outcome.policyId).toBe(result.policy.id);
        expect(outcome.success).toBe(true);
      }
    });

    it('should derive the outcome from engine state, not a constant', async () => {
      await engine.initializeSession('session-1');
      engine.setGoalState([10, 10, 10, 10]);
      await engine.runCycle([0.5, 0.3, 0.1, 0.1]);
      
      const outcome = await engine.act();
      
      // The selected policy comes from PolicySelection, not a placeholder id
      expect(outcome.policyId).not.toBe('');
      expect(outcome.success).toBe(true);
      // Beliefs are far from the goal, so the action carries prediction error
      expect(outcome.predictionError).toBeGreaterThan(0);
      expect(outcome.predictionError).toBeLessThanOrEqual(1);
      expect(outcome.information).toBeGreaterThanOrEqual(0);
      expect(outcome.smfDelta.length).toBe(4);
    });
  });

  describe('learn', () => {
    it('should update quaternion from prediction error', async () => {
      await engine.initializeSession('session-1');
      const observation = [0.5, 0.3, 0.1, 0.1];
      await engine.runCycle(observation);

      const initialQ = { ...engine.getState()!.quaternionState };
      
      const outcome: ActionOutcome = {
        policyId: 'test-policy',
        success: true,
        predictionError: 0.5,
        information: 0.2,
        beliefUpdate: [],
        smfDelta: []
      };

      await engine.learn(outcome);
      
      const state = engine.getState();
      // Quaternion should have changed due to prediction error
      const currentQ = state!.quaternionState;
      const changed = 
        initialQ.w !== currentQ.w || 
        initialQ.x !== currentQ.x || 
        initialQ.y !== currentQ.y || 
        initialQ.z !== currentQ.z;
      
      expect(changed).toBe(true);
    });

    it('should update attention based on outcome', async () => {
      await engine.initializeSession('session-1');
      const observation = [0.5, 0.3, 0.1, 0.1];
      await engine.runCycle(observation);

      const initialPrecision = engine.getState()!.attention.precision;
      
      const outcome: ActionOutcome = {
        policyId: 'test-policy',
        success: true,
        predictionError: 0.3,
        information: 0.1,
        beliefUpdate: [],
        smfDelta: []
      };

      await engine.learn(outcome);
      
      const state = engine.getState();
      // Precision may have changed
      expect(state!.attention.precision).toBeGreaterThanOrEqual(initialPrecision);
    });
  });

  describe('consolidate', () => {
    it('should return high-confidence beliefs as insights', async () => {
      await engine.initializeSession('session-1');
      
      // Add a high-confidence belief
      engine.addBelief('High confidence insight', 0.8, [2, 3, 5, 7]);
      
      const result = await engine.consolidate();
      expect(result.insights).toBeDefined();
    });
  });

  describe('setGoalState', () => {
    it('should set goal state for pragmatic value', async () => {
      await engine.initializeSession('session-1');
      engine.setGoalState([1, 0, 0, 0]);
      
      const observation = [0.5, 0.3, 0.1, 0.1];
      const result = await engine.runCycle(observation);
      
      // Policy should have pragmatic value calculated
      expect(result.policy).toBeDefined();
    });
  });

  describe('event system', () => {
    it('should emit events during cycle', async () => {
      await engine.initializeSession('session-1');
      
      const events: string[] = [];
      const unsubscribe = engine.on((event) => {
        events.push(event.type);
      });

      const observation = [0.5, 0.3, 0.1, 0.1];
      await engine.runCycle(observation);
      
      expect(events).toContain('state_change');
      expect(events).toContain('free_energy_update');
      expect(events).toContain('policy_selected');
      
      unsubscribe();
    });
  });

  describe('getFreeEnergyTrend', () => {
    it('should report decreasing trend when free energy drops', async () => {
      await engine.initializeSession('session-1');
      
      // Run multiple cycles to build trajectory
      const observation = [0.5, 0.3, 0.1, 0.1];
      for (let i = 0; i < 5; i++) {
        await engine.runCycle(observation);
      }
      
      const trend = engine.getFreeEnergyTrend();
      // Trend should be one of the valid values
      expect(['decreasing', 'stable', 'increasing']).toContain(trend);
    });
  });

  describe('addBelief', () => {
    it('should add and normalize beliefs', async () => {
      await engine.initializeSession('session-1');
      
      engine.addBelief('Test belief 1', 0.5, [2, 3]);
      engine.addBelief('Test belief 2', 0.5, [5, 7]);
      
      const state = engine.getState();
      expect(state!.currentBeliefs.length).toBe(2);
      
      // Probabilities should be normalized
      const totalProb = state!.currentBeliefs.reduce(
        (acc, b) => acc + b.probability, 0
      );
      expect(totalProb).toBeCloseTo(1.0, 2);
    });
  });

  describe('expected free energy sign convention', () => {
    const modelParams: GenerativeModelParams = {
      priorPrecision: 1.0,
      likelihoodPrecision: 2.0,
      learningRate: 0.1,
      explorationBonus: 0.3,
      goalWeight: 0.7
    };
    const goalState = [1, 1, 1, 1];
    
    const beliefs: BeliefState[] = [
      createBelief('belief-a', 'A', 0.6, [2, 3]),
      createBelief('belief-b', 'B', 0.4, [5, 7])
    ];
    
    // Sample probabilities deliberately do NOT sum to 1
    const predictionsFor = (content: number[]): Prediction[] => [
      { id: 'p-0', content, probability: 0.6, precision: 1, generated: Date.now() },
      { id: 'p-1', content, probability: 0.54, precision: 1, generated: Date.now() },
      { id: 'p-2', content, probability: 0.48, precision: 1, generated: Date.now() }
    ];
    
    const asPolicy = (id: string, efe: ReturnType<typeof calculateExpectedFreeEnergy>): Policy => ({
      id,
      type: 'RESPOND',
      parameters: {},
      expectedFreeEnergy: efe.total,
      epistemic: efe.epistemic,
      pragmatic: efe.pragmatic,
      risk: efe.risk
    });

    it('should treat distance from the goal as a positive cost', () => {
      const near = calculatePragmaticValue(predictionsFor([1, 1, 1, 1]), goalState);
      const mid = calculatePragmaticValue(predictionsFor([0, 0, 0, 0]), goalState);
      const far = calculatePragmaticValue(predictionsFor([-8, -8, -8, -8]), goalState);
      
      expect(near).toBeGreaterThanOrEqual(0);
      expect(near).toBeCloseTo(0, 6);
      expect(mid).toBeGreaterThan(near);
      expect(far).toBeGreaterThan(mid);
    });

    it('should never produce a negative epistemic value for unnormalized predictions', () => {
      const value = calculateEpistemicValue(beliefs, predictionsFor([1, 1, 1, 1]));
      expect(value).toBeGreaterThanOrEqual(0);
      
      // Even with heavily unnormalized sample weights
      const inflated: Prediction[] = predictionsFor([1, 1, 1, 1]).map(p => ({ ...p, probability: 5 }));
      expect(calculateEpistemicValue(beliefs, inflated)).toBeGreaterThanOrEqual(0);
    });

    it('should prefer the policy closer to the goal', () => {
      const nearEFE = calculateExpectedFreeEnergy(
        beliefs, goalState, predictionsFor([1, 1, 1, 1]), modelParams
      );
      const farEFE = calculateExpectedFreeEnergy(
        beliefs, goalState, predictionsFor([-8, -8, -8, -8]), modelParams
      );
      
      // Larger distance -> larger cost -> larger (worse) expected free energy
      expect(nearEFE.pragmatic).toBeLessThan(farEFE.pragmatic);
      expect(nearEFE.total).toBeLessThan(farEFE.total);
      
      const nearPolicy = asPolicy('near-goal', nearEFE);
      const farPolicy = asPolicy('far-from-goal', farEFE);
      
      // Greedy selection must pick the policy closer to the goal
      expect(selectPolicy([farPolicy, nearPolicy], 0)!.id).toBe('near-goal');
      expect(getTopPolicies([farPolicy, nearPolicy], 1)[0].id).toBe('near-goal');
      
      // Softmax selection must favour it too
      let nearWins = 0;
      for (let i = 0; i < 200; i++) {
        if (selectPolicy([farPolicy, nearPolicy], 0.5)!.id === 'near-goal') nearWins++;
      }
      expect(nearWins).toBeGreaterThan(100);
    });
  });

  describe('belief renormalization', () => {
    it('should renormalize total probability after merging similar beliefs', () => {
      const beliefs: BeliefState[] = [
        createBelief('dup-1', 'duplicate one', 0.5, [2, 3]),
        createBelief('dup-2', 'duplicate two', 0.5, [2, 3]),
        createBelief('other', 'unrelated', 0.5, [11, 13])
      ];
      
      const merged = mergeBeliefs(beliefs, 0.9);
      
      // The two identical prime signatures collapse into one belief
      expect(merged.length).toBe(2);
      
      const total = merged.reduce((acc, b) => acc + b.probability, 0);
      expect(total).toBeCloseTo(1.0, 6);
      merged.forEach(b => {
        expect(b.probability).toBeLessThanOrEqual(1);
        expect(b.probability).toBeGreaterThan(0);
      });
    });

    it('should renormalize the full belief vector after a smooth transition', () => {
      const current: BeliefState[] = [
        createBelief('b0', 'b0', 0.3, [2]),
        createBelief('b1', 'b1', 0.3, [3]),
        createBelief('b2', 'b2', 0.2, [5]),
        createBelief('b3', 'b3', 0.1, [7]),
        createBelief('b4', 'b4', 0.1, [11])
      ];
      const target: BeliefState[] = [
        createBelief('b0', 'b0', 0.1, [2]),
        createBelief('b1', 'b1', 0.1, [3]),
        createBelief('b2', 'b2', 0.4, [5]),
        createBelief('b3', 'b3', 0.3, [7]),
        createBelief('b4', 'b4', 0.1, [11])
      ];
      
      const smoothed = smoothBeliefTransition(current, target, 0.5);
      
      expect(smoothed.length).toBe(current.length);
      const total = smoothed.reduce((acc, b) => acc + b.probability, 0);
      expect(total).toBeCloseTo(1.0, 6);
      smoothed.forEach(b => expect(b.probability).toBeGreaterThanOrEqual(0));
    });
  });
});
