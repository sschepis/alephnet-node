import { describe, it, expect, beforeEach, jest, afterEach } from '@jest/globals';
import { TaskManager, TaskDefinition } from '../../src/core/TaskManager';

describe('TaskManager', () => {
  let manager: TaskManager;
  let mockGun: any;

  const mockTask: TaskDefinition = {
    id: 'task-1',
    name: 'Test Task',
    description: 'A test task',
    version: '1.0',
    ownerId: 'user-1',
    schedule: {
      type: 'MANUAL',
      enabled: true,
      maxConcurrent: 1,
      retry: { maxAttempts: 3, backoffMs: 1000, backoffMultiplier: 2 }
    },
    inputs: {
      schema: {
        type: 'object',
        properties: { val: { type: 'string' } },
        required: ['val']
      }
    },
    output: {
      schema: { type: 'object', properties: {} },
      format: 'TEXT',
      storage: {}
    },
    preferredModel: { provider: 'any' },
    requiredServices: [],
    requiredSkills: [],
    semanticDomain: 'cognitive',
    requiredTier: 'Neophyte',
    prompt: {
      system: 'You are a bot',
      userTemplate: 'Input is {{val}}'
    },
    validation: {
      preExecution: [],
      postExecution: [],
      minCoherence: 0.5,
      timeoutMs: 5000
    },
    tags: [],
    category: 'test'
  };

  beforeEach(() => {
    jest.useFakeTimers();
    mockGun = {
      get: jest.fn().mockReturnThis(),
      put: jest.fn()
    };
    manager = new TaskManager(mockGun, 'local-node');
  });

  afterEach(() => {
    manager.stop();
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  describe('registerTask', () => {
    it('should store task and persist to Gun', () => {
      manager.registerTask(mockTask);
      expect(mockGun.get).toHaveBeenCalledWith('tasks');
      expect(mockGun.get).toHaveBeenCalledWith(mockTask.id);
      expect(mockGun.put).toHaveBeenCalledWith({ definition: mockTask });
    });
  });

  describe('executeTask', () => {
    beforeEach(() => {
      manager.registerTask(mockTask);
    });

    it('should execute successfully with valid input', async () => {
      const exec = await manager.executeTask('task-1', { val: 'test' }, { triggeredBy: 'test' });

      expect(exec.status).toBe('COMPLETED');
      expect(exec.output?.data).toContain('Simulated output');
      expect(exec.attempts.current).toBe(1);
    });

    it('should reject with the final error only after retries are exhausted', async () => {
      // Missing required 'val' fails validation on every attempt.
      const execPromise = manager.executeTask('task-1', {}, { triggeredBy: 'test' });

      // First retry (1000ms backoff) has not fired yet: nothing has settled.
      let settled = false;
      execPromise.then(() => { settled = true; }, () => { settled = true; });
      await jest.advanceTimersByTimeAsync(999);
      await Promise.resolve();
      expect(settled).toBe(false);

      // Exhaust the full attempt chain (1000ms + 2000ms backoff).
      await jest.advanceTimersByTimeAsync(5000);

      const error: any = await execPromise.catch((e: any) => e);
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toContain('Missing required input: val');

      // The failed execution is attached for callers that catch.
      expect(error.execution).toBeDefined();
      expect(error.execution.status).toBe('FAILED');
      expect(error.execution.attempts.current).toBe(3);
      expect(error.execution.attempts.history).toHaveLength(3);
    });

    it('should resolve with the final settled execution after transient retries', async () => {
      let calls = 0;
      const executor = async () => {
        calls++;
        if (calls < 3) throw new Error('transient failure');
        return { output: 'recovered', coherence: 1 };
      };

      const execPromise = manager.executeTask(
        'task-1',
        { val: 'x' },
        { triggeredBy: 'test', executor }
      );

      await jest.advanceTimersByTimeAsync(5000);

      const exec = await execPromise;
      expect(exec.status).toBe('COMPLETED');
      expect(exec.output?.data).toBe('recovered');
      expect(exec.attempts.current).toBe(3);
      expect(calls).toBe(3);
    });

    it('should not settle while retries are still pending', async () => {
      let calls = 0;
      const executor = async () => {
        calls++;
        throw new Error('boom');
      };

      const execPromise = manager.executeTask(
        'task-1',
        { val: 'x' },
        { triggeredBy: 'test', executor }
      );

      // Let the first retry fire (1000ms): attempt 2 has run and failed, but a
      // further retry (2000ms) is still scheduled, so the promise must stay
      // pending.
      let settled = false;
      execPromise.then(() => { settled = true; }, () => { settled = true; });
      await jest.advanceTimersByTimeAsync(1000);
      await Promise.resolve();
      expect(calls).toBe(2);
      expect(settled).toBe(false);

      // Exhaust the chain: the final attempt fails and executeTask rejects.
      await jest.advanceTimersByTimeAsync(5000);
      await expect(execPromise).rejects.toThrow('boom');
      expect(calls).toBe(3);
    });
  });

  describe('Retry Logic', () => {
    beforeEach(() => {
      manager.registerTask(mockTask);
    });

    it('should run the full attempt chain before settling', async () => {
      const execPromise = manager.executeTask('task-1', {}, { triggeredBy: 'test' });

      // Initial attempt has failed (validation); a retry is scheduled but the
      // returned promise must not resolve yet.
      let settled = false;
      execPromise.then(() => { settled = true; }, () => { settled = true; });
      await jest.advanceTimersByTimeAsync(1);
      await Promise.resolve();
      expect(settled).toBe(false);

      // First retry fires (1000ms backoff): attempt 2 fails, still pending.
      await jest.advanceTimersByTimeAsync(1000);
      await Promise.resolve();
      expect(settled).toBe(false);

      // Second retry fires (2000ms backoff): attempt 3 fails, the chain is
      // exhausted and the promise rejects with the final error.
      await jest.advanceTimersByTimeAsync(2000);
      const error: any = await execPromise.catch((e: any) => e);
      expect(error).toBeInstanceOf(Error);
      expect(error.execution.attempts.current).toBe(3);
      expect(error.execution.status).toBe('FAILED');
    });

    it('should reject (not console.error-swallow) when the final attempt fails', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      let calls = 0;
      const executor = async () => {
        calls++;
        throw new Error('terminal failure');
      };

      const execPromise = manager.executeTask(
        'task-1',
        { val: 'x' },
        { triggeredBy: 'test', executor }
      );
      // Attach the handler BEFORE the rejection fires so it is never
      // unhandled.
      const handled = execPromise.catch((e: any) => e);

      await jest.advanceTimersByTimeAsync(5000);

      const error: any = await handled;
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toContain('terminal failure');
      expect(calls).toBe(3);
      // The terminal failure surfaces through the tracked promise; it is not
      // swallowed by an internal console.error retry handler.
      expect(consoleSpy).not.toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });

  describe('Cron Scheduling', () => {
    // Scheduled runs are fired with empty input, so cron tasks use a schema
    // with no required fields (otherwise they would fail validation and spew
    // retry noise into the console during these tests).
    const cronTaskBase = {
      ...mockTask,
      inputs: { schema: { type: 'object', properties: {}, required: [] } }
    } as TaskDefinition;

    it('should trigger task when cron matches', () => {
      const cronTask = { ...cronTaskBase, id: 'cron-1', schedule: { ...mockTask.schedule, type: 'CRON', cron: '* * * * *' } } as TaskDefinition;
      manager.registerTask(cronTask);
      
      const spy = jest.spyOn(manager, 'executeTask');
      
      // Advance time by 60s (interval is 60s)
      jest.advanceTimersByTime(60000);
      
      expect(spy).toHaveBeenCalledWith('cron-1', {}, expect.objectContaining({ triggeredBy: 'system-scheduler' }));
    });

    it('should not trigger if cron does not match', () => {
        // Cron: 59th minute only
        const cronTask = { ...cronTaskBase, id: 'cron-2', schedule: { ...mockTask.schedule, type: 'CRON', cron: '59 * * * *' } } as TaskDefinition;
        manager.registerTask(cronTask);
        const spy = jest.spyOn(manager, 'executeTask');

        // Set date to a non-matching time
        jest.setSystemTime(new Date(2023, 1, 1, 12, 0, 0)); // 12:00
        
        // Trigger poll manually or via timer
        // pollSchedules uses "new Date()" so we need to mock system time
        jest.advanceTimersByTime(60000);
        
        expect(spy).not.toHaveBeenCalled();
    });
  });
  
  describe('isCronDue internal logic', () => {
      // Accessing private method via any cast for unit testing specific logic
      const callIsCronDue = (mgr: TaskManager, cron: string, date: Date): boolean => {
          return (mgr as any).isCronDue(cron, date);
      };
      
      it('should match exact values', () => {
          const date = new Date(2023, 0, 1, 10, 30); // Jan 1, 10:30
          expect(callIsCronDue(manager, '30 10 1 1 *', date)).toBe(true);
      });

      it('should match asterisks', () => {
          const date = new Date(2023, 0, 1, 10, 30);
          expect(callIsCronDue(manager, '* * * * *', date)).toBe(true);
      });

      it('should match steps', () => {
          const date = new Date(2023, 0, 1, 10, 30);
          expect(callIsCronDue(manager, '*/15 * * * *', date)).toBe(true); // 30 % 15 === 0
          expect(callIsCronDue(manager, '*/20 * * * *', date)).toBe(false); // 30 % 20 !== 0
      });
      
      it('should match lists', () => {
          const date = new Date(2023, 0, 1, 10, 30);
          expect(callIsCronDue(manager, '0,15,30,45 * * * *', date)).toBe(true);
      });
  });
});
