import { SemanticDomain } from '../core/types';

// --- Interfaces ---

export interface TaskDefinition {
  id: string;
  name: string;
  description: string;
  version: string;
  ownerId: string;
  
  schedule: {
    type: 'CRON' | 'INTERVAL' | 'EVENT' | 'MANUAL';
    cron?: string;
    intervalMs?: number;
    eventPatterns?: string[];
    timezone?: string;
    enabled: boolean;
    maxConcurrent: number;
    retry: {
      maxAttempts: number;
      backoffMs: number;
      backoffMultiplier: number;
    };
  };
  
  inputs: {
    schema: {
      type: 'object';
      properties: Record<string, any>;
      required: string[];
    };
    example?: Record<string, any>;
    smfSignature?: number[];
  };
  
  output: {
    schema: { type: 'object'; properties: Record<string, any>; };
    format: 'JSON' | 'TEXT' | 'MARKDOWN' | 'HTML' | 'BINARY';
    storage: {
      toConversation?: boolean;
      toGMF?: boolean;
      toContentStore?: boolean;
      webhookUrl?: string;
    };
  };
  
  preferredModel: {
    provider: 'openai' | 'anthropic' | 'local-llama' | 'vertex-ai' | 'any';
    modelName?: string;
  };
  
  requiredServices: Array<{
    serviceId: string;
    required: boolean;
  }>;
  
  requiredSkills: string[];
  semanticDomain: SemanticDomain;
  requiredTier: 'Neophyte' | 'Adept' | 'Magus' | 'Archon';
  
  prompt: {
    system: string;
    userTemplate: string;
  };
  
  validation: {
    preExecution: Array<{ type: string; config?: any; errorMessage: string; }>;
    postExecution: Array<{ type: string; config?: any; errorMessage: string; action: 'FAIL' | 'WARN' | 'RETRY'; }>;
    minCoherence: number;
    timeoutMs: number;
  };
  
  tags: string[];
  category: string;
}

export interface TaskExecution {
  executionId: string;
  taskId: string;
  conversationId?: string;
  triggeredBy: string;
  input: Record<string, any>;
  status: 'PENDING' | 'VALIDATING' | 'RUNNING' | 'AWAITING_SERVICE' | 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'TIMEOUT';
  executorNodeId: string;
  sriaSessionId?: string;
  timeline: {
    scheduledAt: number;
    startedAt?: number;
    completedAt?: number;
  };
  attempts: {
    current: number;
    max: number;
    history: Array<{
      attemptNumber: number;
      startedAt: number;
      endedAt: number;
      status: string;
      error?: string;
    }>;
  };
  output?: {
    data: any;
    format: string;
    smfSignature: number[];
    coherence: number;
    /** True when no executor was wired in and the output is a simulation */
    simulated?: boolean;
  };
  error?: {
    code: string;
    message: string;
    recoverable: boolean;
  };
}

/**
 * Result returned by a task executor
 */
export interface TaskExecutionResult {
  output: any;
  coherence?: number;
  smf?: number[];
}

/**
 * Injectable execution hook - wires a real engine (e.g. SRIA) into task runs.
 */
export type TaskExecutor = (context: {
  task: TaskDefinition;
  execution: TaskExecution;
  prompt: string;
  input: Record<string, any>;
}) => Promise<TaskExecutionResult> | TaskExecutionResult;

/**
 * Injectable persistence hook for finished (or failed) executions.
 */
export type TaskResultSink = (execution: TaskExecution) => void | Promise<void>;

export interface TaskManagerOptions {
  /** Default executor for every task; can be overridden per execution */
  executor?: TaskExecutor;
  /** Where execution results are written. Defaults to a no-op. */
  resultSink?: TaskResultSink;
}

/**
 * Result sink that persists executions into Gun under tasks/<taskId>/executions/<executionId>
 */
export function createGunResultSink(gun: any): TaskResultSink {
  return (execution: TaskExecution) => {
    gun.get('tasks').get(execution.taskId).get('executions').get(execution.executionId).put({
      executionId: execution.executionId,
      taskId: execution.taskId,
      status: execution.status,
      startedAt: execution.timeline.startedAt ?? null,
      completedAt: execution.timeline.completedAt ?? null,
      attempts: execution.attempts.current,
      output: execution.output ? JSON.stringify(execution.output) : null,
      error: execution.error ? JSON.stringify(execution.error) : null
    });
  };
}

// --- Task Manager ---

export class TaskManager {
  private tasks: Map<string, TaskDefinition> = new Map();
  private executions: Map<string, TaskExecution> = new Map();
  private scheduleInterval: NodeJS.Timeout | null = null;
  private retryTimers: Set<NodeJS.Timeout> = new Set();
  private pendingRetries = new Map<string, { execution: TaskExecution; reject: (error: Error) => void }>();
  private nextRuns: Map<string, number> = new Map();
  private stopped = false;

  constructor(
      private gun: any, 
      private localNodeId: string,
      private options: TaskManagerOptions = {}
  ) {
      // Start scheduling loop
      this.scheduleInterval = setInterval(() => this.pollSchedules(), 60000); // Check every minute
  }

  public registerTask(task: TaskDefinition): void {
      this.tasks.set(task.id, task);
      
      // Seed the next run time for interval schedules
      if (task.schedule.type === 'INTERVAL' && task.schedule.intervalMs) {
          this.nextRuns.set(task.id, Date.now() + task.schedule.intervalMs);
      } else {
          this.nextRuns.delete(task.id);
      }
      
      // Persist to Gun
      this.gun.get('tasks').get(task.id).put({ definition: task });
  }

  /**
   * Run a task.
   *
   * The returned promise settles ONLY with the FINAL settled execution, after
   * the full attempt chain has run (retries exhausted or an attempt
   * succeeded). It never resolves while retries are still pending.
   *
   * - If the final attempt succeeds, resolves with the execution
   *   (`status === 'COMPLETED'`).
   * - If the final attempt fails, REJECTS with the last error; the failed
   *   `TaskExecution` (with `status`, `error` and attempt history populated)
   *   is attached to the error as `error.execution` for callers that catch.
   */
  public async executeTask(
      taskId: string, 
      input: Record<string, any>, 
      context: { triggeredBy: string; conversationId?: string; executor?: TaskExecutor }
  ): Promise<TaskExecution> {
      const task = this.tasks.get(taskId);
      if (!task) throw new Error(`Task ${taskId} not found`);

      const executionId = `exec-${taskId}-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
      const execution: TaskExecution = {
          executionId,
          taskId,
          conversationId: context.conversationId,
          triggeredBy: context.triggeredBy,
          input,
          status: 'PENDING',
          executorNodeId: this.localNodeId,
          timeline: { scheduledAt: Date.now() },
          attempts: { current: 0, max: task.schedule.retry.maxAttempts, history: [] }
      };
      
      this.executions.set(executionId, execution);

      // Await the WHOLE attempt chain: retries run inside this call, not in
      // detached background timers.
      await this.runWithRetries(execution, task, context.executor);
      
      if (execution.status === 'FAILED') {
          const error = new Error(execution.error?.message || `Task ${taskId} execution failed`);
          (error as any).execution = execution;
          throw error;
      }
      
      return execution;
  }

  /**
   * Drive one execution through its full attempt chain (initial attempt plus
   * any retries) without ever leaving this promise unresolved while retries
   * are still pending. Returns when the execution settles: an attempt
   * succeeded, retries are exhausted, or the manager was stopped.
   */
  private async runWithRetries(
      execution: TaskExecution,
      task: TaskDefinition,
      executor?: TaskExecutor
  ): Promise<void> {
      while (true) {
          await this.runExecution(execution, task, executor);

          if (execution.status !== 'FAILED') return;

          const canRetry = !this.stopped && execution.attempts.current < execution.attempts.max;
          if (!canRetry) return;

          const delay = task.schedule.retry.backoffMs * Math.pow(task.schedule.retry.backoffMultiplier, execution.attempts.current - 1);
          await this.sleepForRetry(execution, delay);
      }
  }

  /**
   * Cancellable retry backoff. Timers are tracked so stop() can cancel them;
   * cancellation rejects the tracked promise, which surfaces through
   * executeTask instead of being swallowed.
   */
  private sleepForRetry(execution: TaskExecution, delay: number): Promise<void> {
      return new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => {
              this.retryTimers.delete(timer);
              this.pendingRetries.delete(execution.executionId);
              resolve();
          }, delay);
          this.retryTimers.add(timer);
          this.pendingRetries.set(execution.executionId, { execution, reject });
      });
  }

  private async runExecution(
      execution: TaskExecution, 
      task: TaskDefinition,
      executor?: TaskExecutor
  ): Promise<TaskExecution> {
      execution.status = 'RUNNING';
      execution.timeline.startedAt = Date.now();
      execution.attempts.current++;
      
      const attemptNumber = execution.attempts.current;
      const attemptStartedAt = Date.now();

      try {
          // 1. Validation
          this.validateInput(execution.input, task.inputs.schema); // Mock validator
          
          // 2. Build Prompt
          const prompt = this.buildPrompt(task, execution.input);
          
          // 3. Execution: use the injected executor when one is wired in,
          //    otherwise fall back to a clearly-marked simulation.
          const run = executor || this.options.executor;
          const simulated = !run;
          const result: TaskExecutionResult = run
              ? await run({ task, execution, prompt, input: execution.input })
              : {
                  output: `Simulated output for ${task.name}`,
                  coherence: 0.95,
                  smf: new Array(16).fill(0)
                };

          // 4. Output processing
          execution.output = {
              data: result.output,
              format: task.output.format,
              smfSignature: result.smf || new Array(16).fill(0),
              coherence: result.coherence !== undefined ? result.coherence : 0,
              simulated
          };
          execution.status = 'COMPLETED';
          execution.timeline.completedAt = Date.now();
          execution.error = undefined;
          execution.attempts.history.push({
              attemptNumber,
              startedAt: attemptStartedAt,
              endedAt: execution.timeline.completedAt,
              status: 'COMPLETED'
          });

      } catch (error: any) {
          const message = error?.message || String(error);
          const canRetry = !this.stopped && execution.attempts.current < execution.attempts.max;
          
          execution.status = 'FAILED';
          execution.timeline.completedAt = Date.now();
          execution.error = {
              code: 'EXEC_ERR',
              message,
              recoverable: canRetry
          };
          execution.attempts.history.push({
              attemptNumber,
              startedAt: attemptStartedAt,
              endedAt: execution.timeline.completedAt,
              status: 'FAILED',
              error: message
          });

          // Retries are driven by runWithRetries, NOT background timers here.
      }

      // Persist the result through the injectable sink (default: no-op)
      await this.persistExecution(execution);

      return execution;
  }

  public getExecution(executionId: string): TaskExecution | undefined {
      return this.executions.get(executionId);
  }

  private async persistExecution(execution: TaskExecution): Promise<void> {
      const sink = this.options.resultSink;
      if (!sink) return;
      try {
          await sink(execution);
      } catch (error: any) {
          console.error(`Failed to persist execution ${execution.executionId}: ${error?.message || error}`);
      }
  }

  private validateInput(input: any, schema: any) {
      // Basic validation stub
      if (schema.required) {
          for (const req of schema.required) {
              if (input[req] === undefined) throw new Error(`Missing required input: ${req}`);
          }
      }
  }

  private buildPrompt(task: TaskDefinition, input: Record<string, any>): string {
      let prompt = task.prompt.userTemplate;
      for (const [key, value] of Object.entries(input)) {
        prompt = prompt.replace(new RegExp(`{{${key}}}`, 'g'), String(value));
      }
      return prompt;
  }

  // --- Scheduler ---

  private pollSchedules() {
      const now = new Date();
      const nowMs = now.getTime();
      
      for (const task of this.tasks.values()) {
          if (!task.schedule.enabled) continue;
          
          if (task.schedule.type === 'CRON' && task.schedule.cron) {
              if (this.isCronDue(task.schedule.cron, now)) {
                  this.triggerScheduledTask(task);
              }
          } else if (task.schedule.type === 'INTERVAL' && task.schedule.intervalMs) {
              const intervalMs = task.schedule.intervalMs;
              const nextRun = this.nextRuns.get(task.id);
              
              if (nextRun === undefined) {
                  // First sighting: schedule one interval out
                  this.nextRuns.set(task.id, nowMs + intervalMs);
                  continue;
              }
              
              if (nowMs >= nextRun) {
                  // Advance past any windows missed while stalled instead of
                  // firing once per missed window.
                  const missed = Math.floor((nowMs - nextRun) / intervalMs) + 1;
                  this.nextRuns.set(task.id, nextRun + missed * intervalMs);
                  this.triggerScheduledTask(task);
              }
          }
      }
  }

  /**
   * Next scheduled run for an INTERVAL task (epoch ms), if known
   */
  public getNextRun(taskId: string): number | undefined {
      return this.nextRuns.get(taskId);
  }

  private triggerScheduledTask(task: TaskDefinition) {
      // Check concurrency limits
      const inFlight = this.countInFlight(task.id);
      if (task.schedule.maxConcurrent > 0 && inFlight >= task.schedule.maxConcurrent) {
          console.warn(`Skipping ${task.name}: ${inFlight} execution(s) already in flight`);
          return;
      }
      
      console.log(`Triggering scheduled task: ${task.name}`);
      this.executeTask(task.id, {}, { triggeredBy: 'system-scheduler' })
          .catch((error: any) => {
              console.error(`Scheduled task ${task.id} failed: ${error?.message || error}`);
          });
  }

  private countInFlight(taskId: string): number {
      let count = 0;
      for (const execution of this.executions.values()) {
          if (execution.taskId !== taskId) continue;
          if (execution.status === 'PENDING' || execution.status === 'VALIDATING' ||
              execution.status === 'RUNNING' || execution.status === 'AWAITING_SERVICE') {
              count++;
          }
      }
      return count;
  }

  /**
   * Simple Cron Parser (Minute Hour Day Month DayOfWeek)
   * Supports: asterisk (all), value (exact), asterisk/step (step), list (1,2)
   */
  private isCronDue(cron: string, date: Date): boolean {
      const parts = cron.trim().split(/\s+/);
      if (parts.length !== 5) return false;

      const [min, hour, dom, mon, dow] = parts;
      
      // `oneBased` fields (day-of-month, month) start counting at 1, so */step
      // must be measured from the field minimum, not from zero.
      const match = (val: number, pattern: string, oneBased: boolean = false) => {
          if (pattern === '*') return true;
          if (pattern.includes('/')) {
              const [base, stepRaw] = pattern.split('/');
              const step = parseInt(stepRaw);
              if (!Number.isFinite(step) || step <= 0) return false;
              // Handle */step
              if (base === '*') {
                  const offset = oneBased ? val - 1 : val;
                  return offset >= 0 && offset % step === 0;
              }
              // Handle range/step? Simplified to just *
              return false;
          }
          if (pattern.includes(',')) {
              return pattern.split(',').map(Number).includes(val);
          }
          return parseInt(pattern) === val;
      };

      return match(date.getMinutes(), min) &&
             match(date.getHours(), hour) &&
             match(date.getDate(), dom, true) && // Day of month is 1-based
             match(date.getMonth() + 1, mon, true) && // Month is 0-indexed in JS, 1-based in cron
             match(date.getDay(), dow);
  }
  
  public stop() {
      this.stopped = true;
      
      if (this.scheduleInterval) {
          clearInterval(this.scheduleInterval);
          this.scheduleInterval = null;
      }
      
      // Cancel any pending retries so the process can exit cleanly. Cancelled
      // backoffs surface as rejections through executeTask (never swallowed),
      // and the execution is marked CANCELLED.
      for (const timer of this.retryTimers) {
          clearTimeout(timer);
      }
      this.retryTimers.clear();

      for (const [executionId, pending] of this.pendingRetries) {
          const execution = pending.execution;
          const error = new Error('Task manager stopped before retries completed');
          (error as any).execution = execution;
          execution.status = 'CANCELLED';
          execution.error = {
              code: 'CANCELLED',
              message: error.message,
              recoverable: false
          };
          pending.reject(error);
      }
      this.pendingRetries.clear();
  }
}
