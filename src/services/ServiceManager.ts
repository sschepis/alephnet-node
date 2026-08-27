import { SemanticDomain } from '../core/types';
import { AlephWallet } from '../infra/Wallet';
import { Subscription } from '../common';
import { generateId } from '../common/hash';

// --- Interfaces ---

export interface ServiceDefinition {
  id: string;
  name: string;
  description: string;
  version: string;
  providerNodeId: string;
  providerUserId: string;
  
  access: {
    visibility: 'PUBLIC' | 'RESTRICTED' | 'PRIVATE';
    allowedNodes?: string[];
    allowedUsers?: string[];
    allowedTiers?: Array<'Neophyte' | 'Adept' | 'Magus' | 'Archon'>;
    minCoherence?: number;
    minReputation?: number;
    rateLimit: {
      requestsPerMinute: number;
      requestsPerHour: number;
      requestsPerDay: number;
      burstLimit: number;
    };
    geoRestrictions?: {
      allowedCountries?: string[];
      blockedCountries?: string[];
    };
  };
  
  pricing: {
    model: 'FREE' | 'PER_CALL' | 'SUBSCRIPTION' | 'STAKE_GATED' | 'HYBRID';
    perCallCost?: number;
    subscriptionTiers?: Array<{
      name: string;
      price: number;
      period: 'DAILY' | 'WEEKLY' | 'MONTHLY' | 'YEARLY';
      limits: { requestsPerPeriod: number; priorityLevel: number; };
    }>;
    minStake?: number;
    freeTier?: { requestsPerDay: number; features: string[]; };
    acceptedPayments: Array<'ALEPH' | 'STAKED_ALEPH' | 'USD'>;
    revenueDistribution: { provider: number; network: number; stakers: number; };
  };
  
  interface: {
    protocol: 'REST' | 'GRAPHQL' | 'WEBSOCKET' | 'GRPC' | 'GUN_SYNC';
    baseUrl?: string;
    authentication: 'NONE' | 'API_KEY' | 'KEYTRIPLET' | 'OAUTH' | 'STAKED_IDENTITY';
    endpoints: Array<{
      name: string;
      description: string;
      method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
      path?: string;
      inputSchema: Record<string, any>;
      outputSchema: Record<string, any>;
      costMultiplier: number;
    }>;
    semanticDomain: SemanticDomain;
    smfAxes: number[];
  };
  
  sla: {
    uptimeGuarantee: number;
    maxResponseTimeMs: number;
    dataRetention: { logsRetentionDays: number; resultsRetentionDays: number; };
    supportLevel: 'NONE' | 'COMMUNITY' | 'EMAIL' | 'PRIORITY';
    slaViolationCompensation: { uptimeViolation: number; responseTimeViolation: number; };
  };
  
  tags: string[];
  category: string;
  documentationUrl?: string;
  iconUrl?: string;
  status: 'DRAFT' | 'ACTIVE' | 'DEPRECATED' | 'SUSPENDED';
  createdAt: number;
  updatedAt: number;
  smfSignature: number[];
}

export interface ServiceInstance {
  serviceId: string;
  nodeId: string;
  status: 'STARTING' | 'RUNNING' | 'DRAINING' | 'STOPPED' | 'ERROR';
  health: {
    healthy: boolean;
    lastHealthCheck: number;
    consecutiveFailures: number;
    uptimeMs: number;
    startedAt: number;
  };
  metrics: {
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    averageResponseTimeMs: number;
    p95ResponseTimeMs: number;
    p99ResponseTimeMs: number;
    requestsPerSecond: number;
  };
  economics: {
    totalRevenue: number;
    pendingPayout: number;
    lastPayoutAt: number;
    activeSubscribers: number;
    totalSubscribers: number;
  };
  connections: {
    active: number;
    maxConcurrent: number;
  };
}

// --- Errors & Access Context ---

/**
 * Machine-readable reasons a service call can be rejected.
 */
export type ServiceCallErrorCode =
  | 'SERVICE_NOT_FOUND'
  | 'SERVICE_SUSPENDED'
  | 'ENDPOINT_NOT_FOUND'
  | 'NO_HEALTHY_INSTANCE'
  | 'ACCESS_UNDECLARED'
  | 'VISIBILITY_DENIED'
  | 'NODE_NOT_ALLOWED'
  | 'USER_NOT_ALLOWED'
  | 'TIER_NOT_ALLOWED'
  | 'REPUTATION_TOO_LOW'
  | 'REPUTATION_UNVERIFIABLE'
  | 'COHERENCE_TOO_LOW'
  | 'COHERENCE_UNVERIFIABLE'
  | 'PRICING_UNDECLARED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'COST_EXCEEDED'
  | 'RPC_FAILED';

/**
 * Typed error for every service-call policy violation.
 */
export class ServiceCallError extends Error {
  constructor(
    public readonly code: ServiceCallErrorCode,
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ServiceCallError';
  }
}

/**
 * Supplies the caller-side signals that access rules are checked against.
 * Both lookups return null when the value cannot be established, in which
 * case a service that requires a minimum fails closed.
 */
export interface IServiceAccessContextProvider {
  getReputation(userId: string): Promise<number | null>;
  getCoherence(userId: string): Promise<number | null>;
}

/** Window used for the `burstLimit` check. */
const BURST_WINDOW_MS = 1_000;
const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

// --- Manager ---

export class ServiceManager {
  /** Local best-effort call log per `serviceId:callerId`, for rate limiting. */
  private rateLimitLog = new Map<string, number[]>();

  constructor(
      private gun: any,
      private wallet: AlephWallet,
      private localNodeId: string,
      private accessContext?: IServiceAccessContextProvider
  ) {}

  /**
   * Register a new service.
   */
  public async registerService(definition: ServiceDefinition): Promise<{ serviceId: string; registrationFee: number }> {
      // Validate...
      // Store in Gun
      await new Promise<void>((resolve) => {
          this.gun.get('services').get(definition.id).put({ definition }, (ack: any) => resolve());
      });

      // Register instance locally
      await this.registerInstance(definition.id);

      return { serviceId: definition.id, registrationFee: 10 }; // Fee logic stub
  }

  /**
   * Register a running instance of a service on this node.
   */
  public async registerInstance(serviceId: string): Promise<void> {
      const instance: ServiceInstance = {
          serviceId,
          nodeId: this.localNodeId,
          status: 'RUNNING',
          health: {
              healthy: true,
              lastHealthCheck: Date.now(),
              consecutiveFailures: 0,
              uptimeMs: 0,
              startedAt: Date.now()
          },
          metrics: {
              totalRequests: 0,
              successfulRequests: 0,
              failedRequests: 0,
              averageResponseTimeMs: 0,
              p95ResponseTimeMs: 0,
              p99ResponseTimeMs: 0,
              requestsPerSecond: 0
          },
          economics: {
              totalRevenue: 0,
              pendingPayout: 0,
              lastPayoutAt: 0,
              activeSubscribers: 0,
              totalSubscribers: 0
          },
          connections: {
              active: 0,
              maxConcurrent: 100
          }
      };

      await new Promise<void>((resolve) => {
          this.gun.get('services').get(serviceId).get('instances').get(this.localNodeId).put(instance, (ack: any) => resolve());
      });
  }

  /**
   * Search for services.
   */
  public async search(query: {
    text?: string;
    tags?: string[];
    category?: string;
    semanticDomain?: SemanticDomain;
  }): Promise<ServiceDefinition[]> {
      // Mock search - in real Gun, we'd use index or map
      // Here we assume we can scan `services` node or rely on tags index
      return new Promise((resolve) => {
          const results: ServiceDefinition[] = [];
          this.gun.get('services').map().once((data: any) => {
              if (data && data.definition) {
                  const def = data.definition as ServiceDefinition;
                  // Simple filtering
                  if (query.category && def.category !== query.category) return;
                  if (query.tags && !query.tags.some(t => def.tags.includes(t))) return;
                  results.push(def);
              }
          });
          setTimeout(() => resolve(results), 500);
      });
  }

  /**
   * Call a service.
   *
   * The service definition's own access policy is enforced here — visibility,
   * allow-lists, staking tier, coherence/reputation minimums and rate limits —
   * before any RPC is dispatched or any payment is authorized.
   */
  public async callService<T>(
      serviceId: string,
      endpointName: string,
      input: Record<string, any>,
      options?: { maxCost?: number }
  ): Promise<{ result: T; cost: number; executorNode: string }> {
      // 1. Get Service Def
      const service = await this.getServiceDefinition(serviceId);
      if (!service) throw new ServiceCallError('SERVICE_NOT_FOUND', `Service ${serviceId} not found`);

      // 2. Find Endpoint
      const endpoint = service.interface?.endpoints?.find(e => e.name === endpointName);
      if (!endpoint) {
          throw new ServiceCallError('ENDPOINT_NOT_FOUND', `Endpoint ${endpointName} not found`, { serviceId });
      }

      // 3. Enforce the declared access policy (visibility / allow-lists /
      //    tier / coherence / reputation) before doing any work.
      await this.enforceAccess(service);

      // 4. Enforce rate limits (counted only once access is granted).
      this.enforceRateLimit(service);

      // 5. Find Instance
      const instance = await this.findHealthyInstance(serviceId);
      if (!instance) {
          throw new ServiceCallError('NO_HEALTHY_INSTANCE', `No healthy instances for ${serviceId}`, { serviceId });
      }

      // 6. Calculate Cost.
      //    Pricing must be explicitly declared: a missing pricing block (or a
      //    missing perCallCost) is NOT treated as free — free is an explicit
      //    `perCallCost: 0` choice by the provider. Fail closed otherwise.
      const pricing = service.pricing;
      if (
        !pricing ||
        typeof pricing !== 'object' ||
        typeof pricing.perCallCost !== 'number' ||
        !Number.isFinite(pricing.perCallCost) ||
        pricing.perCallCost < 0
      ) {
        throw new ServiceCallError(
          'PRICING_UNDECLARED',
          `Service ${serviceId} does not declare explicit pricing ` +
            `(perCallCost must be an explicit non-negative number; use 0 for free services)`,
          { serviceId }
        );
      }
      const baseCost = pricing.perCallCost;
      const cost = baseCost * (endpoint.costMultiplier ?? 1);

      if (options?.maxCost !== undefined && cost > options.maxCost) {
          throw new ServiceCallError('COST_EXCEEDED', 'Cost exceeded', { cost, maxCost: options.maxCost });
      }

      // 7. Authorize Payment — to the node that will actually execute the
      //    call, not to the (possibly stale) provider node on the definition.
      const executorNode = instance.nodeId;
      const auth = cost > 0
          ? await this.wallet.authorizePayment(
              executorNode,
              BigInt(Math.round(cost * 1e18)), // cost is a float; scale to base units
              { type: 'SERVICE_CALL', serviceId, endpointName, executorNode }
          )
          : null;

      // 8. Execute (Mock RPC)
      // In real implementation, this would use the protocol defined (HTTP, WebSocket, Gun)
      // Here we simulate a Gun-based RPC or HTTP fetch
      let result: T;
      try {
          result = await this.executeRpc(instance, endpoint, input);
      } catch (e) {
          // Release the escrow: the executor never delivered.
          if (auth) {
              try {
                  await this.wallet.finalizePayment(auth.id, 0n);
              } catch {
                  /* best effort — never mask the RPC failure */
              }
          }
          throw e instanceof ServiceCallError
              ? e
              : new ServiceCallError('RPC_FAILED', e instanceof Error ? e.message : String(e), { serviceId, executorNode });
      }

      // 9. Finalize Payment to the executing node
      if (auth) {
          await this.wallet.finalizePayment(auth.id);
      }

      return { result, cost, executorNode };
  }

  // ─── Access Enforcement ───────────────────────────────────────────────

  /**
   * Enforce a service definition's access rules for the local caller.
   * Throws a ServiceCallError on the first violation.
   *
   * FAIL CLOSED on undeclared access: a definition without an `access` block
   * (or without an explicit `access.visibility`) is NOT public. Only an
   * explicit `access.visibility: 'PUBLIC'` opens a service to arbitrary RPC
   * callers; anything undeclared is denied before any work happens.
   */
  private async enforceAccess(service: ServiceDefinition): Promise<void> {
      if (service.status === 'SUSPENDED') {
          throw new ServiceCallError('SERVICE_SUSPENDED', `Service ${service.id} is suspended`, { serviceId: service.id });
      }

      const access = service.access;
      // Missing access block: not public, not callable. Deny.
      if (!access || typeof access !== 'object') {
          throw new ServiceCallError(
              'ACCESS_UNDECLARED',
              `Service ${service.id} declares no access policy (explicit visibility 'PUBLIC' is required)`,
              { serviceId: service.id }
          );
      }
      // Missing/unknown visibility: not public, not callable. Deny.
      if (
          access.visibility !== 'PUBLIC' &&
          access.visibility !== 'RESTRICTED' &&
          access.visibility !== 'PRIVATE'
      ) {
          throw new ServiceCallError(
              'ACCESS_UNDECLARED',
              `Service ${service.id} does not declare an explicit visibility ('PUBLIC', 'RESTRICTED' or 'PRIVATE')`,
              { serviceId: service.id, visibility: access.visibility }
          );
      }

      const callerNodeId = this.localNodeId;
      const callerUserId = this.wallet.address;
      const isProvider =
          callerNodeId === service.providerNodeId || callerUserId === service.providerUserId;
      if (isProvider) return;

      const allowedNodes = Array.isArray(access.allowedNodes) ? access.allowedNodes : [];
      const allowedUsers = Array.isArray(access.allowedUsers) ? access.allowedUsers : [];
      const allowedTiers = Array.isArray(access.allowedTiers) ? access.allowedTiers : [];

      // ── Visibility ───────────────────────────────────────────────────
      if (access.visibility === 'PRIVATE') {
          throw new ServiceCallError('VISIBILITY_DENIED', `Service ${service.id} is private`, {
              serviceId: service.id,
              visibility: access.visibility,
          });
      }

      if (
          access.visibility === 'RESTRICTED' &&
          allowedNodes.length === 0 &&
          allowedUsers.length === 0 &&
          allowedTiers.length === 0
      ) {
          // Restricted with no allow-list: fail closed rather than open.
          throw new ServiceCallError(
              'VISIBILITY_DENIED',
              `Service ${service.id} is restricted and declares no allow-list`,
              { serviceId: service.id, visibility: access.visibility }
          );
      }

      // ── Allow-lists (enforced whenever declared) ─────────────────────
      if (allowedNodes.length > 0 && !allowedNodes.includes(callerNodeId)) {
          throw new ServiceCallError('NODE_NOT_ALLOWED', `Node ${callerNodeId} is not allowed to call ${service.id}`, {
              serviceId: service.id,
              nodeId: callerNodeId,
          });
      }

      if (allowedUsers.length > 0 && !allowedUsers.includes(callerUserId)) {
          throw new ServiceCallError('USER_NOT_ALLOWED', `User ${callerUserId} is not allowed to call ${service.id}`, {
              serviceId: service.id,
              userId: callerUserId,
          });
      }

      if (allowedTiers.length > 0) {
          const balance = await this.wallet.getBalance();
          if (!allowedTiers.includes(balance.stakingTier)) {
              throw new ServiceCallError(
                  'TIER_NOT_ALLOWED',
                  `Staking tier ${balance.stakingTier} is not allowed to call ${service.id}`,
                  { serviceId: service.id, stakingTier: balance.stakingTier, allowedTiers }
              );
          }
      }

      // ── Reputation / Coherence minimums ──────────────────────────────
      if (typeof access.minReputation === 'number' && access.minReputation > 0) {
          const reputation = await this.resolveReputation(callerUserId);
          if (reputation === null) {
              throw new ServiceCallError(
                  'REPUTATION_UNVERIFIABLE',
                  `Service ${service.id} requires a minimum reputation but none could be established`,
                  { serviceId: service.id, minReputation: access.minReputation }
              );
          }
          if (reputation < access.minReputation) {
              throw new ServiceCallError(
                  'REPUTATION_TOO_LOW',
                  `Reputation ${reputation} is below the minimum ${access.minReputation} for ${service.id}`,
                  { serviceId: service.id, reputation, minReputation: access.minReputation }
              );
          }
      }

      if (typeof access.minCoherence === 'number' && access.minCoherence > 0) {
          const coherence = await this.resolveCoherence(callerUserId);
          if (coherence === null) {
              throw new ServiceCallError(
                  'COHERENCE_UNVERIFIABLE',
                  `Service ${service.id} requires a minimum coherence but none could be established`,
                  { serviceId: service.id, minCoherence: access.minCoherence }
              );
          }
          if (coherence < access.minCoherence) {
              throw new ServiceCallError(
                  'COHERENCE_TOO_LOW',
                  `Coherence ${coherence} is below the minimum ${access.minCoherence} for ${service.id}`,
                  { serviceId: service.id, coherence, minCoherence: access.minCoherence }
              );
          }
      }
  }

  /**
   * Enforce the declared rate limits for this caller.
   *
   * Local best-effort limiter: it stops this node from exceeding the published
   * limits. The provider node remains the authority for its own quota.
   */
  private enforceRateLimit(service: ServiceDefinition): void {
      const limits = service.access?.rateLimit;
      if (!limits || typeof limits !== 'object') return;

      const key = `${service.id}:${this.wallet.address}`;
      const now = Date.now();
      const timestamps = (this.rateLimitLog.get(key) ?? []).filter(t => now - t < DAY_MS);

      const windows: Array<{ limit: number | undefined; windowMs: number; scope: string }> = [
          { limit: limits.burstLimit, windowMs: BURST_WINDOW_MS, scope: 'burst' },
          { limit: limits.requestsPerMinute, windowMs: MINUTE_MS, scope: 'per-minute' },
          { limit: limits.requestsPerHour, windowMs: HOUR_MS, scope: 'per-hour' },
          { limit: limits.requestsPerDay, windowMs: DAY_MS, scope: 'per-day' },
      ];

      for (const { limit, windowMs, scope } of windows) {
          if (typeof limit !== 'number' || limit < 0) continue;
          const used = timestamps.filter(t => now - t < windowMs).length;
          if (used >= limit) {
              this.rateLimitLog.set(key, timestamps);
              throw new ServiceCallError(
                  'RATE_LIMIT_EXCEEDED',
                  `Rate limit exceeded for ${service.id} (${scope}: ${limit})`,
                  { serviceId: service.id, scope, limit, windowMs, used }
              );
          }
      }

      timestamps.push(now);
      this.rateLimitLog.set(key, timestamps);
  }

  private async resolveReputation(userId: string): Promise<number | null> {
      if (this.accessContext) return this.accessContext.getReputation(userId);
      return this.readScore(this.gun.get('reputation').get(userId));
  }

  private async resolveCoherence(userId: string): Promise<number | null> {
      if (this.accessContext) return this.accessContext.getCoherence(userId);
      return this.readScore(this.gun.get('coherence').get(userId));
  }

  /**
   * Read a `{ score }` node, resolving to null when unavailable.
   */
  private readScore(node: any): Promise<number | null> {
      return new Promise((resolve) => {
          let settled = false;
          const settle = (value: number | null) => {
              if (settled) return;
              settled = true;
              clearTimeout(timer);
              resolve(value);
          };
          const timer: any = setTimeout(() => settle(null), 500);
          if (typeof timer?.unref === 'function') timer.unref();

          try {
              node.once((data: any) => {
                  if (typeof data === 'number') return settle(data);
                  if (data && typeof data.score === 'number') return settle(data.score);
                  settle(null);
              });
          } catch {
              settle(null);
          }
      });
  }

  private async getServiceDefinition(id: string): Promise<ServiceDefinition | null> {
      return new Promise((resolve) => {
          this.gun.get('services').get(id).once((data: any) => {
              resolve(data ? data.definition : null);
          });
      });
  }

  private async findHealthyInstance(serviceId: string): Promise<ServiceInstance | null> {
      return new Promise((resolve) => {
          this.gun.get('services').get(serviceId).get('instances').map().once((inst: any) => {
              if (inst && inst.status === 'RUNNING' && inst.health?.healthy === true && inst.nodeId) {
                  resolve(inst);
                  // Return early if map allows, or just let first one win logic
              }
          });
          // Timeout fallback
          const timer: any = setTimeout(() => resolve(null), 500);
          if (typeof timer?.unref === 'function') timer.unref();
      });
  }

  /**
   * Subscribe to a service stream.
   */
  public async subscribeToService<T>(
      serviceId: string,
      topic: string,
      handler: (data: T) => void
  ): Promise<Subscription> {
      // 1. Get Service Def
      const service = await this.getServiceDefinition(serviceId);
      if (!service) throw new Error(`Service ${serviceId} not found`);

      // 2. Subscribe via Gun
      // We assume the service publishes to `services/<id>/streams/<topic>`
      const streamNode = this.gun.get('services').get(serviceId).get('streams').get(topic);
      
      const listener = (data: any) => {
          if (data) handler(data as T);
      };
      
      streamNode.on(listener);

      return {
          unsubscribe: () => {
              streamNode.off(listener);
          },
          closed: false
      } as Subscription;
  }

  private async executeRpc(instance: ServiceInstance, endpoint: any, input: any): Promise<any> {
      const requestId = generateId('req');
      const request = {
          id: requestId,
          input,
          timestamp: Date.now(),
          responsePath: `requests/${requestId}/response`
      };

      // Put request to instance inbox
      this.gun.get('nodes').get(instance.nodeId).get('inbox').get(requestId).put(request);

      // Wait for response
      return new Promise((resolve, reject) => {
          const timeout = setTimeout(() => {
              reject(new Error('RPC timeout'));
          }, 5000); // 5s timeout

          this.gun.get('requests').get(requestId).get('response').once((response: any) => {
              clearTimeout(timeout);
              if (response) {
                  if (response.error) reject(new Error(response.error));
                  else resolve(response.result);
              }
          });
      });
  }
}
