import { SemanticDomain } from '../core/types';
import { EmbeddingService } from '../services/EmbeddingService';
import { determineDomain, cosineSimilarity } from '../common/math';
import { Subscription } from '../common';

// --- Interfaces ---

export type EventSource = 'SRIA' | 'SERVICE' | 'TASK' | 'SYSTEM' | 'USER' | 'CONSENSUS' | 'GMF';
export type EventPriority = 'LOW' | 'NORMAL' | 'HIGH' | 'CRITICAL';

export interface AlephEvent {
  id: string;
  type: string;
  source: {
    nodeId: string;
    component: EventSource;
    userId?: string;
  };
  payload: Record<string, any>;
  semantic?: {
    smf: number[];
    domain: SemanticDomain;
    coherenceProof?: {
      tickNumber: number;
      coherence: number;
    };
  };
  metadata: {
    timestamp: number;
    version: string;
    correlationId?: string;
    causationId?: string;
    priority: EventPriority;
    ttlMs?: number;
    replayable: boolean;
  };
}

export interface EventPattern {
  type?: string;
  source?: {
    nodeId?: string;
    component?: EventSource;
    userId?: string;
  };
  semantic?: {
    domain?: SemanticDomain;
    minCoherence?: number;
    smfSimilarity?: {
      vector: number[];
      threshold: number;
    };
  };
  metadata?: {
    minPriority?: EventPriority;
    correlationId?: string;
  };
}

export type EventHandler = (event: AlephEvent) => Promise<void>;

export interface EventSubscription extends Subscription {
  id: string;
  pattern: EventPattern;
  pause(): void;
  resume(): void;
  unsubscribe(): void;
}

export interface EventBus {
  publish(event: AlephEvent): Promise<void>;
  subscribe(pattern: EventPattern, handler: EventHandler): EventSubscription;
}

// --- Implementation ---

export interface StoredEvent {
    sequence: number;
    event: string;
    storedAt: number;
}

export class GunEventStore {
    private lastTimestamp = 0;
    private sameMsCounter = 0;
    private localLog: StoredEvent[] = [];
    private static readonly MAX_LOCAL_LOG = 1000;

    constructor(private gun: any, private nodeId?: string) {}

    /**
     * Monotonic, restart-safe sequence derived from wall-clock time:
     * `lastTimestamp * 1000 + per-ms counter`. A process restart can never
     * reuse a sequence a previous run already wrote at
     * `eventlog/<nodeId>/<seq>`, because time only moves forward. The counter
     * keeps sequences distinct when several events land in the same
     * millisecond; if it saturates, the logical clock is pushed forward so
     * monotonicity is preserved.
     */
    private nextSequence(): number {
        const now = Date.now();
        if (now > this.lastTimestamp) {
            this.lastTimestamp = now;
            this.sameMsCounter = 0;
        } else if (this.sameMsCounter < 999) {
            this.sameMsCounter++;
        } else {
            this.lastTimestamp += 1;
            this.sameMsCounter = 0;
        }
        return this.lastTimestamp * 1000 + this.sameMsCounter;
    }

    async append(event: AlephEvent): Promise<number> {
        const seq = this.nextSequence();
        const record: StoredEvent = {
            sequence: seq,
            event: JSON.stringify(event),
            storedAt: Date.now()
        };
        
        // The sequence is namespaced by node id so peers do not overwrite
        // each other's entries at eventlog/<nodeId>/<seq>.
        const nodeId = this.nodeId || event.source?.nodeId;
        if (!this.gun || !nodeId) {
            // No shared graph (or no identity): keep a bounded local log rather than throwing
            this.appendLocal(record);
            return seq;
        }
        
        try {
            // Fire and forget persistence for speed in this demo
            this.gun.get('eventlog').get(nodeId).get(seq.toString()).put(record);
        } catch (e) {
            this.appendLocal(record);
        }
        
        return seq;
    }

    /**
     * Events retained locally because no shared graph was available
     */
    getLocalLog(): StoredEvent[] {
        return [...this.localLog];
    }

    private appendLocal(record: StoredEvent): void {
        this.localLog.push(record);
        if (this.localLog.length > GunEventStore.MAX_LOCAL_LOG) {
            this.localLog.shift();
        }
    }
}

class EventSubscriptionImpl implements EventSubscription {
    public closed: boolean = false;
    
    constructor(
        public id: string,
        public pattern: EventPattern,
        private _pause: () => void,
        private _resume: () => void,
        private _unsubscribe: () => void
    ) {}

    pause() { this._pause(); }
    resume() { this._resume(); }
    unsubscribe() {
        if (this.closed) return;
        this.closed = true;
        this._unsubscribe();
    }
}

export class GunEventBus implements EventBus {
  private subscriptions = new Map<string, any>();
  private store: GunEventStore;
  
  constructor(
    private gun: any,
    private localNodeId: string,
    private embeddingService: EmbeddingService
  ) {
      this.store = new GunEventStore(gun, localNodeId);
  }
  
  async publish(event: AlephEvent): Promise<void> {
    // 1. Validate (skip for now)
    
    // 2. Generate semantic metadata if missing
    if (!event.semantic && event.payload) {
        try {
            const text = JSON.stringify(event.payload);
            const smf = await this.embeddingService.embedToSMF(text);
            event.semantic = {
                smf,
                domain: determineDomain(smf)
            };
        } catch (e) {
            // Ignore embedding failure
        }
    }
    
    // 3. Persist
    await this.store.append(event);
    
    // 4. Route to local subscribers
    // In a real Gun bus, we might put to a path subscribers listen to.
    // Here we iterate local subscriptions for simplicity of "Event Bus" abstraction over Gun
    this.routeToLocalSubscribers(event);

    // 5. Broadcast to peers (Put to Gun path)
    this.broadcast(event);
  }
  
  private broadcast(event: AlephEvent): void {
    if (!this.gun || !event.type) return;
    
    try {
        // Gun cannot store nested objects/arrays directly, so the event travels
        // as a serialized envelope.
        this.gun.get('events').get(event.type).set({
            id: event.id,
            nodeId: event.source?.nodeId || this.localNodeId,
            event: JSON.stringify(event),
            broadcastAt: Date.now()
        });
    } catch (e) {
        // Broadcast is best-effort: local delivery and persistence already happened
        console.error(`Event broadcast failed for ${event.id}:`, e);
    }
  }
  
  subscribe(pattern: EventPattern, handler: EventHandler): EventSubscription {
    const id = `sub-${Date.now()}-${Math.random()}`;
    const sub: any = { id, pattern, handler, paused: false, closed: false, recent: new Set<string>() };
    this.subscriptions.set(id, sub);
    
    // Hook into Gun so broadcasts from peers reach the same handler as
    // locally published events. Best-effort with error isolation: a broken
    // graph or a malformed envelope must never break subscription setup.
    if (pattern.type && this.gun) {
        try {
            this.gun.get('events').get(pattern.type).map().on((data: any, _key: string) => {
                if (sub.closed || sub.paused) return;
                try {
                    const raw = typeof data?.event === 'string' ? data.event : null;
                    if (!raw) return;
                    const event: AlephEvent = JSON.parse(raw);
                    if (!event || typeof event !== 'object' || !event.id) return;
                    if (sub.recent.has(event.id)) return;
                    sub.recent.add(event.id);
                    if (sub.recent.size > 500) sub.recent.clear();
                    if (this.matchesPattern(event, sub.pattern)) {
                        Promise.resolve(handler(event)).catch((err) => {
                            console.error(`Event handler ${sub.id} failed:`, err);
                        });
                    }
                } catch (e) {
                    // Malformed envelope: ignore, keep the hook alive
                }
            });
        } catch (e) {
            // Gun hook unavailable (e.g. no graph): local routing still works
        }
    }

    return new EventSubscriptionImpl(
        id,
        pattern,
        () => { sub.paused = true; },
        () => { sub.paused = false; },
        () => {
            sub.closed = true;
            this.subscriptions.delete(id);
        }
    );
  }

  private routeToLocalSubscribers(event: AlephEvent) {
      for (const sub of this.subscriptions.values()) {
          if (sub.paused || sub.closed) continue;
          if (!this.matchesPattern(event, sub.pattern)) continue;
          // Track delivery so the Gun broadcast hook does not re-deliver the
          // same event to this subscription.
          if (!sub.recent) sub.recent = new Set<string>();
          sub.recent.add(event.id);
          if (sub.recent.size > 500) sub.recent.clear();
          sub.handler(event).catch(console.error);
      }
  }
  
  private matchesPattern(event: AlephEvent, pattern: EventPattern): boolean {
    // Type matching (glob support simplified)
    if (pattern.type && pattern.type !== event.type && !pattern.type.endsWith('*')) {
      return false;
    }
    
    // Source matching
    if (pattern.source) {
      if (pattern.source.nodeId && event.source.nodeId !== pattern.source.nodeId) return false;
      if (pattern.source.component && event.source.component !== pattern.source.component) return false;
    }
    
    // Semantic matching
    if (pattern.semantic && event.semantic) {
      if (pattern.semantic.domain && event.semantic.domain !== pattern.semantic.domain) return false;
      if (pattern.semantic.smfSimilarity) {
         const { vector, threshold } = pattern.semantic.smfSimilarity;
         // SMFVector is array of numbers, compatible with cosineSimilarity
         const similarity = cosineSimilarity(vector, event.semantic.smf);
         if (similarity < threshold) return false;
      }
    }
    
    return true;
  }
}
