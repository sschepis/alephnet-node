import { 
  AlephGunBridge as IAlephGunBridge, 
  DSNNodeConfig, 
  AgentTriggerEvent, 
  RoutingDecision,
  GMFObject
} from '../core/types';
import { EmbeddingService } from '../services/EmbeddingService';
import { verifyFromBase64, base64ToBuffer } from '../common/crypto';
import { arraysToGunObjects, gunObjectsToArrays } from '../common/gun-utils';
import { CONSENSUS } from '../common/constants';

/**
 * A signed coherence proof as it travels over the Gun graph.
 * Signature and publicKey are mandatory for the proof to be considered at all.
 */
export interface CoherenceProof {
  tickNumber?: number;
  coherence?: number;
  smfHash?: string;
  signature?: string;
  publicKey?: string;
}

export interface CoherenceProofEnvelope {
  coherenceProof?: CoherenceProof;
}

/**
 * A node that can serve a semantic request (self or a discovered peer).
 */
interface RoutingCandidate {
  nodeId: string;
  semanticDomain: string;
  primeDomain: number[];
  loadIndex: number;
}

export class AlephGunBridge implements IAlephGunBridge {
  private gun: any;
  private dsnNode: any;
  private agentManager: any;
  private embeddingService?: EmbeddingService;
  private isInitialized = false;

  /**
   * Minimum coherence a signed proof must claim to be accepted.
   * Single source of truth: common/constants (must match Consensus).
   */
  private readonly COHERENCE_THRESHOLD = CONSENSUS.MIN_COHERENCE_THRESHOLD;

  async initialize(gun: any, dsnNode: any, agentManager: any, embeddingService?: EmbeddingService): Promise<void> {
    if (!gun) throw new Error("Gun instance is required");
    this.gun = gun;
    this.dsnNode = dsnNode;
    this.agentManager = agentManager;
    this.embeddingService = embeddingService;
    this.isInitialized = true;
    
    console.log(`[AlephGunBridge] Initialized for node ${dsnNode?.config?.nodeId || 'unknown'}`);
  }

  async authenticate(pair: any): Promise<void> {
    if (!this.isInitialized || !this.gun) throw new Error("Bridge not initialized");
    
    return new Promise((resolve, reject) => {
      if (typeof this.gun.user !== 'function') {
         return reject(new Error("Gun.user() is not available. Ensure 'gun/sea' is imported."));
      }
      
      // Add timeout to auth
      const timeout = setTimeout(() => reject(new Error("Gun authentication timed out")), 5000);
      
      this.gun.user().auth(pair, (ack: any) => {
         clearTimeout(timeout);
         if (ack.err) reject(new Error(`Gun Auth Error: ${ack.err}`));
         else resolve();
      });
    });
  }

  getGun(): any {
    if (!this.gun) throw new Error("Bridge not initialized");
    return this.gun;
  }

  async put(path: string, data: any): Promise<void> {
    if (!this.gun) throw new Error("Bridge not initialized");
    
    // Validate inputs
    if (!path || typeof path !== 'string') throw new Error("Invalid path");
    if (data === undefined) throw new Error("Cannot put undefined data");

    const parts = path.split('/');
    let ref = this.gun;
    for (const part of parts) {
        if (!part) continue;
        ref = ref.get(part);
    }

    const safeData = arraysToGunObjects(data);
    
    return new Promise((resolve, reject) => {
        // Gun put doesn't always ack if offline, so we might resolve optimistically?
        // But for production grade, we want confirmation or timeout.
        const timeout = setTimeout(() => {
            // Warn but don't reject? Gun is offline-first.
            // But if caller awaits, they block. Resolve with warning.
            console.warn(`[AlephGunBridge] Put operation timed out for ${path} (optimistic success)`);
            resolve();
        }, 3000);

        ref.put(safeData, (ack: any) => {
            clearTimeout(timeout);
            if (ack.err) reject(new Error(`Gun Put Error: ${ack.err}`));
            else resolve();
        });
    });
  }

  async get(path: string): Promise<any> {
    if (!this.gun) throw new Error("Bridge not initialized");
    const parts = path.split('/');
    let ref = this.gun;
    for (const part of parts) {
        if (!part) continue;
        ref = ref.get(part);
    }

    return new Promise((resolve) => {
        // Timeout for get is critical as Gun might never return if data doesn't exist locally/remotely
        const timeout = setTimeout(() => {
            resolve(undefined);
        }, 2000); // 2s timeout for reads

        ref.once((data: any) => {
            clearTimeout(timeout);
            resolve(gunObjectsToArrays(data));
        });
    });
  }

  subscribe(path: string, callback: (data: any) => void): () => void {
    if (!this.gun) throw new Error("Bridge not initialized");
    const parts = path.split('/');
    let ref = this.gun;
    for (const part of parts) {
        if (!part) continue;
        ref = ref.get(part);
    }

    const handler = (data: any) => {
      try {
        callback(gunObjectsToArrays(data));
      } catch (err) {
        console.error(`[AlephGunBridge] Subscription error on ${path}:`, err);
      }
    };
    ref.on(handler);

    return () => {
        ref.off();
    };
  }

  async projectToSMF(graphPath: string, data: any): Promise<number[]> {
    if (this.embeddingService) {
      try {
        const text = typeof data === 'string' ? data : JSON.stringify(data);
        // Truncate large data for embedding to prevent cost/error
        const safeText = text.length > 8000 ? text.substring(0, 8000) : text;
        return await this.embeddingService.embedToSMF(graphPath + ':' + safeText);
      } catch (err) {
        console.warn('[AlephGunBridge] Embedding failed, falling back to mock projection', err);
      }
    }
    
    const smf = new Array(16).fill(0);
    let hash = 0;
    const str = graphPath + JSON.stringify(data);
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    smf[Math.abs(hash) % 16] = 1; 
    return smf;
  }

  /**
   * Score every known candidate (self + peers) against the request and pick
   * the best one. A peer that specializes in the required semantic domain
   * outranks a generic local node; ties resolve in favour of self (no hop).
   */
  async routeRequest(event: AgentTriggerEvent): Promise<RoutingDecision> {
    const requiredDomain = event.routing?.preferredDomain || 'cognitive';
    const requiredPrimes = event.routing?.requiredSmfAxes || [];

    const candidates = [this.selfCandidate(), ...this.collectPeerCandidates()];

    const ranked = candidates
      .map(candidate => ({
        candidate,
        score: this.scoreCandidate(candidate, requiredDomain, requiredPrimes)
      }))
      // Stable sort: self is first in the input, so it wins equal scores.
      .sort((a, b) => b.score - a.score);

    const winner = ranked[0];
    const overlap = this.primeOverlap(winner.candidate, requiredPrimes);

    return {
        targetNodeId: winner.candidate.nodeId,
        relevanceScore: Math.max(0.1, winner.score),
        semanticDomainMatch: winner.candidate.semanticDomain === requiredDomain,
        primeDomainOverlap: overlap,
        loadFactor: winner.candidate.loadIndex,
        fallbackNodes: ranked.slice(1).map(r => r.candidate.nodeId)
    };
  }

  /**
   * A signed coherence proof is the only acceptable proof.
   *
   * An unsigned (or unattributable) claim is worthless: anyone could assert
   * perfect coherence, so a missing signature or public key is a hard reject
   * before the threshold is even considered.
   */
  async verifyCoherence(proposal: CoherenceProofEnvelope): Promise<boolean> {
    const proof = proposal?.coherenceProof;
    if (!proof) return false;

    const { coherence, smfHash, signature, publicKey } = proof;

    if (typeof signature !== 'string' || signature.length === 0) {
        console.warn('[AlephGunBridge] Coherence proof rejected: missing signature');
        return false;
    }
    if (typeof publicKey !== 'string' || publicKey.length === 0) {
        console.warn('[AlephGunBridge] Coherence proof rejected: missing public key');
        return false;
    }
    if (typeof coherence !== 'number' || !Number.isFinite(coherence)) {
        console.warn('[AlephGunBridge] Coherence proof rejected: coherence is not a number');
        return false;
    }

    try {
        // Signature covers the claimed coherence AND the SMF hash, so neither
        // can be swapped without invalidating the proof.
        const data = JSON.stringify({ coherence, smfHash });
        const isValid = verifyFromBase64(data, signature, base64ToBuffer(publicKey));
        if (!isValid) {
            console.warn('[AlephGunBridge] Invalid coherence signature');
            return false;
        }
    } catch (e) {
        console.error('[AlephGunBridge] Error verifying signature', e);
        return false;
    }

    return coherence >= this.COHERENCE_THRESHOLD;
  }

  // --- Routing helpers ---

  private selfNodeId(): string {
    return this.dsnNode?.config?.nodeId || 'self';
  }

  private selfCandidate(): RoutingCandidate {
    const config = this.dsnNode?.config;
    return {
        nodeId: this.selfNodeId(),
        semanticDomain: typeof config?.semanticDomain === 'string' ? config.semanticDomain : 'cognitive',
        primeDomain: Array.isArray(config?.primeDomain) ? config.primeDomain : [],
        loadIndex: typeof config?.loadIndex === 'number' ? config.loadIndex : 0
    };
  }

  /**
   * Collect routable peers. Only entries that publish a node identity are
   * candidates; bare relay URLs (plain strings in `gunPeers`) carry no
   * semantic metadata and are therefore not routing targets.
   */
  private collectPeerCandidates(): RoutingCandidate[] {
    const raw: unknown[] = [];
    const config = this.dsnNode?.config;

    if (Array.isArray(config?.knownPeers)) raw.push(...config.knownPeers);
    if (typeof this.dsnNode?.getPeers === 'function') {
        const discovered = this.dsnNode.getPeers();
        if (Array.isArray(discovered)) raw.push(...discovered);
    }
    if (Array.isArray(config?.gunPeers)) raw.push(...config.gunPeers);

    const candidates: RoutingCandidate[] = [];
    const seen = new Set<string>([this.selfNodeId()]);

    for (const entry of raw) {
        const candidate = this.toCandidate(entry);
        if (!candidate || seen.has(candidate.nodeId)) continue;
        seen.add(candidate.nodeId);
        candidates.push(candidate);
    }

    return candidates;
  }

  private toCandidate(entry: unknown): RoutingCandidate | null {
    if (!entry || typeof entry !== 'object') return null;

    const peer = entry as Partial<DSNNodeConfig> & { id?: string };
    const nodeId = typeof peer.nodeId === 'string'
        ? peer.nodeId
        : typeof peer.id === 'string' ? peer.id : null;
    if (!nodeId) return null;

    return {
        nodeId,
        semanticDomain: typeof peer.semanticDomain === 'string' ? peer.semanticDomain : '',
        primeDomain: Array.isArray(peer.primeDomain) ? peer.primeDomain : [],
        loadIndex: typeof peer.loadIndex === 'number' ? peer.loadIndex : 0
    };
  }

  private primeOverlap(candidate: RoutingCandidate, requiredPrimes: number[]): number {
    return candidate.primeDomain.filter((p: number) => requiredPrimes.includes(p)).length;
  }

  private scoreCandidate(
    candidate: RoutingCandidate,
    requiredDomain: string,
    requiredPrimes: number[]
  ): number {
    let score = 0;
    if (candidate.semanticDomain === requiredDomain) score += 10;
    score += this.primeOverlap(candidate, requiredPrimes) * 5;
    score -= candidate.loadIndex * 2;
    return score;
  }

  async syncGMFToGraph(): Promise<void> {
    if (!this.gun) return;
    try {
        this.gun.get('gmf').get('deltas').map().on((delta: any, id: string) => {
            console.log('[AlephGunBridge] Received GMF delta', id, delta);
        });
    } catch (err) {
        console.error('[AlephGunBridge] Failed to sync GMF:', err);
    }
  }

  async handleSRIAEvent(event: 'summon' | 'dismiss' | 'step', data: any): Promise<any> {
    console.log(`[AlephGunBridge] SRIA Event: ${event}`, data);
  }
}
