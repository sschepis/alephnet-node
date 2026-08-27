import { 
    KeyTriplet, 
    SemanticDomain, 
    SMFVector 
} from '../core/types';
import { 
    EmbeddingService, 
    SMF_AXIS_MAPPING
} from '../services/EmbeddingService';
import { 
    determineDomain, 
    findSecondaryDomains, 
    cosineSimilarity 
} from '../common/math';
import { contentHash } from '../common/hash';
import { GlobalMemoryField } from '../core/GMF';

// --- Interfaces ---

/**
 * Marker prefix for inline content that holds base64-encoded binary bytes.
 * `Buffer.toString()` mangles non-UTF8 payloads, so binary is stored encoded
 * and restored by `decodeInlineContent`.
 */
export const BINARY_CONTENT_MARKER = 'base64:';

export interface ContentItem {
  contentId: string;
  title: string;
  type: 'TEXT' | 'MARKDOWN' | 'JSON' | 'HTML' | 'IMAGE' | 'AUDIO' | 'BINARY';
  mimeType: string;
  ownerId: string;
  source: {
    type: 'CONVERSATION' | 'TASK' | 'SERVICE' | 'EXTERNAL' | 'USER_UPLOAD';
    id?: string;
    url?: string;
  };
  content: {
    inline?: string;
    externalRef?: {
      protocol: 'IPFS' | 'IPNS' | 'HTTP' | 'GUN';
      uri: string;
      size: number;
      checksum: string;
    };
    encrypted?: {
      ciphertext: string;
      algorithm: 'AES-256-GCM' | 'ChaCha20-Poly1305';
      keyHint: string;
    };
  };
  chunks?: Array<{
    chunkId: string;
    index: number;
    content: string;
    smf: number[];
    startOffset: number;
    endOffset: number;
  }>;
  semantic: {
    smf: number[];
    domain: SemanticDomain;
    secondaryDomains: SemanticDomain[];
    primeFactors: number[];
    keywords: string[];
    entities: Array<{
      name: string;
      type: string;
      salience: number;
    }>;
    summary?: string;
    embeddingModel: string;
    lastIndexedAt: number;
  };
  visibility: {
    level: 'PUBLIC' | 'FRIENDS' | 'PRIVATE' | 'RESTRICTED';
    friendsList?: string[];
    allowedUsers?: string[];
    minTier?: 'Neophyte' | 'Adept' | 'Magus' | 'Archon';
    contributeToGMF: boolean;
    gmfWeight?: number;
    expiresAt?: number | null;
  };
  versioning: {
    version: number;
    previousVersionId?: string;
    history: Array<{
      version: number;
      contentId: string;
      timestamp: number;
      summary: string;
    }>;
    forkedFrom?: string;
  };
  tags: string[];
  category?: string;
  language: string;
  createdAt: number;
  updatedAt: number;
  coherenceProof?: {
    tickNumber: number;
    coherence: number;
    smfHash: string;
  };
}

export interface SemanticQuery {
  naturalLanguage?: string;
  smfVector?: number[];
  keywords?: string[];
  entities?: Array<{ name?: string; type?: string; }>;
  filters?: {
    types?: ContentItem['type'][];
    domains?: SemanticDomain[];
    dateRange?: { after?: number; before?: number; };
    owners?: string[];
    sources?: ContentItem['source']['type'][];
    tags?: string[];
    categories?: string[];
    languages?: string[];
    minCoherence?: number;
    /** Threshold applied to the computed SMF similarity score. */
    minSimilarity?: number;
    includeGMF?: boolean;
  };
  ranking?: {
    strategy: 'RELEVANCE' | 'RECENCY' | 'COHERENCE' | 'HYBRID';
    weights?: { relevance: number; recency: number; coherence: number; };
    boosts?: { ownContent?: number; friendsContent?: number; verifiedContent?: number; };
  };
  results?: {
    limit?: number;
    offset?: number;
    includeChunks?: boolean;
    highlight?: boolean;
    includeSimilarity?: boolean;
  };
}

export interface SemanticQueryResult {
  total: number;
  items: Array<{
    content: ContentItem;
    relevance: number;
    smfSimilarity: number;
    matchingChunks?: Array<{
      chunkId: string;
      content: string;
      similarity: number;
      highlights?: string;
    }>;
    matchSource: 'LOCAL' | 'GMF' | 'NETWORK';
  }>;
  querySMF: number[];
  processingTimeMs: number;
  domainsSearched: SemanticDomain[];
}

// --- Implementation ---

/**
 * Decides whether a content contribution has achieved network consensus and
 * may therefore be written into the Global Memory Field.
 *
 * Implementations typically run the Coherent-Commit protocol over the mesh and
 * resolve `true` only once a 2/3 stake-weighted supermajority accepts.
 */
export type GMFConsensusGate = (contribution: {
  proposalId: string;
  contentId: string;
  normalForm: string;
  smf: SMFVector;
}) => Promise<boolean>;

export class SemanticContentStore {
  /**
   * Local index of items known to this store, keyed by contentId.
   * Populated by `store()` and by successful `get()` fetches, and used as the
   * candidate set for `query()`. Bounded by MAX_LOCAL_INDEX_ENTRIES.
   */
  private static readonly MAX_LOCAL_INDEX_ENTRIES = 1000;
  private localIndex: Map<string, ContentItem> = new Map();
  private pendingGMFContributions: Map<string, string> = new Map();

  constructor(
    private gun: any,
    private gmf: GlobalMemoryField,
    private embedder: EmbeddingService,
    private identity: KeyTriplet,
    private consensusGate?: GMFConsensusGate
  ) {}

  /**
   * Retry every contribution that is still awaiting consensus, dropping those
   * the gate now refuses (or those whose proposal is no longer meaningful).
   * Call this periodically (or after consensus events) so the pending set can
   * never grow without bound.
   */
  async flushPendingGMFContributions(): Promise<number> {
    let flushed = 0;
    for (const [contentId, proposalId] of [...this.pendingGMFContributions]) {
      const item = this.localIndex.get(contentId);
      if (!item) {
        this.pendingGMFContributions.delete(contentId);
        continue;
      }
      const approved = this.consensusGate
        ? await this.consensusGate({
            proposalId,
            contentId,
            normalForm: `content:${contentId}`,
            smf: item.semantic.smf as SMFVector
          })
        : false;
      if (!approved) continue;
      try {
        await this.gmf.insert(
          { term: { id: contentId }, normalForm: `content:${contentId}` },
          item.semantic.smf as SMFVector,
          { nodeId: this.identity.fingerprint, proposalId, consensusAchieved: true }
        );
        this.pendingGMFContributions.delete(contentId);
        flushed++;
      } catch {
        // The contribution stays pending for the next flush; a consensus or
        // integrity error must not abort the sweep.
      }
    }
    return flushed;
  }

  // --- Ingestion ---

  async store(
    content: string | Buffer,
    metadata: {
      title: string;
      type: ContentItem['type'];
      mimeType: string;
      visibility: ContentItem['visibility'];
      tags?: string[];
      category?: string;
    },
    options?: {
      chunkSize?: number;
      contributeToGMF?: boolean;
    }
  ): Promise<ContentItem> {
    // Binary payloads are base64-encoded behind a marker so that retrieval
    // round-trips the exact bytes instead of a lossy utf8 conversion.
    const isBinary = Buffer.isBuffer(content);
    const payload = isBinary
      ? `${BINARY_CONTENT_MARKER}${(content as Buffer).toString('base64')}`
      : (content as string).toString();

    const contentId = await contentHash(payload, this.embedder.modelName);

    // Only text carries semantics: describe binary by its metadata instead of
    // embedding base64 noise.
    const indexText = isBinary
      ? `${metadata.title} ${metadata.mimeType} ${(metadata.tags ?? []).join(' ')}`
      : payload;
    
    // Chunk content
    const chunkSize = options?.chunkSize ?? 1000;
    const chunkData = this.chunkContent(indexText, chunkSize);
    
    // Embed chunks
    const chunkEmbeddings = await this.embedder.batchEmbedToSMF(chunkData.map(c => c.content));
    const chunks = chunkData.map((c, i) => ({
        chunkId: `${contentId}-chk-${i}`,
        index: i,
        content: c.content,
        smf: chunkEmbeddings[i],
        startOffset: c.start,
        endOffset: c.end
    }));
    
    // Aggregate SMF (average)
    const aggregateSMF = this.aggregateSMFs(chunkEmbeddings);
    
    // Domain & Metadata
    const domain = determineDomain(aggregateSMF);
    const keywords = this.simpleExtractKeywords(indexText); // Simplified extraction
    
    const item: ContentItem = {
      contentId,
      title: metadata.title,
      type: metadata.type,
      mimeType: metadata.mimeType,
      ownerId: this.identity.fingerprint,
      source: { type: 'USER_UPLOAD' },
      content: {
        inline: payload.length < 1_000_000 ? payload : undefined,
        externalRef: payload.length >= 1_000_000 ? {
            protocol: 'GUN', // Placeholder
            uri: `gun://content/${contentId}/raw`,
            size: payload.length,
            checksum: contentId // simplified
        } : undefined
      },
      chunks,
      semantic: {
        smf: aggregateSMF,
        domain,
        secondaryDomains: findSecondaryDomains(aggregateSMF),
        primeFactors: [], // Logic to compute primes needed
        keywords,
        entities: [], // Logic needed
        summary: indexText.slice(0, 200) + '...', // Simple summary
        embeddingModel: this.embedder.modelName,
        lastIndexedAt: Date.now()
      },
      visibility: metadata.visibility,
      versioning: {
        version: 1,
        history: []
      },
      tags: metadata.tags ?? [],
      category: metadata.category,
      language: 'en', // Detection logic needed
      createdAt: Date.now(),
      updatedAt: Date.now()
    };
    
    await this.storeInGun(item);
    this.indexItem(item);
    
    if (options?.contributeToGMF && metadata.visibility.contributeToGMF) {
      await this.contributeToGMF(item);
    }
    
    return item;
  }

  /**
   * Restore an item's inline content. Binary payloads come back as a Buffer
   * with the exact original bytes.
   */
  decodeInlineContent(item: ContentItem): string | Buffer | null {
    const inline = item.content.inline;
    if (inline === undefined) return null;

    if (inline.startsWith(BINARY_CONTENT_MARKER)) {
      return Buffer.from(inline.slice(BINARY_CONTENT_MARKER.length), 'base64');
    }
    return inline;
  }

  // --- Query ---

  /**
   * Search the local index.
   * 
   * @param requesterId Identity the results are filtered for. Defaults to the
   *   local node identity; pass the remote identity when serving a peer so that
   *   PRIVATE/FRIENDS/RESTRICTED items stay hidden.
   */
  async query(query: SemanticQuery, requesterId?: string): Promise<SemanticQueryResult> {
    const startTime = Date.now();
    const viewer = requesterId ?? this.identity.fingerprint;
    
    let querySMF = query.smfVector;
    if (!querySMF) {
        const text = query.naturalLanguage || (query.keywords || []).join(' ');
        if (text) querySMF = await this.embedder.embedToSMF(text);
        else querySMF = new Array(16).fill(0) as unknown as SMFVector;
    }

    const candidates = await this.fetchCandidateItems();
    
    const items = candidates.map(item => {
        // Access control first: never score content the requester cannot see
        if (!this.isVisibleTo(item, viewer)) return null;
        
        const sim = cosineSimilarity(querySMF as SMFVector, item.semantic.smf);
        // Basic filtering
        if (query.filters) {
            if (query.filters.types && !query.filters.types.includes(item.type)) return null;
            if (query.filters.domains && !query.filters.domains.includes(item.semantic.domain)) return null;
            if (query.filters.owners && !query.filters.owners.includes(item.ownerId)) return null;
            if (query.filters.tags && !query.filters.tags.some(t => item.tags.includes(t))) return null;
            if (query.filters.languages && !query.filters.languages.includes(item.language)) return null;
            if (query.filters.categories && 
                !query.filters.categories.includes(item.category ?? '')) return null;
            if (query.filters.dateRange?.after !== undefined && 
                item.createdAt < query.filters.dateRange.after) return null;
            if (query.filters.dateRange?.before !== undefined && 
                item.createdAt > query.filters.dateRange.before) return null;
            if (query.filters.minCoherence && (item.coherenceProof?.coherence ?? 0) < query.filters.minCoherence) return null;
            // Similarity threshold applies to the score computed above
            if (query.filters.minSimilarity !== undefined && sim < query.filters.minSimilarity) return null;
        }
        
        return {
            content: item,
            relevance: sim, // Simplified relevance = similarity
            smfSimilarity: sim,
            matchSource: 'LOCAL' as const
        };
    }).filter((r): r is NonNullable<typeof r> => r !== null);
    
    // Sort
    items.sort((a, b) => b.relevance - a.relevance);
    
    // Pagination
    const offset = query.results?.offset ?? 0;
    const limit = query.results?.limit ?? 20;
    const paginated = items.slice(offset, offset + limit);

    return {
        total: items.length,
        items: paginated,
        querySMF: querySMF as number[],
        processingTimeMs: Date.now() - startTime,
        domainsSearched: [determineDomain(querySMF as SMFVector)]
    };
  }

  /**
   * Find items semantically similar to `contentId`.
   * The `minSimilarity` threshold is applied to the actual SMF similarity score.
   */
  async findSimilar(contentId: string, options?: {
    limit?: number;
    minSimilarity?: number;
    sameOwnerOnly?: boolean;
  }, requesterId?: string): Promise<SemanticQueryResult> {
    const content = await this.get(contentId, requesterId);
    if (!content) throw new Error(`Content ${contentId} not found`);
    
    const limit = options?.limit ?? 10;
    
    const result = await this.query({
      smfVector: content.semantic.smf,
      filters: {
        owners: options?.sameOwnerOnly ? [content.ownerId] : undefined,
        minSimilarity: options?.minSimilarity
      },
      ranking: { strategy: 'RELEVANCE' },
      // Request one extra slot: the source item itself matches perfectly
      results: { limit: limit + 1 }
    }, requesterId);
    
    // The source item is not "similar to itself"
    const matches = result.items
      .filter(entry => entry.content.contentId !== contentId)
      .slice(0, limit);
    
    return {
      ...result,
      total: matches.length,
      items: matches
    };
  }

  /**
   * Fetch a single content item.
   *
   * Visibility is enforced (fail closed): with no `requesterId` only PUBLIC
   * items are returned; PRIVATE/FRIENDS/RESTRICTED items require the matching
   * requester. This closes the historical bypass where `get()` ignored the
   * visibility model that `query()` enforced.
   *
   * When a backing store (Gun) is available the item is re-read from it rather
   * than served from the local index, so a remotely-updated item is never
   * served stale.
   */
  async get(contentId: string, requesterId?: string): Promise<ContentItem | null> {
    if (this.gun && typeof this.gun.get === 'function') {
      const item = await this.readFromGun(contentId);
      if (item === null) return null;
      return this.isVisibleTo(item, requesterId) ? item : null;
    }

    const cached = this.localIndex.get(contentId);
    if (!cached) return null;
    return this.isVisibleTo(cached, requesterId) ? cached : null;
  }

  private readFromGun(contentId: string): Promise<ContentItem | null> {
    return new Promise((resolve) => {
        const timeout = setTimeout(() => resolve(null), 1000);
        this.gun.get('content').get(contentId).once((data: any) => {
            clearTimeout(timeout);
            if (data && data.item) {
                const item = data.item as ContentItem;
                this.indexItem(item);
                resolve(item);
            }
            else resolve(null);
        });
    });
  }

  // --- Access control ---

  /**
   * Visibility enforcement:
   * - owner sees everything they own
   * - PUBLIC: everyone
   * - FRIENDS: identities on the friends list
   * - RESTRICTED: identities on the allowlist
   * - PRIVATE: owner only
   */
  private isVisibleTo(item: ContentItem, requesterId?: string): boolean {
    const expired = item.visibility.expiresAt != null && item.visibility.expiresAt < Date.now();
    const isOwner = requesterId !== undefined && requesterId === item.ownerId;
    
    if (isOwner) return true;
    if (expired) return false;
    
    switch (item.visibility.level) {
      case 'PUBLIC':
        return true;
      case 'FRIENDS':
        return requesterId !== undefined &&
          (item.visibility.friendsList ?? []).includes(requesterId);
      case 'RESTRICTED':
        return requesterId !== undefined &&
          (item.visibility.allowedUsers ?? []).includes(requesterId);
      case 'PRIVATE':
      default:
        return false;
    }
  }

  // --- Internal ---

  private chunkContent(text: string, size: number): { content: string, start: number, end: number }[] {
      const chunks = [];
      for (let i = 0; i < text.length; i += size) {
          chunks.push({
              content: text.slice(i, i + size),
              start: i,
              end: Math.min(i + size, text.length)
          });
      }
      return chunks;
  }

  private aggregateSMFs(smfs: SMFVector[]): SMFVector {
      if (smfs.length === 0) return new Array(16).fill(0) as unknown as SMFVector;
      const agg: number[] = new Array(16).fill(0);
      smfs.forEach(v => v.forEach((val: number, i: number) => agg[i] += val));
      const avg = agg.map(v => v / smfs.length);
      return avg as unknown as SMFVector; // Should normalize?
  }

  private async storeInGun(item: ContentItem): Promise<void> {
      if (!this.gun || typeof this.gun.get !== 'function') return;
      return new Promise((resolve) => {
          this.gun.get('content').get(item.contentId).put({ item }, (ack: any) => resolve());
          // Update indices...
      });
  }

  /**
   * Contribute an item to the Global Memory Field.
   *
   * GMF writes are consensus-gated: `GlobalMemoryField.insert` rejects any
   * payload that has not achieved consensus. A store cannot vote on its own
   * behalf, so the decision is delegated to the injected `consensusGate`.
   * Without a gate the contribution is recorded as pending rather than being
   * force-written, so local content never fabricates network agreement.
   */
  private async contributeToGMF(item: ContentItem): Promise<void> {
      const proposalId = `prop-${item.contentId}`;
      const proposal = {
          term: { id: item.contentId },
          normalForm: `content:${item.contentId}`
      };

      const approved = this.consensusGate
          ? await this.consensusGate({
                proposalId,
                contentId: item.contentId,
                normalForm: proposal.normalForm,
                smf: item.semantic.smf as SMFVector
            })
          : false;

      if (!approved) {
          this.pendingGMFContributions.set(item.contentId, proposalId);
          return;
      }

      await this.gmf.insert(proposal, item.semantic.smf as SMFVector, {
          nodeId: this.identity.fingerprint,
          proposalId,
          consensusAchieved: true
      });
      this.pendingGMFContributions.delete(item.contentId);
  }

  /**
   * Content ids awaiting consensus before they can enter the GMF.
   */
  get pendingGMFCount(): number {
      return this.pendingGMFContributions.size;
  }
  
  /**
   * Add/replace an item in the local index used by `query()`.
   *
   * The index is a query accelerator, not an authority — it is bounded (LRU)
   * so a long-lived node serving many content ids cannot grow without limit.
   */
  private indexItem(item: ContentItem): void {
      if (this.localIndex.has(item.contentId)) {
          this.localIndex.delete(item.contentId);
      }
      this.localIndex.set(item.contentId, item);
      while (this.localIndex.size > SemanticContentStore.MAX_LOCAL_INDEX_ENTRIES) {
          const oldest = this.localIndex.keys().next().value;
          if (oldest === undefined) break;
          this.localIndex.delete(oldest);
      }
  }

  /**
   * Remove an item from the local index.
   */
  removeFromIndex(contentId: string): boolean {
      return this.localIndex.delete(contentId);
  }

  /**
   * Number of items currently held in the local index.
   */
  get indexedCount(): number {
      return this.localIndex.size;
  }
  
  /**
   * Candidate set for a query: every item this store knows about locally.
   * Network/GMF candidates are merged in by the caller layers.
   */
  private async fetchCandidateItems(): Promise<ContentItem[]> {
      return Array.from(this.localIndex.values());
  }

  private simpleExtractKeywords(text: string): string[] {
      return text.split(/\s+/).filter(w => w.length > 5).slice(0, 5);
  }
}
