import {
  GMFObject,
  GMFSnapshot,
  GMFDelta,
  SMFVector
} from '../core/types';
import { createHash } from 'crypto';
import { smfHash, stableStringify } from '../common/hash';

/**
 * Thrown when a write is attempted for an object that has not passed consensus.
 * The GMF is a consensus-gated store: un-agreed data must never enter it.
 */
export class GMFConsensusError extends Error {
  public readonly code = 'GMF_CONSENSUS_NOT_ACHIEVED';

  constructor(
    public readonly objectId: string,
    public readonly proposalId: string
  ) {
    super(
      `GMF write rejected: consensus not achieved for proposal '${proposalId}' (object ${objectId})`
    );
    this.name = 'GMFConsensusError';
  }
}

/**
 * Thrown when an insert payload is structurally invalid.
 */
export class GMFValidationError extends Error {
  public readonly code = 'GMF_INVALID_PAYLOAD';

  constructor(message: string) {
    super(`GMF write rejected: ${message}`);
    this.name = 'GMFValidationError';
  }
}

/**
 * Attests that a delta payload's `consensusAchieved` claim is real.
 *
 * The `consensusAchieved` flag inside a peer delta is self-attested and is
 * therefore worthless on its own: any peer can mint it. When a
 * `GMFConsensusVerifier` is wired into the GMF, `applyDelta` consults it and
 * rejects any payload the verifier does not accept. Without a verifier,
 * peer-path inserts are rejected outright (fail closed) — only the local
 * `insert()` path may write without one, and it stays gated on
 * `metadata.consensusAchieved === true`.
 */
export interface GMFConsensusVerifier {
  verify(payload: GMFObject): boolean;
}

/**
 * Global Memory Field (GMF)
 *
 * Represents the shared semantic state of the AlephNet.
 * Manages Objects (semantic units), Snapshots (state checkpoints), and Deltas (changes).
 *
 * Implements "Semantic State Synchronization".
 *
 * Integrity model:
 *   - Object ids are content addresses: id = sha256(semanticObject.normalForm).
 *     Any delta whose payload does not hash back to its id is a tampered delta.
 *   - Every applied delta extends an append-only delta chain hash, and its
 *     digest is remembered so replays (duplicates) are rejected.
 *   - Snapshot hashes cover id + weight + smf digest + normal form of every
 *     object (each component length-prefixed), chained to the previous
 *     snapshot hash.
 *   - Peer deltas are consensus-gated via an injected GMFConsensusVerifier.
 *     Without one, peer-path inserts fail closed.
 *
 * Replay protection across restarts: call `seedDeltaChain` with a
 * `{ chainHash, appliedDigests }` persisted by a storage layer to restore the
 * chain hash and the digest set. Without seeding, the chain starts fresh and
 * replay protection only covers deltas applied since construction.
 */
export class GlobalMemoryField {
  private objects: Map<string, GMFObject> = new Map();
  private snapshots: Map<number, GMFSnapshot> = new Map();
  private deltas: GMFDelta[] = [];

  private currentSnapshotId: number = 0;
  private lastSnapshotHash: string = '00000000000000000000000000000000';

  /** Running hash over every delta that has been accepted, in order. */
  private deltaChainHash: string = '00000000000000000000000000000000';
  /** Digests of accepted deltas, used for replay/duplicate detection. */
  private appliedDeltaDigests: Set<string> = new Set();
  /** Why the most recent applyDelta() call returned false (null when accepted). */
  private lastDeltaRejection: string | null = null;

  constructor(private readonly consensusVerifier?: GMFConsensusVerifier) {
    // Initialize with genesis snapshot synchronously
    this.createSnapshotSync();
  }

  /**
   * Restore replay protection and the delta hash chain from persistence.
   *
   * Call once at startup with the values returned by `getDeltaChainHash()`
   * and `getAppliedDeltaDigests()` before the previous shutdown. Any delta
   * whose digest is already in `appliedDigests` will be rejected as a
   * replay. Without seeding, the chain starts fresh.
   *
   * @throws GMFValidationError when the seed is structurally invalid
   */
  public seedDeltaChain(seed: { chainHash: string; appliedDigests: string[] }): void {
    if (!seed || typeof seed.chainHash !== 'string' || seed.chainHash.length === 0) {
      throw new GMFValidationError('seedDeltaChain requires a non-empty chainHash');
    }
    if (
      !Array.isArray(seed.appliedDigests) ||
      seed.appliedDigests.some(digest => typeof digest !== 'string')
    ) {
      throw new GMFValidationError('seedDeltaChain requires appliedDigests to be an array of strings');
    }

    this.deltaChainHash = seed.chainHash;
    this.appliedDeltaDigests = new Set(seed.appliedDigests);
  }

  /**
   * Digests of every delta accepted so far (local writes and peer deltas).
   * Snapshot this alongside `getDeltaChainHash()` for `seedDeltaChain`.
   */
  public getAppliedDeltaDigests(): string[] {
    return Array.from(this.appliedDeltaDigests);
  }

  // --- Data Structure Management ---

  /**
   * Insert or update an object in the GMF.
   *
   * This is a consensus-gated write: `metadata.consensusAchieved` MUST be true.
   * A caller holding a proposal that has not (yet) achieved consensus gets a
   * typed rejection instead of silently polluting snapshots and recall.
   *
   * @throws GMFConsensusError when consensus has not been achieved
   * @throws GMFValidationError when the payload is structurally invalid
   */
  public async insert(
    semanticObject: { term: unknown; normalForm: string },
    smf: SMFVector,
    metadata: { nodeId: string; proposalId: string; consensusAchieved: boolean },
    initialWeight: number = 1.0
  ): Promise<GMFObject> {
    if (!semanticObject || typeof semanticObject.normalForm !== 'string' || semanticObject.normalForm.length === 0) {
      throw new GMFValidationError('semanticObject.normalForm must be a non-empty string');
    }
    if (!this.isValidSmf(smf)) {
      throw new GMFValidationError('smf must be a 16-dimensional vector of finite numbers');
    }
    if (typeof initialWeight !== 'number' || !Number.isFinite(initialWeight) || initialWeight <= 0) {
      throw new GMFValidationError('initialWeight must be a positive finite number');
    }

    const id = await this.generateObjectId(semanticObject.normalForm);

    if (!metadata || metadata.consensusAchieved !== true) {
      throw new GMFConsensusError(id, metadata?.proposalId ?? 'unknown');
    }

    const existing = this.objects.get(id);
    let deltaType: 'insert' | 'update_weight' = 'insert';

    let obj: GMFObject;

    if (existing) {
      // Update existing
      deltaType = 'update_weight';
      obj = {
        ...existing,
        weight: existing.weight + initialWeight, // simplistic accumulation
        redundancyScore: existing.redundancyScore + 1,
        // Update SMF? Usually SMF is intrinsic to the object's meaning.
        // If meaning changes, it's a new object.
      };
    } else {
      // Create new
      obj = {
        id,
        semanticObject,
        weight: initialWeight,
        smf,
        insertedAt: Date.now(),
        proposalId: metadata.proposalId,
        redundancyScore: 1,
        metadata
      };
    }

    this.objects.set(id, obj);
    this.recordDelta(deltaType, id, obj);

    return obj;
  }

  public getObject(id: string): GMFObject | undefined {
    return this.objects.get(id);
  }

  public getAllObjects(): GMFObject[] {
    return Array.from(this.objects.values());
  }

  // --- Synchronization & Snapshots ---

  /**
   * Create a snapshot of the current state.
   * Snapshots are used for synchronization checkpoints.
   */
  public async createSnapshot(): Promise<GMFSnapshot> {
    return this.createSnapshotSync();
  }

  public getSnapshot(id: number): GMFSnapshot | undefined {
    return this.snapshots.get(id);
  }

  public getLatestSnapshot(): GMFSnapshot | undefined {
    return this.snapshots.get(this.currentSnapshotId);
  }

  /**
   * Hash chaining every delta accepted so far (local writes and peer deltas).
   */
  public getDeltaChainHash(): string {
    return this.deltaChainHash;
  }

  /**
   * Reason the last applyDelta() call was refused (null if it was accepted).
   */
  public getLastDeltaRejection(): string | null {
    return this.lastDeltaRejection;
  }

  /**
   * Apply a delta from a peer.
   *
   * The payload is never trusted as-is: the envelope is shape-checked, the
   * object is re-derived and re-hashed against the content address carried by
   * the delta id, replays are rejected via the delta digest set, and weight
   * updates must be monotonic against local state.
   */
  public applyDelta(delta: GMFDelta): boolean {
    this.lastDeltaRejection = null;

    if (!this.isWellFormedEnvelope(delta)) {
      return this.rejectDelta('malformed delta envelope');
    }

    if (delta.timestamp < (this.getLatestSnapshot()?.timestamp || 0)) {
      // Old delta: it predates our latest checkpoint, so it cannot advance state.
      return this.rejectDelta('stale delta (predates latest snapshot)');
    }

    const digest = this.deltaDigest(delta);
    if (this.appliedDeltaDigests.has(digest)) {
      return this.rejectDelta('duplicate delta (already applied)');
    }

    if (delta.type === 'remove') {
      if (!this.objects.has(delta.id)) {
        return this.rejectDelta('remove targets an unknown object');
      }
      this.objects.delete(delta.id);
      this.commitDelta(delta, digest);
      return true;
    }

    // insert | update_weight: validate the payload against the hash chain.
    const candidate = this.validateObjectPayload(delta);
    if (!candidate) return false; // rejection reason already recorded

    if (this.consensusVerifier) {
      try {
        if (!this.consensusVerifier.verify(candidate)) {
          return this.rejectDelta('delta payload failed consensus verification');
        }
      } catch (error) {
        return this.rejectDelta(
          `delta payload could not be consensus-verified: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    } else {
      // Fail closed: without a verifier the payload's `consensusAchieved`
      // flag is self-attested by the peer and cannot be trusted. Only the
      // local insert() path may write without a verifier, and it stays gated
      // on metadata.consensusAchieved === true.
      return this.rejectDelta(
        'peer delta rejected: no consensus verifier configured (self-attested consensus flag)'
      );
    }

    const existing = this.objects.get(delta.id);

    if (delta.type === 'update_weight') {
      if (!existing) {
        return this.rejectDelta('update_weight for an object we do not hold');
      }
      if (existing.semanticObject.normalForm !== candidate.semanticObject.normalForm) {
        return this.rejectDelta('update_weight would rewrite the object meaning');
      }
      if (candidate.weight < existing.weight) {
        return this.rejectDelta('update_weight is not monotonic (weight rollback)');
      }
    } else if (existing) {
      return this.rejectDelta('insert for an object that already exists');
    }

    this.objects.set(delta.id, candidate);
    this.commitDelta(delta, digest);
    return true;
  }

  /**
   * Get deltas since a specific snapshot.
   * Returns deltas with timestamp >= snapshot.timestamp (inclusive)
   */
  public getDeltasSince(snapshotId: number): GMFDelta[] {
    const snapshot = this.snapshots.get(snapshotId);
    if (!snapshot) return []; // Or throw, or return all if snapshotId is 0
    return this.deltas.filter(d => d.timestamp >= snapshot.timestamp);
  }

  // --- Internal Helpers ---

  private recordDelta(type: 'insert' | 'update_weight' | 'remove', id: string, data?: GMFObject) {
    const delta: GMFDelta = {
      type,
      id,
      timestamp: Date.now(),
      snapshotId: this.currentSnapshotId,
      data
    };
    this.commitDelta(delta, this.deltaDigest(delta));
  }

  /**
   * Append an accepted delta to the log and extend the delta hash chain.
   */
  private commitDelta(delta: GMFDelta, digest: string): void {
    this.deltas.push(delta);
    this.appliedDeltaDigests.add(digest);
    this.deltaChainHash = this.hashStringSync(this.deltaChainHash + digest);
  }

  /**
   * Canonical digest of a delta (stable key order) used for replay detection
   * and for extending the delta chain.
   */
  private deltaDigest(delta: GMFDelta): string {
    return this.hashStringSync(stableStringify({
      type: delta.type,
      id: delta.id,
      timestamp: delta.timestamp,
      snapshotId: delta.snapshotId,
      data: delta.data ?? null
    }));
  }

  private rejectDelta(reason: string): false {
    this.lastDeltaRejection = reason;
    return false;
  }

  private isWellFormedEnvelope(delta: GMFDelta | undefined | null): delta is GMFDelta {
    if (!delta || typeof delta !== 'object') return false;
    if (delta.type !== 'insert' && delta.type !== 'update_weight' && delta.type !== 'remove') return false;
    if (typeof delta.id !== 'string' || delta.id.length === 0) return false;
    if (typeof delta.timestamp !== 'number' || !Number.isFinite(delta.timestamp) || delta.timestamp <= 0) return false;
    if (typeof delta.snapshotId !== 'number' || !Number.isInteger(delta.snapshotId) || delta.snapshotId < 0) return false;
    return true;
  }

  /**
   * Re-derive a trusted GMFObject from an untrusted delta payload.
   *
   * The object id is a content address of the normal form, so a payload whose
   * meaning (or claimed id) has been tampered with cannot hash back to the
   * delta id and is rejected.
   */
  private validateObjectPayload(delta: GMFDelta): GMFObject | null {
    const data = delta.data as Partial<GMFObject> | undefined;

    if (!data || typeof data !== 'object') {
      this.rejectDelta('missing delta payload');
      return null;
    }

    const semantic = data.semanticObject;
    if (!semantic || typeof semantic.normalForm !== 'string' || semantic.normalForm.length === 0) {
      this.rejectDelta('payload has no semanticObject.normalForm');
      return null;
    }

    if (typeof data.weight !== 'number' || !Number.isFinite(data.weight) || data.weight < 0) {
      this.rejectDelta('payload weight is not a non-negative finite number');
      return null;
    }

    if (!this.isValidSmf(data.smf)) {
      this.rejectDelta('payload smf is not a 16-dimensional finite vector');
      return null;
    }

    if (!data.metadata || data.metadata.consensusAchieved !== true) {
      this.rejectDelta('payload has not achieved consensus');
      return null;
    }

    const expectedId = this.hashStringSync(semantic.normalForm);
    if (delta.id !== expectedId || data.id !== expectedId) {
      this.rejectDelta('payload does not hash to the delta id (tampered delta)');
      return null;
    }

    return {
      id: expectedId,
      semanticObject: { term: semantic.term, normalForm: semantic.normalForm },
      weight: data.weight,
      smf: [...data.smf],
      insertedAt: typeof data.insertedAt === 'number' && Number.isFinite(data.insertedAt)
        ? data.insertedAt
        : delta.timestamp,
      proposalId: typeof data.proposalId === 'string' ? data.proposalId : '',
      redundancyScore: typeof data.redundancyScore === 'number' && Number.isFinite(data.redundancyScore)
        ? data.redundancyScore
        : 1,
      metadata: {
        nodeId: typeof data.metadata.nodeId === 'string' ? data.metadata.nodeId : 'unknown',
        consensusAchieved: true
      }
    };
  }

  private isValidSmf(smf: unknown): smf is number[] {
    return Array.isArray(smf)
      && smf.length === 16
      && smf.every(n => typeof n === 'number' && Number.isFinite(n));
  }

  private async generateObjectId(content: string): Promise<string> {
    return this.hashStringSync(content);
  }

  private hashStringSync(content: string): string {
    const hash = createHash('sha256');
    hash.update(content);
    return hash.digest('hex');
  }

  /**
   * Synchronous snapshot creation for constructor.
   *
   * The snapshot content commits to the full identity of every object
   * (content address + weight + SMF digest + normal form), chained to the
   * previous snapshot hash. Weight-only coverage would let a peer swap an
   * object's meaning or SMF without changing the checkpoint.
   *
   * Every joined component is length-prefixed (`<len>:<value>`), so a normal
   * form that itself contains `|` or `:` cannot be confused with the join
   * boundaries (e.g. `a|b` as one object vs `a` + `b` as two).
   */
  private createSnapshotSync(): GMFSnapshot {
    const timestamp = Date.now();
    const objectCount = this.objects.size;

    const sortedIds = Array.from(this.objects.keys()).sort();
    const stateStr = sortedIds.map(id => {
      const obj = this.objects.get(id)!;
      return [
        id,
        obj.weight.toFixed(4),
        smfHash(obj.smf),
        obj.semanticObject.normalForm
      ]
        .map(component => `${component.length}:${component}`)
        .join('');
    }).join('');

    const hash = this.hashStringSync(stateStr + this.lastSnapshotHash);

    this.currentSnapshotId++;
    const snapshot: GMFSnapshot = {
      id: this.currentSnapshotId,
      timestamp,
      objectCount,
      hash
    };

    this.snapshots.set(this.currentSnapshotId, snapshot);
    this.lastSnapshotHash = hash;

    return snapshot;
  }

  // --- Sync Logic Stub ---
  // The design doc mentions "Coherence-gated writes".
  // This class manages the STORE. The Consensus module governs the WRITE access.
  // But we can add a method to verify state against a peer's snapshot.

  public verifyState(peerSnapshot: GMFSnapshot): { valid: boolean; missingDeltas: boolean } {
    const mySnapshot = this.getSnapshot(peerSnapshot.id);
    if (!mySnapshot) {
       // We don't have this snapshot history
       return { valid: false, missingDeltas: true };
    }
    if (mySnapshot.hash !== peerSnapshot.hash) {
      // Divergence detected
      return { valid: false, missingDeltas: false };
    }
    return { valid: true, missingDeltas: false };
  }
}
