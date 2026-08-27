import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { GlobalMemoryField, GMFConsensusError, GMFValidationError, GMFConsensusVerifier } from '../../src/core/GMF';
import { SMFVector, GMFObject, GMFDelta } from '../../src/core/types';
import { createHash } from 'crypto';

describe('GlobalMemoryField', () => {
  let gmf: GlobalMemoryField;
  const mockSmf: SMFVector = Array(16).fill(0) as unknown as SMFVector;
  const mockMetadata = {
    nodeId: 'node-1',
    proposalId: 'prop-1',
    consensusAchieved: true
  };

  /** Permissive verifier: accepts every payload (tests default trust). */
  const permissiveVerifier: GMFConsensusVerifier = { verify: () => true };

  /** Object ids are content addresses of the normal form. */
  const contentId = (normalForm: string): string =>
    createHash('sha256').update(normalForm).digest('hex');

  /** A well-formed, consensus-bearing delta payload. */
  const objectFor = (normalForm: string, overrides: Partial<GMFObject> = {}): GMFObject => ({
    id: contentId(normalForm),
    semanticObject: { term: normalForm, normalForm },
    weight: 1,
    smf: mockSmf,
    insertedAt: Date.now(),
    proposalId: 'p1',
    redundancyScore: 1,
    metadata: { nodeId: 'n1', consensusAchieved: true },
    ...overrides
  });

  const deltaFor = (
    type: GMFDelta['type'],
    normalForm: string,
    data?: unknown,
    timestampOffset: number = 1000
  ): GMFDelta => ({
    type,
    id: contentId(normalForm),
    timestamp: Date.now() + timestampOffset,
    snapshotId: 1,
    data
  });

  beforeEach(() => {
    gmf = new GlobalMemoryField(permissiveVerifier);
  });

  describe('insert', () => {
    it('should create a new object if it does not exist', async () => {
      const obj = await gmf.insert(
        { term: 'test', normalForm: 'test' },
        mockSmf,
        mockMetadata
      );

      expect(obj).toBeDefined();
      expect(obj.semanticObject.normalForm).toBe('test');
      expect(obj.weight).toBe(1.0);
      expect(obj.redundancyScore).toBe(1);
      
      const stored = gmf.getObject(obj.id);
      expect(stored).toEqual(obj);
    });

    it('should update existing object', async () => {
      // First insert
      await gmf.insert(
        { term: 'test', normalForm: 'test' },
        mockSmf,
        mockMetadata
      );
      
      // Second insert (same normalForm)
      const obj = await gmf.insert(
        { term: 'test', normalForm: 'test' },
        mockSmf,
        mockMetadata
      );
      
      expect(obj.weight).toBe(2.0);
      expect(obj.redundancyScore).toBe(2);
    });

    it('should refuse to insert an object that has not achieved consensus', async () => {
      await expect(
        gmf.insert(
          { term: 'rogue', normalForm: 'rogue' },
          mockSmf,
          { nodeId: 'node-1', proposalId: 'prop-rogue', consensusAchieved: false }
        )
      ).rejects.toThrow(GMFConsensusError);

      // Nothing leaked into the store or the snapshot
      expect(gmf.getObject(contentId('rogue'))).toBeUndefined();
      expect(gmf.getAllObjects()).toHaveLength(0);
      const snapshot = await gmf.createSnapshot();
      expect(snapshot.objectCount).toBe(0);
    });

    it('should reject structurally invalid payloads', async () => {
      await expect(
        gmf.insert({ term: 'x', normalForm: '' }, mockSmf, mockMetadata)
      ).rejects.toThrow(/normalForm/);

      await expect(
        gmf.insert(
          { term: 'x', normalForm: 'x' },
          [1, 2, 3] as unknown as SMFVector,
          mockMetadata
        )
      ).rejects.toThrow(/16-dimensional/);
    });
  });

  describe('Snapshots', () => {
    it('should create initial snapshot on construction', () => {
      const snapshot = gmf.getLatestSnapshot();
      expect(snapshot).toBeDefined();
      expect(snapshot?.id).toBeGreaterThan(0);
    });

    it('should create new snapshot with correct ID', async () => {
      const initial = gmf.getLatestSnapshot()!;
      await gmf.insert(
        { term: 'test', normalForm: 'test' },
        mockSmf,
        mockMetadata
      );
      
      const newSnapshot = await gmf.createSnapshot();
      expect(newSnapshot.id).toBe(initial.id + 1);
      expect(newSnapshot.objectCount).toBe(1);
      expect(newSnapshot.hash).not.toBe(initial.hash);
    });

    it('should cover smf and normal form, not just id and weight', async () => {
      const otherSmf = Array(16).fill(0) as unknown as SMFVector;
      otherSmf[3] = 0.5; // same id + same weight, different meaning vector

      const a = new GlobalMemoryField();
      const b = new GlobalMemoryField();

      const objA = await a.insert({ term: 'same', normalForm: 'same' }, mockSmf, mockMetadata);
      const objB = await b.insert({ term: 'same', normalForm: 'same' }, otherSmf, mockMetadata);

      expect(objA.id).toBe(objB.id);
      expect(objA.weight).toBe(objB.weight);

      const snapA = await a.createSnapshot();
      const snapB = await b.createSnapshot();
      expect(snapA.hash).not.toBe(snapB.hash);
    });

    it('should not collide when normal forms contain join separators', async () => {
      // 'left|right' as one object must hash differently from two objects
      // 'left' + 'right', and ':'-bearing normal forms must stay distinct.
      const one = new GlobalMemoryField();
      const two = new GlobalMemoryField();
      const colon = new GlobalMemoryField();

      await one.insert({ term: 'x', normalForm: 'left|right' }, mockSmf, mockMetadata);
      await two.insert({ term: 'x', normalForm: 'left' }, mockSmf, mockMetadata);
      await two.insert({ term: 'x', normalForm: 'right' }, mockSmf, mockMetadata);
      await colon.insert({ term: 'x', normalForm: 'a:b:c' }, mockSmf, mockMetadata);

      const snapOne = await one.createSnapshot();
      const snapTwo = await two.createSnapshot();
      const snapColon = await colon.createSnapshot();

      expect(snapOne.hash).not.toBe(snapTwo.hash);
      expect(snapOne.hash).not.toBe(snapColon.hash);
      expect(snapTwo.hash).not.toBe(snapColon.hash);
    });
  });

  describe('applyDelta', () => {
    it('should apply insert delta', async () => {
      const deltaObj = objectFor('foo');
      const applied = gmf.applyDelta(deltaFor('insert', 'foo', deltaObj));

      expect(applied).toBe(true);
      expect(gmf.getLastDeltaRejection()).toBeNull();
      expect(gmf.getObject(deltaObj.id)).toEqual(deltaObj);
    });

    it('should extend the delta hash chain on every accepted delta', () => {
      const before = gmf.getDeltaChainHash();
      expect(gmf.applyDelta(deltaFor('insert', 'chain', objectFor('chain')))).toBe(true);
      expect(gmf.getDeltaChainHash()).not.toBe(before);
    });

    it('should apply remove delta', async () => {
        // Setup existing object
        await gmf.insert({ term: 'del', normalForm: 'del' }, mockSmf, mockMetadata);
        const objs = gmf.getAllObjects();
        const id = objs[0].id;

        const applied = gmf.applyDelta({
            type: 'remove',
            id: id,
            timestamp: Date.now() + 1000,
            snapshotId: 1
        });

        expect(applied).toBe(true);
        expect(gmf.getObject(id)).toBeUndefined();
    });

    it('should reject a remove for an object we do not hold', () => {
        const applied = gmf.applyDelta(deltaFor('remove', 'ghost'));
        expect(applied).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('unknown object');
    });

    it('should ignore old deltas', async () => {
        const latestSnapshotTimestamp = gmf.getLatestSnapshot()!.timestamp;
        
        const applied = gmf.applyDelta({
            type: 'insert',
            id: 'old',
            timestamp: latestSnapshotTimestamp - 1000,
            snapshotId: 0,
            data: {}
        });
        
        expect(applied).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('stale delta');
    });

    it('should reject a replayed (duplicate) delta', () => {
        const delta = deltaFor('insert', 'dup', objectFor('dup'));

        expect(gmf.applyDelta(delta)).toBe(true);
        expect(gmf.applyDelta({ ...delta })).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('duplicate delta');
    });

    it('should reject a tampered payload that no longer hashes to the delta id', () => {
        const tampered = objectFor('honest');
        tampered.semanticObject = { term: 'evil', normalForm: 'evil' };

        const applied = gmf.applyDelta(deltaFor('insert', 'honest', tampered));

        expect(applied).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('tampered delta');
        expect(gmf.getObject(contentId('honest'))).toBeUndefined();
    });

    it('should reject a payload whose claimed id was swapped', () => {
        const spoofed = objectFor('legit', { id: 'i-claim-this-id' });
        const applied = gmf.applyDelta(deltaFor('insert', 'legit', spoofed));

        expect(applied).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('tampered delta');
    });

    it('should reject malformed payloads', () => {
        expect(gmf.applyDelta(deltaFor('insert', 'nodata'))).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('missing delta payload');

        const badSmf = objectFor('badsmf', { smf: [1, 2] });
        expect(gmf.applyDelta(deltaFor('insert', 'badsmf', badSmf))).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('smf');

        const badWeight = objectFor('badweight', { weight: Number.NaN });
        expect(gmf.applyDelta(deltaFor('insert', 'badweight', badWeight))).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('weight');
    });

    it('should reject a malformed envelope', () => {
        const applied = gmf.applyDelta({
            type: 'insert',
            id: '',
            timestamp: Date.now() + 1000,
            snapshotId: 1,
            data: objectFor('whatever')
        });
        expect(applied).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('malformed delta envelope');
    });

    it('should reject deltas carrying non-consensus objects', () => {
        const unconsented = objectFor('unconsented', {
            metadata: { nodeId: 'n1', consensusAchieved: false }
        });

        const applied = gmf.applyDelta(deltaFor('insert', 'unconsented', unconsented));

        expect(applied).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('consensus');
    });

    it('should reject update_weight for unknown objects and weight rollbacks', () => {
        expect(
          gmf.applyDelta(deltaFor('update_weight', 'unseen', objectFor('unseen')))
        ).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('we do not hold');

        // Establish the object at weight 5, then attempt a rollback to weight 1
        expect(
          gmf.applyDelta(deltaFor('insert', 'grow', objectFor('grow', { weight: 5 })))
        ).toBe(true);
        expect(
          gmf.applyDelta(deltaFor('update_weight', 'grow', objectFor('grow', { weight: 1 }), 2000))
        ).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('not monotonic');

        // A monotonic increase is accepted
        expect(
          gmf.applyDelta(deltaFor('update_weight', 'grow', objectFor('grow', { weight: 7 }), 3000))
        ).toBe(true);
        expect(gmf.getObject(contentId('grow'))?.weight).toBe(7);
    });

    it('should reject an insert for an object that already exists', () => {
        expect(gmf.applyDelta(deltaFor('insert', 'twice', objectFor('twice')))).toBe(true);
        expect(
          gmf.applyDelta(deltaFor('insert', 'twice', objectFor('twice', { weight: 9 }), 2000))
        ).toBe(false);
        expect(gmf.getLastDeltaRejection()).toContain('already exists');
    });
  });

  describe('consensus verification of peer deltas', () => {
    it('should reject a self-attested consensus flag when no verifier is configured', () => {
        const unverified = new GlobalMemoryField();
        const applied = unverified.applyDelta(
            deltaFor('insert', 'self-attested', objectFor('self-attested'))
        );

        expect(applied).toBe(false);
        expect(unverified.getLastDeltaRejection()).toContain('no consensus verifier');
        expect(unverified.getObject(contentId('self-attested'))).toBeUndefined();
    });

    it('should accept a payload the verifier approves', () => {
        const verified = new GlobalMemoryField({ verify: () => true });

        expect(verified.applyDelta(deltaFor('insert', 'ok', objectFor('ok')))).toBe(true);
        expect(verified.getObject(contentId('ok'))).toBeDefined();
    });

    it('should reject a payload the verifier refuses', () => {
        const suspicious = new GlobalMemoryField({
            verify: (payload: GMFObject) => payload.weight < 100
        });

        expect(
            suspicious.applyDelta(deltaFor('insert', 'heavy', objectFor('heavy', { weight: 999 })))
        ).toBe(false);
        expect(suspicious.getLastDeltaRejection()).toContain('failed consensus verification');
        expect(suspicious.getObject(contentId('heavy'))).toBeUndefined();
    });

    it('should reject when the verifier throws', () => {
        const broken = new GlobalMemoryField({
            verify: () => { throw new Error('verifier unavailable'); }
        });

        expect(broken.applyDelta(deltaFor('insert', 'any', objectFor('any')))).toBe(false);
        expect(broken.getLastDeltaRejection()).toContain('could not be consensus-verified');
    });

    it('should still allow the local insert path without a verifier', async () => {
        const unverified = new GlobalMemoryField();

        await expect(
            unverified.insert({ term: 'x', normalForm: 'local' }, mockSmf, mockMetadata)
        ).resolves.toBeDefined();
        expect(unverified.getObject(contentId('local'))).toBeDefined();
    });

    it('should still allow removes without a verifier', async () => {
        const unverified = new GlobalMemoryField();
        await unverified.insert({ term: 'x', normalForm: 'del' }, mockSmf, mockMetadata);

        expect(unverified.applyDelta(deltaFor('remove', 'del'))).toBe(true);
        expect(unverified.getObject(contentId('del'))).toBeUndefined();
    });
  });

  describe('seedDeltaChain', () => {
    it('should restore replay protection from seeded digests', () => {
        const first = new GlobalMemoryField(permissiveVerifier);
        const delta = deltaFor('insert', 'seed', objectFor('seed'));

        expect(first.applyDelta(delta)).toBe(true);
        const chainHash = first.getDeltaChainHash();
        const digests = first.getAppliedDeltaDigests();
        expect(digests).toHaveLength(1);

        const restored = new GlobalMemoryField(permissiveVerifier);
        restored.seedDeltaChain({ chainHash, appliedDigests: digests });

        expect(restored.getDeltaChainHash()).toBe(chainHash);
        expect(restored.getAppliedDeltaDigests()).toEqual(digests);

        // The already-applied delta is now a replay.
        expect(restored.applyDelta(delta)).toBe(false);
        expect(restored.getLastDeltaRejection()).toContain('duplicate delta');
    });

    it('should reject a malformed seed', () => {
        const unseeded = new GlobalMemoryField();

        expect(() =>
            unseeded.seedDeltaChain({ chainHash: '', appliedDigests: [] })
        ).toThrow(GMFValidationError);
        expect(() =>
            unseeded.seedDeltaChain({ chainHash: 'x', appliedDigests: [1] as unknown as string[] })
        ).toThrow(GMFValidationError);
    });
  });

  describe('getDeltasSince', () => {
    it('should return recent deltas', async () => {
      const snap1 = gmf.getLatestSnapshot()!;
      
      await gmf.insert({ term: 'a', normalForm: 'a' }, mockSmf, mockMetadata);
      
      const deltas = gmf.getDeltasSince(snap1.id);
      expect(deltas.length).toBe(1); // The insert we just did
      expect(deltas[0].type).toBe('insert');
    });
  });

  describe('verifyState', () => {
    it('should validate matching snapshots', async () => {
      const snap = gmf.getLatestSnapshot()!;
      const result = gmf.verifyState(snap);
      expect(result.valid).toBe(true);
      expect(result.missingDeltas).toBe(false);
    });

    it('should detect unknown snapshot', () => {
      const result = gmf.verifyState({
          id: 999,
          timestamp: 0,
          objectCount: 0,
          hash: 'unknown'
      });
      expect(result.valid).toBe(false);
      expect(result.missingDeltas).toBe(true);
    });

    it('should detect divergence (same ID, diff hash)', () => {
      const snap = gmf.getLatestSnapshot()!;
      const result = gmf.verifyState({
          ...snap,
          hash: 'different-hash'
      });
      expect(result.valid).toBe(false);
      expect(result.missingDeltas).toBe(false);
    });
  });
});
