import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { ConsensusProtocol, ConsensusProposal, Vote } from '../../src/core/Consensus';
import { DSNNodeConfig, GMFObject, SMFVector } from '../../src/core/types';
import { smfHash } from '../../src/common/hash';

describe('ConsensusProtocol', () => {
  let protocol: ConsensusProtocol;
  const mockSmf: SMFVector = Array(16).fill(0.1) as unknown as SMFVector;
  // Make domain deterministic: idx 4-7 are cognitive.
  mockSmf[5] = 1.0; 

  const mockObject: GMFObject = {
    id: 'obj-1',
    semanticObject: { term: 'test', normalForm: 'test' },
    weight: 1,
    smf: mockSmf,
    insertedAt: Date.now(),
    proposalId: '',
    redundancyScore: 1,
    metadata: { nodeId: 'n1', consensusAchieved: false }
  };

  const baseVoter: DSNNodeConfig = {
    nodeId: 'voter-1',
    name: 'Voter',
    domain: 'cognitive',
    seaPublicKey: 'key',
    gunPeers: [],
    keyTriplet: {} as any,
    semanticDomain: 'cognitive', // Matches mockObject
    primeDomain: [],
    smfAxes: [],
    sriaCapable: true,
    bootstrapUrl: '',
    status: 'ONLINE',
    lastHeartbeat: 0,
    supportedProviders: [],
    hostedSkills: [],
    loadIndex: 0,
    stakingTier: 'Neophyte', // Multiplier 1
    alephBalance: 0
  };

  /** Voter config whose nodeId matches the ballot's voterId. */
  const voterFor = (id: string, overrides: Partial<DSNNodeConfig> = {}): DSNNodeConfig => ({
    ...baseVoter,
    nodeId: id,
    ...overrides
  });

  /** Ballot without any weight: the protocol derives it. */
  const ballot = (
    id: string,
    choice: 'SUPPORT' | 'CONTEST',
    overrides: Partial<Vote> = {}
  ): Vote => ({
    voterId: id,
    vote: choice,
    stakeAmount: 10,
    timestamp: 0,
    voterConfig: voterFor(id),
    ...overrides
  });

  beforeEach(() => {
    protocol = new ConsensusProtocol('local-node');
  });

  describe('createProposal', () => {
    it('should create valid proposal if coherence high', () => {
      const prop = protocol.createProposal(mockObject, 'proposer-1', 100, 0.8);
      expect(prop.tickProof.valid).toBe(true);
      expect(prop.targetObject).toBe(mockObject);
    });

    it('should create invalid proposal if coherence low', () => {
      const prop = protocol.createProposal(mockObject, 'proposer-1', 100, 0.5);
      expect(prop.tickProof.valid).toBe(false);
    });

    it('should commit to a real sha256 smf hash (not a float join)', () => {
      const prop = protocol.createProposal(mockObject, 'proposer-1', 100, 0.9);
      expect(prop.smfHash).toMatch(/^[0-9a-f]{64}$/);
      expect(prop.smfHash).toBe(smfHash(mockSmf));
      expect(prop.smfHash).not.toContain(',');
    });
  });

  describe('calculateVoteWeight', () => {
    it('should give base weight for matching domain', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 1);
      const weight = protocol.calculateVoteWeight(baseVoter, prop);
      // Domain match (1.5) * Prime (1.0) * Axis (1+0) * Tier (1) = 1.5
      expect(weight).toBeCloseTo(1.5);
    });

    it('should penalty for domain mismatch', () => {
      const mismatchVoter = { ...baseVoter, semanticDomain: 'perceptual' as any };
      const prop = protocol.createProposal(mockObject, 'p1', 1, 1);
      const weight = protocol.calculateVoteWeight(mismatchVoter, prop);
      // Mismatch (0.5) ... = 0.5
      expect(weight).toBeCloseTo(0.5);
    });

    it('should apply tier multiplier', () => {
      const archonVoter = { ...baseVoter, stakingTier: 'Archon' as any };
      const prop = protocol.createProposal(mockObject, 'p1', 1, 1);
      const weight = protocol.calculateVoteWeight(archonVoter, prop);
      // 1.5 * 10 = 15
      expect(weight).toBeCloseTo(15.0);
    });

    it('should scale weight by reputation', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 1);
      // 1.5 * 0.5 reputation = 0.75
      expect(protocol.calculateVoteWeight(baseVoter, prop, 0.5)).toBeCloseTo(0.75);
      // Reputation cannot inflate weight beyond the earned tier value
      expect(protocol.calculateVoteWeight(baseVoter, prop, 99)).toBeCloseTo(1.5);
    });
  });

  describe('evaluateProposal', () => {
    it('should reject if proof is invalid', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.1); // invalid
      const result = protocol.evaluateProposal(prop, []);
      expect(result.accepted).toBe(false);
      expect(result.reason).toContain('Invalid tick proof');
    });

    it('should reject a forged proof flag when coherence is below threshold', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      // Attacker flips `valid` but cannot raise the actual coherence
      prop.tickProof.valid = true;
      prop.tickProof.coherence = 0.2;

      const result = protocol.evaluateProposal(prop, [
        ballot('v1', 'SUPPORT'),
        ballot('v2', 'SUPPORT'),
        ballot('v3', 'SUPPORT')
      ]);

      expect(result.accepted).toBe(false);
      expect(result.reason).toContain('Coherence below threshold');
      expect(result.totalSupport).toBe(0);
    });

    it('should reject if no votes', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const result = protocol.evaluateProposal(prop, []);
      expect(result.accepted).toBe(false);
      expect(result.reason).toContain('No votes');
    });

    it('should reject below the minimum quorum of 3 distinct voters', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const result = protocol.evaluateProposal(prop, [
        ballot('v1', 'SUPPORT'),
        ballot('v2', 'SUPPORT')
      ]);

      expect(result.accepted).toBe(false);
      expect(result.distinctVoters).toBe(2);
      expect(result.reason).toContain('Quorum not met');
    });

    it('should not reach quorum by ballot stuffing from one voter', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const result = protocol.evaluateProposal(prop, [
        ballot('v1', 'SUPPORT'),
        ballot('v1', 'SUPPORT'),
        ballot('v1', 'SUPPORT'),
        ballot('v1', 'SUPPORT')
      ]);

      expect(result.accepted).toBe(false);
      expect(result.distinctVoters).toBe(1);
      expect(result.rejectedVotes).toBe(3);
      expect(result.reason).toContain('Quorum not met');
    });

    it('should count only one ballot per voter (highest weight survives)', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const result = protocol.evaluateProposal(prop, [
        // Same voter twice: Neophyte (1.5) then Archon (15). Only one counts.
        ballot('v1', 'SUPPORT'),
        ballot('v1', 'SUPPORT', { voterConfig: voterFor('v1', { stakingTier: 'Archon' }) }),
        ballot('v2', 'SUPPORT'),
        ballot('v3', 'CONTEST')
      ]);

      expect(result.distinctVoters).toBe(3);
      expect(result.rejectedVotes).toBe(1);
      // v1 = 15 (highest of its two ballots), v2 = 1.5
      expect(result.totalSupport).toBeCloseTo(16.5);
      expect(result.totalContest).toBeCloseTo(1.5);
    });

    it('should ignore a caller-supplied weight entirely', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      // A malicious peer injects a weight field onto the wire format
      const stuffed = {
        ...ballot('v1', 'SUPPORT'),
        weight: 9999
      } as unknown as Vote;

      const result = protocol.evaluateProposal(prop, [
        stuffed,
        ballot('v2', 'CONTEST'),
        ballot('v3', 'CONTEST')
      ]);

      // Recomputed weights: 1.5 support vs 3.0 contest
      expect(result.totalSupport).toBeCloseTo(1.5);
      expect(result.totalContest).toBeCloseTo(3.0);
      expect(result.accepted).toBe(false);
    });

    it('should discard ballots whose attached config claims another identity', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const result = protocol.evaluateProposal(prop, [
        ballot('v1', 'SUPPORT', { voterConfig: voterFor('someone-else') }),
        ballot('v2', 'SUPPORT'),
        ballot('v3', 'SUPPORT')
      ]);

      expect(result.distinctVoters).toBe(2);
      expect(result.rejectedVotes).toBe(1);
      expect(result.accepted).toBe(false);
    });

    it('should discard ballots below the minimum vote stake', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const result = protocol.evaluateProposal(prop, [
        ballot('v1', 'SUPPORT', { stakeAmount: 1 }),
        ballot('v2', 'SUPPORT'),
        ballot('v3', 'SUPPORT')
      ]);

      expect(result.distinctVoters).toBe(2);
      expect(result.rejectedVotes).toBe(1);
      expect(result.reason).toContain('Quorum not met');
    });

    it('should reject ballots with a non-finite stake amount', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const result = protocol.evaluateProposal(prop, [
        ballot('v1', 'SUPPORT', { stakeAmount: Number.NaN }),
        ballot('v2', 'SUPPORT', { stakeAmount: Number.POSITIVE_INFINITY }),
        ballot('v3', 'SUPPORT')
      ]);

      expect(result.distinctVoters).toBe(1);
      expect(result.rejectedVotes).toBe(2);
      expect(result.reason).toContain('Quorum not met');
    });

    it('should treat case/whitespace variants of one voter id as a single voter', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const result = protocol.evaluateProposal(prop, [
        ballot('v1', 'SUPPORT'),
        ballot('V1', 'SUPPORT', { voterConfig: voterFor('V1') }),
        ballot(' v1 ', 'SUPPORT', { voterConfig: voterFor(' v1 ') }),
        ballot('v2', 'SUPPORT')
      ]);

      expect(result.distinctVoters).toBe(2);
      expect(result.rejectedVotes).toBe(2);
      expect(result.reason).toContain('Quorum not met');
    });

    it('should give config-less ballots zero weight and no quorum contribution', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const anonymous: Vote[] = Array.from({ length: 10 }, (_, i) => ({
        voterId: `anon-${i}`,
        vote: 'SUPPORT',
        stakeAmount: 100,
        timestamp: 0
      }));

      const result = protocol.evaluateProposal(prop, anonymous);

      expect(result.distinctVoters).toBe(0);
      expect(result.totalSupport).toBe(0);
      expect(result.rejectedVotes).toBe(10);
      expect(result.reason).toContain('No votes');
    });

    it('should count only registry-listed voters toward quorum when a registry is provided', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const registry = new Map<string, DSNNodeConfig>([['v1', voterFor('v1')]]);

      const result = protocol.evaluateProposal(
        prop,
        [
          ballot('v1', 'SUPPORT'),
          ballot('v2', 'SUPPORT'),
          ballot('v3', 'SUPPORT'),
          ballot('v4', 'SUPPORT')
        ],
        registry
      );

      expect(result.distinctVoters).toBe(1);
      expect(result.rejectedVotes).toBe(3);
      expect(result.reason).toContain('Quorum not met');
    });

    it('should accept at exactly the 2/3 boundary', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const result = protocol.evaluateProposal(prop, [
        ballot('v1', 'SUPPORT'),                       // 1.5
        ballot('v2', 'SUPPORT'),                       // 1.5
        ballot('v3', 'CONTEST', { reputation: 0.5 }),  // 0.75
        ballot('v4', 'CONTEST', { reputation: 0.5 })   // 0.75
      ]);

      // 3.0 / 4.5 === 2/3 exactly
      expect(result.weightedRedundancy).toBe(2 / 3);
      expect(result.accepted).toBe(true);
      expect(result.reason).toBe('Consensus achieved');
    });

    it('should reject just below the 2/3 boundary', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const result = protocol.evaluateProposal(prop, [
        ballot('v1', 'SUPPORT'),                       // 1.5
        ballot('v2', 'SUPPORT'),                       // 1.5
        ballot('v3', 'CONTEST', { reputation: 0.5 }),  // 0.75
        ballot('v4', 'CONTEST', { reputation: 0.51 })  // 0.765
      ]);

      expect(result.weightedRedundancy).toBeLessThan(2 / 3);
      expect(result.accepted).toBe(false);
      expect(result.reason).toContain('Insufficient support');
    });

    it('should achieve consensus with sufficient support', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const votes: Vote[] = [
        ballot('v1', 'SUPPORT'),
        ballot('v2', 'SUPPORT'),
        ballot('v3', 'SUPPORT'),
        ballot('v4', 'CONTEST')
      ];
      // Total 6.0. Support 4.5. 4.5/6 = 0.75 >= 2/3
      const result = protocol.evaluateProposal(prop, votes);
      expect(result.accepted).toBe(true);
      expect(result.totalSupport).toBeCloseTo(4.5);
      expect(result.distinctVoters).toBe(4);
    });

    it('should fail consensus with insufficient support', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const votes: Vote[] = [
        ballot('v1', 'SUPPORT'),
        ballot('v2', 'CONTEST'),
        ballot('v3', 'CONTEST')
      ];
      // Total 4.5. Support 1.5. 1.5/4.5 = 0.33 < 2/3
      const result = protocol.evaluateProposal(prop, votes);
      expect(result.accepted).toBe(false);
    });

    it('should resolve weights from an authoritative voter registry', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 0.9);
      const registry = new Map<string, DSNNodeConfig>([
        ['v1', voterFor('v1', { stakingTier: 'Archon' })],
        ['v2', voterFor('v2')],
        ['v3', voterFor('v3')]
      ]);

      const result = protocol.evaluateProposal(
        prop,
        [
          // Ballot lies about its own tier; the registry overrides it
          ballot('v1', 'SUPPORT', { voterConfig: voterFor('v1', { stakingTier: 'Neophyte' }) }),
          ballot('v2', 'SUPPORT'),
          ballot('v3', 'CONTEST')
        ],
        registry
      );

      expect(result.totalSupport).toBeCloseTo(16.5); // 15 + 1.5
      expect(result.accepted).toBe(true);
    });
  });

  describe('castVote', () => {
    it('should build a ballot without any weight field', () => {
      const vote = protocol.castVote(voterFor('v1'), 'SUPPORT', 25);
      expect(vote.voterId).toBe('v1');
      expect(vote.stakeAmount).toBe(25);
      expect((vote as unknown as Record<string, unknown>).weight).toBeUndefined();
    });
  });

  describe('verifyCoherence', () => {
    it('should return true for similar context', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 1);
      // Same vector
      const result = protocol.verifyCoherence(prop, mockSmf);
      expect(result).toBe(true);
    });

    it('should return false for dissimilar context', () => {
      const prop = protocol.createProposal(mockObject, 'p1', 1, 1);
      // Orthogonal vector
      const diffSmf = Array(16).fill(0);
      diffSmf[0] = 1; // Perceptual
      // dot product approx 0
      const result = protocol.verifyCoherence(prop, diffSmf as unknown as SMFVector);
      expect(result).toBe(false);
    });
  });
});
