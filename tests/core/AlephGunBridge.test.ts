import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { AlephGunBridge } from '../../src/core/AlephGunBridge';
import { AgentTriggerEvent } from '../../src/core/types';
import { generateEd25519KeyPair, signToBase64, Ed25519KeyPair } from '../../src/common/crypto';

describe('AlephGunBridge', () => {
  let bridge: AlephGunBridge;
  let mockGun: any;
  let mockDSNNode: any;
  let mockAgentManager: any;

  beforeEach(async () => {
    mockGun = {};
    mockDSNNode = {
      config: {
        nodeId: 'local-node',
        semanticDomain: 'cognitive',
        gunPeers: []
      }
    };
    mockAgentManager = {};

    bridge = new AlephGunBridge();
    await bridge.initialize(mockGun, mockDSNNode, mockAgentManager);
  });

  describe('initialize', () => {
    it('should store dependencies', () => {
      // Since properties are private, we assume success if no error thrown
      // and subsequent methods that use them work.
      expect(bridge).toBeDefined();
    });
  });

  describe('projectToSMF', () => {
    it('should return a 16-dimensional vector', async () => {
      const result = await bridge.projectToSMF('some/path', { data: 'test' });
      expect(result).toHaveLength(16);
      expect(result.every((n: number) => typeof n === 'number')).toBe(true);
    });

    it('should be deterministic', async () => {
      const result1 = await bridge.projectToSMF('path/a', { val: 1 });
      const result2 = await bridge.projectToSMF('path/a', { val: 1 });
      expect(result1).toEqual(result2);
    });

    it('should produce different vectors for different inputs', async () => {
      // Note: hash collision possible but unlikely for simple distinct strings in small test
      const result1 = await bridge.projectToSMF('path/a', { val: 1 });
      const result2 = await bridge.projectToSMF('path/b', { val: 2 });
      expect(result1).not.toEqual(result2);
    });
  });

  describe('routeRequest', () => {
    const baseEvent: AgentTriggerEvent = {
      action: 'NEW_MESSAGE',
      conversationId: 'conv-123',
      routing: {
        preferredDomain: 'cognitive',
        requiredSmfAxes: [2, 3]
      }
    };

    it('should route to self if no peers available', async () => {
      mockDSNNode.config.gunPeers = [];
      const decision = await bridge.routeRequest(baseEvent);
      expect(decision.targetNodeId).toBe('local-node');
      expect(decision.semanticDomainMatch).toBe(true);
    });

    it('should route to self when peers are bare relay URLs (no semantics)', async () => {
      mockDSNNode.config.gunPeers = ['https://relay-1/gun', 'https://relay-2/gun'];
      const decision = await bridge.routeRequest(baseEvent);
      expect(decision.targetNodeId).toBe('local-node');
    });

    it('should route to a peer if available', async () => {
      // Peers publish their semantic identity; the best scoring one wins.
      mockDSNNode.config.knownPeers = [
        { nodeId: 'peer-1', semanticDomain: 'cognitive', primeDomain: [2, 3], loadIndex: 0 },
        { nodeId: 'peer-2', semanticDomain: 'cognitive', primeDomain: [2], loadIndex: 1 }
      ];

      const decision = await bridge.routeRequest(baseEvent);
      // peer-1: domain(+10) + 2 axes(+10) - load(0) = 20
      // peer-2: domain(+10) + 1 axis(+5)  - load(2) = 13
      // self:   domain(+10) + 0 axes      - load(0) = 10
      expect(['peer-1', 'peer-2']).toContain(decision.targetNodeId);
      expect(decision.targetNodeId).toBe('peer-1');
      expect(decision.relevanceScore).toBeGreaterThan(0);
      expect(decision.primeDomainOverlap).toBe(2);
      expect(decision.fallbackNodes).toEqual(['peer-2', 'local-node']);
    });

    it('should route to self when no peer matches the required domain', async () => {
      mockDSNNode.config.knownPeers = [
        { nodeId: 'peer-1', semanticDomain: 'perceptual', primeDomain: [], loadIndex: 0 },
        { nodeId: 'peer-2', semanticDomain: 'temporal', primeDomain: [], loadIndex: 0 }
      ];

      const decision = await bridge.routeRequest(baseEvent);
      expect(decision.targetNodeId).toBe('local-node');
      expect(decision.fallbackNodes).toContain('peer-1');
    });

    it('should use peers exposed via getPeers()', async () => {
      mockDSNNode.getPeers = () => [
        { nodeId: 'discovered-1', semanticDomain: 'cognitive', primeDomain: [2, 3], loadIndex: 0 }
      ];

      const decision = await bridge.routeRequest(baseEvent);
      expect(decision.targetNodeId).toBe('discovered-1');
    });
  });

  describe('verifyCoherence', () => {
    let keyPair: Ed25519KeyPair;

    /** Produce the exact payload the bridge verifies. */
    const signedProof = (
      coherence: number,
      smfHash: string,
      signedCoherence: number = coherence
    ) => ({
      coherenceProof: {
        tickNumber: 1,
        coherence,
        smfHash,
        signature: signToBase64(
          JSON.stringify({ coherence: signedCoherence, smfHash }),
          keyPair.privateKey
        ),
        publicKey: keyPair.publicKeyBase64
      }
    });

    beforeEach(() => {
      keyPair = generateEd25519KeyPair();
    });

    it('should return false if proof is missing', async () => {
      const result = await bridge.verifyCoherence({});
      expect(result).toBe(false);
    });

    it('should return false if coherence is below threshold', async () => {
      const result = await bridge.verifyCoherence(signedProof(0.6, 'abc'));
      expect(result).toBe(false);
    });

    it('should accept a signed proof at exactly the network threshold', async () => {
      // CONSENSUS.MIN_COHERENCE_THRESHOLD is 0.7 — the bridge must agree with it.
      const result = await bridge.verifyCoherence(signedProof(0.7, 'abc'));
      expect(result).toBe(true);
    });

    it('should return false for an unsigned proof even when coherence is high', async () => {
      const result = await bridge.verifyCoherence({
        coherenceProof: { coherence: 0.85, tickNumber: 1, smfHash: 'abc' }
      });
      expect(result).toBe(false);
    });

    it('should return false when the public key is missing', async () => {
      const proof = signedProof(0.85, 'abc');
      const result = await bridge.verifyCoherence({
        coherenceProof: { ...proof.coherenceProof, publicKey: undefined }
      });
      expect(result).toBe(false);
    });

    it('should return false when the signature does not cover the claim', async () => {
      // Signature was produced for 0.85 but the proof claims 0.95
      const result = await bridge.verifyCoherence(signedProof(0.95, 'abc', 0.85));
      expect(result).toBe(false);
    });

    it('should return false when the signature is not valid base64 ed25519', async () => {
      const proof = signedProof(0.85, 'abc');
      const result = await bridge.verifyCoherence({
        coherenceProof: { ...proof.coherenceProof, signature: 'not-a-signature' }
      });
      expect(result).toBe(false);
    });

    it('should return true for a signed proof with sufficient coherence', async () => {
      const result = await bridge.verifyCoherence(signedProof(0.85, 'abc'));
      expect(result).toBe(true);
    });
  });

  describe('syncGMFToGraph', () => {
    it('should run without error', async () => {
      await expect(bridge.syncGMFToGraph()).resolves.not.toThrow();
    });
  });

  describe('handleSRIAEvent', () => {
    it('should handle summon event', async () => {
      await expect(bridge.handleSRIAEvent('summon', { some: 'data' })).resolves.not.toThrow();
    });
    
    it('should handle dismiss event', async () => {
        await expect(bridge.handleSRIAEvent('dismiss', { some: 'data' })).resolves.not.toThrow();
      });
  });
});
