import { describe, it, expect, beforeEach, jest, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DSNNode, DSNNodeOptions, DSNNodeIdentityError } from '../../src/core/DSNNode';
import { SemanticDomain } from '../../src/core/types';
import { generateKeyTriplet } from '../../src/common/crypto';

/**
 * Chainable Gun mock that records every `put` payload.
 */
function createGunMock() {
  const writes: Array<Record<string, any>> = [];
  const chain: any = {
    get: () => chain,
    put: (data: Record<string, any>, cb?: (ack: any) => void) => {
      writes.push(data);
      if (cb) cb({});
      return chain;
    },
    opt: () => chain
  };
  return { gun: chain, writes };
}

describe('DSNNode', () => {
  let node: DSNNode;
  const mockOptions: DSNNodeOptions = {
    nodeId: 'test-node-1',
    semanticDomain: 'cognitive',
    bootstrapUrl: 'https://test-bootstrap.com'
  };

  beforeEach(() => {
    jest.useFakeTimers();
    node = new DSNNode(mockOptions);
  });

  afterEach(() => {
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  describe('Constructor', () => {
    it('should initialize with correct configuration', () => {
      expect(node.config.nodeId).toBe(mockOptions.nodeId);
      expect(node.config.semanticDomain).toBe(mockOptions.semanticDomain);
      expect(node.config.bootstrapUrl).toBe(mockOptions.bootstrapUrl);
      expect(node.config.status).toBe('OFFLINE');
    });

    it('should generate a real Ed25519 key triplet', () => {
      expect(node.config.keyTriplet).toBeDefined();
      // Real Ed25519 public keys are 32 bytes, base64 encoded (~44 chars with padding)
      expect(node.config.keyTriplet.pub).toMatch(/^[A-Za-z0-9+/]+=*$/);
      expect(node.config.keyTriplet.pub.length).toBeGreaterThanOrEqual(43);
      // Verify resonance field is a 16-dimensional vector
      expect(node.config.keyTriplet.resonance).toHaveLength(16);
      // Verify fingerprint exists
      expect(node.config.keyTriplet.fingerprint).toBeDefined();
      expect(node.config.keyTriplet.fingerprint.length).toBe(16);
      // bodyPrimes is optional but should exist after generation
      expect(node.config.keyTriplet.bodyPrimes).toBeDefined();
      expect(node.config.keyTriplet.bodyPrimes!.length).toBeGreaterThan(0);
    });
  });

  describe('start', () => {
    it('should set status to ONLINE and update lastHeartbeat', async () => {
      const gunMock = {};
      await node.start(gunMock);
      expect(node.config.status).toBe('ONLINE');
      expect(node.config.lastHeartbeat).toBeGreaterThan(0);
    });

    it('should use provided gun instance', async () => {
      const gunMock = { opt: jest.fn() };
      await node.start(gunMock);
      // Accessing private gun property via casting if necessary or just ensuring no error
      expect(node.config.status).toBe('ONLINE');
    });

    it('should be a no-op when already started', async () => {
      await node.start({});
      const firstHeartbeat = node.config.lastHeartbeat;
      expect(jest.getTimerCount()).toBe(1);
      
      await node.start({});
      
      // No duplicate heartbeat interval
      expect(jest.getTimerCount()).toBe(1);
      expect(node.config.status).toBe('ONLINE');
      expect(node.config.lastHeartbeat).toBe(firstHeartbeat);
    });

    it('should never publish the private key to the mesh graph', async () => {
      const { gun, writes } = createGunMock();
      await node.start(gun);
      
      const meshRecord = writes.find(w => w.keyTriplet !== undefined);
      expect(meshRecord).toBeDefined();
      expect(meshRecord!.keyTriplet.priv).toBeUndefined();
      expect(meshRecord!.keyTriplet.pub).toBe(node.config.keyTriplet.pub);
      expect(meshRecord!.fingerprint).toBe(node.getFingerprint());
      
      // The private key must not appear anywhere in what was written to Gun
      expect(JSON.stringify(writes)).not.toContain(node.config.keyTriplet.priv);
    });
  });

  describe('getPublishableConfig', () => {
    it('should strip the private key from the config copy', () => {
      const publishable = node.getPublishableConfig();
      expect((publishable.keyTriplet as Record<string, unknown>).priv).toBeUndefined();
      expect(publishable.keyTriplet.pub).toBe(node.config.keyTriplet.pub);
      expect(JSON.stringify(publishable)).not.toContain(node.config.keyTriplet.priv);
    });
  });

  describe('identity persistence', () => {
    let dataDir: string;
    const keyFileName = 'keytriplet.json';

    beforeEach(() => {
      dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsn-node-keys-'));
    });

    afterEach(() => {
      fs.rmSync(dataDir, { recursive: true, force: true });
    });

    it('should persist a generated identity with owner-only permissions', () => {
      const persisted = new DSNNode({ ...mockOptions, persistKeysTo: dataDir });
      const keyFile = path.join(dataDir, keyFileName);
      
      expect(fs.existsSync(keyFile)).toBe(true);
      expect(fs.statSync(keyFile).mode & 0o777).toBe(0o600);
      
      const onDisk = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
      expect(onDisk.pub).toBe(persisted.config.keyTriplet.pub);
      expect(onDisk.priv).toBe(persisted.config.keyTriplet.priv);
      expect(onDisk.fingerprint).toBe(persisted.getFingerprint());
    });

    it('should reload the persisted identity instead of generating a new one', () => {
      const first = new DSNNode({ ...mockOptions, persistKeysTo: dataDir });
      const second = new DSNNode({ ...mockOptions, persistKeysTo: dataDir });
      
      expect(second.getFingerprint()).toBe(first.getFingerprint());
      expect(second.config.keyTriplet.pub).toBe(first.config.keyTriplet.pub);
      expect(second.config.keyTriplet.priv).toBe(first.config.keyTriplet.priv);
      expect(second.getResonance()).toEqual(first.getResonance());
    });

    it('should accept an explicit json file path', () => {
      const keyFile = path.join(dataDir, 'nested', 'identity.json');
      const first = new DSNNode({ ...mockOptions, persistKeysTo: keyFile });
      
      expect(fs.existsSync(keyFile)).toBe(true);
      expect(new DSNNode({ ...mockOptions, persistKeysTo: keyFile }).getFingerprint())
        .toBe(first.getFingerprint());
    });

    it('should prefer a caller-provided key triplet and not persist it', () => {
      const provided = generateKeyTriplet();
      const withKeys = new DSNNode({
        ...mockOptions,
        keyTriplet: provided,
        persistKeysTo: dataDir
      });
      
      expect(withKeys.getFingerprint()).toBe(provided.fingerprint);
      expect(fs.existsSync(path.join(dataDir, keyFileName))).toBe(false);
    });

    it('should generate a fresh identity when no persistence is configured', () => {
      const a = new DSNNode(mockOptions);
      const b = new DSNNode(mockOptions);
      expect(a.getFingerprint()).not.toBe(b.getFingerprint());
    });

    it('should throw a typed error when the persisted identity is malformed', () => {
      const keyFile = path.join(dataDir, keyFileName);
      fs.writeFileSync(keyFile, '{"pub":"only-a-pub"}', 'utf8');

      expect(() => new DSNNode({ ...mockOptions, persistKeysTo: dataDir }))
        .toThrow(DSNNodeIdentityError);

      // The corrupt file is left untouched (no silent overwrite)
      expect(fs.readFileSync(keyFile, 'utf8')).toBe('{"pub":"only-a-pub"}');
    });

    it('should throw a typed error when the persisted identity is unreadable json', () => {
      const keyFile = path.join(dataDir, keyFileName);
      fs.writeFileSync(keyFile, 'not-json{{', 'utf8');

      expect(() => new DSNNode({ ...mockOptions, persistKeysTo: dataDir }))
        .toThrow(DSNNodeIdentityError);
    });

    it('should regenerate and overwrite a corrupt identity only when recoverCorruptIdentity is set', () => {
      const keyFile = path.join(dataDir, keyFileName);
      fs.writeFileSync(keyFile, 'not-json{{', 'utf8');

      const recovered = new DSNNode({
        ...mockOptions,
        persistKeysTo: dataDir,
        recoverCorruptIdentity: true
      });

      expect(recovered.getResonance()).toHaveLength(16);
      const onDisk = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
      expect(onDisk.pub).toBe(recovered.config.keyTriplet.pub);
    });

    it('should make start() fail when persistence failed and failOnPersistError is set', async () => {
      // A file blocking the data directory makes the persist write fail.
      const blocker = path.join(dataDir, 'not-a-directory');
      fs.writeFileSync(blocker, 'file in the way', 'utf8');

      const node = new DSNNode({
        ...mockOptions,
        persistKeysTo: path.join(blocker, keyFileName),
        failOnPersistError: true
      });

      await expect(node.start({})).rejects.toThrow(DSNNodeIdentityError);
    });

    it('should start anyway when persistence fails but failOnPersistError is not set', async () => {
      const blocker = path.join(dataDir, 'not-a-directory');
      fs.writeFileSync(blocker, 'file in the way', 'utf8');

      const node = new DSNNode({
        ...mockOptions,
        persistKeysTo: path.join(blocker, keyFileName)
      });

      await expect(node.start({})).resolves.not.toThrow();
      expect(node.config.status).toBe('ONLINE');
    });
  });

  describe('joinMesh', () => {
    it('should throw error if node is not started', async () => {
      await expect(node.joinMesh()).rejects.toThrow("Node must be started before joining mesh");
    });

    it('should return peers when started', async () => {
      await node.start({});
      const result = await node.joinMesh();
      expect(result.peers.length).toBeGreaterThan(0);
      expect(node.config.gunPeers).toEqual(result.peers);
    });

    it('should include gatewayUrl if provided', async () => {
      await node.start({});
      const gateway = 'https://custom-gateway.com';
      const result = await node.joinMesh({ gatewayUrl: gateway });
      expect(result.peers).toContain(gateway + '/gun');
    });
  });

  describe('heartbeat', () => {
    it('should update lastHeartbeat periodically', async () => {
      await node.start({});
      const initialHeartbeat = node.config.lastHeartbeat;
      
      // Advance time by 30 seconds + 1ms
      jest.advanceTimersByTime(30001);
      
      expect(node.config.lastHeartbeat).toBeGreaterThan(initialHeartbeat);
    });

    it('should not heartbeat if offline', async () => {
       // Access private method or just check logic if we could simulate offline while timer runs
       // But stop() clears status to OFFLINE.
       await node.start({});
       await node.stop();
       const stoppedHeartbeat = node.config.lastHeartbeat;
       
       jest.advanceTimersByTime(30001);
       expect(node.config.lastHeartbeat).toBe(stoppedHeartbeat);
    });
  });

  describe('stop', () => {
    it('should set status to OFFLINE', async () => {
      await node.start({});
      await node.stop();
      expect(node.config.status).toBe('OFFLINE');
    });
  });
});
