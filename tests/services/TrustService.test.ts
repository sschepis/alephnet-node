import { describe, it, expect, beforeEach } from '@jest/globals';
import { SignedEnvelopeService } from '../../src/services/SignedEnvelopeService';
import { TrustEvaluator } from '../../src/services/TrustEvaluator';
import { TrustGate } from '../../src/services/TrustGate';
import { DomainManager, DomainLookupError } from '../../src/services/DomainManager';
import { ServiceManager, ServiceCallError } from '../../src/services/ServiceManager';
import { generateKeyTriplet, signToBase64, base64ToBuffer, KeyTriplet } from '../../src/common/crypto';
import type { SignedEnvelope, Endorsement, TrustAssessment } from '../../src/common/trust-types';
import type { DomainDefinition } from '../../src/common/types';
import type { AlephWallet } from '../../src/infra/Wallet';

// ─── Test Doubles ─────────────────────────────────────────────────────────

/**
 * Minimal in-memory Gun stand-in: a path -> value map with Gun's chaining,
 * `once`, `map().once()` and node-shaped reads for parent paths.
 */
class FakeGunNode {
  constructor(
    private store: Map<string, any>,
    private path: string = '',
    private onPut?: (path: string, value: any, store: Map<string, any>) => void
  ) {}

  get(key: string): FakeGunNode {
    return new FakeGunNode(this.store, this.path ? `${this.path}/${key}` : key, this.onPut);
  }

  put(value: any, cb?: (ack: any) => void): FakeGunNode {
    if (value === null || value === undefined) {
      this.store.delete(this.path);
      for (const key of Array.from(this.store.keys())) {
        if (key.startsWith(`${this.path}/`)) this.store.delete(key);
      }
    } else if (typeof value === 'object') {
      const existing = this.store.get(this.path);
      this.store.set(
        this.path,
        existing && typeof existing === 'object' ? { ...existing, ...value } : { ...value }
      );
    } else {
      this.store.set(this.path, value);
    }
    this.onPut?.(this.path, value, this.store);
    cb?.({ ok: 1 });
    return this;
  }

  once(cb: (data: any, key: string) => void): FakeGunNode {
    cb(this.read(), this.lastKey());
    return this;
  }

  map(): { once: (cb: (data: any, key: string) => void) => void } {
    const children = this.childKeys();
    return {
      once: (cb: (data: any, key: string) => void) => {
        for (const key of children) {
          cb(new FakeGunNode(this.store, `${this.path}/${key}`, this.onPut).read(), key);
        }
      },
    };
  }

  on(cb: (data: any, key: string) => void): FakeGunNode {
    cb(this.read(), this.lastKey());
    return this;
  }

  off(): FakeGunNode {
    return this;
  }

  private lastKey(): string {
    return this.path.split('/').pop() ?? '';
  }

  private read(): any {
    if (this.store.has(this.path)) return this.store.get(this.path);
    const children = this.childKeys();
    if (children.length === 0) return undefined;
    const node: any = {};
    for (const key of children) {
      node[key] = new FakeGunNode(this.store, `${this.path}/${key}`, this.onPut).read();
    }
    return node;
  }

  private childKeys(): string[] {
    const prefix = this.path ? `${this.path}/` : '';
    const keys = new Set<string>();
    for (const key of this.store.keys()) {
      if (!key.startsWith(prefix)) continue;
      const rest = key.slice(prefix.length);
      if (!rest) continue;
      keys.add(rest.split('/')[0]);
    }
    return Array.from(keys);
  }
}

function envelopeServiceFor(identity: KeyTriplet | null, seaVerifier?: any): SignedEnvelopeService {
  return new SignedEnvelopeService({ getIdentity: async () => identity }, seaVerifier);
}

/** An endorsement whose signature is over something other than the contentHash. */
function forgedEndorsement(endorser: KeyTriplet): Endorsement {
  return {
    endorser: {
      pub: endorser.pub,
      fingerprint: endorser.fingerprint,
      resonance: [...endorser.resonance],
    },
    signature: signToBase64('not-the-content-hash', base64ToBuffer(endorser.priv)),
    timestamp: Date.now(),
  };
}

function walletStub(overrides: Record<string, any> = {}): AlephWallet {
  return {
    address: 'caller-user',
    getBalance: async () => ({ stakingTier: 'Adept', available: 10n ** 24n, reserved: 0n }),
    authorizePayment: async () => ({ id: 'auth-1' }),
    finalizePayment: async () => ({ transactionId: 'tx-1' }),
    ...overrides,
  } as unknown as AlephWallet;
}

// ═══════════════════════════════════════════════════════════════════════════
// SignedEnvelopeService
// ═══════════════════════════════════════════════════════════════════════════

describe('SignedEnvelopeService.verify', () => {
  let author: KeyTriplet;
  let service: SignedEnvelopeService;
  let envelope: SignedEnvelope<{ text: string }>;

  beforeEach(async () => {
    author = generateKeyTriplet();
    service = envelopeServiceFor(author);
    envelope = await service.create({ text: 'hello' }, 'prompt', '1.0.0', ['fs:read']);
  });

  it('verifies a well-formed envelope', async () => {
    const result = await service.verify(envelope);

    expect(result.valid).toBe(true);
    expect(result.ed25519Valid).toBe(true);
    expect(result.resonanceValid).toBe(true);
    expect(result.seaVerification).toBe('absent');
    expect(result.endorsements).toEqual([]);
  });

  it('rejects a tampered payload', async () => {
    const result = await service.verify({ ...envelope, payload: { text: 'evil' } });

    expect(result.valid).toBe(false);
    expect(result.error).toContain('Content hash mismatch');
  });

  it('reports per-endorsement validity', async () => {
    const endorserA = generateKeyTriplet();
    const endorserB = generateKeyTriplet();

    const endorsed = await envelopeServiceFor(endorserA).endorse(envelope, 'looks good');
    const withForged: SignedEnvelope<{ text: string }> = {
      ...endorsed,
      endorsements: [...endorsed.endorsements, forgedEndorsement(endorserB)],
    };

    const result = await service.verify(withForged);

    expect(result.endorsements).toHaveLength(2);
    expect(result.endorsements[0]).toMatchObject({ endorserPub: endorserA.pub, valid: true });
    expect(result.endorsements[1]).toMatchObject({ endorserPub: endorserB.pub, valid: false });
    expect(result.warnings.join(' ')).toContain('endorsement');
    // An appendable field must not be able to invalidate someone else's artifact
    expect(result.valid).toBe(true);
  });

  it('never treats a SEA co-signature as verified when no SEA user is available', async () => {
    const result = await service.verify({ ...envelope, seaSignature: 'sea-sig' });

    expect(result.seaVerification).toBe('unavailable');
    expect(result.seaValid).toBe(false);
    expect(result.warnings.join(' ')).toContain('no SEA user available');
    expect(result.valid).toBe(true);
  });

  it('verifies a SEA co-signature when a SEA user is available', async () => {
    const good = envelopeServiceFor(author, { verify: async () => true });
    const bad = envelopeServiceFor(author, { verify: async () => false });

    const okResult = await good.verify({ ...envelope, seaSignature: 'sea-sig' });
    expect(okResult.seaVerification).toBe('valid');
    expect(okResult.seaValid).toBe(true);
    expect(okResult.valid).toBe(true);

    // An invalid co-signature is attacker-appendable: it must warn but NOT
    // invalidate someone else's artifact. Only the author signature gates validity.
    const badResult = await bad.verify({ ...envelope, seaSignature: 'sea-sig' });
    expect(badResult.seaVerification).toBe('invalid');
    expect(badResult.seaValid).toBe(false);
    expect(badResult.valid).toBe(true);
    expect(badResult.warnings.join(' ')).toContain('SEA co-signature failed verification');
  });

  it('marks SEA unavailable when the verifier throws', async () => {
    const flaky = envelopeServiceFor(author, {
      verify: async () => {
        throw new Error('no sea user');
      },
    });

    const result = await flaky.verify({ ...envelope, seaSignature: 'sea-sig' });
    expect(result.seaVerification).toBe('unavailable');
    expect(result.seaValid).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// TrustEvaluator
// ═══════════════════════════════════════════════════════════════════════════

describe('TrustEvaluator', () => {
  let trusted: KeyTriplet;
  let attacker: KeyTriplet;
  let envelopeService: SignedEnvelopeService;
  let evaluator: TrustEvaluator;
  let verifyCalls: number;
  let getFriendsCalls: number;

  beforeEach(() => {
    trusted = generateKeyTriplet();
    attacker = generateKeyTriplet();

    envelopeService = envelopeServiceFor(null);
    verifyCalls = 0;
    const originalVerify = envelopeService.verify.bind(envelopeService);
    (envelopeService as any).verify = async (env: any) => {
      verifyCalls++;
      return originalVerify(env);
    };

    getFriendsCalls = 0;
    const socialGraph = {
      getFriends: async () => {
        getFriendsCalls++;
        return [{ id: 'trusted', publicKey: trusted.pub }];
      },
      getFriendsOfFriend: async () => [],
    };

    const reputationProvider = {
      getReputation: async (pub: string) => (pub === trusted.pub ? 0.95 : 0.0),
      getStakingTier: async (pub: string) => (pub === trusted.pub ? 'Archon' : 'Neophyte') as any,
      getCoherenceScore: async () => 0.9,
    };

    evaluator = new TrustEvaluator(
      envelopeService,
      null,
      socialGraph,
      reputationProvider,
      { getCommonDomains: async () => [] }
    );
  });

  const sign = (identity: KeyTriplet, payload: any) =>
    envelopeServiceFor(identity).create(payload, 'prompt', '1.0.0', ['fs:read', 'wallet:transfer']);

  it('trusts a signed artifact from a friend', async () => {
    const assessment = await evaluator.evaluate(await sign(trusted, { text: 'hi' }));

    expect(assessment.factors.signatureValid).toBe(true);
    expect(assessment.level).toBe('VOUCHED');
  });

  it('verifies the signature BEFORE consulting the cache', async () => {
    const good = await sign(trusted, { text: 'hi' });
    const trustedAssessment = await evaluator.evaluate(good);
    expect(trustedAssessment.level).toBe('VOUCHED');

    // Attack: reuse the trusted contentHash, attach a malicious payload and a
    // garbage signature. The cached assessment must not be inherited.
    const forged = {
      ...good,
      payload: { text: 'rm -rf /' },
      signature: 'Z2FyYmFnZQ==',
      author: {
        pub: attacker.pub,
        fingerprint: attacker.fingerprint,
        resonance: [...attacker.resonance],
      },
    } as SignedEnvelope<{ text: string }>;

    const forgedAssessment = await evaluator.evaluate(forged);

    expect(forgedAssessment.level).toBe('REVOKED');
    expect(forgedAssessment.score).toBe(-1);
    expect(forgedAssessment.factors.signatureValid).toBe(false);
  });

  it('scopes the cache to the verified author so signers cannot share assessments', async () => {
    const payload = { text: 'identical content' };
    const trustedEnvelope = await sign(trusted, payload);
    const attackerEnvelope = await sign(attacker, payload);

    // Same content ⇒ same contentHash: the only thing separating them is the signer.
    expect(attackerEnvelope.contentHash).toBe(trustedEnvelope.contentHash);

    const trustedAssessment = await evaluator.evaluate(trustedEnvelope);
    const attackerAssessment = await evaluator.evaluate(attackerEnvelope);

    expect(trustedAssessment.level).toBe('VOUCHED');
    expect(attackerAssessment.level).not.toBe('VOUCHED');
    expect(attackerAssessment.score).toBeLessThan(trustedAssessment.score);
  });

  it('rejects an envelope whose fingerprint does not derive from its public key', async () => {
    const good = await sign(trusted, { text: 'hi' });
    const swapped = {
      ...good,
      author: { ...good.author, fingerprint: attacker.fingerprint },
    };

    const assessment = await evaluator.evaluate(swapped);

    expect(assessment.level).toBe('REVOKED');
    expect(assessment.factors.signatureValid).toBe(false);
  });

  it('re-verifies on every evaluation but reuses the cached score', async () => {
    const envelope = await sign(trusted, { text: 'hi' });

    await evaluator.evaluate(envelope);
    await evaluator.evaluate(envelope);

    expect(verifyCalls).toBe(2); // signature gate is never cached away
    expect(getFriendsCalls).toBe(1); // scoring is cached
  });

  it('ignores endorsements whose signatures do not verify', async () => {
    const envelope = await sign(trusted, { text: 'endorsed' });
    const forged: SignedEnvelope<any> = {
      ...envelope,
      endorsements: [
        forgedEndorsement(generateKeyTriplet()),
        forgedEndorsement(generateKeyTriplet()),
        forgedEndorsement(generateKeyTriplet()),
        forgedEndorsement(generateKeyTriplet()),
        forgedEndorsement(generateKeyTriplet()),
      ],
    };

    const assessment = await evaluator.evaluate(forged);

    expect(assessment.factors.endorsementQuality).toBe(0);
  });

  it('counts verified endorsements once per endorser', async () => {
    const envelope = await sign(trusted, { text: 'endorsed for real' });
    const endorserA = generateKeyTriplet();
    const endorserB = generateKeyTriplet();

    let endorsed = await envelopeServiceFor(endorserA).endorse(envelope);
    endorsed = await envelopeServiceFor(endorserB).endorse(endorsed);

    // Replay one endorsement plus an unverifiable one: neither may add weight.
    const padded: SignedEnvelope<any> = {
      ...endorsed,
      endorsements: [
        ...endorsed.endorsements,
        endorsed.endorsements[0],
        forgedEndorsement(generateKeyTriplet()),
      ],
    };

    const assessment = await evaluator.evaluate(padded);

    // sqrt dampening: contribution = sqrt(2 verified) * 0.3
    expect(assessment.factors.endorsementQuality).toBeCloseTo(Math.sqrt(2) * 0.3, 10);
  });

  it('caps the influence of minted-identity endorsement farms', async () => {
    const envelope = await sign(trusted, { text: 'farmed' });
    const farmed: SignedEnvelope<any> = { ...envelope, endorsements: [] };

    for (let i = 0; i < 5; i++) {
      const throwaway = generateKeyTriplet();
      farmed.endorsements.push({
        endorser: {
          pub: throwaway.pub,
          fingerprint: throwaway.fingerprint,
          resonance: [...throwaway.resonance],
        },
        signature: signToBase64(envelope.contentHash, base64ToBuffer(throwaway.priv)),
        timestamp: Date.now(),
      });
    }

    const assessment = await evaluator.evaluate(farmed);

    // 5 verified throwaway endorsements: dampened, well below the maximum.
    expect(assessment.factors.endorsementQuality).toBeLessThan(1.0);
    expect(assessment.factors.endorsementQuality).toBeCloseTo(Math.sqrt(5) * 0.3, 10);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// TrustGate
// ═══════════════════════════════════════════════════════════════════════════

describe('TrustGate.checkAll', () => {
  let author: KeyTriplet;
  let envelope: SignedEnvelope<{ text: string }>;

  beforeEach(async () => {
    author = generateKeyTriplet();
    envelope = await envelopeServiceFor(author).create({ text: 'plugin' }, 'plugin', '1.0.0', [
      'ui:notification',
      'wallet:transfer',
    ]);
  });

  it('derives the assessment from the envelope instead of accepting one', async () => {
    let evaluated = 0;
    const unknownAssessment: TrustAssessment = {
      score: 0.1,
      level: 'UNKNOWN',
      factors: {
        signatureValid: true,
        socialDistance: 0,
        authorReputation: 0,
        stakingTier: 0,
        endorsementQuality: 0,
        coherenceScore: 0,
      },
      evaluatedAt: Date.now(),
      ttlMs: 1000,
    };

    const gate = new TrustGate({
      evaluate: async () => {
        evaluated++;
        return unknownAssessment;
      },
    });

    const results = await gate.checkAll(envelope);

    expect(evaluated).toBe(1);
    expect(results.get('wallet:transfer')).toEqual({ decision: 'DENY', reason: undefined });
    expect(results.get('ui:notification')?.decision).toBe('CONFIRM');
  });

  it('denies everything when the envelope is not from the expected author', async () => {
    let evaluated = 0;
    const gate = new TrustGate({
      evaluate: async () => {
        evaluated++;
        throw new Error('should not be reached');
      },
    });

    const results = await gate.checkAll(envelope, generateKeyTriplet().fingerprint);

    expect(evaluated).toBe(0);
    expect([...results.values()].every(r => r.decision === 'DENY')).toBe(true);
  });

  it('denies every capability for an unverifiable envelope', async () => {
    const evaluator = new TrustEvaluator(
      envelopeServiceFor(null),
      null,
      { getFriends: async () => [], getFriendsOfFriend: async () => [] },
      {
        getReputation: async () => 1,
        getStakingTier: async () => 'Archon' as any,
        getCoherenceScore: async () => 1,
      },
      { getCommonDomains: async () => [] }
    );
    const gate = new TrustGate(evaluator);

    const forged = { ...envelope, payload: { text: 'evil' } };
    const results = await gate.checkAll(forged);

    expect([...results.values()].every(r => r.decision === 'DENY')).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// DomainManager
// ═══════════════════════════════════════════════════════════════════════════

describe('DomainManager', () => {
  let store: Map<string, any>;
  let gun: FakeGunNode;
  let owner: KeyTriplet;
  let ownerService: SignedEnvelopeService;

  const definitionFor = (overrides: Partial<DomainDefinition> = {}): DomainDefinition => ({
    id: 'domain-1',
    handle: 'alchemists',
    name: 'Alchemists',
    description: 'A guild',
    ownerId: owner.fingerprint,
    createdAt: Date.now(),
    visibility: 'public',
    rules: {
      minStakingTier: 'Neophyte',
      minReputation: 0,
      requiresApproval: false,
      grantedCapabilities: [],
    },
    metadata: {},
    ...overrides,
  });

  const managerWith = (wallet: AlephWallet) =>
    new DomainManager(null as any, wallet, gun as any);

  const registerEnvelope = (definition: DomainDefinition) =>
    ownerService.create(definition, 'domain-definition', '1.0.0', []);

  beforeEach(() => {
    store = new Map<string, any>();
    gun = new FakeGunNode(store);
    owner = generateKeyTriplet();
    ownerService = envelopeServiceFor(owner);
  });

  it('registers a verified domain envelope and unwraps it on read', async () => {
    const manager = managerWith(walletStub({ address: owner.fingerprint }));
    const definition = definitionFor();

    await manager.registerDomain(await registerEnvelope(definition));

    expect(await manager.getDomainIdByHandle('alchemists')).toEqual({
      status: 'found',
      domainId: 'domain-1',
    });
    const loaded = await manager.getDomain('domain-1');
    expect(loaded.status).toBe('found');
    if (loaded.status !== 'found') throw new Error('expected found');
    expect(loaded.definition.handle).toBe('alchemists');
    expect(loaded.definition.rules.minStakingTier).toBe('Neophyte');
    // The stored node is the envelope, not the bare definition
    expect(store.get('domains/domain-1').signature).toBeDefined();
  });

  it('reports a missing domain as absent and distinguishes it from a timeout', async () => {
    const manager = managerWith(walletStub({ address: owner.fingerprint }));

    expect(await manager.getDomain('nope')).toEqual({ status: 'absent' });
    expect(await manager.getDomainIdByHandle('unused')).toEqual({ status: 'absent' });
  });

  it('rejects an unsigned or tampered registration', async () => {
    const manager = managerWith(walletStub({ address: owner.fingerprint }));
    const definition = definitionFor();
    const envelope = await registerEnvelope(definition);

    await expect(
      manager.registerDomain({ ...envelope, signature: 'Z2FyYmFnZQ==' })
    ).rejects.toThrow(/Invalid domain registration envelope/);

    await expect(
      manager.registerDomain({
        ...envelope,
        payload: { ...definition, handle: 'hijacked' },
      })
    ).rejects.toThrow(/Invalid domain registration envelope/);

    await expect(
      manager.registerDomain({ ...envelope, signature: '' } as any)
    ).rejects.toThrow(/not signed/);

    await expect(
      manager.registerDomain({
        ...envelope,
        payload: { ...definition, ownerId: 'someone-else' },
      })
    ).rejects.toThrow(/Invalid domain registration envelope/);

    expect(store.size).toBe(0);
  });

  it('joins a domain stored as an envelope, honouring requiresApproval', async () => {
    const manager = managerWith(walletStub({ address: owner.fingerprint }));
    const definition = definitionFor({
      rules: {
        minStakingTier: 'Adept',
        minReputation: 0,
        requiresApproval: true,
        grantedCapabilities: [],
      },
    });

    await manager.registerDomain(await registerEnvelope(definition));

    // Before the fix this threw: `definition.rules` was undefined on the envelope.
    await expect(manager.joinDomain('domain-1')).resolves.toEqual({ status: 'pending' });
    const members = await manager.getMembers('domain-1');
    expect(members.map(m => m.status)).toContain('pending');
  });

  it('defaults missing rules instead of throwing', async () => {
    const manager = managerWith(walletStub({ address: owner.fingerprint }));
    store.set('domains/domain-2', { id: 'domain-2', handle: 'no-rules' });

    const loaded = await manager.getDomain('domain-2');
    expect(loaded.status).toBe('found');
    if (loaded.status !== 'found') throw new Error('expected found');
    expect(loaded.definition.rules).toEqual({
      minStakingTier: 'Neophyte',
      minReputation: 0,
      requiresApproval: false,
      whitelist: undefined,
      blacklist: undefined,
      grantedCapabilities: [],
    });
    await expect(manager.joinDomain('domain-2')).resolves.toEqual({ status: 'active' });
  });

  it('enforces the minimum staking tier', async () => {
    const manager = managerWith(
      walletStub({
        address: owner.fingerprint,
        getBalance: async () => ({ stakingTier: 'Neophyte' }),
      })
    );
    await manager.registerDomain(
      await registerEnvelope(
        definitionFor({
          rules: {
            minStakingTier: 'Magus',
            minReputation: 0,
            requiresApproval: false,
            grantedCapabilities: [],
          },
        })
      )
    );

    await expect(manager.joinDomain('domain-1')).rejects.toThrow(/Insufficient staking tier/);
  });

  it('lists stored domain definitions', async () => {
    const manager = managerWith(walletStub({ address: owner.fingerprint }));
    await manager.registerDomain(await registerEnvelope(definitionFor()));
    await manager.registerDomain(
      await registerEnvelope(definitionFor({ id: 'domain-2', handle: 'seers' }))
    );

    const domains = await manager.listDomains(2);

    expect(domains).toHaveLength(2);
    expect(domains.map(d => d.handle).sort()).toEqual(['alchemists', 'seers']);
  });

  it('enforces the whitelist: unlisted identities are denied', async () => {
    const manager = managerWith(walletStub({ address: 'caller-user' }));
    await manager.registerDomain(
      await registerEnvelope(
        definitionFor({
          rules: {
            minStakingTier: 'Neophyte',
            minReputation: 0,
            requiresApproval: false,
            grantedCapabilities: [],
            whitelist: ['someone-else'],
          },
        })
      )
    );

    await expect(manager.joinDomain('domain-1')).rejects.toThrow(/not whitelisted/);
  });

  it('enforces minReputation, denying when reputation is unknown (fail closed)', async () => {
    const manager = managerWith(walletStub({ address: owner.fingerprint }));
    await manager.registerDomain(
      await registerEnvelope(
        definitionFor({
          rules: {
            minStakingTier: 'Neophyte',
            minReputation: 0.8,
            requiresApproval: false,
            grantedCapabilities: [],
          },
        })
      )
    );

    // No reputation record: unknown reputation is a denial, not a pass.
    await expect(manager.joinDomain('domain-1')).rejects.toThrow(
      /Reputation could not be established/
    );

    // Below the minimum: denied.
    store.set(`reputation/${owner.fingerprint}`, { score: 0.2 });
    await expect(manager.joinDomain('domain-1')).rejects.toThrow(/Insufficient reputation/);

    // At/above the minimum: allowed.
    store.set(`reputation/${owner.fingerprint}`, { score: 0.9 });
    await expect(manager.joinDomain('domain-1')).resolves.toEqual({ status: 'active' });
  });

  it('treats a timed-out read as unknown, not as available or absent (TOCTOU)', async () => {
    // A Gun node whose once() never fires: the read times out.
    const hangingGun: any = { get: () => hangingGun, once: () => {} };
    const manager = new DomainManager(null as any, walletStub(), hangingGun);

    await expect(manager.joinDomain('domain-1')).rejects.toThrow(DomainLookupError);

    const registering = new DomainManager(
      null as any,
      walletStub({ address: owner.fingerprint }),
      hangingGun
    );
    await expect(
      registering.registerDomain(await registerEnvelope(definitionFor()))
    ).rejects.toThrow(DomainLookupError);
  }, 10000);
});

// ═══════════════════════════════════════════════════════════════════════════
// ServiceManager access control
// ═══════════════════════════════════════════════════════════════════════════

describe('ServiceManager.callService', () => {
  let store: Map<string, any>;
  let gun: FakeGunNode;
  let authorized: Array<{ to: string; amount: bigint }>;
  let finalized: Array<{ id: string; amount?: bigint }>;
  let wallet: AlephWallet;

  const baseDefinition = (access: any, pricing: any = { perCallCost: 1, acceptedPayments: ['ALEPH'] }) => ({
    id: 'svc-1',
    name: 'Oracle',
    providerNodeId: 'provider-node-stale',
    providerUserId: 'provider-user',
    status: 'ACTIVE',
    access,
    pricing,
    interface: {
      protocol: 'GUN_SYNC',
      endpoints: [{ name: 'ask', costMultiplier: 2, inputSchema: {}, outputSchema: {} }],
    },
  });

  const seedService = (definition: any) => {
    store.set('services/svc-1', { definition });
    store.set('services/svc-1/instances/executor-node', {
      serviceId: 'svc-1',
      nodeId: 'executor-node',
      status: 'RUNNING',
      health: { healthy: true },
    });
  };

  const rateLimit = {
    requestsPerMinute: 100,
    requestsPerHour: 100,
    requestsPerDay: 100,
    burstLimit: 100,
  };

  beforeEach(() => {
    store = new Map<string, any>();
    // Auto-answer any RPC written to a node inbox.
    gun = new FakeGunNode(store, '', (path, _value, s) => {
      const match = /^nodes\/(.+)\/inbox\/(.+)$/.exec(path);
      if (match) s.set(`requests/${match[2]}/response`, { result: { answeredBy: match[1] } });
    });

    authorized = [];
    finalized = [];
    wallet = walletStub({
      address: 'caller-user',
      authorizePayment: async (to: string, amount: bigint) => {
        authorized.push({ to, amount });
        return { id: 'auth-1' };
      },
      finalizePayment: async (id: string, amount?: bigint) => {
        finalized.push({ id, amount });
        return { transactionId: 'tx-1' };
      },
    });
  });

  const manager = (accessContext?: any) =>
    new ServiceManager(gun as any, wallet, 'local-node', accessContext);

  it('pays the node that actually executes the call', async () => {
    seedService(baseDefinition({ visibility: 'PUBLIC', rateLimit }));

    const call = await manager().callService<{ answeredBy: string }>('svc-1', 'ask', {});

    expect(call.executorNode).toBe('executor-node');
    expect(call.result.answeredBy).toBe('executor-node');
    expect(call.cost).toBe(2);
    // Payment follows the executor, not providerNodeId
    expect(authorized).toEqual([{ to: 'executor-node', amount: BigInt(2e18) }]);
    expect(finalized).toEqual([{ id: 'auth-1', amount: undefined }]);
  });

  it('denies PRIVATE services to other callers before any payment', async () => {
    seedService(baseDefinition({ visibility: 'PRIVATE', rateLimit }));

    await expect(manager().callService('svc-1', 'ask', {})).rejects.toMatchObject({
      code: 'VISIBILITY_DENIED',
    });
    expect(authorized).toEqual([]);
  });

  it('denies RESTRICTED services with no allow-list', async () => {
    seedService(baseDefinition({ visibility: 'RESTRICTED', rateLimit }));

    await expect(manager().callService('svc-1', 'ask', {})).rejects.toBeInstanceOf(ServiceCallError);
  });

  it('enforces allowedNodes', async () => {
    seedService(
      baseDefinition({ visibility: 'RESTRICTED', allowedNodes: ['some-other-node'], rateLimit })
    );

    await expect(manager().callService('svc-1', 'ask', {})).rejects.toMatchObject({
      code: 'NODE_NOT_ALLOWED',
    });
  });

  it('enforces allowedUsers and allowedTiers', async () => {
    seedService(
      baseDefinition({ visibility: 'RESTRICTED', allowedUsers: ['someone-else'], rateLimit })
    );
    await expect(manager().callService('svc-1', 'ask', {})).rejects.toMatchObject({
      code: 'USER_NOT_ALLOWED',
    });

    seedService(baseDefinition({ visibility: 'RESTRICTED', allowedTiers: ['Archon'], rateLimit }));
    await expect(manager().callService('svc-1', 'ask', {})).rejects.toMatchObject({
      code: 'TIER_NOT_ALLOWED',
    });
  });

  it('enforces minReputation and minCoherence, failing closed when unknown', async () => {
    seedService(baseDefinition({ visibility: 'PUBLIC', minReputation: 0.8, rateLimit }));

    await expect(
      manager({ getReputation: async () => 0.2, getCoherence: async () => 1 }).callService(
        'svc-1',
        'ask',
        {}
      )
    ).rejects.toMatchObject({ code: 'REPUTATION_TOO_LOW' });

    await expect(
      manager({ getReputation: async () => null, getCoherence: async () => 1 }).callService(
        'svc-1',
        'ask',
        {}
      )
    ).rejects.toMatchObject({ code: 'REPUTATION_UNVERIFIABLE' });

    seedService(baseDefinition({ visibility: 'PUBLIC', minCoherence: 0.9, rateLimit }));
    await expect(
      manager({ getReputation: async () => 1, getCoherence: async () => 0.3 }).callService(
        'svc-1',
        'ask',
        {}
      )
    ).rejects.toMatchObject({ code: 'COHERENCE_TOO_LOW' });

    expect(authorized).toEqual([]);
  });

  it('enforces the declared rate limit', async () => {
    seedService(
      baseDefinition({
        visibility: 'PUBLIC',
        rateLimit: { requestsPerMinute: 1, requestsPerHour: 10, requestsPerDay: 10, burstLimit: 5 },
      })
    );
    const svc = manager();

    await svc.callService('svc-1', 'ask', {});
    await expect(svc.callService('svc-1', 'ask', {})).rejects.toMatchObject({
      code: 'RATE_LIMIT_EXCEEDED',
    });
    expect(authorized).toHaveLength(1);
  });

  it('rejects suspended services and unknown endpoints', async () => {
    seedService({ ...baseDefinition({ visibility: 'PUBLIC', rateLimit }), status: 'SUSPENDED' });
    await expect(manager().callService('svc-1', 'ask', {})).rejects.toMatchObject({
      code: 'SERVICE_SUSPENDED',
    });

    seedService(baseDefinition({ visibility: 'PUBLIC', rateLimit }));
    await expect(manager().callService('svc-1', 'nope', {})).rejects.toMatchObject({
      code: 'ENDPOINT_NOT_FOUND',
    });
  });

  it('skips payment entirely for free calls', async () => {
    seedService(
      baseDefinition({ visibility: 'PUBLIC', rateLimit }, { model: 'FREE', perCallCost: 0 })
    );

    const call = await manager().callService('svc-1', 'ask', {});

    expect(call.cost).toBe(0);
    expect(authorized).toEqual([]);
    expect(finalized).toEqual([]);
  });

  it('denies calls when the definition declares no access policy', async () => {
    seedService(baseDefinition(undefined, { perCallCost: 1 }));

    await expect(manager().callService('svc-1', 'ask', {})).rejects.toMatchObject({
      code: 'ACCESS_UNDECLARED',
    });
    expect(authorized).toEqual([]);
  });

  it('denies calls when the access block declares no visibility', async () => {
    seedService(baseDefinition({ rateLimit }, { perCallCost: 1 }));

    await expect(manager().callService('svc-1', 'ask', {})).rejects.toMatchObject({
      code: 'ACCESS_UNDECLARED',
    });
    expect(authorized).toEqual([]);
  });

  it('rejects a service with no explicit pricing (free must be perCallCost: 0)', async () => {
    seedService(baseDefinition({ visibility: 'PUBLIC', rateLimit }, null));

    await expect(manager().callService('svc-1', 'ask', {})).rejects.toMatchObject({
      code: 'PRICING_UNDECLARED',
    });
    expect(authorized).toEqual([]);
  });

  it('rejects a service whose perCallCost is not an explicit non-negative number', async () => {
    seedService(
      baseDefinition({ visibility: 'PUBLIC', rateLimit }, { perCallCost: Number.NaN })
    );

    await expect(manager().callService('svc-1', 'ask', {})).rejects.toMatchObject({
      code: 'PRICING_UNDECLARED',
    });
    expect(authorized).toEqual([]);
  });
});
