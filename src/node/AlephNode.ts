/**
 * AlephNode — Composition Root
 *
 * Turns the independently built domain layers into a runnable node:
 *
 *   identity  → src/social/Identity (encrypted at rest; ephemeral + warned
 *               when no password is configured — never plaintext)
 *   storage   → FileSocialStore (dataDir) or MemorySocialStore
 *   semantic  → SemanticObserver (async-initialized tinyaleph kernel)
 *   economy   → AlephWallet / StakingService / Faucet — ONLY with a Gun
 *               ledger, because the wallet moves real funds through Gun
 *   coherence → ClaimRegistry (always) + VerificationMarket (needs a ledger)
 *   HTTP      → AlephServer from src/app, with one ActionModule per domain
 *
 * Degradation is explicit. A missing Gun, faucet secret or tinyaleph load
 * failure DISABLES the affected subsystem with a recorded reason, and its
 * actions answer with a typed `SUBSYSTEM_UNAVAILABLE` failure. Nothing is
 * ever silently faked — that was the defining sin of the deleted legacy
 * code.
 */

import * as path from 'path';
import { randomBytes, reconstructKeyTriplet } from '../common/crypto';
import { createLogger, type Logger } from '../common/logging';
import type { Result } from '../common/patterns/Result';
import { LOCK_PERIOD_MS, type LockPeriod } from '../common/types';
import {
  DEV_BYPASS_ACKNOWLEDGEMENT,
  ActionRegistry,
  AlephServer,
  createDevAuthBypass,
  type ActionError,
  type ActionInvocation,
  type AuthenticatedIdentity,
  type DevAuthBypass,
  type TierResolver
} from '../app';
import {
  ActionVerifier,
  ContentStore,
  FeedManager,
  FileSocialStore,
  FriendGraph,
  Groups,
  Identity,
  IdentityError,
  MemorySocialStore,
  Profiles,
  type SocialStore
} from '../social';
import { initializeSemanticKernel, SemanticObserver } from '../semantic';
import { AlephWallet } from '../infra/Wallet';
import { Faucet, StakingService, type StakingReconcileRecord } from '../economy';
import { ClaimRegistry, VerificationMarket } from '../coherence';
import { NodeAttestedSigner } from './attestation';
import { LruMap } from './lru';
import { createActionModules } from './actions';
import {
  createWalletTierResolver,
  StakingTierResolver,
  walletForAddress as makeAddressWallet
} from './TierResolver';
import {
  AlephNodeConfig,
  AlephNodeStartupError,
  AlephNodeStatus,
  CoherenceSubsystem,
  EconomySubsystem,
  NodeSubsystems,
  SemanticSubsystem,
  SocialSubsystem,
  SubsystemName,
  SubsystemStatus
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// CONFIG RESOLUTION
// ═══════════════════════════════════════════════════════════════════════════

/** Hard caps on per-identity caches (unbounded maps are memory-exhaustion bugs). */
const MAX_CALLER_WALLETS = 500;
const MAX_STAKING_SERVICES = 500;

/** How long to wait for the ledger stakes subtree when reconciling a cold cache. */
const STAKES_READ_TIMEOUT_MS = 2_000;

interface ResolvedConfig {
  readonly port: number;
  readonly host: string;
  readonly dataDir?: string;
  readonly staticPath?: string;
  readonly corsOrigins: readonly string[];
  readonly gun: unknown;
  readonly faucetSecret?: Buffer | string;
  readonly treasuryCap?: bigint;
  readonly identityPassword?: string;
  readonly semanticDegradedOk: boolean;
  readonly devAuthBypass: boolean;
  readonly installSignalHandlers: boolean;
}

function resolveConfig(config: AlephNodeConfig): ResolvedConfig {
  if (config.port !== undefined && (!Number.isInteger(config.port) || config.port < 0 || config.port > 65_535)) {
    throw new AlephNodeStartupError('INVALID_CONFIG', `Invalid port: ${String(config.port)}`);
  }
  const corsOrigins = config.corsOrigins ?? [];
  // The documented contract is an EXACT-MATCH Origin allowlist; `'*'` would
  // silently widen CORS to every origin, so it is rejected at startup rather
  // than honoured.
  if (corsOrigins.includes('*')) {
    throw new AlephNodeStartupError(
      'INVALID_CONFIG',
      `corsOrigins may not contain '*': the CORS contract is an exact-match ` +
        `allowlist (never '*'). List each origin explicitly.`
    );
  }
  return {
    port: config.port ?? 0,
    host: config.host ?? '127.0.0.1',
    dataDir: config.dataDir,
    staticPath: config.staticPath,
    corsOrigins,
    gun: config.gun,
    faucetSecret: config.faucetSecret,
    treasuryCap: config.treasuryCap,
    identityPassword: config.identityPassword,
    semanticDegradedOk: config.semantic?.degradedOk ?? true,
    devAuthBypass: config.devAuthBypass ?? false,
    installSignalHandlers: config.installSignalHandlers ?? false
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// NODE
// ═══════════════════════════════════════════════════════════════════════════

export class AlephNode {
  readonly logger: Logger;
  readonly config: ResolvedConfig;

  private identity!: Identity;
  private identityPersistent = false;
  private subsystems!: NodeSubsystems;
  private actionRegistry!: ActionRegistry;
  private server!: AlephServer;

  private startedAt: number | null = null;
  private stopped = false;
  private disposed = false;
  private readonly callerWallets = new LruMap<string, AlephWallet>(MAX_CALLER_WALLETS);

  private constructor(config: AlephNodeConfig) {
    this.config = resolveConfig(config);
    this.logger = config.logger ?? createLogger('node');
  }

  /**
   * Async factory: loads/creates the identity, initializes the semantic
   * kernel and wires every subsystem.
   */
  static async create(config: AlephNodeConfig = {}): Promise<AlephNode> {
    const node = new AlephNode(config);
    await node.initialize();
    return node;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // ACCESSORS
  // ─────────────────────────────────────────────────────────────────────────

  get nodeId(): string {
    return this.identity.nodeId;
  }

  get fingerprint(): string {
    return this.identity.fingerprint;
  }

  getIdentity(): Identity {
    return this.identity;
  }

  getSubsystems(): NodeSubsystems {
    return this.subsystems;
  }

  getActionRegistry(): ActionRegistry {
    return this.actionRegistry;
  }

  getServer(): AlephServer {
    return this.server;
  }

  get running(): boolean {
    return this.startedAt !== null;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // LIFECYCLE
  // ─────────────────────────────────────────────────────────────────────────

  /** Bind the HTTP server and start serving. */
  async start(): Promise<void> {
    if (this.stopped) {
      throw new AlephNodeStartupError(
        'NODE_STOPPED',
        'This AlephNode instance was stopped and cannot be restarted'
      );
    }
    if (this.startedAt !== null) {
      throw new AlephNodeStartupError('NODE_RUNNING', 'AlephNode is already started');
    }
    await this.server.start();
    this.startedAt = Date.now();
    this.logger.info('AlephNode started', {
      nodeId: this.identity.nodeId,
      fingerprint: this.identity.fingerprint,
      host: this.config.host,
      port: this.server.port,
      actions: this.actionRegistry.size
    });
  }

  /**
   * Graceful, idempotent shutdown: closes the HTTP server (peers, SSE
   * clients, auth timers, sockets), then disposes the observer's event
   * streams.
   */
  async stop(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    const wasStarted = this.startedAt !== null;
    this.startedAt = null;

    if (wasStarted) {
      await this.server.stop();
    }
    this.disposeObserver();

    if (wasStarted) {
      this.logger.info('AlephNode stopped', { fingerprint: this.identity.fingerprint });
    }
  }

  private disposeObserver(): void {
    if (this.disposed) return;
    this.disposed = true;
    try {
      this.subsystems.semantic.observer?.dispose();
    } catch (error) {
      this.logger.debug('Observer disposal failed', { message: String(error) });
    }
  }

  /**
   * Invoke an action directly against the registry (used by tests and by
   * internal callers; HTTP clients POST to /actions/:name instead).
   */
  async invokeAction(
    name: string,
    input: unknown,
    options: { identity?: AuthenticatedIdentity | null } = {}
  ): Promise<Result<ActionInvocation, ActionError>> {
    return this.actionRegistry.invoke(name, input, {
      identity: options.identity ?? null,
      requestId: `direct_${randomBytes(6).toString('hex')}`,
      logger: this.logger.child({ component: 'node:invoke' }),
      receivedAt: Date.now()
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // STATUS
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Node id/fingerprint, uptime, semantic kernel state (including whether it
   * is degraded), per-subsystem enabled/disabled state and counts.
   */
  getStatus(): AlephNodeStatus {
    const semantic = this.subsystems.semantic;
    const observer = semantic.observer;
    let kernel: { loaded: boolean; degraded: boolean } | null = null;
    let degraded = !semantic.enabled;
    if (observer !== null) {
      try {
        const state = observer.getState();
        kernel = { loaded: state.kernel.loaded, degraded: state.kernel.degraded };
        degraded = degraded || state.kernel.degraded;
      } catch {
        kernel = null;
        degraded = true;
      }
    }

    const registryStats = this.subsystems.coherence.registry.stats();

    return {
      nodeId: this.identity.nodeId,
      fingerprint: this.identity.fingerprint,
      identityPersistent: this.identityPersistent,
      identityCanSign: this.identity.canSign(),
      startedAt: this.startedAt,
      uptimeMs: this.startedAt === null ? 0 : Date.now() - this.startedAt,
      listening: this.server.listening,
      port: this.server.listening ? this.server.port : null,
      semantic: { enabled: semantic.enabled, degraded, kernel },
      subsystems: this.statusSubsystems(),
      counts: {
        actions: this.actionRegistry.size,
        memoryTraces: observer === null ? null : this.memoryTraceCount(observer),
        claims: registryStats.claims,
        claimEdges: registryStats.edges
      }
    };
  }

  private memoryTraceCount(observer: SemanticObserver): number | null {
    try {
      return observer.getMemoryBank().size;
    } catch {
      // A failed read is "unknown", never a fabricated 0.
      return null;
    }
  }

  private statusSubsystems(): Record<SubsystemName, SubsystemStatus> {
    const semantic = this.subsystems.semantic;
    const economy = this.subsystems.economy;
    const coherence = this.subsystems.coherence;
    const faucetEnabled = economy.enabled && economy.faucet !== null;
    return {
      semantic: { name: 'semantic', enabled: semantic.enabled, reason: semantic.reason },
      social: { name: 'social', enabled: true, reason: null },
      content: { name: 'content', enabled: true, reason: null },
      economy: { name: 'economy', enabled: economy.enabled, reason: economy.reason },
      faucet: {
        name: 'faucet',
        enabled: faucetEnabled,
        reason: faucetEnabled ? null : economy.faucetReason
      },
      coherence: {
        name: 'coherence',
        enabled: true,
        reason: null,
        detail: {
          marketAvailable: coherence.market !== null,
          marketReason: coherence.marketReason
        }
      }
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // INITIALIZATION
  // ─────────────────────────────────────────────────────────────────────────

  private async initialize(): Promise<void> {
    this.identity = await this.loadOrCreateIdentity();
    const store = await this.createStore();
    const verifier = new ActionVerifier();
    const bindVerifier = new ActionVerifier();
    const semantic = await this.initSemantic();
    const economy = this.initEconomy();
    const tierResolver: TierResolver = economy.enabled
      ? createWalletTierResolver(this.config.gun)
      : new StakingTierResolver({ readStaked: async () => null });
    const coherence = this.initCoherence(economy);
    const social = this.initSocial(store, verifier, bindVerifier, tierResolver);
    this.subsystems = { semantic, social, economy, coherence };

    if (this.identity.canSign()) {
      try {
        const created = await social.groups.ensureDefaultGroups(this.identity);
        if (created.length > 0) {
          this.logger.info('Created default groups', { count: created.length });
        }
      } catch (error) {
        this.logger.warn('Default group creation failed', {
          message: error instanceof Error ? error.message : String(error)
        });
      }
    }

    this.actionRegistry = new ActionRegistry({
      logger: this.logger.child({ component: 'node:actions' }),
      tierResolver
    });
    for (const module of createActionModules(this.subsystems)) {
      this.actionRegistry.registerModule(module);
    }

    this.server = this.createServer();
    this.server.routes.get(
      '/node/status',
      (_ctx, res) => {
        res.json(this.getStatus());
      },
      { auth: 'public', description: 'Node subsystem status' }
    );

    this.logger.info('AlephNode composition complete', {
      nodeId: this.identity.nodeId,
      fingerprint: this.identity.fingerprint,
      actions: this.actionRegistry.size
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // SUBSYSTEM WIRING
  // ─────────────────────────────────────────────────────────────────────────

  private async loadOrCreateIdentity(): Promise<Identity> {
    const password = this.config.identityPassword;
    if (this.config.dataDir === undefined || typeof password !== 'string' || password.length === 0) {
      const identity = Identity.create({ displayName: 'Ephemeral AlephNet Node' });
      this.logger.warn(
        'No identity password configured: using an EPHEMERAL node identity. ' +
          'The private key is NOT written to disk, so the node cannot be restarted ' +
          'under the same identity. Set ALEPH_IDENTITY_PASSWORD with --data to persist one.'
      );
      return identity;
    }

    const identityFile = path.join(this.config.dataDir, 'identity', 'node.json');
    try {
      const identity = await Identity.load(identityFile, password);
      this.identityPersistent = true;
      this.logger.info('Loaded node identity', { fingerprint: identity.fingerprint });
      return identity;
    } catch (error) {
      if (error instanceof IdentityError && error.code === 'weak_password') {
        // A too-short password is a CONFIGURATION error, not a failed unlock.
        throw new AlephNodeStartupError(
          'IDENTITY_PASSWORD_TOO_WEAK',
          `The identity password is too weak (${error.message})`
        );
      }
      if (error instanceof IdentityError && error.code === 'not_found') {
        const identity = Identity.create({ displayName: 'AlephNet Node' });
        try {
          await identity.save(identityFile, password);
        } catch (saveError) {
          if (saveError instanceof IdentityError && saveError.code === 'weak_password') {
            throw new AlephNodeStartupError(
              'IDENTITY_PASSWORD_TOO_WEAK',
              `The identity password is too weak (${saveError.message})`
            );
          }
          throw new AlephNodeStartupError(
            'IDENTITY_SAVE_FAILED',
            `Cannot persist the new node identity: ${saveError instanceof Error ? saveError.message : String(saveError)}`
          );
        }
        this.identityPersistent = true;
        this.logger.info('Created and saved a new node identity', {
          fingerprint: identity.fingerprint,
          identityFile
        });
        return identity;
      }
      if (error instanceof IdentityError) {
        throw new AlephNodeStartupError(
          'IDENTITY_UNLOCK_FAILED',
          `Cannot unlock the node identity (${error.code}): ${error.message}`
        );
      }
      throw new AlephNodeStartupError(
        'IDENTITY_LOAD_FAILED',
        `Cannot load the node identity: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  private async createStore(): Promise<SocialStore> {
    if (this.config.dataDir === undefined) {
      return new MemorySocialStore();
    }
    try {
      return await FileSocialStore.create({ basePath: path.join(this.config.dataDir, 'social') });
    } catch (error) {
      // A store the node cannot open is a startup failure with a stable code,
      // not a raw ENOENT/EACCES escaping into the caller.
      throw new AlephNodeStartupError(
        'STORE_INIT_FAILED',
        `Cannot initialize the social store: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Initialize the shared tinyaleph kernel and the observer. A load failure
   * either fails startup (degradedOk=false) or disables the subsystem with a
   * recorded reason (default).
   */
  private async initSemantic(): Promise<SemanticSubsystem> {
    try {
      const kernel = await initializeSemanticKernel();
      const observer = new SemanticObserver();
      await observer.initialize();
      this.logger.info('Semantic kernel loaded', {
        loaded: kernel.isInitialized(),
        degraded: kernel.isDegraded
      });
      return { enabled: true, reason: null, observer };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!this.config.semanticDegradedOk) {
        throw new AlephNodeStartupError(
          'SEMANTIC_KERNEL_UNAVAILABLE',
          `Semantic kernel failed to initialize: ${message}`
        );
      }
      const reason = `tinyaleph kernel failed to load: ${message}`;
      this.logger.warn('Semantic subsystem degraded: disabled with a recorded reason', { reason });
      return { enabled: false, reason, observer: null };
    }
  }

  /**
   * Wire the economy. `AlephWallet` moves real funds through a Gun ledger,
   * so without a STRUCTURALLY VALID Gun instance the whole subsystem is
   * DISABLED — there is no in-memory ledger stand-in, because a stand-in
   * would fake balances. A broken Gun (an object missing `get`) is reported
   * as invalid, and the status can never claim "enabled" for it.
   */
  private initEconomy(): EconomySubsystem {
    const gun = this.config.gun;
    const enabled = isStructurallyValidGun(gun);
    const reason = enabled
      ? null
      : gun === null || gun === undefined
        ? 'no Gun ledger supplied (AlephWallet requires one)'
        : 'invalid Gun ledger supplied (missing get/put/once)';

    const stakingServices = new LruMap<string, StakingService>(MAX_STAKING_SERVICES);

    const walletFor = (identity: AuthenticatedIdentity): AlephWallet | null => {
      if (!enabled) return null;
      // Dev-auth-bypass identities carry no public key; reconstructing a
      // triplet from '' would throw and surface as a 500. Fail closed with
      // null so the action layer answers a typed 'identity unavailable'.
      if (typeof identity.publicKey !== 'string' || identity.publicKey.length === 0) {
        return null;
      }
      const existing = this.callerWallets.get(identity.fingerprint);
      if (existing !== undefined) return existing;
      // Public-only triplet: the wallet derives its address from the
      // fingerprint and never signs anything.
      let triplet: ReturnType<typeof reconstructKeyTriplet>;
      try {
        triplet = reconstructKeyTriplet(identity.publicKey);
      } catch {
        return null;
      }
      const wallet = new AlephWallet({ ...triplet, priv: '' }, gun);
      this.callerWallets.set(identity.fingerprint, wallet);
      return wallet;
    };

    const walletForAddress = (address: string): AlephWallet | null => {
      if (!enabled) return null;
      return makeAddressWallet(gun, address);
    };

    const stakingFor = async (identity: AuthenticatedIdentity): Promise<StakingService | null> => {
      const wallet = walletFor(identity);
      if (wallet === null) return null;
      const existing = stakingServices.get(identity.fingerprint);
      if (existing !== undefined) return existing;
      const service = new StakingService(wallet);
      stakingServices.set(identity.fingerprint, service);
      // A freshly-created service has a COLD position cache (it may have been
      // evicted from the LRU, or the ledger holds positions staked before
      // this process started). Best-effort reconcile from the on-ledger
      // stakes subtree so the lock ratchet survives restarts; a failure
      // proceeds with a logged warning instead of failing the call.
      await this.reconcileColdStakes(service, wallet.address);
      return service;
    };

    // The node's own wallet is the treasury AND the coherence escrow.
    const nodeWallet = enabled
      ? new AlephWallet({ ...reconstructKeyTriplet(this.identity.publicKeyBase64), priv: '' }, gun)
      : null;

    let faucet: Faucet | null = null;
    let faucetReason: string | null = null;
    // The faucet needs BOTH a ledger wallet and a signing secret. Report every
    // missing prerequisite, not just the first one, so operators can fix the
    // configuration in a single pass.
    const normalizedSecret = this.normalizeFaucetSecret();
    const missingPrerequisites: string[] = [];
    if (!enabled || nodeWallet === null) {
      missingPrerequisites.push(reason ?? 'no ledger wallet');
    }
    if (normalizedSecret.reason !== null) {
      missingPrerequisites.push(normalizedSecret.reason);
    }

    if (missingPrerequisites.length > 0) {
      faucetReason = missingPrerequisites.join('; ');
    } else if (nodeWallet !== null && normalizedSecret.secret !== null) {
      try {
        faucet = new Faucet({
          secret: normalizedSecret.secret,
          treasury: nodeWallet,
          ...(this.config.treasuryCap === undefined ? {} : { treasuryCap: this.config.treasuryCap })
        });
      } catch (error) {
        faucetReason = error instanceof Error ? error.message : String(error);
      }
    }

    // The coherence market's wallet resolver shares the caller wallet
    // registry, so a stake claimed by an authenticated caller can really
    // move out of that caller's ledger account.
    return {
      enabled,
      reason,
      faucet,
      faucetReason,
      walletFor,
      walletForAddress,
      stakingFor
    };
  }

  /** Undefined/too-short secrets are treated as absent, each with its own reason. */
  private normalizeFaucetSecret(): { secret: Buffer | null; reason: string | null } {
    const raw = this.config.faucetSecret;
    if (raw === undefined) {
      return { secret: null, reason: 'no faucet secret configured (ALEPH_FAUCET_SECRET)' };
    }
    const secret = Buffer.isBuffer(raw) ? raw : Buffer.from(raw, 'utf8');
    if (secret.length < 32) {
      // Present-but-short is a different failure than absent: mislabeling it
      // as "not configured" sends operators hunting for a missing env var.
      return { secret: null, reason: 'faucet secret too short (minimum 32 bytes)' };
    }
    return { secret, reason: null };
  }

  /**
   * Rebuild a StakingService's position from the on-ledger stakes subtree.
   * Best-effort: on failure the service proceeds with a cold cache and the
   * failure is logged — a ledger outage must not break wallet actions.
   */
  private async reconcileColdStakes(service: StakingService, address: string): Promise<void> {
    try {
      const records = await readStakeRecords(this.config.gun, address, STAKES_READ_TIMEOUT_MS);
      const position = await service.reconcile(records);
      if (position !== null) {
        this.logger.debug('Reconciled staking position from the ledger', {
          address,
          records: records.length,
          staked: String(position.staked)
        });
      }
    } catch (error) {
      this.logger.warn('Staking position reconcile failed; proceeding with a cold cache', {
        address,
        message: error instanceof Error ? error.message : String(error)
      });
    }
  }

  private initCoherence(economy: EconomySubsystem): CoherenceSubsystem {
    const registry = new ClaimRegistry();
    const marketReason = economy.enabled ? null : economy.reason ?? 'no Gun ledger supplied';
    const escrow = economy.enabled ? economy.walletForAddress(this.identity.fingerprint) : null;
    if (escrow === null) {
      return { registry, market: null, marketReason };
    }
    // The escrow is the node's own wallet (the treasury).
    const market = new VerificationMarket(registry, escrow, {
      resolveWallet: (address: string) => this.callerWallets.get(address)
    });
    return { registry, market, marketReason: null };
  }

  private initSocial(
    store: SocialStore,
    verifier: ActionVerifier,
    bindVerifier: ActionVerifier,
    tierResolver: TierResolver
  ): SocialSubsystem {
    const friends = new FriendGraph({ store, verifier });
    const profiles = new Profiles({ store, verifier, friends });
    const groups = new Groups({
      store,
      verifier,
      tiers: { getTier: async (fingerprint: string) => tierResolver.resolveTier(fingerprint) }
    });
    // ContentStore and FeedManager mutations require SIGNED envelopes. The
    // node never holds client private keys, so it attests envelopes with its
    // own key: the attested verifier accepts them only for identities that
    // just passed HTTP request authentication.
    const attested = new NodeAttestedSigner(this.identity);
    const content = new ContentStore({ store, friends, verifier: attested.verifier });
    const feed = new FeedManager({ store, groups, verifier: attested.verifier });

    return {
      enabled: true,
      reason: null,
      store,
      verifier,
      bindVerifier,
      friends,
      profiles,
      groups,
      feed,
      content,
      signFor: <P>(identity: AuthenticatedIdentity, action: string, payload: P) =>
        attested.signFor(identity, action, payload)
    };
  }

  private createServer(): AlephServer {
    let unsafeDevAuthBypass: DevAuthBypass | undefined;
    if (this.config.devAuthBypass) {
      if (process.env.NODE_ENV === 'production') {
        throw new AlephNodeStartupError(
          'DEV_BYPASS_UNSAFE',
          'Refusing --dev-auth-bypass under NODE_ENV=production'
        );
      }
      unsafeDevAuthBypass = createDevAuthBypass(DEV_BYPASS_ACKNOWLEDGEMENT);
    }

    return new AlephServer({
      port: this.config.port,
      host: this.config.host,
      staticPath: this.config.staticPath,
      corsOrigins: this.config.corsOrigins,
      installSignalHandlers: this.config.installSignalHandlers,
      actions: this.actionRegistry,
      logger: this.logger.child({ component: 'node:http' }),
      ...(unsafeDevAuthBypass === undefined ? {} : { unsafeDevAuthBypass })
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// MODULE HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Structural validity of a Gun ledger. A broken ledger must NEVER be
 * reported as "enabled": the wallet would throw mid-request instead of
 * failing the subsystem up front. `get` is the minimum surface the wallet
 * needs to address the ledger at all.
 */
function isStructurallyValidGun(gun: unknown): boolean {
  return (
    typeof gun === 'object' &&
    gun !== null &&
    typeof (gun as { get?: unknown }).get === 'function'
  );
}

/** Minimal Gun chain surface used by {@link readStakeRecords}. */
interface GunChainLike {
  get(key: string): GunChainLike;
  once(callback: (data: unknown) => void): unknown;
}

/**
 * Read the ACTIVE stake records owned by `address` from the ledger stakes
 * subtree, with a hard timeout. Returns the records the StakingService can
 * rebuild a cold position from; rejects on timeout/malformed chains so the
 * caller can log and proceed.
 */
function readStakeRecords(
  gun: unknown,
  address: string,
  timeoutMs: number
): Promise<StakingReconcileRecord[]> {
  return new Promise<StakingReconcileRecord[]>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error(`timed out after ${timeoutMs}ms reading ledger stakes`));
    }, timeoutMs);
    timer.unref?.();

    try {
      const chain = (gun as GunChainLike).get('ledger').get('stakes');
      chain.once((data: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(collectStakeRecords(data, address));
      });
    } catch (error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error instanceof Error ? error : new Error(String(error)));
    }
  });
}

/** Filter the stakes-map snapshot down to well-formed ACTIVE records for `address`. */
function collectStakeRecords(data: unknown, address: string): StakingReconcileRecord[] {
  if (typeof data !== 'object' || data === null) return [];
  const records: StakingReconcileRecord[] = [];
  for (const [stakeId, raw] of Object.entries(data as Record<string, unknown>)) {
    if (typeof raw !== 'object' || raw === null) continue;
    const record = raw as Record<string, unknown>;
    if (record.status !== 'ACTIVE' || record.owner !== address) continue;
    if (typeof stakeId !== 'string' || stakeId.length === 0) continue;
    const lockPeriod = record.lockPeriod;
    if (typeof lockPeriod !== 'string' || !(lockPeriod in LOCK_PERIOD_MS)) continue;
    const lockedUntil = record.lockedUntil;
    if (typeof lockedUntil !== 'number' || !Number.isInteger(lockedUntil)) continue;
    let amount: bigint;
    try {
      amount = BigInt(String(record.amount));
    } catch {
      continue;
    }
    if (amount <= 0n) continue;
    records.push({
      stakeId,
      amount,
      lockPeriod: lockPeriod as LockPeriod,
      lockedUntil
    });
  }
  return records;
}
