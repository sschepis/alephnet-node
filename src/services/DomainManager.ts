import { AlephGunBridge } from '../core/AlephGunBridge';
import { AlephWallet } from '../infra/Wallet';
import { 
  DomainDefinition, 
  DomainRules, 
  DomainMembership, 
  DomainVisibility, 
  DomainRole, 
  MembershipStatus,
  StakingTier
} from '../common/types';
import { SignedEnvelope } from '../common/trust-types';
import { SignedEnvelopeService } from './SignedEnvelopeService';
import * as crypto from 'crypto';

const TIER_ORDER: StakingTier[] = ['Neophyte', 'Adept', 'Magus', 'Archon'];

/** How long to wait for a Gun read before treating the node as empty. */
const GUN_READ_TIMEOUT_MS = 500;

/** Rules applied when a stored domain has no (or a partial) rules object. */
const DEFAULT_DOMAIN_RULES: DomainRules = {
  minStakingTier: 'Neophyte',
  minReputation: 0,
  requiresApproval: false,
  grantedCapabilities: [],
};

/**
 * Outcome of a timed Gun read. A timed-out (or errored) read is reported as
 * `available: false` — it is NOT the same as "the node does not exist", and
 * code paths that gate decisions on availability must treat it as unknown.
 */
export interface GunReadResult {
  available: boolean;
  data: any;
}

/** Typed outcome of a domain lookup: absence and unavailability are distinct. */
export type DomainLookupResult =
  | { status: 'found'; definition: DomainDefinition }
  | { status: 'absent' }
  | { status: 'unknown' };

/** Typed outcome of a handle lookup: absence and unavailability are distinct. */
export type HandleLookupResult =
  | { status: 'found'; domainId: string }
  | { status: 'absent' }
  | { status: 'unknown' };

/**
 * Thrown when a domain/handle read timed out and the answer is therefore
 * unknown. Callers must fail closed: an unknown read is neither "available"
 * nor "not found".
 */
export class DomainLookupError extends Error {
  public readonly code = 'DOMAIN_LOOKUP_UNKNOWN';

  constructor(message: string) {
    super(message);
    this.name = 'DomainLookupError';
  }
}

/** Case/whitespace-insensitive identity comparison (fingerprints/addresses). */
function sameId(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

export class DomainManager {
  private readonly envelopeService: SignedEnvelopeService;

  constructor(
    private bridge: AlephGunBridge,
    private wallet: AlephWallet,
    private gun: any,
    envelopeService?: SignedEnvelopeService
  ) {
    // verify() never touches private key material, so a null-identity provider
    // is enough for a verification-only envelope service.
    this.envelopeService =
      envelopeService ?? new SignedEnvelopeService({ getIdentity: async () => null });
  }

  /**
   * Register a new domain using a signed envelope.
   * The envelope must contain a valid DomainDefinition and be signed by the owner.
   */
  async registerDomain(envelope: SignedEnvelope<DomainDefinition>): Promise<void> {
    // ── Structural checks ────────────────────────────────────────────
    if (!envelope || typeof envelope !== 'object') {
      throw new Error('Domain registration requires a signed envelope');
    }
    if (!envelope.signature || !envelope.author?.pub || !envelope.resonanceProof) {
      throw new Error('Domain registration envelope is not signed');
    }
    if (envelope.artifactType !== 'domain-definition') {
      throw new Error(
        `Domain registration requires a 'domain-definition' envelope, got '${envelope.artifactType}'`
      );
    }

    const definition = envelope.payload;
    if (!definition || typeof definition !== 'object' || !definition.id || !definition.handle) {
      throw new Error('Domain definition must include an id and a handle');
    }

    // ── Cryptographic verification (never assume the caller did it) ───
    const verification = await this.envelopeService.verify(envelope);
    if (!verification.valid) {
      throw new Error(
        `Invalid domain registration envelope: ${verification.error ?? 'signature verification failed'}`
      );
    }

    // The signer is the only identity allowed to claim ownership.
    if (
      definition.ownerId &&
      definition.ownerId !== envelope.author.fingerprint &&
      definition.ownerId !== envelope.author.pub
    ) {
      throw new Error('Domain ownerId does not match the envelope author');
    }

    // Check handle availability. A timed-out read is NOT proof the handle is
    // free: fail closed so a slow relay cannot cause a duplicate handle.
    const handleLookup = await this.getDomainIdByHandle(definition.handle);
    if (handleLookup.status === 'found' && handleLookup.domainId !== definition.id) {
        throw new Error(`Handle ${definition.handle} is already taken`);
    }
    if (handleLookup.status === 'unknown') {
        throw new DomainLookupError(
            `Cannot verify handle '${definition.handle}' is available (read timed out)`
        );
    }

    // Store in Gun
    // domains/by_handle/<handle> -> domainId
    this.gun.get('domains').get('by_handle').get(definition.handle).put(definition.id);
    
    // domains/<domainId> -> envelope (store the whole signed envelope)
    this.gun.get('domains').get(definition.id).put(envelope);
    
    // Add owner as member (if not already implicit)
    // The owner is the envelope author.
    await this.addMember(definition.id, envelope.author.fingerprint, 'owner', 'active');
  }

  async joinDomain(domainId: string): Promise<{ status: MembershipStatus }> {
    // Fetch domain — getDomain unwraps the stored SignedEnvelope for us, so
    // `definition` is a real DomainDefinition with normalized rules. A timed
    // out read is reported separately from "not found": it must not be
    // mistaken for a deny-by-absence.
    const lookup = await this.getDomain(domainId);
    if (lookup.status === 'absent') throw new Error("Domain not found");
    if (lookup.status === 'unknown') {
      throw new DomainLookupError(
        `Cannot verify domain '${domainId}' (read timed out); refusing to join`
      );
    }

    const definition = lookup.definition;
    const rules = this.normalizeRules(definition.rules);

    // Check rules
    let status: MembershipStatus = 'active';
    if (rules.requiresApproval) {
      status = 'pending';
    }

    const address = this.wallet.address;

    if (rules.blacklist && rules.blacklist.some(entry => sameId(entry, address))) {
      throw new Error('This identity is banned from the domain');
    }

    // Whitelist: when declared, only listed identities may join. Declared but
    // not listed -> denied.
    if (
      rules.whitelist &&
      rules.whitelist.length > 0 &&
      !rules.whitelist.some(entry => sameId(entry, address))
    ) {
      throw new Error('This identity is not whitelisted for the domain');
    }

    // Minimum reputation: fail closed — an unknown reputation is a denial,
    // never a pass.
    if (typeof rules.minReputation === 'number' && rules.minReputation > 0) {
      const reputation = await this.readReputation(address);
      if (reputation === null) {
        throw new Error(
          `Reputation could not be established; cannot verify the domain minimum (${rules.minReputation})`
        );
      }
      if (reputation < rules.minReputation) {
        throw new Error(`Insufficient reputation. Required: ${rules.minReputation}`);
      }
    }

    // Check staking tier
    const balance = await this.wallet.getBalance();
    const userTierIdx = TIER_ORDER.indexOf(balance.stakingTier);
    const requiredTierIdx = TIER_ORDER.indexOf(rules.minStakingTier);

    if (userTierIdx < requiredTierIdx) {
        throw new Error(`Insufficient staking tier. Required: ${rules.minStakingTier}`);
    }

    await this.addMember(domainId, address, 'member', status);
    return { status };
  }

  async leaveDomain(domainId: string): Promise<boolean> {
    await this.removeMember(domainId, this.wallet.address);
    return true;
  }

  /**
   * Load a domain definition.
   *
   * Domains are stored as the full SignedEnvelope at `domains/<id>`, so the
   * stored node is unwrapped back to its DomainDefinition payload here.
   *
   * Returns a typed result: `absent` means the node exists but holds no
   * definition, `unknown` means the read timed out (the domain MAY exist —
   * callers must fail closed), and `found` carries the definition.
   */
  async getDomain(domainId: string): Promise<DomainLookupResult> {
    const primary = await this.readOnce(this.gun.get('domains').get(domainId));
    if (!primary.available) return { status: 'unknown' };

    const direct = this.extractDefinition(primary.data);
    if (direct) return { status: 'found', definition: direct };

    // Gun stores nested objects as separate nodes: follow the payload link.
    if (this.isGunRef(primary.data?.payload)) {
      const payload = await this.readOnce(
        this.gun.get('domains').get(domainId).get('payload')
      );
      if (!payload.available) return { status: 'unknown' };

      const definition = this.extractDefinition(payload.data);
      return definition
        ? { status: 'found', definition }
        : { status: 'absent' };
    }

    return { status: 'absent' };
  }

  /**
   * Load the stored SignedEnvelope for a domain, when one is available.
   */
  async getDomainEnvelope(domainId: string): Promise<SignedEnvelope<DomainDefinition> | null> {
    const read = await this.readOnce(this.gun.get('domains').get(domainId));
    if (!read.available) return null;

    const stored = read.data;
    if (!stored || typeof stored !== 'object' || !stored.signature || !stored.author) {
      return null;
    }
    const lookup = await this.getDomain(domainId);
    if (lookup.status !== 'found') return null;
    return { ...stored, payload: lookup.definition } as SignedEnvelope<DomainDefinition>;
  }

  async getDomainIdByHandle(handle: string): Promise<HandleLookupResult> {
      const read = await this.readOnce(this.gun.get('domains').get('by_handle').get(handle));
      if (!read.available) return { status: 'unknown' };
      if (typeof read.data === 'string') return { status: 'found', domainId: read.data };
      return { status: 'absent' };
  }

  /**
   * List stored domain definitions (up to `limit`).
   */
  async listDomains(limit: number = 20): Promise<DomainDefinition[]> {
      if (limit <= 0) return [];

      const found: DomainDefinition[] = [];
      const seen = new Set<string>();

      await new Promise<void>((resolve) => {
          const finish = this.settleOnce(resolve);

          try {
              this.gun.get('domains').map().once((data: any, key: string) => {
                  // `by_handle` is an index node, not a domain.
                  if (key === 'by_handle') return;

                  const definition = this.extractDefinition(data);
                  if (!definition || seen.has(definition.id)) return;

                  seen.add(definition.id);
                  found.push(definition);

                  if (found.length >= limit) finish();
              });
          } catch {
              finish();
          }
      });

      return found.slice(0, limit);
  }

  async getMembers(domainId: string): Promise<DomainMembership[]> {
      const read = await this.readOnce(
          this.gun.get('domains').get(domainId).get('members')
      );
      if (!read.available) return [];
      const data = read.data;
      if (!data || typeof data !== 'object') return [];
      return Object.keys(data)
        .filter(k => k !== '_' && data[k] && typeof data[k] === 'object')
        .map(k => data[k] as DomainMembership);
  }

  async getCommonDomains(userId: string): Promise<string[]> {
      const myDomains = await this.getUserDomains(this.wallet.address);
      const theirDomains = await this.getUserDomains(userId);
      return myDomains.filter(d => theirDomains.includes(d));
  }

  private async getUserDomains(userId: string): Promise<string[]> {
      if (!userId) return [];
      const read = await this.readOnce(
          this.gun.get('users').get(userId).get('domains')
      );
      if (!read.available) return [];
      const data = read.data;
      if (!data || typeof data !== 'object') return [];
      return Object.keys(data).filter(k => k !== '_' && data[k]);
  }

  // ─── Shape Helpers ────────────────────────────────────────────────────

  /**
   * Pull a DomainDefinition out of whatever a Gun node handed back: the
   * definition itself, a stored SignedEnvelope (`payload`), or a `{definition}`
   * wrapper. Returns null when the node holds none of those.
   */
  private extractDefinition(data: any): DomainDefinition | null {
      if (!data || typeof data !== 'object') return null;

      const candidate =
          (this.looksLikeDefinition(data) && data) ||
          (this.looksLikeDefinition(data.payload) && data.payload) ||
          (this.looksLikeDefinition(data.definition) && data.definition) ||
          null;

      if (!candidate) return null;

      return {
          ...(candidate as DomainDefinition),
          visibility: this.normalizeVisibility(candidate.visibility),
          rules: this.normalizeRules(candidate.rules),
      };
  }

  private looksLikeDefinition(value: any): boolean {
      return (
          !!value &&
          typeof value === 'object' &&
          typeof value.id === 'string' &&
          typeof value.handle === 'string'
      );
  }

  /**
   * Fill in a complete DomainRules, defaulting anything the stored node is
   * missing. Prevents `rules.requiresApproval` style reads from throwing.
   * List entries (whitelist/blacklist) are trimmed so identity comparisons
   * are not defeated by stray whitespace.
   */
  private normalizeRules(rules: any): DomainRules {
      const source = rules && typeof rules === 'object' ? rules : {};
      return {
          minStakingTier: TIER_ORDER.includes(source.minStakingTier)
              ? source.minStakingTier
              : DEFAULT_DOMAIN_RULES.minStakingTier,
          minReputation:
              typeof source.minReputation === 'number' && Number.isFinite(source.minReputation)
                  ? source.minReputation
                  : DEFAULT_DOMAIN_RULES.minReputation,
          requiresApproval: source.requiresApproval === true,
          whitelist: Array.isArray(source.whitelist)
              ? source.whitelist.filter((e: unknown) => typeof e === 'string').map((e: string) => e.trim())
              : undefined,
          blacklist: Array.isArray(source.blacklist)
              ? source.blacklist.filter((e: unknown) => typeof e === 'string').map((e: string) => e.trim())
              : undefined,
          grantedCapabilities: Array.isArray(source.grantedCapabilities)
              ? source.grantedCapabilities
              : [],
      };
  }

  private normalizeVisibility(visibility: any): DomainVisibility {
      return visibility === 'private' || visibility === 'secret' || visibility === 'public'
          ? visibility
          : 'public';
  }

  private isGunRef(value: any): boolean {
      return !!value && typeof value === 'object' && typeof value['#'] === 'string';
  }

  // ─── Gun Read Helpers ─────────────────────────────────────────────────

  /**
   * Read a Gun node once, reporting whether data actually arrived. A missing
   * node still fires its callback (with undefined) and is reported as
   * `{ available: true, data: null }`; only a timeout or transport error is
   * reported as `available: false`. Callers must NOT conflate the two: an
   * unavailable read means the answer is unknown, not "not found".
   */
  private readOnce(node: any): Promise<GunReadResult> {
      return new Promise((resolve) => {
          let settled = false;
          let timer: any;
          const finish = (result: GunReadResult) => {
              if (settled) return;
              settled = true;
              clearTimeout(timer);
              resolve(result);
          };

          timer = setTimeout(
              () => finish({ available: false, data: null }),
              GUN_READ_TIMEOUT_MS
          );
          if (typeof timer?.unref === 'function') timer.unref();

          try {
              node.once((data: any) => finish({ available: true, data: data ?? null }));
          } catch {
              finish({ available: false, data: null });
          }
      });
  }

  /**
   * Read the caller's reputation score (`reputation/<id>` as a bare number or
   * a `{ score }` node). Returns null when the score cannot be established —
   * callers requiring a minimum must fail closed on null.
   */
  private async readReputation(userId: string): Promise<number | null> {
      const read = await this.readOnce(this.gun.get('reputation').get(userId));
      if (!read.available || read.data === null) return null;
      if (typeof read.data === 'number' && Number.isFinite(read.data)) return read.data;
      if (
          read.data &&
          typeof read.data === 'object' &&
          typeof read.data.score === 'number' &&
          Number.isFinite(read.data.score)
      ) {
          return read.data.score;
      }
      return null;
  }

  /**
   * Build a resolver that fires at most once and is armed with a timeout.
   */
  private settleOnce<R>(resolve: (value: any) => void): (value?: R) => void {
      let done = false;
      const timer: any = setTimeout(() => settle(undefined), GUN_READ_TIMEOUT_MS);
      if (typeof timer?.unref === 'function') timer.unref();

      function settle(value?: R): void {
          if (done) return;
          done = true;
          clearTimeout(timer);
          resolve(value === undefined ? null : value);
      }

      return settle;
  }

  private async addMember(domainId: string, userId: string, role: DomainRole, status: MembershipStatus) {
    const membership: DomainMembership = {
      domainId,
      userId,
      role,
      status,
      joinedAt: Date.now()
    };
    
    this.gun.get('domains').get(domainId).get('members').get(userId).put(membership);
    this.gun.get('users').get(userId).get('domains').get(domainId).put(membership);
  }

  private async removeMember(domainId: string, userId: string) {
      this.gun.get('domains').get(domainId).get('members').get(userId).put(null);
      this.gun.get('users').get(userId).get('domains').get(domainId).put(null);
  }
}
