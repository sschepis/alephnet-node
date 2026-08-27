/**
 * Node Layer — Node-Attested Envelopes
 *
 * The social layer's mutations all require `SignedAction` envelopes whose
 * verified author IS the acting identity. HTTP requests, however, prove the
 * caller to the AUTH layer with the caller's own Ed25519 key — the node
 * process never holds client private keys, so it cannot sign a
 * `content.put` / `feed.mark.read` envelope *as* the caller.
 *
 * This module closes that gap without weakening the store's guarantees:
 *
 *   - `NodeAttestedSigner.signFor(identity, action, payload)` builds an
 *     envelope whose author fields carry the HTTP-AUTHENTICATED caller's
 *     fingerprint + public key, signed with the NODE's own private key.
 *     The signature is therefore an attestation: "this node, after verifying
 *     the caller's request signature, vouches that <identity> performed
 *     <action>".
 *   - `NodeAttestedVerifier` is the `ActionVerifier` handed to the social
 *     stores that take node-built envelopes. It verifies the envelope's
 *     signature under the NODE's key, requires the claimed author to have an
 *     active attestation registered by the signer, binds the claimed
 *     `authorPub` to that attestation, checks freshness and rejects replayed
 *     nonces.
 *
 * The author identity can therefore never be forged through input fields:
 * an envelope is accepted only when (a) the node signed it and (b) the node
 * itself recorded the author from an HTTP-authenticated request. A caller
 * with no valid request signature never gets an attestation, and a captured
 * envelope cannot be replayed (freshness window + single-use nonces).
 */

import type { AuthenticatedIdentity } from '../app';
import { base64ToBuffer, verifyFromBase64 } from '../common/crypto';
import {
  ActionSigner,
  ActionVerifier,
  MemoryNonceStore,
  SignedAction,
  SignedActionError,
  SignedActionFailure,
  VerifiedAction,
  canonicalActionString,
  createNonce,
  isFingerprint,
  Timestamp
} from '../social';

// ═══════════════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════════════

/** How long a recorded HTTP-auth attestation stays usable. */
export const DEFAULT_ATTESTATION_TTL_MS = 60 * 1000;

/** Envelope freshness window (matches the social layer default). */
const MAX_AGE_MS = 5 * 60 * 1000;
const MAX_FUTURE_MS = 60 * 1000;

/** Bound on concurrently-attested identities, so the map cannot grow forever. */
const MAX_ATTESTATIONS = 2_000;

interface Attestation {
  readonly fingerprint: string;
  readonly publicKey: string;
  readonly expiresAt: Timestamp;
}

// ═══════════════════════════════════════════════════════════════════════════
// VERIFIER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * `ActionVerifier` that accepts envelopes attested by this node instead of
 * envelopes signed by the author's own key (which the node does not hold).
 */
export class NodeAttestedVerifier extends ActionVerifier {
  private readonly nodePublicKey: string;
  private readonly attestationTtlMs: number;
  private readonly attestations = new Map<string, Attestation>();
  private readonly nonces = new MemoryNonceStore();

  constructor(nodePublicKeyBase64: string, attestationTtlMs: number = DEFAULT_ATTESTATION_TTL_MS) {
    super();
    this.nodePublicKey = nodePublicKeyBase64;
    this.attestationTtlMs = attestationTtlMs;
  }

  /**
   * Record that `identity` just passed HTTP request authentication. Only the
   * node (which owns the signer) may call this; envelope authors must come
   * from here, never from envelope fields alone.
   */
  attest(identity: AuthenticatedIdentity): void {
    this.prune();
    this.attestations.set(identity.fingerprint, {
      fingerprint: identity.fingerprint,
      publicKey: identity.publicKey,
      expiresAt: Date.now() + this.attestationTtlMs
    });
    while (this.attestations.size > MAX_ATTESTATIONS) {
      const oldest = this.attestations.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.attestations.delete(oldest);
    }
  }

  /**
   * Verify a node-attested envelope. Never calls the base-class signature
   * check (the author did not sign it — the node did); every other guard
   * (action match, freshness, nonce, author binding) still applies.
   */
  override async verify<P>(
    envelope: SignedAction<P>,
    expectedAction?: string | readonly string[]
  ): Promise<VerifiedAction<P>> {
    const failure = (code: SignedActionFailure, message: string): never => {
      throw new SignedActionError(code, message);
    };

    if (typeof envelope !== 'object' || envelope === null || typeof envelope.action !== 'string') {
      failure('malformed_envelope', 'Envelope must be an object with an action name');
    }
    if (typeof envelope.action !== 'string' || envelope.action.length === 0) {
      failure('malformed_envelope', 'Envelope action must be a non-empty string');
    }
    if (expectedAction !== undefined) {
      const allowed = typeof expectedAction === 'string' ? [expectedAction] : expectedAction;
      if (!allowed.includes(envelope.action)) {
        failure(
          'action_mismatch',
          `Expected action ${allowed.join('|')} but envelope declares ${envelope.action}`
        );
      }
    }
    if (typeof envelope.timestamp !== 'number' || !Number.isFinite(envelope.timestamp) || envelope.timestamp <= 0) {
      failure('malformed_envelope', 'Envelope timestamp must be a positive finite number');
    }
    if (typeof envelope.nonce !== 'string' || envelope.nonce.length < 8 || envelope.nonce.length > 128) {
      failure('malformed_envelope', 'Envelope nonce must be a string of 8..128 chars');
    }
    if (typeof envelope.signature !== 'string' || envelope.signature.length === 0) {
      failure('malformed_envelope', 'Envelope signature must be a base64 string');
    }

    const now = Date.now();
    const age = now - envelope.timestamp;
    if (age > MAX_AGE_MS) {
      failure('timestamp_out_of_window', `Envelope is stale: ${age}ms old, limit ${MAX_AGE_MS}ms`);
    }
    if (age < -MAX_FUTURE_MS) {
      failure('timestamp_out_of_window', `Envelope timestamp is ${-age}ms in the future`);
    }

    // The envelope MUST be signed by the node: without the node's key nobody
    // can attest an author, and the base verifier's signature path is
    // deliberately bypassed for the author key the node does not hold.
    const signed = canonicalActionString(
      envelope.action,
      envelope.payload,
      envelope.timestamp,
      envelope.nonce
    );
    let signatureValid = false;
    try {
      signatureValid = verifyFromBase64(signed, envelope.signature, base64ToBuffer(this.nodePublicKey));
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) {
      failure('invalid_signature', 'Envelope was not signed by this node');
    }

    if (!isFingerprint(envelope.authorFingerprint)) {
      failure('malformed_envelope', 'Envelope authorFingerprint must be 16 lowercase hex characters');
    }

    // The claimed author must have an ACTIVE attestation recorded by the node,
    // and the claimed public key must be the one that passed HTTP auth.
    const attestation = this.attestations.get(envelope.authorFingerprint);
    if (attestation === undefined || attestation.expiresAt <= now) {
      failure(
        'fingerprint_mismatch',
        'Envelope author has no active HTTP-auth attestation on this node'
      );
    }
    if (attestation!.publicKey !== envelope.authorPub) {
      failure('fingerprint_mismatch', 'Envelope authorPub does not match the attested identity');
    }

    const nonceKey = `${attestation!.fingerprint}:${envelope.nonce}`;
    const claimed = await this.nonces.claim(nonceKey, envelope.timestamp + MAX_AGE_MS);
    if (!claimed) {
      failure('replayed_nonce', 'Envelope nonce has already been used by this author');
    }

    return {
      action: envelope.action,
      payload: envelope.payload,
      author: { pub: attestation!.publicKey, fingerprint: attestation!.fingerprint },
      timestamp: envelope.timestamp,
      nonce: envelope.nonce,
      signature: envelope.signature
    };
  }

  /** Drop expired attestations so the map stays bounded. */
  private prune(): void {
    const now = Date.now();
    for (const [fingerprint, attestation] of this.attestations) {
      if (attestation.expiresAt <= now) this.attestations.delete(fingerprint);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// SIGNER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Builds node-attested envelopes for HTTP-authenticated callers and exposes
 * the matching verifier for the social stores that consume them.
 */
export class NodeAttestedSigner {
  readonly verifier: NodeAttestedVerifier;

  constructor(private readonly nodeSigner: ActionSigner, attestationTtlMs?: number) {
    this.verifier = new NodeAttestedVerifier(nodeSigner.publicKeyBase64, attestationTtlMs);
  }

  /**
   * Build a `SignedAction<P>` carrying `identity` as the author, signed with
   * the node's key. The identity must come from HTTP request authentication —
   * callers pass `ctx.identity`, never a body field.
   */
  signFor<P>(identity: AuthenticatedIdentity, action: string, payload: P): SignedAction<P> {
    this.verifier.attest(identity);
    const timestamp = Date.now();
    const nonce = createNonce();
    const signature = this.nodeSigner.sign(
      canonicalActionString(action, payload, timestamp, nonce)
    );
    return {
      action,
      payload,
      authorPub: identity.publicKey,
      authorFingerprint: identity.fingerprint,
      timestamp,
      nonce,
      signature
    };
  }
}
