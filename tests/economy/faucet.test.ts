/**
 * Faucet tests.
 *
 * Each test asserts a specific legacy exploit is closed:
 *  - fixed server-defined drip (caller cannot choose an amount)
 *  - finite treasury: caps on cumulative payouts, no self-minting
 *  - HMAC challenge authenticity with an injected secret, actually verified
 *  - real Ed25519 claim signatures
 *  - cooldown keyed on the VERIFIED fingerprint, not client input
 *  - real leading-zero-bit proof of work
 */

import { describe, expect, it } from '@jest/globals';
import { generateEd25519KeyPair, randomBytes, signToBase64 } from '../../src/common/crypto';
import {
  Faucet,
  FaucetClaimRequest,
  FaucetError,
  claimMessage,
  countLeadingZeroBits,
  meetsDifficulty,
  powHash,
  solveFaucetChallenge
} from '../../src/economy/Faucet';
import { ONE_TOKEN, parseTokens, wholeTokens } from '../../src/economy/units';
import { createTestLedger, TestLedger, TestWallet } from './fakeLedger';

const DRIP = wholeTokens(10);

interface FaucetFixture {
  faucet: Faucet;
  treasury: TestWallet['wallet'];
}

function buildFaucet(
  ledger: TestLedger,
  overrides: Partial<ConstructorParameters<typeof Faucet>[0]> = {}
): FaucetFixture {
  const treasury = ledger.createWallet({ available: wholeTokens(1_000_000) }).wallet;
  const faucet = new Faucet({
    secret: randomBytes(32),
    treasury,
    difficultyBits: 4,
    cooldownMs: 60_000,
    ...overrides
  });
  return { faucet, treasury };
}

/** Issue a challenge, solve the PoW and sign it — the honest client path. */
function buildClaim(faucet: Faucet, claimant: TestWallet): FaucetClaimRequest {
  const issued = faucet.issueChallenge(claimant.keyTriplet.pub);
  const nonce = solveFaucetChallenge(issued.challenge, issued.difficulty).nonce;
  const signature = signToBase64(
    claimMessage(issued.challenge, nonce),
    Buffer.from(claimant.keyTriplet.priv, 'base64')
  );
  return { challenge: issued.challenge, nonce, signature, pub: claimant.keyTriplet.pub };
}

describe('proof of work', () => {
  it('counts leading zero bits and enforces the target', () => {
    expect(countLeadingZeroBits('0'.repeat(64))).toBe(256);
    expect(countLeadingZeroBits('f'.repeat(64))).toBe(0);
    expect(countLeadingZeroBits('08')).toBe(4);
    expect(countLeadingZeroBits('01')).toBe(4 + 3);
    expect(countLeadingZeroBits('1f')).toBe(3);
    expect(countLeadingZeroBits('2f')).toBe(2);
    expect(countLeadingZeroBits('4f')).toBe(1);

    const hash = powHash('challenge', '0');
    const bits = countLeadingZeroBits(hash);
    expect(meetsDifficulty(hash, bits)).toBe(true);
    expect(meetsDifficulty(hash, bits + 1)).toBe(false);
  });

  it('solveFaucetChallenge produces a hash meeting the difficulty', () => {
    const { nonce, hash } = solveFaucetChallenge('test-challenge', 8);
    expect(meetsDifficulty(hash, 8)).toBe(true);
    expect(nonce.length).toBeGreaterThan(0);
  });
});

describe('Faucet', () => {
  it('rejects construction without a proper injected secret (nothing is hardcoded)', () => {
    const treasury = createTestLedger().createWallet({ available: wholeTokens(100) }).wallet;
    expect(() => new Faucet({ secret: randomBytes(8), treasury })).toThrow(/at least 32 bytes/);
    expect(() => new Faucet({ treasury } as any)).toThrow(FaucetError);
  });

  it('credits exactly the fixed drip on a valid claim', async () => {
    const ledger = createTestLedger();
    const { faucet, treasury } = buildFaucet(ledger);
    const claimant = ledger.createWallet();

    const before = ledger.available(claimant.address);
    const result = await faucet.claim(buildClaim(faucet, claimant));
    await ledger.flush();

    expect(result.amount).toBe(DRIP);
    expect(ledger.available(claimant.address) - before).toBe(DRIP);
    expect(result.fingerprint).toBe(claimant.wallet.address);
    expect(ledger.available(treasury.address)).toBeLessThan(wholeTokens(1_000_000));
  });

  it('cannot be tricked into paying a caller-supplied amount', async () => {
    const ledger = createTestLedger();
    const { faucet } = buildFaucet(ledger);
    const claimant = ledger.createWallet();

    // Attack: smuggle an amount. The request type has no amount field and
    // the credited amount is always the server-configured drip.
    const request = { ...buildClaim(faucet, claimant), amount: '999999999999' } as FaucetClaimRequest;
    const result = await faucet.claim(request);
    await ledger.flush();

    expect(result.amount).toBe(DRIP);
    expect(ledger.available(claimant.address)).toBe(DRIP);
  });

  it('rejects a wrong PoW nonce', async () => {
    const ledger = createTestLedger();
    const { faucet } = buildFaucet(ledger);
    const claimant = ledger.createWallet();

    const issued = faucet.issueChallenge(claimant.keyTriplet.pub);

    // Find a nonce that provably fails the target.
    let failingNonce = '0';
    while (meetsDifficulty(powHash(issued.challenge, failingNonce), issued.difficulty)) {
      failingNonce = String(Number(failingNonce) + 1);
    }

    await expect(
      faucet.claim({
        challenge: issued.challenge,
        nonce: failingNonce,
        signature: signToBase64(
          claimMessage(issued.challenge, failingNonce),
          Buffer.from(claimant.keyTriplet.priv, 'base64')
        ),
        pub: claimant.keyTriplet.pub
      })
    ).rejects.toMatchObject({ code: 'POW_INSUFFICIENT' });

    expect(ledger.available(claimant.address)).toBe(0n);
  });

  it('rejects a claim with a forged or absent signature', async () => {
    const ledger = createTestLedger();
    const { faucet } = buildFaucet(ledger);
    const claimant = ledger.createWallet();

    const issued = faucet.issueChallenge(claimant.keyTriplet.pub);
    const nonce = solveFaucetChallenge(issued.challenge, issued.difficulty).nonce;

    // Absent signature
    await expect(
      faucet.claim({ challenge: issued.challenge, nonce, signature: '', pub: claimant.keyTriplet.pub })
    ).rejects.toMatchObject({ code: 'SIGNATURE_INVALID' });

    // Signature by a key that did not solve the challenge (attacker key)
    const attacker = generateEd25519KeyPair();
    await expect(
      faucet.claim({
        challenge: issued.challenge,
        nonce,
        signature: signToBase64(
          claimMessage(issued.challenge, nonce),
          Buffer.from(attacker.privateKeyBase64, 'base64')
        ),
        pub: claimant.keyTriplet.pub
      })
    ).rejects.toMatchObject({ code: 'SIGNATURE_INVALID' });

    expect(ledger.available(claimant.address)).toBe(0n);
  });

  it('rejects a tampered challenge even with valid work and signature', async () => {
    const ledger = createTestLedger();
    const { faucet } = buildFaucet(ledger);
    const claimant = ledger.createWallet();

    const issued = faucet.issueChallenge(claimant.keyTriplet.pub);

    // Tamper with the expiry INSIDE the HMAC-authenticated envelope, then
    // honestly mine and sign the tampered string.
    const segments = issued.challenge.split('.');
    segments[5] = String(Number(segments[5]) + 86_400_000);
    const tampered = segments.join('.');

    const nonce = solveFaucetChallenge(tampered, issued.difficulty).nonce;
    const request: FaucetClaimRequest = {
      challenge: tampered,
      nonce,
      signature: signToBase64(
        claimMessage(tampered, nonce),
        Buffer.from(claimant.keyTriplet.priv, 'base64')
      ),
      pub: claimant.keyTriplet.pub
    };

    await expect(faucet.claim(request)).rejects.toMatchObject({ code: 'CHALLENGE_FORGED' });
    expect(ledger.available(claimant.address)).toBe(0n);
  });

  it('rejects a challenge issued to a different key', async () => {
    const ledger = createTestLedger();
    const { faucet } = buildFaucet(ledger);
    const claimant = ledger.createWallet();
    const other = ledger.createWallet();

    // Challenge bound to `other`, mined and signed by `claimant`: the work
    // and signature are valid but the binding check must fail.
    const issued = faucet.issueChallenge(other.keyTriplet.pub);
    const nonce = solveFaucetChallenge(issued.challenge, issued.difficulty).nonce;

    await expect(
      faucet.claim({
        challenge: issued.challenge,
        nonce,
        signature: signToBase64(
          claimMessage(issued.challenge, nonce),
          Buffer.from(claimant.keyTriplet.priv, 'base64')
        ),
        pub: claimant.keyTriplet.pub
      })
    ).rejects.toMatchObject({ code: 'CHALLENGE_KEY_MISMATCH' });
  });

  it('enforces cooldown on the verified fingerprint, regardless of claimed identity', async () => {
    const ledger = createTestLedger();
    const { faucet } = buildFaucet(ledger);
    const claimant = ledger.createWallet();

    const first = await faucet.claim(buildClaim(faucet, claimant));
    await ledger.flush();
    expect(first.amount).toBe(DRIP);

    // Second claim from the SAME key. The caller may lie about its identity
    // all it wants — the request has no fingerprint field and the cooldown
    // keys off the verified public key.
    const forgedIdentity = { ...buildClaim(faucet, claimant), fingerprint: 'rotated-identity' };
    await expect(faucet.claim(forgedIdentity)).rejects.toMatchObject({ code: 'COOLDOWN_ACTIVE' });

    // A genuinely different key is NOT blocked by the first key's cooldown.
    const other = ledger.createWallet();
    const otherClaim = await faucet.claim(buildClaim(faucet, other));
    expect(otherClaim.amount).toBe(DRIP);
  });

  it('enforces the treasury cap and can never pay more than configured', async () => {
    const ledger = createTestLedger();
    const { faucet } = buildFaucet(ledger, {
      treasuryCap: DRIP,
      dripAmount: DRIP,
      cooldownMs: 0
    });

    const first = ledger.createWallet();
    const second = ledger.createWallet();

    await faucet.claim(buildClaim(faucet, first));
    // Even with the cooldown disabled, the cumulative cap blocks further payouts.
    await expect(faucet.claim(buildClaim(faucet, second))).rejects.toMatchObject({
      code: 'TREASURY_EXHAUSTED'
    });
  });

  it('enforces the challenge expiry', async () => {
    const ledger = createTestLedger();
    const treasury = ledger.createWallet({ available: wholeTokens(1_000_000) }).wallet;
    let now = 1_000_000;

    const faucet = new Faucet({
      secret: randomBytes(32),
      treasury,
      difficultyBits: 4,
      now: () => now
    });

    const claimant = ledger.createWallet();
    const request = buildClaim(faucet, claimant);

    // Advance past the challenge lifetime.
    now += 6 * 60 * 1000;

    await expect(faucet.claim(request)).rejects.toMatchObject({ code: 'CHALLENGE_EXPIRED' });
  });

  it('rejects a challenge whose issuedAt is in the future (clock skew guard)', async () => {
    const ledger = createTestLedger();
    const treasury = ledger.createWallet({ available: wholeTokens(1_000_000) }).wallet;
    let now = 1_000_000;

    const faucet = new Faucet({
      secret: randomBytes(32),
      treasury,
      difficultyBits: 4,
      now: () => now
    });

    const claimant = ledger.createWallet();
    const request = buildClaim(faucet, claimant);

    // The server clock drifts backwards after issuing: the envelope is now
    // "from the future" and must not be honoured.
    now -= 60_000;

    await expect(faucet.claim(request)).rejects.toMatchObject({ code: 'CHALLENGE_NOT_YET_VALID' });
    expect(ledger.available(claimant.address)).toBe(0n);
  });

  it('two concurrent claims of the same challenge pay exactly one drip', async () => {
    const ledger = createTestLedger();
    const { faucet } = buildFaucet(ledger);
    const claimant = ledger.createWallet();

    const request = buildClaim(faucet, claimant);
    const [first, second] = await Promise.allSettled([
      faucet.claim(request),
      faucet.claim(request)
    ]);
    await ledger.flush();

    const fulfilled = [first, second].filter(result => result.status === 'fulfilled');
    const rejected = [first, second].filter(result => result.status === 'rejected');
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect((rejected[0] as PromiseRejectedResult).reason).toMatchObject({
      code: 'CHALLENGE_CONSUMED'
    });
    expect(ledger.available(claimant.address)).toBe(DRIP);
  });

  it('releases the reservation when the transfer fails, so the claimant can retry', async () => {
    const ledger = createTestLedger();
    // Empty treasury: every transfer fails.
    const treasury = ledger.createWallet({ available: 0n }).wallet;
    const faucet = new Faucet({
      secret: randomBytes(32),
      treasury,
      difficultyBits: 4,
      cooldownMs: 60_000
    });
    const claimant = ledger.createWallet();

    const cap = faucet.stats().treasuryCap;
    await expect(faucet.claim(buildClaim(faucet, claimant))).rejects.toMatchObject({
      code: 'TRANSFER_FAILED'
    });

    // Nothing moved, so the reservation must have been fully released:
    // counters, cooldown and consumed set are all back to their prior state.
    expect(faucet.remaining()).toBe(cap);

    // Fund the treasury and retry the same claimant: it must succeed.
    ledger.seed(treasury.address, { available: wholeTokens(1_000_000) });
    const retry = await faucet.claim(buildClaim(faucet, claimant));
    await ledger.flush();
    expect(retry.amount).toBe(DRIP);
    expect(ledger.available(claimant.address)).toBe(DRIP);
  });

  it('prunes cooldown entries once their window has elapsed', async () => {
    const ledger = createTestLedger();
    const treasury = ledger.createWallet({ available: wholeTokens(1_000_000) }).wallet;
    let now = 1_000_000;

    const faucet = new Faucet({
      secret: randomBytes(32),
      treasury,
      difficultyBits: 4,
      cooldownMs: 1_000,
      now: () => now
    });

    const first = ledger.createWallet();
    await faucet.claim(buildClaim(faucet, first));
    expect(faucet.stats().claimants).toBe(1);

    // Long past the cooldown: the entry must be pruned on the next claim.
    now += 60_000;
    const second = ledger.createWallet();
    await faucet.claim(buildClaim(faucet, second));
    expect(faucet.stats().claimants).toBe(1);

    // The first claimant is no longer blocked by its old cooldown entry.
    now += 60_000;
    await faucet.claim(buildClaim(faucet, first));
    expect(faucet.stats().claimants).toBe(1);
  });

  it('exposes remaining treasury without minting', () => {
    const ledger = createTestLedger();
    const { faucet } = buildFaucet(ledger, { treasuryCap: parseTokens('1000') });
    expect(faucet.remaining()).toBe(parseTokens('1000'));
    expect(faucet.stats().dripAmount).toBe(DRIP);
  });
});
