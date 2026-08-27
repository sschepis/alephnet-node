/**
 * Shared harness for the social test suite.
 */

import { Identity } from '../../src/social/Identity';
import { ActionVerifier, signAction, SignedAction } from '../../src/social/SignedAction';
import { MemorySocialStore } from '../../src/social/SocialStore';

/** Mutable clock so tests can control time precisely. */
export class FakeClock {
  nowMs: number;

  constructor(start = 1_700_000_000_000) {
    this.nowMs = start;
  }

  /** Current time as a `SocialClock`-compatible function. */
  now = (): number => this.nowMs;

  advance(ms: number): void {
    this.nowMs += ms;
  }
}

export interface Wired {
  clock: FakeClock;
  store: MemorySocialStore;
  verifier: ActionVerifier;
  alice: Identity;
  bob: Identity;
  mallory: Identity;
}

/**
 * A store + verifier sharing one fake clock, plus three identities
 * (alice, bob, mallory).
 */
export function wire(nowMs?: number): Wired {
  const clock = new FakeClock(nowMs);
  const store = new MemorySocialStore();
  const verifier = new ActionVerifier({ clock: clock.now });
  return {
    clock,
    store,
    verifier,
    alice: Identity.create({ displayName: 'Alice' }),
    bob: Identity.create({ displayName: 'Bob' }),
    mallory: Identity.create({ displayName: 'Mallory' })
  };
}

/** Sign an envelope for `identity` using the shared clock. */
export function act<P>(
  action: string,
  payload: P,
  identity: Identity,
  clock: FakeClock
): SignedAction<P> {
  return signAction(action, payload, identity, { clock: clock.now });
}
