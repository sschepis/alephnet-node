/**
 * AlephNet Node — Unified TypeScript package barrel.
 *
 * Everything ships from here: common primitives, core, infra, services,
 * storage, schema, and the five domain layers (semantic, social, economy,
 * coherence, app) plus the node composition layer.
 *
 * NOTE: several barrels export overlapping symbol names; the conflicting
 * ones are re-exported explicitly below rather than deleted.
 */

export * from './common';
export * from './core';
export * from './infra';
export * from './services';
export * from './storage';
export * from './schema';

export * from './semantic';
export * from './social';
export * from './economy';
export * from './coherence';
export * from './app';
export * from './node';

// ── NAME COLLISIONS BETWEEN BARRELS ────────────────────────────────────────
// `MessageType` is exported by BOTH `core/network/types` (network protocol
// frames: 'handshake' | 'ping' | ...) and `social/DirectMessages` (DM
// message kinds: 'text' | 'image' | 'file' | 'link'). Both are TYPE-ONLY
// union aliases (no runtime value exists under either name), so there are no
// duplicate VALUE exports to disambiguate. The core spelling stays the
// canonical type export for backwards compatibility with the pre-unification
// barrel; the social one is re-exported under an explicit alias so no
// functionality is lost.
export type { MessageType } from './core/network/types';
export type { MessageType as SocialMessageType } from './social/DirectMessages';
