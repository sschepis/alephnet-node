/**
 * Social Actions
 *
 * `social.friends.*`, `social.profile.*`, `social.groups.*` and
 * `social.feed.get`, wired to the social domain layer.
 *
 * Mutations require a verified `SignedAction` envelope, which the CLIENT
 * signs with its own Ed25519 key (the node never holds client private keys,
 * so it cannot sign on a caller's behalf). The envelope travels in the
 * action input and is bound to the HTTP-authenticated caller via
 * `bindEnvelope`: the envelope author must BE the authenticated fingerprint.
 * The actor therefore always comes from `ctx.identity.fingerprint` — never
 * from an input field, and the domain layer re-verifies every envelope
 * before mutating anything.
 */

import type { ActionModule } from '../../app';
import type { SocialSubsystem } from '../types';
import {
  FEED_ACTIONS,
  FRIEND_ACTIONS,
  GROUP_ACTIONS,
  PROFILE_ACTIONS,
  type CreateGroupPayload,
  type CreatePostPayload,
  type FeedSource,
  type FriendRequestPayload,
  type MarkReadFeedPayload,
  type ProfileUpdatePayload,
  type RequestIdPayload,
  type SignedAction
} from '../../social';
import { action, bindEnvelope, requireActor } from './helpers';

// ═══════════════════════════════════════════════════════════════════════════
// DEPS
// ═══════════════════════════════════════════════════════════════════════════

export interface SocialActionDeps {
  readonly social: SocialSubsystem;
}

// ═══════════════════════════════════════════════════════════════════════════
// INPUT SHAPES
// ═══════════════════════════════════════════════════════════════════════════

/** A signed envelope as it crosses the HTTP boundary. */
const ENVELOPE_FIELD = {
  envelope: {
    type: 'object' as const,
    required: true,
    description: 'SignedAction envelope signed by the authenticated caller'
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// MODULE
// ═══════════════════════════════════════════════════════════════════════════

export function createSocialActions(deps: SocialActionDeps): ActionModule {
  const bind = async <P>(ctx: Parameters<typeof bindEnvelope>[1], envelope: unknown, actions: readonly string[]): Promise<void> => {
    await bindEnvelope<P>(deps.social.bindVerifier, ctx, envelope, actions);
  };

  return {
    namespace: 'social',
    actions: [
      // ── friends.request ──────────────────────────────────────────────────
      action({
        name: 'social.friends.request',
        description: 'Send a friend request to another fingerprint (signed envelope).',
        input: { ...ENVELOPE_FIELD },
        handler: async (input, ctx) => {
          await bind<FriendRequestPayload>(ctx, input.envelope, [FRIEND_ACTIONS.request]);
          return deps.social.friends.sendRequest(input.envelope as SignedAction<FriendRequestPayload>);
        }
      }),

      // ── friends.accept ───────────────────────────────────────────────────
      action({
        name: 'social.friends.accept',
        description: 'Accept a pending friend request addressed to the caller (signed envelope).',
        input: { ...ENVELOPE_FIELD },
        handler: async (input, ctx) => {
          await bind<RequestIdPayload>(ctx, input.envelope, [FRIEND_ACTIONS.accept]);
          return deps.social.friends.acceptRequest(input.envelope as SignedAction<RequestIdPayload>);
        }
      }),

      // ── friends.list ─────────────────────────────────────────────────────
      action({
        name: 'social.friends.list',
        description: 'List the authenticated caller\'s friends and friendship stats.',
        input: {},
        handler: async (_input, ctx) => {
          const identity = requireActor(ctx);
          const [friends, stats] = await Promise.all([
            deps.social.friends.listFriends(identity.fingerprint),
            deps.social.friends.getStats(identity.fingerprint)
          ]);
          return { friends, stats };
        }
      }),

      // ── profile.get ──────────────────────────────────────────────────────
      action({
        name: 'social.profile.get',
        description: 'Read a profile (default: the caller\'s own), with visibility enforced.',
        input: {
          fingerprint: { type: 'string', pattern: /^[0-9a-f]{16}$/, description: 'Target fingerprint; defaults to the caller' }
        },
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          const target = (input.fingerprint as string | undefined) ?? identity.fingerprint;
          const profile = await deps.social.profiles.getProfile(target, identity.fingerprint);
          return { profile };
        }
      }),

      // ── profile.update ───────────────────────────────────────────────────
      action({
        name: 'social.profile.update',
        description: 'Create or update the caller\'s own profile (signed envelope). The edited profile is always the envelope author\'s.',
        input: { ...ENVELOPE_FIELD },
        handler: async (input, ctx) => {
          await bind<ProfileUpdatePayload>(ctx, input.envelope, [PROFILE_ACTIONS.update]);
          return deps.social.profiles.updateProfile(input.envelope as SignedAction<ProfileUpdatePayload>);
        }
      }),

      // ── groups.create ────────────────────────────────────────────────────
      action({
        name: 'social.groups.create',
        description: 'Create a group owned by the authenticated caller (signed envelope).',
        input: { ...ENVELOPE_FIELD },
        handler: async (input, ctx) => {
          await bind<CreateGroupPayload>(ctx, input.envelope, [GROUP_ACTIONS.create]);
          return deps.social.groups.createGroup(input.envelope as SignedAction<CreateGroupPayload>);
        }
      }),

      // ── groups.post ──────────────────────────────────────────────────────
      action({
        name: 'social.groups.post',
        description: 'Post to a group the authenticated caller is a member of (signed envelope).',
        input: { ...ENVELOPE_FIELD },
        handler: async (input, ctx) => {
          await bind<CreatePostPayload>(ctx, input.envelope, [GROUP_ACTIONS.post]);
          return deps.social.groups.createPost(input.envelope as SignedAction<CreatePostPayload>);
        }
      }),

      // ── feed.get ─────────────────────────────────────────────────────────
      action({
        name: 'social.feed.get',
        description: 'The authenticated caller\'s aggregated feed (group posts), newest first.',
        input: {
          limit: { type: 'integer', min: 1, max: 500, default: 50 },
          offset: { type: 'integer', min: 0, default: 0 }
        },
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          const items = await deps.social.feed.getFeed(identity.fingerprint, {
            limit: input.limit as number,
            offset: input.offset as number
          });
          return { items };
        }
      }),

      // ── feed.markRead ────────────────────────────────────────────────────
      action({
        name: 'social.feed.markRead',
        description:
          'Mark a feed source read for the authenticated caller up to a timestamp. ' +
          'The read marker is written through a signed `feed.mark.read` envelope ' +
          '(node-attested: the caller\'s key is never held by the node).',
        input: {
          source: {
            type: 'object',
            required: true,
            description: '{ kind: "group" | "conversation", id: string, name?: string }'
          },
          upTo: { type: 'integer', min: 1, description: 'Read-up-to timestamp; defaults to now' }
        },
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          const payload: MarkReadFeedPayload = {
            source: input.source as FeedSource,
            ...(input.upTo === undefined ? {} : { upTo: input.upTo as number })
          };
          const envelope = deps.social.signFor(identity, FEED_ACTIONS.markRead, payload);
          return deps.social.feed.markRead(envelope);
        }
      })
    ]
  };
}
