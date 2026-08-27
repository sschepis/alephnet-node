/**
 * Content Actions
 *
 * `content.put` / `content.get` / `content.list`, wired to the social
 * layer's content-addressed `ContentStore`.
 *
 * `ContentStore` mutations are now SIGNED-ENVELOPE based: the store only
 * accepts a `SignedAction<PutContentPayload>` whose verified author IS the
 * owner. The node never holds client private keys, so it cannot sign the
 * envelope with the caller's key. Instead the node ATTESTS the envelope with
 * its own key after HTTP request authentication has already proved the
 * caller: `social.signFor(identity, 'content.put', payload)` builds an
 * envelope whose author fields carry `ctx.identity`, and the store's
 * verifier (a node-attested verifier) accepts it only for identities the
 * node itself recorded from authenticated requests. Ownership can therefore
 * never be claimed through an input field.
 *
 * Reads pass an explicit requester fingerprint, so visibility
 * (PUBLIC/FRIENDS/PRIVATE/UNLISTED) is enforced by the store itself.
 */

import type { ActionModule } from '../../app';
import type { SocialSubsystem } from '../types';
import type { ContentKind, PutContentPayload, Visibility } from '../../social';
import { AccessDeniedError, CONTENT_ACTIONS } from '../../social';
import { action, DomainActionError, requireActor } from './helpers';

// ═══════════════════════════════════════════════════════════════════════════
// DEPS
// ═══════════════════════════════════════════════════════════════════════════

export interface ContentActionDeps {
  readonly social: SocialSubsystem;
}

// ═══════════════════════════════════════════════════════════════════════════
// MODULE
// ═══════════════════════════════════════════════════════════════════════════

export function createContentActions(deps: ContentActionDeps): ActionModule {
  return {
    namespace: 'content',
    actions: [
      // ── put ──────────────────────────────────────────────────────────────
      action({
        name: 'content.put',
        description:
          'Store content (owner = the authenticated caller) and receive its 64-hex content address.',
        input: {
          content: { type: 'string', required: true, minLength: 1, maxLength: 1_048_576 },
          kind: { type: 'string', enum: ['text', 'json', 'markdown', 'html', 'binary'] },
          visibility: { type: 'string', enum: ['PUBLIC', 'FRIENDS', 'PRIVATE', 'UNLISTED'] },
          metadata: { type: 'object', description: 'Arbitrary JSON metadata' }
        },
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          // The HTTP contract stays the same (a content string plus optional
          // kind/visibility/metadata); it is mapped onto the new signed
          // `content.put` payload shape, with the owner taken from the
          // AUTHENTICATED caller.
          const payload: PutContentPayload = {
            content: input.content as string,
            ...(input.kind === undefined ? {} : { kind: input.kind as ContentKind }),
            ...(input.visibility === undefined ? {} : { visibility: input.visibility as Visibility }),
            ...(input.metadata === undefined ? {} : { metadata: input.metadata as Record<string, unknown> })
          };
          const envelope = deps.social.signFor(identity, CONTENT_ACTIONS.put, payload);
          return deps.social.content.put(envelope);
        }
      }),

      // ── get ──────────────────────────────────────────────────────────────
      action({
        name: 'content.get',
        description: 'Fetch content by hash as the authenticated caller; visibility is enforced.',
        input: {
          hash: { type: 'string', required: true, pattern: /^[0-9a-f]{64}$/, description: '64-hex content address' }
        },
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          try {
            const retrieved = await deps.social.content.get(input.hash as string, identity.fingerprint);
            if (retrieved === null) {
              return { found: false };
            }
            // Binary blobs are not JSON-safe; hand back base64 explicitly.
            const content =
              typeof retrieved.content === 'string'
                ? retrieved.content
                : (retrieved.content as Buffer).toString('base64');
            return {
              found: true,
              hash: retrieved.hash,
              content,
              ...(typeof retrieved.content === 'string' ? {} : { encoding: 'base64' }),
              kind: retrieved.kind,
              mimeType: retrieved.mimeType,
              size: retrieved.size,
              owner: retrieved.owner,
              visibility: retrieved.visibility,
              metadata: retrieved.metadata,
              createdAt: retrieved.createdAt
            };
          } catch (error) {
            if (error instanceof AccessDeniedError) {
              throw new DomainActionError('ACCESS_DENIED', error.message);
            }
            throw error;
          }
        }
      }),

      // ── list ─────────────────────────────────────────────────────────────
      action({
        name: 'content.list',
        description:
          'List one owner\'s content (default: the caller), filtered to what the caller may actually see.',
        input: {
          owner: { type: 'string', pattern: /^[0-9a-f]{16}$/, description: 'Owner fingerprint; defaults to the caller' },
          limit: { type: 'integer', min: 1, max: 500, default: 50 },
          offset: { type: 'integer', min: 0, default: 0 }
        },
        handler: async (input, ctx) => {
          const identity = requireActor(ctx);
          const owner = (input.owner as string | undefined) ?? identity.fingerprint;
          const items = await deps.social.content.list(owner, identity.fingerprint, {
            limit: input.limit as number,
            offset: input.offset as number
          });
          return { items };
        }
      })
    ]
  };
}
