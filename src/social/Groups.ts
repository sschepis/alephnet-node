/**
 * Groups — groups, membership, posts, reactions, comments
 *
 * Legacy flaws fixed here:
 *   - `createPost(groupId, { authorId })` trusted a caller-supplied `authorId`,
 *     and `authorId === 'system'` skipped the membership check entirely, so any
 *     caller could post as anybody. Here the author is ALWAYS the verified
 *     envelope author, and payloads that try to declare an author are rejected
 *     outright (`assertNoImpersonation`).
 *   - The default groups were owned by the magic string `'system'`, which is
 *     what made the bypass useful. Default groups are now created by a real
 *     signing identity (`ensureDefaultGroups`), so no privileged
 *     pseudo-identity exists at all.
 *   - Reactions/comments implicitly used the local node id; they are signed too.
 *   - Reads had no requester, so invisible/private group content leaked. Every
 *     read takes a requester fingerprint and enforces membership.
 */

import { sha256Hex } from '../common/crypto';
import { TIER_ORDER, type StakingTier } from '../common/types';
import type { ActionSigner, ActionVerifier, SignedAction, VerifiedAction } from './SignedAction';
import { assertNoImpersonation, signAction } from './SignedAction';
import type { SocialStore } from './SocialStore';
import { getRecord, listRecords, storeKey } from './SocialStore';
import {
  AccessDeniedError,
  Base64,
  ContentHash,
  Fingerprint,
  MediaRef,
  PageOptions,
  SocialError,
  Timestamp,
  assertContentHash,
  assertFingerprint,
  assertRecordId,
  assertText,
  systemClock,
  type SocialClock
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// ACTIONS & PAYLOADS
// ═══════════════════════════════════════════════════════════════════════════

export const GROUP_ACTIONS = {
  create: 'group.create',
  join: 'group.join',
  leave: 'group.leave',
  invite: 'group.invite',
  acceptInvite: 'group.invite.accept',
  revokeInvite: 'group.invite.revoke',
  removeMember: 'group.member.remove',
  promote: 'group.member.promote',
  post: 'group.post.create',
  deletePost: 'group.post.delete',
  react: 'group.post.react',
  unreact: 'group.post.unreact',
  comment: 'group.post.comment'
} as const;

/**
 * Group visibility.
 *   PUBLIC    — listed; anyone may join
 *   INVISIBLE — unlisted; anyone holding the id may join
 *   PRIVATE   — invitation only
 */
export type GroupVisibility = 'PUBLIC' | 'INVISIBLE' | 'PRIVATE';

const GROUP_VISIBILITIES: readonly GroupVisibility[] = ['PUBLIC', 'INVISIBLE', 'PRIVATE'];

export interface GroupRules {
  /** Minimum staking tier required to join, when a tier oracle is wired in. */
  minStakingTier?: StakingTier;
  /** Whether ordinary members may invite. Admins always may. */
  membersCanInvite: boolean;
  maxPostLength: number;
}

export interface CreateGroupPayload {
  name: string;
  description?: string;
  topic?: string;
  visibility?: GroupVisibility;
  avatarHash?: ContentHash | null;
  rules?: Partial<GroupRules>;
}

export interface GroupIdPayload {
  groupId: string;
}

export interface InvitePayload {
  groupId: string;
  invitee: Fingerprint;
  /** Time to live in ms. Defaults to 24h, hard-capped at 30 days. */
  ttlMs?: number;
}

export interface AcceptGroupInvitePayload {
  inviteId: string;
}

export interface InviteIdPayload {
  inviteId: string;
}

export interface MemberPayload {
  groupId: string;
  member: Fingerprint;
}

export interface CreatePostPayload {
  groupId: string;
  content: string;
  media?: MediaRef[];
}

export interface PostIdPayload {
  groupId: string;
  postId: string;
}

export interface ReactPayload extends PostIdPayload {
  reaction: string;
}

export interface CommentPayload extends PostIdPayload {
  content: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// RECORDS
// ═══════════════════════════════════════════════════════════════════════════

export interface GroupRecord {
  id: string;
  name: string;
  description: string;
  topic: string;
  /** Verified fingerprint of the creator. Never the string 'system'. */
  ownerFingerprint: Fingerprint;
  visibility: GroupVisibility;
  avatarHash: ContentHash | null;
  members: Fingerprint[];
  admins: Fingerprint[];
  banned: Fingerprint[];
  rules: GroupRules;
  createdAt: Timestamp;
  updatedAt: Timestamp;
  postCount: number;
}

export interface GroupCommentRecord {
  id: string;
  authorFingerprint: Fingerprint;
  content: string;
  timestamp: Timestamp;
  signature: Base64;
}

export interface GroupPostRecord {
  id: string;
  groupId: string;
  /** Verified author, derived from the signature — never from the payload. */
  authorFingerprint: Fingerprint;
  authorPub: Base64;
  content: string;
  media: MediaRef[];
  timestamp: Timestamp;
  /** Signature over the post envelope, so authorship stays provable at rest. */
  signature: Base64;
  editedAt: Timestamp | null;
  deletedAt: Timestamp | null;
  reactions: Record<Fingerprint, string>;
  comments: GroupCommentRecord[];
}

export interface GroupInviteRecord {
  id: string;
  groupId: string;
  invitedBy: Fingerprint;
  invitee: Fingerprint;
  createdAt: Timestamp;
  expiresAt: Timestamp;
  acceptedAt: Timestamp | null;
  revokedAt: Timestamp | null;
  signature: Base64;
}

/**
 * A group as shown to a NON-member requester. Member/admin/banned lists are
 * stripped so PUBLIC groups do not disclose their membership to strangers.
 */
export type GroupPublicView = Omit<GroupRecord, 'members' | 'admins' | 'banned'>;

export class GroupsError extends SocialError {}

/** Optional staking-tier source for tier-gated groups. */
export interface StakingTierOracle {
  getTier(fingerprint: Fingerprint): Promise<StakingTier>;
}

// ═══════════════════════════════════════════════════════════════════════════
// KEYS & LIMITS
// ═══════════════════════════════════════════════════════════════════════════

const K_GROUP = 'group';
const K_POST = 'grouppost';
const K_INVITE = 'groupinvite';

const groupKey = (id: string): string => storeKey(K_GROUP, assertRecordId(id, 'groupId'));
const postKey = (groupId: string, postId: string): string =>
  storeKey(K_POST, assertRecordId(groupId, 'groupId'), assertRecordId(postId, 'postId'));
const postPrefix = (groupId: string): string => `${K_POST}/${assertRecordId(groupId, 'groupId')}/`;
const inviteKey = (id: string): string => storeKey(K_INVITE, assertRecordId(id, 'inviteId'));

export const GROUP_LIMITS = {
  name: 120,
  description: 1000,
  topic: 64,
  post: 5000,
  comment: 2000,
  reaction: 32,
  maxMedia: 10
} as const;

export const DEFAULT_GROUP_RULES: GroupRules = {
  membersCanInvite: true,
  maxPostLength: GROUP_LIMITS.post
};

const DEFAULT_INVITE_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_INVITE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** Groups created by `ensureDefaultGroups`. */
export const DEFAULT_GROUP_SEEDS: readonly CreateGroupPayload[] = [
  {
    name: 'Public Square',
    description: 'The default public gathering place for all agents.',
    topic: 'General',
    visibility: 'PUBLIC'
  },
  {
    name: 'Announcements',
    description: 'New public groups and system updates.',
    topic: 'System',
    visibility: 'PUBLIC'
  }
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUPS
// ═══════════════════════════════════════════════════════════════════════════

export interface GroupsOptions {
  store: SocialStore;
  verifier: ActionVerifier;
  clock?: SocialClock;
  tiers?: StakingTierOracle;
}

export interface PostQuery extends PageOptions {
  /** Only posts strictly older than this timestamp. */
  before?: Timestamp;
  /** Only posts strictly newer than this timestamp. */
  after?: Timestamp;
  includeDeleted?: boolean;
}

export class Groups {
  private readonly store: SocialStore;
  private readonly verifier: ActionVerifier;
  private readonly clock: SocialClock;
  private readonly tiers?: StakingTierOracle;

  constructor(options: GroupsOptions) {
    this.store = options.store;
    this.verifier = options.verifier;
    this.clock = options.clock ?? systemClock;
    this.tiers = options.tiers;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Group lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  /** Create a group owned by the verified author. */
  async createGroup(envelope: SignedAction<CreateGroupPayload>): Promise<GroupRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.create);
    const payload = verified.payload ?? ({} as CreateGroupPayload);
    const owner = verified.author.fingerprint;
    const now = this.clock();

    const record: GroupRecord = {
      id: `grp_${sha256Hex(`group.create|${verified.signature}`).slice(0, 24)}`,
      name: assertText(payload.name, 'name', GROUP_LIMITS.name),
      description: payload.description
        ? assertText(payload.description, 'description', GROUP_LIMITS.description, {
            allowEmpty: true
          })
        : '',
      topic: payload.topic ? assertText(payload.topic, 'topic', GROUP_LIMITS.topic) : '',
      ownerFingerprint: owner,
      visibility: requireGroupVisibility(payload.visibility ?? 'PUBLIC'),
      avatarHash: payload.avatarHash ? assertContentHash(payload.avatarHash, 'avatarHash') : null,
      members: [owner],
      admins: [owner],
      banned: [],
      rules: {
        ...DEFAULT_GROUP_RULES,
        ...(payload.rules ?? {}),
        maxPostLength: Math.min(
          payload.rules?.maxPostLength ?? GROUP_LIMITS.post,
          GROUP_LIMITS.post
        )
      },
      createdAt: now,
      updatedAt: now,
      postCount: 0
    };

    await this.store.put(groupKey(record.id), record);
    return record;
  }

  /**
   * Create the conventional starter groups, owned by a REAL signing identity.
   * The legacy version used `ownerId: 'system'` — the very pseudo-identity that
   * made impersonation exploitable.
   */
  async ensureDefaultGroups(signer: ActionSigner): Promise<GroupRecord[]> {
    const existing = await this.allGroups();
    const created: GroupRecord[] = [];
    for (const seed of DEFAULT_GROUP_SEEDS) {
      if (existing.some((group) => group.name === seed.name)) continue;
      const envelope = signAction(GROUP_ACTIONS.create, seed, signer, { clock: this.clock });
      created.push(await this.createGroup(envelope));
    }
    return created;
  }

  /** Join a PUBLIC or INVISIBLE group. PRIVATE groups require an invitation. */
  async joinGroup(envelope: SignedAction<GroupIdPayload>): Promise<GroupRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.join);
    const group = await this.requireGroup(verified.payload?.groupId);
    const joiner = verified.author.fingerprint;

    if (group.banned.includes(joiner)) {
      throw new AccessDeniedError('You are banned from this group', { groupId: group.id });
    }
    if (group.visibility === 'PRIVATE') {
      throw new AccessDeniedError('This group is invitation only', { groupId: group.id });
    }
    await this.assertTier(group, joiner);

    if (!group.members.includes(joiner)) {
      group.members.push(joiner);
      group.updatedAt = this.clock();
      await this.store.put(groupKey(group.id), group);
    }
    return group;
  }

  /** Leave a group. The owner cannot leave. */
  async leaveGroup(envelope: SignedAction<GroupIdPayload>): Promise<GroupRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.leave);
    const group = await this.requireGroup(verified.payload?.groupId);
    const member = verified.author.fingerprint;
    if (member === group.ownerFingerprint) {
      throw new GroupsError('owner_cannot_leave', 'The group owner cannot leave the group');
    }
    group.members = group.members.filter((m) => m !== member);
    group.admins = group.admins.filter((m) => m !== member);
    group.updatedAt = this.clock();
    await this.store.put(groupKey(group.id), group);
    return group;
  }

  /** Invite somebody. Admins always may; members only if the rules allow. */
  async invite(envelope: SignedAction<InvitePayload>): Promise<GroupInviteRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.invite);
    const group = await this.requireGroup(verified.payload?.groupId);
    const inviter = verified.author.fingerprint;
    const invitee = assertFingerprint(verified.payload?.invitee, 'invitee');

    if (!group.members.includes(inviter)) {
      throw new AccessDeniedError('Only members may invite to this group');
    }
    if (!group.admins.includes(inviter) && !group.rules.membersCanInvite) {
      throw new AccessDeniedError('Only admins may invite to this group');
    }
    if (group.banned.includes(invitee)) {
      throw new GroupsError('banned', 'That fingerprint is banned from this group');
    }

    const record: GroupInviteRecord = {
      id: `ginv_${sha256Hex(`group.invite|${verified.signature}`).slice(0, 24)}`,
      groupId: group.id,
      invitedBy: inviter,
      invitee,
      createdAt: verified.timestamp,
      expiresAt: verified.timestamp + clampTtl(verified.payload?.ttlMs),
      acceptedAt: null,
      revokedAt: null,
      signature: verified.signature
    };
    await this.store.put(inviteKey(record.id), record);
    return record;
  }

  /**
   * Accept a group invitation. Expiry is ENFORCED here — the legacy layer set
   * `expiresAt` and then never looked at it again.
   */
  async acceptInvite(envelope: SignedAction<AcceptGroupInvitePayload>): Promise<GroupRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.acceptInvite);
    const inviteId = assertRecordId(verified.payload?.inviteId, 'inviteId');
    const invite = await getRecord<GroupInviteRecord>(this.store, inviteKey(inviteId));
    if (!invite) {
      throw new GroupsError('unknown_invite', 'No such invitation', { inviteId });
    }
    if (invite.invitee !== verified.author.fingerprint) {
      throw new AccessDeniedError('This invitation was issued to a different fingerprint');
    }
    if (invite.revokedAt !== null) {
      throw new GroupsError('invite_revoked', 'This invitation has been revoked');
    }
    if (invite.acceptedAt !== null) {
      throw new GroupsError('invite_used', 'This invitation has already been accepted');
    }
    if (this.clock() >= invite.expiresAt) {
      throw new GroupsError('invite_expired', 'This invitation has expired', {
        expiresAt: invite.expiresAt
      });
    }

    const group = await this.requireGroup(invite.groupId);
    if (group.banned.includes(invite.invitee)) {
      throw new AccessDeniedError('You are banned from this group');
    }
    await this.assertTier(group, invite.invitee);

    if (!group.members.includes(invite.invitee)) {
      group.members.push(invite.invitee);
      group.updatedAt = this.clock();
      await this.store.put(groupKey(group.id), group);
    }
    invite.acceptedAt = this.clock();
    await this.store.put(inviteKey(invite.id), invite);
    return group;
  }

  /** Revoke a group invitation. The issuer or a group admin may revoke. */
  async revokeInvite(envelope: SignedAction<InviteIdPayload>): Promise<GroupInviteRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.revokeInvite);
    const inviteId = assertRecordId(verified.payload?.inviteId, 'inviteId');
    const invite = await getRecord<GroupInviteRecord>(this.store, inviteKey(inviteId));
    if (!invite) {
      throw new GroupsError('unknown_invite', 'No such invitation', { inviteId });
    }
    const group = await this.requireGroup(invite.groupId);
    const actor = verified.author.fingerprint;
    if (invite.invitedBy !== actor && !group.admins.includes(actor)) {
      throw new AccessDeniedError('Only the issuer or a group admin may revoke this invitation');
    }
    invite.revokedAt = this.clock();
    await this.store.put(inviteKey(invite.id), invite);
    return invite;
  }

  /** Remove (and ban) a member. Admins only; the owner is untouchable. */
  async removeMember(envelope: SignedAction<MemberPayload>): Promise<GroupRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.removeMember);
    const group = await this.requireGroup(verified.payload?.groupId);
    const actor = verified.author.fingerprint;
    const member = assertFingerprint(verified.payload?.member, 'member');

    if (!group.admins.includes(actor)) {
      throw new AccessDeniedError('Only admins may remove members');
    }
    if (member === group.ownerFingerprint) {
      throw new GroupsError('owner_protected', 'The group owner cannot be removed');
    }

    group.members = group.members.filter((m) => m !== member);
    group.admins = group.admins.filter((m) => m !== member);
    if (!group.banned.includes(member)) group.banned.push(member);
    group.updatedAt = this.clock();
    await this.store.put(groupKey(group.id), group);
    return group;
  }

  /** Promote a member to admin. Admins only. */
  async promoteMember(envelope: SignedAction<MemberPayload>): Promise<GroupRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.promote);
    const group = await this.requireGroup(verified.payload?.groupId);
    const actor = verified.author.fingerprint;
    const member = assertFingerprint(verified.payload?.member, 'member');

    if (!group.admins.includes(actor)) {
      throw new AccessDeniedError('Only admins may promote members');
    }
    if (!group.members.includes(member)) {
      throw new GroupsError('not_a_member', 'That fingerprint is not a member of this group');
    }
    if (!group.admins.includes(member)) {
      group.admins.push(member);
      group.updatedAt = this.clock();
      await this.store.put(groupKey(group.id), group);
    }
    return group;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Posts, reactions, comments
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Create a post. The author is the verified signer and membership is
   * enforced against THAT fingerprint — there is no 'system' escape hatch.
   */
  async createPost(envelope: SignedAction<CreatePostPayload>): Promise<GroupPostRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.post);
    const group = await this.requireGroup(verified.payload?.groupId);
    const author = verified.author.fingerprint;

    this.assertMember(group, author, 'post in');

    const content = assertText(verified.payload?.content, 'content', group.rules.maxPostLength);
    const media = normalizeMedia(verified.payload?.media);

    const post: GroupPostRecord = {
      id: `post_${sha256Hex(`group.post|${verified.signature}`).slice(0, 24)}`,
      groupId: group.id,
      authorFingerprint: author,
      authorPub: verified.author.pub,
      content,
      media,
      timestamp: verified.timestamp,
      signature: verified.signature,
      editedAt: null,
      deletedAt: null,
      reactions: {},
      comments: []
    };

    await this.store.put(postKey(group.id, post.id), post);
    group.postCount += 1;
    group.updatedAt = this.clock();
    await this.store.put(groupKey(group.id), group);
    return post;
  }

  /** Soft-delete a post. The author or a group admin may do this. */
  async deletePost(envelope: SignedAction<PostIdPayload>): Promise<GroupPostRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.deletePost);
    const group = await this.requireGroup(verified.payload?.groupId);
    const post = await this.requirePost(group.id, verified.payload?.postId);
    const actor = verified.author.fingerprint;

    if (post.authorFingerprint !== actor && !group.admins.includes(actor)) {
      throw new AccessDeniedError('Only the author or a group admin may delete this post');
    }
    post.deletedAt = this.clock();
    post.content = '[deleted]';
    post.media = [];
    await this.store.put(postKey(group.id, post.id), post);
    return post;
  }

  /** React to a post. Members only; the reactor is the verified author. */
  async addReaction(envelope: SignedAction<ReactPayload>): Promise<GroupPostRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.react);
    const group = await this.requireGroup(verified.payload?.groupId);
    const actor = verified.author.fingerprint;
    this.assertMember(group, actor, 'react in');

    const post = await this.requirePost(group.id, verified.payload?.postId);
    post.reactions[actor] = assertText(
      verified.payload?.reaction,
      'reaction',
      GROUP_LIMITS.reaction
    );
    await this.store.put(postKey(group.id, post.id), post);
    return post;
  }

  /** Remove your own reaction. Members only. */
  async removeReaction(envelope: SignedAction<PostIdPayload>): Promise<GroupPostRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.unreact);
    const group = await this.requireGroup(verified.payload?.groupId);
    const actor = verified.author.fingerprint;
    this.assertMember(group, actor, 'remove reactions in');

    const post = await this.requirePost(group.id, verified.payload?.postId);
    delete post.reactions[actor];
    await this.store.put(postKey(group.id, post.id), post);
    return post;
  }

  /** Comment on a post. Members only; the commenter is the verified author. */
  async addComment(envelope: SignedAction<CommentPayload>): Promise<GroupCommentRecord> {
    const verified = await this.verify(envelope, GROUP_ACTIONS.comment);
    const group = await this.requireGroup(verified.payload?.groupId);
    const actor = verified.author.fingerprint;
    this.assertMember(group, actor, 'comment in');

    const post = await this.requirePost(group.id, verified.payload?.postId);
    const comment: GroupCommentRecord = {
      id: `cmt_${sha256Hex(`group.comment|${verified.signature}`).slice(0, 20)}`,
      authorFingerprint: actor,
      content: assertText(verified.payload?.content, 'content', GROUP_LIMITS.comment),
      timestamp: verified.timestamp,
      signature: verified.signature
    };
    post.comments.push(comment);
    await this.store.put(postKey(group.id, post.id), post);
    return comment;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Reads — requester is always explicit
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * A group, if `requester` may see it. Members receive the full record;
   * non-members of PUBLIC groups receive a `GroupPublicView` with the
   * member/admin/banned lists stripped.
   */
  async getGroup(
    groupId: string,
    requester: Fingerprint
  ): Promise<GroupRecord | GroupPublicView | null> {
    assertFingerprint(requester, 'requester');
    const group = await getRecord<GroupRecord>(this.store, groupKey(groupId));
    if (!group) return null;
    if (!this.canSeeGroup(group, requester)) return null;
    if (group.members.includes(requester)) return group;
    return publicGroupView(group);
  }

  /** Groups `requester` may see: public ones plus their own memberships. */
  async listGroups(requester: Fingerprint): Promise<Array<GroupRecord | GroupPublicView>> {
    assertFingerprint(requester, 'requester');
    const groups = await this.allGroups();
    return groups
      .filter((group) => this.canSeeGroup(group, requester))
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .map((group) => (group.members.includes(requester) ? group : publicGroupView(group)));
  }

  /** Groups `requester` is a member of. */
  async listMemberships(requester: Fingerprint): Promise<GroupRecord[]> {
    assertFingerprint(requester, 'requester');
    const groups = await this.allGroups();
    return groups.filter((group) => group.members.includes(requester));
  }

  /** Posts in a group, newest first, if `requester` may read them. */
  async getPosts(
    groupId: string,
    requester: Fingerprint,
    query: PostQuery = {}
  ): Promise<GroupPostRecord[]> {
    assertFingerprint(requester, 'requester');
    const group = await this.requireGroup(groupId);
    if (!this.canReadPosts(group, requester)) {
      throw new AccessDeniedError('You cannot read posts in this group', { groupId: group.id });
    }
    return this.readPosts(group, { ...query, limit: query.limit ?? 50 });
  }

  /**
   * All posts from groups `requester` may read (their memberships plus public
   * groups), newest first. Used by the feed.
   *
   * Pagination operates on the FULL union across groups: every post of every
   * readable group is loaded (no per-group truncation) and then
   * `before`/`after`/`offset`/`limit` are applied to the merged list, so
   * pages beyond the first 50 posts of any one group remain reachable.
   */
  async getAllPosts(requester: Fingerprint, query: PostQuery = {}): Promise<GroupPostRecord[]> {
    assertFingerprint(requester, 'requester');
    const groups = await this.allGroups();
    const readable = groups.filter(
      (group) => !group.banned.includes(requester) && this.canReadPosts(group, requester)
    );
    const collected: GroupPostRecord[] = [];
    for (const group of readable) {
      collected.push(...(await this.readPosts(group, { includeDeleted: false })));
    }
    let posts = collected;
    if (query.before !== undefined) posts = posts.filter((post) => post.timestamp < query.before!);
    if (query.after !== undefined) posts = posts.filter((post) => post.timestamp > query.after!);
    posts.sort((a, b) => b.timestamp - a.timestamp);
    const offset = query.offset ?? 0;
    const limit = query.limit ?? 50;
    return posts.slice(offset, offset + limit);
  }

  /** One post, if `requester` may read the group. */
  async getPost(
    groupId: string,
    postId: string,
    requester: Fingerprint
  ): Promise<GroupPostRecord | null> {
    assertFingerprint(requester, 'requester');
    const group = await this.requireGroup(groupId);
    if (!this.canReadPosts(group, requester)) {
      throw new AccessDeniedError('You cannot read posts in this group', { groupId: group.id });
    }
    return getRecord<GroupPostRecord>(this.store, postKey(group.id, postId));
  }

  /** Pending invitations addressed to `requester`. */
  async getInvites(requester: Fingerprint): Promise<GroupInviteRecord[]> {
    assertFingerprint(requester, 'requester');
    const invites = await listRecords<GroupInviteRecord>(this.store, `${K_INVITE}/`);
    const now = this.clock();
    return invites.filter(
      (invite) =>
        invite.invitee === requester &&
        invite.acceptedAt === null &&
        invite.revokedAt === null &&
        invite.expiresAt > now
    );
  }

  /** Whether `fingerprint` is a member of `groupId`. */
  async isMember(groupId: string, fingerprint: Fingerprint): Promise<boolean> {
    const group = await getRecord<GroupRecord>(this.store, groupKey(groupId));
    return group ? group.members.includes(fingerprint) : false;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Internals
  // ─────────────────────────────────────────────────────────────────────────

  private async verify<P>(envelope: SignedAction<P>, action: string): Promise<VerifiedAction<P>> {
    const verified = await this.verifier.verify(envelope, action);
    // Reject payloads that try to name their own author ('system', someone
    // else's fingerprint, ...) instead of silently ignoring them.
    assertNoImpersonation(action, verified.payload);
    return verified;
  }

  private async allGroups(): Promise<GroupRecord[]> {
    return listRecords<GroupRecord>(this.store, `${K_GROUP}/`);
  }

  private async requireGroup(groupId: unknown): Promise<GroupRecord> {
    const id = assertRecordId(groupId, 'groupId');
    const group = await getRecord<GroupRecord>(this.store, groupKey(id));
    if (!group) throw new GroupsError('unknown_group', 'No such group', { groupId: id });
    return group;
  }

  private async requirePost(groupId: string, postId: unknown): Promise<GroupPostRecord> {
    const id = assertRecordId(postId, 'postId');
    const post = await getRecord<GroupPostRecord>(this.store, postKey(groupId, id));
    if (!post) throw new GroupsError('unknown_post', 'No such post', { postId: id });
    return post;
  }

  /**
   * Shared pagination/filtering for post reads. `limit === undefined` means
   * "no cap" — used by feed aggregation so the pagination happens on the
   * merged union, not per group.
   */
  private async readPosts(group: GroupRecord, query: PostQuery): Promise<GroupPostRecord[]> {
    let posts = await listRecords<GroupPostRecord>(this.store, postPrefix(group.id));
    if (!query.includeDeleted) posts = posts.filter((post) => post.deletedAt === null);
    if (query.before !== undefined) posts = posts.filter((post) => post.timestamp < query.before!);
    if (query.after !== undefined) posts = posts.filter((post) => post.timestamp > query.after!);
    posts.sort((a, b) => b.timestamp - a.timestamp);
    const offset = query.offset ?? 0;
    if (query.limit === undefined) return posts.slice(offset);
    return posts.slice(offset, offset + query.limit);
  }

  private assertMember(group: GroupRecord, actor: Fingerprint, verb: string): void {
    if (group.banned.includes(actor)) {
      throw new AccessDeniedError(`You are banned from this group`, { groupId: group.id });
    }
    if (!group.members.includes(actor)) {
      throw new AccessDeniedError(`You must be a member to ${verb} this group`, {
        groupId: group.id,
        actor
      });
    }
  }

  private canSeeGroup(group: GroupRecord, requester: Fingerprint): boolean {
    if (group.visibility === 'PUBLIC') return true;
    return group.members.includes(requester);
  }

  private canReadPosts(group: GroupRecord, requester: Fingerprint): boolean {
    if (group.banned.includes(requester)) return false;
    if (group.members.includes(requester)) return true;
    // Public groups are readable without joining; everything else is not.
    return group.visibility === 'PUBLIC';
  }

  /** Fail closed when a tier is required but no oracle can vouch for it. */
  private async assertTier(group: GroupRecord, candidate: Fingerprint): Promise<void> {
    const required = group.rules.minStakingTier;
    if (!required) return;
    if (!this.tiers) {
      throw new AccessDeniedError(
        'This group requires a staking tier but no tier oracle is configured',
        { groupId: group.id, required }
      );
    }
    const actual = await this.tiers.getTier(candidate);
    if (TIER_ORDER.indexOf(actual) < TIER_ORDER.indexOf(required)) {
      throw new AccessDeniedError(`This group requires staking tier ${required}`, {
        groupId: group.id,
        required,
        actual
      });
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function requireGroupVisibility(value: unknown): GroupVisibility {
  const upper = typeof value === 'string' ? value.toUpperCase() : '';
  if (!(GROUP_VISIBILITIES as readonly string[]).includes(upper)) {
    throw new GroupsError(
      'invalid_visibility',
      'Group visibility must be one of PUBLIC|INVISIBLE|PRIVATE'
    );
  }
  return upper as GroupVisibility;
}

/** Strip membership data from a group before showing it to a non-member. */
function publicGroupView(group: GroupRecord): GroupPublicView {
  return {
    id: group.id,
    name: group.name,
    description: group.description,
    topic: group.topic,
    ownerFingerprint: group.ownerFingerprint,
    visibility: group.visibility,
    avatarHash: group.avatarHash,
    rules: group.rules,
    createdAt: group.createdAt,
    updatedAt: group.updatedAt,
    postCount: group.postCount
  };
}

function clampTtl(ttlMs: unknown): number {
  if (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs <= 0) {
    return DEFAULT_INVITE_TTL_MS;
  }
  return Math.min(Math.trunc(ttlMs), MAX_INVITE_TTL_MS);
}

function normalizeMedia(media: unknown): MediaRef[] {
  if (media === undefined || media === null) return [];
  if (!Array.isArray(media)) {
    throw new GroupsError('invalid_media', 'media must be an array');
  }
  if (media.length > GROUP_LIMITS.maxMedia) {
    throw new GroupsError('invalid_media', `At most ${GROUP_LIMITS.maxMedia} media items per post`);
  }
  return media.map((item) => {
    const ref = item as Partial<MediaRef>;
    return {
      type: assertText(ref.type, 'media.type', 32),
      hash: assertContentHash(ref.hash, 'media.hash'),
      mimeType: ref.mimeType ? assertText(ref.mimeType, 'media.mimeType', 128) : undefined,
      metadata: (ref.metadata as Record<string, unknown> | undefined) ?? undefined
    };
  });
}
