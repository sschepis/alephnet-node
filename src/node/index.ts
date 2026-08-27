/**
 * Node Layer — Barrel
 *
 * The composition layer that turns the domain layers into a runnable
 * AlephNet node. `AlephNode` is the entry point; the action module
 * factories are re-exported for hosts that want to compose the actions
 * into a custom registry.
 */

export { AlephNode } from './AlephNode';

export {
  createWalletTierResolver,
  StakingTierResolver,
  walletForAddress,
  type StakedBalanceReader,
  type StakingTierResolverOptions
} from './TierResolver';

export type {
  AlephNodeConfig,
  AlephNodeSemanticOptions,
  AlephNodeStatus,
  CoherenceSubsystem,
  EconomySubsystem,
  NodeCounts,
  NodeSubsystems,
  SemanticStatus,
  SemanticSubsystem,
  SocialSubsystem,
  SubsystemName,
  SubsystemStatus
} from './types';

export { AlephNodeStartupError } from './types';

export { createActionModules } from './actions';

export {
  createSemanticActions,
  type SemanticActionDeps
} from './actions/semantic';

export {
  createSocialActions,
  type SocialActionDeps
} from './actions/social';

export {
  createContentActions,
  type ContentActionDeps
} from './actions/content';

export {
  createCoherenceActions,
  type CoherenceActionDeps
} from './actions/coherence';

export {
  createEconomyActions,
  createFaucetActions,
  createWalletActions,
  type EconomyActionDeps
} from './actions/economy';

export {
  DomainActionError,
  action,
  bindEnvelope,
  requireActor,
  unavailable,
  type ActionFailure,
  type ActionResult,
  type ActionSuccess
} from './actions/helpers';
