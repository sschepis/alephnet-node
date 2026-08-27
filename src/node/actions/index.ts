/**
 * Action Module Assembly
 *
 * Builds every `ActionModule` from the node's subsystem bundle. This is the
 * single point where the domain layers meet the application layer's
 * `ActionRegistry` seam.
 */

import type { ActionModule } from '../../app';
import type { NodeSubsystems } from '../types';
import { createCoherenceActions } from './coherence';
import { createContentActions } from './content';
import { createFaucetActions, createWalletActions } from './economy';
import { createSemanticActions } from './semantic';
import { createSocialActions } from './social';

/**
 * All action modules for a running node, in registration order.
 */
export function createActionModules(subsystems: NodeSubsystems): readonly ActionModule[] {
  return [
    createSemanticActions({ semantic: subsystems.semantic }),
    createSocialActions({ social: subsystems.social }),
    createContentActions({ social: subsystems.social }),
    createWalletActions({ economy: subsystems.economy }),
    createFaucetActions({ economy: subsystems.economy }),
    createCoherenceActions({ coherence: subsystems.coherence, economy: subsystems.economy })
  ];
}
