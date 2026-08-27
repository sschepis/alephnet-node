#!/usr/bin/env node
/**
 * AlephNet Node — CLI Entrypoint
 *
 *   node dist/node/bin.js --port 8080 --data ./data [--static ./public]
 *                        [--host 0.0.0.0] [--dev-auth-bypass]
 *
 * Optional secrets come from the environment:
 *   ALEPH_FAUCET_SECRET      faucet HMAC secret (>= 32 bytes)
 *   ALEPH_IDENTITY_PASSWORD  encrypts the persisted node identity
 *   OPENAI_API_KEY           reported in the banner; embedding features are
 *                            not part of this composition build
 *
 * Startup failures exit non-zero with a readable message — never a raw
 * stack trace. Signal handlers are registered exactly once per process and
 * shut the node down gracefully.
 */

// NOTE: `process` is used as the Node global on purpose. A namespace import
// (`import * as process from 'process'`) compiles under esModuleInterop to
// `__importStar(require('process'))`, which shallow-copies only OWN enumerable
// properties — silently dropping the EventEmitter prototype methods, so
// `process.once(...)` would throw "process.once is not a function" at runtime.
import { wholeTokens } from '../economy';
import { AlephNode } from './AlephNode';
import { AlephNodeStartupError } from './types';

// ═══════════════════════════════════════════════════════════════════════════
// ARGUMENTS
// ═══════════════════════════════════════════════════════════════════════════

interface CliOptions {
  readonly port?: number;
  readonly host?: string;
  readonly dataDir?: string;
  readonly staticPath?: string;
  readonly devAuthBypass: boolean;
  readonly help: boolean;
  readonly errors: readonly string[];
}

const USAGE = `Usage: alephnet-node [options]

Options:
  -h, --help            Show this help
  --port <n>            TCP port to bind (decimal integer, default: ephemeral)
  --host <address>      Bind address (default: 127.0.0.1)
  --data <dir>          Persistence directory (identity + social store)
  --static <dir>        Serve static files from this directory
  --dev-auth-bypass     DISABLE request authentication (development only;
                        refused under NODE_ENV=production)

Environment:
  ALEPH_FAUCET_SECRET       Faucet HMAC secret, >= 32 bytes
  ALEPH_IDENTITY_PASSWORD   Password encrypting the persisted node identity
  OPENAI_API_KEY            Reported in the startup banner only
`;

function readValue(argv: readonly string[], index: number, flag: string): string | null {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function parseArgs(argv: readonly string[]): CliOptions {
  const options: { port?: number; host?: string; dataDir?: string; staticPath?: string } = {};
  const errors: string[] = [];
  let devAuthBypass = false;
  let help = false;

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    try {
      switch (arg) {
        case '--help':
        case '-h':
          help = true;
          break;
        case '--dev-auth-bypass':
          devAuthBypass = true;
          break;
        case '--port': {
          const raw = readValue(argv, index, arg);
          if (raw !== null) {
            // `Number()` would happily accept '0x1A' (26), '1e2' (100) or
            // '' (0); the contract is a DECIMAL port, so only plain digits
            // are legal here.
            if (!/^[0-9]{1,5}$/.test(raw)) {
              throw new Error(
                `--port must be a decimal integer in [0, 65535], got ${JSON.stringify(raw)}`
              );
            }
            const port = Number.parseInt(raw, 10);
            if (!Number.isInteger(port) || port < 0 || port > 65_535) {
              throw new Error(`--port must be an integer in [0, 65535], got ${raw}`);
            }
            options.port = port;
            index += 1;
          }
          break;
        }
        case '--host': {
          const raw = readValue(argv, index, arg);
          if (raw !== null) {
            options.host = raw;
            index += 1;
          }
          break;
        }
        case '--data': {
          const raw = readValue(argv, index, arg);
          if (raw !== null) {
            options.dataDir = raw;
            index += 1;
          }
          break;
        }
        case '--static': {
          const raw = readValue(argv, index, arg);
          if (raw !== null) {
            options.staticPath = raw;
            index += 1;
          }
          break;
        }
        default:
          if (arg.startsWith('-')) {
            throw new Error(`unknown option: ${arg}`);
          }
          throw new Error(`unexpected argument: ${arg}`);
      }
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }

  return { ...options, devAuthBypass, help, errors };
}

// ═══════════════════════════════════════════════════════════════════════════
// BANNER
// ═══════════════════════════════════════════════════════════════════════════

function printBanner(node: AlephNode, cli: CliOptions): void {
  const status = node.getStatus();
  const lines: string[] = [
    '',
    '════════════════════════════════════════════════════════════════',
    '  AlephNet Node',
    '════════════════════════════════════════════════════════════════',
    `  node id     : ${status.nodeId}`,
    `  fingerprint : ${status.fingerprint}`,
    `  identity    : ${status.identityPersistent ? 'persistent (encrypted)' : 'EPHEMERAL (not persisted)'}`,
    `  http        : http://${cli.host ?? '127.0.0.1'}:${String(status.port)}`,
    `  actions     : ${String(status.counts.actions)}`,
    '',
    '  subsystems:'
  ];
  for (const subsystem of Object.values(status.subsystems)) {
    const state = subsystem.enabled ? 'enabled ' : 'DISABLED';
    const reason = subsystem.reason === null ? '' : ` — ${subsystem.reason}`;
    lines.push(`    [${state}] ${subsystem.name}${reason}`);
  }
  if (status.semantic.enabled) {
    lines.push(`    semantic kernel: ${status.semantic.degraded ? 'DEGRADED' : 'loaded'}`);
  }
  lines.push(
    '',
    `  OPENAI_API_KEY: ${process.env.OPENAI_API_KEY === undefined ? 'not set (embedding features are not part of this build)' : 'set'}`,
    '',
    '  press Ctrl-C to shut down gracefully',
    '════════════════════════════════════════════════════════════════',
    ''
  );
  process.stdout.write(lines.join('\n'));
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════

async function main(argv: readonly string[]): Promise<number> {
  const cli = parseArgs(argv);

  if (cli.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (cli.errors.length > 0) {
    for (const error of cli.errors) {
      process.stderr.write(`alephnet-node: ${error}\n`);
    }
    process.stderr.write(USAGE);
    return 2;
  }

  const faucetSecretRaw = process.env.ALEPH_FAUCET_SECRET;
  const faucetSecret =
    faucetSecretRaw === undefined || faucetSecretRaw.length === 0
      ? undefined
      : Buffer.from(faucetSecretRaw, 'utf8');
  const identityPassword = process.env.ALEPH_IDENTITY_PASSWORD;

  // ONE-TIME signal handlers (process.once): exactly one shutdown path per
  // process, however many nodes are composed. Registered BEFORE create()/
  // start() so an interrupt during startup still shuts down cleanly.
  let node: AlephNode | null = null;
  let shuttingDown = false;
  const onSignal = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    process.stderr.write(`alephnet-node: received ${signal}; shutting down gracefully\n`);

    const forceTimer = setTimeout(() => {
      process.stderr.write('alephnet-node: graceful shutdown timed out; exiting\n');
      process.exit(1);
    }, 15_000);
    forceTimer.unref();

    void (async () => {
      if (node !== null) {
        try {
          await node.stop();
        } catch (error: unknown) {
          process.stderr.write(
            `alephnet-node: shutdown failed: ${error instanceof Error ? error.message : String(error)}\n`
          );
          process.exit(1);
          return;
        }
      }
      process.exit(0);
    })();
  };
  process.once('SIGINT', () => onSignal('SIGINT'));
  process.once('SIGTERM', () => onSignal('SIGTERM'));

  // Startup failures exit non-zero with a READABLE message. The legacy
  // binary printed raw EADDRINUSE stack traces; `AlephNode.create()` and
  // `start()` raise typed errors instead.
  try {
    node = await AlephNode.create({
      port: cli.port ?? 0,
      host: cli.host ?? '127.0.0.1',
      dataDir: cli.dataDir,
      staticPath: cli.staticPath,
      devAuthBypass: cli.devAuthBypass,
      faucetSecret,
      identityPassword,
      treasuryCap: wholeTokens(1_000_000),
      semantic: { degradedOk: true }
    });
    await node.start();
  } catch (error) {
    const name = error instanceof AlephNodeStartupError ? error.name : 'startup';
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`alephnet-node: startup failed (${name}): ${message}\n`);
    return 1;
  }

  printBanner(node, cli);

  return 0;
}

void main(process.argv.slice(2)).then(
  (code) => {
    if (code !== 0) {
      process.exit(code);
    }
  },
  (error: unknown) => {
    process.stderr.write(
      `alephnet-node: fatal: ${error instanceof Error ? error.message : String(error)}\n`
    );
    process.exit(1);
  }
);
