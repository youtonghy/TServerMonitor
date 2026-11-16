// Entry point. Reads protocol messages from stdin, writes protocol messages to stdout.
import { createInterface } from 'node:readline';

import { type Inbound, log, send } from './protocol.js';
import { cancelRun, resolveToolResult, runTask } from './run.js';

// Keep stdout clean for the protocol: route stray console output to stderr.
console.log = (...args: unknown[]) => log(...args);
console.info = console.log;
console.warn = (...args: unknown[]) => log(...args);

const VERSION = '0.1.0';

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg: Inbound;
  try {
    msg = JSON.parse(line) as Inbound;
  } catch {
    log('ignoring malformed protocol line');
    return;
  }
  switch (msg.type) {
    case 'run':
      void runTask(msg);
      break;
    case 'tool_result':
      resolveToolResult(msg.run_id, msg.call_id, msg.output, msg.is_error);
      break;
    case 'cancel':
      cancelRun(msg.run_id);
      break;
    default:
      log('unknown message type');
  }
});

// Parent closed our stdin: the daemon is gone or wants us to stop.
rl.on('close', () => process.exit(0));

process.on('unhandledRejection', (e) => log('unhandled rejection:', e instanceof Error ? e.message : String(e)));

send({ type: 'ready', version: VERSION });
