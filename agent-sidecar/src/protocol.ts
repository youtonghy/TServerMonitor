// Newline-delimited JSON protocol between the Rust daemon (parent) and this sidecar.
// stdout is reserved for protocol messages; diagnostics go to stderr.

import type { JSONSchema7 } from 'ai';

export type ApiFormat = 'responses' | 'messages';

export interface ModelSpec {
  format: ApiFormat;
  base_url: string;
  model: string;
  /** Name of the env var that holds the key. The key itself never travels over the protocol. */
  api_key_env: string;
  auth: 'api_key' | 'bearer';
}

export interface ToolDef {
  name: string;
  description: string;
  input_schema: JSONSchema7;
}

export interface RunMessage {
  type: 'run';
  run_id: string;
  system: string;
  prompt: string;
  model: ModelSpec;
  max_steps: number;
  tools: ToolDef[];
  output_schema: JSONSchema7;
}

export interface ToolResultMessage {
  type: 'tool_result';
  run_id: string;
  call_id: string;
  output: unknown;
  is_error: boolean;
}

export type Inbound = RunMessage | ToolResultMessage | { type: 'cancel'; run_id: string };

export type Outbound =
  | { type: 'ready'; version: string }
  | { type: 'tool_call'; run_id: string; call_id: string; name: string; input: unknown }
  | { type: 'step'; run_id: string; text: string }
  | { type: 'result'; run_id: string; output: unknown; usage: unknown; mode: 'structured' | 'text' }
  | { type: 'error'; run_id: string; message: string };

export function send(msg: Outbound): void {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

export function log(...args: unknown[]): void {
  process.stderr.write(`${args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')}\n`);
}
