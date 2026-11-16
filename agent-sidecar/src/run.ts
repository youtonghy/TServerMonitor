import { generateText, isStepCount, jsonSchema, Output, tool, type ToolSet } from 'ai';

import { type RunMessage, send } from './protocol.js';
import { createModel, providerOptions } from './providers.js';

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void };

/** Tool calls waiting for the Rust daemon, keyed by `${run_id}:${call_id}`. */
const pending = new Map<string, Pending>();
let callSeq = 0;

export function resolveToolResult(runId: string, callId: string, output: unknown, isError: boolean): void {
  const key = `${runId}:${callId}`;
  const p = pending.get(key);
  if (!p) return;
  pending.delete(key);
  // tool errors go back to the model as data so it can adjust its next call
  p.resolve(isError ? { error: true, detail: output } : output);
}

export function cancelRun(runId: string): void {
  for (const [key, p] of pending) {
    if (key.startsWith(`${runId}:`)) {
      pending.delete(key);
      p.reject(new Error('run cancelled'));
    }
  }
}

function callRust(runId: string, name: string, input: unknown): Promise<unknown> {
  const callId = `c${++callSeq}`;
  return new Promise((resolve, reject) => {
    pending.set(`${runId}:${callId}`, { resolve, reject });
    send({ type: 'tool_call', run_id: runId, call_id: callId, name, input });
  });
}

function buildTools(msg: RunMessage): ToolSet {
  const tools: ToolSet = {};
  for (const def of msg.tools) {
    tools[def.name] = tool({
      description: def.description,
      inputSchema: jsonSchema<Record<string, unknown>>(def.input_schema),
      execute: async (input) => callRust(msg.run_id, def.name, input),
    });
  }
  return tools;
}

/** Extracts the first JSON object from model text (tolerates ```json fences and chatter). */
export function extractJson(text: string): unknown {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(text);
  const body = fenced?.[1] ?? text;
  const start = body.indexOf('{');
  const end = body.lastIndexOf('}');
  if (start < 0 || end <= start) {
    throw new Error('model did not return a JSON object');
  }
  return JSON.parse(body.slice(start, end + 1));
}

function errorMessage(e: unknown): string {
  if (e instanceof Error) {
    const cause = (e as { cause?: unknown }).cause;
    const status = (e as { statusCode?: number }).statusCode;
    const parts = [e.message];
    if (status) parts.push(`(HTTP ${status})`);
    if (cause instanceof Error && cause.message !== e.message) parts.push(`cause: ${cause.message}`);
    return parts.join(' ').slice(0, 1000);
  }
  return String(e).slice(0, 1000);
}

/** Errors that mean "this endpoint cannot do structured output", worth a text-mode retry. */
function isStructuredOutputFailure(e: unknown): boolean {
  const name = e instanceof Error ? e.name : '';
  const msg = errorMessage(e).toLowerCase();
  return (
    name.includes('NoObjectGenerated') ||
    name.includes('NoOutputGenerated') ||
    name.includes('TypeValidation') ||
    name.includes('JSONParse') ||
    msg.includes('json_schema') ||
    msg.includes('response_format') ||
    msg.includes('output_format') ||
    msg.includes('structured')
  );
}

export async function runTask(msg: RunMessage): Promise<void> {
  const runId = msg.run_id;
  const onStepFinish = (step: { text: string }) => {
    if (step.text?.trim()) send({ type: 'step', run_id: runId, text: step.text });
  };
  try {
    const model = createModel(msg.model);
    const tools = buildTools(msg);
    try {
      const result = await generateText({
        model,
        system: msg.system,
        prompt: msg.prompt,
        tools,
        output: Output.object({ schema: jsonSchema(msg.output_schema) }),
        // +1: producing the structured output is a step of its own
        stopWhen: isStepCount(msg.max_steps + 1),
        onStepFinish,
        providerOptions,
        maxRetries: 2,
      });
      send({ type: 'result', run_id: runId, output: result.output, usage: result.totalUsage, mode: 'structured' });
      return;
    } catch (e) {
      if (!isStructuredOutputFailure(e)) throw e;
      process.stderr.write(`structured output failed (${errorMessage(e)}), retrying in text mode\n`);
    }

    // Text-mode fallback for endpoints without structured output support.
    const result = await generateText({
      model,
      system: `${msg.system}\n\n最终回答只输出一个 JSON 对象，不要输出其他文字。JSON 必须符合以下 JSON Schema：\n${JSON.stringify(msg.output_schema)}`,
      prompt: msg.prompt,
      tools,
      stopWhen: isStepCount(msg.max_steps + 1),
      onStepFinish,
      providerOptions,
      maxRetries: 2,
    });
    send({ type: 'result', run_id: runId, output: extractJson(result.text), usage: result.totalUsage, mode: 'text' });
  } catch (e) {
    send({ type: 'error', run_id: runId, message: errorMessage(e) });
  }
}
