import { generateText, isStepCount, jsonSchema, Output, streamText, tool, type ToolSet } from 'ai';

import { type RunMessage, send } from './protocol.js';
import { createModel, providerOptionsFor, reasoningFor } from './providers.js';

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

/** Abort handles of active runs, so a cancel stops the model call itself. */
const controllers = new Map<string, AbortController>();

export function cancelRun(runId: string): void {
  controllers.get(runId)?.abort(new Error('run cancelled'));
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

function buildTools(msg: RunMessage): ToolSet | undefined {
  if (msg.tools.length === 0) return undefined;
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

/** Relays often reject unknown parameters such as reasoning effort with HTTP 400. */
function isBadRequest(e: unknown): boolean {
  return (e as { statusCode?: number }).statusCode === 400 || /\b400\b/.test(errorMessage(e));
}

/**
 * Runs `fn` with the configured reasoning effort; if the endpoint rejects the request with 400,
 * retries once without it so a relay that does not understand the parameter still works.
 */
export async function withEffort<T>(
  effort: ReturnType<typeof reasoningFor>,
  fn: (reasoning: ReturnType<typeof reasoningFor>) => Promise<T>,
): Promise<T> {
  try {
    return await fn(effort);
  } catch (e) {
    if (!effort || !isBadRequest(e)) throw e;
    process.stderr.write(`request with reasoning=${effort} rejected (${errorMessage(e)}), retrying without it\n`);
    return fn(undefined);
  }
}

export async function runTask(msg: RunMessage): Promise<void> {
  const controller = new AbortController();
  controllers.set(msg.run_id, controller);
  try {
    if (msg.mode === 'chat') await runChat(msg, controller.signal);
    else await runStructured(msg, controller.signal);
  } catch (e) {
    send({ type: 'error', run_id: msg.run_id, message: controller.signal.aborted ? 'run cancelled' : errorMessage(e) });
  } finally {
    controllers.delete(msg.run_id);
  }
}

/** Free-text conversation: text deltas stream out as they arrive, tools work as in structured mode. */
async function runChat(msg: RunMessage, abortSignal: AbortSignal): Promise<void> {
  const runId = msg.run_id;
  const model = createModel(msg.model);
  const tools = buildTools(msg);
  const result = await withEffort(reasoningFor(msg.model), async (reasoning) => {
    const r = streamText({
      model,
      reasoning,
      system: msg.system,
      messages: msg.messages ?? [],
      tools,
      stopWhen: isStepCount(msg.max_steps),
      onStepEnd: (step: { text: string }) => {
        if (step.text?.trim()) send({ type: 'step', run_id: runId, text: step.text });
      },
      providerOptions: providerOptionsFor(msg.model, reasoning),
      maxRetries: 2,
      abortSignal,
    });
    for await (const part of r.stream) {
      if (part.type === 'text-delta' && part.text) send({ type: 'delta', run_id: runId, text: part.text });
      else if (part.type === 'error') throw part.error instanceof Error ? part.error : new Error(String(part.error));
    }
    return { text: await r.text, usage: await r.usage };
  });
  send({ type: 'result', run_id: runId, output: result.text, usage: result.usage, mode: 'chat' });
}

async function runStructured(msg: RunMessage, abortSignal: AbortSignal): Promise<void> {
  const runId = msg.run_id;
  const onStepFinish = (step: { text: string }) => {
    if (step.text?.trim()) send({ type: 'step', run_id: runId, text: step.text });
  };
  const schema = msg.output_schema ?? {};
  const model = createModel(msg.model);
  const tools = buildTools(msg);
  try {
    const result = await withEffort(reasoningFor(msg.model), (reasoning) => generateText({
      model,
      reasoning,
      system: msg.system,
      prompt: msg.prompt ?? '',
      tools,
      abortSignal,
      output: Output.object({ schema: jsonSchema(schema) }),
      // +1: producing the structured output is a step of its own
      stopWhen: isStepCount(msg.max_steps + 1),
      onStepFinish,
      providerOptions: providerOptionsFor(msg.model, reasoning),
      maxRetries: 2,
    }));
    send({ type: 'result', run_id: runId, output: result.output, usage: result.usage, mode: 'structured' });
    return;
  } catch (e) {
    if (!isStructuredOutputFailure(e)) throw e;
    process.stderr.write(`structured output failed (${errorMessage(e)}), retrying in text mode\n`);
  }

  // Text-mode fallback for endpoints without structured output support.
  const result = await withEffort(reasoningFor(msg.model), (reasoning) => generateText({
    model,
    reasoning,
    system: `${msg.system}\n\n最终回答只输出一个 JSON 对象，不要输出其他文字。JSON 必须符合以下 JSON Schema：\n${JSON.stringify(schema)}`,
    prompt: msg.prompt ?? '',
    tools,
    abortSignal,
    stopWhen: isStepCount(msg.max_steps + 1),
    onStepFinish,
    providerOptions: providerOptionsFor(msg.model, reasoning),
    maxRetries: 2,
  }));
  send({ type: 'result', run_id: runId, output: extractJson(result.text), usage: result.usage, mode: 'text' });
}
