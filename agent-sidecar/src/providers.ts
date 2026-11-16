import { createAnthropic } from '@ai-sdk/anthropic';
import { createOpenAI } from '@ai-sdk/openai';
import type { LanguageModel } from 'ai';

import type { ModelSpec } from './protocol.js';

/**
 * Builds a model for any endpoint that speaks one of two wire formats:
 * - `responses`: OpenAI Responses API, POST {base_url}/responses
 * - `messages`:  Anthropic Messages API, POST {base_url}/messages
 */
export function createModel(spec: ModelSpec): LanguageModel {
  const apiKey = process.env[spec.api_key_env];
  if (!apiKey) {
    throw new Error(`environment variable ${spec.api_key_env} is not set`);
  }
  const baseURL = spec.base_url.replace(/\/+$/, '');
  switch (spec.format) {
    case 'responses':
      return createOpenAI({ apiKey, baseURL }).responses(spec.model);
    case 'messages':
      return spec.auth === 'bearer'
        ? createAnthropic({ authToken: apiKey, baseURL })(spec.model)
        : createAnthropic({ apiKey, baseURL })(spec.model);
    default: {
      const never: never = spec.format;
      throw new Error(`unsupported api format ${String(never)}`);
    }
  }
}

/** Provider options that keep requests stateless and portable across relays. */
export const providerOptions = {
  openai: { store: false, parallelToolCalls: false },
};
