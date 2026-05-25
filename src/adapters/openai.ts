/**
 * OpenAI adapter — wraps a v4-style `openai` client so every
 * `chat.completions.create` call has its input scanned at the input boundary
 * and (when not streamed) its output scanned at the output boundary.
 *
 * The `openai` package is a peer dependency — bring your own.
 */

import { Pipeline } from "../core/pipeline.js";
import { Context, makeContext } from "../core/types.js";
import { Decision } from "../core/enforcer.js";
import { SecurityError } from "./errors.js";

interface ChatCompletionMessage {
  role: string;
  content: string | Array<{ type: string; text?: string }> | null;
}

interface ChatCompletionCreateParams {
  messages: ChatCompletionMessage[];
  model: string;
  stream?: boolean;
  [k: string]: unknown;
}

interface OpenAILikeClient {
  chat: {
    completions: {
      create(params: ChatCompletionCreateParams): Promise<unknown>;
    };
  };
}

/**
 * Wraps an OpenAI client and applies a soweak Pipeline at I/O boundaries.
 *
 * @example
 * ```ts
 * import OpenAI from "openai";
 * import { SecureOpenAI } from "soweak/adapters/openai";
 *
 * const client = new SecureOpenAI(new OpenAI(), pipeline);
 * const resp = await client.chat.completions.create({
 *   model: "gpt-4o-mini",
 *   messages: [{ role: "user", content: "..." }],
 * });
 * ```
 */
export class SecureOpenAI {
  readonly chat: {
    completions: { create: (params: ChatCompletionCreateParams) => Promise<unknown> };
  };

  constructor(client: OpenAILikeClient, pipeline: Pipeline, context?: Context) {
    const ctx = context ?? makeContext();
    this.chat = {
      completions: {
        async create(params: ChatCompletionCreateParams): Promise<unknown> {
          for (const msg of params.messages) {
            const text = extractText(msg.content);
            for (const chunk of text) {
              const decision = await pipeline.acheckInput(chunk, ctx);
              if (Decision.isBlocked(decision)) throw new SecurityError(decision);
            }
          }
          const response = await client.chat.completions.create(params);
          if (params.stream) return response;
          const choices =
            (response as { choices?: Array<{ message?: { content?: string } }> }).choices ?? [];
          for (const choice of choices) {
            const content = choice.message?.content;
            if (typeof content === "string") {
              const decision = await pipeline.acheckOutput(content, ctx);
              if (Decision.isBlocked(decision)) throw new SecurityError(decision);
            }
          }
          return response;
        },
      },
    };
  }
}

function extractText(content: ChatCompletionMessage["content"]): string[] {
  if (content === null) return [];
  if (typeof content === "string") return [content];
  if (Array.isArray(content)) {
    const out: string[] = [];
    for (const part of content) {
      if (part.type === "text" && typeof part.text === "string") {
        out.push(part.text);
      }
    }
    return out;
  }
  return [];
}
