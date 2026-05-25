/**
 * Anthropic adapter — wraps an `@anthropic-ai/sdk` client.
 */

import { Pipeline } from "../core/pipeline.js";
import { Context, makeContext } from "../core/types.js";
import { Decision } from "../core/enforcer.js";
import { SecurityError } from "./errors.js";

interface AnthropicMessage {
  role: string;
  content: string | Array<{ type: string; text?: string }>;
}

interface MessagesCreateParams {
  messages: AnthropicMessage[];
  model: string;
  max_tokens: number;
  system?: string | Array<{ type: string; text?: string }>;
  stream?: boolean;
  [k: string]: unknown;
}

interface AnthropicLikeClient {
  messages: {
    create(params: MessagesCreateParams): Promise<unknown>;
  };
}

export class SecureAnthropic {
  readonly messages: { create: (params: MessagesCreateParams) => Promise<unknown> };

  constructor(client: AnthropicLikeClient, pipeline: Pipeline, context?: Context) {
    const ctx = context ?? makeContext();
    this.messages = {
      async create(params: MessagesCreateParams): Promise<unknown> {
        for (const msg of params.messages) {
          for (const text of extractText(msg.content)) {
            const decision = await pipeline.acheckInput(text, ctx);
            if (Decision.isBlocked(decision)) throw new SecurityError(decision);
          }
        }
        const response = await client.messages.create(params);
        if (params.stream) return response;
        const content =
          (response as { content?: Array<{ type: string; text?: string }> }).content ?? [];
        for (const block of content) {
          if (block.type === "text" && typeof block.text === "string") {
            const decision = await pipeline.acheckOutput(block.text, ctx);
            if (Decision.isBlocked(decision)) throw new SecurityError(decision);
          }
        }
        return response;
      },
    };
  }
}

function extractText(content: AnthropicMessage["content"]): string[] {
  if (typeof content === "string") return [content];
  if (Array.isArray(content)) {
    const out: string[] = [];
    for (const block of content) {
      if (block.type === "text" && typeof block.text === "string") {
        out.push(block.text);
      }
    }
    return out;
  }
  return [];
}
