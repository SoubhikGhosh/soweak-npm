/**
 * Generic `fetch` adapter — wraps `fetch` so request bodies hit the input
 * boundary and response bodies hit the output boundary.
 *
 * This is the universal adapter that works in browsers, Node 18+, Deno,
 * Bun, Workers, React, Angular — anywhere `fetch` exists. Use it when no
 * vendor-specific adapter ships (or to guard arbitrary REST/LLM endpoints).
 */

import { Pipeline } from "../core/pipeline.js";
import { Context, makeContext } from "../core/types.js";
import { Decision } from "../core/enforcer.js";
import { SecurityError } from "./errors.js";

export interface SecureFetchOptions {
  /** Function that pulls one or more input-text chunks out of the request body. */
  extractInputs?: (body: unknown) => Iterable<string>;
  /** Function that pulls one or more output-text chunks out of the response JSON. */
  extractOutputs?: (json: unknown) => Iterable<string>;
  /** Override the default `fetch`. */
  fetchImpl?: typeof fetch;
  /** Context to use for scanning; defaults to a fresh one per call. */
  context?: Context;
}

function defaultExtractInputs(body: unknown): string[] {
  if (typeof body === "string") {
    try {
      const parsed = JSON.parse(body);
      return walkStrings(parsed, ["content", "prompt", "input", "text", "messages"]);
    } catch {
      return [body];
    }
  }
  if (body instanceof Uint8Array) {
    try {
      return [new TextDecoder().decode(body)];
    } catch {
      return [];
    }
  }
  if (body && typeof body === "object") {
    return walkStrings(body, ["content", "prompt", "input", "text", "messages"]);
  }
  return [];
}

function defaultExtractOutputs(json: unknown): string[] {
  return walkStrings(json, ["content", "text", "output", "answer", "completion"]);
}

function walkStrings(value: unknown, keys: string[]): string[] {
  const out: string[] = [];
  const visit = (v: unknown): void => {
    if (typeof v === "string") {
      out.push(v);
      return;
    }
    if (Array.isArray(v)) {
      for (const item of v) visit(item);
      return;
    }
    if (v && typeof v === "object") {
      for (const k of keys) {
        if (k in (v as Record<string, unknown>)) visit((v as Record<string, unknown>)[k]);
      }
    }
  };
  visit(value);
  return out;
}

/**
 * Build a `fetch` wrapper that runs `pipeline` against request inputs and
 * (when the response is JSON) response outputs. Returns the original
 * Response object so callers can stream it, await `.text()`, etc.
 *
 * @example
 * ```ts
 * const safeFetch = secureFetch(pipeline);
 * const res = await safeFetch("https://api.openai.com/v1/chat/completions", {
 *   method: "POST",
 *   headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
 *   body: JSON.stringify({ model: "gpt-4o-mini", messages: [...] }),
 * });
 * ```
 */
export function secureFetch(pipeline: Pipeline, options: SecureFetchOptions = {}): typeof fetch {
  const f = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const extractInputs = options.extractInputs ?? defaultExtractInputs;
  const extractOutputs = options.extractOutputs ?? defaultExtractOutputs;

  return async function secureFetchWrapper(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    const ctx = options.context ?? makeContext();
    if (init?.body !== undefined && init?.body !== null) {
      for (const text of extractInputs(init.body)) {
        if (!text) continue;
        const decision = await pipeline.acheckInput(text, ctx);
        if (Decision.isBlocked(decision)) throw new SecurityError(decision);
      }
    }
    const response = await f(input, init);
    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) return response;

    // Clone so the caller can still read the body.
    const clone = response.clone();
    let parsed: unknown;
    try {
      parsed = await clone.json();
    } catch {
      return response;
    }
    for (const text of extractOutputs(parsed)) {
      if (!text) continue;
      const decision = await pipeline.acheckOutput(text, ctx);
      if (Decision.isBlocked(decision)) throw new SecurityError(decision);
    }
    return response;
  } as typeof fetch;
}
