/**
 * Pipeline: executes a Policy against a Payload at a boundary.
 *
 * - sync surface: `run`, `checkInput`, `checkOutput`, `checkRetrieval`, `checkToolCall`
 * - async surface: `arun`, `acheckInput`, ...
 * - {@link StreamingPipeline} wraps any async iterable of chunks and re-runs
 *   the pipeline at `Boundary.STREAM` against a growing buffer.
 */

import { AuditEvent, AuditLog } from "./audit.js";
import { Signal } from "./detector.js";
import { Action, Decision } from "./enforcer.js";
import { SoweakError } from "./errors.js";
import { Policy } from "./policy.js";
import { Boundary, Context, makeContext, makePayload, Payload } from "./types.js";

export interface AsyncRunOptions {
  /** When set, aborting cancels the pipeline early with a thrown AbortError. */
  signal?: AbortSignal;
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) {
    const reason = (signal as { reason?: unknown }).reason ?? new SoweakError("operation aborted");
    if (reason instanceof Error) throw reason;
    throw new SoweakError(String(reason));
  }
}

export class Pipeline {
  readonly policy: Policy;
  readonly audit: AuditLog | null;

  constructor(policy: Policy, audit: AuditLog | null = null) {
    this.policy = policy;
    this.audit = audit;
  }

  run(payload: Payload, ctx?: Context | null): Decision {
    const context = ctx ?? makeContext();
    const boundary = payload.boundary;
    const rules = this.policy.forBoundary(boundary);
    const allSignals: Signal[] = [];

    if (rules.length === 0) {
      const decision = Decision.allow(payload);
      this.emit(context, boundary, allSignals, decision);
      return decision;
    }

    let lastDecision: Decision | null = null;
    let currentPayload = payload;
    for (const rule of rules) {
      const ruleSignals: Signal[] = [];
      for (const det of rule.detectors) {
        for (const s of det.inspect(currentPayload, context)) {
          ruleSignals.push(s);
        }
      }
      const decision = rule.enforcer.decide(currentPayload, ruleSignals, context);
      allSignals.push(...ruleSignals);
      currentPayload = decision.payload;
      lastDecision = decision;
      if (decision.action === Action.BLOCK) {
        break;
      }
    }

    const final: Decision = { ...lastDecision!, signals: [...allSignals] };
    this.emit(context, boundary, allSignals, final);
    return final;
  }

  async arun(
    payload: Payload,
    ctx?: Context | null,
    options: AsyncRunOptions = {},
  ): Promise<Decision> {
    const context = ctx ?? makeContext();
    const signal = options.signal;
    throwIfAborted(signal);
    const boundary = payload.boundary;
    const rules = this.policy.forBoundary(boundary);
    const allSignals: Signal[] = [];

    if (rules.length === 0) {
      const decision = Decision.allow(payload);
      await this.aemit(context, boundary, allSignals, decision);
      return decision;
    }

    let lastDecision: Decision | null = null;
    let currentPayload = payload;
    for (const rule of rules) {
      throwIfAborted(signal);
      const ruleSignals: Signal[] = [];
      for (const det of rule.detectors) {
        const sigs = await det.ainspect(currentPayload, context);
        ruleSignals.push(...sigs);
      }
      const decision = await rule.enforcer.adecide(currentPayload, ruleSignals, context);
      allSignals.push(...ruleSignals);
      currentPayload = decision.payload;
      lastDecision = decision;
      if (decision.action === Action.BLOCK) {
        break;
      }
    }

    const final: Decision = { ...lastDecision!, signals: [...allSignals] };
    await this.aemit(context, boundary, allSignals, final);
    return final;
  }

  // ----- ergonomic helpers -------------------------------------------------

  checkInput(text: string, ctx?: Context | null, metadata: Record<string, unknown> = {}): Decision {
    return this.run(makePayload(Boundary.INPUT, text, null, metadata), ctx);
  }

  checkOutput(
    text: string,
    ctx?: Context | null,
    metadata: Record<string, unknown> = {},
  ): Decision {
    return this.run(makePayload(Boundary.OUTPUT, text, null, metadata), ctx);
  }

  checkRetrieval(
    documents: unknown[],
    ctx?: Context | null,
    metadata: Record<string, unknown> = {},
  ): Decision {
    const joined = documents.map(docText).join("\n\n");
    return this.run(makePayload(Boundary.RETRIEVAL, joined, documents, metadata), ctx);
  }

  checkToolCall(
    tool: string,
    args: Record<string, unknown>,
    ctx?: Context | null,
    metadata: Record<string, unknown> = {},
  ): Decision {
    const text = `${tool}(${JSON.stringify(args)})`;
    return this.run(
      makePayload(Boundary.TOOL_CALL, text, { tool, arguments: args }, metadata),
      ctx,
    );
  }

  async acheckInput(
    text: string,
    ctx?: Context | null,
    options: AsyncRunOptions & { metadata?: Record<string, unknown> } = {},
  ): Promise<Decision> {
    return this.arun(makePayload(Boundary.INPUT, text, null, options.metadata ?? {}), ctx, options);
  }

  async acheckOutput(
    text: string,
    ctx?: Context | null,
    options: AsyncRunOptions & { metadata?: Record<string, unknown> } = {},
  ): Promise<Decision> {
    return this.arun(
      makePayload(Boundary.OUTPUT, text, null, options.metadata ?? {}),
      ctx,
      options,
    );
  }

  async acheckRetrieval(
    documents: unknown[],
    ctx?: Context | null,
    options: AsyncRunOptions & { metadata?: Record<string, unknown> } = {},
  ): Promise<Decision> {
    const joined = documents.map(docText).join("\n\n");
    return this.arun(
      makePayload(Boundary.RETRIEVAL, joined, documents, options.metadata ?? {}),
      ctx,
      options,
    );
  }

  async acheckToolCall(
    tool: string,
    args: Record<string, unknown>,
    ctx?: Context | null,
    options: AsyncRunOptions & { metadata?: Record<string, unknown> } = {},
  ): Promise<Decision> {
    const text = `${tool}(${JSON.stringify(args)})`;
    return this.arun(
      makePayload(Boundary.TOOL_CALL, text, { tool, arguments: args }, options.metadata ?? {}),
      ctx,
      options,
    );
  }

  private emit(ctx: Context, boundary: Boundary, signals: Signal[], decision: Decision): void {
    if (!this.audit) return;
    const event: AuditEvent = {
      requestId: ctx.requestId,
      boundary,
      signals: [...signals],
      decision,
      timestamp: new Date(),
    };
    this.audit.record(event);
  }

  private async aemit(
    ctx: Context,
    boundary: Boundary,
    signals: Signal[],
    decision: Decision,
  ): Promise<void> {
    if (!this.audit) return;
    const event: AuditEvent = {
      requestId: ctx.requestId,
      boundary,
      signals: [...signals],
      decision,
      timestamp: new Date(),
    };
    await this.audit.arecord(event);
  }
}

export function docText(doc: unknown): string {
  if (typeof doc === "string") return doc;
  if (doc && typeof doc === "object") {
    const d = doc as Record<string, unknown>;
    for (const key of ["text", "page_content", "content", "body"]) {
      const v = d[key];
      if (typeof v === "string") return v;
    }
    // LangChain-style class instances often have these as properties.
    if (typeof d["page_content"] === "string") return d["page_content"] as string;
    if (typeof d["text"] === "string") return d["text"] as string;
  }
  return String(doc);
}

// ---------------------------------------------------------------------------
// StreamingPipeline
// ---------------------------------------------------------------------------

import { SecurityError } from "../adapters/errors.js";

export interface StreamingPipelineOptions {
  scanEveryChars?: number;
  boundary?: Boundary;
  /**
   * Cap the total characters retained for scanning. Defaults to 16 KiB; once
   * exceeded, the oldest characters are dropped (sliding window). Prevents
   * a runaway-output stream from growing the buffer without bound.
   */
  maxBufferChars?: number;
}

/**
 * Guard an async iterable of text chunks (an LLM streaming response).
 *
 * Wraps a Pipeline and re-runs its STREAM (or fallback boundary) rules over
 * a growing buffer. On BLOCK, throws {@link SecurityError} and stops consuming
 * the source.
 */
export class StreamingPipeline {
  readonly pipeline: Pipeline;
  readonly scanEveryChars: number;
  readonly boundary: Boundary;
  readonly maxBufferChars: number;

  constructor(pipeline: Pipeline, options: StreamingPipelineOptions = {}) {
    this.pipeline = pipeline;
    this.scanEveryChars = options.scanEveryChars ?? 200;
    this.boundary = options.boundary ?? Boundary.STREAM;
    this.maxBufferChars = options.maxBufferChars ?? 16 * 1024;
    if (this.scanEveryChars <= 0) {
      throw new SoweakError("scanEveryChars must be positive");
    }
    if (this.maxBufferChars <= 0) {
      throw new SoweakError("maxBufferChars must be positive");
    }
  }

  async *guard(
    chunks: AsyncIterable<string>,
    ctx?: Context | null,
    options: AsyncRunOptions = {},
  ): AsyncIterable<string> {
    const context = ctx ?? makeContext();
    const signal = options.signal;
    let buffer = "";
    let lastScanLen = 0;
    let dropped = 0; // chars dropped from the head due to maxBufferChars
    for await (const chunk of chunks) {
      throwIfAborted(signal);
      if (!chunk) continue;
      buffer += chunk;
      if (buffer.length > this.maxBufferChars) {
        const drop = buffer.length - this.maxBufferChars;
        buffer = buffer.slice(drop);
        dropped += drop;
        lastScanLen = Math.max(0, lastScanLen - drop);
      }
      if (buffer.length - lastScanLen >= this.scanEveryChars) {
        const decision = await this.pipeline.arun(
          makePayload(this.boundary, buffer, { dropped }),
          context,
          options,
        );
        if (Decision.isBlocked(decision)) {
          throw new SecurityError(decision);
        }
        lastScanLen = buffer.length;
      }
      yield chunk;
    }
    if (buffer.length > lastScanLen) {
      throwIfAborted(signal);
      const decision = await this.pipeline.arun(
        makePayload(this.boundary, buffer, { dropped }),
        context,
        options,
      );
      if (Decision.isBlocked(decision)) {
        throw new SecurityError(decision);
      }
    }
  }
}
