/**
 * LLM06 — Excessive Agency: tool authorization framework.
 *
 * Couples three things to every tool call:
 *
 * 1. **Scopes** — the tool requires certain capability scopes; the caller's
 *    Context must grant them via `ctx.metadata.grantedScopes`.
 * 2. **Approval** — optionally requires a handler to return `true` (or a
 *    truthy Promise) before the underlying function runs.
 * 3. **Rate limit** — sliding-window cap on (tool, user) per N seconds.
 *
 * Wrap tool functions with `guardedTool`. At the call site, run them inside
 * an `authorize` callback. Calls outside an `authorize` block throw a
 * `PermissionError`.
 *
 * Works in Node, browsers, React, Angular, anywhere JS runs. JS is single-
 * threaded; we use a module-level "current context" stack rather than
 * Python's contextvars.
 */

import { Context } from "../core/types.js";
import { SoweakError } from "../core/errors.js";
import { InMemoryWindowStore, WindowStore } from "../storage/index.js";

export class PermissionError extends SoweakError {
  constructor(message: string) {
    super(message);
    this.name = "PermissionError";
    Object.setPrototypeOf(this, PermissionError.prototype);
  }
}

export class ApprovalRequired extends PermissionError {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalRequired";
    Object.setPrototypeOf(this, ApprovalRequired.prototype);
  }
}

export interface ToolCall {
  tool: string;
  arguments: Record<string, unknown>;
  scopes: readonly string[];
  userId: string | null;
  tenantId: string | null;
}

export interface ToolCallEvent {
  timestamp: Date;
  tool: string;
  arguments: Record<string, unknown>;
  scopes: readonly string[];
  decision: "allowed" | "denied_scope" | "denied_rate" | "denied_approval";
  userId: string | null;
  tenantId: string | null;
  reason: string;
}

export type ApprovalHandler = (call: ToolCall) => boolean | Promise<boolean>;

export const TOOL_AUDIT_KEY = "toolAuditCallback";
export const GRANTED_SCOPES_KEY = "grantedScopes";

// ---------------------------------------------------------------------------
// Active context — single-threaded JS, but async tasks may interleave.
// We model it as a stack so reentrant calls work.
// ---------------------------------------------------------------------------

const _contextStack: Context[] = [];

/**
 * Run `fn` with `ctx` as the active context for any guardedTool calls inside.
 * Supports both sync and async functions; async tasks chained inside the
 * callback inherit the context until they complete.
 */
export function authorize<T>(ctx: Context, fn: () => T): T;
export function authorize<T>(ctx: Context, fn: () => Promise<T>): Promise<T>;
export function authorize<T>(ctx: Context, fn: () => T | Promise<T>): T | Promise<T> {
  _contextStack.push(ctx);
  let popped = false;
  function pop(): void {
    if (popped) return;
    popped = true;
    const i = _contextStack.lastIndexOf(ctx);
    if (i >= 0) _contextStack.splice(i, 1);
  }
  try {
    const result = fn();
    if (result instanceof Promise) {
      return result.finally(pop);
    }
    pop();
    return result;
  } catch (e) {
    pop();
    throw e;
  }
}

export function currentContext(): Context | null {
  return _contextStack.length > 0 ? _contextStack[_contextStack.length - 1] : null;
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

class ToolRateLimiter {
  readonly limit: number;
  private readonly window: number;
  private readonly store: WindowStore;

  constructor(limit: number, store: WindowStore | null = null, windowSeconds = 60) {
    if (limit <= 0) throw new SoweakError("rate limit must be positive");
    if (windowSeconds <= 0) throw new SoweakError("windowSeconds must be positive");
    this.limit = limit;
    this.store = store ?? new InMemoryWindowStore();
    this.window = windowSeconds;
  }

  private key(tool: string, user: string): string {
    return `tool:${tool}:user:${user}`;
  }

  allow(tool: string, user: string): boolean {
    const now = Date.now() / 1000;
    const key = this.key(tool, user);
    if (this.store.count(key, now, this.window) >= this.limit) return false;
    const count = this.store.record(key, now, this.window);
    return count <= this.limit;
  }
}

// ---------------------------------------------------------------------------
// The wrapper
// ---------------------------------------------------------------------------

export interface GuardedToolOptions {
  scopes?: Iterable<string>;
  approval?: "auto" | "human";
  rateLimitPerMinute?: number;
  approvalHandler?: ApprovalHandler;
  rateLimitStore?: WindowStore;
  rateLimitWindowSeconds?: number;
}

// Intentionally permissive: guardedTool wraps any user function. Narrowing
// this further would break callers that pass non-standard signatures.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyFn = (...args: any[]) => any;

/**
 * Wrap `fn` so every call is gated by scope check, optional rate limit, and
 * optional human approval. Supports both sync and async functions.
 */
export function guardedTool<F extends AnyFn>(
  fn: F,
  options: GuardedToolOptions = {},
): F & { __soweakGuarded: true; __soweakScopes: ReadonlySet<string> } {
  const required = new Set(options.scopes ?? []);
  const approval = options.approval ?? "auto";
  if (approval !== "auto" && approval !== "human") {
    throw new SoweakError("approval must be 'auto' or 'human'");
  }
  const handler: ApprovalHandler = options.approvalHandler ?? (() => false);
  const limiter =
    options.rateLimitPerMinute && options.rateLimitPerMinute > 0
      ? new ToolRateLimiter(
          options.rateLimitPerMinute,
          options.rateLimitStore ?? null,
          options.rateLimitWindowSeconds ?? 60,
        )
      : null;
  const toolName = fn.name || "anonymous";

  const wrapper = function (...args: unknown[]) {
    const ctx = currentContext();
    if (ctx === null) {
      emit(null, toolName, args, "denied_scope", required, "no active context");
      throw new PermissionError(`tool ${toolName} called outside an authorize() block`);
    }

    const granted = new Set(
      (ctx.metadata[GRANTED_SCOPES_KEY] as Iterable<string> | undefined) ?? [],
    );
    const missing = [...required].filter((s) => !granted.has(s));
    if (missing.length > 0) {
      const reason = `missing scopes: ${JSON.stringify(missing.sort())}`;
      emit(ctx, toolName, args, "denied_scope", required, reason);
      throw new PermissionError(
        `tool ${toolName} requires ${JSON.stringify([...required].sort())}; missing ${JSON.stringify(missing.sort())}`,
      );
    }

    if (limiter !== null) {
      const user = ctx.userId ?? "anonymous";
      if (!limiter.allow(toolName, user)) {
        const reason = `rate limit ${limiter.limit}/min exceeded for user=${user}`;
        emit(ctx, toolName, args, "denied_rate", required, reason);
        throw new PermissionError(reason);
      }
    }

    if (approval === "human") {
      const call: ToolCall = {
        tool: toolName,
        arguments: { args },
        scopes: [...required].sort(),
        userId: ctx.userId ?? null,
        tenantId: ctx.tenantId ?? null,
      };
      const verdict = handler(call);
      if (verdict instanceof Promise) {
        return verdict.then((ok) => {
          if (!ok) {
            emit(ctx, toolName, args, "denied_approval", required, "approval rejected");
            throw new ApprovalRequired(`tool ${toolName} requires human approval`);
          }
          emit(ctx, toolName, args, "allowed", required, "");
          return fn(...args);
        });
      }
      if (!verdict) {
        emit(ctx, toolName, args, "denied_approval", required, "approval rejected");
        throw new ApprovalRequired(`tool ${toolName} requires human approval`);
      }
    }

    emit(ctx, toolName, args, "allowed", required, "");
    return fn(...args);
  } as unknown as F & { __soweakGuarded: true; __soweakScopes: ReadonlySet<string> };

  Object.defineProperty(wrapper, "__soweakGuarded", { value: true });
  Object.defineProperty(wrapper, "__soweakScopes", { value: required });
  Object.defineProperty(wrapper, "name", { value: toolName, configurable: true });
  return wrapper;
}

function emit(
  ctx: Context | null,
  tool: string,
  args: unknown[],
  decision: ToolCallEvent["decision"],
  scopes: ReadonlySet<string>,
  reason: string,
): void {
  if (!ctx) return;
  const cb = ctx.metadata[TOOL_AUDIT_KEY];
  if (typeof cb !== "function") return;
  const event: ToolCallEvent = {
    timestamp: new Date(),
    tool,
    arguments: { args },
    scopes: [...scopes].sort(),
    decision,
    userId: ctx.userId ?? null,
    tenantId: ctx.tenantId ?? null,
    reason,
  };
  (cb as (e: ToolCallEvent) => void)(event);
}
