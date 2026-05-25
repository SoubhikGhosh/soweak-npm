/**
 * LLM10 — Unbounded Consumption: token / cost budgets and rate limits.
 *
 * Instantiate once per scope (per-process, per-user, per-tenant) and call
 * `charge` from the call site that actually consumes tokens (after the LLM
 * call returns).
 */

import { Signal } from "../core/detector.js";
import { Action, Decision, Enforcer, makeDecision } from "../core/enforcer.js";
import { SoweakError } from "../core/errors.js";
import { Context, Payload } from "../core/types.js";
import {
  CounterStore,
  InMemoryCounterStore,
  InMemoryWindowStore,
  WindowStore,
} from "../storage/index.js";

export interface Budget {
  readonly name: string;
  consumed(scope: string): number;
  remaining(scope: string): number;
  reset(scope?: string | null): void;
}

export class BudgetExceededError extends SoweakError {
  readonly budgetName: string;
  readonly scope: string;
  readonly limit: number;
  readonly attempted: number;

  constructor(budgetName: string, scope: string, limit: number, attempted: number) {
    super(
      `budget ${JSON.stringify(budgetName)} exceeded for scope ${JSON.stringify(
        scope,
      )}: attempted ${attempted}, limit ${limit}`,
    );
    this.name = "BudgetExceededError";
    this.budgetName = budgetName;
    this.scope = scope;
    this.limit = limit;
    this.attempted = attempted;
    Object.setPrototypeOf(this, BudgetExceededError.prototype);
  }
}

export class TokenBudget implements Budget {
  readonly name: string;
  readonly limit: number;
  readonly store: CounterStore;

  constructor(options: { limit: number; name?: string; store?: CounterStore }) {
    if (options.limit <= 0) throw new SoweakError("limit must be positive");
    this.limit = options.limit;
    this.name = options.name ?? "token-budget";
    this.store = options.store ?? new InMemoryCounterStore();
  }

  private key(scope: string): string {
    return `${this.name}:${scope}`;
  }

  charge(scope: string, tokens: number): number {
    if (tokens < 0) throw new SoweakError("tokens must be non-negative");
    const next = this.store.add(this.key(scope), tokens, this.limit);
    if (next === null) {
      const attempted = this.store.get(this.key(scope)) + tokens;
      throw new BudgetExceededError(this.name, scope, this.limit, attempted);
    }
    return next;
  }

  consumed(scope: string): number {
    return this.store.get(this.key(scope));
  }

  remaining(scope: string): number {
    return Math.max(0, this.limit - this.consumed(scope));
  }

  reset(scope: string | null = null): void {
    if (scope === null) this.store.reset();
    else this.store.reset(this.key(scope));
  }
}

export interface ModelPricing {
  inputPer1k: number;
  outputPer1k: number;
}

export const DEFAULT_PRICING: Record<string, ModelPricing> = {
  "gpt-4o": { inputPer1k: 0.005, outputPer1k: 0.015 },
  "gpt-4o-mini": { inputPer1k: 0.00015, outputPer1k: 0.0006 },
  "claude-sonnet-4-5": { inputPer1k: 0.003, outputPer1k: 0.015 },
  "claude-haiku-4-5": { inputPer1k: 0.0008, outputPer1k: 0.004 },
  "gemini-1.5-pro": { inputPer1k: 0.0035, outputPer1k: 0.0105 },
  "gemini-1.5-flash": { inputPer1k: 0.000075, outputPer1k: 0.0003 },
};

export class CostBudget implements Budget {
  readonly name: string;
  readonly limit: number;
  readonly store: CounterStore;
  private pricing: Record<string, ModelPricing>;

  constructor(options: {
    limitUsd: number;
    pricing?: Record<string, ModelPricing>;
    name?: string;
    store?: CounterStore;
  }) {
    if (options.limitUsd <= 0) throw new SoweakError("limitUsd must be positive");
    this.limit = options.limitUsd;
    this.name = options.name ?? "cost-budget";
    this.pricing = options.pricing ? { ...options.pricing } : { ...DEFAULT_PRICING };
    this.store = options.store ?? new InMemoryCounterStore();
  }

  registerPricing(model: string, pricing: ModelPricing): void {
    this.pricing[model] = pricing;
  }

  private key(scope: string): string {
    return `${this.name}:${scope}`;
  }

  private costOf(model: string, inputTokens: number, outputTokens: number): number {
    const rate = this.pricing[model];
    if (!rate) {
      throw new SoweakError(
        `no pricing registered for model ${JSON.stringify(model)}; call registerPricing()`,
      );
    }
    return (inputTokens / 1000) * rate.inputPer1k + (outputTokens / 1000) * rate.outputPer1k;
  }

  charge(scope: string, model: string, inputTokens: number, outputTokens: number): number {
    const cost = this.costOf(model, inputTokens, outputTokens);
    const next = this.store.add(this.key(scope), cost, this.limit);
    if (next === null) {
      const attempted = this.store.get(this.key(scope)) + cost;
      throw new BudgetExceededError(this.name, scope, this.limit, attempted);
    }
    return next;
  }

  consumed(scope: string): number {
    return this.store.get(this.key(scope));
  }

  remaining(scope: string): number {
    return Math.max(0, this.limit - this.consumed(scope));
  }

  reset(scope: string | null = null): void {
    if (scope === null) this.store.reset();
    else this.store.reset(this.key(scope));
  }
}

export class BudgetEnforcer extends Enforcer {
  private readonly _budget: Budget;
  private readonly _scopeAttr: keyof Context;
  private readonly _name: string;

  constructor(budget: Budget, options: { scopeAttr?: keyof Context; name?: string } = {}) {
    super();
    this._budget = budget;
    this._scopeAttr = options.scopeAttr ?? "userId";
    this._name = options.name ?? `budget[${budget.name}]`;
  }

  get name(): string {
    return this._name;
  }

  decide(payload: Payload, signals: Signal[], ctx: Context): Decision {
    const rawScope = (ctx as unknown as Record<string, unknown>)[this._scopeAttr as string];
    const scope = typeof rawScope === "string" && rawScope ? rawScope : "default";
    const remaining = this._budget.remaining(scope);
    if (remaining <= 0) {
      return makeDecision({
        action: Action.BLOCK,
        payload,
        signals: [...signals],
        reason: `budget ${JSON.stringify(this._budget.name)} exhausted for ${JSON.stringify(scope)}`,
        metadata: { budget: this._budget.name, scope, remaining },
      });
    }
    if (signals.length > 0) {
      return makeDecision({ action: Action.WARN, payload, signals: [...signals] });
    }
    return Decision.allow(payload);
  }
}

export class RateLimiter {
  readonly limit: number;
  private readonly window: number;
  readonly store: WindowStore;

  constructor(options: { requestsPerMinute: number; store?: WindowStore; windowSeconds?: number }) {
    if (options.requestsPerMinute <= 0) throw new SoweakError("requestsPerMinute must be positive");
    const windowSeconds = options.windowSeconds ?? 60;
    if (windowSeconds <= 0) throw new SoweakError("windowSeconds must be positive");
    this.limit = options.requestsPerMinute;
    this.window = windowSeconds;
    this.store = options.store ?? new InMemoryWindowStore();
  }

  allow(scope: string): boolean {
    const now = Date.now() / 1000;
    if (this.store.count(scope, now, this.window) >= this.limit) return false;
    const count = this.store.record(scope, now, this.window);
    return count <= this.limit;
  }
}

export class RateLimitEnforcer extends Enforcer {
  private readonly _limiter: RateLimiter;
  private readonly _scopeAttr: keyof Context;
  private readonly _name: string;

  constructor(options: {
    requestsPerMinute: number;
    scopeAttr?: keyof Context;
    name?: string;
    store?: WindowStore;
    windowSeconds?: number;
  }) {
    super();
    this._limiter = new RateLimiter({
      requestsPerMinute: options.requestsPerMinute,
      store: options.store,
      windowSeconds: options.windowSeconds,
    });
    this._scopeAttr = options.scopeAttr ?? "userId";
    this._name = options.name ?? "rate-limit";
  }

  get name(): string {
    return this._name;
  }

  get limit(): number {
    return this._limiter.limit;
  }

  decide(payload: Payload, signals: Signal[], ctx: Context): Decision {
    const rawScope = (ctx as unknown as Record<string, unknown>)[this._scopeAttr as string];
    const scope = typeof rawScope === "string" && rawScope ? rawScope : "default";
    if (!this._limiter.allow(scope)) {
      return makeDecision({
        action: Action.BLOCK,
        payload,
        signals: [...signals],
        reason: `rate limit ${this._limiter.limit}/min exceeded for ${JSON.stringify(scope)}`,
      });
    }
    if (signals.length > 0) {
      return makeDecision({ action: Action.WARN, payload, signals: [...signals] });
    }
    return Decision.allow(payload);
  }
}
