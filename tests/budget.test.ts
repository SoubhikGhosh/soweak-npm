import { describe, expect, it } from "vitest";
import {
  BudgetEnforcer,
  BudgetExceededError,
  CostBudget,
  Decision,
  Pipeline,
  PolicyBuilder,
  RateLimitEnforcer,
  RateLimiter,
  TokenBudget,
  makeContext,
} from "../src/index.js";

describe("TokenBudget", () => {
  it("charges and tracks remaining", () => {
    const budget = new TokenBudget({ limit: 1000 });
    expect(budget.consumed("alice")).toBe(0);
    expect(budget.charge("alice", 100)).toBe(100);
    expect(budget.remaining("alice")).toBe(900);
  });

  it("throws when over limit", () => {
    const budget = new TokenBudget({ limit: 100 });
    budget.charge("alice", 90);
    expect(() => budget.charge("alice", 20)).toThrow(BudgetExceededError);
    // No partial charge.
    expect(budget.consumed("alice")).toBe(90);
  });
});

describe("CostBudget", () => {
  it("charges based on pricing", () => {
    const budget = new CostBudget({ limitUsd: 1.0 });
    const cost = budget.charge("alice", "gpt-4o-mini", 10000, 5000);
    expect(cost).toBeGreaterThan(0);
    expect(cost).toBeLessThan(0.01);
  });
});

describe("BudgetEnforcer", () => {
  it("blocks when budget exhausted", () => {
    const budget = new TokenBudget({ limit: 10 });
    budget.charge("alice", 10);
    const pipeline = new Pipeline(
      new PolicyBuilder().onInput().enforce(new BudgetEnforcer(budget)).build(),
    );
    const d = pipeline.checkInput("anything", makeContext({ userId: "alice" }));
    expect(Decision.isBlocked(d)).toBe(true);
  });
});

describe("RateLimiter", () => {
  it("allows up to limit then blocks", () => {
    const rl = new RateLimiter({ requestsPerMinute: 2 });
    expect(rl.allow("alice")).toBe(true);
    expect(rl.allow("alice")).toBe(true);
    expect(rl.allow("alice")).toBe(false);
  });

  it("RateLimitEnforcer blocks via Pipeline", () => {
    const pipeline = new Pipeline(
      new PolicyBuilder()
        .onInput()
        .enforce(new RateLimitEnforcer({ requestsPerMinute: 1 }))
        .build(),
    );
    const ctx = makeContext({ userId: "alice" });
    expect(pipeline.checkInput("a", ctx).action).not.toBe("block");
    expect(Decision.isBlocked(pipeline.checkInput("b", ctx))).toBe(true);
  });
});
