/**
 * Token / cost budgets and rate limits (LLM10 — Unbounded Consumption).
 *
 * The pre-call BudgetEnforcer blocks when the scope is already exhausted.
 * After the LLM call returns, you call `budget.charge(...)` with the actual
 * usage.
 */

import {
  BudgetEnforcer,
  BudgetExceededError,
  CostBudget,
  Decision,
  Pipeline,
  PolicyBuilder,
  RateLimitEnforcer,
  TokenBudget,
  makeContext,
} from "../../src/index.js";
import { FileCounterStore } from "../../src/node/index.js";

// In-memory by default. For multi-process persistence, pass a FileCounterStore
// — or implement your own CounterStore subclass against Redis.
const tokens = new TokenBudget({
  limit: 100_000,
  store: new FileCounterStore("/tmp/soweak-token-budget.json"),
});
const cost = new CostBudget({ limitUsd: 5.0 });

const pipeline = new Pipeline(
  new PolicyBuilder()
    .onInput("rate-limit")
    .enforce(new RateLimitEnforcer({ requestsPerMinute: 30 }))
    .onInput("budget-gate")
    .enforce(new BudgetEnforcer(tokens, { scopeAttr: "userId" }))
    .build(),
);

const ctx = makeContext({ userId: "alice" });
const decision = pipeline.checkInput("explain quantum computing", ctx);
console.log("pre-call decision:", decision.action);

if (!Decision.isBlocked(decision)) {
  // Pretend we just called the model and got a response.
  const usage = { promptTokens: 25, completionTokens: 380 };
  tokens.charge("alice", usage.promptTokens + usage.completionTokens);
  cost.charge("alice", "gpt-4o-mini", usage.promptTokens, usage.completionTokens);
  console.log("remaining tokens:", tokens.remaining("alice"));
  console.log("spent USD:", cost.consumed("alice").toFixed(4));
}

try {
  tokens.charge("alice", 999_999_999);
} catch (e) {
  if (e instanceof BudgetExceededError) {
    console.log("blocked at hard limit:", e.message);
  }
}
