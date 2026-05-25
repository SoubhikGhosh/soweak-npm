# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — initial release

### Added

- Core abstractions: `Boundary`, `Severity`, `OwaspCategory`, `Payload`,
  `Context`, `Signal`, `Detector`, `Enforcer`, `Decision`, `Policy`,
  `PolicyBuilder`, `Pipeline`, `StreamingPipeline`, `AuditLog`,
  `SoweakError`, `ConfigurationError`.
- Detectors: prompt-injection, input/output DLP, system-prompt extraction,
  HTML, SQL, shell, canary, indirect-injection, tenant-isolation,
  provenance, retrieval-anomaly, citation-required, lexical grounding,
  embedding grounding, repetition, ML classifier (bring-your-own).
- Enforcers: `BlockEnforcer`, `RedactEnforcer`, `LogOnlyEnforcer`,
  `ThresholdEnforcer`, `TransformEnforcer`, `htmlSanitizerEnforcer`,
  `BudgetEnforcer`, `RateLimitEnforcer`.
- Output handling (LLM05): browser-safe `sanitizeHtml`, `URLAllowlist`,
  `isSafeSql`.
- Tool authorization (LLM06): `guardedTool`, `authorize`,
  `currentContext`, scope / approval / rate-limit / audit.
- Budgets and rate limits (LLM10): `TokenBudget`, `CostBudget`,
  `RateLimiter`, pluggable `CounterStore` / `WindowStore`.
- Storage backends: in-memory; file-backed via `soweak/node`.
- Audit log: `InMemoryAuditLog`, `CallbackAuditLog` (everywhere);
  `JsonLinesAuditLog` via `soweak/node`.
- Adapters: `SecureOpenAI`, `SecureAnthropic`, universal `secureFetch`.
- Declarative policies: `buildPolicy` (browser-safe JSON object),
  `loadPolicy` (via `soweak/node`, reads a file).
- LLM-as-judge: `llmJudgeClassifier`.
- ESM + CJS dual build with per-feature subpath exports and full
  `.d.ts` typings.
- Examples: 12 runnable Node scripts, React hook + chat component,
  Angular service + standalone component.

### Notes

- Node-only helpers (`JsonLinesAuditLog`, `FileCounterStore`,
  `FileWindowStore`, `loadPolicy`) are exposed under the `soweak/node`
  subpath import rather than the main entry, so the main path is
  browser-safe with no dynamic `require('fs')` calls.
- Request IDs use `crypto.randomUUID()` when available; falls back to a
  Date + Math.random composite for older runtimes.
- `Pipeline.arun` and `StreamingPipeline.guard` accept an `AbortSignal`
  for cooperative cancellation.
- `StreamingPipeline` caps its scan buffer at `maxBufferChars`
  (default 16 KiB) and slides on overflow.
