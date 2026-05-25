/**
 * soweak — OWASP LLM Top 10 security middleware framework.
 *
 * Defense at every boundary of an LLM pipeline: input, retrieval, tool call,
 * output, streaming. Wire it into OpenAI, Anthropic, LangChain, or any
 * fetch-based LLM endpoint. Works in Node, browsers, React, Angular,
 * React Native — anywhere ES2020 runs.
 *
 * Quick start:
 * ```ts
 * import {
 *   Pipeline,
 *   PolicyBuilder,
 *   BlockEnforcer,
 *   Severity,
 *   promptInjectionDetector,
 *   inputDlpDetector,
 * } from "soweak";
 *
 * const policy = new PolicyBuilder()
 *   .onInput("prompt-injection")
 *     .detect(promptInjectionDetector(), inputDlpDetector())
 *     .enforce(new BlockEnforcer({ minSeverity: Severity.HIGH }))
 *   .build();
 *
 * const pipeline = new Pipeline(policy);
 * const decision = pipeline.checkInput("Ignore all previous instructions and ...");
 * if (Decision.isBlocked(decision)) { ... }
 * ```
 */

export const VERSION = "0.1.0";

// core
export {
  Boundary,
  OwaspCategory,
  Severity,
  severityFromLabel,
  severityLabel,
  severityWeight,
  makeContext,
  makePayload,
} from "./core/types.js";
export type { Context, Payload } from "./core/types.js";
export { Detector, makeSignal } from "./core/detector.js";
export type { Signal } from "./core/detector.js";
export { Action, Decision, Enforcer, makeDecision } from "./core/enforcer.js";
export { Policy, PolicyBuilder } from "./core/policy.js";
export type { Rule } from "./core/policy.js";
export {
  AuditLog,
  CallbackAuditLog,
  InMemoryAuditLog,
  auditEventToDict,
  auditEventToJson,
} from "./core/audit.js";
export type { AuditEvent } from "./core/audit.js";
export { ConfigurationError, SoweakError } from "./core/errors.js";
export { Pipeline, StreamingPipeline, docText } from "./core/pipeline.js";
export type { AsyncRunOptions, StreamingPipelineOptions } from "./core/pipeline.js";

// detectors
export {
  CanaryDetector,
  PatternMatchDetector,
  INPUT_DLP_PACK,
  OUTPUT_DLP_PACK,
  OUTPUT_HTML_PACK,
  OUTPUT_SHELL_PACK,
  OUTPUT_SQL_PACK,
  PROMPT_INJECTION_PACK,
  SYSTEM_PROMPT_EXTRACTION_PACK,
  inputDlpDetector,
  outputDlpDetector,
  outputHtmlDetector,
  outputShellDetector,
  outputSqlDetector,
  promptInjectionDetector,
  systemPromptExtractionDetector,
  makePack,
  makePattern,
} from "./detectors/index.js";
export type { Pattern, PatternPack } from "./detectors/index.js";

// enforcers
export {
  BlockEnforcer,
  LogOnlyEnforcer,
  RedactEnforcer,
  ThresholdEnforcer,
  TransformEnforcer,
} from "./enforcers/index.js";

// output sanitisation (LLM05)
export {
  DEFAULT_ALLOWED_ATTRS,
  DEFAULT_ALLOWED_TAGS,
  URLAllowlist,
  htmlSanitizerEnforcer,
  isSafeSql,
  sanitizeHtml,
} from "./output/index.js";

// agent / tool authorization (LLM06)
export {
  ApprovalRequired,
  GRANTED_SCOPES_KEY,
  PermissionError,
  TOOL_AUDIT_KEY,
  authorize,
  currentContext,
  guardedTool,
} from "./agent/index.js";
export type {
  ApprovalHandler,
  ToolCall,
  ToolCallEvent,
  GuardedToolOptions,
} from "./agent/index.js";

// budgets & rate limits (LLM10)
export {
  BudgetEnforcer,
  BudgetExceededError,
  CostBudget,
  DEFAULT_PRICING,
  RateLimitEnforcer,
  RateLimiter,
  TokenBudget,
} from "./budget/index.js";
export type { Budget, ModelPricing } from "./budget/index.js";

// storage (file-backed stores live in `soweak/node`)
export {
  CounterStore,
  InMemoryCounterStore,
  InMemoryWindowStore,
  WindowStore,
} from "./storage/index.js";

// RAG (LLM08)
export {
  IndirectInjectionDetector,
  ProvenanceDetector,
  RetrievalAnomalyDetector,
  TenantIsolationDetector,
} from "./rag/index.js";

// grounding (LLM09)
export {
  CitationRequiredDetector,
  DEFAULT_CITATION_REGEX,
  EmbeddingGroundingDetector,
  GroundingDetector,
  RETRIEVED_DOCS_KEY,
  RETRIEVED_TEXT_KEY,
  cosineSimilarity,
  gatherRetrieval,
  splitSentences,
  tokenize,
} from "./grounding/index.js";
export type { Embedder } from "./grounding/index.js";

// streaming (LLM10)
export { RepetitionDetector } from "./streaming/index.js";

// ML augmentation
export {
  DEFAULT_JUDGE_PROMPT_TEMPLATE,
  MLClassifierDetector,
  llmJudgeClassifier,
} from "./ml/index.js";
export type { Classifier } from "./ml/index.js";

// declarative policy loader (`loadPolicy(path)` lives in `soweak/node`)
export {
  DEFAULT_DETECTOR_REGISTRY,
  DEFAULT_ENFORCER_REGISTRY,
  SUPPORTED_VERSIONS,
  buildPolicy,
} from "./config/index.js";
export type { DetectorFactory, EnforcerFactory } from "./config/index.js";

// adapter errors
export { SecurityError } from "./adapters/errors.js";
