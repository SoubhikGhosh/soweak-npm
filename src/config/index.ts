/**
 * Declarative policy loader (JSON).
 *
 * Schema (version 1):
 *
 * ```jsonc
 * {
 *   "version": 1,
 *   "rules": [
 *     { "name": "prompt-injection", "boundary": "input",
 *       "detectors": [{ "type": "prompt_injection" }],
 *       "enforcer": { "type": "block", "minSeverity": "high" } }
 *   ]
 * }
 * ```
 *
 * Detector / enforcer `type` strings resolve through a registry. Pass
 * `detectorRegistry` / `enforcerRegistry` overrides on calls to register
 * custom types.
 *
 * YAML support: not bundled (avoid the dep for browsers). Parse YAML with
 * any library (`js-yaml`, `yaml`) and pass the resulting object to
 * `buildPolicy`.
 */

import { Detector } from "../core/detector.js";
import { Enforcer } from "../core/enforcer.js";
import { ConfigurationError } from "../core/errors.js";
import { Policy, PolicyBuilder } from "../core/policy.js";
import { Boundary, OwaspCategory, Severity, severityFromLabel } from "../core/types.js";
import {
  CanaryDetector,
  inputDlpDetector,
  outputDlpDetector,
  outputHtmlDetector,
  outputShellDetector,
  outputSqlDetector,
  PatternMatchDetector,
  promptInjectionDetector,
  systemPromptExtractionDetector,
  makePack,
  makePattern,
} from "../detectors/index.js";
import {
  BlockEnforcer,
  LogOnlyEnforcer,
  RedactEnforcer,
  ThresholdEnforcer,
} from "../enforcers/index.js";
import { CitationRequiredDetector, GroundingDetector } from "../grounding/index.js";
import {
  IndirectInjectionDetector,
  ProvenanceDetector,
  RetrievalAnomalyDetector,
  TenantIsolationDetector,
} from "../rag/index.js";
import { RepetitionDetector } from "../streaming/index.js";

export type DetectorFactory = (spec: Record<string, unknown>) => Detector;
export type EnforcerFactory = (spec: Record<string, unknown>) => Enforcer;

function severity(value: unknown): Severity {
  if (typeof value === "number") return value;
  if (typeof value === "string") return severityFromLabel(value);
  throw new ConfigurationError(`invalid severity: ${JSON.stringify(value)}`);
}

function buildPatternPack(spec: Record<string, unknown>) {
  const patternsSpec = (spec.patterns ?? []) as Array<Record<string, unknown>>;
  const patterns = patternsSpec.map((p) =>
    makePattern({
      regex: p.regex as string,
      severity: severity(p.severity ?? "medium"),
      description: (p.description as string) ?? "",
      confidence: p.confidence as number | undefined,
      attackType: p.attackType as string | undefined,
      flags: p.flags as string | undefined,
    }),
  );
  return makePack({
    name: (spec.name as string) ?? "custom",
    category: (spec.category as OwaspCategory) ?? OwaspCategory.LLM01_PROMPT_INJECTION,
    patterns,
    version: spec.version as string | undefined,
  });
}

export const DEFAULT_DETECTOR_REGISTRY: Record<string, DetectorFactory> = {
  prompt_injection: () => promptInjectionDetector(),
  input_dlp: () => inputDlpDetector(),
  system_prompt_extraction: () => systemPromptExtractionDetector(),
  output_dlp: () => outputDlpDetector(),
  output_html: () => outputHtmlDetector(),
  output_sql: () => outputSqlDetector(),
  output_shell: () => outputShellDetector(),
  canary: (spec) =>
    new CanaryDetector({
      tokens: (spec.tokens as string[]) ?? [],
      name: spec.name as string | undefined,
      severity: spec.severity !== undefined ? severity(spec.severity) : undefined,
    }),
  indirect_injection: (spec) =>
    new IndirectInjectionDetector({ name: spec.name as string | undefined }),
  tenant_isolation: (spec) =>
    new TenantIsolationDetector({
      tenantKey: spec.tenantKey as string | undefined,
      name: spec.name as string | undefined,
    }),
  provenance: (spec) =>
    new ProvenanceDetector({
      requiredKeys: spec.requiredKeys as string[] | undefined,
      name: spec.name as string | undefined,
    }),
  retrieval_anomaly: (spec) =>
    new RetrievalAnomalyDetector({
      maxDeviation: spec.maxDeviation as number | undefined,
      name: spec.name as string | undefined,
    }),
  citation_required: (spec) =>
    new CitationRequiredDetector({
      minChars: spec.minChars as number | undefined,
      citationRegex: spec.citationRegex as string | undefined,
      severity: spec.severity !== undefined ? severity(spec.severity) : undefined,
      name: spec.name as string | undefined,
    }),
  grounding: (spec) =>
    new GroundingDetector({
      minOverlap: spec.minOverlap as number | undefined,
      minSentenceTokens: spec.minSentenceTokens as number | undefined,
      severity: spec.severity !== undefined ? severity(spec.severity) : undefined,
      name: spec.name as string | undefined,
    }),
  repetition: (spec) =>
    new RepetitionDetector({
      windowSize: spec.windowSize as number | undefined,
      minRepeats: spec.minRepeats as number | undefined,
      unitSizes: spec.unitSizes as number[] | undefined,
      name: spec.name as string | undefined,
    }),
  pattern_match: (spec) =>
    new PatternMatchDetector(buildPatternPack(spec.pack as Record<string, unknown>)),
};

export const DEFAULT_ENFORCER_REGISTRY: Record<string, EnforcerFactory> = {
  block: (spec) =>
    new BlockEnforcer({
      minSeverity: spec.minSeverity !== undefined ? severity(spec.minSeverity) : undefined,
      name: spec.name as string | undefined,
    }),
  redact: (spec) =>
    new RedactEnforcer({
      placeholder: spec.placeholder as string | undefined,
      minSeverity: spec.minSeverity !== undefined ? severity(spec.minSeverity) : undefined,
      name: spec.name as string | undefined,
    }),
  log_only: (spec) => new LogOnlyEnforcer({ name: spec.name as string | undefined }),
  threshold: (spec) =>
    new ThresholdEnforcer({
      blockAt: spec.blockAt as number | undefined,
      warnAt: spec.warnAt as number | undefined,
      name: spec.name as string | undefined,
    }),
};

export const SUPPORTED_VERSIONS = [1] as const;

export function buildPolicy(
  data: Record<string, unknown>,
  options: {
    detectorRegistry?: Record<string, DetectorFactory>;
    enforcerRegistry?: Record<string, EnforcerFactory>;
  } = {},
): Policy {
  const version = (data.version as number | undefined) ?? 1;
  if (!SUPPORTED_VERSIONS.includes(version as 1)) {
    throw new ConfigurationError(
      `unsupported policy version ${JSON.stringify(version)}; supported: ${SUPPORTED_VERSIONS.join(",")}`,
    );
  }
  const detReg = { ...DEFAULT_DETECTOR_REGISTRY, ...(options.detectorRegistry ?? {}) };
  const enfReg = { ...DEFAULT_ENFORCER_REGISTRY, ...(options.enforcerRegistry ?? {}) };
  const rules = (data.rules as unknown[]) ?? [];
  if (!Array.isArray(rules)) throw new ConfigurationError("policy.rules must be an array");

  const builder = new PolicyBuilder();
  rules.forEach((raw, i) => {
    if (!raw || typeof raw !== "object") {
      throw new ConfigurationError(`rules[${i}] must be an object`);
    }
    const rule = raw as Record<string, unknown>;
    const name = (rule.name as string | undefined) ?? `rule-${i}`;
    const boundary = rule.boundary as Boundary;
    if (!boundary || !Object.values(Boundary).includes(boundary)) {
      throw new ConfigurationError(
        `rules[${i}] invalid boundary ${JSON.stringify(boundary)}; expected one of ${JSON.stringify(Object.values(Boundary))}`,
      );
    }

    const detectorSpecs = (rule.detectors as Array<Record<string, unknown>>) ?? [];
    if (!Array.isArray(detectorSpecs)) {
      throw new ConfigurationError(`rules[${i}].detectors must be an array`);
    }
    const detectors: Detector[] = detectorSpecs.map((spec, j) => {
      const type = spec.type as string;
      if (!type) throw new ConfigurationError(`rules[${i}].detectors[${j}] missing 'type'`);
      const factory = detReg[type];
      if (!factory) {
        throw new ConfigurationError(
          `rules[${i}].detectors[${j}] unknown type ${JSON.stringify(type)}`,
        );
      }
      return factory(spec);
    });

    const enfSpec = rule.enforcer as Record<string, unknown> | undefined;
    if (!enfSpec || typeof enfSpec !== "object") {
      throw new ConfigurationError(`rules[${i}].enforcer must be an object`);
    }
    const enfType = enfSpec.type as string;
    if (!enfType) throw new ConfigurationError(`rules[${i}].enforcer missing 'type'`);
    const enfFactory = enfReg[enfType];
    if (!enfFactory) {
      throw new ConfigurationError(`rules[${i}].enforcer unknown type ${JSON.stringify(enfType)}`);
    }
    const enforcer = enfFactory(enfSpec);

    const clauseMap = {
      [Boundary.INPUT]: () => builder.onInput(name),
      [Boundary.RETRIEVAL]: () => builder.onRetrieval(name),
      [Boundary.TOOL_CALL]: () => builder.onToolCall(name),
      [Boundary.OUTPUT]: () => builder.onOutput(name),
      [Boundary.STREAM]: () => builder.onStream(name),
    } as const;
    let clause = clauseMap[boundary]();
    if (detectors.length > 0) clause = clause.detect(...detectors);
    clause.enforce(enforcer);
  });

  return builder.build();
}

// `loadPolicy(path)` lives in `soweak/node` — it needs `node:fs`. In the
// browser, parse the JSON yourself (`await fetch(url).then(r => r.json())`)
// and call `buildPolicy(data)`.
