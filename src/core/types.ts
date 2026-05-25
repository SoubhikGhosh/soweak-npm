/**
 * Core data types: boundaries, severity, OWASP category, Payload, Context.
 */

import { SoweakError } from "./errors.js";

export type Boundary = "input" | "retrieval" | "tool_call" | "output" | "stream";

export const Boundary = {
  INPUT: "input" as const,
  RETRIEVAL: "retrieval" as const,
  TOOL_CALL: "tool_call" as const,
  OUTPUT: "output" as const,
  STREAM: "stream" as const,
} as const;

/**
 * Signal severity. Ordered: INFO < LOW < MEDIUM < HIGH < CRITICAL.
 */
export enum Severity {
  INFO = 0,
  LOW = 1,
  MEDIUM = 2,
  HIGH = 3,
  CRITICAL = 4,
}

const SEVERITY_LABELS: Record<Severity, string> = {
  [Severity.INFO]: "info",
  [Severity.LOW]: "low",
  [Severity.MEDIUM]: "medium",
  [Severity.HIGH]: "high",
  [Severity.CRITICAL]: "critical",
};

const SEVERITY_BY_LABEL: Record<string, Severity> = {
  info: Severity.INFO,
  low: Severity.LOW,
  medium: Severity.MEDIUM,
  high: Severity.HIGH,
  critical: Severity.CRITICAL,
};

export function severityLabel(s: Severity): string {
  return SEVERITY_LABELS[s];
}

export function severityFromLabel(label: string): Severity {
  const key = label.toLowerCase();
  const value = SEVERITY_BY_LABEL[key];
  if (value === undefined) {
    throw new SoweakError(
      `invalid severity ${JSON.stringify(label)}; expected one of info/low/medium/high/critical`,
    );
  }
  return value;
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  [Severity.INFO]: 0.1,
  [Severity.LOW]: 0.3,
  [Severity.MEDIUM]: 0.5,
  [Severity.HIGH]: 0.8,
  [Severity.CRITICAL]: 1.0,
};

export function severityWeight(s: Severity): number {
  return SEVERITY_WEIGHT[s];
}

/**
 * OWASP Top 10 for LLM Applications (2025).
 */
export const OwaspCategory = {
  LLM01_PROMPT_INJECTION: "LLM01",
  LLM02_SENSITIVE_INFO: "LLM02",
  LLM03_SUPPLY_CHAIN: "LLM03",
  LLM04_DATA_POISONING: "LLM04",
  LLM05_OUTPUT_HANDLING: "LLM05",
  LLM06_EXCESSIVE_AGENCY: "LLM06",
  LLM07_SYSTEM_PROMPT_LEAKAGE: "LLM07",
  LLM08_VECTOR_EMBEDDING: "LLM08",
  LLM09_MISINFORMATION: "LLM09",
  LLM10_UNBOUNDED_CONSUMPTION: "LLM10",
} as const;

export type OwaspCategory = (typeof OwaspCategory)[keyof typeof OwaspCategory];

/**
 * A piece of content flowing through a boundary.
 *
 * `text` is the canonical text the detectors inspect. `raw` carries the
 * original object (e.g., a tool-call dict, a list of retrieved docs) so
 * enforcers can rebuild the structured form when needed.
 */
export interface Payload {
  boundary: Boundary;
  text: string;
  raw?: unknown;
  metadata: Record<string, unknown>;
}

export function makePayload(
  boundary: Boundary,
  text: string = "",
  raw: unknown = null,
  metadata: Record<string, unknown> = {},
): Payload {
  return { boundary, text, raw, metadata };
}

/**
 * Request-scoped context that travels with every Payload through a pipeline.
 */
export interface Context {
  requestId: string;
  userId?: string | null;
  tenantId?: string | null;
  sessionId?: string | null;
  metadata: Record<string, unknown>;
}

let _idCounter = 0;

/**
 * Best-available request-id generator.
 *
 * Order of preference:
 *   1. `globalThis.crypto.randomUUID()` (Node ≥ 19, all modern browsers)
 *   2. Falls back to a Date + Math.random() composite — sufficient for log
 *      correlation, NOT for cryptographic uniqueness.
 *
 * Override per-request by passing `requestId` to `makeContext`.
 */
function _quickId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (c && typeof c.randomUUID === "function") {
    return c.randomUUID();
  }
  const rand = Math.floor(Math.random() * 0xffffffff)
    .toString(16)
    .padStart(8, "0");
  const ts = Date.now().toString(16);
  const ctr = (++_idCounter & 0xffff).toString(16).padStart(4, "0");
  return `${ts}-${rand}-${ctr}`;
}

export function makeContext(init: Partial<Context> = {}): Context {
  return {
    requestId: init.requestId ?? _quickId(),
    userId: init.userId ?? null,
    tenantId: init.tenantId ?? null,
    sessionId: init.sessionId ?? null,
    metadata: init.metadata ?? {},
  };
}
