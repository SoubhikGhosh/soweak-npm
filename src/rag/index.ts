/**
 * LLM08 — Vector & Embedding weaknesses: retriever middleware.
 *
 * Detectors run at `Boundary.RETRIEVAL` against `payload.raw` (the
 * structured list of retrieved documents).
 */

import { Detector, makeSignal, Signal } from "../core/detector.js";
import { Boundary, Context, OwaspCategory, Payload, Severity } from "../core/types.js";
import { PatternMatchDetector } from "../detectors/patternMatch.js";
import { PROMPT_INJECTION_PACK } from "../detectors/patterns.js";
import { SoweakError } from "../core/errors.js";

function docText(doc: unknown): string {
  if (typeof doc === "string") return doc;
  if (doc && typeof doc === "object") {
    const d = doc as Record<string, unknown>;
    for (const k of ["text", "page_content", "content", "body"]) {
      const v = d[k];
      if (typeof v === "string") return v;
    }
  }
  return "";
}

function docMetadata(doc: unknown): Record<string, unknown> {
  if (doc && typeof doc === "object") {
    const d = doc as Record<string, unknown>;
    if (d.metadata && typeof d.metadata === "object") {
      return d.metadata as Record<string, unknown>;
    }
    const meta: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(d)) {
      if (k !== "text" && k !== "page_content" && k !== "content" && k !== "body") {
        meta[k] = v;
      }
    }
    return meta;
  }
  return {};
}

function docScore(doc: unknown): number | null {
  const meta = docMetadata(doc);
  for (const k of ["score", "relevance_score", "similarity"]) {
    const v = meta[k];
    if (typeof v === "number") return v;
  }
  return null;
}

function* iterDocs(payload: Payload): Iterable<[number, unknown]> {
  const raw = payload.raw;
  if (Array.isArray(raw)) {
    for (let i = 0; i < raw.length; i++) yield [i, raw[i]];
  }
}

/**
 * Run prompt-injection patterns against retrieved document text — the
 * LLM01 defence at the retrieval boundary.
 */
export class IndirectInjectionDetector extends Detector {
  private readonly inner: PatternMatchDetector;
  private readonly _name: string;
  private readonly _boundaries: readonly Boundary[];

  constructor(options: { name?: string; boundaries?: readonly Boundary[] } = {}) {
    super();
    this.inner = new PatternMatchDetector(PROMPT_INJECTION_PACK);
    this._name = options.name ?? "indirect-injection";
    this._boundaries = options.boundaries ?? [Boundary.RETRIEVAL];
  }

  override get name(): string {
    return this._name;
  }

  override get category(): OwaspCategory {
    return OwaspCategory.LLM01_PROMPT_INJECTION;
  }

  override get boundaries(): readonly Boundary[] {
    return this._boundaries;
  }

  override *inspect(payload: Payload, ctx: Context): Iterable<Signal> {
    for (const [i, doc] of iterDocs(payload)) {
      const text = docText(doc);
      if (!text) continue;
      const docPayload: Payload = {
        boundary: Boundary.RETRIEVAL,
        text,
        raw: doc,
        metadata: {},
      };
      for (const sig of this.inner.inspect(docPayload, ctx)) {
        yield makeSignal({
          detector: this._name,
          category: sig.category,
          severity: sig.severity,
          confidence: sig.confidence,
          message: `document[${i}]: ${sig.message}`,
          span: sig.span,
          matchedText: sig.matchedText,
          metadata: { ...sig.metadata, docIndex: i },
        });
      }
    }
  }
}

/**
 * Flag retrieved documents whose tenant key doesn't match ctx.tenantId.
 */
export class TenantIsolationDetector extends Detector {
  private readonly _tenantKey: string;
  private readonly _name: string;

  constructor(options: { tenantKey?: string; name?: string } = {}) {
    super();
    this._tenantKey = options.tenantKey ?? "tenant_id";
    this._name = options.name ?? "tenant-isolation";
  }

  override get name(): string {
    return this._name;
  }

  override get category(): OwaspCategory {
    return OwaspCategory.LLM08_VECTOR_EMBEDDING;
  }

  override get boundaries(): readonly Boundary[] {
    return [Boundary.RETRIEVAL];
  }

  override *inspect(payload: Payload, ctx: Context): Iterable<Signal> {
    const requestTenant = ctx.tenantId;
    if (!requestTenant) return;
    for (const [i, doc] of iterDocs(payload)) {
      const meta = docMetadata(doc);
      const docTenant = meta[this._tenantKey];
      if (docTenant === undefined || docTenant === null) {
        yield makeSignal({
          detector: this._name,
          category: OwaspCategory.LLM08_VECTOR_EMBEDDING,
          severity: Severity.HIGH,
          confidence: 0.95,
          message: `document[${i}] missing ${JSON.stringify(this._tenantKey)}; cannot verify tenant ${JSON.stringify(requestTenant)}`,
          metadata: { docIndex: i, requestTenant },
        });
        continue;
      }
      if (docTenant !== requestTenant) {
        yield makeSignal({
          detector: this._name,
          category: OwaspCategory.LLM08_VECTOR_EMBEDDING,
          severity: Severity.CRITICAL,
          confidence: 1.0,
          message: `document[${i}] tenant=${JSON.stringify(docTenant)} but request tenant=${JSON.stringify(requestTenant)}`,
          metadata: { docIndex: i, docTenant, requestTenant },
        });
      }
    }
  }
}

/**
 * Flag retrieved documents that lack any provenance field.
 */
export class ProvenanceDetector extends Detector {
  private readonly _required: readonly string[];
  private readonly _name: string;

  constructor(options: { requiredKeys?: readonly string[]; name?: string } = {}) {
    super();
    const keys = options.requiredKeys ?? ["source", "url", "uri", "doc_id"];
    if (keys.length === 0) throw new SoweakError("requiredKeys must be non-empty");
    this._required = keys;
    this._name = options.name ?? "provenance";
  }

  override get name(): string {
    return this._name;
  }

  override get category(): OwaspCategory {
    return OwaspCategory.LLM08_VECTOR_EMBEDDING;
  }

  override get boundaries(): readonly Boundary[] {
    return [Boundary.RETRIEVAL];
  }

  override *inspect(payload: Payload, _ctx: Context): Iterable<Signal> {
    for (const [i, doc] of iterDocs(payload)) {
      const meta = docMetadata(doc);
      const hasAny = this._required.some((k) => Boolean(meta[k]));
      if (!hasAny) {
        yield makeSignal({
          detector: this._name,
          category: OwaspCategory.LLM08_VECTOR_EMBEDDING,
          severity: Severity.MEDIUM,
          confidence: 0.95,
          message: `document[${i}] lacks provenance (none of ${JSON.stringify(this._required)} set)`,
          metadata: { docIndex: i, requiredKeys: [...this._required] },
        });
      }
    }
  }
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

/**
 * Flag retrieval score outliers. A document scoring far below the rest of
 * the batch often signals a poisoned or irrelevant injection.
 */
export class RetrievalAnomalyDetector extends Detector {
  private readonly _maxDeviation: number;
  private readonly _name: string;

  constructor(options: { maxDeviation?: number; name?: string } = {}) {
    super();
    const maxDeviation = options.maxDeviation ?? 3.0;
    if (maxDeviation <= 0) throw new SoweakError("maxDeviation must be positive");
    this._maxDeviation = maxDeviation;
    this._name = options.name ?? "retrieval-anomaly";
  }

  override get name(): string {
    return this._name;
  }

  override get category(): OwaspCategory {
    return OwaspCategory.LLM08_VECTOR_EMBEDDING;
  }

  override get boundaries(): readonly Boundary[] {
    return [Boundary.RETRIEVAL];
  }

  override *inspect(payload: Payload, _ctx: Context): Iterable<Signal> {
    const scored: Array<[number, number]> = [];
    for (const [i, doc] of iterDocs(payload)) {
      const score = docScore(doc);
      if (score !== null) scored.push([i, score]);
    }
    if (scored.length < 3) return;
    const scores = scored.map(([, s]) => s);
    const med = median(scores);
    const mad = median(scores.map((s) => Math.abs(s - med))) || 1e-9;
    for (const [i, s] of scored) {
      const dev = Math.abs(s - med) / mad;
      if (dev > this._maxDeviation) {
        yield makeSignal({
          detector: this._name,
          category: OwaspCategory.LLM08_VECTOR_EMBEDDING,
          severity: Severity.MEDIUM,
          confidence: 0.7,
          message: `document[${i}] score=${s.toFixed(3)} deviates ${dev.toFixed(1)}× from median ${med.toFixed(3)}`,
          metadata: { docIndex: i, score: s, median: med, deviation: dev },
        });
      }
    }
  }
}
