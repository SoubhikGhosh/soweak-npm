/**
 * LLM09 — Misinformation: grounding and citation checks.
 *
 * - CitationRequiredDetector: signals when long output makes claims with no
 *   citation marker.
 * - GroundingDetector: lexical overlap with retrieval context.
 * - EmbeddingGroundingDetector: cosine similarity over user-provided embeddings.
 */

import { Detector, makeSignal, Signal } from "../core/detector.js";
import { Boundary, Context, OwaspCategory, Payload, Severity } from "../core/types.js";
import { SoweakError } from "../core/errors.js";

export const DEFAULT_CITATION_REGEX = "\\[[\\w_:-]+\\]|\\(\\d{1,3}\\)";
export const RETRIEVED_TEXT_KEY = "retrievedText";
export const RETRIEVED_DOCS_KEY = "retrievedDocuments";

export class CitationRequiredDetector extends Detector {
  private readonly _minChars: number;
  private readonly _regex: RegExp;
  private readonly _severity: Severity;
  private readonly _name: string;

  constructor(
    options: {
      minChars?: number;
      citationRegex?: string;
      severity?: Severity;
      name?: string;
    } = {},
  ) {
    super();
    const minChars = options.minChars ?? 200;
    if (minChars <= 0) throw new SoweakError("minChars must be positive");
    this._minChars = minChars;
    this._regex = new RegExp(options.citationRegex ?? DEFAULT_CITATION_REGEX);
    this._severity = options.severity ?? Severity.MEDIUM;
    this._name = options.name ?? "citation-required";
  }

  override get name(): string {
    return this._name;
  }

  override get category(): OwaspCategory {
    return OwaspCategory.LLM09_MISINFORMATION;
  }

  override get boundaries(): readonly Boundary[] {
    return [Boundary.OUTPUT];
  }

  override *inspect(payload: Payload, _ctx: Context): Iterable<Signal> {
    const text = payload.text;
    if (text.length < this._minChars) return;
    if (this._regex.test(text)) return;
    yield makeSignal({
      detector: this._name,
      category: OwaspCategory.LLM09_MISINFORMATION,
      severity: this._severity,
      confidence: 0.7,
      message: `Output is ${text.length} chars but contains no citation marker matching ${this._regex.source}`,
    });
  }
}

const TOKEN_RE = /[\p{L}\p{N}_]{3,}/gu;
const SENTENCE_RE = /[^.!?。!?؟۔]+[.!?。!?؟۔]?/gu;
const STOPWORDS = new Set([
  "this",
  "that",
  "with",
  "from",
  "they",
  "have",
  "been",
  "were",
  "would",
  "could",
  "should",
  "what",
  "which",
  "their",
  "there",
  "these",
  "those",
  "about",
  "into",
  "than",
  "then",
  "when",
  "where",
  "while",
  "your",
  "will",
  "also",
]);

export function tokenize(text: string): Set<string> {
  const out = new Set<string>();
  const lowered = text.toLowerCase();
  const matches = lowered.matchAll(TOKEN_RE);
  for (const m of matches) {
    if (!STOPWORDS.has(m[0])) out.add(m[0]);
  }
  return out;
}

export function splitSentences(text: string): string[] {
  const out: string[] = [];
  const matches = text.matchAll(SENTENCE_RE);
  for (const m of matches) {
    const s = m[0].trim();
    if (s) out.push(s);
  }
  return out;
}

export function gatherRetrieval(ctx: Context): string {
  const direct = ctx.metadata[RETRIEVED_TEXT_KEY];
  if (typeof direct === "string" && direct) return direct;
  const docs = ctx.metadata[RETRIEVED_DOCS_KEY];
  if (Array.isArray(docs)) {
    const parts: string[] = [];
    for (const d of docs) {
      if (typeof d === "string") parts.push(d);
      else if (d && typeof d === "object") {
        const dd = d as Record<string, unknown>;
        for (const k of ["text", "page_content", "content", "body"]) {
          const v = dd[k];
          if (typeof v === "string") {
            parts.push(v);
            break;
          }
        }
      }
    }
    return parts.join("\n\n");
  }
  return "";
}

export class GroundingDetector extends Detector {
  private readonly _minOverlap: number;
  private readonly _minSentenceTokens: number;
  private readonly _severity: Severity;
  private readonly _name: string;

  constructor(
    options: {
      minOverlap?: number;
      minSentenceTokens?: number;
      severity?: Severity;
      name?: string;
    } = {},
  ) {
    super();
    const minOverlap = options.minOverlap ?? 0.3;
    if (minOverlap <= 0 || minOverlap > 1) {
      throw new SoweakError("minOverlap must be in (0, 1]");
    }
    this._minOverlap = minOverlap;
    this._minSentenceTokens = options.minSentenceTokens ?? 4;
    this._severity = options.severity ?? Severity.LOW;
    this._name = options.name ?? "grounding";
  }

  override get name(): string {
    return this._name;
  }

  override get category(): OwaspCategory {
    return OwaspCategory.LLM09_MISINFORMATION;
  }

  override get boundaries(): readonly Boundary[] {
    return [Boundary.OUTPUT];
  }

  override *inspect(payload: Payload, ctx: Context): Iterable<Signal> {
    const retrieval = gatherRetrieval(ctx);
    if (!retrieval) return;
    const retrievalTokens = tokenize(retrieval);
    if (retrievalTokens.size === 0) return;
    let offset = 0;
    for (const sentence of splitSentences(payload.text)) {
      const start = payload.text.indexOf(sentence, offset);
      const end = start >= 0 ? start + sentence.length : null;
      if (end !== null) offset = end;
      const tokens = tokenize(sentence);
      if (tokens.size < this._minSentenceTokens) continue;
      let intersection = 0;
      for (const t of tokens) if (retrievalTokens.has(t)) intersection++;
      const overlap = intersection / tokens.size;
      if (overlap < this._minOverlap) {
        yield makeSignal({
          detector: this._name,
          category: OwaspCategory.LLM09_MISINFORMATION,
          severity: this._severity,
          confidence: 0.6,
          message: `Sentence has ${(overlap * 100).toFixed(0)}% lexical overlap with retrieval context (threshold ${(this._minOverlap * 100).toFixed(0)}%)`,
          span: start >= 0 && end !== null ? [start, end] : null,
          matchedText: sentence.slice(0, 160),
          metadata: {
            overlap,
            minOverlap: this._minOverlap,
            sentenceTokens: tokens.size,
          },
        });
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Embedding-based grounding
// ---------------------------------------------------------------------------

export type Embedder = (texts: string[]) => Promise<number[][]> | number[][];

export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) {
    throw new SoweakError(`vector length mismatch: ${a.length} vs ${b.length}`);
  }
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

/**
 * Cosine-similarity grounding using a user-supplied embedder.
 *
 * Bring any embedding function: an OpenAI embeddings call, a local
 * `@xenova/transformers` pipeline, a remote service. The detector is
 * dependency-free.
 *
 * Because embedders are typically async, this detector overrides `ainspect`
 * and returns a single empty `inspect` from sync calls. Pair it with
 * `pipeline.arun` / `pipeline.acheckOutput`.
 */
export class EmbeddingGroundingDetector extends Detector {
  private readonly _embedder: Embedder;
  private readonly _threshold: number;
  private readonly _minSentenceTokens: number;
  private readonly _severity: Severity;
  private readonly _name: string;

  constructor(options: {
    embedder: Embedder;
    threshold?: number;
    minSentenceTokens?: number;
    severity?: Severity;
    name?: string;
  }) {
    super();
    const threshold = options.threshold ?? 0.55;
    if (threshold <= 0 || threshold > 1) {
      throw new SoweakError("threshold must be in (0, 1]");
    }
    this._embedder = options.embedder;
    this._threshold = threshold;
    this._minSentenceTokens = options.minSentenceTokens ?? 4;
    this._severity = options.severity ?? Severity.MEDIUM;
    this._name = options.name ?? "embedding-grounding";
  }

  override get name(): string {
    return this._name;
  }

  override get category(): OwaspCategory {
    return OwaspCategory.LLM09_MISINFORMATION;
  }

  override get boundaries(): readonly Boundary[] {
    return [Boundary.OUTPUT];
  }

  override *inspect(_payload: Payload, _ctx: Context): Iterable<Signal> {
    // Sync surface — defer to ainspect when used inside Pipeline.arun.
  }

  override async ainspect(payload: Payload, ctx: Context): Promise<Signal[]> {
    const retrieval = gatherRetrieval(ctx);
    if (!retrieval) return [];
    const sentences = splitSentences(payload.text);
    const eligible: Array<[number, string]> = [];
    for (let i = 0; i < sentences.length; i++) {
      if (sentences[i].split(/\s+/).length >= this._minSentenceTokens) {
        eligible.push([i, sentences[i]]);
      }
    }
    if (eligible.length === 0) return [];
    const batch = [retrieval, ...eligible.map(([, s]) => s)];
    const vectors = await this._embedder(batch);
    if (vectors.length !== batch.length) {
      throw new SoweakError(
        `embedder returned wrong number of vectors: expected ${batch.length}, got ${vectors.length}`,
      );
    }
    const retrievalVec = vectors[0];
    const signals: Signal[] = [];
    let offset = 0;
    for (let k = 0; k < eligible.length; k++) {
      const [i, sentence] = eligible[k];
      const sentVec = vectors[k + 1];
      const sim = cosineSimilarity(sentVec, retrievalVec);
      if (sim >= this._threshold) continue;
      const start = payload.text.indexOf(sentence, offset);
      const end = start >= 0 ? start + sentence.length : null;
      if (end !== null) offset = end;
      signals.push(
        makeSignal({
          detector: this._name,
          category: OwaspCategory.LLM09_MISINFORMATION,
          severity: this._severity,
          confidence: 1 - sim,
          message: `Sentence cosine similarity ${sim.toFixed(2)} below threshold ${this._threshold.toFixed(2)}`,
          span: start >= 0 && end !== null ? [start, end] : null,
          matchedText: sentence.slice(0, 160),
          metadata: { similarity: sim, threshold: this._threshold, sentenceIndex: i },
        }),
      );
    }
    return signals;
  }
}
