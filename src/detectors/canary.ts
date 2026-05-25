/**
 * CanaryDetector — detect system-prompt leakage on the output boundary.
 *
 * Place unique canary tokens inside your system prompt; scan model output
 * for those tokens. Any hit indicates the model is regurgitating privileged
 * context.
 */

import { Detector, makeSignal, Signal } from "../core/detector.js";
import { Boundary, Context, OwaspCategory, Payload, Severity } from "../core/types.js";
import { SoweakError } from "../core/errors.js";

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export class CanaryDetector extends Detector {
  private readonly _tokens: readonly string[];
  private readonly _boundaries: readonly Boundary[];
  private readonly _name: string;
  private readonly _severity: Severity;
  private readonly _regex: RegExp;

  constructor(options: {
    tokens: Iterable<string>;
    boundaries?: readonly Boundary[];
    name?: string;
    severity?: Severity;
  }) {
    super();
    const toks = Array.from(options.tokens).filter((t) => t.length > 0);
    if (toks.length === 0) {
      throw new SoweakError("CanaryDetector requires at least one non-empty token");
    }
    this._tokens = toks;
    this._boundaries = options.boundaries ?? [Boundary.OUTPUT, Boundary.STREAM];
    this._name = options.name ?? "canary";
    this._severity = options.severity ?? Severity.CRITICAL;
    this._regex = new RegExp(toks.map(escapeRegex).join("|"), "g");
  }

  override get name(): string {
    return this._name;
  }

  override get category(): OwaspCategory {
    return OwaspCategory.LLM07_SYSTEM_PROMPT_LEAKAGE;
  }

  override get boundaries(): readonly Boundary[] {
    return this._boundaries;
  }

  get tokens(): readonly string[] {
    return this._tokens;
  }

  override *inspect(payload: Payload, _ctx: Context): Iterable<Signal> {
    const text = payload.text;
    if (!text) return;
    this._regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = this._regex.exec(text)) !== null) {
      const start = match.index;
      const end = start + match[0].length;
      yield makeSignal({
        detector: this._name,
        category: OwaspCategory.LLM07_SYSTEM_PROMPT_LEAKAGE,
        severity: this._severity,
        confidence: 1.0,
        message: `Canary token leaked in output: ${JSON.stringify(match[0])}`,
        span: [start, end],
        matchedText: match[0],
        metadata: { attackType: "system_prompt_leak" },
      });
    }
  }
}
