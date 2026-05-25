/**
 * PatternMatchDetector — regex-driven Detector.
 *
 * Compilation happens once at construction time; `inspect` only does the
 * `matchAll` walk.
 */

import { Detector, makeSignal, Signal } from "../core/detector.js";
import { Boundary, Context, OwaspCategory, Payload } from "../core/types.js";
import { Pattern, PatternPack } from "./patterns.js";

interface CompiledPattern {
  regex: RegExp;
  pattern: Pattern;
}

function ensureGlobal(flags: string): string {
  return flags.includes("g") ? flags : flags + "g";
}

export class PatternMatchDetector extends Detector {
  private readonly _pack: PatternPack;
  private readonly _boundaries: readonly Boundary[];
  private readonly _name: string;
  private readonly _compiled: readonly CompiledPattern[];

  constructor(
    pack: PatternPack,
    options: { boundaries?: readonly Boundary[]; name?: string } = {},
  ) {
    super();
    this._pack = pack;
    this._boundaries = options.boundaries ?? [Boundary.INPUT];
    this._name = options.name ?? `pattern-match[${pack.name}]`;
    this._compiled = pack.patterns.map((p) => ({
      regex: new RegExp(p.regex, ensureGlobal(p.flags)),
      pattern: p,
    }));
  }

  override get name(): string {
    return this._name;
  }

  override get category(): OwaspCategory {
    return this._pack.category;
  }

  override get boundaries(): readonly Boundary[] {
    return this._boundaries;
  }

  get pack(): PatternPack {
    return this._pack;
  }

  override *inspect(payload: Payload, _ctx: Context): Iterable<Signal> {
    const text = payload.text;
    if (!text) return;
    for (const { regex, pattern } of this._compiled) {
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(text)) !== null) {
        const start = match.index;
        const end = start + match[0].length;
        yield makeSignal({
          detector: this._name,
          category: this._pack.category,
          severity: pattern.severity,
          confidence: pattern.confidence,
          message: pattern.description,
          span: [start, end],
          matchedText: match[0],
          metadata: {
            attackType: pattern.attackType,
            pattern: pattern.regex,
          },
        });
        // Guard against zero-width matches infinite-looping.
        if (match[0].length === 0) {
          regex.lastIndex++;
        }
      }
    }
  }
}
