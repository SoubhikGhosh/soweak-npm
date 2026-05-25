/**
 * LLM10 streaming protections: repetition detection.
 *
 * When an LLM gets stuck in a loop, runtime costs balloon and output is
 * junk. RepetitionDetector flags this from streamed output.
 */

import { Detector, makeSignal, Signal } from "../core/detector.js";
import { Boundary, Context, OwaspCategory, Payload, Severity } from "../core/types.js";
import { SoweakError } from "../core/errors.js";

export class RepetitionDetector extends Detector {
  private readonly _window: number;
  private readonly _minRepeats: number;
  private readonly _boundaries: readonly Boundary[];
  private readonly _name: string;
  private readonly _patterns: Array<{ unit: number; regex: RegExp }>;

  constructor(
    options: {
      windowSize?: number;
      minRepeats?: number;
      unitSizes?: readonly number[];
      boundaries?: readonly Boundary[];
      name?: string;
    } = {},
  ) {
    super();
    const minRepeats = options.minRepeats ?? 5;
    if (minRepeats < 2) throw new SoweakError("minRepeats must be >= 2");
    this._window = options.windowSize ?? 400;
    this._minRepeats = minRepeats;
    const unitSizes = options.unitSizes ?? [3, 5, 10, 20, 40];
    this._boundaries = options.boundaries ?? [Boundary.OUTPUT, Boundary.STREAM];
    this._name = options.name ?? "repetition";
    this._patterns = unitSizes.map((n) => ({
      unit: n,
      regex: new RegExp(`(.{${n},${n}})\\1{${minRepeats - 1},}`, "s"),
    }));
  }

  override get name(): string {
    return this._name;
  }

  override get category(): OwaspCategory {
    return OwaspCategory.LLM10_UNBOUNDED_CONSUMPTION;
  }

  override get boundaries(): readonly Boundary[] {
    return this._boundaries;
  }

  override *inspect(payload: Payload, _ctx: Context): Iterable<Signal> {
    const text = payload.text;
    if (!text) return;
    const tail = text.length > this._window ? text.slice(-this._window) : text;
    for (const { unit, regex } of this._patterns) {
      const match = tail.match(regex);
      if (match && match[1]) {
        const repeatsInMatch = match[0].length / match[1].length;
        yield makeSignal({
          detector: this._name,
          category: OwaspCategory.LLM10_UNBOUNDED_CONSUMPTION,
          severity: Severity.HIGH,
          confidence: 0.9,
          message: `Output repeats ${this._minRepeats}+ times (unit=${unit} chars): ${JSON.stringify(match[1])}`,
          matchedText: match[0].slice(0, 80),
          metadata: {
            unitSize: unit,
            unit: match[1],
            repeats: Math.floor(repeatsInMatch),
          },
        });
        return;
      }
    }
  }
}
