/**
 * Detector interface and Signal type.
 */

import { Boundary, Context, OwaspCategory, Payload, Severity } from "./types.js";

export interface Signal {
  detector: string;
  category: OwaspCategory;
  severity: Severity;
  confidence: number;
  message: string;
  span?: [number, number] | null;
  matchedText?: string | null;
  metadata: Record<string, unknown>;
}

export function makeSignal(
  init: Omit<Signal, "confidence" | "metadata"> & Partial<Pick<Signal, "confidence" | "metadata">>,
): Signal {
  return {
    detector: init.detector,
    category: init.category,
    severity: init.severity,
    confidence: init.confidence ?? 1.0,
    message: init.message,
    span: init.span ?? null,
    matchedText: init.matchedText ?? null,
    metadata: init.metadata ?? {},
  };
}

/**
 * A signal producer. Subclass and implement `inspect` (sync iterator of
 * signals). Optionally override `ainspect` when your detector performs real
 * I/O — by default it falls back to the sync impl.
 */
export abstract class Detector {
  abstract get name(): string;
  abstract get category(): OwaspCategory;

  /**
   * Boundaries where this detector is meaningful. Default: input only.
   * Advisory documentation; the framework runs the detector at whichever
   * boundary the policy attaches it to.
   */
  get boundaries(): readonly Boundary[] {
    return [Boundary.INPUT];
  }

  abstract inspect(payload: Payload, ctx: Context): Iterable<Signal>;

  async ainspect(payload: Payload, ctx: Context): Promise<Signal[]> {
    return Array.from(this.inspect(payload, ctx));
  }
}
