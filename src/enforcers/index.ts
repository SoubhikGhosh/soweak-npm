/**
 * Built-in enforcers: Block, Redact, LogOnly, Threshold, Transform.
 */

import { Signal } from "../core/detector.js";
import { Action, Decision, Enforcer, makeDecision } from "../core/enforcer.js";
import { Context, Payload, Severity, severityLabel, severityWeight } from "../core/types.js";
import { SoweakError } from "../core/errors.js";

function maxSeverity(signals: Signal[]): Severity | null {
  if (signals.length === 0) return null;
  let max: Severity = signals[0].severity;
  for (let i = 1; i < signals.length; i++) {
    if (signals[i].severity > max) max = signals[i].severity;
  }
  return max;
}

export class BlockEnforcer extends Enforcer {
  private readonly _minSeverity: Severity;
  private readonly _name: string;

  constructor(options: { minSeverity?: Severity; name?: string } = {}) {
    super();
    this._minSeverity = options.minSeverity ?? Severity.HIGH;
    this._name = options.name ?? "block";
  }

  get name(): string {
    return this._name;
  }

  decide(payload: Payload, signals: Signal[], _ctx: Context): Decision {
    const max = maxSeverity(signals);
    if (max !== null && max >= this._minSeverity) {
      return makeDecision({
        action: Action.BLOCK,
        payload,
        signals: [...signals],
        reason: `max severity ${severityLabel(max)} >= ${severityLabel(this._minSeverity)}`,
      });
    }
    if (signals.length > 0) {
      return makeDecision({ action: Action.WARN, payload, signals: [...signals] });
    }
    return Decision.allow(payload);
  }
}

export class RedactEnforcer extends Enforcer {
  private readonly _placeholder: string;
  private readonly _minSeverity: Severity;
  private readonly _name: string;

  constructor(
    options: {
      placeholder?: string;
      minSeverity?: Severity;
      name?: string;
    } = {},
  ) {
    super();
    this._placeholder = options.placeholder ?? "[REDACTED]";
    this._minSeverity = options.minSeverity ?? Severity.LOW;
    this._name = options.name ?? "redact";
  }

  get name(): string {
    return this._name;
  }

  decide(payload: Payload, signals: Signal[], _ctx: Context): Decision {
    const eligible = signals.filter(
      (s) => s.span !== null && s.span !== undefined && s.severity >= this._minSeverity,
    );
    if (eligible.length === 0) {
      return makeDecision({
        action: signals.length > 0 ? Action.WARN : Action.ALLOW,
        payload,
        signals: [...signals],
      });
    }
    const spans: Array<[number, number]> = eligible
      .map((s) => s.span as [number, number])
      .slice()
      .sort((a, b) => b[0] - a[0]);
    let text = payload.text;
    for (const [start, end] of spans) {
      text = text.slice(0, start) + this._placeholder + text.slice(end);
    }
    const newPayload: Payload = { ...payload, text };
    return makeDecision({
      action: Action.REDACT,
      payload: newPayload,
      signals: [...signals],
      reason: `redacted ${spans.length} span(s)`,
    });
  }
}

export class LogOnlyEnforcer extends Enforcer {
  private readonly _name: string;

  constructor(options: { name?: string } = {}) {
    super();
    this._name = options.name ?? "log-only";
  }

  get name(): string {
    return this._name;
  }

  decide(payload: Payload, signals: Signal[], _ctx: Context): Decision {
    return makeDecision({
      action: signals.length > 0 ? Action.WARN : Action.ALLOW,
      payload,
      signals: [...signals],
    });
  }
}

/**
 * Score = Σ(severity_weight × confidence). Block above `blockAt`,
 * warn above `warnAt`, otherwise allow.
 */
export class ThresholdEnforcer extends Enforcer {
  private readonly _blockAt: number;
  private readonly _warnAt: number;
  private readonly _name: string;

  constructor(options: { blockAt?: number; warnAt?: number; name?: string } = {}) {
    super();
    const blockAt = options.blockAt ?? 1.0;
    const warnAt = options.warnAt ?? 0.5;
    if (blockAt < warnAt) {
      throw new SoweakError("blockAt must be >= warnAt");
    }
    this._blockAt = blockAt;
    this._warnAt = warnAt;
    this._name = options.name ?? "threshold";
  }

  get name(): string {
    return this._name;
  }

  decide(payload: Payload, signals: Signal[], _ctx: Context): Decision {
    const score = signals.reduce((acc, s) => acc + severityWeight(s.severity) * s.confidence, 0);
    if (score >= this._blockAt) {
      return makeDecision({
        action: Action.BLOCK,
        payload,
        signals: [...signals],
        reason: `score ${score.toFixed(2)} >= blockAt ${this._blockAt}`,
        metadata: { score },
      });
    }
    if (score >= this._warnAt) {
      return makeDecision({
        action: Action.WARN,
        payload,
        signals: [...signals],
        reason: `score ${score.toFixed(2)} >= warnAt ${this._warnAt}`,
        metadata: { score },
      });
    }
    return makeDecision({
      action: Action.ALLOW,
      payload,
      signals: [...signals],
      metadata: { score },
    });
  }
}

export class TransformEnforcer extends Enforcer {
  private readonly _transform: (text: string) => string;
  private readonly _name: string;

  constructor(transform: (text: string) => string, options: { name?: string } = {}) {
    super();
    this._transform = transform;
    this._name = options.name ?? "transform";
  }

  get name(): string {
    return this._name;
  }

  decide(payload: Payload, signals: Signal[], _ctx: Context): Decision {
    const newText = this._transform(payload.text);
    const newPayload: Payload = { ...payload, text: newText };
    return makeDecision({
      action: Action.TRANSFORM,
      payload: newPayload,
      signals: [...signals],
      reason: "payload transformed",
    });
  }
}
