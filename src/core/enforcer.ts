/**
 * Enforcer interface, Action, Decision.
 */

import { Signal } from "./detector.js";
import { Context, Payload } from "./types.js";

export type Action = "allow" | "warn" | "redact" | "transform" | "require_approval" | "block";

export const Action = {
  ALLOW: "allow" as const,
  WARN: "warn" as const,
  REDACT: "redact" as const,
  TRANSFORM: "transform" as const,
  REQUIRE_APPROVAL: "require_approval" as const,
  BLOCK: "block" as const,
} as const;

export interface Decision {
  action: Action;
  payload: Payload;
  signals: Signal[];
  reason: string;
  metadata: Record<string, unknown>;
}

export function makeDecision(init: {
  action: Action;
  payload: Payload;
  signals?: Signal[];
  reason?: string;
  metadata?: Record<string, unknown>;
}): Decision {
  return {
    action: init.action,
    payload: init.payload,
    signals: init.signals ?? [],
    reason: init.reason ?? "",
    metadata: init.metadata ?? {},
  };
}

export const Decision = {
  allow(payload: Payload, signals: Signal[] = []): Decision {
    return makeDecision({ action: Action.ALLOW, payload, signals });
  },
  warn(payload: Payload, signals: Signal[] = [], reason = ""): Decision {
    return makeDecision({ action: Action.WARN, payload, signals, reason });
  },
  block(payload: Payload, signals: Signal[] = [], reason = ""): Decision {
    return makeDecision({ action: Action.BLOCK, payload, signals, reason });
  },
  redact(payload: Payload, signals: Signal[] = [], reason = ""): Decision {
    return makeDecision({ action: Action.REDACT, payload, signals, reason });
  },
  transform(payload: Payload, signals: Signal[] = [], reason = ""): Decision {
    return makeDecision({ action: Action.TRANSFORM, payload, signals, reason });
  },
  isBlocked(d: Decision): boolean {
    return d.action === Action.BLOCK;
  },
  isAllowed(d: Decision): boolean {
    return (
      d.action === Action.ALLOW ||
      d.action === Action.WARN ||
      d.action === Action.REDACT ||
      d.action === Action.TRANSFORM
    );
  },
};

/**
 * An action taker. Given a payload and its signals, returns a Decision.
 */
export abstract class Enforcer {
  abstract get name(): string;
  abstract decide(payload: Payload, signals: Signal[], ctx: Context): Decision;

  async adecide(payload: Payload, signals: Signal[], ctx: Context): Promise<Decision> {
    return this.decide(payload, signals, ctx);
  }
}
