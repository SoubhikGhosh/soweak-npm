/**
 * Audit log: AuditEvent + sinks (in-memory, JSON-lines file, callback).
 */

import { Signal } from "./detector.js";
import { Action, Decision } from "./enforcer.js";
import { Boundary } from "./types.js";

export interface AuditEvent {
  requestId: string;
  boundary: Boundary;
  signals: Signal[];
  decision: Decision;
  timestamp: Date;
}

export interface AuditEventDict {
  timestamp: string;
  request_id: string;
  boundary: Boundary;
  signals: Array<{
    detector: string;
    category: string;
    severity: string;
    confidence: number;
    message: string;
    span: [number, number] | null;
    matched_text: string | null;
    metadata: Record<string, unknown>;
  }>;
  decision: {
    action: Action;
    reason: string;
    metadata: Record<string, unknown>;
  };
}

import { severityLabel } from "./types.js";

export function auditEventToDict(e: AuditEvent): AuditEventDict {
  return {
    timestamp: e.timestamp.toISOString(),
    request_id: e.requestId,
    boundary: e.boundary,
    signals: e.signals.map((s) => ({
      detector: s.detector,
      category: s.category,
      severity: severityLabel(s.severity),
      confidence: s.confidence,
      message: s.message,
      span: s.span ?? null,
      matched_text: s.matchedText ?? null,
      metadata: s.metadata,
    })),
    decision: {
      action: e.decision.action,
      reason: e.decision.reason,
      metadata: e.decision.metadata,
    },
  };
}

export function auditEventToJson(e: AuditEvent): string {
  return JSON.stringify(auditEventToDict(e));
}

export abstract class AuditLog {
  abstract record(event: AuditEvent): void;

  async arecord(event: AuditEvent): Promise<void> {
    this.record(event);
  }

  close(): void {
    // default no-op
  }
}

/** Keeps events in memory. Useful for tests and short-lived processes. */
export class InMemoryAuditLog extends AuditLog {
  private _events: AuditEvent[] = [];

  override record(event: AuditEvent): void {
    this._events.push(event);
  }

  get events(): readonly AuditEvent[] {
    return this._events;
  }

  clear(): void {
    this._events = [];
  }

  get length(): number {
    return this._events.length;
  }
}

/**
 * Calls a user-supplied function for every event. Works in browser, Node,
 * React Native, anywhere. Most flexible sink — wire it to your logger,
 * OTLP exporter, fetch POST, etc.
 */
export class CallbackAuditLog extends AuditLog {
  constructor(private fn: (event: AuditEvent) => void | Promise<void>) {
    super();
  }

  override record(event: AuditEvent): void {
    void this.fn(event);
  }

  override async arecord(event: AuditEvent): Promise<void> {
    await this.fn(event);
  }
}
