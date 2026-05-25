import { Decision } from "../core/enforcer.js";
import { Signal } from "../core/detector.js";
import { SoweakError } from "../core/errors.js";

export class SecurityError extends SoweakError {
  readonly decision: Decision;

  constructor(decision: Decision) {
    super(decision.reason || `blocked at boundary ${decision.payload.boundary}`);
    this.name = "SecurityError";
    this.decision = decision;
    Object.setPrototypeOf(this, SecurityError.prototype);
  }

  get signals(): Signal[] {
    return this.decision.signals;
  }

  get boundary(): string {
    return this.decision.payload.boundary;
  }
}
