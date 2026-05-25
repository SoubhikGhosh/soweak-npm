/**
 * Policy, Rule, and PolicyBuilder.
 */

import { Detector } from "./detector.js";
import { Enforcer } from "./enforcer.js";
import { Boundary } from "./types.js";

export interface Rule {
  boundary: Boundary;
  detectors: readonly Detector[];
  enforcer: Enforcer;
  name: string;
}

export class Policy {
  readonly rules: readonly Rule[];

  constructor(rules: readonly Rule[] = []) {
    this.rules = rules;
  }

  forBoundary(boundary: Boundary): Rule[] {
    return this.rules.filter((r) => r.boundary === boundary);
  }

  static builder(): PolicyBuilder {
    return new PolicyBuilder();
  }
}

class BoundaryClause {
  private detectors: Detector[] = [];

  constructor(
    private parent: PolicyBuilder,
    private boundary: Boundary,
    private name: string,
  ) {}

  detect(...detectors: Detector[]): BoundaryClause {
    this.detectors.push(...detectors);
    return this;
  }

  enforce(enforcer: Enforcer): PolicyBuilder {
    this.parent._commit({
      boundary: this.boundary,
      detectors: [...this.detectors],
      enforcer,
      name: this.name,
    });
    return this.parent;
  }
}

export class PolicyBuilder {
  private rules: Rule[] = [];

  onInput(name: string = "input"): BoundaryClause {
    return new BoundaryClause(this, Boundary.INPUT, name);
  }

  onRetrieval(name: string = "retrieval"): BoundaryClause {
    return new BoundaryClause(this, Boundary.RETRIEVAL, name);
  }

  onToolCall(name: string = "tool_call"): BoundaryClause {
    return new BoundaryClause(this, Boundary.TOOL_CALL, name);
  }

  onOutput(name: string = "output"): BoundaryClause {
    return new BoundaryClause(this, Boundary.OUTPUT, name);
  }

  onStream(name: string = "stream"): BoundaryClause {
    return new BoundaryClause(this, Boundary.STREAM, name);
  }

  /** @internal */
  _commit(rule: Rule): void {
    this.rules.push(rule);
  }

  build(): Policy {
    return new Policy([...this.rules]);
  }
}
