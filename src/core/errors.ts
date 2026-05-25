/**
 * Error hierarchy.
 *
 * Every error soweak throws extends `SoweakError`. Subclasses preserve the
 * narrower `instanceof` checks callers may already depend on (e.g.
 * `SecurityError`, `BudgetExceededError`, `PermissionError`).
 */

export class SoweakError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = "SoweakError";
    // Preserve cause if supplied (Node ≥ 16.9 / modern browsers).
    if (options && "cause" in options) {
      // @ts-expect-error - cause exists on Error in ES2022 but lib targets vary
      this.cause = options.cause;
    }
    // Keep prototype chain correct across transpilation.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ConfigurationError extends SoweakError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ConfigurationError";
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}
