import { Injectable } from "@angular/core";
import {
  BlockEnforcer,
  CallbackAuditLog,
  CanaryDetector,
  Decision,
  Pipeline,
  PolicyBuilder,
  RedactEnforcer,
  Severity,
  inputDlpDetector,
  outputHtmlDetector,
  promptInjectionDetector,
} from "soweak";
import { secureFetch } from "soweak/adapters/fetch";

export interface SoweakConfig {
  canaries?: string[];
  onAudit?: (decision: Decision) => void;
}

@Injectable({ providedIn: "root" })
export class SoweakService {
  private _pipeline: Pipeline;
  private _safeFetch: typeof fetch;

  constructor() {
    this._pipeline = this.build({ canaries: ["x7K2-PRODSEC-9F4E"] });
    this._safeFetch = secureFetch(this._pipeline);
  }

  configure(config: SoweakConfig): void {
    this._pipeline = this.build(config);
    this._safeFetch = secureFetch(this._pipeline);
  }

  private build(config: SoweakConfig): Pipeline {
    const audit = config.onAudit
      ? new CallbackAuditLog((event) => config.onAudit!(event.decision))
      : null;
    const builder = new PolicyBuilder()
      .onInput("prompt-injection")
      .detect(promptInjectionDetector())
      .enforce(new BlockEnforcer({ minSeverity: Severity.HIGH }))
      .onInput("dlp")
      .detect(inputDlpDetector())
      .enforce(new RedactEnforcer({ minSeverity: Severity.HIGH }))
      .onOutput("html")
      .detect(outputHtmlDetector())
      .enforce(new BlockEnforcer({ minSeverity: Severity.HIGH }));
    if (config.canaries?.length) {
      builder
        .onOutput("canary")
        .detect(new CanaryDetector({ tokens: config.canaries }))
        .enforce(new BlockEnforcer({ minSeverity: Severity.CRITICAL }));
    }
    return new Pipeline(builder.build(), audit);
  }

  scanInput(text: string): Decision {
    return this._pipeline.checkInput(text);
  }

  scanOutput(text: string): Decision {
    return this._pipeline.checkOutput(text);
  }

  get safeFetch(): typeof fetch {
    return this._safeFetch;
  }

  get pipeline(): Pipeline {
    return this._pipeline;
  }
}
