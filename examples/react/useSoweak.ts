import { useMemo } from "react";
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

export interface UseSoweakOptions {
  canaries?: string[];
  onAudit?: (decision: Decision) => void;
  // When wiring up to your LLM endpoint, point this at it.
  llmEndpoint?: string;
}

export function useSoweak(options: UseSoweakOptions = {}) {
  const { canaries = [], onAudit, llmEndpoint } = options;

  const pipeline = useMemo(() => {
    const audit = onAudit ? new CallbackAuditLog((event) => onAudit(event.decision)) : null;
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
    if (canaries.length > 0) {
      builder
        .onOutput("canary")
        .detect(new CanaryDetector({ tokens: canaries }))
        .enforce(new BlockEnforcer({ minSeverity: Severity.CRITICAL }));
    }
    return new Pipeline(builder.build(), audit);
  }, [canaries.join("|"), onAudit]);

  const safeFetch = useMemo(() => secureFetch(pipeline), [pipeline]);

  const scanInput = (text: string) => pipeline.checkInput(text);
  const scanOutput = (text: string) => pipeline.checkOutput(text);

  const ask = async (prompt: string): Promise<string> => {
    if (!llmEndpoint) throw new Error("useSoweak: llmEndpoint not configured");
    const res = await safeFetch(llmEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt }),
    });
    const data = (await res.json()) as { output?: string; content?: string };
    return data.output ?? data.content ?? "";
  };

  return { pipeline, scanInput, scanOutput, safeFetch, ask };
}
