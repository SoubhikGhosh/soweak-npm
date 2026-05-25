/**
 * Built-in detectors and pattern packs.
 */

import { Boundary } from "../core/types.js";
import { CanaryDetector } from "./canary.js";
import { PatternMatchDetector } from "./patternMatch.js";
import {
  INPUT_DLP_PACK,
  OUTPUT_DLP_PACK,
  OUTPUT_HTML_PACK,
  OUTPUT_SHELL_PACK,
  OUTPUT_SQL_PACK,
  PROMPT_INJECTION_PACK,
  SYSTEM_PROMPT_EXTRACTION_PACK,
} from "./patterns.js";

// ---------- input boundary (LLM01 / LLM02 / LLM07) ----------

export function promptInjectionDetector(): PatternMatchDetector {
  return new PatternMatchDetector(PROMPT_INJECTION_PACK);
}

export function inputDlpDetector(): PatternMatchDetector {
  return new PatternMatchDetector(INPUT_DLP_PACK);
}

export function systemPromptExtractionDetector(): PatternMatchDetector {
  return new PatternMatchDetector(SYSTEM_PROMPT_EXTRACTION_PACK);
}

// ---------- output boundary (LLM02 output, LLM05) ----------

export function outputDlpDetector(): PatternMatchDetector {
  return new PatternMatchDetector(OUTPUT_DLP_PACK, { boundaries: [Boundary.OUTPUT] });
}

export function outputHtmlDetector(): PatternMatchDetector {
  return new PatternMatchDetector(OUTPUT_HTML_PACK, { boundaries: [Boundary.OUTPUT] });
}

export function outputSqlDetector(): PatternMatchDetector {
  return new PatternMatchDetector(OUTPUT_SQL_PACK, { boundaries: [Boundary.OUTPUT] });
}

export function outputShellDetector(): PatternMatchDetector {
  return new PatternMatchDetector(OUTPUT_SHELL_PACK, { boundaries: [Boundary.OUTPUT] });
}

export { CanaryDetector, PatternMatchDetector };
export {
  INPUT_DLP_PACK,
  OUTPUT_DLP_PACK,
  OUTPUT_HTML_PACK,
  OUTPUT_SHELL_PACK,
  OUTPUT_SQL_PACK,
  PROMPT_INJECTION_PACK,
  SYSTEM_PROMPT_EXTRACTION_PACK,
};
export { makePack, makePattern } from "./patterns.js";
export type { Pattern, PatternPack } from "./patterns.js";
