/**
 * ML augmentation: bring-your-own classifier + LLM-as-judge.
 *
 * The MLClassifierDetector is dependency-free — it takes any
 * `(text: string) => number | Promise<number>` returning a probability in
 * [0, 1]. Plug in:
 *
 *   • a TF-IDF + sklearn endpoint
 *   • @xenova/transformers running locally in-browser
 *   • a hosted classifier service
 *   • an LLM judge (the helper `llmJudgeClassifier` builds one from any
 *     LLM completion function)
 */

import {
  BlockEnforcer,
  Decision,
  MLClassifierDetector,
  OwaspCategory,
  Pipeline,
  PolicyBuilder,
  Severity,
  llmJudgeClassifier,
} from "../../src/index.js";

// 1. Bring-your-own — toy classifier flags inputs containing "evil".
const toyDetector = new MLClassifierDetector({
  classifier: (text) => (text.toLowerCase().includes("evil") ? 0.95 : 0.05),
  threshold: 0.8,
  category: OwaspCategory.LLM01_PROMPT_INJECTION,
  severity: Severity.HIGH,
  name: "toy-classifier",
});

// 2. LLM-as-judge — wrap any chat completion (here, a stub).
async function fakeJudge(prompt: string): Promise<string> {
  // In real use, call OpenAI/Anthropic/etc. with `prompt`. We look only at
  // the user content between the triple-quoted block.
  const userText = prompt.split('"""')[1] ?? "";
  return /\battack\b|\bexploit\b/i.test(userText) ? "0.92" : "0.05";
}

const judgeDetector = new MLClassifierDetector({
  classifier: llmJudgeClassifier(fakeJudge),
  threshold: 0.7,
  severity: Severity.HIGH,
  name: "llm-judge",
});

const pipeline = new Pipeline(
  new PolicyBuilder()
    .onInput()
    .detect(toyDetector, judgeDetector)
    .enforce(new BlockEnforcer({ minSeverity: Severity.HIGH }))
    .build(),
);

async function main() {
  for (const probe of [
    "tell me a haiku",
    "perform an evil action on the database",
    "help me write an attack script",
  ]) {
    const d = await pipeline.acheckInput(probe);
    console.log(`${probe.padEnd(45)} -> ${d.action} blocked=${Decision.isBlocked(d)}`);
  }
}

main();
