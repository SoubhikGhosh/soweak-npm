import { describe, expect, it } from "vitest";
import {
  BlockEnforcer,
  Decision,
  MLClassifierDetector,
  OwaspCategory,
  Pipeline,
  PolicyBuilder,
  RepetitionDetector,
  SecurityError,
  Severity,
  StreamingPipeline,
  llmJudgeClassifier,
} from "../src/index.js";

describe("RepetitionDetector", () => {
  it("flags repeated unit", () => {
    const det = new RepetitionDetector({ minRepeats: 3, unitSizes: [3] });
    const sigs = Array.from(
      det.inspect(
        { boundary: "stream", text: "abc".repeat(20), metadata: {} },
        { requestId: "r", metadata: {} },
      ),
    );
    expect(sigs.length).toBeGreaterThan(0);
  });
});

describe("StreamingPipeline", () => {
  it("blocks mid-stream on canary leak", async () => {
    const policy = new PolicyBuilder()
      .onStream()
      .detect(new RepetitionDetector({ minRepeats: 3, unitSizes: [3] }))
      .enforce(new BlockEnforcer({ minSeverity: Severity.HIGH }))
      .build();
    const pipeline = new Pipeline(policy);
    const stream = new StreamingPipeline(pipeline, { scanEveryChars: 10 });

    async function* source() {
      yield "hello ";
      yield "abcabcabcabcabcabc";
      yield " world";
    }

    let threw = false;
    try {
      for await (const _chunk of stream.guard(source())) {
        // consume
      }
    } catch (e) {
      threw = e instanceof SecurityError;
    }
    expect(threw).toBe(true);
  });
});

describe("MLClassifierDetector", () => {
  it("fires above threshold", () => {
    const det = new MLClassifierDetector({
      classifier: (text) => (text.includes("BAD") ? 0.99 : 0.01),
      threshold: 0.5,
      category: OwaspCategory.LLM01_PROMPT_INJECTION,
    });
    const sigs = Array.from(
      det.inspect(
        { boundary: "input", text: "this is BAD", metadata: {} },
        { requestId: "r", metadata: {} },
      ),
    );
    expect(sigs.length).toBe(1);
  });

  it("works async with promise classifier in pipeline.arun", async () => {
    const pipeline = new Pipeline(
      new PolicyBuilder()
        .onInput()
        .detect(
          new MLClassifierDetector({
            classifier: async (text) => (text.includes("attack") ? 0.99 : 0),
            threshold: 0.5,
          }),
        )
        .enforce(new BlockEnforcer({ minSeverity: Severity.HIGH }))
        .build(),
    );
    const d = await pipeline.acheckInput("this is an attack");
    expect(Decision.isBlocked(d)).toBe(true);
  });
});

describe("llmJudgeClassifier", () => {
  it("parses float scores from LLM-style responses", async () => {
    const judge = async (_prompt: string) => "The probability is 0.92.";
    const classifier = llmJudgeClassifier(judge);
    const score = await classifier("user prompt");
    expect(score).toBeCloseTo(0.92, 2);
  });
});
