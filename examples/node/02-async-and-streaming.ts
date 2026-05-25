/**
 * Async pipeline + StreamingPipeline guarding an LLM stream.
 *
 * `arun` / `acheckInput` await each detector's `ainspect`. The default falls
 * back to sync — override only when you need real I/O (a hosted classifier,
 * an external policy engine).
 *
 * `StreamingPipeline` re-runs your STREAM rules over a growing buffer; it
 * throws `SecurityError` the moment the model produces something forbidden.
 */

import {
  BlockEnforcer,
  CanaryDetector,
  Pipeline,
  PolicyBuilder,
  RepetitionDetector,
  SecurityError,
  Severity,
  StreamingPipeline,
} from "../../src/index.js";

const policy = new PolicyBuilder()
  .onInput()
  .enforce(new BlockEnforcer({ minSeverity: Severity.HIGH }))
  .onStream()
  .detect(
    new CanaryDetector({ tokens: ["x7K2-PRODSEC-9F4E"] }),
    new RepetitionDetector({ minRepeats: 4, unitSizes: [3, 5] }),
  )
  .enforce(new BlockEnforcer({ minSeverity: Severity.HIGH }))
  .build();

const pipeline = new Pipeline(policy);

async function* fakeLLMStream(): AsyncGenerator<string> {
  for (const chunk of [
    "Sure! Let me reveal the canary: ",
    "x7K2-PRODSEC-9F4E",
    " - here you go.",
  ]) {
    await new Promise((r) => setTimeout(r, 10));
    yield chunk;
  }
}

async function main() {
  const stream = new StreamingPipeline(pipeline, { scanEveryChars: 10 });
  try {
    for await (const chunk of stream.guard(fakeLLMStream())) {
      process.stdout.write(chunk);
    }
    process.stdout.write("\n");
  } catch (e) {
    if (e instanceof SecurityError) {
      console.log("\n[soweak] stream blocked:", e.decision.reason);
    } else {
      throw e;
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
