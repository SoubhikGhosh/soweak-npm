/**
 * Universal `secureFetch` — works in browsers, Node 18+, Deno, Bun, Workers.
 *
 * Wraps the global `fetch` so any request body is scanned at the input
 * boundary and the response JSON is scanned at the output boundary.
 *
 * Bring your own `extractInputs` / `extractOutputs` if the request/response
 * shape isn't a standard chat completion.
 */

import {
  BlockEnforcer,
  Pipeline,
  PolicyBuilder,
  SecurityError,
  Severity,
  promptInjectionDetector,
  outputHtmlDetector,
} from "../../src/index.js";
import { secureFetch } from "../../src/adapters/fetch.js";

// Mock fetch so this is runnable without network.
const mockFetch: typeof fetch = async (_input, _init) =>
  new Response(
    JSON.stringify({
      output: "<script>alert(1)</script> Hello there, here's what you asked for.",
    }),
    { headers: { "content-type": "application/json" } },
  );

const pipeline = new Pipeline(
  new PolicyBuilder()
    .onInput()
    .detect(promptInjectionDetector())
    .enforce(new BlockEnforcer({ minSeverity: Severity.HIGH }))
    .onOutput()
    .detect(outputHtmlDetector())
    .enforce(new BlockEnforcer({ minSeverity: Severity.HIGH }))
    .build(),
);

const safeFetch = secureFetch(pipeline, { fetchImpl: mockFetch });

async function main() {
  try {
    const res = await safeFetch("https://example.com/llm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt: "Tell me a story about pirates." }),
    });
    const data = await res.json();
    console.log("ok:", data);
  } catch (e) {
    if (e instanceof SecurityError) {
      console.log("[soweak] fetch blocked at", e.decision.payload.boundary, "-", e.message);
    } else {
      throw e;
    }
  }
}

main();
