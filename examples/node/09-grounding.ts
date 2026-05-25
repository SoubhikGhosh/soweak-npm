/**
 * LLM09 — Misinformation: citations + grounding.
 *
 * - CitationRequiredDetector: signals when long output makes claims without
 *   any citation marker (`[1]`, `(2)`, `[doc-id]`).
 * - GroundingDetector: flags output sentences with low lexical overlap
 *   against the retrieval context.
 * - EmbeddingGroundingDetector: cosine similarity over your embedder of
 *   choice — catches paraphrase-shaped ungrounded claims the lexical
 *   detector misses.
 *
 * None of these are fact-checkers. Treat signals as "worth a human look",
 * not "definitely false".
 */

import {
  CitationRequiredDetector,
  EmbeddingGroundingDetector,
  GroundingDetector,
  LogOnlyEnforcer,
  Pipeline,
  PolicyBuilder,
  RETRIEVED_TEXT_KEY,
  makeContext,
} from "../../src/index.js";

// 1. Citations.
const pipelineCit = new Pipeline(
  new PolicyBuilder()
    .onOutput()
    .detect(new CitationRequiredDetector({ minChars: 80 }))
    .enforce(new LogOnlyEnforcer())
    .build(),
);
const d1 = pipelineCit.checkOutput(
  "ACME was founded in 1942. Its first widget shipped in 1944. Profits grew to $1M in 1950.",
);
console.log(
  "citations:",
  d1.signals.map((s) => s.message),
);

// 2. Lexical grounding.
const pipelineGrd = new Pipeline(
  new PolicyBuilder()
    .onOutput()
    .detect(new GroundingDetector({ minOverlap: 0.3 }))
    .enforce(new LogOnlyEnforcer())
    .build(),
);
const ctx = makeContext({
  metadata: {
    [RETRIEVED_TEXT_KEY]: "ACME Inc was founded in 1942 in Seattle to build widgets.",
  },
});
const d2 = pipelineGrd.checkOutput(
  "The company moved to Antarctica and invented spaceships, with hippos as engineers.",
  ctx,
);
console.log(
  "grounding:",
  d2.signals.map((s) => s.message),
);

// 3. Embedding grounding — bring your own embedder.
// In a real app, call OpenAI embeddings or @xenova/transformers here.
const fakeEmbedder = async (texts: string[]): Promise<number[][]> =>
  texts.map((t) => {
    // Trivial bag-of-letters embedding — just for the example.
    const v = new Array(26).fill(0);
    for (const ch of t.toLowerCase()) {
      const i = ch.charCodeAt(0) - 97;
      if (i >= 0 && i < 26) v[i]++;
    }
    return v;
  });

const pipelineEmb = new Pipeline(
  new PolicyBuilder()
    .onOutput()
    .detect(new EmbeddingGroundingDetector({ embedder: fakeEmbedder, threshold: 0.5 }))
    .enforce(new LogOnlyEnforcer())
    .build(),
);

(async () => {
  const d3 = await pipelineEmb.acheckOutput(
    "ACME was incorporated in 1942. It manufactures widgets. zzz xyxy unrelated content here.",
    ctx,
  );
  console.log("embedding grounding signals:", d3.signals.length);
})();
