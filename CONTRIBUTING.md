# Contributing to soweak

Thanks for taking the time to contribute.

## Code of conduct

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

```bash
git clone https://github.com/soweak-ai/soweak-npm.git
cd soweak-npm
npm install
npm run check    # typecheck + lint + format + tests
npm run build    # build cjs + esm + types
npm run test:dist  # smoke test against built dist/
```

Node ≥ 18 is required for development.

## Layout

```
src/
  core/         # types, detector, enforcer, policy, pipeline, audit, errors
  detectors/    # pattern packs + factories
  enforcers/    # block, redact, transform, threshold, log
  output/       # sanitizeHtml, URLAllowlist, isSafeSql, htmlSanitizerEnforcer
  agent/        # guardedTool, authorize, currentContext
  budget/       # TokenBudget, CostBudget, RateLimiter + enforcers
  storage/      # in-memory CounterStore / WindowStore
  rag/          # IndirectInjection / TenantIsolation / Provenance / Anomaly
  grounding/    # CitationRequired / Grounding / EmbeddingGrounding
  streaming/    # RepetitionDetector
  ml/           # MLClassifierDetector + llmJudgeClassifier
  config/       # buildPolicy (browser-safe)
  adapters/     # openai, anthropic, fetch, errors
  node/         # Node-only: JsonLinesAuditLog, File*Store, loadPolicy
  index.ts      # main browser-safe entry
tests/          # vitest specs
examples/       # runnable Node, React, Angular examples
scripts/        # build & smoke scripts
```

## Where new defences go

A new defence goes at the **right boundary** — that's the whole
architectural premise. New input-side patterns that try to "cover"
output-boundary problems will be rejected.

| If you're defending against...     | Add a detector at boundary | Or add an enforcer for      |
| ---------------------------------- | -------------------------- | --------------------------- |
| user-supplied prompt injection     | `input`                    | block / threshold           |
| PII / secrets in the prompt        | `input`                    | redact / block              |
| docs that smuggle instructions     | `retrieval`                | block / require_approval    |
| cross-tenant retrieval             | `retrieval`                | block                       |
| ungrounded model claims            | `output`                   | warn / require_approval     |
| risky HTML / SQL / shell in output | `output`                   | transform / block           |
| canary / system-prompt leakage     | `output` / `stream`        | block                       |
| repeating model loops              | `stream`                   | block                       |
| over-quota usage                   | `input` (gate)             | block (`BudgetEnforcer`)    |
| dangerous tool execution           | n/a                        | `guardedTool` + scopes/approval |

If you're not sure where a defence belongs, open a draft PR and we'll work
it out together.

## Style

- `npm run format` (Prettier) and `npm run lint` (ESLint) must be clean.
- Stick to TypeScript's strict mode; no `any` in public APIs.
- Public APIs need JSDoc with one short summary line. Code comments
  explain **why**, not **what** — well-named identifiers explain the what.
- Don't write your own `require()` calls — Node-only modules belong under
  `src/node/` and `import` from `node:*` instead.

## Adding a pattern

1. Add the regex to the appropriate pack in `src/detectors/patterns.ts`.
2. Test it against a couple of true positives **and** a true negative in
   `tests/`.
3. Run the pattern at the right severity — `CRITICAL` only for clear-cut
   attacks, `HIGH` for strong heuristics, lower for noisy signals you'd
   want as `WARN` rather than `BLOCK`.

## Adding a detector

1. New file under `src/detectors/`, `src/rag/`, etc.
2. Extend `Detector`; implement `inspect` (sync) and optionally
   `ainspect` (async).
3. Add a factory function and a registry entry in
   `src/config/index.ts` so the declarative loader can build it.
4. Tests + an example snippet in `examples/`.

## Tests

```bash
npm test            # node environment
npm run test:browser  # happy-dom environment (validates browser safety)
npm run test:dist   # against the built dist/
```

Don't disable tests. Don't snapshot match large outputs. Be specific in
assertions: every signal field that matters in production should be
asserted somewhere.

## Releasing

Releases run via the `release.yml` workflow on a `v*` tag. Locally:

```bash
npm version <patch|minor|major>
git push --follow-tags
```

The workflow runs `npm run check`, builds, smoke-tests the dist, and
publishes with npm provenance.

## License

By contributing you agree your code will be licensed under Apache-2.0.
