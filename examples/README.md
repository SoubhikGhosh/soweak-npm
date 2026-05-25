# soweak examples

Runnable examples covering the major use cases.

| Directory | What it shows |
| --- | --- |
| `node/01-quickstart.ts` | 60-second tour: block prompt-injection, redact PII, scan output for canary leaks. |
| `node/02-async-and-streaming.ts` | Async pipeline + StreamingPipeline guarding an LLM stream. |
| `node/03-rag-defense.ts` | RAG / LLM08: indirect injection, tenant isolation, provenance, retrieval anomaly. |
| `node/04-tool-authorization.ts` | LLM06: `guardedTool` with scopes, rate limit, human approval. |
| `node/05-budgets-and-rate-limits.ts` | LLM10: token & cost budgets + rate-limit enforcer. |
| `node/06-secure-openai.ts` | Drop-in OpenAI client wrapper (`SecureOpenAI`). |
| `node/07-secure-fetch.ts` | Universal `secureFetch` wrapper around any REST/LLM endpoint. |
| `node/08-ml-classifier-and-judge.ts` | Bring-your-own ML classifier + LLM-as-judge. |
| `node/09-grounding.ts` | LLM09: citation requirement + lexical grounding + embedding grounding. |
| `node/10-declarative-policy.ts` | Load a policy from JSON, register a custom detector. |
| `node/11-express-middleware.ts` | Wire soweak into an Express route. |
| `node/12-audit-log.ts` | InMemory, JSON-lines, and callback audit sinks. |
| `react/SoweakChat.tsx` | React chat box that pre-scans input and post-scans LLM output via `secureFetch`. |
| `react/useSoweak.ts` | Reusable React hook around a soweak pipeline. |
| `angular/soweak.service.ts` | Angular `@Injectable` service mirroring the React hook. |
| `angular/chat.component.ts` | Component using the service to scan chat I/O. |

All Node examples are TypeScript and run with:

```bash
npx tsx examples/node/01-quickstart.ts
```
