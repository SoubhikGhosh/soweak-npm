# React example

Two files, drop them into any Vite/CRA/Next.js project:

* `useSoweak.ts` — reusable hook that builds a `Pipeline` once and exposes
  `scanInput`, `scanOutput`, and a `secureFetch` ready to call your LLM
  backend.
* `SoweakChat.tsx` — minimal chat component that scans typed input before
  sending and scans the assistant reply before rendering it.

## Install in your app

```bash
npm install soweak
```

## What to put on the server vs the client

soweak is pure TypeScript and has no Node-only globals in its core path, so
it runs identically in the browser. There's a tradeoff:

* **Client-side scanning** (what this example shows) — catches obviously bad
  inputs before they leave the user's machine. Good UX. *Not* a security
  boundary: a malicious user can bypass any client check.
* **Server-side scanning** — the actual security boundary. Use
  `secureFetch` or `SecureOpenAI` on your API route as the source of truth.

The typical setup: run soweak in both places, with the same policy. The
client scan is for UX, the server scan is for enforcement.

## What stays Node-only

`JsonLinesAuditLog`, `FileCounterStore`, `FileWindowStore`, and `loadPolicy`
all use `fs`. They will throw if imported in the browser. Use the in-memory
or `CallbackAuditLog` sinks instead, and build policies with `buildPolicy`
on the parsed JSON.
