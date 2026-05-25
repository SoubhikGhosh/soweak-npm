/**
 * Express middleware (works the same with Fastify, Koa, Hono, etc.).
 *
 * Pre-scan request body at /chat; reject blocked traffic with HTTP 400; pass
 * the rest through. Charge tokens after the model call returns.
 *
 * Install: npm install express @types/express
 * Run: npx tsx examples/node/11-express-middleware.ts
 */

import type { Request, Response, NextFunction } from "express";
import {
  BlockEnforcer,
  CanaryDetector,
  Decision,
  Pipeline,
  PolicyBuilder,
  Severity,
  TokenBudget,
  makeContext,
  promptInjectionDetector,
  inputDlpDetector,
  RedactEnforcer,
} from "../../src/index.js";

const pipeline = new Pipeline(
  new PolicyBuilder()
    .onInput()
    .detect(promptInjectionDetector(), inputDlpDetector())
    .enforce(new RedactEnforcer({ minSeverity: Severity.HIGH }))
    .onOutput()
    .detect(new CanaryDetector({ tokens: ["x7K2-PRODSEC-9F4E"] }))
    .enforce(new BlockEnforcer({ minSeverity: Severity.CRITICAL }))
    .build(),
);

// Exported for use in the route handler (see comment block below).
export const tokens = new TokenBudget({ limit: 1_000_000 });

export function soweakInput(req: Request, res: Response, next: NextFunction): void {
  const userId = (req.headers["x-user-id"] as string) ?? "anonymous";
  const ctx = makeContext({ userId });
  const decision = pipeline.checkInput(String(req.body?.prompt ?? ""), ctx);
  if (Decision.isBlocked(decision)) {
    res.status(400).json({
      error: "blocked by soweak",
      reason: decision.reason,
      signals: decision.signals.map((s) => ({ d: s.detector, sev: s.severity })),
    });
    return;
  }
  // Save the (possibly redacted) text for the route handler to use.
  (req as Request & { sanitizedPrompt: string }).sanitizedPrompt = decision.payload.text;
  (req as Request & { soweakCtx: typeof ctx }).soweakCtx = ctx;
  next();
}

// To wire it up in an app:
//
//   import express from "express";
//   const app = express();
//   app.use(express.json());
//   app.post("/chat", soweakInput, async (req, res) => {
//     const safePrompt = (req as any).sanitizedPrompt as string;
//     const ctx = (req as any).soweakCtx;
//     const reply = await callLLM(safePrompt);
//     const out = pipeline.checkOutput(reply, ctx);
//     if (out.action === "block") return res.status(502).json({ error: out.reason });
//     // charge usage
//     tokens.charge(ctx.userId ?? "anon", estimateTokens(safePrompt) + estimateTokens(reply));
//     res.json({ reply: out.payload.text });
//   });
//
//   app.listen(3000);

console.log("Express middleware example loaded. Wire `soweakInput` into your app.");
