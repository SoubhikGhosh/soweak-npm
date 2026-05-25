/**
 * Tool authorization (LLM06 — Excessive Agency).
 *
 * `guardedTool` couples three checks to every tool call:
 *   1. scopes — `ctx.metadata.grantedScopes` must include the required set
 *   2. approval — when `approval: 'human'`, an approval handler must return true
 *   3. rate limit — per-(tool, user) per minute
 *
 * Audit events go to `ctx.metadata.toolAuditCallback` if set.
 */

import {
  ApprovalRequired,
  GRANTED_SCOPES_KEY,
  PermissionError,
  TOOL_AUDIT_KEY,
  authorize,
  guardedTool,
  makeContext,
} from "../../src/index.js";

// Pretend implementation.
function _sendEmail(to: string, subject: string, body: string) {
  console.log(`[email] to=${to} subject=${subject} body=${body.slice(0, 30)}...`);
}

const sendEmail = guardedTool(
  function sendEmail(to: string, subject: string, body: string) {
    _sendEmail(to, subject, body);
    return "ok";
  },
  {
    scopes: ["email:send"],
    approval: "human",
    rateLimitPerMinute: 3,
    approvalHandler: (call) => {
      // Plug in your real approval UI / Slack bot / pager here.
      console.log(`[approval] approve ${call.tool} for user=${call.userId}? auto-yes`);
      return true;
    },
  },
);

const ctx = makeContext({
  userId: "alice",
  metadata: {
    [GRANTED_SCOPES_KEY]: ["email:send"],
    [TOOL_AUDIT_KEY]: (e: unknown) => console.log("[audit]", JSON.stringify(e)),
  },
});

authorize(ctx, () => {
  sendEmail("alice@example.com", "hello", "first call");
  sendEmail("alice@example.com", "hello", "second call");
  sendEmail("alice@example.com", "hello", "third call");
  try {
    sendEmail("alice@example.com", "hello", "fourth call should rate-limit");
  } catch (e) {
    if (e instanceof PermissionError) {
      console.log("rate limit hit:", e.message);
    }
  }
});

// Without scope:
const noScope = makeContext({ userId: "carol" });
try {
  authorize(noScope, () => sendEmail("x@y.z", "hi", "body"));
} catch (e) {
  if (e instanceof PermissionError) console.log("no-scope rejection:", e.message);
}

// Approval rejected:
const denied = guardedTool(function danger() {}, {
  approval: "human",
  approvalHandler: () => false,
});
const ctx2 = makeContext({ userId: "alice" });
try {
  authorize(ctx2, () => denied());
} catch (e) {
  if (e instanceof ApprovalRequired) console.log("approval denied:", e.message);
}
