import { describe, expect, it } from "vitest";
import {
  ApprovalRequired,
  GRANTED_SCOPES_KEY,
  PermissionError,
  TOOL_AUDIT_KEY,
  authorize,
  currentContext,
  guardedTool,
  makeContext,
} from "../src/index.js";

describe("guardedTool", () => {
  it("rejects calls outside authorize()", () => {
    const sendEmail = guardedTool(
      function sendEmail(_to: string) {
        return "ok";
      },
      { scopes: ["email:send"] },
    );
    expect(() => sendEmail("x@y.z")).toThrow(PermissionError);
  });

  it("allows calls with granted scopes", () => {
    const sendEmail = guardedTool(
      function sendEmail(_to: string) {
        return "ok";
      },
      { scopes: ["email:send"] },
    );
    const ctx = makeContext({
      userId: "alice",
      metadata: { [GRANTED_SCOPES_KEY]: ["email:send"] },
    });
    const result = authorize(ctx, () => sendEmail("x@y.z"));
    expect(result).toBe("ok");
  });

  it("rejects when scope is missing", () => {
    const sendEmail = guardedTool(function sendEmail() {}, { scopes: ["email:send"] });
    const ctx = makeContext({ userId: "alice", metadata: { [GRANTED_SCOPES_KEY]: [] } });
    expect(() => authorize(ctx, () => sendEmail())).toThrow(PermissionError);
  });

  it("respects approval=human", () => {
    let asked = 0;
    const danger = guardedTool(function danger() {}, {
      scopes: ["dangerous"],
      approval: "human",
      approvalHandler: () => {
        asked += 1;
        return false;
      },
    });
    const ctx = makeContext({
      userId: "alice",
      metadata: { [GRANTED_SCOPES_KEY]: ["dangerous"] },
    });
    expect(() => authorize(ctx, () => danger())).toThrow(ApprovalRequired);
    expect(asked).toBe(1);
  });

  it("rate-limits per (tool, user)", () => {
    const ping = guardedTool(function ping() {}, {
      scopes: [],
      rateLimitPerMinute: 2,
    });
    const ctx = makeContext({ userId: "alice" });
    authorize(ctx, () => {
      ping();
      ping();
      expect(() => ping()).toThrow(PermissionError);
    });
  });

  it("emits tool audit events", () => {
    const events: unknown[] = [];
    const tool = guardedTool(function ok() {
      return 1;
    });
    const ctx = makeContext({
      userId: "alice",
      metadata: { [TOOL_AUDIT_KEY]: (e: unknown) => events.push(e) },
    });
    authorize(ctx, () => tool());
    expect(events).toHaveLength(1);
  });

  it("currentContext reflects nesting", () => {
    const outer = makeContext({ userId: "outer" });
    const inner = makeContext({ userId: "inner" });
    authorize(outer, () => {
      expect(currentContext()?.userId).toBe("outer");
      authorize(inner, () => {
        expect(currentContext()?.userId).toBe("inner");
      });
      expect(currentContext()?.userId).toBe("outer");
    });
    expect(currentContext()).toBeNull();
  });
});
