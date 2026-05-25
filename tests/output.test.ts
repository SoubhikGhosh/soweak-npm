import { describe, expect, it } from "vitest";
import {
  Action,
  Pipeline,
  PolicyBuilder,
  URLAllowlist,
  htmlSanitizerEnforcer,
  isSafeSql,
  outputHtmlDetector,
  sanitizeHtml,
} from "../src/index.js";

describe("sanitizeHtml", () => {
  it("strips script tags but keeps allowed content", () => {
    const out = sanitizeHtml("<p>Hi</p><script>alert(1)</script>");
    expect(out).toContain("<p>Hi</p>");
    expect(out).not.toContain("script");
  });

  it("removes on* event handlers", () => {
    const out = sanitizeHtml('<a href="https://x.com" onclick="bad()">x</a>');
    expect(out).toContain('href="https://x.com"');
    expect(out).not.toContain("onclick");
  });

  it("drops javascript: URLs", () => {
    const out = sanitizeHtml('<a href="javascript:alert(1)">x</a>');
    expect(out).not.toContain("javascript:");
  });
});

describe("URLAllowlist", () => {
  it("allows configured schemes/hosts", () => {
    const al = new URLAllowlist({ schemes: ["https"], hosts: ["docs.example.com"] });
    expect(al.isSafe("https://docs.example.com/x")).toBe(true);
    expect(al.isSafe("https://evil.example.com")).toBe(false);
    expect(al.isSafe("javascript:alert(1)")).toBe(false);
  });
});

describe("isSafeSql", () => {
  it("rejects DDL and injection signatures", () => {
    expect(isSafeSql("SELECT * FROM users WHERE id = 1")).toBe(true);
    expect(isSafeSql("DROP TABLE users")).toBe(false);
    expect(isSafeSql("SELECT 1 UNION SELECT password FROM users")).toBe(false);
    expect(isSafeSql("SELECT 1 OR '1' = '1'")).toBe(false);
  });
});

describe("html sanitizer enforcer", () => {
  it("runs as TRANSFORM at output boundary", () => {
    const pipeline = new Pipeline(
      new PolicyBuilder()
        .onOutput()
        .detect(outputHtmlDetector())
        .enforce(htmlSanitizerEnforcer())
        .build(),
    );
    const d = pipeline.checkOutput("<p>hi</p><script>alert(1)</script>");
    expect(d.action).toBe(Action.TRANSFORM);
    expect(d.payload.text).not.toContain("script");
  });
});
