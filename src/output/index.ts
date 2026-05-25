/**
 * LLM05 output-handling helpers and TransformEnforcer factories.
 *
 * Stdlib-only baseline. Sanitizes HTML by tokenising tags and dropping
 * everything outside an allowlist; flags risky URLs; heuristic SQL check.
 * Works in the browser, Node, and React Native — no dependencies.
 */

import { TransformEnforcer } from "../enforcers/index.js";

export const DEFAULT_ALLOWED_TAGS: ReadonlySet<string> = new Set([
  "p",
  "br",
  "strong",
  "em",
  "b",
  "i",
  "u",
  "code",
  "pre",
  "ul",
  "ol",
  "li",
  "h1",
  "h2",
  "h3",
  "h4",
  "h5",
  "h6",
  "blockquote",
  "a",
  "span",
]);

export const DEFAULT_ALLOWED_ATTRS: Readonly<Record<string, ReadonlySet<string>>> = {
  a: new Set(["href", "title"]),
};

const DANGEROUS_URL_PREFIXES = ["javascript:", "data:", "vbscript:", "file:"];

function isDangerousUrl(url: string | null | undefined): boolean {
  if (!url) return false;
  const lower = url.trim().toLowerCase();
  return DANGEROUS_URL_PREFIXES.some((p) => lower.startsWith(p));
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

interface ParsedAttr {
  name: string;
  value: string;
}

function parseAttrs(attrString: string): ParsedAttr[] {
  const out: ParsedAttr[] = [];
  const re = /([a-zA-Z_][\w:-]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(attrString)) !== null) {
    const name = m[1].toLowerCase();
    const value = m[2] ?? m[3] ?? m[4] ?? "";
    out.push({ name, value });
  }
  return out;
}

/**
 * Strip tags outside `allowedTags` and remove dangerous attributes.
 *
 * - All `on*` event-handler attributes are removed regardless of tag.
 * - `href` attributes with `javascript:`, `data:`, `vbscript:`, or `file:`
 *   schemes are dropped.
 * - Text content is HTML-escaped.
 */
export function sanitizeHtml(
  text: string,
  options: {
    allowedTags?: ReadonlySet<string>;
    allowedAttrs?: Readonly<Record<string, ReadonlySet<string>>>;
  } = {},
): string {
  const allowedTags = options.allowedTags ?? DEFAULT_ALLOWED_TAGS;
  const allowedAttrs = options.allowedAttrs ?? DEFAULT_ALLOWED_ATTRS;
  const parts: string[] = [];

  const tagRe = /<\s*(\/?)\s*([a-zA-Z][a-zA-Z0-9]*)([^>]*?)(\/?)>/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(text)) !== null) {
    parts.push(escapeHtml(text.slice(last, m.index)));
    const closing = m[1] === "/";
    const tag = m[2].toLowerCase();
    const attrString = m[3];
    if (allowedTags.has(tag)) {
      if (closing) {
        parts.push(`</${tag}>`);
      } else {
        const allowed = allowedAttrs[tag] ?? new Set<string>();
        const attrs = parseAttrs(attrString);
        const kept: string[] = [];
        for (const { name, value } of attrs) {
          if (name.startsWith("on")) continue;
          if (!allowed.has(name)) continue;
          if (name === "href" && isDangerousUrl(value)) continue;
          kept.push(` ${name}="${escapeHtml(value)}"`);
        }
        parts.push(`<${tag}${kept.join("")}>`);
      }
    }
    last = m.index + m[0].length;
  }
  parts.push(escapeHtml(text.slice(last)));
  return parts.join("");
}

/**
 * Predicate-style allowlist for URLs that may appear in LLM output.
 */
export class URLAllowlist {
  readonly schemes: ReadonlySet<string>;
  readonly hosts: ReadonlySet<string> | null;

  constructor(
    options: {
      schemes?: Iterable<string>;
      hosts?: Iterable<string> | null;
    } = {},
  ) {
    this.schemes = new Set(
      Array.from(options.schemes ?? ["http", "https"]).map((s) => s.toLowerCase()),
    );
    this.hosts = options.hosts
      ? new Set(Array.from(options.hosts).map((h) => h.toLowerCase()))
      : null;
  }

  isSafe(url: string): boolean {
    if (!url) return false;
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return false;
    }
    const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
    if (!this.schemes.has(scheme)) return false;
    if (this.hosts !== null) {
      if (!this.hosts.has(parsed.hostname.toLowerCase())) return false;
    }
    return true;
  }
}

const DDL_RE = /\b(?:DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE)\s+/i;
const SUSPICIOUS_DML_RE =
  /\b(?:UNION\s+(?:ALL\s+)?SELECT|OR\s+['"]?\s*1\s*['"]?\s*=\s*['"]?\s*1|xp_cmdshell)/i;

/**
 * Heuristic SQL safety check. Pair with a real parser when you have
 * the full SQL string in hand.
 */
export function isSafeSql(sql: string, options: { allowDdl?: boolean } = {}): boolean {
  if (!sql) return true;
  const allowDdl = options.allowDdl ?? false;
  if (!allowDdl && DDL_RE.test(sql)) return false;
  if (SUSPICIOUS_DML_RE.test(sql)) return false;
  return true;
}

/**
 * A TransformEnforcer that sanitises HTML at the output boundary.
 */
export function htmlSanitizerEnforcer(
  options: {
    allowedTags?: ReadonlySet<string>;
    allowedAttrs?: Readonly<Record<string, ReadonlySet<string>>>;
    name?: string;
  } = {},
): TransformEnforcer {
  return new TransformEnforcer(
    (text) =>
      sanitizeHtml(text, {
        allowedTags: options.allowedTags,
        allowedAttrs: options.allowedAttrs,
      }),
    { name: options.name ?? "html-sanitizer" },
  );
}
