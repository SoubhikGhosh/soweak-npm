# Security Policy

## Supported versions

The `0.x` line is the current development series. Until `1.0` only the
latest minor receives security fixes.

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: |

## Reporting a vulnerability

If you believe you have found a security issue in `soweak`, please **do not
open a public issue**. Instead, email the maintainers using GitHub's
security advisory flow:

1. Open [https://github.com/soweak-ai/soweak-npm/security/advisories/new](https://github.com/soweak-ai/soweak-npm/security/advisories/new).
2. Describe:
   - the affected component (e.g. `sanitizeHtml`, `secureFetch`, a specific
     pattern pack);
   - reproduction steps and the minimum input required;
   - the impact and any known affected downstream users.

You should receive an initial response within five business days. Once a
fix is ready, we will coordinate a release and a CVE if appropriate.

## Honest scope

soweak is **defence in depth**, not a replacement for the controls listed
below. Reports that demonstrate one of these "out of scope" categories are
welcome but won't be treated as security vulnerabilities:

- **Client-side bypass.** Anything running in a browser can be tampered
  with by the user. Soweak's browser usage is for UX (catch obviously bad
  inputs early); enforcement must happen server-side as well.
- **LLM09 grounding heuristics.** Lexical and embedding grounding are
  hints, not facts. A plausible fabrication that shares vocabulary or
  paraphrases the source will pass.
- **Regex coverage gaps in the pattern packs.** Patterns are intentionally
  conservative; novel injection variants we don't yet match are accepted
  as bug reports, not CVEs.
- **DoS via crafted input** that simply takes longer to scan but is
  catch-able with timeouts on the surrounding `pipeline.arun(...)` call —
  pass an `AbortSignal` (`{ signal }`) to cancel.

What we *do* treat as security issues:

- Bypasses of `sanitizeHtml` that yield executable JavaScript when
  inserted into a normal `innerHTML`.
- `secureFetch` failing to scan a body it should have scanned.
- `guardedTool` invoking the underlying function without satisfying scopes
  / approval / rate limit.
- Buffer-cap bypass in `StreamingPipeline`.
- ReDoS in shipped patterns that takes seconds or more on inputs under
  10 KB.
- Audit-log tampering or silent drops.

Thanks for keeping users safe.
