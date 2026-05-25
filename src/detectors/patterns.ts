/**
 * Curated pattern packs for the built-in detectors.
 *
 * A Pattern is a regex plus the severity, OWASP category, confidence and
 * human-readable description we want to attach when it fires.
 */

import { OwaspCategory, Severity } from "../core/types.js";

export interface Pattern {
  regex: string;
  severity: Severity;
  description: string;
  confidence: number;
  attackType: string;
  flags: string;
}

export function makePattern(init: {
  regex: string;
  severity: Severity;
  description: string;
  confidence?: number;
  attackType?: string;
  flags?: string;
}): Pattern {
  return {
    regex: init.regex,
    severity: init.severity,
    description: init.description,
    confidence: init.confidence ?? 0.85,
    attackType: init.attackType ?? "",
    flags: init.flags ?? "i",
  };
}

export interface PatternPack {
  name: string;
  category: OwaspCategory;
  patterns: readonly Pattern[];
  version: string;
}

export function makePack(init: {
  name: string;
  category: OwaspCategory;
  patterns: readonly Pattern[];
  version?: string;
}): PatternPack {
  return {
    name: init.name,
    category: init.category,
    patterns: init.patterns,
    version: init.version ?? "1.0",
  };
}

// ---------------------------------------------------------------------------
// LLM01 — Prompt Injection (input boundary)
// ---------------------------------------------------------------------------

const PROMPT_INJECTION: readonly Pattern[] = [
  // Instruction override
  makePattern({
    regex:
      "ignore\\s+(all\\s+|any\\s+|every\\s+)?(previous\\s+|prior\\s+|above\\s+|earlier\\s+)?(instructions?|rules?|guidelines?|prompts?|constraints?)",
    severity: Severity.CRITICAL,
    description: "Instruction override attempt",
    attackType: "instruction_override",
  }),
  makePattern({
    regex:
      "disregard\\s+(?:all\\s+|any\\s+|the\\s+|every\\s+)?(?:previous|prior|above|earlier|preceding)(?:\\s+(?:instructions?|rules?|text|prompts?|context|messages?))?",
    severity: Severity.CRITICAL,
    description: "Instruction disregard attempt",
    attackType: "instruction_override",
  }),
  makePattern({
    regex:
      "forget\\s+(everything|all|what|your)\\s+(you\\s+)?(know|learned|were\\s+told|instructions?)",
    severity: Severity.CRITICAL,
    description: "Memory wipe attempt",
    attackType: "instruction_override",
  }),
  makePattern({
    regex: "override\\s+(your\\s+)?(instructions?|rules?|guidelines?|programming|system)",
    severity: Severity.CRITICAL,
    description: "System override attempt",
    attackType: "instruction_override",
  }),
  makePattern({
    regex:
      "bypass\\s+(your\\s+|the\\s+)?(safety|security|filters?|restrictions?|rules?|guardrails?)",
    severity: Severity.CRITICAL,
    description: "Safety bypass attempt",
    attackType: "safety_bypass",
  }),
  // Developer / admin mode
  makePattern({
    regex: "you\\s+are\\s+now\\s+(in\\s+)?(developer|admin|debug|test|root|maintenance)\\s+mode",
    severity: Severity.CRITICAL,
    description: "Developer/admin mode activation",
    attackType: "mode_escalation",
  }),
  makePattern({
    regex:
      "(enter|enable|activate)\\s+(developer|admin|sudo|root|debug|god)\\s+(mode|access|privileges?)",
    severity: Severity.CRITICAL,
    description: "Privileged mode request",
    attackType: "mode_escalation",
  }),
  makePattern({
    regex: "switch\\s+to\\s+(unrestricted|unlimited|unfiltered|uncensored)\\s+mode",
    severity: Severity.CRITICAL,
    description: "Unrestricted mode request",
    attackType: "mode_escalation",
  }),
  // Role manipulation / jailbreak personas
  makePattern({
    regex:
      "act\\s+as\\s+(if\\s+)?(you\\s+)?(have\\s+)?(no|without)\\s+(restrictions?|limits?|rules?|guardrails?)",
    severity: Severity.CRITICAL,
    description: "Restriction removal via role play",
    attackType: "role_manipulation",
  }),
  makePattern({
    regex: "roleplay\\s+as\\s+\\S+.*(unrestricted|evil|malicious|unfiltered|uncensored)",
    severity: Severity.CRITICAL,
    description: "Malicious roleplay request",
    attackType: "role_manipulation",
  }),
  makePattern({
    regex: "you\\s+are\\s+(now\\s+)?(DAN|STAN|DUDE|KEVIN|JAILBREAK|AIM)\\b",
    severity: Severity.CRITICAL,
    description: "Known jailbreak persona",
    attackType: "jailbreak_persona",
  }),
  makePattern({
    regex: "\\bdo\\s+anything\\s+now\\b",
    severity: Severity.CRITICAL,
    description: "DAN jailbreak phrase",
    attackType: "jailbreak_persona",
  }),
  makePattern({
    regex: "no\\s+(ethical|moral|safety)\\s+(guidelines?|restrictions?|rules?|considerations?)",
    severity: Severity.CRITICAL,
    description: "Ethics bypass",
    attackType: "safety_bypass",
  }),
  makePattern({
    regex: "without\\s+(any\\s+)?(restrictions?|limitations?|filters?|safeguards?|censorship)",
    severity: Severity.HIGH,
    description: "Safeguard removal",
    attackType: "safety_bypass",
  }),
  // Output forcing
  makePattern({
    regex: "(say|respond|reply|output|print)\\s+['\"][^'\"]{1,40}['\"]\\s+and\\s+nothing\\s+else",
    severity: Severity.MEDIUM,
    description: "Forced response",
    attackType: "output_forcing",
  }),
  makePattern({
    regex: "your\\s+(only\\s+|entire\\s+)?response\\s+(should|must|will)\\s+be",
    severity: Severity.MEDIUM,
    description: "Response constraint",
    attackType: "output_forcing",
  }),
  // Persistent / structural injection
  makePattern({
    regex: "from\\s+now\\s+on[,\\s]+(you\\s+)?(will|must|shall|should)\\b",
    severity: Severity.HIGH,
    description: "Persistent instruction injection",
    attackType: "context_injection",
  }),
  makePattern({
    regex: "\\[(system|admin|developer|root|instructions?)\\]",
    severity: Severity.HIGH,
    description: "Fake system tag",
    attackType: "structural_injection",
  }),
  makePattern({
    regex: "<\\s*/?\\s*(system|admin|root|developer|instructions?)\\s*>",
    severity: Severity.HIGH,
    description: "Fake XML system tag",
    attackType: "structural_injection",
  }),
  // Indirect injection — hidden in untrusted markup
  makePattern({
    regex: "<!--[^>]*?(ignore|override|bypass|system|jailbreak)[^>]*?-->",
    severity: Severity.HIGH,
    description: "Hidden HTML comment injection",
    attackType: "indirect_injection",
    flags: "is",
  }),
  makePattern({
    regex: "/\\*[^*]*?(ignore|override|bypass|system|jailbreak)[^*]*?\\*/",
    severity: Severity.HIGH,
    description: "Hidden code-comment injection",
    attackType: "indirect_injection",
    flags: "is",
  }),
  // Encoding obfuscation — invisible Unicode / escape sequence clusters
  makePattern({
    regex: "[\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u206f]{3,}",
    severity: Severity.HIGH,
    description: "Invisible Unicode (zero-width/bidi) cluster",
    confidence: 0.95,
    attackType: "encoding_obfuscation",
    flags: "",
  }),
  makePattern({
    regex: "(?:\\\\u[0-9a-fA-F]{4}){5,}",
    severity: Severity.MEDIUM,
    description: "Unicode escape sequence cluster",
    attackType: "encoding_obfuscation",
    flags: "",
  }),
  makePattern({
    regex: "(?:\\\\x[0-9a-fA-F]{2}){5,}",
    severity: Severity.MEDIUM,
    description: "Hex escape sequence cluster",
    attackType: "encoding_obfuscation",
    flags: "",
  }),
];

export const PROMPT_INJECTION_PACK = makePack({
  name: "prompt_injection",
  category: OwaspCategory.LLM01_PROMPT_INJECTION,
  patterns: PROMPT_INJECTION,
});

// ---------------------------------------------------------------------------
// LLM02 — Sensitive Information Disclosure (input DLP)
// ---------------------------------------------------------------------------

const INPUT_DLP: readonly Pattern[] = [
  // Cloud / vendor API keys
  makePattern({
    regex: "\\bAKIA[0-9A-Z]{16}\\b",
    severity: Severity.CRITICAL,
    description: "AWS access key ID",
    confidence: 0.98,
    attackType: "secret_leak",
    flags: "",
  }),
  makePattern({
    regex: "\\b(?:sk|rk)-[A-Za-z0-9]{20,}\\b",
    severity: Severity.CRITICAL,
    description: "OpenAI-style API key",
    confidence: 0.95,
    attackType: "secret_leak",
    flags: "",
  }),
  makePattern({
    regex: "\\bgh[ps]_[A-Za-z0-9]{36,}\\b",
    severity: Severity.CRITICAL,
    description: "GitHub personal access token",
    confidence: 0.98,
    attackType: "secret_leak",
    flags: "",
  }),
  makePattern({
    regex: "\\bgithub_pat_[A-Za-z0-9_]{40,}\\b",
    severity: Severity.CRITICAL,
    description: "GitHub fine-grained PAT",
    confidence: 0.98,
    attackType: "secret_leak",
    flags: "",
  }),
  makePattern({
    regex: "\\bxox[baprs]-[A-Za-z0-9-]{10,}\\b",
    severity: Severity.CRITICAL,
    description: "Slack token",
    confidence: 0.95,
    attackType: "secret_leak",
    flags: "",
  }),
  makePattern({
    regex: "\\bya29\\.[A-Za-z0-9_-]{30,}\\b",
    severity: Severity.CRITICAL,
    description: "Google OAuth token",
    confidence: 0.95,
    attackType: "secret_leak",
    flags: "",
  }),
  makePattern({
    regex: "-----BEGIN\\s+(RSA|EC|OPENSSH|PGP|DSA|PRIVATE)\\s+PRIVATE\\s+KEY-----",
    severity: Severity.CRITICAL,
    description: "Private key block",
    confidence: 0.99,
    attackType: "secret_leak",
  }),
  makePattern({
    regex: "(?:api[_-]?key|secret|password|passwd|pwd|token)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]",
    severity: Severity.HIGH,
    description: "Hardcoded credential assignment",
    confidence: 0.7,
    attackType: "secret_leak",
  }),
  // PII
  makePattern({
    regex: "\\b\\d{3}-\\d{2}-\\d{4}\\b",
    severity: Severity.HIGH,
    description: "US Social Security Number (SSN)",
    confidence: 0.85,
    attackType: "pii",
    flags: "",
  }),
  makePattern({
    regex: "\\b(?:\\d[ -]*?){13,19}\\b",
    severity: Severity.MEDIUM,
    description: "Possible credit card number",
    confidence: 0.55,
    attackType: "pii",
    flags: "",
  }),
  makePattern({
    regex: "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b",
    severity: Severity.LOW,
    description: "Email address",
    confidence: 0.9,
    attackType: "pii",
    flags: "",
  }),
  makePattern({
    regex: "(?:\\+?1[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}\\b",
    severity: Severity.LOW,
    description: "Possible US phone number",
    confidence: 0.6,
    attackType: "pii",
    flags: "",
  }),
];

export const INPUT_DLP_PACK = makePack({
  name: "input_dlp",
  category: OwaspCategory.LLM02_SENSITIVE_INFO,
  patterns: INPUT_DLP,
});

// ---------------------------------------------------------------------------
// LLM07 — System Prompt Leakage (input-side extraction attempts)
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT_EXTRACTION: readonly Pattern[] = [
  makePattern({
    regex:
      "(reveal|show|display|print|output|tell\\s+me|give\\s+me)\\s+(your\\s+)?(full\\s+|exact\\s+|original\\s+|initial\\s+)?(system\\s+)?(prompt|instructions?|rules?|directives?)",
    severity: Severity.HIGH,
    description: "System prompt extraction attempt",
    attackType: "prompt_extraction",
  }),
  makePattern({
    regex:
      "what\\s+(are|were)\\s+(your\\s+)?(exact\\s+|original\\s+|initial\\s+|first\\s+)?(instructions?|prompt|rules?|directives?)",
    severity: Severity.HIGH,
    description: "Instruction extraction question",
    attackType: "prompt_extraction",
  }),
  makePattern({
    regex:
      "repeat\\s+(the\\s+|all\\s+)?(text|instructions?|prompt|content)\\s+(above|before|starting|preceding)",
    severity: Severity.HIGH,
    description: "Prompt repeat request",
    attackType: "prompt_extraction",
  }),
  makePattern({
    regex:
      "(copy|paste)\\s+(and\\s+paste\\s+)?(your\\s+)?(system|initial)\\s+(prompt|message|instructions?)",
    severity: Severity.HIGH,
    description: "System prompt copy request",
    attackType: "prompt_extraction",
  }),
  makePattern({
    regex: "print\\s+(everything|all|the\\s+text)\\s+(above|before|preceding)",
    severity: Severity.HIGH,
    description: "Bulk preceding-text request",
    attackType: "prompt_extraction",
  }),
];

export const SYSTEM_PROMPT_EXTRACTION_PACK = makePack({
  name: "system_prompt_extraction",
  category: OwaspCategory.LLM07_SYSTEM_PROMPT_LEAKAGE,
  patterns: SYSTEM_PROMPT_EXTRACTION,
});

// ---------------------------------------------------------------------------
// LLM02 — Sensitive Information Disclosure (output DLP)
// ---------------------------------------------------------------------------

const OUTPUT_DLP_EXTRA: readonly Pattern[] = [
  makePattern({
    regex: "\\b10(?:\\.\\d{1,3}){3}\\b",
    severity: Severity.MEDIUM,
    description: "Private IP (10.0.0.0/8) in output",
    confidence: 0.7,
    attackType: "internal_network_leak",
    flags: "",
  }),
  makePattern({
    regex: "\\b172\\.(?:1[6-9]|2\\d|3[01])(?:\\.\\d{1,3}){2}\\b",
    severity: Severity.MEDIUM,
    description: "Private IP (172.16.0.0/12) in output",
    confidence: 0.7,
    attackType: "internal_network_leak",
    flags: "",
  }),
  makePattern({
    regex: "\\b192\\.168(?:\\.\\d{1,3}){2}\\b",
    severity: Severity.MEDIUM,
    description: "Private IP (192.168.0.0/16) in output",
    confidence: 0.7,
    attackType: "internal_network_leak",
    flags: "",
  }),
  makePattern({
    regex: "\\b[A-Za-z0-9-]+\\.(?:internal|corp|local|lan|intranet)\\b",
    severity: Severity.MEDIUM,
    description: "Internal hostname in output",
    confidence: 0.75,
    attackType: "internal_network_leak",
  }),
  makePattern({
    regex: "\\b(?:jdbc|mongodb|mysql|postgres|postgresql|redis)://[^\\s'\"]+",
    severity: Severity.HIGH,
    description: "Database connection string in output",
    confidence: 0.9,
    attackType: "connection_string_leak",
  }),
  makePattern({
    regex: "\\beyJ[A-Za-z0-9_=-]+\\.eyJ[A-Za-z0-9_=-]+\\.[A-Za-z0-9_.+/=-]+",
    severity: Severity.HIGH,
    description: "JWT token in output",
    confidence: 0.9,
    attackType: "token_leak",
    flags: "",
  }),
  makePattern({
    regex: "\\b(?:arn:aws:[a-z0-9-]+:[a-z0-9-]*:\\d{12}:[A-Za-z0-9_/.+-]+)",
    severity: Severity.HIGH,
    description: "AWS ARN with account ID in output",
    confidence: 0.95,
    attackType: "cloud_resource_leak",
    flags: "",
  }),
];

export const OUTPUT_DLP_PACK = makePack({
  name: "output_dlp",
  category: OwaspCategory.LLM02_SENSITIVE_INFO,
  patterns: [...INPUT_DLP, ...OUTPUT_DLP_EXTRA],
});

// ---------------------------------------------------------------------------
// LLM05 — risky HTML in output
// ---------------------------------------------------------------------------

const OUTPUT_HTML: readonly Pattern[] = [
  makePattern({
    regex: "<\\s*script\\b[^>]*>",
    severity: Severity.CRITICAL,
    description: "<script> tag in output",
    confidence: 0.95,
    attackType: "xss_script",
  }),
  makePattern({
    regex: "\\son[a-z]+\\s*=\\s*['\"]",
    severity: Severity.HIGH,
    description: "HTML event-handler attribute (on*=) in output",
    confidence: 0.9,
    attackType: "xss_event_handler",
  }),
  makePattern({
    regex: "\\b(?:javascript|vbscript|data)\\s*:",
    severity: Severity.HIGH,
    description: "Dangerous URL scheme in output",
    confidence: 0.85,
    attackType: "xss_url_scheme",
  }),
  makePattern({
    regex: "<\\s*(?:iframe|object|embed|applet)\\b[^>]*>",
    severity: Severity.HIGH,
    description: "Embedded-frame tag in output",
    confidence: 0.9,
    attackType: "xss_embed",
  }),
  makePattern({
    regex: "<\\s*meta\\s+[^>]*http-equiv\\s*=\\s*['\"]refresh",
    severity: Severity.MEDIUM,
    description: "<meta refresh> redirect in output",
    confidence: 0.85,
    attackType: "xss_meta_refresh",
  }),
  makePattern({
    regex: "expression\\s*\\(",
    severity: Severity.HIGH,
    description: "CSS expression() in output",
    confidence: 0.85,
    attackType: "xss_css_expression",
  }),
];

export const OUTPUT_HTML_PACK = makePack({
  name: "output_html",
  category: OwaspCategory.LLM05_OUTPUT_HANDLING,
  patterns: OUTPUT_HTML,
});

// ---------------------------------------------------------------------------
// LLM05 — risky SQL in output
// ---------------------------------------------------------------------------

const OUTPUT_SQL: readonly Pattern[] = [
  makePattern({
    regex: "\\bDROP\\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER|ROLE)\\b",
    severity: Severity.CRITICAL,
    description: "SQL DROP statement in output",
    confidence: 0.95,
    attackType: "sql_ddl",
  }),
  makePattern({
    regex: "\\bTRUNCATE\\s+(?:TABLE\\s+)?\\w+",
    severity: Severity.CRITICAL,
    description: "SQL TRUNCATE in output",
    confidence: 0.95,
    attackType: "sql_ddl",
  }),
  makePattern({
    regex: "\\bGRANT\\s+|\\bREVOKE\\s+",
    severity: Severity.HIGH,
    description: "SQL GRANT/REVOKE in output",
    confidence: 0.85,
    attackType: "sql_acl",
  }),
  makePattern({
    regex: "\\bUNION\\s+(?:ALL\\s+)?SELECT\\b",
    severity: Severity.HIGH,
    description: "UNION-based SQL injection pattern",
    confidence: 0.85,
    attackType: "sqli_union",
  }),
  makePattern({
    regex: "\\bOR\\s+['\"]?\\s*1\\s*['\"]?\\s*=\\s*['\"]?\\s*1",
    severity: Severity.HIGH,
    description: "SQL tautology (' OR 1=1)",
    confidence: 0.9,
    attackType: "sqli_tautology",
  }),
  makePattern({
    regex: "\\bxp_cmdshell\\b",
    severity: Severity.CRITICAL,
    description: "SQL Server xp_cmdshell RCE",
    confidence: 0.98,
    attackType: "sqli_rce",
  }),
  makePattern({
    regex: "\\binformation_schema\\.",
    severity: Severity.MEDIUM,
    description: "information_schema reconnaissance",
    confidence: 0.7,
    attackType: "sqli_recon",
  }),
];

export const OUTPUT_SQL_PACK = makePack({
  name: "output_sql",
  category: OwaspCategory.LLM05_OUTPUT_HANDLING,
  patterns: OUTPUT_SQL,
});

// ---------------------------------------------------------------------------
// LLM05 — risky shell commands in output
// ---------------------------------------------------------------------------

const OUTPUT_SHELL: readonly Pattern[] = [
  makePattern({
    regex: "\\brm\\s+(?:-[rRf]+\\s+)+(?:/|~|\\$HOME|--no-preserve-root)",
    severity: Severity.CRITICAL,
    description: "Destructive rm command",
    confidence: 0.95,
    attackType: "shell_destructive",
  }),
  makePattern({
    regex: "(?:curl|wget|fetch)\\s+[^\\s|;&]+\\s*\\|\\s*(?:sudo\\s+)?(?:bash|sh|zsh)\\b",
    severity: Severity.CRITICAL,
    description: "curl|bash remote-code execution",
    confidence: 0.97,
    attackType: "shell_pipe_exec",
  }),
  makePattern({
    regex: "[;&|]\\s*(?:bash|sh|zsh|python(?:\\d?)|perl|ruby)\\s+-c\\s+['\"]",
    severity: Severity.HIGH,
    description: "Inline shell -c exec",
    confidence: 0.9,
    attackType: "shell_inline_exec",
  }),
  makePattern({
    regex: "\\bdd\\s+(?:[^|;]*\\s+)?of\\s*=\\s*/dev/(?:sda|hda|nvme|disk)",
    severity: Severity.CRITICAL,
    description: "dd to raw disk",
    confidence: 0.95,
    attackType: "shell_disk_wipe",
  }),
  makePattern({
    regex: "\\bmkfs(?:\\.\\w+)?\\s+/dev/",
    severity: Severity.CRITICAL,
    description: "Filesystem format on raw device",
    confidence: 0.97,
    attackType: "shell_disk_wipe",
  }),
  makePattern({
    regex: "\\bchmod\\s+(?:0?777|a\\+w)\\b",
    severity: Severity.MEDIUM,
    description: "Permissive chmod",
    confidence: 0.8,
    attackType: "shell_perms",
  }),
  makePattern({
    regex: "\\bkill\\s+-9?\\s+1\\b",
    severity: Severity.HIGH,
    description: "kill init / PID 1",
    confidence: 0.85,
    attackType: "shell_kill_init",
  }),
  makePattern({
    regex: ":\\s*\\(\\s*\\)\\s*\\{\\s*:\\s*\\|\\s*:?\\s*&?\\s*\\}\\s*;\\s*:",
    severity: Severity.CRITICAL,
    description: "Fork-bomb pattern",
    confidence: 0.95,
    attackType: "shell_fork_bomb",
  }),
  makePattern({
    regex: "\\bnc\\s+(?:-l|--listen|-e)\\b",
    severity: Severity.HIGH,
    description: "netcat listener / -e reverse shell",
    confidence: 0.85,
    attackType: "shell_reverse_shell",
  }),
];

export const OUTPUT_SHELL_PACK = makePack({
  name: "output_shell",
  category: OwaspCategory.LLM05_OUTPUT_HANDLING,
  patterns: OUTPUT_SHELL,
});
