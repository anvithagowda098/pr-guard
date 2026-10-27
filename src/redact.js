// Secret handling. Two jobs:
//  - redact(): scrub anything key-shaped before diff text goes to a miner;
//  - scanSecrets(): flag secrets on added lines as local findings, which cost
//    nothing and don't depend on any miner being right.
import { addedLines, isSensitiveFile } from "./extract.js";

// AWS's documented example key ids, used throughout docs and test suites.
const AWS_EXAMPLE_IDS = new Set(["AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE"]);
const PLACEHOLDER = /^(changeme|change_me|password|secret|xxx+|\*+|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|your[-_].*|example.*|dummy.*|test.*|process\.env.*)$/i;

// `group` names the capture to replace (0 = whole match).
const RULES = [
  { type: "private_key", severity: "high", group: 0, re: /-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[\s\S]*$)/g },
  { type: "aws_access_key_id", severity: "high", group: 0, re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, skip: (m) => AWS_EXAMPLE_IDS.has(m[0]) },
  { type: "aws_secret_access_key", severity: "high", group: 1, re: /aws_?secret(?:_?access)?_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi },
  { type: "github_token", severity: "high", group: 0, re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g },
  { type: "slack_token", severity: "high", group: 0, re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: "stripe_live_key", severity: "high", group: 0, re: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g },
  { type: "google_api_key", severity: "high", group: 0, re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: "llm_api_key", severity: "high", group: 0, re: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}\b/g },
  // A bare 0x+64 hex is usually a hash; only treat it as a key when labelled as one.
  { type: "wallet_private_key", severity: "high", group: 1, re: /(?:private[_-]?key|secret[_-]?key|mnemonic|wallet[_-]?key)["']?\s*[:=]\s*["']?((?:0x)?[0-9a-fA-F]{64})\b/gi },
  { type: "jwt", severity: "medium", group: 0, re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { type: "url_credentials", severity: "medium", group: 1, re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]{3,})@/gi, skip: (m) => PLACEHOLDER.test(m[1]) },
  { type: "hardcoded_credential", severity: "medium", group: 1, re: /(?:password|passwd|secret|token|api[_-]?key)["']?\s*[:=]\s*["']([^"'\s]{8,})["']/gi, skip: (m) => PLACEHOLDER.test(m[1]) },
];

function* matches(text) {
  for (const rule of RULES) {
    for (const m of text.matchAll(rule.re)) {
      if (rule.skip?.(m)) continue;
      const value = m[rule.group];
      const start = m.index + (rule.group ? m[0].indexOf(value) : 0);
      yield { rule, start, end: start + value.length };
    }
  }
}

/** Secret-looking spans in text: [{ type, severity, start, end }]. Values are not returned. */
export function secretSpans(text) {
  return [...matches(text ?? "")].map(({ rule, start, end }) => ({ type: rule.type, severity: rule.severity, start, end }));
}

/** Replace secret-looking spans with `[REDACTED:<type>]`. */
export function redact(text) {
  if (!text) return { text: text ?? "", hits: [] };
  const spans = [...matches(text)].sort((a, b) => a.start - b.start);
  let out = "";
  let pos = 0;
  const hits = [];
  for (const { rule, start, end } of spans) {
    if (start < pos) continue; // overlapping a span already redacted
    out += text.slice(pos, start) + `[REDACTED:${rule.type}]`;
    pos = end;
    hits.push({ type: rule.type, severity: rule.severity });
  }
  return { text: out + text.slice(pos), hits };
}

/**
 * Secrets on added lines, plus any sensitive file (.env, keys) the PR adds.
 * Values are never included in the findings.
 */
export function scanSecrets(files) {
  const findings = [];
  for (const f of files) {
    if (isSensitiveFile(f.filename) && f.status !== "removed") {
      findings.push({ file: f.filename, line: null, type: "sensitive_file", severity: "high", title: `Sensitive file committed: ${f.filename}` });
    }
    for (const { line, text } of addedLines(f.patch)) {
      const seen = new Set();
      for (const { rule } of matches(text)) {
        if (seen.has(rule.type)) continue;
        seen.add(rule.type);
        findings.push({ file: f.filename, line, type: rule.type, severity: rule.severity, title: `Possible ${rule.type.replace(/_/g, " ")} committed` });
      }
    }
  }
  return findings;
}
