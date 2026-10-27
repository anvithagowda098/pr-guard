// Deterministic security rules for code and diffs. Same input, same answer:
// no model, no upstream. Each rule looks at one line at a time, so findings
// carry a line number and the offending code (with any secret redacted).
import { addedLines } from "../src/extract.js";
import { redact, secretSpans } from "../src/redact.js";

// Request-controlled values across common web stacks.
const USER_INPUT = /\breq\.(query|body|params|headers|cookies)\b|\brequest\.(args|form|json|GET|POST|data|values|params|query|body|files)\b|\$_(GET|POST|REQUEST|COOKIE)\b|\bctx\.(query|request|params)\b|\.FormValue\(|\.URL\.Query\(\)|\bprocess\.argv\b|\bsys\.argv\b|\binput\(/;

// A string being assembled from pieces: concatenation, template or f-string
// interpolation, %-formatting or .format().
const BUILT_STRING = /["'`]\s*\+\s*[\w$(]|[\w$)\]]\s*\+\s*["'`]|\$\{[^}]+\}|\bf["'][^"']*\{|["']\s*%\s*[\w(]|["']\s*\.format\(|["']\s*\.\s*\$\w/;

// SQL, not English that happens to say "select ... from": upper-case keywords,
// or lower-case ones in a shape prose doesn't take.
const SQL_UPPER = /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[\s\S]*?\b(FROM|INTO|SET|WHERE|VALUES)\b/;
const SQL_LOWER = /\bselect\s+(\*|[\w.]+\s*,|count\s*\()[\s\S]*\bfrom\b|\b(insert\s+into|delete\s+from)\s+[\w.`"]+|\bupdate\s+[\w.`"]+\s+set\b|\bwhere\s+[\w.]+\s*=/i;
const SQL_TEXT = { test: (l) => SQL_UPPER.test(l) || SQL_LOWER.test(l) };

const COMMENT = /^\s*(\/\/|#|\/\*|\*|--)/;

const RULES = [
  {
    id: "sql-injection",
    title: "SQL built from strings",
    cwe: "CWE-89",
    test: (l) => SQL_TEXT.test(l) && BUILT_STRING.test(l),
    severity: (l) => (USER_INPUT.test(l) ? "critical" : "high"),
    confidence: 0.85,
    fix: "use a parameterized query or the driver's placeholders",
  },
  {
    id: "command-injection",
    title: "OS command built from strings",
    cwe: "CWE-78",
    test: (l) =>
      (/\b(exec|execSync)\s*\(/.test(l) && (BUILT_STRING.test(l) || USER_INPUT.test(l))) ||
      /\bspawn(Sync)?\s*\([^)]*shell\s*:\s*true/.test(l) ||
      /\bos\.(system|popen)\s*\(|\bsubprocess\.\w+\([^)]*shell\s*=\s*True/.test(l) ||
      /\bexec\.Command\(\s*"(sh|bash|cmd(\.exe)?)"\s*,\s*"(-c|\/c)"/.test(l) ||
      /\b(system|shell_exec|passthru|popen|proc_open)\s*\(\s*\$/.test(l),
    severity: (l) => (USER_INPUT.test(l) ? "critical" : "high"),
    confidence: 0.85,
    fix: "pass arguments as an array (execFile, subprocess.run([...])) and never through a shell",
  },
  {
    id: "code-injection",
    title: "dynamic code evaluation",
    cwe: "CWE-95",
    test: (l) => /\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.run(InNewContext|InThisContext|InContext)?\s*\(|\bsetTimeout\s*\(\s*["'`]/.test(l),
    severity: (l) => (USER_INPUT.test(l) ? "critical" : "medium"),
    confidence: 0.8,
    fix: "parse the input instead of executing it (JSON.parse, a math parser, a lookup table)",
  },
  {
    id: "unsafe-deserialization",
    title: "deserializing untrusted data",
    cwe: "CWE-502",
    test: (l) =>
      /\bpickle\.loads?\s*\(|\bmarshal\.loads\s*\(|\bObjectInputStream\s*\(|\bunserialize\s*\(\s*\$/.test(l) ||
      (/\byaml\.load\s*\(/.test(l) && !/Loader\s*=\s*(yaml\.)?(Safe|CSafe)Loader/.test(l)),
    severity: (l) => (USER_INPUT.test(l) ? "critical" : "high"),
    confidence: 0.8,
    fix: "use a data-only format (JSON) or a safe loader (yaml.safe_load)",
  },
  {
    id: "tls-verification-disabled",
    title: "TLS certificate verification turned off",
    cwe: "CWE-295",
    test: (l) =>
      /rejectUnauthorized\s*:\s*false|\bverify\s*=\s*False\b|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED["'\]]*\s*=\s*["']?0|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)\b/.test(l),
    severity: () => "high",
    confidence: 0.9,
    fix: "keep verification on; trust a private CA explicitly instead",
  },
  {
    id: "path-traversal",
    title: "file path taken from the request",
    cwe: "CWE-22",
    test: (l) => /\b(readFile|readFileSync|createReadStream|sendFile|send_file|open|os\.Open|file_get_contents)\s*\(/.test(l) && USER_INPUT.test(l),
    severity: () => "high",
    confidence: 0.7,
    fix: "resolve the path against a fixed root and reject anything that escapes it",
  },
  {
    id: "ssrf",
    title: "server-side request to a URL from the request",
    cwe: "CWE-918",
    test: (l) => /\b(fetch|axios(\.\w+)?|got|requests\.\w+|urlopen|http\.Get|curl_init)\s*\(/.test(l) && USER_INPUT.test(l),
    severity: () => "high",
    confidence: 0.7,
    fix: "allow-list destination hosts and block private address ranges",
  },
  {
    id: "xss",
    title: "unescaped HTML output",
    cwe: "CWE-79",
    // A plain string literal assigned to innerHTML is fine; anything else isn't.
    test: (l) => /\.(innerHTML|outerHTML)\s*=(?!=)(?!\s*["'`][^"'`$]*["'`]\s*;?\s*$)|dangerouslySetInnerHTML|\bdocument\.write\s*\(|\bmark_safe\s*\(|\|\s*safe\b/.test(l),
    severity: (l) => (USER_INPUT.test(l) ? "high" : "medium"),
    confidence: 0.6,
    fix: "set textContent, or escape/sanitize before inserting HTML",
  },
  {
    id: "weak-hash",
    title: "weak hash (MD5/SHA-1)",
    cwe: "CWE-328",
    test: (l) => /createHash\(\s*["'](md5|sha1)["']\)|\bhashlib\.(md5|sha1)\s*\(|MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"|\b(md5|sha1)\s*\(\s*\$/.test(l),
    severity: (l) => (/pass(word|wd)?/i.test(l) ? "high" : "low"),
    confidence: 0.6,
    fix: "use bcrypt/argon2 for passwords and SHA-256+ elsewhere",
  },
  {
    id: "debug-enabled",
    title: "debug mode enabled",
    cwe: "CWE-489",
    test: (l) => /\bapp\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b/.test(l),
    severity: () => "medium",
    confidence: 0.6,
    fix: "drive debug mode from the environment and keep it off in production",
  },
];

const SECRET_RULE = { id: "hardcoded-secret", cwe: "CWE-798", confidence: 0.9, fix: "move it to a secret store or environment variable, and rotate the exposed value" };

export const RULE_COUNT = RULES.length + 1;

const looksLikeDiff = (text) => /^(diff --git |@@ -\d)/m.test(text);

/** The lines to scan: added lines of a diff, or every line of plain code. */
export function linesOf(text) {
  if (looksLikeDiff(text)) return addedLines(text.replace(/^diff --git .*$/gm, ""));
  return text.split(/\r?\n/).map((t, i) => ({ line: i + 1, text: t }));
}

const evidence = (line) => redact(line.trim()).text.slice(0, 160);

/**
 * @param {string} text code, a unified diff, or a question with code in it
 * @returns {{ findings: object[], linesScanned: number }}
 */
export function scan(text) {
  const lines = linesOf(String(text ?? ""));
  const findings = [];
  for (const { line, text: l } of lines) {
    for (const s of new Set(secretSpans(l).map((x) => `${x.type}\0${x.severity}`))) {
      const [type, severity] = s.split("\0");
      findings.push({ rule: SECRET_RULE.id, title: `hardcoded secret (${type.replace(/_/g, " ")})`, severity, cwe: SECRET_RULE.cwe, line, evidence: evidence(l), fix: SECRET_RULE.fix, confidence: SECRET_RULE.confidence });
    }
    if (COMMENT.test(l)) continue;
    for (const r of RULES) {
      if (r.test(l)) findings.push({ rule: r.id, title: r.title, severity: r.severity(l), cwe: r.cwe, line, evidence: evidence(l), fix: r.fix, confidence: r.confidence });
    }
  }
  return { findings, linesScanned: lines.length };
}
