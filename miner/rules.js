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

// Solidity, applied only to .sol files (or code that declares `pragma solidity`).
// Ids match the categories PR Guard reads from reviewers' findings (src/normalize.js).
const SOLIDITY_RULES = [
  {
    id: "tx-origin",
    title: "tx.origin used for authorization",
    cwe: "CWE-863",
    test: (l) => /\btx\.origin\b\s*(==|!=)|(==|!=)\s*tx\.origin\b/.test(l),
    severity: () => "high",
    confidence: 0.85,
    fix: "check msg.sender instead; tx.origin can be any contract's caller",
  },
  {
    id: "delegatecall",
    title: "delegatecall",
    cwe: "CWE-829",
    test: (l) => /\.delegatecall\s*\(/.test(l),
    severity: () => "medium",
    confidence: 0.6,
    fix: "only delegatecall a fixed, trusted implementation; never a caller-supplied address",
  },
  {
    id: "selfdestruct",
    title: "selfdestruct",
    cwe: "CWE-284",
    test: (l) => /\b(selfdestruct|suicide)\s*\(/.test(l),
    severity: () => "medium",
    confidence: 0.7,
    fix: "remove selfdestruct, or restrict it to a governed, time-locked path",
  },
  {
    id: "unchecked-call",
    title: "low-level call result not checked",
    cwe: "CWE-252",
    // A bare statement: nothing captures or tests the returned success flag.
    test: (l) => /^\s*[\w.()[\]]+\.(call|send)\s*(\{[^}]*\})?\s*\([^;]*\)\s*;/.test(l),
    severity: () => "medium",
    confidence: 0.7,
    fix: "capture the success flag and require it, or use a safe transfer helper",
  },
];

// Multi-line Solidity patterns, over consecutive added lines of one file.
const VALUE_CALL = /\.call\s*\{\s*value\s*:|\.call\.value\s*\(/;
const STATE_WRITE = /\b\w+\s*\[[^\]]+\]\s*(=|-=|\+=)(?!=)|\b\w*(balance|deposit|share|credit)\w*\s*(=|-=)(?!=)/i;
const PUBLIC_FN = /\bfunction\s+\w+\s*\([^)]*\)([^{;]*)\b(external|public)\b([^{;]*)/;
const GUARDED = /\bonly[A-Z]\w*|\bauth\b|\binitializer\b|\brequiresAuth\b/;
const PRIVILEGED_WRITE = /\b_?(owner|admin|governance|implementation|operator|minter|treasury)\s*=(?!=)/i;
const SENDER_CHECK = /require\s*\(\s*msg\.sender\s*==|msg\.sender\s*!=|_checkOwner\s*\(|_checkRole\s*\(|hasRole\s*\(/;

function solidityFlows(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const { text: l, line, file } = lines[i];
    if (COMMENT.test(l)) continue;
    const next = lines.slice(i + 1, i + 9).filter((x) => x.file === file);
    if (VALUE_CALL.test(l) && next.some((x) => !COMMENT.test(x.text) && STATE_WRITE.test(x.text))) {
      out.push({ rule: "reentrancy", title: "state updated after an external call (reentrancy)", severity: "high", cwe: "CWE-841", ...(file && { file }), line, evidence: evidence(l), fix: "update balances before the call (checks-effects-interactions), or add a reentrancy guard", confidence: 0.75 });
    }
    const fn = l.match(PUBLIC_FN);
    if (fn && !GUARDED.test(fn[1] + fn[3])) {
      // The body: the rest of this line, then lines up to the function's closing brace.
      const body = [l.slice(l.indexOf("{") + 1)];
      for (const x of next) { if (/^\s*}\s*$/.test(x.text) || PUBLIC_FN.test(x.text)) break; body.push(x.text); }
      const text = body.join("\n");
      if (PRIVILEGED_WRITE.test(text) && !SENDER_CHECK.test(text)) {
        out.push({ rule: "access-control", title: "privileged state set without access control", severity: "high", cwe: "CWE-284", ...(file && { file }), line, evidence: evidence(l), fix: "restrict it (onlyOwner, a role, or require(msg.sender == owner))", confidence: 0.75 });
      }
    }
  }
  return out;
}

const SECRET_RULE = { id: "hardcoded-secret", cwe: "CWE-798", confidence: 0.9, fix: "move it to a secret store or environment variable, and rotate the exposed value" };

export const RULE_COUNT = RULES.length + SOLIDITY_RULES.length + 2 + 1; // + 2 multi-line Solidity patterns, + secrets

const looksLikeDiff = (text) => /^(diff --git |@@ -\d)/m.test(text);

/**
 * The lines to scan: added lines of a diff (with the file they belong to,
 * when the diff names it), or every line of plain code.
 */
export function linesOf(text) {
  if (!looksLikeDiff(text)) return text.split(/\r?\n/).map((t, i) => ({ line: i + 1, text: t }));
  // Split a multi-file diff at its file headers; a bare hunk has no file.
  const out = [];
  for (const section of text.split(/^(?=diff --git )/m)) {
    const file = section.match(/^diff --git a\/\S+ b\/(\S+)/)?.[1] ?? section.match(/^\+\+\+ b\/(\S+)/m)?.[1] ?? null;
    for (const l of addedLines(section.replace(/^diff --git .*$/gm, ""))) out.push(file ? { ...l, file } : l);
  }
  return out;
}

const evidence = (line) => redact(line.trim()).text.slice(0, 160);

/**
 * @param {string} text code, a unified diff, or a question with code in it
 * @returns {{ findings: object[], linesScanned: number }}
 */
export function scan(text) {
  const src = String(text ?? "");
  const lines = linesOf(src);
  const isSolidity = (file) => (file ? /\.sol$/i.test(file) : /\bpragma\s+solidity\b/.test(src));
  const findings = [];
  for (const { line, text: l, file } of lines) {
    for (const s of new Set(secretSpans(l).map((x) => `${x.type}\0${x.severity}`))) {
      const [type, severity] = s.split("\0");
      findings.push({ rule: SECRET_RULE.id, title: `hardcoded secret (${type.replace(/_/g, " ")})`, severity, cwe: SECRET_RULE.cwe, ...(file && { file }), line, evidence: evidence(l), fix: SECRET_RULE.fix, confidence: SECRET_RULE.confidence });
    }
    if (COMMENT.test(l)) continue;
    for (const r of isSolidity(file) ? [...RULES, ...SOLIDITY_RULES] : RULES) {
      if (r.test(l)) findings.push({ rule: r.id, title: r.title, severity: r.severity(l), cwe: r.cwe, ...(file && { file }), line, evidence: evidence(l), fix: r.fix, confidence: r.confidence });
    }
  }
  findings.push(...solidityFlows(lines.filter((x) => isSolidity(x.file))));
  return { findings, linesScanned: lines.length };
}
