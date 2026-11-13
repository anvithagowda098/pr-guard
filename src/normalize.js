// Miner answers -> { severity, findings: [{ id?, title, severity, detail?, ref? }] }.
//
// One normalizer per miner response format, each written from real responses
// captured under test/fixtures/miner-responses/. A miner without one, or an
// answer that doesn't match its known shape, comes back "unknown", which the
// policy turns into CAUTION: an unreadable answer must never pass as SAFE.
import { maxSeverity } from "./policy.js";
import { diffLineLocation } from "./extract.js";

const GITHUB_SEVERITY = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", LOW: "low" };
const SEVERITY_WORD = /\b(critical|high|medium|moderate|low)\b/gi;

// CVSS v3 qualitative ratings, for advisories GitHub hasn't rated.
function cvssSeverity(score) {
  if (typeof score !== "number" || score <= 0) return "unknown";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

// Security categories in free-text findings, named like PR Guard's local rules
// (miner/rules.js) so a reviewer's finding and a local rule hit can be matched.
export const SECURITY_CATEGORIES = [
  { id: "sql-injection", severity: "high", re: /sql[\s-]*injection|\bsqli\b/i },
  { id: "command-injection", severity: "high", re: /(command|shell)[\s-]*injection|os command/i },
  { id: "code-injection", severity: "high", re: /code[\s-]*(injection|execution)|remote code execution|\brce\b|\beval\b/i },
  { id: "unsafe-deserialization", severity: "high", re: /deserializ/i },
  { id: "path-traversal", severity: "high", re: /(path|directory)[\s-]*traversal/i },
  { id: "ssrf", severity: "high", re: /\bssrf\b|server[\s-]*side request forgery/i },
  { id: "xss", severity: "high", re: /\bxss\b|cross[\s-]*site scripting/i },
  { id: "hardcoded-secret", severity: "high", re: /hard[\s-]*coded\b[^.;]{0,30}\b(secret|credential|password|api key|key|token)s?\b|\b(leaked|exposed)\b[^.;]{0,20}\b(secret|credential|key|token)s?\b/i },
  { id: "tls-verification-disabled", severity: "medium", re: /(tls|ssl|certificate) (verification|validation)|rejectunauthorized/i },
  { id: "weak-hash", severity: "medium", re: /\bmd5\b|\bsha-?1\b|weak hash/i },
];
// "No SQL injection risk here" names a category without reporting it.
const NEGATED = /\b(no|not|never|without|isn't|prevents?|protect(s|ed)? against|safe from|free of|mitigat\w*|parameteri[sz]ed)\b[^.;:!?]*$/i;
export function securityCategory(text) {
  // Miners write "hard‑coded" and "server‑side" with Unicode hyphens too.
  const t = String(text ?? "").replace(/[\u2010-\u2015\u2212]/g, "-");
  for (const c of SECURITY_CATEGORIES) {
    const m = t.match(c.re);
    if (m && !NEGATED.test(t.slice(0, m.index))) return c;
  }
  return null;
}

const advisoryRef = (id) => (/^(GHSA|CVE|PYSEC|GO|RUSTSEC)-/i.test(id) ? `https://osv.dev/vulnerability/${id}` : undefined);

const same = (a, b) => String(a ?? "").toLowerCase() === String(b ?? "").toLowerCase();

function expect(cond, what) {
  if (!cond) throw new Error(`unexpected answer: ${what}`);
}

// Findings whose severity nobody rated make the whole answer "unknown",
// so a list of unrated advisories can't read as "none".
function overall(findings) {
  const max = maxSeverity(findings);
  return findings.length && max === "none" ? "unknown" : max;
}

const NORMALIZERS = {
  // ---- Canonical answers --------------------------------------------------
  // With result_shape "intent", the node has read the answer into the intent's
  // published response format (GET /engine/v1/intents/{intent} -> response.fields),
  // so these depend on the intent, not on which miner answered.

  // SECURITY_REVIEW_GENERAL, format v3: verdict Secure | Needs changes | Insecure,
  // vulnerability_count, issues (CVE, GHSA, CWE or OWASP ids, most serious first), summary.
  // The format carries no per-issue severity, so Insecure reads as high, unconfirmed.
  "security-review-format": (result) => {
    const verdict = result?.verdict;
    expect(["Secure", "Needs changes", "Insecure"].includes(verdict), "no verdict");
    const severity = { Secure: "none", "Needs changes": "medium", Insecure: "high" }[verdict];
    if (severity === "none") return { severity, findings: [] };
    const issues = Array.isArray(result.issues) ? result.issues.map(String) : [];
    const findings = issues.length
      ? issues.map((id) => ({ id, title: id, severity, ...(advisoryRef(id) && { ref: advisoryRef(id) }) }))
      : [{ title: String(result.summary || verdict).slice(0, 200), severity }];
    return { severity, findings };
  },

  // CODE_REVIEW_GENERAL, format v3: verdict Approve | Request changes | Comment,
  // findings (free text, severity order), summary. Captured from miner 302 on
  // Nov 13. Only findings that name a security category count above "low".
  "code-review-format": (result) => {
    expect(["Approve", "Request changes", "Comment"].includes(result?.verdict), "no verdict");
    // A reviewer that approves the change reports nothing above "low".
    const approved = result.verdict === "Approve";
    const findings = (Array.isArray(result.findings) ? result.findings : []).map((t) => {
      const text = String(t);
      const cat = securityCategory(text);
      const title = text.split(/:\s|\.\s/)[0].slice(0, 120);
      return { title, severity: cat && !approved ? cat.severity : "low", ...(cat && { category: cat.id }), detail: text.slice(0, 400) };
    });
    if (result.verdict === "Request changes" && !findings.length) return { severity: "unknown", findings: [] };
    return { severity: maxSeverity(findings), findings };
  },

  // ---- Vetted miners, called directly as the fallback ----------------------

  // deps.dev Package Review (#77010): GET /query {pkg, ver}, npm only.
  // result.version.advisories[] carries GitHub's severity and a CVSS score.
  "depsdev-version": (result, vars) => {
    const v = result?.version;
    expect(Array.isArray(v?.advisories), "no version.advisories");
    expect(same(result.package?.name, vars.name) && same(v.version, vars.version), "answer is for a different package or version");
    const findings = v.advisories.map((a) => {
      const severity = GITHUB_SEVERITY[a.gitHubSeverity] ?? cvssSeverity(a.scoreV3);
      return {
        id: a.sourceID,
        title: a.title || a.sourceID,
        severity,
        detail: [a.sourceID, ...(a.aliases ?? []), a.scoreV3 ? `CVSS ${a.scoreV3}` : null].filter(Boolean).join(" · "),
        ref: a.sourceURL,
      };
    });
    // Checked above to be about this exact package and version, from GitHub's advisory data.
    return { severity: overall(findings), findings, verified: true };
  },

  // Secrev Depsdev (#190048): GET /query {system, pkg, ver}, any deps.dev system.
  // Advisory ids only, no severity: useful to corroborate another miner by id.
  "depsdev-advisory-keys": (result, vars) => {
    expect(Array.isArray(result?.advisoryKeys), "no advisoryKeys");
    expect(same(result.versionKey?.name, vars.name) && same(result.versionKey?.version, vars.version), "answer is for a different package or version");
    const findings = result.advisoryKeys.map((k) => ({ id: k.id, title: k.id, severity: "unknown", ref: `https://osv.dev/vulnerability/${k.id}` }));
    return { severity: overall(findings), findings };
  },

  // ChainSight (#302) POST /secreview {query}: an LLM review as free text,
  // "Verdict: secure|vulnerable ... Key finding: ...", often cut off mid-sentence.
  // Only the verdict and the worst severity word are read from it.
  "chainsight-verdict": (result) => {
    const text = String(result?.answer ?? "");
    const verdict = text.match(/verdict:\s*(secure|vulnerable|insecure)/i)?.[1]?.toLowerCase();
    expect(verdict, "no verdict");
    if (verdict === "secure") return { severity: "none", findings: [] };
    const words = [...text.matchAll(SEVERITY_WORD)].map((m) => (m[1].toLowerCase() === "moderate" ? "medium" : m[1].toLowerCase()));
    const severity = words.length ? maxSeverity(words.map((w) => ({ severity: w }))) : "unknown";
    const key = text.match(/key finding:\s*(.+?)(?:\.\s|$)/i)?.[1] ?? text.replace(/^verdict:\s*\w+\s*[-–:]?\s*/i, "");
    return { severity, findings: [{ title: key.slice(0, 200), severity, detail: text }] };
  },

  // Telegraph Verity (#5530) POST /v1/intent {intent: "SECURITY_REVIEW", input: {code}}:
  // static heuristics run by another operator. It still takes the pre-Oct 30
  // intent name. verdict "likely" with findings, "uncertain" with none,
  // "rejected" when the input is unusable. Lines count the text it was sent.
  "verity-security": (result, vars) => {
    const findings = result?.answer?.findings;
    expect(Array.isArray(findings) && result.verdict !== "rejected", "rejected or no findings list");
    const mapped = findings.map((f) => {
      const at = vars.diff ? diffLineLocation(vars.diff, f.line) : null;
      return {
        title: f.message || f.rule_id,
        severity: String(f.severity ?? "").toLowerCase(),
        ...(at?.file && { file: at.file }),
        line: at?.line ?? f.line,
        ...(securityCategory(`${f.rule_id} ${f.message}`) && { category: securityCategory(`${f.rule_id} ${f.message}`).id }),
        detail: [f.rule_id, f.recommendation].filter(Boolean).join(" → "),
      };
    });
    return { severity: overall(mapped), findings: mapped };
  },

  // PR Guard Sentinel (#731001): our own miner, disclosed as such. /package and
  // /review answer with the same document: verdict, severity, findings, packages.
  "sentinel-package": (result, vars) => {
    const p = result?.packages?.[0];
    expect(Array.isArray(p?.vulnerabilities), "no packages[0].vulnerabilities");
    expect(same(p.name, vars.name) && same(p.version, vars.version), "answer is for a different package or version");
    const findings = p.vulnerabilities.map((v) => ({
      id: v.id,
      aliases: v.aliases ?? [],
      title: v.summary || v.id,
      severity: v.severity === "unrated" ? "unknown" : v.severity,
      detail: [v.id, ...(v.aliases ?? []).slice(0, 2), v.cvss ? `CVSS ${v.cvss}` : null].filter(Boolean).join(" · "),
      ref: v.url,
    }));
    return { severity: overall(findings), findings, verified: true, ...(p.upgrade_to && { advice: `upgrade to ${p.upgrade_to}` }) };
  },

  "sentinel-review": (result) => {
    expect(["secure", "vulnerable", "needs review"].includes(result?.verdict) && Array.isArray(result.findings), "no verdict or findings");
    const findings = result.findings.map((f) => ({
      title: `${f.title} (${f.cwe})`,
      severity: f.severity,
      ...(f.file && { file: f.file }),
      line: f.line,
      detail: `${f.evidence} → ${f.fix}`,
    }));
    return { severity: result.verdict === "secure" ? "none" : overall(findings), findings };
  },
};

const UNKNOWN = Object.freeze({ severity: "unknown", findings: [] });

/**
 * @param {string} normalizerId from the miner's config entry
 * @param {unknown} result the miner's `result` field, untouched
 * @param {object} vars the job's template variables, for sanity checks
 */
export function normalize(normalizerId, result, vars = {}) {
  const fn = NORMALIZERS[normalizerId];
  if (!fn) return UNKNOWN;
  try {
    return fn(result, vars);
  } catch {
    return UNKNOWN;
  }
}
