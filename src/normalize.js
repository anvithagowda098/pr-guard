// Miner answers -> { severity, findings: [{ id?, title, severity, detail?, ref? }] }.
//
// One normalizer per miner response format, each written from real responses
// captured under test/fixtures/miner-responses/. A miner without one, or an
// answer that doesn't match its known shape, comes back "unknown", which the
// policy turns into CAUTION: an unreadable answer must never pass as SAFE.
import { maxSeverity } from "./policy.js";

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
    return { severity: overall(findings), findings };
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
    return { severity: overall(findings), findings, ...(p.upgrade_to && { advice: `upgrade to ${p.upgrade_to}` }) };
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
