// Verdict from check outcomes.
//
// An outcome is one check on one target:
//   { check, target, status: "ok"|"failed"|"skipped", reason?,
//     severity: "none"|"low"|"medium"|"high"|"critical"|"unknown",
//     findings: [{ title, severity, ... }], confirmed, disagreement, calls: [...] }
// `confirmed` means a high/critical result is backed by deterministic evidence:
// registry-backed data about this exact package and version, PR Guard's local
// rules finding the same issue in the diff, or a local check (a committed key).
// A reviewer's opinion alone can't BLOCK a PR.

export const SEVERITIES = ["none", "low", "medium", "high", "critical"];
const rank = (s) => SEVERITIES.indexOf(s);
const isHigh = (s) => rank(s) >= rank("high");

/** Checks whose absence makes a SAFE verdict meaningless. */
export const REQUIRED_CHECKS = new Set(["deps", "diff"]);

/**
 * @param {object[]} outcomes
 * @returns {{ verdict: "SAFE"|"CAUTION"|"BLOCK", reasons: string[] }}
 */
export function decide(outcomes) {
  const block = [];
  const caution = [];
  for (const o of outcomes) {
    const label = `${o.check}: ${o.target}`;
    if (o.status === "failed") caution.push(`${label} — check failed (${o.reason ?? "unknown error"})`);
    else if (o.status === "skipped") {
      if (REQUIRED_CHECKS.has(o.check)) caution.push(`${label} — not checked (${o.reason ?? "skipped"})`);
    } else if (o.severity === "unknown") {
      caution.push(o.findings.length ? `${label} — ${o.findings.length} finding${o.findings.length === 1 ? "" : "s"}, severity not rated` : `${label} — miner answer could not be interpreted`);
    }
    else if (isHigh(o.severity) && o.confirmed) block.push(`${label} — ${o.severity}`);
    else if (isHigh(o.severity)) caution.push(`${label} — ${o.severity}, unconfirmed${o.disagreement ? " (reviewer and local rules disagree)" : ""}`);
    else if (o.disagreement) caution.push(`${label} — PR Guard's local rules flagged something the reviewer didn't`);
    else if (o.severity === "medium") caution.push(`${label} — medium`);
  }
  if (block.length) return { verdict: "BLOCK", reasons: [...block, ...caution] };
  if (caution.length) return { verdict: "CAUTION", reasons: caution };
  return { verdict: "SAFE", reasons: [] };
}

/** Whether the workflow step should fail, per the `fail-on` input. */
export function shouldFail(verdict, failOn = "block") {
  if (failOn === "never") return false;
  if (failOn === "caution") return verdict === "BLOCK" || verdict === "CAUTION";
  return verdict === "BLOCK";
}

/** Highest severity among findings ("none" if empty). */
export function maxSeverity(findings) {
  return findings.reduce((acc, f) => (rank(f.severity) > rank(acc) ? f.severity : acc), "none");
}
