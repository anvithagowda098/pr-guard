// Verdict from check outcomes.
//
// An outcome is one check on one target:
//   { check, target, status: "ok"|"failed"|"skipped", reason?,
//     severity: "none"|"low"|"medium"|"high"|"critical"|"unknown",
//     findings: [{ title, severity, ... }], confirmed, disagreement, calls: [...] }
// `confirmed` means a high/critical result is backed by two agreeing miners or
// by a deterministic local check. One miner alone can't BLOCK a PR.

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
    } else if (o.severity === "unknown") caution.push(`${label} — miner answer could not be interpreted`);
    else if (isHigh(o.severity) && o.confirmed) block.push(`${label} — ${o.severity}`);
    else if (isHigh(o.severity)) caution.push(`${label} — ${o.severity}, unconfirmed${o.disagreement ? " (miners disagree)" : ""}`);
    else if (o.disagreement) caution.push(`${label} — miners disagree`);
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

/**
 * Combine two normalized opinions ({ severity, findings }) on the same target.
 * Agreement on high/critical confirms it; a high/critical answer the other
 * miner doesn't share is a disagreement.
 */
export function combineOpinions(first, second) {
  if (!second || second.severity === "unknown") return { ...first, confirmed: false, disagreement: false };
  const firstHigh = isHigh(first.severity);
  const secondHigh = isHigh(second.severity);
  return {
    severity: rank(second.severity) > rank(first.severity) ? second.severity : first.severity,
    findings: [...first.findings, ...second.findings],
    confirmed: firstHigh && secondHigh,
    disagreement: firstHigh !== secondHigh,
  };
}
