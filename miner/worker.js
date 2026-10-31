// PR Guard Sentinel: a Telegraph miner for SECURITY_REVIEW_GENERAL.
//   POST /review   { code | diff | query }        rule scan + any packages named
//   POST /package  { ecosystem, name, version }   known vulnerabilities via OSV
//   GET  /health
//   GET  /miner.yaml                              this miner's Telegraph YAML
// Every answer leads with one plain sentence ("Verdict: ..."), which is what
// Telegraph's scorers read, followed by the structured fields.
import { scan, RULE_COUNT } from "./rules.js";
import { lookupPackage, packagesIn, osvEcosystem, worst, compareVersions } from "./osv.js";
import MINER_YAML from "./miner-yaml.generated.js";

export const VERSION = "0.1.0";
const MAX_BODY_BYTES = 200_000;
const RANK = ["none", "unrated", "low", "medium", "high", "critical"];

const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8" } });

/**
 * The lowest version that fixes every known vulnerability: for each one, its
 * earliest fix above the current version; then the highest of those.
 * `unfixed` counts vulnerabilities with no fix above the current version.
 */
export function upgradeAdvice(version, vulns) {
  let target = null;
  let unfixed = 0;
  for (const v of vulns) {
    const fix = v.fixed_in.filter((f) => compareVersions(f, version) > 0).sort(compareVersions)[0];
    if (!fix) unfixed++;
    else if (!target || compareVersions(fix, target) > 0) target = fix;
  }
  return { upgrade_to: target, unfixed };
}

function packageSentence(p) {
  const label = `${p.name} ${p.version} (${p.ecosystem})`;
  if (!p.vulnerabilities.length) return `${label} has no known vulnerabilities in OSV.`;
  const counts = {};
  for (const v of p.vulnerabilities) counts[v.severity] = (counts[v.severity] ?? 0) + 1;
  const bySev = Object.entries(counts).sort((a, b) => RANK.indexOf(b[0]) - RANK.indexOf(a[0])).map(([s, n]) => `${n} ${s}`).join(", ");
  const top = p.vulnerabilities.slice().sort((a, b) => RANK.indexOf(b.severity) - RANK.indexOf(a.severity))[0];
  const advice = p.upgrade_to
    ? `; upgrade to ${p.upgrade_to} or later${p.unfixed ? ` (fixes all but ${p.unfixed} with no fix yet)` : " to fix all of them"}`
    : "; no fixed version is published yet";
  return `${label} has ${p.vulnerabilities.length} known vulnerabilit${p.vulnerabilities.length === 1 ? "y" : "ies"} (${bySev}), worst: ${top.summary} [${top.id}${top.aliases[0] ? `, ${top.aliases[0]}` : ""}]${advice}.`;
}

function findingSentence(f) {
  return `${f.severity}: ${f.title} (${f.cwe}) at ${f.file ? `${f.file}:` : "line "}${f.line}: \`${f.evidence}\`; fix: ${f.fix}`;
}

/** Combine a rule scan and package lookups into one answer. */
export function compose({ findings, linesScanned }, packages, failedPackages = []) {
  const severity = worst([...findings.map((f) => f.severity), ...packages.map((p) => p.severity)]);
  const vulnerable = RANK.indexOf(severity) >= RANK.indexOf("low");
  const parts = [];
  if (findings.length) parts.push(`${findings.length} code issue${findings.length === 1 ? "" : "s"}: ${findings.slice(0, 5).map(findingSentence).join("; ")}${findings.length > 5 ? `; and ${findings.length - 5} more` : ""}.`);
  for (const p of packages) parts.push(packageSentence(p));
  for (const p of failedPackages) parts.push(`${p.name} ${p.version} (${p.ecosystem}) could not be looked up.`);
  if (!findings.length && linesScanned) parts.push(`No injection, eval, shell, deserialization, TLS, path, SSRF, XSS or hardcoded-secret patterns in ${linesScanned} line${linesScanned === 1 ? "" : "s"} scanned.`);
  const verdict = vulnerable ? "vulnerable" : severity === "unrated" ? "needs review" : "secure";
  const answer = `Verdict: ${verdict}. ${parts.join(" ")}`.trim();
  const confidence = vulnerable ? Math.max(0.6, ...findings.map((f) => f.confidence), packages.some((p) => p.vulnerabilities.length) ? 0.95 : 0) : failedPackages.length ? 0.4 : 0.6;
  return {
    answer,
    verdict,
    severity,
    confidence,
    reason: `Deterministic scan with ${RULE_COUNT} rule families over ${linesScanned} line(s)${packages.length ? ` and ${packages.length} OSV package lookup(s)` : ""}. Rule-based, not a full audit.`,
    findings,
    packages,
    method: "deterministic-rules+osv",
    version: VERSION,
    checked_at: new Date().toISOString(),
  };
}

async function readJson(request) {
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) return { error: [413, `body over ${MAX_BODY_BYTES} bytes`] };
  try {
    return { body: text ? JSON.parse(text) : {} };
  } catch {
    return { error: [400, "body must be JSON"] };
  }
}

async function lookupAll(pkgs, fetchImpl) {
  const settled = await Promise.allSettled(pkgs.map((p) => lookupPackage(p, fetchImpl)));
  return {
    packages: settled.filter((s) => s.status === "fulfilled").map((s) => ({ ...s.value, ...upgradeAdvice(s.value.version, s.value.vulnerabilities) })),
    failed: pkgs.filter((_, i) => settled[i].status === "rejected"),
  };
}

export function createHandler({ fetch: fetchImpl = (...a) => fetch(...a) } = {}) {
  return async function handle(request) {
    const url = new URL(request.url);
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      return json(200, { ok: true, name: "PR Guard Sentinel", version: VERSION, rules: RULE_COUNT, intents: ["SECURITY_REVIEW_GENERAL"] });
    }
    if (request.method === "GET" && url.pathname === "/miner.yaml") {
      return new Response(MINER_YAML, { headers: { "content-type": "text/yaml; charset=utf-8" } });
    }
    if (request.method !== "POST") return json(405, { error: "use POST" });
    const { body, error } = await readJson(request);
    if (error) return json(error[0], { error: error[1] });

    if (url.pathname === "/review") {
      const text = body.code ?? body.diff ?? body.query;
      if (typeof text !== "string" || !text.trim()) return json(400, { error: "send code, diff or query as a string" });
      const { packages, failed } = await lookupAll(packagesIn(text), fetchImpl);
      return json(200, compose(scan(text), packages, failed));
    }

    if (url.pathname === "/package") {
      const pkgs = body.name ? [{ ecosystem: body.ecosystem ?? "npm", name: body.name, version: String(body.version ?? "") }] : packagesIn(body.query);
      if (!pkgs.length || pkgs.some((p) => !p.version)) return json(400, { error: "send ecosystem, name and version, or a query like lodash@4.17.15" });
      if (pkgs.some((p) => !osvEcosystem(p.ecosystem))) return json(400, { error: `unsupported ecosystem: ${pkgs[0].ecosystem}` });
      const { packages, failed } = await lookupAll(pkgs, fetchImpl);
      if (!packages.length) return json(502, { error: "OSV lookup failed" });
      return json(200, compose({ findings: [], linesScanned: 0 }, packages, failed));
    }

    return json(404, { error: "not found" });
  };
}

export default { fetch: createHandler() };
