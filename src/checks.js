// What to check on a PR: paid jobs for miners, plus local checks that need no
// miner (secrets on added lines, new install scripts).
import { chunkDiff, extractUrls, extractAddresses, addressChanges } from "./extract.js";
import { scanSecrets } from "./redact.js";
import { maxSeverity } from "./policy.js";

export const ALL_CHECKS = ["deps", "diff", "addresses", "patch", "urls"];

// Paid checks with vetted, routable miners today; the others stay opt-in.
export const DEFAULT_CHECKS = ["deps", "diff", "addresses"];

// Canonical params are at most 2,000 characters a string (refused above that).
export const ROUTE_MAX_CHARS = 2000;

// deps.dev's names for our ecosystems.
const DEPSDEV_SYSTEM = { npm: "npm", PyPI: "pypi", Go: "go", "crates.io": "cargo" };

/**
 * Which changed packages to check first when there are more than the cap:
 * direct dependencies, then packages the PR title names (dependency bots
 * write "Bump lodash from 4.17.15 to 4.17.21"), then upgrades of existing
 * packages, then newly added ones. Stable within each group.
 */
export function rankDeps(deps, title = "") {
  const named = new Set(String(title).toLowerCase().match(/[@\w./-]+/g) ?? []);
  const rank = (d) => (d.direct ? 0 : named.has(d.name.toLowerCase()) ? 1 : d.from ? 2 : 3);
  return deps.map((d, i) => [d, i]).sort((a, b) => rank(a[0]) - rank(b[0]) || a[1] - b[1]).map(([d]) => d);
}

/**
 * Paid jobs in priority order: direct dependencies, the diff, new on-chain
 * addresses, transitive dependencies, the patch-vs-description check, then URLs. The budget is
 * spent front to back, so low-value checks are the ones that get skipped.
 *
 * @param {object} pr
 * @param {object[]} pr.deps merged dependency changes (extract.mergeDependencyChanges)
 * @param {object[]} pr.files redacted PR files ({ filename, patch })
 * @param {string} pr.title
 * @param {string} pr.body
 * @param {Set<string>} enabled check names
 */
export function buildJobs({ deps, files, title, body }, enabled, { maxDeps = 25, maxUrls = 10, maxAddresses = 5, maxChars = 12_000, maxChunks = Infinity } = {}) {
  // Package-version vulnerability lookups live under SECURITY_REVIEW_GENERAL on
  // Telegraph; CVE_LOOKUP_CVSS miners only take a CVE id (see data/miners-summary.json).
  // Each job carries the canonical ask Telegraph routes by ranking (`route`);
  // the vetted miners in config/miners.json are the fallback.
  const depJob = (d) => ({
    check: "deps",
    intent: "SECURITY_REVIEW_GENERAL",
    target: d.to ? `${d.name}@${d.to}` : `${d.name} (${d.spec})`,
    vars: { ecosystem: d.ecosystem, name: d.name, version: d.to, from: d.from, spec: d.spec, depsdev_system: DEPSDEV_SYSTEM[d.ecosystem] },
    route: { intent: "SECURITY_REVIEW_GENERAL", params: { target: `${d.ecosystem} package ${d.name} version ${d.to}` }, normalizer: "security-review-format" },
  });
  const resolvable = rankDeps(deps.filter((d) => d.to), title).slice(0, maxDeps);
  const direct = resolvable.filter((d) => d.direct).map(depJob);
  const transitive = resolvable.filter((d) => !d.direct).map(depJob);

  const chunks = chunkDiff(files, { maxChars }).slice(0, maxChunks);
  const diff = chunks.map((c, i) => {
    const routable = c.text.length <= ROUTE_MAX_CHARS;
    return {
      check: "diff",
      intent: routable ? "CODE_REVIEW_GENERAL" : "SECURITY_REVIEW_GENERAL",
      target: chunks.length > 1 ? `chunk ${i + 1}/${chunks.length}: ${c.files.join(", ")}` : c.files.join(", "),
      vars: { diff: c.text, files: c.files, chunk_index: i + 1, chunk_count: chunks.length },
      route: routable ? { intent: "CODE_REVIEW_GENERAL", params: { code: c.text }, normalizer: "code-review-format" } : null,
      ...(!routable && { routeSkipped: `over the ${ROUTE_MAX_CHARS.toLocaleString("en-US")}-character limit for canonical asks` }),
    };
  });

  // On-chain addresses the PR adds: buy the contract's risk profile before the
  // code starts sending funds there. SMART_CONTRACT_AUDIT_GENERAL has no input
  // schema, so the routed ask is a plain-language query.
  const addresses = extractAddresses(files, { max: maxAddresses }).map((a) => ({
    check: "addresses",
    intent: "SMART_CONTRACT_AUDIT_GENERAL",
    target: `${a.address} on ${a.chain}${a.assumed ? " (assumed)" : ""}`,
    vars: { address: a.address, chain_id: a.chainId, chain: a.chain, file: a.file, line: a.line },
    route: {
      intent: "SMART_CONTRACT_AUDIT_GENERAL",
      body: { query: `Token and contract security risk (honeypot, owner and proxy flags, verified source) of the contract at ${a.address} on ${a.chain} (chain id ${a.chainId})` },
      normalizer: null,
    },
  }));

  const patch = chunks.length
    ? [{
        check: "patch",
        intent: "CODE_PATCH_VERIFY_GENERAL",
        target: "PR description vs diff",
        vars: { title, body: (body ?? "").slice(0, 4000), diff: chunks[0].text, files: files.map((f) => f.filename) },
      }]
    : [];

  const urls = extractUrls(files, { max: maxUrls }).map((u) => ({
    check: "urls",
    intent: "URL_SAFE_GENERAL",
    target: u.url,
    vars: { url: u.url, file: u.file, line: u.line },
  }));

  const jobs = [];
  if (enabled.has("deps")) jobs.push(...direct);
  if (enabled.has("diff")) jobs.push(...diff);
  if (enabled.has("addresses")) jobs.push(...addresses);
  if (enabled.has("deps")) jobs.push(...transitive);
  if (enabled.has("patch")) jobs.push(...patch);
  if (enabled.has("urls")) jobs.push(...urls);
  return jobs;
}

/** Dependencies with no registry version (git, path, alias) can't be looked up. */
export function unresolvableDepOutcomes(deps) {
  return deps.filter((d) => !d.to).map((d) => ({
    check: "deps",
    target: `${d.name} (${d.spec})`,
    status: "skipped",
    reason: "no registry version to look up",
    severity: "none",
    findings: [],
    confirmed: false,
    disagreement: false,
    calls: [],
  }));
}

const local = (check, target, findings) => ({
  check,
  target,
  status: "ok",
  severity: maxSeverity(findings),
  findings,
  // Deterministic and run on the raw diff, so a hit is confirmed on its own.
  confirmed: true,
  disagreement: false,
  calls: [],
});

/**
 * Local checks on the raw (unredacted) files.
 * @param {object[]} rawFiles
 * @param {object[]} installScripts from extract.diffInstallScripts
 */
export function localOutcomes(rawFiles, installScripts) {
  const secrets = scanSecrets(rawFiles);
  const out = [local("secrets", secrets.length ? `${secrets.length} on added lines` : "added lines", secrets)];
  const swapped = addressChanges(rawFiles);
  if (swapped.length) {
    // Not a finding about either address: a prompt to confirm the new one is intended.
    out.push({ ...local("address-changes", swapped.map((c) => `${c.file}:${c.line}`).join(", "), swapped.map((c) => ({
      title: `address changed: ${c.from} → ${c.to}`,
      severity: "medium",
      file: c.file,
      line: c.line,
      detail: "confirm the new address is intended; swapping a payment or contract address is a known supply-chain attack",
    }))), confirmed: false });
  }
  if (installScripts.length) {
    out.push(local("install-scripts", installScripts.map((s) => `${s.file}#${s.script}`).join(", "), installScripts.map((s) => ({
      title: `${s.change} ${s.script} script: ${s.command}`,
      severity: "medium",
      file: s.file,
    }))));
  }
  return out;
}
