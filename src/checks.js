// What to check on a PR: paid jobs for miners, plus local checks that need no
// miner (secrets on added lines, new install scripts).
import { chunkDiff, extractUrls } from "./extract.js";
import { scanSecrets } from "./redact.js";
import { maxSeverity } from "./policy.js";

export const ALL_CHECKS = ["deps", "diff", "patch", "urls"];

// Paid checks with a vetted miner today; the others stay opt-in until one exists.
export const DEFAULT_CHECKS = ["deps", "diff"];

// deps.dev's names for our ecosystems.
const DEPSDEV_SYSTEM = { npm: "npm", PyPI: "pypi", Go: "go", "crates.io": "cargo" };

/**
 * Paid jobs in priority order: direct dependencies, the diff, transitive
 * dependencies, the patch-vs-description check, then URLs. The budget is
 * spent front to back, so low-value checks are the ones that get skipped.
 *
 * @param {object} pr
 * @param {object[]} pr.deps merged dependency changes (extract.mergeDependencyChanges)
 * @param {object[]} pr.files redacted PR files ({ filename, patch })
 * @param {string} pr.title
 * @param {string} pr.body
 * @param {Set<string>} enabled check names
 */
export function buildJobs({ deps, files, title, body }, enabled, { maxDeps = 25, maxUrls = 10, maxChars = 12_000 } = {}) {
  // Package-version vulnerability lookups live under SECURITY_REVIEW on
  // Telegraph; CVE_LOOKUP miners only take a CVE id (see data/miners-summary.json).
  const depJob = (d) => ({
    check: "deps",
    intent: "SECURITY_REVIEW",
    target: d.to ? `${d.name}@${d.to}` : `${d.name} (${d.spec})`,
    vars: { ecosystem: d.ecosystem, name: d.name, version: d.to, from: d.from, spec: d.spec, depsdev_system: DEPSDEV_SYSTEM[d.ecosystem] },
  });
  const resolvable = deps.filter((d) => d.to).slice(0, maxDeps);
  const direct = resolvable.filter((d) => d.direct).map(depJob);
  const transitive = resolvable.filter((d) => !d.direct).map(depJob);

  const chunks = chunkDiff(files, { maxChars });
  const diff = chunks.map((c, i) => ({
    check: "diff",
    intent: "SECURITY_REVIEW",
    target: chunks.length > 1 ? `chunk ${i + 1}/${chunks.length}: ${c.files.join(", ")}` : c.files.join(", "),
    vars: { diff: c.text, files: c.files, chunk_index: i + 1, chunk_count: chunks.length },
  }));

  const patch = chunks.length
    ? [{
        check: "patch",
        intent: "CODE_PATCH_VERIFY",
        target: "PR description vs diff",
        vars: { title, body: (body ?? "").slice(0, 4000), diff: chunks[0].text, files: files.map((f) => f.filename) },
      }]
    : [];

  const urls = extractUrls(files, { max: maxUrls }).map((u) => ({
    check: "urls",
    intent: "URL_SAFE",
    target: u.url,
    vars: { url: u.url, file: u.file, line: u.line },
  }));

  const jobs = [];
  if (enabled.has("deps")) jobs.push(...direct);
  if (enabled.has("diff")) jobs.push(...diff);
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
  // Deterministic and run on the raw diff, so a hit doesn't need a second opinion.
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
  if (installScripts.length) {
    out.push(local("install-scripts", installScripts.map((s) => `${s.file}#${s.script}`).join(", "), installScripts.map((s) => ({
      title: `${s.change} ${s.script} script: ${s.command}`,
      severity: "medium",
      file: s.file,
    }))));
  }
  return out;
}
