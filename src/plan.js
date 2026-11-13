// A pull request -> a scan plan, shared by the Action and the web page:
// dependency changes read from manifests, redacted file patches, the paid
// jobs to run, and the local outcomes that need no miner.
import { manifestEcosystem, diffManifest, mergeDependencyChanges, diffInstallScripts } from "./extract.js";
import { redact } from "./redact.js";
import { buildJobs, localOutcomes, unresolvableDepOutcomes } from "./checks.js";

/**
 * @param {(where: { path: string, ref: string }) => Promise<string | null>} getText
 * @param {object[]} files PR files ({ filename, status, previous_filename?, patch? })
 */
export async function collectDependencies(getText, files, baseSha, headSha) {
  const deps = [];
  const installScripts = [];
  const errors = [];
  for (const f of files) {
    if (!manifestEcosystem(f.filename)) continue;
    const basePath = f.previous_filename ?? f.filename;
    try {
      const [baseText, headText] = await Promise.all([
        f.status === "added" ? null : getText({ path: basePath, ref: baseSha }),
        f.status === "removed" ? null : getText({ path: f.filename, ref: headSha }),
      ]);
      deps.push(...diffManifest(f.filename, baseText, headText));
      installScripts.push(...diffInstallScripts(f.filename, baseText, headText));
    } catch (err) {
      errors.push({ file: f.filename, error: err.message });
    }
  }
  return { deps: mergeDependencyChanges(deps), installScripts, errors };
}

/**
 * @param {object} p
 * @param {{ title: string, body?: string }} p.pr
 * @param {object[]} p.rawFiles PR files, unredacted (local checks need the real text)
 * @param {string} p.baseSha merge base
 * @param {string} p.headSha
 * @param {Function} p.getText see collectDependencies
 * @param {Set<string>} p.checks paid checks to plan
 * @param {object} [p.limits] passed to buildJobs
 * @returns {{ jobs: object[], local: object[], errors: object[], notes: string[] }}
 */
export async function planScan({ pr, rawFiles, baseSha, headSha, getText, checks, limits }) {
  const { deps, installScripts, errors } = await collectDependencies(getText, rawFiles, baseSha, headSha);
  // Only redacted text ever leaves the runner.
  const files = rawFiles.map((f) => ({ filename: f.filename, status: f.status, patch: f.patch && redact(f.patch).text }));
  const jobs = buildJobs({ deps, files, title: pr.title, body: pr.body }, checks, limits);
  const local = [...localOutcomes(rawFiles, installScripts), ...unresolvableDepOutcomes(deps)];
  const notes = [];
  const changed = deps.filter((d) => d.to).length;
  const checked = jobs.filter((j) => j.check === "deps").length;
  if (checks.has("deps") && changed > checked) {
    notes.push(`${changed - checked} of ${changed} changed packages were not checked (limit ${checked}): direct dependencies and packages named in the title go first.`);
  }
  return { jobs, local, errors, notes };
}
