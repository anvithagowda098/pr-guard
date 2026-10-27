// Action entry point: read the PR, buy checks, post one verdict comment.
// Every path ends in a verdict; nothing here should crash the workflow.
import * as core from "@actions/core";
import * as github from "@actions/github";
import { readFile } from "node:fs/promises";
import { Telegraph, Budget, DEFAULT_NODE_URL } from "./telegraph.js";
import { manifestEcosystem, diffManifest, mergeDependencyChanges, diffInstallScripts } from "./extract.js";
import { redact } from "./redact.js";
import { ALL_CHECKS, buildJobs, localOutcomes, unresolvableDepOutcomes } from "./checks.js";
import { runCheck, runAll } from "./runner.js";
import { decide, shouldFail } from "./policy.js";
import { renderComment } from "./report.js";
import { appendLedger } from "./ledger.js";
import { listPrFiles, mergeBase, getText, upsertComment } from "./github.js";
import bundledMiners from "../config/miners.json" with { type: "json" };

const RUN_DEADLINE_MS = 100_000; // leave headroom under the 2-minute target
const LEDGER_PATH = "pr-guard-ledger.jsonl";

function inputs() {
  const num = (name, dflt) => {
    const v = Number(core.getInput(name) || dflt);
    if (!Number.isFinite(v) || v < 0) throw new Error(`input ${name} must be a non-negative number`);
    return v;
  };
  const failOn = core.getInput("fail-on") || "block";
  if (!["block", "caution", "never"].includes(failOn)) throw new Error("input fail-on must be block, caution or never");
  return {
    privateKey: core.getInput("telegraph-private-key"),
    maxUsdPerPr: num("max-usd-per-pr", 0.1),
    maxUsdPerCall: num("max-usd-per-call", 0.05),
    failOn,
    checks: new Set((core.getInput("checks") || ALL_CHECKS.join(",")).split(",").map((s) => s.trim()).filter(Boolean)),
    nodeUrl: core.getInput("node-url") || DEFAULT_NODE_URL,
    minersConfig: core.getInput("miners-config"),
    token: core.getInput("github-token"),
  };
}

async function collectDependencies(octokit, repoRef, files, baseSha, headSha) {
  const deps = [];
  const installScripts = [];
  const errors = [];
  for (const f of files) {
    if (!manifestEcosystem(f.filename)) continue;
    const basePath = f.previous_filename ?? f.filename;
    try {
      const [baseText, headText] = await Promise.all([
        f.status === "added" ? null : getText(octokit, { ...repoRef, path: basePath, ref: baseSha }),
        f.status === "removed" ? null : getText(octokit, { ...repoRef, path: f.filename, ref: headSha }),
      ]);
      deps.push(...diffManifest(f.filename, baseText, headText));
      installScripts.push(...diffInstallScripts(f.filename, baseText, headText));
    } catch (err) {
      errors.push({ file: f.filename, error: err.message });
    }
  }
  return { deps: mergeDependencyChanges(deps), installScripts, errors };
}

async function run() {
  const cfg = inputs();
  const { context } = github;
  const pr = context.payload.pull_request;
  if (!pr) {
    core.info("Not a pull_request event; nothing to check.");
    core.setOutput("verdict", "SKIPPED");
    return;
  }
  const octokit = github.getOctokit(cfg.token);
  const repoRef = { owner: context.repo.owner, repo: context.repo.repo };
  const issue = { ...repoRef, issue_number: pr.number };
  const runUrl = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;

  const post = async (body) => {
    try {
      await upsertComment(octokit, { ...issue, body });
    } catch (err) {
      // Fork PRs get a read-only token; the job summary still shows the result.
      core.warning(`could not comment on the PR: ${err.message}`);
    }
    try {
      await core.summary.addRaw(body).write();
    } catch (err) {
      core.warning(`could not write the job summary: ${err.message}`);
    }
  };

  if (!cfg.privateKey) {
    const fork = pr.head?.repo?.full_name !== pr.base?.repo?.full_name;
    const note = fork
      ? "Skipped: workflows on fork PRs don't receive secrets, so there is no wallet to pay for checks."
      : "Skipped: no `telegraph-private-key` secret is configured, so there is no wallet to pay for checks.";
    await post(renderComment({ verdict: "SKIPPED", note, nodeUrl: cfg.nodeUrl }));
    core.setOutput("verdict", "SKIPPED");
    core.setOutput("cost_usd", "0");
    return;
  }

  const deadline = Date.now() + RUN_DEADLINE_MS;
  const miners = cfg.minersConfig ? JSON.parse(await readFile(cfg.minersConfig, "utf8")) : bundledMiners;

  const rawFiles = await listPrFiles(octokit, { ...repoRef, pull_number: pr.number });
  const base = await mergeBase(octokit, { ...repoRef, base: pr.base.sha, head: pr.head.sha });
  const { deps, installScripts, errors } = await collectDependencies(octokit, repoRef, rawFiles, base, pr.head.sha);
  for (const e of errors) core.warning(`could not read ${e.file}: ${e.error}`);

  // Only redacted text ever leaves the runner.
  const files = rawFiles.map((f) => ({ filename: f.filename, status: f.status, patch: f.patch && redact(f.patch).text }));
  const jobs = buildJobs({ deps, files, title: pr.title, body: pr.body }, cfg.checks);

  const budget = new Budget(cfg.maxUsdPerPr);
  const tg = new Telegraph({ nodeUrl: cfg.nodeUrl, privateKey: cfg.privateKey, maxUsdPerCall: cfg.maxUsdPerCall, budget, timeoutMs: 30_000 });
  const onCall = (entry) => appendLedger(LEDGER_PATH, { pr: pr.number, ...entry });

  const paid = await runAll(jobs, (job) => runCheck({ tg, miners, job, deadline, onCall }));
  const outcomes = [...localOutcomes(rawFiles, installScripts), ...unresolvableDepOutcomes(deps), ...paid];
  const { verdict, reasons } = decide(outcomes);
  const spentUsd = Number(budget.spent) / 1e6;

  await post(renderComment({ verdict, reasons, outcomes, spentUsd, budgetUsd: cfg.maxUsdPerPr, nodeUrl: cfg.nodeUrl, runUrl }));

  const signalHashes = outcomes.flatMap((o) => o.calls.map((c) => c.signalHash)).filter(Boolean);
  core.setOutput("verdict", verdict);
  core.setOutput("cost_usd", spentUsd.toFixed(6));
  core.setOutput("signal_hashes", signalHashes.join(","));
  core.setOutput("ledger_path", LEDGER_PATH);
  if (shouldFail(verdict, cfg.failOn)) core.setFailed(`PR Guard verdict: ${verdict}`);
}

run().catch(async (err) => {
  // Last resort: report CAUTION with the reason instead of a stack trace.
  core.error(err.stack ?? String(err));
  core.setOutput("verdict", "CAUTION");
  try {
    const pr = github.context.payload.pull_request;
    if (pr) {
      const octokit = github.getOctokit(core.getInput("github-token"));
      const body = renderComment({ verdict: "CAUTION", reasons: [`PR Guard could not finish: ${err.message}`], nodeUrl: core.getInput("node-url") || DEFAULT_NODE_URL });
      await upsertComment(octokit, { owner: github.context.repo.owner, repo: github.context.repo.repo, issue_number: pr.number, body });
    }
  } catch {}
  if ((core.getInput("fail-on") || "block") === "caution") core.setFailed(`PR Guard could not finish: ${err.message}`);
});
