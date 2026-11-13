// Action entry point: read the PR, buy checks, post one verdict comment.
// Every path ends in a verdict; nothing here should crash the workflow.
import * as core from "@actions/core";
import * as github from "@actions/github";
import { readFile } from "node:fs/promises";
import { Telegraph, Budget, DEFAULT_NODE_URL } from "./telegraph.js";
import { DEFAULT_CHECKS } from "./checks.js";
import { planScan } from "./plan.js";
import { runCheck, runAll } from "./runner.js";
import { decide, shouldFail } from "./policy.js";
import { renderComment } from "./report.js";
import { appendLedger } from "./ledger.js";
import { listPrFiles, mergeBase, getText, upsertComment } from "./github.js";
import { scanHosted, HostedRefusal, DEFAULT_SERVICE_URL } from "./hosted.js";
import bundledMiners from "../config/miners.json" with { type: "json" };

const RUN_DEADLINE_MS = 100_000; // leave headroom under the 2-minute target
const HOSTED_DEADLINE_MS = 4 * 60_000; // hosted checks run one after another
const LEDGER_PATH = "pr-guard-ledger.jsonl";

function inputs() {
  const num = (name, dflt) => {
    const v = Number(core.getInput(name) || dflt);
    if (!Number.isFinite(v) || v < 0) throw new Error(`input ${name} must be a non-negative number`);
    return v;
  };
  const failOn = core.getInput("fail-on") || "block";
  if (!["block", "caution", "never"].includes(failOn)) throw new Error("input fail-on must be block, caution or never");
  if (!["auto", "off"].includes(core.getInput("routing") || "auto")) throw new Error("input routing must be auto or off");
  return {
    privateKey: core.getInput("telegraph-private-key"),
    maxUsdPerPr: num("max-usd-per-pr", 0.1),
    maxUsdPerCall: num("max-usd-per-call", 0.05),
    failOn,
    checks: new Set((core.getInput("checks") || DEFAULT_CHECKS.join(",")).split(",").map((s) => s.trim()).filter(Boolean)),
    nodeUrl: core.getInput("node-url") || DEFAULT_NODE_URL,
    minersConfig: core.getInput("miners-config"),
    token: core.getInput("github-token"),
    serviceUrl: core.getInput("service-url") || DEFAULT_SERVICE_URL,
    routing: core.getInput("routing") || "auto",
  };
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

  const finish = async ({ verdict, spentUsd, signalHashes = [], ledgerPath = "" }) => {
    core.setOutput("verdict", verdict);
    core.setOutput("cost_usd", spentUsd.toFixed(6));
    core.setOutput("signal_hashes", signalHashes.join(","));
    core.setOutput("ledger_path", ledgerPath);
    if (shouldFail(verdict, cfg.failOn)) core.setFailed(`PR Guard verdict: ${verdict}`);
  };

  if (!cfg.privateKey) {
    // No wallet here: public repositories are scanned by the hosted service.
    if (context.payload.repository?.private) {
      const note = "Skipped: this repository is private. Free hosted scans cover public repositories only; add a `TELEGRAPH_PRIVATE_KEY` secret to pay for checks from your own wallet.";
      await post(renderComment({ verdict: "SKIPPED", note, nodeUrl: cfg.nodeUrl }));
      return finish({ verdict: "SKIPPED", spentUsd: 0 });
    }
    let scan;
    try {
      scan = await scanHosted({ serviceUrl: cfg.serviceUrl, prUrl: pr.html_url, deadline: Date.now() + HOSTED_DEADLINE_MS });
    } catch (err) {
      if (!(err instanceof HostedRefusal)) throw err;
      await post(renderComment({ verdict: "SKIPPED", note: `Skipped: ${err.message}`, nodeUrl: cfg.nodeUrl }));
      return finish({ verdict: "SKIPPED", spentUsd: 0 });
    }
    const { verdict, reasons } = scan.verdict ? scan : decide(scan.outcomes);
    const note = [
      `Free hosted scan: checks were paid from PR Guard's sponsor wallet in test USDC. [Full report](${scan.reportUrl})${scan.timedOut ? " (some checks ran out of time)" : ""}.`,
      ...(scan.notes ?? []),
    ].join(" ");
    await post(renderComment({ verdict, reasons, outcomes: scan.outcomes, spentUsd: scan.spentUsd, budgetUsd: scan.budgetUsd, nodeUrl: scan.nodeUrl, runUrl, note }));
    const signalHashes = scan.outcomes.flatMap((o) => o.calls.map((c) => c.signalHash)).filter(Boolean);
    return finish({ verdict, spentUsd: scan.spentUsd, signalHashes });
  }

  const deadline = Date.now() + RUN_DEADLINE_MS;
  const miners = cfg.minersConfig ? JSON.parse(await readFile(cfg.minersConfig, "utf8")) : bundledMiners;

  const rawFiles = await listPrFiles(octokit, { ...repoRef, pull_number: pr.number });
  const base = await mergeBase(octokit, { ...repoRef, base: pr.base.sha, head: pr.head.sha });
  const getFileText = ({ path, ref }) => getText(octokit, { ...repoRef, path, ref });
  const { jobs, local, errors, notes } = await planScan({ pr, rawFiles, baseSha: base, headSha: pr.head.sha, getText: getFileText, checks: cfg.checks });
  for (const e of errors) core.warning(`could not read ${e.file}: ${e.error}`);

  const budget = new Budget(cfg.maxUsdPerPr);
  const tg = new Telegraph({ nodeUrl: cfg.nodeUrl, privateKey: cfg.privateKey, maxUsdPerCall: cfg.maxUsdPerCall, budget, timeoutMs: 45_000 });
  const onCall = (entry) => appendLedger(LEDGER_PATH, { pr: pr.number, ...entry });

  // One routing record for the run: once a routed answer for an intent is
  // unusable, the remaining checks for that intent go straight to the fallback.
  const routing = { mode: cfg.routing, health: {} };
  const paid = await runAll(jobs, (job) => runCheck({ tg, miners, job, deadline, onCall, routing }));
  const outcomes = [...local, ...paid];
  const { verdict, reasons } = decide(outcomes);
  const spentUsd = Number(budget.spent) / 1e6;

  await post(renderComment({ verdict, reasons, outcomes, spentUsd, budgetUsd: cfg.maxUsdPerPr, nodeUrl: cfg.nodeUrl, runUrl, note: notes.join(" ") || undefined }));

  const signalHashes = outcomes.flatMap((o) => o.calls.map((c) => c.signalHash)).filter(Boolean);
  await finish({ verdict, spentUsd, signalHashes, ledgerPath: LEDGER_PATH });
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
