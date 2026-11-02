// The runner against a fake Telegraph client. Normalizers don't exist yet, so
// every miner answer must come back "unknown" and the verdict CAUTION.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fillTemplate, runCheck, runAll } from "../src/runner.js";
import { buildJobs, rankDeps, localOutcomes, unresolvableDepOutcomes } from "../src/checks.js";
import { decide } from "../src/policy.js";
import { renderComment, MARKER } from "../src/report.js";

const FAR = Date.now() + 60_000;
const job = { check: "deps", intent: "SECURITY_REVIEW_GENERAL", target: "lodash@4.17.15", vars: { ecosystem: "npm", name: "lodash", version: "4.17.15" } };

function fakeTg(responses) {
  const sent = [];
  const next = (req) => {
    sent.push(req);
    return Promise.resolve(responses.shift());
  };
  return {
    sent,
    askMiner: (minerId, req) => next({ minerId, ...req }),
    ask: (body) => next({ auto: true, body }),
  };
}

const okResponse = (minerId) => ({ ok: true, status: 200, costUsd: 0.01, body: { miner_id: minerId, miner_name: `m${minerId}`, result: { anything: 1 }, signal_hash: `0xsig${minerId}` }, receipt: { receipt_hash: `0xr${minerId}` } });

test("fillTemplate substitutes strings, keeps raw values for whole placeholders", () => {
  const vars = { name: "lodash", version: "4.17.15", files: ["a", "b"], missing: null };
  assert.deepEqual(fillTemplate({ q: "{{name}}@{{version}}", files: "{{files}}", nested: ["{{name}}", 3], gone: "{{missing}}" }, vars), {
    q: "lodash@4.17.15",
    files: ["a", "b"],
    nested: ["lodash", 3],
    gone: null,
  });
});

test("no configured miner: skipped, which cautions for required checks", async () => {
  const out = await runCheck({ tg: fakeTg([]), miners: { deps: [] }, job, deadline: FAR });
  assert.equal(out.status, "skipped");
  assert.match(out.reason, /no vetted deps miner/);
  assert.equal(decide([out]).verdict, "CAUTION");
});

test("direct ask fills the payload template; unknown format means CAUTION", async () => {
  const tg = fakeTg([okResponse(7)]);
  const miners = { deps: [{ minerId: 7, endpoint: "/cve", payload: { package: "{{name}}", version: "{{version}}" } }] };
  const ledger = [];
  const out = await runCheck({ tg, miners, job, deadline: FAR, onCall: (e) => ledger.push(e) });

  assert.deepEqual(tg.sent[0], { minerId: 7, method: "POST", endpoint: "/cve", payload: { package: "lodash", version: "4.17.15" } });
  assert.equal(out.status, "ok");
  assert.equal(out.severity, "unknown");
  assert.deepEqual(out.calls.map((c) => [c.minerId, c.signalHash, c.receiptHash, c.costUsd]), [[7, "0xsig7", "0xr7", 0.01]]);
  assert.equal(ledger.length, 1);
  assert.equal(ledger[0].signal_hash, "0xsig7");
  assert.equal(decide([out]).verdict, "CAUTION");
});

test("falls through failed miners to the next one", async () => {
  const tg = fakeTg([{ ok: false, status: 502, reason: "http_502", costUsd: 0 }, okResponse(9)]);
  const miners = { deps: [{ minerId: 1, endpoint: "/a", payload: {} }, { minerId: 9, endpoint: "/b", payload: {} }] };
  const out = await runCheck({ tg, miners, job, deadline: FAR });
  assert.equal(out.status, "ok");
  assert.deepEqual(out.calls.map((c) => [c.minerId, c.ok]), [[1, false], [9, true]]);
});

test("every miner failing is a failed check; running out of budget is a skip", async () => {
  const miners = { deps: [{ minerId: 1, endpoint: "/a", payload: {} }] };
  const failed = await runCheck({ tg: fakeTg([{ ok: false, reason: "timeout", costUsd: 0 }]), miners, job, deadline: FAR });
  assert.deepEqual([failed.status, failed.reason], ["failed", "timeout"]);
  const broke = await runCheck({ tg: fakeTg([{ ok: false, reason: "over_budget", costUsd: 0 }]), miners, job, deadline: FAR });
  assert.deepEqual([broke.status, broke.reason], ["skipped", "budget exhausted"]);
});

test("past the deadline nothing is bought", async () => {
  const tg = fakeTg([okResponse(1)]);
  const out = await runCheck({ tg, miners: { deps: [{ minerId: 1, endpoint: "/a", payload: {} }] }, job, deadline: Date.now() - 1 });
  assert.equal(tg.sent.length, 0);
  assert.deepEqual([out.status, out.reason], ["skipped", "time limit"]);
});

test("runAll keeps order and respects the concurrency limit", async () => {
  let inFlight = 0;
  let peak = 0;
  const results = await runAll([5, 1, 3, 2, 4], async (n) => {
    peak = Math.max(peak, ++inFlight);
    await new Promise((r) => setTimeout(r, n));
    inFlight--;
    return n * 10;
  }, 2);
  assert.deepEqual(results, [50, 10, 30, 20, 40]);
  assert.equal(peak, 2);
});

test("buildJobs orders direct deps, diff, transitive deps, patch, urls and honours `checks`", () => {
  const deps = [
    { ecosystem: "npm", name: "t", to: "1.0.0", direct: false },
    { ecosystem: "npm", name: "d", to: "2.0.0", direct: true },
    { ecosystem: "npm", name: "g", to: null, spec: "git+https://x", direct: true },
  ];
  const files = [{ filename: "src/a.js", patch: "@@ -1 +1 @@\n+fetch('https://new.evil.com/x')" }];
  const all = buildJobs({ deps, files, title: "t", body: "b" }, new Set(["deps", "diff", "patch", "urls"]));
  assert.deepEqual(all.map((j) => `${j.check}:${j.target}`), ["deps:d@2.0.0", "diff:src/a.js", "deps:t@1.0.0", "patch:PR description vs diff", "urls:https://new.evil.com/x"]);
  assert.equal(all[0].intent, "SECURITY_REVIEW_GENERAL");
  assert.equal(all[0].vars.depsdev_system, "npm");
  const onlyDeps = buildJobs({ deps, files, title: "t", body: "b" }, new Set(["deps"]));
  assert.deepEqual(onlyDeps.map((j) => j.check), ["deps", "deps"]);
  assert.deepEqual(unresolvableDepOutcomes(deps).map((o) => o.target), ["g (git+https://x)"]);
});

test("local outcomes: a committed AWS key BLOCKs without any miner", () => {
  const key = "AKIA" + "Z7QW3XK2LMNOPQRS";
  const files = [{ filename: "a.js", status: "modified", patch: `@@ -1 +1 @@\n+const k = "${key}";` }];
  const outcomes = localOutcomes(files, [{ file: "package.json", script: "postinstall", command: "node x.js", change: "added" }]);
  assert.deepEqual(outcomes.map((x) => `${x.check}:${x.severity}`), ["secrets:high", "install-scripts:medium"]);
  assert.equal(decide(outcomes).verdict, "BLOCK");
});

test("comment: marker first, verdict, costs, signal links, receipts, escaping", () => {
  const outcomes = [
    { check: "deps", target: "lodash@4.17.15", status: "ok", severity: "high", confirmed: true, disagreement: false, findings: [{ title: "Prototype | pollution", severity: "high" }], calls: [{ minerId: 7, minerName: "CVEBot", costUsd: 0.01, signalHash: "0xsig", receiptHash: "0xrec" }] },
    { check: "secrets", target: "added lines", status: "ok", severity: "none", confirmed: true, disagreement: false, findings: [], calls: [] },
  ];
  const body = renderComment({ verdict: "BLOCK", reasons: ["deps: lodash@4.17.15 — high"], outcomes, spentUsd: 0.01, budgetUsd: 0.1, nodeUrl: "https://node.test", runUrl: "https://gh/run/1" });
  assert.ok(body.startsWith(MARKER));
  assert.match(body, /## PR Guard: 🔴 BLOCK/);
  assert.match(body, /Prototype \\\| pollution/);
  assert.match(body, /\[signal\]\(https:\/\/node\.test\/engine\/v1\/signal\/0xsig\)/);
  assert.match(body, /\*\*Spent:\*\* \$0\.010 of \$0\.100 budget · 1 paid call /);
  assert.match(body, /`0xrec`/);
  assert.match(body, /\| secrets \| added lines \| ✅ none \| local \| \$0\.000 \| — \|/);
});

test("comment stays under GitHub's size limit", () => {
  const outcomes = Array.from({ length: 2000 }, (_, i) => ({ check: "deps", target: `p${i}@1`, status: "ok", severity: "medium", findings: [{ title: "x".repeat(200), severity: "medium" }], confirmed: false, disagreement: false, calls: [] }));
  const body = renderComment({ verdict: "CAUTION", outcomes, nodeUrl: "https://n", runUrl: "https://r" });
  assert.ok(body.length <= 65_536);
  assert.match(body, /truncated/);
});

test("an upstream 404 stops at the first miner instead of paying the next one", async () => {
  const notFound = { ok: false, status: 500, reason: "http_500", costUsd: 0.01, bodyText: '{"error":"upstream error 404: Not Found"}' };
  const tg = fakeTg([notFound, okResponse(2)]);
  const miners = { deps: [{ minerId: 1, endpoint: "/a", payload: {} }, { minerId: 2, endpoint: "/b", payload: {} }] };
  const out = await runCheck({ tg, miners, job, deadline: FAR });
  assert.equal(tg.sent.length, 1);
  assert.deepEqual([out.status, out.reason], ["skipped", "not in the public registry"]);
  assert.equal(out.calls[0].costUsd, 0.01, "the miss is still shown as charged");
});

test("ecosystem filter: an npm-only miner isn't asked about a PyPI package", async () => {
  const tg = fakeTg([okResponse(2)]);
  const miners = { deps: [{ minerId: 1, endpoint: "/a", payload: {}, ecosystems: ["npm"] }, { minerId: 2, endpoint: "/b", payload: {} }] };
  await runCheck({ tg, miners, job: { ...job, vars: { ...job.vars, ecosystem: "PyPI" } }, deadline: FAR });
  assert.deepEqual(tg.sent.map((r) => r.minerId), [2]);
});

test("disabled entries are kept in config but never called", async () => {
  const tg = fakeTg([okResponse(2)]);
  const miners = { deps: [{ minerId: 1, endpoint: "/a", payload: {}, enabled: false }, { minerId: 2, endpoint: "/b", payload: {} }] };
  await runCheck({ tg, miners, job, deadline: FAR });
  assert.deepEqual(tg.sent.map((r) => r.minerId), [2]);
  const none = await runCheck({ tg: fakeTg([]), miners: { deps: [{ minerId: 1, endpoint: "/a", payload: {}, enabled: false }] }, job, deadline: FAR });
  assert.equal(none.status, "skipped");
});

test("fix advice reaches the PR comment", () => {
  const body = renderComment({ verdict: "BLOCK", reasons: [], outcomes: [{ check: "deps", target: "lodash@4.17.15", status: "ok", severity: "high", confirmed: true, disagreement: false, advice: "upgrade to 4.18.0", findings: [{ title: "Prototype Pollution", severity: "high" }], calls: [] }], nodeUrl: "https://n" });
  assert.match(body, /high: Prototype Pollution · confirmed · fix: upgrade to 4\.18\.0/);
});

test("rankDeps: over the cap, the packages the PR is about are checked first", () => {
  const d = (name, extra = {}) => ({ ecosystem: "npm", name, to: "1.0.0", direct: false, ...extra });
  const deps = [d("@rtsao/scc"), d("array-includes", { from: "0.9.0" }), d("lodash", { from: "4.17.15" }), d("express", { direct: true }), d("@babel/core")];
  const order = (title) => rankDeps(deps, title).map((x) => x.name);
  assert.deepEqual(order("Bump lodash from 4.17.15 to 4.17.21"), ["express", "lodash", "array-includes", "@rtsao/scc", "@babel/core"]);
  assert.deepEqual(order("Bump @babel/core"), ["express", "@babel/core", "array-includes", "lodash", "@rtsao/scc"]);
  const jobs = buildJobs({ deps, files: [], title: "Bump lodash and n8n-workflow" }, new Set(["deps"]), { maxDeps: 2 });
  assert.deepEqual(jobs.map((j) => j.target), ["express@1.0.0", "lodash@1.0.0"]);
});

test("planScan notes the packages left over by the cap", async () => {
  const { planScan } = await import("../src/plan.js");
  const lock = (names) => JSON.stringify({ lockfileVersion: 3, packages: Object.fromEntries([["", {}], ...names.map((n) => [`node_modules/${n}`, { version: "1.0.0" }])]) });
  const texts = { "b:package-lock.json": lock([]), "h:package-lock.json": lock(["a", "b", "c", "lodash"]) };
  const { jobs, notes } = await planScan({
    pr: { title: "Bump lodash" },
    rawFiles: [{ filename: "package-lock.json", status: "modified", patch: "" }],
    baseSha: "b", headSha: "h",
    getText: async ({ path, ref }) => texts[`${ref}:${path}`] ?? null,
    checks: new Set(["deps", "diff"]),
    limits: { maxDeps: 2 },
  });
  assert.deepEqual(jobs.map((j) => j.target), ["lodash@1.0.0", "a@1.0.0"]);
  assert.deepEqual(notes, ["2 of 4 changed packages were not checked (limit 2): direct dependencies and packages named in the title go first."]);
});
