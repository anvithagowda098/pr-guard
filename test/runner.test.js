// The runner against a fake Telegraph client. Normalizers don't exist yet, so
// every miner answer must come back "unknown" and the verdict CAUTION.
import { test } from "node:test";
import assert from "node:assert/strict";
import { fillTemplate, runCheck, runAll } from "../src/runner.js";
import { buildJobs, localOutcomes, unresolvableDepOutcomes } from "../src/checks.js";
import { decide } from "../src/policy.js";
import { renderComment, MARKER } from "../src/report.js";

const FAR = Date.now() + 60_000;
const job = { check: "deps", intent: "CVE_LOOKUP", target: "lodash@4.17.15", vars: { name: "lodash", version: "4.17.15" } };

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
  const out = await runCheck({ tg: fakeTg([]), miners: { CVE_LOOKUP: [] }, job, deadline: FAR });
  assert.equal(out.status, "skipped");
  assert.match(out.reason, /no vetted CVE_LOOKUP miner/);
  assert.equal(decide([out]).verdict, "CAUTION");
});

test("direct ask fills the payload template; unknown format means CAUTION", async () => {
  const tg = fakeTg([okResponse(7)]);
  const miners = { CVE_LOOKUP: [{ minerId: 7, endpoint: "/cve", payload: { package: "{{name}}", version: "{{version}}" } }] };
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

test("falls through failed miners (not charged) to the next one", async () => {
  const tg = fakeTg([{ ok: false, status: 502, reason: "http_502", costUsd: 0 }, okResponse(9)]);
  const miners = { CVE_LOOKUP: [{ minerId: 1, endpoint: "/a", payload: {} }, { minerId: 9, endpoint: "/b", payload: {} }] };
  const out = await runCheck({ tg, miners, job, deadline: FAR });
  assert.equal(out.status, "ok");
  assert.deepEqual(out.calls.map((c) => [c.minerId, c.ok]), [[1, false], [9, true]]);
});

test("every miner failing is a failed check; running out of budget is a skip", async () => {
  const miners = { CVE_LOOKUP: [{ minerId: 1, endpoint: "/a", payload: {} }] };
  const failed = await runCheck({ tg: fakeTg([{ ok: false, reason: "timeout", costUsd: 0 }]), miners, job, deadline: FAR });
  assert.deepEqual([failed.status, failed.reason], ["failed", "timeout"]);
  const broke = await runCheck({ tg: fakeTg([{ ok: false, reason: "over_budget", costUsd: 0 }]), miners, job, deadline: FAR });
  assert.deepEqual([broke.status, broke.reason], ["skipped", "budget exhausted"]);
});

test("past the deadline nothing is bought", async () => {
  const tg = fakeTg([okResponse(1)]);
  const out = await runCheck({ tg, miners: { CVE_LOOKUP: [{ minerId: 1, endpoint: "/a", payload: {} }] }, job, deadline: Date.now() - 1 });
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
