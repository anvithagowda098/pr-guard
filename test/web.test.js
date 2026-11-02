// The web page's API end to end, offline: fake GitHub, fake KV, and a fake
// payment-gated Telegraph node replaying real captured miner answers.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generatePrivateKey } from "viem/accounts";
import { createApp } from "../web/worker.js";
import { parsePullUrl } from "../web/github.js";
import { scanHosted, HostedRefusal } from "../src/hosted.js";
import { decide } from "../src/policy.js";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
const captured = (name) => JSON.parse(readFileSync(new URL(`./fixtures/miner-responses/SECURITY_REVIEW_GENERAL/${name}`, import.meta.url), "utf8")).body;
const ANSWERS = {
  77010: captured("77010-npm-lodash-4.17.15-200-paid.json"),
  190048: captured("190048-npm-lodash-4.17.15-200-paid.json"),
  5530: captured("5530-review-clean-diff-200-paid.json"),
};
const challenge = {
  x402Version: 2,
  resource: { url: "https://node.test/engine/v1/ask", description: "t", mimeType: "application/json" },
  accepts: [{ scheme: "exact", network: "eip155:11155111", amount: "10000", asset: "0xcc194e1a843B658526D0D5C431f670028582Ae17", payTo: "0x000000000000000000000000000000000000dEaD", maxTimeoutSeconds: 60, extra: { name: "USD Coin", version: "2" } }],
};

class FakeKV {
  constructor() { this.m = new Map(); }
  async get(k, type) { const v = this.m.get(k); return v === undefined ? null : type === "json" ? JSON.parse(v) : v; }
  async put(k, v) { this.m.set(k, v); }
}

function world() {
  const asks = [];
  const pulls = {
    7: { title: "Pin lodash", body: "", html_url: "https://github.com/o/r/pull/7", head: { sha: "h7", repo: { full_name: "o/r" } }, base: { sha: "b7", repo: { full_name: "o/r" } } },
    8: { title: "Docs", body: "", html_url: "https://github.com/o/r/pull/8", head: { sha: "h8", repo: { full_name: "o/r" } }, base: { sha: "b8", repo: { full_name: "o/r" } } },
  };
  const files = {
    7: [
      { filename: "package.json", status: "modified", patch: '@@ -1 +1 @@\n-"lodash": "4.18.1"\n+"lodash": "4.17.15"' },
      { filename: "src/a.js", status: "modified", patch: "@@ -1,1 +1,2 @@\n x\n+const y = 2;" },
    ],
    8: [{ filename: "README.md", status: "modified", patch: "@@ -1 +1 @@\n-a\n+b" }],
  };
  const raw = { "mb/package.json": JSON.stringify({ dependencies: { lodash: "4.18.1" } }), "h7/package.json": JSON.stringify({ dependencies: { lodash: "4.17.15" } }) };
  const fetch = async (input, init) => {
    const req = new Request(input, init);
    const u = new URL(req.url);
    const ok = (body, headers = {}) => new Response(typeof body === "string" ? body : JSON.stringify(body), { status: 200, headers });
    if (u.host === "api.github.com") {
      let m = u.pathname.match(/^\/repos\/o\/r\/pulls\/(\d+)$/);
      if (m) return pulls[m[1]] ? ok(pulls[m[1]]) : new Response("{}", { status: 404 });
      m = u.pathname.match(/^\/repos\/o\/r\/pulls\/(\d+)\/files$/);
      if (m) return ok(files[m[1]]);
      if (u.pathname.startsWith("/repos/o/r/compare/")) return ok({ merge_base_commit: { sha: "mb" } });
    }
    if (u.host === "raw.githubusercontent.com") {
      const key = u.pathname.replace(/^\/o\/r\//, "");
      return raw[key] ? ok(raw[key]) : new Response("", { status: 404 });
    }
    const ask = u.pathname.match(/^\/engine\/v1\/ask\/(\d+)$/);
    if (u.host === "node.test" && ask) {
      if (!req.headers.get("payment-signature")) return new Response("{}", { status: 402, headers: { "PAYMENT-REQUIRED": b64(challenge) } });
      asks.push({ miner: ask[1], ...(await req.json()) });
      return ok(ANSWERS[ask[1]], { "PAYMENT-RESPONSE": b64({ success: true }), "X-TELEGRAPH-RECEIPT": b64({ receipt_hash: `0xrec${ask[1]}` }) });
    }
    return new Response("unexpected " + req.url, { status: 599 });
  };
  const env = { SCANS: new FakeKV(), SPONSOR_KEY: generatePrivateKey().slice(2), NODE_URL: "https://node.test" };
  return { app: createApp({ fetch }), env, asks };
}

const call = (app, env, method, path, body, ip = "1.2.3.4") =>
  app(new Request("https://web.test" + path, { method, headers: { "content-type": "application/json", "cf-connecting-ip": ip }, body: body ? JSON.stringify(body) : undefined }), env);

test("parsePullUrl accepts PR links and rejects everything else", () => {
  assert.deepEqual(parsePullUrl("https://github.com/o/r/pull/7"), { owner: "o", repo: "r", number: 7 });
  assert.deepEqual(parsePullUrl("github.com/o/r.js/pull/12/files?x=1"), { owner: "o", repo: "r.js", number: 12 });
  for (const bad of ["", "https://github.com/o/r", "https://evil.com/o/r/pull/1", "https://github.com/o/r/issues/1", "javascript:alert(1)"]) assert.equal(parsePullUrl(bad), null, bad);
});

test("a full scan from the page: plan, one paid check per step, verdict, permalink, recent", async () => {
  const { app, env, asks } = world();
  const start = await call(app, env, "POST", "/api/scan", { url: "https://github.com/o/r/pull/7" });
  assert.equal(start.status, 201);
  const { id, scan } = await start.json();
  assert.deepEqual(scan.jobs.map((j) => `${j.check}:${j.target}`), ["deps:lodash@4.17.15", "diff:package.json, src/a.js"]);
  assert.equal(scan.status, "running");
  assert.ok(!JSON.stringify(scan).includes("const y = 2"), "the public view never carries diff text");

  let s = scan;
  let steps = 0;
  while (s.status !== "done") {
    const r = await call(app, env, "POST", `/api/scan/${id}/step`);
    assert.equal(r.status, 200);
    s = (await r.json()).scan;
    steps++;
  }
  assert.equal(steps, 2, "one request per paid job");
  assert.equal(s.verdict, "BLOCK");
  assert.equal(s.spentUsd, 0.03);
  assert.deepEqual(asks.map((a) => a.miner), ["77010", "190048", "5530"]);
  const deps = s.outcomes.find((o) => o.check === "deps");
  assert.equal(deps.confirmed, true);
  assert.ok(deps.calls.every((c) => c.signalHash && c.receiptHash));

  const again = await call(app, env, "GET", `/api/scan/${id}`);
  assert.equal((await again.json()).scan.verdict, "BLOCK");
  const recent = await (await call(app, env, "GET", "/api/recent")).json();
  assert.deepEqual(recent.recent.map((r) => [r.id, r.verdict, r.label]), [[id, "BLOCK", "o/r#7"]]);

  // The same commit again: same report, nothing new bought.
  const cached = await (await call(app, env, "POST", "/api/scan", { url: "https://github.com/o/r/pull/7" })).json();
  assert.deepEqual([cached.id, cached.cached], [id, true]);
  assert.equal(asks.length, 3);
});

test("a PR with nothing to buy finishes at once, for free", async () => {
  const { app, env, asks } = world();
  const r = await (await call(app, env, "POST", "/api/scan", { url: "https://github.com/o/r/pull/8" })).json();
  assert.equal(r.scan.status, "done");
  assert.equal(r.scan.verdict, "SAFE");
  assert.equal(asks.length, 0);
});

test("limits: per-visitor scans, daily budget, and bad input", async () => {
  const { app, env } = world();
  env.SCANS_PER_IP_PER_DAY = "1";
  assert.equal((await call(app, env, "POST", "/api/scan", { url: "https://github.com/o/r/pull/8" })).status, 201);
  const second = await call(app, env, "POST", "/api/scan", { url: "https://github.com/o/r/pull/7" });
  assert.equal(second.status, 429);
  assert.match((await second.json()).error, /1 free scans per visitor per day/);
  assert.equal((await call(app, env, "POST", "/api/scan", { url: "https://github.com/o/r/pull/7" }, "5.6.7.8")).status, 201, "another visitor still can");

  const broke = world();
  broke.env.USD_PER_DAY = "0";
  const id = (await (await call(broke.app, broke.env, "POST", "/api/scan", { url: "https://github.com/o/r/pull/7" })).json()).id;
  assert.equal(id, undefined, "no new scans once the day's budget is spent");

  assert.equal((await call(app, env, "POST", "/api/scan", { url: "not a link" })).status, 400);
  const missing = await call(app, env, "POST", "/api/scan", { url: "https://github.com/o/r/pull/99" }, "9.9.9.9");
  assert.equal(missing.status, 400);
  assert.match((await missing.json()).error, /public repositories/);
  assert.equal((await call(app, env, "GET", "/api/scan/nope")).status, 404);
});

test("the page is served with a strict content security policy", async () => {
  const { app, env } = world();
  for (const path of ["/", "/r/abc123"]) {
    const r = await call(app, env, "GET", path);
    assert.equal(r.status, 200);
    assert.match(r.headers.get("content-security-policy"), /default-src 'none'.*connect-src 'self'/);
    assert.match(await r.text(), /<title>PR Guard<\/title>/);
  }
});

// The Action without a wallet: src/hosted.js driving this same service.
const hostedFetch = (app, env) => (url, init) => app(new Request(url, { ...init, headers: { ...init?.headers, "cf-connecting-ip": "20.1.2.3" } }), env);

test("hosted mode: the Action's client runs a whole scan through the service", async () => {
  const { app, env, asks } = world();
  const scan = await scanHosted({ serviceUrl: "https://web.test/", prUrl: "https://github.com/o/r/pull/7", deadline: Date.now() + 60_000, fetch: hostedFetch(app, env) });
  assert.equal(scan.status, "done");
  assert.equal(scan.verdict, "BLOCK");
  assert.equal(scan.spentUsd, 0.03);
  assert.match(scan.reportUrl, /^https:\/\/web\.test\/r\/[a-z0-9]+$/);
  assert.deepEqual(asks.map((a) => a.miner), ["77010", "190048", "5530"]);
  assert.equal(JSON.parse(env.SCANS.m.get(`scan:${scan.id}`)).source, "action");
});

test("hosted mode: limits are per repository, and a refusal says why", async () => {
  const { app, env } = world();
  env.SCANS_PER_REPO_PER_DAY = "1";
  env.SCANS_PER_IP_PER_DAY = "0"; // the page's per-visitor limit doesn't apply to the Action
  const run = (n) => scanHosted({ serviceUrl: "https://web.test", prUrl: `https://github.com/o/r/pull/${n}`, deadline: Date.now() + 60_000, fetch: hostedFetch(app, env) });
  assert.equal((await run(8)).verdict, "SAFE");
  await assert.rejects(run(7), (err) => err instanceof HostedRefusal && /used its 1 free hosted scans/.test(err.message));
});

test("hosted mode: checks still waiting at the deadline count as skipped", async () => {
  const { app, env, asks } = world();
  const scan = await scanHosted({ serviceUrl: "https://web.test", prUrl: "https://github.com/o/r/pull/7", deadline: Date.now() - 1, fetch: hostedFetch(app, env) });
  assert.equal(scan.timedOut, true);
  assert.equal(asks.length, 0);
  assert.deepEqual(scan.outcomes.filter((o) => o.status === "skipped").map((o) => `${o.check}:${o.reason}`), ["deps:time limit", "diff:time limit"]);
  assert.equal(decide(scan.outcomes).verdict, "CAUTION");
});

test("hosted mode: a dropped connection mid-check is retried without paying twice", async () => {
  const { app, env, asks } = world();
  let dropped = 0;
  const flaky = async (url, init) => {
    const res = await hostedFetch(app, env)(url, init);
    // The first step's answer is lost on the way back, after the service recorded it.
    if (String(url).endsWith("/step") && dropped++ === 0) throw new TypeError("fetch failed");
    return res;
  };
  const scan = await scanHosted({ serviceUrl: "https://web.test", prUrl: "https://github.com/o/r/pull/7", deadline: Date.now() + 60_000, fetch: flaky, sleep: async () => {} });
  assert.equal(scan.verdict, "BLOCK");
  assert.deepEqual(asks.map((a) => a.miner), ["77010", "190048", "5530"], "each miner paid once");
});
