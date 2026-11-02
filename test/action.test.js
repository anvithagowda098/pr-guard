// End to end on loopback: the real action entry point and bundled miner
// config against a fake GitHub API and a fake payment-gated node that replays
// real captured miner answers. Proves the wiring (files -> deps -> paid calls
// -> second opinion -> ledger -> one comment, updated on re-run).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generatePrivateKey } from "viem/accounts";

const captured = (name) => JSON.parse(readFileSync(new URL(`./fixtures/miner-responses/SECURITY_REVIEW/${name}`, import.meta.url), "utf8")).body;
const capturedNew = (name) => JSON.parse(readFileSync(new URL(`./fixtures/miner-responses/SECURITY_REVIEW_GENERAL/${name}`, import.meta.url), "utf8")).body;
const ANSWERS = {
  5530: capturedNew("5530-review-clean-diff-200-paid.json"),
  77010: captured("77010-npm-lodash-4.17.15-200-paid.json"),
  190048: captured("190048-npm-lodash-4.17.15-200-paid.json"),
};

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
const challenge = {
  x402Version: 2,
  resource: { url: "http://local/engine/v1/ask", description: "t", mimeType: "application/json" },
  accepts: [{ scheme: "exact", network: "eip155:11155111", amount: "10000", asset: "0xcc194e1a843B658526D0D5C431f670028582Ae17", payTo: "0x000000000000000000000000000000000000dEaD", maxTimeoutSeconds: 60, extra: { name: "USD Coin", version: "2" } }],
};

function fakeServer() {
  const state = { comments: [], asks: [], nextId: 1 };
  const files = [
    { filename: "package.json", status: "modified", patch: '@@ -1 +1 @@\n-"lodash": "4.17.21"\n+"lodash": "4.17.15"' },
    { filename: "src/app.js", status: "modified", patch: "@@ -1,1 +1,2 @@\n const a = 1;\n+const b = 2;" },
  ];
  const contents = {
    "mb:package.json": JSON.stringify({ dependencies: { lodash: "4.17.21" } }),
    "headsha:package.json": JSON.stringify({ dependencies: { lodash: "4.17.15" } }),
  };
  const server = createServer(async (req, res) => {
    let body = "";
    for await (const c of req) body += c;
    const url = new URL(req.url, "http://x");
    const json = (code, data, headers = {}) => {
      res.writeHead(code, { "content-type": "application/json", ...headers });
      res.end(JSON.stringify(data));
    };
    const p = url.pathname;
    if (p === "/repos/o/r/pulls/1/files") return json(200, files);
    if (p === "/repos/o/r/compare/basesha...headsha") return json(200, { merge_base_commit: { sha: "mb" } });
    if (p.startsWith("/repos/o/r/contents/")) {
      const text = contents[`${url.searchParams.get("ref")}:${decodeURIComponent(p.slice("/repos/o/r/contents/".length))}`];
      if (text === undefined) return json(404, { message: "Not Found" });
      res.writeHead(200, { "content-type": "application/vnd.github.raw" });
      return res.end(text);
    }
    if (p === "/repos/o/r/issues/1/comments" && req.method === "GET") return json(200, state.comments);
    if (p === "/repos/o/r/issues/1/comments" && req.method === "POST") {
      const c = { id: state.nextId++, body: JSON.parse(body).body };
      state.comments.push(c);
      return json(201, c);
    }
    const edit = p.match(/^\/repos\/o\/r\/issues\/comments\/(\d+)$/);
    if (edit && req.method === "PATCH") {
      const c = state.comments.find((x) => x.id === Number(edit[1]));
      c.body = JSON.parse(body).body;
      return json(200, c);
    }
    const ask = p.match(/^\/engine\/v1\/ask\/(\d+)$/);
    if (ask && ANSWERS[ask[1]]) {
      if (!req.headers["payment-signature"]) return json(402, {}, { "PAYMENT-REQUIRED": b64(challenge) });
      state.asks.push({ miner: ask[1], ...JSON.parse(body) });
      return json(200, ANSWERS[ask[1]], { "X-TELEGRAPH-RECEIPT": b64({ receipt_hash: `0xrec${ask[1]}` }), "PAYMENT-RESPONSE": b64({ success: true }) });
    }
    json(404, { message: `unhandled ${req.method} ${p}` });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, state, base: `http://127.0.0.1:${server.address().port}` })));
}

function runAction(env, cwd) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [new URL("../src/index.js", import.meta.url).pathname], { env, cwd });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.on("close", (code) => resolve({ code, out }));
  });
}

test("action: buys a dependency check, confirms it with a second miner, blocks, one comment across re-runs", async () => {
  const { server, state, base } = await fakeServer();
  const dir = await mkdtemp(join(tmpdir(), "pr-guard-"));
  try {
    const event = { pull_request: { number: 1, title: "bump lodash", body: "", base: { sha: "basesha", repo: { full_name: "o/r" } }, head: { sha: "headsha", repo: { full_name: "o/r" } } } };
    await writeFile(join(dir, "event.json"), JSON.stringify(event));
    for (const f of ["out", "summary"]) await writeFile(join(dir, f), "");
    const env = {
      PATH: process.env.PATH,
      GITHUB_EVENT_NAME: "pull_request",
      GITHUB_EVENT_PATH: join(dir, "event.json"),
      GITHUB_REPOSITORY: "o/r",
      GITHUB_API_URL: base,
      GITHUB_SERVER_URL: "https://github.com",
      GITHUB_RUN_ID: "1",
      GITHUB_OUTPUT: join(dir, "out"),
      GITHUB_STEP_SUMMARY: join(dir, "summary"),
      "INPUT_GITHUB-TOKEN": "t",
      "INPUT_TELEGRAPH-PRIVATE-KEY": generatePrivateKey(),
      "INPUT_NODE-URL": base,
    };

    const first = await runAction(env, dir);
    assert.equal(first.code, 1, first.out); // fail-on: block
    const second = await runAction(env, dir);
    assert.equal(second.code, 1, second.out);

    assert.equal(state.comments.length, 1, "re-run updated the same comment");
    const comment = state.comments[0].body;
    assert.match(comment, /PR Guard: 🔴 BLOCK/);
    assert.match(comment, /deps: lodash@4\.17\.15 — high/);
    assert.match(comment, /\[Prototype Pollution in lodash\]\(https:\/\/osv\.dev\/vulnerability\/GHSA-p6mc-m468-83gw\)/);
    assert.match(comment, /confirmed/);
    assert.match(comment, /\/engine\/v1\/signal\/0x106d54f4/);
    const askedOf = (id) => state.asks.find((a) => a.miner === id);
    assert.deepEqual(askedOf("77010"), { miner: "77010", method: "GET", endpoint: "/query", payload: { pkg: "lodash", ver: "4.17.15" } });
    assert.deepEqual(askedOf("190048"), { miner: "190048", method: "GET", endpoint: "/query", payload: { system: "npm", pkg: "lodash", ver: "4.17.15" } });
    assert.equal(askedOf("302"), undefined, "id 302 is no longer ChainSight and must not be called");
    assert.equal(askedOf("5530").endpoint, "/v1/intent");
    assert.equal(askedOf("5530").payload.intent, "SECURITY_REVIEW");
    assert.match(askedOf("5530").payload.input.code, /^diff --git a\/package\.json/);
    assert.equal(askedOf("731001"), undefined, "the confirming reviewer is only asked about high findings");
    assert.match(comment, /\| diff \| package\.json, src\/app\.js \| ✅ none \|/);

    const ledger = (await readFile(join(dir, "pr-guard-ledger.jsonl"), "utf8")).trim().split("\n").map(JSON.parse);
    assert.equal(ledger.length, 6, "three paid calls per run: deps, its confirmation, the diff review");
    assert.ok(ledger.every((e) => e.cost_usd === 0.01 && e.receipt.receipt_hash.startsWith("0xrec")));
    assert.match(await readFile(join(dir, "out"), "utf8"), /cost_usd[\s\S]*0\.030000/);
  } finally {
    server.close();
  }
});
