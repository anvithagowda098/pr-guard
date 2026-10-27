// End to end on loopback: the real action entry point against a fake GitHub
// API and a fake payment-gated node. Proves the wiring (files -> deps ->
// paid call -> ledger -> one comment, updated on re-run), not miner quality.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generatePrivateKey } from "viem/accounts";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64");
const challenge = {
  x402Version: 2,
  resource: { url: "http://local/engine/v1/ask/7", description: "t", mimeType: "application/json" },
  accepts: [{ scheme: "exact", network: "eip155:84532", amount: "10000", asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", payTo: "0x000000000000000000000000000000000000dEaD", maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" } }],
};

function fakeServer() {
  const state = { comments: [], asks: [], nextId: 1 };
  const files = [
    { filename: "package.json", status: "modified", patch: '@@ -1 +1 @@\n-"lodash": "4.17.21"\n+"lodash": "4.17.15"' },
    { filename: "src/app.js", status: "modified", patch: "@@ -1,1 +1,2 @@\n const a = 1;\n+const key = \"" + "AKIA" + "Z7QW3XK2LMNOPQRS" + "\";" },
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
    if (p === "/engine/v1/ask/7") {
      state.asks.push(JSON.parse(body));
      if (!req.headers["payment-signature"]) return json(402, {}, { "PAYMENT-REQUIRED": b64(challenge) });
      return json(200, { miner_id: 7, miner_name: "fake", result: "opaque", cost_usd: 0.01, signal_hash: "0xsig" }, { "X-TELEGRAPH-RECEIPT": b64({ receipt_hash: "0xrec" }), "PAYMENT-RESPONSE": b64({ success: true }) });
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

test("action: pays for a dependency check, blocks on a committed key, one comment across re-runs", async () => {
  const { server, state, base } = await fakeServer();
  const dir = await mkdtemp(join(tmpdir(), "pr-guard-"));
  try {
    const event = { pull_request: { number: 1, title: "bump lodash", body: "", base: { sha: "basesha", repo: { full_name: "o/r" } }, head: { sha: "headsha", repo: { full_name: "o/r" } } } };
    await writeFile(join(dir, "event.json"), JSON.stringify(event));
    await writeFile(join(dir, "miners.json"), JSON.stringify({ CVE_LOOKUP: [{ minerId: 7, endpoint: "/cve", payload: { package: "{{name}}", version: "{{version}}" } }] }));
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
      "INPUT_MINERS-CONFIG": join(dir, "miners.json"),
      INPUT_CHECKS: "deps",
    };

    const first = await runAction(env, dir);
    assert.equal(first.code, 1, first.out); // fail-on: block
    const second = await runAction(env, dir);
    assert.equal(second.code, 1, second.out);

    assert.equal(state.comments.length, 1, "re-run updated the same comment");
    const comment = state.comments[0].body;
    assert.match(comment, /PR Guard: 🔴 BLOCK/);
    assert.match(comment, /aws access key id/);
    assert.match(comment, /lodash@4\.17\.15/);
    assert.match(comment, /\/engine\/v1\/signal\/0xsig/);
    assert.deepEqual(state.asks[0], { method: "POST", endpoint: "/cve", payload: { package: "lodash", version: "4.17.15" } });

    const ledger = (await readFile(join(dir, "pr-guard-ledger.jsonl"), "utf8")).trim().split("\n").map(JSON.parse);
    assert.equal(ledger.length, 2);
    assert.equal(ledger[0].signal_hash, "0xsig");
    assert.equal(ledger[0].cost_usd, 0.01);
    assert.match(await readFile(join(dir, "out"), "utf8"), /cost_usd[\s\S]*0\.010000/);
  } finally {
    server.close();
  }
});
