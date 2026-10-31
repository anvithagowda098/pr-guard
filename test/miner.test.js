// PR Guard Sentinel miner: rules, OSV summarizing and the HTTP contract.
// OSV is stubbed with a real advisory record captured from Telegraph.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { scan } from "../miner/rules.js";
import { cvss3Score, packagesIn, lookupPackage, dedupe, compareVersions } from "../miner/osv.js";
import { createHandler, upgradeAdvice } from "../miner/worker.js";

const AWS_ID = "AKIA" + "Z7QW3XK2LMNOPQRS";
const osvRecord = JSON.parse(readFileSync(new URL("./fixtures/miner-responses/CVE_LOOKUP/36009-GHSA-p6mc-m468-83gw-200-paid.json", import.meta.url), "utf8")).body.result;
const rules = (code) => scan(code).findings.map((f) => `${f.rule}:${f.severity}`);

test("flags the cases ChainSight was tested on", () => {
  assert.deepEqual(rules(`const rows = await db.query("SELECT * FROM users WHERE id = '" + req.query.id + "'");`), ["sql-injection:critical"]);
  assert.deepEqual(rules("res.send(String(eval(req.body.expr)));"), ["code-injection:critical"]);
  assert.deepEqual(rules("exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));"), ["command-injection:critical"]);
});

test("leaves the safe versions alone", () => {
  for (const code of [
    'cur.execute("INSERT INTO users (name) VALUES (%s)", (name,))',
    "const rows = await db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);",
    "execFile('ping', ['-c', '1', host], cb);",
    "const data = yaml.load(text, Loader=yaml.SafeLoader)",
    "data = yaml.safe_load(text)",
    "el.textContent = req.query.name;",
    'el.innerHTML = "<b>static</b>";',
    "// eval(req.body.expr) used to live here",
    "const msg = 'select a file from the list' + suffix;",
  ]) {
    assert.deepEqual(rules(code), [], code);
  }
});

test("other rule families across languages", () => {
  const cases = {
    "obj = pickle.loads(request.data)": "unsafe-deserialization:critical",
    "cfg = yaml.load(open('c.yml'))": "unsafe-deserialization:high",
    "requests.get(url, verify=False)": "tls-verification-disabled:high",
    "tls.Config{InsecureSkipVerify: true}": "tls-verification-disabled:high",
    "os.system('tar xf ' + name)": "command-injection:high",
    "subprocess.run(cmd, shell=True)": "command-injection:high",
    'cur.execute(f"SELECT * FROM t WHERE id = {uid}")': "sql-injection:high",
    "res.sendFile(req.query.path)": "path-traversal:high",
    "const r = await fetch(req.query.url);": "ssrf:high",
    "el.innerHTML = comment.body;": "xss:medium",
    "const h = crypto.createHash('md5').update(password)": "weak-hash:high",
    "app.run(debug=True)": "debug-enabled:medium",
  };
  for (const [code, want] of Object.entries(cases)) assert.deepEqual(rules(code), [want], code);
});

test("secrets are found, even in comments, and never echoed back", () => {
  const { findings } = scan(`// old key: ${AWS_ID}\nconst x = 1;`);
  assert.deepEqual(findings.map((f) => [f.rule, f.line]), [["hardcoded-secret", 1]]);
  assert.ok(!JSON.stringify(findings).includes(AWS_ID));
  assert.match(findings[0].evidence, /\[REDACTED:aws_access_key_id\]/);
});

test("diffs: only added lines, with new-file line numbers", () => {
  const diff = "diff --git a/a.js b/a.js\n@@ -10,2 +10,3 @@\n-eval(req.body.old)\n context()\n+res.send(eval(req.body.expr))\n+ok()";
  const { findings, linesScanned } = scan(diff);
  assert.equal(linesScanned, 2);
  assert.deepEqual(findings.map((f) => [f.rule, f.line]), [["code-injection", 11]]);
});

test("the planted-vulnerability PR fixture", () => {
  const patch = readFileSync(new URL("./fixtures/prs/leaked-secret-sqli.patch", import.meta.url), "utf8").replace("__AWS_KEY_ID__", AWS_ID);
  assert.deepEqual(scan(patch).findings.map((f) => `${f.rule}@${f.line}`), ["hardcoded-secret@3", "sql-injection@9", "code-injection@13"]);
  const clean = readFileSync(new URL("./fixtures/prs/clean.patch", import.meta.url), "utf8");
  assert.deepEqual(scan(clean).findings, []);
});

test("CVSS v3 base scores match the spec's examples", () => {
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"), 7.4);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
  assert.equal(cvss3Score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8);
  assert.equal(cvss3Score("CVSS:4.0/AV:N/AC:L"), null);
});

test("package mentions in free text", () => {
  assert.deepEqual(packagesIn("Check lodash@4.17.15, @babel/core@7.0.0 and django==3.2.0, contact a@b.com"), [
    { ecosystem: "npm", name: "lodash", version: "4.17.15" },
    { ecosystem: "npm", name: "@babel/core", version: "7.0.0" },
    { ecosystem: "PyPI", name: "django", version: "3.2.0" },
  ]);
  assert.deepEqual(packagesIn("cargo: serde@1.0.100"), [{ ecosystem: "crates.io", name: "serde", version: "1.0.100" }]);
});

const osvStub = (vulns) => {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    return new Response(JSON.stringify(vulns.length ? { vulns } : {}), { status: 200 });
  };
  return { fetch, calls };
};

test("OSV lookup: rated, with fixed versions; clean is none", async () => {
  const stub = osvStub([osvRecord]);
  const r = await lookupPackage({ ecosystem: "npm", name: "lodash", version: "4.17.15" }, stub.fetch);
  assert.deepEqual(stub.calls[0], { url: "https://api.osv.dev/v1/query", body: { version: "4.17.15", package: { name: "lodash", ecosystem: "npm" } } });
  assert.equal(r.severity, "high");
  assert.deepEqual(r.vulnerabilities[0].fixed_in, ["4.17.19"]);
  assert.equal((await lookupPackage({ ecosystem: "pypi", name: "x", version: "1" }, osvStub([]).fetch)).severity, "none");
});

const post = (handler, path, body) =>
  handler(new Request(`https://miner.test${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: typeof body === "string" ? body : JSON.stringify(body) }));

test("HTTP: /review answers in prose first, with structured findings", async () => {
  const handler = createHandler({ fetch: osvStub([osvRecord]).fetch });
  const res = await post(handler, "/review", { query: "Review this and check lodash@4.17.15:\nexec('ping -c 1 ' + req.query.host)" });
  assert.equal(res.status, 200);
  const b = await res.json();
  assert.match(b.answer, /^Verdict: vulnerable\. 1 code issue: critical: OS command built from strings \(CWE-78\) at line 2/);
  assert.match(b.answer, /lodash 4\.17\.15 \(npm\) has 1 known vulnerability \(1 high\), worst: Prototype Pollution in lodash \[GHSA-p6mc-m468-83gw, CVE-2020-8203\]; upgrade to 4\.17\.19 or later to fix all of them\./);
  assert.equal(b.packages[0].upgrade_to, "4.17.19");
  assert.equal(b.severity, "critical");
  assert.equal(b.confidence, 0.95);
  assert.equal(b.findings[0].line, 2);
});

test("HTTP: clean code is secure, with a modest confidence", async () => {
  const b = await (await post(createHandler({ fetch: osvStub([]).fetch }), "/review", { code: "const total = items.reduce((a, b) => a + b, 0);" })).json();
  assert.equal(b.verdict, "secure");
  assert.match(b.answer, /^Verdict: secure\. No injection, eval, shell/);
  assert.equal(b.confidence, 0.6);
});

test("HTTP: /package by fields or by query, and errors", async () => {
  const handler = createHandler({ fetch: osvStub([osvRecord]).fetch });
  const byFields = await (await post(handler, "/package", { ecosystem: "npm", name: "lodash", version: "4.17.15" })).json();
  assert.equal(byFields.verdict, "vulnerable");
  assert.equal(byFields.packages[0].vulnerabilities[0].id, "GHSA-p6mc-m468-83gw");
  const byQuery = await (await post(handler, "/package", { query: "is lodash@4.17.15 safe?" })).json();
  assert.equal(byQuery.packages[0].name, "lodash");

  assert.equal((await post(handler, "/package", { name: "x" })).status, 400);
  assert.equal((await post(handler, "/package", { ecosystem: "cobol", name: "x", version: "1" })).status, 400);
  assert.equal((await post(handler, "/review", {})).status, 400);
  assert.equal((await post(handler, "/review", "{not json")).status, 400);
  assert.equal((await post(handler, "/review", { code: "x".repeat(200_001) })).status, 413);
  assert.equal((await handler(new Request("https://miner.test/review"))).status, 405);
  assert.equal((await handler(new Request("https://miner.test/health"))).status, 200);
});

test("HTTP: an OSV outage degrades to 'could not be looked up', not a false secure", async () => {
  const handler = createHandler({ fetch: async () => new Response("down", { status: 503 }) });
  const b = await (await post(handler, "/review", { query: "is lodash@4.17.15 ok?" })).json();
  assert.match(b.answer, /lodash 4\.17\.15 \(npm\) could not be looked up\./);
  assert.equal(b.confidence, 0.4);
  assert.equal((await post(handler, "/package", { name: "lodash", version: "4.17.15" })).status, 502);
});

test("OSV duplicates (PYSEC + GHSA) merge, keeping the rated record", () => {
  const merged = dedupe([
    { id: "PYSEC-2021-1", aliases: ["CVE-2021-1"], severity: "unrated", cvss: null, fixed_in: ["3.2.1"] },
    { id: "GHSA-aaaa", aliases: ["CVE-2021-1"], severity: "high", cvss: 7.5, fixed_in: ["3.1.9", "3.2.1"] },
    { id: "GHSA-bbbb", aliases: [], severity: "low", cvss: 3.1, fixed_in: [] },
  ]);
  assert.deepEqual(merged.map((v) => [v.id, v.severity, v.aliases, v.fixed_in]), [
    ["GHSA-aaaa", "high", ["CVE-2021-1", "PYSEC-2021-1"], ["3.1.9", "3.2.1"]],
    ["GHSA-bbbb", "low", [], []],
  ]);
});

test("versions sort numerically", () => {
  assert.deepEqual(["4.17.21", "4.18.0", "4.17.19", "4.17.9", "v1.10.0", "v1.9.2"].sort(compareVersions), ["v1.9.2", "v1.10.0", "4.17.9", "4.17.19", "4.17.21", "4.18.0"]);
});

test("upgrade advice: the lowest version that fixes everything", () => {
  const vulns = [{ fixed_in: ["4.17.19"] }, { fixed_in: ["3.9.0", "4.17.21"] }, { fixed_in: ["4.18.0"] }];
  assert.deepEqual(upgradeAdvice("4.17.15", vulns), { upgrade_to: "4.18.0", unfixed: 0 });
  assert.deepEqual(upgradeAdvice("4.17.15", [...vulns, { fixed_in: [] }]), { upgrade_to: "4.18.0", unfixed: 1 });
  assert.deepEqual(upgradeAdvice("1.0.0", [{ fixed_in: ["0.9.0"] }]), { upgrade_to: null, unfixed: 1 });
});

test("GET /miner.yaml serves exactly the committed YAML", async () => {
  const res = await createHandler()(new Request("https://miner.test/miner.yaml"));
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(await res.text(), readFileSync(new URL("../miner/miner.yaml", import.meta.url), "utf8"), "run node scripts/embed-yaml.js");
});

test("multi-file diffs: each finding names its file", () => {
  const diff = [
    "diff --git a/src/calc.js b/src/calc.js",
    "@@ -1,1 +1,2 @@",
    " const x = 1;",
    "+res.send(eval(req.body.expr));",
    "diff --git a/app/db.py b/app/db.py",
    "@@ -40,1 +40,2 @@",
    " def get(uid):",
    '+    cur.execute(f"SELECT * FROM users WHERE id = {uid}")',
  ].join("\n");
  assert.deepEqual(scan(diff).findings.map((f) => `${f.rule}@${f.file}:${f.line}`), ["code-injection@src/calc.js:2", "sql-injection@app/db.py:41"]);
});

test("registration helper sends exactly the intended transactions", async () => {
  const { REGISTRATION: r, APPROVE_DATA, REGISTER_DATA } = await import("../miner/register-page.js");
  const { decodeFunctionData, parseAbi } = await import("viem");
  const yaml = readFileSync(new URL("../miner/miner.yaml", import.meta.url), "utf8");
  const { createHash } = await import("node:crypto");
  assert.equal(r.yamlHash, "0x" + createHash("sha256").update(yaml).digest("hex"), "helper must commit to the current YAML");
  assert.ok(yaml.includes("- " + r.intents[0]), "helper intents must match the YAML");
  const reg = decodeFunctionData({ abi: parseAbi(["function registerMiner(string,bytes32,address,uint256,string[]) returns (uint256)"]), data: REGISTER_DATA });
  assert.deepEqual(reg.args, [r.yamlUrl, r.yamlHash, r.owner, 10000n, ["SECURITY_REVIEW_GENERAL"]]);
  const appr = decodeFunctionData({ abi: parseAbi(["function approve(address,uint256) returns (bool)"]), data: APPROVE_DATA });
  assert.deepEqual(appr.args, [r.diamond, 3n * 10n ** 18n]);
  // The page was served once at /register (Oct 31) and removed after use.
  assert.equal((await createHandler()(new Request("https://miner.test/register"))).status, 405);
});
