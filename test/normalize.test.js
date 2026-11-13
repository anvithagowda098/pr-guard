// Normalizers against real paid responses (captured 2026-10-27 to 2026-11-13),
// and how their findings are confirmed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { normalize } from "../src/normalize.js";
import { decide } from "../src/policy.js";
import { confirmFindings, judgeRouted } from "../src/runner.js";

const capture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/miner-responses/SECURITY_REVIEW/${name}`, import.meta.url), "utf8"));
const result = (name) => capture(name).body.result;
const lodash15 = { ecosystem: "npm", name: "lodash", version: "4.17.15" };

test("deps.dev Package Review: lodash@4.17.15 has six advisories, worst HIGH", () => {
  const n = normalize("depsdev-version", result("77010-npm-lodash-4.17.15-200-paid.json"), lodash15);
  assert.equal(n.severity, "high");
  assert.deepEqual(n.findings.map((f) => `${f.id}:${f.severity}`), [
    "GHSA-29mw-wpgm-hmr9:medium",
    "GHSA-35jh-r3h4-6jhm:high",
    "GHSA-f23m-r3pf-42rh:medium",
    "GHSA-p6mc-m468-83gw:high",
    "GHSA-r5fr-rjxr-66jc:high",
    "GHSA-xxjr-mmjv-4gpg:medium",
  ]);
  const proto = n.findings.find((f) => f.id === "GHSA-p6mc-m468-83gw");
  assert.equal(proto.title, "Prototype Pollution in lodash");
  assert.match(proto.detail, /CVE-2020-8203 · CVSS 7\.4/);
  assert.equal(proto.ref, "https://osv.dev/vulnerability/GHSA-p6mc-m468-83gw");
});

test("deps.dev Package Review: a clean version is none", () => {
  assert.deepEqual(normalize("depsdev-version", result("77010-npm-lodash-4.18.1-200-paid.json"), { name: "lodash", version: "4.18.1" }), { severity: "none", findings: [], verified: true });
});

test("an answer about a different package or version is unknown, not trusted", () => {
  assert.equal(normalize("depsdev-version", result("77010-npm-lodash-4.18.1-200-paid.json"), lodash15).severity, "unknown");
  assert.equal(normalize("depsdev-advisory-keys", result("190048-npm-lodash-4.17.15-200-paid.json"), { name: "underscore", version: "4.17.15" }).severity, "unknown");
});

test("Secrev Depsdev: advisory ids only, so severity is unrated", () => {
  const n = normalize("depsdev-advisory-keys", result("190048-npm-lodash-4.17.15-200-paid.json"), lodash15);
  assert.equal(n.severity, "unknown");
  assert.equal(n.findings.length, 6);
  const django = normalize("depsdev-advisory-keys", result("190048-pypi-django-3.2.0-200-paid.json"), { name: "django", version: "3.2.0" });
  assert.equal(django.findings.length, 66);
  assert.ok(django.findings.some((f) => f.id.startsWith("PYSEC-")));
});

test("unknown normalizer or malformed answer is unknown", () => {
  assert.equal(normalize("nope", {}).severity, "unknown");
  assert.equal(normalize("depsdev-version", { version: {} }, lodash15).severity, "unknown");
  assert.equal(normalize("depsdev-advisory-keys", null, lodash15).severity, "unknown");
});

test("deps.dev Package Review is registry data about this exact version: a HIGH is confirmed -> BLOCK", () => {
  const n = normalize("depsdev-version", result("77010-npm-lodash-4.17.15-200-paid.json"), lodash15);
  assert.equal(n.verified, true);
  const c = confirmFindings("deps", n, lodash15);
  assert.deepEqual([c.confirmed, c.disagreement, c.findings.length], [true, false, 6]);
  assert.equal(decide([{ check: "deps", target: "lodash@4.17.15", status: "ok", calls: [], ...c }]).verdict, "BLOCK");
});

test("advisory ids with no rating, or a review that can't name the package, never BLOCK", () => {
  const ids = confirmFindings("deps", normalize("depsdev-advisory-keys", result("190048-npm-lodash-4.17.15-200-paid.json"), lodash15), lodash15);
  assert.deepEqual([ids.severity, ids.confirmed], ["unknown", false]);
  const review = confirmFindings("deps", normalize("security-review-format", { verdict: "Insecure", vulnerability_count: 1, issues: ["GHSA-p6mc-m468-83gw"] }), lodash15);
  assert.deepEqual([review.severity, review.confirmed], ["high", false]);
  assert.equal(decide([{ check: "deps", target: "x", status: "ok", calls: [], ...review }]).verdict, "CAUTION");
});

test("PyPI with only unrated ids cautions with a clear reason", () => {
  const n = normalize("depsdev-advisory-keys", result("190048-pypi-django-3.2.0-200-paid.json"), { name: "django", version: "3.2.0" });
  const { verdict, reasons } = decide([{ check: "deps", target: "django@3.2.0", status: "ok", confirmed: false, disagreement: false, calls: [], ...n }]);
  assert.equal(verdict, "CAUTION");
  assert.match(reasons[0], /66 findings, severity not rated/);
});

const chainsight = (name) => JSON.parse(readFileSync(new URL(`./fixtures/miner-responses/${name}`, import.meta.url), "utf8")).body.result;

test("ChainSight: verdicts and worst severity from real answers", () => {
  const read = (name) => normalize("chainsight-verdict", chainsight(name));
  assert.deepEqual(read("SECURITY_REVIEW/302-secreview-clean-200-paid.json"), { severity: "none", findings: [] });
  const evalCase = read("SECURITY_REVIEW/302-secreview-eval-200-paid.json");
  assert.equal(evalCase.severity, "critical");
  assert.match(evalCase.findings[0].title, /^eval\(req\.body\.expr\) runs arbitrary JavaScript/);
  assert.equal(read("AUTO/auto-security-question-sqli-200-paid.json").severity, "critical");
  // Cut off before any severity word: vulnerable, but unrated.
  const cmd = read("SECURITY_REVIEW/302-secreview-cmdinj-200-paid.json");
  assert.equal(cmd.severity, "unknown");
  assert.match(cmd.findings[0].title, /exec\('ping -c 1 ' \+ req\.query\.host/);
});

test("ChainSight: no verdict means unknown; one miner alone can't BLOCK", () => {
  assert.equal(normalize("chainsight-verdict", { answer: "I could not process this." }).severity, "unknown");
  const evalCase = normalize("chainsight-verdict", chainsight("SECURITY_REVIEW/302-secreview-eval-200-paid.json"));
  const { verdict, reasons } = decide([{ check: "diff", target: "src/calc.js", status: "ok", confirmed: false, disagreement: false, calls: [], ...evalCase }]);
  assert.equal(verdict, "CAUTION");
  assert.match(reasons[0], /critical, unconfirmed/);
});

test("Sentinel /package: real answer through Telegraph, rated, with upgrade advice", () => {
  const n = normalize("sentinel-package", result("731001-package-npm-lodash-4.17.15-200-paid.json"), lodash15);
  assert.equal(n.severity, "high");
  assert.equal(n.findings.length, 6);
  assert.equal(n.advice, "upgrade to 4.18.0");
  assert.ok(n.findings.every((f) => f.id && Array.isArray(f.aliases)));
  assert.equal(normalize("sentinel-package", result("731001-package-npm-lodash-4.17.15-200-paid.json"), { name: "lodash", version: "4.17.21" }).severity, "unknown");
});

test("Sentinel /package is checked against the exact version: confirmed, with upgrade advice", () => {
  const c = confirmFindings("deps", normalize("sentinel-package", result("731001-package-npm-lodash-4.17.15-200-paid.json"), lodash15), lodash15);
  assert.equal(c.confirmed, true);
  assert.equal(c.advice, "upgrade to 4.18.0");
});

test("Sentinel /review: findings keep file and line; clean code is none", async () => {
  const { createHandler } = await import("../miner/worker.js");
  const ask = async (diff) => (await (await createHandler()(new Request("https://m.test/review", { method: "POST", body: JSON.stringify({ diff }) }))).json());
  const bad = normalize("sentinel-review", await ask("diff --git a/db.js b/db.js\n@@ -1,1 +1,2 @@\n x\n+db.query(\"SELECT * FROM t WHERE id = '\" + req.query.id + \"'\")"));
  assert.equal(bad.severity, "critical");
  assert.deepEqual([bad.findings[0].file, bad.findings[0].line], ["db.js", 2]);
  assert.match(bad.findings[0].title, /SQL built from strings \(CWE-89\)/);
  assert.deepEqual(normalize("sentinel-review", await ask("diff --git a/a.js b/a.js\n@@ -1,1 +1,2 @@\n x\n+const y = 2;")), { severity: "none", findings: [] });
  assert.equal(normalize("sentinel-review", { answer: "no structure" }).severity, "unknown");
});

const newNet = (name) => JSON.parse(readFileSync(new URL(`./fixtures/miner-responses/SECURITY_REVIEW_GENERAL/${name}`, import.meta.url), "utf8"));

test("Verity (independent): both planted bugs, mapped to the real file and line", () => {
  const cap = newNet("5530-review-two-file-diff-200-paid.json");
  const n = normalize("verity-security", cap.body.result, { diff: cap.request.payload.input.code });
  assert.equal(n.severity, "high");
  assert.deepEqual(n.findings.map((f) => `${f.file}:${f.line}`), ["src/routes/user.js:12", "src/routes/calc.js:2"]);
  assert.match(n.findings[0].detail, /^sql-injection-risk → Use parameterized queries/);
});

test("Verity: clean diff is none ('uncertain', no findings); unusable input is unknown", () => {
  const clean = newNet("5530-review-clean-diff-200-paid.json");
  assert.deepEqual(normalize("verity-security", clean.body.result, { diff: clean.request.payload.input.code }), { severity: "none", findings: [] });
  assert.equal(normalize("verity-security", newNet("5530-input-as-string-rejected-200-paid.json").body.result, {}).severity, "unknown");
});

test("Verity's high findings are confirmed by PR Guard's local rules at the same file:line -> BLOCK", () => {
  const v = newNet("5530-review-two-file-diff-200-paid.json");
  const diff = v.request.payload.input.code;
  const c = confirmFindings("diff", normalize("verity-security", v.body.result, { diff }), { diff });
  assert.deepEqual([c.confirmed, c.disagreement, c.severity], [true, false, "critical"], "the higher of the two: PR Guard's rule rates SQL on user input critical");
  assert.ok(c.findings.every((f) => f.corroborated));
  assert.equal(decide([{ check: "diff", target: "src/routes", status: "ok", calls: [], ...c }]).verdict, "BLOCK");
});

test("local rules catch what a reviewer misses: CAUTION, never a silent SAFE", () => {
  const diff = "diff --git a/db.js b/db.js\n@@ -1,1 +1,2 @@\n x\n+db.query(\"SELECT * FROM t WHERE id = '\" + req.query.id + \"'\")";
  const c = confirmFindings("diff", { severity: "none", findings: [] }, { diff });
  assert.deepEqual([c.severity, c.confirmed, c.disagreement], ["medium", false, true]);
  assert.match(c.findings[0].title, /PR Guard local rule/);
  assert.equal(decide([{ check: "diff", target: "db.js", status: "ok", calls: [], ...c }]).verdict, "CAUTION");
});

const routed = (name) => JSON.parse(readFileSync(new URL(`./fixtures/miner-responses/ROUTED/${name}`, import.meta.url), "utf8"));
const asRecord = (cap) => ({ ok: cap.ok, status: cap.status, body: cap.body, costUsd: cap.costUsd });

test("routed CODE_REVIEW_GENERAL (miner 302, intent format): security findings rated, style notes low", () => {
  const cap = routed("code-review-sqli-eval-diff-302-intent.json");
  const diff = cap.request.params.code;
  const route = { intent: "CODE_REVIEW_GENERAL", params: { code: diff }, normalizer: "code-review-format" };
  const { answer } = judgeRouted(asRecord(cap), route, [], { diff });
  assert.equal(answer.severity, "high");
  assert.deepEqual(answer.findings.filter((f) => f.category).map((f) => f.category), ["sql-injection", "code-injection"]);
  assert.ok(answer.findings.filter((f) => !f.category).every((f) => f.severity === "low"));
  const c = confirmFindings("diff", answer, { diff });
  assert.equal(c.confirmed, true, "local rules find the same two issues");
  assert.equal(normalize("code-review-format", { verdict: "Approve", findings: [] }).severity, "none");
  assert.equal(normalize("code-review-format", { verdict: "maybe" }).severity, "unknown");
});

test("routed SECURITY_REVIEW_GENERAL went to miner 77003, which ignored the target: rejected, for packages and code", () => {
  for (const name of ["security-review-lodash-77003-off-target.json", "security-review-diff-77003-off-target.json"]) {
    const cap = routed(name);
    assert.equal(cap.body.result_shape, "raw");
    const route = { intent: "SECURITY_REVIEW_GENERAL", params: cap.request.params, normalizer: "security-review-format" };
    const judged = judgeRouted(asRecord(cap), route, [{ minerId: "77010", normalizer: "depsdev-version" }], lodash15);
    assert.match(judged.reject, /miner 77003 answered in its own format, and not about this target/);
  }
  assert.match(judgeRouted({ ok: false, status: 503, reason: "http_503" }, {}, [], {}).reject, /could not route/);
});

test("a routed raw answer from a vetted miner is read with that miner's normalizer", () => {
  const body = { miner_id: "77010", result_shape: "raw", result: result("77010-npm-lodash-4.17.15-200-paid.json") };
  const { answer } = judgeRouted({ ok: true, status: 200, body }, { normalizer: "security-review-format" }, [{ minerId: "77010", normalizer: "depsdev-version" }], lodash15);
  assert.deepEqual([answer.severity, answer.verified], ["high", true]);
});

test("Sentinel /package on the new network rates PyPI with upgrade advice", () => {
  const n = normalize("sentinel-package", newNet("731001-package-pypi-django-3.2.0-200-paid.json").body.result, { name: "django", version: "3.2.0" });
  assert.equal(n.severity, "critical");
  assert.equal(n.findings.length, 38);
  assert.equal(n.advice, "upgrade to 5.2.17");
});

test("code review wording: a negated or approved mention is not a finding", () => {
  const n = normalize("code-review-format", { verdict: "Request changes", findings: ["The query is parameterized, so there is no SQL injection risk.", "Path traversal: req.params.file is joined into a filesystem path."] });
  assert.deepEqual(n.findings.map((f) => [f.category ?? null, f.severity]), [[null, "low"], ["path-traversal", "high"]]);
  const ok = normalize("code-review-format", { verdict: "Approve", findings: ["Uses eval() only on a constant string."] });
  assert.equal(ok.severity, "low");
});

test("Unicode hyphens in a finding still name its category (seen live from miner 302)", () => {
  const n = normalize("code-review-format", { verdict: "Request changes", findings: ["Hard‑coded AWS credentials expose secrets; they will be leaked."] });
  assert.deepEqual([n.findings[0].category, n.findings[0].severity], ["hardcoded-secret", "high"]);
});

test("Solidity through routed code review (miner 302, captured): reentrancy and open setOwner, confirmed by PR Guard's rules -> BLOCK", () => {
  const cap = routed("code-review-solidity-reentrancy-302-intent.json");
  const diff = cap.request.params.code;
  const n = normalize("code-review-format", cap.body.result);
  assert.deepEqual(n.findings.filter((f) => f.category).map((f) => f.category), ["reentrancy", "access-control"]);
  const c = confirmFindings("diff", n, { diff });
  assert.deepEqual([c.confirmed, c.disagreement], [true, false]);
  assert.equal(decide([{ check: "diff", target: "contracts/Vault.sol", status: "ok", calls: [], ...c }]).verdict, "BLOCK");
});

// ---- GoPlus (#200001), captured Nov 13 -----------------------------------
const goplus = () => JSON.parse(readFileSync(new URL("./fixtures/miner-responses/SMART_CONTRACT_AUDIT_GENERAL/200001-token-security-usdt-200-paid.json", import.meta.url), "utf8"));
const usdt = { address: "0xdAC17F958D2ee523a2206206994597C13D831ec7", chain_id: "1" };

test("GoPlus on USDT: an established token's admin powers are known, so nothing above low", () => {
  const n = normalize("goplus-token-security", goplus().body.result, usdt);
  assert.deepEqual([n.severity, n.verified], ["low", true]);
  assert.equal(n.findings[0].title, "Tether USD (USDT), on GoPlus's trusted list");
  assert.ok(n.findings.some((f) => f.title === "the owner can change balances" && f.severity === "low"));
  assert.equal(decide([{ check: "addresses", target: "USDT", status: "ok", calls: [], ...confirmFindings("addresses", n, usdt) }]).verdict, "SAFE");
});

test("GoPlus: a honeypot outside the trusted list is high and confirmed -> BLOCK; no token data is low", () => {
  const cap = goplus().body.result;
  const t = cap.result[usdt.address.toLowerCase()];
  const honeypot = { ...cap, result: { [usdt.address.toLowerCase()]: { ...t, trust_list: "0", is_honeypot: "1", is_open_source: "0" } } };
  const c = confirmFindings("addresses", normalize("goplus-token-security", honeypot, usdt), usdt);
  assert.deepEqual([c.severity, c.confirmed], ["high", true]);
  assert.ok(c.findings.some((f) => f.title === "source code not verified" && f.severity === "medium"));
  assert.equal(decide([{ check: "addresses", target: "x", status: "ok", calls: [], ...c }]).verdict, "BLOCK");
  assert.equal(normalize("goplus-token-security", { code: 1, message: "OK", result: {} }, usdt).severity, "low");
  assert.equal(normalize("goplus-token-security", { code: 2, message: "error" }, usdt).severity, "unknown");
  assert.equal(normalize("goplus-token-security", cap, { address: "0x2222222222222222222222222222222222222222" }).severity, "low", "an answer without this address has no data about it");
});

test("live, Nov 13: a reviewer that names a reentrancy but rates it low is overruled by PR Guard's rules -> BLOCK", () => {
  const diff = routed("code-review-solidity-reentrancy-302-intent.json").request.params.code;
  // The shape miner 302 returned for demo PR #5: the issues named, the verdict "Approve".
  const n = normalize("code-review-format", { verdict: "Approve", findings: ["Reentrancy: withdraw sends ETH before zeroing the balance.", "Unrestricted ownership change: setOwner has no modifier."] });
  assert.equal(n.severity, "low");
  const c = confirmFindings("diff", n, { diff });
  assert.deepEqual([c.severity, c.confirmed], ["high", true]);
  assert.equal(decide([{ check: "diff", target: "Vault.sol", status: "ok", calls: [], ...c }]).verdict, "BLOCK");
});

test("a hard-coded token address is not a hard-coded secret", () => {
  const n = normalize("code-review-format", { verdict: "Request changes", findings: ["Hard‑coded token address (USDT) assumes the token exists on the target chain.", "Hard-coded API key in config."] });
  assert.deepEqual(n.findings.map((f) => f.category ?? null), [null, "hardcoded-secret"]);
});

// ---- CodeWire Smart Contract Audit (#1900999007), captured Nov 13 -----------
const codewire = (name) => JSON.parse(readFileSync(new URL(`./fixtures/miner-responses/SMART_CONTRACT_AUDIT_GENERAL/${name}`, import.meta.url), "utf8"));

test("CodeWire on the demo vault: reentrancy critical, missing access control high, confirmed by PR Guard's rules -> BLOCK", () => {
  const cap = codewire("1900999007-audit-reentrant-vault-200-paid.json");
  const n = normalize("codewire-audit", cap.body.result);
  assert.deepEqual(n.findings.slice(0, 2).map((f) => [f.category, f.severity]), [["reentrancy", "critical"], ["access-control", "high"]]);
  const diff = cap.request.payload.contract;
  const c = confirmFindings("diff", n, { diff });
  assert.equal(c.confirmed, true);
  assert.equal(decide([{ check: "diff", target: "Vault.sol", status: "ok", calls: [], ...c }]).verdict, "BLOCK");
});

test("CodeWire on the fixed vault: only low findings -> SAFE; no verdict -> unknown", () => {
  const cap = codewire("1900999007-audit-fixed-vault-200-paid.json");
  const n = normalize("codewire-audit", cap.body.result);
  assert.equal(n.severity, "low");
  assert.ok(n.findings.length >= 2 && n.findings.every((f) => f.severity === "low"));
  const c = confirmFindings("diff", n, { diff: cap.request.payload.contract });
  assert.equal(decide([{ check: "diff", target: "Vault.sol", status: "ok", calls: [], ...c }]).verdict, "SAFE");
  assert.equal(normalize("codewire-audit", { summary: "no structure" }).severity, "unknown");
});
