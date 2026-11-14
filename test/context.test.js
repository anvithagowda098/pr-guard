// Impact context: call sites of changed code, sent to the reviewer with the diff.
import { test } from "node:test";
import assert from "node:assert/strict";
import { changedSymbols, findUsages, contextBlock } from "../src/context.js";
import { buildJobs } from "../src/checks.js";
import { planScan } from "../src/plan.js";

const patch = (file, body) => ({ filename: file, status: "modified", patch: body });

test("changedSymbols: definitions on changed lines and enclosing functions from hunk headers", () => {
  const files = [
    patch("src/validate.js", "@@ -10,4 +10,4 @@ export function sanitizeId(raw) {\n-  return String(raw).replace(/[^0-9]/g, \"\");\n+  return String(raw);\n }"),
    patch("app/auth.py", "@@ -1,2 +1,3 @@\n+def require_admin(user):\n+    return True"),
    patch("contracts/Vault.sol", "@@ -5,3 +5,4 @@ contract Vault {\n+    modifier onlyKeeper() { _; }"),
    patch("README.md", "@@ -1 +1 @@\n+function notCode() {}"),
    patch("src/x.js", "@@ -1 +1 @@\n+function run() {}"),
  ];
  assert.deepEqual(changedSymbols(files).map((s) => `${s.file}:${s.name}`), [
    "src/validate.js:sanitizeId",
    "app/auth.py:require_admin",
    "contracts/Vault.sol:Vault",
    "contracts/Vault.sol:onlyKeeper",
  ]);
});

test("findUsages: nearest files first, not the changed files or tests, definitions skipped, secrets redacted", async () => {
  const repo = {
    "src/routes/user.js": "const { sanitizeId } = require('../validate');\napp.get('/u', (req, res) => db.query(`SELECT * FROM u WHERE id = ${sanitizeId(req.query.id)}`));",
    "src/validate.js": "export function sanitizeId(raw) {}",
    "src/routes/user.test.js": "sanitizeId('1')",
    "lib/other.js": "const key = 'AKIAQ7Z3LMNOPQRS4TUV'; sanitizeId(key);",
    "docs/guide.md": "sanitizeId",
  };
  const sites = await findUsages({
    symbols: [{ name: "sanitizeId", file: "src/validate.js" }],
    paths: Object.keys(repo),
    read: async (p) => repo[p],
    changed: ["src/validate.js"],
  });
  assert.deepEqual(sites.map((s) => `${s.path}:${s.line}`), ["src/routes/user.js:1", "src/routes/user.js:2", "lib/other.js:1"]);
  assert.ok(!sites.some((s) => /AKIA/.test(s.text)), "secrets in context are redacted");
  assert.match(contextBlock(sites), /^\n# Read-only context, not part of this change[\s\S]*# src\/routes\/user\.js:2 uses sanitizeId \(changed in src\/validate\.js\)\n#   app\.get/);
});

test("diff jobs carry the context in the review text, and in the routed ask only when it fits", () => {
  const files = [patch("src/validate.js", "@@ -10,4 +10,4 @@ export function sanitizeId(raw) {\n-  return x;\n+  return y;\n }")];
  const site = { symbol: "sanitizeId", from: "src/validate.js", path: "src/routes/user.js", line: 2, text: "db.query(sanitizeId(req.query.id))" };
  const [job] = buildJobs({ deps: [], files, usages: [site] }, new Set(["diff"]));
  assert.match(job.vars.review, /# src\/routes\/user\.js:2 uses sanitizeId/);
  assert.equal(job.route.params.code, job.vars.review);
  assert.match(job.notes[0], /^Context: 1 call site of changed code in 1 other file sent with the diff\.$/);
  const many = Array.from({ length: 12 }, (_, i) => ({ ...site, line: i + 1, text: "x".repeat(150) }));
  const [big] = buildJobs({ deps: [], files, usages: many }, new Set(["diff"]));
  assert.equal(big.route.params.code, big.vars.diff, "over 2,000 characters: the routed ask gets the diff alone");
  assert.match(big.notes[0], /except in the routed ask \(2,000-character limit\)/);
});

test("planScan finds call sites through the repository tree, and a failing tree lookup just skips context", async () => {
  const files = [patch("src/validate.js", "@@ -10,4 +10,4 @@ export function sanitizeId(raw) {\n-  return x;\n+  return y;\n }")];
  const repo = { "h:src/routes/user.js": "db.query(sanitizeId(req.query.id));" };
  const base = { pr: { title: "Loosen sanitizeId" }, rawFiles: files, baseSha: "b", headSha: "h", getText: async ({ path, ref }) => repo[`${ref}:${path}`] ?? null, checks: new Set(["diff"]) };
  const { jobs } = await planScan({ ...base, listPaths: async () => ["src/validate.js", "src/routes/user.js"] });
  assert.match(jobs[0].vars.review, /src\/routes\/user\.js:1 uses sanitizeId/);
  const failing = await planScan({ ...base, listPaths: async () => { throw new Error("rate limited"); } });
  assert.equal(failing.jobs[0].vars.review, failing.jobs[0].vars.diff);
});
