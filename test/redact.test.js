import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { redact, scanSecrets } from "../src/redact.js";

// Fake credentials are assembled at runtime so no secret-shaped literal sits
// in the repo for push protection to trip on.
const AWS_ID = "AKIA" + "Z7QW3XK2LMNOPQRS";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYzFAKEKEYQQ";
const GH_TOKEN = "ghp_" + "a".repeat(36);
const secretPatch = readFileSync(new URL("./fixtures/prs/leaked-secret-sqli.patch", import.meta.url), "utf8")
  .replace("__AWS_KEY_ID__", AWS_ID)
  .replace("__AWS_SECRET__", AWS_SECRET);

test("redact removes key material and keeps the surrounding code", () => {
  const { text, hits } = redact(secretPatch);
  assert.ok(!text.includes(AWS_ID));
  assert.ok(!text.includes(AWS_SECRET));
  assert.match(text, /AWS_ACCESS_KEY_ID = "\[REDACTED:aws_access_key_id\]"/);
  assert.match(text, /aws_secret_access_key = "\[REDACTED:aws_secret_access_key\]"/);
  assert.match(text, /SELECT \* FROM users WHERE id = '" \+ req\.query\.id/, "code a reviewer needs is untouched");
  assert.deepEqual(hits.map((h) => h.type).sort(), ["aws_access_key_id", "aws_secret_access_key"]);
});

test("redact covers tokens, PEM blocks, labelled wallet keys and URL passwords", () => {
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----";
  const input = [
    `token=${GH_TOKEN}`,
    pem,
    `PRIVATE_KEY=0x${"ab".repeat(32)}`,
    `tx: 0x${"cd".repeat(32)}`,
    "DATABASE_URL=postgres://app:s3cr3tpw@db:5432/app",
    "slack " + "xoxb-" + "1234567890-abcdefghij",
  ].join("\n");
  const { text } = redact(input);
  assert.ok(!text.includes(GH_TOKEN));
  assert.ok(!text.includes("MIIEow"));
  assert.ok(!text.includes("ab".repeat(32)));
  assert.ok(text.includes("cd".repeat(32)), "an unlabelled 32-byte hash is left alone");
  assert.ok(!text.includes("s3cr3tpw") && text.includes("postgres://app:[REDACTED:url_credentials]@db"));
  assert.ok(!text.includes("abcdefghij"));
});

test("redact leaves placeholders and AWS's documented example key", () => {
  const input = 'password: "${DB_PASSWORD}"\napi_key = "your-api-key-here"\nid = AKIAIOSFODNN7EXAMPLE';
  assert.deepEqual(redact(input), { text: input, hits: [] });
});

test("scanSecrets reports type and line, never the value", () => {
  const findings = scanSecrets([{ filename: "src/server.js", status: "modified", patch: secretPatch }]);
  assert.deepEqual(findings.map((f) => `${f.type}@${f.line}:${f.severity}`), ["aws_access_key_id@3:high", "aws_secret_access_key@4:high"]);
  assert.ok(!JSON.stringify(findings).includes(AWS_ID));
});

test("scanSecrets ignores removed lines and flags committed .env files", () => {
  const files = [
    { filename: "a.js", status: "modified", patch: `@@ -1,1 +1,1 @@\n-const k = "${AWS_ID}";\n+const k = process.env.KEY;` },
    { filename: ".env", status: "added", patch: "@@ -0,0 +1 @@\n+DEBUG=1" },
    { filename: "old/.env", status: "removed" },
  ];
  assert.deepEqual(scanSecrets(files).map((f) => `${f.type}:${f.file}`), ["sensitive_file:.env"]);
});
