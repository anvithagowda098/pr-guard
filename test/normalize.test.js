// Normalizers against real paid responses captured 2026-10-27.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { normalize } from "../src/normalize.js";
import { combineOpinions, decide } from "../src/policy.js";

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
  assert.deepEqual(normalize("depsdev-version", result("77010-npm-lodash-4.18.1-200-paid.json"), { name: "lodash", version: "4.18.1" }), { severity: "none", findings: [] });
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

test("the two deps.dev miners together: ids corroborate the HIGH findings -> BLOCK", () => {
  const first = normalize("depsdev-version", result("77010-npm-lodash-4.17.15-200-paid.json"), lodash15);
  const second = normalize("depsdev-advisory-keys", result("190048-npm-lodash-4.17.15-200-paid.json"), lodash15);
  const combined = combineOpinions(first, second);
  assert.equal(combined.confirmed, true);
  assert.equal(combined.disagreement, false);
  assert.equal(combined.findings.length, 6, "corroboration doesn't duplicate findings");
  assert.ok(combined.findings.every((f) => f.corroborated));
  const outcome = { check: "deps", target: "lodash@4.17.15", status: "ok", calls: [], ...combined };
  assert.equal(decide([outcome]).verdict, "BLOCK");
});

test("a second miner that answers 'no advisories' disagrees -> CAUTION", () => {
  const first = normalize("depsdev-version", result("77010-npm-lodash-4.17.15-200-paid.json"), lodash15);
  const combined = combineOpinions(first, { severity: "none", findings: [] });
  assert.deepEqual([combined.confirmed, combined.disagreement], [false, true]);
  assert.equal(decide([{ check: "deps", target: "x", status: "ok", calls: [], ...combined }]).verdict, "CAUTION");
});

test("PyPI with only unrated ids cautions with a clear reason", () => {
  const n = normalize("depsdev-advisory-keys", result("190048-pypi-django-3.2.0-200-paid.json"), { name: "django", version: "3.2.0" });
  const { verdict, reasons } = decide([{ check: "deps", target: "django@3.2.0", status: "ok", confirmed: false, disagreement: false, calls: [], ...n }]);
  assert.equal(verdict, "CAUTION");
  assert.match(reasons[0], /66 advisories, severity not rated/);
});
