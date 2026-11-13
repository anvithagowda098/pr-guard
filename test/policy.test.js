import { test } from "node:test";
import assert from "node:assert/strict";
import { decide, shouldFail, maxSeverity } from "../src/policy.js";

const o = (over) => ({ check: "deps", target: "x@1", status: "ok", severity: "none", findings: [], confirmed: false, disagreement: false, calls: [], ...over });

test("all clean is SAFE", () => {
  assert.deepEqual(decide([o({}), o({ check: "diff", severity: "low" })]), { verdict: "SAFE", reasons: [] });
});

test("confirmed high/critical BLOCKs; unconfirmed only cautions", () => {
  assert.equal(decide([o({ severity: "critical", confirmed: true })]).verdict, "BLOCK");
  const r = decide([o({ severity: "high" })]);
  assert.equal(r.verdict, "CAUTION");
  assert.match(r.reasons[0], /unconfirmed/);
});

test("medium, disagreement, failures and unreadable answers caution", () => {
  for (const over of [{ severity: "medium" }, { disagreement: true }, { status: "failed", reason: "timeout" }, { severity: "unknown" }]) {
    assert.equal(decide([o(over)]).verdict, "CAUTION", JSON.stringify(over));
  }
});

test("skipping a required check cautions; skipping an optional one doesn't", () => {
  assert.equal(decide([o({ check: "diff", status: "skipped", reason: "budget exhausted" })]).verdict, "CAUTION");
  assert.equal(decide([o({ check: "urls", status: "skipped", reason: "budget exhausted" })]).verdict, "SAFE");
});

test("BLOCK reasons come first and caution reasons are kept", () => {
  const r = decide([o({ severity: "medium", target: "a@1" }), o({ severity: "high", confirmed: true, target: "b@2" })]);
  assert.equal(r.verdict, "BLOCK");
  assert.deepEqual(r.reasons, ["deps: b@2 — high", "deps: a@1 — medium"]);
});

test("fail-on modes", () => {
  assert.equal(shouldFail("BLOCK", "block"), true);
  assert.equal(shouldFail("CAUTION", "block"), false);
  assert.equal(shouldFail("CAUTION", "caution"), true);
  assert.equal(shouldFail("BLOCK", "never"), false);
});

test("maxSeverity", () => {
  assert.equal(maxSeverity([]), "none");
  assert.equal(maxSeverity([{ severity: "low" }, { severity: "high" }, { severity: "medium" }]), "high");
});
