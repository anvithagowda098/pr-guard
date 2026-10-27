// No network: the node is a stub fetch. The 402 challenge below is the generic
// x402 v2 shape the library parses, not a captured Telegraph response.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generatePrivateKey } from "viem/accounts";
import { Telegraph, Budget, decodeHeader, callPolicy, usdToAtomic } from "../src/telegraph.js";

const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64");

function challenge(amount) {
  return {
    x402Version: 2,
    resource: { url: "https://node.test/engine/v1/ask", description: "test", mimeType: "application/json" },
    accepts: [{
      scheme: "exact",
      network: "eip155:84532",
      amount: String(amount),
      asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      payTo: "0x000000000000000000000000000000000000dEaD",
      maxTimeoutSeconds: 60,
      extra: { name: "USDC", version: "2" },
    }],
  };
}

// Answers 402 until it sees a PAYMENT-SIGNATURE header, then 200.
function stubNode({ amount, okBody = { ok: true }, okHeaders = {} }) {
  const calls = [];
  const fetch = async (input, init) => {
    const req = new Request(input, init);
    calls.push({ url: req.url, signature: req.headers.get("payment-signature") });
    if (!req.headers.get("payment-signature")) {
      return new Response("{}", { status: 402, headers: { "PAYMENT-REQUIRED": b64(challenge(amount)) } });
    }
    return new Response(JSON.stringify(okBody), { status: 200, headers: okHeaders });
  };
  return { fetch, calls };
}

test("decodeHeader handles base64 JSON, missing and garbage values", () => {
  assert.deepEqual(decodeHeader(b64({ a: 1 })), { a: 1 });
  assert.equal(decodeHeader(null), null);
  assert.deepEqual(decodeHeader("not-base64-json"), { undecodable: "not-base64-json" });
});

test("callPolicy keeps quotes under the cap across v1/v2 field names and reserves one", () => {
  const budget = new Budget(1);
  const hold = { atomic: null, refusal: null };
  const keep = callPolicy(50_000n, budget, hold)(2, [{ value: "90000" }, { maxAmountRequired: "20000" }, { amount: "10000" }]);
  assert.deepEqual(keep, [{ maxAmountRequired: "20000" }]);
  assert.equal(hold.atomic, 20_000n);
  assert.equal(budget.reserved, 20_000n);
});

test("callPolicy does not reserve twice when the library re-runs it", () => {
  const budget = new Budget(1);
  const hold = { atomic: null, refusal: null };
  const policy = callPolicy(50_000n, budget, hold);
  policy(2, [{ amount: "10000" }]);
  policy(2, [{ amount: "10000" }]);
  assert.equal(budget.reserved, 10_000n);
});

test("usdToAtomic uses 6 decimals", () => {
  assert.equal(usdToAtomic(0.01), 10_000n);
  assert.equal(usdToAtomic(0.05), 50_000n);
});

test("under-cap quote is signed, retried, and the receipt decoded", async () => {
  const receipt = { receipt_hash: "0xabc" };
  const payment = { success: true, transaction: "0x1", network: "eip155:84532" };
  const node = stubNode({
    amount: 10_000,
    okBody: { miner_id: 1, result: "raw", signal_hash: "0xsig" },
    okHeaders: { "X-TELEGRAPH-RECEIPT": b64(receipt), "PAYMENT-RESPONSE": b64(payment) },
  });
  const tg = new Telegraph({ nodeUrl: "https://node.test", privateKey: generatePrivateKey(), maxUsdPerCall: 0.05, fetch: node.fetch });
  const r = await tg.ask({ intent: "CVE_LOOKUP" });

  assert.equal(node.calls.length, 2);
  assert.equal(node.calls[0].signature, null);
  assert.ok(node.calls[1].signature, "second request carries PAYMENT-SIGNATURE");
  assert.equal(r.ok, true);
  assert.equal(r.paid, true);
  assert.equal(r.quote.accepts[0].amount, "10000");
  assert.deepEqual(r.receipt, receipt);
  assert.equal(r.body.signal_hash, "0xsig");
  assert.equal(r.costUsd, 0.01);
});

test("over-cap quote is refused before anything is signed", async () => {
  const node = stubNode({ amount: 60_000 });
  const tg = new Telegraph({ nodeUrl: "https://node.test", privateKey: generatePrivateKey(), maxUsdPerCall: 0.05, fetch: node.fetch });
  const r = await tg.ask({ intent: "CVE_LOOKUP" });

  assert.equal(node.calls.length, 1, "no paid retry");
  assert.equal(r.ok, false);
  assert.equal(r.paid, false);
  assert.equal(r.reason, "over_cap");
});

test("pay:false returns the free 402 quote without signing", async () => {
  const node = stubNode({ amount: 10_000 });
  const tg = new Telegraph({ nodeUrl: "https://node.test", fetch: node.fetch });
  const r = await tg.askMiner(42, { endpoint: "/x", payload: {} }, { pay: false });

  assert.equal(node.calls.length, 1);
  assert.equal(node.calls[0].url, "https://node.test/engine/v1/ask/42");
  assert.equal(r.status, 402);
  assert.equal(r.reason, "payment_required");
  assert.equal(r.quote.accepts[0].payTo, "0x000000000000000000000000000000000000dEaD");
});

test("network failure becomes a record, not a throw", async () => {
  const tg = new Telegraph({
    nodeUrl: "https://node.test",
    privateKey: generatePrivateKey(),
    fetch: async () => { throw new TypeError("fetch failed"); },
  });
  const r = await tg.ask({ intent: "CVE_LOOKUP" });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "network_error");
});

test("parallel calls cannot overspend the shared budget", async () => {
  const node = stubNode({ amount: 30_000 });
  const budget = new Budget(0.05);
  const tg = new Telegraph({ nodeUrl: "https://node.test", privateKey: generatePrivateKey(), maxUsdPerCall: 0.05, budget, fetch: node.fetch });
  const [a, b] = await Promise.all([tg.ask({ n: 1 }), tg.ask({ n: 2 })]);

  assert.deepEqual([a.ok, b.ok].sort(), [false, true]);
  assert.equal([a, b].find((r) => !r.ok).reason, "over_budget");
  assert.equal(budget.spent, 30_000n);
  assert.equal(budget.reserved, 0n);
});

test("a failed miner call after signing releases the reservation", async () => {
  const budget = new Budget(0.1);
  const fetch = async (input, init) => {
    const req = new Request(input, init);
    if (!req.headers.get("payment-signature")) {
      return new Response("{}", { status: 402, headers: { "PAYMENT-REQUIRED": b64(challenge(10_000)) } });
    }
    return new Response("miner exploded", { status: 502 });
  };
  const tg = new Telegraph({ nodeUrl: "https://node.test", privateKey: generatePrivateKey(), budget, fetch });
  const r = await tg.ask({});

  assert.equal(r.ok, false);
  assert.equal(r.reason, "http_502");
  assert.equal(r.costUsd, 0);
  assert.equal(budget.spent, 0n);
  assert.equal(budget.reserved, 0n);
});
