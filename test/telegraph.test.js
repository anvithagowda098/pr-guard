// No network: the node is a stub fetch. The 402 challenge below is the generic
// x402 v2 shape the library parses, not a captured Telegraph response.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generatePrivateKey } from "viem/accounts";
import { Telegraph, Budget, decodeHeader, callPolicy, usdToAtomic, PAYMENT_ASSETS } from "../src/telegraph.js";

const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64");

const ETH_SEPOLIA = { network: "eip155:11155111", asset: "0xcc194e1a843B658526D0D5C431f670028582Ae17" };

// The shape of Telegraph's live challenge since its Oct 30 move to Ethereum Sepolia.
function challenge(amount, { network = ETH_SEPOLIA.network, asset = ETH_SEPOLIA.asset } = {}) {
  return {
    x402Version: 2,
    resource: { url: "https://node.test/engine/v1/ask", description: "test", mimeType: "application/json" },
    accepts: [{
      scheme: "exact",
      network,
      amount: String(amount),
      asset,
      payTo: "0x000000000000000000000000000000000000dEaD",
      maxTimeoutSeconds: 60,
      extra: { name: "USD Coin", version: "2" },
    }],
  };
}

// Answers 402 until it sees a PAYMENT-SIGNATURE header, then 200.
function stubNode({ amount, okBody = { ok: true }, okHeaders = {}, ...where }) {
  const calls = [];
  const fetch = async (input, init) => {
    const req = new Request(input, init);
    calls.push({ url: req.url, signature: req.headers.get("payment-signature") });
    if (!req.headers.get("payment-signature")) {
      return new Response("{}", { status: 402, headers: { "PAYMENT-REQUIRED": b64(challenge(amount, where)) } });
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
  const keep = callPolicy(50_000n, budget, hold)(2, [{ ...ETH_SEPOLIA, value: "90000" }, { ...ETH_SEPOLIA, maxAmountRequired: "20000" }, { ...ETH_SEPOLIA, amount: "10000" }]);
  assert.deepEqual(keep, [{ ...ETH_SEPOLIA, maxAmountRequired: "20000" }]);
  assert.equal(hold.atomic, 20_000n);
  assert.equal(budget.reserved, 20_000n);
});

test("callPolicy does not reserve twice when the library re-runs it", () => {
  const budget = new Budget(1);
  const hold = { atomic: null, refusal: null };
  const policy = callPolicy(50_000n, budget, hold);
  policy(2, [{ ...ETH_SEPOLIA, amount: "10000" }]);
  policy(2, [{ ...ETH_SEPOLIA, amount: "10000" }]);
  assert.equal(budget.reserved, 10_000n);
});

test("usdToAtomic uses 6 decimals", () => {
  assert.equal(usdToAtomic(0.01), 10_000n);
  assert.equal(usdToAtomic(0.05), 50_000n);
});

test("under-cap quote is signed, retried, and the receipt decoded", async () => {
  const receipt = { receipt_hash: "0xabc" };
  const payment = { success: true, transaction: "0x1", network: "eip155:11155111" };
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

test("a failed miner call that still settled payment is counted as spent", async () => {
  // Mirrors a captured TxLens response: HTTP 500 plus PAYMENT-RESPONSE success.
  const budget = new Budget(0.1);
  const fetch = async (input, init) => {
    const req = new Request(input, init);
    if (!req.headers.get("payment-signature")) {
      return new Response("{}", { status: 402, headers: { "PAYMENT-REQUIRED": b64(challenge(10_000)) } });
    }
    return new Response('{"error":"miner error 502"}', { status: 500, headers: { "PAYMENT-RESPONSE": b64({ success: true, transaction: "0x64" }) } });
  };
  const tg = new Telegraph({ nodeUrl: "https://node.test", privateKey: generatePrivateKey(), budget, fetch });
  const r = await tg.ask({});

  assert.equal(r.ok, false);
  assert.equal(r.charged, true);
  assert.equal(r.costUsd, 0.01);
  assert.equal(budget.spent, 10_000n);
});

test("only Telegraph's test USDC is ever paid: another token or chain is refused unsigned", async () => {
  for (const where of [
    { network: "eip155:11155111", asset: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238" }, // Circle's Sepolia USDC, not Telegraph's
    { network: "eip155:1", asset: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" }, // mainnet USDC: real money
  ]) {
    const node = stubNode({ amount: 10_000, ...where });
    const tg = new Telegraph({ nodeUrl: "https://node.test", privateKey: generatePrivateKey(), fetch: node.fetch });
    const r = await tg.ask({});
    assert.equal(node.calls.length, 1, `no paid retry for ${where.network}`);
    assert.equal(r.paid, false);
    assert.ok(["unsupported_asset", "payment_failed"].includes(r.reason), r.reason);
  }
});

test("the old Base Sepolia challenge still signs (for replaying captured runs)", async () => {
  const old = PAYMENT_ASSETS.find((a) => a.network === "eip155:84532");
  const node = stubNode({ amount: 10_000, network: old.network, asset: old.asset });
  const tg = new Telegraph({ nodeUrl: "https://node.test", privateKey: generatePrivateKey(), fetch: node.fetch });
  assert.equal((await tg.ask({})).ok, true);
});

test("private keys are accepted with or without 0x and surrounding whitespace", async () => {
  const { normalizePrivateKey } = await import("../src/telegraph.js");
  const hex = "ab".repeat(32);
  assert.equal(normalizePrivateKey(hex), `0x${hex}`); // MetaMask's export format
  assert.equal(normalizePrivateKey(`  0x${hex}\n`), `0x${hex}`);
  assert.equal(normalizePrivateKey(`0X${hex.toUpperCase()}`), `0x${hex.toUpperCase()}`);
  for (const bad of ["", "0x1234", "not a key", `${hex}00`, "0xFb49DF5c009e60749776bF3CBed3D1C25Dde0297"]) {
    assert.throws(() => normalizePrivateKey(bad), (e) => /64 hex characters/.test(e.message) && !e.message.includes(bad.trim() || "\u0000"), bad);
  }
  // A key without 0x works end to end.
  const tg = new Telegraph({ nodeUrl: "https://node.test", privateKey: hex, fetch: async () => new Response("{}") });
  assert.match(tg.address, /^0x[0-9a-fA-F]{40}$/);
});

test("the default fetch is called unbound, as Cloudflare Workers require", async () => {
  const real = globalThis.fetch;
  // Workers throw "Illegal invocation" when fetch runs with another object as `this`.
  globalThis.fetch = function (input) {
    if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation");
    return Promise.resolve(new Response(JSON.stringify({ ok: true, url: String(input) })));
  };
  try {
    const tg = new Telegraph({ nodeUrl: "https://node.test" });
    assert.deepEqual(await tg.getJson("/x"), { ok: true, url: "https://node.test/x" });
    const r = await tg.post("/y", {}, { pay: false });
    assert.equal(r.status, 200);
  } finally {
    globalThis.fetch = real;
  }
});
