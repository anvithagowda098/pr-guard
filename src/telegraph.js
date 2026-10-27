// Telegraph client: free discovery, paid asks over x402, receipt decoding.
// Miner `result` payloads are passed through untouched; interpreting them is
// normalize.js's job, built from captured responses.
import { wrapFetchWithPayment, x402Client } from "@x402/fetch";
import { ExactEvmScheme, toClientEvmSigner } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";

export const DEFAULT_NODE_URL = "https://devnode.telegraphprotocol.com";
export const NETWORK = "eip155:84532"; // Base Sepolia
export const USDC_DECIMALS = 6;

export const usdToAtomic = (usd) => BigInt(Math.round(Number(usd) * 10 ** USDC_DECIMALS));
export const atomicToUsd = (atomic) => Number(BigInt(atomic)) / 10 ** USDC_DECIMALS;

// Telegraph and x402 headers carry base64-encoded JSON.
export function decodeHeader(value) {
  if (!value) return null;
  try {
    return JSON.parse(Buffer.from(value, "base64").toString("utf8"));
  } catch {
    return { undecodable: value };
  }
}

// v2 requirements use `amount`; v1 used `maxAmountRequired` (some servers send `value`).
export const quotedAtomic = (req) => BigInt(req.amount ?? req.maxAmountRequired ?? req.value ?? 0);

// Drop any payment option priced above the cap. If nothing is left, the x402
// client refuses to sign, so an over-cap quote never turns into a payment.
export const capPolicy = (maxAtomicPerCall) => (_version, reqs) =>
  reqs.filter((r) => quotedAtomic(r) <= maxAtomicPerCall);

export function createPaymentClient(privateKey, maxAtomicPerCall) {
  const account = privateKeyToAccount(privateKey);
  const client = x402Client.fromConfig({
    schemes: [{ network: NETWORK, client: new ExactEvmScheme(toClientEvmSigner(account)) }],
    // The library's own USD cap applies first; ours is the binding one.
    spendControls: { maxAmountPerPayment: atomicToUsd(maxAtomicPerCall) },
  });
  client.registerPolicy(capPolicy(maxAtomicPerCall));
  return { client, address: account.address };
}

function responseHeaders(res) {
  const out = {};
  for (const [k, v] of res.headers) out[k] = v;
  return out;
}

async function readBody(res) {
  const text = await res.text();
  try {
    return { text, json: JSON.parse(text) };
  } catch {
    return { text, json: null };
  }
}

export class Telegraph {
  /**
   * @param {object} opts
   * @param {string} [opts.nodeUrl]
   * @param {string} [opts.privateKey] burner testnet key; omit for discovery-only use
   * @param {number} [opts.maxUsdPerCall] hard per-call cap, default $0.05
   * @param {number} [opts.timeoutMs] per-request timeout, default 45s
   * @param {typeof fetch} [opts.fetch] injectable for tests
   */
  constructor({ nodeUrl = DEFAULT_NODE_URL, privateKey, maxUsdPerCall = 0.05, timeoutMs = 45_000, fetch: fetchImpl = globalThis.fetch } = {}) {
    this.nodeUrl = nodeUrl.replace(/\/+$/, "");
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.maxAtomicPerCall = usdToAtomic(maxUsdPerCall);
    if (privateKey) {
      const { client, address } = createPaymentClient(privateKey, this.maxAtomicPerCall);
      this.payClient = client;
      this.address = address;
    }
  }

  async getJson(path) {
    const res = await this.fetch(this.nodeUrl + path, { signal: AbortSignal.timeout(this.timeoutMs) });
    const { text, json } = await readBody(res);
    if (!res.ok) throw new Error(`GET ${path} -> ${res.status}: ${text.slice(0, 300)}`);
    return json ?? text;
  }

  // Free discovery endpoints
  listIntents() { return this.getJson("/engine/v1/intents"); }
  getIntent(intent) { return this.getJson(`/engine/v1/intents/${encodeURIComponent(intent)}`); }
  getIntentMiners(intent) { return this.getJson(`/engine/v1/intents/${encodeURIComponent(intent)}/miners`); }
  listMiners({ intent, status = "active", limit = 50 } = {}) {
    const q = new URLSearchParams({ ...(intent && { intent }), status, limit: String(limit) });
    return this.getJson(`/api/miners?${q}`);
  }
  getMiner(id) { return this.getJson(`/api/miners/${encodeURIComponent(id)}`); }
  getSignal(hash) { return this.getJson(`/engine/v1/signal/${encodeURIComponent(hash)}`); }
  getOpenApi() { return this.getJson("/miner-dispatcher/openapi.json"); }

  /** Paid, auto-routed by intent. `body` is sent as-is (docs show more than one shape). */
  ask(body, opts) {
    return this.post("/engine/v1/ask", body, opts);
  }

  /** Paid, direct to one miner, using an endpoint from its miner record. */
  askMiner(minerId, { method = "POST", endpoint, payload }, opts) {
    return this.post(`/engine/v1/ask/${encodeURIComponent(minerId)}`, { method, endpoint, payload }, opts);
  }

  /**
   * POST to a paid endpoint. With `pay: false` the request goes out unpaid, so
   * a 402 quote or a 422 pre-validation error comes back for free.
   * Never throws: every outcome is a record with `ok` and, on failure, `reason`.
   */
  async post(path, body, { pay = true } = {}) {
    const url = this.nodeUrl + path;
    const started = Date.now();
    const record = { url, request: body, paid: false, ok: false };

    // Keep the 402 challenge so the quoted price and payTo land in the record.
    const recordingFetch = async (input, init) => {
      const res = await this.fetch(input, init);
      if (res.status === 402 && !record.quote) record.quote = decodeHeader(res.headers.get("payment-required"));
      return res;
    };

    const init = {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    };

    let res;
    try {
      if (pay) {
        if (!this.payClient) throw new Error("no private key configured");
        res = await wrapFetchWithPayment(recordingFetch, this.payClient)(url, init);
      } else {
        res = await recordingFetch(url, init);
      }
    } catch (err) {
      record.durationMs = Date.now() - started;
      record.error = [err?.message ?? String(err), err?.cause?.message].filter(Boolean).join(": ");
      record.reason = classifyError(err, record.quote, this.maxAtomicPerCall);
      return record;
    }

    const { text, json } = await readBody(res);
    Object.assign(record, {
      status: res.status,
      durationMs: Date.now() - started,
      headers: responseHeaders(res),
      bodyText: text,
      body: json,
      payment: decodeHeader(res.headers.get("payment-response")),
      receipt: decodeHeader(res.headers.get("x-telegraph-receipt")),
    });
    record.paid = Boolean(record.payment);
    record.ok = res.status === 200;
    if (!record.ok) record.reason = res.status === 402 ? "payment_required" : res.status === 422 ? "rejected_by_prevalidation" : `http_${res.status}`;
    return record;
  }
}

function classifyError(err, quote, cap) {
  if (err?.name === "TimeoutError" || err?.name === "AbortError") return "timeout";
  const msg = err?.message ?? "";
  if (msg.startsWith("Failed to create payment payload") && quote?.accepts?.length && quote.accepts.every((r) => quotedAtomic(r) > cap)) {
    return "over_cap";
  }
  if (msg.startsWith("Failed to create payment payload")) return "payment_failed";
  if (msg.startsWith("Failed to parse payment requirements")) return "bad_payment_challenge";
  return "network_error";
}
