#!/usr/bin/env node
// Step 2: one CVE_LOOKUP call, printed raw, before any normalizer exists.
// Unpaid by default: an unpaid POST returns the 402 quote (or a 422 if the
// payload fails pre-validation) at no charge. Add --pay to buy the answer.
//
// Direct to a miner (request shape comes from its record in data/miners.json):
//   node scripts/first-call.js --miner <id> --endpoint <path> [--method POST] --payload '<json>' [--pay]
// Auto-routed (the docs show two body shapes, so the body is passed verbatim):
//   node scripts/first-call.js --body '{"intent":"CVE_LOOKUP","params":{...}}' [--pay]
//
// Every response is saved under test/fixtures/miner-responses/ so the
// normalizers can be written from real captures.
import { mkdir, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { Telegraph } from "../src/telegraph.js";

try { process.loadEnvFile(".env"); } catch {}

const { values: args } = parseArgs({
  options: {
    miner: { type: "string" },
    endpoint: { type: "string" },
    method: { type: "string", default: "POST" },
    payload: { type: "string" },
    body: { type: "string" },
    intent: { type: "string", default: "CVE_LOOKUP" },
    pay: { type: "boolean", default: false },
    "max-usd": { type: "string", default: "0.05" },
  },
});

const json = (s, flag) => {
  try {
    return JSON.parse(s);
  } catch (err) {
    console.error(`--${flag} is not valid JSON: ${err.message}`);
    process.exit(2);
  }
};

if (!args.body && !(args.miner && args.endpoint && args.payload)) {
  console.error("need either --body '<json>' (auto-routed) or --miner <id> --endpoint <path> --payload '<json>' (direct)");
  console.error("run `node scripts/discover.js CVE_LOOKUP` first to see each miner's endpoints and input_schema");
  process.exit(2);
}

const tg = new Telegraph({
  nodeUrl: process.env.TELEGRAPH_NODE_URL || undefined,
  privateKey: args.pay ? process.env.TELEGRAPH_PRIVATE_KEY : undefined,
  maxUsdPerCall: Number(args["max-usd"]),
});
if (args.pay && !tg.address) {
  console.error("--pay needs TELEGRAPH_PRIVATE_KEY (run `node scripts/wallet.js`)");
  process.exit(2);
}

console.log(`node:   ${tg.nodeUrl}`);
console.log(`mode:   ${args.pay ? `PAID (cap $${args["max-usd"]}/call, wallet ${tg.address})` : "unpaid probe (free)"}`);

const r = args.body
  ? await tg.ask(json(args.body, "body"), { pay: args.pay })
  : await tg.askMiner(args.miner, { method: args.method, endpoint: args.endpoint, payload: json(args.payload, "payload") }, { pay: args.pay });

const show = (label, v) => console.log(`\n--- ${label} ---\n${typeof v === "string" ? v : JSON.stringify(v, null, 2)}`);
show("request", { url: r.url, body: r.request });
console.log(`\nstatus: ${r.status ?? "(no response)"}  ok: ${r.ok}  paid: ${r.paid}  ${r.reason ? "reason: " + r.reason : ""}  duration_ms: ${r.durationMs}`);
if (r.error) show("error", r.error);
if (r.quote) show("402 quote (PAYMENT-REQUIRED, decoded)", r.quote);
if (r.headers) show("response headers", r.headers);
if (r.bodyText !== undefined) show("raw body", r.bodyText);
if (r.payment) show("PAYMENT-RESPONSE (decoded)", r.payment);
if (r.receipt) show("X-TELEGRAPH-RECEIPT (decoded)", r.receipt);

if (r.ok && r.body) {
  const { miner_id, miner_name, cost_usd, duration_ms, signal_hash } = r.body;
  show("summary", { miner_id, miner_name, cost_usd, duration_ms, signal_hash });
  if (signal_hash) {
    try {
      show(`signal lookup /engine/v1/signal/${signal_hash}`, await tg.getSignal(signal_hash));
    } catch (err) {
      show("signal lookup failed", err.message);
    }
  }
}

// Only real HTTP responses become fixtures; network errors have nothing to capture.
if (r.status === undefined) process.exit(1);

const dir = `test/fixtures/miner-responses/${args.intent}`;
await mkdir(dir, { recursive: true });
const who = args.miner ? `miner-${args.miner}` : "auto";
const file = `${dir}/${new Date().toISOString().replace(/[:.]/g, "-")}-${who}-${r.status ?? "err"}${r.paid ? "-paid" : ""}.json`;
await writeFile(file, JSON.stringify({ captured_at: new Date().toISOString(), ...r }, null, 2));
console.log(`\nsaved ${file}`);
