#!/usr/bin/env node
// Step 1 (free): dump intents, intent specs and miner records for the intents
// PR Guard uses into data/miners.json, then print a per-intent call table.
// Everything is saved raw; the table printer only reads the fields the
// docs list for /api/miners and falls back to raw JSON for anything else.
//
//   node scripts/discover.js [INTENT ...]
import { mkdir, writeFile } from "node:fs/promises";
import { Telegraph } from "../src/telegraph.js";

const DEFAULT_INTENTS = [
  "CVE_LOOKUP",
  "VULNERABILITY_TRIAGE",
  "SECURITY_REVIEW",
  "CODE_PATCH_VERIFY",
  "CODE_REVIEW",
  "URL_SCAN",
  "URL_SAFE",
  "MALWARE_DETECTION",
];

const intents = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT_INTENTS;
const tg = new Telegraph({ nodeUrl: process.env.TELEGRAPH_NODE_URL || undefined });

const settle = async (fn) => {
  try {
    return { ok: true, data: await fn() };
  } catch (err) {
    return { ok: false, error: err.message };
  }
};

const out = {
  fetched_at: new Date().toISOString(),
  node: tg.nodeUrl,
  intents_index: await settle(() => tg.listIntents()),
  openapi: await settle(() => tg.getOpenApi()),
  intents: {},
};

for (const intent of intents) {
  const [spec, intentMiners, miners] = await Promise.all([
    settle(() => tg.getIntent(intent)),
    settle(() => tg.getIntentMiners(intent)),
    settle(() => tg.listMiners({ intent, status: "active", limit: 50 })),
  ]);
  out.intents[intent] = { spec, intent_miners: intentMiners, miners };
}

await mkdir("data", { recursive: true });
await writeFile("data/miners.json", JSON.stringify(out, null, 2));
console.log(`saved raw discovery to data/miners.json (${tg.nodeUrl})\n`);

// ---- per-intent call table ----------------------------------------------

const firstArray = (x) =>
  Array.isArray(x) ? x : x && typeof x === "object" ? Object.values(x).find(Array.isArray) ?? null : null;
const short = (v, n = 140) => {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s === undefined ? "" : s.length > n ? s.slice(0, n - 1) + "…" : s;
};

function schemaSummary(schema) {
  if (!schema) return "(none)";
  if (schema.properties && typeof schema.properties === "object") {
    const req = new Set(schema.required ?? []);
    return Object.entries(schema.properties)
      .map(([k, v]) => `${k}${req.has(k) ? "*" : ""}:${v?.type ?? "?"}`)
      .join(", ");
  }
  return short(schema);
}

function endpointSummary(endpoints) {
  if (!Array.isArray(endpoints)) return short(endpoints);
  return endpoints
    .map((e) => (e && typeof e === "object" ? `${e.method ?? "?"} ${e.path ?? e.endpoint ?? short(e, 60)}` : String(e)))
    .join(" | ");
}

// How many of the queried intents each miner shows up in (flags the
// one-miner-claims-everything proxies).
const seenIn = new Map();
for (const { miners } of Object.values(out.intents)) {
  for (const m of firstArray(miners.data) ?? []) {
    const id = m?.id ?? m?.miner_id;
    if (id !== undefined) seenIn.set(id, (seenIn.get(id) ?? 0) + 1);
  }
}

for (const [intent, { spec, miners }] of Object.entries(out.intents)) {
  console.log(`=== ${intent} ===`);
  console.log(`spec: ${spec.ok ? short(spec.data, 400) : "ERROR " + spec.error}`);
  if (!miners.ok) {
    console.log(`miners: ERROR ${miners.error}\n`);
    continue;
  }
  const list = firstArray(miners.data);
  if (!list) {
    console.log(`miners: unexpected shape, raw: ${short(miners.data, 400)}\n`);
    continue;
  }
  console.log(`${list.length} active miners`);
  for (const m of list) {
    const id = m.id ?? m.miner_id;
    const flag = intents.length > 1 && seenIn.get(id) === intents.length ? "  [listed on every queried intent]" : "";
    console.log(`- #${id} ${m.name ?? m.miner_name ?? ""}  min_price_usdc=${m.min_price_usdc ?? "?"}${flag}`);
    console.log(`    rank/score: ${short(m.rank ?? m.score ?? m.intents ?? m.rankings ?? "?")}`);
    console.log(`    endpoints:  ${endpointSummary(m.endpoints)}`);
    console.log(`    input:      ${schemaSummary(m.input_schema)}`);
  }
  console.log();
}
