#!/usr/bin/env node
// Step 1 (free): dump intents, intent specs and miner records for the intents
// PR Guard uses into data/miners.json (raw, large, not committed), and write a
// compact per-intent summary to data/miners-summary.json.
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
console.log(`saved raw discovery to data/miners.json (${tg.nodeUrl})`);

// ---- per-intent summary ----------------------------------------------------
// Field names below are the ones /api/miners actually returns (Oct 2026):
// endpoints[{method,path,description}], input_schema, output_schema,
// supported_intents[], scores[{intent_id,rank,score}], total_requests_served,
// min_price_usdc (atomic units, 10000 = $0.01).

const short = (v, n = 140) => {
  const s = typeof v === "string" ? v : JSON.stringify(v);
  return s === undefined ? "" : s.length > n ? s.slice(0, n - 1) + "…" : s;
};

const props = (schema) => Object.keys(schema?.properties ?? {});

function schemaSummary(schema) {
  const req = new Set(schema?.required ?? []);
  return Object.entries(schema?.properties ?? {}).map(([k, v]) => `${k}${req.has(k) ? "*" : ""}:${v?.type ?? "?"}`).join(", ") || "(none)";
}

// Multi-intent miners list every endpoint; keep the ones that serve this intent.
function endpointsFor(m, intent) {
  const slug = intent.toLowerCase().replace(/_/g, "-");
  const eps = m.endpoints ?? [];
  if ((m.supported_intents ?? []).length <= 1) return eps;
  return eps.filter((e) => (e.description ?? "").includes(intent) || (e.path ?? "").includes(slug));
}

const summary = {};
for (const [intent, { miners }] of Object.entries(out.intents)) {
  if (!miners.ok || !Array.isArray(miners.data)) {
    summary[intent] = { error: miners.error ?? "unexpected shape" };
    continue;
  }
  summary[intent] = miners.data
    .map((m) => {
      const s = (m.scores ?? []).find((x) => x.intent_id === intent);
      const multi = (m.supported_intents ?? []).length > 1;
      return {
        id: m.id,
        name: m.name,
        base_url: m.base_url,
        price_usd: Number(m.min_price_usdc ?? 0) / 1e6,
        served: m.total_requests_served ?? 0,
        intents: (m.supported_intents ?? []).length,
        rank: s?.rank ?? null,
        score: s?.score ?? null,
        endpoints: endpointsFor(m, intent).map((e) => ({ method: e.method, path: e.path, description: short(e.description ?? "", 300) })),
        // A multi-intent miner's schema mixes every route's params; it's in the raw dump.
        input_schema: multi ? null : m.input_schema ?? null,
        output_fields: props(m.output_schema),
        signal_mapping: m.signal_mapping ?? null,
      };
    })
    .sort((a, b) => (a.rank ?? 1e9) - (b.rank ?? 1e9));
}
await writeFile("data/miners-summary.json", JSON.stringify({ fetched_at: out.fetched_at, node: out.node, intents: summary }, null, 2));
console.log("saved per-intent summary to data/miners-summary.json\n");

for (const [intent, list] of Object.entries(summary)) {
  console.log(`=== ${intent} ===`);
  if (!Array.isArray(list)) {
    console.log(`  ERROR ${list.error}\n`);
    continue;
  }
  for (const m of list) {
    const flag = m.intents > 10 ? `  [claims ${m.intents} intents]` : "";
    console.log(`#${m.id} ${m.name}  rank=${m.rank ?? "-"} score=${m.score?.toFixed(3) ?? "-"} served=${m.served} $${m.price_usd}${flag}`);
    for (const e of m.endpoints) console.log(`    ${e.method} ${e.path}`);
    if (m.input_schema) console.log(`    input: ${schemaSummary(m.input_schema)}`);
  }
  console.log();
}
