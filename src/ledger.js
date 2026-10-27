// Append-only JSONL record of every purchase attempt; uploaded as a workflow
// artifact so each paid call can be reconciled by receipt_hash.
import { appendFile } from "node:fs/promises";

/** One ledger line from a Telegraph call record. */
export function ledgerEntry({ pr, check, target, intent, minerId }, r) {
  return {
    ts: new Date().toISOString(),
    pr,
    check,
    target,
    intent,
    miner_id: r.body?.miner_id ?? minerId ?? null,
    url: r.url,
    status: r.status ?? null,
    ok: r.ok,
    reason: r.reason ?? null,
    quoted_atomic: r.quote?.accepts?.[0]?.amount ?? null,
    cost_usd: r.costUsd,
    reported_cost_usd: r.body?.cost_usd ?? null,
    signal_hash: r.body?.signal_hash ?? null,
    receipt: r.receipt ?? null,
    payment_response: r.payment ?? null,
    duration_ms: r.durationMs,
  };
}

export async function appendLedger(path, entry) {
  await appendFile(path, JSON.stringify(entry) + "\n");
}
