// Runs paid checks against the configured miners for each intent.
import { combineOpinions } from "./policy.js";
import { normalize } from "./normalize.js";
import { ledgerEntry } from "./ledger.js";

const MAX_ATTEMPTS = 3; // per opinion; failed miner calls aren't charged, but they cost time

/** Fill {{var}} placeholders. A string that is exactly "{{var}}" takes the raw value. */
export function fillTemplate(template, vars) {
  if (typeof template === "string") {
    const whole = template.match(/^\{\{(\w+)\}\}$/);
    if (whole) return vars[whole[1]] ?? null;
    return template.replace(/\{\{(\w+)\}\}/g, (_, k) => (vars[k] == null ? "" : String(vars[k])));
  }
  if (Array.isArray(template)) return template.map((t) => fillTemplate(t, vars));
  if (template && typeof template === "object") {
    return Object.fromEntries(Object.entries(template).map(([k, v]) => [k, fillTemplate(v, vars)]));
  }
  return template;
}

function callMiner(tg, entry, vars) {
  if (entry.auto) return tg.ask(fillTemplate(entry.body, vars));
  return tg.askMiner(entry.minerId, { method: entry.method ?? "POST", endpoint: entry.endpoint, payload: fillTemplate(entry.payload, vars) });
}

const callSummary = (entry, r) => ({
  minerId: r.body?.miner_id ?? entry.minerId ?? "auto",
  minerName: r.body?.miner_name ?? entry.name ?? null,
  costUsd: r.costUsd,
  signalHash: r.body?.signal_hash ?? null,
  receiptHash: r.receipt?.receipt_hash ?? null,
  durationMs: r.durationMs,
  ok: r.ok,
  reason: r.reason ?? null,
});

const isHigh = (s) => s === "high" || s === "critical";

/**
 * One check on one target. Tries the intent's miners in order until one
 * answers; a high/critical answer gets a second opinion from the next miner.
 * @returns outcome (see policy.js)
 */
export async function runCheck({ tg, miners, job, deadline, onCall }) {
  const { check, intent, target, vars } = job;
  const entries = miners[intent] ?? [];
  const calls = [];
  const base = { check, intent, target, findings: [], confirmed: false, disagreement: false, calls };
  if (!entries.length) return { ...base, status: "skipped", severity: "none", reason: `no vetted ${intent} miner yet` };

  let next = 0;
  let lastReason = null;
  const opinion = async () => {
    for (let tries = 0; tries < MAX_ATTEMPTS && next < entries.length; tries++) {
      if (Date.now() > deadline) { lastReason = "time limit"; return null; }
      const entry = entries[next++];
      const r = await callMiner(tg, entry, vars);
      calls.push(callSummary(entry, r));
      await onCall?.(ledgerEntry({ check, target, intent, minerId: entry.minerId }, r));
      if (r.ok) return normalize(entry.normalizer, r.body?.result);
      lastReason = r.reason;
      if (r.reason === "over_budget") return null; // budget spent: stop rather than shop for a cheaper miner
    }
    return null;
  };

  const first = await opinion();
  if (!first) {
    const status = lastReason === "over_budget" || lastReason === "time limit" ? "skipped" : "failed";
    return { ...base, status, severity: "none", reason: lastReason === "over_budget" ? "budget exhausted" : lastReason };
  }
  const combined = isHigh(first.severity) ? combineOpinions(first, await opinion()) : first;
  return { ...base, status: "ok", severity: combined.severity, findings: combined.findings, confirmed: combined.confirmed ?? false, disagreement: combined.disagreement ?? false };
}

/** Run jobs in order with at most `concurrency` in flight. */
export async function runAll(jobs, worker, concurrency = 4) {
  const results = new Array(jobs.length);
  let i = 0;
  const lanes = Array.from({ length: Math.min(concurrency, jobs.length) }, async () => {
    while (i < jobs.length) {
      const idx = i++;
      results[idx] = await worker(jobs[idx]);
    }
  });
  await Promise.all(lanes);
  return results;
}
