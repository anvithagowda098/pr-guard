// Runs paid checks against the configured miners for each intent.
import { combineOpinions } from "./policy.js";
import { normalize } from "./normalize.js";
import { ledgerEntry } from "./ledger.js";

const MAX_ATTEMPTS = 3; // per opinion; a failed call can still be charged, so retries cost money too

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

// Seen from both deps.dev proxies for an unknown package: HTTP 500 with
// {"error":"upstream error 404: ..."} (captured 2026-10-27).
const isUpstreamNotFound = (r) => r.status >= 400 && /upstream error 404/i.test(r.bodyText ?? "");

/**
 * One check on one target. Tries the intent's miners in order until one
 * answers; a high/critical answer gets a second opinion from the next miner.
 * @returns outcome (see policy.js)
 */
export async function runCheck({ tg, miners, job, deadline, onCall }) {
  const { check, intent, target, vars } = job;
  // Miners are configured per check (two checks can share an intent but need
  // different miners); an entry may limit itself to some ecosystems.
  const entries = (miners[check] ?? []).filter((e) => e.enabled !== false && (!e.ecosystems || e.ecosystems.includes(vars.ecosystem)));
  const calls = [];
  const base = { check, intent, target, findings: [], confirmed: false, disagreement: false, calls };
  if (!entries.length) return { ...base, status: "skipped", severity: "none", reason: `no vetted ${check} miner yet` };

  let next = 0;
  let lastReason = null;
  const opinion = async () => {
    for (let tries = 0; tries < MAX_ATTEMPTS && next < entries.length; tries++) {
      if (Date.now() > deadline) { lastReason = "time limit"; return null; }
      const entry = entries[next++];
      const r = await callMiner(tg, entry, vars);
      calls.push(callSummary(entry, r));
      await onCall?.(ledgerEntry({ check, target, intent, minerId: entry.minerId }, r));
      if (r.ok) return normalize(entry.normalizer, r.body?.result, vars);
      lastReason = r.reason;
      // The registry itself doesn't know the package (private or unpublished);
      // every miner proxies the same registry, and each miss is charged.
      if (isUpstreamNotFound(r)) { lastReason = "not_found"; return null; }
      if (r.reason === "over_budget") return null; // budget spent: stop rather than shop for a cheaper miner
    }
    return null;
  };

  const first = await opinion();
  if (!first) {
    const skipped = { over_budget: "budget exhausted", "time limit": "time limit", not_found: "not in the public registry" };
    if (skipped[lastReason]) return { ...base, status: "skipped", severity: "none", reason: skipped[lastReason] };
    return { ...base, status: "failed", severity: "none", reason: lastReason };
  }
  const combined = isHigh(first.severity) ? combineOpinions(first, await opinion()) : first;
  return {
    ...base,
    status: "ok",
    severity: combined.severity,
    findings: combined.findings,
    confirmed: combined.confirmed ?? false,
    disagreement: combined.disagreement ?? false,
    ...((combined.advice ?? first.advice) && { advice: combined.advice ?? first.advice }),
  };
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
