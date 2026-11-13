// Runs one paid check. First through Telegraph's routing: a canonical ask
// ({ intent, params }) that the network serves from the miner its rankings
// pick. Only if that answer is unusable (off-target, unreadable, unavailable)
// is one vetted miner asked directly. No miner is asked to second-guess
// another: a high finding is confirmed by deterministic evidence instead, an
// exact package match from registry-backed data, or PR Guard's local rules
// finding the same issue in the same diff.
import { normalize } from "./normalize.js";
import { ledgerEntry } from "./ledger.js";
import { scan } from "../miner/rules.js";

const MAX_ATTEMPTS = 3; // fallback miners tried in turn when one fails (failover, not a second opinion)

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

const callSummary = (r, { via, entry, note } = {}) => ({
  minerId: r.body?.miner_id ?? entry?.minerId ?? null,
  minerName: r.body?.miner_name ?? entry?.name ?? null,
  via, // "routed": Telegraph picked the miner; "direct": a vetted fallback
  costUsd: r.costUsd,
  signalHash: r.body?.signal_hash ?? null,
  receiptHash: r.receipt?.receipt_hash ?? null,
  durationMs: r.durationMs,
  ok: r.ok,
  reason: r.reason ?? null,
  ...(note && { note }),
});

const isHigh = (s) => s === "high" || s === "critical";
const isEmpty = (n) => n.severity === "unknown" && !n.findings.length;

// Seen from both deps.dev proxies for an unknown package: HTTP 500 with
// {"error":"upstream error 404: ..."} (captured 2026-10-27).
const isUpstreamNotFound = (r) => r.status >= 400 && /upstream error 404/i.test(r.bodyText ?? "");

/**
 * Whether a routed answer can be used, and read. An answer in the intent's
 * format is read by the intent's normalizer; a raw answer only if it came from
 * a vetted miner whose normalizer confirms it is about this target.
 * `systematic` marks a miner that ignores the request (the router will keep
 * sending it there); a one-off unreadable answer or an outage is not.
 * @returns {{ answer: object } | { reject: string, systematic: boolean }}
 */
export function judgeRouted(r, route, entries, vars) {
  if (!r.ok) return { reject: r.status === 503 ? "Telegraph could not route it right now" : `the routed call failed (${r.reason})`, systematic: false };
  const id = r.body?.miner_id ?? "?";
  const vetted = entries.find((e) => String(e.minerId) === String(id));
  if (r.body?.result_shape === "intent") {
    const n = normalize(route.normalizer, r.body.result, vars);
    return isEmpty(n) ? { reject: `miner ${id}'s answer had no readable verdict`, systematic: false } : { answer: n };
  }
  if (vetted) {
    const n = normalize(vetted.normalizer, r.body?.result, vars);
    if (!isEmpty(n)) return { answer: n };
  }
  // Free text the node couldn't read into the format: unusable this time only.
  const text = typeof r.body?.result?.answer === "string" || typeof r.body?.result === "string";
  return text
    ? { reject: `miner ${id}'s answer had no readable verdict`, systematic: false }
    : { reject: `miner ${id} answered in its own format, and not about this target`, systematic: true };
}

/** Confirm high findings by deterministic evidence; flag local-rule hits the reviewer missed. */
export function confirmFindings(check, answer, vars) {
  if (check === "deps") return { ...answer, confirmed: isHigh(answer.severity) && answer.verified === true, disagreement: false };
  if (check !== "diff" || !vars.diff) return { ...answer, confirmed: false, disagreement: false };
  const local = scan(vars.diff).findings.filter((f) => f.rule !== "hardcoded-secret"); // secrets: the local secret scan reports those
  const matches = (f, l) => (f.category && f.category === l.rule) || (f.file && f.line && f.file === l.file && f.line === l.line);
  const findings = answer.findings.map((f) => (isHigh(f.severity) && local.some((l) => matches(f, l)) ? { ...f, corroborated: true } : f));
  const missed = local.filter((l) => isHigh(l.severity) && !answer.findings.some((f) => matches(f, l)));
  return {
    ...answer,
    findings: [
      ...findings,
      ...missed.map((l) => ({ title: `${l.title} (PR Guard local rule)`, severity: "medium", ...(l.file && { file: l.file }), line: l.line, detail: `${l.evidence} → ${l.fix}` })),
    ],
    severity: missed.length && answer.severity === "none" ? "medium" : answer.severity,
    confirmed: findings.some((f) => f.corroborated),
    disagreement: missed.length > 0,
  };
}

/**
 * One check on one target.
 * @param {object} p
 * @param {object} [p.routing] { mode: "auto" | "off", health: { [intent]: false } once routing
 *   gave an unusable answer this run, deferFallback: return after a rejected routed answer
 *   (the web page runs one paid call per request) }
 * @param {object[]} [p.priorCalls] calls already made for this job (a deferred routed call)
 * @param {string[]} [p.priorNotes] notes that came with them
 * @returns outcome (see policy.js), or { deferred: true, calls, notes } with deferFallback
 */
export async function runCheck({ tg, miners, job, deadline, onCall, routing = { mode: "auto", health: {} }, priorCalls = [], priorNotes = [] }) {
  const { check, intent, target, vars, route } = job;
  // Fallback miners are configured per check; an entry may limit itself to some ecosystems.
  const entries = (miners[check] ?? []).filter((e) => e.enabled !== false && (!e.ecosystems || e.ecosystems.includes(vars.ecosystem)));
  const calls = [...priorCalls];
  const notes = [...priorNotes];
  const base = { check, intent, target, findings: [], confirmed: false, disagreement: false, calls, notes };
  const ledger = (r, minerId, askedIntent) => onCall?.(ledgerEntry({ check, target, intent: askedIntent, minerId }, r));
  const health = routing.health ?? {};

  let answer = null;
  let lastReason = null;
  const tryRoute = route && routing.mode !== "off" && health[route.intent] !== false && !priorCalls.length;
  if (tryRoute) {
    if (Date.now() > deadline) return { ...base, status: "skipped", severity: "none", reason: "time limit" };
    const r = await tg.ask({ intent: route.intent, params: route.params });
    const judged = judgeRouted(r, route, entries, vars);
    calls.push(callSummary(r, { via: "routed", note: judged.reject && `not used: ${judged.reject}` }));
    await ledger(r, r.body?.miner_id ?? "routed", route.intent);
    if (judged.answer) answer = judged.answer;
    else {
      if (r.reason === "over_budget") return { ...base, status: "skipped", severity: "none", reason: "budget exhausted" };
      notes.push(`Routed ${route.intent} answer not used: ${judged.reject}.`);
      if (judged.systematic) {
        health[route.intent] = false; // don't pay for the same off-target routing again this run
        await routing.onUnusable?.(route.intent, judged.reject);
      }
      if (routing.deferFallback) return { deferred: true, calls, notes };
    }
  } else if (!route && job.routeSkipped) {
    notes.push(`Not routed: ${job.routeSkipped}.`);
  }

  if (!answer) {
    if (!entries.length) {
      return tryRoute
        ? { ...base, status: "failed", severity: "none", reason: "routed answer unusable and no vetted miner for this target" }
        : { ...base, status: "skipped", severity: "none", reason: `no vetted ${check} miner yet` };
    }
    for (let i = 0; i < Math.min(MAX_ATTEMPTS, entries.length); i++) {
      if (Date.now() > deadline) { lastReason = "time limit"; break; }
      const entry = entries[i];
      const r = await tg.askMiner(entry.minerId, { method: entry.method ?? "POST", endpoint: entry.endpoint, payload: fillTemplate(entry.payload, vars) });
      calls.push(callSummary(r, { via: "direct", entry }));
      await ledger(r, entry.minerId, entry.intent);
      if (r.ok) { answer = normalize(entry.normalizer, r.body?.result, vars); break; }
      lastReason = r.reason;
      // The registry itself doesn't know the package (private or unpublished);
      // every miner proxies the same registry, and each miss is charged.
      if (isUpstreamNotFound(r)) { lastReason = "not_found"; break; }
      if (r.reason === "over_budget") break; // budget spent: stop rather than shop for a cheaper miner
    }
  }

  if (!answer) {
    const skipped = { over_budget: "budget exhausted", "time limit": "time limit", not_found: "not in the public registry" };
    if (skipped[lastReason]) return { ...base, status: "skipped", severity: "none", reason: skipped[lastReason] };
    return { ...base, status: "failed", severity: "none", reason: lastReason };
  }
  const judged = confirmFindings(check, answer, vars);
  return {
    ...base,
    status: "ok",
    severity: judged.severity,
    findings: judged.findings,
    confirmed: judged.confirmed,
    disagreement: judged.disagreement,
    ...(judged.advice && { advice: judged.advice }),
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
