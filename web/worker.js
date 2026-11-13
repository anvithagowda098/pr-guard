// PR Guard web: scan any public pull request from a browser, paid from a
// sponsor wallet on Telegraph's testnet.
//
//   POST /api/scan            { url }  plan the scan (no payment yet)
//   POST /api/scan/:id/step   run the next paid check; the last one sets the verdict
//   GET  /api/scan/:id        the scan so far
//   GET  /api/recent          recent finished scans
//   GET  /, /r/:id            the page
//
// One paid check per request keeps each invocation inside the Workers free
// plan's CPU limit (signing a payment costs ~3.5 ms). State lives in KV.
import { Telegraph, Budget, atomicToUsd, DEFAULT_NODE_URL } from "../src/telegraph.js";
import { planScan } from "../src/plan.js";
import { runCheck } from "../src/runner.js";
import { decide } from "../src/policy.js";
import minersConfig from "../config/miners.json" with { type: "json" };
import { createGitHub, parsePullUrl, UserError } from "./github.js";
import { PAGE } from "./page.js";

const DEFAULTS = {
  scansPerIpPerDay: 5, // visitors of the page
  scansPerRepoPerDay: 20, // repositories using the Action without a wallet
  scansPerDay: 100,
  usdPerDay: 1.5, // the sponsor wallet's daily ceiling across all visitors
  usdPerScan: 0.1,
  usdPerCall: 0.05,
};
const LIMITS = { maxDeps: 8, maxChunks: 3, maxChars: 12_000 };
const MAX_FILES = 100;
const SCAN_TTL = 60 * 60 * 24 * 90; // keep reports 90 days
const ROUTE_RETRY_SECONDS = 6 * 60 * 60; // try routing an intent again after an unusable answer
const RECENT = 30;

const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const today = () => new Date().toISOString().slice(0, 10);
const num = (v, d) => (v === undefined || v === "" ? d : Number(v));

function limitsFrom(env) {
  return {
    scansPerIpPerDay: num(env.SCANS_PER_IP_PER_DAY, DEFAULTS.scansPerIpPerDay),
    scansPerRepoPerDay: num(env.SCANS_PER_REPO_PER_DAY, DEFAULTS.scansPerRepoPerDay),
    scansPerDay: num(env.SCANS_PER_DAY, DEFAULTS.scansPerDay),
    usdPerDay: num(env.USD_PER_DAY, DEFAULTS.usdPerDay),
    usdPerScan: num(env.USD_PER_SCAN, DEFAULTS.usdPerScan),
    usdPerCall: num(env.USD_PER_CALL, DEFAULTS.usdPerCall),
  };
}

const kvGet = async (env, key) => (await env.SCANS.get(key, "json")) ?? null;
const kvPut = (env, key, value, ttl) => env.SCANS.put(key, JSON.stringify(value), ttl ? { expirationTtl: ttl } : undefined);

/** What the browser sees: the scan without the diff text it was planned from. */
function publicScan(s) {
  return {
    id: s.id,
    pr: s.pr,
    status: s.status,
    createdAt: s.createdAt,
    next: s.next,
    jobs: s.jobs.map(({ check, intent, target }) => ({ check, intent, target })),
    outcomes: s.outcomes,
    spentUsd: s.spentUsd,
    budgetUsd: s.budgetUsd,
    verdict: s.verdict ?? null,
    reasons: s.reasons ?? [],
    notes: s.notes ?? [],
    network: s.network,
    nodeUrl: s.nodeUrl,
  };
}

async function createScan(request, env, deps) {
  const lim = limitsFrom(env);
  const body = await request.json().catch(() => ({}));
  const where = parsePullUrl(body.url);
  if (!where) return json(400, { error: "Paste a GitHub pull request link, like https://github.com/owner/repo/pull/123" });

  const gh = deps.github ?? createGitHub({ token: env.GITHUB_TOKEN, fetch: deps.fetch });
  const pull = await gh.getPull(where.owner, where.repo, where.number);
  const label = `${where.owner}/${where.repo}#${where.number}`;

  // The same commit was already scanned: show that report instead of paying again.
  const cacheKey = `pr:${label}@${pull.head.sha}`;
  const cached = await env.SCANS.get(cacheKey);
  if (cached) return json(200, { id: cached, cached: true });

  // The page is limited per visitor, the Action (no wallet) per repository.
  const source = body.source === "action" ? "action" : "page";
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  const rlKey = source === "action" ? `rl:${today()}:repo:${label.replace(/#\d+$/, "").toLowerCase()}` : `rl:${today()}:${ip}`;
  const dayKey = `day:${today()}`;
  const [used, day] = await Promise.all([kvGet(env, rlKey), kvGet(env, dayKey)]);
  if (source === "action" && (used ?? 0) >= lim.scansPerRepoPerDay) return json(429, { error: `this repository has used its ${lim.scansPerRepoPerDay} free hosted scans for today (they reset at 00:00 UTC). Add a \`TELEGRAPH_PRIVATE_KEY\` secret to pay for more from your own wallet.` });
  if (source === "page" && (used ?? 0) >= lim.scansPerIpPerDay) return json(429, { error: `This page allows ${lim.scansPerIpPerDay} free scans per visitor per day. Try again tomorrow, or install the GitHub Action.` });
  if ((day?.scans ?? 0) >= lim.scansPerDay || (day?.usd ?? 0) >= lim.usdPerDay) return json(429, { error: "Today's free scans are used up. Please try again tomorrow." });

  const rawFiles = await gh.listFiles(where.owner, where.repo, where.number, MAX_FILES);
  const baseSha = await gh.mergeBase(where.owner, where.repo, pull.base.sha, pull.head.sha);
  const headRepo = pull.head.repo?.full_name ?? `${where.owner}/${where.repo}`;
  const baseRepo = pull.base.repo?.full_name ?? `${where.owner}/${where.repo}`;
  const getText = ({ path, ref }) => gh.rawText(ref === pull.head.sha ? headRepo : baseRepo, ref, path);
  const { jobs, local, errors, notes: planNotes } = await planScan({
    pr: pull,
    rawFiles,
    baseSha,
    headSha: pull.head.sha,
    getText,
    checks: new Set(["deps", "diff"]),
    limits: LIMITS,
  });

  const notes = [...planNotes];
  if (rawFiles.length >= MAX_FILES) notes.push(`Only the first ${MAX_FILES} changed files were read.`);
  if (errors.length) notes.push(`Could not read ${errors.map((e) => e.file).join(", ")}.`);

  const id = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  const scan = {
    id,
    pr: { owner: where.owner, repo: where.repo, number: where.number, label, title: pull.title, url: pull.html_url, headSha: pull.head.sha },
    source,
    status: jobs.length ? "running" : "done",
    createdAt: new Date().toISOString(),
    jobs,
    next: 0,
    outcomes: local,
    spentUsd: 0,
    budgetUsd: lim.usdPerScan,
    notes,
    network: "Ethereum Sepolia testnet",
    nodeUrl: env.NODE_URL || DEFAULT_NODE_URL,
  };
  if (!jobs.length) Object.assign(scan, decide(scan.outcomes));

  await Promise.all([
    kvPut(env, `scan:${id}`, scan, SCAN_TTL),
    env.SCANS.put(cacheKey, id, { expirationTtl: SCAN_TTL }),
    kvPut(env, rlKey, (used ?? 0) + 1, 60 * 60 * 26),
    kvPut(env, dayKey, { scans: (day?.scans ?? 0) + 1, usd: day?.usd ?? 0 }, 60 * 60 * 26),
  ]);
  if (scan.status === "done") await addRecent(env, scan);
  return json(201, { id, scan: publicScan(scan) });
}

async function addRecent(env, scan) {
  const recent = (await kvGet(env, "recent")) ?? [];
  const entry = { id: scan.id, label: scan.pr.label, title: scan.pr.title, verdict: scan.verdict, spentUsd: scan.spentUsd, at: new Date().toISOString() };
  await kvPut(env, "recent", [entry, ...recent.filter((r) => r.id !== scan.id)].slice(0, RECENT));
}

async function step(id, env, deps) {
  const scan = await kvGet(env, `scan:${id}`);
  if (!scan) return json(404, { error: "No such scan." });
  if (scan.status === "done") return json(200, { scan: publicScan(scan) });

  // Another tab is already running this check: let the caller wait and re-read.
  if (scan.lock && scan.lock.n === scan.next && Date.now() - scan.lock.at < 90_000) return json(409, { scan: publicScan(scan), busy: true });
  scan.lock = { n: scan.next, at: Date.now() };
  await kvPut(env, `scan:${id}`, scan, SCAN_TTL);

  const lim = limitsFrom(env);
  const dayKey = `day:${today()}`;
  const day = (await kvGet(env, dayKey)) ?? { scans: 0, usd: 0 };
  const job = scan.jobs[scan.next];
  let outcome;
  if (day.usd >= lim.usdPerDay || scan.spentUsd >= scan.budgetUsd) {
    outcome = { check: job.check, intent: job.intent, target: job.target, status: "skipped", reason: "budget exhausted", severity: "none", findings: [], confirmed: false, disagreement: false, calls: scan.pending?.[scan.next]?.calls ?? [] };
  } else {
    const budget = new Budget(Math.min(scan.budgetUsd - scan.spentUsd, lim.usdPerDay - day.usd));
    const tg = deps.telegraph ?? new Telegraph({
      nodeUrl: env.NODE_URL || DEFAULT_NODE_URL,
      privateKey: env.SPONSOR_KEY,
      maxUsdPerCall: lim.usdPerCall,
      budget,
      timeoutMs: 45_000,
      fetch: deps.fetch,
    });
    // Routing health is shared across scans for a few hours: once a routed
    // answer for an intent is unusable, later checks go straight to the fallback.
    const intent = job.route?.intent;
    const health = intent && (await env.SCANS.get(`route:${intent}`)) === "unusable" ? { [intent]: false } : {};
    const routing = {
      mode: env.ROUTING === "off" ? "off" : "auto",
      health,
      deferFallback: true, // one paid call per request keeps the step inside the CPU limit
      onUnusable: (i, why) => env.SCANS.put(`route:${i}`, "unusable", { expirationTtl: ROUTE_RETRY_SECONDS, metadata: { why } }),
    };
    const pending = scan.pending?.[scan.next];
    outcome = await runCheck({ tg, miners: deps.miners ?? minersConfig, job, deadline: Date.now() + 100_000, routing, priorCalls: pending?.calls ?? [], priorNotes: pending?.notes ?? [] });
    if (!deps.telegraph) outcome.spentUsd = atomicToUsd(budget.spent);
  }
  if (outcome.deferred) {
    // The routed answer was unusable: keep its call, and buy the fallback on the next request.
    const spentNow = outcome.spentUsd ?? outcome.calls.reduce((s, c) => s + (c.costUsd ?? 0), 0);
    scan.pending = { ...(scan.pending ?? {}), [scan.next]: { calls: outcome.calls, notes: outcome.notes } };
    scan.spentUsd = Math.round((scan.spentUsd + spentNow) * 1e6) / 1e6;
    delete scan.lock;
    await Promise.all([
      kvPut(env, `scan:${id}`, scan, SCAN_TTL),
      kvPut(env, dayKey, { scans: day.scans, usd: Math.round((day.usd + spentNow) * 1e6) / 1e6 }, 60 * 60 * 26),
    ]);
    return json(200, { scan: publicScan(scan) });
  }
  // A deferred routed call was counted on the request that made it.
  const priorCost = (scan.pending?.[scan.next]?.calls ?? []).reduce((s, c) => s + (c.costUsd ?? 0), 0);
  if (scan.pending) delete scan.pending[scan.next];
  const spent = outcome.spentUsd ?? Math.max(0, outcome.calls.reduce((s, c) => s + (c.costUsd ?? 0), 0) - priorCost);
  delete outcome.spentUsd;

  scan.outcomes.push(outcome);
  scan.spentUsd = Math.round((scan.spentUsd + spent) * 1e6) / 1e6;
  scan.next += 1;
  delete scan.lock;
  if (scan.next >= scan.jobs.length) {
    scan.status = "done";
    Object.assign(scan, decide(scan.outcomes));
  }
  await Promise.all([
    kvPut(env, `scan:${id}`, scan, SCAN_TTL),
    kvPut(env, dayKey, { scans: day.scans, usd: Math.round((day.usd + spent) * 1e6) / 1e6 }, 60 * 60 * 26),
  ]);
  if (scan.status === "done") await addRecent(env, scan);
  return json(200, { scan: publicScan(scan) });
}

/** @param deps test seams: fetch, github, telegraph, miners */
export function createApp(deps = {}) {
  return async function handle(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      if (request.method === "GET" && (path === "/" || /^\/r\/[a-z0-9]+$/.test(path))) {
        return new Response(PAGE, {
          headers: {
            "content-type": "text/html; charset=utf-8",
            "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'",
            "cache-control": "no-store",
          },
        });
      }
      if (request.method === "POST" && path === "/api/scan") return await createScan(request, env, deps);
      let m = path.match(/^\/api\/scan\/([a-z0-9]+)\/step$/);
      if (request.method === "POST" && m) {
        // A paid check must finish and be recorded even if the caller hangs up.
        const work = step(m[1], env, deps);
        ctx?.waitUntil(work.catch(() => {}));
        return await work;
      }
      m = path.match(/^\/api\/scan\/([a-z0-9]+)$/);
      if (request.method === "GET" && m) {
        const scan = await kvGet(env, `scan:${m[1]}`);
        return scan ? json(200, { scan: publicScan(scan) }) : json(404, { error: "No such scan." });
      }
      if (request.method === "GET" && path === "/api/recent") return json(200, { recent: (await kvGet(env, "recent")) ?? [] });
      return json(404, { error: "Not found." });
    } catch (err) {
      if (err instanceof UserError) return json(400, { error: err.message });
      console.error(err);
      return json(500, { error: "Something went wrong on our side. Please try again." });
    }
  };
}

export default { fetch: createApp() };
