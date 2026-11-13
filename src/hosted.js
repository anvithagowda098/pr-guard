// Hosted mode: no wallet in the repository. The Action hands the pull request
// to PR Guard's public service, which buys the same checks from a sponsor
// wallet, one paid check per request. Public repositories only, since the
// service reads the PR through GitHub's public API.
export const DEFAULT_SERVICE_URL = "https://pr-guard-app.pr-guard.workers.dev";

/** The service answered with a reason the PR wasn't scanned (a limit, a bad link). */
export class HostedRefusal extends Error {}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Scan a public pull request through the hosted service.
 * Returns the finished scan, or a partial one with the unrun checks marked
 * skipped when the deadline passes first.
 */
export async function scanHosted({ serviceUrl = DEFAULT_SERVICE_URL, prUrl, deadline, fetch: fetchImpl = (...a) => globalThis.fetch(...a), sleep = wait, busyWaitMs = 5_000 }) {
  const base = serviceUrl.replace(/\/+$/, "");
  const call = async (method, path, body) => {
    const res = await fetchImpl(base + path, {
      method,
      headers: { "content-type": "application/json", "user-agent": "pr-guard-action" },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  };

  const start = await call("POST", "/api/scan", { url: prUrl, source: "action" });
  if (start.status === 400 || start.status === 429) throw new HostedRefusal(start.data.error ?? `the service answered ${start.status}`);
  if (start.status >= 300) throw new Error(`PR Guard service answered ${start.status}: ${start.data.error ?? "no reason given"}`);
  const id = start.data.id;
  let scan = start.data.scan ?? (await call("GET", `/api/scan/${id}`)).data.scan;

  let failures = 0;
  while (scan?.status !== "done") {
    if (Date.now() >= deadline) return { ...timedOut(scan), reportUrl: `${base}/r/${id}` };
    let r;
    try {
      r = await call("POST", `/api/scan/${id}/step`);
      failures = 0;
    } catch (err) {
      // The connection dropped mid-check. The service still finishes and
      // records it, so re-read the scan rather than paying for it twice.
      if (++failures > 3) throw err;
      await sleep(busyWaitMs);
      scan = (await call("GET", `/api/scan/${id}`)).data.scan ?? scan;
      continue;
    }
    if (r.status === 409) {
      // Someone else (the web page, a re-run) is running this check: wait and re-read.
      await sleep(busyWaitMs);
      scan = (await call("GET", `/api/scan/${id}`)).data.scan ?? scan;
      continue;
    }
    if (r.status !== 200) throw new Error(`PR Guard service answered ${r.status}: ${r.data.error ?? "no reason given"}`);
    scan = r.data.scan;
  }
  return { ...scan, reportUrl: `${base}/r/${id}` };
}

/** The checks not yet run count as skipped, which the policy treats as CAUTION. */
function timedOut(scan) {
  const skipped = scan.jobs.slice(scan.next).map(({ check, intent, target }) => ({
    check, intent, target, status: "skipped", reason: "time limit", severity: "none", findings: [], confirmed: false, disagreement: false, calls: [],
  }));
  return { ...scan, outcomes: [...scan.outcomes, ...skipped], verdict: null, reasons: [], timedOut: true };
}
