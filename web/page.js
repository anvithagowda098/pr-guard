// The single page behind / and /r/:id. All text that comes from a pull request
// or a miner is set with textContent, never as HTML.
export const PAGE = String.raw`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PR Guard</title>
<meta name="description" content="Security checks for any public GitHub pull request, bought from Telegraph's miner network.">
<style>
:root{--bg:#fafaf9;--fg:#1c1917;--muted:#57534e;--card:#fff;--line:#e7e5e4;--accent:#1c1917;--accentfg:#fff;
--safe:#15803d;--safebg:#f0fdf4;--caution:#a16207;--cautionbg:#fefce8;--block:#b91c1c;--blockbg:#fef2f2;--chip:#f5f5f4}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0c0a09;--fg:#e7e5e4;--muted:#a8a29e;--card:#1c1917;--line:#292524;--accent:#e7e5e4;--accentfg:#0c0a09;
--safe:#4ade80;--safebg:#052e16;--caution:#facc15;--cautionbg:#2a2106;--block:#f87171;--blockbg:#2a0a0a;--chip:#292524}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:760px;margin:0 auto;padding:32px 16px 48px}
h1{font-size:1.75rem;margin:0}h2{font-size:1.05rem;margin:0 0 12px}
.lede{color:var(--muted);margin:6px 0 24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:0 0 16px}
form{display:flex;gap:8px;flex-wrap:wrap}
input{flex:1 1 320px;min-width:0;padding:12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font:inherit}
button{padding:12px 18px;border:0;border-radius:8px;background:var(--accent);color:var(--accentfg);font:inherit;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
.hint{color:var(--muted);font-size:.875rem;margin:8px 0 0}
.error{color:var(--block);margin:8px 0 0}
.verdict{border-radius:10px;padding:14px 16px;font-weight:700;font-size:1.15rem;margin:0 0 12px}
.v-SAFE{background:var(--safebg);color:var(--safe)}.v-CAUTION{background:var(--cautionbg);color:var(--caution)}.v-BLOCK{background:var(--blockbg);color:var(--block)}.v-run{background:var(--chip);color:var(--muted)}
.pr a{color:inherit;font-weight:600}.pr{margin:0 0 12px;word-break:break-word}
ul.reasons{margin:0 0 12px;padding-left:20px}
.row{border-top:1px solid var(--line);padding:10px 0}
.row:first-child{border-top:0}
.row .head{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.tag{font-size:.75rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;background:var(--chip);border-radius:6px;padding:2px 6px}
.target{font-family:ui-monospace,monospace;font-size:.9rem;word-break:break-all}
.res{margin:4px 0 0}.meta{color:var(--muted);font-size:.85rem;margin:4px 0 0;word-break:break-word}
.meta a{color:inherit}
.s-high,.s-critical{color:var(--block);font-weight:600}.s-medium,.s-unknown{color:var(--caution);font-weight:600}.s-low,.s-none{color:var(--safe);font-weight:600}
details{margin:6px 0 0}summary{cursor:pointer;color:var(--muted);font-size:.875rem}
details ul{margin:6px 0 0;padding-left:20px;font-size:.9rem}
.spent{color:var(--muted);font-size:.9rem;margin:12px 0 0}
.recent a{display:flex;gap:8px;align-items:baseline;padding:8px 0;border-top:1px solid var(--line);color:inherit;text-decoration:none}
.recent a:first-child{border-top:0}
.pill{font-size:.75rem;font-weight:700;border-radius:999px;padding:2px 8px;white-space:nowrap}
.recent .label{font-family:ui-monospace,monospace;font-size:.85rem;white-space:nowrap}.recent .t{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
footer{color:var(--muted);font-size:.85rem;margin-top:24px}
footer p{margin:6px 0}
.linkbtn{background:none;color:var(--fg);border:1px solid var(--line);padding:6px 10px;font-weight:500;font-size:.875rem}
</style></head><body><main>
<h1>PR Guard</h1>
<p class="lede">Security checks for any public GitHub pull request, bought live from <a href="https://telegraphprotocol.com" rel="noopener">Telegraph</a>'s miner network. Vulnerable dependencies, injection, leaked keys: one verdict, with a receipt for every check.</p>

<section class="card">
<form id="f"><label for="u" class="hint" style="width:100%;margin:0 0 4px">Pull request link</label>
<input id="u" name="u" type="url" inputmode="url" autocomplete="off" placeholder="https://github.com/owner/repo/pull/123" required>
<button id="go" type="submit">Scan</button></form>
<p class="hint">Free on Telegraph's testnet, paid from the PR Guard sponsor wallet. 5 scans per visitor per day.</p>
<p id="err" class="error" role="alert" hidden></p>
</section>

<section id="scan" class="card" hidden aria-live="polite"></section>

<section class="card"><h2>Recent scans</h2><div id="recent" class="recent"><p class="hint">Loading…</p></div></section>

<footer>
<p><strong>How it works.</strong> PR Guard reads the pull request from GitHub and redacts anything that looks like a secret. Then it buys each check through Telegraph's routing, which picks the miner for the task:</p>
<ul>
<li><strong>Code:</strong> a canonical <code>CODE_REVIEW_GENERAL</code> ask for each part of the diff.</li>
<li><strong>Dependencies:</strong> a canonical <code>SECURITY_REVIEW_GENERAL</code> ask for each changed package.</li>
</ul>
<p>If a routed answer isn't about what was asked, PR Guard says so and asks one vetted miner instead: deps.dev Package Review (#77010) or PR Guard Sentinel for packages, Telegraph Verity (#5530) for code. A finding blocks only with deterministic evidence: registry data about the exact package version, or PR Guard's own rules finding the same issue in the diff. Every paid check links to its receipt on the Telegraph node.</p>
<p><strong>Disclosure.</strong> PR Guard Sentinel is built by the PR Guard team. Payments are test USDC on Ethereum Sepolia, not real money. Up to $0.10 is spent per scan. A scan is advisory, not a full audit.</p>
</footer>
</main>
<script>
(function () {
  var $ = function (s) { return document.querySelector(s); };
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = String(text); return e; }
  function safeUrl(u) { try { var x = new URL(u); return x.protocol === "https:" ? x.href : null; } catch (e) { return null; } }
  function link(href, text) { var u = safeUrl(href); if (!u) return el("span", null, text); var a = el("a", null, text); a.href = u; a.target = "_blank"; a.rel = "noopener"; return a; }
  function usd(n) { return "$" + Number(n || 0).toFixed(3); }
  var BADGE = { SAFE: "🟢 SAFE", CAUTION: "🟡 CAUTION", BLOCK: "🔴 BLOCK" };
  var NAMES = { deps: "Dependency", diff: "Code", addresses: "Address", "address-changes": "Address change", secrets: "Secrets", "install-scripts": "Install scripts" };

  function showError(msg) { var e = $("#err"); e.textContent = msg; e.hidden = !msg; }

  function outcomeRow(o, nodeUrl) {
    var row = el("div", "row");
    var head = el("div", "head");
    head.append(el("span", "tag", NAMES[o.check] || o.check), el("span", "target", o.target));
    row.append(head);
    var res = el("p", "res");
    if (o.status === "skipped") res.append(el("span", "s-unknown", "skipped"), document.createTextNode(" · " + (o.reason || "")));
    else if (o.status === "failed") res.append(el("span", "s-unknown", "check failed"), document.createTextNode(" · " + (o.reason || "")));
    else {
      var top = (o.findings || []).filter(function (f) { return f.severity === o.severity; })[0] || (o.findings || [])[0];
      res.append(el("span", "s-" + o.severity, o.severity === "none" ? "no issues" : o.severity));
      if (top) res.append(document.createTextNode(": " + top.title));
      if (o.disagreement) res.append(document.createTextNode(" · local rules disagree"));
      else if (o.confirmed && (o.severity === "high" || o.severity === "critical")) res.append(document.createTextNode(" · confirmed"));
      if (o.advice) res.append(document.createTextNode(" · fix: " + o.advice));
    }
    row.append(res);
    var calls = o.calls || [];
    var meta = el("p", "meta");
    if (!calls.length) meta.textContent = "local check, free";
    else {
      var cost = calls.reduce(function (s, c) { return s + (c.costUsd || 0); }, 0);
      meta.append(document.createTextNode(calls.map(function (c) {
        var via = c.via === "routed" ? (c.note ? " (routed, not used)" : " (routed)") : c.via === "direct" ? " (fallback)" : "";
        return "#" + c.minerId + (c.minerName ? " " + c.minerName : "") + via;
      }).join(", ") + " · " + usd(cost)));
      calls.forEach(function (c) {
        if (!c.signalHash) return;
        meta.append(document.createTextNode(" · "));
        meta.append(link(nodeUrl + "/engine/v1/signal/" + c.signalHash, "receipt " + c.signalHash.slice(0, 10) + "…"));
      });
    }
    row.append(meta);
    (o.notes || []).forEach(function (n) { row.append(el("p", "meta", n)); });
    if ((o.findings || []).length && o.severity !== "none") {
      var d = el("details"); d.append(el("summary", null, o.findings.length + " finding" + (o.findings.length === 1 ? "" : "s")));
      var ul = el("ul");
      o.findings.slice(0, 40).forEach(function (f) {
        var li = el("li");
        li.append(el("span", "s-" + f.severity, f.severity), document.createTextNode(" "));
        li.append(f.ref ? link(f.ref, f.title) : document.createTextNode(f.title));
        if (f.file) li.append(document.createTextNode(" (" + f.file + (f.line ? ":" + f.line : "") + ")"));
        if (f.detail) li.append(document.createTextNode(" · " + f.detail));
        ul.append(li);
      });
      d.append(ul); row.append(d);
    }
    return row;
  }

  function render(s) {
    var box = $("#scan"); box.hidden = false; box.textContent = "";
    var pr = el("p", "pr"); pr.append(link(s.pr.url, s.pr.label), document.createTextNode(" · " + s.pr.title)); box.append(pr);
    var done = s.status === "done";
    var v = el("div", "verdict " + (done ? "v-" + s.verdict : "v-run"),
      done ? BADGE[s.verdict] : "Scanning: check " + Math.min(s.next + 1, s.jobs.length) + " of " + s.jobs.length + "…");
    box.append(v);
    if (done && s.reasons.length) { var ul = el("ul", "reasons"); s.reasons.forEach(function (r) { ul.append(el("li", null, r)); }); box.append(ul); }
    s.outcomes.forEach(function (o) { box.append(outcomeRow(o, s.nodeUrl)); });
    s.jobs.slice(s.next).forEach(function (j, i) {
      var row = el("div", "row"); var head = el("div", "head");
      head.append(el("span", "tag", NAMES[j.check] || j.check), el("span", "target", j.target)); row.append(head);
      row.append(el("p", "meta", i === 0 && !done ? "buying this check on Telegraph…" : "waiting"));
      box.append(row);
    });
    var spent = el("p", "spent", "Spent " + usd(s.spentUsd) + " of " + usd(s.budgetUsd) + " · " + s.network + " · paid from the PR Guard sponsor wallet");
    box.append(spent);
    (s.notes || []).forEach(function (n) { box.append(el("p", "hint", n)); });
    if (done) {
      var b = el("button", "linkbtn", "Copy link to this report");
      b.onclick = function () { navigator.clipboard && navigator.clipboard.writeText(location.href).then(function () { b.textContent = "Link copied"; }); };
      box.append(b);
    }
  }

  async function api(method, path, body) {
    var r = await fetch(path, { method: method, headers: body ? { "content-type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
    var j = await r.json().catch(function () { return {}; });
    return { status: r.status, body: j };
  }

  var running = null;
  async function run(id) {
    if (running === id) return; running = id;
    var r = await api("GET", "/api/scan/" + id);
    if (r.status !== 200) { showError(r.body.error || "Scan not found."); running = null; return; }
    var s = r.body.scan; render(s);
    while (s.status !== "done") {
      r = await api("POST", "/api/scan/" + id + "/step");
      if (r.status === 409) { await new Promise(function (ok) { setTimeout(ok, 3000); }); r = await api("GET", "/api/scan/" + id); }
      if (r.status >= 400 && r.status !== 409) { showError(r.body.error || "The scan stopped. Reload to resume."); break; }
      s = r.body.scan; render(s);
    }
    running = null; loadRecent();
  }

  async function loadRecent() {
    var r = await api("GET", "/api/recent"); var box = $("#recent"); box.textContent = "";
    var list = (r.body && r.body.recent) || [];
    if (!list.length) { box.append(el("p", "hint", "No scans yet. Be the first.")); return; }
    list.forEach(function (x) {
      var a = el("a"); a.href = "/r/" + encodeURIComponent(x.id);
      a.append(el("span", "pill v-" + x.verdict, BADGE[x.verdict] || x.verdict), el("span", "label", x.label), el("span", "t", x.title));
      box.append(a);
    });
  }

  $("#f").addEventListener("submit", async function (ev) {
    ev.preventDefault(); showError("");
    var btn = $("#go"); btn.disabled = true; btn.textContent = "Reading the pull request…";
    try {
      var r = await api("POST", "/api/scan", { url: $("#u").value });
      if (r.status >= 400) { showError(r.body.error || "Could not start the scan."); return; }
      history.pushState(null, "", "/r/" + r.body.id);
      await run(r.body.id);
    } finally { btn.disabled = false; btn.textContent = "Scan"; }
  });
  window.addEventListener("popstate", function () { var m = location.pathname.match(/^\/r\/([a-z0-9]+)$/); if (m) run(m[1]); });

  var m = location.pathname.match(/^\/r\/([a-z0-9]+)$/);
  if (m) run(m[1]);
  loadRecent();
})();
</script></body></html>`;
