// The one PR comment: verdict, why, what was checked, what it cost, and the
// Telegraph evidence for every paid call.
import { NETWORK_LABEL } from "./telegraph.js";


export const MARKER = "<!-- pr-guard -->";
const GITHUB_COMMENT_LIMIT = 65_536;

const BADGE = { SAFE: "🟢 SAFE", CAUTION: "🟡 CAUTION", BLOCK: "🔴 BLOCK", SKIPPED: "⚪ SKIPPED" };
const SEV_ICON = { none: "✅", low: "🔵", medium: "🟡", high: "🔴", critical: "🔴", unknown: "❔" };

const usd = (n) => `$${Number(n).toFixed(3)}`;
const cell = (s, max = 120) => {
  const t = String(s ?? "").replace(/\r?\n/g, " ").replace(/\|/g, "\\|");
  return t.length > max ? t.slice(0, max - 1) + "…" : t;
};

function resultCell(o) {
  if (o.status === "skipped") return `⏭️ skipped (${o.reason ?? ""})`;
  if (o.status === "failed") return `⚠️ failed (${o.reason ?? ""})`;
  const top = o.findings.find((f) => f.severity === o.severity) ?? o.findings[0];
  const high = o.severity === "high" || o.severity === "critical";
  const extra = o.disagreement ? " · miners disagree" : high && o.confirmed ? " · confirmed" : "";
  const advice = o.advice ? ` · fix: ${o.advice}` : "";
  return `${SEV_ICON[o.severity] ?? ""} ${o.severity}${top ? `: ${top.title}` : ""}${extra}${advice}`;
}

const minerCell = (calls) => calls.map((c) => `#${c.minerId}${c.minerName ? ` ${c.minerName}` : ""}`).join(", ") || "local";

const evidenceCell = (calls, nodeUrl) =>
  calls.filter((c) => c.signalHash).map((c) => `[signal](${nodeUrl}/engine/v1/signal/${c.signalHash})`).join(" ") || "—";

/**
 * @param {object} r
 * @param {"SAFE"|"CAUTION"|"BLOCK"|"SKIPPED"} r.verdict
 * @param {string[]} r.reasons
 * @param {object[]} r.outcomes
 * @param {number} r.spentUsd
 * @param {number} r.budgetUsd
 * @param {string} r.nodeUrl
 * @param {string} [r.runUrl] link to the workflow run (ledger artifact lives there)
 * @param {string} [r.note] shown under the heading (e.g. why the run was skipped)
 */
export function renderComment({ verdict, reasons = [], outcomes = [], spentUsd = 0, budgetUsd, nodeUrl, runUrl, note }) {
  const lines = [MARKER, `## PR Guard: ${BADGE[verdict] ?? verdict}`, ""];
  if (note) lines.push(note, "");
  if (reasons.length) {
    lines.push(...reasons.slice(0, 15).map((r) => `- ${cell(r, 200)}`));
    if (reasons.length > 15) lines.push(`- …and ${reasons.length - 15} more`);
    lines.push("");
  }

  if (outcomes.length) {
    lines.push("| Check | Target | Result | Miner | Cost | Evidence |", "|---|---|---|---|---|---|");
    for (const o of outcomes) {
      const cost = o.calls.reduce((s, c) => s + (c.costUsd ?? 0), 0);
      lines.push(`| ${o.check} | ${cell(o.target, 60)} | ${cell(resultCell(o))} | ${cell(minerCell(o.calls), 50)} | ${usd(cost)} | ${evidenceCell(o.calls, nodeUrl)} |`);
    }
    lines.push("");
  }

  const calls = outcomes.flatMap((o) => o.calls);
  const paid = calls.filter((c) => c.costUsd > 0);
  const budget = budgetUsd !== undefined ? ` of ${usd(budgetUsd)} budget` : "";
  lines.push(`**Spent:** ${usd(spentUsd)}${budget} · ${paid.length} paid call${paid.length === 1 ? "" : "s"} · Telegraph testnet (${NETWORK_LABEL})`);

  const detailed = outcomes.filter((o) => o.findings.length);
  if (detailed.length) {
    lines.push("", "<details><summary>Findings</summary>", "");
    for (const o of detailed) {
      for (const f of o.findings) {
        const where = f.file ? ` (\`${f.file}${f.line ? `:${f.line}` : ""}\`)` : "";
        const title = f.ref ? `[${cell(f.title, 200)}](${f.ref})` : cell(f.title, 200);
        lines.push(`- **${f.severity}** ${title}${where}${f.detail ? ` — ${cell(f.detail, 300)}` : ""}`);
      }
    }
    lines.push("", "</details>");
  }

  const receipts = calls.filter((c) => c.receiptHash || c.signalHash);
  if (receipts.length) {
    lines.push("", "<details><summary>Telegraph receipts</summary>", "", "| Miner | signal_hash | receipt_hash | Cost |", "|---|---|---|---|");
    for (const c of receipts) lines.push(`| #${c.minerId} | \`${c.signalHash ?? "—"}\` | \`${c.receiptHash ?? "—"}\` | ${usd(c.costUsd ?? 0)} |`);
    lines.push("", "</details>");
  }

  if (runUrl) lines.push("", `<sub>[Run and purchase ledger](${runUrl}) · checks bought autonomously via Telegraph</sub>`);

  let body = lines.join("\n");
  if (body.length > GITHUB_COMMENT_LIMIT) {
    const tail = `\n\n…truncated; see the purchase ledger${runUrl ? ` in the [run](${runUrl})` : ""}.`;
    body = body.slice(0, GITHUB_COMMENT_LIMIT - tail.length) + tail;
  }
  return body;
}
