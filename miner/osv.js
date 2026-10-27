// Known vulnerabilities for one package version, from OSV (osv.dev), which
// matches by version range and covers npm, PyPI, Go, crates.io, Maven and more.
// Severity: GitHub's rating when the advisory has one, else the CVSS v3 base
// score computed from the vector. CVSS v4-only advisories stay unrated.

const OSV_QUERY = "https://api.osv.dev/v1/query";

const ECOSYSTEMS = {
  npm: "npm", node: "npm", javascript: "npm",
  pypi: "PyPI", python: "PyPI", pip: "PyPI",
  go: "Go", golang: "Go",
  "crates.io": "crates.io", cargo: "crates.io", rust: "crates.io",
  maven: "Maven", java: "Maven",
  rubygems: "RubyGems", gem: "RubyGems", ruby: "RubyGems",
  nuget: "NuGet", packagist: "Packagist", composer: "Packagist",
};

export const osvEcosystem = (name) => ECOSYSTEMS[String(name ?? "").toLowerCase()] ?? null;

// ---- CVSS v3.x base score (FIRST spec, section 7) ---------------------------

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

// CVSS 3.1 Roundup: smallest one-decimal number >= x, robust to float error.
function roundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvss3Score(vector) {
  const m = Object.fromEntries(String(vector).split("/").slice(1).map((p) => p.split(":")));
  if (!/^CVSS:3\.[01]\//.test(vector) || ["AV", "AC", "PR", "UI", "S", "C", "I", "A"].some((k) => !m[k])) return null;
  const changed = m.S === "C";
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exploit = 8.22 * W.AV[m.AV] * W.AC[m.AC] * pr * W.UI[m.UI];
  if ([pr, impact, exploit].some(Number.isNaN)) return null;
  if (impact <= 0) return 0;
  return roundup(Math.min(changed ? 1.08 * (impact + exploit) : impact + exploit, 10));
}

export function cvssSeverity(score) {
  if (score == null) return "unrated";
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "none";
}

const GITHUB = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", LOW: "low" };

/** One OSV record -> { id, aliases, summary, severity, cvss, fixed_in, url }. */
export function summarizeVuln(v, name) {
  const vector = (v.severity ?? []).find((s) => s.type === "CVSS_V3")?.score;
  const cvss = vector ? cvss3Score(vector) : null;
  const severity = GITHUB[v.database_specific?.severity] ?? cvssSeverity(cvss);
  const fixed = new Set();
  for (const a of v.affected ?? []) {
    if (String(a.package?.name).toLowerCase() !== String(name).toLowerCase()) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed.add(e.fixed);
  }
  return {
    id: v.id,
    aliases: v.aliases ?? [],
    summary: v.summary ?? (v.details ?? "").split("\n")[0].slice(0, 200),
    severity,
    cvss,
    fixed_in: [...fixed],
    url: `https://osv.dev/vulnerability/${v.id}`,
  };
}

const RANK = ["none", "unrated", "low", "medium", "high", "critical"];
export const worst = (sevs) => sevs.reduce((a, s) => (RANK.indexOf(s) > RANK.indexOf(a) ? s : a), "none");

/**
 * @param {{ ecosystem: string, name: string, version: string }} pkg
 * @param {typeof fetch} fetchImpl
 */
export async function lookupPackage({ ecosystem, name, version }, fetchImpl = fetch) {
  const eco = osvEcosystem(ecosystem);
  if (!eco) throw new Error(`unsupported ecosystem: ${ecosystem}`);
  const res = await fetchImpl(OSV_QUERY, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ version, package: { name, ecosystem: eco } }),
  });
  if (!res.ok) throw new Error(`OSV answered ${res.status}`);
  const body = await res.json();
  const vulns = (body.vulns ?? []).map((v) => summarizeVuln(v, name));
  return { ecosystem: eco, name, version, severity: worst(vulns.map((v) => v.severity)), vulnerabilities: vulns };
}

/**
 * Package mentions in free text: "lodash@4.17.15", "@scope/pkg@1.2.3",
 * "django==3.2.0" (PyPI). An ecosystem word anywhere in the text applies to
 * @-style mentions; npm is assumed otherwise.
 */
export function packagesIn(text, { max = 10 } = {}) {
  const s = String(text ?? "");
  const word = s.toLowerCase().match(/\b(npm|pypi|pip|python|golang|cargo|crates\.io|rust|maven|rubygems|gem|nuget|packagist|composer)\b/)?.[1];
  const atEco = osvEcosystem(word) ?? "npm";
  const out = new Map();
  for (const m of s.matchAll(/(?<![\w@/.-])(@?[a-z0-9][\w.-]*(?:\/[\w.-]+)*)@(v?\d+(?:\.\d+){0,3}(?:[-+][\w.]+)?)\b/gi)) {
    out.set(`${atEco}\0${m[1]}\0${m[2]}`, { ecosystem: atEco, name: m[1], version: m[2] });
  }
  for (const m of s.matchAll(/(?<![\w.-])([a-z0-9][\w.-]*)==(\d+(?:\.\d+){0,3}(?:[-.+]?\w+)?)\b/gi)) {
    out.set(`PyPI\0${m[1]}\0${m[2]}`, { ecosystem: "PyPI", name: m[1], version: m[2] });
  }
  return [...out.values()].slice(0, max);
}
