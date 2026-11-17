// Impact context: where the code a pull request changes is used elsewhere in
// the repository. A diff alone can't show that a loosened validator in one
// file is fed user input in another; the call sites can. They are sent to the
// reviewer next to the diff, read-only, and are never treated as part of the
// change (PR Guard's own rules still scan only the added lines).
import { shouldSkipFile, isDocFile } from "./extract.js";
import { redact } from "./redact.js";

const CODE_FILE = /\.(js|mjs|cjs|jsx|ts|tsx|py|go|rs|rb|php|java|kt|cs|sol|vy)$/i;
const TEST_FILE = /(^|\/)(test|tests|__tests__|spec|specs|fixtures?|mocks?)\/|\.(test|spec)\.\w+$|_test\.(go|py)$/i;

// Definitions across the languages PR Guard reads.
const DEFINITION = [
  /\b(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/, // JS/TS, Solidity
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/, // JS arrow or function expression
  /\bclass\s+([A-Za-z_$][\w$]*)/, // JS/TS, Python, PHP, Java
  /^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/, // Python
  /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(/, // Go
  /^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_]\w*)/, // Rust
  /\bmodifier\s+([A-Za-z_]\w*)/, // Solidity
  /^\s*(?:abstract\s+)?(?:contract|interface|library)\s+([A-Za-z_]\w*)/, // Solidity
  /^\s*(?:export\s+)?(?:const|let|var)\s+([A-Z][A-Z0-9_]{2,})\s*=/, // exported constants (CONFIG_VALUE = ...)
];
// Too generic to search for usefully.
const STOP = new Set(["main", "init", "run", "get", "set", "app", "handler", "index", "default", "constructor", "render", "test", "setup", "data", "value", "config", "module", "exports", "require", "self", "this", "new", "fn", "cb", "next", "err", "res", "req"]);

function definedIn(text) {
  for (const re of DEFINITION) {
    const m = text.match(re);
    if (m && m[1].length >= 3 && !STOP.has(m[1].toLowerCase())) return m[1];
  }
  return null;
}

/**
 * Functions, classes and constants a PR changes: defined on an added or removed
 * line, or named in a hunk header (git puts the enclosing function there).
 * @returns {{ name: string, file: string }[]}
 */
export function changedSymbols(files, { max = 8 } = {}) {
  const out = new Map();
  for (const f of files) {
    if (!f.patch || !CODE_FILE.test(f.filename) || shouldSkipFile(f.filename) || isDocFile(f.filename)) continue;
    // A changed line counts for the definition it's on, or else the nearest
    // definition above it in the hunk (an unchanged `function` line, or the
    // enclosing function git names in the hunk header).
    let enclosing = null;
    const add = (name) => { if (name && !out.has(name)) out.set(name, { name, file: f.filename }); };
    for (const raw of f.patch.split("\n")) {
      const hunk = raw.match(/^@@ [^@]+ @@\s?(.*)$/);
      if (hunk) { enclosing = definedIn(hunk[1]); continue; }
      if (/^(\+\+\+|---)/.test(raw)) continue;
      const changed = /^[+-]/.test(raw);
      const name = definedIn(changed || raw.startsWith(" ") ? raw.slice(1) : raw);
      if (name) enclosing = name;
      if (changed) add(name ?? enclosing);
    }
  }
  return [...out.values()].slice(0, max);
}

const dirOf = (p) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
function closeness(path, changed) {
  // Shared leading directories with the nearest changed file.
  let best = 0;
  for (const c of changed) {
    const a = dirOf(path).split("/");
    const b = dirOf(c).split("/");
    let n = 0;
    while (n < a.length && n < b.length && a[n] === b[n]) n++;
    best = Math.max(best, n);
  }
  return best;
}

/**
 * Call sites of the changed symbols in files the PR doesn't touch.
 * @param {object} p
 * @param {{ name: string, file: string }[]} p.symbols
 * @param {string[]} p.paths every file path in the repository at the head commit
 * @param {(path: string) => Promise<string | null>} p.read file text at the head commit
 * @param {string[]} p.changed paths the PR changes (not searched: their diff is already sent)
 * @returns {Promise<{ symbol: string, from: string, path: string, line: number, text: string }[]>}
 */
export async function findUsages({ symbols, paths, read, changed, maxFiles = 30, perSymbol = 3, maxSites = 8 }) {
  if (!symbols.length) return [];
  const skip = new Set(changed);
  const candidates = paths
    .filter((p) => CODE_FILE.test(p) && !skip.has(p) && !shouldSkipFile(p) && !isDocFile(p) && !TEST_FILE.test(p))
    .map((p, i) => [p, closeness(p, changed), i])
    .sort((a, b) => b[1] - a[1] || a[2] - b[2])
    .slice(0, maxFiles)
    .map(([p]) => p);
  const patterns = symbols.map((s) => ({ ...s, re: new RegExp(`(?<![\\w$])${s.name.replace(/\$/g, "\\$")}(?![\\w$])`) }));
  const count = new Map();
  const sites = [];
  // Read in small parallel batches, nearest files first; stop once enough sites are found.
  const texts = [];
  for (let i = 0; i < candidates.length && texts.length < candidates.length; i += 5) {
    const batch = candidates.slice(i, i + 5);
    texts.push(...(await Promise.all(batch.map(async (path) => { try { return [path, await read(path)]; } catch { return [path, null]; } }))));
  }
  for (const [path, text] of texts) {
    if (sites.length >= maxSites) break;
    if (!text) continue;
    const lines = text.split("\n");
    for (let i = 0; i < lines.length && sites.length < maxSites; i++) {
      const line = lines[i];
      if (line.length > 400) continue; // minified or generated
      for (const s of patterns) {
        if ((count.get(s.name) ?? 0) >= perSymbol || !s.re.test(line) || definedIn(line) === s.name) continue;
        count.set(s.name, (count.get(s.name) ?? 0) + 1);
        sites.push({ symbol: s.name, from: s.file, path, line: i + 1, text: redact(line.trim()).text.slice(0, 160) });
        break;
      }
    }
  }
  return sites;
}

/** The read-only block appended after a diff chunk. */
export function contextBlock(sites) {
  if (!sites.length) return "";
  const lines = ["", "# Read-only context, not part of this change: where code changed above is used elsewhere in the repository."];
  for (const s of sites) lines.push(`# ${s.path}:${s.line} uses ${s.symbol} (changed in ${s.from})`, `#   ${s.text}`);
  return lines.join("\n") + "\n";
}
