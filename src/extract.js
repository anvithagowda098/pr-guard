// Turns a PR's changed files into what PR Guard buys checks for: new or bumped
// dependencies, added URLs, added install scripts, and diff chunks small
// enough for one miner call. Pure functions; github.js does the fetching.
import { parse as parseToml } from "smol-toml";

const basename = (path) => path.slice(path.lastIndexOf("/") + 1);

/** Ecosystem for a manifest path we know how to read, else null. */
export function manifestEcosystem(path) {
  const name = basename(path);
  if (name === "package.json" || name === "package-lock.json") return "npm";
  if (/^requirements.*\.txt$/.test(name) || name === "pyproject.toml") return "PyPI";
  if (name === "go.mod") return "Go";
  if (name === "Cargo.toml") return "crates.io";
  return null;
}

// ---- version specs ---------------------------------------------------------

const VERSION_RE = /\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?/;

// What counts as an exact pin differs per ecosystem: a bare "1.2.3" is exact
// for npm and Poetry, but a caret range for Cargo.
const PIN = {
  npm: /^=?v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/,
  pep440: /^===?\s*\d[^,;*\s]*$/,
  poetry: /^(?:==?)?\s*\d+(?:\.\d+)*(?:[-.+]?[0-9A-Za-z]+)*$/,
  cargo: /^=\s*\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/,
};

// A range like "^4.17.15" or ">=2.0,<3" becomes its lower bound, flagged as
// inexact; specs without a registry version (git, paths, aliases) get null.
function versionFrom(spec, pin) {
  if (typeof spec !== "string") return { version: null, exact: false };
  const s = spec.trim();
  if (/^(git\+|git:|https?:|file:|link:|workspace:|npm:|github:)/.test(s) || s.includes("/")) return { version: null, exact: false };
  const m = s.match(VERSION_RE);
  if (!m) return { version: null, exact: false };
  return { version: m[0], exact: pin.test(s) };
}

// ---- manifest parsers: text -> [{ name, spec, version, exact }] -------------

function parsePackageJson(text) {
  const pkg = JSON.parse(text);
  const out = [];
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const [name, spec] of Object.entries(pkg[field] ?? {})) {
      out.push({ name, spec, ...versionFrom(spec, PIN.npm) });
    }
  }
  return out;
}

function parsePackageLock(text) {
  const lock = JSON.parse(text);
  const out = [];
  if (lock.packages) {
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (!path || entry.link || !entry.version) continue;
      const name = path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      out.push({ name, spec: entry.version, version: entry.version, exact: true });
    }
  } else {
    const walk = (deps) => {
      for (const [name, entry] of Object.entries(deps ?? {})) {
        if (entry.version) out.push({ name, spec: entry.version, version: entry.version, exact: true });
        walk(entry.dependencies);
      }
    };
    walk(lock.dependencies);
  }
  return out;
}

// PEP 503 name normalisation, so "Django" and "django" are the same package.
const pypiName = (name) => name.toLowerCase().replace(/[-_.]+/g, "-");

const PEP508_RE = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(\(?\s*(?:===|==|~=|>=|<=|!=|>|<)[^;]*)?/;

function parsePep508(line) {
  const m = line.trim().match(PEP508_RE);
  if (!m) return null;
  const spec = (m[2] ?? "").replace(/[()]/g, "").trim();
  return { name: pypiName(m[1]), spec, ...versionFrom(spec, PIN.pep440) };
}

function parseRequirements(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (!line || line.startsWith("-")) continue; // options: -r, -e, --index-url
    const dep = parsePep508(line);
    if (dep) out.push(dep);
  }
  return out;
}

function parsePyproject(text) {
  const doc = parseToml(text);
  const out = [];
  const pep508 = (list) => {
    for (const line of list ?? []) {
      const dep = parsePep508(line);
      if (dep) out.push(dep);
    }
  };
  pep508(doc.project?.dependencies);
  for (const list of Object.values(doc.project?.["optional-dependencies"] ?? {})) pep508(list);

  const poetry = doc.tool?.poetry;
  const poetryTables = [poetry?.dependencies, poetry?.["dev-dependencies"], ...Object.values(poetry?.group ?? {}).map((g) => g.dependencies)];
  for (const table of poetryTables) {
    for (const [name, value] of Object.entries(table ?? {})) {
      if (name.toLowerCase() === "python") continue;
      const spec = typeof value === "string" ? value : value?.version;
      out.push({ name: pypiName(name), spec: spec ?? "", ...versionFrom(spec, PIN.poetry) });
    }
  }
  return out;
}

function parseGoMod(text) {
  const out = [];
  let inBlock = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\($/.test(line)) { inBlock = true; continue; }
    if (inBlock && line === ")") { inBlock = false; continue; }
    const body = inBlock ? line : line.match(/^require\s+(.+)$/)?.[1];
    const m = body?.match(/^(\S+)\s+(v\S+)$/);
    if (m) out.push({ name: m[1], spec: m[2], version: m[2], exact: true });
  }
  return out;
}

function parseCargoToml(text) {
  const doc = parseToml(text);
  const out = [];
  const tables = [doc.dependencies, doc["dev-dependencies"], doc["build-dependencies"], doc.workspace?.dependencies];
  for (const target of Object.values(doc.target ?? {})) {
    tables.push(target.dependencies, target["dev-dependencies"], target["build-dependencies"]);
  }
  for (const table of tables) {
    for (const [key, value] of Object.entries(table ?? {})) {
      const spec = typeof value === "string" ? value : value?.version;
      const name = (typeof value === "object" && value?.package) || key;
      // Cargo reads a bare "1.2.3" as ^1.2.3; only "=1.2.3" pins.
      out.push({ name, spec: spec ?? "", ...versionFrom(spec, PIN.cargo) });
    }
  }
  return out;
}

const PARSERS = {
  "package.json": parsePackageJson,
  "package-lock.json": parsePackageLock,
  "pyproject.toml": parsePyproject,
  "go.mod": parseGoMod,
  "Cargo.toml": parseCargoToml,
};

export function parseManifest(path, text) {
  if (text == null || text === "") return [];
  const name = basename(path);
  const parser = PARSERS[name] ?? (/^requirements.*\.txt$/.test(name) ? parseRequirements : null);
  if (!parser) throw new Error(`no parser for ${path}`);
  return parser(text);
}

/**
 * New and bumped dependencies between two versions of one manifest.
 * Removals and unchanged entries are dropped.
 * @returns {{ecosystem, name, from, to, spec, exact, manifest}[]}
 */
export function diffManifest(path, baseText, headText) {
  const ecosystem = manifestEcosystem(path);
  const baseVersions = new Map();
  for (const d of parseManifest(path, baseText)) {
    if (!baseVersions.has(d.name)) baseVersions.set(d.name, new Set());
    baseVersions.get(d.name).add(d.spec);
  }
  const seen = new Set();
  const out = [];
  for (const d of parseManifest(path, headText)) {
    const before = baseVersions.get(d.name);
    const key = `${d.name}\0${d.spec}`;
    if (before?.has(d.spec) || seen.has(key)) continue;
    seen.add(key);
    const from = before ? [...before].join(", ") : null;
    out.push({ ecosystem, name: d.name, from, to: d.version, spec: d.spec, exact: d.exact, manifest: path });
  }
  return out;
}

/**
 * One entry per ecosystem/name/version across all manifests. A lockfile's
 * exact version wins over a manifest range for the same package, and
 * packages named in a manifest are marked `direct` (checked first).
 */
export function mergeDependencyChanges(changes) {
  const direct = new Set(changes.filter((c) => !c.manifest.endsWith("package-lock.json")).map((c) => `${c.ecosystem}\0${c.name}`));
  const byName = new Map();
  for (const c of changes) {
    const k = `${c.ecosystem}\0${c.name}`;
    if (!byName.has(k)) byName.set(k, []);
    byName.get(k).push(c);
  }
  const out = [];
  for (const [k, list] of byName) {
    const exact = list.filter((c) => c.exact && c.to);
    const chosen = exact.length ? exact : list;
    const seen = new Set();
    for (const c of chosen) {
      const v = c.to ?? c.spec;
      if (seen.has(v)) continue;
      seen.add(v);
      out.push({ ...c, direct: direct.has(k) });
    }
  }
  return out.sort((a, b) => Number(b.direct) - Number(a.direct));
}

// ---- install scripts -------------------------------------------------------

const INSTALL_HOOKS = ["preinstall", "install", "postinstall", "prepare"];

/** Install-time scripts added or changed in a package.json. */
export function diffInstallScripts(path, baseText, headText) {
  if (basename(path) !== "package.json" || !headText) return [];
  const before = baseText ? JSON.parse(baseText).scripts ?? {} : {};
  const after = JSON.parse(headText).scripts ?? {};
  return INSTALL_HOOKS.filter((h) => after[h] && after[h] !== before[h]).map((h) => ({
    file: path,
    script: h,
    command: after[h],
    change: before[h] ? "changed" : "added",
  }));
}

// ---- added lines, URLs -----------------------------------------------------

/** Added lines of a unified-diff patch, with their line numbers in the new file. */
export function addedLines(patch) {
  const out = [];
  let line = 0;
  for (const raw of (patch ?? "").split("\n")) {
    const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) { line = Number(hunk[1]); continue; }
    if (raw.startsWith("+") && !raw.startsWith("+++")) out.push({ line: line++, text: raw.slice(1) });
    else if (!raw.startsWith("-")) line++;
  }
  return out;
}

/**
 * Where line `n` (1-based) of a unified-diff text sits in the new files:
 * { file, line } for added and context lines, null for headers and removals.
 * Lets a miner that counts lines of the text it was sent point at real code.
 */
export function diffLineLocation(text, n) {
  let file = null;
  let line = 0;
  const lines = String(text ?? "").split("\n");
  for (let i = 0; i < lines.length && i < n; i++) {
    const raw = lines[i];
    const header = raw.match(/^diff --git a\/\S+ b\/(\S+)/);
    if (header) { file = header[1]; continue; }
    const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) { line = Number(hunk[1]); continue; }
    const here = i === n - 1;
    if (raw.startsWith("+++") || raw.startsWith("---")) { if (here) return null; continue; }
    if (raw.startsWith("-")) { if (here) return null; continue; }
    if (here) return file ? { file, line } : { line };
    line++;
  }
  return null;
}

const URL_RE = /https?:\/\/[^\s"'`<>()[\]{}\\]+/g;
const IGNORED_HOSTS = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|(.+\.)?example\.(com|org|net)|.+\.(test|local|invalid|example)|www\.w3\.org|schemas\.[^/]+)$/i;

/** URLs on added lines, deduped, skipping placeholders and local hosts. */
export function extractUrls(files, { max = 10 } = {}) {
  const found = new Map();
  for (const f of files) {
    if (shouldSkipFile(f.filename)) continue;
    for (const { line, text } of addedLines(f.patch)) {
      for (const m of text.matchAll(URL_RE)) {
        const url = m[0].replace(/[.,;:!?]+$/, "");
        let host;
        try { host = new URL(url).hostname; } catch { continue; }
        if (IGNORED_HOSTS.test(host) || found.has(url)) continue;
        found.set(url, { url, file: f.filename, line });
      }
    }
  }
  return [...found.values()].slice(0, max);
}

// ---- diff chunks -----------------------------------------------------------

const LOCKFILES = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|uv\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock)$/;
const GENERATED = /(^|\/)(vendor|node_modules|third_party|dist|build)\/|\.min\.(js|css)$|\.map$/;
const BINARY = /\.(png|jpe?g|gif|ico|webp|bmp|pdf|zip|gz|tgz|bz2|xz|7z|jar|woff2?|ttf|eot|otf|mp[34]|mov|wasm|exe|dll|so|dylib|class|pyc)$/i;

/** Files whose contents must never leave the runner, even redacted. */
export const isSensitiveFile = (path) =>
  /(^|\/)\.env(\.(?!example$|sample$|template$)[^/]+)?$/.test(path) ||
  /\.(pem|key|p12|pfx|jks|keystore)$/i.test(path) ||
  /(^|\/)(id_(rsa|dsa|ecdsa|ed25519)|\.npmrc|\.pypirc|\.netrc|credentials(\.json)?)$/.test(path);

/** Lockfiles, generated/vendored code, binaries and sensitive files aren't reviewed. */
export const shouldSkipFile = (path) =>
  LOCKFILES.test(path) || GENERATED.test(path) || BINARY.test(path) || isSensitiveFile(path);

function splitLong(header, body, maxChars) {
  const pieces = [];
  let cur = "";
  const flush = () => { if (cur) pieces.push(header + cur); cur = ""; };
  // Prefer hunk boundaries; fall back to line boundaries for a giant hunk.
  const hunks = body.split(/\n(?=@@ )/);
  for (const hunk of hunks) {
    const block = hunk + "\n";
    if (header.length + cur.length + block.length <= maxChars) { cur += block; continue; }
    flush();
    if (header.length + block.length <= maxChars) { cur = block; continue; }
    for (const line of block.split("\n")) {
      const l = line.slice(0, maxChars - header.length - 1) + "\n";
      if (header.length + cur.length + l.length > maxChars) flush();
      cur += l;
    }
  }
  flush();
  return pieces;
}

/**
 * Pack reviewable file patches into chunks of at most `maxChars`.
 * Patches should already be redacted.
 * @param {{filename: string, patch?: string}[]} files
 */
export function chunkDiff(files, { maxChars = 12_000 } = {}) {
  const sections = [];
  for (const f of files) {
    if (!f.patch || shouldSkipFile(f.filename)) continue;
    const header = `diff --git a/${f.filename} b/${f.filename}\n`;
    const text = header + f.patch + "\n";
    if (text.length <= maxChars) sections.push({ files: [f.filename], text });
    else for (const piece of splitLong(header, f.patch, maxChars)) sections.push({ files: [f.filename], text: piece });
  }
  const chunks = [];
  for (const s of sections) {
    const last = chunks.at(-1);
    if (last && last.text.length + s.text.length <= maxChars) {
      last.text += s.text;
      for (const f of s.files) if (!last.files.includes(f)) last.files.push(f);
    } else {
      chunks.push({ files: [...s.files], text: s.text });
    }
  }
  return chunks;
}
