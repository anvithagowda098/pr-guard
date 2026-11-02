// Read-only GitHub access for the web page. Public pull requests only: the
// optional token carries no scopes and only raises GitHub's rate limit.
const API = "https://api.github.com";

/** An error whose message is safe and useful to show the visitor. */
export class UserError extends Error {}

export function createGitHub({ token, fetch: fetchImpl = (...a) => fetch(...a) } = {}) {
  const headers = {
    accept: "application/vnd.github+json",
    "user-agent": "pr-guard-web",
    "x-github-api-version": "2022-11-28",
    ...(token && { authorization: `Bearer ${token}` }),
  };

  async function api(path) {
    const res = await fetchImpl(API + path, { headers });
    if (res.status === 404) throw new UserError("Pull request not found. Only pull requests in public repositories can be scanned here.");
    if (res.status === 403 || res.status === 429) throw new UserError("GitHub is rate-limiting this page right now. Please try again in a few minutes.");
    if (!res.ok) throw new Error(`GitHub ${path} answered ${res.status}`);
    return res.json();
  }

  return {
    getPull: (owner, repo, number) => api(`/repos/${owner}/${repo}/pulls/${number}`),

    async listFiles(owner, repo, number, max = 100) {
      const out = [];
      for (let page = 1; out.length < max; page++) {
        const batch = await api(`/repos/${owner}/${repo}/pulls/${number}/files?per_page=100&page=${page}`);
        out.push(...batch);
        if (batch.length < 100) break;
      }
      return out.slice(0, max);
    },

    /** Merge base of base...head; falls back to base when GitHub can't compare. */
    async mergeBase(owner, repo, base, head) {
      try {
        return (await api(`/repos/${owner}/${repo}/compare/${base}...${head}`)).merge_base_commit.sha;
      } catch (err) {
        if (err instanceof UserError) return base;
        throw err;
      }
    },

    /** File text at a commit of a public repository, or null if absent. */
    async rawText(fullName, ref, path) {
      const url = `https://raw.githubusercontent.com/${fullName}/${ref}/${path.split("/").map(encodeURIComponent).join("/")}`;
      const res = await fetchImpl(url, { headers: { "user-agent": "pr-guard-web" } });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`raw ${path} answered ${res.status}`);
      return res.text();
    },
  };
}

/** owner/repo/number from a GitHub pull request URL, or null. */
export function parsePullUrl(input) {
  const m = String(input ?? "").trim().match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+)\/pull\/(\d+)(?:[/?#].*)?$/i);
  return m ? { owner: m[1], repo: m[2], number: Number(m[3]) } : null;
}
