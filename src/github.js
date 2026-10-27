// GitHub I/O: PR files, file contents at a commit, and the single PR Guard comment.
import { MARKER } from "./report.js";

export function listPrFiles(octokit, { owner, repo, pull_number }) {
  return octokit.paginate(octokit.rest.pulls.listFiles, { owner, repo, pull_number, per_page: 100 });
}

/** Where the PR branched from base, so dependency diffs ignore later base commits. */
export async function mergeBase(octokit, { owner, repo, base, head }) {
  const { data } = await octokit.rest.repos.compareCommitsWithBasehead({ owner, repo, basehead: `${base}...${head}`, per_page: 1 });
  return data.merge_base_commit.sha;
}

/** File text at a ref, or null if it doesn't exist there. */
export async function getText(octokit, { owner, repo, path, ref }) {
  try {
    const { data } = await octokit.rest.repos.getContent({ owner, repo, path, ref, mediaType: { format: "raw" } });
    if (typeof data === "string") return data;
    if (data instanceof ArrayBuffer) return Buffer.from(data).toString("utf8");
    if (data?.content) return Buffer.from(data.content, data.encoding ?? "base64").toString("utf8");
    return null;
  } catch (err) {
    if (err.status === 404) return null;
    throw err;
  }
}

/** Update PR Guard's comment if there is one, else create it. Re-runs never stack comments. */
export async function upsertComment(octokit, { owner, repo, issue_number, body }) {
  const comments = await octokit.paginate(octokit.rest.issues.listComments, { owner, repo, issue_number, per_page: 100 });
  const mine = comments.find((c) => c.body?.startsWith(MARKER));
  if (mine) {
    const { data } = await octokit.rest.issues.updateComment({ owner, repo, comment_id: mine.id, body });
    return data;
  }
  const { data } = await octokit.rest.issues.createComment({ owner, repo, issue_number, body });
  return data;
}
