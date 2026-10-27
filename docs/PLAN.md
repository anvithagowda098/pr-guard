# PR Guard: plan and state (handoff)

Telegraph Hackathon Season II: Apps & Agents track (Mission 10, Model Economy) plus the Miners track. The event runs Nov 1 to Dec 1, 2026 (23:59 UTC). Submit by Nov 29.

## The rules that matter (hackathon.telegraphprotocol.com/rules, read Oct 27)

- **Apps & Agents prizes:**
  - 8 delivery awards of $225. Judges pick the set of entries covering the most distinct missions, then the most distinct working apps.
  - Excellence awards: $700 / $350 / $150, ranked by score.
- **Miners prizes:** 4 delivery awards of $300 (favours unblocking missing, mission-critical intents), plus excellence $500 / $300.
- **To win:** at least 70/100, with technical quality at least 24/35. The rubric: technical 35, commercial 30, adoption 15, integration 10, proof 10.
- **Multiple tracks and earlier work:** entering more than one track is allowed if each entry is a distinct contribution. Code written before Nov 1 is allowed (disclose reused parts). **Transaction evidence must come from Nov 1–Dec 1:** the October test payments don't count.
- **Disqualifying:** fake receipts, manufactured adoption, collusive requests. PR Guard buying from our own miner must be disclosed. The miner's case rests on independent tests, not self-purchases.
- **Reviewers check each mission in five steps:** run with new input, check the result, inspect the Telegraph request, break it, reproduce it.

## What works today (branch claude/pr-guard-telegraph-c6l9dk)

- **The Action** (`src/`), 75 tests:
  - Dependency check: deps.dev Package Review #77010, confirmed by Secrev Depsdev #190048 matching advisory ids.
  - Diff security review: ChainSight #302 `/secreview`.
  - Local secret and install-script scan.
  - Budget reserved at quote time, a PR comment, a ledger.
- **The miner** (`miner/`): PR Guard Sentinel, `SECURITY_REVIEW`.
  - Rule-based `/review` and OSV-backed `/package`.
  - Tested, but not yet deployed or registered. The id 731001 and slug `pr-guard-sentinel` were free on Oct 27.
- **Network facts learned:** see the README section "Which miners, and why". Failed miner calls are charged. Unknown packages answer 500 with "upstream error 404".

## Next steps, in order

1. **Repos:** move to a private `pr-guard` repo now. Go public around Nov 14–20, because adoption needs a public Action. Delete the branch from the public `intelligent-doc-query` repo once moved.
2. **Deploy the miner** to Cloudflare Workers (needs `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`). Set `base_url`, validate at integrate.telegraphprotocol.com, then register. Gas comes from the Base Sepolia ETH faucet.
3. **Add the Sentinel miner to `config/miners.json`** as the second opinion for `diff`, so the rules and the AI agreeing can produce BLOCK. Also add it for `deps` on non-npm ecosystems, since it rates PyPI, Go and Cargo.
4. **Demo repo** with 3 ready PRs: clean, a vulnerable dependency (lodash 4.17.15), and an injection plus a leaked key. Re-run it in November for evidence.
5. **Public "paste a PR link" page** with a sponsored free tier, permalinks and a recent-scans feed.
6. **Evaluation set:** labelled vulnerable and clean packages and code snippets, scored against the competing miners. Report cost per correct answer, and consider an Evaluators-track entry.
7. **Real adoption:** real maintainers on real repos. Never staged.
8. **Submission:** 2–5 minute video, README run steps, evidence (receipts, signal hashes, ledger), and the 5 commercial answers.

## Environment needs

- **Network allowlist:**
  - Already added: `devnode.telegraphprotocol.com`, `docs.telegraphprotocol.com`, `facilitator.payai.network`, `sepolia.base.org`, `hackathon.telegraphprotocol.com`.
  - Still needed: `api.cloudflare.com`, `*.workers.dev`, `api.osv.dev`, `integrate.telegraphprotocol.com`.
- **Burner wallet:** created in this container's `pr-guard/.env` (gitignored). It's lost when the container goes, which is fine: generate a new one with `node scripts/wallet.js` and refund it from the faucet.
