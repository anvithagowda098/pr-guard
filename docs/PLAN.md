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

## What works today

- **The Action** (`src/`), 75 tests:
  - Dependency check: deps.dev Package Review #77010, confirmed by Secrev Depsdev #190048 matching advisory ids.
  - Diff security review: ChainSight #302 `/secreview`.
  - Local secret and install-script scan.
  - Budget reserved at quote time, a PR comment, a ledger.
- **The miner** (`miner/`): PR Guard Sentinel, `SECURITY_REVIEW`.
  - Rule-based `/review` and OSV-backed `/package`.
  - **Deployed:** https://pr-guard-sentinel.pr-guard.workers.dev (Cloudflare Workers, `npm run deploy:miner`).
  - **Registered and active** on Telegraph, Oct 27 19:12 UTC:
    - registrationId 4869, routing id 731001;
    - owner and fee address `0xFb49DF5c009e60749776bF3CBed3D1C25Dde0297` (the user's MetaMask);
    - tx `0x88e4ca7650af50613b85b018a91882b75339f395845eb44236a968727e09de67`, relayed by the console.
  - The registered YAML URL is `/miner.yaml` on the Worker, committed by hash. **Any YAML change needs `updateMiner` from the owner wallet.**
  - **First paid call through Telegraph:** `/engine/v1/ask/731001`, /package lodash 4.17.15, 200, $0.01. Signal `0x2d457569…b48d`. This was a self-test from the PR Guard burner, to be disclosed; it predates the event, so it isn't evidence.
- **Network facts learned:** see the README section "Which miners, and why". Failed miner calls are charged. Unknown packages answer 500 with "upstream error 404".

## Next steps, in order

1. **Repo:** this private `pr-guard` repo (moved here from a branch of `intelligent-doc-query` on Oct 27, history kept). Go public around Nov 14–20, because adoption needs a public Action.
2. ~~Deploy and register the miner~~: done Oct 27. Watch its rank and score at `/api/miners?intent=SECURITY_REVIEW`.
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
- **Burner wallet:** created in the container's `.env` (gitignored). It's lost when the container goes, which is fine: generate a new one with `node scripts/wallet.js` and refund it from the faucet.
