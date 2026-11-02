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

## Network move (Oct 30): read this first

Telegraph moved its testnet from Base Sepolia to **Ethereum Sepolia** (chain 11155111) on Oct 30.
- **Contracts:** new Diamond `0x3624EB012B5E998BB57B6bE6C9Cfc9c4bc5eb99b`. Test USDC is `0xcc194e1a843B658526D0D5C431f670028582Ae17`, which anyone can mint.
- **Intents** are now family children: `SECURITY_REVIEW` → `SECURITY_REVIEW_GENERAL`, `CVE_LOOKUP` → `CVE_LOOKUP_CVSS`, `URL_SCAN` → `URL_SCAN_VERDICT`, and so on.
- **Miners:**
  - Registration needs a MACHINA bond: $1 for the first intent, refundable.
  - ChainSight (#302) was not carried over, and neither was our Oct 27 registration.
  - deps.dev Package Review (#77010) and Secrev Depsdev (#190048) were, with the same inputs.
- **Funding:** `scripts/fund-testnet.js` mints USDC, swaps to MACHINA and sends gas.
- **Oct 31:**
  - The burner (`0xd0Cd…cfB44`) holds 22 USDC.
  - The user's MetaMask held 3.45 MACHINA plus gas for re-registering the miner. The bond took about 1.15 MACHINA.
- **Miner re-registered on the new Diamond, Oct 31:**
  - registrationId **4857**, tx `0x845d43703f6b5d610f35600f05749d84c27c30369487dd253a07f0b0860bf2a4`;
  - intent `SECURITY_REVIEW_GENERAL`, YAML hash `0x9c0796…2bab`.
  - It was done through a one-time helper page (`miner/register-page.js`). Telegraph's console offered only the old intent names, and the Diamond rejected them ("a prefix is not an intent").
  - **Active on Telegraph since Nov 2.** Listed among the 24 `SECURITY_REVIEW_GENERAL` miners. Paid calls through Telegraph to `/review` and `/package` both work.
- **Diff review on the new network (Nov 2):** Verity (#5530, independent) asks first; Sentinel confirms. On the planted bugs both agree at the same file:line, giving BLOCK.

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

## Timeline (dates in UTC; the deadline is Dec 1 23:59 UTC, which is Dec 2 05:29 IST)

**Phase 0, before the event (Wed Oct 28 – Sat Oct 31)**

| When | Task | Who |
|---|---|---|
| Oct 28–29 | Create private repo `pr-guard-demo` and give Claude access | User |
| Oct 28–29 | Register on the H2 site: Apps & Agents (Mission 10) and Miners (`SECURITY_REVIEW`); join the Discord | User |
| Oct 29–30 | Sentinel as second opinion: `diff` BLOCKs when the AI and the rules agree; non-npm deps get ratings | Claude |
| Oct 29–30 | Demo repo: the workflow plus 3 PRs (clean, lodash 4.17.15, leaked key plus SQL injection) | Claude |
| Oct 30–31 | New burner for the Action, funded from the Circle faucet, stored as a GitHub secret | User, guided |
| Oct 31 | Dry run on the demo PRs and fixes | Claude |

**Phase 1, the event opens (Sun Nov 1 – Sat Nov 7)**

| When | Task | Who |
|---|---|---|
| Nov 1 | Re-run the demo PRs: the first in-event evidence (receipts, signal hashes, ledger) | Both |
| Nov 1–2 | "Introducing PR Guard" post tagging @Telegraphprotoc | Claude drafts, user posts |
| Nov 2–6 | Public "paste a PR link" page: sponsored free scans, permalinks, recent-scans feed | Claude |
| Nov 3–7 | Outreach list: 15–20 real people or projects | User |

**Phase 2, prove it works (Sun Nov 8 – Sat Nov 14, milestone)**

| When | Task | Who |
|---|---|---|
| Nov 8–11 | Test set of about 50 labelled cases; score every miner; accuracy and cost-per-correct leaderboard | Claude |
| Nov 10–12 | Hardening against the failure cases judges will try; beginner run guide | Claude |
| Nov 12–13 | Make `pr-guard` public and tag v0.1 | User clicks, Claude prepares |
| Sat Nov 14 | Milestone post: a working purchase with receipts | Claude drafts, user posts |

**Phase 3, real users (Sun Nov 15 – Sat Nov 21, showcase)**

| When | Task | Who |
|---|---|---|
| Nov 15–21 | Help 5–10 real people install it on real repos. Never staged. | User |
| Nov 15–21 | Fix what real users hit; watch the miner's rank | Claude |
| Fri Nov 20 | Community showcase demo | User |

**Phase 4, package and submit (Sun Nov 22 – Sun Nov 29)**

| When | Task | Who |
|---|---|---|
| Nov 22–23 | Decide whether to enter the Evaluators track from the test set | Both |
| Tue Nov 24 | Feature freeze: fixes only from here | Both |
| Nov 24–26 | Evidence pack: receipts, signals, ledgers, dated user list, miner stats, test results | Claude |
| Nov 25–27 | Demo video, 2–5 minutes | Claude scripts, user records |
| Nov 26–28 | Submission text for both entries: 5 commercial answers, run steps, limits, disclosures | Claude drafts, user reviews |
| Sun Nov 29 | **Submit both entries** | User |
| Nov 30 – Dec 1 | Buffer only | – |

**After submitting:**
- Dec 2–8: judging. Keep the miner, the page and a funded wallet running.
- About Dec 9: provisional results, with 72 hours to appeal.
- December: separate adoption challenges (2 × $500), so keep users active.

## Environment needs

- **Network allowlist:**
  - Already added: `devnode.telegraphprotocol.com`, `docs.telegraphprotocol.com`, `facilitator.payai.network`, `sepolia.base.org`, `hackathon.telegraphprotocol.com`.
  - Still needed: `api.cloudflare.com`, `*.workers.dev`, `api.osv.dev`, `integrate.telegraphprotocol.com`.
- **Burner wallet:** created in the container's `.env` (gitignored). It's lost when the container goes, which is fine: generate a new one with `node scripts/wallet.js` and refund it from the faucet.
