# Telegraph Hackathon Season II: submission pack

Drafted Nov 14, 2026, and updated until submission. Everything here can be pasted into the H2 form; links and numbers are checked.

Still to do before Dec 1:
- [ ] 2–5 minute demo video (script separate).
- [ ] Update 3 (Nov 20 showcase) and update 4.
- [ ] Independent users: add them under *Evidence → adoption* as they come.
- [ ] Showcase permission: confirm the choices below.
- [ ] Re-check every link the day before submitting.

---

## Entry 1: Apps & Agents: PR Guard

### Project details

| | |
|---|---|
| Name | **PR Guard** |
| Track | Apps & Agents |
| Missions | **10 Model Economy** ("supply chain verification priced per commit"); **14 Web3 Native & DeFi** (buying contract, address and sanctions analysis before funds move) |
| Intents bought | `CODE_REVIEW_GENERAL`, `SECURITY_REVIEW_GENERAL`, `SANCTIONS_SCREENING_MATCH_GENERAL`, `SMART_CONTRACT_AUDIT_GENERAL` (routed first), plus vetted fallbacks called directly |
| Live app (reviewer access) | https://pr-guard-app.pr-guard.workers.dev (paste any public pull request, no wallet) |
| Code | https://github.com/anvithagowda098/pr-guard |
| Demos | Seven pull requests with live reports: [demo/README.md](../demo/README.md) |
| How it works | [docs/HOW-IT-WORKS.md](HOW-IT-WORKS.md) |
| Team / contact | Anvitha (GitHub `anvithagowda098`, X `@gowda_anvi`) |
| Starred bounties repo as | `anvithagowda098` |

### Short public summary

PR Guard is a security check for GitHub pull requests that buys its answers from Telegraph instead of one vendor. For each pull request it asks the network, by intent, to review the code change (Solidity included). It also checks each new or upgraded package for known vulnerabilities, and screens each new on-chain address against sanctions lists and token-risk data. Each answer is paid per call over x402 and comes back with a receipt.

It posts one verdict (SAFE, CAUTION or BLOCK) with every check, its cost and its receipt. A BLOCK needs deterministic evidence, never one miner's opinion. Routed answers are checked before they're trusted, and an unusable one falls back to a vetted miner, with the reason shown.

It runs as a GitHub Action (no key needed on public repositories) or on a public page. Along the way we:
- reported a routing gap ([bounties#187](https://github.com/telegraphprotocol/bounties/issues/187));
- wired in another builder's sanctions miner at his suggestion;
- contributed evaluation material for smart-contract audits and CVE lookups.

Testnet only (Ethereum Sepolia).

### Commercial summary

**1. Who is it for?** Small engineering teams and open-source maintainers who merge pull requests without a dedicated security reviewer, and Web3 teams whose pull requests change contracts or the addresses funds are sent to. The problem comes up on every pull request: daily for an active repository.

**2. What does it improve?** Today a team either eyeballs the diff, or relies on alerts that arrive after merge (dependency bots), or pays per-seat subscriptions to one scanner vendor. PR Guard gives:
- **Before merge:** one verdict per pull request, combining dependency, code, secret and on-chain address checks.
- **Many providers, no lock-in:** answers come from several providers on an open network.
- **Proof:** a receipt for every paid answer.
- **Cost:** per pull request, not per seat. On testnet a typical pull request costs $0.01–$0.05 and is capped at $0.10.
- **Speed:** each paid check takes about 15–30 s, and checks run in parallel in the Action.

**3. What does it do today?** It works end to end on Telegraph's testnet:
- **Live surfaces:** the GitHub Action and the public page.
- **Demos:** seven demo pull requests with live reports (SAFE, dependency BLOCK, code BLOCK, address-swap CAUTION, reentrant-contract BLOCK, sanctioned-payout BLOCK, cross-file CAUTION).
- **Paid calls through the hosted page:** 43, in 20 scans ($0.39), each with an on-chain settlement transaction ([evidence/hosted-scans.json](evidence/hosted-scans.json)).
- **Tests:** 147 automated tests that replay real captured miner answers.

**4. Why would someone adopt it, and what remains before production?** No seats, no vendor lock-in, receipts for every answer, and setup is one file. Before production:
- **Mainnet:** payments on mainnet, from a managed wallet.
- **Private repositories:** a hosted GitHub App mode.
- **Ranked routing:** ranking for `SECURITY_REVIEW_GENERAL`, which today has no evaluator. PR Guard falls back meanwhile.
- **Coverage:** more package ecosystems.

**5. How can someone try it, and who maintains it?**
- **No setup:** paste a public pull request into the page.
- **Your repository:** add [`examples/pr-guard.yml`](../examples/pr-guard.yml) to a public repository, or use your own burner wallet for private ones.

Maintained by Anvitha (`anvithagowda098`).

### How to run it (for reviewers)

1. **No setup, 1 minute.** Open https://pr-guard-app.pr-guard.workers.dev and paste https://github.com/anvithagowda098/pr-guard/pull/5. A pull request already scanned at the same commit opens its saved report: 🔴 BLOCK, a reentrant `withdraw` and an open `setOwner`.
2. **New input.** Paste any other public pull request. The checks are bought live (about 15–30 s each), paid by a sponsor wallet in test USDC, with up to $0.10 per scan.
3. **Inspect the Telegraph request.** On any report, open a "receipt" link: the Telegraph node's public record of that request, its miner and its settlement transaction. The transaction is on Ethereum Sepolia.
4. **Break it.** Paste a pull request from a private repository, a link that isn't a pull request, or the sanctioned-payout demo (https://github.com/anvithagowda098/pr-guard/pull/6). Each gives a clear error or verdict.
5. **On your own repository.** Add [`examples/pr-guard.yml`](../examples/pr-guard.yml) to a public repository and open a pull request. PR Guard comments within about a minute. No key needed.
6. **Reproduce offline.** `npm ci && npm test` runs 160 tests with no network. The end-to-end tests replay real captured miner answers against a fake payment-gated node.

| | |
|---|---|
| **Network** | Telegraph testnet, Ethereum Sepolia (test USDC, no real value) |
| **Spending limits** | $0.05 per call, $0.10 per pull request (Action defaults). Hosted page: 5 scans per visitor and 20 per repository per day, $1.50 per day overall |
| **Sponsor wallet** | https://pr-guard-app.pr-guard.workers.dev/api/sponsor |

**Troubleshooting:** see the README's [Troubleshooting](../README.md#troubleshooting).

### Evidence

**Wallets**

| Address | Role |
|---|---|
| `0x2DAC17d7e47C11E373980B30e22E7d864a073208` | Hosted page sponsor: pays for scans on the public page |
| `0x83b5A31d89a976Ec607C3064078fd0f7EB34abcc` | PR Guard Action in this repository (demo runs), and evaluation-material uploads |
| `0xd0Cd487cCc2d870709Bc05DfD6d7E27f0d5cfB44` | Development burner: vetting probes and captured fixtures |
| `0xFb49DF5c009e60749776bF3CBed3D1C25Dde0297` | Owner and fee address of PR Guard Sentinel (#731001) |

**Live demo reports.** These are our own tests, not adoption. Each check links to its Telegraph receipt.

| Demo | Verdict | Report (Nov 13) | One settlement transaction (Nov 13) | Re-run (Nov 17) |
|---|---|---|---|---|
| #1 clean change | 🟢 SAFE | [91f1fd167b70](https://pr-guard-app.pr-guard.workers.dev/r/91f1fd167b70) | routed `CODE_REVIEW_GENERAL` → #302: `0xe67503ab6f968b34da5b0f54de2a6f3b23191c774561a1f8091ae4f14237cacc` | [8fee1e820713](https://pr-guard-app.pr-guard.workers.dev/r/8fee1e820713) |
| #2 lodash 4.17.15 | 🔴 BLOCK | [d6c6983b423b](https://pr-guard-app.pr-guard.workers.dev/r/d6c6983b423b) | #77010 deps.dev: `0x92452a2a5affed8c81504cf2f5bd3554512829d1de2c9194304fb94d67a6da03` | [4969f5b82cd2](https://pr-guard-app.pr-guard.workers.dev/r/4969f5b82cd2) |
| #3 leaked key + injection | 🔴 BLOCK | [bc66dc5c844e](https://pr-guard-app.pr-guard.workers.dev/r/bc66dc5c844e) | #5530 Verity: `0x585214cbe4e9419ce22422fca3c9922e3dd1014dec970fb53179a92b8b04414e` | [22f928ab84bd](https://pr-guard-app.pr-guard.workers.dev/r/22f928ab84bd) |
| #4 address swap | 🟡 CAUTION | [b22eec6747c4](https://pr-guard-app.pr-guard.workers.dev/r/b22eec6747c4) | #200001 GoPlus: `0x3a4c59e68884ea1d1a5d7eeb50fb8e8d8d568ed5234cdd94ab02e0f5ed88989c` | [9b631798ba2b](https://pr-guard-app.pr-guard.workers.dev/r/9b631798ba2b) |
| #5 reentrant vault | 🔴 BLOCK | [695b58066331](https://pr-guard-app.pr-guard.workers.dev/r/695b58066331) | routed `CODE_REVIEW_GENERAL` → #302: `0xa631c7a9176c0e77a96e2f85212bd8562704fb1b155a60236dbd5a104da33d02` | [6d50f28e950d](https://pr-guard-app.pr-guard.workers.dev/r/6d50f28e950d) |
| #6 sanctioned payout | 🔴 BLOCK | [5017f9be53ea](https://pr-guard-app.pr-guard.workers.dev/r/5017f9be53ea) | routed `SANCTIONS_SCREENING_MATCH_GENERAL` → #731002: `0xad0c1162113cea488a26bdd15d504335b4c87668db6fe33f26c8c70dc9f92a32` | [f0d17cbef465](https://pr-guard-app.pr-guard.workers.dev/r/f0d17cbef465) |
| #7 loosened validator | 🟡 CAUTION (SAFE [without context](https://pr-guard-app.pr-guard.workers.dev/r/1895dcdb8382)) | [be9e180c79d7](https://pr-guard-app.pr-guard.workers.dev/r/be9e180c79d7) | routed `CODE_REVIEW_GENERAL` → #302: `0xf5eda69d808eb852a54d3195769a81360097294c258e102934c19290b77a5ade` | [d228be4ce003](https://pr-guard-app.pr-guard.workers.dev/r/d228be4ce003) |

**Other records**
- **All hosted scans** with every call, receipt and transaction: [evidence/hosted-scans.json](evidence/hosted-scans.json) (20 scans, 43 paid calls, $0.39, Nov 2–14).
- **GitHub Action runs on the demo pull requests (Nov 2):**
  - 41497627143: SAFE, $0.01.
  - 41497634721: BLOCK, $0.03.
  - 41497642958: BLOCK, $0.02.

- **GitHub Action runs on the demo pull requests (Nov 17),** after GitHub lifted the billing lock: each demo PR carries PR Guard's comment, with the same verdicts as the reports above. The first re-run caught routing changes that had turned BLOCKs into CAUTION; the fixes, and the answers that exposed them, are in the commits of Nov 17 and in [HOW-IT-WORKS.md](HOW-IT-WORKS.md#what-we-found-along-the-way).

  Purchase ledgers are attached to each run.
- **Vetting probes:** each miner's real answers are kept in [`test/fixtures/miner-responses/`](../test/fixtures/miner-responses/), each with its payment proof and receipt. The vetting history is in [MINERS.md](MINERS.md).

**Network findings and collaboration**
- **Routing gap:** routed `SECURITY_REVIEW_GENERAL` ignores the target. Reported with receipts: https://github.com/telegraphprotocol/bounties/issues/187
- **Counterproof:** its builder suggested his sanctions miner (#731002) for the address check in the showcase thread. It was wired in the same day, and his fix to the routed answer format was confirmed live.
- **Feedback on X:** a question about changes in one file affecting another led to the call-site context feature, shown in demo #7.

**Adoption:** independent users will be listed here, with links and dates, as they come. Everything above is our own testing.

### Known limitations

- **Testnet only.**
- **Repositories:** hosted scans cover public repositories only.
- **Routed security reviews:** `SECURITY_REVIEW_GENERAL` has no ranking yet (bounties#187), so those checks fall back to vetted miners.
- **Canonical asks:** limited to 2,000 characters per field, so larger diffs go to a vetted reviewer directly.
- **Ecosystems:** packages from npm, PyPI, Go and Cargo only.
- **This repository's own Actions:** paused by a GitHub account billing lock (open with GitHub Support). The demos show their results on the report pages.

### Disclosures

- **Own miner:** PR Guard Sentinel (#731001) is our own miner. PR Guard uses it only as a fallback (PyPI, Go and crates.io packages; code when Verity fails), and the report labels it.
- **Sponsored use:** the public page and the no-key Action are paid by our sponsor wallet. That is sponsored testnet use, not paying customers.
- **Outside code:** code written before Nov 1 is part of the repository's history; in-event evidence is dated Nov 1 or later.

### Showcase permission (to confirm)

- Public sharing of this text, screenshots, reports and the video: **yes** (proposed).
- Buyer introductions: **yes** (proposed).

---

## Entry 2: Evaluators: evaluation material for security intents

| | |
|---|---|
| Track | Evaluators |
| Contributor wallet | `0x83b5A31d89a976Ec607C3064078fd0f7EB34abcc` |
| Missions | 14 Web3 Native & DeFi (smart-contract audits); security tooling across missions (CVE lookups) |

### Contributions

1. **`SMART_CONTRACT_AUDIT_GENERAL`: 105 preference pairs**, built from SmartBugs Curated (real vulnerable contracts, labelled by hand, Apache 2.0).
   - **Accepted:** 103 admitted, 2 rejected as near-duplicates.
   - **Contributors:** went from 1 to 2. Five are needed before a judgment intent's questions are used.
   - **Method and checks:**
     - comments stripped so the dataset's labels can't leak;
     - answers generated deterministically from the labels;
     - cited lines verified against the code shown;
     - near-duplicates dropped;
     - length and verdict wording balanced so neither is a shortcut.
   - **Code and data:** [evaluation/smart-contract-audit/](../evaluation/smart-contract-audit/), reproducible from a pinned dataset commit and a file hash.
2. **`CVE_LOOKUP_CVSS`: two truth sources:** NVD (NIST) with an exact `intent_mapping` to its primary CVSS v3.1 base score, and CIRCL Vulnerability-Lookup.
   - **Accepted:** both admitted. The intent's contributors went from 7 to 8.
   - **Checks:** schema-checked, and the NVD path verified on four CVEs.
   - **Files:** [evaluation/cve-lookup-truth-sources/](../evaluation/cve-lookup-truth-sources/)

**Why these:** the smart-contract audit intent couldn't be ranked with a single contributor, so routed audits went to a miner that timed out. CVE lookups are scored only against truth sources.

**Conflict of interest:** PR Guard's own miner serves neither intent.

**Invitation:** we asked other builders in #hackathon (Nov 14) to add audit material so the intent reaches five contributors.

---

## Entry 3 (optional): Miners: PR Guard Sentinel

Only worth entering if independent apps start using it.

| | |
|---|---|
| Miner | PR Guard Sentinel, routing id **731001**, `SECURITY_REVIEW_GENERAL` |
| Registration | Ethereum Sepolia, registrationId **4857**, tx `0x845d43703f6b5d610f35600f05749d84c27c30369487dd253a07f0b0860bf2a4` |
| YAML | https://pr-guard-sentinel.pr-guard.workers.dev/miner.yaml (hash `0x9c079634…2bab`) |
| Code | [`miner/`](../miner/) |
| What it does | Deterministic rules (17, now including Solidity) for diffs and code, plus OSV-backed package lookups with CVSS and upgrade advice |

**Honest status:** it is used only by PR Guard (as a fallback), and its intent has no evaluator yet, so there is no ranking to compete in.

---

## Original H2 updates and activation (for the 20 growth points)

| Date | What | Link |
|---|---|---|
| Nov 13 | Update 1 on X: intro thread | https://x.com/gowda_anvi/status/2121162244851736805 |
| Nov 13 | Showcase thread in the Telegraph Discord | (link from the Discord thread) |
| Nov 13 | Routing gap reported | https://github.com/telegraphprotocol/bounties/issues/187 |
| Nov 14 | Update 2 on X: milestone, a routed purchase with a receipt | https://x.com/gowda_anvi/status/2121601194942713887 |
| Nov 14 | Milestone post in the showcase thread; sanctions miner wired in after Counterproof's suggestion | (link from the Discord thread) |
| Nov 14 | Reply on X to a technical question, with the feature built from it (demo #7) | (link to the reply) |
| Nov 14 | Call in #hackathon for audit evaluation material | (Discord) |
| Nov 20 | Update 3, community showcase | to do |
| ~Nov 27 | Update 4: results and lessons | to do |

Tutorial: [docs/HOW-IT-WORKS.md](HOW-IT-WORKS.md). Troubleshooting and costs: [README](../README.md).
