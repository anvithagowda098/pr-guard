# PR Guard demo

`demo/app` is a tiny Express API with a payments module, and `demo/contracts` holds a small vault. Seven open pull requests change them, one per outcome. Each has a live report from PR Guard's public page (re-scanned Nov 17, 2026, on Telegraph's testnet, after routing had moved to different miners; the Nov 13 reports are listed in [docs/SUBMISSION.md](../docs/SUBMISSION.md)):

| Pull request | What it changes | Verdict | Report |
|---|---|---|---|
| [#1](https://github.com/anvithagowda098/pr-guard/pull/1) `demo/clean-change` | adds a parameterized search endpoint | 🟢 SAFE | [report](https://pr-guard-app.pr-guard.workers.dev/r/8fee1e820713) |
| [#2](https://github.com/anvithagowda098/pr-guard/pull/2) `demo/vulnerable-dependency` | downgrades lodash to 4.17.15 | 🔴 BLOCK: known high-severity advisories for that exact version | [report](https://pr-guard-app.pr-guard.workers.dev/r/4969f5b82cd2) |
| [#3](https://github.com/anvithagowda098/pr-guard/pull/3) `demo/leaked-key-and-injection` | hardcodes a (fake) AWS key, builds SQL from strings, `eval`s input | 🔴 BLOCK: committed key, plus injection the reviewer found and PR Guard's own rules confirm | [report](https://pr-guard-app.pr-guard.workers.dev/r/22f928ab84bd) |
| [#4](https://github.com/anvithagowda098/pr-guard/pull/4) `demo/address-swap` | replaces the payout address, accepts USDT | 🟡 CAUTION: the payout address changed (the address-swap attack shape); each new address gets a paid GoPlus risk check | [report](https://pr-guard-app.pr-guard.workers.dev/r/9b631798ba2b) |
| [#5](https://github.com/anvithagowda098/pr-guard/pull/5) `demo/reentrant-vault` | adds a Solidity vault with a reentrant `withdraw` and an open `setOwner` | 🔴 BLOCK: the reviewer names both, and PR Guard's Solidity rules confirm them | [report](https://pr-guard-app.pr-guard.workers.dev/r/6d50f28e950d) |
| [#6](https://github.com/anvithagowda098/pr-guard/pull/6) `demo/sanctioned-payout` | points payouts at an address on the US OFAC SDN list | 🔴 BLOCK: the address is on the US OFAC SDN list (LAZARUS GROUP); the routed sanctions screen reports the match and PR Guard's OFAC snapshot confirms it | [report](https://pr-guard-app.pr-guard.workers.dev/r/f0d17cbef465) |
| [#7](https://github.com/anvithagowda098/pr-guard/pull/7) `demo/loosened-validator` | stops `sanitizeId` stripping non-digits; only `validate.js` changes | 🟡 CAUTION: PR Guard sends the reviewer the call sites in `server.js`, where the id is concatenated into SQL. Without that context the same PR [came back SAFE](https://pr-guard-app.pr-guard.workers.dev/r/1895dcdb8382) | [report](https://pr-guard-app.pr-guard.workers.dev/r/d228be4ce003) |

Each report lists every paid check, the miner that answered (routed by Telegraph, or a vetted fallback and why), what it cost, and a link to its receipt on the Telegraph node.

## Try it yourself (reviewers)

Two ways, neither needs a wallet:

1. **Any public pull request, in the browser.** Paste its link into https://pr-guard-app.pr-guard.workers.dev.
   - The same commit always opens the same saved report.
   - To see a fresh paid run, use a pull request nobody has scanned yet, or push a new commit to one.
2. **On your own repository.** Add the [one-file workflow](../examples/pr-guard.yml) to a public repository and open a pull request. PR Guard comments within about a minute. The checks run on your repository's GitHub Actions and are paid by PR Guard's sponsor wallet.

Each pull request also carries PR Guard's comment from the GitHub Action, last re-run on Nov 17 (Actions were paused Nov 3–16 by a GitHub billing lock, since lifted by GitHub Support). That re-run found routing had moved to different miners since Nov 13, and caught three ways their answers could be misread; see [What we found along the way](../docs/HOW-IT-WORKS.md#what-we-found-along-the-way).

The AWS key in the demo is fake (it was never issued) and exists only to show detection.
