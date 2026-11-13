# PR Guard demo

`demo/app` is a tiny Express API with a payments module, and `demo/contracts` holds a small vault. Five open pull requests change them, one per outcome. Each has a live report from PR Guard's public page (scanned Nov 13, 2026, on Telegraph's testnet):

| Pull request | What it changes | Verdict | Report |
|---|---|---|---|
| [#1](https://github.com/anvithagowda098/pr-guard/pull/1) `demo/clean-change` | adds a parameterized search endpoint | 🟢 SAFE | [report](https://pr-guard-app.pr-guard.workers.dev/r/91f1fd167b70) |
| [#2](https://github.com/anvithagowda098/pr-guard/pull/2) `demo/vulnerable-dependency` | downgrades lodash to 4.17.15 | 🔴 BLOCK: known high-severity advisories for that exact version | [report](https://pr-guard-app.pr-guard.workers.dev/r/d6c6983b423b) |
| [#3](https://github.com/anvithagowda098/pr-guard/pull/3) `demo/leaked-key-and-injection` | hardcodes a (fake) AWS key, builds SQL from strings, `eval`s input | 🔴 BLOCK: committed key, plus injection the reviewer found and PR Guard's own rules confirm | [report](https://pr-guard-app.pr-guard.workers.dev/r/bc66dc5c844e) |
| [#4](https://github.com/anvithagowda098/pr-guard/pull/4) `demo/address-swap` | replaces the payout address, accepts USDT | 🟡 CAUTION: the payout address changed (the address-swap attack shape); each new address gets a paid GoPlus risk check | [report](https://pr-guard-app.pr-guard.workers.dev/r/b22eec6747c4) |
| [#5](https://github.com/anvithagowda098/pr-guard/pull/5) `demo/reentrant-vault` | adds a Solidity vault with a reentrant `withdraw` and an open `setOwner` | 🔴 BLOCK: the reviewer names both, and PR Guard's Solidity rules confirm them | [report](https://pr-guard-app.pr-guard.workers.dev/r/695b58066331) |

Each report lists every paid check, the miner that answered (routed by Telegraph, or a vetted fallback and why), what it cost, and a link to its receipt on the Telegraph node.

## Try it yourself (reviewers)

Two ways, neither needs a wallet:

1. **Any public pull request, in the browser.** Paste its link into https://pr-guard-app.pr-guard.workers.dev.
   - The same commit always opens the same saved report.
   - To see a fresh paid run, use a pull request nobody has scanned yet, or push a new commit to one.
2. **On your own repository.** Add the [one-file workflow](../examples/pr-guard.yml) to a public repository and open a pull request. PR Guard comments within about a minute. The checks run on your repository's GitHub Actions and are paid by PR Guard's sponsor wallet.

GitHub Actions in this repository are paused for now: a billing lock on the owner's GitHub account (GitHub Free, nothing billable) is with GitHub Support. The demo pull requests above therefore show their results on the report pages rather than as PR comments. Earlier PR comments from Nov 2 are still on the pull requests.

The AWS key in the demo is fake (it was never issued) and exists only to show detection.
