# PR Guard

**Security review for pull requests, bought from an open network of specialist miners.**

PR Guard reads a pull request and buys independent security checks from miners on [Telegraph](https://telegraphprotocol.com). It then posts one comment with the verdict (🟢 SAFE, 🟡 CAUTION or 🔴 BLOCK), the evidence, what the checks cost, and a Telegraph receipt for every paid check.

**Try it now:** paste any public pull request link into **https://pr-guard-app.pr-guard.workers.dev**. You don't need an account, a wallet or a key.

> Telegraph runs on a testnet. Checks are paid in test USDC on Ethereum Sepolia, which is free and has no real value.

## What it checks

| Check | How | Cost |
|---|---|---|
| **New or upgraded dependencies** (npm, PyPI, Go, Cargo) | Each package version is checked for known vulnerabilities through Telegraph (`SECURITY_REVIEW_GENERAL`). | $0.01 per package |
| **Code changes** | The redacted diff is reviewed through Telegraph (`CODE_REVIEW_GENERAL`) for injection, `eval` on input and similar bugs. PR Guard's own rules check the same diff. | $0.01 per part of the diff |
| **Committed secrets and keys** | Local scan of added lines | free |
| **New install scripts** (`preinstall`, `install`, `postinstall`, `prepare` in `package.json`) | Local check | free |

## Get started

There are three ways to use it, and only the last one needs a wallet.

### 1. In the browser

Open **https://pr-guard-app.pr-guard.workers.dev** and paste a pull request link from any public repository.
- **Cost:** none to you. A sponsor wallet pays for the checks, up to $0.10 per scan.
- **Limits:** 5 scans per visitor per day.
- **Reports:** each one gets a permanent link.
- **Examples:** the three demo pull requests (one SAFE, two BLOCK) and their reports are in [demo/README.md](demo/README.md).

### 2. On your repository, with no setup (public repositories)

Add this file as `.github/workflows/pr-guard.yml` (also in [`examples/pr-guard.yml`](examples/pr-guard.yml)):

```yaml
name: PR Guard
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  guard:
    runs-on: ubuntu-latest
    timeout-minutes: 6
    steps:
      - uses: anvithagowda098/pr-guard@main
```

Every pull request then gets a PR Guard comment. How it works without a key:
- **What is sent:** the Action passes only the PR link to PR Guard's hosted service.
- **Who pays:** the hosted service buys the checks from the sponsor wallet, up to $0.10 per scan and 20 scans per repository per day.
- **Private repositories** are never sent anywhere. They get a "skipped" note instead.
- **Fork pull requests:** GitHub gives their workflows a read-only token, so the result appears in the run's job summary instead of a comment.

### 3. With your own wallet (private repositories, your own budget)

The Action pays each miner itself, from a burner wallet that you fund with free test USDC. Use [`examples/pr-guard-wallet.yml`](examples/pr-guard-wallet.yml) and add a `TELEGRAPH_PRIVATE_KEY` repository secret.

1. **Create a burner:** create a new wallet that is used only for this (`node scripts/wallet.js` makes one). Never use a key that holds real funds.
2. **Fund it:** get a little Sepolia ETH from a faucet, then mint test USDC with `node scripts/fund-testnet.js mint 20`.
3. **Store the key:** save it as the `TELEGRAPH_PRIVATE_KEY` repository secret. The `0x` prefix is optional.

The key stays in GitHub's secret store. The Action uses it only to sign each payment, and every payment is capped by `max-usd-per-call` and `max-usd-per-pr`. Each run uploads a purchase ledger (`pr-guard-ledger.jsonl`) as an artifact.

### Inputs

| Input | Default | |
|---|---|---|
| `telegraph-private-key` | none | A burner key with test USDC. Leave it out for free hosted scans. |
| `fail-on` | `block` | Fail the check on `block`, on `caution` (CAUTION or BLOCK), or `never`. |
| `max-usd-per-pr` | `0.10` | Budget for one run (own wallet). |
| `max-usd-per-call` | `0.05` | Quotes above this are refused before anything is signed (own wallet). |
| `checks` | `deps,diff` | Paid checks to run (own wallet). The local checks always run. |
| `service-url` | the hosted service | Used when no key is set. |
| `routing` | `auto` | `auto` buys through Telegraph's routing first; `off` asks the vetted miners directly. |
| `node-url` | `https://devnode.telegraphprotocol.com` | Telegraph node. |
| `miners-config` | bundled | Path to a miners allowlist overriding [`config/miners.json`](config/miners.json). |

**Outputs:**
- `verdict`
- `cost_usd`
- `signal_hashes`: one per paid call
- `ledger_path`

## How the verdict is decided

- **BLOCK:** a confirmed high or critical finding. **A miner's opinion on its own can never block a pull request.** Confirmed means deterministic evidence backs it:
  - **Dependencies:** registry data (GitHub's advisories through deps.dev, or OSV) about this exact package and version.
  - **Code:** PR Guard's own rules find the same issue in the same diff.
  - **Local checks:** for example, a committed key.
- **CAUTION:** any of the following:
  - a medium finding;
  - an unconfirmed high finding;
  - an issue PR Guard's rules found that the reviewer didn't;
  - a check that failed, or an answer that couldn't be read;
  - a dependency or diff check skipped because the budget or the time ran out.
- **SAFE:** none of the above.

## How checks are bought

PR Guard asks Telegraph for each check by intent and lets the network choose the miner. It doesn't hard-code a provider.

1. **Routed first.** Each check is a canonical ask: `{"intent": "CODE_REVIEW_GENERAL", "params": {"code": …}}` for each part of the diff, and `{"intent": "SECURITY_REVIEW_GENERAL", "params": {"target": "npm package lodash version 4.17.15"}}` for each package. Telegraph routes it to a miner, and returns the answer in the intent's standard format.
2. **Checked before it's trusted.** PR Guard uses a routed answer only if it's in the intent's format, or comes from a vetted miner and is about the exact package asked.
3. **One vetted fallback.** If the routed answer can't be used, PR Guard asks one vetted miner directly and says why in the report. It then skips routing for that intent for the rest of the run; the hosted service skips it for 6 hours. No miner is ever asked just to second-guess another.

Each row of the PR comment shows which miner answered, and whether Telegraph routed it or it was a fallback.

**What routing does today (Nov 13, 2026):**
- **Code reviews** route well. Miner 302 answered in the standard format and found both planted bugs.
- **Package lookups** route to miner 77003. It ignores the request and returns the 100 newest advisories, so PR Guard falls back. The intent has no evaluator yet, so there's no ranking to route by. This is reported to Telegraph with receipts.
- **Size limit:** canonical asks take at most 2,000 characters, so a larger part of a diff goes to the vetted reviewer directly.

| Vetted fallback | Operator | Used for |
|---|---|---|
| #77010 deps.dev Package Review | independent | npm packages, with severity and CVSS |
| #731001 PR Guard Sentinel | **this project** (disclosed) | PyPI, Go and crates.io packages |
| #190048 Secrev Depsdev | independent | any ecosystem, advisory ids only (never blocks) |
| #5530 Telegraph Verity | independent | code, when the routed review is unusable or the diff part is too big |

Every miner was tested with paid calls before it was added, and its raw answers are kept as test fixtures. [docs/MINERS.md](docs/MINERS.md) covers how each one was chosen and how to vet and add another. PR Guard Sentinel is a rule-based miner with no AI model and no API key; its code is in [`miner/`](miner/).

## Spending and privacy

- **Spending:**
  - **Before a call:** each price quote is checked against the per-call cap and reserved against the run's budget before it's signed. Calls running in parallel therefore can't overspend together.
  - **After a call:** any call that returns a settled payment counts as spent, including a routed answer that couldn't be used. That costs at most $0.01 per intent per run, since routing is then skipped for that intent.
  - **When the budget runs out:** the lowest-value checks are skipped first, so the verdict says CAUTION rather than SAFE.
- **Privacy:**
  - **What miners see:** diffs are redacted before they go to a miner. Cloud keys, tokens, private keys, URL passwords and labelled credentials are removed.
  - **Never sent:** `.env`, `*.pem`, `id_rsa` and similar files, even redacted.
  - **Skipped:** lockfiles, vendored and minified code, binaries and documentation.

## Development

You need Node 20 or later.

```sh
npm ci
npm test             # 121 tests, all offline
npm run build        # bundles dist/index.js; commit it, the Action runs from it
npm run deploy:web   # the hosted page and API (Cloudflare Workers)
npm run deploy:miner # PR Guard Sentinel (Cloudflare Workers)
```

| Folder | What it is |
|---|---|
| `src/` | The Action and the shared engine: plan the scan, buy checks over x402, normalize answers, decide, report |
| `web/` | The hosted page and API: one paid check per request, results in Workers KV |
| `miner/` | PR Guard Sentinel, the miner |
| `config/` | The vetted miner list |
| `scripts/` | Discovery, wallet, funding and first-call tools |
| `test/` | Unit and end-to-end tests. They replay real captured miner answers against a fake payment-gated node |
| `demo/` | A small app and three demo pull requests (SAFE, dependency BLOCK, code BLOCK) |

## Troubleshooting

| What you see | Why | What to do |
|---|---|---|
| ⚪ SKIPPED: "this repository is private" | Free hosted scans read the PR through GitHub's public API, so they cover public repositories only. | Use your own wallet: [option 3](#3-with-your-own-wallet-private-repositories-your-own-budget). |
| ⚪ SKIPPED: "used its 20 free hosted scans for today" | Each repository gets 20 hosted scans a day. They reset at 00:00 UTC. | Wait for the reset, or use your own wallet. |
| ⚪ SKIPPED: "Today's free scans are used up" | The sponsor wallet's daily cap across all users has been reached. | Try again after 00:00 UTC, or use your own wallet. |
| No comment on a pull request from a fork | GitHub gives fork workflows a read-only token. | The result is in the run's job summary. |
| "telegraph-private-key must be a private key" | The secret isn't a 64-character hex key. | Paste the key itself, with or without `0x`, not an address or a seed phrase. |
| ⚠️ failed (`payment_required`) or (`payment_failed`) | The wallet can't pay: usually no test USDC left. | Run `node scripts/wallet.js balance`, then `node scripts/fund-testnet.js mint 20`. |
| ⏭️ skipped (`budget exhausted`) | The run hit `max-usd-per-pr`. | Raise `max-usd-per-pr`. The verdict says CAUTION rather than SAFE when a required check is skipped. |
| ⚠️ failed (`timeout`) or (`network_error`) | A miner or the Telegraph node didn't answer in time. Failed calls are credited back on Telegraph's current network. | Re-run the job. A failed check gives CAUTION, never SAFE. |

Still stuck? [Open an issue](https://github.com/anvithagowda098/pr-guard/issues/new) with the link to your workflow run. The link is all we need: never paste a private key into an issue.

## Contributing

You can try it on your own repository, report a wrong verdict, or add a miner. [CONTRIBUTING.md](CONTRIBUTING.md) lists good first contributions.

## Known limitations

- **Testnet only:** Telegraph's mainnet isn't live yet.
- **Patch verification and URL safety are off:** no miner on Telegraph does them reliably yet (see [docs/MINERS.md](docs/MINERS.md)).
- **Routing isn't ranked yet for package lookups:** see [How checks are bought](#how-checks-are-bought). PR Guard handles it with a fallback, and starts using routing again as soon as the answers are usable.
- **Hosted scans are smaller:** at most 8 packages and 3 diff chunks per pull request, and the checks run one after another.
- **zod advisory:** `npm audit` reports a high-severity advisory in zod 3, which comes in through `@x402/core`; x402 2.28 has no release that fixes it. PR Guard uses zod only to parse small payment headers.

---

Built for the Telegraph Hackathon, Season II. Apps & Agents track: PR Guard. Miners track: PR Guard Sentinel.
