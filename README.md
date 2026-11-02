# PR Guard

**Security review for pull requests, bought from an open network of specialist miners.**

PR Guard reads a pull request and buys independent security checks from miners on [Telegraph](https://telegraphprotocol.com). It then posts one comment with the verdict (🟢 SAFE, 🟡 CAUTION or 🔴 BLOCK), the evidence, what the checks cost, and a Telegraph receipt for every paid check.

**Try it now:** paste any public pull request link into **https://pr-guard-app.pr-guard.workers.dev**. You don't need an account, a wallet or a key.

> Telegraph runs on a testnet. Checks are paid in test USDC on Ethereum Sepolia, which is free and has no real value.

## What it checks

| Check | How | Cost |
|---|---|---|
| **New or upgraded dependencies** (npm, PyPI, Go, Cargo) | A miner looks up each package version for known vulnerabilities. A second miner confirms any high or critical result. | $0.01 per package, plus $0.01 to confirm |
| **Code changes** | A miner reviews the redacted diff for vulnerabilities such as injection and `eval` on input. A second reviewer confirms any high or critical finding. | $0.01 per chunk of up to 12,000 characters |
| **Committed secrets and keys** | Local scan of added lines | free |
| **New install scripts** (`preinstall`, `install`, `postinstall`, `prepare` in `package.json`) | Local check | free |

## Get started

There are three ways to use it, and only the last one needs a wallet.

### 1. In the browser

Open **https://pr-guard-app.pr-guard.workers.dev** and paste a pull request link from any public repository.
- **Cost:** none to you. A sponsor wallet pays for the checks, up to $0.10 per scan.
- **Limits:** 5 scans per visitor per day.
- **Reports:** each one gets a permanent link.

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
| `node-url` | `https://devnode.telegraphprotocol.com` | Telegraph node. |
| `miners-config` | bundled | Path to a miners allowlist overriding [`config/miners.json`](config/miners.json). |

**Outputs:**
- `verdict`
- `cost_usd`
- `signal_hashes`: one per paid call
- `ledger_path`

## How the verdict is decided

- **BLOCK:** a confirmed high or critical finding. Confirmed means two miners agree, or a deterministic local check found it, such as a committed key. **One miner on its own can never block a pull request.**
- **CAUTION:** any of the following:
  - a medium finding;
  - an unconfirmed high finding;
  - miners that disagree;
  - a check that failed, or an answer that couldn't be read;
  - a dependency or diff check skipped because the budget or the time ran out.
- **SAFE:** none of the above.

## Miners

| Miner | Operator | Used for |
|---|---|---|
| #77010 deps.dev Package Review | independent | npm packages, with severity and CVSS |
| #190048 Secrev Depsdev | independent | second opinion on advisories, every ecosystem |
| #5530 Telegraph Verity | independent | code review of each diff chunk |
| #731001 PR Guard Sentinel | **this project** (disclosed) | PyPI, Go and crates.io packages; confirms code findings |

Every miner was tested with paid calls before it was added, and its raw answers are kept as test fixtures. [docs/MINERS.md](docs/MINERS.md) covers how each one was chosen and how to vet and add another. PR Guard Sentinel is a rule-based miner with no AI model and no API key; its code is in [`miner/`](miner/).

## Spending and privacy

- **Spending:**
  - **Before a call:** each price quote is checked against the per-call cap and reserved against the run's budget before it's signed. Calls running in parallel therefore can't overspend together.
  - **After a call:** any call that returns a settled payment counts as spent.
  - **When the budget runs out:** the lowest-value checks are skipped first, so the verdict says CAUTION rather than SAFE.
- **Privacy:**
  - **What miners see:** diffs are redacted before they go to a miner. Cloud keys, tokens, private keys, URL passwords and labelled credentials are removed.
  - **Never sent:** `.env`, `*.pem`, `id_rsa` and similar files, even redacted.
  - **Skipped:** lockfiles, vendored and minified code, binaries and documentation.

## Development

You need Node 20 or later.

```sh
npm ci
npm test             # 109 tests, all offline
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

## Known limitations

- **Testnet only:** Telegraph's mainnet isn't live yet.
- **Patch verification and URL safety are off:** no miner on Telegraph does them reliably yet (see [docs/MINERS.md](docs/MINERS.md)).
- **Hosted scans are smaller:** at most 8 packages and 3 diff chunks per pull request, and the checks run one after another.
- **zod advisory:** `npm audit` reports a high-severity advisory in zod 3, which comes in through `@x402/core`; x402 2.28 has no release that fixes it. PR Guard uses zod only to parse small payment headers.

---

Built for the Telegraph Hackathon, Season II. Apps & Agents track: PR Guard. Miners track: PR Guard Sentinel.
