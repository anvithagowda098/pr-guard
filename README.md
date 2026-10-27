# PR Guard

A GitHub Action that buys security checks from Telegraph's miner network on every pull request. It posts one comment with a verdict (🟢 SAFE / 🟡 CAUTION / 🔴 BLOCK), the evidence, what the checks cost, and the Telegraph receipts.

Payments use **testnet USDC on Base Sepolia**. That money is free from a faucet and worth $0. The wallet is a burner and never holds real funds.

## Status

| Part | State |
|---|---|
| Telegraph client: discovery, paid asks, receipts, per-call cap, per-PR budget | done, tested offline |
| Reading the PR: npm (package.json and lockfile), PyPI (requirements, pyproject), Go (go.mod), Cargo (Cargo.toml); added URLs; install scripts; diff chunks | done, tested |
| Secret redaction before anything leaves the runner; local secret scan | done, tested |
| Verdict policy, PR comment, purchase ledger, the Action itself | done; end-to-end test against a fake GitHub API and node |
| **Which miners to use, and how to read their answers** | **waiting on real miner responses** |

Until `config/miners.json` lists vetted miners and `src/normalize.js` can read their answers, paid checks are skipped or come back "unknown". Both of those give CAUTION, never a guessed SAFE. Local checks already work: a committed AWS key gives BLOCK, and a new `postinstall` script gives CAUTION.

## How the verdict is decided

- **BLOCK:** a confirmed high or critical finding. Confirmed means two miners agree, or a local check (such as a committed key) found it. One miner on its own can't block a PR.
- **CAUTION:** any of the following:
  - a medium finding;
  - an unconfirmed high finding;
  - miners that disagree;
  - a check that failed;
  - an answer that couldn't be read;
  - a dependency or diff check skipped because the budget or time ran out.
- **SAFE:** none of the above.

## Spending limits

- `max-usd-per-call` (default $0.05): any quote above this is refused before anything is signed.
- `max-usd-per-pr` (default $0.10): each quote is reserved against this budget before it's signed, so calls running in parallel can't overspend it together.
- A call is counted as spent whenever the node returns a settled payment, even if the miner then fails. Telegraph's docs say failed calls are free, but a TxLens 500 was charged on 2026-10-27. Calls with no payment proof release their reservation.
- When the budget runs out, the lowest-value checks are the ones skipped. Priority order: direct dependencies, then the diff, then transitive dependencies, then the PR description, then URLs.

## Privacy

- Diffs are redacted before they go to a miner: cloud keys, tokens, private keys, URL passwords and labelled credentials.
- `.env`, `*.pem`, `id_rsa` and similar files are never sent, even redacted.
- Lockfiles, vendored and minified code, and binaries are skipped.

## Use it

Copy `examples/pr-guard.yml` into `.github/workflows/`. Then add a `TELEGRAPH_PRIVATE_KEY` repository secret holding a funded burner key (see step 2 below).

- **Fork PRs** don't receive secrets, so they get a "skipped" note instead of a check.
- **Ledger:** every purchase is written to `pr-guard-ledger.jsonl`, which is uploaded as a workflow artifact.

## Development

You need Node 20 or later. Behind an HTTPS proxy (Node 22.21+), prefix network commands with `NODE_USE_ENV_PROXY=1`.

```sh
cd pr-guard
npm ci
npm test         # 49 tests, no network (the end-to-end test uses loopback only)
npm run build    # bundles dist/index.js; commit it, since the Action runs from it
```

### Step 1: discovery (free)

```sh
node scripts/discover.js                  # all PR Guard intents
node scripts/discover.js CVE_LOOKUP       # or just one
```

This saves the raw intent specs and miner records to `data/miners.json` and prints, per miner: id, floor price, rank or score, endpoints and input schema. A miner listed on every intent gets a flag, because that usually means a relabelled proxy.

### Step 2: wallet and the first paid call

```sh
node scripts/wallet.js            # creates .env with a burner key and prints its address
# fund it: https://faucet.circle.com -> Base Sepolia -> USDC (no ETH needed)
node scripts/wallet.js balance
```

Probes are unpaid: they return the price quote (402), or 422 if the payload is wrong, at no cost. Build the payload from the miner's record.

```sh
node scripts/first-call.js --miner <id> --endpoint <path> --payload '<json for lodash@4.17.15>'
```

Add `--pay` to buy the answer. For the auto-routed endpoint, pass the whole body with `--body '<json>'` instead.

The script prints the raw body, all response headers, the decoded payment proof and receipt, and the signal lookup. Each response is saved under `test/fixtures/miner-responses/`.

### Step 3: vet miners, then fill the config

Add miners that give sensible answers to `config/miners.json`, best first. Each entry looks like this:

```json
{ "minerId": 123, "name": "…", "method": "POST", "endpoint": "/path", "payload": { "pkg": "{{name}}", "v": "{{version}}" }, "normalizer": "…" }
```

These variables are available in payloads:

| Check | Variables |
|---|---|
| deps | `ecosystem`, `name`, `version`, `from`, `spec` |
| diff | `diff`, `files`, `chunk_index`, `chunk_count` |
| patch | `title`, `body`, `diff`, `files` |
| urls | `url`, `file`, `line` |

A string that is exactly `"{{var}}"` is replaced by the raw value, so an array stays an array. Each normalizer goes in `src/normalize.js`, written from that miner's captured responses.

## Known limitations

- `npm audit` reports a high-severity advisory in zod 3, which comes in through `@x402/core`. x402 2.28 has no release that fixes it. PR Guard only uses zod to parse small payment headers.
- Testnet only.
