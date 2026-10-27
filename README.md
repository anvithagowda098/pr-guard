# PR Guard

A GitHub Action that buys security checks from Telegraph's miner network on every pull request and posts one SAFE / CAUTION / BLOCK comment with the evidence, the cost and the Telegraph receipts.

**Status:** build steps 1–2 (discovery and the first paid call). The normalizers wait until there are real miner responses to build them from.

## Requirements

- Node 20 or later
- Testnet only: Base Sepolia (`eip155:84532`), paying in USDC through x402
- Behind an HTTPS proxy on Node 22.21 or later, prefix commands with `NODE_USE_ENV_PROXY=1`. Node's built-in `fetch` ignores `HTTPS_PROXY` without it.

```sh
cd pr-guard
npm ci
npm test            # offline unit tests
```

## Step 1: discovery (free)

```sh
node scripts/discover.js                  # all PR Guard intents
node scripts/discover.js CVE_LOOKUP       # or just one
```

This writes the raw intent specs, the miner records and the dispatcher OpenAPI to `data/miners.json`. For each miner it prints its id, name, floor price, rank/score, endpoints and input schema. A miner listed on every queried intent gets a flag: that pattern usually means a relabelled proxy.

## Step 2: wallet and the first paid call

```sh
node scripts/wallet.js            # creates .env with a burner key, prints the address
# fund it: https://faucet.circle.com -> Base Sepolia -> USDC (no ETH needed)
node scripts/wallet.js balance
```

Pick a CVE_LOOKUP miner from the discovery table. Build its request from that miner's `endpoints` and `input_schema`, then probe it. A probe is unpaid: it returns the 402 price quote, or a 422 if the payload fails pre-validation, and costs nothing.

```sh
node scripts/first-call.js --miner <id> --endpoint <path> --payload '<json for lodash@4.17.15>'
```

Add `--pay` to buy the answer. The cap is $0.05 per call (`--max-usd` changes it), and any quote above the cap is refused before anything is signed.

```sh
node scripts/first-call.js --miner <id> --endpoint <path> --payload '<json>' --pay
```

The auto-routed endpoint takes the body verbatim, because the docs show two different body shapes:

```sh
node scripts/first-call.js --body '{"intent":"CVE_LOOKUP","params":{...}}'
```

The script prints the raw body, all response headers, the decoded `PAYMENT-RESPONSE` and `X-TELEGRAPH-RECEIPT`, and the `/engine/v1/signal/<hash>` lookup. It saves everything to `test/fixtures/miner-responses/<INTENT>/`, and those captures are what the normalizers will be written from.
