# Miners

Which Telegraph miners PR Guard buys from, how they were chosen, and how to vet and add another one.

## In use

Every check is first bought through Telegraph's routing: a canonical ask by intent (`CODE_REVIEW_GENERAL` for code, `SECURITY_REVIEW_GENERAL` for packages), and the network picks the miner. The miners below are the vetted fallbacks. One of them is called directly only when the routed answer is unusable, and the next only if that call fails.

| Check | Fallback miner | Operator | Role |
|---|---|---|---|
| deps | #77010 deps.dev Package Review | independent | npm packages: advisories with GitHub's severity and CVSS |
| deps | #731001 PR Guard Sentinel | **this project** | PyPI, Go and crates.io packages: OSV advisories with CVSS |
| deps | #190048 Secrev Depsdev | independent | any ecosystem, advisory ids only: unrated, so it can only give CAUTION |
| diff | #5530 Telegraph Verity | independent | code, when the routed review is unusable or a part of the diff is over 2,000 characters |
| diff | #731001 PR Guard Sentinel | **this project** | code, only if Verity fails |
| diff | #1900999007 CodeWire Smart Contract Audit | independent | Solidity: first fallback for diffs that touch `.sol` files |
| addresses | #200001 GoPlus Security | independent | risk flags for each new on-chain address (honeypot, owner powers, verified source, proxy, taxes) |

The list lives in `config/miners.json`, keyed by check, best first. No miner is asked to second-guess another. A BLOCK needs deterministic evidence: registry data about the exact package and version, PR Guard's local rules (the same rule set as Sentinel, run inside PR Guard for free) finding the same issue in the diff, or a local check such as a committed key.

PR Guard Sentinel is our own miner (`miner/`). Its use is disclosed wherever it appears, and the case for it rests on independent tests, not on PR Guard's own purchases.

## Vetting history

Every miner was tested with paid calls before it was added. The raw answers are kept as test fixtures in `test/fixtures/miner-responses/`, and every normalizer is tested against them. Newest first.

### Nov 13, 2026: smart contracts and addresses (mission 14)

- **`SMART_CONTRACT_AUDIT_GENERAL` has no input schema**, so only plain-language asks reach it. Two routed asks (a Solidity diff, an address) both went to miner 20260828 (PREFLIGHT), which answered "unavailable": its language model timed out.
- **Routed `CODE_REVIEW_GENERAL` handles Solidity.** Miner 302 named the reentrancy and the open `setOwner` in the demo vault. Once it called them "low" with an Approve verdict, and once it answered in prose the node couldn't read. PR Guard's own Solidity rules settle the first case, and the fallback the second.
- **CodeWire Smart Contract Audit (#1900999007)**, `GET /contract-audit {contract}`: on the vulnerable vault it found reentrancy (critical) and missing access control (high); on a fixed vault, only low issues. Its answers are structured prose ("Finding 1: …, affects …, severity …").
- **GoPlus Security (#200001)**, `GET /token-security {chain_id, contract_addresses}`: GoPlus's full token risk profile. USDT is on its trusted list, with known admin powers (owner can change balances, pausable, blacklist).
- **Sourcify Verified Contracts (#200002)**, `GET /contract`: unusable. It passes every parameter through as a query string, and Sourcify rejects them (`chainId`, then `chain`). Both calls were credited back to escrow.

### Nov 13, 2026: routing first

Telegraph's team advised apps to buy through routing rather than calling several miners to cross-check each other. Canonical asks, paid, on Ethereum Sepolia:

- **`CODE_REVIEW_GENERAL` with a 6-line diff** (SQL string concatenation, `eval` on input): routed to miner 302 (ChainSight), returned in the intent's format, and found both bugs. Fixture: `ROUTED/code-review-sqli-eval-diff-302-intent.json`.
- **`SECURITY_REVIEW_GENERAL`**, once with `npm package lodash version 4.17.15` and once with the same diff: both routed to miner 77003 (GitHub Security Advisories). It returned the 100 newest advisories, none about the target, in its raw format. The intent has 32 miners and no evaluator, so there is no ranking to route by. Fixtures: `ROUTED/security-review-*-77003-off-target.json`. Reported to Telegraph.
- **Canonical params:** each string is limited to 2,000 characters (refused with `invalid_params` above that, before payment). Routing sometimes answers 503 "could not route this question now".
- **Direct ask to Verity (#5530)** with the same diff: both bugs at the right lines. Fixture: `SECURITY_REVIEW_GENERAL/5530-review-sqli-eval-diff-200-paid.json`.

### Nov 2, 2026: new code reviewers

- **Verity (#5530):** still takes the old `SECURITY_REVIEW` name, with code under `input.code`. It found both planted bugs (SQL injection, `eval`) and stayed quiet on a parameterized query.
- **Sentinel (#731001):** went live on Telegraph's node and found the same two bugs at the same file:line. It also rates PyPI, Go and crates.io packages, which no other dependency miner did.
- **TxLens (#9002):** still fails ("perplexity key has no credit left").
- **Failed calls:** on the new network they are credited back to the caller's Telegraph escrow balance ("nothing was billed").

### Oct 31, 2026: re-check after Telegraph's move to Ethereum Sepolia

- Both dependency miners carried over with identical answers (`test/fixtures/miner-responses/SECURITY_REVIEW_GENERAL/`).
- ChainSight did not carry over, and its id (302) now belongs to another miner.
- Intent names are now family children, e.g. `SECURITY_REVIEW_GENERAL`.

### Oct 27, 2026: first vetting (Base Sepolia)

- **Dependencies:** two miners, both under SECURITY_REVIEW. No CVE_LOOKUP miner accepts a package and version; they only take a CVE id.
  - **deps.dev Package Review** (#77010) is asked first, for npm. It returns each advisory with GitHub's severity rating and a CVSS score.
  - **Secrev Depsdev** (#190048) covers every ecosystem, but returns advisory ids only. It serves as the second opinion: listing the same ids confirms a high finding.
  - Both are proxies over Google's deps.dev, so they share one upstream. Their agreement shows the miner layer is honest, not that the data was checked twice independently.
- **Code-diff review:** ChainSight (#302, `POST /secreview`, takes a plain-language `query`).
  - It got 4 of 4 test cases right: SQL injection, `eval` on user input and shell injection flagged; a parameterized query called secure.
  - Its answers were free text and sometimes cut off mid-sentence.
  - TxLens (#9002) also takes code, but its call failed because its upstream AI account had no credit, and it was still charged.
- **URL safety:** URL Sentinel (#5001) and ProofGate (#7402) both rated Google's standard phishing test page safe. ProofGate reported that it hadn't queried any threat feed. URL checks stay off until a miner gets this right.
- **Unknown packages:** both deps.dev miners answer HTTP 500 with "upstream error 404". PR Guard stops at the first such miss instead of paying the next miner for the same answer.

## Vetting and adding a miner

You need Node 20 or later. Behind an HTTPS proxy (Node 22.21+), prefix network commands with `NODE_USE_ENV_PROXY=1`.

### Step 1: discovery (free)

```sh
node scripts/discover.js                  # all PR Guard intents
node scripts/discover.js CVE_LOOKUP_CVSS  # or just one
```

This saves the raw intent specs and miner records to `data/miners.json` and prints, per miner: id, floor price, rank or score, endpoints and input schema. A miner listed on every intent gets a flag, because that usually means a relabelled proxy.

### Step 2: wallet and the first paid call

```sh
node scripts/wallet.js            # creates .env with a burner key and prints its address
# fund it: a little Sepolia ETH from a faucet (e.g. Coinbase's CDP faucet, network "Ethereum Sepolia"),
# then mint free test USDC:  node scripts/fund-testnet.js mint 20
node scripts/wallet.js balance
```

Probes are unpaid: they return the price quote (402), or 422 if the payload is wrong, at no cost. Build the payload from the miner's record.

```sh
node scripts/first-call.js --miner <id> --endpoint <path> --payload '<json for lodash@4.17.15>'
```

Add `--pay` to buy the answer. For the auto-routed endpoint, pass the whole body with `--body '<json>'` instead.

The script prints the raw body, all response headers, the decoded payment proof and receipt, and the signal lookup. Each response is saved under `test/fixtures/miner-responses/`.

### Step 3: vet miners, then fill the config

`config/miners.json` lists vetted miners per **check**, best first. It's keyed by check rather than intent, because two checks can share an intent but need different miners. An entry looks like this:

```json
{ "minerId": "77010", "name": "…", "intent": "SECURITY_REVIEW_GENERAL", "method": "GET", "endpoint": "/query",
  "payload": { "pkg": "{{name}}", "ver": "{{version}}" }, "normalizer": "depsdev-version", "ecosystems": ["npm"] }
```

These variables are available in payloads:

| Check | Variables |
|---|---|
| deps | `ecosystem`, `name`, `version`, `from`, `spec`, `depsdev_system` |
| diff | `diff`, `files`, `chunk_index`, `chunk_count` |
| patch | `title`, `body`, `diff`, `files` |
| urls | `url`, `file`, `line` |

- A string that is exactly `"{{var}}"` is replaced by the raw value, so an array stays an array.
- Each normalizer lives in `src/normalize.js` and is tested against that miner's captured responses (`test/normalize.test.js`).
- A normalizer rejects any answer that is about a different package or version than the one asked.
