# PR Guard Sentinel (miner)

A Telegraph miner for `SECURITY_REVIEW`. It's a Cloudflare Worker with two endpoints:

| Endpoint | Does |
|---|---|
| `POST /review` `{query \| code \| diff}` | Deterministic rule scan, plus an OSV lookup for any `package@version` named |
| `POST /package` `{ecosystem, name, version}` | Known vulnerabilities from OSV, with severity, CVSS and fixed versions |
| `GET /health` | Liveness check |

How it works:
- There's no model and no API key: the same input always gets the same answer.
- Every answer starts with `Verdict: secure|vulnerable|needs review.` That sentence is what Telegraph reads as the label.
- Secrets found in code are reported by type and line. Their values are never echoed back.

## Test

```sh
npm test    # test/miner.test.js covers rules, CVSS, OSV parsing and the HTTP contract
```

## Deploy (Cloudflare Workers, free plan)

The environment needs `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.

```sh
npx wrangler@<pinned> deploy -c miner/wrangler.toml
curl https://pr-guard-sentinel.pr-guard.workers.dev/health
```

## Register on Telegraph

1. **Check the URL:** `base_url` in `miner.yaml` must match the deployed Worker (`https://pr-guard-sentinel.pr-guard.workers.dev`).
2. **Validate:** paste `miner.yaml` into the console at https://integrate.telegraphprotocol.com, which checks it against the live endpoints. The documented `POST /api/validate` answered 404 on 2026-10-27.
3. **Register:** with the miner wallet, at https://integrate.telegraphprotocol.com. It pins the YAML and sends `registerMiner`. Registration costs only Base Sepolia gas; there's no stake.
4. **Confirm it's live:** `GET https://devnode.telegraphprotocol.com/api/miners/731001` should return the record.

PR Guard (the app) uses this miner as a second, independent opinion: rules here, an AI reviewer (ChainSight) there. That relationship is disclosed in the submission.
