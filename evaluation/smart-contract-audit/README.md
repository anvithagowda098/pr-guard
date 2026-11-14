# Evaluation material: SMART_CONTRACT_AUDIT_GENERAL

105 preference pairs for Telegraph's smart-contract audit intent (Mission 14, Web3 Native & DeFi), built from [SmartBugs Curated](https://github.com/smartbugs/smartbugs-curated): real vulnerable Solidity contracts whose vulnerable lines were labelled by hand.

**Why this intent.** On Nov 14, 2026 the evaluation pool for `SMART_CONTRACT_AUDIT_GENERAL` held 199 eligible rows, all from **one contributor**. A judgment intent's questions are only used once the pool has material from at least 5 contributors, so the intent couldn't be ranked. Routed audits went to a miner that answered "unavailable" (see `docs/MINERS.md`).

PR Guard's own miner (PR Guard Sentinel) does not serve this intent.

## What a row is

| Field | Content |
|---|---|
| `prompt` | The contract with **every comment removed**, asking for an audit with line numbers. The dataset marks vulnerable lines with comments (`// <yes> <report> REENTRANCY`, `@vulnerable_at_lines`), and some comments explain the bug, so leaving them in would give the answer away. Line numbers count from the first line of code shown. |
| `chosen` | The correct audit: each labelled vulnerability with its class, severity, line, code, why it's exploitable and how to fix it. One row in five uses a terse style. |
| `rejected` | A plausible but wrong audit. The strategy rotates: it calls the contract safe; names two wrong classes at unrelated lines; understates the real issue without locating it; or lists style nits and misses the vulnerability. |
| `provenance` | `source_kind: "dataset"`, `source_url`: the contract's file in SmartBugs Curated. |

Both answers are generated deterministically from the dataset's labels by [`build_rows.py`](build_rows.py). No language model wrote them.

## Checks

- **Line numbers:** every line number cited in a `chosen` answer matches the code shown in its prompt (0 mismatches).
- **No answer leaks:** no prompt contains the dataset's markers or the original comments.
- **Near-duplicates:** contracts 75% or more similar to an earlier one (token shingles) are dropped (35 of 143), because the node rejects prompts 85% or more similar to one it already holds. 3 more were too long for the 16,000-character limit.
- **Length isn't a shortcut:** `chosen` is the longer answer in 43 rows, `rejected` in 62.
- **The verdict word isn't a shortcut:** every `chosen` says "vulnerable", and so do 52 of the 105 `rejected`.

**Known limit:** every contract in this dataset is vulnerable. The pairs test whether a judge prefers finding the right bug, in the right place, at the right severity. They don't test whether it wrongly flags safe code.

## Reproduce

```sh
git clone https://github.com/smartbugs/smartbugs-curated   # built from commit 230e6491
python3 -I build_rows.py smartbugs-curated rows.jsonl
sha256sum rows.jsonl   # c0cce4310c85e97b0457987374f35ed0c0afa23b82a85d844d9438316f4debf2
```

## Upload

On [Anjoman](https://anjoman.ai/dashboard/eval?intent=SMART_CONTRACT_AUDIT_GENERAL), with the contributor's wallet connected. Or sign and post it to `/api/evalpool/submissions` as described in [Contribute Evaluation Data](https://anjoman.ai/docs/scoring/contribute-evaluation-data).

## License

The contracts come from SmartBugs Curated, licensed under the Apache License 2.0 (copy in [`LICENSE-smartbugs-curated`](LICENSE-smartbugs-curated)).

Changes made here: comments removed, leading and trailing blank lines trimmed, and audit answers generated from the dataset's labels.
