# How PR Guard buys a security check on Telegraph

A walkthrough of one paid check, with a real request and answer, for developers who want to build on Telegraph or check what PR Guard does.

## The idea in one paragraph

[Telegraph](https://telegraphprotocol.com) is an open network where providers ("miners") answer questions of a given kind ("intents"), and apps pay per answer. An app doesn't sign up for one vendor's API: it asks the network for an intent, the network picks a miner, and the app pays over [x402](https://www.x402.org/), an HTTP payment flow, in USDC (test USDC on today's testnet). Every paid answer comes with a receipt. PR Guard uses this to buy a security verdict for each pull request from whichever providers answer best.

## One check, step by step

**1. Plan.** PR Guard reads the pull request and builds the checks it will buy:
- one per changed package;
- one per part of the diff, with secrets redacted first, plus the places elsewhere in the repository where the changed code is used;
- one per new on-chain address.

Free local checks (committed keys, install scripts) run here too.

**2. Ask by intent.** Each check is a *canonical ask*: the intent, plus its typed params. This one comes from a demo diff that builds SQL from strings and calls `eval` on user input:

```http
POST https://devnode.telegraphprotocol.com/engine/v1/ask
Content-Type: application/json

{"intent": "CODE_REVIEW_GENERAL",
 "params": {"code": "diff --git a/src/users.js b/src/users.js\n@@ -1,3 +1,6 @@\n+app.get('/user', ... db.query(\"SELECT * FROM users WHERE id = '\" + req.query.id + \"'\") ..."}}
```

The node checks the params against the intent's schema before anything is charged. `code` may be at most 2,000 characters.

**3. Pay.** The first reply is `402 Payment Required`, with a `PAYMENT-REQUIRED` header quoting the price: $0.01 in test USDC on Ethereum Sepolia. Before signing, PR Guard checks the quote against its per-call cap and reserves it against the pull request's budget. It then signs a USDC transfer authorization (EIP-3009) with its wallet and sends the same request again with a `PAYMENT-SIGNATURE` header. PR Guard uses the `@x402/fetch` library for this.

**4. Get the answer and the receipt.** Telegraph's router picked miner 302 (ChainSight) and read its answer into the intent's standard format (`result_shape: "intent"`):

```json
{"miner_id": "302", "intent": "CODE_REVIEW_GENERAL", "result_shape": "intent", "cost_usd": 0.01,
 "result": {"verdict": "Request changes",
            "findings": ["SQL Injection: Directly concatenating req.query.id into the SQL string allows attackers to execute arbitrary queries...",
                         "Code Injection / Remote Code Execution: eval(req.body.expr) executes any JavaScript code sent by the client..."]},
 "signal_hash": "0x..."}
```

Two response headers carry the proof:
- `PAYMENT-RESPONSE`: the settlement transaction (here `0x8bcecc6b…6709` on Ethereum Sepolia).
- `X-TELEGRAPH-RECEIPT`: Telegraph's receipt (intent, amount, epoch, transaction).

The `signal_hash` opens the public record at `https://devnode.telegraphprotocol.com/engine/v1/signal/<hash>`.

Full capture: [`test/fixtures/miner-responses/ROUTED/code-review-sqli-eval-diff-302-intent.json`](../test/fixtures/miner-responses/ROUTED/code-review-sqli-eval-diff-302-intent.json).

**5. Check the answer before trusting it.** Routing is only as good as the network's rankings, and some intents have no ranking yet. PR Guard uses a routed answer only if:
- it is in the intent's format; or
- it came from a vetted miner and is about the exact target.

Otherwise PR Guard asks one vetted miner directly (`POST /engine/v1/ask/{minerId}`) and says why in the report. It also skips routing for that intent for the rest of the run. No miner is ever paid to second-guess another.

**6. Confirm before blocking.** A miner's opinion alone never blocks a pull request. A high finding is confirmed by deterministic evidence:
- registry data about the exact package version;
- the exact address on the US OFAC sanctions list (PR Guard ships a snapshot of the official list, so a screening miner that misses a listed address is overruled);
- PR Guard's own rules finding the same issue in the same diff, as they did here (string-built SQL, `eval` on input).

**7. Report.** One comment (or report page) with the verdict, each check, the miner that answered (routed or fallback), what it cost and a link to its receipt.

## What we found along the way

Using the network for real turned up gaps worth knowing about:
- **A routing gap.** Routed `SECURITY_REVIEW_GENERAL` asks all went to miner 77003, which ignores the target and returns the 100 newest advisories. That intent has no evaluator yet, so there's no ranking to route by. PR Guard detects it and falls back. Reported as [bounties#187](https://github.com/telegraphprotocol/bounties/issues/187).
- **A dropped answer field.** Routed sanctions screens at first lost the matched list in the node's standard format. The miner's builder (Counterproof) fixed it the same day.
- **Inconsistent answers.** The same miner sometimes answers in prose the node can't read. That costs one fallback call for that check only.
- **A size limit.** Canonical asks cap a string at 2,000 characters, so larger diffs go to a vetted reviewer directly.
- **Routing moves, and answers change shape.** On Nov 17, sanctions screens were routed to a different miner, whose answers carry no match score, so a listed address came back only as a "possible match". The same day, the Solidity auditor reworded its reports, and a newly routed code reviewer answered "Approve" while its own text named two critical bugs (the node had rejected its findings). PR Guard now confirms sanctions hits against its own snapshot of the OFAC list, reads both wordings, and treats a review whose findings the node rejected as unreadable. Both changes were caught by re-running the demo pull requests.

## Try it

- **No setup:** paste any public pull request link into https://pr-guard-app.pr-guard.workers.dev, then follow a receipt link to see the request on the Telegraph node.
- **Your own repository:** add [`examples/pr-guard.yml`](../examples/pr-guard.yml). No key is needed for public repositories.
- **One paid ask from a terminal,** with a burner wallet holding test USDC (see [docs/MINERS.md](MINERS.md), step 2, for creating and funding one):
  ```sh
  node scripts/first-call.js --body '{"intent":"CODE_REVIEW_GENERAL","params":{"code":"<a short diff>"}}' --pay
  ```
  It prints the quote, the paid answer, the payment proof and the receipt.
