# PR Guard demo

`demo/app` is a tiny Express API. Three pull requests change it, one per outcome:

| Branch | What it changes | Expected verdict |
|---|---|---|
| `demo/clean-change` | adds a parameterized search endpoint | 🟢 SAFE |
| `demo/vulnerable-dependency` | downgrades lodash to 4.17.15 | 🔴 BLOCK: known high-severity advisories, confirmed by two miners |
| `demo/leaked-key-and-injection` | hardcodes a (fake) AWS key, builds SQL from strings, `eval`s input | 🔴 BLOCK: committed key (local) plus injection confirmed by two independent reviewers |

## Try it yourself (reviewers)

Fork-free: open a pull request against this repo from a new branch that changes anything under `demo/app`. PR Guard comments within about a minute. Every paid check in the comment links to its Telegraph signal, and the run's purchase ledger is attached to the workflow run.

The AWS key in the demo is fake (it was never issued) and exists only to show detection.
