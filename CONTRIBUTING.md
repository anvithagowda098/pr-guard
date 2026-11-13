# Contributing to PR Guard

Thanks for trying PR Guard. Reports from real use are the most useful contributions of all.

## Good first contributions

- **Try it on your repository.** Add the [one-file workflow](README.md#2-on-your-repository-with-no-setup-public-repositories) to a public repository and open a pull request. Then [open an issue](https://github.com/anvithagowda098/pr-guard/issues/new) with what happened: the verdict, how long it took, and anything that confused you.
- **Report a wrong verdict.** A missed vulnerability or a false alarm, with a link to the pull request or report page. These become test cases.
- **Add an ecosystem.** Maven, NuGet, RubyGems and Composer manifests aren't read yet. Parsing lives in `src/extract.js`, and the tests are in `test/extract.test.js`.
- **Vet a miner.** Telegraph has dozens of miners for `SECURITY_REVIEW_GENERAL`, `VULNERABILITY_TRIAGE_GENERAL`, `CODE_PATCH_VERIFY_GENERAL` and `SMART_CONTRACT_AUDIT_GENERAL`. [docs/MINERS.md](docs/MINERS.md) shows how to test one with paid calls and add it to `config/miners.json`. Include the captured answers as fixtures.
- **Improve PR Guard Sentinel's rules.** `miner/rules.js` holds the deterministic code rules. Each rule needs a test with a vulnerable and a safe example in `test/miner.test.js`.

## Before you open a pull request

```sh
npm ci
npm test        # all offline; must pass
npm run build   # if you changed src/, commit the rebuilt dist/index.js
```

- **Tests:** keep them offline. Replay captured miner answers instead of calling the network.
- **Miner answers:** don't guess at their format. Base every normalizer on real captured responses.
- **Keys:** never commit one, even a testnet key. `.env` is ignored for that reason.

## Security issues

Please don't open a public issue for a vulnerability in PR Guard itself. Use GitHub's private vulnerability reporting on this repository instead.
