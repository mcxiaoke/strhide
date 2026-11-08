<!--
Thanks for the pull request. Fill in what applies and delete the rest.
Reviewers check the "Verification" section first: claims without commands and results are not evidence.
-->

## What changed

<!-- One paragraph. What behaviour is different after this PR? -->

## Why

<!-- The failure mode, measurement, or invariant that motivated it. The diff shows the what. -->

## Blast radius

- Affected domains: <!-- structure / content / analysis / cli / gui / docs -->
- Affected carriers: <!-- PNG, JPEG, HEVC, WAV, FLAC, ZIP, PDF, PE, MKV, ... -->
- **Wire format impact**: <!-- none / additive / breaking — if not "none", link the spec commit -->
- Spec documents updated: <!-- docs/api/spec/... or "n/a" -->

## Verification

Paste the commands you ran and their outcome. `cargo test` without `--all-features` does not build the CLI tests, so say which form you used.

```text
cargo build --release --all-features        → ok
cargo test --all-features --all-targets     → N passed
cargo clippy --all-targets --all-features -- -D warnings → clean
python ../scripts/import_lint.py            → clean
python scripts/baseline_hash.py --check     → 28/28 identical
python scripts/check_feature_matrix.py      → ok
```

GUI changes:

```text
pnpm build / pnpm test:unit / pnpm test:cross / pnpm test:e2e   → results
```

## Checklist

- [ ] One logical change; no unrelated refactors mixed in
- [ ] Commit messages in English, Conventional Commits, `!` for breaking changes
- [ ] If output bytes changed: `baseline_hash.py --write` was intentional and CHANGELOG explains the impact on existing carriers
- [ ] If identifiers/versions/slots/labels changed: the corresponding `docs/api/spec/*` file is updated in this PR
- [ ] If dependencies changed: `python scripts/gen_third_party_licenses.py` was re-run and the lists are committed
- [ ] If a new flag/subcommand exists: `docs/CLI_GUIDE.md` (and `docs/GUI_GUIDE.md` if applicable) updated
- [ ] No secrets, real payloads, or confidential carriers added to the repo or to tests
- [ ] Security-relevant change? It is described above in terms of impact, not intent

## Notes for reviewers

<!-- Anything subtle: known limitations, follow-up work, measurements that surprised you. -->
