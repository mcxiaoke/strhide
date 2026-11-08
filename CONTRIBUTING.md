# Contributing to strhide

Thanks for taking the time. This project touches cryptographic key derivation, wire formats, and binary file patching, so the bar for changes is *evidence*, not enthusiasm: every change to an output-affecting path has to prove it did not alter existing behaviour.

- [Before you start](#before-you-start)
- [Set up a development environment](#set-up-a-development-environment)
- [The gates every change must pass](#the-gates-every-change-must-pass)
- [Commit and PR conventions](#commit-and-pr-conventions)
- [Changing the wire format](#changing-the-wire-format)
- [Changing dependencies](#changing-dependencies)
- [What will not be merged](#what-will-not-be-merged)
- [Licensing of contributions](#licensing-of-contributions)

---

## Before you start

| I want to… | Do this |
| :--- | :--- |
| report a bug | open an issue using the bug template — include version, platform, command, and whether the carrier survives |
| report a **security** problem | **not** an issue: follow [SECURITY.md](SECURITY.md) |
| propose a feature | open an issue first; anything touching the wire format needs agreement before code |
| ask a usage question | [docs/FAQ.md](docs/FAQ.md) and [SUPPORT.md](SUPPORT.md) |
| fix a typo / improve docs | just open the PR, no issue needed |

Skip the issue only for documentation and obvious one-line fixes.

## Set up a development environment

```bash
git clone https://github.com/mcxiaoke/strhide.git
cd strhide/rust
cargo build --release --all-features
cargo test --all-features --all-targets
```

Two prerequisites worth reading before your first patch:

- **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)** — repository layout, feature flags, the vendored HEVC sources, and why a plain `cargo build` does not refresh the CLI binary.
- **[docs/TESTING.md](docs/TESTING.md)** — what each test suite covers, how the byte-level baseline works, and which suites are `#[ignore]`d by default.

## The gates every change must pass

Run all of these from `rust/` (plus the GUI and Python ones when relevant). A PR that fails any of them will not be reviewed.

```bash
cd rust
cargo build --release --all-features                     # the CLI binary must actually rebuild
cargo test --all-features --all-targets                  # full suite
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings # zero warnings
python ../scripts/import_lint.py                         # layering: stego must not depend on structure
python ../scripts/check_feature_matrix.py                # run when you touch cfg/feature gates
python ../scripts/baseline_hash.py --check               # byte-for-byte output unchanged
```

When you change anything under `gui/`:

```bash
cd gui
pnpm build
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
pnpm test:unit && pnpm test:cross && pnpm test:e2e
```

Before submitting, sanity-check the behaviour you claim to have changed:

```bash
cargo test local_ --all-features -- --ignored    # fast batch, ~30-60 s
cargo test heavy_ --all-features -- --ignored    # benchmark/matrix suites, ~2 min
```

Optional stress runs for the stego engines (`examples/jpg_stress`, `png_stress`, `hevc_stress`, `audio_stress`) — multi-threaded, multi-round, randomised payloads with SHA-256 round-trip verification. Run them when you touch a cost model, the trellis, or a codec path.

## Commit and PR conventions

- **Commit messages are English**, in Conventional Commits form with a scope: `feat(api):`, `fix(structure):`, `docs(api):`, `refactor(cli)!:`, `test(stego):`, `perf(hevc):`. The `!` marks a breaking change and must be explained in the body.
- **One logical change per commit.** Do not mix a refactor with a behaviour change; reviewers cannot verify a diff that does two things.
- **Explain the why, not the what.** The diff shows the what. State the failure mode you fixed, the measurement you took, or the invariant you restored.
- **PR description**: what changed, why, how you verified it (commands + results), and the blast radius (which formats, which domains, wire-format impact yes/no).
- **No AI-generated justification.** If a change was produced with tooling, verify it yourself against the code; a convincing rationale is not evidence.

## Changing the wire format

The specification in [`docs/api/spec/`](docs/api/spec/README.md) is normative, and its stability classes (**F** frozen / **D** dialect / **I** implementation-free) decide what a change costs. If you touch any of the following, the PR must include the corresponding spec update in the same commit:

- `format_id`, `strategy_id`, `algorithm_id`, cipher-suite ids, TLV `type_id` (append-only — never re-purpose an existing value);
- version fields, header/trailer layout, chunking, AAD composition, nonce derivation;
- KDF labels, salts, HKDF `info` construction;
- cost models or slot rules that change which bytes are written.

Plus:

1. `python ../scripts/baseline_hash.py --check` must pass, or `--write` must be justified as an intentional format change.
2. [CHANGELOG.md](CHANGELOG.md) gets an entry that says plainly whether existing carriers stop being readable.
3. `docs/api/spec/CORRECTIONS.md` is updated when the change corrects previously documented behaviour.

Before 1.0 there is no requirement to read old formats, but silently breaking them is not acceptable: it must be recorded.

## Changing dependencies

- Prefer the standard library; the crate deliberately has no HTTP client and no async runtime.
- New dependencies must be permissively licensed (MIT / Apache-2.0 / BSD / ISC / Zlib). Copyleft-only dependencies will be rejected.
- After a dependency bump, regenerate the attribution lists (run from the repository root) and commit them together:

```bash
python scripts/gen_third_party_licenses.py           # rewrite docs/licenses/*
python scripts/gen_third_party_licenses.py --check   # verify they are current
```

- Anything that changes the engine's output requires the baseline check (above), and anything HEVC-related should note the patent considerations in [LEGAL.md](LEGAL.md) §4.

## What will not be merged

- Weakening a security default (a lower PBKDF2 iteration floor, a silent fallback to a public key, disabling an AEAD check).
- Adding network code, telemetry, update pings, or crash reporting.
- Removing the fail-closed behaviour of `restore` in favour of "best effort" output.
- Test-only shortcuts that bypass the baseline or the layering lint.
- Features that claim steganalysis resistance without a measurement behind the claim.

## Licensing of contributions

No CLA is required. By submitting a pull request you agree that your contribution is licensed under the Apache License 2.0, the same terms as the project (see [LICENSE](LICENSE)). Only contribute code you have the right to submit; if you port an algorithm from a paper, cite it in the commit message and in the relevant spec document.

By participating you also agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
