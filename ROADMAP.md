# Roadmap

This is a direction document, not a schedule. Nothing here is a commitment, and items may be dropped or reordered. For what has already shipped, see [CHANGELOG.md](CHANGELOG.md).

Current version: **0.9.3**, pre-1.0.

---

## Compatibility promises

| Area | Now (pre-1.0) | After 1.0 (intended) |
| :--- | :--- | :--- |
| Wire format (UBE v2 / content V4) | Frozen-class fields may still change between releases; every change is called out in the CHANGELOG | Frozen-class fields become a hard compatibility guarantee; readers must accept all earlier 1.x carriers |
| Rust public API | Stable surface documented in [docs/api/STEGO-API.md](docs/api/STEGO-API.md) tightens only in a minor release, with the change recorded | SemVer: breaking changes require a major version |
| CLI | Subcommand names, flags, and exit codes are stable in practice; new flags are additive | Same, plus a deprecation cycle of at least one minor release |
| Identifier values | `format_id`, `strategy_id`, `algorithm_id`, `CipherSuiteId`, TLV `type_id` are **append-only** | Append-only, permanently |

There is deliberately **no backward-read requirement** before 1.0. Old carriers may become unreadable; that is announced, not silent.

## Toward 1.0

The gates that matter more than features:

1. **Byte-level baseline enforced in CI.** Today `scripts/baseline_hash.py` runs only on the maintainer's machine because the baseline lives under the ignored `temp/` directory. A committed, reduced corpus plus a committed baseline would let CI catch output drift. See [docs/TESTING.md](docs/TESTING.md) §4.
2. **English wire specification.** `docs/api/spec/` is normative and Chinese-only. A third-party implementer who cannot read Chinese cannot use it. Priority order: index, `CRYPTO.md`, both envelope documents.
3. **Independent implementation check in CI.** A Python reader was validated against PNG carriers during development; it is not part of the test suite.
4. **Code signing / notarisation** for the desktop bundles and, if feasible, the CLI binaries — currently every artifact is unsigned and users must bypass SmartScreen/Gatekeeper.
5. **Documentation link check** so renames cannot leave dead links.

## Candidate work (unordered, uncommitted)

| Area | Candidate | Why |
| :--- | :--- | :--- |
| Structure domain | `ContainerTags` profile so private dialects can cover the structure domain too (today `StructureProfile` only has `default_secret` / `stealth_domain` / `magic`, and `prIv` / `stEg` / `SHRD` / `MP4_UUID_NEUTRAL` / JPEG APP15 stay visible) | Private builds currently isolate the content domain only |
| GUI | Carrier restoration (`restore`) from the desktop app | Today it is CLI-only, which surprises users who hid data in the GUI |
| GUI | `.bak` handling and in-place editing | The GUI hard-codes `backup: false` and always writes elsewhere |
| GUI | Deterministic runs (`--seed`) and dry runs | Needed for reproducible demos and screenshots |
| CLI | Parity gaps around `--no-filename` in the GUI, and structured JSON for more commands | Scriptability |
| Docs | Archive the legacy `WIRE_SPEC_*.md` (~90 KB) under `docs/archive/` and keep only `CORRECTIONS.md` | Two sets of specs invite the wrong one being quoted |
| Packaging | Embed `LICENSE` / `NOTICE` / the license lists into the **desktop** installers (CLI releases already ship a `strhide-<version>-licenses.zip`) | Apache-2.0 §4 requires the license to travel with binaries |
| Quality | Steganalysis regression gate on a fixed corpus | Cost-model changes can silently worsen detection rates |

## Explicitly out of scope

- **Mobile apps, browser extensions, a hosted service.** The project is a library, a CLI, and a desktop app.
- **Recovering payloads from re-encoded media.** That is information-theoretically gone, not a missing feature.
- **Claiming resistance to targeted forensic analysis.** No tier promises that; see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) §7.
- **Network features of any kind** — no update pings, telemetry, or cloud key escrow.

## How to influence this list

Open an issue with the problem you actually have, not the feature you think you want. Concrete use cases (carrier type, payload size, threat you are defending against) move items up; "would be nice" does not. See [SUPPORT.md](SUPPORT.md).
