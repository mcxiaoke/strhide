# Changelog

All notable user-visible changes to StrHide / `strhide` are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

> **Interface and wire-format stability**: before `1.0`, the public API and the
> on-disk wire formats may still change. Wire-format changes invalidate data
> hidden by older versions; each such change is called out explicitly.

## [0.9.3] - 2026-11-07

### Added

- **Third-party implementable wire specifications.** The former single
  `WIRE_SPEC` document is split into per-topic normative documents under
  `docs/api/spec/`: shared concepts and terminology, key derivation/AEAD,
  deterministic math, capacity/limits, the content-envelope common layer plus
  per-carrier specs (PNG, JPEG, HEVC/HEIF, WAV/FLAC), and the structure-domain
  UBE envelope plus per-format adapters (PNG, JPEG, RIFF, ISO-BMFF, ZIP, PDF,
  PE, Matroska).
- **Deterministic math (`detmath`).** All floating-point operations that affect
  output bytes now use a project-owned math library instead of the host `libm`,
  with reference implementations in Python and Go. This removes platform
  drift in cost models; ARM64 hardware verification is complete.
- **Validator and diagnostics improvements.** CLI `-v` logging, preserved
  worker panic text, probe failures recorded instead of discarded, and
  capability failures no longer reported as "unsupported format".
- **Independent second implementation check.** A Python reader was validated
  against PNG carriers written by the Rust implementation.

### Changed

- **Rust public API tightened for release.** Internal modules are hidden from
  docs, most internals moved to `pub(crate)`, and public option/result types
  now use builders, `Default`, and `#[non_exhaustive]`. Library consumers
  should construct options via builder methods rather than struct literals.
- **Capacity reporting** now matches the amount actually writable for the
  selected strategy; capacity shortfalls return `PayloadTooLarge` rather than
  a format error.
- **HEVC dependencies** now resolve from the registry (crates.io), enabling
  normal `cargo` publishing workflows.
- Documentation cross-references were updated to the new per-topic specs.

### Fixed

- **Cross-platform byte drift** in MiPOD / J-MiPOD cost calibration; costs are
  quantized (low 20 mantissa bits cleared) so ordering is stable across
  platforms and languages.
- **PDF multi-revision XRef handling**, HEIF `iloc`/Exif thumbnail bridging,
  and path-traversal protection for archive/batch operations.
- **FLAC stress failures** (`TrellisInfeasible`/`DeadGroup`) via STC warm-up
  initialization and bounded retries.
- **RIFF/WebP structure-domain compliance** and locating of EOF envelopes after
  size changes.
- **Stale work-lock recovery** by PID after a crash.

### Known limitations

- The content domain is **not reversible**: extracting removes the payload, but
  the carrier's pixels/coefficients remain modified. Only the structure domain
  supports bit-for-bit `restore`.
- HEIF thumbnail bridging currently supports JPEG items and Exif-embedded
  JPEGs only; uncompressed (`unci`) items are rejected.
- ZIP support requires a readable EOCD and a non-ZIP64 central directory for
  pre-directory injection; otherwise the payload is appended at EOF.
  Self-extracting executables are not accepted as ZIP carriers.
- PE `codebits` injection rewrites a bounded set of instruction encodings and
  is intended for binaries without Authenticode signatures.
- Stealth mode requires a password; without it the envelope is not
  obfuscated.
