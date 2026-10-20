# strhide

**Smart format-preserving, lossless data hiding.** Hide text or files inside ordinary host files (PNG, JPEG, MP4, ZIP, PDF, Windows PE executables, or any file) without changing the host's visible format, appearance, or functionality — and restore the original host file bit-for-bit afterwards.

This repository ships two implementations:

| Implementation | Language | Status |
| --- | --- | --- |
| [`rust/`](rust/) | Rust (edition 2024) | **Maintained (0.3.x)** — single static binary, built from source |
| [`python/`](python/) | Python ≥ 3.10 | **Frozen at 0.2.0, deprecated** — `pip install strhide`, library + CLI |

Compatibility is one-directional: the Rust build can still read envelopes written by the old Python package, but Python cannot read Rust's new default fully-encrypted envelopes, nor PE carriers written with the `pe_slack` / `pe_codebits` strategies. Use the Rust binary for everything.

> [中文说明（README.zh.md）](README.zh.md)

## Features

- **Format preserving** — the carrier file stays a valid PNG/JPEG/MP4/ZIP/PDF/PE and renders or runs normally.
- **100% reversible** — an embedded SHA-256 of the original host guarantees the `read`/`remove` output matches the original bit-for-bit.
- **Always encrypted on disk** — every envelope is Deflate-compressed and AES-256-GCM-encrypted before it touches the carrier. With no password a built-in key is used, so the carrier never leaks plaintext payload, host hash, or filenames; supplying a password adds real key separation (PBKDF2-HMAC-SHA256, 100,000 rounds + HKDF-SHA256, chunked GCM).
- **Stealth mode** — with a password, envelope signatures and header fields are derived from the password, so there is nothing to find without it. Even in the default (non-stealth) mode there are no static ASCII magics: no `STRHIDE` / `STH!` strings, only high-entropy binary signatures (legacy magics still recognized for reading).
- **Black-box steganalysis** — `scan` treats files as unknown and reports structural + statistical signs of hidden data from *any* tool, not just strhide.
- **Password hint** — an optional (≤ 1 KiB) hint is stored with the envelope and shown when the password is required.
- **Safe by default** — integrity/signature rejection checks refuse to modify files that should not be touched (e.g. signed binaries); `read` refuses to overwrite an existing output file unless `--overwrite` is given; in-place writes create a `.bak` backup; original file timestamps are preserved.
- **TOML configuration** — `./strhide.toml` or `~/.strhide/config.toml` provides defaults; explicit CLI flags always win.
- **Batch carriers** — `write`, `remove`, and `scan` accept several files (and directories) at once; `read`/`inspect`/`verify` take exactly one carrier.

## Install

**Prebuilt binaries (recommended — no Python or Rust toolchain required):**

Download from [GitHub Releases](https://github.com/mcxiaoke/strhide/releases/latest):

| Platform | File |
| --- | --- |
| Windows x64 | `strhide-windows-x86_64.exe` |
| Windows ARM64 | `strhide-windows-aarch64.exe` |
| macOS (Intel + Apple Silicon) | `strhide-macos-universal2` |
| Linux x64 (fully static) | `strhide-linux-x86_64` |
| Linux ARM64 (fully static) | `strhide-linux-aarch64` |

```bash
chmod +x strhide-macos-universal2          # macOS / Linux
./strhide-macos-universal2 --help
sha256sum -c SHA256SUMS.txt                # verify the download
```

> **macOS (unsigned build):** Gatekeeper quarantines downloaded binaries that are not notarized. Either right-click the file → **Open**, or run `xattr -d com.apple.quarantine ./strhide-macos-universal2`.
>
> **Windows:** SmartScreen may warn about an unsigned executable — choose **More info → Run anyway**.

**Python (deprecated, frozen at 0.2.0):**

```bash
pip install strhide
```

**Build from source:**

```bash
cd rust
cargo build --release
# binary at target/release/strhide
```

## CLI quick start

```bash
# Hide text in an image (in-place, with a .bak backup)
strhide write -c photo.png -t "meet me at 7"

# Hide a file, encrypted, with a password hint
strhide write -c report.pdf -d secret.zip -p "S3cret!" -H "my usual one"

# Extract the hidden data (refuses to overwrite an existing file unless --overwrite)
strhide read -c photo.png -o out/

# Black-box steganalysis: scan files or a whole directory recursively for hidden
# content from any tool (structural + statistical signs, no strhide knowledge);
# --json supported
strhide scan -c suspicious.bin ./downloads -r

# Show envelope metadata and per-strategy capacity for a carrier (what was
# hidden, when, which strategy, and how much more could fit); --json supported
strhide inspect -c report.pdf --json

# Verify host + envelope integrity (3 levels; --json supported)
strhide verify -c report.pdf

# Remove the hidden data, restoring the original host file
strhide remove -c photo.png

# Batch: embed the same payload into several carriers (with -o they are written
# to an existing directory instead of in place), then strip them all again
strhide write -c a.png b.png c.png -t "meet me at 7"
strhide remove -c a.png b.png c.png

# List every format, strategy, and its capacity limit (static reference)
strhide list
```

Password sources (checked in order): `-p/--password` → `--password-file` → `STRHIDE_PASSWORD` env var → config file → interactive prompt (`-e/--encrypt`).

> **Security note:** a password passed via `-p` may leak through shell history and the process list. Prefer `--password-file`, `STRHIDE_PASSWORD`, or the interactive prompt.

## Python API

> **Deprecation notice (2026-10-18):** the pure-Python implementation is frozen at **0.2.0** and will no longer receive new features. Use the prebuilt Rust binary for the full feature set. In particular, Python does **not** implement the `pe_slack` / `pe_codebits` PE strategies, and it predates Rust's default fully-encrypted envelope (built-in-key mode), so it cannot read carriers written by current Rust builds. It remains available for existing users and for reading legacy 0.2.0-era files.

```python
from strhide import write_carrier, read_carrier, inspect_carrier

# Hide text in a carrier (writes carrier.png in-place by default)
result = write_carrier("carrier.png", data_text="hello", password="pw")

# Extract it again
result = read_carrier("carrier.png", output_path="restored.txt", password="pw")

# Metadata without extracting
meta = inspect_carrier("carrier.png", password="pw")
```

All functions return a result dict and raise `StrHideError` subclasses on failure (`RejectionError`, `CorruptedDataError`, `PasswordError`, `UnsupportedFormatError`, `NoHiddenDataError`, `RestoreMismatchError`). The package ships type annotations (`py.typed`).

## Supported carriers & strategies

| Carrier | Detection | Typical strategies |
| --- | --- | --- |
| PNG | ✓ | chunk injection between IDAT chunks |
| JPEG | ✓ | APPn segment injection, multi-segment chaining |
| MP4 | ✓ | free/uuid box injection |
| ZIP | ✓ | entries before the central directory |
| PDF | ✓ | incremental update / object injection |
| Windows PE (exe/dll) | ✓ | `pe_slack` section-padding envelope (file size unchanged), `pe_codebits` instruction-encoding channel, or overlay data |

Unrecognized formats are **rejected**: strhide only modifies explicitly supported carriers, because appending data to an arbitrary file can corrupt it. The `eof` strategy remains available as a fallback *within* supported formats (e.g. oversized PNG payloads).

`strhide inspect -c <file>` shows the exact strategies available for a given carrier along with their capacity limits; `-s auto` (default) picks a suitable one, and `-s ask` lists them interactively (single carrier only).

## Repository layout

```
strhide/
├── python/     # Python package (library + CLI), published to PyPI
├── rust/       # Rust implementation (library + CLI binary)
├── docs/       # design notes and change logs
└── LICENSE     # Apache-2.0
```

## License

[Apache License 2.0](LICENSE)
