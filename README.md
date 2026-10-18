# strhide

**Smart format-preserving, lossless data hiding.** Hide text or files inside ordinary host files (PNG, JPEG, MP4, ZIP, PDF, Windows PE executables, or any file) without changing the host's visible format, appearance, or functionality — and restore the original host file bit-for-bit afterwards.

Two fully cross-compatible implementations ship in this repository:

| Implementation | Language | Distribution |
| --- | --- | --- |
| [`python/`](python/) | Python ≥ 3.10 | `pip install strhide` — library **and** CLI |
| [`rust/`](rust/) | Rust (edition 2024) | Single static binary, built from source |

Both implement the same envelope format, so a file written by one can be read, verified, and cleaned by the other.

> [中文说明（README.zh.md）](README.zh.md)

## Features

- **Format preserving** — the carrier file stays a valid PNG/JPEG/MP4/ZIP/PDF/PE and renders or runs normally.
- **100% reversible** — an embedded SHA-256 of the original host guarantees the `read`/`remove` output matches the original bit-for-bit.
- **Strong crypto (optional)** — PBKDF2-HMAC-SHA256 (100,000 rounds) + HKDF-SHA256 key derivation, chunked AES-256-GCM encryption, Deflate compression.
- **Stealth mode** — with a password, envelope signatures are derived from the password and static magic bytes are stripped, so there is nothing to find without the password.
- **Password hint** — an optional (≤ 1 KiB) hint is stored with the envelope and shown when the password is required.
- **Safe by default** — integrity/signature rejection checks refuse to modify files that should not be touched (e.g. signed binaries), in-place writes create a `.bak` backup, and original file timestamps are preserved.
- **TOML configuration** — `./strhide.toml` or `~/.strhide/config.toml` provides defaults; explicit CLI flags always win.
- **Batch carriers** — `write` and `remove` accept several files at once: `write` embeds the same payload into each, `remove` strips each one, printing a per-run summary (`read`/`inspect`/`verify` still take exactly one carrier).

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

# Extract the hidden data
strhide read -c photo.png -o out/

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
strhide list-strategies
```

Password sources (checked in order): `-p/--password` → `--password-file` → `STRHIDE_PASSWORD` env var → config file → interactive prompt (`-e/--encrypt`).

> **Security note:** a password passed via `-p` may leak through shell history and the process list. Prefer `--password-file`, `STRHIDE_PASSWORD`, or the interactive prompt.

## Python API

> **Deprecation notice (2026-10-18):** the pure-Python implementation is frozen at **0.2.0** and will no longer receive new features. Use the prebuilt Rust binary for the full feature set. In particular, Python does **not** implement the `pe_codebits` PE strategy and cannot read carriers written with it. The Python package remains available for existing users; its behavior is aligned with Rust except for that strategy.

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
| Windows PE (exe/dll) | ✓ | `pe_codebits` instruction-encoding channel (file size unchanged) or overlay data |

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
