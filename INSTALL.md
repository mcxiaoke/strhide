# Installation

`strhide` ships as a single static binary per platform, as a Rust crate, and as a desktop app (`StrHide Studio`). Pick the path that matches what you need.

- [1. Prebuilt binaries](#1-prebuilt-binaries)
- [2. Verify the download](#2-verify-the-download)
- [3. First-run smoke test](#3-first-run-smoke-test)
- [4. Install as a Rust crate](#4-install-as-a-rust-crate)
- [5. Build from source](#5-build-from-source)
- [6. Desktop app](#6-desktop-app)
- [7. Troubleshooting](#7-troubleshooting)

---

## 1. Prebuilt binaries

Grab the file for your platform from the [Releases](https://github.com/mcxiaoke/strhide/releases) page. Every asset is a complete CLI containing all ten subcommands.

| File | Platform | Notes |
| :--- | :--- | :--- |
| `strhide-windows-x86_64.exe` | Windows 10/11 x64 | Baseline build, runs on any x86-64 CPU |
| `strhide-windows-x86_64-avx2.exe` | Windows 10/11 x64 | Built with `-C target-cpu=x86-64-v3`; faster, **requires AVX2** |
| `strhide-windows-aarch64.exe` | Windows 11 on ARM | |
| `strhide-linux-x86_64` | Linux x64 | Fully static (musl), no glibc dependency |
| `strhide-linux-x86_64-avx2` | Linux x64 | Static, requires AVX2 |
| `strhide-linux-aarch64` | Linux ARM64 | Static (musl) |
| `strhide-macos-universal2` | macOS 11+ | Universal binary (Apple Silicon + Intel) |
| `SHA256SUMS.txt` | — | Checksums for everything above |

```bash
# Linux / macOS
chmod +x strhide-linux-x86_64
mv strhide-linux-x86_64 ~/.local/bin/strhide

# Windows (PowerShell): put it somewhere on PATH
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\strhide" | Out-Null
Move-Item .\strhide-windows-x86_64.exe "$env:LOCALAPPDATA\strhide\strhide.exe"
```

The domain-specific entry points (`sthc`, `sths`, `sthv`) and the `sth` alias are separate binaries built from the same crate; the prebuilt releases contain only `strhide` / `strhide.exe`, which accepts every subcommand. Build from source (§5) if you want the split entry points.

**The binaries are not code-signed.** Expect a warning the first time:

- **Windows** — SmartScreen shows "Windows protected your PC". Choose *More info* → *Run anyway*, or unblock the file first: `Unblock-File .\strhide.exe`.
- **macOS** — Gatekeeper refuses to run a downloaded unsigned binary. Either right-click → *Open* → *Open* in Finder, or clear the quarantine flag: `xattr -d com.apple.quarantine ./strhide-macos-universal2`.
- **Linux** — no signature gate, but some distros mount `/tmp` as `noexec`; install to a real directory instead of running from `Downloads` if you hit `Permission denied`.

If you need verified provenance rather than an unsigned download, build from source (§5) or install through `cargo` (§4).

## 2. Verify the download

```bash
# Linux
sha256sum -c SHA256SUMS.txt --ignore-missing

# macOS
shasum -a 256 -c SHA256SUMS.txt 2>/dev/null | grep -v FAILED

# Windows (PowerShell)
$want = (Select-String -Path .\SHA256SUMS.txt -Pattern 'windows-x86_64.exe$').Line.Split()[0]
$got  = (Get-FileHash .\strhide-windows-x86_64.exe -Algorithm SHA256).Hash.ToLower()
if ($got -eq $want) { "OK" } else { "MISMATCH" }
```

A mismatch means the file did not come from the release pipeline — do not run it.

Each CLI release also publishes `strhide-<version>-licenses.zip` containing `LICENSE`, `NOTICE`, and the full third-party attribution lists. Keep it if you redistribute the binary.

## 3. First-run smoke test

```bash
strhide --version      # version string
strhide list           # supported carriers, strategies, algorithms, capacity limits
strhide --help         # all ten subcommands
```

A round trip in a scratch directory:

```bash
cd "$(mktemp -d)"
cp /path/to/strhide/testdata/png/img_png_0001.png small.png   # or any PNG/JPEG/PDF/ZIP you own
strhide write small.png -t "hello" -p "test-pass" -o hidden.png
strhide read  hidden.png -p "test-pass"           # prints: hello
strhide restore hidden.png -p "test-pass" -o restored.png
cmp small.png restored.png && echo "bit-exact restore OK"
```

No `testdata` checkout handy? Any PNG works. Note that `restore` only guarantees bit-exactness for structure-domain writes, and only while the file is untouched afterwards — see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## 4. Install as a Rust crate

Library only (no CLI dependencies pulled in):

```bash
cargo add strhide
```

CLI binaries from crates.io:

```bash
cargo install strhide --features cli      # installs strhide, sth, sthc, sths, sthv
```

Feature selection matters: the default feature set is `structure + content + analysis` with **no** `cli`. A plain `cargo build` in `rust/` compiles the library only and will **not** refresh `target/release/strhide.exe` — always pass `--all-features` (or `--features cli`) when you intend to run the CLI. The full matrix is in [rust/README.md](rust/README.md#feature-matrix).

## 5. Build from source

Requirements: Rust stable (edition 2024, i.e. 1.85+), a C toolchain for the musl static build (optional), and `git`.

```bash
git clone https://github.com/mcxiaoke/strhide.git
cd strhide/rust

cargo build --release --all-features
# binaries: target/release/{strhide,sth,sthc,sths,sthv}
```

Without the HEVC engine (smaller build, no HEVC dependencies):

```bash
cargo build --release --no-default-features --features "structure,content-png,content-jpeg,content-audio,analysis,cli"
```

A fully static Linux binary:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --all-features --target x86_64-unknown-linux-musl
```

Verification before you trust a local build:

```bash
cargo test --all-features --all-targets
python ../scripts/baseline_hash.py --check    # default-parameter byte output unchanged
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the full contributor workflow and the vendored HEVC sources.

## 6. Desktop app

Download the installer for your platform from the Releases page — the GUI release is tagged `gui-v*` and is separate from the CLI tags. Tauri's bundler emits macOS `.dmg`, Windows `.msi` / `.exe`, and Linux `.deb` / `.AppImage`; the exact file names are listed on the release page.

The desktop app is also unsigned. macOS needs the same Gatekeeper step as §1; Windows shows the same SmartScreen prompt.

To build it yourself:

```bash
cd gui
pnpm install
pnpm tauri dev      # development, hot reload
pnpm tauri build    # production bundle under gui/src-tauri/target/release/bundle/
```

Linux build prerequisites: `libwebkit2gtk-4.1-dev`, `libappindicator3-dev`, `librsvg2-dev`, `patchelf`. The GUI uses the OS webview (WebView2 on Windows, WKWebView on macOS, WebKitGTK on Linux); nothing else is bundled. Usage is documented in [docs/GUI_GUIDE.md](docs/GUI_GUIDE.md).

## 7. Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `cargo build --release` produced no `strhide.exe` | `cli` is not in the default feature set | add `--all-features` or `--features cli` |
| `Permission denied` on Linux | running from a `noexec` mount | copy to `~/.local/bin` and `chmod +x` |
| `Illegal instruction` on Linux/Windows | you took the `avx2` build on a pre-Haswell CPU | use the baseline build |
| `macOS cannot be opened because the developer cannot be verified` | unsigned binary | `xattr -d com.apple.quarantine <file>` |
| `No hidden data` after moving a file around | a chat app / image host / editor re-encoded it | keep the original stego file; re-embed from a fresh copy |
| `Restore verification failed` | the carrier changed after writing, or two envelopes are layered | remove envelopes in reverse order, or accept that the host is gone |
| `Payload too large` | payload exceeds the selected safety tier | lower the payload, raise the tier, or pick a bigger carrier |

More in [docs/FAQ.md](docs/FAQ.md). If none of it helps, see [SUPPORT.md](SUPPORT.md).
