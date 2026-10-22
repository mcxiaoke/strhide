# strhide

**Smart format-preserving, lossless data hiding.** Hide text or files inside ordinary host files (PNG, JPEG, WebP, HEIC/HEIF, MP4, WAV, MKV, ZIP, PDF, Windows PE executables) without changing the host's visible format, appearance, or functionality — and restore the original host file bit-for-bit afterwards.

This repository ships two implementations:

| Implementation | Language | Status |
| --- | --- | --- |
| [`rust/`](rust/) | Rust (edition 2024) | **Maintained (0.6.x)** — single static binary, built from source |


> [中文说明（README.zh.md）](README.zh.md)

## Features

- **Format preserving** — the carrier file stays a valid PNG/JPEG/WebP/HEIF/MP4/WAV/MKV/ZIP/PDF/PE and renders, plays, or runs normally.
- **100% reversible** — an embedded SHA-256 of the original host guarantees the `read`/`restore` output matches the original bit-for-bit.
- **Always encrypted on disk** — every envelope is Deflate-compressed and AES-256-GCM-encrypted before it touches the carrier. With no password a built-in key is used, so the carrier never leaks plaintext payload, host hash, or filenames; supplying a password adds real key separation (PBKDF2-HMAC-SHA256, 100,000 rounds + HKDF-SHA256, chunked GCM).
- **Stealth mode** — with a password, envelope signatures and header fields are derived from the password, so there is nothing to find without it. Even in the default (non-stealth) mode there are no static ASCII magics: no `STRHIDE` / `STH!` strings, only high-entropy binary signatures. The pre-v2 ASCII magics (`STRHIDE` / `STH!`) are no longer recognized.
- **Black-box steganalysis** — `scan` treats files as unknown and reports structural + statistical signs of hidden data from *any* tool, not just strhide; JPEG carriers additionally go through a **calibrated DCT test** (`dct:calibration`), and a `clean` verdict is explicitly labelled as not being evidence of absence.
- **Password hint** — an optional (≤ 1 KiB) hint is stored with the envelope and shown when the password is required.
- **Safe by default** — integrity/signature rejection checks refuse to modify files that should not be touched (e.g. signed binaries); `write`, `restore`, and `embed` default to writing a new `<stem>-out.<ext>` file, leaving original carriers untouched; explicit `--in-place` modifies carriers directly (creating a `.bak` backup copy); `read`, `extract`, `write`, and `restore` refuse to overwrite existing output files unless `--overwrite` is explicitly specified; original file timestamps are preserved.
- **TOML configuration** — `./strhide.toml` or `~/.strhide/config.toml` provides defaults; explicit CLI flags (`-c, --config`) always win (see [`strhide.sample.toml`](strhide.sample.toml) for an annotated template).
- **Batch & recursive carriers** — `write`, `restore`, `scan`, `inspect`, `verify`, and `embed` accept several files (and directories with `-r, --recursive`) at once; `read` takes exactly one carrier.
- **Content-adaptive steganography (HILL & UERD)** — `embed` and `extract` hide data directly in image pixels (PNG, HILL cost model) or DCT frequency coefficients (JPEG, via UERD cost model). Unlike structure-domain injection, content steganography modifies minimal-distortion texture regions and survives metadata stripping. Pixels are written by **ternary ±1 matching** inside the pixel's eight-value class (`val & 0xF8`), so probability mass crosses value-pair boundaries instead of flattening each pair — the specific pattern chi-square and SPA look for. Measured on the bundled corpus at full capacity the self-scan dropped from 50/100 (SUSPICIOUS, RS+SPA) to 25/100 (LOW, SPA only).

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

**Build from source:**

```bash
cd rust
cargo build --release
# binary at target/release/strhide
```

## CLI quick start

```bash
# Hide text in an image (default writes to photo-out.png, leaving photo.png untouched)
strhide write photo.png -t "meet me at 7"

# Or modify carrier in-place (creates photo.png.bak backup)
strhide write photo.png -t "meet me at 7" --in-place

# Hide text streamed from a pipe (other payload sources: -d file, --text-file, --text-base64)
cat secret.txt | strhide write image.jpg --stdin

# Hide a file, encrypted, with a password hint
strhide write report.pdf -d secret.zip -p "S3cret!" -H "my usual one"

# Extract the hidden data (refuses to overwrite an existing file unless --overwrite)
strhide read photo-out.png -o out/
strhide read photo-out.png --stdout

# Black-box steganalysis: scan files or a whole directory recursively for hidden
# content from any tool (structural + statistical signs, no strhide knowledge);
# --json supported
strhide scan suspicious.bin ./downloads -r

# Same scan, silent, gated on the exit code: 1 when any file is judged
# "likely-hidden", 0 otherwise (suspicious/low findings stay at 0)
strhide scan suspicious.bin ./downloads -r -q

# Show envelope metadata and per-strategy capacity for carriers (supports multi-carrier
# and recursive directory scan with -r); --json supported
strhide inspect report.pdf --json
strhide inspect ./photos -r --json

# Verify host + envelope integrity (3 levels; supports multi-carrier and -r; --json supported)
strhide verify report.pdf ./photos -r

# Remove the hidden data, restoring the original host file (default writes to <carrier>-out.<ext>)
strhide restore photo-out.png -o restored.png
# Or restore in-place:
strhide restore photo.png --in-place

# --- Content-adaptive pixel/DCT steganography (immune to metadata stripping) ---

# Probe maximum steganographic capacity of an image without modifying it
strhide embed photo.png --capacity

# Embed text or file into complex textures (HILL for PNG, UERD for JPEG)
strhide embed photo.png -t "classified message" -p "P@ss123" -o stego.png
strhide embed cover.jpg -d secret.zip -p "P@ss123" --in-place

# Extract content-adaptive hidden data (--stdout or -o, with --overwrite protection)
strhide extract stego.png -p "P@ss123" --stdout
strhide extract stego.jpg -p "P@ss123" -o recovered.zip --overwrite

# Batch: embed the same payload into several carriers (written to an existing directory
# or as <stem>-out.<ext>), then restore them
strhide write a.png b.png c.png -t "meet me at 7" -o done/
strhide restore done/a.png done/b.png done/c.png -o restored/

# List every format, strategy, and its capacity limit (supports --json for automation)
strhide list --json
```

Password sources (checked in order): `-p/--password` → `--password-file` → `STRHIDE_PASSWORD` env var → config file → interactive prompt (`-e/--encrypt`). `-p` and `--password-file` are mutually exclusive.

Payload sources on `write` are mutually exclusive too: `-d/--data`, `-t/--text`, `--text-file`, `--text-base64`, `--stdin` cannot be combined. When none is given, the `STRHIDE_TEXT` env var is used as a last-resort fallback.

> **Security note:** a password passed via `-p` may leak through shell history and the process list. Prefer `--password-file`, `STRHIDE_PASSWORD`, or the interactive prompt.

## Rust library API

The `strhide` crate can be used as a library. The recommended entry point is a **`StrHide`** instance: it binds one private dialect (`Profile`) and one writer-behaviour baseline (`LocalParams`), then exposes every verb as an ordinary method. The whole dialect can be declared `const` at compile time (zero runtime cost), and both file-path and in-memory (`&[u8]` -> `Vec<u8>`) variants are provided.

```rust
use strhide::engine::{PayloadSource, WriteOptions};
use strhide::facade::StrHide;
use strhide::params::Profile;

// The whole private dialect is declared at compile time.
const ENGINE: StrHide = StrHide::new()
    .with_profile(Profile::new().with_default_secret("my-deployment-key"));

// Structure domain, in-memory:
let (stego, _) = ENGINE.write_bytes(
    &cover,
    PayloadSource::Bytes(b"secret"),
    &WriteOptions::default(),
)?;
let read = ENGINE.read_bytes(&stego, None)?;
assert_eq!(read.data, b"secret");

// Content domain (image steganography), in-memory:
let stego = ENGINE.embed(&jpeg, b"secret", &Default::default())?;
let payload = ENGINE.extract(&stego, &Default::default())?;
assert_eq!(payload, b"secret");
```

A host can also drive its own command line with the bound dialect: `ENGINE.run_cli_from(std::env::args_os())` returns the exit code without calling `process::exit`. The underlying free functions (`write_carrier_bytes`, etc.) remain available for callers that prefer them.

Library documentation:

- [`docs/api/ARCHITECTURE.md`](docs/api/ARCHITECTURE.md) — module topology, public API surface, data flow, extension points;
- [`docs/api/WIRE_SPEC.md`](docs/api/WIRE_SPEC.md) — UBE v2.2 binary wire format, key derivation, compatibility matrix.

Runnable examples: `cargo run --example in_memory`, `cargo run --example private_profile`, `cargo run --example codec_bench`.

All functions return a result dict and raise `StrHideError` subclasses on failure (`RejectionError`, `CorruptedDataError`, `PasswordError`, `UnsupportedFormatError`, `NoHiddenDataError`, `RestoreMismatchError`). The package ships type annotations (`py.typed`).

## Supported carriers & strategies

| Carrier | Detection | Typical strategies |
| --- | --- | --- |
| PNG | ✓ | chunk injection between IDAT chunks |
| JPEG | ✓ | APPn segment injection, multi-segment chaining |
| WebP | ✓ | `riff_chunk` private `SHRD` chunk injection |
| HEIC / HEIF | ✓ | `box_uuid` compliant ISO BMFF uuid box injection |
| MP4 | ✓ | `box_uuid` free/uuid box injection |
| WAV | ✓ | `riff_chunk` private `SHRD` chunk injection |
| MKV | ✓ | `ebml_void` compliant EBML Void element injection |
| ZIP | ✓ | entries before the central directory |
| PDF | ✓ | incremental update / object injection |
| Windows PE (exe/dll) | ✓ | `pe_slack` section-padding envelope (file size unchanged), `pe_codebits` instruction-encoding channel, or overlay data |

Unrecognized formats are **rejected**: strhide only modifies explicitly supported carriers, because appending data to an arbitrary file can corrupt it. The `eof` strategy remains available as a fallback *within* supported formats (e.g. oversized PNG payloads).

`strhide inspect <file>` shows the exact strategies available for a given carrier along with their capacity limits; `-s auto` (default) picks a suitable one, and `-s ask` lists them interactively (single carrier only).

### Content-adaptive pixel/DCT steganography (`embed` / `extract`)

| Domain | Supported formats | Algorithm | Mechanism |
| --- | --- | --- | --- |
| Spatial domain | PNG (RGB/RGBA/Grayscale) | **HILL** (High-Low-Low) + asymmetric ±1 | Ternary ±1 matching in high-pass texture regions; the move stays inside the pixel's eight-value class so the `val & 0xF8` cost map — and hence the slot ranking — is identical on both ends |
| DCT frequency domain | JPEG / JPG (Baseline) | **UERD + ternary STC (V3)** | Fixed grid of every AC position, ternary `±1` write-back, 44-byte superblock, `dct-io` lossless re-encoding |

*UERD on the real block grid*: the cost model uses the file's own luminance quantization table and the true
MCU-padded block map (4:2:0 interleaves block rows, so `ceil(sqrt(n))` is wrong for most carriers), and it prices
every AC position — including zeros — because the code is ternary.

*JPEG: fixed-grid ternary STC*: the slot set is **every AC position of every block** (`k = 1..63`), ordered by flat
index and permuted with a key. Nothing about the set depends on coefficient values, so extraction needs no cost map
and no re-ranking: it reads parities and rebuilds the same sequence from the key. The group size `u` is chosen by
the *slot budget* (`--slot-budget`, default 1,200,000):

```
u = max(1, min(64, floor(budget / (bits + h - 1)), floor(|body grid| / (bits + h - 1))))
```

A 4 KiB payload on a 1920x1280 photo gets `u = 36` (one bit spread over 36 coefficients), 64 KiB gets `u = 2`.
`--slot-budget` is an embed-side knob only: extraction trusts the `u` recorded in the superblock, so carriers
written with a different budget still decode. Legality is one bound — `|c| = 1023` cannot grow (`category(1024)`
is outside the baseline AC table) — plus, for carriers whose Huffman table is over-optimised, the directions whose
`(run, category)` symbol is missing.

*PNG: matrix coding layer (`--codec`)*: spatial payload bits are placed by `(7,3)` Hamming matrix embedding by
default. `--codec stc` switches to syndrome-trellis codes (`--stc-h 4..10` default 8, `--stc-u 1..3` default 1),
which minimises *cost-weighted* distortion instead of per-block change count. The codec, `h` and `u` are recorded in
the PNG carrier header, so `extract` never needs the flags.

`--stc-u` is how many slots share one syndrome row: `u=1` is one bit per slot (0.50 changes/bit), while `u=2/3`
spreads the same message over 2x/3x the slots — fewer changed slots and lower weighted distortion, at `1/u` of the
capacity. Measured on PNG carriers (33 KB incompressible payload): `u=2` reaches **0.2758** changes/bit and `u=3`
**0.2276** on a 1920x1920 carrier whose slot pool is only 16% used, both below Hamming's 0.2925; on a 960x960
carrier where `u=2` already consumes 82% of the pool it is 0.3063, slightly *above* Hamming. STC's entire advantage
comes from picking the cheapest slots, and a saturated pool has no cheap slots left.

*What the self-check can and cannot see*: `scan` is triage, not proof. JPEG carriers go through a **calibrated DCT
test** (`dct:calibration`): the image is decoded, cropped 4 px so the 8x8 grid lands half a block off the embedding
grid, re-quantised with the file's own table, and the magnitude-pair imbalance — including the `(0, 1)` pair, which
is where `0 <-> ±1` moves land — is compared against that reference. Measured on the 80-carrier corpus with
incompressible payloads: clean median 0.000 / max 0.011, recommended load (<= 0.10 bpp) max 0.007, full capacity
median 0.141 with **85% flagged at a 0.05 threshold and zero false positives**. A quality-100 carrier (all
quantization steps are 1) is not calibratable by design, because re-quantising decoded pixels is dominated by IDCT
rounding at that scale. **A `clean` verdict still does not mean a carrier holds no hidden data** — a clean or low
JPEG result carries an explicit note saying so.

*Private dialect & domain isolation*: with no password, both the envelope key and the header-slot permutation are derived from a constant that lives in the source tree, so any strhide build can read a no-password carrier. Replace that constant with `--stego-secret <SECRET>` (or the `stego_secret` config key, or `STRHIDE_STEGO_SECRET`) to define a private secret dialect. To isolate key derivation across teams or environments without changing passwords, specify `--stego-domain <DOMAIN>` (or `stego_domain` in config, or `STRHIDE_STEGO_DOMAIN`): keys and header permutations are subkeyed via HKDF with NFC normalization and length prefixing. Embed and extract must agree on secret and domain; any mismatch safely fails as `NoHiddenData`.

*Safety capacity tiers (`--safety` & `--enforce-safety`)*: Content steganography supports three calibrated safety capacity tiers:
- `high` (default recommended): payload budget $\le 0.10$ bpp (approx. slot ratio $r \ge 6.9$). Minimal distortion, optimal for anti-steganalysis.
- `balanced`: payload budget $\le 0.15$ bpp ($r \ge 4.6$). Legacy capacity threshold.
- `paranoid`: payload budget $\le 0.06$ bpp ($r \ge 11.5$). Ultra-low footprint for extreme evasion requirements.

By default, exceeding the recommended safety tier prints an advisory warning with exact bpp and change rate metrics. Specifying `--enforce-safety` strictly rejects oversized payloads to prevent unintentional detection exposure.

*JPEG header (44-byte superblock)*: version, flags, 16-byte salt, 12-byte nonce, envelope length, cipher-suite
id, codec id, `h`, `u`, component mask and extension length. It is carried by 718 slots (STC `h=8, u=2`, exactly
352 bits) and the whole block is the AEAD's associated data, so a flipped field fails the tag instead of steering
the decoder. Optional fields go into a TLV extension area after the superblock (`--` writers set it through the
library, no CLI flag). The header's *location* is derived from `SuiteKDF(password, cover_digest)`, so reading it
costs a full KDF — there is no cheap password oracle. Cipher suites: id 1 = PBKDF2-SHA256 200k + AES-256-GCM
(default), id 2 = 600k (`--cipher-suite 2`), id 3 = Argon2id reserved.

*PNG header*: a 32-byte word (salt, nonce, length/codec/h) plus a 32-byte `FeatureWord` describing codec,
parameters and safety rules; 512 slots carry both, and the pair is the AEAD's associated data.

*Measured on 8 photos at 1920x1280, default settings (mean of the corpus run)*:

| Payload | `u` | Embed | Extract | PSNR | File growth |
| --- | ---: | ---: | ---: | ---: | ---: |
| 4 KiB | 36 | 1.4 s | 0.12 s | 58.2 dB | +0.06% |
| 16 KiB | 9 | 1.4 s | 0.12 s | 50.0 dB | +0.49% |
| 64 KiB | 2 | 0.9 s | 0.12 s | 35.2 dB | +9.8% |

64 KiB on a 1920x1280 carrier is ~0.22 bpp, i.e. more than twice the *recommended* rate: the growth is the price
of changing ~10% of all coefficients. At the recommended tier (<= 0.10 bpp) growth stays below 1%.

*Safety protections:* Animated PNGs (APNG `acTL`), palette-indexed PNGs (`PLTE`), interlaced PNGs (Adam7), and progressive JPEGs (SOF2) are safely rejected with actionable guidance.

## Repository layout

```
strhide/
├── rust/       # Rust implementation (library + CLI binary)
├── docs/       # design notes and change logs
└── LICENSE     # Apache-2.0
```

## License

[Apache License 2.0](LICENSE)
