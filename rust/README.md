# strhide (Rust)

Rust implementation of **strhide** — format-preserving, lossless data hiding and content-adaptive steganography. Compiles to a library crate (`strhide`) and static CLI binaries.

See the [root README](../README.md) for project-wide architecture, and [README.zh.md](../README.zh.md) for the Chinese overview.

---

## Table of Contents

- [Cargo Features](#cargo-features)
  - [Feature Matrix](#feature-matrix)
  - [Adding strhide as a Dependency](#adding-strhide-as-a-dependency)
- [Library Usage Guide](#library-usage-guide)
  - [Architecture & Prelude](#architecture--prelude)
  - [The Facade: `StrHide`](#the-facade-strhide)
  - [Private Dialects & Custom Profiles](#private-dialects--custom-profiles)
  - [Structure Domain (Container Hiding & 100% Bit-Exact Restore)](#structure-domain-container-hiding--100-bit-exact-restore)
  - [Content Domain (Adaptive Image, Video, & Audio Steganography)](#content-domain-adaptive-image-video--audio-steganography)
  - [Dynamic Algorithm Discovery](#dynamic-algorithm-discovery)
  - [Diagnostics: Cross-Domain Inspection & Verification](#diagnostics-cross-domain-inspection--verification)
  - [Steganalysis Domain (Black-Box Detection)](#steganalysis-domain-black-box-detection)
  - [Configuration File Management](#configuration-file-management)
  - [Error Handling](#error-handling)
- [CLI Quick Start](#cli-quick-start)
  - [Build CLI Binaries](#build-cli-binaries)
  - [Domain-Specific Entry Points](#domain-specific-entry-points)
  - [Common CLI Commands](#common-cli-commands)
- [Compatibility & License](#compatibility--license)

---

## Cargo Features

`strhide` uses fine-grained Cargo features to keep dependencies lean and compile times fast.

### Design Philosophy
- **Library defaults are lightweight**: `default = ["structure", "content", "analysis"]`.
- `cargo add strhide` does not drag in CLI or terminal dependencies (`clap`, `rpassword`, `base64`).
- All features compile without warnings under `-D warnings`.

### Feature Matrix

| Feature | Description | Extra Dependencies |
| :--- | :--- | :--- |
| **`default`** | Full library capabilities: structure + content + analysis | — |
| `core-io` | Atomic filesystem commit & timestamp preservation | `filetime` |
| **`structure-base`** | Container hiding for PNG, JPEG, MP4, WAV, MKV, ZIP (`.zip`, `.jar`, `.docx`, `.xlsx`, `.pptx`), PDF, PE slack/overlay | `serde_json`, `core-io` |
| **`structure-pe`** | Adds x86/x64 instruction substitution (`pe_codebits`) via iced-x86 | `iced-x86`, `structure-base` |
| **`structure`** | Meta-feature enabling the full structure domain | `structure-base`, `structure-pe` |
| `content-base` | Steganography foundation: Rayon thread pool, cost model traits, generic STC | `rayon`, `core-io` |
| **`content-png`** | Spatial image steganography (HILL, S-UNIWARD, MiPOD) | `content-base` |
| **`content-jpeg`** | DCT frequency domain image steganography (UERD, J-UNIWARD, J-MiPOD) | `dct-io`, `content-base` |
| **`content-hevc`** | H.265/HEVC CABAC bypass sign-bit steganography (MP4, MOV, MKV, Annex-B) | `oxideav-h265`, `rusty_h265`, `content-base` |
| **`content-audio`**| Audio steganography: WAV PCM sample domain & FLAC prediction residual domain | `content-base` |
| **`content-heif-bridge`**| HEIF/HEIC container & thumbnail transcoding bridge | `content-hevc`, `content-png`, `content-jpeg` |
| **`content`** | Meta-feature enabling all content steganography engines | `content-png`, `content-jpeg`, `content-hevc`, `content-audio`, `content-heif-bridge` |
| **`analysis`** | Black-box steganalysis (JPEG calibrated DCT `dct:calibration`, UBE envelopes) | `jpeg-decoder`, `dct-io`, `structure` |
| **`config`** | TOML configuration file support (`strhide.toml`, user/system configs) | `toml` |
| **`cli`** | Command-line interface binaries (`sth`, `strhide`, `sthc`, `sths`, `sthv`) | `clap`, `rpassword`, `base64`, `config`, all domains |

### Adding strhide as a Dependency

```toml
# 1. Full library (default: structure + content + analysis; zero CLI dependencies)
strhide = "0.9.3"

# 2. Container/structural hiding only (lightweight, zero disassembly dependency)
strhide = { version = "0.9.3", default-features = false, features = ["structure-base"] }

# 3. Image steganography only (PNG + JPEG)
strhide = { version = "0.9.3", default-features = false, features = ["content-png", "content-jpeg"] }

# 4. Audio steganography only (WAV + FLAC)
strhide = { version = "0.9.3", default-features = false, features = ["content-audio"] }

# 5. Steganalysis & carrier forensics only
strhide = { version = "0.9.3", default-features = false, features = ["analysis"] }
```

---

## Library Usage Guide

### Architecture & Prelude

The crate is organized into clean conceptual layers:
- **`facade`**: The recommended unified entry point ([`StrHide`](#the-facade-strhide)).
- **`structure`**: Container-level injection & 100% bit-exact restoration ([`PayloadSource`], [`WriteOptions`], [`ReadOptions`], [`RestoreOptions`]).
- **`stego`**: Content-adaptive steganography ([`EmbedOptions`], [`ExtractOptions`], [`ProbeOptions`]).
- **`analysis`**: Black-box inspection and heuristic steganalysis.
- **`prelude`**: Commonly used types re-exported for convenience:

```rust
use strhide::prelude::*;
```

---

### The Facade: `StrHide`

[`StrHide`] is thread-safe and implements `Copy`. It binds:
1. One **`Dialect`** (the private deployment keys and wire identities).
2. One **`LocalParams`** (writer baseline: chunk sizes, compression, rejection policies).

Both path-based and in-memory byte-based methods are provided:

```rust
use strhide::facade::StrHide;
use strhide::structure::{PayloadSource, ReadOptions, WriteOptions};

fn main() -> Result<(), strhide::errors::StrHideError> {
    let engine = StrHide::new();

    // --- In-Memory Byte API ---
    let cover_png = std::fs::read("tests/assets/small.png")?;
    let payload = b"Secret payload content";

    // Write payload into carrier bytes
    let (stego_bytes, write_res) = engine.structure().write_bytes(
        &cover_png,
        PayloadSource::Bytes(payload),
        &WriteOptions {
            password: Some("vault-pass"),
            ..WriteOptions::default()
        },
    )?;
    println!("Embedded {} bytes into envelope", write_res.ube_size);

    // Read payload back from carrier bytes
    let read_res = engine.structure().read_bytes(&stego_bytes, Some("vault-pass"))?;
    assert_eq!(read_res.data, payload);

    // Restore original carrier bytes (bit-exact check against recorded SHA-256)
    let (restored_bytes, _) = engine.structure().restore_bytes(&stego_bytes, Some("vault-pass"))?;
    assert_eq!(restored_bytes, cover_png);

    Ok(())
}
```

---

### Private Dialects & Custom Profiles

By default, carriers without a user password are encrypted under strhide's built-in public key constants so that official binaries can interoperate. 

For isolated environments, you can define a **private dialect** at compile-time with **zero runtime cost**:

```rust
use strhide::facade::{Dialect, StrHide};

// Constant private dialect compiled into your application:
const ENGINE: StrHide = StrHide::new().with_dialect(
    Dialect::new().with_default_secret("organization-master-deployment-secret")
);

// Stock strhide binaries will fail to locate or decrypt envelopes written by ENGINE.
```

---

### Structure Domain (Container Hiding & 100% Bit-Exact Restore)

The structure domain embeds payloads into container structures (e.g. PNG private chunks, JPEG COM segments, MP4/MOV UUID boxes, ZIP pre-central-directory, PDF incremental revisions, PE slack/overlay/codebits).

The bit-exact guarantee covers the structure-domain envelope only. A content-domain embed re-encodes the media in place, so a carrier written and then re-encoded cannot be restored: `restore` compares the full SHA-256 and fails closed with `RestoreMismatch` instead of emitting a non-matching file. The CLI also refuses to add a second domain to an occupied carrier unless `--overwrite` is explicit.

```rust
use std::path::Path;
use strhide::facade::StrHide;
use strhide::structure::{PayloadSource, ReadOptions, RestoreOptions, WriteOptions};

fn run_structure() -> Result<(), strhide::errors::StrHideError> {
    let engine = StrHide::new();
    let carrier = Path::new("report.pdf");

    // 1. Write payload to a safe output file: "report-out.pdf"
    let write_opts = WriteOptions {
        password: Some("my-password"),
        password_hint: Some("company project codename"),
        stealth: false,         // Set true for plausible deniability (derived headers)
        output_path: Some(Path::new("report-out.pdf")),
        ..WriteOptions::default()
    };
    engine.structure().write_file(carrier, PayloadSource::Text("Confidential briefing"), &write_opts)?;

    // 2. Read payload from carrier
    let read_opts = ReadOptions::new()
        .with_password("my-password")
        .with_overwrite(true);
    let read_result = engine.structure().read_file(Path::new("report-out.pdf"), &read_opts)?;
    println!("Payload string: {}", String::from_utf8_lossy(&read_result.data));

    // 3. Restore carrier bit-for-bit
    let restore_opts = RestoreOptions {
        password: Some("my-password"),
        output_path: Some(Path::new("report-restored.pdf")),
        ..RestoreOptions::default()
    };
    engine.structure().restore_file(Path::new("report-out.pdf"), &restore_opts)?;

    // Byte-for-byte identity guaranteed:
    assert_eq!(std::fs::read(carrier)?, std::fs::read("report-restored.pdf")?);
    Ok(())
}
```

---

### Content Domain (Adaptive Image, Video, & Audio Steganography)

The content domain modulates pixel values, DCT frequency coefficients, CABAC bypass sign bits, or audio samples/residuals according to distortion cost models:

- **PNG**: Spatial domain HILL / S-UNIWARD / MiPOD with ternary $\pm 1$ matching constrained within eight-value classes (`val & 0xF8`).
- **JPEG**: DCT frequency domain UERD / J-UNIWARD / J-MiPOD with ternary STC and fixed-grid AC slots.
- **HEVC / H.265**: CABAC bypass sign-bit steganography with anti-emulation byte (EPB) collision evasion, yielding **zero file size expansion** ($\Delta = 0$) across MP4, MOV, MKV, and HEIC/HEIF carriers.
- **Audio (WAV & FLAC)**: WAV PCM sample-domain LSB matching, and FLAC residual prediction error steganography preserving Rice codeword lengths.

```rust
use strhide::core::payload::Payload;
use strhide::facade::StrHide;
use strhide::stego::{
    EmbedOptions, ExtractOptions, ProbeOptions, SafetyEnforcement, SafetyLevel,
    SafetyPolicy, SpatialAlgorithm, StegoTuning, PngParams,
};

fn run_content_stego(carrier_bytes: &[u8]) -> Result<(), strhide::errors::StrHideError> {
    let engine = StrHide::new();

    // 1. Probe maximum embedding capacity
    let probe_opts = ProbeOptions::default();
    let cap_info = engine.stego().probe(carrier_bytes, &probe_opts)?;
    println!("Carrier capacity: {} bytes (at safety tier: {})", cap_info.max_raw_payload_bytes, cap_info.safety_level);

    // 2. Embed payload into image pixels / DCT coefficients / audio samples
    let embed_opts = EmbedOptions {
        password: Some("stego-secret"),
        safety: SafetyPolicy {
            level: SafetyLevel::High,
            enforcement: SafetyEnforcement::Advisory,
        },
        tuning: StegoTuning::Png {
            model: SpatialAlgorithm::Hill,
            params: PngParams::default(),
        },
        ..EmbedOptions::default()
    };
    let payload = Payload::text("Discreet message embedded in carrier data");
    let stego_bytes = engine.stego().embed(carrier_bytes, &payload, &embed_opts)?;

    // 3. Extract payload from stego carrier
    let extract_opts = ExtractOptions {
        password: Some("stego-secret"),
        ..ExtractOptions::default()
    };
    let extracted_payload = engine.stego().extract(&stego_bytes, &extract_opts)?;
    assert_eq!(extracted_payload.as_bytes(), payload.as_bytes());

    Ok(())
}
```

---

### Dynamic Algorithm Discovery

Query available algorithms dynamically at runtime without hardcoding algorithm identifiers:

```rust
use strhide::formats::FileFormat;
use strhide::stego::{algorithms_for_format, list_stego_algorithms, StegoAlgorithmInfo};

fn discover_algorithms() {
    // List all registered steganography algorithms across all domains
    let all_algos: Vec<StegoAlgorithmInfo> = list_stego_algorithms();
    for info in all_algos {
        println!("{}: {} ({})", info.id, info.name, info.domain);
    }

    // Filter algorithms applicable to a specific carrier format (e.g. JPEG)
    let jpeg_algos = algorithms_for_format(FileFormat::Jpeg);
    for info in jpeg_algos {
        println!("JPEG Algorithm: {} (default: {})", info.name, info.is_default);
    }
}
```

---

### Diagnostics: Cross-Domain Inspection & Verification

Inspect headers, detect envelopes, verify cryptographic tags, and probe capacities across both structure and content domains:

```rust
use std::path::Path;
use strhide::facade::{DualOptions, StrHide};

fn run_diagnostics() -> Result<(), strhide::errors::StrHideError> {
    let engine = StrHide::new();
    let opts = DualOptions {
        password: Some("pwd"),
        ..Default::default()
    };

    // Inspect: detects format, envelope metadata, capacity per strategy
    let inspect_result = engine.inspect_any(Path::new("carrier.png"), &opts)?;
    println!("Format: {}", inspect_result.structure.format);
    if let Some(stego) = inspect_result.content {
        println!("Content Stego Detected: {}", stego.has_hidden_data);
    }

    // Verify: 3-level independent validation (L1 host integrity, L2 envelope structure, L3 AEAD decryption)
    let verify_result = engine.verify_any(Path::new("carrier.png"), &opts)?;
    assert!(verify_result.is_any_ok());

    Ok(())
}
```

---

### Steganalysis Domain (Black-Box Detection)

The `analysis` module inspects unknown carriers using structural anomaly detection, entropy measures, and calibrated DCT tests (`dct:calibration`):

```rust
use std::path::Path;
use strhide::facade::StrHide;

fn run_steganalysis() -> Result<(), strhide::errors::StrHideError> {
    let engine = StrHide::new();
    let report = engine.analysis().scan_file(Path::new("suspicious.jpg"))?;

    println!("Carrier verdict: {:?}", report.verdict); // Clean | Low | Suspicious | LikelyHidden
    println!("Overall anomaly score: {}/100", report.anomaly_score);
    for finding in &report.findings {
        println!("  - [{}] {}", finding.rule_id, finding.message);
    }
    Ok(())
}
```

---

### Configuration File Management

When the `config` feature is enabled, settings can be loaded from TOML configuration files:

```rust
use strhide::core::config;

// Lookup order (CWD is explicitly excluded for security):
// 1. Explicit path passed to load (if Some)
// 2. Executable-adjacent directory (<exe_dir>/strhide.toml, <exe_dir>/config.toml)
// 3. User configuration directory (~/.config/strhide/config.toml, %APPDATA%\strhide\config.toml)
// 4. System configuration directory (/etc/strhide/config.toml, %ProgramData%\strhide\config.toml)
let cfg = config::load(None)?;

println!("Configured default strategy: {:?}", cfg.strategy);
println!("Configured stego safety tier: {:?}", cfg.stego.as_ref().and_then(|s| s.safety.as_deref()));
```

> **Security Note**: In accordance with the security policy, configuration files do **not** store plaintext passwords or password file paths. Passwords must be provided at runtime via CLI parameters, `STRHIDE_PASSWORD`, or interactive prompts.

---

### Error Handling

All library functions return `Result<T, StrHideError>`. The enum is `#[non_exhaustive]`, so a wildcard arm is required; `StrHideError::kind()` returns a stable `ErrorKind` for callers that branch on behaviour instead of on message text (the CLI and the desktop app both do this):

```rust
use strhide::errors::StrHideError;

fn handle_errors(err: StrHideError) {
    match err {
        StrHideError::Password(msg) => eprintln!("Authentication failed: {msg}"),
        StrHideError::PasswordWithHint { message, hint } => {
            eprintln!("{message}");
            if let Some(hint) = hint {
                eprintln!("Hint: {hint}");
            }
        }
        // The payload does not fit this carrier (or the solve would exceed the
        // working-memory budget). Never reported as an unsupported format.
        StrHideError::PayloadTooLarge(detail) => eprintln!("Payload too large: {detail}"),
        StrHideError::SafetyThreshold { tier, required_bytes, available_bytes } => eprintln!(
            "Exceeds the '{tier}' tier: {required_bytes} bytes needed, {available_bytes} allowed"
        ),
        // Signed carriers (PE Authenticode, PDF ByteRange, signed JAR), read-only
        // inputs, and unwritable output directories all land here.
        StrHideError::Rejection(reason) => eprintln!("Refused for safety: {reason}"),
        StrHideError::NoHiddenData(_) => eprintln!("No hidden payload found"),
        StrHideError::RestoreMismatch { residual_envelope, .. } => {
            if residual_envelope {
                eprintln!("Another envelope is still present: remove envelopes newest-first");
            } else {
                eprintln!("The carrier changed after the write; the original is unrecoverable");
            }
        }
        StrHideError::General(msg) => eprintln!("Error: {msg}"),
        _ => eprintln!("Operation failed: {err}"),
    }
}
```

---

## CLI Quick Start

### Build CLI Binaries

```bash
cargo build --release --all-features
# Binaries placed in target/release/
```

### Domain-Specific Entry Points

`strhide` compiles five targeted CLI binaries from the same codebase:

| Binary | Available Subcommands | Description |
| :--- | :--- | :--- |
| **`sth`** / **`strhide`** | `write`, `read`, `restore`, `embed`, `extract`, `capacity`, `inspect`, `verify`, `scan`, `list` | Full command set |
| **`sthc`** | `write`, `read`, `restore` | Container structure hiding only |
| **`sths`** | `embed`, `extract`, `capacity` | Content-adaptive steganography only |
| **`sthv`** | `inspect`, `verify`, `scan`, `list` | Carrier verification, diagnostics, & steganalysis |

### Common CLI Commands

```bash
# Hide text in a photo (writes to photo-out.png)
strhide write photo.png -t "Secret message"

# Hide a ZIP file inside a PDF, encrypted with a password file and a hint
strhide write document.pdf -d archive.zip --password-file vault-pass.txt -H "Company vault"

# In-place hiding with automatic .bak backup
strhide write photo.png -t "Secret" --in-place

# Read payload back
strhide read photo-out.png --stdout
strhide read photo-out.png -o recovered/

# 100% bit-exact carrier restoration (structure domain; fails closed after a content embed)
strhide restore photo-out.png -o clean.png

# Content-adaptive steganography (HILL for PNG, UERD for JPEG)
strhide embed cover.jpg -t "Secret" -o stego.jpg
strhide extract stego.jpg --stdout

# HEVC CABAC bypass steganography (zero file size growth Δ=0)
strhide embed video.mp4 -t "Secret" -o stego.mp4

# Probe stego embedding capacity without modifying the file
strhide capacity photo.png

# Black-box steganalysis inspection
strhide scan suspicious.jpg
```

---

## Compatibility & License

- **Wire Specification**: Detailed packet headers, crypto primitives, and wire specs are documented in [`docs/api/spec/STRUCTURE-ENVELOPE.md`](../docs/api/spec/STRUCTURE-ENVELOPE.md) (UBE v2.2) and
  [`docs/api/spec/CONTENT-ENVELOPE.md`](../docs/api/spec/CONTENT-ENVELOPE.md) (V4 content envelope, incl. which
  parts are frozen wire format and which are free to change). The full document map is in
  [`docs/api/spec/README.md`](../docs/api/spec/README.md).
- **License**: Apache-2.0. See [LICENSE](../LICENSE).
