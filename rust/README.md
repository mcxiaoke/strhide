# strhide (Rust)

Rust implementation of **strhide** — smart, format-preserving, lossless data hiding and content-adaptive steganography. Compiles to a high-performance library crate (`strhide`) and static CLI binaries.

See the [root README](../README.md) for project-wide architecture, and [README.zh.md](../README.zh.md) for the Chinese documentation.

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
  - [Content Domain (Adaptive Image & Video Steganography)](#content-domain-adaptive-image--video-steganography)
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
- `cargo add strhide` **never** drags in heavy CLI or terminal dependencies like `clap`, `rpassword`, or `base64`.
- All features are strictly additive and compile without warnings under `-D warnings`.

### Feature Matrix

| Feature | Description | Extra Dependencies |
| --- | --- | --- |
| **`default`** | Full library capabilities: both domains + steganalysis | — |
| `core-io` | Atomic filesystem commit & timestamp preservation | `filetime` |
| **`structure-base`** | Container hiding for PNG, JPEG, MP4, ZIP, PDF, PE slack/overlay | `serde_json`, `core-io` |
| **`structure-pe`** | Adds x86/x64 instruction substitution (`pe_codebits`) | `iced-x86`, `structure-base` |
| **`structure`** | Meta-feature enabling the full structure domain | `structure-base`, `structure-pe` |
| `content-base` | Steganography foundation: Rayon thread pool, cost model traits, generic STC | `rayon`, `core-io` |
| **`content-png`** | Spatial image steganography (HILL, S-UNIWARD, ternary ±1 matching) | `content-base` |
| **`content-jpeg`** | DCT frequency domain image steganography (UERD, ternary STC) | `dct-io`, `content-base` |
| **`content-hevc`** | H.265/HEVC CABAC bypass sign-bit steganography (Annex-B & MP4/MOV bitstreams) | `oxideav-h265`, `rusty_h265`, `content-base` |
| **`content-heif-bridge`**| HEIF/HEIC container & thumbnail transcoding bridge | `content-hevc`, `content-png`, `content-jpeg` |
| **`content`** | Meta-feature enabling all content steganography engines | `content-png`, `content-jpeg`, `content-hevc`, `content-heif-bridge` |
| **`analysis`** | Black-box steganalysis (JPEG calibrated DCT `dct:calibration`, UBE envelopes) | `jpeg-decoder`, `dct-io`, `structure` |
| **`config`** | TOML configuration file support (`strhide.toml`, user/system configs) | `toml` |
| **`cli`** | Command-line interface binaries (`sth`, `strhide`, `sthc`, `sths`, `sthv`) | `clap`, `rpassword`, `base64`, `config`, all domains |

### Adding strhide as a Dependency

Choose the feature set suited for your deployment:

```toml
# 1. Full library (default: structure + content + analysis; no CLI dependencies)
strhide = "0.8"

# 2. Minimal container/structural hiding (lightweight, zero disassembly dependency)
strhide = { version = "0.8", default-features = false, features = ["structure-base"] }

# 3. Structural hiding including PE code substitution
strhide = { version = "0.8", default-features = false, features = ["structure"] }

# 4. Pure image steganography (PNG + JPEG)
strhide = { version = "0.8", default-features = false, features = ["content-png", "content-jpeg"] }

# 5. Steganalysis & carrier forensics only
strhide = { version = "0.8", default-features = false, features = ["analysis"] }
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

[`StrHide`] is cheap, thread-safe, and implements `Copy`. It binds:
1. One **`Dialect`** (the private deployment keys and wire identities).
2. One **`LocalParams`** (writer baseline: chunk sizes, compression, rejection policies).

Both path-based and in-memory byte-based methods are provided:

```rust
use strhide::facade::StrHide;
use strhide::structure::{PayloadSource, ReadOptions, WriteOptions};

fn main() -> Result<(), strhide::errors::StrHideError> {
    let engine = StrHide::new();

    // --- In-Memory Byte API ---
    let cover_png = std::fs::read("tests/fixtures/carrier.png")?;
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
    println!("Embedded {} bytes into envelope", write_res.envelope_size);

    // Read payload back from carrier bytes
    let read_res = engine.structure().read_bytes(&stego_bytes, Some("vault-pass"))?;
    assert_eq!(read_res.data, payload);

    // Restore original carrier bytes (bit-exact check against recorded SHA-256)
    let (restored_bytes, _) = engine.structure().remove_bytes(&stego_bytes, Some("vault-pass"))?;
    assert_eq!(restored_bytes, cover_png);

    Ok(())
}
```

---

### Private Dialects & Custom Profiles

By default, without a user password, carriers are encrypted under strhide's built-in public constants so that official binaries can interoperate. 

For closed environments, you can define a **private dialect** at compile-time with **zero runtime cost**:

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

The structure domain embeds payloads into container structures (e.g. PNG private ancillary chunks, JPEG APP15 segments, MP4 UUID boxes, ZIP pre-central-directory, PDF incremental revisions, PE slack/overlay/codebits).

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
        stealth: false,         // Set true for plausible deniability (header magics derived from password)
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
    engine.structure().remove_file(Path::new("report-out.pdf"), &restore_opts)?;

    // Byte-for-byte identity guaranteed:
    assert_eq!(std::fs::read(carrier)?, std::fs::read("report-restored.pdf")?);
    Ok(())
}
```

---

### Content Domain (Adaptive Image & Video Steganography)

The content domain modulates pixel values, DCT frequency coefficients, or H.265/HEVC CABAC bypass sign bits according to distortion cost models (HILL, UERD, Scheme C):

- **PNG**: Spatial domain HILL / S-UNIWARD with ternary $\pm 1$ matching constrained within eight-value classes (`val & 0xF8`) to evade SPA/RS detectors.
- **JPEG**: DCT frequency domain UERD / J-UNIWARD with ternary STC and fixed-grid AC slots.
- **HEIF / HEIC / HEVC**: CABAC bypass sign-bit steganography with EPB (anti-emulation) collision evasion, yielding **zero file size expansion** ($\Delta = 0$).

```rust
use std::path::Path;
use strhide::facade::StrHide;
use strhide::stego::{EmbedOptions, ExtractOptions, ProbeOptions, SafetyLevel, SafetyPolicy};

fn run_content_stego() -> Result<(), strhide::errors::StrHideError> {
    let engine = StrHide::new();

    // 1. Probe maximum embedding capacity
    let probe_opts = ProbeOptions::default();
    let cap_info = engine.stego().probe_file(Path::new("photo.jpg"), &probe_opts)?;
    println!("Carrier capacity: {} bytes (at safety tier: {:?})", cap_info.capacity, cap_info.safety_tier);

    // 2. Embed payload into image DCT coefficients
    let embed_opts = EmbedOptions {
        password: Some("stego-secret"),
        safety: SafetyPolicy {
            tier: SafetyLevel::High,     // Paranoid | High | Balanced
            enforce: true,               // Refuse payload if it exceeds safety tier
        },
        ..EmbedOptions::default()
    };
    let payload = b"Discreet message in frequency coefficients";
    engine.stego().embed_file(
        Path::new("photo.jpg"),
        payload,
        Some(Path::new("photo-stego.jpg")),
        &embed_opts,
    )?;

    // 3. Extract payload from stego image
    let extract_opts = ExtractOptions {
        password: Some("stego-secret"),
        ..ExtractOptions::default()
    };
    let extracted = engine.stego().extract_file(
        Path::new("photo-stego.jpg"),
        None, // In-memory extraction
        &extract_opts,
    )?;
    assert_eq!(&extracted.data[..], payload);

    Ok(())
}
```

---

### Diagnostics: Cross-Domain Inspection & Verification

Inspect headers, detect envelopes, verify cryptographic tags, and probe capacities across both structure and content domains simultaneously:

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
use strhide::analysis::{scan_carrier, ScanOptions};

fn run_steganalysis() -> Result<(), strhide::errors::StrHideError> {
    let opts = ScanOptions::default();
    let report = scan_carrier(Path::new("suspicious.jpg"), &opts)?;

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
// 3. User configuration directory (~/.config/strhide/config.toml, ~/.strhide/config.toml, %APPDATA%\strhide\config.toml)
// 4. System configuration directory (/etc/strhide/config.toml, %ProgramData%\strhide\config.toml)
let cfg = config::load(None)?;

println!("Configured default strategy: {:?}", cfg.strategy);
println!("Configured stego safety tier: {:?}", cfg.stego.as_ref().and_then(|s| s.safety.as_deref()));
```

> **Security Note**: In accordance with the security policy, configuration files do **not** store plaintext passwords or password file paths. Passwords must be provided at runtime via CLI parameters, `STRHIDE_PASSWORD`, or interactive prompts.

---

### Error Handling

All library functions return `Result<T, StrHideError>`. Common error variants include:

```rust
use strhide::errors::StrHideError;

fn handle_errors(err: StrHideError) {
    match err {
        StrHideError::Password(msg) => eprintln!("Authentication failed: {msg}"),
        StrHideError::PasswordWithHint { hint, .. } => eprintln!("Password required. Hint: {hint}"),
        StrHideError::CarrierTooSmall { needed, available } => {
            eprintln!("Payload too large: needed {needed} bytes, available {available} bytes");
        }
        StrHideError::SignedBinaryRejected(msg) => eprintln!("Security refusal: {msg}"),
        StrHideError::General(msg) => eprintln!("Error: {msg}"),
        _ => eprintln!("Operation failed: {err}"),
    }
}
```

---

## CLI Quick Start

### Build CLI Binaries

```bash
cargo build --release --features cli
# Binaries placed in target/release/
```

### Domain-Specific Entry Points

`strhide` compiles four targeted CLI binaries from the same codebase:

| Binary | Available Subcommands | Description |
| --- | --- | --- |
| **`sth`** / **`strhide`** | `write`, `read`, `restore`, `embed`, `extract`, `capacity`, `inspect`, `verify`, `scan`, `list` | Full command set |
| **`sthc`** | `write`, `read`, `restore` | Container structure hiding only |
| **`sths`** | `embed`, `extract`, `capacity` | Content-adaptive steganography only |
| **`sthv`** | `inspect`, `verify`, `scan`, `list` | Carrier verification, diagnostics, & steganalysis |

### Common CLI Commands

```bash
# Hide text in a photo (writes to photo-out.png)
strhide write photo.png -t "Secret message"

# Hide a ZIP file inside a PDF, encrypted with password and a hint
strhide write document.pdf -d archive.zip -p "P@ss123" --hint "Company vault"

# In-place hiding with automatic .bak backup
strhide write photo.png -t "Secret" --in-place

# Read payload back
strhide read photo-out.png --stdout
strhide read photo-out.png -o recovered/

# 100% bit-exact carrier restoration
strhide restore photo-out.png -o clean.png

# Content-adaptive steganography (HILL for PNG, UERD for JPEG)
strhide embed cover.jpg -t "Secret" -o stego.jpg
strhide extract stego.jpg --stdout

# HEIF/HEIC CABAC bypass steganography (zero file size growth Δ=0)
strhide embed photo.heic -t "Secret" -o stego.heic

# Probe stego embedding capacity without modifying the file
strhide embed photo.png --capacity

# Black-box steganalysis inspection
strhide scan suspicious.jpg
```

---

## Compatibility & License

- **Wire Specification**: Detailed packet headers, crypto primitives, and wire specs are documented in [`docs/api/WIRE_SPEC.md`](../docs/api/WIRE_SPEC.md).
- **Python Version**: The legacy Python implementation in `python/` is frozen at 0.2.0 and not compatible with modern 0.8+ UBE envelopes.
- **License**: Apache-2.0. See [LICENSE](../LICENSE).
