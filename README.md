# strhide

**Format-preserving, lossless data hiding and steganography tool.** Hide data inside carrier files (PNG, JPEG, WebP, HEIC/HEIF, MP4, MOV, MKV, WAV, FLAC, ZIP, Office documents, PDF, Windows PE executables) while preserving file format compliance and visual/auditory integrity.

---

## 1. Project Structure

```text
strhide/
├── rust/        # Core Rust library crate (`strhide`) and static CLI binaries
├── gui/         # Desktop application `StrHideStudio` (Tauri 2 + React + TypeScript)
├── docs/        # Technical specifications, architecture docs, wire format, and changes logs
│   ├── smart_file_data_hiding_design.md   # Overall technical design specification
│   ├── api/
│   │   ├── ARCHITECTURE.md                # System architecture, facades, and modules
│   │   ├── STEGO-API.md                   # Content domain steganography API guide
│   │   ├── WIRE_SPEC.md                   # Wire format index (both domains)
│   │   ├── WIRE_SPEC_STRUCTURE.md         # Structure domain UBE v2.2 wire format
│   │   └── WIRE_SPEC_CONTENT.md           # Content domain V4 envelope wire format
│   └── CHANGES-*.md                       # Chronological engineering change logs
├── scripts/     # Baseline hash verification, regression testing, and CI scripts
└── testdata/    # Test fixtures and baseline multi-format corpus
```

---

## 2. Capabilities & Domains

strhide operates across two independent domains. They can be composed on one carrier at the library level, but the CLI rejects a second domain unless `--overwrite` is given, and restoration guarantees apply to the structure-domain envelope only:

| Domain | Carrier Formats | Techniques & Models | Restoration |
| :--- | :--- | :--- | :--- |
| **Structure Domain** (Container Envelope) | PNG, JPEG, WebP, MP4, MOV, WAV, MKV, ZIP (`.zip`, `.jar`, `.docx`, `.xlsx`, `.pptx`), PDF, Windows PE (`.exe`, `.dll`) | Structural gap injection (private chunks, comment markers, unreferenced stream objects, central directory pre-injection, PE slack/codebits) | **100% bit-exact restoration** of the pre-write host (verified via full SHA-256); fails closed with `RestoreMismatch` if the carrier was re-encoded after the write, e.g. by a content-domain embed |
| **Content Domain** (Media Steganography) | PNG, JPEG, HEVC/H.265 (MP4, MOV, MKV, HEIC/HEIF, Annex-B), Audio (WAV, FLAC) | Adaptive cost models (PNG: HILL/S-UNIWARD/MiPOD; JPEG: UERD/J-UNIWARD/J-MiPOD; HEVC: CABAC bypass sign-bit Scheme C, $\Delta = 0$; Audio: WAV PCM LSB, FLAC residual matching) | Irreversible modification (lossless restoration not applicable) |
| **Diagnostics** | All supported formats | Structural inspection, cryptographic verification, and black-box steganalysis (`scan`) | Read-only analysis |

---

## 3. CLI Usage

### Binaries & Aliases
The CLI is distributed as a unified binary (`strhide` / `sth`) and three domain-specific entry points:

* `strhide` / `sth`: Full entry point (all 10 commands).
* `sthc`: Container structure domain (`write`, `read`, `restore`).
* `sths`: Media steganography domain (`embed`, `extract`, `capacity`).
* `sthv`: Diagnostics and analysis (`inspect`, `verify`, `scan`, `list`).

### Common Commands

```bash
# ── Structure Domain ──
# Hide secret into carrier (default writes to <name>-out.<ext>)
sth write report.pdf -d secret.zip -p "password" -H "hint text"     # [alias: w]

# Read/extract hidden payload (refuses overwrite unless --overwrite)
sth read report-out.pdf -o out/ -p "password"                       # [alias: r]

# Restore the pre-write host bit-exactly (structure domain; fails closed if the carrier was re-encoded)
sth restore report-out.pdf -o report-restored.pdf                   # [alias: s]

# ── Content Domain (Adaptive Steganography) ──
# Probe carrier embedding capacity
sth capacity photo.jpg                                              # [alias: c]

# Embed payload into image/video/audio coefficients
sth embed photo.jpg -t "secret message" -o stego.jpg -p "password"   # [alias: e]

# Extract payload from stego carrier
sth extract stego.jpg -o secret.txt -p "password"                   # [alias: x]

# ── Diagnostics & Forensics ──
sth inspect carrier.png [--json]                                    # Inspect structure and headers
sth verify carrier.png -p "password"                                # Verify cryptographic integrity
sth scan target_folder/ -r                                          # Black-box steganalysis
sth list                                                            # List formats and capacity limits [alias: l]
```

> [!NOTE]
> **Content-domain payloads are bound to the carrier's metadata.** The
> steganographic locator keys are derived from the container's metadata
> summary, so a stego file must be kept exactly as produced: editing metadata
> or re-saving with a tool that rewrites ancillary chunks (e.g. PNG
> `tEXt`/`gAMA`/`iCCP`, JPEG APPn) makes the payload unreadable —
> indistinguishable from a wrong password. A pure IDAT/recompression pass that
> preserves metadata is safe. Always keep the original stego file.
>
> **Capacity reports** (`sth capacity`) reflect the minimal envelope framing
> (no filename; carrying a filename costs `1 + name_len` extra bytes) and are
> additionally bounded by the engine's working-memory budget, so the reported
> maximum is always writable. Exceeding it fails before any write with a
> "capacity exceeded" error.

---

## 4. Desktop Client (`StrHideStudio`)

The desktop client is located in `gui/`, developed with **Tauri 2**, **React**, **TypeScript**, and **Tailwind CSS**.

* **Dynamic Algorithm Discovery**: Queries the core engine at runtime (`get_stego_algorithms_cmd`) and filters available algorithms based on the carrier format context.
* **Two-Phase Extraction Cache**: Eliminates redundant decoding and Argon2id KDF recomputation when previewing metadata and saving payloads.
* **Thread Isolation & Live Logs**: Dedicated background thread pools with `catch_unwind` isolation and a floating diagnostic log modal.
* **Development & Build**:
  ```bash
  cd gui
  pnpm install
  pnpm build         # Frontend TypeScript check and Vite build
  pnpm tauri dev     # Launch desktop app in development mode
  ```

---

## 5. Further Documentation

* [Technical Implementation Specification](docs/smart_file_data_hiding_design.md): In-depth protocol specification, adapter algorithms, and safety matrices.
* [System Architecture & Public API](docs/api/ARCHITECTURE.md): Crate module topology, facade APIs, and pipeline designs.
* [Stego Content Domain API Guide](docs/api/STEGO-API.md): API reference for content-adaptive steganography and algorithm introspection.
* [Wire Format Specification (index)](docs/api/WIRE_SPEC.md): Which document covers which domain.
* [Structure Domain Wire Format](docs/api/WIRE_SPEC_STRUCTURE.md): UBE v2.2 binary layouts, AAD, stealth masks, compat matrix.
* [Content Domain Wire Format](docs/api/WIRE_SPEC_CONTENT.md): V4 envelope, stability classes (frozen / dialect / free), key derivation, slot selection, STC syndrome, HILL cost ranking.
* [Rust Library Usage Guide](rust/README.md): Detailed documentation on using `strhide` as a Rust crate dependency.
* [Chinese Documentation / 中文文档](README.zh.md)
