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
│   │   ├── WIRE_SPEC.md                   # Wire format index (redirects to spec/)
│   │   ├── spec/                          # Normative wire-format specs (per topic)
│   │   │   ├── README.md                  # Overview, terminology, doc map
│   │   │   ├── CRYPTO.md                  # Key derivation and AEAD (both domains)
│   │   │   ├── DETMATH.md                 # Deterministic math semantics
│   │   │   ├── CAPACITY.md                # Capacity formulas and limits
│   │   │   ├── CONTENT-*.md               # Content domain (envelope + carriers)
│   │   │   ├── STRUCTURE-*.md             # Structure domain (UBE + adapters)
│   │   │   └── CORRECTIONS.md             # Old WIRE_SPEC errata
│   │   ├── WIRE_SPEC_STRUCTURE.md         # Legacy structure domain doc (non-normative)
│   │   └── WIRE_SPEC_CONTENT.md           # Legacy content domain doc (non-normative)
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
> **Content-domain payloads are bound to the carrier's pixels, not its tags.**
> The steganographic locator keys are derived from the image identity (PNG:
> geometry plus critical chunks; JPEG: DC coefficients; WAV/FLAC: stream
> parameters), so metadata-only edits are safe: adding or rewriting PNG
> `tEXt`/`iCCP`/`tIME`/`gAMA` chunks (exiftool, image optimisers, an editor's
> "save as") no longer makes the payload unreadable, and a lossless
> IDAT/recompression pass that keeps the pixels is safe too. Anything that
> changes the pixels does destroy it — lossy re-encoding, cropping, resizing —
> and the failure is indistinguishable from a wrong password. Keep the original
> stego file.
>
> **Capacity reports** (`sth capacity`) reflect the minimal envelope framing
> (no filename; carrying a filename costs `1 + name_len` extra bytes) and are
> additionally bounded by the engine's working-memory budget, so the reported
> maximum is always writable. Exceeding it fails before any write with a
> "capacity exceeded" error.

---

## 4. Performance

Measured with in-memory library APIs on an Intel i7-11700 (8C/16T) / Windows 10 / `--release` (LTO) build:
fixed password, fixed seed, 20 samples per cell, **includes PBKDF2, excludes disk I/O**.

* **Structure domain** — **20–46 ms** write, **20–28 ms** read across 9 container formats and 4 KiB–4 MiB payloads.
  Dominated by the fixed key-derivation cost; payload and carrier size barely move the number.
* **Content domain** — **0.06–14.6 s** embed (extraction is 16–73 % of that) across all 9 stego algorithms
  (PNG ×3, JPEG ×3, HEVC video/still, WAV, FLAC). The engine/container path sets the order of magnitude;
  payload size sets the slope within one engine. Carrier size, resolution and duration alone do **not** predict
  cross-engine cost.

See [BENCHMARK.md](BENCHMARK.md) for the two summary tables, plus the full
[structure](docs/BENCH_STRUCTURE_20261107.md) and [content](docs/BENCH_CONTENT_20261107.md) reports
for methodology, variance and raw samples.

---

## 5. Desktop Client (`StrHideStudio`)

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

## 6. Further Documentation

* [Performance Baseline (short)](BENCHMARK.md): Two summary tables + the dominant cost factors.
* [Structure Domain Benchmark](docs/BENCH_STRUCTURE_20261107.md) / [Content Domain Benchmark](docs/BENCH_CONTENT_20261107.md): Full methodology, per-cell statistics and raw samples.
* [Technical Implementation Specification](docs/smart_file_data_hiding_design.md): In-depth protocol specification, adapter algorithms, and safety matrices.
* [System Architecture & Public API](docs/api/ARCHITECTURE.md): Crate module topology, facade APIs, and pipeline designs.
* [Stego Content Domain API Guide](docs/api/STEGO-API.md): API reference for content-adaptive steganography and algorithm introspection.
* [Wire Format Specification (index)](docs/api/spec/README.md): Document map, terminology, byte order, version policy, and per-topic normative specs.
* [Structure Domain Wire Format](docs/api/spec/STRUCTURE-ENVELOPE.md): UBE v2.2 envelope plus per-format adapters under `docs/api/spec/STRUCTURE-*.md`.
* [Content Domain Wire Format](docs/api/spec/CONTENT-ENVELOPE.md): V4 envelope, stability classes (frozen / dialect / free), key derivation, slot selection, STC syndrome, and per-carrier cost models under `docs/api/spec/CONTENT-*.md`.
* [Rust Library Usage Guide](rust/README.md): Detailed documentation on using `strhide` as a Rust crate dependency.
* [Chinese Documentation / 中文文档](README.zh.md)
