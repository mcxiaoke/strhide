# CAPACITY — Capacity Formulas and Operational Limits Specification

**Status**: Normative. This document specifies capacity metrics, working set budgets, and hard limits across both content and structural domains in `strhide`.  
**Scope**: Capacities reported by `probe` / `inspect`, capacity admission gates in `embed` / `write`, and `PayloadTooLarge` error criteria.  
**Navigation**: [Specification Overview](./README.md) · [Content Domain Envelope](./CONTENT-ENVELOPE.md) · [Structural Domain Envelope](./STRUCTURE-ENVELOPE.md) · [Deterministic Math](./DETMATH.md).

Tiers: Capacity formulas and structural overheads are **Tier F**; working set budget gates are **Tier F** (`probe` and `embed` MUST share the exact same evaluation metrics); pure reporting-level adapter maximums are **Tier I**; long-video estimation accuracy is **Tier I**.

---

## 1. Unified Content Domain Formula

```text
header_slots = base_slots + ext_slots
body_slots   = total_slots - header_slots          (0 if total_slots < header_slots)
message_bits = floor(body_slots / u) - (h - 1)     (STC; see coding/stc.rs:390-392)
max_payload  = floor(message_bits / 8) - 22        (BODY_OVERHEAD)
```

- `BODY_OVERHEAD = 22 = 4 bytes length + 1 flags + 1 minimum micro-header + 16 AEAD tag` (`rust/src/stego/envelope.rs:90-97`).
- 26-bit `body_len` maximum: `HEADER_LEN_MAX = 67,108,863` (`rust/src/stego/header.rs:16-20`).
- Plaintext upper bound: `MAX_PLAINTEXT_LEN = HEADER_LEN_MAX - 22 = 67,108,841` (`rust/src/stego/envelope.rs:99-102`).
- All `probe` reported values represent **raw payload bytes**, excluding the file micro-header. Internally, engines debit `22 B`; public entry points `probe` / `embed` subsequently deduct `MAX_FILENAME_OVERHEAD = 1 + 255 = 256` via `filename_safe_capacity`, ensuring reported capacity remains safe even for payloads with the maximum possible filename length (`rust/src/stego/mod.rs:276-290`, `:503`, `:267`; `rust/src/stego/io.rs:102-106`).
- Consequently, a given carrier has two distinct metrics: engine-internal `max_raw_payload_bytes` (deducts 22) and the public API reported capacity (deducts an additional 256). The specification mandates that within the **same API entry point family**, `probe` and `embed` MUST use identical metrics and MUST NOT be mixed.

**Uniform Evaluation Requirement**: `probe` and `embed` MUST reuse the identical calculation function, identical `ext_len`, identical `stc_h / u`, identical working set budget gate, and identical `filename_safe_capacity` post-processing. Otherwise, capacities reported by `probe` will be rejected at embed time.

---

## 2. Carrier-Specific Rules (Content Domain)

### 2.1 PNG
- `total_slots`: Modifiable pixel slots satisfying cost model candidate selection and `class_rule = 1` filtering. Evaluates green channel single-channel pool first; if payload exceeds capacity, falls back to RGB triple-channel pool (Alpha channel is never touched). See `rust/src/stego/png/engine.rs:1370-1377`, `:1613-1618`, `:2569-2573`.
- `base_slots = 512` (64-byte base header, 1 slot = 1 bit); `ext_slots = 8 * ext_len` (`rust/src/stego/header.rs:153-156`, `rust/src/stego/png/engine.rs:1197`, `:1283`).
- `h / u`: STC constraint $h \in [4, 10]$, spatial $u \in [1, 3]$ (`rust/src/stego/coding/stc.rs:78-91`); defaults to $h = 8$, while `Auto` selects $u$ based on slot-to-bit ratio; Hamming coding fixes $k = 3$.
- Maximum pixel limit: `MAX_PNG_PIXELS = 64 * 1024 * 1024` (`rust/src/stego/png/engine.rs:506`).
- `max_payload` is obtained via binary search using `body_payload_fits`, debited directly against actual codec / $u$ values (`rust/src/stego/png/engine.rs:2472-2513`).

### 2.2 JPEG
- `total_slots = block_count * grid_rule.slots_per_block()`; defaults to `GridRule::ALL_AC`, i.e., $k = 1 \dots 63$ per block, yielding 63 slots per block (`rust/src/stego/jpeg/engine.rs:1819-1821`, `rust/src/stego/format.rs:53-63`).
- `base_slots = 718 = 2 * (44 * 8 + 8 - 1)` (`rust/src/stego/format.rs:156-159`); `ext_slots = 4 * (8 * ext_len + 8 - 1) = 4 * (8 * ext_len + 7)` (`rust/src/stego/format.rs:161-168`, default profile `:240-248`).
- `h / u`: Base header uses $sb\_h = 8, sb\_u = 2$; extension uses $ext\_h = 8, ext\_u = 4$; body allows $h \in [4, 10], u \in [1, 64]$ (`rust/src/stego/format.rs:181-191`).
- If Huffman tables are over-optimized (`has_incomplete_table`), the grouped upper bound at $u = 3$ replaces geometric bounds (`rust/src/stego/jpeg/engine.rs:1837-1854`).
- `max_payload = max_bits / 8 - 22` (`rust/src/stego/jpeg/engine.rs:1837-1856`).

### 2.3 WAV
- `total_slots = data_len / bytes_per_sample`, representing all PCM sample components inside the `data` chunk (`rust/src/stego/audio/wav.rs:59-63`, `:240-243`).
- `base_slots = 512`; `ext_slots = 8 * ext_len` (`rust/src/stego/audio/core.rs:568`, `:711`).
- $h = 8$ (`DEFAULT_STC_H`, `rust/src/stego/coding/stc.rs:78`); $u \ge 1$, `Auto` selects $u \in [1, 3]$.
- `max_payload` is calculated analytically via closed-form `payload_bytes_from_slots`, bounded by the 768 MiB working set limit (`rust/src/stego/audio/core.rs:349-373`, `:388-402`).

### 2.4 FLAC
- `total_slots = total_usable + 512`: `total_usable` represents **movable residual slots** tallied after frame-by-frame decoding, not total samples (`rust/src/stego/audio/flac/mod.rs:886-892`, `:1026-1028`).
- Body debits only `512`; extension bytes ($8 \times \text{ext\_len}$) occupy subframe tails without consuming residual pool capacity (`rust/src/stego/audio/core.rs:1023-1026`); $h = 8$, `min_group = 3`, meaning $u \ge 3$ (`rust/src/stego/audio/flac/mod.rs:894-896`).
- Capacity reporting and embedding share identical `capacity_info` logic (`rust/src/stego/audio/core.rs:388-451`).

### 2.5 HEVC
- `total_slots`: Total count of CABAC-absorbable bins within selected slices (`rust/src/stego/hevc/engine.rs:818`, `:856`); exact mode scans comprehensively via `scan_hevc_slot_count` (`:522-523`).
- `base_slots = 524 = 2 * (32 * 8 + 7 - 1)` (`rust/src/stego/hevc/engine.rs:89-94`); `ext_slots = 2 * (8 * ext_len + 6)`, or 0 when $\text{ext\_len} = 0$ (`:130-142`, `:316`, `:427`).
- $h = 7, u = 2$ fixed (`rust/src/stego/hevc/engine.rs:130-134`); extension length maximum is 64 bytes (`:123-124`).
- `max_payload` uses `hevc_max_raw_payload`, identical across probe and embed (`rust/src/stego/hevc/engine.rs:470-500`, `:860`).

### 2.6 Working Memory Budgets (Capacity Gate Requirement)

| Carrier | Budget | Sizing Formula |
|---|---|---|
| PNG | 8 GiB | `64 MiB + 61 B / pixel`, plus `24 B` per body slot (STC adds backtrack bitmap), `rust/src/stego/png/engine.rs:516-534`, `:558-560` |
| JPEG | 8 GiB | Base bytes + $\lceil 2^{\min(h, 10)} / 64 \rceil \times 8 \text{ B}$ per slot, `rust/src/stego/jpeg/engine.rs:100`, `:196-201`, `:1833` |
| WAV / FLAC | 768 MiB | $n \times (\lceil 2^{(h-1) + (u > 1)} / 64 \rceil \times 8 + 1 + 1 + 1 + 8)$, `rust/src/stego/audio/core.rs:69`, `:337-342`, `:371-373` |
| HEVC | No standalone budget | Gated by CABAC slot counts and banding strategy bounds, `rust/src/stego/hevc/engine.rs:895-898` |

Exceeding budget MUST be rejected as insufficient capacity (PNG: `PayloadTooLarge`, `rust/src/stego/png/engine.rs:536-549`; JPEG: `PayloadTooLarge`, `rust/src/stego/jpeg/engine.rs:164-190`).

### 2.7 20% Estimation for Long HEVC Videos
- When `exact = false` and carrier is an MP4 container: if selectable slice count $\le 150$, a **full scan** is performed (0% estimation error); otherwise $\text{sample\_limit} = \text{round}(\text{selectable} \times 0.20).\text{clamp}(150, 1000)$, extrapolating total slots across reference and non-reference bands according to their respective sampled byte-to-slot densities (`rust/src/stego/hevc/engine.rs:727-735`, `:803-823`).
- This samples a 20% slice subset, not the first 20% of the timeline window; setting `exact = true` / `--exact` forces a full scan (`:681-685`).
- Estimation belongs to **Tier I**: it affects reported probe capacity only, without altering the exact gate in `embed`, which always enforces true slot counts.

---

## 3. Structural Domain

### 3.1 Minimum Envelope and UBE Composition

```text
UBE = header(112) + hint_len + meta_len + trailer(24)        (engine.rs:1231-1240)
meta_len   = compact_meta_ciphertext + AEAD tag(16)
compact_meta = version(1) + name_len(2) + name + varint(raw_size) + digest(32) + varint(created_at)
payload    = framed_len(n, chunk_size) = n + chunks * 20, chunks = ceil(n / chunk_size) >= 1
```

- Minimum envelope size is given by `min_ube_len(payload_len)`: `112 + meta_len + framed_len(payload_len, CHUNK_SIZE) + 24`. Under current timestamps where the 7-bit varint takes 5 bytes, with an empty filename: `meta_len = 1 + 2 + 32 + varint(payload_len) + 5 + 16`. Hence `min_ube_len(0) = 213`, `min_ube_len(1) = 214` (`rust/src/structure/envelope.rs:102-132`). Legacy claims of `MIN_UBE_PLAIN=178 / MIN_UBE_ENCRYPTED=214` are inaccurate; these constants do not exist in code.
- 41B compact meta = $1 + 2 + 32 + 1 \text{ (1-byte varint for raw\_size)} + 5 \text{ (5-byte second-precision timestamp varint)}$; `hint` is capped at 1024 bytes; `meta` is capped at 256 KiB.
- Per-chunk framing overhead is strictly **20 B** (4B length prefix + 16B tag, `rust/src/core/crypto.rs:61-64`); default `CHUNK_SIZE = 2 MiB`, maximum `64 MiB` (`:96`, `:101`).

### 3.2 Capacity Metrics by Adapter

| Format | Capacity Metric (governed by `strategy_capacities`) | Reference |
|---|---|---|
| Generic EOF | Unbounded (file expands) | `rust/src/structure/adapters/eof.rs:25-33` |
| PNG | `chunk` maximum `0x7FFFFFFF`; if exceeded, falls back to `eof` | `rust/src/structure/adapters/png.rs:119-129` |
| JPEG | Nominal `app_segment` bound `JPEG_MAX_TOTAL_CAPACITY = 64 MiB`, further bounded by `MAX_JPEG_HEADER_SCAN = 16 MiB` and SOS displacement: $p + 4 \times \lceil p / 65533 \rceil \le 16 \text{ MiB} - \text{sos}$; SOS scan failure falls back to `eof` | `rust/src/structure/adapters/jpeg.rs:16-18`, `:198-216`, `:252-269` |
| WAV | Private `SHRD` RIFF chunk, bounded by $R + 8 + N + (N \& 1) \le \text{u32::MAX}$ and declared RIFF boundaries | `rust/src/structure/adapters/wav.rs:25-38`, `riff.rs:126-133`, `:468-473` |
| WebP | `SHRD` chunk permitted only in extended format (VP8X); otherwise falls back to `eof` | `rust/src/structure/adapters/webp.rs:25-50` |
| MKV | `ebml_void` or `eof`; reports "unbounded", but practically bounded by VINT limit and engine clamp | `rust/src/structure/adapters/mkv.rs:43-64` |
| MP4 | `box_uuid` / `eof`; reports "unbounded", practically bounded by engine clamp | `rust/src/structure/adapters/mp4.rs:66-72`, `isobmff.rs:415-435` |
| HEIF | Prefers `item_hidden` (requires parsable `meta` / `iinf` / `iloc`); otherwise `free_box` / `box_uuid` / `eof`; capacity metric $\sim 4 \text{ GiB}$, subsequently clamped by engine to 64 MiB–1 GiB | `rust/src/structure/adapters/heif.rs:57-72`, `isobmff.rs:437-472` |
| ZIP | `pre_cd_inject` $\le \text{0xFFFFFFFE} - \max(\text{cd\_offset}, \text{eocd} + 16)$; `cd_offset == 0`, ZIP64 locator, 32-bit overflow, or missing EOCD fall back to `eof` | `rust/src/structure/adapters/zip.rs:145-171`, `:173-235` |
| PE | Minimum of codebits and slack: $\min(\text{bits}/8 - 14, \text{longest\_zero\_run} - 14)$ | `rust/src/structure/adapters/pe.rs:208-283`, `:254-258` |
| PDF | `incremental` allowed only if trailer/xref are parsable, unencrypted, and object ID $< \text{0x7FFF\_FFFF}$; classic xref capped at 10 GB, XRef stream capped at 4 GB; otherwise falls back to `eof` | `rust/src/structure/adapters/pdf.rs:50-96`, `:795-801`, `:839-845` |

All adapter limits are clamped by the engine to `structure_payload_limit(host_len)` (`rust/src/structure/engine.rs:1938-1975`).

### 3.3 Implications of Auto Strategy Selection

`auto` is determined once via `choose_auto_strategy(reader, exact_ube_size)` in each adapter; while adapters may internally switch to `eof` based on probing, the engine **will not** retry alternative strategies if injection fails (`rust/src/structure/engine.rs:1242-1246`). Therefore:

- PNG: Falls back to `eof` only if `ube > 0x7FFFFFFF`; JPEG: falls back to `eof` if `ube > 64 MiB`, `ube > app_segment_payload_capacity(sos)`, or SOS scan fails.
- PDF: Falls back to `eof` if object header length exceeds `MAX_OFFSET_DELTA (128)`; this is an offset delta limitation of the envelope header, not a carrier capacity limit.
- HEIF: Selects `item_hidden` only if `ube <= u32::MAX - 8` and `isobmff_can_item_hidden` holds; otherwise uses `box_uuid` (`heif.rs:57-68`).
- PE: Precedence is `pe_slack → pe_overlay` (`pe.rs:176-210`); `pe_codebits` requires explicit selection (`-s pe_codebits`) and is never picked by `auto`.
- ZIP: `cd_offset == 0`, ZIP64 locator presence, $\text{patch\_limit} + \text{ube} \ge \text{0xFFFFFFFF}$, or missing EOCD all trigger fallback to `eof`.
- WAV / WebP: Declared RIFF boundary must equal physical length and leave sufficient headroom under 4 GiB; otherwise falls back to `eof` (`wav.rs:25-35`, `webp.rs:25-35`).
- MP4 always chooses `box_uuid`; MKV always chooses `ebml_void`: neither adapter features `eof` fallback in `auto` (`mp4.rs:66-68`, `mkv.rs:43-45`).

---

## 4. Master Limits Table

| Limit Parameter | Value | Reference |
|---|---|---|
| `HEADER_LEN_MAX` | `67,108,863` (26-bit) | `rust/src/stego/header.rs:16-20` |
| `BODY_OVERHEAD` | `22` | `rust/src/stego/envelope.rs:97` |
| `MAX_PLAINTEXT_LEN` | `67,108,841` | `rust/src/stego/envelope.rs:101-102` |
| `MAX_EXT_BYTES` (PNG / JPEG / WAV / FLAC) | `255` | `rust/src/stego/header.rs:159` |
| HEVC `ext_len` | $\le 64$ | `rust/src/stego/hevc/engine.rs:124` |
| HEVC MP4 `moov` box | $\le 32 \text{ MiB}$ (exceeding returns `UnsupportedFormat`) | `rust/src/stego/hevc/engine.rs:2627-2631` |
| PNG trailing data after `IEND` | $\le 16 \text{ MiB}$ (exceeding returns `CorruptedData`) | `rust/src/stego/png/engine.rs:334-341` |
| `MAX_PNG_PIXELS` | `67,108,864` | `rust/src/stego/png/engine.rs:506` |
| PNG / JPEG Working Set | `8 GiB` | `rust/src/stego/png/engine.rs:516`, `rust/src/stego/jpeg/engine.rs:100` |
| Audio Working Set | `768 MiB` | `rust/src/stego/audio/core.rs:69` |
| Structural Header / Trailer | `112 B` / `24 B` | `rust/src/structure/envelope.rs:83`, `:89` |
| `MAX_HINT_LEN` | `1024` | `rust/src/structure/envelope.rs:90` |
| `MAX_META_LEN` | $256 \text{ KiB} = 262,144$ | `rust/src/structure/envelope.rs:100` |
| `MAX_OFFSET_DELTA` | `128` | `rust/src/structure/envelope.rs:74-88` |
| `CHUNK_OVERHEAD` | `20 B / chunk` | `rust/src/core/crypto.rs:61-64` |
| `CHUNK_SIZE` / `MAX_CHUNK_SIZE` | `2 MiB` / `64 MiB` | `rust/src/core/crypto.rs:96`, `:101` |
| `MAX_VERIFY_PAYLOAD_SIZE` | `1 GiB` | `rust/src/core/crypto.rs:786` |
| Structural Payload Clamp | $\text{clamp}(256 \times \text{host\_len}, 64 \text{ MiB}, 1 \text{ GiB})$ | `rust/src/structure/engine.rs:1938-1943` |
| Content Domain Filename | `255 B` | `rust/src/stego/envelope.rs:78` |

---

## 5. Error Semantics

- **Insufficient carrier capacity MUST return `PayloadTooLarge`, never `UnsupportedFormat`.** `UnsupportedFormat` is reserved exclusively for "carrier format/structure is unrecognized by the engine", and MUST NOT be returned when a recognized carrier is simply too small.
- PNG: Slot exhaustion or budget overflow both return `PayloadTooLarge` (`rust/src/stego/png/engine.rs:544`, `:1582`, `:1596`, `:1620`, `:1629`).
- JPEG: Grid smaller than base header or budget overflow both return `PayloadTooLarge` (`rust/src/stego/jpeg/engine.rs:1825`, `:164-190`).
- HEVC: Slot exhaustion returns `PayloadTooLarge` (`rust/src/stego/hevc/engine.rs:1295`).
- Structural Domain: Rejection prior to writing under `structure_payload_limit` returns `PayloadTooLarge` (`rust/src/structure/engine.rs:1088-1093`).
- **Implementation Deviation**: WAV / FLAC slot exhaustion currently returns `General` (`rust/src/stego/audio/core.rs:753-769`), deviating from normative requirements; callers MUST NOT treat `UnsupportedFormat` as a proxy for capacity exhaustion.

---

## 6. Stability Tiers

| Content | Tier | Justification |
|---|---|---|
| §1 Unified Formula, `BODY_OVERHEAD`, `HEADER_LEN_MAX` | **F** | Alterations change writable boundaries and byte layouts |
| §2 Per-carrier `total/base/ext` and `h/u` | **F** | `probe` and `embed` must share exact metrics; changes invalidate baselines |
| §2.6 Budget Gates | **F** | Directly governs `max_raw_payload_bytes` and `PayloadTooLarge` decisions |
| §2.7 Long-video 20% Estimation | **I** | Affects reporting accuracy only without changing embedding logic |
| §3.1 Structural Header/Trailer/Chunk Overhead | **F** | Existing UBE carriers depend on these dimensions |
| §3.2 Adapter Capacity Text | **I** | Informational reporting ceilings; true gates are enforced by engine clamping |
| §4 Limits Table Numerical Values | **F** | Parsing engines reject values using matching thresholds |
| §5 Error Classification | **F** | Contractual API behavior |
