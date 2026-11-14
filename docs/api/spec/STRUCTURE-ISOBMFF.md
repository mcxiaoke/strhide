# ISO-BMFF Structural Domain Adapters: MP4/MOV and HEIF/HEIC

This document specifies the structural domain (UBE) adapters for `format_name = "MP4"` (`Mp4Adapter`) and `format_name = "HEIF"` (`HeifAdapter`), which share the underlying box-stream engine in `isobmff.rs`. Common definitions for 112B headers, 24B trailers, AAD, and `offset_delta` semantics are in [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2–§15; content domain HEVC/HEIF is specified in [CONTENT-HEVC.md](CONTENT-HEVC.md); the two domains are mutually exclusive and non-interchangeable.

---

## 1. Scope, Navigation, and Stability

- Carriers: MP4 / MOV containers with top-level ISO/IEC 14496-12 boxes, fragmented MP4 / CMAF streams, and HEIF / HEIC image containers (including AVIF brands). Adapters navigate via box headers without decoding media bitstreams.
- Registration Priority: `rust/src/structure/registry.rs:25-36`; `HEIF` precedes `MP4`, ensuring files with `ftyp` headers evaluate under HEIF first.
- Strategy IDs: `box_uuid = 3`, `eof = 1`, `item_hidden = 12`, `free_box = 13` (`rust/src/structure/registry.rs:90-104`).

| Tier | ISO-BMFF Structural Scope |
| --- | --- |
| **F** | MP4 first-box 4CC whitelist; HEIF `ftyp` dimensions and brand checks; `MP4_UUID_NEUTRAL` 16B usertype; `uuid` box 24/32B headers and `calc_prefix_len` transition boundary; `free` / `mdat` 8B headers; `item_hidden` structures (`infe` v2/v3, `iloc` entries, second `mdat`); `offset_delta` (24/32/8/0); locator header identification rules; physical append layout after final box |
| **D** | None. UUID usertype, item type `resv`, and `infe` / `iloc` templates are fixed constants |
| **I** | Carrier copy buffer sizing, `meta` scanning paths, `strategy_note` phrasing, error message strings; readers depend on none of these |

Difference from Content Domain: Content domain HEVC modifies CABAC `coeff_sign_flag` in VCL slices, replaying substreams ([CONTENT-HEVC.md](CONTENT-HEVC.md) §2); structural domain operations append or rewrite box headers only, copying media bytes in `mdat` verbatim (`isobmff.rs:85-86`, `:1178-1181`). `item_hidden` introduces an isolated item without re-encoding cover images or accessing thumbnails.

---

## 2. Format Detection (`detect`)

`detect` inspects the initial stream bytes without raising errors, restoring stream position before returning (`rust/src/structure/adapters/mp4.rs:25-60`, `heif.rs:21-51`).

**MP4 Path**: Reads the first 8 bytes and matches `bytes[4..8]` (FourCC) against the whitelist (`mp4.rs:33-57`):

```text
ftyp styp moov moof mdat sidx emsg free skip wide uuid pdin
```

Does not require `moov` or `mdat`, nor does it validate brand compatibility; files starting with `mdat`, `uuid`, or `free` pass detection.

**HEIF Path**: First box MUST be `ftyp`, with 32-bit size within $[12, 4096]$; reads the entire box and executes `is_heif_bytes` (`heif.rs:30-41`). Brand evaluation traverses 4-byte chunks in `payload = bytes[8..size]`, skipping index 1 (`minor_version`), testing major brand (index 0) and all compatible brands against `HEIF_BRANDS` (`rust/src/formats/sniff.rs:189-212`, `:23-26`):

```text
heic heix hevc hevx mif1 msf1 heim heis avif avis
```

Rejection conditions: Missing leading `ftyp`, `ftyp` size out of bounds, or no matching brand. `detect` does not require `meta`, `iinf`, or `iloc`; these are enforced during `item_hidden` admission.

**Pre-Write Structural Gate**: Regardless of detection outcome, `write_core` invokes `isobmff_verify_structure`, returning `CorruptedData` on error (`rust/src/structure/engine.rs:1028-1035`). The validator inspects boxes sequentially: reading 64-bit `largesize` (16B header) when `size == 1`, and treating `size == 0` as extending to EOF; rejecting headers where $size < \text{header\_len}$, bounds exceed EOF, addition overflows, or box count exceeds 1,000,000; requires at least one explicit box and presence of `ftyp` (`isobmff.rs:239-359`). Pure CMAF fragments lacking `ftyp` pass `detect` but are rejected at pre-write verification.

---

## 3. Supported Strategies, `auto`, and Capacity

| Adapter | Strategy | ID | Behavior | Reference |
| --- | --- | --- | --- | --- |
| MP4 | `box_uuid` | 3 | Appends a `uuid` box (24/32B header) at physical EOF | `mp4.rs:62-64`, `isobmff.rs:92-111` |
| MP4 | `eof` | 1 | Appends raw UBE at EOF with no container header | `mp4.rs:62-64`, `isobmff.rs:119-121` |
| HEIF | `item_hidden` | 12 | Rewrites `meta`, appending a second `mdat` at EOF | `heif.rs:53-55`, `isobmff.rs:818-1195` |
| HEIF | `free_box` | 13 | Appends a `free` box (8B header) at physical EOF | `heif.rs:53-55`, `isobmff.rs:112-118` |
| HEIF | `box_uuid` | 3 | Identical to MP4 | `heif.rs:53-55` |
| HEIF | `eof` | 1 | Identical to MP4 | `heif.rs:53-55` |

`Mp4Adapter` does not expose `free_box`; passing `free_box` to MP4 returns unsupported strategy (`engine.rs:1248-1253`). Adapters never reuse existing `free`/`skip` boxes, always appending new ones.

**`auto` Resolution** (single evaluation without retry or fallback, `engine.rs:1242-1255`):

- MP4: Always selects `box_uuid` regardless of UBE size (`mp4.rs:66-68`).
- HEIF: If $ube\_total\_size \le \text{ITEM\_HIDDEN\_MAX\_ENVELOPE}$ and `isobmff_can_item_hidden(reader)` is true, selects `item_hidden`; otherwise selects `box_uuid` (`heif.rs:57-68`). $\text{ITEM\_HIDDEN\_MAX\_ENVELOPE} = \text{u32::MAX} - 8 = 4,294,967,287$ (`isobmff.rs:19`).
- There is no automatic fallback to `eof`; `eof` requires explicit selection.

Capacity reporting: `box_uuid` / `eof` report `capacity_bytes = None` and `limit = "unlimited (file grows)"`; HEIF `item_hidden` / `free_box` report `None`, specifying "up to ~4 GiB envelope" (`isobmff.rs:415-472`). `inspect` clamps available strategies to $\text{structure\_payload\_limit}(host\_len) = \text{clamp}(256 \times host\_len, 64\text{ MiB}, 1\text{ GiB})$ (`engine.rs:1938-1975`, `:2604-2611`), yielding displayed values of 64 MiB to 1 GiB.

---

## 4. Injection Layout, `offset_delta`, and Sizing

### 4.1 Common Characteristics

All four strategies copy the carrier prefix $[0, host\_len)$ verbatim, with $inject\_offset = host\_len$ for `eof`, `box_uuid`, and `free_box`; `item_hidden` shifts this coordinate due to `meta` expansion (§4.4). All strategies terminate at file EOF, positioning trailers within the final 24 bytes (`adapters/mod.rs:357-359`). Under `eof`, `box_uuid`, and `free_box`, original box offsets remain invariant, keeping `stco`, `co64`, `iloc`, and `sidx` valid without modification.

### 4.2 `box_uuid`

Prepends a `uuid` box with 16B usertype `MP4_UUID_NEUTRAL` (`isobmff.rs:11-13`, `d4 1a 8e 9c 4f 21 4e 87 9a 33 5b 6d 12 84 ef 70`):

```text
32-bit Header (24 + ube < 0xFFFFFFFF):
  +0  u32be size = 24 + ube_total_size
  +4  "uuid"
  +8  MP4_UUID_NEUTRAL[16]              ← UBE start = inject_offset + 24

64-bit Header (24 + ube >= 0xFFFFFFFF):
  +0  u32be 1
  +4  "uuid"
  +8  u64be largesize = 32 + ube_total_size
  +16 MP4_UUID_NEUTRAL[16]              ← UBE start = inject_offset + 32
```

The switch point is determined strictly by `calc_prefix_len(ube_size)` (`isobmff.rs:30-32`), shared between writer and `offset_delta`: $24 + ube == \text{0xFFFFFFFE}$ uses 24B, while $\text{0xFFFFFFFF}$ uses 32B (`isobmff.rs:1670-1679`). Total footprint is $inject\_size = \text{header\_len} + ube$ (`isobmff.rs:92-111`).

### 4.3 `free_box`

```text
+0  u32be size = 8 + ube_total_size
+4  "free"
+8  UBE[0 .. ube_total_size)          ← offset_delta = 8
```

Emits 32-bit size only; if $8 + ube > \text{u32::MAX}$, returns `Envelope too large for 32-bit free box` (`isobmff.rs:112-118`). Upper bound: $\text{u32::MAX} - 8 = 4,294,967,287$. Readers accept existing `free` or `skip` headers (`isobmff.rs:209-216`); writers emit `free` only.

### 4.4 `item_hidden`

Admission via `check_item_hidden_layout` (`isobmff.rs:522-609`, shared with `isobmff_can_item_hidden`, `:611-633`) requires: `meta`, `iinf`, and `iloc` all use 8B headers (no `size == 1`); `iloc` version $\le 2$; `off_sz` and `len_sz` $\in \{4, 8\}$; `base_sz` $\in \{0, 4, 8\}$; `iinf` version $\le 1$; `meta` end coordinate $\le 1\text{ GiB}$ (`MAX_ISOBMFF_META_SCAN`, `:481`, `:855-859`).

Writing sequence (`isobmff.rs:818-1195`):

1. Scan top-level boxes to locate `meta`, buffering $[0, m\_end)$ (`:830-863`).
2. Parse `meta` sub-boxes (preserving trailing bytes $< 8\text{B}$ as `meta_tail`, `:870-893`).
3. Set $new\_id = \max(existing\_item\_ids) + 1$; reject if overflowing `u32::MAX` (`:908-959`).
4. Generate `infe`: $new\_id \le \text{0xFFFF}$ uses v2 (21B); else v3 (23B). Emits $item\_type = \text{"resv"}$, $item\_protection\_index = 0$, empty $item\_name$; omits mime type and hidden flags (`:961-984`).
5. Append `iloc` entry: `item_id` (v0/v1: 2B; v2: 4B), $construction\_method = 0$ for $v \ge 1$, $dref = 0$, $base\_offset = 0$, $extent\_count = 1$, optional $extent\_index$, $extent\_offset$, $extent\_length$ (`:1029-1046`). $extent\_offset = host\_size + delta\_meta + 8$ and $extent\_length = ube\_size$, pointing to the second `mdat` payload area (`:1026-1027`).
6. Set $delta\_meta = infe\_len + iloc\_item\_len$; increment sizes and item counts of `meta`, `iloc`, and `iinf` by 1 (`:1128-1160`), reconstructing `meta` (`:1162-1174`).
7. Write output: $[0, m\_off)$ + new `meta` + host $[m\_end, host\_size)$, appending:

```text
+0  u32be size = 8 + ube_total_size
+4  "mdat"
+8  UBE[0 .. ube_total_size)          ← offset_delta = 8
```

Returns $inject\_offset = host\_size + delta\_meta$ (start of second `mdat` header) and $inject\_size = 8 + ube$ (`:1183-1194`). Pre-injection `meta` expansion is excluded from `inject_size`.

**Existing `iloc` Offset Adjustment**: Adjusts items with $construction\_method == 0$ only. If $base\_offset \ge m\_end$ (non-zero with $base\_sz > 0$), increment $base\_offset$ and dependent extents by $delta\_meta$; if base offset precedes `meta` but extent absolute offset $base + extent\_offset \ge m\_end$, increment extent offset only; items preceding `meta` remain unchanged; entries with $construction\_method \ne 0$ (`idat`) are neither parsed nor altered (`isobmff.rs:1050-1126`). Does not inspect `stco`/`co64`.

**Capacity**: $ube \le 4,294,967,287$; when $off\_sz == 4$, $host\_size + delta\_meta + 8 \le \text{u32::MAX}$, otherwise `write_sized_uint` reports 32-bit `iloc` overflow (`isobmff.rs:753-756`, `:1045`).

### 4.5 `eof`

No container header; $inject\_size = ube\_size$, $offset\_delta = 0$ (`isobmff.rs:119-121`, `mp4.rs:117-122`, `heif.rs:126-133`).

### 4.6 `offset_delta` Summary Table

| Adapter | Strategy | `offset_delta` | Reference |
| --- | --- | --- | --- |
| MP4 | `box_uuid` | `calc_prefix_len(ube)` = 24 or 32 | `mp4.rs:111-122`, `isobmff.rs:30-32` |
| MP4 | `eof` | 0 | Same |
| HEIF | `box_uuid` | 24 or 32 | `heif.rs:120-133` |
| HEIF | `free_box` / `item_hidden` | 8 | Same |
| HEIF | `eof` | 0 | Same |

---

## 5. Locator Pipeline (`locate`)

Shared via `isobmff_locate` without overriding `locate_with_hint` (header hints ignored, `adapters/mod.rs:218-225`). Pipeline (`isobmff.rs:128-237`):

1. **Trailer**: `EnvelopeTrailer::read_from_tail` reads and validates CRC against expected trailer magic; enforces $ube\_total\_size \ge 136$ and $ube\_offset + ube\_total\_size \le \text{file\_size}$ (`:132-154`).
2. **24B Header**: When $ube\_offset \ge 24$, inspect $[ube\_offset - 24, ube\_offset)$; matching FourCC `uuid`, usertype `MP4_UUID_NEUTRAL`, and $size == 24 + total \implies (ube\_offset, total, "box\_uuid")$ (`:156-176`).
3. **32B Header**: Matching $size == 1$, FourCC `uuid`, $largesize == 32 + total$, and usertype $\implies \text{"box\_uuid"}$ (`:178-200`).
4. **8B Header**: When $size == 8 + total$, FourCC `free` or `skip` $\implies \text{"free\_box"}$; FourCC `mdat` with `isobmff_has_iloc_item(ube_offset, total)` true $\implies \text{"item\_hidden"}$ (`:202-228`).
5. **EOF Fallback**: `trailer.locate_start(file_size)` resolves to recorded offset or $file\_size - total \implies \text{"eof"}$ (`:230-234`, `envelope.rs:870-879`).

`item_hidden` confirmation checks `iloc` extents in top-level `meta` for $absolute\_offset == ube\_offset \land extent\_length == total$; if unmatched, falls back to `eof` (`isobmff.rs:1542-1658`).

---

## 6. `remove` and Cover Restoration

- **MP4**: Uses `HostAdapter::strip` default: copies $[0, inject\_offset)$, skips $inject\_size$, copies remainder (`adapters/mod.rs:236-260`). `box_uuid` removes the entire box; `eof` removes appended UBE.
- **HEIF**: Dispatches via `isobmff_strip` (`heif.rs:92-99`, `isobmff.rs:635-657`). Strategy 12 routes to `heif_item_hidden_strip`.
- **`item_hidden` Restoration** (`isobmff.rs:1197-1540`): Requires $inject\_offset \ge m\_end$ and $inject\_offset + inject\_size == \text{file\_size}$ (`:1254-1269`); rescans `meta`, removes the final entry from `iloc` and trailing `infe` from `iinf` (sizing derived dynamically from item length, `:1304-1367`); subtracts $delta\_meta$ from extents with $construction\_method == 0$ where $offset \ge m\_end$ (`:1411-1477`); reconstructs `meta`, copies up to $inject\_offset$, and drops the second `mdat` (`:1525-1539`).
- Engine recalculates length and SHA-256 against header $orig\_host\_size$ and $orig\_host\_sha256$, returning `RestoreMismatch` on discrepancy (`engine.rs:2299-2361`).

---

## 7. Boundary and Error Semantics

| Condition | Outcome |
| --- | --- |
| Fragmented MP4 (`styp`/`moof`/`sidx`) | `detect` accepts; `verify_structure` requires `ftyp`, rejecting pure CMAF fragments; appends at EOF (`mp4.rs:33-57`, `isobmff.rs:351-353`) |
| Multiple `ftyp` boxes | `detect` inspects first box only; validator requires presence of `ftyp`, tolerating duplicates (`isobmff.rs:275-277`, `:351-353`) |
| 64-bit top-level box (`size == 1`) | Skips via 16B header; 64-bit `box_uuid` locate supported; `item_hidden` rejects 64-bit `meta`/`iloc`/`iinf` (`isobmff.rs:279-291`, `:526-530`, `:553-558`) |
| `size == 0` box | Extends to EOF; files composed solely of `size == 0` are rejected (`isobmff.rs:249-254`, `:342-349`) |
| Corrupted box chain | Truncated headers, $size < \text{header\_len}$, bounds exceeding EOF, u64 overflow, or box counts $> 1,000,000$ reject writing (`isobmff.rs:257-340`) |
| HEIF thumbnails | Sniffing inspects `ftyp` brand only; `item_hidden` appends `resv` items via `iinf`/`iloc` without modifying primary image or thumbnail bytes (`isobmff.rs:961-984`, `:1183-1189`) |
| Existing `free`/`skip`/`mdat` envelopes | `suspicious_structures` flags trailing 24/32B `uuid` boxes only (`isobmff.rs:361-413`) |
| Unrecognized strategy | `UnsupportedFormat` (`isobmff.rs:79-83`) |
| Explicit `free_box` with UBE $> \text{u32::MAX} - 8$ | `General("Envelope too large for 32-bit free box")` (`isobmff.rs:114-115`) |
| `item_hidden` missing `meta`/`iinf`/`iloc` | `UnsupportedFormat`; `auto` selects `box_uuid` beforehand (`isobmff.rs:840-842`, `:522-609`) |

Brands `avif` and `avis` route through the HEIF path; `item_hidden` eligibility depends on `meta` structure without codec-specific branching.

---

## 8. Tier I Writer Details and Self-Verification

- **No Transcoding**: Boxes and media samples are copied in sequence; only headers and `meta` counts/offsets are modified; no padding boxes are merged or split (`isobmff.rs:85-86`, `:1162-1189`).
- **Memory Footprint**: `item_hidden` buffers $[0, m\_end)$ only ($\le 1\text{ GiB}$), streaming the remainder (`isobmff.rs:861-863`, `:1176-1181`).
- **Post-Write Validation**: `locate` MUST recover the written coordinates $(actual\_ube\_offset, ube\_total\_size)$ exactly (`engine.rs:1454-1472`).
- **Regression Tests**:
  - `prefix_len_switches_to_the_large_header_at_the_u32_bound`
  - `inject_writes_exactly_calc_prefix_len_header_bytes`
  - `locate_and_verify_accept_a_64_bit_box`
  - `item_hidden_roundtrips_on_a_synthetic_meta_heif`
  - `item_hidden_strip_rejects_forged_coordinates` (`isobmff.rs:1670-1816`, `:2127-2185`, `:2340-2393`)

```bash
cargo test --all-features --lib structure::adapters::isobmff
cargo test --all-features --lib structure::adapters::heif
python scripts/baseline_hash.py --check
```
