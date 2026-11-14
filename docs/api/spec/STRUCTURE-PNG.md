# PNG Structural Domain Adapter: Private Chunk Injection (`prIv`)

This document specifies the structural domain (UBE) adapter for `format_name = "PNG"`. Common envelope layouts, trailers, AAD, and strategy IDs are defined in [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2–§15 and [CAPACITY.md](CAPACITY.md) §4; content domain (spatial/pixel LSB) is specified in [CONTENT-PNG.md](CONTENT-PNG.md); the two domains are mutually exclusive and non-interchangeable.

---

## 1. Scope, Navigation, and Stability

Carriers must begin with the standard 8-byte PNG signature; this adapter operates strictly on chunk streams without decoding pixel data.

| Tier | PNG Structural Scope |
| --- | --- |
| **F** | 8-byte signature `89 50 4E 47 0D 0A 1A 0A`; strategy names `chunk` / `eof` with `strategy_id` 2 / 1; private chunk type `prIv`; `[u32be len][type][data][u32be crc32]` layout; injection point = start of final `IEND` chunk; `offset_delta = 8`; CRC32 covering `type ‖ data`; locator candidate/displacement admission rules |
| **D** | None. No optional chunks, optional fields, or version branches; `stEg` is a legacy reader-compatibility alias only and is never emitted |
| **I** | Copy buffer sizes, CRC calculation paths, `strategy_note` phrasing, padding chunks (currently none); readers depend on none of these |

Constants: signature and chunk identifier `rust/src/structure/adapters/png.rs:11-15`, strategy registry `rust/src/structure/registry.rs:90-104`, envelope dimensions in [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2.

---

## 2. Format Detection (`detect`)

`detect` compares only the first 8 bytes against the PNG magic signature, returning `bool` without raising errors; it restores stream position upon completion (`rust/src/structure/adapters/png.rs:101-113`). Short 8-byte files pass detect; true structural admission is enforced prior to injection via `find_iend_offset` (`png.rs:27-92`):

1. File length $\ge 8 + 12 = 20\text{ B}$, else `CorruptedData("File too small to be a valid PNG")` (`png.rs:31-35`);
2. First 8 bytes MUST equal the PNG signature, else `UnsupportedFormat("Invalid PNG magic signature")` (`png.rs:39-43`);
3. Beginning at offset 8, skip through chunks by reading the 4-byte Big-Endian length; truncated chunk headers, `length > 0x7FFFFFFF`, arithmetic overflow, or chunks extending past EOF abort scanning (`png.rs:48-76`);
4. Only `IEND` chunks with `length == 0` are recorded as candidates, keeping the **last** one (`png.rs:78-83`); if no valid `IEND` is found, return `CorruptedData("Valid PNG IEND chunk not found")` (`png.rs:85-91`).

If scanning encounters corruption after having already logged an `IEND`, the function returns that earlier offset without error, retaining trailing bytes as dirty tail data; this lenient behavior is intentional. Injection paths execute a full chunk CRC check prior to writing, rejecting malformed carriers with `CorruptedData` (`rust/src/structure/engine.rs:1028-1035`, `png.rs:342-426`).

---

## 3. Supported Strategies and `auto`

| Strategy | `strategy_id` | Behavior | Reference |
| --- | --- | --- | --- |
| `chunk` | 2 | Inserts a new `prIv` ancillary chunk before the final `IEND`, placing UBE as chunk data | `png.rs:13`, `:148-215`; `registry.rs:92` |
| `eof` | 1 | Delegates to `EofAdapter`, appending UBE at physical EOF (after any post-IEND trailing data) | `png.rs:155-157`; `eof.rs:48-55`; `registry.rs:91` |

`auto` evaluates UBE exact dimensions exclusively: if $ube\_total\_size > \text{0x7FFFFFFF}$, it selects `eof`; otherwise it selects `chunk` (`png.rs:119-125`). It does not measure carrier headroom or perform fallbacks beyond this threshold (`engine.rs:1242-1255`). Explicit unsupported strategies return `UnsupportedFormat` (`png.rs:159-163`).

Capacity reporting (`strategy_capacities`, `png.rs:127-146`) reports `chunk = 0x7FFFFFFF`, `eof = None` (unbounded / file expands). `inspect` clamps both to the engine ceiling $\text{structure\_payload\_limit}(host\_len) = \text{clamp}(256 \times host\_len, 64\text{ MiB}, 1\text{ GiB})$ (`engine.rs:1938-1975`, `:2604-2611`), making displayed values substantially smaller than 2 GiB; for an 87,105B stego PNG (original 86,854B), both strategies report `67,108,864` (`temp/baseline/baseline.json:757-777`).

---

## 4. Injection Point and Chunk Layout

Under `chunk`, injection occurs directly before the final `IEND` chunk header, displacing the entire `IEND` (and any subsequent trailing data) backward (`png.rs:174-180`, `:211-212`):

```text
Offset inject_offset:
  +0   u32be  length = ube_total_size
  +4   "prIv" (70 72 49 76)
  +8   UBE[0 .. ube_total_size)        ← offset_delta = 8
  +8+ube_total_size  u32be CRC32(type ‖ data)
```

- Total chunk length is $ube\_total\_size + 12$; `inject` returns $inject\_size = 4 + 4 + ube\_total\_size + 4$ (`png.rs:189-208`, `:214`).
- CRC32-IEEE covers the 4-byte chunk type and chunk data, written as Big-Endian following payload data; calculated streaming during `inject` (`png.rs:186-206`), and recomputed over the same range in `finalize` after header/trailer backfilling (`png.rs:484-508`).
- Offset of UBE origin relative to injection point is fixed to 8 (`chunk`) or 0 (`eof`) (`png.rs:475-482`); encoded into header `offset_delta` and covered by AAD (`engine.rs:1267-1278`).
- Chunk type bytes for `prIv` are `70 72 49 76`; under PNG casing rules: first byte lowercase = ancillary (1), second byte lowercase = public (0), third byte uppercase = reserved bit 0, fourth byte lowercase = safe-to-copy (1). Describing it as a "private ancillary chunk" in code/CLI is functional terminology and does not alter these bit patterns.
- Existing chunks are never reordered or re-encoded; `IEND` and subsequent trailing bytes are copied verbatim (`png.rs:211-212`). Under `eof`, `IEND` and trailing bytes remain untouched at their original offsets, and UBE appends at file EOF (`eof.rs:48-55`).

---

## 5. Envelope Offsets, Capacity, and Lower Bounds

$actual\_ube\_offset = inject\_offset + offset\_delta$ (`engine.rs:1407`); `trailer_offset` uses default $ube\_offset + ube\_total\_size - 24$, positioning the trailer within the final 24 bytes of `prIv` data (`adapters/mod.rs:357-359`, `engine.rs:1432-1441`). Post-injection self-verification requires `locate` to return $(actual\_ube\_offset, ube\_total\_size)$; failure aborts the write (`engine.rs:1454-1472`).

```text
chunk: File expansion = 12 + ube_total_size; single-chunk bound 0x7FFFFFFF
eof:   File expansion = ube_total_size; no chunk length bound
Injection containment: ube_total_size <= inject_size; injection_end <= file_length
```

Capacity does not originate from pre-existing padding: adapters never reuse zero-padding or existing private chunk payloads, always creating a new chunk; hence no carrier-measured capacity function exists (`png.rs:127-146`). The effective limit is the engine payload ceiling: $raw\_size \le \text{structure\_payload\_limit}(orig\_host\_size)$ (`engine.rs:1123`). Structural lower bound for `locate`/`confine` is $112 + 24 = 136$ (`engine.rs:199-201`, `png.rs:268`, `:431`); minimum possible encrypted envelope is 214B (`min_ube_len(1)`, `rust/src/structure/envelope.rs:123-140`). Explicitly selecting `chunk` with $ube\_total\_size > 2\text{ GiB} - 1$ fails injection, prompting switch to `--strategy eof` (`png.rs:168-172`); `auto` switches to `eof` during strategy resolution.

---

## 6. Locator Paths and Dialect Hints

`locate_with_hint` evaluates three paths sequentially (`png.rs:225-340`):

1. **Forward Chunk Scan**: After signature verification, scan sequentially from offset 8 reading 8-byte chunk headers, skipping CRC checks (`png.rs:238-268`). On encountering chunk types `prIv` or `stEg` with $length \ge 136$, read 24 bytes of trailer at $data\_offset + length - 24$, unpacking with expected trailer magic (`png.rs:268-275`).
2. **Self-Describing Confirmation**: Accepted only if $trailer.ube\_total\_size == length$ and either: $trailer.ube\_offset == data\_offset$ (exact match); or the first 8 bytes of chunk data equal expected header magic (accommodating physical relocation from content domain IDAT recompression). Returns `(data_offset, length, "chunk")` (`png.rs:283-299`).
3. **EOF Fallback**: Reads 24 bytes of trailer from EOF; `locate_start(file_size)` returns the recorded offset if trailer is EOF-aligned, else $file\_size - ube\_total\_size$; requires exact match or header magic match (`png.rs:319-337`, `envelope.rs:870-879`). Returns `(start, ube_total_size, "eof")`.

Magic hints carry no version field: input is `expected_header_magic: Option<[u8; 8]>` and `expected_trailer_magic: Option<&[u8; 4]>`; defaulting to `STANDARD_HEADER_MAGIC` when omitted (`png.rs:235-237`, `adapters/mod.rs:218-225`). When a password is provided, the engine tries stealth-derived magic first, then profile magic (`engine.rs:145-166`). `confine_location` enforces $ube\_total\_size \ge 136$ and $ube\_offset + ube\_total\_size \le \text{file\_length}$ (`engine.rs:191-207`).

Concatenated PNG streams encountering signatures at chunk boundaries are skipped (`png.rs:56-59`, `:305-315`); `locate` encountering `IEND` continues scanning if followed by a PNG signature, guaranteeing discovery of envelopes placed before the **final** `IEND`. CgBI (Apple proprietary chunk before IHDR), APNG (`acTL` / `fcTL` / `fdAT`), color types, bit depths, and interlacing are handled transparently: the adapter traverses them as standard chunks relying strictly on length and `IEND`.

---

## 7. `remove` and Cover Restoration

`remove` leverages `HostAdapter::strip`: copies $[0, inject\_offset)$, skips $inject\_size$ bytes, then copies remaining bytes to EOF (`adapters/mod.rs:236-260`). For `chunk`, this strips the entire `[len][prIv][UBE][crc]` chunk, restoring `IEND` and trailing dirty data to their original coordinates.

- If content recompression displaced the chunk, `strip_coordinates_for_location` adjusts $inject\_offset$ for `chunk` / `eof` according to locate results (`engine.rs:2268-2296`); relocated spans remain bounded by $ube\_total\_size \le inject\_size$ and file length (`engine.rs:2828-2902`).
- The restored file size and SHA-256 are computed and validated against $orig\_host\_size$ and $orig\_host\_sha256$ in the header; discrepancies emit `RestoreMismatch`; if residual envelope signatures are detected, `residual_envelope` is set, indicating reverse-order removal is required (`engine.rs:2299-2360`).
- Bit-for-bit restoration includes post-IEND dirty tails; original SHA-256 is the final test of correctness.

---

## 8. Writer-Side Tier I (Non-Normative)

- **No Pixel Re-encoding**: Structural writing never alters IDAT Deflate levels, row filters, or raster data, copying bytes verbatim (`png.rs:177-179`, `:211-212`).
- **Chunk Placement**: `prIv` is fixed directly preceding the final `IEND`; no padding chunks are inserted, and existing chunks are not merged or split.
- **CRC Recomputation**: Because headers and trailers are backfilled after `inject`, `finalize` recomputes chunk CRC across offset $ube\_offset - 4$ for length $4 + ube\_total\_size$ (`png.rs:490-506`, `engine.rs:1443-1451`).
- **Retries**: No envelope-level retries exist in the adapter; post-write `locate` failure aborts the entire transaction (`engine.rs:1454-1472`).

---

## 9. Known Limitations and Error Semantics

| Condition | Outcome |
| --- | --- |
| File $< 20\text{ B}$ / Invalid signature / No zero-length `IEND` | `CorruptedData` / `UnsupportedFormat` / `CorruptedData` (`png.rs:31-35`, `:39-43`, `:85-91`) |
| Truncated chunk stream or out-of-bounds length | Scan halts; uses previously logged `IEND` if available, else reports "IEND not found" (`png.rs:48-83`) |
| $ube\_total\_size > \text{0x7FFFFFFF}$ under explicit `chunk` | `UnsupportedFormat`, prompting switch to `eof` (`png.rs:168-172`) |
| Unrecognized strategy name | `UnsupportedFormat` (`png.rs:159-163`) |
| UBE stream shorter than declared size | `CorruptedData("Envelope stream ended before its declared size")` (`png.rs:196-201`) |
| Non-PNG carrier passed to `locate` | `Ok(None)` (not an error) (`png.rs:240-243`) |
| Chunk CRC corrupted in cover | `verify_structure` returns `(false, "CRC32 mismatch...")`; rejected before write (`png.rs:399-407`, `engine.rs:1028-1035`) |
| Trailer magic matches but CRC fails | Emits `CorruptedData` (`envelope.rs:844-858`), never silently ignored |

The presence of `prIv` / `stEg` is detectable via structural audits: `suspicious_structures` flags private chunks with $length \ge 136$ (`png.rs:428-473`).

---

## 10. Self-Verification

- Unit tests (`png.rs:526-583`): `locate_rejects_a_trailer_that_describes_another_region`, `locate_accepts_a_trailer_that_describes_its_chunk`.
- Regression: `tests/test_regression/review_20261030.rs:233-252` validates `chunk` with $offset\_delta == 8$ and $inject\_offset == \text{chunk\_data\_offset} - 8$; `tests/test_regression/fixes.rs:947-969` validates readability after IDAT recompression displacement; `tests/test_security/stealth.rs:223-228` tests forged `prIv` rejection.
- Baseline: `scripts/baseline_hash.py:263-314` validates PNG structural writing: `write -t <payload> → inspect --json → read → restore`.

```bash
cargo test --all-features --lib structure::adapters::png
cargo test --all-features --test test_regression
python scripts/baseline_hash.py --check
```
