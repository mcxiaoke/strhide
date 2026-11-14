# JPEG Structural Domain Adapter Specification (APP Segment Injection)

> Scope: This document defines format detection, strategies, injection layout, locating, and restoration when JPEG serves as a **structural domain carrier**.  
> Envelope fields, AAD, encryption, and trailer semantics are specified in [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md);  
> Complete wire layout tables are in [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2–§15 and [CAPACITY.md](CAPACITY.md) §4;  
> DCT content domain steganography (UERD / J-UNIWARD / J-MiPOD) is specified in [CONTENT-JPEG.md](CONTENT-JPEG.md); the two domains are mutually exclusive and non-interchangeable.  
> Adapter implementation: `rust/src/structure/adapters/jpeg.rs`, registered as `JPEG` (`:230-232`), ordered following PNG in `ADAPTERS` (`rust/src/structure/registry.rs:25-36`).

---

## 1. Navigation and Terminology

- **Injection Point** `inject_offset`: Byte offset of the `0xFF` marker of the first Start-of-Scan (SOS) marker (`jpeg.rs:344-356`).
- **UBE Origin** = $inject\_offset + offset\_delta$; for this adapter, $offset\_delta = 4$ (`jpeg.rs:553-564`; sealed into header AAD prior to injection, `rust/src/structure/engine.rs:1267-1278`).
- **Chain**: Multiple APP15 segments linked in file order, forming a contiguous logical UBE payload across segments, punctuated by 4-byte segment headers.
- **First SOS**: Terminal boundary for marker stream scanning; entropy-coded scan data following SOS never participates in parsing (`jpeg.rs:108-116`).

---

## 2. Stability Tiers (F / D / I)

| Tier | Scope |
| :--- | :--- |
| **F** | APP15 marker `FF EF`, segment length field semantics and 65,533 payload bound, insertion point = first SOS, $offset\_delta = 4$, segment chain adjacency (next payload start = prev payload end + 4), trailer placement at end of final segment payload, `partition_jpeg_payload_lengths` splitting function, locator admitting only APP15 and EOF trailers |
| **D** | None. This adapter defines no substitutable private fields or dialect parameters |
| **I** | `auto` strategy selection and fallback, capacity reporting text, `JPEG_MAX_TOTAL_CAPACITY` fast path, `suspicious_structures` 136-byte threshold, `verify_structure` phrasing, 64 KiB buffer sizes |

The 16 MiB header scan limit (`jpeg.rs:18`) determines whether written carriers remain discoverable by this implementation; altering it breaks readability on large files and is treated as Tier F.

---

## 3. Format Detection (`detect`)

`detect` performs a single check: seeks to offset 0, reads 2 bytes, and verifies `FF D8` (`jpeg.rs:234-246`), restoring stream position before returning (`:244`).

- Does not check for EOI (`FF D9`).
- Requires no APP0 / JFIF or EXIF headers, and does not check file extensions.
- Any stream beginning with `FF D8` is classified as JPEG; routing evaluates in `registry.rs:25-36` order (PNG before JPEG).
- Read or seek failures return `false` without raising errors.

---

## 4. Supported Strategies and `auto`

`supported_strategies = ["app_segment", "eof"]` (`jpeg.rs:248-250`), with wire IDs 5 and 1 respectively (`registry.rs:90-104`).

`auto` performs a **single-pass decision without retry** (`engine.rs:1242-1255`) following this precedence (`jpeg.rs:252-269`):

1. If $ube\_size > 64\text{ MiB} \to \text{eof}$ (`:253-254`).
2. If `find_jpeg_sos_offset` fails (missing SOS, corrupted segment length, 16 MiB scan overflow, or non-marker run overflow) $\to \text{eof}$ (`:260-262`).
3. If $ube\_size > \text{app\_segment\_payload\_capacity}(sos\_offset) \to \text{eof}$ (`:265-267`).
4. Otherwise select `app_segment`.

Capacity reporting (`jpeg.rs:271-322`): `app_segment` reports an exact usable byte count; `eof` reports unbounded (file expansion). EOF appends at physical EOF (past EOI in standard JPEGs), without parsing EOI coordinates (`rust/src/structure/adapters/eof.rs:48-55`).

**APPn Selection**: Writers fixedly emit APP15 (`JPEG_APP15 = FF EF`, `jpeg.rs:14`); no round-robin or fallback across APP2–APP14 exists. `JPEG_COM` (`:15`) is read solely by `suspicious_structures` to flag legacy envelopes (`:542-547`); `locate` explicitly rejects COM segments (`tests/test_lifecycle/jpeg_multisegment.rs:156-187`).

---

## 5. Injection Layout

Written directly preceding `sos_offset` (`jpeg.rs:352-371`):

```text
FF EF | len_hi len_lo (Big-Endian u16, including 2 bytes of length field) | payload[len - 2]
```

- Maximum segment length field is 65,535 $\implies$ single-segment payload bound is 65,533 (`jpeg.rs:16`, `:122-127`, `:363-366`).
- Total injected footprint is $inject\_size = \sum (4 + payload\_len)$ (`:366`); headers are positioned at $inject\_offset + 4$ (`engine.rs:1407`, `:1428-1429`).
- Consecutive segments start **4 bytes past the end of the previous segment's payload**; logical UBE readers chain segments across this 4-byte header gap (`jpeg.rs:500-514`, `adapters/mod.rs:403-470`).
- The UBE trailer resides in the final 24 bytes of the last segment payload: $inject\_offset + inject\_size - 24$ (`jpeg.rs:566-572`).

**Payloads Exceeding 65,533 Bytes**: Partitioned into multi-segment chains. `partition_jpeg_payload_lengths` fills segments up to 65,533 bytes; if the trailing remainder $< 24$ bytes, it borrows 1,024 bytes from the preceding segment, ensuring the final segment has $\ge 1024$ bytes (`jpeg.rs:172-195`). `inject` strictly expects `app_segment`; insufficient capacity returns `UnsupportedFormat` suggesting `--strategy eof` (`:344-350`).

---

## 6. Capacity Metric

`app_segment_payload_capacity(sos)` (`jpeg.rs:205-225`) requires that the first SOS remains within the 16 MiB scan window after injection:

```text
budget = 16 MiB - sos_offset
fits(p) = p + 4 * ceil(p / 65533) <= budget
capacity = max{ p <= min(budget, 64 MiB) | fits(p) }
```

Practical capacity is slightly less than $16\text{ MiB} - sos\_offset$ (chain header overhead is $\approx 1\text{ KiB} / 16\text{ MiB}$) and **never reaches 64 MiB**; 64 MiB serves as a fast-path ceiling in `auto` (`jpeg.rs:17`, `:215`). As `sos_offset` increases, usable capacity decreases.

---

## 7. Insertion Point and Existing Markers

- Insertion occurs **immediately preceding the first SOS**, not following SOI (`jpeg.rs:352-356`). APP0/JFIF, APP1/EXIF, other APPn markers, DQT/DHT/SOF, and existing COM/APP15 markers precede the injection point untouched.
- Existing APP15 segments are neither reordered nor merged; the new chain is placed flush against the first SOS.
- All bytes starting from the first SOS (entropy-coded scan data and subsequent scans) are copied verbatim (`:373-375`), leaving progressive / multi-scan streams undamaged.
- Stacking envelopes: Public APIs check via `locate` prior to write, rejecting files with existing envelopes (`engine.rs:1046-1058`). If stacked manually, `locate` scans backward, matching the chain closest to SOS first (`jpeg.rs:406`); removal must execute in reverse order of injection.

---

## 8. Locator (`locate`)

1. Verify `FF D8` at offset 0, returning `None` on mismatch (`jpeg.rs:385-389`).
2. Scan all segments preceding the first SOS, collecting `(payload_offset, payload_length)` for each APP15 marker (`:391-400`).
3. Iterate candidates backward from the last segment (`:406`): skip segments where $payload < 24$ (`:407-409`); read the trailing 24 bytes and unpack using expected trailer magic (`:410-420`).
4. Single-segment match: $trailer.ube\_offset == payload\_offset$ and $ube\_total\_size == payload\_length$ (`:423-431`).
5. Multi-segment match: Accumulate backward across segments, verifying $curr\_off + curr\_len == next\_off - 4$ (accounting for 4-byte segment headers), total accumulated length equals $ube\_total\_size$, and starting offset equals $trailer.ube\_offset$ (`:434-464`).
6. Fallback to EOF trailer via `read_from_tail` if no APP15 matches, resolving via `locate_start(file_size)` with strategy name `eof` (`:474-480`).
7. Enforce physical containment: $ube\_total\_size \ge 112 + 24$ and $ube\_offset + ube\_total\_size \le \text{file\_size}$ (`engine.rs:191-207`).

**Hint Handling**: `locate` receives `expected_trailer_magic` only, ignoring header magic hints (`adapters/mod.rs:218-225`). The engine tries stealth trailer magic first, followed by dialect magic (`engine.rs:145-166`). `remove` and `verify` require $inject\_offset + offset\_delta == trailer.ube\_offset$; `app_segment` is not relocatable (`engine.rs:2828-2873`).

---

## 9. `remove` and Cover Restoration

JPEG uses standard `strip` (`adapters/mod.rs:236-290`):

1. Copy $[0, inject\_offset)$;
2. Skip $[inject\_offset, inject\_offset + inject\_size)$ (the entire APP15 chain: headers + payloads);
3. Copy all remaining bytes to EOF.

Because no bytes outside the chain are modified ($patch\_offset = 0$), stripping restores original JPEG bytes bit-for-bit. The engine validates restored file size and SHA-256 against $orig\_host\_size$ and $orig\_host\_sha256$ (`engine.rs:2299-2311`), returning `RestoreMismatch` on discrepancy (`:2354-2360`). Under `eof`, stripping truncates the appended UBE stream.

---

## 10. Boundary and Rejection Conditions

- **EXIF / JFIF Coexistence**: Pre-existing APP0/APP1 markers are preserved; marker scanning skips APP1 payloads based on segment length (`jpeg.rs:135-140`), preventing thumbnail `FF D8` markers from being mistaken for file headers.
- **Pre-existing Large APP15 / COM**: Segments with payloads $\ge 136$ bytes trigger suspicious warnings without blocking writes (`jpeg.rs:530-551`).
- **Segment Corruption**: Segment length $< 2$ returns `MalformedLength`, converted by `find_jpeg_sos_offset` to `CorruptedData` (`:122-125`, `:162-167`); segment lengths extending past EOF terminate scanning (`:118-121`, `:135-140`).
- **Scan Abort Criteria**: More than 4,096 consecutive non-`0xFF` bytes preceding the first SOS $\to$ `NonMarkerRun` (`:80-85`); marker stream exceeding 16 MiB $\to$ `HeaderScanLimit` (`:72-75`); missing SOS $\to$ `CorruptedData` (`:166`).
- **Progressive / Multi-Scan**: Fully supported; requires that the first SOS is reachable; subsequent scans are shifted intact.
- **Pre-write Validation**: Whether `auto` resolves to `eof` or `app_segment`, `verify_structure` (`find_jpeg_sos_offset`) runs first, rejecting JPEGs with unreachable SOS markers (`engine.rs:1027-1035`, `jpeg.rs:517-528`).
- **64 MiB Constant**: Unreachable under the 16 MiB scan window, serving as an upper bound only.

---

## 11. Tier I Writer-Side Behaviors

- `auto` makes a single evaluation without retry (`jpeg.rs:252-269`, `engine.rs:1027-1035`).
- Capacity text, `available` flags, and limit strings are reporting artifacts (`jpeg.rs:271-322`).
- 136-byte suspicious structure thresholds, `verify_structure` log formatting, error messages, and 64 KiB buffer sizes are non-normative implementation details (`:63-69`, `:530-551`, `:517-528`).
- Segment length partitioning borrowing 1,024 bytes for final segments is part of the normative partitioning function; third-party writers constructing chains readable by this implementation must reproduce this logic (`jpeg.rs:172-195`, `:500-514`).

---

## 12. Self-Verification

```bash
cd rust
cargo test --all-features --all-targets
cargo test jpeg_ --all-features
cargo test jpeg_app_segment_capacity_keeps_relocated_sos_in_scan_window --all-features
python ../scripts/baseline_hash.py --check
```

Manual checks: verify `strhide inspect` reports strategy `app_segment` with `FF EF` preceding `ube_offset`; verify `strhide restore` recovers the original SHA-256; for multi-segment chains, verify $x + len == next - 4$ across segment boundaries.
