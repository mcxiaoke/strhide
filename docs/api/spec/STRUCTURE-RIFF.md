# RIFF Container Adapter: WAV / WebP Private Chunk Injection (`riff_chunk`)

This document specifies the structural domain (UBE) adapters for `format_name = "WAV"` and `"WEBP"`. Common definitions for envelopes, trailers, AAD, `offset_delta`, and strategy IDs are defined in [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2–§15; this document focuses on RIFF container detection, strategy selection, chunk layout, capacity, and cover restoration. Content domain steganography (WAV PCM LSB / FLAC residuals) is defined in [CONTENT-AUDIO.md](CONTENT-AUDIO.md); the two domains are mutually exclusive and non-interchangeable.

---

## 1. Scope, Navigation, and Stability

Carriers are `WAVE` or `WEBP` containers starting with a 12-byte RIFF header. Adapters operate strictly on top-level chunk streams: no PCM audio decoding, no WebP image decoding, and no re-encoding; envelopes are appended exclusively as newly constructed top-level chunks.

| Tier | RIFF Structural Scope |
| --- | --- |
| **F** | `"RIFF"` + `u32le` size + form type (`WAVE` / `WEBP`); chunk identifier `"SHRD"`; chunk length field `u32le`; 8-byte chunk header prepended to UBE; append at physical EOF; 1-byte `0x00` padding on odd byte counts; `riff_chunk` parameters: $offset\_delta = 8$, $patch\_offset = 4$, $inject\_size = 8 + ube\_total\_size + (ube\_total\_size \& 1)$; RIFF size field updated per §4.2; coordinate cross-verification in locator |
| **D** | Carrier branching: WebP Extended Format (first chunk following 12B header is `VP8X`) permits `riff_chunk`, while Simple Format allows `eof` only; whether declared RIFF boundary equals physical EOF and whether chunk tables span the boundary precisely determine `riff_chunk` availability; UBE oddness dictates padding byte |
| **I** | Copy buffering / streaming methods, scanner implementation, `strategy_note` phrasing, error messages, `auto` predicate invocation frequency; readers depend on none of these |

Difference from Content Domain WAV/FLAC: Structural domain operations append a RIFF chunk, leaving PCM samples inside `data` and FLAC residual frames byte-for-byte untouched; PCM LSB and residual mutations belong to [CONTENT-AUDIO.md](CONTENT-AUDIO.md).

---

## 2. Format Detection (`detect`)

`detect` inspects the first 12 bytes exclusively: `buf[0..4] == "RIFF"` and `buf[8..12]` equals the expected form type (`b"WAVE"` for WAV, `b"WEBP"` for WebP), returning `true` on match and `false` otherwise without raising errors, restoring stream position before returning (`rust/src/structure/adapters/riff.rs:13-31`, `wav.rs:18`, `webp.rs:18`). It does not validate the size field, chunk table, minimum file length, or WebP `VP8X`. Registration evaluates in `registry.rs:25-36` order (`WEBP` precedes `WAV`), with distinct form types preventing misclassification.

Structural validation gates occur during pre-write verification and injection:

1. File length $< 12 \to \text{CorruptedData}("<format>\text{ file too small for a valid RIFF header}")$ (`riff.rs:62-68`).
2. $host\_len \ne 8 + old\_riff\_size$ (streaming WAV with size 0 or `0xFFFFFFFF`, trailing garbage) $\to$ `CorruptedData`, prompting switch to `--strategy eof` (`riff.rs:93-99`).
3. Chunk table does not span declared boundary precisely $\to$ `CorruptedData`; trailing odd-length chunk missing pad returns `MissingFinalPad` (`riff.rs:107-121`, `:389-446`).
4. WebP Simple Format explicitly requesting `riff_chunk` $\to$ `UnsupportedFormat`, prompting switch to `--strategy eof` (`webp.rs:53-68`).
5. Pre-write checks enforce Tier 1 prerequisites: WAV requires `fmt ` and `data` chunks; WebP requires one of `VP8 `, `VP8L`, or `VP8X` (`wav.rs:77-85`, `webp.rs:96-104`, `engine.rs:1027-1035`).

---

## 3. Strategies, `auto`, and Capacity Reporting

| Strategy | `strategy_id` | Behavior | Reference |
| --- | --- | --- | --- |
| `riff_chunk` | 10 | Appends a new `SHRD` top-level chunk at physical EOF with UBE as chunk data | `registry.rs:90-104`; `riff.rs:81-161` |
| `eof` | 1 | Appends UBE after EOF without modifying RIFF headers | `registry.rs:91`; `riff.rs:73-78` |

Both adapters list `["riff_chunk", "eof"]` in order of precedence (`wav.rs:21-23`, `webp.rs:21-23`). `auto` resolution rules:

- WAV: If `riff_can_chunk(reader, ube_size)` is true, select `riff_chunk`; otherwise select `eof` (`wav.rs:25-35`).
- WebP: If the first chunk following 12B header is `VP8X` **and** `riff_can_chunk` is true, select `riff_chunk`; otherwise select `eof` (`webp.rs:25-36`).

`riff_can_chunk` enforces injection requirements: $host\_len == 8 + old\_riff\_size$, chunk table is `Exact`, and $old\_riff\_size + inject\_size \le \text{u32::MAX}$ (`riff.rs:454-479`). `riff_chunk` always causes the file to expand.

Capacity reporting (`riff.rs:520-560`): Under **dynamic inspection** (`reader != None`), `riff_chunk` reports actual usable headroom $capacity\_bytes = \text{u32::MAX} - old\_riff\_size - 8$ (`riff.rs:483-503`); if this headroom falls below `min_ube_len(0)`, it sets `available = false`, `capacity_bytes = None`, noting fallback to `eof` (`riff.rs:506-518`, `:546-556`). Under **static inspection** (`reader == None`), it reports `capacity_bytes = None` and `limit = "up to 4GB RIFF limit (file grows)"`; `eof` is unbounded. `inspect` clamps both to the engine ceiling $\text{structure\_payload\_limit}(host\_len) = \text{clamp}(256 \times host\_len, 64\text{ MiB}, 1\text{ GiB})$ (`engine.rs:1938-1975`, `:2604-2611`), omitting values when `available = false`.

---

## 4. Injection Layout

### 4.1 `riff_chunk`

```text
Offset inject_offset = host_len (Original Physical EOF)
  +0                "SHRD" (53 48 52 44)
  +4                u32le chunk_size = ube_total_size
  +8                UBE[0 .. ube_total_size)        ← offset_delta = 8
  +8+ube_total_size 0x00 (Only if ube_total_size is odd)
```

- Chunk identifier literal is `SHRD` (`riff.rs:11`); length field counts chunk data only, **excluding** its 8-byte header and **excluding** the padding byte (`riff.rs:147-157`).
- Appended strictly after all existing chunks without reordering (`riff.rs:142-145`).
- $inject\_size = 8 + ube\_total\_size + (ube\_total\_size \& 1)$ (`riff.rs:123-124`); `inject` returns $(host\_len, inject\_size, 4, old\_riff\_size)$ (`riff.rs:160`), indicating a 4-byte patch at offset 4.

### 4.2 RIFF Total Size Field

$new\_riff\_size = old\_riff\_size + inject\_size$, validated against $new\_riff\_size \le \text{u32::MAX}$ (`riff.rs:126-133`); writes `"RIFF" + u32le(new_riff_size) + form_type` (`riff.rs:136-138`). The RIFF size field represents "file length - 8"; hence post-injection file length is $8 + new\_riff\_size$. Outside offset 4, all other bytes of the 12-byte header and existing chunks are copied verbatim (`riff.rs:142-143`).

### 4.3 `eof`

RIFF headers remain unmodified; $inject\_size = ube\_total\_size$, $inject\_offset = host\_len$, $offset\_delta = 0$, with no patch ($patch\_offset = 0$) (`riff.rs:73-78`, `wav.rs:100-104`, `webp.rs:118-122`).

---

## 5. Differences between WAV and WebP

| Feature | WAV | WebP |
| --- | --- | --- |
| Form Type | `WAVE` | `WEBP` |
| Chunk FourCC | `SHRD` | `SHRD` (shared constant) |
| `riff_chunk` Prerequisite | Any valid `RIFF/WAVE` per §2 | Extended Format: first chunk after 12B header MUST be `VP8X` (`webp.rs:25-36`, `:53-68`) |
| L1 Mandatory Chunks | `fmt ` and `data` (`wav.rs:77-85`) | Any one of `VP8 `, `VP8L`, or `VP8X` (`webp.rs:96-104`) |
| Capacity Note | Boundary mismatch notes "auto falls back to eof" (`riff.rs:499-505`) | Notes Simple Format lacking `VP8X` (`webp.rs:44-49`) |
| Append Location | Physical EOF (after `data` / `LIST`) | Physical EOF (after all top-level chunks) |

---

## 6. Capacity Formulas, Bounds, and Overflow Behaviors

Let $H = host\_len$, $R = old\_riff\_size$ (u32le), $N = ube\_total\_size$, and $P = N \& 1$. `riff_chunk` is eligible if and only if:

```text
H == 8 + R
Chunk table spans H precisely
R + 8 + N + P <= 0xFFFF_FFFF        <=>  R + inject_size <= u32::MAX
```

The chunk size field can theoretically record $N$, but container size triggers first: maximum $N$ satisfies $N + P \le \text{0xFFFF\_FFFF} - R - 8$, meaning capacity is bounded by $R$ rather than an independent 4 GiB. Maximum post-injection file size is $\text{0xFFFF\_FFFF} + 8$ bytes.

- Structural lower bound: `locate` requires chunk length $\ge 24$ (`riff.rs:194`); `confine_location` requires $ube\_total\_size \ge 112 + 24 = 136$ (`engine.rs:191-207`). Practical minimum envelopes are `min_ube_len(0) = 213` and `min_ube_len(1) = 214` (`rust/src/structure/envelope.rs:123-140`).
- Engine payload limit: $raw\_size \le \text{clamp}(256 \times orig\_host\_size, 64\text{ MiB}, 1\text{ GiB})$ (`engine.rs:1123`, `:1938-1943`).
- Overflow behavior: `auto` falls back to `eof` when `riff_can_chunk` fails; explicit `riff_chunk` with overflowing size returns `General("RIFF 4GB container size overflow")` (`riff.rs:126-133`), and boundary/table errors return `CorruptedData` suggesting `--strategy eof` (`riff.rs:93-121`).

---

## 7. Locator Pipeline (`locate`)

`riff_locate` executes in this order (`riff.rs:163-228`):

1. File $< 12\text{B}$ or first 4 bytes $\ne \text{"RIFF"} \to \text{Ok(None)}$; does NOT check form type or size fields at this step (`riff.rs:167-176`).
2. Scan top-level chunks forward from offset 12: read `[4CC][u32le size]`, advancing by $8 + size + (size \& 1)$ (`riff.rs:180-218`).
3. On finding `SHRD` with $size \ge 24$ contained within EOF: read 24B trailer from $data\_end - 24$ and unpack with expected trailer magic; if $trailer.ube\_offset == data\_offset$ and $trailer.ube\_total\_size == size$, return `(data_offset, size, "riff_chunk")` (`riff.rs:192-210`).
4. Fallback to EOF trailer if not found in chunk scan: read 24B trailer from EOF, evaluating `locate_start(file_size)` to return `(start, ube_total_size, "eof")` (`riff.rs:221-225`, `envelope.rs:870-879`).
5. Hints: `expected_header_magic` is ignored; uses `expected_trailer_magic` only (`adapters/mod.rs:218-225`). Stealth trailer magic takes precedence over profile magic (`engine.rs:145-166`).
6. Containment check: $ube\_total\_size \ge 136$ and $ube\_offset + ube\_total\_size \le \text{file\_size}$ (`engine.rs:191-207`), followed by coordinate cross-check with $offset\_delta$ (`engine.rs:2828-2902`). `riff_chunk` does not permit relocation; coordinate desynchronization returns `CorruptedData` (`engine.rs:2268-2296`).

---

## 8. `remove` and Cover Restoration

WAV and WebP adapters use default `strip`: copies $[0, inject\_offset)$, skips $inject\_size$ bytes, copies remainder to EOF; if $patch\_offset \ne 0$, writes $orig\_patch\_val$ at output stream offset $patch\_offset$ (`adapters/mod.rs:236-289`).

- `riff_chunk`: Skips the entire `SHRD` chunk (8B header + UBE + padding). Because offset 4 falls within $[0, inject\_offset)$, the modified size was initially copied, but `patch_offset = 4` immediately restores $old\_riff\_size$, reverting the RIFF size field to its original value; all other chunks are untouched.
- `eof`: Copies $[0, host\_len)$, with $patch\_offset = 0$.
- `verify_restored` recomputes restored file size and SHA-256 against $orig\_host\_size$ and $orig\_host\_sha256$, returning `RestoreMismatch` on discrepancy (`engine.rs:2298-2312`).

---

## 9. Boundary and Abnormal Structures

- `LIST` / `INFO`: Handled as standard top-level chunks based on outer length, without parsing sub-chunks (`riff.rs:180-218`, `:406-446`).
- `fact`: Neither checked nor required.
- `data`: Structural adapters neither parse nor modify sample data; `SHRD` appends past `data`.
- WebP `VP8X`: Checks only that FourCC at offset 12 is `VP8X` (`riff.rs:36-47`), without parsing canvas dimensions or flags.
- Corrupted Chunks: If `riff_chunk_table` returns `None` or `MissingFinalPad`, writing is rejected; `verify_structure` returns `(false, details)` (`riff.rs:292-336`).
- Streaming WAVs (size = 0 or `0xFFFFFFFF`): `riff_chunk` rejects, `auto` routes to `eof`; `verify_structure` permits EOF overlays on chunk boundaries (`riff.rs:263-290`).
- `suspicious_structures` flags any `SHRD` chunk regardless of length (`riff.rs:348-386`).

---

## 10. Tier I Writer Details and Self-Verification

- Writer details: Copy buffer sizes, streaming strategies, scan caching, and message phrasing are non-normative.
- Injection Sequence: Pre-write validation $\to$ `riff_inject` writes new RIFF header, copies chunks, appends `SHRD` $\to$ engine backfills header at `actual_ube_offset` and trailer at default trailer offset (`engine.rs:1428-1441`). RIFF does not override `finalize`.
- Post-write verification: `locate` MUST recover the written coordinates $(actual\_ube\_offset, ube\_total\_size)$ exactly; failures abort and clean up temporary files (`engine.rs:1454-1472`, `:1601`).
- Regression tests: `tests/test_regression/review_20261025.rs:123-175` validates $inject\_offset = host\_len$, $patch\_offset = 4$, $inject\_size = 8 + ube\_total\_size$; `tests/test_lifecycle/matrix.rs:734-793` covers Simple WebP `auto -> eof` and explicit `riff_chunk` rejection.
