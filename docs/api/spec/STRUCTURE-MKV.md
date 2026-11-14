# EBML/Matroska Container Adapter: Void Injection (`ebml_void`)

This document specifies the structural domain (UBE) adapter for `format_name = "MKV"` (Matroska / WebM). Common envelope layouts, trailers, AAD, `offset_delta`, and strategy IDs are defined in [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2–§15; this document focuses on EBML container detection, strategy selection, Void element layout, capacity, locating, and cover restoration. Content domain HEVC video (including MKV packaging) is specified in [CONTENT-HEVC.md](CONTENT-HEVC.md); the two domains are mutually exclusive and non-interchangeable.

---

## 1. Scope, Navigation, and Stability

Carriers are EBML documents beginning with the 4-byte EBML Header ID. The adapter appends top-level Void elements at physical EOF without decoding audio/video tracks, inspecting `Segment` internals, or rewriting `Cues` / `SeekHead`. All original carrier bytes are copied verbatim (`rust/src/structure/adapters/mkv.rs:79-80`).

| Tier | MKV Structural Scope |
| --- | --- |
| **F** | EBML Header ID `1A 45 DF A3`; `doc_type` excluded from detection; Void ID `EC`; VINT encoding rules and all-ones reserved mask; $inject\_offset = host\_len$; $offset\_delta = 1 + vint\_len$ ($2 \dots 9$); $inject\_size = 1 + vint\_len + ube\_total\_size$; $patch\_offset = 0$; envelope terminates at physical EOF; no original bytes modified |
| **D** | `auto` unconditionally selects `ebml_void`; explicit `eof`; VINT byte width derived from UBE size; known vs unknown size `Segment` handling |
| **I** | Copy buffer sizes and streaming implementation, `strategy_note` phrasing, error message text, `suspicious_structures` warnings; readers depend on none of these |

Difference from Content Domain: Content domain steganography modifies CABAC `coeff_sign_flag` in VCL slices, preserving carrier length and container layout ([CONTENT-HEVC.md](CONTENT-HEVC.md) §2); structural domain operations append a top-level `Void` element at file EOF, leaving bitstreams untouched.

---

## 2. Format Detection (`detect`)

`detect` executes two checks, restoring stream position before returning (`mkv.rs:17-37`):

1. Save stream position $\to$ seek to 0 $\to$ read 4 bytes and verify `EBML_HEADER_ID = 0x1A45_DFA3` (`ebml.rs:9`, `mkv.rs:27-29`);
2. Invoke `read_vint_size`, passing if it returns `Ok` (`mkv.rs:30`);
3. Restore stream position (`mkv.rs:35`).

- **Excludes DocType Verification**: Does not parse `0x4282` (`matroska` / `webm`) strings, `EBMLVersion` (`0x4286`), or `DocTypeVersion`. WebM, `.ebml`, and any EBML document with valid headers pass detection.
- Does not inspect `Segment`, `SeekHead`, or `Cues`; short 5-byte files with valid headers pass detection.
- `MkvAdapter` is evaluated last in `ADAPTERS` (`rust/src/structure/registry.rs:25-36`).

Pre-write structural validation (`engine.rs:1027-1035`, `mkv.rs:146-245`) enforces true admission gates:

1. File length $< 12\text{ bytes} \to \text{"MKV file too small for EBML container"}$ (`mkv.rs:151-154`).
2. Top-level element ID read failure: leading byte zero or ID length $> 4$ (`ebml.rs:43-54`).
3. Top-level element size VINT parse failure: leading byte zero or length $> 8$ (`ebml.rs:69-80`).
4. Declared element size extends past EOF, or addition overflows (`mkv.rs:205-225`).
5. Missing EBML Header or Matroska Segment (`mkv.rs:234-239`).
6. Explicit unsupported strategy $\to$ `UnsupportedFormat` (`mkv.rs:73-77`); UBE size exceeding VINT range $\to$ `General("Envelope size exceeds the EBML VINT range")` (`mkv.rs:87-89`).

---

## 3. Strategies, `auto`, and Capacity Reporting

| Strategy | `strategy_id` | Behavior | Reference |
| --- | --- | --- | --- |
| `ebml_void` | 11 | Appends an EBML `Void` element at physical EOF, storing UBE as payload | `registry.rs:101`; `mkv.rs:86-92` |
| `eof` | 1 | Appends raw UBE at physical EOF without Void or container headers | `registry.rs:91`; `mkv.rs:93-95` |

Supported strategies: `["ebml_void", "eof"]` (`mkv.rs:39-41`); `auto` unconditionally returns `"ebml_void"`, regardless of carrier size or UBE length (`mkv.rs:43-45`). If VINT overflows, `auto` raises an error per §2 without falling back to `eof`.

Capacity reporting (`mkv.rs:47-64`): Both strategies report `capacity_bytes = None` and `limit = "unlimited (file grows)"`; `ebml_void` notes `"Embedded into compliant EBML Void element (0 trailing bytes)"`. `inspect` clamps both to $\text{structure\_payload\_limit}(host\_len) = \text{clamp}(256 \times host\_len, 64\text{ MiB}, 1\text{ GiB})$ (`engine.rs:1938-1975`).

---

## 4. Injection Layout

### 4.1 `ebml_void`

```text
Offset inject_offset = host_len (Original Physical EOF)
  +0                 EC                      ← EBML Void ID (1 byte, ebml.rs:8)
  +1                 VINT(ube_total_size)     ← 1..8 bytes (ebml.rs:25-37)
  +1+vint_len        UBE[0 .. ube_total_size)  ← offset_delta = 1 + vint_len
```

- VINT Encoding Rules: For $len \in [1, 8]$, the length marker bit is $1 \ll (7 \cdot len)$; when $val < (1 \ll (7 \cdot len)) - 1$, write $len$ bytes Big-Endian $(marker \mid val)$ (`ebml.rs:26-34`). Bits preceding the first `1` indicate byte length; remaining $7 \cdot len$ bits carry value.
- Boundary Carry: 126 encodes in 1 byte, but 127 MUST encode as 2 bytes (`40 7F`) to avoid the reserved all-ones sentinel representing "unknown size" (`ebml.rs:28-31`, tests `:111-127`). Values $\ge 2^{56} - 1$ return `None` (`ebml.rs:36`).
- $offset\_delta$ is derived from the identical VINT (`mkv.rs:292-306`), signed into AAD prior to write (`engine.rs:1267-1278`). $offset\_delta \le 9$ natively satisfies the 128B maximum limit. `ebml_void` is relocatable: if remuxing shifts prefix lengths, readers extrapolate from EOF, and `verify` / `strip` adjust $inject\_offset$ dynamically (`relocatable_strategy`).
- `inject` returns $(host\_len, 1 + vint\_len + ube\_total\_size, 0, 0)$ (`mkv.rs:86-99`): $patch\_offset = 0$; original carrier bytes are unpatched. The Void payload equals UBE length with **no padding or trailing bytes**.

Examples:

| `ube_total_size` | VINT Bytes | `offset_delta` | `inject_size` |
| --- | --- | --- | --- |
| 214 (min encrypted envelope) | `40 D6` | 3 | 217 |
| 16,383 | `20 3F FF` | 4 | 16,387 |
| 16,384 | `20 40 00` | 4 | 16,388 |
| 1 MiB (1,048,576) | `30 00 00` | 4 | 1,048,580 |

### 4.2 Placement and Unmodified Structures

- Placement is fixed at physical EOF (`host_len`, `mkv.rs:79-85`): never inserted after `SeekHead` or between Header and Segment, and never reuses existing Void elements.
- Segment Size Unmodified: The adapter never updates `Segment` sizes. A Void appended after a known-size Segment forms a **sibling top-level element**; under unknown-size Segments (`0x01FFFFFFFFFFFFFF`), it is read as a top-level element directly.
- `SeekHead` and `Cues` are never updated; original offsets remain valid, but existing indices do not catalogue the appended Void.

### 4.3 `eof`

$inject\_offset = host\_len, inject\_size = ube\_total\_size, offset\_delta = 0$, with no Void header (`mkv.rs:93-95`, `:292-306`).

---

## 5. Capacity and Bounds Table

Let $N = ube\_total\_size$ and $L = vint\_len(N)$.

| Range of $N$ | $L$ | $offset\_delta = 1 + L$ | $inject\_size$ |
| --- | --- | --- | --- |
| $0 \dots 126$ | 1 | 2 | $N + 2$ |
| $127 \dots 16,382$ | 2 | 3 | $N + 3$ |
| $16,383 \dots 2,097,150$ | 3 | 4 | $N + 4$ |
| $2,097,151 \dots 268,435,454$ | 4 | 5 | $N + 5$ |
| $268,435,455 \dots 34,359,738,366$ | 5 | 6 | $N + 6$ |
| $34,359,738,367 \dots 4,398,046,511,102$ | 6 | 7 | $N + 7$ |
| $4,398,046,511,103 \dots 562,949,953,421,310$ | 7 | 8 | $N + 8$ |
| $562,949,953,421,311 \dots 2^{56} - 2$ | 8 | 9 | $N + 9$ |

- Maximum representable VINT is $2^{56} - 2$; $2^{56} - 1$ is the reserved unknown-size sentinel.
- Segment sizing imposes no container-level ceiling.
- Engine payload limits: $raw\_size \le \text{clamp}(256 \times orig\_host\_size, 64\text{ MiB}, 1\text{ GiB})$ (`engine.rs:1123`, `:1996`).
- Lower bounds: locator requires $112 + 24 = 136$ bytes (`engine.rs:191-207`); minimum encrypted envelope is 214B (`min_ube_len(1)`).

---

## 6. Locator Pipeline (`locate`)

Execution sequence (`mkv.rs:102-137`):

1. Read final 24 bytes via `EnvelopeTrailer::read_from_tail(stego, expected_trailer_magic)`; magic mismatch returns `None`; CRC failures return `CorruptedData` (`envelope.rs:831-859`).
2. $start = trailer.locate\_start(file\_size)$: returns recorded offset if trailer is EOF-aligned, else $file\_size - ube\_total\_size$ (allowing relocation from content domain rewrites) (`envelope.rs:870-879`). Underflow returns `None`.
3. Prefix Verification: $prefix\_len = 1 + vint\_len(trailer.ube\_total\_size)$; if $start \ge prefix\_len$, read $[start - prefix\_len, start)$; if $prefix[0] == \text{0xEC}$ and following bytes match VINT exactly, return `(start, ube_total_size, "ebml_void")` (`mkv.rs:121-132`).
4. Prefix mismatch falls back to `(start, ube_total_size, "eof")` (`mkv.rs:135-136`).

`locate` does not traverse the EBML chain or parse Segment bounds; full chain scanning runs only during `verify_structure` (`mkv.rs:162-232`). `expected_header_magic` is ignored (`adapters/mod.rs:218-225`). Stealth trailer magic takes precedence over profile magic (`engine.rs:145-166`). `confine_location` enforces $ube\_total\_size \ge 136$ and containment within EOF (`engine.rs:191-207`).

---

## 7. `remove` and Cover Restoration

`MkvAdapter` uses default `strip` (`adapters/mod.rs:236-289`): copies $[0, inject\_offset)$, skips $inject\_size$, and copies remainder; $patch\_offset = 0$ requires no field rollbacks:

- `ebml_void`: Skips the entire `EC + VINT + UBE` block, restoring original carrier bytes bit-for-bit. Because no existing Segment headers, `SeekHead`, or `Cues` were modified, **no fields require restoration**.
- `eof`: Skips UBE, restoring original carrier bytes.
- `verify_restored` recomputes restored file size and SHA-256 against header $orig\_host\_size$ and $orig\_host\_sha256$, returning `RestoreMismatch` on discrepancy (`engine.rs:2299-2312`).

---

## 8. Boundary and Abnormal Structures

- **Unknown-Size Segment**: `read_vint_size` maps all-ones to `None` (`ebml.rs:94-98`), ending scanning at EOF (`mkv.rs:227-230`). Appended Void elements are read as top-level elements directly.
- **Known-Size Segment (including size = 0)**: Scanning skips the Segment, processing the appended Void as a top-level element (`mkv.rs:205-226`).
- **Pre-existing Void**: Existing Void elements are skipped by `verify_structure`; injection always appends a new Void at EOF without merging.
- **Multiple Segments**: Supported; requires at least one `MATROSKA_SEGMENT_ID` (`mkv.rs:188-189`, `:237-239`); appends after the final Segment.
- **WebM**: Handled identically; DocType and version headers are unparsed.
- **Relocation Post-Content Domain Rewrites**: `relocatable_strategy` whitelists `chunk`, `eof`, and `ebml_void` (`engine.rs:2310-2312`). If remuxing alters prefix lengths, `locate` reconstructs the offset from EOF, and `strip_coordinates_for_location` adjusts $inject\_offset$ by the shift delta (`engine.rs:2321-2350`), allowing `verify` and `remove` to succeed.
- **Suspicious Structures**: `suspicious_structures` reads the final 24 bytes looking for `ube_offset + ube_total_size == file_size` preceded by `EC + VINT` (`mkv.rs:247-290`).

---

## 9. Tier I Writer Details and Self-Verification

- Writer details: Buffer sizing, streaming transfers, and message phrasing are non-normative.
- Injection Sequence: Pre-write validation $\to$ `inject` copies carrier and appends Void $\to$ engine backfills header at `actual_ube_offset` and trailer at default offset (`engine.rs:1407-1441`). Does not override `finalize`.
- Post-Write Validation: `locate` MUST return written coordinates $(actual\_ube\_offset, ube\_total\_size)$ exactly (`engine.rs:1454-1472`).
- Regression checks: `tests/test_lifecycle/matrix.rs:113, 128, 400, 426` validate `ebml_void` lifecycle; `tests/test_security/forge.rs:191-198` validates forged `ube_total_size` rejection.
