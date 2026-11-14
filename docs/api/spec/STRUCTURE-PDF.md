# PDF Structural Domain Adapter: Incremental Update (`incremental`)

This document specifies the structural domain (UBE) adapter for `format_name = "PDF"`. Common envelope layouts and `offset_delta` semantics are in [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) (§12 and §14); capacity metrics are summarized in [CAPACITY.md](CAPACITY.md) §4. Citations are given as `file:line` relative to the repository root.

---

## 1. Scope, Navigation, and Stability

Carriers are ISO 32000-1 PDF documents. The adapter avoids parsing page trees, content streams, object streams, or cross-reference entries, reading only the trailing `startxref` / `%%EOF` / trailer structures, and appending a compliant incremental update section. The UBE stream is embedded as the payload of a standard stream object.

| Tier | PDF Structural Scope |
| --- | --- |
| **F** | `%PDF-` detection (`pdf.rs:8`, `:672-684`); 1 MiB backward scan window for final `%%EOF` (`pdf.rs:121`, `:143-155`); 64 KiB window for `startxref` / trailer (`pdf.rs:308`); 8 KiB window and balanced `<<>>` parsing for XRef stream dictionaries (`pdf.rs:214`, `:177-198`); extraction rules for `/Size`, `/Root`, and `/Encrypt`; object header template and `END_OBJ` (`pdf.rs:589-591`, `:784`); classic `xref` / `trailer` vs XRef stream layout templates (`pdf.rs:793-865`); `/Prev` chaining; $offset\_delta = 46 + \text{digits}(N) + \text{digits}(L)$ (`pdf.rs:589-591`, `:1171-1188`); EOL absorption after `%%EOF` (`pdf.rs:313-320`); trailing dirty data preservation (`pdf.rs:873-874`); strategy IDs: `incremental = 6`, `eof = 1` (`registry.rs:91`, `:96`) |
| **D** | Trailer and header magic only (standard, Profile dialect, stealth-derived); passed via `expected_trailer_magic` without altering layout geometry (`engine.rs:145-166`) |
| **I** | Sizing of 64 KiB / 8 KiB / 1 MiB scanning windows (`pdf.rs:120-121`, `:214`, `:308`); `strategy_note` and capacity text (`pdf.rs:708-740`, `:1070-1080`); candidate `endstream` enumeration paths |

---

## 2. Format Detection (`detect`) and Pre-Write Rejection

`detect` verifies the initial 5 bytes `%PDF-` at offset 0, restoring stream position before returning (`pdf.rs:8`, `:672-684`):

1. Save stream position; `seek(Start(0))` failure returns `false`;
2. Read 5 bytes via `read_exact`; failures return `false`;
3. Returns `true` if and only if bytes match `PDF_MAGIC` (`pdf.rs:673-681`);
4. Restore stream position (`pdf.rs:682`).

PDFs where `%PDF-` is preceded by BOM or leading garbage (which some readers tolerate up to 1024B) are **not** detected; version numbers (`%PDF-1.x`) are unparsed; file extensions are ignored. Registration order tests PDF after ZIP (`registry.rs:25-36`).

Structural validation is enforced via `find_last_eof` (`pdf.rs:108-160`):

- If a valid EOF envelope terminates at EOF (validated via trailer magic with $ube\_offset + ube\_total\_size == file\_size$), the effective EOF rolls back to `t.ube_offset` (`pdf.rs:124-141`);
- Otherwise, scans backward from `file_size` up to 1 MiB (`pdf.rs:121`, `:143`) in 64 KiB blocks (`pdf.rs:120`) to locate the **last occurrence** of `%%EOF` (`pdf.rs:145-155`); failure returns `CorruptedData("Valid PDF %%EOF marker not found within tail window")` (`pdf.rs:157-159`).

Multiple `%%EOF` / xref incremental update chains are not traversed: the engine extracts the final marker and its nearest preceding `startxref` (`pdf.rs:322-334`); earlier revisions serve as fallbacks for `/Root` and `/Info` within the 64 KiB tail window (`pdf.rs:440-445`).

Linearized PDFs: Handled as standard incremental updates without parsing `/Linearized` dictionaries or hint tables (new revisions append at EOF, and readers prioritize the final `startxref`).

Encrypted PDFs: Rejection criteria for the incremental strategy (`parse_pdf_trailer_info`, `pdf.rs:50-96`) trigger if any of the following hold:

1. The newest trailer (classic `trailer` or XRef stream dictionary) contains an indirect reference `/Encrypt N G R` $\to$ `CorruptedData("PDF is encrypted (/Encrypt in the newest trailer)...")` (`pdf.rs:60-66`, `:390`, `:245`);
2. The next object ID cannot be resolved (no `/Size` and no discoverable `N G obj`) $\to$ `pdf.rs:68-72`; or object ID $\ge \text{0x7FFF\_FFFF}$ ($2,147,483,647$) or $\ge \text{u64::MAX} - 1 \to$ `pdf.rs:73-77`;
3. `/Root` cannot be determined $\to$ `pdf.rs:82-86`;
4. `%%EOF` or `startxref` is missing, or `startxref` integer parsing fails $\to$ `pdf.rs:157-159`, `:323-334`.

`/Encrypt` checks the newest trailer only without traversing `/Prev` (`pdf.rs:39-44`, `:435-439`). Encrypted documents cannot use `incremental`, causing `auto` to route to `eof` (`pdf.rs:697-705`); `eof` does not parse trailers.

Digitally signed PDFs are rejected prior to write by an independent guard checking for overlapping `/ByteRange` and `/Sig` markers (`rejection.rs:158-209`, `:395-397`).

---

## 3. Supported Strategies and `auto`

| Strategy | `strategy_id` | Behavior | Reference |
| --- | --- | --- | --- |
| `incremental` | 6 | Appends a stream object, incremental xref section, and new `%%EOF` past the old `%%EOF`, storing UBE as stream data | `pdf.rs:742-877`; `registry.rs:96` |
| `eof` | 1 | Delegates to `EofAdapter`, appending UBE at physical EOF (past any trailing dirty bytes) | `pdf.rs:749-751`; `eof.rs:35-56`; `registry.rs:91` |

`auto` invokes `choose_auto_strategy(host, exact_ube_size)` once without retry (`engine.rs:1242-1246`): if `parse_pdf_trailer_info` succeeds and $pdf\_obj\_header(new\_obj\_num, ube\_size).len() \le \text{MAX\_OFFSET\_DELTA (128)}$, it selects `incremental`; otherwise (parse failure, encryption, header $> 128$) it selects `eof` (`pdf.rs:690-706`; `envelope.rs:81`). Explicit unsupported strategies return `UnsupportedFormat` (`pdf.rs:686-688`, `engine.rs:1248-1253`).

---

## 4. Injection Layout

The UBE stream resides **inside the new incremental update section** (preceding the new `%%EOF`), not appended at EOF; layout sequence (`pdf.rs:768-874`):

```text
[0, eof_offset)                          Copied verbatim: includes old %%EOF and up to 16B of trailing CR/LF
                                         (eof_offset = marker start + 5 + newline count, pdf.rs:313-320)
eof_offset                               inject_offset
+ obj_header                             "\n{N} 0 obj\n<< /Type /Metadata /Length {L} >>\nstream\n"
                                         (pdf.rs:589-591, leading \n absorbed into offset_delta)
+ UBE                                    Header 112 B ... Trailer 24 B (written verbatim)
+ "\nendstream\nendobj\n"                18 B (pdf.rs:784)
+ xref section                           Classic or XRef stream layout (see below)
+ dirty tail                             Original [eof_offset, EOF) copied after new %%EOF
                                         (pdf.rs:873-874)
```

- $offset\_delta = pdf\_obj\_header(N, L).len() = 46 + \text{digits}(N) + \text{digits}(L)$: 46 is the template constant, and `digits` denotes decimal character count (`pdf.rs:589-591`, `:1171-1188`). $inject\_offset + offset\_delta$ represents the UBE start offset.
- Object ID $N = new\_obj\_num$: classic documents use `/Size` from newest trailer (`pdf.rs:336-343`, `:384-391`); XRef streams use stream dictionary `/Size` (`pdf.rs:405-419`); falls back to $\max(N) + 1$ scanned across the 64 KiB window (`pdf.rs:420-431`, `:535-579`).
- Classic Section (newest xref anchor is `xref` keyword, `pdf.rs:262-289`): `xref\n{N} 1\n{actual_obj_offset:010} 00000 n \n`, followed by `trailer\n<<\n/Size {N+1}\n`, optional `/Root`, `/Info`, `/Prev {prev_startxref}\n>>\nstartxref\n{xref_offset}\n%%EOF\n` (`pdf.rs:846-864`). $actual\_obj\_offset = inject\_offset + 1$, pointing to `N 0 obj` (`pdf.rs:776`, `:822-826`).
- XRef Stream Section (newest anchor is `N G obj` with dictionary `/Type /XRef`, `pdf.rs:363-370`, `:237-239`): Appends object $M = N + 1$ with dictionary `/Type /XRef`, `/Size {M+1}`, `/W [1 4 2]`, `/Index [N 2]`, `/Root`, `/Info`, `/Prev {prev_startxref}`, `/Length 14`; the 14-byte data encodes two `type=1 | offset(4B BE) | gen=0(2B)` entries pointing to `actual_obj_offset` and `xref_offset`; terminated via `\nendstream\nendobj\nstartxref\n{xref_offset}\n%%EOF\n` (`pdf.rs:802-830`). The emitted dialect matches the latest revision.
- $xref\_offset = inject\_offset + obj\_header.len() + ube\_size + 18$ (`pdf.rs:791`).
- `inject` returns $(eof\_offset, inject\_size, 0, 0)$ (`pdf.rs:876`), where $inject\_size = \text{obj\_header} + ube\_size + 18 + \text{xref\_section\_len}$ (`pdf.rs:867`). File expansion equals `inject_size`; dirty tails are shifted past the new `%%EOF` (`fixes.rs:408`).
- Reader Tolerance: Follows standard ISO 32000-1 incremental updates (final `%%EOF` $\to$ `startxref` $\to$ `/Prev` chain).

---

## 5. Capacity and Bounds

`strategy_capacities` reports `capacity_bytes = None` and `limit = "unlimited (file grows)"` for both strategies (`pdf.rs:709-739`). `incremental` availability requires `parse_pdf_trailer_info` success, falling back to `available = false` on error (`pdf.rs:716-729`).

Hard bounds enforced by code:

```text
offset_delta = 46 + digits(N) + digits(L) <= 128       // If exceeded, auto routes to eof; incremental errors
N <= 0x7FFF_FFFE                                       // parse rejects >= 0x7FFF_FFFF
Classic xref: actual_obj_offset <= 9_999_999_999       // 10-digit field; >= 10^10 rejected
XRef stream:  xref_offset < 2^32                       // 4-byte offset; >= 4 GiB rejected
Payload <= clamp(256 * host_len, 64 MiB, 1 GiB)       // Engine payload limit
```

- The 128B delta limit (`MAX_OFFSET_DELTA`, `envelope.rs:88`) bounds the combined decimal digits of object ID and `/Length`. If exceeded, `auto` routes to `eof` (`pdf.rs:692-706`), while explicit `incremental` returns `General("... exceeds the 128 bytes the header can record")` (`engine.rs:1303-1310`).
- Object ID overflow and 10-digit field overflow emit `UnsupportedFormat("... larger than 10 GB ...")` (`pdf.rs:839-845`); XRef stream 4GB overflow emits `UnsupportedFormat("... larger than 4 GB ...")` (`pdf.rs:795-801`).
- `inspect` clamps `None` to $\text{structure\_payload\_limit}(host\_len) = \text{clamp}(256 \times host\_len, 64\text{ MiB}, 1\text{ GiB})$ (`engine.rs:1938-1943`, `:1952-1975`; `crypto.rs:786`).
- Lower bounds: `locate` requires $ube\_offset \ge 8$ (`pdf.rs:644-648`) and $ube\_total\_size \ge 136$ (`engine.rs:199-201`). Minimum encrypted envelope is 214B (`min_ube_len(1)`).

---

## 6. Locator Pipeline (`locate`)

Validates `%PDF-` first (`pdf.rs:884-888`), then evaluates two paths (`pdf.rs:879-935`):

1. **Incremental Path**: After `find_last_eof` succeeds, scans backward within the preceding 64 KiB window for `endstream` (`pdf.rs:898-923`). Evaluates each candidate via `try_locate_endstream`: allowing 0..3 trailing CR/LF within a 24+3B window before `endstream`, unpacks the 24B trailer, validating $trailer.ube\_offset + ube\_total\_size == abs\_stream\_end$ and $ube\_offset \ge 8$, and verifies that the 8 bytes preceding `ube_offset` end with `stream\r\n`, `stream\n`, or `stream` (`pdf.rs:613-665`). Returns `(ube_offset, ube_total_size, "incremental")`.
2. **EOF Path**: If `EnvelopeTrailer::read_from_tail` matches with $ube\_offset + ube\_total\_size == file\_size \implies (ube\_offset, ube\_total\_size, "eof")$ (`pdf.rs:927-932`).
3. Otherwise returns `Ok(None)` (`pdf.rs:934`).

UBE origin is read directly from trailer `ube_offset`. `expected_header_magic` is ignored in this adapter (`adapters/mod.rs:218-225`). Stealth trailer magic takes precedence over profile magic (`engine.rs:145-166`). `confine_location` enforces physical containment ($ube\_total\_size \ge 136$, $ube\_offset + ube\_total\_size \le file\_len$, `engine.rs:191-207`).

---

## 7. `remove` and Cover Restoration

PDF uses default `strip` (`adapters/mod.rs:236-290`): copies $[0, inject\_offset)$, skips $inject\_size$ bytes, and copies remaining bytes to EOF; $patch\_offset == 0$ requires no field rollbacks (`pdf.rs:876`, `engine.rs:2255`):

- `incremental`: Skips object header + UBE + `endstream/endobj` + xref section; dirty tails past $inject\_offset + inject\_size$ are appended, recovering $[0, eof\_offset) + \text{dirty\_tail} = \text{original file}$ (`pdf.rs:313-320`, `:873-874`).
- `eof`: $inject\_offset = host\_len, inject\_size = ube\_len$, restoring original file (`eof.rs:48-56`, `:74-83`).

Pre-restoration validation: $inject\_offset + offset\_delta == ube\_offset$ (`incremental` is not relocatable, `engine.rs:2268-2296`), $ube\_total\_size \le inject\_size$, and file bounds containment (`engine.rs:2828-2902`). Restored size and SHA-256 are verified against header values, returning `RestoreMismatch` on discrepancy (`engine.rs:2299-2361`).

---

## 8. Boundary Conditions

| Condition | Behavior |
| --- | --- |
| Corrupted xref / missing `startxref` | Missing `startxref` disables `incremental` (`auto` routes to `eof`); existing incremental envelopes remain discoverable via `locate` (xref unparsed) |
| Incremental update chains (multiple `%%EOF`) | Parses final `%%EOF` and nearest preceding `startxref` only; earlier revisions serve as `/Root`/`/Info` fallbacks within 64 KiB (`pdf.rs:440-445`) |
| `%%EOF` in comments | If placed past the true marker, backward scan anchors to it, advancing `eof_offset` into comments (`pdf.rs:143-155`) |
| `trailer` / `startxref` in comments | Handled via object scan fallback or triggers parse failure (`pdf.rs:322-334`, `:420-431`) |
| `obj` / `startxref` tokens in streams | Scanned as lossy UTF-8 text; mitigates by selecting $\max(/Size, \text{scanned})$ and requiring dictionary syntax (`pdf.rs:262-289`, `:422-431`) |
| Linearized PDF | Handled as standard incremental update; linearization hint tables remain unmodified |
| Encrypted PDF (indirect `/Encrypt`) | `incremental` rejected; `auto` routes to `eof` (`pdf.rs:60-66`) |
| Trailing dirty data | Preserved intact following the new `%%EOF` (`pdf.rs:869-874`) |
| `eof` envelope $> 1\text{ MiB}$ | 1 MiB scan window may miss old `%%EOF`; path 1 skips, but path 2 succeeds via EOF trailer (`pdf.rs:121`, `:927-932`) |
| `%PDF-` not at offset 0 | Fails `detect`, rejecting file as a PDF carrier (`pdf.rs:672-684`) |

`suspicious_structures` flags trailer signatures within the trailing 128 KiB preceded by `stream` or `%%EOF` (`pdf.rs:973-1055`).

---

## 9. Tier I Writer Details and Self-Verification

- **Streaming Transfers**: Transferred via 64 KiB buffers with `copy_exact` (`io.rs:11-30`, `pdf.rs:769-781`).
- **Invariance**: $[0, eof\_offset)$, existing `%%EOF`, dirty tails, and reference tokens are copied verbatim; only new objects and xref sections are appended (`pdf.rs:768-874`).
- **Post-Write Validation**: Re-running `locate` MUST return $(actual\_ube\_offset, ube\_total\_size)$ exactly (`engine.rs:1454-1472`).
- **Regression Commands**:

```bash
cargo test --all-features --all-targets
python scripts/baseline_hash.py --check
```
