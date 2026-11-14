# ZIP Structural Domain Adapter: Pre-Central-Directory Injection (`pre_cd_inject`)

This document specifies the structural domain (UBE) adapter for `format_name = "ZIP"`. Common envelope layouts, trailers, AAD, and strategy IDs are defined in [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2–§15; capacity metrics are summarized in [CAPACITY.md](CAPACITY.md) §4. Citations are given as `file:line` relative to the repository root.

---

## 1. Scope, Navigation, and Stability

Carriers are ZIP archives (and isomorphic formats such as `.jar`, `.docx`, `.xlsx`, `.pptx`) with discoverable End of Central Directory (EOCD) records. The adapter performs byte relocation and EOCD field patching without decompressing, parsing local file headers, or validating entry CRCs.

| Tier | ZIP Structural Scope |
| --- | --- |
| **F** | EOCD signature `PK\x05\x06` and 65,558B scan window; injection point = declared EOCD `cd_offset`; UBE placed flush before the Central Directory; EOCD+16 patched to $cd\_offset + ube\_size$; $offset\_delta = 0$; $patch\_offset = eocd\_pos + 16 + ube\_size$; $inject\_size = ube\_size$; strategy names `pre_cd_inject` / `eof` with IDs 4 / 1; 32-bit capacity inequality; ZIP64 / empty archive / overflow rejection criteria |
| **D** | None. The adapter does not read `Profile`; only expected trailer magic varies with dialect, without altering geometry |
| **I** | Copy buffer size (64 KiB, `rust/src/structure/adapters/io.rs:6`), `strategy_note` phrasing (`zip.rs:494-504`), EOCD candidate collection heuristics, capacity string formatting |

Constants: `rust/src/structure/adapters/zip.rs:10-14` (`ZIP_LOCAL_MAGIC` `PK\x03\x04`, `ZIP_EOCD_MAGIC` `PK\x05\x06`, `ZIP_SPAN_MAGIC` `PK\x07\x08`, `ZIP_CD_MAGIC` `PK\x01\x02`); strategy registry `rust/src/structure/registry.rs:90-104` (`pre_cd_inject = 4`, `eof = 1`).

---

## 2. Format Detection (`detect`)

`detect` compares the first 4 bytes exclusively, restoring stream position before returning (`zip.rs:123-139`):

1. Record stream position; `seek(Start(0))` failure returns `false` (`zip.rs:124-130`);
2. Read first 4 bytes; files $\le 3$ bytes return `false`;
3. Returns `true` if and only if bytes match `PK\x03\x04`, `PK\x05\x06`, or `PK\x07\x08` (`zip.rs:131-136`);
4. Restore stream position (`zip.rs:137`).

EOCD-only 22B empty archives pass detection because their first 4 bytes are `PK\x05\x06` (`rust/tests/test_regression/review_20261025.rs:59-70`); `PK\x07\x08` represents a data descriptor signature (`ZIP_SPAN_MAGIC`, `zip.rs:12`), recognized to tolerate truncated/abnormal files. Detection operates independently of file extensions, ZIP64 status, or encryption.

`find_eocd_offset` (`zip.rs:16-75`, shared between readers and writers) enforces true structural validation:

- Scan window: $scan\_len = \min(file\_size, 65536 + 22)$, buffering the tail into memory and scanning backward for all 4-byte occurrences of `PK\x05\x06` (`0x06054b50`) (`zip.rs:19-41`); EOCD records beyond the trailing 65,558 bytes are treated as non-existent.
- Two-pass scan: Pass 1 requires the record to terminate at EOF ($eocd\_pos + 22 + comment\_len == file\_size$); Pass 2 relaxes this to $\le file\_size$ (supporting `eof` envelopes appended past EOCD) (`zip.rs:43-55`).
- Candidate admission: Requires $cd\_offset + cd\_size \le eocd\_pos$ (or $cd\_offset == cd\_size == 0$ on empty archives) AND verification that bytes at `cd_offset` are `PK\x01\x02` (`zip.rs:57-64`, `:87-93`), preventing forged EOCD bytes inside comments from misplacing injection points (`zip.rs:25-34`).
- Failure to locate a valid EOCD returns `CorruptedData("Valid ZIP EOCD ... record not found")` (`zip.rs:72-74`).

EOCD fields parsed: `cd_size` (+12), `cd_offset` (+16), `comment_len` (+20); disk numbers (+4/+6) and entry counts (+8/+10) are neither read nor validated (`zip.rs:48-63`).

ZIP64 detection is location-based: `has_zip64_locator` inspects the 4 bytes at $eocd\_pos - 20$; if equal to `PK\x06\x07` (`0x07064b50`), it flags ZIP64 (`zip.rs:105-114`). The ZIP64 EOCD record `PK\x06\x06` is **never parsed**. Real ZIP64 archives with 32-bit fields set to sentinel `0xFFFFFFFF` fail `find_eocd_offset` immediately with `CorruptedData`; only hybrid ZIP64 files retaining valid 32-bit fields alongside locators are detected and rejected per §5.

SFX Tolerance: `find_eocd_offset` skips past arbitrary pre-CD stubs, copying $[0, cd\_offset)$ intact (`zip.rs:286-287`). However, `detect` requires the first 4 bytes to match one of the three `PK` signatures, preventing `MZ`-prefixed executables from entering this adapter.

---

## 3. Supported Strategies and `auto`

| Strategy | `strategy_id` | Behavior | Reference |
| --- | --- | --- | --- |
| `pre_cd_inject` | 4 | Inserts UBE at `cd_offset` and updates EOCD's `cd_offset` field | `zip.rs:240-315`; `registry.rs:94` |
| `eof` | 1 | Delegates to `EofAdapter`, appending UBE past EOF | `zip.rs:247-249`; `eof.rs:35-56`; `registry.rs:91` |

`auto` makes a single-pass determination without retry (`zip.rs:145-171`, `engine.rs:1242-1255`):

1. If `find_eocd_offset` returns $cd\_offset == 0$ (empty archive, UBE would overwrite signature) $\to \text{eof}$ (`zip.rs:151`);
2. If ZIP64 locator is detected $\to \text{eof}$ (`zip.rs:155-157`);
3. Set $patch\_limit = \max(cd\_offset, eocd\_pos + 16)$; if $patch\_limit + ube\_size \ge \text{0xFFFFFFFF} \to \text{eof}$ (`zip.rs:162-167`);
4. Otherwise select `pre_cd_inject`;
5. If `find_eocd_offset` raises an error $\to \text{eof}$ (`zip.rs:169`).

Explicit strategies outside `supported_strategies` return `UnsupportedFormat` (`engine.rs:1248-1253`, `zip.rs:251-255`).

---

## 4. Injection Layout

The UBE stream resides **immediately preceding the Central Directory**, following the final local file entry; $offset\_delta = 0$ (`adapters/mod.rs:345-352`), meaning the first byte of UBE is `inject_offset`, with trailers occupying the final 24 bytes of UBE (`adapters/mod.rs:357-359`).

```text
[0, cd_offset)           Copied verbatim (stubs, local file headers, and payloads untouched)
[cd_offset, +ube_size)   UBE (Header 112 B ... Trailer 24 B)   inject_offset = cd_offset
cd_offset + ube_size     Central Directory (original bytes displaced backward intact)
...                      (ZIP64 records/locators if present)
eocd_pos + ube_size      EOCD: +12 cd_size unchanged; +16 cd_offset = original cd_offset + ube_size
                         +20 comment_len and comment copied verbatim
```

- Writing Sequence: Copy $[0, cd\_offset) \to$ write UBE $\to$ copy $[cd\_offset, eocd\_pos + 16) \to$ write updated 4-byte `cd_offset` $\to$ skip original 4-byte field $\to$ copy remaining EOCD bytes (`zip.rs:286-312`).
- `inject` returns $(inject\_offset, inject\_size, patch\_offset, orig\_patch\_val) = (cd\_offset, ube\_size, eocd\_pos + 16 + ube\_size, \text{original } cd\_offset)$ (`zip.rs:303-314`). $patch\_offset$ is in stego coordinates; $offset\_delta = 0$ satisfies $inject\_offset + offset\_delta == trailer.ube\_offset$ (`engine.rs:1407`, `:2851-2859`).
- File expansion equals $ube\_size$ bytes; no local headers or CD entries are created: UBE occupies the slack space between the last local file entry and the Central Directory. Standard ZIP tools locate CD via EOCD `cd_offset` and resolve local files via relative offsets; because these offsets precede `cd_offset`, standard readers access files without corruption.
- The engine backfills headers at `actual_ube_offset` and trailers at $ube\_offset + ube\_total\_size - 24$ (`engine.rs:1426-1441`).

---

## 5. Capacity and Lower Bounds

The 32-bit `cd_offset` in EOCD is patched; `cd_size` remains untouched. Constraints:

```text
patch_limit = max(cd_offset, eocd_pos + 16)
patch_limit + ube_size < 0xFFFFFFFF          // Both new cd_offset and patch offset must fit in u32
=> Capacity Bound = 0xFFFFFFFE - patch_limit
```

Checked in `zip.rs:162-167`, `:278-283`; reported values in `zip.rs:205-215`. Explicit `pre_cd_inject` encountering overflow returns `UnsupportedFormat("Central directory or EOCD patch offset overflow (>4GB) ...")` (`zip.rs:278-283`); `auto` switches to `eof`.

| Scenario | `pre_cd_inject` Reporting | Reference |
| --- | --- | --- |
| Standard Archive | `available = true`, $capacity\_bytes = \text{0xFFFFFFFE} - patch\_limit$ | `zip.rs:194-216` |
| Empty Archive ($cd\_offset == 0$) | `available = false`, notes fallback to `eof` | `zip.rs:189-193` |
| ZIP64 (Locator Present) | `available = false`, notes fallback to `eof` | `zip.rs:198-203` |
| Missing / Corrupted EOCD | `available = false`, notes fallback to `eof` | `zip.rs:218-222` |
| `eof` | `None` (unbounded / file grows) | `zip.rs:230-236` |

Static inspection (`reader == None`) reports `carrier-dependent (4 GiB - EOCD offset)` (`zip.rs:176-185`). `inspect` clamps available strategies to $\text{structure\_payload\_limit}(host\_len) = \text{clamp}(256 \times host\_len, 64\text{ MiB}, 1\text{ GiB})$ (`engine.rs:1938-1975`).

Lower bounds: `locate` requires $cd\_offset \ge 136$ (`zip.rs:323-325`); `confine_location` enforces $ube\_total\_size \ge 136$ and $ube\_offset + ube\_total\_size \le file\_len$ (`engine.rs:191-207`). Minimum encrypted envelopes are `min_ube_len(0) = 213` and `min_ube_len(1) = 214` (`rust/src/structure/envelope.rs:123-140`).

---

## 6. Locator Pipeline (`locate`)

`locate` evaluates two paths sequentially (`zip.rs:317-349`):

1. **Pre-CD Path**: If `find_eocd_offset` succeeds and $cd\_offset \ge 136$, read 24 bytes of trailer at $cd\_offset - 24$ and unpack using `expected_trailer_magic` (`zip.rs:323-330`); if $trailer.ube\_offset + trailer.ube\_total\_size == cd\_offset$, accept and return `(ube_offset, ube_total_size, "pre_cd_inject")` (`zip.rs:330-336`).
2. **EOF Fallback**: If `EnvelopeTrailer::read_from_tail` matches with $ube\_offset + ube\_total\_size == file\_size$, return `(ube_offset, ube_total_size, "eof")` (`zip.rs:341-346`).
3. If neither matches, return `Ok(None)` (`zip.rs:348`).

`locate` unpacks UBE origin from trailer `ube_offset`, using EOCD `cd_offset` purely as an identity check. `expected_header_magic` is ignored in this adapter (`adapters/mod.rs:218-225`). Stealth trailer magic takes precedence over profile magic (`engine.rs:145-166`).

---

## 7. `remove` and Cover Restoration

`strip` is overridden (`zip.rs:351-408`). Strategy `eof` delegates to `EofAdapter` (copying $orig\_host\_size$ bytes, `zip.rs:357-359`). Otherwise, streaming restoration executes:

1. Copy $[0, inject\_offset)$ (`zip.rs:362-363`);
2. Set $inject\_end = inject\_offset + inject\_size$; seek to `inject_end` and copy $patch\_offset - inject\_end$ bytes (`zip.rs:372-390`);
3. Write 4-byte Little-Endian `orig_patch_val` at output stream, reverting EOCD+16 to original `cd_offset` (`zip.rs:393`);
4. Skip the 4-byte patched field in stego file, copying remaining bytes to EOF (`zip.rs:396-405`).

`pre_cd_inject` is not relocatable; any coordinate discrepancy returns `CorruptedData` (`engine.rs:2310-2350`). File size and SHA-256 are validated against $orig\_host\_size$ and $orig\_host\_sha256$ in the header; discrepancies return `RestoreMismatch` (`engine.rs:2353-2409`). Bit-for-bit restoration recovers original comments and prefix stubs.

---

## 8. Boundary Conditions

| Condition | Behavior |
| --- | --- |
| EOCD signature inside comment | Pass 1 enforces EOF termination; Pass 2 validates `PK\x01\x02` at `cd_offset`; forged signatures inside comments are rejected (`zip.rs:43-67`) |
| Empty ZIP (22B EOCD only) | `detect` passes; `auto` routes to `eof`; explicit `pre_cd_inject` returns `UnsupportedFormat("Empty archive ...")` (`zip.rs:258-264`) |
| ZIP64 (Locator at $eocd\_pos - 20$) | `auto` / capacity routes to `eof`; explicit injection returns `UnsupportedFormat("ZIP64 archive ...")` (`zip.rs:265-271`) |
| ZIP64 with sentinel 32-bit fields | `find_eocd_offset` fails directly; `verify_structure` returns "Corrupted ZIP" (`zip.rs:410-432`) |
| Data Descriptor `PK\x07\x08` | Not parsed as entry; accepted by `detect` if in first 4 bytes (`zip.rs:131-136`) |
| Multi-Disk Split Archives | Disk numbers are unparsed; eligibility depends on whether `cd_offset` resolves valid CD signatures |
| `MZ`-Prefixed SFX Archives | Rejected during initial 4-byte `detect` check |
| EOCD $> 65,558\text{ B}$ from EOF | Unreachable via 65 KiB scan window; `find_eocd_offset` treats EOCD as missing |
| Signed JARs / Unparsable CDs | Rejected by separate security guards (`rejection.rs:346-352`) |

`suspicious_structures` flags pre-CD and EOF trailer signatures $\ge 136$ bytes (`zip.rs:434-492`).

---

## 9. Tier I Writer Details and Self-Verification

- **Streaming Transfers**: `copy_exact` transfers data using 64 KiB buffers; premature EOF returns `CorruptedData("Unexpected EOF while copying stream")` (`io.rs:11-30`, `zip.rs:291-294`).
- **Invariance**: Central Directory, remaining EOCD fields, comments, and pre-CD entries are copied byte-for-byte; only bytes $[eocd\_pos + 16, +20)$ are altered.
- **Post-Write Validation**: Re-executing `locate` MUST return $(actual\_ube\_offset, ube\_total\_size)$ exactly (`engine.rs:1454-1472`).
- **Regression Commands**:

```bash
cargo test --all-features --test test_regression
python scripts/baseline_hash.py --check
```
