# STRUCTURE-PE: Windows PE Adapter (`pe_overlay` / `pe_codebits` / `pe_slack`)

This document specifies the structural domain (UBE) adapter for `format_name = "PE"`. Common envelope layouts, 112B headers, 24B trailers, AAD, and strategy IDs are defined in [STRUCTURE-ENVELOPE.md](STRUCTURE-ENVELOPE.md) §2–§15; limits are summarized in [CAPACITY.md](CAPACITY.md) §4. All layouts and constants adhere strictly to executable code in `rust/src/structure`.

---

## 1. Scope, Navigation, and Stability

Applicable carriers: Windows executable images with DOS `MZ` headers and NT `PE\0\0` signatures (EXE, DLL, SYS, SCR, etc., without distinction by extension). Three distinct strategies share the identical adapter and envelope:

| Strategy | `strategy_id` | Paradigm | File Size |
| --- | --- | --- | --- |
| `pe_overlay` | 7 | Appends complete UBE at file EOF (past PE image boundary) | Expands by $ube\_total\_size$ |
| `pe_codebits` | 8 | Encodes UBE bit-by-bit into equivalent `.text` instruction forms; stores restoration diff in zero-padding | Unchanged |
| `pe_slack` | 9 | Overwrites complete UBE into section-alignment zero-padding | Unchanged |

Strategy registry source: `rust/src/structure/registry.rs:90-104`; adapter declarations: `rust/src/structure/adapters/pe.rs:148-169`.

| Tier | PE Structural Scope |
| --- | --- |
| **F** | `MZ` / `PE\0\0` admission criteria; PE32 / PE32+ optional header magic `0x10B` / `0x20B` and Security Directory offset; strategy names and IDs 7/8/9; overlay injection point and trailer locator rules; section slack derivation; `ChannelHeader` 14B layout, masking, and 176-slot prefix; diff bitmap format; codebits instruction selection and filtering rules |
| **D** | `StructureProfile` magic numbers, default keys, and stealth domains; feature flag `structure-pe` gating `pe_codebits` availability |
| **I** | Capacity / `strategy_note` phrasing; scan and transfer buffer sizing; `auto` precedence ordering; 4 GiB `slack_off` overflow message; warnings on existing overlays |

---

## 2. Format Detection (`detect`)

`detect` invokes `parse_pe_headers`, returning `true` on success and restoring stream position before returning (`rust/src/structure/adapters/pe.rs:138-146`):

1. Fails if file length $< \text{0x40}$, offset 0 is not `MZ`, $e\_lfanew < \text{0x40}$ or $e\_lfanew + 24 > host\_size$, or bytes at $e\_lfanew$ are not `PE\0\0` (`pe.rs:28-62`).
2. 20B COFF Header: parses `NumberOfSections` (+2..+4) and `SizeOfOptionalHeader` (+16..+18) (`pe.rs:64-68`).
3. Optional Header Magic: `0x10B` denotes `PE32`, `0x20B` denotes `PE32+`; other values record `Unknown` without immediate rejection (`pe.rs:73-87`).
4. Security Directory: offset +128 in PE32, +144 in PE32+; read when $size\_of\_optional\_header \ge offset + 8$; if both VA and size are non-zero, sets $has\_authenticode = true$ (`pe.rs:89-101`).
5. Section Table Origin: $e\_lfanew + 24 + size\_of\_optional\_header$; parses 40B section headers, reading `raw_size` (+16) and `raw_ptr` (+20); $pe\_image\_end = \max(e\_lfanew + 24 + opt\_size, raw\_ptr + raw\_size)$ (`pe.rs:104-120`).

Signed PEs pass `detect` but are rejected before writing (`pe.rs:391-395`, `rejection.rs:381-393`). Files where $host\_size < pe\_image\_end$ are rejected across all strategies (`pe.rs:397-402`).

---

## 3. Supported Strategies, Precedence, and `auto`

The three strategies are mutually exclusive: `pe_overlay` is continuous and append-based; `pe_slack` is continuous and overwrite-based, requiring UBE to fit within a **single** zero-padded gap; `pe_codebits` is scattered, having no continuous file offset ($inject\_offset = inject\_size = 0$).

Precedence in `choose_auto_strategy` for PE is **`pe_slack` $\to$ `pe_overlay`** (`pe.rs:176-210`); `pe_codebits` **is excluded from `auto`** and requires explicit selection via `-s pe_codebits`:

1. If section tables parse successfully and continuous zero-padding $\ge ube\_len$ exists, select `pe_slack`.
2. Otherwise select `pe_overlay`.

Why `pe_codebits` is excluded from `auto`: It scans `.text` linearly using `iced`, filtering `Code::INVALID` without constructing control flow graphs (CFGs) or recognizing inline jump/constant tables. If non-instruction data bytes are misidentified as mutable instructions, errors manifest only when that specific code path executes. It is therefore designated an **advanced / opt-in** strategy.

`auto` never selects `eof`; `eof` is supported via explicit specification only, sharing behavior with `pe_overlay` under `strategy_id = 1`.

---

## 4. `pe_overlay`

### 4.1 Geometry and Writing

`inject` copies $[0, host\_size)$ verbatim, appending UBE at the new physical EOF, returning $(inject\_offset = host\_size, inject\_size = ube\_size, 0, 0)$ (`pe.rs:416-422`):

```text
[0, host_size)                 Original carrier (including pre-existing overlays)
[host_size, host_size+ube)     UBE (header ‖ hint ‖ meta ‖ payload ‖ trailer)
```

- **No Section Alignment**: Appends directly past physical EOF without alignment padding; section headers, section data, and certificate tables are untouched.
- **Pre-existing Overlays Supported**: Appends past existing overlays; if $host\_size > pe\_image\_end + 136$, a warning is logged without aborting (`pe.rs:555-566`, `engine.rs:1368-1372`).
- $offset\_delta = 0$; trailers occupy the final 24 bytes of the file (`adapters/mod.rs:345-359`).

### 4.2 Capacity, Authenticode, and Locating

- Unbounded capacity, reporting `capacity_bytes: None`, `limit: "unlimited (file grows)"` (`pe.rs:346-351`), clamped by `structure_payload_limit(host_len)`.
- **Invalidates Authenticode**: Modifying file bytes alters the Authenticode hash; signed PEs are rejected prior to write (`pe.rs:391-395`).
- `locate` reads 24B trailer from file EOF, requiring $ube\_offset \ge pe\_image\_end$ and $ube\_offset + ube\_total\_size == file\_size$ to return `"pe_overlay"` (`pe.rs:441-459`). Restoration truncates at `header.inject_offset` (`pe.rs:530-536`).

---

## 5. `pe_codebits`

Available strictly under the `structure-pe` compile feature (`pe.rs:148-169`, `rust/src/structure/adapters/pe_codebits.rs:1`).

### 5.1 Eligible Instructions and Slot Selection

Linear decoding traverses `.text` within $[text\_offset, text\_offset + text\_scan\_len)$, where $text\_scan\_len = \min(VirtualSize, SizeOfRawData)$ (`pe_layout.rs:235-249`, `:386-402`), filtering instructions (`pe_codebits.rs:204-306`):

| Filter | Rule | Reference |
| --- | --- | --- |
| F0 | Instructions decoded as `Code::INVALID` (data, jump tables) are skipped | `:223-226` |
| F1 | MUST form a semantic pair or commutative form | `:228-237` |
| F2 | Both operands MUST be bare registers ($\text{mod} = 11$); memory / SIB / immediates rejected | `:239-243` |
| F3 | `TEST` instructions where both registers are identical carry no information | `:245-249` |
| F4 | Re-encoded form MUST match original bytes bit-for-bit, rejecting non-canonical encodings | `:270-275` |
| F5 | Inverted form MUST encode to the exact same byte length as original | `:277-293` |

Semantic pairs cover 8/16/32/64-bit register-register forms of `ADD / ADC / AND / OR / XOR / SUB / SBB / MOV / CMP` (`pe_codebits.rs:77-163`): "store" forms (`op rm, r`) encode bit `0`, while "load" forms (`op r, rm`) encode bit `1`. `TEST` instructions are commutative (`pe_codebits.rs:167-172`), encoding bit value as **$ordinal(r_0) < ordinal(r_1)$**, where $r_0$ is `op0` (r/m) and $r_1$ is `op1` (reg) (`pe_codebits.rs:245-253`).

Slots are indexed in scan order; channel bitstreams unpack **MSB-first**, mapping bit 0 to the first available slot (`pe_codebits.rs:320-328`, `:623-657`). Length-preserving replacements ensure that `profile(text, bitness)` returns identical candidate positions before and after embedding (`pe_codebits.rs:198-206`).

### 5.2 `ChannelHeader` (14 Bytes)

Occupies the first 112 slots, followed by 8 UBE bytes (64 slots) providing mask IKM; readers MUST scan the first **176** slots (`pe_codebits.rs:43-51`, `:460-477`).

| Offset | Length | Field | Type | Masked | Description |
| --- | --- | --- | --- | --- | --- |
| 0 | 4 | `magic` | `[u8; 4]` | No | Standard = `STANDARD_TRAILER_MAGIC = 78 e6 66 d2`; stealth = derived trailer magic |
| 4 | 1 | `version` | u8 | Yes | Fixed `1` (`CHANNEL_VERSION`) |
| 5 | 1 | `flags` | u8 | Yes | Reserved, written as 0; unvalidated by readers |
| 6 | 4 | `ube_len` | u32 LE | Yes | Total byte length of embedded UBE (including 24B trailer) |
| 10 | 4 | `slack_off` | u32 LE | Yes | Absolute file offset of diff bitmap in PE slack |

- Layout: `pe_codebits.rs:358-400`. Magic matches UBE trailer magic (`:602-604`); mask IKM matches UBE header magic from channel bit positions 112..176 (`:466-476`, `:608-612`).
- Masking: $\text{HKDF-SHA256}(salt=None, ikm=envelope\_header\_magic(8B))$ with info `strhide-pe-channel-mask-v2`, taking 10 bytes; applied as $bytes[4..14] \oplus mask[0..10]$ (`rust/src/core/crypto.rs:342-348`, `pe_codebits.rs:393-400`).
- Validation: Requires $prof.len() \ge 176$; unmasked magic must match; $version == 1$; $136 \le ube\_len \le 64\text{ MiB}$. `extract_ube` enforces slot count $\ge (14 + ube\_len) \times 8$ (`pe_codebits.rs:460-497`, `:541-554`, `:559-571`).

### 5.3 Diff Format via `slack_off`

The diff is a **dense, fixed-length bitmap** with no headers, lengths, or CRCs; length is derived implicitly from `ChannelHeader.ube_len`:

```text
diff_len = CHANNEL_HEADER_LEN + ube_len        (in bytes, pe_codebits.rs:446-448)
bit i    = whether channel slot i was flipped   (MSB-first within byte)
```

Bit $i = 1$ indicates slot $i$ was mutated to its equivalent encoding; bit $i = 0$ indicates unmodified state. The first $14 \times 8$ bits cover the `ChannelHeader` itself, enabling full restoration of header instruction slots (`pe_codebits.rs:624-657`, `:665-723`).

Constraints on `slack_off`:
- MUST fit within `u32`; values $> 4\text{ GiB}$ are rejected (`pe.rs:716-722`).
- MUST fall within a continuous zero-padded gap where $slack\_off + diff\_len$ does not exceed padding bounds (`pe.rs:705-714`, `:779-793`).

### 5.4 100% Restoration, Capacity, and Risk Boundaries

Restoration (`pe.rs:770-818`): Parse layout $\to$ decode `ChannelHeader` and compute $diff\_len \to$ verify $[slack\_off, slack\_off + diff\_len)$ resides inside zero-padding $\to$ read diff bitmap and invert flipped slots via `apply_diff` $\to$ overwrite diff area with zeros. Restored file size and SHA-256 are validated against $orig\_host\_size$ and $orig\_host\_sha256$ in the UBE header, returning `RestoreMismatch` on error (`engine.rs:2298-2361`).

Capacity (`pe.rs:248-283`):

```text
cap_bits  = floor(available_slots / 8) - 14
cap_slack = longest_zero_run - 14
capacity  = min(cap_bits, cap_slack)
available = capacity >= min_ube_len(1)        (214 B minimum encrypted envelope)
```

Non-x86/x64 COFF machine types (anything other than `0x14C` or `0x8664`) return `UnsupportedMachine` (`pe_layout.rs:229-233`). Re-embedding into an existing `pe_codebits` channel is rejected (`pe.rs:692-703`).

---

## 6. `pe_slack`

### 6.1 Slack Candidate Discovery

Candidates are identified from section headers in file order (`pe_layout.rs:161-200`):

1. Gap between section table end and first section raw data (`first_raw > sec_table_end`, `pe_layout.rs:173-183`);
2. Tail of each section: from $raw\_ptr + \min(VirtualSize, SizeOfRawData)$ to $\min(raw\_ptr + SizeOfRawData, host\_size)$ (`pe_layout.rs:184-193`);
3. Subtracting section data $[raw\_ptr, raw\_ptr + \min(VirtualSize, SizeOfRawData))$ (`pe_layout.rs:162-170`, `:203-223`).

EOF overlay space is explicitly excluded (`pe_layout.rs:157-160`). Sections with $VirtualSize == 0$ yield no padding candidates.

### 6.2 Writing, Capacity, and Restoration

- Selects the smallest continuous zero-run capable of accommodating $ube\_len$ (`pe_layout.rs:254-279`); verifies that the selected run contains all zeros (`pe_slack.rs:82-84`).
- Overwrites in-place: copies $[0, off)$, writes UBE, copies $[off + ube\_size, host\_size)$, returning $(off, ube\_size, 0, 0)$ without altering file size (`pe_slack.rs:52-92`).
- Capacity equals longest zero-run; $available = run \ge min\_ube\_len(1)$ (`pe.rs:308-330`).
- Restoration verifies coordinates within padding ranges, copies prefix, overwrites span with zeros, and copies remainder (`pe_slack.rs:218-254`). Applicable to any architecture (ARM64, .NET) with PE32/PE32+ headers.

---

## 7. Locator Pipeline (`locate`) and Hint Handling

Evaluation precedence: **`codebits` $\to$ `overlay` $\to$ `slack` $\to$ `eof`** (`pe.rs:425-482`):

| Precedence | Path | Criteria | Result |
| --- | --- | --- | --- |
| 1 | `ChannelHeader` | Parse `.text` $\to$ `read_channel_header`; magic mismatch = no channel | `(0, ube_len, "pe_codebits")` (`pe.rs:746-765`) |
| 2 | EOF Trailer | `read_from_tail`; $ube\_offset \ge pe\_image\_end$ and $ube\_offset + ube\_total\_size == file\_size$ | `"pe_overlay"` (`pe.rs:441-459`) |
| 3 | Padding Scan | Search slack ranges for trailer magic; unpack and validate CRC; require single range containment | `"pe_slack"` (`pe_slack.rs:101-214`) |
| 4 | EOF Trailer | $ube\_offset + ube\_total\_size == file\_size$ | `"eof"` (`pe.rs:471-479`) |

`expected_header_magic` is ignored in PE (`adapters/mod.rs:218-225`); `expected_trailer_magic` is evaluated. `pe_overlay` and `pe_slack` are not relocatable (`engine.rs:2867-2912`).

---

## 8. `remove` Restoration Sequence

1. Dispatched by `header.strategy_id`: `pe_codebits` first, then `pe_slack`, followed by EOF truncation for `pe_overlay` / `eof` (`pe.rs:513-537`).
2. `pe_codebits` applies `apply_diff` to `.text` and zero-fills $[slack\_off, slack\_off + diff\_len)$ (`pe.rs:769-818`).
3. `pe_slack` zero-fills the envelope padding range (`pe_slack.rs:218-254`).
4. `pe_overlay` / `eof` truncates at `header.inject_offset` (`pe.rs:530-536`).
5. Engine recalculates length and SHA-256 against header values, returning `RestoreMismatch` on discrepancy (`engine.rs:2298-2361`).

---

## 9. Boundary Conditions

| Condition | Behavior |
| --- | --- |
| Signed PE (Authenticode) | Rejected across all strategies; capacity reports `available = false` (`pe.rs:362-372`, `:391-395`) |
| 32-bit vs 64-bit | Security directory at +128 in PE32, +144 in PE32+; codebits determines bitness from COFF `Machine` (`0x14C` = 32-bit, `0x8664` = 64-bit) (`pe_layout.rs:229-233`) |
| DLL / EXE / SYS / SCR | Handled identically without extension filtering |
| .NET / CLR | No CLR-specific parsing; `pe_slack`/`pe_overlay` supported; `pe_codebits` unsafe on IL |
| UPX / Packed Code | Compressed `.text` may mislead linear decoders; prefer `pe_slack` or `pe_overlay` |
| Section Table Anomalies | Section tables beyond 64 KiB return `NotPe` (`pe_layout.rs:295-301`); out-of-bounds sections rejected |
| Pre-existing Overlay | Supported; `pe_overlay` appends past existing overlay; logs non-fatal warning if $> pe\_image\_end + 136$ (`pe.rs:555-566`) |
| Empty Payload | Explicitly rejected by `pe_codebits` and `pe_slack` (`pe.rs:668-674`, `pe_slack.rs:59-63`) |
| $slack\_off > 4\text{ GiB}$ | Rejected by `pe_codebits` (`pe.rs:716-722`) |
| Existing `codebits` Channel | Secondary injection rejected (`pe.rs:692-703`) |

---

## 10. Tier I Writer Details and Self-Verification

- `choose_auto_strategy` determines the initial strategy attempt without retry (`engine.rs:1242-1255`).
- Capacity reporting uses `min_ube_len(1) = 214\text{ B}` as the eligibility threshold (`pe.rs:266-268`, `:312-315`).
- Post-write validation verifies that `locate` recovers written coordinates exactly; `pe_codebits` coordinates evaluate as `(0, ube_len)` (`engine.rs:1454-1475`).
- `verify_structure` validates PE headers and section tables without checking signatures or machine types (`pe.rs:539-553`).

**PE Verification Commands**:

```bash
cargo test --all-features --test test_pe codebits::
cargo test --all-features --test test_pe slack::
cargo test --all-features pe_codebits::tests::
cargo test --all-features test_pe_authenticode_rejection
```
