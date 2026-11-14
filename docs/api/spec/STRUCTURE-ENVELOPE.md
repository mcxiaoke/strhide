# STRUCTURE-ENVELOPE: Structural Domain Common Envelope UBE v2

Applicable to `strhide` 0.9.3, adhering to executable code in `rust/src/structure`. This document defines the **UBE** (Universal Byte Envelope) byte stream shared by all structural domain carriers; container integration details are specified in [STRUCTURE-PNG.md](./STRUCTURE-PNG.md), [STRUCTURE-JPEG.md](./STRUCTURE-JPEG.md), [STRUCTURE-RIFF.md](./STRUCTURE-RIFF.md), [STRUCTURE-ISOBMFF.md](./STRUCTURE-ISOBMFF.md), [STRUCTURE-ZIP.md](./STRUCTURE-ZIP.md), [STRUCTURE-PDF.md](./STRUCTURE-PDF.md), [STRUCTURE-PE.md](./STRUCTURE-PE.md), and [STRUCTURE-MKV.md](./STRUCTURE-MKV.md). Key derivation details are in [CRYPTO.md](./CRYPTO.md). Citations are given as `file:line` relative to the repository root.

---

## 1. Scope and Stability

- Scope: 112B header, password hint, compact metadata, chunked payload stream, 24B trailer, AAD, flags, stealth mode, `offset_delta`, locating and validation, and PE `ChannelHeader` 14B.
- Exclusions: Carrier container headers, injection/extraction algorithms, strategy selection, and capacity reporting (governed by format-specific `STRUCTURE-*.md` and [CAPACITY.md](./CAPACITY.md)).
- **Tier F (Frozen)**: Field offsets and lengths, AAD concatenation, chunked 4B length prefixes, trailer layout and CRC, field mask ranges, and `ChannelHeader` 14B. Alterations invalidate existing carriers and break byte-level baselines.
- **Tier D (Dialect)**: Header/trailer magic numbers, default keys, and stealth domains, customizable via `StructureProfile` (`rust/src/structure/params.rs:31-54`); modifying values produces mutually unreadable dialects.
- **Tier I (Implementation Freedom)**: `chunk_size`, compression level, `CompressionStrategy`, and writer strategy selection heuristics (`rust/src/structure/engine.rs:1100-1145`). Readers MUST NOT rely on specific values.
- **Pre-1.0 Notice**: Tier F indicates that internal repository changes immediately break existing carriers and baselines; third parties should pin behavior to specific release tags.
- Endianness: All multi-byte integers in the structural domain are **Little-Endian** (`rust/src/structure/envelope.rs:144, 400-410`).

---

## 2. Overall Layout and Dimensions

```text
Relative to UBE Origin:
0                             Envelope Header (112 B, §3)
112                           Password Hint (hint_len B, optional, §6)
112 + hint_len                Metadata Block (meta_len B, AEAD, §7)
112 + hint_len + meta_len     Payload Chunk Stream (Chunked AEAD, §8)
ube_total_size - 24           Envelope Trailer (24 B, §9)
```

```text
ube_total_size  = 112 + hint_len + meta_len + payload_written + 24
payload_written = compressed_plain_len + chunk_count * 20
chunk_count     = max(1, ceil(compressed_plain_len / chunk_size))
```

Writers calculate `exact_ube_size` via the formula above to guide strategy selection prior to injection, and cross-check against actual written bytes afterward; any discrepancy aborts (`rust/src/structure/engine.rs:1231-1240, 1339-1351`). Capacity reporting employs `min_ube_len(payload_len)`: `min_ube_len(0) = 213`, `min_ube_len(1) = 214` (`rust/src/structure/envelope.rs:116-132`, tests `:1010-1023`).

---

## 3. Envelope Header (112 Bytes)

Fixed 112 bytes, serialized in Little-Endian. The first 80 bytes form the fixed AAD prefix; `meta_len` and `hint_len` reside at the end and are appended to AAD (§5); the four post-injection coordinates (excluding `offset_delta`) are excluded from AAD (`rust/src/structure/envelope.rs:144-159`).

| Offset | Length | Field | Type | AAD | Description |
| --- | --- | --- | --- | --- | --- |
| 0 | 8 | `magic_header` | `[u8; 8]` | Prefix | Header magic (§3.1) |
| 8 | 1 | `version` | u8 | Prefix | MUST be `0x02` |
| 9 | 1 | `flags` | u8 | Prefix | §4 |
| 10 | 1 | `strategy_id` | u8 | Prefix | §14 |
| 11 | 1 | `offset_delta` | u8 | Prefix | Injection offset delta, $\le 128$ (§12) |
| 12 | 16 | `salt` | `[u8; 16]` | Prefix | KDF random salt; unmasked |
| 28 | 12 | `base_nonce` | `[u8; 12]` | Prefix | Random base nonce; unmasked |
| 40 | 8 | `orig_host_size` | u64 LE | Prefix | Original carrier byte count |
| 48 | 32 | `orig_host_sha256` | `[u8; 32]` | Prefix | Original carrier SHA-256 digest |
| 80 | 8 | `inject_offset` | u64 LE | No | Injection offset in carrier coordinates |
| 88 | 8 | `inject_size` | u64 LE | No | Injected span byte count |
| 96 | 4 | `patch_offset` | u32 LE | No | Patched field offset; 0 = no patch |
| 100 | 4 | `orig_patch_val` | u32 LE | No | Original value at patched field |
| 104 | 4 | `meta_len` | u32 LE | Appended | Metadata ciphertext length (with tag) |
| 108 | 4 | `hint_len` | u32 LE | Appended | Password hint byte length |

### 3.1 Magic Numbers

- Standard: `STANDARD_HEADER_MAGIC = b7 54 2c 82 7e 31 1d 6e` (`rust/src/core/params.rs:27`).
- Custom Dialects: `Profile.magic.header` (`rust/src/structure/params.rs:100-103`).
- Stealth Mode: Derived dynamically from password, overriding the above (§11; `rust/src/structure/engine.rs:1193-1203`).

### 3.2 Full Validation Rules (`validate_against(ube_total_size, host_len)`)

Readers MUST execute these checks prior to allocating buffers based on any header field (`rust/src/structure/envelope.rs:265-348`):

1. `version == CURRENT_VERSION == 0x02` (`:266-271`); else `CorruptedData`.
2. `hint_len <= MAX_HINT_LEN = 1024` (`:272-277`, `:90`).
3. `meta_len <= MAX_META_LEN = 262144` (256 KiB) (`:278-283`, `:100`).
4. `hint_len + meta_len + (112 + 24) <= ube_total_size` (`:284-291`).
5. `strategy_id` MUST be registered in `STRATEGY_REGISTRY` (`:294-302`); 0 and unregistered values are rejected.
6. `inject_size == 0`, or $inject\_size \ge 136$ with $inject\_offset + inject\_size$ non-overflowing (`:308-316`).
7. `offset_delta <= MAX_OFFSET_DELTA = 128` (`:321-326`, `:81`).
8. `patch_offset == 0` or $patch\_offset \ge 4$ (a 4-byte field cannot fit in $1 \dots 3$) (`:329-334`).
9. When `patch_offset != 0`, $patch\_offset + 4 \le host\_len$ (physical carrier size, `:338-346`).

The locator phase enforces physical containment: $ube\_total\_size \ge 136$ and $ube\_offset + ube\_total\_size \le \text{file\_size}$; failures are treated as "absence of envelope" rather than errors (`rust/src/structure/engine.rs:191-207`). `host_len` is retrieved by the reader prior to opening envelopes (`engine.rs:1803`).

---

## 4. Flags Bit Definitions

| Bit | Constant | Value | Semantics |
| --- | --- | --- | --- |
| 0 | `FLAG_ENCRYPTED` | 0x01 | Encrypted with **user password**; does not indicate unencrypted vs encrypted |
| 1 | `FLAG_COMPRESSED` | 0x02 | Payload compressed via raw Deflate prior to sealing |
| 2 | `FLAG_IS_FILE` | 0x04 | Payload is a file (otherwise text / raw inline bytes) |
| 3 | `FLAG_STEALTH` | 0x08 | Stealth mode: password-derived magic + header field mask |
| 4 | `FLAG_HAS_HINT` | 0x10 | Writer wrote a hint; reader relies strictly on `hint_len` |
| 5 | `FLAG_COMPACT_META` | 0x20 | Metadata uses compact binary layout (§7) |
| 6–7 | — | — | Reserved, MUST be 0 |

- Constants and logic: `rust/src/structure/envelope.rs:61-72`, `rust/src/structure/engine.rs:1148-1166`.
- **When `FLAG_ENCRYPTED = 0`, payload and metadata are sealed via AEAD using `Profile` default key**; this bit solely indicates "user password required" (`engine.rs:1148-1157`, `envelope.rs:210-218`).
- Writers **always** set `FLAG_COMPACT_META` for encodable metadata (`engine.rs:1217-1220`); readers encounter bit 0 report "unsupported metadata layout" and no longer parse legacy JSON (`engine.rs:355-366`).
- `validate_against` does NOT check reserved bits; only the raw header gate checks `flags & !0x3F == 0` (`envelope.rs:675-689`). Writers MUST NOT set reserved bits.

---

## 5. AAD Construction

Metadata blocks and payload chunks share the identical variable-length AAD (`EnvelopeHeader::auth_aad`):

```text
header[0..80]
  = magic_header(8) | version(1) | flags(1) | strategy_id(1) | offset_delta(1)
  | salt(16) | base_nonce(12) | orig_host_size(8) | orig_host_sha256(32)
AAD = header[0..80] | u32le(meta_len) | u32le(hint_len) | hint(hint_len)
  Total Length = 88 + hint_len
Chunk AAD = AAD | u64le(chunk_index) | u8(is_last)
  Total Length = 97 + hint_len
```

Reference: `rust/src/structure/envelope.rs:354-366, 390-397`; chunk additions: `rust/src/core/crypto.rs:508-511, 602-605`. Length fields MUST be authenticated before trusting decrypted data; hints are plaintext but signed in AAD so tampering breaks all seals. Sequential read order: header $\to$ hint $\to$ metadata (`engine.rs:1808-1872`).

---

## 6. Password Hint

- `hint_len` bytes follow the header directly as plaintext UTF-8; readers read by `hint_len` without requiring `FLAG_HAS_HINT` (`rust/src/structure/engine.rs:1836-1844`).
- Writers: NFC normalization + `trim()`, rejecting strings $> 1024$ bytes; empty hints are omitted without setting flags (`engine.rs:984-995, 1164-1166`).
- **Mutually Exclusive with Stealth**: Supplying both `password_hint` and `stealth` aborts (`engine.rs:969-973`); stealth never includes hints to prevent identification.
- Readers decode hints via `from_utf8_lossy`, never rejecting envelopes for non-UTF-8 hint bytes (`engine.rs:1840-1844`).

---

## 7. Metadata Block

Always sealed via AEAD (even when passwordless). When `FLAG_COMPACT_META` is set, plaintext adheres to the compact layout (`engine.rs:1217-1220`).

### 7.1 Compact Plaintext Layout

| Order | Field | Encoding | Constraints |
| --- | --- | --- | --- |
| 1 | `version` | u8 = `0x01` | `COMPACT_META_VERSION`; other values rejected |
| 2 | `name_len` | u16 LE | $\le 65535$ |
| 3 | `filename` | UTF-8 bytes | Empty string for text/inline payloads |
| 4 | `raw_size` | varint | Uncompressed payload byte length |
| 5 | `raw_sha256` | 32 raw bytes | SHA-256 of uncompressed payload |
| 6 | `created_at` | varint | Creation time (Unix seconds) |

Reference: `rust/src/structure/engine.rs:282-337`; version constant `:211`; filename bound `:216`.

### 7.2 Unsigned LEB128 Varint

Each byte stores 7 bits of payload; bit 7 = 1 indicates continuation; least significant groups come first; capped at 10 bytes. The 10th byte allows bit 0 only (bits 1..7 MUST be 0), otherwise returning overflow / length errors (`engine.rs:218-258`).

### 7.3 AEAD Parameters

- Key: `meta_key`; nonce: `make_meta_nonce(base_nonce)` = first 8 bytes identical, lower 32 bits $u32le(base\_nonce[8..12]) \oplus \text{0xFFFF\_FFFF}$ (`rust/src/core/crypto.rs:366-373`).
- AAD: Variable-length AAD from §5; wire length: $meta\_len = len(plaintext) + 16$ (`crypto.rs:382-398`, `engine.rs:1232`).
- Decryption failures map uniformly to "wrong password or corrupted metadata", leaking no distinction (`engine.rs:1874-1876`).

### 7.4 Minimum Plaintext

Empty filename, 1-byte payload: $1 + 2 + 0 + 1 + 32 + 5 = 41$ bytes (`created_at` timestamp takes 5 bytes in varint). Adding 16B tag yields $meta\_len = 57$.

---

## 8. Payload Chunk Stream

```text
┌ chunk_len (u32 LE, 4B) ┬ chunk ciphertext (chunk_len B, including 16B tag) ┐
```

- `chunk_len` specifies ciphertext byte length (plaintext + 16B tag), excluding its own 4B length prefix (`rust/src/core/crypto.rs:523-526, 574`).
- Chunk size is not negotiated or stored; readers self-delimit via length prefixes (`crypto.rs:424-428`).
- $chunk\_count = \max(1, \lceil plain\_len / chunk\_size \rceil)$; per-chunk framing overhead is 20B (4 + 16) (`crypto.rs:71-88`, `:59-64`).
- Empty payloads emit a single final chunk with `is_last = 1` (0B plaintext, 16B ciphertext, $chunk\_len = 16$), distinguishing empty payloads from truncated streams (`crypto.rs:467-489`).
- `chunk_index` is u64 starting at 0; `is_last` is 1 only on the final chunk (`crypto.rs:510-511`).
- Total payload partition: $total\_payload\_bytes = ube\_total\_size - (112 + 24 + hint\_len + meta\_len)$ (`engine.rs:1878-1882`).
- Reader single-chunk limit: $\min(\text{remaining}, \text{MAX\_CHUNK\_SIZE} + 16)$, where $MAX\_CHUNK\_SIZE = 64 \text{ MiB}$ (`crypto.rs:581-588, 101`). Chunk AEAD verification failures, bounds violations, or premature EOF return `CorruptedData`.

---

## 9. Envelope Trailer (24 Bytes)

| Offset | Length | Field | Type | Description |
| --- | --- | --- | --- | --- |
| 0 | 8 | `ube_offset` | u64 LE | Physical starting offset of UBE at write time |
| 8 | 8 | `ube_total_size` | u64 LE | Total size of UBE stream |
| 16 | 4 | `trailer_crc32` | u32 LE | CRC32-IEEE over bytes 0..16 |
| 20 | 4 | `trailer_magic` | `[u8; 4]` | Trailer magic signature |

- Standard magic: `STANDARD_TRAILER_MAGIC = 78 e6 66 d2` (`rust/src/core/params.rs:30`); custom profiles use `Profile.magic.trailer`; stealth uses password-derived magic (§11).
- `trailer_crc32 = CRC32_IEEE(ube_offset ‖ ube_total_size)` (`crypto.rs:724-736`), XORed with password-derived mask under stealth mode (`:740-753`).
- **Reading from Carrier EOF** (`envelope.rs:831-859`): File $< 24\text{B} \to \text{None}$; magic mismatch $\to \text{None}$ (standard "no envelope"); magic matches but CRC/parsing fails $\to$ **returns `CorruptedData`** (MUST NOT silently report no data).
- `unpack(data, expected_magic)`: `None` accepts standard magic and unmasked CRC only; `Some(m)` matches magic $m$, trying raw CRC first, followed by masked CRC (`envelope.rs:771-825`).
- `locate_start(file_size)`: If $ube\_offset + ube\_total\_size == file\_size$, return $ube\_offset$; otherwise require $ube\_total\_size \ge 136$ and return $file\_size - ube\_total\_size$ (allowing relocation after carrier rewrites, `envelope.rs:870-879`).
- Continuous strategies position trailers at $ube\_offset + ube\_total\_size - 24$ (`adapters/mod.rs:356-358`); scattered strategies record $ube\_offset = 0$ in the trailer (§13).

---

## 10. Keys, AEAD, and Compression

- Valid Credentials: Non-empty user password prioritized, falling back to `Profile.secret()` (official default `BUILTIN_DEFAULT_KEY`, `rust/src/core/crypto.rs:171-172`; selection logic `engine.rs:1152-1153`). Empty string passwords are treated as not provided (`engine.rs:964, 1752`).
- Derivation: One PBKDF2 + three HKDFs (`crypto.rs:256-273`): $IKM = \text{PBKDF2-HMAC-SHA256}(NFC(password), salt, 100000)$; expanded via HKDF-SHA256 ($salt = salt$) with labels `strhide-payload`, `strhide-metadata`, `strhide-header-mask-v1`. Full specification in [CRYPTO.md](./CRYPTO.md).
- Cipher: AES-256-GCM exclusively, 16B tag (`crypto.rs:34-37, 59`). Metadata nonce XORs with `0xFFFF_FFFF`; chunk nonces XOR lower 32 bits with $chunk\_index$ (`crypto.rs:354-373`).
- Compression: Raw Deflate (no zlib headers/trailers), levels $0 \dots 9$ (writer choice, `crypto.rs:642-665`). Readers check `FLAG_COMPRESSED`, bounded by AAD-protected `raw_size` (`engine.rs:1979-1988`, `crypto.rs:729-756`). Requiring $\ge 2\%$ compression gain and 256 KiB sampling on files $> 1 \text{ MiB}$ are Tier I writer heuristics (`engine.rs:1100-1145`).

---

## 11. Stealth Mode

- Requires a non-empty user password; operating without a password is rejected (`engine.rs:975-982`). Mutually exclusive with hints (§6).
- Magic Derivation (`crypto.rs:285-300`): $IKM = \text{PBKDF2-HMAC-SHA256}(NFC(password), domain, 100000)$; expanded via HKDF-SHA256 ($salt = domain$) with info `strhide-stealth-header` $\to$ 8B header magic, and `strhide-stealth-trailer` $\to$ 4B trailer magic. Default domain is `b"strhide-stealth-v1"` (`rust/src/core/params.rs:37`).
- Field Mask (`crypto.rs:305-312`, `envelope.rs:422-433`): 76B mask derived via $\text{PBKDF2}(password, salt) \to \text{HKDF info } \text{"strhide-header-mask-v1"}$; applied as $header[8..12] \oplus mask[0..4]$ and $header[40..112] \oplus mask[4..76]$. $salt$ and $base\_nonce$ remain unmasked.
- Trailer CRC Mask (`crypto.rs:318-329`): $mask = \text{CRC32\_IEEE}(trailer\_magic \mathbin{\Vert} \text{b"STEA"})$; writer sets $crc \oplus mask$.
- Non-stealth passwordless envelopes are also masked using `Profile.secret()`; **`FLAG_ENCRYPTED` envelopes are unmasked** to allow passwordless readers to recognize that a password is required (`envelope.rs:449-466`, `engine.rs:1184-1188`).
- Reader Recognition Pipeline (`envelope.rs:559-662`):
  1. Password provided and matches password-derived 8B header magic $\to$ unmask with password; requires $version = 0x02$ and `FLAG_STEALTH` set (`:580-607`).
  2. Unmasked `FLAG_ENCRYPTED` envelope: $version = 0x02$, `FLAG_ENCRYPTED` set, passes bare header validation (`:615-620`).
  3. `Profile.secret()` unmasking: requires $FLAG\_ENCRYPTED == 0$, $strategy\_id \in [1, \text{MAX\_KNOWN\_STRATEGY\_ID}]$, $offset\_delta \le 128$; **this tier does not check version** (deferred to `validate_against`) (`:622-648`).
  4. Bare header admission: $version = 0x02$, $flags \& !0x3F == 0$, $strategy\_id \in [1, 13]$, $offset\_delta \le 128$, $meta\_len \le 256 \text{ KiB}$, $hint\_len \le 1024$ (`:675-689`).  
  Complete failure returns `CorruptedData`; `inspect` treats this as absence of data to preserve dialect privacy (`engine.rs:2630-2656`).

---

## 12. `offset_delta` and Post-Injection Coordinates

- Semantics: The first byte of the UBE envelope begins at $inject\_offset + offset\_delta$. Pre-envelope container headers introduce non-zero deltas (PNG: 8B; JPEG APP15: 4B; ISO-BMFF: 8B or 24/32B; EBML Void: $\le 9\text{B}$; PDF incremental object headers: $46 + \text{digits}(N) + \text{digits}(L)$, reaching 66B with two 10-digit IDs); capped at 128 (`envelope.rs:74-88`, `engine.rs:1267-1278`).
- Upper bound affects reader admission only: setting the ceiling to 128 accommodates large PDF object headers while remaining frozen for 1.0.
- Calculation Timing: Computed by adapters **prior** to header serialization, allowing placement inside authenticated AAD (offset 11 < 80); the four coordinate fields are written back post-injection (`engine.rs:1397-1412`).
- Physical Coordinate Constraints (Continuous strategies, `engine.rs:2828-2902`):
  1. $inject\_offset + offset\_delta == trailer.ube\_offset$; strategies `chunk`, `eof`, and `ebml_void` permit global relocation (content domain re-encoding alters prefix lengths; MKV `locate` tracks Void from EOF to tolerate Segment resizing), adjusting $inject\_offset$ accordingly (`engine.rs:2860-2874, 2268-2296`; `relocatable_strategy`); other strategies fail if desynchronized.
  2. $ube\_total\_size \le inject\_size$.
  3. $inject\_offset + inject\_size \le \text{file\_size}$; during relocation, evaluated as $ube\_offset + (inject\_size - offset\_delta) \le \text{file\_size}$ (`:2881-2900`).
- Shape constraints: $inject\_size == 0$ or $\ge 136$; $patch\_offset \in \{0\} \cup [4, \infty)$ with $patch\_offset + 4 \le host\_len$ (§3.2).
- Scattered Strategy Exception: Under `pe_codebits`, $inject\_offset$ and $inject\_size$ are 0 by definition; coordinate verification is bypassed only when caller strategy and header `strategy_id` both indicate `pe_codebits` (`engine.rs:2835-2850`).
- Restoration Verification: `remove` recalculates file size and SHA-256 of the restored carrier, validating against $orig\_host\_size$ and $orig\_host\_sha256$ in AAD; mismatches return `RestoreMismatch` (`engine.rs:2299-2361`).

---

## 13. Scattered Strategy Channel Header: PE `ChannelHeader` (14 Bytes)

`pe_codebits` encodes the UBE bit-by-bit into equivalent `.text` instruction forms without continuous file offsets, placing a 14B channel header across the first 112 available instruction slots (`rust/src/structure/adapters/pe_codebits.rs:43-51`).

| Offset | Length | Field | Type | Masked | Description |
| --- | --- | --- | --- | --- | --- |
| 0 | 4 | `magic` | `[u8; 4]` | No | Standard = `78 e6 66 d2` (= UBE trailer magic); stealth = derived trailer magic |
| 4 | 1 | `version` | u8 | Yes | Fixed `0x01` |
| 5 | 1 | `flags` | u8 | Yes | Reserved, currently 0 |
| 6 | 4 | `ube_len` | u32 LE | Yes | Total byte length of embedded UBE |
| 10 | 4 | `slack_off` | u32 LE | Yes | Absolute file offset of PE slack storing diff bitmap |

- Layout: `pe_codebits.rs:358-400`; constants `CHANNEL_VERSION = 1`, `CHANNEL_HEADER_LEN = 14` (`:41-44`).
- Masking: $mask = \text{HKDF-SHA256}(salt=None, ikm=envelope\_header\_magic\_8B)$ with info `strhide-pe-channel-mask-v2`, taking 10 bytes; applied as $bytes[4..14] \oplus mask[0..10]$ (`rust/src/core/crypto.rs:342-348`, `pe_codebits.rs:393-400`).
- IKM Source: The 8 UBE bytes directly following the channel header (channel bit positions 112..176, corresponding to UBE `header[0..8]`). Readers scan the first 176 candidate slots to unmask (`pe_codebits.rs:48-51, 460-477`).
- Validation: $version == 1$; $136 \le ube\_len \le 64 \text{ MiB}$; available slots $\ge (14 + ube\_len) \times 8$; magic must match during locating (`pe_codebits.rs:480-509, 541-554`).
- Restoration via `slack_off`: Diff length = $14 + ube\_len$ **bytes**, where each bit represents one channel stream bit (MSB-first, `pe_codebits.rs:320-350`), indicating instruction mutation. During extraction/restoration, original instructions are restored and the diff area is **zero-filled**; `slack_off` MUST reside within declared PE slack sections with adequate space (`pe_codebits.rs:665-680`, `adapters/pe.rs:776-795`).
- Writers return $(inject\_offset, inject\_size, patch\_offset, orig\_patch\_val) = (0, 0, 0, 0)$ (`adapters/pe.rs:705-738`, `engine.rs:1420-1426`).

---

## 14. Strategy IDs and Envelope Identifiability

`strategy_id` is a single byte; the registration table serves as authoritative source (`rust/src/structure/registry.rs:90-104`):

| ID | Name | ID | Name |
| --- | --- | --- | --- |
| 1 | eof | 8 | pe_codebits |
| 2 | chunk | 9 | pe_slack |
| 3 | box_uuid | 10 | riff_chunk |
| 4 | pre_cd_inject | 11 | ebml_void |
| 5 | app_segment | 12 | item_hidden |
| 6 | incremental | 13 | free_box |
| 7 | pe_overlay | — | — |

- $MAX\_KNOWN\_STRATEGY\_ID = MAX\_STRATEGY\_ID = 13$, dynamically computed from the registry (`registry.rs:200-216`, `envelope.rs:45-52`).
- Envelope recognition requirements: $version = 0x02$, registered $strategy\_id \in [1, 13]$, $offset\_delta \le 128$, $hint\_len \le 1024$, $meta\_len \le 256 \text{ KiB}$ (§3.2, §11). Failures in `inspect` are reported as "no hidden data" (`engine.rs:2644-2656`).
- Private dialects appear as non-existent envelopes to standard readers (`engine.rs:101-116`, `params.rs:112-121`).

---

## 15. Implementation Self-Verification Checklist

1. Headers are strictly 112B Little-Endian; `version` MUST be `0x02`.
2. Evaluate §3.2 nine validation rules before allocating buffers.
3. Construct AAD per §5; `meta_len`, `hint_len`, and hint MUST match byte-for-byte; chunk AAD appends $chunk\_index$ and $is\_last$.
4. `chunk_len` includes 16B tag, excluding 4B length prefix; empty payloads write a single final chunk with $is\_last = 1$ and 16B ciphertext.
5. Validate $payload\_written$ and $ube\_total\_size$ against §2 formulas.
6. Trailers read final 24B: magic mismatch $\to$ no envelope; magic matches but CRC fails $\to$ `CorruptedData`.
7. Metadata: reject if `FLAG_COMPACT_META` is 0; varint 10th byte allows bit 0 only.
8. Never reuse nonces: metadata nonces XOR with `0xFFFFFFFF`; chunk nonces XOR lower 32 bits with $chunk\_index$.
9. Passwordless envelopes MUST be masked via `Profile.secret()`; `FLAG_ENCRYPTED` envelopes MUST remain unmasked.
10. Stealth mode requires a password and prohibits hints; magic, mask, and CRC derive from password.
11. Continuous strategies verify $inject\_offset + offset\_delta == ube\_offset$, $ube\_total\_size \le inject\_size$, and containment within file bounds; only `chunk`, `eof`, and `ebml_void` permit relocation (`relocatable_strategy`, `engine.rs:2310-2312`).
12. `pe_codebits` uses 14B + 8B IKM unmasking; `slack_off` MUST fall within slack boundaries; writer coordinates are all zeros.
13. Reject unknown strategy IDs, unrecognized flag bits, and out-of-bounds `offset_delta` immediately (fail-closed).
