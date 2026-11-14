# Content Domain Common Envelope Specification (V4)

This document specifies the wire format common layer shared across PNG / WAV / FLAC / JPEG / HEVC for independent third-party implementations. Carrier-specific cost models and candidate pools are outside the scope of this document (see §9). Envelope version is `version = 0x40`, where major version MUST be 4 (`rust/src/stego/header.rs:162`).

---

## 1. General Principles and Stability

### 1.1 Stability Tiers

- **F (Frozen)**: Written carriers depend on it; modifications render existing carriers permanently unreadable and require bumping `format_major`.
- **D (Dialect)**: Substitutable via `*FormatProfile` / `StegoProfile`; produces an isolated format dialect where builds cannot cross-read.
- **I (Implementation Freedom)**: Governs writer details only; readers are unaffected, requiring only byte-level baseline regeneration.

Envelopes, micro-headers, the three base header variants, flags/TLVs, the slot model, ChaCha12 sampling and permutations, and STC are **Tier F**; the TLV `type_id` namespace is **Tier D** (only append-only non-critical types are allowed); writer-side trellis search, cost models, and retries are **Tier I** (see individual carrier specifications).

> **Pre-1.0 Notice**: Wire formats remain subject to change prior to 1.0. Revisions will be documented in `docs/CHANGES-*.md` and validated by rebuilding baselines in `scripts/baseline_hash.py`; post-1.0, Tier F specifications can change only via increments to `format_major`.

### 1.2 Common Conventions

- Slot = a single modifiable parity bit (least significant bit) within the carrier; bytes are unpacked into slots **MSB-first** (bit 7 maps to the first slot) (`rust/src/stego/png/engine.rs:1206-1218`).
- Multi-byte fields are Big-Endian except for `sigma`, which is f32 Little-Endian (§3.1).
- Every byte of the base header and extension region enters AEAD AAD; CRC32 serves solely for pre-validation and provides no cryptographic authenticity (`rust/src/stego/envelope.rs:104-120`).
- The ciphertext body contains no magic bytes and no plaintext length tags (`rust/src/stego/envelope.rs:1-11`).

### 1.3 `format_id`

1 = PNG (`png/engine.rs:76`), 2 = WAV (`audio/mod.rs:49`), 3 = FLAC (`audio/mod.rs:51`), 4 = JPEG (implicit, `jpeg/engine.rs:65`), 5 = HEVC (implicit, `hevc/engine.rs:97`). This identifier is encoded into both AAD and spatial domain header fields, and both values MUST match.

---

## 2. Envelope and Micro-Header

### 2.1 Plaintext Layout

```text
plaintext  = [4B BE orig_len][1B flags][micro_header][payload]
ciphertext = AEAD(plaintext)          // Appends 16B tag
body_len   = len(ciphertext)          // Includes tag; excludes salt / nonce
```

`orig_len` is the uncompressed plaintext length (including micro-header), not the length of `payload` (`rust/src/stego/envelope.rs:372-401`).

### 2.2 Length Constants

- `SALT_LEN` / `NONCE_LEN` / `TAG_LEN` = 16 / 12 / 16 (`rust/src/stego/envelope.rs:64-66`).
- `BODY_OVERHEAD` = 22 = 4 + 1 + 1 + 16 (`envelope.rs:97`).
- `HEADER_LEN_MAX` = $2^{26} - 1 = 67,108,863$ (`rust/src/stego/header.rs:16-20`); `MAX_PLAINTEXT_LEN` = $67,108,841 = \text{HEADER\_LEN\_MAX} - 22$ (`envelope.rs:101-102`).
- `body_len` $\in [22, \text{HEADER\_LEN\_MAX}]$, validated immediately upon decoding the base header (Spatial: `header.rs:253-258`; JPEG: `header_v4.rs:127-132`; HEVC: `engine.rs:251-256`). `salt` and `nonce` reside exclusively in the base header, consume no body slots, and are excluded from `body_len` (`envelope.rs:13-24`).

### 2.3 Micro-Header

- `tag = 0x00`: `[0x00][data]`, text / raw bytes, no filename.
- `tag = 0x01`: `[0x01][name_len: u8][UTF-8 name][data]`, file payload; `name_len ≤ 255`.

Writers perform NFC normalization, path sanitization, and 255-byte truncation (`rust/src/stego/envelope.rs:279-306`); readers re-sanitize upon extraction (`:333-365`); maximum file micro-header overhead is capped at 256 bytes (`:88`).

Edge-case behaviors (fail-open, no error raised):

- **Writer Silent Downgrade**: If a filename sanitized via `sanitize_filename` evaluates to whitespace, `.`, `..`, or collapses to the fallback name (`core::fs::FALLBACK_NAME`), `encode_micro_header` raises no error; instead, it rewrites `tag = 0x00`, drops the filename, and keeps the payload intact (`envelope.rs:318-335`, `:283-303`). Carriers that "are files without filenames" are valid wire artifacts, and readers MUST NOT reject them.
- **Reader Fallback Naming**: If a decoded filename from `tag = 0x01` evaluates to empty after sanitization, readers fall back to `"extracted.bin"` (`envelope.rs:362-363`, `core/fs.rs:59`).
- **Protocol Effect of `--no-filename`**: When CLI `--no-filename` is passed, even if the payload originates from a file (`-d <FILE>`), the engine wraps it as `Payload::bytes`, emitting `tag = 0x00` and saving up to 256 bytes of payload space (`stego/engine.rs:491-496`, `envelope.rs:88`). This is writer-only behavior transparent to readers.

### 2.4 Envelope Flags (Plaintext Byte 5)

- Bit 0 = `FLAG_COMPRESSED`: Payload is compressed.
- Bits 1..3 = Compression algorithm ID: 0 = Deflate (only implemented algorithm).
- Bits 4..7 = Reserved, MUST be 0.

When uncompressed, algorithm ID MUST be 0; when compressed, decompressed length MUST equal `orig_len`; non-zero reserved bits MUST be rejected (`rust/src/stego/envelope.rs:123-130`, `:504-552`).

### 2.5 AAD

```text
AAD = "strhide-content-envelope-v4\0" (28B) ‖ u8(format_id) ‖ base_header ‖ extension
```

(`rust/src/stego/envelope.rs:105`, `:113-120`). Any tampering with header fields or extension bytes MUST cause AEAD verification to fail.

### 2.6 Decryption and Deframing Sequence

1. Ciphertext $< 5 + \text{tag}$ $\to$ fail (`:463-465`);  
2. AEAD verification fails $\to$ return `NoHiddenData` (`:467-494`);  
3. Plaintext $< 5$ $\to$ fail; otherwise read `orig_len` and `flags` (`:496-502`);  
4. Validate flags, algorithm, and length, then parse micro-header (`:504-552`).

---

## 3. Three Base Header Schemes

Slots are selected using L2 `locate_seed`. CRCs are CRC32-IEEE computed over all preceding bytes in the header, stored as Big-Endian. Fields are denoted as `off:size`; unlabeled types denote raw bytes.

### 3.1 Spatial Domain 64B (PNG / WAV / FLAC)

Layout: `rust/src/stego/header.rs:173-219`, encoding: `:264-291`, decoding: `:297-455`.

| off:size | Field | Type | Values / Validation |
| :--- | :--- | :--- | :--- |
| 0:16 / 16:12 / 28:4 | salt / nonce / body_len | — / — / u32be | L3 salt / AEAD nonce / $22 \dots 2^{26}-1$ |
| 32:1 / 33:1 | version / flags | u8 | major=4 / bits 0-1, others 0 |
| 34:1 / 35:1 | format_id / algorithm_id | u8 | Matches carrier and $1 \dots 3$ / PNG $1 \dots 3$, Audio 0 |
| 36:2 | suite_id | u16be | Known suite (1 or 2) |
| 38:1 / 39:1 / 40:1 | codec_id / stc_h / stc_u | u8 | 0 or 1; Hamming uses h=u=0; STC uses h $4 \dots 10$, u $1 \dots 3$ |
| 41:1 / 42:1 / 43:1 | channel_mode / class_rule / reserved | u8 | PNG 0/1, Audio 0 / PNG 0/1, Audio 0 / 0 |
| 44:2 / 46:2 / 48:2 / 50:2 | p1_window / p2_window / neg_log2_epsilon / exclusion_permille | u16be | Odd $1 \dots 63$ / Odd $1 \dots 63$ / $1 \dots 127$ / $0 \dots 900$ |
| 52:4 / 56:1 / 57:1 | sigma / kernel_id / reserved | f32le / u8 / u8 | Finite and $> 0$ / 0 / 0 |
| 58:2 / 60:4 | ext_len / crc32 | u16be / u32be | $0 \dots 255$ / CRC over offsets 0..60 |

Range violations and non-zero reserved bytes are rejected uniformly in `rust/src/stego/header.rs:387-431`. Audio strictly uses STC; Hamming header configurations in audio return `NoHiddenData` (`rust/src/stego/audio/core.rs:499-500`).

### 3.2 JPEG 44B

Layout: `rust/src/stego/jpeg/header_v4.rs:1-26`, encoding: `:74-89`, decoding: `:92-169`.

| off:size | Field | Type | Values / Validation |
| :--- | :--- | :--- | :--- |
| 0:1 / 1:1 / 2:2 | version / flags / suite_id | u8 / u8 / u16be | major=4 / bits 0-1, others 0 / Known suite |
| 4:16 / 20:12 | salt / nonce | — | L3 salt / AEAD nonce |
| 32:4 | body_len | u32be | $22 \dots 2^{26}-1$ |
| 36:1 / 37:1 / 38:1 | codec_id / stc_h / stc_u | u8 | MUST be 0 (ternary STC) / $4 \dots 10$ / $1 \dots 64$ |
| 39:1 | ext_len | u8 | $0 \dots 255$ |
| 40:4 | crc32 | u32be | CRC over offsets 0..40 |

Implicit constants: `format_id = 4`, luminance channel modulation only, no Hamming path (`rust/src/stego/jpeg/header_v4.rs:43-70`).

### 3.3 HEVC / HEIF 32B

Layout: `rust/src/stego/hevc/engine.rs:148-173`, encoding: `:177-191`, decoding: `:194-278`.

| off:size | Field | Type | Values / Validation |
| :--- | :--- | :--- | :--- |
| 0:4 / 4:1 / 5:1 | magic4 / version / flags | — / u8 | Matches L2-derived value / major=4 / bits 0-1, others 0 |
| 6:1 / 7:2 | stc_u / window_slices | u8 / u16be | $1 \dots 64$ (reader authoritative, must match profile) / $\ge 1$ |
| 9:1 / 10:2 | ext_len / suite_id | u8 / u16be | $0 \dots 64$ / Known suite |
| 12:4 / 16:12 | body_len / nonce | u32be / — | $22 \dots 2^{26}-1$ / Also input to session salt |
| 28:4 | crc32 | u32be | CRC over offsets 0..28 |

Implicit constants: `format_id = 5`, `stc_h` (official 7, from `rust/src/stego/format.rs:99-105`), `total_windows = 1`. `magic4` is dynamically derived via L2, not a fixed literal magic.

### 3.4 Common Validation (Prior to Reading Body)

1. `major == 4`;  
2. `flags` permits only bits 0 and 1;  
3. `FLAG_EXT_PRESENT == (ext_len > 0)` (`rust/src/stego/header.rs:225-247`);  
4. `suite_id ∈ {1 (AES-256-GCM), 2 (ChaCha20-Poly1305)}` (`rust/src/core/crypto.rs:132-136`);  
5. `body_len ∈ [22, HEADER_LEN_MAX]`;  
6. Carrier-specific field validation (§3.1–§3.3);  
7. `ext_len ≤ 255` (Spatial/JPEG) or `≤ 64` (HEVC);  
8. CRC32 verification passes. Recomputing CRC maliciously is ineffective: header bytes are bound inside AAD, forcing AEAD failure.

---

## 4. Flags, `ext_len`, and TLV Syntax

### 4.1 Base Header Flags

- Bit 0 = `FLAG_EXT_PRESENT = 0x01`: Extension region contains at least one TLV.
- Bit 1 = `FLAG_EXT_CRITICAL = 0x02`: At least one TLV has its critical flag set.
- Bits 2..7 = Reserved, MUST be 0.

`FLAG_EXT_CRITICAL` MUST accurately reflect actual extension contents; setting it on an empty extension or omitting it when critical TLVs exist MUST be rejected (`rust/src/stego/header.rs:480-500`). `ext_len` denotes extension length in **bytes**; message bits equal $8 \times \text{ext\_len}$ (`rust/src/stego/png/engine.rs:1191-1199`).

### 4.2 TLV Syntax

- `type_id(1B) ‖ len(1B) ‖ value(len B)`, where `len ∈ 0..=255`; bit 7 (`0x80`) of `type_id` is the critical bit (`rust/src/stego/header.rs:43-59`).
- `type_id = 0` denotes padding: from this byte onward, all remaining extension bytes MUST be strictly 0, terminating parsing; non-zero values MUST be rejected (`header.rs:112-146`).
- Truncated or out-of-bounds TLV entries MUST be rejected; writers MUST NOT emit `type_id = 0` with non-zero length or `value.len() > 255` (`header.rs:72-92`).

### 4.3 Fail-Closed Behavior

- **Writers reject any critical TLV**: V4 defines no critical semantics; rejecting them prevents writing unreadable carriers (`rust/src/stego/header.rs:94-110`).
- **Readers reject any critical TLV**: `extract` / `inspect` uniformly return "no hidden data" (Spatial: `png/engine.rs:2024-2033`, `:2295-2303`; Audio: `audio/core.rs:584-591`; JPEG: `jpeg/engine.rs:1362`, `:1606-1616`). Unrecognized non-critical TLVs are ignored.
- Structural corruption in the extension region produces `CorruptedData` at parsing level, collapsing to `NoHiddenData` in content domain `extract` (§8.1).

### 4.4 Extension Slot Count

- PNG / WAV / FLAC: $8 \times \text{ext\_len}$, 1 slot per bit, unencoded by STC (`rust/src/stego/png/engine.rs:1197`).
- JPEG: $\text{ext\_u} \times (8 \times \text{ext\_len} + \text{ext\_h} - 1)$, officially $4 \times (8 \times \text{ext\_len} + 7)$ (`rust/src/stego/format.rs:161-164`).
- HEVC: $2 \times (8 \times \text{ext\_len} + 6)$, with fixed $h=7, u=2$ (`rust/src/stego/hevc/engine.rs:131-143`).

When $\text{ext\_len} = 0$, JPEG still reserves $4 \times 7 = 28$ slots (`rust/src/stego/format.rs:544`); Spatial and HEVC reserve 0 slots.

---

## 5. Slot Model

- **Bit Ordering**: Bytes are unpacked into slots MSB-first and reassembled in the same order (`png/engine.rs:1206-1218`).
- **Header Region**: The base header and extension region form prefixes of the identical permutation: $[0, \text{base\_slots})$ and $[\text{base\_slots}, \text{base\_slots} + \text{ext\_slots})$. Permutations MUST be prefix-stable, enabling readers to decode the base header first to determine `ext_len` before generating extension slots (§6.3–§6.5).
- **Body Slots**: Derivation of $N = \text{slots\_for}(8 \times \text{body\_len}, h, u)$ body slots **varies by carrier and MUST match verbatim**:
  - PNG: Sorts candidates by cost, truncates by exclusion rate to exactly $N$, then calls `permute_indices` on this slice (`rust/src/stego/png/engine.rs:1742-1744`, `:2141-2154`);
  - JPEG: Calls `permute_prefix(grid, N)` on the full `BodyGrid`, then truncates to the first $N$ (`rust/src/stego/jpeg/engine.rs:1007-1008`, `:1330-1331`);
  - HEVC: Applies linear congruential selection inside bands to retrieve the first $N$ (`rust/src/stego/hevc/engine.rs:376-414`);
  - WAV: Extracts prefix `at(base + i)` from whole-pool `KeyedPermutation(locate_seed, total_slots)`; FLAC: selects body pool via `thin_pick`, then calls `KeyedPermutation(locate_seed, body_n)` on the selection (`rust/src/stego/audio/core.rs:250-255`, `:831`).
  These patterns are strictly non-interchangeable. Permuting whole pools before truncating in PNG or truncating before permuting in JPEG desynchronizes slot mappings entirely.
- **Decoupling Header Slots from Costs**: Header slots MUST NOT depend on cost maps or `algorithm_id`; readers must decode the header before discovering `algorithm_id` (`png/engine.rs:1189-1200`, `hevc/engine.rs:304-338`).

---

## 6. Pseudorandom Stream and Permutations

### 6.1 ChaCha12

Constants: `0x61707865, 0x3320646E, 0x79622D32, 0x6B206574`; 32B seed is unpacked as eight 32-bit little-endian words; `state[12..14]` is a 64-bit block counter (initial 0); `state[14..16]` is zero (`rust/src/stego/prng.rs:25`, `:60-93`). Each block undergoes 6 double-rounds (12 rounds): columns `(0,4,8,12)(1,5,9,13)(2,6,10,14)(3,7,11,15)`, diagonals `(0,5,10,15)(1,6,11,12)(2,7,8,13)(3,4,9,14)` (`prng.rs:97-113`). Quarter-round (QR): `a+=b; d^=a; d<<<=16; c+=d; b^=c; b<<<=12; a+=b; d^=a; d<<<=8; c+=d; b^=c; b<<<=7` (`prng.rs:29-45`). Output is `buffer[i] = x[i] + state[i]` formatted as Little-Endian u32; `next_u64 = lo | (hi << 32)` (`prng.rs:115-146`).

Test vector (`seed = 01 00 ... 00`, first 128 bytes from `rust/src/stego/prng.rs:301-327`):

```text
12 05 6e 59 d5 65 05 6b ef 0e 0f 09 df 5c 22 9a
49 24 8c 27 90 52 5d 0f 93 02 18 ff 0b 4d dd 10
a6 00 22 39 d9 a4 54 e2 9e 10 7a 7d 06 fe fd fe
f0 21 0f eb a0 44 f9 f2 9b 17 72 c9 60 dc 29 c0
0c 73 66 c5 cb c6 04 24 0e 66 5e b0 2a 69 37 2a
7a f9 79 b2 6f bb 78 09 2a c7 c4 b8 80 29 a7 c8
54 51 3b c2 17 bb fc 7d 90 43 2e 30 8e ba 15 af
c6 5a eb 48 ef 10 0d 56 01 e6 af ba 25 71 17 a9
```

### 6.2 `gen_range` (Rejection Sampling)

```text
bound <= 1        -> 0
bound <= 2^32 - 1 -> b = bound; limit = 2^32 - (2^32 mod b); take next_u32(); if r < limit return r mod b
otherwise         -> b = bound; limit = 2^64 - (2^64 mod b); take next_u64(); if r < limit return r mod b
```

(`rust/src/stego/prng.rs:152-180`). Using raw modulo introduces distribution bias and desynchronizes sequences.

### 6.3 Dual-Form Fisher–Yates

- **Full Array** `permute_indices(items, seed)`: `for i in (1..n).rev()`, $j = \text{gen\_range}(i+1)$, swap `items[i]` and `items[j]` (`prng.rs:185-202`).
- **Prefix** `permute_prefix(items, k, seed)`: `end = min(k, n-1)`, `for i in 0..end`, $j = i + \text{gen\_range}(n-i)$, swap (`prng.rs:209-235`, `:242-248`). Only the first $k$ elements are finalized.
- **Prefix Continuation Stability**: Splitting `0..k` into consecutive calls `0..s` and `s..k` sharing the same RNG produces identical results to a single invocation (`prng.rs:213-235`, `:471-491`); this is the prerequisite for reading base headers before generating extension slots.

### 6.4 HEVC Keyed Linear Congruential Permutation

```text
fold(seed32): s = 0x243F6A8885A308D3
              for each 8B LE chunk: s = splitmix64(s ^ chunk)
params(len, seed32, band_start):
  s = fold(seed32) ^ (u64(band_start) * 0x9E3779B97F4A7C15)
  start  = splitmix64(s) % len
  stride = max(splitmix64(s ^ 0xA5A55A5A3C3CC3C3) % len, 1)
  while gcd(stride, len) != 1: stride += 1; if stride >= len then stride = 1 and break
pos_i = (start + i * stride) mod len        // Multiplication evaluated in u64
splitmix64(x): x += 0x9E3779B97F4A7C15; z = (x ^ (x>>30)) * 0xBF58476D1CE4E5B9;
               z = (z ^ (z>>27)) * 0x94D049BB133111EB; return z ^ (z>>31)
```

(`rust/src/stego/hevc/engine.rs:344-373`, `:1958-1988`). $\gcd(\text{stride}, \text{len}) = 1$ ensures a full permutation; `band_start` (absolute coordinate, not band index) binds the derivation, ensuring that empty bands do not displace subsequent bands; `pos_i` is independent of the number of requested elements, providing prefix stability.

### 6.5 Audio 6-Round Feistel with Cycle Walking

```text
PERM_LABEL = "strhide-audio-perm-v1"; ROUNDS = 6
mix(z): z += 0x9E3779B97F4A7C15; z = (z ^ (z>>30)) * 0xBF58476D1CE4E5B9;
        z = (z ^ (z>>27)) * 0x94D049BB133111EB; return z ^ (z>>31)
perm_new(seed32, n):
  bits = 1 if n <= 1 else 64 - leading_zeros(n - 1)      # ceil(log2 n)
  half = clamp(ceil(bits / 2), 1, 32)
  d = SHA-256(PERM_LABEL ‖ seed32 ‖ u64be(n));  k0 = u64be(d[0..8]);  k1 = u64be(d[8..16])
round(i) = mix(k[i & 1] ^ rotl64(i, 17))
permute_block(x):
  L = (x >> half) & mask;  R = x & mask
  repeat r = 0..5:  f = round(r ^ R) & mask;  (L, R) = (R, L ^ f)
  return (L << half) | R
at(i): x = i mod n;  y = permute_block(x);  while y >= n: x = y; y = permute_block(x);  return y
```

(`rust/src/stego/audio/perm.rs:29-44`, `:64-91`, `:100-118`, `:124-145`). `permute_block` is a bijection over $2^{2 \cdot \text{half}}$, and cycle walking preserves bijectivity, making `at(i)` a permutation over $[0, n)$; returns 0 when $n \le 1$.

---

## 7. STC: Parameters, Column Vectors, and Syndrome Decoding

### 7.1 Parameters and Capacity

Constraint: $h \in [4, 10]$ (`rust/src/stego/coding/stc.rs:78-83`), $u \in [1, 64]$; Spatial restricts $u \le 3$ (`header.rs:374`), JPEG permits $u \le 64$ via header. HEVC extension fixes $h=7, u=2$; HEVC body writes using `HevcFormatProfile` (official `7/2`, `hevc/engine.rs:1400`), while readers reconstruct trellis using `stc_u` from the base header (`hevc/engine.rs:2249`), making `stc_u` authoritative on read. `stc_h` is unencoded in HEVC headers and is sourced from profile. $n$ carrier elements accommodate $m = \lfloor n/u \rfloor - (h - 1)$ bits; writer sets $n = u \cdot (m + h - 1)$, where $m=0 \implies n=0$, with $n$ a multiple of $u$ (`stc.rs:390-406`).

### 7.2 Column Vectors

```text
mask = (1 << h) - 1
pattern(idx): x = (splitmix64(seed + idx) as u32) & mask   # Wrapping u64 addition
              x |= 1; x |= 1 << (h - 1); return reverse_low_bits(x, h)
```

`seed` is u64: base headers use L2 `header_stc_seed`, extensions use `ext_stc_seed`, body uses L3 `stc_seed` (`rust/src/stego/format.rs:480-485`, `:495-516`). `reverse_low_bits` maps bit $d$ to $h - 1 - d$, positioning bit 0 as the current settlement row and bit $(h-1)$ as newest state (`stc.rs:174-191`, `:349-376`). Column generation: start at $\text{idx} = s$, sample $\text{col} = \text{pattern}(\text{idx})$; if duplicate and $\text{cols.len}() < 2^{h-2}$, retry with $\text{idx} \mathrel{+}= u$; accept duplicates after reaching $2^{h-2}$ distinct columns (`stc.rs:361-373`).

### 7.3 Syndrome Decoding (Reader)

```text
row_syndrome(r) = XOR over g ∈ [max(0, r - h + 1), r], s ∈ [0, u)
                  when (cols[s] >> (r - g)) & 1 == 1, xor (vals[g * u + s] & 1)
```

Message bit $b$ = $\text{row\_syndrome}(b + h - 1)$; the first $h - 1$ rows represent warm-up states (`rust/src/stego/coding/stc.rs:408-450`). Message bytes are packed **MSB-first**: bit $7 - (b \bmod 8)$ in byte $\lfloor b/8 \rfloor$, trailing bits zero-padded. **Reading requires no Viterbi trellis search**: the reader merely computes $H \cdot x$; trellis search exists solely on writers to find minimal-distortion flip sets (`stc.rs:51-55`).

### 7.4 $u = 1$ Deterministic Solution

When $m = n - h + 1$, every slot value is uniquely determined: the $j$-th element flips if and only if parity of row $j + h - 1 \ne \text{message bit } j$. No search or cost weighting is involved, with an exact 0.5 flip rate (`stc.rs:556-561`); reading logic is identical to $u > 1$.

---

## 8. Behavioral Semantics

### 8.1 `extract`: Unified `NoHiddenData`

After carrier parsing succeeds, **any failure prior to AEAD verification** (invalid header, extension errors, critical TLVs, unknown suite, AEAD verification failure, mismatched ciphertext length) MUST uniformly return `NoHiddenData`, preventing callers from distinguishing between absent data and invalid keys (`rust/src/stego/envelope.rs:449-465`, `audio/core.rs:499-500`, `:586`, `png/engine.rs:2007`, `:2024-2033`). Once AEAD verification passes, framing errors (unsupported compression, $\text{orig\_len} > \text{max\_payload\_bytes}$, decompression failure, corrupted micro-header) indicate an authentic envelope with internal structural damage, emitting `CorruptedData` / `UnsupportedVersion` (`rust/src/stego/png/engine.rs:2174-2185`, `rust/src/stego/envelope.rs:504-552`).

### 8.2 `verify`: Three Independent Verification Tiers

1 = `carrier` (carrier parsed successfully);  
2 = `header` (`inspect` recognizes valid readable envelope);  
3 = `payload` (`extract` succeeded and passed AEAD verification).  
Each tier independently reports `ok` / `message`; a failure at Tier 3 MUST NOT be reported as success at Tier 2 (`rust/src/stego/audio/core.rs:1162-1220`).

### 8.3 Unauthenticated Lengths

`body_len` is unauthenticated prior to decryption and MUST ONLY be used to:  
1. Validate against range $[22, \text{HEADER\_LEN\_MAX}]$;  
2. Delimit slot reading within the policy bound $\min(\text{max\_payload\_bytes} + 22, \text{HEADER\_LEN\_MAX})$ (`rust/src/stego/params.rs:809-843`).  
`max_payload_bytes` defaults to `MAX_PLAINTEXT_LEN` as a **plaintext** limit (`params.rs:766-773`). Allocating buffers based on unverified lengths is strictly prohibited; body slots are calculated via $\text{slots\_for}(8 \cdot \text{body\_len}, h, u)$, failing immediately if candidates are insufficient (`jpeg/engine.rs:1309-1319`).

### 8.4 Fail-Closed Rules

`major != 4`, reserved bits in flags non-zero, `EXT_PRESENT` mismatch with `ext_len`, `EXT_CRITICAL` mismatch with extension contents, unknown suite, `body_len` out of bounds, CRC mismatch, `ext_len` overflow, critical TLVs present, or truncated / unpadded extension bytes MUST all be rejected prior to attempting body reads.

---

## 9. Related Specifications

- [CONTENT-PNG.md](./CONTENT-PNG.md): Channels, cost models, and candidate sorting
- [CONTENT-JPEG.md](./CONTENT-JPEG.md): DCT grid, superblocks, and extension slots
- [CONTENT-HEVC.md](./CONTENT-HEVC.md): CABAC slots, windows, and banding
- [CONTENT-AUDIO.md](./CONTENT-AUDIO.md): WAV sample domain / FLAC residual domain
- [CRYPTO.md](./CRYPTO.md): L1/L2/L3 derivation, AAD, AEAD, and credentials
- [CAPACITY.md](./CAPACITY.md): Capacity formulas and probe/embed alignment
- [DETMATH.md](./DETMATH.md): Deterministic numerical semantics for `exp` / `ln` / `ln_1p` / `cos` / `log2`
