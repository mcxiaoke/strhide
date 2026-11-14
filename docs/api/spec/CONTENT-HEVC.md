# HEVC / HEIF Content Carrier Specification (V4)

Navigation: [Common Envelope and STC](CONTENT-ENVELOPE.md) | [Capacity](CAPACITY.md) | [Cryptography](CRYPTO.md) | [Overview](README.md)

This document specifies the slot geometry, banding, keyed linear permutation, 32B base header, `pre_salt`, and writer constraints specific to HEVC video and HEIF/HEIC images. Common envelopes, micro-headers, AAD, L1/L2/L3 derivation, TLV rules, and STC are specified in the common layer documents.

---

## 1. Scope and Stability

Applies to HEVC video streams packaged within MP4 / MOV / MKV containers, raw Annex-B byte streams, and primary or `grid` image items in HEIF / HEIC files. HEIF thumbnail bridging operates outside Scheme C; see §8.5.

**Container Parsing Defensive Ceiling**: Inspecting MP4/MOV container structures (via `inspect` and paths constructing `StegoHeaderInfo`) loads the entire `moov` box into memory. A hard ceiling of 32 MiB is enforced; exceeding this returns `UnsupportedFormat("MP4 moov box exceeds 32 MiB")` (`rust/src/stego/hevc/engine.rs:2627-2631`). This protects against malformed or malicious container structures; normal `moov` boxes (including `stsd` / `stbl`) are far smaller.

| Content | Tier | Justification |
| :--- | :--- | :--- |
| Slot semantics, banding, linear permutation, 32B base header, `pre_salt`, session salt | **F** | Changes render existing carriers permanently unreadable |
| `HevcFormatProfile` labels and default $stc\_h / stc\_u$ | **D** | Modifying labels or parameters produces an isolated format dialect |
| Re-encoding, zero-padding, multi-threading, SIMD, race prevention strategies | **I** | Affects writer output bytes only; guarded by byte-level baselines |

Official profile: `magic_label = b"strhide-hevc-magic-v4"`, `cover_salt = b"strhide-hevc-cover-v1"`, $stc\_h = 7$, $stc\_u = 2$ (`rust/src/stego/format.rs:98-105`).

---

## 2. Modulation Point: Syntax Element

The sole modified syntax element is the TU-level CABAC bypass `coeff_sign_flag` (sign of non-DC transform coefficients). DC coefficients ($x_c == y_c == 0$) are permanently excluded (`rust/src/stego/hevc/slot.rs:581-589`; logged at `:615-626`). Each slot is recorded as a 16-byte structure (`rust/src/stego/hevc/slot.rs:143-159`):

| Field | Type | Meaning |
| :--- | :--- | :--- |
| `cost` | f32 | Perceptual distortion cost of flipping coefficient sign |
| `op_idx` | u32 | Index in the slice's `BinOp` trace log |
| `slice_idx` | u32 | 0-based slice index within carrier |
| `substream_idx` | u16 | WPP / tile substream index within slice |
| `original_bit` | u8 | Original sign bit: 0 = positive, 1 = negative (slot parity) |

Writers invert `original_bit` and re-encode the identical CABAC substream along the logged trace; rewritten NAL length MUST exactly match the original span, otherwise the operation is rejected (`rust/src/stego/hevc/engine.rs:1909-1920`). Stream dimensions, parameter sets, slice headers, and decoded visual geometry remain unaltered (`rust/src/stego/hevc/bitstream.rs:178-191`).

---

## 3. Slot Pool and Header Locating

Candidate slots originate strictly from VCL slices capable of carrying payload (§8.2), appended in decode order to the slot buffer; the prefix of this buffer forms the header candidate pool.

- Header pool size: $pool\_size = \min(total\_window\_slots, 2048)$ (`rust/src/stego/hevc/engine.rs:91-92`, `:2236-2237`).
- Header slot count: $524 + ext\_slots$, where $ext\_slots = 2 \cdot (8 \cdot ext\_len + 6)$, or 0 when $ext\_len = 0$ (`rust/src/stego/hevc/engine.rs:94`, `:137-142`).
- Header slot $i$: $pos_i = (start + i \cdot stride) \bmod pool\_size$, for $i \in [0, 524 + ext\_slots)$, with $band\_start = 0$ (`rust/src/stego/hevc/engine.rs:304-338`).

`start` and `stride` are derived from L2 `locate_seed` per §5. The first 524 items of this permutation carry the base header, and subsequent items carry the extension region, allowing readers to decode the base header first and resume decoding extension bytes based on decoded `ext_len`. $524 = 2 \cdot (256 + 6)$ corresponds to official defaults $h = 7, u = 2$; $stc\_h$ is not encoded into headers (`rust/src/stego/hevc/engine.rs:148-152`).

Writer window target: $target\_slots = \max(524 + ext\_slots + desired\_body\_slots + 128, 2048)$ (`rust/src/stego/hevc/engine.rs:430-438`). The first pass records at least 2048 slots (`MinSlots`), continuing with `TargetSlots(target_slots)` until the payload target is met or the carrier is exhausted (`:1229-1257`).

---

## 4. Body Banding

Banding depends strictly on the `nal_unit_type` sequence and whether inter-frame pictures exist in the carrier; embedding modifications alter neither property (`rust/src/stego/hevc/engine.rs:4098-4120`):

- Carriers with no inter-frame pictures (still images, all-intra): all pictures belong to Band 0.
- Carriers with inter-frame pictures: non-reference pictures belong to Band 0; reference non-IRAP pictures belong to Band 1; IRAP pictures (BLA / IDR / CRA, types $16 \dots 23$) and RASL pictures carry zero slots.

Body pool construction (`rust/src/stego/hevc/engine.rs:376-414`): within the `pool_size` prefix, all header positions are eliminated; remaining slots are appended in decode order to Band 0 or Band 1; slots beyond `pool_size` are appended directly to their respective band (header slots exist exclusively within the prefix). Final band ranges: $bands = [0 \dots band0.len(), band0.len() \dots total\_body]$ (`:4014-4026`). Body slot $i$:

```text
(start, stride) = params(band.len(), perm_seed, band.start)
pos_i = band.start + ((start + i * stride) mod band.len())
```

Band 0 is exhausted first; Band 1 is entered only when $body\_n > band0.len()$; the two bands never interleave (`rust/src/stego/hevc/engine.rs:1955-1988`). $body\_n$ is computed from $body\_len \times 8$ using $\text{slots\_for}(8 \cdot body\_len, stc\_h, stc\_u)$ (`:2248-2251`).

---

## 5. Keyed Linear Permutation Complete Definition

`params(len, perm_seed, band_start)` (`rust/src/stego/hevc/engine.rs:344-373`):

```text
seed = 0x243F6A8885A308D3
for chunk in perm_seed[0..32] as 4 × u64le:
    seed = splitmix64(seed XOR chunk)
seed ^= band_start * 0x9E3779B97F4A7C15
start  = splitmix64(seed) mod len
stride = splitmix64(seed XOR 0xA5A55A5A3C3CC3C3) mod len
stride = max(stride, 1)
while gcd(stride, len) != 1:
    stride += 1
    if stride >= len: stride = 1; break

splitmix64(x):
    x = x + 0x9E3779B97F4A7C15
    z = (x XOR (x >> 30)) * 0xBF58476D1CE4E5B9
    z = (z XOR (z >> 27)) * 0x94D049BB133111EB
    return z XOR (z >> 31)
```

Header uses L2 `locate_seed`; body uses L3 32B `perm_seed`. Chunks of 8 bytes are folded sequentially as `u64le` (avoiding parallel XOR) to prevent entropy collapse (`:345-351`). Boundary conditions: $len = 0$ returns empty; $len = 1$ sets $start = 0, stride = 1$; $stride$ is coprime to $len$; prefix elements are independent of requested count (`:327-337`). Multiplications evaluate in u64 to avoid overflow on large HEIC carriers (`:1979-1984`).

---

## 6. 32B Base Header

Layout and encoding: `rust/src/stego/hevc/engine.rs:148-190`, decoding and validation: `:193-278`.

| Offset | Size | Field | Description |
| :--- | :--- | :--- | :--- |
| 0 | 4 | `magic` | L2-derived 4-byte signature |
| 4 | 1 | `version` | `0x40` (major version 4) |
| 5 | 1 | `flags` | `EXT_PRESENT` / `EXT_CRITICAL`, other bits MUST be 0 |
| 6 | 1 | `stc_u` | STC constraint width, $1 \dots 64$ |
| 7 | 2 | `window_slices` | Slices recorded in writer's primary window, $\ge 1$ |
| 9 | 1 | `ext_len` | Extension TLV byte length, $0 \dots 64$ |
| 10 | 2 | `suite_id` | AEAD cipher suite identifier |
| 12 | 4 | `body_len` | Ciphertext length (including 16B tag) |
| 16 | 12 | `nonce` | AEAD nonce; input to session salt derivation |
| 28 | 4 | CRC32-IEEE | CRC over `bytes[0..28]`, Big-Endian |

Implicit constants: `format_id = 5`, `total_windows = 1`, and `stc_h` (from profile, official default 7). These are bound cryptographically via AAD and STC parameters (`:148-152`, `:1393`).

`stc_u` is self-describing: writers emit `fmt.stc_u` (`:1385-1390`), and readers validate $1 \dots 64$ and construct the trellis using this header value (`:231-235`, `:2248-2249`). $stc\_h$ is sourced strictly from profile; header geometry assumes official $h=7, u=2$ (524 slots). `flags` / `ext_len` consistency, suite validity, and $body\_len \in [BODY\_OVERHEAD, HEADER\_LEN\_MAX]$ are validated prior to reading payload bytes (`:221-257`).

Session Salt (Tier F): `session_salt = SHA-256("strhide-hevc-session-v4" ‖ nonce[0..12])` (`rust/src/stego/hevc/engine.rs:451-456`). Generation of nonce follows the common envelope.

---

## 7. `pre_salt` and Carrier Identity

`pre_salt` incorporates invariant parameter sets and slice headers, guaranteeing identical keys across writers and readers. Common prefix: $salt\_prefix = cover\_salt \mathbin{\Vert} \text{"hevc-v4"}$ (`rust/src/stego/hevc/engine.rs:4265-4270`).

Container Path `DigestInputs::ParameterSets` (`:4272-4287`):

```text
pre_salt = SHA-256(salt_prefix ‖ u64be(P)
                   ‖ for each ps[0..P]: u64be(len(ps)) ‖ ps)
```

`P` is the total count of VPS / SPS / PPS NAL units, each including its 2B NAL header; non-parameter sets (e.g. SEI) are stripped (`rust/src/stego/hevc/heif_boxes.rs:515-560`).

Annex-B Path via `compute_hevc_cover_digest` (`:4289`; defined in `rust/src/stego/hevc/bitstream.rs:192-211`):

```text
pre_salt = SHA-256(salt_prefix ‖ u64be(N)
                   ‖ for each physical NAL span:
                       Parameter Set: Full NAL bytes (header_offset..end)
                       VCL Slice:     2B NAL header ‖ u64be(nal_len))
```

The first CABAC byte following a VCL slice header may be altered during embedding and MUST NOT enter the digest; NAL length is preserved and invariant (`bitstream.rs:178-191`).

---

## 8. Extension Region, Capacity, Windows, and HEIF

### 8.1 Extension Region and Capacity
$ext\_len \le 64$ (`rust/src/stego/hevc/engine.rs:123-124`, `:441-448`); TLV syntax follows common envelope; extension slots equal $2 \cdot (8 \cdot ext\_len + 6)$ (`:136-142`).

```text
hdr_slots   = 524 + ext_slots
body_slots  = total_slots - hdr_slots
max_payload = message_bits(body_slots, stc_h, stc_u) / 8 - BODY_OVERHEAD
```

$BODY\_OVERHEAD = 22$; `body_len` includes tag (`:468-500`). `total_slots` counts all eligible candidate slots recorded across the window. Probing uses profile $stc\_u$; body decoding uses header $stc\_u$; both equal 2 under official defaults.

### 8.2 Windows and Slice Selection
- Candidate slices evaluate in decode order; only VCL slices where `picture_band` returns `Some` enter the pool; IRAP and RASL are skipped (`:4098-4120`).
- `window_slices` records the actual count of slices scanned during embedding (`:1364-1370`).
- Readers record `MinSlots(2048)` on the first pass; if $recorded\_slices < window\_slices$, they rescan via `TargetSlices(window_slices)` (`:2038-2042`, `:2222-2234`). In both passes, $pool\_size = \min(total\_window\_slots, 2048)$.

### 8.3 Emulation Prevention Byte (EPB) Conflict Resolution
Writers execute up to 24 retry rounds (`:81`, `:1407`): solving base header, extension, and body STC separately; re-encoding only modified slices/substreams; verifying that replay matches original spans (with up to 4 trailing zero bytes, §9). If re-encoding produces a new `00 00 xx <= 3` sequence requiring EPB insertion, or re-encoding fails, the affected slots enter `forbidden` with cost penalty $FORBIDDEN\_SLOT\_SURCHARGE = 10^9$, triggering another solve round. EPB exclusion radius is $8 \ll \min(round, 3)$; if no slot falls within radius, the nearest flipped slot prior to the window is excluded; persistent failures abort (`:1631-1687`).

### 8.4 HEIF Scheme C
- Primary item is not `grid`: target = `pitm` primary item; primary item is `grid`: target = `iref/dimg` tile items, falling back to primary item if `dimg` is missing (`rust/src/stego/hevc/heif_boxes.rs:161-184`).
- `hvcC` is resolved via `ipma` linking target items; missing `hvcC` causes rejection; `iloc` single-extent spans are parsed; overlapping extents are rejected (`:440-488`, `:193-223`).

### 8.5 HEIF Thumbnail Bridging (Independent of Scheme C)
Attempted exclusively on `FileFormat::Heif` after Scheme C fails. Triggers include `NoHiddenData`, `UnsupportedFormat`, `TrellisInfeasible`; does not trigger on `Cancelled`, credential mismatch, policy, or container parse errors; disallowed under `HevcMode::Cabac`; disabled when feature `content-heif-bridge` is off (`rust/src/stego/engine.rs:426-447`, `:497-540`, `:569-597`).

Bridging targets (`rust/src/stego/heif/thumb_bridge.rs:651-741`): `thmb`-referenced JPEG items, or any non-primary single-extent JPEG item; secondarily Exif embedded JPEG thumbnails. Primary items are never targeted and remain untouched. Uncompressed (`unci`) items are unsupported and rejected. Bridging uses JPEG V4 envelope (`format_id = 4`), bypassing 32B HEVC headers and CABAC slots.

---

## 9. Writer-Only Tier I Scope

- **Re-encoding / Re-packetization**: CABAC substreams are re-encoded along `BinOp` traces; context initial states are loaded from `SubstreamRecord.init_contexts`; intermediate substreams append termination bits per ITU-T H.265 §9.3.2.6 (`rust/src/stego/hevc/engine.rs:1739-1817`).
- **Length Invariance**: Exact-length matches replace in-place; 1–4 bytes short pad trailing zeros; length increases return `BadSubstream` (`:1858-1880`).
- **Replay Verification**: Unflipped streams must replay identically, tolerating up to 4 trailing zero padding bytes (`cabac_zero_word`) (`:1924-1934`).
- **Parallelization**: Multi-threading via Rayon operates on independent slices, with no cross-slice reduction (`:1565-1588`).
- **SIMD**: Any SIMD paths must match scalar execution bit-for-bit, verified via baselines.
- **Verification**: Changes require running `python scripts/baseline_hash.py --check` and `cargo run --release --all-features --example hevc_stress`.
