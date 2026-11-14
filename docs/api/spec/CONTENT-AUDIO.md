# WAV / FLAC Audio Content Carrier Specification (V4)

Navigation: [Common Envelope and STC](CONTENT-ENVELOPE.md) | [Capacity](CAPACITY.md) | [Cryptography](CRYPTO.md) | [Overview](README.md)

This document specifies PCM slot definitions, layouts, `pre_salt`, capacity formulas, and writer boundaries specific to WAV and FLAC carriers. The 64B base header, AAD, L1/L2/L3 derivation, TLV rules, and STC matrix definitions are specified in common layer documents.

---

## 1. Scope and Stability

Applies to RIFF / WAVE integer PCM audio and native FLAC (`fLaC`) streams. WAV supports 8 / 16 / 24 / 32-bit integer PCM (16 / 24-bit are primary paths); FLAC supports 4..=24-bit (depths > 24-bit are rejected). Both share the 64B header architecture, with `format_id` fixed to WAV = 2 and FLAC = 3 (`rust/src/stego/audio/mod.rs:49-51`).

| Scope | Tier | Justification |
| :--- | :--- | :--- |
| Slot definitions, slot planning, `thin_pick`, `pre_salt`, capacity budget | **F** | Alterations render existing carriers permanently unreadable |
| `hpos_salt` labels, format profile defaults, `format_id` | **D** | Modifying labels produces an isolated dialect |
| Cost models, direction salt, retry loops, multi-threading / SIMD | **I** | Writer details only; guarded by byte-level baselines |

Audio carriers **strictly use STC**. `codec_id = 1` denotes STC (`rust/src/stego/audio/core.rs:803-807`); `codec_id = 0` (Hamming) is an unallocated reserved value in audio; reading a Hamming header in audio returns `NoHiddenData` (`:637-653`, `:797-810`). There is no fallback sequence between Hamming and STC.

---

## 2. Common Header and Slot Budget

Audio uses the 64B `SpatialHeaderV4` common layout (`rust/src/stego/header.rs:153-156`, `:173-219`). Audio-specific fields are fixed: `algorithm_id = 0`, `channel_mode = 0`, `class_rule = 0`, `p2_window = 1`, `kernel_id = 0` (`rust/src/stego/audio/core.rs:798-821`). `format_id` is 2 or 3; $stc\_h$ and $stc\_u$ are self-describing in the header, and readers reconstruct the trellis according to these values.

The base header occupies 512 slots (`PNG_AUDIO_BASE_SLOTS`), and the extension region occupies $8 \cdot ext\_len$ slots, yielding $header\_slots = 512 + 8 \cdot ext\_len$ (`rust/src/stego/audio/core.rs:711-714`, `:837-852`). TLV semantics follow the common envelope; when $ext\_len = 0$, no extension slots are written.

---

## 3. WAV

### 3.1 Parsing and Slot Definitions
- Supported formats: `RIFF/WAVE` containing standard `FORMAT_PCM` or PCM sub-formats of `WAVE_FORMAT_EXTENSIBLE`; RF64, floating-point PCM, and ADPCM are rejected (`rust/src/stego/audio/wav.rs:102-162`).
- `block_align` MUST equal $channels \times bytes\_per\_sample$; the `data` chunk MUST NOT extend past EOF (`wav.rs:180-195`).
- `SampleKind` supports `U8 / I16 / I24 / I32` (`rust/src/stego/audio/sample.rs:17-26`, `:64-76`): 8-bit unsigned, and 16 / 24 / 32-bit signed little-endian two's complement; there is no `U16` variant (WAV 16-bit integer PCM is always signed). `from_bits` accepts only $bits \in \{8, 16, 24, 32\}$; other representations return `UnsupportedFormat` (`sample.rs:64-76`). A slot value of 0 indicates the sample's LSB is 0, and 1 indicates LSB is 1; writing inverts the LSB (16/24-bit are signed two's complement little-endian; 24-bit samples are sign-extended to i32 prior to arithmetic) (`sample.rs:84-126`, `core.rs:288-320`).

$total\_slots = data\_len / bytes\_per\_sample$, indexed in file-interleaved channel/sample order (`rust/src/stego/audio/wav.rs:60-63`). In 16-bit stereo, both 16-bit channel components form independent slots; in 24-bit audio, each 3-byte sample component forms an independent slot. Slot granularity is per-channel sample component, not `block_align`.

### 3.2 Slot Planning
WAV uses `Mapping::Permuted`: $perm = KeyedPermutation(locate\_seed, total\_slots)$ (`rust/src/stego/audio/core.rs:219-223`, `:711-714`). Slot mappings:

```text
header_i    = perm.at(i)                    for i < 512
extension_i = perm.at(512 + i)              for i < 8 * ext_len
body_i      = perm.at(512 + 8*ext_len + i)  for i < body_slots
```

(`rust/src/stego/audio/core.rs:234-255`). Body slot count: $body\_slots = total\_slots - (512 + 8 \cdot ext\_len)$, encompassing all slots not claimed by header or extension. Header and extension positions are fixed before the body is populated, enabling readers to decode base headers without prior knowledge of $ext\_len$.

**Note**: This permutation uses L2 `locate_seed`, not L3 `perm_seed` (`core.rs:711-714`). L3 `perm_seed` serves exclusively as direction flip salt (§6.2).

---

## 4. FLAC

### 4.1 Parsing and Slot Classification
- The STREAMINFO block MUST be the first metadata block with length 34B; supports bit depths 4..=24-bit; `total_samples` and stream MD5 are read from STREAMINFO (`rust/src/stego/audio/flac/mod.rs:122-181`, `:187-212`; `mod.rs:158-174`).
- The carrier MUST decode fully; non-zero STREAMINFO MD5 mismatches with decoded PCM MD5 are rejected (`flac/mod.rs:454-464`).
- Slots are classified into two structural types (`rust/src/stego/audio/flac/frame.rs:700-747`):
  1. **Subframe Tail**: The final residual symbol in each subframe satisfying Rice $k \ge 1$, $fold \gg k \ge 1$, with valid $\pm 1$ mobility; allocated to header and extension pools.
  2. **Body Residual Slots**: Residual symbols possessing complete compensation chains ($index + order + 1 < len$) where shifts can be offset by subsequent residual multiples; allocated to body pools. Structural validity is checked; non-movable slots remain in the candidate set and are bypassed by STC (`flac/mod.rs:626-641`).

### 4.2 `thin_pick` Sampling
Uniform thinning function for header/extension selection (`rust/src/stego/audio/flac/mod.rs:827-841`):

```text
thin_pick(index, range, wanted, phase):
    if wanted == 0 or range == 0: return false
    phase = phase mod range
    before = (u128(index)     * wanted + phase) / range
    after  = (u128(index + 1) * wanted + phase) / range
    return after != before
```

### 4.3 Header and Extension Extraction
`pick_tails` (`flac/mod.rs:848-879`):
- Header: `index` traverses all subframe tails in file order, $range = tail\_total$, $wanted = 512$, $phase = u64le(locate\_seed[0..8])$.
- Extension: Unselected tails are reindexed $n$, with $range = tail\_total - 512$, $wanted = 8 \cdot ext\_len$, $phase = u64le(locate\_seed[8..16])$.
- Selected tails retain original file order, filling the first $512 + 8 \cdot ext\_len$ entries of the slot buffer. Hence $header\_i = i$, $extension\_i = 512 + i$ (`core.rs:237-246`).

### 4.4 Body Extraction and Permutation
$base = u64le(locate\_seed[16..24])$ (`rust/src/stego/audio/mod.rs:86-91`). For each embedding attempt:

```text
body_phase = u64le(SHA-256("strhide-v4-flac-body-phase"
                           ‖ u64le(base) ‖ salt ‖ nonce)[0..8])
```

(`audio/mod.rs:106-114`). Body slots are sampled uniformly across all structural residuals ($analysis.slots$) (`flac/mod.rs:634-640`):

```text
thin_pick(index, analysis.slots, body_slots, body_phase)
```

Selected candidates are packed in file order, then permuted via $perm = KeyedPermutation(locate\_seed, body\_n)$:  
$body\_i = (512 + 8 \cdot ext\_len) + perm.at(i)$ (`audio/core.rs:224-253`, `:831-855`), with $body\_n = body\_slots$. **The reference implementation uses L2 `locate_seed`, not L3 `perm_seed`**.

### 4.5 Retries
Allows up to 6 retry attempts (`FLAC_EMBED_ATTEMPTS = 6`, `audio/mod.rs:96`, `:208-245`). Each attempt clones from the original carrier, re-rolling `salt`, `nonce`, and `body_phase`; retries occur exclusively on `DeadGroup` / `DeadElement`, whereas other errors abort immediately. Exhausting 6 attempts returns `FLAC embedding exhausted its retry budget` (`audio/mod.rs:118-126`, `:256-263`). Decoded waveforms are validated against drift after each write: $DRIFT\_BUDGET = 2$ quantization steps (`flac/mod.rs:91`, `audio/mod.rs:248-254`).

---

## 5. `pre_salt`

Both formats digest invariant header metadata; PCM sample bytes and checksums **never enter** the digest. `hpos_salt` is supplied by the format profile (WAV: `b"strhide-audio-hpos-salt-v1"`, FLAC: `b"strhide-flac-hpos-salt-v1"`, `rust/src/stego/format.rs:283-300`).

WAV (`rust/src/stego/audio/mod.rs:58-68`), integers formatted as Big-Endian:

```text
pre_salt = SHA-256(hpos_salt ‖ "wav-v4" ‖ u16be(channels) ‖ u32be(sample_rate)
                   ‖ u16be(block_align) ‖ u16be(bits) ‖ u32be(data_len))
```

FLAC (`:75-83`):

```text
pre_salt = SHA-256(hpos_salt ‖ "flac-v4" ‖ u32be(sample_rate)
                   ‖ u8(channels) ‖ u8(bits_per_sample) ‖ u64be(total_samples))
```

FLAC's stream MD5 is explicitly excluded because it is recalculated after embedding; including it would desynchronize reader and writer keys (`:70-83`). WAV includes `data_len` as u32.

---

## 6. Capacity, Costs, and Tier I Details

### 6.1 Capacity Formulas
`capacity_slots` and planning denominators differ between formats:

- WAV: $total = data\_len / bytes$; $available = total - (512 + 8 \cdot ext\_len)$.
- FLAC: Header and extension slots are sampled from disjoint tail pools, **without consuming body budget**; $body\_header\_slots = 512$, $capacity\_slots = total\_usable + 512$, meaning $available = total\_usable$ (usable movable residuals), while body sampling denominator remains the structural pool $analysis.slots$ (`flac/mod.rs:886-892`, `:566-590`). Total slot array size equals $512 + 8 \cdot ext\_len + body\_n$.

Payload capacity conversion (`rust/src/stego/audio/core.rs:350-367`):

```text
ciphertext_bits = u * (slots / u) - (h - 1)   # STC
max_payload     = ciphertext_bits / 8 - 22    # BODY_OVERHEAD
```

$max\_body\_slots(h, u)$ is capped by the 768 MiB working set budget ($MAX\_WORKING\_SET\_BYTES = 768 \times 1024 \times 1024$), governed by payload size rather than file size, permitting $\approx 1 \text{ MiB}$ payloads at $h = 8$ (`core.rs:62-69`, `:371-374`). Capacity safety tiers correspond to 0.5%, 1.5%, and 3% modification thresholds (`:71-88`).

### 6.2 Cost Models and Direction Salt (Tier I)
Each slot cost evaluates as $1 / (\text{epsilon} + \text{rms} + 0.5 \cdot d_1)$, where $\text{rms}$ evaluates across a $\pm 16$ slot window, $\text{epsilon} = 10^{-3}$, and digital silence ($\text{rms} < 10^{-7}$ and $d_1 < 10^{-7}$) assigns $10^6$ (`rust/src/stego/audio/cost.rs:31-51`, `:94-129`). Costs govern writer STC encoding only and are never reconstructed by readers (`cost.rs:24-29`).

Direction salt takes the first 8 bytes of L3 `perm_seed` (Big-Endian): $dir\_salt = u64be(perm\_seed[0..8])$ (`core.rs:836`). The base header uses $dir\_salt$, extension uses $dir\_salt \oplus \text{0x5DEE\_CE66}$, and body uses $dir\_salt \oplus \text{0xA5A5\_5A5A}$ to drive `direction_flip` (`core.rs:843-876`, `:280-286`). Modification direction does not affect readers, altering writer statistics and baselines only.

### 6.3 Writer Tier I Boundaries
Writers modify slots via $\pm 1$, clamping WAV samples at numerical boundaries; FLAC ensures waveform drift $\le 2$ via compensation chains. Slot planning, STC matrices, and direction selection may run concurrently or via SIMD, provided scalar equivalence is preserved.

---

## 7. Self-Verification and Baselines

Readers validate the following prior to decoding body data:

1. 64B header CRC32 passes, $format\_id \in \{2, 3\}$, $codec\_id = 1$, suite is supported, and $body\_len \in [BODY\_OVERHEAD, HEADER\_LEN\_MAX]$; otherwise return `CorruptedData` / `UnsupportedFormat`.
2. WAV: `RIFF/WAVE` header, PCM format tags, $block\_align = channels \times bytes$, and `data` boundary integrity (`wav.rs:102-195`).
3. FLAC: STREAMINFO is first block and spans 34B, $bits \le 24$, decoded PCM MD5 matches STREAMINFO (`flac/mod.rs:122-181`, `:454-464`).
4. FLAC post-embed verification recalculates CRC16 and MD5, rejecting outputs that exceed drift budget (`flac/mod.rs:760-783`, `audio/mod.rs:248-254`).

Regression criteria: `python scripts/baseline_hash.py --check` passes completely; audio concurrency verification via `cargo run --release --all-features --example audio_stress`.
