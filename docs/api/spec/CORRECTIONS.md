# Errata and Migration Log for Legacy WIRE_SPEC (2026-11-07)

This document records inaccuracies identified in legacy documentation against the **current `rust/src` implementation** during the modularization of `docs/api/WIRE_SPEC*.md`.  
The specifications located in `docs/api/spec/` are normative; older documents are retained strictly for historical reference and are no longer maintained.

- Legacy [WIRE_SPEC_CONTENT.md](../WIRE_SPEC_CONTENT.md) and [WIRE_SPEC_STRUCTURE.md](../WIRE_SPEC_STRUCTURE.md) have been flagged with deprecation banners.
- In the Status column, "Corrected" indicates that the new specification describes the actual code behavior; "Recorded" indicates an implementation characteristic or limitation documented informatively.

---

## A. Content Domain: Key Derivation and Envelope

| # | Legacy Description | Actual Implementation | New Location | Status |
|---|---|---|---|---|
| A1 | HEVC `session_salt` = 12B base header `nonce` (CONTENT:250) | `SHA-256("strhide-hevc-session-v4" ‖ nonce)` (32B) `hevc/engine.rs:452-457` | CRYPTO §1.6 | Corrected |
| A2 | HEVC `pre_salt = cover_salt ‖ "hevc-v4" ‖ parameter_sets`, pointing to `carrier_identity` (CONTENT:208) | Container: `... ‖ u64be(ps_count) ‖ Σ(u64be(len) ‖ bytes)`; Annex-B: `... ‖ u64be(span_count) ‖ parameter set NAL / VCL 2B header + u64be(nal_len)` (`hevc/engine.rs:4272-4288`, `bitstream.rs:192-211`) | CRYPTO §1.4 / CONTENT-HEVC §7 | Corrected |
| A3 | JPEG `pre_salt` `block_count` left undefined (CONTENT:205) | Number of 8×8 blocks in component 0 (`jpeg/engine.rs:246`) | CRYPTO §1.4 | Corrected |
| A4 | Domain fallback precedence: "Explicit > Profile > Official default string" (CONTENT:140) | Third tier is `None`, info contains label only (`stego/params.rs:987-989`, `format.rs:521-533`) | CRYPTO §1.2 | Corrected |
| A5 | "`salt(16B) / nonce(12B)` reside exclusively in carrier header" (CONTENT:156) | HEVC 32B header only stores 12B nonce, without 16B salt (salt is hash-derived) | CONTENT-ENVELOPE §3.3 | Corrected |
| A6 | "`format_id` and certain implicit fields are not stored" (CONTENT:519) | PNG/WAV/FLAC headers store and validate `1..=3` at offset 34; only JPEG/HEVC omit it implicitly (`stego/header.rs:190, 271, 306, 326-330`) | CONTENT-ENVELOPE §3 | Corrected |
| A7 | Envelope flags omit mandatory validation checks (CONTENT:152) | Bits 4..7 MUST be 0; compression algorithm ID MUST be 0 when uncompressed (`stego/envelope.rs:504-552`) | CONTENT-ENVELOPE §2 | Corrected |
| A8 | Header validation lists only "length / version / CRC / suite" (CONTENT:803) | Also enforces `format_id` match, `algorithm_id` range, `codec_id` 0/1, audio `channel_mode / class_rule = 0`, and `body_len ≥ 22` (`header.rs:326-362`) | CONTENT-ENVELOPE §3 | Corrected |
| A9 | Type 0 padding: "values MUST be all zeros and are skipped" (CONTENT:591) | From type 0 onward, remaining extension bytes MUST be strictly 0 to the end and terminate; otherwise `CorruptedData` (`header.rs:117-146`) | CONTENT-ENVELOPE §4.2 | Corrected |

---

## B. Content Domain: PRNG, Permutations, STC, and Slots

| # | Legacy Description | Actual Implementation | New Location | Status |
|---|---|---|---|---|
| B1 | STC column vector uses `splitmix64(seed XOR idx)` (CONTENT:484) | `splitmix64(seed.wrapping_add(idx))` (`coding/stc.rs:355`) | CONTENT-ENVELOPE §7.2 | Corrected |
| B2 | ChaCha test vector first 16 bytes written as `12 05 6e 59 5d 56 b0 f6 ...`; seed stated as "first byte 1" but example wrote `00 01 ...` (CONTENT:290-300) | Correct first row is `12 05 6e 59 d5 65 05 6b ef 0e 0f 09 df 5c 22 9a`; seed = `01 00 ... 00` (`prng.rs:301-327`) | CONTENT-ENVELOPE §6.1 | Corrected |
| B3 | Uniform slot ordering: "select N candidates then permute; permuting whole pool then taking prefix forbidden" (CONTENT:384) | Differs per carrier: PNG selects N then calls `permute_indices`; JPEG calls `permute_prefix` over full BodyGrid then truncates; Audio applies `KeyedPermutation` over whole/body pool | CONTENT-ENVELOPE §5, carrier specs | Corrected |
| B4 | FLAC body permutation uses L3 `perm_seed` (CONTENT:459) | Uses L2 `locate_seed`; `perm_seed` serves solely as direction salt (`audio/core.rs:224-253, 831-855`) | CONTENT-AUDIO §4.4 | Corrected |
| B5 | FLAC capacity debited as `total_slots - (512 + 8 * ext_len)` (CONTENT:615) | Extension slots do not preempt residual pool; capacity evaluates as `total_usable + 512` (`flac/mod.rs:886-892`) | CAPACITY §2.4 | Corrected |
| B6 | WAV "slot = one PCM sample" (CONTENT:433) | Each audio channel component forms an independent slot (16/24-bit per-channel components) | CONTENT-AUDIO §3 | Corrected |
| B7 | Audio supports only 16/24-bit (CONTENT:813) | WAV supports 8/16/24/32-bit; FLAC supports 4..=24-bit | CONTENT-AUDIO §1 | Corrected |
| B8 | HEVC body parameters fixed to $h=7, u=2$; header `stc_u` redundant (CONTENT:420, 869) | Reader constructs trellis using header `stc_u` (`hevc/engine.rs:2249`); only `stc_h` comes from profile | CONTENT-HEVC §6 | Corrected |
| B9 | HEVC banding determined by "unpredictable markers" (CONTENT:424) | Determined by `nal_unit_type` + `has_inter`; IRAP/RASL carry zero slots (`hevc/engine.rs:4109-4119`) | CONTENT-HEVC §4 | Corrected |
| B10 | HEVC slots indexed uniformly by decode order | Header pool uses decode-order prefix; body pool is reindexed per band0 + band1 (`band.start`) | CONTENT-HEVC §3-4 | Corrected |
| B11 | `max_payload = message_bits / 8 - 22`, omitting $u$ factor (CONTENT:611) | $m = \lfloor n/u \rfloor - (h - 1)$ (`coding/stc.rs:390-392`) | CAPACITY §1 | Corrected |
| B12 | Working memory budget lists only PNG 8 GiB (CONTENT:627) | JPEG also has 8 GiB; WAV/FLAC has 768 MiB (`jpeg/engine.rs:100`, `audio/core.rs:69`) | CAPACITY §2.6 | Corrected |
| B13 | Long video "weighted estimate across first 20% window" (CONTENT:631) | Samples 20% across selectable pictures and clamps to `[150, 1000]`; $\le 150$ performs full scan (`hevc/engine.rs:727-735`) | CAPACITY §2.7 | Corrected |

---

## C. Content Domain: Cost Models and detmath

| # | Legacy Description | Actual Implementation | New Location | Status |
|---|---|---|---|---|
| C1 | Grayscale conversion evaluates directly as `0.299R + ...` (CONTENT:656) | All three channels masked with `& 0xF8` prior to weighting (`png/cost/hill.rs:68-71`, etc.) | CONTENT-PNG §5 | Corrected |
| C2 | `val mod 8 ∈ [1, 6]` applied unconditionally (CONTENT:398) | Reader checks header `class_rule`, executing only when `= 1`; writer sets 1 (`png/engine.rs:1359, 1721, 2141`) | CONTENT-PNG §3 | Corrected |
| C3 | `sigma` used exclusively by S-UNIWARD (CONTENT:684) | Under MiPOD, same field conveys `alpha`; writer clamps to `[0.01, 0.90]`, default `0.20f32` (`png/engine.rs:1678-1691, 2069-2077`) | CONTENT-PNG §2 / §7 | Corrected |
| C4 | Body slot count uses `slots_for`, ignoring `codec_id` (CONTENT:400) | `slots_for_codec(...)`; Hamming and STC require different slot counts (`png/engine.rs:1577, 2117-2122`) | CONTENT-PNG §3 | Corrected |
| C5 | "$u=1$ and Hamming consume no cost" (CONTENT:743) | Candidate set is still selected and truncated via cost sorting; only the trellis omits directional edge costs | CONTENT-PNG §8 | Corrected |
| C6 | Pipeline depends on host libm `cos/exp/ln` (CONTENT:723), contradicting §13.11.5 | All operations invoke `stego::detmath` (`cost_calibration.rs:163-174, 216`) | DETMATH §1 | Corrected |
| C7 | `ln` series evaluated to $z^{10}/21$ (CONTENT:757) | Evaluated to $z^{11}/23$ (`detmath.rs:197-207`) | DETMATH §4 | Corrected |
| C8 | `ln_1p` precision claimed as ~1 ulp (CONTENT:758) | Audit found corpus maximum 6.91 ulp, dense sample maximum 16.6360 ulp | DETMATH §5 | Corrected |
| C9 | "Four digest groups" (CONTENT:785) | Five items: `exp / ln / cos / ln_1p / log2` (`detmath.rs:415-421`) | DETMATH §9 | Corrected |
| C10 | Python and Go port only four functions (CONTENT:984) | Both scripts implement all five including `log2` | DETMATH §9 | Corrected |
| C11 | Bit-for-bit consistency claimed across all three platforms (CONTENT:765, 785) | Audit: 20 mismatches out of 52,153 inputs; substantial divergence when Go enables FMA | DETMATH §9 | Corrected |
| C12 | JPEG base header slots fixed at 718 (CONTENT:413) | `header_slots(ext_len) = 718 + 4 * (8 * ext_len + 7)`; even with $\text{ext\_len} = 0$, evaluates to 746 (`jpeg/engine.rs:833`, `format.rs:156-169`) | CONTENT-JPEG §3 | Corrected |
| C13 | JPEG blocks ordered by "raster order within component" | `dct_io` returns MCU interleaved order (in 4:2:0, block index 2 lies below index 1) | CONTENT-JPEG §3 | Corrected |
| C14 | JPEG uses `exclusion_permille` sorting truncation | JPEG 44B header has no such field; costs feed solely into trellis edge weights | CONTENT-JPEG §4 | Corrected |
| C15 | J-MiPOD shares identical parameters with Spatial MiPOD | JPEG uses $p=3, l=3$, $\text{floor}=10^{-6}$, and skips 7×7 FI smoothing (`jmipod.rs:30-34`) | CONTENT-JPEG §7 | Corrected |
| C16 | Content domain supports "bit-for-bit JPEG restoration" | Only the structural domain supports restore; JPEG entropy-coded scan segments are rewritten (`dct-io`) | CONTENT-JPEG §9 | Corrected |

---

## D. Structural Domain: UBE Envelope

| # | Legacy Description | Actual Implementation | New Location | Status |
|---|---|---|---|---|
| D1 | Header validation lists only version / length / displacement (STRUCT:125-132) | Also checks registered `strategy_id`, valid `inject_size` shape, and $\text{patch\_offset} + 4 \le \text{host\_len}$ (`envelope.rs:294-346`) | STRUCTURE-ENVELOPE §3.2 | Corrected |
| D2 | Append strategies require $\text{ube\_offset} + \text{size} == \text{file length}$ (STRUCT:154) | `confine_location` checks $\le$; `locate_start` allows global relocation (`engine.rs:191-207, 870-879`) | STRUCTURE-ENVELOPE §12 | Corrected |
| D3 | Reserved bits must be 0 enforced by `validate_against` (STRUCT:176) | Enforced solely by raw header gate checking `flags & !0x3F` (`envelope.rs:675-689`) | STRUCTURE-ENVELOPE §4 | Corrected |
| D4 | Reader uses "three-tier recognition" (STRUCT:404) | Uses four tiers; raw encrypted header is evaluated prior to default unmasking (`envelope.rs:615-648`) | STRUCTURE-ENVELOPE §11 | Corrected |
| D5 | Default unmasking tier requires `version = 0x02` (STRUCT:409) | Does not check version at that stage; requires `strategy_id` $\in [1, 13]$ (`envelope.rs:622-648`) | STRUCTURE-ENVELOPE §11 | Corrected |
| D6 | Single chunk capped at $\min(\text{remaining}, \text{MAX\_CHUNK\_SIZE})$ (STRUCT:301) | $\min(\text{remaining}, \text{MAX\_CHUNK\_SIZE} + 16)$ (chunk length includes tag) (`crypto.rs:581-588`) | STRUCTURE-ENVELOPE §8 | Corrected |
| D7 | Invalid trailer uniformly signals "no envelope" (STRUCT:318) | If magic matches but CRC fails, returns `CorruptedData` (`envelope.rs:844-858`) | STRUCTURE-ENVELOPE §9 | Corrected |
| D8 | `MIN_UBE_PLAIN = 178` / `MIN_UBE_ENCRYPTED = 214` (STRUCT:502) | Constants do not exist; `min_ube_len(0) = 213`, `min_ube_len(1) = 214` (`envelope.rs:116-132`) | STRUCTURE-ENVELOPE §2 | Corrected |
| D9 | Stealth header mask HKDF omits salt (STRUCT:379-381) | `HKDF-SHA256(salt=Some(envelope_salt), ikm=PBKDF2(...))` (`crypto.rs:305-312`) | CRYPTO §2.4 | Corrected |
| D10 | Scattered strategy skips coordinate checks when `inject_size == 0` (STRUCT:146) | Requires caller strategy name and header `strategy_id` to both be `pe_codebits` (`engine.rs:2835-2850`) | STRUCTURE-ENVELOPE §12 | Corrected |
| D11 | Hint read handling left unspecified | Read strictly according to `hint_len`, without validating `FLAG_HAS_HINT` (`engine.rs:1836-1844`) | STRUCTURE-ENVELOPE §6 | Corrected |
| D12 | Compact metadata lacks explicit validation list | `version = 0x01`, valid UTF-8 filename, immediate failure on truncation/out-of-bounds (`engine.rs:302-330`) | STRUCTURE-ENVELOPE §7 | Corrected |

---

## E. Structural Domain: Adapters

| # | Legacy Description | Actual Implementation | New Location | Status |
|---|---|---|---|---|
| E1 | PNG injection offset omitted | `prIv` chunk header is 8B; `inject_size = 8 + ube + 4` (including CRC) (`png.rs:189-214`) | STRUCTURE-PNG §4-5 | Corrected |
| E2 | JPEG structural domain uses COM segment (design doc) | Fixed to APP15; COM plays no role in injection or locating (`jpeg.rs:14-15, 530-551`) | STRUCTURE-JPEG §5 | Corrected |
| E3 | JPEG single segment 65,535 / 256 KiB forces eof | Single segment carries 65,533 payload; chained segments can exceed 256 KiB; capacity bounded by 16 MiB window and SOS | STRUCTURE-JPEG §6 | Corrected |
| E4 | RIFF `offset_delta` omitted | 8B `SHRD` chunk header (`wav.rs:100-104`, `webp.rs:118-122`) | STRUCTURE-RIFF §4 | Corrected |
| E5 | RIFF capacity expressed as "4GB limit" | Practically bounded by $R + 8 + N + (N \& 1) \le \text{u32::MAX}$ (`riff.rs:126-133`) | STRUCTURE-RIFF §6 | Corrected |
| E6 | ISO-BMFF injection point "after moov / before mdat" | Injected at physical EOF; `item_hidden` introduces a second `mdat` (`isobmff.rs:85-88, 1183-1192`) | STRUCTURE-ISOBMFF §4 | Corrected |
| E7 | HEIF item contains mime / hidden flags | Writes `infe` v2/v3, `item_type = "resv"`, empty name, protection index 0 (`isobmff.rs:961-984`) | STRUCTURE-ISOBMFF §4 | Corrected |
| E8 | ZIP defaults to `pre_cd_inject`; empty archive / ZIP64 / missing EOCD falls back to eof | Also falls back on `cd_offset == 0`, ZIP64 locator, or 32-bit overflow (`zip.rs:145-171`); detects locator without parsing EOCD64 | STRUCTURE-ZIP §3-5 | Corrected |
| E9 | PDF incremental segment always writes classic `xref` / `trailer` | XRef stream dialect writes `/Type /XRef` stream object (`pdf.rs:787-830`) | STRUCTURE-PDF §4 | Corrected |
| E10 | PDF `offset_delta` omitted | $46 + \text{digits}(N) + \text{digits}(L)$; two 10-digit numbers yield $66 > 64$, so `MAX_OFFSET_DELTA` was raised to 128 prior to 1.0 (`pdf.rs:589-591, 697-705`) | STRUCTURE-PDF §4 | Corrected |
| E11 | PE codebits covers ModR/M memory/SIB mutations | Restricted to $\text{mod} = 11$ register-to-register pairs and TEST operand swapping (`pe_codebits.rs:239-243`) | STRUCTURE-PE §5.1 | Corrected |
| E12 | `pe_slack` treated as scattered strategy with ChannelHeader | Sequential overwrite of section padding, with no ChannelHeader or diff bitmap (`pe_slack.rs:52-92`) | STRUCTURE-PE §6 | Corrected |
| E13 | PE restoration diff stored as "compact binary list" | Headerless fixed-length dense bitmap of size $14 + \text{ube\_len}$, MSB-first (`pe_codebits.rs:344-350, 446-448`) | STRUCTURE-PE §5.3 | Corrected |
| E14 | MKV inserts Void after SeekHead and updates Segment size | Appends top-level Void at physical EOF without modifying Segment, SeekHead, or Cues (`mkv.rs:79-99`) | STRUCTURE-MKV §4 | Corrected |
| E15 | EBML Void VINT spans up to 9 bytes | 1B Void ID + up to 8B VINT, hence $\text{offset\_delta} \le 9$ (`ebml.rs:28-36`, `mkv.rs:292-306`) | STRUCTURE-MKV §4 | Corrected |
| E16 | auto "transparently falls back to eof when capacity is insufficient" | Several adapters do not fall back: MP4 is always `box_uuid`, HEIF falls back from `item_hidden` to `box_uuid`, PNG falls back only beyond $2 \text{ GiB} - 1$ | STRUCTURE-ISOBMFF §3, STRUCTURE-PNG §3 | Corrected |

---

## F. Out-of-Scope Issues (Recorded / Resolved)

1. ~~`riff.rs` capacity reporting indicated `available = true` near 4 GiB despite actual injection failing due to RIFF size overflow (related to E5).~~  
   **Fixed (2026-11-08)**: `riff_strategy_capacities` computes `capacity_bytes = u32::MAX - declared_size - 8` via `riff_chunk_headroom()`, setting `available = false` when headroom is 0 (`tests/test_regression/review_20261025.rs::riff_chunk_capacity_reports_the_u32_headroom`).
2. ~~`webp.rs` static capacity table reported `riff_chunk` available for Simple Format; `engine.rs` did not verify `available`.~~  
   **Fixed (2026-11-08)**: When `reader = None`, note explicitly specifies "Extended Format (VP8X) only"; `apply_engine_payload_limit` skips entries with `available = false` (`webp_static_capacity_table_marks_the_extended_format_requirement`).
3. ~~`CAPACITY.md` and `ARCHITECTURE.md` auto strategy descriptions conflicted with non-fallback behaviors (E16).~~  
   **Corrected (2026-11-08)**: `ARCHITECTURE.md` §7.1 updated with format-specific `auto` decision table; `CAPACITY.md` §3.3 updated with MP4/MKV non-fallback clarifications.
4. ~~Comments at `detmath.rs:320, 352` referenced non-existent `scripts/detmath/compare.sh`.~~  
   **Corrected (2026-11-08)**: Comments updated to reference `scripts/detmath/detmath.py` / `detmath.go` and pinned Rust digests.
5. ~~Comments at `mkv.rs:113-117` stated `ebml_void` was relocatable while engine permitted only `chunk` / `eof`.~~  
   **Code evolved, comment verified**: `relocatable_strategy` whitelist includes `chunk` / `eof` / `ebml_void` (`engine.rs:2310-2312`).
6. Comments at `pe.rs:741-744` mention legacy `STH!` / `STHC`, which the implementation does not accept.

---

## G. Second-Round Audit Errata (2026-11-08)

Audited item-by-item against code and documented revisions:

| # | Document Description Prior to Revision | Actual Implementation | Revision Target |
|---|---|---|---|
| G1 | `CONTENT-AUDIO.md`: `SampleKind` included `U16` | Only `U8 / I16 / I24 / I32`; `from_bits` rejects all other bit depths (`audio/sample.rs:17-78`) | CONTENT-AUDIO §3.1 |
| G2 | `STEGO-API.md`: Retained `embed --capacity` alias; listed `--cipher-suite` as hidden | `--capacity` removed; capacity probing is a standalone `capacity` subcommand; `--cipher-suite` is public, with only `--slot-budget` and six tuning options hidden (`cli/args.rs:427-530`) | STEGO-API §6 |
| G3 | `smart_file_data_hiding_design.md`: Content envelope still described as `[salt][nonce][ciphertext]`; audio limited to 16/24-bit; JPEG injection wrote COM; chunked AAD formula missed `meta_len / hint_len / hint`; adapter table missed WEBP/WAV/HEIF/MKV; pre-v2 JSON layout retained; `offset_delta` written as 0..=64 | V4 envelope stores salt/nonce in base header and signs entire header as AAD; audio supports 8/16/24/32-bit; JPEG injects APP15; AAD total length is 97 + hint_len; 10 adapter classes; JSON layout rejected by reader; offset delta upper bound is 128 | design §3.2, §3.4, §3.5, §5, §6.1, §6.5 |
| G4 | Dual-domain stacking claimed "order-independent" | Stacking structural domain before content domain causes `restore` to fail with `RestoreMismatch` (fail-closed); only whitelisted strategies (`chunk` / `eof` / `ebml_void`) permit relocation | design §7, CLI_GUIDE §5.1, STRUCTURE-MKV §8, STRUCTURE-ENVELOPE §15.11 |
| G5 | Content domain spec omitted PNG `tRNS` (type 0/2) rejection and trailing data retention after `IEND` (16 MiB limit) | `png/engine.rs:295-311`, `:326-344` | CONTENT-PNG §1, CAPACITY §4 |
| G6 | Content domain spec omitted JPEG constraints: Baseline only, 1/3 components, MCU / Block / 8 GiB limits | `jpeg/engine.rs:68-128`, `:151-166` | CONTENT-JPEG §1 |
| G7 | Content micro-header omitted filename sanitization fallback to 0x00 / reader fallback to `extracted.bin`, and `--no-filename` effect | `envelope.rs:283-303`, `:318-335`, `:362-363`; `stego/engine.rs:491-496` | CONTENT-ENVELOPE §2.3 |
| G8 | Omitted MP4 `moov` 32 MiB limit | `hevc/engine.rs:2627-2631` | CONTENT-HEVC §1, CAPACITY §4 |
| G9 | PNG `stc_u=0(auto)` not clarified as writer-only enum; wire format requires `1..=3` | `header.rs:365-382` reader rejects 0 | CONTENT-PNG §2 |
| G10 | `STRUCTURE-PDF.md` retained legacy offset delta upper bound of 64 | `MAX_OFFSET_DELTA = 128` (`envelope.rs:88`, `engine.rs:1303-1310`) | STRUCTURE-PDF §5 |
| G11 | `STRUCTURE-RIFF.md` capacity reporting retained `capacity_bytes = None`; residual `MIN_UBE_PLAIN = 178` | Reports actual headroom dynamically; obsolete constants removed and replaced with `min_ube_len()` | STRUCTURE-RIFF §3, §6 |
| G12 | Cross-references in adapter specs cited frozen `WIRE_SPEC_STRUCTURE.md` §14/§15 as normative | Replaced with references to `STRUCTURE-ENVELOPE.md` and `CAPACITY.md` | Introductions of all STRUCTURE-*.md |
| G13 | Typographical error in Chinese terminology referring to micro-envelopes | Corrected across all affected documents | ARCHITECTURE, STRUCTURE-MKV, WIRE_SPEC_*, design |
