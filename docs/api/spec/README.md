# strhide Wire Format Specification (Overview and Index)

> Scope: `strhide` 0.9.x (Wire format: Structural domain **UBE v2**, Content domain **V4 Content Envelope**).  
> This directory contains **normative specifications**, intended to enable third parties to implement fully interoperable readers and writers without inspecting the Rust source code.  
> Reference implementation: `rust/src`; see [../ARCHITECTURE.md](../ARCHITECTURE.md) for module responsibilities, and [../STEGO-API.md](../STEGO-API.md) for public APIs.

---

## 0. Document Map

### Common Layer

| Document | Topic |
|---|---|
| [CRYPTO.md](./CRYPTO.md) | Dual-domain key derivation, HKDF labels, AEAD, AAD, stealth masks, PE channel header mask |
| [DETMATH.md](./DETMATH.md) | Normative definitions of deterministic floating-point math library (`exp`/`ln`/`ln_1p`/`cos`/`log2`) |
| [CAPACITY.md](./CAPACITY.md) | Dual-domain capacity formulas, extension slots, working memory budgets, and all operational limits |

### Content Domain (`embed` / `extract`)

| Document | Topic |
|---|---|
| [CONTENT-ENVELOPE.md](./CONTENT-ENVELOPE.md) | Micro-header, three base header layouts, flags/TLV, slot model, ChaCha12/permutation, STC, failure semantics |
| [CONTENT-PNG.md](./CONTENT-PNG.md) | PNG pixel slots, HILL / S-UNIWARD / MiPOD cost models, candidate sorting |
| [CONTENT-JPEG.md](./CONTENT-JPEG.md) | JPEG DCT grid, superblocks, UERD / J-UNIWARD / J-MiPOD, ternary STC |
| [CONTENT-HEVC.md](./CONTENT-HEVC.md) | HEVC/HEIF CABAC sign bit slots, banding, linear permutation, windows, and race prevention |
| [CONTENT-AUDIO.md](./CONTENT-AUDIO.md) | WAV PCM sample domain, FLAC residual domain, Feistel permutation, thin_pick, retry loop |

### Structural Domain (`write` / `restore`)

| Document | Topic |
|---|---|
| [STRUCTURE-ENVELOPE.md](./STRUCTURE-ENVELOPE.md) | UBE v2: 112B header, hint, meta, chunked payload, 24B trailer, stealth, PE ChannelHeader |
| [STRUCTURE-PNG.md](./STRUCTURE-PNG.md) | PNG `prIv` chunk injection |
| [STRUCTURE-JPEG.md](./STRUCTURE-JPEG.md) | JPEG APP segment injection |
| [STRUCTURE-RIFF.md](./STRUCTURE-RIFF.md) | WAV / WebP RIFF chunk injection |
| [STRUCTURE-ISOBMFF.md](./STRUCTURE-ISOBMFF.md) | MP4/MOV and HEIF/HEIC box / item injection |
| [STRUCTURE-ZIP.md](./STRUCTURE-ZIP.md) | ZIP injection before Central Directory |
| [STRUCTURE-PDF.md](./STRUCTURE-PDF.md) | PDF incremental update injection |
| [STRUCTURE-PE.md](./STRUCTURE-PE.md) | PE overlay / codebits / slack |
| [STRUCTURE-MKV.md](./STRUCTURE-MKV.md) | Matroska/WebM EBML Void injection |

Historical documents (**non-normative**, links and old section numbering preserved for reference): [../WIRE_SPEC_CONTENT.md](../WIRE_SPEC_CONTENT.md), [../WIRE_SPEC_STRUCTURE.md](../WIRE_SPEC_STRUCTURE.md). When this specification conflicts with older documents, **this directory takes precedence**; see [CORRECTIONS.md](./CORRECTIONS.md) for a summary of known differences.

---

## 1. The Two Steganographic Domains

`strhide` defines **two mutually incompatible envelope schemes** with isolated key derivation domains that cannot be cross-read.

| Dimension | Structural Domain (`write` / `restore`) | Content Domain (`embed` / `extract`) |
|---|---|---|
| Envelope | UBE v2: `112B header` + hint + meta + chunked payload + `24B trailer` | Key-derived base header (Spatial 64B / JPEG 44B / HEVC 32B) + optional TLV + single AEAD body |
| Static Signatures | Fixed 8B header magic + 4B trailer magic (password-derived in stealth mode) | No fixed magic; `magic4` is derived via L2 |
| Endianness | **Little-endian** | Multi-byte fields are **Big-endian** (`sigma` is the exception: f32 LE) |
| Payload | Chunked AEAD; each chunk has a `u32 LE` length prefix; chunk AAD contains index/is_last | One-shot AEAD, unchunked |
| Metadata | Filename, original size, SHA-256, creation time (independent AEAD block) | Micro-header inside ciphertext: 4B original length + 1B flags + filename |
| Cover Restoration | Supports bit-for-bit `restore` (records cover size + SHA-256) | **Irreversible**; cover pixels/coefficients are altered and cannot be recovered |
| Passwordless Default Key | `BUILTIN_DEFAULT_KEY` | `PUBLIC_DEFAULT_SECRET` |
| Compression | raw deflate; `Auto` requires saving ≥ 2% | raw deflate; retained only if strictly smaller than plaintext |

Derivation labels, AADs, or default keys must never be mixed across the two domains. Any cross-read must return "no hidden data".

---

## 2. Normative Conventions

### 2.1 Language and Conformance

- **MUST / MUST NOT**: Strict requirements necessary for interoperability; **SHOULD / SHOULD NOT**: Recommended defaults from which implementations may deviate if documented.
- All constants, field offsets, and formulas provide references to the reference implementation (`rust/src/...:line`). These locations serve as **evidence**, not normative specifications; line numbers may drift as the codebase evolves.
- De facto behaviors of the current reference implementation are explicitly labeled **Tier I** (see §2.3): they describe how the reference implementation writes bytes, but reader implementations MUST NOT depend on them.

### 2.2 Endianness and Bit Ordering

- Structural Domain: **Little-endian** across all fields unless explicitly noted otherwise (header / trailer / meta / chunk lengths).
- Content Domain: Base header and HKDF info multi-byte fields are **Big-endian**; the `sigma` field is **f32 little-endian**.
- Bit Packing: Byte-internal bit ordering is **MSB-first** (bit 7 is the first slot/message bit), unless a structure explicitly specifies LSB-first.
- CRC: Both domains use **CRC32-IEEE** (reflected polynomial `0xEDB88320`, initial value `0xFFFFFFFF`, inverted output).

### 2.3 Stability Tiers

| Tier | Meaning | Impact of Changes |
|---|---|---|
| **F (Frozen)** | Written carriers depend on it | Any change renders existing carriers unreadable; changes before 1.0 require explicit tracking as breaking changes |
| **D (Dialect)** | Substitutable via compile-time profiles/labels | Does not corrupt official carriers, but produces an isolated dialect unreadable by official builds |
| **I (Implementation Freedom)** | Affects writing behavior only, not readability | Readers do not depend on it; free to optimize as long as byte-level baselines protect repository output |

**Prior to 1.0, any Tier F specification remains subject to change.** Versioning policy:

- `CipherSuiteId`, `strategy_id`, `format_id`, `algorithm_id`, and TLV `type_id` are **append-only**: new values may be added, but existing semantics cannot be altered.
- Version fields (`version`, `CURRENT_VERSION`, `compact meta version`, `CHANNEL_VERSION`) are strictly monotonically increasing; unrecognized versions fail-closed.
- No legacy read paths are provided (pre-release project). Reading an unsupported version MUST return an explicit "unsupported version" or absence of data rather than guessing layouts.

### 2.4 Reference Implementation Scope

- Carrier quality evaluation and estimation in the `analysis` module still use host `libm`, and **do not participate in byte-level output**; all floating-point math affecting output bytes MUST follow [DETMATH.md](./DETMATH.md).
- SIMD utilization, parallelization strategies, compression levels, and retry loops in the reference implementation belong to Tier I; readers MUST NOT rely on specific choices.
- This specification does not claim that bit-for-bit equivalence with the reference implementation is required for interoperability; the test for interoperability is **the ability to correctly read and extract legitimate carriers written by the counterpart**. Byte-level baselines exist strictly to guard this repository's own consistency.

---

## 3. Third-Party Implementation Roadmap (Recommended Order)

1. Read [CRYPTO.md](./CRYPTO.md); implement Unicode NFC normalization, PBKDF2, HKDF, AES-256-GCM, and ChaCha20-Poly1305.
2. Select target domain:
   - Content domain: Read [CONTENT-ENVELOPE.md](./CONTENT-ENVELOPE.md) → Carrier-specific document → [DETMATH.md](./DETMATH.md) → [CAPACITY.md](./CAPACITY.md);
   - Structural domain: Read [STRUCTURE-ENVELOPE.md](./STRUCTURE-ENVELOPE.md) → Format adapter document → [CAPACITY.md](./CAPACITY.md).
3. Implement **extraction** first (reconstruct keys, slots, and syndrome decoding), followed by embedding/writing.
4. Verify using known test vectors: ChaCha12 reference vectors, the five detmath digest values, and carrier slot/cost test vectors (where provided).

---

## 4. Terminology

| Term | Meaning |
|---|---|
| UBE | Unified Binary Envelope (Structural domain envelope) |
| Base Header / Superblock | Carrier-dependent header in content domain (Spatial 64B, JPEG 44B, HEVC 32B) |
| Slot | A mutable parity bit in the carrier (byte bit, DCT coefficient parity, PCM LSB, CABAC sign bit, etc.) |
| Candidate Pool | The set of carrier positions satisfying eligibility rules to carry slots |
| Permutation | Slot pseudorandom reordering keyed by seed; not encryption, but unpredictable without key |
| STC | Syndrome Trellis Coding, matrix coding; reading side only computes syndromes |
| Pre-salt (`pre_salt`) | KDF salt constructed solely from invariant carrier metadata (before and after embedding) |
| Dialect / Profile | An isolated wire format generated by substituting labels, salts, or parameters at compile time |
| L1 / L2 / L3 | Three-tier content domain keys: Locating Master Key, Locating Key, and Session Key |

---

## 5. Documentation Maintenance Rules

- Whenever adding `format_id`, `strategy_id`, TLV, derivation labels, slot rules, or cost models, update the corresponding topic specification and errata status in [CORRECTIONS.md](./CORRECTIONS.md).
- Any change to Tier F algorithms constitutes a wire format change, requiring synchronized updates to byte-level baselines and changelogs.
- `file:line` citations reflect the reference implementation; if code and documentation conflict, update the documentation to match code and record the deviation in [CORRECTIONS.md](./CORRECTIONS.md).
