# CRYPTO: Key Derivation and AEAD (Content Domain V4 / Structural Domain UBE v2)

Applicable to `strhide` 0.9.3 (`rust/src`). Scope: Credentials, domain separation, L1/L2/L3 key derivation, nonces, AEAD AAD, and field masks across both envelopes; wire byte layout details are covered in dedicated envelope specifications.  
Navigation: [Specification Overview](./README.md) · [Content Domain Envelope](./CONTENT-ENVELOPE.md) · [Structural Domain Envelope](./STRUCTURE-ENVELOPE.md) · [Architecture and Public API](../ARCHITECTURE.md). References are written as `file:line` relative to the repository root.

---

## 0. Conventions and Stability

"MUST" indicates a strict requirement for interoperability. All hashes are SHA-256; HKDF refers to RFC 5869 HKDF-SHA256 (`L` = target byte count, `salt=None` defaults to 32 all-zero bytes per §2.2 of RFC 5869); PBKDF2 refers to PBKDF2-HMAC-SHA256 outputting 32 bytes. **Endianness differs across domains**: Content domain multi-byte fields are Big-Endian; Structural domain multi-byte fields are Little-Endian.

Stability Tiers: **F (Frozen)** (modifications break existing carriers and baseline hashes); **D (Dialect)** (substitutable via private profiles/constants, creating incompatible formats); **I (Implementation Freedom)** (affects writer details only). **Cross-version stability is not guaranteed prior to 1.0**: Tier F indicates that changes within this repository will immediately invalidate existing carriers and test baselines; third parties should pin their behavior to specific release tags.

---

## 1. Content Domain (V4 Content Envelope)

### 1.1 Credentials, NFC, and Default Keys (Tier F / Values Tier D)

- Two credential variants (`core/crypto.rs:121-127`): `Password(&str)` is normalized via NFC before running PBKDF2; `FileKey(&[u8;32])` serves directly as HKDF IKM, bypassing PBKDF2.
- Passwords and domain strings MUST undergo Unicode NFC normalization before entering derivation (`core/crypto.rs:180`); subsequent transformations like case-folding MUST NOT be performed.
- Credential precedence (`stego/options.rs:421-444`): Non-empty `password` and `key` are mutually exclusive $\to$ `key` $\to$ non-empty `password` $\to$ `StegoProfile.default_secret` (empty string = unconfigured, `stego/params.rs:982-984`) $\to$ `PUBLIC_DEFAULT_SECRET = "strhide-default-content-stego-key-2026"` (`stego/envelope.rs:62`). An empty string password MUST be treated as "not provided".
- Domain fallback (`stego/options.rs:705-712`): Explicit non-empty `domain` > `StegoProfile.domain` > **No domain**. The official default is "no domain" (not a fixed string); when no domain is configured, info consists solely of the label.

### 1.2 HKDF info Formatting (Tier F)

```text
info(label, domain) = label                                        when domain is None / empty string
                    = label ‖ u64be(len(NFC(domain))) ‖ NFC(domain) otherwise
```

Reference: `stego/format.rs:521-533` (`info_with_domain`), `stego/envelope.rs:133-151`. `len` is the byte length after NFC normalization; the length prefix MUST be retained to prevent collisions between `("ab", "c")` and `("a", "bc")`.

### 1.3 L1: Locating Master Key (Tier F)

```text
Password: p_nfc = NFC(p)
  With domain: ikm = HKDF-Expand(SHA256, salt=None, ikm=p_nfc, info=info(domain_label, domain), L=32)
  No domain:   ikm = UTF-8 bytes of p_nfc (unhashed)
  master = PBKDF2-HMAC-SHA256(pass=ikm, salt=pre_salt(32B), iter=200_000, dkLen=32)

FileKey k[32]:
  master = HKDF-Expand(SHA256, salt=pre_salt(32B), ikm=k, info=info(domain_label, domain), L=32)
```

Reference: `stego/format.rs:433-465`; iteration count `CONTENT_L1_PBKDF2_ITERATIONS = 200_000` (`core/crypto.rs:114`). Note that the password for PBKDF2 is the HKDF output when a domain is present; the salt is always `pre_salt`. `max_pbkdf2_iterations` defaults to 200,000 (`stego/params.rs:758-772`); readers reject values below this threshold.

### 1.4 Carrier Identity `pre_salt` (Tier F; Public Salt Constants Tier D)

All produce SHA-256 $\to$ 32B; multi-byte fields are Big-Endian.

| Carrier | Formula (`‖` denotes sequential concatenation) | Reference |
|---|---|---|
| PNG | `hpos_salt ‖ "png-v4" ‖ u64be(w) ‖ u64be(h) ‖ [bit_depth, color_type, channels] ‖ meta_digest`; `meta_digest = SHA-256` over each **critical chunk**: `ty(4B) ‖ u32be(len) ‖ data` (file order); excludes `IDAT` / `prIv`, and excludes all ancillary chunks (lowercase first letter: `tEXt` / `zTXt` / `iTXt` / `tIME` / `eXIf` / `iCCP` / `gAMA` / `sRGB` / `pHYs` ...), so only `IHDR` / `PLTE` / `IEND` participate. Ancillary chunks are metadata frequently modified by third-party tools; including them in the salt would render payloads unrecoverable upon any metadata edit (fixed 2026-11-07). | `stego/png/engine.rs:1155-1204` |
| JPEG | `cover_digest_tag ‖ "jpeg-v4" ‖ cover_digest`; `tag = b"strhide-cover-v1"` (`stego/format.rs:241`); `cover_digest = SHA-256(tag ‖ u32be(block_count) ‖ u32be(component_count) ‖ DC i16be for each block in each component)`, where `block_count` is taken from component 0. | `stego/jpeg/engine.rs:243-270` |
| WAV | `hpos_salt ‖ "wav-v4" ‖ u16be(channels) ‖ u32be(sample_rate) ‖ u16be(block_align) ‖ u16be(bits) ‖ u32be(data_len)`, bits = 8 / 16 / 24 / 32 (`stego/audio/sample.rs:66-77`; FLAC imposes a 24-bit upper bound). | `stego/audio/mod.rs:58-68` |
| FLAC | `hpos_salt ‖ "flac-v4" ‖ u32be(sample_rate) ‖ [channels, bits_per_sample] ‖ u64be(total_samples)`, excluding STREAMINFO MD5. | `stego/audio/mod.rs:75-83` |
| HEVC Container | `cover_salt ‖ "hevc-v4" ‖ u64be(ps_count) ‖ Σ(u64be(ps_len) ‖ ps_bytes)` | `stego/hevc/engine.rs:4260-4288` |
| HEVC Annex-B | `cover_salt ‖ "hevc-v4" ‖ u64be(span_count) ‖ Σ span`; parameter set span = full NAL; VCL span = 2B NAL header ‖ `u64be(nal_len)`; all other spans do not contribute. | `stego/hevc/engine.rs:4289-4290`; `stego/hevc/bitstream.rs:192-211` |

Public salt constants (Tier D; modifying creates a dialect):  
PNG: `b"strhide-stego-hpos-salt-v2"` (`stego/format.rs:267`), WAV: `b"strhide-audio-hpos-salt-v1"` (`:287`), FLAC: `b"strhide-flac-hpos-salt-v1"` (`:297`), HEVC: `b"strhide-hevc-cover-v1"` (`:102`).

### 1.5 L2: Header Locating Keys (Tier F)

```text
salt = None
locate_seed     = HKDF-Expand(SHA256, ikm=master, info=info(hpos_label, domain),  L=32)
magic4          = HKDF-Expand(SHA256, ikm=master, info=info(magic_label, domain), L=4)
header_stc_seed = u64be(HKDF-Expand(SHA256, ikm=master, info=b"strhide-v4-hdr-stc", L=8))
ext_stc_seed    = u64be(HKDF-Expand(SHA256, ikm=master, info=b"strhide-v4-ext-stc", L=8))
```

Reference: `stego/format.rs:468-486`. The two STC seeds are fixed literals and omit domain/suite; implementations MUST NOT add domain separation, otherwise the trellis cannot be reconstructed.

### 1.6 L3: Session Keys and `session_salt` (Tier F)

```text
info_x = info(x_label, domain) ‖ u16be(suite_id)          // x ∈ {enc, perm, stc}
enc_key   = HKDF-Expand(SHA256, salt=session_salt, ikm=master, info=info_enc,  L=32)
perm_seed = HKDF-Expand(SHA256, salt=session_salt, ikm=master, info=info_perm, L=32)
stc_seed  = u64be(HKDF-Expand(SHA256, salt=session_salt, ikm=master, info=info_stc, L=8))
```

Reference: `stego/format.rs:488-516`; suite is appended strictly as `u16be` at the end of info. `session_salt`:

| Carrier | Value | Reference |
|---|---|---|
| PNG / JPEG / WAV / FLAC | 16B `salt` from base header, used verbatim | `stego/png/engine.rs:1506`; `stego/jpeg/engine.rs:945`; `stego/audio/core.rs:725` |
| HEVC | `SHA-256("strhide-hevc-session-v4" ‖ nonce)` $\to$ **32B**; nonce is the 12B header nonce | `stego/hevc/engine.rs:452-457` (used at `1337-1341, 2166-2170`) |

HEVC MUST compute the labeled hash above and MUST NOT use the raw nonce as salt.

### 1.7 Complete Label Table (Tier D: modifying labels creates a dialect)

| Carrier | `domain_label` | `hpos_label` | `enc_label` | `perm_label` | `stc_label` | `magic_label` |
|---|---|---|---|---|---|---|
| PNG | `strhide-stego-domain-v1` | `strhide-stego-hpos-v2` | `enc` | `perm` | `strhide-stc-trellis-v1` | `strhide-v4-hdr-magic` |
| JPEG | `strhide-stego-domain-v1` | `hpos` | `enc` | `perm` | `stc-trellis` | `strhide-v4-hdr-magic` |
| WAV | `strhide-stego-domain-v1` | `audio-hpos` | `audio-enc-v1` | `audio-perm-v1` | `audio-stc-trellis-v1` | `strhide-v4-hdr-magic` |
| FLAC | `strhide-stego-domain-v1` | `audio-hpos` | `audio-enc-v1` | `audio-perm-v1` | `audio-stc-trellis-v1` | `strhide-v4-hdr-magic` |
| HEVC | `strhide-stego-domain-v1` | `strhide-hevc-hpos-v4` | `strhide-hevc-enc-v4` | `strhide-hevc-perm-v4` | `strhide-hevc-stc-v4` | `strhide-hevc-magic-v4` |

References: PNG `stego/format.rs:326-333`, Audio `337-344`, JPEG `348-355`, HEVC `359-366`; HEVC magic label `stego/format.rs:101`; other three carrier families pass `b"strhide-v4-hdr-magic"` at call sites (`stego/png/engine.rs:1498`, `stego/jpeg/engine.rs:729`, `stego/audio/core.rs:196`). WAV and FLAC share labels and are differentiated via `hpos_salt` with `"wav-v4"` / `"flac-v4"`.

### 1.8 AEAD, AAD, and Micro-Header (Tier F)

| `suite_id` | AEAD | Nonce | Tag |
|---|---|---|---|
| 1 (default) | AES-256-GCM | 12B | 16B |
| 2 | ChaCha20-Poly1305 | 12B | 16B |

Reference: `core/crypto.rs:132-166` (wire ID and 16B tag), implementation `stego/envelope.rs:410-447`. `salt` and `nonce` reside exclusively in the base header and do not enter the ciphertext body; `body_len` counts only ciphertext + tag (`stego/envelope.rs:64-97`).

- Micro-header (belongs to content domain, not key derivation): Plaintext layout is `4B BE raw_len ‖ 1B flags ‖ micro_header ‖ body`, where `BODY_OVERHEAD = 22`; type `0x00` = text / raw bytes; `0x01` = file (`1B name_len ‖ name`); flags bit 0 = compressed, bits 1..3 = algorithm ID (0 = Deflate) (`stego/envelope.rs:68-97, 313-330`).
- **AAD MUST BE**: `"strhide-content-envelope-v4\0" (28B) ‖ format_id (1B) ‖ base_header ‖ extension` (`stego/envelope.rs:105, 113-120`). Base header size is 64B Spatial / 44B JPEG / 32B HEVC (`stego/header.rs:153`, `stego/format.rs:109`, `stego/hevc/engine.rs:90`); extension length is capped at 255B (64B for HEVC) (`stego/header.rs:159`, `stego/hevc/engine.rs:124`).
- `format_id`: PNG 1 (`stego/png/engine.rs:76`), WAV 2 / FLAC 3 (`stego/audio/mod.rs:49-51`), JPEG 4 (`stego/jpeg/engine.rs:65`), HEVC 5 (`stego/hevc/engine.rs:97`). Base headers for PNG, WAV, and FLAC store this value at byte offset 34 (decoder strictly validates `1..=3` matching expected carrier, `stego/header.rs:306, 326-330`); JPEG and HEVC headers omit this field and implicitly assume 4 or 5. `build_v4_aad` always passes the carrier family constant as its 1B argument.
- Authentication failures, unrecognized cipher suites, non-zero reserved bits in flags, or malformed micro-headers MUST all uniformly fail with `NoHiddenData` (`stego/envelope.rs:454-553`); base header CRC32 serves solely to catch corruption early. Version byte `0x40` is contained inside the header and covered by AAD (`stego/header.rs:162`).

Constants: `CONTENT_L1_PBKDF2_ITERATIONS = 200_000` (`core/crypto.rs:114`), `SALT / NONCE / TAG = 16 / 12 / 16` (`stego/envelope.rs:64-66`), `PUBLIC_DEFAULT_SECRET` (`:62`), `BODY_OVERHEAD = 22` (`:97`).

---

## 2. Structural Domain (UBE v2)

### 2.1 Master Key (Tier F; Defaults Tier D)

```text
pwd = Non-empty user password, else StructureProfile.default_secret, else BUILTIN_DEFAULT_KEY
ikm = PBKDF2-HMAC-SHA256(pass=NFC(pwd), salt=salt(16B), iter=100_000, dkLen=32)
payload_key = HKDF-Expand(SHA256, salt=Some(salt), ikm=ikm, info=b"strhide-payload",  L=32)
meta_key    = HKDF-Expand(SHA256, salt=Some(salt), ikm=ikm, info=b"strhide-metadata", L=32)
```

Reference: `core/crypto.rs:210-217, 240-252`; iteration count `core/crypto.rs:106`; `BUILTIN_DEFAULT_KEY = "strhide::structure::envelope::v2::default::builtin::public::secret"` (`:171-172`); fallback logic `structure/params.rs:88-93`, `structure/engine.rs:1153`. PBKDF2 and HKDF share the identical 16B `salt`. AEAD is fixed to AES-256-GCM (`core/crypto.rs:382-419`).

### 2.2 Nonce Derivation (Tier F)

```text
make_chunk_nonce(base, i): base[0..8] ‖ le32( le32(base[8..12]) XOR (i as u32) )
make_meta_nonce(base):     base[0..8] ‖ le32( le32(base[8..12]) XOR 0xFFFFFFFF )
```

Reference: `core/crypto.rs:354-373`. Metadata nonce permanently occupies `0xFFFFFFFF`, preventing overlap with any chunk index; `chunk_index` and `is_last` enter AAD only.

### 2.3 AAD (Tier F)

Fixed 80B:  
`magic_header(8) ‖ version(1) ‖ flags(1) ‖ strategy_id(1) ‖ offset_delta(1) ‖ salt(16) ‖ base_nonce(12) ‖ orig_host_size(u64 LE) ‖ orig_host_sha256(32)` (`core/crypto.rs:56`; `structure/envelope.rs:354-366`).

Variable-length:  
`header[0..80] ‖ meta_len(u32 LE) ‖ hint_len(u32 LE) ‖ hint` = 88 + `hint_len` (`structure/envelope.rs:390-397`); each chunk further appends `chunk_index(u64 LE) ‖ is_last(u8)` $\to$ 97 + `hint_len` (`core/crypto.rs:508-511, 602-605`). `meta_len` and `hint_len` are located at offsets 104..112 and MUST be authenticated via `auth_aad`. Post-injection coordinates (offsets 80..104: `inject_offset` / `inject_size` / `patch_offset` / `orig_patch_val`) are excluded from AAD and are validated via physical containment and host restoration hashes (`structure/envelope.rs:148-159`).

### 2.4 Stealth Mode (Tier F; Domain Separation Constants Tier D)

```text
1) Magic numbers (salt = domain bytes, NOT the envelope salt):
   ikm = PBKDF2-HMAC-SHA256(NFC(password), salt=domain, iter=100_000, dkLen=32)
   header_magic  = HKDF-Expand(SHA256, salt=Some(domain), ikm, info=b"strhide-stealth-header",  L=8)
   trailer_magic = HKDF-Expand(SHA256, salt=Some(domain), ikm, info=b"strhide-stealth-trailer", L=4)

2) Header field mask (salt = 16B envelope salt):
   mask76 = HKDF-Expand(SHA256, salt=Some(salt), ikm=PBKDF2(NFC(pwd), salt, 100_000, 32),
                        info=b"strhide-header-mask-v1", L=76)

3) Trailer CRC:
   mask32 = CRC32_IEEE(trailer_magic ‖ b"STEA"); trailer_crc32 = raw_crc ⊕ mask32
```

Reference: Magic numbers `core/crypto.rs:285-300` (invoked at `structure/engine.rs:1019`, `structure/envelope.rs:583`); Header mask `core/crypto.rs:305-312`; CRC `core/crypto.rs:318-329` (written at `structure/envelope.rs:740-753`). Default `STEALTH_DOMAIN = b"strhide-stealth-v1"` (`core/params.rs:37`, `structure/params.rs:95-98`), customizable (Tier D).

- Mask application range (`structure/envelope.rs:422-433`): `header[8..12] ^= mask[0..4]`, `header[40..112] ^= mask[4..76]`; `salt (12..28)` and `base_nonce (28..40)` remain unmasked.
- Activation condition (`structure/envelope.rs:449-466`): Stealth mode derives mask from user password; non-stealth with `FLAG_ENCRYPTED = 0` uses `Profile::secret()`. The `FLAG_ENCRYPTED` header bit remains unmasked so passwordless readers can immediately identify "password required".
- Standard magic numbers: `b7 54 2c 82 7e 31 1d 6e` / `78 e6 66 d2` (`core/params.rs:27, 30`).

### 2.5 PE ChannelHeader Mask (Tier F)

14B layout: `magic(4) ‖ version(1) ‖ flags(1) ‖ ube_len(u32 LE) ‖ slack_off(u32 LE)` (`structure/adapters/pe_codebits.rs:372-380`). Only bytes 4..14 are masked:

```text
mask10 = HKDF-Expand(SHA256, salt=None, ikm=envelope_header_magic(8B),
                     info=b"strhide-pe-channel-mask-v2", L=10)
out[4+i] = plain[4+i] XOR mask10[i]        // i = 0..10
```

Reference: `core/crypto.rs:342-348`; `pe_codebits.rs:393-400, 414-436`. IKM MUST be the 8B `magic_header` of the UBE header (channel bits 112..176), NOT the plaintext `CHANNEL_MAGIC` of `ChannelHeader[0..4]` (`pe_codebits.rs:460-478`). `CHANNEL_MAGIC = STANDARD_TRAILER_MAGIC`, `CHANNEL_VERSION = 1`, `CHANNEL_HEADER_LEN = 14` (`pe_codebits.rs:38-44`). Standard mode provides format obfuscation only; it does not claim cryptographic confidentiality.

Constants: `PBKDF2_ITERATIONS = 100_000` (`core/crypto.rs:106`), `AAD / HEADER / TRAILER = 80 / 112 / 24` (`structure/envelope.rs:83-89`), mask info labels as listed above, CRC mask suffix `STEA` (`core/crypto.rs:326-327`).

---

## 3. Cross-Domain Incompatibility

| Dimension | Content Domain V4 | Structural Domain UBE v2 |
|---|---|---|
| PBKDF2 Iterations | 200,000 (Password only) | 100,000 (Always) |
| HKDF Salt | `pre_salt` (32B, carrier-derived) | Envelope `salt` (16B); stealth magic uses `domain` |
| AEAD | AES-256-GCM / ChaCha20-Poly1305 | AES-256-GCM exclusively |
| AAD Root | 28B content prefix + `format_id` | 80B header prefix |
| Endianness | Big-Endian | Little-Endian |
| Passwordless Default | `PUBLIC_DEFAULT_SECRET` | `BUILTIN_DEFAULT_KEY` |

Readers on either side MUST NOT fall back to keys, salts, or labels from the opposite domain.

---

## 4. Implementation Self-Verification Checklist

The following test vectors (except item 6) do not require access to this repository; passing them verifies cryptographic correctness, but does not guarantee full carrier readability.

1. **ChaCha12 Stream**: `key = 01 00 ... 00` (32B, only first byte is 1), `IV = 0`, 12 rounds; the first 128 bytes are (`stego/prng.rs:291-327`):  
   `12 05 6e 59 5d 56 b0 f6 ee f0 90 f0 cd 25 a2 09 / 49 24 8c 27 90 52 5d 0f 93 02 18 ff 0b 4d dd 10 / a6 00 22 39 d9 a4 54 e2 9e 10 7a 7d 06 fe fd fe / f0 21 0f eb a0 44 f9 f2 9b 17 72 c9 60 dc 29 c0`.
2. **Full-range Fisher–Yates**: Seed `b"strhide-prng-contract-seed-2026!"`, $n = 256$, first 16 elements: `61 121 191 236 8 58 233 146 64 12 35 66 70 210 254 52`, last 16 elements: `93 222 27 189 132 24 10 164 145 37 133 170 180 127 4 135` (`stego/prng.rs:337-364`).
3. **Prefix Fisher–Yates**: Same seed, $n = 256$, $k = 16$, first 16 elements: `135 5 129 183 174 138 43 152 172 19 34 143 201 40 236 108` (`stego/prng.rs:496-505`).
4. **Cipher Suite Cross-Rejection**: Given identical `(key, nonce, aad, plaintext)`, suite 1 ciphertext decrypted under suite 2 MUST fail, and vice versa (`stego/envelope.rs:767-799`).
5. **Structural Domain KDF Known Answer**: `password = "test_password"`, `salt = b"1234567890123456"` $\to$  
   `payload_key = 2834274fef93d55fc5a3cb070c09c08eedecd8910b9a601fd67b703c8e078674`,  
   `meta_key = 5406a23d873a956bcf01781771ea5f96857b61bda4f15ef53d40d87f07477c68`;  
   Stealth mode (`domain = b"strhide-stealth-v1"`):  
   `header_magic = 3858efa8820a029b`, `trailer_magic = 3a97756c` (`core/crypto.rs:943-970`).
6. **Detmath Digests**: `exp 68107bf871d53df2`, `ln 6021ef64db0e27ef`, `cos 55f3c5acb971153a`, `ln_1p 23e6e71dccf69b20`, `log2 d97b86f58ee1dfba` (`WIRE_SPEC_CONTENT.md` §13.11.5, `scripts/detmath/`); affects writer sorting only.
7. **28 Byte-Level Baseline Cases** (`python scripts/baseline_hash.py --check`) are strictly for internal regression testing within this repository; external implementers do not have the private corpus and should not use it as an interoperability criterion.

Failure semantics: If any key, domain, suite, or AAD field is mismatched, the content domain uniformly returns `NoHiddenData`, while the structural domain manifests as metadata or chunk authentication failure. Implementations MUST NOT leak internal discrepancies through detailed error variants.
