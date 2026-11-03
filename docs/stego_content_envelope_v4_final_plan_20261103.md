# stego 内容域信封与密码学 V4 最终方案

> 文档编号：`FINAL-STEGO-ENVELOPE-V4-20261103`
> 编写时间：2026-11-03
> 适用范围：`rust/src/core/crypto.rs`、`rust/src/stego/**`（PNG / WAV / FLAC / JPEG / HEVC-HEIF-MP4-MKV-AnnexB）
> 取代：`temp\docs\stego_content_envelope_v4_old_docs` 里面的旧文档和审查报告。
> 前提：**只做 V4；不兼容 v2/v3；不写迁移代码；不保留 legacy 双读/迁移工具。**
> 本文性质：最终执行方案。

---

## 0. 结论与关键决策

1. **只保留 V4 单一路径。** 所有 v2/v3 的 `FeatureWord`、`HEADER_V2_ESCAPE_H`、旧 `CipherSuite`、旧 `JpegFormatProfile.format_major/minor/suites`、`JpegParams.cipher_suite` 全部删除；不写迁移代码。
2. **Header 固定 base + 可选扩展 TLV。** 不再做“纯固定长度、无扩展路径”；每种载体 base 长度固定，`ext_len` + TLV 提供未来字段；扩展槽位从同一 keyed header permutation 的后续槽位读取。
3. **单一 L1 慢哈希。** 口令模式固定 PBKDF2-HMAC-SHA256 **200,000** 次；`FileKey` 模式固定 HKDF-SHA256；L2/L3 只做 HKDF。`suite_id` 只表示 AEAD 算法，不再承载 KDF 迭代数。
4. **校验顺序固定：** Header 解码/CRC → 结构/长度/白名单 → Header 扩展 TLV → Body 槽位计算 → Body 提取 → AEAD → frame 解包。未认证的 `body_len`/`ext_len` 只允许在硬上限内驱动计算。
5. **CRC 只做意外损坏早拒绝；认证靠 AEAD。** 不引入 keyed MAC；若未来需要“Header 在 AEAD 前可认证”，才会把 4B CRC 替换为 keyed MAC（本节不作为 V4 实现）。
6. **probe 与 embed 同源同算。** `probe` 与 `embed` 使用同一 `Credential`、同一 `pre_salt`、同一 `HeaderSlotPlan`、同一 `ext_len`；不再有“无密码 probe 零种子”的特殊路径。代价是无密码 probe 也要付 200k PBKDF2；这是确定的正确性取舍。
7. **默认限额：** `max_payload_bytes = MAX_PLAINTEXT_LEN = 0x03FF_FFFF`（67,108,863），`max_pbkdf2_iterations = 200_000`。若业务要更小/更高，改 `ExtractParams::default` 这两个值；本文按此默认执行。
8. **Header 扩展 TLV：** `tag` 1B（bit7 critical）、`len` 1B、`value` len B；未知 non-critical 忽略，未知 critical 失败；不改变 base 布局即可新增可选字段。
9. **容量公式写死到变量级**，见 §4；`body_len` 统一为“AEAD 密文字节数（含 16B tag）”，不再有 PNG/JPEG `+28`、HEVC `-16` 的换算。

---

## 1. 分层架构与边界

### 1.1 三层职责

| 层 | 负责 | 不负责 | 现有代码归属 |
|---|---|---|---|
| **Carrier/Coding** | 容器解析、像素/系数/CABAC 槽位、代价图、Hamming/STC、keyed 槽位置换、物理 Header 槽位写入/读取 | 不决定 AEAD/KDF/错误折叠 | `stego/png/engine.rs`、`stego/jpeg/engine.rs`、`stego/hevc/engine.rs`、`stego/audio/*`、`stego/coding/*` |
| **Envelope** | 逻辑 Header、版本/flags/suite/长度、L1/L2/L3、AEAD、AAD、body frame、限额与错误语义 | 不解析 PNG/JPEG/HEVC 容器 | `stego/envelope.rs`（重构）、`stego/header.rs`（Header/TLV） |
| **Core crypto** | `Credential`、`CipherSuiteId`、PBKDF2/HKDF/AEAD 原语 | 不引用 stego | `core/crypto.rs`（扩展） |

### 1.2 边界判定

- 影响“哪些槽位、如何排列、如何编码”的字段属于 Carrier/Coding：`codec_id`、`stc_h`、`stc_u`、`channel_mode`、`class_rule`、`p1_window`、`p2_window`、`neg_log2_epsilon`、`exclusion_permille`、`sigma`、`kernel_id`、`algorithm_id`。
- 影响“定位、解密、认证、payload 包装”的字段属于 Envelope：`version`、`flags`、`format_id`、`suite_id`、`body_len`、`salt`、`nonce`、`ext_len`、TLV、`header_crc32`、micro-header、压缩标志。
- `Header` 是交换面：Envelope 产出一个固定 base + 扩展 TLV；Carrier 负责把字节映射到槽位。

### 1.3 流程衔接

**Embed：**

```text
engine.decode(carrier)
  -> pre_salt = SHA-256(format_label || immutable_carrier_meta)
  -> Credential = resolve_credential(password, key, dialect)
  -> HeaderLocatorKeys = L1/L2
  -> HeaderV4 { fields, ext_len } + extensions = encode_extension(...)
  -> SlotPlan::build(locate_seed, ext_len) -> header_slots/body_slots
  -> Body = build_plaintext(payload) -> AEAD(enc_key, nonce, AAD)
  -> write header bits + body bits
```

**Extract：**

```text
engine.decode(carrier)
  -> pre_salt -> Credential -> L1/L2
  -> HeaderSlotPlan(locate_seed, ext_len from base? first read base)
  -> read base header; check CRC/version/format/suite/body_len/ext_len
  -> read extension TLV from continuation slots
  -> validate_header(limits) before body slot computation
  -> body slots -> body ciphertext -> AEAD -> frame
```

**关键：** `ext_len` 在 base header 中；读取 base 后才能知道扩展槽位数，因此扩展槽位使用同一 permutation 的**后续前缀**，不需要二次随机源。

---

## 2. 三种物理 Header（含扩展区）

### 2.1 通用常量（新增/现有）

| 常量 | 值 | 来源 |
|---|---:|---|
| `SALT_LEN` | 16 | 现有 `SALT_LEN`（`stego/envelope.rs:62`） |
| `NONCE_LEN` | 12 | 现有 `NONCE_LEN`（`stego/envelope.rs:63`） |
| `TAG_LEN` | 16 | 现有 `TAG_LEN`（`stego/envelope.rs:64`） |
| `BODY_OVERHEAD` | 22 | 现有 `BODY_OVERHEAD`（`stego/envelope.rs:81`），= 4+1+1+16 |
| `HEADER_LEN_MAX` | `0x03FF_FFFF` | 现有 `HEADER_LEN_MAX`（`stego/header.rs:30-35`） |
| ★ `CONTENT_L1_PBKDF2_ITERATIONS` | 200,000 | 新增，放 `core/crypto.rs` |
| ★ `PNG_AUDIO_BASE_HEADER_BYTES` | 64 | 新增；现有 32B Header + 32B FeatureWord 的合并（`stego/header.rs:104-113`） |
| `JPEG_SUPERBLOCK_BYTES` | 44 | 现有（`stego/format.rs:243`） |
| ★ `HEVC_SUPERBLOCK_BYTES` | 32 | 新增；实际 Superblock 大小（`stego/hevc/engine.rs:98-105`） |
| ★ `JPEG_SUPERBLOCK_SLOTS` | 718 | 新增常量；`JpegFormatProfile::superblock_slots()`：`2*(44*8+8-1)=718`（`stego/format.rs:283-286`，默认 `sb_h=8,sb_u=2`） |
| `HEVC_SUPERBLOCK_MIN_SLOTS` | 524 | 现有（`stego/hevc/engine.rs:103`） |
| ★ `PNG_AUDIO_BASE_SLOTS` | 512 | 新增常量；现有 `V2_TOTAL_HEADER_SLOTS` 值（`stego/header.rs:111-113`），旧名在 Step 6/9 清理 |
| ★ `MAX_EXT_BYTES` | 255 | 新增，PNG/WAV/FLAC/JPEG 的 `ext_len` 上限 |
| ★ `HEVC_MAX_EXT_BYTES` | 64 | 新增，HEVC 的 `ext_len` 上限（STC h=7,u=2 时 524 + 16*64 + 12 = 1560 ≤ 2048） |
| ★ `HEVC_HEADER_SLOTS_MAX` | 2048 | 新增常量；现有 `pool_size` 上限字面量（`stego/hevc/engine.rs:202-211`） |

### 2.2 PNG / WAV / FLAC：64B base + 可选 ext

**Base 布局（总长 64B）：**

| 偏移 | 宽度 | 字段 | 取值/语义 |
|---:|---:|---|---|
| 0 | 16 | `salt` | L3 HKDF salt，随机/Seeded |
| 16 | 12 | `nonce` | AEAD nonce |
| 28 | 4 | `body_len` | u32 BE，22..=0x03FF_FFFF；AEAD 密文含 tag |
| 32 | 1 | `version` | `(major<<4)|minor`，V4.0 = `0x40` |
| 33 | 1 | `flags` | bit0 `EXT_PRESENT`，bit1 `EXT_CRITICAL`，bits2..7 必须 0 |
| 34 | 1 | `format_id` | 1 PNG，2 WAV，3 FLAC；必须与载体一致 |
| 35 | 1 | `algorithm_id` | PNG：1 HILL/2 SUNIWARD/3 MIPOD（`stego/png/registry.rs:12-17`）；音频固定 0 |
| 36 | 2 | `suite_id` | u16 BE，1 AES-256-GCM / 2 ChaCha20-Poly1305；0/未知失败 |
| 38 | 1 | `codec_id` | 0 Hamming，1 STC |
| 39 | 1 | `stc_h` | Hamming 必须 0；STC 4..=10 |
| 40 | 1 | `stc_u` | Hamming 必须 0；STC 1..=3 |
| 41 | 1 | `channel_mode` | PNG 0 Green/1 Rgb；音频固定 0 |
| 42 | 1 | `class_rule` | PNG 0/1；音频固定 0 |
| 43 | 1 | `reserved` | 必须 0 |
| 44 | 2 | `p1_window` | u16 BE，奇数 1..=63 |
| 46 | 2 | `p2_window` | u16 BE，奇数 1..=63 |
| 48 | 2 | `neg_log2_epsilon` | u16 BE，1..=127 |
| 50 | 2 | `exclusion_permille` | u16 BE，0..=900 |
| 52 | 4 | `sigma` | f32 LE，有限且 >0 |
| 56 | 1 | `kernel_id` | 固定 0（HILL） |
| 57 | 1 | `reserved` | 必须 0 |
| 58 | 2 | `ext_len` | u16 BE，0..=255；扩展 TLV 字节数 |
| 60 | 4 | `header_crc32` | u32 BE，CRC32_IEEE(bytes[0..60]) |

**校验：** 64 = 16+12+4+1+1+1+1+2+1+1+1+1+1+1+2+2+2+2+4+1+1+2+4。  
**扩展区：** 64B 之后的 `8*ext_len` 个槽位（每字节 8 个 bit 槽），取自同一 `header_layout` 的后续槽位：`permuted[512 .. 512 + 8*ext_len]`。  
**header slots：** `PNG_AUDIO_BASE_SLOTS + 8*ext_len`。

**Header CRC 覆盖：** 首字节 0，末字节 59（即 `bytes[0..60]`），**不含** 60..64 的 CRC 自身；扩展 TLV 不在 CRC 覆盖范围内（由 AAD 认证）。

### 2.3 JPEG：44B base + 可选 ext

**Base 布局（总长 44B）：**

| 偏移 | 宽度 | 字段 | 取值/语义 |
|---:|---:|---|---|
| 0 | 1 | `version` | `(major<<4)|minor`，V4.0 = `0x40` |
| 1 | 1 | `flags` | bit0 `EXT_PRESENT`，bit1 `EXT_CRITICAL`，bits2..7 必须 0 |
| 2 | 2 | `suite_id` | u16 BE，1/2 |
| 4 | 16 | `salt` | L3 HKDF salt |
| 20 | 12 | `nonce` | AEAD nonce |
| 32 | 4 | `body_len` | u32 BE，22..=0x03FF_FFFF |
| 36 | 1 | `codec_id` | 0 = ternary STC（V4 唯一值） |
| 37 | 1 | `stc_h` | 4..=10 |
| 38 | 1 | `stc_u` | 1..=64 |
| 39 | 1 | `ext_len` | u8，0..=255 |
| 40 | 4 | `header_crc32` | CRC32_IEEE(bytes[0..40]) |

**校验：** 44 = 1+1+2+16+12+4+1+1+1+1+4。  
**隐含字段：** `format_id = 4`、`components_mask = 0x01 (Y)`；不落盘，由 `JpegFormatProfile`/AAD 前缀绑定。  
**扩展区：** 现有 `JpegFormatProfile` 的 `ext_h=8`、`ext_u=4` 继续用于 TLV 区：  
`extension_slots(ext_len) = ext_u * (8*ext_len + ext_h - 1) = 4*(8*ext_len+7)`（现有公式 `stego/format.rs:289-291`）。  
**header slots：** `718 + extension_slots(ext_len)`。  
**Header CRC 覆盖：** `bytes[0..40]`（0..39），不含 40..44 自身；扩展不在 CRC 覆盖范围。

### 2.4 HEVC：32B base + 可选 ext

**Base 布局（总长 32B）：**

| 偏移 | 宽度 | 字段 | 取值/语义 |
|---:|---:|---|---|
| 0 | 4 | `magic` | L2 派生 `magic4` |
| 4 | 1 | `version` | `(major<<4)|minor`，V4.0 = `0x40` |
| 5 | 1 | `flags` | bit0 `EXT_PRESENT`，bit1 `EXT_CRITICAL`，bits2..7 必须 0 |
| 6 | 1 | `stc_u` | 1..=64 |
| 7 | 2 | `window_slices` | u16 BE，>=1 |
| 9 | 1 | `ext_len` | u8，0..=64；扩展 TLV 字节数 |
| 10 | 2 | `suite_id` | u16 BE，1/2 |
| 12 | 4 | `body_len` | u32 BE，22..=0x03FF_FFFF |
| 16 | 12 | `nonce` | AEAD nonce；同时作为 HEVC session_salt 的输入 |
| 28 | 4 | `header_crc32` | CRC32_IEEE(bytes[0..28]) |

**校验：** 32 = 4+1+1+1+2+1+2+4+12+4。  
**固定字段：** `format_id = 5` 隐含；`total_windows = 1` 在 V4 固定，不再落盘（旧 v2 的 `total_windows` 字段已删除）；`stc_h` 由 `HevcFormatProfile.stc_h` 提供，必须与 profile 一致，不落盘。  
**扩展区：** 扩展区与 Base Superblock 一致采用 STC（`h=7, u=2`）矩阵编码，槽位计算为 `hevc_extension_slots(ext_len) = if ext_len == 0 { 0 } else { 2 * (8 * ext_len + 7 - 1) = 16 * ext_len + 12 }`。引入冗余度使得在 CABAC 防竞争字节（EPB `0x00 0x00 0x03`）冲突或 `BadSubstream` 时，求解器可通过多轮 `forbidden` 槽位避让完成重编码，避免裸槽位导致的重编码失败。  
**header slots：** `524 + hevc_extension_slots(ext_len)`，必须 ≤ `pool_size`（≤2048）；`ext_len <= 64` 保证最大槽位 `524 + 16*64 + 12 = 1560 ≤ 2048`。`superblock_positions` 一次置换 `524 + hevc_extension_slots(ext_len)` 个前缀槽位，前 524 槽位由 `sb_trellis`（基于 `header_stc_seed`）求解 base，后续槽位由 `ext_trellis`（基于 `ext_stc_seed`）求解 TLV。  
**Header CRC 覆盖：** `bytes[0..28]`，不含 28..32 自身；扩展不在 CRC 覆盖范围。

**format_id/algorithm_id 的落盘规则（确定选择）：** PNG/WAV/FLAC 在 base 中显式写 `format_id` 与 `algorithm_id`；JPEG/HEVC 的格式由载体类型唯一确定，不在 base 中重复落盘，但 `build_v4_aad` 的 `format_id` 前缀仍然写入并参与认证——把 JPEG Header 塞进 HEVC 或反之，AAD/密钥必然不同。JPEG/HEVC 提取不需要代价模型，`algorithm_id` 只用于嵌入侧，不落盘。PNG 的 `algorithm_id` 必须落盘（提取要重建 HILL/S-UNIWARD/MiPOD 代价图）。

---

## 3. 密钥、AEAD、nonce 与 AAD

### 3.1 凭据类型（新增）

```rust
// core/crypto.rs（新增）
pub enum Credential<'a> {
    Password(&'a str),       // 人类口令/部署字符串：L1 PBKDF2 200k
    FileKey(&'a [u8; 32]),   // 32B 高熵密钥：L1 HKDF-SHA256
}
```

**身份规则（新增函数，落位 `stego/options.rs`；不可放 `core`，因为 `core` 不能引用 `stego`）：**

```rust
pub fn resolve_credential<'a>(
    password: Option<&'a str>,
    key: Option<&'a [u8; 32]>,
    dialect: &'a StegoProfile,
) -> Result<Credential<'a>, StrHideError>
```

- `key` 与显式非空 `password` 同时提供 -> `StrHideError::General("password and key are mutually exclusive")`；
- `key` 优先进入 `Credential::FileKey`；
- 否则显式非空 password -> `Password`；
- 否则 `dialect.default_secret`（现有字段 `stego/params.rs:683`）-> `Password`；
- 否则 `Credential::Password(PUBLIC_DEFAULT_SECRET)`（现有常量 `stego/envelope.rs:60`）。
- `Credential` **不实现 `Debug`**，避免日志泄漏；`EmbedOptions`/`ExtractOptions`/`ProbeOptions`/`InspectOptions`/`VerifyOptions` 的现有 `Debug` 实现必须把 `key` 与 `password` 都显示为 `"<redacted>"`。

### 3.2 L1/L2/L3（新增函数，落位 `stego/format.rs`）

```rust
pub struct WireCipherProfile {
    pub domain_label: &'static [u8],
    pub hpos_label: &'static [u8],
    pub enc_label: &'static [u8],
    pub perm_label: &'static [u8],
    pub stc_label: &'static [u8],
    pub default_suite: CipherSuiteId,
}

pub struct HeaderLocatorKeys {
    pub locate_seed: [u8; 32],
    pub header_stc_seed: u64,
    pub ext_stc_seed: u64,
    pub magic4: [u8; 4],
}

pub struct SessionKeys {
    pub enc_key: [u8; 32],
    pub perm_seed: [u8; 32],
    pub stc_seed: u64,
}

pub fn derive_locator_master(
    cred: Credential<'_>,
    domain: Option<&str>,
    cipher: &WireCipherProfile,
    pre_salt: &[u8; 32],
) -> Result<[u8; 32], StrHideError>;

pub fn derive_l2_locator_keys(
    master: &[u8; 32],
    cipher: &WireCipherProfile,
    magic_label: &[u8],
    domain: Option<&str>,
) -> Result<HeaderLocatorKeys, StrHideError>;

pub fn derive_l3_session_keys(
    cipher: &WireCipherProfile,
    suite: CipherSuiteId,
    master: &[u8; 32],
    session_salt: &[u8],
    domain: Option<&str>,
) -> Result<SessionKeys, StrHideError>;
```

**L1：**

```text
Password: master = PBKDF2-HMAC-SHA256(NFC(password') , pre_salt, 200_000, 32)
          password' = domain-subkey(password, domain, cipher.domain_label)  // 现有 derive_domain_subkey_with_label（stego/envelope.rs:108-126）
FileKey:  master = HKDF-SHA256(salt=pre_salt, ikm=key32,
                               info=info_with_domain(cipher.domain_label, domain), 32)
```

- L1 在 Header 定位前执行一次；`max_pbkdf2_iterations < 200_000` 时在 L1 前拒绝。
- 不再有 L3 二次 PBKDF2/600k/Argon2；`suite_id` 只选 AEAD。

**L2（无随机盐，纯 HKDF-Expand）：**

```text
locate_seed      = HKDF-Expand(master, info_with_domain(cipher.hpos_label, domain), 32)
header_stc_seed  = HKDF-Expand(master, b"strhide-v4-hdr-stc", 8) -> u64 BE
ext_stc_seed     = HKDF-Expand(master, b"strhide-v4-ext-stc", 8) -> u64 BE
magic4           = HKDF-Expand(master, info_with_domain(magic_label, domain), 4)
                     // PNG/WAV/FLAC/JPEG 传 b"strhide-v4-hdr-magic"；HEVC 传 HevcFormatProfile.magic_label
```

**L3（以 Header 的 salt/nonce 为 HKDF salt）：**

```text
session_salt = header.salt16   (PNG/WAV/FLAC/JPEG)
             | SHA-256(b"strhide-hevc-session-v4" || nonce)  (HEVC)
enc_key      = HKDF-Expand(master, salt=session_salt,
                           info=info_with_domain(cipher.enc_label, domain) || u16be(suite as u16), 32)
perm_seed    = HKDF-Expand(master, salt=session_salt,
                           info=info_with_domain(cipher.perm_label, domain) || u16be(suite as u16), 32)
stc_seed     = HKDF-Expand(master, salt=session_salt,
                           info=info_with_domain(cipher.stc_label, domain) || u16be(suite as u16), 8) -> u64 BE
```

- `header_stc_seed` 用于 JPEG/HEVC 的 Base Header STC；`ext_stc_seed` 用于 JPEG/HEVC 的 Extension STC；`stc_seed` 用于 Body STC。
- PNG/音频的 body permutation 使用 `perm_seed`；HEVC `band_positions` 使用 `stc_seed`（见 §4/§5）。
- HEVC `band_positions` 的 keyed Weyl（新增 `band_positions(bands,count,stc_seed)`）：对每个 band 取 `seed_i = HKDF-Expand(Hkdf::new(None, &stc_seed.to_be_bytes()), b"hevc-band-v4"||band_index, 16)`；`start_i = u64(seed_i[0..8]) % band_len`；`stride_i = 1 + (u64(seed_i[8..16]) % (band_len-1))`（`band_len<=1` 时直接返回 `[0]`），递增 `stride_i` 直到 `gcd(stride_i,band_len)==1`；第 `j` 个位置为 `(start_i + j*stride_i) % band_len`。这样既保持 Weyl 的空间均匀性，又保证位置依赖 `stc_seed`。

**一次 KDF、verify 复用（新增 crate-private 类型，落位 `stego/engine.rs`）：**

```rust
pub(crate) struct PreparedCarrier {
    pub pre_salt: [u8; 32],
    pub master: [u8; 32],
    pub locator: HeaderLocatorKeys,
}
```

`inspect_*`/`extract_*`/`verify_*` 的内部函数统一接收 `&PreparedCarrier`；`verify_*` 顶层只调用一次 `derive_locator_master`/`derive_l2_locator_keys`，再复用给 L2/L3，禁止 `verify` 内部再次调用 `extract` 重新派生。

### 3.3 `pre_salt`（32B，定位 Header 前）

**PNG：**

```text
meta = SHA-256(
  for chunk in image.chunks where chunk.ty != b"IDAT" && chunk.ty != b"prIv":
      chunk.ty || u32be(chunk.data.len()) || chunk.data
)
pre_salt = SHA-256(png.hpos_salt
  || b"png-v4"
  || u32be(width) || u32be(height)
  || bit_depth_u8 || color_type_u8 || channels_u8
  || meta)
```

- `RawImage` 需新增 `bit_depth: u8`、`color_type: u8`（§6）；`chunks` 现有 `PngChunk { ty, data }`（`stego/png/engine.rs:130-133`）。
- 排除 `IDAT` 是因为内容域会重压缩 `IDAT`；排除 `prIv` 是因为结构域容器隐写（`structure/adapters/png.rs`）在“先内容域 embed、后结构域 write”双域共存时会在 `IEND` 前注入 `prIv` 私有块，排除 `prIv` 确保结构域操作不改变内容域的 `pre_salt`。`meta` 对其余非 IDAT/prIv 块的类型/长度/内容计算哈希。

**WAV：**

```text
pre_salt = SHA-256(wav.hpos_salt
  || b"wav-v4"
  || u16be(channels) || u32be(sample_rate)
  || u16be(block_align) || u16be(kind.bits() as u16)
  || u32be(data_len))
```

- `WavLayout` 现有字段：`data_len/channels/sample_rate/block_align/kind`（`stego/audio/wav.rs:43-57`）；`kind.bits()`（`stego/audio/sample.rs:39-42`）。

**FLAC：**

```text
pre_salt = SHA-256(flac.hpos_salt
  || b"flac-v4"
  || u32be(sample_rate) || u8(channels) || u8(bits_per_sample)
  || u64be(total_samples))
```

- `StreamInfo` 现有字段（`stego/audio/flac/mod.rs:86-94`）；**严禁包含 `md5`**（嵌入后重写，见 `audio/flac/mod.rs:533-536`）。

**JPEG：**

```text
pre_salt = SHA-256(fmt.cover_digest_tag
  || b"jpeg-v4"
  || cover.digest)
```

- `CoverFrame { digest: [u8;32] }`（`stego/jpeg/engine.rs:208-226`）；`cover_digest` 由不可变 DC 系数计算（`:238-265`）。

**HEVC：**

```text
pre_salt = SHA-256(fmt.cover_salt
  || b"hevc-v4"
  || cover_digest)
```

- `cover_digest` 来自 VPS/SPS/PPS 内容（`stego/hevc/engine.rs:3240-3269`）。

> `pre_salt` 不是“每文件唯一”：相同尺寸/相同元数据的 PNG/WAV/FLAC 会共享 pre_salt；这是可用信息决定的边界。PBKDF2 200k 仍会为每个口令付出成本；本文不宣称杜绝彩虹表。

### 3.4 `CipherSuiteId` / suite 表（append-only）

**新增 `core/crypto.rs`：**

```rust
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuiteId {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
}

impl CipherSuiteId {
    pub const fn from_u16(id: u16) -> Option<Self> { ... }
    pub const fn tag_len(self) -> usize { 16 }
    pub const fn name(self) -> &'static str { ... }
}
```

| id | 名称 | AEAD | 状态 |
|---:|---|---|---|
| 0 | 保留/非法 | — | Header 拒绝 |
| 1 | `aes-256-gcm` | AES-256-GCM | 默认；V4 唯一默认 |
| 2 | `chacha20-poly1305` | ChaCha20-Poly1305 | 可选；需新增依赖 |
| 3.. | 保留 | — | append-only，未来新增 |

**规则：**

- 旧代码中的 `SUITE_PBKDF2_200K`/`SUITE_PBKDF2_600K`（`stego/format.rs:113-130`）、`SUITES`（`:140`）、`DEFAULT_SUITE_ID`（`:143`）、`CipherSuite`/`Kdf`/`Aead`（`:46-110`）全部删除；id 1/2 不再表示 PBKDF2 200k/600k。
- `suite_id` 只由 Header 决定；`EmbedOptions.suite_id` 仅写侧选择；解码端不盲试，未知/不许立即失败。
- `ExtractParams.allowed_suites: Option<Vec<u16>>` 保留现有字段（`params.rs:633`）；`None` 接受 1/2。
- `max_pbkdf2_iterations` 保留现有字段（`:638`），默认改为 200,000；少于 200,000 在 L1 前拒绝。

### 3.5 Nonce / salt / Freshness

- `salt16`：PNG/WAV/FLAC/JPEG 随机或 Seeded；HEVC 无 salt。
- `nonce12`：所有格式；AEAD nonce；HEVC 同时用于 `session_salt`。
- 现有 `Freshness`（`envelope.rs:264-316`）保留：
  - `Random`：CSPRNG；
  - `Seeded([u8;32])`：`salt(attempt,binding)`/`nonce(attempt,binding)`；
  - `binding` 由 `Freshness::seeded_binding(carrier,payload)`（`:286-292`）扩展为 `binding || u8(format_id) || u8(version_major) || u8(version_minor) || encode_extension(extensions)`；
  - JPEG 重试 `attempt` 递增，salt/nonce 随之变化；
  - HEVC `session_salt = SHA-256("strhide-hevc-session-v4"||nonce)`。
- **唯一性规则：** 同一 `(master, session_salt, nonce)` 只能对应同一明文；Seeded 重放同一输入得到字节级相同输出（可复现），不同 payload/载体/format/version/ext 必须改变 binding -> salt/nonce。
- 不得用计数器/固定 nonce；没有分块 AEAD，V4 仍是单信封单次 AEAD。

### 3.6 AAD

```text
AAD = b"strhide-content-envelope-v4\0"   // 28 bytes
    || u8(format_id)
    || base_header_bytes                  // 64 / 44 / 32
    || extension_bytes                    // encode_extension 的原始字节；0 时为空
```

- 包含全部 base Header 字段（version/flags/suite/body_len/salt/nonce/coding/CRC）与全部扩展 TLV。
- `pre_salt`/cover digest 已通过 L1 KDF 绑定，不重复放入 AAD。
- **JPEG 扩展区必须入 AAD**（当前实现缺失，`jpeg/engine.rs:881`、`:1288` 只有 superblock）；V4 修复。
- `header_crc32` 不是认证；AAD+AEAD tag 才是。

---

## 4. 校验顺序、限额、错误语义

### 4.1 固定顺序

1. 解析载体，计算 `pre_salt`；
2. `resolve_credential`；若凭据是 `Credential::Password` 且 `max_pbkdf2_iterations < 200_000`，立即失败（extract 返回 `NoHiddenData`，verify 记 L2 policy fail）；`FileKey` 不走 PBKDF2，不受该字段约束；
3. L1 -> L2；
4. 用 `locate_seed` 读取 base Header；
5. 校验 base：`version_major==4`、`format_id` 与载体一致（PNG/音频；JPEG/HEVC 由引擎固定）、`flags` 保留位 0、`suite_id` 已知、`body_len` 范围、`ext_len` 范围、`codec/stc_h/stc_u/算法参数` 范围、`header_crc32`；同时计算 `header_slots = base_slots + extension_slots(ext_len)`，若 `header_slots > carrier_total_slots` 立即失败（未认证 `ext_len` 不得越界读扩展槽）；
6. 读取扩展槽位（`ext_len` 已知且已证明可容纳）并解析 TLV；校验 `EXT_PRESENT`/`EXT_CRITICAL` 与 TLV critical 标志一致；
7. `ExtractParams::validate_header`：`allowed_suites`、`body_len <= min(HEADER_LEN_MAX, max_payload_bytes + BODY_OVERHEAD)`、header slots 可容纳、`suite` 允许；
8. 计算 Body 槽位/容量；若 `body_len*8` 超出 body slots -> 失败；
9. 读取 `body_len` 字节密文；
10. AEAD 解密 + tag 校验；
11. `unpack_envelope_parts` 校验 `orig_len <= max_payload_bytes`、解压 `.take(max+1)`；
12. 成功返回 `Payload`。

**硬规则：** 第 7 步之前不得进行代价图、Body STC、Body 大 `Vec` 分配；`body_len`/`ext_len` 只能用于有上限的结构检查。第 5 步必须先证明 `header_slots <= carrier_total_slots` 才允许第 6 步读取扩展槽。

### 4.2 `ExtractParams`（最终 API）

保留现有字段并新增：

```rust
// params.rs
pub struct ExtractParams {
    pub allowed_suites: Option<Vec<u16>>,       // 现有，None=1/2
    pub max_pbkdf2_iterations: u32,             // 现有，默认 200_000
    pub max_payload_bytes: usize,               // 新增，默认 MAX_PLAINTEXT_LEN
}

impl ExtractParams {
    pub fn with_max_payload_bytes(mut self, n: usize) -> Self; // 新增
    pub fn validate_header(
        &self,
        suite_id: u16,
        body_len: u32,
        header_slots: usize,
        carrier_slots: usize,
    ) -> Result<(), StrHideError>; // 新增
}
```

- `max_payload_bytes` 比较对象是解密后的 `orig_len`（`build_plaintext` 的 4B 长度）；不是 `body_len`。
- `body_len` 早期上限：`min(HEADER_LEN_MAX, max_payload_bytes.saturating_add(BODY_OVERHEAD))`。
- `max_pbkdf2_iterations` 比较对象是 `Credential::Password` 的固定 L1 200k；`<200k` 直接拒绝。`FileKey` 走 HKDF，不受该字段约束。
- `allowed_suites` 使用现有 `allows_suite`（`params.rs:652-656`）；V4 保持该字段名，不再引入第二套命名。

### 4.3 错误语义

| 失败点 | `extract` | `inspect` | `verify` |
|---|---|---|---|
| 定位/CRC/版本/格式/长度/参数 | `NoHiddenData` | `has_hidden_data=false` | L2 fail |
| suite 未知/被 `allowed_suites` 排除 | `NoHiddenData` | `has_hidden_data=false` | L2 fail（policy/unsupported） |
| TLV 未知 non-critical | 忽略 | 忽略 | note |
| TLV 未知 critical | `NoHiddenData`（不进入 Body） | `has_hidden_data=false` | L2 fail `UnsupportedVersion` |
| Body 槽位不足/截断 | `NoHiddenData` | n/a | L3 fail |
| AEAD tag 失败 | `NoHiddenData`（同一文案/同一错误类别） | n/a | L3 fail `authentication failed` |
| AEAD 成功后 frame/长度/解压失败 | `CorruptedData`/`Capacity` | n/a | L3 具体原因 |

- `extract` **绝不返回 `StrHideError::Password`**；错误消息固定为 `NoHiddenData("No valid payload found")`（不区分无数据/错口令/篡改/policy）。
- `verify` 才允许细分：L1 载体、L2 Header/策略、L3 AEAD/解帧；仍不得把“口令错误”与“数据损坏”拆成不同 L3 文案（统一 `authentication failed`）。

---

## 5. Header 扩展性与版本策略

### 5.1 Flags（所有载体同一语义）

| 位 | 名称 | 语义 |
|---:|---|---|
| 0 | `EXT_PRESENT` | `ext_len>0` 时必须 1，否则必须 0 |
| 1 | `EXT_CRITICAL` | 扩展中至少有一个 critical TLV；否则必须 0 |
| 2..7 | reserved | 必须 0 |

### 5.2 TLV

```text
tag   u8   bit7=critical；bits6..0=type（0 保留 padding）
len   u8   0..=255
value len bytes
```

- 编码：`encode_extension(&[Tlv]) -> Result<Vec<u8>, StrHideError>`（现有 `jpeg/header_v3.rs:247-303`，迁移到 `stego/header.rs` 并 re-export）。
- 解析：按 `tag/len/value` 顺序；type 0/len 0 视为 padding，跳过；`ext_len` 必须恰好覆盖所有 TLV，尾部只允许全 0 padding；否则 `CorruptedData`。
- 对齐：无填充对齐；TLV 紧邻；每个 value <=255。
- 未知 non-critical：忽略。
- 未知 critical：extract `NoHiddenData`；inspect `has_hidden_data=false`；verify L2 `UnsupportedVersion`。
- **扩展区不计入 header CRC**；计入 AAD。

### 5.3 版本

- `version` 1B：高 4 位 `major`，低 4 位 `minor`；V4.0 = `0x40`。
- `major`：
  - `<4`：不存在（无 legacy，直接不识别）；
  - `4`：V4；
  - `>4`：extract `NoHiddenData`；inspect/verify 在 Header 可读时 `UnsupportedVersion`；不按 V4 硬解析。
- `minor >0`：
  - base 布局不变；
  - 未知 non-critical TLV 忽略；
  - 未知 critical TLV -> `UnsupportedVersion`；
  - 未知 flags/reserved 位 -> `CorruptedData`（fail-closed）。
- **未来新增字段无需换 major 的路径：** 新字段一律放进 TLV；可选字段用 non-critical tag，旧 V4 解码器忽略；影响解码语义的字段用 critical tag，旧解码器 fail-closed；只有 base 布局/长度语义变化才换 major。
- `reserved` 必须 0；不得用 reserved 承载未来字段（避免旧解码器误读）。
- `ext_len` 是 base 字段；base 固定；扩展区只追加，不改变 base 偏移。

### 5.4 扩展对容量的挤压（写死）

| 载体 | header slots | 额外槽位/字节 |
|---|---:|---|
| PNG/WAV/FLAC | `512 + 8*ext_len` | 1 字节扩展 = 8 槽 |
| JPEG | `718 + 4*(8*ext_len+7)` | 1 字节扩展 = 32 槽（ext_h=8,ext_u=4） |
| HEVC | `if ext_len == 0 { 524 } else { 524 + 16*ext_len + 12 }` | 1 字节扩展 = 16 槽（stc_h=7,stc_u=2），初始偏移 12 槽 |

**容量公式（所有载体共用）：**

```text
H = base_header_slots + extension_slots(ext_len)
body_slots = carrier_total_slots - H                    // PNG 用 SlotPlan.count_body_slots；JPEG 用 n_total-H；HEVC 用 total_slots-H；音频用 total_usable-H
max_body_len = max { b in [BODY_OVERHEAD, HEADER_LEN_MAX] : codec_slots(b*8) <= body_slots }
max_raw_payload = max_body_len.saturating_sub(BODY_OVERHEAD)
```

- `codec_slots`：Hamming = `b*8`；STC = `StcTrellis::slots_for(b*8)`（现有 STC 求解器）。
- **probe 与 embed 必须调用同一个 `compute_capacity(plan, codec, ext_len, params)`**，不得各写一套。
- `probe` 的 `extensions` 通过 `encode_extension` 得到 `ext_len`；`embed` 用同一函数；二者 `HeaderSlotPlan` 相同、`Credential` 相同、`pre_salt` 相同。

---

## 6. 代码影响面（完整）

### 6.1 删除/替换的旧类型与字段

| 文件:行 | 旧对象 | 处理 |
|---|---|---|
| `stego/format.rs:46-110` | `Kdf`/`Aead`/`CipherSuite` | 删除，统一 `CipherSuiteId` |
| `stego/format.rs:113-143` | `SUITE_PBKDF2_200K`/`SUITE_PBKDF2_600K`/`RESERVED_SUITE_ARGON2ID`/`SUITES`/`DEFAULT_SUITE_ID` | 删除；V4 suite 1/2 重定义见 §3.4 |
| `stego/format.rs:245-275` | `JpegFormatProfile` 的 `format_major`/`format_minor`/`hpos_label`/`stc_label`/`enc_label`/`perm_label`/`suites` | 删除；label 移到 `WireCipherProfile`，`format` 固定 V4 |
| `stego/format.rs:294-308` | `JpegFormatProfile::header_slots`/`default_suite` 的旧 suite 语义 | 重写：`header_slots(ext_len)` 只按 `ext_h/ext_u` 计算；`default_suite` 从 `WireCipherProfile.default_suite` |
| `stego/format.rs:434-456` | `PngFormatProfile` 的 `fallback_secret`/`domain_label`/`hpos_label`/`stc_label`/`body` | 删除；改为 `hpos_salt` + `cipher` |
| `stego/format.rs:466-479` | `AudioFormatProfile` 同名字段 | 删除；改为 `hpos_salt` + `cipher` |
| `stego/format.rs:486-501` | `AUDIO_BODY_FORMAT` | 删除 |
| `stego/format.rs:198-224` | `HevcFormatProfile.kdf_info`/`header_bytes` | 删除；改为 `cipher` + 固定 32B/16B tag 常量 |
| `stego/params.rs:349-350` | `JpegParams.cipher_suite` | 删除；suite 改由 `EmbedOptions.suite_id` |
| `stego/params.rs:374-376` | `JpegParams.extensions` | 删除；统一 `EmbedOptions.extensions` |
| `stego/params.rs:528-530`、`:577` | `JpegParams` 默认值/`validate` 对 `cipher_suite`/`extensions` 的处理 | 删除对应字段和校验 |
| `stego/format.rs:377-381` | `JpegFormatProfile` 的 `suites` 校验 | 删除（suite 允许列表移到 `ExtractParams`） |
| `stego/header.rs:30-345` | `HEADER_V2_ESCAPE_H`/`encode_header_word`/`decode_header_word`/`FeatureWord`/`FEATURE_WORD_*`/`V2_TOTAL_HEADER_SLOTS` | 实现 `SpatialHeaderV4`/`Tlv`/`encode_extension`/`parse_extension`；PNG 切至 `SpatialHeaderV4`（Step 5）；旧 `FeatureWord`/`V2_TOTAL_HEADER_SLOTS` 在音频迁移完成后（Step 6）删除 |
| `stego/envelope.rs:65,83` | `HEADER_OVERHEAD=28`/`MIN_ENVELOPE_LEN=50` | 删除；只保留 `BODY_OVERHEAD=22`（现有 `:81`） |
| `stego/envelope.rs:135-207` | `derive_header_perm_seed*` | 删除；改 `derive_l2_locator_keys`/`derive_l3_session_keys` |
| `stego/jpeg/header_v3.rs:67-211` | 旧 `Superblock` 的 `version_minor`/`flags`/`ext_bytes` 语义 | 替换为 `JpegSuperblockV4`，44B 布局见 §2.3 |
| `stego/options.rs:304`、`cli/helpers.rs:325`、`examples/private_format.rs:35` | 跨模块/示例对 `params.cipher_suite` 与旧 `JpegFormatProfile` 字段的引用 | Step 7 同步更新为 V4 选项与 `OFFICIAL_JPEG_CIPHER`，确保 `--all-targets` 编译通过 |

> 删除动作按 §7 分步执行：PNG 在 Step 5 切换；音频在 Step 6 切换并删除 `FeatureWord`；JPEG 在 Step 7 切换并同步更新 cli/examples/tests；HEVC 在 Step 8 切换；全局旧 `CipherSuite/HEADER_OVERHEAD` 在 Step 9 删除。

### 6.2 新增/修改的公共类型与签名

| 文件 | 对象 | 类型/签名（新增标 ★） |
|---|---|---|
| `core/crypto.rs` | ★ `Credential<'a>` | `enum { Password(&'a str), FileKey(&'a [u8;32]) }` |
| `core/crypto.rs` | ★ `CipherSuiteId` | `enum { Aes256Gcm=1, ChaCha20Poly1305=2 }` + `from_u16/tag_len/name` |
| `core/crypto.rs` | ★ `CONTENT_L1_PBKDF2_ITERATIONS` | `u32 = 200_000` |
| `stego/options.rs` | ★ `resolve_credential` | `fn(password:Option<&str>, key:Option<&[u8;32]>, dialect:&StegoProfile)->Result<Credential,StrHideError>`；不能放 `core` |
| `stego/engine.rs` | ★ `PreparedCarrier` | `{ pre_salt:[u8;32], master:[u8;32], locator:HeaderLocatorKeys }`；inspect/extract/verify 共享 |
| `stego/format.rs` | ★ `WireCipherProfile` | `{ domain_label, hpos_label, enc_label, perm_label, stc_label, default_suite }` |
| `stego/format.rs` | ★ `HeaderLocatorKeys`/`SessionKeys` | `{ locate_seed,header_stc_seed,ext_stc_seed,magic4 }` / `{ enc_key,perm_seed,stc_seed }` |
| `stego/format.rs` | ★ `derive_locator_master` | `fn(cred,domain,cipher,pre_salt)->Result<[u8;32],StrHideError>` |
| `stego/format.rs` | ★ `derive_l2_locator_keys` | `fn(master,cipher,magic_label,domain)->Result<HeaderLocatorKeys,StrHideError>` |
| `stego/format.rs` | ★ `derive_l3_session_keys` | `fn(cipher,suite,master,session_salt,domain)->Result<SessionKeys,StrHideError>` |
| `stego/format.rs:245-275` | 修改 `JpegFormatProfile` | `{ cover_digest_tag, cipher:&'static WireCipherProfile, sb_bytes,sb_h,sb_u,ext_h,ext_u,grid_rule }` |
| `stego/format.rs:434-447`、`:466-478` | 修改 `PngFormatProfile`/`AudioFormatProfile` | `{ hpos_salt:&'static [u8], cipher:&'static WireCipherProfile }` |
| `stego/format.rs:190-224` | 修改 `HevcFormatProfile` | `{ magic_label,cover_salt,cipher:&'static WireCipherProfile,stc_h,stc_u }` |
| `stego/format.rs:415-430`、`:449-456`、`:504-510`、`:512-525`、`:217-224` | 更新 `DEFAULT_JPEG_FORMAT`/`OFFICIAL_PNG_FORMAT`/`OFFICIAL_WAV_FORMAT`/`OFFICIAL_FLAC_FORMAT`/`DEFAULT_HEVC_FORMAT` | `cipher` 指向 ★ `OFFICIAL_*_CIPHER`；`JpegFormatProfile` 去旧 suite/format 字段 |
| `stego/format.rs`（新增常量） | ★ `OFFICIAL_PNG_CIPHER`/`OFFICIAL_AUDIO_CIPHER`/`OFFICIAL_JPEG_CIPHER`/`OFFICIAL_HEVC_CIPHER` | PNG/Audio/JPEG 沿用现有 label（`format.rs:418-422,451-454,489-493`）；HEVC 新增 `hpos_label=b"strhide-hevc-hpos-v4"`、`enc_label=b"strhide-hevc-enc-v4"`、`perm_label=b"strhide-hevc-perm-v4"`、`stc_label=b"strhide-hevc-stc-v4"`，`domain_label` 复用 `b"strhide-stego-domain-v1"` |
| `stego/header.rs` | ★ `SpatialHeaderV4` | 字段见 §2.2；`encode()->[u8;64]`；`decode(&[u8;64], expected_format:u8)->Result<Self,StrHideError>` |
| `stego/header.rs` | ★ `Tlv`/`encode_extension`/`parse_extension` | 复用现有 `Tlv{type_id:u8,value:Vec<u8>}`/`encode_extension(&[Tlv])->Result<Vec<u8>,_>`（`jpeg/header_v3.rs:229-303`）；迁移到 `header.rs` 并在旧路径 `pub use` |
| `stego/jpeg/header_v3.rs` | ★ `JpegSuperblockV4` | 字段见 §2.3；`encode()->[u8;44]`；`decode(&[u8;44])->Result<Self,StrHideError>` |
| `stego/hevc/engine.rs` | ★ `HevcSuperblockV4` | 字段见 §2.4；`encode()->[u8;32]`；`decode(&[u8;32], magic4:[u8;4])->Result<Self,StrHideError>` |
| `stego/envelope.rs` | ★ `build_v4_aad` | `fn(format_id:u8, base_header:&[u8], ext:&[u8])->Vec<u8>` |
| `stego/envelope.rs:494-523` | 修改 `unpack_envelope_parts` | 新增参数 `limits:&ExtractParams`；`suite: CipherSuiteId` 取代 `&CipherSuite` |
| `stego/params.rs:627-639` | 修改 `ExtractParams` | 新增 `max_payload_bytes:usize`；`with_max_payload_bytes(self,n)->Self`；★ `validate_header(&self,suite_id,body_len,header_slots,carrier_slots)->Result<(),StrHideError>` |
| `stego/params.rs:130-182` | 修改 `PngParams` | 现有字段仅 `p1_window/p2_window/epsilon/exclusion_percentile/codec/stc_h/stc_u/algorithm_options`；Header 的 `channel_mode/class_rule` 由 `ChannelMode`/`class_rule=1` 引擎侧产生（`png/engine.rs:939-982`、`:1474-1475`），`sigma` 从 `algorithm_options["sigma"]` 读取（`:1493-1505`），`exclusion_permille` 由 `exclusion_percentile` 量化（`params.rs:203-213`），`kernel_id` 固定 0；不新增这些 `PngParams` 字段 |
| `stego/options.rs:451-471` | 修改 `EmbedOptions` | 新增 `key:Option<&[u8;32]>`、`suite_id:Option<u16>`、`extensions:Vec<Tlv>`；`with_key/with_suite_id/with_extensions` |
| `stego/options.rs:812-823` | 修改 `ExtractOptions` | 新增 `key:Option<&[u8;32]>`、`new()`、`with_key`、`with_max_payload_bytes`；现有 `with_allowed_suites` 保留 |
| `stego/options.rs:683-697` | 修改 `ProbeOptions` | 新增 `key:Option<&[u8;32]>`、`extensions:Vec<Tlv>`；`with_key/with_extensions` |
| `stego/options.rs:916-933` | 修改 `BridgeOptions` | 新增 `key:Option<&[u8;32]>`、`suite_id:Option<u16>`、`extensions:Vec<Tlv>`；在 `stego/engine.rs` 中完整透传至 `thumb_bridge` |
| `stego/options.rs:1126-1130`、`:1244-1248` | 修改 `InspectOptions`/`VerifyOptions` | 新增 `key:Option<&[u8;32]>`、`with_key`；现有 `new/with_limits` 保留 |
| `stego/png/engine.rs:81-96` | 修改 `RawImage` | 新增 `bit_depth:u8`、`color_type:u8`（现有字段 `:81-96`） |
| `stego/png/engine.rs:1030-1040`、`:1049-1111` | ★ `header_layout`/`SlotPlan::build` | 新参数 `locate_seed:&[u8;32]`、`ext_len:usize`；`header_slots = 512+8*ext_len` |
| `stego/png/engine.rs:2223-2251` | ★ `probe_png_capacity` 路径 | 用 `resolve_credential` + `encode_extension`，不再 zero seed；`with_extensions` |
| `stego/audio/mod.rs:34-43` | ★ `flac_phases` | `fn(locate_seed:&[u8;32])->(u64,u64)`（现有 `:34-43` 改为从 seed 切片） |
| `stego/audio/mod.rs:150-190` | 修改 `extract_flac`/`embed_flac` | 两阶段抽稀：Pass 1 读取 512 基础槽位获取 `ext_len`；Pass 2 提取扩展槽位与 Body 槽位 |
| `stego/audio/flac/mod.rs:375-454` | 修改 `FlacCarrier::new` | 新增 `ext_slots:usize`；Base 槽位固定 `wanted=512`；扩展槽位从剩余 `tails` 独立抽稀，避免前 512 槽位漂移 |
| `stego/audio/mod.rs:193-223`、`:407-450` | 修改 `probe_flac`/`probe_wav` | 新增 `PreparedCarrier`/`extensions` 参数；容量与 embed 同源（`:193` 现有签名，`:407` 现有签名） |
| `stego/audio/core.rs:172-215` | 修改 `SlotPlan` | 存储 `header_slots:usize`；`body_slot(i)` 从 `header_slots + i` 偏移，避免覆盖扩展槽位 |
| `stego/audio/core.rs:425-475`、`:519-720`、`:780-900` | 修改 `read_header`/`embed`/`extract` | 读写 `SpatialHeaderV4`；`header_slots = 512+8*ext_len`；使用 `cipher` |
| `stego/jpeg/engine.rs:208-226`、`:1151-1319` | 修改 `CoverFrame`/`extract`/`inspect` | `pre_salt` 用 `cover.digest`；AAD 含 extension；`JpegSuperblockV4`；`limits` |
| `stego/hevc/engine.rs:202-211` | 修改 `superblock_positions` | `fn(pool_size:usize, locate_seed:&[u8;32], ext_len:usize)->Result<Vec<usize>,StrHideError>`；置换 `524 + hevc_extension_slots(ext_len)` 槽位 |
| `stego/hevc/engine.rs:1489-1511` | ★ `band_positions` | `fn(bands:&[Band], count:usize, stc_seed:u64)->Vec<usize>`，keyed stride/start |
| `stego/hevc/engine.rs:613-681` | 修改 `build_hevc_capacity_info` | `H = 524 + hevc_extension_slots(ext_len)`；`body_slots=total_slots-H`；`max_body_len` 用统一 `compute_capacity` |
| `stego/hevc/engine.rs:52-59`、`:3228-3308` | 修改 `derive_hevc_key`/`derive_magic`/`trellis_seed_from_key` | 删除；改 L1/L2/L3 |
| `stego/engine.rs:528-534` | 修改 `hevc_extract` | 删除 `StrHideError::Password` 死分支，统一 `Err(bridge_err)` |
| `lib.rs:251` | 导出 | `CipherSuiteId`/`Credential`/`WireCipherProfile` 新位置；删除旧 `CipherSuite` 导出 |
| `rust/Cargo.toml:96-121` | 依赖 | 新增 `chacha20poly1305 = "0.11"`（与 `aes-gcm` 同 RustCrypto AEAD） |
| `gui/src-tauri/src/commands/stego.rs:257-263` | Tauri 请求 | 现有 `ExtractOptions.limits` 保留；新增 key/suite/ext 字段随 command 结构同步 |

> 所有 options 的手写 `PartialEq` 必须加入新增 `key`/`suite_id`/`extensions` 比较；手写 `Debug` 必须把 `key`/`password` 显示为 `"<redacted>"`。`Tlv` 已实现 `Clone/PartialEq/Eq`（`jpeg/header_v3.rs:228-234`）。

### 6.3 保留的类型/字段（已核实）

- `StegoProfile.default_secret`（`params.rs:683`）、`StegoProfile.domain`（`:685`）、`audio`（`:705`，本方案保留单字段；WAV/FLAC 共用同一私有 `AudioFormatProfile`，这是确定取舍）。
- `Freshness`（`envelope.rs:264-316`）、`BODY_OVERHEAD`（`:81`）、`PUBLIC_DEFAULT_SECRET`（`:60`）。
- `ExtractParams.allowed_suites/max_pbkdf2_iterations`（`params.rs:633-638`）、`ExtractOptions.with_allowed_suites`（`options.rs:865-868`）。
- `ProbeOptions.password/domain/safety/tuning/exact/control/pool`（`options.rs:683-697`）。
- `RawImage.chunks/idat_sizes`（`png/engine.rs:81-96`）、`PngChunk{ty,data}`（`:130-133`）。
- `WavLayout` 字段（`audio/wav.rs:43-57`）、`StreamInfo` 字段（`audio/flac/mod.rs:86-94`）。
- `JpegFormatProfile.ext_h/ext_u`（`format.rs:268-270`）、`superblock_slots/extension_slots`（`:283-291`）。
- `Tlv` 字段（`jpeg/header_v3.rs:229-234`）、`encode_extension`（`:247-303`）。

---

## 7. 分步实施计划（每步独立编译/测试/回滚）

> 每一步都基于上一步提交；每步结束必须 `cargo build --all-features` + `cargo test --all-features --all-targets` 通过。任一 Step 失败只回滚该 Step 的提交，不影响已落地的前序 Step。

### Step 0：冻结测试向量（无源码）
- 产出：三种 base 布局的 golden hex、TLV golden、L1/L2/L3 向量（固定口令/FileKey/pre_salt/domain）。
- 验收：向量审查通过；后续测试直接引用；`git diff` 只有文档。

### Step 1：`ExtractParams` + options + core 密码类型
- 改：`core/crypto.rs` 新增 `Credential/CipherSuiteId/CONTENT_L1_PBKDF2_ITERATIONS`；`stego/options.rs` 新增 `resolve_credential`；`ExtractParams.max_payload_bytes` + `with_max_payload_bytes`；`ExtractOptions::new/with_key/with_max_payload_bytes`；`ProbeOptions.key/extensions/with_key/with_extensions`；`InspectOptions/VerifyOptions.key/with_key`；`EmbedOptions.key/suite_id/extensions/with_*`。
- 不改 wire。
- 验收：`cargo test --all-features --all-targets`；新增单元测试覆盖 `max_payload_bytes` 默认值、`resolve_credential` 优先级/互斥、`ExtractParams` builder；`cargo clippy ... -D warnings`。

### Step 2：`WireCipherProfile`（仅新增类型）
- 改：`stego/format.rs` 新增 `WireCipherProfile`（5 个 label + `default_suite`）；不删除旧 profile 字段，不改任何引擎/wire。
- 验证：`cargo check --all-features`；`cargo test --all-features --all-targets`；`import_lint`；无 unused/dead_code warning（`WireCipherProfile` 为 `pub`）。
- 回滚：只回滚 `format.rs` 新增段。

### Step 3：L1/L2/L3 + 单元向量
- 新增 `derive_*`/`HeaderLocatorKeys`/`SessionKeys`；`HeaderLocatorKeys` 包含 `ext_stc_seed`；`resolve_credential` 集成。
- 验证：固定向量（Password/FileKey/domain/format）逐字节比较；`max_pbkdf2<200k` 拒绝；无 `expect` panic。
- 回滚：只回滚 KDF 函数/测试。

### Step 4：Header 类型 + TLV + golden
- 新增 `SpatialHeaderV4`/`JpegSuperblockV4`/`HevcSuperblockV4`/`build_v4_aad`/`Tlv` 迁移；`encode/decode` 与 CRC 边界测试。
- 验证：每个布局的 offset/总长/CRC 覆盖断言；TLV critical/noncritical/padding；不接线引擎。
- 回滚：只回滚 header/envelope 新类型。

> Step 5-8 的每个 `verify_*` 都必须复用同一个 `PreparedCarrier`；测试用计数器断言 `derive_locator_master` 每格式只调用 1 次。

### Step 5：PNG V4（含 Hamming/STC + ext）
- 改：`RawImage` 加 `bit_depth/color_type`；`compute_png_pre_salt` 排除 `IDAT` 与 `prIv`（保障与结构域 `write` 共存）；`PngFormatProfile` 切到 `hpos_salt + cipher`；`header_layout`/`SlotPlan::build` 接 `locate_seed`/`ext_len`；`probe_png_capacity` 同源；`embed/extract/inspect/verify` 用 `SpatialHeaderV4`/`Tlv`/`build_v4_aad`；保留 `FeatureWord` 供 Step 6 音频模块引用；更新 PNG 相关测试。
- 验收：PNG Hamming + STC 往返；ext 0/1 TLV；`probe==embed` 容量；tamper/truncate；`png_stress`；`cargo test --all-features --all-targets`。

### Step 6：WAV/FLAC V4
- 改：`AudioFormatProfile` 切到 `hpos_salt + cipher`；删除 `AUDIO_BODY_FORMAT`；`WavLayout`/`StreamInfo` pre_salt；`flac_phases(locate_seed)`；`core::SlotPlan` 动态存储 `header_slots` 避免覆盖扩展区；`flac/mod.rs` 两段式抽稀（Base 512 恒定 + 扩展区独立抽稀，避免 Base 漂移与越界）；`core::read_header/embed/extract`；`audio` 探测/验证；音频迁移完成后正式删除旧 `FeatureWord` 与 `V2_TOTAL_HEADER_SLOTS`。
- 验收：WAV/FLAC 往返；ext 0/1；probe==embed；`audio_stress`；负测（truncate/tamper）。

### Step 7：JPEG V4
- 改：`JpegFormatProfile` 切到 `cover_digest_tag + cipher + 几何`，删除 `format_major/minor/suites` 与旧 label 字段；`JpegSuperblockV4`；`CoverFrame` pre_salt；AAD 含 extension；`extract_jpeg_from` 删 `for suite`；`JpegParams.cipher_suite/extensions` 删除；同步修改 `options.rs:304`、`cli/helpers.rs:325`、`examples/private_format.rs:35-50`、`tests/test_lifecycle/` 引用，确保 `--all-targets` 编译通过。
- 验收：`jpeg_stress`；J-UNIWARD/UERD/J-MiPOD；ext TLV 0/1；AAD 篡改；`cargo test --all-features --all-targets`。

### Step 8：HEVC V4
- 改：`HevcFormatProfile` 切到 `magic_label/cover_salt/cipher/stc_h/stc_u`，删除 `kdf_info/header_bytes`；`HevcSuperblockV4`（`ext_len <= 64`）；扩展区采用 STC（`h=7, u=2`）与 `ext_stc_seed` 并参与重编码冲突避让；L1 PBKDF2；`superblock_positions(pool,seed,ext_len)` 置换 `524 + hevc_extension_slots(ext_len)` 槽位；`band_positions` keyed；`build_hevc_capacity_info` 新公式；`BridgeOptions` 补齐 key/suite/ext；清理 `engine.rs` 中 dead password 分支；`embed/extract` 用 `build_plaintext`/`unpack`；`ExtractParams`。
- 验收：HEIF/MP4/MKV/Annex-B 往返；ext 0/1；probe==embed；`hevc_stress`；`heavy_dual_domain_coexistence_matrix`；负测。

### Step 9：CLI/GUI/文档/基线/清理
- 改：CLI `--suite`/`--key-file`（新增）与 `max-payload` 选项；GUI Tauri command 字段；`WIRE_SPEC`/`STEGO-API`/`ARCHITECTURE`/`README`；删除旧 suite 常量/旧 `FeatureWord`/旧 `HEADER_OVERHEAD` 残留；`baseline_hash --write` 重建；`--check`。
- 验收：§8 全矩阵 + §9 全质量流程；`baseline_hash --check` 全绿；`import_lint` 全绿。

---

## 8. 测试矩阵

### 8.1 正向

- 5 格式 × suite 1/2 × `Credential::Password`/`FileKey` × payload 0/1B/1KiB/1MiB/接近容量 × `Freshness::Random`/`Seeded` × `extensions=[]/1 noncritical`（V4 尚未定义已知 critical TLV；critical 只用于负测“未知 critical”）。
- PNG Hamming/STC；JPEG STC；HEVC STC；WAV/FLAC 的 Hamming/STC（按实际支持）。
- 同一口令/FileKey 在不同 format/domain 不可互读；不同 `suite_id` 派生不同密钥（`u16be(suite)` 进入 L3 info）。
- `probe` 与 `embed` 在相同 credential/extensions/safety 下 `recommended_max_bytes` 一致。
- `verify` L1/L2/L3 全通过；`inspect` 仅 header。
- 结构域 + 内容域双域共存。

### 8.2 负面（必须）

| 用例 | 期望 |
|---|---|
| Header 截断（少 1B/少 CRC/少 ext） | `extract` `NoHiddenData`；无越界/panic |
| Body 截断（少 1B/少 16B tag/全截断） | `NoHiddenData`；不按 `body_len` 大分配 |
| `body_len=0`、`<22`、`>HEADER_LEN_MAX`、>body slots、>max_payload+22 | Header 后立即拒绝；不进入 Body STC |
| 伪造 `body_len` 大值 | Header 后 `max_body_len`/`max_payload` 检查拒绝，无大分配 |
| 翻转 Header 任意 bit | CRC 失败（意外损坏路径） |
| 翻转 Header 后**重算 CRC** | CRC 通过但 AEAD tag 失败；`extract` `NoHiddenData` |
| 翻转 Body 任意 bit | AEAD 失败 |
| 未知 suite_id / allowed_suites 排除 | Header 后拒绝；不执行 L3/body |
| 未知 critical TLV | `extract` `NoHiddenData`；verify `UnsupportedVersion` |
| 未知 non-critical TLV | 忽略，payload 成功 |
| ext_len 超限/与 flags 不一致/TLV 截断 | 结构拒绝 |
| nonce 重用（同 seed 不同 payload/载体/format/ext） | salt/nonce 必须变化；同输入字节级确定性 |
| FileKey 与 Password 同时提供 | `General` 互斥错误 |
| 无口令 `probe` vs 无口令 `embed` | 容量一致；两者均执行 1 次 L1 |
| `Password` + `max_pbkdf2_iterations < 200_000` | L1 前拒绝；不跑 PBKDF2；`FileKey` 不受限 |
| `max_payload_bytes=128` + 1KiB payload | 若 `body_len>128+22` 在 Header 后拒绝；若压缩后 `body_len<=150` 但 `orig_len>128`，在 AEAD 后 `Capacity` 拒绝 |
| `extract` 错口令/无数据/篡改 | 同一 `NoHiddenData` 文案/类别 |
| `verify` 错口令/篡改 | L3 `authentication failed`，不拆口令/损坏 |
| 旧 v2/v3 样本 | 不复存在；v4-only 构建返回 `NoHiddenData`/`UnsupportedVersion`（无 legacy） |
| `baseline_hash --check` | 全绿；v4 首次 `--write` 后 `--check` |

### 8.3 命令

```bash
cd rust
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release --all-features
cargo test --all-features --all-targets
cargo test local_ --all-features -- --ignored
cargo test heavy_ --all-features -- --ignored
cargo run --release --all-features --example png_stress
cargo run --release --all-features --example jpeg_stress
cargo run --release --all-features --example hevc_stress
cargo run --release --all-features --example audio_stress
python ../scripts/import_lint.py
python ../scripts/baseline_hash.py --write   # 仅 V4 输出切换时
python ../scripts/baseline_hash.py --check
```

---

## 9. 质量与发布流程

1. `cargo fmt --check` 必须 0 diff；
2. `cargo clippy --all-targets --all-features -- -D warnings` 必须 0 warning；
3. `cargo build --release --all-features` 必须成功，产物 `target/release/strhide` 用于 baseline；
4. `cargo test --all-features --all-targets` 必须全绿；
5. `cargo test local_ --all-features -- --ignored`、`heavy_ --ignored`；
6. 四个 stress example；
7. `python scripts/import_lint.py`；
8. V4 输出变化后先 `baseline_hash.py --write`，再 `--check`；两者都必须是同一二进制、同一 feature set；
9. 最终提交前 `git status` 只包含预期文件；不修改 `.git`；不 `commit/push`（除非用户另行要求）。

---

## 10. 风险与回退

| 风险 | 影响 | 处理/回退 |
|---|---|---|
| PBKDF2 200k 让无口令 probe 变慢（约 30-100ms） | GUI/CLI 容量卡片延迟 | 保留正确性优先；GUI 缓存 `probe` 结果；不恢复零种子 |
| 扩展 TLV 挤压容量 | 大 ext 下 payload 变小 | probe/embed 同源 `H=base+ext_slots`；写入前 `Capacity` 拒绝 |
| 删除旧 suite/字段导致大量编译错误 | Step 2/7/9 返工 | 按 §7 分步提交；每步只改相关文件；回滚该提交 |
| HEVC `band_positions` 密钥化改变输出 | baseline 全变 | 预期；Step 8 后统一 `--write`；旧 v2 不读 |
| JPEG 扩展 AAD 改变 | v3 不读；v4 baseline 变 | 预期；无 legacy |
| `ChaCha20-Poly1305` 依赖新增 | 构建时间/供应链 | 固定版本；仅 `content-*` 使用；不用的 feature 仍可编译 |
| CRC 仍非认证 | 只能防意外损坏 | AAD/AEAD 认证；负面测试覆盖“重算 CRC”；不宣称 CRC 防篡改 |
| `pre_salt` 对同元数据载体不唯一 | 相同尺寸/元数据共享 L1 salt | 文档明确边界；PBKDF2 200k 提高成本；不冒充 per-file 唯一 |

**回退策略：** 每个 Step 一个独立提交；出问题 `git revert <step-commit>` 即可回到上一可编译状态。Step 9 之前不删除旧 suite 常量（只新增），Step 9 一次性删除；若 Step 9 失败，回滚 Step 9，保留 V4 引擎 + 旧常量不影响运行（但不符合最终“无 legacy”，需修复后再发）。

---

## 11. 审查问题闭环对照（7 Blocking + 15 Major）

### 11.1 Blocking

| 编号 | 旧问题 | 最终处理（本文位置） |
|---|---|---|
| B-1 | `ExtractParams` API 不存在 | §4.2 明确新增 `max_payload_bytes`/`with_max_payload_bytes`；`ExtractOptions::new`/`with_max_payload_bytes`；保留 `allowed_suites`；§6.2 签名 |
| B-2 | 限额放在 Body 提取后 | §4.1 固定顺序第 7 步在 Body 槽位前 `validate_header`；`unpack` 只做 AEAD 后 `orig_len` 二次检查 |
| B-3 | CRC 被当认证，`body_len` 驱动大分配 | §4.1 第 5/7 步硬上限；§4.3 CRC 只防意外；AAD/AEAD 认证；§5.1 flags；§10 风险 |
| B-4 | PNG 无密码 probe 零种子容量不一致 | §0/§1/§4 规定 probe 与 embed 同 `Credential`/`pre_salt`/`SlotPlan`；§10 明确接受 200k 成本 |
| B-5 | `pre_salt` 引用 `RawImage` 不存在字段 | §3.3 新增 `RawImage.bit_depth/color_type`（§6.2）；WAV 用 `kind.bits()` |
| B-6 | 旧 suite 类型/字段未清理 | §3.4/§6.1 删除 `CipherSuite/Kdf/Aead/SUITES/SUITE_PBKDF2_*`、`JpegParams.cipher_suite`、`JpegFormatProfile.suites/format_major/minor` |
| B-7 | HEVC 容量公式混用 | §5.4/§6.2 `H=524+8*ext_len`、`body_slots=total-H`、`max_body_len` 统一；删除 `header_bytes` |

### 11.2 Major

| 编号 | 旧问题 | 最终处理 |
|---|---|---|
| M-1 | 32MiB 默认退化 | §4.2 `max_payload_bytes = MAX_PLAINTEXT_LEN`（67,108,863）；业务可改默认（已写明） |
| M-2 | nonce/Freshness 缺失 | §3.5 使用现有 `Freshness` + binding 扩展 + HEVC session_salt；§8 重用测试 |
| M-3 | pre_salt 不唯一/PLTE 删除 | §3.3 PNG 加入非 IDAT chunk meta/PLTE；明确“不保证 per-file 唯一”，不宣称彩虹表 |
| M-4 | CRC 测试/安全结论 | §4.1/§4.3 CRC 仅意外；§8 增加“重算 CRC 后 AEAD 拒绝” |
| M-5 | HEVC body band 未密钥化 | §6.2 `band_positions(..., stc_seed)` keyed；§4 容量/§8 测试 |
| M-6 | `JpegFormatProfile` 清理不完整 | §6.1/§6.2 删除 `suites/format_*`；保留 `ext_h/ext_u/sb_h/sb_u/grid_rule` 用于 V4 几何 |
| M-7 | `ExtractParams` 命名/语义 | §4.2 保留 `allowed_suites`；`max_pbkdf2_iterations` 默认 200k；新增 `max_payload_bytes` |
| M-8 | FileKey 只加 Embed/Extract | §6.2 四个 options + `EmbedOptions` 均加 `key`；§3.1 统一 resolver |
| M-9 | 删除 flags/TLV/minor 锁死扩展 | §2/§5 每种载体加 `flags` + `ext_len` + TLV；`version_minor`；§5.3 未来字段路径 |
| M-10 | `WireCipherProfile` 3 vs 5/无 allowlist | §3.2 定义为 5 个 label + `default_suite`；allowlist 在 `ExtractParams`；§6.2 |
| M-11 | 实施步骤不可独立验证 | §7 拆成 Step 0..9，每步 `cargo test/clippy` 验收，独立提交/回滚 |
| M-12 | 负面测试缺失 | §8.2 全表覆盖截断/长度/重算 CRC/未知 TLV/nonce/FileKey/probe/baseline |
| M-13 | 基线/质量流程不完整 | §8.3/§9 完整命令；`--write` 后 `--check` |
| M-14 | verify 重复 L1 | §3.2 新增 `PreparedCarrier` 并在 Step 5-8 复用；§8 KDF 次数断言 |
| M-15 | suite id 1/2 重定义无迁移说明 | §3.4 append-only 表；§6.1 删除旧常量；§9 重建基线/文档 |

### 11.3 Minor 修正

- 所有路径行号以本文章节引用为准；旧文档中的 `jpeg/engine.rs:109`（实际 `CoverFrame:208-226`）、`hevc:849/1671/630`（实际 `819/1562/613`）、`RawImage:103`（实际 `81-96`）、`WavLayout:44`（实际 `43-57`）已修正。
- `WireCipherProfile` 5 标签 + `default_suite`；不再有“3 标签”矛盾。
- `ExtractParams` 统一 `allowed_suites`；`header_crc32` 覆盖范围明确；`Tlv`/`encode_extension` 统一。
- `pre_salt` 中 JPEG/HEVC 的 tag/salt 冗余保留，原因是域分离；不改变安全。

### 11.4 终审核对补丁闭环（FIX-01 ~ FIX-05）

| 编号 | 问题定位 | 根因与危害 | 闭环方案（正文落位） |
|:---:|---|---|---|
| **FIX-01** | PNG `pre_salt` 破坏双域共存 | `meta` 遍历 `!= b"IDAT"`，将结构域注入的 `prIv` 块误算进哈希，导致 `embed content -> write structure` 载体内容域提取 100% 失败 | §3.3 显式排除 `prIv` 块；`meta` 仅哈希 `!= b"IDAT" && != b"prIv"` 的块 |
| **FIX-02** | 音频槽位覆盖与 FLAC 抽稀越界 | (1) `audio/core.rs` 的 `SlotPlan` 硬编码 512，`ext_len>0` 时 Body 覆盖扩展槽；(2) `FlacCarrier::new` 固定抽 512 槽，改 `wanted` 会导致 Base 槽位索引漂移，提取 Pass 1 读扩展槽越界 Panic | §6.2 / Step 6：`SlotPlan` 动态存储 `header_slots`；FLAC 采用 Base 512 恒定抽稀 + 扩展区独立抽稀两阶段设计 |
| **FIX-03** | HEVC 扩展区 EPB 冲突重编码失败 | 扩展区仅 `8*ext_len` 裸槽位（无 STC 冗余），一旦触发 CABAC `0x00 0x00 0x03` 防竞争冲突或 BadSubstream，无法避让 `forbidden` 槽位导致求解失败 | §2.4 / §5.4 / §6.2：扩展区统一采用 STC（`h=7, u=2`），槽位数 $16 \times \text{ext\_len} + 12$；`HEVC_MAX_EXT_BYTES` 设为 64B |
| **FIX-04** | 跨模块同仓引用导致分步编译中断 | Step 5 删 `FeatureWord` 导致未迁移的音频模块无法编译；Step 7 删 `params.cipher_suite` 导致 `options.rs:304`、`cli/helpers.rs:325`、`private_format.rs:35` 编译失败 | §6.1 / Step 5-7：延后 `FeatureWord` 至 Step 6 删除；Step 7 同步更新 cli/options/examples/tests 引用，确保每步 `--all-targets` 绿通 |
| **FIX-05** | 扩展区 STC 独立种子与 HEIF 透传 | (1) Base 与 Ext 共用 STC 种子存在相关性隐患；(2) HEIF 缩略图 `BridgeOptions` 未透传 key/suite/ext；(3) `hevc_extract` 残留已废弃的 Password 错误匹配死分支 | §3.2 `HeaderLocatorKeys` 增加 `ext_stc_seed`；§6.2 `BridgeOptions` 增加透传字段，清理 dead 匹配 |

---

## 12. 附录

### 12.1 常量表

| 常量 | 值 | 说明 |
|---|---:|---|
| `SALT_LEN` | 16 | L3 salt |
| `NONCE_LEN` | 12 | AEAD nonce |
| `TAG_LEN` | 16 | AES-GCM/ChaCha tag |
| `BODY_OVERHEAD` | 22 | 4+1+1+16 |
| `HEADER_LEN_MAX` | `0x03FF_FFFF` | 26-bit body_len |
| `CONTENT_L1_PBKDF2_ITERATIONS` | 200,000 | 口令 L1 |
| `PNG_AUDIO_BASE_SLOTS` | 512 | 64B base |
| `JPEG_SUPERBLOCK_SLOTS` | 718 | 44B base |
| `HEVC_SUPERBLOCK_MIN_SLOTS` | 524 | 32B base |
| `MAX_EXT_BYTES` | 255 | PNG/WAV/FLAC/JPEG |
| `HEVC_MAX_EXT_BYTES` | 64 | HEVC（STC h=7,u=2 时最大槽位 524 + 16*64 + 12 = 1560 ≤ 2048） |

### 12.2 Suite 表（append-only）

| id | AEAD | 默认 | 备注 |
|---:|---|---|---|
| 1 | AES-256-GCM | 是 | 12B nonce/16B tag |
| 2 | ChaCha20-Poly1305 | 否 | 12B nonce/16B tag |
| 3.. | 保留 | 否 | 未来只能追加，不可重定义 |

### 12.3 术语

- **L1**：定位前固定慢哈希；**L2**：Header 定位种子；**L3**：Body 会话密钥。
- **base header**：固定长度 Header；**extension**：`ext_len` + TLV，额外 Header 槽位。
- **body_len**：AEAD 密文字节数（含 16B tag），不含 Header。
- **probe**：容量探测；本方案要求与 embed 同源同算。

### 12.4 自检（文档附录）

> 自检结果：已逐节核对 (a) 保留类型/字段/函数均在真实代码中存在或其签名已标“新增”；(b) 三种布局偏移/总长/CRC 覆盖算术自洽（64/44/32）；(c) 命名统一为 `allowed_suites`/`max_payload_bytes`/`CipherSuiteId`/`SpatialHeaderV4` 等；(d) 7 Blocking + 15 Major 均在 §11 闭环；(e) 全文无未决项与“兼容旧版”执行分支；仅保留“只支持 V4”的明确声明。自检通过。

---

**最终执行原则：** 先做 §7 Step 0-4（不接线），再按 PNG → WAV/FLAC → JPEG → HEVC 顺序切换；每个 Step 独立提交/回滚；Step 9 才删除旧常量、重建基线、跑全质量门禁。任何未通过 §8.2 负面用例的 Step 不允许进入下一 Step。
