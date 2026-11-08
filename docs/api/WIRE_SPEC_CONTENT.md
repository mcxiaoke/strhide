# strhide 内容域线格式参考（V4 内容信封）

> **本文已拆分（2026-11-07），保留为历史参考，非规范。**
> 新规范见 [`docs/api/spec/`](./spec/README.md)：公共层 [CONTENT-ENVELOPE.md](./spec/CONTENT-ENVELOPE.md)、
> 载体文档 [CONTENT-PNG.md](./spec/CONTENT-PNG.md) / [CONTENT-JPEG.md](./spec/CONTENT-JPEG.md) /
> [CONTENT-HEVC.md](./spec/CONTENT-HEVC.md) / [CONTENT-AUDIO.md](./spec/CONTENT-AUDIO.md)。
> 本文与实现冲突时**以新规范为准**；旧文勘误清单见 [CORRECTIONS.md](./spec/CORRECTIONS.md)。

> 适用版本：crate `strhide` 0.9.3（Rust 实现，`rust/Cargo.toml`）。
> **范围**：仅内容域——`embed` / `extract` 在 PNG、JPEG、WAV、FLAC、HEVC/HEIF 载体内部写出的
> V4 微型信封。结构域（UBE 信封，`write` / `restore` 使用）见
> [WIRE_SPEC_STRUCTURE.md](./WIRE_SPEC_STRUCTURE.md)。
> 两域的信封格式与派生域相互独立、互不可读，差异清单见 [spec/README.md §1](./spec/README.md)。

> **本文的定位（请先读这一段）**
>
> 本文是**给本项目的开发用的**，不是对外标准。它的第一读者是三个月后回来改代码的人（包括你自己），
> 作用有三个，按重要性排序：
>
> 1. **留住"为什么"**：每个看起来可以随手改的写法，都写明当初为什么这么写、不这么写会坏什么。
>    `cost_calibration.rs` 里"不 clamp beta、不留 `x > 1e11` 分支"这类决定，代码注释只够写一句，
>    真正的理由在这里；
> 2. **防误改**：标出哪些字节/种子/顺序是"改了就静默换结果"的（不报错、不掉测试、只换载体），
>    见 §13.0 的 F / D / I 分级与附录 A 的冻结向量；
> 3. **写私有方言**：说明哪些旋钮可以换、换了之后与官方构建的关系（见 §13.15）。
>
> 因此本文按"**改动的后果**"组织：每条内容标注是 **冻结**（改了旧载体永久不可读）、
> **方言**（可通过 Profile 替换，产生独立格式）还是 **自由**（写侧实现细节，改了不影响读取）。
>
> 附带结论：本文**不承诺**"第三方照着写一个能互通的 strhide"，也不承诺跨平台/跨版本逐位一致——
> 那是 RFC 的目标，不是 CLI 工具的目标。要开放标准就 fork 后自建。

> **章节编号约定**：两域原先合并在一个文件中，章节号已被其他文档与源码注释引用。拆分后保留原编号
> 空间——结构域占 §2–§12，内容域占 §13。§13 内部在本次拆分中重排过一次（为插入算法章节），
> 新旧编号对应关系见下表；**引用 §13.x 时以本文为准**。

| 拆分前 | 拆分后 | 内容 |
|---|---|---|
| §13.1 – §13.3 | §13.1 – §13.3 | 总则、微头、密钥分层（编号未变） |
| — | §13.4 | 派生标签全表与 HKDF info 拼接（新增） |
| — | §13.5 | 伪随机流与置换（新增） |
| — | §13.6 | 槽位集合与定位（新增） |
| — | §13.7 | STC 矩阵与 syndrome（新增） |
| §13.4 | §13.8 | 三套基础头 |
| §13.5 | §13.9 | flags、ext_len 与 TLV |
| §13.6 | §13.10 | 容量公式 |
| — | §13.11 | PNG 代价排序（新增） |
| §13.7 | §13.12 | 行为语义 |
| §13.8 | §13.13 | 音频（WAV / FLAC） |
| §13.9 | §13.14 | HEVC / HEIF |
| §13.10 | §13.15 | 私有构建 |
| — | §13.16 | 写侧非规范性实现（新增） |

---

## 目录

- [13. 内容域：V4 内容信封](#13-内容域v4-内容信封png--wav--flac--jpeg--hevc)
  - [13.0 稳定性分级与改动后果](#130-稳定性分级与改动后果)
  - [13.1 总则](#131-总则)
  - [13.2 微头与信封长度](#132-微头与信封长度)
  - [13.3 套件与密钥分层（L1 / L2 / L3）](#133-套件与密钥分层l1--l2--l3)
  - [13.4 派生标签全表与 HKDF info 拼接](#134-派生标签全表与-hkdf-info-拼接)
  - [13.5 伪随机流与置换](#135-伪随机流与置换)
  - [13.6 槽位集合与定位](#136-槽位集合与定位)
  - [13.7 STC 矩阵与 syndrome](#137-stc-矩阵与-syndrome)
  - [13.8 三套基础头](#138-三套基础头base-header)
  - [13.9 flags、ext_len 与 TLV](#139-flagsext_len-与-tlv)
  - [13.10 容量公式](#1310-容量公式)
  - [13.11 PNG 代价排序（规范性）](#1311-png-代价排序规范性)
  - [13.12 行为语义](#1312-行为语义)
  - [13.13 音频（WAV / FLAC）](#1313-音频wav--flac)
  - [13.14 HEVC / HEIF](#1314-hevc--heif)
  - [13.15 私有构建](#1315-私有构建)
  - [13.16 写侧非规范性实现](#1316-写侧非规范性实现)
- [14. 常量速查表（内容域）](#142-内容域v4)
- [15. 兼容矩阵（内容域）](#15-兼容矩阵内容域)

---

## 13. 内容域：V4 内容信封（PNG / WAV / FLAC / JPEG / HEVC）

> 本节描述**当前实现**。V4 信封没有 V2/V3 兼容读路径：旧 `CipherSuite`、
> 旧 `header_v3::Superblock`、`MIN_ENVELOPE_LEN` / `HEADER_OVERHEAD` 常量均已删除。
> 旧的 V3 描述只存在于归档文档中。

### 13.0 稳定性分级与改动后果

本文每条内容都标一个分级，用来回答"我能不能改这里"：

| 分级 | 含义 | 改动后果 |
|---|---|---|
| **F 冻结** | 已写出的载体依赖它 | 改了就**读不回**已存在的载体；必须同步重建字节级基线，并在 CHANGES 明确记为不兼容变更 |
| **D 方言** | 可通过 `StegoProfile` / `*FormatProfile` 替换 | 不破坏既有载体，但产生**独立格式**：官方构建读不回，私有构建之间才有互通（§13.15） |
| **I 自由** | 只影响"写成什么样"，不影响"能否读出" | 随改随测，`baseline_hash.py --check` 把关即可（§13.16） |

逐节分级：

| 节 | 内容 | 级别 |
|---|---|---|
| §13.2 | 微头、`BODY_OVERHEAD`、`body_len` 语义 | F |
| §13.3 | `CipherSuiteId` 枚举 | D（append-only，可加项不可改义） |
| §13.3 | L1/L2/L3 派生公式与域分离 | F |
| §13.4 | 载体身份 `pre_salt` 构造 | F |
| §13.4 | 各格式的标签字面量 | D（换标签 = 新方言） |
| §13.5 | ChaCha12 / 采样 / 三种置换 | F |
| §13.6 | 槽位集合与定位 | F |
| §13.7 | STC 列向量与 syndrome | F |
| §13.8 | 三套基础头布局 | F |
| §13.9 | TLV 规则与 `type_id` 空间 | D（新增 non-critical 可向后兼容） |
| §13.10 | 容量公式与预算门 | F（`probe`/`embed` 必须同一口径） |
| §13.11 | PNG 代价排序与截断 | F（决定候选集） |
| §13.12 | `extract`/`verify` 的失败面 | I（接口约定，不是字节） |
| §13.13 / §13.14 | 音频、HEVC 的槽位与分带 | F |
| §13.15 | 私有构建 | D 的定义处 |
| §13.16 | trellis 搜索、方向代价、SIMD、重编码、重试 | I |

**没有"互操作"这一档。** 本文不承诺第三方按文实现能读出本工具的产物，也不承诺本工具能读第三方
产物；那个目标不在项目范围内。同理，**不承诺跨平台/跨版本逐位一致**——官方只保证：同一构建读得回
自己写的载体，由 `baseline_hash.py` 与全量测试守住。

#### 新增内容的写作约定

改这个文件时按三条自检，缺一条就等于没写：

1. **是什么**：字段偏移、字节序、取值范围，能对着代码逐字核对；
2. **为什么这样**：这条写法解决了什么具体问题？换一种写法会坏什么？（例：§13.11.3 为什么必须整数
   截断、§13.6.2 为什么头部槽位不能依赖代价图、§13.7.2 为什么两个位是强制的。）
   没有"为什么"的条目，下次重构时会被当成冗余删掉；
3. **改了会怎样**：F / D / I 哪一级，影响既有载体还是只影响新产物，需要配合哪个测试或基线。

如果一条规则只是"现在代码这么写"，写不出为什么，那它多半是 I 级实现细节，应归到 §13.16 而不是
当成格式约束——把实现细节写成规范，会让后来的人不敢优化。

---

### 13.1 总则

- **正文无魔数、无明文标记**：载荷全部在 AEAD 密文内；没有口令的载体与未修改载体不可区分。
- **头部位置密钥化**：基础头占用的槽位由 L2 `locate_seed` 选出（`header_stc_seed` 只用于
  基础头的 STC 编码，JPEG/HEVC）；`magic4` 由 L2 派生，
  不是固定常量。提取失败统一为 `NoHiddenData`，不泄露"是否存在/密码是否正确"。
- **凭据**：`Credential::{Password(&str), FileKey(&[u8; 32])}`，二选一；空串密码视为未提供。
  未提供时回落到 `StegoProfile.default_secret`，再回落到公开常量 `PUBLIC_DEFAULT_SECRET`
  （后者不提供对抗源码持有者的机密性）。
- **域**：显式 `domain` > `StegoProfile.domain` > 官方默认。域名 NFC 规范化，长度前缀拼接。

### 13.2 微头与信封长度

```text
plaintext  = [4B BE original_len][1B flags][micro_header][payload]
ciphertext = AEAD(plaintext)            // 末尾 16B tag
body_len   = ciphertext.len()           // 只含密文+tag，不含 salt/nonce
```

- `BODY_OVERHEAD = 22` = 4 长度 + 1 flags + 1 最小微头 + 16 tag。
  `max_payload_bytes = message_bits / 8 - 22`。
- `flags`：bit0 = 压缩；bit1..3 = 压缩算法 id（0 = Deflate，唯一实现）。
- 微头：`0x00` 文本/原始字节；`0x01` 文件（含 ≤255 字节文件名）。
- `MAX_PLAINTEXT_LEN = HEADER_LEN_MAX - BODY_OVERHEAD = 67,108,841`（`body_len`
  的 26 位上限作用于含 tag 的密文，明文再扣除 22B 框架开销，超出直接拒绝）。
- salt（16B）与 nonce（12B）**只存在载体头中**，不占正文槽位，也不计入 `body_len`。

### 13.3 套件与密钥分层（L1 / L2 / L3）

`CipherSuiteId`（`core::crypto`）是 append-only 枚举：

| id | AEAD | nonce | tag | 状态 |
|---|---|---|---|---|
| 1 | AES-256-GCM | 12B | 16B | 默认 |
| 2 | ChaCha20-Poly1305 | 12B | 16B | 可选 |

- **L1**：`derive_locator_master(cred, domain_label, cipher, pre_salt)` → 32B 主密钥。
  `Password` 走 PBKDF2-HMAC-SHA256 **200,000 轮**（`CONTENT_L1_PBKDF2_ITERATIONS`）；
  `FileKey` 跳过 PBKDF2 直接作为 IKM 进 HKDF。`pre_salt` 只用嵌入前后不变的元数据
  （WAV 排除 PCM 摘要、FLAC 排除 STREAMINFO MD5；其他格式用参数集/像素布局摘要）。
- **L2**：`derive_l2_locator_keys(&master, cipher, magic_label, domain)` →
  `HeaderLocatorKeys { locate_seed, header_stc_seed, ext_stc_seed, magic4 }`。只用于找头。
- **L3**：`derive_l3_session_keys(cipher, suite, &master, header_salt, domain)` →
  `SessionKeys { enc_key, perm_seed, stc_seed }`。`suite` 只在这里参与派生并决定 AEAD 算法。
- **AEAD 分发位置**：`stego::envelope::{encrypt_v4_with_aad, unpack_v4_envelope_parts}`；
  两者按 `suite` 分别走 `Aes256Gcm` / `ChaCha20Poly1305`，失败一律 `NoHiddenData`。
- **AAD**：`"strhide-content-envelope-v4\0" || format_id || base_header || extension`。
  基础头的每个字段、扩展区每个 TLV 都被认证；篡改不会产生"另一种合理解码"。
  基础头 CRC32 只用于提前拦意外损坏，**认证靠 AEAD**。
- `ExtractParams.max_pbkdf2_iterations` 默认 **200,000**；上限内才做试解，超过直接拒绝。

### 13.4 派生标签全表与 HKDF info 拼接

读取侧在拿到基础头之前必须先算 L1/L2，因此**载体的公开身份公式、标签字面量、info 拼接规则
全部属于线格式**。推导中提到但不在此列的量都不是格式的一部分。

#### 13.4.1 HKDF info 拼接

```text
info(label, domain) = label                         若 domain 为 None 或空串
                    = label ‖ u64be(len(NFC(domain))) ‖ NFC(domain)   否则
```

长度前缀防止 `("ab","c")` 与 `("a","bc")` 碰撞。所有 HKDF 均为 HKDF-SHA256
（RFC 5869，`L` 取目标长度，无附加 context）。

#### 13.4.2 载体身份的 `pre_salt`

`pre_salt` 是 L1 的 PBKDF2 salt / HKDF salt，只用**嵌入前后不变**的元数据，因此读写两侧
（以及 `probe`）必然一致。全部为 SHA-256，多字节字段大端：

| 载体 | 输入 | 说明 |
|---|---|---|
| PNG | `hpos_salt ‖ "png-v4" ‖ u64be(width) ‖ u64be(height) ‖ [bit_depth, color_type, channels] ‖ meta_digest` | `meta_digest = SHA-256` over 每个**关键块**：`ty(4B) ‖ u32be(len) ‖ data`，按文件顺序。排除 `IDAT`、`prIv` 与全部辅助块（首字母小写：`tEXt`/`zTXt`/`iTXt`/`tIME`/`eXIf`/`iCCP`/`gAMA`/`sRGB`/`pHYs`…），即只有 `IHDR`/`PLTE`/`IEND` 参与。辅助块是第三方工具（exiftool、压缩器、编辑器另存）随时会改的元数据，纳入盐会导致一次元数据编辑就把载荷变成不可恢复（2026-11-07 修复） |
| JPEG | `cover_digest_tag ‖ "jpeg-v4" ‖ cover_digest` | `cover_digest_tag = b"strhide-cover-v1"`；`cover_digest = SHA-256(tag ‖ u32be(block_count) ‖ u32be(component_count) ‖ 各 component 各 block 的 DC 系数 i16be)`，DC 不是嵌入目标，故嵌入后不变 |
| WAV | `hpos_salt ‖ "wav-v4" ‖ u16be(channels) ‖ u32be(sample_rate) ‖ u16be(block_align) ‖ u16be(bits) ‖ u32be(data_len)` | `bits` 为 PCM 位深（16/24） |
| FLAC | `hpos_salt ‖ "flac-v4" ‖ u32be(sample_rate) ‖ [channels, bits_per_sample] ‖ u64be(total_samples)` | **排除** STREAMINFO 的 MD5（嵌入会重算它） |
| HEVC | `cover_salt ‖ "hevc-v4" ‖ parameter_sets` | 参数集的序列化口径本文未展开，取值见 `stego/hevc` 的 `carrier_identity` |

`hpos_salt` 与 `cover_salt` 是**公开**常量（私有构建可替换，替换即产生不兼容格式）：

| 载体 | 常量 | 值 |
|---|---|---|
| PNG | `hpos_salt` | `b"strhide-stego-hpos-salt-v2"` |
| WAV | `hpos_salt` | `b"strhide-audio-hpos-salt-v1"` |
| FLAC | `hpos_salt` | `b"strhide-flac-hpos-salt-v1"` |
| HEVC | `cover_salt` | `b"strhide-hevc-cover-v1"` |

#### 13.4.3 L1：定位主密钥

```text
Password(p):
  ikm = HKDF-Expand(SHA256, ikm=NFC(p), salt=None, info=info(domain_label, domain), L=32)  若 domain 非空
      = NFC(p) 的 UTF-8 字节                                                              否则
  master = PBKDF2-HMAC-SHA256(pass=ikm, salt=pre_salt, iter=200_000, dkLen=32)

FileKey(k[32]):
  master = HKDF-Expand(SHA256, ikm=k, salt=pre_salt, info=info(domain_label, domain), L=32)
```

`domain_label` 是唯一随载体族不同的 L1 输入（见 §13.4.5）。密码口令猜测的成本因此固定为
200,000 轮 PBKDF2；头部位置由结果派生，无法便宜地试错。

#### 13.4.4 L2 / L3

```text
L2（salt = 无）:
  locate_seed      = HKDF-Expand(SHA256, ikm=master, info=info(hpos_label, domain),  L=32)
  magic4           = HKDF-Expand(SHA256, ikm=master, info=info(magic_label, domain), L=4)
  header_stc_seed  = u64be(HKDF-Expand(SHA256, ikm=master, info=b"strhide-v4-hdr-stc", L=8))
  ext_stc_seed     = u64be(HKDF-Expand(SHA256, ikm=master, info=b"strhide-v4-ext-stc", L=8))

L3（salt = session_salt）:
  info_x = info(x_label, domain) ‖ u16be(suite_id)            // x ∈ {enc, perm, stc}
  enc_key   = HKDF-Expand(SHA256, ikm=master, salt=session_salt, info=info_enc,  L=32)
  perm_seed = HKDF-Expand(SHA256, ikm=master, salt=session_salt, info=info_perm, L=32)
  stc_seed  = u64be(HKDF-Expand(SHA256, ikm=master, salt=session_salt, info=info_stc, L=8))
```

- `session_salt`：空间域 / JPEG / 音频 = 基础头的 16 B `salt`；HEVC = 基础头的 12 B `nonce`。
- **两个 STC 种子不带 domain、不带 suite**：它们是固定字面量，与 L2 的 `locate_seed` 不同。
  这一点必须照抄，否则读取侧无法重建 header 的 trellis。
- `suite_id` 只参与 L3，且以 `u16be` 追加在 info 末尾。

#### 13.4.5 标签全表（官方 profile）

| 载体 | `domain_label` | `hpos_label` | `enc_label` | `perm_label` | `stc_label` | `magic_label` |
|---|---|---|---|---|---|---|
| PNG | `strhide-stego-domain-v1` | `strhide-stego-hpos-v2` | `enc` | `perm` | `strhide-stc-trellis-v1` | `strhide-v4-hdr-magic` |
| JPEG | `strhide-stego-domain-v1` | `hpos` | `enc` | `perm` | `stc-trellis` | `strhide-v4-hdr-magic` |
| WAV | `strhide-stego-domain-v1` | `audio-hpos` | `audio-enc-v1` | `audio-perm-v1` | `audio-stc-trellis-v1` | `strhide-v4-hdr-magic` |
| FLAC | `strhide-stego-domain-v1` | `audio-hpos` | `audio-enc-v1` | `audio-perm-v1` | `audio-stc-trellis-v1` | `strhide-v4-hdr-magic` |
| HEVC | `strhide-stego-domain-v1` | `strhide-hevc-hpos-v4` | `strhide-hevc-enc-v4` | `strhide-hevc-perm-v4` | `strhide-hevc-stc-v4` | `strhide-hevc-magic-v4` |

默认 `suite_id = 1`（AES-256-GCM）。WAV 与 FLAC 共用同一组标签，靠 §13.4.2 的 `hpos_salt`
区分——同一密码在两种载体上派生出不同密钥。

---

### 13.5 伪随机流与置换

槽位分散需要**跨版本、跨平台、跨编译器逐位一致**的伪随机序列：一旦这里的算法变了，既有载体
就永久不可读。因此本节固定了三件事：流发生器、无偏采样、三种置换形态。

#### 13.5.1 ChaCha12 流（`prng`）

12 轮 ChaCha（Bernstein 2008 / RFC 8439 的 quarter-round 定义），**不使用**任何上游 RNG 库。

- 初始状态 16 个 `u32`：`state[0..4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}`；
  `state[4..12]` = 32 B 种子按小端拆成的 8 个字；`state[12..14]` = 64 位块计数器，初值 0；
  `state[14..16]` = 64 位 stream，恒为 0。
- 每块：`x = state`，执行 6 次双轮。列轮
  `(0,4,8,12)(1,5,9,13)(2,6,10,14)(3,7,11,15)`，对角轮
  `(0,5,10,15)(1,6,11,12)(2,7,8,13)(3,4,9,14)`。
- quarter-round(a,b,c,d)：`a+=b; d^=a; d<<<=16; c+=d; b^=c; b<<<=12; a+=b; d^=a; d<<<=8; c+=d; b^=c; b<<<=7`。
- 输出 16 字：`buffer[i] = x[i] + state[i]`（wrapping），按 `u32` 小端串成 64 B；
  发出后计数器低字 `state[12] += 1`，溢出进 `state[13]`。
- `next_u64 = lo | (hi << 32)`，其中 `lo`、`hi` 是连续两个 `next_u32`。

**参考向量**（`seed = 00 01 00 ... 00`，即首字节 1、其余 0；前 128 字节）：

```text
12 05 6e 59 5d 56 b0 f6 ee f0 90 f0 cd 25 a2 09
49 24 8c 27 90 52 5d 0f 93 02 18 ff 0b 4d dd 10
a6 00 22 39 d9 a4 54 e2 9e 10 7a 7d 06 fe fd fe
f0 21 0f eb a0 44 f9 f2 9b 17 72 c9 60 dc 29 c0
0c 73 66 c5 cb c6 04 24 0e 66 5e b0 2a 69 37 2a
7a f9 79 b2 6f bb 78 09 2a c7 c4 b8 80 29 a7 c8
54 51 3b c2 17 bb fc 7d 90 43 2e 30 8e ba 15 af
c6 5a eb 48 ef 10 0d 56 01 e6 af ba 25 71 17 a9
```

#### 13.5.2 无偏区间采样

```text
gen_range(bound):
  bound <= 1            -> 0
  bound <= 2^32 - 1     -> 令 b=bound, limit = 2^32 - (2^32 mod b)；循环取 r=next_u32，r<limit 时返回 r mod b
  否则                   -> 令 b=bound, limit = 2^64 - (2^64 mod b)；循环取 r=next_u64，r<limit 时返回 r mod b
```

拒绝采样是格式的一部分：换成取模会引入偏置，且改变序列。

#### 13.5.3 Fisher–Yates（两种形态）

- **整段置换** `permute_indices(items, seed)`：新建 ChaCha12(seed)，`for i in (1..n).rev()`：
  `j = gen_range(i+1)`，交换 `items[i]`、`items[j]`。
- **前缀置换** `permute_prefix(items, k, seed)`：新建 ChaCha12(seed)，
  `end = min(k, n-1)`，`for i in 0..end`：`j = i + gen_range(n-i)`，交换。
  只前 k 个位置被最终确定，尾部只参与取值。

前缀置换满足**续接稳定性**：把 `0..k` 拆成 `0..s` 与 `s..k` 两次调用、共用同一 RNG 实例，
结果与一次调用完全相同。这是"读侧先读基础头、知道 `ext_len` 后再续算扩展槽"的前提。

#### 13.5.4 键控线性置换（HEVC）

HEVC 的槽位规模可达数十亿，物化置换向量不现实，改用**互质步长的线性同余**：

```text
fold(seed32) : s = 0x243F6A8885A308D3
               for each 8-byte little-endian chunk of seed32: s = splitmix64(s ^ chunk)
params(len, seed32, band_start):
  s = fold(seed32) ^ (band_start * 0x9E3779B97F4A7C15)
  start  = splitmix64(s) % len
  stride = max(splitmix64(s ^ 0xA5A55A5A3C3CC3C3) % len, 1)
  while gcd(stride, len) != 1: stride += 1; 若 stride >= len 则退化为 1 并停止
pos_i = (start + i * stride) mod len        // i = 0,1,2,...；乘积用 64 位无符号运算
```

`splitmix64(x)`：`x += 0x9E3779B97F4A7C15; z = x; z = (z ^ (z>>30)) * 0xBF58476D1CE4E5B9;
z = (z ^ (z>>27)) * 0x94D049BB133111EB; return z ^ (z>>31)`。

`gcd(stride,len) = 1` 保证 `pos_i` 在 `0..len` 上是排列；`band_start` 而非带的序号参与派生，
使插入一个空带不会平移后续带的映射。

#### 13.5.5 键控 Feistel 置换（音频）

音频域用六轮平衡 Feistel + cycle walking，**逐位置求值**、不需要物化向量：

```text
perm_new(seed32, n):
  bits = ceil(log2(n))（n <= 1 时取 1）
  half = clamp(ceil(bits/2), 1, 32)
  d    = SHA-256(b"strhide-audio-perm-v1" ‖ seed32 ‖ u64be(n))
  k0   = u64be(d[0..8]);  k1 = u64be(d[8..16])

round(i)      : mix(k[i & 1] ^ rotl64(i, 17))       // mix = splitmix64 的终结函数
permute_block(x):
  L = (x >> half) & ((1<<half)-1);  R = x & ((1<<half)-1)
  repeat 6 rounds (r = 0..5):  f = round(r ^ R) & mask;  (L, R) = (R, L ^ f)
  return (L << half) | R

at(i):
  x = i mod n;  y = permute_block(x)
  while y >= n: x = y; y = permute_block(x)
  return y
```

`permute_block` 在 `2^(2*half)` 上是双射，cycle walking 保持双射性，因此 `at` 是 `[0,n)` 上的排列。
`n == 1` 时 `at(0) = 0`。

---

### 13.6 槽位集合与定位

#### 13.6.1 通用规则

- **槽位**是"载体中一个可翻转的奇偶位"。写入时一个字节的 8 个 bit 占 8 个槽，
  **高位在前**（byte 的 bit7 对应第一个槽）。
- **基础头与扩展区**占用同一个置换的前缀：`[0, 512+8·ext_len)` 或载体对应的超块前缀。
  因此读侧可以先读基础头、拿到 `ext_len`，再续算扩展槽；三种置换形态都保证前缀稳定
  （§13.5.3 续接稳定、§13.5.4 `pos_i` 与 `count` 无关、§13.5.5 逐位置求值）。
- **正文槽位是"截断的置换前缀"**：先确定候选池，再取前 `slots_for(bits, h, u)` 个候选，
  最后对这段候选做置换；不是"对整池置换后取前 N"。这个区别改变结果，必须照抄。
- 头部槽位**不得依赖代价模型**：读侧必须先读头，才能知道 `algorithm_id`。

#### 13.6.2 PNG

设图像解码后为 `pixels`（行优先、`channels` 交错），`hc = 1`（channels ≥ 3）否则 `0`。

1. **头部候选池**：所有满足 `8 <= pixels[px*channels+hc] <= 247` 的像素，按像素升序。
   这就是全部条件——与代价图无关。
2. **头部布局**：对该池做 `permute_prefix(pool, 512 + 8·ext_len, locate_seed)`。
   基础头第 `b` 字节的第 `j` 位（j=0 为 MSB）写在 `pool[b*8+j]` 的 `hc` 通道。
3. **正文候选**：见 §13.11（代价排序 + 平滑区截断）。候选是像素索引，按
   `(代价位模式, 像素索引)` 全序升序。
4. **正文槽位**：按候选顺序逐像素展开通道。跳过"该像素已被头部占用且通道 == `hc`"；
   目标通道值必须仍在 `[8,247]`，且 `val mod 8 ∈ [1,6]`（`class_rule = 1`，写侧恒为此值）。
   通道集合由 `channel_mode` 决定：`0` = 仅 `hc`，`1` = `[0,1,2]`（alpha 永不使用）。
   取前 `slots_for(bits, stc_h, stc_u)` 个，记为 `body[]`；对该数组做
   `permute_indices(body, perm_seed)`，置换后第 `i` 个元素才是第 `i` 个正文槽。

#### 13.6.3 JPEG

```text
Grid     = { bi * 63 + (k-1) | bi ∈ [0, block_count), k ∈ [k_min, k_max] }    // 官方 k ∈ [1,63]
HdrSlots = permute_prefix(Grid, hdr_n, locate_seed)   // hdr_n = 2*(8*sb_bytes + sb_h - 1)
BodyGrid = Grid \ HdrSlots，按扁平索引升序
BodySlots= permute_prefix(BodyGrid, body_n, perm_seed)
```

- `block_count` = 亮度分量（component 0）的 8×8 块数；块按分量内光栅顺序编号。
- `hdr_n`：`sb_bytes=44, sb_h=8, sb_u=2` → `2*(352+7) = 718` 槽；扩展区
  `ext_n = ext_u*(8*ext_len + ext_h - 1)`（`ext_h=8, ext_u=4`，`ext_len=0` 时仍为 28 槽）。
- `body_n = stc_u * (bits + stc_h - 1)`，`bits = 8 * body_len`。
- 槽位值是系数奇偶：`parity(c) = c & 1`，写入载体映射为 `2 | parity`（见 §13.7）。

#### 13.6.4 HEVC / HEIF

窗口内的候选槽是 CABAC bypass `coeff_sign_flag` 的枚举结果，按解码顺序编号为 `0..pool_size`。

- **头部**：`pos_i = (start + i*stride) mod pool_size`（§13.5.4，`band_start = 0`），
  `i ∈ [0, 524 + ext_slots)`，`ext_slots = 2*(8*ext_len + 6)`。
- **正文分带**：按切片的"不可预测"标记把候选分成 band 0（无可参考帧）与 band 1，
  再剔除落在头部前缀内的位置，得到 `band0`、`band1` 两个升序索引数组（带内保持解码顺序）。
- **正文槽位**：先耗尽 band 0 再进入 band 1；对每个带用
  `(start, stride) = params(band.len(), perm_seed, band.start)`，按
  `pos_i = band.start + ((start + i*stride) mod band.len())` 取，直到凑满 `body_n`。
- 两个 band 永不交错：能在 band 0 装下就绝不触碰参考帧。

#### 13.6.5 WAV

- 槽 = 一个 PCM 采样（按 `data` 块内的采样顺序，`block_align` 交错）。
- `perm = KeyedPermutation(locate_seed, total_slots)`（§13.5.5）。
- 头部第 `i` 槽 = `perm.at(i)`；扩展区第 `i` 槽 = `perm.at(512 + i)`；
  正文第 `i` 槽 = `perm.at(512 + 8*ext_len + i)`。

> 注意：音频的槽位置换用 **L2 的 `locate_seed`**，不是 L3 的 `perm_seed`。`perm_seed` 只用于
> 写侧的方向代价（§13.16），不参与槽位选择。

#### 13.6.6 FLAC

FLAC 的槽位分两类，两者用**键控偶数稀释**从各自的池里挑，再对正文做置换：

```text
thin_pick(index, range, wanted, phase):
  wanted == 0 或 range == 0  -> false
  phase = phase mod range
  return floor((index * wanted + phase) / range) != floor(((index+1) * wanted + phase) / range)
```

- 头部池 = 各 subframe 的尾部位（"subframe tail"），`wanted = 512`，
  `phase = u64le(locate_seed[0..8])`；扩展区 `wanted = 8*ext_len`，
  `phase = u64le(locate_seed[8..16])`。头部槽位即被选中的尾部，**就在原位置**（不做置换）。
- 正文池 = 残差槽（按文件内解码顺序），`wanted = body_n`，
  `phase = u64le(SHA-256(b"strhide-v4-flac-body-phase" ‖ u64le(base) ‖ salt ‖ nonce)[0..8])`，
  `base = u64le(locate_seed[16..24])`，`salt`/`nonce` 取自基础头（写侧 6 次重试内可变）。
- 被选中的正文槽聚成一个长度为 `body_n` 的数组，再做
  `KeyedPermutation(perm_seed, body_n)` 的逐位置置换，第 `i` 个槽 = `header_slots + perm.at(i)`。
- `wanted` 与 `range` 都从文件可推导，因此读侧只需 O(payload) 内存。

---

### 13.7 STC 矩阵与 syndrome

这一层只回答"给定槽位奇偶序列和种子，(h,u) 校验矩阵是什么、消息位怎么读出来"。
**读取不需要 trellis 搜索**：搜出来的只是"写侧选择了哪些翻转"，与解码无关。

#### 13.7.1 参数与容量

- `h`（约束高度）∈ `4..=10`；`u`（每组元素数）∈ `1..=64`。空间域 `u <= 3`，
  JPEG `u <= 64`，HEVC 固定 `h=7, u=2`。
- `n` 个元素承载 `m = n/u - (h-1)` 个消息位；写侧需要的元素数
  `n = u * (m + h - 1)`（`m = 0` 时 `n = 0`）。`n` 必须是 `u` 的倍数。

#### 13.7.2 列向量

把元素按连续 `u` 个一组分组，第 `g` 组拥有一行 syndrome；组内第 `s` 个元素（`s ∈ [0,u)`）
使用列向量 `cols[s]`，其第 `d` 位（`d ∈ [0,h)`）表示对第 `g+d` 行的贡献。

```text
mask = (1 << h) - 1
pattern(idx):
  x = (splitmix64(seed XOR idx) as u32) & mask     // seed 为 u64 的 header_stc_seed / ext_stc_seed / stc_seed
  x |= 1                    // 固定在"即将结算的行"上，否则某些奇偶不可达
  x |= 1 << (h-1)           // 固定在新进入状态的那一位
  return reverse_low_bits(x, h)
```

`reverse_low_bits(x,h)` 把低 `h` 位左右翻转（bit `d` → bit `h-1-d`），使**存储后的** bit 0
对应即将结算的行、bit `h-1` 对应最新状态。

`cols[s]` 的取法：从 `idx = s` 开始，`col = pattern(idx)`；若 `col` 已在 `cols` 中且
`cols.len() < 2^(h-2)`，则 `idx += u` 重试。`2^(h-2)` 是可区分列向量的上限（只剩 `h-2` 个自由位），
超过它必然重复，此时接受重复。

#### 13.7.3 syndrome（读取）

```text
row_syndrome(row) = XOR over g ∈ [max(0,row-h+1), row], s ∈ [0,u)
                      当 (cols[s] >> (row-g)) & 1 == 1 时，异或 (vals[g*u+s] & 1)
```

`vals[j]` 是第 `j` 个槽的奇偶（0 或 1）。消息第 `b` 位（`b` 从 0 起）等于 `row_syndrome(b + h - 1)`：
前 `h-1` 行是 trellis 预热，不承载消息。消息按 **MSB-first** 打包成字节
（`b/8` 字节的 `bit (7 - b%8)`），末字节多余位为 0。

#### 13.7.4 `u = 1` 的特殊性

`u = 1` 时每个元素独占一行，`m = n - h + 1`，且 `H` 的每列只有一个强制位，
**方程有唯一解**：第 `j` 个元素翻转当且仅当"第 `j+h-1` 行的当前奇偶 ≠ 消息第 `j` 位"。
这条路径不是 trellis 搜索，没有代价参与，翻转率恒为 0.5。读侧行为与 `u > 1` 完全一致
（都用 §13.7.3），因此规范只需定义 syndrome，不必区分两种情况。

---

### 13.8 三套基础头（base header）

三套头都由 L2 选槽；`format_id` 与部分隐含字段不存储，但在 AAD 前缀中绑定。
多字节字段一律大端。

#### 13.8.1 空间域（PNG / WAV / FLAC）：64 字节

| off | size | 字段 |
|---|---|---|
| 0 | 16 | salt（L3 HKDF salt） |
| 16 | 12 | nonce |
| 28 | 4 | body_len（密文含 tag） |
| 32 | 1 | version = `(major << 4) | minor`，major 必须 4 |
| 33 | 1 | flags（`EXT_PRESENT` / `EXT_CRITICAL`） |
| 34 | 1 | format_id（1=PNG，2=WAV，3=FLAC） |
| 35 | 1 | algorithm_id（PNG 代价模型 wire id） |
| 36 | 2 | suite_id |
| 38 | 1 | codec_id（0=Hamming，1=STC） |
| 39 | 1 | stc_h（4..=10；Hamming 时必须为 0） |
| 40 | 1 | stc_u（1..=3；Hamming 时必须为 0） |
| 41 | 1 | channel_mode（PNG：0 绿，1 RGB；音频 0） |
| 42 | 1 | class_rule（PNG：0/1；音频 0） |
| 43 | 1 | reserved，必须 0 |
| 44 | 2 | p1_window（奇数 1..=63） |
| 46 | 2 | p2_window（奇数 1..=63） |
| 48 | 2 | neg_log2_epsilon（1..=127） |
| 50 | 2 | exclusion_permille（0..=900） |
| 52 | 4 | sigma（**f32 little-endian**，有限且 > 0） |
| 56 | 1 | kernel_id（当前必须 0） |
| 57 | 1 | reserved，必须 0 |
| 58 | 2 | ext_len（TLV 字节数，0..=255） |
| 60 | 4 | CRC32-IEEE over bytes[0..60] |

> 音频（WAV/FLAC）只用 STC：`codec_id = 0`（Hamming）在音频域**保留未用**，
> 音频 `extract` 遇到 Hamming 头直接 `NoHiddenData`。golden vectors 中的
> Hamming 头只用于校验布局与 CRC，不代表音频引擎会写出的载体。

#### 13.8.2 JPEG：44 字节

| off | size | 字段 |
|---|---|---|
| 0 | 1 | version（major 4） |
| 1 | 1 | flags |
| 2 | 2 | suite_id |
| 4 | 16 | salt |
| 20 | 12 | nonce |
| 32 | 4 | body_len（密文含 tag） |
| 36 | 1 | codec_id（0 = ternary STC） |
| 37 | 1 | stc_h（4..=10） |
| 38 | 1 | stc_u（1..=64） |
| 39 | 1 | ext_len（0..=255） |
| 40 | 4 | CRC32-IEEE over bytes[0..40] |

#### 13.8.3 HEVC / HEIF：32 字节

| off | size | 字段 |
|---|---|---|
| 0 | 4 | magic4（L2 派生） |
| 4 | 1 | version（major 4） |
| 5 | 1 | flags |
| 6 | 1 | stc_u（1..=64） |
| 7 | 2 | window_slices（≥1） |
| 9 | 1 | ext_len（0..=64） |
| 10 | 2 | suite_id |
| 12 | 4 | body_len（密文含 tag） |
| 16 | 12 | nonce（同时作为 HEVC session salt 输入） |
| 28 | 4 | CRC32-IEEE over bytes[0..28] |

隐含字段：`format_id = 5`、`stc_h`（来自 `HevcFormatProfile`，官方 7）、`total_windows = 1`。

### 13.9 flags、ext_len 与 TLV

- `EXT_PRESENT` 必须与 `ext_len > 0` 一致；`EXT_CRITICAL` 表示扩展区含 critical TLV。
- TLV：`type_id(1B) | len(1B) | value(len B)`；`type_id` 高位 `0x80` 为 critical。
  `type 0` 仅用于 padding，值必须全 0 且解析时跳过。
- **写侧拒绝 critical**：V4 尚未定义任何 critical TLV，`encode_extension_for_write`
  直接拒绝（否则写出的载体连本构建都读不回）。critical 只能由负测/伪造载体产生。
- **fail-closed**：未知 critical TLV → 立即拒绝；未知 non-critical TLV → 跳过；
  截断/长度越界 → `CorruptedData`；扩展区总字节数超上限 → 拒绝。
  上限：空间/JPEG `MAX_EXT_BYTES = 255`；HEVC `ext_len <= 64`。
- **扩展槽位**：
  - 空间域（PNG/WAV/FLAC）：`ext_slots = 8 * ext_len`，一槽一 bit，不经过 STC；
  - JPEG：`ext_slots = ext_u * (8 * ext_len + ext_h - 1)`（官方 `h=8, u=4`）；
  - HEVC：`ext_slots = 2 * (8 * ext_len + 7 - 1)`，固定 `h=7, u=2`。
  `ext_len = 0` 时：HEVC 与空间域为 0；**JPEG 例外**——按上式仍占 `ext_u * (ext_h - 1) = 4 * 7 = 28` 槽（官方 h=8, u=4），因为扩展区 STC 网格在零 TLV 时仍保留 trellis 尾长；该值由 `stego/format.rs::extension_slots` 与同文件内联测试固定，写读两侧一致。
  **off-by-8 语义**：`ext_len` 是字节数，消息位是 `8 * ext_len`，不是 `ext_len`。

### 13.10 容量公式

统一形式：

```text
header_slots = base_slots + ext_slots
body_slots   = total_slots - header_slots
max_payload  = message_bits(body_slots, stc_h) / 8 - BODY_OVERHEAD
```

- **PNG**：`total_slots` 为可用绿色/RGB 槽；`base_slots = 512`（64B 头）。
- **WAV / FLAC**：`total_slots` 为采样或残差槽；`base_slots = 512`。
- **JPEG**：`total_slots` 为全图 AC（`k=1..63`）几何网格；`base_slots = 718`
  （44B 头 = 352 bit，`2 * (352 + 8 - 1)`）。
- **HEVC**：`total_slots` 为窗口内可用 CABAC bin；
  `base_slots = 524`，`ext_slots = 2 * (8 * ext_len + 6)`，`stc_h = 7` 固定：

```text
max_payload = message_bits(total_slots - (524 + ext_slots)) / 8 - 22
```

`probe` 与 `embed` 必须复用同一公式、同一调参与同一扩展区（`ProbeOptions.extensions`
必须等于即将写入的 `EmbedOptions.extensions`），否则容量与实际可嵌长度会不一致。
**工作内存预算同为公式的一部分**：PNG/JPEG 的 STC 求解有统一预算（PNG 8 GiB，
含像素/代价图/槽位/trellis 位图），`probe` 上报的 `max_raw_payload_bytes` 已经预算
折算，`embed` 对同一载荷套用同一预算门；超出预算按容量不足（`PayloadTooLarge`）
拒绝，而不是报"不支持的文件格式"。
长视频 `probe` 默认按前 20% 窗口加权估算；`--exact` / `exact=true` 才全量扫描。

### 13.11 PNG 代价排序（规范性）

读取侧必须重建正文候选的顺序，而候选顺序由代价图决定。本节固定 `algorithm_id = 1`（HILL）
的完整算法。**代价图只通过"排序 + 截断"影响格式**；它的绝对数值不进入任何认证域。

#### 13.11.1 数值约定（ieee-order）

- 全程 IEEE-754 双精度（`f64`）。只使用 `+ - * /`、`abs`、`min`/`max`；**没有超越函数**。
- 所有求和的**顺序**在下面逐项给出，不得重结合（不得用"成对求和""树形归约"替代）。
- 不得把 `a*b + c` 融合为 FMA，也不得在 `--target-cpu=native` 下允许收缩（`fp-contract = off`）。
  一旦融合，末位不同 → 排序不同 → 候选集不同 → 读不出来。
- 结果只以 `f64::to_bits()` 参与排序（见 §13.11.3），NaN 不允许出现。

#### 13.11.2 HILL 代价图

输入：`pixels`（行优先、`channels` 交错）、`w`、`h`、`p1`、`p2`、`epsilon`。
输出：长度 `w*h` 的代价图（每像素一个值）。

```text
class_value(v) = v & 0xF8                      // 清除低 3 位，嵌入不改变它

灰度化:
  channels == 1 : gray[i]      = class_value(pixels[i])
  channels >= 3 : gray[i]      = 0.299*R + 0.587*G + 0.114*B   // R=ch0,G=ch1,B=ch2，左结合
  其他           : gray[i]      = class_value(pixels[i*channels])

pad  = 1 + (p1-1)/2 + (p2-1)/2                 // 整数除法；p1、p2 已保证为正奇数
对称延拓: 对 i ∈ [0, h+2*pad)、j ∈ [0, w+2*pad)
  reflect_index(t, n) : n<=1 -> 0; p=2n; t=t mod p（非负）; t>=n -> p-1-t; 否则 t
  X[i][j] = gray[reflect_index(i-pad, h)][reflect_index(j-pad, w)]

阶段 1（高通，KB 核）: hp=h+2*pad, wp=w+2*pad, h1=hp-2, w1=wp-2
  K = [-0.25, 0.50, -0.25, 0.50, -1.00, 0.50, -0.25, 0.50, -0.25]
  I1[i][j] = | K0*X[i][j]   + K1*X[i][j+1] + K2*X[i][j+2]
             + K3*X[i+1][j] + K4*X[i+1][j+1] + K5*X[i+1][j+2]
             + K6*X[i+2][j] + K7*X[i+2][j+1] + K8*X[i+2][j+2] |   // 严格左到右

阶段 2（低通 p1×p1 + 取倒数）: h2=h1-(p1-1), w2=w1-(p1-1), l1 = 1.0 / (p1*p1)
  I2[i][j] = 1.0 / max( sum_l1 , eps )        // eps 取 (epsilon>0 且有限) 否则 1e-12
  其中 sum_l1 = (Σ_{u=0..p1-1} (Σ_{v=0..p1-1} I1[i+u][j+v])) * l1
       —— 内层按 v 升序累加，外层按 u 升序累加；先求和再乘 l1

阶段 3（低通 p2×p2，可分离）: l2 = 1.0 / p2
  垂直: T[i][j] = Σ_{u=0..p2-1} ( I2[i+u][j] * l2 )     // 每项先乘 l2 再累加，u 升序
  水平: C[i][j] = ( Σ_{v=0..p2-1} T[i][j+v] ) * l2      // 先求和再乘 l2，v 升序
```

`C` 即代价图。注意阶段 3 的垂直与水平**不对称**（一项先乘、一项后乘），这是实现现状，
规范照抄；写成统一的"先求和再乘"会改变末位。

线上参数来源：`p1_window`、`p2_window`、`neg_log2_epsilon`（`epsilon = 2^-k`）、
`sigma`（f32，S-UNIWARD 用）都来自基础头，因此这些值不写死。

#### 13.11.3 候选截断与全序

```text
eligible = { px | 8 <= pixels[px*channels + hc] <= 247 }        // hc 同 §13.6.2
allowed  = |eligible| * (1000 - exclusion_permille) / 1000      // 整数除法，向零截断
candidates = eligible 中按 (cost.to_bits(), px) 升序排序后的前 `allowed` 个
```

- `exclusion_permille` 来自基础头字节 50..52 的 `exclusion_permille`（0..=900）。
  **必须用整数运算**：`|eligible| * (1000-p) / 1000`。写成 `|eligible| * (1.0 - p/1000.0)`
  再截断会在末位舍入上偏差一个元素（例如 `p=900, |eligible|=1000` 得 99 而非 100），
  导致读写候选集错位。
- 排序键是 `(cost 的 IEEE 位模式, 像素索引)` 的**全序**：代价非负有限，位模式的字典序与数值序一致；
  用位模式可让 `select_nth_unstable`（O(n) 选择）与全排序结果逐位一致。平局按像素索引升序。
- `allowed = 0` 表示没有正文槽位，直接按容量不足处理。

#### 13.11.4 另外两个代价模型（改动注意）

本节没有把这两个模型展开到与 §13.11.2 同级，原因是**踩坑方式不同**；动它们之前先读这一段。

**`algorithm_id = 2`（S-UNIWARD）——公式短，落地选择分散。** 它的数值路径与 HILL 同级：只有乘加、
`abs` 和一次倒数，没有超越函数。难点不在公式，而在四处「看起来无所谓」的选择，改任何一处都会
**静默改变排序**（不报错、不掉测试、只换候选集）：

1. 16 个 Daubechies-8 tap **按 10 位小数截断后硬编码**，不是数学精确值——重写时必须逐字保留这 16 个
   十进制常数，换成 `db8` 的精确系数会改变末位；
2. 两个 pass 的卷积**方向相反**（残差用反向核、适用性用正向核，前者是后者的精确伴随）；
   镜像任一者都会给边缘的另一侧定价；
3. 边界用 **clamp 延拓**（复制边缘像素），不是零填充——零填充会让最外圈显得特别"贵"；
4. `sigma` 默认 `1.0`（8-bit 空间的参考实现取值），**不是**论文的 `2^-6`（那是 JPEG 域设定）；
   它以 f32 存于头里（§13.8.1 字节 52..56）。

**`algorithm_id = 3`（MiPOD）——标定输出必须量化，否则会跨平台漂移。** 它把 Fisher 信息转换成
加性代价，中间有三处钉不住逐位结果的环节：

1. `rho` 由 `rho·(exp(rho)+2) = x` 的 Newton 迭代求出（最多 32 轮、相对容差 `1e-14`）；
2. 拉格朗日乘子用 Illinois regula falsi，在 32,768 桶的 log-Fisher 直方图上求根；
3. 全程依赖 `cos`、`exp`、`ln`，而 libm 的超越函数**不保证跨平台正确舍入**——IEEE-754 只约束
   `+ - * /` 与 `sqrt`。

这些代价同时喂给**候选排序**和 trellis，末位差就会把载荷挪到别的像素上，读侧只能返回
`NoHiddenData`（与错密码不可区分）。2026-11-06 在 Windows/UCRT 与 Ubuntu/glibc 上实测：

- 28 例真实语料逐例一致；合成图矩阵 12 组里 **`mipod` + 纯渐变图**这一组不一致
  （`62f4bc8d5d29` vs `e852749beeb6`），其余 11 组一致；
- 逐阶段摘要定位到差异**只发生在标定这一步**：`σ²`、`I_n`、`box_smooth` 的输出在两个平台上
  逐位相同（`cos` 不是问题），差的只有 `fisher_to_costs` 的输出，幅度 ≤ 255 ulp（相对 `2^-44`）。

因此 `fisher_to_costs` 在返回前把每个代价的**低 20 位尾数清零**（相对量子 `2^-32`）：比实测
离散度粗四个数量级，比任何会改变排序的代价差细六个数量级。量化后同一矩阵 12/12 一致，28 例
基线**一例未变**（真实语料的代价间隔远大于量子）。

残留风险与约束：

- 两个平台的数值若**跨过桶边界**仍会差一个量子（概率约 `离散度/量子 ≈ 4e-5`/元素）。这条只能靠
  跨平台 CI 兜底，不能靠文档保证；
- 量化位数属于 **F 级**：改它会同时改候选集与 trellis 取舍，等于改格式，必须重建基线；
- `u = 1` 与 Hamming 路径不吃代价，只有 STC 路径受影响。

这条管线的五个阶段都有固定摘要，见附录 A.3：改任何一段都会让 `cost_vector_digests_are_pinned`
变红，并在 `scripts/cost_vectors_check.py` 里指出是哪一段开始分叉。

#### 13.11.5 初等函数：不调用 libm

代价管线的每一步都会影响排序，所以 `exp` / `ln` / `ln_1p` / `cos` 不能来自平台数学库：
IEEE-754 只约束 `+ - * /` 与 `sqrt`，libm 的超越函数在 glibc / UCRT / musl 之间可以差 1–2 ulp，
经过 `1e-14` 的 Newton 容差放大后实测可达 255 ulp（§13.11.4）。`stego/detmath.rs` 因此自带实现：

| 函数 | 做法 | 精度 |
|---|---|---|
| `exp` | `k = round(x/ln2)`，两词 `ln2` 归约，14 项 Taylor（`|r| <= ln2/2`），指数域移位还原 | ~1 ulp |
| `ln` | `frexp` 取指数，尾数归一到 `[√2/2, √2)`，`2·atanh(s)` 级数到 `z^10/21` | ~1 ulp |
| `ln_1p` | `|x| < 2^-4` 走 12 项级数，否则回落 `ln(1+x)` | ~1 ulp |
| `cos` | 三词 `π/2` 归约（首个 33 位，`n·hi` 精确），象限选择，`r^16`/`r^17` 多项式 | ~1 ulp |
| `log2` | `ln(x) · log2(e)`；只用于把 `epsilon` 量化成头里的指数，取整前的一点点误差不影响 `k` | ~1 ulp |

只用 `+ - * /`、位级 `frexp`/`ldexp`、固定项数与固定顺序，因此结果是输入位模式的纯函数，
与平台数学库无关。精度比 libm 差一点无所谓——这里的契约是可复现，不是正确舍入。

三份实现必须逐位一致，各自跑一遍即可自检（摘要相同）：

| 语言 | 文件 | 命令 |
|---|---|---|
| Rust | `rust/src/stego/detmath.rs` | `cargo test --lib detmath` |
| Python | `scripts/detmath/detmath.py` | `python scripts/detmath/detmath.py` |
| Go | `scripts/detmath/detmath.go` | `go run scripts/detmath/detmath.go` |

```text
exp    68107bf871d53df2
ln     6021ef64db0e27ef
cos    55f3c5acb971153a
ln_1p  23e6e71dccf69b20
log2   d97b86f58ee1dfba
```

覆盖范围：空间域的 DCT 基与全域标定、JPEG 的 `precover` DCT 基（J-UNIWARD / J-MiPOD 用）、
以及 `header::quantize_epsilon_k` / 音频的同名函数（决定头里的 `neg_log2_epsilon`）。
`analysis` 域另有一份相同的 DCT 基，但那是检测分析、不参与写格式，仍用 libm。

已验证（2026-11-07）：**x86_64/MSVC、x86_64/glibc、aarch64/glibc 三个平台**的 Rust 实现给出同样的四组摘要，
Python 在两个 x86 平台、Go 在 x86_64 上也相同；28 例字节基线在三个平台上都是 **28/28 一致**。
把 libm 换成这套实现后基线一例未变，说明中间量的 ulp 级差异本来就被量化吸收。

arm64 的验证方式是交叉编译后免工具链运行：
`rustup target add aarch64-unknown-linux-musl` + `-C linker=rust-lld`（sysroot 里的 lld，无需外部工具链），
产出 ~3.3 MB 静态二进制，Debian 11 arm64 上直接 `--check` 全绿。

**移植注意**：别的语言在 arm64 上可能把 `a*b + c` 融合成 FMA（Go 就允许），那样逐位一致不成立；
移植时必须显式关闭收缩，或用不产生乘加的写法。

---

### 13.12 行为语义

- **extract 统一失败面**：错密码、错域、错方言、无数据、头部损坏、AEAD 失败、
  critical TLV 未知，全部返回 `NoHiddenData`（只有 `CorruptedData` /
  `UnsupportedVersion` 用于明确的结构错误，由调用方决定是否外露）。
- **verify 分级**：结构层（载体可解析）→ 头部层（长度/版本/CRC/suite 合法）→
  载荷层（AEAD 通过）；每级给出独立结论，不把"头部存在"误报成"载荷可解"。
- **未认证长度**：`body_len` 在解密前不可信，只用于在硬上限
  （`max_payload_bytes` / `HEADER_LEN_MAX`）内裁剪计算；超过上限立即拒绝，
  不按声明长度分配内存。
- **fail-closed**：未知 major 版本、未知 critical TLV、suite id 不在枚举内、
  CRC 不符、flags 预留位非 0，均在读 body 之前拒绝。

### 13.13 音频（WAV / FLAC）

- PCM 采样域（WAV）与 FLAC 残差域，16/24-bit 两种容器路径共用 64B 头。
- `pre_salt` 只取嵌入前后不变的元数据：WAV 用采样率/声道/位深/数据长度等并**排除
  实际 PCM 摘要**；FLAC 用 STREAMINFO 的非 MD5 字段并**排除 MD5**。两者字段编码为大端，
  避免字节序差异造成跨平台 `NoHiddenData`。
- 扩展区 TLV 与空间域同规则；`body_len` 语义同上（密文含 16B tag）。

### 13.14 HEVC / HEIF

- 只调制 TU 内 CABAC bypass 的 `coeff_sign_flag`；不改变码流尺寸与解码结果。
- 32B 头固定 524 个基础槽；`window_slices` 记录主窗口候选切片数，控制提取成本。
- `magic4 = HKDF-Expand(master, info(magic_label))[..4]`，即 L2 输出；私有构建改
  `magic_label` 即可消除开源指纹。头部槽位由凭据派生的 `locate_seed` 决定，不再是
  “只由参数集决定、与密码无关”。
- 扩展区 `ext_len <= 64`；HEIF 在方案 C 不可用时桥接到缩略图 JPEG/未压缩项。

### 13.15 私有构建

`StegoProfile` 的 `jpeg/png/hevc` 线格式身份是编译期常量；改任一派生标签即产生
不兼容线格式。运行时只能选 suite/domain/凭据，不能切换格式身份
（可切换的格式就是可枚举的指纹）。

### 13.16 写侧非规范性实现

以下内容决定"写成什么样"，不影响"能否读出"。它们**可以随时改动**，只要字节级基线
（`scripts/baseline_hash.py`）全绿；本规范不对它们作承诺。

- **trellis 求解**：`u > 1` 时按列做动态规划（状态 `2^h`、回溯位图每 `(列,状态)` 一位）。
  平局规则：`flip < keep` 严格小于才翻转（平局保留原值）；`±1` 两个方向都合法时
  `rho_plus <= rho_minus` 取 `+1`。这两条平局规则改变输出字节，但读侧不需要它们。
- **非对称方向代价**：空间域按"邻域类别均值"给 `±1` 两个方向定价（HILL 用 8 邻域残差平方的代理）；
  音频用 `perm_seed` 前 8 字节作为方向盐。只影响方向，不影响槽位集合。
- **`u` 的选择**：JPEG/空间域按容量与 `slot_budget` 选最大可行 `u`；HEVC 固定 `u=2`。
  读侧只信头里的值并做范围校验。
- **SIMD**：`avx2` 路径必须与标量路径**逐位等价**；基线比对是唯一判据。
- **重编码细节**：PNG 的 deflate 级别选择与行滤波器、WebP 的 `eof`/`riff_chunk` 策略、
  HEVC 重编码后短 1–4 字节补 0 的分支、FLAC 的预测器补偿与 MD5 重算。
- **重试**：FLAC 最多 6 轮（每轮换 salt/nonce 与 body phase）、HEVC 防竞争最多 24 轮。
- **并发**：`rayon` 的并行只用于逐元素映射，不参与归约，因此不改变结果。

---

## 14. 常量速查表（内容域）

### 14.2 内容域（V4）

| 常量 | 值 |
|---|---|
| `PUBLIC_DEFAULT_SECRET` | `"strhide-default-content-stego-key-2026"` |
| `SALT_LEN` / `NONCE_LEN` / `TAG_LEN` | `16` / `12` / `16` |
| `BODY_OVERHEAD` | `22`（4 长度 + 1 flags + 1 微头 + 16 tag） |
| `HEADER_LEN_MAX` | `67,108,863`（2²⁶ − 1） |
| `CONTENT_L1_PBKDF2_ITERATIONS` | `200_000` |
| `CipherSuiteId` | `1 = AES-256-GCM`（默认），`2 = ChaCha20-Poly1305`，append-only |
| **空间域基础头（PNG/WAV/FLAC）** | `64` 字节 / `512` 槽 |
| **JPEG 基础头** | `44` 字节 / `352` bit = `718` 槽 |
| **HEVC 基础头** | `32` 字节 / `524` 槽 |
| **扩展槽位数** | `stc_u × (8 × ext_len + stc_h − 1)`；HEVC 固定 `h=7, u=2` |
| **`MAX_EXT_BYTES`（空间/JPEG）** | `255`；HEVC `ext_len ≤ 64` |
| **JPEG STC 参数** | 头中自描述，`h ∈ 4..=10`，`u ∈ 1..=64` |
| **空间域默认 STC** | `h = 8`，`u ≤ 3`（Hamming (7,3) 为 `k=3`） |
| **空间域可嵌入像素范围** | `[8, 247]` |
| **HEVC 魔数** | `HKDF-Expand(master, info(magic_label))[..4]`（官方 `magic_label = b"strhide-hevc-magic-v4"`） |
| **HEVC STC 参数** | `h = 7, u = 2`（来自 `DEFAULT_HEVC_FORMAT`） |
| **HEVC 派生标签** | `cover_salt = b"strhide-hevc-cover-v1"`、domain 标签与 JPEG/PNG 共享 `b"strhide-stego-domain-v1"` |
| **HEVC 最大防竞争迭代轮数** | `24` |

### 补充常量（本次规范化新增）

| 常量 | 值 |
|---|---|
| `SPATIAL_ALGORITHM_HILL` / `_SUNIWARD` / `_MIPOD` | `1` / `2` / `3`（永久保留） |
| `EXCLUSION_PERMILLE`（默认） | `300` |
| `CHACHA12_ROUNDS` | `12`（6 个双轮） |
| `AUDIO_PERM_ROUNDS` | `6`（Feistel 轮数） |
| `STC_MIN_H` / `STC_MAX_H` | `4` / `10` |
| `SPATIAL_MAX_U` / `KERNEL_MAX_U` | `3` / `64` |
| `HEVC_SUPERBLOCK_MIN_SLOTS` | `524` |
| `JPEG_SUPERBLOCK_SLOTS` / `JPEG_EXT_SLOTS(0)` | `718` / `28` |
| `FLAC_EMBED_ATTEMPTS` / `HEVC_MAX_ANTI_COLLISION` | `6` / `24` |

---

## 15. 兼容矩阵（内容域）

### 15.1 版本与布局兼容

| 读侧能力 \ 写侧产物 | 是否可读 | 结果 |
|---|---|---|
| V4 内容信封（当前，基头 64/44/32 B + 可选 TLV） | ✅ | 正常读取 |
| Scheme C（HEIF/HEIC、HEVC Annex-B、MP4/MOV、MKV 原位 CABAC） | ✅ | 原生支持（MKV 支持在 v0.8.x 引入） |
| Audio（WAV PCM LSB 与 FLAC 残差隐写） | ✅ | v0.8.x 起原生支持（content-audio 特性） |
| V3 及更早的内容信封 | ❌ | 无兼容读路径（V4 重写了头部与派生，旧类型已删除） |
| 未知 `format_id` / 未知 `suite_id` / 未知 `algorithm_id` | ❌ | 一律 `NoHiddenData`，不回落到任何默认值 |

### 15.2 方言（Profile）兼容

| 配置组合 | 官方读侧 | 同方言读侧 | 备注 |
|---|---|---|---|
| 官方默认密钥 | ✅ | ✅ | 完全互通（`PUBLIC_DEFAULT_SECRET` 不提供对抗源码持有者的机密性） |
| 内容域自定义 `stego_secret` | ❌ | ✅ | 错误密钥表现为 `NoHiddenData`（与错误密码不可区分） |
| 内容域自定义 `stego_domain` | ❌ | ✅ | HKDF 域标签不同，密钥与 header 置换不一致 |
| 私有 `PngFormatProfile` / `JpegFormatProfile` / `AudioFormatProfile` / `HevcFormatProfile` | ❌ | ✅ | `hpos_salt`、`cover_digest_tag`、`grid_rule`、标签或 `stc_h`/`stc_u` 任一不同即产生不兼容格式 |
| 显式 `domain` | 仅同 domain 可读 | 同 domain 可读 | 域参与 L1/L2/L3 全部派生 |
| suite 2（ChaCha20-Poly1305） | ✅ | ✅ | 0.8.5+ 已实现；更早的构建报不支持 |

### 15.3 写侧参数与互读

| 参数 | 是否影响互读 | 说明 |
|---|---|---|
| `exclusion_percentile` | 影响（已自描述） | 写入基础头 `exclusion_permille`；读侧按头值 + 整数截断重建候选 |
| `p1_window` / `p2_window` / `epsilon` / `sigma` | 影响（已自描述） | 全部进基础头；读侧不再读取调用方参数 |
| `stc_h` / `stc_u` | 影响（已自描述） | 头里 4..=10 / 1..=64 |
| `channel_mode` / `class_rule` | 影响（已自描述） | PNG 专用；读侧按头值展开通道 |
| `algorithm_id` | 影响 | `1` 已规范化；`2`/`3` 写入后仅同实现可读（§13.11.4） |
| 压缩策略与级别 | ❌ 不影响 | 只在密文内 flags 体现，读侧始终 inflate |
| 写侧重试次数（FLAC 6 / HEVC 24） | ❌ 不影响 | 只影响成功概率与耗时 |
| SIMD / 并行度 | ❌ 不影响 | 要求与标量逐位等价 |

---

> 本规范随内容域线格式改动更新。任何新增 `format_id`、TLV、派生标签、槽位规则或代价模型，
> 都必须同步更新本文件（含 §13.0 的分级表与 §15 兼容矩阵）与对应测试
> （`cargo test`、`cargo test --doc`、`python scripts/baseline_hash.py --check`）。
> **改动 §13.4–§13.7、§13.11 的任一算法即构成线格式变更**，必须走格式评审，不能只改代码。

---

## 附录 A 冻结向量与跨平台实测

下面这些向量是"改了就一定有事"的哨兵。它们的用途不是给外部实现对照，而是让**本仓库的测试**
在有人无意改动 F 级内容时立刻变红。

| 向量 | 内容 | 守护对象 |
|---|---|---|
| ChaCha12 KAT | `seed = 00 01 00…00`（首字节 1）的前 128 字节 | §13.5.1 流发生器 |
| 整段置换 | `seed = b"strhide-prng-contract-seed-2026!"`，`n = 256`，前 16 个位置 = `61 121 191 236 8 58 233 146 64 12 35 66 70 210 254 52` | §13.5.3 整段 Fisher–Yates |
| 前缀置换 | 同一 seed，`n = 256`，`k = 16`，前 16 个位置 = `135 5 129 183 174 138 43 152 172 19 34 143 201 40 236 108` | §13.5.3 前缀 Fisher–Yates 与续接稳定性 |
| 字节级基线 | `testdata/baseline/` 28 个载体 × (structure, content) 的 SHA-256 | 全部 F 级内容的综合结果 |

前三个在 `rust/src/stego/prng.rs` 的 contract test 里；第四个用
`python scripts/baseline_hash.py --check` 跑。四者全绿只说明"没有意外改动字节"，
**不说明**别的实现能读出这些字节——后者不在本文的承诺范围（见 §13.0）。

新增 F 级内容时，应同时给它加一个可固定的摘要（置换序列、矩阵列、syndrome 字节），
否则下次重构就只能靠人工比对。

### A.2 跨平台实测（2026-11-06）

字节级基线平时只在 Windows 上跑，所以"同一份载体换个平台还读得回吗"一直没有数据。用一台
Ubuntu 22.04 / x86_64（1 核）实机验证：

| 项 | 结果 |
|---|---|
| 28 例真实语料 `--check` | **x86_64/Windows、x86_64/Ubuntu、aarch64/Debian 11 三个平台均 28/28 逐例一致**（含 PNG 的 hill/suniward/mipod、JPEG 的 uerd/juniward/jmipod、HEVC、FLAC、WAV） |
| 合成图矩阵（4 图 × 3 算法，800×800，32 KiB 载荷，固定 `--seed`） | 修复前 11/12；修复后 **12/12** |
| 唯一不一致 | `mipod` + 纯渐变图：Windows `62f4bc8d5d29` / Linux `e852749beeb6` |
| 差异定位 | `σ²`、`I_n`、`box_smooth` 逐位相同；只有 `fisher_to_costs` 的输出不同，≤ 255 ulp |

复现方式：两边各跑一次 `scripts/baseline_hash.py --check`，再用同一张图、同一 `--seed` 各
`embed -a mipod` 一次比对 `sha256`。**没有把这一步放进 CI**：`testdata/` 有 845 MB，只适合本地
或专用跑机；想让它在 CI 里生效，得先挑一小组（≤ 5 MB）进入仓库。

### A.3 跨实现向量（`cost-vectors.json`）

字节比对只能告诉你"最后不一致"，说不出是哪一步。所以 MiPOD 的代价管线另有一组**逐阶段摘要**：

| 文件 | 作用 |
|---|---|
| `docs/api/cost-vectors.json` | 固定输入（32×32 RGB，像素以 hex 内联）+ 五个阶段的 FNV-1a 摘要 |
| `rust/src/stego/png/cost/mipod.rs` 的 `vectors` 测试 | 重算并与摘要比对；`STHIDE_WRITE_COST_VECTOR=1` 时重新生成 JSON |
| `scripts/cost_vectors_check.py` | 纯标准库的第二实现（Python），从 JSON 复算全部五段 |
| `scripts/detmath/{detmath.py,detmath.go}` | 两份 `exp`/`ln`/`ln_1p`/`cos` 移植，摘要必须与 §13.11.5 的四个值相同 |

阶段：`plane`（`pixel & 0xF8` 的亮度）→ `variance`（`σ²`，Wiener 残差 + 局部余弦补空间）→
`fisher`（`2/σ⁴`）→ `smoothed`（7×7 盒滤波）→ `cost`（标定 + 量化，**这条是契约**）。

实测（2026-11-06）：Windows 上的 Python 与 Linux/glibc 上的 Python **五段全部逐位相同**，
无需任何容差；脚本耗时 0.3 秒。用法：

```bash
cargo test --release --all-features --lib cost_vector   # Rust 侧：摘要未漂移
python scripts/cost_vectors_check.py                    # 另一语言：五段是否一致
```

新增一个 F 级数值阶段（例如换代价模型）时，应同时扩一份这样的向量：它比字节比对早一步定位问题，
也是"另一个语言实现是否对齐"的唯一低成本判据。

### A.4 第二实现：`scripts/spec_extract_png.py`

一份只读的 Python 实现，用来验证本文是否足够写出一个能读出 Rust 产物的读取器。它不复用任何
Rust 代码，全部按 §13.3–§13.11 重写：

| 组成 | 覆盖的章节 |
|---|---|
| PNG 解码（8-bit、非隔行、filter 0–4） | —（载体编解码，不属于线格式） |
| `pre_salt`、L1/L2/L3、`info(label, domain)` | §13.4 |
| ChaCha12 + 拒绝采样 + 前缀/整段 Fisher–Yates | §13.5（含 KAT 自检） |
| 头部池、正文候选与排序、槽位展开 | §13.6、§13.11.1–13.11.3（HILL） |
| STC 列向量与 syndrome | §13.7 |
| AEAD AAD、微头、`body_len` 语义 | §13.2、§13.3、§13.8 |

实测（2026-11-06/07）：

| 用例 | 结果 |
|---|---|
| `hill` + 文本载荷（无密码） | 读出 |
| `hill` + 密码 | 读出 |
| `hill` + 文件载荷（`u = 1` 路径，300 B） | 逐字节一致 |
| **`mipod` + 文本，Rust 在 Windows 嵌入、Python 在 Windows 读取** | 读出 |
| **`mipod` + 文本，Rust 在 Windows 嵌入、Python 在 Ubuntu/glibc 读取** | 读出 |
| 错误密码 | `header CRC mismatch`，与"没有数据"不可区分 |

`mipod` 那两行是关键：读取只需要**排序**一致，而排序经 §13.11.4 的量化后对 libm 差异不敏感，
所以**不需要先自己实现 `exp`/`ln`/`cos`**——那是"产出同样字节"才需要的。

未覆盖（有意留白，不是遗漏）：S-UNIWARD 代价模型、JPEG / HEVC / 音频载体、扩展 TLV、
suite 2、Hamming 编码、16-bit PNG。想扩到这些地方时，按上表逐块补即可，键派生与 STC
这两层不需要再动。

```bash
python scripts/spec_extract_png.py carrier.png            # 默认公开密钥
python scripts/spec_extract_png.py carrier.png --password pw --out payload.bin
python scripts/spec_extract_png.py --self-test            # ChaCha12 KAT
```
