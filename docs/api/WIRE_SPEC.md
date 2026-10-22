# strhide 线格式规范（Wire Specification）

> 适用版本：crate `strhide` 0.5.x（Rust 实现）。
> 本文是 strhide 隐写字节布局的**权威规范**，内容按当前源码核对：结构域 UBE 见 `src/envelope.rs`、`src/engine.rs`、`src/crypto.rs`；内容域微信封见 `src/stego/`。
> 配套文档：[ARCHITECTURE.md](./ARCHITECTURE.md)（模块职责与数据流转）。

---

## 目录

1. [总览与术语](#1-总览与术语)
2. [结构域：UBE v2.2 总体布局](#2-结构域ube-v22-总体布局)
3. [Envelope Header（112 字节）](#3-envelope-header112-字节)
4. [标志位（Flags）](#4-标志位flags)
5. [AAD（认证附加数据）](#5-aad认证附加数据)
6. [密码提示（Password Hint）](#6-密码提示password-hint)
7. [元数据块（Metadata Block）](#7-元数据块metadata-block)
8. [载荷分块流（Payload Chunk Stream）](#8-载荷分块流payload-chunk-stream)
9. [Envelope Trailer（24 字节）](#9-envelope-trailer24-字节)
10. [密钥派生与加密细节](#10-密钥派生与加密细节)
11. [Stealth（隐蔽）模式](#11-stealth隐蔽模式)
12. [散落策略信道头：PE Codebits ChannelHeader（14 字节）](#12-散落策略信道头pe-codebits-channelheader14-字节)
13. [内容域：微信封（Micro-Envelope）](#13-内容域微信封micro-envelope)
14. [常量速查表](#14-常量速查表)
15. [兼容矩阵](#15-兼容矩阵)

---

## 1. 总览与术语

strhide 有两个相互独立的隐写域，各自有不同的字节布局：

| 域 | 承载内容 | 字节布局 | 入口 |
|---|---|---|---|
| **结构域（structure）** | 一个自包含的 **UBE**（Universal Byte Envelope，连续或经散落信道编码），有头、有尾、有魔数 | 本规范 §2–§12 | `engine` |
| **内容域（content）** | 嵌入图像像素 / DCT 系数 LSB 的**微信封**，无静态魔数 | 本规范 §13 | `stego` |

### 1.1 两种信封格式对比（重要）

`write` 与 `embed` 产出的是**两套不同的信封**，不是同一信封的不同封装。它们的派生域相互隔离，互不兼容，也不能互相读取。差异如下：

| 维度 | 结构域信封（`write`，UBE） | 内容域微信封（`embed`） |
|---|---|---|
| 代码 | `envelope.rs` + `engine.rs` + `pe_codebits.rs` | `stego/envelope.rs` |
| 总体结构 | `112B header` + 可选 hint + 元数据块 + 分块载荷 + `24B trailer`（散落策略外包 `14B ChannelHeader`） | `16B salt` + `12B nonce` + 单个密文块 |
| 静态魔数 | 有：8B 头魔数 + 4B 尾魔数 | **无**，整体呈高熵随机数据 |
| 定位尾标（trailer） | 有 24B（offset/size/CRC/magic） | 无 |
| 元数据 | 文件名、原始大小、原始 SHA-256、创建时间（独立 AEAD 块） | 无文件名/时间戳；仅密文内 4B 长度 + 1B 标志 |
| 载荷密封 | 分块：每块 `u32 LE` 长度前缀 + 密文，chunk AAD 含 index/is_last | 一次性整体密封，无分块 |
| 字节序 | 小端 | 外层无整数；密文内部长度为**大端** |
| AEAD AAD | 前 80B header；分块再追加 `chunk_index/is_last` | `salt ‖ nonce`（28B） |
| 无密码默认密钥 | `BUILTIN_DEFAULT_KEY` | `PUBLIC_DEFAULT_SECRET` |
| HKDF 子密钥标签 | `strhide-payload`、`strhide-metadata`（掩码：`strhide-header-mask-v1`、`strhide-pe-channel-mask-v1`） | `strhide-stego-enc-v1`、`strhide-stego-perm-v1`、`strhide-stego-hpos-v2`、`strhide-stc-trellis-v1` |
| 额外派生 | stealth 魔数与 76B/10B 字段掩码 | header 槽位置换种子（无 salt）、STC 网格种子 |
| 宿主还原 | 记录宿主 size + SHA-256，支持 bit-for-bit 还原（散落策略依赖 slack diff） | **无宿主还原**：像素/系数被改即不可逆，只能重嵌或覆盖 |
| 最终承载 | 注入容器结构空隙（chunk/段/box/overlay 等）或指令编码散落 | 矩阵编码分散到像素 / DCT 系数的 LSB |
| 压缩 | raw deflate；`Auto` 需节省 ≥2% 才保留 | raw deflate；`compressed.len() < raw.len()` 才保留 |
| 密码 NFC 归一化 | 统一做 Unicode NFC 归一化 | 统一做 Unicode NFC 归一化 |

> 旧设计文档 §1.2 曾把"像素域 LSB"列为非目标；内容域是在该边界调整后新增的，因此其信封格式没有沿用 UBE，而是独立设计的极简伪随机结构。

术语：

- **UBE**：Universal Byte Envelope，结构域注入载体的完整字节容器。
- **Carrier / Host**：载体文件（PNG、JPEG、MP4 等）。
- **AEAD**：AES-256-GCM 认证加密；密文附带 16 字节 tag。
- **AAD**：AEAD 认证但不加密的附加数据（见 §5）。
- **Profile / Dialect（方言）**：读写必须一致、但不写入线格式的私有参数（见 [ARCHITECTURE §6](./ARCHITECTURE.md#6-参数分级模型l-class-与-p-class)）。

**字节序**：结构域所有多字节整数一律**小端（little-endian）**；内容域微信封内部长度为大端（见 §13）。

**版本**：结构域 `CURRENT_VERSION = 0x02`。

---

## 2. 结构域：UBE v2.2 总体布局

```text
偏移区（相对 UBE 起点）
┌──────────────────────────────┬─────────────────────────────┐
│ 0                            │ Envelope Header（112 字节）  │  §3
├──────────────────────────────┼─────────────────────────────┤
│ 112                          │ Password Hint（hint_len 字节，可选）│  §6
├──────────────────────────────┼─────────────────────────────┤
│ 112 + hint_len               │ Metadata Block（meta_len 字节，AEAD）│  §7
├──────────────────────────────┼─────────────────────────────┤
│ 112 + hint_len + meta_len    │ Payload Chunk Stream（分块 AEAD）│  §8
├──────────────────────────────┼─────────────────────────────┤
│ ube_total_size - 24          │ Envelope Trailer（24 字节）  │  §9
└──────────────────────────────┴─────────────────────────────┘
```

UBE 总尺寸由下式精确给出（写侧在注入前预算，注入后交叉核对）：

```text
ube_total_size = HEADER_SIZE(112)
               + hint_len
               + meta_len                        // raw meta 长度 + 16（tag）
               + payload_written                 // 见 §8.4
               + TRAILER_SIZE(24)
```

---

## 3. Envelope Header（112 字节）

定长 112 字节，小端序列化。前 80 字节即 AAD（§5）；后 32 字节在注入完成后才填入（注入器在放置信封前不知道最终偏移）。

| 相对偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 8 | `magic_header` | `[u8; 8]` | 头魔数（§3.1） |
| 8 | 1 | `version` | `u8` | 信封版本，当前 `0x02` |
| 9 | 1 | `flags` | `u8` | 标志位（§4） |
| 10 | 1 | `strategy_id` | `u8` | 策略 ID（§7 适配器表） |
| 11 | 1 | `reserved` | `u8` | 保留，必须为 0 |
| 12 | 16 | `salt` | `[u8; 16]` | KDF 随机盐 |
| 28 | 12 | `base_nonce` | `[u8; 12]` | 随机基准 nonce |
| 40 | 8 | `orig_host_size` | `u64` | 原始载体尺寸 |
| 48 | 32 | `orig_host_sha256` | `[u8; 32]` | 原始载体 SHA-256（原始字节，非 hex） |
| 80 | 8 | `inject_offset` | `u64` | 注入点在载体中的偏移 |
| 88 | 8 | `inject_size` | `u64` | 注入区域字节数 |
| 96 | 4 | `patch_offset` | `u32` | 被补丁位置（stego 坐标）；0 表示无补丁 |
| 100 | 4 | `orig_patch_val` | `u32` | 被补丁位置的原始值 |
| 104 | 4 | `meta_len` | `u32` | 元数据块（含 tag）长度 |
| 108 | 4 | `hint_len` | `u32` | 密码提示长度 |

### 3.1 魔数（Magic）

头魔数按模式取值：

- **标准模式**：`STANDARD_HEADER_MAGIC = [0xb7, 0x54, 0x2c, 0x82, 0x7e, 0x31, 0x1d, 0x6e]`（8 字节，高熵伪随机，取自 `SHA-256("strhide-standard-header-v2")[..8]`）。
- **自定义方言**：`Profile::magic.header`。
- **Stealth 模式**：由密码派生（§11.1），覆盖上述取值。

### 3.2 字段校验

读取侧对不可信的 header 执行 `validate_against(ube_total_size)`：

- `version` 必须等于 `CURRENT_VERSION`；
- `hint_len` 不得超过 `MAX_HINT_LEN = 1024`；
- `hint_len + meta_len + (112 + 24)` 不得超过 `ube_total_size`。

---

## 4. 标志位（Flags）

`flags` 字节位定义：

| 位 | 常量 | 值 | 含义 |
|---|---|---|---|
| bit 0 | `FLAG_ENCRYPTED` | `0x01` | 使用了**用户密码**（无密码时此位为 0，但载荷仍以密钥加密） |
| bit 1 | `FLAG_COMPRESSED` | `0x02` | 载荷密封前经过 raw deflate 压缩 |
| bit 2 | `FLAG_IS_FILE` | `0x04` | 载荷是文件（而非内联字节/文本） |
| bit 3 | `FLAG_STEALTH` | `0x08` | Stealth 模式：密码派生魔数 + 字段掩码 |
| bit 4 | `FLAG_HAS_HINT` | `0x10` | header 后跟随密码提示 |
| bit 5 | `FLAG_COMPACT_META` | `0x20` | 元数据为紧凑二进制布局（§7） |
| bit 6–7 | — | — | 保留，必须为 0 |

要点：

- **`FLAG_ENCRYPTED` 不等于"是否加密"**：该位为 0 时，载荷与元数据仍以 `Profile` 的默认密钥（官方方言为内置公开密钥）密封。
- 当前写侧对可编码的元数据**总是**置 `FLAG_COMPACT_META`；JSON 布局已移除。

---

## 5. AAD（认证附加数据）

header 的**前 80 字节**构成定长 AAD（`AAD_SIZE = 80`），被绑定进元数据块与每个载荷分块的 AEAD 密封。篡改其中任何字节都会使认证失败。

AAD 即以下字段的拼接（与 §3 表中偏移 0..80 一致）：

```text
magic_header (8) | version (1) | flags (1) | strategy_id (1) | reserved (1)
| salt (16) | base_nonce (12) | orig_host_size (8) | orig_host_sha256 (32)
```

---

## 6. 密码提示（Password Hint）

- 当 `FLAG_HAS_HINT` 置位时，紧跟 header 的 `hint_len` 字节为提示文本（UTF-8）。
- 提示在写入前做 NFC 归一化并 `trim()`，最长 1024 字节。
- **与 stealth 互斥**：stealth 模式下不允许提示（提示本身会成为定位线索，且 stealth 依赖密码定位）。

---

## 7. 元数据块（Metadata Block）

元数据块始终经 AEAD 密封（即使无用户密码）。其明文为 **compact 二进制布局**（`FLAG_COMPACT_META`）。

### 7.1 Compact 明文布局

```text
┌──────────┬──────────────┬──────────┬────────────┬──────────────┬────────────┐
│ version  │ name_len     │ filename │ raw_size   │ raw_sha256   │ created_at │
│ u8 (1)   │ u16 LE (2)   │ name_len│ varint     │ 32 字节       │ varint     │
└──────────┴──────────────┴──────────┴────────────┴──────────────┴────────────┘
```

| 字段 | 编码 | 说明 |
|---|---|---|
| `version` | `u8` = `0x01`（`COMPACT_META_VERSION`） | compact 元数据布局版本 |
| `name_len` | `u16` LE | 文件名长度（最大 65535） |
| `filename` | UTF-8 字节 | 载荷文件名（文本载荷时为空） |
| `raw_size` | varint（§7.2） | 未压缩载荷尺寸 |
| `raw_sha256` | 32 原始字节 | 未压缩载荷 SHA-256 |
| `created_at` | varint | 写入时刻的 Unix 秒级时间戳 |

### 7.2 Varint 编码

无符号 LEB128：每字节低 7 位承载数据，最高位（bit 7）为 1 表示后续还有字节，低位组在前；解码器最多接受 10 字节，超出即报错。

### 7.3 元数据 AEAD

- 密钥：`meta_key`（§10）。
- Nonce：`make_meta_nonce(base_nonce)` —— 与载荷分块 nonce 域分离（§10.2）。
- AAD：§5 的 80 字节 header AAD。
- 线格式长度：`meta_len = len(compact 明文) + 16`（tag）。

### 7.4 最小明文尺寸

空文件名、1 字节载荷时，compact 明文为：

```text
1 (version) + 2 (name_len) + 0 (name) + 1 (raw_size) + 32 (digest) + 5 (created_at)
= 41 字节
```

（`created_at` 为当前量级 Unix 时间戳，约 1.7×10⁹，varint 需 5 字节。）

---

## 8. 载荷分块流（Payload Chunk Stream）

载荷（压缩后或原文）按 `chunk_size` 切分，逐块独立 AEAD 密封，每块自带长度前缀。**分块大小不协商、不存储**：读侧按长度前缀自定界，因此写侧可自由选择分块而不影响互读。

### 8.1 分块帧格式

```text
┌──────────────┬────────────────────────────────────┐
│ chunk_len    │ chunk ciphertext                   │
│ u32 LE (4)   │ len = chunk_len（明文 + 16B tag）  │
└──────────────┴────────────────────────────────────┘
```

- `chunk_len` 为该块**密文**长度（含 16 字节 tag），不含自身 4 字节前缀。
- 分块顺序排列，直到覆盖整个载荷区域。

### 8.2 分块 AAD

每个分块的 AAD 为：

```text
header AAD (80) | chunk_index (u64 LE, 8) | is_last (u8, 1)     // 共 89 字节
```

- `chunk_index` 从 0 起递增。
- `is_last`：最后一块为 1，其余为 0。

### 8.3 空载荷约定

即使载荷为空（0 字节），写侧仍产出**一个空的最终块**（`is_last = 1`，明文为空，密文为 16 字节 tag），使读侧能区分"无载荷"与"流被截断"。

### 8.4 长度计算

```text
chunk_count = max(1, ceil(plaintext_len / chunk_size))
payload_written = plaintext_len + chunk_count * 20
                  // 每块开销：4（长度前缀）+ 16（tag）= 20
```

读侧逐块处理，单块长度上限为 `min(载荷区剩余字节, MAX_CHUNK_SIZE)`，防止伪造信封申请巨型分配。

---

## 9. Envelope Trailer（24 字节）

定长 24 字节，位于 UBE 末尾，为读侧提供从载体 EOF 反向定位的手段。

| 相对偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 8 | `ube_offset` | `u64` | UBE 在载体中的（实际）起始偏移 |
| 8 | 8 | `ube_total_size` | `u64` | UBE 总尺寸 |
| 16 | 4 | `trailer_crc32` | `u32` | 前 16 字节的 CRC32（见下） |
| 20 | 4 | `trailer_magic` | `[u8; 4]` | 尾魔数 |

- **尾魔数**：标准模式为 `STANDARD_TRAILER_MAGIC = [0x78, 0xe6, 0x66, 0xd2]`（取自 `SHA-256("strhide-standard-trailer-v2")[..4]`）；自定义方言为 `Profile::magic.trailer`；stealth 为密码派生值（§11.1）。
- **CRC32**：标准模式 `trailer_crc32 = CRC32_IEEE(ube_offset ‖ ube_total_size)`（即前 16 字节，`crc32fast`）。Stealth 模式该值与密码派生掩码异或（§11.3）。
- 解析时先校验魔数，再校验 CRC；`read_from_tail` 读取载体最后 24 字节，无法构成合法 trailer 时返回"无信封"（非错误）。

---

## 10. 密钥派生与加密细节

### 10.1 主密钥派生

```text
1. 密码做 NFC 归一化（§10.3）
2. PBKDF2-HMAC-SHA256(password, salt, iterations = 100_000) → IKM (32 字节)
3. HKDF-SHA256(salt = Some(salt), IKM)，按不同 info 独立 expand：
   - info = b"strhide-payload"  → payload_key (32)
   - info = b"strhide-metadata" → meta_key    (32)
```

- 密码来源：`FLAG_ENCRYPTED` 时为用户密码；否则为 `Profile::secret()`（官方方言为 `BUILTIN_DEFAULT_KEY`）。
- 算法固定为 **AES-256-GCM**；PBKDF2 轮数固定 **100 000**，均为线格式常量。

### 10.2 Nonce 派生

由 12 字节 `base_nonce` 派生：前 8 字节保持不变，低 4 字节（按 u32 LE 解读）与一个值异或：

```text
make_chunk_nonce(base_nonce, index): 低 32 位 = base_nonce[8..12] XOR chunk_index
make_meta_nonce(base_nonce):         低 32 位 = base_nonce[8..12] XOR 0xFFFFFFFF
```

元数据块固定占用 `XOR 0xFFFFFFFF` 的 nonce，与所有载荷分块（index 从 0 起）域分离，不会复用 nonce。

### 10.3 NFC 归一化

所有密码、提示、文件名在进入派生/存储前做 Unicode NFC 归一化（`normalize_nfc`），避免 macOS/iOS 的 NFD 分解形式导致跨平台派生出不同密钥。

### 10.4 压缩

- 算法为 **raw deflate**（无 zlib 头/尾），级别默认 6（范围 0..=9）。
- 是否保留压缩由 `CompressionStrategy` 决定（`Auto` 时需 `comp_len*100 < raw_size*98`，即至少节省 2%）；该决策为写侧行为，读侧只看 `FLAG_COMPRESSED` 并以元数据 `raw_size` 作为解压硬上限。

---

## 11. Stealth（隐蔽）模式

Stealth 模式要求必须提供用户密码。其目标是：没有密码时，信封的魔数、头部敏感字段、尾部 CRC 都呈现为高熵随机数据，无法通过静态特征定位。

### 11.1 魔数派生

```text
PBKDF2-HMAC-SHA256(password, domain, 100_000) → IKM
HKDF-SHA256(salt = Some(domain), IKM)：
  info = b"strhide-stealth-header"  → header magic (8)
  info = b"strhide-stealth-trailer" → trailer magic (4)
```

- `domain` 为域分隔符：官方为 `STEALTH_DOMAIN = b"strhide-stealth-v1"`，可由 `Profile::stealth_domain` 替换。
- 注意此处 PBKDF2 的"盐"即 `domain`（与常规信封的随机 salt 不同）。

### 11.2 头部字段掩码

```text
derive_header_mask(password, salt):
  PBKDF2-HMAC-SHA256(password, salt, 100_000) → IKM
  HKDF expand info = b"strhide-header-mask-v1" → mask (76 字节)
```

掩码（写侧异或，读侧再异或还原）：

```text
header bytes 8..12   XOR mask[0..4]    // version | flags | strategy_id | reserved
header bytes 40..112 XOR mask[4..76]   // orig_host_size 起的 72 字节
```

- `salt`（12..28）与 `base_nonce`（28..40）不掩码（本就是随机值，且是派生输入）。
- **非 stealth 的无密码信封**也采用相同掩码机制，但掩码密钥为 `Profile::secret()`；`FLAG_ENCRYPTED` 信封不掩码（由 AEAD 认证）。

### 11.3 Trailer CRC 掩码

```text
derive_trailer_crc_mask(trailer_magic) =
    CRC32_IEEE( trailer_magic ‖ b"STEA" )        // b"STEA" = 0x53,0x54,0x45,0x41
trailer_crc32(stealth) = raw_crc XOR mask
```

这使得无法通过扫描标准 IEEE CRC32 特征来发现 trailer。

### 11.4 读侧三层识别

`EnvelopeHeader::unpack_with_profile` 按序尝试：

1. **密码 + stealth**：若密码派生的 header 魔数匹配（先认证密码），用密码去掩码，要求 `version = 0x02` 且 `FLAG_STEALTH` 置位；
2. **Profile 默认密钥去掩码**：要求 `version = 0x02`、无 `FLAG_ENCRYPTED`、`strategy_id ≤ 11`、`reserved = 0`；
3. **裸 header**：直接解析（`FLAG_ENCRYPTED` 信封不掩码）。

---

## 12. 散落策略信道头：PE Codebits ChannelHeader（14 字节）

### 12.1 产生背景与角色

结构域的大多数策略（如 `chunk`、`app_segment`、`box_uuid`、`pre_cd_inject`）均在载体的结构性空隙中连续存放完整的 UBE 信封（含 112B Header 与 24B Trailer）。

但**散落策略（scattered strategy，当前为 `pe_codebits`）**不同：它将 UBE 字节流逐比特编码进 PE 文件 `.text` 代码节中 x86/x64 指令的等价编码中（如 ModR/M 寻址形式、SIB 字节变换、TEST 指令等），在载体中**没有连续的文件偏移**。

为使读侧定位器（`locate`）与提取器（`open_ube_reader`）能够在不反汇编整段代码的前提下快速确定嵌入 UBE 的字节数、版本以及 100% 还原所需的原指令差异信息，`pe_codebits` 在代码流的前 112 个可用指令槽位中承载了一个定长 14 字节的信道头（`ChannelHeader`，14 字节 = 112 比特）。

### 12.2 信道头布局（14 字节，小端）

```text
┌──────────────┬──────────┬──────────┬──────────────┬──────────────┐
│ magic        │ version  │ flags    │ ube_len      │ slack_off    │
│ [u8; 4] (4)  │ u8 (1)   │ u8 (1)   │ u32 LE (4)   │ u32 LE (4)   │
└──────────────┴──────────┴──────────┴──────────────┴──────────────┘
```

| 相对偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 4 | `magic` | `[u8; 4]` | 信道魔数（见下） |
| 4 | 1 | `version` | `u8` | 信道版本，当前固定为 `0x01`（`CHANNEL_VERSION`） |
| 5 | 1 | `flags` | `u8` | 标志位，保留，当前为 0 |
| 6 | 4 | `ube_len` | `u32` | 散落嵌入的代码段 UBE 信封总字节数 |
| 10 | 4 | `slack_off` | `u32` | 存放原指令还原差异（instruction diff）的 PE Slack 区域绝对文件偏移 |

- **信道魔数**：
  - 标准模式：`CHANNEL_MAGIC = STANDARD_TRAILER_MAGIC = [0x78, 0xe6, 0x66, 0xd2]`。
  - Stealth 模式：采用用户密码派生的 trailer magic。

### 12.3 确定性掩码混淆（Masking）

为避免明文版本号、标志与零填充长度成为特征扫描器的指纹，`ChannelHeader` 的**字节 4..14**（共 10 字节）始终经过确定性密钥流掩码异或混淆：

```text
derive_channel_header_mask(magic):
  HKDF-SHA256(salt = None, ikm = magic)
  expand info = b"strhide-pe-channel-mask-v1" → mask (10 字节)

channel_bytes[4..14] = unmasked[4..14] XOR mask[0..10]
```

- **混淆效果**：在标准模式下，消除了 `0x01` 版本号和高位为 0 的整数填充；在 Stealth 模式下，因 `magic` 由密码派生，实现了对信道头的密码学盲化。

### 12.4 宿主 100% 还原机制（Slack Diff）

指令编码替换属于载体代码层面的微调。剥离（`remove`）时，`PeAdapter` 读取 `slack_off` 处的紧凑二进制指令差异列表，精确将受影响指令回滚为原始机器码，结合 UBE Header 中记录的原文件 SHA-256 进行双重核验，确保 PE 可执行文件还原后哈希完全吻合。

---

## 13. 内容域：图像隐写

内容域没有结构化信封与静态魔数。载荷先被封成一个**微信封**，再通过矩阵编码把微信封比特分散到图像元素（JPEG 量化 DCT 系数 / PNG 像素）的奇偶位上。

内容域有**两套载体格式**，共用微信封与密钥分层思路，但头部与槽位规则不同：

| | JPEG（V3，STC 三元码） | PNG（空间域，HILL） |
|---|---|---|
| 头部 | 44 字节超块 + 可选 TLV 扩展区 | 32 字节头 + 32 字节 FeatureWord |
| 头部槽位 | `718 + n_ext`（密钥置换前 K 槽） | 512（密钥置换前 K 槽） |
| 槽位集合 | 全图 AC 位置（几何网格，与系数值无关） | 分类候选像素（与像素值相关，需重算代价图） |
| 每槽承载 | 三元 `±1`（`R = 1/24 .. 1/1` 自适应） | 由 `--codec` 决定（Hamming / STC `u ≤ 3`） |
| 头部定位成本 | 一次套件 KDF（无快速口令预言机） | 一次 HKDF（无盐，避免循环依赖） |
| 提取是否需要代价图 | **不需要** | 需要 |

### 13.1 微信封（两种载体共用）

```text
plaintext = orig_len (4, BE) ‖ flags (1) ‖ payload bytes
ciphertext = AEAD(enc_key, nonce, plaintext, aad = 载体头部全部字节)
```

- AEAD：AES-256-GCM，tag 16 字节；`nonce` 12 字节由载体头部承载。
- **AAD = 载体头部全部字节**（JPEG：44 字节超块；PNG：32 字节头 + 32 字节 FeatureWord）。任何被解码器使用的头字段都被绑定，改写即校验失败，而不是"能解密但行为诡异"。
- `flags` 位分配（密文内，唯一演进入口）：

| 位 | 含义 |
|---|---|
| `bit0` | `1` = 载荷经 raw deflate 压缩（仅当压缩后更短时才压缩） |
| `bit1..3` | 压缩算法 id：`0 = deflate`（brotli/zstd 预留）；置非 0 而不压缩 → 拒绝 |
| `bit4..7` | **必须为 0**；非 0 即拒绝（`CorruptedData`） |

- 常量：`SALT_LEN = 16`、`NONCE_LEN = 12`、`TAG_LEN = 16`、`HEADER_OVERHEAD = 28`、`MIN_ENVELOPE_LEN = 49`、`BODY_OVERHEAD = 21`（4 长度 + 1 标志 + 16 tag）。28 字节 salt/nonce 物理上位于载体头部，不占正文槽位；`envelope_len` 仍是"逻辑信封长度"（含这 28 字节），正文比特数 = `8 × (envelope_len − 28)`。

### 13.2 密码套件表（JPEG V3）

套件 id 索引到代码里写死的参数集："一个 id 换一整套密码参数"，新增算法只加表项，不动超块。

| id | 名称 | KDF | AEAD | 状态 |
|---:|---|---|---|---|
| 0 | — | — | — | 无效（零填充/未设置），一律拒绝 |
| 1 | `pbkdf2-sha256-200k` | PBKDF2-HMAC-SHA256, 200,000 次, 32B | AES-256-GCM, 12B nonce, 16B tag | **v1 默认** |
| 2 | `pbkdf2-sha256-600k` | 同上, 600,000 次 | 同上 | 可选 |
| 3 | `argon2id-m64t2p2` | Argon2id m=64 MiB, t=2, p=2 | 同上 | **仅保留 id，v1 不实现** |

规则：只增不改、id 不复用；提取端按 **id 升序试枚举**，每次尝试付一次该套件 KDF；`suite_id` 只作一致性校验（防实现错位），不作发现依据；提取端强制 KDF 成本上限（PBKDF2 迭代 ≤ 2,000,000）。

### 13.3 JPEG V3：密钥派生分层

```text
cover_digest = SHA-256("strhide-cover-v1" ‖ u32(block_count) ‖ u32(component_count)
                        ‖ 全部 DC 系数(i16 BE，分量/块顺序))
              // DC 永不参与嵌入 → 嵌入前后恒定，两端可复算

master            = SuiteKDF_i(password, salt = cover_digest)      // 每个候选套件一次
header_perm_seed  = HKDF(master, info = "hpos"   ‖ domain)         // 定位头部槽位
enc_key,perm_seed = HKDF(master, salt = 超块 salt, info = "enc" / "perm" ‖ domain)
body_stc_seed     = HKDF(perm_seed, salt = 超块 salt, info = "stc-trellis")  // perm_seed 已包含 domain
hdr_stc_seed      = HKDF(header_perm_seed, info = "stc-trellis-hdr" ‖ domain)
ext_stc_seed      = HKDF(header_perm_seed, info = "stc-trellis-ext" ‖ domain)
```

- **头部位置由套件 KDF 派生**：没有口令连头部槽位都算不出来，"读头 → 结构校验"这条微秒级口令预言机因此不存在；每次口令猜测的代价被锁死在该载体实际使用的套件 KDF 上。
- `salt` 明文位于超块第 4..20 字节，但**不再是 KDF 的盐**（KDF 盐是 `cover_digest`），只用于 HKDF 分层分化，跨载体预计算表因此失效。
- `domain`（`--stego-domain`）以 `label ‖ u64be(len) ‖ NFC(domain)` 形式折入每个派生值；异域提取在头部阶段即失配，折叠为 `NoHiddenData`。

### 13.4 JPEG V3：44 字节超块（偏移永久冻结）

```text
off  size  field            说明
0    1     version_major    主版本，不兼容变更才改（当前 1）
1    1     version_minor    次版本，只加可选扩展时改（当前 0）
2    2     flags            全部保留，必须为 0
4    16    salt             正文密钥的 HKDF 盐（每载体随机）
20   12    nonce            AEAD nonce
32   4     envelope_len     BE，bit0..26 有效，bit26..32 必须为 0
36   2     suite_id         密码套件 id（BE），须与试枚举出的套件一致
38   1     codec_id         0 = 三元 STC（1 = Hamming 预留）
39   1     h                STC 约束高度 4..=10
40   1     u                格宽 1..=64
41   1     components_mask  bit0 = Y；其余保留
42   2     ext_bytes        扩展区字节数，0 = 无扩展
```

- 超块 `h = 8, u = 2` → `n_sb = 2 × (352 + 7) = 718` 槽，`m = 718/2 − 7 = 352` 比特，精确填充。
- 所有多字节整数 **big-endian**；保留位/字节写 0，解码时校验为 0。
- 解码端字段校验（任一不满足即拒绝，不猜）：`envelope_len ∈ [49, 2²⁶)`、`suite_id` 等于当前试枚举套件、`codec_id` 已知、`h ∈ 4..=10`、`u ∈ 1..=64`、`components_mask & 0x01 != 0`。
- **没有 `probe`**：不存在可被离线爆破利用的明文口令校验位。
- **没有 `has_ext`**：`ext_bytes > 0` 已足够表达。

### 13.5 JPEG V3：槽位契约与布局

```text
Grid      = { (bi, k) | 0 ≤ bi < block_count, 1 ≤ k ≤ 63 }      // 平坦索引 idx = bi*63 + (k−1)，升序
HdrSlots  = permute(Grid, header_perm_seed)[0 .. 718 + n_ext]
BodyGrid  = Grid \ HdrSlots
BodySlots = permute(BodyGrid, perm_seed)[0 .. u×(bits+h−1)]
```

三条不变量：**值不参与**（唯例外是 DC 作头部 KDF 盐，而 DC 永不嵌入）；**头部先扣**（`BodyGrid` 显式去掉头部槽位，否则同一系数被改两次）；**尾部落选可接受**（按密钥均匀抽样，不是按代价挑选）。

布局（两端只在本处一致，提取端只信头部）：

```text
u = max(1, min(64, floor(SlotBudget / (bits + h − 1)), floor(|BodyGrid| / (bits + h − 1))))
n = u × (bits + h − 1)
```

`SlotBudget`（默认 1,200,000）是**纯嵌入端参数**，不属线格式；提取端只校验 `u ∈ 1..=64` 与 `n ≤ |BodyGrid|`，不比对本地预算推导值。

三元合法性（仅嵌入端）：所有 AC 位置双向 `±1` 均可，仅在 `|c| = 1023` 处挡一个方向（`category(1024) = 11` 超出 baseline AC 的 10 档上限）。写回按回溯给出的 `−1/0/+1` 直接作用于 `i16` 系数。

### 13.6 JPEG V3：扩展区 TLV 与版本策略

```text
type : u8   （bit7 = critical，bit0..6 = 类型号 0..127；类型 0 保留为补齐标记）
len  : u8   （0..255）
value: len 字节
```

- 扩展区槽数 `n_ext = 4 × (8·ext_bytes + 7)`，`STC(h=8, u=4)` 恰好承载 `8·ext_bytes` 比特，无残余；扩展区起点 = 第 718 槽。
- 解码规则：未知识别号 + `critical=1` → 拒绝（`UnsupportedVersion`）；`critical=0` → 跳过；`len` 越界 → `CorruptedData`；尾部补齐字节非 0 → `CorruptedData`；`flags` 非 0 → 拒绝；`version_major != 1` → 拒绝；`version_minor > 本地` → 允许（解析已知 TLV，未知按上表处理）。
- **扩展区的解析放在载荷解密成功之后**：此时载体已被证明是本工具的（AEAD 通过），才能给出"扩展区损坏/未知关键扩展"这类精确错误；提前报错会变成廉价口令预言机。

### 13.7 空间域（PNG）：头部与槽位

空间域本期未改槽位策略，仅两处适配：

1. **AAD = 32 字节头 + 32 字节 FeatureWord**（共 64 字节），任何 codec/h/u 篡改都会让 tag 校验失败；
2. **KDF 走同一套件**：`master = SuiteKDF_1(password, salt = 头内 16B salt)` → `enc_key/perm_seed = HKDF(master, salt, "enc"/"perm" ‖ domain)`。

```text
header_slots[0..256]    = salt (16B) ‖ nonce (12B) ‖ word1 (4B)
header_slots[256..512]  = FeatureWord (32B / 256 bits)
```

#### 4 字节 Word1 控制字

| 位 | 宽度 | 内容 |
|---|---|---|
| bit 0..26 | 26 | 逻辑微信封长度（`HEADER_LEN_MAX = 2^26 − 1`） |
| bit 26..28 | 2 | 矩阵编码标识：`0 = Hamming`；`1..3 = STC u` |
| bit 28..32 | 4 | `15`（`0x0F`）= v2 逃逸标记（本版本唯一写出的形态） |

#### 32 字节 FeatureWord 自描述字

- `bit 0..4` 版本 `= 2`；`bit 4..6` codec（0=Hamming，1=STC）；`bit 6..9` `u`（1..3）；`bit 9..13` `h`（4..10）
- `bit 13..15` `channel_mode`；`bit 15..17` `class_rule`（1 = 安全非边界 `val % 8 ∈ [1,6]`）；`bit 17..19` `kdf_id`
- `bit 19..27` `eligible_min`（8）；`bit 27..35` `eligible_max`（247）；`bit 35..51` `exclusion_permille`
- `bit 51..256` 保留零位（非 0 即 `NoHiddenData`）

#### 空间域残差赤字消除

- 前 512 槽（头部池）：`val ∈ [8, 247]` 且未被平滑排除的候选像素，经 `derive_header_perm_seed`（无盐）置换选出。
- 正文候选池：排除头部 512 槽后，像素收敛至 `val % 8 ∈ [1, 6]`。
- 单向门（`spatial_move_safe`）：`r = 1` 仅允许 `+1`；`r = 6` 仅允许 `−1`；`r ∈ [2,5]` 双向。边界频数 `ΔH[0] = ΔH[7] = 0`。

### 13.8 容量安全档位（SafetyLevel）

| 档位 | bpp 预算（bits/pixel） | 目标比例 `r = slots/bits` | 定位 |
|---|---:|---:|---|
| `Paranoid` | ≤ 0.06 | ≥ 11.5 | 极限高抗检 |
| `High` | ≤ 0.10 | ≥ 6.9 | **默认推荐档** |
| `Balanced` | ≤ 0.15 | ≥ 4.6 | 边界档位 |

- `Advisory`（默认）：超限仅打印警示，不中断；`Enforced`（`--enforce-safety`）：硬性拒绝并报错。
- 载荷率是抗检最灵敏的变量。JPEG V3 实测（80 图语料）：推荐档位下载荷在标定检测器下 0 误报，满容量时检出 85%。

### 13.9 私有版构建指引

格式身份是**编译期**的 `FormatProfile`（`stego::format`），不是 CLI 开关——可切换的格式就是可枚举的格式。

1. 复制 `DEFAULT_FORMAT` 的字面量，至少改 5 个域分隔标签（`cover_digest_tag` / `hpos_label` / `stc_label` / `enc_label` / `perm_label`）；
2. 需要时再改头部几何（`sb_bytes` / `sb_h` / `sb_u`，必须满足 `n = u·(8·bytes + 7)`、`m = 8·bytes`）或 `grid_rule`（`k_min ≥ 1`，DC 绝不能进池）；
3. 在自己的 `main` 里把自己的 `FormatProfile` 传给 `stego::jpeg::embed` / `extract`，或用 `cargo build --features private-profile` 替换 `DEFAULT_FORMAT`；
4. 改完先跑 roundtrip，再跑检测评估（`docs/stc_v3_phase3_eval_20261021.md` 的脚本可直接复用）；
5. **不要分发二进制**：常量会被逆向，私有标签一旦随二进制流出即失去意义。

注意：A 层参数（标签/几何）只影响"谁能读、检测器怎么建模"，**不改变抗检上限**——上限仍由载荷率与代价函数决定，改标签躲得过针对上游格式的定向检测器，躲不过通用隐写分析。

### 13.10 冻结清单与演进决策树

**发布后永不改变（变了就是新格式）**

1. `cover_digest` 的定义（`"strhide-cover-v1"` ‖ 块数 ‖ 分量数 ‖ 全部 DC）；**DC 永不得参与嵌入**；
2. `header_perm_seed = HKDF(SuiteKDF(password, cover_digest), "hpos" ‖ domain)`；
3. 头部置换算法（ChaCha12 + Fisher-Yates `permute_indices`）；
4. 超块槽数 718、超块 STC 参数 `(h=8, u=2)`、超块比特数 352；
5. 超块字段偏移与语义（新增字段一律走扩展区）；
6. 扩展区起点 = 第 718 槽，扩展区 STC 参数 `u=4, h=8`；
7. 正文起点 = `718 + n_ext`，正文置换与 trellis 种子派生 label；
8. 密码套件表只增不改、id 不复用、试枚举顺序固定 id 升序。

**每块网格**：`Grid` 只含 `k = 1..=63`；槽位一律用平坦索引 `idx = bi*63 + (k−1)`；`BodyGrid` 用 `bool` bitset 按 `idx` 正序收集，**严禁 `HashSet`/`HashMap`**（迭代顺序不稳会让 Fisher-Yates 序列两端错位）。

**加字段的决策树**

```text
新需求 → 是否改变密钥派生 / AEAD（算法或成本参数）？
  是 → 加一条套件表项 + 新 suite_id（不动超块、不升版本）
  否 → 是否需要正文解码前就知道？
        否 → 不进格式（如代价函数、极化权重：仅嵌入端使用）
        是 → 能否用 1 个可选 TLV 表达？
              能 → 加 TLV，minor + 1，critical 按需
              不能（>255B 或必须固定位置）→ 提升 major，超块不动，正文前置声明新布局
```

---

## 14. 常量速查表

### 14.1 结构域

| 常量 | 值 |
|---|---|
| `CURRENT_VERSION` | `0x02` |
| `HEADER_SIZE` | `112` |
| `AAD_SIZE` | `80` |
| `TRAILER_SIZE` | `24` |
| `MAX_HINT_LEN` | `1024` |
| `FLAG_ENCRYPTED` / `FLAG_COMPRESSED` / `FLAG_IS_FILE` | `0x01` / `0x02` / `0x04` |
| `FLAG_STEALTH` / `FLAG_HAS_HINT` / `FLAG_COMPACT_META` | `0x08` / `0x10` / `0x20` |
| `STANDARD_HEADER_MAGIC` | `b7 54 2c 82 7e 31 1d 6e` |
| `STANDARD_TRAILER_MAGIC` | `78 e6 66 d2` |
| `CHANNEL_HEADER_LEN` / `CHANNEL_VERSION` | `14` / `1`（散落策略） |
| `STEALTH_DOMAIN` | `b"strhide-stealth-v1"` |
| `PBKDF2_ITERATIONS` | `100_000` |
| `CHUNK_SIZE`（默认） | `2 MiB = 2,097,152` |
| `MAX_CHUNK_SIZE` | `64 MiB = 67,108,864` |
| `MAX_KNOWN_STRATEGY_ID` | `11` |
| `BUILTIN_DEFAULT_KEY` | `"strhide::envelope::v2::default::builtin::public::secret"` |
| `MIN_UBE_PLAIN` | `178`（见 §14.3） |
| `MIN_UBE_ENCRYPTED` | `214`（见 §14.3） |

### 14.2 内容域

| 常量 | 值 |
|---|---|
| `PUBLIC_DEFAULT_SECRET` | `"strhide-default-content-stego-key-2026"` |
| `SALT_LEN` / `NONCE_LEN` / `TAG_LEN` | `16` / `12` / `16` |
| `HEADER_OVERHEAD` / `BODY_OVERHEAD` | `28` / `21` |
| `MIN_ENVELOPE_LEN` | `49` |
| `HEADER_LEN_MAX` | `67,108,863`（2²⁶ − 1） |
| **JPEG V3 超块** | `44` 字节 / `352` 比特 / `718` 槽（`h=8, u=2`） |
| **JPEG V3 扩展区** | `n_ext = 4·(8·ext_bytes + 7)` 槽（`h=8, u=4`） |
| **JPEG V3 默认套件** | id 1 = PBKDF2-SHA256 200k + AES-256-GCM |
| **JPEG V3 `SlotBudget`** | `1,200,000`（嵌入端参数，非线格式） |
| **JPEG V3 `KERNEL_MAX_U`** | `64` |
| **JPEG V3 系数上限** | `|c| ≤ 1023` |
| 空间域 Header 槽位数 | `512`（256 头 + 256 FeatureWord） |
| `DEFAULT_HAMMING_K` | `3`（Hamming (7,3)） |
| `DEFAULT_STC_H` / `MAX_STC_U` | `8` / `3`（空间域） |
| 空间域可嵌入像素范围 | `[8, 247]` |

### 14.3 最小信封口径

- `MIN_UBE_PLAIN = 178 = 112 + 41(raw meta) + 1(raw payload) + 24`：**未计入 AEAD tag**，是容量报告（如 `pe_codebits`）使用的保守门槛，而非实际可产出的信封。
- `MIN_UBE_ENCRYPTED = 214 = 112 + (41+16) + (1+4+16) + 24`：含元数据与载荷 tag，是实际可产出的最小信封口径。

---

## 15. 兼容矩阵

### 15.1 版本与布局兼容

| 读侧能力 \ 写侧产物 | 是否可读 | 结果 |
|---|---|---|
| UBE v2.2（当前，compact meta） | ✅ | 正常读取 |
| UBE v2.2，`FLAG_COMPACT_META` 未置（旧 JSON 元数据） | ❌ | 报不支持的元数据布局 |
| pre-v2（v0.2/v0.3，ASCII 魔数、明文/JSON 元数据） | ❌ | 报告"无隐藏数据"（旧 ASCII 魔数与明文布局已移除） |
| 版本号 ≠ `0x02` | ❌ | 报不支持的信封版本 |

### 15.2 方言（Profile）兼容

| 配置组合 | 官方读侧 | 同方言读侧 | 备注 |
|---|---|---|---|
| 官方魔数 + 官方默认密钥 | ✅ | ✅ | 完全互通 |
| 自定义 `magic`（头/尾） | ❌ | ✅ | 官方定位逻辑只认标准/派生魔数；私有信封对官方不可见 |
| 自定义 `default_secret`，标准魔数 | ❌ | ✅ | 官方去掩码/AEAD 失败；表现为不可读 |
| 自定义 `stealth_domain` | ❌ | ✅ | 派生出不同魔数，官方无法定位 |
| Stealth + 密码 | 仅持有同密码可读 | 持有同密码可读 | 域（domain）也必须一致 |
| 内容域自定义 `stego_secret` | ❌ | ✅ | 错误密钥表现为 `NoHiddenData`（与错误密码不可区分） |

### 15.3 写侧本地参数（L class）兼容

| 参数 | 是否影响互读 | 说明 |
|---|---|---|
| `chunk_size` | ❌ 不影响 | 分块长度前缀自定界，读侧接受任意 ≤ 64 MiB 的分块 |
| 压缩级别（0..=9） | ❌ 不影响 | 读侧只看 `FLAG_COMPRESSED`，始终 inflate raw deflate |
| `CompressionStrategy`（Auto/Never/Always） | ❌ 不影响 | 仅决定是否置 `FLAG_COMPRESSED` |
| `RejectionPolicy` | ❌ 不影响 | 纯写侧安全检查，不进入信封 |

### 15.4 策略 ID 兼容

- 策略 ID `1–11` 为官方保留段（见 [ARCHITECTURE §7](./ARCHITECTURE.md#7-适配器与策略体系)）。
- 解掩码启发式（`MAX_KNOWN_STRATEGY_ID = 11`）会把未知 ID 视为噪声；使用未注册策略 ID 的信封在默认模式下不可读。

---

> 本规范随线格式相关改动更新。任何新增标志位、扩展字段或派生路径，都必须同步更新本文件与对应测试（`cargo test`、`cargo test --doc`），并在 §15 兼容矩阵中注明影响。
