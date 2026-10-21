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

## 13. 内容域：微信封（Micro-Envelope）

内容域没有结构化信封与静态魔数。载荷先被封成一个**微信封**，再通过矩阵编码把微信封比特分散到图像候选元素的 LSB。

### 13.1 微信封字节布局

```text
┌──────────────┬──────────────┬──────────────────────────────┐
│ salt (16)    │ nonce (12)   │ ciphertext ‖ tag (16)        │
└──────────────┴──────────────┴──────────────────────────────┘
  ↑ HEADER_OVERHEAD = 28 字节
```

- AEAD：AES-256-GCM；**AAD = salt ‖ nonce**（28 字节）。
- 常量：`SALT_LEN = 16`、`NONCE_LEN = 12`、`TAG_LEN = 16`、`HEADER_OVERHEAD = 28`、`MIN_ENVELOPE_LEN = 49`、`BODY_OVERHEAD = 21`（4 长度 + 1 标志 + 16 tag；28 字节 salt/nonce 由 header 槽位承载，不计入 body 开销）。

### 13.2 密文明文内部结构

```text
┌────────────────────┬─────────────┬───────────────────┐
│ orig_len (4, BE)   │ flags (1)   │ payload bytes     │
└────────────────────┴─────────────┴───────────────────┘
```

- `orig_len`：**大端** u32，未压缩载荷长度。
- `flags`：bit 0（`0x01`）表示载荷经 raw deflate 压缩；当 `compressed.len() < payload.len()` 时才压缩。

### 13.3 内容域密钥派生与域隔离

```text
derive_domain_subkey(ikm, domain):
  norm_d = normalize_nfc(domain)
  len_bytes = (norm_d.len() as u64).to_be_bytes()
  info = b"strhide-stego-domain-v1" || len_bytes || norm_d
  HKDF(salt = None, IKM = ikm).expand(info) → subkey (32)

derive_keys(password, salt, domain):
  norm_pwd = normalize_nfc(password)
  PBKDF2-HMAC-SHA256(norm_pwd, salt, 100_000) → pbkdf2_key
  effective_ikm = derive_domain_subkey(pbkdf2_key, domain) // None 时直接使用 pbkdf2_key
  HKDF(salt = Some(salt), effective_ikm):
    info = b"strhide-stego-enc-v1"  → enc key  (32)
    info = b"strhide-stego-perm-v1" → perm seed (32)

derive_header_perm_seed(password, domain):
  // 无 salt，打破"先有 salt 才能定位 header"的循环依赖
  norm_pw = normalize_nfc(password.unwrap_or(PUBLIC_DEFAULT_SECRET))
  effective_ikm = derive_domain_subkey(norm_pw, domain) // None 时直接使用 norm_pw
  HKDF(salt = Some(b"strhide-stego-hpos-salt-v2"), ikm = effective_ikm):
    info = b"strhide-stego-hpos-v2" → header seed (32)

derive_stc_seed(perm_seed, salt):
  HKDF(salt = Some(salt), ikm = perm_seed):
    info = b"strhide-stc-trellis-v1" → 8 字节（u64 大端）
```

- 密钥来源：显式密码优先，否则 `Profile::stego_secret()`，再否则为公开常量 `PUBLIC_DEFAULT_SECRET = "strhide-default-content-stego-key-2026"`。
- 域隔离标签（`stego_domain`）：启用时通过 `derive_domain_subkey` 注入大端长度前缀与 NFC 规范化字符，相同密码在不同 domain 下派生的密钥和置换种子完全正交，提取端异域即在头部槽位阶段直接失配并折叠为 `NoHiddenData`。
- 内容域与结构域的派生域相互独立（info 标签、默认密钥均不同），即使同一 `Profile` 承载，也不会耦合两套方言。

### 13.4 Header 槽位与 v2 FeatureWord 自描述

线格式头部占据由 `derive_header_perm_seed` 置换选出的**前 512 个槽位**（永远采用 legacy `[8, 247]` 及默认排除率规则选取，确保头部定位与自描述参数解耦）：

```text
header_slots[0..256]    = salt (16B) ‖ nonce (12B) ‖ word1 (4B)
header_slots[256..512]  = FeatureWord (32B / 256 bits)  [当 word1.stc_h == 15 时]
```

#### 4 字节 Word1 控制字
| 位 | 宽度 | 内容 |
|---|---|---|
| bit 0..26 | 26 | 微信封总长度（`HEADER_LEN_MAX = 2^26 − 1 = 67,108,863`，约 64 MiB − 1） |
| bit 26..28 | 2 | 矩阵编码标识：`0 = Hamming`；`1..3 = STC u`（v1 历史文件） |
| bit 28..32 | 4 | STC 约束高度 `h`：`15`（`0x0F`）表示 **v2 逃逸标记**；`4..10` 为 v1 历史文件高度 |

#### 32 字节 FeatureWord 自描述字
当 `raw_stc_h == 15` 时，从槽位 `[256..512]` 解码 32 字节自描述控制块：
- `bit 0..8`：版本号 `version = 2`
- `bit 8..11`：矩阵编码 `codec`（0=Hamming, 1=STC）
- `bit 11..14`：STC 分组大小 `u`（1..3）
- `bit 14..17`：STC 约束高度 `h`（4..10，实际存储偏移后数值）
- `bit 17..19`：密钥派生标识 `kdf_id`（0=PBKDF2 100k [兼容], 1=600k [预留], 2=Argon2id [预留]）
- `bit 19..22`：通道模式 `channel_mode`（0=Green, 1=Blue, 2=RgbSpread [预留]）
- `bit 22..25`：类边界规则 `class_rule`（1=Safe non-boundary `val % 8 in [1, 6]`）
- `bit 25..32`：保留零位
- `bit 32..40`：合格像素下界 `eligible_min`（8）
- `bit 40..48`：合格像素上界 `eligible_max`（247）
- `bit 48..64`：排除千分比 `exclusion_permille`（如 300 = 30%）
- `bit 64..256`：保留高 192 位零位

提取端根据 `raw_stc_h == 15` 自动分发：v2 走 FeatureWord 解析，v1 逐位无损回退。未知版本或非零保留位折叠为 `NoHiddenData`。

### 13.5 空间域残差赤字消除与嵌入安全 (P0-B)

- **前 512 槽（头部池）**：按 Legacy 规则 `val in [8, 247]` 且未被 30% 平滑排除的候选像素，经 `derive_header_perm_seed` 置换选出。
- **正文候选池（Body Pool）**：在排除头部 512 槽后，像素严格收敛至模 8 余数 `val % 8 in [1, 6]`。
- **单向门赤字消除（`spatial_move_safe`）**：
  - 余数 $r = 1$：仅允许 $+1$ 转移至 $r=2$（绝不 $-1$ 越界至 $0$）；
  - 余数 $r = 6$：仅允许 $-1$ 转移至 $r=5$（绝不 $+1$ 越界至 $7$）；
  - 余数 $r \in [2, 5]$：允许双向 $\pm 1$ 转移；
  - 边界频数变动量严格保持 $\Delta H[0] = 0, \Delta H[7] = 0$，彻底清零类残差单向门赤字泄露（$Z_0$ 保持在 $[-0.04, 0.00]\sigma \ll 3.0\sigma$）。

### 13.6 容量安全档位（SafetyLevel）与执行模式

| 档位 | bpp 预算（bits/pixel） | 目标比例 $r = \text{slots}/\text{bits}$ | 定位 |
|---|---:|---:|---|
| `Paranoid` | $\le 0.06$ | $\ge 11.5$ | 极限高抗检，微统计指纹完全浸润在物理传感器底噪中 |
| `High` | $\le 0.10$ | $\ge 6.9$ | **新默认推荐档**，STC u=3 最优低改动区间（~0.22 flips/bit） |
| `Balanced` | $\le 0.15$ | $\ge 4.6$ | 边界档位，STC u=2/3 临界线 |

- **执行模式**：
  - `Advisory`（默认）：当载荷超过当前安全档位推荐容量时，在 stderr 打印黄色警示信息与实际 bpp/r，不中断流程；
  - `Enforced`（显式 `--enforce-safety`）：超限时硬性拒绝嵌入并报错，提示换用更大载体或分卷存储。

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
| Header 槽位数 | `256`（= 32 字节） |
| `HEADER_LEN_MAX` | `67,108,863`（2²⁶ − 1） |
| `PBKDF2_ITERATIONS` | `100_000` |
| `DEFAULT_HAMMING_K` | `3`（Hamming (7,3)） |
| `DEFAULT_STC_H` / `MAX_STC_U` | `8` / `3`（STC 参数范围 h: 2..=14） |
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
