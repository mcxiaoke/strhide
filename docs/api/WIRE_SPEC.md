# strhide 线格式规范（Wire Specification）

> 适用版本：crate `strhide` 0.9.1（Rust 实现，`rust/Cargo.toml`）。
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
13. [内容域：图像与视频隐写（JPEG / PNG / HEIF / HEVC）](#13-内容域图像与视频隐写jpeg--png--heif--hevc)
14. [常量速查表](#14-常量速查表)
15. [兼容矩阵](#15-兼容矩阵)

---

## 1. 总览与术语

strhide 有两个相互独立的隐写域，各自有不同的字节布局：

| 域 | 承载内容 | 字节布局 | 入口 |
|---|---|---|---|
| **结构域（structure）** | 一个自包含的 **UBE**（Universal Byte Envelope，连续或经散落信道编码），有头、有尾、有魔数 | 本规范 §2–§12 | `engine` |
| **内容域（content）** | 嵌入图像像素 / DCT 系数 / H.265 旁路符号位的**微信封**，无静态魔数 | 本规范 §13 | `stego` |

### 1.1 两种信封格式对比（重要）

`write` 与 `embed` 产出的是**两套不同的信封**，不是同一信封的不同封装。它们的派生域相互隔离，互不兼容，也不能互相读取。差异如下：

| 维度 | 结构域信封（`write`，UBE） | 内容域微信封（`embed`） |
|---|---|---|
| 代码 | `envelope.rs` + `engine.rs` + `pe_codebits.rs` | `stego/envelope.rs` + `stego/header.rs` + `stego/format.rs` |
| 总体结构 | `112B header` + 可选 hint + 元数据块 + 分块载荷 + `24B trailer`（散落策略外包 `14B ChannelHeader`） | 密钥化基础头（空间 64B / JPEG 44B / HEVC 32B）+ 可选 TLV 扩展区 + 单个 AEAD 密文正文（见 §13） |
| 静态魔数 | 有：8B 头魔数 + 4B 尾魔数 | **无固定魔数**：`magic4` 由 L2 派生，整体呈高熵随机数据 |
| 定位尾标（trailer） | 有 24B（offset/size/CRC/magic） | 无 |
| 元数据 | 文件名、原始大小、原始 SHA-256、创建时间（独立 AEAD 块） | 无时间戳；密文内微头为 4B 原始长度 + 1B flags + 1B 类型（文件另带 ≤255B 文件名，见 §13.2） |
| 载荷密封 | 分块：每块 `u32 LE` 长度前缀 + 密文，chunk AAD 含 index/is_last | 一次性整体密封，无分块 |
| 字节序 | 小端 | 基础头多字节字段为**大端** |
| AEAD AAD | header 前 80B + `meta_len`/`hint_len` + hint 正文；分块再追加 `chunk_index/is_last` | `"strhide-content-envelope-v4\0" ‖ format_id ‖ base_header ‖ extension`（见 §13.3） |
| 无密码默认密钥 | `BUILTIN_DEFAULT_KEY` | `PUBLIC_DEFAULT_SECRET` |
| HKDF 子密钥标签 | `strhide-payload`、`strhide-metadata`（掩码：`strhide-header-mask-v1`、`strhide-pe-channel-mask-v2`） | L1 `strhide-stego-domain-v1`；L2 `strhide-stego-hpos-v2` + `strhide-v4-hdr-magic` / `strhide-v4-hdr-stc` / `strhide-v4-ext-stc`；L3 的 enc/perm/stc 标签随格式方言不同（见 §13.3） |
| 额外派生 | stealth 魔数与 76B/10B 字段掩码 | header 槽位置换种子（无 salt）、STC 网格种子 |
| 宿主还原 | 记录宿主 size + SHA-256，支持 bit-for-bit 还原（散落策略依赖 slack diff） | **无宿主还原**：像素/系数被改即不可逆，只能重嵌或覆盖 |
| 最终承载 | 注入容器结构空隙（chunk/段/box/overlay 等）或指令编码散落 | 矩阵编码分散到像素 / DCT 系数 / H.265 变换系数符号位 |
| 压缩 | raw deflate；`Auto` 需节省 ≥2% 才保留（>1 MiB 先按 256 KiB 分层样本判定） | raw deflate；`compressed.len() < raw.len()` 才保留 |
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

定长 112 字节，小端序列化。前 80 字节是 AAD 的定长前缀（§5），`meta_len` / `hint_len` 与提示正文另行追加进 AAD；只有后 32 字节里的四个**注入后坐标**（`inject_offset` / `inject_size` / `patch_offset` / `orig_patch_val`）不在 AAD 内 —— 它们在密封之后才由注入器写入，只能做结构校验（§3.4）。

| 相对偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 8 | `magic_header` | `[u8; 8]` | 头魔数（§3.1） |
| 8 | 1 | `version` | `u8` | 信封版本，当前 `0x02` |
| 9 | 1 | `flags` | `u8` | 标志位（§4） |
| 10 | 1 | `strategy_id` | `u8` | 策略 ID（§7 适配器表） |
| 11 | 1 | `offset_delta` | `u8` | 注入点到信封首字节的位移（§3.3），≤ `MAX_OFFSET_DELTA = 64` |
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
- `meta_len` 不得超过 `MAX_META_LEN = 256 KiB`（元数据块最大是"文件名 + 定长尾巴"，这个上限让读取侧不必按不可信字段申请大缓冲）；
- `hint_len + meta_len + (112 + 24)` 不得超过 `ube_total_size`；
- `offset_delta` 不得超过 `MAX_OFFSET_DELTA = 64`；
- `patch_offset` 为 0（无补丁）或 ≥ 4（补丁覆盖一个 4 字节字段）。

### 3.3 `offset_delta`（注入点位移）

多数策略会在信封前面写一段容器结构：PNG `prIv` chunk 头 8 字节、JPEG APP15 段头 4 字节、ISO-BMFF `meta`/`free` box 头 8 字节或 `uuid` box 头 24/32 字节、EBML Void ID + VINT 最多 9 字节。因此信封首字节并不固定在 `inject_offset`，而是位于 `inject_offset + offset_delta`。

该字段位于 AAD 覆盖范围内（偏移 11 < 80），因此被元数据块与载荷分块的 AEAD 一同认证。写入端在封装 header **之前**由 `envelope_offset_delta(adapter, strategy, ube_size)` 求得并写入，所以它既参与认证，又能在 `verify` 时与 trailer 记录的 `ube_offset` 交叉核对：

```
inject_offset + offset_delta == trailer.ube_offset        （连续策略）
ube_total_size <= inject_size                             （容器头只会让注入区域更大）
inject_offset + inject_size <= 文件长度
```

散落策略（`pe_codebits`）没有连续注入区域，其 `inject_offset` / `inject_size` 按定义为 0，上述三条不适用（`inject_size == 0` 即跳过）。

### 3.4 未认证字段与物理边界

`inject_offset` / `inject_size` / `patch_offset` / `orig_patch_val` 是 header 中唯一不被 AEAD 覆盖的部分：它们在注入完成后才写入，而注入发生在元数据块与全部分块密封之后。因此这四个字段**不承担任何安全判断**，改由三条结构约束兜底：

1. **物理包含**：`locate` 只提出候选位置；`locate_envelope` 统一校验
   `ube_total_size >= 112 + 24` 且 `ube_offset + ube_total_size <= 文件长度`，
   不满足即视为"无信封"。追加型策略（`eof` / `pe_overlay` / `ebml_void`）额外要求
   `ube_offset + ube_total_size == 文件长度`。
2. **坐标交叉**：`inject_offset + offset_delta == trailer.ube_offset`（`offset_delta` 在 AAD 内）。
3. **还原校验**：`remove` 会把还原出的载体重新哈希，与 AAD 内的 `orig_host_sha256` 比对，
   不一致返回 `RestoreMismatch`，因此篡改上述任一字段都无法产出"看起来成功"的错误载体。

任何绕过上述约束的伪造都只能得到 `NoHiddenData`，不会驱动按不可信长度分配缓冲区。

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

元数据块与每个载荷分块的 AEAD 使用**变长 AAD**（`EnvelopeHeader::auth_aad`）：

```text
magic_header (8) | version (1) | flags (1) | strategy_id (1) | offset_delta (1)
| salt (16) | base_nonce (12) | orig_host_size (8) | orig_host_sha256 (32)   // 前 80 字节
| meta_len (4, LE) | hint_len (4, LE) | hint bytes (hint_len)
```

- 前 80 字节是定长前缀（`AAD_SIZE = 80`）。
- `meta_len` / `hint_len` 是读取端在验证任何 tag **之前**就必须信任的两个长度：前者决定元数据缓冲大小，后者决定元数据块从哪里开始。把它们纳入 AAD 后，伪造的长度只会导致认证失败，而不再能驱动分配或挪动切割点。
- 提示正文（`hint`）是明文（必须无密码可读），纳入 AAD 后，篡改提示会同时破坏元数据块与所有载荷分块的 tag。
- 四个注入后坐标不在 AAD 内，见 §3.4。

分块 AAD 在此基础上再追加 `chunk_index` / `is_last`（§8.2）。

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
- AAD：§5 的变长 AAD（80 字节前缀 + `meta_len` + `hint_len` + hint 正文）。
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
header AAD (80) | meta_len (u32 LE, 4) | hint_len (u32 LE, 4) | hint (hint_len)
                | chunk_index (u64 LE, 8) | is_last (u8, 1)
// 总长 = 97 + hint_len
```

- `meta_len` / `hint_len` 与 hint 正文由 `EnvelopeHeader::auth_aad` 追加（88 + hint_len）；
  分块层再追加 `chunk_index` 和 `is_last`（`core/crypto.rs`），故为 `97 + hint_len`。
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
- 超过 1 MiB 的载荷在整份压缩前，先对固定的 256 KiB 分层样本（8 × 32 KiB，首尾均匀分布）应用同一 2% 判据；样本判为不可压缩时直接写未压缩流并置 `FLAG_COMPRESSED = 0`，跳过整份 deflate。标志始终描述实际写入的字节，读侧仍只看该标志。

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
header bytes 8..12   XOR mask[0..4]    // version | flags | strategy_id | offset_delta
header bytes 40..112 XOR mask[4..76]   // orig_host_size 起的 72 字节
```

- `salt`（12..28）与 `base_nonce`（28..40）不掩码（本就是随机值，且是派生输入）。
- **非 stealth 的无密码信封**也采用相同掩码机制，但掩码密钥为 `Profile::secret()`；`FLAG_ENCRYPTED` 信封**不掩码** —— 读侧必须能在没有密码时识别出"这是一个需要密码的信封"，才能给出带提示的 `PasswordWithHint`，否则提示本身永远读不到。这类 header 的完整性由 AAD（§5）保证，与掩码无关。

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
2. **Profile 默认密钥去掩码**：要求 `version = 0x02`、无 `FLAG_ENCRYPTED`、`strategy_id ≤ MAX_KNOWN_STRATEGY_ID`（当前 13）、`offset_delta ≤ 64`；
3. **裸 header**：直接解析（`FLAG_ENCRYPTED` 信封不掩码，理由见 §11.3）。

---

## 12. 散落策略信道头：PE Codebits ChannelHeader（14 字节）

### 12.1 产生背景与角色

结构域的大多数策略（如 `chunk`、`app_segment`、`box_uuid`、`pre_cd_inject`）均在载体的结构性空隙中连续存放完整的 UBE 信封（含 112B Header 与 24B Trailer）。

但**散落策略（scattered strategy，当前为 `pe_codebits`）**不同：它将 UBE 字节流逐比特编码进 PE 文件 `.text` 代码节中 x86/x64 指令的等价编码中（如 ModR/M 寻址形式、SIB 字节变换、TEST 指令等），在载体中**没有连续的文件偏移**。

为使读侧定位器（`locate`）与提取器（`open_ube_reader`）能够在不反汇编整段代码的前提下快速确定嵌入 UBE 的字节数、版本以及 100% 还原所需的原指令差异信息，`pe_codebits` 在代码流的前 112 个可用指令槽位中承载了一个定长 14 字节的信道头（`ChannelHeader`，14 字节 = 112 比特）。

信道头的掩码密钥取自紧随其后的 UBE 头魔数（UBE 字节 0..8，对应通道 bit 位置 112..176），因此读侧在解掩码前必须扫描并组装前 **176** 个可用指令槽位（见 §12.3）。

### 12.2 信道头布局（14 字节，小端）

```text
┌──────────────┬──────────┬──────────┬──────────────┬──────────────┐
│ magic        │ version  │ flags    │ ube_len      │ slack_off    │
│ [u8; 4] (4)  │ u8 (1)   │ u8 (1)   │ u32 LE (4)   │ u32 LE (4)   │
└──────────────┴──────────┴──────────┴──────────────┴──────────────┘
```

| 相对偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 4 | `magic` | `[u8; 4]` | 信道魔数（见下）；明文可见 |
| 4 | 1 | `version` | `u8` | 信道版本，当前固定为 `0x01`（`CHANNEL_VERSION`）；经掩码 |
| 5 | 1 | `flags` | `u8` | 标志位，保留，当前为 0；经掩码 |
| 6 | 4 | `ube_len` | `u32` | 散落嵌入的代码段 UBE 信封总字节数；经掩码 |
| 10 | 4 | `slack_off` | `u32` | 存放原指令还原差异（instruction diff）的 PE Slack 区域绝对文件偏移；经掩码 |

- **信道魔数**：
  - 标准模式：`CHANNEL_MAGIC = STANDARD_TRAILER_MAGIC = [0x78, 0xe6, 0x66, 0xd2]`。
  - Stealth 模式：采用用户密码派生的 trailer magic（`strhide-stealth-trailer`）。
- **掩码密钥**：不是上面的 4 字节 `magic`，而是 UBE 头部的 8 字节 envelope header magic（标准模式为公开常量 `STANDARD_HEADER_MAGIC`，Stealth 模式为密码派生的 `strhide-stealth-header`），见 §12.3。

### 12.3 确定性掩码混淆（Masking）

为避免明文版本号、标志与零填充长度成为特征扫描器的指纹，`ChannelHeader` 的**字节 4..14**（共 10 字节）始终经过确定性密钥流掩码异或混淆：

```text
derive_channel_header_mask(envelope_header_magic):        // 8 字节 IKM
  HKDF-SHA256(salt = None, ikm = envelope_header_magic)
  expand info = b"strhide-pe-channel-mask-v2" → mask (10 字节)

channel_bytes[4..14] = unmasked[4..14] XOR mask[0..10]
```

- **IKM 来源**：UBE 头魔数位于通道 bit 位置 112..176（即 UBE 字节 0..8）。写侧在 `embed` 时直接从 UBE 前 8 字节取值；读侧从 `.text` 前 176 个可用指令槽位读取，`profile_upto` 只需扫描该前缀。
- **标准模式（非机密）**：IKM 是公开常量 `STANDARD_HEADER_MAGIC`（`b7 54 2c 82 7e 31 1d 6e`），任何知道格式的人都能解掩码。该掩码在此模式下**仅是格式混淆**，不构成机密性承诺；载荷机密性始终由 AEAD（§10）提供。
- **Stealth 模式**：IKM 是密码派生的 8 字节 header magic，与 `ChannelHeader[0..4]` 中可见的 4 字节 trailer magic **不是同一个值**。只持有 `ChannelHeader[0..4]` 的观察者无法推导掩码；能解码通道位流并读取位置 112..176 的观察者仍可恢复 IKM，因此这里的改进是“不再由明文可见字段直接派生”，不是对通道位流分析者的绝对机密。
- **与旧实现的差异（P1-5）**：旧实现使用 `ikm = ChannelHeader[0..4]`（明文可见的 4 字节 magic）与 `info = strhide-pe-channel-mask-v1`，无密码观察者可直接解出 `version/flags/ube_len/slack_off`。新实现已改为上述 8 字节 IKM + `v2` 标签。
- **兼容性**：本项目未发布，不提供旧版读取路径。用旧掩码实现写出的 PE `pe_codebits` 载具在本版本中无法通过信道头校验，表现为 `NoHiddenData` / 读取失败；需用原版本剥离后重新写入。

### 12.4 宿主 100% 还原机制（Slack Diff）

指令编码替换属于载体代码层面的微调。剥离（`remove`）时，`PeAdapter` 读取 `slack_off` 处的紧凑二进制指令差异列表，精确将受影响指令回滚为原始机器码，结合 UBE Header 中记录的原文件 SHA-256 进行双重核验，确保 PE 可执行文件还原后哈希完全吻合。

---

## 13. 内容域：V4 内容信封（PNG / WAV / FLAC / JPEG / HEVC）

> 本节描述**当前实现**。V4 信封没有 V2/V3 兼容读路径：旧 `CipherSuite`、
> 旧 `header_v3::Superblock`、`MIN_ENVELOPE_LEN` / `HEADER_OVERHEAD` 常量均已删除。
> 旧的 V3 描述只存在于归档文档中。

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

### 13.4 三套基础头（base header）

三套头都由 L2 选槽；`format_id` 与部分隐含字段不存储，但在 AAD 前缀中绑定。
多字节字段一律大端。

#### 13.4.1 空间域（PNG / WAV / FLAC）：64 字节

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

#### 13.4.2 JPEG：44 字节

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

#### 13.4.3 HEVC / HEIF：32 字节

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

### 13.5 flags、ext_len 与 TLV

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

### 13.6 容量公式

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

### 13.7 行为语义

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

### 13.8 音频（WAV / FLAC）

- PCM 采样域（WAV）与 FLAC 残差域，16/24-bit 两种容器路径共用 64B 头。
- `pre_salt` 只取嵌入前后不变的元数据：WAV 用采样率/声道/位深/数据长度等并**排除
  实际 PCM 摘要**；FLAC 用 STREAMINFO 的非 MD5 字段并**排除 MD5**。两者字段编码为大端，
  避免字节序差异造成跨平台 `NoHiddenData`。
- 扩展区 TLV 与空间域同规则；`body_len` 语义同上（密文含 16B tag）。

### 13.9 HEVC / HEIF

- 只调制 TU 内 CABAC bypass 的 `coeff_sign_flag`；不改变码流尺寸与解码结果。
- 32B 头固定 524 个基础槽；`window_slices` 记录主窗口候选切片数，控制提取成本。
- `magic4 = HKDF-Expand(master, info(magic_label))[..4]`，即 L2 输出；私有构建改
  `magic_label` 即可消除开源指纹。头部槽位由凭据派生的 `locate_seed` 决定，不再是
  “只由参数集决定、与密码无关”。
- 扩展区 `ext_len <= 64`；HEIF 在方案 C 不可用时桥接到缩略图 JPEG/未压缩项。

### 13.10 私有构建

`StegoProfile` 的 `jpeg/png/hevc` 线格式身份是编译期常量；改任一派生标签即产生
不兼容线格式。运行时只能选 suite/domain/凭据，不能切换格式身份
（可切换的格式就是可枚举的指纹）。


## 14. 常量速查表

### 14.1 结构域

| 常量 | 值 |
|---|---|
| `CURRENT_VERSION` | `0x02` |
| `HEADER_SIZE` | `112` |
| `AAD_SIZE` | `80` |
| `TRAILER_SIZE` | `24` |
| `MAX_HINT_LEN` | `1024` |
| `MAX_META_LEN` | `262144`（256 KiB） |
| `FLAG_ENCRYPTED` / `FLAG_COMPRESSED` / `FLAG_IS_FILE` | `0x01` / `0x02` / `0x04` |
| `FLAG_STEALTH` / `FLAG_HAS_HINT` / `FLAG_COMPACT_META` | `0x08` / `0x10` / `0x20` |
| `STANDARD_HEADER_MAGIC` | `b7 54 2c 82 7e 31 1d 6e` |
| `STANDARD_TRAILER_MAGIC` | `78 e6 66 d2` |
| `CHANNEL_HEADER_LEN` / `CHANNEL_VERSION` | `14` / `1`（散落策略） |
| `STEALTH_DOMAIN` | `b"strhide-stealth-v1"` |
| `PBKDF2_ITERATIONS` | `100_000` |
| `CHUNK_SIZE`（默认） | `2 MiB = 2,097,152` |
| `MAX_CHUNK_SIZE` | `64 MiB = 67,108,864` |
| `MAX_KNOWN_STRATEGY_ID` | `13` |
| `BUILTIN_DEFAULT_KEY` | `"strhide::structure::envelope::v2::default::builtin::public::secret"` |
| `MIN_UBE_PLAIN` | `178`（见 §14.3） |
| `MIN_UBE_ENCRYPTED` | `214`（见 §14.3） |

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

### 14.3 最小信封口径

- `MIN_UBE_PLAIN = 178 = 112 + 41(raw meta) + 1(raw payload) + 24`：**未计入 AEAD tag**，是容量报告（如 `pe_codebits`）使用的保守门槛，而非实际可产出的信封。
- `MIN_UBE_ENCRYPTED = 214 = 112 + (41+16) + (1+4+16) + 24`：含元数据与载荷 tag，是实际可产出的最小信封口径。

---

## 15. 兼容矩阵

### 15.1 版本与布局兼容

| 读侧能力 \ 写侧产物 | 是否可读 | 结果 |
|---|---|---|
| UBE v2.2（当前，compact meta） | ✅ | 正常读取 |
| Scheme C（HEIF/HEIC、HEVC Annex-B、MP4/MOV、MKV 原位 CABAC） | ✅ | 原生支持（MKV 支持在 v0.8.x 引入） |
| Audio（WAV PCM LSB 与 FLAC 残差隐写） | ✅ | v0.8.x 起原生支持（content-audio 特性） |
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
| 内容域自定义 `stego_domain` | ❌ | ✅ | HKDF 域标签不同，密钥与 header 置换不一致 |
| 内容域私有 `JpegFormatProfile` | ❌ | ✅ | 基础头几何/槽位不同，官方无法解析 |
| 内容域 suite 2（ChaCha20-Poly1305） | ✅ | ✅ | 官方 0.8.5+ 已实现；0.8.5 之前的构建报不支持 |

### 15.3 写侧本地参数（L class）兼容

| 参数 | 是否影响互读 | 说明 |
|---|---|---|
| `chunk_size` | ❌ 不影响 | 分块长度前缀自定界，读侧接受任意 ≤ 64 MiB 的分块 |
| 压缩级别（0..=9） | ❌ 不影响 | 读侧只看 `FLAG_COMPRESSED`，始终 inflate raw deflate |
| `CompressionStrategy`（Auto/Never/Always） | ❌ 不影响 | 仅决定是否置 `FLAG_COMPRESSED` |
| `RejectionPolicy` | ❌ 不影响 | 纯写侧安全检查，不进入信封 |

### 15.4 策略 ID 兼容

- 策略 ID `1–13` 为官方保留段（见 [ARCHITECTURE §7](./ARCHITECTURE.md#7-适配器与策略体系)）。
- 解掩码启发式（`MAX_KNOWN_STRATEGY_ID = 13`）会把未知 ID 视为噪声；使用未注册策略 ID 的信封在默认模式下不可读。

---

> 本规范随线格式相关改动更新。任何新增标志位、扩展字段或派生路径，都必须同步更新本文件与对应测试（`cargo test`、`cargo test --doc`），并在 §15 兼容矩阵中注明影响。
