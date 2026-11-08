# STRUCTURE-ENVELOPE：结构域公共信封 UBE v2

适用 `strhide` 0.9.3，以 `rust/src/structure` 的可执行代码为准。本文定义结构域所有载体共用的 **UBE**（Universal Byte Envelope）字节流；适配器如何把该字节流放进宿主容器，见 [STRUCTURE-PNG](./STRUCTURE-PNG.md)、[STRUCTURE-JPEG](./STRUCTURE-JPEG.md)、[STRUCTURE-RIFF](./STRUCTURE-RIFF.md)、[STRUCTURE-ISOBMFF](./STRUCTURE-ISOBMFF.md)、[STRUCTURE-ZIP](./STRUCTURE-ZIP.md)、[STRUCTURE-PDF](./STRUCTURE-PDF.md)、[STRUCTURE-PE](./STRUCTURE-PE.md)、[STRUCTURE-MKV](./STRUCTURE-MKV.md)。密钥派生细节见 [CRYPTO](./CRYPTO.md)。所有引用写作 `文件:行`（相对仓库根）。

## 1. 范围与稳定性

- 适用范围：112B header、密码提示、compact 元数据、分块载荷流、24B trailer、AAD、flags、stealth、`offset_delta`、定位与校验、PE `ChannelHeader` 14B。
- 不适用范围：宿主容器头、注入/剥离算法、策略选择与容量报告（由各 `STRUCTURE-*.md` 与 [CAPACITY](./CAPACITY.md) 规定）。
- **F（冻结）**：字段偏移与长度、AAD 拼接、分块 4B 长度前缀、trailer 布局与 CRC、掩码范围、`ChannelHeader` 14B。改动即令既有载体不可读并破坏字节级基线。
- **D（方言）**：头/尾魔数、默认密钥、stealth 域，由 `StructureProfile` 替换（`rust/src/structure/params.rs:31-54`）；换值即产生互不可读的新格式。
- **I（自由）**：`chunk_size`、压缩级别、`CompressionStrategy`、写侧策略选择（`rust/src/structure/engine.rs:1100-1145`）。读侧不得依赖这些取值。
- **1.0 前不承诺稳定**：F 仅表示“本仓库内改动会立即破坏既有载体与基线”，第三方实现须固定到具体版本号并以其代码为准。
- 字节序：结构域所有多字节整数一律**小端**（`rust/src/structure/envelope.rs:144,400-410`）。

## 2. 总体布局与尺寸

```text
相对 UBE 起点
0                             Envelope Header（112 B，§3）
112                           Password Hint（hint_len B，可选，§6）
112 + hint_len                Metadata Block（meta_len B，AEAD，§7）
112 + hint_len + meta_len     Payload Chunk Stream（分块 AEAD，§8）
ube_total_size - 24           Envelope Trailer（24 B，§9）
```

```text
ube_total_size = 112 + hint_len + meta_len + payload_written + 24
payload_written = compressed_plain_len + chunk_count * 20
chunk_count     = max(1, ceil(compressed_plain_len / chunk_size))
```

写侧先按上式预算 `exact_ube_size`，注入前用于策略选择，注入后与实际写入字节数交叉核对，不一致即失败（`rust/src/structure/engine.rs:1231-1240,1339-1351`）。容量报告使用最小可写载荷的 `min_ube_len(payload_len)`：`min_ube_len(0)=213`、`min_ube_len(1)=214`（`rust/src/structure/envelope.rs:116-132`，测试 `:1010-1023`）。

## 3. Envelope Header（112 字节）

固定 112B，按小端序列化。前 80B 是 AAD 定长前缀；`meta_len`/`hint_len` 位于尾部但在 AAD 中另行追加（§5）；仅 `offset_delta` 之外的四项注入后坐标不属于任何 AAD（`rust/src/structure/envelope.rs:144-159`）。

| 偏移 | 长度 | 字段 | 类型 | AAD | 说明 |
| --- | --- | --- | --- | --- | --- |
| 0 | 8 | `magic_header` | `[u8;8]` | 前缀 | 头魔数（§3.1） |
| 8 | 1 | `version` | u8 | 前缀 | 必须为 `0x02` |
| 9 | 1 | `flags` | u8 | 前缀 | §4 |
| 10 | 1 | `strategy_id` | u8 | 前缀 | §14 |
| 11 | 1 | `offset_delta` | u8 | 前缀 | 注入点位移，≤64（§12） |
| 12 | 16 | `salt` | `[u8;16]` | 前缀 | KDF 随机盐，先于解掩码可读 |
| 28 | 12 | `base_nonce` | `[u8;12]` | 前缀 | 随机基准 nonce |
| 40 | 8 | `orig_host_size` | u64 LE | 前缀 | 原始载体字节数 |
| 48 | 32 | `orig_host_sha256` | `[u8;32]` | 前缀 | 原始载体 SHA-256 原始字节 |
| 80 | 8 | `inject_offset` | u64 LE | 否 | 注入点（宿主坐标） |
| 88 | 8 | `inject_size` | u64 LE | 否 | 注入区域字节数 |
| 96 | 4 | `patch_offset` | u32 LE | 否 | 被补丁位置；0=无补丁 |
| 100 | 4 | `orig_patch_val` | u32 LE | 否 | 被补丁处原值 |
| 104 | 4 | `meta_len` | u32 LE | 追加 | 元数据密文长度（含 tag） |
| 108 | 4 | `hint_len` | u32 LE | 追加 | 提示字节数 |

### 3.1 魔数

- 标准：`STANDARD_HEADER_MAGIC = b7 54 2c 82 7e 31 1d 6e`（`rust/src/core/params.rs:27`）。
- 自定义方言：`Profile.magic.header`（`rust/src/structure/params.rs:100-103`）。
- stealth：由密码派生并覆盖上述值（§11；`rust/src/structure/engine.rs:1193-1203`）。

### 3.2 `validate_against(ube_total_size, host_len)` 全规则

读取侧在按任何长度申请缓冲前必须执行（`rust/src/structure/envelope.rs:265-348`）：

1. `version == CURRENT_VERSION == 0x02`（`:266-271`）；否则 `CorruptedData`。
2. `hint_len ≤ MAX_HINT_LEN = 1024`（`:272-277`，`:90`）。
3. `meta_len ≤ MAX_META_LEN = 262144`（256 KiB）（`:278-283`，`:100`）。
4. `hint_len + meta_len + (112+24) ≤ ube_total_size`（`:284-291`）。
5. `strategy_id` 必须存在于 `STRATEGY_REGISTRY`（`:294-302`）；0 与未注册值一律拒绝。
6. `inject_size == 0`，或 `inject_size ≥ 136` 且 `inject_offset + inject_size` 不溢出（`:308-316`）。
7. `offset_delta ≤ MAX_OFFSET_DELTA = 64`（`:321-326`，`:81`）。
8. `patch_offset == 0` 或 `patch_offset ≥ 4`（4 字节字段无法放在 1..=3）（`:329-334`）。
9. `patch_offset != 0` 时 `patch_offset + 4 ≤ host_len`（物理载体长度，`:338-346`）。

定位阶段另有物理包含检查：`ube_total_size ≥ 136` 且 `ube_offset + ube_total_size ≤ 文件长度`，不满足按“无信封”处理而非错误（`rust/src/structure/engine.rs:191-207`）。`host_len` 由读取器在打开信封前取得（`engine.rs:1803`）。

## 4. flags 位定义

| 位 | 常量 | 值 | 语义 |
| --- | --- | --- | --- |
| 0 | `FLAG_ENCRYPTED` | 0x01 | 使用了**用户密码**；不代表“是否加密” |
| 1 | `FLAG_COMPRESSED` | 0x02 | 载荷密封前经 raw deflate |
| 2 | `FLAG_IS_FILE` | 0x04 | 载荷为文件（否则为文本/内联字节） |
| 3 | `FLAG_STEALTH` | 0x08 | stealth：密码派生魔数 + 字段掩码 |
| 4 | `FLAG_HAS_HINT` | 0x10 | 写侧写入提示；读侧以 `hint_len` 为准 |
| 5 | `FLAG_COMPACT_META` | 0x20 | 元数据为 compact 布局（§7） |
| 6–7 | — | — | 保留，必须为 0 |

- 常量与置位逻辑：`rust/src/structure/envelope.rs:61-72`、`rust/src/structure/engine.rs:1148-1166`。
- **`FLAG_ENCRYPTED=0` 时载荷与元数据仍以 `Profile` 的默认密钥 AEAD 密封**；该位仅表示“需要用户密码”（`engine.rs:1148-1157`、`envelope.rs:210-218`）。
- 写侧对可编码元数据**总是**置 `FLAG_COMPACT_META`（`engine.rs:1217-1220`）；读侧遇该位为 0 直接报“不支持的元数据布局”，不再解析 JSON（`engine.rs:355-366`）。
- `validate_against` **不**校验保留位；只有裸头识别门槛检查 `flags & !0x3F == 0`（`envelope.rs:675-689`）。写入端不得置保留位。

## 5. AAD

元数据块与每个载荷分块使用同一变长 AAD（`EnvelopeHeader::auth_aad`）：

```text
header[0..80]
  = magic_header(8) | version(1) | flags(1) | strategy_id(1) | offset_delta(1)
  | salt(16) | base_nonce(12) | orig_host_size(8) | orig_host_sha256(32)
AAD = header[0..80] | u32le(meta_len) | u32le(hint_len) | hint(hint_len)
  总长 = 88 + hint_len
分块 AAD = AAD | u64le(chunk_index) | u8(is_last)
  总长 = 97 + hint_len
```

出处 `rust/src/structure/envelope.rs:354-366,390-397`；分块追加见 `rust/src/core/crypto.rs:508-511,602-605`。两个长度字段必须先于任何 tag 校验被信任，故纳入 AAD；hint 是明文但纳入 AAD，篡改提示会破坏所有 seal。`meta_len`/`hint_len`/hint 的读取顺序为：header → hint → meta（`engine.rs:1808-1872`）。

## 6. 密码提示（Hint）

- `hint_len` 字节紧跟 header，明文 UTF-8；读侧按 `hint_len` 读取，不依赖 `FLAG_HAS_HINT`（`rust/src/structure/engine.rs:1836-1844`）。
- 写侧：NFC 归一化 + `trim()`，长度 >1024 字节即拒绝；空提示不写、不置位（`engine.rs:984-995,1164-1166`）。
- **与 stealth 互斥**：`password_hint` 与 `stealth` 同时给出即拒绝（`engine.rs:969-973`）；stealth 无提示，避免定位线索。
- 读侧展示使用 `from_utf8_lossy`，不因非 UTF-8 拒绝信封（`engine.rs:1840-1844`）。

## 7. 元数据块（Metadata Block）

始终 AEAD 密封（即使无用户密码）。`FLAG_COMPACT_META` 置位时明文为 compact 布局（`engine.rs:1217-1220`）。

### 7.1 Compact 明文逐字段

| 顺序 | 字段 | 编码 | 约束 |
| --- | --- | --- | --- |
| 1 | `version` | u8 = `0x01` | `COMPACT_META_VERSION`；其他值拒绝 |
| 2 | `name_len` | u16 LE | ≤65535 |
| 3 | `filename` | UTF-8 字节 | 文本载荷为空串 |
| 4 | `raw_size` | varint | 压缩前载荷字节数 |
| 5 | `raw_sha256` | 32 原始字节 | 压缩前载荷摘要 |
| 6 | `created_at` | varint | Unix 秒 |

编码/解码 `rust/src/structure/engine.rs:282-337`；版本常量 `:211`；文件名上限 `:216`。

### 7.2 varint（无符号 LEB128）

每字节低 7 位为数据、bit7=1 表示后续还有字节，低位组在前；最多 10 字节。第 10 字节只允许 bit0 有效（不得有 bit7，且 bit1..6 必须为 0），否则报溢出/过长（`engine.rs:218-258`）。

### 7.3 AEAD 参数

- 密钥 `meta_key`；nonce `make_meta_nonce(base_nonce)` = 前 8B 不变、低 32 位为 `u32le(base_nonce[8..12]) XOR 0xFFFF_FFFF`（`rust/src/core/crypto.rs:366-373`）。
- AAD 为 §5 的变长 AAD；线格式 `meta_len = len(明文) + 16`（`crypto.rs:382-398`；`engine.rs:1232`）。
- 解密失败统一映射为“密码错误或元数据损坏”，不得区分（`engine.rs:1874-1876`）。

### 7.4 最小明文

空文件名、1 字节载荷：`1 + 2 + 0 + 1 + 32 + 5 = 41` 字节（`created_at` 为约 1.7×10⁹，varint 占 5B）。加上 16B tag 后 `meta_len = 57`。

## 8. 载荷分块流（Payload Chunk Stream）

```text
┌ chunk_len (u32 LE, 4B) ┬ chunk ciphertext (chunk_len B，含 16B tag) ┐
```

- `chunk_len` 是该块**密文**长度（明文 + 16B tag），不含自身 4B 前缀（`rust/src/core/crypto.rs:523-526,574`）。
- 分块大小不协商、不存储；读侧靠长度前缀自定界（`crypto.rs:424-428`）。
- `chunk_count = max(1, ceil(plain_len / chunk_size))`；每块开销 20B（4+16）（`crypto.rs:71-88`；常量 `:59-64`）。
- 空载荷仍写一个 `is_last=1` 的空最终块（明文 0B，密文 16B，`chunk_len=16`），用于区分“无载荷”与“流被截断”（`crypto.rs:467-489`）。
- `chunk_index` 为 u64，从 0 递增；`is_last` 为 1 仅用于最后一块（`crypto.rs:510-511`）。
- 分区总长 `total_payload_bytes = ube_total_size - (112 + 24 + hint_len + meta_len)`（`engine.rs:1878-1882`）。
- 读侧单块密文上限 `min(剩余字节, MAX_CHUNK_SIZE + 16)`，其中 `MAX_CHUNK_SIZE = 64 MiB`（`crypto.rs:581-588,101`）。任何块 AEAD 失败、越界或提前 EOF 均为 `CorruptedData`。

## 9. Envelope Trailer（24 字节）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
| --- | --- | --- | --- | --- |
| 0 | 8 | `ube_offset` | u64 LE | 写入时 UBE 实际起始偏移 |
| 8 | 8 | `ube_total_size` | u64 LE | UBE 总尺寸 |
| 16 | 4 | `trailer_crc32` | u32 LE | 前 16B 的 CRC32-IEEE |
| 20 | 4 | `trailer_magic` | `[u8;4]` | 尾魔数 |

- 标准魔数：`STANDARD_TRAILER_MAGIC = 78 e6 66 d2`（`rust/src/core/params.rs:30`）；自定义方言用 `Profile.magic.trailer`；stealth 用密码派生值（§11）。
- `trailer_crc32 = CRC32_IEEE(ube_offset ‖ ube_total_size)`（`crypto.rs:724-736`）。stealth 下与该值异或密码派生掩码（`:740-753`）。
- **从尾部读取**（`envelope.rs:831-859`）：文件 <24B → `None`；尾部魔数与期望不符 → `None`（正常“无信封”）；魔数匹配但 CRC/解析失败 → **返回 `CorruptedData`**，不得静默当作无数据。
- `unpack(data, expected_magic)`：`None` 只接受标准魔数且只接受未掩码 CRC；`Some(m)` 要求魔数等于 `m`，先试原始 CRC，再试异或掩码后的 CRC（`envelope.rs:771-825`）。
- `locate_start(file_size)`：若 `ube_offset + ube_total_size == file_size` 取 `ube_offset`；否则要求 `ube_total_size ≥ 136` 并取 `file_size - ube_total_size`（允许内容域重写后信封整体平移，`envelope.rs:870-879`）。
- 连续策略的 trailer 通常位于 `ube_offset + ube_total_size - 24`（`adapters/mod.rs:356-358`），个别适配器可覆写；散落策略 trailer 中的 `ube_offset` 为 0（§13）。

## 10. 密钥、AEAD 与压缩

- 有效凭据：非空用户密码优先，否则 `Profile.secret()`（官方为 `BUILTIN_DEFAULT_KEY`，`rust/src/core/crypto.rs:171-172`；选择逻辑 `engine.rs:1152-1153`）。空串密码按“未提供”处理（`engine.rs:964,1752`）。
- 一次 PBKDF2 + 三次 HKDF（`crypto.rs:256-273`）：`IKM = PBKDF2-HMAC-SHA256(NFC(password), salt, 100000)`；再以 `salt` 为 HKDF-SHA256 salt，按 info `strhide-payload` / `strhide-metadata` / `strhide-header-mask-v1` 独立展开。算法与轮数为线格式常量（`crypto.rs:103-106`）。完整规则见 [CRYPTO](./CRYPTO.md)。
- 算法固定 AES-256-GCM，tag 16B（`crypto.rs:34-37,59`）。元数据 nonce 用 `XOR 0xFFFF_FFFF`，载荷块 `make_chunk_nonce` 用 `低 32 位 XOR chunk_index`（`crypto.rs:354-373`）；两者域分离，不得复用 nonce。
- 压缩为 raw deflate（无 zlib 头尾），级别 0..=9 仅写侧（`crypto.rs:642-665`）。读侧只依据 `FLAG_COMPRESSED`，并以 AAD 保护的 `raw_size` 为解压硬上限（`engine.rs:1979-1988`；`crypto.rs:729-756`）。“至少节省 2%”与 >1 MiB 的 256 KiB 抽样均属 **I** 级写侧策略（`engine.rs:1100-1145`；`crypto.rs:672-720`）。

## 11. Stealth 模式

- 要求必须提供用户密码；无密码即拒绝，不会降级为标准模式（`engine.rs:975-982`）。与提示互斥（§6）。
- 魔数派生（`crypto.rs:285-300`）：`IKM = PBKDF2-HMAC-SHA256(NFC(password), domain, 100000)`；`HKDF-SHA256(salt=domain, IKM)`，info `strhide-stealth-header` → 8B 头魔数、`strhide-stealth-trailer` → 4B 尾魔数。`domain` 默认 `b"strhide-stealth-v1"`（`rust/src/core/params.rs:37`），可由 `Profile.stealth_domain` 替换。此处 PBKDF2 的盐是 domain，不是 header 的随机 salt。
- 字段掩码（`crypto.rs:305-312`；`envelope.rs:422-433`）：76B 掩码由 `PBKDF2(password, salt) → HKDF info strhide-header-mask-v1` 派生，按 `header[8..12] ^= mask[0..4]`、`header[40..112] ^= mask[4..76]` 写入/还原。`salt`/`base_nonce` 不掩码。
- Trailer CRC 掩码（`crypto.rs:318-329`）：`mask = CRC32_IEEE(trailer_magic ‖ b"STEA")`；写侧 `crc ^= mask`。
- **非 stealth 且无用户密码**的信封同样掩码，掩码密钥为 `Profile.secret()`；**`FLAG_ENCRYPTED` 信封不掩码**，以便无密码读者识别“需要密码”并返回提示（`envelope.rs:449-466`；写侧 `engine.rs:1184-1188`）。
- 读侧识别顺序（`envelope.rs:559-662`）：
  1. 有密码且密码派生的 8B 头魔数匹配 → 用密码掩码还原，要求 `version=0x02` 且 `FLAG_STEALTH` 置位（`:580-607`）。
  2. 裸 `FLAG_ENCRYPTED` 信封：`version=0x02`、`FLAG_ENCRYPTED` 置位且通过完整裸头可信门槛（`:615-620`）。
  3. `Profile.secret()` 去掩码：要求 `FLAG_ENCRYPTED` 为 0、`strategy_id ∈ 1..=MAX_KNOWN_STRATEGY_ID`、`offset_delta ≤64`；**本层不校验 version**（由上层 `validate_against` 报“不支持版本”）（`:622-648`）。
  4. 裸头可信门槛：`version=0x02`、`flags & !0x3F == 0`、`strategy_id ∈ 1..=13`、`offset_delta ≤64`、`meta_len ≤256 KiB`、`hint_len ≤1024`（`:675-689`）。
  全部失败返回 `CorruptedData`；`inspect` 将其视为“无数据”以维持私有方言不可见性（`engine.rs:2630-2656`）。

## 12. `offset_delta` 与注入后坐标

- 语义：信封首字节位于 `inject_offset + offset_delta`。策略在信封前写的容器头使位移非零（PNG 8B、JPEG APP15 4B、ISO-BMFF box 头 8B 或 uuid 头 24/32B、EBML Void+VINT 最多 9B），上限 64（`envelope.rs:74-81`；`engine.rs:1267-1278`）。
- 写入时机：在封装 header **之前**由适配器求得，因此位于 AAD（offset 11 < 80），可被认证；注入后只把四个坐标写回（`engine.rs:1397-1412`）。
- 注入后坐标的物理约束（连续策略，`engine.rs:2828-2902`）：
  1. `inject_offset + offset_delta == trailer.ube_offset`；其中 `chunk`/`eof` 允许内容域重写导致整体平移，按平移量修正 `inject_offset`（`engine.rs:2860-2874,2268-2296`），其余策略不一致即损坏。
  2. `ube_total_size ≤ inject_size`（容器头只会让注入区域更大）。
  3. `inject_offset + inject_size ≤ 文件长度`；平移时按 `ube_offset + (inject_size - offset_delta) ≤ 文件长度` 计算（`:2881-2900`）。
- 另有形状约束：`inject_size == 0` 或 ≥136；`patch_offset ∈ {0} ∪ [4, …]` 且 `patch_offset+4 ≤ host_len`（§3.2）。
- 散落策略例外：`pe_codebits` 的 `inject_offset`/`inject_size` 按定义为 0，坐标检查仅在“调用方策略名与 header `strategy_id` 都指向 `pe_codebits`”时跳过，不能以 `inject_size==0` 泛化豁免（`engine.rs:2835-2850`）。
- 还原兜底：`remove` 对还原载体重算大小与 SHA-256，与 AAD 内 `orig_host_size`/`orig_host_sha256` 比对，不符返回 `RestoreMismatch`（`engine.rs:2299-2361`）。

## 13. 散落策略信道头：PE `ChannelHeader`（14 字节）

`pe_codebits` 把 UBE 逐比特编码进 `.text` 指令等价形式，无连续文件偏移，故在通道前 112 个可用指令槽位承载 14B 信道头（`rust/src/structure/adapters/pe_codebits.rs:43-51`）。

| 偏移 | 长度 | 字段 | 类型 | 掩码 | 说明 |
| --- | --- | --- | --- | --- | --- |
| 0 | 4 | `magic` | `[u8;4]` | 否 | 标准=`78 e6 66 d2`（= UBE 尾魔数）；stealth=派生尾魔数 |
| 4 | 1 | `version` | u8 | 是 | 固定 `0x01` |
| 5 | 1 | `flags` | u8 | 是 | 保留，当前 0 |
| 6 | 4 | `ube_len` | u32 LE | 是 | 嵌入的 UBE 总字节数 |
| 10 | 4 | `slack_off` | u32 LE | 是 | 还原 diff 的 PE slack 绝对文件偏移 |

- 布局/打包：`pe_codebits.rs:358-400`；常量 `CHANNEL_VERSION=1`、`CHANNEL_HEADER_LEN=14`（`:41-44`）。
- 掩码：`mask = HKDF-SHA256(salt=None, ikm=envelope_header_magic_8B)`，info `strhide-pe-channel-mask-v2`，取 10B；`bytes[4..14] ^= mask[0..10]`（`rust/src/core/crypto.rs:342-348`；`pe_codebits.rs:393-400`）。
- IKM 来源：紧随信道头之后的 8 个 UBE 字节（通道 bit 位置 112..176，即 UBE `header[0..8]`）。读侧只扫描前 176 个候选槽位即可解出（`pe_codebits.rs:48-51,460-477`）。标准模式 IKM 是公开常量，掩码仅为格式混淆；stealth 模式 IKM 为密码派生头魔数，与可见的 4B 尾魔数不同。
- 校验：`version == 1`；`MIN_UBE_LEN = 136 ≤ ube_len ≤ MAX_CODEBITS_UBE_LEN = 64 MiB`；可用槽位 ≥ `(14 + ube_len) * 8`；定位时魔数必须匹配（`pe_codebits.rs:480-509,541-554`）。`flags` 读侧不校验。
- `slack_off` 还原：diff 长度 = `14 + ube_len` **字节**，其每一位对应通道字节流的一位（字节内 MSB-first，`pe_codebits.rs:320-350`），置位表示该位置被替换为等价指令；剥离时按位翻转回原指令后，将整个 diff 区域**全零填充**（原始内容为全零 padding），`slack_off` 必须落在已声明的 PE slack 区间内且有足够空间，否则拒绝（`pe_codebits.rs:665-680`；`adapters/pe.rs:776-795`）。
- 写入端返回 `(inject_offset, inject_size, patch_offset, orig_patch_val) = (0,0,0,0)`，header/trailer 不再按文件偏移回写（`adapters/pe.rs:705-738`；`engine.rs:1420-1426`）。

## 14. 策略 ID 与信封可识别性

`strategy_id` 是单字节，取值表为唯一事实来源（`rust/src/structure/registry.rs:90-104`）：

| ID | 名称 | ID | 名称 |
| --- | --- | --- | --- |
| 1 | eof | 8 | pe_codebits |
| 2 | chunk | 9 | pe_slack |
| 3 | box_uuid | 10 | riff_chunk |
| 4 | pre_cd_inject | 11 | ebml_void |
| 5 | app_segment | 12 | item_hidden |
| 6 | incremental | 13 | free_box |
| 7 | pe_overlay | — | — |

- `MAX_KNOWN_STRATEGY_ID = MAX_STRATEGY_ID = 13`，由注册表计算而非手写（`registry.rs:200-216`；`envelope.rs:45-52`）；新增策略必须同步注册表，否则新载体会被识别门槛拒绝。
- “这像不像我们的信封”至少要求：`version=0x02`、`strategy_id` 已注册（1..=13）、`offset_delta ≤64`、`hint_len ≤1024`、`meta_len ≤256 KiB`（§3.2、§11）。`validate_against` 失败在 `inspect` 中按“无数据”处理（`engine.rs:2644-2656`）。
- 私有方言（自定义魔数/默认密钥/stealth 域）对官方读者表现为无信封，不可互读（`engine.rs:101-116`；`params.rs:112-121`）。

## 15. 实现自检清单

1. header 严格 112B 小端；`version` 只接受 `0x02`。
2. 读任何长度字段前先跑 §3.2 九条规则，拒绝时不分配缓冲。
3. 构造 AAD 用 §5 公式，`meta_len`/`hint_len`/hint 必须与写入字节完全一致；分块 AAD 再追加 `chunk_index`/`is_last`。
4. `chunk_len` 含 16B tag、不含 4B 前缀；空载荷写一个 `is_last=1`、密文 16B 的最终块。
5. `payload_written` 与 `ube_total_size` 按 §2 公式计算并交叉核对。
6. trailer 读尾 24B：魔数不符=无信封；魔数相符而 CRC 错=损坏，必须报错。
7. 元数据：`FLAG_COMPACT_META` 为 0 直接拒绝；varint 第 10 字节只允许 bit0。
8. nonce 不得复用：元数据固定 `XOR 0xFFFFFFFF`，块 nonce `低32位 XOR index`。
9. 无用户密码信封必须用 `Profile.secret()` 掩码；`FLAG_ENCRYPTED` 信封必须不掩码。
10. stealth 必须要求密码、禁止提示；魔数/掩码/CRC 三者都按密码派生。
11. 连续策略校验 `inject_offset+offset_delta == ube_offset`、`ube_total_size ≤ inject_size`、注入区不越过文件尾；仅 `chunk`/`eof` 允许平移。
12. `pe_codebits` 的 `ChannelHeader` 用 14B + 8B IKM 解掩码，`slack_off` 必须落在 slack 区间；写入端坐标全 0。
13. 对未知策略 ID、未知 flags 位、越界 `offset_delta` 一律拒绝，不得“尽力解析”。
