# 内容域信封公共层规范（V4）

本文件定义 PNG / WAV / FLAC / JPEG / HEVC 共用的线格式公共层，供第三方独立实现使用。载体特有的代价模型与候选池不在本文范围（§9）。版本 `version = 0x40`，major 必须 4（`rust/src/stego/header.rs:162`）。
## 1. 总则与稳定性
### 1.1 稳定性分级
- **F（冻结）**：已写出的载体依赖它；改动使既有载体永久不可读，只能提升 `format_major`。
- **D（方言）**：可由 `*FormatProfile` / `StegoProfile` 替换；产生独立格式，两种构建互不可读。
- **I（自由）**：只决定"写成什么样"；读取不受影响，只需重建字节级基线。

信封与微头、三套基础头、flags/TLV、槽位模型、ChaCha12 采样与置换、STC 为 **F**；TLV 的 `type_id` 空间为 **D**（只可追加 non-critical 类型）；写侧 trellis 搜索、代价与重试为 **I**（见各载体文档）。

> **1.0 前不冻结**：线格式仍可能调整。调整会记入 `docs/CHANGES-*.md` 并重建 `scripts/baseline_hash.py` 基线；发布后 F 级内容只能由 `format_major` 提升而改变。
### 1.2 通用约定
- 槽位 = 载体中一个可翻转的最低有效位；字节按 **MSB-first** 拆槽（bit7 对应首个槽）（`rust/src/stego/png/engine.rs:1206-1218`）。
- 多字节字段除 `sigma` 外均为大端；`sigma` 是 f32 小端（§3.1）。
- 基础头与扩展区的每个字节都进入 AEAD 的 AAD；CRC32 只用于预检，不提供认证（`rust/src/stego/envelope.rs:104-120`）。
- 正文无魔数、无明文长度标记（`rust/src/stego/envelope.rs:1-11`）。
### 1.3 `format_id`
1 = PNG（`png/engine.rs:76`）、2 = WAV（`audio/mod.rs:49`）、3 = FLAC（`audio/mod.rs:51`）、4 = JPEG（隐含，`jpeg/engine.rs:65`）、5 = HEVC（隐含，`hevc/engine.rs:97`）。该值同时写入 AAD 与空间域头字段，两处必须一致。
## 2. 信封与微头
### 2.1 明文布局
```text
plaintext  = [4B BE orig_len][1B flags][micro_header][payload]
ciphertext = AEAD(plaintext)          // 末尾 16B tag
body_len   = len(ciphertext)          // 含 tag，不含 salt / nonce
```
`orig_len` 是解压后明文长度（含微头），不是 `payload` 长度（`rust/src/stego/envelope.rs:372-401`）。
### 2.2 长度常量
- `SALT_LEN` / `NONCE_LEN` / `TAG_LEN` = 16 / 12 / 16（`rust/src/stego/envelope.rs:64-66`）。
- `BODY_OVERHEAD` = 22 = 4 + 1 + 1 + 16（`envelope.rs:97`）。
- `HEADER_LEN_MAX` = 2^26 − 1 = 67,108,863（`rust/src/stego/header.rs:16-20`）；`MAX_PLAINTEXT_LEN` = 67,108,841 = `HEADER_LEN_MAX − 22`（`envelope.rs:101-102`）。
- `body_len ∈ 22..=HEADER_LEN_MAX`，在基础头解码时立即校验（空间 `header.rs:253-258`、JPEG `header_v4.rs:127-132`、HEVC `engine.rs:251-256`）。salt 与 nonce 只存在头中，不占正文槽位，也不计入 `body_len`（`envelope.rs:13-24`）。
### 2.3 微头
- `tag = 0x00`：`[0x00][data]`，文本 / 原始字节，无文件名。
- `tag = 0x01`：`[0x01][name_len: u8][UTF-8 name][data]`，文件；`name_len ≤ 255`。

写侧执行 NFC、路径清理与 255 字节边界截断（`rust/src/stego/envelope.rs:279-306`），读侧复清理（`:333-365`）；文件微头额外开销上限 256 字节（`:88`）。

边界行为（fail-open，不报错）：

- **写侧静默降级**：文件载荷的文件名经 `sanitize_filename` 清洗后若为空白、`.`、`..`、或清洗结果退化到兜底名（`core::fs::FALLBACK_NAME`），`encode_micro_header` 不抛异常，而是改写 `tag = 0x00` 并放弃文件名，正文不变（`envelope.rs:318-335`、`:283-303`）。因此“声明是文件但没有文件名”的载体是合法产物，读侧不得据此报错。
- **读侧兜底命名**：解出 `tag = 0x01` 后，若名字再次清洗为空，读侧回退为 `"extracted.bin"`（`envelope.rs:362-363`；`core/fs.rs:59`）。
- **`--no-filename` 的协议效果**：CLI 传 `--no-filename` 时，即使载荷来自文件（`-d <FILE>`），引擎也先把它包成 `Payload::bytes`，于是写出 `tag = 0x00`，最多省下 256 字节正文空间（`stego/engine.rs:491-496`、`envelope.rs:88`）。这是纯写侧行为，读侧无需感知。
### 2.4 信封 flags（明文第 5 字节）
- 位 0 = `FLAG_COMPRESSED`：载荷已压缩。
- 位 1..3 = 压缩算法 id：0 = Deflate（唯一实现）。
- 位 4..7 保留，必须为 0。

未压缩时算法必须为 0；压缩时解压结果必须恰为 `orig_len`；保留位非 0 拒绝（`rust/src/stego/envelope.rs:123-130`、`:504-552`）。
### 2.5 AAD
```text
AAD = "strhide-content-envelope-v4\0"  (28B) ‖ u8(format_id) ‖ base_header ‖ extension
```
（`rust/src/stego/envelope.rs:105`、`:113-120`）。头字段或扩展字节被篡改时，AEAD 必须失败。
### 2.6 解密与解帧顺序
1. 密文 `< 5 + tag` → 失败（`:463-465`）；2. AEAD 失败 → `NoHiddenData`（`:467-494`）；3. 明文 `< 5` → 失败，否则读 `orig_len` 与 `flags`（`:496-502`）；4. 校验 flags、算法、长度，再解微头（`:504-552`）。
## 3. 三套基础头
由 L2 的 `locate_seed` 选槽。CRC 均为 CRC32-IEEE，覆盖 CRC 字段之前的全部字节，值以大端存放。表中 `off:size`，未标类型者为 bytes。
### 3.1 空间域 64B（PNG / WAV / FLAC）
布局 `rust/src/stego/header.rs:173-219`，编码 `:264-291`，解码 `:297-455`。

| off:size | 字段 | 类型 | 取值 / 校验 |
| :--- | :--- | :--- | :--- |
| 0:16 / 16:12 / 28:4 | salt / nonce / body_len | — / — / u32be | L3 salt / AEAD nonce / 22..=2^26−1 |
| 32:1 / 33:1 | version / flags | u8 | major=4 / bit0-1，其余 0 |
| 34:1 / 35:1 | format_id / algorithm_id | u8 | 等于载体且 1..=3 / PNG 1..=3，音频 0 |
| 36:2 | suite_id | u16be | 已知套件（1 或 2） |
| 38:1 / 39:1 / 40:1 | codec_id / stc_h / stc_u | u8 | 0 或 1；Hamming 时 h=u=0；STC h 4..=10、u 1..=3 |
| 41:1 / 42:1 / 43:1 | channel_mode / class_rule / reserved | u8 | PNG 0/1，音频 0 / PNG 0/1，音频 0 / 0 |
| 44:2 / 46:2 / 48:2 / 50:2 | p1_window / p2_window / neg_log2_epsilon / exclusion_permille | u16be | 奇数 1..=63 / 奇数 1..=63 / 1..=127 / 0..=900 |
| 52:4 / 56:1 / 57:1 | sigma / kernel_id / reserved | f32le / u8 / u8 | 有限且 > 0 / 0 / 0 |
| 58:2 / 60:4 | ext_len / crc32 | u16be / u32be | 0..=255 / CRC over 0..60 |

范围与保留字节在 `rust/src/stego/header.rs:387-431` 一并拒绝。音频只用 STC；Hamming 头在音频域保留未用，音频提取遇到即 `NoHiddenData`（`rust/src/stego/audio/core.rs:499-500`）。
### 3.2 JPEG 44B
布局 `rust/src/stego/jpeg/header_v4.rs:1-26`，编码 `:74-89`，解码 `:92-169`。

| off:size | 字段 | 类型 | 取值 / 校验 |
| :--- | :--- | :--- | :--- |
| 0:1 / 1:1 / 2:2 | version / flags / suite_id | u8 / u8 / u16be | major=4 / bit0-1，其余 0 / 已知 |
| 4:16 / 20:12 | salt / nonce | — | L3 salt / AEAD nonce |
| 32:4 | body_len | u32be | 22..=2^26−1 |
| 36:1 / 37:1 / 38:1 | codec_id / stc_h / stc_u | u8 | 必须 0（三元 STC）/ 4..=10 / 1..=64 |
| 39:1 | ext_len | u8 | 0..=255 |
| 40:4 | crc32 | u32be | CRC over 0..40 |

隐含：`format_id = 4`、只调制亮度分量、无 Hamming 路径（`rust/src/stego/jpeg/header_v4.rs:43-70`）。
### 3.3 HEVC / HEIF 32B
布局 `rust/src/stego/hevc/engine.rs:148-173`，编码 `:177-191`，解码 `:194-278`。

| off:size | 字段 | 类型 | 取值 / 校验 |
| :--- | :--- | :--- | :--- |
| 0:4 / 4:1 / 5:1 | magic4 / version / flags | — / u8 | 等于 L2 派生值 / major=4 / bit0-1，其余 0 |
| 6:1 / 7:2 | stc_u / window_slices | u8 / u16be | 1..=64（读侧权威值，须与 profile 一致）/ ≥ 1 |
| 9:1 / 10:2 | ext_len / suite_id | u8 / u16be | 0..=64 / 已知 |
| 12:4 / 16:12 | body_len / nonce | u32be / — | 22..=2^26−1 / 亦为 session salt 输入 |
| 28:4 | crc32 | u32be | CRC over 0..28 |

隐含：`format_id = 5`、`stc_h`（官方 7，来自 `rust/src/stego/format.rs:99-105`）、`total_windows = 1`。`magic4` 由 L2 派生，不是固定魔数。
### 3.4 公共校验（读正文之前必须完成）
1. `major == 4`；2. `flags` 只允许 bit0/1；3. `FLAG_EXT_PRESENT == (ext_len > 0)`（`rust/src/stego/header.rs:225-247`）；4. `suite_id ∈ {1 AES-256-GCM, 2 ChaCha20-Poly1305}`（`rust/src/core/crypto.rs:132-136`）；5. `body_len ∈ 22..=HEADER_LEN_MAX`；6. 各载体字段范围（§3.1–§3.3）；7. `ext_len ≤ 255`（空间/JPEG）或 `≤ 64`（HEVC）；8. CRC32 匹配。CRC 被重算同样无效：头字节在 AAD 内，AEAD 必须失败。
## 4. flags、`ext_len` 与 TLV
### 4.1 基础头 flags
- 位 0 = `FLAG_EXT_PRESENT = 0x01`：扩展区至少含一个 TLV。
- 位 1 = `FLAG_EXT_CRITICAL = 0x02`：至少一个 TLV 置 critical 位。
- 位 2..7 保留，必须 0。

`FLAG_EXT_CRITICAL` 必须与扩展区实际内容一致；空扩展区置位、或有 critical 未置位均拒绝（`rust/src/stego/header.rs:480-500`）。`ext_len` 是扩展区**字节数**，消息位为 `8 * ext_len`（`rust/src/stego/png/engine.rs:1191-1199`）。
### 4.2 TLV 语法
- `type_id(1B) ‖ len(1B) ‖ value(len B)`，`len ∈ 0..=255`；`type_id` 的 bit7（`0x80`）是 critical 位（`rust/src/stego/header.rs:43-59`）。
- `type_id = 0` 是 padding：自该字节起必须全 0 并结束解析；非零即拒绝（`header.rs:112-146`）。
- 记录越界/截断拒绝；写侧拒绝 `type_id = 0` 与 `value.len() > 255`（`header.rs:72-92`）。
### 4.3 fail-closed
- **写侧拒绝任何 critical TLV**：V4 未定义 critical 语义，避免写出连本构建都读不回的载体（`rust/src/stego/header.rs:94-110`）。
- **读侧拒绝任何 critical TLV**：extract / inspect 统一降级为无隐藏数据（空间 `png/engine.rs:2024-2033`、`:2295-2303`；音频 `audio/core.rs:584-591`；JPEG `jpeg/engine.rs:1362`、`:1606-1616`）。未知 non-critical 跳过。
- 扩展区结构错误在解析层是 `CorruptedData`，在内容域 `extract` 折叠为 `NoHiddenData`（§8.1）。
### 4.4 扩展槽位
- PNG / WAV / FLAC：`8 * ext_len`，一槽一 bit，不经 STC（`rust/src/stego/png/engine.rs:1197`）。
- JPEG：`ext_u * (8 * ext_len + ext_h − 1)`，官方 `4 * (8 * ext_len + 7)`（`rust/src/stego/format.rs:161-164`）。
- HEVC：`2 * (8 * ext_len + 6)`，固定 `h=7, u=2`（`rust/src/stego/hevc/engine.rs:131-143`）。

JPEG 在 `ext_len = 0` 时仍占 `4 * 7 = 28` 槽（`rust/src/stego/format.rs:544`）；空间域与 HEVC 在 `ext_len = 0` 时为 0 槽。
## 5. 槽位模型
- **位序**：字节 MSB-first 拆槽，读取按同一顺序重组（`png/engine.rs:1206-1218`）。
- **头部区**：基础头与扩展区是同一置换的前缀——`[0, base_slots)` 与 `[base_slots, base_slots + ext_slots)`。置换必须前缀稳定，使读侧先读头、学到 `ext_len` 后再续算扩展区（§6.3–§6.5）。
- **正文**：`N = slots_for(8 * body_len, h, u)` 个正文槽的生成规则**因载体而异，必须逐载体照抄**：
  - PNG：先按"代价排序 + 排除率截断"选出恰好 `N` 个候选，再对这段数组做 `permute_indices`（`rust/src/stego/png/engine.rs:1742-1744`、`:2141-2154`）；
  - JPEG：先对完整 `BodyGrid` 做 `permute_prefix(grid, N)`，再截断到前 `N` 个（`rust/src/stego/jpeg/engine.rs:1007-1008`、`:1330-1331`）；
  - HEVC：在 band 内按线性同余取前 `N` 个（`rust/src/stego/hevc/engine.rs:376-414`）；
  - WAV：整体池 `KeyedPermutation(locate_seed, total_slots)` 的 `at(base + i)` 前缀；FLAC：先 thin_pick 选中正文池，再对选中数组做 `KeyedPermutation(locate_seed, body_n)`（`rust/src/stego/audio/core.rs:250-255`、`:831`）。
  三种形态不可互换：对 PNG 改成"整池置换后取前 N"或对 JPEG 改成"先取 N 再置换"都会整条错位。各载体细节见对应文档。
- **头槽与代价解耦**：头部槽位不得依赖代价图或 `algorithm_id`，读侧必须先读头才能知道 `algorithm_id`（`png/engine.rs:1189-1200`、`hevc/engine.rs:304-338`）。
## 6. 伪随机流与置换
### 6.1 ChaCha12
常量 `0x61707865, 0x3320646E, 0x79622D32, 0x6B206574`；32B 种子按 4B 小端拆成 8 字；`state[12..14]` 是 64 位块计数器（初值 0），`state[14..16]` 恒 0（`rust/src/stego/prng.rs:25`、`:60-93`）。每块 6 次双轮（12 轮）：列 `(0,4,8,12)(1,5,9,13)(2,6,10,14)(3,7,11,15)`，对角 `(0,5,10,15)(1,6,11,12)(2,7,8,13)(3,4,9,14)`（`prng.rs:97-113`）。QR：`a+=b; d^=a; d<<<=16; c+=d; b^=c; b<<<=12; a+=b; d^=a; d<<<=8; c+=d; b^=c; b<<<=7`（`prng.rs:29-45`）。输出 `buffer[i]=x[i]+state[i]`，按 u32 小端串 64B；`next_u64 = lo | (hi<<32)`（`prng.rs:115-146`）。

参考向量（`seed = 01 00 … 00`，首 128 字节，取自 `rust/src/stego/prng.rs:301-327`）：
```text
12 05 6e 59 d5 65 05 6b ef 0e 0f 09 df 5c 22 9a
49 24 8c 27 90 52 5d 0f 93 02 18 ff 0b 4d dd 10
a6 00 22 39 d9 a4 54 e2 9e 10 7a 7d 06 fe fd fe
f0 21 0f eb a0 44 f9 f2 9b 17 72 c9 60 dc 29 c0
0c 73 66 c5 cb c6 04 24 0e 66 5e b0 2a 69 37 2a
7a f9 79 b2 6f bb 78 09 2a c7 c4 b8 80 29 a7 c8
54 51 3b c2 17 bb fc 7d 90 43 2e 30 8e ba 15 af
c6 5a eb 48 ef 10 0d 56 01 e6 af ba 25 71 17 a9
```
### 6.2 `gen_range`（拒绝采样）
```text
bound <= 1        -> 0
bound <= 2^32-1   -> b=bound; limit = 2^32 - (2^32 mod b); 取 next_u32，r<limit 返回 r mod b
否则              -> b=bound; limit = 2^64 - (2^64 mod b); 取 next_u64，r<limit 返回 r mod b
```
（`rust/src/stego/prng.rs:152-180`）。改用取模会引入偏置并改变序列。
### 6.3 Fisher–Yates 两种形态
- **整段** `permute_indices(items, seed)`：`for i in (1..n).rev()`，`j=gen_range(i+1)`，交换 `items[i]`、`items[j]`（`prng.rs:185-202`）。
- **前缀** `permute_prefix(items, k, seed)`：`end = min(k, n-1)`，`for i in 0..end`，`j = i + gen_range(n-i)`，交换（`prng.rs:209-235`、`:242-248`）。只有前 k 个位置最终确定。
- **续接稳定性**：把 `0..k` 拆成 `0..s` 与 `s..k` 两次调用并共用同一 RNG，结果与一次调用逐位相同（`prng.rs:213-235`、`:471-491`）；这是头部先读 base、再按 `ext_len` 续算的前提。
### 6.4 HEVC 键控线性同余
```text
fold(seed32): s = 0x243F6A8885A308D3
              for each 8B LE chunk: s = splitmix64(s ^ chunk)
params(len, seed32, band_start):
  s = fold(seed32) ^ (u64(band_start) * 0x9E3779B97F4A7C15)
  start  = splitmix64(s) % len
  stride = max(splitmix64(s ^ 0xA5A55A5A3C3CC3C3) % len, 1)
  while gcd(stride, len) != 1: stride += 1; 若 stride >= len 则 stride = 1 并停止
pos_i = (start + i * stride) mod len        // 乘积用 64 位无符号
splitmix64(x): x += 0x9E3779B97F4A7C15; z = (x ^ (x>>30)) * 0xBF58476D1CE4E5B9;
               z = (z ^ (z>>27)) * 0x94D049BB133111EB; return z ^ (z>>31)
```
（`rust/src/stego/hevc/engine.rs:344-373`、`:1958-1988`）。`gcd(stride, len)=1` 保证是排列；`band_start`（绝对起点而非带序号）参与派生，插入空带不会平移后续带；`pos_i` 与请求数量无关，故头部置换前缀稳定。
### 6.5 音频六轮 Feistel + cycle walking
```text
PERM_LABEL = "strhide-audio-perm-v1"; ROUNDS = 6
mix(z): z += 0x9E3779B97F4A7C15; z = (z ^ (z>>30)) * 0xBF58476D1CE4E5B9;
        z = (z ^ (z>>27)) * 0x94D049BB133111EB; return z ^ (z>>31)
perm_new(seed32, n):
  bits = 1 if n <= 1 else 64 - leading_zeros(n-1)      # ceil(log2 n)
  half = clamp(ceil(bits/2), 1, 32)
  d = SHA-256(PERM_LABEL ‖ seed32 ‖ u64be(n));  k0 = u64be(d[0..8]);  k1 = u64be(d[8..16])
round(i) = mix(k[i & 1] ^ rotl64(i, 17))
permute_block(x):
  L = (x >> half) & mask;  R = x & mask
  repeat r = 0..5:  f = round(r ^ R) & mask;  (L, R) = (R, L ^ f)
  return (L << half) | R
at(i): x = i mod n;  y = permute_block(x);  while y >= n: x = y; y = permute_block(x);  return y
```
（`rust/src/stego/audio/perm.rs:29-44`、`:64-91`、`:100-118`、`:124-145`）。`permute_block` 在 `2^(2·half)` 上双射，cycle walking 保持双射，故 `at` 是 `[0,n)` 的排列；`n <= 1` 时恒 0。
## 7. STC：参数、列向量与 syndrome
### 7.1 参数与容量
`h ∈ 4..=10`（`rust/src/stego/coding/stc.rs:78-83`），`u ∈ 1..=64`：空间域 `u <= 3`（`header.rs:374`）、JPEG `u <= 64`（头字段驱动）。HEVC 扩展固定 `h=7,u=2`；HEVC 正文的写侧用 `HevcFormatProfile` 的 h/u（官方 `7/2`，`hevc/engine.rs:1400`），读侧则按基础头中的 `stc_u` 重建 trellis（`hevc/engine.rs:2249`），因此 `stc_u` 是读侧权威值，写入时必须与 profile 一致。`stc_h` 始终取自 profile，不存储在 HEVC 头中。`n` 个元素承载 `m = n/u − (h−1)` 位；写侧 `n = u·(m + h−1)`，`m=0` 时 `n=0`，`n` 为 `u` 的倍数（`stc.rs:390-406`）。
### 7.2 列向量
```text
mask = (1 << h) - 1
pattern(idx): x = (splitmix64(seed + idx) as u32) & mask   # u64 加法，回绕
              x |= 1; x |= 1 << (h-1); return reverse_low_bits(x, h)
```
`seed` 为 u64：基础头用 L2 `header_stc_seed`，扩展区用 `ext_stc_seed`，正文用 L3 `stc_seed`（`rust/src/stego/format.rs:480-485`、`:495-516`）。`reverse_low_bits` 把 bit `d` 映到 `h−1−d`，使存储后 bit0 是结算行、bit(h−1) 是最新状态（`stc.rs:174-191`、`:349-376`）。取列：从 `idx = s` 起 `col = pattern(idx)`；若已存在且 `cols.len() < 2^(h−2)` 则 `idx += u` 重试；达到 `2^(h−2)` 个不同列后接受重复（自由位只有 `h−2` 个）（`stc.rs:361-373`）。
### 7.3 syndrome（读取）
```text
row_syndrome(r) = XOR over g ∈ [max(0,r−h+1), r], s ∈ [0,u)
                  当 (cols[s] >> (r−g)) & 1 == 1 时，异或 (vals[g·u+s] & 1)
```
消息第 `b` 位 = `row_syndrome(b + h − 1)`；前 `h−1` 行是预热（`rust/src/stego/coding/stc.rs:408-450`）。消息按 **MSB-first** 打包：字节 `b/8` 的 bit `7 − b%8`，末字节多余位 0。**读取不需要 trellis 搜索**：只需重算 `H·x`；搜索只决定写侧翻转集（`stc.rs:51-55`）。
### 7.4 `u = 1` 唯一解
`m = n − h + 1`，每个元素被唯一确定：第 `j` 个元素翻转当且仅当"第 `j+h−1` 行奇偶 ≠ 消息第 `j` 位"。无搜索、无代价参与，翻转率恒 0.5（`stc.rs:556-561`）；读侧与 `u > 1` 同式。
## 8. 行为语义
### 8.1 `extract`：统一 `NoHiddenData`
载体解析成功后，**AEAD 认证通过之前**的任何失败（头非法、扩展区错误、critical TLV、未知 suite、AEAD 失败、密文长度不符）一律返回 `NoHiddenData`，调用方无法区分"无载荷"与"密码错误"（`rust/src/stego/envelope.rs:449-465`、`audio/core.rs:499-500`、`:586`、`png/engine.rs:2007`、`:2024-2033`）。AEAD 通过后，明文帧（压缩算法、`orig_len > max_payload_bytes`、解压失败、微头损坏）属于"已证明是本域载体但结构坏了"，按 `CorruptedData` / `UnsupportedVersion` 露出（`rust/src/stego/png/engine.rs:2174-2185`、`rust/src/stego/envelope.rs:504-552`）。
### 8.2 `verify`：三级独立结论
1 = `carrier`（载体可解析）；2 = `header`（`inspect` 判定存在可读信封）；3 = `payload`（`extract` 成功且 AEAD 通过）。每级独立给出 `ok`/`message`，不得把第 3 级失败误报为第 2 级成功（`rust/src/stego/audio/core.rs:1162-1220`）。
### 8.3 未认证长度
`body_len` 在解密前不可信，仅用于：① 校验 `22..=HEADER_LEN_MAX`；② 在 `min(max_payload_bytes + 22, HEADER_LEN_MAX)` 的策略上限内为槽位读取定界（`rust/src/stego/params.rs:809-843`）。`max_payload_bytes` 默认等于 `MAX_PLAINTEXT_LEN`，是**明文**上限（`params.rs:766-773`）。禁止按声明长度分配大缓冲；正文槽数按 `slots_for(8·body_len, h, u)` 计算，候选池不足立即失败（`jpeg/engine.rs:1309-1319`）。
### 8.4 fail-closed
`major != 4`、`flags` 保留位非 0、`EXT_PRESENT` 与 `ext_len` 不符、`EXT_CRITICAL` 与扩展区不符、suite 未知、`body_len` 越界、CRC 不符、`ext_len` 超限、critical TLV、扩展区截断/越界/padding 后非零，全部必须在读正文之前拒绝。
## 9. 相关文档
- [CONTENT-PNG.md](./CONTENT-PNG.md)：通道、代价模型与候选排序
- [CONTENT-JPEG.md](./CONTENT-JPEG.md)：DCT 网格、超块与扩展区槽位
- [CONTENT-HEVC.md](./CONTENT-HEVC.md)：CABAC 槽位、窗口与分带
- [CONTENT-AUDIO.md](./CONTENT-AUDIO.md)：WAV 采样域 / FLAC 残差域
- [CRYPTO.md](./CRYPTO.md)：L1/L2/L3 派生、AAD、AEAD 与凭据
- [CAPACITY.md](./CAPACITY.md)：容量公式与 probe/embed 同口径
- [DETMATH.md](./DETMATH.md)：`exp` / `ln` / `ln_1p` / `cos` / `log2` 的确定性数值语义
