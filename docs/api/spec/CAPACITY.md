# CAPACITY — 容量公式与限额规范

**状态**：规范性（normative）。本文汇总内容域与结构域的容量口径、工作集预算和硬限额。
**适用范围**：`probe`/`inspect` 上报的容量、`embed`/`write` 的容量门、`PayloadTooLarge` 判定。
**导航**：[规范总览](./README.md) · [内容域信封](./CONTENT-ENVELOPE.md) · [结构域信封](./STRUCTURE-ENVELOPE.md) · [确定性数学](./DETMATH.md)

分级：容量公式与结构开销为 **F**；实现预算门为 **F**（probe 与 embed 必须同口径）；纯报告型适配器上限为 **I**；长视频估算精度为 **I**。

## 1. 内容域统一公式

```text
header_slots = base_slots + ext_slots
body_slots   = total_slots - header_slots          (不足则 0)
message_bits = floor(body_slots / u) - (h - 1)     (STC；见 coding/stc.rs:390-392)
max_payload  = floor(message_bits / 8) - 22        (BODY_OVERHEAD)
```

- `BODY_OVERHEAD = 22 = 4 字节长度 + 1 flags + 1 最小微头 + 16 AEAD tag`（`rust/src/stego/envelope.rs:90-97`）。
- 26 位 `body_len` 上限 `HEADER_LEN_MAX = 67,108,863`（`rust/src/stego/header.rs:16-20`）。
- 明文上限 `MAX_PLAINTEXT_LEN = HEADER_LEN_MAX - 22 = 67,108,841`（`rust/src/stego/envelope.rs:99-102`）。
- 所有 `probe` 报告值都是**原始载荷字节**，不含文件微头。引擎内部先按 `22 B` 计价；公共入口 `probe`/`embed` 随后经 `filename_safe_capacity` 再减 `MAX_FILENAME_OVERHEAD = 1 + 255 = 256`，使上报值对“最长文件名”的文件载荷也安全（`rust/src/stego/mod.rs:276-290`、`:503`、`:267`；`rust/src/stego/io.rs:102-106`）。
- 因此同一载体有两个数：引擎内 `max_raw_payload_bytes`（减 22）与公共 API 报告值（再减 256）。规范要求**同一入口族**内 `probe` 与 `embed` 使用相同口径，不得混用。

**同口径要求**：`probe` 与 `embed` 必须复用同一函数、同一 `ext_len`、同一 `stc_h/u`、同一工作集预算门、同一 `filename_safe_capacity` 后处理。否则上报值会被写入端拒绝。

## 2. 逐载体（内容域）

### 2.1 PNG
- `total_slots`：按代价模型候选集与 `class_rule = 1` 过滤后的可写像素槽。先试绿色单通道池；载荷放不下再试 RGB 三通道池（Alpha 永不触碰）。见 `rust/src/stego/png/engine.rs:1370-1377`、`:1613-1618`、`:2569-2573`。
- `base_slots = 512`（64 字节基础头，1 slot = 1 bit）；`ext_slots = 8 * ext_len`（`rust/src/stego/header.rs:153-156`、`rust/src/stego/png/engine.rs:1197`、`:1283`）。
- `h/u`：STC `h ∈ 4..=10`、空间 `u ∈ 1..=3`（`rust/src/stego/coding/stc.rs:78-91`）；默认 `h = 8`，`Auto` 按槽/比特比选 `u`；Hamming 固定 `k = 3`。
- 最大像素数 `MAX_PNG_PIXELS = 64 * 1024 * 1024`（`rust/src/stego/png/engine.rs:506`）。
- `max_payload` 由二分搜索 `body_payload_fits` 得到，直接按真实 codec/`u` 计价（`rust/src/stego/png/engine.rs:2472-2513`）。

### 2.2 JPEG
- `total_slots = block_count * grid_rule.slots_per_block()`；默认 `GridRule::ALL_AC` 即每块 `k = 1..=63`，共 63 槽（`rust/src/stego/jpeg/engine.rs:1819-1821`、`rust/src/stego/format.rs:53-63`）。
- `base_slots = 718 = 2 * (44*8 + 8 - 1)`（`rust/src/stego/format.rs:156-159`）；`ext_slots = 4 * (8*ext_len + 8 - 1) = 4*(8*ext_len + 7)`（`rust/src/stego/format.rs:161-168`、默认剖面 `:240-248`）。
- `h/u`：头部 `sb_h = 8, sb_u = 2`，扩展 `ext_h = 8, ext_u = 4`；同时 `h ∈ 4..=10`、`u ∈ 1..=64`（`rust/src/stego/format.rs:181-191`）。
- 若 Huffman 表过度优化（`has_incomplete_table`），`u = 3` 的 grouped 上限替代几何上限（`rust/src/stego/jpeg/engine.rs:1837-1854`）。
- `max_payload = max_bits/8 - 22`（`rust/src/stego/jpeg/engine.rs:1837-1856`）。

### 2.3 WAV
- `total_slots = data_len / bytes_per_sample`，即 `data` chunk 内全部 PCM 采样分量（`rust/src/stego/audio/wav.rs:59-63`、`:240-243`）。
- `base_slots = 512`；`ext_slots = 8 * ext_len`（`rust/src/stego/audio/core.rs:568`、`:711`）。
- `h = 8`（`DEFAULT_STC_H`，`rust/src/stego/coding/stc.rs:78`）；`u >= 1`，`Auto` 选 `u ∈ 1..=3`。
- `max_payload` 由 `payload_bytes_from_slots` 闭式反算，且被 768 MiB 工作集上限截断（`rust/src/stego/audio/core.rs:349-373`、`:388-402`）。

### 2.4 FLAC
- `total_slots = total_usable + 512`：`total_usable` 是逐帧解码后统计的**可移动残差槽**，不是全部采样（`rust/src/stego/audio/flac/mod.rs:886-892`、`:1026-1028`）。
- body 只扣 `512`；扩展的 `8 * ext_len` 占 subframe tail，不占残差池（`rust/src/stego/audio/core.rs:1023-1026`）；`h = 8`，`min_group = 3`，即 `u >= 3`（`rust/src/stego/audio/flac/mod.rs:894-896`）。
- 容量报告与写入共用 `capacity_info`（`rust/src/stego/audio/core.rs:388-451`）。

### 2.5 HEVC
- `total_slots`：选定 slice 内 CABAC 可吸收 bin 的总数（`rust/src/stego/hevc/engine.rs:818`、`:856`）；精确模式由 `scan_hevc_slot_count` 全量扫描（`:522-523`）。
- `base_slots = 524 = 2*(32*8 + 7 - 1)`（`rust/src/stego/hevc/engine.rs:89-94`）；`ext_slots = 2*(8*ext_len + 6)`，`ext_len = 0` 时为 0（`:130-142`、`:316`、`:427`）。
- `h = 7, u = 2` 固定（`rust/src/stego/hevc/engine.rs:130-134`）；扩展长度上限 64 字节（`:123-124`）。
- `max_payload` 使用 `hevc_max_raw_payload`，嵌入端同一函数（`rust/src/stego/hevc/engine.rs:470-500`、`:860`）。

### 2.6 工作内存预算（容量门的一部分）

| 载体 | 预算 | 计价 |
|---|---|---|
| PNG | 8 GiB | `64 MiB + 61 B/像素`，每 body slot 再加 `24 B`（STC 另加 backtrack bitmap），`rust/src/stego/png/engine.rs:516-534`、`:558-560` |
| JPEG | 8 GiB | 基础字节 + 每槽 `ceil(2^min(h,10)/64)*8 B`，`rust/src/stego/jpeg/engine.rs:100`、`:196-201`、`:1833` |
| WAV/FLAC | 768 MiB | `n * (ceil(2^((h-1)+(u>1))/64)*8 + 1 + 1 + 1 + 8)`，`rust/src/stego/audio/core.rs:69`、`:337-342`、`:371-373` |
| HEVC | 无独立预算 | 由 CABAC 槽数与分带策略门限定，`rust/src/stego/hevc/engine.rs:895-898` |

超预算一律按容量不足拒绝（PNG `PayloadTooLarge`，`rust/src/stego/png/engine.rs:536-549`；JPEG `PayloadTooLarge`，`rust/src/stego/jpeg/engine.rs:164-190`）。

### 2.7 长视频 HEVC 的 20% 估算
- `exact = false` 且载体为 MP4 容器：可选择一个 slice 数 `<= 150` 时**全量扫描**（0% 估算误差）；否则 `sample_limit = round(selectable * 0.20).clamp(150, 1000)`，按参考片/非参考片两个 band 各用自己的“采样字节→槽”密度外推到总字节（`rust/src/stego/hevc/engine.rs:727-735`、`:803-823`）。
- 这是“抽取 20% 的 slice 样本”而不是“前 20% 时间窗口”；`exact=true` / `--exact` 才全量扫描（`:681-685`）。
- 估算是 **I**：只影响上报值，不影响 `embed` 的精确门；`embed` 始终按实际槽数。

## 3. 结构域

### 3.1 最小信封与 UBE 组成

```text
UBE = header(112) + hint_len + meta_len + trailer(24)        (engine.rs:1231-1240)
meta_len   = 紧凑元数据密文 + AEAD tag(16)
紧凑元数据 = version(1) + name_len(2) + name + varint(raw_size) + digest(32) + varint(created_at)
payload    = framed_len(n, chunk_size) = n + chunks*20, chunks = ceil(n/chunk_size) >= 1
```

- 最小信封由 `min_ube_len(payload_len)` 给出：`112 + meta_len + framed_len(payload_len, CHUNK_SIZE) + 24`。
  当前时间戳下次方 7 位 varint 为 5 字节、空文件名时 `meta_len = 1+2+32+varint(payload_len)+5+16`。
  因此 `min_ube_len(0) = 213`、`min_ube_len(1) = 214`（`rust/src/structure/envelope.rs:102-132`）。旧文 `MIN_UBE_PLAIN=178 / MIN_UBE_ENCRYPTED=214` 中前者不对，且代码中没有这两个常量。
- `41 B` 的紧凑 meta = `1 + 2 + 32 + 1(byte 的 raw_size varint) + 5(当前秒级 created_at varint)`；`hint` 上限 1024，`meta` 上限 256 KiB。
- 每块开销固定 **20 B**（4 字节长度 + 16 字节 tag，`rust/src/core/crypto.rs:61-64`）；默认块 `CHUNK_SIZE = 2 MiB`，最大 `64 MiB`（`:96`、`:101`）。

### 3.2 各适配器容量口径

| 格式 | 口径（以 `strategy_capacities` 为准） | 出处 |
|---|---|---|
| 通用 EOF | 无上限（文件增长） | `rust/src/structure/adapters/eof.rs:25-33` |
| PNG | `chunk` 上限 `0x7FFFFFFF`；超过则 `eof` | `rust/src/structure/adapters/png.rs:119-129` |
| JPEG | `app_segment` 的名义上限 `JPEG_MAX_TOTAL_CAPACITY=64 MiB`，但实际受 `MAX_JPEG_HEADER_SCAN=16 MiB` 与 SOS 位移约束：`p + 4*ceil(p/65533) ≤ 16 MiB − sos`；SOS 扫描失败同样退 `eof` | `rust/src/structure/adapters/jpeg.rs:16-18`、`:198-216`、`:252-269` |
| WAV | 私有 `SHRD` RIFF chunk，受 `R + 8 + N + (N&1) ≤ u32::MAX` 与声明边界约束 | `rust/src/structure/adapters/wav.rs:25-38`、`riff.rs:126-133`、`:468-473` |
| WebP | 仅扩展格式（VP8X）可用 `SHRD` chunk，否则 `eof` | `rust/src/structure/adapters/webp.rs:25-50` |
| MKV | `ebml_void` 或 `eof`，报告"无上限"，实际受 VINT 上限与引擎钳制 | `rust/src/structure/adapters/mkv.rs:43-64` |
| MP4 | `box_uuid` / `eof`，报告"无上限"，实际受引擎钳制 | `rust/src/structure/adapters/mp4.rs:66-72`、`isobmff.rs:415-435` |
| HEIF | 优先 `item_hidden`（要求 `meta`/`iinf`/`iloc` 可解析），否则 `free_box`/`box_uuid`/`eof`；容量口径 `~4 GiB` 后由引擎钳到 64 MiB–1 GiB | `rust/src/structure/adapters/heif.rs:57-72`、`isobmff.rs:437-472` |
| ZIP | `pre_cd_inject` ≤ `0xFFFFFFFE − max(cd_offset, eocd+16)`；`cd_offset==0`、ZIP64 locator、32 位溢出、EOCD 缺失均退 `eof` | `rust/src/structure/adapters/zip.rs:145-171`、`:173-235` |
| PE | 取 codebits 与 slack 的较小者：`min(bits/8 − 14, longest_zero_run − 14)` | `rust/src/structure/adapters/pe.rs:208-283`、`:254-258` |
| PDF | `incremental` 仅当 trailer/xref 可解析且未加密、对象号 `< 0x7FFF_FFFF`；经典 xref 上限 10 GB、XRef 流上限 4 GB；否则退 `eof` | `rust/src/structure/adapters/pdf.rs:50-96`、`:795-801`、`:839-845` |

所有适配器上限最终被引擎钳到 `structure_payload_limit(host_len)`（`rust/src/structure/engine.rs:1902-1927`）。

### 3.3 自动策略选择的影响
`auto` 由各适配器的 `choose_auto_strategy(reader, exact_ube_size)` 一次性决定；适配器内部可因探测结果改选 `eof`，但引擎**不会**在注入失败后再换策略重试（`rust/src/structure/engine.rs:1242-1246`）。因此：

- PNG：`ube > 0x7FFFFFFF` 才退 `eof`；JPEG：`ube > 64 MiB`、`ube > app_segment_payload_capacity(sos)` 或 SOS 扫描失败退 `eof`。
- PDF：对象头长度 `> MAX_OFFSET_DELTA(64)` 退 `eof`；这不是容量上限，而是信封头无法记录的位移。
- HEIF：仅当 `ube <= u32::MAX-8` 且 `isobmff_can_item_hidden` 才选 `item_hidden`，否则 `box_uuid`（`heif.rs:57-68`）。
- PE：优先级 `pe_slack → pe_overlay`（`pe.rs:176-210`）；`pe_codebits` 是显式策略（`-s pe_codebits`），`auto` 不会选它。
- ZIP：`cd_offset==0`、ZIP64 locator、`patch_limit + ube >= 0xFFFFFFFF`、EOCD 缺失均退 `eof`。
- WAV/WebP：RIFF 声明边界必须等于物理长度且 4 GiB 头寸足够，否则 `eof`（`wav.rs:25-35`、`webp.rs:25-35`）。

## 4. 限额总表

| 限额 | 值 | 出处 |
|---|---|---|
| `HEADER_LEN_MAX` | `67,108,863`（26 位） | `rust/src/stego/header.rs:16-20` |
| `BODY_OVERHEAD` | `22` | `rust/src/stego/envelope.rs:97` |
| `MAX_PLAINTEXT_LEN` | `67,108,841` | `rust/src/stego/envelope.rs:101-102` |
| `MAX_EXT_BYTES`（PNG/JPEG/WAV/FLAC） | `255` | `rust/src/stego/header.rs:159` |
| HEVC `ext_len` | `<= 64` | `rust/src/stego/hevc/engine.rs:124` |
| `MAX_PNG_PIXELS` | `67,108,864` | `rust/src/stego/png/engine.rs:506` |
| PNG/JPEG 工作集 | `8 GiB` | `rust/src/stego/png/engine.rs:516`、`rust/src/stego/jpeg/engine.rs:100` |
| 音频工作集 | `768 MiB` | `rust/src/stego/audio/core.rs:69` |
| 结构头 / 尾 | `112 B` / `24 B` | `rust/src/structure/envelope.rs:83`、`:89` |
| `MAX_HINT_LEN` | `1024` | `rust/src/structure/envelope.rs:90` |
| `MAX_META_LEN` | `256 KiB = 262,144` | `rust/src/structure/envelope.rs:100` |
| `MAX_OFFSET_DELTA` | `64` | `rust/src/structure/envelope.rs:81` |
| `CHUNK_OVERHEAD` | `20 B/块` | `rust/src/core/crypto.rs:61-64` |
| `CHUNK_SIZE` / `MAX_CHUNK_SIZE` | `2 MiB` / `64 MiB` | `rust/src/core/crypto.rs:96`、`:101` |
| `MAX_VERIFY_PAYLOAD_SIZE` | `1 GiB` | `rust/src/core/crypto.rs:786` |
| 结构载荷上限 | `clamp(256 * host_len, 64 MiB, 1 GiB)` | `rust/src/structure/engine.rs:1902-1906` |
| 内容文件名 | `255 B` | `rust/src/stego/envelope.rs:78` |

## 5. 错误语义

- **容量不足必须返回 `PayloadTooLarge`，而不是 `UnsupportedFormat`。** `UnsupportedFormat` 只用于“载体不是本引擎认识的格式/结构”，不得用于“载体太小”。
- PNG：槽不足、预算超限均为 `PayloadTooLarge`（`rust/src/stego/png/engine.rs:544`、`:1582`、`:1596`、`:1620`、`:1629`）。
- JPEG：网格小于头、预算超限均为 `PayloadTooLarge`（`rust/src/stego/jpeg/engine.rs:1825`、`:164-190`）。
- HEVC：槽不足为 `PayloadTooLarge`（`rust/src/stego/hevc/engine.rs:1295`）。
- 结构域：写入前按 `structure_payload_limit` 拒绝，返回 `PayloadTooLarge`（`rust/src/structure/engine.rs:1088-1093`）。
- **实现偏差**：WAV/FLAC 的槽不足目前返回 `General`（`rust/src/stego/audio/core.rs:753-769`），与上述规范性要求不符；调用方不应把 `UnsupportedFormat` 当作容量不足的替代信号。

## 6. 稳定性分级

| 内容 | 级别 | 说明 |
|---|---|---|
| §1 统一公式、`BODY_OVERHEAD`、`HEADER_LEN_MAX` | **F** | 改变即改变可写边界与字节布局 |
| §2 各载体 `total/base/ext` 与 `h/u` | **F** | `probe`/`embed` 必须同口径；改动需重建基线 |
| §2.6 预算门 | **F** | 影响 `max_raw_payload_bytes` 与 `PayloadTooLarge` 判定 |
| §2.7 长视频 20% 估算 | **I** | 只影响上报精度，不改变写入 |
| §3.1 结构头/尾/块开销 | **F** | 已写 UBE 依赖 |
| §3.2 适配器容量文本 | **I** | 报告型上限；真正门是引擎钳制 |
| §4 限额数值 | **F** | 解析端按同值拒绝 |
| §5 错误分类 | **F** | 接口契约 |
