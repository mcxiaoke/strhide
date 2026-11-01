# 内容域扩展方案：HEVC/MKV 容器 + WAV/FLAC 音频

> **文档标识**：`docs/content_stego_mkv_hevc_wav_flac_plan_20261101.md`
> **编写时间**：2026-11-01
> **状态**：方案与可行性论证完成，**未改动任何代码**
> **目标**：为内容域（`rust/src/stego/`）增加 `FileFormat::Mkv`（HEVC 轨）与 `FileFormat::Wav` / `FileFormat::Flac` 三个载体的 embed / extract / probe / inspect / verify 能力。
> **定位红线**：沿用现有内容域语义 —— 覆盖写原位、文件长度严格不变（Δ = 0）、容器/帧结构与索引表逐字节保持、格式严格合法、可用标准工具校验通过。

---

## 0. 结论摘要

| 载体 | 复用现成解析器？ | 需要自研的部分 | 是否 Δ=0 | 主要风险 |
| :--- | :--- | :--- | :--- | :--- |
| **MKV (HEVC)** | **能**（`ebml-iterable` + `webm-iterable`，需 1 天 spike 确认偏移语义） | 物理 NAL Span 计算、CRC-32 重算 | 是 | Header Stripping 轨必须拒绝；Cluster CRC-32 必须按 RFC 9559 精确重算 |
| **WAV (PCM)** | **不需要**（仓库已有 `structure/adapters/riff.rs`，约 100 行即可覆盖；`hound` 只做测试对照） | PCM 槽位建模、代价模型 | 是 | 位深/声道/EXTENSIBLE/RF64 覆盖面 |
| **FLAC** | **不能**（无任何 crate 暴露 Rice 码字位偏移）；`claxon` 仅做测试 oracle | 位级帧解析 + 重建解码器 | 是（Rice 保长路线）；否（重编码路线） | 解析器覆盖率必须由帧 CRC-16 + STREAMINFO MD5 自校验兜底 |

三条关键实测结论（本文所有数字均来自本机实测，见 §9 附录脚本）：

1. **MKV 测试样本确实带 Cluster 级 `CRC-32`（0xBF）且位于 Cluster 第一个子元素**，`ContentEncodings` 不存在，`SimpleBlock` 无 Lacing。原 `mkv_and_avc_stego_implementation_plan_20261031.md` 把 CRC 当作"可能存在的边界情况"，实际是**必做项**。
2. **WAV 测试样本是 16-bit / 44.1 kHz / 双声道、只有 `fmt ` + `data` 两个 chunk**，`data` 载荷从偏移 36 开始 —— PCM 直改方案的最简单形态。
3. **FLAC 可以做到"原位不改帧长"**：把残差（Rice 码字）的折叠值改动 ±1/±2 且**限制在码长不变的槽位**上，实测音乐样本中 **93.3%** 的残差满足条件（≈0.93 槽位/字节）；但对"残差极小"的载体（Rice 参数 k ≤ 2）**安全槽位为 0%**。这与载体内容强相关，必须按文件实测容量。

---

## 1. 现状盘点（代码事实，非推测）

### 1.1 内容域现有引擎注册表

`rust/src/stego/engine.rs` 的 `ENGINES` 静态表决定一切分发：

```rust
static ENGINES: &[&dyn StegoEngine] = &[
    #[cfg(feature = "content-png")]   &PngEngine,      // FileFormat::Png
    #[cfg(feature = "content-jpeg")]  &JpegEngine,     // FileFormat::Jpeg
    #[cfg(feature = "content-hevc")]  &HeifEngine,     // FileFormat::Heif
    #[cfg(feature = "content-hevc")]  &Mp4Engine,      // FileFormat::Mp4
    #[cfg(feature = "content-hevc")]  &AnnexBEngine,   // FileFormat::HevcAnnexB
];
```

`StegoEngine` 只有 5 个方法：`probe / embed / extract / inspect / verify`，全部基于 `&[u8]` 载体 + `&StegoProfile` 方言 + 选项结构体。**新增载体 = 新增一个 `StegoEngine` 实现 + 一行注册**，不需要改动 `stego::mod` 的入口函数。

### 1.2 能力表是单一事实源，但它是**位置索引**的

`rust/src/formats/capability.rs` 的 `CAPABILITIES` 数组用 `CAPABILITIES[0..10]` 这种**下标**与 `FileFormat` 一一对应：

```rust
pub fn capability_of(format: FileFormat) -> &'static Capability {
    match format {
        FileFormat::Png => &CAPABILITIES[0],
        ...
        FileFormat::HevcAnnexB => &CAPABILITIES[10],
    }
}
```

**新增 `FileFormat::Flac` 变体时必须同步修改 `FileFormat::ALL`、`as_str()`、`Deserialize` 的变体名字符串数组、以及 `capability_of` 的下标映射**，否则 `every_format_has_exactly_one_row` 与 `domain_support_matches_the_documented_matrix` 两个测试会立刻失败（这是好事，但要提前知道有 4 处要改）。

### 1.3 HEVC 引擎与容器是解耦的

`rust/src/stego/hevc/engine.rs` 的核心函数 `record_carrier_state(carrier, kind, capture, stop, control)` 对 `HevcCarrierKind` 做三路 match，产出统一的：

```rust
(候选 VCL 切片 Vec<CandidateSlice>, DigestInputs, 参数集 Vec<Vec<u8>>, ps_end_offsets)
```

其后**所有逻辑（STC 矩阵求解、CABAC 重编码、EPB 冲突避让、Superblock 锚定、多轮迭代）与容器无关**。这正是 MKV 支持成本极低的原因：只要能把 MKV 解析成 `Vec<PhysicalNalSpan>` + 参数集，其余零改动。

`PhysicalNalSpan { start, len }`（`rust/src/stego/hevc/heif_boxes.rs:20`）就是引擎与容器之间唯一的契约。

### 1.4 `HevcCarrierKind` 有 12 处 match 点

grep 结果（`engine.rs`）：`323/338/352`（`extract_hevc_dimensions`）、`607-609` 与 `1747-1749`、`1792-1794`、`1828-1830`、`2151-2158`（格式名字符串）、`677/888`（`is_video` 判定）、`2750-2789`（`record_carrier_state`）、`3078`（`count_pictures`）。

**新增 `MkvContainer` 变体后这 12 处都要过一遍**。建议顺手抽一个 `HevcCarrierKind::label()` 与 `HevcCarrierKind::is_video_container()`，把散落的 `if kind == Mp4Container || record.pictures > 1` 之类收敛掉，否则第 13 处漏改就是静默错误。

### 1.5 结构域已覆盖 MKV/WAV，内容域是空白

- `structure/adapters/mkv.rs`（317 行）+ `ebml.rs`（155 行，提供 `read_element_id` / `read_vint_size` / `encode_vint`）已能流式定位 `Void` 与 EOF。
- `structure/adapters/wav.rs` + `riff.rs`（407 行）已能遍历 RIFF chunk。
- 内容域：`stego/engine.rs` 内有一条测试 `container_formats_without_a_content_engine_have_none` **显式断言 `Wav`/`Mkv` 没有内容引擎** —— 实现后必须删除/改写这条测试。

### 1.6 可复用的加密与编码基础设施

| 能力 | 位置 | 音频/MKV 能否直接复用 |
| :--- | :--- | :--- |
| 信封封装（AES-256-GCM + salt/nonce/micro-header） | `stego/envelope.rs` | 是，无载体耦合 |
| 头字（26-bit 长度 + codec id + stc_h/u） | `stego/header.rs` `encode_header_word` | 是 |
| 32 字节 FeatureWord（512 slots） | `stego/header.rs` | 是 |
| STC Trellis | `stego/coding.rs` `StcTrellis::from_seed_grouped(seed, h, u)` | 是（纯比特域） |
| Hamming 分组码 | `stego/coding.rs` `hamming_embed_ternary` | 是 |
| 域密钥派生 | `stego/envelope.rs` `derive_*_seed_with_label` | 是，加 `audio.*` / `mkv.*` label |

**意味着音频不需要新造密码学与编码协议**，只需要"把 PCM 采样 / FLAC 残差 + 代价映射"接到现有 STC 上，并复用 PNG 引擎已有的"header slots 由密钥置换选出、body slots 由几何/结构确定"的范式。

---

## 2. 外部资料核查：哪些旧结论必须修正

`docs/` 下已有三份相关文档，结论并非全部可用，逐条核对如下（`frontier_steganography_verification_and_survey_2026.md` 的纠偏大部分成立，但需再修正两点）：

| 旧文档结论 | 本次核查 | 处置 |
| :--- | :--- | :--- |
| MKV 用零拷贝 EBML Span 扫描器（`mkv_and_avc_...20261031.md` §2.1） | **方向正确**，且 `PhysicalNalSpan` 契约确实只要求"绝对偏移+长度" | 采纳 |
| "若 MKV 使用 Cluster CRC-32，需更新"（当作可选） | **错误**：实测 2/2 样本的每个 Cluster 都带 `0xBF`，且是 Cluster 首个子元素 | 升级为**必做**，见 §3.5 |
| 未提及 `ContentEncodings`（Header Stripping） | 实测样本没有，但规范允许 | 采纳"检测到即拒绝" |
| 音频 WAV 用 Block Parity / QIM / STC 并列推荐（`audio_...20261031.md` §3.1-3.3） | **Block Parity 应删除**：它是 STC 校验矩阵退化特例，率失真严格更差 | 只做 STC（+ Hamming 作为低开销模式） |
| FLAC = 解码 → `flacenc` 重编码（`audio_...20261031.md` §5 阶段二） | **可行但取证不安全**：LPC 阶数、Rice 分区、`VENDOR` 签名全部改变，等于自曝重编码 | 降级为**兜底模式**；主路线改为原位 Rice 保长（§5） |
| `claxon` 已 6 年未更新，改用 `symphonia`（`frontier_...2026.md` §1.2） | **事实正确**（`cargo search` 实测 `claxon 0.4.3`、`symphonia-bundle-flac 0.6.1`） | 两者都不进运行时依赖，仅 `dev-dependencies` 做测试 oracle |
| 文档未涉及 | **新发现**：FLAC 的 Rice 参数是**每个分区就地读取**，不是先读完所有分区参数（详见 §5.3） | 写入实现要点，避免踩坑返工 |

---

## 3. 阶段一：MKV 容器（HEVC 轨）

### 3.1 实测样本结构

`temp/testhevc/HDRSample.mkv`（2.7 MB，1920×1080 HEVC Main）与 `SDRSample.mkv`：

```
top-level: EBML(0x1A45DFA3) + Segment(0x18538067)
TrackEntry: TrackNumber=1, TrackType=1, CodecID="V_MPEGH/ISO/HEVC",
            CodecPrivate len=2455  (即标准 HEVCDecoderConfigurationRecord)
Cluster: 4 个；每个 Cluster 首个子元素是 CRC-32(0xBF)，其后 Timestamp(0xE7)、SimpleBlock(0xA3)
SimpleBlock: 285 个，Lacing 直方图 {0: 285}  → 全部无交织
ContentEncodings(0x6D80): 不存在
CRC-32 位置: 9 个，父元素分别为 SeekHead / Info / Tracks / Tags / Cluster×4 / Cues
             （其中只有 4 个 Cluster 会被我们改动，其余 5 个覆盖范围不含任何 Block）
```

`temp/bighevc/anime-a.mkv`（430 MB，Main 10，含 17 条音轨/字幕轨/附件）用于压力与"非目标轨跳过"验证。

### 3.2 解析器选型：用 `ebml-iterable`，还是自研？

**判定规则**：我们需要的不是"解码出帧数据"，而是**每个 VCL NAL 在文件中的绝对字节区间**。凡是把载荷 `Vec<u8>` 拷贝出来、丢掉偏移的 demuxer（`matroska-demuxer`、`symphonia`、FFmpeg 的 libavformat）**一律不可用** —— 重打包会破坏 Cluster 分块、Cues、SeekHead，直接违反 Δ=0。

候选评估：

| 方案 | 版本 | 提供物理偏移？ | 未定长 Segment？ | 零拷贝？ | 结论 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `ebml-iterable` + `webm-iterable` | 0.7.1 / 0.7.1 | **是**（`PositionedTag` 带 `position` 字节偏移） | 文档称 0.4.0 起支持 | 否（Tag 载荷入 `Vec`，但只到单个 Block 粒度） | **首选，需 spike 验证** |
| `matroska-demuxer` | 0.8.1 | 否（Frame 只有 data） | — | 否 | 排除 |
| 自研零拷贝扫描器 | — | 是 | 可控 | 是 | 备选（约 300 行） |

**建议**：先花 **0.5~1 人天**做 spike，用 `ebml-iterable` 跑 `temp/testhevc/HDRSample.mkv`，验证三件事：

1. `PositionedTag.position` 指向元素 ID 的**起始字节**（而非载荷）—— 只有这样才能用 `position + id_len + vint_len` 算出 `SimpleBlock` 载荷起点；
2. `Segment` 与 `Cluster` 若为"未知长度"，迭代器能否正常推进到下一个 Cluster 而不是吞到 EOF；
3. 对 430 MB 的 `anime-a.mkv`，全量遍历耗时与峰值内存可接受（预计每 Block 一次 `Vec` 分配，285 块/4 分钟级别没问题；若样本出现 3.6M 级 Block 再考虑自研）。

**spike 判定失败时的兜底**：`rust/src/stego/hevc/mkv_boxes.rs` 自研零拷贝扫描器，直接复用 `structure/adapters/ebml.rs` 的 VINT 读法（但需要 `&[u8]` 版本，现有的基于 `SeekRead`，需加 20 行 `read_element_id_at(&[u8], pos)`）。这条路径其实更快、内存更省，唯一代价是多写 300 行。

> 注：`ebml.rs` 的 `read_vint_size` 返回 `Option<u64>`（`None` = 未知长度），已经正确处理了 RFC 8794 的"全 1 即未知"，自研路径可直接复用该语义。

### 3.3 定位算法（`parse_mkv_targets`）

```
1. 校验 EBML Header：DocType ∈ {"matroska", "webm"}
2. 进入 Segment（可能为未知长度 → 以文件末尾为界）
3. Tracks → 遍历 TrackEntry：
     TrackType == 1 且 CodecID == "V_MPEGH/ISO/HEVC" → 记 TrackNumber
     若 TrackEntry 下存在 ContentEncodings(0x6D80) → 立即返回 Unsupported
       （ContentCompAlgo=3 的 Header Stripping 会剥离每帧公共前缀，
        直接按 HVCC 长度前缀解析会整体错位）
     CodecPrivate(0x63A2) → 直接喂给现有 parse_hvcc_record()，得 VPS/SPS/PPS + length_size
4. 遍历所有 Cluster → 子元素：
     SimpleBlock(0xA3)  → 解析 Block Header
     BlockGroup(0xA0) → 子元素 Block(0xA1) → 解析 Block Header
     CRC-32(0xBF) → 记录 (crc_offset, covered_range)，见 §3.5
     Void(0xEC) / Timestamp(0xE7) / Position(0xA7) 等 → 跳过
5. Block Header：
     track_number = EBML VINT（注意：Block 里的 track number 是 VINT，
                    与 TrackEntry 的 TrackNumber 数值比较，不是原始字节比较）
     若 != 目标轨 → 整块跳过
     timecode = i16 BE（2 字节）
     flags = 1 字节：bit7 关键帧；bit1-2 lacing（0=无, 1=Xiph, 3=EBML, 2=fixed）
6. Lacing：
     flags & 0x06 == 0 → 整个载荷即连续的 HVCC 长度前缀 NAL 序列
     否则 → 每个子帧的载荷仍然按 HVCC 前缀排列，但**帧边界**要按 lace 头切分；
            实现上先支持无 lacing，遇到 lacing 返回 Unsupported（视频轨实际几乎不用）
7. 按 length_size 切 NAL：
     start = block_payload_offset + length_size
     end   = start + nal_len
     仅收 nal_type ∈ VCL（0..=31 中的切片类型）→ PhysicalNalSpan
```

### 3.4 引擎接入点

| 位置 | 改动 |
| :--- | :--- |
| `stego/hevc/sniff.rs` | `HevcCarrierKind` 增加 `MkvContainer`；`sniff_hevc_carrier` 对 `FileFormat::Mkv` 返回它 |
| `stego/hevc/engine.rs` `record_carrier_state` | 新增 match 臂：`parse_mkv_targets(carrier)` → 与 Mp4 分支同构地填 candidates / parameter_sets |
| `stego/hevc/engine.rs` `count_pictures` | MKV 无 `stsz`，用"块计数"：`parse_mkv_targets` 顺带返回 `picture_count`（无 lacing 时 = SimpleBlock 数量） |
| `stego/hevc/engine.rs` `extract_hevc_dimensions` | 从 SPS 解析（与 Mp4 分支同一路径） |
| `stego/engine.rs` | 新增 `MkvEngine`（`format() = Mkv`），内部调 `hevc_embed/extract/probe/inspect/verify` |
| `formats/capability.rs` | `FileFormat::Mkv` 的 `stego` 从 `&[]` 改为 `&[StegoKind::HevcCabac]` |
| `stego/hevc/engine.rs` 测试 | 删除 `container_formats_without_a_content_engine_have_none` 中的 `Wav`/`Mkv` 两项 |

**注意**：`hevc_embed/hevc_extract` 里有一段 `if format != FileFormat::Heif` 的分支（HEIF 才走缩略图桥接）。MKV 与 MP4 一样属于"Scheme C 唯一路径"，必须落在该分支内，不要因为改动顺序把它变成"未知格式"。

### 3.5 Cluster CRC-32：必须按 RFC 9559 精确重算

规范约束（写错就是 `mkvmerge` / `ffmpeg` 报 `EBML CRC-32 mismatch`）：

- `CRC-32` 元素（ID `0xBF`，1 字节 ID + 1 字节 VINT 长度 + 4 字节大端值）**必须是父 Master 元素的第一个子元素**；
- 校验范围 = **父元素内、`CRC-32` 元素结束之后到父元素末尾的全部字节**（不含父元素自身的 ID 与长度字段，也不含 `CRC-32` 自身 6 字节）。

实现要点：

1. 扫描时对每个带 `0xBF` 的父元素记录 `(crc_value_offset, covers_start, covers_end)`；
2. 隐写只改 Block 载荷，因此只需刷新**被修改 Span 落在其覆盖范围内**的那些父元素；
3. 用现成 `crc32fast`（已在 `Cargo.toml` 依赖里）计算，IEEE 多项式，与 EBML 要求一致；
4. **写完必须自检**：重新计算并比对，不一致直接返回错误而不是产出坏文件。

实测样本里 SeekHead / Info / Tracks / Tags / Cues / 每个 Cluster 都带 CRC-32，所以这条逻辑是常态路径而非罕见分支；只是前 5 者的覆盖范围不含 Block，扫描时判定"被改 Span 是否落在覆盖区间内"即可自动跳过。

### 3.6 边界与拒绝清单

| 情况 | 处理 |
| :--- | :--- |
| `CodecID != V_MPEGH/ISO/HEVC`（含 MPEG-4/AVC、AV1、VP9） | 拒绝，错误信息明确写"I 阶段只支持 HEVC 轨" |
| `ContentEncodings` 存在（压缩/加密） | 拒绝 |
| Block 有 Lacing | 拒绝（视频轨罕见；避免帧边界误判） |
| WebM（DocType=webm） | 允许扫描，但 WebM 规范禁止 HEVC → 实际会因 CodecID 不匹配而拒绝，消息要准确 |
| Segment 未知长度（流式录制） | 支持，以 EOF 为界 |
| 多视频轨 | 取**第一条** HEVC 轨（与 MP4 引擎一致），其余跳过 |

---

## 4. 阶段二：WAV（PCM 空间域）

### 4.1 实测样本

`temp/testaudio/タユタマ零 Track 4.wav`（14.4 MB）与 `Track 16.wav`（20.7 MB）：

```
RIFF size 匹配文件长度（无尾部垃圾）
chunks: ('fmt ', 12, 16), ('data', 36, 14464800)
fmt: tag=1 (PCM) ch=2 rate=44100 block_align=4 bits=16
```

最简单形态：`fmt ` 后直接 `data`，载荷起点 36，采样数 = `data_size / block_align` = 3,616,200。

### 4.2 载体模型

- **槽位 = 一个采样点的一个声道分量**（16-bit 时 = 2 字节小端有符号整数）；
- 修改操作 = 采样值 `±1`（三元 STC 的 `+1 / 0 / -1`）；
- 提取 = 读采样值并按密钥置换取出对应槽位的奇偶性/校验子。

**为什么不用 Block Parity**：块奇偶校验等价于 `H = [1,1,...,1]` 的退化校验矩阵，在相同修改率下失真严格更差；仓库已有 `stc.rs` 与 `hamming_embed_ternary`，直接复用即可，代码量不增加。

### 4.3 代价模型（只在嵌入端计算）

人耳掩蔽规律：**静音段的 ±1 可闻，强瞬态/宽带噪声段不可闻**。用两路局部统计构造（滑动窗口 O(n)，单遍）：

```
d1(i)   = |s(i) - s(i-1)|                       // 一阶差分（瞬态敏感）
rms(i)  = sqrt( mean(s(i-W..i+W)^2) ),  W = 32   // 局部能量（噪声掩蔽）
rho(i)  = 1 / (eps + a*rms(i) + b*d1(i))        // 高能量/强瞬态 → 低代价
```

补充规则：

- **纯数字静音（连续全 0 且长度 > 阈值）代价置为极大有限值**（不能是 `inf`，STC 求解器需要有限浮点；用 `1e9` 并配合"跳过"标记）；
- 裁剪溢出：`s = i16::MAX` 时 `+1` 不可行、`i16::MIN` 时 `-1` 不可行 → 该方向代价置极大；
- 8/24/32-bit 复用同一公式，只是读取宽度与边界不同。

### 4.4 Δ=0 与结构不变的保证

- 只在 `data` chunk 载荷内覆写，**chunk 长度字段、RIFF size、fmt 全部不动** → 文件长度与所有偏移不变；
- 不新增 chunk（那是结构域 `riff_chunk` 策略的事，两者互不影响）；
- 若 `data_size` 为奇数（WAV 规范要求 chunk 补齐字节），补齐字节在 `data` 之外，不受影响。

### 4.5 覆盖面

| 维度 | 支持 |
| :--- | :--- |
| 位深 | 8（无符号，需偏移 128）、16、24、32（int）；32-bit float **拒绝**（±1 ULP 语义不同，另行设计） |
| 声道 | 1~8（多声道按 interleaved 顺序平铺，槽位顺序 = 文件顺序） |
| `WAVE_FORMAT_EXTENSIBLE`（`0xFFFE`） | 支持，按 `SubFormat` 判定是否 PCM |
| 额外 chunk（`LIST`/`fact`/`bext`） | 支持，遍历到 `data` 为止 |
| RF64 / 带 `ds64` | 拒绝（48-bit 长度语义不同，暂不做） |
| 压缩 WAV（`WAVE_FORMAT_ADPCM` 等） | 拒绝 |

### 4.6 容量（估算，实际由引擎按安全等级裁剪）

16-bit / 44.1 kHz / 双声道 = 88,200 槽位/秒。按 Hamming k=3（约 0.43 bit/槽位）：

| 时长 | 槽位 | 可用载荷（约） |
| :--- | ---: | ---: |
| 1 分钟 | 5.29 M | 280 KB |
| 5 分钟 | 26.5 M | 1.4 MB |
| 1 小时 | 317 M | 17 MB |

---

## 5. 阶段三：FLAC（原位 Rice 保长）

### 5.1 为什么不能简单"解码 → 改 PCM → flacenc 重编码"

`frontier_...2026.md` 已经指出：重编码后 LPC 阶数、Rice 分区参数、帧字节长度、`VENDOR` 字符串全部改变。这在取证上是**双重压缩指纹**，等于主动暴露"这个文件被工具重写过"。对 `strhide` 的 Δ=0 品牌是硬伤。

因此主路线定为：**在原始 Rice 码字上原位改动折叠值，只选码长不变的槽位**。

### 5.2 可行性实测（本机数据）

先把"改一个残差"的语义固定下来：

- 采样值 `s(i) = pred(s(i-1..)) + e(i)`，`e` 是存储的残差；
- 我们只改**存储的 `e`**，`e → e ± 1` → 解码出的 `s(i)` 变化 ±1（后续采样通过预测器轻微漂移，见 §5.6）；
- FLAC 的 Rice 编码：折叠 `u = 2e (e≥0) | -2e-1 (e<0)`，码长 `len = (u >> k) + 1 + k`；
- `e ± 1` 使 `u` 变化 ±1 或 ±2，**码长不变 ⟺ `(u+2) >> k == (u-2) >> k`**（且 `u ≥ 2`）。

实测结果：

| 样本 | 编码器 | 帧数（抽检） | 解析成功率 | 安全槽位占比 | 槽位/字节 |
| :--- | :--- | ---: | ---: | ---: | ---: |
| `temp/probe_b.flac`（动画 OST 片段，ffmpeg 编码） | ffmpeg | 12/12 | **100%** | **93.3%** | **0.93** |
| `temp/testaudio/01_Sphere.flac` | libFLAC 1.4.3 | 2/40（另 38 帧解析器未覆盖） | 5% | 95.0% | 0.89 |
| `temp/testaudio/12_Deep_Space_Pyramid.flac` | libFLAC 1.4.3 | 39/40 | 97.5% | **0.0%**（k=0/1） | 0.00 |
| `temp/testaudio/15_Celestial_Crystals.flac` | libFLAC 1.3.1 | 40/40 | 100% | **0.0%**（k=1） | 0.00 |

（解析成功率以「帧 CRC-16 与 ffprobe 报告的帧边界同时吻合」判定；脚本见 `temp/flac_frame_probe.py`。）

**结论与工程含义**：

1. 音乐类载体安全槽位约 0.9/字节 → 10 MB FLAC ≈ 9 M 槽位，容量与同长度 WAV 同量级；
2. **残差极小（k ≤ 2）的载体安全槽位为 0**：`e±1` 必然跨过 Rice 桶边界。这类载体（上采样合成音、极安静素材）**原位路线无容量**；
3. 因此 FLAC 必须实现**按文件实测容量**，并在容量为 0 时给出明确可操作提示（不是"神秘失败"）。

### 5.3 帧解析要点（踩坑记录）

一个真实的坑，写进实现文档以免返工：**FLAC 的 Rice 参数不是"先读完 2^order 个参数，再读全部残差"，而是每个分区内就地在残差之前读取**。以 FFmpeg `libavcodec/flacdec.c::decode_residuals()` 为权威：

```c
method_type = get_bits(&gb, 2);
rice_order  = get_bits(&gb, 4);
for (partition = 0; partition < (1 << rice_order); partition++) {
    tmp = get_bits(&gb, rice_bits);        // ← 参数在分区循环内部
    if (tmp == rice_esc) { tmp = get_bits(&gb, 5); /* 定宽原始残差 */ }
    else { for (; i < samples; i++) get_sr_golomb_flac(&gb, tmp, ...); }
    i = 0;
}
```

分区 0 的残差数量是 `blocksize >> rice_order - pred_order`，其余分区是 `blocksize >> rice_order`。

其余必须严格照规范的字段（顺序不可错）：

```
frame header : 14b sync(0x3FFE) + 1b reserved + 1b blocking + 4b blocksize code
               + 4b samplerate code + 4b channel assignment + 3b sample size + 1b reserved
               + UTF-8 coded frame/sample number (1..7B) + [optional blocksize] + [optional rate]
               + 8b CRC-8   ← 校验覆盖上述全部字节，实测 3/3 文件通过
subframe     : 1b zero + 6b type + 1b wasted-flag (+ unary wasted count)
               CONSTANT  : bps 位常量
               VERBATIM  : bps × blocksize
               FIXED     : bps × order 预热 + residual
               LPC       : bps × order 预热 + 4b (prec-1) + 5b shift + prec × order 系数 + residual
stereo       : channel assignment 8/9/10 时，第二声道（side）位宽 = bps + 1
frame footer : 16b CRC-16（覆盖整帧除自身外全部字节）
```

### 5.4 自校验：让解析器"错就拒绝"，绝不产出坏文件

这是 FLAC 路线能否被信任的关键设计。文件自带两把尺子：

1. **逐帧 CRC-16**：解析出的帧边界若不落在 `CRC-16` 值上 → 该帧解析错误；
2. **STREAMINFO 的 MD5**（offset 18..34）：覆盖**整段解码后 PCM**。

因此实现强制流程：

```
解析 → 完整重建 PCM → 计算 MD5 → 与 STREAMINFO 比对
  一致   → 允许嵌入（同时说明解析器对该文件 100% 正确）
  不一致 → 返回 Unsupported("FLAC carrier could not be fully validated")
```

这条契约把"解析器覆盖率不足"从**静默损坏**降级为**明确拒绝**，也是分阶段放量的前提：先用它跑语料统计覆盖率，再决定默认开启还是标注 beta。

> 反过来说：只要 MD5 对得上，就说明我们对 LPC/FIXED/const/verbatim/wasted/escape 全部处理正确。

### 5.5 槽位与代价

- **槽位集** = 全部"码长安全"的残差码字（按文件顺序），排除已用作 header 的 512 个；
- **槽位选择必须与代价模型无关**：提取端不计算代价，只按 `(seed, 文件结构)` 复现槽位集合 → 与 JPEG V3 的设计一致；
- **嵌入后需要重新验证槽位集稳定**：改动后重算 `k` 和 `u` 桶必须不变（由长度不变条件保证），测试里要断言"stego 文件算出的槽位集 == cover 的槽位集"；
- **代价**：用重建出来的采样算 §4.3 的 `rho(i)`；额外规则：
  - 该残差若落在 escape 分区（定宽原始编码）→ **不作为槽位**（宽度语义不同，收益低风险高）；
  - 该采样若处于纯静音段 → 代价置极大。

### 5.6 预测漂移与修正回路

改 `e(i)` 只改采样 `s(i)`；但 FLAC 的预测器用**已重建的前序采样**，所以 `s(i+1), s(i+2)…` 会跟着漂移：

```
err(j) = Σ_{k=1..order} a_k · err(j-k)      (j > i)
```

- FLAC 的 LPC 系数由 Levinson-Durbin 从自相关求得，理论上是**最小相位**，误差随时间衰减；
- 但系数量化（`qlp_shift`）可能破坏严格最小相位，长 order + 极端系数下有放大风险。

因此必须加一个与 HEVC "EPB 多轮避让"同构的**漂移修正回路**：

```
loop (最多 N=8 轮):
    用修改后的残差重建整帧 PCM
    drift = max |s_stego(j) - s_cover(j)|  (j ∈ 帧内)
    if drift <= DRIFT_BUDGET (默认 2 LSB):
        break
    else:
        把本帧内"最后修改的若干槽位"的代价置为极大，重跑 STC Trellis
写回：帧 CRC-16 重算 + STREAMINFO MD5 重算
```

`DRIFT_BUDGET` 与每帧最大修改数写入 FeatureWord（复用现有 32 字节特性字，已有窗口字段可扩展）。

### 5.7 帧结构层面的 Δ=0 清单

| 需要重算的字段 | 偏移是否变化 | 说明 |
| :--- | :--- | :--- |
| 帧头 CRC-8 | 不变 | 帧头一个字节都没改，**不需要**重算（但实现里仍校验一遍） |
| 帧尾 CRC-16 | 不变 | 内容变了必须重算，长度固定 2 字节 |
| STREAMINFO MD5 | 不变 | 16 字节定长，采样变了必须重算 |
| STREAMINFO min/max frame size | 不变 | 帧字节长度未变 |
| SEEKTABLE | 不变 | 存的是采样号/帧号，不是字节偏移；帧长未变也不会失效 |
| VORBIS_COMMENT / PICTURE / PADDING | 不变 | 完全不碰 |

实测 2/4 个样本带 `SEEKTABLE`，这条"帧长不变 → 索引天然有效"的性质是原位路线相对重编码路线的核心优势。

### 5.8 兜底路线（`--flac-reencode`，默认关闭）

对 §5.2 中"安全槽位 0%"的载体，提供显式可选的重编码模式：

```
claxon/symphonia 解码 → PCM 槽位嵌入（复用 §4 全部逻辑）→ flacenc 重编码
```

- 明确告知：**输出与原始编码器指纹不同、文件长度会变、Δ ≠ 0**；
- 仅作为用户显式选择，不做自动回退（自动回退会造成"同一个命令有时无损有时重编码"的不可预期行为）。

---

## 6. 统一架构：新增模块与注册

```
rust/src/stego/
├── audio/
│   ├── mod.rs            # 公开 API：embed/extract/probe/inspect/verify (WAV/FLAC)
│   ├── pcm.rs            # PCM 抽象：位深/声道/槽位迭代/±1 读写/边界裁剪
│   ├── cost.rs           # 局部能量 + 差分代价模型（WAV 与 FLAC 共用）
│   ├── carrier.rs        # 载体抽象：给出"槽位流 + 覆写回调"，WAV/FLAC 各自实现
│   ├── wav.rs            # RIFF 解析：定位 data 载荷、fmt 参数校验
│   └── flac/
│       ├── mod.rs
│       ├── bitio.rs      # MSB-first 位读写器（含 unary / signed）
│       ├── frames.rs     # 帧头/子帧/残差解析，产出残差码字位偏移 + 帧元数据
│       ├── decode.rs     # FIXED/LPC 重建、wasted bits、声道去相关 → PCM
│       ├── slots.rs      # 安全槽位判定与枚举
│       └── verify.rs     # CRC-16 / MD5 自校验
├── hevc/
│   └── mkv_boxes.rs      # 新增（或 ebml-iterable 适配层）
└── engine.rs             # 新增 WavEngine / FlacEngine / MkvEngine
```

**关键抽象**：`carrier.rs` 定义一个最小 trait，让 WAV 与 FLAC 共用 STC/信封/header 流程：

```rust
pub(crate) trait AudioCarrier {
    /// 载体自检：解析是否完整可信（FLAC 用 MD5，WAV 用结构校验）
    fn validate(&self) -> Result<(), StrHideError>;
    /// 槽位总数（不含已被 header 占用的）
    fn slot_count(&self) -> usize;
    /// 读取槽位当前奇偶性
    fn read_slot(&self, idx: usize) -> u8;
    /// 施加一次 ±1 修改并记录待写回的物理位置
    fn apply(&mut self, idx: usize, delta: i8) -> Result<(), StrHideError>;
    /// 提交：重算校验字段（FLAC 的 CRC-16/MD5；WAV 无）并输出字节
    fn commit(self) -> Result<Vec<u8>, StrHideError>;
    /// 嵌入端专用：每槽位代价
    fn costs(&self) -> Option<Vec<f64>>;
}
```

这样 `embed/extract/probe` 的主干（header 置换 → 信封加密 → STC 求解 → 写回 → 自检）只写一遍。

---

## 7. 数据契约与对外可见变更

| 变更 | 位置 | 影响 |
| :--- | :--- | :--- |
| `FileFormat::Flac` 新变体 | `formats/sniff.rs`（`fLaC` 魔数）+ `ALL` + `as_str` + `Deserialize` 名单 | `capability_of` 下标、CLI `list` 输出、`sniff` 测试 |
| `HevcCarrierKind::MkvContainer` | `stego/hevc/sniff.rs` | 12 处 match 点，见 §1.4 |
| `StegoKind::WavPcm` / `StegoKind::FlacResidual` | `formats/capability.rs` | GUI 能力卡片、CLI `--json` |
| `StegoTuning::Wav`/`Flac`（可选，先不加） | `stego/options.rs` | 暂无旋钮需求，先走 `Auto`，避免无意义 API |
| `StegoProfile` 的 `audio_format()` | `stego/params.rs` | 与 `png_format()/jpeg_format()/hevc_format()` 同构 |
| CLI 扩展名 | `capability.rs` 的 `extensions` | `flac` 新增；`wav`/`mkv` 已有 |
| `baseline_hash.py` | `temp/baseline/baseline.json` | 新增载体不动旧条目；但 `list`/capability 输出若纳入基线需重建 |

**FeatureWord 的算法字段**：音频槽位选择与代价模型解耦，需要写入"槽位枚举规则版本 + WAV/FLAC 子类型"，复用现有 32 字节特性字的保留位；若不够，提升 `FEATURE_WORD_BYTES` 需评估与既有载体的兼容（项目未发布，可接受一次格式升级，但要集中在一处改动）。

---

## 8. 实施顺序、里程碑与验收

### 8.1 顺序（按依赖与风险倒排）

| # | 里程碑 | 内容 | 前置 | 出口标准 |
| :--- | :--- | :--- | :--- | :--- |
| M0 | **技术 spike（0.5~1 天）** | ① `ebml-iterable` 偏移语义验证；② FLAC 位级解析器跑通 `temp/testaudio/*.flac` 全文件 MD5 校验 | 无 | 两个问题都有明确 yes/no，失败即切备选路线 |
| M1 | **WAV 端到端（2~3 天）** | `audio/{pcm,cost,wav}.rs` + `WavEngine` + capability | 复用 STC/信封 | 真实 WAV 往返、Δ=0、ffmpeg 解码无警告 |
| M2 | **MKV/HEVC（2~3 天）** | `mkv_boxes.rs`（或适配层）+ `MkvEngine` + CRC-32 刷新 | M0① | 3 个 mkv 样本往返；`mkvmerge`/`ffmpeg -v error` 无错 |
| M3 | **FLAC 原位（5~8 天）** | `flac/*` 全套 + `FlacEngine` + 漂移回路 | M0②、M1 代价模型 | 语料 MD5 覆盖率 ≥ 95%；往返 + 槽位集稳定 |
| M4 | **FLAC 重编码兜底（1~2 天）** | `--flac-reencode` 显式开关 | M1 | 与 M3 输出在功能上等价（但标记非 Δ=0） |
| M5 | **收尾（1~2 天）** | CLI/GUI 文案、i18n、文档、基线、`CHANGES-*.md` | 全部 | 全量测试 + clippy 全绿 |

### 8.2 测试矩阵

**单元测试**（每模块内）：

- WAV：位深 8/16/24/32 × 声道 1/2/6；`data` 前后有 `LIST`/`fact`；奇数 `data_size`；`EXTENSIBLE`；损坏 chunk 拒绝；
- MKV：VINT 边界（未知长度、8 字节 ID）、无 lacing / 有 lacing、BlockGroup vs SimpleBlock、非目标轨跳过、CRC-32 覆盖范围；
- FLAC：帧头 CRC-8、帧尾 CRC-16、CONSTANT/VERBATIM/FIXED/LPC 四种子帧、escape 分区、wasted bits、声道分配 8/9/10、k=0/1/…/14 各档的安全槽位判定（用构造的比特流，不依赖外部文件）。

**真实素材回归**（`tests/test_media`，标 `#[ignore]` 走 `cargo test local_ -- --ignored`）：

| 素材 | 断言 |
| :--- | :--- |
| `temp/testaudio/*.wav`（3 个，14~42 MB） | 往返；长度不变；`sha256(stego) != sha256(cover)` 但 `len` 相同；差异只在 `data` 区间；ffmpeg 解码 PSNR > 70 dB |
| `temp/testaudio/*.flac`（3 个） | 往返；长度不变；`flac`/ffmpeg 解码无 CRC 警告；MD5 自校验通过；槽位集稳定；漂移 ≤ 预算 |
| `temp/testhevc/*.mkv`（2 个）、`temp/bighevc/anime-a.mkv` | 往返；长度不变；`ffmpeg -v error -i out.mkv -f null -` 无输出；CRC-32 全部匹配 |
| 负例 | 无隐藏数据时 `NoHiddenData`（<20 ms）；错误密码不区分对待；FLAC 无容量的载体返回明确错误 |

**交叉验证（关键，防止"自己验自己"）**：

- WAV：用 `ffmpeg` 解出 PCM，与引擎内部 PCM 逐采样比对；
- FLAC：用 `flac -t` / `ffmpeg` 解码，验证 `CRC-16`、`MD5`、`STREAMINFO` 一致性；
- MKV：`mkvmerge -i`、`ffprobe` 检查轨道/时长/帧数未变。

**基线**：`python scripts/baseline_hash.py --check` 必须全绿（新载体不进入旧基线；若 CLI `list` 输出纳入基线，则明确重建并记录理由）。

### 8.3 验收红线

1. **Δ = 0**：所有新载体的输出文件长度与被覆盖区域集合严格受控（WAV 仅 `data`、FLAC 仅残差位 + 帧 CRC + STREAMINFO MD5、MKV 仅 Block 载荷 + 受影响 CRC-32）；
2. **合法性**：外部工具（ffmpeg / mkvmerge / flac）零报警；
3. **诚实失败**：任何无法自校验的 FLAC 载体必须拒绝，不允许"尽力而为"；
4. `cargo fmt` / `cargo clippy --all-targets --all-features -- -D warnings` 全绿；
5. 新增依赖全部 `optional`，且 `content-audio-*` / `content-mkv` 特性可独立开关。

---

## 9. 附：本次实测所用的核验脚本

均放在 `temp/`（临时产物，不进仓库）：

| 脚本 | 作用 | 关键输出 |
| :--- | :--- | :--- |
| `temp/mkv_probe.py` | 遍历 EBML 树，统计 Cluster/CRC-32/SimpleBlock/Lacing/ContentEncodings | 285 个无 lacing 的 SimpleBlock；每 Cluster 带 CRC-32 |
| `temp/audio_probe.py` | WAV chunk / FLAC STREAMINFO + 元数据块 | 16-bit 44.1k 立体声；SEEKTABLE 存在；MD5 非全零 |
| `temp/flac_frame_probe.py` | FLAC 帧级解析 + CRC-8/CRC-16 校验 + 安全槽位统计 | 93.3%（音乐）/ 0%（k≤2 载体） |
| `temp/flac_rice_probe.py`、`temp/flac_search.py`、`temp/flac_search2.py` | 定位"分区参数就地读取"这一实现细节的过程脚本 | 结论见 §5.3 |

---

## 10. 已否决方案（附理由，避免重复讨论）

| 方案 | 否决理由 |
| :--- | :--- |
| 用 `symphonia` / `matroska-demuxer` / libavformat 做 MKV 解析 | 解码后重打包会改变 Cluster 切分与索引，违反 Δ=0 |
| 用 Block Parity / LSB 替换做 WAV | 率失真严格劣于现成 STC；且极易被卡方/RS 分析检出 |
| 用 QIM 做 WAV 主力 | 追求鲁棒性会牺牲不可见性；本项目定位是"隐写"而非"水印"，鲁棒性不是首要目标 |
| MP3/AAC 内容域（Huffman 符号位） | 需要 1000~1500 行帧级位流定位器，且与 WAV/FLAC 无共用基础设施；列为后续独立阶段 |
| FLAC 直接走 `flacenc` 重编码作为默认 | 编码器指纹暴露，等于自证被处理过；仅保留为显式兜底 |
| 音频槽位用"每 N 采样一槽"（块奇偶） | 与 STC 分组冲突；直接用全部采样做槽位更简单且容量更大 |
| 给 WAV 增加新 chunk 存数据 | 那是结构域已有策略（`riff_chunk`），内容域不应重复 |

---

## 11. 遗留待定项（实现前需要拍板）

1. **FLAC 是否默认开启**：取决于 M0 的 MD5 覆盖率。若语料覆盖率 < 95%，建议默认关闭、标注 experimental，用 `--allow-flac` 显式开启。
2. **`ebml-iterable` 是否进入运行时依赖**：取决于 M0 的内存/耗时数据；若 430 MB 样本遍历 > 5 s 或峰值内存 > 200 MB，改自研扫描器。
3. **音频安全等级换算**：现有 `SafetyPolicy` 以 bpp（bits per pixel）表达，音频需要"每千采样修改数"的等价指标；建议映射为 `changes per 1000 samples`，并在 `StegoCapacityInfo.safety_bpp_limit` 上复用一个明确单位，避免 GUI 显示错位。
4. **是否支持 AIFF**：内核与 WAV 完全同构（大端 PCM），约 150 行，可作为 M5 之后的顺手补充。
