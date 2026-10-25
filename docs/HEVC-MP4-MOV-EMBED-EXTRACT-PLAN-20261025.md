# HEVC MP4/MOV 载体 embed/extract 支持方案（含实测验证）

| 项 | 内容 |
| :--- | :--- |
| **文档编号** | `HEVC-MP4-MOV-EMBED-EXTRACT-PLAN-20261025` |
| **编制日期** | 2026-10-25 |
| **性质** | 方案设计 + 实测验证报告。**未改动主项目任何代码**；所有代码级验证在 `temp/mp4_verify/` 内完成（vendor 副本打补丁实验，原 vendor 仓库与主仓库零改动）。 |
| **适用仓库** | `strhide` 主仓 `rust/src/stego/hevc/` + `strhide-vendor/rust_h265` |
| **关联文档** | `hevc_video_steganography_guide.md`（槽位分级）、`HEVC-STC-AUDIT-20261024.md` §2.3/§3.1（MP4 未实现、`parse_hvcc_spans` 死代码）、`HEVC-VENDORING-DECISION-20261024.md`（vendor 依赖策略） |

---

## 0. 结论摘要

1. **引擎核心已实测支持真实视频内容**：把语料 MP4/MOV 转成 Annex-B 裸流后用**现有 CLI** 跑通了 capacity → embed → extract 全链路——iPhone 4K（3840×2160，I/P/B，78 帧）2048 字节载荷往返字节级一致、**输出文件大小逐字节不变（Δ=0）**、ffmpeg 解码零错误、PSNR 39.2~40.2 dB 且跨 GOP 无衰减；iPhone MOV（CRA/RASL 开放 GOP）同样往返成功（PSNR 33.7 dB）。
2. **MP4/MOV 要做的是"容器层适配"，不是引擎改造**：引擎的嵌入/提取/STC 与容器无关，只需要把"NAL 字节区间从哪来"从 `parse_annex_b_spans` / `parse_heif_targets` 扩展到 MP4 `stbl` 样本表。`bitstream.rs` 里现成但已死的 `parse_hvcc_spans` 正是为此准备（2026-10-24 审计 §3.1 的原话："修 2.3 的 MP4 支持正好需要它"）。
3. **两个 vendor 阻塞点已定位，其一已验证修复**：
   - `slice_segment_header_extension`（小米 14 实拍 1080p 全部中招）：PPS `slice_segment_header_extension_present_flag=1` 时 vendor 整体拒绝。正确语法是 **ue(v) 长度 + u(8) 数据字节**（以 FFmpeg CBS 语法模板为权威；此前"u(1) 标志位"的记忆是错的）。补丁实测让 IDR 第 1 个 tile 完整解出（1020/1020 CTU，21.4 万符号槽）。
   - **tiles entry point 位级错位**（开放问题）：字节边界、上下文初始化、引擎重init 均已验证正确，但 tile 2 子流解码在若干 CTU 后失步，任何字节偏移都解不完整个画面（最好 1858/2040）。WPP 不受影响（真实 HEIC 768/768 子流字节级重放一致）。**这是 tiles 路径的第二个 vendor 缺陷，需深挖**。
4. **帧类型门控是必须做的设计决策**：实测 2 个小米文件 100% 是参考帧（TRAIL_R），严格"只用非参考帧"策略下它们容量为 0；但实测参考帧嵌入的漂移有界（2KB 载荷 PSNR ≥ 33 dB，78 帧无累积趋势）。建议默认门控 + 可选放开。
5. **容器层有三个真实世界约束必须处理**（语料 5/5 全部命中）：**moov 在文件尾部**（不能假定在头部）；**`co64` 与 `stco` 都存在**；**每 AU 单 slice、参数集只在 hvcC 不在码流内**。

---

## 1. 现状：代码级事实

### 1.1 嗅探层已认 MP4，能力层全部拒绝

| 位置 | 现状 |
| :--- | :--- |
| `stego/hevc/sniff.rs:10` | `HevcCarrierKind::Mp4Container` 已声明 |
| `stego/hevc/sniff.rs:57` | `is_mp4_bytes()`：`ftyp/moov/mdat` 首盒 tag 且非 HEIF |
| `stego/hevc/sniff.rs:44` | `sniff_hevc_carrier()` 返回 `Mp4Container` |
| `stego/hevc/engine.rs:116` | `mp4_unsupported()`："MP4/MOV HEVC carriers are not supported yet; remux to HEIF or a raw Annex-B bitstream" |
| `engine.rs:141/197/224/302/795` | 五个专家入口（capacity / dimensions / capacity_info / embed / extract）对 MP4 一律显式报错 |
| `engine.rs:1048` | `record_carrier_state` 的 `_ =>` 臂："Carrier format not supported yet" |
| `stego/mod.rs:128/157` | 统一入口只路由 HEIF 与 Annex-B；MP4 落入通用错误 "requires a PNG, JPEG, HEIF, or HEVC carrier"（实测 CLI 确认，非 panic） |

即：**嗅探层对外宣称支持，能力层不兑现**——2026-10-24 审计 §2.3 的原始结论，至今未变。

### 1.2 引擎与容器的耦合面（改这里就能支持 MP4）

引擎的数据流是：`sniff_hevc_carrier` → `record_carrier_state`（容器解析 → NAL 区间 → 逐 slice `decode_nal_with_observer` 录制 journal + 槽池）→ STC 求解 → 逐 substream CABAC 重编码原位回写。**除"NAL 区间从哪来"之外，全部与容器无关**：

- `record_carrier_state`（`engine.rs:945`）：HEIF 臂调 `parse_heif_targets`，Annex-B 臂调 `parse_annex_b_spans`，`_ =>` 拒绝。MP4 只需新增第三臂。
- `DigestInputs`（`engine.rs:936`）：封面摘要的来源。HEIF 臂哈希参数集内容，Annex-B 臂走 `compute_hevc_cover_digest`。MP4 需要第三种变体（建议与 HEIF 相同：哈希 hvcC 参数集内容——嵌入不碰它们，两端一致）。
- `SliceContext.carrier_span`：回写目标。MP4 场景下就是 mdat 内该 NAL 的字节区间；**引擎保证 Δ=0，样本长度不变，因此 `stsz`/`stco` 无需重写**。
- 其余（`slot_positions` Weyl 置换、STC、`encode_substream`、3a/3b 轮次、EPB 窗口比对）零改动。

---

## 2. 容器层实测普查（5/5 语料文件）

用 `temp/mp4_verify/mp4walk.py`（独立 ISO-BMFF 走查器，与项目代码无关）对 `temp/testhevc/` 下全部视频文件做了完整解析：

| 文件 | 大小 | ftyp brand | sample entry | 样本数 | chunk 表 | NAL 类型普查 | 非参考帧样本 |
| :--- | ---: | :--- | :--- | ---: | :--- | :--- | ---: |
| VID_20250228_120825_C.mp4 | 12.2 MB | isom | **hev1** | 228 | stco | TRAIL_R 113、TRAIL_N 112、IDR 3、SEI 456 | 112（49%） |
| VID_20261002_154545.mp4 | 18.0 MB | mp42 | hvc1 | 344 | **co64** | TRAIL_R 338、IDR 6 | **0** |
| VID_20261007_203536.mp4 | 39.9 MB | mp42 | hvc1 | 816 | **co64** | TRAIL_R 802、IDR 14 | **0** |
| IMG_0033.MOV | 10.4 MB | **qt** | hvc1 | 385 | stco | TRAIL_R 180、TSA_N 180、RASL_N 12、CRA 6、RASL_R 6、IDR 1、SEI 7 | 192（50%） |
| IMG_0892.MOV | 11.9 MB | **qt** | hvc1 | 467 | stco | TRAIL_R 219、TSA_N 219、RASL_N 14、CRA 7、RASL_R 7、IDR 1、SEI 8 | 233（50%） |

**五个必须处理的真实世界约束**：

1. **`moov` 全在文件尾部**（5/5：VID_20250228 的 moov 在 offset 12198057/12207502，即最后 9 KB）。box 走查必须扫全文件，不能假定 moov 在头部；这也意味着**每次 embed/extract 都要顺序读全文件**（HEIF 的 meta 在头部，成本不同）。
2. **`co64` 与 `stco` 都存在**（大文件用 co64），样本偏移计算两者都要支持。
3. **每 AU 恰好 1 个 VCL slice**（5/5：`vcl_slices_per_sample: {1: N}`），1080p/4K 单 slice 封装。多 slice AU 的代码路径存在但语料未覆盖。
4. **参数集只在 `hvcC`，样本内零 in-band 参数集**（5/5 `inband_param_sets: 0`）——包括 brand 为 `hvc1` 的文件（规范上 hvc1 要求 in-band，真实文件不遵守）。解码器喂 hvcC 参数集即可。
5. **MOV 与 MP4 同构**（多个 `wide` 盒 + qt brand），`stbl` 结构完全一致；ftyp brand 均为 isom/mp42/qt，**都不会被 `is_heif_bytes` 误判**，统一入口路由顺序安全。

`hvcC` 解析（`lengthSizeMinusOne`、VPS/SPS/PPS 数组）可整段复用 `heif_boxes.rs:362 parse_hvcc_from_iprp` 的已验证逻辑（含 ipma 关联选择）。

---

## 3. 引擎核心实测验证（现有 CLI，零代码改动）

方法：`ffmpeg -i <语料> -t 3 -c copy -f hevc -bsf:v hevc_mp4toannexb` 得到 Annex-B 裸流，直接用 `rust/target/release/strhide.exe` 跑既有入口。产物在 `temp/mp4_verify/`。

### 3.1 iPhone 4K（VID_20250228 前 3 秒，3840×2160，I/P/B 金字塔）

| 指标 | 实测值 |
| :--- | :--- |
| 解码录制 | 78/78 slice 成功（`decode_nal_with_observer` 对 P/B 帧完全正常） |
| 原始符号槽 | 3,621,881（诊断程序统计） |
| 引擎可用槽 | **2,780,623**（差集 = DC 不建槽 + 多子流 EPB 排除，均为既有设计） |
| 最大原始载荷 | 169.7 KiB（high 档推荐 49.2 KiB） |
| **embed 2048 B** | 成功，**输出 4251466 B = 输入 4251466 B（Δ=0）**，耗时 29.58 s |
| **extract** | 2048 B 字节级一致 |
| ffmpeg 解码 | 零错误零告警 |
| PSNR（逐帧） | 39.2~40.2 dB，78 帧**无衰减趋势**（帧 1: 39.66 → 帧 78: 40.16） |

### 3.2 iPhone MOV 开放 GOP（IMG_0033 前 3 秒，CRA/RASL）

可用槽 3,795,294（最大载荷 231.6 KiB）；2048 B 往返字节级一致；ffmpeg 解码干净；平均 PSNR 33.67 dB（高于 30 dB 门限；该片段内容更暗，翻转代价天然更高）。

### 3.3 小米 14 1080p60（VID_20261002 前 3 秒，100% TRAIL_R）——被 vendor 阻塞

`capacity` 报 **0 槽位**。根因不是引擎：181 个 slice 全部报 `Unsupported("slice_segment_header_extension not supported")`。详见 §4。

**结论：引擎核心对视频内容（P/B 帧、多 GOP、开放 GOP、WPP、4K）工作正常；MP4/MOV 支持的剩余工作 = 容器适配 + 2 个 vendor 缺陷 + 帧类型策略。**

---

## 4. 两个 vendor 阻塞点（已定位，附证据）

### 4.1 阻塞一：`slice_segment_header_extension`（已实验性修复，小米/安卓文件全中招）

**现象**：PPS `slice_segment_header_extension_present_flag=1` 时，vendor `slice.rs:613` 无条件 `Unsupported` 拒绝整个载体。独立 PPS 解析器（`temp/mp4_verify/ppscheck.py`，按规范逐字段实现）确认：seg_refonly 的 PPS 该标志**确实为 1**（且 tiles=1、WPP=0、sign_data_hiding=0）——不是 vendor 解析错误。

**规范事实（关键纠偏）**：该扩展的数据是 **u(8) 字节**而非 u(1) 标志位。FFmpeg CBS 语法模板（`libavcodec/cbs_h265_syntax_template.c`）：

```c
if (pps->slice_segment_header_extension_present_flag) {
    ue(slice_segment_header_extension_length, 0, 256);
    for (i = 0; i < slice_segment_header_extension_length; i++)
        us(8, slice_segment_header_extension_data_byte[i], 0x00, 0xff, 1, i);
}
CHECK(FUNC(byte_alignment)(ctx, rw));
```

**比特流地面真值**（`temp/mp4_verify/slicewalk.py` 逐位走查首个 IDR slice header）：扩展长度 = 6，随后 **6 字节 0xFF**（bit 58–105），`byte_alignment_one_bit` 在 bit 106，其后 5 个 0 到字节边界——与 u(8) 解释完全吻合（按错误的 u(1) 解释会对不齐）。

**实验性补丁**（`temp/mp4_verify/rust_h265_patched`，vendor 的临时副本，**未动原 vendor**）：把拒绝改为"读 ue 长度 + 跳过 length 个 u(8) 字节"。结果：首个 IDR slice 解码成功，**tile 0 完整解出 1020/1020 CTU、214,742 个符号槽**；`slice_segment_header_extension` 位于 slice header 内（CABAC 数据之前），引擎原样透传 header 字节，不受影响。

### 4.2 阻塞二：tiles entry point 子流位级失步（**已大幅定位，2026-10-25 晚更新**）

补丁后 IDR 只解 1027/2040 CTU：tile 0（CTU 0–1019）完美，tile 边界跳转正确发生在 ctb_ts=1020（rs=30，即 30 列处，2 个垂直 tile），随后若干 CTU 即 terminate。

**当日晚间的准确定位（完整证据链）**：

1. **字节边界正确（码流合规）**：插桩打印引擎自然结束位置 `pcm_pos`，与 entry point 目标**逐字节一致**（新小米文件：pcm_pos=82171 = 14+82157；旧文件：pcm_pos=141817 = 14+141803）。规范原文（T-REC-H.265 §7.3.8.1）确认偏移为累计式、byte 0 = slice data 起点、EPB 计入——vendor 的偏移数学无误。
2. **bug #2（已修）**：`sao.rs` 的 SAO merge 标志可用性只查同 slice、**漏查同 tile**（代码注释写了"same slice and same tile"但实现没做）。规范 §7.3.8.3 明确 `sao_merge_left_flag` 仅在 `leftCtbInSliceSeg && leftCtbInTile` 都满足时解析。tile 1 首 CTU 的左邻在同 slice 不同 tile → vendor 多消费 1 个 bin → 立即失步。**补丁（加 `tab_tile_id` 相等判断）实测生效**：新文件 1021→1107 CTU、旧文件 1027→1082。
3. **bug #3（开放）**：SAO 修复后 tile 1 首 CTU 仍多消费约 176 bit。以 filmcraft 为 oracle 做逐 CTU 位置对比：**tile 0 的 1020 个 CTU 与 filmcraft 消耗完全吻合，tile 1 从第一个 CTU 起即解析垃圾**。已排除：PCM 误触发（全程无 pos 回跳）、字节偏移（±24 全扫无解）、上下文继承（更差：1038）、引擎重init（与 slice 起始同构）、帧内可用性（cu_tree 有 tile 检查）、merge 候选（有 tile 检查，且 merge_idx 的 cMax 固定不受候选数影响）。**未定位，需 bin 级 diff 或换解码器（见 §11）。**

**vendor 补丁状态**：两个补丁（扩展语法解析 + SAO tile 检查）在 vendor 临时副本上通过**全部 166 项单测 + 2 doctest**，安全可提议；补丁在 `temp/mp4_verify/rust_h265_patched/`，**原 vendor 仓库与主仓库零改动**。

---

## 5. 帧类型门控策略（核心设计决策）

### 5.1 事实

- HEVC 的 VCL NAL 分参考（`TRAIL_R/TSA_R/STSA_R/RADL_R/RASL_R` + IRAP 16–21）与非参考（`TRAIL_N/TSA_N/STSA_N/RADL_N/RASL_N` = 0/2/4/6/8）两类。
- 非参考帧不装入 DPB：翻转其系数**零时域漂移**；且帧间块的预测基准来自前一帧，连帧内空域漂移都不存在（`hevc_video_steganography_guide.md` §2.1.2 的黄金结论）。
- 参考帧翻转会向后继帧传导。**实测（本方案 §3.1）**：2 KB 载荷下 78 帧 PSNR 39.2~40.2 dB 且**无累积趋势**——幅值感知代价模型（Δpeak ≤ 32）把单次翻转压得很小，短 GOP 内传导有界。但这是小载荷数据，50% 容量下的传导未测。
- **两个小米文件 100% TRAIL_R**（§2）：严格门控下容量为 0。MOV 文件的非参考帧是 **TSA_N**（180+12 个）——门控集合必须含 type 2。

### 5.2 建议策略

| 场景 | 策略 |
| :--- | :--- |
| 静态单图载体（HEIF 容器；或 Annex-B/MP4 中全部 VCL 均为 IRAP） | **不门控**（无时间轴，IDR 不被任何后续帧参考） |
| 视频载体（存在非 IRAP 的 VCL NAL） | **默认只录 {0,2,4,6,8} 非参考帧**——零时域漂移保证 |
| 视频载体 + 用户显式放开 | 允许参考帧入池；代价模型天然限幅；文档明示漂移风险 |

实现要点：
- 门控判据（"本流是否存在非 IRAP VCL"）是**无状态、确定性**的，embed/extract 两端天然一致，无需进 wire 头。
- 是否放开参考帧影响槽池构成，属于**格式身份**性质（与 `stc_h`/`stc_u` 同级：两端必须一致、头部不携带）。建议加 `HevcFormatProfile::allow_reference_frames: bool`（默认 false），私有 dialect 可改。
- Annex-B 路径同步应用同一判据（保持 Annex-B 与 MP4 语义一致）；单 IDR 的 Annex-B 静态图不受影响（全 IRAP → 不门控）。

---

## 6. 实现方案（代码级）

### 6.1 新增 `rust/src/stego/hevc/mp4_boxes.rs`（约 350–450 行）

风格照 `heif_boxes.rs`：零 `unwrap/expect/panic`，全部边界检查，错误走 `HevcError`。

```rust
pub struct Mp4HevcTarget<'a> {
    /// hvcC 中的 VPS/SPS/PPS（无长度前缀）。
    pub parameter_sets: Vec<&'a [u8]>,
    /// NAL 长度前缀字节数（通常 4）。
    pub length_size: usize,
    /// 文件中所有 VCL NAL 的字节区间（不含长度前缀），按样本顺序 = 解码顺序。
    pub slice_spans: Vec<PhysicalNalSpan>,   // 复用 heif_boxes 的类型
}

pub fn parse_mp4_targets(bytes: &[u8]) -> Result<Mp4HevcTarget<'_>>;
```

内部步骤：
1. **全文件 box 走查**（支持 32/64 位盒头、`size==0` 到尾），收集 `moov`——**必须扫到文件尾**（§2 约束 1）。
2. `moov/trak` 中找 `hdlr` handler_type=`vide` 的轨（多个轨时取第一个，确定性）。
3. `trak/mdia/minf/stbl/stsd` → sample entry `hvc1`/`hev1` → 子盒 `hvcC`：`lengthSizeMinusOne` + 参数集数组（复用 `parse_hvcc_from_iprp` 的核心，建议抽成共享函数）。
4. `stbl/stsz`（`sample_size==0` 逐样本 / 固定尺寸两种形态）、`stco`/`co64`、`stsc` → 逐样本绝对字节区间（`sample_offsets` 逻辑本次已在 Python 侧完整实现并通过 5 文件验证，可直译）。
5. 每个样本按 `length_size` 拆 NAL（**复用现成的 `bitstream.rs:93 parse_hvcc_spans`**），收集 `nal_type<=31` 的 VCL 区间。
6. 拒绝清单（显式报错，不静默）：找不到 moov/vide 轨/hvcC/stbl、样本区间越界、**碎片化 MP4（存在 `moof`/`traf`/`trun`）**、加密轨（`sinf`/`schm` 保护）。

### 6.2 `engine.rs` 改动（约 +80 行）

1. `record_carrier_state` 新增 `HevcCarrierKind::Mp4Container` 臂：喂 hvcC 参数集给 `Decoder`，再按 `slice_spans` 顺序逐 slice `decode_nal_with_observer`（与 HEIF 臂同构，只是区间来源不同）；返回 `DigestInputs::Mp4 { parameter_sets }`。
2. `derive_carrier_digest` 新增 `Mp4` 臂：与 HEIF 臂相同——哈希 `cover_salt ‖ 参数集个数 ‖ 各参数集`（嵌入不碰 moov/hvcC，两端一致）。
3. 删除五个入口的 `mp4_unsupported()` 分支（`engine.rs:141/197/224/302/795`）。
4. `extract_hevc_dimensions` 增加 MP4 臂：从 hvcC 参数集找 SPS 解析 `cropped_width/height`。
5. 帧类型门控（§5.2）：`record_carrier_state` 内按"全 IRAP → 不门控，否则只收 {0,2,4,6,8}"过滤 VCL 区间；`HevcFormatProfile` 加 `allow_reference_frames`（默认 false，`DEFAULT_HEVC_FORMAT` 同步）。
6. `record_carrier_state` 的 `_ =>` 臂保留为防御（理论上三种 kind 已全覆盖）。

### 6.3 `stego/mod.rs` 路由（约 +15 行）

`embed_carrier_with_profile` / `extract_carrier_with_profile` / `probe_carrier_capacity_with_profile` 三处，在 HEIF 分支之后、Annex-B 分支之侧，增加 `hevc::sniff::is_mp4_bytes(carrier_bytes)` 分支调对应 `hevc::*` 入口。错误文案同步加 MP4/MOV。

### 6.4 vendor 改动（两个，均需先过 vendor CI 四门禁）

1. **阻塞一修复**（补丁已在 temp 验证）：`slice.rs` 的 `slice_segment_header_extension_present_flag` 分支从拒绝改为解析跳过（ue 长度 + u(8) 字节），带单测（可用语料切出的真实 NAL）。
2. **阻塞二**：tiles entry point 位级失步——按 §4.2 的下一步定位后修复；修复前 MP4 路径应**显式拒绝 tiles 文件**（诚实失败），先覆盖 WPP/无 tiles 文件。
3. 依赖联动：vendor 提交 + 打 tag（如 `v1-20261026`）→ 主仓 `Cargo.toml` 升 tag → `cargo update -p rust_h265`；或先用 `[patch]` 本地联调（见 `hevc_wpp_cost_impl_checklist_20261025.md` §1.7）。

---

## 7. 边界、风险与性能

| 项 | 结论 |
| :--- | :--- |
| **碎片化 MP4（moof/trun/sidx）** | 语料 0/5；实现时显式检测并拒绝（样本偏移要走 `trun` data_offset，工作量另计） |
| **加密/DRM MP4** | 检测 `sinf`/保护 scheme 并拒绝 |
| **多视频轨** | 取第一个 `vide` + `hvc1/hev1` 轨；确定性，两端一致 |
| **码流内多处激活不同 SPS/PPS** | hvcC 只有一套参数集；本方案"先喂全部参数集再喂 slice"对单参数集流正确（语料 5/5 如此）；中途换参的流需记录激活时间点（罕见，记为限制） |
| **Δ=0 保证** | 引擎既有保证；若某 slice 重编码长度变化，引擎直接报错而非写坏容器——MP4 的 `stsz`/`stco` 因此永远有效 |
| **性能** | 4K 实测 ~0.38 s/帧（29.6 s/78 帧）；1 分钟 1080p30（约 1800 帧）预估 10–20 分钟（单线程）。引擎目前单线程；`rayon` 已是依赖，按 slice 并行录制/重编码是后续优化（embed 的 STC 求解需全局槽序，可保持串行） |
| **门控后的容量** | iPhone 4K 严格门控（仅 TRAIL_N）预计损失约一半槽位（49% 帧为非参考），仍有 ~80 KiB 级安全容量；小米文件严格门控为 0（需 opt-in） |
| **与结构域的关系** | 结构域 `Mp4Adapter`（`write/read`，box_uuid/eof）已支持 MP4，与本次内容域扩展正交，互不影响 |

---

## 8. 验收方案

1. **合成 fixture**（进常规套件）：手工构造最小 MP4（ftyp+moov[trak[mdia[minf[stbl[stsd[hvc1[hvcC]] stsz stco stsc]]]]]+mdat），参数集与 slice 用语料真实字节；断言 embed→extract 往返、`stsz/stco` 不变、文件大小不变。
2. **本地语料批测**（`rust/tests/local/local_media.rs` 新增 `local_hevc_mp4_*`）：5 个真实文件逐个 probe→embed 2 KB→extract→字节比对；`ffmpeg -v error` 解码零错误；PSNR ≥ 30 dB（参考帧放开时 ≥ 30，严格门控时 ≥ 40）。
3. **帧类型一致性测试**：构造只含 IRAP 的 MP4（静态图）不断录；含 TRAIL_R+TRAIL_N 的视频断言只录 _N。
4. **vendor 单测**：`slice_segment_header_extension` 长度 0/6/256 三态；tiles 修复后补 entry point 回归。
5. **质量门禁**：`cargo fmt --check`、`cargo clippy --all-targets -D warnings`、`cargo test`（常规 + local）全绿；vendor 侧 CI 四项全绿后才升 tag。
6. **`scan` 联动**（远期）：`analysis` 目前只对 PNG/JPEG 做内容域盲检；MP4 HEVC 通道上线后应同步扩展，避免"自己的隐写自己的扫描器发现不了"。

---

## 9. 验证产物索引（temp/mp4_verify/，可复现）

| 文件 | 说明 |
| :--- | :--- |
| `mp4walk.py` / `mp4_analysis.json` | ISO-BMFF 全盒走查 + 样本表 + NAL 普查（5 文件） |
| `ppscheck.py` | 独立 PPS 解析器（规范字段序），确认 `slice_segment_header_extension_present_flag=1` |
| `slicewalk.py` | slice header 逐位走查器（SPS/PPS/slice），地面真值 |
| `rustdiag/` | 独立诊断 crate（path 依赖 vendor），统计逐 slice 解码结果与符号槽 |
| `rust_h265_patched/` | vendor 临时副本（扩展语法补丁 + 调试插桩）；**原 vendor 仓库零改动** |
| `seg_*.hevc` / `stego_*.hevc` / `psnr.log` | Annex-B 片段、隐写产物、逐帧 PSNR |
| `payload.bin` / `extracted*.bin` | 往返载荷（2048 B，`cmp` 一致） |

复现要点：`ffmpeg -i <mp4/mov> -t 3 -c copy -f hevc -bsf:v hevc_mp4toannexb seg.hevc`，然后 `strhide capacity|embed|extract seg.hevc -p <pw>`。

---

## 10. 排期建议（工作量预估）

| 阶段 | 内容 | 预估 |
| :--- | :--- | :--- |
| A | `mp4_boxes.rs` + engine 三臂 + 路由 + 门控（不含 tiles 文件：显式拒绝） | 3–4 天 |
| B | vendor 阻塞一修复 + 单测 + tag 联动 | 0.5–1 天 |
| C | 合成 fixture + 5 文件本地批测 + ffmpeg 外部验证 | 1–2 天 |
| D | vendor 阻塞二（tiles entry point）定位与修复 | **未知**（位级失步，可能 1–3 天，也可能需要对照 ffmpeg 逐状态排查） |
| E | 性能并行化（rayon 按 slice）、`scan` 扩展 | 远期 |

**建议先做 A+B+C**：覆盖 iPhone/无 tiles 文件（语料 3/5 含全部 MOV 与 4K MP4），tiles 文件（小米）在 D 完成后解锁。

---

## 11. 路线选择与决策记录（2026-10-25 晚）

### 11.1 关键新证据：filmcraft 解码器全量通过

`temp/github/filmcraft`（storytold/filmcraft v0.12.0，**MIT OR Apache-2.0 与 strhide 兼容**，纯 Rust clean-room HEVC 解码器）的 `crates/hevc` 实测（`temp/mp4_verify/filmdiag/`）：

| 载体 | vendor（打 2 补丁后） | filmcraft |
| :--- | :--- | :--- |
| iPhone 4K（I/P/B，78 帧） | ✅ 78/78 slice | ✅ 76 帧 |
| iPhone MOV 开放 GOP（CRA/RASL） | ✅ | ✅ 181 帧 |
| 小米 1080p60 tiles（seg_refonly） | ❌ 1082/2040 CTU | ✅ 168 帧 |
| 小米新拍 tiles（seg_xiaomi_new，2026-10-02 实拍） | ❌ 1107/2040 CTU | ✅ 104 帧 |

**结论：小米码流完全合规（规范原文 + filmcraft + ffmpeg 三方印证），问题是 vendor 解码器能力缺陷；filmcraft 既是可靠参考，也是潜在替代底座。**

### 11.2 tiles 文件的四条路线（需产品决策）

| 路线 | 内容 | 工作量 | 风险 | 评价 |
| :--- | :--- | :--- | :--- | :--- |
| **A. 继续修 vendor** | 已修 2 bug（166 测试通过）；第 3 个未定位 | **不可控**（可能 1 小时也可能数天，不能排除第 4、第 5 个） | 高（连续 3 个 bug 类，调试无底洞） | 不推荐作主线 |
| **B. 移植 observer 到 filmcraft** | 移植录制钩子层（CabacObserver trait + substream 边界 + 符号槽 + level 回填，约 300–500 行）；其 `slice`/`params`/`SliceDecoder` 已 pub，tile/WPP 跳转用自然延续（比 entry point 跳转更稳） | **可预估**（2–5 天含验证：字节级重放、全量矩阵、本地语料） | 中（年轻解码器需建立信任；但实测 4/4、spec 干净、声明支持 tiles/WPP/SDH/依赖 slice） | **推荐**：一次性清偿 vendor 全部 tiles/WPP/SDH 债务 |
| **C. kvazaar 方案 D** | 重编码 + 编码环路内嵌入 | 1–1.5 周 + ADR | 改变产品语义（重编码/代际损失/C 编译依赖/MP4 需重新封装） | 不作为现有文件嵌入路径；仅留作"新内容"可选 feature |
| **D. NAL 级通道降级** | 对 CABAC 解不了的文件用 SEI/trailing 嵌入（`hevc_video_steganography_guide.md` §2.5 流派五，无需解码残差） | ~500–800 行（SEI 构建/解析 + stsz/stco 重写） | 中（Δ≠0 容器表重写；SEI 隐藏性弱于 CABAC 域） | 可作为 B 之前的覆盖面过渡 |

### 11.3 建议决策

1. **立即实施**（不依赖 tiles 修复）：MP4 容器适配 + 帧类型门控，覆盖 iPhone/MOV/无 tiles 文件（语料 3/5；iPhone 是现实世界 HEVC MP4 最大来源）。vendor 合并补丁 1+2（已验证 + 166 测试通过 + 规范原文背书）。
2. **tiles 文件走 B**（filmcraft 移植）作为独立里程碑；若需更快覆盖面，先"对仍失败的文件显式拒绝"（诚实失败）+ D 通道过渡。
3. **C 不排期**，除非接受"重编码"产品语义并写 ADR。

> 止损记录：本次为定位 tiles 第 3 个 bug 投入了过量调试（vendor 插桩 + 逐 CTU 对比 filmcraft + 规范原文核对 + Android 源码查找）。上表即为止损后的决策依据——**问题不在于"能不能修"，而在于"继续修 vendor 的边际成本已超过换底座的一次性成本"**。
