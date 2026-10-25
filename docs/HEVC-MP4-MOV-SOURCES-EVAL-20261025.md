# HEVC MP4/MOV 新下载源码实证评估与决策备忘

| 项 | 内容 |
| :--- | :--- |
| **文档编号** | `HEVC-MP4-MOV-SOURCES-EVAL-20261025` |
| **编制日期** | 2026-10-25 |
| **性质** | 对 `temp/github/` 新下载 MP4 相关源码的**源码级核查 + 语料级实证**评估报告，附路线决策建议。**未改动主仓与 vendor 任何代码**；全部验证在 `temp/mp4_verify/` 下 4 个独立冒烟 crate 内完成。 |
| **关联文档** | `HEVC-MP4-MOV-EMBED-EXTRACT-PLAN-20261025.md`（前序方案+实测，下称"文档1"）、`hevc_mp4_mov_verification_and_action_plan.md`（逐项核验+容器实现代码，下称"文档2"） |
| **输入变更** | 2026-10-25 新下载：`mp4-rust` `mp4box` `mp4parse-rust` `oxideav-mp4` `re_mp4` `rusty_h265` `filmcraft` `libde265` `openHEVC` `x265` `go-h265` `scuffle-h265` `FFmpeg` `gpac` `digital_video_introduction` + T-REC-H.265 全文文本 |

---

## 0. 结论摘要

1. **容器层：`re_mp4`（rerun.io，MIT，v0.5.1）实测 8/8 语料全对**，是三个可行选项中 API 最贴合 strhide 的（`Mp4::read_bytes(&[u8])` 内存直读、`Track::raw_codec_config` 给原始 hvcC 字节、`Sample::byte_range` 给精确样本区间）。**唯一硬伤是 4 处潜在 panic**（含 1 处 `panic!` + 3 处索引越界），主仓 release profile 为 `panic="abort"`，对不可信载体即崩溃——需 fork 修复（约 50 行）后使用。
2. **容器层出局者**：`mp4-rust` 静默丢弃 hvc1 条目的 hvcC（语料 2/5 拿不到参数集，实测复现）；`mp4box` 的 hvcC 解码器只产出显示文本、不暴露参数集结构；`oxideav-mp4` 拖入整个 oxideav-core 框架+aes/cbc/ctr，杀鸡用牛刀；`mp4parse-rust` 能力最强但 MPL-2.0 与 Apache-2.0 主仓有许可摩擦。
3. **解码器层：`rusty_h265`（Remade-With-Rust / Mata Network，Apache-2.0，v0.6.2）实测 5/5 语料零错误**，包括两个 vendor 完全卡死的小米 tiles 文件（vendor 分别卡在 1082/2040、1107/2040 CTU；rusty_h265 解出 180/120 帧）。其源码已完整实现 `slice_segment_header_extension`（ue 长度+u(8) 字节，正是 vendor 阻塞一）、SDH、依赖 slice、tiles、WPP、entry point 偏移。
4. **tiles 路线决策修正**：文档1 §11.2 路线 B（停修 vendor、换底座）判断正确，但底座候选应从 filmcraft 一个扩充为 **rusty_h265（主线）+ filmcraft（备选）**：rusty_h265 实证证据链更硬（147/147 JCT-VC 一致性字节级一致 + 6183/6183 解码哈希 SEI + 本仓 5/5 语料），且许可与主仓完全一致、核心 `#![forbid(unsafe_code)]`、`pub mod cabac/slice/ctu/ps` 全公开（observer 移植面干净）。
5. **三方案共同缺口**：均不支持 `stz2`（紧凑样本尺寸盒）。文档1 §6.1 拒绝清单需补记；实现时对 stz2 文件显式拒绝（诚实失败）。

---

## 1. 验证方法与产物索引

| 冒烟 crate | 被测对象 | 验证内容 | 结果 |
| :--- | :--- | :--- | :--- |
| `temp/mp4_verify/mp4smoke/` | mp4-rust 0.14.0 | 8 语料样本区间+hvcC，与 `mp4walk.py` 真值比对 | 6/8（hvc1 文件 hvcC 丢失） |
| `temp/mp4_verify/remsmoke/` | re_mp4 0.5.1 | 同上 + 区间单调性/越界/hvcC 参数集数组 | **8/8 全对** |
| `temp/mp4_verify/boxsmoke/` | mp4box 0.14.0 | 同上（轨道级） | 8/8（区间），hvcC 仅文本 |
| `temp/mp4_verify/rh265smoke/` | rusty_h265 0.6.2 | 5 个 Annex-B 切片全量 NAL 推流解码 | **5/5 零错误** |

真值基准：`temp/mp4_verify/mp4walk.py` 产出的 `mp4_analysis.json`（VID_20261002 首样本 offset=42799、size=162692、NAL len=162688、type=19、392 样本、7 chunk、3 段 stsc）。

语料（`temp/testhevc/`）：iPhone 4K hev1（stco，moov@尾）、VID_20261002/20261007/20261025（hvc1，**co64**，7 chunk 3 段 stsc，moov@尾）、IMG_0033/0892（**MOV qt 品牌**，wide 盒，mdat 在前）、SDR/HDR Sample（hev1，hvcC 内含 SEI NAL）。

复现：`cd temp/mp4_verify/<crate> && cargo run --release`。

---

## 2. 容器 crate 逐项结论

### 2.1 mp4-rust（alfg）——❌ 出局

- 实测：hev1 文件（iPhone 4K、SDR/HDR）正常——`off[1]=44`（ftyp 28 + free 8 + mdat 头 8，初查曾疑为 +12 偏差，逐盒核对后确认**正确**）；VID_20261002 的 co64+多 chunk+多段 stsc 展开首样本 42799 与真值一致。
- **硬伤（源码级）**：`stsd.rs` 的 `StsdBox::read_box` 只读**第一个** sample entry（`// XXX entry_count` 注释即承认），且只映射 `BoxType::Hev1Box`——**hvc1 落入 `_ => {}` 被静默跳过**。语料 2/5（小米全部文件）hvcC 丢失，实测复现"no hev1 entry in stsd"。
- 其他：Read+Seek 设计（`&[u8]` 需包 Cursor）；依赖 thiserror/byteorder/bytes/num-rational/serde/serde_json（偏重）；`to_json` 有 unwrap（不在读路径）。

### 2.2 re_mp4（rerun.io fork）——✅ 首选（需 fork 修 panic）

**能力（实测 8/8）**：

- `Mp4::read_bytes(&[u8])` 内存直读，无需 Cursor；moov 在文件尾（全部语料）、co64/stco、stsc 多段展开、MOV 多轨（正确区分 vide/soun/meta）全部正确；样本区间单调、在文件内、无重叠。
- `Track::raw_codec_config(mp4) -> Option<Vec<u8>>`：hvc1 与 hev1 **均**返回原始 hvcC 字节（小米文件解出 VPS 23 / SPS 39 / PPS 10 数组；SDR/HDR 额外解出 type 39 SEI 数组）——参数集解析可直接复用主仓已验证的 hvcC 逻辑。
- `Sample { offset, size, is_sync }` + `byte_range()`：即 `SliceContext.carrier_span` 回写目标。
- 碎片化可检测：`mp4.moofs: Vec<MoofBox>` 为公开字段（+ `moov.mvex`），strhide 显式拒绝即可。
- 加密轨：`encv` 等落入 `StsdBoxContent::Unknown` → `raw_codec_config` 返回 `None` → 天然拒绝路径。

**风险（源码级，fork 必修）**：

| 位置 | 问题 |
| :--- | :--- |
| `reader.rs:325` | `panic!("stbl missing stco/co64")`——stbl 两盒俱缺时触发 |
| `reader.rs:318/322` | `stco.entries[chunk_index-1]` / `co64.entries[...]` 索引越界——stsc 引用超出 stco  chunk 数时触发 |
| `reader.rs:330-332` | `stsz.sample_sizes[sample_index]` 索引越界——stsc/stsz 计数不一致时触发 |
| `reader.rs:652` | `unreachable!()`——仅当 trak 缺失，正常流程不可达 |

修复方式：4 处全部改为 `Result` 错误返回 + 边界检查，预计 ≤50 行。另注意两点（非阻塞）：stsd 同样只读第一个 entry（各语料视频轨首条目即视频条目，可接受，文档需注明）；CTS 有按最小值归一化行为（本方案不用时间戳，无影响）。

**依赖**：byteorder / num-rational / serde / serde_json / thiserror（MIT，v0.5.1，MSRV 1.92，rerun.io 出品，fork 自 alfg/mp4-rust 并合入 gpac/mp4box.js 移植）。

### 2.3 mp4box（alfg 新作，v0.14.0）——❌ 出局

- 实测：8/8 区间正确（与 re_mp4 逐字节一致），且支持 fMP4/DASH/CMAF 碎片展开、非破坏性 box 编辑（size/chunk-offset 自动 fixup）。
- **出局原因（源码级）**：`registry/decoders.rs:1298` 的 `HvccDecoder` 只把 hvcC 解成**展示用文本**（"configurationVersion=... profile_space=..."），不暴露参数集数组——strhide 需要的是 VPS/SPS/PPS 原始字节。加之 anyhow 错误模型 + `samples.rs`/`decoders.rs` 合计 19 处 unwrap/expect，与主仓零 panic 标准不符。

### 2.4 mp4parse-rust（Mozilla）——⚠️ 能力最强，许可摩擦

Firefox 出厂级解析器，能力覆盖（stz2、碎片、加密、宽盒）与模糊测试强度均为业界标杆。但 **MPL-2.0**：合入 Apache-2.0 主仓需保留 MPL 文件头、源码提供义务与许可声明隔离，治理成本与"临时工具"定位不匹配。仅在团队决定接受 MPL 兼容策略时重新评估。

### 2.5 oxideav-mp4——❌ 框架过重

`Cargo.toml` 依赖 `oxideav-core` 框架 + aes/cbc/ctr（CENC 密码驱动），API 围绕 `RuntimeContext` demuxer/muxer 编排（`open_demuxer` → `next_packet`）。strhide 只需要"只读样本区间 + 原始 hvcC"，引入整个框架属过度耦合。注：主仓已在使用 `mcxiaoke/oxideav-h265` fork，作者对 oxideav 生态有积累，但此 crate 的抽象层级与需求不匹配。

### 2.6 其他下载物定位

| 仓库 | 定位 |
| :--- | :--- |
| `FFmpeg` / `gpac` | **oracle 保留**：gpac 是 ISOBMFF 最全实现，FFmpeg 是容器+码流行为权威；验证自写解析器/边界行为时对照 |
| `x265` / `libde265` / `openHEVC` | C 实现，作行为参考（libde265 是 JCT-VC 字节级一致的参照解码器） |
| `go-h265` | libde265 的 Go 绑定——纯 Rust 项目不适用 |
| `scuffle-h265` | 仅 header 解析器（非完整解码），且位于 AGPL monorepo——不适用 |
| `digital_video_introduction` | 视频技术教材（BSD-3），团队学习材料 |
| `T-REC-H.265-202108-S!!PDF-E.txt` | 规范全文，争议字段的最终仲裁（本备忘 §3 引用） |

---

## 3. 解码器：rusty_h265 实证评估（tiles 路线的新证据）

### 3.1 语料级实测（rh265smoke，Annex-B 全 NAL 推流）

| 切片 | NAL 数 | 推流错误 | 解出帧 | vendor 对照（文档1） |
| :--- | ---: | ---: | ---: | :--- |
| `seg_xiaomi_new.hevc`（小米新拍 tiles） | 130 | **0** | 120 | ❌ 1107/2040 CTU 即失步 |
| `seg_refonly.hevc`（小米 1080p60 tiles） | 193 | **0** | 180 | ❌ 1082/2040 CTU 即失步 |
| `seg_bframes.hevc`（iPhone 4K I/P/B） | 237 | **0** | 76 | ✅ 78/78 |
| `seg_mov.hevc`（iPhone MOV 开放 GOP） | 199 | **0** | 180 | ✅ |
| `tiles_x265.hevc`（x265 合成 tiles） | 14 | **0** | 9 | — |

### 3.2 源码级能力核对（全部命中）

| 能力 | 位置 | 说明 |
| :--- | :--- | :--- |
| `slice_segment_header_extension` | `slice.rs:456` | **ue 长度 + u(8) 字节**，与 CBS 模板一致——正是 vendor 阻塞一的正确实现 |
| SDH（sign data hiding） | `ps.rs:716` / `ctu/residual.rs:363` | 残差符号隐藏解析 |
| 依赖 slice | `ps.rs:713` / `slice.rs:209` | dependent slice segments |
| tiles / WPP / entry point | README + `slice.rs` entry_point_offsets | 含 entry point 偏移累计式解析 |
| PCM / 35 种 intra / merge+AMVP / 加权预测 / 去块 / SAO / RPS / DPB | README | Main/Main10/Main Still，8/10bit 4:2:0 |
| Range Extensions | SPS 处显式拒绝 | 与 filmcraft 同等限制；手机实拍素材（4:2:0 8/10bit）无影响 |

### 3.3 工程资质

- **许可 Apache-2.0**——与主仓完全一致（filmcraft 为 MIT OR Apache-2.0，需双许可声明）。
- 核心 crate `#![forbid(unsafe_code)]`；unsafe 隔离在 `rusty_h265-accel`，运行时分发，每个 SIMD kernel 配 scalar 孪生逐位对照。
- **147/147 JCT-VC HEVC_v1 一致性流字节级一致**（MD5 对参照解码器）+ **6183/6183 解码图片哈希 SEI 验证**；`HEVC_REQUIRE_VECTORS=1` 防止无语料假绿。
- `pub mod cabac / slice / ctu / ps / decoder` 全部公开——observer 移植面（CABAC bypass 符号事件、子流边界、槽位回填）可干净挂接。
- API：`Decoder::new()` / `push_nal(nal, pts)` / `next_frame()` / `flush()` / `dpb()`；MSRV 1.85，与主仓 edition 2024 兼容。
- 已知边界（README roadmap）：多线程解码未做（ tiles/WPP 已解析但管线单线程）——与当前 vendor 同样单线程，非回归；Range Extensions 显式拒绝。

### 3.4 与 filmcraft 的对比与建议

| 维度 | rusty_h265 0.6.2 | filmcraft-hevc 0.9.0 |
| :--- | :--- | :--- |
| 本仓语料实测 | **5/5 零错误**（含 2 个 tiles 死局文件） | 4/4 解码成功（文档1 §11.1） |
| 一致性证据 | 147/147 字节级 + 6183 SEI 哈希 | 合成流测试（含依赖 slice/SDH） |
| 许可 | Apache-2.0（完全一致） | MIT OR Apache-2.0 |
| 内部可见性 | `pub mod cabac/slice/ctu/ps` | `slice`/`params`/`SliceDecoder` 已 pub |
| 发布形态 | crates.io 正式 crate | 大 monorepo 中的 crate |
| observer 移植工作量 | 300–500 行（估） | 300–500 行（文档2 估） |

**建议：tiles 底座以 rusty_h265 为主线、filmcraft 为备选**，两者 observer 移植工作量同级，先用 1–2 天对同一组 tiles 码流做挂接可行性对比再锁定。文档2 的 `syntax_only` 跳过像素重构优化（周期占比实测）对新底座同样适用，可一并规划。

---

## 4. 对两份既有文档的补充与修正

1. **文档1 §6.1 / 文档2 §6 的容器实现路线成立，但选项从 2 个变为 3 个**：filmcraft-isobmff（零 panic，lint 保障）/ 自写 `mp4_boxes.rs`（零依赖，文档2 代码经逐行核对逻辑正确，其 stsd 多条目遍历甚至比 mp4-rust/re_mp4 都完整）/ **re_mp4 fork（API 最贴合，需修 panic）**。三者都需补记：**不支持 stz2，显式拒绝**。
2. **文档1 §11.2 路线 B 决策成立，底座候选扩充**：见 §3.4。路线 A（继续修 vendor）的止损记录依然有效；rusty_h265 的 5/5 零错误实测进一步压低了换底座的风险。
3. **文档1 §2 约束 3（每 AU 单 slice）**：语料仍全命中；多 slice AU 路径语料未覆盖，实现时以合成 fixture 补齐。
4. **文档2 §4 的帧类型两级门控**与容器/底座选择正交，保持不变；其"门控判据无状态、两端天然一致"的论证不受本次评估影响。
5. **hvc1 in-band 参数集误区**：文档1 §2 约束 4（brand=hvc1 但参数集只在 hvcC）被本次实测再次确认（re_mp4 对 3 个 hvc1 文件均只从 hvcC 解出参数集，样本内零 in-band）。

---

## 5. 落地路线建议（更新版）

| 阶段 | 内容 | 预估 |
| :--- | :--- | :--- |
| A1 | 容器层三选一落地 + 帧类型门控 + 路由（覆盖 iPhone/MOV/无 tiles 文件，语料 3/5；tiles 文件显式拒绝） | 3–4 天 |
| A2 | 若选 re_mp4：fork + 4 处 panic 修复 + 单测（真实语料 NAL 切角） | 0.5 天 |
| B | tiles 底座：rusty_h265 fork + observer 移植（主线）/ filmcraft 移植（备选对比） | 2–5 天 |
| C | 合成 fixture（最小 MP4 + stz2 拒绝 + 多 slice AU）+ 5 文件本地批测 + ffmpeg 外部验证 | 1–2 天 |
| D | `syntax_only` 跳过重构优化（对 iPhone 4K ~15% 周期）+ rayon 按 slice 并行 | 远期 |
| E | `scan` 盲检扩展（MP4 HEVC 通道上线后同步） | 远期 |

**不建议**：继续修 vendor tiles 第 3 个 bug（文档1 §11.2 止损记录）；mp4-rust/mp4box/oxideav-mp4/mp4parse-rust 作为容器依赖；go-h265/scuffle-h265 作为解码器依赖。

---

## 6. 结论

本次下载的真正增量是两块拼图：**re_mp4 提供了经真实语料验证的容器层实现（需 fork 修 panic），rusty_h265 提供了经语料+一致性双重验证的 tiles 解码底座（Apache-2.0、forbid unsafe、内部全公开）**。二者组合恰好覆盖文档1 遗留的全部阻塞点（容器适配 + tiles 失步），且都不触碰引擎核心（STC/槽池/重编码零改动）。建议按 §5 的 A1→A2→B 顺序推进；容器层三个选项的最终选型可在 A1 启动时用 0.5 天做一次挂接对比后锁定。
