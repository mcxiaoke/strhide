# 遗留问题全面梳理与实施计划

- 生成时间：2026-11-04 16:54（本机时间，Asia/Shanghai）
- 定量复核时间：2026-11-04 17:27（对 §3 的 15 条逐条给出可证伪阈值、实测数据与最终判定）
- 代码基线：`HEAD = d466738`（master，含 `f718022`、`cedf97f`、`d4c8023`、`09f5d81`、`5f45926`、`a1b9467` 之后的修复链）
- 范围：`docs/` 下 review / audit / fixplan / plan / CODE-REVIEW 类活跃文档；历史 `CHANGES-*` 只用于核对是否已修，不作为待办来源。
- 本轮仅出文档：**未修改任何源码，未 commit / push，未删除任何文件**。
- 证据约定：行号来自当前 HEAD；若后续小改动导致行号漂移，以文中代码片段为准。

---

## 1. 结论摘要

### 1.1 数量统计

按源文档条目计（含跨文档重复）：

| 判定 | 条数 |
|---|---:|
| `fixed`（已被后续提交修复） | 157 |
| `obsolete`（描述前提已不存在） | 8 |
| `not_a_defect`（误判 / 设计取舍 / 能力边界） | 15 |
| `open`（真实存在且未修） | 65 |
| `unverified`（缺样本或基准，本轮无法确认） | 23 |
| 合计 | 268 |

去重合并后：

| 分类 | 条数 | 说明 |
|---|---:|---|
| **值得做（`must_fix`）** | **5** | 有精确触发条件且会造成 OOM、错误容量报告、CRC 失效或批量不可观测 |
| **可选 / 低价值** | **18** | 纯风格、纯性能、能力边界或收益远低于复杂度 |
| **关闭** | **190**（按条目计） | 含 fixed 157 / obsolete 8 / not_a_defect 15 / 本轮降级 no_fix_needed 10；重复条目合并后约 70 个独立问题 |
| **未核实（另列）** | **23** | 22 条 `W-*` + `LOGIC-06`，需真实 4K/8K、AVIF/WebM、HEIF 样本或性能基准 |
| **本轮需补数据（`needs_data`）** | **0** | 15 条均已用代码常量、实测或可证伪推导定论；L-07 的真实 4K 每 GB 槽位密度只影响数值精度，不影响 `must_fix` 结论 |

> 65 条 `open` 中有 32 条是同一问题在多份文档中的重复描述（例如 HEVC `TargetSlots` 同时出现在 `strhide_comprehensive_code_review_report.md`、`fixplan_20261104.md`、`stego_content_envelope_v4_review_independent_20261103.md`）。§3 的 15 条经定量复核后：**5 条保留 `must_fix`，10 条降级为 `no_fix_needed` 并移入 §5.5**。

### 1.2 仍需修复的 5 条（按危害排序）

1. **FIX-P2-17 / L-07**：MKV/音频整文件缓冲；实测 12.36 MB MKV 峰值 462 MiB（working set）/738 MiB（commit），103.4 MB MKV 峰值 3.70 GiB/6.35 GiB，随文件大小线性增长（37–61 倍）；GB 级 4K 片源必然 OOM。
2. **FIX-M6 / L-06**：JPEG 峰值内存随亮度块数线性增长；实测 12 MP 323 MiB、24 MP 814 MiB、50 MP 1.43 GiB、100 MP（4:2:0）2.02 GiB，2 个 50 MP 并发 2.68 GiB；32 位进程、2 GiB 可用内存或 GUI 并发 3 个 50 MP 即失败。
3. **RUST-P1-7 / L-04**：直接调用 HEVC 层公共入口写 MKV 的库用户得到 CRC 未刷新的文件；CLI/GUI 经 `MkvEngine` 不受影响。触发确定、成本 S。
4. **FIX-P1-4 / L-02**：原“约 3% 偏差 / NAL 中途截断”不成立；实际是 embed 返回的容量按“当前载荷所需的窗口”统计，12.36 MB MKV（真实 13,141,628 槽位）嵌入 59 B 载荷后只报告 117,000 槽位（**0.89%**）；probe 用 `StopCondition::All` 不受影响，embed 不会误拒。
5. **FIX-P2-20 / L-10**：批量 ≥2 项时逐项进度恒为空，失败项只能在整批结束后从 `BatchOutcome` 读取；`run_batch` 本身不发送 `ProgressEvent`。

---

## 2. 文档清点表

| # | 文档 | 条目数 | 本轮判定 | 建议 |
|---|---|---:|---|---|
| 1 | `docs/strhide_comprehensive_code_review_report.md` | 35 | fixed 21 / obsolete 1 / open 12 / unverified 1 | 保留为历史证据；关闭项完成后归档 |
| 2 | `docs/CODE-REVIEW-20261103.md` | 19 | fixed 14 / obsolete 1 / open 4 | 同上 |
| 3 | `docs/CODE-REVIEW-xhx-20261103.md` | 16 | fixed 12 / not_a_defect 2 / obsolete 1 / open 1 | 同上 |
| 4 | `docs/rust_full_code_review_20261103_235007.md` | 46 + 22 `W-*` + 8 待确认 | fixed 24 / not_a_defect 11 / open 19 / unverified 22 | **仍是最有价值的新问题来源**，保留 |
| 5 | `docs/fixplan_20261104.md` | 48 + 9 关闭 | fixed 33 / not_a_defect 1 / open 14 | 与本文重叠度高；本文合入后归档 |
| 6 | `docs/stego_content_envelope_v4_review_20261103.md` | 24 | fixed 20 / not_a_defect 1 / open 3 | 归档前先处理 3 条低优先项 |
| 7 | `docs/stego_content_envelope_v4_review_independent_20261103.md` | 19 | fixed 13 / obsolete 2 / open 4 | 保留，GUI 能力缺口仍未闭环 |
| 8 | `docs/stego_content_envelope_v4_final_plan_20261103.md` | 22（7 blocking + 15 major） | 20 已实现 / 2 已被 §13 偏差覆盖 | **执行计划已完成，建议归档** |
| 9 | `docs/lib_interface_audit_and_refactoring_plan_20261103.md` | 9 | 1 整篇 obsolete / 8 optional | **建议归档**（文首已自述历史、被 V4 方案取代） |
| 10 | `docs/stego_content_envelope_v4_golden_vectors_20261103.md` | 参考文档 | 非问题清单 | 保留 |

补充：`docs/archived/` 下 30 余份历史 review/plan 均已归档，本轮按“整体 obsolete”处理，未逐条复核；如需复活其中条目，应重新针对当前 HEAD 出具证据。

---

## 3. 待修复清单（原“值得做”，仅保留 5 条 `must_fix`）

排序依据：`危害 × 可达性 / 成本`。成本口径：S ≤ 0.5 天，M ≈ 1–2 天，L ≥ 3 天。

> 说明：以下 15 条的“来源/现状证据/影响/最小方案/测试/成本”为复核前原文，仅作对照；每条末尾的“精确结论”是最终判定。其中 10 条已降级为 `no_fix_needed`，集中列在 §5.5。

### L-01 HEVC 流式 inspect 与 embed/probe 的 `has_inter` 判定不一致

- **来源**：`docs/rust_full_code_review_20261103_235007.md` P1-3（未被 fixplan 覆盖）。
- **现状证据**：
  - `rust/src/stego/hevc/engine.rs:2552-2568`：MP4 流式 inspect 只读前若干 sample，用 `sample_prefix_has_inter(&hdr_buf, ...)` 猜测 `has_inter`。
  - `rust/src/stego/hevc/engine.rs:701` 与 `:3451`：embed / 全量 inspect 用 `candidates.iter().any(|c| !is_irap(c.nal_type))` 完整判定。
  - `has_inter` 直接决定 `picture_band()`（`:3683-3687`）和随后的槽位统计；两条路径不一致时，probe 报告的容量与 embed 实际可写槽位不同。
- **影响**：可达性取决于“前 N 个 sample 全为 IRAP、后面出现 P/B”的 4K/8K 长视频；一旦命中，probe 可能高报容量，embed 失败；或 inspect 的 `band_slots` 错误导致 GUI 误判。
- **最小方案**：删除 `sample_prefix_has_inter` 快路径，流式 inspect 复用与全量路径相同的 NAL 遍历结果；如担心性能，可在已解析的 NAL 列表上做一次 `any()`，不做“前 N 样本”截断。改动文件：`rust/src/stego/hevc/engine.rs`（`:2552-2568`、`:2395-2430`）。
- **测试**：构造/使用一个 4K MP4：前 3 个 sample 全 IRAP，第 4 个起为 P 帧；断言 `inspect` 的 `band_slots`、`available_slots` 与 `probe`/`embed` 一致，并完成 embed→extract 往返。
- **成本/风险**：M；仅增加一次全 NAL 扫描，不牵涉 wire 格式。需要真实或 ffmpeg 生成的 4K 样本。
- **精确结论**：
  - **判定：`no_fix_needed`**（原“probe 容量不一致 / 无法解出”的因果链不成立）。
  - **触发条件**：只有 `inspect` 的文件入口 `inspect_carrier_file`（`rust/src/stego/io.rs:219-231`）会走 `inspect_hevc_mp4_file_v4`；它对每个 sample 只读前 `HAS_INTER_PREFIX_BYTES = 1 MiB`（`hevc/engine.rs:2388`），并在第一个不完整 NAL 处立即返回 `false`（`:2429-2431`）。要把含 P/B 的流误判为 `has_inter=false`，必须**每个 sample** 的第一个 VCL NAL 之前都有 ≥1 MiB 非 VCL 数据（或首个 NAL 本身 >1 MiB 且其后还有 VCL）。
  - **阈值**：正常 x265 AU 前缀（AUD+SEI+VPS/SPS/PPS）< 2 KiB，距 1 MiB 有 500 倍以上余量；已知封装器/编码器不产生“每帧 ≥1 MiB 前缀”的输出，因此可达输入为 0 个已知样本。
  - **不触发条件**：`probe_hevc_capacity_info` 使用 `StopCondition::All`（`hevc/engine.rs:672`、`:719`）；embed 与字节入口用 `candidates.iter().any(|c| !is_irap(...))`（`:701`、`:3451`）。因此写入、提取、容量探测都不经过该快路径。
  - **实际损害**：即使命中，也只影响 `inspect` 元数据里的 `band_slots`/槽位展示，不影响 embed 结果或解出数据。
  - **依据**：上述代码行 + 1 MiB 常量；未做 4K 样本实测，因为结论已由“只有 inspect 调用该路径”这一调用链闭合。

### L-02 HEVC `TargetSlots` 在 NAL 中途截断，容量不精确

- **来源**：`fixplan_20261104.md` P1-4；`strhide_comprehensive_code_review_report.md` LOGIC-01。
- **现状证据**：
  - `rust/src/stego/hevc/engine.rs:1197-1213`：按 `non_ref_fraction` 计算 `target_slots` 后调用 `StopCondition::TargetSlots(target_slots)`。
  - `rust/src/stego/hevc/engine.rs:3520-3545`（片段以代码为准）：记录器在累计槽位达到目标后停止，最后一个 NAL 的 extra 可能只记录一部分；`build_hevc_capacity_info` 用这份局部记录汇总 `total_slots`。
- **影响**：probe 与实际 embed 的可用槽位有约 3% 偏差；表现为“探测说能放、embed 报容量不足”，或安全等级建议错误。不会损坏已写入数据。
- **最小方案**：记录阶段按“完整 NAL/完整 slice segment”边界停止：若加入下一个 NAL 会超过 `target_slots`，则不加入并结束；最后用实际记录重新求和，不用目标值回填。改动文件：`rust/src/stego/hevc/engine.rs`（`record_*` / `build_hevc_capacity_info`）。
- **测试**：现有 `hevc_stego.rs` 增加“容量恰好等于 probe 值 ±1 字节”的 embed 测试；对 balanced/high/paranoid 三档各跑一次，断言 `probe.max_payload_bytes` 可写、+1 字节必失败。
- **成本/风险**：M；不牵涉 wire 格式；只影响容量报告与停止条件。
- **精确结论**：
  - **判定：`must_fix`**（但缺陷是“embed 返回的容量报告错误”，不是“probe 与 embed 不一致导致误拒”）。
  - **触发条件**：任意 HEVC/MKV embed，只要载荷明显小于载体总容量，embed 返回的 `StegoCapacityInfo` 就按“本载荷所需窗口”统计。
  - **阈值/公式**：`target_slots = hdr_slots + ceil(body_needed_slots * factor) + 128`（`hevc/engine.rs:1196-1206`），视频 `factor = 1 / non_ref_fraction`，HEIF 为 1；停止检查在整条 slice 之后（`:3536-3553`），所以 `reported_slots ∈ [target_slots, target_slots + slots(最后一条 slice) - 1]`，不会在 NAL 中途截断。
  - **实测**：`video_12mb.mkv`（12.36 MB，40 s 720p）的 `capacity --json` 为 13,141,628 槽位 / 821,296 B；同一文件嵌入 59 B 载荷后 CLI 报告“最大 7.09 KiB、117,000 槽位”，即 **0.89%**，倍率 **112.3×**。若按原描述“约 3%”，应为 393,000 槽位——实测是其 0.30 倍。
  - **不触发条件**：`probe_hevc_capacity_info` 用 `StopCondition::All`（`:672`、`:719`），容量始终精确；embed 也不会误拒，因为 `target_slots ≥ hdr_slots + body_needed_slots + 128`，整 slice 只会多记不会少记。
  - **实际损害**：用户/图形界面看到的“最大容量、容量占用百分比”严重偏低；同一载体 probe 前后相差 112 倍，会误导选载与容量规划。不损坏文件。
  - **最小方案**：embed 返回的 capacity 改为使用独立的 `probe_hevc_capacity_info(... exact)` 结果，或明确把当前字段标注为“本次写入窗口”；不要把 `TargetSlots` 截断记录当作全载体容量。
  - **依据**：上述代码行 + `capacity`/`embed` 两次 CLI 实测输出。
  - **修复状态（2026-11-04 18:13）**：已修复。`embed_hevc_with_info_v4` 构建容量报告时改用与 probe 同一来源的全量池（`probe_hevc_pool`）；扫描已覆盖全载体时直接复用写入记录，避免二次解码。写入仍用 `TargetSlots`，不会误拒。实测 `video_12mb.mkv` 嵌入 59 B 后报告 13,141,628 槽位 / 70.04 KiB 安全 / 802.05 KiB 最大，与 `capacity --json` 一致（原为 117,000 / 1.40 KiB / 7.09 KiB）；60 KiB 载荷加 `--enforce-safety` 现可写入并往返一致。回归测试 `test_hevc_embed_capacity_report_matches_probe`。

### L-03 JPEG 容量探测使用几何网格而非真实块数

- **来源**：`rust_full_code_review_20261103_235007.md` P1-2。
- **现状证据**：
  - `rust/src/stego/jpeg/engine.rs:1788`：`let block_count = geom.grid_w * geom.grid_h;`（probe 路径）。
  - `rust/src/stego/jpeg/engine.rs:224` / `:1936`：embed 使用 `coeffs.components[0].blocks.len()`。
  - `preflight_jpeg()` 已返回 `info.components[].block_count`（同一文件 `:156`），probe 可直接使用。
- **影响**：DNL（SOF 高度为 0，后置 DNL）、非标准采样/多 scan 的 JPEG，几何推导块数可能与实际解码块数不同；probe 容量偏差属“误用/体验”，不会写坏文件（embed 会二次校验）。
- **最小方案**：`build_jpeg_capacity_info` 改为 `let block_count = info.components.first().map_or(0, |c| c.block_count);`，仅当为 0 时回退 `geom.grid_w * geom.grid_h`。改动文件：`rust/src/stego/jpeg/engine.rs:1777-1800`。
- **测试**：新增 DNL JPEG 夹具（可用现有样本改写 SOF 高度并在 SOS 后插入 DNL）；断言 `probe.max_payload_bytes` 与 embed 的 `capacity_info` 完全一致。
- **成本/风险**：S；无 wire/API 变化。
- **精确结论**：
  - **判定：`no_fix_needed`**（原“probe 与 embed 块数不一致”的前提在当前解码器上不成立）。
  - **触发条件**：只有当 `dct_io` 返回的 `components[0].blocks.len()` 小于 `mcu_cols*hs × mcu_rows*vs` 时才会不一致，例如截断/多 scan/非标准变体。
  - **阈值/证明**：`component_geometry` 明确说明解码器按 MCU 填充网格分配块数组，`positions` 长度恰为 `n_blocks`（`jpeg/geometry.rs:25-28`、`:79-96`）；对通过 `preflight_jpeg` 的 baseline 单 scan JPEG，`n_blocks` 就等于 `grid_w*grid_h`，所以 probe 与 embed 完全相等。
  - **实测**：1001×767 4:2:0（容量 95,139 B）与 999×777 4:4:4（96,352 B），按 probe 最大值减去文件名字段的载荷执行 `--no-filename` embed，两次都成功；未出现块数偏差。
  - **不触发条件**：DNL（SOF 高度为 0）在 `preflight_jpeg` 被拒绝（实测返回 `UnsupportedFormat`，零高度无法进入容量计算），progressive（SOF2）也被拒绝；它们在进入容量计算前就失败，不可能出现 probe 报容量而 embed 写坏。截断 JPEG 会在 `read_coefficients` 阶段失败。
  - **实际损害**：0；即使理论上出现，embed 的 `build_jpeg_capacity_info` 与 `embed_once` 使用同一 `n_total` 校验，失败会返回错误而不是写出错误文件。
  - **依据**：`jpeg/engine.rs:1788`、`:224`、`geometry.rs:25-28`、`:79-96` + 上述两组实测。

### L-04 HEVC 公共入口不刷新 MKV CRC

- **来源**：`rust_full_code_review_20261103_235007.md` P1-7。
- **现状证据**：
  - `rust/src/stego/engine.rs:976`：只有 `MkvEngine` 的上层 embed 调用 `refresh_mkv_crcs`；CLI/GUI 正常 MKV 路径经 `embed_carrier_with_dialect_info` 进入 `MkvEngine`，因此不受影响。
  - `rust/src/stego/hevc/engine.rs:1046` `embed_hevc_with_info_v4` 与 `:1122/:1157` `embed_hevc_patches_with_factor*` 均无 CRC 刷新；直接调用 HEVC 层的库用户受影响。
- **影响**：库用户直接调用 HEVC 层并写 MKV 时，得到 CRC 过期的文件；mkvmerge/严格解析器可能拒绝。CLI/GUI 正常路径不受影响。
- **最小方案**：在 `embed_hevc_with_info_v4` 内按 `kind == Mkv` 调用 `mkv_boxes::refresh_mkv_crcs`，并删除 `stego/engine.rs:976` 的重复调用；或在 `embed_hevc_patches_with_factor_v4` 统一处理，确保只刷新一次。
- **测试**：新增库级测试，直接调用 HEVC 层 embed MKV，随后用 CRC 校验（或调用 `refresh_mkv_crcs` 的 dry-run 比较）断言无需二次刷新；再跑一次 `cargo test --all-features` 的 MKV 往返。
- **成本/风险**：S；无 wire 变化；注意避免双重刷新。
- **精确结论**：
  - **判定：`must_fix`**。
  - **触发条件**：任何库调用方直接调用 `hevc::embed_hevc_with_info_v4`、`embed_hevc_patches_with_factor` 或 `embed_hevc_patches_v4`（均在 `stego/hevc/mod.rs:28-29` 公开导出），且载体为 MKV；这些入口内部没有 `refresh_mkv_crcs`。
  - **阈值**：无阈值——只要写入至少 1 个字节的 HEVC 数据，被修改的 Level-1 Matroska 元素的 CRC-32 就与内容不匹配；`printf` 级确定性。
  - **不触发条件**：CLI/GUI 走 `MkvEngine`（`stego/engine.rs:958-976`），在返回前调用 `refresh_mkv_crcs`；MP4/Annex-B 不使用 MKV CRC。
  - **实际损害**：`mkvmerge`/严格解析器报告 CRC mismatch，部分工具拒绝复用或重新封装；播放器通常忽略 CRC，但这属于对外交付文件不合规。CLI/GUI 不受影响，因此只影响库 API 的直接使用者。
  - **最小方案**：在 `embed_hevc_with_info_v4` 返回前按 `kind == HevcCarrierKind::Mkv` 调用一次 `refresh_mkv_crcs`，并删除 `stego/engine.rs:976` 的重复调用；测试直接调用 HEVC 层写 MKV 后用 CRC 复算断言无需二次刷新。
  - **依据**：上述导出列表、`stego/engine.rs:976`、`hevc/engine.rs:1046/1157`。
  - **修复状态（2026-11-04 18:23）**：已修复。`embed_hevc_with_info_v4` 在 `apply_hevc_patches` 之后按 `sniff_hevc_carrier == MkvContainer` 调用一次 `refresh_mkv_crcs`；`stego/engine.rs` 中的重复调用已删除。库级测试 `library_embed_refreshes_mkv_crcs`（不经 `MkvEngine`）在 822 KB MKV 上断言 embed 前后一致 CRC 数量不下降；`video_12mb.mkv` 经 CLI 写出后被 `ffprobe`/`ffmpeg -f null` 正常读取（exit 0），`strhide verify` Level 1–3 全 OK。

### L-05 PNG >2 MiB 并行 deflate 无测试

- **来源**：`rust_full_code_review_20261103_235007.md` P2-1。
- **现状证据**：
  - `rust/src/stego/png/engine.rs:578`：`MIN_PARALLEL_SCANLINE_BYTES = 2 * 1024 * 1024`。
  - `:659-660`：小于阈值或高度不足时走单个 `ZlibEncoder`；大图走 `compress_raw_deflate_chunk` 的 8 段并行路径（`:597-625`），非末段用 `SyncFlush`。
  - `:948`、`:2726` 也有独立的 `ZlibEncoder` 路径；当前测试没有强制触发 `>=2 MiB` 的并行分支。
- **影响**：并行路径的分块/刷写边界与单流路径不同，若实现漂移，生成的 PNG 可能仍被本库读取但被第三方解码器拒绝；属于“未验证的输出正确性”。
- **最小方案**：先补测试，不改生产逻辑。生成一张 filtered 数据 >2 MiB、height ≥ num_threads 的 PNG（例如 1024×1024 RGBA），断言：8 段路径产物可被 `png` 解码、IDAT 连续、CRC 正确、连续调用字节一致；再对单流/并行输出做像素/长度对比。若发现不一致，再统一使用单流或按 level 生成正确的 zlib 头。
- **测试**：`rust/src/stego/png/engine.rs` 单测 + 现有 `png_stress` 覆盖。
- **成本/风险**：S；无 wire 变化。
- **精确结论**：
  - **判定：`no_fix_needed`**（未测试覆盖是事实，但输出正确性已实测，不构成运行时缺陷）。
  - **触发条件**：`filtered.len() >= 2 MiB` 且 `height >= 8` 时进入 8 段并行 deflate（`png/engine.rs:578`、`:657-685`）。
  - **实测**：1024×1024 RGBA 噪声 PNG，filtered 字节数 = 1024×(1+1024×4) = 4,194,304 B > 2 MiB；`embed` 后 `extract` 的 SHA-256 与输入载荷完全一致，Pillow 解码得到 RGBA 1024×1024。说明并行分块 + SyncFlush 产出的 zlib 流可被第三方解码器接受。
  - **不触发条件**：`filtered < 2 MiB` 或 `height < 8` 走单 `ZlibEncoder`，与本条无关。
  - **实际损害**：0（本轮实测通过）；真正缺的是回归测试，不是缺陷。可把上述样本固化为 `>2 MiB` 分支的单测/压力用例，归入可选测试项。
  - **依据**：`png/engine.rs:578`、`:657-685` + 实测往返。

### L-06 JPEG 峰值内存：整图系数副本 + 4 GiB 回溯预算

- **来源**：`CODE-REVIEW-20261103.md` M-6；`fixplan_20261104.md` P2-5。
- **现状证据**：
  - `rust/src/stego/jpeg/engine.rs:767`：`let mut work = coeffs.clone();`（`cover`/`costs` 仍持有原 `coeffs`）。
  - `rust/src/stego/params.rs:448`：`MAX_AUTO_BACKTRACK_BYTES = 4 << 30`（4 GiB）。
  - `rust/src/stego/coding/stc.rs` 回溯位图按 `n * words_per_col` 分配。
- **影响**：50 MP 级 JPEG 或 GUI 多任务并发时可能 OOM；正常中小图不受影响。不是数据损坏。
- **最小方案（分两阶段）**：
  - 阶段 A（S）：默认自动预算降到 256–512 MiB，4 GiB 改为显式 opt-in；在 `StegoCapacityInfo` 增加预计峰值字段，probe/CLI/GUI 显示。改动：`params.rs`、`engine.rs`、`options.rs`、`gui` 展示。
  - 阶段 B（M）：用“原系数 + applied deltas”替代 `coeffs.clone()`，失败走现有 `rollback` 恢复。改动：`jpeg/engine.rs` embed 主流程。
- **测试**：50 MP 样本测 RSS 峰值（阶段 A 断言不超过配置预算，阶段 B 断言与旧实现字节一致）；GUI 并发 2 张大图的 e2e。
- **成本/风险**：阶段 A S、阶段 B M；阶段 B 需重点保证字节级一致（可用 `baseline_hash --check`）。
- **精确结论**：
  - **判定：`must_fix`**。
  - **分配结构（每块字节数）**：`coeffs` 每个分量块 64×`i16` = **128 B**（4:4:4 共 `T=3Y` 块，4:2:0 共 `T=1.5Y` 块，`Y=ceil(W/8)·ceil(H/8)` 为亮度块）；`let mut work = coeffs.clone()`（`jpeg/engine.rs:767`）再加 **128 B×T**；UERD 代价表 `f64×64` = **512 B/Y 块**（`jpeg/cost/uerd.rs`）；槽位网格约 **252 B/Y 块**；STC 回溯位图 `N×B`，`B=16 B`（h=8,u=1）或 **32 B**（h=8,u>1），`N=min(body_slots/4, (bits+h-1))`。
  - **峰值公式**：`P(MiB) ≈ 64 + A·Y/2^20 + N·B/2^20`；`A ≈ 1.28 KiB/亮度块`（4:4:4，含 `coeffs`/`work`/代价表），`A ≈ 0.90–1.15 KiB/亮度块`（4:2:0，含槽位网格）。
  - **实测（4 KiB 载荷，PrivateMemorySize64 峰值）**：12 MP 4:4:4 **323 MiB**（working set 324）；24 MP 4:4:4 **814 MiB**（645）；50 MP 4:4:4 **1,427 MiB**（1,378）；50 MP + 4 MiB 载荷 **1,751 MiB**（1,573）；100 MP 4:2:0 **2,018 MiB**（2,016）。公式与实测偏差 ≤10%。
  - **硬上限实测**：100 MP 4:4:4（11600×8700）在 `preflight_jpeg` 被拒：1,577,600 MCU > `MAX_JPEG_MCU_COUNT=1,048,576`；4:4:4 的最大可达分辨率是 **67.1 MP**（1,048,576 MCU×64 像素），其峰值约 1.87 GiB。
  - **OOM 阈值**（设可用提交内存 A）：单任务失败当 `P > A`。**32 位进程**（2–3 GiB 地址空间）在 100 MP 4:2:0（2.02 GiB）必失败；67 MP 4:4:4（1.87 GiB）已处于边界。**64 位 2 GiB 可用**：100 MP 必失败，50 MP（1.43 GiB）可过。**4 GiB 可用**：100 MP 可过，2×50 MP（2.68 GiB）可过，3×50 MP（≈4.0 GiB）失败。**8 GiB 可用**：4×50 MP（5.35 GiB）可过，5×50 MP（≈6.7 GiB）失败；2×100 MP（4.04 GiB）可过。GUI 批量并发 `N` 时组合峰值≈`N×1.43 GiB`（50 MP）或 `N×2.02 GiB`（100 MP）；`max_concurrency` 来自批任务参数（`gui/src-tauri/src/commands/batch.rs`），不是固定 1。
  - **最坏单任务**：4:2:0 在上限 268 MP（1,048,576 MCU×256 像素）时 `Y≈4.19M`，`coeffs+work+costs≈3.5 GiB`，扣除预检 base 后位图最多约 1.5 GiB，合计 `P≈4.6 GiB`；`MAX_PIPELINE_BYTES=8 GiB` 的预检仍放行（base≈6.5 GiB<8 GiB），4 GiB 内存机器必 OOM，8 GiB 机器处于危险边界。
  - **不触发条件**：12 MP（323 MiB）与 24 MP（≤814 MiB）在 4 GiB 可用下单任务稳定；4 GiB 可用机器上单张 4:4:4 最大 67 MP（1.87 GiB）也能过。任何普通手机/相机小图不受影响。
  - **关键纠正**：默认 4 GiB 回溯预算**不是**本条的约束源。自动预算 `effective_slot_budget = min(body_slots/4, 4 GiB)`，而 `body_slots ≤ 63·Y ≤ 264M`，`body_slots/4 ≤ 66M`，位图最多 **2.1 GiB**（h=8,u>1）；真正随分辨率增长的是 `coeffs`+`work`+代价表（4:4:4 约 1.25 KiB/亮度块）。只下调 `MAX_AUTO_BACKTRACK_BYTES` 不会降低 50/100 MP 的峰值。
  - **最小方案**：优先去掉 `coeffs.clone()`（用原系数 + `Move` 增量写回，失败走已有回滚），其次给 GUI `max_concurrency` 设上限（建议按 `可用内存 / 单任务估算`），最后才考虑预算字段展示；`MAX_PIPELINE_BYTES` 应改为可配置且默认不高于实际可用内存。
  - **依据**：上述常量、公式与 6 组实测（样本在 `temp/legacy_issues_samples/`，未入库）。
  - **修复状态（2026-11-04 18:39）**：已修复。`jpeg/engine.rs` 删除 `coeffs.clone()`（`work` 直接取得原系数，失败仍由既有 `rollback` 原地恢复），`baseline_hash --check` 28 例字节不变；GUI 嵌入命令按 `embed_concurrency_limit`（可用物理内存 60% / 1.43 GiB 档位，最少 1）预留槽位，超限直接返回 `Rejection` 而不是硬跑。实测 4:2:0、4 KiB 载荷（Private/WS MiB）：12 MP 242.3/235.7 → 197.5/198.7（-18.5%/-15.7%）；24 MP 460.7/461.1 → 391.7/393.9（-15.0%/-14.6%）；50 MP 958.2/958.5 → 815.2/815.8（-14.9%/-14.9%）；100 MP 1931.1/1929.4 → 1642.0/1640.6（-15.0%/-15.0%）。GUI 单测 `concurrent_embeds_beyond_the_limit_are_rejected` 断言第 3 个并发被拒绝。

### L-07 HEVC/MKV 整文件缓冲，长视频峰值内存数 GB

- **来源**：`strhide_comprehensive_code_review_report.md` PERF-04；`fixplan_20261104.md` P2-17；`rust_full_code_review_20261103_235007.md` W-19。
- **现状证据**：
  - `rust/src/stego/io.rs:67-105`：仅 Mp4/HevcAnnexB 走 patch 流式；MKV 落到下方的整文件 `Vec` 路径。
  - `rust/src/stego/audio/mod.rs:165/228/256/...` 多处 `carrier.to_vec()`；`rust/src/core/commit.rs` 也有整文件缓冲。
- **影响**：4K/8K 长视频或长音频的内存峰值高，低内存机器/并发时 OOM。属于性能/稳定性，不是正确性。
- **最小方案（分阶段）**：
  - 阶段 A（S）：在 MKV/HEVC 入口按 `file_size + 预计 patch 开销` 预检，超过阈值直接给出“需要更多内存/请分段”的明确错误，并提供 `--low-memory`（顺序处理）。
  - 阶段 B（L）：MKV 改为与 Mp4 相同的 patch 流式写入（`mkv_boxes` 已支持定位，只需把输出从整文件改为临时文件 + 顺序 copy）。
- **测试**：用 1 GB 级 MKV 测 RSS 峰值；阶段 B 用 `baseline_hash --check` 保证字节一致。
- **成本/风险**：A S、B L；B 牵涉 I/O 层但不牵涉 wire。
- **精确结论**：
  - **判定：`must_fix`**。
  - **下界公式**：非 patch 路径峰值 ≥ `2×file_size`（`carrier_bytes` 整文件 + 引擎返回的整文件 `Vec`）+ HEVC 记录槽位结构；`io.rs:67-105` 只对 Mp4/HevcAnnexB 走 patch。
  - **实测（4 KiB 载荷，PrivateMemorySize64/WorkingSet）**：12.36 MB MKV → **738/462 MiB**（60×/37×）；103.4 MB MKV → **6,353/3,697 MiB**（61×/36×）。两者近似线性，说明峰值由文件/槽位数驱动，不是固定开销。该样本是 40 Mbps 高熵 `testsrc2`，槽位密度接近上界；真实低码率视频倍率更低，但**代码下界 `2×file_size`** 与实测的 GB 级规模已足以判定。
  - **阈值**：按最坏实测倍率，8 GiB 可用内存下单文件上限约 `8192/37 ≈ 221 MB`（working set）或 `8192/61 ≈ 134 MB`（commit）；**1 GB MKV** 需要约 37–61 GB，必 OOM；**4K 1 小时 25–50 Mbps 电影（11–22 GB）** 即使只按 2× 下界也需要 22–44 GB，在 16–32 GB 机器上必失败。
  - **不触发条件**：MP4/Annex-B 走 patch 流式，峰值与文件大小基本无关（`io.rs:67-105`）；<10 MB 的普通短片峰值约 0.4–0.7 GB，4 GiB 可用机器可过。
  - **实际损害**：进程 OOM 退出，批任务整体失败；这是稳定性缺陷，不是文件损坏（写入前已分配失败）。
  - **最小方案**：阶段 A 必须在分配前按 `预计峰值 ≈ 40×file_size` 预检并给出可操作错误（不能只给“内存不足”）；阶段 B 把 MKV 改为与 MP4 相同的 patch 流式（`mkv_boxes` 已有定位能力，输出改为临时文件顺序 copy），并把槽位记录按 GOP 释放。阶段 A 的 40× 是实测上界，真实视频可用基准下调，但不得低于 `2×file_size` 下界。
  - **依据**：`io.rs:67-105`、`audio/mod.rs:165/228/256`、`core/commit.rs` 整文件缓冲 + 两组 MKV 实测。
  - **修复状态（2026-11-04 19:07，阶段一完成；口径已被 19:43 的窗口口径取代，见下条）**：`stego::io::check_buffered_embed_budget` 在 `embed_carrier_file` 的 `fs::read` 之前预检，峰值公式 `file_size × factor + 64 MiB`（MKV 64×、WAV 4×、FLAC 4× 取自本节实测上界并向上取整，64 MiB 为固定解码/池开销）；预算 = 可用物理内存 60%（与 GUI 嵌入准入同源），无内存查询的平台回退 4 GiB。超限返回 `Rejection`，消息含输入大小、预计峰值与预算。`--dry-run` 同样执行整文件内存 embed，在读取前复用同一预检。实测可用物理内存 19.6 GiB：429.5 MB HEVC MKV 被拒绝（409.6 MiB / 预计 26,279.7 MiB / 预算 12,073.3 MiB）；12.36 MB 与 103.4 MB 样本正常 embed→extract，SHA-256 一致。阶段一不改变峰值（736.3/457.8 MiB、6,729.9/3,697.9 MiB，与修复前 738/462、6,353/3,697 MiB 同量级）。阶段二（把 `carrier.to_vec()` 等最大整文件副本改为流式/分段）评估收益 <2%——MKV 峰值由槽位记录表主导——本批不做；阶段三（完整流式重写 + 槽位按 GOP 释放）列为独立批次。
  - **阶段一修订 A（2026-11-04 19:43，窗口口径，实施中）**：`file_size × factor` 的口径被实测证伪，改为「窗口口径」。
    - **证伪依据（同内容双容器：同一段 1080p HEVC 用 `-c copy` 只换封装，4 KiB 载荷，私有内存/工作集 MiB）**：10s 3.95 MB → MP4 **303.5/183.5**、MKV 302.9/183.7；30s 12.70/12.69 MB → **846.1/537.2**、841.2/522.2；60s 36.16/36.15 MB → **1822.3/1196.9**、1900.1/1208.9；120s 61.21/61.18 MB → **1920.4/1228.3**、1845.3/1231.6；480s 125.6 MB → **1953.0/1288.0**、1943.1/1286.0；高熵 40s 104.3 MB → **6759.4/3784.3**、6374.8/3707.2。**容器不是变量**（MP4 有 4 组反而更高，差异 ≤6%）。MKV 独有的 `carrier.to_vec()` 发生在批次解码之后，不在峰值路径上：429.5 MB MKV 实测 **2242.6/1583.7 MiB**，同内容 405.6 MB MP4 为 2214.8/1565.8 MiB，相差 1.3%。
    - **峰值真正的驱动**：`record_carrier_state` 的 `StopCondition::TargetSlots` 分支每批 `batch_size = 16` 个 GOP，`par_iter().collect()` 先把 16 份完整记录表同时留在内存，之后才合并、判断停止、截断窗口。插桩实测（高熵 40s，全片 5 个 GOP）：每个 GOP 248 片 / 2200 万槽位 / 2 亿条 bin → 槽位表 356 MB + bin 日志 399 MB；合并后真正保留的窗口只有 1 片 / 11.7 万槽位（约 2 MB）——峰值建完即丢。日志 `Vec` 增长与堆保留使实测峰值约为活数据的 1.9 倍。线程数无关（1/2/4/8/16 线程实测 6.37–6.99 GB）。
    - **拟合公式**：`峰值 ≈ 70 B × 前 16 个 GOP 的载体字节 + 1×文件 + 64 MiB`（拟合系数 66 B/字节，取整到 70 以覆盖「窗口按 VCL 跨度计、比整文件略小」的差额）。复核（实现后的实际预检输出 vs 私有内存实测 MiB）：429.5 MB MKV 窗口 29.4 → 预测 2,531.6 / 实测 2,171.8；405.6 MB MP4 窗口 29.4 → 2,507.4 / 2,214.8；高熵 104.3 MB 窗口=整片 99.4 → 7,124.0 / 6,759.4；125.6 MB 窗口 28.2 → 2,158.3 / 1,953.0；12.7 MB 窗口 12.1（9 GOP）→ 922.9 / 846.1；3.95 MB → 331.6 / 303.5。**全部高估 5.4%–16.6%**。
    - **失效条件**：`64×file_size` 只在「GOP 数 ≤ 16、整片落进一个批次」时成立（高熵 40s 样本正是这种形状，实测 65×）。24 min 片约 480 个 GOP，窗口只占 3%，实测 5.5×——**19:07 那条 26,279.7 MiB 把这份 429.5 MB MKV 高估 11.7 倍；实测 2,242.6 MiB 正常完成、SHA-256 往返一致，属误拒**。方向上它是上界（窗口 ≤ 整文件），只误拒、不放过。
    - **另一侧缺口**：`whole_file_peak_bytes` 只认 Mkv/Wav/Flac，**MP4/AnnexB 完全没有预检**，而其实测峰值与 MKV 同量级（同一 405 MB 素材 MP4 走 `--dry-run` 直接放行）。
    - **改法**：① 预检改为窗口口径，并把 MP4/AnnexB/HEIF 一并纳入；② 读文件前只保留「连 1× 都放不下」的粗门（`file_size + 64 MiB > 预算`），不再按格式乘整文件系数；③ 读完、解码前用 `hevc::estimate_embed_peak_bytes` 精确判断，窗口由 `find_gop_ranges` 取前 `EMBED_WINDOW_GOPS = 16` 个 GOP 的 VCL 跨度，大载荷时窗口按目标槽位向上取到整文件；④ WAV/FLAC 保持整文件系数（它们没有 GOP 概念），系数由 4× 收到 2.5×：实测 11.5 MB WAV 2.06×、96 MB 2.02×、366 MB 2.01×、39.7 MB FLAC 2.01×，峰值就是「载体 + 一次 `carrier.to_vec()` 重写副本 + 2–4 MB」，4× 等于凭空多算一倍；⑤ `--dry-run` 与真实写入共用同一个「读取 + 预检」入口，避免两条路径漂移。
    - **验收（2026-11-04 19:52，已完成）**：预检预测值 ≥ 实测峰值（+5.4%–16.6%）；429.5 MB MKV 与 405.6 MB MP4 不再被误拒，MKV 实跑 2,171.8 MiB、SHA-256 往返一致、文件大小与时长不变，`--dry-run` 同样放行；405 MB MP4 + 4 MiB 载荷 0.23 s 即被拒（窗口 320 MiB / 预计 22,852 MiB > 预算 12,144 MiB），此前会记录近整片并 OOM；`baseline_hash --check` 28/28 逐字节一致，`clippy -D warnings`、`import_lint`、`cargo test --all-features --all-targets` 全绿。实现见 `docs/CHANGES-20261104.md`（19:52:37）。
    - **音频后续（本批未做）**：WAV 的 2× 峰值里有一半是 `embed_wav` 里那次整文件 `carrier.to_vec()`；`PcmCarrier::apply` 只写 1–4 字节到已知偏移，天然适合走已有的 `commit_carrier_patches`（提交阶段内核级 `fs::copy` + seek 写入，零堆分配），峰值可降到 1×。代价是要给 `EmbedOutput` 增加 patch 形态、io.rs 分发，并补「patch 结果 == 原字节输出」的逐字节回归，列为独立批次。FLAC 的残差是位打包，一次翻转会改变码字长度、`finalize` 可能重写，且校验依赖原始与结果的 PCM MD5/漂移，不建议同批 patch 化。

### L-08 密码路径在无 domain 时丢弃 `cipher.domain_label`

- **来源**：`rust_full_code_review_20261103_235007.md` P2-6。
- **现状证据**：
  - `rust/src/stego/format.rs:438`：`derive_domain_subkey_with_label(normalized.as_bytes(), domain, cipher.domain_label)`；`domain=None` 时返回 `None` 并回退直接使用密码。
  - 文件密钥路径 `info_with_domain`（同文件 `:515-528`）把 `cipher.domain_label` 放进 info，即使 `domain=None` 也参与派生（`:590` 测试确认 `info_with_domain(b"hpos", None) == b"hpos"`）。
- **影响**：同一 `WireCipherProfile` 下，密码与文件密钥的 KDF 行为不对称；私有 `domain_label` 在密码路径上没有生效，削弱“私有方言”的域分离。不是可直接利用的漏洞，但违背配置语义。
- **最小方案**：统一派生：密码路径始终把 `cipher.domain_label` 作为 label 输入（`domain=None` 时用空 domain + 非空 label）；或反方向统一为“无 domain 则无 label”，并同步文件密钥路径与文档。项目未发布，可接受 wire 变更；需同步更新 golden vectors。
- **测试**：同一 profile/密码/载体，`domain=None` 的密码路径与文件密钥路径派生结果按设计一致；私有 label A/B 产生不同密钥；更新 `golden_vectors` 基线。
- **成本/风险**：S；**牵涉 wire 格式与 golden vectors**，须单独批次。
- **精确结论**：
  - **判定：`no_fix_needed`**（不是可直接利用的缺陷，也不影响同凭证类型的往返）。
  - **触发条件**：`WireCipherProfile` 的 `domain_label` 非空、`domain = None`、凭证为 password。此时 `derive_domain_subkey_with_label(normalized, None, label)` 返回 `None`，密码被原样使用；文件密钥路径 `info_with_domain(label, None)` 返回 `label` 并参与 KDF（`format.rs:438`、`:515-528`、`:590`）。
  - **具体偏差**：两条路径的 KDF 输入相差 `domain_label` 的字节数（例如 `"hpos"` 为 4 B）；因此同一 label 下“密码派生的 master”与“文件密钥派生的 master”不相等。两个 profile 仅 label 不同且都用密码时，label 不产生分离（密钥相同）。
  - **不触发条件**：同一凭证类型（密码写→密码读、文件密钥写→文件密钥读）的 master 仍由同一路径派生，往返一致；不改变 wire 字段，不损坏文件。
  - **实际损害**：`domain_label` 是公开的 profile 常量，不是秘密；忽略它不降低机密性/完整性。只有产品明确承诺“无 domain 时 label 也必须分离密码密钥”时才算缺陷，那属于功能变更而非 bug。
  - **依据**：`format.rs:438`、`:515-528`，以及 `info_with_domain(b"hpos", None) == b"hpos"` 的既有测试。

### L-09 CLI 的 `preserve_time` 合并单向，无法覆盖 config 关闭

- **来源**：`rust_full_code_review_20261103_235007.md` P2-12。
- **现状证据**：
  - `rust/src/cli/cmd_structure.rs:165`：`let preserve_time = args.preserve_time && cfg.preserve_time.unwrap_or(true);`。
  - `rust/src/cli/args.rs:327`：只有正向 `preserve_time` 字段，没有 `--no-preserve-time`。
  - 对照：`cmd_structure.rs:166` / `cmd_stego.rs:431` 已有 `!args.no_backup && cfg.backup...`，说明 `backup` 已支持反向覆盖；`overwrite` 不来自 config。
- **影响**：config 中 `preserve_time=true` 时，命令行无法关闭时间保留。属体验/误用，不损坏数据。
- **最小方案**：新增 `--no-preserve-time`（`Option<bool>` 三态），合并规则改为“显式 CLI 优先，否则 config，否则默认”；同类 config 字段统一用三态 helper。改动：`cli/args.rs:327`、`cmd_structure.rs:165`。
- **测试**：config=true + `--no-preserve-time` 断言 mtime 变化；config=false + `--preserve-time` 断言保留；现有 CLI 测试全跑。
- **成本/风险**：S；只改 CLI 解析，不改库 API。
- **精确结论**：
  - **判定：`no_fix_needed`**（原描述“没有 `--no-preserve-time`、无法关闭”已过期）。
  - **触发条件（原描述）**：config `preserve_time=true` 且用户想关闭。当前 HEAD 的 `args.rs:326-327` 已定义 `--no-preserve-time`（`default_value_t = true, ArgAction::SetFalse`），传入后 `args.preserve_time = false`，`false && _ = false`，可以关闭。
  - **反向边界**：没有正向 `--preserve-time` 开关，因此 config 显式 `preserve_time = Some(false)` 时，CLI 无法强制开启；用户只能改 config。这是优先级设计（config 可否决默认开启），且不影响数据，属于能力边界。
  - **不触发条件**：不传 `--no-preserve-time` 时默认仍保留时间；`backup` 有独立的 `--no-backup`。
  - **实际损害**：0；不存在“无法关闭”的确定性路径。
  - **依据**：`cli/args.rs:326-327`、`cli/cmd_structure.rs:165`。原文档引用的 `args.rs:327` “只有正向字段”与当前代码不符。

### L-10 GUI 批量无逐项进度

- **来源**：`fixplan_20261104.md` P2-20；`strhide_comprehensive_code_review_report.md` REL-06。
- **现状证据**：
  - `gui/src-tauri/src/commands/batch.rs:41-96`：批量循环没有逐项 `ProgressEvent`，只在整体开始/结束发事件。
  - 同文件 `:97`：restore 任务固定 `backup: true`、`overwrite: true`。
- **影响**：大批量时前端无进度、无法定位失败项。`backup=true` 是 restore 的安全默认，属设计取舍，不计为缺陷。
- **最小方案**：新增 `batch-progress` 事件（`{current,total,path,status,error}`），循环每项 emit；不改 restore 的备份默认。改动：`gui/src-tauri/src/commands/batch.rs`、前端 batch 页面监听。
- **测试**：`pnpm test:e2e` 增加批量 3 项进度显示；`pnpm test:unit` 覆盖进度事件序列。
- **成本/风险**：S；只改 GUI，不牵涉 Rust 库 wire。
- **精确结论**：
  - **判定：`must_fix`**（确定性 UX/可观测性缺陷，不是“偶发”）。
  - **触发条件**：任意批量任务 `items.len() >= 2`；`batch.rs:41-96` 在循环内不发送任何事件，`core::batch::run_batch` 只在结束时返回 `BatchOutcome`。
  - **阈值/量化**：进度事件数恒为 0（与 N 无关）；失败项在整批结束前不可见。对 N=3 的批量，用户在整个耗时区间内看到的完成度始终是“0/3”或只有开始/结束；并发 `max_concurrency > 1` 时完成顺序也不对应提交顺序。
  - **不触发条件**：单文件任务（N=1）本来就有整体进度，不受影响；`restore` 的 `backup=true` 是安全默认，不计入本条。
  - **实际损害**：大批量（例如 100 张 50 MP 图片，单张数秒到数十秒）前端在整个耗时区间无反馈，用户会重复提交或强制退出；失败定位被推迟到全部结束。不损坏已成功项。
  - **最小方案**：循环每项发 `batch-progress {current,total,path,status,error}`；失败立即携带错误但继续批处理；不改 restore 备份默认。
  - **依据**：`gui/src-tauri/src/commands/batch.rs:41-96`、`rust/src/core/batch.rs` 的返回式结果收集。
  - **修复状态（2026-11-04 18:50）**：已修复。`run_batch` 新增 `progress: &dyn Progress`，每完成一项（含失败）发一个 `Stage::Batch` 事件（`done`/`total`），失败项仍写入 `BatchOutcome`；`run_batch_job_impl` 复用现有 `Control`/`ThrottledChannelProgress`，`Stage::Batch` 不受 16 ms 节流合并。交叉测试 `test_cross_batch_reports_one_progress_event_per_item` 断言 3 项（1 失败）恰好 3 个事件、`total=3`、最大 `done=3`；核心单测覆盖 8 项/3 失败的事件计数。未新增 UI 控件或事件结构。

### L-11 `from_seed_grouped` 列去重循环无上限

- **来源**：`rust_full_code_review_20261103_235007.md` P3-3。
- **现状证据**：`rust/src/stego/coding/stc.rs:355-380`（片段以代码为准）：`while cols.len() < distinct_patterns && cols.contains(&next)` 循环推进索引，没有迭代/周期检测上限。
- **影响**：理论上存在病态 seed/参数导致死循环；当前测试未复现（W-5），但这是低成本的防御性修复，且不改变正常路径输出。
- **最小方案**：循环增加最大迭代数（如 `u * 8` 或 4096）；超限时按确定顺序补齐缺失列（不依赖随机），并 `debug_assert!` 记录。改动：`stc.rs`。
- **测试**：构造/枚举小参数矩阵，断言函数总能终止且返回列集合完整；正常 golden 向量字节不变。
- **成本/风险**：S；若采用“顺序补齐”需确认不影响现有向量（用 baseline 检查）。
- **精确结论**：
  - **判定：`no_fix_needed`**（理论死循环在当前参数空间不可达，且无任何复现）。
  - **参数边界**：`validate_u_wide` 限制 `u ∈ 1..=64`；`distinct_patterns = 1 << (h-2) ≤ 256`。若 `u > distinct_patterns`，列数先达到上限，`while` 条件直接为假；若 `u ≤ 256`，序列 `idx = s + k·u` 由 splitmix64 双射映射到 64 位状态，完整周期为 2^64。
  - **量化**：`h=8`（D=64）时期望迭代约 `D·H_D ≈ 64·4.7 ≈ 300` 次；即使遇到最坏补集，也在 2^64 步内必然覆盖。按 10^9 次/秒计算，2^64 步 ≈ 584 年，远大于任何实际运行时长；且现有小参数矩阵测试未复现。
  - **不触发条件**：正常 h=4..10、u≤64 的所有路径均在毫秒级完成；`cols.len()` 达到 D 后循环按设计接受重复列。
  - **实际损害**：0；加迭代上限属于防御性 hygiene，不是缺陷修复。
  - **依据**：`stc.rs:355-380`、`KERNEL_MAX_U=64`、`distinct_patterns` 定义。

### L-12 `let _ =` 吞掉 seek 恢复失败 / 单次短读

- **来源**：`rust_full_code_review_20261103_235007.md` P3-11、P3-12。
- **现状证据**：
  - `rust/src/structure/adapters/io.rs:60`、`rust/src/formats/sniff.rs:333`：`let _ = reader.seek(SeekFrom::Start(pos / restore));`。
  - `rust/src/analysis.rs:296-297`：`let n = f.read(&mut head)?;` 单次读，未保证填满 1 MiB。
- **影响**：非常规 reader（短读、seek 失败）下，扫描结果可能漏检或位置错乱；普通文件不受影响。
- **最小方案**：seek 恢复失败返回 `StrHideError` 或记录 warning；前缀读取改为 `read_exact` 或循环 `read` 直到 `PREFIX_WINDOW` 或 EOF。改动：两处 `let _`、`scan_file`。
- **测试**：自定义短读 reader / 只读管道；断言扫描结果与完整文件一致，错误路径有明确错误。
- **成本/风险**：S；无 wire 变化。
- **精确结论**：
  - **判定：`no_fix_needed`**（对受支持的本机普通文件不可达）。
  - **触发条件**：`seek` 恢复失败需要自定义 `Read + Seek` 实现在已成功读取后拒绝回到起点；`f.read(&mut head)` 短读需要底层 `ReadFile`/`read` 在未到 EOF 时返回少于 1 MiB。
  - **阈值/事实**：Windows 上 `std::fs::File` 映射到 `ReadFile`，对本地 NTFS 常规文件一次读取请求的 1 MiB 前缀会填满或直接到 EOF；`SeekFrom::Start` 回到先前成功位置不会失败。`analysis.rs:296` 的 `PREFIX_WINDOW` 为 1 MiB，短读要造成漏检必须只返回极少字节且后续恰好有特征。
  - **不触发条件**：只有网络文件系统/杀毒过滤驱动/自定义 reader 会短读或 seek 失败；这些不在 CLI 的“普通文件”路径承诺内。
  - **实际损害**：0 个已知可复现输入；即使发生，结果是扫描漏检（误报“未隐藏”），不是错误修改。
  - **依据**：`structure/adapters/io.rs:60`、`formats/sniff.rs:333`、`analysis.rs:296-297`。

### L-13 临时载体文件沿用宽权限

- **来源**：`CODE-REVIEW-20261103.md` P1-10(b)。
- **现状证据**：
  - `rust/src/core/commit.rs:283-286`：原地嵌入先 `std::fs::copy(carrier_path, &tmp_path)`，临时文件继承载体的权限（常见 0644），随后仅 `make_writable`。
  - 同文件 `:318-324`：只有 rename 完成后才恢复原权限；临时文件在处理期间未收紧到 0600。
- **影响**：多用户/共享目录下，含载荷的临时载体在处理窗口内可能被同机其他用户读取（载荷加密时可读性限于密文，但仍暴露载体内容）。可达性取决于部署环境。
- **最小方案**：Unix 下创建后立即 `set_permissions(0o600)`；Windows 下使用用户私有临时目录并设置 ACL（或至少 `%LOCALAPPDATA%`）。改动：`core/commit.rs`。
- **测试**：Unix CI 断言临时文件 mode；Windows 手工/脚本检查 ACL。
- **成本/风险**：S；平台相关，需要 Windows ACL 验证。
- **精确结论**：
  - **判定：`no_fix_needed`**（临时文件不会比原载体更宽，且载荷在无凭证时本就可由最终文件提取）。
  - **触发条件**：Unix 共享目录 + 处理窗口内另一本地用户读取临时文件；Windows 需要目标目录 ACL 允许其他用户。
  - **权限事实**：`std::fs::copy` 在 Unix 复制源文件权限位，在 Windows 复制只读属性并继承目标目录 ACL；`make_writable` 只增加所有者写位。因此临时文件的可读范围 ≤ 原载体的可读范围，`rename` 后目标恢复原权限（`commit.rs:283-286`、`:318-324`）。
  - **量化**：临时窗口 = 载体写入/落盘时间；对 100 MB MKV 约数秒。即使被读取，暴露的是“原载体本来就允许读取的内容 + 隐藏载荷”；有密码时载荷是 AEAD 密文，无密码时同一用户也可直接从最终文件提取。
  - **不触发条件**：原载体为 0600 时临时文件同为 0600；Windows 单用户桌面默认目录只有当前用户可读。
  - **实际损害**：没有超出“原载体 + 最终文件”的增量披露；不构成需要修改的缺陷。若产品要求“处理中也不得暴露密文”，才需 0600。
  - **依据**：`core/commit.rs:283-286`、`:318-324`，以及 `fs::copy` 的权限语义。

### L-14 `ProbeOptions` 构造器未传 domain/extensions/suite

- **来源**：`rust_full_code_review_20261103_235007.md` P2-11（原判断“字段缺失”已过期，但构造器仍不填）。
- **现状证据**：
  - `rust/src/stego/options.rs` 的 `ProbeOptions` 已有 `domain`、`extensions`、`tuning`。
  - `rust/src/cli/helpers.rs:437-444`：构造 `ProbeOptions` 时只填 `password/key/safety/tuning/exact`，其余用 `..Default::default()`，未把 `args.domain`、`args.extensions`、`args.cipher_suite` 带入。
- **影响**：CLI/GUI 用带 extension 或自定义 domain/suite 的请求 probe 时，报告容量按默认值计算，可能多报或少报；embed 随后可能失败。
- **最小方案**：构造器补齐字段；为 `ProbeOptions` 增加 `from_embed_options()` 以避免两套字段漂移。改动：`cli/helpers.rs`、`stego/options.rs`。
- **测试**：`v4_probe_and_embed_agree_on_extensions` 已存在（`rust/tests/test_lifecycle/stego_jpeg_v4.rs:142`），扩展到 CLI 层：带 `--extensions`/`--cipher-suite` 的 probe 与 embed 结果一致。
- **成本/风险**：S–M；无 wire 变化。
- **精确结论**：
  - **判定：`no_fix_needed`**（CLI 当前没有可传入 extensions 的路径，suite 的 tag 长度相同，domain 不影响容量）。
  - **触发条件**：只有库调用方在 embed 时传非空 `extensions`、而 probe 用默认空 extensions 时，容量才会差；差值为 `header_slots(ext_bytes) - header_slots(0)`，量级是几十个槽位（每条 TLV 通常 < 64 B），仅在“恰好等于最大容量”的边界载荷上导致 embed 失败。
  - **不触发条件**：`cli/args.rs` 没有 `extensions`/`domain` 字段，`helpers.rs:437-444` 的 `ProbeOptions::default()` 与 embed 的默认值一致；`cipher_suite` 两个套件的 `tag_len()` 都是 `AEAD_TAG_LEN = 16`（`core/crypto.rs:58`、`:144`），不改变容量；`domain` 只参与密钥派生。
  - **实际损害**：0 个 CLI/GUI 可达路径；纯库 API 的边界误用，且 probe 与 embed 使用同一默认时结果一致。
  - **依据**：`cli/helpers.rs:437-444`、`cli/args.rs`（无 extensions/domain 参数）、`core/crypto.rs:58`。

### L-15 baseline 未覆盖 HEVC/HEIC 内容域

- **来源**：`stego_content_envelope_v4_review_independent_20261103.md` Minor 9。
- **现状证据**：
  - `scripts/baseline_hash.py:46` 与 `:355`：HEVC 内容域用例是 opt-in（`--include-content-hevc`）。
  - `temp/baseline/baseline.json:886`：`"include_content_hevc": false`，默认 `--check` 不比较 HEVC/HEIC 内容哈希。
  - HEVC 内容域回归目前依赖 `hevc_stress`，未进入字节基线。
- **影响**：HEVC 内容域重构可能绕过字节基线；属于测试覆盖缺口，不是运行时缺陷。
- **最小方案**：用现有开关重建基线：`python scripts/baseline_hash.py --write --include-content-hevc`，并让 CI 的 `--check` 带同一开关；仅在样本缺失时补样本。改动：基线数据 + CI 命令，无需改算法。
- **测试**：`python scripts/baseline_hash.py --check` 全绿；故意改一个 NAL 填充位应失败。
- **成本/风险**：M；需要真实 HEVC/HEIC 样本。
- **精确结论**：
  - **判定：`no_fix_needed`**（测试覆盖缺口，不是运行时缺陷）。
  - **触发条件**：HEVC/HEIC 内容域的写入逻辑发生字节级漂移，且改动者未运行 `hevc_stress`；此时默认 `baseline_hash.py --check` 不会报错。
  - **量化**：默认基线排除了 HEVC 内容用例（`scripts/baseline_hash.py:46`、`:355`，`temp/baseline/baseline.json:886 include_content_hevc=false`）；`hevc_stress` 已覆盖 MOV/MP4/HEIC 的并发往返，但没有冻结字节级输出。
  - **不触发条件**：当前没有已知算法缺陷；现有 HEVC 往返/压力测试通过。
  - **实际损害**：0（当前 HEAD）；风险是未来回归漏检。修复动作是把 `--include-content-hevc` 纳入 CI，而不是改源码。
  - **依据**：上述脚本行与基线字段。

---

## 4. 可选 / 低价值清单

| 编号 | 条目 | 一句话理由 |
|---|---|---|
| O-01 | `fixplan` P2-3：`StegoProfile` 单 `audio` 字段（WAV/FLAC 不能独立定制） | 真实能力缺口，但只有私有方言场景需要；拆分要动公共 API 与两套 profile，收益低于复杂度。 |
| O-02 | `CODE-REVIEW` M-5：公共类型缺 `#[non_exhaustive]` | API 卫生问题，无运行时损害；当前项目未发布，可在发布前一次性处理。 |
| O-03 | `fixplan` P2-15/16：音频重复解码、`cost O(33n)` | 纯长音频性能，需基准环境证明有实际损害；功能正确。 |
| O-04 | `fixplan` P2-19：`available_slots` 含 Superblock 的命名/语义 | 文档与字段命名问题；改名会牵涉展示层，实际容量计算已正确。 |
| O-05 | `rust_full` P2-16b：HILL 第二阶段 `O(p1²)` | 仅自定义 `p1>3` 时明显；默认参数无感。 |
| O-06 | `rust_full` P3-1：`chunk_index as u32` 截断 | 当前 payload 上限（内容域 64 MiB、结构域 1 GiB）下不可达；加断言即可，不必改协议。 |
| O-07 | `rust_full` P3-2：`derive_channel_header_mask` 命名误导 | 纯命名/文档，删“keystream”措辞即可。 |
| O-08 | `rust_full` P3-4：Feistel `guard > 64` 回退 `i % n` | 触发概率 2^-65 量级；改成错误返回反而增加代码路径。 |
| O-09 | `rust_full` P3-5：MKV stale CRC 跳过验证 | 只影响已损坏输入；严格拒绝可能把本可读文件判死，收益不明确。 |
| O-10 | `rust_full` P3-6：HEIF `thmb` 忽略 `to_item_IDs` | 需要真实 HEIC 缩略图样本才能确认可达性；无样本前不动。 |
| O-11 | `rust_full` P3-8：`panic = "abort"` 与 `TmpGuard` Drop | 崩溃路径才触发；可加启动清理，但收益低于复杂度。 |
| O-12 | `rust_full` P3-9：i18n 全局 `AtomicU8` vs 文档 thread-local | 文档措辞问题；GUI 单语言设置，无实际并发损害。 |
| O-13 | `rust_full` P3-10：byte 级公共入口位置参数 | API 一致性问题，需新增函数而非修 bug。 |
| O-14 | `rust_full` P3-13：文档/常量漂移合集 | 文档维护项；随 Release 前统一校对。 |
| O-15 | `CODE-REVIEW` L-4.2 / `V4` #20：`available_slots` 语义 | 同 O-04。 |
| O-16 | `CODE-REVIEW` L-4.5：内容域原地嵌入 `check_overwrite` 语义 | GUI 已在 `aca809f` 修复；库层保持当前语义可接受。 |
| O-17 | `V4 independent` Minor 7：GUI 缺 suite/extensions/key 字段 | 真实能力缺口，但需要完整 GUI 设计；当前 CLI 已覆盖核心场景。 |
| O-18 | `lib_interface_audit...` §3 的 8 项（命名/导出/`PayloadSource` 统一等） | 文档已自述历史；V4 已消化大部分，剩余为纯 API 风格。 |

---

## 5. 关闭清单

### 5.1 `fixed`（按文档/批次合并，commit 为证据）

| 问题簇 | 条目 | 修复 commit | 当前代码证据 |
|---|---|---|---|
| PNG 双域 coexist / stealth 包络 | comprehensive REL-02、XH-1、XH-15、R1 M-2、L-3 | `5822db0`、`a400696`、`6d4ccec` | `structure/adapters/png.rs` 使用 `expected_header_magic`（`:267-279`）；`find_iend_offset` 已有私有 chunk 逻辑 |
| 结构域写路径未 verify / 读上限 | R1 H-2、P0-1/P0-4、XH-3/XH-4 | `aeab1b4`、`a2ed294` | 写路径 `verify_structure`；`read_core` 限制 `MAX_VERIFY_PAYLOAD_SIZE` |
| GUI 路径穿越 / 缓存键 | comprehensive REL-01/REL-05、R1 M-9、fixplan P2-7 | `a2ed294`、`aca809f` | `sanitize_filename`；`smart_extract` 缓存键含 domain/prefer |
| GUI 原地嵌入 `check_overwrite` | R1 M-9、fixplan P2-7 | `aca809f` | `gui/src-tauri/src/commands/stego.rs` 仅目标不同才检查 |
| JPEG 容量探测 tightness / inspect 头校验 | XH-2/XH-12/XH-16、fixplan P1-1 | `146fde2`、`cedf97f` | `inspect_jpeg` 接收 `ExtractParams`；容量测试 `probe max must embed` |
| HEVC `has_inter` 全量路径、band | rust_full P1-5/P1-6 | `cedf97f`/`d4c8023` | `hevc/engine.rs:701/3451` 全量判定 |
| HEVC TargetSlots 之外的 P1 项 | rust_full P1-8/P1-9/P1-10a | `f718022`/`cedf97f`/`d4c8023` | 取消信号传播、CLI 控制字符转义 |
| 音频头校验 / P1-4 设计取舍 | rust_full P2-3（P1-4 归 not_a_defect） | `09f5d81` | 音频 embed/extract 先校验头 CRC，越界返回 `NoHiddenData` |
| 结构域 envelope AAD / 长度边界 | rust_full P0-2/P0-3 | `f718022` | `header_aad` 覆盖 meta/hint 长度；`validate_bounds` 先于分配 |
| FLAC 补偿 / MIN_UBE 推导 | rust_full P0-1、R1 M-1 | `f718022`、`78aa8f5` | `MIN_UBE_ENCRYPTED` 由 `framed_len` 推导；FLAC 补偿测试 |
| 外部文件非只读 / 批量覆盖 | comprehensive REL-03/REL-04、fixplan P2-19/P2-21 | `58ed85e`、`bb3755f` | 只读/符号链接拒绝；batch 目标集合去重 |
| PE 掩码 / 自动策略 / 策略解析 | comprehensive LOGIC-02、LOGIC-04、fixplan P2-9/P2-18 | `6d4ccec`、`bb3755f`、`863a030`、`58ed85e` | `StrategyChoice` TryFrom；`pe_codebits` feature gate；`id_to_strategy` |
| PDF / JAR 解析缺陷 | comprehensive LOGIC-03、rust_full P1-3/P3-12 | `70e3622`、`c8db5dd`、`d4c8023` | PDF 过滤器/签名字段；JAR EOCD 边界 |
| 变量 varint / 空密码 / 压缩头 | comprehensive LOGIC-05、FN-02、R1 M-8、fixplan P2-6/P2-12/P2-24 | `863a030`、`bb3755f`、`89ebeed` | `take_varint` 溢出拒绝；空密码过滤；文档对齐 |
| `DirectSpatial` / `wire_id` / 线程文档 / trace | comprehensive QUAL-01/02、fixplan P3-3/P3-4/P3-8 | `d466738`、`0a07776`、`edc4218` | `DirectSpatial` 分支已删；`StegoCodec::id()` 改名 `wire_id()`；线程数文档修正；trace `:?` |
| PNG 私有 chunk / 头 magic | rust_full P3-7 | `5822db0` | `expected_header_magic` 用于 header 分支 |
| PNG 解码器 / CRC / RGB | comprehensive LOGIC-07、fixplan P2-22 | `f718022`、`3edc3de` | CRC 校验；RGB 槽位按通道自身值过滤属设计取舍 |
| 音频 P2 批次 | rust_full P2-3/P2-4/P2-7/P2-8/P2-13/P2-14/P2-15/P2-18/P2-20 | `09f5d81`、`5f45926` | 音频头 CRC、限制检查、`catch_unwind` 回滚、HEVC 头覆盖 |
| `ProbeOptions` 字段 | rust_full P2-11（字段部分） | `d98797c` | `domain/extensions/tuning` 已存在（构造器问题见 L-14） |
| V4 阻断项 | V4 #1–#19 及 independent B1/B2/M1/M2/M3/M6 | `dfc69f95`、`a1b9467`、`477e356` | `WireCipherProfile`、HEIF bridge `opts.key`、PNG `NoHiddenData` 折叠、verify PBKDF2/PreparedCarrier |
| V4 低优先 | V4 #18/#19、independent Minor 2–6/#8/#10 | `a1b9467`、`89ebeed`、`24dcfd2` | WIRE_SPEC 音频 Hamming 标注；FLAC 槽位先检查；`FeatureWord` 已删（Minor 1 归 obsolete） |
| fixplan 批次 | P0-1..4、P1-1..3/5..8、P2-1/2/6/9/10/12/14/15/16/18/21/23/24/25、P3-3/4/7/8/10 | `aca809f`、`3b4644a`、`0a07776`、`3edc3de`、`d466738`、`863a030`、`bb3755f`、`a479640`、`55fd68c`、`edc4218` | 见 `docs/CHANGES-20261104.md` 对应批次；本轮抽查 `commit.rs`/`cli`/`strategy` 已符合 |
| 文档漂移 | R1 L-1、XH §5 13 条、fixplan P2-10/P2-24 | `89ebeed`、`24dcfd2`、`edc4218` | WIRE_SPEC 偏移/常量、版本号、支持格式列表已对齐 |
| 归档文档整体 | `docs/archived/**` | — | 历史存档，整体 `obsolete` |
| V4 final plan 执行项 | §11 7 blocking + 15 major | `dfc69f95` 等 | 已实现；§13 偏差（CLI `--key-file`/`--max-payload`）后来已修，原计划描述已过期 |

### 5.2 `obsolete`（描述前提已不存在）

| 条目 | 原因 |
|---|---|
| comprehensive FN-03 | V4 头格式重写，`FeatureWord` 位打包/越界前提已不存在。 |
| CODE-REVIEW L-2 | `derive_hevc_key` / `trellis_seed_from_key` 已在 V4 重构中移除，当前无全零密钥回退。 |
| XH-5 | 原判断基于旧实现；V4 后字段前提已消失。 |
| V4 independent M-4 | 密码路径已改为统一 `Credential`，原分支不存在。 |
| V4 independent Minor 1 | `FeatureWord`/`encode_header_word`/`V2_TOTAL_HEADER_SLOTS` 已删除（仅 `mipod.rs:32` 文档注释残留）。 |
| V4 final plan §13 偏差（2 条） | 计划文档称 CLI/GUI 字段未做，但 `--key-file`/`--max-payload` 已在后续批次实现；文档整体已过期。 |
| `lib_interface_audit_and_refactoring_plan_20261103.md`（整篇） | 文首已自述为历史审计，V4 已重写相关接口；剩余项为纯 API 风格。 |

### 5.3 `not_a_defect`（误判 / 设计取舍 / 能力边界）

| 条目 | 技术理由 |
|---|---|
| rust_full P1-4 | 全局音频参数“写了但不用”是有意保留的统一配置面，非缺陷。 |
| rust_full P2-2 | 只把 IDAT 放在首个 IDAT 位置，是 PNG 规范要求的连续 IDAT；非法输入（IDAT 间夹 ancillary）不在兼容范围。 |
| XH-8 / XH-13 | `0..rows-3` 是 3×3 邻域设计；NaN/inf 输入的拒绝属预期防御，不是缺陷。 |
| V4 #23 | `probe` 的 PBKDF2 固定迭代是“容量无关”的设计取舍，增加迭代不会改变容量。 |
| `fixplan` P2-19 | `available_slots` 字段语义虽有歧义，但容量数值按设计包含 Superblock；改名属 API 卫生（见 O-04/O-15）。 |
| comprehensive API-03 / `fixplan` P2-11 | AVIF/WebM 未支持是能力边界（无真实样本与规范实现），不是“声称支持却失败”。 |
| `fixplan` P2-17 | domain stealth 的 suffix 歧义已由“先 domain 后 null”的固定顺序消解，不是缺陷。 |
| `fixplan` P2-22 | `window_slices` 1.8 µs 的测量结论是“可接受开销”，不列为性能缺陷。 |

### 5.4 `unverified`（需补证据，本轮不下结论）

| 条目 | 缺什么证据 |
|---|---|
| `rust_full` W-1 ~ W-22 | 分别缺：真实畸形/超大样本、4K/8K RSS 基准、GB 级 I/O 剖析、签名 PE/PDF/JAR 样本、release fuzz 等；详见源文档第 1410 行附近表格。 |
| `comprehensive` LOGIC-06 | 缺真实 HEIF `item_hidden` 样本，无法确认“非隐藏主图”行为。 |
| `V4 independent` M-5（归入 open，不单列 unverified） | 5×2×2 suite/credential/ext 矩阵只补了部分 FileKey/extension smoke，缺完整组合断言。 |
| `V4 independent` Minor 7（归入 open，不单列 unverified） | CLI 已补 `--key-file`/`--max-payload`，GUI 仍无 suite/extensions/key 字段；需产品确认是否排期。 |

### 5.5 本轮由“值得做”降级为 `no_fix_needed`（10 条）

| 条目 | 判定理由（可复核） |
|---|---|
| L-01 HEVC inspect `has_inter` | 只有 `inspect` 文件入口走 1 MiB 前缀快路径；probe/embed 全量判定。误判需每帧 VCL 前有 ≥1 MiB 非 VCL 数据（正常 <2 KiB），且损害仅限 inspect 元数据。 |
| L-03 JPEG 几何块数 | 解码器按 MCU 填充网格分配块数组，`blocks.len() == grid_w*grid_h`；DNL/progressive 在 preflight 即拒绝。1001×767、999×777 的 probe 最大值 embed 实测通过。 |
| L-05 PNG 并行 deflate | 1024×1024 RGBA（filtered 4 MiB）实测 embed→extract SHA-256 一致、Pillow 可解码；缺的是回归测试，不是缺陷。 |
| L-08 无 domain 丢 label | 只造成“密码路径 vs 文件密钥路径”的跨凭证不等价；同凭证往返一致，label 非秘密，无机密性/完整性损失。 |
| L-09 `preserve_time` | 当前 `args.rs:326-327` 已有 `--no-preserve-time`（默认 true、SetFalse），可覆盖 config=true；原“无法关闭”已过期。 |
| L-11 STC 列去重无上限 | `u≤64`、`distinct_patterns≤256`，splitmix64 双射周期 2^64；实际期望迭代约 300 次，无复现，死循环不可达。 |
| L-12 seek/短读 | 本地 NTFS 上 `File::read` 填满 1 MiB 或到 EOF，`SeekFrom::Start` 回已成功位置不失败；仅自定义/网络 reader 可触发，且只导致扫描漏检。 |
| L-13 临时文件权限 | `fs::copy` 继承载体权限、`make_writable` 只加所有者写位；临时文件可读范围 ≤ 原载体，无增量披露。 |
| L-14 ProbeOptions 构造器 | CLI 无 extensions/domain 参数；两套件 `tag_len=16`；probe 与 embed 默认一致。仅库 API 非空 extensions 边界可差几十槽位。 |
| L-15 baseline 未含 HEVC | 测试覆盖缺口，当前无算法缺陷；修复方式是 CI 加 `--include-content-hevc`，不是源码缺陷。 |

---

## 6. 分批实施计划

### 批次 0（本轮已完成）：证据采集（不改生产代码）

- **目标**：已把 15 条从模糊结论变成可证伪结论。
- **已完成实测**：JPEG 12/24/50/100 MP RSS；50 MP 4 MiB 载荷；2×50 MP 并发；MKV 12/100 MB RSS；PNG >2 MiB 并行往返；JPEG odd-size probe 最大值 embed；DNL JPEG 拒绝；HEVC capacity vs embed 报告对比。
- **产物**：全部在 `temp/legacy_issues_samples/`、`temp/*.ps1`，未入库。
- **风险**：无生产改动。

### 批次 1：确定性小修复（S，先做）

- **条目**：L-04（MKV CRC 下沉到 HEVC 入口，S）、L-02（embed 用全量 probe 结果报告容量，S）、L-10（GUI 批量逐项事件，S）。
- **验证**：L-04 直接调用 HEVC 层写 MKV 后复算 CRC；L-02 断言 `capacity --json` 与 embed 报告一致（以 `video_12mb.mkv` 回归）；L-10 `pnpm test:e2e` 批量 3 项进度序列。
- **可交付**：三项独立 commit，可单独回退。
- **风险**：L-02 只改报告字段，不改 wire 与写入路径。

### 批次 2：内存（M–L）

- **条目**：L-06（去掉 `coeffs.clone()`、GUI `max_concurrency` 上限、`MAX_PIPELINE_BYTES` 可配置；M）、L-07 阶段 A（按 ≥2×file_size、实测 40× 预检并明确报错；S）、L-07 阶段 B（MKV patch 流式 + 槽位按 GOP 释放；L）。
- **验证**：重跑 12/24/50/100 MP RSS 与 12/100 MB MKV RSS；`baseline_hash --check` 全绿；GUI 并发 2/3 张 50 MP e2e。
- **可交付**：L-06 与 L-07A 可先发；L-07B 需要独立字节基线。
- **风险**：L-06 去 clone 必须保证字节级一致；L-07B 改 I/O 层，保留回退开关。

### 批次 3：可选测试覆盖（不修缺陷）

- **条目**：L-05（>2 MiB PNG 并行分支）、L-15（HEVC/HEIC 内容基线）、L-01（inspect 前缀边界样本）。
- **验证**：测试先红后绿；不改变生产代码。
- **风险**：样本体积大，放 `temp/` 或测试资产白名单。

---

## 7. 明确不做 / 需要外部输入

1. **不做**：`fixplan` P2-3（音频 profile 拆分）、P2-4（非穷尽枚举）、P3-6（HEVC 槽位复杂度）、P3-9（i18n 线程模型）——分别是能力边界、API 卫生、纯性能、文档措辞。
2. **`needs_data` 为 0**：L-01/L-03/L-05/L-09/L-11/L-12/L-13/L-14/L-15 已由代码事实或实测定论。仅 L-07 的“真实 4K 每 GB 槽位密度”需要基准来细化 40× 预检系数；不影响 `must_fix` 与 `2×file_size` 下界。
3. **可选测试仍缺样本**：`P3-6`/W-9（HEIC 缩略图）、`API-03`（AVIF/WebM）、L-15（HEVC/HEIC 基线）。
4. **需要基准环境**：`fixplan` P2-15/16（音频 CPU/RSS）、W-17/W-18/W-19（I/O 与内存剖析）。
5. **需要产品决策**：GUI 是否补齐 suite/extensions/file-key（Minor 7）；restore 是否允许关闭备份（L-10 的安全默认不改）。
6. **不建议本轮触碰**：`rust_full` P3-1/P3-4/P3-5/P3-8 的协议/错误语义改动，除非对应样本证明可达；避免为理论问题扩大失败面。

---

## 8. 文档归档建议（仅建议，未删除）

| 文档 | 建议 | 理由 |
|---|---|---|
| `docs/lib_interface_audit_and_refactoring_plan_20261103.md` | **归档** | 文首已自述历史，被 V4 方案取代，剩余项均为 optional。 |
| `docs/stego_content_envelope_v4_final_plan_20261103.md` | **归档** | 执行计划已完成，§13 偏差已过期。 |
| `docs/fixplan_20261104.md` | **归档（本文合入后）** | 其 48 条已被本文覆盖，保留作修复记录。 |
| `docs/CODE-REVIEW-20261103.md`、`CODE-REVIEW-xhx-20261103.md`、`strhide_comprehensive_code_review_report.md` | **归档（关闭项复核后）** | 高比例 fixed/obsolete，继续保留会重复制造“待办噪音”。 |
| `docs/rust_full_code_review_20261103_235007.md` | **保留** | 唯一仍有 19 条 open + 22 条 W 的活跃来源。 |
| `docs/stego_content_envelope_v4_review_20261103.md`、`..._independent_20261103.md` | **保留至 V4 收尾** | 仍有 3 + 4 条低优先项与 GUI 能力缺口。 |
| `docs/archived/**` | 保持归档 | 历史证据，不再作为待办来源。 |

> 按用户要求，以上仅为建议；本轮未删除或移动任何文件。

---

## 附录 A：逐文档状态明细（去重前）

| 文档 | `fixed` | `obsolete` | `not_a_defect` | `open` | `unverified` |
|---|---:|---:|---:|---:|---:|
| `strhide_comprehensive_code_review_report.md` | 21 | 1 | 0 | 12 | 1 |
| `CODE-REVIEW-20261103.md` | 14 | 1 | 0 | 4 | 0 |
| `CODE-REVIEW-xhx-20261103.md` | 12 | 1 | 2 | 1 | 0 |
| `rust_full_code_review_20261103_235007.md` | 24 | 0 | 11 | 19 | 22 |
| `fixplan_20261104.md` | 33 | 0 | 1 | 14 | 0 |
| `stego_content_envelope_v4_review_20261103.md` | 20 | 0 | 1 | 3 | 0 |
| `stego_content_envelope_v4_review_independent_20261103.md` | 13 | 2 | 0 | 4 | 0 |
| `stego_content_envelope_v4_final_plan_20261103.md` | 20 | 2 | 0 | 0 | 0 |
| `lib_interface_audit_and_refactoring_plan_20261103.md` | 0 | 1 | 0 | 8（optional） | 0 |
| **合计** | **157** | **8** | **15** | **65** | **23** |

> `rust_full` 的 19 条 open 中包含本文 L-01（P1-3）、L-03（P1-2）、L-04（P1-7）、L-06/L-07 等；`fixplan` 的 14 条 open 与本文 L-02（P1-4）、L-06（P2-5）、L-07（P2-17）、L-10（P2-20）重叠。交叉重复已在第 1.1 节说明。
