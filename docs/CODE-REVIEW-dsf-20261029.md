# strhide `rust/` 代码审查报告

- 审查日期：2026-10-29
- 审查对象：`c:\Home\Projects\strhide\rust\`（含 `src/{core,structure,stego,formats,analysis,cli,facade}` 与上游依赖 `dct-io`、`rusty_h265`、`oxideav_h265` 相关调用面）
- 审查方式：只读静态审查（分 4 组并行 + 主线复核），**未修改任何源码，未 commit/push**
- 基线对照：`cargo clippy --all-targets --all-features -- -D warnings` 退出码 0（无 lint），说明下述问题全部属于**编译器与 lint 看不见的语义/契约层缺陷**，不是风格问题

---

## 0. 结论摘要

| 严重度 | 数量 | 含义 |
|---|---|---|
| Critical | 4 | 静默数据不可读、或直接破坏载体文件（用户不会察觉） |
| High | 9 | 明确功能错误：错误分类、容量虚报、内存可被触发 abort、认证边界缺失 |
| Medium | 24 | 特定配置/特定载体下行为错误、明显浪费、诊断误导 |
| Low | 17 | 文案、一致性、死代码、可维护性 |

三条最该先修（都是"写的时候没人报错，读的时候才失败"）：

1. **PNG 排除率（`exclusion_percentile`）没进 wire 量化**：`--exclusion-rate` 只要不是 0.001 的整数倍，嵌入成功、提取必然返回 `NoHiddenData`。
2. **HEIF `item_hidden` 把所有 iloc extent 都平移 `delta_meta`**，且 meta 头长度硬编码 12 字节：带多 item / iloc v1/v2 的 HEIC 会被写坏。
3. **`thumb_bridge::reconstruct_heif` 只改 iloc 与顶层 box size，不处理 `stco/co64/saio`**：带轨道的 HEIF 在 `delta != 0` 时样本偏移全部失效。

---

## 1. Critical

### C-1 PNG 排除率只按 permille 回写，嵌入端却用原始 f64 → 写得出、读不回

- 位置：[engine.rs#L959-L960](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L959-L960)（嵌入端候选集）、[engine.rs#L1303](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1303)（写 permille）、[engine.rs#L1599-L1600](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1599-L1600)（提取端读 permille）、[params.rs#L203-L211](file:///c:/Home/Projects/strhide/rust/src/stego/params.rs#L203-L211)（`wire_quantized` 只量化 epsilon/sigma）
- 证据：

```rust
// 嵌入：用未经量化的原始 f64 决定候选前缀大小
let allowed_count =
    ((ranked.len() as f64) * (1.0 - params.exclusion_percentile.clamp(0.0, 0.9))) as usize;
// 写入：截断成 permille
exclusion_permille: (clamp * 1000.0) as u16,
// 提取：只有 permille 可用，反推回 f64
effective_params.exclusion_percentile = (fw.exclusion_permille as f64) / 1000.0;
```

- 问题：`params.wire_quantized()` 不包含 `exclusion_percentile`（[params.rs#L203-L211](file:///c:/Home/Projects/strhide/rust/src/stego/params.rs#L203-L211)），而载体自描述字段是 permille 整数。默认值 0.30 恰好 `0.3*1000 == 300` 无误差，所以测试与基线全绿；任何非 0.001 整数倍（如 `--exclusion-rate 0.0123`、`0.2999`）都会让两侧算出**不同的候选像素集合**，提取端在错误的槽位上找 header。
- 后果：嵌入返回成功、产物看起来正常，`extract` 返回 `NoHiddenData`。属于静默数据丢失，且用户没有任何信号。
- 修复方向：把 `exclusion_percentile` 也纳入 `wire_quantized()`（量化到 permille 并立即回填 `f64`），或在写 header 前强制 `params = params.wire_quantized()`（当前 [engine.rs#L1174](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1174) 已经这么做，但 `wire_quantized` 漏了这一项）。
- 顺带：`PngParams::validate()` 不校验 `exclusion_percentile` 值域（[params.rs#L244-L280](file:///c:/Home/Projects/strhide/rust/src/stego/params.rs#L244-L280)），只在用的时候 `clamp`，非法值被静默吞掉。
- 复现：`strhide embed --algorithm hill --exclusion-rate 0.0123 -p x in.png out.png` 后 `strhide extract -p x out.png`。

### C-2 HEIF `item_hidden` 无条件平移所有 iloc extent，且 meta 头长度硬编码 12 字节

- 位置：structure 域 HEIF 适配器（`item_hidden` 注入点）与 `isobmff_can_item_hidden`
- 问题：① 注入后 `meta` box 变大 `delta_meta`，代码对 **item 的所有 extent** 统一加 `delta_meta`；`iloc` 中只有"位于 meta 之后"的 extent 需要平移，位于 `mdat` 且物理位置在前的 extent（`construction_method == 0` 的绝对偏移）不该动。② meta 子 box 头长度按规范是 `4(size)+4(type)+version/flags(4)` = 12，但 `iloc` v1/v2 的 `offset_size/length_size/base_offset_size` 字段个数不同，`hlen` 必须按版本计算；硬编码 12 会把 `iloc` 内部字段写错位。
- 后果：多 item / 多 extent / iloc v1-v2 的真实 HEIC 会被写出**结构性损坏**（图能开、但缩略图/深度图/辅助 item 偏移错误），且 `write` 报告成功。
- 修复方向：按 item 判定 extent 是否在 `meta` 之后（比较 extent 绝对偏移与 `meta` box 起始），只平移受影响的；`hlen` 由 `iloc` version 与字段宽度推导，禁止字面常量。

### C-3 `thumb_bridge::reconstruct_heif` 不修 `stco/co64/saio`，`new_box_sz as u32` 静默截断

- 位置：[thumb_bridge.rs#L385-L475](file:///c:/Home/Projects/strhide/rust/src/stego/heif/thumb_bridge.rs#L385-L475)
- 问题：重建时只 patch `iloc` 与顶层 box 的 size；HEIF 里若存在 `trak`（时间元数据轨、Exif 轨），其 `stco`/`co64` 是 32/64 位绝对 chunk 偏移，`saio` 是辅助信息偏移——bridge 替换了 item payload 长度、后续数据整体位移，这些表全部失效。另外把 `new_box_sz` 直接 `as u32`，超过 4 GiB 时静默回绕。
- 后果：带轨道的 HEIC 在 `delta != 0` 时样本偏移错位（播放器/解析器报错或读到错误数据）；超大文件写坏 box size。
- 修复方向：bridge 写回时统一走"容器重建器"，遇 `stco/co64/saio` 全部做增量修正；`as u32` 前 `checked` 并回退到 64 位 `largesize`。

### C-4 HEVC 嵌入端丢弃"未完成切片"的槽位，提取端不丢 → 全局槽位编号可能整体错位

- 位置：[engine.rs#L2989-L2997](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L2989-L2997)
- 证据：

```rust
if recorder.mode() == RecordMode::Embed && recorder.next_pending_slot() != recorder.slots.len() {
    recorder.slots.clear();
    recorder.reset_pending();
    return;
}
```

- 问题：`RecordMode::Embed` 下切片解码中途截断时整片槽位被丢弃，防止"失同步槽位"进池；但 `Extract` 模式走同一函数却不触发该分支，提取端仍把这些槽位放进 `SlotSink`，后续所有切片的全局槽位索引因此偏移。
- 后果：命中该条件的载体写入成功、提取失败（AEAD/magic 失败被归成 `CorruptedData`，见 H-3）。
- 修复方向：把"是否接受未完成切片"做成两侧共享的判定（同一条件、同一动作），并在丢弃时提示"该切片不参与嵌槽"（embed 与 extract 都要按同一规则重建编号）。

---

## 2. High

### H-1 `stsz` 固定样本尺寸路径无数量上限 → 单个 12 字节字段可触发 16 GiB 分配

- 位置：[mp4_boxes.rs#L502-L513](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/mp4_boxes.rs#L502-L513)
- 证据：`if fixed != 0 { return Ok(vec![fixed; count]); }`
- 问题：`count` 直接来自文件（`sample_count` u32），`vec![fixed; count]` 在 32 位/`u32::MAX` 时可申请 16 GiB。Rust 分配失败是 abort，不是可捕获错误。
- 后果：任何畸形 MP4/HEIC 都能让 `probe/extract` 进程直接退出（不可控 DoS）。
- 修复方向：与样本总数、`mdat` 实际长度做交叉校验（`count * fixed <= mdat_len`），并给出显式上限。

### H-2 PNG 解码没有任何像素/工作集预算

- 位置：[engine.rs#L262-L287](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L262-L287)
- 证据：`let expected = stride.checked_mul(height)...`（只查 usize 溢出）→ `ZlibDecoder::take(expected as u64 + 1)` → `Vec::with_capacity(stride * height)`。
- 问题：IHDR 允许 65535×65535。RGBA 时 `expected ≈ 17.18 GB`，`take()` 会真的把 17 GB 拉进内存；JPEG 侧有 `MAX_PIPELINE_BYTES = 8 GiB`（[engine.rs#L96](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L96)）对照，PNG 侧没有任何等价物。
- 后果：一张几十 KB 的畸形 PNG 就能 OOM/abort。
- 修复方向：加入与 JPEG 同口径的 `MAX_PIXELS` / `MAX_WORKING_SET`，并把 `total_pixels * channels` 的乘加全部 `checked`。

### H-3 容量探针不套用流水线内存预算，超过约 150 MP 后"探针说能装、写入说装不下"

- 位置：JPEG 侧 [engine.rs#L1542](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L1542)、[engine.rs#L1561](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L1561)，对照 [engine.rs#L167](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L167)、[engine.rs#L1654](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L1654)
- 问题：`probe` 只按槽位数算 `max_payload_bits`，不调用 `check_pipeline_budget`。`embed` 的预算是 `base_bytes + body_n * 32B`（`estimate_backtrack_bytes`，h=8），`MAX_PIPELINE_BYTES = 8 GiB`。4:2:0 下总成本约 56 B/槽位，`n_total > ~152M`（≈155 MP）即越界。
- 后果：`MAX_JPEG_MCU_COUNT = 1,048,576`（≈268 MP）下 probe 报 ~33 MB，embed 实际只能 ~8.5 MB 并报 `UnsupportedFormat`；`is_estimated: false` 让这个数字看起来是精确值，调用方按探针挑 payload 会直接失败。
- 修复方向：probe 内复用 `check_pipeline_budget` 反推可用 `body_n`，或让两处共用同一个 `layout_for_payload`。

### H-4 HEVC 缺槽/魔数不匹配被报成 `CorruptedData` 而非 `NoHiddenData`

- 位置：[engine.rs#L1498-L1542](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L1498-L1542)
- 问题：干净载体（槽位不足）与口令错误（magic 不匹配）都返回 `CorruptedData`。
- 后果：`extract` 对"没有隐藏数据"与"文件损坏"给出同一错误，CLI 的提示/退出码语义混乱，用户会误以为视频坏了。
- 修复方向：按三态区分 `NoHiddenData` / `WrongCredential`（或保持统一但附带结构化 `reason`）。

### H-5 信封 AAD 只覆盖前 80 字节，注入坐标不进认证

- 位置：[envelope.rs](file:///c:/Home/Projects/strhide/rust/src/structure/envelope.rs) 112B header 的 AAD 构造
- 问题：`inject_offset / inject_size / patch_offset / orig_patch_val / meta_len / hint_len` 不参与 AAD（仅 `validate_against` 做一致性校验）。
- 后果：这六个字段是"还原指令"，被篡改后 AEAD 仍然通过；`validate_against` 只能发现自相矛盾，发现不了"自洽但指向别处"的改写。最坏情况是按攻击者指定的偏移写回原文件。
- 修复方向：把 112 字节 header 全量纳入 AAD（GCM 的 AAD 本来就是给这种元数据用的），版本号允许内部重排但要在文档里固定。

### H-6 `analysis` 自带一套嗅探，和 `formats::sniff` 分叉；多数容器完全漏报

- 位置：[analysis.rs#L519-L539](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L519-L539)、[analysis.rs#L348-L476](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L348-L476)、[analysis.rs#L1086-L1090](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L1086-L1090)、[sniff.rs#L268-L294](file:///c:/Home/Projects/strhide/rust/src/formats/sniff.rs#L268-L294)
- 证据：`&data[4..8] == b"ftyp"` → 一律 `"MP4"`；`Some("PNG") => {}` / `Some("JPEG") => {}` / `_ => {}`；`track_trailing_entropy` 对 `ZIP|MP4|PDF|HEIF|MKV` 显式关闭。
- 问题/后果：① HEIC/AVIF 被标成 MP4；② HEIF/MP4/WEBP/WAV/MKV/ZIP/PDF 的**追加型隐藏**（`cat payload >> file`）产出 0 条 finding，verdict 仍 `clean`，**且不提示"该类载体未做检测"**；③ 同一文件在 `scan` 与 `embed` 路由里可能得到不同格式名。
- 修复方向：`analysis` 直接调用 `formats::sniff::sniff_bytes`（单一真源）；对无检测器的格式统一 push `DetectorMetric{status:"SKIPPED"}` 并在 notes 里写明覆盖范围。

### H-7 "已确证的追加数据"只给 Suspicious，verdict=`low`、退出码 0

- 位置：[analysis.rs#L246-L250](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L246-L250)、[analysis.rs#L479-L484](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L479-L484)、[cmd_diag.rs#L443-L448](file:///c:/Home/Projects/strhide/rust/src/cli/cmd_diag.rs#L443-L448)
- 证据：`severity = if ent >= 7.0 && trailing >= 32 { Likely } else { Suspicious }`；`Ok(if likely_hidden { 1 } else { 0 })`
- 问题：IEND/EOI 之后有字节是**结构上确证**的事实，却按尾部熵分档。低熵追加（`copy /b img.jpg + secret.txt`）只有 25 分 → `low`；即使两条 Suspicious（50）也只到 `suspicious`，**仍然 exit 0**。
- 后果：`scan -q` 无法作为 CI 门禁；人类可读输出把确证事实标成 LOW。PNG 的 `png:trailing-data` 同样按 Suspicious 分档。
- 修复方向：追加数据至少 `Likely`（长度/熵只影响 detail）；新增 `--fail-on {low,suspicious,likely}`（默认保持现状，避免破坏脚本）。

### H-8 4 分量 / 16-bit 的通道数错配

- 位置：[calibration.rs#L168-L180](file:///c:/Home/Projects/strhide/rust/src/analysis/calibration.rs#L168-L180)、[analysis.rs#L1258-L1274](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L1258-L1274)
- 证据：`let channels = if actual.components.len() == 1 { 1 } else { 3 };` 对照 `PixelFormat::CMYK32 => 4, PixelFormat::L16 => 2`
- 问题：CMYK 实际 4 通道、L16 实际 2 字节/样本，却按 1/3 推 `height = pixels.len()/(width*channels)`，得到 `4h/3` 或 `2h`；`luma_plane` 的边界检查恰好能通过，于是按错误步长取样。
- 后果：`height % 3 != 0` → `None` 但 SKIPPED 理由写 "q100"；整除时输出**带百分比的无意义 rate**，可能虚假 ALERT 或虚假 PASS。
- 修复方向：`decode_jpeg_pixels` 返回的 `channels` 作为唯一真源；`channels==4 || channels==2` 显式 SKIP 并附原因；与 JPEG 侧 `components_mask` 恒 `COMPONENT_Y` 一并决定是否直接拒绝非 1/3 通道内容域嵌入。

### H-9 4 分量 / 16-bit 宁可静态拒绝也不该"猜"（与 H-8 同源的写侧）

- 位置：[engine.rs#L837](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L837)（`components_mask: COMPONENT_Y`）
- 问题：字段在 `check_reserved` 只接受 `COMPONENT_Y`，等价常量；4 分量文件的分量 0 是 C 而非 Y，代价图与 `luma_q` 三层语义都对不上。
- 修复方向：改名 `COMPONENT_0`，或对 `ncomp != 1 && ncomp != 3` 直接拒绝内容域嵌入。

---

## 3. Medium

### 3.1 core / 加密 / 信封 / 批处理

| ID | 位置 | 问题 | 后果 / 修复方向 |
|---|---|---|---|
| M-1 | [batch.rs#L117](file:///c:/Home/Projects/strhide/rust/src/core/batch.rs#L117) vs [batch.rs#L163-L166](file:///c:/Home/Projects/strhide/rust/src/core/batch.rs#L163-L166) | 串行路径用 `e.detail_i18n()`（无 `ctx`），并行路径用 `detail_i18n_with_ctx(ctx)` | 同一错误在单/多线程下文案不同（占位符缺失）。统一调用带 ctx 版本 |
| M-2 | [helpers.rs#L674-L682](file:///c:/Home/Projects/strhide/rust/src/cli/helpers.rs#L674-L682) vs [stc.rs#L78](file:///c:/Home/Projects/strhide/rust/src/stego/coding/stc.rs#L78) | `--algorithm auto` 的 `describe` 硬编码 `stc_h: 7`，实际 `DEFAULT_STC_H = 8` | CLI 显示与真实参数不符；`auto` 还忽略 `--stc-h/--stc-u` 等调参旗标 |
| M-3 | [commit.rs](file:///c:/Home/Projects/strhide/rust/src/core/commit.rs) | `commit_carrier_patches` 不校验 patch span 与目标文件长度 | 越界写会得到 `Err` 或写坏尾部；应在写入前校验 `offset+len <= file_len` |
| M-4 | [fs.rs](file:///c:/Home/Projects/strhide/rust/src/core/fs.rs) | `sanitize_filename` 只剥 `/ \ :`，未处理 Windows 保留名（CON/PRN/AUX/NUL/COM1…）与前后点号 | 恢复名为 `CON` 时写到设备名或直接失败 |
| M-5 | [pipeline.rs](file:///c:/Home/Projects/strhide/rust/src/core/pipeline.rs) | `check_overwrite` 与真正写入之间存在 TOCTOU（先 canonicalize 判重再写） | 并发场景下可能覆盖刚出现的文件 |
| M-6 | [config.rs](file:///c:/Home/Projects/strhide/rust/src/core/config.rs) | `KNOWN_KEYS` 只校验顶层，`[stego]` 未知键静默忽略；CWD 配置**整体覆盖**用户配置而不合并；CWD 配置含密码只告警 | 拼错键名无任何提示；`~/.config` 的通用设置被项目目录配置悄悄丢掉 |
| M-7 | [crypto.rs](file:///c:/Home/Projects/strhide/rust/src/core/crypto.rs) | `make_chunk_nonce` 只 XOR 低 32 位 chunk index；`BUILTIN_DEFAULT_KEY` 是公开常量；stealth 每次 read ≥2 次 PBKDF2 | 无口令时"加密"实为混淆（应在文档与 `--help` 明说）；`chunk_size ≤ 64 MiB` 下需 256 PiB 才可能复用 nonce，实际不可达但应注释上界 |
| M-8 | [envelope.rs](file:///c:/Home/Projects/strhide/rust/src/structure/envelope.rs) | `EnvelopeTrailer::unpack` 在 stealth 模式接受"掩码 CRC" | 减弱 trailer 完整性；建议 stealth 下也校验未掩码 CRC 或改用 HMAC |
| M-9 | [payload.rs](file:///c:/Home/Projects/strhide/rust/src/core/payload.rs) | `Payload::name/kind` 本阶段不上线，仍贯穿所有 API | 死路径增加理解成本；建议 `#[doc(hidden)]` + 注释，或收进 feature |

### 3.2 structure 域与格式适配器

| ID | 位置 | 问题 | 后果 / 修复方向 |
|---|---|---|---|
| M-10 | `isobmff_can_item_hidden` | 用 `pos + 12` 判断 meta 子 box，忽略 `hlen` | 与 C-2 同源；能力探测与真实注入不一致 → `auto` 误判 |
| M-11 | iloc 解析 | `offset_size/length_size/base_offset_size == 0` 是合法（字段省略），但写入端不支持 | `auto` 策略在该类文件上硬失败，无回退 |
| M-12 | `choose_auto_strategy` | 失败后无二次回退 | 首选策略失败即整体失败，用户需手工指定 |
| M-13 | structure 主流程 | 整宿主读入内存；扫描上限 1 GiB | 大 MP4/HEIC 内存翻倍；流式化或 mmap |
| M-14 | `read_box_size` | `as usize` 与 `pos + bsize` 未 `checked` | 32 位或畸形 box 可整数回绕 |
| M-15 | `check_jar_signature` | 不支持 ZIP64（`zip64_eocd`），漏检签名；一次性分配 `cd_size` | 大 JAR 上"无签名"结论不可信 + 内存尖峰 |
| M-16 | `check_pe_authenticode` | 未校验 `size_of_opt_header` | 畸形 PE 上读到错误目录，结论错误 |
| M-17 | MKV/RIFF `verify_structure` | 硬编码 standard trailer magic | 私有 dialect 写入的文件 `verify` 假阴性 |
| M-18 | PDF locate | 搜索窗口 ×4 增长直到全文 | O(n²) 级扫描；大 PDF 明显变慢 |
| M-19 | PDF xref | `{:010}` 固定 10 位；>10 GB 时变 21 字节 | 超大 PDF 的 xref 写坏 |
| M-20 | ZIP/ISOBMFF `strip` | 硬编码 `strategy_id` | 与写入记录不一致，`read` 端可能拒认 |
| M-21 | PE 适配器 | 只读前 64 KiB | 超出即静默退化到不可注入，且无提示 |
| M-22 | PDF 签名检查 | 要求 `%PDF-` 位于 offset 0 | 带前导垃圾（真实世界常见）的 PDF 漏检签名 |

### 3.3 PNG / HILL

| ID | 位置 | 问题 | 后果 / 修复方向 |
|---|---|---|---|
| M-23 | [engine.rs#L431-L459](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L431-L459) | deflate 分块数取 `rayon::current_num_threads()`，直接影响输出字节 | 违背 `Freshness::Seeded` 的 byte-identical 承诺；`baseline_hash --check` 跨核数不一致。固定分块数（或按字节而非线程划分） |
| M-24 | [engine.rs#L192-L196](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L192-L196) | 无条件拒绝任何 PLTE chunk，包括 RGB/RGBA 的 suggested palette | 大量真实 PNG（优化器会写 PLTE 建议调色板）被无理由拒绝 |
| M-25 | [engine.rs#L229](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L229) | `pos = body_end + 4; // Skip CRC` 不校验 CRC | 损坏载体被当作合法；写出后无法定位是输入坏还是自己坏 |
| M-26 | [engine.rs#L1174](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1174) / [params.rs#L244-L280](file:///c:/Home/Projects/strhide/rust/src/stego/params.rs#L244-L280) | `PngParams::validate` 不校验 `exclusion_percentile` | 与 C-1 同源；非法值被 `clamp` 吞掉 |

### 3.4 JPEG

| ID | 位置 | 问题 | 后果 / 修复方向 |
|---|---|---|---|
| M-27 | [geometry.rs#L40-L49](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/geometry.rs#L40-L49) + [jpeg_segments.rs#L44-L103](file:///c:/Home/Projects/strhide/rust/src/formats/jpeg_segments.rs#L44-L103) | DQT 解析失败静默回退 Annex K | 常见 q≈75 与 Annex K(q≈50) 差 1.5–2 倍，`cost=q[k]/block_rho` 排序整体偏移，代价图"看起来正常"；应在 `estimate/capacity` 暴露 `luma_q_source: file|fallback` |
| M-28 | [engine.rs#L617](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L617)、[geometry.rs#L84-L96](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/geometry.rs#L84-L96) | 多扫描/非交织 JPEG 在**整幅代价图 + trellis 求解之后**才因块数不符报错，且归为 `CorruptedData` | 大图浪费数十秒；应在 `preflight_jpeg` 里数 SOS，>1 直接 `UnsupportedFormat` |
| M-29 | [engine.rs#L262-L264](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L262-L264)、[stc.rs#L147-L161](file:///c:/Home/Projects/strhide/rust/src/stego/coding/stc.rs#L147-L161) | 跨零惩罚 `1e13 * 1e3 = 1e16`，`ulp(1e16)=2.0` > 正常代价量级 | 一旦付过惩罚，后续 `<2` 的增量被舍入吞掉，DP 退化为"数惩罚"；`wet_cost` 调大还会推到 `inf` → 行为突变。改成 `(penalty_count, cost)` 字典序 |
| M-30 | [analysis.rs#L872-L907](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L872-L907) | 大文件取尾窗内"最后一个 `FF D9`"当 EOI | 密文里平均每 64 KiB 就有一个 `FF D9` 字节对，trailing 被系统性低估，`Likely` 会降级成 `Suspicious` |
| M-31 | [analysis.rs#L461-L476](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L461-L476)、[analysis.rs#L1128-L1200](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L1128-L1200) | PNG 16-bit / Adam7 / 超限 inflate 时一个检测器行都不 push | 报告仍 `clean` 且无"未检测"提示，与 JPEG 至少输出 `dct:calibration SKIPPED` 不一致 |
| M-32 | [analysis.rs#L1633-L1658](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L1633-L1658) | `dct:chi2` 返回 `None` 时整行消失；`dct:calibration` 的 SKIPPED 文案固定写 "q100" | 漏报不可察觉；排障被误导（真实原因可能是渐进 JPEG/缺 DQT/图太小/通道数不整除） |
| M-33 | [analysis.rs#L1789-L1812](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L1789-L1812)、[analysis.rs#L1818-L1880](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L1818-L1880) | RS 把"测得 0"映射成 `None`，SPA 失败返回 `0.0` 却计入均值 | 同一幅图两种口径；SPA 的 pooled rate 偏低 → 漏报。统一返回 `Option<f64>`，只在有效 slab 求均值 |
| M-34 | [analysis.rs#L1452-L1570](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L1452-L1570)、[analysis.rs#L1685-L1703](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L1685-L1703)、[analysis.rs#L1886-L1897](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L1886-L1897) | WS/RS/SPA 共用 0.70 阈值，`chi2` 映射 `*4.0`，WS 只给 Info(2 分) | RS+SPA+chi2 = 75 直接进 `likely-hidden`（exit 1）→ 干净 PNG 误报；单靠 WS 强信号又不影响 verdict。需按检测器实测 FPR 重标定，改"至少两个独立检测器" |
| M-35 | [analysis.rs#L1258-L1274](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L1258-L1274)、[calibration.rs#L148](file:///c:/Home/Projects/strhide/rust/src/analysis/calibration.rs#L148) | `scan` 对同一 JPEG 解码三次（`read_coefficients` ×2 + 全像素解码）；分析侧不调用 `preflight_jpeg` | CPU 2–3×；单文件峰值远超 engine 的 8 GiB 口径且无保护。一次解码复用 + 分析侧同样加 MCU/像素预算 |

### 3.5 HEVC / HEIF 容器

| ID | 位置 | 问题 | 后果 / 修复方向 |
|---|---|---|---|
| M-36 | [slot.rs#L134-L157](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/slot.rs#L134-L157) | 注释称 32 B/slot，紧邻的 `const _: () = assert!(size_of::<StegoSlot>() == 16);` 是 16 | 文档与实测内存口径（AGENTS.md）对不上，后续优化容易误判 |
| M-37 | [engine.rs#L125-L136](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L125-L136) | Superblock 的 `reserved` 字段 decode 后不校验必须为 0 | 版本演进时旧/新头无法区分；建议非 0 直接拒绝 |
| M-38 | [engine.rs#L2989-L2997](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L2989-L2997) | 丢弃未完成切片时无任何可观测信号（trace 都没有） | C-4 触发时用户无从判断"为何容量比 probe 少" |

---

## 4. Low

| ID | 位置 | 问题 |
|---|---|---|
| L-1 | [engine.rs#L2000-L2009](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L2000-L2009) | PNG `Auto` 固定报 `expected_stc_change_rate(3)` 且 `is_estimated: false`，与实际参数无关 |
| L-2 | [engine.rs#L1303](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1303) | permille 用 `as u16` 截断而非四舍五入（C-1 修复时一并处理） |
| L-3 | [engine.rs#L884-L901](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L884-L901) | 扩展区 `embed_slots(...)?` 未复用"Huffman 表过度优化"的友好文案（superblock/body 都有） |
| L-4 | [engine.rs#L1550-L1558](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L1550-L1558) | probe 展示用的 `u` 未过 `grouped_body_budget` 的 `u>=3` 抬升，`estimated_change_rate` 自相矛盾 |
| L-5 | [engine.rs#L1383-L1395](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L1383-L1395) | `inspect_jpeg` 未过 AEAD 即报 `has_hidden_data: true`；默认口令公开时可构造"结构合法、body 认证失败"的假头 → `inspect` 与 `extract` 结论矛盾 |
| L-6 | [engine.rs#L837](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L837) | `components_mask` 恒 `COMPONENT_Y`（同 H-9） |
| L-7 | [sniff.rs#L206-L208](file:///c:/Home/Projects/strhide/rust/src/formats/sniff.rs#L206-L208) vs [analysis.rs#L523-L525](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L523-L525) | `is_jpeg_bytes` 只认 2 字节且优先级最高，`analysis` 用 3 字节；`FF D8 00 …` 会被送进 JPEG 适配器报"损坏" |
| L-8 | [sniff.rs#L175-L198](file:///c:/Home/Projects/strhide/rust/src/formats/sniff.rs#L175-L198) | `is_heif_bytes` 硬性要求首 box 为 `ftyp`，而 MP4 白名单允许 `free/skip/wide/uuid` 开头 → 前置 filler 的 HEIC 被判 `Mp4`（待真实样本验证） |
| L-9 | [jpeg_segments.rs#L128-L141](file:///c:/Home/Projects/strhide/rust/src/formats/jpeg_segments.rs#L128-L141) | `len < 8` 放过 `8..10` 的畸形 SOF；取"第一个 SOF"在 MPO/多图文件可能取到子图 `Tq` |
| L-10 | [analysis.rs#L966-L975](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L966-L975) | `>1 SOS` 一律写成 "progressive JPEG"，顺序式非交织多扫描也被误标 |
| L-11 | [jpeg/cost/uerd.rs#L1-L30](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/cost/uerd.rs#L1-L30) | UERD/J-UNIWARD 与论文的偏差已文档化，但仓库内缺 DCTR/CC-JRM 评测，抗检测性只有"自洽 + 单测"保证 |
| L-12 | [cmd_diag.rs#L443-L448](file:///c:/Home/Projects/strhide/rust/src/cli/cmd_diag.rs#L443-L448) | `scan` 退出码只认 `likely-hidden`（与 H-7 合并处理） |
| L-13 | structure `remove_core` | 重复 PBKDF2 派生同一子密钥（`write` 时已算过一次） |
| L-14 | structure PDF 签名检查 | `%PDF-` 必须在 offset 0（真实世界 PDF 常带前导垃圾） |
| L-15 | [engine.rs#L125-L136](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L125-L136) | Superblock `reserved` 不校验（同 M-37） |
| L-16 | [payload.rs](file:///c:/Home/Projects/strhide/rust/src/core/payload.rs) | `Payload::name/kind` 未上线但仍贯穿 API（同 M-9） |
| L-17 | [crypto.rs](file:///c:/Home/Projects/strhide/rust/src/core/crypto.rs) | `verify_payload_stream` 1 GiB 上限是硬编码，未与 `LocalParams::chunk_size` 联动 |

---

## 5. 已复核确认"不是问题"（避免后续重复排查）

以下是我或分组审查逐条核对后**确认正确**的主干，改动时若不慎会重新引入问题：

**密码学 / 信封**
- PBKDF2 迭代次数、HKDF 子密钥标签、chunk nonce 构造、stealth magic 派生在 write/read 两侧对称。
- `decrypt_stream_from_chunks` 以 `bytes_consumed >= total_payload_bytes` 判末块；`decompress_stream` 用 AEAD 保护的 `raw_size` 作为膨胀上限（不会成为 zip-bomb 放大器）。
- AEAD 成功之后才报 TLV/`CorruptedData`；`ExtractParams::allows_suite` / `max_pbkdf2_iterations` 在 KDF 之前生效 —— 口令 oracle 防护到位。

**JPEG**
- `slot↔coeff` 映射 `idx/63, idx%63+1`、`grid_indices`/`fill_body_grid` 的升序补集、`hdr_n ≤ n_total` 与 `body_n ≤ body_grid_len` 越界防护正确。
- `2|(c&1)` 与提取端 `c&1`（含负数，`-3 & 1 == 1`）一致；`|c|=1023` 只单向、`apply_deltas` 以 `i32` 计算 —— 无溢出。
- 两阶段 Fisher-Yates（`0..hdr_min` + `hdr_min..hdr_n`，同一 RNG）与一次性 `permute_prefix(..hdr_n)` 等价（有契约测试）；`body_keys`/`stc_seed`/`hdr_seed`/`-hdr`/`-ext` 派生对称。
- Huffman 合法性：`is_complete`（162 符号）、`symbol_ok` 的 ZRL 分块与 `(run%16, cat)`、`(true,false)` 合并游程、`(false,true)` 插入后 EOB、`category()` 封顶 15 —— 与 `dct-io` 编码器逐条一致。
- MCU 交织几何（`mr/mc/dv/dh` 重放）与 `dct-io` `block_counts = n_mcu * du_per_mcu` 等价（probe 用补齐网格算容量**不是**虚报）；`parse_dqt_tables` 的 zigzag→natural 与代价模型 `q[k]` 的 natural 顺序一致。
- 重试闭环：`applied` 每 attempt 新建，失败必 `rollback` 后才重试（hdr/ext/body 共用同一日志、slot 集合互斥）；只有 `embed_once` 返回 `Ok` 才产出 bytes —— 无半成品输出。
- `extract_jpeg` 无 `JpegParams` 入参，`h/u/envelope_len/ext_bytes/salt/nonce/suite` 全部取自 superblock（载体自描述），不从默认值推定。
- `v3_layout::compute` 在 `bits>0` 时 `window ≥ 15`、`u ≥ 1`，除零与 `u=0` 不可达。
- 组件槽位数 718 = `sb_u*(352+sb_h-1)` 与 `header_slots(ext_bytes)` 写读同式。

**PNG**
- HILL 成本图在 header/feature 像素只改 `val&0xF8` 类内值，提取端因此能算出 bit-identical 代价图；`select_nth_unstable` 的 `(cost_bits, index)` 全序与旧 `sort_by` 等字节。

**HEVC**
- BinOp 打包（2 B/bin）与槽位 16 B 的字段宽度足以覆盖 179 个上下文；`CTX_MAX` 饱和后由重编码器范围检查兜住，不会静默用错模型。

**CLI**
- `resolve_password` 优先级链 `-p → password-file → STRHIDE_PASSWORD → config.password → config.password_file → 交互提示`；`unescape_string` 八进制/`\x`/`\u`/`\U` 逐项核对正确；clap 参数组互斥生效。

---

## 6. 修复优先级建议

**P0（发布前必修，都是静默错误）**
1. C-1：`exclusion_percentile` 进 `wire_quantized`（一行改动 + 一条非整 permille 的回归测试）。
2. C-2 / C-3：HEIF iloc `hlen` 按版本推导、只平移受影响的 extent；bridge 重建统一处理 `stco/co64/saio`。
3. C-4：HEVC 两侧在同一条件、同一动作下处理未完成切片。
4. H-1 / H-2：给 `stsz` 固定尺寸与 PNG 解码加"与文件实际数据量交叉校验 + 绝对上限"。

**P1（正确性/语义）**
5. H-3 容量探针与 embed 共用预算；H-4 三态错误；H-5 信封 AAD 覆盖全 112B。
6. H-6 嗅探单一真源 + 未覆盖格式显式 SKIPPED；H-7/H-8/E1 追加数据至少 Likely + `--fail-on`。
7. M-23 PNG 分块固定化（关系到 `baseline_hash --check` 的可重复性）。
8. M-28 多扫描 JPEG 前移到 `preflight`；M-27 DQT 来源可见化。

**P2（体验/质量）**
9. 其余 Medium（配置合并、文件名保留名、TOCTOU、PBKDF2 重复、PDF/PE/ZIP 边界）按模块批量处理。
10. Low 集中清理：文案、常量与注释一致（`stc_h 7→8`、`32B/slot→16B`）、死路径收敛。

---

## 7. 审查方法与局限

- 分 4 组并行静态审查（PNG+HILL/STC、HEVC/HEIF、structure 域与格式适配器、JPEG+analysis+formats），并发不超过 2；每组输出均要求"文件:行号 + 代码证据 + 后果 + 修复方向"，主线对 Critical/High 逐条回读源码复核。
- 未做改动，因此未跑 `cargo build/test/fmt/clippy` 之外的验证；`clippy` 全绿是**对照基线**而非结论依据。
- 残留待实测项：L-8（真实 HEIC 首 box 分布）、M-34（各检测器 FPR 标定）、L-11（DCTR/CC-JRM 对比）、C-2/C-3 在真实带轨道 HEIC 上的复现。
- 本报告只覆盖语义与契约层；`.unwrap()/expect()` 的 panic 面、错误信息 i18n 完整度、测试覆盖缺口未单列，可作为下一轮专项。
</content>
