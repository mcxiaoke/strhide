# `mcxiaoke/strhide` GUI 改造实施结果审查报告 (`dcfc4ba..aaa85c1`)

> **审查范围**：基于上传的最新代码库 `strhidecode.zip`（HEAD 为 `aaa85c15c53d6d2805db694f8635bab13e4f112c`，涵盖 Stage A `dcfc4ba`、Stage B `ef2998b`、Stage C `4bb178d`、Stage D `aaa85c1` 四个提交），对照 v2.0 方案（`U1–U14`）逐文件、逐行进行代码走查与架构边界核验。

## 一、 总体结论与完成度评估

整体来看，执行 Agent 的完成质量**较高**（约 **85%–90%** 的设计目标已落地）：
1. **架构边界守卫通过**：运行 `python3 scripts/import_lint.py` 输出 `OK: all architectural boundaries intact (structure !-> stego, stego !-> structure, core !-> {formats, structure, stego, cli})`；`.github/workflows/ci.yml` 也已加入 `import_lint.py` 及 `--no-default-features` 单域编译矩阵。
2. **核心结构重构已就位**：
   - **Stage A (`dcfc4ba`)**：`SafetyLevel` / `VideoBudget` 下沉至 `core/params.rs`、`FormatCapability` 解除对 `structure-base` 的强耦合、`GLOBAL_LANG: AtomicU8` + `RenderCtx` 替换 `thread_local!`、`ErrorKind` 与 `ErrorDetail` 序列化全部落地。
   - **Stage B (`ef2998b`)**：`FileTarget`、`StegoEmbedResult`、`StegoFacade::{probe_file, inspect_file, verify_file}`、`ProgressWriter<W>`、`StrHide::{inspect_any, smart_extract}` 及 `formats::sniff::sniff_stream` 已实现。
   - **Stage C (`4bb178d`)**：`mp4_boxes::parse_moov_target`、`inspect_hevc_mp4_file`、`core::batch::run_batch`、`ReadResult::summary() -> ReadSummary`、`FileConfig.warnings`、`rename_with_retry` 以及 7 个 Options 结构体的密码 `<redacted>` `Debug` 脱敏均已落地。
   - **Stage D (`aaa85c1`)**：`AnalysisFacade` (`engine.analysis()`)、`EmbedStats { modified_slots, total_candidate_slots }`（覆盖 PNG/JPEG/HEVC 三引擎），以及 `crypto.rs` / `errors.rs` / `params.rs` / `commit.rs` 迁入 `src/core/` 并刪除 `src/sniff.rs` 均已完成。

但在逐行审查中，我们发现了 **1 个会导致 MP4 视频检测 100% 漏报的严重逻辑 Bug（P0）**、**4 个未完全收口的接口/错误码不一致问题（P1）** 以及 **4 个细节瑕疵（P2）**。建议在正式开始编写 GUI 前端前，用一个小补丁（Stage E / Hotfix）将以下问题一次性修齐。

---

## 二、 发现的问题清单与修复方案

### 🔴 P0：严重功能性 Bug（必改）

#### 1. `inspect_hevc_mp4_file` 硬编码 `has_inter = false`，导致普通多帧 MP4 视频流式 `inspect` 100% 漏报（恒返回 `has_hidden_data: false`）

- **问题位置**：`rust/src/stego/hevc/engine.rs:1919` 及 `1857–1866`
- **根因分析**：
  1. 在 HEVC 引擎中，`picture_band(nal_type, has_inter)`（`stego/hevc/engine.rs:2608–2616`）决定哪些 Slice 能够进入 CABAC 槽位池：
     ```rust
     fn picture_band(nal_type: u8, has_inter: bool) -> Option<u8> {
         if !has_inter || is_non_reference_vcl(nal_type) {
             return Some(BAND_NON_REFERENCE);
         }
         if is_irap(nal_type) {
             return None;
         }
         Some(BAND_REFERENCE)
     }
     ```
  2. 当对正常多帧 MP4 视频（含 IDR 关键帧 + P/B 帧，即 `has_inter == true`）执行写入（`embed_hevc_patches` -> `record_carrier_state`，`engine.rs:2410, 2445`）时，因为 `has_inter == true`，**首帧 IDR/IRAP 关键帧（`nal_type` 16..=23）返回 `None`，被排除在槽位池之外**（防止 GOP 帧间预测漂移），32B 的 `HevcSuperblock` 实际写入在后续的 P/B 帧槽位中。
  3. 然而在 Stage C 新增的流式检查函数 `inspect_hevc_mp4_file`（`stego/hevc/engine.rs:1919`）中，代码写成了：
     ```rust
     let (nal_type, _, _) = nal_header_fields(slice_bytes);
     let Some(band) = picture_band(nal_type, false) else { // <-- BUG: 硬编码了 has_inter = false!
     ```
     由于传入了 `false`，`!has_inter` 恒为 `true`，导致 **`inspect_hevc_mp4_file` 把首帧 IDR 关键帧的 CABAC bypass bins 收集进了 `sink` 槽位池**！随后提取 `HevcSuperblock` 时读取的是 IDR 帧的数据而非 P/B 帧的数据，计算出的 `sb.magic` 与 `expected_magic` 永远不匹配（`engine.rs:1722`），从而静默返回 `has_hidden_data: false`！
  4. 此外，`inspect_hevc_mp4_file`（`engine.rs:1857–1866`）在构造 `MediaInfo::new(dims.0, dims.1)` 时，**漏掉了 `parse_moov_target` 已经解析出的 `target.fps` 和 `target.duration_secs`**（未调用 `.with_video(...)`），导致流式检查 MP4 时丢失了帧率、时长和比特率信息。
- **可靠修复代码**（修改 `rust/src/stego/hevc/engine.rs:1857–1945`）：
  ```rust
  // 1. 在构造 media_info 时补齐视频帧率、时长与码率 (engine.rs:1857-1869)
  let mut media_info = None;
  for ps in &target.parameter_sets {
      if ps.len() > 2
          && (ps[0] >> 1) & 0x3F == NAL_SPS_NUT
          && let Some(dims) = sps_dimensions(&nal_rbsp(ps))
      {
          let base = MediaInfo::new(dims.0, dims.1);
          media_info = Some(match (target.fps, target.duration_secs) {
              (Some(fps), Some(sec)) if sec > 0.0 => {
                  let bps = (file_len as f64 * 8.0) / sec;
                  base.with_video(
                      fps as f32,
                      (sec * 1000.0).round() as u64,
                      bps.round() as u64,
                  )
              }
              _ => base,
          });
          break;
      }
  }

  // 2. 在解码循环前先通过轻量级 Seek 探测是否存在非 IRAP 帧 (has_inter)
  let mut has_inter = false;
  for &(sample_offset, sample_size) in target.samples.iter().take(64) {
      if sample_size < target.length_size + 2 || sample_offset + sample_size > file_len {
          continue;
      }
      // 读取 sample 头部或扫描 sample 内的 NAL header
      if sample_size <= 256 * 1024 {
          let mut hdr_buf = vec![0u8; sample_size];
          if file.seek(SeekFrom::Start(sample_offset as u64)).is_ok()
              && file.read_exact(&mut hdr_buf).is_ok()
          {
              let mut spans = Vec::new();
              if crate::stego::hevc::mp4_boxes::collect_sample_slice_spans(
                  &hdr_buf, 0, sample_size, target.length_size, &mut spans,
              ).is_ok()
                  && spans.iter().any(|s| {
                      let (nt, _, _) = nal_header_fields(&hdr_buf[s.start..s.end()]);
                      !is_irap(nt)
                  })
              {
                  has_inter = true;
                  break;
              }
          }
      }
  }
  // 然后在 1919 行传入真实的 has_inter：
  let Some(band) = picture_band(nal_type, has_inter) else {
  ```

---

### 🟠 P1：重要缺口与不一致问题（强烈建议修复）

#### 2. CLI `handle_embed` 仍在调用 `embed_carrier_file` 前无条件执行 `std::fs::read(carrier)`，导致双倍读盘与双倍内存未真正消除

- **问题位置**：
  - `rust/src/cli/cmd_stego.rs:258–265, 372`
  - `rust/src/cli/cmd_structure.rs:300–308`
  - `rust/src/cli/cmd_diag.rs:204, 248`
- **根因分析**：
  - 虽然 `stego::io::embed_carrier_file` 已经重构为内含 `commit_carrier_patches` 的单次读取流，但在 `cli/cmd_stego.rs:258` 的 `for_each_carrier` 循环开头，仍然保留了：
    ```rust
    let carrier_bytes = std::fs::read(carrier)?;
    let (mut options, probe_options) = stego_options(
        &args.tuning,
        password.as_deref(),
        carrier_format(&carrier_bytes),
        cfg,
    )?;
    ```
    并且 `carrier_bytes` 一直存活到函数末尾，而在第 372 行调用 `crate::stego::io::embed_carrier_file(...)` 时，`embed_carrier_file` 内部第 50 行又执行了一次 `let carrier_bytes = std::fs::read(carrier_path)?;`！这意味着非 `--dry-run` 的 CLI `embed` 依然把整个载体读了两遍、驻留了两份内存。
  - 同理，`cmd_structure.rs:300`（`read --auto` 跨层探测回退）和 `cmd_diag.rs:204, 248`（`verify`）仍然写着 `std::fs::read(carrier)`，没有改用新增的 `engine.stego().inspect_file(...)`（享受到 MP4 流式读取）和 `engine.stego().verify_file(...)`。
- **修复建议**：
  - 在 `cmd_stego.rs:258` 中，用 `crate::formats::sniff::sniff_file(carrier)?` 替代 `carrier_format(&carrier_bytes)`；仅在 `if args.dry_run` 分支内才调用 `std::fs::read(carrier)`。
  - 在 `cmd_structure.rs:300` 中改用 `engine.stego().inspect_file(carrier, &inspect_opts)`。

#### 3. `StrHide::inspect_any` 在未检出隐写时丢弃了 `StegoHeaderInfo`，导致干净媒体文件丢失 `MediaInfo`（分辨率/帧率/时长），且缺少 `verify_any`

- **问题位置**：`rust/src/facade.rs:306`、`rust/src/cli/cmd_diag.rs:200–293`
- **根因分析**：
  - 在 `rust/src/facade.rs:306` 中：
    ```rust
    Ok(info) => (Some(info).filter(|i| i.has_hidden_data), None),
    ```
    当用户在 GUI 中拖入一张**干净的** PNG / JPEG / HEIC / MP4 时，`engine.inspect_any(...)` 因为 `i.has_hidden_data == false` 直接把 `DualInspect.content` 过滤成了 `None`。
  - 但由于 `structure::InspectResult` 不包含 `media_info`，**`StegoHeaderInfo.media_info` 是 `inspect` 唯一返回图片宽高、视频帧率与时长的地方**！把它过滤为 `None` 会导致 GUI 在文件拖入预览阶段拿不到任何媒体分辨率信息。
  - 同时，`DualVerifyResult` 仍然留在 `cli/render.rs:25` 和 `cli/cmd_diag.rs:217`，`StrHide` 门面尚未提供 `verify_any`（以及内存版 `inspect_any_bytes` / `smart_extract_bytes`）。
- **修复建议**：
  - 在 `DualInspect` 中保留 `content: Some(info)`（只要载体是受支持的媒体格式，即使 `has_hidden_data == false` 也保留 `StegoHeaderInfo` 以便 GUI 读取 `info.media_info`），或者在 `DualInspect` 顶层增加 `pub media_info: Option<MediaInfo>` 字段；CLI `cmd_diag.rs:57, 104` 只需判断 `if let Some(ref cs) = dual.content && cs.has_hidden_data` 即可保持原有终端输出不变。
  - 将 `DualVerify` 上移至 `facade.rs`，补齐 `StrHide::verify_any`。

#### 4. 文件覆盖保护错误码未完全统一：4 处写入/提取接口仍返回 `StrHideError::Rejection` 而非 `StrHideError::AlreadyExists`

- **问题位置**：
  1. `rust/src/facade.rs:514–519`（`StegoFacade::extract_file`）
  2. `rust/src/structure/engine.rs:1638–1643`（`write_payload_to`，被 `read_carrier_with_dialect` 调用）
  3. `rust/src/structure/engine.rs:1886–1891`（`remove_carrier_with_dialect`）
  4. `rust/src/core/pipeline.rs:222–227`（`preflight_batch`）
- **根因分析**：
  - Stage A 新增了 `StrHideError::AlreadyExists(PathBuf)`（对应 `ErrorKind::AlreadyExists`），并更新了 `core::pipeline::check_overwrite`（`pipeline.rs:125`）。
  - 但上述 4 处库函数仍手写了 `if dest.exists() && !overwrite { return Err(StrHideError::Rejection(...)); }`。这会导致 GUI 在调用 `read_file`、`restore_file`、`extract_file` 或批量预检遇到同名文件时，收到的是 `ErrorKind::Rejection` 而不是 `ErrorKind::AlreadyExists`，无法精准弹出“文件已存在，是否覆盖？”确认框。
- **修复建议**：
  - 将上述 4 处手写判断统一替换为 `crate::core::pipeline::check_overwrite(&dest, overwrite)?;`。

#### 5. 强制安全阈值错误类型不一致：HEVC 返回 `StrHideError::SafetyThreshold`，而 PNG 与 JPEG 仍返回 `StrHideError::General`

- **问题位置**：
  - `rust/src/stego/hevc/engine.rs:676` 返回 `StrHideError::SafetyThreshold { tier, required_bytes, available_bytes }`（`ErrorKind::SafetyThreshold`）。
  - `rust/src/stego/png/engine.rs:1213` 返回 `StrHideError::General(...)`（`ErrorKind::General`）。
  - `rust/src/stego/jpeg/engine.rs:817` 返回 `Attempt::from(StrHideError::General(...))`（`ErrorKind::General`）。
- **根因分析**：
  - GUI 前端依赖 `ErrorKind::SafetyThreshold` 来触发容量超限提示（例如提示用户切换安全档位或关闭强制阻断），但目前只有 HEVC 载体返回 `SafetyThreshold`，PNG 和 JPEG 载体在开启 `SafetyEnforcement::Enforced` 超限时仍返回 `General`。
  - 更重要的是，在 `stego/engine.rs:463` 中，`HeifEngine` 专门捕获 `Err(e @ StrHideError::SafetyThreshold { .. }) => Err(e)` 以阻止策略超限时错误回退到缩略图桥接；若缩略图桥接内部调用 PNG/JPEG 引擎超限，返回 `General` 会破坏错误分类的一致性。
- **修复建议**：
  - 将 `stego/png/engine.rs:1213` 和 `stego/jpeg/engine.rs:817` 统一改为返回 `StrHideError::SafetyThreshold { tier: safety.level, required_bytes: payload.len(), available_bytes: ... }`（注意检查是否有旧单测断言了英文字符串，如有则同步更新单测模式匹配）。

---

### 🟡 P2：细节打磨与边界优化（建议顺手修复）

| 编号 | 模块与位置 | 问题描述 | 修复建议 |
| :--- | :--- | :--- | :--- |
| **6** | `rust/src/core/commit.rs:259–289` | **`rename_with_retry` 退避睡眠少算一次 & Unix `PermissionDenied` 误判**：<br>1. `BACKOFF_MS = [20, 50, 100]` 循环 3 次，当 `attempt == 2` 时 `attempt + 1 < 3` 为 `false`，导致 `100ms` 根本没睡就直接退出了（只尝试了 3 次、睡了 20ms+50ms）。<br>2. `is_sharing_or_permission_error` 在非 Windows 平台将所有 `ErrorKind::PermissionDenied` 映射为 `TargetBusy`，导致 Linux/macOS 下目标目录只读时报错变成“文件被其它进程占用”。 | 1. 循环条件改为尝试 4 次（初次 + 3 次退避 `[20, 50, 100]`），每次失败后 sleep 并在 sleep 后再试一次。<br>2. 将 `PermissionDenied` 视为共享冲突仅限 `#[cfg(windows)]`（Windows 句柄占用常返回 `ERROR_ACCESS_DENIED = 5` / `32` / `33`）；Unix 下保持返回原始 `StrHideError::Io(e)`。 |
| **7** | `rust/src/structure/options.rs:19, 63` | **`StrategyChoice` 定义了但未接入 `WriteOptions`**：<br>`options.rs:19` 新增了强类型的 `pub enum StrategyChoice`，但 `WriteOptions::strategy`（第 63 行）仍然是 `&'a str`，且没有任何接收 `StrategyChoice` 的构造器或字段。 | 在 `WriteOptions` 中增加 `pub const fn with_strategy_choice(mut self, choice: StrategyChoice) -> Self { self.strategy = choice.as_str(); self }`，让 GUI 可以直接传入强类型枚举。 |
| **8** | `rust/src/core/i18n/mod.rs:11` & `rust/src/lib.rs:128, 177` | **`Lang` 缺少 Serde 派生 & `lib.rs` 根导出/文档过时**：<br>1. `core/i18n/mod.rs:11` 的 `pub enum Lang` 未派生 `Serialize, Deserialize`，不便于 GUI 配置文件直接序列化语言枚举。<br>2. `lib.rs:128` 文档注释仍写着 `crate-root residents that a later batch moves under [core]`。<br>3. `lib.rs:177` 和 `prelude` 未重导出新增的 `ErrorKind`、`EmbedStats`、`StegoEmbedResult`、`ReadSummary`、`DualInspect`、`SmartExtractOutcome`。 | 1. 为 `Lang` 增加 `#[derive( serde::Serialize, serde::Deserialize)]`。<br>2. 更新 `lib.rs` 顶部模块文档注释，并将 Stage A–D 新增的核心 DTO 加入 `lib.rs` / `prelude` 重导出。 |
| **9** | `rust/src/core/batch.rs:18, 104–115` | **`run_batch` 缺少单任务进度透传与显式 `RenderCtx`**：<br>`BatchPlan` 仅携带 `cancel: Option<Arc<CancelToken>>`，内部构造 `Control::with_cancel(tok)` 时丢弃了 `Progress` 通道，且错误转换直接调用了 `e.detail_i18n()`（使用全局语言而非显式 `RenderCtx`）。 | 在 `BatchPlan` 中增加可选的 `pub ctx: Option<RenderCtx>`（默认读取 `RenderCtx::current()`）以及可选的单任务进度回调支持。 |

---

## 三、 Stage A–D 逐项核对总表（U1–U14）

| 任务编号 | 规划内容 | 实施状态 | 代码落点与核验结果 |
| :--- | :--- | :--- | :--- |
| **U1** | 修复 `--no-default-features` 单域编译 Bug | ✅ **已完美解决** | `SafetyLevel` / `VideoBudget` 已移入 `core/params.rs`；`formats/capability.rs` 已解耦；CI 已增加 4 组单域编译矩阵。 |
| **U2** | `i18n` 全局原子语言 + 显式 `RenderCtx` | ✅ **已完成**（微瑕） | `core/i18n/mod.rs` 已改用 `AtomicU8` (`GLOBAL_LANG`) 并提供 `RenderCtx`；仅 `Lang` 漏加 `Serialize, Deserialize`（见问题 8）。 |
| **U3** | 门面补齐 `inspect_any`、`smart_extract` 与文件级对称方法 | ⚠️ **部分完成** | `StegoFacade::{probe_file, inspect_file, verify_file}`、`inspect_any`、`smart_extract` 已就位；但 `inspect_any` 过滤掉了干净载体的 `MediaInfo`，且缺 `verify_any`（见问题 3）。 |
| **U4** | `stego` 文件级 API 返回 `StegoEmbedResult` + 消除 CLI 双倍读盘 | ⚠️ **库层已完成 / CLI 未收口** | `stego::io::embed_carrier_file` 已使用 `FileTarget` 并返回 `StegoEmbedResult`；但 `cli/cmd_stego.rs:258` 仍残留 `std::fs::read(carrier)`（见问题 2）。 |
| **U5** | 流式 I/O 进度 (`ProgressWriter`) 与取消检查点 | ✅ **已完成** | `core/control.rs` 已实现 `ProgressWriter` 与 `map_io_cancel`，并已接入 `write_carrier_with`、`remove_carrier_with_dialect` 及 PNG/JPEG/HEVC 引擎。 |
| **U6** | `ErrorDetail` 序列化 + `ErrorKind` + `AlreadyExists` / `TargetBusy` | ⚠️ **已完成 / 4 处漏用** | `core/errors.rs` 已定义 `ErrorKind`、`AlreadyExists`、`TargetBusy`；但 4 处文件覆盖判断仍返回 `Rejection`，PNG/JPEG 安全超限仍返回 `General`（见问题 4、5）。 |
| **U7** | MP4 `inspect` 流式按需读取，消除 GB 级 OOM | 🔴 **已实现但存在 P0 Bug** | `mp4_boxes::parse_moov_target` 与 `inspect_hevc_mp4_file` 已实现流式读取，但第 1919 行硬编码 `picture_band(nal_type, false)` 导致多帧 MP4 100% 漏报（见问题 1）。 |
| **U8** | 零终端输出的结构化批处理引擎 `core::batch` | ✅ **已完成**（可微调） | `core/batch.rs` 已实现基于 `std::thread::scope` 的 `run_batch` 与 3 个单元测试（见问题 9）。 |
| **U9** | `FileConfig.warnings`、`StrategyChoice`、`ReadSummary`、`rename_with_retry` | ✅ **已完成**（微瑕） | 四项均已落地；仅 `rename_with_retry` 少睡最后一次 100ms 且 `StrategyChoice` 未挂到 `WriteOptions` helper 上（见问题 6、7）。 |
| **U10** | 全部 7 个 Options 结构体 `Debug` 密码脱敏 | ✅ **已完美解决** | `WriteOptions`、`ReadOptions`、`RestoreOptions`、`EmbedOptions`、`ProbeOptions`、`ExtractOptions`、`InspectOptions`、`VerifyOptions` 全部实现 `<redacted>` 并附带单测。 |
| **U11** | `sniff_stream<R: Read + Seek>` 流式嗅探 | ✅ **已完美解决** | `formats/sniff.rs` 已提供 `sniff_stream` 并复用于 `sniff_file` 与 `stego/io.rs`。 |
| **U12** | `StrHide::analysis()` 门面接入与 `AnalysisReport` | ✅ **已完美解决** | `facade.rs` 已提供 `AnalysisFacade`（`scan_file` / `scan_bytes`），`analysis.rs` 已导出 `AnalysisReport` 别名并补齐单测。 |
| **U13** | 真实修改率统计 `EmbedStats` | ✅ **已完美解决** | PNG、JPEG、HEVC 三大引擎均已返回精确的 `EmbedStats { modified_slots, total_candidate_slots }` 并写入 `StegoEmbedResult.stats`。 |
| **U14** | 根目录模块收拢至 `src/core/` + `import_lint.py` 门禁 | ✅ **已完美解决** | `crypto.rs`、`errors.rs`、`params.rs`、`commit.rs` 已移入 `src/core/`，旧 `src/sniff.rs` 已移除，`scripts/import_lint.py` 检查通过。 |
