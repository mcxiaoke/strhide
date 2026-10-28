# `strhide` GUI 层适配与前端就绪度统一架构方案（v2.0 终版）

> **文档定位（单一事实源）**：本文档为 `strhide` 面向 GUI 客户端（Tauri v2 / Electron / iced / egui / Slint）的**唯一主蓝图（v2.0）**。它完整合并了《GUI 前端就绪度复核与补齐方案》（`gui_frontend_readiness_plan_20261027.md`，编号 **G1–G10**）与《0.7.4 增量架构审计》（编号 **1.1–7.2**），并逐条吸纳了两份交叉审核意见（`strhide_gui_audit_review_20261028.md` 与 `gui_architecture_and_readiness_cross_audit_20261028_gmf.md`）的全部勘误与裁决。
>
> **代码基线**：`strhide v0.7.4`（仓库 HEAD `9abd810`，含 2026-10-27 阶段 0–4 重构及 2026-10-28 HEVC Scheme C v2 批次 1–5 优化）
>
> **引用规范**：为避免行号随重构漂移，本文所有源码证据均以 **模块路径 + 符号名** 为主锚点，辅以 `0.7.4` 实测行号。

## 零、 总体结论与版本演进说明

### 0.1 核心结论

经过阶段 0–4 架构重组与 2026-10-28 HEVC 批次 1–5 优化，`strhide` 已经完成了“双域解耦、能力表单一事实源、微头自描述（提取端仅需密码）、HEVC 分窗流式早退与增量切片覆写”等核心算法与工程地基。

然而，站在 GUI 开发者视角核对 `0.7.4` 源码，当前库距离“前端开箱即用”仍存在 **14 项关键缺口（整合自 G1–G10 与 0.7.4 增量审计）**，其中包含 **2 项在 0.7.4 新引入的实测回归问题**：

1. **细分 Feature 编译破损（P0 实测复现）**：`stego::io::embed_carrier_file`（`src/stego/io.rs:58`）无条件调用了 `crate::stego::hevc::embed_hevc_patches` 与 `dialect.hevc_format()`，未加 `#[cfg(feature = "content-hevc")]`，导致 `cargo check --no-default-features --features content-png`（或 `content-jpeg`）直接编译失败（3 处编译错误）。

2. **CLI 绕过零拷贝补丁通道（P0 实测确认）**：2026-10-28 批次 4 在 `stego::io::embed_carrier_file` 中实现了 MP4/Annex-B 的 `embed_hevc_patches` + `commit_carrier_patches` 原位零拷贝覆写；但因 `StegoFacade::embed_file`（`src/facade.rs:454`）仅返回 `Option<PathBuf>`（丢失容量与安全告警），`cli::cmd_stego::handle_embed`（`src/cli/cmd_stego.rs:268, 371`）绕过了该函数，仍在内存中分配完整载体 `Vec<u8>` 并调用 `commit_carrier_bytes`。

3. **进度与取消断层（G1 / G8）**：结构域 `src/structure/` 内 `Control` 出现次数为 **0**；全库生产代码中细粒度进度 `Event::progress` 与 `Control::stage_sized` 调用次数为 **0**（2026-10-28 批次 3 改为 Rayon 并行重编码时还误删了 HEVC 的 `Stage::Encode` 上报）；HEVC 的 `record_carrier_state` 与 `probe_hevc_pool` 未传 `Control`，长视频精确扫描期间无法响应取消。

4. **双域聚合与智能提取缺位（G2）**：`DualInspectResult` / `DualVerifyResult` 仍是 `cli::render` 的 `pub(crate)` 私有结构，且门面缺少能防双域数据丢失（`also_present`）、防 PBKDF2 假死（`limits`）的 `smart_extract` 状态机。

5. **跨进程 IPC 序列化、i18n 与桌面端平台防线缺口（G3 / G4 / G5 / G6 / G9）**：`ErrorDetail` / `ReadResult` 缺 `Serialize`、高分辨率载荷直接序列化存在撑爆 WebView IPC 风险、`panic = "abort"` 与 Windows 预览文件句柄占用（`TargetBusy`）未设防、`Options` 的 `Debug` 实现会向日志明文泄露密码。

### 0.2 v1 → v2 审核勘误与方案裁决记录

本版（v2.0）对前序版本中的事实偏差、编译瑕疵及两份文档间的冲突进行了全面修正与裁决：

| 审核议题 | v1 方案问题或两案冲突点 | v2.0 终版修正与裁决结论 | 
| ----- | ----- | ----- | 
| **源码锚点与行号** | 混用了 `0.7.3` 与 `0.7.4` 行号（如 `analysis::scan_file` 误标为 1951 行的测试函数，实际在 `:263`；`StegoFacade::embed_file` 在 `facade.rs:454`；Git 依赖在 `Cargo.toml:76,79`） | **全面订正为 `0.7.4` 精确行号，并以“模块+符号名”为主锚点**，彻底消除行号漂移风险。 | 
| **`errors.rs:146` 定性** | 将 `#[cfg(feature = "structure")] impl From<serde_json::Error>` 与 `stego/io.rs` 并列为“编译直接失败” | **修正定性**：`structure-base` 单独编译可通过；问题本质是 `From` 实现在 `structure-base`（不含 PE）下消失，降级为 **API 门控缺口**。 | 
| **双域诊断与智能提取 (`G2`)** | v1 的 `DualInspectReport` 漏了 `#[serde(flatten)]` 和 `content_error`；`extract_auto_bytes` 盲目捕获 `NoHiddenData` 回退内容域，且丢弃第二域载荷、缺少 `limits` | **全面采纳 27日方案 G2**：使用 `#[serde(flatten)]` 保持 `--json` 100% 兼容；`smart_extract` 先跑廉价 `inspect_any`，带 `limits: ExtractParams` 与 `also_present: Option<Domain>`。 | 
| **结构域进度注入 (`G1`)** | v1 建议直接修改结构域内部流式拷贝循环，且未考虑取消点与 `.bak` 备份的时序 | **采纳 27日方案 G1**：在 `core::control` 提供 `ProgressWriter` / `ProgressSeekWriter` 包装 `out`，10 个适配器零改动；**取消点严格置于 `.bak` 复制与 `rename` 提交区间之前**。 | 
| **i18n 多线程状态 (`G3` / `7.1`)** | 27日方案主张大改 71 处 `t!` 宏显式传 `RenderCtx`；v1 主张 5 行改为 `AtomicU8` 但把 `ErrorDetail.category` 改成了 `Option<String>` 丢了稳定 `Msg` 键 | **融合最优解**：① 底层 `CURRENT` 由 `thread_local!` 换为 `AtomicU8`（5 行代码立即解决工作线程语言失步，免改 71 处宏）；② 新增 `Msg::id()` 稳定键与 `RenderCtx`，保留 `ErrorDetail.category: Option<Msg>` 并序列化为稳定 ID。 | 
| **跨线程 `Control` 与生命周期 (`3.1` / `3.2`)** | v1 提出全局 `intern_dialect_str` 驻留池（有驻留明文密钥风险），并将 `TaskControl` 列为 P0 | **修正与降级**：① 废除明文密钥 `Box::leak` 驻留池，改用 `RuntimeDialect`（`Arc<str>`）或按会话传参；② 保持 `Control<'a>` 为 `Copy`，展示在 Worker 闭包内零改动构造 `Control` 的标准模式，同时提供可选 `TaskControl` 辅助封装。 | 
| **大文件读取模型 (`G4` / `6.1`)** | v1 在 `inspect_file_any` 中误用 `std::fs::read`，又在 §6.1 主张全面引入 `unsafe` 的 `memmap2::Mmap` | **分级裁决**：① `inspect_file` / `verify_file` 必须采用 **有界头尾流式读取（零 `unsafe`、峰值 ≤ 8 MiB）**；② 深入评估 `mmap` 在文件被外部截断时触发 `SIGBUS` 的崩溃风险，仅作为大视频 `embed`/`probe` 的可选受控优化。 | 
| **PNG/JPEG `EmbedOutput.capacity` (`7.2`)** | v1 声称 `embed_png` / `embed_jpeg` 已算完 `available_slots`，构造 `StegoCapacityInfo` 成本为零 | **正面修正**：`stego/options.rs:870-875` 明确注释 PNG/JPEG 嵌入不跑完整容量模型（`embed_png` 仅算绿通道 `pool_green`，`embed_jpeg` 仅算 `enforced_payload_limit`）。尊重该契约，改为导出真正零成本的已应用修改统计 `EmbedStats { modified_slots, .. }`。 | 

## 一、 统一问题全景矩阵（G1–G10 融合 0.7.4 增量审计）

| 统一编号 | 对应旧编号 | 所属模块与关键符号 | 问题与缺口描述 | 严重度 | 
| ----- | ----- | ----- | ----- | ----- | 
| **U1** | 增量 1.1 / 1.2 | `stego::io::embed_carrier_file`  `errors::StrHideError`  `formats::capability::CAPABILITIES` | `stego/io.rs:58` 调用 `hevc::embed_hevc_patches` 缺 `#[cfg(feature = "content-hevc")]`，单开 `content-png`/`jpeg` 编译失败；`errors.rs:146` 门控错写为 `structure`；`CAPABILITIES` 内容域引擎未随 Feature 条件裁剪；CI 缺细分 Feature 构建门禁 | **P0 阻断** | 
| **U2** | 增量 2.2 + G4 | `StegoFacade::embed_file`  `stego::io::embed_carrier_file`  `cli::cmd_stego::handle_embed` | `embed_file` 仅返回 `Option<PathBuf>` 且含裸 `bool`；`cmd_stego.rs:268,371` 为拿容量与告警绕过 `embed_carrier_file`，导致 10-28 批次 4 的 MP4/HEVC 零拷贝原位补丁优化在 CLI 失效；`stego/io.rs:86` 硬编码 `preserve_time = true` | **P0 阻断** | 
| **U3** | G2 + 增量 2.1 | `cli::render::DualInspectResult`  `cli::cmd_diag::handle_inspect`  `StrHide` 门面 | 双域诊断聚合在 `cmd_diag.rs` 重复 4 次且类型为 `pub(crate)`；门面在 `cli/` 中零调用；缺少防双域载荷静默丢失（`also_present`）与防 PBKDF2 假死（`limits`）的 `smart_extract` | **P0 阻断** | 
| **U4** | G1 | `structure::options::*Options`  `structure::engine::{write_core, remove_core}` | 结构域无 `Control` 字段，数 GB 容器写入、还原、SHA-256 校验与 `.bak` 备份全程零进度、零取消；且取消点若落入 `.bak` 复制与 `rename` 之间会残留孤儿 `.bak` | **P0 阻断** | 
| **U5** | G8 + 增量 4.2 | `stego::hevc::engine::{record_carrier_state, probe_hevc_pool}`  `stego::{png,jpeg,hevc}` | 全库生产代码 `Event::progress` 与 `stage_sized` 调用数为 **0**；10-28 批次 3 误删 HEVC `Stage::Encode`；HEVC 切片录制与池扫描未传 `Control`，长视频扫描/解码阶段无法取消；`probe`/`extract`/`verify` 缺阶段上报 | **P0 阻断** | 
| **U6** | G3 + 增量 5.1 / 7.1 | `core::i18n::{lang, set_lang, Msg}`  `errors::{StrHideError, ErrorDetail}` | `i18n` 使用 `thread_local!` 导致 GUI 工作线程语言失步；`Msg` 缺稳定 `id()`；`ErrorDetail` 缺 `Serialize` 与 `ErrorKind`；6 个高频错误变体与 7 个必显字段为硬编码英文散文 | **P0 阻断** | 
| **U7** | G4 + 增量 6.1 | `StegoFacade`  `stego::io` | `StegoFacade` 缺少文件级 `probe_file` / `inspect_file` / `verify_file`；诊断接口若用 `std::fs::read` 读 2 GB 视频会产生 2 GB 堆内存峰值，需改为有界头尾流式读取 | **P1 高** | 
| **U8** | 增量 5.2 / 5.3 / 5.4 | `structure::ReadResult`  `structure::InspectResult`  各域 `*Options` / `*Result` | `ReadResult` 落盘后仍携带全量 `data: Vec<u8>`，跨 Tauri IPC 序列化会撑爆 WebView；`InspectResult.metadata` 密码错误时塞入 `{"error": "Invalid password"}` 弱类型 JSON；缺 `suspicious_hints` 字段；核心枚举与结果缺 `Deserialize` | **P1 高** | 
| **U9** | G5 + 增量 4.3 / 6.2 | `core::pipeline::for_each_carrier`  `core::config::parse_config` | `for_each_carrier` 首错即停、无取消/并发控制、直接向 stdout `println!`；`config.rs` 与 `stego/{png,jpeg}` 内部残留裸 `eprintln!` | **P1 高** | 
| **U10** | G9 | `Cargo.toml` (`panic = "abort"`)  `commit::commit_carrier_bytes`  `formats::capability::capability_of` | `panic = "abort"` 下任何内部 panic 会直接杀死 GUI 并跳过 `TmpGuard::drop` 留下 `.strhide.tmp`；Windows 下 WebView 预览占用文件时 `rename` 无重试且无 `TargetBusy` 错误提示 | **P1 高** | 
| **U11** | G6 + 增量 2.5 | `WriteOptions` / `EmbedOptions`  `PayloadSource`  `cli::helpers` | `*Options` 自动派生的 `Debug` 会将明文密码打入日志；`EmbedOptions` 缺 `PartialEq`（无法做表单脏检查）；`WriteOptions.strategy` 为裸 `&str`；`FileConfig` 合并逻辑滞留 `cli::helpers` | **P1 高** | 
| **U12** | 增量 3.1 / 3.2 | `facade::Dialect`  `core::control::Control` | `Dialect` 字段要求 `&'static str`，运行时动态密钥配置不便；异步 GUI（`tokio::spawn_blocking`）跨线程传递 `Control` 与选项需清晰的 `'static` 桥接模式 | **P1 高** | 
| **U13** | 增量 2.4 + 7.2 | `analysis::scan_file`  `stego::options::EmbedOutput` | `analysis` 未接入 `StrHide` 门面、缺 `scan_bytes` 与 `Control`；`EmbedOutput` 可补充轻量级已应用修改统计 `EmbedStats`（实际翻转槽位数）供 GUI 展示 | **P2 中** | 
| **U14** | G7 + G10 | `src/lib.rs`  `scripts/import_lint.py`  `docs/api/*` | Crate 根残留待迁移模块与死导出（`supports_content_stego`、`src/sniff.rs`）；缺 `import_lint.py` 边界守卫；GUI 推荐 Feature 组合与 JSON-over-IPC 决策需固化入文档 | **P2 中** | 

## 二、 P0 级阻断问题详解与可靠修复方案（U1–U6）

### U1：细分 Feature 编译破损、能力表静态硬编码与 CI 矩阵缺口（增量 1.1 / 1.2）

#### 1. 源码证据与实测复现

* **`stego::io::embed_carrier_file`（`rust/src/stego/io.rs:42-83`）**：2026-10-28 批次 4 新增的 MP4 / Annex-B 补丁分支直接调用了 `crate::stego::hevc::embed_hevc_patches`（`:58`）和 `dialect.hevc_format()`（`:63`）。但 `pub mod hevc` 在 `rust/src/stego/mod.rs:24` 被 `#[cfg(feature = "content-hevc")]` 门控，`StegoProfile::hevc_format` 在 `rust/src/stego/params.rs:880` 同样被 `#[cfg(feature = "content-hevc")]` 门控。
  在工作区实测执行：

  ```
  cargo check --no-default-features --features content-png   # FAILED (3 errors)
  cargo check --no-default-features --features content-jpeg  # FAILED (3 errors)
  
  ```

  为什么 CI 没抓到？因为当前 CI 的最小构建矩阵只跑了 `--no-default-features`、`structure`、`content`、`analysis` 四条，**漏掉了 `content-png`、`content-jpeg`、`content-hevc`、`structure-base` 四条细粒度独立构建**。

* **`errors::StrHideError`（`rust/src/errors.rs:146`）**：`#[cfg(feature = "structure")] impl From<serde_json::Error> for StrHideError` 门控在 `structure`（含 PE 反汇编）上，而 `serde_json` 实际由 `structure-base`（`rust/Cargo.toml:32`）引入。单开 `structure-base` 虽可编译，但该 `From` 转换实现丢失。

* **`formats::capability::CAPABILITIES`（`rust/src/formats/capability.rs:46-121`）**：`FileFormat::Pe` 的结构域策略（`:111`）正确按 `#[cfg(feature = "structure-pe")]` 条件编译，但所有格式的 `structure` 与 `stego` 数组均未按 `structure-base` / `content-png` / `content-jpeg` / `content-hevc` / `content-heif-bridge` 门控，导致裁剪 Feature 的 GUI 查询 `FileFormat::Mp4.supports_stego()` 仍返回 `true`。

#### 2. 可靠修复方案

1. **在 `stego/io.rs` 中补齐 `#[cfg(feature = "content-hevc")]` 门控**（注：采纳审核意见 §5.5，**绝不**将文件 I/O 塞进纯字节级的 `StegoEngine` trait，保持分层纯粹）：

```
// rust/src/stego/io.rs:42
#[cfg(feature = "content-hevc")]
if matches!(
    format,
    Some(crate::formats::FileFormat::Mp4 | crate::formats::FileFormat::HevcAnnexB)
) {
    // 仅当启用 content-hevc 时编译增量补丁零拷贝路径
    // ...
}

```

2. **修正 `rust/src/errors.rs:146`**：改为 `#[cfg(feature = "structure-base")]`。

3. **联动 `rust/src/formats/capability.rs`**：对 `CAPABILITIES` 表中的 `structure` 与 `stego` 切片元素加上对应的 `#[cfg(feature = "...")]` 属性，并更新 `capability.rs` 中的单元测试门控。

4. **补齐 CI 硬性门禁**：在 `.github/workflows/ci.yml` 中将 `structure-base`、`content-png`、`content-jpeg`、`content-hevc`、`analysis` 五条独立构建全部设为硬性检查。

### U2：`StegoFacade::embed_file` 接口补齐与打通 CLI 大视频零拷贝补丁通道（增量 2.2 + G4）

#### 1. 源码证据与影响

* **门面与 I/O 签名不对称**：`StegoFacade::embed_file`（`rust/src/facade.rs:454`）与 `stego::io::embed_carrier_file`（`rust/src/stego/io.rs:31`）接收裸 `backup: bool` 参数，将 `preserve_time` 硬编码为 `true`（`stego/io.rs:79, 86`），且仅返回 `Result<Option<PathBuf>, StrHideError>`（只返回 `.bak` 路径），丢弃了 `embed_hevc_patches` 算出的 `StegoCapacityInfo`！

* **CLI 旁路零拷贝优化**：在 `rust/src/cli/cmd_stego.rs:268-371` 的 `handle_embed` 中，CLI 为了拿到 `output.capacity` 做 Advisory 安全阈值告警和 `--dry-run` 报告，没有调用 `embed_carrier_file`，而是直接调 `embed_carrier_with_dialect_info`（在内部执行 `carrier.to_vec()` 分配数百 MB 完整载体副本）再调 `crate::structure::commit_carrier_bytes`（全盘写出，且跨模块引用了 `structure` 的重导出而非 `crate::commit`）。

#### 2. 可靠修复方案

融合 G4 的 `FileTarget` 设计与 28日方案的 `StegoEmbedResult`，消除裸 `bool` 参数，让 `stego::io::embed_carrier_file` 返回完整结构化结果，并使 CLI 与 GUI 共用同一条零拷贝通道：

```
// 1. 统一文件落盘目标选项（置于 crate::commit 或 crate::core::fs，两域共用）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTarget<'a> {
    /// None = 原地覆盖；Some(file_path) = 写入目标路径
    pub output_path: Option<&'a Path>,
    /// 原地覆盖时是否保留 <carrier>.bak
    pub backup: bool,
    /// 是否保留原载体 atime/mtime 时间戳（修复 stego/io.rs 硬编码 true 的问题）
    pub preserve_time: bool,
    /// 目标文件已存在（非原地）时是否允许覆盖
    pub overwrite: bool,
}

impl Default for FileTarget<'_> {
    fn default() -> Self {
        Self {
            output_path: None,
            backup: true,
            preserve_time: true,
            overwrite: false,
        }
    }
}

// 2. 内容域文件级嵌入的结构化返回结果（置于 rust/src/stego/options.rs）
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StegoWarning {
    SafetyThresholdExceeded {
        payload_bytes: usize,
        recommended_max_bytes: usize,
        safety_level: String,
        actual_bpp: f64,
        limit_bpp: f64,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StegoEmbedResult {
    pub carrier: PathBuf,
    pub written_to: PathBuf,
    pub format: crate::formats::FileFormat,
    pub payload_bytes: usize,
    pub carrier_before_bytes: u64,
    pub carrier_after_bytes: u64,
    pub backup_file: Option<PathBuf>,
    pub capacity: Option<crate::stego::StegoCapacityInfo>,
    pub warnings: Vec<StegoWarning>,
}

```

在 `stego::io::embed_carrier_file` 中：

* 先通过 `core::pipeline::check_overwrite` 校验非原地目标的 `target.overwrite`；

* 对于 `Mp4` / `HevcAnnexB`（在 `#[cfg(feature = "content-hevc")]` 下），调用 `embed_hevc_patches` 拿到 `(patches, capacity)`，立即 `drop(carrier_bytes)`，调用 `commit_carrier_patches(carrier_path, dest, &patches, target.backup, target.preserve_time)`，并将 `Some(capacity)` 存入 `StegoEmbedResult`；

* 若 `options.safety.enforcement == SafetyEnforcement::Advisory`，检查 `capacity`（若 PNG/JPEG 未返回 `capacity` 且调用方需要告警，或按 `enforced_payload_limit` 阈值判定）生成 `StegoWarning::SafetyThresholdExceeded`；

* 在 `cli/cmd_stego.rs` 的非 `--dry-run` 分支中直接调用 `embed_carrier_file`，使 CLI 与 GUI 100% 共享大视频零拷贝原位补丁优化！

### U3：双域联合诊断（`inspect_any` / `verify_any`）与防丢数智能提取（`smart_extract`）下沉门面（G2 + 增量 2.1）

#### 1. 源码证据与 v1 方案缺陷剖析

* 现状：`DualInspectResult`（`cli/render.rs:108`）与 `DualVerifyResult`（`:147`）为 `pub(crate)`，聚合逻辑在 `cli/cmd_diag.rs` 重复 4 次（`:52, :139, :233, :304`），且用 `.ok()` 吞掉了内容域报错；门面 `StrHide` 在 `cli/` 中调用次数为 0。

* 纠正 v1 方案的三处缺陷（采纳 27日方案 G2 与 GMF 交叉复核裁决）：

  1. **必须保留 `#[serde(flatten)]`**：确保 CLI `--json` 输出的顶层字段与现有基线 100% 兼容，同时新增 `content_error: Option<ErrorDetail>` 保留内容域诊断失败原因。

  2. **载体可能同时在两个域都藏有数据**：一个 PNG 或 MP4 可以既有结构域信封（如 `prIv` chunk / `uuid` box），又有内容域隐写（像素 / CABAC）。如果先读结构域成功就直接返回，GUI 用户永远无法得知或提取第二份内容域载荷！因此必须返回 `also_present: Option<Domain>`。

  3. **禁止靠“盲跑提取捕获 `NoHiddenData`”来判域，且必须带 `limits: ExtractParams`**：若结构域是 Stealth 隐身信封而用户输错了密码，`read` 会返回 `NoHiddenData`；若直接回退去跑内容域 `extract`，会对几千万像素的大图做全量代价图计算与 PBKDF2 迭代，造成 UI 假死。必须先走廉价的 `inspect_any` 状态机！

#### 2. 可靠修复方案

```
// 新增于 rust/src/facade.rs
use serde::{Deserialize, Serialize};
use crate::core::control::Control;
use crate::errors::{ErrorDetail, StrHideError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    Structure,
    Content,
}

#[derive(Debug, Clone, Default)]
pub struct DualOptions<'a> {
    pub password: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub control: Control<'a>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DualInspect {
    #[cfg(feature = "structure-base")]
    #[serde(flatten)]
    pub structure: crate::structure::InspectResult,

    #[cfg(feature = "content-base")]
    #[serde(rename = "content_stego", skip_serializing_if = "Option::is_none")]
    pub content: Option<crate::stego::StegoHeaderInfo>,

    #[cfg(feature = "content-base")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_error: Option<ErrorDetail>,
}

#[cfg(all(feature = "structure-base", feature = "content-base"))]
#[derive(Debug, Clone, Default)]
pub struct SmartExtractOptions<'a> {
    pub password: Option<&'a str>,
    pub domain: Option<&'a str>,
    /// 限制尝试的密码套件与最大 PBKDF2 迭代次数，防止错密导致 GUI 假死
    pub limits: crate::stego::ExtractParams,
    /// 当两域同时存在载荷时的优先提取域（默认 Structure）
    pub prefer: Option<Domain>,
    pub control: Control<'a>,
}

#[cfg(all(feature = "structure-base", feature = "content-base"))]
#[derive(Debug, Clone)]
pub struct ExtractOutcome {
    pub payload: crate::core::payload::Payload<'static>,
    pub source: Domain,
    /// 若另一域也同时检出有效隐藏数据，在此返回该域标识，供 GUI 提示“发现第二载荷”
    pub also_present: Option<Domain>,
}

impl StrHide {
    /// 跨双域只读诊断：结构域流式定位 + 内容域有界头部探测
    pub fn inspect_any(
        &self,
        carrier: &Path,
        opts: &DualOptions<'_>,
    ) -> Result<DualInspect, StrHideError> {
        #[cfg(feature = "structure-base")]
        let structure = self.structure().inspect_file(carrier, opts.password)?;

        #[cfg(feature = "content-base")]
        let (content, content_error) = {
            let format = {
                #[cfg(feature = "structure-base")]
                { Some(structure.format) }
                #[cfg(not(feature = "structure-base"))]
                {
                    let mut f = std::fs::File::open(carrier)?;
                    crate::formats::sniff::sniff_stream(&mut f)?
                }
            };
            if format.is_some_and(|f| f.supports_stego()) {
                let stego_opts = crate::stego::InspectOptions {
                    password: opts.password,
                    domain: opts.domain,
                    limits: crate::stego::ExtractParams::default(),
                    control: opts.control,
                };
                match self.stego().inspect_file(carrier, &stego_opts) {
                    Ok(info) => (Some(info).filter(|i| i.has_hidden_data), None),
                    Err(e) => (None, Some(e.detail_i18n())),
                }
            } else {
                (None, None)
            }
        };

        Ok(DualInspect {
            #[cfg(feature = "structure-base")]
            structure,
            #[cfg(feature = "content-base")]
            content,
            #[cfg(feature = "content-base")]
            content_error,
        })
    }

    /// 自动判域安全提取（先经廉价 inspect_any 判定，杜绝盲目全量解码与双载荷丢失）
    #[cfg(all(feature = "structure-base", feature = "content-base"))]
    pub fn smart_extract(
        &self,
        carrier: &Path,
        opts: &SmartExtractOptions<'_>,
    ) -> Result<ExtractOutcome, StrHideError> {
        let diag = self.inspect_any(
            carrier,
            &DualOptions {
                password: opts.password,
                domain: opts.domain,
                control: opts.control,
            },
        )?;
        let has_struct = diag.structure.has_hidden_data;
        let has_content = diag.content.as_ref().is_some_and(|c| c.has_hidden_data);

        let (chosen, also_present) = match (has_struct, has_content) {
            (true, true) => {
                let primary = opts.prefer.unwrap_or(Domain::Structure);
                let secondary = match primary {
                    Domain::Structure => Domain::Content,
                    Domain::Content => Domain::Structure,
                };
                (primary, Some(secondary))
            }
            (true, false) => (Domain::Structure, None),
            (false, true) => (Domain::Content, None),
            (false, false) => {
                return Err(StrHideError::NoHiddenData(format!(
                    "No hidden data found in '{}'",
                    carrier.display()
                )));
            }
        };

        match chosen {
            Domain::Structure => {
                let read_res = self.structure().read_file(
                    carrier,
                    &crate::structure::ReadOptions {
                        output_path: None,
                        password: opts.password,
                        overwrite: false,
                    },
                )?;
                let kind = if read_res.is_file {
                    crate::core::payload::PayloadKind::File
                } else {
                    crate::core::payload::PayloadKind::Text
                };
                let mut payload = crate::core::payload::Payload::owned(read_res.data).with_kind(kind);
                if !read_res.filename.is_empty() {
                    payload = payload.with_name(read_res.filename);
                }
                Ok(ExtractOutcome {
                    payload,
                    source: Domain::Structure,
                    also_present,
                })
            }
            Domain::Content => {
                let ex_opts = crate::stego::ExtractOptions {
                    password: opts.password,
                    domain: opts.domain,
                    limits: opts.limits.clone(),
                    control: opts.control,
                    pool: None,
                };
                let payload = crate::stego::io::extract_carrier_file_payload(
                    carrier,
                    &ex_opts,
                    &self.dialect().stego,
                )?;
                Ok(ExtractOutcome {
                    payload,
                    source: Domain::Content,
                    also_present,
                })
            }
        }
    }
}

```

### U4：结构域进度与取消接入——外包 `ProgressWriter` 与 `.bak` 提交时序守卫（G1）

#### 1. 源码证据与设计权衡

* `WriteOptions`（`src/structure/options.rs:22`）、`ReadOptions`（`:59`）、`RestoreOptions`（`:103`）均无 `control: Control<'a>` 字段。

* 结构域所有适配器写入均通过 `out: &mut dyn Write`（`inject`）或 `out: &mut dyn SeekWrite`（`strip`），且底层流拷贝收敛于 `src/structure/adapters/io.rs:13, 33`（`copy_exact` / `copy_stream`）。

* **关键时序陷阱（27日方案 G1 取舍 4）**：在 `write_carrier_with`（`src/structure/engine.rs:1207`）和 `remove_carrier_with_dialect`（`:1823`）中，流程是：`写入/校验临时文件` → `std::fs::copy 生成 .bak` → `rename(tmp -> target)`。`TmpGuard`（`src/commit.rs:59`）只负责在出错/取消时清理 `.strhide.tmp`，**不会清理 `.bak`**！如果在生成 `.bak` 之后、`rename` 之前响应取消，磁盘上会多出一个孤儿 `.bak` 文件。

#### 2. 可靠修复方案

1. 在 `WriteOptions`、`ReadOptions`、`RestoreOptions` 中增加 `pub control: Control<'a>`（由于 `Control<'a>` 是 `Copy`，三个 Options 结构体依然保持 `Copy`！）。

2. 在 `src/core/control.rs` 中新增 `ProgressWriter` 与 `ProgressSeekWriter`，在引擎调用 `adapter.inject`、`adapter.strip` 和 `verify_restored` 时包装输出流，**10 个格式适配器一行代码不用改**：

```
// 新增于 rust/src/core/control.rs
use std::io::{self, Seek, SeekFrom, Write};

pub const PROGRESS_STEP_BYTES: u64 = 4 * 1024 * 1024; // 每 4 MiB 触发一次进度回调

pub struct ProgressWriter<'a, 'c, W: Write + ?Sized> {
    inner: &'a mut W,
    control: Control<'c>,
    stage: Stage,
    total: u64,
    done: u64,
    next_report: u64,
}

impl<'a, 'c, W: Write + ?Sized> ProgressWriter<'a, 'c, W> {
    pub fn new(inner: &'a mut W, control: Control<'c>, stage: Stage, total: u64) -> Self {
        control.stage_sized(stage, total);
        Self {
            inner,
            control,
            stage,
            total,
            done: 0,
            next_report: PROGRESS_STEP_BYTES.min(total),
        }
    }
}

impl<W: Write + ?Sized> Write for ProgressWriter<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.control.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "strhide: cancelled"));
        }
        let n = self.inner.write(buf)?;
        self.done += n as u64;
        if self.done >= self.next_report || self.done == self.total {
            self.control.report(Event::progress(self.stage, self.done, Some(self.total)));
            self.next_report = self.done + PROGRESS_STEP_BYTES;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write + Seek + ?Sized> Seek for ProgressWriter<'_, '_, W> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// 将底层因取消产生的 Interrupted I/O 错误还原为 StrHideError::Cancelled
pub fn map_io_cancel(control: &Control<'_>, err: StrHideError) -> StrHideError {
    match err {
        StrHideError::Io(ref io_err)
            if io_err.kind() == io::ErrorKind::Interrupted && control.is_cancelled() =>
        {
            StrHideError::Cancelled
        }
        other => other,
    }
}

```

3. **严格界定不可取消的原子提交区**：在 `write_carrier_with`（`inject` + `finalize` 完成后）和 `remove_carrier_with_dialect`（`verify_restored` 完成后），进入 `.bak` 复制前执行最后一次 `options.control.check()?`；一旦开始复制 `.bak` 与 `rename`，视为不可中断的提交事务，彻底杜绝孤儿 `.bak` 文件。

### U5：内容域全阶段进度补齐与 HEVC 扫描/并行重编码取消检查点（G8 + 增量 4.2）

#### 1. 源码证据与设计边界

* **生产代码 0 处 `Event::progress`**：`rg "Event::progress|stage_sized" rust/src` 仅命中 `core/control.rs` 的测试。

* **HEVC 2026-10-28 批次 3 遗漏 `Stage::Encode`**：`src/stego/hevc/engine.rs:765, 773` 上报了 `Stage::Decode` 和 `Stage::Solve`，但在第 890–950 行进入多核切片重编码（`reencode_slice`）时漏掉了 `control.stage(Stage::Encode)`。

* **HEVC 长耗时扫描无取消点**：`probe_hevc_pool`（`src/stego/hevc/engine.rs:364`）与 `record_carrier_state`（`:766, :1430, :1742`）未接收 `control: &Control<'_>`。对 24 分钟视频执行 `capacity --exact`（耗时 168 秒）时，NAL 切片循环内完全无法响应取消。

* **容量探测（`probe`）无阶段上报（G8）**：`png/engine.rs:1885`、`jpeg/engine.rs:1496`、`hevc/engine.rs:368` 的 `probe` 路径只有 `control.check()`，没有任何 `Stage::Decode` / `Stage::CostMap` 进度事件，GUI 点击“测量容量”时进度条完全不动。

#### 2. 可靠修复方案

1. **为 `record_carrier_state` 与 `probe_hevc_pool` 传入 `control: &Control<'_>`**：

   * 在遍历 `candidates`（NAL 切片列表，总数 `total_slices` 已知）时，先调用 `control.stage_sized(Stage::Decode, total_slices as u64)`；

   * 每处理 16 个切片调用一次 `control.check()?` 与 `control.report(Event::progress(Stage::Decode, idx as u64, Some(total_slices as u64)))`。

2. **补齐 PNG / JPEG / HEVC 的 `probe` 与 `extract` 阶段上报（G8）**：

   * PNG / JPEG 的 `probe` 复用与 `embed` 相同的 `Stage::Decode` → `Stage::CostMap` 上报点；在 `compute_cost` 按行块/DCT 块并行计算时，每完成一批上报 `Event::progress(Stage::CostMap, done, Some(total))`。

3. **HEVC 多轮排除重试（`MAX_EMBED_ROUNDS`）与 Rayon 并行重编码的进度语义（回应审核意见 §5.3）**：

   * 在 `embed_hevc_patches_with_factor` 的 `for round in 0..MAX_EMBED_ROUNDS` 循环外（首次进入重编码前）上报 `control.stage_sized(Stage::Encode, touched_slices.len() as u64)`；

   * 在 `par_iter()` 内部首行调用 `control.check()?`：需要说明的是，Rayon 的 `collect::<Result<Vec<_>, _>>()` 在检测到首个 `Err(StrHideError::Cancelled)` 后会停止拉取未开始的任务，正在执行中的几个线程跑完当前切片（单切片仅几毫秒）后即刻汇合返回 `Err(Cancelled)`，不会继续后续轮次；

   * 若因 EPB 防竞争冲突进入下一轮 retry（实测绝大多数在 1–2 轮内完成），进度条保持在 `Stage::Encode` 并刷新当前轮次的 `done / total`。

### U6：i18n 多线程同步、稳定消息 ID（`Msg::id`）与高频错误结构化（G3 + 增量 5.1 / 7.1）

#### 1. 源码证据与两份评审的融合裁决

* `src/core/i18n/mod.rs:48-60` 使用 `thread_local! { static CURRENT: Cell<Lang> }`，UI 主线程调用 `set_lang(Lang::Zh)` 后，后台工作线程的 `lang()` 仍返回 `Lang::En`。

* `src/errors.rs:240` 的 `ErrorDetail` 没有实现 `Serialize`，也没有机器可读的 `ErrorKind`。

* **为什么将“底层 `AtomicU8`”与“显式 `RenderCtx` + `Msg::id()`”结合是最佳方案？**

  * 审核意见（`strhide_gui_audit_review_20261028.md` §3.5 / §4）指出：v1 把 `ErrorDetail.category: Option<Msg>` 替换为 `category_label: Option<String>` 会丢失 `Msg` 这个稳定枚举键，且多语言客户端/服务端需要显式 `RenderCtx { lang }`；

  * 交叉复核报告（GMF §四.2）指出：如果强制把全库 7 个文件 71 处 `t!` 调用全部手动改成 `t!(ctx, ...)`，改动面过大且易引发合并冲突。

  * **两全其美的解法**：

    1. 将 `core/i18n/mod.rs:48` 的 `thread_local!` 替换为 `static CURRENT_LANG: AtomicU8 = AtomicU8::new(0)`（5 行代码改动，让现有 71 处無参 `t!(Msg::...)` 在多线程桌面 GUI 下瞬间具备跨线程一致性，零破坏）；

    2. **同时**新增 `RenderCtx { pub lang: Lang }` 与 `t!(ctx = my_ctx, Msg::...)` 宏分支，并在 `i18n_messages!` 宏中为 `Msg` 生成稳定的 `pub const fn id(self) -> &'static str`（返回 `"ErrIo"`、`"WarnSizeInflation"` 等标识符）；

    3. **保留 `ErrorDetail.category: Option<Msg>` 不变**，为 `Msg` 实现 `Serialize`（序列化为其稳定 `id()` 字符串），并为 `ErrorDetail` 增加 `pub kind: ErrorKind`！

#### 2. 可靠修复方案

```
// 1. rust/src/core/i18n/mod.rs：原子默认语言 + 显式 RenderCtx + Msg::id() 稳定键
use std::sync::atomic::{AtomicU8, Ordering};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Zh,
}

static CURRENT_LANG: AtomicU8 = AtomicU8::new(0); // 0 = En, 1 = Zh

pub fn set_lang(lang: Lang) {
    CURRENT_LANG.store(match lang { Lang::En => 0, Lang::Zh => 1 }, Ordering::Relaxed);
}

pub fn lang() -> Lang {
    match CURRENT_LANG.load(Ordering::Relaxed) {
        1 => Lang::Zh,
        _ => Lang::En,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RenderCtx {
    pub lang: Lang,
}

impl RenderCtx {
    pub const fn new(lang: Lang) -> Self {
        Self { lang }
    }
    pub fn current() -> Self {
        Self { lang: lang() }
    }
}

// 在 i18n_messages! 宏生成的 impl Msg 中增加 id() 与 Serialize：
impl Msg {
    pub const fn id(self) -> &'static str {
        match self {
            $(Msg::$name => stringify!($name),)*
        }
    }
}

impl Serialize for Msg {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.id())
    }
}

```

```
// 2. rust/src/errors.rs：保留 category: Option<Msg>，新增 ErrorKind 与 6 个高频结构化变体（G3）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Io,
    CorruptedData,
    Password,
    PasswordWithHint,
    TrellisInfeasible,
    Rejection,
    AlreadyExists,
    TargetBusy,
    SafetyThreshold,
    RestoreMismatch,
    UnsupportedFormat,
    NoHiddenData,
    UnsupportedVersion,
    Cancelled,
    General,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorDetail {
    /// 机器可读的稳定错误分类（供前端 switch-case 弹窗或分支处理）
    pub kind: ErrorKind,
    /// 稳定消息目录枚举（序列化为 Msg::id() 如 "ErrPassword"）
    pub category: Option<crate::core::i18n::Msg>,
    /// 按当前或指定语言预渲染的分类前缀（如 "密码错误"）
    pub category_label: Option<&'static str>,
    /// 底层详情描述
    pub detail: String,
    /// 密码提示（当 kind == PasswordWithHint 时存在）
    pub hint: Option<String>,
}

```

同时按 G3 规范，将 GUI 最高频触发的错误变体升级为携带强类型结构化字段（不再让 GUI 从英文字符串里用正则抠路径或字节数）：

* `AlreadyExists(PathBuf)`：目标文件已存在时直接携带路径，方便 GUI 弹出“文件 `xxx` 已存在，是否覆盖 / 另存为？”对话框；

* `TargetBusy(PathBuf)`：Windows 下目标文件被预览组件或外部进程占用（配合 U10）；

* `SafetyThreshold { tier: SafetyLevel, required_bytes: usize, available_bytes: usize }`：携带安全档位、当前载荷字节数与推荐上限字节数，方便 GUI 绘制容量对比条并提供“切换至 Balanced 档位”快捷按钮；

* `RestoreMismatch { restored_size: u64, expected_size: u64, restored_sha256: String, expected_sha256: String, residual_envelope: bool }`：结构化展示还原校验失败的期望值与实际值。

此外，对 G3 列出的 **7 个 GUI 必显结构字段**（`Warning`、`LevelStatus`、`StrategyCapacity`、`VerifyLevel` 等）提供 `.render(ctx: RenderCtx) -> String` 方法，在 `messages.rs` 中增补约 20 条中英文模板，确保 `Lang::En` 下输出与现有英文逐字相同，`Lang::Zh` 下实现 100% 纯中文展示。

## 三、 P1 级高优先级缺口详解与可靠修复方案（U7–U12）

### U7：内容域文件级对称接口与大文件有界流式诊断 vs. `mmap` 评估（G4 + 增量 6.1）

#### 1. 源码证据与 `mmap` 安全性深度评估（回应审核意见 §4 / §5.2）

* `StegoFacade`（`src/facade.rs:390-514`）目前有 `embed_file` 和 `extract_file`（以及 `stego/io.rs:98` 的 `extract_carrier_file`），但**缺少 `probe_file`、`inspect_file`、`verify_file`**。

* 当 GUI 在文件列表中展示一个 2 GB 的 MP4 视频并调用诊断接口时，如果底层直接调用 `std::fs::read(carrier_path)`（如 `src/stego/io.rs:39, 112` 及 `src/cli/cmd_diag.rs:46` 所示），会瞬间分配 2 GB 堆内存！

* **有界流式读（Bounded Read）vs. `memmap2::Mmap` 的权衡**：
  审核意见（`strhide_gui_audit_review_20261028.md` §4 & §5.2）敏锐指出：`unsafe { Mmap::map(&file) }` 在文件被外部进程并发截断或修改（或位于 SMB/NFS 网络挂载盘）时，操作系统会向进程发送 `SIGBUS`（Unix）或 `STATUS_IN_PAGE_ERROR`（Windows），在 Rust 中无法通过 `Result` 捕获，会直接导致整个 GUI 进程崩溃！

#### 2. 可靠修复方案（两级策略，安全优先）

1. **第一级（强制、零 `unsafe`、零新依赖）：`inspect_carrier_file` 采用有界窗口流式读取（G4）**

   * PNG `inspect` 只需读取 PNG 头与前几个 IDAT 块解出前几行像素（或对于大图限制最大扫描尺寸）；

   * JPEG `inspect` 只需读取前部系数解出 718 个超块槽位；

   * HEVC / MP4 `inspect`（Scheme C v2，`StopCondition::MinSlots(2048)`）只需解析 `moov` 盒子样本表 + 读取 `mdat` 中前 1\~2 个 NAL 切片的字节区间（仅几十 KB），**完全不需要把整个 2 GB 的 `mdat` 读进内存**！

   * 实现 `stego::io::{inspect_carrier_file, verify_carrier_file, probe_carrier_file}` 并挂入 `StegoFacade`，其中 `inspect_carrier_file` 对 MP4 通过 `Seek + Read` 只读取 `moov` 与前 2 个切片字节，使 2 GB 视频的 `inspect_file` 峰值内存严格 **≤ 8 MiB**！

2. **第二级（可选 Feature `mmap`，仅用于本地大文件 `probe_file` / `embed_file`）**：

   * 仅当用户开启可选 `mmap` Feature 且目标为本地常规文件时，在 `probe_carrier_file` / `embed_carrier_file` 中使用只读映射以节省数 GB 堆分配，并在原地覆写 `commit_carrier_patches` 前显式 `drop(mmap)` 释放句柄。

### U8：IPC 大载荷隔离（`ReadSummary`）、`InspectResult.metadata` 强类型化与 `Deserialize` 补齐（增量 5.2 / 5.3 / 5.4）

#### 1. 源码证据（含 §5.4 措辞修正）

* **`ReadResult`（`src/structure/engine.rs:449`）**：未实现 `Serialize`；且即使 `ReadOptions.output_path` 已指定将载荷写入磁盘文件，`ReadResult.data: Vec<u8>` 依然保留了完整载荷字节。若直接经 Tauri IPC 序列化返回前端，100 MB 文件会变成一亿个十进制数字的 JSON 数组，直接撑爆 WebView。

* **`InspectResult.metadata`（`src/structure/engine.rs:483, 2004-2024`）**：类型为 `Option<serde_json::Value>`。当未提供密码时为 `None`；**当调用方提供了密码但元数据解密失败时**（`:2021`），代码写入 `Some(serde_json::json!({"error": "Invalid password"}))`。这迫使前端做弱类型 JSON 键嗅探。

* **`InspectResult` 缺少 `suspicious_hints`**：当载体包含 Stealth 隐身信封且未提供密码时，`has_hidden_data` 为 `false`；此时 `adapter.suspicious_structures(carrier)`（仅在 `engine.rs:601` 读失败与 `:811` 写警告中调用）能ตรวจ出可疑结构（如 `private PNG chunk 'prIv'`），但 `InspectResult` 却没有字段将该提示传给 GUI！

* **缺失 `Deserialize`**：`FileFormat`（`src/formats/sniff.rs:133`）与 `StrategyId`（`src/structure/registry.rs:183`）仅有手写 `Serialize`，无 `Deserialize`。

#### 2. 可靠修复方案

1. **为 `ReadResult` 提供轻量级 IPC 摘要转换 `ReadSummary`**：

```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReadSummary {
    pub carrier: PathBuf,
    pub is_file: bool,
    pub is_encrypted: bool,
    pub filename: String,
    pub raw_size: u64,
    pub written_file: Option<PathBuf>,
    /// 仅当载荷为文本（或 UTF-8 可读）且 <= 64 KiB 时内联携带，避免大文件撑爆 IPC
    pub text_preview: Option<String>,
}

```

2. **强类型化 `InspectResult.metadata` 并补齐 `suspicious_hints`**：

```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CarrierMetadata {
    pub filename: String,
    pub raw_size: u64,
    pub raw_sha256: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum MetadataInspection {
    Decrypted(CarrierMetadata),
    DecryptFailed { error: String },
}

```

在 `InspectResult` 中将 `metadata` 类型改为 `Option<MetadataInspection>`（得益于 `#[serde(untagged)]`，CLI `--json` 输出格式 100% 保持不变！），并新增：

```
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub suspicious_hints: Vec<String>,

```

当 `has_hidden_data == false` 时填入 `adapter.suspicious_structures(carrier)`，让 GUI 能够提醒用户“检测到可疑隐身信封结构，请尝试输入密码解锁”。
3. **补齐 `FileFormat`、`StrategyId`、`Warning`、`LocalParams`、`CompressionStrategy`、`RejectionPolicy` 的 `Deserialize` 实现**。

### U9：无打印结构化批处理执行器 `core::batch` 与库内 `eprintln!` 清理（G5 + 增量 4.3 / 6.2）

#### 1. 源码证据

* `core::pipeline::for_each_carrier`（`src/core/pipeline.rs:30-65`）内部直接调用 `println!` / `eprintln!`，遇到首个错误直接 `return Err(e)` 中断，无逐项结果返回、无 `CancelToken`、无并发度控制。

* `src/core/config.rs:114, 132`、`src/stego/jpeg/engine.rs:185`、`src/stego/png/engine.rs:736` 存在直接向 stderr 输出的 `eprintln!`。

#### 2. 可靠修复方案（统一采用 27日方案 G5 `core::batch::run_batch`）

将批量执行器收敛为唯一一套 `core::batch::run_batch`（不再保留两套命名）：

```
// 新增于 rust/src/core/batch.rs
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::core::control::{CancelToken, Control};
use crate::errors::{ErrorDetail, StrHideError};

#[derive(Debug, Clone, Default)]
pub struct BatchPlan {
    /// true = 单文件失败后记录错误并继续后续文件（GUI 队列默认）；false = 首错即停（CLI 默认）
    pub continue_on_error: bool,
    /// 最大并发数：1 = 串行（大内存内容域推荐）；>1 = 受控并行
    pub max_concurrency: usize,
    pub cancel: Option<Arc<CancelToken>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemOutcome<R> {
    pub index: usize,
    pub item: PathBuf,
    pub result: Result<R, ErrorDetail>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOutcome<R> {
    pub items: Vec<ItemOutcome<R>>,
    pub succeeded: usize,
    pub failed: usize,
    pub cancelled: bool,
}

```

同时在 `formats::capability::Capability` 中增加 `pub memory: MemoryProfile`（`Streaming` vs `WholeFile`），供 GUI 任务队列自动决定并发度（结构域流式可并行，内容域大图/视频默认串行防 OOM）；并将 `core::config::load` 的配置项告警改为收集在结构体字段 `warnings: Vec<String>` 中返回，彻底清除非 `cli` 模块中的 `println!` / `eprintln!`。

### U10：桌面端崩溃隔离（`panic = "unwind"`）与 Windows 预览文件锁重试（`TargetBusy`）（G9）

#### 1. 源码证据与桌面端真实痛点

* `rust/Cargo.toml:128` 配置了 `[profile.release] panic = "abort"`。若 GUI 二进制沿用此配置，工作线程任何一处意外 panic（如第三方解码器边界条件或 `capability_of` 在 `src/formats/capability.rs:134` 的 `panic!`）都会直接终止整个 GUI 进程，且跳过 `TmpGuard`（`src/commit.rs:59`）的 `Drop` 析构，在用户目录留下半成品 `.strhide.tmp`！

* `src/commit.rs:170` 直接执行 `std::fs::rename(&tmp_path, path)?`。在 Windows 桌面 GUI 中，当用户正在界面右侧用 `<video>` 或 `<img>` 标签预览载体文件时，操作系统文件句柄处于打开状态，此时点击“原地写入/还原”必然在 `rename` 处触发 `ERROR_SHARING_VIOLATION (os error 32)` / `PermissionDenied`。

#### 2. 可靠修复方案

1. **在 `commit.rs` 中为 `rename` 增加有界退避重试与 `TargetBusy` 专用错误**：

```
// rust/src/commit.rs 改进方案
fn rename_with_retry(from: &Path, to: &Path) -> Result<(), StrHideError> {
    const BACKOFF_MS: [u64; 3] = [20, 50, 100];
    let mut last_err = None;
    for (attempt, &wait_ms) in BACKOFF_MS.iter().enumerate() {
        match std::fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if is_sharing_or_permission_error(&e) => {
                last_err = Some(e);
                if attempt + 1 < BACKOFF_MS.len() {
                    std::thread::sleep(std::time::Duration::from_millis(wait_ms));
                }
            }
            Err(e) => return Err(StrHideError::Io(e)),
        }
    }
    // 三次重试仍被占用，返回结构化 TargetBusy 错误，供 GUI 提示“请先关闭预览或选择另存为”
    let _ = last_err;
    Err(StrHideError::TargetBusy(to.to_path_buf()))
}

```

2. **清理库内可达 `panic!`**：将 `formats::capability::capability_of` 中的 `panic!` 改为编译期穷尽 `match`（`FileFormat` 的所有枚举分支直接映射到静态 `Capability` 引用），从根源上消除运行期 panic 可能！

3. **GUI 宿主 Profile 规范**：在 Workspace 的 GUI 子包（如 `src-tauri/Cargo.toml`）中显式声明 `panic = "unwind"`，并在后台任务入口使用 `std::panic::catch_unwind` 兜底转换为 `StrHideError::General`，保证 `TmpGuard::drop` 100% 触发。

### U11：密码日志脱敏（Redacted `Debug`）、表单脏检查与强类型 `Strategy`（G6 + 增量 2.5）

#### 1. 源码证据

* `WriteOptions`（`src/structure/options.rs:21`）、`ReadOptions`（`:58`）、`RestoreOptions`（`:102`）、`EmbedOptions`（`src/stego/options.rs:403`）、`ExtractOptions`（`:701`）等全部使用 `#[derive(Debug)]`。一旦 GUI 开启 `tracing::instrument` 或调试日志打印 `{opts:?}`，**用户的明文密码会直接写入日志文件**！

* `EmbedOptions` 与 `StegoTuning` 未实现 `PartialEq`，GUI 设置面板无法直接对比 `current_opts != saved_opts` 判断是否有未保存修改。

* `WriteOptions.strategy` 为 `&'a str`（`:30`），而输出侧已是强类型 `StrategyId`；`PayloadSource::Stdin`（`src/structure/engine.rs:304`）暴露在库级枚举中；`FileConfig` 转 `*Options` 的函数困在 `src/cli/helpers.rs:226-373`。

#### 2. 可靠修复方案

1. **手写所有含 `password` 选项结构体的 `std::fmt::Debug`**：将 `password` 字段格式化为 `Some("<redacted>")` 或 `None`。

2. **为 `StegoTuning` 与 `EmbedOptions` 实现 `PartialEq`**（`SpatialAlgorithm::Custom` 与 `JpegAlgorithm::Custom` 按 `model.id()` 或 `Arc::ptr_eq` 判等）。

3. **强类型化写入策略选择**：新增 `pub enum StrategyChoice { Auto, Named(StrategyId) }`（保留 `From<&str>` 兼容），并将 `FileConfig` 派生 `WriteOptions` / `EmbedOptions` 的方法下沉至 `core::config::FileConfig`。

### U12：运行时私有方言（`RuntimeDialect`）与异步任务跨线程控制模式（增量 3.1 / 3.2）

#### 1. 针对审核意见 §4 与 §5.1 的深度修正

* **修正 v1 的 `intern_dialect_str` 泄漏池问题**：审核意见 §5.1 正确指出，若用全局 `HashSet<&'static str>` + `Box::leak` 驻留用户在 GUI 中输入的部署密钥，每次输错重改都会在进程内存中永久残留一条明文密钥，属于安全反模式。

* **正确解法**：

  1. 绝大多数组织定制版 GUI 的私有方言在编译期或进程启动时固定一次即可，无需每次调用动态 `leak`；

  2. 若确需在 GUI 运行期动态切换“组织默认密钥 (`default_secret`)”或“隐写隔离域 (`domain`)”，对于每次调用，直接通过 `WriteOptions.password` / `EmbedOptions.password` 与 `EmbedOptions.domain` 传入即可；或者在 `facade` 中提供一个内部持有 `Arc<str>`（配合 `zeroize`）的 `OwnedDialect` 辅助容器，在工作线程作用域内借用给底层引擎，彻底避免 `&'static str` 泄漏。

* **保持 `Control<'a>` 为 `Copy`，提供零开销跨线程范式**：
  审核意见 §4 强调 `Control<'a>` 必须保持 `Copy`（从而让 `WriteOptions` 等保持 `Copy`）。在 `tokio::spawn_blocking` 或 `std::thread::spawn` 中，其实**根本不需要修改 `Control<'a>` 的定义**：只需将 `Arc<CancelToken>` 和 `mpsc::Sender`（或 Tauri `Channel`）`move` 进工作线程闭包，在闭包栈帧内部构造 `Control { progress: &bridge, cancel: Some(&token) }` 即可！为方便调用方少写模板代码，可在 `core::control` 中附加一个独立的 Owned 辅助结构 `TaskControl`（不替代 `Control<'a>`）：

```
// 新增于 rust/src/core/control.rs：不改动 Control<'a> 的 Copy 语义，仅作为跨线程搬运助手
#[derive(Clone, Default)]
pub struct TaskControl {
    pub progress: Option<std::sync::Arc<dyn Progress>>,
    pub cancel: std::sync::Arc<CancelToken>,
}

impl TaskControl {
    pub fn new(progress: impl Progress + 'static) -> Self {
        Self {
            progress: Some(std::sync::Arc::new(progress)),
            cancel: std::sync::Arc::new(CancelToken::new()),
        }
    }

    /// 在工作线程闭包内部借用出 Copy 的 Control<'_>
    pub fn borrow_control(&self) -> Control<'_> {
        Control {
            progress: match &self.progress {
                Some(p) => p.as_ref(),
                None => &NoProgress,
            },
            cancel: Some(&self.cancel),
        }
    }
}

```

## 四、 P2 级增强与工程收尾（U13–U14）

### U13：`analysis` 接入 `StrHide` 门面与 `EmbedOutput` 真实修改统计（增量 2.4 + 7.2 修正版）

1. **`analysis` 子门面与 `scan_bytes`**：
   在 `src/analysis.rs:263` 的 `scan_file` 旁拆分出 `scan_bytes(data: &[u8], label: &str)`，并在 `StrHide` 上暴露 `.analysis()` 子门面，使 GUI 能对内存中的隐写预览产物直接执行黑盒隐写分析评分对比。

2. **关于 `EmbedOutput.capacity` 与 `EmbedStats` 的诚实设计（回应审核意见 §2.3）**：

   * `src/stego/options.rs:870-875` 明确注释：PNG 与 JPEG 的 `embed` 路径刻意将 `capacity` 置为 `None`，因为 `embed_png`（`src/stego/png/engine.rs:1173`）只计算了单通道绿池 `pool_green`，`embed_jpeg`（`src/stego/jpeg/engine.rs:782`）只计算了 `enforced_payload_limit`，并未运行 `probe` 的完整分组容量模型。**我们完全尊重并保留这一设计契约，不在 `embed_png`/`embed_jpeg` 中伪造或额外重跑 `StegoCapacityInfo`**。

   * 但与此同时，`embed_jpeg`（`src/stego/jpeg/engine.rs:655` 的 `applied: Vec<(u32, i8)>`）、`embed_png`（翻转计数）和 `embed_hevc`（翻转槽位数）在嵌入完成时**确实已经精确持有“本次实际修改了多少个元素（`modified_slots`）”**！因此在 `EmbedOutput` 中新增可选的 `pub stats: Option<EmbedStats>`（记录 `modified_slots` 与 `total_candidate_slots`），真正做到**零额外计算成本**，同时让 GUI 能在嵌入完成后立即向用户展示：“本次共精细微调了 1,420 个像素/系数（修改率 0.08%）”。

### U14：模块清理、边界守卫脚本与推荐 Feature 矩阵（G7 + G10）

1. **清理组织遗留（G7）**：

   * 将 `crypto`、`errors`、`params`、`commit` 移入 `src/core/`，顶层 `lib.rs` 保留 `pub use` 重导出；

   * 删除 0 调用点的死导出 `structure::supports_content_stego`（`src/structure/mod.rs:33`、`registry.rs:57`）与过渡兼容层 `src/sniff.rs`；

   * 新增 `scripts/import_lint.py` 并加入 CI，硬性守护三条边界：`structure ↛ stego`、`stego ↛ structure`、`core ↛ {formats, structure, stego, cli}`。

2. **GUI 推荐 Feature 组合表（G10a）**：

   * **标准读写与诊断 GUI**：`default-features = false, features = ["structure", "content"]`（不拉入 `analysis` 专用的 `jpeg-decoder`）；

   * **含反隐写取证页的全功能 GUI**：`default-features = false, features = ["structure", "content", "analysis"]`；

   * **纯图像轻量隐写工具**：`default-features = false, features = ["structure-base", "content-png", "content-jpeg"]`（零反汇编依赖、零 H.265 依赖）。

3. **跨语言与 IPC 形态决策（G10c）**：明确**不构建 C ABI**，统一采用 **JSON-over-IPC**（Tauri Command 直接序列化强类型 Rust 结构，Electron / Python / Flutter 走进程内绑定或 `--json`）。

## 五、 统一分阶段实施路线图与硬性验收表

我们将全部 14 项任务（U1–U14）按依赖关系编排为 **4 个实施阶段（Stage A–D，总计约 6.5–8.5 人日）**。

```
Stage A (P0 编译修复与错误/i18n地基)
   │  解锁 Msg::id() 与 ErrorDetail: Serialize
   ▼
Stage B (P0 门面统一、零拷贝收口与全链路进度/取消)
   │  解锁 GUI 单文件完整闭环（打开诊断 -> 容量探测 -> 嵌入/写入 -> 智能提取 -> 还原）
   ▼
Stage C (P1 有界诊断读、结构化批处理、Windows防锁与安全脱敏)
   │  解锁 GUI 批量任务队列、大视频秒级列表预览与生产级健壮性
   ▼
Stage D (P2 分析门面、修改统计与边界守卫收尾)

```

### 阶段划分与逐项硬性验收标准

| 阶段 | 包含任务 | 预计工期 | 一条式硬性验收口径（Pass / Fail） | 
| ----- | ----- | ----- | ----- | 
| **Stage A**  （P0 地基） | **U1**（Feature 门控修复 + CI 矩阵）  **U6**（i18n `AtomicU8` + `Msg::id()` + `ErrorDetail: Serialize` + 6 个结构化错误变体） | 1.5–2 人日 | 1\. `cargo check --no-default-features --features content-png` 与 `content-jpeg` 零错误通过；  2\. `serde_json::to_string(&err.detail_i18n())` 成功输出含 `kind` 与 `category` (`Msg::id()`) 的 JSON；  3\. `Lang::En` 下 7 个必显字段 `render()` 与原 `message()` 逐字节相等。 | 
| **Stage B**  （P0 核心） | **U2**（`StegoEmbedResult` + CLI 零拷贝汇合）  **U3**（`inspect_any` / `verify_any` / `smart_extract`）  **U4**（结构域 `ProgressWriter` + `.bak` 时序）  **U5**（内容域 `probe`/`hevc` 进度与取消） | 2.5–3 人日 | 1\. `cli/cmd_stego.rs` 改调 `embed_carrier_file`，529 MB 视频嵌入峰值内存不回退；  2\. `inspect_any` 的 `--json` 输出与现有 CLI diff 为空；双域皆有载荷时 `smart_extract` 的 `also_present` 非空；  3\. 4 GB 载体还原中途取消返回 `Cancelled`，无残留 `.tmp` 且**无多出 `.bak`**；  4\. 50 MP JPEG `probe` 与长视频 HEVC `Decode`/`Encode` 均上报中间进度且可随时取消；  5\. `python scripts/baseline_hash.py --check` 全量字节一致。 | 
| **Stage C**  （P1 健壮性） | **U7**（`StegoFacade::*_file` + 有界诊断读）  **U8**（`ReadSummary` + `MetadataInspection` + `suspicious_hints`）  **U9**（`core::batch::run_batch` + 去 `eprintln!`）  **U10**（`TargetBusy` 重试 + `panic = "unwind"`）  **U11**（密码 `Debug` 脱敏 + `PartialEq`）  **U12**（`TaskControl`） | 2–2.5 人日 | 1\. 对 >2 GB 的 MP4 调用 `stego().inspect_file` 峰值内存 ≤ 8 MiB；  2\. 20 项批处理第 3 项失败且 `continue_on_error = true` 时，返回完整 20 条 `ItemOutcome` 且 stdout 零输出；  3\. Windows 下另一进程占用目标文件时，原地写入重试 3 次后返回 `StrHideError::TargetBusy`；  4\. 任意 `*Options` 的 `format!("{opts:?}")` 不包含传入的密码明文。 | 
| **Stage D**  （P2 收尾） | **U13**（`StrHide::analysis()` + `scan_bytes` + `EmbedStats`）  **U14**（`core` 目录归位 + `import_lint.py` + 文档同步） | 0.5–1 人日 | 1\. `python scripts/import_lint.py` 零违规通过；  2\. GUI 使用 `--no-default-features --features structure,content` 编译通过且 `cargo tree` 不含 `jpeg-decoder`。 | 

## 六、 修正后的 GUI 对接参考实现（Tauri v2 多任务安全版）

以下参考模板已彻底修正 v1 示例中的全部问题（采用多任务 `HashMap<u64, Arc<CancelToken>>` 替代单槽覆盖、使用新设计的 `FileTarget` 与 `StegoEmbedResult`、在 `spawn_blocking` 闭包内安全构造 `Control` 并包裹 `catch_unwind`）：

```
// src-tauri/src/commands.rs
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{ipc::Channel, State};

use strhide::core::control::{CancelToken, Control, Event, Progress};
use strhide::errors::{ErrorDetail, StrHideError};
use strhide::facade::{DualInspect, DualOptions, StrHide};
use strhide::prelude::*;

/// GUI 全局状态：StrHide 本身为 Copy，取消令牌按 task_id 独立登记，支持多任务并发与精准取消
#[derive(Default)]
pub struct GuiAppState {
    pub engine: StrHide,
    pub running_tasks: Mutex<HashMap<u64, Arc<CancelToken>>>,
}

#[derive(Clone, serde::Serialize)]
pub struct ProgressPayload {
    pub task_id: u64,
    pub stage: &'static str,
    pub done: u64,
    pub total: Option<u64>,
}

struct ChannelProgress {
    task_id: u64,
    channel: Channel<ProgressPayload>,
}

impl Progress for ChannelProgress {
    fn report(&self, ev: Event) {
        let _ = self.channel.send(ProgressPayload {
            task_id: self.task_id,
            stage: ev.stage.as_str(),
            done: ev.done,
            total: ev.total,
        });
    }
}

/// 推荐交互第 1 步：拖入文件时先跑廉价双域诊断（有界头尾读取，不读全量视频）
#[tauri::command]
pub async fn inspect_carrier_cmd(
    state: State<'_, GuiAppState>,
    carrier_path: PathBuf,
    password: Option<String>,
) -> Result<DualInspect, ErrorDetail> {
    let engine = state.engine;
    tauri::async_runtime::spawn_blocking(move || {
        let opts = DualOptions {
            password: password.as_deref(),
            domain: None,
            control: Control::none(),
        };
        engine.inspect_any(&carrier_path, &opts)
    })
    .await
    .map_err(|e| StrHideError::General(format!("Join error: {e}")).detail_i18n())?
    .map_err(|e| e.detail_i18n())
}

/// 推荐交互第 2 步：执行内容域文件嵌入（享受 MP4/HEVC 零拷贝补丁优化与实时进度）
#[tauri::command]
pub async fn embed_carrier_cmd(
    state: State<'_, GuiAppState>,
    task_id: u64,
    carrier_path: PathBuf,
    output_path: Option<PathBuf>,
    payload_file: PathBuf,
    password: Option<String>,
    backup: bool,
    preserve_time: bool,
    overwrite: bool,
    on_progress: Channel<ProgressPayload>,
) -> Result<strhide::stego::StegoEmbedResult, ErrorDetail> {
    let engine = state.engine;
    let token = Arc::new(CancelToken::new());
    state.running_tasks.lock().unwrap().insert(task_id, Arc::clone(&token));

    let outcome = tauri::async_runtime::spawn_blocking(move || {
        // 在任务边界使用 catch_unwind 兜底（配合 GUI Cargo.toml 的 panic = "unwind"），确保 TmpGuard 正常 Drop
        let res = catch_unwind(AssertUnwindSafe(|| {
            let reporter = ChannelProgress {
                task_id,
                channel: on_progress,
            };
            // Control<'_> 直接借用当前工作线程栈帧上的 reporter 与 token，保持 Copy 零开销
            let control = Control {
                progress: &reporter,
                cancel: Some(&token),
            };

            let name = payload_file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("payload.bin")
                .to_string();
            let bytes = std::fs::read(&payload_file)?;
            let payload = Payload::owned_file(name, bytes);

            let opts = EmbedOptions::default()
                .with_password(password.as_deref().unwrap_or_default())
                .with_control(control);

            let target = strhide::commit::FileTarget {
                output_path: output_path.as_deref(),
                backup,
                preserve_time,
                overwrite,
            };

            engine.stego().embed_file(&carrier_path, &payload, &opts, &target)
        }));

        match res {
            Ok(inner) => inner,
            Err(_) => Err(StrHideError::General("Internal engine panic caught at worker boundary".into())),
        }
    })
    .await;

    state.running_tasks.lock().unwrap().remove(&task_id);

    outcome
        .map_err(|e| StrHideError::General(format!("Worker join error: {e}")).detail_i18n())?
        .map_err(|e| e.detail_i18n())
}

/// 按 task_id 精准取消指定任务，不影响其它正在运行的任务
#[tauri::command]
pub fn cancel_task_cmd(state: State<'_, GuiAppState>, task_id: u64) -> bool {
    if let Some(token) = state.running_tasks.lock().unwrap().get(&task_id) {
        token.cancel();
        true
    } else {
        false
    }
}

```