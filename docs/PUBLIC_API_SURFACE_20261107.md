# StrHide Rust 库公开接口面收敛评估

- 日期：2026-11-07
- 范围：`rust/` 库 crate（`--all-features`），不含 GUI 前端；GUI 仅作为外部消费者统计引用。
- 性质：**只读梳理与方案，不修改任何代码、文档、不 commit**。
- 基线：[RELEASE_READINESS_20261106.md](./RELEASE_READINESS_20261106.md) §2.3（公开接口“可公开发布，但缺少演进护栏”；`facade` 结构清晰；121 个公开 struct 未标 `non_exhaustive`）。

---

## 0. 结论摘要

| 项 | 数字 | 性质 |
|---|---|---|
| 文档化公开条目（rustdoc sidebar） | **607** | 【实测】 |
| 唯一文档条目名 | **594** | 【实测】 |
| `pub mod` 声明 | **104**（其中 16 个 `#[doc(hidden)]`） | 【实测】 |
| `#[doc(hidden)]` 模块内顶层 `pub` 条目 | **141** | 【实测】 |
| 顶层公开条目合计（文档 + 隐藏模块） | **≈748**（1 个重名 `Freshness`） | 【实测/计算】 |
| crate 外（tests/examples/gui/bin）零引用条目 | **335 / 594 = 56.4%** | 【实测】 |
| 收敛后仍保留文档的条目 | **242**（`K` 206 + `KF` 36） | 【静态分析】 |
| 可下沉 `pub(crate)` | **82** | 【静态分析】 |
| 可 `#[doc(hidden)]` 保留 | **283** | 【静态分析】 |

**最高收益、最低风险的三件事**

1. 把 10 个内部模块整体 `#[doc(hidden)]`：`structure::{adapters,envelope,rejection,registry}`、`analysis::calibration`、`cli::args`、`core::i18n::messages`、`formats::{annexb,jpeg_segments}`、`stego::jpeg::cost::precover`。**不改可见性、不破坏编译**，文档面一次性减少 **229 条**（607 → 378）。
2. 修补 3 个“公开签名里出现不可达类型”的真实缺陷（`Tlv`、`StrategyCapacity`、`CipherSuiteId/Credential` 根导出声明），见 §4.0。
3. 文档与代码对齐：STEGO-API 的 audio 专家面在代码中**完全不存在**；`registry::CostModelRegistry` 路径错误；`non_exhaustive` 声明不实。见 §3。

> 关键前提：`#[doc(hidden)]` ≠ 私有。`stego::hevc::{slot,sniff,mp4_boxes,heif_boxes}`、`stego::coding`、`stego::prng`、`stego::jpeg::geometry` 等隐藏模块被 tests/examples 直接使用（例如 `CabacRecorder` 4 次、`parse_mp4_targets` 8 次、`deterministic_payload` 27 次、`geometry_for_carrier` 12 次）。这些**必须保持 `pub`**，只能隐藏文档，不能改 `pub(crate)`。

---

## 1. 统计方法与基线

### 1.1 三层口径

| 层 | 含义 | 采集方式 |
|---|---|---|
| L1 文档面 | docs.rs 实际展示的条目 | `cargo doc --all-features --no-deps`，遍历 `target/doc/strhide/**/sidebar-items.js` |
| L2 源码可见性面 | `pub mod` + `#[doc(hidden)]` + 隐藏模块内顶层 `pub` | `rg` 源码 |
| L3 外部引用面 | tests / examples / gui backend / bin 目标中的真实使用 | `rg` 全词匹配，按标识符计数 |

### 1.2 命令与输出【实测】

```powershell
cd C:\Home\Projects\strhide\rust
cargo doc --all-features --no-deps
# -> Generated target/doc/strhide/index.html ...；同时产生 9 条 rustdoc warning

C:\Home\Develop\venv\Scripts\python.exe C:\Home\Projects\strhide\temp\gen_appendix.py
# -> distribution rows: 89 items: 607

C:\Home\Develop\venv\Scripts\python.exe C:\Home\Projects\strhide\temp\public_api_scan2.py
# -> names: 594 zero_external: 335

rg -n "^pub mod " rust/src | Measure-Object          # 104
rg -n "^#[doc(hidden)]" rust/src | Measure-Object     # 22（属性级，含 16 个模块）
```

- 89 = 88 个文档化模块页 + crate root。
- 594 = 607 条目按名字去重（同名条目跨模块合并，如 `list`、`Freshness`、`estimate`）。
- 外部引用统计脚本先构造 `\b(?:name1|name2|...)\b` 单一正则，对每个消费树只跑一次 `rg -o`，再在 Python 内计数；`tests/`、`examples/`、`gui/src-tauri/src/`、`src/bin/`、`src/main.rs`、`src/lite.rs` 分列。
- 方法校验：v1（逐条目起 `rg` 子进程）与 v2 的零引用集合只差 1 项（`run_cli`，v1 漏计 `src/main.rs`）；v2 已用 `rg -w run_cli src/main.rs` 直接复核。

### 1.3 模块分布（文档化条目）【实测】

| 模块 | struct | enum | fn | trait | const | type | static | 合计 |
|---|---|---|---|---|---|---|---|---|
| `crate`（根，含 2 个宏） | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 |
| `facade` | 10 | 1 | 0 | 0 | 0 | 0 | 0 | 11 |
| `structure`（整棵子树） | 40 | 6 | 89 | 4 | 50 | 1 | 2 | 192 |
| `stego`（整棵子树） | 50 | 10 | 88 | 3 | 28 | 1 | 0 | 180 |
| `core`（整棵子树） | 22 | 12 | 49 | 1 | 35 | 1 | 0 | 120 |
| `formats` | 2 | 3 | 13 | 0 | 35 | 0 | 1 | 54 |
| `analysis` | 4 | 1 | 6 | 0 | 0 | 1 | 0 | 12 |
| `cli` + `cli_i18n` | 18 | 5 | 9 | 0 | 4 | 0 | 0 | 36 |
| **合计** | **146** | **38** | **254** | **8** | **152** | **4** | **3** | **607** |

其中 `structure/adapters` 子树 **126 条**（含 18 个映射器子模块），是最大的单块可收敛面。

### 1.4 外部引用 Top 20【实测】

| 次数 | 条目 | 定义模块 |
|---|---|---|
| 274 | `embed` | `structure/adapters/pe_codebits` |
| 221 | `PayloadSource` | `structure/engine` |
| 185 | `WriteOptions` | `structure/options` |
| 177 | `Payload` | `core/payload` |
| 163 | `StrHideError` | `core/errors` |
| 162 | `t`（宏） | `crate` |
| 153 | `ReadOptions` | `structure/options` |
| 149 | `EmbedOptions` | `stego/options` |
| 148 | `write_carrier` | `structure/engine` |
| 127 | `read_carrier` | `structure/engine` |
| 119 | `embed_carrier` | `stego` |
| 109 | `StructureProfile` | `structure/params` |
| 102 | `profile` | `structure/adapters/pe_codebits` |
| 102 | `RestoreOptions` | `structure/options` |
| 96 | `extract_carrier` | `stego` |
| 88 | `remove_carrier` | `structure/engine` |
| 81 | `Control` | `core/control` |
| 75 | `verify_carrier` | `stego` / `structure/engine` |
| 71 | `ExtractOptions` | `stego/options` |
| 59 | `Freshness` | `stego` |

### 1.5 统计局限（必须先声明）

1. 计数是**标识符出现次数**，包含注释、测试辅助名和同名方法。`embed`、`profile`、`list`、`load`、`t`、`estimate`、`bias` 等常见词会显著虚高。**零计数可靠，非零计数只能作为“有人在用这个方向”的证据。**
2. 公开字段/返回类型即使外部从不写名字，也属于 API 契约（如 `EmbedOutput`、`Warning`、`StrategyId`、`MediaInfo`）。附录 A 用 `KF` 单独标出。
3. `cargo doc --all-features` 覆盖所有 feature；默认 feature 集不含 `cli`，因此默认消费者看不到 `cli::*` 文档。
4. 所有判断分【实测】（命令/文件行可复核）与【静态分析】（读代码后的判断）；未使用任何伪造引用。

---

## 2. 公开面分层判定

判定代号（附录 A 每一行都有）：

- `K` 必须公开：外部真实使用，或文档明确承诺。
- `KF` 必须公开（类型闭包）：零外部引用，但它是某个公开字段/返回值的类型。
- `H` 隐藏但保留：保留 `pub`，加 `#[doc(hidden)]`（或所属模块整体隐藏）；测试/示例仍可编译。
- `C` 改 `pub(crate)`：crate 外零引用，且不出现在任何公开签名。
- `X` 删除/移除导出。

判据顺序：① crate 外真实调用 → ② 公开签名/字段类型闭包 → ③ 文档承诺（`docs/api/*`） → ④ 分层约束（`scripts/import_lint.py`）。

### 2.1 `crate` 根与 `prelude`

- 根 `pub use`：61 个条目 + 5 个模块（`crypto`/`errors`/`params`/`commit`/`i18n`），见 `rust/src/lib.rs:154-162`、`185-220`、`261-278`。
- `prelude`：34 个别名（`lib.rs` 的 `pub mod prelude` 段），与根导出集合不一致（缺 `StrategyId`、`Warning`、`EmbedOutput`、`StegoHeaderInfo`、`StegoVerifyResult`、`InspectOptions`、`VerifyOptions`）。
- **判定：根导出全部 `K`。** 理由：GUI 走模块路径（`strhide::errors::ErrorDetail`、`strhide::structure::engine::*`），但文档与 doctest 走根路径；删除根别名只会让文档失效，不减少任何唯一条目。
- **`prelude` 判定：保留**。它不新增语义条目，只增加别名；但建议补齐与根导出的差集，避免“两个入口集合不同”的认知负担。
- 例外：
  - `compute_default_threads`、`default_thread_count` → `C`（0 外部引用），同时删 `lib.rs:217-220` 中的两个名字；`init_default_thread_pool` 保留（`stego/mod.rs:126` 文档明确建议嵌入方显式调用）。
  - `i18n_messages`、`t` 两个 `#[macro_export]` 宏 → `H`（`#[doc(hidden)]`）。

### 2.2 `facade`（11 条）

| 条目 | 外部引用 | 判定 | 依据 |
|---|---|---|---|
| `StrHide` | 54 | K | GUI/示例主入口 |
| `Dialect` | 13 | K | `DualOptions`/`DualInspect` 使用 |
| `DualOptions` / `DualInspect` / `DualVerify` | 15 / 4 / 2 | K | `StrHide` 方法签名 |
| `SmartExtractOptions` / `ExtractOutcome` | 3 / 3 | K | `smart_extract` 返回/入参 |
| `StructureFacade` / `StegoFacade` | 1 / 1 | K | `StrHide::structure()/stego()` 返回类型 |
| `AnalysisFacade` | 0 | KF | `StrHide::analysis()` 返回类型 |
| `Domain` | 28 | K | GUI 13 次、CLI 9 次 |
| `CliDomain`（`facade.rs:1062`） | 0 | X | 是 `cli::Domain` 的重复别名，`cli` feature 内无消费者 |

【静态分析】`AnalysisFacade` 虽然零引用，但删掉它必须同时删 `StrHide::analysis()`，属破坏性且无收益；保留。

### 2.3 `structure`（192 条）

| 子模块 | 条目 | 判定 | 说明 |
|---|---|---|---|
| `structure::engine` | 27 | **全部 K/KF** | `write/read/remove/inspect/verify` 是 GUI 与 tests 主力；`InspectResult`/`VerifyResult`/`ReadSummary`/`CarrierMetadata`/`MetadataInspection`/`LevelStatus`/`Warning` 是返回类型或字段类型。**不可缩小。** |
| `structure::options` | 4 | K（`StrategyChoice` KF） | `WriteOptions` 185、`ReadOptions` 153、`RestoreOptions` 102 |
| `structure::params` | 1 | K | `StructureProfile` 109 |
| `structure::registry` | 8 | **模块 H**；`StrategyId` K | `StrategyId` 由 `structure/mod.rs:27` 与 `lib.rs:199` 导出，隐藏模块不影响它。`id_to_strategy`/`strategy_to_id`/`ADAPTERS`/`STRATEGY_REGISTRY` 仅 tests 用（`tests` 走全路径），保留 `pub`。 |
| `structure::envelope` | 18 | **模块 H** | tests 用 `structure::envelope::{EnvelopeHeader, HEADER_SIZE}`；无公开签名泄漏（`EnvelopeHeader` 只在 `engine.rs` 私有路径中出现）。 |
| `structure::rejection` | 8 | **模块 H** | tests 用 `run_all_rejection_checks`。 |
| `structure::adapters` | 126 | **模块 H**；`StrategyCapacity` KF | 18 个映射器子模块是内部实现；`StrategyCapacity` 是 `InspectResult.strategies` 的字段类型（`structure/engine.rs:635`，定义在 `structure/adapters/mod.rs:97`），必须先补公开路径。 |

**根 glob 问题【静态分析】**：`structure/mod.rs:24 pub use engine::*;` 把 `engine` 的 27 个条目全部提升到 `structure::` 根。它不增加 sidebar 条目数，但是公开面增长通道。建议后续改成显式列表（见 §4 批次 4），不影响本报告的条目统计。

**证据（UI/IPC 使用）**：
- `gui/src-tauri/src/commands/structure.rs:2` 导入 `structure::engine::{PayloadSource, ReadSummary, RemoveResult, WriteResult}`；
- 同文件 `:6` 调用 `structure::engine::sanitize_filename`。

### 2.4 `stego`（180 条）

| 子模块 | 条目 | 判定 | 说明 |
|---|---|---|---|
| `stego` 根 | 18 | 混合 | 统一入口 15 个函数：`embed/extract/inspect/verify/probe` 及方言变体 K；`extract_carrier_payload`、`inspect/verify_carrier_with_dialect` 文档承诺 K；`embed_carrier_with_dialect_info` H；`compute_default_threads`/`default_thread_count` C；`init_default_thread_pool` K。`StegoCapacityInfo`、`Freshness`、`CostModelRegistry` K。 |
| `stego::options` | 19 | **全部 K/KF** | 7 个选项 + 7 个结果/字段类型（`EmbedOutput`、`EmbedStats`、`StegoHeaderInfo`、`StegoVerifyResult`、`StegoWarning`、`VerifyLevel`、`HevcParams`）。零引用的是结果类型，删不掉。`resolve_credential` C。 |
| `stego::params` | 12 | K/C 混合 | 公开参数类型与常量 K；`DEFAULT_SLOT_BUDGET` 等 5 个内部预算 C。 |
| `stego::format` | 23 | K/H/C 混合 | 格式身份（`GridRule`、三个 profile、`DEFAULT_*`/`OFFICIAL_*`）K；`HeaderLocatorKeys`/`SessionKeys`/`derive_l3_session_keys`/`info_with_domain` C；`OFFICIAL_*_CIPHER`、`JPEG_SUPERBLOCK_*` H。 |
| `stego::engine` | 11 | **模块 C** | `StegoEngine`/`engine_for`/`supported_formats`/具体引擎结构体全部零外部引用。改 `pub(crate) mod engine`，并删 `stego/mod.rs:59`。 |
| `stego::io` | 6 | 3 K + 3 C | 文档承诺 `embed_carrier_file`/`extract_carrier_file`/`extract_carrier_file_payload`；`inspect/probe/verify_carrier_file` 零引用 → C。 |
| `stego::registry` | 4 | K | `list_stego_algorithms`、`algorithms_for_format`、`StegoAlgorithmInfo` 文档承诺。 |
| `stego::traits` | 3 | K | `PngCostModel`/`JpegCostModel`/`JpegGeometry` 文档承诺，外部可自定义代价模型。 |
| `stego::heif::thumb_bridge` | 8 | K | 文档 `heif::*` 专家面。 |
| `stego::hevc::engine` | 35 | K/C/KF 混合 | 3 个承诺入口 + 11 个示例/测试实际使用；21 个零引用内部变体 C；`HevcCarrierPatch`/`HevcSuperblockV4`/`ScanStats`/`EmbedPeakEstimate` KF（出现在保留函数签名或字段）。 |
| `stego::jpeg::engine` | 7 | 4 K + 3 C | `embed_jpeg`/`extract_jpeg`/`probe_jpeg_capacity`/`layout_for_payload` K；`inspect_jpeg`/`verify_jpeg`/`embed_jpeg_with_stats` C。 |
| `stego::jpeg::registry` | 2 | `list` K；`get_jpeg_model` C | `get_jpeg_model` 仅被 `CostModelRegistry` 内部调用，且 `stego/mod.rs:53`、`jpeg/mod.rs:18` 公开导出可删。 |
| `stego::png::engine` | 15 | K/C/KF 混合 | 6 个入口 + `RawImage` K；`PngChunk`/`IdatInfo` KF（`RawImage` 公开字段）；`ChannelMode`/`embed_png_with_stats`/`inspect_png`/`verify_png` C。 |
| `stego::png::registry` | 8 | C + 2 K | `list`（tests 39 次）、`spatial_model_from_wire_id`（2 次）K；其余 6 个 C。 |
| `stego::jpeg::cost::{jmipod,juniward,precover,uerd}` | 6 | 3 K + 3 H | `JmipodCostModel`/`JuniwardCostModel`/`UerdCostModel` K（examples 直接构造）；`precover::{bias,estimate,decompress_luma}` H（仅 tests 用）。 |
| `stego::png::cost::{hill,mipod,suniward}` | 3 | K | `HillCostModel`/`MipodCostModel`/`SuniwardCostModel` 公开代价模型。 |
| `stego::audio` | 0 | **模块 C** | 模块是 `pub mod`，但**没有任何公开条目**；文档承诺的 `audio::{embed_audio, ...}`、`audio::wav::*`、`audio::flac::*` 在代码中不存在（`flac` 为 `pub(crate)`）。 |

**关键缺陷：`Tlv` 不可公开命名【实测+静态分析】**
- `Tlv` 定义在 `rust/src/stego/header.rs:54`，该模块是 `#[doc(hidden)] pub mod header`（`stego/mod.rs:30`）。
- `stego/mod.rs` **没有** `pub use header::Tlv`（已用 `rg` 确认）。
- 但 `EmbedOptions.extensions: Vec<Tlv>`、`ProbeOptions.extensions`、`ExtractOptions.extensions`（`stego/options.rs:464` 等）以及 `probe_hevc_capacity_ext`/`probe_hevc_capacity_info`/`embed_hevc_with_info_v4` 的公开参数都使用 `Tlv`（`stego/hevc/engine.rs` 多处）。
- 结论：外部用户要构造扩展，只能写 `strhide::stego::header::Tlv` —— 一个文档承诺“随时可变”的内部路径。这不是“缩小”问题，而是**必须先补齐的可达性缺陷**。

### 2.5 `core`（120 条）

| 子模块 | 条目 | 判定 | 说明 |
|---|---|---|---|
| `core::errors` | 4 | K | `StrHideError` 163、GUI 19 次 |
| `core::payload` | 2 | K | `Payload`/`PayloadKind` 是 facade 与 GUI 输入 |
| `core::control` | 10 | K/C | `Control`/`CancelToken`/`Event`/`Progress`/`Stage`/`Recorder` K；`TaskControl`/`PROGRESS_STEP_BYTES` C |
| `core::batch` | 4 | K/KF | GUI 用 `BatchOutcome`/`BatchPlan`/`run_batch`；`ItemOutcome` KF |
| `core::commit` | 11 | 5 K + 6 C | GUI 用 `FileTarget`/`write_bytes_atomic`/`same_file`；tests 用 `commit_carrier_bytes`/`commit_carrier_patches`；`TargetLock`/`copy_file_durable`/`reject_*`/`rename_with_retry`/`temp_path_for` C |
| `core::config` | 3 | K/KF | `load` GUI 3 次；`FileConfig`/`StegoConfig` KF |
| `core::crypto` | 33 | K/H 混合 | 文档承诺 6 个函数 + `Credential`/`CipherSuiteId`；实际使用约 19 个；其余 13 个内部实现 → H |
| `core::fs` | 5 | 1 K + 4 C | `sanitize_filename` K（经 `structure::engine` 转出给 GUI）；其余 C |
| `core::pipeline` | 8 | 1 K + 7 C | GUI 只用 `check_overwrite` |
| `core::params` | 13 | K/H | `LocalParams`/`SafetyLevel`/`CompressionStrategy`/`MagicPair`/`RejectionPolicy`/`STANDARD_*_MAGIC`/`MIN_CHUNK_SIZE`/`STEALTH_DOMAIN`/`VideoBudget` K；3 个压缩默认值 H |
| `core::i18n` | 5 + 19 + 1 | K + H + C | `Lang`/`Msg`/`RenderCtx`/`set_lang`/`lang`/`locale::detect` K；`messages` 模块 H（`Msg` 已由 `i18n/mod.rs:9` 导出）；`format_msg` C |
| `core::media` / `sysmem` | 1 / 1 | KF / K | `MediaInfo` 字段类型；`sysmem_available_mb` GUI 使用 |

### 2.6 `formats`（54 条）

| 子模块 | 条目 | 判定 |
|---|---|---|
| `formats::sniff` | 17 | `FileFormat` + 3 个 `sniff_*` K；9 个魔数常量 H（含 `is_*_bytes` 等 4 个内部判定） |
| `formats::capability` | 5 | 全部 K/KF（GUI 用 `CAPABILITIES`/`Capability`；`MemoryProfile`/`StegoKind` 是字段类型） |
| `formats::annexb` | 26 | **模块 H**（NAL 常量被 tests/examples 通过全路径使用，保留 `pub`） |
| `formats::jpeg_segments` | 6 | **模块 H**（0 外部引用） |

### 2.7 `analysis`（12 条）与 `cli`（36 条）

- `analysis`：`scan_file`（tests/GUI）、`scan_bytes`、`ScanReport` K；`AnalysisReport`/`Finding`/`Severity`/`DetectorMetric` KF；`analysis::calibration` 5 条 **模块 H**（0 外部引用）。
- `cli`：`Cli`（tests）、`Domain`（tests）、`run_cli`（`src/main.rs` 调用）、`run_domain_cli`（bins）K；`args` 26 条 **模块 H**（clap derive 结构，只被 `Cli` 内部使用）；`helpers::{resolve_password}` K，`prompt_password`/`resolve_key_file` H；`logging::install` K，`level_for` C；`render::print_error` C。
- `cli_i18n::localize` K（tests 使用）。

### 2.8 零引用清单

**335 个条目在 crate 外零引用**，完整分组见附录 B。注意：其中约 40 个是 `KF`（公开字段/返回类型），不能因为零引用就删除。其余零引用条目在附录 A 中默认标为 `H` 或 `C`。

---

## 3. 文档承诺面 vs 代码实际公开面

| # | 文档位置 | 文档说法 | 代码事实 | 证据 |
|---|---|---|---|---|
| 1 | `docs/api/STEGO-API.md:34` | 稳定面包含 `registry::CostModelRegistry` | 实际路径是 `stego::CostModelRegistry`（`stego/mod.rs` 定义/导出），不存在 `stego::registry::CostModelRegistry` | 【实测】`stego` 根导出；`registry` 模块只有算法清单 |
| 2 | `docs/api/STEGO-API.md:34` | 稳定面包含 `Tlv`、`CipherSuiteId` | `Tlv` 仅在 `stego::header`（`#[doc(hidden)]`）；`CipherSuiteId` 仅在 `core::crypto`（根未导出） | 【实测】`stego/header.rs:54`；`core/crypto.rs`；`rustdoc` 警告 |
| 3 | `docs/api/STEGO-API.md:73-78` | 示例 `use strhide::stego::{... Tlv, CipherSuiteId ...}` | 该 `use` 无法编译 | 【静态分析】基于 #2 |
| 4 | `docs/api/STEGO-API.md:35` | 专家面包含 `audio::{embed_audio, extract_audio, probe_audio_capacity}`、`audio::wav::*`、`audio::flac::*` | `stego::audio` 是空公开模块，0 个公开条目；`flac` 为 `pub(crate)`，`wav` 私有 | 【实测】`cargo doc` sidebar `stego/audio` 为空；`stego/audio/mod.rs` |
| 5 | `docs/api/STEGO-API.md:36` | 内部面包含 `jpeg::{..., header_v3, ...}` | 实际是 `header_v4` + `v3_layout`；同文件 `:17` 已声明 `header_v3::Superblock` 删除 | 【实测】`stego/jpeg/mod.rs:5-9` |
| 6 | `docs/api/ARCHITECTURE.md` §9（约 :605，基线记为 :604） | `LocalParams`、`StructureProfile`、`StegoProfile`、`Dialect`、`Warning`、`CompressionStrategy`、`RejectionPolicy` 等标注 `#[non_exhaustive]` | 全库仅 14 处 `#[non_exhaustive]`，上述类型均未标注 | 【实测】`rg -n "non_exhaustive" rust/src` = 14 |
| 7 | `rust/src/lib.rs:129` | `CipherSuiteId` / `Credential` 是 crate 根可用的公开面 | 根未 `pub use`；`cargo doc` 产生 2 条 unresolved link 警告（`lib.rs:129`） | 【实测】rustdoc 9 条警告 |
| 8 | `docs/api/STEGO-API.md:87,96` | 示例使用 `SpatialAlgorithm::Hill`、`ExtractParams` | `SpatialAlgorithm` 仅 `content-png` feature 下由 `stego` 根导出；示例未导入 `ExtractParams` | 【静态分析】`stego/mod.rs:76`；示例 import 段 |
| 9 | `docs/api/STEGO-API.md:34` | 稳定面包含 `traits::{PngCostModel, JpegCostModel, JpegGeometry}` | 实际存在且公开（但 traits 是 trait 而非类型） | 【实测】`stego/traits` 3 条 |
| 10 | `docs/api/ARCHITECTURE.md` §3.1 | `params::{LocalParams, MagicPair, CompressionStrategy, RejectionPolicy, STEALTH_DOMAIN}` 根可见 | 实际通过 `core::params` 再导出，根可见 | 【实测】`lib.rs:156` |

**结论**：文档把“希望能用”的接口写得比代码实际公开面更大（`audio`、`registry::CostModelRegistry`、`Tlv` 路径），同时把“已经加了”的防护写得比代码实际更全（`non_exhaustive`）。收敛时应以代码为准修正文档，而不是为了匹配文档反向扩大公开面。

---

## 4. 收敛方案（按风险/收益排序）

> 每项格式：**改什么 → 影响调用点 → 是否同步 GUI/测试 → 破坏性**。
> 所有方案均通过 `scripts/import_lint.py` 的分层红线：`structure ↛ stego`、`stego ↛ structure`、`core ↛ {formats,structure,stego,cli,analysis}`、`formats ↛ {structure,stego,cli,analysis}`、`analysis ↛ cli`（`scripts/import_lint.py:6-11`）。本方案只调整可见性与 re-export，不新增跨层引用。

### 4.0 P0：可达性补齐（非缩小，但必须先做）

| 动作 | 具体改动 | 影响 | 破坏性 |
|---|---|---|---|
| P0-1 | `rust/src/stego/mod.rs` 增加 `pub use header::Tlv;`（放在 `:30` 的 `pub mod header;` 之后） | 新增路径，无调用点改动；文档示例可改为 `strhide::stego::Tlv` | 否（纯新增） |
| P0-2 | `rust/src/structure/mod.rs:27` 所在 re-export 增加 `StrategyCapacity`（或把它从 `adapters/mod.rs:97` 移到 `structure/engine.rs` 并在 `structure` 根导出） | `structure/engine.rs:635` 的 `InspectResult.strategies` 字段类型变得可命名；无调用点改动 | 否 |
| P0-3 | 修正 `rust/src/lib.rs:129` 的 `[CipherSuiteId]`/`[Credential]` 链接为 `crate::crypto::...`（不新增根导出） | 只改文档注释；消除 2 条 rustdoc 警告 | 否 |
| P0-4 | 修正 `docs/api/STEGO-API.md:34-36,73-78` 的路径与 audio 承诺；修正 `ARCHITECTURE.md` §9 的 `non_exhaustive` 表述 | 只改文档 | 否 |
| P0-5 | 消除其余 7 条 rustdoc warning（`crate::stego::header::FeatureWord::sigma`、`Domain::Stego/Diagnostics/All`、若干私有项链接） | 只改注释/链接 | 否 |

验证：`cargo doc --all-features --no-deps` 应 0 warning；`cargo test --all-features --doc`。

### 4.1 P1：模块级 `#[doc(hidden)]`（零编译风险，收益最大）

| 模块 | 改动位置 | 文档面减少 | 外部调用点 |
|---|---|---|---|
| `structure::adapters` + 18 子模块 | `structure/mod.rs:16` 加 `#[doc(hidden)]` | 125（126 − `StrategyCapacity`，P0-2 已给它公开路径） | tests 使用 `structure::adapters::{HostAdapter, PeAdapter, pe_codebits}`，全路径仍可编译 |
| `structure::envelope` | `:18` | 18 | `tests/test_pe/slack.rs` 用 `EnvelopeHeader`/`HEADER_SIZE` |
| `structure::rejection` | `:22` | 8 | tests 用 `run_all_rejection_checks` |
| `structure::registry` | `:21` | 7 | tests 用 `ADAPTERS`/`STRATEGY_REGISTRY`/`id_to_strategy`/`strategy_to_id`；仅保留 `StrategyId` 根别名 |
| `analysis::calibration` | `analysis.rs:43` | 5 | 0 |
| `cli::args` | `cli/mod.rs:17` | 13（26 − 13 个 `cli` 根别名） | tests 只用 `cli::Cli` 等根路径 |
| `core::i18n::messages` | `core/i18n/mod.rs:7` | 18（19 − `Msg` 根别名） | `Msg` 已由 `i18n/mod.rs:9` 导出 |
| `formats::annexb` | `formats/mod.rs:14` | 26 | tests/examples 用 NAL 常量全路径 |
| `formats::jpeg_segments` | `:16` | 6 | 0 |
| `stego::jpeg::cost::precover` | `stego/jpeg/cost/mod.rs:3` | 3 | 0 |
| **合计** | | **229** | 无破坏 |

> 【实测】`#[doc(hidden)]` 模块里被 `pub use` 的条目不会从文档消失，而是在 re-export 处**内联**并继续计数。用小样验证：`#[doc(hidden)] pub mod inner { pub struct Foo; }` + `pub use inner::Foo;`，rustdoc 生成的根 `sidebar-items.js` 为 `{"struct":["Foo"]}`。因此 `cli::args` 只减 13（13 个别名保留在 `cli` 根）、`core::i18n::messages` 只减 18（`Msg` 保留）。若在 B1 一并删除这些根别名，则这两行分别变为 26 与 19，合计 243；本方案不删，故取 229。

附加动作（同一批，避免“隐藏了模块但根上还在漏”）：
- `structure/mod.rs:27` 收敛为 `pub use registry::StrategyId;`（删除 `ADAPTERS`/`STRATEGY_REGISTRY`/`find_adapter`/`find_adapter_or_reject` 的根别名）。
  影响：`analysis.rs:1190` 的 `crate::structure::find_adapter(...)` 改为 `crate::structure::registry::find_adapter(...)`；tests 已走 `structure::registry::*` 全路径，无需改。
- `stego/jpeg/mod.rs:18` 的 `pub use registry::get_jpeg_model;` 在 P2 删除（见下）。

破坏性：**否**（`#[doc(hidden)]` 不改变编译可见性）。但 docs.rs 上这些路径不再出现，需在 CHANGES 公告中说明“内部面”。

### 4.2 P2：`pub(crate)` 下沉（82 条，零外部引用但保留编译）

| 组 | 条目 | 改动 |
|---|---|---|
| stego 引擎分派 | `StegoEngine`、`engine_for`、`supported_formats`、具体引擎结构体（11） | `stego/mod.rs:25` → `pub(crate) mod engine;`；删除 `:59` 的 `pub use engine::{...}` |
| stego HEVC 内部变体 | 21 条（`inspect_hevc*`、`verify_hevc*`、`embed_hevc_patches*`、`superblock_positions`、`estimate_embed_peak_bytes`、`embed_window_bytes`、`hevc_extension_slots`、内部常量） | `stego/hevc/engine.rs` 改 `pub(crate)`；保留 `HevcCarrierPatch`/`HevcSuperblockV4`/`ScanStats`/`EmbedPeakEstimate` 为 `pub`（KF） |
| stego IO 文件级 | `inspect_carrier_file`、`probe_carrier_file`、`verify_carrier_file` | `stego/io.rs` 改 `pub(crate)`；保留 3 个承诺入口 |
| PNG/JPEG 引擎 | `embed_png_with_stats`、`inspect_png`、`verify_png`、`ChannelMode`、`inspect_jpeg`、`verify_jpeg`、`embed_jpeg_with_stats` | 改 `pub(crate)`；`png/mod.rs:6-8`、`jpeg/mod.rs:15-16` 的 re-export 同步删减 |
| 注册表 | `get_jpeg_model`、`SPATIAL_ALGORITHM_*`（3）、`get_spatial_model`、`spatial_wire_id`、`spatial_name_from_wire_id` | 改 `pub(crate)`；删除 `stego/mod.rs:53` 与 `stego/png/mod.rs:10-13` 中对应别名；保留 `spatial_model_from_wire_id` 与 `list` |
| stego 参数/格式 | `DEFAULT_SLOT_BUDGET`、`MAX_AUTO_BACKTRACK_BYTES`、`MAX_GROUPED_BACKTRACK_BYTES`、`grouped_body_budget`、`max_grouped_backtrack_slots`、`HeaderLocatorKeys`、`SessionKeys`、`derive_l3_session_keys`、`info_with_domain`、`resolve_credential` | 改 `pub(crate)` |
| 线程数辅助 | `compute_default_threads`、`default_thread_count` | `stego/mod.rs:101,110` 改 `pub(crate)`；删 `lib.rs:217-220` 两个名字 |
| 空模块 | `stego::audio` | `stego/mod.rs:15` → `pub(crate) mod audio;`（模块内 0 公开条目） |
| core 工具 | `core::commit` 6、`core::fs` 4、`core::pipeline` 7、`core::control` 2、`core::i18n::format_msg` | 改 `pub(crate)` |
| formats/cli | `formats::sniff` 9 常量、`cli::{prompt_password, resolve_key_file, level_for, print_error}` | 常量改 `#[doc(hidden)]`；函数改 `pub(crate)` 并从 `cli` 根别名移除 |

**影响与验证**：
- 每个候选都已由 v2 TSV 确认 0 次外部引用；但 `pub(crate)` 会阻止**尚未统计的 doctest**，因此每批必须跑 `cargo test --all-features --doc`。
- 示例依赖的隐藏模块条目（`CabacRecorder`、`parse_mp4_targets`、`parse_heif_targets`、`deterministic_payload`、`geometry_for_carrier`、`bench_scan_slices`、`Move`/`StcTrellis`）**不在 P2 范围**，保持 `pub` + `#[doc(hidden)]`。
- 破坏性：**是**（对外部用户），但实测外部使用为 0；需在 CHANGES 标注。

### 4.3 P3：删除/移除导出

| 项 | 位置 | 说明 |
|---|---|---|
| `facade::CliDomain` | `facade.rs:1062` | 纯重复别名；`cli::Domain` 可直接用 |
| `structure::{ADAPTERS, STRATEGY_REGISTRY, find_adapter, find_adapter_or_reject}` 根别名 | `structure/mod.rs:27` | 0 外部引用；tests 走 `registry` 全路径 |
| `stego` 根的 `get_jpeg_model` | `stego/mod.rs:53` | 0 外部引用；`CostModelRegistry` 内部仍可用 |
| `stego` 根的 png registry 6 个别名 | `stego/mod.rs:55` 区块 | 仅保留 `spatial_model_from_wire_id`（2 次外部使用） |
| `stego` 根的 engine 3 个别名 | `stego/mod.rs:59` | 随 P2 模块下沉 |
| `macro_rules! i18n_messages` / `t!` | `lib.rs` 宏定义处 | 加 `#[doc(hidden)]`，不删除（内部宏展开依赖） |

破坏性：**是**（删除公开路径），但全部 0 外部引用。

### 4.4 P4：`#[non_exhaustive]`（必须最后单独做）

**顺序结论：先收敛，后 `non_exhaustive`。** 理由：

1. 先收敛可以把将被隐藏/删除的类型排除，避免给它们白加属性。
2. 如果同批做，无法区分“可见性收紧导致的编译失败”和“`non_exhaustive` 导致的字面量编译失败”，验证成本翻倍。
3. `#[non_exhaustive]` 本身就是破坏性变更：crate 外的结构体字面量（包括 `..Default::default()` 形式）全部失效。当前 tests/examples 大量使用字面量构造（`WriteOptions` 185 次、`ReadOptions` 153 次、`EmbedOptions` 149 次）。

**建议分层**：

| 类型组 | 是否可先标 | 前提 |
|---|---|---|
| 纯输出类型（`WriteResult`、`ReadResult`、`ReadSummary`、`RemoveResult`、`InspectResult`、`VerifyResult`、`EmbedOutput`、`EmbedStats`、`StegoHeaderInfo`、`StegoVerifyResult`、`StegoEmbedResult`、`DualInspect`、`DualVerify`、`ExtractOutcome`、`ScanReport`、`Finding`、`MetadataInspection`、`StrategyCapacity`、`LevelStatus`） | **可以第一批** | 外部只读字段、不构造字面量 |
| 入参选项（`WriteOptions`、`ReadOptions`、`RestoreOptions`、`EmbedOptions`、`ExtractOptions`、`ProbeOptions`、`InspectOptions`、`VerifyOptions`、`DualOptions`、`SmartExtractOptions`、`PngParams`、`JpegParams`、`HevcParams`、`ExtractParams`、`LocalParams`、`StegoTuning`） | **不能直接标** | 必须先补齐 builder/setter，并把 tests/examples 从字面量改为构造器；这是独立的一批工作 |
| 枚举（`FileFormat`、`SafetyLevel`、`GridRule`、`StegoProfile`、`Domain`、`Freshness`、`JpegAlgorithm`、`HevcMode` 等） | **建议 1.0 前再评估** | `non_exhaustive` 会强制下游补 `_ =>`，破坏 `match` |

基线文档已建议“发布前加防护”；从本报告的收敛结果看，更稳妥的顺序是：
`P0 → P1 → P2 → P3 → 冻结公开面 → 对纯输出类型加 non_exhaustive → 为入参选项补 builder → 最后再给入参/枚举加 non_exhaustive`。

---

## 5. 不建议缩小的项（硬约束）

| 项 | 原因 | 证据 |
|---|---|---|
| `stego::header::Tlv`（以及新增的 `stego::Tlv`） | 3 个公开 options 的 `extensions` 字段 + 3 个 HEVC 公开函数参数直接使用；改 `pub(crate)` 会让公开签名出现私有类型 | `stego/options.rs:464`；`stego/hevc/engine.rs` 多处 |
| `structure::adapters::StrategyCapacity` | `InspectResult.strategies` 字段类型；删/私会导致公开结构体字段不可命名 | `structure/engine.rs:635`；`structure/adapters/mod.rs:97` |
| `stego::hevc::slot::CabacRecorder` | examples `hevc_stress`/`hevc_window_sweep` 直接使用 | 4 次外部引用 |
| `stego::hevc::{mp4_boxes,heif_boxes}` 的 `parse_*_targets` | examples/tests 直接使用 | 8 / 11 次 |
| `stego::prng::deterministic_payload` | tests/examples 直接使用 | 27 次外部引用 |
| `stego::jpeg::geometry::geometry_for_carrier` | examples 直接使用 | 12 次外部引用 |
| `stego::coding::{Move, StcTrellis}` | tests `local_bench.rs` 直接使用 | `Move` 6 次、`StcTrellis` 3 次 |
| `stego::png::engine::{RawImage, PngChunk, IdatInfo}` | `RawImage` 是 Expert 面且公开字段 `chunks: Vec<PngChunk>`、`idat_info: Option<IdatInfo>` | `png/engine.rs` 结构体字段 |
| `structure::engine` 全 27 条 | GUI/tests 主力；结果是 IPC DTO 来源 | `gui/src-tauri/src/commands/structure.rs:2,6` |
| `stego::options` 全部结果类型 | 公开函数返回类型 | `stego/mod.rs` 统一入口签名 |
| `core::batch::ItemOutcome` | `BatchOutcome` 字段类型 | `core/batch.rs` |
| `core::config::{FileConfig, StegoConfig}` | `load` 返回类型 | `core/config.rs` |
| `formats::capability::{MemoryProfile, StegoKind}` | `Capability` 字段类型 | `formats/capability.rs` |
| `core::media::MediaInfo` | `StegoCapacityInfo` 字段类型；GUI 经 serde 序列化 | `stego/mod.rs` |
| `Warning` / `StrategyId` / `StrategyChoice` / `LevelStatus` / `MetadataInspection` | 公开字段类型/公开方法参数 | 附录 A `KF` |
| GUI IPC 直接使用的类型 | `EmbedOptions`、`ExtractOptions`、`ProbeOptions`、`StegoTuning`、`SpatialAlgorithm`、`HevcMode`、`JpegAlgorithm`、`JpegParams`、`PngParams`、`StegoAlgorithmInfo`、`StegoCapacityInfo`、`Safety*`、`ExtractParams`、`Control`、`Progress`、`Event`、`Payload`、`PayloadKind`、`FileTarget`、`write_bytes_atomic`、`check_overwrite`、`load`、`BatchOutcome/BatchPlan/run_batch` | GUI 后端 import 实测 |

---

## 6. 落地顺序（每批独立可编译、可跑全量测试）

| 批次 | 内容 | 预期文档面变化 | 验证命令 | 破坏性 |
|---|---|---|---|---|
| **B0** | P0 可达性/文档修正（5 项） | 607（不变） | `cargo doc --all-features --no-deps`（0 warning）；`cargo test --all-features --doc` | 否 |
| **B1** | P1 模块级 `#[doc(hidden)]`（10 个模块 + `structure` 根别名收敛） | 607 → 378（-229） | `cargo build --release --all-features`；`cargo test --all-features --all-targets`；`cargo test --all-features --doc`；`python ../scripts/import_lint.py` | 否 |
| **B2** | P2 `pub(crate)` 下沉（stego 引擎/IO/注册表/参数 + core 工具） | 378 → 296（-82，文档面） | 同上 + `cargo build --release --all-features --examples`（重点看 hevc/audio stress 示例） | 是（0 外部引用） |
| **B3** | P3 删除重复别名 + 对剩余 H 条目逐个 `#[doc(hidden)]`（40 个模块外 H + 14 个经 re-export 内联的 H） | 296 → 242（-54） | 同上 + `cargo test --all-features --all-targets` | 是（0 外部引用） |
| **B4** | `structure/mod.rs:24` glob → 显式列表 | 不变 | 同上 | 否（只要列表覆盖 tests/examples 路径） |
| **B5** | 纯输出类型 `#[non_exhaustive]` | 不变 | 同上 + `cargo test --all-features --all-targets`（tests 若构造输出类型会失败，需改测试） | 是 |
| **B6** | 入参选项 builder + `non_exhaustive`（独立发布窗口） | 不变 | 同上 + GUI `pnpm build`/`pnpm test:unit`/`pnpm test:cross` | 是 |

> 数字闭合说明（【静态分析】+ 附录 A 判定）：245 条位于 10 个待隐藏模块，其中 16 条经 `pub use` 保留在可见父模块（`StrategyId`、`StrategyCapacity` + `cli` 根 13 个别名 + `Msg`），故 B1 净减 229。剩余 362 条的构成是 `K` 205 + `KF` 35 + `H` 40 + `C` 82；B2 处理 82 条 `C`，B3 再隐藏 40 条模块外 `H` 与 14 条内联 `H`（`cli` 13 + `Msg` 1），最终文档面 = `K` 206 + `KF` 36 = 242，与 §0 的收敛目标一致。

**每批共同验证清单（AGENTS.md 要求）**：

```powershell
cd rust
cargo build --release --all-features
cargo test --all-features --all-targets
cargo test local_ --all-features -- --ignored
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
python ../scripts/import_lint.py
python ../scripts/baseline_hash.py --check
```

GUI 同步时机：
- B1/B2/B3 不改 GUI 使用的任何路径（GUI 只用 `structure::engine`、`stego::options`、`stego::params`、`core::*`、`formats::capability`），**无需改 GUI**；但仍应跑 `cd gui && pnpm build && pnpm test:unit && pnpm test:cross` 确认 IPC DTO 未受影响。
- B6 若给 GUI 构造的 options 加 `non_exhaustive`，必须同步改 `gui/src-tauri` 的构造方式并跑 `pnpm test:e2e`/`test:e2e:real`。

---

## 附录

- 附录 A：607 条文档化条目的逐项判定（含外部引用计数）。
- 附录 B：335 条零外部引用条目分组清单。

> 附录由 `C:\Home\Projects\strhide\temp\gen_appendix2.py` 基于 `public_api_refs_v2.tsv` 生成；脚本与中间数据位于 `temp/`，不属于交付物。

## 附录 A：文档化公开条目全量判定（按定义模块）

> 外部引用 = tests + examples + gui + src/bin + src/main.rs + src/lite.rs 的 rg 全词匹配次数；含注释与同名标识符，常见词会虚高，零计数可靠。
> 判定代号：`K` 必须公开；`KF` 必须公开（作为公开字段/返回类型闭包）；`H` 保留 `pub` 但 `#[doc(hidden)]`（或模块整体隐藏）；`C` 改 `pub(crate)`；`X` 删除/移除导出。

### `analysis`（7）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `scan_file` | 必须公开 | 26 | 19 | 5 | 2 | 0 | 0 |
| `scan_bytes` | 必须公开 | 4 | 4 | 0 | 0 | 0 | 0 |
| `ScanReport` | 必须公开 | 3 | 0 | 0 | 3 | 0 | 0 |
| `Finding` | 必须公开(类型闭包) | 1 | 1 | 0 | 0 | 0 | 0 |
| `AnalysisReport` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `DetectorMetric` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `Severity` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `analysis/calibration`（5）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `estimate` | 隐藏但保留 | 7 | 6 | 1 | 0 | 0 | 0 |
| `CalibrationEstimate` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `dct_chi2_suspicion` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `dct_chi2_suspicion_with_coefficients` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `estimate_with_coefficients` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `cli`（3）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `Domain` | 必须公开 | 28 | 6 | 0 | 13 | 9 | 0 |
| `run_domain_cli` | 必须公开 | 6 | 0 | 0 | 0 | 6 | 0 |
| `run_cli` | 必须公开 | 2 | 0 | 0 | 0 | 0 | 2 |

### `cli/args`（26）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `Cli` | 隐藏但保留 | 3 | 3 | 0 | 0 | 0 | 0 |
| `STRHIDE_GIT_HASH` | 隐藏但保留 | 1 | 0 | 1 | 0 | 0 | 0 |
| `BANNER` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `CapacityArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `Commands` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ContainerCommands` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `DiagCli` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `DiagCommands` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `EmbedArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ExtractArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `GlobalArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `InspectArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ListArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PasswordArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PayloadSourceArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ReadArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `RestoreArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `STRHIDE_BUILD_TIME` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `STRHIDE_VERSION_INFO` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ScanArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `StegoCli` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `StegoCommands` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `StegoTuningArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `StructCli` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `VerifyArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `WriteArgs` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `cli/helpers`（3）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `prompt_password` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `resolve_key_file` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `resolve_password` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |

### `cli/logging`（2）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `level_for` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `install` | 必须公开 | 19 | 4 | 8 | 7 | 0 | 0 |

### `cli/render`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `print_error` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |

### `cli_i18n`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `localize` | 必须公开 | 3 | 3 | 0 | 0 | 0 | 0 |

### `core/batch`（4）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `BatchOutcome` | 必须公开 | 3 | 0 | 0 | 3 | 0 | 0 |
| `BatchPlan` | 必须公开 | 2 | 0 | 0 | 2 | 0 | 0 |
| `run_batch` | 必须公开 | 2 | 0 | 0 | 2 | 0 | 0 |
| `ItemOutcome` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `core/commit`（11）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `TargetLock` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `copy_file_durable` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `reject_carrier_output` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `reject_read_only_target` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `rename_with_retry` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `temp_path_for` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `FileTarget` | 必须公开 | 12 | 10 | 0 | 2 | 0 | 0 |
| `commit_carrier_patches` | 必须公开 | 3 | 3 | 0 | 0 | 0 | 0 |
| `write_bytes_atomic` | 必须公开 | 3 | 0 | 0 | 3 | 0 | 0 |
| `commit_carrier_bytes` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `same_file` | 必须公开 | 2 | 0 | 0 | 2 | 0 | 0 |

### `core/config`（3）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `load` | 必须公开 | 45 | 42 | 0 | 3 | 0 | 0 |
| `FileConfig` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `StegoConfig` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `core/control`（10）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `TaskControl` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `PROGRESS_STEP_BYTES` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `Control` | 必须公开 | 81 | 45 | 30 | 6 | 0 | 0 |
| `Stage` | 必须公开 | 22 | 13 | 0 | 9 | 0 | 0 |
| `CancelToken` | 必须公开 | 18 | 12 | 0 | 6 | 0 | 0 |
| `Event` | 必须公开 | 16 | 9 | 0 | 7 | 0 | 0 |
| `Progress` | 必须公开 | 12 | 8 | 2 | 2 | 0 | 0 |
| `ProgressWriter` | 必须公开 | 5 | 5 | 0 | 0 | 0 | 0 |
| `NoProgress` | 必须公开 | 3 | 3 | 0 | 0 | 0 | 0 |
| `map_io_cancel` | 必须公开 | 3 | 3 | 0 | 0 | 0 | 0 |

### `core/crypto`（33）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AAD_SIZE` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `CHUNK_OVERHEAD` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `CONTENT_L1_PBKDF2_ITERATIONS` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PBKDF2_ITERATIONS` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `chunk_count` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `compute_stream_sha256` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `derive_all` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `derive_header_mask` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `derive_trailer_crc_mask` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `framed_len` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `make_chunk_nonce` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `make_meta_nonce` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `normalize_nfc` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `compute_file_sha256` | 必须公开 | 38 | 38 | 0 | 0 | 0 | 0 |
| `Credential` | 必须公开 | 33 | 12 | 21 | 0 | 0 | 0 |
| `compute_sha256` | 必须公开 | 16 | 16 | 0 | 0 | 0 | 0 |
| `derive_keys` | 必须公开 | 8 | 8 | 0 | 0 | 0 | 0 |
| `encrypt_metadata` | 必须公开 | 7 | 7 | 0 | 0 | 0 | 0 |
| `BUILTIN_DEFAULT_KEY` | 必须公开 | 5 | 5 | 0 | 0 | 0 | 0 |
| `decrypt_metadata` | 必须公开 | 4 | 4 | 0 | 0 | 0 | 0 |
| `verify_payload_stream` | 必须公开 | 4 | 4 | 0 | 0 | 0 | 0 |
| `encrypt_stream_to_chunks` | 必须公开 | 3 | 3 | 0 | 0 | 0 | 0 |
| `CipherSuiteId` | 必须公开 | 2 | 1 | 1 | 0 | 0 | 0 |
| `MAX_VERIFY_PAYLOAD_SIZE` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `decompress_stream` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `derive_channel_header_mask` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `derive_stealth_magics` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `AEAD_TAG_LEN` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `CHUNK_SIZE` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `MAX_CHUNK_SIZE` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `compress_stream` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `decrypt_stream_from_chunks` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `PasswordSecrets` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `core/errors`（4）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `StrHideError` | 必须公开 | 163 | 132 | 12 | 19 | 0 | 0 |
| `ErrorDetail` | 必须公开 | 28 | 0 | 0 | 28 | 0 | 0 |
| `ErrorKind` | 必须公开 | 9 | 8 | 0 | 1 | 0 | 0 |
| `TrellisCause` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `core/fs`（5）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `batch_payload_name` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `escape_control_chars` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `escape_terminal_text` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `unique_batch_path` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `sanitize_filename` | 必须公开 | 15 | 13 | 0 | 2 | 0 | 0 |

### `core/i18n`（5）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `format_msg` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `lang` | 必须公开 | 26 | 17 | 0 | 9 | 0 | 0 |
| `Lang` | 必须公开 | 10 | 7 | 0 | 3 | 0 | 0 |
| `RenderCtx` | 必须公开 | 9 | 0 | 0 | 9 | 0 | 0 |
| `set_lang` | 必须公开 | 1 | 0 | 0 | 1 | 0 | 0 |

### `core/i18n/locale`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `detect` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |

### `core/i18n/messages`（19）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `CAPACITY_AFTER_HELP_EN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `CAPACITY_AFTER_HELP_ZH` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `EMBED_AFTER_HELP_EN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `EMBED_AFTER_HELP_ZH` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `EXTRACT_AFTER_HELP_EN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `EXTRACT_AFTER_HELP_ZH` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `INSPECT_AFTER_HELP_EN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `INSPECT_AFTER_HELP_ZH` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `Msg` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `READ_AFTER_HELP_EN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `READ_AFTER_HELP_ZH` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `RESTORE_AFTER_HELP_EN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `RESTORE_AFTER_HELP_ZH` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `SCAN_AFTER_HELP_EN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `SCAN_AFTER_HELP_ZH` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `VERIFY_AFTER_HELP_EN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `VERIFY_AFTER_HELP_ZH` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `WRITE_AFTER_HELP_EN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `WRITE_AFTER_HELP_ZH` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `core/media`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `MediaInfo` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `core/params`（13）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AUTO_COMPRESSION_SAVING_PERCENT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `DEFAULT_COMPRESSION_LEVEL` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `MAX_COMPRESSION_LEVEL` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `LocalParams` | 必须公开 | 58 | 54 | 4 | 0 | 0 | 0 |
| `SafetyLevel` | 必须公开 | 30 | 14 | 10 | 6 | 0 | 0 |
| `CompressionStrategy` | 必须公开 | 9 | 9 | 0 | 0 | 0 | 0 |
| `MagicPair` | 必须公开 | 9 | 7 | 2 | 0 | 0 | 0 |
| `STANDARD_TRAILER_MAGIC` | 必须公开 | 8 | 8 | 0 | 0 | 0 | 0 |
| `STANDARD_HEADER_MAGIC` | 必须公开 | 3 | 3 | 0 | 0 | 0 | 0 |
| `MIN_CHUNK_SIZE` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `RejectionPolicy` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `STEALTH_DOMAIN` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |
| `VideoBudget` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |

### `core/payload`（2）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `Payload` | 必须公开 | 177 | 143 | 29 | 5 | 0 | 0 |
| `PayloadKind` | 必须公开 | 4 | 0 | 0 | 4 | 0 | 0 |

### `core/pipeline`（8）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `BatchPreflight` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `CarrierValidator` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `batch_output_dir` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `derive_default_output_path` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `for_each_carrier` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `preflight_batch` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `resolve_carrier_target` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `check_overwrite` | 必须公开 | 8 | 0 | 0 | 8 | 0 | 0 |

### `core/sysmem`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `available_physical_memory` | 必须公开 | 1 | 0 | 0 | 1 | 0 | 0 |

### `crate`（2）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `i18n_messages` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `t` | 必须公开 | 162 | 119 | 34 | 9 | 0 | 0 |

### `facade`（11）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `StrHide` | 必须公开 | 54 | 46 | 2 | 6 | 0 | 0 |
| `Domain` | 必须公开 | 28 | 6 | 0 | 13 | 9 | 0 |
| `DualOptions` | 必须公开 | 15 | 9 | 0 | 6 | 0 | 0 |
| `Dialect` | 必须公开 | 13 | 9 | 4 | 0 | 0 | 0 |
| `DualInspect` | 必须公开 | 4 | 0 | 0 | 4 | 0 | 0 |
| `ExtractOutcome` | 必须公开 | 3 | 0 | 0 | 3 | 0 | 0 |
| `SmartExtractOptions` | 必须公开 | 3 | 1 | 0 | 2 | 0 | 0 |
| `DualVerify` | 必须公开 | 2 | 0 | 0 | 2 | 0 | 0 |
| `StegoFacade` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `StructureFacade` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `AnalysisFacade` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `formats/annexb`（26）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `is_hevc_annexb` | 隐藏但保留 | 6 | 6 | 0 | 0 | 0 | 0 |
| `NAL_RADL_N` | 隐藏但保留 | 4 | 0 | 4 | 0 | 0 | 0 |
| `NAL_RASL_N` | 隐藏但保留 | 4 | 0 | 4 | 0 | 0 | 0 |
| `NAL_STSA_N` | 隐藏但保留 | 4 | 0 | 4 | 0 | 0 | 0 |
| `NAL_TRAIL_N` | 隐藏但保留 | 4 | 0 | 4 | 0 | 0 | 0 |
| `NAL_TSA_N` | 隐藏但保留 | 4 | 0 | 4 | 0 | 0 | 0 |
| `NAL_AUD_NUT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_BLA_N_LP` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_BLA_W_LP` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_BLA_W_RADL` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_CRA_NUT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_EOB_NUT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_EOS_NUT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_FD_NUT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_IDR_N_LP` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_IDR_W_RADL` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_PPS_NUT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_PREFIX_SEI_NUT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_RADL_R` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_RASL_R` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_SPS_NUT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_STSA_R` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_SUFFIX_SEI_NUT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_TRAIL_R` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_TSA_R` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `NAL_VPS_NUT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `formats/capability`（5）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `CAPABILITIES` | 必须公开 | 3 | 1 | 0 | 2 | 0 | 0 |
| `Capability` | 必须公开 | 2 | 0 | 0 | 2 | 0 | 0 |
| `capability_of` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `MemoryProfile` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `StegoKind` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `formats/jpeg_segments`（6）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `QuantTable` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `STANDARD_LUMA_QT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `parse_component_dqt` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `parse_component_tq` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `parse_dqt_tables` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `parse_luma_dqt` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `formats/sniff`（17）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `EBML_HEADER_ID` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `HEIF_BRANDS` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `JPEG_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PDF_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PNG_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `SNIFF_PREFIX_BYTES` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ZIP_EOCD_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ZIP_LOCAL_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ZIP_SPAN_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `is_heif_bytes` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `is_jpeg_bytes` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `is_mp4_bytes` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `is_png_bytes` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `FileFormat` | 必须公开 | 33 | 23 | 10 | 0 | 0 | 0 |
| `sniff_bytes` | 必须公开 | 12 | 5 | 7 | 0 | 0 | 0 |
| `sniff_stream` | 必须公开 | 4 | 4 | 0 | 0 | 0 | 0 |
| `sniff_file` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |

### `stego`（18）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `compute_default_threads` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `default_thread_count` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `embed_carrier_with_dialect_info` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `embed_carrier` | 必须公开 | 119 | 103 | 16 | 0 | 0 | 0 |
| `extract_carrier` | 必须公开 | 96 | 82 | 14 | 0 | 0 | 0 |
| `verify_carrier` | 必须公开 | 75 | 75 | 0 | 0 | 0 | 0 |
| `Freshness` | 必须公开 | 59 | 23 | 36 | 0 | 0 | 0 |
| `inspect_carrier` | 必须公开 | 49 | 49 | 0 | 0 | 0 | 0 |
| `probe_carrier_capacity` | 必须公开 | 26 | 18 | 8 | 0 | 0 | 0 |
| `extract_carrier_with_dialect` | 必须公开 | 20 | 20 | 0 | 0 | 0 | 0 |
| `embed_carrier_with_dialect` | 必须公开 | 11 | 11 | 0 | 0 | 0 | 0 |
| `probe_carrier_capacity_with_dialect` | 必须公开 | 5 | 5 | 0 | 0 | 0 | 0 |
| `StegoCapacityInfo` | 必须公开 | 4 | 2 | 0 | 2 | 0 | 0 |
| `CostModelRegistry` | 必须公开 | 3 | 3 | 0 | 0 | 0 | 0 |
| `extract_carrier_payload` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |
| `init_default_thread_pool` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |
| `inspect_carrier_with_dialect` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |
| `verify_carrier_with_dialect` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |

### `stego/engine`（11）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `AnnexBEngine` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `FlacEngine` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HeifEngine` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `JpegEngine` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `MkvEngine` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `Mp4Engine` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `PngEngine` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `StegoEngine` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `WavEngine` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `engine_for` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `supported_formats` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |

### `stego/format`（23）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `HeaderLocatorKeys` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `SessionKeys` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `derive_l3_session_keys` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `info_with_domain` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `OFFICIAL_PNG_CIPHER` | 隐藏但保留 | 8 | 2 | 6 | 0 | 0 | 0 |
| `JPEG_SUPERBLOCK_BYTES` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `JPEG_SUPERBLOCK_SLOTS` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `OFFICIAL_AUDIO_CIPHER` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `OFFICIAL_HEVC_CIPHER` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `OFFICIAL_JPEG_CIPHER` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `DEFAULT_HEVC_FORMAT` | 必须公开 | 39 | 31 | 8 | 0 | 0 | 0 |
| `DEFAULT_JPEG_FORMAT` | 必须公开 | 16 | 1 | 15 | 0 | 0 | 0 |
| `OFFICIAL_PNG_FORMAT` | 必须公开 | 12 | 2 | 10 | 0 | 0 | 0 |
| `JpegFormatProfile` | 必须公开 | 6 | 2 | 4 | 0 | 0 | 0 |
| `WireCipherProfile` | 必须公开 | 4 | 2 | 2 | 0 | 0 | 0 |
| `GridRule` | 必须公开 | 2 | 1 | 1 | 0 | 0 | 0 |
| `derive_l2_locator_keys` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `derive_locator_master` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `OFFICIAL_FLAC_FORMAT` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |
| `OFFICIAL_WAV_FORMAT` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |
| `AudioFormatProfile` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HevcFormatProfile` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `PngFormatProfile` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `stego/heif/thumb_bridge`（8）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `extract_heif_bridge` | 必须公开 | 4 | 4 | 0 | 0 | 0 | 0 |
| `embed_heif_bridge` | 必须公开 | 3 | 3 | 0 | 0 | 0 | 0 |
| `probe_heif_bridge_capacity` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `find_bridge_target` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `inspect_heif_bridge` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |
| `verify_heif_bridge` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |
| `BridgeTarget` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `BridgeTargetKind` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `stego/hevc/engine`（35）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `EMBED_WINDOW_GOPS` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HEVC_EXT_STC_H` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HEVC_EXT_STC_U` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HEVC_FORMAT_ID` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HEVC_HEADER_SLOTS_MAX` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HEVC_MAX_EXT_BYTES` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HEVC_SUPERBLOCK_BYTES` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HEVC_SUPERBLOCK_MIN_SLOTS` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `embed_hevc_patches` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `embed_hevc_patches_v4` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `embed_hevc_payload` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `embed_window_bytes` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `estimate_embed_peak_bytes` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `hevc_extension_slots` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `inspect_hevc` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `inspect_hevc_mp4_file` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `inspect_hevc_mp4_file_v4` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `inspect_hevc_v4` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `superblock_positions` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `verify_hevc` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `verify_hevc_v4` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `extract_hevc` | 必须公开 | 18 | 13 | 5 | 0 | 0 | 0 |
| `embed_hevc` | 必须公开 | 16 | 13 | 3 | 0 | 0 | 0 |
| `probe_hevc_capacity` | 必须公开 | 13 | 11 | 2 | 0 | 0 | 0 |
| `embed_hevc_with_info` | 必须公开 | 4 | 4 | 0 | 0 | 0 | 0 |
| `embed_hevc_with_info_v4` | 必须公开 | 4 | 4 | 0 | 0 | 0 | 0 |
| `extract_hevc_v4` | 必须公开 | 4 | 4 | 0 | 0 | 0 | 0 |
| `probe_hevc_capacity_info` | 必须公开 | 4 | 4 | 0 | 0 | 0 | 0 |
| `extract_hevc_dimensions` | 必须公开 | 3 | 3 | 0 | 0 | 0 | 0 |
| `apply_hevc_patches` | 必须公开 | 2 | 0 | 2 | 0 | 0 | 0 |
| `probe_hevc_capacity_ext` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `HEVC_SUPERBLOCK_POOL_SLOTS` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `EmbedPeakEstimate` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HevcCarrierPatch` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HevcSuperblockV4` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `stego/io`（6）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `inspect_carrier_file` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `probe_carrier_file` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `verify_carrier_file` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `extract_carrier_file_payload` | 必须公开 | 5 | 3 | 0 | 2 | 0 | 0 |
| `embed_carrier_file` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `extract_carrier_file` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |

### `stego/jpeg/cost/jmipod`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `JmipodCostModel` | 必须公开 | 3 | 3 | 0 | 0 | 0 | 0 |

### `stego/jpeg/cost/juniward`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `JuniwardCostModel` | 必须公开 | 5 | 3 | 2 | 0 | 0 | 0 |

### `stego/jpeg/cost/precover`（3）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `bias` | 隐藏但保留 | 7 | 7 | 0 | 0 | 0 | 0 |
| `estimate` | 隐藏但保留 | 7 | 6 | 1 | 0 | 0 | 0 |
| `decompress_luma` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `stego/jpeg/cost/uerd`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `UerdCostModel` | 必须公开 | 12 | 2 | 10 | 0 | 0 | 0 |

### `stego/jpeg/engine`（7）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `embed_jpeg_with_stats` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `inspect_jpeg` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `verify_jpeg` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `extract_jpeg` | 必须公开 | 10 | 0 | 10 | 0 | 0 | 0 |
| `embed_jpeg` | 必须公开 | 9 | 0 | 9 | 0 | 0 | 0 |
| `layout_for_payload` | 必须公开 | 5 | 1 | 4 | 0 | 0 | 0 |
| `probe_jpeg_capacity` | 必须公开 | 2 | 0 | 2 | 0 | 0 | 0 |

### `stego/jpeg/registry`（2）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get_jpeg_model` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `list` | 必须公开 | 39 | 36 | 2 | 0 | 1 | 0 |

### `stego/options`（19）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `resolve_credential` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `EmbedOptions` | 必须公开 | 149 | 123 | 24 | 2 | 0 | 0 |
| `ExtractOptions` | 必须公开 | 71 | 47 | 22 | 2 | 0 | 0 |
| `StegoTuning` | 必须公开 | 59 | 33 | 20 | 6 | 0 | 0 |
| `JpegAlgorithm` | 必须公开 | 27 | 12 | 13 | 2 | 0 | 0 |
| `ProbeOptions` | 必须公开 | 27 | 17 | 8 | 2 | 0 | 0 |
| `SpatialAlgorithm` | 必须公开 | 26 | 13 | 11 | 2 | 0 | 0 |
| `InspectOptions` | 必须公开 | 10 | 10 | 0 | 0 | 0 | 0 |
| `HevcMode` | 必须公开 | 9 | 5 | 2 | 2 | 0 | 0 |
| `VerifyOptions` | 必须公开 | 8 | 8 | 0 | 0 | 0 | 0 |
| `BridgeOptions` | 必须公开 | 7 | 7 | 0 | 0 | 0 | 0 |
| `StegoEmbedResult` | 必须公开 | 3 | 0 | 0 | 3 | 0 | 0 |
| `EmbedOutput` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `EmbedStats` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `HevcParams` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `StegoHeaderInfo` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `StegoVerifyResult` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `StegoWarning` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `VerifyLevel` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `stego/params`（12）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `DEFAULT_SLOT_BUDGET` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `MAX_AUTO_BACKTRACK_BYTES` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `MAX_GROUPED_BACKTRACK_BYTES` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `grouped_body_budget` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `max_grouped_backtrack_slots` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `SafetyPolicy` | 必须公开 | 45 | 20 | 22 | 3 | 0 | 0 |
| `PngParams` | 必须公开 | 38 | 20 | 16 | 2 | 0 | 0 |
| `JpegParams` | 必须公开 | 35 | 18 | 15 | 2 | 0 | 0 |
| `ExtractParams` | 必须公开 | 31 | 15 | 14 | 2 | 0 | 0 |
| `StegoProfile` | 必须公开 | 29 | 29 | 0 | 0 | 0 | 0 |
| `StegoCodec` | 必须公开 | 15 | 6 | 9 | 0 | 0 | 0 |
| `SafetyEnforcement` | 必须公开 | 8 | 4 | 0 | 4 | 0 | 0 |

### `stego/png/cost/hill`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `HillCostModel` | 必须公开 | 15 | 4 | 11 | 0 | 0 | 0 |

### `stego/png/cost/mipod`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `MipodCostModel` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |

### `stego/png/cost/suniward`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `SuniwardCostModel` | 必须公开 | 2 | 0 | 2 | 0 | 0 | 0 |

### `stego/png/engine`（15）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ChannelMode` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `embed_png_with_stats` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `inspect_png` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `verify_png` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `decode_png` | 必须公开 | 21 | 13 | 8 | 0 | 0 | 0 |
| `encode_png` | 必须公开 | 15 | 13 | 2 | 0 | 0 | 0 |
| `RawImage` | 必须公开 | 13 | 12 | 1 | 0 | 0 | 0 |
| `extract_png` | 必须公开 | 7 | 1 | 6 | 0 | 0 | 0 |
| `embed_png` | 必须公开 | 6 | 0 | 6 | 0 | 0 | 0 |
| `SPATIAL_ELIGIBLE_MAX` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `SPATIAL_ELIGIBLE_MIN` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `probe_png_capacity` | 必须公开 | 2 | 0 | 2 | 0 | 0 | 0 |
| `png_pre_salt` | 必须公开 | 1 | 1 | 0 | 0 | 0 | 0 |
| `IdatInfo` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `PngChunk` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `stego/png/registry`（8）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `SPATIAL_ALGORITHM_HILL` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `SPATIAL_ALGORITHM_MIPOD` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `SPATIAL_ALGORITHM_SUNIWARD` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `get_spatial_model` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `spatial_name_from_wire_id` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `spatial_wire_id` | pub(crate) | 0 | 0 | 0 | 0 | 0 | 0 |
| `list` | 必须公开 | 39 | 36 | 2 | 0 | 1 | 0 |
| `spatial_model_from_wire_id` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |

### `stego/registry`（4）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `StegoAlgorithmInfo` | 必须公开 | 2 | 0 | 0 | 2 | 0 | 0 |
| `list_stego_algorithms` | 必须公开 | 1 | 0 | 0 | 1 | 0 | 0 |
| `algorithms_for_format` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |
| `list_algorithms` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |

### `stego/traits`（3）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `PngCostModel` | 必须公开 | 10 | 5 | 5 | 0 | 0 | 0 |
| `JpegCostModel` | 必须公开 | 6 | 2 | 4 | 0 | 0 | 0 |
| `JpegGeometry` | 必须公开 | 1 | 0 | 1 | 0 | 0 | 0 |

### `structure/adapters`（10）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `format_bytes` | 隐藏但保留 | 10 | 0 | 10 | 0 | 0 | 0 |
| `HostAdapter` | 隐藏但保留 | 9 | 9 | 0 | 0 | 0 | 0 |
| `SeekRead` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |
| `FinalizeCtx` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `SeekReadWrite` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `SeekWrite` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `SegmentedSubStream` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `SubStream` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `TrailerCtx` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `StrategyCapacity` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/ebml`（6）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `EBML_HEADER_ID` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `EBML_VOID_ID` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `MATROSKA_SEGMENT_ID` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `encode_vint` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `read_element_id` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `read_vint_size` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/eof`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `EofAdapter` | 隐藏但保留 | 1 | 1 | 0 | 0 | 0 | 0 |

### `structure/adapters/heif`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `HeifAdapter` | 隐藏但保留 | 6 | 6 | 0 | 0 | 0 | 0 |

### `structure/adapters/io`（3）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `copy_exact` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `copy_stream` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `with_restored_position` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/isobmff`（13）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `isobmff_can_item_hidden` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |
| `isobmff_locate` | 隐藏但保留 | 1 | 1 | 0 | 0 | 0 | 0 |
| `isobmff_suspicious_structures` | 隐藏但保留 | 1 | 1 | 0 | 0 | 0 | 0 |
| `ITEM_HIDDEN_MAX_ENVELOPE` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `MAX_ISOBMFF_META_SCAN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `MP4_UUID_NEUTRAL` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `calc_prefix_len` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `heif_strategy_capacities` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `isobmff_inject` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `isobmff_strategy_capacities` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `isobmff_strip` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `isobmff_verify_structure` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `trailing_envelope_len` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/jpeg`（15）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `JpegAdapter` | 隐藏但保留 | 7 | 7 | 0 | 0 | 0 | 0 |
| `JPEG_COM` | 隐藏但保留 | 3 | 3 | 0 | 0 | 0 | 0 |
| `JPEG_EOI` | 隐藏但保留 | 3 | 3 | 0 | 0 | 0 | 0 |
| `MAX_JPEG_HEADER_SCAN` | 隐藏但保留 | 3 | 3 | 0 | 0 | 0 | 0 |
| `JPEG_MAX_TOTAL_CAPACITY` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |
| `JPEG_SOI` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |
| `find_jpeg_sos_offset` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |
| `JPEG_APP15` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `JPEG_MAX_SEG_PAYLOAD` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `JPEG_SOS` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `JpegScanEnd` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `JpegSegment` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `MAX_JPEG_NON_MARKER_SKIP` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `partition_jpeg_payload_lengths` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `scan_jpeg_markers` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/mkv`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `MkvAdapter` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/mp4`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `Mp4Adapter` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |

### `structure/adapters/pdf`（8）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `PdfAdapter` | 隐藏但保留 | 8 | 8 | 0 | 0 | 0 | 0 |
| `parse_pdf_trailer_info` | 隐藏但保留 | 6 | 6 | 0 | 0 | 0 | 0 |
| `PDF_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PdfTailInfo` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PdfTrailerInfo` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `parse_pdf_tail_info` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `parse_pdf_tail_info_with_magic` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `pdf_obj_header` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/pe`（5）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `PeAdapter` | 隐藏但保留 | 7 | 7 | 0 | 0 | 0 | 0 |
| `PE_DOS_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PE_NT_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PeInfo` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `parse_pe_headers` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/pe_codebits`（16）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `embed` | 隐藏但保留 | 274 | 227 | 37 | 9 | 1 | 0 |
| `profile` | 隐藏但保留 | 102 | 92 | 10 | 0 | 0 | 0 |
| `CHANNEL_VERSION` | 隐藏但保留 | 3 | 3 | 0 | 0 | 0 | 0 |
| `CHANNEL_MAGIC` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |
| `ChannelHeader` | 隐藏但保留 | 1 | 1 | 0 | 0 | 0 | 0 |
| `extract_ube` | 隐藏但保留 | 1 | 1 | 0 | 0 | 0 | 0 |
| `CHANNEL_HEADER_LEN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `CodePosition` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `MAX_CODEBITS_UBE_LEN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `MIN_UBE_LEN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `apply_diff` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `channel_requirement` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `parse_channel_header` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `parse_channel_header_from_profile` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `profile_upto` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `read_channel_header` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/pe_layout`（14）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `pe_code_layout` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |
| `parse_slack_layout_streaming` | 隐藏但保留 | 1 | 1 | 0 | 0 | 0 | 0 |
| `CodebitsError` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PeCodeLayout` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PeSlackLayout` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `find_slack_run` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `find_slack_run_streaming` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `max_zero_run_streaming` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `parse_pe_code_layout_streaming` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `pe_slack_layout` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `read_at` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `read_text_range` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `verify_zero_slack` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `write_at` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/pe_slack`（8）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `inject` | 隐藏但保留 | 28 | 28 | 0 | 0 | 0 | 0 |
| `locate` | 隐藏但保留 | 25 | 25 | 0 | 0 | 0 | 0 |
| `strip` | 隐藏但保留 | 13 | 13 | 0 | 0 | 0 | 0 |
| `MIN_CIPHERTEXT_DISTINCT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `MIN_CIPHERTEXT_NONZERO` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `SlackScan` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `find_slack_run` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `scan_slack` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/png`（7）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `PngAdapter` | 隐藏但保留 | 4 | 4 | 0 | 0 | 0 | 0 |
| `CHUNK_PRIV` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `CHUNK_STEG` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `IEND_FULL` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PNG_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `PNG_MAX_CHUNK_LEN` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `find_iend_offset` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/riff`（9）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `RIFF_CHUNK_FOURCC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `riff_can_chunk` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `riff_detect` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `riff_inject` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `riff_locate` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `riff_starts_with` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `riff_strategy_capacities` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `riff_suspicious_structures` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `riff_verify_structure` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/adapters/wav`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `WavAdapter` | 隐藏但保留 | 11 | 11 | 0 | 0 | 0 | 0 |

### `structure/adapters/webp`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `WebpAdapter` | 隐藏但保留 | 4 | 4 | 0 | 0 | 0 | 0 |

### `structure/adapters/zip`（6）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ZipAdapter` | 隐藏但保留 | 12 | 12 | 0 | 0 | 0 | 0 |
| `find_eocd_offset` | 隐藏但保留 | 4 | 4 | 0 | 0 | 0 | 0 |
| `ZIP_CD_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ZIP_EOCD_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ZIP_LOCAL_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `ZIP_SPAN_MAGIC` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/engine`（27）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `PayloadSource` | 必须公开 | 221 | 213 | 4 | 4 | 0 | 0 |
| `write_carrier` | 必须公开 | 148 | 148 | 0 | 0 | 0 | 0 |
| `read_carrier` | 必须公开 | 127 | 127 | 0 | 0 | 0 | 0 |
| `remove_carrier` | 必须公开 | 88 | 88 | 0 | 0 | 0 | 0 |
| `verify_carrier` | 必须公开 | 75 | 75 | 0 | 0 | 0 | 0 |
| `inspect_carrier` | 必须公开 | 49 | 49 | 0 | 0 | 0 | 0 |
| `write_carrier_bytes` | 必须公开 | 24 | 20 | 4 | 0 | 0 | 0 |
| `read_carrier_bytes` | 必须公开 | 21 | 16 | 5 | 0 | 0 | 0 |
| `read_carrier_with_dialect` | 必须公开 | 17 | 17 | 0 | 0 | 0 | 0 |
| `write_carrier_with` | 必须公开 | 16 | 16 | 0 | 0 | 0 | 0 |
| `inspect_carrier_with` | 必须公开 | 13 | 13 | 0 | 0 | 0 | 0 |
| `ReadSummary` | 必须公开 | 11 | 0 | 0 | 11 | 0 | 0 |
| `remove_carrier_bytes` | 必须公开 | 11 | 9 | 2 | 0 | 0 | 0 |
| `CarrierMetadata` | 必须公开 | 7 | 7 | 0 | 0 | 0 | 0 |
| `verify_carrier_bytes` | 必须公开 | 7 | 7 | 0 | 0 | 0 | 0 |
| `WriteResult` | 必须公开 | 6 | 3 | 0 | 3 | 0 | 0 |
| `remove_carrier_with_dialect` | 必须公开 | 5 | 5 | 0 | 0 | 0 | 0 |
| `inspect_carrier_bytes` | 必须公开 | 4 | 4 | 0 | 0 | 0 | 0 |
| `RemoveResult` | 必须公开 | 3 | 0 | 0 | 3 | 0 | 0 |
| `verify_carrier_with` | 必须公开 | 3 | 3 | 0 | 0 | 0 | 0 |
| `ReadResult` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `verify_passed` | 必须公开 | 2 | 2 | 0 | 0 | 0 | 0 |
| `VerifyResult` | 必须公开 | 1 | 0 | 0 | 1 | 0 | 0 |
| `InspectResult` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `LevelStatus` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `MetadataInspection` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |
| `Warning` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/envelope`（18）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `EnvelopeHeader` | 隐藏但保留 | 27 | 27 | 0 | 0 | 0 | 0 |
| `HEADER_SIZE` | 隐藏但保留 | 27 | 27 | 0 | 0 | 0 | 0 |
| `EnvelopeTrailer` | 隐藏但保留 | 17 | 17 | 0 | 0 | 0 | 0 |
| `TRAILER_SIZE` | 隐藏但保留 | 7 | 7 | 0 | 0 | 0 | 0 |
| `MAX_KNOWN_STRATEGY_ID` | 隐藏但保留 | 4 | 4 | 0 | 0 | 0 | 0 |
| `MAX_META_LEN` | 隐藏但保留 | 4 | 4 | 0 | 0 | 0 | 0 |
| `FLAG_COMPACT_META` | 隐藏但保留 | 3 | 3 | 0 | 0 | 0 | 0 |
| `FLAG_COMPRESSED` | 隐藏但保留 | 3 | 3 | 0 | 0 | 0 | 0 |
| `FLAG_ENCRYPTED` | 隐藏但保留 | 3 | 3 | 0 | 0 | 0 | 0 |
| `FLAG_STEALTH` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |
| `MAX_HINT_LEN` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |
| `CURRENT_VERSION` | 隐藏但保留 | 1 | 1 | 0 | 0 | 0 | 0 |
| `min_ube_len` | 隐藏但保留 | 1 | 1 | 0 | 0 | 0 | 0 |
| `AAD_SIZE` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `FLAG_HAS_HINT` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `FLAG_IS_FILE` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `MAX_OFFSET_DELTA` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `UnpackSecrets` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/options`（4）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `WriteOptions` | 必须公开 | 185 | 178 | 5 | 2 | 0 | 0 |
| `ReadOptions` | 必须公开 | 153 | 151 | 0 | 2 | 0 | 0 |
| `RestoreOptions` | 必须公开 | 102 | 98 | 0 | 4 | 0 | 0 |
| `StrategyChoice` | 必须公开(类型闭包) | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/params`（1）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `StructureProfile` | 必须公开 | 109 | 102 | 7 | 0 | 0 | 0 |

### `structure/registry`（8）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `id_to_strategy` | 隐藏但保留 | 6 | 6 | 0 | 0 | 0 | 0 |
| `strategy_to_id` | 隐藏但保留 | 6 | 6 | 0 | 0 | 0 | 0 |
| `ADAPTERS` | 隐藏但保留 | 5 | 5 | 0 | 0 | 0 | 0 |
| `find_adapter` | 隐藏但保留 | 4 | 4 | 0 | 0 | 0 | 0 |
| `STRATEGY_REGISTRY` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |
| `MAX_STRATEGY_ID` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `find_adapter_or_reject` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `StrategyId` | 必须公开 | 0 | 0 | 0 | 0 | 0 | 0 |

### `structure/rejection`（8）

| 条目 | 判定 | 外部引用 | tests | examples | gui | bins | main/lite |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `check_jar_signature` | 隐藏但保留 | 9 | 9 | 0 | 0 | 0 | 0 |
| `check_signature_file` | 隐藏但保留 | 8 | 8 | 0 | 0 | 0 | 0 |
| `check_unsupported_apk` | 隐藏但保留 | 5 | 5 | 0 | 0 | 0 | 0 |
| `check_pdf_signature` | 隐藏但保留 | 4 | 4 | 0 | 0 | 0 | 0 |
| `check_pe_authenticode` | 隐藏但保留 | 3 | 3 | 0 | 0 | 0 | 0 |
| `run_all_rejection_checks` | 隐藏但保留 | 2 | 2 | 0 | 0 | 0 | 0 |
| `check_content` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |
| `run_rejection_checks` | 隐藏但保留 | 0 | 0 | 0 | 0 | 0 | 0 |


## 附录 B：零外部引用条目清单（335 个）

> 分组键是条目的定义模块（同名条目可能出现在多组）。这些条目只说明“crate 外没人写名字”，
> 不代表可以删除：其中约 40 个是公开字段/返回类型（见附录 A 的 `KF`）。

- **`analysis`**（3）：`AnalysisReport`, `DetectorMetric`, `Severity`
- **`analysis/calibration`**（4）：`CalibrationEstimate`, `dct_chi2_suspicion`, `dct_chi2_suspicion_with_coefficients`, `estimate_with_coefficients`
- **`cli/args`**（24）：`BANNER`, `CapacityArgs`, `Commands`, `ContainerCommands`, `DiagCli`, `DiagCommands`, `EmbedArgs`, `ExtractArgs`, `GlobalArgs`, `InspectArgs`, `ListArgs`, `PasswordArgs`, `PayloadSourceArgs`, `ReadArgs`, `RestoreArgs`, `STRHIDE_BUILD_TIME`, `STRHIDE_VERSION_INFO`, `ScanArgs`, `StegoCli`, `StegoCommands`, `StegoTuningArgs`, `StructCli`, `VerifyArgs`, `WriteArgs`
- **`cli/helpers`**（2）：`prompt_password`, `resolve_key_file`
- **`cli/logging`**（1）：`level_for`
- **`cli/render`**（1）：`print_error`
- **`core/batch`**（1）：`ItemOutcome`
- **`core/commit`**（6）：`TargetLock`, `copy_file_durable`, `reject_carrier_output`, `reject_read_only_target`, `rename_with_retry`, `temp_path_for`
- **`core/config`**（2）：`FileConfig`, `StegoConfig`
- **`core/control`**（2）：`PROGRESS_STEP_BYTES`, `TaskControl`
- **`core/crypto`**（13）：`CHUNK_OVERHEAD`, `CONTENT_L1_PBKDF2_ITERATIONS`, `PBKDF2_ITERATIONS`, `PasswordSecrets`, `chunk_count`, `compute_stream_sha256`, `derive_all`, `derive_header_mask`, `derive_trailer_crc_mask`, `framed_len`, `make_chunk_nonce`, `make_meta_nonce`, `normalize_nfc`
- **`core/crypto,structure/envelope`**（1）：`AAD_SIZE`
- **`core/errors`**（1）：`TrellisCause`
- **`core/fs`**（4）：`batch_payload_name`, `escape_control_chars`, `escape_terminal_text`, `unique_batch_path`
- **`core/i18n`**（1）：`format_msg`
- **`core/i18n/messages`**（19）：`CAPACITY_AFTER_HELP_EN`, `CAPACITY_AFTER_HELP_ZH`, `EMBED_AFTER_HELP_EN`, `EMBED_AFTER_HELP_ZH`, `EXTRACT_AFTER_HELP_EN`, `EXTRACT_AFTER_HELP_ZH`, `INSPECT_AFTER_HELP_EN`, `INSPECT_AFTER_HELP_ZH`, `Msg`, `READ_AFTER_HELP_EN`, `READ_AFTER_HELP_ZH`, `RESTORE_AFTER_HELP_EN`, `RESTORE_AFTER_HELP_ZH`, `SCAN_AFTER_HELP_EN`, `SCAN_AFTER_HELP_ZH`, `VERIFY_AFTER_HELP_EN`, `VERIFY_AFTER_HELP_ZH`, `WRITE_AFTER_HELP_EN`, `WRITE_AFTER_HELP_ZH`
- **`core/media`**（1）：`MediaInfo`
- **`core/params`**（5）：`AUTO_COMPRESSION_SAVING_PERCENT`, `DEFAULT_COMPRESSION_LEVEL`, `MAX_COMPRESSION_LEVEL`, `STEALTH_DOMAIN`, `VideoBudget`
- **`core/pipeline`**（7）：`BatchPreflight`, `CarrierValidator`, `batch_output_dir`, `derive_default_output_path`, `for_each_carrier`, `preflight_batch`, `resolve_carrier_target`
- **`crate`**（1）：`i18n_messages`
- **`facade`**（1）：`AnalysisFacade`
- **`formats/annexb`**（20）：`NAL_AUD_NUT`, `NAL_BLA_N_LP`, `NAL_BLA_W_LP`, `NAL_BLA_W_RADL`, `NAL_CRA_NUT`, `NAL_EOB_NUT`, `NAL_EOS_NUT`, `NAL_FD_NUT`, `NAL_IDR_N_LP`, `NAL_IDR_W_RADL`, `NAL_PPS_NUT`, `NAL_PREFIX_SEI_NUT`, `NAL_RADL_R`, `NAL_RASL_R`, `NAL_SPS_NUT`, `NAL_STSA_R`, `NAL_SUFFIX_SEI_NUT`, `NAL_TRAIL_R`, `NAL_TSA_R`, `NAL_VPS_NUT`
- **`formats/capability`**（2）：`MemoryProfile`, `StegoKind`
- **`formats/jpeg_segments`**（6）：`QuantTable`, `STANDARD_LUMA_QT`, `parse_component_dqt`, `parse_component_tq`, `parse_dqt_tables`, `parse_luma_dqt`
- **`formats/sniff`**（7）：`HEIF_BRANDS`, `JPEG_MAGIC`, `SNIFF_PREFIX_BYTES`, `is_heif_bytes`, `is_jpeg_bytes`, `is_mp4_bytes`, `is_png_bytes`
- **`formats/sniff,structure/adapters/ebml`**（1）：`EBML_HEADER_ID`
- **`formats/sniff,structure/adapters/pdf`**（1）：`PDF_MAGIC`
- **`formats/sniff,structure/adapters/png`**（1）：`PNG_MAGIC`
- **`formats/sniff,structure/adapters/zip`**（3）：`ZIP_EOCD_MAGIC`, `ZIP_LOCAL_MAGIC`, `ZIP_SPAN_MAGIC`
- **`stego`**（7）：`compute_default_threads`, `default_thread_count`, `embed_carrier_with_dialect_info`, `extract_carrier_payload`, `init_default_thread_pool`, `inspect_carrier_with_dialect`, `verify_carrier_with_dialect`
- **`stego/engine`**（11）：`AnnexBEngine`, `FlacEngine`, `HeifEngine`, `JpegEngine`, `MkvEngine`, `Mp4Engine`, `PngEngine`, `StegoEngine`, `WavEngine`, `engine_for`, `supported_formats`
- **`stego/format`**（14）：`AudioFormatProfile`, `HeaderLocatorKeys`, `HevcFormatProfile`, `JPEG_SUPERBLOCK_BYTES`, `JPEG_SUPERBLOCK_SLOTS`, `OFFICIAL_AUDIO_CIPHER`, `OFFICIAL_FLAC_FORMAT`, `OFFICIAL_HEVC_CIPHER`, `OFFICIAL_JPEG_CIPHER`, `OFFICIAL_WAV_FORMAT`, `PngFormatProfile`, `SessionKeys`, `derive_l3_session_keys`, `info_with_domain`
- **`stego/heif/thumb_bridge`**（4）：`BridgeTarget`, `BridgeTargetKind`, `inspect_heif_bridge`, `verify_heif_bridge`
- **`stego/hevc/engine`**（24）：`EMBED_WINDOW_GOPS`, `EmbedPeakEstimate`, `HEVC_EXT_STC_H`, `HEVC_EXT_STC_U`, `HEVC_FORMAT_ID`, `HEVC_HEADER_SLOTS_MAX`, `HEVC_MAX_EXT_BYTES`, `HEVC_SUPERBLOCK_BYTES`, `HEVC_SUPERBLOCK_MIN_SLOTS`, `HevcCarrierPatch`, `HevcSuperblockV4`, `embed_hevc_patches`, `embed_hevc_patches_v4`, `embed_hevc_payload`, `embed_window_bytes`, `estimate_embed_peak_bytes`, `hevc_extension_slots`, `inspect_hevc`, `inspect_hevc_mp4_file`, `inspect_hevc_mp4_file_v4`, `inspect_hevc_v4`, `superblock_positions`, `verify_hevc`, `verify_hevc_v4`
- **`stego/io`**（4）：`extract_carrier_file`, `inspect_carrier_file`, `probe_carrier_file`, `verify_carrier_file`
- **`stego/jpeg/cost/precover`**（1）：`decompress_luma`
- **`stego/jpeg/engine`**（3）：`embed_jpeg_with_stats`, `inspect_jpeg`, `verify_jpeg`
- **`stego/jpeg/registry`**（1）：`get_jpeg_model`
- **`stego/options`**（8）：`EmbedOutput`, `EmbedStats`, `HevcParams`, `StegoHeaderInfo`, `StegoVerifyResult`, `StegoWarning`, `VerifyLevel`, `resolve_credential`
- **`stego/params`**（5）：`DEFAULT_SLOT_BUDGET`, `MAX_AUTO_BACKTRACK_BYTES`, `MAX_GROUPED_BACKTRACK_BYTES`, `grouped_body_budget`, `max_grouped_backtrack_slots`
- **`stego/png/engine`**（6）：`ChannelMode`, `IdatInfo`, `PngChunk`, `embed_png_with_stats`, `inspect_png`, `verify_png`
- **`stego/png/registry`**（6）：`SPATIAL_ALGORITHM_HILL`, `SPATIAL_ALGORITHM_MIPOD`, `SPATIAL_ALGORITHM_SUNIWARD`, `get_spatial_model`, `spatial_name_from_wire_id`, `spatial_wire_id`
- **`stego/registry`**（2）：`algorithms_for_format`, `list_algorithms`
- **`structure/adapters`**（7）：`FinalizeCtx`, `SeekReadWrite`, `SeekWrite`, `SegmentedSubStream`, `StrategyCapacity`, `SubStream`, `TrailerCtx`
- **`structure/adapters/ebml`**（5）：`EBML_VOID_ID`, `MATROSKA_SEGMENT_ID`, `encode_vint`, `read_element_id`, `read_vint_size`
- **`structure/adapters/io`**（3）：`copy_exact`, `copy_stream`, `with_restored_position`
- **`structure/adapters/isobmff`**（10）：`ITEM_HIDDEN_MAX_ENVELOPE`, `MAX_ISOBMFF_META_SCAN`, `MP4_UUID_NEUTRAL`, `calc_prefix_len`, `heif_strategy_capacities`, `isobmff_inject`, `isobmff_strategy_capacities`, `isobmff_strip`, `isobmff_verify_structure`, `trailing_envelope_len`
- **`structure/adapters/jpeg`**（8）：`JPEG_APP15`, `JPEG_MAX_SEG_PAYLOAD`, `JPEG_SOS`, `JpegScanEnd`, `JpegSegment`, `MAX_JPEG_NON_MARKER_SKIP`, `partition_jpeg_payload_lengths`, `scan_jpeg_markers`
- **`structure/adapters/mkv`**（1）：`MkvAdapter`
- **`structure/adapters/pdf`**（5）：`PdfTailInfo`, `PdfTrailerInfo`, `parse_pdf_tail_info`, `parse_pdf_tail_info_with_magic`, `pdf_obj_header`
- **`structure/adapters/pe`**（4）：`PE_DOS_MAGIC`, `PE_NT_MAGIC`, `PeInfo`, `parse_pe_headers`
- **`structure/adapters/pe_codebits`**（10）：`CHANNEL_HEADER_LEN`, `CodePosition`, `MAX_CODEBITS_UBE_LEN`, `MIN_UBE_LEN`, `apply_diff`, `channel_requirement`, `parse_channel_header`, `parse_channel_header_from_profile`, `profile_upto`, `read_channel_header`
- **`structure/adapters/pe_layout`**（11）：`CodebitsError`, `PeCodeLayout`, `PeSlackLayout`, `find_slack_run_streaming`, `max_zero_run_streaming`, `parse_pe_code_layout_streaming`, `pe_slack_layout`, `read_at`, `read_text_range`, `verify_zero_slack`, `write_at`
- **`structure/adapters/pe_layout,structure/adapters/pe_slack`**（1）：`find_slack_run`
- **`structure/adapters/pe_slack`**（4）：`MIN_CIPHERTEXT_DISTINCT`, `MIN_CIPHERTEXT_NONZERO`, `SlackScan`, `scan_slack`
- **`structure/adapters/png`**（5）：`CHUNK_PRIV`, `CHUNK_STEG`, `IEND_FULL`, `PNG_MAX_CHUNK_LEN`, `find_iend_offset`
- **`structure/adapters/riff`**（9）：`RIFF_CHUNK_FOURCC`, `riff_can_chunk`, `riff_detect`, `riff_inject`, `riff_locate`, `riff_starts_with`, `riff_strategy_capacities`, `riff_suspicious_structures`, `riff_verify_structure`
- **`structure/adapters/zip`**（1）：`ZIP_CD_MAGIC`
- **`structure/engine`**（4）：`InspectResult`, `LevelStatus`, `MetadataInspection`, `Warning`
- **`structure/envelope`**（4）：`FLAG_HAS_HINT`, `FLAG_IS_FILE`, `MAX_OFFSET_DELTA`, `UnpackSecrets`
- **`structure/options`**（1）：`StrategyChoice`
- **`structure/registry`**（3）：`MAX_STRATEGY_ID`, `StrategyId`, `find_adapter_or_reject`
- **`structure/rejection`**（2）：`check_content`, `run_rejection_checks`

