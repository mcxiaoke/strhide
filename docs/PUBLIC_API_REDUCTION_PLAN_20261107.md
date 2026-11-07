# strhide 公开接口最小化与收敛落地方案

- 编制时间：2026-11-07 12:15（本机时间）
- 关联材料：
  - [RELEASE_READINESS_20261106.md](./RELEASE_READINESS_20261106.md) §0、§2.3、§3（发布就绪度与公开接口护栏缺口）
  - [PUBLIC_API_SURFACE_20261107.md](./PUBLIC_API_SURFACE_20261107.md)（公开条目全量索引与外部引用实测统计）
  - [docs/api/ARCHITECTURE.md](./api/ARCHITECTURE.md)（系统架构与分层边界）
- 核心目标：**尽量减少 public 接口，只开放必要接口，消除内部实现泄露，补齐公开结构体演进护栏。**

---

## 1. 背景与根因诊断

### 1.1 现状指标
根据对 `rust/src`（`--all-features`）的实测扫描：
- **外部可达公开模块高达 104 个**；
- **公开 Struct 共 166 个**，其中包含 `pub` 字段的结构体 124 个，**高达 121 个未标注 `#[non_exhaustive]`**；
- 全库共有 **607 个文档化公开条目**（函数、结构体、枚举、常量等），其中 **335 个（56.4%）在 crate 外部（GUI、tests、examples、bin）为零引用**。

### 1.2 根因分析
1. **模块声明层级穿透（`pub mod` 滥用）**：
   - 在早期重构拆分子目录时，模块声明习惯性使用了 `pub mod` 而非 `pub(crate) mod`；
   - 例如 `structure/mod.rs` 导出了 `pub mod adapters;`，直接将其下 **18 个具体适配器实现子模块**全部暴露给外界；
   - `stego/mod.rs` 导出了 `pub mod hevc;`、`pub mod jpeg;`、`pub mod coding;` 等，导致底层音视频 NAL 解析、CABAC 状态机、STC 编码网格完全泄露。
2. **测试边界倒逼接口外露**：
   - 历史白盒测试放在了外部集成测试目录 `rust/tests/`，为了让外部测试能编译，被迫将大量原本应属于模块内部的私有数据结构与辅助函数升格为 `pub`。
3. **演进护栏缺失的真相**：
   - `RELEASE_READINESS_20261106.md` 中指出的“121 个公开 struct 缺失 `#[non_exhaustive]`”，**其中超过一半（约 70 个）根本就不该是公开类型**（如 `CabacRecorder`, `HevcSuperblockV4`, `Tlv`, `ChannelHeader`, `JpegSegment`, `SlackScan` 等）。它们是由于底层模块被误设为 `pub mod` 而被动卷入 Public API 的。

---

## 2. 公开接口收敛原则

依据项目的定位（**格式保持、无损可还原的数据隐藏工具与库**）以及 GUI（`StrHideStudio`）与外部库开发者的真实集成需求，确立以下四条原则：

1. **门面优先原则（Facade First）**：
   对外主推荐入口统一为 `strhide::facade::StrHide`，通过 `.structure()` / `.stego()` / `.analysis()` 派生子门面。底层自由函数仅保留顶层高阶入口（`write_carrier`, `read_carrier`, `embed_carrier`, `extract_carrier`, `scan_file` 等）。
2. **实现完全内聚原则（Private Implementation）**：
   具体载体的注入算法、音视频/容器解析逻辑、底层线格式打包、密码学微头和 STC 编码矩阵属于**引擎黑盒实现**，禁止对外暴露，必须收敛为 `pub(crate)`。
3. **二进制与文档隔离原则（CLI / Internal Isolation）**：
   命令行 CLI 二进制（`main.rs`, `sthc.rs` 等）所需的支持模块应标记 `#[doc(hidden)]`，防止污染 docs.rs 和库使用者的自动补全。
4. **稳定配置与结果加固原则（Evolution Guards）**：
   对真正面向下游公开的 Options、Results、Stats 结构体，统一标记 `#[non_exhaustive]`，防止后续新增字段导致下游破坏性编译失败。

---

## 3. 详细分类梳理：哪些应该公开，哪些不应该公开

### 3.1 应该公开的接口（Keep Public & Guarded）

这些是下游开发者（包括 GUI、嵌入式调用者、微服务等）正常完成“数据隐藏、读取、还原、诊断”必需的类型。

| 模块 / 分类 | 建议公开的项 | 理由与说明 | 演进护栏要求 |
|---|---|---|---|
| **门面（Facade）** | `StrHide`, `StructureFacade`, `StegoFacade`, `AnalysisFacade`, `Dialect`, `Domain`, `DualOptions`, `DualInspect`, `DualVerify`, `SmartExtractOptions`, `ExtractOutcome`, `run_cli_from`, `run_domain_cli_from` | 官方推荐的第一类入口与多域协同抽象，GUI 和库使用者的核心依赖。 | 带 `pub` 字段的 `Dual*`、`SmartExtractOptions` 等必须标 `#[non_exhaustive]` |
| **错误体系（Errors）** | `StrHideError`, `ErrorKind`, `ErrorDetail`, `TrellisCause` | 全库统一错误处理入口，支持多语言渲染。 | `ErrorDetail` 已结构化，变体保持稳定 |
| **结构域（Structure）** | **选项与结果**：`WriteOptions`, `ReadOptions`, `RestoreOptions`, `WriteResult`, `ReadResult`, `ReadSummary`, `RemoveResult`, `InspectResult`, `VerifyResult`<br>**策略与标识**：`StrategyId`, `StrategyChoice`, `Warning`<br>**载荷来源**：`PayloadSource`<br>**高阶入口**：`write_carrier*`, `read_carrier*`, `remove_carrier*`, `inspect_carrier*`, `verify_carrier*` | 结构域的核心业务实体。注意：统一从 `strhide::structure::*` 导出即可，下层子模块（`engine`, `options`）无需对外部公开。 | 所有 Options 与 Results 结构体必须加 `#[non_exhaustive]` |
| **内容域（Stego）** | **选项与结果**：`EmbedOptions`, `ExtractOptions`, `ProbeOptions`, `InspectOptions`, `VerifyOptions`, `EmbedOutput`, `EmbedStats`, `StegoEmbedResult`, `StegoCapacityInfo`, `StegoAlgorithmInfo`, `StegoHeaderInfo`, `StegoVerifyResult`<br>**策略与调优**：`SafetyPolicy`, `SafetyLevel`, `SafetyEnforcement`, `StegoTuning`, `Freshness`, `JpegParams`, `PngParams`, `ExtractParams`, `SpatialAlgorithm`, `JpegAlgorithm`, `HevcMode`, `HevcParams`<br>**高阶入口**：`embed_carrier*`, `extract_carrier*`, `probe_carrier_capacity*`, `list_stego_algorithms`, `algorithms_for_format`<br>**并发辅助**：`init_default_thread_pool`, `compute_default_threads`, `default_thread_count` | 内容隐写域的核心业务实体与算法配置，GUI 深度依赖其调参枚举和容量返回。 | 所有 Options、Results、Params 结构体必须加 `#[non_exhaustive]` |
| **通用地基（Core）** | **任务控制**：`Control`, `CancelToken`, `Event`, `Progress`, `Stage`<br>**统一载荷**：`Payload`, `PayloadKind`<br>**媒体元数据**：`MediaInfo`<br>**国际化渲染**：`Lang`, `RenderCtx`<br>**批处理（GUI必需）**：`BatchPlan`, `BatchOutcome`, `ItemOutcome`, `run_batch` | 支撑异步进度汇报、流控、载荷抽象与批处理的基本类型。 | `Batch*`、`MediaInfo` 需标 `#[non_exhaustive]` |
| **格式与能力（Formats）** | **嗅探**：`FileFormat`, `sniff_bytes`, `sniff_file`, `sniff_stream`<br>**能力矩阵**：`CAPABILITIES`, `Capability`, `capability_of`, `StegoKind`, `MemoryProfile` | 格式判别和支持特性查询，GUI 和调用方用于做文件过滤与 UI 交互。 | `Capability` 标 `#[non_exhaustive]` |
| **黑盒分析（Analysis）** | `scan_file`, `scan_bytes`, `ScanReport`, `Finding`, `DetectorMetric` | 诊断域分析入口与报告实体。 | `ScanReport`, `Finding` 标 `#[non_exhaustive]` |
| **定制方言（Profiles）** | `StructureProfile`, `StegoProfile`, `MagicPair`, `CompressionStrategy`, `RejectionPolicy` | 针对私有方言、企业定制密钥或特定压缩策略的高级扩展点。 | 必须保持 `#[non_exhaustive]` |
| **Prelude** | `strhide::prelude::*` | 重导出最常用的门面、错误、选项类型，保持轻量。 | - |

---

### 3.2 坚决不应该公开的接口（Must be Private / `pub(crate)`）

以下模块和类型属于**内部实现细节**，绝不应出现在公共 API 中。应直接将其父模块降级为 `pub(crate) mod`，阻断级联泄露。

| 模块路径 | 包含的内部项（举例） | 现状暴露原因 | 为什么必须改为私有（`pub(crate)`） |
|---|---|---|---|
| **`structure::adapters::*`**<br>(全部 18 个适配器子模块) | `PngAdapter`, `ZipAdapter`, `PdfTrailerInfo`, `PeCodeLayout`, `ChannelHeader`, `JpegSegment`, `SlackScan` 等 **130+ 个内部项** | 历史拆分文件时随手写了 `pub mod`；外部集成测试直接引用了适配器内部测试 | 1. 引擎不支持运行时注册外部 Adapter，暴露具体实现类无任何扩展价值；<br>2. 泄露底层容器修改细节（如 PE 节空隙、PDF 增量标记等），锁定内部重构；<br>3. 产生海量未标注 `non_exhaustive` 的 struct。 |
| **`structure::envelope`** | `serialize_carrier_header`, `parse_trailer`, `decrypt_metadata`, `EnvelopeHeader`, `EnvelopeTrailer`, `UnpackSecrets` 等 **40 个内部项** | 白盒测试在 `tests/test_security` 试图伪造恶意头部 | 结构域 UBE v2.2 二进制协议的底层封包解包逻辑。外部使用者只传载荷与载体，绝不应该直接操作或构造裸协议头。 |
| **`structure::rejection`** | `check_signed_pe`, `check_signed_pdf`, `check_carrier_writable` 等 **8 个函数** | 测试直接测试拒绝函数 | 这是 `write_carrier` 内部执行的安全拦截管道，调用方只需接收错误类型，无需单独调用各格式的检查分支。 |
| **`structure::registry` 的内部映射** | `ADAPTERS`, `find_adapter`, `find_adapter_or_reject` | 适配器路由单例 | 外部只需要 `StrategyId` 和 `StrategyChoice`。内部的适配器查找表是私有实现细节。 |
| **`stego::hevc::*`**<br>(全部 8 个子模块) | `bitstream::*`, `slot::*`, `heif_boxes::*`, `mp4_boxes::*`, `sniff::*`, `CabacRecorder`, `FlipGeometry`, `CostFactors`, `HevcSuperblockV4` 等 **104 个底层项** | HEVC 压力测试和抽样工具依赖底层追踪器 | HEVC/H.265 隐写的核心黑盒：包含 NALU 语法解析、CABAC 状态机、SEI 提取、箱体字节级替换。**极度脆弱且紧耦合**，一旦公开将成为永久技术债务。 |
| **`stego::jpeg::*`**<br>(全部 7 个子模块) | `dht::*`, `geometry::*`, `header_v4::*`, `v3_layout::*`, `cost::*` (jmipod, juniward, uerd, precover) 等 **46 个底层项** | 部分 benchmark 示例（如 `stc_capacity_eval`）直接评测底层代价矩阵 | JPEG 霍夫曼表、DCT 频域变换、代价矩阵卷积计算。调用方只通过 `JpegAlgorithm` 选择算法，不应直接操作这些矩阵算子。 |
| **`stego::png::*`**<br>(全部 3 个子模块) | `cost::*` (hill, mipod, suniward), `engine::RawImage`, `engine::IdatInfo`, `engine::PngChunk` 等 **27 个底层项** | 历史 benchmark 示例直接解压 IDAT 测耗时 | 像素滤波、小波分解与代价权重计算细节。外部用户只传图片字节，不应感知 PNG chunk 拆分。 |
| **`stego::coding`** | `stc::*`, `syndrome_trellis_decode` 等 **44 个底层项** | 矩阵评测测试 | Syndrome Trellis Codes（STC）纠错网格构建与 Viterbi 解码。属于纯算法内部实现。 |
| **`stego::envelope`** 与 **`stego::header`** | `SpatialHeaderV4`, `Tlv`, `SessionKeys`, `HeaderLocatorKeys`, `derive_locators` 等 **52 个底层项** | V4 格式自描述测试 | 内容域 V4 伪随机微头的序列化与 TLV 扩展区布局。纯内部线格式细节。 |
| **`stego::prng`** | `deterministic_payload`, `PermutationPrng` 等 **12 个函数** | 压力测试用于生成可复现伪随机测试载荷 | 内部置换发生器，不是通用密码学随机库，不应向外导出。 |
| **`stego::wavelet`** 与 **`stego::heif`** | `dwt2d`, `idwt2d`, `BridgeTarget` | 图像算法与缩略图桥接 | 纯内部图像变换与桥接实现。 |
| **`formats::annexb`** 与 **`formats::jpeg_segments`** | `find_annexb_nal_units`, `QuantTable`, 25 个 NAL 常量 | 供结构分析复用 | 这是为多媒体解析服务的内部辅助工具，`strhide` 不是通用视频编解码库，不应公开这些底层解析器。 |
| **`analysis::calibration`** | `CalibrationEstimate` 等 **4 个内部函数** | 盲校准白盒测试 | 隐写分析内部用于校准图像特征的子算法，外部只需要调用 `scan_file` 拿到结果。 |
| **`core::fs`** | `clone_file_timestamps`, `ensure_dir_writable` 等 **5 个函数** | 文件操作辅助 | 内部文件系统辅助逻辑，绝不应充当通用 FS 工具对外暴露。 |
| **`core::config`** | `FileConfig`, `StegoConfig` | CLI 读取 `strhide.toml` | 纯属 CLI 的配置文件反序列化模型，不属于核心库 API。 |
| **`cli::*` 的内部子模块** | `args::*` (全部 18 个结构体), `cmd_*::*`, `helpers::*`, `render::*`, `logging::*` | CLI 二进制同 crate 共享代码 | 命令行参数定义极易随 clap 升级产生破坏性变更，且对外部嵌入开发者无用。应收拢为 `#[doc(hidden)]` 或私有化，外部运行 CLI 只留 `run_cli_from`。 |
| **`lib.rs` 顶层无序 re-export** | `pub use stego::jpeg::cost::UerdCostModel;`<br>`pub use stego::format::GridRule;` | 阶段 3 遗留的个别临时导出 | 孤立导出一个 `UerdCostModel` 而不导出其他算法，属于遗留的坏味道，应予移除。 |

---

### 3.3 演进护栏精准补齐清单（需要加 `#[non_exhaustive]` 的公开 Struct）

在剔除上述 70+ 个被私有化的底层结构体后，**真正需要作为公共契约存在、且必须标注 `#[non_exhaustive]` 的公开结构体约为 35~40 个**：

#### 1. 选项类（Options - 10 个）
- `strhide::structure::options::WriteOptions`
- `strhide::structure::options::ReadOptions`
- `strhide::structure::options::RestoreOptions`
- `strhide::stego::options::EmbedOptions`
- `strhide::stego::options::ExtractOptions`
- `strhide::stego::options::ProbeOptions`
- `strhide::stego::options::InspectOptions`
- `strhide::stego::options::VerifyOptions`
- `strhide::facade::DualOptions`
- `strhide::facade::SmartExtractOptions`

#### 2. 结果类（Results & Outcomes - 11 个）
- `strhide::structure::engine::WriteResult`
- `strhide::structure::engine::ReadResult`
- `strhide::structure::engine::ReadSummary`
- `strhide::structure::engine::RemoveResult`
- `strhide::structure::engine::InspectResult`
- `strhide::structure::engine::VerifyResult`
- `strhide::stego::options::StegoEmbedResult`
- `strhide::stego::options::StegoVerifyResult`
- `strhide::facade::DualInspect`
- `strhide::facade::DualVerify`
- `strhide::facade::ExtractOutcome`

#### 3. 统计与信息类（Stats & Info - 9 个）
- `strhide::stego::options::EmbedOutput`
- `strhide::stego::options::EmbedStats`
- `strhide::stego::options::StegoCapacityInfo`
- `strhide::stego::registry::StegoAlgorithmInfo`
- `strhide::stego::options::StegoHeaderInfo`
- `strhide::core::media::MediaInfo`
- `strhide::analysis::ScanReport`
- `strhide::analysis::Finding`
- `strhide::formats::capability::Capability`

#### 4. 批处理与控制类（Batch & Control - 4 个）
- `strhide::core::batch::BatchPlan`
- `strhide::core::batch::BatchOutcome`
- `strhide::core::batch::ItemOutcome`
- `strhide::core::control::Event`

> **特例说明（无需标注）**：
> - `MagicPair`：线格式固定的 8 字节前缀与后缀魔数，属于物理定型契约，不扩展；
> - `ErrorDetail`：结构稳定，由 `detail_i18n()` 工厂函数产出。

---

## 4. 影响评估与平滑解耦策略

### 4.1 桌面端 GUI（`gui/src-tauri`）
- **实测结论**：GUI 仅调用了 `facade::*`、`structure::options::*`、`structure::engine::{ReadSummary, WriteResult}`、`stego::options::*`、`core::batch`、`core::control`、`errors::*` 等高层接口。
- **影响为零**：GUI 完全未引用任何将被私有化的 `adapters`, `envelope`, `hevc`, `jpeg`, `coding` 等模块。上述收敛对 GUI 零破坏。

### 4.2 命令行 CLI（`src/cli`）
- **实测结论**：CLI 与核心库处于同一 Rust crate（`rust/src/`）。
- **影响为零**：Rust 语法规则下，同一 crate 内各模块天然可以互相访问 `pub(crate)` 项。将内部实现改为 `pub(crate)` 完全不影响 CLI 的编译与运行。

### 4.3 外部白盒测试（`rust/tests/`）
- 少数集成测试直接引用了 `structure::adapters::pe_codebits`、`stego::header`、`structure::envelope` 等内部符号（约 10 个测试文件）。
- **解耦路径**：
  1. **测试内移**：将纯白盒验证移动至对应源码文件底部的 `#[cfg(test)] mod tests` 中，作为单元测试运行。单元测试天生享有私有访问权；
  2. **临时内部后门（如果暂不迁测试）**：在 `src/lib.rs` 开辟一个 `#[doc(hidden)] pub mod __internal { ... }` 桥接模块，测试改用该路径，彻底从面向公众的 docs.rs 文档与自动补全中移出。

### 4.4 外部示例（`rust/examples/`）
- 少数底层压力/基准测试示例（如 `stc_capacity_eval.rs`）引用了 `stego::jpeg::engine` 等内部函数。
- **解耦路径**：通过 `#[doc(hidden)] pub mod __internal` 提供内部 benchmark 挂载，不列入公共 API 承诺。

### 4.5 第三方私有 Profile 与 CLI 驱动（run_domain_cli_from）
- **场景定位**：第三方或企业用户基于 `strhide` 构建“专属/私有二进制工具”（载体仅其私有编译版本可读写，官方版本探测无数据）。
- **实现方式**：
  第三方在独立二进制工程（或自身 `main.rs`）中，使用 `const` 编译期构造 `Dialect`，注入 `StrHide` 实例，并通过 `run_domain_cli_from` 驱动整套命令行：
  ```rust
  use std::ffi::OsString;
  use strhide::cli::Domain; // 或 strhide::facade::CliDomain
  use strhide::facade::{Dialect, StrHide};
  use strhide::params::MagicPair;
  use strhide::stego::params::StegoProfile;
  use strhide::structure::params::StructureProfile;

  // 1. 声明私有 Profile / Dialect（零运行时开销）
  const PRIVATE_DIALECT: Dialect = Dialect::new()
      .with_structure_profile(
          StructureProfile::new()
              .with_default_secret("corp-deployment-key-2026")
              .with_stealth_domain(b"corp-stealth-v1")
              .with_magic(MagicPair {
                  header: *b"\xDE\xAD\xBE\xEF\x01\x02\x03\x04",
                  trailer: *b"\xDE\xAD\xBE\xEF",
              }),
      )
      .with_stego_profile(
          StegoProfile::new()
              .with_default_secret("corp-stego-key-2026")
              .with_stego_domain(b"corp-stego-v1"),
      );

  const ENGINE: StrHide = StrHide::new().with_dialect(PRIVATE_DIALECT);

  fn main() {
      let argv: Vec<OsString> = std::env::args_os().collect();
      // 2. 驱动指定子领域的私有 CLI（Domain::All / Structure / Stego / Diagnostics）
      let exit_code = ENGINE.run_domain_cli_from(Domain::All, argv);
      std::process::exit(exit_code);
  }
  ```
- **公开接口契约保证**：
  1. **必须完全公开且稳定**：
     - 方言门面：`Dialect`、`StrHide`、`run_cli_from`、`run_domain_cli_from`；
     - 私有配置契约：`StructureProfile`、`StegoProfile`、`MagicPair` 以及更深层线格式定制所需的 `JpegFormatProfile`、`PngFormatProfile`、`HevcFormatProfile`、`WireCipherProfile`、`GridRule`；
     - 领域枚举：`strhide::cli::Domain`（包含 `All`, `Structure`, `Stego`, `Diagnostics`）以及 `strhide::facade::CliDomain` 别名。
  2. **为何不受私有化影响**：
     - 当第三方调用 `ENGINE.run_domain_cli_from(domain, argv)` 时，底层格式适配（`adapters::*`）与隐写算法（`hevc::*`、`jpeg::*`）是由 `ENGINE` 自动调度执行的。第三方**不需要也不应该**直接操作底层的适配器或算法子模块；
     - 同样，第三方只需传入原始 `argv`，clap 参数解析与派发完全由库内部闭环完成，第三方**无需引用 `cli::args::*` 中的 18 个 clap 结构体**。因此收紧内部模块与 clap 结构体对第三方私有 CLI 驱动零破坏。


---

## 5. 分步实施落地路线图

```text
┌──────────────────────────────────────────────────────────────┐
│ Phase 1: 模块级可见性收缩（收紧 pub mod 为 pub(crate) mod）      │
│  - structure/mod.rs (adapters, envelope, rejection, registry)│
│  - stego/mod.rs (hevc, jpeg, png, audio, coding, header...)   │
│  - formats/mod.rs (annexb, jpeg_segments)                    │
│  - core/mod.rs (fs, config)                                  │
│  - analysis.rs (calibration)                                 │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Phase 2: CLI 与内部测试隔离                                    │
│  - src/cli/mod.rs 添加 #[doc(hidden)]                         │
│  - 设立 #[doc(hidden)] pub mod __internal 支撑 tests/examples │
│  - 移除 lib.rs 遗留的零散导出 (UerdCostModel, GridRule)         │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Phase 3: 公开结构体演进护栏集中加固                            │
│  - 为收敛后的约 35~40 个公开 struct 标注 #[non_exhaustive]    │
│  - 确保各 Options 提供完备的 Default 与 with_* 链式构造器       │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│ Phase 4: 文档与 CI 校验闭环                                   │
│  - 更新 docs/api/ARCHITECTURE.md 与 STEGO-API.md             │
│  - 运行 cargo doc --all-features --no-deps (警告清零)         │
│  - 运行 cargo test 与 python scripts/baseline_hash.py --check│
└──────────────────────────────────────────────────────────────┘
```

本方案落地后，`strhide` 的公开接口将实现**表面积减少 80% 以上**，完全消灭内部实现泄露，并为 1.0 版本建立坚固的 SemVer 演进护栏。
