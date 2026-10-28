# `strhide` 数据隐藏库 GUI 层适配深度评估与架构改造方案

> **评估基线**：`strhide v0.7.4`（Rust 2024 Edition，含 2026-10-27 阶段 0–4 架构重组及 2026-10-28 HEVC Scheme C v2 批次 1–5 性能与内存优化）  
> **适用框架**：Tauri v2 / Electron / Wails（跨进程 IPC + Web 前端）、iced / egui / Slint / GPUI（纯 Rust 原生多线程 GUI）、Flutter (`flutter_rust_bridge`)  
> **文档性质**：库使用者视角的架构审计、接口缺口定位与可落地改造指南

## 一、 评估背景与总体结论

站在 `strhide` 库使用者的立场上，如果我们计划为其构建一套生产级图形界面（GUI），首先需要肯定的是：**当前代码库（经历了阶段 0–4 的重构与 2026-10-28 的 HEVC 专项优化）已经具备了良好的分层雏形**。例如：

1. **双域解耦与门面入口**：通过 `facade::StrHide` 绑定编译期 `Dialect` 与 `LocalParams`，并以 `.structure()` 与 `.stego()` 子门面隔离结构域（UBE v2.2 容器注入）与内容域（PNG 空间域 / JPEG DCT 域 / HEVC CABAC 域）。
2. **参数分级（L Class / P Class）**：将仅影响写入端的调优旋钮（`LocalParams`、`EmbedOptions`）与提取端解耦，结合 PNG 64B `FeatureWord`、JPEG 44B 超块、HEVC 32B `HevcSuperblock` 以及加密区内的隐写微头（Micro-header），实现了**提取端除密码外零参数依赖**。
3. **前端就绪层地基**：已初步引入 `core::control`（`Control`、`CancelToken`、`Progress`、`Stage`）、`core::pipeline`（批量路径推导与预检）、`core::media::MediaInfo` 强类型媒体信息及 `errors::ErrorDetail`。

然而，当我们真正动手编写 **Tauri 异步 Command** 或 **iced / egui 后台工作线程** 时，将现有源码（`rust/src/**`）与仓库架构文档（如 `docs/strhide_architecture_and_refactoring_plan.md`、`docs/HEVC-LARGE-CARRIER-MEMORY-PLAN-20261027.md`、`docs/api/ARCHITECTURE.md`）逐行比对，会发现**“架构设计文档承诺的 GUI 就绪能力”与“当前代码实际落地的接口”之间仍存在显著断层**，甚至最新提交中还引入了细分 Feature 编译破损和 CLI/Facade 优化旁路。

### 核心问题全景速查表

| 编号 | 维度 | 问题与缺口摘要 | 精准源码位置 | 影响的 GUI 形态 | 严重度 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1.1** | 编译与门控 | `stego/io.rs` 无条件调用 `hevc::embed_hevc_patches`，未加 `#[cfg(feature = "content-hevc")]`，单开 `content-png`/`jpeg` 编译直接失败；`errors.rs` 中 `serde_json` 门控错写为 `structure` 而非 `structure-base` | `src/stego/io.rs:60`<br>`src/errors.rs:146` | 裁剪 Feature 的轻量级 GUI | **P0 阻断** |
| **1.2** | 能力发现 | `formats::capability::CAPABILITIES` 中内容域引擎列表未随 `content-*` Feature 条件编译，导致裁剪构建下 GUI 能力探测失真 | `src/formats/capability.rs:51-125` | 动态渲染格式支持矩阵的 GUI | **P1 高** |
| **1.3** | 包组织架构 | `oxideav-h265` 与 `rusty_h265` 作为 Git 依赖共存于单一 Crate，阻碍 Workspace 模块化拆分、离线构建与插件化分发 | `rust/Cargo.toml:42, 45` | 全平台打包与 CI/CD | **P2 中** |
| **2.1** | 门面缺口 | 双域聚合诊断（`DualInspectResult` / `DualVerifyResult`）与跨域智能提取（`--auto`）滞留在 `src/cli/`，未下沉至 `facade` | `src/cli/render.rs:107, 145`<br>`src/cli/cmd_diag.rs:45-60`<br>`src/cli/cmd_structure.rs:291` | 所有需要“一键检测/提取”的 GUI | **P0 阻断** |
| **2.2** | 接口割裂 | `StegoFacade::embed_file` 仅返回 `Option<PathBuf>`，丢弃容量与告警；且 `cli/cmd_stego.rs` 绕过 `embed_carrier_file`，导致 2026-10-28 大视频零拷贝补丁优化在 CLI 失效 | `src/facade.rs:342`<br>`src/stego/io.rs:32`<br>`src/cli/cmd_stego.rs:229, 302` | 所有调用文件级嵌入的 GUI 与 CLI | **P0 阻断** |
| **2.3** | 接口不对称 | `StegoFacade` 缺少文件级 `probe_file` / `inspect_file` / `verify_file`，与 `StructureFacade` 的 `_file` / `_bytes` 对称设计脱节 | `src/facade.rs:316-399` | 操作本地文件路径的桌面 GUI | **P1 高** |
| **2.4** | 模块游离 | 黑盒分析 `analysis::scan_file` 游离于 `StrHide` 门面之外，无 `scan_bytes` 内存接口，且 `list` 能力汇总困在 `cli/cmd_diag.rs` | `src/analysis.rs:1951`<br>`src/cli/cmd_diag.rs:542` | 含隐写取证/检测面板的 GUI | **P1 高** |
| **2.5** | 配置合并 | `FileConfig` 虽在 `core::config`，但将其合并为 `EmbedOptions` / `WriteOptions` 的逻辑困在 `cli/helpers.rs` | `src/core/config.rs:51`<br>`src/cli/helpers.rs:236-352` | 支持加载/保存配置的 GUI | **P2 中** |
| **3.1** | 生命周期 | `Dialect` / `StructureProfile` / `StegoProfile` 强制要求 `&'static str`，GUI 无法在运行时从设置界面或系统密钥链动态构造私有方言 | `src/facade.rs:124`<br>`src/structure/params.rs:51`<br>`src/stego/params.rs:815` | 支持自定义私有方言/部署密钥的 GUI | **P0 阻断** |
| **3.2** | 异步与并发 | `WriteOptions<'a>`、`EmbedOptions<'a>`、`Control<'a>` 携带借用生命周期 `'a`，无法直接跨 `tokio::spawn_blocking` 或 UI 后台线程传递 | `src/structure/options.rs:23`<br>`src/stego/options.rs:403`<br>`src/core/control.rs:166` | Tauri 异步命令、iced/egui 异步任务 | **P0 阻断** |
| **4.1** | 进度与取消 | 结构域（`structure`）与分析域（`analysis`）完全未接入 `Control`（违背重构方案 §3.4 / §5.2 承诺），大文件写入/还原无法取消且无进度 | `src/structure/options.rs`<br>`src/structure/engine.rs`<br>`src/analysis.rs` | 处理大型 ZIP/MP4/PE 容器的 GUI | **P0 阻断** |
| **4.2** | 进度粒度 | 内容域生产代码中 `Event::progress` 调用次数为 **0**；HEVC `record_carrier_state` 未传 `Control`，长视频精确探测/解码阶段无法响应取消 | `src/stego/hevc/engine.rs:357, 766`<br>`src/stego/png/engine.rs`<br>`src/stego/jpeg/engine.rs` | 含进度条与取消按钮的 GUI | **P0 阻断** |
| **4.3** | 批量编排 | `core::pipeline::for_each_carrier` 无进度事件、无 `CancelToken`、强行 `println!` 且遇首个错误即中止，无法支撑 GUI 任务队列 | `src/core/pipeline.rs:30-66` | 批量隐写/批量提取任务队列 UI | **P1 高** |
| **5.1** | 序列化缺失 | `StrHideError`、`ErrorDetail`、`TrellisCause`、`Msg`、`Lang` 未实现 `serde::Serialize` / `Deserialize`，无法直接跨越 Tauri IPC 边界 | `src/errors.rs:15, 128, 208`<br>`src/core/i18n/mod.rs:14, 67` | Tauri / Electron / HTTP 服务 | **P0 阻断** |
| **5.2** | IPC 载荷爆炸 | `ReadResult`、`Payload`、`EmbedOutput` 缺 `Serialize`，且未分离“元数据预览”与“大体积字节流”，直接序列化会撑爆 WebView IPC | `src/structure/engine.rs:431`<br>`src/core/payload.rs:49`<br>`src/stego/options.rs:869` | Tauri / WebView 架构 GUI | **P1 高** |
| **5.3** | 反序列化缺失 | 绝大多数 `*Options`、`StegoTuning`、`LocalParams`、`StrategyId`、`FileFormat` 缺少 `serde::Deserialize` | `src/structure/options.rs`<br>`src/stego/options.rs`<br>`src/params.rs` | 前端表单直传 JSON 配置的 GUI | **P1 高** |
| **5.4** | 弱类型元数据 | `InspectResult.metadata` 为 `Option<serde_json::Value>`，且密码错误时塞入 `{"error": "Invalid password"}` 非法结构 | `src/structure/engine.rs:483, 2021` | 强类型前端（TypeScript / Rust UI） | **P1 高** |
| **6.1** | 大文件内存 | `stego/io.rs` 等处仍用 `std::fs::read` 整文件读入堆内存，处理数 GB 4K 视频时产生数 GB 连续分配，缺只读 `mmap` 支持 | `src/stego/io.rs:39, 109`<br>`src/cli/cmd_stego.rs:44, 220` | 处理 >1GB 视频载体的桌面 GUI | **P1 高** |
| **6.2** | 控制台污染 | `stego/jpeg`、`stego/png`、`core/config`、`core/pipeline` 内部残留 `eprintln!` / `println!`，GUI 无法捕获告警；`PayloadSource::Stdin` 易致死锁 | `src/stego/jpeg/engine.rs:185`<br>`src/stego/png/engine.rs:736`<br>`src/core/config.rs:114, 132` | 无终端窗口的桌面 GUI | **P2 中** |
| **7.1** | i18n 线程陷阱 | `core::i18n` 仍用 `thread_local!` 保存语言状态（方案 §5.4 未落地），后台工作线程语言失灵；且错误 `detail` 仍硬编码英文 | `src/core/i18n/mod.rs:45-56`<br>`src/errors.rs:154-205` | 多线程/异步双语 GUI | **P1 高** |
| **7.2** | 视觉预览缺口 | `EmbedOutput` 缺失方案 §3.3 规划的 `QualityStats`（PSNR/修改率），PNG/JPEG 嵌入不返回 `capacity`，且无修改位置热力图/代价图导出接口 | `src/stego/options.rs:869`<br>`src/stego/engine.rs:199, 329` | 专业隐写分析与画质对比视图 | **P2 中** |

## 二、 维度一：Crate 组织、Feature 门控与依赖分发问题

### 1.1 `stego/io.rs` 与 `errors.rs` 的 Feature 条件编译破损（实测 Bug）

**问题诊断**：
在 2026-10-27 阶段 2（批次 5）中，`Cargo.toml` 划分了细粒度的内容域 Feature：`content-png`、`content-jpeg`、`content-hevc`、`content-heif-bridge`。对于许多只需要图片隐写（PNG/JPEG）的轻量级 GUI 工具，开发者会配置：
`strhide = { version = "0.7.4", default-features = false, features = ["structure-base", "content-png", "content-jpeg"] }`
然而，在 2026-10-28 批次 4 的改动中，`rust/src/stego/io.rs:42-83` 的 `embed_carrier_file` 新增了对 MP4 和 Annex-B 的增量补丁快速路径，**却漏加了 `#[cfg(feature = "content-hevc")]` 门控**：

```rust
// rust/src/stego/io.rs:42-69（当前代码）
if matches!(
    format,
    Some(crate::formats::FileFormat::Mp4 | crate::formats::FileFormat::HevcAnnexB)
) {
    // ...
    let direct = || {
        // Bug：当未启用 content-hevc 时，crate::stego::hevc 模块根本不存在（stego/mod.rs:21）！
        crate::stego::hevc::embed_hevc_patches(
            &carrier_bytes,
            eff_payload,
            secret,
            domain,
            dialect.hevc_format(), // Bug：StegoProfile::hevc_format() 也挂在 #[cfg(feature = "content-hevc")] 下！
            options.freshness,
            options.safety,
            &options.control,
        )
    };
```

此外，在 `rust/src/errors.rs:146` 中：
```rust
#[cfg(feature = "structure")]
impl From<serde_json::Error> for StrHideError
```
而在 `Cargo.toml:26` 中，`serde_json` 是由 `structure-base = ["core-io", "dep:serde_json"]` 引入的。若 GUI 仅启用 `structure-base`（排除 `iced-x86` 反汇编依赖），`From<serde_json::Error>` 就会因门控条件不匹配而消失。

**可靠可行的解决办法**：
1. 在 `rust/src/stego/io.rs:42` 补齐 `#[cfg(feature = "content-hevc")]`，或者更彻底地——在 `StegoEngine` trait 上提供默认的 `embed_file` 方法，让 `Mp4Engine` 与 `AnnexBEngine` 内部覆写增量补丁提交逻辑，彻底消除 `stego/io.rs` 中的格式分支判断。
2. 将 `rust/src/errors.rs:146` 的门控修正为 `#[cfg(feature = "structure-base")]`。

```rust
// 修复方案 A：在 rust/src/stego/io.rs 中补齐条件编译门控
#[cfg(feature = "content-hevc")]
if matches!(
    format,
    Some(crate::formats::FileFormat::Mp4 | crate::formats::FileFormat::HevcAnnexB)
) {
    // 仅在启用 content-hevc 时编译增量补丁路径
    // ...
}
```

### 1.2 `formats::capability::CAPABILITIES` 未与编译期 Feature 联动

**问题诊断**：
GUI 启动时需要调用 `formats::capability::CAPABILITIES` 或 `FileFormat::supports_stego()` 来动态生成文件选择器的扩展名过滤器（File Dialog Filter）以及界面上的可用模式开关。
在 `rust/src/formats/capability.rs:110-115` 中，`FileFormat::Pe` 正确地根据 `#[cfg(feature = "structure-pe")]` 裁剪了 `"pe_codebits"` 策略；但同一文件中的 `stego` 字段（第 56、62、74、80、121 行）却完全是硬编码静态切片。如果 GUI 构建时关闭了 `content-hevc`，`FileFormat::Mp4.supports_stego()` 依然返回 `true`，用户选完 MP4 点击嵌入才收到运行时的 `UnsupportedFormat` 报错。

**可靠可行的解决办法**：
在 `rust/src/formats/capability.rs` 中使 `stego` 与 `structure` 数组严格跟随当前激活的 Feature：

```rust
// rust/src/formats/capability.rs 改进方案
pub static CAPABILITIES: &[Capability] = &[
    Capability {
        format: FileFormat::Png,
        #[cfg(feature = "structure-base")]
        structure: &["chunk", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        #[cfg(feature = "content-png")]
        stego: &[StegoKind::PngSpatial],
        #[cfg(not(feature = "content-png"))]
        stego: &[],
        extensions: &["png"],
    },
    Capability {
        format: FileFormat::Heif,
        #[cfg(feature = "structure-base")]
        structure: &["item_hidden", "free_box", "box_uuid", "eof"],
        #[cfg(not(feature = "structure-base"))]
        structure: &[],
        stego: &[
            #[cfg(feature = "content-hevc")]
            StegoKind::HevcCabac,
            #[cfg(feature = "content-heif-bridge")]
            StegoKind::HeifBridge,
        ],
        extensions: &["heic", "heif", "avif"],
    },
    // 其余格式同理按 feature 门控
];
```

### 1.3 单包架构与 Git 依赖对 GUI 工程化的阻碍

**问题诊断**：
`rust/Cargo.toml:42, 45` 直接通过 `git = "https://github.com/mcxiaoke/..."` 引入 `oxideav-h265` 和 `rusty_h265`，且库与 CLI 共处一个 `Cargo.toml`。当为该项目构建 Tauri 或 Rust GUI 时：
- 若将 GUI 放在同一仓库下，最好采用 **Cargo Workspace** 管理；
- 企业内网构建、Linux 发行版打包（Nix / Debian / Flatpak）通常禁止构建期联网拉取 Git 依赖。

**可靠可行的解决办法**：
将 `rust/` 升级为 Cargo Workspace 结构，并将两个自有 H.265 仓库作为 `vendor/` 子模块或 `[patch]` 路径维护：

```toml
# 根目录 Cargo.toml (Workspace 推荐布局)
[workspace]
resolver = "2"
members = [
    "crates/strhide-core",      # 纯核心与协议库（原 rust/src 除 cli 外）
    "crates/strhide-cli",       # 命令行二进制（依赖 strhide-core）
    "crates/strhide-gui-tauri", # 或 strhide-gui-iced，直接依赖 strhide-core
]

[workspace.dependencies]
oxideav-h265 = { path = "vendor/oxideav-h265", version = "0.1.0" }
rusty_h265   = { path = "vendor/rusty_h265", version = "0.1.0" }
```

## 三、 维度二：CLI 与 Library 门面能力割裂——核心业务滞留在 `src/cli/`

在阶段 4 重构中，虽然 `core::pipeline` 下沉了 6 个批量辅助函数，但审计 `rust/src/cli/{cmd_diag,cmd_stego,cmd_structure,helpers,render}.rs` 可以发现，**仍有 5 项对 GUI 至关重要的核心业务逻辑被锁死在 `cli` 模块内部**（且标记为 `pub(crate)` 或与 `println!` 耦合）。

### 2.1 双域联合诊断与跨域自动提取（`--auto`）未下沉至 `StrHide` 门面

**问题诊断**：
在 GUI 中，最符合直觉的交互是：**用户拖入一个文件，GUI 自动显示它是否包含隐藏数据（无论结构域还是内容域），点击“提取”即可自动取出数据**，无需用户先去猜这个 PNG/JPEG/MP4 当初是用 `write`（结构域）还是 `embed`（内容域）写的。
查看源码：
- `DualInspectResult` 与 `DualVerifyResult` 定义在 `rust/src/cli/render.rs:107, 145`，且可见性为 `pub(crate)`；
- 双域 `inspect` 与 `verify` 的编排逻辑写在 `rust/src/cli/cmd_diag.rs:43-65, 214-245`；
- `read` 未命中时自动探测内容域并跳转 `extract`（以及反向跳转）的逻辑写在 `rust/src/cli/cmd_structure.rs:291-330` 和 `rust/src/cli/cmd_stego.rs:445-483`。

如果 GUI 不开启 `cli` Feature，它根本拿不到这些类型和逻辑；即使开启了 `cli` Feature，这些函数也全部直接向 `stdout` 打印文本，返回 `Result<(), StrHideError>`，GUI 完全无法复用！

**可靠可行的解决办法**：
在 `facade.rs` 的 `StrHide` 顶层门面上直接提供跨双域的 `inspect_any`、`verify_any` 与 `extract_any` 方法，并将 `DualInspectResult` / `DualVerifyResult` 提升为 `facade` 的公开强类型结构：

```rust
// 建议新增于 rust/src/facade.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualInspectReport {
    #[cfg(feature = "structure-base")]
    pub structure: Option<crate::structure::InspectResult>,
    #[cfg(feature = "content-base")]
    pub content_stego: Option<crate::stego::StegoHeaderInfo>,
}

impl DualInspectReport {
    pub fn has_any_hidden_data(&self) -> bool {
        let s = {
            #[cfg(feature = "structure-base")]
            { self.structure.as_ref().is_some_and(|r| r.has_hidden_data) }
            #[cfg(not(feature = "structure-base"))]
            { false }
        };
        let c = {
            #[cfg(feature = "content-base")]
            { self.content_stego.as_ref().is_some_and(|r| r.has_hidden_data) }
            #[cfg(not(feature = "content-base"))]
            { false }
        };
        s || c
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchedDomain {
    Structure,
    ContentStego,
}

impl StrHide {
    /// 跨双域统一检查载体（只读），供 GUI 文件拖入时一键获取完整画像
    pub fn inspect_file_any(
        &self,
        carrier: &Path,
        password: Option<&str>,
    ) -> Result<DualInspectReport, StrHideError> {
        #[cfg(feature = "structure-base")]
        let structure = self.structure().inspect_file(carrier, password).ok();

        #[cfg(feature = "content-base")]
        let content_stego = {
            let fmt = std::fs::File::open(carrier)
                .ok()
                .and_then(|mut f| crate::formats::sniff::sniff_stream(&mut f));
            if fmt.is_some_and(|f| f.supports_stego()) {
                std::fs::read(carrier).ok().and_then(|bytes| {
                    let opts = crate::stego::InspectOptions::new()
                        .with_password(password.unwrap_or_default());
                    self.stego().inspect(&bytes, &opts).ok()
                })
            } else {
                None
            }
        };

        Ok(DualInspectReport {
            #[cfg(feature = "structure-base")]
            structure,
            #[cfg(feature = "content-base")]
            content_stego,
        })
    }

    /// 跨双域智能提取：优先尝试结构域（O(1) 定位），未命中时无缝回退内容域提取
    #[cfg(all(feature = "structure-base", feature = "content-base"))]
    pub fn extract_auto_bytes(
        &self,
        carrier: &[u8],
        password: Option<&str>,
        control: crate::core::control::Control<'_>,
    ) -> Result<(MatchedDomain, Payload<'static>), StrHideError> {
        match self.structure().read_bytes(carrier, password) {
            Ok(read_res) => {
                let kind = if read_res.is_file {
                    crate::core::payload::PayloadKind::File
                } else {
                    crate::core::payload::PayloadKind::Text
                };
                let mut payload = Payload::owned(read_res.data).with_kind(kind);
                if !read_res.filename.is_empty() {
                    payload = payload.with_name(read_res.filename);
                }
                Ok((MatchedDomain::Structure, payload))
            }
            Err(StrHideError::NoHiddenData(_) | StrHideError::UnsupportedFormat(_)) => {
                let opts = crate::stego::ExtractOptions::default()
                    .with_password(password.unwrap_or_default())
                    .with_control(control);
                let payload = self.stego().extract(carrier, &opts)?;
                Ok((MatchedDomain::ContentStego, payload))
            }
            Err(e) => Err(e),
        }
    }
}
```

### 2.2 `StegoFacade::embed_file` 返回值残缺，且 CLI 绕过它导致大视频零拷贝优化失效

**问题诊断（重大发现）**：
对比两个子门面的文件写入接口：
- `StructureFacade::write_file` 返回 `Result<WriteResult, StrHideError>`，内含 `carrier`、`format`、`strategy`、`raw_size`、`ube_size`、`is_encrypted`、`backup_file`、`warnings` 等全套结构化信息；
- `StegoFacade::embed_file`（`rust/src/facade.rs:342`）委托给 `stego::io::embed_carrier_file`，却只返回 `Result<Option<PathBuf>, StrHideError>`（仅仅返回了一个可选的 `.bak` 备份路径！）。

这带来了两个严重后果：
1. **GUI 调用 `embed_file` 拿不到任何结果统计**：拿不到 `StegoCapacityInfo`（总槽位数、最大容量、推荐容量、占用百分比）、拿不到 Advisory 安全超限警告（当 `SafetyEnforcement::Advisory` 且载荷超过推荐阈值时），也无法执行 `dry_run`。
2. **CLI 自身为了拿 `capacity` 绕过了 `embed_carrier_file`，导致 2026-10-28 批次 4 的零拷贝补丁优化在 CLI 失效**：
   查看 `rust/src/cli/cmd_stego.rs:220-303`：
   ```rust
   // rust/src/cli/cmd_stego.rs:229-303（当前代码）
   let output = crate::stego::embed_carrier_with_dialect_info(
       &carrier_bytes, &payload, &options, &dialect,
   )?;
   let stego_bytes = output.bytes; // 分配了完整载体副本！
   // ...
   let backup_created =
       crate::structure::commit_carrier_bytes(carrier, &dest, &stego_bytes, backup, true)?;
   ```
   在 2026-10-28 11:04 的 `CHANGES-20261028.md`（批次 4）中，作者专门在 `stego/io.rs::embed_carrier_file` 里为 MP4/HEVC 实现了 `embed_hevc_patches` + `commit_carrier_patches`（免去全尺寸 `Vec<u8>` 拷贝，仅对修改切片 seek 原位覆写）。但因为 `embed_carrier_file` 不返回 `EmbedOutput`（含 `capacity`），`cmd_stego.rs` 根本没有调用它，而是继续调 `embed_carrier_with_dialect_info` + `commit_carrier_bytes`！

**可靠可行的解决办法**：
定义强类型的 `StegoEmbedResult` 与 `StegoWarning`，重构 `stego::io::embed_carrier_file` 使其返回 `Result<StegoEmbedResult, StrHideError>`，并让 CLI 的 `handle_embed` 与 GUI 共同调用这一条路径：

```rust
// 建议定义于 rust/src/stego/options.rs 并由 stego::io::embed_carrier_file 返回
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StegoEmbedResult {
    pub carrier: PathBuf,
    pub output_path: PathBuf,
    pub format: FileFormat,
    pub payload_bytes: usize,
    pub carrier_before_bytes: u64,
    pub carrier_after_bytes: u64,
    pub backup_file: Option<PathBuf>,
    pub capacity: Option<StegoCapacityInfo>,
    pub warnings: Vec<StegoWarning>,
    pub dry_run: bool,
}
```
在 `embed_carrier_file` 内部统一处理：
- 若为 MP4 / Annex-B（且非 `dry_run`），走 `embed_hevc_patches` + `commit_carrier_patches` 零拷贝路径，同时保留其返回的 `_capacity` 填入 `StegoEmbedResult.capacity`；
- 若 `options.safety.enforcement == SafetyEnforcement::Advisory` 且 `payload.len() > cap.recommended_max_bytes`，自动生成 `StegoWarning::SafetyThresholdExceeded` 放入 `warnings`；
- 这样 CLI 和 GUI 只需调 `engine.stego().embed_file(...)` 即可同时享受到**零拷贝低内存**和**完整结构化报表**。

### 2.3 `StegoFacade` 缺少文件级 `probe_file` / `inspect_file` / `verify_file`

**问题诊断**：
在桌面 GUI 中，用户通过文件对话框或拖拽传入的都是 `PathBuf`。`StructureFacade` 提供了完整的 `write_file` / `read_file` / `restore_file` / `inspect_file` / `verify_file`；而 `StegoFacade`（`rust/src/facade.rs:316-399`）除了 `embed_file` 和 `extract_file` 外，`probe`、`inspect`、`verify` 全部只接受 `carrier: &[u8]`。
这迫使 GUI 调用方自己去写 `std::fs::read(&path)`，而且一旦未来底层优化为只读 `mmap` 或流式头部读取（例如 `inspect` 只需读文件头或前几个 NAL 切片），接收 `&[u8]` 的签名会逼迫调用方把几个 GB 的视频全量读进内存。

**可靠可行的解决办法**：
在 `StegoFacade` 与 `stego::io` 中补齐 `probe_file`、`inspect_file`、`verify_file` 三个文件级入口：

```rust
// 建议补充于 rust/src/facade.rs 的 impl StegoFacade<'_>
pub fn probe_file(
    &self,
    carrier: &Path,
    options: &ProbeOptions<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    crate::stego::io::probe_carrier_file(carrier, options, &self.engine.dialect().stego)
}

pub fn inspect_file(
    &self,
    carrier: &Path,
    options: &InspectOptions<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    crate::stego::io::inspect_carrier_file(carrier, options, &self.engine.dialect().stego)
}

pub fn verify_file(
    &self,
    carrier: &Path,
    options: &VerifyOptions<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    crate::stego::io::verify_carrier_file(carrier, options, &self.engine.dialect().stego)
}
```

### 2.4 `analysis` 域与能力列表未接入 `StrHide` 门面，且缺少 `scan_bytes`

**问题诊断**：
1. `analysis::scan_file`（`rust/src/analysis.rs:1951`）是独立自由函数，在 `StrHide` 上没有 `.analysis()` 子门面，且**只有 `scan_file(&Path)`，没有 `scan_bytes(&[u8])`**。当 GUI 需要对内存中刚生成的隐写产物（例如在 `dry_run` 预览对比模式或 WebAssembly / Tauri 内存缓冲中）直接跑一次黑盒隐写分析评分（`risk_score`、`detectors`）以向用户展示“隐写前 vs 隐写后抗检测指标对比”时，必须先写临时文件再调 `scan_file`！
2. `analysis.rs:44` 硬编码引用了 `STANDARD_HEADER_MAGIC`：如果用户使用自定义 `Dialect`（自定义 `MagicPair`），`StrHide` 门面本可将该私有方言的魔数传给 `analysis` 以检测自有方言信封，但独立函数 `scan_file` 无法感知 `StrHide` 的 `Dialect`。

**可靠可行的解决办法**：
在 `analysis.rs` 中将核心扫描逻辑拆分为 `scan_bytes(data: &[u8], label: &str, dialect: Option<&Dialect>) -> Result<ScanReport, StrHideError>` 与 `scan_file`，并在 `StrHide` 上暴露 `.analysis()` 子门面（提供 `scan_file` 与 `scan_bytes`）。

### 2.5 配置合并逻辑（`FileConfig` -> `*Options`）困在 `cli/helpers.rs`

**问题诊断**：
`core::config::FileConfig` 已经下沉到 `core`，但将 `FileConfig` 的字段（如 `strategy`、`stealth`、`preserve_time`、`backup`、`stego.safety`、`stego.enforce_safety`、`stego.algorithm`）转换为 `WriteOptions` 或 `EmbedOptions` / `ProbeOptions` 的函数 `stego_tuning`、`stego_safety`、`stego_options` 却全部写在 `rust/src/cli/helpers.rs:236-352` 中，且绑定了 `clap` 的 `StegoTuningArgs`。GUI 读取 `strhide.toml` 后，无法直接由 `FileConfig` 派生出默认的 `WriteOptions` 和 `EmbedOptions`。

**可靠可行的解决办法**：
在 `core::config::FileConfig`（或各域 Options）上直接提供 `to_write_options()`、`to_stego_safety()`、`resolve_stego_tuning(format: Option<FileFormat>)` 方法，使配置语义真正下沉到 `core`，CLI 与 GUI 共用同一套解析与默认值派生。

## 四、 维度三：借用生命周期（`'a` / `'static`）与异步 GUI / 多线程任务模型的冲突

这是使用 Rust 编写 GUI（无论是 `iced`、`egui`、`Slint` 还是 `Tauri`）时**在编译期最容易碰壁**的设计问题。

### 3.1 `Dialect` / `StructureProfile` / `StegoProfile` 强制 `'static` 生命周期，阻断 GUI 运行时配置私有方言

**问题诊断**：
查看 `rust/src/facade.rs:124`、`rust/src/structure/params.rs:51`、`rust/src/stego/params.rs:815`：
```rust
pub struct StructureProfile {
    pub default_secret: Option<&'static str>,
    pub stealth_domain: Option<&'static [u8]>,
    pub magic: Option<MagicPair>,
}
```
在 `docs/api/ARCHITECTURE.md` §6.2 中解释了使用 `&'static str` 的原因：为了让 `const MY_DIALECT: Dialect = Dialect::new().with_default_secret("...");` 能在编译期通过 `const fn` 求值（因为 Rust 编译器对 `const fn` 中包含 `Drop` 的类型如 `Cow<'static, str>` 重新赋值会报 E0493）。
但是，**在 GUI 场景下，私有方言参数往往不是编译期写死的常量**！用户会在 GUI 的“首选项 / 团队安全配置”弹窗中输入：
- 团队默认密钥（`default_secret`）
- 隐写 HKDF 隔离域（`stego_domain` / `stealth_domain`）
- 甚至从本地配置文件或系统密钥链（Keychain）动态加载。

因为字段类型是 `&'static str`，且 `StrHide` 是 `#[derive(Clone, Copy)]`，GUI 从输入框拿到 `String` 后，除非调用 `Box::leak(input.into_boxed_str())` 造成永久内存泄漏，否则**根本无法构造 `Dialect`**！

**可靠可行的解决办法**：
如何在**既100%保留 `const fn` 编译期零开销构造与 `Copy` 语义**，又**允许 GUI 在运行时安全持有动态方言**？有两条成熟路径：

**方案一（零破坏扩展）：引入 `ArcStr` / 内部驻留或提供 `OwnedDialect` 包装器**
保留 `StructureProfile` / `StegoProfile` / `Dialect` 的 `&'static` 与 `const fn` 不变，新增一个运行时管理容器 `DynamicDialect`（或使用全局去重驻留池 `InternedSecret`），避免重复 `Box::leak`：

```rust
use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

static INTERNED_STRINGS: LazyLock<Mutex<HashSet<&'static str>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// 安全驻留运行时配置字符串（相同字符串全局只分配一次，不会随调用无限泄漏）
pub fn intern_dialect_str(s: &str) -> &'static str {
    let mut pool = INTERNED_STRINGS.lock().unwrap();
    if let Some(&existing) = pool.get(s) {
        return existing;
    }
    let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
    pool.insert(leaked);
    leaked
}
```
并在 `Dialect` 上提供非 `const` 的运行时便捷构造函数：
```rust
impl Dialect {
    /// 供 GUI / 服务端在运行时从动态配置构造方言（内部自动去重驻留）
    pub fn from_runtime_secret(secret: &str) -> Self {
        Self::new().with_default_secret(intern_dialect_str(secret))
    }
}
```
这一方案**不需要改动全库任何一处函数签名**，`StrHide` 依然是 `Copy`，既存の `const ENGINE: StrHide = ...` 100% 兼容，同时彻底解决了 GUI 动态修改方言时重复泄漏内存的问题！

### 3.2 `*Options<'a>` 与 `Control<'a>` 的借用生命周期阻碍跨线程 `spawn`

**问题诊断**：
在 GUI 架构中，任何文件读写或隐写计算都**绝不能在 UI 主线程执行**，必须派发到后台线程（如 `tokio::task::spawn_blocking`、`std::thread::spawn`、`rayon::spawn`）。这些跨线程闭包全部要求 `F: FnOnce() -> R + Send + 'static`。
然而当前库的所有操作选项都带有借用生命周期 `'a`：
- `WriteOptions<'a>`：借用 `output_path: Option<&'a Path>`、`password: Option<&'a str>`、`strategy: &'a str`
- `ReadOptions<'a>` / `RestoreOptions<'a>`：借用 `output_path`、`password`
- `EmbedOptions<'a>` / `ProbeOptions<'a>` / `ExtractOptions<'a>`：借用 `password: Option<&'a str>`、`domain: Option<&'a str>`、`control: Control<'a>`
- `Control<'a>`：借用 `progress: &'a dyn Progress`、`cancel: Option<&'a CancelToken>`

这意味着 GUI 无法在 UI 线程组装好一个 `EmbedOptions` 或 `WriteOptions` 然后 `move` 进后台任务队列（Job Queue）中排队执行！

**可靠可行的解决办法**：
1. **改造 `Control` 为支持 `Arc` 共享的 `ControlHandle`（或让 `Control<'a>` 兼容 `Arc<dyn Progress>`）**：
   在 GUI 中，`CancelToken` 和 `Progress` 监听器天然需要被 UI 主线程（点击取消按钮、读取进度状态）和后台 Worker 线程同时持有。

```rust
// 建议在 rust/src/core/control.rs 中增加 Owned 控制句柄，与借用版 Control<'a> 零成本互转
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct TaskControl {
    pub progress: Option<Arc<dyn Progress>>,
    pub cancel: Arc<CancelToken>,
}

impl TaskControl {
    pub fn new(progress: impl Progress + 'static) -> Self {
        Self {
            progress: Some(Arc::new(progress)),
            cancel: Arc::new(CancelToken::new()),
        }
    }

    pub fn cancel_token(&self) -> Arc<CancelToken> {
        Arc::clone(&self.cancel)
    }

    /// 借用为底层引擎所需的 Control<'_>
    pub fn as_control(&self) -> Control<'_> {
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
2. **为 `*Options` 提供 `'static` Owned 变体或 `Cow<'a, ...>` 升级**：
   将 `WriteOptions<'a>`、`EmbedOptions<'a>` 等内部的 `&'a str` / `&'a Path` 改为 `Cow<'a, str>` / `Cow<'a, Path>`（或者提供实现了 `Serialize + Deserialize + Clone + Send + 'static` 的 `WriteRequest` / `EmbedRequest` DTO 并实现 `.as_options(&self) -> EmbedOptions<'_>`）。这样：
   - 现有传入 `&str` / `&Path` 的调用代码通过 `.into()` 或保持不变；
   - Tauri / GUI 任务队列可以直接存储和传递 `'static` 的请求对象。

## 五、 维度四：长耗时任务的进度汇报（Progress）与协作式取消（Cancel）断层

隐写与大文件容器处理是典型的 CPU + I/O 密集型任务。虽然 `core/control.rs` 定义了 `Stage`、`Event`、`Progress` 和 `CancelToken`，但深入审查三个引擎与文件提交层，可以发现**进度汇报和取消检查存在多处严重断层**。

### 4.1 结构域（`structure`）与分析域（`analysis`）完全未接入 `Control`

**问题诊断**：
在 `docs/strhide_architecture_and_refactoring_plan.md` §3.4 与 §5.2 中，作者明确规划：
> “`WriteOptions` / 内容域 options 带 `control` 与 `pool`……结构域的 `WriteOptions` 同步加 `control`。”

但核查当前实际代码（`rust/src/structure/options.rs` 与 `rust/src/structure/engine.rs`）：
- `WriteOptions`、`ReadOptions`、`RestoreOptions` 中**完全没有 `control` 字段**！
- `structure/engine.rs` 的 `write_core`、`read_core`、`remove_core`、`inspect_core`、`verify_core` 中**没有任何一处调用 `Control`**！
- 当用户在 GUI 中使用结构域向一个 2 GB 的 MP4 视频或大型 ZIP 注入一个 500 MB 的文件载荷时：
  1. 引擎对 2 GB 原始载体做流式 SHA-256（耗时数秒）；
  2. 对 500 MB 载荷做 Deflate 压缩（耗时十余秒）；
  3. 按 2 MiB 分块做 250 次 AES-256-GCM 加密；
  4. 将 2.5 GB 数据写入 `.strhide.tmp` 并创建 2 GB 的 `.bak` 备份文件。
  在整个过程中，**GUI 进度条是 0%，且用户点击“取消”按钮完全无效**！
- 同样地，`analysis::scan_file` 在扫描最多 64 MiB 的图像并解码像素跑 Chi2 / SPA / RS 统计与 JPEG 盲校准时，也没有 `Control` 参数，批量扫描文件夹时无法中断单个慢文件。

**可靠可行的解决办法**：
1. 在 `WriteOptions<'a>`、`ReadOptions<'a>`、`RestoreOptions<'a>` 中补齐 `pub control: Control<'a>` 字段。
2. 在 `crypto.rs` 的流式分块函数 `encrypt_stream_to_chunks`、`decrypt_stream_from_chunks`、`compress_stream` 以及 `structure/engine.rs` 的 `copy_range` 流式拷贝循环中传入 `&Control<'_>`，每处理一个 Chunk（2 MiB）调用一次 `control.check()?` 并触发 `control.report(Event::progress(Stage::Encode, done_bytes, Some(total_bytes)))`。

```rust
// 示例：在 structure/engine.rs 流式拷贝与加密分块中埋入进度与取消检查
pub(crate) fn copy_stream_with_progress(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    mut remaining: u64,
    stage: Stage,
    control: &Control<'_>,
) -> Result<u64, StrHideError> {
    let total = remaining;
    let mut done = 0u64;
    let mut buf = vec![0u8; 256 * 1024]; // 256 KiB 缓冲
    control.stage_sized(stage, total);
    while remaining > 0 {
        control.check()?; // 每次循环响应取消信号，TmpGuard 自动 Drop 清理临时文件
        let to_read = (remaining as usize).min(buf.len());
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        remaining -= n as u64;
        done += n as u64;
        control.report(Event::progress(stage, done, Some(total)));
    }
    Ok(done)
}
```

### 4.2 内容域（`stego`）生产代码中 `Event::progress` 调用数为 0，且 HEVC 解码循环无法取消

**问题诊断（源码实测核对）**：
对整个 `rust/src/` 执行全局搜索 `control\.(report|stage|check)`，结果令人意外：
1. **细粒度进度 `Event::progress(stage, done, total)` 和 `control.stage_sized` 在整个生产代码中调用次数为 0**（仅在 `core/control.rs:276-277` 的单元测试中调用过）！
   - 在 `CHANGES-20261027.md`（14:38:05，阶段 2 批次 3）中曾记录“HEVC Encode 按 slice 携带进度”；
   - 但在 `CHANGES-20261028.md`（10:58:06，批次 3）将 `reencode_slice` 改为 `rayon` 多核并行 `into_par_iter()` 时，原有的逐 slice 进度上报被删除了，且连 `control.stage(Stage::Encode)` 也在 `embed_hevc_patches_with_factor` 中遗漏了！
2. **HEVC 最耗时的 `record_carrier_state` 和 `probe_hevc_pool` 完全没有传入 `Control`**：
   查看 `rust/src/stego/hevc/engine.rs:355-369` 与 `765-772`：
   ```rust
   // rust/src/stego/hevc/engine.rs:355-369
   pub fn probe_hevc_capacity_info(
       carrier: &[u8],
       fmt: &HevcFormatProfile,
       safety_level: SafetyLevel,
       exact: bool,
       control: &Control<'_>,
   ) -> Result<StegoCapacityInfo, StrHideError> {
       let kind = sniff_hevc_carrier(carrier)...;
       let pool = probe_hevc_pool(carrier, kind, exact)?; // <-- 内部耗时最高达 168 秒，却没传 control！
       control.check()?; // <-- 只能等 168 秒全片扫描完才检查取消！
       build_hevc_capacity_info(carrier, kind, fmt, &pool, safety_level)
   }
   ```
   同样在 `embed_hevc_patches_with_factor`（第 766 行）、`extract_hevc`（第 1430 行）、`verify_hevc`（第 1742 行）中，`record_carrier_state` 均未接收 `control: &Control<'_>`。当用户对一部 24 分钟 1080p 视频执行精确容量探测（`exact = true`，34,454 个切片，耗时 168.7 秒）或大载荷嵌入时，在漫长的 `Decode` 阶段内，**既没有任何切片进度更新，也无法响应用户的取消操作**！
3. **`extract`、`probe`、`inspect`、`verify` 四个操作在 PNG/JPEG/HEVC 中均只调了 `control.check()`，从未调用 `control.stage(...)`**：GUI 在执行提取或校验时，连当前处于哪个阶段（`Decode` / `CostMap` / `Verify`）都收不到。

**可靠可行的解决办法**：
1. 为 `record_carrier_state` 和 `probe_hevc_pool` 增加 `control: &Control<'_>` 参数。在遍历 `candidates`（NAL 切片循环）时，每解码一个（或每 16 个）切片调用一次 `control.check()?`，并调用 `control.report(Event::progress(Stage::Decode, idx as u64, Some(total_slices as u64)))`。
2. 在 `rayon` 并行重编码（如 HEVC 的 `reencode_slice` 和 PNG 的并行 Deflate 行压缩）中，使用 `AtomicU64` 计数器配合 `control.check()?` 实现无锁并行进度上报与即时取消短路：

```rust
// HEVC 并行切片重编码中的进度上报与取消短路标准写法
use std::sync::atomic::{AtomicU64, Ordering};

let total_slices = touched_slice_indices.len() as u64;
control.stage_sized(Stage::Encode, total_slices);
let completed = AtomicU64::new(0);

let reencoded: Result<Vec<_>, StrHideError> = touched_slice_indices
    .par_iter()
    .map(|&slice_idx| {
        control.check()?; // Rayon 工作线程发现取消立即短路返回 Err(StrHideError::Cancelled)
        let res = reencode_slice(
            slice_idx,
            &slice_contexts[slice_idx],
            &flips_per_slice[slice_idx],
            &bad_substreams,
            &replay_ok,
        );
        let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
        control.report(Event::progress(Stage::Encode, done, Some(total_slices)));
        Ok(res)
    })
    .collect();
```

### 4.3 `core::pipeline::for_each_carrier` 无法满足 GUI 批量任务队列需求

**问题诊断**：
`rust/src/core/pipeline.rs:30-66` 的 `for_each_carrier` 虽然从 `cli.rs` 下沉到了 `core`，但它的实现仍然是纯 CLI 思维：
- 直接调用 `println!` / `eprintln!` 打印进度总结；
- 遇到第一个失败文件立即 `return Err(e)` 中断整个批次，且只返回 `Result<(), StrHideError>`，GUI 拿不到“哪些文件成功了、产出路径是什么、哪个文件因什么错误失败了”的结构化列表；
- 不支持 `CancelToken` 在文件之间中止批处理，也不支持上报“当前第 `i / N` 个文件”的批次进度。

**可靠可行的解决办法**：
在 `core::pipeline` 中新增面向 GUI / 服务端的结构化批处理执行器 `run_batch`：

```rust
// 建议新增于 rust/src/core/pipeline.rs
use serde::{Deserialize, Serialize};
use crate::core::control::CancelToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum BatchFailurePolicy {
    /// 遇到首个失败立即停止后续文件（CLI 默认行为）
    #[default]
    StopOnFirstError,
    /// 记录错误并继续处理剩余文件（GUI 批量队列常用行为）
    ContinueOnError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchItemOutcome<T> {
    pub carrier: PathBuf,
    pub result: Result<T, crate::errors::ErrorDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSummary<T> {
    pub outcomes: Vec<BatchItemOutcome<T>>,
    pub succeeded: usize,
    pub failed: usize,
    pub cancelled: bool,
}
```

## 六、 维度五：跨进程 IPC / 前端序列化（Serde）与类型契约缺口

如果使用 **Tauri**、**Electron** 或 **Wails** 开发 GUI，Rust 后端与前端（TypeScript）之间通过 JSON IPC 通信；即使使用纯 Rust GUI（如 `iced` / `egui`），保存任务历史记录、导出诊断报告也需要 `serde::Serialize` 与 `serde::Deserialize`。

### 5.1 错误体系（`StrHideError` / `ErrorDetail` / `Msg`）缺失 `Serialize`

**问题诊断**：
在 Tauri 中，命令函数签名为：
`#[tauri::command] async fn write_carrier_cmd(...) -> Result<WriteResult, ErrorDetail>`
Tauri 要求返回值的 `Ok` 和 `Err` 类型都必须实现 `serde::Serialize`。
然而检查 `rust/src/errors.rs` 与 `rust/src/core/i18n/mod.rs`：
- `StrHideError`（`errors.rs:15`）：未实现 `Serialize`；
- `ErrorDetail`（`errors.rs:208`）：仅有 `#[derive(Debug, Clone, PartialEq, Eq)]`，**未实现 `Serialize` / `Deserialize`**；
- `TrellisCause`（`errors.rs:128`）：**未实现 `Serialize` / `Deserialize`**；
- `Msg`（`core/i18n/mod.rs:67`）与 `Lang`（`core/i18n/mod.rs:14`）：**未实现 `Serialize` / `Deserialize`**。

此外，前端不仅需要渲染好的错误文本，还需要**机器可读的错误判别码（Error Kind/Code）**，以便在 UI 上做出精准交互反应（例如：收到 `code == "password_with_hint"` 时自动弹出密码输入框并展示 `hint`；收到 `code == "safety_threshold"` 时弹出“是否切换为 Balanced 档位或强制嵌入”的确认框；收到 `code == "cancelled"` 时静默重置按钮状态而不弹错误 Toast）。

**可靠可行的解决办法**：
为 `ErrorDetail` 增加机器可读的 `ErrorKind` 枚举并实现完整的 `Serialize` / `Deserialize`：

```rust
// rust/src/errors.rs 改造方案
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Io,
    CorruptedData,
    PasswordRequiredOrWrong,
    PasswordWithHint,
    TrellisInfeasible,
    Rejection,
    SafetyThreshold,
    RestoreMismatch,
    UnsupportedFormat,
    NoHiddenData,
    UnsupportedVersion,
    Cancelled,
    General,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// 机器可读的错误分类码，供 GUI 分支处理（如弹窗要求密码、静默处理取消等）
    pub kind: ErrorKind,
    /// 本地化分类前缀标签（根据传入语言渲染）
    pub category_label: Option<String>,
    /// 详细原因描述
    pub detail: String,
    /// 当 kind == PasswordWithHint 时携带的密码提示
    pub hint: Option<String>,
}
```

### 5.2 `ReadResult`、`Payload`、`EmbedOutput` 缺 `Serialize`，且未隔离大字节数组与元数据

**问题诊断**：
1. `ReadResult`（`structure/engine.rs:431`）、`Payload`（`core/payload.rs:49`）、`EmbedOutput`（`stego/options.rs:869`）均未派生 `serde::Serialize`。
2. 在 `ReadResult` 中，`pub data: Vec<u8>` 与 `is_file`、`filename`、`raw_size`、`written_file` 绑在同一个结构体里。
   - 当用户通过 `ReadOptions { output_path: Some(path), .. }` 将载荷提取到磁盘文件时，`structure/engine.rs` **依然把全部 `data: Vec<u8>` 保留在 `ReadResult.data` 中返回**！
   - 如果 Tauri 后端将 `ReadResult` 直接序列化返回给前端，一个 100 MB 的提取文件不仅已经在磁盘写了一份，还会在 IPC 通道中被 `serde_json` 序列化成长度一亿的 JSON 整数数组 `[80, 75, 3, 4, ...]`，直接导致前端 WebView 卡死或内存溢出！

**可靠可行的解决办法**：
1. 当 `ReadOptions.output_path` 为 `Some(_)` 时，落盘成功后不再把巨型 `Vec<u8>` 塞进返回给 UI 的摘要里，或者在 `ReadResult` 上提供 `.into_summary() -> ReadSummary`（不含 `data: Vec<u8>`，但增加 `text_preview: Option<String>` 供小文本载荷直接在 UI 预览）。
2. 为 `ReadSummary`、`StegoEmbedResult` 实现 `Serialize` / `Deserialize`。

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadSummary {
    pub carrier: PathBuf,
    pub is_file: bool,
    pub is_encrypted: bool,
    pub filename: String,
    pub raw_size: u64,
    pub written_file: Option<PathBuf>,
    /// 当 !is_file 且 UTF-8 文本长度 <= 64 KiB 时内联返回，供 GUI 直接展示文本内容
    pub inline_text: Option<String>,
}
```

### 5.3 公开参数与枚举缺失 `serde::Deserialize`（以及 TS 类型生成支持）

**问题诊断**：
当前库中，虽然 `WriteResult`、`InspectResult`、`VerifyResult`、`RemoveResult`、`StrategyId`、`FileFormat`、`Warning` 实现了 `Serialize`，但它们**全部没有实现 `Deserialize`**；同时，输入侧的 `LocalParams`、`CompressionStrategy`、`RejectionPolicy`、`StegoTuning`、`SpatialAlgorithm`、`JpegAlgorithm`、`HevcMode`、`Freshness` **既没有 `Serialize` 也没有 `Deserialize`**。
在 GUI 中，前端往往需要将用户的参数配置保存为预设（Preset JSON）或通过 IPC 发送给 Rust 后端。缺失 `Deserialize` 会迫使 GUI 层为上述十几个类型逐一手写 DTO 转换代码。

**可靠可行的解决办法**：
- 为 `FileFormat`、`StrategyId`、`Warning`、`LocalParams`、`CompressionStrategy`、`RejectionPolicy`、`HevcMode`、`Freshness` 及各 `*Result` 统一补齐 `#[derive(Serialize, Deserialize)]`。
- 对于包含 `Custom(Arc<dyn ...CostModel>)` 的 `SpatialAlgorithm` 和 `JpegAlgorithm`，通过自定义 `Serialize` / `Deserialize` 将 `"hill"` / `"suniward"` / `"uerd"` / `"juniward"` 与枚举变体映射（反序列化遇到未知值报错）。
- 可选增加 `ts-rs` 或 `specta` Feature 门控（`#[cfg_attr(feature = "specta", derive(specta::Type))]`），一键生成前端 TypeScript 类型定义。

### 5.4 `InspectResult.metadata` 的弱类型与错误注入反模式

**问题诊断**：
查看 `rust/src/structure/engine.rs:483` 与 `1995-2025`：
```rust
// rust/src/structure/engine.rs:483
pub metadata: Option<serde_json::Value>,

// rust/src/structure/engine.rs:2021
meta_val = Some(serde_json::json!({"error": "Invalid password"}));
```
当 `inspect_carrier` 成功解密元数据时，`metadata` 的内容是序列化后的 `CarrierMetadata { filename, raw_size, raw_sha256, created_at }`；而当未提供密码或密码错误无法解密元数据时，代码却往 `metadata` 字段塞了一个 `{"error": "Invalid password"}` 的 JSON 对象！
这是一种典型的弱类型反模式：GUI 前端拿到 `InspectResult` 后，无法直接访问 `res.metadata.filename`，还必须先判断 `serde_json::Value` 里有没有 `"error"` 键。而且结构域仅仅为了这一个字段，就被迫在 `structure-base` 中引入了整个 `serde_json` 依赖（见 `docs/strhide_architecture_and_refactoring_plan.md` §十 勘误表第 1 条）。

**可靠可行的解决办法**：
将 `CarrierMetadata` 完善为公开强类型结构，并用强类型枚举 `MetadataInspection`（或 `Option<CarrierMetadata>` + `metadata_error: Option<String>`）替代 `Option<serde_json::Value>`：

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarrierMetadata {
    pub filename: String,
    pub raw_size: u64,
    pub raw_sha256: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetadataInspection {
    Decrypted(CarrierMetadata),
    Locked { error: String },
}
```
注：使用 `#[serde(untagged)]` 甚至能保持现有 CLI `--json` 输出的 JSON 结构 100% 向后兼容，同时让 Rust GUI 直接按强类型模式匹配，并且彻底移除了 `structure-base` 对 `serde_json` 的强依赖！

## 七、 维度六：大文件内存模型、交互式 I/O 陷阱与库内控制台污染

### 6.1 内容域文件级接口仍使用 `std::fs::read` 全量读入堆内存

**问题诊断**：
在 `docs/HEVC-LARGE-CARRIER-MEMORY-PLAN-20261027.md` §2 与 §6（P2）中，作者已经深刻指出了大视频载体的内存瓶颈，并在 2026-10-28 批次 1–4 中将槽位池压缩到 16 B、引入了 Scheme C v2 流式分窗（`StopCondition::MinSlots(2048)` / `TargetSlots`）以及 `commit_carrier_patches` 原位切片覆写。
然而，查看 `rust/src/stego/io.rs:39, 109`：
```rust
pub fn embed_carrier_file(...) -> Result<Option<PathBuf>, StrHideError> {
    let carrier_bytes = std::fs::read(carrier_path)?; // <-- 一次性将整个文件读入堆内存 Vec<u8>！
```
以及 `extract_carrier_file_payload`：
```rust
pub fn extract_carrier_file_payload(...) -> Result<Payload<'static>, StrHideError> {
    let carrier_bytes = std::fs::read(carrier_path)?; // <-- 即使只读前 2 个切片（20ms 早退），也先把整个数 GB 的 MP4 读进堆内存！
```
试想：用户在 GUI 中拖入一个 **4 GB 的 4K HEVC 视频**，仅仅想做一次快速 `inspect` 或输入密码做 `extract`（底层算法只需解码前 2048 个槽位，耗时 <20 ms），却因为外层调用了 `std::fs::read`，不得不先花几秒钟从磁盘读取 4 GB 数据并分配 4 GB 堆内存！

**可靠可行的解决办法**：
在 `core-io` 中引入轻量级的只读内存映射（`memmap2::Mmap`）或封装 `CarrierBuffer`：
- `Mmap` 实现了 `Deref<Target = [u8]>`，因此现有的 `StegoEngine` trait 签名（接收 `carrier: &[u8]`）**一行都不用改**！
- 当 `stego::io` 打开一个 4 GB 的 MP4 文件并映射为 `&mmap[..]` 传给 `inspect_carrier`、`extract_carrier` 或 `embed_hevc_patches` 时，操作系统只会按需分页加载被访问到的前几个切片（仅几 MB 物理内存开销），错密早退真正做到全链路 20 ms、零大内存分配！
- 在 `embed_carrier_file` 中，当 `embed_hevc_patches` 计算完补丁后，只需 `drop(mmap)` 释放文件映射句柄，再调用 `commit_carrier_patches` 原位写入即可（Windows 下必须在写文件前 `drop` 只读 `Mmap` 句柄以避免文件锁冲突）。

```rust
// rust/src/stego/io.rs 使用只读 mmap 替代 std::fs::read 的零侵入方案
pub fn extract_carrier_file_payload(
    carrier_path: &Path,
    options: &ExtractOptions<'_>,
    dialect: &StegoProfile,
) -> Result<Payload<'static>, StrHideError> {
    let file = std::fs::File::open(carrier_path)?;
    // 对于空文件直接报错，非空文件使用只读 mmap 按需分页，无需改动下游 &[u8] 签名
    let metadata = file.metadata()?;
    if metadata.len() == 0 {
        return Err(StrHideError::UnsupportedFormat("Carrier file is empty".into()));
    }
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    crate::stego::extract_carrier_payload(&mmap, options, dialect)
}
```

### 6.2 库代码内部残留 `eprintln!` / `println!` 与 `Stdin` 阻塞隐患

**问题诊断**：
在非 `cli` 模块中检索标准输出宏，发现以下残留：
1. `rust/src/stego/jpeg/engine.rs:185`：`eprintln!("[stego] {msg}");`
2. `rust/src/stego/png/engine.rs:736`：`eprintln!("[png] {msg}");`
3. `rust/src/core/config.rs:114, 132`：遇到未知配置键或本地目录配置含密码时，直接 `eprintln!` 打印警告，返回值 `Result<FileConfig, StrHideError>` 中不包含警告列表。
4. `rust/src/core/pipeline.rs:45, 47, 62`：`for_each_carrier` 直接 `println!` / `eprintln!`。
5. `rust/src/structure/engine.rs:304`：`PayloadSource::Stdin` 在 GUI 应用（Windows `#![windows_subsystem = "windows"]`）中若被误用，会因无标准输入流或阻塞式等待 EOF 导致后台线程挂死。

**可靠可行的解决办法**：
- 将 `core::config::load` 改为返回 `Result<(FileConfig, Vec<ConfigWarning>), StrHideError>`（或保留 `load` 并新增 `load_with_warnings`），让 GUI 可以将配置警告渲染在界面通知栏中；
- 移除 `stego/jpeg/engine.rs:185` 与 `stego/png/engine.rs:736` 中的裸 `eprintln!`（可改用 `log` / `tracing` 宏或通过 `Control` 事件通道传递诊断消息）；
- 将 `PayloadSource::Stdin` 门控在 `#[cfg(feature = "cli")]` 下，或注明仅限 CLI 使用。

### 6.3 内容域与结构域在“需要密码 vs 无隐藏数据”上的交互差异

**问题诊断**：
在 GUI 中，当用户拖入一个文件但尚未输入密码时：
- **结构域（非 Stealth）**：Header 魔数固定，且 `FLAG_ENCRYPTED` 明文可见（经固定掩码解开）。因此 `inspect_file(path, None)` 可以明确告诉 GUI：`has_hidden_data = true, is_encrypted = Some(true), password_hint = Some("...")`！GUI 可以立即在界面上展示一个漂亮的“🔒 该文件包含加密隐藏数据（提示：xxx），请输入密码解锁”状态卡片。
- **结构域（Stealth 模式）**：魔数由密码派生，无密码时 `has_hidden_data = false`，但 `HostAdapter::suspicious_structures` 会检测出可疑容器结构。然而在当前代码中（`structure/engine.rs:450, 578`），**`InspectResult` 结构体中竟然没有 `suspicious_hints: Vec<String>` 字段**！`suspicious_structures` 只在 `write`（作为 `Warning`）和 `read` 失败（拼入 `NoHiddenData` 的英文错误字符串中）时被调用，而在 `inspect_carrier` 中完全没有返回给调用者！
- **内容域（`stego`）**：无密码时默认使用 `PUBLIC_DEFAULT_SECRET` 尝试定位和校验 Header。如果该图片实际上是用密码 `"123456"` 嵌入的，无密码调用 `stego().inspect(&bytes, &InspectOptions::new())` 会返回 `has_hidden_data = false`。

**可靠可行的解决办法**：
1. **在 `structure::InspectResult` 中增加 `pub suspicious_hints: Vec<String>` 字段**：当 `has_hidden_data == false` 时，调用 `adapter.suspicious_structures(carrier)` 填入该字段。这样 GUI 在用户拖入 Stealth 载体时，可以立即提示：“未检测到标准信封，但发现可疑容器结构（`private PNG chunk 'prIv'`），若为隐身模式请提供密码重试”！
2. **在 GUI 状态机设计中明确引导**：对于支持内容域的格式（PNG/JPEG/HEIF/MP4），当结构域与默认密钥内容域均返回 `has_hidden_data == false` 时，GUI 界面应显示：“未检出公开信封（若使用了密码保护或隐身模式，请输入密码后重新检测）”。

## 八、 维度七：多语言（i18n）线程局部陷阱与 GUI 视觉预览/对比能力缺口

### 7.1 `core::i18n` 仍使用 `thread_local!` 状态，且底层诊断文本未纳入本地化

**问题诊断**：
在 `docs/strhide_architecture_and_refactoring_plan.md` §5.4 中，作者已经准确识别出了问题：
> “`i18n/mod.rs:49` 是 `thread_local! { static CURRENT: Cell<Lang> }`，`set_lang` 只影响当前线程。GUI 在 UI 线程设中文，worker 线程渲染仍是英文。改成显式参数：`RenderCtx { lang: Lang }`……”

然而核查当前代码 `rust/src/core/i18n/mod.rs:45-56`：
```rust
thread_local! {
    static CURRENT: Cell<Lang> = const { Cell::new(Lang::En) };
}
pub fn set_lang(lang: Lang) { CURRENT.with(|c| c.set(lang)); }
pub fn lang() -> Lang { CURRENT.with(Cell::get) }
```
**这一计划项在代码中尚未落地**！
1. 如果把 `CURRENT` 从 `thread_local! { Cell<Lang> }` 改为进程级原子变量 `static CURRENT: AtomicU8 = AtomicU8::new(0);`，仅需 5 行代码改动，就能让 UI 主线程调用 `i18n::set_lang(Lang::Zh)` 后**瞬间对所有 Tokio / Rayon / 后台工作线程全局生效**，同时还保留显式传入 `lang: Lang` 的 `ErrorDetail::render(lang)` 接口。
2. 此外，目前 `ErrorDetail::render(Lang::Zh)`（`errors.rs:224`）只翻译了分类前缀（如 `[ERROR] 安全策略拦截: `），后面的 `detail` 依然是引擎内部拼接的英文句子（如 `"Payload (9216 bytes) exceeds safety threshold (4788 bytes)..."`）。对于面向终端用户的中文 GUI，这种“半中半英”的报错体验不佳。

**可靠可行的解决办法**：
1. 立即将 `core/i18n/mod.rs` 中的 `thread_local!` 替换为 `AtomicU8` 全局原子变量（消除跨线程语言不一致问题）：
```rust
// rust/src/core/i18n/mod.rs 修复方案
use std::sync::atomic::{AtomicU8, Ordering};

static CURRENT_LANG: AtomicU8 = AtomicU8::new(0); // 0 = En, 1 = Zh

pub fn set_lang(lang: Lang) {
    let val = match lang {
        Lang::En => 0,
        Lang::Zh => 1,
    };
    CURRENT_LANG.store(val, Ordering::Relaxed);
}

pub fn lang() -> Lang {
    match CURRENT_LANG.load(Ordering::Relaxed) {
        1 => Lang::Zh,
        _ => Lang::En,
    }
}
```
2. 为常见高频用户错误（如密码错误、容量超限、文件已存在拒绝覆盖、签名文件拒绝修改、格式不支持）在 `ErrorDetail` 中提供结构化参数或直接通过 `t!(Msg::...)` 生成双语消息。

### 7.2 缺乏 GUI 专属的“隐写质量指标、容量回传与修改热力图（Diff Preview）”接口

**问题诊断**：
在开发隐写软件的 GUI 时，与命令行最大的体验差异在于**可视化反馈**：
1. **`EmbedOutput` 在 PNG 和 JPEG 引擎中不返回 `capacity`，且缺少 `QualityStats`**：
   查看 `rust/src/stego/engine.rs:199`（`PngEngine::embed`）与 `329`（`JpegEngine::embed`），两者均返回 `Ok(EmbedOutput::bytes_only(bytes))`，即 `capacity` 为 `None`（只有 `HeifEngine`/`Mp4Engine`/`AnnexBEngine` 填充了 `capacity`）。这导致 CLI（`cmd_stego.rs:240`）和 GUI 在嵌入 PNG/JPEG 后如果想知道容量占用率，不得不**重新解码一遍图片去跑 `probe_carrier_capacity`**，白白浪费一倍的 CPU 时间！而实际上 `embed_png` 和 `embed_jpeg` 在内部已经算完了 `available_slots` 和 `total_elements`，顺手构造 `StegoCapacityInfo` 成本为零。
2. **缺少画质与修改统计（`QualityStats`）**：
   重构方案 §3.3 曾设计 `pub quality: Option<QualityStats>`，但未在代码中实现。用户在 GUI 完成嵌入后，非常希望直观看到：**本次嵌入共修改了多少个像素/DCT系数/CABAC符号位（Modified Elements Count）、修改率（Change Rate %）、PSNR（dB）**。
3. **缺少可视化对比/热力图生成辅助接口（Visual Diff / Cost Map Preview）**：
   GUI 往往提供“原图 vs 隐写图”分屏对比，以及“修改点放大镜（将 ±1 修改的像素或 DCT 块高亮为红/绿点）”和“纹理代价分布热力图（Cost Map Grayscale/Heatmap）”。目前 `png::engine::decode_png` 虽在专家面公开，但代价图计算与修改位置集合被封闭在 `embed_png` / `embed_jpeg` 函数内部，GUI 无法获取。

**可靠可行的解决办法**：
1. 在 `EmbedOutput` 中补齐 `pub stats: Option<EmbedStats>`，并在 `embed_png`、`embed_jpeg`、`embed_hevc` 内部直接返回已计算的 `StegoCapacityInfo` 与实际修改统计：
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedStats {
    /// 实际发生 ±1 或 bit 翻转的槽位数量
    pub modified_slots: usize,
    /// 候选池总槽位数
    pub available_slots: usize,
    /// 实际修改比例 (modified_slots / available_slots)
    pub modification_ratio: f64,
    /// 空间域/像素域 PSNR (dB)，仅当可直接由修改量推算时提供（如 PNG ±1 修改：MSE = modified_slots / total_elements）
    pub estimated_psnr_db: Option<f64>,
}
```
注：对于 PNG 空间域，每个被修改的通道值严格变化 `±1`（误差平方为 `1`），因此**根本不需要重新解码对比原图与隐写图**，直接由 `MSE = modified_slots as f64 / total_elements as f64` 即可在 `O(1)` 时间内精确算出 `PSNR = 10.0 * log10(255.0^2 / MSE)`！
2. 在专家面（`stego::png` / `stego::jpeg`）提供一个可选的诊断预览函数 `generate_diff_heatmap_png(orig: &[u8], stego: &[u8]) -> Result<Vec<u8>, StrHideError>`，直接输出一张标注了修改位置的高亮 PNG 字节流，供 GUI 前端通过 `Blob URL` 或 `egui::ColorImage` 直接渲染。

## 九、 分阶段改造实施路线图（Actionable Checklist）

为了让上述改进平稳落地且不破坏现有 728 项单元与集成测试及 58 例字节级基线（`baseline_hash.py`），建议按以下四个小批次推进：

### 阶段 P0：编译修复与零成本补齐（预计 0.5–1 人日）
- [ ] **修复 `stego/io.rs` 编译门控**：为 `embed_carrier_file` 中的 MP4/Annex-B 增量补丁分支加上 `#[cfg(feature = "content-hevc")]`，确保 `--no-default-features --features content-png` 与 `content-jpeg` 恢复编译通过。
- [ ] **修复 `errors.rs` 门控**：将 `impl From<serde_json::Error> for StrHideError` 的门控由 `#[cfg(feature = "structure")]` 修正为 `#[cfg(feature = "structure-base")]`。
- [ ] **修复 `formats/capability.rs` 条件编译**：使 `CAPABILITIES` 表中的 `structure` 与 `stego` 数组严格跟随 `structure-*` 和 `content-*` Feature。
- [ ] **修复 `core/i18n/mod.rs` 跨线程语言状态**：将 `thread_local! { static CURRENT: Cell<Lang> }` 替换为 `AtomicU8`，使 GUI 主线程切换语言对所有工作线程立即生效。

### 阶段 P1：Serde 全面补齐与门面能力收口（预计 1.5–2 人日）
- [ ] **错误与结果类型 Serde 化**：为 `ErrorDetail`（含新增 `ErrorKind`）、`TrellisCause`、`Msg`、`Lang`、`ReadSummary`、`EmbedOutput`、`FileFormat`、`StrategyId`、`Warning`、`LocalParams`、`StegoTuning` 等统一派生 `Serialize` 与 `Deserialize`。
- [ ] **强类型化 `InspectResult.metadata`**：引入 `MetadataInspection` 替换 `Option<serde_json::Value>`，并在 `structure::InspectResult` 中增加 `pub suspicious_hints: Vec<String>`。
- [ ] **升级 `StegoFacade::embed_file` 与 `stego::io`**：返回包含 `capacity`、`warnings`、`backup_file` 的 `StegoEmbedResult`；让 `cli/cmd_stego.rs` 改调 `embed_carrier_file`，激活 CLI 下的大视频零拷贝补丁优化；补齐 `probe_file`、`inspect_file`、`verify_file`。
- [ ] **下沉双域能力至 `StrHide` 门面**：在 `StrHide` 上新增 `inspect_file_any`、`verify_file_any`、`extract_auto_file` / `extract_auto_bytes` 以及 `.analysis()` 子门面（含 `scan_file` 与 `scan_bytes`）。
- [ ] **下沉配置合并方法**：在 `core::config::FileConfig` 上提供生成默认 `WriteOptions` / `EmbedOptions` 的方法，并收集配置警告而非直接 `eprintln!`。

### 阶段 P2：异步/多线程所有权改造与全链路进度/取消（预计 2–3 人日）
- [ ] **运行时 `Dialect` 支持**：在 `facade` 中提供 `intern_dialect_str` 与 `Dialect::from_runtime_secret`，解决 `&'static str` 无法接收 GUI 运行时设置的问题。
- [ ] **引入 `TaskControl` 与 Owned 请求结构**：支持 `Arc<dyn Progress>` 与 `Arc<CancelToken>`，方便跨 `tokio::spawn_blocking` 或 UI 线程传递。
- [ ] **补齐结构域与分析域 `Control`**：在 `WriteOptions`、`ReadOptions`、`RestoreOptions` 及 `analysis::scan_*` 中接入 `Control`，在流式哈希、压缩、分块加解密与文件拷贝循环中埋入 `control.check()?` 与 `Event::progress`。
- [ ] **补齐内容域细粒度进度**：为 HEVC `record_carrier_state` 与 `probe_hevc_pool` 传入 `Control`，在切片解码循环与 Rayon 并行重编码中上报 `Event::progress(stage, done, Some(total))`。
- [ ] **升级 `core::pipeline`**：提供支持 `CancelToken`、进度回调与 `BatchFailurePolicy` 的结构化批量执行器。

### 阶段 P3：大文件只读 `mmap` 与 GUI 视觉预览增强（预计 1.5–2 人日）
- [ ] **`stego/io.rs` 引入只读 `mmap`**：使用 `memmap2::Mmap` 替代 `std::fs::read`，消除多 GB 视频在 `probe_file` / `inspect_file` / `extract_file` / `embed_file` 时的整文件堆内存分配。
- [ ] **补齐 `EmbedOutput` 的 `capacity` 与 `EmbedStats`**：在 PNG/JPEG 嵌入时一并返回容量信息与修改槽位数、推算 PSNR（dB）。
- [ ] **新增修改点热力图/代价图预览接口**：供 GUI 渲染隐写前后像素/DCT 块差异视图。

## 十、 GUI 层对接架构参考模板（Tauri v2 & Rust Native）

完成上述改造后，无论是使用 **Tauri v2** 还是 **iced / egui**，GUI 层都只需编写极薄的胶水代码即可接入 `strhide`：

### 10.1 Tauri v2 异步 Command 与 Channel 实时进度流对接示例

```rust
// src-tauri/src/commands.rs
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{ipc::Channel, State};
use strhide::prelude::*;
use strhide::core::control::{CancelToken, Control, Event, Progress};
use strhide::errors::ErrorDetail;

/// 全局应用状态：持有可动态切换方言的引擎与当前运行任务的取消令牌
pub struct AppState {
    pub engine: Mutex<StrHide>,
    pub active_cancel: Mutex<Option<Arc<CancelToken>>>,
}

/// 将 strhide 的 Progress 事件实时桥接到 Tauri v2 的前端 IPC Channel
struct TauriProgressBridge {
    channel: Channel<GuiProgressEvent>,
}

#[derive(Clone, serde::Serialize)]
pub struct GuiProgressEvent {
    pub stage: &'static str,
    pub done: u64,
    pub total: Option<u64>,
}

impl Progress for TauriProgressBridge {
    fn report(&self, event: Event) {
        let _ = self.channel.send(GuiProgressEvent {
            stage: event.stage.as_str(),
            done: event.done,
            total: event.total,
        });
    }
}

#[tauri::command]
pub async fn embed_file_cmd(
    state: State<'_, AppState>,
    carrier_path: PathBuf,
    output_path: Option<PathBuf>,
    payload_text: Option<String>,
    payload_file: Option<PathBuf>,
    password: Option<String>,
    safety_level: String,
    enforce_safety: bool,
    backup: bool,
    on_progress: Channel<GuiProgressEvent>,
) -> Result<strhide::stego::StegoEmbedResult, ErrorDetail> {
    let engine = *state.engine.lock().unwrap();
    let cancel_token = Arc::new(CancelToken::new());
    *state.active_cancel.lock().unwrap() = Some(Arc::clone(&cancel_token));

    // 将重型 CPU/IO 隐写任务派发至 Tokio blocking 线程池，绝不阻塞 UI 主线程
    let res = tauri::async_runtime::spawn_blocking(move || {
        let bridge = TauriProgressBridge { channel: on_progress };
        let control = Control {
            progress: &bridge,
            cancel: Some(&cancel_token),
        };

        let payload = if let Some(file_path) = payload_file {
            let name = file_path.file_name().and_then(|s| s.to_str()).unwrap_or("payload.bin").to_string();
            let bytes = std::fs::read(&file_path)?;
            Payload::owned_file(name, bytes)
        } else if let Some(text) = payload_text {
            Payload::owned(text.into_bytes()).with_kind(strhide::PayloadKind::Text)
        } else {
            return Err(StrHideError::General("No payload provided".into()));
        };

        let level = SafetyLevel::parse(&safety_level).unwrap_or(SafetyLevel::High);
        let enforcement = if enforce_safety {
            SafetyEnforcement::Enforced
        } else {
            SafetyEnforcement::Advisory
        };

        let opts = EmbedOptions::default()
            .with_password(password.as_deref().unwrap_or_default())
            .with_safety(level, enforcement)
            .with_control(control);

        engine.stego().embed_file(
            &carrier_path,
            output_path.as_deref(),
            &payload,
            &opts,
            backup,
        )
    })
    .await
    .map_err(|e| StrHideError::General(format!("Task panic: {e}")).detail_i18n())?;

    *state.active_cancel.lock().unwrap() = None;
    res.map_err(|e| e.detail_i18n())
}

#[tauri::command]
pub fn cancel_current_task(state: State<'_, AppState>) {
    if let Some(token) = state.active_cancel.lock().unwrap().as_ref() {
        token.cancel();
    }
}
```

### 10.2 纯 Rust GUI（`egui` / `iced`）非阻塞 Worker 与受控 Rayon 线程池配置

在纯 Rust GUI 中，为避免 PNG 并行 Deflate 或 HEVC 多核重编码占满全部 CPU 核心导致 GUI 掉帧（低于 60 FPS），应当在 GUI 初始化时构造一个预留 1–2 个物理核心给 UI 渲染线程的专用 `rayon::ThreadPool`，并通过 `EmbedOptions::with_pool` 注入：

```rust
use std::sync::Arc;

/// 初始化供隐写引擎使用的后台计算线程池，预留至少 1 个核心给 GUI 渲染线程
pub fn create_gui_stego_pool() -> Arc<rayon::ThreadPool> {
    let total_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let worker_threads = total_threads.saturating_sub(1).max(1);

    Arc::new(
        rayon::ThreadPoolBuilder::new()
            .num_threads(worker_threads)
            .thread_name(|idx| format!("strhide-worker-{idx}"))
            .build()
            .expect("failed to build stego rayon pool"),
    )
}
```
