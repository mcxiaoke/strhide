# `strhide` 桌面端 GUI（方案一：Tauri v2 + React + TypeScript）详细架构与实施计划

> **2026-10-30 界面改版说明**：GUI 已改为顶部四页签 `隐写 / 隐藏 / 提取 / 扫描`，各页签的输入文件与参数完全独立，支持多文件批处理并自动跳过不支持的格式；三级校验与无损还原、反隐写取证两个工作台已从 GUI 移除，“自适应容量安全水位尺”改为安全等级下拉框。本文 §1.1 拓扑图、§2 工作台划分（`InspectExtractView` / `VerifyRestoreView` / `ForensicsBatchView` / `CapacityMeter` / `TuningDrawer`）属于改版前的设计与实施计划，保留作历史记录；当前实现见 `gui/src/App.tsx`、`gui/src/views/*`、`gui/src/hooks/*`，变更摘要见 `docs/CHANGES-20261030.md`。

> **文档定位**：本文档是 `strhide` 桌面客户端（基于 **[Tauri v2](https://v2.tauri.app/) + React 19 + TypeScript + Tailwind CSS + shadcn/ui + Zustand**）的工程级架构设计与分阶段实施蓝图。可作为直接交付给研发人员或 AI 编码 Agent 的开发任务书。
>
> **前置基线**：`strhide` 核心库已完成 Stage A–E 全部 GUI 就绪度改造（`StrHide` 统一门面、`inspect_any` / `verify_any` / `smart_extract`、MP4 流式有界诊断、零拷贝原位补丁、`ProgressWriter` + `CancelToken`、结构化 `ErrorDetail`/`ErrorKind`、原子级 `i18n`、无打印批处理 `core::batch::run_batch` 及 `EmbedStats` 修改率统计）。
>
> **v2 修订（对照 Stage E 代码逐项核实）**：① 取消应用内媒体预览，改为调用系统默认程序打开文件 / 定位所在目录，`protocol-asset`、预览句柄守卫、分屏对比全部移除（理由见 §3.2）；② 修正与代码不符的 IPC 契约（`StrategyId` 形状、进度阶段小写枚举、`DualInspect.media_info`、缺失的 `VerifyResult`/`WriteResult`/`ScanReport`/`Capability` 等类型）；③ CSP 补 `connect-src ipc:`，否则 `invoke` 全部被拦；④ 结构域写命令补 `check_overwrite` 守卫，避免静默覆盖用户文件；⑤ `risk_score` 实为 0..100；⑥ 明确 Rayon 池、`ProbeOptions` 映射、i18n 渲染边界与裸 Annex-B 的双域检视兜底。

---

## 一、 总体架构与工程目录拓扑

### 1.1 系统分层架构图

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    前端视图层 (WebView: React 19 + TypeScript)               │
│  ┌──────────────────┬──────────────────┬──────────────────┬───────────────┐ │
│  │ 🔍 检视与智能提取 │ 🛡️ 隐藏与自适应嵌入│ ✅ 三级校验与还原 │ 🔬 取证与批处理│ │
│  │ Inspect & Extract│   Hide & Embed   │ Verify & Restore │ Scan & Batch  │ │
│  └────────┬─────────┴────────┬─────────┴────────┬─────────┴───────┬───────┘ │
│           │                  │                  │                 │         │
│  ┌────────▼──────────────────▼──────────────────▼─────────────────▼───────┐ │
│  │                      状态与句柄管理层 (Zustand Stores)                   │ │
│  │  • useWorkspaceStore (当前载体路径、双域检视缓存、系统打开/定位动作)       │ │
│  │  • useTaskStore      (进度条 Stage/Done/Total、耗时计时器、取消控制)      │ │
│  │  • ErrorInterceptor  (按 ErrorKind 路由覆盖确认框/密码框/安全档位建议)    │ │
│  └────────┬───────────────────────────────────────────────────────▲───────┘ │
└───────────┼───────────────────────────────────────────────────────┼─────────┘
            │ invoke("cmd_name", args)      Channel<ProgressEvent>  │
            ▼ (JSON-over-IPC)               (60fps 节流流式推送)     │
┌───────────┼───────────────────────────────────────────────────────┼─────────┐
│           ▼        Tauri v2 宿主桥接层 (gui/src-tauri)             │         │
│  ┌────────────────────────────────────────────────────────────────┴───────┐ │
│  │ • GuiState { engine: StrHide, tasks: HashMap<String, Arc<CancelToken>>,│ │
│  │              pool: Arc<rayon::ThreadPool> (预留 1-2 核保 UI 流畅) }     │ │
│  │ • spawn_blocking + catch_unwind(AssertUnwindSafe) 崩溃隔离与临时文件守卫 │ │
│  └────────────────────────────────┬───────────────────────────────────────┘ │
│                                   │ 进程内 Rust 强类型直调                  │
│  ┌────────────────────────────────▼───────────────────────────────────────┐ │
│  │                 strhide 核心库 (rust/src, Stage A-E 完备)               │ │
│  │   StrHide::structure() | StrHide::stego() | StrHide::analysis()        │ │
│  │   core::batch::run_batch | formats::capability::CAPABILITIES           │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 仓库目录拓扑规划

为了保持现有 `rust/` 目录（核心库 + CLI）完全干净且独立，建议在仓库根目录下新建 `gui/` 目录存放 Tauri v2 工程，`gui/src-tauri/Cargo.toml` 通过相对路径 `path = "../../rust"` 依赖 `strhide` 库：

```text
strhide/
├── rust/                           # 现有 strhide 核心库与 CLI（零侵入）
│   ├── Cargo.toml
│   └── src/
└── gui/                            # 新增：Tauri v2 桌面端工程根目録
    ├── package.json                # 前端依赖 (React 19, Zustand, Tailwind, Lucide, shadcn, @tauri-apps/plugin-opener)
    ├── vite.config.ts
    ├── tsconfig.json
    ├── index.html
    ├── src/                        # 前端 TypeScript 源码
    │   ├── main.tsx
    │   ├── App.tsx                 # 顶层布局（侧边导航 + 全局拖拽区 + 底部任务栏）
    │   ├── types/
    │   │   └── strhide.ts          # 与 Rust 1:1 对应的强类型 DTO 定义
    │   ├── api/
    │   │   └── commands.ts         # Tauri invoke 与 Channel 强类型封装
    │   ├── store/
    │   │   ├── workspaceStore.ts   # 载体状态、DualInspect 缓存、系统打开/定位动作
    │   │   ├── taskStore.ts        # 任务进度流、取消令牌触发、批处理队列状态
    │   │   └── settingsStore.ts    # 语言 (en/zh)、主题、默认安全档位与备份策略
    │   ├── lib/
    │   │   └── errorHandler.ts     # 基于 ErrorKind 的结构化错误弹窗与恢复动作分发
    │   ├── components/
    │   │   ├── stage/
    │   │   │   ├── CarrierDropzone.tsx   # Tauri 原生拖拽接入与文件选择
    │   │   │   └── CarrierSummary.tsx    # 载体元信息卡（格式/尺寸/时长/SHA-256）+ 系统打开/定位
    │   │   ├── hide/
    │   │   │   ├── CapacityMeter.tsx     # Paranoid / High / Balanced 三档水位尺
    │   │   │   └── TuningDrawer.tsx      # 结构域 StrategyChoice 与内容域算法高级参数
    │   │   └── common/
    │   │       ├── ProgressBarOverlay.tsx # 阶段名 (read/decode/cost_map/solve/encode/write) + 取消按钮
    │   │       └── OverwriteDialog.tsx    # ErrorKind::AlreadyExists 触发的覆盖确认框
    │   └── views/
    │       ├── InspectExtractView.tsx    # 工作台 1：双域检视 + 智能提取 (smart_extract)
    │       ├── HideEmbedView.tsx         # 工作台 2：结构域注入 / 内容域隐写 + 修改率统计
    │       ├── VerifyRestoreView.tsx     # 工作台 3：三级完整性步进校验 + 100% 字节级还原
    │       └── ForensicsBatchView.tsx    # 工作台 4：黑盒反隐写雷达/表格 + 多文件批处理队列
    └── src-tauri/                  # Tauri v2 Rust 宿主层
        ├── Cargo.toml              # 依赖 strhide (features = ["structure", "content", "analysis"])
        ├── build.rs
        ├── tauri.conf.json         # 窗口配置、CSP（含 connect-src ipc:）
        ├── capabilities/
        │   └── default.json        # Tauri v2 ACL 权限声明 (core, dialog, opener)
        └── src/
            ├── main.rs
            ├── lib.rs              # 注册 State、Plugins 与 14 个核心 Commands
            ├── state.rs            # GuiState、任务取消表、受控 Rayon 线程池、节流 ChannelProgress
            └── commands/
                ├── mod.rs
                ├── diag.rs         # inspect_carrier, verify_carrier, scan_carrier, get_capabilities
                ├── structure.rs    # write_structure_file, read_structure_file, restore_structure_file
                ├── stego.rs        # probe_stego_capacity, embed_stego_file, extract_stego_file, smart_extract
                └── batch.rs        # run_batch_job, cancel_task, set_ui_language
```

### 1.3 `gui/src-tauri/Cargo.toml` 关键配置（含 `panic = "unwind"` 铁律）

由于 `rust/Cargo.toml` 为 CLI 配置了 `panic = "abort"`，而 GUI 宿主必须确保任何底层异常都不会直接杀死窗口进程或跳过 `TmpGuard::drop`（防止残留 `.strhide.tmp`），因此 `gui/src-tauri/Cargo.toml` **必须显式声明 `panic = "unwind"`**，并剔除 CLI 专用依赖：

```toml
[package]
name = "strhide-gui"
version = "0.7.4"
edition = "2024"

[lib]
name = "strhide_gui_lib"
crate-type = ["staticlib", "cdylib", "rlib"]

[build-dependencies]
tauri-build = { version = "2.0", features = [] }

[dependencies]
# 仅开启核心三大特性，不启用 cli 特性（省去 clap / rpassword 等终端依赖）
strhide = { path = "../../rust", default-features = false, features = [
    "structure",
    "content",
    "analysis",
] }
tauri = { version = "2", features = [] }
tauri-plugin-dialog = "2"
tauri-plugin-opener = "2"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rayon = "1.10"

# 关键防线：覆盖 CLI 的 abort，配合 catch_unwind 确保临时文件 RAII 守卫 100% 触发
[profile.release]
panic = "unwind"
opt-level = 3
lto = "thin"
strip = true
```

---

## 二、 Tauri v2 后端（`src-tauri`）核心设计与 IPC 契约

### 2.1 全局状态、CPU 护栏与 60fps 节流进度桥接（`src-tauri/src/state.rs`）

内容域（PNG/JPEG/HEVC）计算代价图与算术编码时会吃满 Rayon 线程池。如果吃满全部逻辑核心，WebView 渲染线程会出现掉帧；同时 `ProgressWriter` 在高速 NVMe 盘上可能每毫秒触发一次回调。因此在 `state.rs` 中设计两道保护：
1. **Rayon 线程池预留 1–2 个逻辑核心**：保证 UI 动画与窗口渲染永不卡顿；
2. **`ChannelProgress` 内置 16ms（60fps）时间窗节流**：阶段切换（`done == 0`）和完成事件（`done == total`）立即发送，中间高频进度事件至少间隔 16ms 才跨 IPC 推送一次。

> **线程池必须显式接线**：`run_cancellable_task` 只是把 `Arc<ThreadPool>` 交给 worker，库不会自己切过去。内容域命令要把 `pool` 填进 `EmbedOptions.pool` / `ProbeOptions.pool` / `ExtractOptions.pool`（三者都有该字段），结构域命令则用 `pool.install(|| ...)` 包一层。漏掉这一步等于没有 CPU 护栏。

```rust
// gui/src-tauri/src/state.rs
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;
use tauri::ipc::Channel;

use strhide::core::control::{CancelToken, Control, Event, Progress};
use strhide::core::i18n::{self, RenderCtx};
use strhide::errors::{ErrorDetail, StrHideError};
use strhide::facade::StrHide;

pub struct GuiState {
    pub engine: StrHide,
    pub tasks: Mutex<HashMap<String, Arc<CancelToken>>>,
    pub pool: Arc<rayon::ThreadPool>,
}

impl Default for GuiState {
    fn default() -> Self {
        // 预留 1~2 个 CPU 核心给操作系统与 WebView 渲染线程，防止大图/视频隐写时界面卡顿
        let total_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let worker_threads = total_cores.saturating_sub(1).max(1);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(worker_threads)
            .thread_name(|i| format!("strhide-worker-{i}"))
            .build()
            .expect("failed to build strhide rayon pool");

        Self {
            engine: StrHide::new(),
            tasks: Mutex::new(HashMap::new()),
            pool: Arc::new(pool),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    pub task_id: String,
    pub stage: &'static str,
    pub done: u64,
    pub total: Option<u64>,
    pub percent: Option<f32>,
}

/// 带 60fps (16ms) 节流保护的 Tauri Channel 进度转发器
pub struct ThrottledChannelProgress {
    pub task_id: String,
    pub channel: Channel<ProgressEvent>,
    pub start_instant: Instant,
    pub last_emit_ms: AtomicU64,
    pub last_stage: Mutex<&'static str>,
}

impl ThrottledChannelProgress {
    pub fn new(task_id: String, channel: Channel<ProgressEvent>) -> Self {
        Self {
            task_id,
            channel,
            start_instant: Instant::now(),
            last_emit_ms: AtomicU64::new(0),
            last_stage: Mutex::new(""),
        }
    }
}

impl Progress for ThrottledChannelProgress {
    fn report(&self, ev: Event) {
        let stage_str = ev.stage.as_str();
        let is_boundary = ev.done == 0 || ev.total.is_some_and(|t| ev.done >= t);
        let now_ms = self.start_instant.elapsed().as_millis() as u64;

        let mut prev_stage = self.last_stage.lock().unwrap();
        let stage_changed = *prev_stage != stage_str;
        if stage_changed {
            *prev_stage = stage_str;
        }
        drop(prev_stage);

        if !is_boundary && !stage_changed {
            let last = self.last_emit_ms.load(Ordering::Relaxed);
            if now_ms.saturating_sub(last) < 16 {
                return;
            }
        }
        self.last_emit_ms.store(now_ms, Ordering::Relaxed);

        let percent = ev.total.and_then(|t| {
            if t > 0 {
                Some(((ev.done as f64 / t as f64) * 100.0).clamp(0.0, 100.0) as f32)
            } else {
                None
            }
        });

        let _ = self.channel.send(ProgressEvent {
            task_id: self.task_id.clone(),
            stage: stage_str,
            done: ev.done,
            total: ev.total,
            percent,
        });
    }
}

/// 统一可取消后台任务执行器（自动登记/清理 CancelToken + catch_unwind 崩溃防护 + i18n 错误转换）
pub async fn run_cancellable_task<T, F>(
    state: &GuiState,
    task_id: String,
    on_progress: Channel<ProgressEvent>,
    worker: F,
) -> Result<T, ErrorDetail>
where
    T: Send + 'static,
    F: FnOnce(StrHide, Arc<rayon::ThreadPool>, Control<'_>, Arc<CancelToken>) -> Result<T, StrHideError>
        + Send
        + 'static,
{
    let engine = state.engine;
    let pool = Arc::clone(&state.pool);
    let token = Arc::new(CancelToken::new());
    state
        .tasks
        .lock()
        .unwrap()
        .insert(task_id.clone(), Arc::clone(&token));

    let task_id_clone = task_id.clone();
    let token_clone = Arc::clone(&token);

    let join_res = tauri::async_runtime::spawn_blocking(move || {
        let reporter = ThrottledChannelProgress::new(task_id_clone, on_progress);
        let unwind_res = catch_unwind(AssertUnwindSafe(|| {
            let ctrl = Control {
                progress: &reporter,
                cancel: Some(&token_clone),
            };
            worker(engine, pool, ctrl, Arc::clone(&token_clone))
        }));

        match unwind_res {
            Ok(res) => res,
            Err(_) => Err(StrHideError::General(
                "Internal engine panic caught safely at GUI worker boundary".into(),
            )),
        }
    })
    .await;

    state.tasks.lock().unwrap().remove(&task_id);

    let ctx = RenderCtx::new(i18n::lang());
    match join_res {
        Ok(Ok(val)) => Ok(val),
        Ok(Err(err)) => Err(err.detail_i18n_with_ctx(ctx)),
        Err(join_err) => {
            Err(StrHideError::General(format!("Worker thread join error: {join_err}"))
                .detail_i18n_with_ctx(ctx))
        }
    }
}
```

> **两点实现注意**：① `last_emit_ms` 的读-改-写没有加锁，Rayon 多线程同时 `report()` 时可能双发（对进度条无害，但别在测试里断言"绝不重复"）；想把 G1 的节流单测写准，就把"该不该发"抽成一个纯函数，再用 `Channel::new(|body| ...)`（tauri 2.x 提供）把消息收进 `Arc<Mutex<Vec<_>>>` 断言时间窗与边界事件。② 前端 `invoke` 的 future 被丢弃时后台任务仍会跑完，`cancel_task_cmd` 只是置位令牌，不要假设 drop 等于取消。

### 2.2 后端 14 个核心 Tauri Commands 完整契约表

| 序号 | Command 函数名 | 所属模块 | 输入参数（DTO） | 返回类型（`Result<T, ErrorDetail>`） | 底层调用的 `strhide` API |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `get_capabilities_cmd` | `diag.rs` | 无 | `Vec<Capability>`（`strhide::formats::capability::Capability`） | `formats::capability::CAPABILITIES` |
| **2** | `set_ui_language_cmd` | `batch.rs` | `lang: Lang` (`"en"` \| `"zh"`) | `Lang` | `core::i18n::set_lang(lang)` |
| **3** | `inspect_carrier_cmd` | `diag.rs` | `path: PathBuf`, `password: Option<String>`, `domain: Option<String>` | `DualInspect` | `engine.inspect_any(&path, &DualOptions)` |
| **4** | `verify_carrier_cmd` | `diag.rs` | `path: PathBuf`, `password: Option<String>`, `domain: Option<String>` | `DualVerifyDto` | `engine.verify_any`（或双域 `verify_file`） |
| **5** | `scan_carrier_cmd` | `diag.rs` | `path: PathBuf` | `ScanReport` (`AnalysisReport`) | `engine.analysis().scan_file(&path)` |
| **6** | `smart_extract_cmd` | `stego.rs` | `task_id`, `path`, `output_path: Option<PathBuf>`, `password`, `domain`, `prefer: Option<Domain>`, `overwrite: bool`, `on_progress` | `SmartExtractSummaryDto`（含 `source: Domain`, `also_present: Option<Domain>`, `summary: ReadSummary`） | `engine.smart_extract(&path, &SmartExtractOptions)` |
| **7** | `probe_stego_capacity_cmd` | `stego.rs` | `task_id`, `path`, `password`, `domain`, `safety_level: SafetyLevel`, `algorithm: Option<String>`, `exact: bool`, `on_progress` | `StegoCapacityInfo` | `engine.stego().probe_file(&path, &ProbeOptions)`；`safety_level` → `SafetyPolicy{level, enforcement}`，`algorithm` → `StegoTuning::Png/Jpeg/Hevc`（Rust 侧无 `algorithm` 字段，`SafetyPolicy` 也未派生 serde，必须显式映射） |
| **8** | `embed_stego_file_cmd` | `stego.rs` | `task_id`, `req: StegoEmbedRequest`, `on_progress: Channel<ProgressEvent>` | `StegoEmbedResult`（含 `capacity`, `stats: Option<EmbedStats>`, `warnings`） | `engine.stego().embed_file(&carrier, &payload, &EmbedOptions, &FileTarget)` |
| **9** | `extract_stego_file_cmd` | `stego.rs` | `task_id`, `path`, `output_path: Option<PathBuf>`, `password`, `domain`, `overwrite: bool`, `on_progress` | `ReadSummary` | `stego::io::extract_carrier_file_payload` + `check_overwrite` |
| **10** | `write_structure_file_cmd` | `structure.rs` | `task_id`, `req: StructureWriteRequest`（含 `overwrite: bool`）, `on_progress: Channel<ProgressEvent>` | `WriteResult` | 先 `core::pipeline::check_overwrite(&dest, overwrite)?`（`WriteOptions` 没有 `overwrite` 字段，库不拦），再 `engine.structure().write_file(&carrier, source, &WriteOptions)` |
| **11** | `read_structure_file_cmd` | `structure.rs` | `task_id`, `path`, `output_path: Option<PathBuf>`, `password`, `overwrite: bool`, `on_progress` | `ReadSummary` | `engine.structure().read_file(&path, &ReadOptions)?.summary()` |
| **12** | `restore_structure_file_cmd` | `structure.rs` | `task_id`, `path`, `output_path: Option<PathBuf>`, `password`, `backup: bool`, `overwrite: bool`, `on_progress` | `RemoveResult` | `engine.structure().restore_file(&path, &RestoreOptions)` |
| **13** | `run_batch_job_cmd` | `batch.rs` | `task_id`, `items: Vec<PathBuf>`, `job: BatchJobSpec`, `on_progress: Channel<ProgressEvent>` | `BatchOutcome< serde_json::Value >` | `core::batch::run_batch(&items, &BatchPlan, worker)` |
| **14** | `cancel_task_cmd` | `batch.rs` | `task_id: String` | `bool` | `state.tasks.get(&task_id).map(|t| t.cancel())` |

> **契约核对的四个易错点**：
> - `DualInspect` 是 `#[serde(flatten)]` 结构域 + 顶层 `content_stego` / `content_error` / `media_info`；`strategy` 是 `{id, name}` 不是字符串。
> - `inspect_any` 里结构域错误直接 `?` 冒泡，裸 Annex-B（`.h265`，capability 的 `structure` 为空）会让整个双域检视失败。命令要按 `CAPABILITIES` 先分流，或像内容域那样把结构域错误降级成卡片内提示。
> - `ErrorKind::AlreadyExists` 只在读 / 还原 / 内容域写路径由库触发；结构域写必须命令侧先查（见 #10）。
> - `StrategyCapacity.limit` 与 `LevelStatus.detail` 都是写死的英文字符串：`limit` 要在命令侧调 `StrategyCapacity::render_limit(RenderCtx::current())`；`LevelStatus.detail` 目前没有本地化（`render()` 直接返回原文），中文界面下工作台三的明细仍是英文。

#### 请求载荷（Payload）统一设计：`PayloadInputDto`

为了支持在 GUI 中直接输入“一段秘密文字”或选择“本地任意大文件”作为隐藏载荷，同时避免大载荷文件经前端 JS 读入内存再跨 IPC 传给 Rust，所有写入/嵌入命令统一使用如下 Rust 侧直接读取的枚举：

```rust
// gui/src-tauri/src/commands/mod.rs
use std::path::PathBuf;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PayloadInputDto {
    /// 用户在文本框中直接输入的文本（UTF-8）
    Text { content: String },
    /// 用户通过文件选择器选中的本地文件路径（由 Rust 直接流式或按需读取，零 IPC 传输开销！）
    File { path: PathBuf },
}
```

---

## 三、 前端（React + TypeScript + Zustand）架构与交互规范

### 3.1 前端强类型契约定义（`gui/src/types/strhide.ts`）

前端所有状态严格绑定 Rust 导出的 JSON 结构，杜绝 `any`：

```typescript
// gui/src/types/strhide.ts
export type Lang = "en" | "zh";
export type Domain = "structure" | "content";
export type SafetyLevel = "paranoid" | "high" | "balanced";

export type ErrorKind =
  | "io"
  | "corrupted_data"
  | "password"
  | "password_with_hint"
  | "trellis_infeasible"
  | "rejection"
  | "already_exists"
  | "target_busy"
  | "safety_threshold"
  | "restore_mismatch"
  | "unsupported_format"
  | "no_hidden_data"
  | "unsupported_version"
  | "cancelled"
  | "general";

export interface ErrorDetail {
  kind: ErrorKind;
  category?: string;
  category_label?: string;
  detail: string;
  hint?: string;
}

export interface MediaInfo {
  width: number;
  height: number;
  fps?: number;
  duration_ms?: number;
  bitrate_bps?: number;
}

export interface StrategyCapacity {
  strategy: string;
  capacity_bytes: number | null;
  available: boolean;
  limit: string;
  note?: string;
}

export interface CarrierMetadata {
  filename: string;
  raw_size: number;
  raw_sha256: string;
  created_at: number;
}

export interface StegoHeaderInfo {
  format: string;
  has_hidden_data: boolean;
  algorithm?: string;
  codec?: string;
  envelope_len?: number;
  payload_len?: number;
  media_info?: MediaInfo;
  note?: string;
}

/** 结构域的 `StrategyId` 序列化为 `{id, name}`（`{id: 2, name: "chunk"}`），不是裸字符串。 */
export interface StrategyId {
  id: number;
  name: string;
}

export interface DualInspect {
  carrier: string;
  format: string;
  has_hidden_data: boolean;
  strategy?: StrategyId;
  ube_offset?: number;
  ube_total_size?: number;
  is_encrypted?: boolean;
  is_compressed?: boolean;
  is_stealth?: boolean;
  password_hint?: string;
  orig_host_size?: number;
  orig_host_sha256?: string;
  metadata?: CarrierMetadata | { error: string };
  suspicious_hints?: string[];
  strategies: StrategyCapacity[];
  content_stego?: StegoHeaderInfo;
  content_error?: ErrorDetail;
  /** 内容域解析出的媒体信息（顶层字段，与 `content_stego.media_info` 同源）。 */
  media_info?: MediaInfo;
}

export interface StegoCapacityInfo {
  format: string;
  algorithm: string;
  total_elements: number;
  available_slots: number;
  max_raw_payload_bytes: number;
  max_raw_is_grouped: boolean;
  recommended_max_bytes: number;
  estimated_change_rate: number;
  safety_level: SafetyLevel;
  safety_bpp_limit: number;
  is_estimated: boolean;
  media_info?: MediaInfo;
}

export interface EmbedStats {
  modified_slots: number;
  total_candidate_slots: number;
}

export interface StegoEmbedResult {
  carrier: string;
  written_to: string;
  format: string;
  payload_bytes: number;
  carrier_before_bytes: number;
  carrier_after_bytes: number;
  backup_file?: string;
  capacity?: StegoCapacityInfo;
  stats?: EmbedStats;
  warnings: Array<{
    kind: "safety_threshold_exceeded";
    payload_bytes: number;
    recommended_max_bytes: number;
    safety_level: string;
    actual_bpp: number;
    limit_bpp: number;
  }>;
}

export interface ReadSummary {
  carrier: string;
  is_file: boolean;
  is_encrypted: boolean;
  filename: string;
  raw_size: number;
  written_file?: string;
  text_preview?: string;
}

export interface ProgressEvent {
  taskId: string;
  /** `Stage::as_str()` 的输出：全小写，`cost_map` 带下划线；`total` 未知时只到 `done`。 */
  stage: "read" | "decode" | "cost_map" | "solve" | "encode" | "write" | "verify";
  done: number;
  total: number | null;
  percent: number | null;
}

/** 结构域三级校验中的一级；`skipped` 表示"没能尝试"（不是通过，也不是失败）。 */
export interface LevelStatus {
  ok: boolean;
  detail: string;
  skipped: boolean;
}

/** `verify_carrier_cmd` 的返回：结构域三级 + 内容域可选。 */
export interface DualVerifyDto {
  carrier: string;
  format: string;
  level1_host: LevelStatus;
  level2_envelope: LevelStatus;
  level3_crypto: LevelStatus;
  content_stego?: {
    format: string;
    levels: Array<{ level: number; name: string; ok: boolean; message?: string }>;
  };
}

/** 非致命写入警告，`#[serde(tag = "kind")]` 标签联合。 */
export type WriteWarning =
  | { kind: "size_inflation"; ube_size: number; host_size: number; ratio_pct: number }
  | { kind: "suspicious_structures"; hints: string[] };

export interface WriteResult {
  carrier: string;
  format: string;
  strategy: StrategyId;
  strategy_note?: string;
  raw_size: number;
  ube_size: number;
  is_encrypted: boolean;
  is_stealth: boolean;
  password_hint?: string;
  backup_file?: string;
  warnings: WriteWarning[];
}

export interface RemoveResult {
  carrier: string;
  restored_size: number;
  restored_sha256: string;
  verified_identical: boolean;
  backup_file?: string;
}

/** `formats::FileFormat` 序列化为显示名：`"PNG"` `"JPEG"` `"MP4"` `"HEVC-AnnexB"` ... */
export type FormatName = string;

export interface Capability {
  format: FormatName;
  structure: string[];
  stego: string[];
  extensions: string[];
  memory: "streaming" | "whole_file";
}

export interface DetectorMetric {
  name: string;
  /** `"spatial"` / `"dct"` / `"structural"` / `"signature"` */
  domain: string;
  status: "PASS" | "ALERT";
  metric: string;
  threshold?: string;
  detail: string;
}

/** `scan_carrier_cmd` 的返回（`AnalysisReport` 的别名）。`risk_score` 是 0..100。 */
export interface ScanReport {
  carrier: string;
  format?: FormatName | null;
  file_size: number;
  findings: Array<{ detector: string; severity: "info" | "suspicious" | "likely"; detail: string }>;
  risk_score: number;
  verdict: "clean" | "low" | "suspicious" | "likely-hidden";
  notes: string[];
  detectors: DetectorMetric[];
}
```

### 3.2 文件查看：只调系统打开，不做应用内预览

**决定**：v1 的 GUI 不内嵌图片 / 音视频播放器，也不做"原图 / 隐写后"分屏对比。载体卡片只展示元信息（格式、宽高、时长、码率、文件大小、SHA-256、信封偏移/大小、策略徽章），并提供两个动作：

- **打开文件**：`openPath(path)` —— 交给系统默认程序（图片查看器 / 播放器 / 编辑器）。
- **打开所在目录**：`revealItemInDir(path)` —— 在系统文件管理器里选中该文件。

两者都来自 `@tauri-apps/plugin-opener`（Rust 侧 `tauri-plugin-opener`），前端直接调用，不需要额外的 Tauri command。

这样做省掉四样东西：`protocol-asset` 协议与它的磁盘白名单、WebView2 持有播放句柄导致的"原地覆盖 rename 失败"、`executeWithPreviewGuard` 那 40ms 的时序 hack、以及载荷文本渲染带来的 XSS 面。代价只是用户要切一下窗口，对一个"改文件格式/校验/提取"的工具完全可接受。

```typescript
// gui/src/lib/openActions.ts
import { openPath, revealItemInDir } from "@tauri-apps/plugin-opener";

export const openCarrier = (path: string) => openPath(path);
export const revealCarrier = (path: string) => revealItemInDir(path);
```

> 原地写之前唯一还需要注意的是外部程序可能正开着这个文件：库里的 `commit::rename_with_retry` 会退避重试三次，失败后映射成 `ErrorKind::TargetBusy`，前端弹"请关闭外部播放器或另存为"。如果将来一定要加应用内预览，必须同时补上"写前卸载预览 + 重新挂载"，并以本节的决定为前提重新评估 `protocol-asset` 的 scope。

### 3.3 四大工作台与核心组件设计规范

#### 1. 全局载体舞台与载体信息卡（`CarrierStage.tsx` + `CarrierSummary.tsx`）
- **原生拖拽接入**：监听 `getCurrentWebview().onDragDropEvent`，获取拖入文件或文件夹的操作系统绝对路径 `paths: string[]`。
  - 拖入 **1 个文件**：进入单文件工作模式，立即并行触发 `inspect_carrier_cmd`（MP4 走流式有界读取，耗时 < 50ms）；
  - 拖入 **多个文件或文件夹**：自动提示或切换至“批处理中心（Batch Queue）”。
- **载体信息卡（不做预览）**：
  - **图像载体（PNG / JPEG / WebP）**：显示 `MediaInfo` 宽高、文件大小、格式、SHA-256 与"打开文件 / 打开所在目录"按钮。
  - **视频/音频载体（MP4 / MKV / WAV）**：显示帧率（`fps`）、时长（`duration_ms`）与码率（`bitrate_bps`），播放交给系统默认播放器。
  - **二进制/文档容器（PE / PDF / ZIP）**：渲染结构化容器卡片（各策略槽位状态，如 PE `.text` 代码段密度、扇区零填充 Slack 空间、Authenticode 签名状态）。
  - 图片"原图 / 隐写后"对比**不做**：嵌入完成后用 `EmbedStats` 修改率徽章 + 文件大小变化表达改了多少，需要肉眼确认时用系统看图软件看两遍。

#### 2. 工作台一：🔍 检视与智能提取台（`InspectExtractView.tsx`）
- **双域诊断并列卡片**：
  - **结构域卡片**：展示 `has_hidden_data`、注入策略徽章（`png_chunk` / `mp4_box` / `pe_codebits` 等）、信封偏移量与大小、加密/压缩/Stealth 状态、密码提示（`password_hint`）以及解密后的 `CarrierMetadata`（含原始文件名、字节数、SHA-256 与写入时间）。
    - **隐身信封雷达告警**：当 `has_hidden_data == false` 但 `suspicious_hints` 非空时，渲染醒目的琥珀色告警框：“检测到疑似隐身信封特征（`{hints.join(', ')}`），请在下方输入密码后点击重新检视”。
  - **内容域卡片**：展示 `StegoHeaderInfo`（算法名称如 `HILL` / `UERD` / `HEVC-CABAC-InPlace`、矩阵编码参数如 `STC (h=7, u=2)`、有效载荷字节数）。
- **一键智能提取栏（`SmartExtractBar`）**：
  - 绑定 `smart_extract_cmd`。若检出 `password_hint`，自动显示在密码输入框上方。
  - **双载荷防丢提醒**：当返回 `also_present: Some(secondaryDomain)` 时，顶部弹出双域切换横幅：“此载体同时包含【结构域】与【内容域】两份独立载荷！当前已提取结构域，点击此处一键提取内容域载荷”。
  - **结果展示**：若 `ReadSummary.text_preview` 存在，用 `<pre style={{ whiteSpace: "pre-wrap" }}>` 以纯文本渲染（`textContent`，禁止 `dangerouslySetInnerHTML` 或 Markdown/HTML 渲染——载荷文本完全由第三方控制），并提供"一键复制"与"另存为文件"；若为二进制文件则显示保存路径与"打开所在目录 / 打开文件"按钮（`plugin-opener`）。

#### 3. 工作台二：🛡️ 隐藏与自适应嵌入台（`HideEmbedView.tsx`）
- **双域智能切换器**：
  - 根据 `CAPABILITIES` 自动判断当前载体支持的隐藏域：
    - 若载体为 PNG / JPEG / HEIF / MP4，默认高亮推荐 **“内容域自适应隐写（抗统计分析 / MP4 零体积膨胀）”**，同时允许切换至“结构域容器注入”；
    - 若载体为 ZIP / PDF / PE / MKV / WAV，自动锁定为 **“结构域容器注入（流式极速 / 支持 100% 字节还原）”**。
- **三档安全水位尺（`CapacityMeter.tsx`）**：
  - 实时统计用户当前输入的文本 UTF-8 字节数或所选载荷文件的大小 `payloadBytes`；
  - 在一条可视化水平刻度尺上同时标出：
    - 🟢 `Paranoid` 安全上限（`0.06 bpp`）
    - 🔵 `High` 推荐上限（`0.10 bpp`，默认选中）
    - 🟡 `Balanced` 均衡上限（`0.15 bpp`）
    - 🔴 `Max Raw` 物理极限容量（`max_raw_payload_bytes`）
  - 当 `payloadBytes` 超过当前所选档位的 `recommended_max_bytes` 时，水位尺平滑变为橙色（Advisory 告警模式）或红色（Enforced 阻断模式），无需等点击“开始嵌入”就能提前预知风险。
- **嵌入结果反馈卡**：
  - 完成后展示耗时、文件大小变化对比（如 MP4 Scheme C 显示 `+0 B (0.00% 零膨胀)`），以及 **`EmbedStats` 精确修改率徽章**（例如：`已微调 1,420 / 2,073,600 个候选槽位（修改率 0.068%）`）。

#### 4. 工作台三：✅ 三级校验与无损还原台（`VerifyRestoreView.tsx`）
- **三级完整性步进器（3-Tier Verification Stepper）**：
  - 点击“深度校验”触发 `verify_carrier_cmd`，以纵向三步卡片展示：
    1. **Level 1 · 宿主容器结构校验**（检查 PNG CRC / ZIP 中央目录 / PE 头 / HEVC 比特流语法）；
    2. **Level 2 · 隐写信封/微头边界校验**（检查 UBE Header & Trailer Magic/CRC 或 Stego Superblock）；
    3. **Level 3 · 密码学解密与哈希校验**（流式验证 AEAD 认证标签与全量载荷 SHA-256 / CRC32）。
- **100% 字节级无损还原面板**：
  - 针对含结构域信封的载体，提供“一键剥离信封并还原原始文件”按钮（调用 `restore_structure_file_cmd`）；
  - 成功后展示 `restored_size` 与 `restored_sha256 === orig_host_sha256` 100% 吻合绿标。

#### 5. 工作台四：🔬 反隐写取证与批处理中心（`ForensicsBatchView.tsx`）
- **黑盒反隐写扫描仪表盘（Steganalysis）**：
  - 调用 `scan_carrier_cmd`，左侧用环形仪表盘展示 `risk_score`（**0..100**，阈值：0–9 `clean`、10–29 `low`、30–59 `suspicious`、≥60 `likely-hidden`）与 `verdict`；
  - 右侧用分组表格展示 `detectors`（`signature`、`structural`、`spatial`、`dct` 四大类检测器的实测值 `metric`、阈值 `threshold` 与 `PASS`/`ALERT` 状态），底部醒目展示 `notes` 中的盲区说明（如 ternary `±1` 隐写对传统卡方/RS 的免疫特性）。
- **多文件批量队列（Batch Queue）**：
  - 对接 `run_batch_job_cmd`。根据载体类型自动设置默认并发度（结构域流式操作默认 `max_concurrency = 4`，内容域大图/视频操作默认 `max_concurrency = 1` 防止多任务并发撑爆内存）；
  - 展示总进度、成功/失败计数、单文件耗时 `elapsed_ms`，支持随时点击“取消队列”。

### 3.4 结构化错误拦截器（`gui/src/lib/errorHandler.ts`）

所有 `invoke` 抛出的 `ErrorDetail` 统一交由 `handleStrHideError(err, retryWith)` 处理，彻底告别正则匹配英文报错：

| `err.kind` (`ErrorKind`) | GUI 交互响应动作 |
| :--- | :--- |
| `"already_exists"` | 弹出 `<OverwriteDialog path={...} />`：提供 **“覆盖现有文件”**（自动设置 `overwrite: true` 重新调用原函数）与 **“另存为新路径...”** 两个按钮。注意结构域写命令的 `already_exists` 来自命令侧的 `check_overwrite`，不是库（见 §2.2 脚注）。 |
| `"target_busy"` | 弹出占用提示框：“目标文件正被其它程序占用，请关闭外部播放器/看图工具后重试，或选择另存为”。 |
| `"password"` / `"password_with_hint"` | 自动展开并聚焦密码输入框，抖动提示密码错误；若 `err.hint` 非空，在输入框下方以高亮徽章展示密码提示 `Hint: {err.hint}`。 |
| `"safety_threshold"` | 高亮闪烁容量水位尺，弹出快捷操作卡：“当前载荷超出所选安全档位上限，是否切换为 **Balanced 档位** 或改为 **仅告警不阻断（Advisory）** 继续嵌入？” |
| `"restore_mismatch"` | 弹出还原校验失败诊断卡，对比期望与实际 SHA-256；若检测到残留嵌套信封，提示用户按后进先出顺序再次执行还原。 |
| `"cancelled"` | **静默处理**：仅将底部状态栏更新为“操作已由用户取消”，绝不弹出刺眼的错误红框。 |
| 其它错误类型 | 使用 Toast 组件展示本地化分类标题 `err.category_label` 与详情 `err.detail`。 |

---

## 四、 Tauri v2 权限配置（dialog + opener）与 CSP

应用不启用本地资源协议，也不加载本地媒体：文件选择走 `tauri-plugin-dialog`，查看文件走 `tauri-plugin-opener`。因此只需要这两套权限，并把 CSP 的 `connect-src` 留给 IPC。

```json
// gui/src-tauri/tauri.conf.json 关键片段
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "StrHide Studio",
  "version": "0.7.4",
  "identifier": "com.mcxiaoke.strhide",
  "build": {
    "beforeDevCommand": "pnpm dev",
    "devUrl": "http://localhost:1420",
    "beforeBuildCommand": "pnpm build",
    "frontendDist": "../dist"
  },
  "app": {
    "withGlobalTauri": false,
    "windows": [
      {
        "title": "StrHide Studio",
        "width": 1240,
        "height": 820,
        "minWidth": 960,
        "minHeight": 640,
        "dragDropEnabled": true
      }
    ],
    "security": {
      // connect-src ipc: 这一条不能少，缺了所有 invoke 都会被 WebView 拦掉。
      "csp": "default-src 'self'; connect-src ipc: http://ipc.localhost; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
      // dev 下 Vite 需要 HMR 的 websocket，不设 devCsp 会在 tauri dev 里整页白屏。
      "devCsp": "default-src 'self'; connect-src ipc: http://ipc.localhost ws://localhost:1420 http://localhost:1420; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
    }
  }
}
```

```json
// gui/src-tauri/capabilities/default.json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "default",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "dialog:default",
    "opener:default",
    "opener:allow-open-path",
    "opener:allow-reveal-item-in-dir"
  ]
}
```

要点：

1. **不要开 `assetProtocol`**。既然不做应用内预览，`protocol-asset` 特性、`assetProtocol.scope` 全都不需要；`scope: ["**"]` 等于把整盘文件读权限交给 WebView，和"载荷文本可被第三方控制"叠在一起就是现成的读盘链。
2. **`opener:allow-open-path` / `opener:allow-reveal-item-in-dir` 需要显式声明**，`opener:default` 只覆盖它默认放行的范围；具体 scope 语法以 `tauri-plugin-opener` 版的文档为准。
3. 前端渲染提取出的文本一律 `textContent`，不引入 Markdown/HTML 渲染器。
4. 密码只存在于内存与 IPC 参数里，不进 `settingsStore` 持久化，不进日志。

---

## 五、 分阶段实施计划与硬性验收表（Phase G1 – G5）

整个 Tauri v2 客户端开发切分为 **5 个渐进式阶段（Phase G1–G5）**，每个阶段均可独立编译、独立验证，可直接按阶段交给编码 Agent 执行：

| 阶段 | 阶段名称 | 核心交付物与文件清单 | 一条式硬性验收口径（Pass / Fail） |
| :--- | :--- | :--- | :--- |
| **Phase G1** | **Tauri v2 脚手架与 Rust IPC 桥接层** | • 初始化 `gui/` 与 `gui/src-tauri/`<br>• 配置 `Cargo.toml` (`panic = "unwind"`, 依赖 `../../rust`, 只用 `dialog`+`opener` 插件)<br>• 实现 `state.rs` (`GuiState`, 受控 Rayon 池, 60fps 节流 `ThrottledChannelProgress`, `run_cancellable_task`)，并把 `pool` 真正填进 `EmbedOptions/ProbeOptions/ExtractOptions.pool` 或 `pool.install(...)`<br>• 实现 `commands/{diag,structure,stego,batch}.rs` 全部 14 个命令（结构域写命令先 `check_overwrite`） | 1. `cd gui/src-tauri && cargo check` 零警告通过；<br>2. `cargo test` 用 `Channel::new` 收消息，断言节流时间窗、阶段边界与 `CancelToken` 注册/移除无死锁（节流判定抽成纯函数再测）；<br>3. `cargo tree` 确认未拉入 `clap` / `rpassword` 等 CLI 依赖。 |
| **Phase G2** | **前端基础底座、拖拽舞台与双域检视/提取台** | • 实现 `src/types/strhide.ts` 与 `src/api/commands.ts`<br>• 实现 `workspaceStore.ts`、`taskStore.ts`、`settingsStore.ts`<br>• 实现顶层布局、`CarrierDropzone`、`CarrierSummary`（元信息 + `plugin-opener` 打开文件/定位目录）<br>• 实现 **工作台 1 (`InspectExtractView.tsx`)** | 1. 拖入任意 PNG/JPEG/MP4/PE 文件，体感即时（MP4 走流式有界读取；大 PE 的 codebits 容量探测可能略慢，但界面不卡）地渲染出格式、分辨率/时长及结构域+内容域双诊断卡片，并可用系统程序打开该文件与所在目录；<br>2. 对加密载体输入错误密码弹出本地化提示（含 `password_hint`），输入正确密码一键提取文本并以纯文本渲染（不经过 HTML）；<br>3. 对双域同时含载荷的文件提取时正确弹出 `also_present` 提醒横幅。 |
| **Phase G3** | **隐藏与嵌入工作台 + 三档实时容量水位尺** | • 实现 `CapacityMeter.tsx`（`Paranoid` / `High` / `Balanced` / `Max` 实时水位线，`probe` 去抖 + 可取消）<br>• 实现 `TuningDrawer.tsx`（策略名下拉框 + PNG/JPEG/HEVC 算法参数）<br>• 实现 **工作台 2 (`HideEmbedView.tsx`)** 与 `ProgressBarOverlay.tsx` + `OverwriteDialog.tsx` | 1. 输入载荷文本或选文件时，容量水位尺实时计算占比并在超限时变色告警；<br>2. 对 500MB+ MP4 视频执行内容域嵌入时，底部进度条平滑显示 `decode` / `solve` / `encode` 进度且点击"取消"能中止、无残留 `.tmp`（具体中止延迟实测后写进验收，HEVC 编码阶段不要预设 100ms）；<br>3. 原地覆盖时展示 `EmbedStats` 修改率；目标已存在且未确认覆盖时返回 `already_exists` 而非静默覆盖（含结构域写命令）；外部程序占用目标时映射为 `target_busy` 并给出"另存为"。 |
| **Phase G4** | **三级校验还原台 + 反隐写取证与批处理中心** | • 实现 **工作台 3 (`VerifyRestoreView.tsx`)**（L1/L2/L3 步进器 + 100% 字节级还原 + 嵌套信封提示）<br>• 实现 **工作台 4 (`ForensicsBatchView.tsx`)**（`0..100` 风险评分盘、检测器表格、多文件批处理队列） | 1. 对隐写载体运行校验，L1/L2/L3 三级指示灯逐级变绿；点击“无损还原”后 SHA-256 校验通过；<br>2. 反隐写扫描页准确渲染 `risk_score` 与各检测器 `PASS`/`ALERT` 指标；<br>3. 拖入 20 个文件执行批量检视/扫描，支持单错继续（`continue_on_error: true`）与中途一键取消。 |
| **Phase G5** | **中英双语联动、深浅色主题与跨平台打包** | • 对接前端 i18n 与后端 `set_ui_language_cmd`（`StrategyCapacity.limit` 在命令侧 `render_limit` 后再回前端）<br>• 完善 `errorHandler.ts` 全错误分支弹窗<br>• 配置应用图标、快捷键与 GitHub Actions 跨平台打包（`windows-latest` / `macos-latest` / `ubuntu-latest` 矩阵） | 1. 切换中/英文时，前端界面文案与后端返回的 `ErrorDetail.category_label`、`StrategyCapacity.limit` 同步切换（`LevelStatus.detail` 仍是英文，验收不覆盖）；<br>2. `pnpm tauri build` 在对应 runner 上分别产出 Windows (`.msi`/`.exe`)、macOS (`.dmg`) 与 Linux (`.deb`/`.AppImage`) 安装包。 |

> **明确不做（v1.x）**：应用内图片/音视频预览、原图与隐写后的分屏对比。载体信息用元数据卡 + "系统打开 / 定位所在目录"替代。真要加预览，按 §3.2 末尾的条件重开一次设计评审：必须同时解决文件句柄占用、`protocol-asset` 的最小 scope、以及载荷文本渲染的 XSS 面，不能只加一个 `<video src>`。
