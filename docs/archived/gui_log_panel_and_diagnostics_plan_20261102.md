# GUI Tauri 日志面板与全链路调试方案设计 (2026-11-02)

## 一、方案目标与定位

为 `strhide` 桌面客户端（`gui/` 基于 Tauri 2 + React + TypeScript）构建生产与调试一体化的全链路日志系统与浮层面板（Floating Modal），核心目标：

1. **主界面入口**：在主界面右上角主题切换按钮（`theme-toggle`）的左侧新增日志图标按钮，带有错误/警告指示徽标，点击呼出日志浮层 Modal。
2. **底层原始日志与函数输出（Rust Lib）**：
   - 全面接入官方标准 `log = "0.4"` 门面；
   - 核心库关键算法（PNG/JPEG/音频/HEVC 隐写、STC Trellis 求解、结构域策略匹配、UBE 信封、反隐写检测扫描）关键点结构化日志；
   - Tauri Command（IPC）全生命周期跟踪：调用入参（密码脱敏）、任务进度流转（Stage）、执行耗时（毫秒）、函数原始输出（结构化 JSON 预览）及详细错误原因与堆栈。
3. **前端日志（GUI Frontend）**：
   - 自动拦截 `console.log/info/warn/error/debug`；
   - 全局捕获 `window.onerror` 与 `window.onunhandledrejection`；
   - 跟踪前端调用 IPC 的请求与响应耗时链路。
4. **展示形态与交互体验（Floating Modal）**：
   - 采用大尺寸浮层 Modal（支持全屏放大/还原、Esc 关闭、背景半透明遮罩）；
   - **文本自由选取与复制**：全文字段原生启用 `user-select: text`，支持鼠标任意拖选复制；
   - **一键快捷复制**：提供「复制全部（格式化文本）」、「复制当前过滤结果」、「单条复制」及针对函数原始输出的「复制 JSON」；
   - **调试分析工具**：多源切换（全部 / Rust 后端 / GUI 前端）、级别多选（Debug / Info / Warn / Error）、实时关键字搜索高亮、函数原始返回值折叠/展开、自动滚屏开关（Auto-scroll）、清空缓冲。
5. **主题与无障碍标准**：
   - 严格继承项目的 Slate/Cyan/Rose/Amber 调色盘；
   - 在亮色（Light）与深色（Dark）模式下均通过 WCAG AA/AAA 对比度审查；
   - 中英双语（i18n）文案统一规范。

---

## 二、关键点、数据、算法与逻辑埋点清单

### 1. Rust 核心库关键点 (`rust/src/`)
- **控制与流转 (`core/control.rs`, `core/pipeline.rs`)**：
  - 记录任务阶段变更：`Stage::Read`, `Decode`, `CostMap`, `Solve`, `Encode`, `Write`, `Verify`；
  - 记录原子写入目标提交（`FileTarget`）、取消令牌触发（`CancelToken`）。
- **内容隐写算法 (`stego/`)**：
  - **PNG 空间域** (`stego/png/embed.rs`, `extract.rs`)：载体尺寸、通道格式、代价算法选择（HILL / S-UNIWARD）、STC 矩阵阶数、Trellis 求解状态与改动失真值。
  - **JPEG DCT 域** (`stego/jpeg/embed.rs`, `extract.rs`)：DCT 块数、候选系数容量、UERD 代价图计算耗时、三元 STC 求解与改动率。
  - **音频残差域** (`stego/audio/flac/mod.rs`, `wav/mod.rs`)：残差总数、可用槽位（Moveable Slots）、密码派生相位种子、抽样密度。
  - **HEVC 视频域** (`stego/hevc/mod.rs`)：NALU 类型、CABAC Bin 遍历与容量探测。
- **结构隐写引擎 (`structure/engine/`)**：
  - 格式自适应策略匹配（`auto` 解析为具体策略如 `png_chunk`, `jpeg_app15`, `zip_extra`, `pdf_stream`, `pe_slack` 等）；
  - UBE 信封头结构、Payload 长度、AEAD 加密模式与 Stealth 无痕标志。
- **反隐写检测扫描 (`analysis/`)**：
  - 载体格式探测器扫描历程、各检测器（UBE 签名、卡方统计、DCT 直方图、PE Slack 等）的命中情况与置信度。

### 2. Tauri 后端命令层 (`gui/src-tauri/src/commands/`)
- **`stego.rs`**：
  - `probe_stego_capacity_cmd`：载体路径、安全档位、估算容量、精确扫描耗时；
  - `embed_stego_file_cmd`：载体路径、Payload 种类与长度、输出路径、备份设置、耗时与原始返回值（`StegoEmbedResult`）；
  - `extract_stego_file_cmd` & `smart_extract_cmd`：提取源域匹配、实际载荷大小与还原摘要（`ReadSummary`）。
- **`structure.rs`**：
  - `write_structure_file_cmd`：策略参数、原文件大小、写入后大小、信封尺寸与原始返回值（`WriteResult`）；
  - `read_structure_file_cmd` & `restore_structure_file_cmd`：信封解析与还原校验。
- **`diag.rs`**：
  - `inspect_carrier_cmd`：载体双域检查摘要（`DualInspect` JSON 原始输出）；
  - `scan_carrier_cmd`：检测报告与异常指标（`ScanReport` JSON 原始输出）。
- **`batch.rs`**：
  - `run_batch_job_cmd`：批处理规划、并发度、单个文件错误汇总。

### 3. GUI 前端核心层 (`gui/src/`)
- **`api/commands.ts`**：
  - 统一记录每次 IPC 发起的开始与结束，记录精确执行耗时；
  - 遇到异常时捕获结构化 `ErrorDetail`（错误类型、详细描述、建议操作）。
- **用户交互与全局事件**：
  - 页签切换（Stego/Hide/Extract/Scan）、文件批量拖拽添加与移除；
  - 参数调整（隐蔽强度、无痕模式、Payload 格式切换）；
  - 任务启动与取消。

---

## 三、架构与数据结构设计

### 1. 统一日志条目数据结构 (TypeScript & Rust)

```typescript
export type LogSource = "rust" | "frontend";
export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogEntry {
  id: string;             // 唯一递增标识或 "r-101" / "f-202"
  timestamp: number;      // Unix 毫秒时间戳
  source: LogSource;      // "rust" | "frontend"
  level: LogLevel;        // 日志级别
  target: string;         // 模块名，如 "strhide::stego", "ipc::embed_stego_file"
  message: string;        // 日志说明文字
  data?: unknown;         // 结构化函数原始输出（JSON）或参数明细
}
```

### 2. Rust 端 RingBuffer Logger

- **并发安全**：采用 `Arc<Mutex<VecDeque<LogEntryDto>>>`，上限固定为 2000 条，先进先出自动淘汰；
- **冷启动与持久性**：前端尚未打开或刷新时，日志安全累积在内存缓冲中，随时通过 `get_recent_logs_cmd` 导出；
- **实时广播**：集成至 Tauri 事件系统，在 `AppHandle` 激活后触发 `app:log` 事件，前端实时无感知接收；
- **双向输出**：如果以终端模式启动，同时保持终端 stdout/stderr 格式化彩色输出。

### 3. 前端 LogStore (Zustand)

- 管理混合日志流（上限 2000 条）；
- 维护过滤状态：`filterSource` (`all` | `rust` | `frontend`)、`filterLevel` (`all` | `debug` | `info` | `warn` | `error`)、`searchQuery`（关键字搜索）；
- 维护 UI 状态：`isModalOpen`、`isMaximized`、`autoScroll`（自动滚动）；
- 维护未读错误/警告计数，实时在主界面图标展示红色状态点；
- 提供一键复制全部、复制单条、复制 JSON 函数输出的剪贴板 API。

---

## 四、分批实施与分步提交计划

按照用户明确要求，整个实施过程遵循**分批实施、分批 Git 提交**原则，每批提交前均执行严格测试与 Lint：

### 批次 1：Rust 端日志基础设施与 RingBuffer 收集器
1. 在 `rust/Cargo.toml` 与 `gui/src-tauri/Cargo.toml` 中引入 `log = "0.4"`；
2. 在 `gui/src-tauri/src/logger.rs` 中实现 `RingBufferLogger`、`LogEntryDto` 及单例初始化；
3. 新增 Tauri 命令：`get_recent_logs_cmd`、`clear_logs_cmd`，并在 `lib.rs` 中注册；
4. 验证：`cargo check --manifest-path gui/src-tauri/Cargo.toml` 与 `cargo clippy`。
5. **Git Commit 1**: `feat(gui): implement rust ringbuffer logger and log ipc commands`

### 批次 2：Rust 核心库与 Tauri 命令全链路埋点与原始输出暴露
1. 在 `gui/src-tauri/src/commands/` 各命令中增加进入、执行、退出耗时与原始返回值记录；
2. 在 `gui/src-tauri/src/state.rs` 中的任务执行包装器中增加阶段流转日志；
3. 在 `rust/src/` 的核心隐写/结构/检测引擎中补充关键决策点的 `log::debug!` / `log::info!`；
4. 验证：`cargo test --all-features --all-targets`，`cargo clippy` 零警告。
5. **Git Commit 2**: `feat(core): add structured logging and raw function output tracing`

### 批次 3：前端日志体系（Store、Console 代理、IPC 追踪与 i18n）
1. 创建 `gui/src/store/logStore.ts`；
2. 创建 `gui/src/lib/frontendLogger.ts`，接管 `console.*`、全局异常及 Tauri `app:log` 监听；
3. 在 `gui/src/api/commands.ts` 中封装 IPC 调用耗时与参数日志记录；
4. 在 `gui/src/lib/i18n.ts` 中补充日志面板中英文文案；
5. 验证：`pnpm test:unit` 全部通过。
6. **Git Commit 3**: `feat(gui): add frontend log store, ipc tracing, and console interceptor`

### 批次 4：日志浮层 Modal 组件、右上角入口集成与全量端到端测试
1. 创建 `gui/src/components/common/LogModal.tsx`（支持全屏、Esc 关闭、自由框选复制、JSON 展开折叠、搜索与级别过滤）；
2. 在 `gui/src/App.tsx` 顶栏右上角（`theme-toggle` 左侧）挂载日志按钮并绑定状态小徽标；
3. 补充针对日志面板的前端单元测试与 E2E 测试；
4. 执行全量测试套件（`pnpm build`、`test:unit`、`test:cross`、`test:e2e`、WCAG 对比度检查）；
5. 追加变更记录到 `docs/CHANGES-20261102.md`；
6. **Git Commit 4**: `feat(gui): add floating log modal and header entry button`

---

## 五、验收标准与验证清单

1. **功能完整性**：
   - 点击右上角图标即刻弹出浮层 Modal，背景虚化，当前正在执行的任务不受任何干扰；
   - 包含 Rust 底层关键操作日志、Tauri 命令入参与耗时、以及完整的返回值 JSON；
   - 包含 GUI 前端自身的所有 `console` 日志与 IPC 调用跟踪；
   - 鼠标可原生框选日志文本并 Ctrl+C 复制；
   - 点击「复制全部」或单条复制按钮能够成功将内容写入剪贴板；
   - 函数原始返回值 JSON 可点击展开并支持单独复制。
2. **性能与可靠性**：
   - 环形缓冲容量限制为 2000 条，杜绝长时间运行内存泄漏；
   - 自动滚屏智能暂停：用户手动向上回溯翻阅历史时自动解除锁底。
3. **视觉与代码质量**：
   - 浅色/深色主题均完美符合现有 Slate/Cyan 设计系统并满足 WCAG AA 对比度；
   - Rust 后端 `cargo clippy` 零警告；前端 TypeScript 编译与单元测试 100% PASS。
