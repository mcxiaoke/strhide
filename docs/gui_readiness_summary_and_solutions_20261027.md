# strhide GUI 前端就绪度：架构缺口与可行解决方案全景总结

> **文档创建时间**：2026-10-27 22:42
> **基线版本**：`strhide 0.7.3`（`rust/src` 约 44,000 行），重构计划 `strhide_architecture_and_refactoring_plan.md` 阶段 0–4 验收之后。
> **参考资料**：
> - `docs/strhide_architecture_and_refactoring_plan.md`（重构总规划）
> - `docs/api/ARCHITECTURE.md`（系统架构与分层）
> - `docs/api/STEGO-API.md`（内容域 API 规范）
> - `docs/gui_frontend_readiness_plan_20261027.md`（前端就绪度复核底稿）
> - `AGENTS.md`（内存基线与测试口径）

---

> **文档关系与勘误（2026-10-27 22:55 补充）**
>
> 1. 本文是上表"前端就绪度复核底稿"的**摘要**；完整依据（计划 §五 落地对照矩阵、每项的一条式验收、风险登记、证据索引、实现取舍论证）只在主文档 `docs/gui_frontend_readiness_plan_20261027.md` 中，两者冲突时以主文档为准。
> 2. **勘误一**：§4.2 写的"`TAIL_WINDOW = 64 KiB`"不准确。实测 `analysis.rs:55` 的 `TAIL_WINDOW` 是 **4096**，64 KiB 是另一个常量 `STRUCT_TAIL_WINDOW`（`:63`，用于定位 PNG `IEND` / JPEG `EOI` 等容器结束标记）。两个常量用途不同，不能互相替代。
> 3. **勘误二**：§2.2 同时定义了 `SmartExtractOptions` 又让 `inspect_carrier` 收 `&DualOptions<'_>`，签名不一致。主文档拆为两套：诊断用 `DualOptions`，提取用 `SmartExtractOptions`（并给后者补 `limits`，避免错误密码触发无上限 PBKDF2）。
> 4. 本文未覆盖而主文档新增的三项：容量探测无阶段进度（G8）、`panic = "abort"` 与 Windows 文件占用（G9）、推荐 feature 组合 / 文档同步 / FFI 决策（G10）。

## 零、执行摘要

针对“使用 `strhide` 库开发一个现代 GUI 应用（如 Tauri、Slint、egui、Iced 或 C/FFI 跨语言绑定）”的目标，经过对源码的逐行复核与对账，当前库在 CLI 场景下已完成两域解耦与特征门控，但在 **GUI 接入层（前端就绪层）** 存在 7 处核心缺口。

本方案坚持**“最小侵入、零格式回归、字节级兼容”**原则，给出逐项落地设计：

| 编号 | 核心问题 | 产生后果 | 解决方案核心思想 | 实施人日 | 优先级 |
|---|---|---|---|---|---|
| **G1** | 结构域完全缺失进度与取消 | 4 GB 载体注入/还原时 GUI 卡住转圈且无法取消 | 基于 `io::copy` 收敛点封装 `ProgressWriter`，不改动 10 个具体格式适配器 | 1.5–2.0 | **P0** |
| **G2** | 双域诊断与智能提取被关在 CLI 内部 | GUI 打开文件无法一键检测载荷类型 | 将诊断聚合提至 `StrHide` 门面（`inspect_any` / `smart_extract`），公开强类型 `DualInspect` | 1.0–1.5 | **P0** |
| **G3** | i18n 仅翻译类别，细节为硬编码英文；语言绑在 `thread_local` | 后台 worker 线程翻译失效；UI 中英文混排 | 废除 `thread_local` 改用显式上下文；高频错误与 Warning 结构化；`Msg` 增加稳定 ID | 2.0–3.0 | **P0** |
| **G4** | 内容域缺失轻量级文件 API；两域参数不对称 | 列表页想测隐写容量必须全量 `fs::read` 数 GB 视频 | 补充有界扫描的 `inspect_carrier_file`；引入 `FileTarget` 结构体替换裸 `bool` 参数 | 1.5–2.0 | **P1** |
| **G5** | 批量执行器直接调用终端打印且单错即崩 | 批量任务无法获取明细进度与结果列表 | 在 `core` 实现纯净的 `run_batch`，移除终端宏，支持“出错继续”与并发度控制 | 1.5–2.0 | **P1** |
| **G6** | 敏感密码在 Debug 日志中泄露；缺乏表单脏检查 | UI 调试或日志捕获时凭据外泄 | 手写 `Debug` 脱敏处理；`EmbedOptions` 补 `PartialEq`；`strategy` 强类型化 | 1.0–1.5 | **P1** |
| **G7** | 根目录残留模块与缺乏自动边界守卫 | 代码组织不规整；双域边界易再次隐式劣化 | 根目录非必要模块归位 `core/`；编写 `import_lint.py` 自动化检测 | 2.0–3.0 | **P2** |

**工期总计**：P0 阶段（G1–G3）耗时约 **4.5–6.5 人日**，即可完全解锁 GUI 核心单文件写/读/还原主流程；P1 阶段（G4–G6）耗时约 **4.0–5.5 人日**，解锁批量管理与列表展示；P2 阶段（G7）耗时约 **2–3 人日**。

---

## 一、方案详述与实施蓝图

### 1. 结构域接入控制与进度上报（G1 - P0）

#### 1.1 问题定位
- 源码证据：[`rust/src/structure/options.rs`](file:///c:/Home/Projects/strhide/rust/src/structure/options.rs) 中的 `WriteOptions`、`ReadOptions`、`RestoreOptions` 无 `control` 字段；
- 结构域的还原过程包含三个完整大阶段：`Strip`（剥离）、`Verify`（全量 SHA-256 校验）、`Backup`（复制备份），对于大文件（如 4 GB 的视频或可执行文件）操作耗时达数十秒，但全程零进度、无法被 `CancelToken` 打断。

#### 1.2 解决方案：无侵入式包装 Writer
避免修改 10 个具体格式适配器（PNG, JPEG, MP4, PE, ZIP 等）的实现，而是利用所有结构域写入与拷贝最终都经过 [`rust/src/structure/adapters/io.rs`](file:///c:/Home/Projects/strhide/rust/src/structure/adapters/io.rs) 的特性，在 `core/control.rs` 引入计数包装器：

```rust
// rust/src/core/control.rs
pub const PROGRESS_CHUNK_SIZE: u64 = 4 * 1024 * 1024; // 每 4 MiB 上报一次

pub struct ProgressWriter<'a, 'c, W: std::io::Write + ?Sized> {
    inner: &'a mut W,
    control: Control<'c>, // Control 是 Copy，按值传递
    stage: Stage,
    total: u64,
    done: u64,
    next_report: u64,
}

impl<W: std::io::Write + ?Sized> std::io::Write for ProgressWriter<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.control.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "operation cancelled by user",
            ));
        }
        let n = self.inner.write(buf)?;
        self.done += n as u64;
        if self.done >= self.next_report {
            self.control.report(Event::progress(self.stage, self.done, Some(self.total)));
            self.next_report = self.done + PROGRESS_CHUNK_SIZE;
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
```

- **引擎调用接入**：在 `structure/engine.rs` 的 `write_carrier_with` 和 `remove_carrier_with_dialect` 中，总数据量在操作前即已精准获知（`total = host_size + ube_total_size`），包装 `ProgressWriter` 传入适配器即可提供精确到字节的确定性进度更新。
- **取消信号捕获**：外层捕获 `ErrorKind::Interrupted` 并由 `control.is_cancelled()` 校验，转换为 `StrHideError::Cancelled`，利用外层的 `TmpGuard` 自动回滚并删除临时文件。

---

### 2. 统一双域门面与智能提取抽象（G2 - P0）

#### 2.1 问题定位
- 源码证据：CLI 的 `cli/cmd_diag.rs` 和 `cli/cmd_structure.rs` 内部实现了结构域向内容域的错误重定向与聚合，但外部库只有 `engine.structure()` 和 `engine.stego()`，没有综合诊断和自适应提取接口。
- `DualInspectResult` 属于 `pub(crate)` 私有类型，外部调用方必须自己重新拼装。

#### 2.2 解决方案：上沉双域动词至 `facade.rs`
在 [`rust/src/facade.rs`](file:///c:/Home/Projects/strhide/rust/src/facade.rs) 中为 `StrHide` 补充全域公共 API：

```rust
// rust/src/facade.rs
#[derive(Debug, Clone, Serialize)]
pub struct DualInspect {
    #[serde(flatten)]
    pub structure: InspectResult,
    #[cfg(feature = "content-base")]
    #[serde(rename = "content_stego", skip_serializing_if = "Option::is_none")]
    pub content: Option<StegoHeaderInfo>,
    #[cfg(feature = "content-base")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_error: Option<ErrorDetail>,
}

pub struct SmartExtractOptions<'a> {
    pub password: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub control: Control<'a>,
}

impl StrHide {
    /// 一站式文件诊断：自动利用 CAPABILITIES 表格判定格式，并行/串行探测结构域与内容域
    pub fn inspect_carrier(&self, path: &Path, opts: &DualOptions<'_>) -> Result<DualInspect, StrHideError>;

    /// 智能提取：先快速探测结构域信封，未命中则自动探测内容域特征头并完成解密提取
    pub fn smart_extract(&self, path: &Path, opts: &SmartExtractOptions<'_>) -> Result<Payload<'static>, StrHideError>;
}
```

- **依赖治理**：分派严格基于 [`formats::capability::CAPABILITIES`](file:///c:/Home/Projects/strhide/rust/src/formats/capability.rs#L54)，仅对 `format.supports_stego()` 为真的格式调用内容域，绝不依靠“捕获异常”来探测格式；
- **CLI 瘦身**：CLI 的 `cmd_diag.rs` 彻底转变为该门面方法的薄调用者，彻底消除重复维护风险。

---

### 3. 本地化脱离 `thread_local` 与错误结构化（G3 - P0）

#### 3.1 问题定位
- 源码证据：[`rust/src/core/i18n/mod.rs`](file:///c:/Home/Projects/strhide/rust/src/core/i18n/mod.rs#L48) 存在静态 `CURRENT: Cell<Lang>`；
- GUI 前端若将耗时解密/编码放在 Rayon 或独立线程池中执行，`t!` 宏默认退化为英文；
- `Warning`、`RestoreMismatch` 等错误直接生成英文排版长字符串，GUI 无法提取关键数值（如“损坏大小/实际大小/预期哈希”）。

#### 3.2 解决方案：显式上下文与结构化枚举
1. **显式传参 `RenderCtx`**：
   ```rust
   // rust/src/core/i18n/mod.rs
   #[derive(Debug, Clone, Copy, Default)]
   pub struct RenderCtx {
       pub lang: Lang,
   }

   impl Msg {
       pub const fn id(self) -> &'static str {
           // 提供稳定、无歧义的字符串键（如 "ErrPassword"），供 GUI 前端索引自己的 JSON 翻译文件
           match self { $(Msg::$name => stringify!($name),)* }
       }
   }
   ```
2. **高频错误细分**：
   重构高频错误变体，避免直接格式化为整句英文：
   ```rust
   pub enum StrHideError {
       // ...
       AlreadyExists(PathBuf),
       RestoreMismatch {
           restored_size: u64,
           expected_size: u64,
           restored_sha256: String,
           expected_sha256: String,
       },
       CapacityExceeded {
           tier: SafetyLevel,
           required_bytes: usize,
           available_bytes: usize,
       },
   }
   ```
   使得 GUI 能够针对 `AlreadyExists` 弹出带有文件路径的确认弹窗，针对 `CapacityExceeded` 绘制红色容量超限刻度条。

---

### 4. 消除内存峰值与对称文件 API（G4 - P1）

#### 4.1 问题定位
- 源码证据：内容域的 `inspect` 和 `verify` 只接受 `&[u8]`（[`rust/src/stego/mod.rs`](file:///c:/Home/Projects/strhide/rust/src/stego/mod.rs#L237)）；
- GUI 若想在载体列表加载时探测 20 个大体积 MP4/HEVC 视频的隐写状态，必须把每个视频整体读进内存，峰值内存将瞬间冲破数十 GB。

#### 4.2 解决方案：窗口化文件级诊断
1. **有界读取诊断**：实现 `inspect_carrier_file(&Path)` 与 `verify_carrier_file(&Path)`：
   - 借鉴 [`rust/src/analysis.rs`](file:///c:/Home/Projects/strhide/rust/src/analysis.rs#L50-L64) 的成熟窗口扫描设计（`PREFIX_WINDOW = 1 MiB`，`TAIL_WINDOW = 64 KiB`）；
   - 绝大多数容器（ISOBMFF moov/uuid、JPEG APP15、PNG IEND 前 chunk）的特征头均落在首尾窗口中；
   - 使得单次诊断内存上限严格控制在 **≤ 8 MiB**。
2. **参数结构化**：
   使用强类型 [`FileTarget`](file:///c:/Home/Projects/strhide/rust/src/facade.rs) 代替包含多个裸布尔值的散装参数：
   ```rust
   pub struct FileTarget<'a> {
       pub output: Option<&'a Path>,
       pub backup: bool,
       pub preserve_time: bool,
       pub overwrite: bool,
   }
   ```

---

### 5. 纯净与非阻塞的批量编排器（G5 - P1）

#### 5.1 问题定位
- 源码证据：[`rust/src/core/pipeline.rs`](file:///c:/Home/Projects/strhide/rust/src/core/pipeline.rs#L45-L62) 包含 `println!` 与 `eprintln!`；
- 串行阻塞且一旦某个载体失败即直接返回 `Err`，丢失批处理中间状态。

#### 5.2 解决方案：引入事件流与批量结果收集
在 `core/batch.rs` 建立无副作用的调度器：

```rust
// rust/src/core/batch.rs
pub struct BatchConfig {
    pub continue_on_error: bool,
    pub max_concurrency: usize,
    pub cancel: Option<Arc<CancelToken>>,
}

pub struct ItemReport<T> {
    pub path: PathBuf,
    pub elapsed: std::time::Duration,
    pub result: Result<T, StrHideError>,
}

pub struct BatchReport<T> {
    pub items: Vec<ItemReport<T>>,
    pub total_succeeded: usize,
    pub total_failed: usize,
    pub is_cancelled: bool,
}

pub fn execute_batch<T: Send, F>(
    items: &[PathBuf],
    config: &BatchConfig,
    action: F,
) -> BatchReport<T>
where
    F: Fn(&Path, &Control<'_>) -> Result<T, StrHideError> + Send + Sync;
```
- 所有日志与终端打印下推到 CLI 的 render 层；
- 批量执行能够由 GUI 随时中止（Cancellation），并在 UI 进度表格中逐行显示完成/失败状态。

---

### 6. 安全加固与配置人体工学（G6 - P1）

1. **密码敏感信息脱敏**：
   对 `WriteOptions`、`ReadOptions`、`EmbedOptions`、`ExtractOptions` 实现定制的 `std::fmt::Debug`：
   ```rust
   f.debug_struct("WriteOptions")
       .field("output_path", &self.output_path)
       .field("password", &self.password.map(|_| "<redacted>"))
       .finish()
   ```
   防止开发人员调用 `println!("{:?}", opts)` 或日志框架把用户的隐写密码写入磁盘日志。
2. **支持表单脏检查**：
   为 `EmbedOptions`、`StegoTuning`、`SpatialAlgorithm` 补齐 `PartialEq`，使 GUI 前端能够即时判断“用户是否修改了默认算法调优参数”，并相应高亮“保存配置/恢复默认”按钮。

---

## 二、验收护栏与质量门禁

实施上述改造时，必须严格执行原项目护栏与回归约束：

```bash
# 1. 基础静态检查与无警告门禁
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features

# 2. 最小构建隔离性（确保 core 与各域未反向泄露）
cargo build --no-default-features --features structure-base
cargo build --no-default-features --features content-png
cargo build --no-default-features --features content-jpeg
cargo build --no-default-features --features content-hevc
cargo build --no-default-features --features analysis

# 3. 字节级绝对基线一致性（最核心硬指标）
python scripts/baseline_hash.py --check
```

- **硬性断言**：在任何 options 中添加 `control` 字段或包装 `ProgressWriter` 之后，`baseline_hash.py --check` 必须保持 58/58 全绿，验证**输出文件的每个字节没有发生任何意外漂移**。

---

## 三、文档索引与关联

本文与以下技术文档互为佐证，并作为项目前端就绪度的官方设计蓝图：
- 完整技术审计依据与实测行号：[`docs/gui_frontend_readiness_plan_20261027.md`](file:///c:/Home/Projects/strhide/docs/gui_frontend_readiness_plan_20261027.md)
- 重构主路线图对照：[`docs/strhide_architecture_and_refactoring_plan.md`](file:///c:/Home/Projects/strhide/docs/strhide_architecture_and_refactoring_plan.md)
