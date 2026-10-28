# GUI 前端就绪度复核与补齐方案（2026-10-27 22:38，22:50 合并并行评审）

**基线**：`strhide 0.7.3`，`rust/src` 约 44,000 行，重构计划 `strhide_architecture_and_refactoring_plan.md` 阶段 0–4 已全部落地。
> 版本注记：本次复核开始时工作区为 `0.7.2`；期间提交 `e276954`（2026-10-27 22:30:10）将其升为 `0.7.3`，本文所有行号已按 `0.7.3` 复核。两份并行评审文档的合并记录见 §附录 B。

**复核视角**：不写"库好用不好用"，只回答一个问题——**用这个库写一个 GUI（Tauri / iced / egui，或 C/FFI 跨语言绑定），今天会在哪里被迫重写、哪里会踩坑、怎么补**。
**性质**：本文只给设计与验收口径，不含代码改动。文中 `文件:行号` 均为 2026-10-27 对源码的实测核对结果。

---

## 零、结论

重构把"两域物理隔离 + feature 可裁 + 能力表单一真值源 + 结构化结果"做到了，**作为 CLI 后端的库是健康的**；但计划 §五「前端就绪层」只落地了约一半。缺口按优先级分三档，共十项：

| # | 缺口 | 一句话后果 | 优先级 |
|---|---|---|---|
| G1 | 结构域零进度、零取消 | 写/还原 4 GB 载体时 GUI 无法显示进度也无法中断 | P0 |
| G2 | 双域诊断聚合只存在于 CLI 且为私有类型；没有"自动判域提取" | "打开文件"页要重写 CLI 逻辑；"提取"按钮不知道该走哪个域 | P0 |
| G3 | i18n 只翻译类别，详情为英文硬编码；语言是 `thread_local` | 中文 GUI 出现"密码错误：No hidden strhide data found in 'a.png'" | P0 |
| G4 | 文件级 API 两域不对称 + 裸 bool 参数 | 想在列表里显示尺寸/容量，必须自己 `fs::read` 整个 2 GB 视频 | P1 |
| G5 | 批量执行器是"打印式"的 | 队列页拿不到逐项结果，库还往 GUI 的 stdout 打字 | P1 |
| G6 | `Debug` 泄漏密码；载荷类型两套；`strategy` 是裸字符串 | 日志写进密码；调用点不可读 | P1 |
| G8 | **容量探测只有取消点，没有阶段进度** | "还能塞多少"这条进度条不动，用户以为卡死 | P1 |
| G9 | **`panic = "abort"` + Windows 文件占用** | worker 一次 panic 杀掉整个 GUI；预览着的文件原地写入必失败 | P1 |
| G7 | crate root 残留模块、死导出、边界无强制 | 组织债，双域边界易再次隐式劣化 | P2 |
| G10 | 推荐 feature 组合、文档同步、FFI 形态未定 | GUI 白拖 `analysis`；文档与代码再次漂移 | P2 |

（G8–G10 由并行评审互补与第二轮复核新增，见 §附录 B。）

**结论：P0 三项（G1–G3）共约 5–6.5 人日即可解锁 GUI 单文件主流程**；P1 五项约 6–7.5 人日；P2 两项约 3–4 人日，可与 P1 并行。

---

## 一、复核方法与口径

1. **计划 → 代码逐条对账**：以 `strhide_architecture_and_refactoring_plan.md` §三/§五/§七 的承诺为清单，逐项到源码确认"是否落地、落地到什么程度"。结果见 §二。
2. **反向验证**：不看计划，只看"GUI 真要用会调什么"。以 `facade.rs` 的方法表、`core/` 的公开面、`cli/` 的实际调用为三个入口反推缺什么。
3. **禁用推论**：本文每个结论都附 `文件:行号`；无源码支撑的判断一律标注为"建议"而非"结论"。
4. **参考的既有资料**：`docs/api/ARCHITECTURE.md`（§前端与遗留说明，:271/:559/:576/:603/:616）、`docs/api/STEGO-API.md`、`docs/cli_lib_interface_audit_20261025.md`、`docs/structure_domain_api_guide_20261025.md`、`docs/CHANGES-20261027.md`、`AGENTS.md`（内存与测试口径）。
5. **并行评审合并**：`docs/gui_readiness_summary_and_solutions_20261027.md`（同一轮的第二份评审）逐条比对后合并；采纳 3 项（`smart_extract`、`AlreadyExists`、`CapacityExceeded` 的字段形状），修正其 2 处事实错误，并补出它与我原稿都漏掉的 3 项（G8–G10）。对照见 §附录 B——**不合并差异就等于留下两份互相矛盾的"官方蓝图"**。

---

## 二、计划 §五 落地对照

计划 §五 的六条子项，逐条核对：

| 计划条目 | 承诺 | 现状 | 证据 | 判定 |
|---|---|---|---|---|
| §5.1 归属修正 | i18n/config/批量/控制下沉 `core/` | 已下沉 | `core/{i18n,config,pipeline,control}.rs` 存在 | ✅ 完成 |
| §5.2 进度与取消 | `Control` 进 `EmbedOptions`，**`WriteOptions` 同** | 内容域 5 个 options 都有，**结构域 0 个** | `stego/options.rs:419,614,709,931,1034` vs `structure/options.rs:22,59,103` | ⚠️ 半完成 |
| §5.2 取消语义 | 返回 `Cancelled`、不得 `process::exit`、`TmpGuard` 清理 | 已实现 | `errors.rs:117`、`stego/engine.rs` 20+ 处 `check()` | ✅ 完成 |
| §5.3 结果结构化 | `format: FileFormat`、`strategy: StrategyId`、`Warning` 枚举、`MediaInfo` | 结构域已做；**内容域仍是 `String`** | `structure/engine.rs:396-422` vs `stego/mod.rs:275-276`、`stego/options.rs:892,1011` | ⚠️ 单侧 |
| §5.3 错误结构化 | `ErrorDetail { msg: Msg, args: Vec<..> }` | 实现成 `{ category, detail, hint }`，`detail` 仍是英文整句 | `errors.rs:240-249` | ⚠️ 变体偏离 |
| §5.4 语言去 `thread_local` | `RenderCtx { lang }` 显式传参 | 仍是 `thread_local` + `set_lang` | `core/i18n/mod.rs:48-60`、`cli/mod.rs:108` | ❌ 未做 |
| §5.5 线程池 | `pool: Option<Arc<ThreadPool>>` | 已做 | `stego/options.rs:421` | ✅ 完成 |
| §5.5 预览依赖 | `jpeg-decoder` 提到 `content-jpeg` 或独立 feature | **明确决定不做**，理由记在 ARCHITECTURE.md | `docs/api/ARCHITECTURE.md:616` | ✅ 决策已记录（本文 §六 沿用该决策） |
| §3.4 `HevcParams` 补齐 | 补 HEVC 参数结构 | 只有空结构体 | `stego/options.rs:205` | ✅ 有意为之（文档已说明引擎确实无旋钮） |
| §3.4 `strategy` 强类型化 | — | 结果侧 `StrategyId`，**入参侧仍是 `&str`** | `structure/options.rs:30` | ⚠️ 单侧 |
| §3.2 统一载荷 | 一个载荷类型 | `PayloadSource` 与 `Payload` 并存 | `structure/engine.rs:283`、`core/payload.rs:53` | ⚠️ 未收口 |
| §七-3 边界 lint | 新增 `scripts/import_lint.py` | **不存在** | `scripts/` 仅 6 个 py | ❌ 未做 |

**额外发现（计划外）**：门面在 CLI 中零调用。`cli/` 内直接 `crate::structure::` / `crate::stego::` 共 40 处，`engine.structure()` / `engine.stego()` 0 处。门面目前只被 `tests/test_lifecycle/facade.rs` 与文档示例覆盖——**GUI 会成为它的第一个真实消费者**，这一点直接影响 §三 S2 的取舍。

---

## 三、缺口与解决方案

编号 G1–G12 对应 §七 的排期表。每条给：**证据 → 影响 → 设计 → 影响面/风险 → 验收**。

### G1（P0）结构域没有进度与取消

**证据**

- `WriteOptions`（`structure/options.rs:22-37`）、`ReadOptions:60`、`RestoreOptions:104` 均无 `control` 字段。
- `write_carrier_with`（`structure/engine.rs:1139`）无 control 参数；`adapter.inject(host, &mut ube_cursor, out, &strategy)`（`:1045`）只把 `out: &mut dyn Write` 传下去。
- 内容域对照：`stego/options.rs:419` 等五处都有 `pub control: Control<'a>`。

**影响**

一次结构域操作的真实代价（`remove_carrier_with_dialect`，`:1767-1842`）：

| 阶段 | 读 | 写 | 是否已有总量 |
|---|---|---|---|
| `Strip`：adapters 边读边写 | 载体全量 | 还原结果全量 | ✅ `carrier_size` |
| `Verify`：`File::open(&tmp_target)` 重读 + `compute_stream_sha256`（`:1708`） | 还原结果全量 | — | ✅ `restored_size` |
| `Backup`：`std::fs::copy`（`:1823`，写路径同 `:1207`） | 载体全量 | `.bak` 全量 | ✅ `carrier_size` |

即一个 4 GB 的 MP4/PE 还原 ≈ 5 GB 读 + 5 GB 写，**全程零反馈、零中断**。GUI 只能转圈，用户按"取消"也不起作用——这正是计划 §5.2 开头描述的失败模式，只是当时只处理了内容域。

**设计：包一层 writer，不动 10 个适配器**

关键观察：所有批量拷贝都收敛在 `structure/adapters/io.rs:13`（`copy_exact`）和 `:33`（`copy_stream`），共 36 个调用点、12 个文件；且 `HostAdapter::inject` 的 `out` 只要求 `Write`（`adapters/mod.rs:173-179`），`strip` 要求 `Write + Seek`（`:207`）。因此**在引擎侧包一层计数 writer 即可**，适配器一行不改，字节流完全不变。

```rust
// 放 core/control.rs：Control 在那里，且 core 不依赖任何格式，位置最干净
pub const PROGRESS_STEP: u64 = 4 << 20; // 4 MiB

pub struct ProgressWriter<'a, 'c, W: Write + ?Sized> {
    inner: &'a mut W,
    control: Control<'c>,   // Control 是 Copy，按值存，避免 &Control<'a> 的双重生命周期纠缠
    stage: Stage,
    total: u64,
    done: u64,
    next: u64,
}

impl<W: Write + ?Sized> Write for ProgressWriter<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // 取消用 Interrupted 冒泡，由引擎映射回 Cancelled（见下）
        if self.control.is_cancelled() {
            return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "strhide: cancelled"));
        }
        let n = self.inner.write(buf)?;
        self.done += n as u64;
        if self.done >= self.next {
            self.control.report(Event::progress(self.stage, self.done, Some(self.total)));
            self.next = self.done + PROGRESS_STEP;
        }
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> { self.inner.flush() }
}
```

引擎侧（`structure/engine.rs:1042-1046`）：

```rust
let total = host_size + ube_total_size;           // 两个数在 inject 前均已确定
let mut sink = ProgressWriter::new(out, options.control, Stage::Write, total);
adapter.inject(host, &mut ube_cursor, &mut sink, &selected_strategy)
    .map_err(|e| map_cancel(&options.control, e))?;
```

```rust
// Io(Interrupted) + token 已置位 → Cancelled；其余原样透传，不吞真实 I/O 错误
fn map_cancel(control: &Control<'_>, e: StrHideError) -> StrHideError {
    match e {
        StrHideError::Io(ref io)
            if io.kind() == std::io::ErrorKind::Interrupted && control.is_cancelled() =>
        {
            StrHideError::Cancelled
        }
        other => other,
    }
}
```

`strip` 与 `verify_restored` 的哈希重读用同一思路：

- `strip` → `ProgressSeekWriter`（`Write + Seek` 前向转发，`SeekWrite` 是 blanket impl，见 `adapters/mod.rs:66`），`Stage::Write`，total = 载体大小。
- `verify_restored`（`:1699`）→ `Stage::Verify`，total = `restored_size`（先 `seek(End(0))` 已拿到，`:1706`）。
- `Backup` 的 `std::fs::copy` 换成自写的 `copy_exact` + 计数（`fs::copy` 无法插桩），`Stage::Write`。
- `ReadOptions` 的载荷解密/解压按分块循环（`crypto` chunk）报 `Stage::Decode`。

**四个取舍要说清**

1. **粒度优于计划**：计划 §5.2 写"粒度到阶段，不强求精确到字节"，那是因为 HEVC CABAC 无法预知总量。结构域相反——三个阶段的总量都在动手前已知，**可以做到字节级进度**，白拿的收益。
2. **不做"边写边算哈希、省掉第二遍"**：`verify_restored` 重读的是**落盘后的临时文件**，语义是"磁盘上的字节确实等于原文"，边写边算会退化成"我以为写下去的字节"。省一遍是 20% 的性能，赌的是正确性语义，不在 P0 做。
3. **`Control` 必须在 options 里而不是方法参数**：`Control` 是 `Copy`（`core/control.rs:165`），加进 `WriteOptions`/`ReadOptions`/`RestoreOptions` 后三者仍是 `Copy`，不破坏现有调用形态。
4. **取消点必须排在 backup/rename 之前**（并行评审未覆盖的时序细节）。今天写路径的顺序是 `inject` → `.bak` 复制（`:1207`）→ `rename`，还原路径是 `strip` → `verify` → `.bak` 复制（`:1823`）→ `rename`。`TmpGuard`（`commit.rs:59`）只守临时文件，**不守 `.bak`**：如果在"已复制 .bak、尚未 rename"之间插入取消点，用户会得到一个"原文件没变、但多出一个 .bak"的中间态。约定：**`.bak` 复制与 `rename` 视为不可取消的提交区间**，取消检查只放在它之前；若将来确实需要在提交区间内响应取消，必须先把 `TmpGuard` 扩展成多路径守卫（同时登记 tmp 与 bak）。

**影响面**：`structure/options.rs`（3 个字段 + Default）、`structure/engine.rs`（write/read/remove 三条路径）、新增 2 个小类型。适配器、信封、线格式零改动。

**验收**

- `python scripts/baseline_hash.py --check` 全绿（这条最重要：证明写出的字节一个都没变）。
- 新增测试：① 取消发生在 `Stage::Write` 中途 → 返回 `Cancelled`，且目标路径不存在（或原地文件的 mtime/sha256 未变）；② 进度事件单调不减，最后一条 `done == total`；③ `Control::none()` 下行为与今天完全一致（用基线兜底）。

**工作量**：1.5–2 人日（含测试）。

---

### G2（P0）双域诊断聚合长在 CLI 里，且是私有类型

**证据**

- `DualInspectResult` / `DualVerifyResult` 定义在 `cli/render.rs:108,147`，`pub(crate)`。
- 聚合逻辑在 `cli/cmd_diag.rs` 内**重复 4 次**：单文件 inspect（`:44-50`）、批量 inspect（`:91-103`）、单文件 verify（`:215-222`）、批量 verify（`:257-268`）。
- 每次都为内容域 `std::fs::read(carrier)` 整文件再读一遍（`:46`、`:94`、`:216`、`:266`）。
- 计划 §4.1 决定"聚合发生在 CLI"，但没预料到 GUI 是第二个消费者。

**影响**

GUI 的"打开文件"页面需要一次调用回答：格式是什么、结构域有没有信封、内容域有没有载荷、各自能不能写。今天只能：自己 `structure::inspect` + 自己 `fs::read` + 自己 `stego::inspect` + 自己决定谁失败该降级——**与 CLI 四份代码各写一遍，必然漂移**（哪天空了 `base-off` 的降级策略，两处就不一致）。

**设计：把"动词"上移到 facade，CLI 改为消费者**

不新建独立模块，直接给门面补双域动词——**这同时解决"门面零真实消费者"的问题**（§二末尾）。

```rust
// facade.rs（无条件编译；方法按 feature 门控）
#[derive(Debug, Serialize)]
pub struct DualInspect {
    #[serde(flatten)]
    pub structure: InspectResult,
    /// 字段名与今天的 `--json` 键 `content_stego` 保持一致（rename 而不是改键）。
    #[cfg(feature = "content-base")]
    #[serde(rename = "content_stego", skip_serializing_if = "Option::is_none")]
    pub content: Option<StegoHeaderInfo>,
    /// 内容域"尝试过但失败"的原因；None 表示没尝试（格式不支持）或成功。
    #[cfg(feature = "content-base")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_error: Option<ErrorDetail>,
}

pub struct DualOptions<'a> {
    pub password: Option<&'a str>,
    pub domain: Option<&'a str>,
    pub exact: bool,
    pub control: Control<'a>,
}

impl StrHide {
    pub fn inspect_any(&self, carrier: &Path, o: &DualOptions<'_>) -> Result<DualInspect, StrHideError>;
    pub fn verify_any(&self, carrier: &Path, o: &DualOptions<'_>) -> Result<DualVerify, StrHideError>;
    pub fn inspect_any_bytes(&self, bytes: &[u8], o: &DualOptions<'_>) -> Result<DualInspect, StrHideError>;
    pub fn verify_any_bytes(&self, bytes: &[u8], o: &DualOptions<'_>) -> Result<DualVerify, StrHideError>;
}
```

三条内部规则（从 `cmd_diag` 提炼，写一次）：

1. 先跑结构域；结构域失败即整体失败（信封解析错误是硬错误）。
2. 仅当 `format.supports_stego()`（`formats/capability.rs:145`）才尝试内容域——**用能力表判断，不用"试一下看报什么错"**。
3. 内容域失败降级为 `content: None` + `content_error: Some(..)`，不再 `.ok()` 静默吞掉。今天 CLI 用 `.ok()`（`:49`）丢掉了原因，GUI 需要能显示"为什么没查到"。

`--json` 兼容：`#[serde(flatten)]` 让字段名与今天的 `DualInspectResult` 完全一致，`--json` 输出逐字段不变（计划 §九 对这一项有明确要求）。

**补充：自动判域提取 `smart_extract`（采纳并行评审的提议，并修掉它的三个漏洞）**

CLI 有两个动词 `read`（结构域）/ `extract`（内容域），但 GUI 只有一个"提取"按钮——用户不该知道载荷是哪个域写进去的。所以要一个自动判域动词：

```rust
pub enum Domain { Structure, Content }

pub struct SmartExtractOptions<'a> {
    pub password: Option<&'a str>,
    pub domain: Option<&'a str>,
    /// 错误密码可能触发 PBKDF2；GUI 必须能封顶，否则"密码错了"会变成"卡了 30 秒"。
    pub limits: ExtractParams,
    /// 明确偏好顺序；None = 结构域优先。
    pub prefer: Option<Domain>,
    pub control: Control<'a>,
}

pub struct ExtractOutcome {
    pub payload: Payload<'static>,
    pub source: Domain,
    /// 另一个域**也存在**载荷时填它，避免 GUI 静默丢掉第二份数据。
    pub also_present: Option<Domain>,
}

impl StrHide {
    pub fn smart_extract(&self, carrier: &Path, o: &SmartExtractOptions<'_>) -> Result<ExtractOutcome, StrHideError>;
}
```

三个必须做对的地方（并行评审的草案没有覆盖）：

1. **同一文件可能两个域都有载荷。** PNG 可以既有 `prIv` 信封（结构域）又有像素隐写（内容域），两者互不影响。`smart_extract` 若只返回一份 `Payload` 而不报告另一个域的存在，UI 就会帮用户丢掉一份数据。做法：内部先跑一次 `inspect_any`（便宜），据此决定走哪个域，并把另一域的状态放进 `also_present`；两域都有时按 `prefer`（默认结构域——信封带完整元数据与还原校验）取一份，另一个由 UI 提示"另有一份内容域载荷，可切换提取"。
2. **`limits` 不能省。** 内容域 `ExtractOptions.limits: ExtractParams`（`stego/options.rs:707`）控制"试哪些 cipher suite、PBKDF2 最多迭代多少次"。GUI 上错误密码是常态，没有上限就是一次 30 秒的假死。
3. **必须复用 `inspect_any`，不要"试一次看报什么错"。** 靠捕获 `NoHiddenData` 来决定走哪个域，会在"两个域都没有"时把两次失败的原因丢掉一半，也会在"结构域有但是 stealth 密码不对"时误判为"没有"，转而去内容域白跑一遍全量解码。

**影响面**：`facade.rs` +120 行（含 `smart_extract` +40）；`cli/cmd_diag.rs` 四个副本改为调用门面，净减约 150 行；`cli/render.rs` 的两个 `pub(crate)` 结构体删除；`cli/cmd_structure.rs` 的 `read` 增加 `--smart` 走同一路径（可选）。

**验收**

- `--json` 输出与改动前逐字段 diff 为空（用固定语料跑一次对比样例，落 `temp/`）。
- 新增测试：PNG（双域都有）、ZIP（仅结构域，`content` 必须为 `None` 且 `content_error` 为 `None`）、损坏的 MP4（`content_error` 有值但整体 `Ok`）。
- `smart_extract` 专测：① 只有结构域；② 只有内容域；③ 两域都有 → `also_present == Some(另一个域)`；④ 都没有 → `NoHiddenData` 且 `content_error` 保留原因。

**工作量**：1.5–2 人日（`smart_extract` 让这一项从 1–1.5 涨到 1.5–2）。

---

### G3（P0）i18n：只翻译了类别，且语言是 `thread_local`

**证据**

- `core/i18n/mod.rs:48` `thread_local! { static CURRENT: Cell<Lang> }`，`set_lang`（`:53`）只作用于当前线程；CLI 在 `cli/mod.rs:108,159,170` 设一次。
- `t!` 宏（`core/i18n/mod.rs:93`）内部读 `lang()`，共 **71 处**调用，分布在 7 个文件（`cli/render.rs`、`cmd_*.rs`、`helpers.rs`、`core/pipeline.rs`、`core/config.rs`）。
- `ErrorDetail.detail` 是英文（`errors.rs:246`）；全库 `StrHideError::*(format!` 共 **208 处**（stego 102 / structure 64 / crate root 26 / core 12 / cli 16）。
- **GUI 必显但只有英文字符串**的字段：

| 字段 | 位置 | 内容示例 |
|---|---|---|
| `Warning::message()` | `structure/engine.rs:368` | `Hidden data envelope (1380 bytes) is 68.3% of the carrier file size ...` |
| `LevelStatus.detail` | `structure/engine.rs:491` | 各层英文诊断句 |
| `WriteResult.strategy_note` | `structure/engine.rs:406` | 自动回退说明 |
| `StrategyCapacity.limit` / `note` | `structure/adapters/mod.rs:108-112` | `≤ 2,147,483,647 B (2 GiB - 1)` / `carrier-dependent (.text density + zero slack)` |
| `StegoHeaderInfo.note` | `stego/options.rs:912` | 英文备注 |
| `VerifyLevel.{name,message}` | `stego/options.rs:980` | 层级名与英文消息 |
| `ScanReport.verdict` / `notes` | `analysis.rs:131-160` | `likely-hidden` + 英文注意事项 |

（`Warning::message()` 目前只有一个消费者：`cli/render.rs:198`，改造是 1 行。）

**影响**

中文 GUI 的现象：类别翻好了，详情仍是英文，混排；`Warning`/`StrategyCapacity` 这类**必显**内容翻不了；worker 线程里 `t!` 拿到的永远是英文；`Msg` 没有稳定标识，GUI 想用**自己的**翻译表也无从索引。

**设计：三件事，边界清楚**

**(1) 删 `thread_local`，改显式 `RenderCtx`**（计划 §5.4 原案）

```rust
// core/i18n/mod.rs
#[derive(Debug, Clone, Copy, Default)]
pub struct RenderCtx { pub lang: Lang }
impl RenderCtx {
    pub const fn new(lang: Lang) -> Self { Self { lang } }
    pub fn text(self, msg: Msg) -> &'static str { msg.text(self.lang) }
}
macro_rules! t {
    ($ctx:expr, $msg:path) => { $msg.text($ctx.lang).to_string() };
    ($ctx:expr, $msg:path, $($k:ident = $v:expr),+ $(,)?) => { /* 同今天，lang 取 $ctx */ };
}
```

71 处调用点机械替换；`cli::run_cli_with` 构造一个 `RenderCtx` 往下传。`set_lang`/`lang()` 删除（未发布，不留兼容层）。

**(2) `Msg` 加稳定 id**

`i18n_messages!` 宏（`core/i18n/mod.rs:64`）再生成一个方法：

```rust
impl Msg {
    /// 稳定标识，供前端用自己的翻译表索引。改文案不改 id。
    pub const fn id(self) -> &'static str {
        match self { $(Msg::$name => stringify!($name),)* }
    }
}
```

这样库负责"有哪些消息 + 稳定 key + 英文/中文兜底"，**文案主权交给前端**。GUI 的 `i18n/zh.json` 以 `ErrIo` 这类 key 索引，不依赖库的中文措辞。

**(3) 必显字段去英文化（有界清单）**

给上表 7 个字段加 `render(&RenderCtx) -> String`，配套把散文换成"`Msg` + 数值字段"，`Display` 保持英文原样：

```rust
// structure/engine.rs
impl Warning {
    pub fn render(&self, ctx: &RenderCtx) -> String {
        match self {
            Warning::SizeInflation { ube_size, host_size, ratio_pct } => format_msg(
                Msg::WarnSizeInflation.text(ctx.lang),
                &[("ube", ube_size), ("host", host_size), ("pct", ratio_pct)],
            ),
            Warning::SuspiciousStructures { hints } => /* 同上 */,
        }
    }
    /// 历史英文句子，CLI 与日志用；等价于 render(&RenderCtx::new(Lang::En))。
    pub fn message(&self) -> String { self.render(&RenderCtx::new(Lang::En)) }
}
```

`Msg` 目录（`core/i18n/messages.rs`，今天 172 条）预计新增 **20–25 条**即可覆盖上表。

**明确不做：不逐条翻译 208 条引擎错误详情。** 那 208 句夹着索引、偏移、表名，翻译维护成本远超收益。改为：

- `StrHideError::kind() -> ErrorKind`：稳定判别枚举（比 match 变体更适合跨 FFI/JSON 的前端）。
- 把 6 个高频变体**结构化**，让 GUI 用"自己的语言 + 库给的数字"渲染建议：

```rust
NoHiddenData { hints: Vec<String> }                       // 今天: NoHiddenData(String)，提示句拼在字符串里
UnsupportedFormat { detected_magic: Option<[u8; 4]>, supported: &'static [&'static str] }
RestoreMismatch { restored_size: u64, expected_size: u64,
                  restored_sha256: String, expected_sha256: String,
                  residual_envelope: bool }               // 今天: 4 个值拼成多行英文串（engine.rs:1738-1750）
CapacityExceeded { tier: SafetyLevel,
                   required_bytes: u64, available_bytes: u64 }   // 今天: SafetyThreshold(String)
AlreadyExists(PathBuf)                                    // 今天: Rejection(String)，路径埋在句子里
TargetBusy(PathBuf)                                       // 新增，见 G9：Windows 上文件被占用
```

两处字段形状是并行评审提出、我原稿漏掉的，采纳并说明理由：

- **`AlreadyExists(PathBuf)`**：这是 GUI 最高频的错误——"目标已存在"要弹一个带路径的确认框（覆盖 / 改名 / 取消），今天只能从 `Rejection(String)` 的句子里正则抠路径（`core/pipeline.rs:126`、`facade.rs:498-503` 两处各拼一遍）。结构化后 `--overwrite` 的交互才写得干净。
- **`CapacityExceeded { required_bytes, available_bytes }`**：容量超限的 UI 是一条"需要 12.4 MB / 可用 8.0 MB"的对比条，`required`/`available` 是它真正需要的两个数；我原稿写的 `{ tier, limit, actual }` 表述含糊，采纳评审的字段名。`tier` 保留，因为不同安全档的可用量不同，UI 要显示"在 paranoid 档下超限、balanced 档下可以"。

`RestoreMismatch` 这条尤其值得做：GUI 需要"期望 vs 实际"两行对照表，今天只能正则拆字符串。

**顺带解决 Tauri/IPC 的最后一个卡点**：`ErrorDetail` 目前不可序列化（`errors.rs:240` 无 `Serialize`）。而 `Msg::id()`（上面 (2)）恰好给了它稳定键——两件事一起做，`ErrorDetail` 就能直接过 IPC：

```rust
#[derive(Serialize)]
struct WireError<'a> { kind: &'a str, category: Option<&'a str>, detail: &'a str, hint: Option<&'a str> }
// kind = ErrorKind 的稳定名，category = Msg::id()，detail 是引擎技术细节（英文），
// 前端按 (kind, category) 查自己的文案表，detail 作为"技术详情"折叠显示。
```

**这是 `Msg::id()` 的第二个用途**：它不只是给 i18n 用，也是错误跨进程序列化的主键。没有它，`Msg` 只能在 Rust 侧 `match`，Tauri 的命令返回值里就只能塞英文整句。

**影响面**：`core/i18n/{mod,messages}.rs`、7 个 `t!` 调用文件、`structure/engine.rs` 的 Warning/LevelStatus、`adapters/mod.rs` 的 StrategyCapacity、`errors.rs` 的 6 个变体 + `ErrorDetail` 的 `Serialize`。**这是本文改动面最广的一项**，但每一步都是机械替换，可分开提交。

**验收**

- `Lang::En` 下所有 `render()` 输出与今天的 `message()` **逐字节相同**（专门写一个对照测试，防"重构顺手改了英文文案"）。
- `cargo build --no-default-features --features structure-base` 通过（证明 `core/i18n` 不牵连 content/cli）。
- 71 处 `t!` 替换后 `cargo clippy --all-targets --all-features -D warnings` 无新增告警。

**工作量**：2–3 人日。

---

### G4（P1）文件级 API 两域不对称 + 裸 bool

**证据**

- 内容域只有 `embed_carrier_file`（`stego/io.rs:31`）、`extract_carrier_file_payload`（`:59`）；**没有** `probe/inspect/verify` 的 file 版本，三者都吃 `&[u8]`（`stego/mod.rs:237,255,367`）。
- 门面对应：`embed_file(carrier, target, payload, options, backup: bool)`（`facade.rs:454`）、`extract_file(carrier, output, options, overwrite: bool)`（`:478`）——两个裸 bool。
- 结构域相反：`read_file` 在 `output_path == None` 时直接把载荷返回内存（`structure/options.rs:60-62` 的语义），file/bytes 两条路径成对出现（`facade.rs:274-379`）。

**影响**

- 列表页想显示"1920×1080、能塞多少"：得自己 `std::fs::read` 一个 2 GB 的 MP4 再喂 `probe`。
- 两域内存模型相反（结构域流式 O(1)，内容域整文件进内存，`stego/io.rs:39`），但 API 不表达这个差异，GUI 无法据此安排并发。
- 裸 bool 在调用点不可读：`embed_file(p, None, &pl, &opt, true)` 的 `true` 是什么，看签名才知道。

**设计**

**(a) 补 file 版本，并按"要不要整文件"分两类命名与文档**

| 函数 | 内存 | 说明 |
|---|---|---|
| `inspect_carrier_file` / `verify_carrier_file` | **有界**（头 1 MiB + 尾窗口） | 三种格式的头部与尾部足够判定，`analysis.rs:50-53` 已有同款做法（`MAX_FULL_SCAN` 64 MiB、`PREFIX_WINDOW` 1 MiB、`STRUCT_TAIL_WINDOW`） |
| `probe_carrier_file` / `embed_carrier_file` | **O(文件大小)** | 必须全量解码，文档首行写明，不假装流式 |

这一点值得强调：**诊断类 API 可以做到不读整文件**，而今天的 `cmd_diag.rs:46` 恰恰为了 inspect 读整文件。GUI 的列表页对 2 GB 视频做"有没有藏东西"的判定，不该付 2 GB 的代价。

**(b) 用结构体替换裸 bool，两域对齐**

```rust
pub struct FileTarget<'a> {
    /// None = 原地；Some(dir) = 目录内同名；Some(path) = 指定文件
    pub output: Option<&'a Path>,
    pub backup: bool,
    pub preserve_time: bool,
    pub overwrite: bool,
}
impl StrHide::stego() {
    pub fn embed_file(&self, carrier: &Path, payload: &Payload<'_>,
                      o: &EmbedOptions<'_>, t: &FileTarget<'_>) -> Result<FileOutcome, StrHideError>;
    pub fn extract_file(&self, carrier: &Path, o: &ExtractOptions<'_>,
                        t: &FileTarget<'_>) -> Result<FileOutcome, StrHideError>;
}
pub struct FileOutcome { pub written: PathBuf, pub backup: Option<PathBuf>, pub bytes: u64 }
```

顺带修掉一个**硬编码**：`stego/io.rs:42` 的 `commit_carrier_bytes(.., backup, true)` 把 `preserve_time` 写死为 `true`，结构域是可配的（`WriteOptions.preserve_time`）。GUI 的"保留时间戳"勾选框在内容域今天无法生效。

**影响面**：`stego/io.rs` +4 函数、`facade.rs` 方法签名变更、`cli/cmd_stego.rs` 调用点更新（约 6 处）。

**验收**：facade 新增 6 个 `*_file` 方法的集成测试（含"目录输出"与"已存在拒绝"两条路径）；`inspect_carrier_file` 对 >2 GB 的 MP4 峰值内存 ≤ 8 MiB（可用 `--ignored` 的本地测试，语料在 `temp/testhevc/`）。

**工作量**：1.5 人日。

---

### G5（P1）批量执行器是"打印式"的

**证据**

- `core/pipeline.rs:30` `for_each_carrier` 内部 `println!`（`:45,62`）/ `eprintln!`（`:45`），并直接读 `t!` 的线程语言。
- 首错即停（`:57` `return Err(e)`），无逐项结果、无 cancel、无并发上限。
- `core/config.rs:114,132` 同样在库函数里 `eprintln!`（未知配置键、CWD 密码告警）。

**影响**

GUI 拖 20 个文件进队列，只能：自己写循环 + 自己拼汇总 + 自己猜并发度（猜错就 OOM：HEVC 单载体峰值 1.31 GB，见 `AGENTS.md`）。而且库会在 GUI 进程里往 stdout 打字。

**设计：`core::batch`，沿用 `preflight_batch` 的回调模式**

`core` 不得依赖 formats/structure/stego（计划 §2.1 规则 6），所以执行器只收闭包：

```rust
// core/batch.rs
pub struct BatchPlan {
    pub continue_on_error: bool,
    pub max_concurrency: usize,          // 1 = 顺序；0 = 不限
    pub cancel: Option<Arc<CancelToken>>,
}

pub struct ItemOutcome<R> {
    pub index: usize,
    pub item: PathBuf,
    pub result: Result<R, ErrorDetail>,
    pub elapsed: std::time::Duration,
}

pub struct BatchOutcome<R> {
    pub items: Vec<ItemOutcome<R>>,
    pub cancelled: bool,          // 用户取消导致未跑完
}

pub fn run_batch<R, F>(items: &[PathBuf], plan: &BatchPlan, run: F) -> BatchOutcome<R>
where
    R: Send,
    F: Fn(&Path, &Control<'_>) -> Result<R, StrHideError> + Send + Sync;
```

三条约定：

1. **库不打印**：`Msg::FailCarrier` / `SummaryBatch*` 的渲染搬到 `cli/`（`for_each_carrier` 保留为 CLI 侧的薄包装，或直接由 `cmd_*` 消费 `BatchOutcome` 自行打印）。CLI 输出逐字不变由渲染层保证。
2. **并发上限由调用方给**，库不猜。给 GUI 一个可用的默认建议：结构域可 `usize::MAX`（流式），内容域按 `carrier_bytes` 排序后串行。
3. **取消粒度到项**：每项拿到自己的 `Control`，`cancel` 置位后不再启动新项，在跑的项按 G1 的检查点退出；`cancelled: true` 让 UI 能区分"取消"与"失败"。

配套（可选，但很便宜）：`formats::capability` 的 `Capability` 行加一个字段，把"这个域要不要整文件"变成可查询数据——

```rust
pub enum MemoryProfile { Streaming, WholeFile }
pub struct Capability { /* .. */ pub memory: MemoryProfile }
```

GUI 据此在入队时算并发预算，不用把 `AGENTS.md` 里的数字抄进 UI 代码。

**影响面**：新增 `core/batch.rs`（约 200 行）；`core/pipeline.rs` 去掉打印；`cli/cmd_*.rs` 改用 `run_batch`。

**验收**：3 个单元测试（继续执行并收集全部错误、取消后不再启动新项、`max_concurrency` 上限被遵守——用计数器断言）；CLI 批量输出与改动前逐字对比。

**工作量**：1.5–2 人日。

---

### G6（P1）安全与人体工学小项（建议一次做完）

| 项 | 证据 | 设计 |
|---|---|---|
| `Debug` 泄漏密码 | `structure/options.rs:21` + `password: Option<&'a str>`；`stego/options.rs:403` 同 | 手写 `Debug`，`password: <redacted>`；其余字段照常 |
| 无设置脏检查 | `EmbedOptions` 无 `PartialEq`（`WriteOptions` 有，`structure/options.rs:21`） | `StegoTuning` 手写 `PartialEq`，`EmbedOptions: PartialEq` |
| `strategy` 是裸字符串 | `structure/options.rs:30` `strategy: &'a str`，结果侧却是 `StrategyId` | `pub enum Strategy<'a> { Auto, Ask, Named(StrategyId) }`；`FromStr` 供 CLI 复用；`write_carrier_with` 内部解析一次 |
| 载荷两套 | `PayloadSource`（`structure/engine.rs:283`）vs `Payload`（`core/payload.rs:53`） | `impl From<Payload<'_>> for PayloadSource<'_>` + 把 `Stdin` 变体移到 `cli/`（库类型里不该出现进程级 IO）；计划 §3.2 本就要求，未发布可破 |
| 报告元数据无类型 | `InspectResult.metadata: Option<serde_json::Value>`（`engine.rs:483`） | 定义 `EnvelopeMetadata { filename, size, sha256, created_at }`，`Value` 留 `raw` 兜底 |

`HevcParams` 保持空结构体是**正确的**（`stego/options.rs:205` 的注释已说明引擎确实没有可调旋钮），不建议为了"参数看着齐"而造假字段。GUI 的视频高级面板只该显示 `safety` + `exact` 两项；若要动态生成表单，可加 `StegoTuning::knobs() -> &'static [Knob]`（P2，可选）。

**工作量**：1–1.5 人日。

---

### G7（P2）组织残留收尾

| 项 | 证据 | 处置 |
|---|---|---|
| crate root 仍挂 4 个大模块 | `lib.rs:128-130` 自述"a later batch moves under core" | `crypto/errors/params/commit` 移入 `core/`，root 留 `pub use` 一层 |
| 兼容层残留 | `src/sniff.rs`（纯 re-export，520 B）+ `lib.rs:142` | 删除（未发布） |
| 死导出 | `structure/mod.rs:33` 导出 `supports_content_stego`（`registry.rs:57`），全仓 0 调用 | 删除 |
| 文档过期 | `structure/mod.rs:13-18` 仍称"inspect 内联测内容容量、stage 3 才移走" | 改写为现状 |
| 边界无强制 | 计划 §七-3 的 `scripts/import_lint.py` 不存在 | 补脚本 + 进 CI（三条规则：structure↛stego、stego↛structure、core↛{formats,structure,stego,cli}） |
| 巨型文件 | `structure/engine.rs` 2379 行（计划 §2.2 目标约 900） | 拆 `engine/{write,read,verify,result}.rs`；纯搬迁，基线兜底 |
| 过时注释 | `core/payload.rs:11-14`、`stego/mod.rs:222-226` 仍写"stage 3 会做微头" | 微头已落地，删掉将来时 |

**工作量**：2–3 人日（可与 P1 并行）。

---

### G8（P1）容量探测只有取消点，没有阶段进度

**证据**

- 三个引擎的容量探测路径里只有 `control.check()`，没有任何 `stage` / `report`：
  `stego/png/engine.rs:1885`、`stego/jpeg/engine.rs:1496`、`stego/hevc/engine.rs:252`。
- 同一引擎的 embed 路径却有完整四阶段上报：`png/engine.rs:1117,1121,1153,1443`、`jpeg/engine.rs:580,610,654`、`hevc/engine.rs:588,592,774`。
- 变更记录自己承认了这一点：`docs/CHANGES-20261027.md:205`——"阶段上报只加在 embed 路径（Decode→CostMap→Solve→Encode，HEVC Encode 按 slice 携带进度）；extract/probe 目前只有取消检查点，GUI 进度后补"。

**影响**

"这张图还能塞多少"是 GUI 的**核心卖点**，也是最容易被点的一个按钮。而 `probe` 的代价与 embed 同量级：要跑完整代价图（50 MP JPEG 的 `compute_cost` 是数十秒级），`exact = true` 时还要全量扫描而不是采样。结果：用户点"测量容量"，UI 上**一条进度都没有**，只有转圈——正是 G1 要消灭的失败模式，只是换了个按钮。

**设计：与 embed 共用同一批埋点**

`probe` 与 `embed` 走的是同一份代价图与同一份 slot 计算代码（png/jpeg/hevc 各自的 `compute_cost` + registry），所以埋点应放在**共享层**而不是各写一份：

| 阶段 | 上报内容 | total 是否已知 |
|---|---|---|
| `Stage::Decode` | 解析头/尺寸，瞬时 | 未知 → `Event::stage(Decode)` |
| `Stage::CostMap` | 每 N 个 block/像素上报一次 `done` | ✅ PNG 用 `w*h*channels`，JPEG 用 `block_count*64`，HEVC 用切片数 |
| `Stage::Verify`（仅 `exact = true`） | 全量扫描进度 | ✅ 可用 slot 总数 |
| `Stage::Solve`（仅需精确容量时） | slot 网格填充 | ✅ |

`ProbeOptions` 已经有 `control`（`stego/options.rs:614`），**不需要加字段**，只需在引擎里补上报。

**为什么容易漏**：这条不会让任何测试变红，也不会让 GUI "跑不起来"——它只是让最重要的一个按钮永远转圈。属于"不改也能上线、上线就挨骂"的一类。

**影响面**：三个引擎的 probe 函数（各 3–6 处 `control.stage/report`），无 API 变更。

**验收**：50 MP JPEG 上 `probe` 至少上报 `Decode` + `CostMap` 两个 stage，且 `CostMap` 有 ≥ 5 条中间进度、末条 `done == total`；`exact = true` 时多出 `Verify`。

**工作量**：1–1.5 人日。

---

### G9（P1）崩溃语义与 Windows 平台语义

**证据**

- `rust/Cargo.toml:128`：`[profile.release] panic = "abort"`。
- 库内仍有可达 `panic!`/`expect`：`formats/capability.rs:131-136`（`capability_of` 对未登记格式 `panic!`）、`stego/options.rs:105-113`（`SpatialAlgorithm::model()` 两处 `.expect`）、`core/i18n/mod.rs:141`（`debug_assert!(false)`，debug 构建下缺参会 panic）。
- 提交路径不做重试：`commit.rs:170` 直接 `std::fs::rename(&tmp_path, path)?`。

**影响（两条，都很硬）**

1. **`panic = "abort"` 会绕过 `Drop`。** GUI 若沿用这个 release profile，任何一处 worker panic 都会**直接杀掉整个进程**：用户看不到错误对话框，而 `TmpGuard`（`commit.rs:59`）的 `Drop` 不会执行——正好留下 `core/control.rs:19-23` 那段文档警告过的"半成品临时文件"。这与"取消必须返回错误而不是 `process::exit`"是同一条原则的两面，只是 panic 走了另一条路。
2. **Windows 上文件被占用时 `rename` 必失败。** GUI 用 webview 的 `<img>`/`<video>` 预览载体时，文件句柄通常还开着；此时原地写入（或还原）会在 `rename` 处拿到 `ERROR_ACCESS_DENIED(32)` / `ERROR_SHARING_VIOLATION`，错误信息是一句英文 I/O 错误，UI 无法给出"请先关闭预览"的提示。杀毒软件扫描、资源管理器缩略图也会造成同样的间歇失败。

**设计**

1. **GUI 侧 profile 必须是 `panic = "unwind"`**，并在任务边界兜住 panic：

```rust
let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    engine.structure().write_file(&carrier, src, &opts)
}));
let result = match result {
    Ok(r) => r,
    Err(p) => Err(StrHideError::General(format!("internal panic: {}", panic_msg(&p)))),
};
```

   strhide 自己的 `[profile.release]` 保持 `abort` 没问题（CLI 单进程、崩了就崩了），**但它是对 GUI 有害的默认值**，必须在文档里显式提醒——依赖方的 profile 由依赖方决定，这条不能靠猜。
2. **`commit.rs` 加有界重试 + 专用错误**：`rename` 遇 `PermissionDenied`/`SharingViolation` 时重试 3 次（20/50/100 ms 退避），仍失败则返回新增的 `StrHideError::TargetBusy(PathBuf)`（G3 已列）。GUI 据此弹"文件被占用，请关闭预览后重试"，并可提供"改为另存为"。
3. **可达 panic 收口**：`capability_of` 的 `panic!` 改为 `debug_assert` + 兜底返回"不支持的格式"错误（它有 `Option` 语义的天然出口）；两处 `.expect` 加注释说明为何不可达，或改成 `Result`。
4. **长路径（待验证项）**：`commit` 在目标名上直接 `push(".strhide.tmp")`（`engine.rs:1798` 同款写法），当载体路径接近 Windows 260 字符上限时，临时名会越界。**本文未实测**，建议在 G9 阶段补一条 `\\?\` 前缀路径的测试，再决定是加前缀还是报明确错误。

**验收**：① 故意 `panic!` 注入到 job 内部，GUI 形态下进程存活且拿到一条 `General` 错误；② 用另一个进程持有目标文件句柄（Windows）时，原地写入返回 `TargetBusy` 而不是裸 `Io`；③ `capability_of` 不再有 `panic!` 路径。

**工作量**：1–1.5 人日。

---

### G10（P2）推荐 feature 组合、文档同步与 FFI 形态

**证据**

- `Cargo.toml:22`：`default = ["structure", "content", "analysis"]`。`analysis` 会拖 `jpeg-decoder` + `dct-io`（`Cargo.toml:63`），而 `inspect`/`extract` 都用不到它。
- 多处文档声明"前端已就绪"，与 §二 的对账结果不一致：`docs/api/ARCHITECTURE.md:271,559,576,603`、`README.md:166`（"Typed errors for GUIs"）、`lib.rs` 的 crate layout 注释（`:128-130` 自述"a later batch moves under core"）。
- `docs/api/STEGO-API.md:1` 自称"内容域公开 API 规范（单一事实源）"。

**设计**

**(a) 给 GUI 一张 feature 推荐表**（写进 README/ARCHITECTURE，不进代码）

| 场景 | features | 说明 |
|---|---|---|
| 完整 GUI（写+读+诊断） | `--no-default-features --features structure,content` | 去掉 `analysis`，不拖 `jpeg-decoder`；`inspect`/`verify`/`extract` 全可用 |
| 带"反隐写扫描"页 | `structure,content,analysis` | 只有 `scan` 这个动词需要 |
| 只要容器域（小工具） | `structure-base`（PE 指令替换再加 `structure-pe`） | 不编 PNG/JPEG/HEVC 引擎 |
| 只要内容域 | `content-png` / `content-jpeg` / `content-hevc` | 独立可编（计划 §七 已保证） |

**(b) 文档同步清单**（每改一处 API 就勾一遍，否则下一轮评审又是"文档说已做、代码没做"）

- `docs/api/STEGO-API.md`：内容域新增 `*_file`（G4）、`ProgramOptions` 变更（G8）
- `docs/api/ARCHITECTURE.md`：§前端章节（:271/:559/:576/:603）与遗留说明（:616）
- `README.md:166` 的 "Typed errors for GUIs" 声明
- `rust/src/lib.rs` crate layout 注释（G7 一起改）
- `docs/CHANGES-YYYYMMDD.md`：按 `SOUL.md` 要求，重要改动在顶部追加

**(c) FFI / 多语言绑定：建议明确不做 C ABI**

并行评审把目标形态写成"Tauri、Slint、egui、Iced 或 C/FFI 跨语言绑定"。前三者是 Rust 进程内，第五个是另一类工程：

| 障碍 | 说明 |
|---|---|
| 类型不适合直传 | `Cow<'a, [u8]>`、`PathBuf`、`Option<&'a str>`、泛型 `impl IntoIterator` 都不是 FFI-safe；`Control<'a>` 借 `&dyn Progress` 无法跨语言 |
| `panic` 跨边界 | 未定义行为；需要 `catch_unwind` + `panic = "unwind"`（与 G9 同源） |
| 错误不可序列化 | 需要 G3 的 `ErrorDetail: Serialize` + `Msg::id()` |
| ABI 稳定性 | 一旦发布就要长期维持，而项目当前 `0.7.x`、明令未发布 |

**建议**：不做 C ABI，只提供 **JSON-over-IPC**（Tauri command 直接返回 `serde` 结构；其他语言走子进程 `--json`）。代价是每次调用多一次序列化，收益是零 ABI 维护成本——而 `--json` 的输出本来就已经是结构化的（§二 的对账里 `WriteResult`/`InspectResult` 已 `Serialize`）。**这是决策，不是缺陷**，写在这里是为了避免下一轮又把它当缺口重开。

**工作量**：0.5 人日（文档）+ FFI 若要做另立项。

---

## 四、改完之后 GUI 长什么样（可行性验证）

以下骨架用的是**本文设计后的 API**，用来证明这些缺口补上后不需要再绕路：

```rust
use strhide::prelude::*;
use strhide::core::control::{CancelToken, Control, Event, Progress, Stage};

struct ChanProgress(std::sync::mpsc::Sender<Event>);
impl Progress for ChanProgress {
    fn report(&self, ev: Event) { let _ = self.0.send(ev); }   // 交给 UI 线程
}

fn start_job(engine: StrHide, carrier: PathBuf, text: String) -> impl FnOnce() {
    let (tx, rx) = std::sync::mpsc::channel();
    let token = std::sync::Arc::new(CancelToken::new());
    let ui_token = token.clone();

    move || {
        let progress = ChanProgress(tx);
        let control = Control { progress: &progress, cancel: Some(&ui_token) };
        let opts = WriteOptions {
            password: Some("pw"),
            control,                       // ← G1：结构域也能报进度/取消
            ..WriteOptions::default()
        };
        // 长任务放在 scope 里，Control 借的是本帧内的 sink，不跨线程逃逸
        std::thread::scope(|s| {
            s.spawn(|| engine.structure().write_file(&carrier, PayloadSource::Text(&text), &opts));
        });
        // rx 侧：Stage::Write 的 done/total 直接映射进度条；Err(Cancelled) 关掉进度条即可
    }
}
```

三个关键点：

1. **`Control` 借 `&dyn Progress`**（`core/control.rs:166`），所以 sink 必须活到调用结束——`thread::scope` 是最省事的形态。若必须 `thread::spawn`（detach），把 sink 包 `Arc`，在闭包里先 `let sink = Arc::clone(&arc); let control = Control::with_progress(&*sink);` 也能成立，只是要多一层。**不改成 `Arc<dyn Progress>`**：那会让 `Control` 失去 `Copy`，进而让三个 options 失去 `Copy`，得不偿失。
2. **诊断页一次调用**：`engine.inspect_any(path, &DualOptions { .. })`（G2），不再自己拼两个域。
3. **列表页零成本**：`engine.stego().inspect_file(path, ..)`（G4）只读头尾，2 GB 视频不出内存峰值。
4. **"提取"按钮一次调用**：`engine.smart_extract(path, &opts)`（G2），拿回 `ExtractOutcome { payload, source, also_present }`；`also_present` 非空时在 UI 上挂一条"另一个域也有一份数据"，而不是静默只给一份。

### 推荐交互顺序（把"密码猜错"的代价压到最低）

结构域与内容域的密码语义不同（前者的 hint 存在信封里、后者根本区分不了"没有数据"和"密码不对"），如果没有固定顺序，GUI 很容易让用户为一个错误密码付全量解码的代价：

```
1. inspect_any(path)            // 便宜：结构域读头+尾，内容域读特征头；得到 format/has_hidden_data/is_encrypted/hint
2. 若 hint 非空 → 直接弹提示（不需要用户先失败一次）
3. 若 is_encrypted 且用户没给密码 → 先问密码，再执行
4. 执行 write/read/restore/smart_extract（这一步才读全量）
5. 失败 → 用 ErrorDetail 的 category 决定文案；Cancelled 单独处理（不是错误）
```

第 3 步的意义：`read` 一次 4 GB 的载体只为了拿到"密码错"三个字，是 GUI 上最常见的浪费。`InspectResult` 已经有 `is_encrypted` 与 `password_hint`（`structure/engine.rs:469,475`），这条路是通的，只是需要写进接入文档。

---

## 五、不做清单（GUI 就绪的前提下）

1. **不把 GUI 框架 / 事件循环引入库**（计划 §5.6 已明确）。
2. **不做缩略图解码**：沿用 ARCHITECTURE.md:616 的决策。Tauri 用 webview 的 `<img>/<video>`，iced/egui 用宿主自己的 image crate；库只提供 `MediaInfo`（尺寸/帧率/时长/码率）。真正要补的是**便宜的元数据探测**（G4 的 `inspect_file`），不是像素。
3. **不引入 async runtime**：`Send + Sync` + `Control` 已够；async 会把 208 处同步 I/O 全变成 `block_in_place`，收益为负。
4. **不逐条翻译 208 条引擎错误详情**（G3 已给替代方案：稳定 `kind()` + 6 个高频变体结构化）。
5. **不为"参数看起来整齐"给 HEVC 造字段**。
6. **不省还原的第二遍哈希**（G1 取舍 2）。
7. **不建 C ABI / 不发 FFI 头文件**：只做 JSON-over-IPC（G10(c)）。理由见那张障碍表——类型、panic、ABI 稳定性三条全不划算。
8. **不在库内做 `catch_unwind` 兜底**：panic 是宿主职责（G9）。库内包一层会掩盖真实缺陷，且在 `panic = "abort"` 下完全无效，只会给人虚假的安全感。

---

## 六、排期与验收口径

### 阶段划分

| 阶段 | 内容 | 解锁的东西 | 人日 |
|---|---|---|---|
| A（P0） | G1 结构域控制 + G2 双域诊断/自动判域提取上门面 | GUI 主流程可用：写入可取消、"打开"与"提取"各一次调用 | 3–4 |
| B（P0） | G3 i18n 三件事 + 错误结构化 | 中文 UI 不再是"半英文"，错误可过 IPC | 2.5–3.5 |
| C（P1） | G4 文件级 API + G5 批量 + G8 容量进度 | 列表页 / 队列页 / 容量条全部可用 | 4–5 |
| D（P1） | G6 安全与人体工学 + G9 崩溃与平台语义 | 日志不泄密码、进程不被 panic 杀死、占用文件有明确提示 | 2–3 |
| E（P2） | G7 组织收尾 + G10 集成与文档 | 边界可强制、feature 组合有据、文档不再漂移 | 2.5–3.5 |

A+B 共 5.5–7.5 人日即可让 GUI 第一版跑起来；C/D/E 依次跟进，E 可与 C 并行。

**建议的实施顺序（有依赖关系，不是随便排的）**：G2 依赖 G3 的 `Msg::id()`（`ErrorDetail` 序列化要用它），所以 **G3 的 (2) 先于 G2 的 `content_error` 上线**；G1 的取消点位置依赖 G9 的 `TargetBusy`（占用时也要能报清楚），可以一起做；G8 与 G1 改的是同一批引擎的 `control` 埋点，**同一个 PR 做最省事**。

### 每个阶段结束都要过的护栏（计划 §七）

```bash
cd rust
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --all-targets

# 依赖隔离（五条最小构建，改 core/facade 时尤其重要）
cargo build --no-default-features --features structure-base
cargo build --no-default-features --features content-png
cargo build --no-default-features --features content-jpeg
cargo build --no-default-features --features content-hevc
cargo build --no-default-features --features analysis

# 字节级基线（凡触及写入/还原路径必跑）
python scripts/baseline_hash.py --check
```

`local_` 批测按 `AGENTS.md` 方式跑（日志重定向 + 轮询，整套约 100–110 s、峰值 8.6–9.7 GB），不要在跑批时并行其它重任务。

### 逐项验收速查

| 缺口 | 一条能立刻判断成败的验收 |
|---|---|
| G1 | 4 GB 载体还原中途取消 → 返回 `Cancelled`、目标文件不存在、**且没有多出一个 `.bak`**、`baseline_hash --check` 仍全绿 |
| G2 | `--json` 输出与改动前逐字段 diff 为空；`smart_extract` 两域都有时 `also_present` 非空；门面调用点从 0 变正数 |
| G3 | `Lang::En` 下 7 个字段 `render()` 与旧 `message()` 逐字节相同；`Msg::id()` 覆盖全部变体；`serde_json::to_string(&err.detail_i18n())` 成功 |
| G4 | 2 GB MP4 走 `inspect_file` 峰值内存 ≤ 8 MiB |
| G5 | 20 项里第 3 项失败且 `continue_on_error` 时，仍拿到 20 条 `ItemOutcome` |
| G6 | 任 options `{:?}` 输出不含密码原文 |
| G7 | `python scripts/import_lint.py` 在故意违规时退出码非 0 |
| G8 | 50 MP JPEG 上 `probe` 上报 ≥ 2 个 stage，`CostMap` 有中间进度且末条 `done == total` |
| G9 | 注入 panics 后 GUI 形态进程存活；另一进程持有目标句柄时原地写入返回 `TargetBusy` 而非裸 `Io` |
| G10 | GUI 用 `--no-default-features --features structure,content` 能编过且不含 `jpeg-decoder`（`cargo tree` 验证） |

---

## 七、残余风险与开放问题

| 风险 | 说明 | 处置 |
|---|---|---|
| G1 的 `Interrupted` 映射 | 把"取消"编码成 `io::ErrorKind::Interrupted` 是靠约定识别；若某个适配器真的返回 `Interrupted` 且同时 token 已置位，会被误判为 `Cancelled` | 概率极低（本库无自定义 `Interrupted` 来源）；若担心，改为给 `inject`/`strip` 加 `control` 参数（10 个适配器，机械改动，作为备选方案 B） |
| G1 的取消点与 `.bak` 时序 | 在"已复制 .bak、未 rename"之间取消会留下孤儿备份 | 取消点一律排在提交区间之前（G1 取舍 4）；要动提交区间就先扩展 `TmpGuard` |
| G3 改动面最广 | 71 处 `t!` + 7 个字段 + 6 个错误变体，容易夹带无关改动 | 分 4 次提交（ctx / Msg::id / Warning+Level / errors），每次单独跑护栏 |
| G2 与 `--json` 兼容 | `serde(flatten)` 与新增 `content_error` 会改变 JSON 键集合 | `content_error` 加 `skip_serializing_if`；用改动前样例逐字段比对 |
| G5 并发与内存 | `max_concurrency` 是调用方责任，库不设防 | `Capability.memory` 提供判断依据 + 文档给出"内容域按大小串行"的默认建议 |
| 门面首次被真实使用 | CLI 切到门面后，`cmd_*` 的行为差异可能在错误文案/降级策略上暴露 | G2 阶段先让 CLI 与门面并行跑一轮（同一语料比对输出），再删旧路径 |
| G9 的 panic 兜底会掩盖缺陷 | `catch_unwind` 把真 bug 变成一条 `General` 错误，可能导致用户重试而不是上报 | 只在 job 边界兜，库内部不兜；记录 panic payload 与 backtrace，UI 上标"内部错误" |
| 文档与代码二次漂移 | 本轮评审的直接成因就是"计划说做了、代码没做"（§二 有 5 项） | §六 的文档同步清单进 PR 检查；`CHANGES-*.md` 必须与 API 变更同提交 |
| 两份评审文档再次分叉 | 本轮已经出现两份"官方蓝图"（本文与 `gui_readiness_summary_and_solutions_20261027.md`） | 本文为唯一主文档，另一份降级为摘要并加指回链接（附录 B） |

**开放问题（需产品决策，不属于架构缺陷）**

1. 密码在内存中的生命周期：今天全库用 `&str` 明文传递、无 `zeroize`。若 GUI 需要"锁屏后清空密码"，要引入 `Password` newtype + `zeroize`，并改 options 字段类型——建议单独评估，不混进本方案。
2. 是否需要"多信封"的一等支持：`RestoreMismatch` 的诊断已能识别"下面还压着一个信封"（`engine.rs:1733-1735`），但 UI 上没有"逐层剥离"的入口。属功能增量，非就绪度缺口。

---

## 附录：证据索引（本次核对的源码位置）

| 主题 | 位置 |
|---|---|
| 结构域 options 无 control | `rust/src/structure/options.rs:22,59,103` |
| 写路径 inject 调用点 | `rust/src/structure/engine.rs:1042-1046` |
| 还原三步（strip/verify/backup） | `rust/src/structure/engine.rs:1802-1830` |
| 批量拷贝唯一收敛点 | `rust/src/structure/adapters/io.rs:13,33`（36 处调用 / 12 文件） |
| 适配器 trait 签名 | `rust/src/structure/adapters/mod.rs:142-231` |
| 内容域 control 五处 | `rust/src/stego/options.rs:419,614,709,931,1034` |
| 双域诊断四处重复 | `rust/src/cli/cmd_diag.rs:44-50,91-103,215-222,257-268` |
| 双域结果私有类型 | `rust/src/cli/render.rs:108,147` |
| thread_local 语言 | `rust/src/core/i18n/mod.rs:48-60,93` |
| Warning / LevelStatus / strategy_note | `rust/src/structure/engine.rs:368,406,491` |
| StrategyCapacity 英文散文 | `rust/src/structure/adapters/mod.rs:97-113` |
| 内容域 String 型结果 | `rust/src/stego/mod.rs:275-276`、`stego/options.rs:892,1011` |
| 文件级 API 缺失 | `rust/src/stego/io.rs:31,59`、`stego/mod.rs:237,255,367` |
| 批量打印式执行器 | `rust/src/core/pipeline.rs:30-65` |
| 库内 stderr 输出 | `rust/src/core/config.rs:114,132` |
| 有界扫描先例 | `rust/src/analysis.rs:50-53,263-290`；常量实测：`MAX_FULL_SCAN` 64 MiB（:50）、`PREFIX_WINDOW` 1 MiB（:53）、`TAIL_WINDOW` **4096**（:55）、`STRUCT_TAIL_WINDOW` **64 KiB**（:63） |
| 容量探测无阶段进度 | `stego/png/engine.rs:1885`、`stego/jpeg/engine.rs:1496`、`stego/hevc/engine.rs:252`（仅 `check()`）；对照 embed 埋点 `png:1117,1121,1153,1443`、`jpeg:580,610,654`、`hevc:588,592,774` |
| 变更记录自认的缺口 | `docs/CHANGES-20261027.md:205` |
| panic / abort | `rust/Cargo.toml:128`；`formats/capability.rs:131-136`；`stego/options.rs:105-113`；`core/i18n/mod.rs:141` |
| 提交路径无重试 / 临时名拼接 | `commit.rs:170`；`structure/engine.rs:1797-1799` |
| 默认 feature 含 analysis | `rust/Cargo.toml:22`（default）+ `:63`（jpeg-decoder 仅 analysis 用） |
| 文档声明与实现不符 | `docs/api/ARCHITECTURE.md:271,559,576,603`、`README.md:166`、`rust/src/lib.rs:128-130` |
| 版本基线 | `rust/Cargo.toml:3` = `0.7.3`（提交 `e276954`，2026-10-27 22:30:10） |
| 门面零 CLI 使用 | `rust/src/cli/` 内直调各域 40 处；`facade.rs` 子门面 0 处 |
| crate root 残留 | `rust/src/lib.rs:128-130,142` |
| 死导出与过期文档 | `rust/src/structure/mod.rs:13-18,33` |
| 巨型文件 | `structure/engine.rs` 2379 行、`analysis.rs` 2344 行、`stego/options.rs` 1202 行 |
| 计划对照 | `docs/strhide_architecture_and_refactoring_plan.md` §3.2/§3.4/§4.1/§5.1-5.6/§七/§九/§十 |
| 既有前端说明 | `docs/api/ARCHITECTURE.md:271,559,576,603,616` |

---

## 附录 B：与并行评审的合并记录

同一轮里存在第二份评审 `docs/gui_readiness_summary_and_solutions_20261027.md`（2026-10-27 22:41）。两份文档若各说各话，下一轮执行时必然打架，因此逐条比对后合并如下。

**采纳（我原稿确实漏了）**

| 项 | 来源 | 本文如何处理 |
|---|---|---|
| `smart_extract`（自动判域提取） | 并行评审 §2.2 | 采纳并补三处：`limits`（PBKDF2 封顶）、`prefer`、`also_present`（同一文件两域都有载荷时不能静默丢一份）；见 G2 |
| `AlreadyExists(PathBuf)` | 并行评审 §3.2 | 采纳；这是 GUI 最高频的"覆盖/改名/取消"对话框所需；见 G3 |
| `CapacityExceeded { tier, required_bytes, available_bytes }` | 并行评审 §3.2 | 采纳其字段形状，替换我原稿含糊的 `SafetyThreshold { tier, limit, actual }`；见 G3 |
| 把 C/FFI 跨语言绑定列为可能目标 | 并行评审 目标形态 | 采纳为待决策项，但结论是**不做 C ABI**，只做 JSON-over-IPC；见 G10(c) |

**修正（并行评审的事实/表述问题）**

| 问题 | 实际情况 | 影响 |
|---|---|---|
| "TAIL_WINDOW = 64 KiB" | `TAIL_WINDOW = 4096`（`analysis.rs:55`），64 KiB 是另一个常量 `STRUCT_TAIL_WINDOW`（`:63`） | 若照着 4 KiB 设计窗口，"找容器结束标记"会漏；两个常量用途不同，不能混用 |
| "所有结构域写入与拷贝最终都经过 `adapters/io.rs`" | 该文件确为 36 处调用、12 个文件的收敛点，但**不是唯一**依据 | 结论仍然成立——`ProgressWriter` 包的是 `output`，无论适配器用哪个拷贝 helper，写出去都要经过它。本文按这个更强的理由论证（G1） |
| `inspect_carrier(&self, path, opts: &DualOptions)` 与 `SmartExtractOptions` 并存 | 签名与类型不一致（定义了 `SmartExtractOptions` 却没用） | 本文拆成两套并各自绑定方法：诊断用 `DualOptions`，提取用 `SmartExtractOptions` |
| 版本写 0.7.3 | 正确 | 我原稿写 0.7.2，因为评审跨了 22:30 的版本提交；已改正并留注记 |
| `StrHide::inspect_carrier` 命名 | 与 `structure::inspect_carrier` 同名 | 本文用 `inspect_any` / `verify_any`，避免与模块级自由函数在阅读时混淆 |

**并行评审未覆盖、本轮新增**

| 项 | 说明 |
|---|---|
| G8 容量探测无进度 | 并行评审与我原稿都没提；靠 `CHANGES-20261027.md:205` 的自认与三处 `control.check()` 实测定案 |
| G9 崩溃语义与 Windows 占用 | 涉及 `Cargo.toml:128` 的 `panic = "abort"`、`commit.rs:170` 无重试 |
| G10 feature 组合 / 文档同步 / FFI 决策 | 前两项是"不改代码也会踩"的集成问题 |
| G1 取舍 4（取消点与 `.bak` 时序） | 并行评审只写"取消由 `TmpGuard` 回滚"，实际 `TmpGuard` 不守 `.bak` |
| 密码重试的交互顺序 | §四 的"推荐交互顺序"，把 4 GB 文件的二次读取成本省掉 |

**并行评审刻意省略、本文保留的部分**（因此它只能当摘要，不能替代本文）：计划 §五 落地对照矩阵（§二）、每项的一条式验收（§六）、风险登记（§七）、证据索引（附录 A）、以及三处实现取舍的论证（G1 取舍 1–4）。
