# strhide 双系统 Facade 重构方案审查意见

> **编制日期**：2026-10-22
> **审查对象**：`docs/strhide_dual_system_architecture_and_api_refactoring_20261022.md`（方案建议版）
> **审查方式**：逐条对照 `rust/src` 实际代码（下方均给出 file:line 证据），未改动任何代码。
> **总结论**：事实与诊断**全部成立**，问题清单还比原文档多出一处硬编码与两个隐坑；方向（实例化 + 域间隔离）正确，但方案体量偏大（约 10 个新类型），存在一个**约 1/3 体量的等效最小方案**，另有 4 个落地方坑需要在开工前补进方案。

---

## 1. 结论先行

| 维度 | 判定 | 说明 |
|---|---|---|
| 事实核对 | ✅ 全部属实 | 见 §2 |
| 缺陷清单完整性 | ⚠️ 不完整 | 硬编码 `DEFAULT_FORMAT` 有 **3 处**，原文档只找到 2 处；另漏 `Profile::is_official()` 语义联动 |
| 方向（实例化 / 域隔离） | ✅ 正确 | 与 2026-10-20 方案确立的 L/P 类划分兼容 |
| 方案体量 | ⚠️ 偏大 | 形态 1/2 并存 + 全套 fluent Op 类型 ≈ 10 个新类型，等效最小方案 1 个 struct |
| 落地风险 | ⚠️ 3 处未言明 | `&'static` FormatProfile 标签、`run_cli` 副作用、CLI 参数与 profile 优先级 |

---

## 2. 方案文档事实核对（逐条对照代码）

| 原文档声明 | 核对结果 | 证据 |
|---|---|---|
| "C 语言式散装传参"，三个写/读/删函数签名各异 | ✅ 属实 | `engine.rs:1218` `write_carrier_with(path, source, options, local, profile)`；`engine.rs:1439` `read_carrier_with(path, out, pwd, overwrite)` **不收 profile**，硬转 `Profile::default()`；`engine.rs:1929` `remove_carrier_with_options` 6 位置参数含两个 bool |
| `stego/mod.rs` 高层入口写死 `DEFAULT_FORMAT`，外部 `FormatProfile` 传不进去 | ✅ 属实 | `stego/mod.rs:88`（embed）、`stego/mod.rs:151`（extract） |
| 两套系统独立、动词正交（`write/read/restore` vs `embed/extract/probe`） | ✅ 属实 | 红线合理，方案 §2 展望正确 |
| 前置事实：`Profile` 已含 `stego: StegoProfile` | ✅ 属实 | `params.rs:283-310`；M1b（2026-10-20 方案）已落地，§5.1 实为"加一个字段"而非重构 |
| CLI 侧 stego 已走 `_with_profile` 入口 | ✅ 属实 | `cli.rs:2156/2241` |

补充一个原文档未引用但支持其结论的事实：CLI 侧的 `run_cli()` 目前从 `std::env::args_os()` 取参并加载配置文件 + i18n（`cli.rs:873-889`），见 §3.4。

---

## 3. 方案遗漏的 4 个关键坑（按严重度排序）

### 坑 1：缺陷 3 只修一半 —— 写死 `DEFAULT_FORMAT` 的共 3 处，原文档只提 2 处

- `stego/mod.rs:88`（embed 路径）——原文档已提；
- `stego/mod.rs:151`（extract 路径）——原文档已提；
- **`stego/jpeg/engine.rs:905`（`probe_jpeg_capacity`）—— 原文档完全漏掉。**

probe 传不进 `FormatProfile` 的后果比 embed/extract 更重：自定义方言的几何（`sb_bytes` / `sb_h` / `grid_rule` 等，见 `stego/format.rs:190-219`）一旦改变，header/superblock/body 的 slot 数全部变化，**容量估算结果是错的**，会误导上层裁剪 payload。

修复成本低：底层已有现成出口 `probe_capacity_with_format`（`stego/jpeg/engine.rs:910`），接上即可。**§7 第一阶段必须三处一起修，并同步补一条针对自定义 FormatProfile 的容量回归测试。**

### 坑 2：`Profile::is_official()` 语义未联动

`Profile::is_official()`（`params.rs:403-408`）承载"官方 strhide 能否读开"这一**安全承诺**：私有的 `default_secret` / `stealth_domain` / `magic` / `stego` 均计入非官方判定（`params.rs:466-495` 测试明确了这个意图）。

方案给 `StegoProfile` 增加 `format_profile` 字段后，`StegoProfile::is_official()`（`params.rs:267-269`）与 `Profile::is_official()` 必须同步将其计入非官方方言——否则会存在一个方言维度绕过判定，官方工具读不开却被告知"这是官方方言"。原文档 §5.1 未提此事，需补。

### 坑 3：`Cow<'static, FormatProfile>` 是多余设计

`FormatProfile` 是 `Copy`（`stego/format.rs:189`），字段全是 `&'static` 借用（`&'static [u8]` / `&'static [CipherSuite]`）。直接：

```rust
pub format_profile: Option<FormatProfile>,
```

拷贝零成本；`Cow` 在此需要绕 `ToOwned`（虽然能编译），纯属复杂度。方案 §5.1 的示例需更正。

### 坑 4：`FormatProfile` 字段全 `&'static` —— 宿主只能用静态字面量定义方言

`cover_digest_tag` / `hpos_label` / `stc_label` / `enc_label` / `perm_label` 五个标签全是 `&'static`（`stego/format.rs:196-204`）。这意味着 **CarrotHash 这类宿主只能以代码中的静态常量定义私有方言，无法从配置文件等运行时数据构造**（除非 `Box::leak`，泄漏内存且不优雅）。

这是接入宿主时会真实撞上的墙，方案必须显式记录取舍。本审查倾向**保留 `&'static`**（密钥派生标签进堆反而引入生命周期与清理面），但这应当成为文档中被评审过的决定，而不是副作用。

---

## 4. 接口设计问题清单（可砍的体积）

### 4.1 形态 1 / 形态 2 应二选一，不要"两端并存"

原文档自己在 §2.2 立"物理语义绝不混淆"的红线，而动词本已正交（`write/read/restore` vs `embed/extract/probe`），不存在 guess 空间——`engine.write()` 与 `engine.carrier().write()` 没有歧义。两套并存意味着**每个动词两份文档、测试、维护**。

- 留**根级直通**（形态 2）：6 个转发方法，最省代码；
- 或留**命名空间**（形态 1）：2 个 subsystem struct + 10+ 方法；
- "两种并存且自洽"是最差选项：体积最大、且每次新增动词要写两处。

### 4.2 Fluent 输入类型混乱：payload 入参重新搅浑了 `PayloadSource`

`engine.write(path, "payload.txt")` 的第二参是路径还是文本？现有 `PayloadSource`（Text/File/Bytes/Stdin）已经分清了四类来源，fluent builder 示例把"文件路径"和"文本"混在同一位置。应为：

- 接受 `impl Into<PayloadSource>` 为 `Text` / `Bytes` / `File` 分别提供 `From`；或
- 拆分为 `write_text` / `write_file` / `write_bytes` 显式入口。

### 4.3 `.to_file("extracted.txt", true)` 是位置布尔 —— 老病新发

`remove_carrier_with_options` 的 6 参散装（`engine.rs:1929`）正是这种位置布尔；fluent 新 API 原样复发（clippy 亦憎）。应为 `.overwrite(true)` 链式标志 + `.to_file(path)` 动作。

### 4.4 `StrHideBuilder` 收编 `LocalParams` 过头了

`chunk_size` / `compression` 是**载荷级**取舍（大 payload 想要大 chunk、小 payload 别压缩），引擎级固化会逼所有载荷共享。`LocalParams` 本就是 L 类写侧参数（`params.rs:1-22` 的模块注释已把"谁需要知道"这件事说透），放进 WriteOp 链式即可。"消灭 LocalParams 强迫症"应改为"降级为可选链式项"，`LocalParams` 类型本身保留。

### 4.5 通篇没有 in-memory 变体

`write_carrier_bytes`（`engine.rs:1380`）、`read_carrier_bytes`（`engine.rs:1751`）、`remove_carrier_bytes`（`engine.rs:2017`）才是 CarrotHash 这类内存流转宿主的**真实调用路径**，方案通篇只给 path 形式。facade 需覆盖 `*_bytes` 全套，且内存写默认 `RejectionPolicy::ContentOnly` 的选择要在 facade 里显式表达（文件路径写才默认 `Strict`）。

### 4.6 动词表没定全，重构最忌第二阶段再补动词

§2.1 归纳核心动词 8 个，§4.1 形态 2 只给 5 个，`verify` 与 `probe`（根级/映射关系）缺席。动词表应一次性定全：

| 域 | 动词（齐） | 对应现有函数 |
|---|---|---|
| 结构域 | `write` / `read` / `restore` / `inspect` / `verify` | `write_carrier*` / `read_carrier*` / `remove_carrier*` / `inspect_carrier*`（`engine.rs:2051/2063`）/ `verify_carrier*`（`engine.rs:2228/2239`） |
| 内容域 | `embed` / `extract` / `probe` | `stego::embed_carrier*` / `extract_carrier*` / `probe_carrier_capacity*` |

### 4.7 `run_cli(&self, args)` 三个未言明的坑

1. **`std::process::exit(exit_code)` 在库 API 里是副作用炸弹**（RAII 失守、丢弃 pending 输出）。库应返回退出码（`Result<i32>` 或 `ExitCode`），由宿主决定是否退出。
2. **工作量低估**：现有 `run_cli()` 从 `env::args_os()` 取参、`config::load` 加载配置文件、i18n 初始化与最终语言报错（`cli.rs:873-889`），改造不是"加一个 args 参数"，"5 行接入"的估计过于乐观。
3. **两个真相来源冲突**：引擎绑定的 `Profile` vs CLI 参数里的 `--secret` / `--domain` / `--magic` 等方言开关，谁赢？必须先写清。建议：**CLI 显式参数覆盖 profile，profile 仅作为无参时的兜底**——与 `StegoOptions::secret()` 现行"显式密码优先、profile 收敛兜底"语义（`stego/params.rs:475-480`）保持一致。

---

## 5. 推荐的等效最小方案（约原方案 1/3 体量）

核心痛点实际只有两个：**profile 重复传**、**FormatProfile 传不进去**。都不需要 fluent 大库。

### 第一阶段（Non-breaking，与原方案 §7.1 对齐但修复面扩大）

1. 三处 `DEFAULT_FORMAT` 硬编码全部打通（embed / extract / **probe**）；
2. `StegoProfile` 增加 `format_profile: Option<FormatProfile>`（**普通 Option，非 Cow**）；
3. `StegoProfile::is_official()` 与 `Profile::is_official()` 纳入该字段；
4. 补一条"自定义 FormatProfile 下 embed→extract→probe 往返"回归测试。

### 第二阶段（Additive，单文件 `src/facade.rs`）

`StrHide` struct 持有 `Profile`，**普通方法直接转发现有 `*_with*` 自由函数**，每方法 1–3 行：

```rust
pub struct StrHide { profile: Profile }

impl StrHide {
    pub fn new() -> Self;                   // 官方方言
    pub fn with_profile(profile: Profile) -> Self;

    // —— 结构域：签名复用现有 WriteOptions / LocalParams，零新类型 ——
    pub fn write(&self, path: &Path, source: PayloadSource,
                 options: &WriteOptions, local: &LocalParams) -> Result<WriteResult, StrHideError>;
    pub fn write_bytes(&self, carrier: &[u8], source: PayloadSource) -> Result<Vec<u8>, StrHideError>;
    pub fn read(&self, path: &Path, out: Option<&Path>, password: Option<&str>) -> Result<ReadResult, StrHideError>;
    pub fn read_bytes(&self, carrier: &[u8], password: Option<&str>) -> Result<ReadResult, StrHideError>;
    pub fn restore(&self, path: &Path, out: Option<&Path>, password: Option<&str>) -> Result<RemoveResult, StrHideError>;
    pub fn inspect(&self, path: &Path) -> Result<InspectResult, StrHideError>;
    pub fn verify(&self, path: &Path, password: Option<&str>) -> Result<VerifyResult, StrHideError>;
    // + 其余 *_bytes 变体（restore_bytes 等）

    // —— 内容域：复用现有 StegoOptions ——
    pub fn embed(&self, cover: &[u8], payload: &[u8], options: &StegoOptions) -> Result<Vec<u8>, StrHideError>;
    pub fn extract(&self, carrier: &[u8], options: &StegoOptions) -> Result<Vec<u8>, StrHideError>;
    pub fn probe(&self, cover: &[u8], options: &StegoOptions) -> Result<StegoCapacityInfo, StrHideError>;
}
```

这已消除全部"散装传 profile"，且 `WriteOptions` / `LocalParams` / `StegoOptions` 原样复用，现有测试与 CLI 不受影响。

**Fluent 链是纯糖，等 CarrotHash 真实跑起来、确认普通方法版不够用再加不迟**（先证明必要性）。若上，按 §4.2 修 payload 入参类型、按 §4.3 修位置布尔。

### 第三阶段（CLI 接入）

1. `run_cli` 先做"参数显式传入、**返回退出码不 process::exit**"版；
2. 文档 §6 写明 CLI 方言参数与引擎 profile 的**优先级规则**（显式参数 > profile > 官方默认）；
3. `run_cli` 改造量实测后再宣称接入成本（涉及 i18n / config 初始化）。

---

## 6. 与原方案的差异对照（评审后修订点）

| 原方案条目 | 审查结论 | 修订 |
|---|---|---|
| §2.2 红线（动词隔离） | ✅ 保留 | —— |
| §4.1 形态 1 + 形态 2 并存 | ❌ 砍 | 二选一，推荐先只留根级直通（省一半代码） |
| §4.2 全套 WriteOp/ReadOp/EmbedOp fluent 类型 | ⏸ 缓 | 先出普通方法版（§5 第二阶段），fluent 按需再上 |
| §5.1 `Cow<'static, FormatProfile>` | ❌ 改 | `Option<FormatProfile>`（Copy，零成本） |
| §5.1 只提 embed/extract 两处硬编码 | ❌ 补 | 加 `probe_jpeg_capacity`（`jpeg/engine.rs:905`），共 3 处 |
| §5.1 未提 `is_official()` 联动 | ❌ 补 | 纳入非官方判定，守住"官方读不开"安全承诺 |
| §5.2 `LocalParams` 收编为引擎级调优 | ❌ 改 | 降级为 WriteOp 可选链式项，保留 per-op 语义 |
| §5.2 未提 `&'static` FormatProfile 标签限制 | ❌ 补 | 作为明确决策记录（本审查建议保留 `&'static`） |
| §6.1 `run_cli` 5 行接入 + `process::exit` | ❌ 修 | 返回退出码；接入成本实测；写明参数优先级 |
| §7.1 第一阶段只覆盖 embed/extract 打通 | ❌ 补 | 三处硬编码 + `is_official` + 容量回归测试 |
| §7 全程未覆盖 `*_bytes` in-memory 变体 | ❌ 补 | 动词 × 载体形式（path/bytes）矩阵在设计期一次定全 |
| §7 全程未覆盖 `inspect` / `verify` | ❌ 补 | 见 §4.6 动词表 |

---

## 7. 剩余未检查项与风险

- `analysis.rs`、`router.rs` 对 facade 的影响未评估（本次审查只覆盖 write/read/remove/stego 调用链）；
- `run_cli` 改造的真实工作量未实测（需验证 `config::load` 与 i18n 初始化在"宿主进程内"的行为）；
- **主要风险**：若 CarrotHash 需要从运行时数据构造 `FormatProfile`（如配置文件读方言标签），`&'static` 字段将成为阻塞项，需在新方案落地前决策（贴心方案：暴露 `Box::leak` 封装的 `FormatProfile::leaked()` 便捷函数，或维持只用静态字面量的立场并写明）。
