# strhide Facade API 方案评估与业界接口标准

> **编制日期**：2026-10-22
> **评估对象（三份方案文档）**：
> 1. `docs/strhide_dual_system_architecture_and_api_refactoring_20261022.md`（方案建议 v1，下称"**原方案 v1**"）
> 2. `docs/strhide_dual_system_facade_review_20261022.md`（审查意见，最小方案，下称"**审查意见**"）
> 3. `docs/strhide_dual_system_architecture_final_20261022.md`（v2 源码核定版，下称"**核定版 v2**"）
> **评估方式**：对照 `rust/src` 实际代码核对三份文档的事实与签名；对关键结论（`const fn` 构造链）在本机 **rustc 1.99.1 stable** 上编写最小样例实测编译；并调研业界主流隐写库与 Rust 代表性库的公开接口形态（来源见文末）。
> **总结论**：**以审查意见（最小方案）为骨架，吸收核定版 v2 的三个真实新发现（argv[0] 处理、commit 原子落盘、cli 硬编码清单），但 v2 的核心卖点 `const fn` 编译期方言构造在当前 stable 上因 `Cow` 字段失败，需先做字段类型决策。** 原方案 v1 与 v2 共同坚持的"双形态并存 + 全套 fluent Op"在业界没有先例，属于过度设计，应砍或缓。

---

## 1. 三份文档定位与结论先行

| 文档 | 体量 | 事实完整性 | 接口形态主张 | 总体判定 |
|---|---|---|---|---|
| 原方案 v1 | 大（约 10 个新类型） | 一般（漏 probe、漏 is_official） | 双形态 + 全套 Op | 方向对，形态过度 |
| 审查意见 | 小（1 个 struct） | 较完整（补 probe、is_official、4 个坑） | 单 struct、根级普通方法 | **骨架采纳** |
| 核定版 v2 | 最大（约 14 个 Op + 2 子系统） | **最完整**（再加 const fn、argv[0]、commit、cli 6 处） | 仍坚持双形态 + 全套 Op | 事实吸收，形态仍砍 |

**逐项裁决：**

| 问题 | 结论 |
|---|---|
| 两域辨析（结构域 / 内容域，动词正交） | ✅ 正确，红线保留 |
| 实例化方向（构造时绑定 Profile） | ✅ 正确，与业界主流一致 |
| 双形态并存（命名空间 + 根级直通） | ❌ 砍掉，只留根级直通（动词正交，无 guess 空间） |
| 全套 fluent Op（v1 约 10 个 / v2 约 14 个新类型） | ⏸ 缓行，先出普通方法版，待真实需求再上 |
| 收编 LocalParams 为引擎级、丢失 per-op 覆盖 | ❌ 不改；v2 已补回 per-op 逃生舱，方向正确 |
| 3 处 DEFAULT_FORMAT 打通 + is_official 联动 | ✅ 纳入阶段 1 |
| v2 新增：`const fn` 编译期方言构造 | ⚠️ 目标正确，但**当前 stable 因 Cow 字段失败**，需字段决策（见 §5） |
| v2 新增：argv[0] 保留、commit 原子落盘、cli 硬编码清单 | ✅ 全部纳入 |

---

## 2. 业界主流库接口标准调研

### 2.1 同领域隐写库

| 库 | 语言 | 公开接口形态 | 关键特征 |
|---|---|---|---|
| **OpenStego**（最成熟的开源隐写库之一） | Java | `new OpenStego(plugin, config)` 构造时绑定插件与配置；实例方法 `embedData(msg, cover, name)` / `extractData(stego)` | 配置在构造时绑定，动作即普通实例方法；**无 Op 层、无多形态**；提供 byte[] 与 File 两套重载 |
| **Stegano** | Python | 模块级函数 `lsb.hide(image, "msg")` / `lsb.reveal(image)`（redhide/rdh 等同构） | 极简，输入即路径/图像，hide/reveal 两动词 |
| **pnger** | Rust | 自由函数 `embed_payload_from_bytes_with_options(png, payload, options)` / `extract_payload_from_file_with_options(path, options)`；`EmbeddingOptions` 用 builder | 自由函数 + Options(builder)，path/bytes 双变体——**与 strhide 现状几乎同构** |

### 2.2 Rust 生态代表性库（配置/客户端类）

| 库 | 领域 | 公开接口形态 | 关键特征 |
|---|---|---|---|
| **reqwest** | HTTP 客户端 | `ClientBuilder::new().proxy(p).build()?` 构造持有配置的 `Client`；`client.get(url)` 返回 per-request `RequestBuilder`，终态 `.send()` | 配置层用 builder；**仅因单次请求本身有大量正交可选项**才给 per-request builder，且只有一种形态 |
| **zip** | 归档 | `ZipWriter::new(out)` 持有输出；`start_file(name, opts)` / `write_all(data)` / `finish()` | 有状态句柄 + 普通方法，无 Op 包装 |
| **Sequoia (sequoia-openpgp)** | OpenPGP | 分层：低层无状态 packet/streaming API，高层在 `sequoia` crate 提供 key store；CLI（sq）动词为 encrypt/decrypt/sign/verify | 低层面向高级用户，高层收敛；streaming 优先 |

### 2.3 接口设计规范依据

- **Rust API Guidelines**（官方）：builder 模式定位为"使**复杂配置**可构造"（builders enable construction of complex types），并非要求每个操作包一层 builder。
- **微软 Pragmatic Rust Guidelines（M-INIT-BUILDER）**：存在 **4 个以上**任意初始化排列的类型才需要 builder；最多 2 个可选初始化参数的类型用固有方法即可。
- Rust 论坛对两类 builder 的共识：非消费式（`&mut self` 配置、`&self` 终态）用于配置对象，消费式（`mut self` / `self`）用于一次性构造。

### 2.4 共性规律（四条）

1. **配置与动作分层**：长期配置（方言/密钥/连接）在构造时绑定，动作是普通方法；
2. **Builder 只用于复杂配置的构造**（约 4+ 可选排列），不包每个动作；
3. **同领域隐写库没有一个使用"全套 fluent Op + 双形态"**；
4. **普遍提供文件/内存（path/bytes）两套变体**。

---

## 3. 核定版 v2 新增事实核查（逐项对照源码）

| v2 声明 | 核查结果 | 证据 |
|---|---|---|
| 3 处 DEFAULT_FORMAT（embed/extract/probe） | ✅ 属实 | `stego/mod.rs:88/151`；`stego/jpeg/engine.rs:905` 硬委托 `&DEFAULT_FORMAT`，`910` 有 `probe_capacity_with_format` 出口 |
| inspect 连锁调用 probe，容量随之失真 | ✅ 属实 | `engine.rs:2095` 调 `probe_carrier_capacity_with_profile` |
| `commit_carrier_bytes` 提供临时文件+原子替换+`.bak`+时间戳 | ✅ 属实 | `engine.rs:1319-1355` |
| argv[0] 陷阱：clap 需保留程序名 | ✅ 属实 | `cli.rs:874` 取 `args_os`、`877` `try_get_matches_from(argv)`、`814` 仅扫描时 `skip(1)` |
| `#[non_exhaustive]` 阻断外部 crate 定义 const 方言 | ✅ 属实 | `params.rs:227/282` |
| Option&lt;FormatProfile&gt; 非 Cow、is_official 联动 | ✅ 正确 | FormatProfile 为 Copy |
| payload 歧义、位置布尔、ReadResult 元数据 | ✅ 正确 | `engine.rs:334` PayloadSource、`424` ReadResult |
| cli.rs "6 处 Profile::default() 字面量" | ⚠️ 表述偏差 | 实际字面量 3 处：`cli.rs:754/1356/2043`；其余为调用**无 profile 入口**（write_carrier / read_carrier_with / inspect_carrier / verify_carrier），等价硬编码，结论成立 |
| **`const fn` 编译期方言构造链** | ❌ **当前 stable 失败** | 见 §4 实证 |

---

## 4. 关键实证：`const fn` 构造链在 stable 上的编译结果

**实证环境**：rustc 1.99.1 stable（项目 edition = 2024，未设 rust-version）；最小样例位于 `temp/constfn_test.rs`、`temp/constfn_test2.rs`。

| 字段类型 | const fn 形态 | 结果 |
|---|---|---|
| `Option<Cow<'static, str>>`（现状） | `const fn with_x(mut self, ..) { self.x = Some(Cow::Borrowed(v)); self }` | ❌ **E0493**：赋值需 drop 旧值，`Cow` 析构无法在编译期求值（rust-lang/rust#133214，未稳定） |
| `Option<&'static str>`（Copy） | 同上写法 | ✅ **编译通过、运行正常** |
| 任意含 Cow 字段 | `const fn new()`（仅结构体字面量构造，无赋值） | ✅ 通过（失败的只是链式 `with_*` 赋值） |

**结论**：v2 示例的 `const CARROT_PROFILE: Profile = Profile::new().with_static_secret(...)...` 在当前 stable 上**不能直接落地**，只要 Profile 字段保持 `Cow`。要实现"零运行时开销的编译期私有方言"，有两条路径（见 §5 待决策项 D1）。

---

## 5. 最终融合推荐：最小方案 + v2 实证修正（三阶段）

### 5.1 分层架构（示意）

```text
宿主（CarrotHash / CLI / 服务进程）
        │
        ▼
┌─────────────────────────────────────────────┐
│ StrHide { profile: Profile, local: LocalParams } │
│  new() / with_profile(profile)              │
├──────────────────────┬──────────────────────┤
│ 结构域（无损容器）    │ 内容域（图像自适应）  │
│ write/read/restore   │ embed/extract/probe  │
│ inspect/verify       │ （无 restore）        │
│ × path · bytes       │ × bytes / *_file     │
└──────────────────────┴──────────────────────┘
        │ 每方法 1–3 行转发（底层零改动）
        ▼
write_carrier_with / read_carrier_with_profile / remove_carrier_* /
*_bytes 系列 / stego::*_with_profile / commit_carrier_bytes
```

### 5.2 阶段 1：底层修复（Non-breaking）

1. **三处 `DEFAULT_FORMAT` 硬编码全部打通**：embed（`stego/mod.rs:88`）、extract（`stego/mod.rs:151`）、probe（改用 `probe_capacity_with_format`，`stego/jpeg/engine.rs:910`）。
2. `StegoProfile` 增加 `format: Option<FormatProfile>`（**普通 Option，非 Cow**），并提供 `format_profile() -> &FormatProfile`（回退 `DEFAULT_FORMAT`）。
3. `StegoProfile::is_official()` 与 `Profile::is_official()` 同步将该字段计入非官方判定。
4. 为 `FormatProfile` 补 `PartialEq, Eq`；补"自定义 FormatProfile 下 embed→extract→probe 往返 + 容量估算"回归测试。
5. **const 构造能力**：按 §6 待决策项 D1 的结论补齐 `const fn`（new 至少可立即提供；链式 with_* 取决于字段类型）。

### 5.3 阶段 2：门面（Additive，单文件 `src/facade.rs`）

`StrHide` 持 `profile` 与引擎基线 `local`，普通方法转发现有自由函数，每方法 1–3 行；`WriteOptions` / `LocalParams` / `StegoOptions` 原样复用。

**动词 × 载体矩阵（设计期一次定全）：**

| 域 | 动词 | path 形式 | bytes / 内存 |
|---|---|---|---|
| 结构域 | write | ✅ | ✅ write_bytes |
| 结构域 | read | ✅（output/overwrite） | ✅ read_bytes |
| 结构域 | restore | ✅ | ✅ restore_bytes |
| 结构域 | inspect | ✅ | ✅ inspect_bytes（按需） |
| 结构域 | verify | ✅ | —（按需） |
| 内容域 | embed | ✅ embed_file（复用 commit_carrier_bytes） | ✅ |
| 内容域 | extract | ✅ extract_file（复用 commit_carrier_bytes） | ✅ |
| 内容域 | probe | — | ✅ |

要点：

- **不做命名空间形态、不做双形态并存**：write/embed、read/extract 动词本就正交，根级直通无歧义（同 OpenStego）。
- **Fluent 链是纯糖**：等 CarrotHash 真实跑起来、确认普通方法不够用再加；若上，按 reqwest 模式（动作方法返回 per-op builder，只此一种形态），payload 走 `impl Into<PayloadSource>` 或 `.text()/.file()/.bytes()`，并以 `.overwrite(true)` 替代位置布尔。
- 内存写默认 `RejectionPolicy::ContentOnly`、路径写默认 `Strict`，在 facade 显式表达。
- 保留 per-op 覆盖 `LocalParams` 的入口（v2 的 `.compression()/.rejection()` 逃生舱思路）。

### 5.4 阶段 3：CLI 接入（含 v2 三个坑）

1. `run_cli_from(args)` **返回退出码（`Result<i32>`/`ExitCode`），不在库内 process::exit**；由宿主决定是否退出。
2. **argv[0] 必须保留**（v2 关键坑）：CarrotHash 转发用 `iter::once(argv[0]).chain(argv.iter().skip(2))`，不能传去掉程序名的切片。
3. 消除 cli 硬编码：字面量 3 处（`754/1356/2043`）与无 profile 入口（write/read/inspect/verify handler）统一改为 `&StrHide` 驱动。
4. stego 参数采用 **Overlay 增量覆盖**（以 `engine.profile().clone()` 为基底，仅覆盖显式提供的字段），保留预设 FormatProfile。
5. 优先级：**显式 CLI 参数 > 引擎绑定 profile > 官方默认**。
6. 原 `cli::run_cli()` 委托 `StrHide::new().run_cli_from(env::args_os())`；接入量实测（含 config/i18n 初始化）。

---

## 6. 开工前待决策项

- **D1（关键）：编译期方言构造的字段类型**
  - **路径 A（推荐）**：将 `Profile`/`StegoProfile` 的 `Cow<'static, str>`（及 `Cow<'static, [u8]>`）改为 `&'static str`（`&'static [u8]`）。私钥/域名本就几乎只用静态字面量，Copy 后 const fn 链式构造可编译，类型更简单，且真正实现零运行时开销；代价是失去从运行时 `String` 构造方言的能力。
  - **路径 B**：保留 Cow，宿主用 `LazyLock`/`OnceLock` 运行时初始化，或仅用 `const fn new()` 再在启动时赋值；代价是放弃"编译期常量方言"。
  - 项目未发布，无需兼容旧字段，本评估倾向**路径 A**。
- **D2**：FormatProfile 五个派生标签保留 `&'static`（不进堆），作为被评审决定记录；若需运行时构造，再补 `FormatProfile::leaked()`（Box::leak 封装）。
- **D3**：内存/路径默认 RejectionPolicy 差异在 facade 显式表达。
- **D4**：质量门禁——阶段 1/2 必须保持 `cargo build --release`、`cargo test`、两个 ignored 批测（batch_corpus / batch_stego）、`cargo fmt && cargo clippy -D warnings` 全绿。

---

## 7. 未覆盖项与风险

- `analysis.rs`、`router.rs` 对 facade 的影响未评估（聚焦 write/read/remove/stego 调用链）。
- `run_cli_from` 改造真实工作量未实测（需验证 `config::load` 与 i18n 初始化在宿主进程内的行为）。
- 若坚持路径 B（保留 Cow）且后续 Rust 稳定 `const Drop`（#133214），可再切回 const 链式构造；在此之前 v2 文档的 const 示例不可作为可编译依据。
- 主要外部风险：CarrotHash 若需从配置文件等运行时数据构造方言，与路径 A 冲突，需在阶段 2 前决策。

---

## 8. 参考来源

- OpenStego 主类 API：<https://www.openstego.com/api/com/openstego/desktop/openstego>
- OpenStego 命令行：<https://www.openstego.com/cmdline>
- Stegano（PyPI）：<https://pypi.org/project/stegano/>
- Stegano 模块文档：<https://stegano.readthedocs.io/en/stable/_sources/module.rst.txt>
- pnger（crates.io）：<https://crates.io/crates/pnger>
- reqwest ClientBuilder：<https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html>
- zip ZipArchive：<https://docs.rs/zip/latest/zip/read/struct.ZipArchive.html>
- Sequoia sq CLI：<https://docs.sequoia-pgp.org/sq/>
- 微软 Pragmatic Rust Guidelines：<http://microsoft.github.io/rust-guidelines/print.html>
- Rust 论坛：builder 参数类型共识：<https://users.rust-lang.org/t/builder-build-argument-type-convention/43341>
- const Drop 跟踪 issue：<https://github.com/rust-lang/rust/issues/133214>
