# strhide 结构域 lib 接口参数评审报告

| 项 | 内容 |
| :--- | :--- |
| 文档编号 | `STRUCT-PARAMS-AUDIT-20261025` |
| 审查时间 | 2026-10-25 |
| 基线 | commit `ddb409c`（master，crate 0.7.1），工作区干净 |
| 视角 | **接口与参数的规范性/一致性/可用性**：公开 API 形状、参数命名与类型、默认值语义、文档（rustdoc）准确性、CLI↔库映射。与 [`structure_domain_code_review_20261025.md`](structure_domain_code_review_20261025.md)（健壮性缺陷逐行深审）和 [`cli_lib_interface_audit_20261025.md`](cli_lib_interface_audit_20261025.md)（提取依赖维度）互补，三者无重叠条目 |
| 方法 | 逐行精读 `engine.rs`（2,268 行）、`params.rs`、`facade.rs`、`envelope.rs`、`errors.rs`、`router.rs`、`rejection.rs`、`commit.rs`、`sniff.rs`、`adapters/mod.rs` 全部公开项；对照 `cli.rs` 参数定义与 `handle_write`/`handle_restore` 调用点；10 个适配器的 `supported_strategies`/`choose_auto_strategy`/`strategy_capacities` 全量核对；`cargo clippy --all-targets` 全绿、`cargo test --lib` 242 项全过（验证当日） |
| 结论 | 无 P1（无"参数会写坏数据/读错数据"级缺陷）。**P2 共 5 项**（文档错误/公开 rustdoc 缺失/默认值语义误导/覆盖保护不一致），**P3 共 11 项**（命名与形状不统一、可用性），观察项若干。均为接口卫生问题，不影响功能正确性 |
| 配套 | 参数用法与全部公开面梳理见 [`structure_domain_api_guide_20261025.md`](structure_domain_api_guide_20261025.md) |

---

## 0. 总体结论

1. 结构域公开 API 的**运行时行为契约是自洽的**：L/P 类参数切分清晰（`LocalParams` writer-only / `Profile` 读写配对）、`#[non_exhaustive]` + const builder 风格统一、错误类型单一且判别式可分支、五个动词的 bytes/路径双形态共享同一核心。没有发现"参数组合会导致数据损坏或静默丢失"的问题。
2. 问题集中在**文档层与 API 形状层**：两处 doc 注释粘连错位导致三个公开函数在 rustdoc 上缺失文档（其中 `remove_carrier_with` / `remove_carrier_with_options` 完全无文档）；crate 级文档的 CLI 示例使用了**不存在的参数** `--data-text`；`WriteOptions` 默认值的文档描述与 CLI 实际默认相反；三个动词的"输出覆盖"保护口径不一致。
3. 命名层面存在一组**同一后缀多义**（`_with`）与**双轨词汇**（库 `remove_*` vs CLI/门面 `restore`）的问题；`Profile` 上两个"domain"参数类型不同（`&[u8]` vs `&str`）易混淆。项目未发布（AGENTS.md 声明不考虑旧版本兼容），是统一命名窗口期的最后机会。

---

## 1. P2 问题（5 项，建议尽快处理）

### P2-1. crate 级文档的 CLI 示例使用不存在的参数 `--data-text`

**位置**：`rust/src/lib.rs:45`

```rust
//! strhide write carrier.png --data-text "hello" --password pw
```

**问题**：CLI 的 payload 源参数是 `-d/--data FILE`、`-t/--text TEXT`、`--text-file`、`--text-base64`、`--stdin`（`cli.rs:120-135` 的 `PayloadSourceArgs`），不存在 `--data-text`。`lib.rs` 是 `cargo doc` 的首页与 crates.io 展示页，库用户把首页示例照抄进 shell 会得到 clap 参数错误。

**影响**：新用户首次体验即失败；且这是 crate 级文档（README 的对应示例是正确的，两处不一致）。

**建议**：改为 `strhide write carrier.png --text "hello" --password pw`。顺带核对 lib.rs:46-49 的 `read`/`inspect`/`verify`/`restore` 示例（`--output`/`--password` 均存在，无其它问题）。

### P2-2. doc 注释粘连错位：三个公开函数在 rustdoc 上缺失文档

**位置**：`rust/src/engine.rs:651-678`（write 侧）、`rust/src/engine.rs:1672-1687`（remove 侧）

这是同一模式的编辑事故，两处：

**write 侧**：`/// Inject `source` into `carrier_path` with library-level tuning.` 起的完整文档块（含 `local`/`profile` 参数说明和 `write_carrier_with` + `LocalParams`/`Profile` 的完整示例，engine.rs:651-678）紧跟在 `write_carrier`（649 行结束）之后，却粘连在**私有**结构体 `struct WriteCoreResult`（engine.rs:680）上。公开的 `pub fn write_carrier_with`（engine.rs:1131）只有后补的简短文档（1124-1130，"staging through a temp file and an atomic rename"），不含 `local`/`profile` 参数说明与示例。

**remove 侧**：本应属于 `remove_carrier_with_options` 的文档（"Strip the envelope of a carrier written under `profile`... `overwrite` decides what happens..."，engine.rs:1672-1681）与本应属于 `remove_core` 的文档（"Strip the envelope from `host` into `out`..."，engine.rs:1682-1687）**两段粘连**，全部落在私有 `fn remove_core`（engine.rs:1688）上。公开的 `pub fn remove_carrier_with`（engine.rs:1783）与 `pub fn remove_carrier_with_options`（engine.rs:1801）**没有任何 doc comment**。

**影响**：`cargo doc` / docs.rs 上：`write_carrier_with` 缺 `local`/`profile` 语义说明与示例；`remove_carrier_with`、`remove_carrier_with_options` 零文档（含 `overwrite` 语义、"逆序移除"契约等关键信息）。私有项的 doc 不进文档，这段文字完全沉没。结构域恰恰是文档密度最高的模块，此处缺口显眼。

**建议**：将 651-678 的文档块移到 `pub fn write_carrier_with`（1131）前（与 1124-1130 现有文档合并）；将 1672-1681 移到 `remove_carrier_with_options`（1801）前、1672 前半段（不含 `overwrite` 段）给 `remove_carrier_with`（1783）；1682-1687 留给 `remove_core`。移动后 `cargo doc` 应无 broken intra-doc link。

### P2-3. `WriteOptions` 默认值文档与 CLI 实际默认相反

**位置**：`rust/src/engine.rs:577`（`WriteOptions` doc）

```rust
/// The `Default` values match the CLI defaults: `auto` strategy, timestamps and
/// in-place backup preserved, no encryption, no stealth.
```

**问题**：库默认 `output_path: None` 即**原地覆盖 carrier**；而 CLI `write` 默认（无 `--in-place`、无 `-o`）写 `<stem>-out.<ext>` 新文件、原 carrier 不动（`resolve_carrier_target`，cli.rs:2291+；README 亦如此宣传）。库默认实际对应 **CLI 的 `--in-place`**，不是 CLI 默认。"match the CLI defaults" 只对 `strategy`/`preserve_time`/`backup`/密码四项成立，对最关键的输出位置一项是反的。

**影响**：库使用者按"CLI 默认不动原文件"的心智直接用 `WriteOptions::default()`，会把原 carrier 就地替换（虽有 `.bak`）。这是安全预期层面的误导，比纯措辞问题重。

**建议**：改写为"Defaults match the CLI's `--in-place` behaviour: overwrite the carrier in place, keep a `.bak`, clone timestamps; `strategy='auto'`, no encryption, no stealth. For the CLI's default ('write to `<stem>-out.<ext>`'), set `output_path` explicitly."

### P2-4. crate 级文档"六个载体家族"过时（实际 10 个适配器）

**位置**：`rust/src/lib.rs:11`（"Format-preserving injection for six carrier families"）、`lib.rs:13-15`（列举缺 WebP/HEIF/WAV/MKV）、`lib.rs:29-37`（六行格式表）

**问题**：`router::ADAPTERS` 现有 10 个适配器（PNG、JPEG、WebP、HEIF、MP4、WAV、ZIP、PDF、PE、MKV），README 主表格已列全。前次审查的 P3-21 已修复 `adapters/mod.rs:18` 的同类失实注释（"six supported carriers"），但 `lib.rs` 的 crate 级文档漏改——同一处文档漂移只修了一半。

**影响**：crate 首页宣称的载体集合小于实际能力；用户可能因首页信息放弃 WebP/HEIF/WAV/MKV 用例。

**建议**：lib.rs 的 Feature 列表与格式表更新为 10 格式（可直接采用 README 主表口径：PNG `prIv`、JPEG APP15、WebP `SHRD`、HEIC/HEIF `item_hidden`/`free_box`/`box_uuid`、MP4 `uuid`、WAV `SHRD`、MKV `ebml_void`、ZIP pre-CD、PDF 增量、PE 三信道 + `eof`）。

### P2-5. 三个动词的"输出覆盖"保护口径不一致（write 无保护、门面不可表达）

**位置**：
- 写路径无检查：`rust/src/engine.rs:1145`（`target_path = options.output_path.unwrap_or(carrier_path)`）与 `engine.rs:1203`（`std::fs::rename(&tmp_target, target_path)`）之间没有任何目标存在性检查——`fs::rename` 的替换语义直接覆盖已存在文件。
- 读路径有检查：`engine.rs:1556-1561`（`write_payload_to` 拒绝覆盖，报 `Rejection`）。
- 还原路径有检查：`engine.rs:1822-1827`（`remove_carrier_with_options` 拒绝覆盖非原地目标）。
- 门面锁死 `false`：`rust/src/facade.rs:156-163`（`StrHide::read` 硬编码 `overwrite = false`）、`facade.rs:165-174`（`StrHide::restore` 同）；而内容域 `facade.rs:299-326` 的 `extract_file` **有** `overwrite` 参数。
- CLI 有保护：`cli.rs:2276-2284`（`check_overwrite`）+ 各 handle 的 `--overwrite` 传递。

**问题**：三个层面各不一致——

| 动词 | 库层 | 门面层 |
| :--- | :--- | :--- |
| write | **覆盖已存在目标，无任何拒绝**（保护只在 CLI） | 无 `overwrite` 参数可言 |
| read | `overwrite` 参数，默认拒绝 | `overwrite` 被硬编码 `false`，**无法表达允许覆盖** |
| restore | `overwrite` 参数（仅 `_with_options` 版），默认拒绝 | 同上，硬编码 `false` |

read/restore 的"拒绝覆盖"doc 都写明是为"安全默认"，但 write（同样会覆盖一个已存在文件的动词）反而无此默认；门面作为推荐入口却让用户对 read/restore 的覆盖场景无解（必须退回自由函数）。

**影响**：库使用者的一致性预期被破坏：要么误以为 write 也有保护（数据被替换），要么在门面上卡死（无法覆盖输出）。CLI 用户不受影响（`check_overwrite` 已覆盖全部动词）。

**建议**（择一即可，倾向 ①）：① 门面 `read`/`restore` 增加 `overwrite: bool` 参数（与 `extract_file` 对齐）；② 引擎 `write_carrier_with` 增加 `overwrite` 字段进 `WriteOptions`（默认 `true` 保持现行为，或默认 `false` 并在 CLI 显式传 `true`——后者与 read/restore 口径完全统一，但属行为变更需权衡）；③ 至少在 `WriteOptions.output_path` 与 `remove_carrier`/`read_carrier` 的 doc 中写明三者口径差异。

---

## 2. P3 问题（11 项：不统一 / 不规范 / 不好用）

### P3-1. `_with` 后缀语义漂移：同一后缀五种含义

| 函数 | `_with` 追加的东西 |
| :--- | :--- |
| `read_carrier_with` | `overwrite`（**不含** profile！） |
| `read_carrier_with_profile` | `overwrite` + `profile` |
| `remove_carrier_with` | `backup` + `profile`（不含 overwrite） |
| `remove_carrier_with_options` | `backup` + `profile` + `overwrite` |
| `write_carrier_with` | `local` + `profile` |
| `inspect_carrier_with` / `verify_carrier_with` | `profile` |

读侧想带 profile 必须用 `_with_profile`，写/删/查/证侧的 `_with` 就带 profile；`read_carrier_with` 是唯一一个 `_with` 却不带 profile 的。参数序也有微差：`remove_carrier_with_options(.., backup, profile, overwrite)` 与 `read_carrier_with_profile(.., password, overwrite, profile)` 中 `profile` 与 `overwrite` 的位置互换。

**建议**：趁未发布统一——方案 A：`_with` 一律表示"完整参数版"（read 补齐为 `read_carrier_with(path, out, password, overwrite, profile)`，现有 `_with_profile` 作为别名或删除）；方案 B：全部改成 options 结构（`ReadOptions`/`RemoveOptions`），与 `WriteOptions` 对齐，顺带解决 P3-2。

### P3-2. bytes 系入口必须显式传 `Profile`（write 还要 `LocalParams`），无便捷版

**位置**：`engine.rs:1252`（`write_carrier_bytes`，5 参）、`engine.rs:1623`（`read_carrier_bytes`，3 参）、`engine.rs:1889`（`remove_carrier_bytes`）、`engine.rs:1958`（`inspect_carrier_bytes`）、`engine.rs:2165`（`verify_carrier_bytes`）

路径版有五个免 profile 的便捷函数（`write_carrier`、`read_carrier`、`remove_carrier`、`inspect_carrier`、`verify_carrier`，内部用 `Profile::default()` / `LocalParams::default()`）；bytes 版全部要求显式传 `&Profile`。不想私有方言的内存用户每处都要写 `&Profile::default()`（指南示例 §13.3 可见重复度）。README 的库示例正是用门面 `ENGINE.write_bytes(...)` 绕开的——说明 free-function 层确实缺这一档。

**建议**：补 `read_carrier_bytes_default` 之类的便捷版（或 `profile: Option<&Profile>`，`None` = 官方方言），或明确文档"内存入口请用 `StrHide` 门面"并把 free-function bytes 版定位为高级 API（现状两者都没写）。

### P3-3. 命名双轨：库 `remove_carrier*` vs CLI/门面 `restore`

库的动词叫 remove，CLI 命令、README、门面方法都叫 restore。跨层对照（如把 CLI 脚本翻译成库调用）时需要知道 `restore ⇒ remove_carrier_with_options`。doc 中只有 `remove_carrier` 提到 CLI 的 `restore`（间接）。

**建议**：在 `remove_carrier*` 五个函数的 doc 顶部统一加一行 "This is the library name of the CLI/`StrHide` verb `restore`."（改名 `restore_carrier*` 也可行但属破坏性变更，若近期发布可考虑）。

### P3-4. `WriteOptions.strategy` 是自由字符串，无类型安全

**位置**：`engine.rs:587`（`pub strategy: &'a str`）、`engine.rs:940-947`（运行时校验）、`router.rs:108-117`（`strategy_to_id`）

策略名集合是封闭的（13 个注册名 + `"auto"`），但 API 收 `&str`：拼写错误、大小写错误都要到运行时才报错，且错误消息有两个不同出处（engine 的 `"Strategy '...' not supported by adapter '{}'"` 与 router 的 `"Strategy '...' is not registered in STRATEGY_REGISTRY"`），同一类错误两种文案。CLI 侧 `-s` 收字符串合理，库侧可以更强。

**建议**：提供 `Strategy` 枚举（含 `Auto` + 13 个变体）与 `impl From<&str>`，`WriteOptions.strategy` 保持 `&str` 兼容或改为枚举；错误消息统一走 `strategy_to_id`。

### P3-5. `Profile` 上两个 "domain" 参数：命名近似、类型不同

**位置**：`params.rs:459`（`with_stealth_domain(&'static [u8])`）与 `params.rs:310`（`StegoProfile::with_stego_domain(&'static str)`），经 `Profile::with_stego_domain` 双轨暴露

同一 `Profile` 上：结构域的域分隔串是 `&'static [u8]`，内容域的是 `&'static str`；一个是 stealth magic 派生域、一个是 HKDF 密钥派生域。四个 builder 名字 `with_stealth_domain` / `with_stego_domain` 只差一个前缀字母段，却类型不同、语义不同。`STEALTH_DOMAIN` 常量是 `&[u8]`，内容域官方域没有对应公开常量名。

**建议**：统一为 `&'static [u8]`（`&str` 可 `.as_bytes()` 无损转换，改类型是纯收窄）；或在两组 builder 的 doc 里互相参见并写明类型差异。空串"视为未设置"的规则两组一致（好），但只写在 `secret()` 的 doc 里，`domain` 侧应同步写明。

### P3-6. `PayloadSource::Bytes` 标记 `is_file = true`、文件名 `"payload.bin"`

**位置**：`engine.rs:314`

`Bytes` 是"inline 字节"，却设置 `FLAG_IS_FILE` 并存储文件名 `"payload.bin"`；读回后 `ReadResult.is_file == true`。这与 `Text`/`Stdin`（`is_file = false`、空文件名）形成三态。行为本身跨 CLI/库一致，但对库用户是隐性约定：没有任何 doc 说明 `Bytes` 会带文件语义。

**建议**：在 `PayloadSource` 枚举 doc 中为每个变体写明 metadata 结果（文件名、`is_file`），特别是 `Bytes` 的 `"payload.bin"` + `FLAG_IS_FILE` 组合。

### P3-7. `RejectionPolicy::ContentOnly` 与 `Strict` 在 `write_carrier_bytes` 上行为相同

**位置**：`engine.rs:1268-1271`（`if local.rejection != Skip { check_content(...) }`）、`rejection.rs:360-396`

bytes 入口做不了文件系统检查，所以 `Strict` 与 `ContentOnly` 在该入口等价（都只跑 `check_content`），只有 `Skip` 有差异。参数档位是三档，实际行为在某些入口只有两档——类型系统没有表达这一点，doc 也没写。

**建议**：在 `RejectionPolicy` doc 中写明"bytes 入口下 `Strict` 退化为 `ContentOnly`"；或让 bytes 入口对 `Strict` 报错/警告（不推荐，过于严格）。

### P3-8. `inspect` 与 `read`/`restore` 对"无信封"的报告口径不同

`inspect_carrier*` 返回 `Ok(has_hidden_data = false)`；`read_carrier*` / `remove_carrier*` 同场景返回 `Err(NoHiddenData)`；`verify_carrier*` 返回 `Ok` 但 L2 = fail。三动词三种口径各有道理（inspect 是查询语义），但没有任何一处 doc 把三者放在一起说明，调用方容易在错误处理上写错。

**建议**：在三个动词（或模块级）doc 中补一张"无信封时各动词的表现"小表（指南 §11/§14 已代劳，源头也应有一份）。

### P3-9. engine.rs 存在重复的 `#[cfg(feature = "stego")]`

**位置**：`engine.rs:2028-2029`（`InspectResult` 构造的 `content_stego_capacity` 字段前，同一属性连续两遍）

重复 cfg 无功能影响（同属性多次应用等价于一次），当前 clippy 未报（`clippy::duplicated_attributes` 对 cfg 不触发），但属于明显的编辑残留。同日内容域审查曾在 `stego/png/engine.rs` 抓到过同类问题并已修复，此处是漏网之一。

**建议**：删除 2029 行的重复属性。

### P3-10. 门面 `extract_file` 目录输出硬编码 `extracted.bin` 且非原子写

**位置**：`facade.rs:308-324`

结构域 `read` 目录输出用 metadata 文件名 + `sanitize_filename`；内容域 `extract_file` 目录输出固定 `extracted.bin`（内容域确实没有文件名元数据，行为可解释）且直接 `fs::write` 非原子（原文件可能被截断后写失败）。此项是 2026-10-25 全面审查的结构域相邻遗留项（该报告附录 B 已列），本报告收录仅为完整性：结构域 `read` 的对应路径（`write_payload_to`）是清洗 + 直接创建，本身也是"创建失败即报错"，无截断风险——两者实际风险不对称。

**建议**：`extract_file` 目录输出加防覆盖检查（已有）+ 临时文件原子提交（复用 `commit_carrier_bytes` 或简单 write-rename）；文档写明与结构域 `read` 的文件名差异。

### P3-11. 结构域与内容域的默认 KDF 迭代数不同，跨域文档易混淆

结构域信封 PBKDF2-HMAC-SHA256 = **100,000** 轮（`crypto.rs:92` `PBKDF2_ITERATIONS`，README Features 段落描述的正是它）；内容域 JPEG superblock 默认 cipher suite id 1 = **200,000** 轮、id 2 = 600k（README 内容域段落）。两个"默认 PBKDF2 轮数"同时存在于同一 README。不是缺陷（两个独立子系统各自校准），但用户问"strhide 默认 PBKDF2 多少轮"会得到两个答案。

**建议**：`crypto::PBKDF2_ITERATIONS` doc 加注"structure-domain envelope only; content-domain JPEG superblock suites use their own (200k/600k)"；README 两处描述各加域限定词。

---

## 3. 观察项（确认合理，记录备查）

1. **`WriteOptions` 非 `#[non_exhaustive]`、`LocalParams`/`Profile` 是**：形状不统一但都有道理——`WriteOptions` 生命周期参数 + 调用方以 struct-literal 构造为主（`..WriteOptions::default()`），`LocalParams`/`Profile` 走 builder。若未来给 `WriteOptions` 加字段会破坏 struct-literal（`..default()` 写法不受影响，仅全字段字面量受影响），可接受。
2. **`StrHideError::TrellisInfeasible` / `TrellisCause` 在结构域不可达**：内容域专用错误共用枚举，`errors.rs` doc 已写明；结构域用户的 match 需要一个不可能触发的臂（或通配），属 `#[non_exhaustive]` 枚举的正常代价。
3. **`General` / `NoHiddenData` 无类别前缀**（`#[error("{0}")]`）：CLI 渲染裸文本，i18n 的 `category()` 对二者返回 `None`——设计如此。参数类错误（strategy 不支持、hint 超限等）全部落 `General`，没有专用 `InvalidArguments` 变体；当前规模可接受，参数校验类错误增多时再考虑。
4. **`STEALTH_DOMAIN` / `STANDARD_*_MAGIC` 双点导出**（`params` 定义 + `engine`/`envelope` re-export）：便利性 re-export，`rustdoc` 会显示两处，无碍。
5. **`MagicPair` 不是 `#[non_exhaustive]`**：与 `LocalParams`/`Profile` 风格不同，但它是纯数据对（两个定长数组），直接构造是合理用法，不算问题。
6. **HEIF `free_box` 在 `supported_strategies` 中但永不参与 auto**（`heif.rs:53-67` 只在 item_hidden/box_uuid 间选择）：显式指定可用，容量表有说明。auto 的"单选无回退 + 只选已验证策略"约定下这是正确行为，指南 §8 已写明。
7. **签名 PE 在 `strategy_capacities` 中全部标 `available=false`**（pe.rs:338+）：与 `run_rejection_checks` 的拒绝行为一致，口径统一（做得好）。
8. **`verify` 中 `_is_stealth` 绑定未使用**（engine.rs:2207 解构后下划线前缀）：lint 静音规范用法，无碍。
9. **写后 locate 自检**（engine.rs:1100-1108）：write 成功前对产物做一次回读定位，失败即拒——该机制（第五批修复落地）把"写读不对称"整类缺陷转为写入期错误，是本次核对中发现的接口强保证，建议在 README/library doc 中宣传。
10. **库单测基线**：`cargo test --lib` 242 通过、0 失败；`cargo clippy --all-targets` 0 警告（本次审查期间验证）。

---

## 4. 修复优先级建议

| 批次 | 内容 | 理由 |
| :--- | :--- | :--- |
| 立即（纯文档，零风险） | P2-1（`--data-text`）、P2-2（doc 移位）、P2-4（six carriers）、P3-9（重复 cfg）、P3-3（restore 命名 doc 注记） | 全部是注释/文档移动，不碰任何行为 |
| 随下个功能批次 | P2-3（`WriteOptions` 默认值 doc 改写）、P2-5（门面 read/restore 补 `overwrite`）、P3-6/P3-7/P3-8（doc 补齐） | P2-5 涉及门面签名变更（加参数），宜与其它 API 变更同车 |
| 发布前统一窗口 | P3-1（`_with` 后缀统一）、P3-2（bytes 便捷版）、P3-4（Strategy 枚举）、P3-5（domain 类型统一） | 未发布是改签名/改名的最后机会；AGENTS.md 明确不用考虑旧版兼容 |

以上全部条目均为建议，未改动任何代码。

---

*审查方法与覆盖声明：结构域全部公开项（含 `adapters` trait 与 10 个适配器的策略/容量面、`router` 注册表、`rejection` 函数、`envelope` 低层类型、`crypto` 常量）逐项与源码核对；行号基于 commit `ddb409c` 工作区。未运行动态 fuzz；`--ignored` 本地批量测试未运行（与接口参数无交互）。*
