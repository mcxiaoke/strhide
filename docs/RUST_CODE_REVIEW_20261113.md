# strhide Rust 代码全面评审报告

> **评审日期**：2026-11-13
> **评审对象**：`rust/`（crate `strhide` **0.9.5**，edition 2024，189 个 `.rs`、约 81,089 行）
> **评审范围**：代码质量、工程架构、算法与逻辑、异常处理、公开接口、安全性、测试、文档、CI/CD、性能
> **评审性质**：**只读静态审查**。未修改任何源码，未执行 `git commit` / `push`，工作区保持干净。
> **证据规则**：所有结论均要求 `文件:行号` + 代码片段或命令输出。所有 P1 已由主审回读源码复核；P2/P3 中标注「已复核」的为亲自核对，其余来自专项评审并保留原始出处。无证据的推断统一列入第 8 节「待核实」，不作为缺陷。

---

## 1. 结论摘要

**总体判断：这是一个成熟度明显高于平均水平的代码库，但存在 4 个必须在发布前处理的 P1 级问题，其中 2 个属于「检查门禁假绿」和「静默语义降级」——它们不会表现为测试失败，因而更危险。**

| 维度 | 评价 |
|---|---|
| 代码质量 | 良好。分层、错误分类、i18n、原子提交均有明确契约与测试守护；`clippy -D warnings`、`fmt --check`、rustdoc 全绿。主要债务是 CLI/facade 层破坏了自己定义的错误契约。 |
| 工程架构 | 分层红线在**代码层面成立**（两域互不引用、core 无上层代码引用、analysis 运行时只读），但**保障红线的 CI 工具链失效**；`facade.rs` 演化为上帝对象；`core::crypto` 语义上反向承载结构域协议。 |
| 算法与逻辑 | 核心正确性可信。STC Viterbi、三元 ±1、header/extension 双 seed 对称性、多轮重试、FLAC CRC/MD5 重算、代价模型除零防护均逐载体核对一致，并有 brute-force oracle / golden 向量 / 往返测试。未发现「正常路径必然写后读不出」的缺陷。 |
| 异常处理 | **最薄弱环节**。错误类型设计精良，但 CLI/facade 用 `General(String)` 吞掉 `io::Error` 与 `InvalidArgument`，`detail()` 与 `Display` 文本不一致，`lib.rs` 承诺的「按判别式分支、无需字符串匹配」在这些层实际不成立。 |
| 公开接口 | 稳定面基本清晰，`#[non_exhaustive]` 覆盖到位；但裁剪构建下 `Dialect` / `DualInspect` 出现静默降级，`structure::engine` 意外可见，文档版本与源码链接大面积过期。 |
| 安全性 | 无 P0。最实的问题是本地符号链接覆写与未认证 hint 进入错误消息；密钥/明文未全程 `Zeroizing` 与项目自身威胁模型存在落差。 |
| 测试 / CI | 1,072 个用例全绿，但门禁有效性有缺口：字节基线未进 CI、4 个 stress example 未自动化、CI 用 `--release` 绕过 debug 断言、37 个 `#[ignore]` 永不执行。 |

**P0：0 条。P1：4 条。P2：约 30 条、P3：约 15 条（按主题分组，第 1~8 节）。**

> **第 9 节为后续补充**：与 `docs/strhide_rust_code_review_report_gma_20261113.md` 交叉核验后，另新增 **6 条 P2、约 15 条 P3**（含 CLI 自覆盖、facade 取消信号、GUI 缓存、HEIF 桥前置检查等新维度），并纠正该报告中 3 处被拔高到 P0 的定性。该报告的 #01（7 个残留文件导致编译阻断）已证伪，不合并。

一句话优先级：**先修「假绿门禁」和「静默降级」，再统一错误契约，最后做密钥生命周期与文档同步。**

---

## 2. 审查范围、方法与限制

### 2.1 方法

1. 先摸清代码库：读 `AGENTS.md`（无 `CLAUDE.md`）、`rust/Cargo.toml`、`lib.rs`、`core/errors.rs`、`docs/api/ARCHITECTURE.md`，统计模块规模与代码异味分布。
2. 分派 **6 个专项评审**，覆盖：代码质量与异常处理、架构与分层、安全与密码学、内容域算法、结构域容器逻辑、测试/文档/CI/性能。遵守项目「同时不超过 3 个子智能体」的限制，分两批执行。
3. **主审回读复核**：对高危结论逐条打开源码验证，并对评审结论做降级/纠偏（见第 4 节脚注与第 6 节）。
4. 运行自动化检查取实证（第 3 节）。

### 2.2 限制（影响结论强度，请如实看待）

- 纯静态审查：**未做动态模糊测试、未做漏洞利用验证、未做性能剖析**。标注「可构造畸形输入」的条目给出的是代码级触发条件，未实测。
- **未运行** `python scripts/baseline_hash.py --check`（会写 `temp/baseline/work`，违反只读约束），因此「字节基线是否已漂移」未定论。
- **未运行** 4 个 stress example、未运行 `cargo build --release --all-features`（耗时且会更新二进制）。
- **未审计** `Cargo.lock` 与第三方依赖源码（`oxideav-h265`、`dct-io`、`jpeg-decoder`、`iced-x86`），依赖 CVE 状况未定论。
- 未逐行核对 `stego/heif/thumb_bridge.rs`(1520 行) 与 `stego/hevc/slot.rs`、`superblock.rs` 的 CABAC 重编码可解码性。**第 9 节已补充核验 `thumb_bridge` 的 probe/embed 前置检查与偏移算术，但「bin 翻转后码流仍可解码」仍需动态验证。**
- GUI（`gui/`）不在第 1~8 节范围，仅在与 Rust 库交互处提及。**第 9 节补充核验了 Tauri Rust 后端的 `extract_cache` 与输出路径处理（按该报告的线索），前端 TypeScript 仍不在范围。**

---

## 3. 自动化检查实证结果

工作区状态：`git status --short` 为空（无未提交改动）。

| 检查 | 命令 | 结果 |
|---|---|---|
| 格式化 | `cargo fmt --all --check` | **通过**，无格式漂移 |
| 静态检查 | `cargo clippy --all-targets --all-features -- -D warnings` | **通过**，0 warning |
| 文档构建 | `cargo doc --all-features --no-deps` | **通过**，0 warning |
| 全量测试 | `cargo test --all-features --all-targets` | **1,072 passed / 0 failed**（587 + 8 + 140 + 155 + 12 + 38 + 110 + 22） |
| 架构边界 | `python scripts/import_lint.py` | 输出 `OK: ... analysis !-> cli` —— **但这是假阴性，见 P1-2** |

补充说明：

- 测试日志中 `error: unrecognized subcommand 'write'` 是 `domains::engine_run_domain_cli_from_in_process` 用例**故意**验证域专属 CLI 拒绝非本域命令的预期输出，该用例结果为 `ok`，不是真实失败。
- 预扫描统计：生产代码（排除测试文件）中 `unwrap()`/`expect()` 约 400+ 处，但热点文件（`core/commit.rs`、`core/pipeline.rs`、`stego/io.rs`、`cli/helpers.rs`）的绝大多数位于 `#[cfg(test)]` 模块；`stego/header.rs` 的 `expect` 作用于定长 `[u8;64]` 切片，由类型系统保证。**本次未发现可由畸形载体直接触发的确定性 panic 路径**，但 `panic = "abort"` 会放大任何漏网 panic 的后果。
- 检查日志留存于 `temp/review_checks_20261113.log`（临时产物，未提交）。

---

## 4. 问题清单

### 4.1 P0（必须立即修复）

**无。** 核心写入/读取/还原链有 `finish_injection` 写入后 `locate` 自校验、`verify_restored` 全量 SHA-256 比对、AEAD tag 认证三道兜底，未发现可静默产出损坏载体或泄露密钥的必现路径。

---

### 4.2 P1（发布前必须修复）

#### P1-1 原子写临时文件用 `File::create`，可跟随预置符号链接

**位置**：`rust/src/core/commit.rs:661-676`（另见 `rust/src/structure/engine/write.rs:826-831`）
**已复核**：是。**3 个独立评审均独立指出同一处**。

```rust
// core/commit.rs:657-660 注释声称
/// A plain `fs::write` truncates an existing target before the new bytes are durable
/// (and follows a symlink instead of replacing it).
// core/commit.rs:669 实现
let mut file = std::fs::File::create(&tmp_path)?;   // 无 create_new
file.write_all(bytes)?;
```

同一个文件里的 `copy_file_to_new`（`commit.rs:220`）正确使用了 `OpenOptions::create_new(true)`，说明这是遗漏而非统一设计。`temp_path_for`（`commit.rs:204-209`）用 `pid + u32 随机数` 命名，`structure/engine/write.rs:826` 的 `.create(true).truncate(true)` 同样跟随链接目标。

**影响**：目标位于共享可写目录时，本地攻击者预置同名符号链接，可使 `write_bytes_atomic` / `commit_carrier_patches` 截断并写入链接指向的任意用户可写文件，随后 rename 覆盖目标。`panic = "abort"`（`Cargo.toml:156`）下 `TmpGuard` 不执行，无回滚。
**利用前提（不夸大）**：需同目录写权限、可获知/监视 pid 与临时名；Windows 创建符号链接通常需管理员权限或开发者模式。属**本地**场景，不是远程漏洞。
**整改**：所有临时文件统一 `OpenOptions::new().write(true).create_new(true)`；`AlreadyExists` 时重新生成随机名重试（照 `create_carrier_backup` 的既有模式）；Windows 额外拒绝重解析点，并显式设置受限 ACL。

#### P1-2 架构边界门禁 fail-open：`analysis.rs` 路径不存在，CI 假绿

**位置**：`scripts/import_lint.py:365, 162-167, 381-386`
**已复核**：是（含实跑输出与文件系统核对）。

```python
# import_lint.py:365
( rust_src / "analysis.rs", {"cli"}, "analysis !-> cli" ),
# import_lint.py:163-167
def rust_files(root: Path) -> list[Path]:
    if root.is_file(): return [root]
    if not root.is_dir(): return []
```

实测：`rust/src/analysis.rs` **不存在**（已重构为 `rust/src/analysis/` 目录，含 6 个 `.rs`）；`rust_files()` 返回空列表，`check_tree` 无违规，脚本仍打印包含 `analysis !-> cli` 的 OK 文案。CI (`ci.yml:45-46`) 把它当阻塞门禁。自检用例（`import_lint.py:281-284`）用合成的 `analysis.rs` 文件测试，无法发现真实路径失效。

**影响**：`analysis/` 全部 6 个文件不受任何架构红线约束；任何未来 `analysis → stego/cli` 引用都不会被拦截，而团队会误以为红线有效。规则集本身也缺 `analysis ↛ stego`、`{structure,stego} ↛ {analysis,cli}`、`{core,formats} ↛ facade`（`import_lint.py:343-369` 仅 5 条规则）。
**澄清**：脚本是全文逐行扫描（不是只查文件头 `use`），`#[cfg]` 分支同样被扫描，这两点**不构成缺陷**。
**整改**：规则 root 改为 `rust_src / "analysis"`；`main()` 开头断言每条规则的 `rust_files(root)` 非空，否则返回非零；规则改为「层 → 允许更低层」白名单生成；补齐上述缺失方向；**另增加模块文件唯一性检查（同一目录 `foo.rs` 与 `foo/mod.rs` 并存即报错，防 `rustc E0761`），使未来的目录化重构不会再次让规则 root 静默失效**（该加固建议来自第 9 节交叉核验，当前工作区不存在此问题）。

#### P1-3 裁剪构建下 facade 静默降级：私钥被丢弃、跨域检查返回「空成功」

**位置**：`rust/src/facade.rs:446-457, 571-635`；`rust/src/lib.rs:193`
**已复核**：是。

```rust
// facade.rs:447-457
pub const fn with_default_secret(mut self, secret: &'static str) -> Self {
    #[cfg(feature = "structure-base")] { self.structure.default_secret = Some(secret); }
    #[cfg(feature = "content-base")]   { self.stego.default_secret = Some(secret); }
    self
}
// facade.rs:571-577 / 625-634
pub fn inspect_any(&self, carrier: &Path, opts: &DualOptions<'_>) -> Result<DualInspect, StrHideError> {
    #[allow(unused_variables)] let _ = (carrier, opts);
    ...
    Ok(DualInspect { /* 字段全部带 #[cfg] */ })
}
```

`facade` 无条件编译、无条件导出，但 `Dialect` 字段与 `DualInspect`/`DualVerify` 全部字段被 `#[cfg]` 门控。在 `--no-default-features`（`check_feature_matrix.py` 的第 1 个组合，能编译通过）下：传入的部署密钥被静默丢弃、`is_official()` 恒为 `true`；`inspect_any` / `verify_any` 返回 `Ok(空结构体)` 报告成功。

**影响**：**静默语义/安全降级**，编译矩阵与测试都抓不到；下游在最小构建下以为绑定了私有方言、完成了双域检查，实际什么都没做。与 `ARCHITECTURE.md:95`「域名方法随 feature 出现或消失」的约定不一致。默认构建不受影响。
**整改**：给 `inspect_any` / `verify_any` / `smart_extract` 加 `#[cfg(any(feature="structure-base", feature="content-base"))]`；两域皆关闭时返回显式 `Unsupported` 错误而非 `Ok(空)`；补一个 `--no-default-features` 的 API 契约测试。

#### P1-4 未认证的 password hint 被三重拼接，并可作为终端控制序列注入错误消息

**位置**：`rust/src/structure/engine/read.rs:147-170`、`rust/src/core/errors.rs:319-322`、`rust/src/cli/render.rs:16-20`
**已复核**：是。

```rust
// read.rs:163-169  hint 在 decrypt_metadata(read.rs:186) 之前读取，并拼进 message
Some(h) => format!("Password required to extract hidden data. Hint: '{h}'."),
Err(StrHideError::PasswordWithHint { message, hint: hint_str.clone() })
// errors.rs:319-322  detail() 再拼一次
StrHideError::PasswordWithHint { message, hint } => match hint {
    Some(h) => format!("{message}. Hint: '{h}'."), None => message.clone(),
}
```

`errors.rs:41-43` 的文档明确声明「hint 是**字段**，不是消息的一部分，过去靠 `split_once("Hint: '")` 从文本提取会随措辞改动而失效」——实现违背了这条公开契约。同一 hint 在 `message`、`detail()`、CLI 的 `e.hint()` 中出现三次，且 `--json`（用 `Display`）与文本模式（用 `detail()`）输出不一致。

**安全面向**：hint 来自未认证区域（AEAD tag 直到 `read.rs:186` 才验证），却直接进错误文本；`core/fs.rs:170-195` 已有 `escape_control_chars`，CLI 的 `cmd_structure.rs:303-314` 主路径有转义，但库层 `Display` / `detail_i18n().render()` / 序列化的 `detail` 字段没有。伪造 112B 头 + 24B 尾（公开 magic + 可重算 CRC32）即可植入 OSC 52 剪贴板写入、bidi 覆盖等控制序列。
**整改**：`read.rs` 的 `message` 不再嵌入 hint；`detail()` 直接返回 `message.clone()`，hint 只经 `hint()` / `ErrorDetail.hint` 传递；在 `detail()` 与 `render()` 内统一转义控制字符；把 hint 回显推迟到 metadata AEAD 成功之后。

---

### 4.3 P2（下个版本修复）

#### 4.3.1 异常处理与公开接口契约（一组同源问题，建议一次性重构）

这一组共同导致 `lib.rs:6-7` 承诺的「调用方按判别式分支、无需字符串匹配」在 CLI/facade 层不成立。

| # | 位置 | 问题 | 影响 / 建议 |
|---|---|---|---|
| 2-1 | `cli/helpers.rs:73-86, 356-358`（**已复核**） | 密码文件/密钥文件的 `io::Error` 手工 `map_err` 成 `General(String)` | `kind()` 恒为 `General`，GUI/脚本无法区分文件不存在/权限不足/磁盘满。改用 `?` 触发 `From<io::Error>`，路径上下文另置 |
| 2-2 | `cli/helpers.rs:235-238, 323-326, 446-455`、`core/pipeline.rs:45-48` | `InvalidArgument` 变体在 CLI/pipeline 层形同虚设，参数校验一律 `General` | 库 API 返回 `ErrorKind::InvalidArgument`、CLI 返回 `General`，前端无法决定提示改参数还是报故障 |
| 2-3 | `core/errors.rs:92-99, 106-113 vs 292-322` | `detail()` 与 `#[error]` Display 文本不同：`SafetyThreshold` 措辞/数字顺序不同；`RestoreMismatch` 的 Display **完全不输出两个 SHA-256 字段** | 文本模式与 `--json` 输出不一致，且 `Display` 路径丢失人工比对所需的全部哈希。抽 `render_detail()` 让两者共用 |
| 2-4 | `core/errors.rs:254` | `TrellisInfeasible` 的 `category()` 映射到 `ErrUnsupported`（"不支持的文件格式"），而 Display 是 `Embedding infeasible` | 用户被误导为格式问题，掩盖 `DeadElement/DeadGroup` 诊断。新增 `ErrEmbeddingInfeasible` 或返回 `None` |
| 2-5 | `core/errors.rs:199-204` vs `cli/cmd_diag.rs:147-149, 762` | `From<serde_json::Error>` 把**序列化**失败也报成 `CorruptedData`（载体损坏），且写死 "serialization" 文案；CLI 同类错误一半 `General`、一半走 `From` | 同一类输出失败被分类到相反的错误种类。新增 `Serialization` 变体或统一归 `General` |
| 2-6 | `core/errors.rs:383-391 vs 402-415` | `ErrorDetail.category` / `category_label` 标注 `skip_deserializing`，反序列化后恒为 `None`，而 `render()` 完全依赖 `category` 决定模板 | JSON/IPC 往返后 `render()` 静默降级为无类别前缀。去掉 `skip_deserializing` 或按 `kind` 重建 |
| 2-7 | `facade.rs:796-804` | `smart_extract` 把内容域结构化 `ErrorDetail` 压平为 `General(format!(...))` | `kind`/`category`/`hint` 全丢，无法区分「解码器不可用」与「确实无隐藏数据」 |
| 2-8 | `core/commit.rs:682-710` | `rename_with_retry` 把 Windows `ERROR_ACCESS_DENIED(5)` 与共享冲突 32/33 一并当作「文件被占用」，4 次重试后一律 `TargetBusy` | 目录 ACL 拒绝/网络盘权限场景提示「被其他进程占用」，用户去找不存在的进程。仅对 32/33 重试，`5` 直接返回 `Io(e)` |
| 2-9 | `core/errors.rs:233-234` | `category()` 文档说只有 `NoHiddenData`/`General` 返回 `None`，实际 7 个变体返回 `None` | 注释误导。同步注释 |

#### 4.3.2 安全与密码学

- **2-10 密钥/口令/明文未全程 `Zeroizing`**（`core/crypto.rs:227-247, 473-475, 539-543, 612-644`；`structure/engine/write.rs:255-256`；`structure/engine/read.rs:48-56, 172-177`；`stego/format.rs:526-548`；`stego/envelope.rs:140-158, 549-558`；`cli/helpers.rs:52-91`）。`PasswordSecrets` 实现了 `Drop` 清零，但调用方用 `(secrets.payload_key, secrets.meta_key)` 把 `[u8;32]` **复制**成裸数组，副本永不清理；`AuthenticatedEnvelope.payload_key` 无 `Drop`；内容域 NFC 归一化口令是普通 `String`、PBKDF2 `master` 是裸数组；明文分块 `Vec` 与解压结果直接丢弃。`?` 错误分支同样不清理。
  **口径说明**：`THREAT_MODEL.md` §7.1 声明不承诺防内存取证，但 §2/对手 D 明确要求「密钥不在 `Copy` 结构里残留」，因此密钥残留属于自身承诺范围内的落差；明文残留则属于取舍。建议统一改用 `Zeroizing<[u8;32]>` / `Zeroizing<String>` 并复用已有的 `zero_bytes()`。
- **2-11 AEAD tag 校验晚于未认证长度字段的解析与内存分配**（`read.rs:141-188`、`structure/envelope.rs:798-844`、`stego/header.rs:297-431`）。`hint_len`/`meta_len` 在 tag 校验前就用于 `vec![0u8; n]`；trailer 的 `ube_offset`/`ube_total_size` 只有无密钥 CRC32 保护。**已有有效缓解**：`MAX_META_LEN=256KiB`、`MAX_HINT_LEN=1024`、`HEADER_LEN_MAX=2^26-1`、`check_pipeline_budget`，不构成 OOM。建议把长度并入头部 MAC，或至少在 `PasswordWithHint` 分支前完成 metadata 认证。
- **2-12 `Credential::FileKey` 无熵/来源边界**（`stego/format.rs:543-548`、`core/crypto.rs:117-124`、`cli/helpers.rs:352-385`）。只校验 32 字节长度，不校验全零/单字节重复/可打印 ASCII；此时跳过 200,000 轮 PBKDF2，仅一次 HKDF-Expand，离线猜解成本极低。建议构造器做最小熵检查并文档化「必须来自 CSPRNG」。
- **2-13 未认证输入驱动的 CPU/内存放大**：`structure/adapters/isobmff/mod.rs:482, 496-503` 允许 1 GiB `meta` box 单次 `vec![0u8; size]`（`size32==0` 分支取剩余文件长度）；`structure/adapters/mkv.rs:174-244` 的 `verify_structure` 无元素数上限，最小 2 字节 EBML 元素可驱动 `file_size/2` 次迭代，且每轮重复读尾部 24B（同层 ISO-BMFF 有 1,000,000 上限可对照）。建议上限降到 8–32 MiB、加元素数上限、`tail_envelope` 移出循环。
- **2-14 `release` 未显式声明 `overflow-checks`，叠加 `panic = "abort"`**（`Cargo.toml:152-157`）。解析攻击者可控字节时算术回绕静默、任何 panic 直接终止进程且 `Drop`（`TmpGuard`、`PasswordSecrets` 清零）不执行。**注意**：若改为 `overflow-checks = true`，必须同步为 `iced-x86` 增加 `[profile.release.package."iced-x86"] overflow-checks = false`，否则触发 `Cargo.toml:132-145` 注释所述的 4 GiB 边界 flaky panic。
- **2-15 分块 nonce 计数器 `chunk_index as u32` 截断**（`core/crypto.rs:373-392`）。`chunk_index == 0xFFFFFFFF` 时分块 nonce 与 metadata nonce（`^ 0xFFFFFFFF`）相同，理论上形成 two-time pad。默认 `CHUNK_SIZE=2MiB` 需约 8 PiB 才可达，属理论风险，但 `as u32` 写法应改 `u32::try_from` 并在溢出时报错。
- **2-16 `ChaCha12Stream` 派生 `Debug`**（`stego/prng.rs:51-56, 67-84`）。`state[4..12]` 就是 256-bit 密钥材料，`{:?}` 会写进日志。**当前未找到实际 `{:?}` 调用点，列入第 8 节待核实**，建议移除 derive 改手写。

> 已核实并**不列为缺陷**的设计：无密码时内置公钥统一加密、stealth 魔数/CRC 由口令派生、100k/200k PBKDF2 常量不可由头部降级、`rand::rng()` 为 CSPRNG（未发现 `SmallRng`/`StdRng` 用于密钥/nonce）、AAD 覆盖版本/flags/strategy/salt/nonce/长度/hint/suite/stc 参数、CRC 仅作完整性未当 MAC。

#### 4.3.3 工程架构

- **2-17 `core::crypto` 语义上反向承载 layer3A 协议**（`core/mod.rs:3-5` 声明 "holds nothing format-specific"，但 `core/crypto.rs:6-7, 260-334` 的模块文档自认「由 `crate::structure` 驱动、依赖 UBE v2 线格式」，并把 `derive_all` / `derive_header_mask` / `derive_stealth_magics` / `PBKDF2_ITERATIONS` 放在 layer1）。代码层无 `use crate::structure`（仅在文档注释），但只开 `content` 的构建仍编译进整套 UBE 专有 KDF。建议下沉到 `structure::crypto` 并由 `lib.rs` 重导出兼容路径。
- **2-18 `analysis` 依赖粒度失配 + 穿透 `#[doc(hidden)]` 内部实现**（`Cargo.toml:33,54`；`analysis/structural.rs:10-13, 675`；`analysis/calibration.rs:42`）。`analysis = ["structure", ...]` 强制拉入 `iced-x86`（唯一消费者是 PE `codebits`），而 analysis 实际只用 `pe_layout`/`pe_slack`；且直接依赖 `structure::adapters`/`envelope`/`registry` 这些文档明确排除在 SemVer 承诺外的模块。建议改为 `structure-base` 并建立 `structure::analysis_view` 窄接口。
- **2-19 进程级全局状态与「可重复调用的公开库 API」冲突**（`cli/mod.rs:51-62, 245-256, 289-293`；`core/i18n/mod.rs:49-70`）。`PROGRAM: OnceLock<String>` 用 `set()` 丢弃第二次及以后写入，`CURRENT_LANG: AtomicU8` 为全局；而 `StrHide::run_cli_from` 是设计为可嵌入、可重复调用的公开 API。同进程交替调用会显示第一次的程序名、并发请求互相覆盖语言。建议收进 `CliRunCtx`。
- **2-20 `facade.rs` 已演化为上帝对象**（1223 行、69 个 `pub fn`、74 处 `#[cfg]`）：同时承担配置值对象、双域编排、CLI 转发、三个子门面。P1-3 的静默降级正是由此滋生。建议拆为 `facade/{dialect,strhide,dual,structure,stego,analysis,cli}.rs`，`dual.rs` 升格为独立 orchestration 层。
- **2-21 公开可见面与稳定契约不一致**：`structure/mod.rs:13` 的 `pub mod engine` 未标 `#[doc(hidden)]`（文档的内部模块清单只列 `{adapters,envelope,registry,rejection}`）；`WriteResult.strategy: StrategyId` 等稳定结果类型的字段类型定义在 `doc(hidden)` 模块里；`lib.rs:278` 绕过 `stego::jpeg::UerdCostModel` 直取深层 `cost::` 路径。
- **2-22 特性矩阵缺关键组合**（`scripts/check_feature_matrix.py:43-55`）：11 行中缺 `structure-base+content-base`（这是 `facade.rs` 所有 `#[cfg(all(...))]` 代码的**最小触发组合**）、`content-audio`、`content-heif-bridge`、`structure-pe`、`cli`。脚本自身 docstring 说明只有 single-feature 构建才能暴露 cfg 漂移，`content` 全开会掩盖它。建议补齐并用 `cargo check --all-targets --locked`。
- **2-23 `#[allow(dead_code)]` 堆积**（`core/pipeline.rs` 8 处、全库约 35 处）。`core::pipeline` 的批量函数实际消费者只有 `cli`，默认构建（不含 cli）下靠 allow 静默豁免；`cargo clippy --all-features` 看不到。建议挂 `#[cfg(feature="cli")]` 或提升为正式公开 API。
- **2-24 同名符号与冗余委托层**：`stego::registry::list_algorithms` 返回 `Vec<(&str,&str,&str)>`，`StegoFacade::list_algorithms` 返回 `Vec<StegoAlgorithmInfo>`；`CostModelRegistry`（`stego/mod.rs:148`）是 5 个一行转发的纯委托门面；另有 4 层同名 `registry`。建议二选一保留并改名、移除委托层。
- **2-25 全局 `RenderCtx`/`RenderCtx::current()` 与 `StrHide: Copy` 的线程安全**：已复核 `StrHide` 全字段 `Copy`、无内部可变性，子门面仅持 `&'a StrHide`，**这部分无隐患**；风险集中在上述 2-19 的 `OnceLock`/`AtomicU8`。

#### 4.3.4 算法与逻辑

- **2-26 `GridRule::slots_per_block()` 的 `u8` 减法下溢**（`stego/format.rs:60-63`，**已复核**，`lib.rs:269` 将其作为稳定面导出）。`k_min > k_max` 时 dev/test panic、release（`overflow-checks` 默认 false）静默回绕成巨大槽数，导致容量虚高与巨额 `Vec::with_capacity`。`JpegFormatProfile::validate()`（`format.rs:222-227`）和 5 个引擎主入口有兜底，但 `pub const fn` 可被库调用方直接使用。建议改 `saturating_sub` 或先提升到 `usize`。
- **2-27 `hamming_embed_ternary` 对 `Move::None` 静默不写却无条件计 `flips += 1`**（`stego/coding.rs:484-489, 408-410`）。`flip_with_cost` 遇 `Move::None` 直接返回，Hamming 路径不校验翻转是否成功，若 syndrome 未满足则 extract 读出错误位。**当前唯一调用点 `png/engine/embed.rs:482` 传的 `spatial_move_safe(v)` 永不返回 `None`，产品路径不触发**；属函数级契约隐患，新增载体即命中。建议返回 `TrellisInfeasible`。
- **2-28 JPEG `probe` 容量是乐观上界，与 embed 的「可路由槽位」口径存在剩余差异**（`stego/jpeg/engine/capacity.rs:182-217`，**已复核**）。`max_raw_payload_bytes` 由 `n_total = block_count * slots_per_block` 几何槽数反算，而写侧 `layout.rs:265-278` 会把 Huffman 表关闭的方向置 `f64::INFINITY` 形成死槽。**代码已有缓解**：`has_incomplete_table` 分支（`:206-215`）用 grouped 上界修正，注释明确说明「报告几何上限会 advertise 一个必然失败的容量」，故评审初报的「必然不一致」需降级。剩余差异是**非 Huffman 原因的湿点（如大量 `coeff==±1`）未打折**。影响是用户按 capacity 写入可能遭 `PayloadTooLarge`/6 次重试拒绝，**非静默损坏**。建议 capacity 侧按当前可写槽数打折，或在 probe 文档标注为乐观上界。
- **2-29 FLAC `KeyedPermutation` 域大小 `n` 与 header 反算强耦合、无断言**（`stego/audio/perm.rs:76-90`、`audio/core.rs:224-229, 646-660`）。`n` 混入 SHA-256 派生 round keys，写侧 `n = slot_count - header_slots`、读侧从 `body_len/stc_h/stc_u` 反算，二者必须逐位相等；**当前两条 `plan_body` 已核对收敛、实现正确**，但任一改动使二者分叉会静默毁掉全部正文，直到 AEAD 才报错。建议写入 header 前加 `debug_assert_eq!` 并让 `n` 从单一来源取值。
- **2-30 取消检查点未覆盖最长循环**（`stego/coding/stc.rs:642`、`png/cost/hill.rs:112-171`、`structure/engine/write.rs:142-535, 875`）。STC 前向 Viterbi、rayon 代价图、`write_core` 的 PBKDF2/加密/全文件 locate 自校验均无 `CancelToken` 检查点（`jpeg/engine/embed.rs:216-217` 注释自认「没有安全的半途停止方式」）。**不影响数据正确性**（失败前不写出），仅影响响应延迟。建议每 4096 个 group 插一次 `control.check()?`。

#### 4.3.5 结构域容器与写入逻辑

- **2-31 Windows 硬链接的 in-place 写入未被识别**（`core/commit.rs:81-116`、`structure/rejection.rs:484-494`）。Windows 分支只比较 `canonicalize()` 后的路径字符串，`canonicalize` 不解析硬链接；`nlink > 1` 保护被 `#[cfg(unix)]` 跳过。结果是 rename 只替换一个目录项，另一个硬链接仍指向旧内容，`.bak` 也只备份了一个路径。建议用 `GetFileInformationByHandle` 比较卷序列号 + 文件索引。
- **2-32 ISO BMFF `size==0` 顶层 box 后追加信封会被吞进该 box**（`structure/adapters/isobmff/mod.rs:254-259, 297-302, 347-358`）。`ftyp` + `size==0 mdat` 是常见流式/CMAF 组合，能通过 `verify_structure`（只拒绝「所有 box 都是 size 0」），注入的 `uuid`/`free` box 落在 mdat 声明范围内；strhide 靠尾部 trailer 仍能读回，但严格解析器/播放器可能把信封当媒体数据。建议对含 `size==0` box 且其后仍有字节的载体拒绝追加类策略。
- **2-33 `MkvAdapter::locate` 的 eof 兜底无条件返回 `Some`**（`structure/adapters/mkv.rs:143-148`，**已复核**）。只要尾部 24B 是合法 trailer 形状（magic 公开 + CRC 无密钥，可伪造），就报告「有信封」，而 PNG/JPEG/ZIP/PDF 的同名兜底都带条件。后果是正常 MKV 可能被 `ensure_writable_host` 判「已含隐藏数据」而拒绝写入。建议与 `EofAdapter::locate` 对齐，要求 Void 前缀或 header magic 命中，否则 `Ok(None)`。
- **2-34 `EofAdapter::strip` 用 `orig_host_size` 截断，与重定位后的 `inject_offset` 脱节**（`structure/adapters/eof.rs:85-94` **已复核**；`zip.rs:356-358`；`engine/remove.rs:132-172`）。`remove_core` 对 eof 允许重定位并调整 `strip_header.inject_offset`，但 strip 只按写时的 `orig_host_size` 截断。**降级理由**：`verify_restored` 的 SHA-256 全量比对会拒绝提交，**不会写坏文件**；影响是前缀被外部改写（content 域重编码/remux）时永远还原不回原始文件。建议统一所有 eof 策略的还原坐标来源。
- **2-35 备份文件无限累积、rename 失败留下无主 `.bak`**（`core/commit.rs:174-201, 245-257`；`structure/engine/write.rs:880-885`）。`WriteOptions::backup` 默认 `true`，`next_backup_path` 只找未占用名字、从不回收；rename 失败时调用者拿不到 `backup_path`，`TmpGuard` 只清理 `.tmp`。建议保留策略 + 把备份路径写入错误上下文。
- **2-36 `verify` 通过 ≠ 可无损还原**（`structure/engine/report.rs:479-492`、`verify.rs:202-411`）。`verify_passed` 只检查容器结构、header/trailer 形状与 payload AEAD，从不重算 `orig_host_sha256`；载体在信封外被改动时 verify 为 true 但 remove 必抛 `RestoreMismatch`。代码注释已声明是「deliberately」，但公开 API 文档未见。建议在 `VerifyResult` 增加 `restorable` 字段或文档明示。
- **2-37 `validate_against` 未把注入区约束在 `host_len` 内**（`structure/envelope.rs:315-323`、`read.rs:142`、`inspect.rs:153`）。`envelope_coordinates_agree` 的 `injected_end > file_len` 检查只在 verify/remove 路径执行；read/inspect 完全信任 `inject_offset/inject_size`，`InspectResult` 会展示未经约束的值。建议把上界检查上移到 `validate_against`（它已接收 `host_len`）。
- **2-38 remove 恢复的是 stego 文件的时间戳/权限而非原始载体的**（`structure/engine/remove.rs:266-269, 324-336`；`options.rs:282-293` 的 `RestoreOptions` 无 `preserve_time`）。字节 bit-exact，但元数据不还原。建议把原始时间戳写入信封元数据（AAD 内）。
- **2-39 trailer CRC32 可任意伪造，`verify` L2 的「CRC32 OK」措辞误导**（`structure/envelope.rs:751-763, 813-844`、`verify.rs:332-348`）。CRC 只覆盖 16B prefix、无密钥、magic 公开；`derive_trailer_crc_mask` 也只依赖可从尾部读到的 magic。L3 AEAD 会兜底，`verify_passed` 不会误判为通过，但 L2 单独输出会误导。建议改文案为「magic/格式字段匹配」。

#### 4.3.6 测试、文档、CI

- **2-40 字节级基线门禁未进 CI，且基线元数据落后**（`AGENTS.md:33,68-74` 与 `ci.yml:39-74`；**已复核** CI 7 个步骤确实无 `baseline_hash.py`，只在 `.github/CONTRIBUTING.md:54,94` 与 PR 模板里要求）。`testdata/` 被 `.gitignore:112` 整体忽略，CI checkout 后 28 个语料不存在；`baseline.json` 记录的 commit 已落后 HEAD 约 37 个提交；`--write` 无条件重写基线、无 diff 确认。这是本项目「输出字节不变」硬约束的门禁失守。建议提交缩减语料 + 基线、`--write` 需 `--force` 并打印 diff、CI 加 `--check`。**字节是否已漂移未核实**（受只读约束未运行）。
- **2-41 4 个 stress example 完全不在自动化测试中**（`AGENTS.md:36-46` vs `ci.yml:54`）。8 线程并发、密钥轮换、多档填充、真随机载荷 SHA-256 往返这套最有价值的稳定性验证只靠人工触发，`cargo test --all-targets` 不执行 examples。建议 CI 加 smoke 级 `--example` 步骤。
- **2-42 CI 用 `--release` 跑测试，绕过 `[profile.test]` 与 debug 断言**（`ci.yml:54, 66` vs `AGENTS.md:25`、`Cargo.toml:127-150`）。`--release` 关闭 `debug_assertions`/`overflow-checks`，且 `[profile.test]` 的 `opt-level=2 / debug=1` 与 `[profile.test.package."iced-x86"]` 例外全被绕过——而团队特意依赖 overflow checks 处理 iced-x86 指针截断问题。建议 CI 至少跑一次 debug profile 的全量测试。
- **2-43 37 个 `#[ignore]` 用例在 CI 中永不执行**，其中 `local_`/`heavy_` 全部依赖被 gitignore 的语料；6 个纯 `#[ignore]` 无跳过理由；`test_regression/real_samples.rs` 等常规目录里的语料用例也不被 `cargo test local_/heavy_ -- --ignored` 选中。建议提交最小语料跑 `local_` 子集，heavy 改定期必跑。
- **2-44 3 个 unix-only 用例在 Windows 下完全跳过且无等价覆盖**（`rust/tests/test_cli/p2.rs:422` 只读父目录拒绝、`test_regression/fixes.rs:717` 权限保持、`review_20261019.rs:333` 非 UTF-8 文件名）。Windows 是 CI matrix 之一（`ci.yml:24`）也是主战场。建议用 `std::fs::set_readonly` / ACL 补等价断言。
- **2-45 facade 跨域 API 仅 happy path**（`rust/tests/test_lifecycle/facade.rs:731-757`）。`verify_any` 全仓仅 1 个测试文件引用，只断言 clean/stego 的 `is_any_ok()`；缺错误密码、损坏载体、路径不存在、双域冲突四类断言。
- **2-46 文档版本系统性过期**（**已复核**）：`Cargo.toml:3` 是 `0.9.5`，但 `docs/api/ARCHITECTURE.md:3`、`WIRE_SPEC_CONTENT.md:9`、`WIRE_SPEC_STRUCTURE.md:11`、`api/spec/{STRUCTURE-ENVELOPE.md:3, CRYPTO.md:2}`、`RELEASE.md:3,19`、`ROADMAP.md:5` 仍写 `0.9.3`。
- **2-47 docs/api 源码引用指向已迁移路径**（`ARCHITECTURE.md:681,684-689` 的 `../../rust/src/{params,crypto,errors,commit,analysis}.rs` 全部不存在，实际在 `core/` 下或 `analysis/mod.rs`；`api/spec/CAPACITY.md:105` 等 4 个 `文件:行` 引用指向已改目录的 `isobmff.rs`/`pe.rs`/`pdf.rs`/`pe_codebits.rs`）。另有 5 个 `CRATES_PUBLISH.md` 失效链接（`DEVELOPMENT.md:78`、`docs/README.md:99`、`RELEASE.md:106`、`legal/LEGAL.md:33`、`licenses/THIRD_PARTY_LICENSES.md:37`）与 `ARCHITECTURE.md:9` 的 3 个不存在的背景文档引用。建议批量替换并加 link-check 到 CI。
- **2-48 `TESTING.md` 与 `ROADMAP.md` 关于基线的整段描述过期**（`TESTING.md:9,74,78-82` 称基线在 `temp/baseline/baseline.json`、「不在版本库里」、「CI 不跑」；实际 `scripts/baseline_hash.py:49` 的 `DEFAULT_BASELINE` 已是 `scripts/baseline.json` 且已提交，AGENTS.md 也已把 `--check` 列为必跑）。
- **2-49 无依赖安全策略**：`.github/` 无 `dependabot.yml`/Renovate、无 `cargo audit`/`cargo deny`；`crates.yml:52` 的 `cargo publish` 未带 `--locked`（test/doc/release 都带）。解析不可信码流的 `oxideav-h265 0.0.16`、`strhide-rusty-h265 0.1`、`dct-io 0.1` 是 0.x 包，建议固定精确版本并审计。

#### 4.3.7 性能

- **2-50 FLAC embed 每轮克隆整块载体**（`rust/src/stego/audio/mod.rs:96, 208, 221`，`FLAC_EMBED_ATTEMPTS=6`），另有 8 处单次全文件克隆（`:294,429,558,675,713,741,769,795`）。对数百 MB 音频最坏 6× 分配 + 拷贝。建议改用 header 槽位回滚 / undo 日志复用同一 buffer。
- **2-51 全局初始化与重复解析**：`structure/adapters/isobmff/mod.rs:482` 的整块 `meta` 缓冲（见 2-13）、`structure/engine/write.rs:751-769` 的写入后全文件 `locate` 自校验，在大载体上是主要尾延迟来源。自校验是正确性兜底，不建议移除，可考虑限定扫描窗口。

---

### 4.4 P3（纳入 backlog）

| # | 位置 | 问题 |
|---|---|---|
| 3-1 | `stego/params.rs`(1454)、`options.rs`(1371)、`facade.rs`(1223)、`core/commit.rs`(1004) | 超大文件职责过载，建议按 `params/{codec,safety,profile,wire}`、`options/{embed,extract,probe,...}`、`facade/*`、`commit/{atomic,backup,paths}` 拆分。**注意** `stc.rs`(1488) 与 `structure/envelope.rs`(1134) 是单一算法/线格式，内聚度高，**不建议按行数机械拆分** |
| 3-2 | `cli/helpers.rs:372-378, 443-456`；`core/commit.rs:527-538, 631-642`；`stego/io.rs:115-128, 187-200` | hex 解析、时间戳/权限恢复、SafetyThreshold 警告块重复实现，已各自演化出不同错误文案 |
| 3-3 | `core/crypto.rs:260-293, 327-334`；`core/fs.rs:19` / `stego/envelope.rs:285` / `structure/engine.rs:62` | 3 份重复 HKDF 展开、HKDF 标签分散；3 个同名 `sanitize_filename` 但返回类型分别为 `String` / `Option<String>` / 重导出，易误用 |
| 3-4 | `core/commit.rs:236-239` | `copy_file_durable` 是仅被测试调用的遗留死代码（带 `#[allow(dead_code)]`），容易让维护者误以为备份走它 |
| 3-5 | 全库 43 处 `#[allow(clippy::too_many_arguments)]` | 41 处是内部引擎函数，属合理取舍；仅 `core/crypto.rs:724-735` 的 `pub fn verify_payload_stream` 有 9 个位置参数、5 个裸标量，建议引入 `VerifyStreamParams` 参数对象 |
| 3-6 | `core/commit.rs:193-200, 246-256` | 备份路径 16 次耗尽后归 `General`（应为 `Io`/`TargetBusy`）；兜底随机名未再检查 `exists()` |
| 3-7 | `core/errors.rs:233-234`（见 2-9）、`core/batch.rs:173,235,253` | `run_batch` 的 `Mutex::unwrap` 在 `panic=abort` 下会让 poison 触发二次 panic；建议 `unwrap_or_else(\|p\| p.into_inner())`。**是否存在可达的 worker panic 路径未核实** |
| 3-8 | `stego/prng.rs:51-56` | `#[derive(Debug)]` 泄露密钥材料（调用点待核实，见 2-16） |
| 3-9 | `stego/envelope.rs:222-238` | `Freshness::Seeded` 的 binding 不含 password/domain/suite，同 `--seed` 重复嵌入产生字节完全相同的输出，便于关联分析。**文档已声明仅用于回归基线**，建议在非测试构建拒绝或加 `--allow-deterministic` |
| 3-10 | `stego/format.rs:553-571, 931` | L2 的 `header_stc_seed`/`ext_stc_seed` 不含 `domain`，跨格式 trellis seed 相同；测试 `:931` 明确断言 `png.magic4 == hevc.magic4, "magic label is not per-format"`——**团队已知此行为，需先确认是否为有意设计**，不建议单方面改线格式 |
| 3-11 | `.gitignore:102, 112` | `temp*` 过宽（潜在误伤 `template.rs` 类文件）、`testdata/` 整体忽略（2-40 的根因）。当前实测无构建产物被提交 |
| 3-12 | `rust/tests/**` 6 处纯 `#[ignore]` | 缺跳过理由，易被长期遗忘（见 2-43） |
| 3-13 | `docs/licenses/gui-backend.md:48,397` | 第三方清单中的 `strhide 0.9.3` 版本过期 |

---

## 5. 分维度评价（对照用户关注的五个方面）

### 代码质量
整体良好：`#[non_exhaustive]` 覆盖到位、错误类型有 20 个语义化变体、i18n 结构化、原子提交有 `TmpGuard` + `TargetLock` + `sync_all`、测试密度高。**主要债务不在算法，而在边界层**——CLI/facade 用 `General(String)` 绕过了自己精心设计的错误分类体系（2-1 ~ 2-9），以及 35 处 `#[allow(dead_code)]` 把 feature 裁剪的真实债务显式豁免（2-23）。

### 工程架构
分层契约**代码层面真实成立**（已用 Grep 核对：两域互引仅出现在 intra-doc 注释中，core 无上层代码引用，analysis 运行时只读）。真正的风险在**治理**：门禁 fail-open（P1-2）、`analysis` 不受任何红线约束、`core::crypto` 语义反向依赖、`facade` 上帝对象、裁剪构建静默降级（P1-3）。这些都不是「写得不好」，而是「保障机制没跟上重构速度」。

### 算法和逻辑
**本次最可信的部分**。逐一核对了 STC Viterbi（含 `u=1` 唯一解、warm-up 自由状态、`DeadGroup` 判定）、奇偶矩阵、三元 ±1、湿纸码、header/extension 双 seed 的 embed↔extract 对称性、多轮重试的 salt/nonce 重现、JPEG/PNG/HEVC/Audio 槽位顺序、FLAC 残差修改后 CRC-16/STREAMINFO MD5 重算与二次解码比对、各代价模型的除零与 `!is_finite` 兜底。**未发现正常路径下的确定性正确性缺陷**。剩余问题是口径与防御性（2-26 ~ 2-30），且 2-27/2-29 当前产品路径不触发。

### 异常处理
设计优良、执行不一致。`StrHideError` 的变体划分、`ErrorDetail` 的语言中立视图、`kind()`/`category()`/`hint()` 都是好设计；但 `detail()` 与 `Display` 分叉、CLI 丢失底层 `io::Error`、`InvalidArgument` 名存实亡、未认证 hint 进入消息（P1-4）共同破坏了契约。`panic = "abort"` 又使任何漏网 panic 无 unwind、无 `Drop`（`TmpGuard`、`PasswordSecrets` 清零都不执行），把健壮性问题放大为进程终止。

### 公开接口
`lib.rs` 的 re-export 与 `docs/api/ARCHITECTURE.md` 基本一致，稳定面与 `doc(hidden)` 内部面划分清楚，`GridRule` 等不加护栏是文档明确声明的设计取舍。**三个缺口**：裁剪构建下的静默降级（P1-3，最严重）、`structure::engine` 意外进入稳定可见面（2-21）、文档版本与源码链接大面积过期（2-46/2-47）导致「按当前源码核对」的声明失实。

---

## 6. 已核实为设计取舍 / 不成立（明确不列为缺陷）

为避免误报，以下均经实读核对：

| 核查项 | 结论 |
|---|---|
| `stego` 引用 `structure`（或反之） | **不成立**。命中全在 `//!`/`///` 文档注释 |
| `core` 代码层反向依赖上层 | **不成立**。命中全在文档注释（语义层问题另见 2-17） |
| `analysis` 只读 / 不依赖 stego | 当前成立（运行时仅 `File::open`/`Read`/`Seek`），但**无 lint 保障**，见 P1-2 |
| 两域密钥派生域隔离 | 成立。结构域 `strhide-payload`/`metadata`/`stealth-*` 与内容域 `WireCipherProfile` 标签空间不重叠 |
| `GridRule` / `MagicPair` 不加 `#[non_exhaustive]` | 有意设计，`ARCHITECTURE.md:625` 要求第三方用结构体字面量构造私有方言 |
| 生产代码 `unwrap`/`expect` 可被畸形载体触发 | **本次未发现**。热点均在测试模块，或由定长切片/前置长度检查/类型系统保证 |
| 无密码内置公钥、stealth 派生魔数、100k/200k PBKDF2 | 项目文档已声明的设计，非漏洞 |
| `StrHide: Copy` + 子门面 `&StrHide` | 成立，字段全 `Copy` 无内部可变性，`Send`/`Sync` 无隐患 |
| `import_lint.py` 只查文件头 / 漏 cfg 分支 | **不成立**，脚本全文逐行扫描且只剥离注释与字面量 |
| ZIP/RIFF 的 eof 兜底追加到 EOCD/RIFF 边界之外 | 有意的兼容性取舍（代码注释与两轮 EOCD 扫描均自认），write/read/remove 自洽可无损还原；应写入文档而非改代码 |
| `verify` 通过 ≠ 可还原（2-36） | 代码注释声明为 deliberate；列 P2 是要求**文档明示**，不是要求改行为 |
| `structure/**` 与 `stego/hevc/**` 的 `Result<_, String>` | 共 3 处签名，全部 `pub(super)`/模块内，**不泄漏到公开 API**；`HostAdapter` 所有方法均返回 `StrHideError` |
| `stc.rs` / `structure/envelope.rs` 行数超千 | 单一算法/线格式，内聚度高，不建议机械拆分 |

**评审结论纠偏**（体现主审复核价值）：
- 算法评审初报「JPEG 容量必然与 embed 不一致」为 P1 —— 回读 `capacity.rs:206-215` 发现已有 `has_incomplete_table` grouped 修正，降级为 P2 并注明剩余差异仅限湿点口径（2-28）。
- 结构域评审初报「`EofAdapter::strip` 会写坏文件」为 P1 —— 回读 `remove.rs:176-238` 确认 `verify_restored` 全量 SHA-256 兜底会拒绝提交，降级为 P2「永远还原不回原始文件」（2-34）。
- 安全评审初报「HKDF L2 域隔离失效」为 P2 —— 发现测试 `:931` 明确断言该行为，降级为 P3 并要求先确认设计意图（3-10）。

---

## 7. 整改路线图（建议顺序）

**第 1 批（发布前，改动小、收益最大）**
1. P1-1：所有临时文件改 `create_new(true)` + 冲突重试（一条改动覆盖 `commit.rs` 与 `write.rs`）。
2. P1-2：修 `import_lint.py` 路径 + 加「规则扫描文件数非零」断言 + 补齐红线方向。
3. P1-3：`inspect_any`/`verify_any`/`smart_extract` 加显式 cfg；空 feature 组合返回显式错误。
4. P1-4：hint 从 `message` 中移除、`detail()` 内建转义、回显推迟到 AEAD 成功之后。

**第 2 批（统一错误契约，一次重构）**
5. 抽 `render_detail()` 统一 `Display` 与 `detail()`；`RestoreMismatch` 的 Display 补哈希；`TrellisInfeasible` 换 category；`From<serde_json::Error>` 分类；`ErrorDetail` 去掉 `skip_deserializing`。
6. CLI/pipeline 的 `General` 按语义改 `Io` / `InvalidArgument` / `ConfigError`；`rename_with_retry` 区分权限与占用；`smart_extract` 透传 `ErrorDetail`。

**第 3 批（门禁与文档可信度）**
7. 基线语料与 `baseline.json` 进版本库、CI 加 `--check`、`--write` 加 `--force` + diff；CI 补一次 debug profile 测试与 smoke stress example；补齐特性矩阵 5 个组合。
8. 批量同步文档版本 0.9.5、修正源码引用与失效链接、改写 `TESTING.md`/`ROADMAP.md` 基线章节；加 link-check。

**第 4 批（结构性重构，需单独排期）**
9. `core::crypto` 的 UBE 专有 KDF 下沉；`analysis` 改依赖 `structure-base` + 窄接口；全局 program/lang 收进 `CliRunCtx`。
10. 统一 `Zeroizing` 生命周期（口令、派生密钥、明文缓冲、PRNG state）；拆分 `facade.rs` 并独立 orchestration 层。
11. 容量口径打折、`GridRule` 算术、FLAC 置换断言、Windows 硬链接判定、ISO BMFF `size==0` 策略选择。

---

## 8. 待核实项（不作为缺陷，建议后续验证）

1. **字节基线是否已实际漂移**：`baseline.json` 记录的 commit 落后 HEAD 约 37 个提交，其中多个是解析/注入路径重构。受只读约束未运行 `baseline_hash.py --check`（会写 `temp/baseline/work`），需在完整语料环境下确认。
2. **HEVC CABAC 重编码的可解码性**：`hevc/slot.rs`、`superblock.rs` 未逐行核对；「bin 翻转后码流仍可解码」「缩略图转码往返无损」需动态验证。**`stego/heif/thumb_bridge.rs` 的 probe/embed 前置检查与偏移算术已在第 9 节完成静态核验并转为结论（P2/P3）**，但可解码性仍需动态验证。
3. **极小载体 / payload=0 的端到端实测**：1×1 图像、全零 DCT、纯静音/空 FLAC 的完整 embed→extract 往返未实测（静态推导有防护）。第 9 节补充了 `total_payload_bytes == 0` 的静态结论。
4. **`ErrorDetail` 反序列化后再调 `render()` 的链路**：`cli/` 与 `facade.rs` 内未找到，需查 `gui/src-tauri`。**第 9 节已按线索核验 Tauri 后端的缓存与输出路径，但未发现该 `render()` 链路，仍待核实。**
5. **`run_batch` 是否存在可达的 worker panic 路径**：`Mutex::unwrap` 本身不由载体触发，但 `panic=abort` 下会放大；需动态验证。
6. **`ChaCha12Stream` 的 `{:?}` 实际调用点**：当前 Grep 未命中，需检查 TRACE 日志与 GUI 日志面板。
7. **HEIF `item_hidden` 注入的 `iloc` 平移是否覆盖所有绝对偏移字段**（`sidx`/`saio`/`tfra`）：`verify_restored` 会兜底拒绝，故不产出损坏文件，但需确认分析结果的准确性。
8. **第三方依赖 CVE / `Cargo.lock` 审计**：`oxideav-h265`、`dct-io`、`jpeg-decoder`、`iced-x86` 未审计。
9. **`Freshness::Seeded` / L2 trellis seed 的跨格式行为**（3-9/3-10）：需产品侧确认是有意设计还是历史遗留，再决定是否 bump 线格式版本。

---

## 9. 与 `strhide_rust_code_review_report_gma_20261113.md` 的交叉核验与补充发现

本节为**后续补充**：用户提供了另一份 22 项、1259 行的审查报告，要求把「我方未发现的真实问题」合并进来。处理方式不是照单全收，而是**逐条回读当前源码核验后再合并**。

### 9.1 核验方法与总体可信度判断

- 方式：3 路并行事实核查（#04~#08 / #09~#13 / #14~#22），主审另亲自复核 #01、#02、#03、#17、#18 的代码与调用链。
- **核心结论：该报告混合了旧版本代码快照，不能整体采信。** 实证如下：

| 失真类型 | 具体证据 |
|---|---|
| 整项证伪 | **#01** 声称 7 个残留 `.rs`（`analysis.rs`、`isobmff.rs`、`pdf.rs`、`pe*.rs`）与同名目录并存触发 `rustc E0761`。实测 **7 个文件全部不存在**、`git status` 仅 2 份报告、`cargo clippy/doc/test` 全绿（1,072 用例通过）。 |
| 引用了不存在的符号 | `EnvelopeMetadata`、`from_json_bytes`、`BatchItemResult`、`outcome_mutex`、`abort_flag`、`PeHeaderInfo`、`payload_Compressed`、`HevcEngine::extract_mp4_file` 在当前源码中 Grep 均无命中（部分仅出现在该报告自身）。 |
| 代码形态不符 | **#03** 报告写 `u32::from_be_bytes` + `FINAL_CHUNK_FLAG` + `ctrl.check()?`；实际 `crypto.rs:598` 是 `u32::from_le_bytes`，无该 flag，`is_last` 由 `bytes_consumed >= total_payload_bytes` 决定。 |
| 行号错位 / 两函数对调 | `io.rs:584` 实为 `:230`；`read_carrier_for_embed` 实为 `:441`、`embed_carrier_file` 实为 `:36`（报告写反）；结构域 `reject_read_only_target` 实为 `write.rs:801`（报告写 `:124-137`）；`commit.rs::same_file` 实为 `81-116`（报告写 `141-156`）。 |
| 严重度系统性拔高 | 22 项几乎全标 P0/P1，实测**无一项达到 P1**：最高 P2（6 条），其余 P3 或不成立。 |

因此，本节只合并**经源码复核、且第 1~8 节未覆盖**的部分，并对每条保留纠偏说明；该报告的「修改方案」多数不能直接使用（见 9.4、9.5）。

### 9.2 新增的 P2 问题（6 条，均为我方未覆盖的真实缺陷）

**P2-A｜facade 吞没取消信号，结构域整条 API 链无 `Control`**（对应 #09）
`facade.rs:111-117` 的 `DualOptions` **确实有** `pub control: Control<'a>`，但 `:590` / `:721` 的结构域 `inspect_file(carrier, opts.password)` / `verify_file(carrier, opts.password)` 只传密码；进一步核对 `StructureFacade::inspect_file/verify_file`（`:1001-1007`、`:1019-1025`）、`inspect_carrier_with`（`structure/engine/inspect.rs:35-39`）、`verify_carrier_with`（`verify.rs:35-39`）、`inspect_core`（`:101-106`）、`verify_core`（`:202-207`）**全部没有 `Control` 参数**，是 API 层缺失而非漏传。内容域 `:613-619` / `:746-749` 把所有 `Err`（含 `StrHideError::Cancelled`）塞进 `content_error` 后正常返回 `Ok`；`ensure_domains_free_impl`（`:680-689`）完全不看 `content_error`，内容域检测失败时可能误放行覆盖写入。
**触发边界（已核实）**：CLI 两个调用点用 `Control::none()`（`cmd_stego.rs:314`、`cmd_structure.rs:133`），**只有 GUI 传真实 token**（`gui/.../diag.rs:52,189`、`stego.rs:387`）时可达；`ensure_domains_free` 误放行还需「内容域 inspect 失败 + 载体确有内容域载荷 + 未加 `--overwrite`」同时成立。
**整改**：`inspect_any`/`verify_any` 显式 `Err(Cancelled) => return Err(Cancelled)`；给结构域 inspect/verify 链补 `Control` 参数；`ensure_domains_free` 遇到 `content_error` 返回 `Rejection`。注意报告建议直接照搬的 `UnsupportedFormat` / `log::warn!` 分支在当前源码不存在。

**P2-B｜`read_one` 默认文件名落盘分支缺自覆盖保护**（对应 #19 子项 2）
`cli/cmd_structure.rs:433-458` 只有 `sanitize_filename` + 手写 `exists() && !overwrite` + `write_bytes_atomic`，**没有** `reject_carrier_output`；而 `:398`（batch.dir）与 `cmd_stego.rs:738` 都有。触发：载体在当前工作目录 + 显式 `--overwrite` + 包封内 `filename` 消毒后与载体同名 → `:450` 把载体自身覆盖为载荷内容。`sanitize_filename` 已挡路径遍历，但不能挡自覆盖。
**整改**：写盘前补 `reject_carrier_output(Path::new(&fn_to_use), &args.carrier)?`。

**P2-C｜HEIF 缩略图桥 probe 与 embed 前置检查不一致**（对应 #16，把我方第 8 节待核实 #2 转为结论）
`stego/heif/thumb_bridge.rs:187-215` 的 `probe_heif_bridge_capacity` 调 `find_bridge_target` 后直接 `probe_jpeg_capacity`，**不检查** `has_relocatable_track_tables`；后者唯一生产调用点在 `reconstruct_heif:435`，且仅在 `delta != 0` 时（`:363-367` 等长替换提前返回）。结果：含 `moov` 媒体轨道（如 Apple Live Photo 序列）的 HEIF，`capacity` 报告可用容量，`embed_heif_bridge`（`:99`）却在跑完完整 JPEG DCT 嵌入、代价计算与 STC 求解后才在拼装容器时 `Rejection`。
另两处已核实：`:341-353` 用 `moov.windows(4)` 无对齐裸匹配 FourCC，易把普通整数/字符串误判为 `stco`/`co64`/`saio`（后果是**误拒**而非误报）；`:498` 是 `item.base_offset + ext.offset` 裸加法，而 `:480` 的同类计算用了 `saturating_add`（需畸形 HEIF 构造，debug panic / release 静默回绕，与我方 2-14 的 `overflow-checks` 缺口叠加）。
**整改**：把轨道表检查移入 `find_bridge_target`（或拆读写两个版本）；`:498` 改 `saturating_add`。

**P2-D｜`has_ftyp` 硬要求使合法分片 MP4 的 `verify` L1 误判失败**（对应 #12 子项 1）
`structure/adapters/isobmff/mod.rs:356-358` 写死 `if !has_ftyp { return Ok((false, "... missing ftyp box")); }`，但同域 `mp4.rs:38-56` 的 `detect` 与 `formats/sniff.rs:52-63` 明确接受以 `styp`/`moof`/`sidx` 开头的无 `ftyp` 分片 MP4。同一载体「能写不能验」，属真实的功能不一致。
**整改**：放宽为 `has_ftyp || has_styp_or_moof`，并要求 `explicit_boxes > 0` 后才允许裸包封提前返回 `Ok(true)`（报告引用的 `let ok = explicit_boxes > 0 && has_ftyp && ...` 单行在当前源码不存在，但「裸包封 offset=0 时提前通过」的结论成立）。

**P2-E｜`inspect_core` 返回未消毒的包封文件名**（对应 #05）
`structure/engine/inspect.rs:186-188, 208-210` 把 `decode_metadata` 得到的 `CarrierMetadata` 原样放进 `MetadataInspection::Decrypted(meta_obj)`，未调用 `sanitize_filename`；而读取路径 `read.rs:276-280` 有消毒。暴露面已核实：`InspectResult`（`report.rs:305-340`）派生 `Serialize`，`cli/render.rs:54-55` 文本模式走 `serde_json::to_string` **无 `escape_control_chars`**（对比 `:45` 对 hint 有转义），`--json`（`cmd_diag.rs:108/147`）与 GUI（`gui/.../diag.rs:53-60`）都会拿到原始 `filename`。
**边界**：只读 inspect 路径，**无路径遍历写文件风险**（落盘路径 `read.rs:320-326` 二次消毒）；剩余风险是 CLI 终端控制序列 / 前端渲染注入。与我方 P1-4（hint 注入）同源但**数据不同**，需单独修。
**整改**：反序列化后立即消毒，或在 `MetadataInspection::Display` / JSON 渲染层统一转义。报告修改方案里的 `EnvelopeMetadata::from_json_bytes`、`meta_obj.is_file` 均不存在。

**P2-F｜GUI `extract_cache` 缓存键不含 `file_size` 且写入后未失效**（对应 #20，把我方第 8 节待核实 #4 部分转为结论）
`gui/src-tauri/src/state.rs:16-48` 的 `CachedExtract.matches` 只比较 `path/mtime/password/domain/prefer`；`commands/stego.rs:337, 395-402` 读写缓存；全 `gui/src-tauri/src` Grep `extract_cache` 仅 3 处，`write_structure_file_impl`、`restore_structure_file_impl`、`embed_stego_file_impl` **均无失效调用**，也不存在 `invalidate_extract_cache`。`preserve_time` 默认 `true`（库层 + 前端 `HideStructureView.tsx:85` 硬编码），原地写入会还原 mtime → 缓存键不变。此外缓存的 `payload.data` 无大小上限。
**重要纠偏**：「必然脏缓存命中」**不成立**——当前 GUI 两个写入视图都传 `output_path` 生成**新文件**（`xxx_hidden` / `xxx_stego`），不改原载体，缓存命中是正确行为；`restore` 在当前前端无入口；内容域 `StegoEmbedRequest` 没有 `preserve_time` 字段。脏缓存仅在**通过 IPC 直接以 `output_path=None` 原地写入/还原**时成立（Rust 实现支持）。按条件触发定 P2。
同项 P3：`extract_stego_file_cmd`（`stego.rs:234-290`）未用 `safe_output_filename`、未处理 `dest.is_dir()`（对比 `:413,431-432`）；后果有限（filename 只进 `ReadSummary` 展示，目录输出会返回 Io 错误）。
**整改**：缓存键加 `file_size`、限制只缓存 ≤16 MiB、提供 `invalidate_extract_cache()` 并在三个原地写入成功后调用。

### 9.3 新增的 P3 问题（表格，按主题分组）

| # | 位置（实际行号） | 问题与纠偏 |
|---|---|---|
| 3-14 | `core/commit.rs:447-463` | **macOS/BSD** 的 `process_is_alive` 用 `kill(pid as i32, 0)` 无 `i32::try_from` 边界：`u32::MAX → -1`，`kill(-1,0)` 恒成功 → 陈旧 `.lock` 无法回收。Linux 走 `/proc/{pid}`、Windows 走 `WaitForSingleObject`，**CI matrix 不覆盖该分支**；测试写入格式为 `format!("{}", u32::MAX)` 而非报告引用的 `pid={}`。改 `i32::try_from(pid)` 并拒绝 `<= 0`。 |
| 3-15 | `core/crypto.rs:590,648` + `structure/engine/read.rs:190-194,240-246,265` | `total_payload_bytes == 0` 时 `decrypt_stream_from_chunks` 循环不执行、`seen_final` 检查被 `&& total_payload_bytes > 0` 短路，**跳过 payload AEAD 认证直接 `Ok(0)`**。但 `read` 路径随后校验 `actual_sha256 != meta_obj.raw_sha256`、`verify_payload_stream:785` 校验 `total_bytes != expected_raw_size`，**非空载荷必被兜住**；仅「空载荷信封」可构造无认证尾块而通过，属完整性语义缺口。另 `chunk_len < AEAD_TAG_LEN` 无显式检查，但 AEAD 库会返回 `CorruptedData`，不构成绕过。建议入口要求 `total_payload_bytes >= 4 + AEAD_TAG_LEN` 并简化 `if !seen_final`。 |
| 3-16 | `structure/engine/inspect.rs:101-107,123,139,179,205`；`structure/envelope.rs:622-646` | `inspect_core` 缺 `password.filter(\|s\| !s.is_empty())`（write/read/remove/verify 都有）；仍用旧接口 `locate_envelope` + `unpack_with_profile` + `derive_keys`，单次多次派生 PBKDF2（read/verify 已改用 `UnpackSecrets::derive_attempts` 复用）；`unpack_with_secrets` Step 3 在检查明文魔数前无条件 `derive_header_mask`。影响是 CPU 开销与误导性 `DecryptFailed`，非安全突破。报告「30 万/40 万次」混淆了 100,000 与 200,000 两个常量。 |
| 3-17 | `structure/engine/verify.rs:370-393` | Level 2 失败时仍进入 `open_authenticated_at`，条件 `!is_encrypted \|\| password.is_some()` 无 `if !l2_ok` 短路。但 `secrets.as_ref()` 复用、**不重复 PBKDF2**，`VerifyResult.level2_envelope.ok` 仍单独上报；只是多余 I/O 与诊断噪音。报告引用的 `let mut is_encrypted = false;` 不存在（实际是元组解构）。 |
| 3-18 | `structure/rejection.rs:210-230, 330-350` | `check_pdf_signature` 用 64 KiB 分块 + `overlap = 1024`，要求 `/ByteRange` 与 `/Sig` 同窗口，跨块且相距 >1 KiB 的签名字典可能漏检；`check_jar_signature:343` 在 `:350` 的 `PK\x01\x02` 魔数校验前按 `cd_size` 分配 `vec!`。**纠偏**：实际约束是 `cd_offset.checked_add(cd_size) <= file_size`，报告「最多 16 MiB」上限不存在；已有 `checked_add`、`cd_size==0` 跳过、`starts_with` 防短 slice 等防护；PDF 漏检需精确跨块构造，属窄边界。 |
| 3-19 | `core/pipeline.rs:151-163` | `canonical_identity` 对 `Path::new("out.png").parent() == Some("")` 原样返回相对路径，而 `./out.png` 返回绝对路径；Windows 无大小写折叠 → `preflight_batch` 的 `seen_targets` 冲突检测不一致。**已实测** `parent()` 行为与报告一致，但 `commit.rs::same_file` **不调用**该函数（用自身 `canonicalize` + 大小写折叠），且 `preflight_batch:263` 有 `check_overwrite` 兜底，仅「批处理 + 全裸相对路径 + 显式 `--overwrite`」可触发。 |
| 3-20 | `core/batch.rs:258-267` | `Cancelled` 被 `map_err` 存入 `ItemOutcome.result`，末尾按 `is_ok()` 统一计入 `failed`。**但** `cancelled_flag`（:132,144,194,267）与 GUI 同 token 兜底确实存在，报告「未置位」不成立；串行/并行重复约 28 行（非 45 行）；`.lock().unwrap()` 已由我方 3-7 覆盖。属统计口径问题。 |
| 3-21 | `structure/adapters/isobmff/boxes.rs:86`、`iloc.rs:35` | `read_box_size` 与 `iloc` 子盒解析漏掉 `size < 8` 下界（对照 `read_stream_box_header:55-57` 已有 `if size < header_len`）；需恶意构造容器，循环有 `mpos+8<=m_end` 终止，不死循环。 |
| 3-22 | `structure/adapters/pe/mod.rs:123-125,559-573`；`png.rs:418-425` | PE 节表 `read_exact` 失败静默 `break` 仍返回成功；`verify_structure` 未校验 `host_size < pe_image_end`（但 `inject:411-416` **已有**该校验）；PNG `verify_structure` 未校验 `IEND` 长度必须为 0（与 `find_iend_offset:78` 不一致）。**报告「忽略 CheckSum/FORCE_INTEGRITY」不成立**——`rejection.rs:129-155` 已实现；`slack_ranges` 的 `rawptr==0` 也已被 `first_raw.filter(\|p\| *p > 0)` 间接覆盖。 |
| 3-23 | `stego/png/engine/extract.rs:113,118,134,269-321`、`layout.rs:351`；`embed.rs:141,276` | `open_png_header` 重复 3~4 次全图 `header_pool`/`header_layout`（含 `ext_len==0` 时仍重算），大图额外分配数百 MB `Vec<usize>`；`compute_cost` 早于 `check_pipeline_budget`。**「合法载体被误拒」不成立**：embed 与 extract 用完全相同的预算公式与参数，是刻意对齐的保守计费。纯性能问题。 |
| 3-24 | `stego/hevc/engine/inspect.rs:96-99`；`extract.rs:190-192,323-330`；`stego/jpeg/engine/extract.rs:131-135,196-202` | `hevc_header_info` 硬编码 `h=7`（默认 `DEFAULT_HEVC_FORMAT.stc_h` 恰为 7，仅自定义方言失真）、`envelope_len` 口径与 PNG/JPEG 不一致；HEVC/JPEG 把 critical TLV 拦截放在解密之后。**但** `header.rs:101-108` 的 `encode_extension_for_write` 明确拒绝任何 critical TLV，本版本写出的载体不可达该分支，属防御性冗余；AAD 已覆盖 extension。 |
| 3-25 | `analysis/mod.rs:221-236` + `structural.rs:289-290` | 窗口模式（>64 MiB）下 `trailing_entropy` 的 `Some(_)` 分支忽略 `offset`，直接取文件末尾 4096 字节算熵。**已核实 PNG 调用链真实可达**，但后果被夸大：熵只进 `Finding.detail` 文本，finding 是否产生由 `bytes_after()` 判定、severity 固定 `Likely`、PNG/JPEG 的 `track_trailing_entropy` 直接 `false`，**不产生误报 finding**，仅 detail 数值失真。JPEG 路径传的是 `tail_offset` 而非 EOI end，报告调用点描述有误。 |
| 3-26 | `cli/cmd_diag.rs:235-242, 274-288, 863-867` | `dual_verify_failed(struct_ok=false, content_ok=true, content_present=true, content_errored=false)` 返回 `false`（验证通过），组合**真实可达**（默认构建下 PNG/JPEG 会真正跑结构域 verify）。**但这是有意设计**：单测 `:863-867` 明确断言并注释「任一域通过即通过」。报告建议的 `struct_ran && !struct_ok` 会误伤干净 PNG/JPEG（其 `level2_envelope` 是 `fail("No envelope found")` 而非 skipped）。建议文档明示该语义或提供 `--strict` 模式，**不要改布尔式**。 |
| 3-27 | `facade.rs:1162,1181-1182`；`stego/io.rs:441-458`；`core/commit.rs:510` | `StegoFacade::extract_file` 全量解码后才做 `reject_carrier_output`/`check_overwrite`；`read_carrier_for_embed` 先 `std::fs::read` 再由调用方报 `UnsupportedFormat`（**但 `:447-455` 已有两道前置 budget 门禁**，上限是可用内存 60%/兜底 4 GiB，非报告说的 1 GiB）；`embed_carrier_file` 入口无 `reject_read_only_target`（`commit_carrier_bytes:510` 有，只是时机晚）。均为「昂贵工作后才报错」的时机问题，最终检查都生效。 |
| 3-28 | 多处 | **代码整洁（6 子点中 5 项成立）**：① `core/crypto.rs:658-662` 与 `compress.rs:7-9` 的文档注释被从 `mutually / readable.` 中间劈开；② `structure/engine/write.rs:78-107` 的补充参数说明与 `no_run` doctest 误挂私有 `WriteCoreResult`，公开的 `write_carrier_with`（`:780`）无该示例（`cargo test --doc` 不会检查）；③ `stego/hevc/engine/extract.rs:3` 注释含字节 `0x0B`（`\verify` 转义污染），已用 Python 字节级验证；④ `stego/options.rs:1368-1369` 重复 `#[cfg(test)]`；⑤ `core/payload.rs:205-209` 的 `From<&Payload>` 用 `p.clone()`，对 `Cow::Owned` 深拷贝整个载荷；⑥ `stego/coding/stc.rs:612,684-710,785` 在 `u==1` 提前返回后遗留恒真 `store_extra` 与不可达 `else` 分支。与我方 P3 表格 3-2/3-4 同类但具体条目不同。 |

### 9.4 对该报告三处 P0 定性的纠正

| 编号 | 报告定性 | 核实结论 |
|---|---|---|
| **#01** | P0 编译阻断 | **完全证伪**。7 个文件全部不存在，`git status` 干净，`cargo clippy --all-targets --all-features -- -D warnings`、`cargo doc --all-features --no-deps`、`cargo test --all-features --all-targets`（1,072 通过）全绿。**不合并为问题**；仅采纳其「`import_lint.py` 增加 `foo.rs` / `foo/mod.rs` 唯一性检查」作为 P1-2 的加固建议。 |
| **#02** | P0 高危 / 单测必败 | **代码缺陷真实但定级过高 → P3**（3-14）。`kill(pid as i32, 0)` 无边界检查属实，`u32::MAX → -1` 的 POSIX 分析正确；但仅影响 macOS/BSD 分支，Linux/Windows 与 CI matrix 不受影响，不存在「单测必败」。报告引用的 `if pid == 0 { return false; }`、`pid={}` 锁格式与当前代码不符。 |
| **#03** | P0 认证绕过 | **部分成立但被下游兜住 → P3**（3-15）。`total_payload_bytes==0` 跳过 payload AEAD 属实，但 `read` 的 SHA-256 比对与 `verify` 的 `expected_raw_size` 比对使非空载荷必然失败；`chunk_len < AEAD_TAG_LEN` 由 AEAD 库拒绝。且 AAD 不含 `ube_total_size` 这一点已由我方 2-11 / 2-39 覆盖。报告引用的 `from_be_bytes` + `FINAL_CHUNK_FLAG` 代码形态与当前源码不符。 |

### 9.5 明确不合并的项

- **已证伪**：#01（残留文件）；#19 子项 1（声称存在 `extract_carrier_file_payload` 的 MP4 流式提取通道——实际该函数 `io.rs:230-237` 自身就是 `read_carrier_file` + `extract_carrier_payload`，与 CLI 做法等价，全库无 `extract_mp4_file`，改调零收益）；#13 的 `CheckSum`/`FORCE_INTEGRITY` 断言；#14 的「合法载体被误拒」；#15 的 critical TLV 触发前提；#20 的「必然脏缓存命中」；#21 的「最高 1 GiB」数字。
- **已被第 1~8 节覆盖**：#04（密钥未 `Zeroizing` → 2-10，可补具体持有结构体 `PngKeys`/`PreparedCarrier`/`JpegInspection`/`EmbedContext`）；#12 的 HEIF 1 GiB 缓冲与 MKV 每轮读尾部（→ 2-13）；#11 的 `Mutex::unwrap`（→ 3-7）；#12 的 ISO BMFF `size==0`（→ 2-32）。
- **有既有防护、结论不成立**：#12 的「heif 全量缓冲导致 OOM」（`:51`/`:419` 就是 1 GiB 上限检查，分配在 `:57`/`:425`）；#11 的「未置 cancelled_flag」（token 兜底存在）；#18 的修复方案（会误伤正常载体）。

### 9.6 对整改路线图的影响

1. **第 1 批（发布前）不变**，仍是 4 个 P1；仅 P1-2 的整改追加「模块文件唯一性检查」。
2. **第 2 批新增**：P2-A（facade 取消语义 + 结构域 `Control` 接入）、P2-B（`read_one` 自覆盖）、P2-D（分片 MP4 verify）、P2-E（inspect filename 消毒）——都是改动小、影响用户可见行为的修复。
3. **新增 GUI 后端批次**：P2-F（缓存失效 + `file_size` 键 + 大小上限）需与 `gui/` 的改动协同；P2-C（HEIF 桥前置检查）与内容域容量探测调整同批。
4. 3-14（macOS/BSD 锁）与 3-15（`total_payload_bytes==0`）建议并入「错误处理/纵深防御」批次，不必单独排期。

---

## 附：本次评审产物

- 报告：`docs/RUST_CODE_REVIEW_20261113.md`（本文件，新建，未覆盖任何已有文件；第 9 节为交叉核验后的补充，编辑前已备份至 `temp/backups/RUST_CODE_REVIEW_20261113_*.md`）。
- 参照报告：`docs/strhide_rust_code_review_report_gma_20261113.md`（用户提供的另一份审查，22 项；第 9 节为其核验记录）。
- 自动化检查日志：`temp/review_checks_20261113.log`（临时产物）。
- **未改动任何源码**；按项目规则，本次不产生 `docs/CHANGES-YYYYMMDD.md` 条目（该规则针对代码变动）。
- 全程未执行 `git commit` / `push`。
