# strhide 0.9.3 发布前 Rust 代码全面审查报告

> 审查时间：2026-11-07 17:01 – 17:54（GMT+8）
> 审查基准：会话开始 `227123f`；审查期间 17:50 出现并行提交 `bb21117`，**最终基准为 `bb21117`**。
> 版本：`rust/Cargo.toml` 0.9.3。范围：`rust/src`（123 个 `.rs`、78 459 行）、`rust/tests`、`rust/examples`、`.github/workflows/`、`rust/build.rs`、`Cargo.toml`。
> 性质：**只读审查，未修改任何源码**；所有结论附实证命令或 `文件:行号`。
> 相关文档：`docs/RELEASE_READINESS_20261106.md`（11-06 就绪评估，本报告对其做增量与复核）。

---

## 0. 结论摘要

**仍然不建议直接打 tag 发布。** 常规质量门禁（fmt / clippy / 全量测试 / release 构建 / 架构边界 / 文档 / 打包 / 基线）基本全绿，且 11-06 评估中"未验证"的 19 个 `local_` 与 5 个 `heavy_` 测试本次已跑通；但仍有 **1 个未修复的发布流水线硬阻断**、**6 个 P1 正确性/安全问题**和一批 P2 健壮性问题。

| 级别 | 数量 | 状态 |
|---|---|---|
| P0 发布阻断 | 2 | 1 个已在 `bb21117` 修复，**1 个仍未修复**（release.yml 缺 `cli` feature） |
| P1 正确性/安全 | 6 | 全部未修复 |
| P2 健壮性/工程 | 18 | 多数未修复，部分在 11-06 已记录但仍未闭环 |
| P3 文档/维护性 | 10 | 多数未修复；11-06 记录的 9 个 rustdoc warning 已修 |

**审查期间的重要变化**：`bb21117 fix(ci): gate ExtractOutcome impl and add feature-matrix check` 于 17:50 落地，给 `facade.rs` 的 `impl ExtractOutcome` 补齐了 `#[cfg]`，并把 CI 的 "Minimal feature builds" 换成 `scripts/check_feature_matrix.py`。本报告中该条按「曾实证失败 → 已修复 → 仍有残留」记录，避免把已修项误报为待办。

---

## 1. 门禁实测结果

| 门禁 | 命令 | 结果 |
|---|---|---|
| 格式 | `cargo fmt --all -- --check` | 通过 |
| Clippy（全特性） | `cargo clippy --all-targets --all-features -- -D warnings` | 通过，0 warning（修复前后均通过） |
| 全量测试 | `cargo test --all-features --all-targets` | **1064 passed / 0 failed / 27 ignored** |
| Release 构建 | `cargo build --release --all-features` | 通过 |
| 架构边界 | `python scripts/import_lint.py` | 通过 |
| 字节级基线 | `python scripts/baseline_hash.py --check` | 第 1 次 **20 处 DIFF**；第 2、3 次 **28/28 identical** |
| Rustdoc | `cargo doc --all-features --no-deps` | 通过，**0 warning**（11-06 的 9 个破损链接已修） |
| crates.io 打包 | `cargo package --no-verify --allow-dirty --all-features` | 通过（150 文件 / 3.1 MiB），8 条 `ignoring test ...` warning |
| `local_` 忽略测试 | `cargo test local_ --all-features -- --ignored` | **19 passed / 0 failed**，15.60 s |
| `heavy_` 忽略测试 | `cargo test heavy_ --all-features -- --ignored` | **5 passed / 0 failed**，70.53 s |
| feature 矩阵（修复前） | 9 组 `cargo check --no-default-features ...` | **8/9 失败：E0425**（`facade.rs:246`） |
| feature 矩阵（修复后） | `python scripts/check_feature_matrix.py` | **8/8 通过** |
| 子集代码卫生 | `cargo check --no-default-features --features content-base` | 通过但 **50 条 warning**；`clippy -D warnings` **51 errors** |

> 日志留存：`temp/review_verify.log`、`temp/review_features.log`、`temp/review_extra.log`、`temp/review_ignored_full.log`、`temp/review_postfix.log`、`temp/review_postfix_gates.log`。

---

## 2. P0 发布阻断项

### P0-1 `facade.rs:246` 缺 `#[cfg]` —— **已由 `bb21117` 修复，但有残留**

**实证（修复前，HEAD `227123f`）**：`cargo check --no-default-features --lib` 等 8 个组合全部
```
error[E0425]: cannot find type `ExtractOutcome` in this scope
   --> src\facade.rs:246:6
```
原因：`ExtractOutcome` 结构体（`facade.rs:235`）与 `smart_extract`（`:626`）都有
`#[cfg(all(feature = "structure-base", feature = "content-base"))]`，唯独 `impl ExtractOutcome`（`:246`）没有。
影响链：`ci.yml` 的 "Minimal feature builds" 必红 → `quality` job 失败 → `release.yml` / `crates.yml` / `gui-release.yml` 全部因 `needs: quality` 被阻断。

**修复后复验**：`python scripts/check_feature_matrix.py` 输出 `OK: 8 feature build(s) succeeded`；全量 clippy / 测试仍绿。

**残留**：
- 新脚本 `MATRIX` 只有 8 行，未覆盖 `content-base` / `core-io` / `config` 单独组合；本次额外实测这 3 组 `cargo check` 能编译，但分别产生 **50 / 4 / 4 条 dead_code warning**，且 `cargo clippy --no-default-features --features content-base -- -D warnings` 报 **51 errors**（如 `stego/options.rs:399` 的 `derivable_impls`）。CI 只对 `--all-features` 跑 clippy，子集质量无门禁。
- 建议：把矩阵补齐到全部单行 feature，并对至少一组子集跑 `cargo clippy -- -D warnings`；或对子集下的 dead_code 加 `#[cfg]` / `#[allow(dead_code)]`。

### P0-2 `release.yml` 构建未启用 `cli` feature —— **仍未修复，最高优先级**

`.github/workflows/release.yml:54`、`:111`、`:148-149` 均为：
```yaml
run: cargo build --release --locked --target ${{ matrix.target }}
```
而 `Cargo.toml:67-95` 的 **5 个 bin 全部 `required-features = ["cli"]`**，默认 feature 集是
`["structure", "content", "analysis"]`（不含 `cli`）；`.cargo/config.toml` 只设 `jobs`/线程数，未设默认 features。

**实证 1**：`cargo build --release --bin strhide` → `error: target 'strhide' ... requires the features: 'cli'`（退出 101）。
**实证 2**：`cargo build --release --locked --message-format=json` 的 `compiler-artifact` 列表里**只有 `('strhide', 'lib')`，没有任何 bin**。

后果：三平台 `Stage artifact` 去复制 `rust/target/<triple>/release/strhide.exe`（或 `strhide`）时文件不存在；`upload-artifact` 还带 `if-no-files-found: error`，发布必然失败。若 runner 缓存里恰好残留旧 exe，更危险——**会把旧二进制当新版本发出去**（`AGENTS.md` 已明确提醒过这个坑）。

**修复**：所有 release 构建命令加 `--features cli`（或 `--all-features`）；同时在 workflow 里加一步断言产物存在且 `--version` 的 commit 与当前 tag 一致。

**配套问题（独立于 feature）**：`rust/README.md:402` 称 "compiles **four** targeted CLI binaries"（实际 5 个），且 `:415-441` 所有示例用 `sth`；而 release.yml 三平台只 stage `strhide`，`sth/sthc/sths/sthv` 从不发布。用户下载 Release 后照 README 敲 `sth` 会找不到命令。需统一文档命令名或发布全部 bin。

---

## 3. P1 正确性 / 安全问题（全部未修复）

### P1-1 JPEG 生产路径是概率性失败（作者注释自承约 1/20）

`rust/src/stego/jpeg/engine.rs:556-562`：
```rust
/// Six rather than three: ... Six turns a per-attempt
/// failure rate of roughly a third into a per-run one of about one in
/// twenty.
const EMBED_ATTEMPTS: usize = 6;
```
链路：`embed_once` 的 `missing_symbol_stats`（`:1044-1054`）返回 `retryable: true` → `:773-807` 用新 salt 重试 6 次 → 全失败才报错。`envelope.rs:242-246` 的 `Freshness::Random`（`#[default]`，生产路径）每次调 `rand::rng()` 取新 salt，salt 决定 slot 集合与 trellis；三种 cost 算法共用该重试框架，故都会偶发。

影响：**合法载体 + 合法参数 → 不可复现的功能失败**；调用方拿到 `embed_failed` 无法区分"载体真的不行"与"这次手气不好"，库内部已耗尽 6 次重试，外部无法再重试。发布说明应披露，或改为事前确定性判定（`:428-430` / `:593-596` 注释自承 cross-zero chain 无法用 slot 级检查预测）。

**必须澄清的一点（避免误判）**：`scripts/baseline_hash.py` 传固定 `--seed`，CLI `helpers.rs:434-435` 把它映射为 `Freshness::Seeded`，`envelope.rs:245/253` 用 `HKDF(seed, label||attempt||binding)` 确定性派生 salt/nonce。因此**基线脚本的偶发 DIFF 不是这个概率机制造成的**。本次受控复现：20 次带 `--seed` 全部成功且产物 SHA-256 唯一；40 次不带 `--seed` 全部成功、40 个不同哈希。详见 §7。

**P2 附带缺陷**：`envelope.rs:236-246` 的文档承诺 "Folding the attempt index into the derivation keeps the whole retry sequence reproducible"，但 `Random` 分支完全忽略 `attempt` 与 `binding`，重试序列不可复现、失败无法重放。建议改为"一次取根随机 → 按 attempt 用 HKDF 派生"。

### P1-2 符号链接 / 硬链接载体在写前完全未检测

`structure/rejection.rs:448-455` 用 `std::fs::metadata`（跟随符号链接），全 `structure/` + `core/` 无 `symlink_metadata` / `is_symlink` / `nlink` 检查（`rg` 仅命中 `commit.rs` 里 "unlink race" 注释）。in-place 写入走 `engine.rs:1601` 的 `rename_with_retry(tmp, target)`。

后果：载体是符号链接时被替换成普通文件、链接永久丢失，实际目标文件未改；载体有硬链接时 rename 只替换一个目录项，其余名字仍指向旧 inode，出现同一文件多名字内容不一致。`remove_carrier`（`engine.rs:2444`）同样用 rename，恢复路径同受影响。

修复：拒绝检查改用 `symlink_metadata`，符号链接直接拒绝；Unix 用 `MetadataExt::nlink() > 1`、Windows 用 `GetFileInformationByHandle` 拒绝 in-place 硬链接，或改为对已打开的 `&File` 直接写。

### P1-3 PE 改写后不重算 `CheckSum`，且不检查 `FORCE_INTEGRITY`

`structure/adapters/pe.rs:724-737` 的 `inject_codebits` 改 `.text`、写入节 slack 后直接 `copy_with_patches` 落盘；全 `structure/` 中 `checksum|CheckSum|FORCE_INTEGRITY|DllCharacteristics` 只命中 `registry.rs:23` 的注释。`rejection.rs` 的签名判定只看证书表（`virt_addr != 0 && size != 0`）。`pe_layout.rs:161-199` 的 `slack_ranges` 的 `used` 集合只按节 `min(vsize,rawsize)` 排除，未排除 Data Directory 覆盖区。

后果：对设置 `FORCE_INTEGRITY` 的 DLL/驱动或加载器校验 CheckSum 的 PE 使用 `pe_codebits`/`pe_slack` → 校验和失准、加载失败；若某 Data Directory 落在节尾 padding，会覆盖重定位/调试/导入数据被目录引用的字节。

修复：注入后按 PE 规范重算 CheckSum 写回 `OptionalHeader+64`；或在解析阶段读 `DllCharacteristics & 0x0080` 与 `CheckSum != 0` 并拒绝/回退 `eof`；`slack_ranges` 把有效 Data Directory 的 `[PointerToRawData, +Size)` 并入 `used`。

### P1-4 非 UTF-8 载荷绕过终端转义，原样写 stdout

`cli/render.rs:120-131`：
```rust
match std::str::from_utf8(data) {
    Ok(text) if escape => out.write_all(escape_terminal_text(text).as_bytes())?,
    _ => out.write_all(data)?,          // 非 UTF-8 完全不转义
}
```
同函数注释（`:110-118`）明确写了 "printing them verbatim lets a crafted file drive the terminal (`CSI` cursor games, `OSC 52` clipboard writes)"，但 `escape_terminal_text` 只接受 `&str`（`core/fs.rs:175`），二进制分支直接落回 verbatim。

触发：二进制载荷经 `--stdin` 写入（`structure/engine.rs:418-421` 的 `is_file=false`），随后 `read <carrier>` 不带 `-o/--stdout` 且 stdout 是终端；或 `extract --stdout` 直接在终端输出。构造载体者可注入终端控制序列。

修复：非 UTF-8 数据不走终端输出（改写文件，与 `cmd_stego.rs:757-772` 一致），或以十六进制/`\u{..}` 安全形式呈现。

### P1-5 批量 `inspect` 部分/全部失败仍返回退出码 0

`cli/cmd_diag.rs:124-158` 逐个 `Err(e) => { failures += 1; if !quiet { eprintln!(...) } }`，函数末尾仍 `Ok(())`；`cli/mod.rs:306-311` 的 `Commands::Inspect` 是 `Ok(_) => 0`。`verify`（`cmd_diag.rs:433`）与 `scan`（`:549`）都有非零退出，`inspect` 是唯一恒 0 的诊断命令。

触发：`inspect --json a.png missing.png`，或目录含不可读文件；`failures` 只影响摘要文本。CI/脚本会误判为全部成功。

修复：失败时返回非零，并在 JSON 中保留失败项。

### P1-6 `verify` 不校验 envelope 记录的宿主哈希，却被当作门禁

`structure/engine.rs:3130-3169` 的 L3 只做 `verify_authenticated_payload`（校验 **payload** SHA-256）；`orig_host_sha256` / `orig_host_size` 全文件只在 `:2310`（`remove` 的 `verify_restored`）和 `:2743`（inspect 输出）出现。`verify_passed()` 的文档（`:3171-3176`）明确说它 "makes `verify` usable as a gate"。

后果：载体写入后宿主部分被外部工具改动（信封与 payload 完好）→ `verify` 三层全绿、`verify_passed() == true`，随后 `restore` 因 SHA 不匹配返回 `RestoreMismatch`，用户误判为"可无损恢复"。

修复：L2 增加按 header 坐标虚拟还原宿主并比 SHA-256 + 尺寸，或在 `VerifyResult` 显式标注"宿主可还原性未验证"。

---

## 4. P2 健壮性 / 工程问题

| # | 位置 | 问题与影响 | 建议 |
|---|---|---|---|
| 1 | `core/commit.rs:465,530,623` + `facade.rs:1057` | `commit_carrier_bytes` / `commit_carrier_patches` / `write_bytes_atomic` 三个 pub 写函数内部都不取 `TargetLock`；`rg` 显示 `acquire` 仅 `structure/engine.rs:1521,2399` 与 `stego/io.rs:55` 三处。`facade::StegoFacade::extract_file` 直接调 `write_bytes_atomic`，绕过锁。`commit.rs:247-253` 的文档恰好描述了"两个 writer 各自 rename 成功、后写者静默覆盖先写者"的故障模式 | 把 `TargetLock::acquire` 下沉到 `write_bytes_atomic` 内部，覆盖从建 tmp 到 rename 全过程 |
| 2 | `core/commit.rs:631` | `write_bytes_atomic` 用 `File::create`（跟随已存在的 symlink / 截断预置文件），且全程无 `set_permissions`；明文 payload 权限仅由 umask 决定（常见 0644）。同文件 `copy_file_to_new:182` 却用 `create_new(true)` | 改 `create_new(true)` + 冲突换名；payload 输出显式 `0o600` / `mode(0o600)` |
| 3 | `core/commit.rs:490,496,594,600` | 时间戳/权限恢复失败只 `eprintln!` 一行 warning 后仍返回 `Ok(...)`，库调用者无法程序化感知；库层直写 stdout/stderr（11-06 已列为搁置项 A2，**仍未解决**） | 作为 `StrHideError` 或 `Warning` 字段返回；core 层统一 `log::warn!` |
| 4 | `structure/rejection.rs:75,88-106` | `size_of_opt_header` 读出后未用于校验 Security Directory 偏移，不检查 `NumberOfRvaAndSizes`；任一 `seek`/`read_exact` 失败都 `return Ok(None)`（视为未签名），fail-open。`pe.rs:89-101` 第二道检查同样 fail-open | 按 `NumberOfRvaAndSizes` 计算真实偏移并校验落在文件内；读失败保守拒绝 |
| 5 | `structure/rejection.rs:458` vs `engine.rs:1524,1538` | 签名/权限检查按路径打开一次，写入时按同一路径重新打开，两个独立 fd；`TargetLock` 只锁 target 不锁 carrier，存在 TOCTOU 窗口 | 把已打开的 `&File`/handle 从检查一路传到 `write_core` |
| 6 | `core/crypto.rs:416-418` + `core/errors.rs:24-35` | metadata AEAD tag 失败统一返回 `CorruptedData("Metadata authentication failed")`；最常见原因其实是口令错误。`CorruptedData` 与 `Password` 两个变体的文档都声称覆盖 "wrong-password metadata decryption"，自相矛盾，且消息里没有"密码"字样 | 错误口令返回 `Password`；至少改消息为 "wrong password or corrupted data"，并统一文档 |
| 7 | `core/crypto.rs:210-273,451,491,590,607`；`cli/helpers.rs:47-108` | 无 `zeroize` 依赖；`PasswordSecrets` 还 `derive(Clone, Copy)`，派生 IKM、HKDF 子密钥、header mask、解密明文 `Vec`、CLI 密码 `String` 均不清零。帮助文案已警告 `-p` 在进程列表可见 | 引入 `zeroize`，敏感结构 `Zeroize + Drop` / `Zeroizing`，缩小密码作用域 |
| 8 | `cli/cmd_stego.rs:269-273` | `--stdin` 载荷 `stdin().read_to_end(&mut buf)` 无 `take` / 上限；对比密码文件有 4096 上限（`helpers.rs:67`）、`analysis.rs:313` 有 64 MiB `take` | 加 `--max-payload` 并在读取前 `take(limit)`，超出即报错而非 OOM |
| 9 | `cli/cmd_diag.rs:124-158,329-413,451-465` | 批量 `inspect/verify/scan --json` 静默丢弃失败文件（`reports` 只含成功项）；`scan` 注释 `:527-530` 却声称失败会进 JSON；quiet 模式连 stderr 警告也吞 | 失败项作为带 `path` / `error` 的对象推入数组 |
| 10 | `cli/cmd_stego.rs:103-111,203-215` | `capacity --json` 对每个 carrier 打印一个顶层对象、无 banner，与其它命令统一走 `render.rs:84-105` 的 `print_json`（单文档 + banner）不一致；失败时已输出的半截 JSON 与 stderr 混杂 | 收集为数组统一 `print_json`，失败项带 `error` |
| 11 | `.github/workflows/crates.yml:35` | `jq -e --arg v "$VERSION" '.versions[]?.num == $v'` 对数组每项产生一个布尔输出，`jq -e` 退出码只由**最后一个**输出决定；只要最后一项不等于 `$v`，即便列表中存在匹配也会判 `exists=false` → 重复 `cargo publish` 409。本机无 jq，为静态判断 | 改 `any(.versions[]?; .num == $v)`，并显式处理 `curl` 失败 |
| 12 | `.github/workflows/crates.yml:4-7,29-45` | 任何 `v*` tag 都触发发布，发布内容却是 `Cargo.toml` 里的 `0.9.3`，无 tag ↔ 版本一致性校验（11-06 P2-3 已记录，**仍未解决**） | 加 `[[ "v$VERSION" == "$GITHUB_REF_NAME" ]] || exit 1` |
| 13 | `rust/build.rs:35-48,72-92` | 无 `.git` 时 `find_git_dir()` 返回 `None`，但 `get_git_hash()` 仍执行 `git rev-parse`：在 CI 的 `target/package/...`（位于 checkout 内）会取到外层仓库 HEAD，普通用户环境返回 `unknown`；`get_build_time()` 默认 `SystemTime::now()`，而 release/crates workflow 都未设 `SOURCE_DATE_EPOCH` / `STRHIDE_BUILD_TIME`，`--version` 的 `built:` 每次不同，破坏可复现构建 | 无 `.git` 直接返回 `unknown`；workflow 注入 `STRHIDE_GIT_HASH` 与 `SOURCE_DATE_EPOCH` |
| 14 | `core/sysmem.rs:68-73` + `stego/io.rs:304-309` | 非 windows/linux（含 release.yml 发布的 **macOS universal2**）`available()` 返回 `None` → 固定 4 GiB 预算；Win/Linux 用 60% 物理内存。大 WAV/FLAC 嵌入在 Mac 上会被硬上限拒绝且无日志 | 补 macOS `sysctl`/`host_statistics` 实现，或至少在 `-v` 中报告降级 |
| 15 | `cli_i18n.rs:126` + `core/i18n/messages.rs:439-440,543-545` + `cli/helpers.rs:94-107` | `HelpWriteEncrypt` 写 "Require password (fails immediately if password is not supplied, skips prompt)"，实现是"有 TTY 则交互提示、无 TTY 才失败"；同一 `--encrypt` 在 `embed` 下文案正确。`cli_i18n::walk` 会用 `mut_arg().help(t)` 覆盖 doc help，`write --help` 给出错误安全指引 | 两条文案统一，并明确"非交互终端直接失败" |
| 16 | `scripts/check_feature_matrix.py` + 子集编译 | 8 行矩阵未含 `content-base` / `core-io` / `config` 单独组合；这些组合 `cargo check` 产生 50 / 4 / 4 条 dead_code warning，`clippy -D warnings` 在 `content-base` 下 51 errors | 补矩阵行，并对子集加 clippy 门禁或清理 dead_code |
| 17 | `docs/RELEASE_READINESS_20261106.md:285-299` | 11-06 的 P3 搁置项（A3 全局 `AtomicU8` 语言 + 全局 rayon 池、XH-04/05/09/20 内存准入无 `try_reserve`、R1/R2/R3 ACL 归类与 Unix 目录 fsync 吞错）**仍未闭环**；`:345` 的 4 项"未复现观察项"（ISO-BMFF `item_hidden` 对称性、PDF 多 `%%EOF` 锚定、PE 跳转表误判、CLI `--auto` 批量上下文）仍无运行时夹具 | 至少写入 README "Known limitations"；观察项建夹具 |
| 18 | `core/crypto.rs` / `structure/params.rs` | 无口令时使用源码中的 `BUILTIN_DEFAULT_KEY`（公开常量）做 AES-GCM，只提供"hex dump 看不到明文"的**格式混淆，不提供机密性**；`lib.rs:27-29` 用 "built-in public key" 表述容易让用户误以为有加密保护 | README/CLI 明确标注"无口令不等于保密"，避免安全误解 |

---

## 5. P3 文档 / 维护性

| 位置 | 问题 |
|---|---|
| `rust/README.md:402,415-441` | "four targeted CLI binaries" 实为 5；示例全用 `sth`，Release 只 stage `strhide` |
| `rust/README.md:418` | 示例仍用 `-p "P@ss123"` 明文密码，与 `HelpSharedPassword` 及 README 自身安全说明矛盾 |
| `Cargo.toml:15` + `examples/in_memory.rs:34-35`、`private_format.rs:58-59`、`private_profile.rs:34-35` | `exclude = ["tests/"]` 排除了 `tests/assets/*`，但这 3 个示例运行时要读它；crates.io 用户跑示例必失败（`cargo publish` verify 不编 examples，故不会暴露） |
| `cargo package` 输出 | 8 条 `warning: ignoring test ... as tests\xxx.rs is not included in the published package`（`exclude` 与自动 `[[test]]` 发现冲突） |
| `cli_i18n.rs:127,129-130` | 死映射 `write/no-encrypt`、`write/preserve-time`（args.rs 无此参数）；`HelpWritePreserveTime` 从未引用；`--auto`（`args.rs:374-378,565-569`）无本地化条目，`--lang zh` 下帮助仍英文 |
| `cli/mod.rs:240-242` + `cli/render.rs:84-105` | `-q` 未静音 `cfg.warnings`；`--json` 注入的 `BANNER` 固定为 `sth`，域入口 `sthv/sthc/sths` 的 JSON banner 名不符 |
| `cli/args.rs:263-264` | `--password` 明文 argv（帮助已警告），README 应给出 `--password-file` / 交互提示的安全示例 |
| `release.yml:33-37,81-85` | `-C target-cpu=x86-64-v3` 让 `is_x86_feature_detected!("avx2")` 在该产物中恒真，且产物命名 `...-avx2.exe` 低估 CPU 要求（v3 还需 BMI2/FMA/LZCNT/MOVBE）；macOS 未用 v3，三平台优化级别不一致 |
| `release.yml:9-10` + `gui-release.yml:66` | 顶层 `permissions: contents: write` 作用于全部 job；`tagName: ${{ github.ref_name }}` 在 `workflow_dispatch` 下取分支名，tauri-action 会创建同名 release |
| `core/commit.rs:5-6`、`core/mod.rs:19-24`、`lib.rs:135-136`、`core/control.rs:21` | 文档说 `commit` "lives here ungated"、crypto/errors/params/commit 是 "crate-root residents that a later batch moves under core"，与已完成的移动及 `#[cfg(any(...))]` 门控不符；`control.rs` 的 `[`crate::commit`]` 链接在 `--no-default-features` 下是 broken intra-doc link |

---

## 6. 已核实无问题 / 排除项

- **全量质量门禁**：fmt、clippy（全特性）、1064 单测/集成测试、release 构建、`import_lint.py`、`cargo doc`、`cargo package` 全部通过；`local_` 19 个与 `heavy_` 5 个忽略测试本次补齐并全绿。
- **格式解析器畸形输入防护**：ISO BMFF（largesize `usize::try_from`、`size==0` 特判、box 数上限）、PDF（1 MiB 尾窗 + `endstream` 27 字节窗）、ZIP（EOCD 窗 + 反诱饵）、PE 头/节表、JPEG（marker 扫描上限、`seg_len<2`）、PNG（`checked_add(length+12)`）、RIFF、FLAC frame、WAV/HEIF/MKV box 均有边界校验与严格递增的游标，**未发现可证实的越界切片、整数截断、死循环或「小文件触发超大分配」**。
- **unsafe / SIMD**：`stc.rs:874-943` 的 `accumulate_xor_avx2`、`juniward.rs:394-424` 的 `dot_avx2`，`get_unchecked` 与 `loadu/storeu` 的前置条件与 `is_x86_feature_detected!("avx2","fma")` 检测配套，非 x86_64 有标量兜底；SAFETY 注释与边界一致。
- **密码学基础**：AEAD tag 校验统一经 `aes-gcm`/`chacha20poly1305` 的 `decrypt`，错误统一抹平；payload 与 metadata 用不同 HKDF 子密钥，`make_chunk_nonce` 对 `index < 2^32` 唯一；`Credential` 不实现 `Debug`，facade 的 `Debug` 把 password/key 显示为 `<redacted>`；解压有 `take(orig_len+1)` 防 zip bomb，verify 有 1 GiB 上限。
- **无损恢复**：`orig_host_sha256/size` 在 `get_aad()` 内受 AEAD 认证；`remove` 路径在 rename 之前用 `verify_restored` 比对尺寸 + SHA，不匹配返回 `RestoreMismatch` 不提交；`TmpGuard`、`rename_with_retry`、`create_carrier_backup(create_new)` 的失败路径不留残缺文件。
- **内容域往返**：容量声明与写入共用同一 `v3_layout::compute` / `backtrack_bytes_per_slot`；头解析全部接收固定长度数组并有 version/flags/suite/body_len/ext_len/CRC 白名单；`rollback` 逆序按 `applied` 日志还原且不落盘；并行（rayon）无跨块归约，同 seed 确定性有单测保护。
- **11-06 的 P0（crates.io 打包）与 P2-1（9 个 rustdoc warning）**：本次实测 `cargo package` 成功、`cargo doc` 0 warning，均已关闭。

---

## 7. 基线检查的一次偶发差异（未定位，勿误判）

首次 `python scripts/baseline_hash.py --check` 输出 **20 处 DIFF**，全部集中在
`baseline__testdata_baseline_textures14.jpg` 的 content 域：`uerd`/`juniward`/`jmipod` 三种算法
`status: ok -> embed_failed`，`structure` 仍 `ok`。紧接着的第二次、第三次 `--check` 都是
**28/28 identical**。

**已排除的解释**：
- 不是"随机 salt 概率失败"：基线脚本传固定 `--seed`（`baseline.json` 的 `seed` = `001122...eeff`），CLI 映射到 `Freshness::Seeded`，salt/nonce 确定性派生；本次 20 次带 `--seed` 复现 **全部成功且产物 SHA-256 唯一**。
- 不是生产路径概率失败：40 次不带 `--seed` 复现 **全部成功**（40 个不同哈希，符合 Random 语义）。
- 不是超时：脚本 `--timeout` 默认 900 s，单 case 实测远低于此。
- 首次运行与后台 `cargo clippy/test` 并发；但本轮 20 次 seeded 复现同样在 cargo 后台任务运行时进行，全部通过，CPU 负载不是充分解释。

**结论**：一次未复现的环境性失败（疑似 Windows 文件占用/共享冲突，三种算法都写 `cstego_*.jpg` 这一现象与之吻合，但**无直接证据，不作判定**）。建议给 `--check` 增加两项可观测性再观察：失败时打印 `note`（当前 `IGNORED_KEYS` 把 `note` 过滤掉了，DIFF 输出看不到真实错误），并在 CI 中加 `--keep-work` 保留现场。

---

## 8. 发布前建议动作（按优先级）

1. **【必做】** 修 `release.yml` 三处构建命令：加 `--features cli`；加"产物存在 + `--version` 与 tag 一致"断言。（P0-2）
2. **【必做】** 统一 `rust/README.md` 的二进制数量/命令名与 Release 实际产物；或发布全部 5 个 bin。
3. **【必做】** 修 `cli/render.rs:120-131` 的非 UTF-8 终端输出，修 `cmd_diag.rs` 批量 `inspect` 退出码。（P1-4 / P1-5）
4. **【必做】** 给 `verify` 补宿主可还原性校验，或明确降级 `verify_passed()` 的门禁语义。（P1-6）
5. **【建议】** 修 `TargetLock` 覆盖与 `write_bytes_atomic` 的 `create_new`/权限；补符号链接、硬链接与 PE CheckSum / FORCE_INTEGRITY 处理。（P1-2 / P1-3 / P2-1,2）
6. **【建议】** JPEG 概率失败：短期把 `Freshness::Random` 改成"根随机 + attempt 派生"、错误类型区分"概率性可重试"；至少在 CHANGELOG / README 披露该失败率，并把 `textures14.jpg` 基线显式重试一次。（P1-1）
7. **【建议】** 修 `crates.yml` 的 jq 表达式与 tag↔版本校验；给 release/crates 注入 `SOURCE_DATE_EPOCH`。（P2-11,12,13）
8. **【建议】** 补 macOS 内存查询、子集 clippy 门禁、stdin 载荷上限、批量 `--json` 失败项。（P2-8,9,14,16）
9. **【建议】** 修 i18n 文案/死映射、`--encrypt` 帮助、quiet 与 banner、文档 feature 描述；把 11-06 的 P3 搁置项写进 "Known limitations"。（P2-15,17,18 / P3）
10. **【复核】** 在 Linux / macOS runner 上实跑一次打 tag 的完整发布流程（本次仅在本机 Windows 实证，CI 矩阵未在 GitHub 上验证）；CI 里 `python` 命令在 `ubuntu-latest` 上的可用性也建议确认。

---

## 9. 附录：主要实证命令

```bash
cd rust
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --all-targets
cargo build --release --all-features
cargo doc --all-features --no-deps
cargo package --no-verify --allow-dirty --all-features
cargo test local_ --all-features -- --ignored
cargo test heavy_ --all-features -- --ignored
cargo build --release --bin strhide                    # -> requires the features: cli
cargo build --release --locked --message-format=json # -> 只有 ('strhide','lib')
cargo clippy --no-default-features --features content-base --lib -- -D warnings

cd ..
python scripts/import_lint.py
python scripts/baseline_hash.py --check
python scripts/check_feature_matrix.py
```

本报告为只读审查，未修改任何源码；`temp/` 下仅生成本次验证日志与 60 次复现产物。
