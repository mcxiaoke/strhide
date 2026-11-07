# 代码审查逐条核对与实施记录（2026-11-07）

## 0. 范围与方法

- 审查报告：`docs/CODE_REVIEW_RELEASE_20261107.md`
- 核对基线：`ec8146b`（报告基线 `bb21117` 之后的一次提交，库层直接 print 已改为 `log` 宏）
- 最终实施结果：`17b5e4c` → `deb8ccd` → `49ef993` → `8d6c61b` → `00b47e5`
- 方法：所有结论都以当前 HEAD 的代码、测试、`baseline_hash` 为准；报告里的 `文件:行` 全部重新定位。
  没有只读报告就下结论。每个批次提交前都跑完整验收命令（见 §2）。
- 环境：Windows 10、Rust edition 2024、`cargo` 默认特性与 `--all-features` 均验证；
  GUI 未改动，因此未跑 GUI 套件。

## 1. 结论速览

| 条目 | 判定 | 处置 / 当前证据 | 提交 |
| --- | --- | --- | --- |
| P0-2 | `fixed` | release 构建补 `--features cli` | `17b5e4c` |
| P1-1 | `deferred` | JPEG 概率性嵌入失败，属有界重试的设计权衡 | — |
| P1-2 | `fixed`（Windows 硬链接部分 `deferred`） | 拒绝原地写符号链接/Unix 硬链接 | `49ef993` |
| P1-3 | `fixed`（Data Directory 部分 `deferred`） | 拒绝 FORCE_INTEGRITY / 非零 CheckSum | `49ef993` |
| P1-6 | `deferred` | verify 不校验宿主可恢复性；已明确文档边界 | `00b47e5` |
| P2-4 | `fixed` | PE 可选头边界 + 读失败 fail-closed | `49ef993` |
| P2-6 | `fixed` | AEAD 失败消息不再误导 | `deb8ccd` |
| P2-8 | `fixed` | `--stdin` payload 1 GiB 上限 | `deb8ccd` |
| P2-9 | `fixed` | 批量 JSON 保留失败项 | `deb8ccd` |
| P2-10 | `fixed` | `capacity --json` 单文档 + banner | `deb8ccd` |
| P2-12 | `fixed` | tag 与 `Cargo.toml` 版本一致性校验 | `17b5e4c` |
| P2-14 | `deferred` | macOS 内存查询依赖平台 FFI，本机不可验证 | — |
| P2-15 | `fixed` | `--encrypt` 帮助文案与实现一致 | `deb8ccd` |
| P2-16 | `fixed`（clippy 子集门禁部分 `deferred`） | 特性矩阵补 3 行 | `17b5e4c` |
| P3-1 | `fixed` | README 五个 bin + 示例统一为 `strhide` | `8d6c61b` |
| P3-2 | `fixed` | README 明文密码示例改为 `--password-file` | `8d6c61b` |
| P3-3 | `fixed` | 移除 `exclude = ["tests/"]`，示例资产入包 | `8d6c61b` |
| P3-4 | `fixed` | 同 P3-3（同一根因） | `8d6c61b` |
| P3-5 | `fixed`（preserve-time 映射）/ `deferred`（`--auto` 翻译、dead no-encrypt） | 见 §3 | `deb8ccd` |
| P3-6 | `fixed`（`-q` 抑制配置 warning）/ `deferred`（JSON banner） | 见 §3 | `deb8ccd` |
| P3-7 | `fixed` | README 已不再示范明文 argv 口令 | `8d6c61b` |
| P3-8 | `deferred` | 产物改名 / macOS 优化级别属发布策略 | — |
| P3-9 | 权限项 `obsolete`；tagName 项 `deferred` | 两个 workflow 都已有 `permissions: contents: write` | — |
| P3-10 | `fixed` | 过期架构注释与坏 intra-doc link | `8d6c61b` |

## 2. 分批提交与验收

| 批次 | 提交 | 覆盖条目 | 验收结果 |
| --- | --- | --- | --- |
| 1 | `17b5e4c` | P0-2、P2-12、P2-16 | 特性矩阵 11/11；fmt/clippy/build/test、local_ 19、heavy_ 5、import_lint、baseline 28/28 全绿 |
| 2 | `deb8ccd` | P2-6、P2-8、P2-9、P2-10、P2-15、P3-5、P3-6 | 同上；默认特性 clippy 亦通过 |
| 3 | `49ef993` | P1-2、P1-3（完整性字段）、P2-4 | 同上；`real_signed_pe_rejection` 通过；baseline 28/28 |
| 4 | `8d6c61b` | P3-1、P3-2、P3-3、P3-4、P3-7、P3-10 | 同上；`cargo package --allow-dirty` 无 warning，229 files / 4.3MiB |
| 5 | `00b47e5` | P1-6（文档边界） | fmt、`cargo doc --no-deps --all-features` 无 warning、clippy 通过 |

每批统一执行的命令：

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release --all-features
cargo test --all-features --all-targets
cargo test local_ --all-features -- --ignored        # 19 passed
cargo test heavy_ --all-features -- --ignored        # 5 passed
python scripts/check_feature_matrix.py               # 11/11
python scripts/import_lint.py
python scripts/baseline_hash.py --check              # 28/28 identical
```

## 3. 逐条核对记录

### P0-2 — release 构建不带 `cli`，5 个 bin 全部不产出（`fixed`）

- 当前证据：`rust/Cargo.toml:69,74,83,88,93` 五个 `[[bin]]` 都有
  `required-features = ["cli"]`；而 `ec8146b` 的 `release.yml` 三处构建命令均为
  `cargo build --release --locked --target ...`，不带 `cli`，只产出 `lib`。
  `Stage artifact` 要复制的 `strhide(.exe)` 不存在；若 runner 缓存里有旧 exe，还会误发旧二进制。
- 处置：`release.yml:54,111,148,149` 全部改为 `cargo build --release --locked --features cli ...`。
  未新增“断言产物存在/`--version` 匹配”步骤：`Stage artifact` 在 `cp`/`Copy-Item` 阶段
  已经会因文件缺失失败，再加断言属于重复校验。
- 验收：`cargo build --release --all-features` 与 `cargo test --all-features --all-targets` 通过；
  矩阵与基线未变化。

### P1-1 — JPEG 概率性嵌入失败约 1/20（`deferred`）

- 当前证据：`rust/src/stego/jpeg/engine.rs:550-562` 明确只重试 `missing_symbol`，
  `EMBED_ATTEMPTS = 6`；`:773` 是重试循环，`:1045-1053` 只有 `missing_symbol_stats`
  返回 `retryable: true`。超过 6 次才向调用方报错。
- 报告附带称 envelope 文档“声称整条重试链可复现”与 `Freshness::Random` 矛盾。
  当前 `rust/src/stego/envelope.rs:240-241` 已经明确写出 `binding` 被
  `Freshness::Random` 忽略，`:169-171` 也说明只有 `Seeded` 是复现路径 → 文档不矛盾。
- 判定理由：这是有界重试的设计权衡，不是逻辑错误。报告自身 §7 记录 40/40 真实样本
  成功，未提供可复现失败；提高尝试次数只是拿 CPU 换概率，改变盐派生不会降低失败率；
  要让调用方安全重试还需扩大错误类型/公开 API。风险大于收益，记为 `deferred`。
- 如需后续处理，建议单独立项做“概率-成本曲线”测量，而不是在本次审查修复中拍脑袋调参。

### P1-2 — 原地写不识别符号链接/硬链接（`fixed`，Windows 硬链接 `deferred`）

- 当前证据：`rust/src/structure/rejection.rs:489` 在 `in_place` 且
  `symlink_metadata(...).file_type().is_symlink()` 时拒绝；`:498-503` 在 Unix 下
  `nlink() > 1` 时拒绝。非原地写（`-o` 到别处）只读载具，不受影响。
- 为什么是真实缺陷：`commit` 用 rename 覆盖 `target`；对符号链接来说替换的是链接本身，
  对硬链接来说其他名字仍指向旧 inode 的旧内容，用户看到“写字成功但另一路径没变”。
- Windows 硬链接：`std::fs::Metadata` 没有 `nlink` 稳定 API，检测需要平台 FFI。
  本机无法验证，且引入 FFI/新依赖超出最小修复范围 → 该子项 `deferred`。

### P1-3 — PE CheckSum / DllCharacteristics 未处理（`fixed` 完整性字段；Data Directory `deferred`）

- 当前证据与修复：`rust/src/structure/rejection.rs:131-155` 新增读取可选头
  +64（CheckSum）与 +70（DllCharacteristics）：
  - FORCE_INTEGRITY（0x0080）置位 → 拒绝（loader 会校验校验和）；
  - `CheckSum != 0` → 拒绝（改字节后必然过期）。
- 基线影响：`FFConv.exe` / `FFConv.dll` 的 CheckSum 均为 0、FORCE_INTEGRITY 未置位，
  28 个基线用例全部 identical，没有为了对齐数字改基线。
- 未做部分：把 Data Directory 覆盖的 RVA 区间从 `pe_layout.rs:157` 的 section-tail
  slack 候选中剔除。需要 RVA→文件偏移映射（section 表 + 对齐），会改变 slack 选择，
  进而改变输出字节并触发基线重建；且认证签名 PE 已在 P2-4 处被拒绝。风险明显大于收益，
  记为 `deferred`。

### P1-6 — `verify` 不校验宿主可恢复性（`deferred`，文档边界已收敛）

- 当前证据：`rust/src/structure/engine.rs:3180-3184` 的 `verify_passed` 只看
  `level1_host`、`level2_envelope`、`level3_crypto`；真正比对宿主 SHA-256 的是
  `remove` 路径 `:2310`（`restored_sha256 == header.orig_host_sha256`）。
  所以被改过宿主字节的载体可以 `verify` 通过、`remove` 才拒绝。
- 为什么不直接修：要在 verify 里算宿主 SHA，必须重跑各格式的 `strip`。现有
  `HostAdapter::strip` 的默认实现在 `adapters/mod.rs:285` 会**回退 seek** 写入 patch，
  而 `pe_codebits`/`pe_slack`/`isobmff`/`zip` 各有重写逻辑。可行方案只有：
  1. 实现一个支持回退 seek 的哈希 sink（SHA-256 不可增量回退，需要缓冲/临时文件，
     对“只读诊断”语义不合适）；
  2. 在 verify 里复制一套 strip 逻辑（两个事实来源，正是报告警告的分类风险）；
  3. 仅对有路径的调用写临时文件（bytes API 与 GUI 只读语义不适用）。
  三者都明显扩大抽象或改变 verify 的资源特性，故 `deferred`。
- 已做的诚实收敛：`verify_passed` 文档不再声称是完整门禁，明确 L1-L3 的范围与
  “需要预检请先 `read`/`restore` 到一次性目标”（`00b47e5`）。代码行为未变。

### P2-4 — PE Security Directory 解析 fail-open（`fixed`）

- 当前证据：`rust/src/structure/rejection.rs:35` 的 `check_pe_authenticode` 原来虽然读了
  `size_of_opt_header`，却直接按固定 +128/+144 计算目录偏移；读失败返回 `Ok(None)`
  （当成没签名，继续注入）。`pe.rs:98-105` 预检同样在读失败时当成“无签名”。
- 修复：
  - `rejection.rs:88-118` 先按 magic 求 `sec_dir_rel`，要求
    `SizeOfOptionalHeader >= sec_dir_rel + 8`；超出声明范围直接当“无目录”；
    声明有目录但读不出来（`:105-116`）→ fail-closed，拒绝修改
    “签名状态不可判定”的 PE。
  - `pe.rs:98-105` 读失败时置 `has_authenticode = true`（保守拒绝）。
  - 真实签名 PE 仍返回 Authenticode 拒因（检查顺序保持先目录后完整性字段），
    `test_real_signed_pe_rejection` 通过。

### P2-6 — 元数据 AEAD 失败消息误导（`fixed`）

- 当前证据：`rust/src/core/crypto.rs:421` 原为 `"Metadata authentication failed"`，
  且 `:398-405` 的注释暗示调用方能在引擎层区分“错密码/损坏”。AEAD tag 在密码错误和
  密文篡改时必然同样失败，无法区分。
- 处置：消息改为 `"Wrong password or corrupted metadata"`，注释改为明确“不可区分”。
  结构引擎仍按既有策略映射为 `StrHideError::Password`（`engine.rs:1875`）；内容域保持
  `CorruptedData`。这是行为可见变更（错误文本），已在 CHANGES 记录。

### P2-8 — `--stdin` 无上限读取（`fixed`）

- 当前证据：`rust/src/cli/cmd_stego.rs:293-305` 原为
  `stdin().read_to_end(&mut buf)?`，任意大的管道会先把内存读爆，之后才轮到容量检查。
- 处置：`Read::take(MAX_STDIN_PAYLOAD + 1)`，上限 1 GiB（`MAX_STDIN_PAYLOAD` 常量），
  超限返回明确错误。选择 1 GiB 是因为提取侧已有同量级 payload 上限；没有新增配置项。

### P2-9 — 批量 JSON 丢弃失败项（`fixed`）

- 当前证据：`inspect` 分支只在成功时 `reports.push`（`cmd_diag.rs:123-173`），
  `verify`（`:338-440`）、`scan`（`:474-502`）、`capacity`（`cmd_stego.rs:242` 起）
  同样只输出成功项；失败只写 stderr，`--json` 消费者看不到。
- 处置：四个命令统一收集 `json_items`；失败项以
  `{"path": "...", "error": "..."}` 放进同一个 JSON 数组。成功项结构保持不变。
- 未做：`quiet` 下 stderr 抑制（那是 `-q` 的既定语义；JSON 失败项已保留）。

### P2-10 — `capacity --json` 每 carrier 一个顶层对象、无 banner（`fixed`）

- 当前证据：`cmd_stego.rs:242` 起，逐个 `println!(serde_json::to_string(&cap))`；
  批量时输出多个顶层对象，且不经过 `print_json`，因此没有 banner。
- 处置：改为收集后一次性输出：单 carrier 仍是顶层对象（保持兼容），多 carrier 为数组，
  统一走 `print_json`（带 banner）。失败项也进入同一数组。
- 连带修复：`scripts/baseline_hash.py:333` 原来用单行解析器读 `capacity --json`，
  pretty JSON 下会静默得到 `None`。改成 `load_json_block`。这是解析器适配，不是基线重建：
  28 个用例的 capacity 数值与所有载具字节仍完全一致（`--check` 28/28 identical）。

### P2-12 — crates 发布不校验 tag 与版本（`fixed`）

- 当前证据：`crates.yml` 的 check job 只读 `Cargo.toml` 版本，不比较 tag。
- 处置：`crates.yml:38` 在 `GITHUB_REF_TYPE == tag` 时要求
  `v$VERSION == $GITHUB_REF_NAME`，否则 `exit 1`。`workflow_dispatch` 不触发该校验。

### P2-14 — macOS 内存查询返回 `None`（`deferred`）

- 当前证据：`rust/src/core/sysmem.rs:68-73`，非 Windows/Linux 平台直接 `None`，
  调用方回退到保守的 4 GiB job 预算。
- 为什么 deferred：std 没有跨平台可用内存 API；macOS 需要 `sysctlbyname`/`host_statistics`
  FFI。新增 `libc` 依赖违反本次“不引入新依赖”，自写 FFI 又无法在本机（Windows）编译/运行验证。
  风险（未验证的 FFI）大于收益（仅影响 macOS 并发预算），记为 `deferred`。

### P2-15 — `write --encrypt` 帮助文案与实现相反（`fixed`）

- 当前证据：`rust/src/core/i18n/messages.rs` 的 `HelpWriteEncrypt` 原文说
  “未提供密码直接失败，不提示”，而 CLI 在交互终端下会提示输入。
- 处置：中英文都改为“交互终端下提示输入；无可用终端时直接失败”。
  只改文案，不改交互行为。

### P2-16 — 特性矩阵漏行（`fixed`；子集 clippy 门禁 `deferred`）

- 当前证据：`scripts/check_feature_matrix.py:43-54` 原来只有 8 行，缺少
  `content-base`、`core-io`、`config`；CI 的 “Minimal feature builds” 依赖该脚本。
- 处置：补到 11 行，本机 11/11 全部成功（矩阵行只跑 `cargo build`，不把 warning 当失败）。
- 未做：CI 目前不对单特性组合跑 `clippy -D warnings`；报告提到子集会有 dead_code warning。
  清理这些 warning 需要给大量公共项加条件编译或 `allow`，属于跨模块重构，`deferred`。

### P3-1 — README 与 Release 产物不一致（`fixed`）

- `rust/README.md:402` “four” → “five”（`strhide`/`sth`/`sthc`/`sths`/`sthv`）。
- 示例命令统一为 Release 实际发布的 `strhide`；Release 只 stage `strhide`。
  `sth` 仍保留在入口表中，因为它确实由 `--features cli` 构建，只是不作为发布产物。

### P3-2 / P3-7 — README 明文口令示例（`fixed`）

- `rust/README.md:418` 原为 `-p "P@ss123"`，会进 shell 历史；改为
  `--password-file vault-pass.txt`。`-p` 本身仍受支持（`args.rs:263-267`），未移除功能。

### P3-3 / P3-4 — `exclude = ["tests/"]` 导致示例资产缺失（`fixed`）

- 当前证据：`examples/in_memory.rs:34-35`、`private_format.rs:58-59`、
  `private_profile.rs:34-35` 都读 `tests/assets/*`；`rust/Cargo.toml:15` 排除了整个 `tests/`，
  `cargo package` 会提示忽略 tests 且发布包里的示例无法运行。
- 处置：删除 `exclude`。`cargo package --allow-dirty` 无 warning，229 files / 4.3MiB
  （1.2MiB compressed）；`.crate` 内已确认包含 `tests/assets/minimal.png` 与 `small.jpg`。

### P3-5 — i18n 映射（`fixed` 部分，其余 `deferred`）

- `rust/src/cli_i18n.rs:129`：`write/preserve-time` 之前错误映射到
  `HelpWriteNoPreserveTime`，现改为 `HelpWritePreserveTime`（`deb8ccd`）。
- `:127` 的 `write/no-encrypt` 映射在 `args.rs` 中找不到对应参数，属于死映射；
  删除它要连带核查 message 变体，收益极低，`deferred`。
- `--auto` 在中文 help 下仍显示英文：补齐需要新增 message 变体，属于文案完整度而非缺陷，`deferred`。

### P3-6 — `-q` 与 JSON banner（`fixed` 部分，其余 `deferred`）

- `rust/src/cli/mod.rs:243` 的配置 warning 之前无条件 `eprintln`，现在受
  `!pre.get_flag("quiet")` 控制（`deb8ccd`）。
- JSON banner 固定为 `sth`：它同时是 5 个 bin 共用的机器可读标识，已有测试按此断言；
  改成动态 banner 是输出格式变更，跨 CLI/GUI/测试，`deferred`。

### P3-8 — `x86-64-v3` 产物命名 / macOS 优化级别（`deferred`）

- `release.yml:36,84` 用 `target-cpu=x86-64-v3` 但产物名 `...-avx2`，且报告指出
  macOS 未用 v3。改名或统一优化级别属于发布策略（影响用户下载名、包管理器脚本、
  性能基线），且本机无法验证三平台性能，`deferred`。

### P3-9 — release 权限 / `workflow_dispatch` tagName

- 权限项 `obsolete`：`release.yml:9` 与 `gui-release.yml:10,18` 都已有
  `permissions: contents: write`。
- tagName 项 `deferred`：`gui-release.yml:66` 在 `workflow_dispatch` 下会把分支名当 tag
  建 Release。修法需要产品决定（加 tag 输入、或禁止手动触发、或改为 draft），
  不是无风险纯技术修复，`deferred`。

### P3-10 — 过期架构注释 / 坏 intra-doc link（`fixed`）

- `rust/src/core/mod.rs` 删除了“crypto/errors/params/commit 稍后迁入 core”的过期说明；
  这些模块现在就在 `core` 下。
- `rust/src/core/commit.rs` 的 “lives here ungated” 改为真实门控
  （`core/mod.rs:20` 的 `cfg(any(structure-base, content-base))`）。
- `rust/src/core/control.rs:20` 的 `[`crate::commit`]` 在 no-default 文档下无法解析，
  改为纯文本描述。
- `rust/src/lib.rs:135-137` 说明 crate-root 只是兼容性 re-export。
- `cargo doc --no-deps --all-features` 无 warning。

## 4. 基线说明

`python scripts/baseline_hash.py --check` 在五个批次后都是 **28/28 identical**。
本批次中唯一一次“差异”是 P2-10 改 `capacity --json` 输出为 pretty JSON 后，
`baseline_hash.py` 的单行解析器读不到对象，导致 48 处 `capacity_*` 变成 `None`；
确认不是载具字节变化后，把解析器改成 `load_json_block`（`:333`），复测归零。
没有重建基线、没有改动任何 baseline 数值。

## 5. 残余风险与后续建议

1. **P1-1**：JPEG 在缺失符号极端的载具上仍有概率性失败；建议后续用真实语料测量
   尝试次数与失败率曲线，再决定是否调参或提供“可重试”错误分类。
2. **P1-3**：PE Data Directory 区间仍可能落在 section-tail slack 中；修复需要
   RVA→文件偏移映射，会改变输出字节，建议单独做并同步重建基线。
3. **P1-6**：`verify` 仍不验证宿主可恢复性；调用方若需写回前门禁，应先
   `read`/`restore` 到一次性目标（文档已写明）。
4. **P1-2**：Windows 硬链接无法用 std 检测；若后续允许平台 FFI，可补
   `GetFileInformationByHandle` 的 `NumberOfLinks` 检查。
5. **P2-14**：macOS 并发预算仍走保守回退；补平台实现需在 macOS runner 上验证。
6. **P2-16**：单特性组合仍未纳入 `clippy -D warnings` 门禁，存在子集 dead_code 噪声。
7. **P3-8/P3-9**：发布产物命名与 GUI 手动发布流程需要产品决策。
