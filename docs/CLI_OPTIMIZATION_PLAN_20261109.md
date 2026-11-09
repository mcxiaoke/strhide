# CLI 审查问题与优化实施方案 (2026-11-09)

本文档记录针对 `strhide` Rust CLI 部分的代码审查结果，以及阶段 1（缺陷修复与一致性对齐）和阶段 2（重构与代码清理）的具体实施方案。遵循“改动最小、简单可靠、不引入多余复杂度”的原则。

---

## 一、 实施范围

### 阶段 1：缺陷修复与一致性对齐 (Bug Fixes & Consistency)

1. **补齐 CLI i18n 缺失参数与子命令映射**
   - **问题**：`rust/src/cli_i18n.rs` 漏掉了 `--auto`、`--fail-on`、`--no-filename`、`--seed` 四个参数的映射，导致 `--lang zh` 模式下这些选项的说明依然显示英文；`sthc`/`sths`/`sthv` 域入口子命令的根 `after_help` 未匹配。
   - **修改**：在 `core::i18n` 中补充对应的提示文案（如已有则复用），并在 `cli_i18n.rs` 的 `arg_help` 与 `cmd_after_help` 中补充对应分支。

2. **跨域自动回退条件对齐 (`--auto`)**
   - **问题**：`cmd_stego.rs` 的 `extract` 在回退至 `read` 时检查 `matches!(e, StrHideError::NoHiddenData(_) | StrHideError::UnsupportedFormat(_))`，而 `cmd_structure.rs` 的 `read` 在回退至 `extract` 时仅检查 `StrHideError::NoHiddenData(_)`。遇到 structure 不支持但 content 支持的格式时无法触发 `--auto`。
   - **修改**：在 `cmd_structure.rs` 中将错误匹配统一为 `StrHideError::NoHiddenData(_) | StrHideError::UnsupportedFormat(_)`。

3. **修复配置一致性与参数互斥**
   - **问题 1**：`EmbedArgs` 缺少 `--no-preserve-time` 选项，且在构造 `FileTarget` 时硬编码了 `preserve_time: true`，忽略了 `strhide.toml` 中的 `preserve_time = false` 配置。
   - **修改 1**：在 `EmbedArgs` 中加入 `--no-preserve-time`，并像 `WriteArgs` 一样计算 `let preserve_time = args.preserve_time && cfg.preserve_time.unwrap_or(true);` 传给 `FileTarget`。
   - **问题 2**：`StegoTuningArgs` 的 `key_file` 参数漏设了与 `prompt_password`（`-e`）的互斥关系（`ExtractArgs` 已有）。
   - **修改 2**：在 `StegoTuningArgs` 的 `key_file` 属性中添加 `conflicts_with_all = ["password", "password_file", "prompt_password"]`。

4. **统一 `--stdin` 缓冲区限额防 OOM**
   - **问题**：`cmd_stego.rs` 已对 stdin 输入设置了 1 GiB 上限截断保护，但 `PayloadSource::Stdin.into_buffered()`（用于 `write`）直接调用无上限的 `read_to_end`。
   - **修改**：在 `PayloadSource::into_buffered()` 内使用 `io::Read::take(1 << 30 + 1)` 统一施加 1 GiB 限制，超出时返回明确的错误。

---

### 阶段 2：重构与代码清理 (Refactoring & DRY)

1. **修正 `handle_list` 的格式化混用**
   - **问题**：`cmd_diag.rs` 第 794 行混用了内联捕获 `{id:<8}`、`{desc}` 和位置参数 `{:<15}`，易在后续维护中引发错位。
   - **修改**：标准化为内联命名参数 `println!("{id:<8} {domain:<15} {desc}");`。

2. **消除 `handle_capacity` 算法格式化重复**
   - **问题**：`cmd_stego.rs` 中的 `handle_capacity` 手写了一份算法参数格式化，与 `helpers::format_stego_algorithm` 重复且不完整。
   - **修改**：直接复用 `helpers::format_stego_algorithm`，保持算法与调优参数显示一致。

3. **收敛 `PasswordArgs` 解析方法**
   - **问题**：多处命令开头重复编写 `resolve_password(args.passwords.password.as_deref(), ...)`。
   - **修改**：为 `PasswordArgs` 增加简单的 `pub fn resolve(&self, encrypt_flag: bool, confirm: bool) -> Result<Option<String>, StrHideError>` 辅助方法，简化各 handler 的样板代码。
