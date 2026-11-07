# Rust 库代码直接打印 (Print) 梳理与 Log 统一改造方案

**文档日期**：2026-11-07  
**状态**：已完成 (Completed)  
**目标**：消除 `strhide` 核心库代码中的直接控制台输出（`println!`, `eprintln!`），统一接入 `log` 门控与分级体系，避免污染外部宿主及 GUI 的终端输出，确保可恢复警告与内部调试信息能够被宿主日志系统（如 GUI 的 RingBufferLogger、服务日志等）正确捕获。

---

## 1. 现状梳理与分类

通过对 `rust/src/`（排除 `rust/src/cli/` 交互层）的代码审计，共排查到 23 处 print 宏调用。按照代码层级与影响面分为四类：

### 类别 A：核心库原子提交与元数据恢复警告（8 处）—— 高优先级
在载体写入或还原成功后，恢复只读属性或时间戳发生非阻断性失败时，直接使用了 `eprintln!`。
- **影响**：GUI（StrHide Studio）及外部库调用者在执行文件修改时，stderr 被污染，而 GUI 的前端日志面板无法捕获此警告。
- **位置**：
  1. `rust/src/core/commit.rs:490`（`commit_carrier_bytes` 时间戳恢复失败）
  2. `rust/src/core/commit.rs:496`（`commit_carrier_bytes` 权限恢复失败）
  3. `rust/src/core/commit.rs:594`（`commit_carrier_patches` 时间戳恢复失败）
  4. `rust/src/core/commit.rs:600`（`commit_carrier_patches` 权限恢复失败）
  5. `rust/src/structure/engine.rs:1612`（`write_carrier` 时间戳恢复失败）
  6. `rust/src/structure/engine.rs:1618`（`write_carrier` 权限恢复失败）
  7. `rust/src/structure/engine.rs:2449`（`remove_carrier` 时间戳恢复失败）
  8. `rust/src/structure/engine.rs:2455`（`remove_carrier` 权限恢复失败）

### 类别 B：音频隐写引擎（FLAC）内部调试与统计残留（8 处）—— 中高优先级
在 `stego::audio::flac` 模块中，使用了手写的 `OnceLock` + 环境变量（`STRHIDE_FLAC_DEBUG` / `STRHIDE_FLAC_STATS`）配合 `eprintln!` 输出调试与统计。
- **影响**：绕过了统一的 `log` 门控，无法通过标准的 `RUST_LOG=strhide::stego::audio::flac=debug` 等进行分级和重定向。
- **位置**：
  1. `rust/src/stego/audio/flac/bits.rs:35`（`eof` 越界诊断）
  2. `rust/src/stego/audio/flac/frame.rs:42`（`bad` 损坏字段诊断）
  3. `rust/src/stego/audio/flac/frame.rs:258`（`parse_frame` 帧解析失败诊断）
  4. `rust/src/stego/audio/flac/frame.rs:359`（`parse_frame_inner` 帧头部信息）
  5. `rust/src/stego/audio/flac/frame.rs:438`（`read_subframe` 子帧调试信息）
  6. `rust/src/stego/audio/flac/frame.rs:553`（`read_residual` 残差调试信息）
  7. `rust/src/stego/audio/flac/mod.rs:665`（`slots` 提取统计分析）
  8. `rust/src/stego/audio/flac/mod.rs:1240`（`drift` 残差漂移诊断）

### 类别 C：批处理流控中的控制台硬编码（3 处）—— 结构治理
- **位置**：`rust/src/core/pipeline.rs:46, 48, 63`（`for_each_carrier`）
- **影响**：该函数位于 `core` 模块，但内部硬编码了针对终端的 `eprintln!` / `println!`，并在错误时直接格式化 `i18n::Msg`。
- **方案**：`for_each_carrier` 仅作为 CLI 批处理辅助工具使用，将其输出行为解耦或移至 CLI 辅助层（`src/cli/helpers.rs`），使 `core` 模块彻底消除终端直接输出。

### 类别 D：库内集成测试输出（4 处）—— 审计确认（保持现状）
- **位置**：
  - `rust/src/stego/audio/flac/mod.rs:1574, 1587, 1593`（测试集通过率打印）
  - `rust/src/stego/png/cost/mipod.rs:374`（手动导出成本向量文件时提示）
- **评估**：位于 `#[cfg(test)]` 或 `#[test]` 内部，构建非测试二进制时自动剔除，不影响正式调用者。

---

## 2. 实施改动方案

### 2.1 类别 A 改造方案：统一使用 `log::warn!`
移除多余的 `"warning: "` 字符串前缀（日志记录器自带级别格式）：
```rust
// 改造前
eprintln!("warning: failed to preserve file timestamps for '{}': {e}", target_path.display());
// 改造后
log::warn!("failed to preserve file timestamps for '{}': {e}", target_path.display());
```

### 2.2 类别 B 改造方案：统一接入 `log::debug!` / `log::trace!`
统一 target 为 `"stego::audio::flac"`：
1. 细粒度读取（`bits.rs::eof`, `frame.rs::bad`, 子帧与残差详情）：改用 `log::trace!(target: "stego::audio::flac", ...)`
2. 帧解析失败诊断、统计汇总、漂移检测：改用 `log::debug!(target: "stego::audio::flac", ...)`
3. 移除重复的 `OnceLock` 与环境变量解析，依靠 `log::log_enabled!` 进行零开销检查。

### 2.3 类别 C 改造方案：`for_each_carrier` 归位与解耦
`for_each_carrier` 是纯 CLI 的批处理遍历工具（仅在 `cmd_stego.rs` 与 `cmd_structure.rs` 中被调用），将其迁至 `rust/src/cli/helpers.rs`，让 `core::pipeline` 只保留无终端交互副作用的文件路径计算和防覆盖校验。

---

## 3. 实施步骤与验收流程

1. **备份先行**：修改前将待改动的源码备份至 `temp/backups/logging_refactor_20261107/`。
2. **分步实施**：
   - 步骤 1：修复 `commit.rs` 和 `structure/engine.rs` 中的元数据恢复警告。
   - 步骤 2：重构 `stego/audio/flac/` 下的调试和统计输出为标准 `log` 宏。
   - 步骤 3：将 `for_each_carrier` 从 `core/pipeline.rs` 调整至 `cli/helpers.rs`。
3. **验证闭环**：
   - 静态分析：`cargo fmt --check` 与 `cargo clippy --all-targets --all-features -- -D warnings`
   - 架构依赖：`python ../scripts/import_lint.py`
   - 特性矩阵：`python ../scripts/check_feature_matrix.py`
   - 单元与集成测试：`cargo test --all-features --all-targets`
   - 字节级基线：`python scripts/baseline_hash.py --check`
4. **日志记录**：在 `docs/CHANGES-20261107.md` 顶部追加变更摘要。
