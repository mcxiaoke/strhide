# AGENTS.md

## 项目简介
`strhide` 是一个**智能、格式保持、无损的数据隐藏工具**：在普通文件中隐藏文本或文件，不改变格式、外观或功能，并能之后**还原**原始文件。

- `rust/`：Rust实现，编译为单一静态二进制，开发和维护中。
- `python/` 目录已冻结，不再改动，不要新增和修改任何代码。

## 开发与测试流程

### 主要开发目标：`rust/`

```bash
cd rust
cargo build --release          # 编译，产物在 target/release/strhide
cargo test --release           # 运行release测试套件
cargo fmt && cargo clippy      # 提交前格式化并修复所有 lint
```

### 语料批量回归（不随 `cargo test` 运行）

`rust/tests/batch_corpus.rs` 是 Python `tests/batch_test_runner.py` 的 Rust 对应物：对 `temp/testfiles` 全语料依次跑 拒绝 / 明文 / 加密 / stealth 场景，逐项校验 100% 还原。

```bash
cd rust
cargo test --release --test batch_corpus -- --ignored --nocapture
# 语料在别处时：
STRHIDE_CORPUS=/path/to/corpus cargo test --release --test batch_corpus -- --ignored --nocapture
```

### 通用约定

- 改动代码前先核对影响面，不因修复旧问题引入新问题。
- 不自发 `commit`/`push`，除非明确要求。
- CI（`.github/workflows/ci.yml`）在 ubuntu + windows 上硬性跑 `cargo fmt --check`、`cargo clippy --all-targets -D warnings`、`cargo test --all-targets`；crates 发布与 release 打 tag 都 `needs` 这个质量任务，本地这三项必须先全绿。
