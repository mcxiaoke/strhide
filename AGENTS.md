# AGENTS.md

## 项目简介
`strhide` 是一个**智能、格式保持、无损的数据隐藏工具**：在普通文件中隐藏文本或文件，不改变格式、外观或功能，并能之后**还原**原始文件。

- `rust/`：Rust实现，编译为单一静态二进制，开发和维护中。
- `python/` 目录已冻结，不再改动，不要新增和修改任何代码。

**注意**：项目还未发布，修改代码时不用考虑旧版本生成的文件的兼容性。

## 开发与测试流程

### 主要开发目标：`rust/`

提交代码前要确保以下流程全部通过没有任何警告和错误！

```bash
cd rust
cargo build --release       # 编译，产物在 target/release/strhide
cargo test          		# 运行常规测试套件（全部通过，0 ignored 混杂）
cargo test local_batch_corpus -- --ignored
cargo test local_batch_stego -- --ignored
cargo fmt && cargo clippy   # 提交前格式化并修复所有 lint
```

### 语料批量回归（不随 `cargo test` 运行）

`rust/tests/local/local_corpus.rs` 对 `temp/testfiles` 全语料依次跑 拒绝 / 明文 / 加密 / stealth 场景，逐项校验 100% 还原。

```bash
cd rust
cargo test local_batch_corpus -- --ignored --nocapture
# 语料在别处时：
STRHIDE_CORPUS=/path/to/corpus cargo test --release local_batch_corpus -- --ignored --nocapture

# 内容自适应图像隐写批测（针对 temp/teststego 全量真实大图及抗检扫描评估）：
cargo test local_batch_stego -- --ignored --nocapture
# 隐写语料在别处时：
STRHIDE_STEGO_CORPUS=/path/to/stego_corpus cargo test local_batch_stego -- --ignored --nocapture
```

### 通用约定

- 如果要用python，使用这个 `C:\Home\Develop\venv` 。
- 改动代码前先核对影响面，不因修复旧问题引入新问题。
- 不自发 `commit`/`push`，除非明确要求。
- CI（`.github/workflows/ci.yml`）在 ubuntu + windows 上硬性跑 `cargo fmt --check`、`cargo clippy --all-targets -D warnings`、`cargo test --all-targets`；crates 发布与 release 打 tag 都 `needs` 这个质量任务，本地这三项必须先全绿。
