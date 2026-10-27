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
cargo test --all-features --all-targets   # 全量测试（默认 feature 集不含 cli，CLI 测试按 feature 门控）
cargo test local_ -- --ignored --all-features # 单独运行本地批量测试（约 3 分钟）
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings   # 提交前格式化并修复所有 lint
```

### 字节级基线（架构重构期间必跑）

```bash
python scripts/baseline_hash.py --check   # 与 temp/baseline/baseline.json 逐例比对
```

冻结/重建基线用 `--write`。它跑 `rust/tests/fixtures`、`rust/tests/assets`、`temp/testhevc` 共 58 例的 write/read/restore 与 embed/extract，比对策略、信封大小、还原 sha256 与容量数字；内容域用固定 `--seed` 驱动，连 stego 产物字节（sha256）一起比，结构域信封 nonce 随机、只比大小与还原。依赖 gitignored 语料，只在本地跑，不进 CI。改动任何解析/注入路径后必须 `--check` 全绿。

**本地批测的内存峰值约 12 GB**：`embed_hevc` 会把每个切片的全部 CABAC bin 留在内存里用于磁带回放，一个 13.6 s 的 1080p60 视频就是 3.8 亿 bin（单个视频门限测试单独占用约 12 GB、116 s）。并行跑没问题，但不要在跑批测的同时开其它吃内存的进程——被 swap 拖住时表现和"死锁"很像。

排障提示：跑重测试时把日志重定向到文件再轮询，不要只看终端——`cargo test` 的进度只在测试结束时打印。

本地 HEVC/HEIF 语料放在 `temp/testhevc/`（gitignored）。真实 Annex-B 码流语料由 `python scripts/fetch_hevc_samples.py` 下载并派生（PhotoPrism 公开样本 + ffmpeg open-GOP 重编码），清单写入 `temp/testhevc/annexb/manifest.txt`；`cargo test local_hevc_annexb -- --ignored` 遍历该目录。

### 通用约定

- 如果要用python，使用这个 `C:\Home\Develop\venv` 。
- 改动代码前先核对影响面，不因修复旧问题引入新问题。
- 不自发 `commit`/`push`，除非明确要求。
- CI 上硬性跑 `cargo fmt --check`、`cargo clippy --all-targets --all-features -D warnings`、`cargo test --all-features --all-targets`，外加四条最小 feature 构建（`--no-default-features`、`structure`、`content`、`analysis`）；crates 发布与 release 打 tag 都 `needs` 这个质量任务，本地这些项必须先全绿。
- 默认 feature 是 `structure + content + analysis`，**不含 `cli`**（`cargo add strhide` 不该拖 clap/toml/rpassword）；用 CLI 或跑 CLI 测试时显式加 `--features cli` 或 `--all-features`。
