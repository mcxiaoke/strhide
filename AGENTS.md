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

**HEVC 内存要记两个数**：`embed_hevc` 必须把每个切片的 CABAC bin 序列留在内存里用于磁带回放，一个 13.5 s 的 1080p60 视频约 2.7 亿 bin（2 字节/条 ≈ 0.54 GB）+ 1700 万槽位（32 字节/条 ≈ 0.54 GB）。单个载体实测 **embed 峰值 1.31 GB、extract 0.59 GB**（2026-10-27 之前是 16 B/bin + 56 B/槽位，两者都是 7.45 GB）。整套 `cargo test local_ -- --ignored` 现在实测 **约 100–110 s、峰值 8.6–9.7 GB**（2026-10-27 之前是 287 s / 破 20 GB）。峰值里 HEVC 只占约 1.3 GB×并发数，其余是并行跑的 PNG/JPEG 隐写评测。

关于"要不要给 HEVC 测试加串行锁"：2026-10-27 实测过两种口径——加锁 6.9 GB / 104.7 s，不加锁 8.6–9.7 GB / 99–111 s。**耗时没有差别**（瓶颈是 PNG/JPEG 评测，不是 HEVC），锁只买到 2.5 GB 峰值，却会让排队等锁的测试被报成 "has been running for over 60 seconds"，所以那把 `hevc_serial()` 已删除。两个条件下应该把它加回来（`tests/common` 里一个 static `Mutex`，各 HEVC 测试首行取一次）：① 在 16 GB 内存的机器上跑整套；② 语料里新增 4K/更长的视频载体（单载体峰值会从 1.3 GB 涨到数 GB，叠加才会重新变成问题）。

排障提示：跑重测试时把日志重定向到文件再轮询，不要只看终端——`cargo test` 的进度只在测试结束时打印。

本地 HEVC/HEIF 语料放在 `temp/testhevc/`（gitignored）。真实 Annex-B 码流语料由 `python scripts/fetch_hevc_samples.py` 下载并派生（PhotoPrism 公开样本 + ffmpeg open-GOP 重编码），清单写入 `temp/testhevc/annexb/manifest.txt`；`cargo test local_hevc_annexb -- --ignored` 遍历该目录。

### 通用约定

- 如果要用python，使用这个 `C:\Home\Develop\venv` 。
- 改动代码前先核对影响面，不因修复旧问题引入新问题。
- 不自发 `commit`/`push`，除非明确要求。
- CI 上硬性跑 `cargo fmt --check`、`cargo clippy --all-targets --all-features -D warnings`、`cargo test --all-features --all-targets`，外加四条最小 feature 构建（`--no-default-features`、`structure`、`content`、`analysis`）；crates 发布与 release 打 tag 都 `needs` 这个质量任务，本地这些项必须先全绿。
- 默认 feature 是 `structure + content + analysis`，**不含 `cli`**（`cargo add strhide` 不该拖 clap/toml/rpassword）；用 CLI 或跑 CLI 测试时显式加 `--features cli` 或 `--all-features`。
