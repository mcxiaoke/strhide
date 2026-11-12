# AGENTS.md

## 项目简介
`strhide` 是一个**智能、格式保持、无损的数据隐藏工具**。

- `rust/`：Rust实现，编译为单一静态二进制，开发和维护中。
- `gui/`：基于 Tauri 2 + React + TypeScript 的桌面客户端（`StrHideStudio`），开发和维护中。
- **上游依赖源码 (Vendor)**：本地存放在 `F:\Develop\github\strhide-vendor\`（包括 `rusty_h265`, `oxideav-h265`, `re_mp4`, `rust_h265` 等）。修改上游库代码时在此目录下进行。

**注意**：项目还未发布，修改代码时不用考虑旧版本生成的文件的兼容性。

## 开发与测试流程

### 主要开发目标：`rust/`

提交代码前要确保以下流程全部通过没有任何警告和错误！

```bash
cd rust
cargo build --release --all-features   # 编译，产物在 target/release/strhide
cargo doc --all-features --no-deps # 验证doc没有问题
# 注意：默认 feature 不含 cli，`cargo build --release` 只编库、**不会**更新
# target/release/strhide(.exe)，跑 CLI 与 baseline_hash 前必须带 --all-features
# （或 --features cli），否则会拿旧二进制验证新代码。
cargo test --all-features --all-targets   # 全量测试（默认 feature 集不含 cli，CLI 测试按 feature 门控）
cargo test local_ --all-features -- --ignored  # 单独运行本地快速批量测试（约 30-60 秒）
# 下面的heavy test 可选运行，平时小改动可以不运行
cargo test heavy_ --all-features -- --ignored  # 单独运行耗时评测与矩阵测试（约 2 分钟）
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings   # 提交前格式化并修复所有 lint
# 以下脚本在根目录运行
python scripts/import_lint.py       # 架构依赖边界检查（CI quality 必跑项，防止违规跨层引用）
python scripts/check_feature_matrix.py  # 特性矩阵编译（改动 cfg/feature 门控或模块结构必跑）
python scripts/baseline_hash.py --check   # 与 scripts/baseline.json 逐例比对
```

### 隐写引擎全量并发压力测试 (Stress Tests)

测试各多媒体内容隐写引擎在多线程（默认 8 线程）、多轮密钥旋转、动态真随机载荷（SHA-256 往返校验）及多档填充深度（20%、40%、80%、100%）下的并发稳定性与格式保持性：

```bash
cd rust
cargo run --release --all-features --example jpg_stress   # JPEG 引擎：覆盖 uerd, juniward, jmipod 全量算法
cargo run --release --all-features --example png_stress   # PNG 引擎：覆盖 hill, suniward, mipod 全量算法
cargo run --release --all-features --example hevc_stress  # HEVC 引擎：覆盖 MOV/MP4 视频与 HEIC/HEIF 图像
cargo run --release --all-features --example audio_stress # Audio 引擎：覆盖 WAV/FLAC PCM 采样域隐写
```

### 架构依赖边界检查 (CI Quality)

```bash
python scripts/import_lint.py   # 与 CI quality 一致，检查 stego !-> structure 等分层解耦红线
```

### 桌面端开发与测试流程：`gui/`

如果改动了GUI代码，**必须确保编译没有任误，并且 GUI 这边的测试全部通过**：

```bash
cd gui
pnpm build                                     # 前端 TypeScript 类型检查与 Vite 打包，确保无编译错误
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings # 后端 Rust 代码编译与静态检查无 warning/error
pnpm test:unit                                 # 核心 IPC 命令与参数组合单元测试（13 个用例）
pnpm test:cross                                # GUI 与 CLI 双向交叉验证集成测试（5 个用例）
pnpm test:e2e                                  # UI 交互与对比度测试（23 个用例）
pnpm test:e2e:real                             # 真实进程与真实数据端到端测试（4 个用例，依赖 StrHideStudio.exe 产物）
```

### 字节级基线（架构重构期间必跑）

```bash
python scripts/baseline_hash.py --check   # 与 scripts/baseline.json 逐例比对
```

除非用户明确要求，不得用 `--write` 重建基线。改动任何解析/注入路径后必须 `--check` 全绿。

### 通用约定

- 如果要用python，使用这个 `C:\Home\Develop\venv` 。
- 改动代码前先核对影响面，不因修复旧问题引入新问题。
- 不自发 `commit`/`push`，除非明确要求。
