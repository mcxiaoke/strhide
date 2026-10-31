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
# 注意：默认 feature 不含 cli，`cargo build --release` 只编库、**不会**更新
# target/release/strhide(.exe)，跑 CLI 与 baseline_hash 前必须带 --all-features
# （或 --features cli），否则会拿旧二进制验证新代码。
cargo test --all-features --all-targets   # 全量测试（默认 feature 集不含 cli，CLI 测试按 feature 门控）
cargo test local_ --all-features -- --ignored  #单独运行本地批量测试（约 3 分钟）
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings   # 提交前格式化并修复所有 lint
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
python scripts/baseline_hash.py --check   # 与 temp/baseline/baseline.json 逐例比对
```

冻结/重建基线用 `--write`。改动任何解析/注入路径后必须 `--check` 全绿。

### 通用约定

- 如果要用python，使用这个 `C:\Home\Develop\venv` 。
- 改动代码前先核对影响面，不因修复旧问题引入新问题。
- 不自发 `commit`/`push`，除非明确要求。
