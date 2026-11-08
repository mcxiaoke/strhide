# 开发指南 (Development)

> 面向要改这个仓库的人。提交前必须过的门禁见 [../.github/CONTRIBUTING.md](../.github/CONTRIBUTING.md)，测试细节见 [TESTING.md](TESTING.md)，规范维护见 [api/spec/README.md](api/spec/README.md) §5。

---

## 1. 环境要求

| 组件 | 版本 | 用途 |
| :--- | :--- | :--- |
| Rust | stable（edition 2024，≥ 1.85；开发基准 1.99） | 全部核心与 CLI |
| Node.js | 22 | 桌面端前端 |
| pnpm | 9 | 桌面端包管理 |
| Python | 3.10+（标准库即可） | `scripts/` 下的检查与生成脚本 |
| WebKit2GTK / libappindicator / librsvg / patchelf | 仅 Linux | 构建桌面端 |

Windows 上不需要额外工具链（MSVC 由 rustup 处理）；Linux 静态产物需要 `x86_64-unknown-linux-musl` target 与 `musl-gcc`。

仓库根的 `.cargo/config.toml` 固定了 `jobs = 8`、`RUST_TEST_THREADS = 8`、`RAYON_NUM_THREADS = 8`——压力测试的线程数来自这里，改它会影响并发测试的可复现性。

## 2. 仓库布局

```text
strhide/
├── rust/                 # 核心 crate 与 5 个 CLI 二进制
│   ├── src/
│   │   ├── core/         # 最底层：crypto, commit(原子提交), errors, params, payload, i18n, sysmem
│   │   ├── formats/      # 格式嗅探、能力查询、容器片段工具(annexb / jpeg_segments)
│   │   ├── structure/    # 结构域：信封 + adapters(png/jpeg/riff/isobmff/zip/pdf/pe/mkv)
│   │   ├── stego/        # 内容域：engine, envelope, header, format, options, params,
│   │   │                 #   png/ jpeg/ hevc/ audio/ heif/, coding(STC), detmath, prng, registry
│   │   ├── analysis/     # 黑盒隐写分析（JPEG 标定等）
│   │   ├── cli/          # 参数、命令实现、渲染、日志、国际化
│   │   ├── facade.rs     # 统一入口 StrHide（Dialect + LocalParams）
│   │   └── lib.rs / main.rs / lite.rs / bin/{sthc,sths,sthv}.rs
│   ├── tests/            # 集成测试（见 TESTING.md 分层表）
│   └── examples/         # 压力测试与基准
├── gui/                  # Tauri 2 + React 桌面端（见 gui/README.md）
├── docs/                 # 规范、架构、指南、生成的许可证清单
├── scripts/              # 门禁检查、基线、发布打包、评测
└── testdata/             # 提交进仓库的多格式语料（基线/测试依赖）
```

## 3. Feature 门控（最容易踩的坑）

`rust/Cargo.toml` 的默认集是 `structure + content + analysis`，**不含 `cli`**。因此：

```bash
cargo build --release              # 只编库，不产出/不更新 target/release/strhide.exe
cargo build --release --all-features   # 这才是"跑 CLI 前该跑的那条"
```

常用组合：

| 目标 | 命令 |
| :--- | :--- |
| 全功能 | `--all-features` |
| 无 HEVC 的精简 CLI | `--no-default-features --features "structure,content-png,content-jpeg,content-audio,analysis,config,cli"` |
| 纯库（不带构建链） | `--no-default-features --features structure-base` |
| 只做取证 | `--no-default-features --features analysis` |

`structure-pe` 引入 `iced-x86`；`content-hevc` 引入两个 HEVC 实现；`analysis` 依赖结构域与 `dct-io`。改 feature 边界后必须跑 `python scripts/check_feature_matrix.py`。

## 4. 上游 HEVC 源码与 fork 机制

HEVC 相关依赖有两个，都不是本仓库的代码：

| 依赖 | 来源 | 本项目的处理 |
| :--- | :--- | :--- |
| `oxideav-h265` | crates.io `0.0.16`（MIT），上游 <https://github.com/OxideAV/oxideav-h265> | 直接用上游，不打补丁 |
| `rusty_h265` | crates.io 包名 `strhide-rusty-h265`（Apache-2.0），上游 <https://github.com/Remade-With-Rust/rusty_h265> | 本项目 fork，`package =` 别名引入，源码 key 仍是 `rusty_h265` |

```toml
oxideav-h265 = { version = "0.0.16", optional = true }
rusty_h265 = { package = "strhide-rusty-h265", version = "0.1", optional = true }
```

要在本地改上游代码，**不要**指望 `git` 依赖：`cargo package` 会把 git 源剥掉并回落到 crates.io 同名版本（详见 [CRATES_PUBLISH.md](CRATES_PUBLISH.md) §2）。可用的方式是临时 `[patch.crates-io]` 指向本地路径，验证完再以新版本的 fork 发布。作者机器上的 vendor 副本位于仓库之外（`F:\Develop\github\strhide-vendor\`），**不属于本仓库**，公开克隆无需它也能完整构建。

## 5. 分层与依赖边界

```text
core  ←  formats  ←  structure / stego / analysis  ←  cli  ←  二进制
                         ↑
                      facade（推荐入口，绑定 Dialect + LocalParams）
```

硬规则（由 `scripts/import_lint.py` 在 CI 中强制）：

- `stego` **不得**依赖 `structure`，反之亦然；两域只在 `facade` 层组合。
- `core` 不得反向依赖任何上层模块。
- 新增跨层引用前先想清楚是否应该走 `facade`。

## 6. 加一个载体或算法要动哪些地方

| 你要加的东西 | 必改代码 | 必改文档 | 附加门禁 |
| :--- | :--- | :--- | :--- |
| **结构域新格式** | `formats/sniff.rs`、`structure/adapters/<new>.rs`、注册到 adapter 分派、`strategy_id`/`format_id` 取值 | `api/spec/STRUCTURE-<NEW>.md`、`spec/README.md` 文档地图、`CAPACITY.md` | 基线 + CHANGELOG |
| **内容域新载体** | `stego/<carrier>/`、`stego/format.rs`（profile/标签/盐）、`stego/header.rs`（基础头尺寸）、`registry.rs` | `api/spec/CONTENT-<NEW>.md`、`CRYPTO.md`（`pre_salt` 公式与标签表） | 基线 + 压力测试 |
| **新代价模型** | `stego/{png,jpeg}/cost*`、`CostModelRegistry`、`detmath` 若需新函数 | 对应 `CONTENT-*.md`、`DETMATH.md` | `cost_vectors_check.py` + `heavy_` |
| **新 CLI 子命令** | `cli/args.rs`、`cli/cmd_*.rs`、`cli/mod.rs` 分派、`core/i18n` 文案 | `CLI_GUIDE.md`、`api/STEGO-API.md` §6 映射表 | `test_cli` |
| **新错误类型** | `core/errors.rs`（变体 + `kind()`） | `rust/README.md` 错误示例、GUI 映射 | `test_security` |

## 7. 国际化与文案

- **CLI**：文案在 `core/i18n/`，语言由 `--lang` 或系统 locale 决定；新增文案必须同时给中英两份。
- **桌面端**：所有可见字符串集中在 `gui/src/lib/i18n.ts`，文件顶部写明了术语约定（例如界面用"隐写/嵌入"而非"内容域/结构域"）。改文案前先读那段注释，不要引入第三种叫法。
- **代码与日志**：注释、commit message、日志输出一律英文。

## 8. 日志与诊断

- 用 `log` crate；`-v` → DEBUG，`-vv` → TRACE，输出到 **stderr**，不污染 stdout 管道。
- 不要把口令、密钥、明文载荷写进日志——桌面端的日志面板会被用户导出并贴进 issue。
- 结构化错误优先（`StrHideError::kind()`），不要靠匹配错误文本来分支。

## 9. 常见坑

| 现象 | 原因 | 解决 |
| :--- | :--- | :--- |
| 改完代码跑 CLI 没变化 | 默认 feature 不含 `cli`，二进制没重建 | `--all-features` |
| `cargo test` 里 CLI 测试是空的 | 同上，`test_cli` 受 `cli` feature 门控 | `cargo test --all-features --all-targets` |
| 基线报差异但往返测试全绿 | 输出字节变了 | 确认是否预期；是则 `--write` 并写 CHANGELOG |
| `import_lint` 失败 | 跨层引用（常见：stego 直接用 structure 的类型） | 上移到 `facade` 或 `core` |
| macOS/Windows 上浮点输出不同 | 用了宿主 `libm` | 走 `stego/detmath.rs` |
| 新克隆仓库 `baseline_hash.py --check` 跑不了 | 基线在 `temp/`，被 gitignore | 先在完整语料上 `--write`，见 [TESTING.md](TESTING.md) §4 |
| 并发跑测试随机失败 | 线程数与 `.cargo/config.toml` 不一致 | 不要局部覆盖 `RUST_TEST_THREADS` |

## 10. 提交前

按 [../.github/CONTRIBUTING.md](../.github/CONTRIBUTING.md) §"The gates every change must pass" 逐条跑，一条都别跳。改线格式的额外要求见 [api/spec/README.md](api/spec/README.md) §5 与 [RELEASE.md](RELEASE.md)。
