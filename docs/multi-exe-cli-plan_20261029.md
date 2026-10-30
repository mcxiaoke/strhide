# strhide/rust 多 CLI exe 拆分方案（评估 + 分步计划）

> 2026-10-29 · 状态：**方案待评审，未改任何代码**
> 触发：strhide 功能复杂、独立功能多，评估"多个独立 exe 是否更清晰方便"。
> 对照：pwgen 的 `pwgen.exe` 硬链接为 `pwr.exe`（busybox 风格）——那是"一份代码两个入口名"；
> 本文讨论的是 strhide 这种 10 子命令 / 3 大域的工具该怎么拆。

---

## 0. 结论先行

1. **推荐：在现有单个 Cargo package 内新增 3 个"域专用" `[[bin]]`**，与全量 `strhide` 共存：
   `strhide`（全 10 命令）+ `strhide-struct` + `strhide-stego` + `strhide-diag`。
   全部共享同一个 `strhide` lib crate 的 `cli` 模块，**零逻辑复制**。
2. **pwgen 那个"复制整份 ExecuteGenerate"的痛点在 Rust 里不存在**：Cargo 一个 package 可以
   有多个 bin target，逻辑写在 lib 里，所有 bin 链接同一份编译产物。项目里已有两个现成证据：
   - `examples/` 的 15 个 example target 各是独立可执行文件，共享 lib（`cargo metadata` 实证）；
   - `gui/src-tauri` 是**独立 Cargo package**，`path = "../../rust"` 依赖 lib 并按 feature 裁剪，
     产出 `strhide-gui.exe`——"多个独立 exe 共享一份逻辑"这个项目早就在做。
3. **体积不是痛点，不必为"瘦身"上 workspace**：实测 `strhide.exe` = 3,273,216 B（3.1 MiB），
   CLI zip 1.48 MB。`lto=true + strip=true` 后已经很小。真正的收益是**命令树 / `--help` / 工具名
   的清晰度**，不是二进制大小。
4. **不推荐**：每个子命令一个 exe（10 个，太碎）、现在就把 `rust/` 改成 workspace（改动大、
   收益小）。真正按 feature 裁剪的"瘦 exe"列为**可选第二步**，且不需要 workspace 也能做到。

---

## 1. 现状实证（文件路径 / 行号）

| 事实 | 证据 |
|---|---|
| 单 package、单 lib + 单 bin | `rust/Cargo.toml:61-68`：`[lib]` + 唯一 `[[bin]] name="strhide" path="src/main.rs" required-features=["cli"]` |
| 入口极薄 | `rust/src/main.rs:1-4`：仅 `strhide::cli::run_cli()` + `process::exit` |
| `cli` feature 拉全三域 | `rust/Cargo.toml:59`：`cli = ["structure","content","analysis","config", dep:clap/rpassword/base64]` |
| CLI 代码 3741 行、已按域分文件 | `src/cli/`：`args.rs` 516 + `helpers.rs` 765 + `cmd_stego.rs` 660 + `cmd_diag.rs` 639 + `cmd_structure.rs` 478 + `mod.rs` 268 + `render.rs` 237 + `cli_i18n.rs` 178 |
| 10 子命令 / 3 组 | `args.rs:50-96`：Container `write/read/restore`、Media Stego `embed/extract/capacity`、Diagnostics `inspect/verify/scan/list`；靠 `display_order` + `after_help` 分组 |
| 全局选项 | `args.rs:26-44`：`-c/--config`、`-q/--quiet`、`--lang`，均为 `global = true` |
| handler 已按域拆好 | `cli/mod.rs:39-41` 导入三组 `handle_*`；`mod.rs:193-266` 一个 `match` 分派 |
| 5 步启动流程可复用 | `cli/mod.rs:145-268`：预解析 → 配置 → 语言 → 构造 `Cli` → 分派；`render_early_error` 处理 help/version/错误 |
| GUI 已是"独立 exe 共享 lib" | `gui/src-tauri/Cargo.toml:19-23`：`strhide = { path="../../rust", default-features=false, features=["structure","content","analysis"] }`，有独立 `Cargo.lock` |
| 发布已是双产物 | `scripts/release.py:138-162`：`build_cli`（`cargo build --release --features cli`）与 `build_gui`（`pnpm tauri build --no-bundle`）分开构建，打 2 个 zip |
| 15 个独立 example target | `cargo metadata --no-deps` 实证：lib×1、bin×1、example×15、test×6、build-script×1 |
| release profile | `Cargo.toml:124-129`：`lto=true, codegen-units=1, panic="abort", strip=true` |
| CI 硬约束 | `AGENTS.md:47`：`cargo fmt --check`、`clippy --all-targets --all-features -D warnings`、`test --all-features --all-targets` + 4 条最小 feature 构建 |
| 项目未发布 | `AGENTS.md:10`：不考虑旧版本兼容，允许直接重构 |
| 现有产物 | `strhide.exe` 3.27 MB；`strhide-cli-v0.7.4-windows-x64.zip` 1.48 MB；`...gui...zip` 4.41 MB |

---

## 2. 先厘清"多个 exe"的四种含义

用户说的"多个 exe"至少对应四种完全不同的技术，收益与成本差很多：

| | 含义 | 内容 | 代码复制 | 二进制裁剪 | LTO 次数 | 改动面 |
|---|---|---|---|---|---|---|
| **A** | busybox / 硬链接（pwgen 式） | 同一份字节，多个名字，按 `argv[0]` 分派 | 零 | **无**（全功能照旧） | 1 | 极小 |
| **B** | 单 package 多 `[[bin]]` | 每个 bin 独立链接，共享 lib | 零 | **无**（`cli` 拉全三域） | N | 小 |
| **C1** | 单 package + 细分 feature + 分开构建 | 每个 bin 只编自己域的 lib | 零 | **有** | N×重编 lib | 中 |
| **C2** | workspace 多 package | 每个 package 一个 bin + 自己的 feature 子集 | 零 | **有** | N×重编 lib | 大（工程结构/lock/CI） |
| **D** | 每个子命令一个 exe | 10 个 | 零 | 无 | 10 | 中 |

**A 与 pwgen 的关系**：A 解决的是"不要复制逻辑、只换入口名"，但每个 exe 仍是全功能大二进制。
对 strhide 若采用，就是 `strhide.exe` 硬链接出 `strhide-write.exe` 等，按启动名直接跳到子命令；
好处是零额外 LTO、零复制，坏处是 10 个命令混在一个二进制里的"乱"没解决（只是入口名变了），
且**覆盖式升级若采用"删除+新建"会断开硬链接**，旧 exe 残留旧内容（原地覆盖写才保持同步）。

**Rust 侧的启动名**：`std::env::args_os().next()`（`argv[0]`）由调用者传入，硬链接 / 符号链接 /
改名都能保留；`std::env::current_exe()` 在 Linux 走 `/proc/self/exe`，符号链接会解析回目标
（pwgen 说的"Linux 符号链接失效"即指此），硬链接两平台都能保留启动路径。若用 A，建议
**`argv[0]` 为主 + `current_exe()` 兜底**，语义与 pwgen 的 `ProcessPath > argv[0]` 一致。

---

## 3. 关键约束（动手前必须知道）

1. **`cli` feature 拉全三域** → 方案 B 的多 bin **不会让 exe 变小**，只是命令树更清晰。想要
   "structure 版不带 HEVC 代码"必须走 C1/C2。
2. **Cargo feature 是 package 级合并（unification）**：同一次 `cargo build` 里所有 bin 共享
   同一份 lib 编译结果，feature 取并集。resolver v2/v3 不隔离 workspace 内 normal 依赖。
   **结论：要裁剪必须分开构建**——`release.py` 已经是"CLI 与 GUI 分开构建"的模式，扩展成本低。
3. **fat LTO × N**：`lto=true` 下每个 bin 单独做全程序 LTO。4 个 bin ≈ 4 倍链接时间。
   多 bin 后建议先实测，再决定是否把 `[profile.release] lto` 改为 `"thin"`（Cargo 不支持
   per-target profile，除非拆 package）。
4. **`required-features` 是天然护栏**：新 bin 都写 `required-features=["cli"]`，CI 的 4 条
   最小 feature 构建（`--no-default-features` / `structure` / `content` / `analysis`）会自动跳过
   它们，**这 4 条不用改**。
5. **`--all-targets --all-features` 会自动覆盖新 bin**：`clippy` / `test` 两条 CI 命令不用改，
   只是编译量增加（新 bin 的 `required-features` 在 `--all-features` 下必然满足）。
6. **共享设施必须复用，不能每个 bin 各写一份**：`--config` / `--lang` / `--quiet` 解析、
   `core::config` 加载、i18n 语言检测、`BANNER`、`render::print_error`、`cli_i18n::localize`、
   密码/载荷/调优解析（`helpers.rs` 765 行）——这些正是 pwgen 里"顶层 local function 会被整份
   复制"的等价物。Rust 里它们都在 lib crate 中，**天然只用一份**。
7. **`build.rs` 的注入对所有 bin 可见**：`STRHIDE_VERSION_INFO` / `GIT_HASH` / `BUILD_TIME`
   由 build script 跑一次生成，4 个 bin 的 `--version` 自动一致，不需要额外处理。

---

## 4. 推荐方案：B（第一步），C1 可选（第二步）

### 4.1 域划分与命名

| exe | 子命令 | 对应现有代码 |
|---|---|---|
| `strhide`（**保留**） | 全 10 个 | 现状，瑞士军刀 / 脚本兼容 / 文档示例 |
| `strhide-struct` | `write` `read` `restore` | `cmd_structure.rs` (478 行) |
| `strhide-stego` | `embed` `extract` `capacity` | `cmd_stego.rs` (660 行) |
| `strhide-diag` | `inspect` `verify` `scan` `list` | `cmd_diag.rs` (639 行) |

命名可再定（`shbox/shsteg/shdiag` 更短，但 `strhide-*` 前缀便于 Tab 补全与发布包归类，推荐后者）。
**强烈建议保留全量 `strhide`**：现有 README、测试、`run_cli_from` 私有命令行、脚本都依赖它；
未发布虽无兼容负担，但"全功能入口"本身是合理产品形态。

### 4.2 改造清单（文件级，全部零逻辑复制）

| 文件 | 改动 |
|---|---|
| `rust/Cargo.toml` | 新增 3 个 `[[bin]]`（`name`/`path`/`required-features=["cli"]`）；或直接在 `src/bin/*.rs` 放 3 个文件由 Cargo 自动发现（二选一，推荐显式声明便于审阅） |
| `rust/src/bin/strhide-{struct,stego,diag}.rs` | 各 ~5 行：`fn main() { std::process::exit(strhide::cli::run_domain_cli(Domain::X, std::env::args_os().collect())) }` |
| `rust/src/main.rs` | **不变**（仍是全量 `run_cli()`） |
| `rust/src/cli/args.rs` | 把 `Commands` 按域拆成 `ContainerCommands` / `StegoCommands` / `DiagCommands` 三个 `Subcommand` enum（10 个变体复用**现有** `WriteArgs`…`ScanArgs` struct，**不复制任何选项定义**）；抽 `GlobalArgs { config, quiet, lang }` 用 `#[command(flatten)]` 共享；定义 `StructCli` / `StegoCli` / `DiagCli` 三个 `Parser`；全量 `Cli` 保留（可由三者组合或独立保留） |
| `rust/src/cli/mod.rs` | 新增 `pub fn run_domain_cli(domain, argv)`，把 `run_cli_with` 的 5 步流程抽成公共函数（预解析 / 配置 / 语言 / 构造 / 分派）；`render_early_error` 基于**本域**的 `Command` 生成 help；分派直接复用 `handle_*`（三个 cmd 文件一行不改） |
| `rust/src/cli/{cmd_structure,cmd_stego,cmd_diag}.rs` | **不改**（handler 已按域分好） |
| `rust/src/cli/render.rs`、`cli_i18n.rs`、`core/i18n.rs` | 基本不改；`BANNER`/`--version` 按域显示工具名（`args.rs:17` 的 `BANNER` 改为按 domain 生成，`cli_i18n::localize` 遍历本域 `Command`） |
| `rust/tests/test_cli.rs` | 新增 3 组测试：本域 `--help` 只列自己 3-4 个命令、跨域命令被拒（退出码非 0）、同一参数下输出与全量入口字节一致 |
| `scripts/release.py` | `package_cli` 改为收集 `target/release/strhide*.exe` 全部打进 zip。**`build_cli` 的 `cargo build --release --features cli` 不用改**——Cargo 默认构建 package 内所有满足 `required-features` 的 bin，会自动产出 4 个 exe |
| `README.md` / `README.zh.md` / `rust/README.md` | 补 4 个工具的说明与示例 |
| `rust/Cargo.toml` `[profile.release]` | 多 bin 后先实测 fat LTO 耗时，偏慢则 `lto = "thin"`（可选） |

### 4.3 第二步（可选，按需才做）：真裁剪 C1

若以后确实需要"不含 HEVC 的轻量结构版"：

- 把 `cli` 拆细：`cli-common`（clap + `config` + i18n 基座）、`cli-struct = ["cli-common","structure"]`、
  `cli-stego = ["cli-common","content"]`、`cli-diag = ["cli-common","analysis"]`（注意 `cli-common`
  内部要按 `#[cfg(feature=...)]` 门控 handler，现有 `cmd_*` 已有细粒度 `content-png/jpeg/hevc`
  门控，改造量可控）。
- 每个 bin 的 `required-features` 指向自己的域 feature。
- **`release.py` 改为 4 次独立 `cargo build`**（每次 `--no-default-features --features cli-xxx
  --bin xxx`），规避 feature unification；GUI 那次构建本来就是独立的，照旧。
- **不需要 workspace**：单 package + 分开构建即可裁剪；workspace 会合并两个现有独立
  `Cargo.lock`、改动 `AGENTS.md` 的 4 条最小 feature 构建与 CI 路径，收益不抵成本。
- 收益评估：现 exe 仅 3.1 MiB，裁掉 HEVC 大概率只省 1 MiB 级；**主要价值是"独立依赖集 /
  可单独发布"，不是体积**。因此列为可选。

---

## 5. 不推荐项及理由

- **D 每子命令一个 exe**：10 次 fat LTO；`--config/--lang/--quiet` 与 help/错误渲染要在 10 个
  入口重复挂载；发布包里 10 个 exe 反而让用户更困惑；且 `cli` 拉全三域，每个仍是大二进制。
- **A 硬链接 busybox 单独用**：能拿到"无子命令的短入口"（如 `strhide-write photo.png -t ...`），
  但解决不了"命令树混杂"，且引入 `argv[0]` 分派与硬链接升级断链风险。可作为 B 之上的
  **补充**（把域 bin 再硬链接出动作别名），建议放最后、单独评估。
- **C2 workspace 多 package**：工程结构改动最大（workspace root、共享 lock、CI 路径），
  而裁剪收益在 3.1 MiB 量级上很小。除非将来要发布"多个独立 crate 各自版本化"，否则不做。

---

## 6. 分步实施与验收

**Step 1 — 骨架（最小可验证）**
1. `Cargo.toml` 加 3 个 `[[bin]]` + `src/bin/` 三个薄 main；
2. `args.rs` 拆 3 个 enum + `GlobalArgs`；`mod.rs` 抽 `run_domain_cli`；
3. 验收：`cargo build --release --features cli` 产出 4 个 exe；`strhide-stego --help` 只列
   `embed/extract/capacity`；`strhide-stego write ...` 被拒；`strhide --help` 仍是 10 个命令。

**Step 2 — 质量与发布**
4. 补 `tests/test_cli.rs` 域测试；`release.py` 打包含 4 exe 的 zip；三个 README 更新；
5. 验收（按 `AGENTS.md`）：`cargo fmt --check`、`cargo clippy --all-targets --all-features
   -- -D warnings`、`cargo test --all-features --all-targets` 全绿；`python scripts/release.py
   --cli-only` 生成的 zip 解压后 4 个 exe 均可运行；`release.py` 的 SHA256SUMS 覆盖 4 个 exe。
6. 未动解析/注入路径，`python scripts/baseline_hash.py --check` 可跳过（如动了 CLI 复用代码
   再跑）。

**Step 3 — 可选**
7. 实测 fat LTO 耗时，决定 `lto="thin"`；
8. 若确定要裁剪，按 §4.3 做 C1。

每步完成后在 `docs/CHANGES-20261029.md` 顶部追加变更摘要（时间用本机 `date` 取到秒）。
不自发 commit / push。

---

## 7. 待拍板的决策点

1. **域划分**：3 域（`struct/stego/diag`）是否认可？还是把 `diag` 并入 `struct` 做 2 域？
2. **命名**：`strhide-struct/stego/diag` 还是更短的 `shbox/shsteg/shdiag`？
3. **是否保留全量 `strhide`**（建议保留）。
4. **是否需要真裁剪**（决定要不要做 C1；按当前 3.1 MiB 体积，建议先不做）。
5. **LTO 取舍**：多 bin 后是否接受 `lto="thin"`。
