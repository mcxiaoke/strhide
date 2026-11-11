# StrHide 代码审查报告

- 审查日期：2026-11-11（同日完成二次实证复核，修正记录见 §9）
- 审查对象：`c:\Home\Projects\strhide`（`rust/`、`gui/`、`scripts/`、`.github/workflows/`、根目录配置与 `docs/`）
- 审查方式：逐模块静态阅读 + 可复现的量化统计（文件/行数、`#[test]`/`#[ignore]`/`cfg`/`unwrap`/`allow` 计数、大文件与超长函数定位、跨文件重复行重合度）+ 只读验证（`python scripts/import_lint.py` 实跑 `exit=0`、`git check-ignore`、`git ls-files`）；高危与关键结论均按 `文件:行号` 抽查源码（H-1、H-2、facade、CI、.gitignore 等），抽查清单见 §8/§9
- 统计口径：仅统计一手源码，排除 `target/`、`node_modules/`、`dist/`、`temp/`、`.venv/`、`__pycache__/`、`scripts/stego_eval/.venv`（后者含 2447 个第三方 `.py`，不计入项目代码量）
- 边界说明：本次**未审 `F:\Develop\github\strhide-vendor\` 的 vendor 源码**；未修改任何代码、未创建分支、未提交；未重跑 `cargo clippy` 与完整测试套件（该编译门禁在 `ci.yml:39-74` 中为阻塞项，本报告只陈述 CI 配置事实，不声明"本地 clippy 0 warning"）；草稿中未逐条复验的细粒度行号已在 §9 标注

---

## 0. 结论速览

1. **整体质量高于同类项目平均线**：CI 配置有 `cargo clippy --all-targets --all-features -- -D warnings` 阻塞门禁（`ci.yml:43`）；`import_lint.py` 本次实跑退出码 0；Rust 侧 1107 个 `#[test]`（`rust/src` 585 + `rust/tests` 522），另有 **37 处 `#[ignore…]`**（8 处裸 `#[ignore]`、29 处带 reason），`rust/tests` 约 2.8 万行，测试/生产比很高；错误模型、能力表、baseline、stress 例程等工程设施齐全。
2. **最需要优先处理的是两类"内存/落盘"风险**：
   - 结构域写入路径**先把整个 payload 读进内存，再检查大小上限**（H-1），大文件会 OOM 而不是干净报错；
   - GUI 提取落盘**绕开 facade 的写盘策略**，缺少"输出 == 载体"保护（H-2），极端操作下会不可逆覆盖载体。
3. **最主要的坏味道是跨层复制**：ISOBMFF box 解析 ×4、stego 选项类型 ×6（80 个 `with_*`）、算法名→tuning 映射 ×2（且失败语义不同）、前端串行任务循环 ×4、输出文件名去重 ×3；4 个 stress example 去重行重合度 75.8%–89.6%。
4. **架构分层总体健康**，但 `structure/engine.rs`（3585 行）、`stego/hevc/engine.rs`（5260 行）、`stego/png/engine.rs`（5146 行）把过多职责塞进单个文件；GUI 又直接依赖 `structure::engine`、`stego::io` 等内部模块，削弱了公共 API 边界。
5. **测试与发布体系的主要缺口不在数量，而在"不可信输入、GUI CI 与可复现性"**：没有 fuzz/property 测试；GUI 的 4 套测试与 clippy 完全不在 CI；`check_feature_matrix.py` 漏掉 `content-audio`/`content-heif-bridge`/`structure-pe` 单域组合；`gui-release.yml` 是唯一不复用 CI 质量门禁的发布流；`testdata/`、DL 模型、`temp/` 基线均被 `.gitignore` 排除，格式/评估类用例无法在新克隆上复现（M-21~M-24）。
6. **本批已实施修复**：按"确定是 bug、改动小、收益大、风险低"筛出 H-1、H-2、M-6、L-2，已修复并分两批提交（`cf9b2a7`、`0e138bf`），改法与验证结果见 §10；`.github/` 下的 CI 相关项按要求留待后续处理。

---

## 1. 总体评价

### 1.1 做得好的地方（有代码依据）

- **分层红线有工具守护**：`scripts/import_lint.py` 明确检查 `structure !-> stego`、`stego !-> structure`、`core !-> {formats,structure,stego,cli,analysis}` 等；本次运行输出 `OK: all architectural boundaries intact`。
- **能力清单是单一真源**：`rust/src/formats/capability.rs` 用一张 `CAPABILITIES` 表描述格式/策略/后缀，并有测试校验 `sniff`、adapter router、capability 三者一致（见 `rust/tests/test_lifecycle/sniff.rs`）。这类"看似重复、实际有防线"的设计应保留。
- **错误模型是结构化的**：`StrHideError` + `ErrorDetail{kind,category,detail}`（`rust/src/core/errors.rs:302-330`）让 CLI/GUI 可以按 `kind` 分类，而不是解析字符串；前端 `gui/src/lib/errorHandler.ts` 也优先使用 JSON 中的 `kind`。
- **提交路径考虑了原子性与并发**：`core/commit.rs` 有临时文件 + 原子替换、`TargetLock`、陈旧锁回收与单元测试；`core/fs.rs` 的 `write_bytes_atomic` 被 CLI/GUI 共用。
- **容量/资源防护意识到位**：stego 读写都有"空闲内存 60% 预算"（`rust/src/stego/io.rs:297-310`）、信封有 `MAX_*` 限长、`analysis` 对大文件有前缀/尾部扫描上限。
- **测试与基线设施齐全**：1107 个测试、4 个 stress example、`baseline_hash.py`、`check_feature_matrix.py`、`import_lint.py`；`docs/TESTING.md` 对部分取舍有明确说明。

### 1.2 主要风险

- **可靠性**：写入前无界读 payload；GUI 落盘分叉；并发任务的内存预算各自为政。
- **可维护性**：巨型文件/巨型函数；跨模块复制导致"改一处漏一处"的概率高。
- **可验证性**：手写格式解析器缺少 fuzz；GUI 不在 CI；feature 矩阵有洞。
- **可复现性与发布门禁**：`testdata/`、`*.pt` 模型、`temp/` 基线不入库；`stego_eval` 文档指向不存在的 venv 路径；`gui-release.yml` 不复用 CI 质量门禁；pre-commit 的 clippy 参数与 CI 不一致（§9、M-21~M-24）。

---

## 2. 架构评估

### 2.1 分层与依赖方向

依赖方向基本遵循 `formats/core -> structure|stego -> analysis -> facade -> cli|gui`，且 `import_lint.py` 能验证红线。需要指出的两点：

1. `analysis` 为了能在没有 `content-*` 的情况下独立编译，自己实现了 PNG/JPEG 像素解码（`rust/src/analysis.rs:1400-1520`）。这看起来是重复，但**是 feature 独立性要求的合理代价**，见 §8。
2. `stego` 内部存在 **4 套 ISOBMFF 解析**（结构域 1 套 + 内容域 3 套），跨域的那套由分层红线强制隔离，内容域内部的 3 套则没有隔离理由（M-4）。

### 2.2 模块职责与规模

| 文件 | 行数 | 说明 |
|---|---:|---|
| `rust/src/stego/hevc/engine.rs` | 5260 | 生产代码约 4300 行，混合 MPC 参数集扫描、CABAC 重写、embed/extract/inspect/verify |
| `rust/src/stego/png/engine.rs` | 5146 | 生产代码约 2688 行，内联测试约 2131 行 |
| `rust/src/structure/engine.rs` | 3585 | 无内联测试；`write_core` 单函数 539 行 |
| `rust/src/stego/options.rs` | 1900 | 6 套选项类型 + 80 个 `with_*` |
| `rust/src/stego/params.rs` | 约 1400 | 参数/安全策略/信封限额混在一起 |

`structure/engine.rs` 同时承担：payload 归一化、压缩/加密、策略选择、注入/移除、恢复校验、警告渲染。它仍然可读，但已经接近"单文件承担一个域"的上限。

### 2.3 公共 API 边界

- `rust/src/lib.rs` 把 `core`、`structure`、`stego`、`analysis` 等全部 `pub`，另有 **87 处 `#[doc(hidden)]`**。对未发布的二进制项目可以接受，但 GUI 已经开始依赖内部路径：
  - `gui/src-tauri/src/commands/structure.rs:8` 直接 `use strhide::structure::engine::{PayloadSource, ReadSummary, RemoveResult, WriteResult}`；
  - `gui/src-tauri/src/commands/stego.rs:12` 直接 `use strhide::stego::io::extract_carrier_file_payload`。
- 结果是：库内部重构会直接打断 GUI；而 `structure::mod` 明明已经 re-export 了这些类型（L-9）。
- `reject_carrier_output` 是 `pub(crate)`（`rust/src/core/commit.rs:124`），GUI 想复用安全护栏却拿不到，只能自己写一套（H-2 的根因之一）。

### 2.4 并发与内存模型

- 库内对单次调用有预算（`stego/io.rs:297-310`、`:388-393`），但**预算是"整机可用内存的 60%"，不是进程内共享配额**。
- GUI 在 IPC 层又维护了一套准入：固定 `EMBED_PEAK_BYTES = 1.43 GiB`、`60%` 空闲内存（`gui/src-tauri/src/state.rs:84-104`）。
- 两套模型粒度不同：库按格式估算（HEVC 实测峰值 2243 MiB），GUI 按一个固定值预留。并发批量任务时可能低估（OOM）或过度串行（小 PNG 也按 1.43 GiB 计）。见 M-2。

### 2.5 GUI 与 CLI 是否重复实现

- 结构域：GUI 走 facade（`write_file/read_file`），复用良好。
- 内容域：GUI 的提取命令直接调用低层 `extract_carrier_file_payload` 并自行落盘，绕开了 facade 的 `extract_file` 策略（H-2）。
- 算法名→tuning 映射：CLI 在 `cli/helpers.rs:206`，GUI 在 `commands/stego.rs:31`，两份实现且失败行为不同（M-6）。
- 批量任务：GUI 后端有一套 `run_batch_job`（`commands/batch.rs`），但前端从未调用，形成死 API（M-7）。

### 2.6 feature 门控

- `facade.rs`/`options.rs`/`capability.rs` 集中了大量 `#[cfg(feature = ...)]`（`facade.rs` 73 处、`options.rs` 65 处），属于典型的"条件耦合"热点；每次新增格式都要在多个文件中同步 `cfg`。
- `check_feature_matrix.py` 的单域行没有覆盖 `content-audio`、`content-heif-bridge`、`structure-pe`（M-9），使这些 `cfg` 组合的编译错误只能靠 `--all-features` 兜底，而 `--all-features` 可能互相掩盖问题。

---

## 3. 问题清单（按严重程度）

### 3.1 高

#### H-1｜结构域写入：先无界读入 payload，再检查大小上限 ✅ 已修复（`cf9b2a7`）

> 修复：`PayloadSource::File` 改为 `std::io::Read::take(&mut f, MAX_VERIFY_PAYLOAD_SIZE + 1).read_to_end()`，超限立即返回 `PayloadTooLarge`（与 Stdin 分支同型、与写路径 `structure_payload_limit` 同一绝对上限，合法范围不变）。详见 §10。

- **证据**：
  - `rust/src/structure/engine.rs:434-440`：`PayloadSource::File` 直接 `f.read_to_end(&mut b)`，读之前没有 `metadata().len()` 预检。
  - `rust/src/structure/engine.rs:453-463`：`Stdin` 反而有 `MAX_STDIN_PAYLOAD = 1 GiB` 的 `take(...)` 限制。
  - `rust/src/structure/engine.rs:1126-1137`：`structure_payload_limit(orig_host_size)` 的检查发生在 `into_buffered()` 之后。
- **问题**：同一个入口，Stdin 有上限、File 没有；`PayloadTooLarge` 只在完整读入并完成一次归一化拷贝之后才可能返回。
- **影响**：用户误选一个 20 GB 文件作为 payload，进程会先分配 20 GB（再加压缩缓冲），在低内存机器上直接 OOM；CLI 的 `panic = "abort"` 会终止进程，GUI 的 `catch_unwind` 也兜不住分配失败。
- **严重程度**：高
- **修复方向**：在 `into_buffered()` 前用 `metadata().len()` 与 `structure_payload_limit()` 比较，超限立即返回 `PayloadTooLarge`；或提供受限 `Read` 包装器。写入端也应有独立的绝对上限（与读取端 `MAX_VERIFY_PAYLOAD_SIZE` 对称）。

#### H-2｜GUI 提取落盘绕开 facade，缺少"输出==载体"保护 ✅ 已修复（`0e138bf`）

> 修复：把库内已有的 `reject_carrier_output` 从 `pub(crate)` 提为 `pub`，GUI 两处提取写盘点（`extract_stego_file_cmd`、`smart_extract_impl` 的最终 `target_file`）前置调用，复用与 CLI/facade 相同的 `same_file` 判定。详见 §10。

- **证据**：
  - `gui/src-tauri/src/commands/stego.rs:259-260`：`extract_stego_file_cmd` 得到 payload 后直接 `write_bytes_atomic(dest, ...)`，没有 `reject_carrier_output`。
  - `gui/src-tauri/src/commands/stego.rs:418-437`：`smart_extract_impl` 只做 `candidate.exists()` 去重，写盘点没有 `same_file(dest, carrier)` 判断。（**复核修正**：两处命令的函数开头其实已有 `check_overwrite(dest, overwrite)`，见修复前 `:238-240` / `:327-329`；真正缺的只是"输出==载体"护栏，草稿此处描述不准确。）
  - 对照：`rust/src/facade.rs:1183-1192` 的 `extract_file` 明确调用 `reject_carrier_output` + `check_overwrite`；`rust/src/core/commit.rs:124` 的 `reject_carrier_output` 是 `pub(crate)`，GUI 无法复用。
- **问题**：GUI 复制了 facade 的落盘流程，但漏掉了最关键的两条保护。
- **影响**：用户在"保存提取结果"对话框里选中载体文件本身（或 API 调用方传入该路径）时，载体会被 payload 覆盖，原始载体与隐藏内容同时丢失；且与 CLI 行为不一致。
- **严重程度**：高（触发需要用户操作，但后果不可逆）
- **修复方向**：在 facade 暴露 `extract_to_path()` 并让 GUI 统一调用；至少把 `reject_carrier_output`/`same_file` 提升为公开工具，并在两处 GUI 写盘点前置检查。

---

### 3.2 中（rust 引擎）

#### M-1｜`smart_extract` 对内容域做两遍完整解析

- **证据**：`rust/src/facade.rs:769-855` 先 `inspect_any`，再走 `extract_carrier_file_payload`；`stego/io.rs:263` 的 inspect 对 PNG/JPEG 走 `read_carrier_file` 全量解码，`io.rs:230-235` 的 extract 再次读取并解码。
- **影响**：GUI 默认"智能提取"对每张 PNG/JPEG 解码两次；对 4K HEVC，inspect 与 extract 各做一次容器/码流扫描，大文件延迟和峰值内存接近翻倍。
- **严重程度**：中
- **修复方向**：让 `ExtractOutcome`/inspect 结果携带定位信息供 extract 复用；或按域短路（结构域命中后不再做内容域全量 inspect，除非需要 `also_present`）。

#### M-2｜内存准入策略在库与 GUI 各有一套，且估算口径不同

- **证据**：`rust/src/stego/io.rs:297-310`（单次调用按 60% 空闲内存算预算）、`:388-393`（注释记录 HEVC embed 实测峰值 2243 MiB）；`gui/src-tauri/src/state.rs:84-104`（每个 embed 槽位固定预留 1.43 GiB，再按 60% 空闲内存算槽位数）。
- **问题**：库的预算检查是"每次调用都认为整机预算可用"，GUI 的固定预留又不区分格式。
- **影响**：8 核/16 GB 机器上并发 5 个 4K HEVC 嵌入，实际峰值可达 ~11 GB，但库对每个任务都放行；反过来，5 MB 的 PNG 批量也会按 1.43 GiB/个串行化。极端情况下分配失败会 `abort` 整个进程。
- **严重程度**：中
- **修复方向**：把"进程级内存配额"下沉到库（如 `MemoryBudget` 可注入），GUI 只负责申报/释放；峰值按引擎/容器类型估算，而不是单一常量。

#### M-3｜PNG/音频的 extract 与 inspect 复制同一段信封引导代码

- **证据**：`rust/src/stego/png/engine.rs:1988-2062`（extract 中 decode header + `validate_ext_critical` + limits）与 `:2252-2330`（inspect 中几乎相同的一段）；`rust/src/stego/audio/core.rs:500` 附近也有 inspect/extract 两份引导逻辑。
- **影响**：PBKDF2 次数上限、扩展记录校验、容量限制这些安全相关判断有两份实现；只改一处会造成 "inspect 说可读、extract 报错" 或反向的不一致。
- **严重程度**：中
- **修复方向**：抽出 `open_header_bootstrap(bytes, keys, limits) -> Result<OpenedHeader>`，extract/inspect/verify 只负责把错误映射成各自语义。

#### M-4｜ISOBMFF box 解析存在 4 套实现，校验规则不一致

- **证据**：
  - `rust/src/structure/adapters/isobmff.rs:631`（`read_box_size`）、`:830`（`read_stream_box_header`）；
  - `rust/src/stego/hevc/mp4_boxes.rs:823`（`boxes_in`）；
  - `rust/src/stego/hevc/heif_boxes.rs`（HEIF box 解析）；
  - `rust/src/stego/heif/thumb_bridge.rs:1105`（`parse_isobmff` + `read_box_header`）。
- **问题**：`boxes_in` 会拒绝 `total_size < header_len`；`structure` 侧的 `read_box_size` 先返回 `(size, header_len)` 再由调用方各自检查；`read_stream_box_header` 甚至接受 `size32 < 8`（见 L-2）。64-bit size、size==0、越界截断的处理在四处并不完全一致。
- **影响**：同一个畸形文件在不同入口（inspect/restore/embed/thumb bridge）可能得到不同结论；新增 box 语义要改 4 处。
- **严重程度**：中
- **修复方向**：内容域内提取一个共享的 `isobmff` reader（mp4/heif/thumb 共用）；结构域因分层红线保留独立实现，但用同一组测试向量约束行为。

#### M-5｜6 套选项类型 + 80 个 `with_*` 的复制式 builder

- **证据**：`rust/src/stego/options.rs:485`（Embed）、`:792`（Probe）、`:983`（Extract）、`:1145`（Bridge）、`:1448`（Inspect）、`:1594`（Verify）；全文件 1900 行，`pub fn with_` 共 80 个（`structure/options.rs` 另有 15 个）。
- **问题**：每个结构体都重复声明 `password/key/domain/limits/control/pool/safety/tuning/extensions` 等字段，并各自实现 `Debug/PartialEq/builder`。`BridgeOptions` 等还出现了字段集合不完全一致。
- **影响**：新增一个全局选项（如新的安全开关）要改 6 个结构体 + 6 组 builder + 若干 `From` 转换；漏改会在某个入口静默丢失配置。
- **严重程度**：中
- **修复方向**：抽出 `CommonOptions<'a>` 并 flatten，或用声明式宏生成 builder；保留按域的方法做语义校验即可。

#### M-6｜CLI 与 GUI 重复实现"算法名→tuning"映射，失败语义不同 ✅ 已修复（`0e138bf`）

> 修复：`resolve_tuning` 改为返回 `Result<StegoTuning, StrHideError>`，与 CLI `stego_tuning` 对齐——`None`/空串/`auto`/音频别名仍为 `Auto`，未知名称返回 `General` 错误而不是静默回退；两个调用点加 `?`，并新增单测 `unknown_algorithm_is_rejected_not_silently_auto`。两份映射本身仍在（本次只统一失败语义，未做下沉重构）。详见 §10。

- **证据**：`rust/src/cli/helpers.rs:206-250`（未知算法返回错误）、`gui/src-tauri/src/commands/stego.rs:31-51`（未知算法静默回退 `StegoTuning::Auto`）。
- **影响**：新增算法时如果只改 CLI/后端列表，GUI 会"接受"请求但用 Auto 嵌入，用户以为用了指定算法；且同一算法在两端可能得到不同参数集。
- **严重程度**：中
- **修复方向**：把映射下沉到库（`StegoTuning::from_algorithm_name(&str) -> Result<...>`），GUI/CLI 共用；GUI 对未知值明确报错。

#### M-7｜GUI 注册了 6 个前端从未调用的 IPC 命令，批量接口还是类型擦除的

- **证据**：`gui/src-tauri/src/lib.rs` 的 `generate_handler!` 注册了 `verify_carrier_cmd`、`scan_carrier_cmd`、`restore_structure_file_cmd`、`extract_stego_file_cmd`、`read_structure_file_cmd`、`run_batch_job_cmd`；在 `gui/src` 与 `gui/tests` 中检索这些名字均无调用。
- **补充**：`gui/src-tauri/src/commands/batch.rs:40-122` 用 `job_type: String` 分发，并通过 `serde_json::to_value` 返回 `Value`，前端拿不到类型信息。
- **影响**：约 500 行后端命令/测试维护成本；两套并行的"单文件命令 vs 批量命令"入口容易行为漂移；IPC 面越大，攻击面/审计面越大。
- **严重程度**：中
- **修复方向**：确认是否为下一版 UI 预留；若否直接删除。批量接口改为强类型 DTO + enum `JobType`。

#### M-8｜GUI 的编译检查与 45 个测试完全不在 CI

- **证据**：`.github/workflows/ci.yml` 只跑 Rust 库；`.github/workflows/gui-release.yml` 仅在 `gui-v*` tag 时构建产物（tauri-action 会执行 `beforeBuildCommand`，但不跑 clippy/单测/cross/e2e）。而 `AGENTS.md` 要求 `pnpm build`、`cargo clippy`、`test:unit`、`test:cross`、`test:e2e`、`test:e2e:real`。
- **影响**：Tauri 后端与 `strhide` 库的接口漂移、前端类型错误只能靠提交者本地自觉；GUI/CLI 交叉验证（`gui/src-tauri/tests/cross_validation.rs`）在 CI 中不存在。
- **严重程度**：中
- **修复方向**：增加 PR 级 `windows-latest` job：`pnpm build` + `cargo clippy --manifest-path gui/src-tauri/Cargo.toml -- -D warnings` + `pnpm test:unit` + `pnpm test:cross`；`e2e-real` 可放 nightly/手动。

#### M-9｜feature 矩阵漏掉单域组合

- **证据**：`scripts/check_feature_matrix.py:41-55` 的矩阵包含 `structure-base`、`structure`、`content-base`、`content-png`、`content-jpeg`、`content-hevc`、`content`、`analysis`、`core-io`、`config`，但没有 `content-audio`、`content-heif-bridge`、`structure-pe`。
- **影响**：脚本自身注释声称"每个域单独也能编译"，但音频/HEIF bridge/PE 单域实际未被验证；这些域的 `cfg` 错误只能被 `--all-features` 掩盖。
- **严重程度**：中
- **修复方向**：补三行（`content-audio`、`content-heif-bridge`、`structure-pe`）；如果某些组合有意不支持，在脚本里显式注释原因。

#### M-10｜没有 fuzz/property 测试，手写解析器多

- **证据**：`rust/Cargo.toml` 无 `proptest`/`quickcheck`/`cargo-fuzz` 依赖；`rust/tests` 与 `src` 内均为示例驱动测试。手写解析器覆盖 PDF/ZIP/MKV/PE/ISOBMFF/H.264/HEVC。
- **影响**：恶意或损坏载体是最现实的外部输入；当前只能靠人肉构造用例，越界/死循环/巨额分配类问题容易被漏掉。
- **严重程度**：中
- **修复方向**：对 `inspect/extract/restore` 入口建立 `cargo-fuzz` target（用现成 testdata 做种子），至少覆盖 `structure/adapters/*` 与 `stego::*::inspect`。

#### M-11｜verify 与 read 复制了同一段 KDF/凭据阶梯（加密关键逻辑）

- **证据**：`rust/src/structure/engine.rs:1853-1869`（`open_and_authenticate_envelope`）与 `:3049-3065`（`verify_core`）各自实现 `password -> derive_all`、`profile.secret() -> derive_all` 的回退顺序。
- **影响**：以后调整 stealth/默认凭据策略时，只要漏改一处，就会出现"verify 通过但 read 失败"或相反；这类问题很难在常规测试里暴露。
- **严重程度**：中
- **修复方向**：抽 `UnpackSecrets::derive_attempts(password, salt, profile)`，由两个调用点共享；并加一条"verify/read 使用同一凭据集"的断言测试。

#### M-12｜巨型函数与参数爆炸

- **证据**：
  - `rust/src/structure/engine.rs:990-1528`（`write_core`，539 行）；
  - `rust/src/stego/hevc/engine.rs:1192-1701`（`embed_hevc_patches_with_factor_v4`，510 行、10 个参数、带 `#[allow(clippy::too_many_arguments)]`）；
  - 全库共 **43 处** `allow(clippy::too_many_arguments)`（本次实核）；`stego/hevc/engine.rs` 内 10 处（行号见 §8.3），其余模块分布沿用草稿统计，未逐项复核。
- **影响**：单点改动需理解大量上下文；失败分支难以单测；新参数继续通过 `allow` 堆叠。
- **严重程度**：中
- **修复方向**：把 `write_core` 拆成 prepare/compress/encrypt/select/inject/finalize；引擎入口用参数结构体（`EmbedRequest`）替代长参数列表。

#### M-13｜结构域读写路径的内存放大与上限策略

- **证据**：`rust/src/structure/engine.rs:1946-1951`：`payload_limit = carrier_len * 256`，下限 64 MiB、上限 `MAX_VERIFY_PAYLOAD_SIZE`；读路径先解密到 `Vec` 再解压到新 `Vec`（`engine.rs:2020-2105`）。
- **影响**：
  - 4 MiB 载体即可把上限推到 1 GiB，解压炸弹仍可造成约 1 GiB 峰值（加解密缓冲后更高）；低内存机器可能 OOM。
  - 写入时 payload + 压缩缓冲同时存在（约 2×），`eof` 策略下 payload 可以远超载体大小。
- **严重程度**：中
- **修复方向**：上限同时考虑压缩比上限与当前可用内存；读路径可考虑"解压到临时文件/流式输出"；至少在文档/GUI 中明示峰值。

#### M-14｜前端 4 个视图各写一份串行任务循环

- **证据**：`gui/src/views/HideStructureView.tsx:70-102`、`ExtractView.tsx:54-85`、`ScanView.tsx:99-130`、`StegoEmbedView.tsx:123-221`：都是 `for` 循环 + `startTask`/`queue.update`/`finishTask` + 错误分类。
- **影响**：新增"取消/重试/并行/进度合并"能力要改 4 处；各视图的错误处理已经出现细节差异。
- **严重程度**：中
- **修复方向**：抽 `useSequentialJob({ runOne, onItem })` hook，视图只提供单项执行函数与文案。

#### M-15｜输出文件名去重有三份实现，前端还逐次 IPC

- **证据**：`rust/src/core/fs.rs:107`（`unique_batch_path`，`pub(crate)`，GUI 用不到）、`gui/src/lib/queue.ts:80-101`（`pathExists` + `uniqueOutputPath`，逐个候选调用 `getFileMetadata` IPC）、`gui/src-tauri/src/commands/stego.rs:418-437`（后端自己的 `(i)` 循环）。
- **影响**：三处命名规则（`stem (i).ext`）可能漂移；1000 个重名文件会产生 1000 次 IPC + `metadata` 往返。
- **严重程度**：中
- **修复方向**：把 `unique_batch_path` 公开为一个纯函数/IPC 命令（或让写盘命令返回最终路径），前端只展示；后端统一负责命名。

#### M-16｜PNG/JPEG/audio 不产生进度事件，`Control` 抽象未落地

- **证据**：`rust/src/stego/hevc/engine.rs:757`、`:3851`、`:3997` 有 `control.report(Event::progress(...))`；在 `png/engine.rs`、`jpeg/engine.rs`、`audio/core.rs` 中检索 `report(` 为 0。三者只有 `control.check()`（PNG 11 次、JPEG 12 次）。
- **影响**：GUI 对 PNG/JPEG/音频只能显示"处理中"，大图嵌入/提取期间没有百分比；取消延迟取决于稀疏的 `check()`。
- **严重程度**：中
- **修复方向**：在 PNG 行扫描、JPEG 系数遍历、音频帧循环内按固定步长 `report`；或在统一 IO 层按"解码/嵌入/写盘"阶段发粗粒度事件。

#### M-17｜4 个 stress example 高度复制，且硬编码本机路径

- **证据（已复核）**：`rust/examples/{jpg,png,hevc,audio}_stress.rs` 去重行集合重合度为 75.8%–89.6%（jpg↔png 89.2%、hevc↔audio 89.6%、png↔hevc 75.8%，完整六对见 §8.4）；硬编码绝对路径计数 jpg 2、png 2、hevc 1、audio 0，即 **3/4 文件**含本机路径（如 `png_stress.rs` 中的 `C:/Home/Projects/strhide/testdata/...`）。
- **影响**：并发/密钥轮换/填充深度逻辑改一处漏三处；换机器或 CI 上无法直接运行。
- **严重程度**：中
- **修复方向**：抽 `examples/common/stress.rs`（随机载荷、SHA 往返、轮次/线程数解析、testdata 根目录）；四个 example 只保留引擎特化部分。

#### M-18｜GUI 提取缓存整块 clone payload，并在写盘后继续持有

- **证据**：`gui/src-tauri/src/commands/stego.rs:377-392`：`outcome: fresh.clone()` 存入单槽缓存，`fresh` 又继续用于写盘；`state.rs` 的 `CachedExtract` 在下一次提取前一直持有整块 payload。
- **影响**：提取 500 MB 载荷时，写盘期间同时存在两份（缓存 + 返回值）；写完后缓存仍占用 500 MB。
- **严重程度**：中
- **修复方向**：缓存用 `Arc<[u8]>`/按需重新读取；写盘完成后显式清空缓存，或仅在"预览→保存"两步之间短时保留。

#### M-19｜GUI 生产代码多处 `lock().unwrap()`，poison 即 panic

- **证据**：`gui/src-tauri/src/state.rs:215`、`:346`；`gui/src-tauri/src/logger.rs:76`、`:164`、`:180`、`:186`；`gui/src-tauri/src/commands/batch.rs:31`。
- **影响**：任一持锁线程 panic 后，后续日志/任务取消/语言切换全部 panic；`run_cancellable_task` 的 `catch_unwind` 只能兜住工作闭包，兜不住这些命令线程。
- **严重程度**：中
- **修复方向**：使用 `parking_lot::Mutex`，或统一 `unwrap_or_else(|e| e.into_inner())`；日志模块应保证永不 panic。

#### M-20｜diag 命令手写三份 spawn_blocking/catch_unwind 模板，且没有取消

- **证据**：`gui/src-tauri/src/commands/diag.rs:38-70`、`:179-205`、`:219-240` 三处 `spawn_blocking + catch_unwind + pool.install`；而 `state.rs` 已有 `run_cancellable_task`（被 stego/structure 使用）。
- **影响**：inspect/verify/scan 没有 `Control` 取消能力，批量扫描无法中断；模板复制导致错误映射不一致。
- **严重程度**：中
- **修复方向**：统一走 `run_cancellable_task`（或抽一个 `run_blocking_isolated`），并传入 `Control`。

#### M-21｜GUI 发布流是唯一绕过 CI 质量门禁的发布路径

- **证据**：
  - `.github/workflows/release.yml:17-22`、`.github/workflows/crates.yml`：`quality: uses: ./.github/workflows/ci.yml` + `needs: quality`；
  - `.github/workflows/gui-release.yml:15-71`：**没有** quality job，`on: push tags: gui-v*` / `workflow_dispatch` 后直接 `pnpm install`（:56-58，非 `--frozen-lockfile`）→ `tauri-apps/tauri-action@v0`（:61，浮动大版本）→ `releaseDraft: false`（:69，直接发正式版）；
  - `.github/workflows/ci.yml:3-6` 注释称 "the two release workflows ... call it through `workflow_call`"，实际只有 release/crates 复用，GUI 未复用。
- **影响**：与 M-8 叠加后，`gui-v*` tag 可以在未经 fmt/clippy/库测试/GUI 单测与交叉验证的情况下发布正式桌面版；`pnpm install` 允许 lockfile 漂移，action 版本不固定，产物不可复现。
- **严重程度**：中（工程链路，触发于发布时）
- **修复方向**：给 `gui-release.yml` 加 `quality: uses: ./.github/workflows/ci.yml` 并 `needs: quality`；至少补 `pnpm build` + Tauri clippy + `test:unit` + `test:cross`；改 `pnpm install --frozen-lockfile`、固定 action 版本、先发 draft 再由人工转正。

#### M-22｜pre-commit 的 clippy 参数与 CI/AGENTS 不一致，注释与行为矛盾

- **证据**：`.pre-commit-config.yaml:13` 是 `cargo clippy --all-targets -- -D warnings`（**缺 `--all-features`**）；`ci.yml:43` 与 `AGENTS.md:28` 均为 `cargo clippy --all-targets --all-features -- -D warnings`；`.pre-commit-config.yaml:18-21` 注释写 "run it by hand when editing `cfg` attributes"，但 :22-27 的 `check-feature-matrix` hook 实际对 `types: [rust]` 自动执行。
- **影响**：本地 hook 不编译 `cli`/`content-*` 等 feature-gated 代码，开发者"pre-commit 通过"不等于 CI 通过；注释会让维护者误以为 feature matrix 只手动跑。
- **修复方向**：pre-commit 的 clippy 补 `--all-features`；把注释改为"自动执行，改动 cfg 时不必另跑"，或直接删除冗余说明。

#### M-23｜`stego_eval` 评估套件绑定本机绝对路径，且文档指向不存在的目录

- **证据**：
  - `scripts/stego_eval/README.md:24-40` 声明 venv 在 `temp/stego_eval/.venv/Scripts/python.exe`、工作目录 `C:\Home\Projects\strhide\temp\stego_eval`；实测 `scripts/stego_eval/.venv` 存在、`temp/stego_eval/.venv` **不存在**；
  - `scripts/stego_eval/run.bat:3-7` 优先调用 `F:\ai\torch\venv\Scripts\python.exe`；README 的 Tier 5 依赖 `F:\ai\downloads\aletheia-models`；
  - `git check-ignore -v` 输出 `.gitignore:106:*.pt`、`:108:.venv/`；`git ls-files scripts/stego_eval/models` 为空，7 个 `.pt` + 1 个 `.npz` 模型均不入库。
- **影响**：新克隆按 README 的命令直接失败；Tier 5 深度学习检测在任何非作者机器/CI 上不可复现；`scripts/stego_eval/.venv` 内 2447 个第三方 `.py` 还会污染全仓扫描与备份。
- **修复方向**：venv/模型一律用相对路径 + `requirements.txt`/下载脚本（带 SHA-256 校验），模型缺失时优雅降级并明确标注该层不可用；修正 README 与 `run.bat` 的路径。

#### M-24｜测试数据、基线与样本目录不入库，格式覆盖只能在本机复现

- **证据**：`.gitignore:102 temp*`、`:106 *.pt`、`:107 *.npz`、`:112 testdata/`；`git check-ignore -v testdata` 返回 `.gitignore:112:testdata/`；`ci.yml:48-54` 注释明确 `--all-targets` 不跑需要外部文件的 `#[ignore]d corpus sweep`；`AGENTS.md:68` 的 `temp/baseline/baseline.json` 落在 `temp*` 内。
- **影响**：`cargo test local_/heavy_ -- --ignored`（37 处 ignore 中的语料/压测）、`baseline_hash.py --check`、`test:e2e:real`（依赖被忽略的 `temp/jpgtest`）与 DL 评估在新克隆/CI 上无数据可用；字节级基线没有共享基准，"格式保持"回归只能靠作者本机。
- **严重程度**：中
- **修复方向**：将最小样本集入库（如 `!testdata/mini/` 例外或提供生成脚本 + 校验和），baseline 移到 `tests/fixtures/` 并纳入版本控制，e2e-real 在测试内自动生成样本；CI 至少跑一个不依赖外部大文件的语料子集。

---

### 3.3 低

| ID | 问题 | 证据 | 影响 / 修复方向 |
|---|---|---|---|
| L-1 | 两个转义函数 90% 重复 | `rust/src/core/fs.rs:138-199`（`escape_control_chars` / `escape_terminal_text`） | 只差一个谓词；合并为 `escape_with(predicate)` |
| L-2 ✅ 已修复（`cf9b2a7`） | `read_stream_box_header` 未拒绝 `size32 < 8` | **真实位置为 `rust/src/structure/adapters/isobmff.rs:657-696`**（草稿写的 :830-860 是另一段代码，已修正）；修复后在返回前统一拒绝 `size < header_len`，覆盖 3 个流式调用点（`:479`、`:815`、`:1178`） | 原本畸形 box 会推进 2-7 字节并被重复解析；现返回 `CorruptedData`，`read_meta_box_bytes` 走"无可靠 meta"分支，inject/strip 直接报错 |
| L-3 | HEVC 有 4 个无调用方的 v3 兼容包装器 | `rust/src/stego/hevc/engine.rs:1043`、`:1157`、`:1727`、`:2012`（`embed_hevc_with_info`、`embed_hevc_patches_with_factor`、`embed_hevc`、`extract_hevc`） | 项目尚未发布，AGENTS 明确无需旧格式兼容；这些 `pub fn` 只被 re-export，纯维护负担。删除或标 `#[deprecated]` |
| L-4 | `content-hevc` 单独构建时 `stego::heif` 是空模块 | `rust/src/stego/mod.rs:35-36` + `rust/src/stego/heif/mod.rs:8-14` | 文档/`cargo doc` 会展示一个不可用模块；把 `pub mod heif` 的门控改为 `content-heif-bridge` |
| L-5 | 前端 `ALGORITHMS` 常量无人使用 | `gui/src/lib/stego.ts:5` | 与后端算法列表重复，容易过期；删除，统一用 `getStegoAlgorithms` |
| L-6 | 36 处 `allow(dead_code)`、空 `AudioParams`/`HevcParams` | `rg` 统计；`rust/src/stego/params.rs` 中空结构体 | 条件编译导致的"保留代码"混在一起，建议区分"预留 API"与"死代码" |
| L-7 | CLI 读 `.strhide.toml`，GUI 完全不读 | `rust/src/core/config.rs`；GUI 无 config 逻辑 | 同一文件在 CLI/GUI 下默认算法/安全级别可能不同；至少文档说明，或让 GUI 提供"从配置导入" |
| L-8 | i18n 是进程级全局 Atomic | `rust/src/core/i18n/mod.rs:49-65`，GUI 通过 `set_ui_language_cmd` 全局切换（`commands/batch.rs:24`） | 当前单进程双前端没问题；若库被多租户服务复用会成为隐式状态。注释说明或改为显式 `RenderCtx` |
| L-9 | GUI 直接依赖库内部模块 | `gui/src-tauri/src/commands/structure.rs:8`、`stego.rs:12`、`:21` | 用 `strhide::structure::{...}`、`strhide::structure::sanitize_filename` 等公开 re-export，减少重构耦合 |
| L-10 | TS DTO 手写镜像 Rust serde 结构 | `gui/src/types/strhide.ts`、`types/ipc.ts` | 无 schema 校验/生成，字段重命名只能靠运行时发现。建议 `ts-rs`/`schemars` 或至少加 golden JSON 测试 |
| L-11 | 结构域 trailer 坐标解析在适配器里重复 | `rust/src/structure/adapters/mkv.rs:257-263`、`zip.rs:438-441`、`:461-465`；对照 `structure/envelope.rs` 的 `EnvelopeTrailer::read_from_tail` | 三处手写 24 字节布局，跳过 magic/CRC（在已定位后使用，安全上可接受）；建议提供"只取坐标"的共享函数 |

---

## 4. 重复与可复用性专项

| 重复项 | 位置 | 规模 | 建议 |
|---|---|---:|---|
| ISOBMFF box 解析 | `structure/adapters/isobmff.rs:631-713`；`stego/hevc/mp4_boxes.rs:823-860`；`stego/hevc/heif_boxes.rs`；`stego/heif/thumb_bridge.rs:1105-1145` | 4 套 | 内容域共用一套；结构域保留独立实现但共享测试向量 |
| 6 套 Options | `stego/options.rs:485/792/983/1145/1448/1594`，80 个 `with_*` | 1900 行 | 抽 `CommonOptions` 或宏 |
| 算法→tuning | `cli/helpers.rs:206-250` vs `gui/.../stego.rs:31-51` | 2 套，语义不同 | 下沉到库并统一错误 |
| PNG/音频信封引导 | `png/engine.rs:1988-2062` vs `:2252-2330`；`audio/core.rs:500` 附近 | 2 套/格式 | 抽 `open_header_bootstrap` |
| stress harness | `examples/*_stress.rs` | 行集合重合度 75.8%–89.6%（§8.4） | 抽 `examples/common` |
| 前端任务循环 | `HideStructureView.tsx:70`、`ExtractView.tsx:54`、`ScanView.tsx:99`、`StegoEmbedView.tsx:123` | 4 份 | `useSequentialJob` hook |
| 输出名去重 | `core/fs.rs:107`、`gui/src/lib/queue.ts:89`、`gui/.../stego.rs:418-437` | 3 份 | 公开后端唯一实现 |
| 终端转义 | `core/fs.rs:138` / `:174` | 2 份 | 合并 |
| 结构域 trailer 坐标 | `mkv.rs:257` / `zip.rs:438` / `zip.rs:461` | 3 份 | 共享 helper |
| 批量分发 | `commands/batch.rs` 的 `job_type` 与各单文件命令 | 2 套 | 删除未用批量层或反向由批量层调用单文件实现 |

---

## 5. 性能与脆弱性专项

### 5.1 性能

1. **重复 I/O**：GUI 容量探测（`io.rs:268-275` 全量 `read_carrier_file`）+ 嵌入（`io.rs:38-55` 再次全量读取）→ 每个文件至少 2 次完整读；`smart_extract` inspect + extract 同理（M-1、M-15）。
2. **重复解析**：PNG/JPEG 的 inspect 与 extract 各自解码一遍（M-1/M-3）；结构域 smart 路径对图片还会额外跑内容域 inspect。
3. **内存拷贝**：结构域读路径"解密 Vec + 解压 Vec"（`engine.rs:2020-2105`）；GUI 提取缓存 `clone` 整块 payload（M-18）；GUI 文本 payload 先 `into_buffered()` 再交给引擎（`commands/structure.rs:49-60`），多一次 NFC 归一化/拷贝。
4. **无 O(n²) 证据**：对主要热路径（PNG 行扫描、JPEG 系数、HEVC GOP、analysis 直方图）抽样未发现嵌套全量扫描；主要成本是上面的重复整文件处理，而非算法阶数。
5. **PBKDF2 放大**：每次写入 `derive_stealth_magics` + `derive_all` 两次 KDF；读取需要 magic + header salt 两轮。属于格式设计取舍，已在代码注释中说明，不在本次记为缺陷，但批量小文件时是主要 CPU 成本。

### 5.2 脆弱性

1. **无界读入后限长**：H-1；GUI 的 stego 命令也对 payload 文件直接 `std::fs::read`（`gui/.../stego.rs:166-174`），同样没有预检。
2. **解析器边界**：ISOBMFF 四处 size/header 规则不一致（M-4、L-2）；手写 PDF/ZIP/MKV/PE 无 fuzz（M-10）。
3. **整数转换**：抽查 `structure/adapters/*` 与 `mp4_boxes/heif_boxes`，`as usize` 前基本都有剩余长度检查；`analysis.rs` 的 `stride * height` 虽在 64 位平台安全，但仍依赖前面的 `checked_mul` 约束。未发现可直接触发的越界。
4. **panic 路径（已量化复核）**：`rust/src` 共 458 处 `.unwrap()`、388 处 `.expect(`、43 处 `panic!/unreachable!/todo!`、19 处 `unsafe`。但按文件拆分后，数量最多的 `stego/png/engine.rs` 121 处**全部位于第 2688 行 `#[cfg(test)]` 之后的内联测试区，生产区 0 处**——单看全库总数会明显高估生产风险。其余高位文件为 `structure/adapters/isobmff.rs`(63)、`core/commit.rs`(37)、`analysis.rs`(24)、`structure/engine.rs`(23)，需逐处区分测试辅助与生产解包；草稿记录的 `pe_codebits.rs:281` 属于"前置分支保证 `Some`"型解包。当前未发现可直接触发的越界，但这类隐式不变量建议改 `let Some(x) = ... else` 并加注释；GUI 后端另有 19 处（M-19）。
5. **错误吞噬**：`let _ = ...` 多用于清理/日志；`analysis` 对 DCT 解析失败走 `ok()` 静默降级，建议在 `notes` 中显式标注"该维度未分析"。
6. **并发/锁**：GUI 的 `lock().unwrap()`（M-19）与 `run_batch_job` 内再开线程（`core/batch.rs:120` 起）叠加时，线程数不由 `GuiState` 的准入控制约束。

### 5.3 已核实为"看起来可疑、实际合理"

- **`analysis` 自己解码 PNG/JPEG**：`analysis` feature 不依赖 `content-*`，复用 `stego` 解码器会破坏单域构建；这是有意的功能独立，不算重复缺陷。
- **`verify` 使用默认 cost model**：`png/engine.rs` 的 extract 只用 `cost_model` 做 trace 标记（`rg` 仅 2065 一处使用），恢复不依赖代价图，因此 verify 传默认模型不影响正确性。
- **`smart_extract` 内容域的 `is_encrypted` 用启发式**：`facade.rs:858-864` 有注释说明"内容域即使无密码也用默认 key 加密"，与结构域的 `read_res.is_encrypted` 语义不同但各自成立。
- **结构域 adapter 与 `formats::sniff` 两套检测**：`rust/tests/test_lifecycle/sniff.rs` 已对每个格式做一致性断言，属于有防线的双实现。
- **baseline 不在 CI**：`docs/TESTING.md` 说明 baseline 是本地可写基线，不入 CI 是有意取舍；风险是"字节稳定性无自动守护"，不是遗漏。

---

## 6. 测试与质量保障评估

### 6.1 现状

- Rust：1107 个 `#[test]`（`rust/src` 585 + `rust/tests` 522，本次实核），37 处 `#[ignore…]`（8 处裸 `#[ignore]` + 29 处带 reason）；`rust/tests` 62 文件 27918 行（含 lifecycle/perf/stress 辅助）；`testdata` 覆盖常见格式与边界样本，但**整体被 `.gitignore` 排除**（见 M-24）。
- GUI：13 个 unit（IPC 参数/错误映射，mock `invoke`）、5 个 cross（真实 CLI ↔ GUI 命令）、23 个 e2e（Playwright + mock Tauri IPC，验证 UI 布局/对比度/交互）、4 个 e2e-real（真实 `StrHideStudio.exe` + 本机 `temp/jpgtest` 样本）；共 17 个 ts 文件 1858 行。
- 工程脚本：一手 `.py` 37 个 / 9899 行（不含 `.venv` 内 2447 个第三方文件）；`import_lint.py`（本次实跑通过）、`check_feature_matrix.py`（矩阵有洞，M-9）、`baseline_hash.py`（基线文件在 `temp*`，不入库）。

### 6.2 缺口

1. **GUI 测试不进 CI**（M-8）；`gui-release.yml` 只在 tag 上构建，且**不复用** CI 质量门禁（M-21）。
2. **e2e-real 依赖被 gitignore 的 `temp/jpgtest` 样本**：换机器/新克隆无法运行，实际只有作者本机能跑。应在 `testdata/gui/` 放最小样本，或在测试里自动生成。
3. **没有 fuzz/property**（M-10）。
4. **测试组织**：`png/engine.rs` 内联测试 2131 行，`hevc/engine.rs` 内联测试约 956 行；单文件同时承载实现与测试，review/导航成本高。可拆 `tests/` 子模块（不改变 `cfg(test)` 语义）。
5. **缺少故障注入**：没有"写入中途磁盘满/只读/进程被杀"的测试；`core/commit.rs` 的原子性主要靠单测，缺少系统级验证。
6. **文档与 CI 的漂移（已核实行号）**：`docs/TESTING.md:115` 写"GUI 在真实 macOS/Linux 桌面上的行为依赖 CI runner，本地只覆盖 Windows"，但四个 workflow 均无 GUI 测试 job；`:68` 说明 e2e-real 需 CI 之外先本地构建，`:80` 明确 CI 不跑基线。建议对齐文档或补 job。
7. **测试资产不入库**（M-24）：`testdata/`、`*.pt`/`*.npz`、`temp*` 基线被忽略；37 处 ignore 中的语料/压测用例、baseline、e2e-real 在新克隆上无数据可用。
8. **评估套件与发布链路不可复现/无门禁**（M-21、M-23）：`stego_eval` 的 venv/模型/README 绑定本机绝对路径；GUI tag 可绕过全部质量检查发布正式版。

---

## 7. 改进优先级路线图

### 近期（优先做，收益/风险比最高）

1. **H-1**：`PayloadSource::File` 读前 `metadata` 限长；写入端加绝对上限，与读取端对称。
2. **H-2**：GUI 两处提取落盘统一走 facade 或补 `same_file(carrier, dest)` + `check_overwrite`；把 `reject_carrier_output` 提为公开工具。
3. **M-2**：统一内存准入（库内 `MemoryBudget` + GUI 申报），至少先把 `EMBED_PEAK_BYTES` 按格式区分，并让库的预算检查感知并发。
4. **M-9 + M-8**：补 feature 矩阵三行；加 GUI PR job（build + clippy + unit + cross）。
5. **M-7**：删除或接入 6 个死 IPC 命令；批量接口改强类型。
6. **M-21 / M-22**：`gui-release.yml` 接入 CI 质量门禁并改 `--frozen-lockfile`；pre-commit 的 clippy 补 `--all-features`。两者都是几行配置的改动，收益/成本比最高。
7. **M-23 / M-24**：修正 `stego_eval` 的路径与依赖说明，把最小样本与 baseline 纳入版本控制，让 ignore 语料和 e2e-real 在新克隆上可跑。

### 中期（结构性改善）

1. **M-3/M-4/M-11**：内容域共享信封引导与 ISOBMFF reader；KDF 阶梯单一实现。
2. **M-5/M-6**：Options 扁平化/宏化；算法映射下沉到库。
3. **M-12/M-16**：拆分 `write_core` 与 HEVC 超长函数；补 PNG/JPEG/audio 进度事件。
4. **M-10**：为 `inspect/extract/restore` 建 cargo-fuzz，接入 weekly CI。
5. **M-14/M-15/M-17**：前端 `useSequentialJob`、后端统一命名、stress harness 抽公共模块。
6. **L-3/L-4/L-5/L-6**：清理未发布的兼容层与死常量，减少 API/文档噪音。

---

## 8. 附：统计口径与取证记录（二次复核版）

### 8.1 一手源码规模

| 范围 | 文件数 | 行数 | 备注 |
|---|---:|---:|---|
| `rust/src` | 123 | 80096 | 21 个文件 >1000 行、50 个 >500 行；`analysis.rs`(2933) 是根目录单文件 |
| └ `rust/src/stego` | 58 | 45307 | 占库 56.6%，含 5260/5146 行两大引擎 |
| └ `rust/src/structure` | 26 | 16873 | |
| └ `rust/src/core` | 16 | 6881 | |
| └ `rust/src/cli` | 8 | 4667 | |
| └ `rust/src/formats` | 5 | 1283 | |
| `rust/tests` | 62 | 27918 | 6 个文件 >1000 行 |
| `rust/examples` | 19 | 7615 | |
| `gui/src` | 31 | 3800 | 无 >500 行文件 |
| `gui/src-tauri/src` | 9 | 2026 | |
| `gui/tests` | 17 | 1858 | |
| `scripts`（一手 .py/.go） | 38 | 10205 | 37 个 .py/9899 行 + 1 个 .go/306 行；**不含** `.venv` 内 2447 个第三方 .py |
| `docs`（.md） | 47 | 9588 | 另有 2 个 .svg/199 行 |

### 8.2 坏味道计数（`rust/src` 全文正则计数）

| 指标 | 数量 | 说明 |
|---|---:|---|
| `.unwrap()` / `.expect(` | 458 / 388 | 测试区占比高，见 §5.2.4 |
| `panic!`/`unreachable!`/`todo!` | 43 | 无 `todo!()` 实际调用 |
| `unsafe` | 19 | |
| `#[allow(` | 97 | 其中 `allow(dead_code)` 36、`allow(clippy::too_many_arguments)` 43 |
| `cfg(feature = …)` | 370 | 热点：content-jpeg 65、content-hevc 61、content-png 58、content-base 44、structure-base 40、content-audio 38、structure-pe 18、content-heif-bridge 15 |
| `.clone()` | 187 | |
| `#[doc(hidden)]` | 87 | |
| `pub fn with_*` | 151 | `stego/options.rs` 80、`structure/options.rs` 15 |
| `#[test]` | 1107 | `rust/src` 585 + `rust/tests` 522 |
| `#[ignore…]` | 37 | 8 处裸 `#[ignore]` + 29 处带 reason |

### 8.3 关键定位（本次抽查核实的行号）

- `rust/src/structure/engine.rs:434-447`（File 分支 `read_to_end` 无预检）、`:453-463`（Stdin 1 GiB 限流）、`:1122`（`into_buffered()`）、`:1131-1137`（读完才做限长）→ H-1。
- `rust/src/facade.rs:1181-1192`（`reject_carrier_output` + `check_overwrite` + `write_bytes_atomic`）对照 `gui/src-tauri/src/commands/stego.rs:259-260`、`:411-441`（两处写盘均无保护）→ H-2。
- `rust/src/structure/engine.rs:990`（`write_core`，539 行）；`rust/src/stego/hevc/engine.rs:1192`（`embed_hevc_patches_with_factor_v4`，510 行）；后者所在文件的 `allow(clippy::too_many_arguments)` 共 10 处，行号 1042/1068/1105/1130/1156/1191/2057/2194/2219/2359。
- `rust/src/stego/png/engine.rs:2688` 为 `#[cfg(test)]` 起点，全文件 121 处 unwrap/expect 均在其后，生产区 0 处。
- `scripts/check_feature_matrix.py:43-55` 共 11 行矩阵，无 `content-audio`/`content-heif-bridge`/`structure-pe` → M-9。
- 6 个疑似死 IPC 命令（`verify_carrier_cmd`、`scan_carrier_cmd`、`restore_structure_file_cmd`、`extract_stego_file_cmd`、`read_structure_file_cmd`、`run_batch_job_cmd`）在 `gui/**/*.ts*` 中的引用数全部为 0 → M-7。

### 8.4 取证命令与本次实际输出

- `cd rust && python ../scripts/import_lint.py`（使用 `C:\Home\Develop\venv`）：输出 `OK: all architectural boundaries intact (structure !-> stego, stego !-> structure, core !-> {formats, structure, stego, cli, analysis}, formats !-> {structure, stego, cli, analysis}, analysis !-> cli)`，`exit=0`。
- `git check-ignore -v`：`.gitignore:112:testdata/`、`.gitignore:108:.venv/ scripts/stego_eval/.venv`、`.gitignore:106:*.pt scripts/stego_eval/models/effnetb0_hill.pt`；`git ls-files scripts/stego_eval/models` 为空。
- workflow 文本核对：`ci.yml` 含 `workflow_call` 与 fmt/clippy/import_lint/test/rustdoc/doctest/feature-matrix（`ci.yml:39-74`）；`release.yml:17-22`、`crates.yml` 有 `uses: ./.github/workflows/ci.yml` + `needs: quality`；`gui-release.yml` 三者皆无，且无 `--frozen-lockfile`、无 GUI 测试命令。
- stress example 行集合重合度（去重后相同行 / 较小集合）：jpg↔png 89.2%、jpg↔hevc 76.6%、jpg↔audio 84.8%、png↔hevc 75.8%、png↔audio 84.6%、hevc↔audio 89.6%；硬编码绝对路径计数：jpg 2、png 2、hevc 1、audio 0（即 3/4 文件）。
- **未执行**：`cargo clippy`、`cargo test` 全量、`baseline_hash.py --check`、`check_feature_matrix.py`（耗时或写 `target/`）。这些在 CI 中是阻塞项（`ci.yml:39-74`），本报告只陈述配置事实，不声明本地编译结果。

---

## 9. 二次实证复核与修正记录

### 9.1 复核范围

本报告在同日草稿基础上做了二次复核；修订前的原始版本已按项目规则备份至 `temp/backups/CODE-REVIEW-20261111-*.md`。复核覆盖：§0 全部统计数字、H-1/H-2 源码片段、facade 保护、M-7 死命令、M-9 feature 矩阵、M-12 长函数行号、M-17 相似度与硬编码路径、四个 workflow、`.gitignore`、`.pre-commit-config.yaml`、`import_lint.py` 实跑、模型与测试数据的 git 跟踪状态。复核未启动全仓深度扫描或编译，所有数字可用 §8 的命令复现。

### 9.2 对草稿的修正

| 草稿表述 | 复核结果 | 处理 |
|---|---|---|
| "8 个 `#[ignore]`" | 8 处裸 `#[ignore]` + 29 处带 reason = 37 处 | 全文改为 37 处并注明口径 |
| "`clippy` 本次运行 0 warning" | 本次未重跑编译，无法主张 | 改为陈述 CI 门禁事实 `ci.yml:43` |
| stress 相似度 91.8% / 83.4% / 84.5% / 77.5% | 原口径未复现 | 改用可复现的行集合重合度 75.8%–89.6%，定性结论不变 |
| "四者都包含硬编码路径" | `audio_stress.rs` 为 0 处 | 更正为 3/4 文件 |
| "生产代码 unwrap 集中在 isobmff / pe_codebits" | 全量 846 处，但 `png/engine.rs` 121 处全在内联测试区 | §5.2.4 补充分布数据，避免过度归因 |
| `scripts` 统计出 2485 个 `.py` | 2447 个来自被忽略的 `scripts/stego_eval/.venv`；一手源码仍为 37 个 | 明确统计口径，不作为仓库污染缺陷 |

### 9.3 新增发现

M-21（GUI 发布流绕过 CI 质量门禁、`pnpm install` 未冻结 lockfile、action 版本浮动）、M-22（pre-commit 的 clippy 缺 `--all-features`，注释与 hook 行为矛盾）、M-23（`stego_eval` 的 README 指向不存在的 venv、run.bat 与 Tier 5 绑定 `F:\ai\...`、模型不入库）、M-24（`testdata/`、`*.pt`、`temp*` 基线不入库导致 ignore 语料/基线/e2e-real 无法在新克隆复现）；另补 §8 全量量化数据。

### 9.4 仍需注意的局限

- 草稿中未逐条复验的细粒度行号与部分按模块分布的细项计数（例如 `png/engine.rs:1988-2062`、`audio/core.rs:500`、`facade.rs:769-855`、`core/errors.rs:302-330`、`stego/io.rs:297-310`、`cli/helpers.rs:206-250`、L-1~L-11 的部分位置）沿用草稿记录；动手修改前请以当前源码为准。
- 本报告是静态审查：未做运行时剖析、未执行 fuzz、未验证 GUI 四套测试的实际通过率；用例数量按 `AGENTS.md` 与 `docs/TESTING.md` 引用。
- 未评审 `F:\Develop\github\strhide-vendor\` 的上游库源码；`rust/Cargo.toml:132-150` 对 iced-x86 overflow-checks 的规避仅按本项目配置陈述，不涉及上游实现正确性。

---

## 10. 修复实施记录（2026-11-11 第一批）

### 10.1 筛选原则与范围

按用户要求只实施"确定是 bug、改动小、收益大、风险低"的修复，存在多种方案时选最可靠最简单的；**不改 `.github/` 下的 CI**，且把语义上属于 CI 门禁的 `.pre-commit-config.yaml`、`scripts/check_feature_matrix.py` 一并留到后续。从 37 条问题（H×2 + M×24 + L×11）中选出 4 条，合计 4 个文件、77 行增 / 26 行删，分两批提交；其余为重构、大改、文档噪音或 CI 相关，未动。

### 10.2 已修复清单

| 问题 | 提交 | 最简可靠改法 | 兼容性 |
|---|---|---|---|
| H-1 | `cf9b2a7` | `PayloadSource::File` 用 `std::io::Read::take(&mut f, MAX_VERIFY_PAYLOAD_SIZE + 1)` 有界读取，超限返回 `PayloadTooLarge`；与 Stdin 分支同型 | 合法范围不变：写路径 `structure_payload_limit` 本就 clamp 到同一个 1 GiB 上限，只是把"先 OOM 后拒绝"改成"读前拒绝" |
| L-2 | `cf9b2a7` | `read_stream_box_header` 返回前统一拒绝 `size < header_len` | 合法 ISO BMFF 文件的 32-bit size 必 ≥ 8；`size32==0` 与 64-bit 分支原已保证 ≥ header_len，不受影响 |
| H-2 | `0e138bf` | `reject_carrier_output` 由 `pub(crate)` 提为 `pub`；GUI 两处提取写盘点前置调用（含 `smart_extract_impl` 计算出的最终 `target_file`） | 复用库内既有 `same_file`（符号链接/相对路径/Windows 大小写），与 CLI/facade 行为一致；不改 IPC 签名 |
| M-6 | `0e138bf` | `resolve_tuning` 返回 `Result`，未知算法返回 `General` 错误；`None`/空串/`auto`/音频别名仍为 `Auto`，与 `cli::helpers::stego_tuning` 对齐；两调用点加 `?`，新增单测 | 前端合法算法名不受影响；仅"拼错/未知名称"从静默 Auto 变为显式报错 |

### 10.3 验证结果（全部实跑）

| 检查 | 结果 |
|---|---|
| `cargo fmt --all -- --check`（`rust/`） | 通过 |
| `cargo clippy --all-targets --all-features -- -D warnings`（`rust/`） | 通过（首轮曾因 `File` 同时实现 `Read`/`Write` 导致 `by_ref()` 歧义，已改 UFCS 后通过） |
| `cargo clippy --manifest-path gui/src-tauri/Cargo.toml --all-targets --all-features -- -D warnings` | 通过 |
| `python scripts/import_lint.py` | `exit=0`，分层红线完好 |
| `cargo test --all-features --all-targets`（`rust/`） | `exit=0` |
| GUI 后端 lib 单测 | 12/12（含新增 `unknown_algorithm_is_rejected_not_silently_auto`） |
| `pnpm test:unit` / `pnpm test:cross` / `pnpm test:e2e` | 24/24、7/7、25/25 |
| `pnpm build`（`tsc && vite build`） | 通过 |
| 两批提交的 pre-commit hook（fmt / clippy / feature matrix） | 均通过 |

**未执行（如实标注）**：`pnpm test:e2e:real` 依赖 `gui/src-tauri/target/release/StrHideStudio.exe`（2026-11-09 的旧产物，未重建，跑了也验证不到本次后端改动）；`python scripts/baseline_hash.py --check` 需要先 `cargo build --release --all-features` 更新 CLI 二进制，本批为避免长时 LTO 构建未跑——本批改动只影响「>1 GiB payload」与「size32<8 畸形 box」两条边界，不改动合法样本的字节输出，但按 `AGENTS.md` 的"改动解析/注入路径必跑基线"约定，建议后续补跑；`local_/heavy_` ignored 语料依赖被 `.gitignore` 排除的 `testdata/`（M-24）。

### 10.4 未纳入本批的候选及理由

- **L-4**（`content-hevc` 单域下 `stego::heif` 空模块）：属 feature 门控改动，需重跑完整矩阵；收益低（仅 `cargo doc` 噪音），不是功能 bug。
- **M-8 / M-9 / M-21 / M-22**：CI 门禁相关（`.github/workflows/*.yml`、`scripts/check_feature_matrix.py`、`.pre-commit-config.yaml`），按用户要求留到最后。
- **M-19**（`lock().unwrap()`）：复核发现 `smart_extract` 的缓存锁已用 `poisoned.into_inner()` 处理，草稿描述部分过时；且属脆弱性而非确定 bug。
- **§5.2.1 GUI embed 的 `std::fs::read(&path)` 无界读入**：同型问题，但需先确认内容域 payload 上限再定阈值，留待单独处理。
- 其余 M-*/L-*：重构、死代码清理、文档/测试资产治理，改动面大或收益低。

### 10.5 报告准确性同步修正

- H-2 证据：补注两处命令函数开头**已有** `check_overwrite`，真正缺口是 `same_file` 护栏；
- L-2 位置：由错误的 `:830-860` 修正为 `isobmff.rs:657-696`；
- §0 新增第 6 条修复状态；4 个条目标题加 ✅ 与提交短哈希。
