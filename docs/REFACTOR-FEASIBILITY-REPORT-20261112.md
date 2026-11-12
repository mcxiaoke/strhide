# 大型源文件拆分与代码去重可行性/可靠性审视报告

**审视日期**：2026-11-12  
**基准版本**：Commit `717a74f`（完成 HEVC/Structure 引擎重构后）  
**关联记录**：`docs/CHANGES-20261111.md`, `docs/CODE-REVIEW-20261111-01.md`

---

## 一、 审视背景与评估标准

在 2026-11-11 的架构演进中，项目成功完成了对 `hevc/engine`（从 3854 行单体拆分为 10 个子模块）、`structure/engine`（拆分为 9 个生命周期模块）以及 `structure/adapters/isobmff`（拆分为 5 个专注模块）的彻底重构。该重构证明了以下模式的高可靠性：

1. **单向无环依赖（DAG）**：底层数据/布局 -> 扫描/载体 -> 容量探测 -> 嵌入/提取 -> 巡检/校验。
2. **零破坏对外路径**：通过父级 `mod.rs` 或 `engine.rs` 集中 `pub use` 重新导出，对外 API、测试路径与 CLI/GUI 调用 100% 保持稳定。
3. **验证闭环全绿**：全量测试（`cargo test --all-features --all-targets`）、特性矩阵（`check_feature_matrix.py`）、架构分层边界（`import_lint.py`）以及字节级回归基线（`baseline_hash.py --check`）全通。

基于这一既定标准，本报告对全项目中剩余的 8 处 1000 行以上的大单体文件及高频重复代码方案进行**可行性（Feasibility）**与**可靠性（Reliability）**的全面技术审视。

---

## 二、 逐项深度技术审视

### 1. `rust/src/stego/png/engine.rs`（1831 行）+ `engine_tests.rs`（2455 行）

#### 现状核对
* `png/codec.rs` 已独立承担底层 PNG 容器 chunk 解析与滤波（`decode_png`, `encode_png`, `RawImage`）。
* `png/engine.rs` 仍是一个 1831 行的巨大单体，且其测试文件 `engine_tests.rs` 膨胀至 2455 行。
* 外部引用点：`stego/png/mod.rs` 仅导出 `probe_png_capacity`, `embed_png`, `extract_png`；`stego/engine.rs` 引用了 `embed_png_with_stats`, `inspect_png`, `verify_png`。

#### 可行性分析（Feasibility：极高）
内部模块依赖关系天然正交，可无缝切分为 5 个子模块：
* `engine/layout.rs`（约 450 行）：`SlotPlan`, `ChannelMode`, `pipeline_budget`, `png_pre_salt`, `header_pool`, `header_layout`, `read_slot_bytes`。仅依赖 `codec` 与数学工具。
* `engine/capacity.rs`（约 200 行）：`probe_png_capacity`, `build_png_capacity_with_pools`, `body_payload_fits`。依赖 `layout`。
* `engine/extract.rs`（约 370 行）：`open_png_header`, `extract_png`, `extract_png_image`, `extract_png_with_keys`。依赖 `layout`。
* `engine/embed.rs`（约 480 行）：`embed_png`, `embed_png_with_stats`。依赖 `layout`, `capacity`。
* `engine/inspect.rs`（约 210 行）：`inspect_png`, `inspect_png_image`, `verify_png`。依赖 `extract`, `layout`。
* `engine/mod.rs`（约 120 行）：统一重新导出，对外路径不变。

#### 可靠性分析（Reliability：极高）
* **无状态泄露**：所有函数均为无副作用的纯函数或基于 `&mut RawImage` 的就地操作，不存在借用检查器（Borrow Checker）跨模块生命周期死锁风险。
* **基线保障**：PNG 隐写在 `baseline.json` 中拥有 6 组端到端黄金哈希用例。重构为纯代码搬移，字节级基线可 100% 保持一致。
* **测试治理**：可将 2455 行的 `engine_tests.rs` 拆解为针对各子模块的单元测试，大幅提高测试维护效率。

---

### 2. `rust/src/stego/jpeg/engine.rs`（1674 行）

#### 现状核对
* 前序 Commit `850a5a6` 已成功将容量探测剥离到 `jpeg/capacity.rs`。
* 目前 `engine.rs` 仍包含：载体分析与槽位（L77–L402）、嵌入主流程（L403–L1062，近 660 行）、提取（L1063–L1341）、巡检与校验（L1342–L1674）。

#### 可行性分析（Feasibility：极高）
已有 `capacity.rs` 成功剥离的先例，后续拆解顺畅：
* `engine/layout.rs`（约 330 行）：`CoverFrame`, `SlotPlan`, `BlockStateCache`, `plan_slots`, `apply_deltas`, `parity_carrier`, `ternary_legal`, `cover_digest`, `jpeg_pre_salt`。
* `engine/embed.rs`（约 660 行）：`EmbedContext`, `Attempt`, `embed_jpeg`, `embed_once`, `embed_slots`, `rollback`, `missing_symbol_stats`。
* `engine/extract.rs`（约 280 行）：`extract_jpeg`, `extract_jpeg_from`, `read_superblock`, `read_bits`。
* `engine/inspect.rs`（约 330 行）：`JpegInspection`, `inspect_jpeg_from`, `inspect_jpeg`, `verify_jpeg`。
* `engine/mod.rs`（约 100 行）：保留 `stego::jpeg::engine::*` 原有所有公开符号。

#### 可靠性分析（Reliability：极高）
* **DCT 状态一致性**：`apply_deltas` 与 `rollback` 仅操纵 `JpegCoefficients`，与布局规划清晰解耦。
* **分步回归**：JPEG 算法（UERD, J-UNIWARD, J-MIPOD）对系数改动极其敏感。`baseline.json` 中有 8 组 JPEG 用例，只要坚持“只移动不修改”原则，哈希绝对稳定。

---

### 3. `rust/src/stego/engine.rs`（1575 行 - 顶层调度器）

#### 现状核对
* 该文件定义了 `trait StegoEngine`，并集中实现了全部 8 个具体格式引擎。
* 特别包含：L464–L786（320 行）的 HEVC/HEIF 复杂通道分流逻辑（`should_try_bridge`, `hevc_embed`, `hevc_extract` 等）以及 250 行内联测试。
* 外部调用点极其简单明确：仅通过 `engine_for()`、`supported_carrier_list()` 及 `supported_formats()` 交互。

#### 可行性分析（Feasibility：高）
拆分为 `rust/src/stego/engine/` 目录：
* `mod.rs`（约 120 行）：定义 `StegoEngine` trait、全局 `ENGINES` 表及分发入口 `engine_for`。
* `image.rs`（约 220 行）：`PngEngine` 与 `JpegEngine`（受 `feature = "content-png"` 与 `content-jpeg` 保护）。
* `hevc.rs`（约 450 行）：HEVC 调度辅助函数（`hevc_*`、`should_try_bridge`）及 `HeifEngine`, `Mp4Engine`, `AnnexBEngine`, `MkvEngine`（受 `feature = "content-hevc"` 保护）。
* `audio.rs`（约 200 行）：`FlacEngine`, `WavEngine`（受 `feature = "content-audio"` 保护）。
* `tests.rs`（约 250 行）：集中存放格式注册表验证与退化测试。

#### 可靠性分析（Reliability：极高）
* **特性矩阵安全**：由于不同格式受独立的 Cargo Feature 门控（如 `--no-default-features --features content-png`），将不同格式引擎拆入独立子模块，使 `#[cfg(feature = "...")]` 更加清晰局部化，反向增强了特性矩阵编译的健壮性。
* **零运行时开销**：拆分仅重组编译单元，静态分发与虚表（vtable）结构无任何变化。

---

### 4. `rust/src/structure/adapters/pdf.rs`（1572 行）

#### 现状核对
* 与已成功目录化的 `isobmff/`（2487 行，拆分为 5 个子文件）相比，`pdf.rs` 仍为 1572 行单体。
* 包含：PDF 语法与交叉引用解析（640 行）、`PdfAdapter`（500 行）、内联测试（420 行）。
* 外部仅在 `structure/registry.rs` 中被引用为 `&PdfAdapter`。

#### 可行性分析（Feasibility：极高）
完全对标 `isobmff/` 模式，拆为 `rust/src/structure/adapters/pdf/`：
* `mod.rs`（约 520 行）：`PdfAdapter` 及其 `HostAdapter` 实现、`calc_prefix_len`、`try_locate_endstream`。
* `syntax.rs`（或 `tail.rs`，约 630 行）：`PdfTrailerInfo`, `PdfTailInfo`, `parse_pdf_trailer_info`, `read_xref_stream_dict`, `parse_pdf_tail_info`, 词法解析辅助。
* `tests.rs`（约 420 行）：内联测试独立迁移。

#### 可靠性分析（Reliability：极高）
* **接口绝对封闭**：`pdf` 模块对外唯一的公共类型是 `PdfAdapter`，没有任何私有底层方法被外部泄漏，重构影响面严格限定在该目录内部。
* **测试完备**：该模块自带 420 行覆盖充分的边缘用例（增量更新、10位对象号、平衡字典等），拆分后立即可用测试进行零回归验证。

---

### 5. `rust/src/structure/adapters/pe*.rs`（总计约 2930 行）

#### 现状核对
* `pe_codebits.rs`（1140 行，含 415 行测试）
* `pe.rs`（836 行）
* `pe_layout.rs`（560 行）
* `pe_slack.rs`（394 行）
* 目前以松散平铺的方式放在 `structure/adapters/` 目录下，造成根目录命名污染。

#### 可行性分析（Feasibility：高）
聚合为 `rust/src/structure/adapters/pe/` 目录：
* `mod.rs`（承接 `pe.rs`，剥离出公共 Adapter 入口）
* `codebits.rs`（承接 `pe_codebits.rs` 核心指令替换与间隙逻辑，约 720 行）
* `layout.rs`（承接 `pe_layout.rs`）
* `slack.rs`（承接 `pe_slack.rs`）
* `tests.rs`（集中收纳 415 行单元测试）

#### 可靠性分析（Reliability：高）
* 在 `adapters/mod.rs` 中保持 `pub mod pe; pub use pe::PeAdapter;`，上层 `registry.rs` 无感知。
* 唯一需要注意的是 `pe_codebits.rs` 对 `crate::pe_layout` 的内部引用需平滑转为 `super::layout`。

---

### 6. `rust/src/stego/audio/` 模块（`flac/mod.rs` 1683 行 + `core.rs` 1227 行）

#### 现状核对
* `flac/mod.rs`：内含手写 MD5 算法（L1293–L1465，约 170 行）、残差载体 `FlacCarrier` 与 `CompSlot`、212 行测试。
* `audio/core.rs`：集中了通用音频隐写引擎的 `capacity_info`, `embed`, `extract`, `probe`, `inspect`, `verify` 全流程。

#### 可行性分析（Feasibility：极高）
* **FLAC 模块精简**：
  * 将 RFC 1321 手写 MD5 及测试独立移至 `flac/md5.rs`（纯算法，零依赖）。
  * 将 `FlacCarrier`, `FlacSlot`, `CompSlot`, `FlacTail` 移至 `flac/carrier.rs`。
  * 将内联测试移至 `flac/tests.rs`。
  * `flac/mod.rs` 缩减至约 350 行，专注流解析与调度。
* **Core 模块解耦**：
  * `audio/core.rs` 拆解为 `audio/engine/`：`slot.rs`, `capacity.rs`, `header.rs`, `embed.rs`, `extract.rs`, `inspect.rs`。

#### 可靠性分析（Reliability：高）
* **校验安全**：FLAC 对 `STREAMINFO` MD5 的一致性要求极高，写入后会立即重新全量解码校验 PCM MD5。`md5.rs` 抽离后自带独立向量测试，逻辑安全可控。

---

### 7. `rust/src/core/crypto.rs`（1199 行）

#### 现状核对
* 核心职责为加解密（ChaCha20-Poly1305, AES-GCM）与 KDF（PBKDF2/IKM）。
* 但 L668–L780（120 行）包含了基于 Zstd/Deflate 的**数据流压缩与可压缩性探测**（`compress_stream`, `probe_compressibility`, `decompress_stream`）。
* 内联单元测试占据 260 行。

#### 可行性分析（Feasibility：极高）
* 新建 `rust/src/core/compress.rs`，承接压缩与解压流逻辑及相关测试。
* 在 `core/mod.rs` 与 `crypto.rs` 中保留公共 re-export：
  `pub use super::compress::{compress_stream, decompress_stream, probe_compressibility};`
* `structure/engine/write.rs` 和 `read.rs` 中的调用无须变更任何路径。

#### 可靠性分析（Reliability：极高）
* 职责边界完全清晰（Cryptography vs Compression），符合单一职责原则。
* 零跨层依赖风险（`import_lint.py` 规定 `core` 不得依赖上层，压缩仅依赖标准库及第三方库 `flate2`/`zstd`）。

---

### 8. `rust/src/stego/options.rs`（1587 行）与 `facade.rs`（1223 行）参数去重

#### 现状核对
* 存在 8 个 Options 结构体（`EmbedOptions`, `ProbeOptions`, `ExtractOptions`, `BridgeOptions`, `InspectOptions`, `VerifyOptions`, `DualOptions`, `SmartExtractOptions`）。
* 每个结构体均机械地重复实现以下 Builder 样板（累计 500+ 行）：
  ```rust
  pub fn with_password(mut self, password: &'a str) -> Self { ... }
  pub fn with_password_option(mut self, password: Option<&'a str>) -> Self { ... }
  pub fn with_key(mut self, key: &'a [u8; 32]) -> Self { ... }
  pub fn with_key_option(mut self, key: Option<&'a [u8; 32]>) -> Self { ... }
  pub fn with_domain(mut self, domain: &'a str) -> Self { ... }
  pub fn with_domain_option(mut self, domain: Option<&'a str>) -> Self { ... }
  pub fn with_control(mut self, control: Control<'a>) -> Self { ... }
  pub fn with_pool(mut self, pool: Arc<rayon::ThreadPool>) -> Self { ... }
  pub fn with_pool_option(mut self, pool: Option<Arc<rayon::ThreadPool>>) -> Self { ... }
  ```

#### 可行性分析（Feasibility：高）
* **方案 A（声明宏 Macro）**：定义内部宏 `impl_auth_options!(TargetStruct<'a>)` 与 `impl_exec_options!(TargetStruct<'a>)`，直接在目标结构体上展开方法。
  * *优点*：100% 保持结构体的字段布局、ABI 与方法签名，不改变公有 API 调用形态。
* **方案 B（组合式 Composition）**：提取 `CommonOptions<'a>` 结构体并嵌套。
  * *缺点*：字段直接访问会产生破坏性变更（例如 `opts.password` 变成 `opts.common.password`），需额外保留访问器方法。
* **方案推荐**：采用**声明宏或局部细粒度子模块化**（将 `options.rs` 按生命周期拆为 `options/embed.rs`, `options/probe.rs` 等），优先用宏消除机械样板代码。

#### 可靠性分析（Reliability：极高）
宏生成方式为纯文本语法展开，不改变任何类型签名，能确保所有现有上层代码及外部绑定零破坏。

---

## 三、 审视结论与实施路线图推荐

经过对代码调用链、模块边界、生命周期及编译特性的严密核对，**上述 8 个拆分方案在技术上全部完全可行，且均具备极高可靠性与明确的验证基准。**

为保持开发节奏平稳、规避大面积合并冲突，推荐按以下三期优先级有序推进：

### 第一阶段（P1 极高收益，承接昨日工作）
1. **`stego/png/engine.rs`** 拆分为 `png/engine/`（`embed`, `extract`, `inspect`, `capacity`, `layout`），并将 `engine_tests.rs` 分离。
2. **`stego/jpeg/engine.rs`** 拆分为 `jpeg/engine/`（`embed`, `extract`, `inspect`, `layout`），完成昨日未竟拆分。
3. **`stego/engine.rs`** 拆分为 `stego/engine/`（`image.rs`, `hevc.rs`, `audio.rs`, `traits.rs`, `tests.rs`），彻底隔离各引擎胶水与桥接逻辑。

### 第二阶段（P2 结构层与音频层治理）
4. **`structure/adapters/pdf.rs`** 拆分为 `adapters/pdf/`（`mod.rs`, `syntax.rs`, `tests.rs`）。
5. **`structure/adapters/pe*.rs`** 聚合收敛为 `adapters/pe/` 目录。
6. **`stego/audio/flac/mod.rs`** 剥离独立 `flac/md5.rs` 与载体/测试子模块。

### 第三阶段（P3 关注点解耦与样板去重）
7. **`core/crypto.rs`** 剥离流压缩至 `core/compress.rs`，分离单元测试。
8. **`stego/options.rs`** 运用宏消除 500+ 行重复 Builder 样板代码。

---

## 四、 质量与回归验收基准（每次实施必跑）

每个阶段实施完毕后，必须严格遵循以下验收流程以确保零缺陷：

```bash
cd rust
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --all-targets
cargo test local_ --all-features -- --ignored
python scripts/import_lint.py
python scripts/check_feature_matrix.py
python scripts/baseline_hash.py --check
```
