# StrHide (v1.5.0) 全面深度代码与架构审查报告

## 1. 审查概述与范围

本报告基于对 `strhidecode.zip` 源码包的全量静态精读与交叉比对完成，覆盖以下全部范围：

- **架构与规范文档**：`AGENTS.md`、`docs/api/ARCHITECTURE.md`、`docs/api/STEGO-API.md`、`docs/api/WIRE_SPEC.md`、`docs/smart_file_data_hiding_design.md`、`docs/CHANGES-20261102.md`、`docs/CHANGES-20261103.md`。
- **核心库 (`rust/src/`)**：
  - 门面与入口：`lib.rs`、`facade.rs`、`main.rs`、`cli_i18n.rs`
  - 基础层 (`core/`)：`mod.rs`、`crypto.rs`、`errors.rs`、`params.rs`、`commit.rs`、`batch.rs`、`control.rs`、`payload.rs`、`fs.rs`、`pipeline.rs`、`config.rs`、`media.rs`、`i18n/*`
  - 格式探测层 (`formats/`)：`mod.rs`、`sniff.rs`、`capability.rs`、`annexb.rs`、`jpeg_segments.rs`
  - 结构域 (`structure/`)：`mod.rs`、`options.rs`、`params.rs`、`registry.rs`、`rejection.rs`、`envelope.rs`、`engine.rs` 及 `adapters/` 下全部 19 个模块（PNG、JPEG、RIFF/WebP/WAV、ISOBMFF/MP4/HEIF、EBML/MKV、ZIP、PDF、PE/Layout/Slack/Codebits、EOF、IO）
  - 内容域 (`stego/`)：`mod.rs`、`params.rs`、`options.rs`、`registry.rs`、`engine.rs`、`io.rs`、`format.rs`、`header.rs`、`envelope.rs`、`prng.rs`、`traits.rs`、`coding.rs`、`coding/stc.rs`、`cost_calibration.rs`、`spatial_variance.rs`、`wavelet.rs`、`png/*`（HILL / S-UNIWARD / MiPOD）、`jpeg/*`（UERD / J-UNIWARD / J-MiPOD / Precover / V3 Layout / DHT）、`heif/thumb_bridge.rs`、`hevc/*`（Annex-B / MP4 / MKV / HEIF CABAC Scheme C）、`audio/*`（WAV PCM & FLAC LPC Residual）
  - 隐写分析域 (`analysis/`)：`analysis.rs`、`analysis/calibration.rs`
  - 命令行层 (`cli/`)：`mod.rs`、`args.rs`、`helpers.rs`、`render.rs`、`cmd_structure.rs`、`cmd_stego.rs`、`cmd_diag.rs`
- **桌面端 GUI 后端 (`gui/src-tauri/src/`)**：`lib.rs`、`state.rs`、`logger.rs`、`commands/mod.rs`、`commands/stego.rs`、`commands/structure.rs`、`commands/diag.rs`、`commands/batch.rs`。
- **架构守卫脚本**：`scripts/import_lint.py`。

本报告严格遵循**零臆测、零伪造引用**原则：所有结论均附带真实存在的文件路径、精确行号、原样代码引用（Verbatim Code Snippets）、根因推导与可直接落地的修复方案。

---

## 2. 问题全景汇总表

本审查共定位 **35 项真实存在的代码与架构问题**（含 **6 项 P0 严重级**、**13 项 P1 高危级**、**12 项 P2 中危级**、**4 项 P3 低危/规范级**）：

| 编号 | 维度 | 严重度 | 问题简述 | 核心定位 (`文件:行号`) |
| :--- | :--- | :---: | :--- | :--- |
| **ARCH-01** | 1. 架构设计 | **P2** | `core/params.rs` 违反 `core` 层“零领域耦合”契约，残留结构域魔数与 HEVC 视频预算参数 | `rust/src/core/params.rs:26-70, 227-350` |
| **ARCH-02** | 1. 架构设计 | **P2** | `core::pipeline::for_each_carrier` 混入终端打印与全局语言状态，与 `core::batch` 职责重复 | `rust/src/core/pipeline.rs:30-65` |
| **ARCH-03** | 1. 架构设计 | **P2** | 架构守卫 `scripts/import_lint.py` 存在原始字符串/字符字面量解析缺陷，且漏检 `super::` 与 `formats`/`analysis` | `scripts/import_lint.py:19-67, 100-132` |
| **ARCH-04** | 1. 架构设计 | **P2** | 权威规范文档（`WIRE_SPEC.md`、`ARCHITECTURE.md`、`smart_file_data_hiding_design.md`）与代码实现多处失步 | `docs/api/WIRE_SPEC.md:493, 642, 828, 869-880` |
| **API-01** | 2. 库接口 | **P2** | `StrategyChoice::from<&str>` 将未知/拼写错误的策略名静默降级为 `Auto`，缺少可失败的 `FromStr` | `rust/src/structure/options.rs:35-46` |
| **API-02** | 2. 库接口 | **P2** | `StegoTuning` 缺少 `Audio` 分支，且 `MediaInfo` 无音频采样率/声道/位深字段，导致 WAV/FLAC 元数据常に为 `None` | `rust/src/stego/options.rs:259-287`, `core/media.rs:16-77` |
| **API-03** | 2. 库接口 | **P2** | 能力表与注册表错误宣称 `avif` / `webm` 支持 `HevcCabac`，`FileFormat::Pe` 漏掉 `sys` / `scr`，报错文案漏列 `MKV`/`WAV`/`FLAC` | `rust/src/stego/registry.rs:116-129`, `formats/capability.rs:130-216` |
| **FN-01** | 3. 函数和参数 | **P0** | **`ExtractParams::max_payload_bytes`（默认 32 MiB 防解压炸弹上限）在全部 7 个内容域引擎中均未生效（完全死配置）** | `rust/src/stego/params.rs:272`, `stego/engine.rs:215-656`, `jpeg/engine.rs:1155` |
| **FN-02** | 3. 函数和参数 | **P1** | 结构域与内容域对空密码 `Some("")` 的语义处理完全相反，导致双域调用行为不一致 | `rust/src/structure/engine.rs:981-986`, `stego/options.rs:620-627` |
| **FN-03** | 3. 函数和参数 | **P2** | `FeatureWord` 位打包 `exclusion_permille` 掩码宽度错误（`low64 << 51` 仅剩 13 bit 却按 `0xFFFF` 16 bit 掩码） | `rust/src/stego/header.rs:232, 293` |
| **FN-04** | 3. 函数和参数 | **P1** | CLI `--auto` 跨界回退在多文件批处理（`-o <DIR>`）下丢失批处理上下文，引发输出文件名冲突或覆盖失败 | `rust/src/cli/cmd_structure.rs:333-349`, `cmd_stego.rs:613-621` |
| **QUAL-01** | 4. 代码质量 | **P1** | PNG 与 JPEG 引擎中空函数 `trace(&format!(...))` 在 Release 构建下无条件执行堆内存格式化分配 | `rust/src/stego/png/engine.rs:662, 859-864`, `jpeg/engine.rs:200-205, 729` |
| **QUAL-02** | 4. 代码质量 | **P2** | `thumb_bridge.rs` 中 `BridgeTargetKind::DirectSpatial` 永远不可达，却保留 5 处死分支分发至 `png::*` | `rust/src/stego/heif/thumb_bridge.rs:28-29, 122-333, 627` |
| **QUAL-03** | 4. 代码质量 | **P3** | HEVC `header_bytes`（24 vs 32 vs 40 vs 48）契约混乱、`provisional_sign_flip_cost` 死函数及 FLAC 注释自相矛盾 | `rust/src/stego/format.rs:205, 223`, `hevc/engine.rs:265`, `flac/mod.rs:198-204` |
| **QUAL-04** | 4. 代码质量 | **P3** | `cli_i18n.rs` 漏译多个 CLI 参数（`--auto`、`--no-filename`、`--seed`、`--fail-on`）及子程序 `after_help` | `rust/src/cli_i18n.rs:57-179`, `analysis.rs:120, 139` |
| **PERF-01** | 5. 算法性能 | **P1** | 结构域 `verify_carrier` / `inspect_carrier` 单次调用重复执行 **6~7 次 100,000 轮 PBKDF2**（每次浪费数百毫秒） | `rust/src/structure/envelope.rs:491-518`, `structure/engine.rs:1399, 2412-2538` |
| **PERF-02** | 5. 算法性能 | **P1** | FLAC 嵌入/提取/验证单次操作将整文件完整解码 **3~5 次**，且 WAV/FLAC 只读操作全量克隆数百 MB 载体缓冲 | `rust/src/stego/audio/mod.rs:71-319, 394-449`, `flac/mod.rs:401-544` |
| **PERF-03** | 5. 算法性能 | **P1** | 音频失真代价 `CostParams::cost_at` 对每个槽位重复扫描 33 邻域并从字节流解码样本，未做前缀和或预解码 | `rust/src/stego/audio/cost.rs:96-128`, `audio/core.rs:713` |
| **PERF-04** | 5. 算法性能 | **P1** | MKV 内容域嵌入未接入 `embed_hevc_patches` 补丁式提交，导致 GB 级 MKV 全量读入内存并重复扫描两次 | `rust/src/stego/io.rs:59-62`, `stego/hevc/mkv_boxes.rs:603-636` |
| **PERF-05** | 5. 算法性能 | **P2** | `compress_stream` 在内存中全量缓冲压缩流；`read_core` 先全量解密进 `Vec<u8>` 后才检查 `MAX_VERIFY_PAYLOAD_SIZE` | `rust/src/core/crypto.rs:537`, `structure/engine.rs:1637-1653` |
| **REL-01** | 6. 可靠性与稳定性 | **P0** | **GUI `smart_extract_impl` 路径穿越漏洞（Arbitrary File Overwrite）：未调用 `sanitize_filename` 直接 `dest.join(&filename)`** | `gui/src-tauri/src/commands/stego.rs:375-428`, `structure/engine.rs:1734` |
| **REL-02** | 6. 可靠性与稳定性 | **P0** | **PNG `Structure -> Content` 双域共存后：`stealth` 信封无法定位、`verify_carrier` 坐标校验失败并在 Debug 下 Panic、`restore` 按旧偏移截断损坏 PNG 载体** | `rust/src/structure/adapters/png.rs:268-280`, `structure/engine.rs:2458, 2499`, `adapters/mod.rs:231-244` |
| **REL-03** | 6. 可靠性与稳定性 | **P1** | `commit_carrier_patches` 在源载体只读（Read-Only）时，即便指定 `-o <新路径>` 也会因 `fs::copy` 复制只读权限位而报 `PermissionDenied` | `rust/src/core/commit.rs:229-233` |
| **REL-04** | 6. 可靠性与稳定性 | **P2** | `preflight_batch` 路径碰撞检查对输入载体做 `canonicalize` 而对输出目标不做，且未检测“输出目标覆盖同批另一输入载体” | `rust/src/core/pipeline.rs:187-233` |
| **REL-05** | 6. 可靠性与稳定性 | **P2** | GUI `CachedExtract` 缓存键遗漏 `domain` 与 `prefer`，导致双域载体切换提取域时返回错误的缓存载荷；`extract_stego_file_cmd` 误报 `is_encrypted` | `gui/src-tauri/src/state.rs:16-21`, `commands/stego.rs:268-269, 337` |
| **REL-06** | 6. 可靠性与稳定性 | **P2** | GUI `run_batch_job_cmd` 丢弃进度通道 `_ctrl` 导致批量任务零进度回报，且批量 `restore` 硬编码强制开启备份 | `gui/src-tauri/src/commands/batch.rs:52, 91-98`, `core/batch.rs:146` |
| **REL-07** | 6. 可靠性与稳定性 | **P3** | `inspect_hevc_mp4_file` 将 `u64` 文件长度与 Box 长度直接 `as usize`，在 32 位目标下存在截断风险 | `rust/src/stego/hevc/engine.rs:1921, 1951` |
| **LOGIC-01** | 7. 算法和业务逻辑 | **P0** | **HEVC `embed_hevc_patches_with_factor` 因 `StopCondition::TargetSlots` 提前停止，基于截断的 `PoolProfile` 计算容量并执行 `enforce_safety`，导致 `--enforce-safety` 误杀合法载荷且返回的 `StegoCapacityInfo` 严重失真** | `rust/src/stego/hevc/engine.rs:864-881` |
| **LOGIC-02** | 7. 算法和业务逻辑 | **P0** | **`pe_codebits` 的 `ChannelHeader` 掩码完全由明文 `magic` 派生（无密钥 HKDF），任何无密码观察者均可直接解盲恢复 `version`/`flags`/`ube_len`/`slack_off`，彻底击穿 Stealth 盲化契约** | `rust/src/structure/adapters/pe_codebits.rs:369-427, 507`, `core/crypto.rs:238-244` |
| **LOGIC-03** | 7. 算法和业务逻辑 | **P0** | **PDF 适配器三大缺陷：(1) `read_xref_stream_dict` 遇嵌套字典 `>>` 提前截断导致漏检 `/Encrypt` 和 `/Root`；(2) 向 PDF 1.5+ XRef Stream 文档追加经典 `xref` 表违反 ISO 32000-1 §7.5.8.4；(3) `eof` 模式 >1 MiB 文件漏做增量更新** | `rust/src/structure/adapters/pdf.rs:108, 182-186, 653-671` |
| **LOGIC-04** | 7. 算法和业务逻辑 | **P1** | `EnvelopeHeader::unpack_with_secrets` 在检查明文 `FLAG_ENCRYPTED` 头之前先用默认掩码解盲，且允许 `strategy_id == 0`，存在约 $1/36,400$ 概率将合法自定义密码信封误判为未加密信封 | `rust/src/structure/envelope.rs:491-518` |
| **LOGIC-05** | 7. 算法和业务逻辑 | **P1** | WAV / WebP / MKV / >1 MiB PDF 的 `verify_structure`（Level 1）硬编码传入 `None` 魔数，导致所有 `--stealth` 或私有方言的 `eof` 载体 Level 1 校验必败 | `rust/src/structure/adapters/riff.rs:237`, `mkv.rs:161`, `pdf.rs:108` |
| **LOGIC-06** | 7. 算法和业务逻辑 | **P1** | HEIF `item_hidden` 在 `0 < base_offset < m_end` 且 `base_offset + extent_offset >= m_end` 时漏移位 `delta_meta`，损坏 `mdat` 内 item 偏移 | `rust/src/structure/adapters/isobmff.rs:955-979, 1293-1316` |
| **LOGIC-07** | 7. 算法和业务逻辑 | **P1** | PNG 内容域：(1) `decode_png` 从不校验任何 Chunk CRC-32 且 `encode_png` 重算 CRC 洗白损坏块；(2) `SlotPlan::build` 在 `ChannelMode::Rgb` 下仅用 G 通道过滤 `8..=247`，误杀 R/B 通道合法槽位 | `rust/src/stego/png/engine.rs:259, 743, 1077-1083` |
| **LOGIC-08** | 7. 算法和业务逻辑 | **P2** | JPEG `formats/jpeg_segments.rs` 未跳过连续 `0xFF` 填充字节；PNG 拼接流在 `find_iend_offset` 与 `locate`/`scan` 间行为分裂；`rs_difference` 循环边界 `0..rows - 3` 产生 Off-by-One 漏算最后一行一列窗口 | `rust/src/formats/jpeg_segments.rs:47-63`, `structure/adapters/png.rs:56-80, 288`, `analysis.rs:705, 1924-1925` |

---

## 3. 维度一：架构设计（Architecture Design & Spec Consistency）

### [ARCH-01] `core/params.rs` 违反 `core` 层“零领域耦合”契约，残留结构域魔数与 HEVC 视频预算参数
- **严重度**：P2（中危 / 架构分层违背）
- **定位**：
  - `rust/src/core/mod.rs:1-4`
  - `rust/src/core/params.rs:3-17, 26-70, 227-350`
- **代码实证**：
  `rust/src/core/mod.rs:1-4` 明确声明：
  ```rust
  //! Layer 0: shared foundation used by every other layer.
  //!
  //! `core` holds nothing format-specific: errors, cryptography, atomic file
  //! commit, payload representation, cancellation/progress, and CLI config/i18n.
  ```
  `rust/src/core/params.rs:3-10` 注释也声明：
  ```rust
  //! Exactly one type lives here: [`LocalParams`], the runtime operational budget
  //! (PBKDF2 iteration floor, capacity ceiling, video frame budget). Wire-format
  //! identity — magic bytes, key-derivation domain, default secret — moved to the
  //! domain crates that actually interpret it...
  //! Splitting it this way keeps `core`-level primitives free of any format
  //! dependency...
  ```
  但实际上，`rust/src/core/params.rs` 仍然定义了：
  1. 结构域专属的二进制魔数常量与 `MagicPair`（第 `26-70` 行）：
     ```rust
     pub const STANDARD_HEADER_MAGIC: [u8; 8] = [0xb7, 0x54, 0x2c, 0x82, 0x7e, 0x31, 0x1d, 0x6e];
     pub const STANDARD_TRAILER_MAGIC: [u8; 4] = [0x78, 0xe6, 0x66, 0xd2];
     pub const STEALTH_DOMAIN: &[u8] = b"strhide-stealth-magic-v2";
     pub struct MagicPair {
         pub header: [u8; 8],
         pub trailer: [u8; 4],
     }
     ```
  2. 内容域专属的 `SafetyLevel`（含 `max_bpp()` 图像像素/DCT 载荷率）以及强耦合 HEVC B 帧/参考帧 CABAC 预算的 `VideoBudget`（第 `227-350` 行）：
     ```rust
     pub struct VideoBudget {
         pub non_ref_fraction: f64,
         pub ref_flips_per_picture: usize,
     }
     ```
- **问题分析**：
  Stage 4 架构重构将 `StructureProfile` 迁入 `structure/params.rs`、将 `StegoDialect` 迁入 `stego/params.rs`，但把结构域魔数与内容域/HEVC 预算留在了 `core/params.rs`，随后又在 `structure/params.rs:23` 和 `stego/params.rs:14` 中 `pub use crate::core::params::*` 重导出。这导致 `core` 层感知具体隐写域的协议魔数和 HEVC 帧类型（non-ref vs ref picture），破坏了模块注释所承诺的“仅包含 `LocalParams`”。
- **修复建议**：
  将 `STANDARD_HEADER_MAGIC`、`STANDARD_TRAILER_MAGIC`、`STEALTH_DOMAIN`、`MagicPair` 迁回 `rust/src/structure/params.rs`；将 `SafetyLevel` 与 `VideoBudget` 迁入 `rust/src/stego/params.rs`（或在 `core::params` 保持顶层 `pub use` 别名以兼容外部路径）。

---

### [ARCH-02] `core::pipeline::for_each_carrier` 混入终端打印与全局语言状态，与 `core::batch` 职责重复
- **严重度**：P2（中危 / 分层职责污染）
- **定位**：`rust/src/core/pipeline.rs:30-65` vs `rust/src/core/batch.rs:84-169`
- **代码实证**：
  ```rust
  // rust/src/core/pipeline.rs:30-65
  pub fn for_each_carrier<F>(
      carriers: &[PathBuf],
      quiet: bool,
      mut op: F,
  ) -> Result<(), StrHideError>
  where
      F: FnMut(&Path) -> Result<(), StrHideError>,
  {
      let total = carriers.len();
      let is_batch = total > 1;
      let mut failed = 0usize;
      for (idx, carrier) in carriers.iter().enumerate() {
          if is_batch && !quiet {
              println!("=== [{}/{}] {} ===", idx + 1, total, carrier.display());
          }
          if let Err(e) = op(carrier) {
              failed += 1;
              if is_batch {
                  eprintln!(
                      "{}",
                      t!(Msg::ErrBatchItemFailed, path = carrier.display(), err = e)
                  );
              } else {
                  return Err(e);
              }
          }
      }
      ...
  ```
- **问题分析**：
  1. `core` 层作为无 UI 的底层核心库（供 GUI、SDK、CLI 共用），在 `core::pipeline::for_each_carrier` 中直接写死 `println!`、`eprintln!` 并读取全局 `i18n::lang()`（通过 `t!(...)` 宏）。
  2. `core` 层同时存在两套批处理原语：一套是面向纯库/GUI 的并行有界批处理 `core::batch::run_batch`（支持 `CancelToken`、`RenderCtx`、结构化 `BatchOutcome`），另一套是仅服务于 CLI 的串行打印循环 `core::pipeline::for_each_carrier`。
- **修复建议**：
  将 `for_each_carrier` 移至 `rust/src/cli/helpers.rs`（或让其接收回调/事件钩子而非在 `core` 内直接 `println!`/`eprintln!`），保持 `core::pipeline` 仅保留纯函数式的路径解析与批处理预检（`resolve_carrier_target`、`check_overwrite`、`preflight_batch`）。

---

### [ARCH-03] 架构守卫 `scripts/import_lint.py` 存在词法解析缺陷与层间检查盲区
- **严重度**：P2（中危 / 架构守护盲区）
- **定位**：`scripts/import_lint.py:19-67, 100-132`
- **代码实证**：
  ```python
  # scripts/import_lint.py:19-31, 56-65, 100-108
  RULES = {
      "structure": ("stego", "cli", "analysis"),
      "stego": ("structure", "cli", "analysis"),
      "core": ("structure", "stego", "cli", "analysis", "formats"),
  }
  ...
  elif ch == '"':
      out.append(" ")
      i += 1
      while i < n:
          if src[i] == "\\" and i + 1 < n:
              out.extend((" ", " "))
              i += 2
              continue
          if src[i] == '"':
              out.append(" ")
              i += 1
              break
  ...
  IMPORT_RE = re.compile(
      r"\b(?:crate|strhide)::(?P<layer>[a-z_]+)\b"
  )
  ```
- **问题分析**：
  1. **未处理 Rust 原始字符串（`r#"..."#`）与字符字面量（`'"'`）**：在 `strip_comments_and_strings` 中，遇到字符字面量 `'"'` 或包含奇数个引号的原始字符串 `r#"..."#` 时，状态机将把后续真实 Rust 代码误判为字符串内部并全部清空为空格，导致其后的真实违规导入被漏检；反之，将代码注释掉的部分误判为代码。
  2. **缺少对 `formats` 与 `analysis` 层的边界约束**：`RULES` 未约束 `formats`（`formats` 只应依赖 `core`，绝不应反向依赖 `structure`/`stego`/`cli`/`analysis`），也未约束 `analysis`（不应依赖 `cli`）。
  3. **仅匹配 `crate::` / `strhide::`**：`IMPORT_RE` 不检查 `super::` 相对路径越界导入（例如 `src/core/mod.rs` 若写 `use super::stego::...` 将完全绕过 `import_lint.py`）。
- **修复建议**：
  在 `strip_comments_and_strings` 中补齐对 `r#*\"...\"#*` 原始字符串和 `'"'` / `'\\''` 字符字面量的识别，在 `RULES` 中加入 `"formats": ("structure", "stego", "cli", "analysis")` 与 `"analysis": ("cli",)`，并拦截跨层 `super::` 引用。

---

### [ARCH-04] 权威规范文档（`WIRE_SPEC.md`、`ARCHITECTURE.md`、`smart_file_data_hiding_design.md`）与代码实现多处失步
- **严重度**：P2（中危 / 协议规范与实现不一致）
- **定位**：
  - `docs/api/WIRE_SPEC.md:493, 642-648, 828, 869-871, 879-880, 900-902`
  - `docs/api/ARCHITECTURE.md:323`
  - `docs/smart_file_data_hiding_design.md:73-76, 135, 159`
  - `rust/src/structure/params.rs:111`、`rust/src/structure/envelope.rs:88-96`
- **实证对比**：
  | 项目 | 文档记载位置与内容 | 实际代码位置与内容 | 影响 |
  | :--- | :--- | :--- | :--- |
  | **结构域内置默认密钥字符串** | `docs/api/WIRE_SPEC.md:869`：<br>`"strhide::envelope::v2::default::builtin::public::secret"` | `rust/src/core/crypto.rs:101-102`：<br>`"strhide::structure::envelope::v2::default::builtin::public::secret"` | 按 `WIRE_SPEC.md` §14.1 实现的第三方解码器将派生出完全不同的 PBKDF2 密钥和掩码，无法解开官方默认信封 |
  | **HEVC `SafetyLevel::video_budget()`** | `docs/api/WIRE_SPEC.md:828`：<br>`paranoid: 0.35 / 110`<br>`high: 0.60 / 220`<br>`balanced: 0.95 / 450` | `rust/src/core/params.rs:313-329`：<br>`Paranoid: 0.1 / 110`<br>`High: 0.2 / 220`<br>`Balanced: 0.4 / 450` | `non_ref_fraction` 规范值与代码值相差 2.3~3.5 倍 |
  | **Content Envelope `BODY_OVERHEAD` / `MIN_ENVELOPE_LEN`** | `WIRE_SPEC.md:493` (§13.1)：`BODY_OVERHEAD = 22`, `MIN_ENVELOPE_LEN = 50`；但同文件 `WIRE_SPEC.md:879-880` (§14.2) 写为 `BODY_OVERHEAD = 21`, `MIN_ENVELOPE_LEN = 49` | `rust/src/stego/envelope.rs:81-83`：<br>`BODY_OVERHEAD = 22`, `MIN_ENVELOPE_LEN = 50`（而 `stego/jpeg/v3_layout.rs:233, 291, 365` 测试仍写 `+ 21`） | 规范文档前后自相矛盾（漏算 1 字节 `kind` 字段） |
  | **Structure Envelope `MIN_UBE_PLAIN` / `MIN_UBE_ENCRYPTED`** | `WIRE_SPEC.md:870-871, 900-902` 及 `structure/envelope.rs:88-90` 注释：`MIN_UBE_PLAIN = 178`, `MIN_UBE_ENCRYPTED = 214` | `rust/src/structure/envelope.rs:95-96`：<br>`pub const MIN_UBE_ENCRYPTED: u32 = 213;`<br>`pub const MIN_UBE_PLAIN: u32 = MIN_UBE_ENCRYPTED;` | 空载荷经 deflate 压缩后为 2 字节而非 3 字节，常量已改为 213，但文档与同文件上方注释仍为 178/214 |
  | **SDK 方言定制示例 API** | `WIRE_SPEC.md:642-648` (§13.9)：<br>`use strhide::params::Profile;`<br>`StrHide::new().with_profile(...)` | `rust/src/facade.rs:146-184`：<br>`Profile` 已移除，现为 `Dialect` / `StrHide::with_dialect` | 文档示例代码无法编译 |
  | **Legacy v0/v1 魔数兼容说明** | `ARCHITECTURE.md:323`、`smart_file_data_hiding_design.md:73`、`structure/params.rs:111` 均称默认方言接受 legacy 魔数 | `rust/src/structure/envelope.rs:56-58, 617`：已彻底移除 legacy 魔数分支，仅匹配 8 字节 v2 魔数 | 文档与注释误导调用方以为具备旧版向后兼容 |
  | **结构域标志位、策略 ID 与 JPEG 段类型** | `smart_file_data_hiding_design.md:75-76, 159`：称 bit 6 为流式分块、bit 5 `0=JSON`、策略 ID 仅 1..=9、JPEG 注入 `COM (0xFF 0xFE)` | `structure/envelope.rs:60-72, 169-240`、`adapters/jpeg.rs:14, 298`：bit 6 未分配、全部使用二进制元数据、策略 ID 扩展至 1..=13、JPEG 注入 `APP15 (0xFF 0xEF)` | 设计文档严重滞后于 v2.1 实现 |

---

## 4. 维度二：库接口（Library Interfaces & Public API）

### [API-01] `StrategyChoice::from<&str>` 将未知/拼写错误的策略名静默降级为 `StrategyChoice::Auto`
- **严重度**：P2（中危 / 接口易用性与防呆缺陷）
- **定位**：`rust/src/structure/options.rs:35-46`
- **代码实证**：
  ```rust
  // rust/src/structure/options.rs:35-46
  impl From<&str> for StrategyChoice {
      fn from(name: &str) -> Self {
          let trimmed = name.trim();
          if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
              return Self::Auto;
          }
          match Strategy::from_name(trimmed) {
              Some(s) => Self::Explicit(s),
              None => Self::Auto,
          }
      }
  }
  ```
- **问题分析**：
  虽然 `WriteOptions.strategy` 已改为 `&str` 并在 `structure/engine.rs:883-907` 中校验未知策略名，但公共 API 中导出的强类型枚举 `StrategyChoice`（`rust/src/structure/mod.rs:36`、`rust/src/lib.rs:111`）其 `From<&str>` 实现将任何拼写错误的策略字符串（例如 `StrategyChoice::from("app_segmnet")`）静默转换为 `StrategyChoice::Auto`，且没有实现标准的 `std::str::FromStr`。
- **修复建议**：
  为 `StrategyChoice` 实现 `std::str::FromStr`（遇到未知策略名返回 `Err(StrHideError::General(...))`），并在 `StrategyChoice` 中移除会掩盖拼写错误的 `From<&str>`（或仅保留 `From<Strategy>` 与 `TryFrom<&str>`）。

---

### [API-02] `StegoTuning` 缺少 `Audio` 分支，且 `MediaInfo` 无法表达音频元数据
- **严重度**：P2（中危 / 公共接口不对称与信息丢失）
- **定位**：
  - `rust/src/stego/options.rs:259-287`
  - `rust/src/core/media.rs:16-30, 64-77`
  - `rust/src/stego/audio/core.rs:409, 876, 898`
- **代码实证**：
  ```rust
  // rust/src/stego/options.rs:260-273
  pub enum StegoTuning {
      #[default]
      Auto,
      Png { model: SpatialAlgorithm, params: PngParams },
      Jpeg { model: JpegAlgorithm, params: JpegParams },
      Hevc { mode: HevcMode },
  }
  ```
  ```rust
  // rust/src/core/media.rs:16-30, 64-77
  pub struct MediaInfo {
      pub width: u32,
      pub height: u32,
      pub fps: Option<f64>,
      pub duration_ms: Option<u64>,
      pub bitrate_bps: Option<u64>,
  }
  ...
  impl fmt::Display for MediaInfo {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
          write!(f, "{}x{}", self.width, self.height)?;
          if let (Some(fps), Some(dur_ms), Some(bps)) = (self.fps, self.duration_ms, self.bitrate_bps)
          { ... }
          Ok(())
      }
  }
  ```
- **问题分析**：
  1. `list_stego_algorithms()`（`stego/registry.rs:133-155`）向 CLI 和 GUI 公开了 `"wav_pcm"` 与 `"flac_residual"` 两种算法，但 `StegoTuning` 枚举只有 `Auto`、`Png`、`Jpeg`、`Hevc` 四个分支，没有 `Audio` 分支。CLI（`cli/helpers.rs:250`）只能用 `if matches!(name, "audio" | "wav_pcm" | "flac_residual") { return Ok(StegoTuning::Auto); }` 绕过，而库调用方无法通过 `StegoTuning` 显式指定音频算法或调优音频参数（如 `CostParams::window`、`floor`、`stc_h`）。
  2. `MediaInfo` 结构体强假设所有媒体均有 `width` 和 `height`，导致 WAV 与 FLAC 引擎在 `StegoCapacityInfo` 和 `StegoHeaderInfo` 中只能将 `media_info` 设为 `None`（`stego/audio/core.rs:409, 876`），把声道数、位深、采样率塞进字符串 `note: Some(format!("{}ch {}-bit {}Hz ({})", ...))`（`audio/core.rs:898`）。这导致 CLI `sth capacity` 和 GUI 容量面板无法在媒体信息栏展示音频的采样率、声道数、位深和时长。
  3. 此外，`MediaInfo::Display`（`core/media.rs:68`）要求 `(fps, duration_ms, bitrate_bps)` 三者**同时为 `Some`** 才格式化输出，若某容器仅有分辨率与时长/码率（如 Annex-B 裸流无已知帧率时），附加信息会被全部丢弃。
- **修复建议**：
  1. 在 `StegoTuning` 中增加 `Audio { model: AudioAlgorithm, params: AudioParams }` 分支。
  2. 扩展 `MediaInfo`（支持可选的 `sample_rate_hz: Option<u32>`、`channels: Option<u16>`、`bits_per_sample: Option<u16>`，或使 `width`/`height` 在纯音频载体下可选），并拆解 `Display` 中对 `(fps, duration_ms, bitrate_bps)` 的全有或全无绑定。

---

### [API-03] 能力表与注册表错误宣称 `avif` / `webm` 支持 `HevcCabac`，`FileFormat::Pe` 漏掉 `sys` / `scr`，报错文案滞后
- **严重度**：P2（中危 / 接口元数据失真）
- **定位**：
  - `rust/src/stego/registry.rs:116-129`
  - `rust/src/formats/capability.rs:130, 156, 216`
  - `rust/src/formats/sniff.rs:23, 239`
  - `rust/src/stego/mod.rs:191-194, 203-207`
  - `rust/src/stego/hevc/engine.rs:281, 318, 403, 844, 1547, 1709, 3203`
- **代码实证**：
  ```rust
  // rust/src/stego/registry.rs:116-129
  StegoAlgorithmInfo {
      id: "hevc_cabac",
      domain: StegoDomain::HevcCabac,
      formats: &["HEIF", "MP4", "MKV", "HEVC"],
      extensions: &[
          "heic", "heif", "avif", "mp4", "mov", "m4v", "mkv", "webm", "h265", "265", "hevc",
      ],
      is_default_for_domain: true,
      description: "HEVC CABAC bypass sign-bit steganography (HEIF/MP4/MKV/Annex-B)...",
  }
  ```
- **问题分析**：
  1. **虚假声明 `avif` 与 `webm` 支持内容域 `HevcCabac`**：AVIF 封装的是 AV1（`av01`）编码图像，WebM 规范仅允许 VP8/VP9/AV1 视频轨。而在实际代码中，`heif_boxes.rs:449` 强制要求存在 `hvcC`（HEVC 配置项），`mkv_boxes.rs:99` 强制要求 `CodecID == "V_MPEGH/ISO/HEVC"`。虽然结构域（ISOBMFF / EBML）可以处理 `.avif` 和 `.webm`，但内容域 `HevcCabac` 绝不可能支持标准 `.avif` 或 `.webm` 文件。前端 GUI 根据 `extensions` 构建文件选择器过滤器和能力矩阵时会误导用户。
  2. **`FileFormat::Pe` 扩展名不一致**：`rust/src/structure/adapters/pe.rs:647` 支持 `["exe", "dll", "sys", "scr"]`，但 `rust/src/formats/capability.rs:216` 中 `FileFormat::Pe` 的 `extensions` 仅列出了 `&["exe", "dll"]`，漏掉了 `"sys"` 和 `"scr"`。
  3. **多处报错文案漏列新增的 `MKV`、`WAV`、`FLAC`**：
     - `rust/src/stego/mod.rs:191-194, 203-207`（`unsupported_carrier` 与 `unrecognized_carrier`）仅写 `"requires a PNG, JPEG, HEIF/HEIC, or HEVC carrier (Annex-B or MP4/MOV)"`，漏掉了 `MKV`、`WAV`、`FLAC`。
     - `rust/src/cli/helpers.rs:272, 449` 同样漏掉了 `MKV`、`WAV`、`FLAC`。
     - `rust/src/stego/hevc/engine.rs:281, 318, 403, 844, 1547, 1709, 3203` 共 7 处报错信息仅写 `"requires a HEIF/HEIC, MP4/MOV, or Annex-B .h265 carrier"`，漏掉了已实现的 `MKV`。
- **修复建议**：
  从 `hevc_cabac` 算法与内容域能力说明中移除 `"avif"` 与 `"webm"`（仅在结构域能力中保留），在 `capability.rs:216` 为 `FileFormat::Pe` 补齐 `"sys", "scr"`，并统一更新 `stego/mod.rs`、`cli/helpers.rs` 与 `hevc/engine.rs` 的支持格式提示文本。

---

## 5. 维度三：函数和参数（Functions & Parameters）

### [FN-01] `ExtractParams::max_payload_bytes`（默认 32 MiB 防解压炸弹上限）在全部 7 个内容域引擎中完全未实现
- **严重度**：**P0（严重 / 安全边界失效 & 参数死配置）**
- **定位**：
  - `rust/src/stego/params.rs:267-291`
  - `rust/src/stego/options.rs:766-769, 864-867`
  - `rust/src/stego/engine.rs:215-238, 489-504, 642-656, 1017-1071, 1130-1184`
  - `rust/src/stego/jpeg/engine.rs:1155-1201`
  - `rust/src/stego/png/engine.rs:1728-1734, 2034-2039`
- **代码实证**：
  `rust/src/stego/params.rs:267-291` 与 `docs/api/STEGO-API.md` 明确定义了 `ExtractParams::max_payload_bytes`：
  ```rust
  // rust/src/stego/params.rs:267-291
  pub struct ExtractParams {
      /// Maximum raw payload size accepted after extraction and (optional)
      /// decompression, in bytes. Default: 32 MiB.
      pub max_payload_bytes: usize,
      pub max_pbkdf2_iterations: u32,
      pub allowed_cipher_suites: Vec<u16>,
  }
  impl Default for ExtractParams {
      fn default() -> Self {
          Self {
              max_payload_bytes: 32 * 1024 * 1024,
              ...
          }
      }
  }
  ```
  并且 `ExtractOptions::with_max_payload_bytes`（`stego/options.rs:766`）和 `VerifyOptions::with_max_payload_bytes`（`stego/options.rs:864`）均暴露给外部用户。然而检索全库所有使用 `max_payload_bytes` 的位置，**全库除了定义处、构造器和测试断言默认值为 32 MiB 外，没有任何一处引擎代码读取过 `max_payload_bytes` 字段**：
  1. **`JpegEngine`**（`rust/src/stego/jpeg/engine.rs:1155, 1182-1197`）：
     ```rust
     pub fn extract_jpeg_from(
         carrier_jpeg: &[u8],
         secret: Option<&str>,
         domain: &[u8],
         fmt: &JpegFormat,
         extract: &ExtractParams,
         control: &Control<'_>,
     ) -> Result<Payload<'static>, StrHideError> {
         ...
         if !extract.allows_suite(sb.cipher_suite) { ... }
         if sb.kdf_iterations > extract.max_pbkdf2_iterations { ... }
         // 完全没有检查 extract.max_payload_bytes！
         let envelope_bytes = extract_payload_bytes(&coeffs, &plan, sb.envelope_len, sb.stc_h)?;
         envelope::unpack(&envelope_bytes, secret_str, domain, &fmt.envelope)
     }
     ```
  2. **`PngEngine`**（`rust/src/stego/engine.rs:215-225` & `rust/src/stego/png/engine.rs:2034-2039`）：
     - `PngEngine::extract` 甚至没有把 `&opts.limits` 传给 `png::extract_png`！
     - `png::verify_png`（`stego/png/engine.rs:2037`）将参数命名为 `_limits: &ExtractParams`（加下划线直接丢弃）！
  3. **`HeifEngine` / `Mp4Engine` / `AnnexBEngine` / `MkvEngine`**（`rust/src/stego/engine.rs:489-504, 642-656`）：
     - `hevc_extract` 与 `hevc_verify` 完全没有接收或传递 `opts.limits`！
  4. **`WavEngine` / `FlacEngine`**（`rust/src/stego/engine.rs:1017-1071, 1130-1184`）：
     - `WavEngine::extract`、`WavEngine::verify`、`FlacEngine::extract`、`FlacEngine::verify` 完全没有传递 `opts.limits`！
- **问题分析**：
  这是一个典型的“接口与文档声明了安全配额，但底层执行路径完全遗漏”的严重缺陷。即使调用方显式调用 `ExtractOptions::new().with_max_payload_bytes(1024)`，或者依赖默认的 32 MiB 上限，所有 7 个内容域引擎也都会完全无视 `opts.limits.max_payload_bytes`（仅受 `envelope.rs:94` 硬编码的 `MAX_DECOMPRESSED_LEN = 64 MiB` 限制）。此外，除 JPEG 外，PNG、HEVC、WAV、FLAC 引擎连 `opts.limits.max_pbkdf2_iterations` 和 `opts.limits.allowed_cipher_suites` 也未生效。
- **修复建议**：
  在 `stego/envelope.rs` 的 `unpack`（或 `unpack_with_limits(envelope_bytes, secret, domain, fmt, max_payload_bytes)`）中统一使用 `limits.max_payload_bytes` 替代硬编码的 `MAX_DECOMPRESSED_LEN`（64 MiB），并将 `&opts.limits` 贯穿传入 `PngEngine`、`Hevc`、`WavEngine`、`FlacEngine` 的 `extract` 与 `verify` 函数中。

---

### [FN-02] 结构域与内容域对空密码 `Some("")` 的语义处理完全相反
- **严重度**：P1（高危 / 跨层参数语义冲突）
- **定位**：
  - 内容域：`rust/src/stego/options.rs:620-627, 786, 883`、`rust/src/stego/hevc/engine.rs:3275`
  - 结构域：`rust/src/structure/engine.rs:981-986, 1529-1536`
- **代码实证**：
  内容域将 `Some("")` 过滤为 `None`（视为未提供密码，使用内置公开默认密钥）：
  ```rust
  // rust/src/stego/options.rs:620-627
  pub(crate) fn effective_secret<'d>(&self, dialect: &'d StegoDialect) -> Option<&'d str>
  where
      'a: 'd,
  {
      self.password
          .filter(|s| !s.is_empty())
          .or_else(|| dialect.secret())
  }
  ```
  而结构域将 `Some("")` 视为“用户显式提供了空字符串密码”，开启 `FLAG_ENCRYPTED`，头部保持不掩码（Unmasked），并用 `""` 派生加密密钥：
  ```rust
  // rust/src/structure/engine.rs:981-986
  let has_custom_password = password.is_some();
  let effective_pwd = match password {
      Some(p) => p,
      None => profile.secret(),
  };
  ```
- **问题分析**：
  当库调用方或 GUI 前端绑定一个未输入文本的密码框 `Some("")` 调用 API 时：
  - 在 `stego` 域：`Some("")` 等同于 `None`（不加密 / 使用默认方言密钥），任何人无需密码即可提取。
  - 在 `structure` 域：`Some("")` 被当作自定义密码 `""`，置位 `FLAG_ENCRYPTED = true`；更糟糕的是，当后续调用 `read_carrier` 传入 `None` 时会报“需要密码”，而 CLI `resolve_password`（`cli/helpers.rs:54`）又禁止输入空密码（`"Password cannot be empty"`），导致通过库接口以 `Some("")` 写入的结构域载体**在 CLI 下永远无法被读取或恢复**！
- **修复建议**：
  在结构域入口（`WriteOptions` / `ReadOptions` / `RestoreOptions` / `DualOptions` 或 `write_core` / `read_core` / `verify_core` / `inspect_core`）统一对 `password` 执行 `.filter(|s| !s.is_empty())` 归一化（或显式拒绝 `Some("")` 返回 `StrHideError::Password("Password cannot be empty")`），消除双域语义分裂。

---

### [FN-03] `FeatureWord` 位打包 `exclusion_permille` 掩码宽度错误（64 位左移 51 位后仅剩 13 位）
- **严重度**：P2（中危 / 位域运算精度缺陷）
- **定位**：`rust/src/stego/header.rs:232, 293`
- **代码实证**：
  ```rust
  // rust/src/stego/header.rs:226-233
  let mut low64: u64 = 0;
  low64 |= (self.version as u64 & 0x0F) << 0;
  low64 |= (self.flags as u64 & 0xFF) << 4;
  low64 |= (self.payload_len as u64 & 0xFFFF_FFFF) << 12;
  low64 |= (self.channel_mode as u64 & 0x07) << 44;
  low64 |= (self.cost_model as u64 & 0x0F) << 47;
  low64 |= (self.exclusion_permille as u64 & 0xFFFF) << 51;
  ```
  ```rust
  // rust/src/stego/header.rs:293
  let exclusion_permille = ((low64 >> 51) & 0xFFFF) as u16;
  ```
- **问题分析**：
  `low64` 是 `u64`（共 64 bit，位索引 `0..=63`）。从第 51 位开始向高位打包时，`64 - 51 = 13`，即 `low64` 中仅剩 **13 bit**（`51..=63`，最大值 `0x1FFF = 8191`），而代码与表注释（第 `125` 行 `51..64: exclusion_permille (u16, 0..=1000)`）却使用了 16 位掩码 `0xFFFF` 并声称存储 `u16`。虽然合法的千分比 `0..=1000` 小于 `8191`，但若传入大于 `8191` 的 `u16` 值，高位 `13..16` 会被 `<< 51` 静默截断，导致 `pack -> unpack` 往返不一致。
- **修复建议**：
  将 `header.rs:232` 和 `293` 的掩码修正为 `0x1FFF`（13-bit 掩码），并在 `pack()` 中增加 `debug_assert!(self.exclusion_permille <= 1000)`。

---

### [FN-04] CLI `--auto` 跨界回退在多文件批处理（`-o <DIR>`）下丢失批处理上下文，引发文件命名冲突与覆盖异常
- **严重度**：P1（高危 / 批处理参数传递缺陷）
- **定位**：
  - `rust/src/cli/cmd_structure.rs:327-350`
  - `rust/src/cli/cmd_stego.rs:607-622, 637-656`
  - `rust/src/core/pipeline.rs:107-115`
- **代码实证**：
  在 `rust/src/cli/cmd_structure.rs:333-349` 中，当 `sth read --auto -o out_dir a.png b.png` 处理多载体批处理且某载体无结构域信封而自动转向内容域提取时：
  ```rust
  let mut extract_args = ExtractArgs {
      carrier: vec![carrier.to_path_buf()],
      output: args.output.clone(),
      stdout: args.stdout,
      overwrite: args.overwrite,
      passwords: args.passwords.clone(),
      auto: false,
  };
  if extract_args.passwords.password.is_none() {
      extract_args.passwords.password = password.clone();
  }
  return handle_extract(extract_args, cfg, quiet, engine);
  ```
  而在 `handle_extract`（`cmd_stego.rs:531-557`）中：
  ```rust
  let multi = args.carrier.len() > 1;
  ...
  let output_dir = batch_output_dir(args.output.as_deref(), multi, "extracting from")?;
  ...
  let mut batch = BatchOutputs::new(output_dir);
  ```
  且 `batch_output_dir`（`rust/src/core/pipeline.rs:112`）规定：
  ```rust
  if !multi {
      return Ok(None);
  }
  ```
- **问题分析**：
  因为 `read_one` 构造的 `extract_args.carrier` 只有 1 个元素（`multi == false`）：
  1. `batch_output_dir` 返回 `Ok(None)`，导致 `extract_one` 中 `batch.dir` 为 `None`！
  2. 在 `extract_one`（`cmd_stego.rs:647-656`）中，`explicit` 退化为 `Some(out_dir)`，直接走 `out_path.is_dir()` 分支：
     `let name = sanitize_filename(payload.name().unwrap_or("extracted.bin")); out_path.join(name)`。
  3. 这完全绕过了批处理的 `batch_payload_name`（将无文件名的文本载荷全部命名为 `"extracted.bin"` 而非 `<carrier_stem>.txt`）和 `unique_batch_path` 去重集合 `batch.used`！
  4. 同理，当 `sth extract --auto -o out_dir a.png b.png` 在 `cmd_stego.rs:613-621` 回退到 `handle_read` 时，同样因为 `carrier: vec![carrier.to_path_buf()]` 长度为 1 而丢失 `batch` 状态，导致多个回退文件直接相互覆盖或触发拒绝覆盖错误！
- **修复建议**：
  不要在 `read_one` / `extract_one` 单文件循环内部递归调用顶层的 `handle_extract` / `handle_read`；应直接调用 `extract_one` / `read_one` 并将当前的 `&mut batch: &mut BatchOutputs` 引用传递过去，共享同一个 `batch.dir` 与 `batch.used` 集合。

---

## 6. 维度四：代码质量（Code Quality & Maintainability）

### [QUAL-01] PNG 与 JPEG 引擎中的空函数 `trace(&format!(...))` 在 Release 构建下无条件执行堆内存格式化分配
- **严重度**：P1（高危 / 代码质量与不必要内存分配）
- **定位**：
  - `rust/src/stego/png/engine.rs:662, 859-864, 1426, 1794, 1872`
  - `rust/src/stego/jpeg/engine.rs:200-205, 729, 737, 982`
- **代码实证**：
  ```rust
  // rust/src/stego/png/engine.rs:859-864 (以及 rust/src/stego/jpeg/engine.rs:200-205)
  /// Optional tracing enabled with `STRHIDE_STEGO_TRACE=1`.
  /// Kept in release builds so integration debugging can inspect live failures.
  #[inline(always)]
  fn trace(_msg: &str) {
      // Silenced by default to adhere to strict library purity (Zero I/O).
  }
  ```
  而在所有调用点：
  ```rust
  // rust/src/stego/png/engine.rs:662
  trace(&format!(
      "embed attempt: factor={factor} total_needed={total_needed} (hdr={header_slots} body={body_slots}) avail={}",
      plan.candidates.len()
  ));
  // rust/src/stego/jpeg/engine.rs:729, 737, 982
  trace(&format!(
      "v3 embed: factor={factor}, needed={needed_body_slots}, pool={}, h={}",
      body_pool.len(),
      params.stc_h
  ));
  ```
- **问题分析**：
  1. 注释声称 `"Optional tracing enabled with STRHIDE_STEGO_TRACE=1"`，但函数体实际上是空的。
  2. 在 Rust 中，函数参数在进入 `trace(_msg)` 之前就会完成求值！因此每次调用 `trace(&format!(...))` 时，即便 `trace` 被内联为空操作，`format!(...)` 宏包含不可消除的堆分配（`alloc::fmt::format`），编译器无法将其作为死代码优化掉。在循环重试（如 `factor` 自适应重试、提取时遍历全部 8 种 `SUPERBLOCK_H_CANDIDATES`）中，每次都会在堆上分配并销毁 `String`。
- **修复建议**：
  将 `fn trace(_msg: &str)` 替换为 `macro_rules! trace { ($($arg:tt)*) => { log::trace!(target: "strhide::stego", $($arg)*); }; }`（或直接設为空宏 `macro_rules! trace { ($($arg:tt)*) => {}; }`），彻底消除无意义的 `format!` 堆分配。

---

### [QUAL-02] `thumb_bridge.rs` 中 `BridgeTargetKind::DirectSpatial` 永远不可达，却保留 5 处死分支
- **严重度**：P2（中危 / 死代码与虚假架构分支）
- **定位**：`rust/src/stego/heif/thumb_bridge.rs:28-29, 122-136, 177-186, 214-228, 266-274, 321-333, 627`
- **代码实证**：
  ```rust
  // rust/src/stego/heif/thumb_bridge.rs:24-30
  pub enum BridgeTargetKind {
      /// JPEG-coded auxiliary/thumbnail item (`item_type == b"jpeg"`).
      Jpeg { item_id: u32 },
      /// Uncompressed spatial item (`item_type == b"unci"` or raw RGB/Gray).
      DirectSpatial { item_id: u32 },
  }
  ```
  但在唯一构造 `BridgeTarget` 的函数 `find_bridge_target`（第 `627-629` 行）中：
  ```rust
  // Look for uncompressed spatial items (`unci` - ISO/IEC 23001-17) if no JPEG thumbnail exists
  // Note: For now, `unci` items require wrapping as PNG or raw pixel buffer; if not present,
  // we only bridge `jpeg` items which contain complete self-contained JPEG streams.
  ```
  并且第 `122-136`、`177-186`、`214-228`、`266-274`、`321-333` 行却把 `DirectSpatial` 的原始 extent 字节直接传给 `png::embed_png` / `png::extract_png`（而 ISO 23001-17 `unci` 项根本不是 PNG 文件流，传入 `png::embed_png` 必然报 `Invalid PNG magic`）。
- **修复建议**：
  删除从未构造且逻辑错误的 `BridgeTargetKind::DirectSpatial` 变体及其 5 处匹配分支，使 `thumb_bridge.rs` 职责保持清晰诚实。

---

### [QUAL-03] HEVC `header_bytes`（24 vs 32 vs 40 vs 48）契约混乱、`provisional_sign_flip_cost` 死函数与 FLAC 矛盾注释
- **严重度**：P3（低危 / 代码整洁度与可维护性）
- **定位**：
  - `rust/src/stego/format.rs:205, 223` vs `rust/src/stego/hevc/engine.rs:265, 679`
  - `rust/src/stego/hevc/slot.rs:318-345`
  - `rust/src/stego/audio/flac/mod.rs:198-204` vs `426-431`
- **代码实证**：
  1. `rust/src/stego/format.rs:205` 注释写：
     `/// For HEVC formats, must be >= 24 (the 24-byte HEVC frame header size), with a default value of 40.`
     紧接着第 `223` 行定义：`header_bytes: 48`。
     而在 `rust/src/stego/hevc/engine.rs:265`（`check_header_bytes`）中检查的是：`if fmt.header_bytes < HEVC_SUPERBLOCK_BYTES`（`32`）。而在实际编码中，32 字节 Superblock 固定写入 `superblock_slots`（与 `fmt.header_bytes` 完全无关），16 字节 GCM Tag 写入 `body_slots`，`fmt.header_bytes` 仅在 `recommended_for`（`hevc/engine.rs:679`）估算开销时被减去！
  2. `rust/src/stego/hevc/slot.rs:318-345` 中的 `pub fn provisional_sign_flip_cost(...) -> f32` 在生产代码中从未被调用（`record_stego_sign` 第 `645` 行直接内联计算了 `HIGH_DISPLACEMENT_PENALTY`）。
  3. `rust/src/stego/audio/flac/mod.rs:198-204` 字段注释警告：
     `/// CALLERS MUST NOT USE THIS VECTOR TO FILTER OR RE-INDEX SLOTS: the extractor sees the post-embed file (whose usable set differs whenever a flip moved a sample across the boundary), so it must never take part in slot selection.`
     然而就在同一个文件的第 `426-431` 行（`FlacCarrier::new`）：
     `// S1: Only sample over genuinely movable slots, guaranteeing STC never attempts to flip a saturated sample that would clip or wrap around. let usable = &analysis.usable; ... .filter(|&idx| usable[idx])`
     因为 `analyse` 实际检查的是未加隐写扰动的 `base_pcm`（只要补偿 `comp` 也只改 `c_pos` 后的最终 PCM，等等：在 `analyse` 第 `315` 行，`base_pcm` 是由**当前文件中的 `sub.residuals`** 重建的！如果嵌入时翻转了一个残差 $r[s] \to r[s] \pm 1$ 并翻转了补偿位 $r[c\_pos] \to r[c\_pos] \mp 1$，那么在 `[s, c_pos - 1]` 区间内的重建样本 `base_pcm[k]` 在嵌入后确实发生了 $\pm 1$ 偏移！）。这不仅是注释矛盾，更是一个真实的提取同步风险（见 **[LOGIC-09]**）！

---

### [QUAL-04] `cli_i18n.rs` 漏译多个 CLI 参数，且 `analysis.rs` 结构体文档注释与实际值域不符
- **严重度**：P3（低危 / 国际化完整性与注释准确性）
- **定位**：
  - `rust/src/cli_i18n.rs:57-72, 74-179`
  - `rust/src/analysis.rs:120, 139`
- **代码实证**：
  1. `rust/src/cli_i18n.rs:58-70` 中 `cmd_after_help` 仅匹配 `"strhide" | "sth"`，未匹配分域二进制 `"sthc" | "sths" | "sthv"`；`arg_help`（第 `74-179` 行）漏掉了 `("read", "auto")`、`("extract", "auto")`、`("embed", "no-filename")`、`(_, "seed")`、`("scan", "fail-on")`，导致 `--lang zh` 下这些参数的 `--help` 说明仍显示英文。
  2. `rust/src/analysis.rs:139` 中 `ScanReport::risk_score` 的文档注释写着：
     `/// 0 (clean) .. 10 (very likely hidden).`
     而实际代码（第 `30` 行、`494-499` 行、`2095-2105` 行）使用的是 `0..=100` 分制（`0..=9` clean、`10..=29` low、`30..=59` suspicious、`60..=100` likely-hidden）。同文件第 `120` 行 `DetectorMetric::status` 注释仅写 `"PASS", "ALERT"`，漏掉了实际生成的 `"INFO"` 与 `"SKIPPED"`。

---

## 7. 维度五：算法性能（Algorithm Performance & I/O Efficiency）

### [PERF-01] 结构域 `verify_carrier` / `inspect_carrier` 单次调用重复执行 6~7 次 100,000 轮 PBKDF2
- **严重度**：P1（高危 / 严重 CPU 性能浪费）
- **定位**：
  - `rust/src/structure/envelope.rs:491-518`
  - `rust/src/structure/engine.rs:1399-1444, 2412, 2444, 2475, 2538`
- **代码实证**：
  首先看 `EnvelopeHeader::unpack_with_secrets`（`rust/src/structure/envelope.rs:491-518`）：
  ```rust
  // 2. Standard mode (unencrypted OR default-key encrypted): unmask with builtin key
  let default_mask = crypto::derive_header_mask(profile.secret(), &salt);
  let mut unmasked = [0u8; HEADER_SIZE];
  ...
  // 3. Custom-password encrypted envelope (not stealth): header is NOT masked on wire
  if data[0..8] == profile.magic.header
      && data[8] == UBE_VERSION
      && (data[9] & FLAG_ENCRYPTED) != 0
  ```
  注意：**步骤 2 无条件先执行 100,000 轮 PBKDF2 (`derive_header_mask(profile.secret(), &salt)`)，然后才在步骤 3 检查 `data` 是否根本没有掩码（自定义密码加密模式）**！
  更严重的是，在 `verify_core`（`rust/src/structure/engine.rs:2408-2548`）对单个加密/隐身载体执行校验时：
  1. 第 `2412` 行：`locate_envelope` 派生 `derive_stealth_magics(pwd)`（**第 1 次 100k PBKDF2**），找到信封后调用 `unpack_with_secrets`，其中步骤 2 执行 `derive_header_mask(profile.secret())`（**第 2 次 100k PBKDF2**），若为 stealth 则步骤 4 再执行 `derive_header_mask(pwd)`（**第 3 次 100k PBKDF2**）。随后 `locate_envelope` **直接丢弃了已派生的 `stealth_header_magic`**！
  2. 第 `2444` 行：`verify_core` 为了验证 Trailer，又重新调用一次 `crypto::derive_stealth_magics(pwd)`（**第 4 次 100k PBKDF2**）！
  3. 第 `2475` 行：`verify_core` 验证完 Trailer 后，明明 `locate_envelope` 已经解出了 `header: EnvelopeHeader`，却又对同一段 `header_buf` 重新调用了一次 `EnvelopeHeader::unpack_with_secrets`（内部再次触发 **第 5 次** 和 **第 6 次 100k PBKDF2**）！
  4. 第 `2538` 行：Level 3 解密载荷块时调用 `crypto::decrypt_payload_chunks` -> `derive_key(pwd, salt)`（**第 7 次 100k PBKDF2**）！
- **问题分析**：
  单次 `verify_carrier` 调用居然串行执行了 **6 到 7 次 100,000 轮 PBKDF2-HMAC-SHA256**（共计 600,000~700,000 轮 SHA-256 迭代）！在批量校验目录或 GUI 检查载体时，造成数百毫秒至数秒的无谓卡顿。
- **修复建议**：
  1. 在 `EnvelopeHeader::unpack_with_secrets` 中，**将步骤 3（明文 `data[0..8] == profile.magic.header && (data[9] & FLAG_ENCRYPTED) != 0` 的零成本比对）移到步骤 2（100,000 轮 `derive_header_mask`）之前**！
  2. 让 `locate_envelope` 返回已派生的 `Option<([u8; 8], [u8; 4])>` 隐身魔数对，供 `verify_core` 复用，并删除 `verify_core` 第 `2475` 行对 `EnvelopeHeader::unpack_with_secrets` 的重复调用。

---

### [PERF-02] FLAC 嵌入/提取/验证单次操作将整文件完整解码 3~5 次，且 WAV/FLAC 只读操作全量克隆载体
- **严重度**：P1（高危 / 音频引擎严重性能瓶颈与内存翻倍）
- **定位**：
  - `rust/src/stego/audio/mod.rs:71-143, 155-189, 200-231, 239-273, 285-319, 394-455`
  - `rust/src/stego/audio/flac/mod.rs:401-443, 498-555`
- **代码实证**：
  以 `extract_flac`（`rust/src/stego/audio/mod.rs:155-189`）为例：
  ```rust
  pub fn extract_flac(...) -> Result<Payload<'static>, StrHideError> {
      let info = flac::probe(carrier)?;
      let analysis = flac::analyse(carrier, &info)?;          // <-- 全文件完整 FLAC 解码第 1 次！
      let total_slots = analysis.slots.len();
      let mut scratch = carrier.to_vec();                     // <-- 整文件内存克隆第 1 次！
      let header_bytes = {
          let flac_carrier = FlacCarrier::new(&mut scratch, &info, &analysis, 0, true)?; // <-- 全文件完整 FLAC 解码第 2 次！
          core::extract_header_bytes(&flac_carrier, total_slots, eff_secret, domain)?
      };
      ...
      let mut scratch = carrier.to_vec();                     // <-- 整文件内存克隆第 2 次！
      let flac_carrier = FlacCarrier::new(&mut scratch, &info, &analysis, body_slots, false)?; // <-- 全文件完整 FLAC 解码第 3 次！
      let raw = core::extract_body_bytes(&flac_carrier, ...)?;
  ```
  再看 `embed_flac`（`rust/src/stego/audio/mod.rs:71-143`）：
  - 第 `71` 行：`flac::analyse(carrier, &info)`（**全文件完整解码第 1 次**，含 MD5 计算）；
  - 第 `111` 行：`FlacCarrier::new`（`flac/mod.rs:416` 调用 `frame::decode_frame`，**全文件完整解码第 2 次**）；
  - 第 `132` 行：`flac_carrier.finalize()` -> `refresh_checksums`（`flac/mod.rs:514` 再次对每一帧调用 `frame::decode_frame`，**全文件完整解码第 3 次**）；
  - 若在 Debug 模式下，第 `544` 行 `debug_assert!` 还会调用 `analyse(&out, &self.info)`（**第 4 次全文件解码**），且若开启 `drift` 校验（`audio/mod.rs:136`），`max_sample_drift` 又会把原文件与输出文件各完整解码一次（**第 4、5 次全文件解码**）！
  同时，对于 WAV 格式（`rust/src/stego/audio/mod.rs:394, 413, 427, 449`）：
  ```rust
  // extract_wav / probe_wav / inspect_wav / verify_wav
  let mut scratch = carrier.to_vec();
  let wav = WavCarrier::new(&mut scratch, &info);
  ```
  这四个纯只读函数（提取、容量探测、检查、验证）竟然全都先把整个 WAV 文件（通常数十至数百 MB）`to_vec()` 深拷贝一份，仅仅因为 `WavCarrier<'a>` 持有了 `&'a mut [u8]`！
- **问题分析**：
  1. `flac::analyse` 已经遍历并解码了所有帧，收集了全部 `ResidualSlot` 和 `Compensation`，但因为没有顺便保存每个槽位的代价（或帧偏移与残差值），导致 `FlacCarrier::new` 为了计算 `costs` 又把整个 FLAC 比特流从头 Rice 解码了一遍；而 `extract_flac` / `inspect_flac` 在 `with_costs = false` 时，`FlacCarrier::new`（`flac/mod.rs:416`）**即使 `need_all_costs == false` 且 `sample_limit == 0`（提取头部时根本不需要任何代价！）也依然在循环里无条件调用 `frame::decode_frame` 解码了整个文件的所有帧**！
  2. `refresh_checksums` 其实只需要重算被 `dirty_frames: Vec<bool>` 标记修改过的帧的 CRC-16（以及 STREAMINFO 的全局 PCM MD5，甚至如果补偿残差保持了帧外样本不变且已知被改动的 `s` 和 `c_pos` 样本差值，或仅对 dirty 帧重算 PCM），根本不需要重解未修改帧。
- **修复建议**：
  1. 在 `FlacCarrier::new` 中，当 `!need_all_costs && sample_limit == 0`（用于 `extract` / `inspect` / `verify`）时，**直接跳过帧遍历解码循环**（耗时从 $O(\text{全文件帧解码})$ 降为 $O(1)$），并且对于只读操作无需 `carrier.to_vec()` 克隆。
  2. 在 `flac::analyse` 一次遍历中直接计算或缓存帧元数据与残差代价，消除 `embed_flac` 的第 2 次全量解码。
  3. 将 `WavCarrier` 拆分为只读视图 `WavReader<'a>(&'a [u8])` 与可写视图 `WavCarrier<'a>(&'a mut [u8])`（或使用 `Cow<'a, [u8]>`），彻底消除 `extract_wav`、`probe_wav`、`inspect_wav`、`verify_wav` 对数百 MB WAV 文件的无谓内存深拷贝。

---

### [PERF-03] 音频失真代价 `CostParams::cost_at` 对每个槽位重复扫描 33 邻域并从字节流解码样本
- **严重度**：P1（高危 / $O(W \cdot N)$ 重复解码与浮点除法开销）
- **定位**：`rust/src/stego/audio/cost.rs:96-128`、`rust/src/stego/audio/core.rs:711-715`
- **代码实证**：
  ```rust
  // rust/src/stego/audio/cost.rs:96-128
  pub fn cost_at<F>(&self, index: usize, total: usize, mut sample_at: F) -> f32
  where
      F: FnMut(usize) -> i32,
  {
      if total == 0 {
          return MAX_COST;
      }
      let s = sample_at(index);
      if (s as i64).unsigned_abs() >= self.clip_guard {
          return MAX_COST;
      }
      let w = self.window.max(1);
      let lo = index.saturating_sub(w);
      let hi = (index + w + 1).min(total);
      let count = (hi - lo).max(1) as f64;
      let mut sum_abs = 0.0f64;
      for i in lo..hi {
          let v = (sample_at(i) as f64) / self.scale;
          sum_abs += v.abs();
      }
      let local_energy = sum_abs / count;
      ...
  ```
- **问题分析**：
  对于 5 分钟 48kHz 立体声 WAV（约 $2.88 \times 10^7$ 个样本），在计算每个候选槽位的代价时，`cost_at` 都会对 `[index - 16, index + 16]` 共 33 个样本调用 `sample_at(i)`（从底层字节切片按位宽解码为 `i32`、转 `f64`、除以 `self.scale`、取绝对值求和）。这导致同一个样本被重复解码和浮点除法多达 33 次（对于全量代价计算相当于约 **9.5 亿次** 样本解码与浮点除法）！
- **修复建议**：
  对于连续或高密度槽位评估，使用一维滑动窗口或前缀和数组（Prefix Sum of `|sample[i]|`），将单槽位局部能量计算复杂度从 $O(2W+1)$ 降至严格的 $O(1)$ 整数加减。

---

### [PERF-04] MKV 内容域嵌入未接入补丁式提交（`embed_hevc_patches`），导致 GB 级 MKV 全量驻留内存并扫描两遍
- **严重度**：P1（高危 / 大文件内存峰值与 I/O 退化）
- **定位**：
  - `rust/src/stego/io.rs:59-62`
  - `rust/src/stego/engine.rs:906-924`
  - `rust/src/stego/hevc/mkv_boxes.rs:603-636`
- **代码实证**：
  ```rust
  // rust/src/stego/io.rs:59-62
  #[cfg(feature = "content-hevc")]
  if matches!(format, FileFormat::Mp4 | FileFormat::HevcAnnexB) {
      return embed_hevc_file_Streaming(carrier_path, format, payload, opts, dialect, target);
  }
  ```
  而对于 `FileFormat::Mkv`，`embed_carrier_file` 落入第 `81` 行的通用路径：
  1. `fs::read(carrier_path)` 将整个 MKV 文件读入 `Vec<u8>`；
  2. `embed_hevc_with_info`（`hevc/engine.rs:852`）再执行 `let mut out_carrier = carrier.to_vec();`（内存中同时驻留 **2 份完整 MKV 文件**）；
  3. 随后调用 `mkv_boxes::refresh_mkv_crcs(carrier, &mut out_carrier)`（`mkv_boxes.rs:603-636`）：
     ```rust
     pub fn refresh_mkv_crcs(original: &[u8], out: &mut [u8]) -> Result<usize, HevcError> {
         let parsed = parse_mkv_targets(original)?;
         if parsed.crc_spans.is_empty() {
             return Ok(0);
         }
         let dirty = changed_ranges(original, out);
     ```
     其中 `parse_mkv_targets(original)` 把整个 MKV 文件又从头解析了一遍，而 `changed_ranges(original, out)`（第 `641-660` 行）更是逐字节比对两个 GB 级切片的每一个字节（`for i in 0..len { if a[i] != b[i] ... }`）来寻找哪些字节被改了——明明 `patches: Vec<BytePatch>` 已经精确记录了每一个被修改的字节偏移！
- **修复建议**：
  1. 将 `refresh_mkv_crcs` 改为直接接收 `&[BytePatch]` 和 `parse_mkv_targets` 已解析出的 `crc_spans`，生成的 CRC-32 更新也作为 `BytePatch` 追加到补丁列表中。
  2. 在 `rust/src/stego/io.rs:60` 将 `FileFormat::Mkv` 纳入 `embed_hevc_file_streaming`（即 `FileFormat::Mp4 | FileFormat::Mkv | FileFormat::HevcAnnexB`），实现与 MP4 相同的流式 Patch 提交。

---

### [PERF-05] `compress_stream` 在内存中全量缓冲压缩流；`read_core` 先全量解密进 `Vec<u8>` 后才检查 `MAX_VERIFY_PAYLOAD_SIZE`
- **严重度**：P2（中危 / 流式管线退化为全内存缓冲）
- **定位**：
  - `rust/src/core/crypto.rs:531-552`
  - `rust/src/structure/engine.rs:1637-1653`
- **代码实证**：
  ```rust
  // rust/src/core/crypto.rs:537-542
  let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
  loop {
      control.check()?;
      let n = reader.read(&mut buf)?;
      if n == 0 { break; }
      encoder.write_all(&buf[..n])?;
  }
  let compressed = encoder.finish()?;
  writer.write_all(&compressed)?;
  ```
  ```rust
  // rust/src/structure/engine.rs:1637-1653
  let mut compressed_buf = Vec::new();
  crypto::decrypt_payload_chunks_with_control(
      stego_in, ..., &mut compressed_buf, options.control,
  )?;
  if options.output_path.is_none() && compressed_buf.len() as u64 > MAX_VERIFY_PAYLOAD_SIZE {
      return Err(StrHideError::Capacity(...));
  }
  ```
- **问题分析**：
  1. `compress_stream` 虽然接收 `writer: &mut W`（在 `engine.rs:943` 中是一个磁盘临时文件 `SpooledTempFile`），但内部却用 `DeflateEncoder::new(Vec::new(), ...)` 把所有压缩后的数据先攒在内存 `Vec<u8>` 中，完全失去了传入 `writer: &mut W` 流式溢写磁盘的意义。
  2. `read_core` 在 `options.output_path.is_none()`（内存模式）下，先将所有加密块解密追加到内存 `compressed_buf: Vec<u8>` 中，等全部解密完成后（第 `1648` 行）才检查 `compressed_buf.len() > MAX_VERIFY_PAYLOAD_SIZE (256 MiB)`；其实在解密前就已经知道 `payload_encrypted_len`，应当在分配和解密前直接拦截。
- **修复建议**：
  1. 在 `compress_stream` 中使用计数包装器直接将 `DeflateEncoder` 绑定到 `&mut writer`（`DeflateEncoder::new(&mut counting_writer, ...)`）。
  2. 在 `read_core` 进入 `decrypt_payload_chunks_with_control` **之前**检查 `if options.output_path.is_none() && payload_encrypted_len > MAX_VERIFY_PAYLOAD_SIZE + ...`。

---

## 8. 维度六：代码可靠性与稳定性（Code Reliability, Security & Stability）

### [REL-01] GUI `smart_extract_impl` 路径穿越漏洞（Arbitrary File Overwrite）
- **严重度**：**P0（严重 / 安全漏洞：任意文件写入/覆盖）**
- **定位**：
  - `gui/src-tauri/src/commands/stego.rs:375-383, 406-428`
  - `rust/src/facade.rs:424-436`
  - `rust/src/structure/engine.rs:1728-1740`
- **代码实证**：
  当通过 `StrHide::smart_extract`（`rust/src/facade.rs:424-436`）读取结构域载体时，内部调用 `self.structure().read_file(path, &ReadOptions { output_path: None, ... })`。
  在 `rust/src/structure/engine.rs:1728-1740` 中，当 `output_path` 为 `None` 时：
  ```rust
  // rust/src/structure/engine.rs:1728-1740
  Ok(ReadResult {
      carrier: carrier_path.to_path_buf(),
      data: raw_data,
      is_file: meta.is_file,
      is_encrypted: header.is_encrypted,
      filename: meta.filename, // <-- 注意：此处直接返回了未消毒的原始 meta.filename！
      raw_size,
      written_file,
  })
  ```
  接着，`facade.rs:433` 将 `res.filename` 放入 `Payload::owned_file(res.filename, res.data)` 返回给 GUI 的 `smart_extract_impl`（`gui/src-tauri/src/commands/stego.rs:375-428`）：
  ```rust
  // gui/src-tauri/src/commands/stego.rs:375-383, 406-428
  let filename = payload.name.clone().unwrap_or_else(|| {
      (if is_file { "payload.bin" } else { "payload.txt" }).to_string()
  });
  ...
  let target_file = if dest.is_dir() {
      let mut candidate = dest.join(&filename);
      ...
      candidate
  } else {
      dest.clone()
  };
  write_bytes_atomic(&target_file, &payload.data)?;
  ```
- **问题分析**：
  1. 在 Rust 标准库中，`Path::join` 如果遇到绝对路径（如 `/etc/cron.d/pwn` 或 `C:\Users\...\Startup\pwn.bat`）会**直接替换掉 `dest`**；如果遇到相对路径穿越（如 `../../../.bashrc`），则会跳出用户选定的目标目录 `dest`！
  2. CLI 的 `cmd_stego.rs:650` 和 `cmd_structure.rs:414` 都显式调用了 `sanitize_filename`，但 GUI 的 `smart_extract_impl`（以及 `structure/engine.rs:1734` 返回的 `ReadResult.filename`）**完全没有调用 `sanitize_filename`**！
  3. 攻击者只需构造一个包含恶意 `meta.filename`（如 `"../../.ssh/authorized_keys"`）的载体文件发给受害者，当受害者在 StrHide Studio GUI 中使用智能提取（Smart Extract）并选择保存到任意文件夹时，`write_bytes_atomic` 就会在受害者机器上跨目录写入/覆盖任意文件！
- **修复建议**：
  1. 在 `rust/src/structure/engine.rs:1734` 生成 `ReadResult` 时，或在 `EnvelopeMetadata::unpack_binary`（`structure/envelope.rs:351`）反序列化出口处，统一对 `meta.filename` 调用 `sanitize_filename`（与 `stego/envelope.rs:314` 保持一致，在源头根除未消毒文件名）。
  2. 在 `gui/src-tauri/src/commands/stego.rs:270, 375` 中，对 `payload.name` 强制调用 `strhide::core::fs::sanitize_filename`。

---

### [REL-02] PNG `Structure -> Content` 双域共存导致 Stealth 信封丢失、`verify_carrier` 失败/Panic 及 `restore` 截断损坏 PNG 载体
- **严重度**：**P0（严重 / 数据损坏与 Debug Panic）**
- **定位**：
  - `rust/src/structure/adapters/png.rs:268-280, 314-319`
  - `rust/src/structure/engine.rs:2458, 2499`
  - `rust/src/structure/adapters/mod.rs:231-244`
- **代码实证**：
  先看 `rust/src/structure/adapters/png.rs:268-280`：
  ```rust
  // Fast path: exact offset match (pure structure-domain carrier).
  // Fallback path: if content-domain steganography later re-compressed IDAT,
  // the physical offset of `prIv` shifted. Accept the chunk if its payload
  // starts with the standard UBE header magic and its length matches the trailer.
  let is_valid_shifted = if chunk_data_len >= 8 {
      let mut hdr = [0u8; 8];
      stego_in.seek(SeekFrom::Start(chunk_data_offset))?;
      stego_in.read_exact(&mut hdr)?;
      hdr == crate::params::STANDARD_HEADER_MAGIC
  } else {
      false
  };
  ```
  再看 `verify_core`（`rust/src/structure/engine.rs:2458, 2499`）：
  ```rust
  // line 2458
  if !envelope_coordinates_agree(&header, &trailer, ube_offset, ube_size, stego_size) {
      res.level2_envelope = LevelStatus::fail("Envelope internal offset/size mismatch");
      return Ok(res);
  }
  ...
  // line 2499
  debug_assert_eq!(trailer.ube_offset, ube_offset);
  ```
  再看 `remove_carrier` 调用的 `PngAdapter::strip`（使用 `HostAdapter::strip` 默认实现，`rust/src/structure/adapters/mod.rs:231-244`）：
  ```rust
  fn strip(
      &self,
      stego_in: &mut dyn ReadSeek,
      restored_out: &mut dyn Write,
      header: &EnvelopeHeader,
      ube_total_size: u64,
  ) -> Result<(), StrHideError> {
      let file_size = io::stream_len(stego_in)?;
      let inject_end = header.inject_offset + ube_total_size + self.injection_overhead();
      io::copy_Warning_or_range(stego_in, restored_out, 0, header.inject_offset)?;
      if inject_end < file_size {
          io::copy_range(stego_in, restored_out, inject_end, file_size - inject_end)?;
      }
      Ok(())
  }
  ```
- **问题分析**：
  当用户对同一个 PNG 先执行结构域写入（`write`，注入 `prIv` 块），再执行内容域嵌入（`embed`，重压缩 `IDAT` 块导致 `IDAT` 长度变化，`prIv` 块的物理偏移从 $O_{\text{old}}$ 移动到了 $O_{\text{new}}$）时，存在 **3 个连锁严重 Bug**：
  1. **Bug A（Stealth 与私有方言在偏移变化后完全丢失）**：`png.rs:273` 硬编码了 `hdr == crate::params::STANDARD_HEADER_MAGIC`，忽略了传入 `locate` 的 `custom_magic: Option<&[u8; 8]>`！因此只要结构域写入时启用了 `--stealth` 或自定义方言，内容域重压缩 `IDAT` 后 `PngAdapter::locate` 就会返回 `Ok(None)`，结构域载荷永久无法读取！
  2. **Bug B（`verify_carrier` 校验必败 + Debug Panic）**：即使使用默认魔数，`PngAdapter::locate` 返回了新的物理偏移 `ube_offset = chunk_data_offset`（$O_{\text{new}}$），但信封内部的 `header.inject_offset` 和 `trailer.ube_offset` 依然记录着旧偏移 $O_{\text{old}}$！调用 `verify_carrier` 时，`envelope_coordinates_agree`（`engine.rs:1456`）检查 `header.inject_offset + 8 == ube_offset` 必然返回 `false`，导致 Level 2 报错 `"Envelope internal offset/size mismatch"`；且若绕过该检查，第 `2499` 行的 `debug_assert_eq!(trailer.ube_offset, ube_offset)` 会直接 Panic！
  3. **Bug C（`restore` 截断损坏 PNG 图像）**：`PngAdapter` 没有重写 `strip()`，而是直接继承了 `HostAdapter::strip` 的默认实现（按 `header.inject_offset` 物理偏移切掉 `ube_total_size + 12` 字节）。当 `IDAT` 长度在内容域嵌入后发生变化时，`header.inject_offset`（旧偏移）已经不再指向 `prIv` 块的起始位置，而是指向 `IDAT` 内部或 `IEND` 附近！此时执行 `sth restore` 会直接从 `IDAT` 中间切掉一段数据，不仅没有移除 `prIv` 块，反而**彻底损坏恢复出的 PNG 文件**（且随后因 SHA-256 不匹配才报错，若 `output_path` 已进入提交流程则极其危险）！
- **修复建议**：
  1. 在 `PngAdapter::locate`（`png.rs:273`）中使用 `let expected_magic = custom_magic.unwrap_or(&crate::params::STANDARD_HEADER_MAGIC); hdr == *expected_magic`。
  2. 为 `PngAdapter` 实现专属的 `strip()` 方法：通过扫描 PNG Chunk 定位实际的 `prIv` 块起止偏移（`chunk_start = chunk_data_offset - 8`）进行剥离，而不是盲目信任可能因 `IDAT` 重压缩而陈旧的 `header.inject_offset`。
  3. 在 `verify_core` 中识别 `Format::Png` 下 `prIv` 块整体平移的合法情形（`ube_offset - 8` 恰为合法的 `prIv` 块头且 `trailer.ube_offset == header.inject_offset + 8`），并移除错误的 `debug_assert_eq!(trailer.ube_offset, ube_offset)`。

---

### [REL-03] `commit_carrier_patches` 在源载体只读（Read-Only）时，即使输出到新路径 `-o` 也会报 `PermissionDenied`
- **严重度**：P1（高危 / 文件系统权限故障）
- **定位**：`rust/src/core/commit.rs:226-235`
- **代码实证**：
  ```rust
  // rust/src/core/commit.rs:226-235
  let mut tmp_file = NamedTempFile::new_in(parent)?;
  let tmp_path = tmp_file.path().to_path_buf();

  // Copy original carrier to temp file (uses OS-level fast copy / sendfile / CopyFileEx)
  std::fs::copy(carrier_path, &tmp_path)?;

  // Apply patches in-place on the temp file
  let mut file = OpenOptions::new().read(true).write(true).open(&tmp_path)?;
  ```
- **问题分析**：
  当用户对一个只读（Read-Only，例如 `chmod 444 video.mp4` 或 Windows 只读属性）的 MP4 / Annex-B HEVC 载体执行非原地隐写（如 `sth embed ro_video.mp4 -t "secret" -o out_video.mp4`）时：
  1. `std::fs::copy(carrier_path, &tmp_path)` 在 Linux/macOS/Windows 上会将源文件的**只读权限位（`0444` / `FILE_ATTRIBUTE_READONLY`）一并复制到 `tmp_path`**！
  2. 紧接着第 `233` 行 `OpenOptions::new().read(true).write(true).open(&tmp_path)?` 尝试以可写模式打开刚刚变成只读的 `tmp_path`，立即触发 `PermissionDenied` 错误！
- **修复建议**：
  在 `std::fs::copy(carrier_path, &tmp_path)?` 之后、`OpenOptions::new().read(true).write(true).open(&tmp_path)` 之前，检查 `tmp_path` 的权限，若 `perms.readonly()` 为 `true`，则先将其设为可写（或在已打开的 `tmp_file.as_file_mut()` 上直接 `std::io::copy` + `seek` 打补丁，无需再次 `OpenOptions::open`）！

---

### [REL-04] `preflight_batch` 路径碰撞检查对输入载体与输出目标使用不一致的规范化策略，且漏检“输出覆盖同批输入载体”
- **严重度**：P2（中危 / 批处理安全预检漏洞）
- **定位**：`rust/src/core/pipeline.rs:187-233`
- **代码实证**：
  ```rust
  // rust/src/core/pipeline.rs:187-225
  let mut seen_carriers: HashSet<PathBuf> = HashSet::new();
  let mut seen_targets: HashSet<PathBuf> = HashSet::new();
  for carrier in batch.carriers {
      ...
      let canonical = std::fs::canonicalize(carrier).unwrap_or_else(|_| carrier.clone());
      if !seen_carriers.insert(canonical) {
          return Err(StrHideError::General(format!(
              "Carrier '{}' is listed more than once in the same command",
              carrier.display()
          )));
      }
      if let Some( validator ) = batch.validate {
          validator(carrier)?;
      }
      let target =
          resolve_carrier_target(carrier, batch.in_place, batch.output, batch.output_dir)?;
      if let Some(t) = target {
          if !seen_targets.insert(t.clone()) {
              return Err(StrHideError::General(format!(
                  "Multiple carriers would write to the same output file '{}'",
                  t.display()
              )));
          }
          check_overwrite(&t, batch.overwrite)?;
      }
  }
  ```
- **问题分析**：
  1. `seen_carriers` 存入的是 `canonicalize(carrier)`，而 `seen_targets` 存入的却是未规范化的 `t.clone()`。
  2. **漏检“载体 A 的输出路径恰好是同批次中载体 B 的输入路径”**：例如用户在 `--overwrite` 下执行 `sth write dir1/a.png dir2/a_stego.png --overwrite`（其中 `dir1 == dir2` 或通过软链接指向同一目录），第一个载体 `a.png` 的默认输出 `a_stego.png` 会在批处理中途直接覆盖第二个待处理载体 `a_stego.png`！
- **修复建议**：
  对已存在的 `t`（或其父目录 + 文件名）同样执行规范化，并检查 `seen_targets` 与 `seen_carriers` 之间是否存在交集（在非 `in_place` 模式下禁止任何载体的输出路径命中同批次中的另一个输入载体）。

---

### [REL-05] GUI `CachedExtract` 缓存键遗漏 `domain` 与 `prefer`，且 `extract_stego_file_cmd` 误判 `is_encrypted`
- **严重度**：P2（中危 / GUI 状态与缓存一致性 Bug）
- **定位**：
  - `gui/src-tauri/src/state.rs:16-21`
  - `gui/src-tauri/src/commands/stego.rs:268-269, 333-348`
- **代码实证**：
  ```rust
  // gui/src-tauri/src/state.rs:16-21
  #[derive(Clone)]
  pub struct CachedExtract {
      pub path: std::path::PathBuf,
      pub mtime: Option<std::time::SystemTime>,
      pub password: Option<String>,
      pub outcome: strhide::facade::ExtractOutcome,
  }
  // gui/src-tauri/src/commands/stego.rs:337
  if c.path == path && c.mtime == mtime && c.password == password {
      Some(c.outcome.clone())
  }
  ```
  以及 `gui/src-tauri/src/commands/stego.rs:268-269`：
  ```rust
  let is_file = payload.kind == PayloadKind::File;
  let is_encrypted = password.is_some_and(|p| !p.is_empty())
      || engine.dialect().stego.secret().is_some();
  ```
- **问题分析**：
  1. **缓存键缺失 `domain` 与 `prefer`**：当一个 PNG/JPEG/MP4 同时包含结构域和内容域载荷（Dual-Domain Carrier）时，用户在 GUI 中先用默认 `prefer` 提取了结构域载荷，随后将提取偏好切换为 `Domain::Content`（或修改了 `domain` 参数）再次点击提取，由于 `path`、`mtime`、`password` 未变，`smart_extract_impl` 直接命中缓存并返回上一次的结构域载荷，导致用户无法在 GUI 中切换到另一隐写域！
  2. **`extract_stego_file_cmd` 凭调用方参数臆测 `is_encrypted`**：当载体本身并未加密（`Codec::Raw` 或默认公开密钥），但用户在密码框中填入了密码（内容域头部若未加密，部分路径或未来扩展下），或者反过来需要真实反映载体头部的 `Codec::Encrypted` 状态时，`extract_stego_file_cmd` 没有像 `facade.rs:463` 那样从载体 Header 的 `Codec` 读取 `encrypted` 标志，而是直接根据 `password.is_some()` 赋值。
- **修复建议**：
  在 `CachedExtract` 中加入 `domain: Option<String>` 和 `prefer: Option<Domain>` 字段并参与相等性比较；在 `extract_carrier_file_payload`（或 `Payload` 元数据）中返回载体真实的 `is_encrypted` 布尔标志。

---

### [REL-06] GUI `run_batch_job_cmd` 丢弃进度通道 `_ctrl` 导致批量任务无进度事件，且批量 `restore` 硬编码强制备份
- **严重度**：P2（中危 / GUI 批处理体验与控制缺陷）
- **定位**：
  - `gui/src-tauri/src/commands/batch.rs:52, 91-98`
  - `rust/src/core/batch.rs:144-149`
- **代码实证**：
  ```rust
  // gui/src-tauri/src/commands/batch.rs:48-58
  run_cancellable_task(
      &state,
      task_id,
      on_progress,
      move |engine, pool, _ctrl, token| {
          let plan = BatchPlan {
              continue_on_error: job.continue_on_error,
              max_concurrency: job.max_concurrency.max(1),
              cancel: Some(token),
              ctx: Some(RenderCtx::new(i18n::lang())),
          };
  ```
- **问题分析**：
  1. `run_batch_job_cmd` 将 `run_cancellable_task` 传入的 `_ctrl` 直接丢弃，而 `core/batch.rs:146` 在每个子任务中构造的是 `Control { progress: &NoopProgress, cancel: ... }`。因此 GUI 前端传入 `run_batch_job_cmd` 的 `on_progress: Channel<ProgressEvent>` 在整个批处理过程中**永远收不到任何一条进度更新**（0% 直跳结束）。
  2. 在 `batch.rs:91-98` 的 `"restore"` 分支中，硬编码了 `backup: true, overwrite: true`，`BatchJobSpec` 没有提供 `backup: Option<bool>` 字段，导致用户在批量恢复大量文件时无法关闭 `.bak` 备份文件生成。
- **修复建议**：
  在 `run_batch_job_cmd` 中使用 `AtomicU64` 统计已完成的文件数，每完成一个文件调用 `ctrl.report(Stage::Verify /* 或 Batch */, done, Some(items.len() as u64))` 向前端推送批量进度；并在 `BatchJobSpec` 中增加 `pub backup: Option<bool>`。

---

### [REL-07] `inspect_hevc_mp4_file` 将 `u64` 文件长度与 Box 长度直接 `as usize`
- **严重度**：P3（低危 / 32 位平台溢出截断风险）
- **定位**：`rust/src/stego/hevc/engine.rs:1921, 1951`
- **代码实证**：
  ```rust
  // rust/src/stego/hevc/engine.rs:1921, 1951
  let file_len = file.metadata()?.len() as usize;
  ...
  moov_box = Some((pos, total_size as usize));
  ```
- **问题分析**：
  `inspect_hevc_mp4_file` 专为避免将数 GB 的大体积 MP4 读入内存而设计（通过 `File` + `Seek` 流式定位），但在第 `1921` 行却把 `u64` 的 `file.metadata()?.len()` 直接强转为 `usize`。在 32 位目标架构（如 `wasm32` 或 `armv7`）上处理 `> 4 GiB` 的 MP4 文件时，`file_len` 会发生整数截断，导致第 `1938` 行 `pos + total_size > file_len as u64` 提前中断 Box 解析并报 `"MP4 file missing moov or mdat box"`。
- **修复建议**：
  将 `file_len` 保持为 `u64` 类型，仅在分配 `moov_buf` 等内存切片时使用 `usize::try_from(moov_len)` 并校验上限。

---

## 9. 维度七：算法和业务逻辑（Algorithms, Steganography & Container Business Logic）

### [LOGIC-01] HEVC `embed_hevc_patches_with_factor` 因 `StopCondition::TargetSlots` 提前终止采样，导致 `--enforce-safety` 误杀合法载荷且返回的 `StegoCapacityInfo` 严重失真
- **严重度**：**P0（严重 / 核心业务逻辑计算错误）**
- **定位**：`rust/src/stego/hevc/engine.rs:864-881`（以及 `614-682`）
- **代码实证**：
  请看 `rust/src/stego/hevc/engine.rs:864-881`：
  ```rust
  let desired_body_slots = (body_needed_slots as f64 / min_fraction).ceil() as usize;
  let target_slots = HEVC_SUPERBLOCK_POOL_SLOTS
      .saturating_add(desired_body_slots)
      .saturating_add(128);
  let record = record_carrier_state(
      carrier,
      kind,
      Capture::Full,
      StopCondition::TargetSlots(target_slots),
      control,
  )?;

  let pool = PoolProfile::from_record(&record);
  let capacity_info = build_hevc_capacity_info(carrier, kind, fmt, &pool, safety.level)?;
  enforce_safety(
      payload.len(),
      capacity_info.recommended_max_bytes,
      capacity_info.total_elements,
      safety,
  )?;
  ```
  再看 `build_hevc_capacity_info`（`hevc/engine.rs:647-680`）：
  ```rust
  let usable_body_slots = total_slots.saturating_sub(HEVC_SUPERBLOCK_MIN_SLOTS);
  let budget = safety_level.video_budget();
  let gate_slots = (usable_body_slots as f64 * budget.non_ref_fraction).floor() as usize;
  let non_ref_slots = (pool.band_slots[0] as f64 * budget.non_ref_fraction).floor() as usize;
  let ref_slots = pool.band_slots[1].min(
      pool.band_pictures[1].saturating_mul(budget.ref_flips_per_picture),
  );
  let ladder_slots = non_ref_slots.saturating_add(ref_slots);
  let safe_body_slots = if pool.has_band_split() {
      ladder_slots.min(gate_slots)
  } else {
      gate_slots
  };
  let recommended_max_bytes = codec.max_payload_for_slots(safe_body_slots, ...);
  ```
- **问题分析**：
  为了加速视频嵌入，`embed_hevc_patches_with_factor` 使用了 `StopCondition::TargetSlots(target_slots)`，即**一旦解码出的总槽位数达到当前载荷所需的 `target_slots`，就立刻停止解析后续视频帧**！
  然而紧接着在第 `873-874` 行，代码竟然把这半截 `record`（仅包含视频前几帧的槽位）传给 `PoolProfile::from_record(&record)` 和 `build_hevc_capacity_info` 来计算整个视频的 `StegoCapacityInfo` 和 `recommended_max_bytes`！
  这引发了两个直接后果：
  1. **返回的 `StegoCapacityInfo` 完全错误**：对于一个本来有 1,000,000 个槽位（可安全容纳 20 KB）的长视频，如果用户只嵌入 100 字节载荷，`record` 在收集约 6,500 个槽位后停止，结果 `embed` 返回给 CLI 和 GUI 的容量报告显示该视频总共只有 6,500 个槽位、最大推荐容量只有约 100 字节（已用容量百分比永远显示接近 `100%`）！
  2. **`--enforce-safety` 误杀完全合法的载荷**：
     假设视频前几帧主要是参考帧（Band 1，这在 GOP 开头 I/P 帧中极其常见，因为每個视频流都以 IDR/I 帧和参考 P 帧开头，之后才出现非参考 B 帧！）。`target_slots` 在前几个 I/P 帧就凑够了槽位并停止了扫描。此时截断的 `pool` 中 `band_slots[0] = 0`，`band_pictures[1]` 只有前 2~3 张参考帧（`ref_slots = 3 * 220 = 660` 槽位，仅够约 40 字节载荷）！结果 `build_hevc_capacity_info` 算出的 `recommended_max_bytes` 只有几十字节，紧接着第 `875` 行的 `enforce_safety` **直接报错拒绝嵌入**——尽管该视频后面还有成千上万个非参考 B 帧，且 `sth capacity` 探测出的安全容量高达数十 KB！
- **修复建议**：
  1. `StopCondition::TargetSlots` 不能只按总槽位数停止，而必须确保收集到的 **Band 0（非参考帧）和 Band 1（受每帧上限约束的参考帧）有效安全预算槽位数** 达到 `body_needed_slots`，或者当 `safety.enforcement == SafetyEnforcement::Enforced` / 需要完整 `StegoCapacityInfo` 时，使用快速容器/Slice 扫描获取真实的 `PoolProfile`。
  2. 至少在 `TargetSlots` 停止条件中，应当保证 `safe_body_slots >= body_needed_slots` 后才允许停止扫描，否则继续向后扫描后续的 B 帧。

---

### [LOGIC-02] `pe_codebits` 的 `ChannelHeader` 掩码完全由明文 `magic` 派生（无密钥 HKDF），任何无密码观察者均可直接解盲，彻底击穿 Stealth 契约
- **严重度**：**P0（严重 / 密码学与隐身模式设计缺陷）**
- **定位**：
  - `rust/src/structure/adapters/pe_codebits.rs:369-427, 504-508`
  - `rust/src/structure/adapters/pe.rs:680-687`
  - `rust/src/core/crypto.rs:238-244`
- **代码实证**：
  请看 `rust/src/core/crypto.rs:238-244`：
  ```rust
  /// Derive the 10-byte XOR mask for `pe_codebits` [`ChannelHeader`] bytes `4..14`
  /// from the 4-byte channel magic.
  pub fn derive_channel_header_mask(magic: &[u8; 4]) -> [u8; 10] {
      let hk = Hkdf::<Sha256>::new(None, magic);
      let mut out = [0u8; 10];
      hk.expand(b"strhide-pe-channel-mask-v1", &mut out)
          .expect("10 bytes is a valid HKDF-SHA256 output length");
      out
  }
  ```
  再看 `ChannelHeader::pack_masked` 与 `unpack_masked`（`rust/src/structure/adapters/pe_codebits.rs:369-427`）：
  ```rust
  pub fn pack_masked(&self) -> [u8; CHANNEL_HEADER_SIZE] {
      let mut buf = self.pack(); // buf[0..4] = self.magic (明文!)
      let mask = crate::crypto::derive_channel_header_mask(&self.magic);
      for i in 0..10 {
          buf[4 + i] ^= mask[i];
      }
      buf
  }
  ```
  以及 `pe_codebits.rs:504-508`（`verify_structure`）和 `pe.rs:680-687`（`suspicious_structures`）：
  ```rust
  // rust/src/structure/adapters/pe_codebits.rs:506-508
  let candidate_magic: [u8; 4] = hdr_bytes[0..4].try_into().unwrap();
  if let Some(ch_hdr) = ChannelHeader::unpack_masked(&hdr_bytes, &candidate_magic) {
  ```
- **问题分析**：
  `WIRE_SPEC.md:443` 明确规定 Stealth 模式下的 `ChannelHeader` 应当对无密码检测者不可识别。
  然而在当前实现中：
  1. `buf[0..4]` 原封不动地以明文存储了 4 字节 `self.magic`（即使是密码派生的隐身魔数，这 4 个字节也直接暴露在 `buf[0..4]` 中）。
  2. 后面的 10 个字节 `buf[4..14]`（包含 `version = 1`、`flags = 0`、`ube_len`、`slack_off`）是用 `derive_channel_header_mask(&self.magic)` 异或掩码的——而这个 HKDF 的输入参数**仅仅就是明文写在 `buf[0..4]` 里的那 4 个字节 `magic`**，根本没有任何密码或密钥参与！
  3. 正如 `pe_codebits.rs:507` 和 `pe.rs:683` 自己所写的那样：**任何没有密码的第三方分析器，只要把前 4 个字节 `hdr_bytes[0..4]` 当作 `candidate_magic` 传给 `derive_channel_header_mask`，就能 100% 还原出明文的 `version == 1`、`flags == 0`、`ube_len` 和 `slack_off`**！这意味着该掩码在密码学上等价于**完全明文（零保密性）**，`strhide scan` 甚至不用密码就能在 `pe.rs:683` 直接解开 Stealth 模式的 `ChannelHeader` 并告警！
- **修复建议**：
  `derive_channel_header_mask` 不能仅以明文暴露在 `buf[0..4]` 的 4 字节 `magic` 作为 IKM；应当从密码/方言密钥派生独立的 10 字节掩码（或由完整 8 字节 `stealth_header_magic` 的后 4 字节——即未写入 `buf[0..4]` 的部分——作为 HKDF IKM 派生 `buf[4..14]` 的掩码），从而保证未持有密码的观察者无法仅凭 `buf[0..4]` 解盲 `buf[4..14]`。

---

### [LOGIC-03] PDF 适配器三大缺陷：(1) `read_xref_stream_dict` 遇嵌套字典 `>>` 提前截断导致漏检 `/Encrypt` 与 `/Root`；(2) 向 PDF 1.5+ XRef Stream 文档追加经典 `xref` 表违反 ISO 32000-1；(3) `eof` 模式 >1 MiB 文件漏做增量更新
- **严重度**：**P0（严重 / 容器规范违背与加密 PDF 误改损坏）**
- **定位**：
  - `rust/src/structure/adapters/pdf.rs:108, 182-186, 653-671`
- **代码实证**：
  1. **缺陷 1（嵌套字典 `>>` 提前截断，`pdf.rs:182-186`）**：
     ```rust
     // rust/src/structure/adapters/pdf.rs:182-186
     let text = String::from_utf8_lossy(&buf[..n]);
     let open = text.find("<<")?;
     let after_open = &text[open + 2..];
     let close = after_open.find(">>")?;
     let dict_text = &after_open[..close];
     ```
     在现代 PDF（PDF 1.5+）中，XRef Stream 对象几乎总是带有預測器参数嵌套字典，例如：
     `<< /Type /XRef /DecodeParms << /Columns 5 /Predictor 12 >> /Size 150 /Root 1 0 R /Encrypt 2 0 R /Length 400 >>`
     由于 `after_open.find(">>")` 只是搜索第一个 `">>"` 子串，它会**直接停在内层 `/DecodeParms << ... >>` 的闭合 `>>` 处**！
     结果：排在 `/DecodeParms` 后面的 `/Root`、`/Size`、`/Encrypt`（甚至 `/Type /XRef`）全部被截断丢弃！
     - 若 `/Type /XRef` 在 `/DecodeParms` 之后，`parse_xref_stream_info` 直接返回 `None`，导致所有带 `/DecodeParms` 的现代 PDF 1.5+ 文件全部无法使用 `pdf_ incremental` 策略！
     - 若 `/Type /XRef` 在前而 `/Encrypt` 在 `/DecodeParms` 之后，`check_pdf_encrypted` 漏检 `/Encrypt`，本应被拒绝的加密 PDF 被强行注入未加密对象，损坏原文档！
  2. **缺陷 2（向纯 XRef Stream PDF 追加经典 `xref` 表违反 ISO 32000-1 §7.5.8.4，`pdf.rs:653-671`）**：
     当原 PDF 使用 PDF 1.5+ Cross-Reference Stream（无传统 `xref` 表）时，`PdfAdapter::inject` 依然在文件末尾追加传统的 ASCII `xref\n0 1\n... trailer << /Size ... /Prev ... >>`。根据 ISO 32000-1 §7.5.8.4，纯 XRef Stream 文档的增量更新也必须使用 Cross-Reference Stream 对象（或混合引用流格式），直接用传统 `trailer << /Prev offset >>` 指向一个间接流对象（`N 0 obj << /Type /XRef ... >>`）在严格 PDF 解析器（如 Adobe Acrobat 预检、pdfcpu、qpdf）中属于语法错误（因为传统 `/Prev` 期望指向关键字 `xref` 而非数字对象头 `N 0 obj`）。
  3. **缺陷 3（`verify_structure` 对 >1 MiB PDF 的 `eof` 信封不读 Trailer，`pdf.rs:101-116`）**：
     `pdf.rs:108` 同样调用了 `EnvelopeTrailer::read_from_tail(stego_in, None)`，导致任何大于 1 MiB 的 Stealth PDF 载体在 `verify_structure` 时无法剔除尾部信封，若信封超出 1024 字节尾部搜索窗口则直接因找不到 `%%EOF` 而判定 PDF 宿主结构损坏！
- **修复建议**：
  1. 将 `read_xref_stream_dict` 改为按深度匹配的 `<<` / `>>` 括号计数器（遇到 `<<` 深度 +1，遇到 `>>` 深度 -1，直到深度归零才截取字典），彻底解决 `/DecodeParms << ... >>` 截断问题。
  2. 对于使用 Cross-Reference Stream 的 PDF，在 `pdf_incremental` 注入时生成配套的 `/Type /XRef` 流对象（或在 `strategy_capacities` 中对纯 XRef Stream 优先引导或构造合规的 XRef Stream 增量更新）。

---

### [LOGIC-04] `EnvelopeHeader::unpack_with_secrets` 在检查明文 `FLAG_ENCRYPTED` 前先执行默认密钥解盲，且接受 `strategy_id == 0`
- **严重度**：P1（高危 / 信封头部解包误判风险）
- **定位**：`rust/src/structure/envelope.rs:491-518`
- **代码实证**：
  ```rust
  // rust/src/structure/envelope.rs:491-518
  // 2. Standard mode (unencrypted OR default-key encrypted): unmask with builtin key
  let default_mask = crypto::derive_header_mask(profile.secret(), &salt);
  let mut unmasked = [0u8; HEADER_SIZE];
  for i in 0..8 {
      unmasked[i] = data[i];
  }
  for i in 8..34 {
      unmasked[i] = data[i] ^ default_mask[i - 8];
  }
  if unmasked[0..8] == profile.magic.header
      && unmasked[8] == UBE_VERSION
      && (unmasked[9] & !KNOWN_FLAGS_MASK) == 0
      && unmasked[10] <= MAX_KNOWN_STRATEGY_ID
  {
      return Self::parse_fields(&unmasked);
  }

  // 3. Custom-password encrypted envelope (not stealth): header is NOT masked on wire
  if data[0..8] == profile.magic.header
      && data[8] == UBE_VERSION
      && (data[9] & FLAG_ENCRYPTED) != 0
  {
      return Self::parse_fields(data);
  }
  ```
- **问题分析**：
  当载体是一个**使用用户自定义密码加密的非 Stealth 信封**时：
  - 它在文件中的 `data[0..8]` 本身就等于 `profile.magic.header`，且 `data[8..34]` 是**未加掩码的明文**（`data[8] == 2`, `data[9] & FLAG_ENCRYPTED != 0`）。
  - 然而 `unpack_with_secrets` 却先执行步骤 2：把明文的 `data[8..34]` 异或上 `default_mask` 得到乱码 `unmasked`！
  - 因为 `unmasked[0..8]` 直接复制了 `data[0..8]`，所以 `unmasked[0..8] == profile.magic.header` **恒成立**！
  - 接下来只要随机伪随机流 `default_mask` 使得：
    - `unmasked[8] == 2`（概率 $1/256$）
    - `(unmasked[9] & 0b0100_1000) == 0`（6 个已知位任意，仅 2 个保留位为 0，概率 $1/4$）
    - `unmasked[10] <= 13`（共 14 个值 `0..=13`，注意 `0` 甚至不是合法的 `Strategy` ID！概率 $14/256$）
  - 联合概率为 $\frac{1}{256} \times \frac{1}{4} \times \frac{14}{256} \approx \frac{1}{18,724}$！也就是说，每约 1.8 万个随机盐值的自定义密码加密信封中，就有 1 个会在步骤 2 被误判命中，从而返回被 `default_mask` 异或破坏的垃圾 `EnvelopeHeader`（导致该载体哪怕输入正确密码也永远无法解出）！
- **修复建议**：
  1. **调换步骤 3 和步骤 2 的顺序**：先检查 `data` 是否已经是明文合法的 `FLAG_ENCRYPTED` 头部（`data[0..8] == profile.magic.header && data[8] == UBE_VERSION && (data[9] & FLAG_ENCRYPTED) != 0 && (data[9] & !KNOWN_FLAGS_MASK) == 0 && (1..=MAX_KNOWN_STRATEGY_ID).contains(&data[10])`），若是则直接解析返回（既消除了 $1/18,724$ 的误判率，又省去了 100,000 轮无谓的 PBKDF2 计算！）。
  2. 将策略 ID 范围校验从 `<= MAX_KNOWN_STRATEGY_ID` 收紧为 `(1..=MAX_KNOWN_STRATEGY_ID).contains(&...)`（排除非法的 `0`）。

---

### [LOGIC-05] WAV / WebP / MKV / >1 MiB PDF 的 `verify_structure`（Level 1）硬编码传入 `None` 魔数，导致所有 Stealth 或私有方言 `eof` 载体 Level 1 校验失败
- **严重度**：P1（高危 / Stealth 模式下容器校验失败）
- **定位**：
  - `rust/src/structure/adapters/riff.rs:235-244`
  - `rust/src/structure/adapters/mkv.rs:159-165`
  - `rust/src/structure/adapters/pdf.rs:106-112`
  - `rust/src/structure/adapters/mod.rs:251`
- **代码实证**：
  ```rust
  // rust/src/structure/adapters/riff.rs:235-244
  let effective_end = match EnvelopeTrailer::read_from_tail(stego_in, None) {
      Ok(Some(t))
          if t.ube_offset >= 12
              && t.ube_offset.saturating_add(t.ube_total_size) == file_size =>
      {
          t.ube_offset
      }
      _ => file_size,
  };
  ```
  同样的代码出现在 `rust/src/structure/adapters/mkv.rs:161` 和 `rust/src/structure/adapters/pdf.rs:108`：全部硬编码了 `EnvelopeTrailer::read_from_tail(stego_in, None)`！
- **问题分析**：
  当用户使用 `--stealth`（或自定义方言 `StructureProfile`）向 WAV、WebP、MKV 或 >1 MiB PDF 写入 `eof` 策略信封时，文件末尾 28 字节 Trailer 的最后 4 字节是**密码派生的 `stealth_trailer_magic`**，而不是 `STANDARD_TRAILER_MAGIC`。
  在 `verify_core`（`rust/src/structure/engine.rs:2402`）中，`adapter.verify_structure(&mut f)` 无法接收当前已派生的 `trailer_magic`，内部调用 `read_from_tail(stego_in, None)` 必然返回 `Ok(None)`，导致：
  - `riff.rs`（WAV / WebP）认为 `effective_end == file_size`，继而发现 `riff_end != effective_end`，直接报错：`RIFF size mismatch: header declares ..., file ends at ...`！
  - `mkv.rs`（MKV）尝试把追加在文件末尾的加密 UBE 字节当作 EBML Element 解析，触发 `Unexpected EOF in Element ID` 或 `Element size exceeds file boundary`！
  - 结果：所有使用 `--stealth` + `eof` 策略的 WAV、WebP、MKV 载体在执行 `sth verify -p <pwd>` 时，虽然 Level 2 和 Level 3 全部通过，但 **Level 1 宿主结构验证必然 FAIL**，导致整个 `verify` 命令退出码为 `1`（失败）！
- **修复建议**：
  在 `verify_core` 中先定位信封（获取 `ube_offset` 与 `strategy`），或将已知的 `Option<&[u8; 4]>` Trailer 魔数 / `ube_offset` 传入 `verify_structure`，使 Level 1 能够准确识别 Stealth 模式下的合法 `eof` 尾部信封边界。

---

### [LOGIC-06] HEIF `item_hidden` 在 `0 < base_offset < m_end` 且 `base_offset + extent_offset >= m_end` 时漏移位 `delta_meta`
- **严重度**：P1（高危 / HEIF 容器偏移损坏）
- **定位**：`rust/src/structure/adapters/isobmff.rs:955-979, 1293-1316`
- **代码实证**：
  ```rust
  // rust/src/structure/adapters/isobmff.rs:955-979
  for _ in 0..ext_cnt {
      if (cm == 0 || cm == 1) && idx_sz > 0 {
          pos += idx_sz;
      }
      let ext_off = read_uint(&out[pos..], off_sz);
      // Only shift extent_offset if base_offset didn't already absorb the shift
      if cm == 0 && b_off == 0 && ext_off >= m_end as u64 {
          let new_ext = (ext_off as i64 + delta_meta) as u64;
          write_uint(&mut out[pos..], off_sz, new_ext);
      }
      pos += off_sz + len_sz;
  }
  ```
- **问题分析**：
  在 HEIF 的 `iloc` Box（`construction_method == 0`，文件偏移模式）中，一个 item extent 在文件中的真实物理偏移是 `base_offset + extent_offset`。
  当 `meta` Box 位于 `mdat` Box 之前（绝大多数 HEIC 照片的标准布局）且向 `meta` 内部注入数据使 `meta` 膨胀了 `delta_meta` 字节时，任何真实物理偏移 `>= m_end` 的 item 都向后移动了 `delta_meta` 字节。
  然而看第 `947-975` 行的代码：
  - 如果 `b_off >= m_end as u64`，代码将 `b_off` 加上 `delta_meta`（正确）；
  - 如果 `b_off == 0 && ext_off >= m_end as u64`，代码将 `ext_off` 加上 `delta_meta`（正确）；
  - **但如果 `0 < b_off < m_end as u64`（例如编码器将 `base_offset` 设为 `ftyp` 结尾或小常数，或 `ext_off == 0` 不可选而 `b_off` 位于 `meta` 之前，依靠 `ext_off` 跨越 `meta` 指向 `mdat`），此时 `b_off < m_end` 所以 `b_off` 没加 `delta_meta`，同时因为 `b_off != 0` 所以 `ext_off` 也没加 `delta_meta`**！
  - 结果：该 item 的文件偏移完全没有平移 `delta_meta`，指向了错误的位置，导致注入后 HEIC 图像无法解码，且 `strip`（第 `1293-1316` 行）存在完全相同的对称漏洞。
- **修复建议**：
  当 `cm == 0` 且 `b_off < m_end as u64` 时，只要 `(b_off + ext_off) >= m_end as u64`，就必须对 `ext_off` 加上 `delta_meta`（若一个 item 下所有 extent 均位于 `m_end` 之后且 `ext_cnt > 0 && off_sz == 0`，则应更新 `b_off`）。

---

### [LOGIC-07] PNG 内容域：(1) `decode_png` 从不校验 Chunk CRC-32 且 `encode_png` 重算 CRC 洗白损坏块；(2) `SlotPlan::build` 在 `ChannelMode::Rgb` 下仅用 G 通道过滤饱和像素
- **严重度**：P1（高危 / 校验失真与容量无故损失）
- **定位**：
  - `rust/src/stego/png/engine.rs:235-261, 738-747, 1077-1083, 2046-2055`
- **代码实证**：
  1. **忽略 CRC-32 并重算洗白（`stego/png/engine.rs:259, 738-747`）**：
     ```rust
     // rust/src/stego/png/engine.rs:259
     pos = body_end + 4; // Skip CRC
     ```
     ```rust
     // rust/src/stego/png/engine.rs:738-747
     fn write_chunk(out: &mut Vec<u8>, chunk_type: [u8; 4], data: &[u8]) {
         out.extend_from_slice(&(data.len() as u32).to_be_bytes());
         out.extend_from_slice(&chunk_type);
         out.extend_from_slice(data);
         let mut hasher = Hasher::new();
         hasher.update(&chunk_type);
         hasher.update(data);
         out.extend_from_slice(&hasher.finalize().to_be_bytes());
     }
     ```
     - `decode_png` 在解析 PNG 时完全跳过每个 Chunk 的 4 字节 CRC-32 而不做校验。因此 `verify_png`（第 `2046-2055` 行）在 Level 1 报告 `"PNG structure valid"` 时，哪怕 PNG 的 `IHDR`、`PLTE`、`eXIf` 或 `IEND` 块 CRC 已经损坏也会报 `OK`！
     - 更隐蔽的是，`encode_png` 将保存下来的 `ancillary_before_idat` 和 `ancillary_after_idat` 通过 `write_chunk` 重新写出时，会为可能已损坏的辅助块重新计算一个“合法”的 CRC-32，静默掩盖原图损坏。
  2. **`SlotPlan::build` 在 `ChannelMode::Rgb` 下仅检查 G 通道（`stego/png/engine.rs:1077-1083`）**：
     ```rust
     // rust/src/stego/png/engine.rs:1077-1083
     let mut candidates: Vec<usize> = (0..total_pixels)
         .filter(|&idx| {
             let val = image.pixels[idx * image.channels + channel_offset];
             (8..=247).contains(&val)
         })
         .collect();
     ```
     - `channel_offset` 在 RGB/RGBA 图像中固定为 `1`（即 Green 绿色通道）。
     - 当使用 `ChannelMode::Rgb`（3 通道模式，例如自适应扩容回退到 RGB 模式时）时，`SlotPlan::build` 依然只检查该像素的**绿色通道 `G`** 是否在 `8..=247` 内！
     - 如果一张图片包含大面积纯红（`R=128, G=0, B=128`）或深蓝/亮洋红（`G < 8` 或 `G > 247`），即使其 Red 和 Blue 通道完全处于安全区间 `8..=247` 且在 `expand_body_channels`（第 `1162` 行）中会单独检查单通道 `8..=247`，这些像素也会在 `SlotPlan::build` 阶段被整体踢出 `self.candidates`，导致它们的 R 和 B 通道被完全浪费！
- **修复建议**：
  1. 在 `decode_png` 中使用 `crc32fast::Hasher` 校验每个 Chunk 的 4 字节 CRC-32。
  2. 注意 `SlotPlan::build` 的 `self.candidates` 同时用于定位固定在单通道 `channel_offset` 上的 Header 槽位，因此若修改 `candidates` 过滤条件会改变 wire 置换集；但应在文档与注释中明确记录这一协议级行为，并在下一个版本协议升级中将 Header 候选池（仅需 G 通道在 `8..=247`）与 RGB Body 候选池解耦。

---

### [LOGIC-08] JPEG `formats/jpeg_segments.rs` 未跳过连续 `0xFF` 填充字节；PNG 拼接流行为分裂；`rs_difference` 循环边界 Off-by-One
- **严重度**：P2（中危 / 边界解析与统计精度缺陷）
- **定位**：
  - `rust/src/formats/jpeg_segments.rs:47-63, 111-127`
  - `rust/src/structure/adapters/png.rs:56-80` vs `288, 373, 414` & `rust/src/analysis.rs:705`
  - `rust/src/analysis.rs:1924-1931`
- **代码实证**：
  1. **JPEG `0xFF` 填充字节未跳过（`rust/src/formats/jpeg_segments.rs:47-55`）**：
     ```rust
     let mut pos = 2usize;
     while pos + 4 <= data.len() {
         if data[pos] != 0xFF {
             break;
         }
         let marker = data[pos + 1];
         pos += 2;
     ```
     ITU-T T.81 §B.1.1.2 规定任何 Marker 前都可以有任意多个 `0xFF` 填充字节（Fill Bytes）。项目中的 `stego/jpeg/dht.rs:110`、`structure/adapters/jpeg.rs:94` 和 `analysis.rs:808` 都正确编写了 `while pos < data.len() && data[pos] == 0xFF { pos += 1; }`，唯独 `formats/jpeg_segments.rs` 的 `parse_dqt_tables`（第 `47-55` 行）和 `parse_component_tq`（第 `111-119` 行）直接取 `marker = data[pos + 1]`。一旦遇到合法的 `0xFF 0xFF 0xDB`（带填充字节的 DQT），`marker` 被读成 `0xFF`，紧接着把 `0xDB` 和段长度高字节当作 `seg_len` 跳飞，导致 DQT 解析彻底失败！
  2. **PNG 拼接流（Concatenated PNGs）处理分裂**：
     `structure/adapters/png.rs:56-80` 的 `find_iend_offset` 专门支持多張 PNG 拼接流（在 `IEND` 后若发现又跟着 `PNG_MAGIC` 则继续向后寻找最后一个 `IEND`）。然而同一个文件的 `locate`（第 `288` 行）、`verify_structure`（第 `373` 行）、`suspicious_structures`（第 `414` 行）以及 `analysis.rs:705` 的 `walk_png_chunks` 全部在遇到**第一个 `IEND`** 时就立即 `break` / `return`！这导致：
     - 向拼接 PNG 执行 `chunk` 策略写入时，`inject` 把 `prIv` 插在**最后一个 `IEND`** 之前，但 `locate` 在**第一个 `IEND`** 就停止搜索，导致刚写入的数据立刻读不出来（`NoHiddenData`）！
  3. **`rs_difference` 3x3 窗口循环上界 Off-by-One（`rust/src/analysis.rs:1924-1925`）**：
     ```rust
     // rust/src/analysis.rs:1924-1931
     for i in 0..rows - 3 {
         for j in 0..cols - 3 {
             let mut w = [0i32; 9];
             for dr in 0..3 {
                 for dc in 0..3 {
                     w[dr * 3 + dc] = plane[(i + dr) * cols + (j + dc)];
     ```
     由于 `dr` 和 `dc` 取值为 `0, 1, 2`，最大访问下标为 `i + 2` 和 `j + 2`。要覆盖 `[0..rows]` 和 `[0..cols]`，外层循环范围应为 `0..=rows - 3`（即 `0..rows - 2`），而非 `0..rows - 3`！写成 `0..rows - 3` 导致图像的最后一行和最后一列 3x3 窗口永远未被采样。

---

### [LOGIC-09] FLAC 嵌入残差翻转与补偿位之间的中间样本偏移可能导致边界槽位在提取时 `usable` 集合不一致
- **严重度**：P1（高危 / 极端边界下 FLAC 提取同步风险）
- **定位**：`rust/src/stego/audio/flac/mod.rs:198-204, 297-315, 349-355, 426-431`
- **代码实证**：
  ```rust
  // rust/src/stego/audio/flac/mod.rs:315, 349-355
  let base_pcm = frame::reconstruct_subframe(&sub, fh.block_size as usize, bps)?;
  ...
  let sample_ok = (base_pcm[s] - margin >= min_s) && (base_pcm[s] + margin <= max_s);
  ```
  ```rust
  // rust/src/stego/audio/flac/mod.rs:426-431
  let usable = &analysis.usable;
  let (sampled_indices, is_sampled): (Vec<usize>, bool) = if !need_all_costs && sample_limit > 0 {
      let picked: Vec<usize> = (0..total)
          .filter(|&idx| usable[idx])
          .take(sample_limit)
          .collect();
  ```
- **问题分析**：
  正如 `flac/mod.rs:198-204` 注释自己警告的那样：
  - 当嵌入端翻转槽位 $s$ 的残差（$\Delta r_s = \pm 1$）并在补偿位 $c\_pos$（对于 Fixed 预测器，$c\_pos = s + \text{order}$，相隔 1~4 个样本）施加反向补偿时，在 $(s, c\_pos)$ 之间的中间样本（例如 2~4 阶 Fixed 子帧中的 $s+1, s+2, s+3$）以及 $s$ 本身的重建样本值 `base_pcm` 会发生 $\pm 1 \sim \pm 6$ 的改变！
  - 虽然 `cost.rs:105` 的 `clip_guard` 通过 `MAX_COST` 阻止了 STC 选择靠近饱和边界的槽位，但在 `FlacCarrier::new`（第 `426-431` 行）中，当 `!need_all_costs && sample_limit > 0` 时，代码直接用 `.filter(|&idx| usable[idx])` 过滤了槽位，且在 `finalize`（第 `474` 行）中也检查了 `if !self.analysis.usable[slot_idx] { continue; }`。
  - 更重要的是，在提取端（`extract_flac`），`FlacCarrier::new` 传入的是 `with_costs = false`（此时 `need_all_costs == false`），由于 `extract_body_bytes` 并不读取 `costs`，提取端实际上并未使用 `usable` 过滤槽位置换（`perm::permute_slots` 是在 `0..total_slots` 全集上置换的）。因此 `FlacCarrier::new` 中对 `usable` 的过滤仅影响快速采样容量估算，但 `finalize` 中 `if !self.analysis.usable[slot_idx] { continue; }` 若跳过了一个被 STC 选中的槽位，就会导致写入的 síndrome 与提取端不一致！好在 `cost_at` 对接近饱和边界的槽位返回了 `MAX_COST`，只要 `clip_guard >= margin`，STC 就不会翻转 `!usable` 的槽位，但代码应当将 `usable` 的边界条件与 `CostParams::clip_guard` 统一，并移除 `FlacCarrier::new` 中混淆视听的矛盾逻辑。

---

## 10. 优先级修复路线图（Remediation Roadmap）

### 第一阶段：立即修复（P0 阻断与安全级问题）
1. **[REL-01] 修复 GUI 路径穿越漏洞**：在 `gui/src-tauri/src/commands/stego.rs:375` 和 `rust/src/structure/engine.rs:1734`（或 `EnvelopeMetadata::unpack_binary`）中强制调用 `strhide::core::fs::sanitize_filename`。
2. **[FN-01] 贯通 `ExtractParams::max_payload_bytes`**：在 `rust/src/stego/envelope.rs` 的 `unpack` 及全部 7 个内容域引擎的 `extract` / `verify` 入口接入 `opts.limits`（含 `max_payload_bytes`、`max_pbkdf2_iterations`、`allowed_cipher_suites`）。
3. **[REL-02] 修复 PNG `Structure -> Content` 双域共存故障**：
   - `PngAdapter::locate` 支持 `custom_magic` 偏移回退；
   - `PngAdapter` 实现基于 Chunk 扫描的 `strip()`，替代按旧 `header.inject_offset` 硬切字节的默认实现；
   - 修复 `verify_core` 对平移后 `prIv` 块的坐标校验与 `debug_assert_eq!`。
4. **[LOGIC-01] 修复 HEVC `StopCondition::TargetSlots` 截断 `PoolProfile` Bug**：确保 `record_carrier_state` 收集足够的有效安全槽位，避免 `--enforce-safety` 误杀合法载荷及返回被截断的 `StegoCapacityInfo`。
5. **[LOGIC-02] 修复 `pe_codebits` `ChannelHeader` 掩码无密钥问题**：将 `derive_channel_header_mask` 改为绑定密码/隐身密钥，防止无密码观察者直接用 `buf[0..4]` 解盲 `buf[4..14]`。
6. **[LOGIC-03] 修复 PDF XRef Stream 嵌套字典截断**：在 `read_xref_stream_dict` 中使用 `<<` / `>>` 深度计数配对替代 `after_open.find(">>")`。

### 第二阶段：高优先级优化（P1 可靠性、一致性与性能瓶颈）
1. **[PERF-01] 消除结构域 6~7 倍冗余 PBKDF2**：在 `EnvelopeHeader::unpack_with_secrets` 中先检查明文 `FLAG_ENCRYPTED` 再派生默认掩码（同时修复 **[LOGIC-04]** 的 $1/18,724$ 误判问题），并在 `verify_core` 中复用 `locate_envelope` 已派生的隐身魔数与头部。
2. **[PERF-02 / PERF-03] 优化 WAV/FLAC 性能与内存**：
   - 移除 `extract_wav`、`probe_wav`、`inspect_wav`、`verify_wav` 及 `extract_flac` 中的全文件 `carrier.to_vec()` 克隆；
   - 在 `FlacCarrier::new` 中当 `with_costs == false` 时跳过全文件二次解码；
   - 使用前缀和优化 `audio::cost::CostParams::cost_at`。
3. **[PERF-04] 将 MKV 纳入流式补丁提交**：让 `refresh_mkv_crcs` 基于 `&[BytePatch]` 计算增量 CRC，并在 `stego/io.rs:60` 启用流式补丁提交。
4. **[REL-03] 修复只读载体 `commit_carrier_patches` 权限错误**：在 `fs::copy(carrier_path, &tmp_path)` 后清除临时文件的只读属性位。
5. **[FN-02 / FN-04 / LOGIC-05 / LOGIC-06 / LOGIC-07 / QUAL-01]**：统一双域空密码 `Some("")` 语义、修复 CLI `--auto` 批处理目录共享、向 Level 1 `verify_structure` 传递 Trailer 魔数、修复 HEIF `item_hidden` 偏移平移条件、为 PNG `decode_png` 加上 CRC-32 校验，并将 `trace` 改为零开销宏。

### 第三阶段：架构治理与文档对齐（P2 / P3）
1. **[ARCH-01 / ARCH-02 / ARCH-03]**：清理 `core/params.rs` 中的领域专属类型，将 CLI 打印移出 `core/pipeline.rs`，加固 `scripts/import_lint.py`。
2. **[ARCH-04 / API-01 / API-02 / API-03 / QUAL-02 ~ QUAL-04 / REL-04 ~ REL-07 / LOGIC-08]**：同步更新 `docs/api/WIRE_SPEC.md` 等设计文档，补齐 `StegoTuning::Audio` 与音频 `MediaInfo`，修正 `avif`/`webm`/`pe` 扩展名声明，修复 GUI `CachedExtract` 缓存键与批量进度回调，修正 `formats/jpeg_segments.rs` 填充字节跳过与 `analysis.rs` 的 RS 窗口循环上界。
