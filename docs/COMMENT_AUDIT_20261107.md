# strhide 注释审计报告（2026-11-07）

- 审计时间：2026-11-07 20:10:11（Asia/Shanghai）
- 范围：`rust/src`、`rust/tests`、`rust/examples` 全部 `.rs`；`gui/src`、`gui/src-tauri/src` 粗查
- 性质：只读审计。未修改任何源码、注释或配置，未 commit/push
- 结论口径：判定以“删掉之后读者是否还需要重新推导”为准，不以“注释是否啰嗦”为准

## 一、摘要

| 指标 | 数值 |
|---|---:|
| 扫描 `.rs` 文件 | 205 |
| 代码总行数 | 113,865 |
| 注释行总数 | 16,781（14.7%） |
| 其中文档注释 `///`、`//!` | 11,640 |
| 其中普通注释 `//` | 5,141 |
| 块注释 `/* */` | 0 |
| 含审查/修复编号的注释块 | 212 |
| 其中 `src/` | 133 |
| 其中 `tests/` + `examples/` | 79 |
| 引用已不存在的文档 | 24 处，涉及 16 个文档 |
| 真正的历史叙述（人工复核后重点条目） | 30 块 |
| 判定统计：修正 / 删除 / 精简 / 保留 | 26 / 22 / 211 / 18（共 277 条） |
| `SAFETY:` 注释 | 10 处 |

编号前缀分布（按行 / 按注释块）：

| 前缀 | 行数 | 块数 | 说明 |
|---|---:|---:|---|
| `P0-` / `P1-` / `P2-` / `P3-` | 175 | 169 | 主体，来自 P2/P3 修复批次 |
| `B-` | 25 | 25 | 协议/行为修复编号 |
| `F-` | 16 | 16 | 功能/格式修复编号 |
| `N-` | 3 | 3 | 其余编号 |
| `LOGIC-` | 1 | 1 | 单处 |
| `R-` | 0 | 0 | `rust/` 中已无 `R-nn` 形式；仅有 `R2/R3/R4` 审查轮次文字 |
| `XH-` | 0 | 0 | `rust/` 中不存在 |

用户举例的 `R-21`、`XH-01` 在本仓库 `rust/` 源码中已不存在；这两个编号仍出现在 `docs/CHANGES-20261105.md`、`docs/CHANGES-20261106.md` 与 `docs/RELEASE_READINESS_20261106.md` 中。源码里留下的是 `P*/B*/F*` 编号，以及 `R2/R3/R4`、`review A/G1/G2`、`2026-10-25` 之类的轮次/日期文字。

按目录分布（注释行）：

| 目录 | 注释行 |
|---|---:|
| `src/stego` | 7,692 |
| `src/structure` | 2,928 |
| `src/core` | 1,232 |
| `src/*.rs`（顶层） | 883 |
| `tests/test_lifecycle` | 651 |
| `src/cli` | 592 |
| `examples/` | 480 |
| `tests/test_regression` | 468 |
| `tests/test_cli` | 377 |
| `tests/local` | 309 |
| 其余（`tests/heavy`、`tests/test_pe`、`tests/test_security`、`tests/test_media`、`src/formats`、`src/analysis` 等） | 1,169 |

编号注释块按目录分布：

| 目录 | 编号块 |
|---|---:|
| `src/structure` | 66 |
| `tests/test_regression` | 49 |
| `src/stego` | 27 |
| `src/*.rs`（顶层） | 14 |
| `src/core` | 12 |
| `src/cli` | 11 |
| 其余 | 32 |

注释量最大的 10 个文件：

| 注释行 | 文档注释 | 普通注释 | 文件 |
|---:|---:|---:|---|
| 848 | 518 | 330 | `src/structure/engine.rs` |
| 769 | 452 | 317 | `src/stego/png/engine.rs` |
| 700 | 478 | 222 | `src/stego/hevc/engine.rs` |
| 456 | 260 | 196 | `src/analysis.rs` |
| 437 | 391 | 46 | `src/stego/params.rs` |
| 341 | 206 | 135 | `src/stego/jpeg/engine.rs` |
| 331 | 282 | 49 | `src/structure/envelope.rs` |
| 328 | 234 | 94 | `src/stego/coding/stc.rs` |
| 317 | 236 | 81 | `src/stego/audio/flac/mod.rs` |
| 302 | 298 | 4 | `src/stego/options.rs` |

编号注释最集中的文件：

| 编号块 | 文件 |
|---:|---|
| 18 | `tests/test_regression/review_20261025.rs` |
| 17 | `src/structure/engine.rs` |
| 14 | `src/structure/adapters/isobmff.rs` |
| 12 | `tests/test_regression/fixes.rs` |
| 10 | `src/analysis.rs` |
| 7 | `src/stego/png/engine.rs` |
| 7 | `tests/test_regression/review_20261019.rs` |
| 7 | `src/cli/cmd_diag.rs` |
| 6 | `src/structure/envelope.rs` |
| 6 | `tests/test_regression/review_20261031.rs` |

**整体结论**

1. 编号注释集中在**结构域（`src/structure`）与回归测试**，而不是 `stego`。`stego` 注释总量最大（7,692 行），但主要是算法、代价函数、平台差异和参数约束，编号比例反而较低。
2. 编号注释绝大多数**不是垃圾**：它们把“有价值的当前约束”和“当时的修复过程”混在同一段里。直接整段删除会丢掉“为什么不能改成 X”的信息；正确做法是**去编号、去过程、留约束**。
3. 真正与代码不符的只有 **3 处**：`structure/mod.rs` 的模块迁移叙述自指矛盾、`structure/engine.rs` 一段误粘的文档、`stego/params.rs` 中 256 MiB 的旧上限。另有 **24 处**引用了已从 `docs/` 删除的文档，属于“链接失效”，比冗余更有害。
4. 可以**整段删除**的只有 2 处（模块迁移史、`pe_codebits` 设计文档行）；另有 14 条测试分隔横幅可直接删；其余 197 个编号块建议“精简”，而不是删除。
5. `SAFETY:` 注释 10 处全部应保留，且建议进一步强化（写明 invariant，而不是只写“调用者已检查”）。

## 二、判定口径与统计

本次逐条判定的条目由四部分组成：

| 子集 | 数量 | 判定结果 |
|---|---:|---|
| 含 `P*/B*/F*/N*/LOGIC-*` 的注释块 | 212 | 修正 1、删除 14（测试分隔横幅）、精简 197 |
| 引用已不存在文档的注释块 | 24 | 修正 24（`structure/mod.rs` 的失效引用与 C-1 模块矛盾合并为一条） |
| `stego/params.rs` 旧上限块 | 1 | 修正 1 |
| 人工复核的历史叙述块 | 30 | 删除 8、精简 14、保留 8 |
| `SAFETY:` 注释 | 10 | 保留 10 |

合计：**修正 26、删除 22、精简 211、保留 18（共 277 条）**。

说明：

- 这里的“删除 22”= 14 条测试分隔横幅（`// ----- R1 / P0-3`）+ 8 处批次/日期/审查标签；都不删除测试正文。
- 212 个编号块中，除 14 条纯横幅外，其余只需删掉 `P1-3:`、`(review R3 P1-1)`、`B-06:` 之类的标签；正文如果是在解释当前约束，应原样保留。
- “保留”只给不依赖编号、且当前仍准确的约束型注释。编号本身是过期溯源信息，因此带编号的块一律归入“精简/删除”，即使正文必须一字不改。

复核用命令与正则见第九节。

## 三、修正清单（与当前代码不符或引用失效）

### 3.1 代码/注释不一致

#### C-1 `rust/src/structure/mod.rs:1-14`：模块迁移叙述自指矛盾

当前注释（节选）：

```text
//! Everything reachable as `crate::structure::X` used to live at the crate root
//! as `crate::structure::X` / `crate::structure::adapters::X` /
//! `crate::structure::registry::X`, which made the container-domain engine look
//! like the primary one...
```

问题：句子说“曾经位于 `crate::structure::X`”，但这正是**当前**路径；当前 `mod.rs` 也确实声明了 `pub mod adapters; pub mod engine; pub mod registry;`，全部位于 `crate::structure` 下。该句无法自洽，读者无法从中还原旧布局。

建议：删除迁移史，只保留依赖方向与域平级这两条当前事实。可改为：

```text
//! `structure` and `stego` are peer domains: neither depends on the other.
//! Entry points keep their historical names (`write_carrier`, `verify_carrier`,
//! `read_carrier`), so callers do not need to know which domain owns them.
```

同时第 11 行引用的 `docs/strhide_architecture_and_refactoring_plan.md` 已不存在，见 3.2。

#### C-2 `rust/src/structure/engine.rs:2806-2807`：误粘的文档片段

当前注释：

```rust
/// Shared verify logic over any seekable reader (a `File` on the path path,
/// a `Cursor` on the bytes path).
/// Cross-check the header's injection coordinates against the located envelope.
fn envelope_coordinates_agree(...)
```

问题：前两行是上方 `verify_core` 的文档，被误粘到 `envelope_coordinates_agree`。当前函数的职责只有“坐标交叉校验”，与“any seekable reader”无关。第三行才是本函数文档。

建议：删除前两行，保留：

```rust
/// Cross-check the header's injection coordinates against the located envelope.
```

#### C-3 `rust/src/stego/params.rs:516-529`：256 MiB 旧上限未同步

当前注释：

```text
/// * memory -- one slot costs `2^h / 64` words of traceback state (32 B at
///   `h = 8`, 128 B at `h = 10`), so 256 MiB allows 8.4M slots at `h = 8`;
```

代码证据：

- `src/stego/params.rs:531`：`MAX_AUTO_BACKTRACK_BYTES: usize = 4 << 30;`，即 4 GiB。
- 同段 `src/stego/params.rs:536`：`// Set to 4 GiB ...`。
- 测试 `src/stego/params.rs:1274` 也按 `4 GiB / 32 B` 计算为 134M slots。

因此“256 MiB / 8.4M”是旧值，和紧随其后的 4 GiB 说明直接冲突。

建议改为：

```text
/// * memory -- one slot costs `2^h / 64` words of traceback state (32 B at
///   `h = 8`, 128 B at `h = 10`), so 4 GiB allows 134M slots at `h = 8`;
```

### 3.2 引用已删除文档（24 处 / 16 个文档）

这些路径在仓库中均不存在，`docs/` 下也没有同名或近名文档。读者按图索骥会直接失败。

| # | 位置 | 失效引用 | 判定 / 建议 |
|---:|---|---|---|
| 1 | `rust/src/analysis.rs:28` | `docs/png_blind_calibration_20261023.md` | 修正：删掉路径，或改指现有校准说明；不要把文档名当唯一证据 |
| 2 | `rust/src/analysis.rs:90` | `docs/stego_keyed_parameters_plan_20261020.md` §13 | 修正：删掉路径与 §13，保留“按固定种子重算”的约束 |
| 3 | `rust/src/analysis.rs:1536` | `docs/png_blind_calibration_20261023.md` | 修正：同上 |
| 4 | `rust/src/formats/mod.rs:6` | `docs/strhide_architecture_and_refactoring_plan.md` §2.1 | 修正：删掉路径；依赖方向一句话即可说明 |
| 5 | `rust/src/stego/format.rs:611` | `docs/stego_content_envelope_v4_golden_vectors_20261103.md` | 修正：改为“这些值被 `tests/...` 回归锁定”，或改指 `docs/api/WIRE_SPEC_CONTENT.md`（该文件存在） |
| 6 | `rust/src/stego/header.rs:544` | 同上 | 修正：同上 |
| 7 | `rust/src/stego/params.rs:512` | `docs/stc_v3_phase3_eval_20261021.md` | 修正：删掉路径；保留“由 Phase 3 网格选出”即可 |
| 8 | `rust/src/stego/hevc/engine.rs:4088` | `docs/hevc_video_capacity_quality_audit_20261026.md` §2 | 修正：删掉路径；15-20 dB 的测量值可保留，但应注明测试/样本来源 |
| 9 | `rust/src/stego/hevc/engine.rs:5029` | `docs/stego_content_envelope_v4_golden_vectors_20261103.md` | 修正：同 #5 |
| 10 | `rust/src/stego/jpeg/header_v4.rs:186` | 同上 | 修正：同 #5 |
| 11 | `rust/src/structure/mod.rs:11` | `docs/strhide_architecture_and_refactoring_plan.md` | 修正：删掉路径 |
| 12 | `rust/src/structure/params.rs:4` | 同上 §3.5 | 修正：删掉路径与 §3.5 |
| 13 | `rust/src/structure/adapters/pe_codebits.rs:12` | `docs/pe_codebits_plugin_design.md` (v1.0) | 修正/删除：整行可删；若保留设计说明，应内联为 2-3 句 |
| 14 | `rust/tests/heavy/heavy_stego.rs:42` | `docs/png_blind_calibration_20261023.md` | 修正：删掉路径，保留“0.05–0.70 阈值”这一测试参数理由 |
| 15 | `rust/tests/heavy/heavy_stego.rs:49` | `docs/stego_remediation_plan_20261023_1815.md` | 修正：删掉路径 |
| 16 | `rust/tests/heavy/heavy_stego.rs:660` | `docs/embed_png_jpeg_algorithm_review_20261020_db.md` §9.3 | 修正：删掉路径与 §9.3 |
| 17 | `rust/tests/local/local_media.rs:802` | `docs/hevc_steganalysis_and_quality_spec_20261026.md` | 修正：删掉路径 |
| 18 | `rust/tests/test_lifecycle/profile.rs:3` | `docs/library_api_practical_plan_20261020.md` | 修正：删掉路径；保留 M1 的验收点 |
| 19 | `rust/tests/test_regression/review_20261019.rs:2` | `docs/VERIFY-REVIEWS-AND-FIX-PLAN-20261019.md` | 修正：把文件头改为“历史回归用例”，不再引用文档 |
| 20 | `rust/tests/test_regression/review_20261025.rs:2` | `docs/structure_domain_code_review_20261025.md` | 修正：同上 |
| 21 | `rust/tests/test_regression/review_20261030.rs:1` | `docs/CODE-REVIEW-R2-20261030.md` | 修正：同上 |
| 22 | `rust/tests/test_regression/review_20261031.rs:1` | `docs/CODE-REVIEW-R3-20261031.md` | 修正：同上 |
| 23 | `rust/examples/codec_bench.rs:7` | `docs/stc_coding_design_20261021.md` | 修正：删掉路径 |
| 24 | `rust/examples/v3_eval.rs:16` | `docs/stc_v3_phase3_eval_20261021.md` | 修正：删掉路径 |

仍然有效的 3 处引用（保留）：

- `rust/src/stego/hevc/engine.rs:4622` → `docs/api/WIRE_SPEC_CONTENT.md`
- `rust/src/stego/png/cost/mipod.rs:283` → `docs/api/cost-vectors.json`
- `rust/examples/perf_bench.rs:12` → `docs/PERF_BENCHMARK_PLAN_20261107.md`

### 3.3 建议一并修正的表述（非编号）

- `rust/src/structure/engine.rs:461`：“The English sentence this warning used to be, kept for CLI rendering.” 当前 `message()` 不只用于 CLI，也被 `Display` 和 `render` 使用。建议改为“English text used by `Display`/CLI rendering”，并说明多语言走 `render()`。
- `rust/src/structure/engine.rs:3087-3101`：`debug_assert_eq!` 的说明把“写出时重定位”和“调试断言比较同源字段”混在一起。断言本身正确，但叙述过长；建议压缩为：“`trailer` 与 `ube_total_size` 来自同一条尾部记录，比较它们不能发现写后重定位；重定位由 `relocate` 后的回归用例覆盖。”

## 四、可删除清单（整段或整句）

删除判定共 22 条，分两类；“整段删除”的 2 处已计入修正，不重复计数。

### 4.1 测试分隔横幅（14 条，计入“删除 22”）

附录 A 中判定为“删除”的 14 行，都是 `// ---------- R1 / P0-3 ----------` 形式的测试分组横幅。直接删除，或改成不含编号的空行；测试函数名已经说明归属。

### 4.2 历史/批次标签（8 条，计入“删除 22”，与附录 C 第 1-8 项一致）

| # | 位置 | 内容 | 处理 |
|---:|---|---|---|
| D-1 | `rust/tests/test_cli/p2.rs:1-11` | “(2026-10-17), batch 3”等批次溯源 | 删除批次/日期标签，保留测试范围 |
| D-2 | `rust/tests/test_cli/sources.rs:1-12` | “gap report 2026-10-19, gaps #1 #2 #5” | 删除 gap 编号；保留覆盖点 |
| D-3 | `rust/tests/test_cli/verify.rs:1-15` | “gap report 2026-10-19, gaps #3 #4 #6 #7” | 删除 gap 编号；保留覆盖点 |
| D-4 | `rust/tests/test_regression/fixes.rs:1-4` | “(2026-10-17)”批次说明 | 删除日期/批次 |
| D-5 | `rust/tests/test_regression/p2_fixes.rs:1-8` | “(2026-10-17)”批次说明 | 删除日期/批次 |
| D-6 | `rust/tests/test_regression/p2_protocol.rs:1-8` | “(2026-10-17), batch 2” | 删除日期/批次 |
| D-7 | `rust/src/structure/adapters/isobmff.rs:1385-1386` | “(review 2026-10-25)” | 删除日期标签 |
| D-8 | `rust/src/structure/adapters/isobmff.rs:1814-1816` | “(review 2026-10-25)” | 删除日期标签 |

### 4.3 整段删除（计入“修正 26”，不重复计数）

| # | 位置 | 内容 | 处理 |
|---:|---|---|---|
| W-1 | `rust/src/structure/mod.rs:3-9` | 模块“曾经在 crate root”的迁移史 | 删除该段；修正后的域平级说明保留 |
| W-2 | `rust/src/structure/adapters/pe_codebits.rs:12` | “Design document: `docs/pe_codebits_plugin_design.md` (v1.0).” | 整行删除（文档不存在） |
| W-3 | `rust/tests/test_regression/review_20261019.rs:1-5` | 文件头的审查文档链接与批次说明 | 删除文档链接；保留“回归用例”定位 |
| W-4 | `rust/tests/test_regression/review_20261025.rs:1-6` | 同上 | 同上 |
| W-5 | `rust/tests/test_regression/review_20261030.rs:1-5` | 同上 | 同上 |
| W-6 | `rust/tests/test_regression/review_20261031.rs:1-5` | 同上 | 同上 |

以下虽然含“曾经/旧实现”，但**不建议删除**，因为它们在解释当前防护为什么存在：

- `stego/png/engine.rs:999`：`as u32` 截断 4 GiB chunk 的历史，说明当前长度检查的必要性。
- `structure/adapters/jpeg.rs:201-204`：旧的 64 MiB 容量与 16 MiB 扫描上限冲突，说明当前容量必须受扫描上限约束。
- `structure/adapters/isobmff.rs:485-489`：旧的 `read_to_end`，说明当前 seek 遍历的内存边界。
- `structure/engine.rs:1896-1901`：旧的 64 MiB payload 上限，说明当前“按载体长度缩放”的规则。
- `stego/jpeg/registry.rs:56-57`、`stego/png/registry.rs:94-95`：删除别名后的防回归说明。
- `structure/adapters/pe_codebits.rs:889-891`：pre-v1 未掩码头不再解析的兼容边界。

## 五、精简模式与建议措辞

### 5.1 只删编号（正文保留）

适用于“文档注释本身准确，只是前面挂了编号”的块。示例：

```text
// P1-3: `jpeg-decoder` allocates from the geometry declared in the header...
```

改为：

```text
// `jpeg-decoder` allocates from the geometry declared in the header...
```

大多数 `src/analysis.rs`、`src/cli/*`、`src/core/*` 的编号注释属于这一类。**不要**因为删编号而重写正文。

### 5.2 去历史过程，留当前约束

适用于“先讲旧行为，再讲现在”的块。示例与建议措辞：

1. `structure/engine.rs:3457-3459`  
   原文大意：无密码路径曾派生两次默认 secret（约 300 ms / 600 ms），现在只派生一次，测试断言 PBKDF2 调用为 1。  
   建议：`// The no-password path derives the profile default secret once; the test asserts exactly one PBKDF2 call.`

2. `structure/adapters/isobmff.rs:485-489`  
   原文大意：旧实现 `read_to_end` 最多 1 GiB；现在 seek 遍历。  
   建议：`// Probes seek over the box instead of buffering it; the 1 GiB cap bounds hostile containers without allocating 1 GiB.`

3. `stego/png/engine.rs:999-1001`  
   原文大意：超过 4 GiB 的 chunk 曾被 `as u32` 截断并写出错误长度。  
   建议：`// Reject chunks larger than 4 GiB: `as u32` would truncate the length and write a corrupt chunk.`

4. `structure/engine.rs:1896-1901`  
   原文大意：`MAX_VERIFY_PAYLOAD_SIZE`（1 GiB）曾经是唯一检查，且在分配后才运行；现在先按载体长度缩放，再夹在 64 MiB/1 GiB 之间。  
   建议：`// Bound the declared payload before allocating: scale by carrier length, floor at 64 MiB, cap at 1 GiB.`

5. `analysis.rs:78-82`  
   原文大意：2026-10-21 重新校准，并新增 (0,1) 对；旧的统计只看...  
   建议：删掉日期与“重新校准”过程，保留：`// The chi-square gate uses (0,1) adjacencies; the thresholds below were measured on the calibration corpus.`

6. `structure/envelope.rs:695-699`  
   原文大意：每次读取都重新派生 key material，后来改为预派生。  
   建议：`// Pre-derive key material once per header; read must not repeat PBKDF2.`

### 5.3 测试注释

- 说明“这个用例覆盖哪个缺陷”的：保留测试名与样本理由，删掉编号/日期。示例：`P2-7: a carrier whose .text only holds ...` → `A carrier whose .text only holds ...`。
- 说明“为什么必须用这个样本/这个参数”的：**保留**。例如 `tests/local/local_media.rs:1343` 的高载荷回归、`tests/test_media/hevc_stego.rs:189` 的 Annex-B 窗口 bug、`stego/hevc/sniff.rs:78` 的 TSA/STLA/BLA 起始片段。
- 纯批次溯源（`batch 3`、`gaps #1 #2 #5`）：删。

## 六、按模块的清理建议与优先级

| 优先级 | 模块 | 现状 | 建议 |
|---|---|---|---|
| P0 | `src/structure` | 66 个编号块；`mod.rs` 有自指矛盾；大量容器布局/偏移注释 | 先修 C-1、C-2 与失效文档；其余按“去编号、留布局约束”处理。布局偏移类注释必须保留，删了会导致重新逆向格式 |
| P0 | `tests/test_regression` | 49 个编号块；文件头依赖 4 个已删除的 review 文档 | 先删/改文件头引用；测试正文中的样本理由保留 |
| P1 | `src/stego` | 注释量最大（7,692 行），但编号块仅 27 个 | 编号注释少，重点是 C-3 与 golden-vector 文档引用；算法/代价/SAFETY 注释不要动 |
| P1 | `src/core` | 12 个编号块；平台差异与原子提交说明多 | 只删编号；Windows/Unix 行为差异、`SAFETY` 必须保留 |
| P2 | `src/cli` | 12 个编号块；多为 stdin/stdout/退出码约束 | 删编号；不要删“stdout 归属”“原子提交”这类约束 |
| P2 | `src/analysis.rs` | 10 个编号块；校准与启发式说明多 | 删编号与日期；保留阈值、样本、误报边界 |
| P3 | `examples/`、`tests/heavy`、`tests/local` | 编号少，但引用了多个已删除文档 | 只修文档引用，测试参数理由保留 |
| P3 | `gui/` | 仅 2 处编号引用（`P2-7`） | 删编号即可；未发现失效文档引用 |

### 6.1 GUI 粗查明细（不计入上文的 277 条）

| 位置 | 原文要点 | 判定 | 建议 |
|---|---|---|---|
| `gui/src-tauri/src/state.rs:393` | `P2-7: the extraction cache used to key only on path/mtime/password, so...` | 精简 | 改为“缓存键包含 path/mtime/password + `domain`/`prefer`；任一变化都必须让缓存失效”（当前测试 `extract_cache_key_includes_domain_and_prefer` 就是这个契约） |
| `gui/src-tauri/src/commands/stego.rs:521` | `P2-7: an in-place embed (no -o, or -o equal to the carrier) used to...` | 精简 | 改为“原地写入（无 `-o` 或 `-o` 等于载体）不算覆写目标；只有不同的 `-o` 才做 `check_overwrite`”（当前 `overwrite_target` 返回 `None`） |

GUI 前端（`gui/src/**/*.ts(x)`）未发现 `P*/R*/XH*/fixplan/CODE-REVIEW` 引用；也未发现引用 `docs/` 的注释。

## 七、必须保留/强化的注释

### 7.1 `SAFETY:`（10 处，全部保留）

| 位置 | 主题 |
|---|---|
| `rust/src/core/commit.rs:390` | `OpenProcess` 只请求 synchronize 句柄；空返回的错误分支 |
| `rust/src/core/commit.rs:419` | signal 0 只做权限/存在性检查，不发送信号 |
| `rust/src/core/sysmem.rs:49` | `status.length` 必须是结构体精确大小 |
| `rust/src/stego/coding/stc.rs:660` | AVX2 由 `is_x86_feature_detected!` 门控 |
| `rust/src/stego/coding/stc.rs:885` | 调用者已检查 AVX2；所有切片边界 |
| `rust/src/stego/jpeg/cost/juniward.rs:237` | AVX2 检测与实现一致性 |
| `rust/src/stego/jpeg/cost/juniward.rs:380` | 仅由 `cost_map_avx2` 实例化 |
| `rust/src/stego/jpeg/cost/juniward.rs:402` | `k + 8 <= PAD <= a.len() == b.len()` |
| `rust/src/stego/jpeg/cost/juniward.rs:419` | `k < PAD <= a.len() == b.len()` |
| `rust/src/stego/jpeg/cost/juniward.rs:705` | 两个 feature 已在上方检查 |

建议强化方式：把“调用者检查了 AVX2”这类注释补成不变量，例如“`ptr` 覆盖 `k..k+8` 且 `k+8 <= PAD <= len`，否则越界”，而不是只写“调用者已检查”。

### 7.2 约束型注释（保留）

这些注释的价值高于任何编号，删掉会直接导致后人踩坑：

- `structure/engine.rs` 的“同名 JSON/config 段落必须一起校验”“结构域与内容域单密码只写一处”。
- `structure/envelope.rs` 的 header/trailer 布局、version 字段、mask 语义。
- `structure/adapters/isobmff.rs` 的 `iloc`/`iinf`/`mdat` 偏移与“offset 必须相对 mdat 数据起点”。
- `stego/png/engine.rs` 的 chunk/filter passthrough、4 GiB 长度检查。
- `stego/hevc/sniff.rs` 的 TSA/STSA/RADL/RASL/BLA 起始片段限制。
- `stego/io.rs` 的“embed 在达到目标切片时停止”的语义。
- `stego/jpeg/engine.rs:846` 的 `body_len` 含 AEAD tag 的定义。
- `core/params.rs` 与 `stego/params.rs` 的安全等级、chunk 大小、回溯上限。
- `analysis.rs` 的校准阈值、误报边界、“干净结论不等于没有隐藏数据”。

## 八、附录 A：212 个编号注释块逐条清单

> 判定说明：`精简` = 去编号/去历史，保留当前约束；`删除` = 测试分隔横幅等纯标签；`修正` = 与当前代码不符。
> 行号区间为首行注释到块末；摘要为首行去掉注释符号后的前 90 字。

| # | 文件:行 | 前缀 | 首行摘要 | 判定 | 建议 |
|---:|---|---|---|---|---|
| 1 | `src/analysis.rs:492-494` | P0-P3 (P1-3) | Set when a PNG could not be turned into pixels at all (16-bit, Adam7, | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 2 | `src/analysis.rs:589-591` | B (B-03) | Four-byte patterns are far too common in compressed or random data | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 3 | `src/analysis.rs:645-648` | B (B-03) | Is the 4-byte trailer magic at `magic_pos` backed by a self-consistent | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 4 | `src/analysis.rs:789-793` | P0-P3 (P1-2) | Whole file, and the walk never reached IEND. A conforming | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 5 | `src/analysis.rs:1419-1423` | P0-P3 (P1-7) | `jpeg-decoder` allocates from the geometry declared in the header, not | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 6 | `src/analysis.rs:1674-1678` | P0-P3 (P2-21) | Deliberately informational: WS over-reports on content-adaptive | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 7 | `src/analysis.rs:1856-1859` | P0-P3 (P1-4) | Name the real gate. The old text said "e.g. q100", but the check | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 8 | `src/analysis.rs:1896-1897` | P0-P3 (P1-4) | Reporting nothing at all made a skipped detector indistinguishable | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 9 | `src/analysis.rs:1984-1985` | P0-P3 (P2-23) | A 3x3 window starting at `i` needs `i + 2 < rows`, so the last start is | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 10 | `src/analysis.rs:2209-2211` | P0-P3 (P2-23) | A 4x4 plane has two 3x3 window starts per axis (0 and 1). The loop | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 11 | `src/cli/cmd_diag.rs:19-24` | P0-P3 (P2-6) | Print the content-domain half of an `inspect` result. | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 12 | `src/cli/cmd_diag.rs:227-233` | P0-P3 (P1-1) | Whether the content verifier actually found an envelope. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 13 | `src/cli/cmd_diag.rs:239-242` | P0-P3 (P1-1) | The `verify` exit verdict for one carrier. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 14 | `src/cli/cmd_diag.rs:298-301` | P0-P3 (P1-1) | A content envelope that was found but does not verify fails the file | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 15 | `src/cli/cmd_diag.rs:561-564` | P0-P3 (P1-10) | Notes explain how to read the verdict, so the "a clean | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 16 | `src/cli/cmd_diag.rs:689-691` | P0-P3 (P2-9) | Append one `{"path", "error"}` item per missing input, matching the shape | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 17 | `src/cli/cmd_diag.rs:862-864` | P0-P3 (P1-1) | The R3 P1-1 case: structure envelope intact, content envelope found but | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 18 | `src/cli/cmd_structure.rs:68-71` | P0-P3 (P0-2) | The prompt and `--stdin` both read standard input: whichever runs | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 19 | `src/cli/cmd_structure.rs:317-321` | P0-P3 (P1-8) | `--stdout` means the payload owns stdout, so the hint goes to | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 20 | `src/cli/cmd_structure.rs:373-377` | P0-P3 (P1-2) | Hand over the password already resolved here — the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 21 | `src/cli/cmd_structure.rs:459-463` | P0-P3 (P1-4) | Same atomic commit as the explicit `-o` path and the library: a plain | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 22 | `src/cli/render.rs:220-222` | P0-P3 (P1-1) | Present when the content-domain verifier failed to run. Serialized so | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 23 | `src/core/commit.rs:174-178` | P0-P3 (P2-2) | Copy `src` into a freshly created `dst`. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 24 | `src/core/commit.rs:203-206` | P0-P3 (P2-2) | Create the `<carrier>.bak` for an in-place commit, retrying when the name | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 25 | `src/core/commit.rs:505-513` | P0-P3 (P2-18) | Clear the write protection `fs::copy` cloned from the source. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 26 | `src/core/commit.rs:564-568` | P0-P3 (P0-6) | Every span comes from a byte stream that was read before the copy. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 27 | `src/core/commit.rs:778-780` | P0-P3 (P2-18) | A fresh `-o <path>` target must still work: the temp copy inherits | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 28 | `src/core/config.rs:200-204` | P0-P3 (P1-8) | The sections have their own key sets and were not checked at all, so | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 29 | `src/core/control.rs:294-298` | P0-P3 (P1-5) | Not `ErrorKind::Interrupted`: `Write::write_all` (used by every | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 30 | `src/core/control.rs:331-334` | P0-P3 (P1-5) | Any I/O failure while the token is cancelled is the cancellation | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 31 | `src/core/crypto.rs:184-188` | P0-P3 (P1-7) | Test-only count of PBKDF2 runs, used to prove that a single `verify` does | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 32 | `src/core/crypto.rs:331-341` | P0-P3 (P1-5) | Derive a 10-byte deterministic keystream from the **8-byte envelope header | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 33 | `src/core/fs.rs:131-137` | P0-P3 (P2-2) | Render attacker-controlled text safe for a terminal. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 34 | `src/core/i18n/mod.rs:187-194` | P0-P3 (P2-7) | Argument values are type-erased to `&dyn Display`, so | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 35 | `src/facade.rs:158-163` | P0-P3 (P1-1) | Why the content domain produced no result, when it failed instead of | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 36 | `src/facade.rs:604-606` | P0-P3 (P1-1) | Keep the failure instead of swallowing it with `.ok()`: the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 37 | `src/facade.rs:659-663` | P0-P3 (P1-12) | A failed content inspection is not the same answer as "there | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 38 | `src/facade.rs:1045-1048` | B (B-07) | `read -o <carrier>` would replace the only copy of the hidden data | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 39 | `src/formats/jpeg_segments.rs:40-45` | P0-P3 (P2-23) | Skip `0xFF` fill bytes and return the marker code byte's index plus its | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 40 | `src/formats/jpeg_segments.rs:214-216` | P0-P3 (P2-23) | JPEG allows extra 0xFF fill bytes before a marker code. The parser | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 41 | `src/stego/audio/core.rs:1094-1097` | B (B-04) | The body length includes the AEAD tag, the optional filename micro-header | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 42 | `src/stego/audio/flac/mod.rs:337-341` | F (F-07) | Absolute bit offset of the codeword's first bit. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 43 | `src/stego/audio/flac/mod.rs:472-485` | P0-P3 (P0-1) | Two disjoint pools, both derived from structural predicates plus the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 44 | `src/stego/audio/mod.rs:317-320` | F (F-26) | Reuse `scratch`: the header view borrows it only until `read_base` | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 45 | `src/stego/header.rs:473-479` | B (B-05) | Cross-check a header's `FLAG_EXT_CRITICAL` bit against its extension TLVs. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 46 | `src/stego/heif/thumb_bridge.rs:566-569` | P0-P3 (P1-10) | `iloc` stores extent lengths in a field whose width comes from | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 47 | `src/stego/heif/thumb_bridge.rs:669-671` | B (B-03) | Only items stored as a single file extent can be rewritten by | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 48 | `src/stego/heif/thumb_bridge.rs:1529-1532` | P0-P3 (P1-10) | `iloc` extent lengths are written back through a field whose width comes | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 49 | `src/stego/hevc/engine.rs:2157-2160` | B (B-05) | The flag and the TLVs must agree before any caller trusts the header: | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 50 | `src/stego/hevc/engine.rs:2401-2404` | B (B-04) | The plaintext length lives inside the AEAD body: what remains after the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 51 | `src/stego/hevc/engine.rs:4879-4880` | F (F-01) | F-01 regression: the writer's decode window must never fall below the | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 52 | `src/stego/hevc/slot.rs:453-462` | P0-P3 (P2-1) | [`Self::with_slice_mode`] with capacity preallocated based on slice byte length. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 53 | `src/stego/io.rs:46-49` | B (B-07) | `-o <same path as the carrier>` is an in-place write, not an overwrite of | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 54 | `src/stego/jpeg/engine.rs:204-208` | P0-P3 (P2-14) | No-op tracer hook. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 55 | `src/stego/jpeg/engine.rs:1321-1323` | B (B-02) | Charge extraction the same backtracking bitmap the writer charged: a | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 56 | `src/stego/jpeg/engine.rs:1356-1359` | B (B-05) | The AEAD passed, so the carrier really is ours. Unknown critical | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 57 | `src/stego/jpeg/engine.rs:1603-1605` | B (B-05) | `inspect` must apply the same flag/TLV contract as extract, including the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 58 | `src/stego/jpeg/engine.rs:2003-2005` | P0-P3 (P2-14) | `trace` is a no-op outside tracing builds. Passing `format!` to it | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 59 | `src/stego/mod.rs:272-284` | B (B-03) | Shrink a capacity report by the longest possible file micro-header. | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 60 | `src/stego/params.rs:1075-1076` | B (B-06) | B-06: a custom WAV profile used to leak into FLAC, giving both carriers | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 61 | `src/stego/png/engine.rs:358-362` | P0-P3 (P2-11) | Re-encoding always writes a fresh IEND, so a carrier without one | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 62 | `src/stego/png/engine.rs:960-964` | P0-P3 (P2-14) | No-op tracer hook, mirroring the JPEG engine's `[stego]` lines. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 63 | `src/stego/png/engine.rs:2700-2702` | P0-P3 (P2-14) | `trace` is a no-op outside tracing builds. Passing `format!` to it | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 64 | `src/stego/png/engine.rs:3747-3750` | P0-P3 (P2-1) | Review G1 (P2-1): the probe's `max_raw_payload_bytes` must never exceed | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 65 | `src/stego/png/engine.rs:3805-3807` | P0-P3 (P2-4) | Review G4 (P2-4): `png_pre_salt` binds the locator keys to the ancillary | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 66 | `src/stego/png/engine.rs:3853-3860` | P0-P3 (P2-4) | Review G4 (P2-4) used to pin the opposite behaviour: any ancillary-chunk | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 67 | `src/stego/png/engine.rs:4455-4460` | P0-P3 (P2-22) | Evidence for LOGIC-07 (P2-22): the candidate pool is keyed on the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 68 | `src/structure/adapters/ebml.rs:12-24` | P0-P3 (P3-15) | Encode an unsigned integer as an EBML VINT. | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 69 | `src/structure/adapters/ebml.rs:106-109` | P0-P3 (P3-15) | Boundary values must avoid the all-ones "unknown size" payload of each | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 70 | `src/structure/adapters/heif.rs:58-62` | P0-P3 (P2-4) | item_hidden registers the envelope through 32-bit iloc fields and a | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 71 | `src/structure/adapters/isobmff.rs:15-18` | P0-P3 (P2-4) | Largest envelope the `item_hidden` strategy can carry: the second `mdat` | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 72 | `src/structure/adapters/isobmff.rs:137-144` | P0-P3 (P2-17) | `ube_total_size` is attacker-controlled: the trailer is just 24 bytes at | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 73 | `src/structure/adapters/isobmff.rs:474-480` | P0-P3 (P2-08) | Upper bound on the `meta` box body buffered by | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 74 | `src/structure/adapters/isobmff.rs:483-489` | P0-P3 (P2-08) | Read the top-level `meta` box only, without buffering the file prefix. | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 75 | `src/structure/adapters/isobmff.rs:724-728` | P0-P3 (P0-5) | `largesize` is attacker-controlled: a value that does not fit in | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 76 | `src/structure/adapters/isobmff.rs:885-888` | P0-P3 (P3-4) | A meta body may end in <8 bytes that cannot start a box header (zero | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 77 | `src/structure/adapters/isobmff.rs:925-931` | P0-P3 (P3-5) | Entry header: size/type (8) + version (1); the item id sits at +12 | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 78 | `src/structure/adapters/isobmff.rs:1106-1112` | P0-P3 (P3-3) | Only extents that physically live after the old meta | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 79 | `src/structure/adapters/isobmff.rs:1286-1287` | P0-P3 (P3-4) | The <8-byte meta residue the inject side carried through verbatim | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 80 | `src/structure/adapters/isobmff.rs:2183-2185` | P0-P3 (P1-1) | A crafted ultra-short `iloc` (the meta sub-box walk only guarantees | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 81 | `src/structure/adapters/isobmff.rs:2220-2222` | P0-P3 (P2-1) | An iloc item count larger than the box contents must be rejected by | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 82 | `src/structure/adapters/isobmff.rs:2320-2322` | P0-P3 (P2-2) | An infe entry declaring `item_id = u32::MAX` must refuse the carrier: | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 83 | `src/structure/adapters/isobmff.rs:2337-2338` | P0-P3 (P2-3) | The non-AEAD header can be fully forged, so strip must cross-check the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 84 | `src/structure/adapters/isobmff.rs:2416-2417` | P0-P3 (P2-08) | A `meta` box behind an 8 MiB `mdat` must be reached by seeking over the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 85 | `src/structure/adapters/jpeg.rs:256-259` | P0-P3 (P3-19) | app_segment hides the chain before SOS. A header chain past | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 86 | `src/structure/adapters/mkv.rs:113-117` | P0-P3 (P0-2) | `ebml_void` appends, so the envelope has to end exactly at the file | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 87 | `src/structure/adapters/pdf.rs:16-21` | P0-P3 (P1-3) | Whether the newest cross-reference section is an XRef *stream* rather | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 88 | `src/structure/adapters/pdf.rs:39-43` | P0-P3 (P1-3) | `/Encrypt` reference from the newest trailer (classic or XRef stream), | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 89 | `src/structure/adapters/pdf.rs:55-59` | P0-P3 (P1-3) | An encrypted document cannot be extended incrementally: the new trailer | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 90 | `src/structure/adapters/pdf.rs:171-176` | P0-P3 (P1-3) | End offset of the first balanced `<< ... >>` dictionary in `text`. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 91 | `src/structure/adapters/pdf.rs:787-790` | P0-P3 (P1-3) | 5. Write the incremental cross-reference section in the document's | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 92 | `src/structure/adapters/pe.rs:449-453` | P0-P3 (P0-2) | `pe_overlay` always appends, so the envelope must end exactly at the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 93 | `src/structure/adapters/pe.rs:683-696` | P0-P3 (P1-1) | Defensive check: carrier must not already contain a pe_codebits channel. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 94 | `src/structure/adapters/pe.rs:721-722` | P0-P3 (P3-7) | The channel header stores the slack offset as u32; a run beyond 4 GiB | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 95 | `src/structure/adapters/pe_codebits.rs:48-50` | P0-P3 (P1-5) | Channel positions needed before the header can be unpacked: the 14 header | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 96 | `src/structure/adapters/pe_codebits.rs:605-607` | P0-P3 (P1-5) | The mask key is the 8-byte envelope header magic at the very start of the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 97 | `src/structure/adapters/pe_codebits.rs:899-905` | P0-P3 (P1-5) | Review P1-5 regression: the pre-fix implementation derived the mask from | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 98 | `src/structure/adapters/pe_codebits.rs:921-921` | P0-P3 (P1-5) | The old P1-5 derivation: HKDF over the 4 visible magic bytes. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 99 | `src/structure/adapters/pe_codebits.rs:933-934` | P0-P3 (P1-5) | Sanity check: under the old scheme the visible magic alone restored | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 100 | `src/structure/adapters/png.rs:231-234` | P0-P3 (P0-2) | Stealth and custom-magic dialects use a password/seed-derived 8-byte | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 101 | `src/structure/adapters/png.rs:306-309` | B (B-01) | Concatenated PNG streams are legal input. The next stream's | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 102 | `src/structure/adapters/png.rs:410-412` | B (B-01) | Keep verifying a concatenated stream too: hiding before the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 103 | `src/structure/adapters/png.rs:464-464` | B (B-01) | Continue through a concatenated PNG stream (review B-01). | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 104 | `src/structure/adapters/riff.rs:101-106` | P0-P3 (P1-2) | The declared size can agree with the file length while the chunk table | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 105 | `src/structure/adapters/riff.rs:448-453` | P0-P3 (P3-17) | Whether `riff_chunk` can accept this carrier and envelope: the declared | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 106 | `src/structure/adapters/wav.rs:26-29` | P0-P3 (P1-2) | riff_chunk must stay symmetric: the declared boundary must be the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 107 | `src/structure/adapters/zip.rs:77-86` | P0-P3 (P0-3) | Whether the bytes at `cd_offset` really start a central-directory record. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 108 | `src/structure/adapters/zip.rs:95-104` | P0-P3 (P2-7) | Whether a ZIP64 EOCD locator sits immediately before the EOCD record. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 109 | `src/structure/engine.rs:124-126` | P0-P3 (P1-7) | Trailer magic derived from the same PBKDF2 run. Level 1 and Level 2 | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 110 | `src/structure/engine.rs:175-190` | P0-P3 (P0-2) | Reject a located envelope that cannot physically fit inside the carrier. | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 111 | `src/structure/engine.rs:234-236` | P0-P3 (P2-6) | A 10-byte u64 varint may only use bit 0 of its last byte; the other | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 112 | `src/structure/engine.rs:389-398` | P0-P3 (P2-09) | Materialize this source into `(bytes, stored filename, is_file)`. | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 113 | `src/structure/engine.rs:1259-1266` | P0-P3 (P1-9) | Where the envelope lands relative to the injection point. Strategies | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 114 | `src/structure/engine.rs:1784-1789` | P0-P3 (P1-7) | [`open_and_authenticate_envelope`] for an envelope the caller already | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 115 | `src/structure/engine.rs:2073-2077` | P0-P3 (P0-7) | Write through a sibling temp file and rename, exactly like every carrier | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 116 | `src/structure/engine.rs:2625-2629` | B (B-06) | An envelope we can see but cannot open with this profile is a private | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 117 | `src/structure/engine.rs:2633-2635` | B (B-06) | Staying invisible to a reader that does not hold the dialect is | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 118 | `src/structure/engine.rs:2644-2648` | B (B-06) | A header that fails the level-2 shape check is not a readable envelope; | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 119 | `src/structure/engine.rs:2806-2827` | P0-P3 (P1-9) | Shared verify logic over any seekable reader (a `File` on the path path, a | **修正** | 删掉前两行（`verify_core` 的文档误粘到 `envelope_coordinates_agree`），保留 2808 行起的坐标交叉校验说明。 |
| 120 | `src/structure/engine.rs:2966-2969` | P0-P3 (P1-7) | A single locate scan feeds Level 1's stealth trailer magic, Level 2's | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 121 | `src/structure/engine.rs:3087-3101` | P0-P3 (P1-9) | `locate_envelope` derived these numbers from | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 122 | `src/structure/engine.rs:3243-3245` | P0-P3 (P2-6) | 9 continuation bytes followed by 0x02: the old loop shifted the | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 123 | `src/structure/engine.rs:3424-3427` | P0-P3 (P1-7) | Locating a stealth carrier derives the magics (one PBKDF2); Level 2 | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 124 | `src/structure/engine.rs:3437-3439` | P0-P3 (P2-12) | P2-12: the content domain already treats `Some("")` as "no password"; | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 125 | `src/structure/engine.rs:3469-3472` | P0-P3 (P2-2) | Review G2 (P2-2): advertised strategy capacities never exceed the | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 126 | `src/structure/envelope.rs:368-389` | P0-P3 (P0-2) | Associated data bound into the metadata seal and every payload chunk. | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 127 | `src/structure/envelope.rs:637-641` | N (N-02) | The version is checked by the level-2 verifier, not here, so a | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 128 | `src/structure/envelope.rs:917-919` | P0-P3 (P2-21) | P2-21: strategy IDs start at 1, but the default de-mask path used | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 129 | `src/structure/envelope.rs:938-941` | P0-P3 (P2-21) | P2-21: the encrypted non-stealth header is stored unmasked, so its flag | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 130 | `src/structure/envelope.rs:956-961` | F (F-14) | P2 F-14: masked default headers used to pass the bare gate on | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 131 | `src/structure/envelope.rs:1005-1008` | P0-P3 (P1-8) | P1-8: the old constants advertised 213 B as the smallest writable | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 132 | `src/structure/rejection.rs:305-310` | P0-P3 (P3-22) | Find the EOCD. Garbage appended after a valid archive may itself contain | **精简** | 只删去前缀编号（如 `P1-3:`），正文保留。 |
| 133 | `src/structure/rejection.rs:352-360` | P0-P3 (P0-4) | The buffer must *be* the central directory, not merely be readable. | **精简** | 删去编号与历史过程（“曾经/旧实现/修复前”），压缩为一句“当前为什么这样”的约束说明。 |
| 134 | `tests/heavy/heavy_algorithm_matrix.rs:338-340` | P0-P3 (P2-1) | Working-set budget / capacity refusal (review P2-1): a | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 135 | `tests/heavy/heavy_stego.rs:387-392` | P0-P3 (P2-3) | Which diagnostic depends on the carrier: a complete table | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 136 | `tests/heavy/heavy_stego.rs:447-456` | P0-P3 (P2-3) | Documented limitation: a carrier whose luma AC table | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 137 | `tests/local/local_corpus.rs:1-36` | F (F-02) | Corpus-level batch runner — Rust counterpart of Python | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 138 | `tests/local/local_corpus.rs:318-319` | F (F-02) | The metadata seal is authenticated before stripping (F-02), so an | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 139 | `tests/local/local_media.rs:121-123` | F (F-02) | Strip / remove and check 100% bit-exact restoration. The | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 140 | `tests/local/local_media.rs:172-173` | F (F-02) | Encrypted envelope: the metadata seal is checked before | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 141 | `tests/test_cli/cli_unification.rs:981-985` | P0-P3 (P2-13) | P2-13: in a multi-carrier `read --auto -o <DIR>`, every redirected content | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 142 | `tests/test_cli/cli_unification.rs:1075-1077` | F (F-03) | F-03: a carrier that already holds content payload must not be embedded a | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 143 | `tests/test_cli/cli_unification.rs:1144-1146` | F (F-03) | F-03: a structure envelope written on top of content payload produces a | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 144 | `tests/test_cli/cli_unification.rs:1178-1179` | F (F-03) | F-03: content payload embedded on top of a structure envelope also builds a | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 145 | `tests/test_cli/config.rs:70-71` | P0-P3 (P1-8) | `[stego]` has its own key set and was not checked at all, so a typo like | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 146 | `tests/test_cli/sources.rs:602-605` | P0-P3 (P1-8) | Reading without any password source surfaces the hint. With `--stdout` | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 147 | `tests/test_lifecycle/facade.rs:236-238` | B (B-07) | `-o <carrier>` and "no `-o` at all" describe the same in-place write; the | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 148 | `tests/test_lifecycle/facade.rs:270-272` | B (B-07) | `read -o <carrier>` would replace the only copy of the hidden data with the | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 149 | `tests/test_lifecycle/facade.rs:851-853` | P0-P3 (P1-5) | Cancel before write. The marker must not be `Interrupted`: `write_all` | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 150 | `tests/test_lifecycle/profile.rs:126-129` | B (B-06) | Inspect must report "nothing here" for a dialect it cannot open, not an | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 151 | `tests/test_lifecycle/stego.rs:616-618` | B (B-03) | B-03 / T-09: the advertised maximum is a **file** maximum too. A 255-byte | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 152 | `tests/test_lifecycle/stego_jpeg_v4.rs:151-154` | P0-P3 (P1-1) | P1-1: inspect used to ignore `max_payload_bytes`/`allowed_suites` while | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 153 | `tests/test_media/hevc_stego.rs:505-512` | F (F-01) | Regression (F-01): the writer's decode window must never stop below the | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 154 | `tests/test_media/hevc_stego.rs:552-554` | N (N-01) | N-01: the file-level MP4/Annex-B patch branch must apply the same | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 155 | `tests/test_pe/codebits.rs:720-722` | P0-P3 (P2-2) | The engine enforces `256 x host`, clamped to [64 MiB, 1 GiB]; the | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 156 | `tests/test_pe/codebits.rs:878-880` | P0-P3 (P1-5) | Extract the first 176 bits: 14 bytes of ChannelHeader plus the first 8 | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 157 | `tests/test_pe/codebits.rs:930-931` | P0-P3 (P1-5) | 5. The visible 4-byte magic cannot reproduce the mask: an IKM that only | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 158 | `tests/test_pe/codebits.rs:1048-1049` | P0-P3 (P1-1) | 2. Second injection without knowledge of first password (explicit pe_codebits) | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 159 | `tests/test_pe/codebits.rs:1289-1292` | P0-P3 (P1-8) | P1-8: a 213-byte codebits channel must not be advertised as available. | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 160 | `tests/test_pe/slack.rs:599-602` | F (F-02) | Flip a byte in the payload ciphertext, past the header, hint and the | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 161 | `tests/test_regression/fixes.rs:59-59` | P0-P3 (P0-3) | --------------------------------------------------------------------------- R1 / P0-3 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 162 | `tests/test_regression/fixes.rs:134-134` | P0-P3 (P0-2) | --------------------------------------------------------------------------- R2 / P0-2 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 163 | `tests/test_regression/fixes.rs:258-258` | P0-P3 (P0-4) | --------------------------------------------------------------------------- R3 / P0-4 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 164 | `tests/test_regression/fixes.rs:405-405` | P0-P3 (P0-1) | --------------------------------------------------------------------------- P0-1 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 165 | `tests/test_regression/fixes.rs:443-443` | P0-P3 (P1-5) | --------------------------------------------------------------------------- R4 / P1-5 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 166 | `tests/test_regression/fixes.rs:554-554` | P0-P3 (P1-6) | --------------------------------------------------------------------------- P1-6 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 167 | `tests/test_regression/fixes.rs:793-793` | P0-P3 (P0-1) | --------------------------------------------------------------------------- P0-1 write-pat | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 168 | `tests/test_regression/fixes.rs:845-848` | P0-P3 (P1-6) | P1-6: EOF-overlay carriers (RIFF/WAV, MKV, PDF) must pass L1 for stealth | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 169 | `tests/test_regression/fixes.rs:903-908` | P0-P3 (P0-2) | P0-2: a PNG `chunk` envelope written first, then content-domain embedding, | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 170 | `tests/test_regression/fixes.rs:1073-1075` | F (F-02) | F-02: the restored output is committed only after the envelope metadata | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 171 | `tests/test_regression/fixes.rs:1124-1126` | F (F-02) | F-02: `patch_offset` and the injection geometry are outside the AAD, so | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 172 | `tests/test_regression/fixes.rs:1207-1207` | F (F-05) | --------------------------------------------------------------------------- F-05 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 173 | `tests/test_regression/p2_protocol.rs:43-47` | P0-P3 (P1-3) | XRef-stream PDF whose dictionary nests `/DecodeParms << ... >>` *before* | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 174 | `tests/test_regression/p2_protocol.rs:193-194` | P0-P3 (P1-3) | The update must repeat the document's dialect: an XRef stream object, | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 175 | `tests/test_regression/p2_protocol.rs:427-430` | P0-P3 (P1-3) | The backward `%%EOF` scan is capped at 1 MiB from the effective PDF tail. | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 176 | `tests/test_regression/p2_protocol.rs:510-512` | B (B-06) | `verify` still reports the precise Level-2 diagnostic (test above), but | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 177 | `tests/test_regression/p2_protocol.rs:551-555` | P0-P3 (P0-2) | A metadata block is at most a filename plus a fixed tail, so the reader | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 178 | `tests/test_regression/review_20261019.rs:45-45` | P0-P3 (P1-1) | --------------------------------------------------------------------------- P1-1 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 179 | `tests/test_regression/review_20261019.rs:101-101` | P0-P3 (P2-2) | --------------------------------------------------------------------------- P2-2 / A-11 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 180 | `tests/test_regression/review_20261019.rs:240-241` | P0-P3 (P1-8) | `--stdout` reserves stdout for the payload, so the hint (apostrophe | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 181 | `tests/test_regression/review_20261019.rs:371-371` | P0-P3 (P1-2) | --------------------------------------------------------------------------- P1-2 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 182 | `tests/test_regression/review_20261019.rs:450-450` | P0-P3 (P2-3) | --------------------------------------------------------------------------- P2-3 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 183 | `tests/test_regression/review_20261019.rs:563-563` | P0-P3 (P2-4) | --------------------------------------------------------------------------- P2-4 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 184 | `tests/test_regression/review_20261019.rs:601-601` | P0-P3 (P2-1) | --------------------------------------------------------------------------- P2-1 | **删除** | 删除该分隔横幅/编号；测试函数名已说明归属。 |
| 185 | `tests/test_regression/review_20261025.rs:42-45` | P0-P3 (P2-6) | A 22-byte ZIP consisting of nothing but an EOCD record with a zero Central | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 186 | `tests/test_regression/review_20261025.rs:118-121` | P0-P3 (P1-2) | A WAV whose declared RIFF boundary is not the physical end of the file | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 187 | `tests/test_regression/review_20261025.rs:177-184` | P0-P3 (P1-2) | P1-2: a declared RIFF size can match the file length even when the final | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 188 | `tests/test_regression/review_20261025.rs:225-227` | P0-P3 (P0-1) | L1 must call the table malformed, so the P0-1 pre-write gate refuses | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 189 | `tests/test_regression/review_20261025.rs:259-262` | P0-P3 (P1-1) | End-to-end roundtrip over the item_hidden iinf/iloc patch and restore core | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 190 | `tests/test_regression/review_20261025.rs:345-348` | P0-P3 (P1-4) | A PDF whose dirty tail pushes the injected `%%EOF`/`endstream` pair beyond | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 191 | `tests/test_regression/review_20261025.rs:402-405` | P0-P3 (P2-5) | The writer emits `UBE + "\nendstream"`, so the trailer always ends exactly | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 192 | `tests/test_regression/review_20261025.rs:430-433` | P0-P3 (P1-3) | An encrypted document (`/Encrypt` in the newest trailer) must refuse the | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 193 | `tests/test_regression/review_20261025.rs:498-501` | P0-P3 (P2-7) | A ZIP64 archive with an EOCD64 locator before the classic EOCD (classic | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 194 | `tests/test_regression/review_20261025.rs:574-577` | P0-P3 (P2-4) | item_hidden tops out at a ~4 GiB envelope (32-bit mdat size + iloc | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 195 | `tests/test_regression/review_20261025.rs:597-599` | P0-P3 (P3-17) | WAV/WebP auto must keep riff_chunk only when write and read agree (clean | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 196 | `tests/test_regression/review_20261025.rs:665-668` | P0-P3 (P1-1) | P1-1: the APP15 chain is inserted *before* SOS, so a large chain pushes SOS | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 197 | `tests/test_regression/review_20261025.rs:752-755` | P0-P3 (P3-19) | A JPEG whose header chain (EXIF/ICC/…) runs past the 16 MiB marker-scan | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 198 | `tests/test_regression/review_20261025.rs:794-796` | P0-P3 (P3-4) | [`make_heif_with_meta`] with `pad` zero bytes appended inside the meta box | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 199 | `tests/test_regression/review_20261025.rs:813-815` | P0-P3 (P3-4) | Dropping the meta residue used to shift every later offset: inject | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 200 | `tests/test_regression/review_20261025.rs:854-856` | P0-P3 (P3-5) | An iinf declaring more entries than it carries used to end the max_id scan | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 201 | `tests/test_regression/review_20261025.rs:878-880` | P0-P3 (P3-3) | A 64-bit iloc extent offset with no headroom for the meta growth used to | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 202 | `tests/test_regression/review_20261025.rs:902-905` | P0-P3 (P3-18) | Two concatenated PNGs. The write side inserts before the LAST IEND while | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 203 | `tests/test_regression/review_20261030.rs:13-17` | P0-P3 (P0-1) | `ftyp` + one box whose 64-bit `largesize` is `u64::MAX`. | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 204 | `tests/test_regression/review_20261031.rs:14-20` | P0-P3 (P0-1) | `PK\x03\x04` + 60 filler bytes + an EOCD whose `cd_size` is smaller than the | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 205 | `tests/test_regression/review_20261031.rs:67-72` | P0-P3 (P1-5) | A cancelled `ProgressWriter` must fail fast. | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 206 | `tests/test_regression/review_20261031.rs:100-103` | P0-P3 (P1-2) | Deleting the last 12 bytes of a PNG and appending a payload used to produce | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 207 | `tests/test_regression/review_20261031.rs:135-137` | P0-P3 (P2-11) | A carrier without IEND cannot be re-encoded byte-for-byte, so the content | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 208 | `tests/test_regression/review_20261031.rs:159-165` | P0-P3 (P2-17) | A 204-byte MP4 whose trailer claims a 1 TiB envelope and whose header claims | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 209 | `tests/test_regression/review_20261031.rs:230-234` | P0-P3 (P1-7) | Same blind spot as the PNG `IEND` case above, in the JPEG marker walk: a | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 210 | `tests/test_security/forge.rs:1-13` | P0-P3 (P0-2) | P0-2: the envelope locator must not be usable as an allocation primitive. | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |
| 211 | `tests/test_security/password_hint.rs:221-225` | P0-P3 (P0-3) | P0-3: the hint is plaintext (it has to be readable without the password), | **精简** | 只删去编号/批次标签，测试意图原文保留。 |
| 212 | `tests/test_security/rejection.rs:112-115` | P0-P3 (P3-22) | Garbage trailing an archive may itself contain `PK\x05\x06`; taking the | **精简** | 删去编号/审查日期与“旧行为”过程，保留该样本或参数为何不可替换的说明。 |

## 九、附录 B：复核方法

### 9.1 注释总量

```bash
python temp/comment_audit/scan.py
```

脚本逐行判断 `^\\s*//`、`///`、`//!` 与 `/* ... */`（实际无块注释），输出 `temp/comment_audit/summary.json`。

### 9.2 编号与历史引用

```bash
rg -n --no-heading "\bP[0-3]-[0-9]+" rust/src rust/tests rust/examples -g "*.rs"
rg -n --no-heading "\b[BFLNXH]-[0-9]+|\bLOGIC-[0-9]+|\bR-[0-9]+" rust/src rust/tests rust/examples -g "*.rs"
rg -n --no-heading -i "fixplan|code[_-]review|disposition|bugfix|\breview|regression" rust/src rust/tests rust/examples -g "*.rs"
```

注意：`review` 必须带 `\b`；否则会命中 `preview`，本次初查就出现过该误报。

### 9.3 失效文档引用

```bash
python temp/comment_audit/docrefs.py
```

脚本提取注释中的 `docs/...` 路径并对 `Test-Path` 做存在性检查；输出 24 处失效、16 个文档、3 处有效。

### 9.4 历史叙述

```bash
python temp/comment_audit/hist.py
```

输出 190 行命中“历史词”的注释。**必须人工复核**：`used to` 既可能是历史（`used to be`），也可能是用途（`used to place payload bits`）；`no longer` 多数在描述当前约束，而不是历史。不能按正则批量删除。

### 9.5 局限

- 本报告未逐条重写 15,000+ 行非编号注释；对非编号注释采用“重点约束 + `SAFETY` + 历史词”抽样复核。
- GUI 只做了编号/文档引用粗查，未做逐行语义审计。
- 行号基于 2026-11-07 当前工作树；后续改动会使行号漂移，应以文件路径 + 注释首句定位。

## 十、附录 C：人工复核的 30 个历史叙述块

判定为“删除”的 8 块只删除批次/日期/审查标签或旧行为句，不删除整段；判定为“精简”的 14 块保留当前约束；判定为“保留”的 8 块本身就在解释当前约束，历史词只是叙述习惯。

| # | 位置 | 首行摘要 | 判定 |
|---:|---|---|---|
| 1 | `rust/tests/test_cli/p2.rs:1-11` | Regression tests for P2 CLI/security alignment (2026-10-17), batch 3. | 删除（批次/日期标签） |
| 2 | `rust/tests/test_cli/sources.rs:1-12` | CLI payload/password source coverage (gap report 2026-10-19, gaps #1 #2 #5). | 删除（gap 编号） |
| 3 | `rust/tests/test_cli/verify.rs:1-15` | verify / warning / CLI-output coverage (gap report 2026-10-19, gaps #3 #4 #6 #7). | 删除（gap 编号） |
| 4 | `rust/tests/test_regression/fixes.rs:1-4` | Regression tests for the P0/P1 security and correctness fixes (2026-10-17). | 删除（日期/批次） |
| 5 | `rust/tests/test_regression/p2_fixes.rs:1-8` | Regression tests for P2 engineering-quality fixes (2026-10-17). | 删除（日期/批次） |
| 6 | `rust/tests/test_regression/p2_protocol.rs:1-8` | Regression tests for P2 protocol/diagnostic fixes (2026-10-17), batch 2. | 删除（日期/批次） |
| 7 | `rust/src/structure/adapters/isobmff.rs:1385-1386` | (review 2026-10-25) | 删除（审查日期标签） |
| 8 | `rust/src/structure/adapters/isobmff.rs:1814-1816` | A v2+ iloc box of 16 or 17 bytes cannot hold the 32-bit item count... | 删除（审查日期标签） |
| 9 | `rust/src/analysis.rs:267-270` | Bytes after the container's own end marker are a structural fact, not a... | 精简 |
| 10 | `rust/src/analysis.rs:929-936` | Structural checks for a JPEG, returning whether the marker stream reached... | 精简 |
| 11 | `rust/src/analysis.rs:2178-2179` | Four coincidental magic bytes used to be enough for a `Likely` finding; | 精简 |
| 12 | `rust/src/analysis.rs:2736-2737` | ftyp with a HEIC major brand: the private sniffer used to call every... | 精简 |
| 13 | `rust/src/cli/helpers.rs:837-840` | Four hex digits right after a high surrogate used to be read as a... | 精简 |
| 14 | `rust/src/core/commit.rs:832-835` | A read-only target used to fail inside `rename_with_retry`, which... | 精简 |
| 15 | `rust/src/stego/params.rs:359-361` | Out-of-range values used to be silently clamped while ranking and... | 精简 |
| 16 | `rust/src/stego/hevc/engine.rs:1940-1959` | Keyed stride permutation of each drift band, consumed band by band. | 精简 |
| 17 | `rust/src/stego/hevc/engine.rs:4787-4788` | Regression tests for the safety-policy gate (bug B1: the HEVC path used to... | 精简 |
| 18 | `rust/src/stego/hevc/mp4_boxes.rs:990-992` | A fixed-size `stsz` used to allocate `count` entries straight from the... | 精简 |
| 19 | `rust/src/stego/png/engine.rs:2962-2964` | The regression that motivated chunk/filter passthrough: a smooth... | 精简 |
| 20 | `rust/src/structure/engine.rs:3457-3459` | The no-password path used to derive the profile default secret twice: | 精简 |
| 21 | `rust/src/analysis.rs:1563-1568` | Contiguous row slabs covering the top, middle and bottom of the image. | 精简 |
| 22 | `rust/src/structure/adapters/pe_codebits.rs:889-891` | An unmasked (pre-v1) header no longer parses: the version byte is... | 精简 |
| 23 | `rust/src/lib.rs:159` | Historical path: the message catalogue used to live at `strhide::i18n`. | 保留 |
| 24 | `rust/src/structure/engine.rs:1009-1017` | Refuse malformed hosts before touching them. Detection is deliberately... | 保留 |
| 25 | `rust/src/structure/envelope.rs:844-848` | A magic mismatch is the normal "no envelope here" outcome. A matching... | 保留 |
| 26 | `rust/src/structure/adapters/zip.rs:147-150` | An empty archive has its Central Directory at offset 0: the UBE... | 保留 |
| 27 | `rust/src/structure/adapters/pe.rs:573-578` | Hard evidence first: a strhide header magic inside padding can only be... | 保留 |
| 28 | `rust/src/stego/png/engine.rs:999-1000` | A chunk over 4 GiB used to be truncated by `as u32`, writing a length... | 保留 |
| 29 | `rust/src/stego/jpeg/engine.rs:846-847` | V4 `body_len` is the ciphertext length including the AEAD tag; there is... | 保留 |
| 30 | `rust/src/stego/jpeg/registry.rs:56-57` | The removed "wow"/"nsf5" aliases made callers believe a different... | 保留 |
