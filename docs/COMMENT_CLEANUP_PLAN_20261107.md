# 注释清理建议（2026-11-07）

- 审计时间：2026-11-07 20:30（Asia/Shanghai）
- 范围：`rust/src`、`rust/tests`、`rust/examples`、`gui/src`、`gui/src-tauri/src` 全部 `.rs` / `.ts` / `.tsx`
- 性质：**只读审计，未改动任何源码或注释**，未 commit/push
- 基线：HEAD `e25278a`，工作区另有未提交改动
- 判定口径：删掉之后，读者是否还需要重新推导。需要 = 保留（可就地压缩），不需要 = 删除

## 一、结论摘要

项目里**没有** `TODO` / `FIXME` / `XXX` / `HACK`，也没有注释掉的废弃代码。噪声只有两类：**bugfix 编号标签**和**修复过程的历史叙述**。

| 指标 | 数值 |
|---|---:|
| 文件数 | 244 |
| 总行数 | 119,586 |
| 注释行 | 16,967（14.2%） |
| 注释块（连续注释归为一块） | 5,967 |
| 带 bugfix 编号的注释块 | 247（1,142 行） |
| 仅历史叙述、无编号的注释块 | 50（260 行） |
| 合计需过一遍 | 297 块 / 1,402 行，占注释行 8.3% |

247 个编号块互不重叠地分成四类：

| 类别 | 处置 | 块数 | 行数 |
|---|---|---:|---:|
| A | 只摘编号，正文一字不动 | 164 | 804 |
| B | 删掉历史过程，保留当前约束 | 23 | 125 |
| C | 编号查不到，需改引用 | 36 | 189 |
| D | 整段删除 | 24 | 24 |

按目录：

| 目录 | 编号块 | 编号行 | 纯历史块 | 历史行 |
|---|---:|---:|---:|---:|
| `rust/src` | 153 | 797 | 41 | 223 |
| `rust/tests` | 92 | 339 | 9 | 37 |
| `rust/examples` | 0 | 0 | 0 | 0 |
| `gui/` | 2 | 6 | 0 | 0 |

**核心判断：这 247 个编号块里，真正该整段删掉的只有 24 块。绝大多数只需摘掉 `P1-3:`、`(review R3 P1-1)` 这类标签，正文是在讲当前约束，删了会让人重新踩坑。**

## 二、建议直接删除（D 类，24 块）

全部是测试文件里用编号当分节标题的横线：

```rust
// --------------------------------------------------------------------------- R1 / P0-3

#[test]
fn stealth_requires_password() {
```

`rust/tests/test_regression/review_20261019.rs` 16 处、`fixes.rs` 8 处。

这些横线既没当标题用（下面的 `fn` 名已经说明了用例），编号也检索不到对应条目。**整行删除**，或换成无编号的 `// ---- 名称 ----`。

另有 43 行纯装饰横线（`analysis.rs` 16、`stego/png/engine.rs` 10、`pe_codebits.rs` 8 等）和 106 行带文字的分节标签（`messages.rs` 22、`matrix.rs` 8 等）。前者无害也无用，后者是正常的分节说明，都不建议为它们单开一批改动。

## 三、三处该修的事实性错误

### 3.1 `stego/params.rs:527`：同一段里 256 MiB 与 4 GiB 并存

```text
/// * memory -- one slot costs `2^h / 64` words of traceback state (32 B at
///   `h = 8`, 128 B at `h = 10`), so 256 MiB allows 8.4M slots at `h = 8`;
```

同文件 531 行 `MAX_AUTO_BACKTRACK_BYTES = 4 << 30`（4 GiB），536 行注释明写 "Set to 4 GiB"，540 行按 4 GiB 算出 134M slots。**8.4M 与 134M 差 16 倍**，改成 `4 GiB allows 134M slots at h = 8`。

### 3.2 `structure/engine.rs:461`：描述过窄

```rust
/// The English sentence this warning used to be, kept for CLI rendering.
```

`message()` 不只给 CLI：`render()` 的 `Lang::En` 分支（480 行）和 `Display`（500 行）都调它。改成 "English text used by `Display` and CLI rendering; localized text goes through `render()`"。

### 3.3 `structure/engine.rs:2806-2807`：文档挂错了函数

```rust
/// Shared verify logic over any seekable reader (a `File` on the path path,
/// a `Cursor` on the bytes path).
/// Cross-check the header's injection coordinates against the located envelope.
fn envelope_coordinates_agree(
```

前两行是 `verify_core` 的文档，却挂在 `envelope_coordinates_agree` 上；真正的 `verify_core`（同文件 2952 行）反倒没有文档。把前两行移到 `verify_core`，本函数只留第三行。

## 四、失效引用（C 类，36 块）

### 4.1 指向已删除的文档（16 个文档、24 处）

按图索骥必然失败：

| 位置 | 失效引用 | 建议 |
|---|---|---|
| `structure/adapters/pe_codebits.rs:12` | `docs/pe_codebits_plugin_design.md` | 整行删；设计要点已在该文件 3-24 行的模块文档里 |
| `structure/mod.rs:11`、`structure/params.rs:4`、`formats/mod.rs:6` | `docs/strhide_architecture_and_refactoring_plan.md` | 删路径，依赖方向一句话够用 |
| `stego/params.rs:512`、`examples/v3_eval.rs:16` | `docs/stc_v3_phase3_eval_20261021.md` | 删路径，保留"由 Phase 3 网格测出" |
| `stego/format.rs:611`、`stego/header.rs:544`、`stego/hevc/engine.rs:5029`、`stego/jpeg/header_v4.rs:186` | `docs/stego_content_envelope_v4_golden_vectors_20261103.md` | 改指存在的 `docs/api/WIRE_SPEC_CONTENT.md` |
| `analysis.rs:28`、`analysis.rs:1536`、`tests/heavy/heavy_stego.rs:42` | `docs/png_blind_calibration_20261023.md` | 删路径，保留阈值与样本理由 |
| `stego/hevc/engine.rs:4088` | `docs/hevc_video_capacity_quality_audit_20261026.md` | 删路径，保留 15-20 dB 的测量值 |
| `analysis.rs:90` | `docs/stego_keyed_parameters_plan_20261020.md` §13 | 删路径，保留"按固定种子重算" |
| `tests/test_regression/review_20261019/25/30/31.rs` 文件头 | 4 个 review 文档 | 保留"历史回归用例"定位，删链接 |
| `tests/heavy/heavy_stego.rs:49` | `docs/stego_remediation_plan_20261023_1815.md` | 删路径 |
| `tests/heavy/heavy_stego.rs:660` | `docs/embed_png_jpeg_algorithm_review_20261020_db.md` §9.3 | 删路径与 § |
| `tests/local/local_media.rs:802` | `docs/hevc_steganalysis_and_quality_spec_20261026.md` | 删路径 |
| `tests/test_lifecycle/profile.rs:3` | `docs/library_api_practical_plan_20261020.md` | 删路径，保留 M1 验收点 |
| `examples/codec_bench.rs:7` | `docs/stc_coding_design_20261021.md` | 删路径 |

仍然有效的引用只有 3 处（`docs/api/WIRE_SPEC_CONTENT.md`、`docs/api/cost-vectors.json`、`docs/PERF_BENCHMARK_PLAN_20261107.md`），保留。

### 4.2 6 条 rustdoc 告警（`cargo doc --document-private-items`）

| 位置 | 问题 |
|---|---|
| `structure/engine.rs:1723` | `[`read_carrier_with_profile`]` —— 已改名 `read_carrier_with_dialect` |
| `structure/engine.rs:2195` | `[`remove_carrier_with`]` —— 已改名 `remove_carrier_with_dialect` |
| `stego/audio/flac/mod.rs:1193` | `[`max_sample_drift`]` 在同文件 1264 行，缺 `self::` 前缀 |
| `stego/io.rs:393` | `[`hevc::EMBED_WINDOW_GOPS`]` 实际在 `hevc::engine` |
| `analysis.rs:1934` | `[`chi2_lsb_suspicion`]` 在同文件 1926 行，缺 `self::` 前缀 |
| `structure/engine.rs:1938` | `'<memory>'` 里的 `<` 被当成 HTML 标签 |

这几条不属于"注释太多"，属于"注释错了"，建议一并修。

## 五、编号本身的问题（比冗余更该优先处理）

### 5.1 同一编号指不同问题

| 编号 | 冲突情况 |
|---|---|
| `P1-1` | 4 个条目：JPEG 概率性失败 / `inspect_jpeg` 缺策略校验 / 线格式震荡 |
| `P0-2` | release.yml 缺 `cli` feature / 结构域信封物理边界（两个不相干主题） |
| `P1-5` | FLAC `MD5_OFFSET` / PE codebits 头掩码 / 批量 `inspect` 退出码 |
| `P1-2` | 内容域规范不足 / 原地写不识别符号链接 |
| `P2-2` | 依赖链即线格式 / 独立审查批次 A 的容量报告 |
| `P2-14` | trace 格式化 / 时间戳权限恢复 / macOS 内存查询 |

`P1-1` 出现 13 次、`P1-5` 13 次、`P0-2` 10 次，恰好是冲突最严重的三个。其中**不带轮次前缀的裸编号**（`P1-1` 8 次、`P1-5` 9 次、`P0-2` 9 次）最危险——读者无法判断该去 `docs/` 哪一份报告里查。

### 5.2 一半的编号查不到

116 个不同编号（316 次引用）里，只有 **27 个能在稳定文档中找到**（`docs/api/*.md` 等）。其余 89 个分两种：

- **57 个完全无出处**（89 次引用），分布在 45 个注释块。例如 `R3 P1-1`（6 次）、`R3 P1-5`（4 次）、`R2 P1-9`、`P2-08`、`P3-17`（各 3 次）、`A-04`、`C-07`。带轮次前缀的 `R2/R3/R4 P*` 全部属于此类——`docs/` 里只有按日期命名的 `CODE-REVIEW-R{2,3}` 文档，且部分已被删除，编号本身没有落点。
- **32 个只在 `docs/CHANGES-*.md` 流水账里有上下文**（`A-01`~`A-10`、`B-01`~`B-07`、`F-01`~`F-26`、`P1-7`~`P2-23` 等）。

两类合起来，**77% 的编号对读者是纯噪声**：既查不到，也不告诉你任何当前信息。

### 5.3 changelog 是移动靶

`P0-2`、`P1-7` 这类编号的上下文只在 `docs/CHANGES-*.md`。CHANGES 按日期追加，编号随轮次重排（见 5.1），文件还在持续变长。**把 changelog 当注释脚注，等于把注释绑在会漂移的目标上。**

## 六、必须保留的

| 位置 | 内容 |
|---|---|
| `structure/envelope.rs` | header/trailer 布局、`HEADER_SIZE=112`、AAD 覆盖前 80 字节 + `meta_len`/`hint_len` |
| `structure/adapters/isobmff.rs` | `iloc`/`iinf`/`mdat` 偏移语义、每字节扫描预算 |
| `stego/*/engine.rs` | 槽位几何、成本模型、STC 网格参数 |
| `analysis.rs` | 校准阈值、误报边界、"干净结论 ≠ 没有隐藏数据" |
| `core/crypto.rs` | KDF/AEAD 参数、分块与 nonce 构造 |
| 10 处 `SAFETY:` | AVX2 门控、`OpenProcess` 权限、切片边界 |
| `stego/detmath.rs`、`stego/format.rs` 模块文档 | 可复现性契约，删了会导致跨实现不一致 |

**判断标准**：注释在解释"为什么不能改成另一种写法" → 留；只在解释"以前是什么样" → 删。

### 例外：测试里的历史句要留

`stego/hevc/heif_boxes.rs:839-861` 那三处写"old code panicked here"，是测试用例的**存在理由**，删了就看不出这个 fixture 为什么长这样。这类要保留。

## 七、执行顺序

| 阶段 | 内容 | 风险 | 收益 |
|---|---|---|---|
| 1 | 6 条 rustdoc 告警 + 文档挂错（3.3、4.2） | 无（纯注释） | `cargo doc` 干净 |
| 2 | 3 处事实错误（第三节） | 无 | 避免误导调参 |
| 3 | 24 个编号分隔符 + 失效文档引用（第二、四节） | 无 | 减约 70 行 |
| 4 | 164 个 A 类块：正则摘编号，正文不动 | 低 | 去掉全部过期溯源 |
| 5 | 23 个 B 类块 + 50 个纯历史块：改写句子 | 中（需读懂原意） | 减约 150 行 |

**阶段 4 的正则要白名单化文件。** `structure/adapters/pe_codebits.rs` 里的 `C3`、`F0`~`F5` 是 x86 操作码和设计文档的过滤器编号（`F0: skip data embedded in .text`），不是审计编号。本文统计已排除，批量替换时不要在 `pe_codebits.rs` 跑编号正则。

同理，`used to` 必须人工复核：`used to be enough`（历史）与 `used to place payload bits`、`Tail window used to find a container end marker`（用途）字面相同。本次全仓 135 行 `used to` 里有 18 行属于后者。

## 八、复核命令

```bash
cd rust && cargo doc --no-deps --document-private-items   # 6 条 rustdoc 告警

rg -o --no-heading 'docs/[A-Za-z0-9_./-]+\.md' rust/src rust/tests rust/examples | \
  sed 's/.*docs/docs/' | sort -u | while read p; do [ -f "$p" ] || echo "MISS $p"; done
```

## 附录 A：247 个编号块

`A` 摘编号 / `B` 删历史 / `C` 修引用 / `D` 整段删除。位置为当前工作树行号，后续改动会漂移。

| # | 位置 | 类别 | 编号 | 首行摘要 |
|---:|---|---|---|---|
| 1 | `gui/src-tauri/src/commands/stego.rs:521-523` | A | P2-7 | P2-7: an in-place embed (no `-o`, or `-o` equal to the carrier) used to |
| 2 | `gui/src-tauri/src/state.rs:393-395` | A | P2-7 | P2-7: the extraction cache used to key only on path/mtime/password, so |
| 3 | `rust/src/analysis.rs:492-494` | C | P1-3, R2P1-3 | Set when a PNG could not be turned into pixels at all (16-bit, Adam7, |
| 4 | `rust/src/analysis.rs:589-591` | A | B-03 | Four-byte patterns are far too common in compressed or random data |
| 5 | `rust/src/analysis.rs:645-648` | A | B-03 | Is the 4-byte trailer magic at `magic_pos` backed by a self-consistent |
| 6 | `rust/src/analysis.rs:789-793` | C | P1-2, R3P1-2 | Whole file, and the walk never reached IEND. A conforming |
| 7 | `rust/src/analysis.rs:1419-1423` | C | P1-7, R2P1-7 | `jpeg-decoder` allocates from the geometry declared in the header, not |
| 8 | `rust/src/analysis.rs:1674-1678` | C | P2-21, R3P2-21 | Deliberately informational: WS over-reports on content-adaptive |
| 9 | `rust/src/analysis.rs:1856-1859` | C | P1-4, R2P1-4 | Name the real gate. The old text said "e.g. q100", but the check |
| 10 | `rust/src/analysis.rs:1896-1897` | C | P1-4, R2P1-4 | Reporting nothing at all made a skipped detector indistinguishable |
| 11 | `rust/src/analysis.rs:1984-1985` | A | P2-23 | A 3x3 window starting at `i` needs `i + 2 < rows`, so the last start is |
| 12 | `rust/src/analysis.rs:2209-2211` | B | P2-23 | A 4x4 plane has two 3x3 window starts per axis (0 and 1). The loop |
| 13 | `rust/src/cli/cmd_diag.rs:19-24` | C | P2-6, R2P2-6 | Print the content-domain half of an `inspect` result. |
| 14 | `rust/src/cli/cmd_diag.rs:227-233` | A | P1-1, R3P1-1 | Whether the content verifier actually found an envelope. |
| 15 | `rust/src/cli/cmd_diag.rs:239-242` | A | P1-1, R3P1-1 | The `verify` exit verdict for one carrier. |
| 16 | `rust/src/cli/cmd_diag.rs:298-301` | A | P1-1, R3P1-1 | A content envelope that was found but does not verify fails the file |
| 17 | `rust/src/cli/cmd_diag.rs:561-564` | C | P1-10, R2P1-10 | Notes explain how to read the verdict, so the "a clean |
| 18 | `rust/src/cli/cmd_diag.rs:689-691` | A | P2-9 | Append one `{"path", "error"}` item per missing input, matching the shape |
| 19 | `rust/src/cli/cmd_diag.rs:862-864` | B | P1-1, R3P1-1 | The R3 P1-1 case: structure envelope intact, content envelope found but |
| 20 | `rust/src/cli/cmd_structure.rs:68-71` | C | P0-2, R2P0-2 | The prompt and `--stdin` both read standard input: whichever runs |
| 21 | `rust/src/cli/cmd_structure.rs:317-321` | C | P1-8, P2-2, R3P1-8, R3P2-2 | `--stdout` means the payload owns stdout, so the hint goes to |
| 22 | `rust/src/cli/cmd_structure.rs:373-377` | C | P1-2, R2P1-2 | Hand over the password already resolved here — the |
| 23 | `rust/src/cli/cmd_structure.rs:459-463` | C | P0-7, P1-4, R2P0-7, R3P1-4 | Same atomic commit as the explicit `-o` path and the library: a plain |
| 24 | `rust/src/cli/render.rs:220-222` | A | P1-1 | Present when the content-domain verifier failed to run. Serialized so |
| 25 | `rust/src/core/commit.rs:174-178` | A | P2-2 | Copy `src` into a freshly created `dst`. |
| 26 | `rust/src/core/commit.rs:203-206` | A | P2-2 | Create the `<carrier>.bak` for an in-place commit, retrying when the name |
| 27 | `rust/src/core/commit.rs:505-513` | A | P2-18 | Clear the write protection `fs::copy` cloned from the source. |
| 28 | `rust/src/core/commit.rs:564-568` | C | P0-6, R2P0-6 | Every span comes from a byte stream that was read before the copy. |
| 29 | `rust/src/core/commit.rs:778-780` | A | P2-18 | A fresh `-o <path>` target must still work: the temp copy inherits |
| 30 | `rust/src/core/config.rs:200-204` | C | P1-8, R2P1-8 | The sections have their own key sets and were not checked at all, so |
| 31 | `rust/src/core/control.rs:294-298` | A | P1-5, R3P1-5 | Not `ErrorKind::Interrupted`: `Write::write_all` (used by every |
| 32 | `rust/src/core/control.rs:331-334` | A | P1-5, R3P1-5 | Any I/O failure while the token is cancelled is the cancellation |
| 33 | `rust/src/core/crypto.rs:184-188` | A | P1-7 | Test-only count of PBKDF2 runs, used to prove that a single `verify` does |
| 34 | `rust/src/core/crypto.rs:331-341` | B | P1-5 | Derive a 10-byte deterministic keystream from the **8-byte envelope header |
| 35 | `rust/src/core/fs.rs:131-137` | C | P2-2, R3P2-2 | Render attacker-controlled text safe for a terminal. |
| 36 | `rust/src/core/i18n/mod.rs:187-194` | C | P2-7, R2P2-7 | Argument values are type-erased to `&dyn Display`, so |
| 37 | `rust/src/facade.rs:158-163` | A | P1-1, P1-12, R3P1-1 | Why the content domain produced no result, when it failed instead of |
| 38 | `rust/src/facade.rs:604-606` | A | P1-1, R3P1-1 | Keep the failure instead of swallowing it with `.ok()`: the |
| 39 | `rust/src/facade.rs:659-663` | C | P1-12, R3P1-12 | A failed content inspection is not the same answer as "there |
| 40 | `rust/src/facade.rs:1045-1048` | A | B-07 | `read -o <carrier>` would replace the only copy of the hidden data |
| 41 | `rust/src/formats/jpeg_segments.rs:40-45` | A | P2-23 | Skip `0xFF` fill bytes and return the marker code byte's index plus its |
| 42 | `rust/src/formats/jpeg_segments.rs:214-216` | B | P2-23 | JPEG allows extra 0xFF fill bytes before a marker code. The parser |
| 43 | `rust/src/stego/audio/core.rs:918-922` | C | A-03 | `slot_count()` is the pool actually materialised for this header. |
| 44 | `rust/src/stego/audio/core.rs:1094-1097` | A | B-04 | The body length includes the AEAD tag, the optional filename micro-header |
| 45 | `rust/src/stego/audio/flac/mod.rs:337-341` | A | F-07 | Absolute bit offset of the codeword's first bit. |
| 46 | `rust/src/stego/audio/flac/mod.rs:472-485` | A | P0-1 | Two disjoint pools, both derived from structural predicates plus the |
| 47 | `rust/src/stego/audio/mod.rs:317-320` | A | F-26 | Reuse `scratch`: the header view borrows it only until `read_base` |
| 48 | `rust/src/stego/audio/mod.rs:418-421` | A | C-07 | One scratch for both passes: `read_base` releases its borrow when it |
| 49 | `rust/src/stego/audio/mod.rs:544-545` | A | C-07 | One scratch for both passes (C-07); `read_base` does not keep a borrow. |
| 50 | `rust/src/stego/header.rs:473-479` | A | B-05 | Cross-check a header's `FLAG_EXT_CRITICAL` bit against its extension TLVs. |
| 51 | `rust/src/stego/heif/thumb_bridge.rs:30-33` | A | A-01 | TIFF type of tag 0x0202 (`3` = SHORT, `4` = LONG). The value must be |
| 52 | `rust/src/stego/heif/thumb_bridge.rs:416-419` | A | A-01 | IFD1 after the JPEG moves by `delta`, but IFD0's next-IFD pointer is |
| 53 | `rust/src/stego/heif/thumb_bridge.rs:566-569` | C | P1-10, R3P1-10 | `iloc` stores extent lengths in a field whose width comes from |
| 54 | `rust/src/stego/heif/thumb_bridge.rs:669-671` | A | B-03 | Only items stored as a single file extent can be rewritten by |
| 55 | `rust/src/stego/heif/thumb_bridge.rs:805-806` | A | A-01 | The TIFF entry declares its own width; reading all four value bytes |
| 56 | `rust/src/stego/heif/thumb_bridge.rs:1529-1532` | C | P1-10, R3P1-10 | `iloc` extent lengths are written back through a field whose width comes |
| 57 | `rust/src/stego/hevc/engine.rs:2157-2160` | B | B-05 | The flag and the TLVs must agree before any caller trusts the header: |
| 58 | `rust/src/stego/hevc/engine.rs:2205-2209` | A | M-14 | Body extraction over an already-read, policy-checked V4 header. |
| 59 | `rust/src/stego/hevc/engine.rs:2401-2404` | A | B-04 | The plaintext length lives inside the AEAD body: what remains after the |
| 60 | `rust/src/stego/hevc/engine.rs:2917-2918` | A | M-14 | One header read serves both level 2 and level 3: re-deriving it in the |
| 61 | `rust/src/stego/hevc/engine.rs:4879-4880` | A | F-01 | F-01 regression: the writer's decode window must never fall below the |
| 62 | `rust/src/stego/hevc/heif_boxes.rs:1007-1008` | A | A-04 | A-04: only the MP4 path filtered non-parameter-set arrays, so a prefix |
| 63 | `rust/src/stego/hevc/heif_boxes.rs:1031-1032` | B | A-04 | A-04: `length_size == 3` used to fall into the "unsupported" arm on the |
| 64 | `rust/src/stego/hevc/slot.rs:453-462` | C | P2-1, R2P2-1 | [`Self::with_slice_mode`] with capacity preallocated based on slice byte l |
| 65 | `rust/src/stego/io.rs:46-49` | A | B-07 | `-o <same path as the carrier>` is an in-place write, not an overwrite of |
| 66 | `rust/src/stego/jpeg/engine.rs:204-208` | A | P2-14 | No-op tracer hook. |
| 67 | `rust/src/stego/jpeg/engine.rs:1321-1323` | A | B-02 | Charge extraction the same backtracking bitmap the writer charged: a |
| 68 | `rust/src/stego/jpeg/engine.rs:1356-1359` | A | B-05 | The AEAD passed, so the carrier really is ours. Unknown critical |
| 69 | `rust/src/stego/jpeg/engine.rs:1603-1605` | A | B-05 | `inspect` must apply the same flag/TLV contract as extract, including the |
| 70 | `rust/src/stego/jpeg/engine.rs:2003-2005` | A | P2-14 | `trace` is a no-op outside tracing builds. Passing `format!` to it |
| 71 | `rust/src/stego/mod.rs:272-284` | B | B-03 | Shrink a capacity report by the longest possible file micro-header. |
| 72 | `rust/src/stego/params.rs:1075-1076` | B | B-06 | B-06: a custom WAV profile used to leak into FLAC, giving both carriers |
| 73 | `rust/src/stego/png/engine.rs:358-362` | C | P2-11, R3P2-11 | Re-encoding always writes a fresh IEND, so a carrier without one |
| 74 | `rust/src/stego/png/engine.rs:960-964` | A | P2-14 | No-op tracer hook, mirroring the JPEG engine's `[stego]` lines. |
| 75 | `rust/src/stego/png/engine.rs:2417-2418` | A | M-14 | Level 2 and 3 share one L1/L2 derivation: `verify` is one user request, |
| 76 | `rust/src/stego/png/engine.rs:2700-2702` | A | P2-14 | `trace` is a no-op outside tracing builds. Passing `format!` to it |
| 77 | `rust/src/stego/png/engine.rs:3747-3750` | A | P2-1 | Review G1 (P2-1): the probe's `max_raw_payload_bytes` must never exceed |
| 78 | `rust/src/stego/png/engine.rs:3805-3807` | A | P2-4 | Review G4 (P2-4): `png_pre_salt` binds the locator keys to the ancillary |
| 79 | `rust/src/stego/png/engine.rs:3853-3860` | A | P2-4 | Review G4 (P2-4) used to pin the opposite behaviour: any ancillary-chunk |
| 80 | `rust/src/stego/png/engine.rs:4455-4460` | A | LOGIC-07, P2-22 | Evidence for LOGIC-07 (P2-22): the candidate pool is keyed on the |
| 81 | `rust/src/structure/adapters/ebml.rs:12-24` | B | P3-15 | Encode an unsigned integer as an EBML VINT. |
| 82 | `rust/src/structure/adapters/ebml.rs:106-109` | B | P3-15 | Boundary values must avoid the all-ones "unknown size" payload of each |
| 83 | `rust/src/structure/adapters/heif.rs:58-62` | A | P2-4 | item_hidden registers the envelope through 32-bit iloc fields and a |
| 84 | `rust/src/structure/adapters/isobmff.rs:15-18` | A | P2-4 | Largest envelope the `item_hidden` strategy can carry: the second `mdat` |
| 85 | `rust/src/structure/adapters/isobmff.rs:137-144` | C | P2-17, P2-18, R3P2-17 | `ube_total_size` is attacker-controlled: the trailer is just 24 bytes at |
| 86 | `rust/src/structure/adapters/isobmff.rs:474-480` | A | P2-08 | Upper bound on the `meta` box body buffered by |
| 87 | `rust/src/structure/adapters/isobmff.rs:483-489` | A | P2-08 | Read the top-level `meta` box only, without buffering the file prefix. |
| 88 | `rust/src/structure/adapters/isobmff.rs:514-521` | A | A-10 | Admission check for the `item_hidden` rewrite. |
| 89 | `rust/src/structure/adapters/isobmff.rs:724-728` | C | P0-5, R2P0-5 | `largesize` is attacker-controlled: a value that does not fit in |
| 90 | `rust/src/structure/adapters/isobmff.rs:885-888` | A | P3-4 | A meta body may end in <8 bytes that cannot start a box header (zero |
| 91 | `rust/src/structure/adapters/isobmff.rs:925-931` | A | P3-5 | Entry header: size/type (8) + version (1); the item id sits at +12 |
| 92 | `rust/src/structure/adapters/isobmff.rs:1096-1102` | A | A-02 | The base offset is rewritten below only when it points |
| 93 | `rust/src/structure/adapters/isobmff.rs:1106-1112` | A | P3-3 | Only extents that physically live after the old meta |
| 94 | `rust/src/structure/adapters/isobmff.rs:1286-1287` | A | P3-4 | The <8-byte meta residue the inject side carried through verbatim |
| 95 | `rust/src/structure/adapters/isobmff.rs:1454-1456` | A | A-02 | Mirror the inject-side condition exactly: an extent is |
| 96 | `rust/src/structure/adapters/isobmff.rs:2041-2045` | A | A-02 | A legal but unusual encoding: `base_offset` lies *inside* `meta` |
| 97 | `rust/src/structure/adapters/isobmff.rs:2102-2104` | A | A-10 | `inspect`, `auto` and the writer must agree: a 64-bit `meta` header is |
| 98 | `rust/src/structure/adapters/isobmff.rs:2183-2185` | A | P1-1 | A crafted ultra-short `iloc` (the meta sub-box walk only guarantees |
| 99 | `rust/src/structure/adapters/isobmff.rs:2220-2222` | A | P2-1 | An iloc item count larger than the box contents must be rejected by |
| 100 | `rust/src/structure/adapters/isobmff.rs:2320-2322` | A | P2-2 | An infe entry declaring `item_id = u32::MAX` must refuse the carrier: |
| 101 | `rust/src/structure/adapters/isobmff.rs:2337-2338` | A | P2-3 | The non-AEAD header can be fully forged, so strip must cross-check the |
| 102 | `rust/src/structure/adapters/isobmff.rs:2416-2417` | A | P2-08 | A `meta` box behind an 8 MiB `mdat` must be reached by seeking over the |
| 103 | `rust/src/structure/adapters/jpeg.rs:256-259` | A | P3-19 | app_segment hides the chain before SOS. A header chain past |
| 104 | `rust/src/structure/adapters/mkv.rs:113-117` | A | P0-2 | `ebml_void` appends, so the envelope has to end exactly at the file |
| 105 | `rust/src/structure/adapters/pdf.rs:16-21` | A | P1-3 | Whether the newest cross-reference section is an XRef *stream* rather |
| 106 | `rust/src/structure/adapters/pdf.rs:39-43` | A | P1-3 | `/Encrypt` reference from the newest trailer (classic or XRef stream), |
| 107 | `rust/src/structure/adapters/pdf.rs:55-59` | A | P1-3 | An encrypted document cannot be extended incrementally: the new trailer |
| 108 | `rust/src/structure/adapters/pdf.rs:171-176` | A | P1-3 | End offset of the first balanced `<< ... >>` dictionary in `text`. |
| 109 | `rust/src/structure/adapters/pdf.rs:350-357` | A | A-06 | The dialect of the *newest* cross-reference section is decided by the |
| 110 | `rust/src/structure/adapters/pdf.rs:787-790` | A | P1-3 | 5. Write the incremental cross-reference section in the document's |
| 111 | `rust/src/structure/adapters/pdf.rs:833-838` | C | M-19 | A classic xref entry is exactly 20 bytes: a fixed 10-digit offset, |
| 112 | `rust/src/structure/adapters/pdf.rs:1364-1369` | A | A-06 | Revision 1 is a classic `xref`/`trailer` document, revision 2 replaces |
| 113 | `rust/src/structure/adapters/pe.rs:451-455` | A | P0-2 | `pe_overlay` always appends, so the envelope must end exactly at the |
| 114 | `rust/src/structure/adapters/pe.rs:685-698` | A | P1-1, P3-10 | Defensive check: carrier must not already contain a pe_codebits channel. |
| 115 | `rust/src/structure/adapters/pe.rs:723-724` | A | P3-7 | The channel header stores the slack offset as u32; a run beyond 4 GiB |
| 116 | `rust/src/structure/adapters/pe_codebits.rs:48-50` | A | P1-5 | Channel positions needed before the header can be unpacked: the 14 header |
| 117 | `rust/src/structure/adapters/pe_codebits.rs:605-607` | A | P1-5 | The mask key is the 8-byte envelope header magic at the very start of the |
| 118 | `rust/src/structure/adapters/pe_codebits.rs:899-905` | B | P1-5 | Review P1-5 regression: the pre-fix implementation derived the mask from |
| 119 | `rust/src/structure/adapters/pe_codebits.rs:921` | A | P1-5 | The old P1-5 derivation: HKDF over the 4 visible magic bytes. |
| 120 | `rust/src/structure/adapters/pe_codebits.rs:933-934` | A | P1-5 | Sanity check: under the old scheme the visible magic alone restored |
| 121 | `rust/src/structure/adapters/png.rs:231-234` | A | P0-2 | Stealth and custom-magic dialects use a password/seed-derived 8-byte |
| 122 | `rust/src/structure/adapters/png.rs:306-309` | A | B-01 | Concatenated PNG streams are legal input. The next stream's |
| 123 | `rust/src/structure/adapters/png.rs:410-412` | A | B-01 | Keep verifying a concatenated stream too: hiding before the |
| 124 | `rust/src/structure/adapters/png.rs:464` | A | B-01 | Continue through a concatenated PNG stream (review B-01). |
| 125 | `rust/src/structure/adapters/riff.rs:101-106` | A | P1-2 | The declared size can agree with the file length while the chunk table |
| 126 | `rust/src/structure/adapters/riff.rs:448-453` | A | P1-2, P3-17 | Whether `riff_chunk` can accept this carrier and envelope: the declared |
| 127 | `rust/src/structure/adapters/wav.rs:26-29` | A | P1-2, P3-17 | riff_chunk must stay symmetric: the declared boundary must be the |
| 128 | `rust/src/structure/adapters/zip.rs:77-86` | C | P0-3, R2P0-3 | Whether the bytes at `cd_offset` really start a central-directory record. |
| 129 | `rust/src/structure/adapters/zip.rs:95-104` | A | P2-7 | Whether a ZIP64 EOCD locator sits immediately before the EOCD record. |
| 130 | `rust/src/structure/engine.rs:124-126` | A | P1-7 | Trailer magic derived from the same PBKDF2 run. Level 1 and Level 2 |
| 131 | `rust/src/structure/engine.rs:175-190` | B | P0-2 | Reject a located envelope that cannot physically fit inside the carrier. |
| 132 | `rust/src/structure/engine.rs:234-236` | A | P2-6 | A 10-byte u64 varint may only use bit 0 of its last byte; the other |
| 133 | `rust/src/structure/engine.rs:389-398` | A | P2-09 | Materialize this source into `(bytes, stored filename, is_file)`. |
| 134 | `rust/src/structure/engine.rs:1259-1266` | A | P1-9, R2P1-9 | Where the envelope lands relative to the injection point. Strategies |
| 135 | `rust/src/structure/engine.rs:1784-1789` | A | P1-7 | [`open_and_authenticate_envelope`] for an envelope the caller already |
| 136 | `rust/src/structure/engine.rs:2073-2077` | C | P0-7, R2P0-7 | Write through a sibling temp file and rename, exactly like every carrier |
| 137 | `rust/src/structure/engine.rs:2625-2629` | A | B-06 | An envelope we can see but cannot open with this profile is a private |
| 138 | `rust/src/structure/engine.rs:2633-2635` | A | B-06 | Staying invisible to a reader that does not hold the dialect is |
| 139 | `rust/src/structure/engine.rs:2644-2648` | A | B-06 | A header that fails the level-2 shape check is not a readable envelope; |
| 140 | `rust/src/structure/engine.rs:2806-2827` | A | P1-9, R2P1-9 | Shared verify logic over any seekable reader (a `File` on the path path, a |
| 141 | `rust/src/structure/engine.rs:2835-2844` | A | C-01 | Scattered strategies (`pe_codebits`) record 0/0 by definition: the payload |
| 142 | `rust/src/structure/engine.rs:2966-2969` | A | P1-7 | A single locate scan feeds Level 1's stealth trailer magic, Level 2's |
| 143 | `rust/src/structure/engine.rs:3087-3101` | A | P1-9, R2P1-9 | `locate_envelope` derived these numbers from |
| 144 | `rust/src/structure/engine.rs:3243-3245` | B | P2-6 | 9 continuation bytes followed by 0x02: the old loop shifted the |
| 145 | `rust/src/structure/engine.rs:3424-3427` | B | P1-7 | Locating a stealth carrier derives the magics (one PBKDF2); Level 2 |
| 146 | `rust/src/structure/engine.rs:3437-3439` | A | P2-12 | P2-12: the content domain already treats `Some("")` as "no password"; |
| 147 | `rust/src/structure/engine.rs:3469-3472` | A | P2-2 | Review G2 (P2-2): advertised strategy capacities never exceed the |
| 148 | `rust/src/structure/envelope.rs:368-389` | A | P0-2 | Associated data bound into the metadata seal and every payload chunk. |
| 149 | `rust/src/structure/envelope.rs:637-641` | A | N-02 | The version is checked by the level-2 verifier, not here, so a |
| 150 | `rust/src/structure/envelope.rs:917-919` | A | P2-21 | P2-21: strategy IDs start at 1, but the default de-mask path used |
| 151 | `rust/src/structure/envelope.rs:938-941` | A | P2-21 | P2-21: the encrypted non-stealth header is stored unmasked, so its flag |
| 152 | `rust/src/structure/envelope.rs:956-961` | B | F-14, P2F-14 | P2 F-14: masked default headers used to pass the bare gate on |
| 153 | `rust/src/structure/envelope.rs:1005-1008` | B | P1-8 | P1-8: the old constants advertised 213 B as the smallest writable |
| 154 | `rust/src/structure/rejection.rs:305-310` | A | P3-22 | Find the EOCD. Garbage appended after a valid archive may itself contain |
| 155 | `rust/src/structure/rejection.rs:352-360` | C | P0-1, P0-4, R2P0-4, R3P0-1 | The buffer must *be* the central directory, not merely be readable. |
| 156 | `rust/tests/heavy/heavy_algorithm_matrix.rs:338-340` | A | P2-1 | Working-set budget / capacity refusal (review P2-1): a |
| 157 | `rust/tests/heavy/heavy_stego.rs:387-392` | A | P2-3, P2-5 | Which diagnostic depends on the carrier: a complete table |
| 158 | `rust/tests/heavy/heavy_stego.rs:447-456` | A | P2-3 | Documented limitation: a carrier whose luma AC table |
| 159 | `rust/tests/local/local_corpus.rs:1-36` | A | F-02 | Corpus-level batch runner — Rust counterpart of Python |
| 160 | `rust/tests/local/local_corpus.rs:318-319` | A | F-02 | The metadata seal is authenticated before stripping (F-02), so an |
| 161 | `rust/tests/local/local_media.rs:121-123` | A | F-02 | Strip / remove and check 100% bit-exact restoration. The |
| 162 | `rust/tests/local/local_media.rs:172-173` | A | F-02 | Encrypted envelope: the metadata seal is checked before |
| 163 | `rust/tests/test_cli/cli_unification.rs:981-985` | B | P2-13 | P2-13: in a multi-carrier `read --auto -o <DIR>`, every redirected content |
| 164 | `rust/tests/test_cli/cli_unification.rs:1075-1077` | B | F-03 | F-03: a carrier that already holds content payload must not be embedded a |
| 165 | `rust/tests/test_cli/cli_unification.rs:1144-1146` | A | F-03 | F-03: a structure envelope written on top of content payload produces a |
| 166 | `rust/tests/test_cli/cli_unification.rs:1178-1179` | A | F-03 | F-03: content payload embedded on top of a structure envelope also builds  |
| 167 | `rust/tests/test_cli/config.rs:70-71` | C | P1-8, R2P1-8 | `[stego]` has its own key set and was not checked at all, so a typo like |
| 168 | `rust/tests/test_cli/sources.rs:602-605` | A | P1-8 | Reading without any password source surfaces the hint. With `--stdout` |
| 169 | `rust/tests/test_lifecycle/facade.rs:236-238` | A | B-07 | `-o <carrier>` and "no `-o` at all" describe the same in-place write; the |
| 170 | `rust/tests/test_lifecycle/facade.rs:270-272` | A | B-07 | `read -o <carrier>` would replace the only copy of the hidden data with th |
| 171 | `rust/tests/test_lifecycle/facade.rs:851-853` | A | P1-5, R3P1-5 | Cancel before write. The marker must not be `Interrupted`: `write_all` |
| 172 | `rust/tests/test_lifecycle/profile.rs:126-129` | A | B-06 | Inspect must report "nothing here" for a dialect it cannot open, not an |
| 173 | `rust/tests/test_lifecycle/stego.rs:616-618` | A | B-03 | B-03 / T-09: the advertised maximum is a **file** maximum too. A 255-byte |
| 174 | `rust/tests/test_lifecycle/stego_credentials.rs:1-11` | A | M-14 | V4 credential, policy and error-semantics contract. |
| 175 | `rust/tests/test_lifecycle/stego_jpeg_v4.rs:151-154` | B | P1-1 | P1-1: inspect used to ignore `max_payload_bytes`/`allowed_suites` while |
| 176 | `rust/tests/test_media/heif_stego_bridge.rs:182-185` | A | A-01 | Review A-01: every legal Exif thumbnail encoding must survive an embed and |
| 177 | `rust/tests/test_media/hevc_stego.rs:505-512` | A | F-01 | Regression (F-01): the writer's decode window must never stop below the |
| 178 | `rust/tests/test_media/hevc_stego.rs:552-554` | A | N-01 | N-01: the file-level MP4/Annex-B patch branch must apply the same |
| 179 | `rust/tests/test_pe/codebits.rs:728-730` | A | P2-2 | The engine enforces `256 x host`, clamped to [64 MiB, 1 GiB]; the |
| 180 | `rust/tests/test_pe/codebits.rs:886-888` | A | P1-5 | Extract the first 176 bits: 14 bytes of ChannelHeader plus the first 8 |
| 181 | `rust/tests/test_pe/codebits.rs:938-939` | A | P1-5 | 5. The visible 4-byte magic cannot reproduce the mask: an IKM that only |
| 182 | `rust/tests/test_pe/codebits.rs:1056-1057` | A | P1-1 | 2. Second injection without knowledge of first password (explicit pe_codeb |
| 183 | `rust/tests/test_pe/codebits.rs:1297-1300` | A | P1-8 | P1-8: a 213-byte codebits channel must not be advertised as available. |
| 184 | `rust/tests/test_pe/slack.rs:599-602` | A | F-02 | Flip a byte in the payload ciphertext, past the header, hint and the |
| 185 | `rust/tests/test_regression/fixes.rs:59` | D | P0-3 | -------------------------------------------------------------------------- |
| 186 | `rust/tests/test_regression/fixes.rs:134` | D | P0-2 | -------------------------------------------------------------------------- |
| 187 | `rust/tests/test_regression/fixes.rs:258` | D | P0-4 | -------------------------------------------------------------------------- |
| 188 | `rust/tests/test_regression/fixes.rs:405` | D | P0-1 | -------------------------------------------------------------------------- |
| 189 | `rust/tests/test_regression/fixes.rs:443` | D | P1-5 | -------------------------------------------------------------------------- |
| 190 | `rust/tests/test_regression/fixes.rs:554` | D | P1-6 | -------------------------------------------------------------------------- |
| 191 | `rust/tests/test_regression/fixes.rs:793` | D | P0-1 | -------------------------------------------------------------------------- |
| 192 | `rust/tests/test_regression/fixes.rs:845-848` | A | P1-6 | P1-6: EOF-overlay carriers (RIFF/WAV, MKV, PDF) must pass L1 for stealth |
| 193 | `rust/tests/test_regression/fixes.rs:903-908` | A | P0-2 | P0-2: a PNG `chunk` envelope written first, then content-domain embedding, |
| 194 | `rust/tests/test_regression/fixes.rs:1073-1075` | A | F-02 | F-02: the restored output is committed only after the envelope metadata |
| 195 | `rust/tests/test_regression/fixes.rs:1124-1126` | A | F-02 | F-02: `patch_offset` and the injection geometry are outside the AAD, so |
| 196 | `rust/tests/test_regression/fixes.rs:1207` | D | F-05 | -------------------------------------------------------------------------- |
| 197 | `rust/tests/test_regression/p2_protocol.rs:43-47` | A | P1-3 | XRef-stream PDF whose dictionary nests `/DecodeParms << ... >>` *before* |
| 198 | `rust/tests/test_regression/p2_protocol.rs:193-194` | A | P1-3 | The update must repeat the document's dialect: an XRef stream object, |
| 199 | `rust/tests/test_regression/p2_protocol.rs:230-233` | A | A-06 | Revision 1 is a classic `xref`/`trailer` document, revision 2 replaces the |
| 200 | `rust/tests/test_regression/p2_protocol.rs:427-430` | A | P1-3 | The backward `%%EOF` scan is capped at 1 MiB from the effective PDF tail. |
| 201 | `rust/tests/test_regression/p2_protocol.rs:510-512` | A | B-06, N-02 | `verify` still reports the precise Level-2 diagnostic (test above), but |
| 202 | `rust/tests/test_regression/p2_protocol.rs:551-555` | A | P0-2 | A metadata block is at most a filename plus a fixed tail, so the reader |
| 203 | `rust/tests/test_regression/review_20261019.rs:45` | D | P1-1 | -------------------------------------------------------------------------- |
| 204 | `rust/tests/test_regression/review_20261019.rs:83` | D | A-7 | -------------------------------------------------------------------------- |
| 205 | `rust/tests/test_regression/review_20261019.rs:101` | D | A-11, P2-2 | -------------------------------------------------------------------------- |
| 206 | `rust/tests/test_regression/review_20261019.rs:151` | D | A-4 | -------------------------------------------------------------------------- |
| 207 | `rust/tests/test_regression/review_20261019.rs:196` | D | A-5 | -------------------------------------------------------------------------- |
| 208 | `rust/tests/test_regression/review_20261019.rs:240-241` | C | P1-8, R3P1-8 | `--stdout` reserves stdout for the payload, so the hint (apostrophe |
| 209 | `rust/tests/test_regression/review_20261019.rs:252` | D | A-3 | -------------------------------------------------------------------------- |
| 210 | `rust/tests/test_regression/review_20261019.rs:325` | D | A-6 | -------------------------------------------------------------------------- |
| 211 | `rust/tests/test_regression/review_20261019.rs:347` | D | A-12 | -------------------------------------------------------------------------- |
| 212 | `rust/tests/test_regression/review_20261019.rs:371` | D | P1-2 | -------------------------------------------------------------------------- |
| 213 | `rust/tests/test_regression/review_20261019.rs:450` | D | P2-3 | -------------------------------------------------------------------------- |
| 214 | `rust/tests/test_regression/review_20261019.rs:502` | D | A-9 | -------------------------------------------------------------------------- |
| 215 | `rust/tests/test_regression/review_20261019.rs:525` | D | A-8 | -------------------------------------------------------------------------- |
| 216 | `rust/tests/test_regression/review_20261019.rs:563` | D | P2-4 | -------------------------------------------------------------------------- |
| 217 | `rust/tests/test_regression/review_20261019.rs:601` | D | P2-1 | -------------------------------------------------------------------------- |
| 218 | `rust/tests/test_regression/review_20261019.rs:651` | D | A-13 | -------------------------------------------------------------------------- |
| 219 | `rust/tests/test_regression/review_20261019.rs:721` | D | A-15 | -------------------------------------------------------------------------- |
| 220 | `rust/tests/test_regression/review_20261025.rs:42-45` | A | P2-6 | A 22-byte ZIP consisting of nothing but an EOCD record with a zero Central |
| 221 | `rust/tests/test_regression/review_20261025.rs:118-121` | A | P1-2 | A WAV whose declared RIFF boundary is not the physical end of the file |
| 222 | `rust/tests/test_regression/review_20261025.rs:177-184` | A | P0-1, P1-2 | P1-2: a declared RIFF size can match the file length even when the final |
| 223 | `rust/tests/test_regression/review_20261025.rs:225-227` | A | P0-1 | L1 must call the table malformed, so the P0-1 pre-write gate refuses |
| 224 | `rust/tests/test_regression/review_20261025.rs:259-262` | A | P1-1, P2-1, P2-2, P2-3 | End-to-end roundtrip over the item_hidden iinf/iloc patch and restore core |
| 225 | `rust/tests/test_regression/review_20261025.rs:345-348` | B | P1-4 | A PDF whose dirty tail pushes the injected `%%EOF`/`endstream` pair beyond |
| 226 | `rust/tests/test_regression/review_20261025.rs:402-405` | A | P2-5 | The writer emits `UBE + "\nendstream"`, so the trailer always ends exactly |
| 227 | `rust/tests/test_regression/review_20261025.rs:430-433` | A | P1-3 | An encrypted document (`/Encrypt` in the newest trailer) must refuse the |
| 228 | `rust/tests/test_regression/review_20261025.rs:498-501` | A | P2-7 | A ZIP64 archive with an EOCD64 locator before the classic EOCD (classic |
| 229 | `rust/tests/test_regression/review_20261025.rs:574-577` | A | P2-4 | item_hidden tops out at a ~4 GiB envelope (32-bit mdat size + iloc |
| 230 | `rust/tests/test_regression/review_20261025.rs:597-599` | A | P1-2, P3-17 | WAV/WebP auto must keep riff_chunk only when write and read agree (clean |
| 231 | `rust/tests/test_regression/review_20261025.rs:665-668` | A | P1-1 | P1-1: the APP15 chain is inserted *before* SOS, so a large chain pushes SO |
| 232 | `rust/tests/test_regression/review_20261025.rs:752-755` | A | P3-19 | A JPEG whose header chain (EXIF/ICC/…) runs past the 16 MiB marker-scan |
| 233 | `rust/tests/test_regression/review_20261025.rs:794-796` | A | P3-4 | [`make_heif_with_meta`] with `pad` zero bytes appended inside the meta box |
| 234 | `rust/tests/test_regression/review_20261025.rs:813-815` | B | P3-4 | Dropping the meta residue used to shift every later offset: inject |
| 235 | `rust/tests/test_regression/review_20261025.rs:854-856` | A | P3-5 | An iinf declaring more entries than it carries used to end the max_id scan |
| 236 | `rust/tests/test_regression/review_20261025.rs:878-880` | A | P3-3 | A 64-bit iloc extent offset with no headroom for the meta growth used to |
| 237 | `rust/tests/test_regression/review_20261025.rs:902-905` | B | P3-18 | Two concatenated PNGs. The write side inserts before the LAST IEND while |
| 238 | `rust/tests/test_regression/review_20261030.rs:13-17` | C | P0-1, R2P0-1 | `ftyp` + one box whose 64-bit `largesize` is `u64::MAX`. |
| 239 | `rust/tests/test_regression/review_20261031.rs:14-20` | C | P0-1, R3P0-1 | `PK\x03\x04` + 60 filler bytes + an EOCD whose `cd_size` is smaller than t |
| 240 | `rust/tests/test_regression/review_20261031.rs:67-72` | A | P1-5, R3P1-5 | A cancelled `ProgressWriter` must fail fast. |
| 241 | `rust/tests/test_regression/review_20261031.rs:100-103` | C | P1-2, R3P1-2 | Deleting the last 12 bytes of a PNG and appending a payload used to produc |
| 242 | `rust/tests/test_regression/review_20261031.rs:135-137` | C | P2-11, R3P2-11 | A carrier without IEND cannot be re-encoded byte-for-byte, so the content |
| 243 | `rust/tests/test_regression/review_20261031.rs:159-165` | C | P2-17, P2-18, R3P2-17 | A 204-byte MP4 whose trailer claims a 1 TiB envelope and whose header clai |
| 244 | `rust/tests/test_regression/review_20261031.rs:230-234` | C | P1-7, R4P1-7 | Same blind spot as the PNG `IEND` case above, in the JPEG marker walk: a |
| 245 | `rust/tests/test_security/forge.rs:1-13` | A | P0-2 | P0-2: the envelope locator must not be usable as an allocation primitive. |
| 246 | `rust/tests/test_security/password_hint.rs:221-225` | A | P0-3 | P0-3: the hint is plaintext (it has to be readable without the password), |
| 247 | `rust/tests/test_security/rejection.rs:112-115` | B | P3-22 | Garbage trailing an archive may itself contain `PK\x05\x06`; taking the |

## 附录 B：50 个纯历史叙述块

无编号，但含「曾经 / 旧实现 / 修复前」的叙述。多数仍需保留约束，只改措辞。

| # | 位置 | 行数 | 首行摘要 |
|---:|---|---:|---|
| 1 | `rust/src/analysis.rs:929-936` | 8 | Structural checks for a JPEG, returning whether the marker stream reached |
| 2 | `rust/src/analysis.rs:1563-1568` | 6 | Contiguous row slabs covering the top, middle and bottom of the image. |
| 3 | `rust/src/analysis.rs:2178-2179` | 2 | Four coincidental magic bytes used to be enough for a `Likely` finding; |
| 4 | `rust/src/analysis.rs:2215-2218` | 4 | Three windows flip a zero centre to 1 (worse smoothness -> +1 each) |
| 5 | `rust/src/cli/cmd_diag.rs:55-61` | 7 | Diagnostic lines for a content half that produced no verdict. |
| 6 | `rust/src/cli/helpers.rs:837-840` | 4 | Four hex digits right after a high surrogate used to be read as a |
| 7 | `rust/src/core/commit.rs:832-835` | 4 | A read-only target used to fail inside `rename_with_retry`, which |
| 8 | `rust/src/core/config.rs:222-224` | 3 | Deserialise from the table that was already validated, instead of |
| 9 | `rust/src/core/crypto.rs:921-925` | 5 | Both of these are `pub fn`s reachable from an embedding host, and both |
| 10 | `rust/src/stego/coding/stc.rs:1132-1135` | 4 | 0xA5 puts a 1 in the first message bit. The oracle's warm-row |
| 11 | `rust/src/stego/engine.rs:426-435` | 10 | Whether a failed Scheme C attempt may be retried through the HEIF thumbnail |
| 12 | `rust/src/stego/envelope.rs:285-288` | 4 | One implementation for both domains: `Path::file_name` treats `\` as an |
| 13 | `rust/src/stego/format.rs:1-30` | 30 | Format identities for the content-domain steganography formats. |
| 14 | `rust/src/stego/heif/thumb_bridge.rs:449-454` | 6 | The extent that physically contains the replaced region: only its |
| 15 | `rust/src/stego/heif/thumb_bridge.rs:931-937` | 7 | v3: item_ID(32) at +12..16, protection(16) at +16..18, |
| 16 | `rust/src/stego/heif/thumb_bridge.rs:1186-1191` | 6 | The host-extent selection that drives the iloc length patch: the |
| 17 | `rust/src/stego/heif/thumb_bridge.rs:1477-1479` | 3 | A `meta` box using the 64-bit `largesize` form has a 16-byte header; the |
| 18 | `rust/src/stego/hevc/engine.rs:4191-4195` | 5 | Slice decoding was truncated mid-slice before every sign got its |
| 19 | `rust/src/stego/hevc/engine.rs:5119-5123` | 5 | Patch validation is the release-build guard for a mismatched internal |
| 20 | `rust/src/stego/hevc/heif_boxes.rs:839-842` | 4 | A malformed `infe` v3 entry whose declared size is long enough to pass |
| 21 | `rust/src/stego/hevc/heif_boxes.rs:849-852` | 4 | A single `infe` box whose *declared* size is 20 but whose payload |
| 22 | `rust/src/stego/hevc/heif_boxes.rs:859-861` | 3 | The declared size (20) is smaller than the bytes actually present |
| 23 | `rust/src/stego/hevc/heif_boxes.rs:898-901` | 4 | The zero-progress ISOBMFF DoS shape: all extent size fields zero paired |
| 24 | `rust/src/stego/hevc/mp4_boxes.rs:990-992` | 3 | A fixed-size `stsz` used to allocate `count` entries straight from the |
| 25 | `rust/src/stego/io.rs:626-628` | 3 | 80 carrier bytes per payload byte at the default tier (stc_u 2 x |
| 26 | `rust/src/stego/jpeg/engine.rs:1421-1425` | 5 | Inspect a JPEG for the V4 superblock and stego metadata without solving trelli |
| 27 | `rust/src/stego/jpeg/engine.rs:1459-1462` | 4 | Preflight just succeeded, so the coefficient reader failing here |
| 28 | `rust/src/stego/mod.rs:392-401` | 10 | What `recommended_max_bytes` would be at every tier, indexed by |
| 29 | `rust/src/stego/params.rs:359-361` | 3 | Out-of-range values used to be silently clamped while ranking and |
| 30 | `rust/src/stego/params.rs:373-378` | 6 | No `u <= h` rule here: `validate_stc_u` already caps `u` at 3 |
| 31 | `rust/src/stego/png/cost/suniward.rs:322-332` | 11 | The suitability pass must be the adjoint of the residual pass: the |
| 32 | `rust/src/stego/png/cost/suniward.rs:350-352` | 3 | Only the (l,h) band carries the asymmetry on a y-constant plane, so |
| 33 | `rust/src/stego/png/engine.rs:3072-3075` | 4 | `sigma` is stored in the feature word as an f32. NaN, infinities and |
| 34 | `rust/src/stego/png/engine.rs:3694-3697` | 4 | Colour types 0/2 use `tRNS` as a transparent colour key: every pixel |
| 35 | `rust/src/stego/png/engine.rs:3758-3759` | 2 | The exact size the pre-fix probe advertised: slots fit the pool, but |
| 36 | `rust/src/stego/png/engine.rs:3968-3972` | 5 | The tier table is what hosts read instead of re-deriving the budget, so |
| 37 | `rust/src/structure/adapters/isobmff.rs:1338-1341` | 4 | Walk the entries by their own size fields instead of guessing the |
| 38 | `rust/src/structure/engine.rs:1172-1174` | 3 | Payload key, metadata key and header mask are three HKDF expansions of |
| 39 | `rust/src/structure/engine.rs:1315-1318` | 4 | Assemble the UBE prefix first, then append the ciphertext directly into |
| 40 | `rust/src/structure/engine.rs:1894-1901` | 8 | Upper bound on the payload a carrier of `carrier_len` bytes may declare. |
| 41 | `rust/src/structure/engine.rs:2068-2070` | 3 | Never truncate an existing file by accident: extracting several |
| 42 | `rust/tests/local/local_media.rs:1582-1590` | 9 | Real Annex-B streams: sniff coverage and an end-to-end round-trip. |
| 43 | `rust/tests/test_cli/cli_unification.rs:608-612` | 5 | The stego credential flags were removed from the CLI surface: a private |
| 44 | `rust/tests/test_cli/cli_unification.rs:1229-1231` | 3 | `read -o carrier.png` used to truncate the carrier before the payload was |
| 45 | `rust/tests/test_media/hevc_stego.rs:189-194` | 6 | Deterministic regression for the Annex-B cover-digest window bug |
| 46 | `rust/tests/test_regression/fixes.rs:1212-1214` | 3 | Windows rejects a rename over a read-only file with ERROR_ACCESS_DENIED, |
| 47 | `rust/tests/test_regression/p2_fixes.rs:25-27` | 3 | A `Read + Seek` source that yields `fail_after` bytes and then fails with |
| 48 | `rust/tests/test_regression/p2_protocol.rs:368-371` | 4 | `verify` used to look for `%%EOF` only in the last 64 KiB, so an EOF-overlay |
| 49 | `rust/tests/test_regression/review_20261019.rs:417-418` | 2 | `auto` must pick the chunk strategy for a small payload even with a large |
| 50 | `rust/tests/test_security/forge.rs:111-112` | 2 | 4 GiB metadata on a ~1 KiB file: the pre-fix code allocated this before |
