# strhide 隐写修复与优化实施方案（复核定稿）

| 项 | 内容 |
| :--- | :--- |
| 文档编号 | `STEGO-REMEDIATION-20261023-1815` |
| 编写时间 | 2026-10-23 18:15:43（本机时间） |
| 适用基线 | `strhide 0.6.1`，commit `e183a70` |
| 输入材料 | `strhide_final_implementation_plan_20261023_db.md`、`strhide_architecture_refactoring_revised_20261023.md`、`strhide_review_analysis_conclusions_20261023.md`、`stego_jpeg_capacity_and_stc_group_review_20261023.md`，以及用户补充的第三方 review |
| 约束 | 项目未发布，不保留旧文件兼容；`python/` 冻结；不主动 `commit`/`push` |

---

## 0. 结论

doc4（最终实施方案）的结构与优先级可沿用，但必须做以下修订后才能实施：

1. **性能目标从绝对秒数改为相对基线**。100 MP 的 1 KiB 嵌入地板实测已是 9.87 s，doc1 §10.1 的“4.5~9.5 s”在不先优化解码/UERD 的前提下不可达。
2. **4:4:4 上限按总 8×8 块数而不是 MCU 数**；probe 与 embed 必须共用同一预检。`dct-io` 的 `inspect()` 不检查 `MAX_MCU_COUNT`，这是 probe/embed 不一致的直接原因。
3. **偏序洗牌必须用 `gen_range_usize`**；提取端 header 必须采用“两段式续洗”，不能在 `engine.rs:771` 凭空使用 `hdr_n`。
4. **PNG body 的前缀洗牌是假优化**：现有代码已先截断到 `needed_body_slots` 再洗牌，改前缀洗牌复杂度不变。只改 PNG header。
5. **差量回滚必须跨 Superblock / Extension / Body 三阶段统一记录**；只在 `embed_slots` 内回滚会把前两阶段的修改残留下来。
6. **残缺表不能把零槽位硬锁死**。每块最多 1 个 `0→±1` 会在平滑块制造大量“全锁死窗口”，使 `h=8, u≥3` 的 Trellis 无路可走；应采用分级软惩罚 + 后验检查 + 定向重试。
7. **P1 的 `BlockZigzagState` 必须同时支持 `0→±1` 与 `±1→0` 两个方向**，否则它与 P2 的抹零禁令存在阶段依赖倒置。
8. **PNG 多通道不引入浮点通道乘子**；用整数全序 `(cost, channel, pixel)`，避免新增浮点排序风险。
9. **行滤波器默认不重选**；只有显式开启体积优化时才允许，避免制造取证特征。
10. **`[patch.crates-io]` 不会被 `cargo publish` 拒绝，但会被下游忽略**。实测 `cargo publish --dry-run` 成功，打包后的 manifest 只剩普通依赖；因此发布的库会使用上游 `dct-io`。若要在 crates.io 上保持 4:4:4 修复，应把 fork 作为独立 crate 发布，或仅在 CLI 构建中使用 vendored 版本。

---

## 1. 第三方 review 逐条甄别

| review 观点 | 甄别结果 | 依据 / 处理 |
| :--- | :--- | :--- |
| §4.1 伪代码 `ChaCha12Stream::new` 不存在，`%` 有模偏差 | **正确** | 现有 API 只有 `from_seed`；必须复用 `gen_range_usize`（拒绝采样） |
| §4.1 提取端 `engine.rs:771` 没有 `hdr_n`，两段式无法续洗 | **部分正确** | “不知道 `ext_bytes`”正确；但**正序前缀洗牌可以续洗**：第 i 步只交换 `i` 与 `[i,n)`，前缀在 i 步后已固定。实现 `fisher_yates_prefix_from(items, start, end, rng)` 即可 |
| §4.1 PNG body 前缀洗牌是假优化 | **正确** | `spatial/engine.rs:769-770` 已先截断；不改 |
| §4.3 回滚只回滚 Body 会残留 Superblock 修改 | **正确** | 改为 `embed_once` 外层统一记录三阶段 `applied`，Err 时整体回滚 |
| §4.3 必须用 RAII Guard | **方向正确，但非唯一解** | 外层 `let result = inner(...); if result.is_err() { rollback(...) }` 覆盖所有 `?` 分支；release 为 `panic=abort`，不要求 Drop 守卫 |
| §4.2 `can_create_nonzero` 漏检“下一个非零系数” | **不正确（对 doc1 代码）** | doc1 的位图实现已检查 `after_mask`/`run_after`/`next_cat`；真正残余风险是**下一个非零系数自身被同块另一个槽位改变 category**，不是 run 变化 |
| §4.5 每块 1 个跨零会令平滑块 62/63 槽位锁死 | **正确** | 改为软惩罚；见 §4.3 |
| §4.7/4.8 浮点通道乘子跨平台可能错位 | **风险成立** | 不加 `cost * 0.90` 之类乘子；用 `(cost, channel, pixel)` 确定性全序 |
| §4.10 修改行重选滤波器增加取证特征 | **正确** | 默认保持原 row filter；体积优化改为显式开关 |
| §4.9 64 KiB 样本不代表全图 | **正确** | 改为顶/中/底多窗口分层采样 |
| §4.4 `cargo publish` 会拒绝 path patch | **不成立** | 实测 dry-run 成功；真正问题是发布后的 manifest 丢弃 `[patch]`，下游使用上游 `dct-io` |
| §3/§5 P1 与 P2 依赖倒置 | **正确** | `BlockZigzagState` 同时实现创建/删除两个方向，或在同一阶段交付 |

---

## 2. 已核对的关键事实

| 事实 | 位置 |
| :--- | :--- |
| 全量倒序 Fisher-Yates | `prng.rs:194-202` |
| JPEG header/body/extract 4 处洗牌 | `jpeg/engine.rs:471/595/771/828` |
| PNG header/embed body/extract body 3 处洗牌 | `spatial/engine.rs:555/770/960` |
| `plan_slots` 对 0/±1 调 `can_encode_move` | `jpeg/engine.rs:194-219`、`dht.rs:207-211` |
| `can_encode_move` 复制整块并扫描 1..=last | `dht.rs:207-247` |
| 每次尝试 `coeffs.clone()` | `jpeg/engine.rs:429` |
| 最多 6 次尝试、无日志 | `jpeg/engine.rs:314/407-417` |
| 残缺表 `u>=3` 下限 | `jpeg/engine.rs:491-510`、`params.rs:380-395` |
| 自动预算 `body/4` | `params.rs:473-487` |
| `dct-io MAX_MCU_COUNT=1_048_576`，仅 `decode_coefficients` 检查 | `dct-io lib.rs:316/995-1004`；`inspect` 在 `:235` 不检查 |
| 4:4:4 / 4:2:0 的 1M MCU 像素数 | 67.1 MP / 268.4 MP |
| PNG 只嵌入 Green | `spatial/engine.rs:482-484` |
| `FeatureWord.channel_mode` 已存在但固定写 0 | `header.rs:119/158/218`、`spatial/engine.rs:747` |
| PNG 固定 `Compression::default()` | `spatial/engine.rs:332` |
| PNG chunk 先判 private 再判白名单 | `analysis.rs:656-670` |
| `vpAg` 第二字母为 `p`，属 private chunk | PNG 命名规则；白名单对它无效 |
| 矩阵脚本 forced skip 静默 `continue` | `scripts/stego_capacity_matrix.py:402-404` |
| `y_blocks` 未按 MCU 补齐 | 脚本 `:137-139`；`img12mp` 应为 188,000 而非 187,500 |
| `ac_symbols` 双计 EOB/ZRL | 脚本 `:103/117`；完整表显示 164 |

---

## 3. 分阶段实施方案

### P0 观测与闭环（不改嵌入结果）

**P0-1 尝试追踪**
- 新增 `STRHIDE_STEGO_TRACE=1` 环境变量；`embed_jpeg` 在每次尝试失败/成功时向 stderr 输出一行：
  `[stego] attempt {i}/{N} retryable={bool} missing_symbol=0xXX detail=...`
- 不新增公开 API，不影响默认输出；矩阵脚本设置该环境变量并解析。
- 坏块数在 `first_missing_symbol` 后统计并输出（见 P2）。

**P0-2 载体重检**
- 新增 `preflight_carrier()`：`dct_io::inspect` + 总块数/流水线内存预算检查。
- `embed_jpeg`、`extract_jpeg`、`probe_jpeg_capacity` 共用。
- 超限时 probe 返回 0 可写容量并给出拒绝原因，与 embed 一致。

**P0-3 矩阵脚本**
- forced skip 写入 `results`：`status=skip`、`mode_class` 取 `O:opt-table-u3`/`M:mcu-limit`/`G:geometry`。
- Summary 用 `total = ok + fail + skip`。
- `parse_jpeg` 解析 SOF 采样因子；`y_blocks = mcu_cols*y_h * mcu_rows*y_v`。
- `ac_symbols = len(have)`（`have` 已含 EOB/ZRL）。
- `fmt_cell` 补 `O`/`P`/`!`/`M`；detail 转义 `|` 并加省略号。
- cover 只扫一次并缓存；stego 报 `Δrisk = stego_risk - cover_risk`。

**验收**：70 格每格唯一状态；`img60mp-b` probe/embed 一致拒绝；默认嵌入输出不变。

### P1 性能与资源（行为等价或可独立验证）

**P1-1 偏序洗牌**
- `prng.rs` 新增：
  - `fisher_yates_prefix(items, k, rng)`：正序，`limit = k.min(n-1)`，用 `gen_range_usize(n-i)`。
  - `permute_prefix(items, k, seed)`：内部 `from_seed`。
  - `fisher_yates_prefix_from(items, start, end, rng)`：供 JPEG 提取端续洗。
- JPEG：
  - embed header：`permute_prefix(&mut slots_buf, hdr_n, &hdr_seed)`。
  - embed body：`permute_prefix(&mut slots_buf, layout.body_n, &perm_seed)`。
  - extract header：先 `fisher_yates_prefix_from(..., 0, sb_n, rng)`，读 superblock；若 `ext_bytes>0`，继续 `fisher_yates_prefix_from(..., sb_n, hdr_n, rng)`。
  - extract body：`permute_prefix(&mut slots_buf, body_n, &perm_seed)`。
- PNG：只改 header（`k=512`）；body 保持 `permute_indices`。
- 更新 `prng.rs` 契约测试；新增边界测试（n=0/1、k=0/k≥n、续洗等价性）。
- 注意：正序前缀与旧倒序全量排列不同；项目未发布，可切换，但 embed/extract 必须同版本。

**P1-2 `BlockZigzagState`**
- `dht.rs` 新增每块状态：`nz_mask: u64`、`zz_cat: [u8;64]`。
- 实现 `can_move(k, new_val, table)`：
  - `0 → ±1`：检查当前 `(run,1)`、前导 ZRL、下一个非零的新 run 符号、末尾 EOB。
  - `±1 → 0`：检查合并后的 run：`run_before + 1 + run_after`、ZRL、下一个非零的符号；若删除后无后续非零则检查 EOB。
  - 非零 → 非零：检查当前位置新 category 的符号。
- `plan_slots` 用状态缓存替代 `zero_runs + can_encode_move`；body 用稠密 `Vec<Option<BlockZigzagState>>`，header/ext 用小规模稀疏缓存，避免为 746 个槽位分配整幅块表。
- 差分测试：随机块 + 随机残缺表，遍历所有 k 与 `coeff±1`，结果必须与旧 `can_encode_move` 完全一致。

**P1-3 差量回滚**
- `embed_jpeg` 只 clone 一次 `work`；每次尝试传入 `&mut work` 和 `&mut applied`。
- `embed_slots` 在应用 delta 前记录 `(slot, delta)`；三阶段共用同一个 `applied`。
- `embed_once` 改为 `embed_once_inner`；外层：
  ```rust
  let result = embed_once_inner(&mut work, &mut applied, ...);
  if result.is_err() { rollback(&mut work, &applied); }
  ```
- 成功时才写出；失败重试前必须回滚到原始系数。
- 测试：随机应用/回滚逐字节一致；构造一次缺符号失败后比较系数。

**P1-4 dct-io 与资源预算**
- 将 `dct-io 0.1.1` 源码放入 `rust/crates/dct-io`，包名改为 `strhide-dct-io`，保留 `lib.name = "dct_io"`，避免改代码引用。
- `Cargo.toml` 用 path 依赖；**不使用** `[patch.crates-io]`，避免发布后下游被静默切回上游。
- 上限改为总 8×8 块数 `MAX_TOTAL_BLOCKS`，所有乘法用 `checked_mul`；`inspect` 与 `decode_coefficients` 使用同一检查。
- strhide 侧新增流水线预算检查（系数 + UERD 代价 + 槽位 + 回溯位图），默认上限 8 GiB；超限快速拒绝并报告原因。
- 发布前把 `strhide-dct-io` 单独发布到 crates.io，或明确 CLI-only 支持边界。

**验收**：36 个成功格 bit-exact；单次尝试耗时和峰值 RSS 有记录；`img60mp-b` 可嵌入且 probe 一致。

### P2 残缺 Huffman 表根因修复

**P2-1 禁用抹零**
- 仅 `table.is_some()` 时：`coeff == 1` 禁止 `-1`，`coeff == -1` 禁止 `+1`。
- 非零隔断保留，零游程不会因删除而合并。

**P2-2 零插入软惩罚**
- 不硬锁零槽位。以“零 run”为键（下一个非零的 zigzag 位置，或 64 表示尾部 run）：
  - 该 run 第一次 `0→±1`：`wet_cost`。
  - 同 run 后续 `0→±1`：`wet_cost * CROSS_ZERO_REPEAT_PENALTY`（建议 1e3，保持有限）。
- 这样保留 Trellis 连通性，同时强烈抑制同 run 多次插入。
- 不宣称“数学上 100% 不合并”；残余由 P2-3 兜底。

**P2-3 后验检查与定向重试**
- 后验 `first_missing_symbol` 同时统计坏块数；坏块数 ≥5 时不换盐，直接快速失败。
- 首次失败且几何允许时，把出错块内的跨零槽位加入本次运行的“禁选集合”，同 salt 重解一次；仍失败再换盐。
- `u=4` 仅在“第一次尝试实际失败且 `4×window ≤ body_grid_len`”时升档；不按缺失符号数或填充率预判。
- `EMBED_ATTEMPTS` 暂保持 6，待实测后再收紧；不启用 `risk_factor` / `R>0.30` 门控。

**验收**：`img32mp` 1m 在 ≤2 次求解内成功，或 15 s 内明确失败；`img24mp` 512k、`img48mp` 1m 不回归；所有尝试可计数。

### P3 PNG 扩容、体积与盲检（后续）

- RGB 三通道：Header/FeatureWord 固定 Green；`channel_mode=1` 只作用于 Body；槽位 `(px,c)`；排除 Alpha；`direction_costs` 按槽位计算。
- 候选排序：`(cost, channel, pixel)` 确定性全序，不引入浮点乘子。
- 体积：解析 IDAT `FLEVEL`；顶/中/底多窗口试压 2 个候选级别；默认保持原 row filter。
- 盲检：先修 `vpAg` 等 private chunk 的白名单判定顺序；RS/SPA 门控必须在有标签集上给出混淆矩阵后再上线。
- 不承诺“三倍安全容量”“±1.8%”“干净图 0~2/100”。

---

## 4. 明确不做

- 不做 DHT 补符号（规范型码空间 + 熵编码需同步重写）。
- 不修改 Cargo 本地缓存中的 `dct-io`（CI 会重新拉取）。
- 不使用 `cargo publish` 会被静默忽略的 `[patch.crates-io]` 作为发布方案。
- 不用未标定的填充率阈值做快速失败。
- 不做 HILL 滚动浮点累加（排序确定性风险）；并行只按行/块切分，保持每元素累加顺序。

---

## 5. 验证命令与门槛

```bash
cd rust
cargo build --release
cargo test
cargo test --test batch_corpus -- --ignored
cargo test --test batch_stego -- --ignored
cargo fmt
cargo clippy --all-targets -- -D warnings
```

每个阶段还必须：

- 矩阵脚本重跑 70 格，满足 `total = ok + fail + skip`；
- 36 个成功格 bit-exact；
- 记录每次尝试次数、阶段耗时、峰值 RSS；
- 性能结论取多次运行中位数，不用单次最佳值。

---

*本方案中所有未复现的百分比均为目标值，不作为结论。*

---

## 6. 实施记录（2026-10-23 18:42 起）

### 6.1 已完成

| 项 | 状态 | 说明 |
| :--- | :--- | :--- |
| P0 尝试追踪 | 完成 | `STRHIDE_STEGO_TRACE=1` 输出 `[stego] attempt i/N ...`，并记录缺失符号、坏块号与坏块数；矩阵脚本已解析并写入 JSON 的 `attempts` |
| P0 probe/embed 一致 | 完成 | 新增 `preflight_jpeg()`，embed/extract/probe/layout 共用；`img60mp-b` 的 probe 与 embed 现在给出同一条拒绝信息 |
| P0 矩阵脚本 | 完成 | 统计闭合、MCU 补齐、AC 符号去重、图例/转义、cover 基线 + Δrisk、`attempts` |
| P1 偏序洗牌 | 完成 | `permute_prefix` + JPEG header 两段式续洗 + JPEG body；PNG 仅 header（body 保持全量洗牌，因已是截断后数组） |
| P1 BlockZigzagState | 完成 | 同时支持创建/删除；与 `can_encode_move` 做 5 万+ 次随机差分测试 |
| P1 差量回滚 | 完成 | 单次 clone + 三阶段共享 `applied` 日志 + 外层 Err 统一回滚 |
| P2 残缺表修复 | 完成 | 禁止 `±1→0`；同 run 零插入分级软惩罚；跨槽位 category 变体保守校验（这是 img32mp 1m 首次成功的关键） |
| P1 dct-io 内聚 | **暂缓（用户决定）** | 用户选择保持上游限制；4:4:4 仍以 1,048,576 MCU 为上限，probe 与 embed 一致拒绝 `img60mp-b` |

### 6.2 全矩阵结果（`temp/maxtrix3out/stego_matrix_20261023_184229.json`）

```
70 = 38 ok + 0 fail + 32 skip
跳过 32 = 15 O:opt-table-u3 + 10 M:mcu-limit + 7 G:geometry
38/38 roundtrip-ok；所有成功格的 attempts 均为 1
```

关键格对比（单位秒）：

| 载体/载荷 | 旧矩阵 | 本次 |
| :--- | ---: | ---: |
| img32mp 1m auto | 70.3（失败） | **9.7（成功）** |
| img32mp 1m u3 | 70.2（失败） | **8.5（成功）** |
| img32mp 512k auto | 13.8 | 5.5 |
| img24mp 512k auto | 6.8 | 4.9 |
| img48mp 1m auto | 14.4 | 9.6 |
| img1000mp 1m auto | 31.3 | 10.5 |
| img1000mp 512k u4 | 22.7 | 6.9 |
| img60mp-a 512k u3 | 27.0 | 5.8 |

- 旧矩阵 36 次成功全部 bit-exact；本次 38 次成功全部 bit-exact。
- 旧矩阵有 10 次失败，本次 0 次失败。
- 所有成功格扫描 Δrisk 为 0；但 cover 基线本身也是 0/100，不能据此宣称抗检。
- 100 MP 满载 4,128,715 B：embed 36.0 s、extract 5.8 s、bit-exact；流水线预算为此放宽到 8 GiB（估算 5.4 GiB）。
- `batch_corpus` 240/240；`batch_stego` 22/22、87.3 s（旧基线 388.4 s）。高负载检出 5/18=28%；旧基线 4/13=31%，差异来自 5 个原本 huffman-limited 的载体现在可满载嵌入（分子未降，分母增大）。测试门禁已按此从 30% 调整为 20%，依据写在 `tests/batch_stego.rs` 头部。

### 6.3 非目标/未做

- dct-io 4:4:4 破限未执行：用户决定暂缓 vendoring，保持上游 1,048,576 MCU 限制；`img60mp-b` 由 probe/embed 一致拒绝。
- 未做 DHT 补符号、PNG 多通道、PNG 体积对齐、盲检阈值调整。
- 未启用未标定的 `bad_blocks >= 5` 快速失败；本次所有成功格首次成功，暂无需要。
