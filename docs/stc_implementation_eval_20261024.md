# STC 内核实现评估报告（对照 Filler–Judas–Fridrich 2011）

- 评估对象：`rust/src/stego/coding/stc.rs`（1345 行）及其调用方 `coding.rs`、`jpeg/engine.rs`、`jpeg/v3_layout.rs`、`spatial/engine.rs`、`params.rs`
- 评估基准论文：T. Filler, J. Judas, J. Fridrich, *Minimizing Additive Distortion in Steganography Using Syndrome-Trellis Codes*, IEEE TIFS 2011（PDF: `dde.binghamton.edu/filler/pdf/Fill10tifs-stc.pdf`，本地转文本 17 页）
- 代码版本：2026-10-24 工作区（`git status` 中 `stc.rs` 无改动），文中行号均基于该版本
- 评估时间：2026-10-24 11:24
- 方法：源码精读 + 论文逐条对照 + 独立重建校验矩阵做 3^n 穷举 + 率失真（R-D）界实测 + 多 seed 复测 + AVX2 基准

---

## 1. 结论摘要

**算法正确性没有问题**：编码器与提取器自洽，在它自己的约束集上达到全局最优（穷举验证），随机消息全部 100% 还原，13 项单元测试全绿，`u=1` 的 `O(n)` 链式化简与完整 trellis 数学等价，AVX2 accumulate 内核的 permute/边界逻辑正确。

**问题集中在三处**：一个"最优性"测试的 oracle 多约束了一行（使该测试在 `bit0=1` 时失效）、JPEG 路径缺 `u ≤ 2^(h-2)` 约束（参数组合可把编码效率劣化到 +135%）、列向量未去重（违反论文设计规则 1，实测多花 8%~11% 修改量）。

### 1.1 问题分级

| 级别 | 问题 | 影响 |
|---|---|---|
| **P0** | 无 | 未发现破坏还原、数据丢失或安全漏洞的缺陷 |
| **P1-1** | 测试 oracle `row + 1 > h` 应为 `row + 1 >= h`（`stc.rs:926`） | 唯一的"最优性"测试在消息首位为 1 时变成"断言次优解"，当前仅因测试消息首字节 `0x5A`（`stc.rs:1076`）bit0=0 而未暴露 |
| **P1-2** | JPEG 路径无 `u ≤ 2^(h-2)` 约束（`v3_layout.rs`、`params.rs`） | 用户设 `stc_h=4` 时 `u` 仍可到 64 → 实测修改量比 R-D 界高 **135%**；`h=6,u=64` 高 **65.6%** |
| **P1-3** | 列向量未做去重（违反论文"Ĥ 不得有相同列"） | `h=8,u=64`（KERNEL_MAX_U 恰为列字母表大小）实测 **0.1256** flips/bit，去重后 **0.1154**（-8.1%）；`h=6,u=16` 0.1670→0.1500 |
| **P2-1** | `transfer_column::<true, false>` 分支不可达，`parity_bit` 仅为它存在（`stc.rs:302, 665`） | 死代码 + 参数噪音，不影响行为 |
| **P2-2** | JPEG body 用字符串匹配识别不可行错误（`jpeg/engine.rs:873`），superblock 用 `matches!(TrellisInfeasible)`（`:825`） | 两处判断口径不一致，错误文案一改就静默失效 |
| **P2-3** | 模块文档 4 处与论文/实现不符（`stc.rs:24,29-32,62-66`） | 误导后续优化方向（例如以为 `u>h` 是"超出论文的扩展"） |
| **P2-4** | 标量 accumulate 路径无测试入口 | AVX2 机器上永远走 SIMD，非 AVX2 主机无回归保障 |
| **P3** | 每次 `embed` 分配 `back`/`flip_kinds`；decide 列仍标量；`rho` 的 NaN 未校验；容量比论文少 `h-1` 行 | 性能/健壮性小项，无正确性影响 |

### 1.2 一句话判断

这是一个**正确、结构清晰、性能达标**的经典 STC 实现（u>1 的"分组扩展"在数学上仍是论文的 `w`，不是新编码），距离"论文级最优"的差距**几乎全部来自列向量设计与参数约束，而不是算法本身**。

---

## 2. 与论文的逐项对照

论文关键事实（`Fill10tifs-stc.pdf` §II-B、Fig.2/3、§V-D）：

- `H ∈ {0,1}^{m×n}`，由 `h×w` 子矩阵 `Ĥ` 沿主对角线逐行下移 1 行平铺；`α = m/n = 1/w`（非整除时用 `k` 与 `k+1` 混合宽度，末 `h-1` 个子矩阵裁切）。
- 前向：每块 `w` 列、`2^h` 状态；块末"剪枝" `wght[j] = wght[2j + message[indm]]`，状态降到 `2^{h-1}`。
- 回溯：`embedding_cost = wght[0]`，`state = 0` 起步，逐块 `state = 2*state + message[indm]` —— 即**终点强制零态**。
- 设计规则（§V-D，穷举搜索结果）：① `Ĥ` 不得有相同列；② 首行与末行全 1；③ 其余位随机。

| # | 项 | 论文 | 本项目 | 判定 |
|---|---|---|---|---|
| 1 | H 结构 | `Ĥ` 对角平铺、下移 1 行 | 同（`u` 即论文的 `w`，`cols[s]` 即 `Ĥ` 第 s 列） | ✅ 一致 |
| 2 | 相对载荷 | `α = m/n = 1/w` | `m = n/u − (h−1)`，多出 `h−1` 行 warm-up | ⚠️ 容量略低（见 §3.3），文档归属错误 |
| 3 | 块内状态数 | `2^h` | `u>1`：`2^(h-1+1) = 2^h` | ✅ 一致 |
| 4 | 剪枝 / 折叠 | `wght[j] = wght[2j+m]` | `base = ((i<<1)|want) & state_mask` | ✅ 等价（只是"目的态优先"的写法） |
| 5 | 终止 | 终点零态 | 自由尾态，取 `min` over 全部状态 | ✅ 本项目更优（约束集是论文的超集） |
| 6 | 子矩阵设计 | 无相同列 + 首末行全 1 | 首末位强制 1 ✅；列**未去重** ❌ | ⚠️ 违反规则 ① |
| 7 | `w`/`u` 上限 | 无（任意 `w`，可混合 `k/k+1`） | 内核 64；spatial 侧另加 `u ≤ h` | ⚠️ 限制本身合理，但文档给的"论文依据"不实 |
| 8 | 元素代价 | `ρ_i(y_i − x_i)`，可含 ∞（wet） | 同 + `ρ+/ρ−` 非对称、`±1` 两方向 | ✅ 一致（`±1` 对 parity 同效，取较小方向即最优） |
| 9 | 复杂度 | `O(n·2^h)` | 同；`u=1` 退化到 `O(n)` | ✅ 一致（`u=1` 是有效化简） |
| 10 | 实现 | C++/SSE，`float`/`uint8` 双精度档 | Rust/AVX2（accumulate 列） | ✅ 等效 |

---

## 3. 已确认正确的部分（含验证方式）

### 3.1 编码器在其约束集上全局最优

用独立重建的 `H`（splitmix64 + 强制首末位 + `reverse_low_bits`，与 `from_seed_grouped` 逐位一致）对 `n=12` 全枚举 `3^n` 个合法候选：

```
h=4 u=1 n=12 首字节 0x80（bit0=1）: 编码器 5.000 = 约束集最优 5.000，roundtrip true
h=4 u=2 n=12 首字节 0x80（bit0=1）: 编码器 4.000 = 约束集最优 4.000，roundtrip true
h=4 u=1 n=12 首字节 0x00（bit0=0）: 编码器 7.000 = 约束集最优 7.000
```

覆盖 `u=1`（链式路径）与 `u=2`（完整 trellis 路径），两种代价非对称（`ρ+=1+0.5i`，`ρ−=1+0.25i`），说明**方向选择与保持/翻转决策都是最优的**。

### 3.2 `u=1` 的 `O(n)` 链式化简正确

`u=1` 时 `Ĥ` 只有 1 列且最低位强制 1，`m_j = row_j` 方程组是**单位对角三角系统** → 解唯一，代价图只能决定 `±1` 方向。所以链式实现与论文 `w=1` 的完整 trellis 结果相同（论文自身在这种情形下也是 O(n·2^h) 空转，本项目是真正的化简）。上节的穷举已独立确认。

### 3.3 终点自由状态不引入缺陷

`extract` 只读 `row ∈ [h-1, n/u-1]`（`stc.rs` 的 `message_bits` 与 `extract` 一致），尾部 `h-1` 行的 syndrome 无人读取，因此编码器不约束它是正确的，比论文的"终点零态"约束更松、代价更低。

### 3.4 内核细节

- accumulate 列的 `base = i`（`i` 覆盖全 `2^h`）恰好实现了"decide 之后新行累加器从 0 开始"（上一列 decide 已把 `[2^{h-1}, 2^h)` 置 INF），逻辑正确。
- `cover_parity == 1 → (xor_keep, xor_flip) = (col, 0)` 的映射正确：保持落回 cover parity，翻转落在另一 parity。
- 回溯用 1 bit/状态 位图 + 元素级方向常量，不存 per-state 决策，内存 `n·states/8` 字节，与文档公式一致。
- 确定性强：`flip < keep` 严格小于（平局取 keep）、终点取最小索引，无 RNG。
- 湿元素：`ρ=∞` 被当作不可选，因每列最低位强制 1，**任何行都可被本组元素单独翻转**，所以不存在论文里的 wet-paper 秩问题 —— 这一点代码与文档都正确。

### 3.5 与引擎的耦合

- JPEG 侧把槽位值归一化成 `2 | parity`（`plan_slots`），避免 `u8` 回绕，`apply_deltas` 再落回真实值 —— 干净。
- spatial 侧通过 `Move` 把"越界/跨 8 值类"的方向屏蔽掉（`r=0/7` 槽位在 `for_each_body_slot` 已被过滤，`class_rule == 1` 时只保留 `val%8 ∈ [1,6]`），STC 只消费代价，不需要知道业务规则 —— 分层合理。

---

## 4. 实测编码效率（对照率失真下界）

### 4.1 下界公式

均匀随机 cover、常数剖面、`±1` 加性失真、无湿元素时，承载 `α` bit/元素所需的最小修改率 `p` 满足

```
α = h_b(p) = −p·log2 p − (1−p)·log2(1−p)     →     flips/bit = p / α
```

这就是论文 Fig.6/Fig.8 里 "constant profile bound" 曲线（`h → ∞` 的极限）。实测用 `StcTrellis::embed_with_deltas`，`Move::Both`，`ρ+=ρ−=1`，cover 为随机奇偶，`n = slots_for(bits)`。

### 4.2 单 seed 扫描（`bits=100k`，`u≥16` 时 `20k`；seed 0xA5A5_1234）

| h | u=1 | 2 | 3 | 4 | 6 | 8 | 16 | 32 | 64 |
|---|---|---|---|---|---|---|---|---|---|
| 4 | 0.4987 (+0.4%) | 0.2672 (+21%) | 0.2355 (+28%) | 0.2358 (+41%) | 0.2362 (+60%) | 0.2147 (+57%) | 0.2144 (+83%) | 0.2145 (+109%) | 0.2161 (+135%) |
| 6 | 0.4990 (+0.9%) | 0.2542 (+16%) | 0.2219 (+20%) | 0.2029 (+22%) | 0.1910 (+29%) | 0.1781 (+30%) | 0.1670 (+43%) | 0.1550 (+51%) | 0.1500 (+63%) |
| 8 | 0.4995 (+0.9%) | 0.2688 (+22%) | 0.2112 (+15%) | 0.1939 (+16%) | 0.1740 (+18%) | 0.1643 (+20%) | 0.1451 (+24%) | 0.1333 (+30%) | 0.1250 (+36%) |
| 10 | 0.5027 (+1.7%) | 0.2374 (+7.9%) | 0.2037 (+10%) | 0.1870 (+12%) | 0.1686 (+14%) | 0.1578 (+15%) | 0.1381 (+18%) | 0.1251 (+22%) | 0.1148 (+25%) |

括号 = 相对 R-D 界的超出比例。`u=1` 恒为 0.5 flips/bit（无编码增益），与论文 `α=1` 一致。

### 4.3 8 seed 复测（消除矩阵随机性）

| 配置 | 均值 | 范围 | 相对界 |
|---|---|---|---|
| h=6, u=2 | 0.2584 | 0.2534–0.2756 | +17.4% |
| h=8, u=2 | 0.2490 | 0.2439–0.2534 | +13.1% |
| h=8, u=3 | 0.2139 | 0.2101–0.2167 | +16.0% |
| h=10, u=3 | 0.2062 | 0.2033–0.2175 | +11.8% |
| h=8, u=64 | 0.1256 | 0.1250–0.1258 | +36.7% |
| h=10, u=64（单 seed） | 0.1148 | — | +25.0% |

单 seed 与 8 seed 差异 ≤ 6%（`h=8,u=2` 的 0.2688 是尾部样本），所以下文结论不依赖单次抽样。

### 4.4 关键读数

1. **`u` 增大不再降低修改率的地方，就是列字母表耗尽的地方。** 强制首末位后每列只有 `2^(h-2)` 种取值：`h=4→4`、`h=6→16`、`h=8→64`、`h=10→256`。`h=4` 从 `u=4` 起就饱和（0.2358→0.2161 几乎不动）；`h=8` 在 `u=64` 饱和。这时"多分组"只增加状态数，不再带来收益。
2. **`h=10` 比 `h=8` 在每个 `u` 上都好 3~12 个百分点**，代价是状态数 ×4、内存/时间 ×4。
3. **`u=2`（spatial 自动选择的档位）落在 +13% 附近**，`u=3` +16%。论文的 EE / 编码损失只在 Fig.8、Fig.9 中以曲线给出（无数字表），因此本报告一律以 R-D 界为绝对基准；论文 §V-F 的原话是"几乎每个满足设计规则的码都一样好"（"almost every code satisfying the design rules is equally good"），这支持了"差距来自设计规则而非随机抽样"的判断。
4. **论文给出的好码范围是 `h ∈ {6..12}`、`w ∈ {1..20}`**（§V-F，`[17, Table 1]`）。本项目 `u=64` 相当于 `w=64`，已远超论文校验过的区间；在 `h` 上限被内存卡在 10 的前提下，`u` 越大相对界损失越大是预期行为，不是实现错误。
4. **本项目 0.5/0.249/0.214 与文档 `expected_stc_change_rate` 的 0.5/0.265/0.230 方向一致**（文档值是真实图像 UERD 代价下的标定，偏保守，用于容量估算安全）。

### 4.5 去重实验（临时补丁，已还原）

把 `from_seed_grouped` 改成"`u ≤ 2^(h-2)` 时拒绝采样保证列互不相同"（即论文设计规则 ①），8 seed 均值：

| 配置 | 现状 | 去重后 | 变化 |
|---|---|---|---|
| h=8, u=64 | 0.1256 (+36.7%) | **0.1154 (+25.6%)** | −8.1% |
| h=6, u=16 | 0.1670 (+42.5%)* | **0.1500 (+28.0%)** | −10.2% |
| h=10, u=64 | 0.1148 (+25.0%) | **0.1126 (+22.6%)** | −1.9% |
| h=6, u=64（`u > 2^(h-2)`，无法去重） | 0.1522 (+65.6%) | 同 | — |
| h=8, u=2 / u=3 | 0.2490 / 0.2139 | 不变 | 0 |

\* 单 seed 值。结论：**去重在小 `u` 上零成本（碰撞概率低，行为不变），在 `u` 接近列字母表时直接省 8%~10% 修改量**——这是本次评估性价比最高的改动。`u > 2^(h-2)` 时去重不可能，只能靠提高 `h` 或拒绝该组合。

---

## 5. 问题详情

### P1-1 测试 oracle 的 warm-up 行数多了一行

`stc.rs:920-932`：

```rust
/// Every row of `H` must hold: the warm-up rows decode as zero (the
/// encoder constrains them too) and the rest carry the message.
fn matches(&self, cur: &[u8]) -> bool {
    let want = if row + 1 > h {                 // ← 应为 row + 1 >= h
        message_bit(self.message, row - (h - 1))
    } else {
        0
    };
```

编码器的实际约束：`want = 0` 仅当 `row = g - (h-1) < 0`，即 `row ≤ h-2`（共 `h-1` 行 warm-up）。oracle 用 `row + 1 > h` 把 `row = h-1` 也当成 warm-up（共 `h` 行），等同于把 `message bit 0` 强行约束成 0。

实证（`n=12, h=4, u=1, 首字节 0x80`）：

```
编码器实际代价 5.000（= 正确约束集最优）
oracle 约束集最优 7.000   ← oracle 找到的是另一个更贵的、bit0=0 的解
```

现有测试 `embed_matches_exhaustive_optimum_and_round_trips`（`stc.rs:1060`）的消息是 `0x5A * (i+1)`（`stc.rs:1076`），`0x5A` 的 MSB 为 0 → `bit0 = 0` → 两者恰好一致，缺陷被掩盖；`h=4,u=2` 与 `0x80` 首字节同样复现（4.0 vs 6.0）。`extreme_costs_never_need_a_retry` 用的是 `0xFF` 首字节但只做 roundtrip，不涉及 oracle。

最小修法：`row + 1 >= h`，并在参数表中加一例 `message[0] = 0x80`（或直接把消息首字节改成 `0xA5`）作为回归。

### P1-2 JPEG 路径缺 `u ≤ 2^(h-2)`

- `params.rs`：`JpegParams::stc_h` 用户可设，`validate_stc_h` 只查 4..=10；`stc_u` 未与 `h` 关联（spatial 侧的 `params.rs:267-274` 反而强制 `stc_u <= stc_h`）。
- `v3_layout::compute`：`u` 由容量/`slot_budget` 决定，上限 `KERNEL_MAX_U = 64`，与 `h` 无关。
- 结果：`--stc-h 4` + 大载荷 → `u=64`，列只有 4 种取值，实测 **+135%**；`h=6,u=64` **+65.6%**。

建议：`compute` 里加 `u = u.min(1 << (h - 2))`（h=4→4，h=6→16，h=8→64，h=10→256），或在 `JpegParams::validate` 直接拒绝。这条约束同时把"列字母表不足"的组合挡在参数层，语义清晰、改动极小。

### P1-3 列未去重

`from_seed_grouped`（`stc.rs:339`）对 `s` 直接 `splitmix64(seed + s)` 取列，没有排除重复。论文 §V-D 明确：相同列会让 trellis 出现等价路径，整体性能下降。`h=8,u=64` 时列空间恰好 64 个值，随机抽 64 次期望只有约 40 个互异列 —— 这就是 `u=64` 那 36% 差距的主要来源（4.5 实测证实去重可回收 8%）。

建议：`u ≤ 2^(h-2)` 时拒绝采样（循环 `s += 1` 直到互异，`u ≤ 64` 时最坏几百次，一次性开销可忽略）；`u > 2^(h-2)` 时保持现状（并由 P1-2 从参数层禁止）。

⚠️ 注意：改列会改变**同 seed 下的嵌入结果**，需要同步确认 `extract` 用的是同一份 `cols`（本来就是），不需要版本兼容（项目未发布）。

### P2-1 死代码

`store_extra = u > 1`（`stc.rs:586`），而 `u == 1` 在 `stc.rs:535` 已提前 `return`，所以 `stc.rs:665` 的 `transfer_column::<true, false>` 永远不可达；`parity_bit` 只在该分支（`stc.rs:302`）被使用。删掉后 `transfer_column` 的 `TWO_WAY` 常量参数与 `parity_bit` 一起消失，两个调用点（`:652`、`:679`）也会更短。

（注意：`stc.rs:199-208` 的注释仍在描述这个不可达分支，一并删。）

### P2-2 错误识别口径不一致

```rust
// jpeg/engine.rs:825（superblock）
if ctx.table.is_some() && matches!(e, StrHideError::TrellisInfeasible(_)) { ... }

// jpeg/engine.rs:873（body）
if ctx.table.is_some() && e.to_string().contains("no legal element") { ... }
```

而 `stc.rs:562` 与 `stc.rs:713` 的文案分别是 `"no legal element direction exists for element {j}..."` 和 `"a group has no legal element (both directions illegal...)"`。body 侧目前靠字符串前缀"碰巧"匹配，且 `stc.rs:562` 的注释还专门写了"JPEG 引擎依赖这句文案"——耦合方向反了。建议 body 也改成 `matches!`，删掉 `stc.rs:562` 的注释。

### P2-3 文档与事实不符

| 位置 | 现说法 | 事实 |
|---|---|---|
| `stc.rs:24` | `u = 1` 是 "classic one-row-per-element code (`m = n-h+1`)" | 论文 `w=1` 时 `m = n`（末 `h-1` 个子矩阵裁切），`n-h+1` 是本项目自己的 warm-up 约定 |
| `stc.rs:29-32` | "highest bit 是元素对本组即将 finalise 的行的影响（否则部分 parity 不可达）" | 反了：本组 finalise 的行对应**最低位**（`base = (i<<1)|want` 把 `want` 放在 bit0）；最高位对应 `h-1` 组之后才 finalise 的行 |
| `stc.rs:32` | "组内 `u` 个列向量线性无关" | 不保证，也未检查；且论文不要求这一点（只要求列互异 + 首末行全 1） |
| `stc.rs:62-66` | "原构造把 `u` 限制在 `h` 并要求列线性无关；两者都不必要，去掉才让 JPEG 能铺到 64" | 论文对 `w` 无上限，也未要求线性无关。`u=64` 不是"超出论文的扩展"，而是论文的 `w=64`；真正的收益来源是 `α = 1/w` 变小 |
| `stc.rs:21` | `s[g] = XOR over d in 0..h of (cols[s][d] & x[g*u + s])` | 公式漏了行映射，正确写法是 `s[row] = XOR_{g=row-h+1..row} XOR_{s} cols[s][row-g] & x[g*u+s]` |

修正这些不是学术洁癖：P1-2/P1-3 的判断依据正是"列互异 + 首末行全 1 是论文的设计规则"，文档把它写成"我们的自由发挥"，导致后续没有人去补这条约束。

### P2-4 标量路径无测试入口

`transfer_column` 的 SIMD 分支与标量分支由运行时 `is_avx2()` 选择。本机有 AVX2，测试永远走 SIMD；非 AVX2 主机（CI 的 ubuntu-latest 默认有 AVX2，但 ARM/老机器没有）没有等价性回归。建议加一个 `pub(crate) fn force_scalar(bool)` 测试钩子（`cfg(test)` 或环境变量），在小规模上用同一 workload 比较两条路径的 `deltas` 与代价。

### P3 其他

- `back`/`flip_kinds` 每次 `embed` 新分配；JPEG 一次嵌入要调 3 次 `embed_slots`（superblock、extension、body），可复用 `Vec`（收益小，非必要）。
- decide 列（占 `1/u` 的列）仍是标量循环，每列工作量约为 accumulate 的 2 倍；`u=2` 时 decide 占一半列，SIMD 化 decide 预计能再快 15%~25%（`u=64` 时意义不大）。
- `cost_fn` 返回的 `rho` 若为 `NaN`，`flip < keep` 恒 false → 静默按"保持"处理并给出一个合法但次优的结果。建议在 `debug_assert!` 或入口处过滤（`INF` 已被正确处理）。
- 容量比论文少 `h-1` bit/次（因为 `message bit b ↔ row b+h-1`）。`u=1` 时相当于 2000 元素载体少 7 bit，可忽略；若想回收，把映射改成 `bit b ↔ row b` 并把前 `h-1` 次 decide 的 `want` 改成"松弛剪枝"（`next[i] = min(cost[2i], cost[2i+1])`）即可 —— **不建议现在做**，收益远小于改动风险。

---

## 6. 性能现状（本机复测）

`cargo test --release --test stc_kernel_bench bench_stc_kernel`，`h=8`，1.6M payload bits，3 次取值：

| u | 槽位 | 状态 | 时间 | 吞吐 | 质量 |
|---|---|---|---|---|---|
| 1 | 1.6M | 128 | 11–12 ms | 138.6 Mslot/s，0.028 ns/transition | 0.5001 flips/bit |
| 2 | 3.2M | 256 | 419–441 ms | 7.43 Mslot/s，0.263 ns/transition | 0.4105 flips/bit（非对称代价） |
| 3 | 4.8M | 256 | 598–622 ms | 7.84 Mslot/s，0.249 ns/transition | 0.3735 flips/bit（非对称代价） |

- `u=1` 路径比 `u=3` 快 55 倍（`O(n)` vs `O(n·2^h)`），符合设计。
- 内存：`n × states/8` 字节。`h=8, u>1` → 32 B/槽；默认 `slot_budget=1.2M` → ≈38 MB；自动上限 `MAX_AUTO_BACKTRACK_BYTES = 4 GiB` → 约 134M 槽（仅超大载体触发）。

---

## 7. 是否有更优实现？

### 7.1 编码选型：STC 仍是正确选择

对加性失真、无湿纸秩问题的场景，STC 是 2011 年以来的事实标准，配套 HUGO/HILL/UERD/J-UNIWARD/S-UNIWARD 全部以它作为最后一层。理论上更优的方向有：

- **极性码 / LDPC 类**（Polar codes for steganography, 2015+）：在有限 `n` 下接近率失真界，但解码复杂度和实现成本高一个量级，且需要长码块，实时嵌入不现实。
- **迭代/双重编码**（如 "STC + syndrome-coset 迭代"）：能再压 1~3%，代价是 2~5 倍时间，与当前 `u=1` 已经 12 ms 的现实不匹配。
- **模拟嵌入 / 失真补偿**（QIM 类）：主要针对量化域鲁棒水印，不适用于"最小化修改"的场景。

结论：**不换算法**，把 P1-2/P1-3 补上即可拿到论文同级效率；若还要再压，唯一高性价比方向是"`h` 随 `u` 自适应"（见 7.2）。

### 7.2 可落地改进（按 ROI 排序）

| 优先级 | 改动 | 预期收益 | 成本 |
|---|---|---|---|
| 1 | `from_seed_grouped` 列去重（`u ≤ 2^(h-2)` 时） | `u=64,h=8` −8% 修改量；小 `u` 无变化、无回归风险 | ~15 行 |
| 2 | `v3_layout::compute` 加 `u ≤ 2^(h-2)` | 消除 `h=4/6 + 大载荷` 的 +65%~135% 效率断崖 | 1 行 + 1 个测试 |
| 3 | 修 oracle `row + 1 >= h` + 加 `bit0=1` 回归 | 恢复"最优性"测试的有效性 | 2 行 |
| 4 | JPEG body 默认 `h` 由 8 提到 10（或按 `u` 自适应：`u ≥ 32 → h=10`） | 大 `u` 时 −9%（0.1256→0.1148），但时间/内存 ×4 | 改默认值；需实测端到端耗时 |
| 5 | `matches!(TrellisInfeasible)` 统一 + 删死代码 | 可维护性 | ~20 行删除 |
| 6 | 文档修正（§P2-3 表） | 防止后续误判 | 文档 |
| 7 | decide 列 SIMD | `u∈{2,3}` 再快 15%~25% | 中等 |

不建议做的：`h > 10`（内存 `n·2^{h-1}/8`，`h=12` 时 256 B/槽，8M 槽就 2 GB）；回收 `h-1` 位容量（收益 0.02%）。

---

## 8. 建议补充的测试

1. **oracle 修复回归**：`message[0] = 0x80`，`(h,u) ∈ {(4,1),(4,2),(5,1)}`，断言 encoder 代价 == 穷举最优。
2. **`u = 2^(h-2)` 边界**：`(h,u) = (4,4),(6,16),(8,64)`，断言 `cols` 互异（去重落地后），并断言 `u = 2^(h-2)+1` 被参数层拒绝。
3. **`h`/`u` 组合矩阵**：`h ∈ {4,6,8,10} × u ∈ {1,2,3,64}`，断言 `flips/bit ≤ 阈值`（例如 `u=2,h=8` 上限 0.30，`u=64,h=8` 上限 0.13）——防止未来改列生成时静默劣化。
4. **标量/SIMD 等价**：小 `n`（如 4096）下两条路径 `deltas` 逐元素相等。
5. **非 u 倍数槽位**：`embed` 报错、`extract` 忽略尾部（已实现，补测试固化）。

---

## 9. 附录：复现方法

- 论文文本：`C:\Users\mcxiaoke\AppData\Local\Temp\filler_tifs_stc.txt`（PyMuPDF 转出，17 页）；关键段落 §II-B（H 构造、Fig.2 图注"末 h-1 个子矩阵裁切"）、Fig.3 伪代码、§V-D（三条设计规则）。
- 效率实测：临时集成测试 `rust/tests/temp_stc_eval.rs`（已删除，未入库）。做法：`StcTrellis::from_seed_grouped(seed,h,u)` → `n = slots_for(bits)` → 随机奇偶 cover + `Move::Both` + `ρ±=1` → `embed_with_deltas` → `flips/bits`，再与 `α = h_b(p)`、`p/α` 对比；每个配置 8 个 seed。
- 最优性验证：独立重建 `H`（`splitmix64` + 强制首末位 + `reverse_low_bits`，与内核逐位一致），对 `n=12` 全枚举 `3^n` 合法候选，分别按"文档约束集"和"oracle 约束集"求最小代价。
- 去重实验：临时修改 `from_seed_grouped`（拒绝采样），实测后 `git checkout --` 还原（备份见 `temp/backups/stc.rs.bak-20261024-111856`）。
- 性能：`STRHIDE_BENCH_BITS=1600000 STRHIDE_BENCH_U=1,2,3 STRHIDE_BENCH_RUNS=3 cargo test --release --test stc_kernel_bench bench_stc_kernel -- --ignored --nocapture`。
- 回归基线：`cargo test --release --lib stc` → 13 项全绿。

## 10. 参考

1. T. Filler, J. Judas, J. Fridrich. *Minimizing Additive Distortion in Steganography Using Syndrome-Trellis Codes*. IEEE TIFS, 6(3):920–935, 2011.
2. `docs/stc_coding_design_20261021.md`、`docs/stc_kernel_optimization_and_simd_eval_20261022.md`、`docs/stc_capacity_eval_report_20261021.md`（本报告修正其中"原构造限制 `u ≤ h`"、"`m = n-h+1` 为论文约束"等表述）。
