# FLAC 残差隐写引擎审查报告

- 日期：2026-11-02 00:05 (+0800)
- 审查对象：`rust/src/stego/audio/**`（WAV PCM 引擎 + FLAC 残差引擎，提交 `05510be`、`0aeae40`、`4bec3e4`）
- 审查方式：源码逐行审查 + 在 16 个真实 FLAC 载体 / 7 个真实 WAV 载体上跑 `examples/audio_stress` 压测 + 定向插桩测量
- 本次审查**未修改任何代码**（审查过程中插入的临时探针已全部回滚，`git status` 干净）

---

## 0. 结论摘要

WAV 引擎**健康**（7/7 载体 × 2 档填充 × 3 轮全部通过，无失败）。

FLAC 引擎存在 **1 个根因明确的间歇性失败（P0）**、**1 个安全缺陷（P1）**、以及若干健壮性 / 诚实性 / 性能问题。按严重度排列：

| # | 级别 | 问题 | 性质 |
|:--|:--|:--|:--|
| F1 | **P0** | 槽位选取按"全部合格残差"抽样，容量定价却按"可动残差"计算，导致 9%~38% 的入选槽位是 `Move::None`（冻结槽）；STC 遇到连续冻结组时状态集塌缩 → `TrellisInfeasible` → **间歇性嵌入失败** | 算法/设计缺陷 |
| F2 | **P0** | 4 次重试只重掷 trellis 种子，不改变冻结槽图样，**对 F1 几乎无效**（实测 4/4 全部失败） | 无效缓解 |
| F3 | P1 | 稀释相位 `header_phase` / `body_phase` 是硬编码常量 → 载荷落点与口令无关，同一载体不同口令落在**同一批物理残差**上 | 安全缺陷 |
| F4 | P1 | 每次数据槽移动会连带改写 5~8 倍的补偿残差（实测最多改写全文件 62% 的残差），但 `EmbedStats.modified_slots` 只统计数据槽，改动率被系统性低报 | 统计失真 |
| F5 | P2 | 单次嵌入要做 5~13 遍全文件解码（失败时 ×4），性能被放大 | 性能 |
| F6 | P2 | 失败时对外报 `UnsupportedFormat: predictor reacts too strongly`，把"载荷尺寸与槽位分布不相容"说成"载体不合格"，误导用户 | 可用性 |
| F7 | P2 | 单元测试用的合成载体（FIXED order-2 + 固定 Rice k=8，冻结率 ~0.9%）处在实测分布的最优端，**结构上不可能复现 F1**；语料 harness 只验解码不验嵌入 | 测试盲区 |
| F8 | P3 | 16 个 FLAC 载体中 6 个（37.5%）被 `MAX_STUCK_RATE=0.40` 直接拒用；该阈值与 `capacity_slots()` 里的 1.5 倍折扣系数都是凭单个文件拟合的魔数 | 可用性 |
| F9 | P3 | `DRIFT_BUDGET=8` 作为"补偿正确性闸门"过松（补偿正确时真实漂移为 1~2），检测不到它本来要防的"拖尾"故障 | 闸门失效 |
| F10 | P3 | 尾部池只有 785~3687 个，512 槽的头部要占 14%~25%；短载体（约 <25 秒）直接被拒 | 可扩展性 |

**好消息**：审查中逐一验证过、结论为**正确**的部分：
- 补偿链的数学（逐 tap 抵消、链长 = 阶数、跨槽影响域两两不相交、与移动顺序无关）→ **推导正确，实测漂移 1~2，与"精确补偿"一致**。
- 零膨胀契约（帧长、字节长、帧 CRC-16、STREAMINFO MD5 全部重写，长度不变）→ 压测 100% 通过。
- 槽位不相交性（数据槽 / 补偿目标 / 子帧尾部三者两两互斥）→ 代码可证，是后续修复能成立的前提。
- 读者可由隐写文件独立复现槽位图（结构量 `k`、`rice`、bucket、`has_legal_move` 均在移动下不变）→ **成立**，并已实测确认嵌入前后 `usable` 计数完全一致。
- MD5 / CRC-16 / CRC-8 / Feistel 置换 / Rice 折叠 → 逐一对照参考向量，正确。
- WAV 引擎（sample / cost / perm / wav / core 驱动）→ 未见正确性缺陷，压测全绿。

---

## 1. F1：间歇性失败的根因（重点）

### 1.1 一句话表述

`embed_flac` 用 `analysis.usable`（可动残差数）给容量定价，`FlacCarrier::new` 却用 `analysis.slots`（**全部**合格残差数）作为稀释抽样的分母，于是被选中的槽里有 9%~38% 是 `Move::None`。STC 在 `u=3` 分组下，连续若干组 3 个槽全冻结时可达状态集逐组减半并塌缩为空，`TrellisInfeasible` 就抛出来了。

对应代码（`rust/src/stego/audio/mod.rs:92-102` 与 `flac/mod.rs:409`）：

```rust
let available = analysis.usable.min(analysis.slots).saturating_sub(V2_TOTAL_HEADER_SLOTS);
//                       ^^^^^^^ 定价用"可动"
...
if thin_pick(index, total, body_slots, body_phase)   // total = analysis.slots
//                         ^^^^^ 抽样用"全部"
```

### 1.2 复现（确定性，非概率）

```bash
cd rust
cargo build --release --all-features --example audio_stress

# 同载体、同填充、仅轮次不同：round 0/1/3 成功，round 2 失败
STRHIDE_FLAC_ERR=1 ./target/release/examples/audio_stress \
    ../temp/flacstress/15_Celestial_Crystals.flac 4 0.4 1

# 全语料 50 个作业：2 个失败，且失败时 4 次重试全部失败
STRHIDE_FLAC_ERR=1 ./target/release/examples/audio_stress \
    ../temp/flacstress 4 0.2,0.4,0.6,0.8,1.0 4
```

实测输出（节选）：

```
flac-err: attempt 0 failed: Embedding infeasible: a group has no legal element (...)
flac-err: attempt 1 failed: Embedding infeasible: a group has no legal element (...)
flac-err: attempt 2 failed: Embedding infeasible: a group has no legal element (...)
flac-err: attempt 3 failed: Embedding infeasible: a group has no legal element (...)
  FAIL 15_Celestial_Crystals.flac @ 40% round 2: embed failed: Unsupported format: ...
```

注意这三点，它们直接指向根因：

1. **同一载体 20%/60%/80%/100% 全过，只有 40% 挂** → 不是"载体不合格"，是载荷尺寸与槽位分布的特定组合。
2. **只有特定 round 挂** → 每轮置换不同，冻结组在 plan 序下的排布不同。
3. **4 次重试全挂** → 重试没能改变任何结构性东西。

### 1.3 量化：为什么是"偶发"

在 plan 序下插桩统计（临时探针，已回滚）：

| 载体 | 填充 | 入选槽数 | 冻结率 | 全冻结组数 | 最长连续冻结组 | 结果 |
|:--|:--|--:|--:|--:|--:|:--|
| 15_Celestial_Crystals | 100% | 287,469 | **38.4%** | 5,407 | 3 | ok |
| 15_Celestial_Crystals | 100% | 287,469 | **38.4%** | 5,526 | 4 | ok |
| 15_Celestial_Crystals | 100% | 287,469 | **38.4%** | 5,421 | **4** | **FAIL** |

通过/失败的**唯一**差异就是最长连续全冻结组从 3 变成 4。这解释了"偶发"的全部体感：一个随机量在小样本上围绕阈值抖动。

机理解释（与代码一致）：`u=3` 时每组 3 个槽，**组内只要有 1 个可动槽，该组必可达**（因为每个列向量的第 0 位被强制为 1，任一可动槽翻转即可拨动该组行）。组内 3 个全冻结时，该组对状态集只剩"保持"一种转移，可达集被切一半（仿射子空间每次少 1 维）。连续 K 个全冻结组把 8 位状态集从 256 砍到 256/2^K，K≈8~9 时归零；但实测中由于组内可动槽分布不均、列向量共线（`h=8` 只有 64 种不同列向量），**K=4 就足以致死**。

### 1.4 冻结率的来源：补偿链落在小 Rice 分区里

插桩统计"链条（自身 + 全部补偿目标）内最小 Rice 参数 k"与冻结率的关系（15_Celestial_Crystals）：

| 链内 min k | 槽数 | 冻结率 |
|--:|--:|--:|
| 1 | 115 | 93.9% |
| 2 | 282,763 | 92.3% |
| 3 | 487,170 | 76.7% |
| 4 | 471,708 | 50.2% |
| 5 | 512,020 | 24.8% |
| 6 | 537,923 | **9.6%** |
| 7 | 333,806 | **3.9%** |
| 8 | 98,856 | 0.9% |
| 9 | 33,414 | 0.1% |
| ≥10 | 6,000 | 0.0% |

结论：**冻结率几乎完全是"补偿目标所在 Rice 分区太小"的函数**。k=2 的分区只有 4 个折叠值（±1 的取值空间），而补偿 delta 在 LPC 高阶下可达 ±6，必然跨桶 → 冻结。反之 k≥6 时桶宽 64，冻结率降到个位数。

这条数据是修复方案 S1 与 S2 的共同依据。

### 1.5 语料全景

| 载体 | 合格残差 | 可动残差 | 冻结率 | 尾部池 | 状态 |
|:--|--:|--:|--:|--:|:--|
| 01_Sphere | 873,799 | 794,389 | 9.1% | 981 | ok |
| 周华健-刀剑如梦 | 1,639,734 | 1,490,705 | 9.1% | 2,291 | ok |
| 周杰伦-爱在西元前 | 2,053,646 | 1,862,887 | 9.3% | 2,912 | ok |
| - River | 1,987,895 | 1,778,246 | 10.5% | 2,733 | ok |
| ZerocreationGame - Child and the Wind | 706,012 | 701,618 | 0.6% | 785 | ok |
| ZerocreationGame - Meet | 985,321 | 978,724 | 0.7% | 1,134 | ok |
| ZerocreationGame - Dismal Rain | 1,165,104 | 1,165,092 | 0.0% | 1,141 | ok |
| 朱婧-小河淌水 | 1,809,451 | 1,349,318 | 25.4% | 2,497 | ok（偶发） |
| 朱婧汐-香格里拉(2004版) | 2,616,505 | 1,622,268 | 38.0% | 3,687 | **偶发失败** |
| 15_Celestial_Crystals | 2,763,740 | 1,699,494 | 38.5% | 2,661 | **偶发失败** |
| - Endless / - Refrain / 可惜没如果 / 12_Deep_Space_Pyramid / When Blood Ignites / 情未了 | — | — | >40% | — | 直接拒用 |

两个观察：

- 冻结率与"音源是否安静"强相关：**钢琴独奏、氛围/环境音类（When Blood Ignites、Deep Space Pyramid、Refrain、Endless）全部被拒**，而有持续能量的流行/摇滚源全部可用。这不是随载体运气，是系统性偏斜。
- 被判可用的 10 个载体里，冻结率 25%~38.5% 的 3 个是间歇失败的温床；其余 7 个（≤10.5%）目前稳定。

---

## 2. 其余发现逐一说明

### F2 重试机制无效

`rust/src/stego/audio/mod.rs:115-144` 的重试循环里，`attempt` 只进入 `freshness.salt(attempt, binding)` → 换 STC 种子 → 换 `want` 消息位序列。而可达状态集的塌缩只取决于**冻结槽分布 + 列向量 + 覆盖奇偶**，与消息位无关（每个约束都是"状态某位 = 常数"，是否相容不取决于常数）。所以：

- 塌缩彻底时 4 次全失败（已实测）。
- 塌缩不彻底时（可达集 = 1~2）重试以 1/2 概率蒙对，这解释了为什么偶尔"第 0 次失败第 1 次成功"。
- 代价：每次重试 = 2 遍全文件解码（22 MB 文件约 0.5 s/遍），失败路径白烧 4 倍 CPU。

### F3 稀释相位硬编码 → 落点与口令无关

`mod.rs:105-106`、`182-183`、`237-239`、`259-260`、`297-298` 五处：

```rust
let header_phase = 0x5EED_1234_ABCD_0001u64;
let body_phase   = 0x1234_5678_9ABC_DEF0u64;
```

`thin_pick(index, range, wanted, phase)` 的 `range`/`wanted`/`phase` 全部与口令无关（前两者来自文件和载荷尺寸）。后果：

- 同一载体 + 同一载荷尺寸 → 载荷永远落在**同一批物理残差位置**，与口令、用户无关。
- `Mapping::BodyPermuted` 的 `KeyedPermutation` 只打乱"位到槽的映射顺序"，**不改变槽的集合**，所以口令对位置的保密作用为零。
- 与图像/WAV 引擎对比：它们对全载体做口令派生置换，位置随口令变化；FLAC 这条路径把这个性质丢了。
- 实际威胁：持 cover 的观察者拿到两个不同口令的 stego，两文件改动位置的**交集恒等于改动位置本身**，可直接定位并做平均/差分统计。

### F4 补偿写入放大 5~8 倍且未计入统计

实测（100% 填充，单次嵌入）：

| 载体 | 数据槽移动 | 补偿残差改写 | 合计 | 放大 | 占全文件残差 |
|:--|--:|--:|--:|--:|--:|
| 周杰伦-爱在西元前 | 152,400 | 1,127,397 | 1,279,797 | 8.4× | **62.3%** |
| 朱婧-小河淌水 | 83,327 | 620,331 | 703,658 | 8.4× | 38.9% |
| 15_Celestial_Crystals | 80,113 | 380,178 | 460,291 | 5.7× | 16.7% |
| ZerocreationGame - Dismal Rain | 106,272 | 417,079 | 523,351 | 4.9× | 44.9% |

而 `FlacCarrier::modified_slots()`（`flac/mod.rs:685`）只在 `apply` 里对数据槽 `+1`，补偿写入不计入；`EmbedStats.modified_slots` 因此只报第一列。连带影响：

- 用户看到的"改动率"比真实残差改写数低 5~8 倍。
- 安全档位（Paranoid 0.5% / High 1.5% / Balanced 3.0% 槽数）实际约束的是第一列，不约束真实改写量。
- `write_remainder` 每次都做一次 `read_codeword` 回读校验，128 万次改写 = 128 万次回读，是嵌入耗时的重要组成。

### F5 单嵌 5~13 遍全文件解码

一次成功嵌入的文件遍历：`embed_flac` 的 `analyse`（1）+ 每轮 `FlacCarrier::new`（analyse 1 + 采集 1）+ `refresh_checksums`（1 + 收尾 `analyse` 1）+ `max_sample_drift`（cover 1 + stego 1）≈ **7 遍**；4 次重试下 ≈ **13 遍**；失败路径 ≈ **29 遍**。其中：

- `refresh_checksums` 末尾的 `analyse` 重算 MD5 后与自己刚算的 MD5 比（`flac/mod.rs:510-516`）——同一份字节的两遍解码，恒等，属纯浪费。
- `FlacCarrier::new` 每次都重新 `analyse`，而 4 次重试的输入字节**完全相同**（`bytes = carrier.to_vec()` 重置），结果必然相同。
- `max_sample_drift` 重解码 cover，而 cover 的解码结果前面已经算过。

WAV 侧同尺寸文件嵌入 1.6~6.7 s，FLAC 侧 3~17 s，差距主要来自这里。

### F6 错误信息误导

`mod.rs:146-161`：trellis 不可行时对外抛的是

> This FLAC's predictor reacts too strongly for in-place residual coding: in a quiet stretch a one-unit residual move would need neighbouring codewords to change width...

而真实含义是"当前载荷尺寸 + 当前置换下 trellis 编不出来"。用户会以为载体不可用（实测中同一载体别的填充/轮次完全可用）。压测输出的失败行因此也误导。

### F7 测试盲区

`flac/e2e.rs` 的合成载体：单声道、FIXED order-2、**固定 Rice k=8**（`flac_carrier()` 里 `let k = 8u32`）。对照 §1.4 的表，k=8 → 冻结率 0.9%，**处在整个实测分布的最优端**。真实 FLAC 用 LPC 阶数至 12 + 自适应 Rice，安静段落 k 落到 1~4 → 冻结率 50%~92%。

后果：单元测试结构上不可能触发 F1，`cargo test` 全绿而真实语料间歇失败。

`flac_corpus_validates` 是 `#[ignore]` 且只断言解码 MD5 一致，**不做嵌入/提取**。

### F8 魔数与 37.5% 拒用率

- `MAX_STUCK_RATE = 0.40`（`flac/mod.rs:92`）、`capacity_slots()` 里的 `discount = (1.0 - stuck_rate * 1.5)`（`flac/mod.rs:582`）、`DRIFT_BUDGET = 8`（`flac/mod.rs:82`）、`FLAC_EMBED_ATTEMPTS = 4`（`mod.rs:37`）。
- 前两个直接决定"哪些载体能用、能报多大容量"，是按单个文件拟合的经验值，没有语料级标定。实测中 0.385 与 0.380 刚好卡在 0.40 之下，边界样本一动就翻。

### F9 漂移闸门过松

`DRIFT_BUDGET = 8` 的注释说它是"用来抓住解析器/补偿链 bug"的正确性闸门。但补偿正确时真实漂移是 **1**（立体声 mid/side 下 2），8 这个值抓不住任何东西——它当初要防的"7 dB 拖尾"是几千单位的量级，也远超 8。要么收紧到 2~3 让它成为真闸门，要么承认它只是装饰。

### F10 尾部池过小

16 个真实载体的尾部池为 785~3687。512 槽头部（256 基头 + 256 特征字）要占其中的 14%~25%（合成测试载体 600 个尾部里占 85%）。推论：**短于约 25 秒的 FLAC 直接不可用**（44100 Hz、4096 块、立体声 → 约 215 个尾部 < 512）。

---

## 3. 修复方案

按"先止血、再治本、再加固"排序。S1+S2 是治本组合，建议一起做。

### S0（止血，1 小时）：让失败变成可诊断、可规避

1. **拆开两类错误**：`TrellisInfeasible` 单独报"载荷尺寸与当前载体槽位分布不相容，请减小载荷或换载体"，不要再复用"predictor reacts too strongly"。把后者留给真正的 `stuck_rate > MAX_STUCK_RATE` 拒用。
2. **`max_sample_drift` 提前**：在 4 次重试之前算一次（它只依赖文件，与 attempt 无关），别放在最后。
3. 补一条压测断言：把"最长连续全冻结组"作为可观测指标暴露出来（`STRHIDE_FLAC_STATS` 已有钩子）。

收益：用户能看懂失败原因，压测能定位，不改任何算法行为。

### S1（治本，**推荐首选**）：把"可动性"纳入槽位选取

**关键前提（已验证成立）**：`Rice` 参数 `k`、`rice` 标志、自身 bucket、`has_legal_move` 在移动下全部不变；且由于补偿对 +1/-1 反对称（`minus == -plus`），**一个槽的 `Move::None` 状态在嵌入前后保持不变**（`PlusOnly`/`MinusOnly` 互换，`Both`/`None` 不变）。实测嵌入 128 万个残差后，`usable` 计数分毫不差。

因此**读者可以从隐写文件独立算出与写者完全一致的冻结集合**——当前代码注释里"补偿链是否能装下取决于会被改写的残差，所以只能否决方向、不能参与选取"的判断是**过虑了**：能装下与否取决于方向，但"完全装不下"（即 `Move::None`）是**不变**的，只有它才需要参与选取。

做法：

1. 结构合格性判定从现在的 `{rice, k>=1, bucket>=1, has_legal_move}` 扩展为 **再叠加 `move_legality != Move::None`**。
2. 稀释抽样改为在"非冻结"子流上做：`thin_pick(index, non_frozen_total, body_slots, phase)`，遍历时跳过冻结槽（`analyse` 那一遍顺带把冻结位图记下来即可，1 bit/合格残差 ≈ 330 KB，无需二次解码）。
3. 容量定价与抽样用**同一个**分母（即现在的 `analysis.usable`），F1 消失。

效果：

- **trellis 不再有任何冻结位置 → `TrellisInfeasible` 结构上不可能发生**，F1、F2 一并消除，4 次重试可删（省 4 倍 CPU，也省掉"偶发"的全部体感）。
- 可用槽池从 `slots` 缩到 `usable`（15_Celestial：2.76 M → 1.70 M），容量报告与真实可用量**首次一致**，F8 的 1.5 倍折扣魔数可一并删掉。
- 每一遍遍历只多算一次 `slot_legality_raw`（已有），不增加解码遍数。

风险与对策：

- **LPC 位移取整**可能让 `minus` 与 `-plus` 差 1，极端情况翻转某个槽的 `None` 状态。对策：若要绝对稳妥，把选取条件收紧为 `move_legality == Move::Both`（`Both` 在移动后仍是 `Both`，严格不变），代价是可用池再小一些；或者保留 `!= None` 并加一条**回归测试**断言"嵌入前后 `usable` 计数不变"（见 S5）。建议先按 `!= None` 实现 + 上回归测试，测试若发现翻转再收紧到 `Both`。
- 需要与 S3（口令派生相位）一起改，两处都动到稀释参数。

### S2（治本，与 S1 互补）：对补偿链加 Rice 参数下限

在结构合格性里再加一条：**自身残差与全部补偿目标都必须满足 `rice == true` 且 `k >= KMIN`**（`KMIN` 取 6，或写进特征字做成自适应）。

依据是 §1.4 那张表：`KMIN=6` → 冻结率 9.6%→6.5%；`KMIN=7` → 3.0%。

- `k` 是**不变**的结构量 → 读者可复现，与 S1 的可复现性要求相容。
- 代价：可用池进一步缩小（15_Celestial 从 2.76 M → 约 1.01 M，`KMIN=6`）。
- 与 S1 的关系：S1 之后残余冻结率已经很低，S2 是"把冻结消灭在源头"，两者叠加后 `u=3` 下全冻结组概率降到 ~10^-6 量级。若只上一个，**优先上 S1**。

### S3（安全，必做）：稀释相位改为口令派生

```rust
let body_phase   = u64::from_be_bytes(H(secret, domain, "flac-body-phase",  wanted)[..8]) ;
let header_phase = u64::from_be_bytes(H(secret, domain, "flac-head-phase",  512)[..8]);
```

- 口令在两端都有 → 可复现性不受影响。
- **绝不能**把 `attempt` 掺进去（读者不知道用了哪次）。
- 收益：载荷物理位置随口令散布，与图像/WAV 引擎的保密性质对齐。
- 现状下"两个 stego 交集即改动位置"的攻击失效。

### S4（诚实性）：统计与容量口径对齐

1. `EmbedStats.modified_slots` 之外增加 `residuals_written`（数据槽 + 补偿），或至少在 FLAC 路径把两者一起计入对外展示的改动量。
2. 容量报告与小马 API 输出里注明"每移动 1 个采样会连带改写 N 个残差"。
3. 若采用 S1，`capacity_slots()` 直接等于"非冻结槽数"，删掉 1.5 倍折扣。

### S5（回归测试，必做）：把 F1 关进 CI

1. **造一个坏载体**：合成 FIXED order-4 / LPC order-8~12 + 自适应 Rice（安静段 k=1~3）的 FLAC，冻结率目标 30%~50%。断言"嵌入 + 提取 100% 成功，且不触发任何重试"。
2. **断言不变式**：对一个真实载体，嵌入后 `analyse().slots / usable / tails` 与嵌入前完全相等（这是 S1 成立的基础，也是 F1 修复后一切可复现性的地基）。
3. 把 `max_raw_payload_bytes` 档位（100% 填充）纳入常规测试，别只测 20%。
4. 把 `flac_corpus_validates` 扩展成"验证 + 嵌入 + 提取"，用 `STRHIDE_FLAC_CORPUS` 指向 `temp/testaudio`，在小子集上跑。

### S6（性能）：解码遍数 5~13 → 2~3

1. `embed_flac` 的首次 `analyse` 结果缓存并传入 `FlacCarrier::new`（4 次重试共用）→ 省 8 遍。
2. `refresh_checksums` 末尾的自比 `analyse` 删掉 → 省 1 遍。
3. `max_sample_drift` 用已缓存的 cover 解码结果 → 省 1 遍。
4. S1 落地后重试可删 → 再省 3 遍。
5. `write_remainder` 的回读校验改为 `debug_assert` 或按 `STRHIDE_FLAC_DEBUG` 门控 → 省 128 万次随机读。

预期：22 MB 载体嵌入从 ~9.5 s 降到 ~2 s 量级。

### S7（可选，长期）：放宽容错的补偿链

现状要求"每个后继采样精确还原"，链长恰为 `order`，解唯一，没有自由度。若把链延长到 `order + E`，则状态方程变成 `order` 个方程、`order + E` 个未知量，**出现 E 维解族**，可以在其中挑一组能装进各自 Rice 桶的解。

- 收益：把大量冻结槽变成可动槽（源头提升可用容量）。
- 代价：允许中间采样出现几单位的瞬时漂移（需把 `DRIFT_BUDGET` 提到 4~8 才说得通），且每次移动改写更多残差。
- 判定：这是**以可听度换容量**，与本项目"最小可表示步长"的定位有冲突。**建议先做 S1/S2/S3，把 S7 作为备选**，除非安静音源的可用性被列为硬需求。

---

## 4. 建议落地顺序

| 步骤 | 内容 | 预期效果 |
|:--|:--|:--|
| 1 | S0（错误分类 + 指标暴露） | 失败可诊断，不改行为，零风险 |
| 2 | S1（可动性纳入选取） | **根除间歇失败**，容量口径变诚实 |
| 3 | S5（坏载体 + 不变式回归测试） | 锁死 S1 的成果，防止回归 |
| 4 | S3（口令派生相位） | 补上位置保密性 |
| 5 | S2（Rice 下限）+ 删重试 + 优化解码遍数 | 冻结率降到个位数，性能提升 4~5 倍 |
| 6 | S4（统计口径）+ F9（收紧漂移闸门到 2~3） | 对外数字与真实行为一致 |
| 7 | 视需要评估 S7 / F10 | 安静音源可用性与短载体支持 |

第 2、3 步是本轮的核心；做完之后"FLAC 压力测试偶发错误"应当彻底消失，且可以从代码中删除整套重试逻辑。

---

## 5. 附录

### A. 复现命令

```bash
cd rust
cargo build --release --all-features --example audio_stress
mkdir -p ../temp/flacstress && cp ../temp/testaudio/*.flac ../temp/flacstress/

# 最小复现（同载体同填充仅轮次不同，round 2 失败）
STRHIDE_FLAC_ERR=1 ./target/release/examples/audio_stress \
    ../temp/flacstress/15_Celestial_Crystals.flac 4 0.4 1

# 全语料（50 作业，2 失败，均 4 次重试全失败）
STRHIDE_FLAC_ERR=1 ./target/release/examples/audio_stress \
    ../temp/flacstress 4 0.2,0.4,0.6,0.8,1.0 4

# 逐载体槽位统计
for f in ../temp/flacstress/*.flac; do
  echo "$(basename "$f") :: $(STRHIDE_FLAC_STATS=1 \
    ./target/release/examples/audio_stress "$f" 1 1.0 1 2>&1 | grep -m1 '^flac-stats')"
done

# WAV 对照（全绿）
mkdir -p ../temp/wavstress && cp ../temp/testaudio/*.wav ../temp/wavstress/
./target/release/examples/audio_stress ../temp/wavstress 3 0.2,1.0 4
```

### B. 本次审查中插过的临时探针（均已回滚）

- `stego/audio/core.rs`：plan 序下统计冻结槽数 / 全冻结组数 / 最长连续全冻结组（`STRHIDE_FLAC_STATS`）。
- `stego/audio/flac/mod.rs`：链内最小 k 与冻结率交叉直方图（`STRHIDE_FLAC_HIST`）。
- `stego/audio/flac/mod.rs`：数据槽移动数 vs 补偿残差改写数（`STRHIDE_FLAC_STATS`）。

需要复核本文任何数字时，三处探针可原样加回，位置分别是 `core.rs` 的 `moves` 构造之后、`flac/mod.rs` 的 `analyse` 末尾、`flac/mod.rs` 的 `apply` 补偿循环内。

### C. 审查范围

- 逐行精读：`stego/audio/{core,mod,cost,perm,sample,wav,tests}.rs`、`stego/audio/flac/{mod,frame,bits,e2e}.rs`
- 参照阅读：`stego/coding/stc.rs`、`stego/engine.rs`（音频派发部分）、`stego/format.rs`（音频 profile）
- 实测：16 个真实 FLAC（22 MB 量级，含钢琴独奏 / 氛围 / 流行 / 摇滚）、7 个真实 WAV，共 64 个嵌入-提取作业 + 21 个负向检查
