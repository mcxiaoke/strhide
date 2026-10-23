# stego 模块技术代际定位与抗检测能力评估

> **⚠️ 部分结论已被更正（2026-10-23 22:15）**
>
> 本文 §2「代际定位」、§3.4「文献横向」、§6「升级路径」中关于"代价函数落后一到两代、
> 换 MiPOD/QMP 是最高性价比"的判断，已被 `docs/stego_survey_and_roadmap_20261023.md` 推翻：
> 在 2025–2026 年的 RMNet / WSERNet 两套 CNN 检测器上，HILL 的检出率是三种空域代价里
> **最低**的（0.4 bpp：HILL 89.4/93.4 vs S-UNIWARD 94.7/96.9 vs WOW 95.0/97.2）。
> 另有两处更正：非加性策略（CMD/BBC）在综述中**没有任何增益数字**；"低载荷安全"仅是
> 本自研检测器的盲区，不代表 CNN 也看不见。
>
> 仍然成立的部分：编码层（STC）处于第一梯队、缺富模型评测、结构域可归因性属独立威胁模型。
> 阅读本文时请以新文档为准。

| 项 | 内容 |
| :--- | :--- |
| 文档编号 | `STEGO-POSITION-AUDIT-20261023-2125` |
| 编制时间 | 2026-10-23 21:25:21（本机时间） |
| 范围 | `rust/src/stego/`（PNG 空间域 + JPEG DCT 域），不含结构域容器隐藏 |
| 方法 | 逐文件核对实现 → 对照 `docs/` 已有实测 → 对照公开文献 |
| 结论强度 | 实现事实为**核对结论**；抗检能力部分明确区分「本机实测」「文献数据」「推断」，见 §8 |

---

## 0. 结论

1. **编码层处于第一梯队，且是合理扩展而非落后。** STC（Filler TIFS 2011）至今仍是畸变最小化框架的事实标准编码器；学界共识是 STC/SPC 已逼近编码效率极限，近十年的研究重心已整体转到代价函数设计。本项目的分组 `u`（PNG `u≤3`、JPEG 内核上限 64）比 Filler 原始构造（`u≤h`）更激进，属于有效扩展。
2. **代价函数落后一到两代。** HILL（ICIP 2014）、UERD（TIFS 2015）属"启发式"第一代；其后有统计模型系（MiPOD 2016 / JMiPOD）与学习型系（UT-GAN 2020、SPAR-RL 2021、JS-GAN 2025），以及 2024 年的 QMP/GQMP、DCDT。**换代价函数是当前性价比最高的安全提升手段，架构上已无阻碍**（`CostModelRegistry` 可插拔）。
3. **抗检测能力：对传统统计检测近乎免疫，对富模型无数据，对 CNN 只有弱证据。** 前者的"免疫"是三元 `±1` 匹配的构造性质，不构成抗现代隐写分析的证据；真正缺失的是 SRM/SCRMQ + FLD ensemble 的 `P_E` 评测。
4. **两个具体的抗检弱点是"默认单绿通道"和"8 值类约束"**，都是在实现中被工程需求引入的，不是算法本身的必然。
5. **定位判断**：这是"经典主流方案的正确实现"，工程完成度（参数自描述、无判别 oracle、密码学信封、可插拔代价模型）高于同类工具的平均水平；但安全侧停在 2014/2015 年的代价函数与"传统检测器"一级的评测，不能称为"先进技术"。

---

## 1. 实现事实核对

以下全部为读码确认，不是文档转述。

### 1.1 编码层

| 事实 | 位置 |
| :--- | :--- |
| STC 实现：带状校验矩阵由 stego secret 派生，列向量最低位/最高位强制为 1 | `stego/coding/stc.rs:1-100` |
| `DEFAULT_STC_H = 8`（128 状态），`MIN_STC_H = 4`，`MAX_STC_H = 10` | `stego/coding/stc.rs:86-91` |
| `MAX_STC_U = 3`（空间域头部只有 2 bit 表达 `u`），`KERNEL_MAX_U = 64`（JPEG 超块用整字节） | `stego/coding/stc.rs:95-109` |
| 支持非对称三元失真 `rho_plus` / `rho_minus`；非法方向通过 `Move` 直接不提供（等价 wet cost） | `stego/coding/stc.rs:29-46` |
| 提取端只需重算 `s = Hx`，**不需要代价图与 trellis** | 同上 |

### 1.2 PNG 空间域

| 事实 | 位置 |
| :--- | :--- |
| 三元 `±1` 匹配，移动锁在八值类 `v & 0xF8` 内（类底只能 +1、类顶只能 −1） | `stego/spatial/engine.rs:1-25` |
| 可嵌入值域 `[8, 247]`；`class_rule == 1` 时进一步要求 `v % 8 ∈ [1,6]`，排除 r=0/7 的边界亏欠 | `stego/spatial/engine.rs:60-61, 853-855` |
| 代价：HILL，高通过滤 → 两级低通，默认 `p1=3`、`p2=15`、`epsilon=f32::EPSILON` | `stego/spatial/cost/hill.rs:1-30`；`stego/params.rs:186-201` |
| 代价图输入先做 `v & 0xF8` 掩码，保证嵌入前后逐位一致 | `stego/spatial/cost/hill.rs:43-64` |
| 方向代价：向邻域类均值移动更便宜，权重 `1 + 4·r²`，且**只决定方向、不参与槽位排序** | `stego/spatial/cost/hill.rs:160-186` |
| 槽位规划：合格像素按 `(cost bits, index)` 全序排序 → 剔除最平滑 30% → 密钥化置换取前 512 作头部/特征字 → 正文取最便宜前 N | `stego/spatial/engine.rs:726-791, 812-859` |
| 通道模式：`Green`（默认）优先，容量不足才扩 `Rgb`；Alpha 永不写入 | `stego/spatial/engine.rs:655-683`；`embed_spatial_with_profile` 先算 `pool_green` |
| `codec = Auto` 默认，按槽位比 `r` 选 `u ∈ {3,2,1}` | `stego/params.rs:195`；`stego/coding.rs::auto_select_codec` |

### 1.3 JPEG DCT 域

| 事实 | 位置 |
| :--- | :--- |
| 槽位是**几何集合**：全部 AC 位置按 flat index 密钥置换，两端都不看系数值 | `stego/jpeg/v3_layout.rs:1-30` |
| 头部 44B 超块 + TLV 扩展，定位种子由 `SuiteKDF(password, cover_digest)` 派生 | `stego/jpeg/engine.rs:1-30` |
| 代价：UERD，块能量用 `|c| & !1` 保证两端一致，8 邻域平滑在 MCU 真实几何上做，`Q[k]` 取文件自身 DQT | `stego/jpeg/cost/uerd.rs:1-30, 73-105` |
| 写入为 parity 对 `(2k,2k+1)` 内单方向翻转，故 JPEG 上是**二进制 STC**（每元素一个候选方向） | `stego/jpeg/engine.rs:24-30`；`coding::dct_move` |
| 仅 Y 分量参与嵌入（`COMPONENT_Y`），色度不动 | `stego/jpeg/engine.rs:732, 842, 913` |
| `u = min(body_grid/window, slot_budget/window, 64)`；`slot_budget = max(1.2M, min(n/4, 4GiB/bytes_per_slot))` | `stego/jpeg/v3_layout.rs:70-105`；`stego/params.rs:473-487` |
| 实测工作点举例：24 MP 载体 + 200 KB → `r = 14.7` → `u = 3`（**不是 64**；64 只是内核上限） | `stego/params.rs:470-472` 注释 |

### 1.4 默认安全档位

| 档位 | bpp 上限 | 目标槽位比 `r` |
| :--- | ---: | ---: |
| `Paranoid` | 0.06 | 11.5 |
| **`High`（默认）** | **0.10** | **6.9** |
| `Balanced` | 0.15 | 4.6 |

位置：`stego/params.rs:79-107`。注意学界评测点常取 0.4 bpp / 0.4 bpnzAC，本项目默认工作点比常见评测点低 3~4 倍，**这是它"看起来抗检不错"的主要来源之一**。

---

## 2. 代际定位

### 2.1 三代代价函数

文献对畸变最小化框架的分类已经稳定（Pan & Ni, *Symmetry* 2024；Liu et al., *Signal Processing* 2024）：

| 代 | 代表 | 本项目的对应 |
| :--- | :--- | :--- |
| 启发式（2010-2015） | HUGO、WOW、S-UNIWARD、**HILL**、**UERD**、GUED | PNG = HILL，JPEG = UERD |
| 统计模型（2016-） | MG、**MiPOD**、**JMiPOD** | 无 |
| 学习型（2019-） | UT-GAN、SPAR-RL、PICO-RL、JS-GAN、JEC-RL | 无 |

2024-2025 年的增量工作（QMP/GQMP、DCDT）仍在第一类框架内改进启发式设计，说明"启发式并未出局"，但 HILL/UERD 已明确不是该类的上限。

### 2.2 编码层的正确判断

关键词是**"已近极限"**：Pan & Ni 2024 的原话是 *"state-of-the-art coding methods, e.g., STCs and SPCs, have already approached the theoretical limit of coding efficiency… researchers have focused on improving the design of the distortion cost function"*。

因此：

- STC **不落后**，它是论文里的标准对照组，不换掉它是对的；
- 本项目的分组 `u` 让"每 bit 摊到 u 个元素"，是标准 STC 的合法扩展（Filler 原构造限 `u ≤ h`，本项目放开到 64，并在 `stc.rs:55-64` 给出了放开后仍可达的论证）；
- 唯一能说"更新"的是 SPC（polar codes），在个别码率下优于 STC，但差距在工程噪声内。

### 2.3 一句话代际结论

> **编码层 2011 年（但仍是主流）；代价层 2014/2015 年（已落后）；评测层 1999-2003 年（经典统计检测器）。**

---

## 3. 抗检测能力分层评估

### 3.1 对传统统计检测器：近乎免疫，但不能算成绩

**本项目 scan 的四类空域估计器**（`analysis.rs`）是卡方、SPA、RS、WS，均为 1999-2003 年的替换模型检测器。

【实测-本项目】`docs/png_blind_calibration_20261023.md` §3.3，29 个载体配对：

| 载荷 | WS / RS / SPA 相对载体 | 风险 |
| :--- | :--- | :--- |
| 64 B | **逐位相同** | 29/29 clean |
| 4 KiB | **逐位相同** | 29/29 clean |
| 满载（RGB ≈0.9 bpp） | SPA 下降 27 / 不变 2 / 上升 0 | 29/29 clean |

**为什么这不构成抗检证据**：RS/SPA/WS 建模的是"LSB 替换导致 `(2k,2k+1)` 值对均衡"。三元 `±1` 匹配从构造上就不产生该均衡，这是 2003 年以来文献的既有结论。同一份文档 §3.2 也证明：这些估计器对**真正的 LSB 替换**检出率是 100%/85%/100%，所以它们没坏，只是不测这一类。

该文档 §7.3 已自认："要把'我们的嵌入是否可见'变成可测量结论，需要建模 LSB matching 的统计量或有标定的 CNN。"

### 3.2 对富模型（SRM / SCRMQ + FLD ensemble）：完全空白

这是学界 `P_E` 评测的第一道门槛，也是绝大多数隐写论文的主表。**本项目没有任何 SRM/SCRMQ 结果**，`analysis.rs` 里也没有实现空间富模型或 DCT 富模型（DCTR/GFR）。

影响：无法回答"在标准 FLD ensemble 下，0.1 bpp 的 HILL+STC 载体对的可分性是多少"。按文献经验这个工作点通常 `P_E > 0.4`（接近不可分），但**本项目没有自己的数字**。

### 3.3 对 CNN（SRNet / EffNet）：只有弱证据

【实测-本项目】`docs/png_blind_calibration_20261023.md` §4.2，6 个载体 × 4 变体，Aletheia 预训练模型：

| 文件 | 变体 | SRNet-HILL | EffNet-HILL |
| :--- | :--- | ---: | ---: |
| 0001 | 载体 / 64 B / 4 KiB / 满载 | 0.335 / 0.338 / 0.342 / 0.467 | 0.593 全程不变，满载 0.641 |
| 0003 | 同上 | 0.387 / 0.399 / 0.327 / **0.731** | 0.998 全程 |
| 0004 | 同上 | 0.715 / 0.715 / 0.719 / 0.730 | 0.993 全程 |

可用结论：

- **低/中载荷（64 B、4 KiB）：无可测漂移**；
- **满载：会露**。`0003` 的 SRNet-HILL 从 0.387 升到 0.731，经典层综合分从 23 升到 55；
- **绝对分数不可作判据**：干净载体上 EffNet-HILL 跨度为 0.48~0.9975，SRNet-HILL 0.31~0.72，模型未在目标语料上重标定。

样本量 6 张，只能定性说"满载在针对性检测器下会暴露"，**不能给出检测阈值或载荷安全边界**。

### 3.4 文献横向：同类方案的真实差距

同为"代价函数 + STC"，公开文献给出的顺序是稳定的：**JMiPOD ≳ J-UNIWARD > UERD**（JPEG）、**MiPOD ≳ S-UNIWARD ≈ HILL**（空域）。

两组可直接引用的数字：

1. SRNet 检出率 @0.4 bpnzAC（*Electronics* 2025, 14:1610, Table 5）：

   | 方案 | SRNet 检出率 |
   | :--- | ---: |
   | J-UNIWARD | 63.86% |
   | **UERD** | **80.87%** |

2. `P_E` @QF=75、R=0.2（CCFR 载荷分散策略，HAL 论文 *Steganography by Minimizing Statistical Detectability*）：

   | 方案 | `P_E` |
   | :--- | ---: |
   | **UERD** | **0.245** |
   | JMiPOD | 0.269 |
   | J-UNIWARD | 0.301 |

两组数据方向一致：**UERD 在 CNN/富模型下比 J-UNIWARD 差 5~17 个百分点**。这是代价函数的代际差，不是实现缺陷——本项目的 UERD 已做了两处修正（MCU 真实几何、文件自身 DQT），比朴素移植更准。

---

## 4. 抗检弱点清单

按"确定度 × 影响"排序。

### 4.1 PNG 默认只写绿通道（确定，影响大）

`ChannelMode::Green` 优先，容量够就不扩 RGB（`engine.rs` 先算 `pool_green`；该布局是"小载荷输出字节不变"的兼容性妥协）。

【文献】彩色图像隐写分析（Abdulrahman et al., IWCC 2015 / SCN 2016；Goljan et al. WIFS 2014 的 SCRMQ）明确：**同等载荷只嵌一个通道比分散到三个通道更容易被检出**。

| 载荷 | S-UNIWARD 单绿 | S-UNIWARD RGB |
| :--- | ---: | ---: |
| 0.2 bpc | 87.92% | 76.30% |
| 0.4 bpc | 94.10% | 85.30% |

差 10 个百分点量级。本项目默认恰好落在"最容易被检出"的那一侧。

### 4.2 八值类约束（确定，影响中）

`v & 0xF8` 不变是为"提取端能重建代价图 → 能重建槽位排序"服务的。代价：

- 每个槽位的可动方向被砍掉一半（类底/类顶只有一个方向）；
- `class_rule == 1` 又排除 `v % 8 ∈ {0,7}`，槽位池再缩约 25%；
- 学术 STC 没有这个约束——因为标准做法用固定槽位集合（或 wet cost 排除），不依赖代价图。

这是**本项目独有**的自由度损失，也是"改动率 0.22~0.27 仍高于理论预期"的部分原因。

### 4.3 JPEG 槽位是随机子集，丢掉了成本选择性（确定，影响中）

空间域可以"只挑最便宜的槽"，JPEG 侧 `BodySlots = permute(BodyGrid)[0..n]` 是密钥均匀抽样，不能按 UERD 代价挑（`v3_layout.rs` 契约第 3 条明确写了这一点）。

结果：JPEG 侧的加权失真优势只来自 STC 的 Viterbi 最优性，拿不到"跳过昂贵元素"的额外收益。代价是容量与安全性的取舍更依赖 `u` 摊薄。

### 4.4 代价函数代际（确定，影响大）

HILL / UERD 均在 2014/2015 停步。见 §2、§3.4。

### 4.5 缺标准评测（确定，影响最大——因为它让你看不见 4.1~4.4 的实际量级）

没有 SRM/SCRMQ 的 `P_E`，没有在目标语料上重标定的 CNN EER，也没有覆盖 4.1 的"彩色单通道"检测器。现在的 `scan` 只能证明"不是 LSB 替换"，`docs/png_blind_calibration_20261023.md` §7 已把这条列为已知局限。

### 4.6 结构域封装的可归因性（确定，但属另一威胁模型）

`analysis.rs` 模块文档原话：结构指纹轨道"是唯一能抓到 strhide 自己的轨道"——自有 magic、非标准 chunk、IEND/EOI 之后的尾部数据。**对手只要知道 strhide 的格式，就能 100% 判定**，与像素统计无关。

讨论"抗检测"时必须把这条和载体隐写分开：载体隐写对抗的是统计隐写分析，结构域对抗的是格式识别。两者不可比。

---

## 5. 相对优势（客观记录，避免只列缺点）

1. **默认工作点保守**：`bpp ≤ 0.10` 且 `r ≥ 6.9`，比学界常用评测点（0.4 bpp / 0.4 bpnzAC）低 3~4 倍。多数工具默认跑在更高载荷上。
2. **改动率确实低**：STC `u=3` 实测 0.223~0.230 flips/bit（PNG）、0.240~0.252（JPEG），对比 Hamming k=3 的 0.292，净减 20%~24%（80 张真实相机原片，`docs/stc_capacity_eval_report_20261021.md` §二）。
3. **分组 `u` 的自适应选择**：按 `r` 分段选 3/2/1，满载检出率随 `u` 单调下降（Hamming 87% → u=3 67%，`stc_coding_design_20261021.md` §14），机制清晰。
4. **参数自描述 + 无判别 oracle**：codec/h/u 编码进头部，错密码与"无数据"折叠为同一错误。这是实用工具里少见的严谨度。
5. **可插拔代价模型**：`CostModelRegistry` + `SpatialCostModel` / `JpegCostModel` trait，替换代价函数是加模块而非重构。

---

## 6. 升级路径（按性价比）

| 优先级 | 动作 | 改动面 | 预期收益 | 风险 |
| :--- | :--- | :--- | :--- | :--- |
| P0 | 补 SRM/SCRMQ + FLD ensemble 评测，产出 `P_E` 曲线；在目标语料上重标定 Aletheia | 新增 `scripts/` 评测，不改引擎 | 把"抗检能力"从定性变定量，是后续所有决策的前提 | 无（纯测量） |
| P1 | PNG 默认改 RGB 三通道（或按通道 cost 加权分配） | `ChannelMode` 选择策略 + 阈值重标定 + 兼容性说明 | 文献量级 10 个百分点检测率改善；同时抬高满载容量 | 小载荷输出不再字节不变；正文槽位池变化会影响既有推荐容量 |
| P2 | PNG 换 MiPOD 或 QMP，JPEG 换 J-UNIWARD | 新增 `cost/mipod.rs`、`cost/juniward.rs`，注册进 Registry | 代价层从"第一代"进到"第二代/2024 改进型" | 需要重标定 `exclusion_percentile` 与方向代价；耗时可能上升（MiPOD 需迭代求解） |
| P3 | 解除八值类约束 | 需要把槽位顺序/集合写进头部，或改固定网格 | 恢复被砍掉的自由度，改动率与失真下降 | 触及线格式与兼容性，改动面最大 |
| P4 | JPEG 改用代价排序子集（而非随机子集） | `v3_layout` 契约变更 + 提取端需要代价图 | 拿到选择性收益 | 提取端必须能重建代价图，与"无参数提取"设计冲突 |
| 不建议 | 学习型代价（UT-GAN / SPAR-RL / JS-GAN） | 需 GPU 训练 + 模型分发 | 理论最优抗检 | 与"单一静态二进制"的产品定位直接冲突，收益/成本比最差 |

**推荐顺序的理由**：P0 不做，P1~P4 都无法验证收益。P1 只改一个默认值与阈值，是"改一行换 10 个百分点"的动作。P2 才是代际升级，但需要 P0 的度量支撑才敢翻默认。

---

## 7. 与主流方案的横向对照

| 方案 | 编码 | 代价 | 抗 SRM/富模型 | 抗 CNN（低载荷） | 抗 CNN（满载） | 备注 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **本项目 PNG** | STC + u≤3 | HILL 2014 | 无数据 | 实测无漂移 | 实测会露 | 默认单绿通道 + 8 值类约束 |
| **本项目 JPEG** | STC + u≤64 | UERD 2015 | 无数据 | 无数据 | 无数据 | 仅 Y 分量；槽位为随机子集 |
| S-UNIWARD + STC | STC | UNIWARD 2014 | 强 | 强 | 中 | 空域经典强基线 |
| MiPOD + STC | STC | MiPOD 2016 | 更强 | 更强 | 中 | 需迭代求解，慢 |
| QMP/GQMP + STC | STC | QMP 2024 | SOTA（启发式类） | — | — | 论文称优于 S-UNIWARD/HILL/MiPOD |
| J-UNIWARD + STC | STC | J-UNIWARD 2014 | 强 | 强 | 中 | JPEG 事实标准对照 |
| JMiPOD + STC | STC | JMiPOD 2016 | 更强 | 更强 | — | `P_E` 略优于 J-UNIWARD |
| UT-GAN / SPAR-RL | STC | 学习型 | 最强 | 最强 | 强 | 需 GPU 训练与模型分发 |
| JS-GAN / JEC-RL | STC | 学习型（JPEG） | 强 | — | — | 论文报告优于 J-UNIWARD 2.6%~11% |

表中"强/更强"为文献定性描述，非本项目实测；空白表示文献未提供同口径数据。

---

## 8. 本文的局限

1. **抗检结论的强度不均**：§3.1 是本机实测（可信），§3.4 是文献数据（适用条件不同语料/不同检测器），§3.3 只有 6 张配对样本（仅能定性）。
2. **未做新实验**：本文没有重跑任何评测，所有数字来自 `docs/` 既有记录与公开文献。若要下"抗检强/弱"的定量结论，必须先补 P0。
3. **文献数字不可直接横向相减**：§3.4 的两组数据来自不同论文、不同语料、不同检测器配置与不同载荷定义（bpnzAC vs bpp），只能看方向，不能精确比较幅度。
4. **"落后 1~2 代"是代际判断，不是性能倍数**：具体差距取决于载荷、载体分布与检测器，本文给出的 5~17 个百分点仅适用于 §3.4 引用的那两组实验条件。
5. **彩色单通道的量化数据来自他人实验**（S-UNIWARD/WOW），本项目未测自身实现在该检测器下的表现。

---

## 9. 数据来源

**本项目实测**

- `docs/stc_coding_design_20261021.md` §8.5（3 载体对比）、§12.4（u=1/2/3 实测）、§14（batch_stego 满载检出率）、§15（80 张原片结论）
- `docs/stc_capacity_eval_report_20261021.md`（4,480 点评测全表）
- `docs/png_blind_calibration_20261023.md` §2（分层采样）、§3（阈值标定与 216 载体分布）、§4（Aletheia 交叉核对）
- `temp/calib/*.json`（原始结果：`covers_real.json`、`lsb_real.json`、`real_stego.json`、`seval_smoke_dl.json`）

**代码**

- `rust/src/stego/{mod,params,format,header}.rs`
- `rust/src/stego/coding/stc.rs`
- `rust/src/stego/spatial/{engine.rs,cost/hill.rs}`
- `rust/src/stego/jpeg/{engine.rs,v3_layout.rs,cost/uerd.rs}`
- `rust/src/analysis.rs`（自研检测器与阈值注释）
- `rust/tests/batch_stego.rs`（门禁与历史数字）

**公开文献**

1. T. Filler, J. Judas, J. Fridrich, "Minimizing Additive Distortion in Steganography Using Syndrome-Trellis Codes," *IEEE TIFS*, 2011.
2. B. Li, M. Wang, J. Huang, X. Li, "A New Cost Function for Spatial Image Steganography," *ICIP*, 2014.（HILL）
3. L. Guo, J. Ni, W. Su, C. Tang, Y.-Q. Shi, "Using Statistical Image Model for JPEG Steganography: Uniform Embedding Revisited," *IEEE TIFS*, 2015.（UERD）
4. V. Holub, J. Fridrich, T. Denemark, "Universal distortion function for steganography in an arbitrary domain," *EURASIP JIS*, 2014.（S/J-UNIWARD）
5. V. Sedighi, R. Cogranne, J. Fridrich, "Content-Adaptive Steganography by Minimizing Statistical Detectability," *IEEE TIFS*, 2016.（MiPOD）
6. Q. Liu, W. Su, J. Ni, X. Hu, J. Huang, "An efficient distortion cost function design for image steganography in spatial domain using quaternion representation," *Signal Processing*, 2024.（QMP/GQMP）
7. Y. Pan, J. Ni, "Domain Transformation of Distortion Costs for Efficient JPEG Steganography with Symmetric Embedding," *Symmetry*, 2024.（DCDT）
8. J. Yang et al., "An embedding cost learning framework using GAN," *IEEE TIFS*, 2020.（UT-GAN）
9. W. Tang et al., "An automatic cost learning framework for image steganography using deep reinforcement learning," *IEEE TIFS*, 2021.（SPAR-RL）
10. J. Yang et al., "JPEG Image Steganography With Automatic Embedding Cost Learning," *Int. J. Intelligent Systems*, 2025.（JS-GAN）
11. M. Goljan, J. Fridrich, R. Cogranne, "Rich model for steganalysis of color images," *WIFS*, 2014.（SCRMQ）
12. Abdulrahman et al., "Color image steganalysis using correlations between RGB channels," *IWCC*, 2015 / *SCN*, 2016.
13. M. Boroumand, M. Chen, J. Fridrich, "Deep residual network for steganalysis of digital images," *IEEE TIFS*, 2019.（SRNet）
14. "A Generic Image Steganography Recognition Scheme…," *Electronics*, 2025, 14:1610, Table 5（UERD 80.87% vs J-UNIWARD 63.86% @SRNet, 0.4 bpnzAC）
15. "Steganography by Minimizing Statistical Detectability: The cases of JPEG and Color Images," HAL（`P_E`: UERD 0.245 / JMiPOD 0.269 / J-UNIWARD 0.301, QF75 R=0.2）
