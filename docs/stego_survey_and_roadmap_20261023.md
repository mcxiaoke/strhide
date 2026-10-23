# stego 模块技术综述与改善路线

> 基于 `temp/papers` 的 4 篇论文与 `temp/github` 的 33 个开源库，修正并替代
> `docs/stego_algorithm_positioning_and_detection_audit_20261023.md` 中关于"代价函数代际"的判断。

| 项 | 内容 |
| :--- | :--- |
| 文档编号 | `STEGO-SURVEY-ROADMAP-20261023-2215` |
| 编制时间 | 2026-10-23 22:15（本机时间） |
| 资料 | 论文 4 篇（PDF + 转写 txt）、GitHub 仓库 33 个 |
| 方法 | 论文按原文表格逐项核对数字；库按 README/LICENSE/源码判读 |
| 配套 | `docs/steganalysis_eval_plan_20261023.md`（评测脚本与协议） |

---

## 0. 结论

1. **撤回"HILL 落后一代、应换 MiPOD/S-UNIWARD"的判断。** 在两套 2025–2026 年的 CNN 检测器上，HILL 的检出率是三种空域算法里**最低**的（0.4 bpp：HILL 89.4 / 93.4，S-UNIWARD 94.7 / 96.9，WOW 95.0 / 97.2）。没有证据支持换 S-UNIWARD 或 WOW 能带来收益。
2. **真正的最优不是换算法，而是"少改"和"改对方向"。** 载荷从 0.4 降到 0.1 bpp 能让检出率掉 20 个百分点；换成另一套代价函数只能动 3~6 个百分点，且方向不稳定。
3. **0.10 bpp 不是安全线。** HILL 在 0.1 bpp 下仍被检出 68.7%（SRNet）~77.3%（RMNet）。此前"低载荷几乎不可检"的说法要下调。
4. **JPEG 侧唯一稳定更优的是 J-MiPOD**（GFR 79.9%、CNN 88.4%，两种检测器都是最低），但**整个开源生态没有可用实现**（见 §4.3）。
5. **ROI 最高的改动是 cost polarization**：strhide 已有 `polarize_weight` 开关，但实现是"全局乘常数"，丢失了方向信息；`hstego` 给出了正确做法（wiener precover → 重压缩 → 按符号逐系数打折）。不动架构、不动线格式。
6. **跨算法泛化衰减 20 个百分点**：用 S-UNIWARD 训的检测器测 HILL 只有 76.8%（自训练 96.9%）。HILL 的痕迹与主流算法最不同源——对"不知道工具用什么算法"的检测方，这是**天然的防守优势**。
7. **跨源失配的收益比任何算法选择都大**：真实多源语料（ALASKA2）0.6 bpp 的检出率比 BOSSbase 0.4 bpp 低 24 个百分点，载荷还更高。
8. **33 个库里只有 3 个可直接复用**（hstego / pySTC / sealwatch），其余是 CTF 工具、玩具实现或需自训的检测器。
9. **不要做**：换 MiPOD（无实现 + HILL 已不吃亏）、非加性 CMD/BBC（综述无任何增益数字）、STC→SPC（<1 个百分点）。
10. **一个必须先修的方法论问题**：strhide 的 JPEG `bpp` 分母是"Y 分量总系数（4:2:0 下等于像素数）"，学界 JPEG 载荷用 `bpnzAC`（非零 AC 系数）。两者差一个数量级，任何跨来源对比前必须统一口径。

---

## 1. 资料与方法

| 编号 | 论文 | 性质 | 用于本文的部分 |
| :--- | :--- | :--- | :--- |
| P1 | A Comprehensive Survey of Digital Image Steganography and Steganalysis（APSIPA 2024） | 综述，无自有实验 | 算法分类、§5.1 局限声明 |
| P2 | A Steganalysis Method Based on Relationship Mining（Electronics 2025, RMNet） | 实测 | Table 1（载荷梯度）、Table 2（跨算法）、Table 11（ALASKA2） |
| P3 | Steganalysis Network for Weak Steganographic Signal Extraction（Sensors 2026, WSERNet） | 实测 | Table 6（算法对比） |
| P4 | Steganalysis in Directional JPEG Images（WIFS 2024） | 实测 | Table I（四算法 × 两检测器）、Table II（方向性敏感度） |

所有数字均回到原文表格逐项核对，行号见 §9。论文之间条件不同（数据集、尺寸、划分、检测器），**只比同一张表内的数字**，不跨表相减。

---

## 2. 认知修正

### 2.1 HILL 的真实位置

同一检测器、同一数据集下比较（准确率↑ = 越容易被检出）：

| 检测器 | 载荷 | WOW | S-UNIWARD | **HILL** | 来源 |
| :--- | ---: | ---: | ---: | ---: | :--- |
| RMNet | 0.4 bpp | 97.15 | 96.86 | **93.35** | P2 T1 |
| RMNet | 0.1 bpp | 86.20 | 82.03 | **77.34** | P2 T1 |
| SRNet | 0.4 bpp | 94.95 | 94.72 | **89.37** | P2 T1 |
| WSERNet | 0.4 bpp | 93.14 | 91.63 | **87.32** | P3 T6 |
| WSERNet | 0.1 bpp | 78.18 | 72.06 | **69.79** | P3 T6 |

**HILL 在 5 个条件里全部最低。** 这与"启发式第一代已经过时"的印象相反。

可能的解释（未被论文验证，属推断）：

- 两个数据集都以 S-UNIWARD/WOW 为主训练，HILL 样本比例低；
- HILL 的代价在纹理区高度聚集，改动分布更"尖锐"，而 CNN 的池化/下采样对这种分布不敏感；
- 佐证在 §3.2 的跨算法表：HILL 作为未知目标是衰减最大的（−20 pt），说明其痕迹确实与主流不同源。

**不能反过来说"HILL 最强"**：检测器换到富模型（SRM/GFR）时排序会变，Fridrich 组早期的结论是 S-UNIWARD 对 SRM 更强。正确表述是**"排名依赖检测器，没有稳定赢家，HILL 至少不吃亏"**。

### 2.2 JPEG 侧的排序随检测器翻转

P4 Table I（ALASKA2 512×512，QF75，0.4 bpnzAC，nsF5 为 0.2）：

| 算法 | GFR + FLD | CNN（EfficientNet-B0） |
| :--- | ---: | ---: |
| J-UNIWARD | 87.2 | 90.3 |
| UERD | 85.5 | **93.4** |
| J-MiPOD | **79.9** | **88.4** |
| nsF5（0.2） | 94.5（JRM） | 87.0 |

- **J-MiPOD 在两个检测器下都最安全**，这是唯一稳定的结论；
- UERD 在 GFR 下**优于** J-UNIWARD（85.5 < 87.2），在 CNN 下**劣于**（93.4 > 90.3）；
- 所以我此前引用的"UERD 落后 J-UNIWARD 5~17 个百分点"来自另一篇不同条件的论文，不能当作普适结论。

**教训**：跨论文比 P_E 是无效的（P1 §4.2.1 也明确反对），排序在 3~5 个百分点内会随检测器翻转。

### 2.3 撤回的三条旧结论

| 旧说法（`…audit_20261023.md`） | 更正 |
| :--- | :--- |
| "代价函数落后一到两代，换 MiPOD/QMP 是性价比最高的安全提升" | 在 CNN 检测器下 HILL 检出率最低；换算法无收益证据。**降优先级** |
| "非加性（CMD/BBC）大幅提升安全性" | P1 只述机理，**没有任何增益数字**，且引用了 RLAE 的相反结论（加性可胜过非加性）。不能作为决策依据 |
| "低载荷（64B/4KiB）无可测漂移 → 低载荷安全" | 那只是本项目自研检测器的盲区，不代表 CNN 也看不见。HILL 0.1 bpp 仍有 69%~77% 检出率 |

---

## 3. 论文的可操作结论

### 3.1 载荷是最强杠杆，且收益递减

HILL 的检出率随载荷变化（P2 T1 / P3 T6）：

| 载荷 | 0.1 | 0.2 | 0.3 | 0.4 |
| :--- | ---: | ---: | ---: | ---: |
| SRNet（P2） | 68.66 | 76.47 | 81.35 | 89.37 |
| RMNet（P2） | 77.34 | 85.96 | 90.58 | 93.35 |
| WSERNet（P3） | 69.79 | 77.14 | 83.35 | 87.32 |

0.1→0.2 增加 7.4~8.6 pt，0.3→0.4 只增加 2.8~4.0 pt。**收益递减，但 0.1 bpp 本身并不安全。**

对照本项目默认 `bpp ≤ 0.10`（`params.rs:79-107`）：这个档位在本项目语料上的真实检出率**从未测过**，不能假定安全。

### 3.2 跨算法泛化：HILL 的痕迹最"不像"主流

P2 Table 2，训练 0.4 bpp S-UNIWARD、直接测其他算法：

| 测试算法 | RMNet 准确率 | 相对自训练 |
| :--- | ---: | ---: |
| WOW | 95.75 | −1.1 |
| S-UNIWARD（自训练） | 96.86 | — |
| MiPOD | 87.74 | −8.4 |
| HUGO | 82.31 | −13.8 |
| **HILL** | **76.80** | **−20.1** |

P3 的跨算法表给出同样方向（训 S-UNIWARD → 测 HILL 73.67）。

含义：**如果检测方不知道载体是用什么算法嵌的，针对 S-UNIWARD 训出来的模型对 HILL 只有 77% 左右**。这对 HILL + 密钥化槽位选择的组合是实质优势。

但反过来：**一旦检测方知道是 HILL 并专门训练，检出率就回到 93%**。所以"算法保密"的收益只存在于"对方没做定向训练"这一前提。

### 3.3 跨源失配：比换算法重要一个量级

P2 Table 11（ALASKA2，灰度，6:2:2）：

| 算法 | 0.6 bpp |
| :--- | ---: |
| WOW | 73.05 |
| S-UNIWARD | 71.65 |
| HILL | 69.43 |

对比同表 BOSSbase 的 0.4 bpp（93.35）——**载荷更高（0.6 > 0.4）却低 24 个百分点**。差额来自载体源的多样性（数十种相机 + 不同 ISP）。

对 strhide：本项目语料本身就是混源（相机原片 + DIV2K + 网络图 + 截图）。**这既是评测难点，也是天然保护**——但前提是对方没有在你的语料分布上重训。

### 3.4 JPEG 方向性与量化表

P4 Table II，各嵌入函数对方向性的敏感度：

| 嵌入函数 | 内容方向性 | 量化表（QT）方向性 |
| :--- | :--- | :--- |
| J-UNIWARD | 小 | 中 |
| **UERD** | **无** | **高** |
| J-MiPOD | 小 | 高 |
| nsF5 | 中 | 小 |

两个直接可用的结论：

1. **UERD 对内容方向完全不敏感**——它的代价只依赖块能量与量化步长。这解释了为什么它在 CNN 下最容易被检出：改动分布与内容的方向结构无关，而这正是方向性检测器要抓的。
2. **UERD 对非对称量化表高度敏感**——本项目 UERD 用的是文件自身 DQT（`jpeg/cost/uerd.rs:11-21`），相机直出的非标准表会直接改变代价分布。

另有一条通用风险：P4 发现 BOSSbase 与 ALASKA2 都偏向水平边缘（ALASKA2 方向分布 17/44/33/6%），**训练集的方向性偏差会被检测器学走**。本项目的评测语料若偏向某类构图，`P_E` 会系统性偏高或偏低。

### 3.5 非加性策略：无可用数据

P1 描述了 CMD（方向同步）、BBC/BBM（块边界连续性）、GINA（通道对齐）的机理，但**没有给出任何 `P_E` 或准确率数字**；同时引用了 RLAE 的结果"加性方法可以胜过非加性"。

结论：**不作为本轮改造依据**。如果要做，必须先自己度量。

---

## 4. 33 个开源库盘点

### 4.1 分层

| 层 | 数量 | 仓库 |
| :--- | ---: | :--- |
| 可直接复用 | 3 | **hstego**（MIT）、**pySTC**（MIT）、**sealwatch**（MPL-2.0，已装） |
| 需移植（公式参考） | 3 | stegolab（MIT 文件头）、IStego100K 的 `uerd.m` / `HILL_GINA`（GPL-3 子目录）、image-steganography-lab（反例） |
| 仅参考思路 | 8 | rsteg、lupin（Rust 工程结构）、StegoForge（检测器编排）、zip-image-stego、stegseek、zsteg、AperiSolve、stegoVeritas |
| 需自训才能用 | 3 | RMNet（Apache-2.0，无权重）、SiaStegNet（无权重）、SteganoGAN（预训练但二进制不可用） |
| 无关（CTF / 玩具 / 其他格式） | 16 | 其余 |

注意：`IStego100K` 是**数据集**（208,104 张 1024×1024，10 万 cover-stego 对，QF75-95，J-UNIWARD / nsF5 / UERD，0.1~0.4 嵌入率），但仓库只有网盘链接、不含图像。`ST3GG` 是 CTF 工具箱，**不是数据集**。

### 4.2 三个可直接复用的

**hstego（MIT）** — 最有价值。它是"端到端可用"的同类工具，策略可以直接对照：

- 载荷上限 `MAX_PAYLOAD = 0.05`（`hstegolib.py:33`），比本项目默认 0.10 更保守；
- **cost polarization**（`hstegolib.py:1015-1045`）：wiener 滤波估计 precover → 重压缩得到 `coeffs_estim` → `s = sign(estim - coeffs)` → 对"回到估计值"的方向把 ρ 乘以 `m = 0.65`；
- 通道策略是**逐通道独立算 cost + 按容量切分消息**（`split_by_capacity`），不是联合优化；
- STC 直接 vendored DDE 的 C 实现。

**pySTC（MIT，附 cp311/cp312 wheel）** — DDE C++ STC 的 ctypes 封装，477 + 915 行，`stc_hide/stc_unhide` 接口。**只支持二元嵌入**，未导出多层 `stc_ml`。可作对照基线，不能直接替换本项目的三元实现。

**sealwatch 2025.9（MPL-2.0）** — 已在 venv 中，SRM/SRMQ1/CRM/DCTR/GFR/JRM/CC-JRM/PHARM + FLD ensemble。评测脚本已就绪。

### 4.3 关键缺口

| 缺口 | 现状 | 影响 |
| :--- | :--- | :--- |
| **MiPOD / J-MiPOD 实现** | 全生态**无真实实现**；只有"mipod-style"教学近似 | 想做 J-MiPOD 必须自己按论文实现（UERD 的代价结构 + 多元高斯 + 迭代求逆） |
| **彩色联合通道分配** | 只有 hstego / stegolab 的"逐通道独立 + 切分"，无联合优化 | "改 RGB"能拿到分布收益，但拿不到最优分配收益 |
| **非加性（CMD/BBC）** | 仅 IStego100K 有灰度 CMD（`CMDGrayEmbeddingSimulator.m`），BBC 无实现 | 想试只能自己写 |
| **检测器权重** | RMNet / SiaStegNet 均未附 `.pth` | 要么自训（GPU + BOSSbase），要么继续用 Aletheia |

---

## 5. 改善路线

排序依据：预期收益 ÷ 改动面。所有收益量级都来自 §3 的实测表。

### P0 — 建立自己的基线（前置，未完成）

- 目标：拿到本项目 HILL+STC 在 0.05/0.10/0.20/0.40 bpp 下的 `P_E` 曲线；
- 工具：`scripts/steganalysis_pe.py`（已完成，见配套文档）；
- 为什么最先：**没有基线，后面每一条都无法判断值不值**。特别是 §3.1 显示 0.1 bpp 仍有 69%~77% 检出率，本项目的实际位置完全是未知数。
- 成本：2 000 对 × 4 载荷，SRMQ1 约 2.5 小时。

### P1 — 统一载荷口径（方法论，必须先做）

- 问题：JPEG 侧 `bpp = payload*8 / (block_count*64)`，4:2:0 下等于"每像素比特"；学界用 `bpnzAC`。两者差约 6~8 倍，跨来源对比会得出完全错误的结论。
- 做法：`StegoCapacityInfo` 增加 `nonzero_ac` 与 `payload_bpnzac` 字段，CLI 同时打印两个口径；
- 改动面：`jpeg/engine.rs` 的 probe 输出 + `mod.rs` 的结构体 + CLI 显示；
- 收益：让"0.10 bpp 到底相当于学界的哪个点"变成可回答的问题。

### P2 — 把 cost polarization 做对（最高 ROI）

- 现状：`polarize_weight` 只做 `rho_minus *= w`（`jpeg/engine.rs:898`），**与系数方向无关**，等于全局偏向一个方向；
- 目标：按 hstego 的做法，用 precover 估计决定**每个系数**哪个方向更自然；
- 改动面：`jpeg/engine.rs` 的代价构造 + 一次 wiener 滤波与重压缩（可用 `dct_io` 自己实现，无需新依赖）；线格式不变，头部不动；
- 预期：hstego 用 `m=0.65`，属于"利用 JPEG 压缩 side information"，是 UERD 之上最常见的免费增益；
- 风险：需要先有 P0 的基线才能验证；precover 估计会增加嵌入耗時约 10%~20%。

### P3 — PNG 通道分配

- 现状：默认单绿通道，容量不足才扩 RGB（`spatial/engine.rs:952` 附近）；
- 证据：彩色空域单通道比 RGB 均分检出率高约 11 pt（S-UNIWARD @0.2 bpc：87.92% vs 76.30%，Abdulrahman et al. 2015/2016）；
- **注意**：P4 的 JPEG 结论（只嵌 Y 仍被 90%+ 检出）**不能**搬到 PNG，两者检测器不同；
- 做法：默认 `Rgb`，或按通道 cost 加权分配；需重标定 `exclusion_percentile` 与 `safety bpp`；
- 风险：小载荷输出不再字节稳定（现有测试会失败，需同步更新）。

### P4 — UERD 的方向项 / QT 处理

- 证据：P4 Table II 量化了 `UERD = 内容方向 none / QT 方向 high`；
- 做法 A（小）：对非对称 DQT 做对称化修正后再算块能量；
- 做法 B（中）：在 UERD 的 ρ 上加一个方向感知项（参考 J-UNIWARD 的小波方向能量）；
- 收益未知，需 P0 基线对照；成本低于换整个代价函数。

### P5 — 解除八值类约束（大改，暂缓）

- 现状：`v & 0xF8` 不变保证代价图在 stego 上可复现，代价是每个槽位丢一半自由度；
- 解法：把槽位排序写进头部（容量代价），或改用 JPEG 那样的几何槽位；
- 判定：只有 P0 显示"改动率/失真确实是瓶颈"时才做。

### 不建议

| 项 | 理由 |
| :--- | :--- |
| 换 MiPOD / J-MiPOD | 无开源实现；HILL 在 CNN 下已不吃亏；J-MiPOD 要自己实现迭代求解，工程量远大于收益 |
| 换 S-UNIWARD / WOW | 两套 CNN 下检出率都**高于** HILL（§2.1） |
| 非加性 CMD / BBC | 综述无任何增益数字，反向证据存在 |
| STC → SPC | 编码效率已近极限，<1 pt |
| 学习型代价（UT-GAN / SPAR-RL） | 与"单一静态二进制"定位冲突 |

---

## 6. 一个被低估的既有优势

§3.2 的跨算法表说明：**痕迹"不像主流"本身就是防守**（HILL 被 S-UNIWARD 训练的检测器识别率仅 76.8%）。而 strhide 还有两层额外的东西：

1. **校验矩阵由密钥派生**（`coding/stc.rs`），同一张图不同密钥得到完全不同的改动集合；
2. **PNG 槽位排序密钥化置换**（`spatial/engine.rs:774-780`），头部位置也不固定。

这防的是"提取"和"指纹匹配"，**不防"检测存在"**——检测方不需要密钥也能训练分类器。所以别把它当抗检手段，但它确实让"针对某个 strhide 版本做定向指纹"变得困难。

---

## 7. 数据缺口

| 缺口 | 补法 |
| :--- | :--- |
| 本项目 HILL+STC 的真实 `P_E` | P0 |
| JPEG 载荷的 bpnzAC 口径 | P1 |
| 本项目 JPEG 的 GFR/CC-JRM 结果 | 已支持脚本，未跑（CC-JRM 需 Linux） |
| 单通道 vs RGB 在本项目语料上的差值 | P3 前先测，别只信文献的 11 pt |
| 非加性策略的真实收益 | 无现成实现，暂不做 |

---

## 8. 与审计文档的冲突处理

`docs/stego_algorithm_positioning_and_detection_audit_20261023.md` 的 §2、§3.4、§6 中关于"代价函数代际"和"UERD 落后 J-UNIWARD"的表述**以本文为准**。冲突根源是那份文档依据的是 2024 年之前的文献共识与不同条件的第三方数据；本文依据的是 2025–2026 年三篇实测论文的同表数据。

保留不变的判断：编码层（STC）处于第一梯队；缺富模型评测；结构域可归因性是独立威胁模型。

---

## 9. 数据溯源

| 引用 | 位置 |
| :--- | :--- |
| HILL/S-UNI/WOW × 载荷 | `temp/papers/A Steganalysis Method Based on Relationship Mining.txt:294-322`（Table 1） |
| 跨算法泛化 | 同上 `:329-390`（Table 2） |
| ALASKA2 跨源 | 同上 `:564-590`（Table 11） |
| WSERNet 算法对比 | `temp/papers/Steganalysis Network for Weak Steganographic Signal Extraction and Enhancement.txt:619`（Table 6） |
| JPEG 四算法 × 两检测器 | `temp/papers/Steganalysis in Directional JPEG Images.txt:154-164`（Table I） |
| 方向性敏感度 | 同上 `:208-214`（Table II） |
| 旋转鲁棒性 | 同上 `:64-66` |
| hstego 载荷上限 | `temp/github/hstego/hstegolib.py:33` |
| hstego 极化 | 同上 `:1015-1045` |
| pySTC 接口 | `temp/github/pySTC/pystc/stc_interface.cpp` |
| 本项目极化实现 | `rust/src/stego/jpeg/engine.rs:887-900` |
| 本项目载荷档位 | `rust/src/stego/params.rs:79-107` |
| 本项目槽位排序 | `rust/src/stego/spatial/engine.rs:726-791` |
