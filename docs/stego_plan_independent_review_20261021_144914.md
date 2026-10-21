# 内容域隐写“参数收敛与抗检加固”方案独立评审

> **评审对象**：  
> - [`docs/steganalysis_tools_and_countermeasures_memo_20261021.md`](steganalysis_tools_and_countermeasures_memo_20261021.md)（下称 **memo**）  
> - [`docs/stego_profile_convergence_and_hardening_plan_20261021.md`](stego_profile_convergence_and_hardening_plan_20261021.md)（下称 **plan**）  
>
> **评审日期**：2026-10-21 14:49  
> **评审方式**：逐条核对实现代码；对 `temp/images/png/0001.png`、`0002.png` 两张 1920×1280 相机原图做嵌入/提取/扫描实测；复核 `docs/stc_capacity_eval_report_20261021.md` 的评测方法。  
> **结论**：**方向正确，但不建议按 plan 当前顺序直接实施**。有三项 P0 问题必须先解决：评测证据自指、`0xF8` 类边界结构性指纹、header 无扩展位导致的 `ChannelMode` 设计缺陷。`stego_domain` 可按子密钥方案保留，`safety_level` 需改容量口径，`RgbSpread` 应降级为待验证实验。  
> **代码改动**：本次评审未修改任何生产代码或原文档；实验脚本与产物在 `temp/stego_probe/`。

---

## 0. 证据等级约定

| 等级 | 含义 |
|---|---|
| **E1** | 代码/规范中的确定事实，可直接按文件行号核对 |
| **E2** | 本次或已有报告中的实测数据，附复现方式 |
| **E3** | 基于原理的推断或待验证假设，不能当作结论 |

后文每条判断尽量标注证据等级。memo 与 plan 中未标注等级的定量结论，建议统一按 E3 处理，直到补上独立评测。

---

## 1. 结论摘要

### 1.1 总体判断

两份文档最有价值的部分是**概念分层**：

- 把“让官方工具/公开提取器读不出”与“让统计检测器发现不了”分开；
- 把参数分成“私有方言/写侧策略/内部数学常量”；
- 指出载荷率是抗检的第一杠杆。

这些方向是对的。但作为**可实施、可验收**的方案，目前存在三类问题：

1. **证据链不成立**：用项目自带的 `scan`（chi2/RS/SPA，均为 LSB 替换模型）证明抗 SRM/SRNet，并据此定出 `r≥4.5` 的“安全线”。
2. **漏掉真正的结构性指纹**：`val & 0xF8` 类边界只能单向移动，留下与密钥无关、可线性估计嵌入率的直方图凹陷；该指纹在推荐容量下仍有约 9σ 强度，而 `scan` 完全看不到。
3. **方案设计与现有格式冲突**：`stego_domain` 的字符串拼接会破坏默认兼容；`ChannelMode` 是读写对称参数，但 32 位 header 已无空位，读端无法得知模式；`safety_level` 用槽位比做预算，遇到三通道打散会把载荷放大 3 倍。

### 1.2 问题分级

| 编号 | 问题 | 等级 | 影响 |
|---|---|---|---|
| **P0-1** | 以 `scan` 分数作为抗 SRM/SRNet 证据；阈值无留出集、无 CI | E1/E2 | 所有“安全容量/安全等级”结论不可信 |
| **P0-2** | `0xF8` 类边界单向移动，形成可估计嵌入率的结构指纹 | E1/E2 | 推荐容量下仍可被 scheme-aware 检测器稳定检出 |
| **P0-3** | header 32 位已用满；`ChannelMode` 无位置记录，且可能影响 header 定位 | E1 | 读端可用性缺陷；后续 mode/phase/KDF 无法扩展 |
| **P1-1** | `stego_domain` 示例默认值会改变现有 5 个 HKDF 标签 | E1 | 默认路径破坏兼容，与“100% 互通”矛盾 |
| **P1-2** | `safety_level` 的 r 预算与 `RgbSpread` 冲突；4.5 是边界非余量 | E1/E2 | 开三通道后载荷与 bpp 放大 3 倍 |
| **P1-3** | API 收敛仍保留 `stc_h`/`algorithm`，CLI 仍暴露全部数学参数 | E1 | “收敛”目标落空；source-breaking 无迁移路径 |
| **P1-4** | 结构/编码器指纹未验证；“结构层 0 风险”过强 | E2/E3 | 换编码器来源的载体可能出现 FLEVEL/块结构指纹 |
| **P1-5** | PBKDF2 100k 迭代偏弱；无 KDF 版本字段 | E1 | 真实保密性弱于 domain 隔离的收益 |
| **P2-1** | 论文归属、`0xF8` 定位、u=3 JPEG 数字、版本号等事实性偏差 | E1 | 文档可信度 |
| **P2-2** | “风险跳变率”无定义；4,480 点非独立；采样截断前 4 MB | E1/E2 | 统计结论不可复现 |
| **P2-3** | `--capacity` 的 i18n 格式占位符原样输出；“half of max”文案过期 | E1 | 用户可见错误 |

---

## 2. 评审方法与复现

### 2.1 代码核对范围

| 主题 | 文件 |
|---|---|
| 空间域嵌入/提取/容量 | `rust/src/stego/spatial/engine.rs` |
| HILL 代价与方向代价 | `rust/src/stego/spatial/cost/hill.rs` |
| 三元移动/矩阵编码 | `rust/src/stego/coding.rs`、`coding/stc.rs` |
| header 位布局 | `rust/src/stego/header.rs` |
| KDF/信封 | `rust/src/stego/envelope.rs` |
| 参数结构 | `rust/src/stego/params.rs`、`rust/src/params.rs` |
| 盲检扫描 | `rust/src/analysis.rs`、`analysis/calibration.rs` |
| CLI/config/i18n | `rust/src/cli.rs`、`config.rs`、`i18n/` |
| 版本 | `rust/Cargo.toml` |

### 2.2 实测设置

- 载体：`temp/images/png/0001.png`、`0002.png`，1920×1280，RGB，8-bit，相机原片导出。
- 载荷：随机字节，45 KiB（46,080 B）、100 KiB、188 KiB；密码统一为 `probe`。
- 45 KiB 略低于 `--capacity` 报出的推荐值 46,454 B；按 `r = available_slots / needed_bits ≈ 4.54`，`Auto` 应选 `u=3`；实测 0.227 flips/bit，与 u=3 区间一致。
- 100 KiB：`r ≈ 2.04`，`Auto` 选 `u=1`；188 KiB：`r ≈ 1.09`，`u=1`。
- 分析脚本：`temp/stego_probe/analyze.py`；逐像素比较绿色通道，统计改动方向、`cover_val % 8` 残差分布、逐类直方图变化，并按 `src/analysis.rs` 原样复算 `chi2_lsb_suspicion`。
- 扫描：`strhide scan --json`，与实际 CLI 行为一致。
- 结构指纹：解析 PNG chunk，比较 zlib 头、FLEVEL、IDAT 分块。

### 2.3 局限

- 仅两张 PNG，不能替代全语料统计；但类边界机制是**结构性**的，两张图已足以证伪“不存在该指纹”的普适断言。
- 未覆盖 JPEG/UERD 的类边界等价物，未覆盖 RGBA/灰度。
- 9σ 是“已知 clean 参考直方图”下的强度；盲检还需要自然图像直方图模型，但不影响“该指纹可被利用”的结论。
- 未训练 SRM/CNN；因此本评审不反过来声称“SRM 一定检出”，只指出**现有证据不能证明检不出**。

### 2.4 复现命令

```powershell
# 生成随机载荷
python -c "import os; open(r'temp/stego_probe/payload_45.bin','wb').write(os.urandom(45*1024))"

# 嵌入
rust/target/release/strhide.exe embed temp/images/png/0001.png `
  -d temp/stego_probe/payload_45.bin -p probe `
  -o temp/stego_probe/s045.png --overwrite

# 扫描
rust/target/release/strhide.exe scan --json temp/stego_probe/s045.png

# 残差/chi2 分析
python temp/stego_probe/analyze.py
```

---

## 3. P0-1：评测证据自指，`scan` 分数不能证明抗 SRM/SRNet

### 3.1 代码事实（E1）

`strhide scan` 的内容域检测器只有三项：

| 检测器 | 模型假设 | 代码位置 |
|---|---|---|
| `chi2-lsb` | LSB **替换**会把 `(2k, 2k+1)` 频数拉平 | `analysis.rs:860-880` |
| `rs-analysis` | RS 状态转移，针对 LSB 替换 | `analysis.rs:964-990` |
| `spa` | 样本对分析（DWW），针对 LSB 替换 | `analysis.rs:993-1058` |

以上是像素域内容检测器；JPEG 还会额外跑结构域的 `dct:calibration`。本节讨论的是像素域证据，结论不受该结构检测器影响。

`chi2_lsb_suspicion` 返回 `(df - chi2) / df` 的截断值。它只对“直方图比自然图像更均匀”给出正分；当嵌入让直方图**更不均匀**时，`chi2 > df`，函数返回 0。也就是说，它是**单边**检测器。

这一点与 `0xF8` 类边界指纹的方向正好相反：类边界移动让 `(0,1)`、`(6,7)` 对更不均匀，chi2 反而返回 0。

### 3.2 项目自己已经承认过（E1）

`docs/CHANGES-20261020.md:9`：

> “RS/SPA 只建模 LSB 替换的必然结果……要恢复 0.90 需引入建模 ±1 的检测器。”

既然已知检测器不建模 ±1，就不能用它的分数来论证 ±1/STC 的抗检性。memo 的 §4.1 “实证”与这条记录直接冲突。

### 3.3 实测：分数对 3.4%→31.4% 的改动完全不敏感（E2）

| 文件 | 载荷 | 改动绿色像素 | 改动比例 | `scan` 分数 | 发现的检测器 |
|---|---:|---:|---:|---:|---|
| 0001 原图 | — | — | — | **50** | RS≈0.09，SPA≈0.08 |
| s045 | 45 KiB | 83,845 | 3.41% | **50** | RS≈0.09，SPA≈0.08 |
| s100 | 100 KiB | 409,229 | 16.65% | **50** | RS≈0.09，SPA≈0.08 |
| s188 | 188 KiB | 770,623 | 31.36% | **50** | RS≈0.09，SPA≈0.08 |

- 原图本身已经是 `50 / suspicious`（RS/SPA 假阳性）。
- 嵌入后分数不变，说明 `scan` 没有检测到嵌入，只是在重复同一组假阳性。
- 采用 `src/analysis.rs` 原样复算的 chi2 在 full image、first 4 MB、flat RGB、green 单通道上均为 **0.0**。

结论：`scan` 对三元 ±1 嵌入没有检验力。memo 把“87.5% → <7.5%”解释为“抗检能力提升一个数量级”，是把**自家启发式分数的跳变**误当成了**检测器的错误率**。

### 3.4 统计方法问题（E1/E2）

1. **同一批数据既调阈值又报效果**：`r=4.5` 是在这 80 张图上选的，没有留出集。它更像拟合值，不是验证值。
2. **有效样本是 80，不是 4,480**：4,480 = 80 图 × 2 格式 × 7 载荷 × 4 编码；同一张图的多档结果高度相关，不能按独立样本算 CI。
3. **“风险跳变率”没有定义**：报告没有给出阈值、基线、聚合方式。7.5% = 6/80，图像级 95% CI 约 3%～16%，不能写成“<7.5% 的黄金安全线”。
4. **没有 SRM/SRNet**：memo 引用的 85%～95% / 58%～65% 是外部文献在标准语料上的数量级，不是本项目的实测。

### 3.5 建议

- 把 `scan` 降级为“自家工具自检”，不再作为 plan 的验收标准。
- 建立独立评测：
  - **SRM（34,671 维）+ FLD 集成**，按图像级交叉验证，报告 \(P_E\) 与 CI；
  - 或至少实现 **scheme-aware** 检测器：聚合 32 个 8 值类的边界赤字、双边 chi2、逐通道残差；
  - 载荷梯度至少覆盖 0.05 / 0.1 / 0.15 / 0.2 bpp，并报告“检测所需样本量”，而不是单一分数。
- 所有容量阈值必须来自留出集；文档中把未验证数字标为 E3。

---

## 4. P0-2：`0xF8` 类边界单向移动是可估计嵌入率的结构指纹

### 4.1 机制（E1）

空间引擎为了保持 HILL 代价图逐位可复现，把像素限制在 8 值类内：

- `val % 8 == 0`（类底）只能 `+1`；
- `val % 8 == 7`（类顶）只能 `-1`；
- 其余可 `+1` 或 `-1`。

见 `coding.rs:366-390`、`engine.rs:507-534`。这样 `val & 0xF8` 不变，提取端能重算同一张代价图；但类底/类顶是**单向门**：只出不进或只进不出。

### 4.2 实测（E2）

0001.png，45 KiB（推荐容量附近，u=3）：

| 指标 | 数值 |
|---|---:|
| 改动绿色像素 | 83,845（3.41%） |
| 改动落在 r=0/7 的比例 | 24.81% |
| r=0 直方图变化 | **-1.62%** |
| r=1 直方图变化 | **+1.70%** |
| r=6 直方图变化 | **+1.77%** |
| r=7 直方图变化 | **-1.35%** |
| 每类样本数 | ≈30.3 万～31.5 万 |
| r=0 绝对赤字 \(\delta_0\) | 5,096 |
| Poisson 显著性 | 5,096 / √315,445 ≈ **9.1σ** |

0002.png 复现：

| 指标 | 数值 |
|---|---:|
| 改动绿色像素 | 85,795（3.49%） |
| r=0/7 占比 | 25.2% |
| r=0 / r=1 / r=6 / r=7 | **-1.68% / +1.71% / +1.84% / -1.38%** |
| \(\delta_0\) | 5,164 |
| 显著性 | ≈ **9.3σ** |

高载荷对照：

| 载荷 | 改动比例 | r=0 | r=1 | r=6 | r=7 | \(\delta_0\) | 显著性 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 45 KiB | 3.41% | -1.62% | +1.70% | +1.77% | -1.35% | 5,096 | 9.1σ |
| 100 KiB | 16.65% | -7.96% | +8.56% | +9.08% | -6.98% | 25,113 | 44.7σ |
| 188 KiB | 31.36% | -14.83% | +16.49% | +17.66% | -12.62% | 46,778 | 83.3σ |

30% 的平滑区排除没有缓解：改动落在边界的比例仍约 25%，与均匀分布一致。

### 4.3 可估计嵌入率（E2）

本组实测满足近似线性关系：

\[
N_{\text{changed}} \approx 16 \cdot \delta_0
\]

| 载荷 | \(16\delta_0\) | 实际改动 | 误差 |
|---|---:|---:|---:|
| 45 KiB | 81,536 | 83,845 | -2.8% |
| 100 KiB | 401,808 | 409,229 | -1.8% |
| 188 KiB | 748,448 | 770,623 | -2.9% |
| 0002 45 KiB | 82,624 | 85,795 | -3.7% |

也就是说，攻击者只需看 r=0 的净赤字，就能在不知道密钥、不知道具体改动位置的情况下，把嵌入量估到约 3% 误差。再把 32 个 8 值类聚合，信噪比还会进一步提高。

### 4.4 为什么现有防线挡不住

- **`safety_level` 减半**：\(\delta_0\) 与改动量近似线性，9σ 只会降到约 4.5σ，不会“致盲”。
- **`stego_domain`**：完全不影响像素统计。
- **`RgbSpread`**：总改动量不变；如果把三通道聚合，信号不变；如果逐通道看，每通道样本变少，但攻击者可以联合建模。它不是这个指纹的解。
- **`exclusion_percentile`**：按代价排除平滑像素，不按残差排除边界，实测无缓解。
- **`scan`**：chi2 是单边的，方向正好相反；RS/SPA 不建模类边界。

### 4.5 修复选项

**方案 A（推荐，P0）：排除类边界**

- 候选集只接受 `r ∈ [1,6]`；
- 候选槽位减少 25%，按 `r=4.5` 的推荐载荷从 46,454 B 降到约 34,835 B；45 KiB 示例仍能嵌入（`r≈3.4`，`Auto` 会降为 `u=2` 而非 `u=3`），但改动率从 0.227 升到约 0.26，安全余量下降；
- 单向移动彻底消失，`r=0/7` 赤字不再存在；
- 代价图不变，提取端只需使用同一 eligibility 规则；
- 需要版本/配置区分新旧文件（旧文件用 r∈[0,7]，新文件用 r∈[1,6]）。

**方案 B（研究项）：keyed class phase**

- 如果只是“每张图一个相位”，只有 8 种可能，攻击者可以穷举，等价于 3 bit 秘密，不够；
- 要真正打散，需要 per-block 或 per-slot 相位，代价图的 HILL 局部性要重做；
- 不建议作为 v1 的修复。

**方案 C：允许跨类 ±1 + 固定点校验**

- 允许 `7→8`、`0→-1` 后，`v & 0xF8` 会变，代价图与提取端排序可能不一致；
- 需要在 stego 图上重算代价图并验证排序，复杂，暂不建议。

### 4.6 文档需要改的地方

memo §4.2 目前把 `val & 0xF8` 写成“论文最优配置 / 数学基石 / 绝不可动”。应改为：

> `0xF8` 是**提取端代价图可复现性**的基石，但它同时带来固定对齐的类边界单向移动，形成可估计嵌入率的结构指纹。需要在该不变式与抗检性之间做显式取舍；推荐排除 r=0/7。

---

## 5. P0-3：header 无扩展位，`ChannelMode` 的读端设计不成立

### 5.1 位预算（E1）

`header.rs:15-25`：

```
bit  0..26  envelope length
bit 26..28  codec id (2 bits)
bit 28..32  stc h (4 bits)
```

26 + 2 + 4 = 32，**没有空位**。`MAX_STC_H=10`，h 的取值是 4..10，11..15 未使用；`MAX_STC_U=3`，codec id 0..3 也已用满。

### 5.2 鸡生蛋问题（E1）

`header` 的位置由 `header_seed` 对候选集做置换后取前 256 个槽位决定（`spatial/engine.rs:536-546`）。如果 `ChannelMode::RgbSpread` 改变候选集：

- 读端不知道 mode，就找不到 header；
- 也就无法从 header 里读出 mode。

plan §4 把“写入 RgbSpread / 读取 GreenOnly → 提取失败”写成“安全阻断”，但这实际上是**可用性缺陷**，不是安全边界。用户只要忘记在 extract 时配同一个 mode，就会丢数据；攻击者如果有二进制，也可以两种模式都试。

### 5.3 建议的分类：P / F / L

plan 现在的 P/L 二分不够，建议增加 **F 类（Format feature）**：

| 类别 | 定义 | 是否影响 header 定位 | 例子 |
|---|---|---|---|
| **P（Private dialect）** | 秘密/方言，读写必须一致 | **可以** | `default_secret`、`stego_domain` |
| **F（Format feature）** | 格式特性，写端记录、读端自描述 | **不可以** | codec/u/h、channel mode、class phase、KDF id |
| **L（Write policy）** | 只影响写侧预算/压缩 | 不可以 | payload budget、compression |

关键原则：**F 类不得影响 header 定位**。header 永远使用 legacy 设置（GreenOnly、phase 0、legacy 候选集），F 类写在 header 的 feature word 里；P 类可以影响 header seed（因为它是秘密/方言的一部分）。

### 5.4 v2 header 迁移路径（建议）

- 用 `stc_h = 15`（当前未使用值）作为 v2 标记：旧读端 `validate_stc_h` 会拒绝，安全落到 `NoHiddenData`；需先用旧版本验证这一点。
- v2 header 仍在同样的 256 个 legacy header 槽位写入前 32 字节；随后再读 32 个槽位作为 feature word。
- feature word 至少包含：version、codec、u、h、channel mode、class phase、KDF id、保留位。
- 这样 `channel_mode`、`class_phase`、KDF 升级都能一次解决，不必每次都改格式。
- 容量代价是 32 个槽位，可忽略。
- 必须保证 v2 的 header 定位仍只用 legacy 参数；否则又回到鸡生蛋。

### 5.5 `RgbSpread` 本身要先验证收益

- HILL 代价图是**亮度**（`0.299R + 0.587G + 0.114B`，`hill.rs:53-58`）；三个通道的 base cost 相同。
- STC 按代价选槽，扩散后**总改动量不变**。
- 对逐通道检测器，密度降 1/3；对联合 color-SRM/聚合检测器，信号基本不变。
- 收益主要是“破除绿色单通道先验”，属于**反工具指纹**，不是一般意义上的抗统计检测。
- 建议先做 color-SRM 对照实验，再决定是否投入 1.0～1.5 人日；在路线图中降到 P2。

### 5.6 alpha/灰度细节

- RGBA 的 alpha 不能改（会改变透明度）；候选只取 R/G/B，但索引要按 `channels=4` 处理。
- 灰度图（channels=1/2）没有三通道，需要优雅降级为单通道。
- plan §3.3 的“候选槽扩展为 3×W×H”需要明确“只对 RGB 三色平面，alpha 排除”。

---

## 6. P1-1：`stego_domain` 按文档写法会破坏默认兼容

### 6.1 五个旧标签（E1）

`stego/envelope.rs` 中现有标签：

| 用途 | 标签 |
|---|---|
| AEAD key | `strhide-stego-enc-v1` |
| body perm seed | `strhide-stego-perm-v1` |
| header seed salt | `strhide-stego-hpos-salt-v2` |
| header seed info | `strhide-stego-hpos-v2` |
| STC trellis | `strhide-stc-trellis-v1` |

它们的后缀版本并不统一（`enc-v1`、`perm-v1`、`hpos-salt-v2`、`hpos-v2`、`trellis-v1`）。plan §3.1 的示例：

```rust
pub fn domain(&self) -> &[u8] {
    self.stego_domain.as_deref().unwrap_or(b"strhide-stego-v2")
}
// 然后用 format!("{}-enc-v1", domain)
```

默认会得到 `strhide-stego-v2-enc-v1`，与旧的 `strhide-stego-enc-v1` 不同。**一个前缀无法还原全部旧标签**，因此“None = 官方默认域、100% 互通”和示例代码是矛盾的。

### 6.2 更优做法：domain 作为 HKDF 子密钥

```text
subkey = HKDF-SHA256(
    ikm  = pbkdf2_key,
    info = "strhide-stego-domain-v1" || len_be(domain) || NFC(domain)
)
```

- `None` 分支完全走旧逻辑，五个标签一字不改；
- `Some(domain)` 只替换 IKM，标签仍用旧的五个；
- 避免字符串拼接歧义（`"ab"+"c"` vs `"a"+"bc"`）；
- 可以做 golden vector：默认输出与改前逐字节一致。

### 6.3 还需要补的工程点

- **NFC 归一化**：今天刚为密码修了 NFC，domain 同样要归一化；否则 macOS NFD 与 Windows NFC 会得到不同子密钥。
- **长度前缀**：避免拼接歧义。
- **空 domain = None**：与 `secret()` 的空串语义一致。
- **`is_official()` 更新**：`StegoProfile::is_official()` 目前只看 `secret()`（`params.rs:254`）；加入 domain 后必须同时要求 `domain().is_none()`，否则“只设了 domain”的 profile 会被误判为官方。`Profile::is_official()` 也依赖这个。
- **`Profile::with_stego_domain` 糖方法**：plan §4 的兼容矩阵写了 `Profile.with_stego_domain(...)`，但 §3.1 没有提供这个方法；要么补，要么改矩阵。
- **CLI/config 管线**：`--stego-domain`、`STRHIDE_STEGO_DOMAIN`、`FileConfig.stego_domain`、`KNOWN_KEYS`、`resolve_stego_secret` 的返回值结构（现在只返回 `Option<String>`，需要同时返回 domain）、两个 clap args 结构体、帮助文本、i18n。plan 的 0.5 人日明显偏乐观。
- **测试**：
  - 默认路径 golden vector（逐字节）；
  - 同密码不同 domain → `NoHiddenData`；
  - 同 domain → 成功；
  - 空 domain = None；
  - NFC/NFD domain → 相同结果；
  - 长度前缀碰撞（`"ab"+"c"` vs `"a"+"bc"`）。
- **测试措辞**：plan §6 的“头部物理像素索引完全不同”是概率断言（256 个槽位仍可能碰撞），应改为“header seed 不同 + 交叉提取恒定 `NoHiddenData`”。

### 6.4 威胁模型要写清楚

- domain 是**密钥域隔离**，不是抗统计检测；
- 对只有图片的攻击者，domain 不改变任何像素统计；
- 对拥有二进制但不知道配置的攻击者，domain 是一个低熵口令，可能被字典枚举；
- 对拥有配置的攻击者，domain 不提供保护。
- 因此不要把 domain 列为“防指纹”的主要手段；真正的“防指纹”是 secret + 结构/编码器归一化。

---

## 7. P1-2：`safety_level` 的容量口径与 `RgbSpread` 冲突

### 7.1 问题（E1）

plan 用：

\[
r = \frac{\text{available\_slots}}{\text{needed\_bits}}
\]

做推荐容量。`recommended_payload_bytes` 也是按 `available_body_slots / 4.5 / 8 - BODY_OVERHEAD` 计算（`coding.rs:86-102`）。

一旦 `RgbSpread` 把候选槽从 \(N\) 变成 \(3N\)：

- 同样的 `r=4.5`，推荐载荷变成 3 倍；
- bpp（payload bits per pixel）也变成 3 倍；
- 抗检性反而下降。

这不是理论问题：`recommended_payload_bytes` 直接吃 `available_body_slots`，三通道会让它线性放大。

### 7.2 r 不是跨格式可比的安全量

- PNG：slots 是绿色像素（排除 30% 平滑区后约 0.7N）；
- JPEG：slots 是 |AC|≥2 的 DCT 系数；
- 同一 \(r\) 在 PNG 和 JPEG 上对应的 bpp、改动密度不同。
- memo 把 \(r\) 当作通用安全旋钮，不成立。

### 7.3 4.5 是边界，不是余量

报告自己在 \(r=4.67\)（0.50 载荷）时给出 PNG u3 3.8%、JPEG u3 7.5% 的风险跳变；在 \(r=9.35\)（0.25 载荷）才是 0%～1.3%。把 recommended 放在 \(r=4.5\) 等于把默认值放在边界上。

建议三档，并用 bpp 作为主预算、r 作为 codec 适配的次级约束：

| 档位 | bpp 目标（PNG 绿通道） | 近似 r | 说明 |
|---|---:|---:|---|
| Balanced | ≤ 0.15 | 4.5 | 边界，不建议作为默认“安全” |
| High | ≤ 0.10 | 6.75 | 建议作为默认 recommended |
| Paranoid | ≤ 0.06～0.08 | 9 | 保守场景 |

JPEG 需要另一套 bpp 目标，不能直接复用 PNG 的。

### 7.4 其他问题

- `capacity_divisor = 0.5` 与正文“30%～50%”不一致；统一成一个明确值。
- `UltraStealth` 只减半不会“致盲”：见 P0-2，9σ → 约 4.5σ。
- **强制拒绝**会破坏现有脚本：现在 `recommended_max_bytes` 只是建议；默认应只警告/报告，`Enforce` 作为显式策略，或放到 0.6 breaking change 并给迁移说明。
- **codec 约束**：用户显式选 `Hamming` 时改动率 0.29；UltraStealth 的容量减半不能把它变成 u=3。safety level 必须同时约束 codec，或明确声明“只限容量，不保证改动率”。
- **提取端忽略 safety_level**：它是写侧策略；加测试防止未来误用。
- **推荐值的 codec 假设**：`recommended_max_bytes` 目前隐含 u=3。对 Hamming，r=4.5 对应 0.29 flips/bit，不是 0.23；输出里应同时标注 codec 假设，避免用户误读。
- **Auto 的 max 与 recommended 口径不同**：`max_raw_payload_bytes` 在 Auto 下按 u=1 报，`recommended` 按 u=3 算；输出应明确标注，否则用户会以为两者同一编码策略。

---

## 8. P1-3：API 收敛与 CLI 仍自相矛盾

### 8.1 `StegoOptions` 示例（E1）

plan §3.4 的示例仍保留：

```rust
pub algorithm: Option<String>,
pub stc_h: u8,
```

但正文说“低层数学参数下沉”。`stc_h` 已经在 header 中自描述（`header.rs` 的 4 bit h），完全没必要暴露；`algorithm: Option<String>` 是 stringly-typed，建议改 enum（`Auto | Hill | Uerd`）。

### 8.2 删除字段是 source-breaking（E1）

`StegoOptions.spatial_params`、`jpeg_params` 是公开字段（`stego/params.rs:278-287`）。直接删除会破坏所有库使用者。当前版本 0.5.0（`Cargo.toml:3`），需要：

- 要么保留一个 minor 的 `#[doc(hidden)]` 兼容层 + deprecation；
- 要么明确 0.6 breaking，并给迁移指南；
- plan §4 只写了 wire 兼容，没有写 source 兼容，需要拆开。

### 8.3 CLI 仍暴露全部数学参数（E1）

`cli.rs:335-470` 仍有：

```
--p1-window
--p2-window
--neighbor-weight
--min-abs-coeff
--stc-h
--stc-u
--exclusion-rate
```

这与“下沉”目标矛盾。要么删除，要么改成语义档位（如 `--texture-selectivity low|medium|high`）。`--stc-h` 尤其不应出现在普通 UI。

### 8.4 `exclusion_percentile` 是读写对称参数（E1）

`extract_spatial` 也用 `params.exclusion_percentile` 重算候选集（`spatial/engine.rs:687-707`）。它不是纯写侧；如果用户只在 embed 改、extract 不改，就会失败。plan 把它下沉为内部常量可以，但必须：

- 删除/废弃 `--exclusion-rate`，或
- 在帮助里明确“embed/extract 必须一致”，并把它归入 F 类（若可配）。

### 8.5 命名冲突（E1）

`Profile::domain()` 已存在（UBE stealth domain，`params.rs:354`）。再加 `StegoProfile::domain()` 会混淆。建议：

- `StegoProfile::stego_domain()` / `with_stego_domain()`；
- 文档中明确它和 `Profile::domain()` 是两棵独立的 KDF 树。

### 8.6 `is_official()` 必须更新（E1）

见 §6.3；加 domain 字段后，`StegoProfile::is_official()` 需要同时检查 secret 和 domain，否则“只设 domain”会被当作官方。

---

## 9. P1-4：结构/编码器指纹与 KDF 弱项

### 9.1 结构层不是“0 风险”

memo §3.1 写“内容域完全抛弃结构注入，结构层检测为 0 风险”。这不严谨：

- 本样本 0001.png 的原始 zlib 头是 `0x789C`（FLEVEL=2），IDAT 为 85 个 65,536 B 分块；重编码后 FLEVEL 和分块数保持一致，结构差异确实很小。
- 但 `encode_png` 固定用 `Compression::default()`（level 6，`spatial/engine.rs:320`）。如果源图来自 level 9、zopfli 或优化器，重编码会产生 FLEVEL/块结构差异。
- 文件大小仍会增长约 1.0%（45 KiB 载荷：5,558,833 → 5,614,337 B），这是嵌入本身的必然结果，但在“原图 vs 重编码”分类器里可能是一个弱特征。
- JPEG 侧还要看 DHT/APP 段是否重写；本次未测。

建议：把“结构层 0 风险”改为“本样本结构差异很小；需对 level 9/zopfli/JPEG 优化器来源做语料级验证”。真正的“防指纹”工作应包括：

- 估计并匹配原图 zlib FLEVEL；
- 保持 IDAT 分块与 filter 策略；
- JPEG 保持原始 DHT/量化表/APP 段；
- 做“原图 vs strhide 输出”的结构分类实验。

### 9.2 PBKDF2 100k 偏弱

`stego/envelope.rs:69` 使用 PBKDF2-HMAC-SHA256 100,000 次。按 2026 年的离线攻击成本，这偏弱；OWASP 对 PBKDF2-HMAC-SHA256 的建议是 600,000 次，或 Argon2id。

这比 domain 隔离更影响真实保密性：domain 只做域分离，不增加暴力破解成本。建议：

- v2 header 增加 KDF id；
- 新文件默认 Argon2id（或至少 600k PBKDF2）；
- 保留旧 KDF 读取；
- 注意：KDF id 不得影响 header 定位（F 类原则），否则旧读端无法找到 header。

---

## 10. P2：事实性、统计与用户可见问题

### 10.1 事实性

| 文档表述 | 问题 | 建议 |
|---|---|---|
| “HILL/UERD 是李斌与 Fridrich 等学者的最优解” | HILL 是 Li et al.；UERD 是 Guo et al.；Fridrich 是 SRM/UNIWARD 方向 | 补准确引用 |
| “八值类掩码是论文最优配置” | `0xF8`、`[8,247]` 是项目自研不变式，不是论文结论 | 改成“项目为代价图可复现性引入的不变式” |
| “与 0.3.x / 0.4.0 完全一致” | 当前 0.5.0；`CHANGES-20261020.md:12` 明确 0.4.0 PNG stego 本版提不出 | 拆成 wire / 读旧 / 写新三行 |
| “JPEG u=3 改动率 0.22” | 报告实测 0.24～0.25 | 改为“0.24～0.25（JPEG）” |
| “卡方检出率直接失效” | 不是 chi2 失效，是 chi2/RS/SPA 的前提假设与本方案不匹配 | 改为“前提失配，因此无检验力” |
| “结构层 0 风险” | 本样本很小，但不是普遍保证 | 改为“低风险，需语料级验证” |

### 10.2 统计与采样

- `analysis.rs:817-825` 把像素截到前 4,000,000 字节：
  - 1920×1280 RGB 只覆盖前约 54% 行；
  - RGBA 只覆盖前约 41% 行；
  - chi2 是 RGB 交错混合，不是逐通道。
- 建议全图统计或分块/等距抽样；chi2 至少按通道分别算。
- “风险跳变率”需要定义：基线、阈值、聚合方式、是否图像级。
- 4,480 点按 80 张图做图像级 bootstrap，不要按点算 CI。
- 报告中的“0.0% 完全隐形”应改为“在本检测器、本语料、本载荷下未触发”；这不是普遍隐形。

### 10.3 用户可见 bug（顺带）

1. `strhide embed --capacity` 输出里 `{kib:.1}`、`{rate:.3}` 原样打印：`format_msg` 只按 key 查找，不支持 format spec（`i18n/mod.rs:130-134`），而 `messages.rs:629-701` 用了 `:.1`。
2. `messages.rs:700` 仍写“recommended max is half of max”，与 `r=4.5` 公式不一致。
3. `--exclusion-rate` 的中英文帮助默认值不一致（一处 0.20，一处 0.30/0.20）。

---

## 11. 更优的实施路线

### P0（先做，约 1～2 周）

1. **独立评测**
   - SRM+FLD（或 scheme-aware 类边界估计器 + 双边 chi2 + 逐通道）；
   - 全图统计，图像级 CI；
   - 把 `scan` 降级为自检，不再作为验收标准。

2. **修类边界指纹**
   - 排除 `r∈{0,7}`，全语料复测容量与检测强度；
   - 目标：\(\delta_0\) 降到噪声级；
   - 记录容量损失（约 25%）：推荐载荷 46,454 B → 约 34,835 B；45 KiB 仍可嵌入，但 `Auto` 会从 `u=3` 降到 `u=2`，改动率升到约 0.26。

3. **v2 header**
   - 用 `h=15` 转义 + feature word；
   - 确保 F 类不影响 header 定位；
   - 为 channel mode / class phase / KDF id 预留字段。

### P1（约 1～2 周）

4. **容量策略**
   - 改为 bpp/改动密度预算；
   - 三档：Balanced 0.15、High 0.10、Paranoid 0.06～0.08；
   - 默认 recommended 从 4.5 提到约 6.75；
   - `Enforce` 显式化；safety 同时约束 codec；extract 忽略。

5. **domain 子密钥化**
   - 保留旧标签；NFC；长度前缀；golden vector；
   - 补 CLI/config/env 与 `is_official()`。

6. **KDF 升级**
   - Argon2id 或 600k PBKDF2；KDF id 写入 v2 header；
   - 保留旧 KDF 读取。

7. **结构/编码器归一化**
   - 匹配 zlib FLEVEL、IDAT 分块、JPEG DHT/APP；
   - 做“原图 vs 重编码”分类实验。

### P2（可选）

8. **`RgbSpread`**
   - 先做 color-SRM 对照；
   - 收益不明确就砍掉；
   - 若做：header 固定 GreenOnly + v2 记录 mode；alpha 排除；预算按 bpp。

9. **API 收敛**
   - deprecation + 语义档位；
   - 不在 0.5.x 直接删字段；
   - 隐藏 `stc_h`/`algorithm`。

---

## 12. 对两份文档的具体修改清单

### memo

- [ ] §1.1 / §1.3：把“87.5% → <7.5%”标注为“自家 `scan` 分数跳变率，不是 SRM/SRNet \(P_E\)”。
- [ ] §3.1：把“结构层检测为 0 风险”改为“低风险，需语料级验证”；补编码器/FLEVEL/分块指纹。
- [ ] §3.2：把“卡方检出率直接失效”改为“chi2/RS/SPA 前提失配，对本方案无检验力”。
- [ ] §3.2/§4.1：补充 `0xF8` 类边界单向移动的机制、实测和修复选项。
- [ ] §4.2：把“绝不可动”改为“可复现性基石，但有可检测代价”；`0xF8` 不再称为论文最优。
- [ ] §4.1 ④：`RgbSpread` 的“信号降为 1/3”改为“逐通道密度降 1/3；联合检测器信号基本不变，待实验”。
- [ ] §1.2：HILL/UERD 的论文归属修正；补引用。
- [ ] §5：把“私有 secret/domain”与“抗统计检测”分开写；domain 只解决定向提取隔离。

### plan

- [ ] §2.1：增加 F 类；把 `channel_mode` 从 P 类移到 F 类。
- [ ] §3.1：domain 改为 HKDF 子密钥；保留旧标签；补 NFC、长度前缀、golden vector；补 `Profile::with_stego_domain` 与 `is_official()`。
- [ ] §3.2：safety 改为 bpp/改动密度三档；4.5 不作为默认；Enforce 显式；约束 codec。
- [ ] §3.3：先做 color-SRM 实验；若做，header 固定 GreenOnly + v2 记录 mode；alpha 排除；预算按 bpp。
- [ ] §3.4：保留一个 minor 的 deprecation；隐藏 `stc_h`/`algorithm`；删除或语义化 CLI 数学参数。
- [ ] §4：拆成 wire / source / 读旧 / 写新；修正 0.3.x/0.4.0；补 golden vector。
- [ ] §5：Phase 顺序改为“评测/类边界/header → 容量/domain/KDF → encoder → channel”。
- [ ] §6：验收加入“独立检测器”“类边界赤字”“golden vector”“图像级 CI”；删除“scan 0 CLEAN”作为唯一标准。

---

## 13. 附录：关键代码位置

| 事实 | 位置 |
|---|---|
| 绿色单通道写死 | `stego/spatial/engine.rs:499-500` |
| `[8,247]` 与 `0xF8` 类内约束 | `spatial/engine.rs:502-517`、`coding.rs:346-390` |
| 类底/类顶单向移动 | `coding.rs:366-390` |
| 30% 平滑区排除（embed/extract） | `spatial/engine.rs:526-534`、`687-707` |
| header 32 字节与 256 槽位 | `spatial/engine.rs:586-600` |
| header 位布局 | `stego/header.rs:15-45` |
| `recommended_payload_bytes` | `stego/coding.rs:86-102` |
| Auto codec 阈值 | `stego/coding.rs:108-124` |
| KDF 标签 | `stego/envelope.rs:75-111` |
| PBKDF2 100k | `stego/envelope.rs:69` |
| `StegoProfile` / `is_official` | `params.rs:228-260` |
| `Profile::domain` | `params.rs:354` |
| `StegoOptions` 公开字段 | `stego/params.rs:278-287` |
| `scan` 内容检测器 | `analysis.rs:817-855` |
| 单边 chi2 | `analysis.rs:860-880` |
| 4 MB 采样截断 | `analysis.rs:817-825` |
| CLI 数学参数 | `cli.rs:335-470` |
| i18n format spec bug | `i18n/mod.rs:130-134` |
| 版本 0.5.0 | `Cargo.toml:3` |
| 0.4.0 PNG 不兼容记录 | `docs/CHANGES-20261020.md:12` |

---

## 14. 最终建议

- **不要**按 plan 当前顺序（domain → API → channel）直接实施。domain 是低风险但低抗检收益；channel 是高成本且收益未验证；二者都没有触及最严重的类边界指纹。
- **先做** P0-1/P0-2/P0-3：独立评测、类边界修复、v2 header。完成后再决定 safety/domain/channel 的具体形态。
- memo 的定位应从“分析底稿/结论”改为“机制资料 + 待验证假设”；所有定量结论加证据等级和复现链接。
- 如果只能做一件事：**先量化并修复 `0xF8` 类边界指纹**。它不依赖新 API、不需要 domain、不需要三通道，却直接决定“推荐容量下是否可被 scheme-aware 检测器稳定估计嵌入率”。

---

> **附**：本次实测脚本与输出位于 `temp/stego_probe/`（`analyze.py`、`s045.png`、`s100.png`、`s188.png` 等），未纳入版本控制；生产代码与两份原文档均未修改。
