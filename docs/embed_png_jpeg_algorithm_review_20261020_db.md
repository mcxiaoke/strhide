# embed 对 PNG / JPEG 的算法现状、优缺点、改进方案与业界对比

> **编制时间**：2026-10-20 22:00:07（`db` 版）
> **核对对象**：`rust/src/stego/`（`strhide 0.4.0`，commit `55637b1`）
> **核对方式**：逐文件读源码（含依赖 `dct-io 0.1.1` 源码）+ 项目已有实测文档 `docs/stego_keyed_parameters_plan_20261020.md` 与
> `docs/embed_png_jpeg_algorithm_review_20261020-215214.md`（下称"前序报告"）中的单样本数据。
> **定位**：只讨论 `strhide embed` / `extract` 的**内容域隐写**，不涉及 `write` / `restore` 的结构域隐藏。
> **与前序报告的关系**：本版补全了"算法代际定位 / 编码层差距 / STC 落地方案 / 最新生成式方向"，并对
> UERD 块网格的块顺序做了源码级**勘误**（见 §6.2）。前序报告的单样本实测数据原样保留。

---

## 1. 结论先行（TL;DR）

1. **`embed` 不是"完整的 HILL/UERD"，而是"现代代价函数 + 简化编码层"的组合：**
   - PNG：**HILL 代价图（2014）→ 密钥化选槽 → `(7,3)` 汉明矩阵码 → 像素 LSB 替换**，只嵌绿通道。
   - JPEG：**UERD 代价图（2015）→ 密钥化选槽 → `(7,3)` 汉明矩阵码 → 幅度对内 LSB 替换**，只改亮度 Y 的 `|c|≥2` AC。
   - 学界 HILL/UERD 通常默认搭配 **STC（综合征网格码，Filler 2011）+ ±1（三进制）修改**。本项目只移植了"往哪里改"（代价图），"怎么改、改多少"（编码层）用的是更老的汉明码 + 二进制替换。

2. **代际定位**：代价函数停在 **2014–2015 主流一代**（只落后小半代，MiPOD/J-UNIWARD 更强）；真正落后学界 SOTA **一整代**的是
   **编码层（汉明 → STC）** 和 **写入门控（LSB 替换 → ±1/三进制）**，外加**非加性/多通道/湿代价**完全未做。

3. **两个工程/正确性缺陷（应先修）：**
   - **PNG 重编码不保留辅助块且固定 filter 0**：`encode_png` 只写 IHDR/IDAT/IEND，丢失 iCCP/gAMA/sRGB/pHYs/tEXt/eXIf/bKGD 等，
     且全用 filter 0 导致 IDAT 体积明显变大（前序报告实测一张 960×960 RGBA 藏 5 字节后 **+23.1%**、chunk 数 45→3）。
   - **JPEG UERD 的 8 邻域块网格用 `ceil(sqrt(块数))` 估算**：只在方形图上碰巧正确，非方形图（如 1920×1080）邻域能量错位；
     量化表还写死 Annex K，未用文件自带 DQT。不影响往返（两端对称），但降低自适应质量。

4. **当前抗检靠"低载荷率"，不是编码安全性**：写入门控仍是 LSB 替换，汉明只把改动数降 42%（0.5 → 0.2917 次/bit），
   不消除"成对翻转/偶奇均衡"的统计痕迹。前序报告实测：满容量 PNG `scan` 50/100、JPEG 85/100；半容量 PNG 0/100、JPEG 25/100。
   项目自带 `scan` 仅 χ²/SPA/RS + 校准，**没有 SRM/GFR/CNN 这类现代盲检**，clean 不构成"无隐藏"证据。

5. **最该做的两件事：**
   - 先做 **P0 缺陷修复**（PNG 透传辅助块/保留滤波、UERD 真实几何+真实 DQT、头部进矩阵编码）——不改协议、风险低、收益直接。
   - 再做 **STC + 三进制 ±1** 这一代际升级——这是抗盲检收益最大、但工程量也最大的一步，且 **±1 有前置依赖**（见 §9.2）。

---

## 2. 范围：两条信道不要混

| 命令 | 作用域 | 是否可逆 | PNG | JPEG |
|---|---|---|---|---|
| `write` / `restore` | 结构域 | **100% 可逆** | `prIv` 私有 chunk（或 EOF） | APP15/COM 段链（或 EOF） |
| `embed` / `extract` | 内容域 | **不可逆**（改像素/系数） | 改像素 LSB | 改量化 DCT 系数 LSB |

本文只讨论第二行。需要"藏了还能字节级还原原文件"的场景应使用 `write`；`embed` 只保证视觉无损与统计隐蔽。

---

## 3. 共用框架（PNG / JPEG 对称的部分）

读代码：`rust/src/stego/{mod.rs, envelope.rs, coding.rs, prng.rs, params.rs, registry.rs}`。

### 3.1 信封与加密（`envelope.rs`）

- 载荷先 Deflate（仅当压缩后更小才启用）；明文布局 `[4B 原始长度][1B flags][payload]`。
- 加密：**AES-256-GCM**，密钥经 **PBKDF2-HMAC-SHA256（100 000 次）+ HKDF-SHA256** 派生；salt/nonce 同时作 AAD。
- 输出：`[16B salt][12B nonce][ciphertext][16B GCM tag]`；最小信封约 49B，正文固定开销 21B（4+1+16）。
- **无密码时使用源码公开常量 `PUBLIC_DEFAULT_SECRET`**：任何官方二进制都能提取无密码信封——这是产品事实，不是"免密加密"。
- 无 magic、无明文标记；错误密码统一报 `No valid payload found`，降低区分性 oracle。

### 3.2 槽位布局（密钥化）

- **头部固定 256 槽**：对候选集做密钥化全置换（种子由口令派生，不含 salt，解决"salt 在头部里"的鸡生蛋问题），取前 256。
  头部写 32B 明文（salt+nonce+长度），**直接 LSB 替换，不做矩阵编码**。
- **正文**：从候选集去掉头部 256 槽，取代价最低的 `needed_body_slots` 个，再用 salt 派生种子做一次置换；之后用汉明码嵌入。

### 3.3 编码层（`coding.rs`）

- `(7,3)` 汉明综合症码：每 **7 个槽载 3 bit，至多改 1 槽**；块尾不足 7 个时退化为 1:1 LSB。
- 平均改动率 `(7/8)/3 = 0.2917` 次/bit，项目实测 0.2903–0.2913；相对直接 LSB 的 0.5，**少改约 42%**。
- 嵌入效率约 **3.43 bits/change**（直接 LSB 为 2）。
- 这是**固定分块、非全局最优**：块边界与代价无关，块尾 1:1 浪费容量；没有湿通道/湿纸码能力。

---

## 4. PNG：HILL + 单通道 + 汉明 + LSB 替换

读代码：`rust/src/stego/spatial/engine.rs`、`rust/src/stego/spatial/cost/hill.rs`。

### 4.1 嵌入流程

1. **自写 PNG 解码器**：仅 8-bit、非隔行（拒 Adam7）、灰度/RGB/灰度α/RGBA；拒调色板、APNG。解码时只取 IHDR/IDAT，其余 chunk 直接丢弃。
2. **HILL 代价图**：先对像素 `& 0xFE` 屏蔽 LSB（保证嵌入/提取重算代价图逐位一致）→
   KB 3×3 高通取绝对值 → `p1×p1`（默认 3）盒均值取倒数 → `p2×p2`（默认 15）可分离均值低通。
3. **候选集**：只取**绿通道 G**（灰度取通道 0）；像素值限 `[2,253]`（避开 0/255 饱和）；按代价升序，**剔除最平滑 30%**。
4. **头部**：256 槽密钥化全置换，直接 LSB 替换写 32B。
5. **正文**：最低代价 N 槽 + salt 置换 + `(7,3)` 汉明；写入规则 `val & 0xFE | bit`，即 **LSB 替换**。
6. **重编码**：只写 IHDR/IDAT/IEND，每行固定 filter 0（None），zlib `Compression::default()`。

### 4.2 前序报告单样本实测（样本 `temp/teststego/DC912sk1.png`，960×960 RGBA，1 345 052 B）

| 项目 | 结果 |
|---|---|
| 报告最大载荷 / 推荐载荷 | 34 505 B（33.7 KiB）/ 17 252 B（1/2） |
| 接近满容量嵌入 | 33 000 B |
| PSNR（RGB） / 最大像素差 | **63.67 dB** / 1 |
| 改动像素 | 77 251 / 921 600 = **8.38%** |
| 满容量 `scan` | **50/100 SUSPICIOUS**（RS≈0.07，SPA≈0.11） |
| 半容量 `scan` | **0/100 CLEAN** |
| 藏 5B 后文件体积 | 1 656 621 B（**+23.1%**），chunk 数 45→3，bKGD 丢失 |

### 4.3 优点

- 真正的内容自适应：改动集中在纹理/噪声区，视觉无损（63.7 dB、max_delta=1）；HILL 计算便宜（约 76 ms/百万像素级）。
- 代价图对 LSB 屏蔽，嵌入/提取槽位排序可逐位复现；密钥化置乱使头部位置不可公开推导。
- 汉明降改动 42%；排除饱和/平滑区，工程稳妥；AEAD 信封、容量探测、批量回归齐备。

### 4.4 缺点

1. **LSB 替换正是 χ²/SPA/RS 的目标**：汉明只减少改动数，不改变"成对翻转"；高载荷显形（实测 50/100）。
2. **重编码破坏格式一致性（与"格式保持"定位冲突）**：丢辅助块（ICC/DPI/文本/EXIF）、固定 filter 0、默认压缩级别，体积常增大。
3. **单通道**：只用 G，容量约为三通道的 1/3。
4. **无 STC / 非对称代价（ρ+1/ρ−1）/ 湿纸码**：`SpatialParams::wet_cost` 在 PNG 侧实际未接线。
5. **贪心 + 固定分块汉明**：非全局最小失真，块尾 1:1 浪费容量。
6. **参数不落信封**：改 `--p1-window/--exclusion-rate` 后提取端必须手动对齐，否则静默失败。
7. 头部固定 256 槽无 ECC，小图收益敏感；仅支持 8-bit，覆盖面窄。

---

## 5. JPEG：UERD + Y 分量 + 汉明 + 幅度对内替换

读代码：`rust/src/stego/jpeg/engine.rs`、`rust/src/stego/jpeg/cost/uerd.rs`；系数读写 `dct-io 0.1.1`。

### 5.1 嵌入流程

1. **系数读取**：`dct_io::read_coefficients` 直接解析 baseline JPEG 量化 DCT 系数；**不做 IDCT/DCT，零生成损失**；拒 progressive（SOF2）。
2. **UERD 代价图**：仅 Y（`components[0]`）；块能量 `E_b = Σ_{k=1..63}(|c_k| & !1)·Q[k]`；8 邻域平滑（权重 0.25）；
   系数代价 `ρ = Q[k] / 平滑后块能量`。`Q[k]` 用**内置 Annex K 标准亮度表**，非文件自带 DQT。
3. **候选集**：仅 AC（k=1..63）、**`|c| ≥ 2`**（`min_abs.max(2)`）、`cost < wet_cost`；剔除能量最低 **20%** 块。
4. **头部/正文**：与 PNG 完全对称（256 槽裸 LSB；正文汉明）。
5. **写入**：仅在同一幅度对内翻转（2↔3、4↔5、−2↔−3…），绝不碰 0/1，故不改变零游程、不跨 Huffman 幅度类别；
   用原 Huffman 表重写，文件大小基本不变，EXIF/JFIF/量化表/哈夫曼表保留。

### 5.2 前序报告单样本实测（样本 `temp/teststego/chenleicover_4.jpg`，500×500 RGB，69 067 B）

| 项目 | 结果 |
|---|---|
| 报告最大载荷 / 推荐载荷 | 1 316 B（1.3 KiB）/ 658 B（1/2） |
| 接近满容量嵌入 | 1 250 B |
| PSNR（RGB） / 最大像素差 | **52.42 dB** / 11 |
| 改动像素（解码后） | 39 080 / 250 000 = **15.63%**；约改 ~2 900 个系数 |
| 满容量 `scan` | **85/100 LIKELY-HIDDEN**（校准 DCT≈19%） |
| 半容量 `scan` | **25/100 LOW** |
| 藏 5B 后文件体积 | 69 068 B（+1 B）；段结构、EXIF/JFIF 完全保留 |

### 5.3 优点

- 系数域直接改写、零重压缩、零生成损失；段结构与文件大小几乎不变，元数据/哈夫曼表保留。
- 只改 `|c|≥2` 非零 AC，正确规避 F5 shrinkage、零游程与 Huffman 类别破坏；UERD 轻量，适合批量。
- 与 PNG 共享汉明、密钥化槽位、AEAD 信封。

### 5.4 缺点

1. **UERD 块几何用 `ceil(sqrt(总块数))` 估算网格宽**：非方形图（如 1920×1080，Y 块 240×135=32 400，sqrt≈180）会把不相邻块当邻居，
   8 邻域能量扩散失真。正确网格宽应为 **`ceil(width/8)`**（见 §6 勘误）。
2. **量化表写死 Annex K**：文件用自定义 DQT 时 `Q[k]` 权重不匹配（校准模块才读真实 DQT，未回喂代价图）。
3. **偶奇配对翻转**：`|c|≥2` 对内翻转使 DCT 直方图偶奇趋于均衡，正是校准式 χ²/Fridrich 校准攻击目标；满容量 85/100，quality-100 不适用。
4. **只用 Y**：Cb/Cr 未用；**只用 `|c|≥2`**：丢弃大量 `|c|=1` AC，容量受限。
5. 无 STC / 三进制 / 非对称代价 / 非加性；头部 256 槽裸替换；仅 baseline；参数不落信封。

---

## 6. 源码勘误：UERD 块顺序到底是什么

前序报告 §4.5 称"`dct-io` 返回 MCU 交错顺序，4:2:0 每个 MCU 有 2×2 个 Y 块，块数组不是行优先栅格"。
经核对 `dct-io 0.1.1` 源码（`decode_coefficients`，约 1019–1090 行），**该表述不准确**，修正如下：

- 解码按 `for mcu_idx in 0..n_mcu`（MCU 行优先）外层、按 component 内层遍历；**每个 component 单独维护一个 `blocks` Vec 顺序追加**
  （`comp_blocks[comp_idx][block_idx] = block`，索引单调递增）。
- 因此跨 component 是分离的，而**单个 component 内的 `blocks` 就是该分量的标准光栅序**：
  4:2:0 下每个 MCU 内 Y 的 4 个数据单元按标准"左→右、上→下"追加，MCU 行扫描拼接后等价于 Y 分量
  `ceil(width/8) × ceil(height/8)` 的行优先栅格。这与库文档"in raster scan order (left-to-right, top-to-bottom)"一致。
- 结论：**Y 块网格宽恒为 `ceil(width/8)`、高为 `ceil(height/8)`，与采样因子无关**；可由 `dct_io::inspect()` 的
  `width/height`（或 `h_samp/v_samp` 与 MCU 列数）直接算出。当前 `sqrt(块数)` 仅在**方形图**上碰巧正确，
  非方形图错位。修复时无需做 MCU 反交错，只需把网格宽从 `sqrt(total)` 改为 `ceil(width/8)`，但需把几何信息传入 `compute_cost`（当前签名只有 `coeffs/params`）。

---

## 7. 共性优点与共性缺点

**共性优点**：代价模型与引擎解耦（`SpatialCostModel`/`JpegCostModel` trait）便于扩展；代价图对 LSB 屏蔽保证可复现；
密钥化头/正文置换；AEAD 无 magic 信封；有独立容量探测与推荐值（最大/2）；`batch_stego` 真实语料回归。

**共性缺点**：
- 不是完整最小失真框架：无 STC、无非对称代价、无湿纸码；汉明固定分块，块边界与代价无关。
- 写入门控是 LSB 替换，高载荷统计痕迹明显；头部固定 256 槽无 ECC；参数不落信封（不一致即静默失败）。
- **注册表别名误导**：`"wow"` 实际返回 HILL、`"nsf5"` 实际返回 UERD（`registry.rs`），库调用方会误以为选到对应算法。
- **死参数**：`SpatialParams::wet_cost`（PNG 未用）、`JpegParams::mode_dc_weight`（UERD 未用）。
- 无密码模式用公开常量；`embed` 不可逆。

---

## 8. 业界主流与最新算法对比

### 8.1 三条演进谱系（▲ 标 strhide 所处代际）

- **空间域代价模型**：LSB 替换(1990s) → LSB matching ±1(2002) → LSBMR(2006) → HUGO(2010) → WOW(2012)
  → S-UNIWARD(2014) → **▲ HILL(2014)** → MiPOD(2016) → 非加性 MG/HILL-GMR/synch(2017–) → CNN/GAN 学代价(2019–) → 扩散生成式(2023–2026)。
- **JPEG 代价模型**：JSteg/OutGuess(1999–2001) → F5(2001) → MB(2006) → J-UNIWARD(2014，标杆)
  → **▲ UERD(2015)** → J-MiPOD(2016) → GUED/RBV(2019) → 非加性/彩色联合(2020–) → 学习式 → 扩散生成式。
- **编码层（差距最大处）**：直接 LSB → **▲ 汉明/F5 矩阵码(2001–2005)** → 湿纸码 WPC(2005)
  → **STC(2011，Filler，事实标准)** → 多进制/多层/非加性 STC(2013–) → 深度学习联合编码(2019–)。

### 8.2 主流代价模型对比

| 算法 | 域 / 年代 | 核心思想 | 抗盲检 | 计算成本 | 备注 |
|---|---|---|---|---|---|
| HUGO | 空间 2010 | SPAM 特征、4 方向子模型 | 中 | 高 | 已被超越 |
| WOW | 空间 2012 | 方向高通滤波 | 强 | 中高 | 纹理区好 |
| S-UNIWARD | 空间 2014 | Daubechies 小波相对变化 | 很强 | 中高 | 通用、易复现，PNG 首选之一 |
| **HILL** | 空间 2014 | 高通 + 两级低通 | 强（主流） | 低 | **▲ strhide**，简单稳定 |
| MiPOD | 空间 2016 | 多元高斯 + 最小化最优检测器功效 | 很强 | 高 | 常优于 HILL，高安全场景 |
| F5 / OutGuess / MB | JPEG 2001–06 | 矩阵编码 / 统计保持 | 中 | 低 | 汉明综合症来源 |
| J-UNIWARD | JPEG 2014 | 系数扰动映射空域小波相对变化 | 很强 | 高 | JPEG 事实基线 |
| **UERD** | JPEG 2015 | 块能量 + 量化加权 + 邻域平滑 | 强（略逊 J-UNIWARD） | 很低 | **▲ strhide**，最轻量 |
| J-MiPOD / GUED / RBV | JPEG 2016–19 | 统计模型 / 通用 / 残差块方差 | 很强 | 高 | 与 J-UNIWARD 同级或更强 |

### 8.3 编码/修改规则对比

| 方案 | 改动率（次/bit） | 嵌入效率 | 抗盲检 | 复杂度 | 备注 |
|---|---:|---:|---|---|---|
| LSB 替换 | 0.5 | 2 bits/change | 低 | 极低 | χ²/SPA 目标；**▲ strhide 写入门控** |
| LSB matching ±1 | ~0.5 | 2 | 中 | 低 | 直方图自然，需同步 |
| **汉明 (7,3)** | **0.2917** | **3.43** | 中 | 低 | **▲ strhide**；固定分块、非全局最优 |
| 湿纸码 WPC | — | — | — | 中 | 处理禁用位置，常与 STC 组合 |
| **STC** | 接近理论最优 | 随载荷率/约束高逼近 1/α 界（低载荷约 6–9） | 高 | 高 | 事实标准，原生支持湿通道 |
| 非加性/可变代价 STC | 更优 | 更优 | 很高 | 很高 | 配合 synch/Gibbs，处理相邻耦合 |

> HILL/UERD 只回答"往哪里改"；汉明/STC 回答"改多少、怎么改"。strhide 只完整做了前者。

### 8.4 最新方向（2019–2026）与定位差异

| 方向 | 代表 | 容量 | 抗再编码 | 与本项目关系 |
|---|---|---|---|---|
| 端到端 CNN 隐写 | HiDDeN 2018、SteganoGAN 2019、UDH 2022 | 小–中 | 弱–中 | 多为"图藏图"，需训练 |
| 学代价 + STC | ASDL-GAN、SPAR-RL、JEC-RL、UT-GAN | 中 | 依赖 STC | 增益常针对单一检测器，可复现性弱 |
| 生成式/扩散隐写 | CGIS、HIS、Plug-and-Hide、AGM（2024–2025） | 小 | 弱 | 直接生成/潜变量映射，无修改痕迹；依赖模型权重 |
| 鲁棒水印 | StegaStamp、Stable Signature、TrustMark、Gaussian Shading、VideoSeal | 几十–约 1000 bit | 强 | 做版权/溯源，非"藏大文件" |
| 无封面 coverless | 检索映射 / 码本，2024–2025 | 极低 | 很强（不改载体） | 需共享码本，不适合大文件 |

**截至 2026 年，没有出现取代"UNIWARD/MiPOD + STC"体系的通用新范式**；热点集中在检测侧（深度隐写分析、算法识别）、
鲁棒水印与生成式。对"藏几十 KB–MB、原文件传输、精确提取"的需求，**最小失真 + STC 仍是最实用路线**，生成式/水印不替代当前定位。

### 8.5 横向对比（本项目 vs 主流方案）

| 维度 | strhide PNG | strhide JPEG | 主流 PNG（S-UNIWARD/MiPOD+STC） | 主流 JPEG（J-UNIWARD+STC） |
|---|---|---|---|---|
| 代价函数 | HILL | UERD | S-UNIWARD / MiPOD | J-UNIWARD / J-MiPOD |
| 编码 | 贪心+汉明(7,3) | 贪心+汉明(7,3) | STC | STC |
| 修改规则 | LSB 替换 | 幅度对内替换 | ±1 / 三进制 | ±1 / 三进制 |
| 改动率 | 0.2917 | 0.2917 | 接近最优 | 接近最优 |
| 容量 | 中低（单通道） | 低（Y + `|c|≥2`） | 中高（多通道） | 中（Y+Cb/Cr） |
| 低载荷抗检 | 好 | 中 | 更好 | 更好 |
| 高载荷抗检 | 差（50/100） | 差（85/100） | 明显更好 | 明显更好 |
| 格式保持 | **差（丢块/膨胀）** | 好（零生成损失） | 取决于实现 | 取决于实现 |
| 工程成熟度 | 已落地 | 已落地 | 多为研究原型 | 多为研究原型 |

### 8.6 差距矩阵（按维度）

| 维度 | 现状 | SOTA | 差距 |
|---|---|---|---|
| 空间域代价 | HILL 2014 | S-UNIWARD / MiPOD | 小半代 |
| JPEG 代价 | UERD 2015 | J-UNIWARD / J-MiPOD / GUED | 小半代 |
| 写入门控 | 二进制 LSB 替换 | ±1 / 三进制 | **一整代** |
| 编码层 | (7,3) 汉明 | STC / 非加性 STC | **一整代（最大）** |
| 非加性 | 无 | synch / Gibbs / GMRF、ρ±1 | 一整代 |
| 通道 | 单通道（G / Y） | RGB / YCbCr 联合 | 容量与安全 |
| 格式保持 | JPEG 优；PNG 丢块/膨胀 | 透传元数据、保滤波 | PNG 硬伤 |
| 抗检自测 | χ²/SPA/RS + 校准 | SRM/maxSRM、GFR、SRNet/KeNet | 缺现代闭环 |
| 工程化（加密/CLI/可逆/封装） | 强 | 研究原型常无提取 | **领先** |

---

## 9. 改进与优化方案（按优先级）

### 9.1 P0：低风险、不改协议、应先修

| # | 改动 | 具体做法（文件级） | 收益 |
|---|---|---|---|
| P0-1 | **PNG 透传辅助块** | `decode_png` 收集全部非 IDAT chunk 的原始字节（含类型/CRC），重编码时按原顺序回写，仅替换 IDAT；保留 iCCP/gAMA/sRGB/pHYs/tEXt/zTXt/eXIf/bKGD 等 | 不再丢元数据，符合"格式保持" |
| P0-2 | **PNG 保留/恢复滤波** | 解码时记录每行原始 filter type；重编码时沿用原 filter type 重算 filtered 字节（改的是 unfilter 后像素 LSB，结果确定且合法）；或在 5 种 filter 中按最小绝对差选择；zlib 级别对齐原图 | 体积回到原图附近，消除 +23% |
| P0-3 | **UERD 真实几何** | 用 `dct_io::inspect()` 取 width/height，Y 网格宽 = `ceil(width/8)`；扩展 `JpegCostModel::compute_cost` 传入几何（或在 engine 内构造 `(w,h)`） | 非方形图 8 邻域正确 |
| P0-4 | **UERD 用真实 DQT** | 复用/抽取 `analysis/calibration.rs::parse_luma_dqt` 到共用位置，按分量取文件自带量化表 | 自定义质量表代价排序正确 |
| P0-5 | **头部进矩阵/湿纸编码** | 256 槽也走汉明（或更弱重复码），消除"裸替换 + 位置可定位"指纹 | 降低头部固定痕迹 |
| P0-6 | **清理别名/死参数** | 删除或真正实现 `"wow"`/`"nsf5"` 别名；接线或删除 `wet_cost`/`mode_dc_weight` | 消除 API 语义错误 |
| P0-7 | **参数指纹落信封** | 头部/AEAD 明文中加 1B 算法 ID + 量化参数指纹；提取端自动匹配或显式报错 | 杜绝静默失败 |
| P0-8 | 容量报告 | `--capacity` 同时给预计改动率/PSNR/推荐载荷口径 | 可解释性 |

> P0-1/P0-2 建议先备份再改（`temp/backups/`），并为"像素字节往返 + 元数据逐 chunk 一致 + 体积不显著膨胀"加回归。

### 9.2 P1：算法代际升级（抗盲检核心）

#### 9.2.1 上 STC（最高性价比）

- 新增 `rust/src/stego/coding/stc.rs`，实现 Filler et al. 2011 的 Syndrome Trellis Code；约束高 `h` 可配（建议 h=10，可 7–12 权衡）。
- 输入：覆盖图（候选槽顺序）+ 每个槽的 `ρ+1/ρ−1/ρ0`（湿槽置 `ρ=∞`）+ 目标综合症（=消息比特），输出近优改动；提取端用同一个奇偶校验矩阵 `H` 重算综合症即得消息。
- 与现有汉明**共存**：通过算法 ID/参数开关选择，便于灰度与回滚；容量模型需按 STC 重算（payload-limited 给定消息求改动，或 distortion-limited 给定预算求容量）。
- 收益：同载荷改动数显著下降、嵌入效率逼近理论界、原生支持湿通道（天然允许把 `|c|=1`、饱和像素等设为湿）。
- **许可证**：Rust 生态现成实现 phasmcore（GPL）、Stegcore（AGPL）**只能读不能抄**；用 MIT 的 **pySTC / stegolab** 作数值 oracle，
  Rust 侧按论文自实现，并做随机用例对拍（消息/改动/综合症一致）。

#### 9.2.2 落地真 ±1 / 三进制（有前置依赖，不可直接开关）

- 当前选槽依赖"在 stego 图上重算代价图"，靠 `&0xFE`（PNG）/ `&!1`（JPEG）保证不变性；±1 会让排序无法复现 → 提取失败。
- **前置**：把"精确代价排序"改为**块级选择**——用块内整数方差（或 HILL 块均值，`&0xFE` 稳定）选块，块内再用密钥决定具体槽；
  选择与"具体像素取何值"解耦后，±1 才能安全落地。
- PNG：对非饱和像素允许 `{−1,0,+1}`（非对称代价）；JPEG：非零系数允许 `{−1,0,+1}`，对 `|c|=1` 设 **`ρ−1=∞`（禁 1→0）、允许 1→2**，
  `|c|=0` 保持湿（保护零游程）——既不产生 shrinkage，又能利用大量 `|c|=1` 提升容量。

#### 9.2.3 升级代价模型与非对称代价

- PNG 增加 S-UNIWARD / MiPOD；JPEG 增加 J-UNIWARD / J-MiPOD / GUED；统一输出非对称 `ρ+1/ρ−1`。
- 自适应 `k`/`exclusion`：低载荷用大 exclusion、高载荷换更大 k；把推荐载荷从固定 1/2 改为按图/按载荷率校准。

### 9.3 P2：高阶能力与格式扩展

- **非加性**：synch / Gibbs construction / GMRF，处理相邻像素/系数的耦合代价（论文报告相对加性平均可再降约 30% 失真）。
- **多通道/彩色联合**：PNG 对 RGB 分别算代价或转 YCbCr 按人眼加权；JPEG 启用 Cb/Cr 并做通道间非加性（容量可接近 3×，需控检测面）。
- **现代盲检闭环**：SRM/maxSRM + ensemble、GFR、SRNet/KeNet；在 BOSSbase/BOWS2/Alaska 等标准集上报告
  加权错误概率 `P_E = 0.5(误检+漏检)`（越接近 0.5 越安全），替代当前自检口径。
- 支持 progressive JPEG、16-bit/调色板/隔行 PNG；WebP/AVIF/HEIC 真无损走"HILL/S-UNIWARD+STC"、有损走 QDCT（详见 `docs/modern_stego_for_image_and_video.md`）。
- 性能：HILL 二级低通若开放大窗口（如 63）改用积分图；大图可用 rayon 并行。

### 9.4 工作量与优先级（估算，供排期）

| 阶段 | 内容 | 相对规模 | 风险 |
|---|---|---|---|
| P0-1/2 | PNG 块透传 + 滤波保留 | 中（动解码器/回归） | 低（纯容器侧） |
| P0-3/4 | UERD 几何 + DQT | 小 | 低（两端对称、不兼容协议，未发布） |
| P0-5/6/7 | 头部编码、别名、参数指纹 | 中 | 低（需协议版本位） |
| P1 STC | 编码 + 容量模型 + 对拍 | **大** | 中（需数值 oracle） |
| P1 ±1 | 块级选槽改造 + 三进制 | 中–大 | 中（动选择/提取一致性） |
| P2 | 非加性/多通道/现代盲检 | 大 | 中–高 |

> 建议顺序：P0-3/4（最小、先拿正确性）→ P0-1/2（格式保持）→ P0-5/6/7（清理）→ 单独立项做 STC 设计文档再实现。

---

## 10. 复现方式（前序报告）

```powershell
# 容量探测
.\rust\target\release\strhide.exe embed --capacity temp/teststego/DC912sk1.png
.\rust\target\release\strhide.exe embed --capacity temp/teststego/chenleicover_4.jpg

# 接近满容量嵌入（随机不可压缩载荷）
C:\Home\Develop\venv\Scripts\python.exe -c "import secrets; open('temp/payload_png.bin','wb').write(secrets.token_bytes(33000))"
.\rust\target\release\strhide.exe embed temp/teststego/DC912sk1.png -d temp/payload_png.bin -o temp/full_png.png --overwrite

# 自检
.\rust\target\release\strhide.exe scan temp/full_png.png
```

---

## 11. 关键代码位置

| 内容 | 文件 |
|---|---|
| PNG 解码/编码、嵌入/提取、容量探测 | `rust/src/stego/spatial/engine.rs` |
| HILL 代价函数 | `rust/src/stego/spatial/cost/hill.rs` |
| JPEG 嵌入/提取、容量探测 | `rust/src/stego/jpeg/engine.rs` |
| UERD 代价函数（含 `sqrt` 网格、标准表） | `rust/src/stego/jpeg/cost/uerd.rs` |
| 真实 DQT 解析（可复用） | `rust/src/analysis/calibration.rs` |
| 汉明矩阵编码 | `rust/src/stego/coding.rs` |
| 信封 / 密钥派生 | `rust/src/stego/envelope.rs` |
| 算法注册表（别名 wow/nsf5） | `rust/src/stego/registry.rs` |
| 参数与校验 | `rust/src/stego/params.rs` |
| 置换 PRNG | `rust/src/stego/prng.rs` |
| 系数读写依赖 | `dct-io 0.1.1`（`inspect()` 可取 width/height/采样） |
| 批量语料回归 | `rust/tests/batch_stego.rs` |

---

## 12. 局限声明

- PSNR、容量、`scan` 分数等来自**前序报告的单机单样本**及项目文档的 15 张语料，用于说明量级与方向，**不是全语料统计结论**。
- `scan` 是项目自带检测器（χ²/SPA/RS + 校准），不代表第三方现代盲检；低分不等于不可检测。
- STC 嵌入效率等区间为论文常识性范围，实际值随载荷率、约束高与代价图变化，落地时应以实现实测为准。
- 本文结论以文件路径与函数名为准（行号会随版本漂移）；安全性取决于载荷率、载体、攻击者模型与检测器。
