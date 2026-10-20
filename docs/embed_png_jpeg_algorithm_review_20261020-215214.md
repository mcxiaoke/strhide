# embed 对 PNG / JPEG 的算法现状、优缺点与改进建议

> **编制时间**：2026-10-20 21:52:14
> **核对对象**：`rust/src/stego/`（`strhide 0.4.0`，commit `55637b1`）
> **实测环境**：Windows 10，`rust/target/release/strhide.exe`，语料 `temp/teststego`
> **定位**：本文只讨论 `strhide embed` / `extract` 的内容域隐写，不涉及 `write` / `restore` 的结构域隐藏。
> **结论性质**：代码核对 + 单机单样本实测。样本数据用于说明量级和方向，不代表全语料统计结论。

---

## 1. 结论先行

1. **`embed` 现在不是“完整的 HILL/UERD 算法”**，而是：
   - PNG：**HILL 代价函数 + 贪心选槽 + `(7,3)` 汉明矩阵编码 + LSB 替换**；
   - JPEG：**UERD 代价函数 + 贪心选槽 + `(7,3)` 汉明矩阵编码 + 幅度对内 LSB 替换**。
   学术界的 HILL/UERD 通常默认搭配 **STC（综合征网格码）+ ±1 matching**。本项目只移植了代价函数，编码与修改规则是简化实现。
2. **PNG 的主要问题在工程侧**：重新编码会丢失 ancillary chunk，且固定 filter 0 会让文件明显变大。实测一张 960×960 RGBA PNG 藏 5 字节后体积 +23.1%，`bKGD` 等 chunk 丢失。
3. **JPEG 的主要问题在代价图正确性**：UERD 用 `sqrt(total_blocks)` 猜块行列号，但 `dct-io` 返回的是 MCU 交错顺序；4:2:0/4:2:2 等常见 JPEG 的 8 邻域能量会算到不相邻的块上。往返提取不受影响，但代价图质量下降。
4. **高载荷会被统计检测**：当前仍是 LSB 替换，汉明只降低改动数量，不改变“成对翻转”的痕迹。实测接近满容量时 PNG `scan` 50/100、JPEG 85/100；半容量时 PNG 0/100、JPEG 25/100。
5. **低载荷是当前的安全操作点**：`recommended_max = max / 2` 与实测吻合。若需要更高安全性，必须升级到 STC + ±1 + 湿代价，而不是继续调 HILL/UERD 参数。

---

## 2. 先厘清两条管线

| 命令 | 作用域 | 是否可逆 | PNG 载体 | JPEG 载体 |
|---|---|---|---|---|
| `write` / `restore` | 结构域 | **100% 可逆** | `prIv` 私有 chunk（或 EOF） | APP15/COM 段链（或 EOF） |
| `embed` / `extract` | 内容域 | **不可逆** | 改像素 LSB | 改量化 DCT 系数 LSB |

本文只讨论第二行。`embed` 修改了像素/系数，所以无法 `restore` 回原始文件；需要“藏了还能原样还原”的场景应使用 `write`。

---

## 3. PNG 侧：HILL + 单通道 + 汉明 + LSB 替换

### 3.1 代码路径

- 解码/编码：`rust/src/stego/spatial/engine.rs`
- 代价函数：`rust/src/stego/spatial/cost/hill.rs`
- 编码：`rust/src/stego/coding.rs`
- 信封：`rust/src/stego/envelope.rs`

### 3.2 嵌入流程

1. **PNG 解码**
   - 只接受 8-bit、非交错、RGB / RGBA / 灰度 / 灰度+Alpha。
   - 调色板 PNG、APNG、Adam7 交错 PNG 直接拒绝。
   - 只读取 IHDR、IDAT、IEND 等必要 chunk；其他 chunk 在后续重编码时不会保留。

2. **HILL 代价图**
   - 灰度转换前先做 `pixel & 0xFE`，屏蔽 LSB，保证嵌入前后代价图逐位一致。
   - 阶段 1：KB 3×3 高通核，取绝对值。
   - 阶段 2：`p1 × p1` 盒式均值，取倒数（默认 `p1 = 3`）。
   - 阶段 3：`p2 × p2` 可分离盒式均值（默认 `p2 = 15`）。
   - 对称填充量由参数推导：`pad = 1 + (p1-1)/2 + (p2-1)/2`；默认 `(3,15)` 得到 9。

3. **候选集**
   - 目标通道：RGB/RGBA 用 G（`channel_offset = 1`），灰度/灰度+Alpha 用通道 0。
   - 只允许通道值在 `[2, 253]`，避免改到 0/255 饱和值，也保证 `val & 0xFE` 在翻转后不变。
   - 按代价升序排序，保留最便宜的 `(1 - exclusion_percentile)` 比例；默认排除最平滑的 30%。

4. **头部**
   - 对候选集做**密钥化全置换**，取前 256 个槽。
   - 写 32 字节头：`[16B salt][12B nonce][4B total_len]`。
   - 头部是**直接 LSB 替换**，没有汉明编码。
   - 头部置换种子由密码派生（`derive_header_perm_seed`），不依赖 salt，解决“salt 在头部里”的鸡生蛋问题。

5. **正文**
   - 从候选集中去掉头部 256 槽，按代价取最便宜的 `needed_body_slots` 个。
   - 用 salt 派生的种子再做一次密钥化置换。
   - 用 `(7,3)` 汉明码嵌入：每 7 个槽携带 3 bit，最多改 1 个槽；块尾不足 7 个槽时退化为 1:1 LSB。
   - 实际写入规则是 `val ^= 1`，即 **LSB 替换**，不是 ±1 matching。

6. **重编码**
   - 只写 IHDR / IDAT / IEND。
   - 每行固定 filter 0（None）。
   - zlib 使用 `Compression::default()`。
   - **不保留原 IDAT 分块、不保留 ancillary chunk、不做自适应滤波。**

7. **信封**
   - 载荷先 Deflate；只有压缩后更小才使用压缩。
   - 明文格式：`[4B 原始长度][1B flags][payload]`。
   - AES-256-GCM 加密；密钥由 PBKDF2-HMAC-SHA256（100,000 次）+ HKDF-SHA256 派生。
   - salt/nonce 同时作为 AAD。
   - 最小信封 49 字节；正文固定开销 21 字节（4+1+16）。

### 3.3 实测数据

样本：`temp/teststego/DC912sk1.png`，960×960 RGBA，1,345,052 B。

| 项目 | 结果 |
|---|---|
| 报告最大载荷 | 34,505 B（33.7 KiB） |
| 推荐载荷 | 17,252 B（16.8 KiB），即最大值的 1/2 |
| 实际嵌入 | 33,000 B（接近满容量） |
| PSNR（RGB） | 63.67 dB |
| 改动像素 | 77,251 / 921,600 = 8.38% |
| 最大像素差 | 1 |
| `strhide scan` | 50/100 SUSPICIOUS（RS ≈ 0.07，SPA ≈ 0.11） |
| 半容量 17,000 B | `scan` 0/100 CLEAN |

重编码副作用（同一张图，藏 5 字节）：

| 项目 | 原图 | embed 输出 |
|---|---:|---:|
| 文件大小 | 1,345,052 B | 1,656,621 B（+23.1%） |
| chunk 数 | 45 | 3 |
| chunk 列表 | IHDR, bKGD, 多个 IDAT, IEND… | IHDR, IDAT, IEND |
| bKGD | 保留 | 丢失 |

### 3.4 优点

- HILL 计算便宜，默认参数下 960×960 的容量探测约 76 ms。
- 只改 1 个 LSB，最大像素差为 1，33 KB 载荷仍有 63.7 dB。
- `(7,3)` 汉明把平均改动率从 0.5 次/bit 降到 0.2917 次/bit，少改约 42%。
- 代价图用 `& 0xFE` 屏蔽 LSB，嵌入/提取可逐位复现。
- 头部/正文都做了密钥化置换，不再是“固定前 256 个最便宜槽”的明显指纹。
- AES-GCM + 无 magic 的微信封，错误密码统一报 `No valid payload found`，不构成明显 oracle。

### 3.5 缺点

1. **重编码破坏文件、增大体积**：丢 chunk、固定 filter 0、默认压缩级别。实测 +23.1%。
2. **单通道**：只改 G，容量约为三通道方案的 1/3。
3. **LSB 替换**：高载荷下 χ²/SPA/RS 可见；汉明只减少改动数量，不改变配对翻转的统计特征。
4. **贪心 + 固定分块汉明**：块边界与代价无关，不是全局最小失真；块尾 1:1，浪费容量。
5. **没有非对称代价/湿纸码**：`SpatialParams::wet_cost` 在 PNG 侧实际未使用；饱和像素只做硬排除。
6. **头部开销固定**：256 槽 + 32 字节，且无 ECC；小图收益敏感。
7. **参数不落信封**：`--p1-window`、`--exclusion-rate` 等改动后，提取端必须手动保持一致，否则静默失败。
8. **格式覆盖窄**：调色板 PNG、APNG、Adam7、16-bit 都不支持。

---

## 4. JPEG 侧：UERD + Y 分量 + 汉明 + 幅度对内替换

### 4.1 代码路径

- 嵌入/提取：`rust/src/stego/jpeg/engine.rs`
- 代价函数：`rust/src/stego/jpeg/cost/uerd.rs`
- 编码：`rust/src/stego/coding.rs`
- 信封：`rust/src/stego/envelope.rs`
- 系数读写：`dct-io 0.1.1`

### 4.2 嵌入流程

1. **系数读取**
   - `dct_io::read_coefficients` 直接解析 baseline JPEG 的量化 DCT 系数。
   - 不经过 IDCT/DCT，不做像素域重压缩，理论上无 generation loss。
   - 渐进式 JPEG（SOF2）直接拒绝。

2. **UERD 代价图**
   - 只处理 Y 分量（`components[0]`）。
   - 块能量：`Σ_{k=1..63} (|c_k| & !1) × Q[k]`。
   - 8 邻域块能量平滑，权重 `neighbor_weight = 0.25`。
   - 系数代价：`Q[k] / smoothed_energy`。
   - `Q[k]` 使用内置的**标准亮度量化表**（自然序），不是文件自带的 DQT。

3. **候选集**
   - 只处理 AC 系数 `k = 1..63`。
   - 只允许 `|c| >= 2`（`min_abs.max(2)`），避免把 1 改成 0 或把 0 改成 1。
   - 要求 `cost < wet_cost`。
   - 按代价升序排序，排除能量最低的 20% 块。

4. **头部 / 正文**
   - 与 PNG 相同：头部 256 槽、32 字节、直接 LSB；正文取最便宜的 N 个槽后密钥化置换；`(7,3)` 汉明。

5. **写入规则**
   - 只在同一幅度对内翻转：`2↔3`、`4↔5`、`-2↔-3`……
   - 从不碰 0/1，因此不改变零游程，也不会跨 Huffman 幅度类别。
   - 用原 Huffman 表重写码流，文件大小基本不变。

### 4.3 实测数据

样本：`temp/teststego/chenleicover_4.jpg`，500×500 RGB，69,067 B。

| 项目 | 结果 |
|---|---|
| 报告最大载荷 | 1,316 B（1.3 KiB） |
| 推荐载荷 | 658 B（0.6 KiB），即最大值的 1/2 |
| 实际嵌入 | 1,250 B（接近满容量） |
| PSNR（RGB） | 52.42 dB |
| 解码后改动像素 | 39,080 / 250,000 = 15.63% |
| 最大像素差 | 11 |
| 约计改动系数 | ~2,900 个（1,250×8×0.2917） |
| `strhide scan` | 85/100 LIKELY-HIDDEN（校准 DCT ≈ 19%） |
| 半容量 650 B | `scan` 25/100 LOW |

重编码副作用（藏 5 字节）：

| 项目 | 原图 | embed 输出 |
|---|---:|---:|
| 文件大小 | 69,067 B | 69,068 B（+1 B） |
| 段标记 | APP0, DQT×2, SOF0, DHT×4, SOS | 完全相同 |
| EXIF/JFIF | 保留 | 保留 |

### 4.4 优点

- DCT 系数域直接改，不重压缩，没有 generation loss。
- 文件大小基本不变，段结构保持。
- 只改 `|c| ≥ 2` 的 AC 系数，避开 F5 的 shrinkage 问题，零游程和 Huffman 表结构稳定。
- UERD 计算便宜，适合批量处理。
- 同样具备汉明、密钥化槽位、AEAD 信封。

### 4.5 缺点

1. **UERD 块邻域算错**
   - `uerd.rs` 用 `w_blocks = ceil(sqrt(total_blocks))` 当块行列号。
   - `dct-io` 返回的块顺序是 **MCU 交错顺序**：4:2:0 每个 MCU 有 2×2 个 Y 块，块数组不是行优先栅格。
   - 结果 8 邻域平滑会把不相邻的块当成邻居；方形 4:4:4 图碰巧正确，常见的 4:2:0/4:2:2 和非方形图都不正确。
   - **不影响往返提取**（两端用同一错误网格），但代价图质量下降。

2. **只用 Y 分量**：Cb/Cr 完全没用；4:2:0 下色度块更少，但仍有容量空间。

3. **只允许 `|c| ≥ 2`**：丢掉大量 `|c| = 1` 的 AC 系数；这些系数占非零 AC 的很大比例，直接限制容量。

4. **只用内置标准亮度量化表**：文件使用自定义 DQT 时，`Q[k]` 权重不匹配，代价排序会偏。

5. **只支持 baseline**：渐进式 JPEG 在 Web 上很常见，当前直接拒绝。

6. **没有 STC / 非对称代价 / 湿纸码**：仍是贪心 + 固定分块汉明 + 幅度对内替换；高载荷可检测。

7. **参数不落信封**：`--neighbor-weight`、`--min-abs-coeff`、`--exclusion-rate` 改动后，提取端必须手动保持一致。

---

## 5. 共性优点与共性缺点

### 5.1 共性优点

- 代价函数与嵌入引擎解耦（`SpatialCostModel` / `JpegCostModel`），便于扩展。
- 代价图对 LSB 做了屏蔽（PNG `& 0xFE`，JPEG `|c| & !1`），保证嵌入/提取的槽位排序可复现。
- 头部与正文都做了密钥化置换；头部位置不再公开可推导。
- AEAD 信封无 magic、无明文标记；错误密码统一报错，降低 oracle 风险。
- 有独立的容量探测 `probe_carrier_capacity`，并给出推荐值（最大值的一半）。
- `batch_stego` 有真实语料回归，覆盖拒绝/明文/加密/满容量/50% 容量/自检。

### 5.2 共性缺点

- **不是完整的最小失真框架**：没有 STC，没有非对称代价，没有湿纸码；汉明是固定分块，块边界与代价无关。
- **LSB 替换**：高载荷下统计痕迹明显；汉明只降低改动数量。
- **头部固定 256 槽 + 32 字节**：无 ECC，小图开销敏感。
- **参数不落信封**：算法/参数不一致时表现为静默 `NoHiddenData`。
- **注册表别名误导**：`"wow"` 返回 HILL，`"nsf5"` 返回 UERD（`registry.rs`），库调用方会误以为选到了对应算法。
- **死参数**：`SpatialParams::wet_cost` 在 PNG 侧未使用，`JpegParams::mode_dc_weight` 在 UERD 中未使用。
- **无密码模式使用公开常量密钥**：`PUBLIC_DEFAULT_SECRET` 是源码常量，任何人拿到二进制都能解无密码信封。
- **不可逆**：`embed` 无法 `restore` 回原始文件。

---

## 6. 改进路线

### 6.1 P0：低风险、立竿见影

| 改动 | 具体做法 | 预期收益 |
|---|---|---|
| PNG 保留 chunk | 解码后重建 PNG 时复用原 chunk 序列，只替换 IDAT；保留 `bKGD`、`iCCP`、`gAMA`、`tEXt`、`EXIF` 等 | 不再丢元数据 |
| PNG 自适应滤波 | 每行在 None/Sub/Up/Average/Paeth 中按最小绝对值和选择；zlib 用原级别或 9 | 体积回到原图附近，避免 +23% |
| JPEG 真实块网格 | 用 `dct_io::inspect` 取宽高、`h_samp/v_samp`，按 MCU 顺序把块索引映射到 `(block_row, block_col)` | UERD 8 邻域能量正确；非方形/4:2:0 明显受益 |
| JPEG 文件 DQT | 解析 DQT 段，按分量使用文件自己的量化表；`dct-io` 目前不暴露 DQT，需要自己解析或上游扩展 | 自定义量化表图像的代价排序正确 |
| 删除误导别名 | 删除 `"wow"`/`"nsf5"` 别名，或真正实现对应算法 | 避免 API 语义错误 |
| 接线或删除死参数 | `SpatialParams::wet_cost`、`JpegParams::mode_dc_weight` | 避免“调了没效果” |
| 参数指纹 | 头部增加 1 字节算法 ID + 量化参数指纹（可放在 AEAD 明文中） | 提取端可自动匹配或给出明确错误 |
| 容量报告增强 | `--capacity` 增加预计改动率、PSNR、推荐载荷说明 | 用户理解 `recommended_max` 的来源 |

### 6.2 P1：算法升级，收益最大

| 改动 | 说明 |
|---|---|
| **STC + 真 ±1 matching + 非对称湿代价** | 从“贪心 + 汉明 + 替换”升级到真正的最小失真框架。STC 允许任意槽位耦合，不再受 7 槽块边界限制；±1 消除成对翻转痕迹；湿代价可以安全使用 `|c|=1`、饱和像素等“禁用位置”。**关键前提**：槽位顺序必须由密钥决定，而不是由提取端重算代价排序，否则 ±1 会破坏代价图可复现性。 |
| **多通道/颜色代价** | PNG 目前只改 G；可对 R/G/B 分别算 HILL 代价，或转到 YCbCr 后按人眼敏感度加权。容量可接近 3×，但要控制色度失真和检测面。 |
| **JPEG 使用 `|c|=1`** | 设置 `ρ-1 = ∞`（禁止 1→0），允许 `1→2`；这样不产生 shrinkage，又能利用大量 `|c|=1` 系数。`|c|=0` 仍保持 wet，避免改变零游程。 |
| **自适应 k / exclusion** | 低载荷用 `k=3` 或更大 exclusion；高载荷用 `k=4/5` 降低改动率，或降低 exclusion 换容量。把 `recommended_max` 从固定 1/2 改成按图/按载荷率校准。 |
| **头部压缩/ECC** | 头部用汉明或重复码，或把 256 槽降到 ~128 槽；小图收益明显。 |

### 6.3 P2：算法研究与格式扩展

- PNG 增加 **S-UNIWARD / MiPOD** 代价模型，与 HILL 做 A/B。
- JPEG 增加 **J-UNIWARD / J-MiPOD** 代价模型，与 UERD 做 A/B。
- 支持渐进式 JPEG、16-bit PNG、调色板 PNG、交错 PNG。
- 现代格式：WebP/HEIC/AVIF 走“真无损 + HILL/S-UNIWARD + STC”，有损模式走 QDCT 系数域。
- 性能：HILL 第二级低通当前是朴素 `p1²` 盒滤波；默认 `p1=3` 足够快，若开放到 63 建议用积分图。大图可用 rayon 并行。
- 可选 Reed-Solomon 等 ECC，用于轻微再编码/裁剪场景；默认关闭，避免容量损失。

---

## 7. 市面主流与最新算法

### 7.1 代价函数谱系（传统最小失真）

| 算法 | 域 | 核心思想 | 评价 |
|---|---|---|---|
| HUGO 2010 | 空域 | SPAM 特征 + 4 方向子模型 | 老，慢，已被超越 |
| WOW 2012 | 空域 | 方向小波滤波 | 纹理区好，比 HILL 慢 |
| S-UNIWARD 2014 | 空域 | Daubechies-8 小波系数相对变化 | 抗检强，PNG 首选之一，计算较重 |
| **HILL 2014** | 空域 | 高通 + 两级低通 | **本项目 PNG 在用**；快、稳、工程友好 |
| MiPOD 2016 | 空域 | 高斯模型 + Fisher 信息最小化 | 更接近最优检测器，慢，适合高安全场景 |
| **UERD 2015** | DCT | 块能量 + 量化表加权 + 8 邻域平滑 | **本项目 JPEG 在用**；快，UERD 是 J-UNIWARD 的实用折中 |
| J-UNIWARD 2014 | DCT | 系数扰动映射到空域小波相对变化 | JPEG 强基线，慢 |
| J-MiPOD 2016 | DCT | 统计模型 | 更强，最慢 |

### 7.2 编码/嵌入框架

| 方案 | 改动率 | 容量 | 抗盲检 | 复杂度 | 备注 |
|---|---:|---|---|---|---|
| LSB 替换 | 0.5 次/bit | 1 bit/槽 | 低 | 极低 | 经典 χ²/SPA 攻击目标 |
| LSB matching ±1 | ~0.5 次/bit | 1 bit/槽 | 中 | 低 | 直方图更自然，但提取需同步 |
| **汉明矩阵 (7,3)** | **0.2917 次/bit** | **3/7 bit/槽** | 中 | 低 | **本项目**；固定分块，非全局最优 |
| **STC** | 接近理论最优 | 可变 | 高 | 高 | 学术/开源事实标准；Filler 2011 |
| 湿纸码 WPC | — | — | — | 中 | 处理禁用位置，常与 STC 结合 |
| 极化码/SPC | 更优 | 可变 | 高 | 研究 | 尚未大规模工程化 |

**关键区别**：HILL/UERD 只是“往哪里改”；汉明/STC 决定“改多少、怎么改”。本项目只完成了前半部分，后半部分是简化实现。

### 7.3 学习型 / 生成式 / 水印（最新方向）

| 方向 | 代表 | 容量 | 抗再编码 | 适用 |
|---|---|---|---|---|
| 端到端 CNN 隐写 | HiDDeN 2018、SteganoGAN 2019、UDH 2022 | 小~中 | 弱~中 | 研究、短消息 |
| 学习代价 + STC | ASDL-GAN 2019、SPAR-RL 2020、JEC-RL 2021 | 中 | 依赖 STC | 研究；增益常是“针对某个检测器” |
| 生成式/扩散隐写 | 2023–2025 多篇 | 小 | 弱 | 研究；依赖模型权重 |
| 鲁棒水印 | StegaStamp 2020、Stable Signature 2023、TrustMark 2023、VideoSeal 2024 | 100~1000 bit | 强 | 版权/溯源，不是文件隐藏 |
| 无封面隐写 | coverless / 检索映射，2024–2025 | 极低 | 强（不改载体） | 需要共享码本，容量很小 |

截至 2026 年，**没有出现取代“STC + UNIWARD/MiPOD”体系的新通用范式**；近两年的热点更多在检测侧（深度隐写分析、算法识别）、鲁棒水印、生成式/无封面方向。对于“藏几十 KB~MB、原文件传输、精确提取”这个需求，传统最小失真 + STC 仍是最实用的。

---

## 8. 横向对比

| 维度 | 本项目 PNG | 本项目 JPEG | 主流 PNG（S-UNIWARD/MiPOD + STC） | 主流 JPEG（J-UNIWARD + STC） |
|---|---|---|---|---|
| 代价函数 | HILL | UERD | S-UNIWARD / MiPOD | J-UNIWARD / J-MiPOD |
| 编码 | 贪心 + 汉明 (7,3) | 同左 | STC | STC |
| 修改规则 | LSB 替换 | 幅度对内替换 | ±1 matching | ±1 |
| 改动率 | 0.2917 次/bit | 0.2917 次/bit | 接近最优 | 接近最优 |
| 容量 | 中低（单通道） | 低（Y + `|c|≥2`） | 中高 | 中 |
| 低载荷抗检 | 好 | 中 | 更好 | 更好 |
| 高载荷抗检 | 差（实测 50/100） | 差（实测 85/100） | 明显更好 | 明显更好 |
| 实现复杂度 | 低 | 中 | 高 | 高 |
| 工程成熟度 | 已落地 | 已落地 | 论文/参考实现多 | 论文/参考实现多 |

---

## 9. 建议

1. **如果近期只做一件事**：先修 PNG 重编码（保留 chunk + 自适应 filter）和 JPEG UERD 的 MCU 网格/DQT。这两项风险低、收益直接，分别解决“文件变大/丢元数据”和“代价图算错”。
2. **如果要做安全升级**：上 STC + ±1 + 湿代价。这是从“简化版最小失真”到“真正最小失真”的分水岭，但工作量大，建议先用 MIT 许可的参考实现（stegolab / pySTC）做数值对拍，再改 Rust。
3. **如果要做容量**：多通道 + 允许 `|c|=1`（用湿代价只允许 1→2，不允许 1→0）+ 自适应 `k`。
4. **不要混淆 `write` 和 `embed`**：需要 100% 还原原文件，用 `write`；`embed` 只保证视觉/统计隐蔽，不保证可逆。
5. **对外表述要克制**：当前低载荷确实能保持 `scan` 干净，但高载荷不是“抗统计隐写分析”。`recommended_max` 的一半容量是有实测依据的安全操作点。

---

## 10. 复现方式

```powershell
# 容量探测
.\rust\target\release\strhide.exe embed --capacity temp/teststego/DC912sk1.png
.\rust\target\release\strhide.exe embed --capacity temp/teststego/chenleicover_4.jpg

# 接近满容量嵌入（随机不可压缩载荷）
C:\Home\Develop\venv\Scripts\python.exe -c "import secrets; open('temp/payload_png.bin','wb').write(secrets.token_bytes(33000))"
.\rust\target\release\strhide.exe embed temp/teststego/DC912sk1.png -d temp/payload_png.bin -o temp/full_png.png --overwrite

# 自检
.\rust\target\release\strhide.exe scan temp/full_png.png

# PSNR / 改动像素
C:\Home\Develop\venv\Scripts\python.exe -c "
import numpy as np
from PIL import Image
a=np.asarray(Image.open('temp/teststego/DC912sk1.png').convert('RGB')).astype(np.float64)
b=np.asarray(Image.open('temp/full_png.png').convert('RGB')).astype(np.float64)
mse=np.mean((a-b)**2); print('PSNR', 10*np.log10(255**2/mse))
print('changed', int(np.any(a!=b, axis=2).sum()))
"
```

---

## 11. 附录：关键代码位置

| 内容 | 文件 |
|---|---|
| PNG 解码/编码、嵌入/提取、容量探测 | `rust/src/stego/spatial/engine.rs` |
| HILL 代价函数 | `rust/src/stego/spatial/cost/hill.rs` |
| JPEG 嵌入/提取、容量探测 | `rust/src/stego/jpeg/engine.rs` |
| UERD 代价函数 | `rust/src/stego/jpeg/cost/uerd.rs` |
| 汉明矩阵编码 | `rust/src/stego/coding.rs` |
| 微信封 / 密钥派生 | `rust/src/stego/envelope.rs` |
| 算法注册表 | `rust/src/stego/registry.rs` |
| 参数定义与校验 | `rust/src/stego/params.rs` |
| 置换 PRNG | `rust/src/stego/prng.rs` |
| 批量语料回归 | `rust/tests/batch_stego.rs` |

---

## 12. 局限声明

- 本文的 PSNR、容量、`scan` 分数来自**单机单样本**，用于说明量级和方向，不是全语料统计结论。
- `scan` 是项目自带检测器，不代表所有第三方检测器；低分不等于“不可检测”。
- 代码行号会随版本变化，本文以文件路径和函数名为准。
- 本文不构成“当前实现不安全”的绝对结论；安全性取决于载荷率、载体、攻击者模型和检测器。
