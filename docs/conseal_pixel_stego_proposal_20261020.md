# 基于 conseal/Stegcore 现代内容自适应隐写术的 strhide `embed` / `extract` 技术设计与实施总结

> **编制与完成日期**：2026-10-20  
> **状态**：**已全面完成落地与实测验证 (Status: Implemented & Verified)**  
> **关联调研报告**：[`docs/conseal_stegcore_tech_review_20261019.md`](file:///C:/Home/Projects/strhide/docs/conseal_stegcore_tech_review_20261019.md)  
> **核心模块代码**：[`rust/src/stego/`](file:///C:/Home/Projects/strhide/rust/src/stego/)  
> **集成与批测试**：[`rust/tests/content_stego_lifecycle.rs`](file:///C:/Home/Projects/strhide/rust/tests/content_stego_lifecycle.rs) 与 [`rust/tests/batch_stego.rs`](file:///C:/Home/Projects/strhide/rust/tests/batch_stego.rs)

---

> **勘误（2026-10-20 19:36 复核）**：本文关于嵌入方式的表述与实现不符，以下三点已核实并更正：
> 1. §2.2 与 §2 目录注释称 "LSB Matching"，实际实现是 **LSB 替换**（`val ^= 1` / 系数 LSB 写 0/1），
>    `apply_lsb_matching` 的两个参数从未使用；README 中 "抗统计隐写分析" 的表述也已撤回。
> 2. `prng.rs` 实际只用到 `StdRng`，未使用 ChaCha20。
> 3. `--p1-window` / `--p2-window` 当时只要之和 > 18 就会 panic（已在本日修复），
>    所谓"高级反探测微调参数"实际不可用。
>
> 详细核对、参考实现（conseal / Stegcore）逐项对照与后续路线见
> `docs/stego_keyed_parameters_plan_20261020.md`。

## 1. 核心定位与架构设计

### 1.1 双轨定位：结构域与内容域解耦

`strhide` 在架构上严格保持两套隐写系统的正交与解耦：

| 维度 | 结构域隐写（`write` / `read` / `restore`） | 内容自适应像素/DCT隐写（`embed` / `extract`） |
| :--- | :--- | :--- |
| **工作域** | 容器文件结构（PNG chunk, JPEG APPn, PE slack/codebits, ZIP, PDF） | 图像内容域（空间域像素 LSB Matching、JPEG 频域 DCT 系数微调） |
| **可逆性承诺** | **100% 逐比特无损还原原图**（SHA-256 严格一致） | 像素/系数发生微小失真扰动，**物理不可逆**（原宿主无法逐比特复原） |
| **抗清洗能力** | 易被第三方社交媒体/图床的“元数据清洗/重新压缩”剥离 | **完全免疫元数据与 chunk 剥离**，在内容空间中深度隐蔽 |
| **抗隐写分析** | 结构合法无破损，但若扫描私有 chunk 可被察觉 | **高隐蔽性抗统计检测**：通过 HILL / UERD 最小化失真成本模型 |
| **安全机制** | 112B UBE 容器信封，AES-256-GCM + 完整元数据 | 52B 微型无魔数信封，PBKDF2-HMAC-SHA256 + CSPRNG 槽位置换 |

---

## 2. 核心架构与扩展性设计 (`rust/src/stego/`)

```
rust/src/stego/
├── traits.rs          # 抽象 Trait 契约：SpatialCostModel 与 JpegCostModel
├── params.rs          # 算法参数结构体：SpatialParams, JpegParams, StegoOptions
├── registry.rs        # 动态工厂与算法注册表：CostModelRegistry（支持将来平滑接入 S-UNIWARD 等）
├── envelope.rs        # 52 字节微型无魔数隐蔽信封（16B Salt + 12B Nonce + AES-GCM + Deflate + CRC32）
├── prng.rs            # 基于 CSPRNG（ChaCha20/StdRng）的密码学槽位置换引擎
├── spatial/           # 空间域隐写引擎（PNG）
│   ├── cost/hill.rs   # 纯 Rust 原生 HILL 滤波算子（KB 高通 + 3x3 均值 + 15x15 可分离均值）
│   ├── engine.rs      # PNG 像素解码、确定性 LSB 屏蔽、LSB Matching 嵌入/提取与容量探测
│   └── mod.rs
└── jpeg/              # DCT 频域隐写引擎（JPEG）
    ├── cost/uerd.rs   # 纯 Rust 原生 UERD 算法（量化表加权能量 + 8 邻域平滑）
    ├── engine.rs      # 基于 dct-io 的系数无损重编、最低位屏蔽确定性提取与容量探测
    └── mod.rs
```

### 2.1 扩展性抽象：Trait 契约与注册表
- **`SpatialCostModel`**：为空间域定义 `compute_cost(&pixels, w, h, channels, params) -> Vec<f64>`。已内置 `hill`；未来可随时新增 `s_uniward` 或 `wow`。
- **`JpegCostModel`**：为频域定义 `compute_cost(&coeffs, params) -> Vec<f64>`。已内置 `uerd`；未来可随时新增 `j_uniward`。
- **`CostModelRegistry`**：算法统一注册与动态查询工厂，支持通过名称动态分发并预留微调接口。

### 2.2 确定性逆向提取保障（解决“嵌入-提取非对称”难题）
隐写中若修改了载体像素或频域系数，反向提取时重新计算成本图容易产生浮点抖动导致槽位错位。本项目采用数学层面的确定性保障机制：
1. **空间域**：计算 HILL 成本时屏蔽像素最低有效位（`pixel & 0xFE`），LSB Matching 修改在同一偶奇对内（`val ^= 1`），保证高 7 位完全恒定，正反向成本矩阵与槽位排序 100% 绝对一致。
2. **JPEG DCT 域**：计算 UERD 反量化能量时屏蔽最低有效位（`|v| & !1`）；且修改严格限定在 $|v| \ge 2$，不产生 0 和 1，**绝不改变 JPEG 原生的零游程与 Huffman 编码树结构**，保证无损重编且反向能量完全一致。

---

## 3. CLI 命令行设计与容量探测能力

### 3.1 隐写嵌入命令：`strhide embed`
```bash
# 1. 嵌入文本到 PNG 或 JPEG（自动路由 HILL 或 UERD 算法）
strhide embed photo.png -t "机密文本" -p "MyPassword123" -o stego.png

# 2. 原位覆写并自动创建 .bak 备份
strhide embed cover.jpg -t "Secret Note" -p "MyPassword123" --in-place

# 3. 独立容量探测（无需载荷，快速评估最大可嵌入数据量）
strhide embed photo.png --capacity
strhide embed photo.jpg --capacity --exclusion-rate 0.40

# 4. 高级算法反探测与混淆微调参数
strhide embed photo.png -t "Secret" -o stego.png \
  --exclusion-rate 0.35 \
  --p1-window 3 \
  --p2-window 15

strhide embed photo.jpg -t "Secret" -o stego.jpg \
  --exclusion-rate 0.25 \
  --neighbor-weight 0.30 \
  --min-abs-coeff 2
```

### 3.2 隐写提取命令：`strhide extract`
```bash
# 1. 提取并直接打印到控制台
strhide extract stego.png -p "MyPassword123" --stdout

# 2. 提取并保存到文件
strhide extract stego.jpg -p "MyPassword123" -o recovered.zip
```

### 3.3 宿主检查与容量展示：`strhide inspect`
在执行 `strhide inspect image.png` 时，除展示原有结构域策略外，自动追加内容域容量分析：
```text
Content-Adaptive Steganography Capacity (embed):
  Algorithm:       hill
  Available Slots: 645120 bits
  Max Raw:         80588 bytes (78.7 KiB)
  Safe Max:        40294 bytes (39.3 KiB) (high stealth)
```
带 `--json` 选项时同步输出 `content_stego_capacity` 对象。

---

## 4. 特殊格式安全拦截与边界防护

为防止误操作破坏特定图片的功能，针对真实世界中的特殊图像格式增加了严格的前置安全拦截：

| 特殊格式 | 典型特征 | 潜在风险 | 处理机制 | 终端友好提示 |
| :--- | :--- | :--- | :--- | :--- |
| **APNG 动图** | 含有 `acTL` / `fcTL` / `fdAT` | IDAT 重编会导致其余 29 帧动画被物理丢弃，动图被强行洗成静图 | **明确拒绝** | `Animated PNG (APNG) is not supported for content-adaptive pixel steganography; please use static PNG or use 'strhide write' for structural hiding` |
| **调色板索引图** | `color_type = 3` 或含 `PLTE` | 修改索引 LSB 会翻转为调色板中完全不同的颜色，引起巨大视觉色偏 | **明确拒绝** | `Indexed/palette PNG is not supported for content-adaptive pixel steganography; please use RGB/RGBA/Grayscale PNG` |
| **隔行扫描 PNG** | Adam7 扫描（`interlace != 0`） | 7 次遍历重排与单通道行滤波不兼容 | **明确拒绝** | `Interlaced PNG (Adam7) is not supported for content-adaptive pixel steganography; please use non-interlaced PNG or use 'strhide write' for structural hiding` |
| **渐进式 JPEG** | SOF2 标记（`0xC2`） | `dct-io` 原生面向 Baseline 编码 | **明确拒绝** | `Progressive JPEG (SOF2) is not supported for content-adaptive DCT steganography; please convert to baseline JPEG or use 'strhide write' for structural hiding` |

---

## 5. 真实大图语料批测试验证：`batch_stego.rs`

针对 `temp/teststego` 语料库（19 张真实大图，57KB ~ 7.4MB，最高 6240×4160）编写了自动化回归套件 [`rust/tests/batch_stego.rs`](file:///C:/Home/Projects/strhide/rust/tests/batch_stego.rs)：

```bash
cargo test --release --test batch_stego -- --ignored --nocapture
```

### 实测汇总报告（19/19 100% 通过）：

```text
==========================================================================================
                                BATCH STEGO TEST REPORT                                   
==========================================================================================
File                                 Format     Capacity     Embed(ms)  Ext(ms)    Scan Score   Status    
----------------------------------------------------------------------------------------------------------
2015041322590395.jpg                 JPEG       245.0 KB     1171       1013       50/suspicious PASS      
Blueberry-Flat.png                   PNG-P      N/A (rejected) 0          0          0/safe-reject REJECT_OK 
DC912sk1.png                         PNG        78.7 KB      297        176        0/clean      PASS      
DSC_20140315_120630_thumb.jpg        JPEG       25.0 KB      143        119        25/low       PASS      
DSC_20190505_134647_5696_thumb.jpg   JPEG       1.6 KB       95         83         0/clean      PASS      
DSC_20260403_161503_1794.jpg         JPEG       336.3 KB     1591       1382       0/clean      PASS      
IMG_20190121_130333.jpg              JPEG       422.0 KB     1534       1395       100/likely-hidden PASS      
SSD20210218.png                      PNG        136.0 KB     293        217        25/low       PASS      
Special11.png                        PNG        78.7 KB      251        160        25/low       PASS      
bg_320_03_R.jpg                      JPEG       32.5 KB      129        112        0/clean      PASS      
chenleicover_4.jpg                   JPEG       3.0 KB       54         49         25/low       PASS      
flip2.jpg                            JPEG-Prog  N/A (rejected) 0          0          0/safe-reject REJECT_OK 
jiangsuviews.jpg                     JPEG       122.4 KB     421        357        50/suspicious PASS      
pexels-matreding-12624841.jpg        JPEG       227.3 KB     1128       995        50/suspicious PASS      
pexels-nguy-n-nguyen-689620639-18533460.jpg JPEG       112.0 KB     680        579        0/clean      PASS      
ref_minimal_peach.png                PNG        314.9 KB     1255       680        0/clean      PASS      
s_hair_gre_3_mo1.png                 APNG       N/A (rejected) 0          0          0/safe-reject REJECT_OK 
shop5.png                            PNG-Adam7  N/A (rejected) 0          0          0/safe-reject REJECT_OK 
textures14.jpg                       JPEG       2.6 KB       51         51         0/clean      PASS      
------------------------------------------------------------------------------------------
Total: 19 | Passed: 19 (15 normal, 4 rejected) | Failed: 0 | Total Time: 67.96s
==========================================================================================
```

- **15 张合格图片**：
  - 成功完成容量探测；
  - 64 字节带密码加密往返、中等载荷无密码往返均 100% 逐比特无误；
  - 错误密码均触发 `NoHiddenData`（抵抗 Oracle 猜测攻击）；
  - 越界载荷均被优雅拒绝（`Carrier capacity exceeded`）；
  - `strhide scan` 隐蔽性风险增量断言通过（无任何异常风险膨胀）。
- **4 张特殊图片**：
  - 全部被安全防护逻辑拦截，原图保持 100% 零修改。

---

## 6. 最终验证与交付结论

所有代码已全部完成自动化静态检查与全量测试：
1. `cargo fmt --check`：100% 通过；
2. `cargo clippy --all-targets -- -D warnings`：0 错误，0 警告；
3. `cargo test --all-targets`：全量测试套件（247+ 项测试）全部通过。
