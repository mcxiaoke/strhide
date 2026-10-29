# `strhide` 扩展支持 HEIF / HEIC / HEVC — 最终版可靠可行方案

| 项 | 内容 |
| :--- | :--- |
| 文档编号 | `STEGO-HEIF-HEIC-HEVC-FINAL-20261024` |
| 编制时间 | 2026-10-24 |
| 适用项目 | [`mcxiaoke/strhide`](https://github.com/mcxiaoke/strhide)（Rust，`adapters/heif.rs`、`stego/` 模块） |
| 文档性质 | 对你提供的三份参考文档（架构稿、技术综述、实施分析）做**事实核查后的定稿方案**；凡与核查结果冲突之处，以本文档为准 |

> **2026-10-24 修订说明**：初版曾判断"现阶段没有可用的 HEVC 有损编码器地基，方案 D 不应排期"。经进一步核实，**`ultravideo/kvazaar`（BSD-3-Clause）是一个真实、成熟、许可证与 `strhide` 完全兼容的 HEVC 有损编码器**，且其内置的 `--crypto` 选择性加密机制证实了 `trans_coeff_signs`（变换系数符号位）与 `intra_pred_modes`（帧内预测模式）两个语法元素在编码器代码里确实有现成的挂载点。这把方案 D 从"长期关注、不排期"升级为"可行、但需要你主动决定是否接受引入 C 编译期依赖"的选项，详见第 1.1 节与第 3.4 节（已重写）。

---

## 0. 先说结论

你给的三份文档在**架构设计思路**上基本是对的（结构域 vs 内容域的边界划分、HEIF/HEIC/HEVC 的概念区分、grid 分块陷阱、`iloc` 偏移重算规则、SDH/CABAC bypass 的技术原理，这些都符合 HEVC/HEIF 标准的公开事实），**值得保留**。

但文档中列出的"可直接拿来用"的几个 Rust 库，**我逐一查证后发现有相当一部分是虚构的仓库名，或者真实存在但成熟度被严重夸大**。这是三份文档最大的风险点——如果直接照搬去写 `Cargo.toml`，会在立项阶段就卡住。核查结果见第 1 节，**这是本方案与原文档最本质的区别，请优先读这部分**。

在核查基础上，本文档给出 **4 个方案**，按"现在就能做、可靠性最高"到"值得长期投入、但现阶段不该写进 Milestone 承诺"排列：

| 方案 | 定位 | 新增外部依赖 | 现在能不能做 |
| :--- | :--- | :--- | :--- |
| **方案 A：容器域隐藏 Item**（结构域，`write/read`） | 兜底方案，立即可做 | 零依赖 | ✅ 现在就能做，1~2 天 |
| **方案 B：内嵌缩略图/辅助图桥接**（内容域，复用 `stego::jpeg`） | 真实相机 `.heic` 的首选通道 | 零依赖 | ✅ 现在就能做，2~3 天 |
| **方案 C：HEVC CABAC 旁路符号位原地隐写**（内容域，新写一个窄范围语法解析器） | 覆盖没有缩略图的纯 `.heic`/`.hevc` | 零依赖（但要自己写 ~1500~2500 行解析代码，而不是"复用现成库几百行"） | ⚠️ 可做，但工作量比原文档估的大 2~4 倍，建议作为独立里程碑 |
| **方案 D：RDO 闭环压缩域隐写（QDST/SDH + 在编码环路内嵌入）** | 学术级旗舰方案 | C FFI 接 `ultravideo/kvazaar`（BSD-3-Clause，与 Apache-2.0 兼容） | ✅ **已核实有可行路径**（2026-10-24 更新，见第 1.1 节修订）：不是纯 Rust，但许可证干净、工程量可控，可作为可选 feature 排期 |

---

## 1. 依赖生态核查结果（重点，请先读）

我对三份文档中点名的全部 Rust/其他语言仓库做了逐一搜索核实，下表是结论：

### 1.1 核心结论（2026-10-24 修订）：没有成熟的**纯 Rust** HEVC 有损编码器，但有成熟的 **C（BSD-3-Clause）**编码器可以 FFI

原文档反复提到"`oxideav-h265` 已完整实现 HEVC 35 种帧内预测 + CABAC + RDOQ + SDH + Still Picture 编码，12MP 解码仅需 0.065s"——**这段描述不准确**。核实后的真实状态：

- `oxideav-h265`（crates.io 上确有此 crate，MIT，截至 v0.0.10）官方自述是：**"decoder scaffold"**。解码器方向已经做到能对 Annex-B / hvcC 做端到端解码（16 个一致性测试向量字节精确），但**编码器部分目前只有 `make_encoder`：一个只支持 PCM（无损直存）的 IDR 编码器 bootstrap**，官方原话是"encoder beyond the PCM bootstrap"仍是尚未完成的 gap。也就是说，**它现在不能做有损帧内编码，更谈不上 RDOQ / SDH / QDST 这些要在有损编码路径里才有意义的功能**。
- 没有找到任何其他纯 Rust、有 Apache-2.0 兼容许可证、且**支持 HEVC 有损帧内编码**的库。`gen2brain/h265`（Go）在 v0.2.0 之后倒是新增了 `hevc.NewEncoder`（intra-only IDR 编码器，已核实真实存在），但它是 Go 不是 Rust，接入方式和 C FFI 本质相同（需要 `go build -buildmode=c-archive` 导出静态库），成熟度和生产验证程度也不如下面这个。

**但"纯 Rust 没有"不等于"没有可用的编码器"**。核实后发现 **`ultravideo/kvazaar`**（芬兰坦佩雷大学 Ultra Video Group 出品，C99）是一个真实、工业级成熟（v2.3.2，2025-09-16 发布）、**BSD-3-Clause 许可证**（自 v2.1 起，与 Apache-2.0 完全兼容，不是 GPL/LGPL）、已被 FFmpeg 官方集成（`libavcodec/libkvazaar.c`）的 HEVC 编码器。已核实的关键事实：

- 支持 **Main / Main 10 / Main Still Picture** 三种 profile（`Main Still Picture` 正是 HEIC 静态图用的 profile）；
- `--(no-)rdoq`（RDOQ，默认开启）与 `--(no-)signhide`（Sign Data Hiding，默认关闭）都是真实存在的命令行参数；
- 更关键的是，它原生带有 `--crypto` 选择性加密机制，可选作用域包括 `trans_coeff_signs`（变换系数符号位）与 `intra_pred_modes`（帧内预测模式）——这两个语法元素**正是**第 3.4 节讨论的 SDH/IPM 隐写方案要挂载的位置。`--crypto` 本身做的是加密（打乱比特用于保密），不是隐写嵌入，但它的存在证实了 Kvazaar 代码库里确实有现成的、可以复用或模仿的"在这两个语法元素上做自定义处理"的接口点，这比"自己从 RDO 内部代码里挖一个新的挂载点"要容易得多。

这意味着**方案 D 不再是"地基不存在"的问题，而是"要不要接受引入一个 C 编译期依赖"的工程决策问题**——许可证层面没有障碍，剩下的权衡见第 3.4 节（已重写）。

### 1.2 逐库核实表

| 原文档中的名称 | 核实结论 | 实际状态 | 对本方案的影响 |
| :--- | :--- | :--- | :--- |
| `OxideAV/oxideav-h265`（crates.io: `oxideav-h265`） | ✅ **真实存在**，MIT | 解码端：端到端可用（Annex-B / hvcC，16 个一致性向量字节精确）。编码端：**仅 PCM 无损 IDR bootstrap**，无有损帧内编码、无 RDOQ、无 SDH 编码能力 | 可作为**解码/提取端参考**，不能作为"方案三"编码端地基使用 |
| `OxideAV/oxideav-heif`（容器层，隶属 `OxideAV` workspace，和 `oxideav-avif` 共用同一个容器 crate） | ✅ **真实存在**，MIT | 已支持 box 解析、Item 模型、grid/alpha/irot/imir 组合、还未压缩图像写入；是容器层而非编解码层 | 可选参考，但 `strhide` 已有自研 `adapters/isobmff.rs`，**不建议新增此依赖**，自己扩展现成代码成本更低、可控性更高 |
| `tbraun96/heic-rs` | ❌ **未找到该仓库**。`tbraun96` 这个 GitHub 用户真实存在，但其公开项目是 `netbeam`（异步网络库）、`parse-rs` 等，与 HEIC 无关 | 很可能是幻觉虚构的仓库 | **不要在 `Cargo.toml` 里尝试引用，会直接编译失败** |
| `roticv/rust_h265` | ✅ **真实存在**，`MIT OR Apache-2.0` | **纯解码器**，官方状态标注"functional"：支持 Main/Main10、I/P/B slice、SAO、deblocking、**sign-data-hiding 的读取**、transquant bypass、PCM；无 SIMD/多线程，约为单线程 FFmpeg 的 1/5 速度；**不含编码器** | 三个库里**成熟度最高、最值得参考/依赖**的纯 Rust HEVC 解码器，适合做方案 C 提取端与语法解析的底座或参考实现 |
| `dan335/heif-oxide` | ❌ **未找到该仓库**。`dan335` 用户真实存在，公开项目是 `nimp`（图像节点编辑器）、`nodemangler`，与 HEIF 无关 | 很可能是幻觉虚构 | 同上，不要引用 |
| `gen2brain/h265`（Go） | ✅ **真实存在**，MIT。官方自述是 `rust_h265` 与 `oxideav-h265` 的 **Go 移植/融合版**，支持 8-16bit、tiles、wavefront 等；**v0.2.0 起已新增 `hevc.NewEncoder`（intra-only IDR 编码器）与 `heic.Encode`**（2026-10-24 复核修正：早期版本确实只有解码器，但当前版本已是编解码器） | 真实，但是 **Go 语言**，不能直接作为 `strhide`（Rust）的依赖；接入方式与 C FFI 本质相同（`go build -buildmode=c-archive`），生产验证程度不如 Kvazaar | 可作为**代码可读性参考**或**备选 FFI 路径**，优先级低于下方的 Kvazaar（成熟度、生产验证更强） |
| `ultravideo/kvazaar`（C99） | ✅ **真实存在**，**BSD-3-Clause**（自 v2.1 起，此前 LGPLv2.1），v2.3.2（2025-09-16），FFmpeg 官方集成 | 支持 Main/Main10/Main Still Picture；`--rdoq`、`--signhide`、`--crypto`（含 `trans_coeff_signs`/`intra_pred_modes` 子选项）均已核实为真实存在的命令行参数，多个独立来源（Arch man page、Debian README、Docker Hub 官方镜像）交叉确认 | **方案 D 的推荐 FFI 路径**，见第 3.4 节；注意 `libkvazaar7` 的 Debian 包依赖 `libcrypto++`，若要启用 `--crypto` 对应的编译选项，大概率也要链接 Crypto++ |
| `OpenVisualCloud/SVT-HEVC`（C，Intel） | ✅ **真实存在**，BSD-2-Clause-Patent | **已于 2024-07-29 被 Intel 官方归档为只读**，最后版本 v1.5.1（2021-06-03），不再接受任何补丁 | 许可证干净，但项目已停止维护超过 4 年，**不建议作为新项目的首选依赖**，Kvazaar 优先级更高 |
| `imazen/heic`（crates.io: `heic`） | ✅ **真实存在** | 纯 Rust、`#![forbid(unsafe_code)]`、仅 I-slice（静态图足够）解码器；**License 确实是 `AGPL-3.0-only OR LicenseRef-Imazen-Commercial`**（双重授权，付费可商用，免费路径是 AGPL） | 原文档"⚠️ 许可证不兼容"的判断**是对的**，予以保留：除非愿意购买 Imazen 商业授权，否则不能在 Apache-2.0 的 `strhide` 里直接引入或抄代码 |
| `Cykooz/libheif-rs` | ✅ **真实存在**，MIT（包装层），需要系统 `libheif >= 1.17`（C 库，底层 x265/libde265 是 GPL/LGPL） | 功能最全（读写、Grid 合成、无损编码），是目前**唯一能让你"调一个函数就拿到标准合规无损 HEIC"的方案** | 作为 `--features heif-ffi` 可选 feature，是方案 D 降级后的现实落地路径（见 4.4 节），而不是默认路径 |
| `daniellerch/pySTC`、`hstego`、`aletheia` | ✅ 真实（Python/C++），HILL/S-UNIWARD/隐写分析评测相关 | 真实的学术工具 | 仅作为**算法与评测基线参考**，不是 Rust 依赖，不纳入工程实现 |
| `listenlink/HM`（HEVC 官方参考软件 HM） | ✅ 真实（C++，BSD 类协议） | 真实，是学术界 HEVC 隐写论文常用的实验平台 | 仅作为**算法参考**（理解 RDO/四叉树/SDH 的标准实现方式），不建议往 `strhide` 里接 C++ 依赖 |
| `scuffle-h265` | ✅ 真实存在，`MIT OR Apache-2.0` | 比原文档描述的"专注解析 SPS/PPS，轻量稳定"**更窄**：目前**只解析 SPS NALU**（PPS、slice、residual 均未实现），仍标注"under active development, may not be stable" | 现阶段能力不足以支撑任何实际隐写需求，仅可关注后续版本 |

### 1.3 小结：这对你的技术选型意味着什么

1. **原文档"方案一"（HEVC NAL/CABAC 旁路原地隐写）在原则上是可行的，但不是"复用几百行代码"那么轻松**——你需要自己实现一个窄范围的 HEVC CABAC bypass bin / residual_coding 语法解析器（可以参考 `roticv/rust_h265`，MIT/Apache-2.0 协议允许你阅读、移植甚至直接依赖它的解码逻辑），工作量按真实情况应估到 1500~2500 行而不是几百行。
2. **原文档"方案二"（内嵌 JPEG 缩略图桥接）是本方案中风险最低、性价比最高的一条**，因为它完全不碰 HEVC 码流，100% 复用你项目里已经跑通的 `stego::jpeg`，核实结论没有改变这一条的可行性评估。
3. **原文档"方案三"（oxideav-h265 变换域 RDO 闭环隐写）目前没有地基**，应改为"长期关注项"而不是写进近期 Milestone。
4. 所有"零外部依赖、几天落地"的表述里，唯一名副其实的是**方案 A（容器域）**和**方案 B（缩略图桥接）**；方案 C 虽然也是零外部依赖，但"零依赖"不等于"零工作量"，自己写的解析器本身就是一项不小的开发。

---

## 2. 架构边界回顾（沿用原文档判断，核实无误）

`strhide` 现有双系统正交架构继续适用，不需要改变：

- **系统 A（结构域，`write / read / restore`）**：负责 ISOBMFF 容器级无损挂载，已在 `adapters/heif.rs` 里识别 HEIF 系 brands（`heic`、`heix`、`hevc`、`hevx`、`mif1`、`msf1`、`avif` 等），通过 `box_uuid` / `eof` 注入信封。
- **系统 B（内容域，`embed / extract / probe`）**：负责对载体做不可逆的抗检测微调，目前仅支持 PNG / JPEG 嗅探，遇到 HEIF/HEIC/HEVC 会返回 `UnsupportedFormat`。

本次扩展的目标就是让系统 B 能够嗅探并处理 HEIF/HEIC/HEVC 载体，同时让系统 A 新增更隐蔽的容器内藏匿策略。两个系统继续保持正交、互不干扰。

### 2.1 三个概念的区分（标准事实，核实无误，直接采用）

1. **HEIF**（ISO/IEC 23008-12）：基于 ISOBMFF 的通用图像容器标准，brand 典型为 `mif1`/`msf1`，内部可以装 HEVC、AV1（即 AVIF）、JPEG 缩略图、未压缩 `unci` 图像等任意编码的图像 Item。
2. **HEIC**：特指以 HEVC 为底层编码器的 HEIF 容器，典型 brand 为 `heic`/`heix`/`hevc`/`hevx`，是 iOS/macOS 相机默认格式。**iPhone 拍摄的高分辨率照片几乎总是采用 grid 分块结构**（例如 4032×3024 由 48 个 512×512 的独立 `hvc1` Tile Item 拼接而成），这是实现时必须处理的真实世界约束，不是边缘情况。
3. **HEVC/H.265**：底层视频/静态图压缩标准，作为文件有两种封装形态：
   - **Annex-B 裸码流**（`.hevc`/`.h265`）：`0x000001`/`0x00000001` 起始码分隔 NAL。
   - **长度前缀封装**（`hvc1`/`hev1`，存在 `.heic`/`.mp4` 里）：无起始码，用 `hvcC` 盒子里的 `lengthSizeMinusOne`（通常为 3，即 4 字节大端长度）做分隔。**这两种格式解析逻辑完全不同，必须在 `bitstream.rs` 里分支处理，不能混用。**

---

## 3. 四个方案详细设计

### 3.1 方案 A（结构域，优先级最高、立即可做）：ISOBMFF 隐藏 Item

纳入 `adapters/heif.rs` 的新增策略，不属于 `stego` 模块（这是容器域，不是自适应隐写域）：

| 策略名 | 原理 | 隐蔽性 |
| :--- | :--- | :--- |
| `box_uuid`（已支持） | 文件级追加自定义 `uuid` Box | 中等，`isobmff_suspicious_structures` 扫描器能发现尾部异常 Box |
| `item_hidden`（新增，推荐） | 在 `iinf` 里登记一条不挂载在 `pitm`（主图索引）上的私有 Item，数据存入 `mdat`，`iloc` 记录偏移 | 高：所有标准解码器只按 `pitm` 渲染主图，完全忽略未被引用的 Item，对可见内容零干扰 |
| `item_aux`（新增） | 将数据伪装为辅助图像（`auxl`：Alpha 通道 / 深度图 / HDR 增益图） | 高，但要求伪装的辅助图像类型属性（`auxC`）看起来合理 |
| `free_atom`（新增） | 数据伪装为标准 `free`/`skip` 填充 Box | 中等，`free` Box 体积异常大本身就是一个可疑特征，适合小载荷 |

**工作量**：扩展 `adapters/isobmff.rs` 增加 `iinf`/`iloc` 的解析与重写辅助函数，约 1~2 天。**这是唯一不涉及"隐写分析对抗"的方案，纯粹是容器工程，可靠性最高，建议作为第一步立刻做。**

### 3.2 方案 B（内容域，次优先级）：内嵌缩略图 / 辅助图桥接隐写

> **2026-10-25 后续调整（覆盖下文"首选通道/默认主路径"的表述）**：HEIF 内容域的运行时路由已改为**方案 C 优先、方案 B 兜底**，写入/读取/容量三处同序。桥接仍保留为其自身 API（`embed_heif_bridge` / `extract_heif_bridge`）可用的回退通道，"主图 bit-exact"从默认路径的取舍依据降为该方案自身的性质。

#### 为什么这是真实相机 `.heic` 的"降维打击"方案
几乎所有 iPhone/主流安卓相机拍摄的 `.heic` 都在 `meta` 的 `iinf` 里声明了不止一个 Item：

- 主图 Item（`item_type = hvc1` 或 `grid`）；
- **缩略图 Item**（`item_type = jpeg`，在 `iref` 里通过 `thmb` 引用指向主图），分辨率通常 320×240~512×384，体积约 15~45 KB；
- 部分设备还会有 HDR 增益图或景深图（`auxl`）。

#### 工作流
1. 解析 `meta`→`iinf`/`iloc`（约 250 行纯 Rust，无需外部容器库，`strhide` 自研 ISOBMFF 解析器已有基础）；
2. 若存在 `item_type == jpeg` 的 Item，直接切出该段字节（它就是一个合法的 `\xFF\xD8...\xFF\xD9` JPEG 流），**直接调用 `strhide` 现成的 `stego::jpeg::embed_jpeg`**（UERD 代价模型 + V3 Superblock + STC），得到新字节；
3. 若存在 `item_type == unci` 未压缩像素项，调用现成的 `stego::spatial`（HILL + STC）；
4. 用新数据替换 `mdat` 中原 Item 区间，按 `construction_method`（见 5.2 节）重算并回写所有受影响 Item 的 `iloc` 偏移。

#### 优势（核实后依然成立）
- **主图 100% bit-exact**，与相机直出字节完全一致，任何针对 HEVC 码流本身的隐写分析器在主图上检出率为 0；
- **100% 复用已验证的 `stego::jpeg`/`stego::spatial` 引擎**，新增代码量很小（~300~400 行），没有新的密码学/编码风险；
- 容量：320×240 的内嵌 JPEG 约 1200~1800 个 8×8 块，`SafetyLevel::High` 下可安全藏 800B~1.5KiB，极限可达 8~12KiB。

**局限**：依赖载体文件本身带缩略图/辅助图。对于没有缩略图的纯 `.heic`（例如经过裁剪处理、程序生成的截图转换等）或裸 `.hevc`/`.h265` 视频文件，这条路径不适用，需要方案 C 兜底。

**工作量**：2~3 天。**建议与方案 A 一起作为 v0.7 的默认主路径。**

### 3.3 方案 C（内容域，覆盖全格式）：HEVC CABAC 旁路符号位原地隐写

这是覆盖"没有缩略图的纯 HEVC/HEIC"场景的唯一现实路径，但需要如实纠正工作量预期。

#### 核心原理（HEVC 标准公开事实，核实无误）
HEVC 标准 §7.3.8.11 原生定义了 **Sign Data Hiding (SDH)**：在一个 4×4 变换子块内，若首尾非零系数扫描距离 > 4（阈值可配置），编码器不显式写入首个非零系数的符号位，而是用该子块所有非零系数绝对值之和的奇偶性隐式表达符号。`coeff_sign_flag` 本身是在 CABAC **旁路模式（Bypass，等概率 p=0.5）**下编码的，旁路模式不依赖上下文状态机，因此：

- 直接翻转一个旁路 bin 对应的比特，**不会扰乱后续 CABAC 上下文状态**（这是它区别于"修改 Regular-coded bin 会导致整个上下文模型错位"的关键）；
- 只要翻转发生在"归一化区间不变"的边界内，**不会改变码流总长度**（零码率膨胀）。

把目标奇偶性从"原始符号位"替换成"STC 编码后的密文比特"，就能得到一个零膨胀、高隐蔽的隐写通道。

#### 必须解决的工程问题（原文档低估的部分）

要定位这些 SDH 槽位，**必须能解析到 residual_coding() 语法层**，这意味着你需要实现（或移植）：

1. NAL 拆封（Annex-B 起始码 / `hvcC` 长度前缀，二者不可混用，见 2.1 节）+ 防竞争字节（Emulation Prevention Bytes, `0x000003`）脱壳与回封装；
2. VPS/SPS/PPS 参数集解析（获取 bit depth、chroma format、scaling list 等，影响 CABAC 上下文初始化和 4×4 子块划分规则）；
3. Slice Header 解析（定位 `slice_data` 起始比特偏移）；
4. CTU 递归四叉树（`split_cu_flag`）+ TU 划分（`split_transform_flag`）语法遍历，**虽然不需要做完整像素重构**，但要正确走到每个 TU 的 `residual_coding()`；
5. CABAC 算术解码引擎本身（Regular-coded bin 要正确维护上下文状态机，哪怕你最终只改 Bypass bin，前面所有 Regular bin 也必须正确解码才能让比特流指针走到正确位置）；
6. 在 `residual_coding()` 里识别 SDH 生效条件（`sign_data_hiding_enabled_flag`、首尾非零系数扫描距离 > 4）、定位 `coeff_abs_level_remaining` 对应比特位置，计算待隐藏比特与现有奇偶性的差值，必要时对代价最小的一个系数做 ±1 调整；
7. 回写：把修改后的比特原地写回（对于纯符号位翻转是真正的"原地"；对于±1 系数调整需要重新计算该系数的 `coeff_abs_level_remaining` 编码并处理可能的长度变化，一旦长度变化就不再是单比特翻转那么简单，需要考虑同一 Bypass 段内后续比特的连锁调整）。

**这是一个完整的（虽然范围窄化到只做到残差语法层、不做反变换/反量化/环路滤波的）HEVC 语法层解码器 + 回写器**，并不是"直接复用 `dct-io` 的思路改改就行"。参考 `roticv/rust_h265`（MIT/Apache-2.0，已验证字节精确对齐 FFmpeg）的内部实现是目前最现实的起点：要么作为依赖直接引入其解码管线、在其基础上加一个"同步记录每个 SDH 槽位的比特偏移"的 hook，要么参考它的语法表实现自己裁剪过的版本。

#### 修正后的工作量估计
原文档估 450~600 行、2~3 天。更现实的估计是：**若以 `roticv/rust_h265` 为依赖并只新增"定位 SDH 槽位 + 原地翻转"的薄层逻辑，约 800~1200 行、4~7 天**；**若完全自己从零写一个窄化的 CABAC + residual_coding 解析器（不依赖 `rust_h265`，保持 `strhide` 现在"自研、少依赖"的风格），约 1800~2600 行、2~3 周**。这取决于你是否愿意为此新增一个外部依赖。

#### 两种落地路径的取舍
- **路径 C1（依赖 `roticv/rust_h265`）**：优点是复用一个已验证字节精确的解码管线，减少自己踩 CABAC 上下文表的坑；缺点是引入了一个外部 crate（MIT/Apache-2.0，与 `strhide` 许可证兼容，没有法律风险），且它目前无多线程/SIMD，大文件处理会慢（约为 FFmpeg 单线程的 1/5）。但 `strhide` 的隐写场景通常是中小文件，这个性能量级大概率可接受。
- **路径 C2（自研窄化解析器）**：优点是保持零外部依赖、完全可控；缺点是工作量最大，且需要你自己对着 HEVC 标准正文核对 CABAC 上下文初始化表（这部分最容易出 bug，错一个上下文索引就会导致花屏或崩溃）。

**建议**：先走 **C1**，把 `rust_h265` 当作只读的语法分析底座（只用它定位 SDH 槽位的比特偏移，不用它做完整像素重构），实现提取端（`extract`）；嵌入端的"原地翻转"只需要在原始字节缓冲区上按比特偏移做异或操作，不需要重新跑一遍编码器。这样可以把工作量压到路径 C1 的量级，同时把"是否要维护自己的 CABAC 解码器"这个长期负担转嫁给上游。如果之后发现 `rust_h265` 的许可证、维护活跃度或性能不满足需求，再考虑切换到 C2 自研。

**工作量**：以路径 C1 计，4~7 天实现 + 1~2 周测试/修正边界情况（10bit、4:2:2/4:4:4、多 tile、WPP 等）。**建议作为独立里程碑（v0.8），不要和方案 A/B 放进同一个 Sprint。**

### 3.4 方案 D（2026-10-24 重写）：接 `kvazaar`（C FFI）做 RDO 闭环压缩域隐写

原文档的"方案三 IPM/QDST 优先级保持隐写"、"四叉树结构保持隐写"在学术上都是真实存在的技术路线（可查证的 IEEE/期刊论文，参见第 6 节），抗检测能力确实是这几种方案里最强的，因为它们不引入任何独立于真实编码过程之外的失真——隐写决策是在编码器内部的 RDO 选择分支里做的，而不是在编码完成后"事后"修改码流。

#### 1.1 节已更新的核心判断：地基问题已解决，剩下的是工程取舍

要把这类方案落地到 `strhide`，前提是有一个可控、可插桩的 HEVC 有损帧内编码器。第 1.1 节已核实：纯 Rust 里没有，但 **`ultravideo/kvazaar`（C99，BSD-3-Clause）是一个现实可用的地基**：

- **许可证**：BSD-3-Clause，与 `strhide` 的 Apache-2.0 完全兼容，不涉及 GPL/LGPL 分发义务问题——这是它相对于原文档"方案四"（`libheif-rs` + 系统 `libheif`，底层 x265/libde265 是 GPL/LGPL）的决定性优势，**应优先于 `libheif-rs` 路线考虑**。
- **成熟度**：12+ 年研发历史，FFmpeg 官方集成验证，v2.3.2 为最新稳定版，持续维护中（不像 SVT-HEVC 已被 Intel 归档只读）。
- **挂载点**：原生 `--crypto` 机制证实了 `trans_coeff_signs`（变换系数符号位）与 `intra_pred_modes`（帧内预测模式）在代码里确实有现成的拦截点——这两个恰好是方案 D 要挂 STC 的位置。**但要澄清**：`--crypto` 做的是加密（混淆比特用于保密传输），不是隐写嵌入；它证明"挂载点存在、可行"，不代表"把 STC 接进去是零工作量"——需要你在相同的代码位置，把"异或加密逻辑"换成"按 `StcTrellis::embed_with_deltas` 决定是否翻转该比特"的逻辑，这仍然是实打实的新代码，只是比从 RDO 内部代码里现挖一个全新的挂载点容易得多。
- **API 复杂度**：Kvazaar 对外只暴露 `kvz_api_get(bit_depth)` 一个入口函数拿到函数表，参数通过 `(api.config_parse)(cfg, "key", "value")` 字符串接口传入，不需要对接复杂的 C 结构体字段偏移——这意味着 Rust 侧的 FFI 胶水层可以不依赖 `bindgen`，手写 `extern "C"` 声明即可，体量不大（具体行数取决于你要暴露多少参数，几十到一百多行是合理区间，但这不是我验证过的精确数字，实现前建议先读一遍 `kvazaar.h` 再估算）。

#### 需要你主动决定的工程取舍

许可证问题解决了，但还有两个不是"查证"能解决、需要你自己权衡的决策点：

1. **C 编译期依赖 vs. Single Static Binary**：你的项目文档明确把"不破坏零 C/C++ 编译期强依赖"列为设计红线。接入 Kvazaar 意味着构建 `strhide` 需要一个 C 编译器（`cc` crate + `build.rs` 静态编译 `kvazaar` 源码是可行的，Kvazaar 本身是纯 C99，没有再传递的第三方 C 依赖，除非启用 `--crypto` 牵涉 Crypto++），交叉编译矩阵也会变复杂（尤其是如果你要支持 Windows/macOS/Linux/ARM 多平台静态单文件分发）。这不是不能接受，但应该是一个**显式的、写进 ADR（架构决策记录）的选择**，而不是"反正许可证干净就顺手接了"。
2. **复杂度与收益是否匹配你的实际需求**：方案 D 换来的是"学术 SOTA 级抗检测能力"，但方案 A+B（已经零依赖、这周就能上线）已经覆盖了"真实相机 `.heic` 照片"的主流场景、且主图 100% bit-exact 本身就是最强的"零特征"伪装；方案 C（CABAC 旁路符号位原地翻转）覆盖了"没有缩略图的纯 HEVC"场景，同样零码率膨胀。方案 D 的增量价值主要体现在：需要对抗**专门针对 HEVC 码流本身做统计检测的高级隐写分析器**（而不仅仅是容器结构扫描或一般性检测）的场景。如果你的实际威胁模型没有这么高的对抗强度，方案 D 的投入产出比未必划算。

#### 建议路线
1. **作为独立的可选 Cargo feature**（如 `--features hevc-kvazaar`），不编译进默认二进制，`build.rs` 用 `cc` crate 静态编译 Kvazaar 的 C 源码（而不是依赖系统预装的动态库，这样能保持"开启该 feature 后仍是单一可执行文件"，只是不再是"零 C 依赖"）。
2. **第一步只做验证性原型**：在 Kvazaar 的 `--crypto` 挂载点（`trans_coeff_signs`/`intra_pred_modes` 的拦截逻辑所在源文件，需要你 clone 仓库后实际定位，本文档未逐行读过 Kvazaar 源码、不保证具体文件名）旁边加一个调用 `StcTrellis` 的新分支，先跑通"能嵌入、能用 `roticv/rust_h265`（方案 C 里确认的解码器）提取回来"的最小闭环，再谈 RDO 代价模型的精细化。
3. **把 `libheif-rs`/系统 `libheif` 降级为"仅在用户环境已有 libheif 时的轻量替代路径"**，不再作为方案 D 的首选——Kvazaar 的 BSD-3-Clause + 静态编译方案明显优于背负 GPL/LGPL 分发义务的 FFI 路径。
4. 工作量：实现 FFI 胶水层 + 最小验证闭环，预计 1~1.5 周；把它打磨到能处理真实 iPhone 分辨率照片、多种 QP、10-bit 等边界情况，再加 1~2 周。**建议作为独立里程碑排期（而不是"长期关注、不排期"），但仍晚于方案 A/B/C。**

---

## 4. 推荐路线图（已按核实结果修正工作量与顺序）

### Milestone 1（v0.7，约 1 周）：零外部依赖，覆盖真实世界的大多数场景
1. 方案 A：`adapters/heif.rs` 新增 `item_hidden` / `free_atom` 策略（结构域）。
2. 方案 B：`stego/heif/thumb_bridge.rs`，桥接内嵌 JPEG/辅助图到现成的 `stego::jpeg`/`stego::spatial`。
3. 端到端测试：真机拍摄的 iPhone/Android `.heic` 样本，覆盖 `embed → extract → probe` 全链路。

### Milestone 2（v0.8，约 2~3 周，独立排期）：覆盖无缩略图的纯 HEVC/HEIC
1. 引入 `roticv/rust_h265` 作为只读语法分析依赖（路径 C1），评估其许可证、更新频率是否满足长期维护要求。
2. 实现 `stego/hevc/sniff.rs`（嗅探 ftyp brand / Annex-B 起始码）+ `stego/hevc/sdh.rs`（定位 SDH 槽位比特偏移 + STC 嵌入/提取）。
3. 覆盖 iPhone Grid 分块（48-Tile）场景：按 `item_id` 升序收集所有 `hvc1` Tile，拼接成全局槽位序列。
4. 边界情况专项测试：10-bit、4:2:2/4:4:4、多 tile/WPP slice、`sign_data_hiding_enabled_flag = 0` 的降级处理（此时应该直接判定该 TU 不可用作槽位，而不是报错）。

### Milestone 3（v0.9，约 2.5~3.5 周，需先做 ADR 决策）：方案 D，接 `kvazaar` 做 RDO 闭环隐写
1. **前置决策**：是否接受为 `--features hevc-kvazaar` 引入 C 编译期依赖（`cc` crate 静态编译 Kvazaar 源码），写一份简短 ADR 记录决策与理由——这不是技术核查能替你做的决定，见第 3.4 节"需要你主动决定的工程取舍"。
2. 若决定推进：`build.rs` 静态编译 `kvazaar`（BSD-3-Clause，纯 C99），Rust 侧手写 `extern "C"` 绑定 `kvz_api_get` 入口与 `config_parse` 字符串配置接口（预计不需要 `bindgen`）。
3. 定位 Kvazaar 源码中 `--crypto` 对 `trans_coeff_signs`/`intra_pred_modes` 的拦截逻辑所在位置，旁路加入调用 `StcTrellis::embed_with_deltas` 的新分支，先跑通最小验证闭环（嵌入 → 用方案 C 确认可用的 `roticv/rust_h265` 解码提取 → 校验）。
4. 若 `--crypto` 对应编译选项需要链接 Crypto++，评估是否要把这个 C++ 依赖也静态编译进去，或者改为绕开 `--crypto` 代码路径、直接在源码里新增一个不依赖 Crypto++ 的挂载点。
5. 补充 10-bit、4:2:2/4:4:4、真实 iPhone 分辨率、多 QP 值等边界情况测试。
6. （长期关注，不设时间表）定期 review `OxideAV/oxideav-h265` 的纯 Rust 编码器进展（关注其 "encoder beyond PCM bootstrap" 的 gap 是否补齐），一旦成熟到可用状态，可以考虑用它替换掉 Kvazaar 这个 C 依赖，回归"零 C 依赖"的项目红线。

### 验收标准（沿用原文档思路，核实无误）
- 新增的 `strhide write`（结构域）与 `strhide embed`（内容域）应保持正交：`embed` 生成的 `.heic` 不应包含任何 `uuid` Box 或尾部追加数据，`isobmff_suspicious_structures` 扫描结果应为 0 告警。
- 对方案 C 的产出，补充轻量级双重压缩特征检验，确认码率增幅 ≤ 0.5%（SDH 纯符号位翻转理论上应为 0%，±1 幅值调整的情况需要实测）。

---

## 5. 关键工程避坑点（HEIF/HEVC 标准事实，核实无误，照抄保留）

1. **iPhone HEIC 的 grid 分块陷阱**：4032×3024 的照片由 48 个独立 512×512 `hvc1` Tile Item 组成，主图 Item 类型是 `grid`（存于 `idat`，仅 8~12 字节，描述行列数），通过 `iref` 的 `dimg` 引用这些 Tile。正确做法是收集所有 `item_type == hvc1` 的 Item，按 `item_id` 升序排列构成全局槽位序列——`item_id` 在文件内唯一且确定，保证嵌入端与提取端生成一致的全局序列。
2. **`iloc` 的三种 `construction_method`**：
   - `0`（File Offset）：相对整个文件的绝对偏移——**修改排在前面的 Item 长度会导致后续所有同类型 Item 偏移失效，必须统一重算**；
   - `1`（`idat` Offset）：相对 `meta` 内部 `idat` 盒子的偏移；
   - `2`（Item Offset）：相对另一个 Item 的偏移。
   建议优先选择**原地等长修改**（Δ=0，如方案 C 的纯符号位翻转）来规避整表重算；方案 B 这种长度会变化的情况，必须统一修补受影响 Item 的 `base_offset`/`extent_offset`。
3. **Annex-B 与 `hvcC` 两种 NAL 封装不可混用**：裸 `.hevc`/`.h265` 用起始码分隔；`.heic`/`.mp4` 内的 `hvc1` Item 用 `hvcC` 里 `lengthSizeMinusOne` 指定的长度前缀分隔（通常 4 字节大端）。`bitstream.rs` 必须按 `HevcCarrierKind` 分流处理。
4. **防竞争字节（Emulation Prevention Bytes, `0x000003`）**：RBSP 字节流受此规则约束，任何在 RBSP 层的修改，序列化回 NAL 时都要重新插入 EPB，或者在原地微调前过滤掉会触发 `0x000000..=0x000003` 模式的槽位。
5. **与 `analysis.rs`（`strhide scan`）的联动**：目前 `scan` 只对 PNG/JPEG 做内容域盲检，对 HEIF 仅检查尾随 `uuid` Box。方案 A/B/C 落地后，应同步扩展 `scan` 对新增通道的检测能力，否则会出现"自己的隐写自己的扫描器都发现不了"的虚假安全感——这个扫描器本来就是用来验证隐写效果的,如果不同步更新就失去了验收意义。

---

## 6. 参考资料（已标注核实状态）

### 6.1 Rust 依赖 / FFI 目标库（按建议优先级）
- ✅ **[roticv/rust_h265](https://github.com/roticv/rust_h265)**（`MIT OR Apache-2.0`）——方案 C 的推荐依赖/参考，解码功能实测字节精确对齐 FFmpeg。
- ✅ **[ultravideo/kvazaar](https://github.com/ultravideo/kvazaar)**（C99，**BSD-3-Clause**）——方案 D 的**推荐 FFI 目标**，支持 Main Still Picture、RDOQ、Sign Hiding，原生 `--crypto` 机制证实 `trans_coeff_signs`/`intra_pred_modes` 挂载点存在；FFmpeg 官方集成，12+ 年维护历史。
- ✅ **[OxideAV/oxideav-h265](https://github.com/OxideAV/oxideav-h265)**（MIT）——仅用其解码端做交叉验证参考；**其编码端目前仅为 PCM bootstrap，不可用**，值得长期关注其进展，一旦成熟可考虑替换 Kvazaar 以回归零 C 依赖。
- ⚠️ **[OpenVisualCloud/SVT-HEVC](https://github.com/OpenVisualCloud/SVT-HEVC)**（C，BSD-2-Clause-Patent）——许可证干净，但已于 2024-07-29 被 Intel 归档为只读，不建议作为新项目依赖。
- ⚠️ **[gen2brain/h265](https://github.com/gen2brain/h265)**（Go，MIT）——v0.2.0 起已有 intra-only 编码器，可作为 Kvazaar 之外的备选 FFI 目标（需 `go build -buildmode=c-archive`），但生产验证不如 Kvazaar。
- ⚠️ **[Cykooz/libheif-rs](https://github.com/Cykooz/libheif-rs)**（MIT 包装层，底层 GPL/LGPL）——**已降级为次选**：仅在你已有/愿意接受系统 `libheif`+x265 的 GPL/LGPL 分发义务时考虑，Kvazaar 路线通常更优。
- ⚠️ **[imazen/heic](https://github.com/imazen/heic-decoder-rs)**（`AGPL-3.0-only OR 商业授权`）——除非购买商业授权，否则不可用于 `strhide`（Apache-2.0）。
- ❌ `tbraun96/heic-rs`、`dan335/heif-oxide`——**核实未找到对应仓库，极可能是虚构引用，不要尝试依赖**。

### 6.2 学术与算法参考（非 Rust 依赖，仅供理解原理）
- HEVC 标准 §7.3.8.11（Sign Data Hiding）、§9.3.3.2.3（CABAC Bypass 编解码）——SDH 与旁路编码的权威出处。
- [daniellerch/pySTC](https://github.com/daniellerch/pySTC)、[daniellerch/hstego](https://github.com/daniellerch/hstego)、[daniellerch/aletheia](https://github.com/daniellerch/aletheia)——STC/HILL/S-UNIWARD 的 Python/C++ 参考实现与隐写分析评测工具，用于理解代价函数设计与自测，不作为 Rust 依赖引入。
- [listenlink/HM](https://github.com/listenlink/HM)（HEVC 官方参考软件）——理解 RDO/四叉树/SDH 标准实现方式的最佳对照读物，不建议往 `strhide` 接 C++ 依赖。

### 6.3 本项目既有文档（按你给出的上传文件，供交叉参考）
- `strhide_stego_heif_heic_hevc_plan.md`（架构设计稿，2026-10-23）——整体分层思路可用，具体库选型以本文档第 1 节核实结果为准。
- `heic_hevc_steganography_guide.md`（技术综述）——HEVC 帧内压缩原理部分准确，Python 示例代码路径（`pySTC` + `pillow_heif`）作为算法验证原型是合理的，但不是 `strhide`（Rust）的最终实现路径。
- `heic_hevc_steganography_implementation_analysis_20261024.md`（实施分析）——四大痛点（失真漂移、RD 敏感度、CABAC 崩溃）的技术描述准确，可直接作为方案 C 的设计依据；其"Rust 生态核查结论"部分的库状态已被本文档第 1 节覆盖更新。

---

## 附：给后续维护者的一句话总结

> 结构域（方案 A）和缩略图桥接（方案 B）现在就能做，零风险，建议立刻开工；HEVC 码流级隐写（方案 C）可行但要自己啃一个语法解析器，工作量是原估计的 2~4 倍，建议借用 `roticv/rust_h265` 而不是从零写；RDO 闭环压缩域隐写（方案 D）**纯 Rust 没有地基，但 C FFI 接 `kvazaar`（BSD-3-Clause，许可证干净）是可行的**——真正要权衡的不是"有没有库"，而是"要不要为此接受一个 C 编译期依赖"，这件事值得你写一份 ADR 认真决定一次，而不是顺着许可证干净就默认接受。
