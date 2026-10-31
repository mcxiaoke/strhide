# 现有隐写技术文档真实性核查与截至 2026 年全格式前沿隐写技术全景综述

本文档分为两大部分：**第一部分**针对上传的三份技术调研与实施方案文档（`modern_steganography_technologies_survey_20261031.md`、`audio_steganography_research_and_implementation_plan_20261031.md`、`mkv_and_avc_stego_implementation_plan_20261031.md`）开展逐项事实核查（Fact-Checking），甄别其中的**虚假/幻觉文献编号、概念混淆、标准细节偏差与工程踩坑点**；**第二部分**结合截至 2026 年的学术顶会（IEEE S&P、ACM CCS、CVPR、ICCV、NeurIPS、ICLR、ICML、AAAI、IEEE TIFS）与开源生态，系统梳理图像、视频、音频、文本/大语言模型、版式文档/字体、3D 神经资产及可执行二进制等各大文件格式的最前沿隐写技术体系。

---

## 第一部分：上传的三份技术文档真实性与准确性逐项核查

通过对三份文档中引用的论文、arXiv 预印本编号、GitHub 开源项目、Rust 生态库（crates.io）以及音视频编解码标准（ISO/IEC 14496-10 H.264、ISO/IEC 14496-3 AAC、ISO/IEC 11172-3 MP3、Matroska EBML）的交叉检索验证，整体结论如下：

- **引用的真实开源项目与工程大方向基本属实**：例如 [The-A-Files](https://github.com/pawel-kaczmarek/The-A-Files)、[Tolsi/awesome-steganography](https://github.com/Tolsi/awesome-steganography)、[cristiancmoises/awesome-steganography](https://github.com/cristiancmoises/awesome-steganography)、[ktekeli/audio-steganography-algorithms](https://github.com/ktekeli/audio-steganography-algorithms)、[Ganateju/audio-stego-project](https://github.com/Ganateju/audio-stego-project) 以及 Rust 社区的 [remade-with-rust/rusty_h264](https://github.com/remade-with-rust/rusty_h264)（`v0.16.1`）和 [OxideAV/oxideav-h264](https://github.com/OxideAV/oxideav-h264) 均真实存在。
- **存在严重的“真标题 + 假 arXiv 编号”大模型幻觉（Hallucination）**：在 `modern_steganography_technologies_survey_20261031.md` 中，列出的 **5 个 arXiv 编号（`2105.13080`、`2305.19103`、`2407.01234`、`2404.14567`、`2405.08901`）全部是伪造或张冠李戴的错误编号**（后三个甚至带有明显的顺子数字规律 `01234`、`14567`、`08901`），尽管它们对应的论文名称（`Meteor`、`Discop`、`Splats in Splats`、`SecureGS`、`GS-Hider`）在学术界确实存在。
- **存在多处关键算法机理误读与编码标准盲区**：特别是在 **3DGS 隐写实现复杂度**、**MP3/AAC 压缩域 Huffman 符号位隐写机理**、**LLM 隐写安全证明模型**、**FLAC 重编码指纹暴露**以及 **H.264/AVC CABAC 旁路进位传播与帧内空间漂移**上，原文档存在明显偏差，若直接照搬实施会导致工程返工或安全性失效。

### 1.1 文档一核查：`modern_steganography_technologies_survey_20261031.md`

#### （1）文献引用与 arXiv 编号核查对照表

| 原文档引用表述 | 真实性判定 | 核查事实与真实文献出处 |
| :--- | :--- | :--- |
| `Meteor (2021, arXiv:2105.13080)` | **标题真，编号假** | [arXiv:2105.13080](https://arxiv.org/abs/2105.13080) 实为一篇函数型数据拟合优度检验的统计学论文（*A review of goodness-of-fit tests for models involving functional data*）。`Meteor` 的真实出处为 Kaptchuk 等人发表于 **ACM CCS 2021** 的论文，预印本存放在 IACR ePrint 档案库：[IACR ePrint 2021/686](https://eprint.iacr.org/2021/686)。 |
| `Discop (2023, arXiv:2305.19103)` | **标题真，编号假** | [arXiv:2305.19103](https://arxiv.org/audio/2305.19103) 实为探讨大模型概念表征的认知科学论文（*Does Conceptual Representation Require Embodiment?*）。`Discop` 的真实出处为丁金扬、陈可江等人发表于 **IEEE S&P 2023** 的论文 [*Discop: Provably Secure Steganography in Practice Based on "Distribution Copies"*](https://dingjinyang.github.io/uploads/Discop_sp23_paper.pdf)（官方代码库：[comydream/Discop](https://github.com/comydream/Discop)）。 |
| `Splats in Splats / Splats in Splats++ (2024, arXiv:2407.01234)` | **标题真，编号顺子造假** | [arXiv:2407.01234](https://arxiv.org/abs/2407.01234) 实为电力储能设施最优控制的数学论文（*Optimal Control of a Power Storage Facility with Variable Payoffs*）。真实的 `Splats in Splats` 迟至 2024 年 12 月才提交（录用于 **AAAI 2026**），真实编号为 **[arXiv:2412.03121](https://arxiv.org/abs/2412.03121)**；其扩展版 `Splats in Splats++` 提交于 2026 年 4 月，真实编号为 **[arXiv:2604.15862](https://arxiv.org/abs/2604.15862)**。 |
| `SecureGS (2024, arXiv:2404.14567)` | **标题真，编号顺子造假** | [arXiv:2404.14567](https://arxiv.org/html/2404.14567v1) 实为临床皮肤科多模态医疗问答比赛报告（*WangLab at MEDIQA-M3G 2024*）。真实的 `SecureGS`（*Boosting the Security and Fidelity of 3D Gaussian Splatting Steganography*）录用于 **ICLR 2025**，真实编号为 **[arXiv:2503.06118](https://arxiv.org/abs/2503.06118)**。 |
| `GS-Hider (2024, arXiv:2405.08901)` | **标题真，编号顺子造假** | [arXiv:2405.08901](https://arxiv.org/pdf/2405.08901) 实为高能物理（`hep-ph`）方向论文。真实的 `GS-Hider`（*Hiding Messages into 3D Gaussian Splatting*）录用于 **NeurIPS 2024**，真实编号为 **[arXiv:2405.15118](https://arxiv.org/abs/2405.15118)**。 |
| `StegaINR (2023)` 与 `Noise-NeRF (2023)` | **真实存在** | `StegaINR` 对应 [arXiv:2312.04743](https://arxiv.org/html/2312.04743v1)；`Noise-NeRF` 对应 [arXiv:2401.01216](https://arxiv.org/abs/2401.01216)（2024 年 1 月提交）；此外该方向最具代表性的奠基工作是 **ICCV 2023** 的 `StegaNeRF`（[arXiv:2212.01602](https://arxiv.org/abs/2212.01602)）。 |
| `AudioSeal (Meta AI, 2024, ICML)` 与 `WavMark (2023, Interspeech)` | **部分偏差** | `AudioSeal`（[arXiv:2401.17264](https://arxiv.org/abs/2401.17264)）确实发表于 **ICML 2024**；而 `WavMark`（[arXiv:2308.12770](https://arxiv.org/abs/2308.12770)）是微软研究院 2023 年发布的预印本，发表于 Interspeech 的同类知名工作实为索尼 AI 的 `SilentCipher`。 |

#### （2）核心技术机理纠偏

1. **`Meteor` 的安全模型与编码机制误述**：
   原文档 §2.2 称 `Meteor`“运行算术编码，被数学证明达到信息论安全（Information-Theoretically Secure）”。事实上，根据 [IACR ePrint 2021/686](https://eprint.iacr.org/2021/686)，`Meteor` 证明的是在攻击者已知语言模型概率分布的前提下的**密码学计算安全（Cryptographic / Computational Security，归约至底层 CSPRNG 的不可区分性）**，而非信息论绝对安全；且 `Meteor` 的核心贡献恰恰是指出传统算术编码（如 Ziegler 2019）在多步累积下会因区间截断造成概率偏移，因此改用**每步重新用伪随机掩码异或的加密前缀区间采样**。真正追求信息论安全界（KL 散度趋近于 0）的现代方法主要是基于**最小熵耦合（Minimum Entropy Coupling）**的 `iMEC`（[arXiv:2210.14889](https://arxiv.org/abs/2210.14889)，ICML 2023）与基于分布拷贝的 `Discop`（[IEEE S&P 2023](https://dingjinyang.github.io/uploads/Discop_sp23_paper.pdf)）。
2. **3D Gaussian Splatting（3DGS）隐写机理与工程复杂度的严重误判**：
   原文档 §5.1 与 §6 声称 `GS-Hider`、`SecureGS`、`Splats in Splats` 的原理是“在 `.ply` 文件的高阶球谐系数（SH）或旋转四元数末位嵌入”，并评估其实现复杂度为“**中等（~300 行）| 纯 Rust PLY 解析器**”。
   这是对上述三篇论文的完全误读：
   - [`GS-Hider` (arXiv:2405.15118)](https://arxiv.org/abs/2405.15118) 将原始 3DGS 的球谐函数（SH）系数替换为一个**耦合安全特征属性（Coupled Secured Feature Attribute）**，并需要联合训练两个深度神经网络（Scene Decoder 与 Message Decoder）在渲染管线中解耦原始 RGB 场景与隐藏的 3D/图像信息。
   - [`SecureGS` (arXiv:2503.06118)](https://arxiv.org/abs/2503.06118) 基于 Scaffold-GS 锚点（Anchor Points）架构，利用隐私保护神经网络解码隐藏高斯点的偏移、缩放与旋转属性。
   - [`Splats in Splats` (arXiv:2412.03121)](https://arxiv.org/abs/2412.03121) 结合了重要性分级的 SH 系数加密与**卷积自编码器（Convolutional Autoencoder）**来映射原始高斯体与隐藏高斯体的不透明度。
   换言之，这三篇顶会论文全部依赖 **PyTorch + CUDA 可微光栅化训练与神经网络解码器**，绝不可能用 300 行纯 Rust PLY 解析器实现。如果 `strhide` 希望用 ~300 行纯 Rust 对 `.ply` 3DGS 资产做隐写，那属于**经典点云/高阶球谐系数浮点尾数的 QIM 或自适应 STC 隐写**（直接微调 `.ply` 中的 `f_rest_0..f_rest_44` 高阶球谐浮点数尾数），在规划中必须将“经典 `.ply` 高阶 SH 微扰隐写”与“神经 3DGS 场景隐写”明确区分。

---

### 1.2 文档二核查：`audio_steganography_research_and_implementation_plan_20261031.md`

#### （1）压缩音频（MP3 / AAC）内容域隐写的核心技术误区
原文档 §2 断言：“修改 MP3/AAC 量化频域系数会导致变长 Huffman 膨胀与比特库（Bit Reservoir）雪崩……因此真隐写最终还是落地在 PCM”。
这一结论忽略了 ISO/IEC 11172-3（MP3）与 ISO/IEC 13818-7 / 14496-3（AAC）标准中一个极其重要的比特流结构特性——**非零量化 MDCT 系数的符号位（Sign Bits）独立性**：
- 在 MP3（Layer III）和 AAC 的 Huffman 编码表（除少数带符号小码表外，在无符号码表与 `ESC` 逃逸序列 `linbits` 中）中，Huffman 码字仅编码量化系数的**幅值（Magnitude $|x|$）**，而每个非零系数的**正负号（Sign Bit）是以固定 1 比特明文形式紧跟在 Huffman 码字之后写入比特流的**（参见 [A Huffman Coding Section-based Steganography for AAC Audio](https://www.researchgate.net/publication/272964109_A_Huffman_Coding_Section-based_Steganography_for_AAC_Audio) 及 [Escape Sequences AAC Steganography (IEEE 5671308)](https://ieeexplore.ieee.org/document/5671308/)）。
- 因此，翻转高频非零 MDCT 量化系数的符号位（或修改大系数 `ESC` 逃逸扩展位 `linbits` 的奇偶性），**编码后的比特流长度严格保持不变（$\Delta = 0$）**，既不会触发变长 Huffman 码字膨胀，也不会波及帧头、`main_data_begin` 指针或比特库（Bit Reservoir）。
- 当然，这依然需要编写 MP3/AAC 帧级 Huffman 位流解析定位器（工作量约 1,000～1,500 行 Rust），因此将 WAV PCM 作为第一阶段 P0 目标在工程排期上是合理的，但文档中关于“修改 MP3/AAC 量化系数必然改变 Huffman 码长”的定性在编码理论上是不准确的。

#### （2）WAV 时域算法选型与 FLAC 重编码风险核查
1. **Block Parity（块奇偶校验）与 STC 的关系**：
   原文档 §3.1 将 `audio-stego-project` 中的 Block-Based Parity Coding（每 $N$ 个采样改 1 bit）与 §3.3 的 STC 并列推荐。实际上，从编码理论看，块奇偶校验只是将校验矩阵 $H$ 退化为单位分块向量 $[1, 1, \dots, 1]$ 的平凡线性分组码，其率失真性能远逊于 `strhide` 已经内置实现的 **STC（Syndrome-Trellis Codes）**。既然 `strhide` 已有成熟的 `stego/coding/stc.rs`，在 WAV PCM 上直接计算局部一阶/二阶差分能量代价 $\rho_i$ 并送入现有 STC 求解器，代码量同样不到 200 行，且抗隐写分析能力高出一个世代，完全没有必要再维护一套低阶的 Block Parity。
2. **Rust FLAC 依赖库状态与重编码取证破绽**：
   - 生态核查：原文档推荐的 [`claxon`](https://crates.io/crates/claxon) 最新版本停留在 2020 年 8 月的 `v0.4.3`，已超过 6 年未更新；截至 2026 年，Rust 生态中最成熟活跃的纯 Rust 音频解码库是 [`symphonia`](https://crates.io/crates/symphonia)（2026 年已发布 `v0.6.1`，子包 [`symphonia-bundle-flac`](https://crates.io/crates/symphonia-bundle-flac) 原生支持完整 FLAC 规范）。而 [`flacenc`](https://docs.rs/flacenc/latest/flacenc) 是纯 Rust FLAC 编码器，可用于重编码。
   - **取证安全警告**：必须注意到，将 `.flac` 解压为 PCM、修改采样后再用 `flacenc` 重新编码，虽然音频采样只有 $\pm 1$ 微扰，但 **`flacenc` 生成的子帧线性预测阶数（LPC Order）、Rice 熵编码分区参数、帧大小以及 `VENDOR` 编码器签名都会与原文件（通常由 `libFLAC` 生成）截然不同**。这与 JPEG 重压缩（Double Compression）同理，属于容易被容器/编码器指纹比对识破的“重编码隐写”，而非 MP4/HEVC 那样的原位（$\Delta = 0$）无痕隐写。

---

### 1.3 文档三核查：`mkv_and_avc_stego_implementation_plan_20261031.md`

#### （1）本地与开源 Rust H.264 仓库核查
经核查 crates.io 与 GitHub：
- [`rusty_h264`](https://github.com/remade-with-rust/rusty_h264)（[`crates.io/crates/rusty_h264`](https://crates.io/crates/rusty_h264)，2026 年 9 月更新至 `v0.16.1`）确实是纯 Rust、`#![forbid(unsafe_code)]` 且与 Cisco OpenH264 逐比特对齐的 H.264 编解码库。
- [`OxideAV/oxideav-h264`](https://github.com/OxideAV/oxideav-h264) 也确实是 2026 年活跃的纯 Rust H.264 编解码项目。

#### （2）MKV 容器原位隐写方案遗漏的两个标准级边界问题
文档三 §2.2 提出的“零拷贝 EBML Span 扫描器”架构方向非常扎实，但遗漏了 Matroska（RFC 9559）规范中的两个关键边界情况：
1. **轨道级头部剥离压缩（Header Stripping，`ContentCompAlgo = 3`）**：
   Matroska 标准允许在 `TrackEntry -> ContentEncodings (0x6D80) -> ContentEncoding (0x6240) -> ContentCompression (0x5034)` 中启用 `ContentCompAlgo = 3`（Header Stripping），将每个视频帧公共的前缀字节（例如长度前缀字节或 NAL Header 公共字节）剥离并存放在 `ContentCompSettings (0x4255)` 中。若 MKV 视频轨启用了该特性，直接把 `SimpleBlock` 载荷当作完整的 HVCC/AVCC 长度前缀 NAL 解析会彻底错位！因此在扫描 `TrackEntry` 时**必须检测 `ContentEncodings`（`0x6D80`）**，一旦发现存在压缩或加密编码，应明确拒绝（返回 `Unsupported`）或正确还原偏移。
2. **Cluster `CRC-32` 元素（`0xBF`）的精确作用范围**：
   文档三提到“若 MKV 使用了 Cluster 层 CRC-32（`0xBF`），需更新 CRC-32”。根据 RFC 9559（EBML 标准），`CRC-32` 元素必须是父 Master 元素（如 `Cluster`）的**第一个直接子元素**，且其 IEEE CRC-32 校验和仅覆盖**该父元素内位于 `CRC-32` 元素结束位置之后的全部字节**（不包含 `Cluster` 自身的 ID、VINT 大小以及 `CRC-32` 元素本身的 6 个字节）。在原位回写时必须严格按此区间重算，否则 `ffmpeg` 或 `mkvmerge` 校验会报 `EBML CRC-32 mismatch`。

#### （3）H.264/AVC CABAC 原位隐写必须警惕的三大算法陷阱
文档三 §3.1 认为：“翻转 H.264 CABAC 的 `coeff_sign_flag` 不会引起上下文漂移，且 H.264 没有 SDH（符号位隐藏），因此比 HEVC 更简单”。这一判断过于乐观，实际工程落地必须解决以下三个核心问题：
1. **H.264 Baseline / Constrained Baseline Profile 使用的是 CAVLC 而非 CABAC**：
   不同于 HEVC（全 Profile 统一强制使用 CABAC），H.264 中由 PPS 的 `entropy_coding_mode_flag` 决定熵编码模式：当 `entropy_coding_mode_flag == 0`（Baseline / Constrained Baseline / Extended Profile，广泛存在于 WebRTC、老旧手机录像、行车记录仪与监控视频）时，残差采用 **CAVLC（基于上下文的自适应变长编码）**；仅当 `entropy_coding_mode_flag == 1`（Main / High Profile）时才使用 CABAC。CAVLC 的 `TrailingOnes` 符号位与非零系数 `level_prefix / level_suffix` 符号位直接以裸比特形式嵌入在 VLC 码流中（翻转 `TrailingOnes` 符号位或 `level` 符号位反而连算术编码进位都没有，天然是 100% 物理比特原位翻转！），但两套语法解析完全不同，必须在 PPS 解析阶段先行分流或对 `entropy_coding_mode_flag == 0` 给出明确提示。
2. **CABAC Bypass 翻转并非天然保证 NAL 字节长度不变（进位传播与 `outstanding_bits`）**：
   虽然 `EncodeBypass` 不修改上下文概率表，但它会修改算术编码器的区间下界 `codILow = (codILow << 1) + (binVal * codIRange)`。当 `codILow >= 0x0400` 时会触发进位（Carry），沿着此前累积的 `outstanding_bits`（连续的 `0xFF` 比特）向前传播进位！这会导致从翻转点到前一个非挂起比特之间的多个输出字节发生翻转（例如 `0x7F 0xFF` 变为 `0x80 0x00`），进而：
   - 可能意外产生或消除 `0x000000`～`0x000003` 序列，改变防竞争字节（EPB `0x03`）的数量；
   - 在 Slice 末尾 `rbsp_slice_trailing_bits` 处可能改变终止位的对齐边界。因此多轮 EPB 冲突避让与严格等长验证（`new_nal.len() == orig_nal.len()`）在 H.264 CABAC 中同样不可或缺。
3. **帧内预测空间级联漂移（Intra Spatial Drift）与环路去块滤波传播**：
   在 H.264 和 HEVC 中，即便是非参考帧（Non-reference B/P slice），其内部的 Intra 宏块（或同一 I 帧内的所有宏块）都会使用**左邻与上邻块重建后的边界像素**作为当前块的帧内预测参考值！如果翻转了一个 4×4 或 8×8 DCT 块中影响右边界（$x=3$）或下边界（$y=3$）的系数符号，误差会像多米诺骨牌一样向右下方的所有相邻帧内宏块不断累积放大，产生肉眼可见的条纹伪影。因此 H.264 代价模型不能只看单块 DCT 基函数能量，必须对**帧内块（Intra MB）施加强惩罚或仅允许在非参考帧的帧间残差块（Inter MB，且后续块不对其进行空间预测）的高频位置嵌入**。

---

## 第二部分：截至 2026 年各文件格式最前沿隐写技术全景综述

随着深度学习隐写分析（Steganalysis，如 SRNet、EffNet、SiaStegNet、湛卢/Zhanlu 等）与大语言模型、扩散模型、3D 神经渲染的演进，2020～2026 年的现代隐写技术已经形成了**“最小化可微/统计最优失真 + 极化/网格码（STC/Polar Codes）”**（针对传统载体修改）与**“可证明分布保持采样（Distribution-Preserving Generative Steganography）”**（针对生成式 AI 载体）两大核心支柱。以下按文件格式类别梳理截至 2026 年的最前沿技术。

### 2.1 各大文件格式最前沿隐写技术总览表

| 载体大类 | 具体文件格式 | 2020–2026 最前沿代表技术 / 算法 | 核心嵌入域与机理 | 抗隐写分析安全性 / 特点 |
| :--- | :--- | :--- | :--- | :--- |
| **无损光栅图像** | PNG, BMP, TIFF, WebP (Lossless) | **MiPOD / GMRF** + **CMD / Synch** 非加性耦合 + **LISO** ([ICLR 2023](https://openreview.net/forum?id=gLPkzWjdhBN)) / **SPAR-RL** | 空域像素三元 $\pm 1$ 微扰；基于局部高斯方差估计或 GRU 神经迭代优化器动态学习代价，配合 STC / Polar 码 | 对抗 SRNet / CovNet 等深度隐写分析器能力最强；支持 RDH（PVO / MHM）实现 100% 比特级可逆还原 |
| **有损变换域图像** | JPEG, HEIC, AVIF, JPEG XL | **J-MiPOD** ([IEEE TIFS](https://cyber.kent.ac.uk/newsletters/DDD/NL-2021-4_University-of-Kent.pdf))、**e-J-UNIWARD**（边信息预载体）、彩色跨通道协方差模型 | 量化 DCT / ADST 系数三元 $\pm 1$ 调制；若有原始未压缩图则利用量化舍入误差（Precover Side-Information）定向非对称调制 | 解决了彩色 YCbCr 通道相关性暴露问题，在相同 bpnzac 下比传统 J-UNIWARD 降低 10%～18% 检测率 |
| **生成式扩散图像** | PNG / JPEG / WebP (AI 生成) | **Gaussian Shading** ([CVPR 2024](https://arxiv.org/abs/2404.04956))、**CRoSS** ([NeurIPS 2023](https://arxiv.org/abs/2305.16936))、**Tree-Ring** ([arXiv:2305.20030](https://arxiv.org/abs/2305.20030)) | 在扩散模型初始高斯潜变量（Latent Noise）或傅里叶环中通过分布保持采样嵌入，经 DDIM Inversion 盲提取 | **数学证明分布无损（Performance-Lossless）**，生成图像与普通扩散图同分布，且抗 JPEG 压缩、裁剪与重绘 |
| **现代视频与容器** | MP4, MOV, MKV (`H.264`, `HEVC`, `VVC`, `AV1`) | **CABAC Bypass 符号位 STC 原位调制** ([ResearchGate 2026](https://www.researchgate.net/publication/410986949_High_Capacity_Bitrate-Preserving_Video_Steganography_for_HEVC_Via_Codeword_Mapping_of_CABAC_Bypass-Coded_Sign_Flags))、**PU/IPM 多边形编码 + 深度滤波补偿 (IDLSNF)** ([IEEE 2026](https://www.computer.org/csdl/journal/tq/2026/03/11425004/2eOBLpaPToI)) | 原位路线：翻转非参考帧 CABAC 旁路残差/MVD 符号位并避让 EPB（$\Delta=0$）；重编码路线：调制帧内预测模式/PU 划分并用轻量 CNN 抵消预测漂移 | 原位方案实现**零文件膨胀（$\Delta=0$）与零容器改动**，毫秒级流式处理；深度补偿方案大幅提升高容量下的 PSNR |
| **无损与有损音频** | WAV, FLAC, AIFF, MP3, AAC, Opus | **心理声学掩蔽代价 + STC** ([The-A-Files](https://github.com/pawel-kaczmarek/The-A-Files))、**AAC/MP3 Huffman 符号位与逃逸码调制** ([IEEE 5671308](https://ieeexplore.ieee.org/document/5671308/))、**AudioSeal** ([ICML 2024](https://arxiv.org/abs/2401.17264)) / **Codec-Latent Watermarking** ([arXiv:2607.21132](https://arxiv.org/html/2607.21132v1)) | WAV：时频能量掩蔽 + STC 或可逆 PEE；MP3/AAC：非零 MDCT 系数独立符号位翻转（$\Delta=0$）；神经水印：16kHz 时域局部化对抗嵌入或 RVQ 潜空间嵌入 | MP3/AAC 符号位方案保持码流严格等长；2026 年最新神经音频方案可抵抗 EnCodec 等神经声码器重编码与零样本语音克隆 |
| **文本与自然语言** | TXT, Markdown, JSON, 社交文本 | **Meteor** ([ACM CCS 2021](https://eprint.iacr.org/2021/686))、**iMEC** ([ICML 2023](https://arxiv.org/abs/2210.14889))、**Discop** ([IEEE S&P 2023](https://dingjinyang.github.io/uploads/Discop_sp23_paper.pdf))、**Sparse Sampling** ([arXiv:2503.19499](https://arxiv.org/html/2503.19499v1)) | 利用 LLM 下一个 Token 的条件概率分布，通过分布拷贝旋转或最小熵耦合，使秘密比特控制采样过程而不改变输出边缘分布 | **可证明安全（Provably Secure）**：生成的隐写文本与正常采样文本在统计上完全不可区分（KL 散度为 0） |
| **版式文档与矢量** | PDF, DOCX/OOXML, OTF/TTF, SVG | **FontCode** ([ACM TOG](https://www.semanticscholar.org/paper/FontCode-Xiao-Zhang/a1ddd369a32546b47a95aa6d109041ec5f00405f))、**PDF `TJ` 字距微调与字符属性隐写** ([ResearchGate 2024](https://www.researchgate.net/publication/380462849_Text_steganography_enhanced_character-level_embedding_algorithm_using_font_attribute_with_increased_resilience_to_statistical_attacks))、**SVG 贝塞尔控制点 QIM** | 微扰字体字形轮廓控制点（支持打印拍照后 OCR 提取）、PDF `TJ` 操作符千分位字距微移、SVG 浮点尾数调制 | 远比零宽字符（ZWSP）隐蔽，能抵御纯文本复制剥离，FontCode 甚至能跨物理打印-扫描信道存活 |
| **3D 视觉与神经资产** | `.ply` (3DGS), `.obj`/`.glb`, NeRF/INR 权重 | **GS-Hider** ([NeurIPS 2024](https://arxiv.org/abs/2405.15118))、**SecureGS** ([ICLR 2025](https://arxiv.org/abs/2503.06118))、**Splats in Splats / ++** ([AAAI 2026](https://arxiv.org/abs/2412.03121) / [arXiv:2604.15862](https://arxiv.org/abs/2604.15862))、`.ply` 高阶 SH QIM/STC | 神经派：耦合安全特征场或 Scaffold-GS 锚点加密 + 神经网络解码；经典派：对 `.ply` 3阶球谐系数（45 维 `f_rest`）浮点尾数做局部密度自适应 STC | 3DGS 点云含百万级高斯图元，单文件可隐藏数 MB 数据或完整 3D 子场景，多视角渲染 PSNR > 40 dB |
| **可执行程序与代码** | PE (`.exe`/`.dll`), ELF, Wasm, 源代码 | **指令同义置换与寄存器重分配** ([Hydan](https://academiccommons.columbia.edu/doi/10.7916/D8V414JC/download) 演进 + STC)、**AST 等价变换与 LLM 代码生成隐写** | 机器码层：利用等价 x86-64/ARM64 指令编码对（如交换律操作数方向位）结合 STC；源码层：结合 LLM Token 采样生成合法代码 | 二进制体积与签名节区布局零改变（$\Delta=0$），代码正常编译/执行且通过静态控制流完整性检查 |

---

### 2.2 图像格式隐写前沿（PNG / BMP / WebP / JPEG / HEIC / Diffusion）

#### 1. 空域与无损图像（PNG / BMP / TIFF / WebP Lossless）：从启发式代价到神经迭代优化
传统的空域自适应隐写（如 `strhide` 已实现的 **HILL** 与 **S-UNIWARD**）通过高通滤波器衡量局部纹理复杂度，并为每个像素独立分配加性修改代价（Additive Distortion）。近年来该领域的三大突破为：
- **统计最优与非加性同步代价（MiPOD + CMD / Synch）**：
  **MiPOD** 基于局部像素残差的多元高斯分布模型，直接最小化似然比检验的最优检测功效（Deflection Coefficient）。在此基础上，**CMD（Clustering Modification Directions）** 与 **Synch（Synchronizing Modification Directions）** 打破了“相邻像素失真相互独立”的假设，鼓励相邻像素向相同方向（同为 $+1$ 或同为 $-1$）微调，从而保持局部高通残差的平滑性，在不增加计算复杂度的前提下将抗 SRNet 检测能力提升 15% 以上。
- **对抗性与神经迭代代价优化（ADV-EMB / SPAR-RL / LISO）**：
  针对深度卷积隐写分析网络（如 SRNet、CovNet），学术界提出了利用梯度符号对抗扰动调整代价的 **ADV-EMB**、基于强化学习寻找最优代价的 **SPAR-RL**，以及发表于 ICLR 2023 的 **LISO**（[Learning Iterative Neural Optimizers for Image Steganography](https://openreview.net/forum?id=gLPkzWjdhBN)，开源代码见 [cxy1997/LISO](https://github.com/cxy1997/LISO)）。LISO 利用门控循环单元（GRU）在自然图像流形上进行端到端迭代优化，无需依赖慢速的网格编码即可快速收敛到极低可检测性的隐写图像。
- **高精度可逆数据隐藏（RDH：PVO 与多直方图平移 MHM）**：
  在医疗、司法与高敏取证图像中，2020～2026 年的主流 RDH 算法已从早期的差分扩展（DE）和单直方图平移（HS）演进为 **像素值排序（PVO, Pixel-Value Ordering）** 与 **多直方图修改（MHM, Multiple Histograms Modification）**。通过将图像分块并对块内像素排序，仅利用块内最大值与次大值、最小值与次小值的预测误差进行扩展，可在同等嵌入容量下将 PSNR 提升至 $58\sim 62\text{ dB}$，且提取后宿主文件 SHA-256 100% 还原。
- **WebP 图像隐写**：
  WebP 分为基于 VP8 帧内预测的有损模式与基于 **VP8L** 的无损模式。最新研究（如 [An Efficient Steganographic Protocol for WebP Files, MDPI 2023](https://www.mdpi.com/2076-3417/13/22/12404)）指出：对于无损 WebP，可直接解压为 RGBA 像素矩阵运行 HILL/MiPOD + STC 后重编码为 VP8L；或在 VP8L 比特流的 LZ77 向后引用距离码与 Color Cache 索引中做无损等价替换。

#### 2. 有损变换域图像（JPEG / HEIC / AVIF）：J-MiPOD、边信息与彩色通道耦合
- **J-MiPOD 与彩色通道联合建模**：
  Cogranne 等人提出的 **J-MiPOD**（[DDD Tech Watch Review](https://cyber.kent.ac.uk/newsletters/DDD/NL-2021-4_University-of-Kent.pdf)）将 MiPOD 统计高斯模型推广至 8×8 量化 DCT 域，通过先局部去块再估计二维子带方差来求解每个 DCT 系数的改变概率。近年来針對彩色 JPEG 图像的研究发现，独立在 Y、Cb、Cr 通道嵌入会破坏跨通道残差相关性（被色度敏感型深度网络捕获），因此前沿方案采用 **RGB 空域反投影失真（Decompressed Spatial Distortion）** 来联合约束亮度和色度 DCT 系数的修改方向。
- **预载体边信息隐写（Side-Informed Steganography, e-J-UNIWARD）**：
  当嵌入端拥有压缩前的原始无损图像（例如相机直出或截图转存 JPEG）时，计算 8×8 DCT 系数在量化时的真实舍入误差 $e_{ij} = d_{ij} - \text{round}(d_{ij}) \in [-0.5, 0.5]$。对于舍入误差接近 $\pm 0.5$ 的系数，向原值方向微调 1 个量化步长的代价趋近于 0，而反方向代价极大。这种非对称失真设计是目前学术界公认安全容量最高的 JPEG 隐写方案。

#### 3. 扩散模型生成式隐写（Diffusion-Based Generative Steganography, 2023–2026）
这是 2023～2026 年计算机视觉顶会最火热的颠覆性范式：不再修改现有图像，而是将秘密信息直接融入 Stable Diffusion / Flux 等扩散模型的生成过程：
- **CRoSS**（[NeurIPS 2023, arXiv:2305.16936](https://arxiv.org/abs/2305.16936)）：利用扩散模型的前向 DDIM Inversion 与反向确定性去噪对称性，将秘密图像映射为潜空间条件引导，实现高鲁棒性的无载体图像隐写。
- **Tree-Ring Watermarks**（[Wen et al., arXiv:2305.20030](https://arxiv.org/abs/2305.20030)）：在初始高斯噪声潜变量的傅里叶频域同心圆环上植入结构化密钥图案，生成图像后通过 DDIM 反演回初始噪声空间进行匹配检测。
- **Gaussian Shading**（[Yang et al., CVPR 2024, arXiv:2404.04956](https://arxiv.org/abs/2404.04956)，官方代码：[bsmhmmlf/Gaussian-Shading](https://github.com/bsmhmmlf/Gaussian-Shading)）：目前该方向的里程碑工作。它通过水印扩散、流密码随机化与**分布保持采样（Distribution-Preserving Sampling）**，将秘密比特直接映射为严格服从标准正态分布 $\mathcal{N}(0, I)$ 的初始潜变量采样点。数学上可严格证明其生成图像的分布与无隐写模型**完全一致（Performance-Lossless）**，无需任何额外训练，即可在单张生成图中隐藏数百比特信息并抵抗高强度 JPEG 压缩与噪声攻击。
- **2026 年最新安全审视**：2026 年初的研究 [*Rethinking Security of Diffusion-based Generative Steganography* (arXiv:2602.10219)](https://arxiv.org/html/2602.10219v1) 揭示，若攻击者能够检测 DDIM 反演残差轨迹的对称性异常或多次重用相同密钥种子，部分早期扩散隐写（如 StegaDDPM）仍存在统计泄露风险，因此必须保证每次嵌入使用一次性密码学非重用种子。

---

### 2.3 视频与流媒体容器格式隐写前沿（H.264/AVC, H.265/HEVC, AV1, MP4/MKV）

现代视频隐写明确分化为**“原位比特流域（Bitrate-Preserving In-Place Domain，$\Delta=0$）”**与**“重编码语法/模式域（Re-encoding Syntax Domain）”**两条技术路线：

#### 1. 原位零膨胀比特流路线（CABAC Bypass Sign Modulation）
- **核心机理**：以 `strhide` 现有的 HEVC 引擎及学术界最新工作（如 [High Capacity Bitrate-Preserving Video Steganography for HEVC Via Codeword Mapping of CABAC Bypass-Coded Sign Flags, 2026](https://www.researchgate.net/publication/410986949_High_Capacity_Bitrate-Preserving_Video_Steganography_for_HEVC_Via_Codeword_Mapping_of_CABAC_Bypass-Coded_Sign_Flags) 和 [IEEE Access 2020](https://ieeexplore.ieee.org/iel7/6287639/8948470/09046749.pdf)）为代表。利用 H.264/AVC（Main/High Profile）与 H.265/HEVC 中变换系数符号位（`coeff_sign_flag`）及运动矢量差符号位（`mvd_sign_flag`）采用 CABAC 等概率旁路（Bypass）编码的特性，在不改变上下文概率状态的前提下翻转符号位，并通过多轮 STC 避让防竞争字节（EPB `0x03`）冲突，确保每个 Slice NAL 单元的字节长度严格不变（$\Delta = 0$）。
- **工程优势**：由于 NAL 字节数不变，外层容器（无论是 MP4/MOV 的 `stsz`/`stco`/`co64` 采样表，还是 MKV 的 `SimpleBlock` 与 `Cues` 索引）**完全不需要重打包**，可在保持容器二进制指纹 100% 原样的前提下完成隐写。

#### 2. 预测模式与划分单元重编码路线（IPM / PU Partition + 深度滤波补偿）
- **最新进展（2026）**：2026 年发表于 IEEE 的 [*Large Capacity H.265/HEVC Video Steganography Based on Polygon Encoding and DLSN*](https://www.computer.org/csdl/journal/tq/2026/03/11425004/2eOBLpaPToI) 将 P 帧中相邻预测单元（PU）的划分模式映射到二维多边形坐标系中进行高容量编码，并引入改进型深度可学习相似性网络滤波器（**IDLSNF**）对重构帧进行补偿，有效抑制了帧间预测失真累积（Inter-frame Distortion Drift）。
- **生成式与抗转码视频水印（2026）**：针对短视频平台强制二次转码（H.264/HEVC/AV1 重压缩）的场景，2026 年最新的 [*Codec-Robust Video Watermarking with Generative Video Priors* (arXiv:2609.26236)](https://arxiv.org/html/2609.26236) 利用生成式视频先验将信息嵌入在跨帧高度稳定的中频时空特征中，使其在经历平台有损转码后仍可提取。

---

### 2.4 音频格式隐写前沿（WAV / FLAC / MP3 / AAC / Neural Audio Codecs）

#### 1. 未压缩与无损音频（WAV / AIFF / FLAC）：心理声学代价 + STC 与可逆 PEE
- 基于 [The-A-Files](https://github.com/pawel-kaczmarek/The-A-Files) 统一评测基准与 [Tolsi/awesome-steganography](https://github.com/Tolsi/awesome-steganography/blob/main/categories/03-audio-steganography.md) 的实证对比，在 16-bit/24-bit PCM 时域上，简单的 LSB 或固定块奇偶校验已属于容易被二阶差分马氏链（Markov transition features）或深度学习音频隐写分析器识破的早期方案。
- **当前最优实践**：计算短时傅里叶变换（STFT）或局部高通滤波能量残差，将静音段与纯音（Tonal）段的代价设为无穷大（`WET`），仅在瞬态冲击（Transient）与宽带噪声掩蔽段按能量梯度分配低代价，随后调用 **STC 综合网格码**进行 $\pm 1$ 三元嵌入；对于要求提取后原文件哈希零变化的场景，则采用 **可逆预测误差扩展（Reversible PEE）**。

#### 2. 压缩比特流音频（MP3 / AAC）：Huffman 符号位与自适应码表映射（AHCM）
- **非零 MDCT 量化系数符号位翻转 + STC**：如前文核查所述，直接解析 MP3/AAC 帧内的 Huffman 数据区，定位高频比例因子频带（Scale Factor Bands）中幅值 $|x|=1$ 的非零量化系数，将其跟随的 1-bit 裸符号位作为 STC 槽位进行翻转（[ResearchGate 2026](https://www.researchgate.net/publication/272964109_A_Huffman_Coding_Section-based_Steganography_for_AAC_Audio)）。该方案实现了真正的 **MP3/AAC 原位零膨胀隐写（$\Delta = 0$）**，无二次重编码失真。
- **自适应 Huffman 码字映射（AHCM）**：结合心理声学模型，在等长 Huffman 码字对或 `ESC` 逃逸序列 `linbits` 上执行自适应映射（[AHCM, ResearchGate](https://www.researchgate.net/publication/330647033_AHCM_Adaptive_Huffman_Code_Mapping_for_Audio_Steganography_Based_on_Psychoacoustic_Model)）。

#### 3. 神经音频水印与抗神经声码器隐写（2024–2026）
- **局部化时域对抗水印**：Meta AI 的 **AudioSeal**（[ICML 2024, arXiv:2401.17264](https://arxiv.org/abs/2401.17264)）将隐写/水印检测精度推到了单个采样点级别（1/16,000 秒），不仅能提取载荷，还能在一段被拼接篡改的音频中精确定位出哪几百毫秒被替换过。
- **抗神经编解码器（RVQ）与抗语音克隆前沿（2026）**：随着 EnCodec、SoundStream、DAC 等残差矢量量化（RVQ）神经音频编解码器在语音生成中的普及，传统波形微扰会被 RVQ 离散化彻底抹除。2026 年的最新研究 **VoiceMark**（[ResearchGate 2026](https://www.researchgate.net/publication/396804376_VoiceMark_Zero-Shot_Voice_Cloning-Resistant_Watermarking_Approach_Leveraging_Speaker-Specific_Latents)）与 **Codec-Internal Latent Audio Watermarking**（[arXiv:2607.21132](https://arxiv.org/html/2607.21132v1)）直接在神经解码器之前的连续潜变量（Pre-decoder Continuous Latents）或说话人特征空间中嵌入信息，使其在经历神经声码器重构乃至零样本语音克隆后依然可被提取。

---

### 2.5 文本、自然语言（LLM）、版式文档（PDF / OOXML / Font）与 SVG 隐写前沿

#### 1. 可证明安全的 LLM 生成式自然语言隐写（2021–2026）
传统修改式文本隐写（如 Unicode 零宽字符 ZWSP、空白符 SNOW、同形异义字 Homoglyphs）虽实现极简，但只要经过 Unicode 规范化（NFC/NFKC）或码点扫描便一览无余。2021～2026 年自然语言隐写的绝对主流是**可证明安全的自回归生成式隐写（Provably Secure Generative Steganography）**：
- **Meteor**（[ACM CCS 2021, IACR 2021/686](https://eprint.iacr.org/2021/686)）：用 CSPRNG 伪随机位流对前缀区间进行动态异或掩码，解决了算术编码多步采样中的前缀偏差。
- **iMEC**（[Schroeder de Witt et al., ICML 2023, arXiv:2210.14889](https://arxiv.org/abs/2210.14889)）：将隐写编码建模为均匀分布密文块与 LLM Token 预测分布之间的**最小熵耦合（Minimum Entropy Coupling）**问题，逼近香农熵理论容量上限。
- **Discop**（[Ding et al., IEEE S&P 2023](https://dingjinyang.github.io/uploads/Discop_sp23_paper.pdf)）：通过构造多个旋转相位的“概率分布副本（Distribution Copies）”，由秘密比特决定从哪一个副本中采样，从而在不改变单个 Token 采样概率分布的前提下实现零 KL 散度嵌入。
- **2025–2026 稀疏采样与高吞吐演进**：针对大词表 LLM（如词表大小 $V > 128,000$）构建二叉树或耦合矩阵耗时过长的问题，2025 年提出的 **Sparse Sampling Steganography**（[arXiv:2503.19499](https://arxiv.org/html/2503.19499v1)）与高效大模型隐写框架（[arXiv:2501.00786](https://arxiv.org/pdf/2501.00786)、[arXiv:2504.08977](https://arxiv.org/pdf/2504.08977)）将单步编码复杂度降至 $O(1)$，并在多语言开源模型上实现了实时零偏差隐写。

#### 2. 版式文档（PDF / Word OOXML）、字体（Font）与矢量图（SVG）内容域隐写
- **PDF 内容流字距微调（`TJ` Operator Kerning Modulation）**：
  不同于在 PDF 末尾追加增量对象的结构域隐藏，PDF **内容域真隐写**直接作用于页面内容流（Content Stream）中的 `TJ` 文本排版数组，例如 `[(H) -3 (e) 2 (llo)] TJ`。在 PDF 规范中，`TJ` 数组中的数值表示以千分之一文本空间单位（$1/1000\text{ em}$）计算的字距微调量。将字距调整 $\pm 1\sim 2$ 个千分位单位（视觉位移小于 $0.01\text{ pt}$，人眼与截图比对均完全不可见），即可在每一对相邻字符间编码 1 bit 信息，且能完美通过 PDF 重线性化（Linearization）与增量剥离。
- **字体字形轮廓微扰（FontCode）与字符属性编码**：
  哥伦比亚大学提出的 **FontCode**（[Xiao et al., ACM TOG 2018](https://www.semanticscholar.org/paper/FontCode-Xiao-Zhang/a1ddd369a32546b47a95aa6d109041ec5f00405f)）与 2024 年最新演进的字符级微属性算法（[ResearchGate 2024](https://www.researchgate.net/publication/380462849_Text_steganography_enhanced_character-level_embedding_algorithm_using_font_attribute_with_increased_resilience_to_statistical_attacks)）通过微移内嵌字体（TrueType/OpenType）或文档中单个字形的贝塞尔曲线控制点，不仅在电子屏幕上不可察觉，甚至在**打印到纸张再用手机拍照后**仍可通过卷积网络恢复出隐藏信息。
- **SVG 矢量路径浮点量化调制（QIM）**：
  对 SVG `<path d="..."/>`、`<polygon points="..."/>` 中的浮点坐标在小数点后第 4～5 位实施带步长 $\Delta = 10^{-4}$ 的量化索引调制（QIM）或奇偶编码，并跳过整数坐标（如 `0`、`100`）以防暴露反常小数尾数。

---

### 2.6 3D 神经视觉资产（3DGS / NeRF）与可执行二进制（PE / ELF）隐写前沿

#### 1. 3D Gaussian Splatting（3DGS）与神经辐射场（NeRF, 2023–2026）
3D 资产隐写目前存在两条截然不同的技术栈：
- **学术界深度神经耦合栈（面向高维资产隐写与抗渲染攻击）**：
  - **StegaNeRF**（[ICCV 2023, arXiv:2212.01602](https://arxiv.org/abs/2212.01602)）、**StegaINR**（[arXiv:2312.04743](https://arxiv.org/html/2312.04743v1)）与 **Noise-NeRF**（[arXiv:2401.01216](https://arxiv.org/abs/2401.01216)）：通过在 NeRF MLP 权重微调或可训练噪声输入中隐藏二维图像，使得从特定相机位姿渲染并通过提取网络时可恢复秘密图像。
  - **GS-Hider**（[NeurIPS 2024, arXiv:2405.15118](https://arxiv.org/abs/2405.15118)）、**GaussianStego**（[arXiv:2407.01301](https://arxiv.org/abs/2407.01301)）、**SecureGS**（[ICLR 2025, arXiv:2503.06118](https://arxiv.org/abs/2503.06118)）与 **Splats in Splats / ++**（[AAAI 2026, arXiv:2412.03121](https://arxiv.org/abs/2412.03121) / [arXiv:2604.15862](https://arxiv.org/abs/2604.15862)）：针对 3DGS `.ply` 点云文件公开透明、直接修改几何坐标易被点云可视化看穿的痛点，设计了耦合特征属性、Scaffold-GS 锚点神经加密与重要性分级球谐系数（SH）自编码器映射，实现了“在 3D 场景中隐藏另一个 3D 场景”且抗点云裁剪与视角变换。
- **工程界轻量无损栈（面向 `.ply` 文件级纯 Rust 嵌入）**：
  标准 3DGS `.ply` 文件每个高斯顶点包含 62 个 `f32` 属性（3 个位置坐标 `x,y,z`、3 个法线、3 个 0 阶球谐直流分量 `f_dc_0..2`、**45 个 1～3 阶球谐高频分量 `f_rest_0..44`**、1 个不透明度 `opacity`、3 个缩放 `scale_0..2`、4 个旋转四元数 `rot_0..3`）。其中 45 个高阶球谐系数仅影响随视角变化的微弱高光反射，对 IEEE 754 `f32` 尾数（Mantissa）最低位执行基于不透明度与梯度权重的 **STC 自适应调制**，无需任何深度学习依赖即可在数毫秒内向一个 200 MB 的 `.ply` 场景无损嵌入数 MB 密文，且保持 `.ply` 文件字节长度严格不变（$\Delta = 0$）。

#### 2. 可执行二进制（PE / ELF / Wasm）：指令同义编码与 STC
- 自经典的 **Hydan**（[El-Khalil & Keromytis, Columbia University](https://academiccommons.columbia.edu/doi/10.7916/D8V414JC/download)）开创 x86 等价指令替换以来，早期方法因固定比例替换 `ADD/SUB` 或交换操作数编码方向，容易被操作码 $n$-gram 频率统计检测（[Steganalysis of Hydan](https://www.researchgate.net/publication/220722486_Steganalysis_of_Hydan)）。
- 现代二进制内容域隐写（如 `strhide` 在 `pe_codebits.rs` 中探索的方向）通过引入**局部指令频率先验代价 + STC 综合征网格编码**，将指令编码方向位（如 x86 `0x01 / 0x03` 寄存器-寄存器 `ADD/MOV/CMP/XOR/AND/OR` 的 ModR/M `d` 方向位）的修改率压低至 $5\%$ 以下，从而在完全不改变代码节（`.text`）长度、不破坏重定位表与控制流图的前提下抵抗指令分布统计分析。

---

## 第三部分：对 `strhide` 下一阶段技术演进的实操建议

结合第一部分的核查纠偏与第二部分的前沿全景，针对 `strhide` 的“纯 Rust、单一静态二进制、原位无损（$\Delta = 0$）优先、高抗检性”定位，建议按以下务实优先级推进：

| 优先级 | 扩展模块 | 推荐实施方案（经核查纠偏后） | 规避的原文档陷阱 |
| :--- | :--- | :--- | :--- |
| **P0（立即可做）** | **MKV 容器 HEVC 原位隐写** (`stego/hevc/mkv_boxes.rs`) | 复用 `ebml.rs` 编写零拷贝物理 NAL Span 扫描器，解析 `V_MPEGH/ISO/HEVC` 的 `CodecPrivate (hvcC)` 与 `SimpleBlock/Block` | 必须检查并拒绝 `ContentCompAlgo = 3`（Header Stripping 压缩轨），并按 RFC 9559 精确重算 Cluster `0xBF` CRC-32 |
| **P0（立即可做）** | **WAV / AIFF PCM 自适应 STC 音频隐写** (`stego/audio/wav.rs`) | 直接基于一阶/二阶局部能量差分构建代价映射并调用现有 `stego/coding/stc.rs`，同时提供 `--reversible` 可逆 PEE 模式 | 放弃退化的 Block Parity（STC 在相同修改率下安全性远高于块奇偶），无需重复造轮子 |
| **P1（高价值扩展）** | **H.264/AVC 原位视频隐写** (`stego/avc/`) | 基于 `rusty_h264` + `oxideav-h264` 构建 CABAC `coeff_sign_flag` 旁路原位重写器，支持 MP4 (`avc1`/`avcC`)、MKV 与 Annex-B | 必须在 PPS 中区分 `entropy_coding_mode_flag`（拒绝或单独处理 CAVLC），并对 Intra 宏块施加强代价惩罚以防止帧内空间预测级联漂移 |
| **P1（高价值扩展）** | **PNG / JPEG 失真模型升级** (`MiPOD` / `J-MiPOD` + `CMD`) | 在现有 `stego/png` 和 `stego/jpeg` 中增加 `mipod` / `j-mipod` 代价模型与非加性 CMD 同步策略，以及 PNG 可逆 PVO 模式 | 纯数学矩阵/方差递推计算，零外部依赖，直接将图像抗深度隐写分析能力提升至学术界最高基线 |
| **P2（特色载体扩展）** | **3DGS `.ply` 球谐系数原位 STC 隐写**与 **PDF `TJ` 字距隐写** | 对 `.ply` 顶点属性的 45 个高阶球谐系数 `f_rest_0..44` 的 IEEE 754 `f32` 尾数 LSB 执行自适应 STC 原位嵌入（$\Delta=0$） | 厘清“经典 `.ply` 高阶 SH 原位 STC 隐写”与需要 PyTorch 训练的 `GS-Hider`/`SecureGS` 的本质区别，保持纯 Rust 零运行时负担 |

---

## 参考资料与核查信源索引

1. Kaptchuk, G., Jois, T. M., Green, M., & Rubin, A. (2021). [Meteor: Cryptographically Secure Steganography for Realistic Distributions (IACR Cryptology ePrint Archive 2021/686)](https://eprint.iacr.org/2021/686).
2. Ding, J., Chen, K., Wang, Y., et al. (2023). [Discop: Provably Secure Steganography in Practice Based on "Distribution Copies" (IEEE S&P 2023)](https://dingjinyang.github.io/uploads/Discop_sp23_paper.pdf) & [GitHub: comydream/Discop](https://github.com/comydream/Discop).
3. Schroeder de Witt, C., Sokota, S., Kolter, J. Z., Foerster, J., & Strohmeier, M. (2023). [Perfectly Secure Steganography Using Minimum Entropy Coupling (ICML 2023, arXiv:2210.14889)](https://arxiv.org/abs/2210.14889).
4. [Efficient Provably Secure Steganography Based on Sparse Sampling (arXiv:2503.19499, 2025)](https://arxiv.org/html/2503.19499v1) & [Secure, High-Capacity and Efficient Steganography via Large Language Models (arXiv:2501.00786, 2025)](https://arxiv.org/pdf/2501.00786).
5. Zhang, X., Meng, J., Li, R., Xu, Z., Zhang, Y., & Zhang, J. (2024). [GS-Hider: Hiding Messages into 3D Gaussian Splatting (NeurIPS 2024, arXiv:2405.15118)](https://arxiv.org/abs/2405.15118).
6. Zhang, X., Meng, J., Xu, Z., et al. (2025). [SecureGS: Boosting the Security and Fidelity of 3D Gaussian Splatting Steganography (ICLR 2025, arXiv:2503.06118)](https://arxiv.org/abs/2503.06118).
7. Guo, Y., Huang, W., Li, Y., et al. (2024/2026). [Splats in Splats: Robust and Effective 3D Steganography towards Gaussian Splatting (AAAI 2026, arXiv:2412.03121)](https://arxiv.org/abs/2412.03121) & [Splats in Splats++ (arXiv:2604.15862)](https://arxiv.org/abs/2604.15862).
8. Li, X., et al. (2024). [GaussianStego: A Generalizable Steganography Pipeline for Generative 3D Gaussians Splatting (arXiv:2407.01301)](https://arxiv.org/abs/2407.01301).
9. Li, C., et al. (2023). [StegaNeRF: Embedding Invisible Information within Neural Radiance Fields (ICCV 2023, arXiv:2212.01602)](https://arxiv.org/abs/2212.01602), [StegaINR (arXiv:2312.04743)](https://arxiv.org/html/2312.04743v1), & [Noise-NeRF (arXiv:2401.01216)](https://arxiv.org/abs/2401.01216).
10. Yang, Z., Zeng, K., Chen, K., Fang, H., Zhang, W., & Yu, N. (2024). [Gaussian Shading: Provable Performance-Lossless Image Watermarking for Diffusion Models (CVPR 2024, arXiv:2404.04956)](https://arxiv.org/abs/2404.04956) & [GitHub: bsmhmmlf/Gaussian-Shading](https://github.com/bsmhmmlf/Gaussian-Shading).
11. Yu, J., Zhang, X., Xu, Y., & Zhang, J. (2023). [CRoSS: Diffusion Model Makes Controllable, Robust and Secure Image Steganography (NeurIPS 2023, arXiv:2305.16936)](https://arxiv.org/abs/2305.16936).
12. Wen, Y., Kirchenbauer, J., Geiping, J., & Goldstein, T. (2023). [Tree-Ring Watermarks: Fingerprints for Diffusion Images that are Invisible and Robust (arXiv:2305.20030)](https://arxiv.org/abs/2305.20030).
13. [Rethinking Security of Diffusion-based Generative Steganography (arXiv:2602.10219, 2026)](https://arxiv.org/html/2602.10219v1).
14. Chen, X., Kishore, V., & Weinberger, K. Q. (2023). [LISO: Learning Iterative Neural Optimizers for Image Steganography (ICLR 2023)](https://openreview.net/forum?id=gLPkzWjdhBN) & [GitHub: cxy1997/LISO](https://github.com/cxy1997/LISO).
15. San Roman, R., Fernandez, P., Elsahar, H., Défossez, A., Furon, T., & Tran, T. (2024). [Proactive Detection of Voice Cloning with Localized Watermarking / AudioSeal (ICML 2024, arXiv:2401.17264)](https://arxiv.org/abs/2401.17264).
16. Chen, G., Wu, Y., Liu, S., Liu, T., Du, X., & Wei, F. (2023). [WavMark: Watermarking for Audio Generation (arXiv:2308.12770)](https://arxiv.org/html/2509.19812).
17. [Investigating Codec-Internal Latent Audio Watermarking for Neural Audio Codecs (arXiv:2607.21132, 2026)](https://arxiv.org/html/2607.21132v1) & [VoiceMark: Zero-Shot Voice Cloning-Resistant Watermarking (2026)](https://www.researchgate.net/publication/396804376_VoiceMark_Zero-Shot_Voice_Cloning-Resistant_Watermarking_Approach_Leveraging_Speaker-Specific_Latents).
18. [A Huffman Coding Section-based Steganography for AAC Audio (ResearchGate)](https://www.researchgate.net/publication/272964109_A_Huffman_Coding_Section-based_Steganography_for_AAC_Audio) & [A Steganography Method for AAC Audio Based on Escape Sequences (IEEE Xplore)](https://ieeexplore.ieee.org/document/5671308/).
19. [High Capacity Bitrate-Preserving Video Steganography for HEVC Via Codeword Mapping of CABAC Bypass-Coded Sign Flags (ResearchGate, 2026)](https://www.researchgate.net/publication/410986949_High_Capacity_Bitrate-Preserving_Video_Steganography_for_HEVC_Via_Codeword_Mapping_of_CABAC_Bypass-Coded_Sign_Flags) & [Large Capacity H.265/HEVC Video Steganography Based on Polygon Encoding and DLSN (IEEE, 2026)](https://www.computer.org/csdl/journal/tq/2026/03/11425004/2eOBLpaPToI).
20. [Codec-Robust Video Watermarking with Generative Video Priors (arXiv:2609.26236, 2026)](https://arxiv.org/html/2609.26236).
21. Xiao, C., Zhang, C., & Zheng, C. (2018). [FontCode: Embedding Information in Text Documents using Glyph Perturbation (ACM Transactions on Graphics)](https://www.semanticscholar.org/paper/FontCode-Xiao-Zhang/a1ddd369a32546b47a95aa6d109041ec5f00405f).
22. Kaczmarek, P. [The-A-Files: Research toolkit for evaluating audio steganography and watermarking](https://github.com/pawel-kaczmarek/The-A-Files), [Tolsi/awesome-steganography](https://github.com/Tolsi/awesome-steganography/blob/main/categories/03-audio-steganography.md), [remade-with-rust/rusty_h264](https://github.com/remade-with-rust/rusty_h264), [OxideAV/oxideav-h264](https://github.com/OxideAV/oxideav-h264), [symphonia](https://crates.io/crates/symphonia), & [flacenc](https://docs.rs/flacenc/latest/flacenc).
