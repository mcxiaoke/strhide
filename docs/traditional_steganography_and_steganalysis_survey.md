# 传统图像隐写术与近5年（2021–2026）隐写分析检测算法全面综述

传统（非神经网络）隐写术的核心范式是**最小失真框架（Minimal Distortion Framework）**：先根据载体图像的局部纹理复杂度或统计模型手工设计**嵌入代价函数（Embedding Cost）**，再通过**校验格码（[Syndrome-Trellis Codes, STC](http://dde.binghamton.edu/download/syndrome/)）**或隐写极化码（SPC）在最小化总失真的前提下嵌入秘密信息（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。近5年（2021–2026年），针对此类内容自适应隐写术的隐写分析（Steganalysis）已全面转向**受高通滤波先验约束的深度残差网络、二阶协方差池化、轻量化多视角网络以及图神经网络关系挖掘模型**。

## 一、 最先进的传统隐写算法（非神经网络）与开源项目

在非神经网络范畴内，抗检测能力最强的算法均属于**内容自适应隐写术（Content-Adaptive Steganography）**，通过将修改（通常为像素值或 DCT 系数的 $\pm 1$ 扰动）集中在难以被统计建模的高频复杂纹理区来规避检测（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。

### 1. 核心抗检测传统隐写算法对比

| 算法名称 | 嵌入域 | 提出年份 | 核心抗检测原理 | 抗检测能力与性能特点 |
| :--- | :--- | :---: | :--- | :--- |
| **[HILL](http://dde.binghamton.edu/download/stego_algorithms/)** (High-pass, Low-pass, Low-pass) | 空域 (Spatial) | 2014 | 采用 1 个高通滤波器提取边缘/纹理残差，再结合 2 个低通滤波器对代价进行平滑，使低代价区域高度聚集在复杂纹理中心（[Sensors 2026](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/)）。 | **空域抗深度学习检测最强基准之一**：在 0.4 bpp 载荷下，主流深度检测器对其检测准确率比对 WOW 低 3.8%–6.3%（[Sensors 2026](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/)）。 |
| **[MiPOD](http://dde.binghamton.edu/download/stego_algorithms/)** (Minimizing the Power of Optimal Detector) | 空域 (Spatial) | 2016 | 摆脱启发式经验规则，将局部像素残差建模为多元广义高斯分布，直接最小化最优似然比检测器的统计检验功效（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 | **统计模型驱动的顶峰**：对高维手工统计特征（如 SRM、maxSRMd2）和跨算法迁移检测具有极强的抵抗力（[Electronics 2025](https://www.mdpi.com/2079-9292/14/21/4347)）。 |
| **[S-UNIWARD](http://dde.binghamton.edu/download/stego_algorithms/)** (Spatial UNIversal WAvelet Relative Distortion) | 空域 (Spatial) | 2014 | 利用方向小波滤波器组计算局部系数相对变化量的总和作为失真度量，严厉惩罚平滑与规则边缘区域的修改（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 | **通用性极强的空域标准基线**：在 0.4 bpp 下修改率仅约 7.65%，峰值信噪比（PSNR）高达 59.26 dB（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 |
| **[WOW](http://dde.binghamton.edu/download/stego_algorithms/)** (Wavelet Obtained Weights) | 空域 (Spatial) | 2012 | 利用方向高通滤波器组评估不同方向上的残差能量，确保在所有方向上都具备复杂纹理的区域才被赋予低嵌入代价（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 | **方向性自适应隐写经典代表**：对传统手工特征抗检测能力强，但相比 HILL 更容易被现代 CNN 捕捉局部集中伪影（[Sensors 2026](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/)）。 |
| **[CMD](https://arxiv.org/html/1912.03878v2) / [Synch](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image) / [GINA](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)** | 空域 / 彩色空域 | 2015–2021 | **非加性隐写（Non-additive）**：将图像划分为不相交子晶格分步嵌入，动态更新代价使相邻像素（CMD-HILL）或 R/G/B 通道间（CMD-C、GINA）的修改方向保持同步（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 | **大幅提升基础算法安全性**：在 HILL 或 MiPOD 基础上结合 CMD 同步修改策略，能显著降低对相邻像素高通差分残差的破坏（[arXiv 2020](https://arxiv.org/html/1912.03878v2)）。 |
| **[J-UNIWARD](http://dde.binghamton.edu/download/stego_algorithms/)** | JPEG 频域 (DCT) | 2014 | 将 UNIWARD 的方向小波相对失真推广至 JPEG 域，评估修改量化 DCT 系数对解压后空域小波系数的影响（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 | **JPEG 域抗检测黄金标准**：在 QF 90、0.4 bpnzAC 下修改率约 9.19%（PSNR 52.77 dB），抗检测性能远超传统 F5、nsF5 和 OutGuess（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 |
| **[J-MiPOD](https://github.com/uibk-uncover/conseal)** | JPEG 频域 (DCT) | 2020 | 将 MiPOD 的多元高斯统计建模与最优检测器功效最小化理论扩展至 JPEG 量化 DCT 域，利用解压后空域像素方差推导 DCT 系数嵌入概率（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 | **最先进的传统 JPEG 隐写算法**：在 0.4 bpnzAC（QF 75）下，GFR 手工特征对其检测准确率仅为 79.9%，CNN 检测准确率为 88.9%（[WIFS 2024](https://informationsecurity.uibk.ac.at/pdfs/LB2024_WIFS.pdf)）。 |
| **[UERD](https://github.com/uibk-uncover/conseal)** (Uniform Embedding Revisited Distortion) | JPEG 频域 (DCT) | 2015 | 综合考虑 $8\times 8$ DCT 块能量（块复杂度）与量化步长模式，使修改均匀分布在各离散 DCT 系数上以减小一阶/二阶统计量偏移（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 | **计算效率极高**：避免了 J-UNIWARD 繁重的小波变换计算，运行速度快一个数量级以上，安全性仅次于 J-UNIWARD 和 J-MiPOD（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 |
| **[BBC / BBM](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)** | JPEG 频域 (DCT) | 2020–2022 | **非加性 JPEG 隐写**：通过控制 DCT 块内不同位置的修改方向，抑制块间修改引起的块边界不连续性（Block Boundary Continuity）（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 | **针对块效应检测的专门强化**：有效抵御依赖块间相关性特征（如 JRM、GFR）和深度卷积网络的检测（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 |

### 2. 主流开源隐写项目与代码库

* **[conseal (uibk-uncover/conseal)](https://github.com/uibk-uncover/conseal)**：由奥地利因斯布鲁克大学（University of Innsbruck）团队于 2024–2026 年持续维护的 Python/Rust 高性能隐写库，完整集成了空域的 **HILL、MiPOD、S-UNIWARD、WOW、HUGO、LSB** 以及 JPEG 域的 **J-UNIWARD、J-MiPOD、UERD、EBS、nsF5、F5** 的代价计算与嵌入模拟器，可直接通过 `pip3 install conseal` 安装使用。
* **[HStego (daniellerch/hstego)](https://github.com/daniellerch/hstego)**：面向实际端到端抗检测隐写通信的开源工具（Python + C），底层采用 **S-UNIWARD**（针对 PNG/位图）和 **J-UNIWARD + 代价极化（Cost Polarization）**（针对 JPEG 图像），并集成完整的 **STC（Syndrome-Trellis Codes）** 编解码器实现真实秘密信息的嵌入与提取，同时内置了最大安全容量（5%）限制以规避深度学习隐写分析。
* **[Binghamton DDE Lab 官方代码库](http://dde.binghamton.edu/download/stego_algorithms/)**：纽约州立大学宾汉姆顿分校 Fridrich 教授团队发布的官方基准代码库（MATLAB / C++ MEX），提供了 **S-UNIWARD、J-UNIWARD、SI-UNIWARD、WOW、HUGO、MiPOD** 以及 **[STC 编解码器](http://dde.binghamton.edu/download/syndrome/)** 的标准参考实现。
* **[StegoLab (daniellerch/stegolab)](https://github.com/daniellerch/stegolab)**：包含 S-UNIWARD、J-UNIWARD（含彩色图像 Wiener 滤波改进版）及 LSB 匹配等算法的纯 Python 教学与研究实现。

## 二、 近5年（2021–2026）针对传统隐写术的主流与先进检测算法及准确数据

在被动监管（Passive-Warden）标准场景下，评估隐写分析模型的两个核心指标为**平均检测错误率（$P_E$）**与**检测准确率（$P_A = 1 - P_E$）**。当嵌入载荷达到或超过 **0.4 bpp / bpnzAC** 时，先进深度学习模型在标准实验室数据集（BOSSbase、BOWS2）上的检测错误率 $P_E$ 已降至 **10% 以下**（即准确率 $P_A > 90\%$）；但在 **0.1–0.2 bpp** 低载荷、任意尺寸或现实跨源失配（Cover-Source Mismatch, CSM）场景下，检测依然极具挑战（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。

### 1. 隐写分析模型演进与核心方法（2021–2026）

| 模型/方法名称 | 发表年份 | 适用域 | 参数量 / 复杂度 | 核心架构设计与技术亮点 |
| :--- | :---: | :--- | :---: | :--- |
| **[SRM](http://dde.binghamton.edu/download/feature_extractors/) / [GFR](https://github.com/uibk-uncover/sealwatch) / [PHARM](https://github.com/uibk-uncover/sealwatch)** | 经典基线 | 空域 / JPEG 域 | 34,671维 (SRM) / 17,000维 (GFR) | **手工富模型（Rich Models）+ FLD 集成分类器**：利用数十个方向高通滤波核或 2D Gabor 滤波器提取残差共生矩阵，至今仍是衡量算法抗统计分析能力的必测基准（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 |
| **[SRNet](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)** | 2019 (核心基准) | 空域 & JPEG 域 | 4.77M / 12.10 GFLOPs | **端到端深度残差网络基石**：完全随机初始化卷积核（不依赖手工 SRM 滤波器），在前 7 个残差层禁用池化（Unpooled）以防止微弱隐写信号衰减（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 |
| **[SiaStegNet](https://github.com/SiaStg/SiaStegNet)** | 2021 | 空域 (任意尺寸) | 0.71M / 14.40 GFLOPs | **孪生卷积隐写分析网络**：将输入图像划分为两个子区域送入权重共享的对称孪生子网络，结合对比损失（Contrastive Loss）提取子区域间的噪声统计一致性，无需重训即可检测任意尺寸图像（[Electronics 2025](https://www.mdpi.com/2079-9292/14/21/4347)）。 |
| **[JIN 预训练 + EfficientNet / ConvNeXt](https://janbutora.github.io/assets/pdfs/IN-pretraining-6.pdf)** | 2021–2026 | JPEG 域 / 彩色图像 | 依骨干网而定 | **大规模隐写域迁移学习**：在 ImageNet 图像上使用 J-UNIWARD（0.4–0.6 bpnzAC）构建 JIN 数据集进行预训练，并将网络首层卷积步长（Stem Stride）修改为 1 以保留高频 DCT 残差，在 ALASKA II 与 StegBench 上取得最高精度（[StegBench 2026](https://www.mdpi.com/1999-4893/19/8/655)）。 |
| **[LWENet](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/)** | 2022 | 空域 | 0.38M | **轻量级高效多视角网络**：采用 30 个固定 SRM 高通滤波核预处理，结合瓶颈残差块（BRB）、深度可分离卷积以及多视角全局池化（MGP，综合均值/最大值/方差视角），参数量不到 SRNet 的 1/12，准确率反而提升约 2%–5%（[Electronics 2025](https://www.mdpi.com/2079-9292/14/21/4347)）。 |
| **[UCNet](https://ieeexplore.ieee.org/document/9851403/)** | 2022 | 彩色空域 & JPEG 域 | 1.12M / 14.30 GFLOPs | **通用彩色图像隐写分析网络**：使用 30 个 SRM 核与 32 个 Gabor 核分别对 RGB 三通道独立预处理提取 186 维残差并拼接，避免早期跨通道求和破坏通道间隐写相关性（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 |
| **[CVTStegNet](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image) / [SwT-SN](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)** | 2022–2023 | 空域 | 中等规模 | **CNN-Transformer 混合架构**：浅层利用 CNN 提取局部高频残差提升信噪比，深层引入卷积视觉 Transformer（CvT）或 Swin Transformer 建模全局长距离依赖（[APSIPA 2024 综述](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image)）。 |
| **[DFNet](https://www.mdpi.com/2079-9292/14/21/4347)** | 2025 | 空域 & JPEG 域 | 0.30M | **双路径特征增强与分形下采样网络（IEEE TIFS 2025）**：融合残差路径与密集连接路径（Dense Path），结合坐标注意力机制与分形下采样，在 0.1 bpp 极低载荷下表现优异（[Electronics 2025](https://www.mdpi.com/2079-9292/14/21/4347)）。 |
| **[RMNet](https://www.mdpi.com/2079-9292/14/21/4347)** | 2025年11月 | 空域 & 真实多源场景 | 0.91M | **基于图关系挖掘的隐写分析网络**：以 LWENet 为骨干，通过跨注意力融合浅层细节与深层语义，将特征图建模为 $16\times 16$ 图节点，利用“局部全连接 ($R=5$) + 全局动态余弦相似度 ($\tau=0.8$)”邻接矩阵与 APPNP 图传播算法挖掘隐写信号空间分布（[Electronics 2025](https://www.mdpi.com/2079-9292/14/21/4347)）。 |
| **[WSERNet](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/)** | 2026年2月 | 空域 | 轻量级推理 | **微弱隐写信号提取与增强网络**：提出受高通先验约束的可学习滤波器（LFCHP）、二阶信号辅助分支（SSAB，训练时通过全局协方差池化强化微弱信号，推理时移除零开销）以及全局软池化（GSP），显著降低池化层的信号损失（[Sensors 2026](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/)）。 |

### 2. 权威基准数据集上的准确检测数据对比

隐写分析领域存在两种主流的数据集划分协议（均基于 **BOSSbase 1.01 + BOWS2** 共 20,000 张 $256\times 256$ 灰度图像）：
1. **标准大训练集协议（14:1:5 划分）**：14,000 对图像（含全部 BOWS2 及 4,000 对 BOSSbase）用于训练，1,000 对验证，5,000 对测试。
2. **跨库测试协议（6:1:3 或 4:1:5 划分）**：不同比例的训练样本集，用于评估模型在更严格训练样本限制下的收敛与泛化性能。

#### （1）标准 14:1:5 划分基准下的检测准确率（$P_A$，%）与训练复杂度对比
数据来源：2025年11月发表于 *Electronics* 的 [RMNet 论文 Table 1 & Table 8](https://www.mdpi.com/2079-9292/14/21/4347)（硬件环境：NVIDIA RTX 3090，PyTorch 2.0.1，200 Epochs）。

| 隐写算法 | 嵌入载荷 (bpp) | [SRNet](https://www.mdpi.com/2079-9292/14/21/4347) (2019) | [GBRAS-Net](https://www.mdpi.com/2079-9292/14/21/4347) (2021) | [SiaStegNet](https://github.com/SiaStg/SiaStegNet) (2021) | [LWENet](https://www.mdpi.com/2079-9292/14/21/4347) (2022) | [DFNet](https://www.mdpi.com/2079-9292/14/21/4347) (2025) | [RMNet](https://github.com/Yang-Da-xiong/RMNet) (2025) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **模型参数量 (M)** | — | 4.77M | — | 0.71M | 0.38M | 0.30M | 0.91M |
| **训练耗时 (小时)** | — | 31.7 h | — | 14.3 h | 11.5 h | 16.2 h | 13.2 h |
| **WOW** | 0.4 | 94.95% | 95.98% | 95.86% | 96.63% | 97.10% | **97.15%** |
| **WOW** | 0.3 | 90.70% | 93.55% | 93.29% | 95.31% | 95.41% | **95.66%** |
| **WOW** | 0.2 | 83.24% | 90.73% | 86.51% | 92.80% | 92.51% | **93.13%** |
| **WOW** | 0.1 | 74.13% | 80.32% | 78.23% | 85.96% | **86.47%** | 86.20% |
| **S-UNIWARD** | 0.4 | 94.72% | 95.41% | 95.42% | 96.42% | 96.39% | **96.86%** |
| **S-UNIWARD** | 0.3 | 88.10% | 91.94% | 93.83% | 93.84% | 94.42% | **94.66%** |
| **S-UNIWARD** | 0.2 | 81.62% | 89.30% | 85.03% | 90.92% | 91.27% | **91.61%** |
| **S-UNIWARD** | 0.1 | 68.96% | 76.47% | 73.78% | 81.02% | **82.70%** | 82.03% |
| **HILL** | 0.4 | 89.37% | 90.13% | 90.99% | 92.18% | 93.02% | **93.35%** |
| **HILL** | 0.3 | 81.35% | 87.70% | 88.23% | 90.52% | 90.55% | **90.58%** |
| **HILL** | 0.2 | 76.47% | 81.25% | 80.35% | 85.59% | 85.93% | **85.96%** |
| **HILL** | 0.1 | 68.66% | 70.25% | 70.62% | 76.19% | 74.64% | **77.34%** |

#### （2）WSERNet 与主流轻量化/二阶池化网络对比数据（BOSSbase + BOWS2）
数据来源：2026年2月发表于 *Sensors* 的 [WSERNet 论文 Table 6](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/)（硬件环境：NVIDIA RTX 3090，300 Epochs，3次独立实验均值）。

| 隐写算法 | 嵌入载荷 (bpp) | [Zhu-Net](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/) (2020) | [SRNet](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/) (2019) | [FPNet](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/) (2022) | [CPSN](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/) (协方差池化) | [LWENet](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/) (2022) | [WSERNet](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/) (2026) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **WOW** | 0.4 | 88.69% | 90.08% | 90.76% | 91.25% | 92.06% | **93.14%** |
| **WOW** | 0.3 | 86.25% | 87.41% | 87.95% | 88.07% | 88.23% | **90.47%** |
| **WOW** | 0.2 | 81.10% | 82.91% | 83.09% | 83.37% | 84.14% | **87.10%** |
| **WOW** | 0.1 | 71.34% | 73.67% | 74.63% | 74.04% | 76.16% | **78.18%** |
| **S-UNIWARD** | 0.4 | 84.63% | 88.43% | 87.36% | 89.85% | 89.78% | **91.63%** |
| **S-UNIWARD** | 0.3 | 78.44% | 84.86% | 84.50% | 85.25% | 85.66% | **87.35%** |
| **S-UNIWARD** | 0.2 | 71.58% | 78.88% | 76.88% | 79.26% | 79.72% | **81.33%** |
| **S-UNIWARD** | 0.1 | 62.43% | 68.20% | 67.14% | 68.52% | 69.03% | **72.06%** |
| **HILL** | 0.4 | 81.10% | 83.78% | 82.96% | 85.25% | 85.59% | **87.32%** |
| **HILL** | 0.3 | 76.20% | 80.31% | 79.47% | 81.22% | 81.34% | **83.35%** |
| **HILL** | 0.2 | 70.59% | 74.49% | 74.07% | 75.88% | 75.27% | **77.14%** |
| **HILL** | 0.1 | 62.46% | 66.34% | 66.75% | 67.20% | 67.87% | **69.79%** |

#### （3）跨隐写算法泛化检测准确率（Mismatched Steganographic Algorithms，0.4 bpp）
在真实取证中，检测方往往不知道发送方使用的是哪一种具体隐写算法。当所有模型仅在 **0.4 bpp S-UNIWARD** 生成的样本上训练，并直接测试其他 4 种未见过的传统隐写算法时，各模型准确率如下（数据来源：[RMNet 论文 Table 2](https://www.mdpi.com/2079-9292/14/21/4347)）：

| 训练算法 (0.4 bpp) | 测试算法 (0.4 bpp) | [LWENet](https://www.mdpi.com/2079-9292/14/21/4347) | [DFNet](https://www.mdpi.com/2079-9292/14/21/4347) | [SiaStegNet](https://github.com/SiaStg/SiaStegNet) | [GBRAS-Net](https://www.mdpi.com/2079-9292/14/21/4347) | [SRNet](https://www.mdpi.com/2079-9292/14/21/4347) | [RMNet](https://github.com/Yang-Da-xiong/RMNet) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **S-UNIWARD** | **WOW** | 94.36% | 95.25% | 94.50% | 92.93% | 93.56% | **95.75%** |
| **S-UNIWARD** | **MiPOD** | 86.81% | 86.59% | 87.31% | 85.02% | 87.43% | **87.74%** |
| **S-UNIWARD** | **HUGO** | 78.79% | 76.86% | 81.37% | 81.22% | **84.60%** | 82.31% |
| **S-UNIWARD** | **HILL** | 74.88% | 66.69% | 75.89% | 75.84% | 76.49% | **76.80%** |

#### （4）ALASKA #2 真实多设备数据集与 JPEG 域检测数据
* **ALASKA #2 真实场景多源基准（10,000 张图像，$256\times 256$，6:2:2 划分，0.6 bpp）**：由于 ALASKA #2 图像来自数十款不同相机传感器与不同图像信号处理（ISP）流水线，各模型准确率相比 BOSSbase 均出现显著下降，反映出真实环境下载体源异质性的严峻挑战（数据来源：[RMNet 论文 Table 11](https://www.mdpi.com/2079-9292/14/21/4347)）：

| 隐写算法 (0.6 bpp) | [GBRAS-Net](https://www.mdpi.com/2079-9292/14/21/4347) | [SRNet](https://www.mdpi.com/2079-9292/14/21/4347) | [SiaStegNet](https://github.com/SiaStg/SiaStegNet) | [DFNet](https://www.mdpi.com/2079-9292/14/21/4347) | [LWENet](https://www.mdpi.com/2079-9292/14/21/4347) | [RMNet](https://github.com/Yang-Da-xiong/RMNet) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **WOW** | 64.92% | 70.80% | 71.73% | 72.03% | 72.43% | **73.05%** |
| **S-UNIWARD** | 69.88% | 69.97% | 71.13% | 70.62% | 71.50% | **71.65%** |
| **HILL** | 67.47% | 62.00% | 67.70% | 68.85% | 69.38% | **69.43%** |

* **JPEG 域隐写分析基准（QF 75 标准量化表）**：根据因斯布鲁克大学发表于 [IEEE WIFS 2024](https://informationsecurity.uibk.ac.at/pdfs/LB2024_WIFS.pdf) 的实验数据，在针对 **J-MiPOD（0.4 bpnzAC，QF 75）** 的检测中，传统 **[GFR](https://informationsecurity.uibk.ac.at/pdfs/LB2024_WIFS.pdf)** 手工特征+集成分类器的检测准确率为 **79.9%**，而基于预训练 **[EfficientNet](https://informationsecurity.uibk.ac.at/pdfs/LB2024_WIFS.pdf)** 的 CNN 检测器将准确率提升至 **88.9%**；对非自适应的 **nsF5（0.2 bpnzAC，QF 75）**，**JRM** 特征与 CNN 的检测准确率则分别高达 **94.8%** 与 **86.4%**（[WIFS 2024 Table I](https://informationsecurity.uibk.ac.at/pdfs/LB2024_WIFS.pdf)）。

### 3. 主流开源隐写分析工具箱与代码库

* **[sealwatch (uibk-uncover/sealwatch)](https://github.com/uibk-uncover/sealwatch)**：与 `conseal` 配套的现代 Python/C++ 隐写分析特征提取与检测库，内置了 **SRM、GFR、PHARM、DCTR、JRM、SPAM、ccJRM** 等全套高频残差特征提取器与 FLD 集成分类器，支持多核高速并行提取。
* **[Aletheia (daniellerch/aletheia)](https://github.com/daniellerch/aletheia)**：目前功能最完整的开源综合隐写分析工具箱（Python），集成了 **SRNet、EfficientNet（B0/B4）** 等深度学习预训练模型以及 **SRM、GFR、DCTR** 特征与集成分类器，支持针对 **J-UNIWARD、HILL、S-UNIWARD、nsF5、Steghide、OutGuess** 的自动化检测与 DCI-SI 置信度评估。
* **[StegExpose (b3dk7/StegExpose)](https://github.com/b3dk7/stegexpose)**：专门针对早期非自适应 LSB 隐写（如 LSB 替换、OpenStego 等）的轻量级统计分析工具（融合 RS 分析、Sample Pairs、卡方攻击与 Primary Sets），适合快速初筛简单工具生成的隐写图，但对现代自适应隐写（HILL、J-UNIWARD 等）无效。
* **前沿深度隐写分析网络官方 PyTorch 源码库**：
  * **SiaStegNet**：[https://github.com/SiaStg/SiaStegNet](https://github.com/SiaStg/SiaStegNet)
  * **RMNet (2025)**：[https://github.com/Yang-Da-xiong/RMNet](https://github.com/Yang-Da-xiong/RMNet)
  * **WSERNet (2026)**：`https://github.com/LWL139/WSERNet`（详见 [Sensors 2026 论文数据可用性声明](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/)）

## 三、 核心参考文献与数据来源

1. Luo W, Wei K, Li Q, et al. [A Comprehensive Survey of Digital Image Steganography and Steganalysis](https://www.emerald.com/atsip/article/13/1/1/1331386/A-Comprehensive-Survey-of-Digital-Image). *APSIPA Transactions on Signal and Information Processing*, 2024, 13(1): 1–67.
2. Liang W, Li Q. [Steganalysis Network for Weak Steganographic Signal Extraction and Enhancement (WSERNet)](https://pmc.ncbi.nlm.nih.gov/articles/PMC12944376/). *Sensors*, 2026, 26(4): 1329.
3. Yang R, Yang Y, Zhou L, Meng X. [A Steganalysis Method Based on Relationship Mining (RMNet)](https://www.mdpi.com/2079-9292/14/21/4347). *Electronics*, 2025, 14(21): 4347.
4. Lorch B, Böhme R. [Steganalysis in Directional JPEG Images](https://informationsecurity.uibk.ac.at/pdfs/LB2024_WIFS.pdf). *IEEE International Workshop on Information Forensics and Security (WIFS)*, 2024.
5. Butora J, Yousfi Y, Fridrich J. [How to Pretrain for Steganalysis](https://janbutora.github.io/assets/pdfs/IN-pretraining-6.pdf). *ACM Workshop on Information Hiding and Multimedia Security (IH&MMSec)*, 2021.
6. StegBench Team. [StegBench: A Dual-Branch Benchmark Dataset for Multi-Class Steganalysis](https://www.mdpi.com/1999-4893/19/8/655). *Algorithms*, 2026, 19(8): 655.
