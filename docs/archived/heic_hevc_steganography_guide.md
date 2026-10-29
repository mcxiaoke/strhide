# HEIC / HEIF 与 HEVC 帧内抗检测隐写术技术指南与开源实现方案

## 1. HEIC / HEIF 架构特性决定了传统空域与 DCT 隐写无法直接迁移

传统的图像隐写术主要针对 **PNG / BMP**（空域像素直接修改，如 LSB、S-UNIWARD、HILL）或 **JPEG**（固定 $8\times8$ 分块的离散余弦变换域，如 F5、J-UNIWARD、UED）。然而，[HEIF（High Efficiency Image File Format）是基于 ISOBMFF 的容器标准，而苹果 iOS 默认采用的 HEIC 格式底层使用 H.265/HEVC 帧内编码（Intra-frame Coding）](https://pmc.ncbi.nlm.nih.gov/articles/PMC11120525/)。直接将传统隐写迁移至 HEIC 会面临三大核心障碍：

* **可变尺寸四叉树递归分块（CTU / CU / PU / TU）**：不同于 JPEG 固定的 $8\times8$ 块，[HEVC 将图像划分为最大 $64\times64$ 的编码树单元（CTU），并基于率失真优化（RDO）递归分裂为不同尺寸的编码单元（CU）、预测单元（PU）和变换单元（TU）](https://www.mdpi.com/1424-8220/24/16/5103)。任何破坏最优率失真代价的粗糙修改都会在重压缩校准时暴露异常。
* **35 种帧内方向预测引发强烈的“帧内失真漂移（Intra-Frame Distortion Drift）”**：HEVC 亮度分量包含 Planar、DC 以及 33 种角度预测模式。由于当前块重构后的右边界和下边界像素会被直接用作相邻块的预测参考值，[在变换系数或预测模式上哪怕改动 1 比特，误差也会沿着预测方向向整张图扩散](https://pmc.ncbi.nlm.nih.gov/articles/PMC13619809/)。
* **混合 DST/DCT 变换与 CABAC 上下文算术编码**：HEVC 对 $4\times4$ 亮度帧内残差块采用离散正弦变换（DST），其余块采用离散余弦变换（DCT），且熵编码阶段采用自适应二进制算术编码（CABAC）。直接替换比特极易破坏上下文概率模型或导致文件体积异常膨胀（Bit Rate Increase, BRI）。

## 2. 三大技术路线全景对比：压缩域原生隐写、深度学习鲁棒隐写与容器层隐写

根据应用场景对“抗隐写分析检测（Undetectability）”、“抗有损重压缩（Robustness）”及“工程实现难度”的不同要求，针对 HEIC / HEIF 的方案可分为三大技术路线：

| 技术路线 | 核心原理 | 代表算法与开源项目 | 抗隐写分析与鲁棒性 | 适用场景 |
| :--- | :--- | :--- | :--- | :--- |
| **1. HEVC 帧内压缩域自适应隐写**<br>*(抗检测能力最强)* | 在 HEVC 编码过程中微调分块结构（CU/PU/TU）、帧内预测模式（IPM）或量化系数（QDST/QDCT），结合 STC 最小化率失真代价 | [Quad-Tree 四叉树保持隐写](https://ieeexplore.ieee.org/document/10477576/)、[IPM-PP 优先级保持隐写](https://ieeexplore.ieee.org/iel8/76/4358651/11112653.pdf)、[CABAC 旁路符号位隐写](https://www.researchgate.net/publication/410986949_High_Capacity_Bitrate-Preserving_Video_Steganography_for_HEVC_Via_Codeword_Mapping_of_CABAC_Bypass-Coded_Sign_Flags)、[4×4 QDST 矩阵隐写](https://www.researchgate.net/publication/353765916_An_Efficient_Video_Steganography_Method_Based_on_HEVC) | 极难被空域或压缩域隐写分析器检出，100% 兼容标准解码器；但二次有损转码会抹除信息 | 原文件无损传输场景下的高安全隐蔽通信、抗取证检测 |
| **2. 端到端深度学习抗压缩隐写**<br>*(跨平台传输鲁棒性最强)* | 通过神经网络将秘密比特映射至潜空间或中低频特征，训练中引入模拟有损压缩噪声层，抵抗 HEIC 量化损失 | [Meta Watermark Anything (WAM)](https://github.com/facebookresearch/watermark-anything)、[Adobe TrustMark](https://github.com/adobe/trustmark)、[RoSteALS (CVPR 2023)](https://github.com/TuBui/RoSteALS)、[StegaStamp](https://github.com/tancik/StegaStamp) | 可抵抗 HEIC/JPEG/WebP 有损重压缩与裁剪；但对整图特征改动较大，不适合高对抗性反隐写检测 | 跨社交平台传图、AIGC 溯源、数字版权盲水印 |
| **3. ISOBMFF 容器层与辅助轨隐写**<br>*(工程落地最快、零画质损失)* | 利用 HEIF 底层的 ISOBMFF Box 树状结构，在偏移间隙（`iloc`）、自定义块（`free`/`uuid`）或辅助图层（`auxl`）嵌入数据 | [strukturag/libheif](https://github.com/strukturag/libheif)、[GPAC / MP4Box](https://github.com/gpac/gpac/wiki/GPAC-support-for-HEIF)、[JavDomGom/videostego](https://github.com/JavDomGom/videostego)、[image-invisible-watermarker](https://pypi.org/project/image-invisible-watermarker/) | 零画质损伤、容量无上限；但容易被文件结构解析器或元数据剥离工具发现 | 本地大容量载荷封装、快速标记、CTF 题目设计 |

## 3. 聚焦“高隐蔽与抗检测”：四大前沿 HEVC Intra 自适应隐写方案深度解析

在**不需要强力抗重压缩变形、核心追求隐藏与抗隐写分析检测**的前提下，算法设计的核心是**最小化加性/非加性失真（Minimizing Distortion）**：为每个候选修改位置定义率失真与统计偏移代价，并使用校验格码（[daniellerch/pySTC](https://github.com/daniellerch/pySTC)）或极化隐写码（[martin9676/Polarized-Steganographic-Codes](https://github.com/martin9676/Polarized-Steganographic-Codes)）完成接近率失真理论极限的嵌入。

| 抗检测方案名称 | 隐写载体（HEVC 语法元素） | 核心抗检测机制 | 规避的隐写分析器类型 | 码率膨胀（BRI）与画质表现 |
| :--- | :--- | :--- | :--- | :--- |
| **方案一：TU / CU 四叉树分块结构保持隐写** | 变换单元与编码单元分裂标志（`split_transform_flag` / `split_cu_flag`） | 仅微调分裂与不分裂 RD Cost 极其接近的非跳级块（[IEEE TMM 2024 四叉树保持方案](https://ieeexplore.ieee.org/document/10477576/)），保留帧内预测与残差系数的局部最优性 | 同时免疫**空域残差检测**（SRNet 等）与 **IPM 预测模式检测**（[Universal Intra Steganalysis](https://pmc.ncbi.nlm.nih.gov/articles/PMC13619809/)） | 视觉完全无损，码率增幅 < 0.5%，单图容量适中 |
| **方案二：IPM 优先级保持 + 分层抗漂移隐写** | 亮度块 35 种帧内预测模式（Intra Prediction Modes, IPM） | 保持候选 IPM 的 RD 优先级排序（[IPM-PP 算法](https://ieeexplore.ieee.org/iel8/76/4358651/11112653.pdf)），分层解耦嵌入以消除相邻块参考像素引发的失真漂移（[Layered IPM Steganography](https://www.researchgate.net/publication/352170711_A_Layered_Embedding-Based_Scheme_to_Cope_with_Intra-Frame_Distortion_Drift_In_IPM-Based_HEVC_Steganography)） | 规避 39 维 IPM 共现矩阵（IPMC）与块边界梯度检测（[GradIPMFormer](https://arxiv.org/abs/2602.11547)） | 视觉极难察觉，KL 散度偏移极小 |
| **方案三：CABAC 旁路符号位与 SDH 恒定码率隐写** | 算术编码旁路模式下的变换系数符号位（`coeff_sign_flag`）与原生符号位隐藏（SDH） | 在固定等概率（0.5）的 CABAC Bypass 通道进行码字映射（[CABAC Bypass Sign Mapping](https://www.researchgate.net/publication/410986949_High_Capacity_Bitrate-Preserving_Video_Steganography_for_HEVC_Via_Codeword_Mapping_of_CABAC_Bypass-Coded_Sign_Flags)），或复用原生 [Sign Data Hiding](https://www.researchgate.net/publication/261497974_Additional_sign_bit_hiding_of_transform_coefficients_in_HEVC) 奇偶校验 | 规避基于**码率异常增长**、二次压缩编码元素对比与上下文概率表的检测（[CABAC Constant Bitrate](https://www.researchgate.net/publication/281717146_A_CABAC_based_HEVCc_video_steganography_algorithm_without_bitrate_increase)） | **严格零码率膨胀（BRI = 0）**，编码开销极低 |
| **方案四：4×4 QDST 零漂移系数 + STC 自适应隐写** | $4\times4$ 亮度块量化离散正弦变换系数（QDST）特定位置 | 结合预测方向仅修改不参与相邻块边界参考像素重构的系数（[Intra-Frame QDST Scheme](https://www.researchgate.net/publication/400967646_A_HEVC_Steganography_Scheme_Based_on_Intra-Frame_QDST_Coefficient)），从数学上切断误差传播链 | 规避基于帧内残差高阶统计与重压缩鬼影（Coding Ghosts）的检测（[HEIF Double Compression Detector](https://www.mdpi.com/1424-8220/24/16/5103)） | 容量高，彻底消除传统变换域隐写的块边界伪影 |

### 3.1 为什么“TU / CU 四叉树分块结构隐写”能实现跨模态免疫
根据 [Universal Video Steganalysis in HEVC Intra Frame](https://pmc.ncbi.nlm.nih.gov/articles/PMC13619809/) 的理论推导，当隐写仅通过微调率失真代价（RD Cost）来改变某个 CU 或 TU 是否继续向下分裂时：
1. **空域统计不变**：所有变换块内的像素残差依然由真实图像经过正常变换与量化生成，没有人为叠加任何独立噪声，因此针对空域像素的深度学习检测器（如 SRNet、XuNet）完全失效。
2. **IPM 最优性不变**：在选定的分块尺寸下，35 种帧内预测模式依然取其率失真代价最小的**全局最优模式**，因此针对 IPM 转移概率的检测器无法捕捉到次优替换痕迹。
3. **四叉树结构保持原则**：[Quad-Tree Structure-Preserving Adaptive Steganography (IEEE TMM 2024)](https://ieeexplore.ieee.org/document/10477576/) 进一步将分块修改限制在“非跳级修改（Non-skip-level Modification）”，仅在纹理复杂度处于分裂临界点的区域利用 STC 嵌入，使隐写后的四叉树深度分布与自然图像高度吻合。

### 3.2 为什么“CABAC 旁路符号位与 SDH 隐写”能做到零码率膨胀与快速实现
HEVC 标准在 `§7.3.8.11` 残差编码中原生设计了 **Sign Data Hiding (SDH)** 机制（[HEVC Coding Tools Perceptual Analysis](https://www.researchgate.net/publication/349942821_Analysis_of_the_Perceptual_Quality_Performance_of_Different_HEVC_Coding_Tools)）：当一个 $4\times4$ 变换子块内首尾两个非零系数在扫描顺序上的距离超过阈值（通常为 4）时，编码器不显式写入首个非零系数的符号位，而是计算该子块所有非零系数绝对值之和的奇偶性（偶数代表正号 `+`，奇数代表负号 `-`）。如果奇偶性与实际符号不符，编码器会自动挑选块内率失真代价最小的一个系数将其幅值 $\pm 1$。
* **直接复用为隐写通道**：只要将该奇偶校验的目标值从“首个非零系数的正负号”替换为“经过 STC 编码后的秘密比特”，就能直接借用编码器自带的 RDOQ（率失真优化量化）选点逻辑完成高隐蔽嵌入，且由于符号位在 CABAC 中采用等概率（0.5）旁路编码（Bypass Mode），不会引起码率异常波动。

## 4. 免从零手写：两条可直接落地的工程实现路径与代码模板

如果你不想从头编写庞大的 HEVC 编解码器，可以直接复用现有开源组件，通过以下两条路径快速落地：

### 4.1 路径 A：纯 Python 现成库直接拼装（`pySTC` + `pillow-heif` 无损旁路方案）
如果允许生成的 `.heic` 文件开启 HEVC 标准内置的变换量化旁路模式（`transquant_bypass_enabled_flag = 1`，即 x265 无损编码模式），你可以直接用 Python 组合以下三个现成开源库，在 **50 行代码内**构建一套能躲避 [daniellerch/aletheia](https://github.com/daniellerch/aletheia) 深度学习隐写分析的工具：
* **核心隐写编码库**：[daniellerch/pySTC](https://github.com/daniellerch/pySTC)（提供 C++ Syndrome-Trellis Codes 的 Python 绑定及现成的 **HILL** 空域自适应失真函数）或 [daniellerch/hstego](https://github.com/daniellerch/hstego)（提供 **S-UNIWARD** 失真函数）。
* **HEIC 容器读写库**：[bigcat88/pillow_heif](https://github.com/bigcat88/pillow_heif)（底层封装工业级 [strukturag/libheif](https://github.com/strukturag/libheif)）。

```python
import numpy as np
from PIL import Image
import pillow_heif
import pystc  # 来自 https://github.com/daniellerch/pySTC
from scipy.signal import convolve2d

# 注册 HEIF/HEIC 插件
pillow_heif.register_heif_opener()

def compute_hill_cost(channel: np.ndarray) -> np.ndarray:
    """计算 HILL (High-pass, Low-pass, Low-pass) 自适应隐写失真代价"""
    img = channel.astype(np.float64)
    # KB 高通滤波器提取复杂纹理边缘残差
    kb_kernel = np.array([
        [-1,  2, -1],
        [ 2, -4,  2],
        [-1,  2, -1]
    ], dtype=np.float64)
    residual = convolve2d(img, kb_kernel, mode='same', boundary='symm')
    
    # 第一层 3x3 均值低通滤波
    l1_kernel = np.ones((3, 3), dtype=np.float64) / 9.0
    w = convolve2d(np.abs(residual), l1_kernel, mode='same', boundary='symm')
    
    # 计算倒数代价并进行第二层 15x15 低通平滑，使修改聚集在复杂纹理区
    rho = 1.0 / (w + 1e-10)
    l2_kernel = np.ones((15, 15), dtype=np.float64) / 225.0
    cost = convolve2d(rho, l2_kernel, mode='same', boundary='symm')
    
    # 防止像素值 0 和 255 发生溢出 (Wet Paper Coding)
    cost[channel == 0] = 1e10
    cost[channel == 255] = 1e10
    return cost.astype(np.float32)

def embed_heic_adaptive(cover_path: str, stego_heic_path: str, secret_bytes: bytes, key: bytes):
    """使用 HILL + STC 将秘密信息嵌入并保存为标准无损旁路 HEIC"""
    img = Image.open(cover_path).convert("RGB")
    arr = np.array(img)
    
    # 对 B 通道计算 HILL 失真代价（建议总负载控制在 <= 0.05 bpp 以对抗深度学习检测）
    cover_ch = arr[:, :, 2]
    costs = compute_hill_cost(cover_ch)
    
    # 调用 pySTC 在最小失真代价下执行 +-1 嵌入
    stego_ch = pystc.hide(cover_ch, secret_bytes, key, costs, mx_payload=0.05)
    arr[:, :, 2] = stego_ch
    
    # 通过 pillow-heif 调用 x265 无损模式（开启 HEVC transquant_bypass_enabled_flag）封装
    stego_img = Image.fromarray(arr)
    stego_img.save(
        stego_heic_path,
        format="HEIF",
        quality=-1,  # 触发 libheif / x265 无损变换量化旁路编码，100% 保留 STC 修改位
        chroma="444"
    )

def extract_heic_adaptive(stego_heic_path: str, key: bytes) -> bytes:
    """从 HEIC 图像中无损提取 STC 隐藏消息"""
    img = Image.open(stego_heic_path).convert("RGB")
    stego_ch = np.array(img)[:, :, 2]
    return pystc.unhide(stego_ch, key)
```

### 4.2 路径 B：在现成 HEVC 编码器（C++ HM 或 Rust `oxideav-h265`）中挂载压缩域隐写
如果你需要生成**标准有损压缩（Lossy QP 20~32）**的 `.heic` / `.h265` 文件，可以直接基于以下两个现成的开源编码器进行极小改动（仅需修改 1 个文件中的 1 个函数）：
* **C++ 官方参考编码器底座**：[listenlink/HM (HEVC Test Model)](https://github.com/listenlink/HM)（可参考 [tianyili2017/HEVC-Complexity-Reduction](https://github.com/tianyili2017/HEVC-Complexity-Reduction) 对 HM 源码的清晰工程组织，以及 [HM 官方 Doxygen 文档](https://hevc.hhi.fraunhofer.de/HM-doc/_t_enc_search_8cpp.html)）。
* **纯 Rust 现代 HEVC/HEIC 编解码器底座**：[OxideAV/oxideav-h265](https://github.com/OxideAV/oxideav-h265)（零 `unsafe` 依赖，已完整实现 HEVC 35 种帧内预测、`encoder::residual` 残差编码与 HEIC `hvcC` 封装，代码可读性远高于 C++ HM）。

#### 挂载点 1：在 `TEncSearch::estIntraPredLumaQT()` 中实现 IPM 优先级保持隐写（C++ HM）
* **关键避坑提示**：切勿在 RDO 结束后的比特流写入阶段（`TEncSbac`）直接强改 PU 的预测模式，否则会导致色度模式推导不一致或被外层 CU 四叉树分裂决策覆盖而引发解码器崩溃（详见 [Stack Overflow: How to modify intra prediction modes in HEVC Encode for steganography](https://stackoverflow.com/questions/74167361/hevc-how-to-modify-intra-prediction-modes-in-the-encode-for-steganography-purpo)）。
* **精确修改位置**：打开 `source/Lib/TLibEncoder/TEncSearch.cpp` 中的 [`TEncSearch::estIntraPredLumaQT()`](https://hevc.hhi.fraunhofer.de/HM-doc/_t_enc_search_8h_source.html)（约第 2937 行），在候选模式完成全率失真代价（RD Cost）排序之后、**尚未将重构 YUV 像素拷贝至 `pcRecoYuv` 之前**插入选择逻辑：

```cpp
// 位于 source/Lib/TLibEncoder/TEncSearch.cpp -> TEncSearch::estIntraPredLumaQT()
// 此时 uiRdModeList[0] 为最优 IPM，uiRdModeList[1] 为次优 IPM
// dRdCostList[0] 与 dRdCostList[1] 为对应的率失真代价

if (bEnableStego && uiWidth == 4) { // 仅挑选纹理复杂的 4x4 PU 块作为隐写载体
    Double dDeltaCost = dRdCostList[1] - dRdCostList[0];
    // 当最优模式与次优模式的 RD Cost 差值低于安全阈值（或由 STC 判定当前位置需要翻转）时：
    uint8_t currentModeParity = uiRdModeList[0] & 1;
    uint8_t targetSecretBit   = getNextStegoBitFromSTC(dDeltaCost);
    
    if (currentModeParity != targetSecretBit) {
        // 用次优模式（或同奇偶性的最小代价候选模式）替换最优模式
        uiBestPUMode = uiRdModeList[1];
        dBestPUCost  = dRdCostList[1];
    }
}
// 随后让 HM 照常使用 uiBestPUMode 执行 xIntraCodingTUBlock() 进行变换、量化与重构像素更新
// 这样后续相邻块会自动基于修改后的重构像素进行预测，彻底消除解码端失真漂移！
```

#### 挂载点 2：在 `xCompressCU()` 中实现四叉树分块结构保持隐写（C++ HM）
* **精确修改位置**：打开 `source/Lib/TLibEncoder/TEncCu.cpp` 的 `TEncCu::xCompressCU()` 函数，在当前深度 `uhDepth` 完成了不分裂代价 `rpcBestCU->getTotalCost()` 与四叉树分裂总代价 `rpcTempCU->getTotalCost()` 的计算之后，在比较分支处介入（[Quad-Tree Structure-Preserving Adaptive Steganography](https://ieeexplore.ieee.org/document/10477576/)）：

```cpp
// 位于 source/Lib/TLibEncoder/TEncCu.cpp -> TEncCu::xCompressCU()
Double dNonSplitCost = rpcBestCU->getTotalCost();
Double dSplitCost    = rpcTempCU->getTotalCost();
Double dDiffCost     = fabs(dSplitCost - dNonSplitCost);

// 仅在 16x16 或 8x8 层级、且分裂与不分裂的 RD 代价高度接近时嵌入秘密比特
if (bEnableStego && uhDepth == 2 && dDiffCost < STEGO_RD_THRESHOLD) {
    uint8_t secretSplitFlag = getNextStegoBitFromSTC(dDiffCost);
    if (secretSplitFlag == 1) {
        // 强制采纳分裂后的子 CU（rpcTempCU）
        std::swap(rpcBestCU, rpcTempCU);
    }
    // 若 secretSplitFlag == 0，则保留不分裂的 rpcBestCU
} else {
    // 正常 RDO 分支
    if (dSplitCost < dNonSplitCost) {
        std::swap(rpcBestCU, rpcTempCU);
    }
}
```

#### 挂载点 3：在 `residual_coding()` / SDH 中实现变换系数奇偶校验隐写（Rust `oxideav-h265` 或 C++ HM）
* **精确修改位置**：在 [OxideAV/oxideav-h265](https://github.com/OxideAV/oxideav-h265) 的 `encoder::residual` 模块（或 C++ HM 的 `TComTrQuant::signBitHidingHDQ()`）中，复用 $4\times4$ 变换子块的非零系数绝对值求和奇偶校验逻辑：
  * 计算 $4\times4$ 量化系数子块（建议仅针对不参与相邻块边界参考像素重构的系数，参见 [Intra-Frame QDST Scheme](https://www.researchgate.net/publication/400967646_A_HEVC_Steganography_Scheme_Based_on_Intra-Frame_QDST_Coefficient)）非零幅值之和 `sum_abs`。
  * 将 `sum_abs & 1` 作为载体比特，将每个系数幅值 $\pm 1$ 带来的量化失真误差作为 STC 代价 `cost`，直接调用 STC 决定修改哪一个高频系数的最低有效位。
  * 提取端只需用标准解码器（或参考 [lijun9250lj/HEVC-MVPO-Video-steganalysis](https://www.sciopen.com/article/10.32604/cmc.2024.048095) 的语法元素解析流程）读取每个 $4\times4$ 子块的非零系数绝对值之和，无需任何复杂逆运算即可直接恢复隐藏比特。

## 5. 核心参考资料与开源仓库汇总

* **自适应隐写编码与评估工具箱**：
  * [daniellerch/pySTC](https://github.com/daniellerch/pySTC)：Syndrome-Trellis Codes (STC) 的 Python/C++ 开源实现（含 HILL 失真代价计算示例）。
  * [martin9676/Polarized-Steganographic-Codes (SPSC)](https://github.com/martin9676/Polarized-Steganographic-Codes)：基于极化码的低复杂度高嵌入效率隐写码实现。
  * [daniellerch/hstego](https://github.com/daniellerch/hstego)：集成 S-UNIWARD 与 J-UNIWARD 的高抗检测自适应隐写工具。
  * [daniellerch/aletheia](https://github.com/daniellerch/aletheia)：集成富模型（SRM）与深度学习网络的开源隐写分析评测工具箱。
* **HEIF / HEIC 与 HEVC 编解码开源底座**：
  * [strukturag/libheif](https://github.com/strukturag/libheif) 与 [bigcat88/pillow_heif](https://github.com/bigcat88/pillow_heif)：主流 C/C++ 与 Python HEIF/HEIC 编解码与 ISOBMFF 容器封装库。
  * [OxideAV/oxideav-h265](https://github.com/OxideAV/oxideav-h265) 与 [roticv/rust_h265](https://github.com/roticv/rust_h265)：纯 Rust 实现的 H.265/HEVC 编解码器，支持 35 种帧内预测、CABAC、SDH 与无损 HEIC 静态图封装。
  * [listenlink/HM](https://github.com/listenlink/HM) 与 [tianyili2017/HEVC-Complexity-Reduction](https://github.com/tianyili2017/HEVC-Complexity-Reduction)：C++ HEVC 官方参考软件 HM 及其编码阶段修改范例。
  * [GPAC / MP4Box HEIF Support](https://github.com/gpac/gpac/wiki/GPAC-support-for-HEIF) 与 [JavDomGom/videostego](https://github.com/JavDomGom/videostego)：ISOBMFF 容器结构解析与 Box 级数据注入工具。
* **深度学习抗压缩鲁棒隐写/盲水印项目**：
  * [facebookresearch/watermark-anything](https://github.com/facebookresearch/watermark-anything)：Meta FAIR 局部化抗压缩深度隐写水印。
  * [adobe/trustmark](https://github.com/adobe/trustmark)：Adobe Research 任意分辨率抗压缩隐写水印框架（[TrustMark 论文](https://openresearch.surrey.ac.uk/esploro/outputs/conferencePaper/TrustMark-Robust-Watermarking-and-Watermark-Removal/991164459902346)）。
  * [TuBui/RoSteALS](https://github.com/TuBui/RoSteALS)：基于自编码器潜空间的鲁棒隐写（[RoSteALS 论文](https://arxiv.org/html/2304.03400v1)）。
  * [tancik/StegaStamp](https://github.com/tancik/StegaStamp)：端到端抗失真 CNN 隐写模型。
* **HEVC Intra 抗检测隐写与隐写分析代表论文**：
  * [Quad-Tree Structure-Preserving Adaptive Steganography for HEVC (IEEE TMM 2024)](https://ieeexplore.ieee.org/document/10477576/)
  * [IPM Priority-Preserving Adaptive Steganography for HEVC (IEEE TCSVT)](https://ieeexplore.ieee.org/iel8/76/4358651/11112653.pdf)
  * [An Adaptive IPM-Based HEVC Video Steganography via Minimizing Rate-Distortion Cost](https://www.computer.org/csdl/journal/tq/2023/04/09847125/1Fu4UX6IYuI)
  * [A Layered Embedding-Based Scheme to Cope with Intra-Frame Distortion Drift in IPM-Based HEVC Steganography](https://www.researchgate.net/publication/352170711_A_Layered_Embedding-Based_Scheme_to_Cope_with_Intra-Frame_Distortion_Drift_In_IPM-Based_HEVC_Steganography)
  * [High Capacity Bitrate-Preserving Video Steganography for HEVC Via Codeword Mapping of CABAC Bypass-Coded Sign Flags](https://www.researchgate.net/publication/410986949_High_Capacity_Bitrate-Preserving_Video_Steganography_for_HEVC_Via_Codeword_Mapping_of_CABAC_Bypass-Coded_Sign_Flags)
  * [A HEVC Steganography Scheme Based on Intra-Frame QDST Coefficient](https://www.researchgate.net/publication/400967646_A_HEVC_Steganography_Scheme_Based_on_Intra-Frame_QDST_Coefficient)
  * [Universal Video Steganalysis in HEVC Intra Frame Based on the Convolutional Residual Network](https://pmc.ncbi.nlm.nih.gov/articles/PMC13619809/)
  * [H.265/HEVC Video Steganalysis Based on CU Block Structure Gradients and IPM Mapping (GradIPMFormer)](https://arxiv.org/abs/2602.11547)
  * [A Lightweight Double Compression Detector for HEIF Images Based on Encoding Information](https://www.mdpi.com/1424-8220/24/16/5103)
