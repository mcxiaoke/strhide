# 富模型 + FLD ensemble 隐写分析评测方案（P0 落地）

| 项 | 内容 |
| :--- | :--- |
| 文档编号 | `STEGO-PE-EVAL-PLAN-20261023-2140` |
| 编制时间 | 2026-10-23 21:40（本机时间） |
| 上游 | `docs/stego_algorithm_positioning_and_detection_audit_20261023.md` §6 P0 |
| 目标 | 把"抗检能力"从定性判断变成可复现的 `P_E` 曲线 |
| 状态 | 工具链已在本机跑通；脚本 `scripts/steganalysis_pe.py` 已交付并小规模验证 |

---

## 0. 结论

1. **用 `sealwatch`（Univ. Innsbruck，2024-）**，不要自己实现 SRM，也不要先去折腾 MATLAB。
   它是 DDE Lab 官方 MATLAB 实现的高保真 Python 移植，一条 `pip install` 就有 SRM/SRMQ1/CRM/DCTR/GFR/JRM/CC-JRM/PHARM + FLD ensemble，**许可证 MPL-2.0，商用友好**。
2. **DDE 的 MATLAB 原版只在两种情况下才值得用**：要与某篇论文逐位对齐特征值，或已有 MATLAB 授权。它的许可证是 **research / non-profit only**，与本项目的 Apache-2.0 不兼容，只能用于内部评测、不能把代码带进发布物。
3. **Aletheia 是第二轨，不能替代 P_E 评测**。它是 CNN 模型套件，给的是"这张图像不像被嵌过"的分数，不是可分性指标；而且你已经在 §4.2 实测过它跨语料退化严重（干净图 0.48~0.9975），必须先用目标语料重标定才可用。
4. **时间预算**：2 000 对载体、4 个载荷点、SRM 34 671 维，单机 16 进程约 **4 小时**特征提取 + **1 小时**训练。SRMQ1（12 753 维）约 1.5 小时 + 1 小时。

---

## 1. 工具选型

### 1.1 候选对比

| 工具 | 形态 | 覆盖 | 许可证 | 本机实测 | 结论 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **sealwatch** | `pip install sealwatch` | SRM/SRMQ1/CRM/DCTR/GFR/JRM/CC-JRM/PHARM + FLD ensemble | MPL-2.0 | ✅ 可用 | **首选** |
| **DDE**（Binghamton） | MATLAB + MEX（C++ 源码） | SRM/SRMQ1/PSRM/maxSRM/CF*/CC-JRM/DCTR + ensemble | research / non-profit only | 未装 MATLAB | 仅做交叉校验 |
| **Aletheia** | Python + 预训练 CNN | SRNet/EffNet/Yedroudj/Zhu-Net | MIT 类 | 已用于 §4.2 | 第二轨，需重标定 |
| StegExpose | Java | chi2/RS/SPA/WS | — | — | 与现有 `analysis.rs` 同代，无增量 |
| 各类 GitHub `SRM-python` | 零散 | 多为 SRM 滤波器的部分实现 | 不一 | — | 不建议，正确性无法保证 |

### 1.2 为什么 sealwatch 够用

- 官方声明"基于 DDE 的 MATLAB 参考实现"，并把已知差异写在 `compatibility.md` 里；
- 提供与 DDE 同构的 **FLD ensemble**（随机子空间 + bootstrap + 自动超参搜索），输出可直接换算成 `P_E`；
- **CRM（color rich models）** 是 DDE 那批 MATLAB 里没有现成下载的，正好补上本项目"单通道 vs RGB"这个空白；
- MPL-2.0 允许在非开源工具里调用，不污染本项目的 Apache-2.0。

风险：包自述 "under intensive development"（Alpha）。缓解办法：先用 SPAM 与 DDE 的历史数字对齐一次（SPAM 686 维、`P_E` 曲线在文献里到处都有），确认移植无误再跑全量。

---

## 2. 本机实测性能（2026-10-23）

空域，512×512 中心裁剪，单核：

| 特征 | 维度 | 单张耗时 | 备注 |
| :--- | ---: | ---: | :--- |
| SPAM | 686 | **0.17 s** | 唯一的 Rust 后端，其余全 Python |
| CRM (q=1, Tc=2) | 2 073 | 3.5 s | **API 默认值，偏弱** |
| **CRM (q=1, Tc=3)** | **5 404** | 3.7 s | 包文档口径，评测用这个 |
| SRMQ1 | 12 753 | 8.7 s | 推荐先跑这一档 |
| SRM | 34 671 | **22.5 s** | 全量，最后再跑 |

JPEG（不做裁剪，直接吃原图）：

| 特征 | 维度 | 单张耗时 | 备注 |
| :--- | ---: | ---: | :--- |
| JRM | 11 255 | 14.2 s @2048×1530 | 无需额外参数 |
| GFR | 17 000 | 6.2 s @512×512；51.9 s @2048×1530 | 必须给 `qf`，只支持 75 / 95 |
| CC-JRM | 22 510 | — | **Windows 上失败**，见 §5.9 |

其他实测：

- `import sealwatch` 需要 5.5~6.6 s（含 torch），多进程时每个 worker 都要付一次；
- FLD ensemble 训练（100 对样本，自动超参搜索）：686 维 50 s / 12 753 维 103 s / 34 671 维 66 s；
- 空域端到端验证：8 个 cover + 8 个 stego，SRMQ1 提取 37 s（8 进程），训练 2 splits 26 s；
- JPEG 端到端验证：3 对 512×512 QF75，GFR 提取 18 s（3 进程），17000 维正常输出。

环境：`C:/Home/Develop/venv/Scripts/python.exe`（Python 3.12.12，已含 sealwatch 2025.9、jpeglib 1.0.2、torch 2.14.1+cu126 / RTX 4070）。

---

## 3. 评测协议

### 3.1 载体的选择与规模

| 项 | 建议 | 理由 |
| :--- | :--- | :--- |
| 数量 | **≥ 1 000 对**，目标 2 000 | `P_E` 的标准误 ≈ `sqrt(P(1-P)/n)`；n=1 000 时约 1.5%，足够分辨 3~5 个百分点的差异 |
| 尺寸 | 统一中心裁 **512×512** | 与 BOSSbase 口径一致，便于与文献的趋势对照 |
| 来源 | 现有 216 张真实 PNG + 80 张相机原片 + DIV2K | 覆盖自然图、相机片、人工图三类 |
| 去重 | 按**原始文件**去重 | `temp/images/png` 与 DIV2K 可能有同源图，混进去会虚高 |

**关键约束**：同一张原图只能出一个 cover。不要靠"一张大图裁 6 块"凑数量——同一来源的裁块高度相关，会让 `P_E` 虚高、且训练/测试泄露。

### 3.2 载荷点

PNG（bpp，bits per pixel）：

- `0.05`、`0.10`、`0.20`、`0.40`

`0.10` 是本项目默认 `High` 档的工作点，必须包含；`0.40` 是与文献主表可比的点；`0.05` 用于确认"低载荷不可检"的边界。

JPEG（bpnzAC，bits per non-zero AC coefficient）：`0.1`、`0.2`、`0.4`。

注意 bpp 与 bpnzAC 不是一回事，换算需要载体自身的非零 AC 计数，不要混用。

### 3.3 划分与指标

- **按 cover 分组**划分 train/test（同一 cover 的 cover-feature 与所有载荷的 stego-feature 必须同侧）；
- 10 次随机 split，50/50；
- `P_E = (P_FA + P_MD) / 2`，等先验；
- 报 **mean ± std**，不要报单次结果。

### 3.4 必须有的对照组（否则结论没有意义）

| 组 | 目的 |
| :--- | :--- |
| 本项目 HILL+STC（单绿通道） | 现状基线 |
| 本项目 HILL+STC（RGB 三通道） | 量化 P1 的收益 |
| 本项目 + S-UNIWARD 代价 | 分离"实现"与"代价函数"的差异 |
| DDE/第三方 S-UNIWARD 生成的 stego | 验证本项目的 STC 是否与参考实现同水平 |

没有后两组，"我们的 P_E 是 0.3" 无法判断是代价函数的问题还是 STC 实现的问题。

---

## 4. 脚本用法

已交付 `scripts/steganalysis_pe.py`（仅空域；JPEG 侧见 §6）。

```bash
# 0. 依赖：本机开发 venv 已装好 sealwatch 2025.9 / jpeglib / torch(CUDA)
C:/Home/Develop/venv/Scripts/python.exe -m pip list | grep -iE "sealwatch|jpeglib|torch"
# 缺什么补什么，不要用系统 Python 或 WorkBuddy 的隔离 venv
C:/Home/Develop/venv/Scripts/python.exe -m pip install sealwatch

# 1. 生成配对样本（复用已有标定工具；"full" 会先 probe 真实容量）
C:/Home/Develop/venv/Scripts/python.exe scripts/png_blind_calib.py gen \
    --bin rust/target/release/strhide.exe \
    --covers-list temp/calib/covers_real.txt \
    --payloads 4096,full --out temp/pe_samples

# 2. 提取特征（cover 特征落盘缓存，跑第二个载荷时直接复用）
C:/Home/Develop/venv/Scripts/python.exe scripts/steganalysis_pe.py features \
    --manifest temp/pe_samples/manifest.json --payload 4096 \
    --features srmq1 --crop 512 --jobs 16 \
    --out temp/pe_features/srmq1_4096.npz \
    --cover-cache temp/pe_features/covers_srmq1_512.npz

# 3. 训练 + 输出 P_E
C:/Home/Develop/venv/Scripts/python.exe scripts/steganalysis_pe.py eval \
    --features temp/pe_features/srmq1_4096.npz --splits 10 \
    --out temp/pe_features/srmq1_4096.json
```

`features` 支持的 `--features`：

| 值 | 域 | 维度 | 说明 |
| :--- | :--- | ---: | :--- |
| `spam` | 空域 | 686 | 唯一的 Rust 后端，用来验证管线 |
| `crm` | 空域（彩色） | 5 404 | 看"单通道 vs RGB"用这个 |
| `srmq1` | 空域 | 12 753 | 推荐的中间档 |
| `srm` | 空域 | 34 671 | 全量 |
| `gfr` | JPEG | 17 000 | 需要 `--jpeg-qf 75`（只支持 75/95） |
| `jrm` | JPEG | 11 255 | 无需 qf |

输出 JSON 含 `p_e_mean / p_e_std / p_e_min / p_e_max` 与每次 split 的 `p_fa / p_md`。

**跑的顺序建议**：`spam`（分钟级，先验证管线）→ `crm`（40 分钟）→ `srmq1`（1.5 小时）→ `srm`（4 小时）；JPEG 用 `gfr`（512×512 约 6 s/张）或 `jrm`（约 1.6 s/张）。

---

## 5. 陷阱清单

1. **裁剪泄露**：一张图裁多块分别进 train/test，`P_E` 会明显虚高。脚本已按 cover 分组，不要绕过。
2. **SRM 是灰度特征**：对"单绿通道 vs RGB"这个具体问题，SRM 只能间接反映（灰度化会混合三通道），必须配 `crm` 一起看。
3. **CRM 的 Tc**：API 默认 `Tc=2` 只有 2 073 维，是弱检测器；要 `Tc=3` 的 5 404 维。脚本已固定为后者。
4. **载荷口径**：`bpp` 与 `bpnzAC` 不能混；JPEG 的载荷要按实际非零 AC 数算，不能用像素数。
5. **`full` 载荷不是同一个相对载荷**：不同载体容量差别很大，"满载"跑出来的是"各载体各自满"，横向比较意义有限。主表用固定 bpp，满载只作补充。
6. **绝对 `P_E` 不可跨语料比**：本项目语料不是 BOSSbase，数字不能和论文表格直接对照。论文数字只用来定"排序"和"量级"。
7. **sealwatch 是 Alpha**：先做一次 SPAM 对齐（DDE 公布过 SPAM 的 `P_E` 曲线）确认移植正确。
8. **多进程内存**：34 671 维 × 2 000 对 × 4 B × 2 侧 ≈ 555 MB/载荷，加载全部载荷会到 2 GB 以上，分载荷跑。
9. **CC-JRM 在 Windows 上直接失败**：`sw.ccjrm.extract_from_file()` 报 `OSError: writing DCT to ...tmp...jpeg failed`（内部用 jpeglib 写临时文件）。用 `jrm`（11 255 维，非校准版）代替，或在 WSL/Linux 下跑 CC-JRM。
10. **GFR 的质量因子**：量化步长只对 QF 75 / 95 有表，混合 QF 的语料必须统一重编码到 QF75（学术惯例），否则 `qf` 参数与载体不匹配，特征口径就乱了。重编码会改变 DCT 系数——所以要先重编码、再用 strhide 嵌入，不能反过来。
11. **cover 缓存有后端指纹**：`--cover-cache` 现在会记录 `backend` 与 `crop`，用不同档位复用时会被拒绝而不是静默拼错维度。

---

## 6. 尚未覆盖的部分

- **CNN 的 `P_E`**：Aletheia 的输出是分数不是概率，要得到 `P_E` 必须先在同一语料上训练/标定，成本比富模型高一个量级。建议富模型先出结论，CNN 只做定性旁证。本机有 CUDA（RTX 4070），跑 Aletheia 不是瓶颈。
- **与 DDE 的逐位对齐**：只在需要复现某篇论文的具体数值时才做。
- **CC-JRM**：需要 Linux 或修掉 Windows 的临时文件问题（见 §5.9）。当前用 `jrm` 替代。
- **SPC / 极化码对照**：编码层不在本轮评测范围内。

---

## 7. 验收标准

| 阶段 | 标准 |
| :--- | :--- |
| 管线正确性 | SPAM 在已知语料上复现 DDE 量级的 `P_E`（同载荷下差异 < 5 个百分点） |
| 基线可用 | 本项目 @0.10 bpp 的 `P_E` 能稳定复现（10 split 的 std < 0.03） |
| 决策可用 | 单通道 vs RGB 的 `P_E` 差异能分辨（差值 > 2×std） |
| 横向可用 | S-UNIWARD 对照组的 `P_E` 高于本项目 HILL（若相反，说明 STC 实现有问题） |

## 8. 交付物

- `scripts/steganalysis_pe.py`：特征提取 + FLD + `P_E`（已跑通）
- 每档特征的结果 JSON：`temp/pe_features/*.json`
- 结论回写到 `docs/stego_algorithm_positioning_and_detection_audit_20261023.md` §3.2，把"完全空白"替换成实测曲线
