# HEVC 隐写检测面与画质评估规范

| 项 | 内容 |
| :--- | :--- |
| **文档编号** | `HEVC-STEG-SPEC-20261026` |
| **编制日期** | 2026-10-26 |
| **性质** | **合并 + 修编**。合并 `hevc_steganography_detection_and_tools_20261026.md`（检测工具调研）与 `hevc_steganalysis_and_quality_eval_20261026.md`（抗检与画质规范草案），并纠正其中 4 处与代码不符的结论（见 §2），逐项标注实现状态。 |
| **适用范围** | Scheme C（CABAC bypass + STC），载体 `.heic` / `.heif` / `.mp4` / `.mov` / Annex-B |
| **配套** | 曲线原始数据：`docs/hevc_payload_quality_curve_20261026.md`；容量口径：`docs/hevc_video_capacity_quality_audit_20261026.md`；工具：`scripts/hevc_quality_sweep.py`、`scripts/stego_eval` |

---

## 0. 实现状态总表

| 能力 | 状态 | 落地位置 |
| :--- | :--- | :--- |
| 原位修改、$\Delta = 0$、容器表不动 | ✅ | `engine.rs`；`local_hevc_mp4_container_tables_untouched` |
| 凭据派生 header magic（`Label ‖ Secret`） | ✅ | `engine.rs::derive_magic` |
| 只动 CABAC 旁路符号位，179 个上下文状态逐位不变 | ✅ | `slot.rs`；`crates/rusty_h265/src/observer.rs:50` |
| 幅值感知代价 + `Δpeak > 32` / `|c| > 4` 软熔断 | ✅ 2026-10-25 | `slot.rs::compute_sign_flip_cost` |
| 漂移分层（band 0 / band 1，IRAP 排除） | ✅ 2026-10-26 | `engine.rs::picture_band` / `band_positions` |
| 视频推荐容量按图片数 + 阶梯预算 | ✅ 2026-10-26 | `params.rs::video_budget` |
| 四维画质指标（PSNR / 8×8 patch / p99.9 / 坏块率） | ✅ 2026-10-26 | `local_media.rs::compare_pixels` |
| 按载体类型分开的画质门限 | ✅ 2026-10-26 | `STILL_GATE` / `VIDEO_GATE` |
| PSNR / SSIM / VMAF 载荷曲线工具 | ✅ 2026-10-26 | `scripts/hevc_quality_sweep.py` |
| 盲检回归（SRM / SRNet） | ⬜ 待建（套件已在） | `scripts/stego_eval` |
| VMAF 进 CI | ⬜ 未做 | 依赖外部模型文件，见 §3.5 |
| 静图推荐容量与画质红线对齐 | ⚠️ **未对齐** | 见 §4 |

---

## 1. 检测面（按攻击成本从低到高）

四类检测 + 一类反推，逐条给出对本方案的实际威胁。原调研文档的骨架保留，措辞降级为可核实的事实。

| 层级 | 检测手段 | 代表工具 / 方法 | 对本方案的威胁 |
| :--- | :--- | :--- | :--- |
| **L1 容器与码率** | 非标 `uuid`/`free` box、尾随字节、`stsz`/`stco`/`iloc` 重算痕迹、码率膨胀（BRI） | Bento4 `mp4dump`、MediaInfo、`strhide::adapters::isobmff::isobmff_suspicious_structures` | **无效**。`Δ = 0` 已由测试锁定，`moov`/`stsz`/`stco` 逐字节不变 |
| **L2 语法与最优性** | IPM 共现、四叉树分裂、AMVP/MVPO 最优性、CABAC 上下文概率漂移、SEI / filler 异常 | Elecard StreamEye、HM conformance checker、sherlock265 | **无效**。不修改 IPM / CU 树 / MV / 任何常规上下文编码位，上下文状态逐位恒等 |
| **L3 压缩域统计** | 符号邻接（AoSO）、差分 (AoDO)、level 直方图、块边界梯度 | 学术特征 + SVM | **主要理论威胁**。符号位本身近似 $p=0.5$，翻转只让局部符号分布略偏离；实测翻改率在推荐值下极低（视频 <0.06% 像素移动 >16 级） |
| **L4 像素域与深度学习** | SRM 残差 + CNN、3D-CNN/ConvLSTM 捕捉时域漂移 | SRM、SRNet、GBRAS-Net、YeNet | **主要理论威胁**。误差稀疏且贴强边缘；但参考帧翻转会带来时域持久误差，是 L4 最可能的抓手 |
| **RDO 反推** | 同参数重编码，比较块级 $J = D + \lambda R$ 偏离 | x265 重编码 + 局部分析 | **理论上最难防**。符号翻转不改变 RDO 判决路径（不重编码），但若重编码后系数分布明显退化，可被标记为可疑块 |

现实屏障（Cover-Source Mismatch）：检测模型依赖同源同参数训练集，跨编码器/跨设备时残差自然方差远大于隐写扰动，虚警率不可控——这也是没有商业开箱工具的根本原因，而不是"技术上不可能"。

---

## 2. 对原两篇的纠正

| # | 原文说法 | 事实 | 依据 |
| :--- | :--- | :--- | :--- |
| 1 | 「修改系数群符号位会破坏原生 SDH 奇偶关系，严苛解码器可直接检出」 | **不成立**。SDH 的推导位由 `|level|` 之和的奇偶性决定，本方案从不改幅值；且 fork 只在 `k < nsigns`（真有传输符号的系数）时记录槽位，推导位根本不进池 | `crates/rusty_h265/src/ctu/residual.rs:405,604`（`sign_hidden` / `k < nsigns`，注释："the sign-hidden coefficient never had one"） |
| 2 | 「在 `compute_sign_flip_cost` 里乘 $\gamma_{\text{nal}}=25$，引导 STC 优先藏进非参考帧」 | **空操作**。`cost` 只决定 $u=2$ 分组内翻哪一个；哪些槽位进分组由 `band_positions` 决定，而池已按 band 排序，同组两个槽通常同层——统一乘 25 不改变任一选择 | `engine.rs::band_positions`、`embed_hevc` 中 `positions = band_positions(&bands, needed_slots)` |
| 3 | 「需确保合入 `record_stego_level` 幅值回填」 | 已合入（2026-10-25），含 `Δpeak>32` / `|c|>4` 的 `1e6` 软熔断 | `slot.rs::record_stego_level` / `compute_sign_flip_cost` |
| 4 | 「帧内预测只读取当前块最右列 $x=N-1$ 与最下行 $y=N-1$」 | 方向写反。帧内预测读的是**左列 / 上行**已重构像素；右列 / 下行是本块误差**传播**的方向 | H.265 §8.4.2。结论（误差沿块边界扩散）成立，描述不成立 |
| 5 | 「约 50%~60% 的帧是非参考帧」 | 偏乐观。实测 `IMG_0033.MOV` 192/385 = **49.9%**，`VID_20250228` 112/228 = 49.1% | 本文 §3.4 基线；`hevc_capacity_diag` |
| 6 | 「L1/L2 100% 免疫、零语法破绽」 | 结论方向对，但"100%"无法证明。可核实的是：`Δ = 0` 有测试锁定，上下文状态逐位恒等有代码依据 | 同 §0 |

另：`libvmaf` 没有内置模型，直接 `libvmaf` 会报 `no such built-in model`，必须 `model=path=...`（本仓库模型可复用 `F:/Develop/github/vmaf/model/vmaf_v0.6.1.json`，`hevc_quality_sweep.py` 已自动查找）。

---

## 3. 画质评估规范

### 3.1 为什么不能只看平均 PSNR

稀疏、块局部的扰动会被均值摊平。极端例子：1219 万像素的照片里只有 20 个像素跳变 220 级，$\text{MSE}$ 仅增加 $20 \times 220^2 / 12{,}192{,}768 = 0.079$，全图 PSNR 仍有 **59.1 dB**，但那 20 个点在暗部是刺眼白斑。

本项目实测同样如此：`IMG_0033.MOV` 在推荐容量下平均只动 **0.56 个量化级**，但单点最大 **99 级**、1000 个 8×8 块里有 1 块低于 25 dB。

### 3.2 指标定义与取舍

| 指标 | 定义 | 作用 |
| :--- | :--- | :--- |
| `psnr` | 全体样本（3 平面、全部帧）均方误差换算 | 底线，不能作为唯一判据 |
| `min_patch_psnr` | 全部帧中**最差** 8×8 亮度块 PSNR | 抓"均值好、局部坏"。**静图**的块会一直显示，必须进门槛；**视频**的单个块只出现 1/60 秒 |
| `bad_patch_fraction` | 8×8 块 PSNR < 25 dB 的比例 | 极值统计的**长度归一化**版本：最差块随片长增长（385 帧 vs 816 帧的极值不可比），坏块比例可以比 |
| `max_abs_diff` / `p999_abs_diff` | 单样本最大偏差 / 99.9 分位偏差 | 前者抓灾难样本，后者抓尾巴厚度 |
| `large_fraction` | 偏差 > 16 级的样本比例 | 稀疏性指标 |
| VMAF (mean/min) | Netflix 感知模型 | 最接近"人眼是否看得出"；**不建模闪烁**，且对稀疏扰动偏宽松 |
| 时域闪烁 RMSE | $\mathrm{RMSE}(\Delta_t^{\text{cover}} - \Delta_t^{\text{stego}})$ | 检验相邻帧差异是否被改变（隔帧形态的专属指标） |

### 3.3 门限：按载体类型分开

静图与视频的失效方式不同——静图整张画面都在承载载荷且无时域掩蔽；视频把载荷摊到数百帧（还可能整帧不动）。同一套阈值要么误杀健康视频，要么放过坏块静图。

**静图（`.heic`，按 12% 容量口径；括号内为 50% 容量压力口径）**

| 指标 | 实测基线 | 优秀 | **CI 红线（`STILL_GATE`）** |
| :--- | :--- | :--- | :--- |
| `psnr` | 38.7 – 43.8 dB（36.5 – 38.7） | ≥ 42 dB | **≥ 34 dB** |
| `min_patch_psnr` | 26.3 – 28.2 dB（20.6 – 23.0） | ≥ 26 dB | **≥ 20 dB** |
| `max_abs_diff` | 12 – 25（22 – 30） | ≤ 24 | **≤ 48** |
| `p999_abs_diff` | 8 – 17（15 – 20） | ≤ 12 | **≤ 24** |
| `large_fraction` | 0.00 – 0.21%（0.03 – 0.22%） | ≤ 0.1% | **≤ 1%** |
| `bad_patch_fraction` | 0（0.1 – 0.6%） | ≤ 0.05% | **≤ 0.5%** |

**视频（`.mp4` / `.mov`，按推荐容量口径，385 / 228 / 816 图三个载体）**

| 指标 | 实测基线 | 优秀 | **CI 红线（`VIDEO_GATE`）** |
| :--- | :--- | :--- | :--- |
| `psnr` | 48.5 – 53.5 dB | ≥ 48 dB | **≥ 42 dB** |
| `min_patch_psnr` | 13.6 – 32.4 dB | 仅报告 | **≥ 8 dB**（只拦灾难） |
| `max_abs_diff` | 19 – 99 | ≤ 80 | **≤ 140** |
| `p999_abs_diff` | 4 – 14 | ≤ 16 | **≤ 24** |
| `large_fraction` | 0.00 – 0.06% | ≤ 0.1% | **≤ 0.2%** |
| `bad_patch_fraction` | 0.000 – 0.100% | ≤ 0.1% | **≤ 0.3%** |
| VMAF mean | 97.9 – 99.99 | ≥ 97 | ≥ 95（人工/定期，不进 CI） |

视频的 `min_patch_psnr` 只作灾难拦截，理由见 §3.2：在 6.2 M 个块上取最小值是极值统计，用它当门限等于把门限变成片长的函数。

### 3.4 实测基线（2026-10-26）

`IMG_0033.MOV`（1080p60 / 385 图 / 推荐 40.6 KiB / 极限 354.4 KiB，亮度平面）：

| 载荷 | PSNR | 最差 8×8 | p99.9 | >16 级 | 坏块<25dB | 有差异帧 |
| ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 KiB | 62.04 | 20.39 | 2 | 0.0000 | 0.000% | 192/385 |
| 5 KiB | 55.29 | 17.15 | 7 | 0.0001 | 0.004% | 192/385 |
| 15 KiB | 50.68 | 16.85 | 12 | 0.0003 | 0.027% | 192/385 |
| **40.6 KiB（推荐）** | **46.55** | **10.21** | **17** | **0.0011** | **0.129%** | 192/385 |
| 100 KiB（2.5×） | 35.62 | 9.02 | 29 | 0.0098 | 0.982% | 378/385 |
| 362.8 KiB（8.9×） | 28.83 | 5.33 | 55 | 0.0784 | 10.6% | 378/385 |

推荐值以内载荷只落在非参考帧上，**193/385 帧逐像素未变**。VMAF/SSIM 曲线见 `hevc_payload_quality_curve_20261026.md`。

### 3.5 手段

```bash
# 载荷-画质曲线（PSNR / SSIM / VMAF + 逐帧 CSV）；模型自动从本地 vmaf 仓库取
python scripts/hevc_quality_sweep.py --carrier temp/testhevc/IMG_0033.MOV \
  --payloads 1024,5120,15360,40600,102400,362800 --metrics psnr,ssim,vmaf

# 单次对比：PSNR + SSIM 同时出（ffmpeg 会自动 split 复用的输入）
ffmpeg -hide_banner -nostdin -i cover.mp4 -i stego.mp4 \
  -lavfi "[0:v][1:v]psnr;[0:v][1:v]ssim" -f null -

# VMAF（必须显式给模型；feature= 可同时出 psnr/ssim）
ffmpeg -hide_banner -nostdin -i cover.mp4 -i stego.mp4 \
  -lavfi "[0:v][1:v]libvmaf=log_fmt=json:log_path=vmaf.json:model=path:vmaf_v0.6.1.json:feature=name=psnr|name=float_ssim" \
  -f null -
```

目视核对：取同一帧同一 320×200 区域，左=原图、中=隐写、右=$|\Delta| \times 12$。误差贴边缘=被掩蔽，铺满平坦区=块状伪影。

CI 侧（`cargo test local_ -- --ignored`）已覆盖：`compare_decoded` 的六项指标 + `STILL_GATE` / `VIDEO_GATE`，并新增 `local_hevc_video_recommended_capacity_quality`（按**推荐容量**而非百分比跑，直接验证 CLI 对用户的承诺）。

比较是**流式**的：ffmpeg 的 rawvideo 一帧一帧读入、比较完即丢弃（整段物化一个 4K 载体是 12.4 MB/帧 × 228 帧 ≈ 2.8 GB/侧）。

这两个实现细节踩过坑，改的时候别退回去：

1. **stderr 必须并发抽干**。管道里有 64 KiB 缓冲，没人读就会把 ffmpeg 卡在 write 上，而比较循环在等一个永远不会到来的字节——表现是测试进程 36 MB RSS、旁边挂着一个 `ffmpeg.exe`、进度永远不动。
2. **帧长必须取解码后的尺寸**，不是 SPS、也不是 ffprobe。`test.heic` 的 SPS 是 1652×1792，实际解码 1652×1790（一致性窗口裁边），按前者切帧会把整条流读歪，一个字节都比不到——所以 `compare_decoded` 里有一条"零帧比较直接报错"的守卫，避免这种失败被当成"画质完美"。

本地套件（并行）实测 **189 s / 23 项全绿**，内存峰值约 **12 GB**（来自 `embed_hevc` 保留全部 CABAC bin，与比较逻辑无关）。

### 3.6 盲检回归（待建）

1. 取 `temp/testhevc` 的 cover/stego 组，统一解码为无损 PNG（视频抽帧）；
2. 用 `scripts/stego_eval`（含 SRM 特征与 SRNet 权重）跑分类；
3. 通过标准：在 `High` / `Paranoid` 推荐载荷下，$P_E = \frac{1}{2}(P_{FA}+P_{MD}) \ge 0.45$，ROC AUC $\in [0.50, 0.55]$（接近随机猜测）。

这是唯一能把"抗检"量化的路径，也是 §1 中 L3/L4 威胁的唯一可信回答方式。

---

## 4. 已知未决

1. **静图推荐容量与画质红线未对齐**。`IMG_1133.HEIC` 在推荐值 105.7 KiB 下实测 PSNR **26.5 dB**（VMAF 未测），低于本规范静图红线 34 dB。即图像侧的 `bpp_limit` / `target_ratio` 锚点偏激进（视频侧 2026-10-26 已改为阶梯预算）。需要一次专项标定，把静图推荐值也锚到 $\ge$ 34 dB。
2. **极限容量可见**。视频极限（8.9× 推荐）VMAF 77、单点偏差 178 级，CLI 只告警不阻断；`--enforce-safety` 可选。
3. **VMAF 未进 CI**。依赖外部模型文件，且 1080p60 全片 VMAF 太慢；目前只在 §3.5 的手动流程里跑。
4. **隔帧形态**。推荐值以内只改一半帧，若未来把 band 0 预算推高，需重新评估时域闪烁（§3.2 的闪烁 RMSE 指标已就位，但还没设门限）。
