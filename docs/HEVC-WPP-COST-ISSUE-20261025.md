# HEVC WPP 子流重写与符号翻转失真代价问题综述（2026-10-25）

> 状态：M10 已尝试修复并**完整回退**；M11（trellis seed 密钥化）已保留。
> 本文汇总两个耦合问题的完整分析、实验数据与尝试过的方案，供外部审阅，
> 目标是回答一个问题：**是否存在"理论上可靠、工程上简单"的方案让 WPP
> 中段子流安全参与嵌入**，还是接受"仅使用每 slice 最后一个子流"的现状。

---

## 1. 背景架构

strhide 的 HEVC 引擎在 CABAC 域做**变换系数符号位**（`coeff_sign_flag`，
bypass 编码）的原位翻转隐写：

- 解码端挂 `CabacRecorder`（rust_h265 observer）录制 bin 流 journal
  （Decision/Bypass/Terminate ops）与 stego 槽位；
- 嵌入端对被触碰的子流用自带的 CABAC 编码器（oxideav-h265）重编码写回，
  逐字节校验后替换 RBSP 段；
- WPP（波前并行）码流每 CTU 行切一个**子流**（substream），子流之间由
  slice header 的 `entry_point_offsets` 声明字节边界。

## 2. 问题 M10：WPP 中段子流永远无法重放

### 2.1 现象

`encode_substream` 对不以 `Terminate{bit:1}` 结尾的子流无条件补写
`terminate(1)+flush`。WPP 行边界子流的 journal 末尾是 `Terminate{bit:0}`
（行尾 `end_of_slice_segment_flag=0` 的正确语义），强补后重放与封面必然
不同 → 3a 保真校验失败 → **每 slice 除最后一个子流外全部被静默排除**。

实测 `gradient-512.heic`（x265 生成，16 子流）：15 个中段子流全部排除，
约 60% 槽位禁用。后果：probe 容量虚报（嵌入中途 TrellisInfeasible）、
可用槽集中在图像底部、x265/ffmpeg 默认 WPP 输出全部受影响；iPhone HEIC
（tile 单子流）不受影响。

### 2.2 关键事实（已实证）

1. **解码器不消费子流尾部**。rust_h265 在 WPP 行边界直接按
   `entry_point_offsets` 字节偏移硬切到下一子流（decoder.rs:829-858）；
   `term(0)` 之后的 flush/对齐位被跳过。FFmpeg 同样按 entry point 切段。
2. **尾部位形是编码器自由度**。kvazaar 行尾写 `term(0)+term(1)
   (end_of_subset_one_bit)+finish+align(1+0s)`（encoderstate.c:742-757）；
   x265 只写 `term(0)+finish(0xff 缓冲冲刷)+byteAlign`。两者都是标准一致
   码流，位形互不相同。
3. **x265 的 finish 与规范 Figure 9-15 EncodeFlush 位序列不等价**
   （0xff 进位缓冲链 vs outstanding 机制，resolve 时序不同，实验中重放的
   首个输出位即不同）。

### 2.3 尝试过的修复方案（按时间序）

| 方案 | 做法 | 结果 |
| :--- | :--- | :--- |
| A. 不补写 | 中段子流照 journal 原样收尾（`Terminate{0}` 后直接 0 对齐） | replay 长度比封面短 ~1 字节，仍全部失败（封面尾部有冲刷位） |
| B. 规范 flush | vendor 加 `CabacEncoder::encode_flush()`（Figure 9-15），中段重放后冲刷+对齐 | 长度精确一致，但**内容**不同（x265 finish ≠ 规范 flush），仍全部失败 |
| C. 尾部透传 | 重放 bins 位后，从封面**逐位复制**剩余尾部 | **16/16 子流 replay 全部通过**；但带翻转重编码时，靠近子流末尾的 bypass 翻转位仍滞留在算术寄存器中未输出，透传用封面旧位接上 → **翻转静默丢失**（表现为偶发提取失败，定位到"每子流最后一个 stego 槽"） |
| D. flush+前缀校验 | 中段重放 = bins + `encode_flush()`（保证全部位含翻转冲出）+ 0 填充到封面段长；3a 校验放宽为"bins 位前缀一致"（尾部不比较） | **重放、往返、全套测试全部稳定通过**（往返 6/6、test_media 全绿、全套 616 测试绿）。但暴露了下一节的 cost 问题 → 最终整体回退 |

方案 D 在**码流正确性上是完备的**（见 §4 的同构性验证），回退的唯一原因
是它放大暴露了失真代价模型的缺陷（§3）。

## 3. 问题：符号翻转的失真代价模型（cost model）

### 3.1 现有模型

`slot.rs record_stego_sign`：

```rust
let freq_dist = (x_c + y_c) as f64;
let freq_factor = 1.0 / (1.0 + freq_dist * 0.35);
let comp_factor = if c_idx == 0 { 1.0 } else { 0.7 };
let cost = (10.0 * freq_factor * comp_factor).max(0.1);
```

只用频率位置与分量，**不含**：变换块尺寸（trafo_size）、QP、系数幅值
|c|、块能量。评审报告 §3.4#6 早有记录（"Phase 2 结合 Q_step 的计划与实现
脱节"）。

### 3.2 M10 修复后暴露的现象

外部 ffmpeg 解码验证（嵌入 ~12% 容量载荷，断言单样本位移 ≤ 200、
PSNR ≥ 30 dB、大位移占比 ≤ 0.12）：

| 载体 | M10 修复前（中段子流不可用） | M10 修复后（方案 D） |
| :--- | :--- | :--- |
| test.heic | PSNR 33.3, max d=58 ✓ | PSNR 33-36, max 58-133 ✓ |
| IMG_5887.HEIC | PSNR 55.2, max 92 ✓ | PSNR 46-62, max 41-121 ✓ |
| IMG_1904.HEIC | PSNR 34.9, max 159 ✓ | PSNR 35-43, max 95-171 ✓ |
| **IMG_0874.HEIC** | PSNR ~40, max ≤200 ✓ | PSNR 40-44 ✓，**max 213-229 ✗（5/5 次稳定超限）** |

关键观察：

1. **IMG_0874 超限是稳定窄带**（213/223/227/229/223），不是随机撞大系数
   的形状；PSNR 与稀疏性指标全部正常。
2. **码流语义无损**：对 cover 与 stego 分别录制 journal 逐 slice 对比，
   所有 slice 的 ops 数量、子流数量完全同构，唯一差异正是被翻转的 sign
   槽本身——**排除解码分歧，超限是真实符号翻转的位移**。
3. 翻转分布诊断（IMG_0874，payload=cap/8）：**77% 翻转落在 32×32 变换块**
   （与槽池构成一致），其中 32×32 的 (1,0)/(0,1) 最低频槽被翻 6 个
   （旧模型 cost 仅 7.41，最高档才 10）。

### 3.3 物理分析

符号翻转的重建像素位移 ≈ `2·|c_recon|·basis_peak(u,v,N)`，其中
`c_recon = level·Q_step`：

- **|c_recon|（内容项）是主导项**：32×32 块的 (1,0) 系数量级可达数千，
  位移轻松过 200；4×4 纹理块高频系数量级 1-10。
- **basis_peak（结构项）是次要项**：归一化 2D DCT 基峰值 ~2/N，
  大块反而更小；边界频带（u=0 或 v=0）比内部高 √2 倍。
- 项目调研文档 `docs/hevc_video_steganography_guide.md` §2.2.2 的
  HevcTuCostModel（UERD 家族公式）同样以**块能量为分母、量化步长为分子**
  ——即内容自适应定价，与 JPEG 侧 UERD/HILL 的设计一致。

**结论：没有 |c| 的任何结构定价都无法可靠封顶单样本位移**——这是模型
维度的缺失，不是参数未调好。

### 3.4 尝试过的 cost 方案

| 方案 | 做法 | 结果（同载荷实测） |
| :--- | :--- | :--- |
| 基线（现状） | 纯 freq/comp | IMG_0874 max 225-229 超限；其余文件正常 |
| trafo 线性 | `cost ×= trafo/4 × qp_factor` | IMG_0874 max 降到 ~109-168 ✓，但 **PSNR 跌至 28.6 dB**（失真摊薄成大量小位移，总 MSE 上升） |
| trafo 平方（能量定价） | `cost ×= (trafo/4)²`，freq 也平方 | **PSNR 跌至 25.1 dB**，更差（翻转涌向"结构便宜但系数未必小"的小块高频） |
| 低频排除 | `x_c+y_c ≤ 2` 的槽不进槽池（两端一致） | **其余三个文件全面提升**（PSNR +6~8 dB，max 减半），但 IMG_0874 仍稳定 213-229 超限（其大位移来自更高频位置的大系数） |

### 3.5 治本方向与障碍

**治本 = 把 |c|（解码后的系数量化电平）纳入 cost**。障碍在 HEVC 语法顺序：

- `coeff_sign_flag` 在 `coeff_abs_level_remaining` **之前**解码
  （residual_coding.rs：sign 批量解码在前，level 循环在后）——录制 sign
  槽时幅值未知；
- 需要在 rust_h265（vendor fork）的 observer 加"level 回填 cost"钩子：
  sign 解码时挂起 slot，level 解出后回填；
- 必须处理 **sign data hiding（SDH）错位**：`sign_data_hiding_enabled_flag=1`
  时每 CG 首个非零系数的符号不在码流中（由块内绝对值和奇偶推导），
  sign 位与 level 的索引映射偏移 1；
- 另需块能量分母（UERD 式），同样要等整块系数解完。

工程量：vendor 接口改动 + 映射处理 + 两端一致性测试，中等偏上；且
"翻转引发的 SDH 推导位连带变化"等二阶效应需要一并论证。

## 4. 现状（2026-10-25）

- **M11 已保留**：HEVC trellis seed 改为从（口令派生的）AES key 经 HKDF
  派生（`trellis_seed_from_key`），关闭无口令者定位明文消息头 + CRC32
  离线枚举 oracle，与 PNG/JPEG 安全模型对齐。全套测试绿，外部 ffmpeg
  验证 5/5 稳定通过（回退 M10 后的翻转分布下 max |d| ≤ 133）。
- **M10 已回退**：`encode_substream` 恢复无条件补 `terminate(1)`（中段
  子流继续被 3a 排除），`slot.rs` cost 恢复基线，oxideav-h265 依赖回
  v1-20261024。vendor 仓库的 `encode_flush` 提交（v1-20261025 tag）保留
  在 GitHub 上但 strhide 不再引用。
- WPP 中段子流容量损失作为**已知限制**记录（见评审报告 M10）。

## 5. 请审阅者回答的问题

1. 在不改 rust_h265 vendor（即拿不到 |c|）的前提下，是否存在比"排除
   中段子流"更好的**可靠**折中？（我们试过的结构定价与低频排除均不能
   同时满足 PSNR ≥ 30 dB 与 max ≤ 200。）
2. 若走 |c| 回填钩子路线：SDH 错位、跨子流块边界（一个 TU 的系数不会
   跨子流，但 CG 概念在 4×4 子块级）、以及 cost 回填与 slot 录制顺序的
   一致性，有无更简单的接口设计（例如整块解完后一次性回填）？
3. 200 的单样本位移上限本身是否合理？（32×32 低频大系数符号翻转的合法
   上界本可超过 200；该断言的本意是抓码流破坏，而我们已证明码流无损。）
4. STC 加权（L¹，cost=幅度）与 MSE 最优（L²，cost=能量）在该场景应如何
   选择？实测两者都不理想，怀疑根因还是缺内容项。

## 附录：相关代码位置（当前 HEAD）

- `rust/src/stego/hevc/engine.rs`：`encode_substream`、3a/3b 轮次、
  `replay_matches_cover`（M10 回退后语义）
- `rust/src/stego/hevc/slot.rs`：`record_stego_sign`（cost 基线模型）
- vendor：`F:\Develop\github\strhide-vendor\rust_h265\src\residual_coding.rs`
  （sign/level 解码顺序、SDH gate）、`.../cabac.rs`（CabacObserver）
- 参考：`temp/github/kvazaar-hevc/src/encoderstate.c:737-761`（行尾写法）、
  `docs/hevc_video_steganography_guide.md` §2.2.2（HevcTuCostModel 公式）
- 外部验证测试：`rust/tests/local/local_media.rs`
  `local_hevc_stego_carriers_decode_in_ffmpeg_with_high_psnr`
