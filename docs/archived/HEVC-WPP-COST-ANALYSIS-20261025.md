# HEVC WPP 符号翻转失真代价与子流重写深度分析报告（2026-10-25）

> 关联文档：[`docs/HEVC-WPP-COST-ISSUE-20261025.md`](file:///c:/Home/Projects/strhide/docs/HEVC-WPP-COST-ISSUE-20261025.md)  
> 分析对象：M10（WPP 中段子流重写）尝试后在 `local_hevc_stego_carriers_decode_in_ffmpeg_with_high_psnr` 测试中偶发/稳定触发 `IMG_0874.HEIC: a decoded sample moved by 225 (limit 200)` 的深层根因与解法审阅。

---

## 1. 现象复现与核心事实确认

### 1.1 测试失败现场
在启用 M10（方案 D：规范 `encode_flush` + RBSP 前缀校验）后，运行本地 HEVC 外部验证测试：
```bash
cargo test local_hevc_stego_carriers_decode_in_ffmpeg_with_high_psnr -- --ignored --nocapture
```
在验证 `IMG_0874.HEIC` 时触发断言崩溃：
```text
thread 'local_media::hevc_external::local_hevc_stego_carriers_decode_in_ffmpeg_with_high_psnr' panicked at tests\local\local_media.rs:866:13:
IMG_0874.HEIC: a decoded sample moved by 225 (limit 200), which is more than a coefficient-sign flip should ever cause
```
关键指标观测：
- **ffmpeg 解码状态**：Clean（0 error, 0 corrupt, 0 complaint）；
- **全帧 PSNR**：$39.28 \sim 44\text{ dB}$（远高于测试门限 $30\text{ dB}$）；
- **大位移样本占比**：$0.0111$（约 1.1%，远低于测试门限 $0.12$）；
- **最大样本位移**：$225$（超过测试门限 $200$）。

### 1.2 为什么回退 M10 后测试全绿？
回退 M10 后，`encode_substream` 恢复无条件追加 `terminate(1)`。由于 WPP 中段子流在行尾为 `terminate(0)`，重放必不一致，导致**每 slice 除最后一行 CTU 对应的子流外，其余中段子流全部被 3a 轮次静默排除**。
- `IMG_0874.HEIC` 约 77% 的槽位（主要位于图像中上部的 32×32 大块）被完全弃用；
- 翻转仅发生在底部的少数小块中，因此最大位移被压低至 66；
- **核心结论**：测试通过是由于“坏槽被排除”掩盖了缺陷，而非代价模型具备真正的保真度。

---

## 2. 源码级实证与前序分析纠偏

通过深入核对 vendor 源码（`F:\Develop\github\strhide-vendor\rust_h265\src\residual_coding.rs`），针对《综述文档》§3.5 中关于“改动难度过高”的预设进行了逐项查证，得出了重要纠偏结论：

### 2.1 纠偏一：SDH（Sign Data Hiding）根本不存在索引错位！
前序分析担忧：“`sign_data_hiding_enabled_flag=1` 时每 CG 首个非零系数符号不在码流中，导致 sign 位与 level 的索引映射偏移 1”。

**源码事实（`residual_coding.rs:770-833`）**：
1. **逆扫描（Reverse Scan）机制**：HEVC 在 4×4 系数组（CG）内按逆扫描顺序遍历非零系数（`m = 0 .. n_end - 1`）；
2. **SDH 隐藏位置**：SDH 规范隐藏的是**前向扫描的第一个非零系数**，这在逆扫描顺序中恰好是**最后一个系数**（即 `m = n_end - 1`，位置为 `first_nz_pos_in_cg`）；
3. **符号位解码**：`sign_nb = if sign_hidden { n_end - 1 } else { n_end }`，随后 `decode_coeff_sign_flags` 传入 `coords[..sign_nb]`。此时解码出的 `sign_nb` 个 sign bit 严格按顺序对应逆扫描的前 `sign_nb` 个系数；
4. **电平解码循环**：紧随其后的 `for m in 0..n_end` 循环中，当 `m < sign_nb` 时，`trans_coeff_level` 与前面记录的第 `m` 个 sign 槽位**完全一一对应，不存在任何索引位移或错位**；
5. 最后一个隐藏系数（`m = n_end - 1`）在码流中本来就没有对应的 bypass bin，因此根本没有触发 `decode_stego_sign`，也不会进入槽池。

### 2.2 纠偏二：SDH 符号绝不发生连带反转
前序分析担忧：“翻转符号位可能引发 SDH 推导符号的连锁变化”。

**源码事实（`residual_coding.rs:822-827`）**：
- SDH 的符号推导依据是该 CG 内所有系数的绝对值之和 `sum_abs & 1`（奇偶校验）；
- Scheme C 隐写仅在 CABAC bypass 域翻转 `coeff_sign_flag`（符号位），**系数绝对值 $|c|$（`trans_coeff_level`）完全未被修改**；
- 因而 `sum_abs` 的值及其奇偶性保持恒定，**推导符号 100% 免疫于隐写翻转，不存在任何二阶连带效应**。

### 2.3 纠偏三：变换单元（TU）绝对不会跨子流
- HEVC 规范中，WPP 切分边界为 CTU 行（通常 $64\times 64$）；
- TU 的最大尺寸为 $32\times 32$；
- 任何 TU 均完整包含在单个 CTU 内部，**绝对不会横跨 WPP 子流边界**。

---

## 3. 对《综述文档》第 5 节四个核心问题的权威解答

### 问题 1：在不改 vendor（拿不到 $|c|$）的前提下，是否存在比“排除中段子流”更好的可靠折中？
**结论：不存在。纯结构几何模型无法从数学上封顶最大空域位移。**
- 无论是乘以 `trafo_size`（线性）还是 `trafo_size^2`（平方），只要代价中缺少真实电平 $|c|$，算法就无法区分“低频小残差（$|c|=1$）”与“低频大残差（$|c|=1000$）”；
- 盲目惩罚大块会导致 STC 将翻转全量转嫁给小块（4×4/8×8），小块局部失真聚集导致整帧 PSNR 崩塌（实测跌至 25~28 dB）；
- 排除低频（如 $x_c + y_c \le 2$）虽然对平坦区域有效，但对复杂纹理图像（如 `IMG_0874`），大系数在较高频位置依然存在。
- **因此，纯结构定价必然在“PSNR 崩塌”与“单样本大位移超限”之间顾此失彼。**

### 问题 2：若走 $|c|$ 回填钩子路线，接口设计如何做到极简？
**结论：无需异步挂起或复杂数据结构，在 CG 级别同步回填仅需约 20 行代码。**
- **设计方案**：
  在 `CabacObserver` trait 中新增一个回调方法：
  ```rust
  fn record_coeff_level(&mut self, level: u32);
  ```
  在 `residual_coding.rs` 的电平循环中：
  ```rust
  if m < sign_nb as usize {
      if let Some(obs) = cabac.observer() {
          unsafe { (*obs).record_coeff_level(trans_coeff_level as u32) };
      }
  }
  ```
- **Recorder 端逻辑**：
  `CabacRecorder` 内部维护刚刚加入当前 CG 的槽位索引切片，收到 `record_coeff_level` 后直接将 `level` 写入对应的 `StegoSlot`：
  - 若 $|c| > 1$（或大块低频且 $|c| > 1$）：直接标记为非 stego 槽位（`slot_idx = None` 或 `cost = f64::INFINITY`），STC Trellis 将自动将其视为湿纸（Wet Paper）绕开；
  - 仅保留真正安全的微小系数（$|c| = 1$）参与嵌入。

### 问题 3：测试中断言 `MAX_ABS_SAMPLE_DELTA <= 200` 是否合理？
- **关于码流破坏**：从标准兼容性来看，225 的位移并未破坏码流（ffmpeg 正常解码且 PSNR 高达 40+ dB），此前 200 的初衷确实是作为防 bitstream 损坏的保守网；
- **关于隐写安全**：从隐写视觉质量（Perceptual Security）来看，单个像素跳变 225 意味着暗部产生肉眼清晰可见的白点（或反之），在现代空域隐写分析（如 SRM/SCA）下极易被检出。
- **判定**：不应单纯放宽测试上限来掩盖代价模型的盲目性；引入 $|c|$ 守卫后，最大位移自然能收敛到 60~100 以内。

### 问题 4：STC 加权（$L^1$）与 MSE 最优（$L^2$）如何选择？
- **此前平方实验失败的原因**：此前实验是对结构尺寸（`trafo_size`）做了平方惩罚，而非对反变换能量做平方；
- **理论指导（UERD 范式）**：
  在反变换域，符号翻转造成的冲激幅度为 $\Delta = 2 |c| \cdot Q_{\text{step}}(QP)$，引起的均方误差（MSE）为 $\Delta^2 = 4 |c|^2 \cdot Q_{\text{step}}^2$；
  因此，真正的 $L^2$ 能量代价应为：
  $$\rho \propto \frac{|c|^2 \cdot Q_{\text{step}}^2(QP)}{\text{freq\_weight}}$$
  配合“$|c| > 1$ 设为不可翻转”的硬门限，算法既拥有高容量，又能实现极佳的 PSNR 与零可见伪影。

---

## 4. 推荐实施路径

1. **Vendor 加固**：在 `rust_h265` 的 `residual_coding.rs` 中增加 `record_coeff_level` 钩子（轻量改动）；
2. **代价模型升级**：在 `strhide/src/stego/hevc/slot.rs` 中引入 $|c|$ 门限（$|c| > 1$ 排除）；
3. **恢复 M10 方案 D**：在子流重写中重新应用规范 flush 与前缀校验，使 WPP 全部子流安全可用；
4. **全量回归验证**：运行 `cargo test local_ -- --ignored` 确认 `IMG_0874.HEIC` 在全量子流开启下 PSNR $\ge 40\text{ dB}$、最大位移 $\le 100$。
