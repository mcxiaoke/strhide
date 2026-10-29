# HEVC 符号翻转代价模型 —— 实施核对清单

> **编制日期**：2026-10-25 16:04
> **对应方案**：`docs/hevc_wpp_cost_final_plan_20261025.md`
> **定位**：本文只回答"怎么落地"。所有结论均对源码实测核对过，与方案文档冲突处以本文为准。
> **仓库**：`C:/Home/Projects/strhide`（主仓）+ `F:/Develop/github/strhide-vendor/rust_h265`（解码器）

## 0. 实测核对结果（先看这张表）

| 方案论断 | 实测 | 结论 |
| :--- | :--- | :--- |
| M10 中段子流 100% 字节级重放 | 临时插桩 `encode_substream(sub, &[])` + `replay_matches_cover` 全量重放：gradient-512 `16/16`、test.heic `28/28`、IMG_5887 `32/32`、IMG_1904 / IMG_0874 / IMG_2887 各 `768/768` 全部 `match=true` | ✅ 方案正确，`engine.rs:678-691` 注释确已过期 |
| 满容量依赖中段子流 | `test_hevc_capacity_is_reachable` 通过，`slots=3757 / needed=3756` —— 几乎吃光整个槽池，说明中段子流确实在被使用 | ✅ 不需要恢复方案 D |
| DC `(0,0)` 不建槽 | `slot.rs:155-161` 提前 `return`，确认存在 | ✅ 回填必须处理 DC 占位 |
| `dq` 已含 `1/N` | `residual_coding.rs:421-427`：`shift = bit_depth + log2_trafo_size - 5` | ✅ 与 §8.6.3 一致，绝不能二次除 N |
| 逆变换移位与 N 无关 | `inverse_transform.rs:188` `shift=7`，`:202` `shift=20-bit_depth`，总计 19 | ✅ 公式成立 |
| `INFINITY` 会 DeadGroup | `stc.rs:707-726`：所有状态代价全 `inf` 时抛 `TrellisCause::DeadGroup` | ✅ 必须用有限大惩罚 |
| vendor 基线 | `cargo test` → 166 passed / 0 failed | ✅ 改动后须保持 |
| 改前失真基线（50% 载荷，`Freshness::Seeded`，3 个种子） | IMG_0874：PSNR 30.77~31.75 dB，max\|d\| 98~106，large_frac 2.8~3.9%<br>IMG_1904：PSNR 26.03~29.18 dB，max\|d\| 134~173，large_frac 7.1~9.9% | ⚠️ 单样本位移 100~173 灰度级，PSNR 掉到 26 dB，问题真实存在 |

## 1. 方案文档需要修正的 7 处（照抄会出问题）

### 1.1 `dq` 并非总存在（会导致编译错误或取值错误）

方案 §3.1 的片段假设循环内一定有 `dq`。实际 `residual_coding.rs:834-859` 是两个分支：

```rust
if cu_transquant_bypass {
    coeffs[y_c * trafo_size + x_c] = trans_coeff_level as i16;   // 无反量化
} else {
    let dq = (trans_coeff_level * scale as i64 * scale_m as i64 + add as i64) >> shift;
    let dq = dq.clamp(-32768, 32767) as i16;
    coeffs[y_c * trafo_size + x_c] = dq;
}
```

→ `cu_transquant_bypass` 路径下 `abs_dq = |trans_coeff_level|`。虽然罕见，但必须显式处理。

### 1.2 `transform_skip` 的二次缩放（方案完全没提）

`residual_coding.rs:870-883` 在循环**之后**又对整块 coeffs 做了一次 `>> ts_shift`（8-bit 4×4 时 `ts_shift = 15-8-2 = 5`，即缩小 32 倍）。循环内上报的 `abs_dq` 会比真实空域扰动大 32 倍 → 这些槽位会被 `1e6` 惩罚整体弃用（容量损失，非质量问题）。

→ 修法：把 `bit_depth` / `ts_shift` / `ts_offset` 提到系数循环之前算好，循环内上报"经过同样缩放后的有效 `abs_dq`"，`coeffs` 的赋值逻辑一行不动。

### 1.3 bit depth 未归一（Main10 会误判）

vendor 声明支持 Main / Main10，`dq` 随位深放大 4 倍；而 `SAFE_MAX_SAMPLE_DELTA` 是按 8-bit 灰度级定的。10-bit 母版会被系统性高估 4 倍。

→ `record_stego_level(..., bit_depth: u8)` 多带一个参数（trait 方法本来就有默认空实现，无兼容成本），代价函数里 `peak_sample_delta /= 2f64.powi(bit_depth as i32 - 8)`。

### 1.4 `StegoSlot` 新增 `abs_level` / `abs_dq` 会白吃内存

`all_slots` 规模实测：IMG_2887 有 271 万槽、IMG_0874 有 157 万槽。`StegoSlot` 当前约 56 B/条，再加两个 `u16` = 每条 +4~8 B（含对齐）→ 最大母版多约占 20 MB 常驻。而这两个字段**下游没有任何消费者**（`engine.rs` 只用 `slot.cost`）。

→ 建议：不落库，`record_stego_level` 里直接把 `cost` 写回 `slot.cost`；只保留 `cost` 字段。若确实要诊断，用 `cfg(debug_assertions)` 或环境变量开关。

### 1.5 `pending_sign_slots: Vec<Option<usize>>` 可以完全不要

方案用"DC 压 `None` + 游标消费"解决错位，方向对，但多了一个每槽 16 B 的临时表。更简做法：

- `record_stego_sign` 遇到 `(0,0)` 直接 `return`（现状已如此，不建槽）；
- `record_stego_level` 遇到 `(x_c, y_c) == (0, 0)` 直接 `return`，**不推进游标**；
- 其余情况取 `slots[cursor]`，`debug_assert_eq!` 校验坐标后写回，`cursor += 1`。

正确性依据：两个回调的坐标序列同源同序（`coords[0..sign_nb]`，一个按 `m` 递增解码符号，一个按 `m` 递增解码电平），且 `(0,0)` 在一个 TU 内唯一，两边的跳过条件字面相同 → 非 DC 顺序天然 1:1。

### 1.6 §4 的阈值自相矛盾

正文写"断言 `max_abs_diff <= 80`"，示例代码写 `<= 100`；且单槽 `Δpeak ≤ 32` 并不能约束同一 TU 内多次翻转的**叠加**（`Δpeak` 是逐槽约束）。→ 阈值必须按实测落定，不要先写死。

### 1.7 缺"依赖联动"这一步（最容易卡住的地方）

`rust/Cargo.toml:41` 锁的是 git tag：`rust_h265 = { git = "...", tag = "v1-20261025" }`。改了 vendor 不换 tag，主仓根本看不到新方法。

→ 两条路径（选一）：
1. **本地联调（推荐先做）**：`rust/Cargo.toml` 临时加
   `[patch."https://github.com/mcxiaoke/rust_h265.git"] rust_h265 = { path = "F:/Develop/github/strhide-vendor/rust_h265" }`，改完删掉。
2. **正式发布**：vendor 提交后打 `v1-20261026` → 推 tag → 主仓改 `tag = "v1-20261026"` → `cargo update -p rust_h265`（需要网络）。

## 2. 执行顺序

| 阶段 | 内容 | 卡点 |
| :--- | :--- | :--- |
| A | vendor 加钩子（`cabac.rs` + `residual_coding.rs`，约 30 行） | `cargo test` 166 项 / `clippy --release -D warnings` / `fmt --check` / `cargo doc`（这四项就是 vendor CI 的内容） |
| B | 主仓 `slot.rs` 换代价模型 + 游标回填 | 建议先只改结构、`cost` 仍用旧公式跑一遍，确认回填对齐无误（`debug_assert` 不炸） |
| C | `engine.rs:678-691` 改注释（逻辑不动） | 注释要按实测重写，别再提"方案 D" |
| D | 确定性回归测试 + 前后对比度量 | 见 §4 |
| E | 依赖 tag 联动、`docs/CHANGES-20261025.md` 记录 | 需用户确认后才提交/打 tag/推送 |

## 3. 具体补丁

### 3.1 `rust_h265/src/cabac.rs`（trait + 转发）

在 `pub trait CabacObserver`（第 38-56 行）末尾加带默认实现的方法（防止第三方实现被破坏）：

```rust
    /// 回填当前 CG 内已记录符号位系数的绝对量化电平与反量化幅值。
    ///
    /// 调用顺序与同一 CG 内 `record_stego_sign` 的调用顺序严格一一对应（含 DC `(0, 0)`）。
    #[inline]
    fn record_stego_level(
        &mut self,
        _x_c: u8,
        _y_c: u8,
        _abs_level: u32,
        _abs_dq: i32,
        _bit_depth: u8,
    ) {
    }
```

在 `impl<'a> CabacReader<'a>` 内（`decode_stego_sign` 之后）加转发：

```rust
    #[inline]
    pub fn record_stego_level(
        &mut self,
        x_c: u8,
        y_c: u8,
        abs_level: u32,
        abs_dq: i32,
        bit_depth: u8,
    ) {
        if let Some(obs) = self.observer {
            // SAFETY: observer 生命周期覆盖整个 decode_nal_with_observer 调用期，单线程顺序访问
            unsafe {
                (*obs).record_stego_level(x_c, y_c, abs_level, abs_dq, bit_depth);
            }
        }
    }
```

### 3.2 `rust_h265/src/residual_coding.rs`（循环内上报）

在 `for m in 0..n_end as usize`（第 794 行）**之前**算好位深与 transform_skip 缩放：

```rust
    let plane_bit_depth = if plane == ResidualPlane::Luma {
        sps.bit_depth_luma
    } else {
        sps.bit_depth_chroma
    };
    let ts_shift = if transform_skip && !cu_transquant_bypass {
        (15 - plane_bit_depth as i32 - log2_trafo_size as i32).max(0)
    } else {
        0
    };
```

循环内把赋值改成"先算 `abs_dq`，再统一上报、统一存储"：

```rust
            let abs_dq: i32;
            if cu_transquant_bypass {
                abs_dq = trans_coeff_level.unsigned_abs().min(i32::MAX as u64) as i32;
                coeffs[y_c * trafo_size + x_c] = trans_coeff_level as i16;
            } else {
                let scale_m: u32 = /* 原样保留 839-855 行 */;
                let dq = (trans_coeff_level * scale as i64 * scale_m as i64 + add as i64) >> shift;
                let dq = dq.clamp(-32768, 32767) as i16;
                // 上报空域等效幅值：transform_skip 在循环后还会 >> ts_shift，这里提前折算，
                // 避免 4×4 transform_skip 块被高估 2^ts_shift 倍。
                abs_dq = if ts_shift > 0 {
                    ((dq as i32 + (1 << (ts_shift - 1))) >> ts_shift).unsigned_abs() as i32
                } else {
                    dq.unsigned_abs() as i32
                };
                coeffs[y_c * trafo_size + x_c] = dq;
            }

            if m < sign_nb as usize {
                cabac.record_stego_level(
                    x_c as u8,
                    y_c as u8,
                    trans_coeff_level.unsigned_abs().min(u32::MAX as u64) as u32,
                    abs_dq,
                    plane_bit_depth,
                );
            }
```

> 注意 839-855 行的 `scale_m` 计算要原样保留（scaling list / dc_scale 查表），不要被上面的改写删掉。

### 3.3 主仓 `rust/src/stego/hevc/slot.rs`

`StegoSlot` 保持只有 `cost`（不加 `abs_level`/`abs_dq`）；`CabacRecorder` 增加一个游标字段：

```rust
    /// 下一个待回填代价的槽位（`record_stego_level` 顺序消费）。
    next_pending_slot: usize,
```

`with_slice()` 是显式结构体字面量，必须同步补 `next_pending_slot: 0`。

代价函数（放在 `StegoSlot` 之后）：

```rust
/// 单像素空域最大允许位移（8-bit 灰度级，超出后软熔断）。
const SAFE_MAX_SAMPLE_DELTA: f64 = 32.0;
/// 软熔断惩罚：必须是有限值，`f64::INFINITY` 会让 STC 在 u=2 组内抛 DeadGroup。
const HIGH_DISPLACEMENT_PENALTY: f64 = 1_000_000.0;

/// 由真实反量化幅值估算符号翻转的失真代价。
///
/// `abs_dq` 已含 H.265 §8.6.3 的 `1/N`（`bdShift = bitDepth + log2(N) - 5`），
/// 此处不能再除 N；§8.6.4 逆变换总增益与 N 无关。
#[inline]
pub fn compute_sign_flip_cost(
    abs_level: u32,
    abs_dq: i32,
    qp: i32,
    trafo_size: u8,
    c_idx: u8,
    x_c: u8,
    y_c: u8,
    bit_depth: u8,
) -> f64 {
    let n = trafo_size.max(4) as f64;
    let dq = if abs_dq > 0 {
        abs_dq as f64
    } else {
        // 兜底：调用方未回填（单元测试直接调 record_stego_sign）时按 §8.6.3 估算。
        let q_step = 2.0_f64.powf((qp - 4) as f64 / 6.0);
        abs_level.max(1) as f64 * q_step * (64.0 / n)
    };

    // 逆变换基向量峰值：0 频 1.0，非 0 频约 sqrt(2)（整数核峰值 ~90 ≈ 64·√2）。
    let gx = if x_c == 0 { 1.0 } else { core::f64::consts::SQRT_2 };
    let gy = if y_c == 0 { 1.0 } else { core::f64::consts::SQRT_2 };
    let bit_depth_scale = 2f64.powi(bit_depth as i32 - 8);
    let peak_sample_delta = (dq * gx * gy) / 64.0 / bit_depth_scale;

    // 整块能量项：抑制大块对整帧 PSNR 的摊薄损伤。
    let block_sse_factor = 1.0 + 0.05 * (n / 4.0) * (n / 4.0);
    let freq_masking = 1.0 + ((x_c + y_c) as f64) * 0.35;
    let comp_factor = if c_idx == 0 { 1.0 } else { 0.7 };
    let l2_cost = peak_sample_delta * peak_sample_delta * block_sse_factor * comp_factor
        / freq_masking;

    if peak_sample_delta > SAFE_MAX_SAMPLE_DELTA || abs_level > 4 {
        HIGH_DISPLACEMENT_PENALTY + l2_cost
    } else {
        l2_cost.max(0.1)
    }
}
```

`record_stego_level`（inherent 方法，与 trait 桥接方法同名不冲突——现有 `record_stego_sign` 已是这种写法）：

```rust
    #[inline]
    pub fn record_stego_level(
        &mut self,
        x_c: u8,
        y_c: u8,
        abs_level: u32,
        abs_dq: i32,
        bit_depth: u8,
    ) {
        // DC 不建槽：镜像 record_stego_sign 的跳过条件，且不推进游标。
        if x_c == 0 && y_c == 0 {
            return;
        }
        let Some(slot) = self.slots.get_mut(self.next_pending_slot) else {
            debug_assert!(false, "record_stego_level outran record_stego_sign");
            return;
        };
        debug_assert_eq!(
            (slot.x_c, slot.y_c),
            (x_c, y_c),
            "CG sign/level desync at slot {}",
            self.next_pending_slot
        );
        slot.cost = compute_sign_flip_cost(
            abs_level,
            abs_dq,
            slot.qp,
            slot.trafo_size,
            slot.c_idx,
            slot.x_c,
            slot.y_c,
            bit_depth,
        );
        self.next_pending_slot += 1;
    }
```

### 3.4 `engine.rs:678-691` 注释重写

```rust
    // H.265 §9.3.2.6 / §7.3.8.2 substream termination. The last substream of a
    // slice ends with `end_of_slice_segment_flag = 1`, already in `ops`. A
    // mid-slice WPP/tile row ends with `end_of_slice_segment_flag = 0`
    // (`Terminate { bit: 0 }`), followed in the bitstream by
    // `end_of_subset_one_bit = 1` and byte alignment; the decoder jumps straight
    // to the next entry point and never records that bit, so emitting
    // `encode_terminate(1)` + `align_zero()` reconstructs the standard tail.
    // Verified 2026-10-25: every substream of every local carrier replays
    // byte-exactly (512×512 WPP: 16/16, real HEICs: 768/768), which is why the
    // embedder may flip bins in mid-row substreams at all.
```

## 4. 度量与回归

改前基线（本次实测，50% 载荷、`Seeded`、payload `(i*131)%251`）：

| 母版 | PSNR | max\|d\| | large_frac |
| :--- | :--- | :--- | :--- |
| IMG_0874.HEIC (seed 1/7/42) | 30.93 / 31.75 / 30.77 | 105 / 106 / 98 | 3.94% / 2.76% / 3.93% |
| IMG_1904.HEIC (seed 1/7/42) | 26.03 / 26.78 / 29.18 | 173 / 134 / 167 | 9.87% / 8.88% / 7.11% |

改后按同一表格复测，再定断言阈值。建议：

1. 先跑 `probe`/`embed`/`extract` 往返正确性（`cargo test --test test_media`）；
2. 再跑本表 6 组，确认 `max|d|` 显著下降、PSNR 上升；
3. 最后把实测值写进 `local_media.rs` 的新测试，阈值留 10~15% 余量（不要先写 `<80`）；
4. 若 `large_frac` 上升（翻转集中到平坦区），说明 `abs_level > 4` 这条硬规则过严，应改为只依赖 `Δpeak`。

## 5. 已知风险

- **同块叠加未建模**：`Δpeak ≤ 32` 是逐槽约束，同一 TU 内多槽翻转会叠加，极端情况下仍可超限。STC 在低载荷下几乎不撞，高载荷下靠 `large_frac` 监控。
- **满载退化**：100% 容量时几乎所有槽都要用，代价模型失效（等价于旧模型），但不会 DeadGroup（惩罚是有限值）。
- **平坦区聚集**：惩罚项会把翻转推向 `|c|` 小的槽位，视觉上可能集中到平坦区域，需要用 `large_frac` 和肉眼抽检确认。
- **兼容性**：代价只影响嵌入侧（提取只读符号位），改代价模型不会让旧文件失效；项目未发布，也不需向后兼容。

## 6. 实施结果（2026-10-25 16:15）

已按 §2 顺序落地，两个仓库均通过各自门禁：

- **vendor `rust_h265`**：提交 `73e7d3a`（feat: 回填钩子）+ `aeadd6d`（style: 修掉当前 stable clippy 两处旧 lint），tag **`v1-20261025-2`**，已推送 `origin/master`。`cargo test` 166 项、`clippy --release -D warnings`、`fmt --check`、`cargo doc`（`-D warnings`）四项全绿。
- **主仓 strhide**：`Cargo.toml` 依赖改为 `tag = "v1-20261025-2"`；`slot.rs` 代价模型 + 游标回填 + 4 项单测；`engine.rs` 注释纠偏（逻辑未动）；`local_media.rs` 新增确定性回归测试。`cargo fmt --check`、`cargo clippy --all-targets -D warnings`、`cargo test`（637 项）、`local_hevc_` 批测 4/4 全绿。

### 改前 / 改后对比（50% 容量、`Seeded`、`(i*131)%251` 载荷）

| 母版 | 种子 | 改前 PSNR | 改后 PSNR | 改前 max\|d\| | 改后 max\|d\| | 改前 large_frac | 改后 large_frac |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| IMG_0874.HEIC | 1 | 30.93 | **37.39** | 105 | **24** | 3.94% | **0.08%** |
| IMG_0874.HEIC | 7 | 31.75 | **37.28** | 106 | **29** | 2.76% | **0.22%** |
| IMG_0874.HEIC | 42 | 30.77 | **36.47** | 98 | **24** | 3.93% | **0.06%** |
| IMG_1904.HEIC | 1 | 26.03 | **38.51** | 173 | **27** | 9.87% | **0.03%** |
| IMG_1904.HEIC | 7 | 26.78 | **38.13** | 134 | **31** | 8.88% | **0.12%** |
| IMG_1904.HEIC | 42 | 29.18 | **38.00** | 167 | **29** | 7.11% | **0.27%** |

结论：单样本位移从 98~173 收到 24~31（落在 `SAFE_MAX_SAMPLE_DELTA = 32` 的设计上限内），整帧 PSNR 提升 6~12 dB，大幅值样本占比下降 30~100 倍；满容量 `test_hevc_capacity_is_reachable`（需 3756/3757 槽）仍通过，说明 `1e6` 有限惩罚没有在高载荷下造成 `DeadGroup`。

### 与方案文档的最终差异（已落地版本）

1. 钩子多带 `bit_depth` 参数，代价函数按 `2^(bd-8)` 归一（Main10 不再被高估 4 倍）。
2. `abs_dq` 在 `transform_skip` 路径折算 `>> ts_shift`；`cu_transquant_bypass` 路径用 `|trans_coeff_level|`。
3. `StegoSlot` 不新增字段；`Vec<Option<usize>>` 占位表改为 `next_pending_slot` 游标。
4. `compute_sign_flip_cost` 拆成 `(幅值已知)` / `provisional_sign_flip_cost`（幅值未知）两条入口，规避 clippy `too_many_arguments`，没有用 `#[allow]`。
