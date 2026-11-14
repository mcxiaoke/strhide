# JPEG 内容域规范（V4）

本文件定义 JPEG（`format_id = 4`）内容域的槽位几何、三元 STC 接口与三套代价模型，供第三方独立实现。信封、字节头布局、AAD、ChaCha12、Fisher-Yates、STC 矩阵与 KDF 见 [CONTENT-ENVELOPE.zh.md](CONTENT-ENVELOPE.zh.md)；DCT 超越函数的逐位纪律见 [DETMATH.zh.md](DETMATH.zh.md)。本文只描述 JPEG 特有的部分。

## 1. 适用范围与稳定性分级

读侧完整路径：JPEG 解码得到各分量按 MCU 交织排列的量化 DCT 系数（`rust/src/stego/jpeg/engine.rs:223-231`）→ 仅取 component 0 做封面摘要（`:238-261`）→ 定位头槽 → 读 44B 超块 → 读扩展区 → 用密钥置换取正文槽 → 取系数 LSB 做三元 STC 综合。代价模型、方向偏置、重编码与重试均不参与读侧。

**载体准入（写侧与容量探测都在解码前/解码时拦截，拒绝即 `UnsupportedFormat`）**：

- **仅 Baseline JPEG（SOF0）**：遇到 SOF2/渐进式直接拒绝，提示转 Baseline 或用结构域 `write`（`engine.rs:68-75`）。
- **分量数只能是 1（灰度）或 3（YCbCr）**：4 分量 CMYK 会被拒绝，因为槽位网格、亮度代价表与 `components_mask` 都假定单亮度平面或 Y/Cb/Cr，否则会把 C 分量误当亮度调制（`engine.rs:118-128`）。
- **三道硬限额**：`MAX_JPEG_MCU_COUNT = 1,048,576`、`MAX_JPEG_TOTAL_BLOCKS = 6,291,456`、整条流水线工作集 `MAX_PIPELINE_BYTES = 8 GiB`（`engine.rs:86-100`，判定见 `:151-166`）。前两项同时用于容量探测与嵌入，避免两条路径对同一载体给出不同结论。

| 级别 | JPEG 内容 |
| :--- | :--- |
| **F** | 44B 超块字段与 CRC；基础头 718 槽与扩展区槽数；component 0 / MCU 块序；Grid 与扁平索引；前缀 Fisher-Yates；正文 `body_n = u·(bits+h−1)`；奇偶映射 `c & 1` 与载体 `2|parity`；STC 综合；`codec_id = 0` |
| **D** | `JpegFormatProfile` 的 `sb_h/sb_u/ext_h/ext_u/grid_rule` 及 KDF 标签；官方值固定为本文数值，替换即产生独立格式（`rust/src/stego/format.rs:115-148`、`:238-249`） |
| **I** | 代价模型选择与全部代价常数；方向偏置与 `polarize_weight`；重编码实现；确定性开关；重试轮数；deflate 级别；`slot_budget`/容量策略 |

I 级项只决定"写成哪些系数"。任何满足同一综合方程的三元改动集都可被读侧解出，因此第三方写入器可以使用不同的代价模型或搜索顺序；若要逐字节复现基线，则必须逐位复现第 4–8 节。

## 2. 第三方必须读出的超块字段（F）

44B 超块布局逐字见 `rust/src/stego/jpeg/header_v4.rs:1-16`，编码 `:74-89`，解码 `:92-169`。

| off:size | 字段 | 类型 | 读侧校验 |
| :--- | :--- | :--- | :--- |
| 0:1 / 1:1 | version / flags | u8 | major 必须 4；flags 只允许 bit0/bit1 |
| 2:2 | suite_id | u16be | 已知 AEAD 套件（1 或 2） |
| 4:16 / 20:12 | salt / nonce | — | L3 salt；AEAD nonce |
| 32:4 | body_len | u32be | 22..=2^26−1，密文长度含 16B tag |
| 36:1 | codec_id | u8 | 必须 0（三元 STC） |
| 37:1 | stc_h | u8 | 4..=10 |
| 38:1 | stc_u | u8 | 1..=64（JPEG 专用宽字段） |
| 39:1 | ext_len | u8 | 0..=255；必须与 `FLAG_EXT_PRESENT` 一致 |
| 40:4 | crc32 | u32be | CRC32-IEEE over bytes[0..40] |

`format_id = 4`、仅亮度分量、无 Hamming 路径均由载体隐含，不写入头（`header_v4.rs:43-70`）。超块本身是头槽前 718 槽的 STC 解码结果，见 §3。

## 3. 槽位几何（F）

### 3.1 块与系数编号

`block_count = coeffs.components[0].blocks.len()`，含 JPEG 的 MCU 填充块，不是可见像素块数（`engine.rs:223-231`）。块序是 **MCU 交织序**，不是分量内光栅序（`rust/src/stego/jpeg/geometry.rs` 的 `positions` 由 MCU 遍历生成）。每个块内系数按自然序（row-major）编号，`k = 0` 为 DC，`k = 1..=63` 为 AC。

官方 `GridRule::ALL_AC` 为 `k_min = 1, k_max = 63`（`format.rs:55-58`）。扁平槽索引 `idx = bi*slots_per_block + (k-k_min)`，`slots_per_block = k_max-k_min+1`；官方即 `Grid = { bi*63 + (k-1) | 0 ≤ bi < block_count, 1 ≤ k ≤ 63 }`（`rust/src/stego/jpeg/v3_layout.rs:29`、`:134-143`、`:196-200`）。DC 永不进入网格：它是头定位 KDF 的摘要输入，必须保持不变（`format.rs:39-51`）。

### 3.2 头槽与扩展槽

`hdr_n = sb_u*(sb_bytes*8+sb_h−1) + ext_u*(8*ext_len+ext_h−1)`。官方 `sb_bytes=44, sb_h=8, sb_u=2, ext_h=8, ext_u=4`：基础头 `2*(352+7)=718` 槽，扩展区 `4*(8*ext_len+7)=32*ext_len+28` 槽（`format.rs:156-169`、`:238-249`）。**即使 `ext_len = 0`，扩展区仍占 28 槽**，故此时 `hdr_n = 746`（一般式 `746 + 32*ext_len`；`CONTENT-ENVELOPE.zh.md:116`、`engine.rs:833`）。

1. `slots_buf = grid_indices(block_count, grid_rule)`，按扁平索引升序生成（`v3_layout.rs:134-143`）。
2. `permute_prefix(slots_buf, hdr_n, locate_seed)`：对全 Grid 做前向 Fisher-Yates 的前 `hdr_n` 步，取前 `hdr_n` 个为头槽（`engine.rs:856-858`；`prng.rs:219-248`）。前向交换保证前缀稳定，读侧可先算 `hdr_min = header_slots(0)` 读完超块后再续算到实际 `hdr_n`（`engine.rs:1257-1269`）。
3. 头槽 `[0..718)` 承载 352 bit，经 `STC(sb_h=8, sb_u=2)`；`[718..hdr_n)` 承载 `8*ext_len` bit，经 `STC(ext_h=8, ext_u=4)`（`engine.rs:951-1003`）。`ext_len = 0` 时后 28 槽不写，但仍被占用、不再分给正文。
4. `BodyGrid = Grid \ HdrSlots`，仍按扁平索引升序构造（排序排除，禁止哈希集合序；`v3_layout.rs:146-193`）。
5. `bits = 8*body_len`；`window = bits + stc_h − 1`；`body_n = u*window`（`v3_layout.rs:98-108`）。
6. `permute_prefix(BodyGrid, body_n, perm_seed)`，再截断到 `body_n`（`engine.rs:1007-1008`、`:1330`）。这是"对全 BodyGrid 的均匀随机有序子样本"，**不是先按代价排序取前 N**；文档旧表述若说"先取 N 再置换"应按代码修正（`v3_layout.rs:22-24`）。

写侧 `u = min(⌊body_grid_len/window⌋, ⌊slot_budget/window⌋, 64)`，且 ≥1；`slot_budget` 是 I 级性能旋钮（`v3_layout.rs:98-107`）。读侧不信预算，只信超块的 `stc_u` 并校验容量（`v3_layout.rs:60-68`）。

### 3.3 奇偶映射
```text
parity(c)     = c & 1              // 0 或 1
carrier(c)    = 2 | parity(c)      // 写侧三元字母表 2/3
```

写侧先以 `2|parity` 送入 STC，再把 `−1/0/+1` 增量施加到原系数（`engine.rs:278-298`、`:482-483`）。读侧只取 `(c & 1)`，不区分 2 与 3（`engine.rs:1405-1410`）。

## 4. 候选、排序与三元 STC（F/I）
JPEG **没有**按代价的候选排序，也 **没有** `exclusion_permille`：44B 超块不携带该字段，引擎不读取它。正文槽顺序就是 §3.2 的置换顺序；代价只进入 STC trellis 的边权。因此第 4–7 节的代价全部是 I 级；"排序键"与 PNG 的 `exclusion_permille` 截断均不适用于 JPEG，不得移植。

- 代价数组按 `bi*64 + k` 索引，分配 64 项/块；DC 固定为 `wet_cost`。
- `plan_slots` 把代价截到 `min(cost, wet_cost)`，并按方向偏置拆分：偏置 `>0` 时 plus 价为 `base*polarize_weight`、minus 为 `base`；偏置 `<0` 反之（`engine.rs:445-453`）。
- 方向选择：`rho_plus <= rho_minus` 取 `+1`，否则取 `−1`；平局取 `+1`（`rust/src/stego/coding/stc.rs:147-155`）。`0` 表示保留。
- 两个方向都被 Huffman 表关闭时，`Move::Both` 但两价均为无穷，只剩"保留"可达（`engine.rs:454-478`）。

三元 STC 写侧求解 `H·(c mod 2) = message`，增量 `δ ∈ {−1,0,+1}`（`stc.rs:515-809`、`:488-514`）。读侧综合逐位为：

```text
s(r) = XOR{ (col[si] >> (r-g)) & 1 ? (v[g*u+si] & 1) : 0 }
       g ∈ [max(0, r-(h-1)), r], si ∈ [0, u)
bit_b = s(b + h − 1)
```

（`stc.rs:408-449`）。前 `h−1` 行是 warm-up，不承载消息位。第三方读侧只需 `c & 1`，不需要知道代价、方向或 `2|parity`。

## 5. UERD 代价模型（I）

入口 `UerdCostModel::compute_cost`，`rust/src/stego/jpeg/cost/uerd.rs:94-196`。

**系数口径**：输入是量化系数 `c[b][k]`；亮度量化表 `Q[k]` 取自文件 DQT 自然序，缺失时由引擎用 Annex K 回退，并逐项 `max(1)`（`uerd.rs:96`）。

**块能量**，对 `k = 1..63` 按升序累加：

```text
E_b = Σ_{k=1}^{63} (|c[b][k]| & ~1) * Q[k]
```

`& ~1` 把量化贡献变成 `|c|` 的阶梯函数（`|1|=0, |2|=2, |3|=2, |4|=4`），使一次 ±1 最多改变一个阶梯；并非"±1 不变"（`uerd.rs:98-116`）。

**块邻域**：块间用 component 0 在 MCU 填充网格上的 8 邻域（含对角），按 `dr ∈ {-1,0,1}`、`dc ∈ {-1,0,1}` 的固定顺序累加，跳过中心；越界或无对应块的填充格跳过，零能量块仍计入；邻居数 `n>0` 时：

```text
Ē_b = E_b + neighbor_weight * (Σ_{neighbors} E_n / n)
```

无邻居时 `Ē_b = E_b`（`uerd.rs:131-167`）。默认 `neighbor_weight = 0.25`（`rust/src/stego/params.rs:594-604`）。

**代价**：块平滑能量 `≤ 0` 时该块全部 AC 置 `wet_cost`；否则对 `k = 1..63`：

```text
ρ[b][k] = min( Q[k] / Ē_b , wet_cost )
```

`wet_cost` 默认 `1e13`（`params.rs:594-604`；`uerd.rs:177-193`）。全部数值为 f64，仅 `+ − * /`，无超越函数。

## 6. J-UNIWARD 代价模型（I）

入口 `JuniwardCostModel::compute_cost`，`rust/src/stego/jpeg/cost/juniward.rs:112-179`。

**预处理**：按 `c*Q` 反量化并对每块做 8×8 IDCT，得到 MCU 填充的亮度平面（跳过 +128；`precover.rs:185-240`）。量化步长 `Q[k]` 取 `max(1)` 后转 f32（`juniward.rs:133-137`）。

**方向滤波**：DB8 分解滤波逐字硬编码 10 位小数：

```text
−0.0544158422,  0.3128715909, −0.6756307363,  0.5853546837,
 0.0158291053, −0.2840155430, −0.0004724846,  0.1287474266,
 0.0173693010, −0.0440882539, −0.0139810279,  0.0087460940,
 0.0048703530, −0.0003917404, −0.0006754494, −0.0001174768
```

（`rust/src/stego/wavelet.rs:23-40`）。平滑滤波 `lpdf[i] = (−1)^i * HPDF[15−i]`（`:42-53`）。三个子带按论文顺序 `(l,h) = 水平、(h,l) = 垂直、(h,h) = 对角`（`:61-68`）。

**可分离残差**：对每个子带，先做水平卷积（`f2`，在 x 方向），再对水平结果做垂直卷积（`f1`，在 y 方向）：

```text
R[y][x] = Σ_{a=0..15} f1[a] * ( Σ_{b=0..15} f2[b] * plane[y+a−8][x+b−8] )
```

边界索引 `clamp(0, w−1)` / `clamp(0, h−1)`；两趟均按 `a` / `b` 升序与 `x` 升序累加（`juniward.rs:426-472`）。方向权重 `1/(|R|+σ)` 写成带 PAD 的 f32 平面，边界复制而非置零（`:474-517`）。

`σ` 默认 `2^-6 = 1/64 = 0.015625`，可由 `params.model_option("sigma", ...)` 覆盖，且 `max(MIN_POSITIVE)`（`juniward.rs:57-58`、`:133-136`）。

**足迹与代价**：对块内 `(i,j)`，用同一对 `f1/f2` 与 DCT 基 `C` 生成 23-tap 一维响应：

```text
u_i[ky] = |Σ_a f1[a] * C[ky+a−15][i]|      // 仅 0 ≤ idx < 8 的项
v_j[kx] = |Σ_b f2[b] * C[kx+b−15][j]|
T_j[ky] = Σ_kx patch[ky][kx] * v_j[kx]
S_i,j   = Σ_ky u_i[ky] * T_j[ky]
ρ[bi][k=i*8+j] += Q[k] * S_i,j             // 每子带累加
```

`SUPPORT = 8+16−1 = 23`，`BASIS_SHIFT = 15`，`PAD = 24`；`i`、`j` 升序，k=0 跳过（`juniward.rs:61-101`、`:264-306`、`:544-576`）。三个子带固定按 `(l,h),(h,l),(h,h)` 顺序累加（`:206-209`）。最终 DC、非有限、`≤0` 或 `> wet_cost` 置湿（`:167-172`）。

**确定性**：`params.deterministic == true` 时强制标量 dot（4 个累加槽、`PAD` 升序，无 SIMD）；否则 x86 上可走 AVX2+FMA `sweep_avx2`（`juniward.rs:148-152`、`:332-423`）。逐位基线与平台迁移必须使用确定性路径。

## 7. J-MiPOD 代价模型（I）

入口 `JmipodCostModel::compute_cost`，`rust/src/stego/jpeg/cost/jmipod.rs:77-160`。

**空间方差**：`estimate_variance(plane, pw, ph, p=3, degree=3, wiener_window=2, floor=1e-6)`；Wiener 残差采用 Matlab `wiener2` 的偶数窗、左上锚定、零填充语义。`dof = 3*3 − 3*4/2 = 3`，逐像素 `σ² = max(1e-6, ‖P⊥r‖²/dof)`（`jmipod.rs:48-58`、`rust/src/stego/spatial_variance.rs:371-405`）。

**DCT 方差传播**：

```text
Var_dct[v,u]   = Σ_{y,x} C[y,v]² * C[x,u]² * σ²[y,x]
Var_q[k]       = max( Var_dct[k] / Q[k]², 1e-5 )
Fisher[k]      = 2 / Var_q[k]²                  // k = 1..63；DC 不活跃
```

（`jmipod.rs:109-131`、`:175-210`）。`Q[k]` 为 `max(1)` 的 DQT 值，`Q²` 逐项平方（`:117`）。

**参考载荷**：`nz_ac` = component 0 全部非零 AC 数；为 0 时回退 `total_blocks*63`。`α` 默认 `0.20` bit/non-zero-AC，可在 `[0.01,0.90]` 覆盖；`target_bits = α*nz_ac`（`jmipod.rs:133-149`）。

**标定与量化**：`fisher_to_costs(fisher, target_bits)`（`rust/src/stego/cost_calibration.rs:206-338`）：

1. `ln(Fisher)`，非有限/`≤0` 记为 `−∞`（inactive）；`REDUCTION_CHUNK = 2^18` 保证分块归约逐位一致（`cost_calibration.rs:55-57`、`:214-241`）。
2. 三元容量 `active*ln 3`，目标 `target = min(target_bits*ln 2, capacity*0.999)`；`LN_3 = 1.0986122886681098`（`:48`、`:249-251`）。
3. 在 `[u_min,u_max]` 建 `BINS = 32768` 的均匀 log-Fisher 直方图（`:50-53`、`:106-124`）。
4. 求根 `ρ*(e^ρ+2) = x` 用 Newton：初值 `ln_1p(x)`、32 轮、停机 `1e-14*(1+|ρ|)`、步长截到 `ρ≥0`、`x` 上限 `1e300`（`:59-81`）。
5. 外层 Lagrange 乘子用 Illinois：初始括区 `t_lo = −max_log−30`，`t_hi = −min_log+5`，各方向最多 100 次 `±10` 扩张；80 轮，停机 `1e-12*max(target,1)`，最终插值（`:259-326`）。
6. `quantize_cost` 清低 20 位尾数（量子 `2^-32`），`0/负/非有限` 原样返回（`:340-379`）。

代价返回后再做：DC、非有限、`≤0`、`> wet_cost` 全部置为 `wet_cost`（`jmipod.rs:154-158`）。本模型的超越函数只经 `detmath`：DCT 基用 `cos`（§8），标定用 `ln`/`ln_1p`/`exp`（`cost_calibration.rs:214-220`、`:68-72`、`:99-102`）。J-MiPOD 的量化代价**直接作为 trellis 边权**，不经过排序；DETMATH.zh.md 中"只参与排序"的表述不适用于 JPEG。

**方向偏置**：仅当 `polarize_weight != 1.0` 时返回 `precover::bias(..., dead_zone=0.0)`；偏置来自反量化→Wiener 3×3→前向 DCT→再量化的估计差（`jmipod.rs:162-172`；`precover.rs:126-150`、`:281-300`）。

**与空间域 MiPOD 的差异**：JPEG 在亮度平面上估计空间方差后传播到 DCT 域，并除以 `Q[k]²`；空间域直接在像素上估计并用 `p=9/l=9`、`floor=0.01`。J-MiPOD 用 `p=3/l=3`、仅 `1e-6` 数值下限；不做空间域的 FI 图平滑（连 3×3 后滤波也不做）；参考速率是 bit/non-zero-AC（`jmipod.rs:30-34`、`:47-58`），空间域是 bit/可嵌入像素。

## 8. precover 与 DCT 基（I）

`dct_basis()[x][u] = 0.5 * c_u * cos((2x+1)uπ/16)`，`c_0 = 1/√2`，其余 `c_u = 1`；`x` 外层、`u` 内层升序生成（`precover.rs:46-64`）。`cos` 必须走 `detmath::cos`（Cody–Waite 三段 `π/2` 归约 + 多项式），不得调用 libm；这是 `rust/src/stego/detmath.rs:298-312` 的逐位实现，摘要见 DETMATH.zh.md §6。

- **硬编码表**：只有 DB8 的 16 个 tap（§6）按 10 位小数逐字冻结；`lpdf` 由它反序变号生成，不另存表。DCT 基没有 64 项硬编码表，运行时由 `detmath::cos` 生成。
- **IDCT**：`idct_block` 按 `B = C·F·C^T` 的两趟矩阵乘实现（前向为 `F = C^T·B·C`），`sum` 顺序为 `v` / `u` 升序（`precover.rs:67-118`）。`decompress_luma` 对每块 64 个系数全部反量化后 IDCT，跳过 +128 level shift（`:185-240`）。
- **禁止 FMA**：标量与确定性路径禁止 `a*b+c` 收缩、禁止重结合、禁止 `fp-contract`（DETMATH.zh.md §8）。J-UNIWARD 的 AVX2+FMA 只在 `deterministic == false` 时可选；基线必须走标量。
- 若第三方不追求逐字节复现，只要求互读，则代价模型整体为 I 级，可完全不实现本节；只要写出的系数满足 §4 的综合方程即可。

## 9. 写侧非规范性约束（I）

- **模型选择**：默认 UERD；J-UNIWARD、J-MiPOD 由调用者选择，不写入任何头字段（`engine.rs:1195-1216` 的读路径无模型参数）。
- **质量与表选择**：不做转码或重压缩，不选择新质量因子。`dct_io::write_coefficients` 用原文件的 Huffman 表重编码熵编码扫描段，EXIF/ICC/DQT/DHT 等所有非熵编码段逐字节保留（`dct-io-0.1.1/src/lib.rs:179-207`；`engine.rs:1057`）。
- **"原 JPEG 还原"**：非扫描段与输入逐字节相同；系数值不变时像素完全相同，但熵编码扫描段由本实现重新写出，**不保证与原文件扫描字节逐字节相同**。内容域不提供 bit-exact restore（restore 属结构域，`rust/src/cli/args.rs:93`），第三方若需原扫描字节必须另存。基线在 seed 模式比较整个 stego 的 SHA-256（`scripts/baseline_hash.py:368`）与提取载荷文本（`:380-382`），不比较原扫描字节。
- **确定性**：`Freshness::Seeded` 使同一载体与同一参数逐字节可复现；`deterministic` 禁用 SIMD 选择（`engine.rs:586-589`）。重试第 1..6 轮（`EMBED_ATTEMPTS = 6`，`engine.rs:562`）；仅"缺失 Huffman 符号"可重试，失败轮用 `applied` 回滚系数（`:773-806`、`:1160`）。每轮 salt/nonce 由 attempt 派生，故重试后头字段不同；读侧从实际超块读取，不依赖轮数。
- **deflate**：载荷可压缩时用 Deflate（唯一算法），级别为 `Compression::default()`（level 6）；仅在更小时使用，读侧按 flags 总是解压（`rust/src/stego/envelope.rs:372-401`）。
- **Huffman 交叉零惩罚**：表存在时，跨零 `0↔±1` 的重复 run 乘 `CROSS_ZERO_REPEAT_PENALTY = 1000`；同块已有该 run 时置 `wet_cost*1000`，并禁止擦除 `±1`（`engine.rs:303`、`:407-442`）。此为写侧启发式，不影响可读性。
- **扩展区 critical**：写侧拒绝 critical TLV；读侧遇到 critical 降级为无隐藏数据（`CONTENT-ENVELOPE.zh.md:107-110`）。

## 10. 自检

```bash
cd rust
cargo build --release --all-features          # 更新 target/release/strhide
cargo test --all-features --all-targets       # JPEG 槽位、STC、代价、往返
cargo test --all-features jpeg                # 仅 JPEG 相关用例
python ../scripts/import_lint.py              # 分层依赖
python ../scripts/cost_vectors_check.py       # 仅覆盖空间域 MiPOD，无 JPEG 向量
python ../scripts/baseline_hash.py --check --only jpg
```

- `cost-vectors`：当前 `docs/api/cost-vectors.json` 只有空间域 MiPOD 的固定向量，JPEG 三套模型没有对外向量文件；第三方逐位复现必须依赖本文公式、`detmath` 摘要与基线，而不是该文件。
- 基线：`baseline_hash.py` 的 JPEG 语料为 `uerd` / `juniward` / `jmipod` 三组（`scripts/baseline_hash.py:85-91`），`--only jpg` 可过滤；`--write` 只能全量冻结（`:528-560`）。
- 确定性数值：`detmath` 的 `exp/ln/cos/ln_1p/log2` 摘要必须匹配 DETMATH.zh.md §9；任何采样、置换、STC 或代价常数改动都要重建 JPEG 基线。
