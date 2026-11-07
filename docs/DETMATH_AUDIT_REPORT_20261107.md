# detmath 实现审计报告（正确性 / 跨语言一致性 / 精度可靠性）

- 审计时间：2026-11-07 10:04（Asia/Shanghai）
- 审计对象：
  - `rust/src/stego/detmath.rs`（工作区版本，含未提交的纯注释改动；`git status` 显示 `M`）
  - `scripts/detmath/detmath.py`
  - `scripts/detmath/detmath.go`
- 任务约束：**本次审计未修改任何项目代码、未改动任何既有文档、未 commit、未 push**。审计用的临时脚本/语料/二进制只放在 `temp/detmath_audit/`。
- 标注约定：**【实测】**＝本机实际运行得到的输出；**【静态分析】**＝读代码/读汇编/按 IEEE-754 规则推导，未运行。

---

## 0. 结论摘要（先看这里）

1. **算法本身没有功能性错误**。exp / ln / cos / sin / log2 / ldexp / frexp 的归约、级数、项数、指数域移位都能对上经典实现，边界行为（±0、±Inf、NaN、次正规、上溢/下溢）在实测中与预期一致。见 §2。
2. **唯一实质性的精度问题是 `ln_1p`**：最坏 **16.63 ulp**（项目自带的 mpmath 脚本），本文语料 **6.91 ulp**，而 `WIRE_SPEC_CONTENT.md` §13.11.5 写的是 “~1 ulp”。原因不是级数项数，而是 `|x| >= 2^-4` 回落 `ln(1.0 + x)` 时 `1.0 + x` 的舍入被 `1/ln(1+x)` 放大。见 §2.3、§4。
3. **“三语言逐位一致”目前不成立**：52,153 条输入中 **20 条**不一致（18 条是 Go 的 NaN 载荷 `0x7FF8000000000001`，2 条是 `cos(±1e15)` 越界后的整型转换差异）。见 §3。
4. **Go 在启用 FMA 的构建上会破坏一致性**：`GOAMD64=v3` 与默认 v1 有 **2176 条**差异；arm64（qemu）与 Rust 有 **2397 条**差异；arm64 上 Go 自带 5 项摘要自检 **5/5 MISMATCH**。见 §3.4、§5.3。
5. **Rust 侧在已测范围内是确定的**：O0/O3/`+fma`/`target-cpu=native`/aarch64-musl(qemu) 对 52,153 条输入 **0 差异**。见 §3.3。
6. **现有测试不足以支撑文档里的跨平台声明**：摘要网格只覆盖 `exp` 的 `k∈[-128,128]`、`ln` 最小 `1e-12`、`ln1p` 仅正数小区间、`cos` 仅 `n∈[0,15]`；CI 只跑 Rust，不跑 Go/arm64；代码注释引用的 `scripts/detmath/compare.sh` **不存在**。见 §5.3。

结论：实现的数值内核**够用且不必重写**（代价管线末端的 `quantize_cost` 截断低 20 位，量子 2^-32，远粗于 1e-15 级误差）；需要补的是**跨语言移植的一致性与验证闭环**，不是数学算法。

---

## 1. 方法与证据清单

### 1.1 版本与来源更正

【实测】`git log --oneline -- rust/src/stego/detmath.rs`：

```text
d65300b fix(stego): route the last two libm call sites through detmath
f497bd3 feat(stego): own exp/ln/ln_1p/cos so costs stop depending on the platform libm
```

【实测】`git show --stat 1d35801` 只改了
`docs/CHANGES-20261106.md`、`docs/api/WIRE_SPEC_CONTENT.md`、`rust/src/stego/cost_calibration.rs`，
**没有**新增 `detmath.rs`。所以任务描述里的 `1d35801` 是前置的 “MiPOD cost 量化” commit；
detmath 实际从 **`f497bd3`** 引入，`log2` 在 **`d65300b`** 补入。

### 1.2 三语言对比装置

`temp/detmath_audit/` 下的临时文件（都不是项目代码）：

| 文件 | 作用 |
|---|---|
| `gen_inputs.py` | 生成 `inputs.tsv`：52,153 行（`函数名 \t 输入位模式hex`） |
| `rust_harness.rs` | 用 `#[path=...] mod detmath;` 直接包含**未改动**的 Rust 源码，逐行输出结果位模式 |
| `py_run.py` | 直接 import `scripts/detmath/detmath.py` |
| `go/harness.go` | 直接复制 `scripts/detmath/detmath.go` 的非 main 部分并加逐行输出 |
| `compare.py` / `accuracy.py` / `analyze2.py` / `constants.py` / `misc_checks.py` | 对比、ulp 精度、分支覆盖、常数核对 |

语料构成【实测】：`exp 20,278`、`ln 10,188`、`ln1p 4,200`、`cos 9,230`、`log2 8,257`，合计 **52,153**。
覆盖：随机常规值、十进制/二进制边界、`2^n` 附近、`±0`、`±Inf`、canonical NaN、最小次正规 `5e-324`、
`|x|` 到 `1e15`、`exp` 的 `EXP_HI/EXP_LO` 两侧、`ln` 的 `√2` 两侧、`cos` 的象限边界与 `n` 跨 `2^20`。

比较的是 **binary64 位模式**：Rust `f64::to_bits`、Python `struct.pack("<d")`、Go `math.Float64bits`。
没有比较 float32；三份实现内部全部是 double。

### 1.3 高精度参考

【实测】使用 `C:\Home\Develop\venv` 的 `mpmath` 200 位（项目自带脚本用 256 位）。
ulp 定义：`|got - true| / ulp(true)`；`true` 为 0 或次正规时统一用 `2^-1074`（修正了早期脚本对
`true < 2^-1074` 误用 `2^(e-52)` 的假象）。

---

## 2. 实现正确性（逐函数）

### 2.1 `exp`（[detmath.rs:154-176](file:///C:/Home/Projects/strhide/rust/src/stego/detmath.rs#L154-L176)）

【静态分析】

- 归约：`k = round_i32(x * INV_LN2)`（[:164](file:///C:/Home/Projects/strhide/rust/src/stego/detmath.rs#L164)），`r = (x - k·LN2_HI) - k·LN2_LO`（[:165-166]）。`|k| <= 1024`，`|k| < 2^20`，因此 `k·LN2_HI` 因 `LN2_HI` 尾数低 20 位为 0 而**严格精确**，`k·LN2_LO` 也只是 1 次舍入。
- 多项式：Horner 到 `EXP_C[0..13]`（1/1!…1/14!），`|r| <= ln2/2 ≈ 0.34657`；截断项 `r^15/15! ≈ 9.5e-20`（注释写 1.07e-19，同量级）。
- 还原：`ldexp(1.0 + r*p, k)`。`k ∈ [-1074, 1024]`，`ldexp` 的两段循环保证中间量为 normal（见 §2.7）。
- 边界：`x > EXP_HI → +inf`，`x < EXP_LO → +0`，`NaN → 返回原 NaN`（保载荷）。
- 结论：**无功能性错误**。次正规输出存在“先舍入 `1+r*p` 再按 2 的幂缩放”的理论二次舍入，但只会造成 ≤1 ulp 且完全确定；实测次正规段 600 例最大 **0.58 ulp**，无需修改。

【实测】精度：最大 **1.00 ulp**、`≤0.5 ulp` 90.02%、`≤1 ulp` 99.99%；项目 256 位脚本 79,081 例最大 **1.1098 ulp**、`≤1 ulp` 99.98%。
`exp(709.782712893384) = 1.7976931348622732e+308`（有限），再大一个 ulp 即 `+inf`，边界正确。

### 2.2 `ln`（[detmath.rs:179-211](file:///C:/Home/Projects/strhide/rust/src/stego/detmath.rs#L179-L211)）

【静态分析】

- `frexp` → `m ∈ [0.5,1)`，再乘 2 并至多折半一次，使 `m ∈ [0.7071, 1.4143]`，`s=(m-1)/(m+1) ∈ [-0.1716, 0.1716]`（[`:192-197`]）。
- `atanh` 级数：循环从 `p=1/23`、`d=21` 递减到 `d=3`，再 `p=1+z*p`，实际包含到 `z^11/23`（注释 [`:199`] 写的是 “through z^10/21”，**差一项**）。截断量在 `|z|<=0.0295` 时 `≈ z^12/25 ≈ 1.7e-20`，比注释 “~1e-17” 还好；该注释错误不影响结果。
- 还原：`ef*LN2_HI + (ef*LN2_LO + ln_m)`（[`:208`]）；`|ef| <= 1074 < 2^20`，`ef*LN2_HI` 精确。
- 边界：`+0/-0 → -inf`，`x<0 → NaN`，`+inf → +inf`；`ln(5e-324) = -744.4400719213812`（0.389 ulp）说明次正规路径正确。
- 结论：**无功能性错误**。

【实测】最大 **1.12 ulp**，`≤0.5 ulp` 99.70%；项目密集样本最大 **2.74 ulp**、`≤1 ulp` 96.05%。文档 “~1 ulp” 对 `ln` 基本成立，但严格说是 “1–3 ulp”。

### 2.3 `ln_1p`（[detmath.rs:213-235](file:///C:/Home/Projects/strhide/rust/src/stego/detmath.rs#L213-L235)）——**唯一有实质精度问题**

【静态分析】

- `|x| < 0.0625`：交替级数 12 项（[:222-232]）。截断项 `x^13/13`，在 `x=2^-4` 时 `≈ 2^-52/13 ≈ 1.7e-17` 绝对值，
  相对 `ln(1.0625)=0.0606` 约 **2.8e-16 ≈ 1.3 ulp**；注释 [`:221`] 的 “~1e-19 relative” 与事实不符（差了约 3 个数量级）。
- `|x| >= 0.0625`：直接 `ln(1.0 + x)`（[`:233`]）。问题在这里：`1.0 + x` 的 1 次舍入误差最大 `2^-53`，
  传递到结果约为 `(2^-53)/(x·ln(1+x))`；当 `x` 刚过 `2^-4` 时分母仅 `0.0606`，误差被放大到 **~8 ulp**，
  再叠加 `ln` 自身 1–3 ulp，实测最坏到 16 ulp。
- 符号零：`ln_1p(-0.0)` 走级数分支，`+0 + (-0)` 得 **`+0.0`**；libm 的 `log1p(-0.0)` 返回 **`-0.0`**。
  这是与 IEEE/libm 的行为偏差（三语言一致地“错”），对格式无影响。
- 结论：**数学结果在可接受范围内，但精度声明错误、负零语义偏差**。

【实测】本文语料最大 **6.91 ulp**（`x = 0.06250000000000006`，恰好落在回落分支）；
`x=0.1` → 5.03 ulp；项目 256 位脚本 88,955 例最大 **16.6360 ulp**，`≤1 ulp` 仅 **75.82%**，
`≤2 ulp` 86.78%。分支拆分：【实测】系列分支（`|x|<2^-4`）1,125 例最大 **3.00 ulp**；
回落分支 3,070 例最大 **6.91 ulp**、`≤0.5 ulp` 95.05%。

### 2.4 `sin_small` / `cos_small`（[detmath.rs:238-266](file:///C:/Home/Projects/strhide/rust/src/stego/detmath.rs#L238-L266)）

【静态分析】Horner 到 `r^17`（sin）/`r^16`（cos），`|r| <= π/4`。
截断项分别约 `8.4e-20` 与 `2.0e-18`（注释 7.7e-20 / 2.9e-18，同量级）。系数全部正确舍入（§3.2）。
【实测】`cos` 近零点（`|cos|<1e-8`，210 例）最大 **0.50 ulp**、100% ≤0.5 ulp，说明小角度的相对精度正常。

### 2.5 `cos`（[detmath.rs:298-312](file:///C:/Home/Projects/strhide/rust/src/stego/detmath.rs#L298-L312)）

【静态分析】

- `n = round_i32(x*TWO_OVER_PI)`（[`:302`]）；三词归约 `((x - nf·PIO2_1) - nf·PIO2_2) - nf·PIO2_3`（[`:305`]）；`n & 3` 选象限（[:306-311]，负数补码等价于数学 `(n mod 4+4) mod 4`，正确）。
- **越界行为**：`|x| >= 2^31·π/2 ≈ 3.37e9` 时 `x*TWO_OVER_PI` 超出 i32。Rust `as i32` 饱和（正→`2^31-1`，负→`-2^31`）；
  Go 的转换是 “implementation-defined”（amd64 上得到 `-2^31`）；Python 用任意精度整数，不饱和。三者从此分道扬镳。
- **精度崩塌点**：`nf·PIO2_1` 并非永远精确。实测 `|x|` 从 1e7（0.418 ulp）到 1.58e7 就跳到 **6.5e6 ulp**，
  `1e8 → 1.09e8 ulp`、`1e9 → 2.75e8 ulp`、`1e15 → 4.9e14 ulp`。文档说的 “2^20 起逐渐退化” 过于保守，
  实际是 **“<~1e7 仍小于 1 ulp，之后断崖”**。
- 管道内只用 `|x| <= π`（DCT 基），不触发任何越界/断崖；但 API 是 `pub fn`，域外没有断言或守卫。
- 结论：**域内正确**；域外既不准也不跨语言一致。文档已承认这一点，但没有代码级防护。

【实测】`|x| <= 2^20·π/2`：最大 **2.24 ulp**、`≤1 ulp` 98.18%、`≤2 ulp` 99.99%；项目 `[-π,π]` 48,073 例最大 **1.7633 ulp**、`≤1 ulp` 98.51%。
`cos(±1e15)` 是三种语言三种答案（见 §3.3）。

### 2.6 `log2`（[detmath.rs:270-283](file:///C:/Home/Projects/strhide/rust/src/stego/detmath.rs#L270-L283)）

【静态分析】`ln(x) * LOG2_E`；定义域处理与 `ln` 相同（`±0 → -inf`、`x<0 → NaN`、`+inf → +inf`）。
因为结果随后在 `header.rs` / `audio/core.rs` 里立即 `.round()`，末位差不会改变整数——除非恰好落在半整数上（概率 ~ulp 量级，可忽略）。
【实测】最大 **1.79 ulp**（项目 20,180 例最大 2.31）、`≤1 ulp` 97.87%。**够用**。

### 2.7 `ldexp` / `frexp` / `round_i32`

【静态分析】

- `ldexp`（[:105-118]）：`k>1023` 时乘 `0x7FE0…`(2^1023) 再减 1023；`k<-1022` 时乘 `0x0010…`(2^-1022) 再加 1022；
  最后指数域 `((1023+k) as u64) << 52`。对 `k=1024`，循环后 `k=1`，指数域 1024 合法；对 `k=-1074`，循环后 `k=-52`，
  先得到 `~2^-1022`（normal），再乘 `2^-52` 一次性进入次正规，只有 1 次舍入。**正确**。
- `frexp`（[:126-141]）：子正规乘 `2^54`（`0x4350…`）提升，掩码 `0x800FFFFFFFFFFFFF` 保留符号+尾数，注入
  `0x3FE0…` 得 `[0.5,1)`。递归只一层，`x*2^54` 不会溢出（最大子正规 `~2^-1022`）。**正确**。
- `round_i32`（[:145-150]）：正数 `(x+0.5) as i32` = round-half-up；负数 `(x-0.5) as i32` = round-half-away。
  归约区间内值域安全；只有 `cos` 的域外输入会触发饱和（见 §2.5）。**域内正确**。

### 2.8 特殊值行为表【实测】

| 输入 | exp | ln | ln_1p | cos | log2 |
|---|---|---|---|---|---|
| `NaN` | 原样返回（保载荷） | canonical NaN | canonical NaN | canonical NaN | canonical NaN |
| `+Inf` | `+Inf` | `+Inf` | —（不适用） | NaN | `+Inf` |
| `-Inf` | `+0` | NaN | NaN | NaN | NaN |
| `±0` | `1` / `1` | `-Inf` | `+0`（libm 为 `-0`） | `1` | `-Inf` |
| 最小次正规 | （输入域外） | `-744.4400719213812` | 走级数 | — | 见 §3 |

`NaN` 载荷【实测】：Python 的 `float("nan")` = `0x7FF8000000000000`；Go 的 `math.NaN()` = `0x7FF8000000000001`；Rust `f64::NAN` = `0x7FF8000000000000`。这是 §3 中 18 条差异的唯一来源。

---

## 3. Magic number 的可信度

### 3.1 核对方法

【实测】`constants.py` + mpmath 200 位：把每个字面量解析成 double，求 `(lit - true)/ulp(true)`；
对“头部+尾部”常数再求 `lit_hi + lit_lo - true` 的绝对残差；对多项式系数逐个与正确舍入的 `1/n!` 比位模式。
对 `PIO2_*` 用 π/2 做真值；对 `LN2_*` 用 ln2；对 `EXP_HI/LO` 用 `1024·ln2` / `-1075·ln2`。

### 3.2 结果表

| 常数 | 位模式 | 与真值偏差 | 判定 |
|---|---|---|---|
| `LN2_HI` | `0x3fe62e42fee00000` | 低 20 位为 0；`hi+lo` 残差 `1.1612227e-26`（≈2^-76） | **正确**，经典 fdlibm ln2_hi |
| `LN2_LO` | `0x3dea39ef35793c76` | 作为 `ln2-hi` 的尾项 `-0.449 ulp` | **正确舍入** |
| `INV_LN2` | `0x3ff71547652b82fe` | `-0.0917 ulp` | **正确舍入**（`std::f64::consts::LOG2_E`） |
| `PIO2_1` | `0x3ff921fb54400000` | 低 21 位为 0（33 位有效） | 经典 fdlibm 拆分，**正确** |
| `PIO2_2` | `0x3dd0b4611a600000` | 低 20 位为 0；是三词设计中的第二词（与完整余项相差约 `PIO2_3`，属正常拆分） | 经典 fdlibm，**可用** |
| `PIO2_3` | `0x3ba3198a2e037074` | 相对理想尾项 `0.732 ulp`（>0.5，非正确舍入） | 经典 fdlibm，**可用** |
| `PIO2_1+2+3` | — | 相对 π/2 残差 `-2.7529965e-37`（≈2^-122） | 注释称 “~139 位” **不准确**：实际约 122 位 |
| `TWO_OVER_PI` | `0x3fe45f306dc9c882` | `-0.6455 ulp`；正确舍入应为 `…883` | **低 1 ulp**（非正确舍入） |
| `SQRT2` | `0x3ff6a09e667f3bcd` | `+0.435 ulp` | **正确舍入** |
| `EXP_HI` | `0x40862e42fefa39ef` | 等于 `float(1024·ln2)`，`-0.209 ulp` | **正确**（见行为验证） |
| `EXP_LO` | `0xc0874910d52d3051` | 比 `-1075·ln2` 高 1 ulp（`…3052`） | **行为正确，注释错误**（见下） |
| `EXP_C[0..13]` | — | 14 个系数全部 = 正确舍入的 `1/(i+1)!` | **正确**（复跑核对输出 `[]`） |
| `SIN_C[0..7]` | — | 全部正确舍入 | **正确** |
| `COS_C[0..7]` | — | 全部正确舍入 | **正确** |
| `ldexp` 魔数 | `2^1023` / `2^-1022` | 行为验证 `k=-1074 → 5e-324` | **正确** |
| `frexp` 魔数 | `2^54` / 掩码 / 注入指数 | `ln(5e-324)` 0.389 ulp | **正确** |

### 3.3 具体写错/写偏的地方

1. **`EXP_LO` 注释错**（[detmath.rs:45-46](file:///C:/Home/Projects/strhide/rust/src/stego/detmath.rs#L45-L46)）：
   注释写 `ln(2^-1074) ~= -745.1332`，实际 `ln(2^-1074) = -744.4400719213812`；
   `-745.1332` 是 `ln(2^-1075)`。**代码值是对的**（`exp(-745.1332191019411) = 5e-324`，
   再小一格即 `0`），因为 `2^-1075` 才是“舍入到最小次正规”的分界。
   ⚠️ 若有人按注释把常数“修正”成 `ln(2^-1074)`，`(-745.133, -744.440]` 区间会错误地返回 0。这是**必须改注释、不能改常数**的典型。
2. **`TWO_OVER_PI` 低 1 ulp**（[:39](file:///C:/Home/Projects/strhide/rust/src/stego/detmath.rs#L39)）：
   【实测】把常量换成正确舍入值后，203 个 cos 相关输入中有 **55 个**象限 `n` 发生变化。
   由于三语言共享同一常量，**当前不影响一致性**；它只影响 cos 在象限边界附近的正确性（管道内 `n` 仅 0/±1/±2，影响可忽略）。
3. **`PIO2` “~139 位” 与 `ln` “through z^10/21” 两处注释不准**：实测分别是 ~122 位、实际含 `z^11/23`。
   都不影响结果。
4. **`ln_1p` 的 “~1e-19 relative”**（[:221](file:///C:/Home/Projects/strhide/rust/src/stego/detmath.rs#L221)）：实际约 `2.8e-16`（≈1.3 ulp），
   若据此以为 `ln_1p` 有 1 ulp 精度会误判。
5. **“four functions / four numbers” 文案过期**（`detmath.rs:414`、`detmath.py:4,10`、`detmath.go:3`）：现在是 5 个函数（含 `log2`）。
6. **`scripts/detmath/compare.sh` 不存在**（`detmath.rs:320,352` 两处引用）：`scripts/detmath/` 下只有 `.py` 和 `.go`。
   注释把验证手段指向一个不存在的文件。

---

## 4. 跨语言一致性（实测）

### 4.1 主结果（amd64 默认构建，52,153 条）

【实测】Rust（MSVC x86_64，release）vs Python 3（同机 CPython）：**2 条**不一致，均为 `cos(±1e15)`。
Rust vs Go（`GOAMD64` 默认 v1）：**19 条**：`ln 7`、`ln1p 3`、`cos 4`、`log2 5`、`exp 0`。
三语言合起来 **20 条**（18 条 NaN + 2 条 cos 越界）。

【实测】三语言不一致明细（`temp/detmath_audit/compare.out.txt`）：

```text
cos: 5   (3×NaN 载荷 + cos(+1e15) + cos(-1e15))
ln: 7    (全部为 NaN 载荷)
ln1p: 3  (全部为 NaN 载荷)
log2: 5  (全部为 NaN 载荷)
exp: 0
```

两条 cos 越界：

```text
in=430c6bf526340000 (+1e15)  py=bfdd5c2cb5e27352  rust=71dafba507d81877  go=6f002428c9e1ce94
in=c30c6bf526340000 (-1e15)  py=bfdd5c2cb5e27352  rust=6f0023b69b950979  go=6f0023b69b950979
```

【静态分析】原因：
- `+1e15`：Rust 饱和到 `i32::MAX`（`n&3=3`）；Go/amd64 转成 `-2^31`（`n&3=0`）；Python 为精确大整数，`n mod 4` 是第三种值。
- `-1e15`：Rust 与 Go/amd64 都到 `i32::MIN`（`n&3=0`），恰好相同；Python 仍不同。
- 18 条 NaN：Go 的 `math.NaN()` 是 `0x7FF8000000000001`，Rust/Python 是 `0x7FF8000000000000`。

### 4.2 构建矩阵（实测）

| 比较 | 差异条数 | 分布 |
|---|---|---|
| Go v1 vs v2 | **0** | — |
| Go v1 vs v3 | **2176** | exp 1774, cos 402 |
| Go v1 vs v4 | **2176** | exp 1774, cos 402 |
| Go v1 vs arm64(qemu) | **2380** | exp 1894, ln 11, ln1p 50, cos 412, log2 13 |
| Rust vs Go arm64(qemu) | **2397** | exp 1894, ln 18, ln1p 53, cos 414, log2 18 |
| Rust O0 / O3 / `+fma` / `native` | **0 / 0 / 0 / 0** | — |
| Rust x86 vs aarch64-musl(qemu) | **0** | 52,153 条全同 |

【实测】Go 自带摘要自检：
- 默认 `GOAMD64`：5 项全 ok（与 Rust 摘要一致）。
- `GOAMD64=v3`：`exp`、`cos` **MISMATCH**（`exp 798e551510d936a6`，`cos 0a028e5986ea4d51`），其余 3 项 ok。
- arm64 + qemu：**5/5 全部 MISMATCH**。
这证明“摘要自检”能发现偏差，但项目 CI 里根本没跑 Go，所以这个信号从未被利用。

### 4.3 根因（静态分析 + 汇编实证）

【实测】`go tool objdump -s "main.exp" go_arm64`（arm64 二进制）：

```text
detmath.go:115  FMSUBD F2, F0, F1, F2     // (x - kf*ln2Hi) 被融合成 FMSUB
detmath.go:115  FMSUBD F3, F2, F1, F1
detmath.go:119  FMADDD F2, F3, F1, F2     // Horner: expC[i] + r*p
detmath.go:121  FMADDD F2, F3, F1, F2
detmath.go:122  FMADDD F2, F3, F1, F1     // 1.0 + r*p
```

Go 语言规范允许把 `a*b + c` 融合为 FMA（arm64 与 `GOAMD64>=v3` 会这么做）；Rust 默认**不收缩**。
融合改变了每一步的舍入，所以 Go 的 `exp`/`cos`/`sin` 在 arm64 上系统性偏移。
`ln` 的残余差异来自 `lnM := 2.0*s*p`（`detmath.go:149`）被并进下一行的加法（`:151`）。

【实测】修复实验（仅在 `temp/` 副本上做，**未改项目代码**）：

| 版本 | 做法 | arm64 相对 Rust 的差异 |
|---|---|---|
| 原始 | — | 2397 |
| fix1 | 所有 `mul+add` 经 `//go:noinline func prod(a,b float64) float64` 屏障 | 94 |
| fix2 | fix1 + `lnM := prod(2.0*s, p)` | 20 |
| fix3 | fix2 + `math.NaN()` → `Float64frombits(0x7FF8000000000000)` | **2**（只剩 cos 越界） |

也就是说：**FMA 屏障 + NaN 规范化**可以把 Go 的差异从 2397 降到 2（那 2 条是 `cos` 域外，本就不该在契约内）。
代价：每个乘加多一次函数调用/阻止内联，Go 移植是校验工具，不是性能路径，完全可以接受。

### 4.4 生产影响

【静态分析】生产只跑 Rust（`cargo build`），Python 仅用于 `scripts/cost_vectors_check.py` 的交叉验收，Go 仅参考实现。
Rust 在已测构建矩阵上 0 差异，因此**当前发布产物的字节一致性不受 §4 差异影响**。
但这与文档 “三份实现必须逐位一致” 的表述冲突，属于**声明与事实不符**，不是产品 bug。

---

## 5. 精度验证方案与现有缺口

### 5.1 精度实测总表

| 函数 | 本文语料 n（有效样本） | 最大 ulp | ≤0.5 ulp | ≤1 ulp | ≤2 ulp | 项目 256 位脚本（n / max / ≤1） |
|---|---|---|---|---|---|---|
| exp | 19,839 | **1.00** | 90.02% | 99.99% | 100% | 79,081 / 1.1098 / 99.98% |
| ln | 10,178 | **1.12** | 99.70% | 99.97% | 100% | 58,087 / 2.7372 / 96.05% |
| ln_1p | 4,195 | **6.91** | 95.69% | 99.24% | 99.67% | 88,955 / **16.6360** / 75.82% |
| cos（abs(x) ≤ 2^20·π/2） | 9,009 | **2.24** | 79.11% | 98.18% | 99.99% | 48,073 / 1.7633 / 98.51%（`[-π,π]`） |
| log2 | 8,249 | **1.79** | 85.15% | 97.87% | 100% | 20,180 / 2.3070 / 98.39% |

其它实测：`exp` 次正规段 600 例 max **0.58 ulp**；`cos` 近零点 210 例 max **0.50 ulp**；
`ln(5e-324)` 0.389 ulp；`exp(EXP_HI)` −0.106 ulp；`exp(EXP_LO)` 0.5 ulp（正确舍入到 5e-324）。

### 5.2 建议的持续验证方案（可执行）

1. **参考实现**：测试期用 `mpmath`（200 位以上，等价 MPFR 精度）；不要把 MPFR 引入运行时代码。
   对 `cos` 的大参数用 `mp.cos(mp.mpf(x))`（不要用 double 的 `math.cos`）。
2. **指标**（每次 PR 都产出，不设“全对”门槛，设回归门槛）：
   - 最大 ulp、`≤0.5/≤1/≤2 ulp` 比例、p99；
   - 按分支分组（`exp` normal/subnormal、`ln` `√2` 两侧、`ln1p` series/fallback、`cos` 象限/域内域外、`log2`）；
   - 正确舍入率单列（当前 exp 90%、log2 85%，不要写 “正确舍入”）。
3. **门槛建议**（基于实测留 2 倍余量）：`exp ≤2`、`ln ≤4`、`ln1p ≤20`、`cos(|x|≤π) ≤3`、
   `cos(|x|≤1e7) ≤4`、`log2 ≤4`；再加一个 `cos` 域外“必须在文档声明的域内才测”的断言。
4. **向量来源与数量**：
   - 现有 52,153 条语料迁到 `scripts/detmath/`（或 `tests/`）并按函数拆分；
   - 每函数至少 2 万条：1 万条随机（对数均匀覆盖量级）+ 5 千条邻近 ulp/边界 + 特殊值/次正规；
   - 每条结果的位模式打包成 FNV/SHA 摘要（沿用现有 digest 机制），作为“廉价回归”；精度指标用 mpmath 离线跑（每周/发版，不必每个 PR）。
5. **纳入 CI**：
   - Rust：现有 `cargo test --lib detmath` 已覆盖摘要；再加 `aarch64-unknown-linux-musl` 交叉编译 + qemu 跑摘要（当前 CI 未做）。
   - Go：在 CI 加 `go run scripts/detmath/detmath.go`（默认 + `GOAMD64=v3`），以及 `GOARCH=arm64` + qemu 跑摘要；
     这是**最低成本**能挡住 §4 FMA 回归的手段。
   - 三语言联测：把 `gen_inputs.py` + 三个 harness + `compare.py` 收进仓库，作为独立 job（可 nightly）。
   - Python：CPython 每个字节码一次舍入，无 FMA 风险；只需跑摘要即可，不需要屏障。
6. **当前测试缺口【实测/静态分析】**：
   - `output_digests_are_pinned` 的网格：`exp` 仅 `k∈[-128,128]`（不含次正规、`EXP_HI/EXP_LO`、`±Inf/NaN`）；
     `ln` 最小 `1e-12`（无次正规）；`ln1p` 仅 `0..0.597`（无负数、无 `-1`、无回落分支的边界）；
     `cos` 仅 `n∈[0,15]`（无特殊值、无大参数）；`log2` 最小 `8.67e-19`（无次正规）。
   - `stays_close_to_the_platform_libm` 只测 `x=i/3, |i|<=400`，且用 libm 作参考（参考本身不保证正确舍入），
     对 `ln_1p` 只有一条 `1e-12` 断言；**完全覆盖不到 16.6 ulp 的回落分支**。
   - CI（`.github/workflows/ci.yml`）只跑 Rust；Go/Python 摘要与 arm64 都不在 CI 里。
   - `scripts/detmath/compare.sh` 不存在，注释里的“CI 会 diff 三语言”是空头支票。

---

## 6. 可靠性风险（跨平台）

### 6.1 已实测

| 配置 | 结论 |
|---|---|
| x86_64 MSVC rustc release，O0/O3/`+fma`/`target-cpu=native` | 52,153 条 **0 差异** |
| aarch64-unknown-linux-musl（rust-lld 交叉编译，qemu 运行） | **0 差异** |
| Go amd64 `GOAMD64=v1` vs `v2` | 0 差异 |
| Go amd64 `GOAMD64=v1` vs `v3/v4` | **2176 差异**（FMA） |
| Go arm64（qemu） | **2397 差异**（FMA + NaN + int 转换） |
| Python CPython 3（Windows x86_64） | 与 Rust 仅 2 条 cos 域外差异 |

文档另称 2026-11-07 已在真实 Debian 11 arm64 上跑过 28 例字节基线（`CHANGES-20261107.md` 09:12）。
本次没有独立复验真实硬件，只复验了 qemu；该声明属于**项目自述**。

### 6.2 未测 / 无法保证

1. **x87 80-bit 中间精度**：本次没测 i686/32-bit。Rust 的 `i686-*` 目标默认要求 SSE2，正常构建不会走 x87；
   但若有人显式 `-C target-feature=-sse2`，中间精度变化会破坏确定性。建议在 CI 或文档中**禁止该配置**。
2. **`-ffast-math` 类**：Rust stable 不暴露 fast-math；但 `RUSTFLAGS` 可以加 `-C target-feature` 等。
   当前没有 CI 检查 `RUSTFLAGS`；建议加一条 “禁止改变浮点语义的 flags” 的说明/检查。
3. **不同 rustc/LLVM 版本**：未做版本矩阵。理论上 IEEE 运算 + 禁止收缩可保证结果稳定，但常量（`std::f64::consts`）
   与优化器的表达式重排仍需实测。建议在 CI 固定 toolchain，并用 `rust-toolchain.toml` 锁定。
4. **Go 的 386/other arch**：只测了 amd64/arm64。Go 386 的浮点实现细节未验证。
5. **Python 的其他实现**（PyPy、GraalPy）：CPython 已验证；其他实现的浮点求值策略未验证。
6. **FMA 之外的指令级差异**（如 ARM 的 `FMUL` 与 `FMADD` 选择随编译器版本变化）：Go 的 FMA 收缩**没有语言级保证**，
   今天用屏障能压住，未来编译器仍可能以别的方式重排；这条是**结构性风险**，只能靠 CI 持续盯摘要。
7. **`cos` 越界**：三种语言对 `|x| >= 3.37e9` 的整型转换行为不同（Rust 饱和、Go implementation-defined、Python 任意精度），
   任何调用方一旦越界，**逐位一致契约立即失效**，且精度也崩塌。当前靠“管道内不会发生”约束，不是代码保证。

### 6.3 可落地的检测手段

- 把 §5.2 的 CI 矩阵落地：Rust x86_64 + aarch64(qemu)、Go v1/v3/arm64(qemu)、Python；
  每个都跑同一份 52,153 条语料摘要（若太长，至少跑现有 5 组 digest + 边界值）。
- 每次发版保留一份 `temp/` 之外的“跨架构摘要”产物（5×64-bit），作为可追溯证据。
- 对 `cos` 在 API 入口加 `debug_assert!(x.abs() < 2f64.powi(20) * PI/2)` 或显式文档约束；
  检测手段可以是 CI 里跑一个“域外输入必须返回 NaN”的测试，而不是让域外输入静默返回垃圾。
- 对 Go 移植：加 `prod` 屏障 + `Float64frombits` canonical NaN（§4.3 已实证 2397→2）；
  这只影响校验工具，不影响产品。

---

## 7. 方案建议（按优先级）

### P0（应当尽快做，成本低、直接消除“声明与事实不符”）

1. **Go 移植加 FMA 屏障 + NaN 规范化**
   - 改什么：`detmath.go` 里所有 `a*b + c` 改为经 `//go:noinline func prod(a,b float64) float64`；
     `math.NaN()` 改为 `math.Float64frombits(0x7FF8000000000000)`；注意 `ln` 的 `lnM := 2.0*s*p` 也要走 `prod`。
   - 怎么验证：GOAMD64=v1/v3/v4 + GOARCH=arm64（qemu）跑 5 项摘要 + 52,153 条对比，目标从 2397 降到 2。
   - 成本/风险：极低（只改移植工具）；风险是把 Go 变得更慢，但 Go 不参与生产。
2. **CI 加 Go 摘要（默认 + `GOAMD64=v3`）与 arm64（qemu）摘要**
   - 改什么：`.github/workflows/ci.yml` 加 job；或先加一个 `scripts/detmath/check.sh`。
   - 怎么验证：故意把 `prod` 改成普通乘法，CI 必须红。
   - 成本/风险：低；qemu 镜像/交叉编译需要固定版本，否则 CI 自身不稳定。
3. **修正 `ln_1p` 的精度声明与负零行为说明**
   - 改什么：`WIRE_SPEC_CONTENT.md` §13.11.5 把 `ln_1p` 的 “~1 ulp” 改为 “最坏 ~17 ulp（回落分支），
     在代价管线内可接受”；`detmath.rs:221` 的 “~1e-19” 改为 “~3e-16（≈1.3 ulp）”。
     是否修 `ln_1p(-0.0)` 的符号：建议**只写文档、不改代码**（改代码会改摘要、改三语言，且格式路径不需要负零）。
   - 怎么验证：重跑 mpmath 脚本，引用 16.6360/6.91 两个数。
   - 成本/风险：纯文档；无代码风险。
4. **补 `scripts/detmath/compare.sh`（或删掉注释里的引用）**
   - 改什么：新增一个真正能跑的脚本，串起 `gen_inputs` + 三个 harness + `compare.py`；或把 `detmath.rs:320,352` 的
     “compare.sh” 改为实际命令。
   - 怎么验证：本地/CI 跑一次，输出 “20 mismatches” 或 “ALL BIT-IDENTICAL”（取决于是否先做 P0-1）。
   - 成本/风险：低。

### P1（发版前应做）

5. **扩充摘要网格**：`exp` 加 `±EXP_HI/EXP_LO`、次正规（`|x|>708`）、`±Inf/NaN`；`ln` 加最小次正规与 `1.0`；
   `ln1p` 加 `-1`、`-0.0`、`2^-4` 两侧、负数；`cos` 加 `±Inf/NaN`、`0`、`±π/2`、`±π`；`log2` 加次正规与 `±0`。
   同时保留一份“分支标签”，让摘要失败能定位到函数。成本：改 3 个文件的测试网格 + 更新 PINNED；风险：摘要会变一次（属于预期）。
6. **把三语言 52,153 条语料收进仓库**：作为 nightly job，而不是只活在本机 `temp/`。
7. **`cos` 域约束代码化**：在 `pub fn cos` 入口加 `debug_assert!(|x| < 2^20·π/2)`（或返回 NaN 并文档化）。
   成本极低；风险是“域外调用方”会暴露（目前没有，属于好事）。

### P2（可选，收益有限）

8. **把 `TWO_OVER_PI` 改成正确舍入的 `0x3fe45f306dc9c883`**：会改变 55/203 个象限判定，从而改 `cos` 结果与摘要；
   管道内几乎无影响，但属于“改格式噪声”。**不建议现在做**，除非同时重建基线并跑三语言。
9. **对 `cos` 做 Payne–Hanek 或更高位数归约**：只有需要支持 `|x|>1e7` 时才值得；当前管道 `|x|<=π`，**属于过度设计**。
10. **`ln_1p` 改造**：若未来要求 ≤2 ulp，可把回落分支改成 `ln(1+x)` 的补偿形式（先算 `u = 1+x`，再用
    `ln(u) + (x - (u-1))/u` 修正），但会改摘要与三语言。当前代价管线对 `ln_1p` 误差不敏感（Newton 容差 1e-14，
    末端量化 2^-32），**不必做**。

### 已经足够、不必过度设计的部分

- `exp`/`ln`/`log2`/`cos`（域内）的精度：1–3 ulp 对 `quantize_cost`（截断低 20 位、量子 2^-32）绰绰有余；
  不需要 double-double、正确舍入或 MPFR 运行时。
- Rust 的 FMA 行为：Rust 默认不收缩，已实测 0 差异；不需要在源码里加屏障（那是 Go 的问题）。
- `ldexp`/`frexp` 的位操作：已逐条核对，不需要改成 `mul`/`logb`。
- Python 移植：CPython 无 FMA，**不需要**照抄 Go 的 `prod` 屏障。
- `analysis/calibration.rs` 仍用 libm：它不参与写格式，保持现状即可（文档已注明）。

---

## 附录 A：复现命令

```powershell
# 语料 + 三语言输出
cd C:\Home\Projects\strhide\temp\detmath_audit
C:\Home\Develop\venv\Scripts\python.exe gen_inputs.py
C:\Home\Develop\venv\Scripts\python.exe py_run.py
#  Rust: rustc -O harness，生成 rust_out.tsv
#  Go:   go build -o go_harness.exe ./go; .\go_harness.exe > go_out.tsv
C:\Home\Develop\venv\Scripts\python.exe compare.py

# 精度
C:\Home\Develop\venv\Scripts\python.exe accuracy.py
C:\Home\Develop\venv\Scripts\python.exe C:\Home\Projects\strhide\temp\detmath_mpmath_diff.py  # 项目自带 256 位脚本
C:\Home\Develop\venv\Scripts\python.exe constants.py
C:\Home\Develop\venv\Scripts\python.exe misc_checks.py

# Go 构建矩阵
$env:GOAMD64='v3'; go run detmath.go          # exp/cos MISMATCH（实测）
$env:GOARCH='arm64'; go build ...             # qemu 运行：5/5 MISMATCH（实测）
wsl -e sh -c "cd /mnt/c/Home/Projects/strhide/temp/detmath_audit && ./digest_arm64"
```

## 附录 B：证据文件

- `temp/detmath_audit/compare.out.txt` —— 三语言 20 条差异明细
- `temp/detmath_audit/accuracy.out.txt` —— 各函数 ulp 分布与最坏输入
- `temp/detmath_audit/mpmath_diff.out.txt` —— 项目 256 位脚本（30 万采样）
- `temp/detmath_audit/constants.out.txt` —— 常数核对原始输出
- `temp/detmath_audit/analyze2.out.txt` —— 分支分组精度
- `temp/detmath_audit/*.tsv` —— 各构建的逐行输出（rust_o0/o3/o3fma/native/arm64、go_default/v2/v3/v4/arm64、gofix*）

## 附录 C：本次审计的边界

- 【实测】只在本机 Windows 10 x86_64 上运行 Python/Go 与 Rust MSVC；aarch64 是 qemu 下的交叉编译产物，
  不是真实 ARM 硬件。真实硬件的项目自述见 `CHANGES-20261107.md` 09:12，本次未复验。
- 【实测】未测 i686/x87、未测 `-ffast-math`、未测不同 rustc 版本、未测 PyPy。
- 代码行号对应**工作区当前版本**（含未提交注释改动）；HEAD 版本的注释行号略有差异。
- 本报告没有修改任何项目源码；`git status` 中的 `M docs/CHANGES-20261107.md` 与 `M rust/src/stego/detmath.rs`
  是审计开始前就存在的未提交改动，本次未触碰。
