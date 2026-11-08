# PNG 内容域：槽位、代价与通道（V4）
本文件规定 `format_id = 1` 的 PNG 载体如何选择槽位、如何由三种代价模型构造排序键、如何展开正文通道。公共信封、64 字节基础头、TLV、`locate_seed`/`perm_seed`、ChaCha12/Fisher–Yates、STC 见 [CONTENT-ENVELOPE.md](CONTENT-ENVELOPE.md) §2–§7；初等函数见 [DETMATH.md](DETMATH.md) 与 `rust/src/stego/detmath.rs:3-16`。下文所有 `exp/ln/ln_1p/cos/log2` 均指该实现，不是平台 libm。
## 1 范围与稳定性
- 载体为 8-bit、非隔行、颜色类型 0/2/4/6 的 PNG；隔行、调色板、APNG、16-bit 不属于本规范（`rust/src/stego/png/engine.rs:92-95`、`:245-262`）。
- **颜色类型 0/2 携带 `tRNS` 块时直接拒绝**：对 0/2 类型，`tRNS` 是单一透明色键（透明色键值，同值像素视为全透明），不是 alpha 通道；类内 `±1` 嵌入会把像素移出或落入色键，使透明背景变黑或实心像素镂空。引擎在解析阶段即报 `UnsupportedFormat`，提示改用 RGBA / 灰度+alpha，或改走结构域 `write`（`rust/src/stego/png/engine.rs:295-311`）。颜色类型 4/6 的 `tRNS` 是真正的 alpha，不受影响。
- **`IEND` 之后的尾随数据原样保留**：`IEND` 块（含其 4B CRC）之后到文件末尾的所有字节按非 chunk 数据处理，读入 `tail` 并在重编码时逐字节追加回文件尾（`engine.rs:118-121`、`:326-344`、`:794`、`:855`）。长度上限 `MAX_TAIL_BYTES = 16 MiB`，超出报 `CorruptedData`（`engine.rs:334-341`）。这是位保真的必要条件：部分厂商把数字签名/防伪标记放在 `IEND` 之后。
- `algorithm_id` 1/2/3 与 `hill`/`suniward`/`mipod` 永久绑定；未知 id 不得回落默认模型（`rust/src/stego/png/registry.rs:13-17`、`:57-64`；`rust/src/stego/png/engine.rs:2049-2050`）。

| 级别 | 本域内容 |
| --- | --- |
| **F** | `format_id=1`；`algorithm_id` 1/2/3；`channel_mode`、`class_rule`；`p1_window`、`p2_window`、`neg_log2_epsilon`、`exclusion_permille`、`sigma`（MiPOD 时为 `alpha`）；头部池与布局；正文候选排序/截断；三种代价图及 `fisher_to_costs` 的低 20 位尾数量化 |
| **D** | 无。本域没有可追加且读侧可忽略的字段；未来新增 `algorithm_id` 属于 F 级分配 |
| **I** | 方向代价、并行/SIMD 等价实现、PNG 重编码的滤波器与 deflate 参数、外层重试；读侧均不依赖（§8） |

1.0 前 F 级内容仍可能调整；调整必须重建 `scripts/baseline_hash.py` 基线。

### 1.1 1.0 冻结规则（PNG 特有）

本域的 F 级内容比 JPEG / HEVC / 音频三域**更刚性**，因为提取端必须逐位重构写入端的代价图与候选排序：

| 域 | 提取端是否重建代价图 | 代价模型能否在不破坏旧载体的前提下优化 |
| --- | --- | --- |
| PNG 空间域 | **是**（候选池截断 + 全量排序） | **不能** |
| JPEG 频域 | 否（`stc_h`/`stc_u` 自描述 + 种子置换） | 能 |
| HEVC 压缩域 | 否（CABAC 原位语法元素） | 能 |
| WAV / FLAC | 否（按帧参数定位） | 能 |

因此 1.0 之后：

- `algorithm_id` 1/2/3 的每一个数值步骤（灰度化、三阶段卷积、边缘填充、`sigma` / `alpha`、`fisher_to_costs` 的低 20 位尾数量化、比较键的构造顺序）**永久冻结**。以“优化”或“修复”为名的任何数值改动都会让旧载体的载荷不可恢复；
- 新代价模型只能以**新的 `algorithm_id`** 追加，既有三个 id 的语义永不改变；
- 允许的改动限于**不改变字节输出**的等价重写（SIMD、并行、内存布局），且必须通过 `baseline_hash.py --check` 28/28 与真实载体往返验证。
## 2 输入：基础头即全部参数
写侧先量化参数（`rust/src/stego/params.rs:210-236`）；读侧只信基础头，调用方参数仅为提示（`rust/src/stego/png/engine.rs:2060-2078`）。

| 输入 | 位置/来源 | 读侧语义 |
| --- | --- | --- |
| `pixels,w,h,channels` | PNG 解码器 | 行优先、通道交错，`channels ∈ {1,2,3,4}` |
| `format_id` | 头字节 34 | 必须为 1（`header.rs:271`、`:326-330`） |
| `algorithm_id` | 头字节 35 | 1 HILL / 2 S-UNIWARD / 3 MiPOD，1..=3（`header.rs:332-336`） |
| `channel_mode` | 头字节 41 | 0 Green / 1 RGB；其他值拒绝（`header.rs:337-340`） |
| `class_rule` | 头字节 42 | 0 或 1；写侧恒 1，读侧按头值（`engine.rs:1721`、`:1359`、`:2141`） |
| `p1_window` / `p2_window` | 头 44:2 / 46:2 | 正奇数 1..=63；缺省 3 / 15（`header.rs:280-281`；`params.rs:243-244`） |
| `neg_log2_epsilon` | 头 48:2 | `epsilon=2^-k`，k 1..=127；缺省 k=23（`header.rs:30-37`、`:282`；`params.rs:245`） |
| `exclusion_permille` | 头 50:2 | 0..=900；缺省 300（`header.rs:283`；`params.rs:246`） |
| `sigma` | 头 52:4，f32le | S-UNIWARD 时是 `sigma`（缺省 1.0）；MiPOD 时是 `alpha`（缺省 `0.20f32`），读侧钳到 `[0.01,0.90]`（`engine.rs:1678-1691`、`:2069-2077`；`mipod.rs:55`） |
| `codec_id/stc_h/stc_u` | 头 38/39/40 | 只决定正文槽数与编码；写侧缺省 `h=8, u=0(auto)`（`engine.rs:2107-2122`；`params.rs:247-249`）。**`u = 0` 只是写侧运行时枚举值**：写头前必须解析为具体 `1..=3`（连同 `codec_id` 一起由 `auto_select_codec` 按实际承载正文的槽池选出，`engine.rs:1571-1630` 的结果写入 `:1727` 的 `wire_u`）；读侧要求 `codec_id=1` 时 `stc_h ∈ 4..=10` 且 `stc_u ∈ 1..=3`，读到 `u=0` 判 `CorruptedData`（`header.rs:365-382`） |
| `locate_seed`/`perm_seed` | L2/L3 | 头部/正文置换键（[CONTENT-ENVELOPE.md](CONTENT-ENVELOPE.md) §6） |
| `kernel_id` | 头 56 | 只接受 0，即内置归一化 KB 核（`hill.rs:15-22`） |

`p1/p2` 经 `PngParams::validate` 拒绝 0 与偶数（`params.rs:326-332`）；trait 直接调用时还会防御性归一化为 `max(1)|1`（`hill.rs:93-102`）。
## 3 像素、槽位与通道
### 3.1 头部通道 `hc`
`hc = 1` 当 `channels >= 3`，否则 `0`（`engine.rs:1046-1048`）。`channels=2`（灰度+alpha）时 `hc=0`；alpha 永不参与候选。
### 3.2 头部池与布局
头部池是全部满足 `8 <= pixels[px*channels+hc] <= 247` 的像素，按像素升序，与代价图无关（`engine.rs:72-73`、`:1139-1153`）。对池做 `permute_prefix(pool, 512+8*ext_len, locate_seed)`（`engine.rs:1193-1199`）；该前缀 Fisher–Yates 的 `k` 被钳到 `n-1`（`rust/src/stego/prng.rs:204-248`）。

基础头占前 512 槽，扩展区每字节 8 槽（`header.rs:153-156`；`engine.rs:1281-1316`）。第 `b` 字节第 `j` 位（`j=0` 为 MSB）写入 `header_slots[b*8+j]` 的 `hc` 通道，扩展区从索引 512 续接（`engine.rs:1820-1852`）。读侧先用 `ext_len=0` 读前 512 槽，再按头中的 `ext_len` 续接同一置换（`engine.rs:2000-2018`）。`carrier_slots<512` 或 `512+8*ext_len>carrier_slots` 必须返回 `NoHiddenData`（`engine.rs:1995-2013`）。
### 3.3 正文候选与槽位展开
正文候选像素先通过同一个 `hc` 条件，再按 §4 排序/截断（`engine.rs:1241-1279`）。槽是字节偏移 `slot=px*channels+c`（`engine.rs:1320-1326`、`:1354`）。
按候选像素升序、像素内通道升序访问；跳过“该像素 `hc` 通道已被头部占用”的槽，同像素其他通道仍可用（`engine.rs:1331-1334`、`:1348-1353`）。每个被访问通道还须满足：

1. 自身值 `val ∈ [8,247]`；
2. 当 `class_rule==1` 时，`val % 8 ∈ [1,6]`。

否则跳过（`engine.rs:1354-1361`）。写侧恒传 `class_rule=1`（`engine.rs:1721`、`:1742`）；读侧用头值，只有 `0` 会跳过第 2 条（`engine.rs:1359`、`:2141`）。`class_rule=1` 排除 `r=0/7`；`r=1` 只可 `+1`、`r=6` 只可 `-1`、`r=2..5` 两向皆可（`rust/src/stego/coding.rs:376-382`）。

取得前 `needed_body_slots` 个槽后，对数组做 `permute_indices(body, perm_seed)`；置换后第 `i` 个元素才是第 `i` 个正文槽（`engine.rs:1738-1744`、`:1857-1859`）。`needed_body_slots` 由 `body_len*8` 与 `codec/h/u` 决定（`engine.rs:2117-2122`）。
### 3.4 通道模式
| `channel_mode` | `channels>=3` | `channels<3` | 语义 |
| --- | --- | --- | --- |
| 0 Green | `[1]` | `[0]` | 仅 `hc` |
| 1 RGB | `[0,1,2]` | 不可用 | R/G/B；alpha 永不用 |

（`engine.rs:1050-1091`）。未知值或不支持的 mode 一律 `NoHiddenData`（`engine.rs:2100-2105`）。写侧优先 Green；容量不足且 `channels>=3` 时升级 RGB（`engine.rs:1562-1636`）。
## 4 候选排序与截断
```text
eligible = { px | 8 <= pixels[px*channels+hc] <= 247 }       // 像素升序
ranked   = [(cost[px].to_bits(), px) for px in eligible]
allowed  = len(ranked) * (1000 - exclusion_permille) / 1000   // usize 整数除法，向零截断
candidates = ranked 前 allowed 个，按 (cost.to_bits(), px) 升序
```

整数公式是线格式的一部分；写成浮点 `len*(1.0-p/1000.0)` 会差一个元素（`engine.rs:1263-1273`）。`allowed<len` 时先 `select_nth_unstable(allowed_count)`、截断、再排序前缀；`allowed==len` 全排序；`allowed==0` 候选为空（`engine.rs:1274-1279`）。`(cost bits,px)` 是全序，因此选择与全排序逐位一致；平局按像素索引升序（`engine.rs:1248-1261`）。三种内置模型代价均非负有限（MiPOD 非活跃元素为 0），`to_bits()` 字典序等于数值序，无 NaN（`cost_calibration.rs:202-205`）。
## 5 HILL（`algorithm_id = 1`）
### 5.1 灰度化与填充
```text
class_value(v) = v & 0xF8
channels==1 : gray[i] = class_value(pixels[i])
channels>=3 : r=class_value(pixels[i*channels]); g=class_value(pixels[i*channels+1])
              b=class_value(pixels[i*channels+2])
              gray[i] = 0.299*r + 0.587*g + 0.114*b          // 左结合
channels==2 : gray[i] = class_value(pixels[i*channels])
```

逐字见 `hill.rs:56-77`；`class_value` 见 `hill.rs:231-237`。RGB 三个通道都先清低 3 位再加权；这保证类内 `±1` 后代价图逐位不变（`hill.rs:56-66`）。

```text
pad = 1 + (p1-1)/2 + (p2-1)/2                    // 整数除法
reflect_index(t,n): n<=1 -> 0; period=2n; t=t.rem_euclid(period)
                    t>=n -> period-1-t; 否则 t
X[i][j] = gray[reflect_index(i-pad,h)][reflect_index(j-pad,w)]
```

`pad` 见 `hill.rs:103`；`reflect_index`/`pad_symmetric` 见 `hill.rs:264-293`。输出恰为 `w*h`（`hill.rs:170-178`）。
### 5.2 三阶段精确求和顺序
```text
hp=h+2*pad, wp=w+2*pad, h1=hp-2, w1=wp-2
K = [-0.25, 0.50, -0.25, 0.50, -1.00, 0.50, -0.25, 0.50, -0.25]

阶段1: I1[i][j] = | K0*X[i][j]   + K1*X[i][j+1] + K2*X[i][j+2]
                    + K3*X[i+1][j] + K4*X[i+1][j+1] + K5*X[i+1][j+2]
                    + K6*X[i+2][j] + K7*X[i+2][j+1] + K8*X[i+2][j+2] |
                    // 严格 K0..K8 左到右，最后 abs

阶段2: l1=1.0/(p1*p1); h2=h1-(p1-1); w2=w1-(p1-1)
  sum = 0.0
  for u in 0..p1-1: sum += Σ_{v=0..p1-1} I1[i+u][j+v]    // 内层 v 升序
  avg = sum * l1                                          // 先求和再乘
  I2[i][j] = 1.0 / avg.max(eps)
  eps = epsilon (>0 且有限)，否则 1e-12

阶段3: l2=1.0/p2
  垂直: T[i][j] = Σ_{u=0..p2-1} ( I2[i+u][j] * l2 )       // 每项先乘，u 升序
  水平: C[i][j] = ( Σ_{v=0..p2-1} T[i][j+v] ) * l2         // 先求和，v 升序，再乘
```

`K` 见 `hill.rs:15-22`；阶段 1 九项顺序见 `hill.rs:112-128`；阶段 2 见 `hill.rs:131-151`；阶段 3 的“垂直先乘、水平后乘”见 `hill.rs:154-176`。该不对称是规范要求，统一写法会改变末位并改变排序。线格式 `epsilon=2^-k`，`k=round(-log2(epsilon))` 限 1..=127（`header.rs:30-37`），缺省 `2^-23`（`params.rs:245`）。
## 6 S-UNIWARD（`algorithm_id = 2`）
### 6.1 平面与滤波器
亮度平面与 HILL 相同：单通道 `p & 0xF8`；RGB 三个通道各 `& 0xF8` 后按 `0.299/0.587/0.114` 加权；两通道取首通道（`suniward.rs:91-110`）。

```text
hpdf = [-0.0544158422,  0.3128715909, -0.6756307363,  0.5853546837,
         0.0158291053, -0.2840155430, -0.0004724846,  0.1287474266,
         0.0173693010, -0.0440882539, -0.0139810279,  0.0087460940,
         0.0048703530, -0.0003917404, -0.0006754494, -0.0001174768]
lpdf[i] = (-1)^i * hpdf[15-i]
bands = [(lpdf,hpdf), (hpdf,lpdf), (hpdf,hpdf)]       // 水平、垂直、对角
```

逐字 tap 见 `wavelet.rs:23-40`；`lpdf` 见 `wavelet.rs:42-53`；`TAPS=16, HALF=8` 见 `wavelet.rs:55-59`；band 顺序见 `wavelet.rs:61-68`。
### 6.2 残差与适用性
每个 band `(f1,f2)` 先水平后垂直：

```text
残差水平: tmp[y][x] = Σ_{b=0..15} f2[b] * plane[y][clamp(x-b+8,0,w-1)]
残差垂直: R[y][x]   = Σ_{a=0..15} f1[a] * tmp[clamp(y-a+8,0,h-1)][x]
W[y][x] = 1.0 / (|R[y][x]| + sigma)

适用性水平: tmp2[y][x] = Σ_{b=0..15} |f2[b]| * W[y][clamp(x+b-8,0,w-1)]
适用性垂直: cost[y][x] += Σ_{a=0..15} |f1[a]| * tmp2[clamp(y+a-8,0,h-1)][x]
```

残差水平 `b` 升序，垂直目标行先清零、`a` 升序且跳过零 tap（`suniward.rs:159-184`）；适用性水平 `b` 升序，垂直 `a` 升序、跳过零 tap并累加到 `cost`（`suniward.rs:205-230`）。边界为复制边缘的 `clamp`，不是零填充。`sigma = model_option("sigma",1.0).max(f64::MIN_POSITIVE)`（`suniward.rs:57-62`、`:112-114`）；读侧取头中 f32（`engine.rs:2069-2072`）。缺省 1.0，论文 `2^-6` 不适用于本 8-bit 空间域。三个 band 的累加顺序必须是 `(l,h)`、`(h,l)`、`(h,h)`（`suniward.rs:122-133`）。残差用反向核、适用性用正向核；镜像任一者会给边缘另一侧定价（`suniward.rs:139-149`、`:187-195`）。
## 7 MiPOD（`algorithm_id = 3`）
### 7.1 平面、Wiener 残差与局部方差
平面同 §6.1（`mipod.rs:112-136`）。方差链路：

1. **Wiener 残差**，固定 `w=2`（`mipod.rs:44-50`）。偶数窗口锚点在左上（`spatial_variance.rs:93-113`）：

   ```text
   sum=0; sum_sq=0
   for dy=0..1: sy=y+dy; 越界跳过（零填充）
     for dx=0..1: sx=x+dx; 越界跳过
       sum += z[sy][sx]; sum_sq += z[sy][sx]^2
   mu=sum/4; v=max(0, sum_sq/4 - mu^2)
   ```

   全图 `noise = (Σ_y Σ_x v)/n`，行内与行间按索引升序；`noise<=0` 时残差全 0（`spatial_variance.rs:117-154`）。最终 `r = diff*min(1,noise/v)`，实现为 `v>noise ? (noise/v)*diff : diff`（`spatial_variance.rs:159-165`）。

2. **局部余弦补空间**，`p=9, degree=9, q=45, dof=81-45=36`（`mipod.rs:43-50`；`spatial_variance.rs:396-397`）。DCT-II 基：

   ```text
   φ0(a) = sqrt(1/9) * cos(π*0*(2a+1)/18)
   φk(a) = sqrt(2/9) * cos(π*k*(2a+1)/18)
   ```

   （`spatial_variance.rs:79-91`）。水平投影 `H[y][x][kv] = Σ_{a=0..8} φ_kv(a) * r[y][reflect(x+a-4,w)]`，`a` 升序（`spatial_variance.rs:169-206`）。对每个 `(y,x)`：

   ```text
   norm=0
   for kv=0..8:                                  // 升序
     vals[a] = H[mirror(y+a-4)][x][kv], a=0..8
     for ku=max(9-kv,0)..8:                     // 升序，即 ku+kv>=9
       proj = Σ_{a=0..8} φ_ku(a)*vals[a]        // a 升序
       norm += proj^2
   ```

   （`spatial_variance.rs:240-264`）。`sigma2=max(0.01, norm/dof)`（`spatial_variance.rs:366-405`）。
### 7.2 Fisher 信息与 7×7 平滑
```text
I[y][x] = 2.0/(sigma2[y][x]*sigma2[y][x])
smoothed = box_smooth(I,w,h,7)
```

`mipod.rs:95-99`。盒滤波用镜像索引、先水平后垂直，`d=-3..3` 升序，先求和再乘 `1/7`；窗口大于图像时逐点镜像（`spatial_variance.rs:408-489`）。
### 7.3 Fisher → 加性代价
`alpha` 是参考载荷（bits per pixel），缺省 `0.20f32`，从基础头 `sigma` 取回并钳到 `[0.01,0.90]`（`mipod.rs:25-34`、`:101-107`；`engine.rs:2069-2077`）。`target_bits = alpha*w*h`（`mipod.rs:107`）。
`fisher_to_costs`（`cost_calibration.rs:206-338`）：

1. `u_n=ln(I_n)`，仅当 `I_n` 有限且 `>0`，否则 `-inf`；统计 `active/min_log/max_log`。`active==0`、`target_bits<=0` 或非有限 → 全 0。
2. `capacity=active*LN_3`；`target=min(target_bits*LN_2, capacity*0.999)`；`target<=0` → 全 0。
3. 直方图 `BINS=32768`；`span=max(max_log-min_log,1e-12)`，`du=span/32768`，`inv_du=1/du`；桶号 `min(floor((u-u_min)*inv_du),32767)`，仅统计有限项（`cost_calibration.rs:106-148`）。
4. 总熵按桶号升序：`x=exp(min(t+center(i),690))`，`center(i)=u_min+(i+0.5)*du`，`rho=solve_rho(x)`，`sum += count*H3(rho)`（`cost_calibration.rs:150-167`）。
5. 括号：`t_lo=-max_log-30`，`F<=0` 时每次减 10，最多 100 次；`t_hi=-min_log+5`，`F>=0` 时每次加 10，最多 100 次；失败则全 0（`cost_calibration.rs:259-285`）。
6. Illinois：`tol=1e-12*max(target,1.0)`，最多 80 轮；割线 `c=(a*fb-b*fa)/(fb-fa)`（分母 0 取中点），`c` 越界取中点；终止 `|fc|<=tol` 或 `|b-a|<=1e-14*(1+max(|a|,|b|))`；同侧时折半另一端（`side==-1` 折半 `fa`，`side==1` 折半 `fb`）（`cost_calibration.rs:287-326`）。
7. 插值表 `32769` 项：`u=u_min+i*du`，`table[i]=solve_rho(exp(min(t+u,690)))`（`cost_calibration.rs:169-177`）。逐元素 `pos=(u-u_min)*inv_du`；`pos<=0` 取 `table[0]`；`j=floor(pos)`，`j>=32768` 取 `table[32768]`；否则 `table[j]+(table[j+1]-table[j])*(pos-j)`（`cost_calibration.rs:179-192`）。
8. 非有限 `u` 代价 0；其余先插值再量化（`cost_calibration.rs:328-337`）。

```text
solve_rho(x): x=min(x,1e300); x<=0 或 NaN -> 0
  rho=ln_1p(x)
  重复 32 次:
    e=exp(rho); f=rho*(e+2)-x; df=e*(1+rho)+2
    next=max(rho-f/df,0)
    若 |next-rho|<=1e-14*(1+next) 则 next 并停止；否则 rho=next

H3(rho): rho<=0 -> LN_3=1.0986122886681098
  否则 lm=ln_1p(2*exp(-rho)); l=rho+lm
       beta=exp(-l); p0=exp(-lm); H3=2*beta*l+p0*lm
```

`solve_rho` 见 `cost_calibration.rs:63-81`；`H3` 见 `cost_calibration.rs:90-104`。
### 7.4 量化与跨平台结论
`quantize_cost` 对有限正值清零低 20 位尾数：`from_bits(bits & !((1<<20)-1))`；`0`、负值、非有限值原样返回（`cost_calibration.rs:340-379`），相对量子 `2^-32`。量化单调，不反转大小关系，但可能把不同代价压成同值，由像素索引决胜。
实测（`cost_calibration.rs:340-358`）：Windows/UCRT 与 Ubuntu/glibc 在 `sigma^2`、`I_n`、7×7 平滑图上逐位一致；差异只在 Newton 后的 `rho`，最多 255 ulp（相对 `2^-44`）。清零后合成图矩阵 12/12 一致、28 例真实语料基线未变。残留风险：两平台值若跨桶边界仍可能差一个量子，代码按 `离散度/量子` 估计约 `4e-5`/元素，只能靠跨平台 CI 兜底。修改量化位数会改变候选集与 trellis 取舍，属 F 级，必须重建基线。
## 8 写侧非规范内容（I）
以下只决定“写成什么样”，读侧不复现；实现方可替换，但不得改变 §3–§7 的槽位与排序输入。

- **方向代价**：HILL 对请求槽位用 8 邻域类掩码均值 `mean`，`base*(1+4*((v±1-mean)/255)^2)`（`hill.rs:181-262`）。S-UNIWARD/MiPOD 返回 `(base,base)`（`rust/src/stego/traits.rs:62-76`）。它只决定 `±1` 方向，不参与排序（`engine.rs:1746-1756`）。
- **并行/SIMD 等价**：参考实现按行并行（`hill.rs:112-176`、`suniward.rs:159-230`），每行独立、按行索引写出；任何 SIMD/线程数都必须复现 §5–§7 的求和顺序，否则 `to_bits()` 排序改变。
- **PNG 重编码**：读侧只消费解码像素；写侧复用原始每行滤波器并选择接近原体积的 deflate 级别（`engine.rs:108-115`、`:650-706`），不影响槽位或代价。
- **重试**：PNG 写侧为单趟（`engine.rs:1818-1886`）；若外层重选 salt/nonce，必须整趟重算，读侧以头值为准。
## 9 自检与已知答案
MiPOD 逐阶段向量：`docs/api/cost-vectors.json` 固定 32×32 RGB 输入与五个 FNV-1a 摘要（`plane/variance/fisher/smoothed/cost`），见文件第 1–9 行与 `mipod.rs:292-358`；Rust 测试 `cost_vector_digests_are_pinned`（`mipod.rs:360-383`）。

```bash
cargo test --all-features --lib cost_vector_digests_are_pinned
python scripts/cost_vectors_check.py            # stage 4 是契约；0-3 仅诊断
python scripts/cost_vectors_check.py --strict   # 中间阶段不一致也失败
```

脚本约定见 `scripts/cost_vectors_check.py:20-27`、`:407-413`。模型与数值不变量：

```bash
cargo test --all-features --lib png::cost
cargo test --all-features --lib spatial_variance
cargo test --all-features --lib cost_calibration
python scripts/baseline_hash.py --check
```

- HILL：`cost_map_is_invariant_under_class_internal_moves`、`direction_costs_follow_the_local_mean`（`hill.rs:331-410`）。
- S-UNIWARD：`cost_map_is_invariant_under_class_internal_moves`、`suitability_reads_the_side_the_residual_lands_on`（`suniward.rs:333-403`）。
- MiPOD：`cost_map_is_invariant_under_class_internal_moves`、`reference_payload_does_not_reorder_costs`（`mipod.rs:197-265`）。
- 方差/平滑：`separable_complement_equals_explicit_projector`、`box_smooth_matches_naive_reflection_bit_identically`（`spatial_variance.rs:586-762`）。
- 标定：`quantise_cost_is_monotone_and_absorbs_ulp_noise`、`calibration_is_deterministic_across_thread_counts`（`cost_calibration.rs:388-561`）。

HILL 与 S-UNIWARD 没有独立冻结数值向量；其已知答案由上述不变量测试与 `baseline_hash.py` 的 28 例字节基线覆盖；MiPOD 的数值契约由 §9 的五段摘要覆盖。
