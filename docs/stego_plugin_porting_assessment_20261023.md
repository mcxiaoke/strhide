# stego 算法可插拔性评估与 temp/github 可移植性清点

> 回答两个问题：(1) strhide 的 stego 算法接口现在能不能真正"插拔"；(2) `temp/github`
> 里的开源实现有多少能借鉴移植。
> 补充 `docs/stego_survey_and_roadmap_20261023.md`（下称"路线文"）的 §4.3 缺口清点。

| 项 | 内容 |
| :--- | :--- |
| 文档编号 | `STEGO-PLUGIN-PORT-20261023-2300` |
| 编制时间 | 2026-10-23 23:00（本机时间） |
| 方法 | 逐个仓库读 LICENSE/源码；对照 `rust/src/stego` 现状；用已装 `conseal 2025.11` 做实测 |
| 代码改动 | 无。本文只做评估 |

---

## 0. 结论

1. **代码基本不能抄。** conseal 里最有价值的 MiPOD / J-MiPOD 是 `CC BY-NC-SA 4.0`，且原许可
   明文禁止"把本代码用于实际隐藏通信"；J-UNIWARD / S-UNIWARD / WOW / HUGO 源自 DDE，限
   "教育、研究、非营利"。本项目是 `Apache-2.0`，这四类全都不能引入。**算法公式可以按论文
   重写，代码不行。**
   注意这不是"发布才受限"：CC BY-NC 限制的是**用途**不是发行，MiPOD 那句"禁止用于实际
   藏数据"更是直接命中本项目用途（详见 §2.1）。
2. **许可干净、真能参考代码的只有两个：`hstego`（MIT）和 `pySTC`（MIT）。** hstego 恰好包含
   路线文 P2 要做的 cost polarization 和一份完整的 J-UNIWARD。
3. **conseal 的正确用法是"测试预言机"，不是"源码仓库"。** 它已装在
   `C:\Home\Develop\venv`（2025.11），可以在开发/测试阶段生成参考 cost map，逐点比对 Rust
   实现的数值正确性 —— 这属于测试用途，不会污染 Apache-2.0 代码库。
4. **接口有四处硬缺口，当前状态下加第二个算法必然要改 `params.rs` 和 trait。** 最严重的一处：
   **PNG 侧提取必须由调用方从外部指定 cost model**，因为 header 槽位是按代价排序选的，
   不先知道算法就读不出 header —— 而 header 里存着算法 id，形成死锁。JPEG 侧没有这个问题。
5. **新实测发现（本文新增数据）**：空间引擎为换取代价图可复现而做的 `& 0xF8` 掩码，会让
   HILL 在低动态范围图像上**严重偏离参考实现**：截图类 Spearman 仅 0.21，保留候选集有 25%
   不同；照片类 0.96 基本无差。这条把路线文 P5（解除八值类约束）的收益从"理论上的自由度"
   变成了可量化的问题。

---

## 1. 可插拔现状盘点

`rust/src/stego/traits.rs` 已经定义了 `SpatialCostModel` / `JpegCostModel`，
`registry.rs` 提供按名查找，`list_algorithms()` 供 CLI 枚举。骨架是有的，但存在结构耦合：

### 1.1 缺口 A：JPEG 侧无法表达非对称代价（阻塞 cost polarization）

`SpatialCostModel` 有 `direction_costs()`（`traits.rs:47-57`），
`JpegCostModel` **没有**（`traits.rs:60-83` 只有 `compute_cost`）。

后果：路线文 P2 要做的 cost polarization 落不了地。现在的 `polarize_weight` 只能在
`jpeg/engine.rs:427` 对 `minus_cost` 整体乘一个常数：

```rust
base * polarize_weight          // jpeg/engine.rs:427
```

这与系数方向无关，正是路线文 §P2 指出的缺陷。要按 hstego 的做法（逐系数判断哪个方向
"更自然"）实现，必须先给 `JpegCostModel` 补一个返回 `(rho_plus, rho_minus)` 的方法。

**改动面**：trait 加带默认实现的方法（返回 `(base, base)`）→ 不破坏现有 UERD；
`jpeg/engine.rs` 的 `build_plan` 改为向模型取方向代价，`polarize_weight` 降级为兼容开关。

### 1.2 缺口 B：PNG 提取不自描述（结构性，最严重）

`extract_spatial_with_profile()` 的签名要求调用方传入 `cost_model`（`spatial/engine.rs:1193-1206`）：

```rust
let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, params);
let plan  = SlotPlan::build(&image, &costs, params, password, domain, spatial)?;
```

而 `SlotPlan::build` 是先按 `(cost_bits, pixel_index)` 全序排名再取 header 槽
（`spatial/engine.rs:754-772`）。所以**不先知道用哪个 cost model，就算不出 header 槽位；
算不出 header 槽位，就读不到 header 里的算法 id。**

对比 JPEG 侧：槽位是"几何格 + 密钥置换"，与代价无关
（`jpeg/engine.rs:6-14`，注释明确写 "the extractor needs no cost map, no ranking and no threshold"），
因此 header 先可读、算法 id 先可读，代价只在嵌入端当 ρ 用 —— 这才是真正的可插拔。

**这意味着：现在换一个 PNG cost model，用户必须额外记住并在提取时手动指定算法**，
文件本身不自描述。加第二个空间算法前必须解决，否则"可插拔"只是编译器层面的可插拔。

**两个可选解**：

| 方案 | 做法 | 代价 |
| :--- | :--- | :--- |
| B1（小改，推荐） | **只把 header 槽位改成与代价无关**：在 eligible 像素（`[8,247]`）上做密钥置换取前 768 个，body 仍按代价排序 | 线格式变（项目未发布，可接受）；header 可能落进平滑区，但 96 字节摊到百万像素，视觉可忽略 |
| B2（大改） | 空间侧全面改几何槽位，代价退化为纯 ρ | 丢掉"优先用纹理区"的选择，需重标定 `exclusion_percentile` 与 capacity |

B1 的收益是让 PNG 变成自描述，且不动 body 的既有行为，建议优先。

### 1.3 缺口 C：参数结构与算法绑死

- `SpatialParams` 里 `high_pass_kernel` / `p1_window` / `p2_window` / `epsilon`
  （`params.rs:142-175`）是 **HILL 专属**；
- `JpegParams` 里 `neighbor_weight` / `wet_cost`（`params.rs:266-314`）是 **UERD 专属**。

加 S-UNIWARD 需要 `sigma` 和高斯低通、加 J-UNIWARD 需要 16 个小波滤波器系数、
加 MiPOD 需要 `block_size`/`degree`/`lambda` —— 现在无处安放，只能往这两个结构体里继续塞，
最终 `SpatialParams` 变成所有算法的并集，`validate()` 还得写一堆"字段 X 只在算法 Y 下有效"。

**建议**：加 `algorithm_options: BTreeMap<String, f64>`（或 `enum CostParams { Hill{..}, Suniward{..} }`），
把算法私有参数收进去，`params.rs` 的 `validate` 只校验通用字段。这项可与缺口 A 一起做。

### 1.4 缺口 D：注册表无一致性保障

`registry.rs:21-35` 两处手工 `match`，`list_algorithms()`（`:38-51`）第三处手工列表，
现有测试（`:58-75`）只覆盖已注册的 `hill`/`uerd`。
没有"注册表里的每个 id 都能通过 `validate()`、能写进 header、能被 `list_algorithms()` 列到"
的自动化约束。加到第 3、4 个算法时这里最容易悄悄不同步。

**建议**：加一个表驱动测试，遍历 `list_algorithms()` 的每个 id，断言
`get_*_model(id).is_some()`、`params.validate()` 通过、header 的算法 id 字段能编码/解码往返。

---

## 2. 许可矩阵（决定"能不能抄代码"）

| 来源 | 覆盖范围 | 许可 | 能进 Apache-2.0？ |
| :--- | :--- | :--- | :--- |
| `conseal` 自有代码（uerd / ebs / nsF5 / tools / simulate / color / coding / hill / wow / suniward） | 见下行例外 | MPL-2.0 | 同文件不行；作为独立文件可组合，但单一静态二进制里维护 MPL 边界不值当。**建议不抄** |
| `conseal` 的 **mipod / jmipod** | `mipod/_defs.py:1-17`、`jmipod/_defs.py:1-17` | **CC BY-NC-SA 4.0**（Cogranne, UTT） | **✗ 明确禁止**。非商业 + 相同方式共享 + 原文"forbid any practical use of this code for communication by hiding data" |
| `conseal` 的 **juniward** | `juniward/_costmap.py:10-20` | DDE：仅教育/研究/非营利 | **✗** |
| `conseal` 的 hill / suniward / wow / hugo | 文件头写 "inspired by stegolab / DDE" | 上游无 LICENSE（默认全部权利保留）或 DDE 非营利 | **✗** |
| `capsule-7800700-code-jmipod`（J-MiPOD 官方 Matlab，含 UERD/J-UNIWARD/JMiPOD） | 全仓库 | CC BY-NC-SA 4.0 | **✗** |
| `stegolab` | 全仓库 | 无 LICENSE 文件 | **✗** |
| **`hstego`** | 全仓库（含 J-UNIWARD、cost polarization、vendored STC） | **MIT** | ✓ |
| **`pySTC`** | DDE STC 的 ctypes 封装 | **MIT** | ✓（但只支持二元，不能替换本项目三元实现） |
| `image-steganography-lab` | 全仓库 | GPL-2.0 | **✗** |

**结论**：清点 37 个仓库后，能合法参考**代码**的只有 hstego / pySTC。
其余一律只能"读论文公式、自己写实现"。这不是保守，是 `LICENSE` 是 Apache-2.0 的硬约束。

值得强调：**算法本身（公式、流程）不受版权保护，实现代码受。** 按论文重写 J-UNIWARD /
S-UNIWARD 是干净的；把 conseal 的 `.py` 翻译成 Rust 不是。

### 2.1 "只用不发布，还受约束吗"——分类讨论

常见误解是"许可证约束的是发布，我自用就不算"。这个说法对宽松许可和著佐权许可成立，
**对 CC BY-NC 不成立**。原因是版权法下"复制"和"发行"是两个独立行为：

- 宽松/著佐权许可证（MIT、Apache-2.0、MPL-2.0、GPL/AGPL）**无条件授予复制权**，
  只在"发行/分发"这一环附加义务（保留声明、公开源码）。所以私有自用不触发义务。
- CC BY-NC 把**授权本身**限定在非商业目的，也就是"复制"这个动作就带条件，
  不依赖是否发行。NC 管的是"用途"，不是"分发"。

| 许可 | 义务的触发点 | 私有自用（不分发） |
| :--- | :--- | :--- |
| MIT / BSD / Apache-2.0 | 分发时保留声明 | 无义务 |
| MPL-2.0 | 分发可执行体时公开被覆盖文件的源码 | 无义务 |
| GPL-2.0 / GPL-3.0 | 分发（convey）时提供源码 | 无义务 |
| AGPL-3.0 | 提供网络交互服务即触发 | **有义务**（这条是 GPL 的例外） |
| CC BY-NC-SA 4.0 | 授予限于 NonCommercial 目的 | 个人非商业：许可范围内；**有商业目的：超出授权** |

落到 MiPOD 这份实现上，真正卡住的不是"能不能发布"，而是**两条独立的东西**：

1. **NC 是用途限制。** 如果是个人做研究、不做商业用途、也不发布，严格讲 NC 允许你复制
   （这正是 NC 的本意）。但一旦有商业目的（公司内部项目、或将来商业化）就越界了，
   跟发不发布无关。
2. **那句额外的用途禁令才是关键。** 原文（`mipod/_defs.py:15`）：
   > "The authors also fordid any practical use of this code for communication by hiding data into JPEG images."

   这句话限制的是**"用这份代码去实际藏数据"这个行为**，不是"再分发"。而 strhide 的用途
   恰好就是它禁止的那件事。这一条与开源与否、发行与否都无关。

对 strhide 还有第三条现实约束：本项目是 `Apache-2.0`，`AGENTS.md` 的 CI 里写着
crates 发布与 release 打 tag。**只要发布，就必须干净**；而 git 历史不可逆 —— 先把
MiPOD 代码塞进仓库再删掉，历史里仍然在。

**所以真正的分界线不是"发不发布"，而是"有没有复制这份代码"：**

| 做法 | 是否受 MiPOD 许可约束 |
| :--- | :--- |
| 把 `conseal/mipod/*.py` 逐行翻译成 Rust，放进 `rust/src` | **是**（翻译属于衍生作品） |
| 读论文公式，自己从零写 | **否**（公式、流程不受版权保护） |
| 在 `rust/` 里调用 `conseal` 包做对照测试 | **否**（不是衍生作品，是调用方）；但商业用途下 NC 仍可能不覆盖 |
| 把 conseal 当 dev-time 预言机，产物（参考数值）写进测试断言 | **否**（数值不是表达） |

最后一条是本文推荐的做法：**依赖边界留在 `temp/` 与 `venv` 里，仓库中不出现衍生代码**，
将来要发布时删掉脚本即可，不需要清理 git 历史。

---

## 3. conseal 逐算法可借鉴性

conseal 是 Innsbruck 组的模拟器，README 自己声明：**"only simulates the embedding... We do
not provide any end-to-end steganography method"** —— 没有消息封装、没有提取、没有编码层。
所以它能提供的只有 **cost map**，而本项目已有自己的 STC + 容器层。价值集中在"代价函数是否正确"。

| 算法 | 文件 | 对本项目的价值 | 判断 |
| :--- | :--- | :--- | :--- |
| **UERD** | `uerd/_costmap.py` | **可作 UERD 数值回归基准** | 公式与 `jpeg/cost/uerd.rs` 一致：`E_b = Σ_{k≥1}|y_k·Q_k|`，`ρ = Q_k/(E_b + 0.25·Σ_{8邻域}E)`（`:_costmap.py:93`）。差异仅两处：本项目的 `& !1` 掩码（为可复现，必要）与**边界处邻域求平均用实际邻居数、conseal 用 scipy `symm` 镜像**。建议用它在多张 4:2:0/4:4:4 图上做逐点比对 |
| **J-UNIWARD** | `juniward/_costmap.py`（15 KB） | **唯一的完整参考实现**，但许可不可用 | 公式可读，实现要自己写。同一算法在 **hstego `hstegolib.py:957` 有一份 MIT 版本**，直接看那份 |
| **J-MiPOD** | `jmipod/_costmap.py` + `_defs.py` | 路线文 §4.3 说"全生态无实现"——**这条要更正**：本地 clone 的 conseal（`Cargo.toml` 标 2026.6.0）有真实现：`estimate_variance`（参数化 DCT 模型拟合局部方差）+ DCT 域协方差变换 + 8 邻域平滑加权。venv 里的 2025.11 **没有** `jmipod` 模块，路线文可能依据的是较早版本 | **仍不可用**：CC BY-NC-SA + 禁止实用。且路线文自己的结论是"ROI 低" |
| **MiPOD** | `mipod/_costmap.py` + `_defs.py` + `ixlnx3.mat` | 同上 | 不可用 |
| **S-UNIWARD / WOW / HUGO** | `suniward/`、`wow/`、`hugo/` | 路线文已论证在 CNN 下检出率**高于** HILL | 不值得做 |
| **EBS / nsF5 / F5** | `ebs/`、`nsF5/`、`F5/` | JPEG 侧的历史算法，EBS 是 ALASKA 用过的 | 无收益，仅评测对照 |
| **`color/joint/_ternary.py`** | 逐通道联合概率分配 | 对应路线文 §4.3"彩色联合通道分配"缺口 | 思路可参考（MPL，别抄代码）。本项目 `ChannelMode::Rgb` 目前是**复用亮度 cost**（`hill.rs:53-59` 用固定权重合成单一 gray），不是逐通道 cost，更不是联合分配 |
| **`src/hill.rs`（纯 Rust）** | 121 行，`pad_symmetric` + 可分离 15×15 | 结构与 `spatial/cost/hill.rs` 几乎同构，**验证了本项目实现路径正确** | 无需移植，可作交叉复核 |
| **`simulate/_solver.py`** | λ 搜索（二分/Brent） | 把 ρ 映射到目标载荷的拉格朗日乘子 | 本项目用 STC，不需要 |
| **`coding/wpc.py`** | wet paper codes | 只在没有 STC 时有意义 | 不需要 |

---

## 4. 其它仓库中真正有用的两处

### 4.1 hstego 的 cost polarization（MIT，路线文 P2 的实现依据）

`hstegolib.py:1015-1045`：

```python
m = 0.65
precover = scipy.signal.wiener(spatial, (3, 3))
coeffs_estim = compress(precover, quant)
s = np.sign(coeffs_estim - coeffs)
rho_p1[s > 0] = m * rho_p1[s > 0]      # 往"估计值"方向走，打折
rho_m1[s < 0] = m * rho_m1[s < 0]
```

即：wiener 估计 → 重压缩得到"本该是"的系数 → 谁往估计值靠，谁的代价乘 0.65。
这是唯一一个"MIT 许可 + 公式完整 + 与现有 JPEG 流程不冲突"的现成增益点。

移植时注意本项目约束：`polarize_weight` 现在只在 `sparse_overrides` 存在时生效
（`jpeg/engine.rs:414-429`），改成逐系数方向代价后这条路径要重写；
且极化只影响 ρ，不影响槽位（JPEG 槽位本来与代价无关），所以**不需要动线格式**。

### 4.2 conseal 作为数值预言机

已确认 `C:\Home\Develop\venv` 里 `conseal 2025.11` 可 import，且
`conseal.hill._costmap._compute_cost` 接受 float 输入（不受 uint8 限制）。
用它生成参考 cost map、与 Rust 输出逐点比对，是验证 UERD/HILL 实现正确性最省事的办法。
**仅限测试代码引用，不要进 `rust/src`。**

---

## 5. 新实测：`& 0xF8` 掩码让 HILL 偏离参考实现

### 5.1 为什么必须掩码

空间引擎把像素限制在八值类内（`v & 0xF8` 不变），这样代价图在 stego 上可复现，
槽位排序两端才一致（`spatial/cost/hill.rs:43-47` 有明确注释）。
代价是 HILL 必须在**被 `& 0xF8` 压到 32 个亮度级**的图像上算。

### 5.2 实测偏离程度

方法：取 `temp/testfiles` 的 PNG，用 `conseal` 的浮点 HILL 分别算
"精确灰度" 与 "通道先 `& 0xF8` 再合成灰度" 两张 cost map，在 eligible 像素
（绿通道 `[8,247]`）上比较排名一致性。

| 图像 | 尺寸 | 类型 | Spearman | 保留候选集（最便宜 70%）重合 |
| :--- | :--- | :--- | ---: | ---: |
| `file-02.png` | 1024×1024 | 调色板/图形 | **0.205** | **74.9%** |
| `file-03.png` | 2560×1440 | 截图 | **0.714** | **85.0%** |
| `file-09.png` | 3341×2529 | 照片 | 0.957 | 99.9% |

（复现脚本：`temp/hill_mask_probe3.py`，走 float 路径以排除 uint8 二次量化干扰；
uint8 路径 `temp/hill_mask_probe.py` 给出同向结果 0.142 / 0.707 / 0.957。）

### 5.3 怎么读这组数

- **对照片影响小**（0.96），所以此前用照片语料做的一切结论不必推翻；
- **对截图/图形影响大**：掩码把"轻微纹理"抹成"完全平坦"，HILL 的 `1/I2` 阶段直接饱和到
  `1/eps`，于是这些像素被 30% 排除规则整批踢出候选集。方向上是**偏保守**（更少改动平滑区），
  但代价是容量浪费 + 改动分布不再等于论文里的 HILL；
- 因此"本项目用 HILL"这个表述对截图类载体是不准确的，评测时（路线文 P0）应当把载体按
  动态范围分层统计，否则 `P_E` 会被这两类图片的巨大差异抹平。

### 5.4 与 P5 的关系

路线文 P5 把"解除八值类约束"描述为"每个槽位丢一半自由度"，判定条件是"P0 显示改动率是瓶颈"。
本文补充第二个理由：**约束不只是限制范围，还强制降低了代价函数的分辨率**，对截图类载体
的代价排序破坏达 25%。如果走 §1.2 的 B1 方案（header 几何化）只是自描述；
要真正解掉这条，得走 B2（全面几何槽位，代价退化为纯 ρ），那时 cost map 可以按精确像素算，
不再需要掩码。

---

## 6. 建议路线

按"收益 ÷ 改动面"排序，与路线文的 P0-P5 对齐。

| 优先级 | 事项 | 依据 | 改动面 | 状态 |
| :--- | :--- | :--- | :--- | :--- |
| **A** | `JpegCostModel` 补方向偏好（`direction_bias`，默认对称） | 缺口 A，P2 前置 | trait + `jpeg/engine.rs` | **已完成** |
| **B** | 按 hstego 重做 cost polarization（wiener precover + 逐系数方向） | 路线文 P2，MIT 可参考 | UERD 代价构造，不动线格式 | **已完成** |
| **C** | header 槽位与代价解耦 + 算法 id 写进 feature word | 缺口 B | `SlotPlan::build`、`FeatureWord`、提取流程 | **已完成** |
| **D** | 参数包 + 注册表一致性测试 | 缺口 C/D | `params.rs`、`registry.rs` | **已完成** |
| **E** | 加 **J-UNIWARD** 作为第二个 JPEG 插件 | 验证插件边界；顺便给 P0 一个文献可比的对照点 | 新 `jpeg/cost/juniward.rs`，参考 hstego（MIT） | **已完成** |
| **F** | 加 **S-UNIWARD** 作为第二个空间插件 | 同上，仅作对照，不做默认 | 新 `spatial/cost/suniward.rs`，按论文重写 | **已完成** |
| **G** | 用 conseal 建 cost map 回归测试 | 数值正确性 | `rust/tests/`，不引 Python 运行时 | 待做 |

### 6.1 A-D 实施结果（2026-10-23 23:28）

| 项 | 实际做法 | 与本文原设想的偏差 |
| :--- | :--- | :--- |
| A | trait 方法命名为 `direction_bias`，返回 `Option<Vec<i8>>` | 原设想是与 `SpatialCostModel::direction_costs` 对称的 `(Vec<f64>, Vec<f64>)`；改为符号向量是因为 100 MP 载体的 cost map 已 ~50 MB，两张方向图会把工作集三倍化，而极化族模型只需要方向 |
| B | `jpeg/cost/precover.rs`：反量化→IDCT→3×3 Wiener→FDCT→重量化→取符号 | 无实质偏差。WIENER 边界用 clamp（scipy 用镜像），只影响最外一圈且只轻微扰动该处的符号 |
| B | `polarize_weight` 语义改为"偏好方向折扣"，并拒绝 `> 1.0` | 原实现允许 >1，那等于惩罚更隐蔽的方向，与参数名相反 |
| C | header 槽位 = 全部 eligible 像素 + 密钥置换；`FeatureWord.algorithm_id` 放进原 reserved 的 `bytes[8]` | 原设想只改槽位；实际还必须把算法 id 写进 header，否则解耦后仍无信息可用 |
| C | 提取改为"先读 header → 解析模型 → 再算 cost"；调用方传入的模型降级为提示 | 原设想的 B1 只解决"header 可读"，未定义谁来决定模型；实际把 carrier 定为权威 |
| D | `algorithm_options: BTreeMap<String,f64>` + `model_option()`，既有类型化字段保留 | 未做完整的 per-algorithm 枚举拆分：会波及 `cli.rs` 的 flag 映射与 config diff，当前无行为收益 |

**验证**：`cargo test` 549 项全绿、`batch_corpus` 240/240、`batch_stego` 22/22（含 4 个安全拒绝）、
`fmt --check` 与 `clippy -D warnings` 干净。

**B 的实测**（`tests/assets/small.jpg`，4 KiB 载荷）：朝 precover 估计值移动的占比
**0.334 → 0.802**，总改动数 16429 → 13344。方向项生效，且顺带减少了改动量。

**C 的实测**（`tests/png_self_describing.rs`）：给提取端传入一个 id 完全不同的冒牌模型，
提取仍成功——证明 carrier 的声明优先于调用方的猜测。

### 6.2 E-F 实施结果（2026-10-23 23:49）

| 项 | 实际做法 | 说明 |
| :--- | :--- | :--- |
| E | `jpeg/cost/juniward.rs`，σ 默认 `2^-6`（`algorithm_options.sigma` 可覆盖） | **JPEG 侧不需要 wire id**：提取槽位是几何 + 密钥，与代价无关。所以加 JPEG 模型是纯增量，不动线格式 —— 这一点与原设想一致，比 C 顺利 |
| E | 16 抽头 Daubechies-8 抽到 `stego/wavelet.rs` 共享 | 两个 UNIWARD 用同一套滤波器，不复制 |
| E | ξ 与 \|ξ\| 都按 1D 外积实现 | 单系数扰动是 8×8 IDCT 基 × quant，而基与 2D 滤波器都可分离，故内层只需 23×23 点积 |
| F | `spatial/cost/suniward.rs`，wire id `2`，σ 默认 `1.0`（对齐 conseal/stegolab；论文的 `2^-6` 是 JPEG 域取值） | 单像素扰动是 delta，响应即分析滤波器本身，\|ξ\| 可分离 → 每个 band 两趟 1D 卷积 |
| F | 代价在 `& 0xF8` 掩码像素上算，并加不变量单测 | 与 HILL 同因：排序要能被提取端逐位复现 |

**性能**（release，单线程，embed 全程）：

| 载体 | 基准 | 新模型 | 倍数 |
| :--- | ---: | ---: | ---: |
| 24 MP JPEG（6000×4000） | UERD 0.50 s | J-UNIWARD 9.20 s | **18×** |
| 6 MP PNG（3000×2000） | HILL 2.47 s | S-UNIWARD 2.87 s | **1.16×** |

**质量指标**（`small.jpg`）：

- J-UNIWARD 平坦块均代价 9139 vs 繁忙块 385（**24×**）—— 纹理自适应成立；
- J-UNIWARD 最便宜 10% 槽位与 UERD 仅重合 **0.47** —— 两者真的选不同位置，不是"更慢的同款"。

**插件边界的结论**：加 JPEG 模型 = registry 一行 + 一个新文件；加空间模型 = 同上再加一个 wire id。
两者都没碰引擎、`params.rs` 或线格式。A-D 的接口设计在 E/F 上验证通过。

**S-UNIWARD 已经很便宜，但没设成默认**：6 MP 只慢 16%，工程上完全可用。仍然保持 `auto → HILL`，
因为路线文 §2.1 的 2025–2026 实测显示 HILL 在两个 CNN 检测器下检出率更低。要不要改默认属于
策略决定，需要 P0 基线数据支撑，不该顺手改。


### 明确不做

| 项 | 理由 |
| :--- | :--- |
| 移植 MiPOD / J-MiPOD | CC BY-NC-SA + 明文禁止实用；路线文已判定 ROI 低 |
| 移植 WOW / HUGO | 路线文 §2.1：CNN 下检出率高于 HILL |
| 移植 conseal 的 simulate / coding | 本项目 STC 已在其上，且没有端到端能力 |
| 引入 Python 运行时做 oracle | 破坏"单一静态二进制"定位；只在 dev/test 用 |

---

## 7. 数据溯源

| 引用 | 位置 |
| :--- | :--- |
| conseal 自我声明"仅模拟" | `temp/github/conseal/README.md:19` |
| conseal MPL-2.0 | `temp/github/conseal/LICENSE:1` |
| MiPOD/J-MiPOD 的 CC BY-NC-SA 与"禁止实用" | `conseal/mipod/_defs.py:1-17`、`conseal/jmipod/_defs.py:1-17` |
| J-UNIWARD 的 DDE 非营利条款 | `conseal/juniward/_costmap.py:10-20` |
| conseal UERD 公式 | `conseal/uerd/_costmap.py:84-113` |
| conseal 空间 HILL 纯 Rust 实现 | `conseal/src/hill.rs:47-114` |
| conseal 彩色联合三元分配 | `conseal/color/joint/_ternary.py:14-52` |
| hstego MIT | `temp/github/hstego/LICENSE.txt:1` |
| hstego cost polarization（`m=0.65`） | `hstego/hstegolib.py:1015-1045` |
| hstego J-UNIWARD 代价 | `hstego/hstegolib.py:957-1005` |
| J-MiPOD 官方 Matlab（CC BY-NC-SA） | `temp/github/capsule-7800700-code-jmipod/LICENSE:1` |
| stegolab 无 LICENSE | `temp/github/stegolab/`（目录内无 LICENSE/COPYING） |
| 本项目 Apache-2.0 | `LICENSE:1`、`rust/Cargo.toml:7` |
| JPEG 槽位与代价无关 | `rust/src/stego/jpeg/engine.rs:6-14` |
| `polarize_weight` 只作用于 minus | `rust/src/stego/jpeg/engine.rs:427` |
| `JpegCostModel` 无 direction_costs | `rust/src/stego/traits.rs:60-83` |
| 空间提取需外部传入 cost model | `rust/src/stego/spatial/engine.rs:1175-1212` |
| 空间槽位按代价全序排名 | `rust/src/stego/spatial/engine.rs:754-772` |
| HILL 的 `& 0xF8` 掩码与理由 | `rust/src/stego/spatial/cost/hill.rs:43-59` |
| HILL 灰度用固定权重合成单通道 | `rust/src/stego/spatial/cost/hill.rs:48-59` |
| 参数结构（HILL/UERD 专属字段） | `rust/src/stego/params.rs:142-175`、`:266-314` |
| 注册表手工三处列表 | `rust/src/stego/registry.rs:21-51` |
| 掩码偏离实测脚本 | `temp/hill_mask_probe3.py`（float）、`temp/hill_mask_probe.py`（uint8） |
