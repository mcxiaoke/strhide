# strhide 容量探针与提取参数关联性分析备忘

**创建日期**：2026-10-31  
**适用模块**：`rust/src/cli/`、`rust/src/stego/`

---

## 1. 核心结论速览

1. **`extract` 与 `embed` 时的命令行调优参数基本无关**：
   - strhide 采用**自描述载荷（Self-describing Carrier）**架构。嵌入时所使用的代价算法、超参数（STC 约束高度 $h$、排除率、窗口大小等）、载荷长度、加密元信息均已加密序列化至隐写头部（Header / Feature Word）。
   - `extract` 解码时**唯一必需对应的凭据参数是密码（`-p` / `--password` / `--password-file`）**。提取端无需也不接受 `--algorithm`、`--safety`、`--stc-h`、`--exclusion-rate` 等参数。
2. **`capacity` 的计算结果与 `--algorithm` 以及其它参数的关系取决于载体格式**：
   - **PNG 格式**：`--algorithm`（`hill` / `suniward` / `mipod`）**直接影响容量**。因为探针会实际运行代价模型并按代价排序剔除平滑区域，不同算法选出的候选像素集合不同，导致有效槽位（`available_slots`）不同。
   - **JPEG 格式**：`--algorithm`（`uerd` / `juniward` / `jmipod`）**不影响容量大小**。JPEG 探针基于固定的 DCT 网格几何划分槽位，无需计算代价即可确定容量，算法名仅记录在返回的元数据中。
   - **其它关键影响参数**：`--safety`（直接改变建议安全容量）、`--exclusion-rate`（对 PNG 槽位数影响极大）、`--stc-h`（轻微影响物理极限容量）、`-p/--password`（微调 PNG 头部槽位分布）、`--exact`（控制 HEVC 视频是否全扫描）。

---

## 2. `extract` 与 `embed` 命令行参数的关系详析

### 2.1 协议架构：自描述载荷（Self-describing Payload）
在 `rust/src/stego/` 设计中，载体载荷具备完整的自描述能力：
- **载荷头部**：通过伪随机排布或固定网格存储在载体的前导槽位中（例如 PNG 占用 512 像素，JPEG 占用固定前导系数）。
- **加密保护**：头部由用户密码（或 profile 缺省私钥）经由 Argon2id / Blake3 派生的密钥进行 ChaCha20-Poly1305 加密认证。
- **自描述元数据包括**：
  - 隐写版本号与特性字（`FeatureWord`）
  - 代价模型标识（如 HILL, S-UNIWARD, MiPOD, UERD, J-UNIWARD, J-MiPOD）
  - 编码超参数（STC 约束高度 $h$、子块模式、排除阈值等）
  - 原始载荷长度、文件名（除非指定 `--no-filename`）及认证校验码（MAC tag）

### 2.2 参数映射与对照表

| 命令行参数 | embed 是否使用 | extract 是否使用 | extract 行为说明 |
| :--- | :---: | :---: | :--- |
| **`-p / --password`** / **`--password-file`** | 是 | **是 (唯一关键凭据)** | 必须与 embed 时完全一致，用于派生密钥解密头部元数据。若 embed 未加密码，extract 亦无需提供。 |
| **`-a / --algorithm`** | 是 | **否 (不接受)** | extract 自动从解密后的头部元数据中读取 embed 采用的算法。 |
| **`--safety`** / **`--enforce-safety`** | 是 | **否 (不接受)** | 仅用于写入时的安全门限拦截，提取时不涉及安全预算。 |
| **`--stc-h`** / **`--exclusion-rate`** | 是 | **否 (不接受)** | extract 自动从头部读取 STC 高度及空间规则，按记录的参数初始化解码 Trellis。 |
| **`--p1-window`** / **`--p2-window`** | 是 | **否 (不接受)** | 由头部特征参数直接复现，提取端不需要用户手动传入。 |
| **`--seed`** | 是 | **否 (不接受)** | 嵌入刷新率种子，解密仅依赖头部明文 Nonce 与密钥派生。 |
| **`--no-filename`** | 是 | **否** | 若 embed 加了 `--no-filename`，extract 未指定 `-o` 时会自动命名为 `<carrier>.out` / `<carrier>.payload`。 |
| **`--auto`** | 否 | **是 (可选)** | 当载体未检测到内容域隐写时，自动 fallback 到结构域（`strhide read`）进行读取。 |

---

## 3. `capacity` 容量探针计算逻辑与参数相关性

### 3.1 载体格式差异

#### (1) PNG 空间域自适应隐写
- **算法相关性**：**强相关**。
- **机制原理**：
  1. 调用 `cost_model.compute_cost(&image.pixels, w, h, channels, &params)` 计算整图所有像素的代价；
  2. 在 `SlotPlan::build` 中按代价升序排列，并依据 `--exclusion-rate` 剔除最平滑的像素区间：
     $$\text{allowed\_count} = \lfloor \text{ranked.len()} \times (1.0 - \text{exclusion\_percentile}) \rfloor$$
  3. 不同的代价算法（HILL、S-UNIWARD、MiPOD）对边缘、纹理和平滑区域的打分分布完全不同，因此保留下来的 `candidates`（候选像素坐标集合）存在差异；
  4. 多通道展开时，像素在各通道上需校验是否满足 `[8, 247]` 内部区间及类内安全规则 `(val % 8) ∈ [1, 6]`，并排除头部占用的 512 个像素。不同的像素坐标集合导致最终统计出的可用体部槽位数（`available_body_slots`）不同；
  5. 可用槽位直接决定物理最大载荷（`max_raw_payload_bytes`）与建议容量（`recommended_max_bytes`）。

#### (2) JPEG DCT 频域自适应隐写
- **算法相关性**：**无关（数值恒定）**。
- **机制原理**：
  1. 在 `probe_jpeg_capacity` 中，总槽位由图像 DCT 块数与网格规则静态决定：
     $$\text{n\_total} = \text{block\_count} \times \text{slots\_per\_block}$$
     $$\text{body\_slots} = \text{n\_total} - \text{hdr\_n}$$
  2. 代价模型仅在探针中提取 `cost_model.id()` 写入信息，**不执行实际代价计算**；代价模型仅在真正 `embed` 时用于对候选系数赋权并由 STC 寻找最小失真修改路径；
  3. 因此无论指定 `uerd`、`juniward` 还是 `jmipod`，JPEG 的槽位数、物理最大容量、建议安全容量数值完全一致。

#### (3) HEVC / MP4 视频码流
- 基于变换块残差语法元素估算容量，不涉及空间/DCT代价模型；指定无关的图片算法会被 CLI 校验拦截。

#### (4) HEIF 静态图像
- 若直接走 HEVC CABAC 码流，不受算法参数影响；
- 若主码流容量不足且 fallback 到缩略图桥接（`thumb_bridge`），则行为继承自缩略图格式（PNG 缩略图受影响，JPEG 缩略图数值不变）。

---

### 3.2 参数影响矩阵

| 参数名称 | 适用载体 | 是否影响容量数值 | 影响的字段与具体行为 |
| :--- | :--- | :---: | :--- |
| **`--safety <LEVEL>`** | 全部 | **是** | 直接影响 `recommended_max_bytes`（推荐安全载荷）、`safety_level` 与 `safety_bpp_limit`。档位从 paranoid (0.05 bpp) 到 high (0.10 bpp) 再到 balanced (0.15~0.20 bpp)，推荐容量成倍放大。 |
| **`--exclusion-rate`** | PNG | **是 (极强)** | 默认 0.3（剔除 30% 最平滑区域）。调低排除率（例如 0.1）会放宽候选像素，导致 `available_slots`、`max_raw_payload_bytes`、`recommended_max_bytes` 显著暴增。 |
| **`-a / --algorithm`** | PNG | **是** | 影响代价图形态，改变留存的候选像素坐标集合，从而改变 `available_slots` 和容量数值。 |
| **`-a / --algorithm`** | JPEG | **否 (仅字段名)** | `available_slots` 与容量大小完全相同，仅返回 JSON 中的 `algorithm` 字段变更。 |
| **`-p / --password`** | PNG | **是 (微弱)** | 密码影响 512 个头部槽位的伪随机置换分布，导致被头部占用的像素不同，从而使留给体部的槽位（`available_slots`）产生微弱变动（通常相差数个字节）。 |
| **`-p / --password`** | JPEG | **否** | JPEG 头部槽位位置固定，不随密码改变槽位总数。 |
| **`--stc-h`** | 全部 | **是 (微弱)** | STC 约束高度（4..=10）。STC 网格终止边缘效应消耗 $-(h-1)$ 比特，改变 $h$ 会微调 `max_raw_payload_bytes`。 |
| **`--p1-window` / `--p2-window`** | PNG | **是 (微弱)** | 改变空间域滤波核尺寸，微调代价图数值分布。 |
| **`--slot-budget`** | JPEG | **是 (仅修改率)** | 限制可用槽位预算上限，影响 STC 分组 $u$ 的选取，从而改变 `estimated_change_rate`，不影响图像客观物理槽位。 |
| **`--exact`** | 视频/HEVC | **是 (消除约数)** | 禁用快速抽样估算，对全载体码流进行逐语法元素精确扫描，消除 `~` 约数标记。 |
| **`-c / --config`** | 全部 | **是** | 若配置文件预置了 `[stego]` 默认参数，在未显式传参时作为默认值生效。 |

---

## 4. 实测验证数据记录

测试二进制：`rust/target/debug/strhide.exe`  
测试基准文件：`rust/tests/fixtures/carrier.png` (128×128 RGBA) 与 `rust/tests/fixtures/carrier.jpg` (256×256)

### 4.1 PNG 实测对比 (`carrier.png`)

```bash
# 默认算法 (hill)
strhide capacity carrier.png --algorithm hill --json
{"format":"PNG","algorithm":"hill","total_elements":16384,"available_slots":16488,"max_raw_payload_bytes":2038,"recommended_max_bytes":126,"tier_limits":[67,126,200]}

# S-UNIWARD 算法
strhide capacity carrier.png --algorithm suniward --json
{"format":"PNG","algorithm":"suniward","total_elements":16384,"available_slots":16110,"max_raw_payload_bytes":1990,"recommended_max_bytes":116,"tier_limits":[61,116,186]}

# MiPOD 算法
strhide capacity carrier.png --algorithm mipod --json
{"format":"PNG","algorithm":"mipod","total_elements":16384,"available_slots":16161,"max_raw_payload_bytes":1997,"recommended_max_bytes":116,"tier_limits":[61,116,186]}

# 密码影响 (带 -p "test1234")
strhide capacity carrier.png --algorithm hill -p "test1234" --json
{"format":"PNG","algorithm":"hill","total_elements":16384,"available_slots":16492,"max_raw_payload_bytes":2038,"recommended_max_bytes":126,"tier_limits":[67,126,200]}
# (注：available_slots 从 16488 微调变为 16492)

# 排除率影响 (--exclusion-rate 0.1)
strhide capacity carrier.png --exclusion-rate 0.1 --json
{"format":"PNG","algorithm":"hill","total_elements":16384,"available_slots":21558,"max_raw_payload_bytes":2671,"recommended_max_bytes":173,"tier_limits":[95,173,271]}
# (注：available_slots 从 16488 暴增到 21558，recommended_max_bytes 从 126 增加到 173)

# 安全档位影响 (--safety balanced)
strhide capacity carrier.png --safety balanced --json
{"format":"PNG","algorithm":"hill","total_elements":16384,"available_slots":16488,"max_raw_payload_bytes":2038,"recommended_max_bytes":200,"safety_level":"balanced"}
```

### 4.2 JPEG 实测对比 (`carrier.jpg`)

```bash
# UERD 算法
strhide capacity carrier.jpg --algorithm uerd --json
{"format":"JPEG","algorithm":"uerd","total_elements":65536,"available_slots":63766,"max_raw_payload_bytes":2634,"max_raw_is_grouped":true,"recommended_max_bytes":797,"tier_limits":[469,797,1206]}

# J-UNIWARD 算法
strhide capacity carrier.jpg --algorithm juniward --json
{"format":"JPEG","algorithm":"juniward","total_elements":65536,"available_slots":63766,"max_raw_payload_bytes":2634,"max_raw_is_grouped":true,"recommended_max_bytes":797,"tier_limits":[469,797,1206]}

# J-MiPOD 算法
strhide capacity carrier.jpg --algorithm jmipod --json
{"format":"JPEG","algorithm":"jmipod","total_elements":65536,"available_slots":63766,"max_raw_payload_bytes":2634,"max_raw_is_grouped":true,"recommended_max_bytes":797,"tier_limits":[469,797,1206]}
```
*(注：JPEG 三种算法下，所有容量数值完全恒定一致，仅算法标识名不同)*

---

## 5. 关键源码位置索引

- CLI 参数定义：[`rust/src/cli/args.rs`](file:///c:/Home/Projects/strhide/rust/src/cli/args.rs) (`StegoTuningArgs`, `CapacityArgs`, `ExtractArgs`)
- 参数解析与构建：[`rust/src/cli/helpers.rs`](file:///c:/Home/Projects/strhide/rust/src/cli/helpers.rs) (`stego_tuning`, `stego_options`)
- 容量探针与提取命令处理：[`rust/src/cli/cmd_stego.rs`](file:///c:/Home/Projects/strhide/rust/src/cli/cmd_stego.rs) (`run_capacity_probe`, `handle_extract`, `extract_one`)
- 引擎调度分发：[`rust/src/stego/engine.rs`](file:///c:/Home/Projects/strhide/rust/src/stego/engine.rs) (`StegoEngine::probe`, `StegoEngine::extract`)
- PNG 空间域探针与槽位规划：[`rust/src/stego/png/engine.rs`](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs) (`probe_png_capacity`, `SlotPlan::build`)
- JPEG DCT 域探针与几何计算：[`rust/src/stego/jpeg/engine.rs`](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs) (`probe_jpeg_capacity`)
