# 内容域隐写参数收敛与黑盒抗检加固实施方案

> **编制日期**：2026-10-21  
> **文档状态**：待评审（For Review）  
> **关联文档**：技术调研与检测器机理见 [`docs/steganalysis_tools_and_countermeasures_memo_20261021.md`](file:///c:/Home/Projects/strhide/docs/steganalysis_tools_and_countermeasures_memo_20261021.md)。  
> **方案定位**：面向项目维护者与库使用者的工程实施规划。收敛内容隐写（`stego`）暴露给库使用者的 API 表面积，消除误导性数学参数，补齐真正的私有方言隔离能力，并基于黑盒对抗视角落地抗检加固。

---

## 1. 背景与改造动因

当前 `strhide` 的内容域隐写接口在“参数暴露”上存在两个相反方向的结构性问题：

1. **过度暴露了不该暴露的内部调优参数**：
   * `SpatialParams` 和 `JpegParams` 目前对外暴露了 `high_pass_kernel`（3×3 滤波核）、`p1_window`、`p2_window`、`neighbor_weight`（8 邻域权重）等低层数学参数。
   * **危害**：这些参数是学术界针对自然图像高阶残差训练出的最优解。普通调用者误以为“改动滤波核可以去指纹”，一旦乱改，轻则破坏抗检性导致平滑区被污染、盲检报警；重则破坏提取端 LSB 不敏感性不变形，导致解不出数据。
2. **缺失了真正关乎防指纹与定向隔离的核心能力**：
   * **HKDF 域分隔符硬编码**：`strhide-stego-enc-v1`、`strhide-stego-hpos-v2`、`strhide-stc-trellis-v1` 等在代码中硬编码。没有类似结构域的 `stealth_domain`，无法做到应用级密码学域隔离。
   * **通道固定在绿色单通道**：空域 PNG 强制只改 Green 通道，暴露了单通道高阶差分方差突出的明显指纹。
   * **载荷缺乏安全工作点调控**：深度学习（SRNet）与富模型（SRM）在满载下检出率极高，缺乏面向高隐蔽场景的“保守容量策略（Safety Margin）”。

---

## 2. 参数架构与收敛分类原则

按照“谁必须知道”与“参数真实作用”重新划定三类参数边界：

```
                    ┌──────────────────────────────────────────────┐
                    │               API 参数总览                    │
                    └──────────────────────┬───────────────────────┘
                                           │
         ┌─────────────────────────────────┼─────────────────────────────────┐
         ▼                                 ▼                                 ▼
┌─────────────────┐               ┌─────────────────┐               ┌─────────────────┐
│  P 类 (Profile)  │               │  L 类 (Options)  │               │  内部下沉常量    │
│  私有方言/防指纹  │               │  写侧安全与策略  │               │  算法调优数学参数│
├─────────────────┤               ├─────────────────┤               ├─────────────────┤
│ • default_secret│               │ • safety_level  │               │ • 滤波核 (KB)   │
│ • stego_domain  │               │ • codec (Auto)  │               │ • 平滑窗口 3/15 │
│ • channel_mode  │               │ • compression   │               │ • 八值类掩码&F8 │
│ (读写必须对称)   │               │ (纯写侧,自描述)  │               │ • 邻域权重 0.25 │
└─────────────────┘               └─────────────────┘               └─────────────────┘
```

### 2.1 P 类参数：收敛进 `StegoProfile`（定义私有方言，两端必须对称）

这些参数直接决定载体是否携带公开特征。一旦配置，官方二进制和通用提取器**绝对无法定位和解出**，直接报 `NoHiddenData`：

| 字段 | 类型 | 默认值 | 作用与安全价值 |
|---|---|---|---|
| **`default_secret`** | `Option<Cow<'static, str>>` | `None`（官方公开常量） | 替代无密码模式下的公开常量 `PUBLIC_DEFAULT_SECRET`（**已实现**） |
| **`stego_domain`** | `Option<Cow<'static, [u8]>>` | `None`（官方默认域） | **本次新增**：替代硬编码的 HKDF salt/info 标签，实现跨系统的密码学域隔离 |
| **`channel_mode`** | `ChannelMode` | `ChannelMode::Green` | 嵌入通道选择（单绿色通道 vs 基于密钥种子三通道伪随机打散） |

### 2.2 L 类参数：保留在 `StegoOptions`（高层策略与安全预算，写侧自描述）

只影响写入时的资源取舍与盲检抗性，提取端要么无需知道、要么从信封头部自描述解码：

| 字段 | 类型 | 默认值 | 作用与抗检价值 |
|---|---|---|---|
| **`safety_level`** | `SafetyLevel` | `SafetyLevel::Standard` | **本次新增**：`Standard`（100% 推荐容量）；`UltraStealth`（限制使用 30%~50% 容量，压低载荷率对抗 SRNet/SRM） |
| **`codec`** | `StegoCodec` | `StegoCodec::Auto` | 编码策略（Auto / STC / Hamming），自描述记录于头部字中 |
| **`compression`** | `CompressionStrategy` | `CompressionStrategy::Auto` | 载荷压缩决策，针对已加密的高熵载荷允许显式 `Never` 跳过 Deflate |

### 2.3 内部下沉参数：移出公共视野（不再对普通调用者暴露）

以下参数全部降级为内部实现常量，或仅在内部测试中保留：
* `high_pass_kernel`（固定为归一化 KB 核 `[-0.25, 0.50, ...]`）
* `p1_window = 3` 与 `p2_window = 15`
* `epsilon = f32::EPSILON as f64`
* `val & 0xF8` 等价类掩码与 `[8, 247]` 动态范围
* `min_abs_coeff = 2`、`neighbor_weight = 0.25`、`wet_cost = 1e13`
* 默认排除比例 `exclusion_percentile = 0.30` 与 `block_exclusion_percentile = 0.20`

---

## 3. 具体落地技术设计

### 3.1 改造一：`StegoProfile` 补齐私有 KDF 域隔离（`stego_domain`）

#### 痛点代码现状（`src/stego/envelope.rs`）
```rust
// 现存硬编码字面量：
hk.expand(b"strhide-stego-enc-v1", &mut enc_key_bytes);
hk.expand(b"strhide-stego-perm-v1", &mut perm_seed);
let hk = Hkdf::<Sha256>::new(Some(b"strhide-stego-hpos-salt-v2"), pw.as_bytes());
hk.expand(b"strhide-stego-hpos-v2", &mut header_seed);
hk.expand(b"strhide-stc-trellis-v1", &mut out);
```

#### 实施设计
1. 在 `params.rs` 中为 [`StegoProfile`](file:///c:/Home/Projects/strhide/rust/src/params.rs#L228-L235) 增加字段：
   ```rust
   #[derive(Debug, Clone, Default)]
   #[non_exhaustive]
   pub struct StegoProfile {
       pub default_secret: Option<Cow<'static, str>>,
       /// 私有 KDF 派生域；None 表示使用官方默认域标签。
       pub stego_domain: Option<Cow<'static, [u8]>>,
   }
   
   impl StegoProfile {
       pub fn with_stego_domain<D: Into<Cow<'static, [u8]>>>(mut self, domain: D) -> Self {
           self.stego_domain = Some(domain.into());
           self
       }
       pub fn domain(&self) -> &[u8] {
           self.stego_domain.as_deref().unwrap_or(b"strhide-stego-v2")
       }
   }
   ```
2. 改造 `src/stego/envelope.rs` 派生函数，接入 `domain: &[u8]`：
   * 将所有的标签扩展定义为 `format!("{}-enc-v1", domain)` 或通过子切片连接（零动态分配方式），使调用者自定义 `domain` 后，整个 KDF 派生空间彻底与开源仓库隔离。
3. CLI 支持：
   * 新增参数 `--stego-domain <STRING>`，配置文件支持 `stego_domain`，环境变量支持 `STRHIDE_STEGO_DOMAIN`。

---

### 3.2 改造二：`StegoOptions` 引入安全容量等级（`safety_level`）

#### 痛点与机理
* 调研表明，**高载荷是促使 SRNet 和 SRM 检出率飙升至 90% 的唯一主因**。
* 目前的 `recommended_max_bytes` 将工作点锚定在 $r = 4.5$（改动率 $\le 7.5\%$）。但在极端对抗场景（如面临深度学习审查网关），需要更保守的容量预算（$r \ge 8.0 \sim 10.0$）。

#### 实施设计
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SafetyLevel {
    /// 标准推荐容量 (r >= 4.5, STC u=3 / u=2)，兼顾容量与常规隐蔽性
    #[default]
    Standard,
    /// 极限隐蔽模式 (r >= 9.0)，容量减半，单位图像改动点极度稀疏，致盲 SRNet/SRM
    UltraStealth,
}

impl SafetyLevel {
    pub fn capacity_divisor(&self) -> f64 {
        match self {
            Self::Standard => 1.0,
            Self::UltraStealth => 0.5, // 仅允许使用推荐容量的 50%
        }
    }
}
```
* `probe_carrier_capacity` 和 `embed_carrier` 入口根据 `options.safety_level` 限制最大允许载荷，超限明确拒绝，提示使用更保守分卷或更换大图。

---

### 3.3 改造三：嵌入通道分散策略（`ChannelMode`）

#### 痛点与机理
* 当前空域引擎在 `spatial/engine.rs:500` 写死 `channel_offset = 1`（Green 通道）。
* 检测工具比对 R、G、B 通道差分残差时，Green 通道的噪声方差呈现孤立异常。

#### 实施设计
1. 在 `StegoProfile` 中引入 `ChannelMode`：
   ```rust
   #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
   pub enum ChannelMode {
       /// 默认模式：仅使用绿色通道（保持历史兼容）
       #[default]
       GreenOnly,
       /// RGB 伪随机离散分布：依据 perm_seed 将候选槽位打散至 R/G/B 三个颜色平面
       RgbSpread,
   }
   ```
2. 在 `spatial::engine` 收集候选像素时：
   * `GreenOnly`：候选槽总数 $N = W \times H$；
   * `RgbSpread`：候选槽扩展为 $3 \times W \times H$，每个颜色通道单独判定 `[8, 247]` 范围与 HILL 代价，再按代价整体排序。
   * **收益**：改动点被稀释到 3 个平面，任何单通道统计攻击（如 `stegoVeritas`）的信号幅度下降为原来的 $\frac{1}{3}$。

---

### 3.4 改造四：精简与收敛 `StegoOptions` API 接口

在 `src/stego/params.rs` 中重构公开结构体，将低层数学参数封装：

```rust
#[derive(Debug, Clone, Default)]
pub struct StegoOptions {
    /// 算法名称 (默认 "auto")
    pub algorithm: Option<String>,
    /// 显式口令
    pub password: Option<String>,
    /// 安全隐蔽等级 (Standard / UltraStealth)
    pub safety_level: SafetyLevel,
    /// 编码层选择 (Auto / Stc / Hamming)
    pub codec: StegoCodec,
    /// STC 约束高度 (默认 8)
    pub stc_h: u8,
    /// 载荷压缩策略 (Auto / Never / Always)
    pub compression: CompressionStrategy,
}
```

* 原 `spatial_params` 和 `jpeg_params` 转为内部模块私有结构体或设为 `#[doc(hidden)]` 的高级专家调试参数，一般使用者不再需要传递和配置这堆浮点数。

---

## 4. 兼容性保障矩阵

| 场景 | 写入端配置 | 读取端配置 | 兼容性与行为表现 |
|---|---|---|---|
| **官方默认互通** | `Profile::default()` | 官方二进制 / `Profile::default()` | **100% 逐位双向互通**，与 0.3.x / 0.4.0 完全一致 |
| **私有 Secret 隔离** | `Profile.with_stego_secret("my-sec")` | 官方二进制 | 官方报 `NoHiddenData`，安全阻断（已验证） |
| **私有 Domain 隔离** | `Profile.with_stego_domain(b"corp-v1")` | 官方二进制 / 其他 Domain | 官方报 `NoHiddenData`，即使密码相同也无法交叉提取 |
| **多通道模式隔离** | `ChannelMode::RgbSpread` | 默认 `GreenOnly` | 读取端提取失败，安全报 `NoHiddenData` |

---

## 5. 分期实施路线图

### Phase 1：Profile 补齐私有域隔离（预计 0.5 人日）
* **范围**：`StegoProfile` 新增 `stego_domain`，打通 `src/stego/envelope.rs` 中的 HKDF 标签派生。
* **风险**：低。默认值为官方常量，完全向后兼容。
* **验证**：补齐“同密码不同 domain 互报 `NoHiddenData`”的黑盒隔离测试。

### Phase 2：API 表面积收敛与 `safety_level` 落地（预计 1.0 人日）
* **范围**：收敛 `StegoOptions`，引入 `SafetyLevel`；将 `SpatialParams` 内部化；容量计算接入 `safety_level`。
* **风险**：中低。属于库层 API 的梳理优化，需同步适配现有集成测试的构造调用。

### Phase 3：RGB 多通道打散支持（预计 1.0 ~ 1.5 人日）
* **范围**：`spatial/engine.rs` 支持候选槽跨通道检索，评估三通道打散后的加权失真与容量。
* **风险**：中。需要验证多通道在调色板、单色灰度图下的优雅降级。

---

## 6. 评审与验收标准（Checklist for Review）

- [ ] **域隔离可证伪性**：使用相同的载体图片与相同的密码，若 `stego_domain` 不同，提取端**必须恒定返回 `NoHiddenData`**，且两次嵌入的头部物理像素索引完全不同。
- [ ] **官方兼容零破坏**：在所有配置均为默认时，已有的 240+ 批测语料与 19+ 隐写测试（`batch_stego`）保持 100% 绿灯。
- [ ] **高阶盲检抗性验证**：在 `UltraStealth` 模式下，针对大尺寸原图嵌入小载荷，运行 `strhide scan` 自检以及 `batch_stego`，盲检风险值必须维持在 `0 CLEAN`。
- [ ] **API 简洁性**：普通库使用者仅需接触 `Profile`（负责私有方言与密钥）与 `StegoOptions`（负责安全等级与编码模式），无需了解任何高通卷积核或平滑窗口尺寸。
