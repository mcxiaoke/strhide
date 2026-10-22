# strhide 双系统架构辨析与现代化 Facade API 重构方案

> **编制日期**：2026-10-22  
> **状态**：方案建议（待审阅，未动代码）  
> **核心定位**：厘清 strhide 内部两套彼此独立的隐写系统，终结"C 语言式散装函数传参"的低效调用体验，构建基于面向对象 / 现代化 Facade 门面的实例化 API，并为 CarrotHash 等宿主工具提供优雅的私有方言嵌入能力。

---

## 目录

1. [问题背景与重构动机](#1-问题背景与重构动机)
2. [底层真相：两套基本独立的隐写系统对比](#2-底层真相两套基本独立的隐写系统对比)
3. [现有 API 的三大结构性缺陷](#3-现有-api-的三大结构性缺陷)
4. [重构方案：统一门面与实例化引擎（Facade Pattern）](#4-重构方案统一门面与实例化引擎facade-pattern)
5. [Profile 与配置体系的重新整合](#5-profile-与配置体系的重新整合)
6. [在 CarrotHash 等宿主中的落地效果](#6-在-carrothash-等宿主中的落地效果)
7. [演进路径与向前兼容策略](#7-演进路径与向前兼容策略)

---

## 1. 问题背景与重构动机

在近期尝试将 `strhide` 作为依赖库引入其他工具（如 `CarrotHash`，通过隐藏参数 `-s / --stego` 化身为隐写工具并使用私有方言）的过程中，暴露出 `strhide` 作为一个 Rust Library 的极度别扭感：

- **调用极其繁琐**：每次执行任何操作，都必须像 C 语言函数指针一样，把一大堆零散对象（`&Profile`, `&LocalParams`, `&WriteOptions` 等）作为入参层层传递；
- **概念割裂且混乱**：存在 `Profile`、`FormatProfile`、`LocalParams`、`StegoOptions`、`WriteOptions` 等多个重叠类型，调用方很难理清哪个配置管什么；
- **缺乏实例生命周期**：外部程序无法先初始化一个 `let engine = StrHide::with_profile(my_profile)` 然后持续调用 `engine.write()` 或 `engine.read()`，状态无法绑定。

要彻底解决这一问题，必须**先从根本上认清 strhide 内部的架构本质**，绝不能简单粗暴地将所有接口揉成一个大杂烩。

---

## 2. 底层真相：两套基本独立的隐写系统对比

`strhide` 代码库中实际并存着**两套哲学不同、数学原理不同、载体格式不同、操作语义完全独立**的隐写子系统：

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          strhide 顶层门面                               │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
    ┌───────────────▼──────────────┐  ┌──────────────▼──────────────┐
    │ 系统 A：结构域容器无损隐写     │  │ 系统 B：内容域图像自适应隐写   │
    │ (Carrier / Structure Domain) │  │ (Adaptive Stego / Content)  │
    └──────────────────────────────┘  └─────────────────────────────┘
```

### 2.1 核心差异矩阵

| 维度 | 系统 A：结构域容器隐写（Carrier / Structure） | 系统 B：内容域自适应隐写（Content / Stego） |
|---|---|---|
| **核心模块** | `engine` + `envelope` + `adapters` + `router` | `stego` (spatial / jpeg / coding / registry) |
| **设计哲学** | **100% 无损挂载、格式保持、可逆恢复** | **内容微调、有损不可逆、抗取证统计分析** |
| **工作原理** | 在文件格式的合法结构空隙（PNG chunk、JPEG APP15、MP4 uuid、PE slack/codebits、ZIP pre-CD、PDF incremental）注入二进制信封 | 基于代价模型（JPEG UERD、PNG HILL），通过 STC 校验格编码微调像素值或 DCT 交流系数 |
| **载体范围** | PNG, JPEG, MP4, ZIP, PDF, PE, WEBP, HEIF, WAV, MKV | **仅限图像**（JPEG DCT 系数，PNG 空间域像素） |
| **信封协议** | **UBE v2.2**（112B Header + Hint + 独立加密元数据块 + 分块 AEAD 载荷 + 24B Trailer） | **Micro-Envelope**（16B salt + 12B nonce + 单密文块，无静态魔数，呈高熵随机分布） |
| **宿主可逆性** | **支持 bit-for-bit 还原**：记录原图 SHA-256，`restore` / `remove` 严格验证还原一致性 | **绝无还原能力**：像素/系数一经修改不可逆，绝不支持 `restore` |
| **核心动词** | **`write`**, **`read`**, **`restore` / `remove`**, **`inspect`**, **`verify`** | **`embed`**, **`extract`**, **`probe`**（容量探测） |
| **私有方言** | `default_secret`, `stealth_domain`, 自定义魔数对 `MagicPair` | `stego_secret`, `stego_domain`, 派生标签（`FormatProfile`） |

### 2.2 结论与红线

1. **动词天然隔离**：系统 A 的核心动词是 `write / read / restore`；系统 B 的核心动词是 `embed / extract / probe`。
2. **严禁混为一谈**：绝不能设计一个所谓的 `engine.write()` 然后让它内部隐式猜测走“结构注入”还是“像素修改”；也绝不能让系统 B 暴露无意义的 `restore`。两套系统的底层逻辑必须严格保持清晰边界。

---

## 3. 现有 API 的三大结构性缺陷

### 缺陷 1：C 语言式面向过程传参，缺乏“实例封装”
目前所有 API 均为无状态顶层函数：
```rust
// 现状：每一次调用都必须把上下文重复传递
write_carrier_with(path, source, &write_opts, &local_params, &profile)?;
read_carrier_with_profile(path, output, password, overwrite, &profile)?;
remove_carrier_with_options(path, output, password, backup, &profile, overwrite)?;
```
在实际应用（如守护进程、服务、或嵌入到 CarrotHash）中，**私有方言 `Profile` 在整个程序生命周期内是恒定不变的**。逼迫调用者在每一处代码都显式传递 `profile`，不仅代码冗长，而且极易因某一处漏传或用了默认值而引发静默的解密失败。

### 缺陷 2：命名非正交与参数模式不对称
- 写操作叫 `write_carrier_with`（接收 profile）；
- 读操作叫 `read_carrier_with_profile`（因为 `read_carrier_with` 竟然**不接收** profile，只接收 overwrite！）；
- 还原操作叫 `remove_carrier_with_options`（包含 6 个散装参数）；
- 写操作有 `WriteOptions`，读和删却全为扁平散装长参数列表。

### 缺陷 3：内容域 `embed_carrier_with_profile` 内部写死 `DEFAULT_FORMAT`
在 `src/stego/mod.rs:88`：
```rust
// 致命缺陷：高层入口虽然接收了 Profile，但调用 JPEG 时写死了 DEFAULT_FORMAT
jpeg::embed_jpeg(
    carrier_bytes, payload, secret, domain,
    &format::DEFAULT_FORMAT, // <--- 无法传递自定义 FormatProfile！
    &jpeg_params, &*model,
)
```
这导致外部即使定义了私有的 `FormatProfile`，也无法通过 `stego` 的统一入口使用，被迫绕过统一入口去调用底层的 `jpeg::embed_jpeg`。

---

## 4. 重构方案：统一门面与实例化引擎（Facade Pattern）

设计一个顶层聚合结构体 **`StrHide`**（或称 `StrHideEngine`），作为整个库的唯一主入口。

### 4.1 双层调用模型

为了兼顾“两套系统的绝对独立性”与“常用调用的极致人体工学”，提供两种并存且自洽的调用接口：

```rust
// 创建绑定了私有方言的引擎实例
let engine = StrHide::with_profile(my_profile);

// -------------------------------------------------------------
// 形态 1：显式命名空间调用（最正交、最严谨、物理语义绝不混淆）
// -------------------------------------------------------------
// 结构域容器操作：
engine.carrier().write("photo.png", "secret").execute()?;
let data = engine.carrier().read("photo.png").to_vec()?;
engine.carrier().restore("photo.png").execute()?;
let report = engine.carrier().inspect("photo.png")?;

// 内容域自适应隐写：
let stego_img = engine.stego().embed(&cover_bytes, b"secret").execute()?;
let extracted = engine.stego().extract(&stego_img).execute()?;
let cap = engine.stego().probe(&cover_bytes)?;

// -------------------------------------------------------------
// 形态 2：根级快捷直通调用（动词天然正交，符合直觉）
// -------------------------------------------------------------
engine.write("photo.png", "secret").execute()?; // 自动转发 carrier().write
let data = engine.read("photo.png").to_vec()?;  // 自动转发 carrier().read
engine.restore("photo.png").execute()?;         // 自动转发 carrier().restore
engine.embed(&cover_bytes, b"secret").execute()?; // 自动转发 stego().embed
let out = engine.extract(&stego_img).execute()?;  // 自动转发 stego().extract
```

### 4.2 Fluent Operation 链式调用设计

消除散装长参数列表，改为 Operation Builder 模式：

```rust
// 写入操作：
engine.write(carrier_path, "payload.txt")
    .password("my-password")
    .stealth(true)
    .strategy("pe_slack")
    .backup(true)
    .execute()?; // 返回 WriteResult

// 读取操作：
let bytes = engine.read(carrier_path)
    .password("my-password")
    .to_vec()?; // 直接拿字节

engine.read(carrier_path)
    .password("my-password")
    .to_file("extracted.txt", true)?; // 写入目标文件，支持 overwrite

// 内容域嵌入操作：
let stego_bytes = engine.embed(&cover_bytes, payload_slice)
    .password("optional-pwd")
    .safety_level(SafetyLevel::Recommended)
    .execute()?;
```

---

## 5. Profile 与配置体系的重新整合

彻底厘清参数分级，将现有零散的 5 个配置类型收敛为清晰的 **2 层心智模型**：

```text
┌──────────────────────────────────────────────────────────────────┐
│ 1. 方言层（Profile）：决定"与谁通信"，生命周期绑定于 Engine 实例   │
│    - structure: 默认密钥、Stealth 域、自定义魔数对               │
│    - stego: 图像默认密钥、图像域、FormatProfile (JPEG V3 标签)    │
└──────────────────────────────────────────────────────────────────┘
                                │ 注入并驱动
┌───────────────────────────────▼──────────────────────────────────┐
│ 2. 操作层（Operation Options）：决定"本次怎么执行"，按需链式配置 │
│    - password / hint / output_path / overwrite / backup          │
└──────────────────────────────────────────────────────────────────┘
```

### 5.1 统一后的 `Profile` 结构演进

```rust
#[derive(Debug, Clone, Default)]
pub struct Profile {
    // === 结构域容器方言 ===
    pub default_secret: Option<Cow<'static, str>>,
    pub stealth_domain: Option<Cow<'static, [u8]>>,
    pub magic: Option<MagicPair>,

    // === 内容域自适应方言 ===
    pub stego: StegoProfile,
}

#[derive(Debug, Clone, Default)]
pub struct StegoProfile {
    pub default_secret: Option<Cow<'static, str>>,
    pub stego_domain: Option<Cow<'static, str>>,
    /// 解决历史遗留缺陷：允许外部注入自定义的 JPEG V3 wire-format 身份规范！
    pub format_profile: Option<Cow<'static, FormatProfile>>,
}
```

- **解决缺陷 3**：`stego::embed_carrier_with_profile` 与 `extract_carrier_with_profile` 在分发到 JPEG 时，检查 `profile.stego.format_profile`，若存在则使用自定义的 `FormatProfile`，否则安全回退至官方默认 `&DEFAULT_FORMAT`。
- **消灭 `LocalParams` 强迫症**：`chunk_size`、`compression` 等 writer-only 参数不再作为每次调用的强加入参，而是作为 `StrHideBuilder` 的可选调优参数（有默认值 2MB / Auto）。

---

## 6. 在 CarrotHash 等宿主中的落地效果

一旦完成该封装，在 CarrotHash 中引入隐藏参数 `-s / --stego` 将变得轻盈而优雅：

### 6.1 场景 A：直接挂载 strhide 完整 CLI

在 `strhide::cli` 暴露一个支持注入引擎上下文的执行器：
```rust
impl StrHide {
    pub fn run_cli<I, T>(&self, args: I) -> i32
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone;
}
```
**CarrotHash 的 `src/bin/hash_cli.rs` 中仅需 5 行代码**：
```rust
// 检测到隐藏开关 -s / --stego 时
if args.get(0).map(|s| s == "-s" || s == "--stego").unwrap_or(false) {
    let engine = StrHide::with_profile(CARROT_PRIVATE_PROFILE);
    let exit_code = engine.run_cli(&args[1..]);
    std::process::exit(exit_code);
}
```

### 6.2 场景 B：CarrotHash 内部按需调用核心 API

若 CarrotHash 希望自己定义极简的隐藏交互界面：
```rust
let engine = StrHide::with_profile(CARROT_PRIVATE_PROFILE);

match mode {
    Mode::Hide => {
        engine.write(carrier, payload_file).execute()?;
        println!("写入完成");
    }
    Mode::Extract => {
        let data = engine.read(carrier).to_vec()?;
        println!("提取成功: {} 字节", data.len());
    }
    Mode::Restore => {
        engine.restore(carrier).execute()?;
        println!("原文件已 100% 还原");
    }
}
```
完全消除了所有裸露的 `LocalParams`、`Profile` 散装参数。

---

## 7. 演进路径与向前兼容策略

为确保现有测试与旧代码 100% 不受破坏，建议按三步稳妥落地：

1. **第一阶段：修复底层与参数打通（Non-breaking）**
   - 补齐 `StegoProfile` 对 `FormatProfile` 的持有与传递，修复 `src/stego/mod.rs` 中写死 `DEFAULT_FORMAT` 的缺陷；
   - 保证底层现有函数（`write_carrier_with` 等）签名稳定，通过全量测试。
2. **第二阶段：构建 `StrHide` 门面与 Operation 链式体系（Additive）**
   - 新增 `src/facade.rs`（或 `src/client.rs`），实现 `StrHide`、`CarrierSubsystem`、`StegoSubsystem` 以及 `WriteOp`、`ReadOp`、`EmbedOp` 等句柄；
   - 在 `src/lib.rs` 顶层导出 `StrHide` 作为第一推荐 API。
3. **第三阶段：CLI 模块适配与 CarrotHash 接入**
   - 让 `cli.rs` 的内部处理流程基于 `StrHide` 实例驱动；
   - 增加 `StrHide::run_cli` 入口；
   - 在 CarrotHash 中接入该库并完成端到端集成测试。
