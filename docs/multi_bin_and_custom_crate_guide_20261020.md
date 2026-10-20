# strhide 多二进制与定制算法/参数扩展指南

本文档介绍在**不改动原项目核心代码**的前提下，如何为 `strhide` 构建多个不同命令行、微调参数、甚至替换算法的独立二进制（Binary）执行文件。

---

## 核心设计背景

`strhide`（Rust 模块）在工程架构上采用了典型的 `[lib]` + `[[bin]]` 模式：
- **核心库 (`src/lib.rs`)**：导出全部底层模块，包括 `engine`（读写调度）、`stego`（隐写算法与参数）、`crypto`（加解密）、`envelope`（数据封装）、`adapters`（各类载体文件处理）等。
- **命令行入口 (`src/main.rs`)**：仅包含 4 行胶水代码，负责调用 `strhide::cli::run_cli()`。

由于所有业务逻辑都在 `lib` 中导出，任何外部代码或新二进制都可以将其视为一个普通库，直接引用并自由组装。

---

## 方案选型总览

| 方案 | 适用场景 | 依赖关系 | 侵入性 |
|---|---|---|---|
| **方案一：同 Crate `src/bin/`** | 命令行不同、参数微调、快速出包 | 同一个 Cargo.toml，共用依赖与编译缓存 | 极低（仅新建文件，不改既有代码） |
| **方案二：独立外部 Crate** | 独立工具、深度定制算法、跨磁盘放置、需额外第三方库 | 作为一个全新项目，通过 `path` 引用 strhide 库 | 零侵入（原项目代码与配置完全只读） |
| **方案三：Cargo `examples/`** | 调参实验、算法指标对比、临时测试脚本 | 同一个 Cargo.toml，专为测试/演示设计 | 极低（不污染发布的二进制列表） |

---

## 方案一：同 Crate 内的 `src/bin/` 机制（最快、开箱即用）

Cargo 具备自动发现机制：只要在 `rust/src/bin/` 目录下放置 `.rs` 文件，Cargo 就会将其识别为一个同名的独立二进制目标，**无需在 `Cargo.toml` 中手动配置 `[[bin]]`**。

### 1. 目录结构
```text
rust/
├── Cargo.toml
├── src/
│   ├── lib.rs              # 现有库逻辑（原封不动）
│   ├── main.rs             # 默认的 strhide 官方命令（原封不动）
│   └── bin/                # 新建此目录
│       ├── strhide_tune.rs # 定制二进制 1 (例如：调参定制版)
│       └── strhide_exp.rs  # 定制二进制 2 (例如：简化版/专有格式版)
```

### 2. 源码示例 (`rust/src/bin/strhide_tune.rs`)
```rust
use clap::Parser;
use std::path::PathBuf;
use strhide::engine::{write_carrier, PayloadSource, WriteOptions};
use strhide::stego::params::SpatialParams;

/// 自定义命令行：参数和命令结构完全独立
#[derive(Parser, Debug)]
#[command(name = "strhide-tune", about = "Custom tuned strhide tool")]
struct Cli {
    #[arg(short, long)]
    carrier: PathBuf,

    #[arg(short, long)]
    payload: String,

    /// 算法微调：自适应排除平滑区域百分比 (调整默认值为 0.45，官方默认是 0.30)
    #[arg(long, default_value_t = 0.45)]
    exclusion: f64,

    /// 算法微调：低通滤波窗口大小
    #[arg(long, default_value_t = 5)]
    p1_window: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    // 1. 微调算法参数
    let mut custom_params = SpatialParams::default();
    custom_params.exclusion_percentile = args.exclusion;
    custom_params.p1_window = args.p1_window;

    // 2. 微调写入选项
    let options = WriteOptions {
        strategy: "chunk", // 针对特定需求强制固定策略
        ..WriteOptions::default()
    };

    println!("[strhide-tune] Running with exclusion = {}", args.exclusion);
    let result = write_carrier(&args.carrier, PayloadSource::Text(&args.payload), &options)?;
    println!("[strhide-tune] Success! Carrier written to: {}", result.carrier);

    Ok(())
}
```

### 3. 构建与运行命令
```bash
# 只编译你的定制二进制
cargo build --bin strhide_tune

# 发布优化模式编译
cargo build --release --bin strhide_tune

# 直接运行并传递专属参数
cargo run --bin strhide_tune -- --carrier test.png --payload "hello" --exclusion 0.45
```

---

## 方案二：独立外部 Crate 模式（物理隔离最彻底、推荐用于独立项目）

### 1. 核心概念
这个 Crate **就是一个 100% 独立的标准 Rust 项目**。它与你在网上用 `cargo add serde` 引用开源库没有任何区别，唯一的区别是依赖来源写的是**本地路径**。

你可以把它放在本项目的平级目录、桌面、或者**电脑上的任意其他磁盘（如 `D:\`、`E:\` 等）**。

### 2. 跨磁盘/跨路径的 `Cargo.toml` 依赖写法

假设原项目位于：`C:/Home/Projects/strhide/rust`

#### 方式 A：跨盘/绝对路径引用（放在任意磁盘皆可）
```toml
[package]
name = "my-stego-app"
version = "0.1.0"
edition = "2024"

[dependencies]
# 绝对路径引用（Windows 下推荐使用正斜杠 / 避免转义问题）
strhide = { path = "C:/Home/Projects/strhide/rust" }

# 你的专属独立依赖（可以随意引入数据分析、图表绘制库，完全不影响主项目）
clap = { version = "4", features = ["derive"] }
# plotters = "0.3"
```

#### 方式 B：同盘相对路径引用（推荐项目放在平级或子目录时使用）
```toml
[dependencies]
# 向上两级找到 strhide 的 rust 核心目录
strhide = { path = "../../rust" }
clap = { version = "4", features = ["derive"] }
```

#### 方式 C：远程 Git 引用（如代码已推送到远程仓库）
```toml
[dependencies]
strhide = { git = "https://github.com/mcxiaoke/strhide.git", branch = "master" }
```

### 3. 该方案的显著优势
1. **原仓库完全洁癖**：原项目的 Git 仓库不会出现任何未跟踪的临时文件、试验文件或额外的分支依赖。
2. **依赖完全解耦**：实验需要的重型依赖（如图像处理、机器学习评估、可视化库）只会下载并链接到独立项目，原项目的发布构建体积和编译速度不受任何影响。
3. **独立分发与升级**：你的独立项目可以拥有自己的 README、版本号和 Git 历史。原项目升级算法时，独立项目 `cargo build` 会自动拉取最新的代码。

---

## 方案三：Cargo `examples/` 目录（适合指标评估与临时脚本）

如果你的微调代码只是为了“做一次实验”、“跑一组对比数据”或“验证某参数下的不可感知性”，放在 `examples/` 是最轻量的。

### 1. 目录结构
```text
rust/
├── examples/
│   ├── eval_hill_params.rs # 专门跑参数扫描的脚本
│   └── compare_uerd.rs     # 专门跑 DCT 能量对比的脚本
```

### 2. 运行方法
```bash
cargo run --example eval_hill_params -- --help
```
- **特点**：平时跑 `cargo build` 或发布时不会构建它们，对日常开发零负担。

---

## 深入：在“不改原代码”下如何进行算法微调？

`strhide` 的模块化设计允许你在独立可执行文件里直接替换或扩展底层算法：

### 1. 微调算法内置参数（无代码修改）
通过修改参数结构体覆盖默认行为：
- **空间域（PNG / 原生像素）**：[`strhide::stego::params::SpatialParams`](file:///c:/Home/Projects/strhide/rust/src/stego/params.rs)
  - `high_pass_kernel`：3x3 高通滤波器卷积核权重（默认是 KB 算子）。
  - `p1_window` / `p2_window`：低通滤波平滑窗口大小。
  - `exclusion_percentile`：排除平滑敏感区域的百分比阈值。
- **频域（JPEG DCT 系数）**：[`strhide::stego::params::JpegParams`](file:///c:/Home/Projects/strhide/rust/src/stego/params.rs)
  - `neighbor_weight`：邻域能量加权系数。
  - `block_exclusion_percentile`：低能量 DCT 块排除比例。

### 2. 实现全新的代价模型算法（面向接口扩展）
`strhide` 导出了算法抽象 Trait：
- 空间域代价模型接口：[`strhide::stego::traits::SpatialCostModel`](file:///c:/Home/Projects/strhide/rust/src/stego/traits.rs)
- JPEG 频域代价模型接口：[`strhide::stego::traits::JpegCostModel`](file:///c:/Home/Projects/strhide/rust/src/stego/traits.rs)

在新二进制中，你可以直接实现该接口：
```rust
use strhide::stego::params::SpatialParams;
use strhide::stego::traits::SpatialCostModel;

pub struct MyExperimentalCostModel;

impl SpatialCostModel for MyExperimentalCostModel {
    fn id(&self) -> &'static str {
        "my-model-v1"
    }

    fn description(&self) -> &'static str {
        "Custom experimental distortion cost function"
    }

    fn compute_cost(
        &self,
        pixels: &[u8],
        width: usize,
        height: usize,
        channels: usize,
        params: &SpatialParams,
    ) -> Vec<f64> {
        // 在这里编写你微调或全新的像素修改代价计算逻辑
        vec![1.0; width * height]
    }
}
```
这样你既获得了完全自主的算法控制权，又能无缝享受 `strhide` 原生提供的载体解析、AES-256-GCM 认证加密、格式无损校验和隐写提取机制。
