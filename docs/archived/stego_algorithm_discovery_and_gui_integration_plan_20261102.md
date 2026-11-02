# GUI 隐写算法动态发现与 Lib 接口优化方案

> **文档创建时间**：2026-11-02  
> **状态**：全阶段实施完成（阶段一核心库、阶段二Tauri后端、阶段三前端交互均全量验证通过）  
> **涉及模块**：`rust/src/stego/`, `rust/src/facade.rs`, `gui/src-tauri/`, `gui/src/`

---

## 1. 现状调查与问题根因诊断

针对“GUI 隐写 Tab 算法选择不全”的问题，经过对前端、Tauri IPC 后端以及 Rust 核心库的全链路代码核对，确认原因由三层缺失叠加导致：

### 1.1 前端 GUI 完全硬编码（写死）
- **写死定义文件**：[`gui/src/lib/stego.ts#L5`](file:///c:/Home/Projects/strhide/gui/src/lib/stego.ts#L5)
  ```typescript
  export const ALGORITHMS = ["auto", "hill", "suniward", "mipod", "uerd", "juniward", "jmipod"];
  ```
- **写死展示标签**：[`gui/src/views/StegoEmbedView.tsx#L51-L59`](file:///c:/Home/Projects/strhide/gui/src/views/StegoEmbedView.tsx#L51-L59)
  ```typescript
  const algorithmLabel: Record<string, string> = {
    auto: c.stego.algoAuto,
    hill: "HILL",
    suniward: "S-UNIWARD",
    mipod: "MiPOD",
    uerd: "UERD",
    juniward: "J-UNIWARD",
    jmipod: "J-MiPOD",
  };
  ```
- **缺失的算法**：
  1. **HEVC CABAC**（针对 HEIF、MP4、MKV、Annex-B HEVC 载体）：代码中存在完整引擎（`HeifEngine`, `Mp4Engine`, `MkvEngine`, `AnnexBEngine`），但 UI 无法选择 `hevc` 算法。
  2. **音频隐写**（针对 WAV PCM、FLAC Residual 载体）：代码中存在 `WavEngine`、`FlacEngine`，但 UI 既没有展示也不支持查看。
- **交互缺陷**：
  - 下拉框是静态死列表，与拖入的文件格式**毫无联动**。例如用户拖入 `.mp4` 文件，高级设置下拉框中依然只有 `HILL`、`UERD` 等图像算法；如果用户选了 `HILL` 尝试隐写 MP4，会在底层抛出载体不兼容错误。

### 1.2 Tauri 后端缺少查询命令与转换遗漏
- **缺少算法 IPC 查询命令**：后端只暴露了 `get_capabilities_cmd`（载体格式级能力），没有暴露任何关于隐写算法的 IPC 命令。
- **参数转换遗漏**：[`gui/src-tauri/src/commands/stego.rs#L24-L40`](file:///c:/Home/Projects/strhide/gui/src-tauri/src/commands/stego.rs#L24-L40)
  ```rust
  fn resolve_tuning(algo: Option<&str>) -> StegoTuning {
      if let Some(name) = algo {
          if let Some(m) = SpatialAlgorithm::from_name(name) {
              return StegoTuning::Png { model: m, params: PngParams::default() };
          }
          if let Some(m) = JpegAlgorithm::from_name(name) {
              return StegoTuning::Jpeg { model: m, params: JpegParams::default() };
          }
      }
      StegoTuning::Auto
  }
  ```
  该函数只匹配了 PNG 和 JPEG 算法，**完全漏掉了 `HevcMode`**！即使前端传了 `"hevc"`，这里无法识别，会静默回退为 `StegoTuning::Auto`。

### 1.3 Rust 核心库（lib）接口缺陷与近期改动未同步
- **现有接口过于简陋**：
  核心库仅在 [`rust/src/stego/registry.rs#L16`](file:///c:/Home/Projects/strhide/rust/src/stego/registry.rs#L16) 中提供了一个供内部 CLI 打印用的静态函数：
  ```rust
  pub fn list_algorithms() -> Vec<(&'static str, &'static str, &'static str)>
  // 返回元组: (id, target_domain_str, description)
  ```
  缺陷如下：
  1. **非结构化、无序列化**：返回未结构化的三元组字符串，没有 `#[derive(Serialize)]`，无法直接通过 IPC 传递给前端。
  2. **缺少支持的格式列表（formats / extensions）**：元组中的 `domain` 仅是文字标签（如 `"Spatial (PNG)"`、`"JPEG (JPG)"`），无法被程序解析用作格式匹配。
  3. **未通过 Facade 暴露**：[`rust/src/facade.rs`](file:///c:/Home/Projects/strhide/rust/src/facade.rs) 的 `StrHide` / `StegoFacade` 只有操作方法（`embed`, `extract`, `probe`, `inspect`, `verify`），缺少算法元数据查询接口。
  4. **最近改动未同步**：最近新增了 FLAC 音频隐写引擎（`FlacEngine`），但在 `registry.rs` 中仍只写着 `"Audio (WAV)"`，未收录 FLAC。
  5. **底层判定 Bug**：[`rust/src/stego/options.rs#L360`](file:///c:/Home/Projects/strhide/rust/src/stego/options.rs#L360) 的 `StegoTuning::applicable_to` 中：
     ```rust
     #[cfg(feature = "content-hevc")]
     (StegoTuning::Hevc { .. }, FileFormat::Heif | FileFormat::Mp4) => Ok(()),
     #[cfg(feature = "content-hevc")]
     (StegoTuning::Hevc { .. }, FileFormat::HevcAnnexB) => Ok(()),
     ```
     **遗漏了 `FileFormat::Mkv`**！导致指定 HEVC 算法对 MKV 文件操作时会被误报为载体不支持。

---

## 2. 核心设计与数据结构规范

为了彻底解耦前端与后端算法硬编码，并在核心库中提供完善的元数据自省能力，设计如下结构体与接口：

### 2.1 结构化算法信息实体 `StegoAlgorithmInfo`

在 `rust/src/stego/mod.rs`（或 `registry.rs`）中定义：

```rust
use serde::{Deserialize, Serialize};

/// 描述一个内容域隐写算法的完整元数据信息
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StegoAlgorithmInfo {
    /// 唯一算法标识（CLI / IPC / 配置参数入参），如 "hill", "uerd", "hevc", "wav_pcm", "flac_residual"
    pub id: String,

    /// 友好的人类可读名称，如 "HILL", "UERD", "HEVC CABAC Bypass", "WAV PCM Matching"
    pub name: String,

    /// 算法技术原理与论文引用等详细描述
    pub desc: String,

    /// 隐写领域分类标识: "spatial" | "dct" | "hevc" | "audio"
    pub domain: String,

    /// 适用的载体格式标识列表（对应 FileFormat 标识）
    /// 例如: ["png"]、["jpeg"]、["heif", "mp4", "mkv", "hevc_annexb"]、["wav"]、["flac"]
    pub formats: Vec<String>,

    /// 适用的文件扩展名列表（方便前端基于文件名扩展快速匹配过滤）
    /// 例如: ["png"]、["jpg", "jpeg", "jpe"]、["mp4", "mov", "mkv", "heic", ...]
    pub extensions: Vec<String>,

    /// 是否为所属格式的默认推荐算法（例如 PNG 默认为 HILL, JPEG 默认为 UERD）
    pub is_default: bool,
}
```

### 2.2 核心库内置算法列表清单表

基于当前核心库能力，注册表全量数据映射如下：

| ID | Name | Domain | 对应文件格式 (formats) | 常见扩展名 (extensions) | 是否默认 | 机制说明简述 |
|---|---|---|---|---|:---:|---|
| `hill` | HILL | `spatial` | `["png"]` | `["png"]` | 是 | 高低通滤波器自适应空间域（Li et al., 2014） |
| `suniward` | S-UNIWARD | `spatial` | `["png"]` | `["png"]` | 否 | 小波方向相对失真空间域（Holub et al., 2014） |
| `mipod` | MiPOD | `spatial` | `["png"]` | `["png"]` | 否 | 最小可检测性方差统计模型（Sedighi et al., 2016） |
| `uerd` | UERD | `dct` | `["jpeg"]` | `["jpg", "jpeg", "jpe"]` | 是 | DCT 变换系数能量逆权重分布（Guo et al., 2015） |
| `juniward` | J-UNIWARD | `dct` | `["jpeg"]` | `["jpg", "jpeg", "jpe"]` | 否 | DCT 小波相对失真代价模型（Holub et al., 2014） |
| `jmipod` | J-MiPOD | `dct` | `["jpeg"]` | `["jpg", "jpeg", "jpe"]` | 否 | 频域多元正态联合可检测性模型（Cogranne et al., 2020） |
| `hevc` | HEVC CABAC | `hevc` | `["heif", "mp4", "mkv", "hevc_annexb"]` | `["heic", "heif", "avif", "mp4", "mov", "m4v", "mkv", "webm", "h265", "hevc", "265"]` | 是 | H.265 CABAC 旁路符号位零膨胀隐写（Scheme C） |
| `wav_pcm` | WAV PCM LSB | `audio` | `["wav"]` | `["wav"]` | 是 | 内容自适应感知掩蔽 + STC 样点匹配（+/-1 LSB） |
| `flac_residual` | FLAC Residual | `audio` | `["flac"]` | `["flac"]` | 是 | 保持定长码字的多项式预测残差匹配 |

---

## 3. 分层改造实施方案

### 3.1 核心库层（`rust/src/`）

1. **注册表结构化与完善**（`rust/src/stego/registry.rs`）：
   - 实现 `list_stego_algorithms() -> Vec<StegoAlgorithmInfo>`。
   - 实现辅助方法 `algorithms_for_format(format: FileFormat) -> Vec<StegoAlgorithmInfo>`。
   - 将现有 `list_algorithms()`（返回三元组）调整为基于 `list_stego_algorithms()` 生成，保证单点事实来源。
2. **Facade 暴露**（`rust/src/facade.rs`）：
   - 在 `StegoFacade` 及 `StrHide` 上暴露 `list_algorithms(&self) -> Vec<StegoAlgorithmInfo>`。
3. **修复 `applicable_to` 遗漏**（`rust/src/stego/options.rs`）：
   - 将 `FileFormat::Mkv` 加入 `StegoTuning::Hevc` 的许可列表：
     ```rust
     #[cfg(feature = "content-hevc")]
     (StegoTuning::Hevc { .. }, FileFormat::Heif | FileFormat::Mp4 | FileFormat::Mkv) => Ok(()),
     ```
4. **单元测试与一致性测试**：
   - 在 `registry.rs` 中增加测试，确保每个算法的 `formats` 与 `formats::capability::CAPABILITIES` 完全对齐，防止日后新增格式时发生漂移。

### 3.2 Tauri 后端层（`gui/src-tauri/`）

1. **暴露查询 IPC 命令**（`gui/src-tauri/src/commands/stego.rs`）：
   ```rust
   #[tauri::command]
   pub fn get_stego_algorithms_cmd() -> Vec<StegoAlgorithmInfo> {
       strhide::stego::list_stego_algorithms()
   }
   ```
   并在 `gui/src-tauri/src/lib.rs` 的 `generate_handler!` 中注册。
2. **完善 `resolve_tuning` 算法转换**（`gui/src-tauri/src/commands/stego.rs`）：
   ```rust
   fn resolve_tuning(algo: Option<&str>) -> StegoTuning {
       if let Some(name) = algo {
           if let Some(m) = SpatialAlgorithm::from_name(name) {
               return StegoTuning::Png { model: m, params: PngParams::default() };
           }
           if let Some(m) = JpegAlgorithm::from_name(name) {
               return StegoTuning::Jpeg { model: m, params: JpegParams::default() };
           }
           #[cfg(feature = "content-hevc")]
           if let Some(mode) = HevcMode::from_name(name) {
               return StegoTuning::hevc(mode);
           }
       }
       StegoTuning::Auto
   }
   ```

### 3.3 前端 GUI 层（`gui/src/`）

1. **类型定义与 API 封装**：
   - 在 `gui/src/types/strhide.ts` 补充 `StegoAlgorithmInfo` 接口。
   - 在 `gui/src/api/commands.ts` 增加 `getStegoAlgorithms(): Promise<StegoAlgorithmInfo[]>`。
2. **状态 Hook 封装**（`gui/src/hooks/useStegoAlgorithms.ts`）：
   - 实现全局单例缓存（类似现有的 `useCapabilities`），进程启动后异步拉取一次。
3. **算法下拉框上下文感知（Context-Aware Filter）**：
   - 在 `gui/src/views/StegoEmbedView.tsx` 中：
     - 保留第一项为 `auto`（根据文件自适应选择默认最优算法）。
     - **智能过滤规则**：
       - **当待处理文件队列为空时**：展示所有可用算法，并标注适用的文件格式（如 `UERD (JPEG)`、`HEVC CABAC (HEIF/MP4/MKV)`）。
       - **当文件队列全部为单一类型时**（如全部为 `.png`）：
         动态过滤下拉框，仅显示 `auto` 与适应该格式的算法（`HILL`, `S-UNIWARD`, `MiPOD`）。
       - **当文件队列包含多种类型时**（如同时包含 `.png` 与 `.mp4`）：
         默认强制选中 `auto`，并提示“多格式批处理模式下已自动采用格式最优算法”，禁用单一特定算法以防止跨载体冲突。
4. **UI 展示增强**：
   - 下拉选项旁展示信息提示图标（Tooltip），鼠标悬浮时展示该算法的 `desc`（包括论文出处、优劣势评语）。

---

## 4. 实施阶段与测试验收要求

### 阶段一：核心库及测试通过
- 修改 `rust/` 下代码并增加对应单元测试。
- 验证指令：
  ```bash
  cd rust
  cargo fmt
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all-features --all-targets
  python scripts/baseline_hash.py --check
  ```

### 阶段二：Tauri 后端集成
- 在 `gui/src-tauri` 增加命令与测试。
- 验证指令：
  ```bash
  cd gui
  cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings
  pnpm test:cross
  ```

### 阶段三：前端界面与交互升级
- 替换前端硬编码，接入动态算法。
- 验证指令：
  ```bash
  cd gui
  pnpm build
  pnpm test:unit
  pnpm test:e2e
  ```
