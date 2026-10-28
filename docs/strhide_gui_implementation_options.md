# `strhide` GUI 实施方案选型与架构设计指南

> **基线状态**：`strhide` 核心库已完成 Stage A–E 全部 GUI 就绪度改造（双域统一门面 `StrHide`、`inspect_any` / `verify_any` / `smart_extract`、MP4 流式有界诊断、零拷贝原位补丁、`ProgressWriter` + `CancelToken`、结构化 `ErrorDetail`/`ErrorKind`、多线程原子 `i18n`、无打印批处理 `core::batch::run_batch` 以及 `EmbedStats` 修改率统计）。
>
> 本文基于 `strhide` 的真实载体特性与业务工作流，为你提供 **5 套备选 GUI 实施方案** 的深度对比、优缺点剖析、推荐度评级以及首选方案的完整工程落地蓝图。

---

## 一、 选型前提：`strhide` 的 GUI 有哪些独特技术诉求？

在选择 GUI 框架前，必须先看清 `strhide` 与普通 CRUD 小工具的本质区别：

1. **多格式媒体预览与对比刚需**：
   - `strhide` 支持 **10 种结构域载体**（PNG, JPEG, MP4, HEIF/HEIC, MKV, WebP, WAV, PDF, ZIP, PE）与 **5 种内容域载体**（PNG, JPEG, HEIF, MP4, Annex-B HEVC）。
   - 用户在做内容域隐写（尤其是图像/视频隐写）时，最核心的交互体验是 **“左原图/原视频 vs. 右隐写图/视频同屏对比”**、**“像素/系数修改位置热力图放大镜”** 以及 **“预览音频/视频是否出现肉眼可见伪影”**。
   - **关键分水岭**：系统 WebView（如 [Tauri v2](https://v2.tauri.app/)、[Dioxus Desktop](https://dioxuslabs.com/)）天然具备硬件加速的 `<video>`、`<img>`、`<audio>` 渲染能力；而纯 Rust 自绘 GUI（如 [egui](https://github.com/emilk/egui)、[Iced](https://github.com/iced-rs/iced)）只能轻松渲染静态图片（PNG/JPEG/WebP），**没有内置的 MP4/HEVC 视频播放器**。
2. **重计算/重 I/O 与 UI 线程彻底解耦**：
   - 50 MP 大图代价图计算（HILL / S-UNIWARD / J-UNIWARD）、4K HEVC CABAC 算术编码重打包、数 GB 容器的 SHA-256 校验都是秒级甚至十秒级任务。
   - Stage A–E 已提供 `Control { progress, cancel }`、`ProgressWriter` 与 `core::batch::run_batch`，GUI 框架必须能优雅地消费后台线程推送的 `Event { stage, done, total }` 流。
3. **跨平台单包分发 vs. 现代视觉表现力**：
   - 安全与隐私工具用户既看重 **现代专业的界面交互**（容量水位条、三级校验步进器、反隐写风险仪表盘），也看重 **轻量无臃肿依赖**（拒绝 150 MB+ 的 Electron Chromium 全家桶）。

---

## 二、 五大备选 GUI 实施方案全景对比表

| 评估维度 | 方案一：[Tauri v2](https://v2.tauri.app/) + React/Vue (TS) | 方案二：[egui](https://github.com/emilk/egui) (`eframe`) | 方案三：[Iced](https://github.com/iced-rs/iced) (0.13 / 0.14) | 方案四：[Dioxus Desktop](https://dioxuslabs.com/) (0.6 / 0.7) | 方案五：[Slint](https://slint.rs/) (`slint-ui`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **综合推荐度** | 🌟 **⭐⭐⭐⭐⭐ (9.5 / 10)**<br>**【现代桌面主力首选】** | 🔥 **⭐⭐⭐⭐☆ (8.8 / 10)**<br>**【纯 Rust 单文件首选】** | 🦀 **⭐⭐⭐⭐ (8.2 / 10)**<br>**【纯 Rust 传统桌面架构】** | ⚡ **⭐⭐⭐☆ (7.5 / 10)**<br>**【纯 Rust 写 WebView 折中】** | 🎨 **⭐⭐⭐ (7.0 / 10)**<br>**【声明式轻量嵌入式风】** |
| **技术栈组成** | Rust (`src-tauri`) + TypeScript + React/Vue + Tailwind | **100% 纯 Rust**（即时模式 Immediate Mode） | **100% 纯 Rust**（Elm 响应式架构 Retained Mode） | **95% 纯 Rust** (`rsx!` 宏) + Tailwind CSS | Rust + `.slint` 专用声明式 DSL |
| **进程与通信模型** | 单进程，前后端经 Tauri IPC (`Channel` + JSON) 通信 | 单进程内存直调（**零序列化开销**） | 单进程内存直调（**零序列化开销**） | 单进程内存直调（Rust 跑在主进程，DOM 经 WebView 渲染） | 单进程内存直调（Model 绑定） |
| **安装包体积** | **~5 – 8 MB**（复用系统 WebView2 / WKWebView） | **~6 – 10 MB**（真正单 `.exe` 绿色可执行文件） | **~8 – 14 MB**（真正单 `.exe` 绿色可执行文件） | **~6 – 10 MB**（复用系统 WebView） | **~5 – 9 MB**（单可执行文件） |
| **图片/视频预览能力** | **极强**：原生支持 PNG/JPEG/WebP/WAV 及 **MP4 视频直接播放** | **中**：支持静态图片与**像素级隐写差值热力图**，但无内置视频播放 | **中**：支持静态图片与 Canvas 绘制，无内置视频播放 | **极强**：同样复用系统 WebView，支持 `<video>` 播放 | **弱**：仅支持基础位图展示，多媒体预览需自行解码 |
| **复杂表单与图表生态** | **天花板级**：shadcn/ui、ECharts/Recharts 轻松画容量条与取证雷达图 | **良好**：内置 `egui_plot` 与丰富调试控件，布局极其紧凑高效 | **中**：基础控件齐全，但复杂表格、树形容器结构需较多自定义代码 | **良**：可直接使用 HTML/CSS 生态，但第三方 JS 图表集成略绕 | **中偏弱**：动态不定长列表（如批量队列、多检测器表）编写较繁琐 |
| **空闲资源占用** | 内存 ~60–120 MB（含 WebView 进程），空闲 CPU 0% | 内存 **~25–45 MB**，响应式重绘模式下空闲 CPU < 0.5% | 内存 **~30–50 MB**，纯事件驱动空闲 CPU 0% | 内存 ~60–110 MB（含 WebView），空闲 CPU 0% | 内存 **~20–35 MB**，空闲 CPU 0% |
| **AI 辅助编码友好度** | **最高**：LLM 对 Tauri v2 + React + Tailwind 的生成准确率接近 100% | **高**：代码集中、无跨文件模板，AI 很容易一次性写对逻辑 | **中**：0.12 -> 0.13/0.14 API 演进较大，AI 偶有旧版 API 混用 | **中**：0.5 -> 0.6/0.7 宏与 Signal 语法演进快，需锁定版本提示词 | **中偏低**：专用 `.slint` 语法语料较少 |

---

## 三、 各备选方案深度剖析与优缺点评价

### 方案一：[Tauri v2](https://v2.tauri.app/) + React 19 / Vue 3 (TypeScript) + Tailwind CSS / shadcn-ui
> **推荐度：⭐⭐⭐⭐⭐（9.5 / 10）—— 最适合打造商业级/开源标杆级 `strhide` 桌面客户端**

* **为什么它最契合现在的 `strhide`？**
  我们在 Stage A–E 中专门为 `strhide` 打造的 **`ErrorDetail` (`ErrorKind` + `Msg::id()`)、`ReadSummary`（64 KiB 文本预览截断防爆 IPC）、`StegoEmbedResult`、`DualInspect` (`#[serde(flatten)]`)、`StrategyCapacity` 以及 `FileTarget`**，天然就是为 Tauri v2 的 `#[tauri::command]` 和 `tauri::ipc::Channel<Event>` 量身定做的！后端胶水层只需不到 300 行代码即可把整个 `StrHide` 门面暴露给前端。
* **核心优势**：
  1. **开箱即用的全格式媒体预览**：拖入 MP4/MOV 视频或 PNG/JPEG/WAV，前端直接用 `convertFileSrc(path)` 喂给 `<video>` / `<img>` / `<audio>` 标签即可流畅预览，支持嵌入前后双画面同步播放对比。
  2. **极致的视觉与交互体验**：
     - **容量水位尺（Capacity Meter）**：当用户选择载荷文件或输入文本时，前端实时计算字节数，在进度条上同时画出 `Paranoid (0.06 bpp)`、`High (0.10 bpp)`、`Balanced (0.15 bpp)` 三条安全刻度线，超过推荐值自动变黄（Advisory）或变红（Enforced）。
     - **反隐写取证仪表盘（Steganalysis Dashboard）**：调用 `engine.analysis().scan_file` 后，用可视化的风险仪表盘（`0..10`）和彩色标签展示 `dct:calibration`、`spatial:rs`、`png:trailing-data` 等检测器结果。
  3. **开发与迭代速度最快**：无论是你自己写还是交给 AI Agent 实施，React + Tailwind + shadcn/ui 都能在 1–2 天内产出极为精美的深浅色自适应界面与中英双语界面。
* **主要缺点与规避办法**：
  - **缺点 1**：需要 Node.js / pnpm 前端构建环境，编译产物依赖操作系统的 WebView（Windows 10/11 自带 WebView2，macOS 自带 WKWebView，Linux 需 `webkit2gtk`）。
  - **缺点 2**：Windows 下如果前端 `<video src="...">` 正在预览 `video.mp4`，此时用户点击“原地覆盖（In-place Embed）”，WebView2 可能会锁住文件句柄。
    - *规避办法*：① 前端在触发原地写入 Command 前先将 `<video>` 的 `src` 置空释放句柄；② 后端 Stage C/E 已实现的 `rename_with_retry` + `ErrorKind::TargetBusy` 会自动重试并给出友好提示。

---

### 方案二：[egui](https://github.com/emilk/egui) (`eframe`) 纯 Rust 即时模式 GUI
> **推荐度：⭐⭐⭐⭐☆（8.8 / 10）—— 最适合打造“单文件绿色便携版”或“安全研究人员/极客取证工作台”**

* **为什么值得强烈考虑？**
  如果你希望整个项目保持 **100% 纯 Rust 血统**，不需要 `package.json`、不需要 `node_modules`，任何人 `git clone` 后只需一行 `cargo run -p strhide-gui --release` 就能跑起来，且编译出一个 **无任何外部依赖的单一可执行文件（`strhide-gui.exe`）**，那么 [egui](https://github.com/emilk/egui) 是纯 Rust 生态中最成熟、开发最爽快的选择。
* **核心优势**：
  1. **零 IPC、零序列化、内存直通**：UI 线程与工作线程共享同一个 Rust 进程地址空间。`DualInspect`、`ReadResult`、`ScanReport` 直接通过 `std::sync::mpsc::channel` 传递所有权，连 `ReadSummary` 的 64 KiB 截断都不需要。
  2. **独一无二的“像素/DCT 隐写修改热力图（Diff Heatmap）”能力**：
     - 在 `egui` 中，你可以直接读取嵌入前后的 `RawImage` 像素缓冲区（或 JPEG DCT 系数块），在 Rust 内存中以零拷贝方式生成一张 **“隐写修改位置高亮图层（将 `±1` 修改的像素渲染为亮绿色/亮红色）”**，直接上传为 GPU Texture，支持滚轮无级缩放查看 HILL / S-UNIWARD 算法是如何精准避开平滑天空区域、只修改复杂纹理边缘的！这对隐写工具来说是极具杀伤力的专业特性。
  3. **进度与取消对接极简**：即时模式每帧直接读取 `CancelToken` 与原子进度，无需编写复杂的事件订阅状态机。
* **主要缺点与规避办法**：
  - **缺点 1**：无法直接内嵌播放 MP4/HEVC 视频（只能展示 `MediaInfo` 分辨率/帧率/时长信息，或点击按钮调用系统默认播放器 `open::that(path)` 打开）。
  - **缺点 2**：默认外观偏工业调试器风格，且默认不含中文字体。
    - *规避办法*：启动时通过 `FontDefinitions` 直接加载系统自带的中文字体（Windows 微软雅黑 `msyh.ttc` / macOS 苹方 `PingFang.ttc` / Linux Noto Sans CJK），无需将十几 MB 字体打包进二进制；并配置圆角、留白与现代配色主题（如 Catppuccin / Tokyo Night）。

---

### 方案三：[Iced](https://github.com/iced-rs/iced) (0.13 / 0.14) 纯 Rust Elm 架构 GUI
> **推荐度：⭐⭐⭐⭐（8.2 / 10）—— 适合偏爱严格状态机与传统原生桌面观感的纯 Rust 开发者**

* **核心优势**：
  1. **纯正的保留模式（Retained Mode）与 Elm 架构**：通过 `State`、`Message`、`update()`、`view()` 严格分离状态与视图，没有即时模式的每帧布局开销，窗口静止时 CPU/GPU 占用严格为 0%。
  2. **原生异步任务支持**：`iced::Task`（原 `Command`）与 `Subscription` 可以很干净地包装 `strhide` 的后台线程池任务。
* **主要缺点**：
  - `strhide` 的参数面板非常丰富（结构域有策略选择、加密、Stealth、密码提示、时间戳保留；内容域有安全档位、强制模式、PNG/JPEG/HEVC 各自的高级算法参数）。在 Iced 中，每一个输入框、下拉框、复选框都必须定义一个 `Message` 枚举变体并在 `update` 中匹配，样板代码量大约是 `egui` 或 `Tauri` 的 2–3 倍。
  - 同样不支持内置 MP4 视频播放。

---

### 方案四：[Dioxus Desktop](https://dioxuslabs.com/) (0.6 / 0.7)
> **推荐度：⭐⭐⭐☆（7.5 / 10）—— 适合“想要 WebView 的多媒体与 CSS 颜值，但死活不想写 TypeScript/JS”的场景**

* **核心优势**：
  - 底层和 Tauri 一样使用 `tao` + `wry`（系统 WebView），因此**天然支持 `<video>` 播放 MP4 和 Tailwind CSS 样式**；
  - 但前端逻辑全部运行在 **同一个 Rust 进程** 中，用 `rsx! { div { ... } }` 编写组件，点击按钮直接 `spawn_blocking` 调用 `StrHide`，**完全省去了 Tauri 的前后端 IPC 桥接层**。
* **主要缺点**：
  - 仍然需要写 HTML/CSS 类名；且当你需要现成的高级 UI 组件（如虚拟滚动表格、复杂图表、分屏对比滑块）时，无法像 React/Vue 那样直接 `npm install` 现成组件库，生态丰富度弱于方案一。

---

### 方案五：[Slint](https://slint.rs/) (`slint-ui`)
> **推荐度：⭐⭐⭐（7.0 / 10）—— 适合超轻量固定布局工具，不太适合复杂动态数据与多媒体取证**

* **核心优势**：内存占用极低（~20 MB），`.slint` 声明式语法清晰，编译出的原生界面干净利落。
* **主要缺点**：
  1. 动态数据结构（如 `DualInspect` 的多层可选嵌套字段、`ScanReport` 的不定长 `detectors` 列表）需要繁琐地映射为 `slint::ModelRc<slint::SharedString>` 等桥接类型，无法直接复用 Rust 结构体。
  2. 开源协议为 GPLv3 / 商业授权 / Ambassador 计划（虽然开源项目可用，但不如 MIT/Apache-2.0 的 Tauri/egui/Iced 自由）。

---

## 四、 终极选型建议与“双轨架构”落地方案

结合 `strhide` 现有的代码结构（Cargo Workspace 在 `rust/` 下），我最推荐采用 **“以方案一（Tauri v2）或方案二（egui）择一为主力”** 的策略：

* **如果你希望做出一款颜值出众、支持视频/图片直接预览、交互现代、且能让 AI Agent 在最短时间内高质量写完 UI 的主流桌面软件** 👉 **果断选【方案一：Tauri v2 + React (TS) + Tailwind/shadcn-ui】**。
* **如果你希望整个仓库保持 100% 纯 Rust、`cargo build --release` 直接产出一个几 MB 的单文件 `.exe` 随身携带，且想做“像素级隐写修改热力图放大镜”** 👉 **果断选【方案二：egui (`eframe`)】**。

> 💡 **架构彩蛋**：由于我们在 Stage A–E 已经把所有业务逻辑都收敛进了 `strhide` 库门面（`StrHide`），你甚至可以在 `rust/` 下建立 Cargo Workspace，将 GUI 拆成独立 crate（例如 `gui-egui` 或 `src-tauri`），核心库 `strhide` 一行代码都不用再动！

---

## 五、 `strhide` GUI 四大核心工作台（视图层）功能设计规范

无论最终拍板 **方案一（Tauri v2）** 还是 **方案二（egui）**，GUI 界面都建议围绕 `strhide` 的核心能力设计为以下 **4 个主标签页（Tabs）+ 1 个全局拖入区**：

### 1. 🔍 检视与提取工作台（Inspect & Smart Extract）—— *默认首页*
* **交互流**：
  1. 用户拖入任意文件（或文件夹）→ 立即在后台触发 `engine.inspect_any(path, &DualOptions)`。
  2. **顶部媒体信息栏**：展示格式图标（`FileFormat`）、文件大小，以及 `MediaInfo`（如 `1920×1080, 29.97 fps, 13.6s`）和媒体缩略图/视频预览。
  3. **双域状态双卡片**：
     - **左卡（结构域 Structure Domain）**：展示 `has_hidden_data`、策略名称（`StrategyId`，如 `png_chunk` / `pe_codebits`）、偏移量、是否加密、是否 Stealth 隐身、密码提示（`password_hint`）以及解密出的 `CarrierMetadata`（原始文件名、大小、SHA-256、创建时间）。若未检出但 `suspicious_hints` 非空，高亮弹出黄色警示条：“检测到可疑隐身信封结构（如私有块），请尝试输入密码重检”。
     - **右卡（内容域 Content Stego Domain）**：展示 `StegoHeaderInfo`（算法如 `HILL` / `UERD` / `HEVC-CABAC-InPlace`、编码器如 `STC (h=7, u=2)`、密文长度与载荷长度）。
  4. **一键智能提取栏（Smart Extract）**：
     - 密码输入框（若检出 `password_hint` 自动作为 placeholder 提示）+ “一键提取”按钮（调用 `engine.smart_extract`）。
     - 若返回 `also_present: Some(other_domain)`，弹出醒目提示：“该载体同时包含结构域与内容域两份隐藏数据！提供切换按钮分别导出”。
     - 若提取出的载荷为文本（`ReadSummary.text_preview` 存在），直接在界面右侧代码框内高亮预览并提供“一键复制”；若为文件则弹出保存路径。

### 2. 🛡️ 隐藏与嵌入工作台（Hide / Embed）
* **交互流**：
  1. **模式切换器（Segmented Control）**：
     - **模式 A：内容域自适应隐写（Content Stego，`engine.stego().embed_file`）** —— *当拖入 PNG / JPEG / HEIC / MP4 时默认推荐*，特点是抗压缩/重编码分析、MP4 零体积膨胀（Δ = 0）。
     - **模式 B：结构域容器注入（Structure Write，`engine.structure().write_file`）** —— *当拖入 ZIP / PDF / PE / MKV / WAV 或超大载荷时自动切换*，特点是流式极速、支持 100% 字节级无损还原。
  2. **实时容量水位尺（Live Capacity Bar）**：
     - 拖入载体后后台自动跑一次 `engine.stego().probe_file`（MP4 默认走 20% 采样亚秒级返回，提供“精确全扫 `exact`”勾选框）或读取 `InspectResult.strategies`。
     - 当用户在下方输入文本或选择载荷文件时，实时计算 `payload_bytes / recommended_max_bytes` 百分比，并在容量条上标出 `Paranoid` / `High` / `Balanced` 三档水位线。
  3. **高级参数抽屉（Collapsible Tuning Drawer）**：
     - 内容域：安全档位（`SafetyLevel`）、超限阻断开关（`SafetyEnforcement`）、算法选择（PNG: `HILL`/`S-UNIWARD`；JPEG: `UERD`/`J-UNIWARD`；HEVC: `Auto`/`Cabac`）及 `no_filename` 匿名微头开关。
     - 结构域：策略下拉框（绑定 `StrategyChoice`：从 `InspectResult.strategies` 动态加载可用策略并显示每个策略的容量上限 `limit`）、`stealth` 隐身开关、密码提示 `hint`。
  4. **输出目标与结果反馈**：
     - 绑定 `FileTarget`（另存为 `-out` vs. 原地覆盖、保留 `.bak` 备份、克隆原始时间戳 `preserve_time`）。
     - 嵌入完成后展示耗时、文件体积变化（`carrier_before_bytes` → `carrier_after_bytes`）以及 **`EmbedStats` 修改率微章**（如 `已微调 1,420 / 2,073,600 候选槽位 (0.068%)`）。

### 3. ✅ 校验与无损还原工作台（Verify & Restore）
* **交互流**：
  1. **三级完整性诊断（3-Tier Verification Stepper）**：
     - 调用 `engine.verify_any`（或分别调用结构域 `verify_file` 与内容域 `verify_file`），用三步状态指示灯直观展示：
       - **Level 1（宿主容器结构）**：PNG CRC / ZIP EOCD / PE Header / JPEG DHT / HEVC Bitstream 是否合法；
       - **Level 2（隐写信封/微头）**：UBE 头尾 Magic 与 CRC / Stego Superblock 是否完整；
       - **Level 3（加密认证与完整性）**：AEAD Tag 认证与有效载荷 SHA-256 / CRC32 是否 100% 匹配。
  2. **结构域一键 100% 还原（Bit-for-Bit Restore）**：
     - 调用 `engine.structure().restore_file`，展示还原后的文件大小与原始 SHA-256 绿勾对比；
     - 若捕获 `ErrorKind::RestoreMismatch` 且 `residual_envelope == true`，直观提示用户：“该文件包含多层嵌套信封，请按后进先出顺序依次还原”。

### 4. 🔬 反隐写取证与批量队列工作台（Steganalysis & Batch Queue）
* **交互流**：
  1. **黑盒反隐写扫描器（Steganalysis）**：
     - 调用 `engine.analysis().scan_file`，顶部展示 `0..10` 风险评分仪表盘与结论标签（`clean` / `low` / `suspicious` / `likely-hidden`）；
     - 下方表格渲染 `ScanReport.detectors`（按 `signature`、`structural`、`spatial`、`dct` 四大域分组，展示测量值 `metric`、阈值 `threshold` 与 `PASS`/`ALERT` 徽章），并显著展示 `notes` 中的盲区免责说明。
  2. **多文件批量处理中心（Batch Queue）**：
     - 对接 `core::batch::run_batch`，支持一次性拖入几十个载体批量执行 `Inspect`、`Verify`、`Scan`、`Embed` 或 `Extract`；
     - 列表实时展示每个文件的进度、耗时（`elapsed_ms`）与成功/失败详情（点击失败项直接弹出本地化后的 `ErrorDetail`），顶部提供全局“暂停/取消全部（`CancelToken::cancel()`）”按钮。
