# strhide

**智能格式保持、无损数据隐藏工具。** 将文本或文件隐藏到普通宿主文件（PNG、JPEG、WebP、HEIC/HEIF、MP4、WAV、MKV、ZIP、PDF、Windows PE 可执行文件）中，不改变宿主的可见格式、外观和功能，事后可逐比特还原原始宿主文件。

本仓库提供两套实现：

| 实现 | 语言 | 状态 |
| --- | --- | --- |
| [`rust/`](rust/) | Rust (edition 2024) | **主力维护中（0.3.x）**——单文件静态二进制，从源码构建 |
| [`python/`](python/) | Python ≥ 3.10 | **已冻结在 0.2.0，弃用**——`pip install strhide`，库 + CLI |

两个实现的信封格式**互不兼容**：Python 读不了 Rust 的全加密信封与 `pe_slack` / `pe_codebits` 策略载体；Rust 自 2026-10-21 起也**不再读取** 0.2.0 时代的旧信封（旧 ASCII 魔数 `STRHIDE` / `STH!`、JSON 元数据与明文封装已删除）。跨版本迁移请先用 0.3.x 的 Rust 二进制读取并重新写入。

> [English documentation (README.md)](README.md)

## 特性

- **格式保持**——宿主文件仍是合法的 PNG/JPEG/WebP/HEIF/MP4/WAV/MKV/ZIP/PDF/PE，可正常显示、播放或运行。
- **100% 可逆**——信封中嵌入原始宿主的 SHA-256，`read`/`restore` 输出保证与原文件逐比特一致。
- **落盘即加密**——每个信封在写入载体前都经 Deflate 压缩与 AES-256-GCM 加密。不设密码时使用内置密钥，载体中不会泄露明文载荷、宿主哈希或文件名；设置密码则获得真正的密钥分离（PBKDF2-HMAC-SHA256 10 万轮 + HKDF-SHA256，分块 GCM）。
- **隐写模式（Stealth）**——设置密码后，信封签名与头部字段均由密码派生，没有密码就无从发现隐藏数据。即使在默认（非 stealth）模式下也没有静态 ASCII 魔数：不存在 `STRHIDE` / `STH!` 这类字符串，只有高熵二进制签名（旧版 ASCII 魔数已不再被识别）。
- **黑盒隐写分析**——`scan` 把文件视为未知对象，报告来自**任意工具**（不只是 strhide）的结构与统计特征异常；JPEG 额外走**校准式 DCT 检验**（`dct:calibration`），并明确标注 `clean` 不构成「无隐藏数据」的证据。
- **密码提示**——可选（≤ 1 KiB）的提示信息随信封存储，在需要输入密码时展示。
- **默认安全**——完整性/签名拒绝检查会拒绝修改不宜触碰的文件（如签名二进制）；`write`、`restore` 与 `embed` 默认输出至 `<stem>-out.<ext>` 新文件，原始宿主 100% 保持干净；提供显式 `--in-place` 选项进行原地修改（自动创建 `.bak` 备份）；`read`、`extract`、`write` 和 `restore` 默认拒绝覆盖已存在的输出文件（需 `--overwrite` 才允许）；保留原始文件时间戳。
- **TOML 配置**——`./strhide.toml` 或 `~/.strhide/config.toml` 提供默认值，显式命令行参数（`-c, --config`）始终优先（详见注解模板 [`strhide.sample.toml`](strhide.sample.toml)）。
- **批量与递归载体**——`write`、`restore`、`scan`、`inspect`、`verify`、`embed` 均支持一次处理多个文件或目录递归扫描（`-r, --recursive`）；`read` 针对单个载体。
- **内容自适应隐写（HILL & UERD）**——`embed` 与 `extract` 命令直接在图像像素（PNG，按 HILL 成本模型选位）或 DCT 频域系数（JPEG，通过 UERD 成本模型）中嵌入数据。与结构层注入不同，内容隐写修改的是最小失真纹理区，可抵御元数据剥离清洗。像素写入采用**三元 ±1 匹配**：修改被约束在像素所在的八值类内（`val & 0xF8`），因此概率质量会跨值对边界流动，而不是把每个值对压平——后者正是卡方/SPA 检测器攻击的目标。实测：本仓库语料满容量嵌入后自检分数由 50/100（SUSPICIOUS，RS+SPA）降到 25/100（LOW，仅 SPA）。

## 安装

**预编译二进制（推荐，无需 Python 或 Rust 工具链）：**

从 [GitHub Releases](https://github.com/mcxiaoke/strhide/releases/latest) 下载：

| 平台 | 文件 |
| --- | --- |
| Windows x64 | `strhide-windows-x86_64.exe` |
| Windows ARM64 | `strhide-windows-aarch64.exe` |
| macOS（Intel + Apple Silicon） | `strhide-macos-universal2` |
| Linux x64（全静态） | `strhide-linux-x86_64` |
| Linux ARM64（全静态） | `strhide-linux-aarch64` |

```bash
chmod +x strhide-macos-universal2          # macOS / Linux
./strhide-macos-universal2 --help
sha256sum -c SHA256SUMS.txt                # 校验下载文件
```

> **macOS（未公证）：** Gatekeeper 会拦截未公证的下载二进制。可右键文件 → **打开**，或执行 `xattr -d com.apple.quarantine ./strhide-macos-universal2`。
>
> **Windows：** SmartScreen 可能提示未签名程序——选择 **更多信息 → 仍要运行**。

**Python（已弃用，冻结在 0.2.0）：**

```bash
pip install strhide
```

**从源码构建：**

```bash
cd rust
cargo build --release
# 产物位于 target/release/strhide
```

## 命令行快速上手

```bash
# 在图片中隐藏文本（默认写入 photo-out.png，原始 photo.png 保持未修改）
strhide write photo.png -t "meet me at 7"

# 或显式进行原地写入（修改原图并创建 photo.png.bak 备份）
strhide write photo.png -t "meet me at 7" --in-place

# 通过管道隐藏文本（其他载荷源：-d 文件、--text-file、--text-base64）
cat secret.txt | strhide write image.jpg --stdin

# 隐藏文件，加密并附加密码提示
strhide write report.pdf -d secret.zip -p "S3cret!" -H "my usual one"

# 提取隐藏数据（默认拒绝覆盖已存在文件，需 --overwrite 才允许）
strhide read photo-out.png -o out/
strhide read photo-out.png --stdout

# 黑盒隐写分析：递归扫描文件或整个目录，检测来自任意工具的隐藏内容
# （结构 + 统计特征，不依赖 strhide 内部知识）；支持 --json
strhide scan suspicious.bin ./downloads -r

# 同一份扫描，静默执行并以退出码判定：任一文件被判 "likely-hidden" 则退出码 1，
# 否则 0（suspicious/low 级发现不影响退出码）
strhide scan suspicious.bin ./downloads -r -q

# 查看信封元数据与各策略容量（支持多载体及 -r 递归扫描目录）；支持 --json
strhide inspect report.pdf --json
strhide inspect ./photos -r --json

# 校验宿主与信封完整性（3 级检查，支持多载体与 -r 递归；支持 --json）
strhide verify report.pdf ./photos -r

# 移除隐藏数据，还原原始宿主文件（默认输出为 <carrier>-out.<ext>）
strhide restore photo-out.png -o restored.png
# 或原地还原载体：
strhide restore photo.png --in-place

# --- 内容自适应像素/DCT隐写（免疫第三方元数据与chunk清洗）---

# 探测图片的最大安全隐写容量（不修改原图）
strhide embed photo.png --capacity

# 将文本或文件嵌入复杂高频纹理中（PNG 默认 HILL，JPEG 默认 UERD）
strhide embed photo.png -t "机密信息" -p "P@ss123" -o stego.png
strhide embed cover.jpg -d secret.zip -p "P@ss123" --in-place

# 提取内容自适应隐藏数据（支持 --stdout 与 --overwrite 防护）
strhide extract stego.png -p "P@ss123" --stdout
strhide extract stego.jpg -p "P@ss123" -o recovered.zip --overwrite

# 批量：把同一份载荷写入多个载体（输出到目录或默认各自输出为 <stem>-out.<ext>），再批量还原
strhide write a.png b.png c.png -t "meet me at 7" -o done/
strhide restore done/a.png done/b.png done/c.png -o restored/

# 列出全部格式、策略及其容量上限（支持 --json 格式化输出）
strhide list --json
```

密码来源（按顺序检查）：`-p/--password` → `--password-file` → 环境变量 `STRHIDE_PASSWORD` → 配置文件 → 交互式输入（`-e/--encrypt`）。`-p` 与 `--password-file` 互斥。

`write` 的载荷源同样互斥：`-d/--data`、`-t/--text`、`--text-file`、`--text-base64`、`--stdin` 不可同时使用。都不提供时，环境变量 `STRHIDE_TEXT` 作为最后兜底。

> **安全提示**：通过 `-p` 传入的密码可能经 shell 历史和进程列表泄露，建议优先使用 `--password-file`、`STRHIDE_PASSWORD` 或交互式输入。

## Python API

> **弃用说明（2026-10-18）**：纯 Python 实现冻结在 **0.2.0**，不再新增功能。请使用预编译的 Rust 二进制以获得完整能力。特别是 Python **未实现** `pe_slack` / `pe_codebits` PE 策略，且早于 Rust 默认的全加密信封（内置密钥模式），因此读不了当前 Rust 写入的载体。Python 包仍保留给现有用户及读取 0.2.0 时代的旧文件。

```python
from strhide import write_carrier, read_carrier, inspect_carrier

# 在载体中隐藏文本（默认原地写入 carrier.png）
result = write_carrier("carrier.png", data_text="hello", password="pw")

# 再次提取
result = read_carrier("carrier.png", output_path="restored.txt", password="pw")

# 只读元数据，不提取
meta = inspect_carrier("carrier.png", password="pw")
```

所有函数返回结果字典，失败时抛出 `StrHideError` 子类（`RejectionError`、`CorruptedDataError`、`PasswordError`、`UnsupportedFormatError`、`NoHiddenDataError`、`RestoreMismatchError`）。包自带类型注解（`py.typed`）。

## 支持的载体与策略

| 载体 | 识别 | 典型策略 |
| --- | --- | --- |
| PNG | ✓ | IDAT 块之间注入 chunk |
| JPEG | ✓ | APPn 段注入、多段链式 |
| WebP | ✓ | `riff_chunk` 私有 `SHRD` chunk 注入 |
| HEIC / HEIF | ✓ | `box_uuid` 规范 ISO BMFF uuid box 注入 |
| MP4 | ✓ | `box_uuid` free/uuid box 注入 |
| WAV | ✓ | `riff_chunk` 私有 `SHRD` chunk 注入 |
| MKV | ✓ | `ebml_void` 规范 EBML Void 元素注入 |
| ZIP | ✓ | 中央目录之前插入条目 |
| PDF | ✓ | 增量更新 / 对象注入 |
| Windows PE（exe/dll） | ✓ | `pe_slack` 节填充信封（文件尺寸不变）、`pe_codebits` 指令编码信道，或 overlay 数据 |

无法识别的格式将**被拒绝**：strhide 只修改显式支持的载体——向任意文件追加数据可能损坏该文件。`eof` 策略仍作为受支持格式内部的降级选项存在（如超大 PNG 载荷）。

`strhide inspect <文件>` 可查看某载体实际支持的策略及其容量上限；`-s auto`（默认）自动选择，`-s ask` 交互式选择（仅限单个载体）。

### 内容自适应像素/DCT隐写（`embed` / `extract`）

| 隐写域 | 支持格式 | 算法 | 机制特点 |
| --- | --- | --- | --- |
| 空间域 | PNG（RGB/RGBA/灰度） | **HILL**（High-Low-Low）+ 非对称 ±1 | 最小失真 KB 高通 + 双级均值平滑；三元 ±1 写入且不离开像素的八值类，成本图按 `val & 0xF8` 掩码，嵌入/提取槽位排序严格一致 |
| DCT 频域 | JPEG / JPG（基线编码） | **UERD** | 量化表加权能量与近似 8 邻域扩散，通过 `dct-io` 实现无损重编 |

*安全拦截防护*：APNG 动图（`acTL`）、调色板索引图（`PLTE`）、隔行扫描图（Adam7）与渐进式 JPEG（SOF2）会被自动检测并优雅拦截，保护原图功能与外观不受破坏。

*私有方言*：无密码时，信封密钥与头部槽位置换都由源码内的公开常量派生，因此任何 strhide 构建都能读取无密码载体。用 `--stego-secret <SECRET>`（或配置项 `stego_secret`、环境变量 `STRHIDE_STEGO_SECRET`，优先级依次递减）替换该常量即可建立私有方言：写入与提取必须使用同一个值，否则提取报 `NoHiddenData`。该参数属于「读写必须一致」的 P 类参数，应与密码同源保管，不要和调参项混放。

*UERD 的 8 邻域是近似实现*：系数流不带块几何信息，因此邻域在 `ceil(sqrt(块数))` 网格上计算，而非真实图像网格。嵌入端与提取端使用同一套近似，槽位排序仍严格对称，只是代价模型与原论文有偏差。

*矩阵编码层（`--codec`）*：PNG 载荷位默认由 `(7,3)` 汉明矩阵编码放置。`--codec stc` 切换为**综合征网格码**（对整个槽位序列做 Viterbi，`--stc-h 4..10`，默认 8），优化的是**代价加权**失真而非"改了几个槽"。所选 codec 记在载体头部，`extract` 无需任何 flag。本仓库语料 33 KB 不可压缩载荷实测：加权失真 `Σρ` 在两张纹理图上分别降 **408 倍**与 **2.0 倍**，但在接近均匀噪声的图上反升 12%；改动个数稳定上升 **71%**（0.5 vs 0.2917 次/比特）；自检分数从未更差（参考载体 25/100 → **0/100**）；耗时 1.2–1.3 倍。由于 STC 每 bit 只需约 1 个槽而汉明需 2.33 个，其容量上限高 **2.33 倍**——容量探测按真实值报告，但填满会抬高检测面，推荐值仍取上限一半。**默认仍是 Hamming**：改动个数是用户可感知的副作用，且现有 PNG 语料仅 3 张，不足以支撑翻默认。

*自检能看到什么、看不到什么*：`scan` 是筛查工具，不是证据。JPEG 现在走**校准式 DCT 检验**（`dct:calibration`）：解码像素、裁掉 4 px 让 8×8 网格与嵌入网格错半块、用文件自身的量化表重新量化，再把「偶奇配对失衡」与该参照对比。实测 15 张真实载体、不可压缩载荷：干净载体 **0 误报**、**满容量 14/15 检出**、50% 容量 10/15。唯一漏检是 quality-100（量化步长全 1）的载体——这种图校准按设计不适用：对解码像素重新量化时，IDCT 舍入误差与量化步长同量级。**`clean` 结论仍不能当作「没有隐藏数据」的证据**——JPEG 判为 clean/low 时报告会带一条明确的说明。

## 仓库结构

```
strhide/
├── python/     # Python 包（库 + CLI），已发布至 PyPI
├── rust/       # Rust 实现（库 + CLI 二进制）
├── docs/       # 设计文档与变更日志
└── LICENSE     # Apache-2.0
```

## 许可证

[Apache License 2.0](LICENSE)
