# strhide

**智能格式保持、无损数据隐藏工具。** 将文本或文件隐藏到普通宿主文件（PNG、JPEG、MP4、ZIP、PDF、Windows PE 可执行文件）中，不改变宿主的可见格式、外观和功能，事后可逐比特还原原始宿主文件。

本仓库提供两套实现：

| 实现 | 语言 | 状态 |
| --- | --- | --- |
| [`rust/`](rust/) | Rust (edition 2024) | **主力维护中（0.3.x）**——单文件静态二进制，从源码构建 |
| [`python/`](python/) | Python ≥ 3.10 | **已冻结在 0.2.0，弃用**——`pip install strhide`，库 + CLI |

兼容性是**单向**的：Rust 仍可读取旧版 Python 包写入的信封，但 Python 读不了 Rust 新默认的全加密信封，也读不了用 `pe_slack` / `pe_codebits` 策略写入的 PE 载体。请一律使用 Rust 二进制。

> [English documentation (README.md)](README.md)

## 特性

- **格式保持**——宿主文件仍是合法的 PNG/JPEG/MP4/ZIP/PDF/PE，可正常显示或运行。
- **100% 可逆**——信封中嵌入原始宿主的 SHA-256，`read`/`remove` 输出保证与原文件逐比特一致。
- **落盘即加密**——每个信封在写入载体前都经 Deflate 压缩与 AES-256-GCM 加密。不设密码时使用内置密钥，载体中不会泄露明文载荷、宿主哈希或文件名；设置密码则获得真正的密钥分离（PBKDF2-HMAC-SHA256 10 万轮 + HKDF-SHA256，分块 GCM）。
- **隐写模式（Stealth）**——设置密码后，信封签名与头部字段均由密码派生，没有密码就无从发现隐藏数据。即使在默认（非 stealth）模式下也没有静态 ASCII 魔数：不存在 `STRHIDE` / `STH!` 这类字符串，只有高熵二进制签名（读取时仍兼容旧版魔数）。
- **黑盒隐写分析**——`scan` 把文件视为未知对象，报告来自**任意工具**（不只是 strhide）的结构与统计特征异常。
- **密码提示**——可选（≤ 1 KiB）的提示信息随信封存储，在需要输入密码时展示。
- **默认安全**——完整性/签名拒绝检查会拒绝修改不宜触碰的文件（如签名二进制）；`read` 默认拒绝覆盖已存在的输出文件（需 `--overwrite`）；原地写入自动创建 `.bak` 备份；保留原始文件时间戳。
- **TOML 配置**——`./strhide.toml` 或 `~/.strhide/config.toml` 提供默认值，显式命令行参数始终优先。
- **批量载体**——`write`、`remove`、`scan` 可一次处理多个文件（及目录）；`read`/`inspect`/`verify` 只接受单个载体。

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
# 在图片中隐藏文本（原地写入，自动创建 .bak 备份）
strhide write -c photo.png -t "meet me at 7"

# 隐藏文件，加密并附加密码提示
strhide write -c report.pdf -d secret.zip -p "S3cret!" -H "my usual one"

# 提取隐藏数据（默认拒绝覆盖已存在文件，需 --overwrite 才允许）
strhide read -c photo.png -o out/

# 黑盒隐写分析：递归扫描文件或整个目录，检测来自任意工具的隐藏内容
# （结构 + 统计特征，不依赖 strhide 内部知识）；支持 --json
strhide scan -c suspicious.bin ./downloads -r

# 查看信封元数据与各策略容量（隐藏了什么、何时、何种策略、还能再藏多少）；支持 --json
strhide inspect -c report.pdf --json

# 校验宿主与信封完整性（3 级检查，支持 --json）
strhide verify -c report.pdf

# 移除隐藏数据，还原原始宿主文件
strhide remove -c photo.png

# 批量：把同一份载荷分别写入多个载体（带 -o 时写入已存在的目录而非原地改写），再逐个剥离
strhide write -c a.png b.png c.png -t "meet me at 7"
strhide remove -c a.png b.png c.png

# 列出全部格式、策略及其容量上限（静态参考表）
strhide list
```

密码来源（按顺序检查）：`-p/--password` → `--password-file` → 环境变量 `STRHIDE_PASSWORD` → 配置文件 → 交互式输入（`-e/--encrypt`）。

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
| MP4 | ✓ | free/uuid box 注入 |
| ZIP | ✓ | 中央目录之前插入条目 |
| PDF | ✓ | 增量更新 / 对象注入 |
| Windows PE（exe/dll） | ✓ | `pe_slack` 节填充信封（文件尺寸不变）、`pe_codebits` 指令编码信道，或 overlay 数据 |

无法识别的格式将**被拒绝**：strhide 只修改显式支持的载体——向任意文件追加数据可能损坏该文件。`eof` 策略仍作为受支持格式内部的降级选项存在（如超大 PNG 载荷）。

`strhide inspect -c <文件>` 可查看某载体实际支持的策略及其容量上限；`-s auto`（默认）自动选择，`-s ask` 交互式选择（仅限单个载体）。

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
