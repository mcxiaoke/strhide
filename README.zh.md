# strhide

**智能格式保持、无损数据隐藏工具。** 将文本或文件隐藏到普通宿主文件（PNG、JPEG、MP4、ZIP、PDF、Windows PE 可执行文件或任意文件）中，不改变宿主的可见格式、外观和功能，事后可逐比特还原原始宿主文件。

本仓库提供两套完全跨兼容的实现：

| 实现 | 语言 | 分发方式 |
| --- | --- | --- |
| [`python/`](python/) | Python ≥ 3.10 | `pip install strhide` —— 库 + CLI |
| [`rust/`](rust/) | Rust (edition 2024) | 单文件静态二进制，从源码构建 |

两者实现相同的信封（envelope）格式：一方写入的数据可以由另一方读取、校验和清除。

> [English documentation (README.md)](README.md)

## 特性

- **格式保持**——宿主文件仍是合法的 PNG/JPEG/MP4/ZIP/PDF/PE，可正常显示或运行。
- **100% 可逆**——信封中嵌入原始宿主的 SHA-256，`read`/`remove` 输出保证与原文件逐比特一致。
- **强加密（可选）**——PBKDF2-HMAC-SHA256（10 万轮）+ HKDF-SHA256 密钥派生，分块 AES-256-GCM 加密，Deflate 压缩。
- **隐写模式（Stealth）**——设置密码后，信封签名由密码派生并去除静态魔数，没有密码就无从发现隐藏数据。
- **密码提示**——可选（≤ 1 KiB）的提示信息随信封存储，在需要输入密码时展示。
- **默认安全**——完整性/签名拒绝检查会拒绝修改不宜触碰的文件（如签名二进制）；原地写入自动创建 `.bak` 备份；保留原始文件时间戳。
- **TOML 配置**——`./strhide.toml` 或 `~/.strhide/config.toml` 提供默认值，显式命令行参数始终优先。

## 安装

**Python（库 + CLI）：**

```bash
pip install strhide
```

**Rust（CLI）：**

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

# 提取隐藏数据
strhide read -c photo.png -o out/

# 查看信封元数据（隐藏了什么、何时、使用何种策略）
strhide inspect -c report.pdf --json

# 校验宿主与信封完整性（3 级检查，支持 --json）
strhide verify -c report.pdf

# 移除隐藏数据，还原原始宿主文件
strhide remove -c photo.png

# 列出某个载体支持的隐藏策略
strhide list -c report.pdf
```

密码来源（按顺序检查）：`-p/--password` → `--password-file` → 环境变量 `STRHIDE_PASSWORD` → 配置文件 → 交互式输入（`-e/--encrypt`）。

> **安全提示**：通过 `-p` 传入的密码可能经 shell 历史和进程列表泄露，建议优先使用 `--password-file`、`STRHIDE_PASSWORD` 或交互式输入。

## Python API

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
| Windows PE（exe/dll） | ✓ | `pe_codebits` 指令编码信道（文件尺寸不变）或 overlay 数据 |

无法识别的格式将**被拒绝**：strhide 只修改显式支持的载体——向任意文件追加数据可能损坏该文件。`eof` 策略仍作为受支持格式内部的降级选项存在（如超大 PNG 载荷）。

`strhide list -c <文件>` 可查看某载体实际支持的策略；`-s auto`（默认）自动选择，`-s ask` 交互式选择。

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
