# strhide 命令行工具实用指南 (CLI Guide)

`strhide` 是一个智能、格式保持、无损的数据隐藏与隐写工具。本文档面向日常用户、运维工程师和安全分析人员，系统介绍 CLI 的命令体系、常用参数组合与典型应用场景。

---

## 1. 架构与二进制体系

为了兼顾功能完整性与终端输入的敏捷性，工具链编译为 4 个静态二进制入口：

| 二进制命令 | 覆盖子命令范围 | 适用场景 |
| :--- | :--- | :--- |
| `strhide` / `sth` | 包含全部 10 个子命令 | 完整全功能入口，适合日常综合使用 |
| `sthc` | `write`, `read`, `restore` | **结构/容器域 (Container)**：在文件空隙、元数据、尾部或代码段注入信封，支持位精确还原 |
| `sths` | `embed`, `extract`, `capacity` | **媒体隐写域 (Content Stego)**：在图像像素 (HILL/S-UNIWARD)、JPEG DCT 系数 (UERD/J-UNIWARD)、HEVC/H.265 CABAC 码流或音频 PCM 中嵌入载荷，免疫元数据擦除 |
| `sthv` | `inspect`, `verify`, `scan`, `list` | **诊断分析域 (Diagnostics)**：信封解析、完整性核验、黑盒隐写取证与能力查询 |

> **提示**：`sth <COMMAND>` 等价于 `strhide <COMMAND>`。子命令均支持单字母短别名（例如 `sth w` = `write`，`sth e` = `embed`，`sth c` = `capacity`）。

---

## 2. 全局公共参数

所有子命令均共享以下全局控制选项：

| 参数 | 简写 | 说明与用法 |
| :--- | :--- | :--- |
| `--config <FILE>` | `-c` | 指定 TOML 配置文件。未指定时依次检索 `<exe_dir>`、用户配置目录、系统配置目录 |
| `--quiet` | `-q` | 静默模式。隐藏 Banner 与普通信息输出，仅在发生严重错误时输出并退出 |
| `--verbose` | `-v` | 提高诊断日志级别。`-v` 开启 DEBUG 级别，`-vv` 开启 TRACE 级别（输出至 stderr，不污染重定向） |
| `--lang <LANG>` | 无 | 强制界面语言：`zh`（简体中文）或 `en`（英文）。未指定时按系统 Locale 自动检测 |

---

## 3. 载荷输入规范

`write`（容器写入）与 `embed`（隐写嵌入）支持三种互斥的载荷来源：

```bash
# 1. 文件载荷 (-d / --data)：最常用的二进制/大文件输入
sth write carrier.png -d secret.zip -o out.png

# 2. 文本载荷 (-t / --text)：快速隐藏短文本或机密凭据
sth write carrier.png -t "my-secret-token" -o out.png

# 2.1 文本转义 (--unescape)：支持解析 \n, \t, \xHH 等转义字符
sth write carrier.png -t "line1\nline2\x20end" --unescape -o out.png

# 3. 管道流 (--stdin)：标准输入管道串联
cat payload.txt | sth write carrier.png --stdin -o out.png
echo "hello" | sth embed cover.jpg --stdin -o out.jpg
```

---

## 4. 口令与加密规范

| 参数 | 适用场景 | 说明 |
| :--- | :--- | :--- |
| `-p, --password <PWD>` | 命令行快速测试 | 直接明文指定口令（注意避免在多用户主机的 shell 历史中留痕） |
| `--password-file <FILE>` | 生产/CI 自动化脚本 | 从指定文件第一行读取口令，避免进程列表泄漏 |
| `-e, --encrypt` | 交互式终端操作 | 终端交互式弹出提示并进行口令二次确认，安全不留痕 |
| `--key-file <FILE>` | 高安全对称信封（**仅内容域**：`embed`/`extract`/`capacity`/`verify`/`inspect`） | 接受 32 字节原始二进制密钥或 64 字符 Hex 文本，跳过口令 KDF 派生。结构域 `write`/`read`/`restore` 不接受该参数，只支持 `-p` / `--password-file` / `-e`（`rust/src/cli/args.rs:261-270`、`:317`） |
| `-H, --hint <TEXT>` | 容器写入记忆提示 | 存储口令提示信息（`read` 失败时回显；注意 `--stealth` 模式下禁止携带提示） |

---

## 5. 容器/结构域实用指南 (Container Domain)

结构域利用各类格式的规范容许区间（如 PNG Chunk、JPEG APPn、ZIP 注释、PDF 间接对象、PE Slack）存储加密信封，**不改动原始图像像素或音视频编码，并支持 100% 位精确恢复**。

### 5.1 写入隐藏 (`write`)
```bash
# 基础写入新文件
sth write photo.png -t "机密文本" -p "MyPass123" -o photo_stego.png

# 原地写入并生成备份（默认生成 photo.png.bak）
sth write photo.png -t "机密文本" -p "MyPass123" --in-place

# 原地写入且不生成备份
sth write photo.png -t "机密文本" -p "MyPass123" --in-place --no-backup

# 潜行模式 (--stealth)：擦除所有明显魔数与公开特征，无密码探测呈现为纯白噪声
sth write photo.png -d secret.bin -p "StrongPassword" --stealth -o stealth.png

# 指定格式策略 (--strategy)：JPEG 只支持 app_segment 与 eof，强制改走文件尾
sth write photo.jpg -d data.zip -s eof -o out.jpg

# 批量写入：多个载体写入至目标目录
sth write img1.png img2.png -t "批量数据" -o output_dir/
```

> **双域前置检查（写前拒绝）**：`write` 在改动任何字节之前会先探测载体是否**已有**隐藏数据——结构域信封或内容域隐写。命中即报 `Rejection`：“already contains structure/content-domain payload; remove it first (restore/extract) or pass --overwrite”。`--overwrite` 只放行“继续叠加”，不会清除已有信封；且叠加后**结构域的 bit-exact 还原承诺失效**：先 `write` 再 `embed` 时，`restore` 会因宿主 SHA-256 不符而报 `RestoreMismatch`（机制见 `docs/smart_file_data_hiding_design.md` §7）。需要还原原始宿主时，请始终先 `restore` 再做内容域操作。

### 5.2 提取载荷 (`read`)
```bash
# 自动提取：文本直接打印至终端，文件按原文件名存入当前目录
sth read photo_stego.png -p "MyPass123"

# 提取并保存到指定路径
sth read photo_stego.png -p "MyPass123" -o extracted_secret.zip

# 强制将载荷输出至标准输出管道（适合配合 jq 或重定向）
sth read photo_stego.png -p "MyPass123" --stdout > payload.bin

# 智能跨域提取 (--auto)：若未检测到容器隐藏，自动重定向至媒体隐写提取
sth read unknown_stego.png -p "MyPass123" --auto
```

### 5.3 位无损还原 (`restore`)
```bash
# 剥离隐藏信封，将载体严格按原始 SHA-256 位无损恢复
sth restore photo_stego.png -o restored.png

# 原地恢复载体
sth restore photo_stego.png --in-place
```

---

## 6. 媒体隐写域实用指南 (Stego Domain)

媒体隐写域通过自适应代价模型（如 HILL、UERD）将载荷嵌入至载体像素或频域系数中，**完全免疫元数据擦除或容器格式重封装**。

### 6.1 容量探测 (`capacity`)
在嵌入大载荷前，应先通过 `capacity` 探测载体的安全容量上限：
```bash
# 查看图像载体的最大容量报告与推荐安全嵌入量
sth capacity photo.jpg

# 输出机器可读的 JSON 格式
sth capacity photo.jpg --json

# 评估偏执最高安全级别 (paranoid) 下的容量限度
sth capacity photo.jpg --safety paranoid
```

### 6.2 内容隐写嵌入 (`embed`)
```bash
# 基础嵌入（默认采用高安全性算法：PNG 用 HILL，JPEG 用 UERD）
sth embed photo.jpg -t "隐蔽指令" -p "MyPass123" -o photo_embedded.jpg

# 原地嵌入并就地覆盖
sth embed photo.png -d secret.zip -p "MyPass123" --in-place

# 切换算法模型 (-a)：例如换用 S-UNIWARD 或 J-UNIWARD
sth embed photo.png -d secret.bin -a suniward -o out.png
sth embed photo.jpg -d secret.bin -a juniward -o out.jpg

# 指定安全级别与强制门限校验：
# safety 档位：paranoid (极高抗检) | high (默认安全) | balanced (兼顾容量)
# --enforce-safety：若载荷超过当前安全等级限度，立即报错拒绝，防止误产生高风险文件
sth embed photo.jpg -d big.zip --safety high --enforce-safety -o out.jpg

# 匿名化嵌入 (--no-filename)：不在载体内存储载荷的原始文件名
sth embed photo.png -d sensitive.docx --no-filename -o out.png

# 演练模式 (--dry-run)：在内存中完整运行编码与安全评估，不产生磁盘写入
sth embed photo.jpg -d secret.bin --dry-run

# 确定性重现 (--seed)：传入 64 位十六进制种子，生成字节级完全固定的产物（回归测试专用）
sth embed photo.png -t "test" --seed 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -o out.png
```

### 6.3 内容隐写提取 (`extract`)
```bash
# 从载体中提取隐写数据
sth extract photo_embedded.jpg -p "MyPass123"

# 提取并保存到指定输出路径
sth extract photo_embedded.jpg -p "MyPass123" -o recovered.zip

# 管道输出模式
sth extract photo_embedded.jpg -p "MyPass123" --stdout | tar -xzv

# 智能跨域提取 (--auto)：若未检测到媒体隐写，自动重定向至结构域读取
sth extract carrier.png -p "MyPass123" --auto
```

---

## 7. 诊断分析域实用指南 (Diagnostics Domain)

诊断工具均为只读命令，不会对被测文件做任何写入修改。

### 7.1 信封结构检查 (`inspect`)
全面解析载体中是否存在 strhide 信封，输出信封版本、魔数、注入策略、载荷大小及格式信息：
```bash
# 检查单个文件
sth inspect photo_stego.png

# 带口令解析加密信封头
sth inspect photo_stego.png -p "MyPass123"

# 递归检查整个目录并输出 JSON
sth inspect ./suspicious_folder/ -r --json
```

### 7.2 完整性诊断 (`verify`)
深度校验文件完整性、信封签名、AES-GCM/Poly1305 认证标签与原始载体哈希：
```bash
# 校验载体及其信封完整性
sth verify photo_stego.png -p "MyPass123"

# 退出码判定（校验通过返回 0，任一失败返回 1）
sth verify photo_stego.png -q && echo "Carrier intact"
```

### 7.3 黑盒隐写取证与安全扫描 (`scan`)
`scan` 无需口令，针对未知可疑文件执行黑盒统计分析（卡方检验、RS 空间相关性分析、JPEG 标定直方图、畸变特征比对）：
```bash
# 扫描单个文件或目录
sth scan suspect.jpg
sth scan ./incoming_files/ -r

# JSON 格式输出供安全脚本审计
sth scan ./downloads/ -r --json > report.json

# CI / 安全网关门禁 (--fail-on)：当发现可疑文件达到指定级别时直接退出非 0
# 级别可选：low | suspicious | likely
sth scan ./release_assets/ -r --fail-on likely
```

### 7.4 格式与算法清单 (`list`)
列出当前构建版本支持的载体格式、隐藏策略、媒体代价模型与容量上限：
```bash
sth list
sth list --json
```

---

## 8. 自动化与最佳实践

### 8.1 配置文件 (`strhide.toml`)
在可执行文件目录或 `~/.config/strhide/config.toml` 中定义默认偏好，避免重复输入参数：
```toml
# 结构域默认选项
strategy      = "auto"        # 默认注入策略
stealth       = false         # 潜行模式开关
encrypt       = false         # 是否默认要求加密
preserve_time = true          # 保持原始时间戳
backup        = true          # 原地写入时是否创建 .bak 备份
lang          = "zh"          # 界面语言 (zh | en)

# 媒体隐写域默认选项
[stego]
safety         = "high"       # 默认安全级别 (paranoid | high | balanced)
enforce_safety = false        # 是否强校验安全门限
algorithm      = "auto"       # 默认代价模型 (auto | hill | uerd 等)
```

### 8.2 CI / 脚本环境建议
1. **密码传递**：优先使用 `STRHIDE_PASSWORD` 环境变量或 `--password-file`，禁止在 Shell 脚本中明文裸写 `-p`。
2. **安静模式**：在自动化脚本中加上 `-q`，通过退出码判断成败（成功返回 `0`，失败返回非 `0`）。
3. **输出冲突防护**：自动化流程若允许复写，应显式指定 `--overwrite`；就地修改建议显式指定 `--no-backup` 以节省存储。
