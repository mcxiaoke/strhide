# 智能多格式无损数据隐藏命令行工具（strhide）技术实现规范

> 版本：v2.2 ｜ 状态：已正式实施（Python 原型全量交付，Go 移植就绪） ｜ 范围：核心协议规范、适配器算法、抗干扰与跨平台调用标准

---

## 1. 规范范围、核心定位与可行性边界

### 1.1 工具核心定位
本工具（`strhide`）定位为**“宿主功能保全型结构化数据容器（Function-Preserving Container Hiding）”**。
* **专注于**：利用常见文件格式本身的物理结构规则（扩展块、保留区、中央目录间隙、尾部附加区），在**100% 保持宿主原有功能可用**的前提下，无损隐藏任意文本或二进制数据。
* **非目标（明确不可行/过度工程化舍弃）**：
  * **不做像素域/频域 LSB 隐写**：LSB 容量微小（仅占宿主千分之几）、极易在转码/压缩时损毁，且实现与提取极为脆弱。
  * **不承诺对抗国家级数字取证分析**：在容器结构层面藏入数据，任何深入到字节码分析的取证工具（如 `binwalk`、格式解析器）必然能发现文件尺寸异常或未注册的扩展块。硬做全盘盲区隐写会导致定位极其低效且极度容易损坏文件。
* **已落地的低特征模式（--stealth 去特征化规范）**：
  * **去特征化/防静态特征码扫描**：彻底移除明文字符串魔数（如 `‰STRHIDE`、`STH!`），将头部与尾部签名替换为基于用户密码与固定域分离盐（`b"strhide-stealth-v1"`）派生的动态鉴权指纹，避免被简单的 `strings` 命令或静态 YARA 规则识别。

---

## 2. 严格安全拦截机制（禁止修改的文件矩阵）

任何带完整性校验、数字签名或自校验机制的文件，注入后必然导致校验失败。系统秉持 **Fail-Safe by Default（遇险则避）** 原则，在进入任何操作前执行强制探测，一旦命中直接拒绝并提示：

| 文件类别 | 触发条件 / 判定依据 | 终端提示信息与处理行为 |
| :--- | :--- | :--- |
| **已签名 Windows PE** (`.exe`, `.dll`, `.sys`) | `OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]` 的 `VirtualAddress != 0` 且 `Size != 0` | `[ERROR] 拒绝操作：目标 PE 文件包含 Authenticode 数字签名。修改将导致签名失效，已被系统安全拦截。` |
| **Android APK 包** (`.apk`) | 扩展名为 `.apk` 或匹配 ZIP 归档结构且为 Android 安装包 | `[ERROR] 拒绝操作：APK 格式不在支持列表中（不支持作为载体文件进行修改）。直接拒绝，零额外开销。` |
| **已签名 PDF 文档** (`.pdf`) | 交叉引用表或文档对象中包含 `/ByteRange` 且带有 `/Type /Sig` 签名字典 | `[ERROR] 拒绝操作：目标 PDF 包含数字电子签名。结构修改会导致阅读器提示“证书无效或文档已被篡改”。` |
| **已签名 Java 归档** (`.jar`, `.war`) | 归档内 `META-INF/` 目录下存在 `*.SF`、`*.RSA`、`*.DSA` 签名清单文件 | `[ERROR] 拒绝操作：目标 JAR 文件包含签名清单（META-INF/*.SF）。修改归档内容会导致 JVM 运行时拒绝加载。` |
| **独立数字签名文件** (`.sig`, `.asc`, `.p7s`) | 匹配 PGP/GPG 二进制头或 Armor 文本签名头 | `[ERROR] 拒绝操作：目标文件本身为数字签名文件，不支持作为宿主。` |
| **只读属性 / 无写权限** | 文件属性为只读，或所在目录缺乏写入/重命名权限 | `[ERROR] 拒绝操作：缺乏写入权限，无法安全执行原子写入与替换。` |

---

## 3. 格式底层二进制深水区与容错算法

针对现实中非标准文件的各类缺陷，适配器必须具备以下精准容错能力：

### 3.1 PNG 尾部脏数据（Trailing Garbage）容错定位
* **现实陷阱**：很多经第三方编辑器导出的 PNG，在 `IEND` 块（12 字节）之后常常伴随未对齐的 0 字节填充、缩略图或厂商私有标记。若单纯 `seek(-12)` 判定 IEND，必然误判报错。
* **实现方案**：
  1. 适配器从文件尾部向前建立 4KB 滑动缓冲区倒序寻找 `49 45 4E 44`（ASCII `"IEND"`）。
  2. 验证 `IEND` 前 4 字节为 `00 00 00 00`（Length=0），后 4 字节为标准 CRC `AE 42 60 82`。
  3. 确认后，将 UBE 信封严格插入在 `IEND` 块之前，并将原本尾随在 `IEND` 后的任何脏数据原样移动到最末尾保存。

### 3.2 JPEG 标记扫描与假标记（False Marker）跳跃
* **现实陷阱**：JPEG 的图像数据流（`SOS` 之后）是高熵压缩区，可能随机出现 `FF D9`。单纯字符串搜索会导致过早截断。
* **实现方案**：适配器必须严格按 Marker 链顺序跳跃（解析每个段的 2 字节长度），抵达 `SOS`（`FF DA`）后，通过扫描排除字节填充（`FF 00`）与重启标记（`RSTm`），唯有匹配到真正的 `FF D9`（EOI）才作为数据注入边界。

### 3.3 MP4 绝对偏移保护与 64 位大尺寸支持
* **实现方案**：严格仅在 MP4 末尾追加顶层 64 位 `uuid` Box，绝不在 `moov`/`mdat` 前后插入，避免 `stco`/`co64` 帧偏移表失效。

### 3.4 ZIP 家族双模自适应与 EOCD 修正
* **实现方案**：
  * 小数据（`≤ 60KB`）：直接注入 EOCD 注释区。
  * 大数据（`> 60KB`）：采用 `pre_cd_inject` 策略。在中央目录（Central Directory）前插入信封，并把 EOCD（以及存在时的 ZIP64 EOCD）中的 `CD_Offset` 加上注入尺寸，保证所有解压工具与 Office 软件零警告打开。

---

## 4. 全量原始文件指纹与 100% 无损 Remove 还原协议

用户对工具最基本也是最高的要求是：**一旦执行 remove（strip）剥离隐藏数据，宿主文件必须逐字节 100% 还原为操作前的原始状态，不能有哪怕 1 比特的偏差**。

为此，系统建立“**还原元数据自闭环**”机制，将还原所需的所有关键参数固化记录在信封头中：

### 4.1 固定头部记录的还原凭证（Recovery Credentials）
信封固定头部（前 80 字节）强制包含：
1. `orig_host_size`（8 Bytes, uint64）：操作前原始宿主文件的**精确字节总数**。
2. `orig_host_sha256`（32 Bytes）：操作前原始宿主文件的**全量完整 SHA-256 指纹**（流式计算整文件，绝非局部取样）。
3. `inject_offset`（8 Bytes, uint64）：在原始宿主哪个精确字节偏移处切开插入了数据。
4. `inject_size`（8 Bytes, uint64）：插入的总字节数（外层容器扩展块 + UBE 信封总长）。
5. `patch_offset`（4 Bytes, uint32）：宿主头部被修改的字段偏移（如 RIFF 总大小字段、ZIP CD 偏移字段；无修改则为 0）。
6. `orig_patch_val`（4 Bytes, uint32）：该被修改字段在注入前的原始 32 位整数值（无修改则为 0）。

### 4.2 各格式 100% 无损还原（Remove）执行机制

```
[用户触发 strhide remove <carrier>]
                 |
                 v
[定位 UBE 信封，读取 80B 头部还原凭证]
                 |
                 v
[根据 strategy_id 执行精确逆向物理回滚]
  |-- 策略 A (尾部追加型: EOF, PE Overlay, MP4 uuid):
  |     直接调用 truncate(orig_host_size)
  |
  |-- 策略 B (中间切入型: PNG Chunk):
  |     移除 [inject_offset : inject_offset + inject_size] 的字节
  |     将后续的 IEND 块及脏数据整体前移贴合
  |
  |-- 策略 C (带头字段修正型: ZIP Pre-CD, WebP/WAV RIFF):
  |     移除插入数据块，后续内容前移
  |     将 patch_offset 处的 4 字节恢复为 orig_patch_val
                 |
                 v
[计算还原后文件的全量 SHA-256]
                 |
                 +---> 校验: SHA-256 == orig_host_sha256 ?
                           |-- 是 (100% 吻合) -> 原子写入替换原文件，提示还原成功
                           |-- 否 (存在偏差) -> 立即中止并保留临时文件，报错拒绝覆盖！
```

通过这一套“**逆向切片拼接 + 原始补丁写回 + 全量 SHA-256 强校验**”流程，从数学和工程上绝对确保文件 100% 恢复如初。

---

## 5. 极简统一二进制信封协议（UBE v2.2 规范）

协议所有数值统一采用**小端序（Little-Endian）**编码：

```
+--------------------------------------------------------------------------------+
| 1. 固定头部 (Fixed Header, 108 Bytes)                                          |
|    - 前 80 字节为不可变鉴权区 (Immutable AAD) - 强绑定 AES-256-GCM 完整性认证   |
|    - 后 28 字节为注入偏移与元数据尺寸 (Mutable Offsets & MetaLen)                 |
+--------------------------------------------------------------------------------+
| 2. 加密元数据块 (Metadata Block, 变长 JSON, 密文含 16B GCM Tag)                 |
+--------------------------------------------------------------------------------+
| 3. 加密数据载荷流 (Payload Stream, 2MB 分块流式 AEAD, 每块含 16B GCM Tag)        |
+--------------------------------------------------------------------------------+
| 4. 通用定位尾标 (Universal Locator Trailer, 24 Bytes) - 自带 CRC32 与双向校验   |
+--------------------------------------------------------------------------------+
```

### 5.1 108 字节固定头部（Fixed Header）字段定义

固定头部共 108 字节，其中**前 80 字节**定义为不可变 AAD（`get_aad()` 返回该切片），参与后续所有元数据与载荷分块的 AEAD 密码学强绑定鉴权：

| 偏移 | 字段名 | 长度 | 类型 | 取值与详细说明 |
| :--- | :--- | :--- | :--- | :--- |
| `0x00` | `magic_header` | 8B | `bytes` | 标准模式：`89 53 54 52 48 49 44 45`（`‰STRHIDE`）；<br>隐蔽模式（`--stealth`）：`HMAC-SHA256("strhide-stealth-v1", password)[:8]` 动态魔数 |
| `0x08` | `version` | 1B | `uint8` | 协议版本号，当前固定为 `0x02` |
| `0x09` | `flags` | 1B | `uint8` | `bit 0`: 是否加密 (`0`=明文, `1`=加密)<br>`bit 1`: 是否压缩 (`0`=无, `1`=Deflate)<br>`bit 2`: 载荷类型 (`0`=文本, `1`=文件)<br>`bit 3`: 隐蔽模式 (`0`=普通, `1`=Stealth)<br>`bit 4..7`: 保留填 `0` |
| `0x0A` | `strategy_id` | 1B | `uint8` | 写入策略编号（`1`=EOF, `2`=PNG_CHUNK, `3`=MP4_UUID, `4`=ZIP_PRE_CD, `5`=JPEG_APP 等） |
| `0x0B` | `reserved` | 1B | `uint8` | 对齐保留，填 `0x00` |
| `0x0C` | `salt` | 16B | `bytes` | CSPRNG 生成的 128 位随机盐（明文模式填 `0`） |
| `0x1C` | `base_nonce` | 12B | `bytes` | CSPRNG 生成的 96 位随机 Nonce 基础值 |
| `0x28` | `orig_host_size`| 8B | `uint64`| 原始宿主文件的精确字节大小 |
| `0x30` | `orig_host_sha256`| 32B| `bytes` | **原始宿主全量 SHA-256 指纹**，用于 `remove` 100% 一致性强校验 |
| *(以上前 80 字节)* | *(Immutable AAD)* | | | *(作为 AES-GCM Additional Authenticated Data 参与鉴权)* |
| `0x50` | `inject_offset`| 8B | `uint64`| 宿主数据被切开插入的绝对字节偏移 |
| `0x58` | `inject_size` | 8B | `uint64`| 实际向宿主注入的总字节数（包装器 + 信封） |
| `0x60` | `patch_offset` | 4B | `uint32`| 宿主头部被修改的字段偏移量（无修改填 0） |
| `0x64` | `orig_patch_val`| 4B | `uint32`| 被修改字段在注入前的原始 32 位值（无修改填 0） |
| `0x68` | `meta_len` | 4B | `uint32`| 加密后的元数据块长度（含 16B Tag） |
| `0x6C` | `padding` | 4B | `uint32`| 64 位对齐保留填 0 |

### 5.2 24 字节定位尾标（Locator Trailer）
位于 UBE 信封最末端，提供常数级 O(1) 逆向定位与防损坏检测：
* `ube_offset`（8 Bytes, uint64）：信封在宿主文件中的起始绝对偏移。
* `ube_total_size`（8 Bytes, uint64）：从 `magic_header` 到尾标结束的总长度。
* `trailer_crc32`（4 Bytes, uint32）：前 16 字节（`ube_offset` 与 `ube_total_size`）的标准 IEEE 802.3 CRC32 校验码。
* `trailer_magic`（4 Bytes, bytes）：标准模式为 `"STH!"`（`0x53544821`）；隐蔽模式为 `HMAC-SHA256("strhide-stealth-v1", password)[:4]`。
* **双向校验强制规范**：在 `read`、`verify`（Level 2）以及 `remove` 阶段，系统必须显式读取尾标 24 字节并校验 CRC32 与魔数，任何单比特损坏立即拦截并拒绝寻址。

---

## 6. 极简密码学流水线

* **Unicode NFC 标准化**：
  为彻底消除 macOS（NFD 分解型）与 Windows/Linux（NFC 合造型）在输入多语言字符、带音标字符时的底层字节差异，所有密码与秘密文本在参与计算前强制执行：
  `password = unicodedata.normalize("NFC", password)`。
* **密钥派生**：标准 **RFC 5869 HKDF-SHA256**。
  ```python
  PRK = HMAC_SHA256(key=salt, msg=password_nfc_utf8)
  Key_Payload = HKDF_Expand(PRK, info=b"strhide-payload", length=32)
  Key_Meta    = HKDF_Expand(PRK, info=b"strhide-metadata", length=32)
  ```
* **隐蔽模式魔数派生**：
  ```python
  stealth_digest = HMAC_SHA256(key=b"strhide-stealth-v1", msg=password_nfc_utf8)
  header_magic = stealth_digest[:8]
  trailer_magic = stealth_digest[8:12]
  ```
* **认证加密**：标准 **AES-256-GCM**。
  * 将信封固定头部前 80 字节作为不可变 AAD 进行强绑定认证。
  * 按 **2MB (`2,097,152 Bytes`)** 分块流式加密，每一块绑定 `FixedHeader_AAD || uint64_le(chunk_index) || uint8(is_last)`，杜绝重排与截断。
* **压缩机制**：标准 **Deflate / Zlib**。若压缩率不足 2%（`comp_len >= raw_len * 0.98`），自动保留原流，避免逆膨胀。

---

## 7. 操作系统保全、默认原地备份与隐蔽性告警

为了确保注入或还原后文件不在操作系统层面产生异常痕迹，同时保护用户原始数据：
1. **原子替换保护**：所有写操作先写入同目录下的 `.tmp` 临时文件，通过自校验后调用 `os.replace` 原子提交，防止异常中断产生破损文件。
2. **默认 In-place 模式保留原文件备份 (`<carrier>.bak`)**：
   - 当用户在未指定 `-o` 的原地模式下执行 `write`（写入）或 `remove`（还原）时，系统在原子提交替换前，强制自动完整备份原载体为 **`<carrier_path>.bak`**。
   - 允许传入 `--no-backup` 开关显式关闭备份（用于自动化测试或磁盘受限场景）。
3. **隐蔽性容量膨胀安全告警 (>50%)**：
   - 注入前自动计算 UBE 信封总长度与载体原始大小的比例。
   - 当 `ube_total_size > orig_host_size * 0.5` 时，终端自动输出高亮警告（`[WARNING] Hidden data envelope size exceeds 50.0% of carrier file size... Noticeable file size inflation may compromise stealthiness!`），提醒用户剧烈文件体积增长易引起分析人员察觉。
4. **属性与时间戳克隆**：保留原文件执行权限（`chmod`）与时间戳（`--preserve-time`），使修改后的载体在资源管理器中“修改时间”保持不变。

---

## 8. CLI 命令行接口规范

统一命令风格，保持简洁一致：

```bash
# 1. 写入模式 (Write)
strhide write -c <carrier> -d <secret-file> [-o <out>] [-p <pass>] [--strategy auto|ask|<name>] [--stealth] [--preserve-time]
strhide write -c <carrier> -t "secret text" [--unescape] [-p <pass>]
strhide write -c <carrier> --text-file <path.txt> [-p <pass>]
strhide write -c <carrier> --text-base64 <b64_str> [-p <pass>]
cat secret.bin | strhide write -c <carrier> --stdin -o output.png -p <pass>

# 2. 提取模式 (Read)
strhide read -c <carrier> [-o <out-dir|out-file>] [-p <pass>]
strhide read -c <carrier> --stdout [-p <pass>]

# 3. 三级校验 (Verify)
strhide verify -c <carrier> [-p <pass>] [--json]

# 4. 检视信息 (Inspect)
strhide inspect -c <carrier> [-p <pass>] [--json]

# 5. 100% 无损还原 (Remove / Strip)
strhide remove -c <carrier> [-o <out>] [-p <pass>]

# 6. 列出可用策略 (List Strategies)
strhide list-strategies -c <carrier>
```

---

## 9. 跨平台/跨Shell编码治理与调用规范

为了保证在 Windows / Linux / macOS，不同 Shell（PowerShell / CMD / Bash / Zsh）以及各类语言（Node.js, Go, Python, Rust）中调用不出现乱码、截断或转义错误，建立以下调用通道规范：

1. **载荷数据与控制参数彻底分离**：
   - 复杂/超长文本：使用 `--text-file <path>` 或 `STRHIDE_TEXT` 环境变量；
   - 二进制或多语言流：直接使用 `--stdin` / `--stdout` 走系统管道流（底层绑定无缓冲 `sys.stdin.buffer` / `os.Stdin`），100% 绕过控制台代码页（CP936/GBK/UTF-8）与转义符。
2. **密码安全传递通道（按优先级）**：
   - 方式 1：`STRHIDE_PASSWORD` 环境变量（跨进程调用最安全，不暴露在进程参数列表）；
   - 方式 2：`--password-file <path>`（直接读取 UTF-8 文本）；
   - 方式 3：交互式无回显安全输入；
   - 方式 4：`-p / --password` 命令行直传。

---

## 10. 实施状态与测试实证记录

* **实施状态**：**已 100% 完成工程实施与生产级代码交付**（位于 `python/strhide`）。
* **格式适配器落地矩阵**：
  * `PngAdapter` (`adapters/png.py`)：`stEg` 辅助块注入、CRC 重新计算、尾部脏数据滑动窗口容错。
  * `JpegAdapter` (`adapters/jpeg.py`)：Marker 状态机扫描、EOI（`FF D9`）精准边界定位。
  * `Mp4Adapter` (`adapters/mp4.py`)：ISO BMFF 顶层 64 位 `uuid` Box 追加，不改变原音视频帧绝对偏移量。
  * `ZipAdapter` (`adapters/zip.py`)：`pre_cd_inject` 策略与 Central Directory Offset 动态修正。
  * `EofAdapter` (`adapters/eof.py`)：通用尾部追加适配器（支持 EXE, PDF 等）。
* **自动化测试套件**：
  * pytest 单元与集成测试套件：**36 / 36 项测试全部通过（100%）**。
  * 真实世界大样本全矩阵批量测试（`tests/batch_test_runner.py`）：涵盖 `temp/testfiles` 中 26 个真实文件（PNG, JPG, MP4, ZIP, PDF, 未签名 EXE, 已签名 EXE, APK，最大 34MB），包含普通模式、加密模式、隐蔽模式及 100% 逐比特无损还原校验，**72 / 72 项细分测试全部通过（100.0%）**。
* **下一步规划**：按本技术规范直接向 Go 1.22+ 交叉编译版本平移。
