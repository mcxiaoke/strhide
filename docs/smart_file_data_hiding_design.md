# 智能多格式无损数据隐藏与隐写工具（strhide）技术实现规范

> 版本：v3.2 ｜ 状态：现行规范，与 Rust 0.8.x 实现（`rust/`）对齐 ｜ 范围：双域架构、结构域信封协议、内容域多媒体隐写、适配器算法与 CLI 规范

---

## 1. 规范范围、系统定位与设计边界

### 1.1 系统定位与双域模型
`strhide` 是面向二进制多媒体与通用文件载体的数据隐藏工具，提供两个相互独立的工作域：

1. **结构域（Structure Domain / Container Hiding）**：
   - **机制**：利用载体文件格式本身的物理结构规则（如私有辅助块、注释段、未引用流对象、中央目录前置、PE 节表尾部零填充与指令等价置换等），在保持宿主文件原有物理结构和展示/执行功能正常的前提下，嵌入自闭环的统一二进制信封（Universal Binary Envelope, UBE）。
   - **核心属性**：**100% 逐比特无损还原**。剥离隐藏数据后，载体文件完全恢复到注入前的原始状态，全量 SHA-256 哈希值逐比特一致。
2. **内容域（Content Domain / Media Steganography）**：
   - **机制**：利用失真代价模型（Cost Model）与网格/矩阵编码（STC/Hamming），将数据调制嵌入在多媒体底层数据中（PNG 空间域像素、JPEG DCT 频域系数、HEVC CABAC 语法元素旁路符号位、WAV PCM 采样位、FLAC 线性预测残差位）。
   - **核心属性**：**格式保持、抗统计检测与极低视觉/听觉失真**。其中 HEVC 压缩域隐写实现严格零字节膨胀（$\Delta = 0$）。内容域修改具有不可逆性，不提供原始载体逐比特还原。
3. **双域复合共存（Dual-Domain Coexistence）**：
   - 多媒体载体（如 JPEG、PNG、HEIC、HEVC、WAV）支持在同一文件内同时承载内容域隐写数据与结构域容器信封，且注入与提取顺序无关。

### 1.2 非设计目标与取证边界
* **结构域取证边界**：结构域以宿主正常解析与展示为目标，不承诺对抗深度数字取证。格式解析工具与熵分析工具（如 `binwalk`、格式解析器）可通过检测未引用块、非标准段或文件总尺寸波动识别载荷存在。
* **低特征模式（去特征化规范，两个层级）**：
  * **标准层（始终生效）**：落盘信封不含任何静态 ASCII 魔数（无 `STRHIDE` / `STH!` 字符串），头尾魔数采用高熵伪随机二进制序列；载荷、元数据与原宿主 SHA-256 全部经 AES-256-GCM 密封（无口令时使用内置默认密钥派生）。
  * **Stealth 隐蔽层（`--stealth`，需口令）**：信封头尾魔数由用户口令动态派生，头部关键字段及尾标 CRC32 经流密钥掩码。未提供正确口令时，公开扫描工具无法检出信封特征。该模式下禁止设置密码提示（`--hint`）。

---

## 2. 安全预检与拦截矩阵

为防止损坏具有完整性校验或数字签名的文件，系统在执行任何写操作前执行预检拦截（Fail-Safe by Default）。命中以下任一规则时，立即终止并返回具体错误信息：

| 载体类别 | 判定条件 / 检验算法 | 终端拦截提示 |
| :--- | :--- | :--- |
| **已签名 Windows PE** (`.exe`, `.dll`, `.sys`, `.scr`) | PE Optional Header 的 `IMAGE_DIRECTORY_ENTRY_SECURITY`<br>（PE32: 偏移 128，PE32+: 偏移 144）<br>`VirtualAddress != 0` 且 `Size != 0` | `Windows PE contains an Authenticode digital signature. Modification will invalidate the signature.` |
| **Android APK 包** (`.apk`) | 文件扩展名为 `.apk` 或匹配 Android 安装包特征 | `APK 格式不在支持列表中（不支持作为载体文件进行修改）。` |
| **已签名 PDF 文档** (`.pdf`) | 64KB 重叠滑动窗口流式扫描：<br>在同一窗口内共现 `/ByteRange` 与 `/Sig`（或 `/SubFilter /adbe.pkcs7`） | `PDF document contains a cryptographic digital signature. Modifying it will invalidate the signature.` |
| **已签名 Java 归档** (`.jar`, `.war`, `.ear`) | ZIP 归档内部 `META-INF/` 目录下存在 `*.SF`、`*.RSA`、`*.DSA` 签名清单文件 | `JAR archive contains digital signature file (<filename>). Modifying it will break JVM verification.` |
| **独立数字签名文件** (`.sig`, `.asc`, `.p7s`, `.p7b`) | 扩展名匹配或头部包含 PGP/GPG/PKCS#7 签名标识 | `File '<filename>' is a standalone digital signature file and cannot be used as a carrier.` |
| **权限不足** | 载体文件或目标目录无写权限 | `No write permission on target file / parent directory.` |

---

## 3. 统一二进制信封协议规范（UBE v2.2 - 结构域）

信封（Universal Binary Envelope, UBE）是结构域统一封装载荷、鉴权参数与还原凭据的自闭环二进制结构。
除特定格式适配器包装头（大端序）外，UBE 内部所有多字节整数一律采用**小端序（Little-Endian）**。

### 3.1 总体布局

```text
+--------------------------------------------------------------------------------+
| 1. 固定头部 (Fixed Header, 112 字节, 8 字节对齐)                               |
|    - 0x00 ~ 0x4F (80 字节): 定长 AAD 前缀 - 绑定 AES-256-GCM 认证（§3.4）         |
|    - 0x50 ~ 0x6F (32 字节): 物理偏移、尺寸与元数据长度参数                     |
+--------------------------------------------------------------------------------+
| 2. 密码提示块 (Password Hint Block, 可选, 变长 UTF-8, 长度 ≤ 1024 字节)        |
+--------------------------------------------------------------------------------+
| 3. 元数据块 (Metadata Block, 变长: 紧凑二进制 v1 或 JSON, 含 16 字节 GCM Tag)   |
+--------------------------------------------------------------------------------+
| 4. 载荷数据流 (Payload Stream, 分块流式 AEAD, 每块含 4B 长度 + 密文 + 16B Tag)   |
+--------------------------------------------------------------------------------+
| 5. 通用定位尾标 (Universal Locator Trailer, 24 字节)                           |
+--------------------------------------------------------------------------------+
```

### 3.2 固定头部字段定义（112 字节）

结构体打包格式（小端）：`<8sBBBB16s12sQ32sQQIIII`。定长 112 字节，无 padding 字段。

| 偏移 | 字段名 | 长度 | 类型 | 取值范围与说明 |
| :--- | :--- | :--- | :--- | :--- |
| `0x00` | `magic_header` | 8B | `bytes` | 标准模式：高熵二进制 `b7 54 2c 82 7e 31 1d 6e`（`SHA-256("strhide-standard-header-v2")[..8]`）；stealth 模式：口令派生的 8 字节伪随机值。**旧版** `89 53 54 52 48 49 44 45`（`\x89STRHIDE`）仅作向下读取兼容识别。 |
| `0x08` | `version` | 1B | `uint8` | 协议版本号，当前固定为 `0x02` |
| `0x09` | `flags` | 1B | `uint8` | `bit 0`: **是否使用用户口令密钥**（`0`=内置密钥模式，落盘加密，读取无需输入口令；`1`=用户口令模式，读取需口令）<br>`bit 1`: 是否压缩（`0`=无, `1`=Deflate）<br>`bit 2`: 载荷类型（`0`=文本, `1`=文件）<br>`bit 3`: stealth 模式（`0`=标准, `1`=Stealth，须与 bit0 同时置位）<br>`bit 4`: 含密码提示<br>`bit 5`: 紧凑二进制元数据（`0`=JSON, `1`=紧凑 v1）<br>`bit 6`: 流式分块载荷<br>`bit 7`: 保留，填 `0` |
| `0x0A` | `strategy_id` | 1B | `uint8` | `1`=eof, `2`=chunk, `3`=box_uuid, `4`=pre_cd_inject, `5`=app_segment, `6`=incremental, `7`=pe_overlay, `8`=pe_codebits, `9`=pe_slack |
| `0x0B` | `offset_delta` | 1B | `uint8` | 注入点到信封首字节的物理位移（取值范围 0..=64，用于三级坐标校验，如适配器外层容器包装头偏移补偿） |
| `0x0C` | `salt` | 16B | `bytes` | CSPRNG 生成的 128 位随机盐 |
| `0x1C` | `base_nonce` | 12B | `bytes` | CSPRNG 生成的 96 位 Nonce 基础值 |
| `0x28` | `orig_host_size` | 8B | `uint64` | 原始宿主文件的精确字节大小 |
| `0x30` | `orig_host_sha256` | 32B | `bytes` | **原始宿主全量 SHA-256 指纹**，用于还原校验 |
| *(0x00 ~ 0x4F)* | *(AAD 前缀)* | *80B* | | *上述前 80 字节是 AES-256-GCM AAD 的定长前缀；`meta_len`/`hint_len` 与提示正文另行追加（§3.4）* |
| `0x50` | `inject_offset` | 8B | `uint64` | 宿主文件被修改或切开插入的绝对物理字节偏移 |
| `0x58` | `inject_size` | 8B | `uint64` | 向宿主注入的总字节数（外层格式容器头 + UBE 整体长度） |
| `0x60` | `patch_offset` | 4B | `uint32` | 宿主头部被修改的字段物理偏移（无修改则填 0） |
| `0x64` | `orig_patch_val` | 4B | `uint32` | 被修改字段在注入前的原始 32 位无符号整数值（无修改则填 0） |
| `0x68` | `meta_len` | 4B | `uint32` | 元数据块长度（含 16 字节 GCM Tag） |
| `0x6C` | `hint_len` | 4B | `uint32` | 密码提示文本 UTF-8 字节长度（无提示填 0，最大 1024） |

> **头部敏感字段掩码**：在 stealth 模式（用口令）和标准内置密钥模式（bit0=0）下，`version/flags/strategy_id/offset_delta`（0x08..0x0B）以及 `orig_host_size/orig_host_sha256/inject_offset/inject_size/patch_offset/orig_patch_val/meta_len/hint_len`（0x28..0x6F，共 72 字节）按 76 字节流密钥做 XOR 掩码；用户显式口令标准模式（bit0=1, bit3=0）不掩码。

### 3.3 密码提示块（Password Hint Block）
* **存储位置**：位于 112 字节固定头部之后、元数据块之前。
* **物理表示**：当 `flags & FLAG_HAS_HINT (0x10)` 置位时，占用连续的 `hint_len` 字节（UTF-8 编码文本）。
* **约束规则**：明文存储，长度不超过 1024 字节，写入前经 Unicode NFC 规范化。与隐蔽模式互斥（`flags & FLAG_STEALTH` 时 `hint_len` 必须为 0）。

### 3.4 元数据块（Metadata Block）
元数据块经 AES-256-GCM 加密，由 `flags & FLAG_COMPACT_META (0x20)` 决定原始格式：
1. **紧凑二进制布局（v1，默认）**：
   - `0x00`: `version` (1B, 0x01)
   - `0x01`: `name_len` (2B LE, ≤ 65535)
   - `0x03`: `filename` (`name_len` 字节 UTF-8，提取端强制做路径净化)
   - 随附：`raw_size` (LEB128)、`raw_sha256` (32B 二进制)、`created_at` (LEB128 Unix 时间戳)。
2. **旧版 JSON 布局**：JSON 字典的 UTF-8 字节流。
3. **加密绑定**：AAD 为 `header[0..80] || meta_len || hint_len || hint`（变长），Tag 占用 16 字节。`meta_len`/`hint_len`/提示正文因此也被认证；只有四个注入后坐标（`inject_offset`/`inject_size`/`patch_offset`/`orig_patch_val`）在 AAD 之外，改由物理边界、坐标交叉与还原 SHA-256 三重结构校验兜底（见 `docs/api/WIRE_SPEC.md` §3.4、§5）。

### 3.5 载荷数据流（Payload Stream）
数据流采用分块 AEAD 封装：
* **分块规格**：默认分块大小为 2MB (`CHUNK_SIZE = 2,097,152` 字节)，单块硬上限为 64MB (`MAX_CHUNK_SIZE = 67,108,864` 字节)。
* **分块结构**：`[4B chunk_len (LE)] + [密文 (长度 ≤ 64MB)] + [16B GCM Tag]`。
* **分块 Nonce**：`chunk_nonce = base_nonce[:8] || ((base_nonce[8:12] as u32) ^ chunk_index).to_le_bytes()`。
* **分块 AAD**：`chunk_aad = fixed_header_aad (80B) || chunk_index (8B, u64 LE) || is_last (1B, u8)`。
* **空载荷边界**：载荷长度为 0 时写入单个 `chunk_index=0, is_last=1` 的空加密块（密文长度 0，尾随 16 字节 Tag）。

### 3.6 通用定位尾标（Universal Locator Trailer, 24 字节）
尾标位于 UBE 信封的最末尾，用于实现常数时间 $O(1)$ 的逆向边界定位与损坏探测。结构体打包格式（小端）：`<QQI4s`。

| 偏移 | 字段名 | 长度 | 类型 | 取值与说明 |
| :--- | :--- | :--- | :--- | :--- |
| `0x00` | `ube_offset` | 8B | `uint64` | UBE 固定头部在载体文件中的绝对起始物理偏移 |
| `0x08` | `ube_total_size` | 8B | `uint64` | UBE 完整字节长度（`112 + hint_len + meta_len + payload_size + 24`） |
| `0x10` | `trailer_crc32` | 4B | `uint32` | 前 16 字节（`ube_offset` 与 `ube_total_size`）的 CRC32；标准模式为 IEEE 802.3 原值，stealth 模式与 `CRC32(trailer_magic || b"STEA")` 异或掩码 |
| `0x14` | `trailer_magic` | 4B | `bytes` | 标准模式：高熵 `78 e6 66 d2`（`SHA-256("strhide-standard-trailer-v2")[..4]`）；stealth 模式：口令派生的 4 字节魔数。 |

---

## 4. 密码学与密钥派生规范

### 4.1 Unicode NFC 标准化
所有用户密码与文本数据在参与哈希和派生计算前统一执行 Unicode NFC 标准化，消除不同操作系统间的底层编码差异。

### 4.2 结构域密钥派生流水线（PBKDF2 + HKDF-SHA256）
所有落盘信封的元数据与载荷流一律经 AES-256-GCM 密封。
* 未提供密码时使用内置公开默认密钥（CLI `write` 会向 stderr 打印警告：无密码信封仅防止无意浏览，不提供机密性）：
  `BUILTIN_DEFAULT_KEY = "strhide::structure::envelope::v2::default::builtin::public::secret"`
* **派生阶段**：
  1. $\text{IKM} = \text{PBKDF2-HMAC-SHA256}(\text{pwd}_{\text{nfc}} \text{ 或 BUILTIN\_DEFAULT\_KEY}, \text{salt}, 100000, 32)$
  2. $\text{PRK} = \text{HKDF-Extract}(\text{salt}, \text{IKM})$
  3. $\text{Key}_{\text{payload}} = \text{HKDF-Expand}(\text{PRK}, b"\text{strhide-payload}", 32)$
  4. $\text{Key}_{\text{meta}} = \text{HKDF-Expand}(\text{PRK}, b"\text{strhide-metadata}", 32)$

### 4.3 隐蔽模式动态魔数与掩码
* 隐蔽模式魔数派生：
  - 固定盐：$b"\text{strhide-stealth-v1}"$
  - $\text{IKM}_{\text{stealth}} = \text{PBKDF2}(\text{pwd}_{\text{nfc}}, b"\text{strhide-stealth-v1}", 100000, 32)$
  - $\text{magic\_header} = \text{HKDF-Expand}(\text{PRK}_{\text{stealth}}, b"\text{strhide-stealth-header}", 8)$
  - $\text{trailer\_magic} = \text{HKDF-Expand}(\text{PRK}_{\text{stealth}}, b"\text{strhide-stealth-trailer}", 4)$
* 头部 76 字节流密钥掩码：$\text{mask}_{76} = \text{HKDF-Expand}(\text{PRK}, b"\text{strhide-header-mask-v1}", 76)$。
* 尾标 CRC32 掩码：$\text{trailer\_crc32} = \text{raw\_crc} \oplus \text{CRC32}(\text{trailer\_magic} \parallel b"\text{STEA}")$。

### 4.4 数据压缩机制
采用标准 Raw Deflate（`wbits = -15`）。若压缩后字节数 $\ge \text{raw\_size} \times 0.98$（节省空间不足 2%），自动放弃压缩并采用未压缩流（置 `FLAG_COMPRESSED = 0`），避免高熵载荷逆向膨胀。

对超过 1 MiB 的载荷，写入侧先对固定的 256 KiB 分层样本（8 × 32 KiB，首尾均匀分布）做一次 deflate，再用同一 2% 判据决定是否执行整份压缩；样本判为不可压缩时直接写未压缩流，跳过整份 deflate。该判据只影响写入耗时与压缩标志，`FLAG_COMPRESSED` 始终与实际写入的字节一致；读侧行为不变。

---

## 5. 结构域格式专用适配器技术规范

系统包含针对各大主流容器的专用格式适配器：

| 适配器 | 支持格式与扩展名 | 支持策略 | 注入机制 |
| :--- | :--- | :--- | :--- |
| **PNG** | `.png` | `chunk` (默认), `eof` | 插入私有辅助块 `prIv`（位于末尾 `IEND` 之前）；脏尾数据原样保留 |
| **JPEG** | `.jpg`, `.jpeg` | `app_segment` (默认), `eof` | 插入 `COM` 标记段（`0xFF 0xFE`，位于 `SOS` 扫描起始标记之前） |
| **MP4 / MOV** | `.mp4`, `.mov`, `.m4v` | `box_uuid` (默认), `eof` | 追加顶层 `uuid` Box（RFC 4122 v4 UUID，32/64位双模头部） |
| **ZIP 归档** | `.zip`, `.jar`, `.docx`, `.xlsx`, `.pptx` | `pre_cd_inject` (默认), `eof` | 在中央目录（Central Directory）前切开插入信封，并修正 EOCD 记录中的 `cd_offset` |
| **PDF 文档** | `.pdf` | `incremental` (默认), `eof` | ISO 32000-1 增量更新段（追加 Metadata 流对象、增量 xref 表与 trailer） |
| **PE 可执行文件** | `.exe`, `.dll`, `.sys`, `.scr` | `pe_codebits`, `pe_slack`, `pe_overlay`, `eof` | 指令编码置换 / 节尾零填充填充（零文件增长）/ 镜像尾部 Overlay 追加 |
| **EOF 适配器** | 上述格式超限或损坏时降级 | `eof` | 文件物理末尾追加（不作为未知格式兜底，未知格式直接拒绝） |

---

## 6. 内容域多媒体隐写技术规范

内容域（`strhide::stego`）针对特定媒体格式进行压缩域与采样域自适应隐写，不使用 UBE 结构化容器，而是使用极简高熵伪随机微信封。

### 6.1 极简高熵微信封
* **结构**：`[16B salt] + [12B nonce] + [密文 (含 16B GCM Tag)]`。
* **特性**：无静态魔数、无明文长度字段、无明文时间戳或文件名；密钥派生与结构域相互隔离；无凭据时整体呈现伪随机分布。

### 6.2 图像空间域隐写（PNG）
* **代价模型**：支持 `HILL`（高通与低通联合滤波，默认）、`S-UNIWARD`（二维可分离小波方向滤波器组）与 `MiPOD`（像素方差自适应估计与独立加性噪声模型）。
* **残差赤字消除与匹配规则**：采用三元 $\pm 1$ 匹配，且严格约束在像素的 8 阶等价类内（`val & 0xF8`），避免奇偶直方图扁平化与值对边界畸变，抵抗 SPA / RS 隐写分析。

### 6.3 图像频域隐写（JPEG）
* **代价模型**：支持 `UERD`（统一嵌入重构失真模型，默认）、`J-UNIWARD` 与 `J-MiPOD`。
* **调制机制**：直接作用于 DCT 量化系数（仅选择交流系数 AC slots，严禁修改直流系数 DC），使用三元校验网格综合编码（STC, Syndrome-Trellis Codes）最小化总失真代价。

### 6.4 视频与图像容器压缩域隐写（HEVC CABAC，Scheme C）
* **支持容器与流**：MP4 / MOV 容器视频、MKV (Matroska) 容器视频、HEIC / HEIF 图像以及原始 Annex-B 码流。
* **原位调制与零膨胀**：解析变换单元（TU）语法元素，在 CABAC 旁路区间调制高频变换系数的符号位（`coeff_sign_flag`）。由于符号位采用旁路等概率编码（Bypass Mode），符号位反转完全保持语法合规，规避防竞争字节（EPB）风险，**实现严格零字节文件膨胀（$\Delta = 0$）**。

### 6.5 音频域隐写（WAV & FLAC）
* **WAV PCM 采样域**：针对 16-bit / 24-bit 线性 PCM 音频数据，基于听觉感知掩蔽代价与 STC 编码进行最低有效位（LSB）匹配。
* **FLAC 预测残差域**：解析 FLAC 帧结构与多项式预测子帧，在保持残差码字长度不变的前提下对残差数据进行调制嵌入，全流程受 PCM MD5 校验和与漂移预算严格保护。

### 6.6 安全容量档位与策略（SafetyPolicy）
内容域提供三档容量安全预算策略，避免过度嵌入导致抗检指标劣化：
* `Paranoid`：极限抗检预算（例如 JPEG bpp $\le 0.06$）；
* `High`：推荐生产档位（例如 JPEG bpp $\le 0.10$）；
* `Balanced`：平衡容量档位（例如 JPEG bpp $\le 0.15$）。
* 执行模式：`Advisory`（默认，超限告警但不中断）；`Enforced`（超限强制拦截抛错）。

### 6.7 动态算法元数据自省
核心库导出 `list_stego_algorithms()` 与 `algorithms_for_format(format)`，返回包含算法唯一 ID、显示名称、原理描述、适用域及格式扩展名的 `StegoAlgorithmInfo` 元数据，供 CLI 与 GUI 进行上下文感知的动态呈现与参数绑定。

---

## 7. 双域复合共存与顺序无关性

为满足复杂安全场景下多层数据隔离与多域隐蔽需求，系统支持在单个多媒体载体上同时施加内容域隐写与结构域信封：

1. **双向流水线对称性**：
   - `Content -> Structure`：先对原始媒体执行内容域嵌入，再将生成的隐写媒体作为宿主注入结构域信封；
   - `Structure -> Content`：先向宿主注入结构域信封，再在媒体流中执行内容域嵌入。
2. **偏移位移自描述容错**：
   针对先注入结构域后执行内容域嵌入时容器重新打包导致的绝对物理偏移位移（例如 PNG IDAT 重新 Deflate 压缩），结构域适配器在定位时结合自描述有效性判定（验证块内部是否以合法 Header Magic 起始），消除偏移位移导致的解析失败。
3. **密钥隔离**：
   结构域与内容域使用相互独立的 KDF 域标签和默认公开密钥，任一域的密码不会导致另一域产生伪阳性解密。

---

## 8. 100% 逐比特无损还原协议（结构域）

执行 `strhide restore`（别名 `s`）时，系统严格按凭据回滚物理改动：

```text
[已隐藏载体文件]
       |
       v
[定位 UBE 尾标与头部凭证 (Fixed Header)]
       |
       v
[提取还原凭据: orig_host_size, orig_host_sha256, inject_offset, inject_size, patch_offset, orig_patch_val]
       |
       v
[执行逆向物理回滚]
  |-- 尾部追加型 (eof, pe_overlay, box_uuid, incremental): 截断至 orig_host_size
  |-- 中间切入型 (chunk): 切除 [inject_offset : inject_offset + inject_size] 并拼接后续数据
  |-- 头字段修正型 (pre_cd_inject): 切除信封，在 patch_offset 处还原 4 字节 orig_patch_val
  |-- 零增长型 (pe_slack): 将信封区间重置清零
  |-- 指令信道型 (pe_codebits): 根据 diff 记录还原 .text 指令原始编码
       |
       v
[全量 SHA-256 强一致校验]
  计算还原后临时文件 SHA-256
       |
       +---> SHA-256 == orig_host_sha256 ?
                 |-- 是 -> 原子重命名替换，完成还原
                 |-- 否 -> 抛出 RestoreMismatchError，严禁覆盖！
```

---

## 9. 命令行接口规范与多入口体系

系统提供单一全能主入口与三个域专用独立入口，所有入口共享底层核心库：

| 二进制命令 | 简写 | 覆盖命令范围 | 适用定位 |
| :--- | :--- | :--- | :--- |
| `strhide` | `sth` | 全部 10 个核心动词 | 全功能统一命令行入口 |
| `sthc` | - | `write`, `read`, `restore` | 容器结构域专用入口 |
| `sths` | - | `embed`, `extract`, `capacity` | 内容多媒体隐写域专用入口 |
| `sthv` | - | `inspect`, `verify`, `scan`, `list` | 只读诊断、取证与分析专用入口 |

### 9.1 核心命令与短别名速查

```bash
# ── 容器结构域 (Container) ──
sth write <carrier> -t "secret text" [-o out.png] [-p password]     # 写入 (别名: w)
sth read <carrier> -o <out-dir|out-file> [-p password]              # 读取提取 (别名: r)
sth restore <carrier> [-o out.png]                                  # 100% 无损还原 (别名: s)

# ── 多媒体内容隐写域 (Media Stego) ──
sth embed <carrier> -d <payload-file> [-o out.jpg] [-p password]    # 嵌入隐写 (别名: e)
sth extract <carrier> -o <out-file> [-p password]                   # 提取隐写 (别名: x)
sth capacity <carrier> [--exact]                                    # 探测嵌入容量 (别名: c)

# ── 诊断与分析 (Diagnostics) ──
sth inspect <carrier> [--json]                                      # 查看结构与元数据
sth verify <carrier> [-p password]                                  # 校验信封完整性
sth scan <carrier-or-dir> [-r]                                      # 黑盒隐写分析与检测
sth list                                                            # 列出支持格式与容量 (别名: l)
```

---

## 10. 核心数据结构参考（Rust 实现）

### 固定头部（EnvelopeHeader, 112 字节）
```rust
#[repr(C, packed)]
pub struct EnvelopeHeader {
    pub magic_header: [u8; 8],
    pub version: u8,
    pub flags: u8,
    pub strategy_id: u8,
    pub offset_delta: u8,        // 0x0B: 注入点到信封首字节位移 (0..=64)
    pub salt: [u8; 16],
    pub base_nonce: [u8; 12],
    pub orig_host_size: u64,
    pub orig_host_sha256: [u8; 32],
    pub inject_offset: u64,
    pub inject_size: u64,
    pub patch_offset: u32,
    pub orig_patch_val: u32,
    pub meta_len: u32,
    pub hint_len: u32,
}
```

### 通用定位尾标（EnvelopeTrailer, 24 字节）
```rust
#[repr(C, packed)]
pub struct EnvelopeTrailer {
    pub ube_offset: u64,        // 0x00 (LE)
    pub ube_total_size: u64,    // 0x08 (LE)
    pub trailer_crc32: u32,     // 0x10 (LE, stealth 模式经掩码)
    pub trailer_magic: [u8; 4], // 0x14
}
```
