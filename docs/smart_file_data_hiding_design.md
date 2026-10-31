# 智能多格式无损数据隐藏命令行工具（strhide）技术实现规范

> 版本：v3.0 ｜ 状态：现行规范，与 Rust 0.3.x 实现（`rust/`）对齐 ｜ 范围：核心协议规范、适配器算法、容错机制与 CLI 接口
>
> v3.0 相对 v2.2 的主要变更：所有落盘信封一律加密（无口令时使用内置密钥，不再有明文信封）；标准模式魔数改为高熵二进制（ASCII `STRHIDE`/`STH!` 仅作 legacy 读取兼容）；新增 `pe_slack`（strategy_id=9）策略；新增 `scan` 黑盒隐写分析命令；`read` 默认拒绝覆盖已存在文件；头部 112 字节布局中无 `padding` 字段。

---

## 1. 规范范围、系统定位与设计边界

### 1.1 系统定位
`strhide` 是面向二进制载体文件的“宿主功能保全型结构化数据容器（Function-Preserving Container Hiding）”工具。
* **核心目标**：利用常见文件格式本身的物理结构规则（私有辅助块、注释段、未引用流对象、扩展元数据、中央目录前置、可执行文件附加区等），在保持宿主文件原有物理结构和展示功能正常的前提下，无损嵌入任意文本或二进制载荷。
* **设计原则**：
  1. **功能保全优先**：宿主文件在常规播放器、阅读器、图像查看器或操作系统环境中必须保持正常打开与解析。
  2. **100% 逐比特无损还原**：剥离隐藏数据后，载体文件必须完全恢复到注入前的原始状态，全量 SHA-256 哈希值逐比特一致。
  3. **确定性与无歧义**：采用确定性的状态机与固化结构，避免不可靠的经验型启发式搜索。

### 1.2 非设计目标与约束边界
* **不采用像素域/声学 LSB 隐写**：LSB 修改载荷容量受限于宿主尺寸（通常低于 1%），且在格式重压缩、转码或轻微缩放时极易被破坏。
* **不承诺对抗深度静态与动态数字取证分析**：在容器结构层面注入数据，文件分析工具（如 `binwalk`、格式解析器、熵分析器）可通过解析未分配区域、异常块或文件总尺寸波动检测出载荷存在。
* **低特征模式（去特征化规范，两个层级）**：
  * **标准层（始终生效）**：即使不设密码，落盘信封也不含任何静态 ASCII 魔数——标准头部/尾标魔数已替换为高熵伪随机二进制序列（无 `STRHIDE`/`STH!` 可读字符串），且载荷、元数据、宿主 SHA-256 全部经 AES-256-GCM 加密（无口令时用内置密钥派生）。
  * **Stealth 层（`--stealth`，需口令）**：信封头/尾魔数由口令派生，头部敏感字段（version/flags/strategy_id/宿主 SHA-256/偏移尺寸）经口令流密钥掩码，尾标 CRC32 同样被掩码，使公开 CRC32 滑动窗口扫描失效。未提供正确口令时，探测接口不输出任何表明存在隐藏容器的特征；该模式下严格禁止口令提示（`--hint`）。

---

## 2. 安全预检与拦截矩阵

为防止损坏具有完整性校验或数字签名的文件，系统在执行任何写操作前必须执行预检拦截（Fail-Safe by Default）。命中以下任一规则时，立即终止并返回具体错误信息：

| 载体类别 | 判定条件 / 检验算法 | 终端拦截提示 |
| :--- | :--- | :--- |
| **已签名 Windows PE** (`.exe`, `.dll`, `.sys`, `.scr`) | PE Optional Header 的 `IMAGE_DIRECTORY_ENTRY_SECURITY`<br>（PE32: 偏移 128，PE32+: 偏移 144）<br>`VirtualAddress != 0` 且 `Size != 0` | `Windows PE contains an Authenticode digital signature. Modification will invalidate the signature.` |
| **Android APK 包** (`.apk`) | 文件扩展名为 `.apk` 或匹配 Android 安装包特征 | `APK 格式不在支持列表中（不支持作为载体文件进行修改）。` |
| **已签名 PDF 文档** (`.pdf`) | 全文件以 64KB 重叠滑动窗口流式扫描：<br>同时存在 `/ByteRange` 与 `/Type /Sig`（或 `/SubFilter /adbe.pkcs7`） | `PDF document contains a cryptographic digital signature. Modifying it will invalidate the signature.` |
| **已签名 Java 归档** (`.jar`, `.war`, `.ear`) | ZIP 归档内部 `META-INF/` 目录下存在 `*.SF`、`*.RSA`、`*.DSA` 签名清单文件 | `JAR archive contains digital signature file (<filename>). Modifying it will break JVM verification.` |
| **独立数字签名文件** (`.sig`, `.asc`, `.p7s`, `.p7b`) | 扩展名匹配或头部包含 PGP/GPG/PKCS#7 签名标识 | `File '<filename>' is a standalone digital signature file and cannot be used as a carrier.` |
| **权限不足** | 载体文件或目标目录无写权限（`os.W_OK`） | `No write permission on target file / parent directory.` |

---

## 3. 统一二进制信封协议规范（UBE v2.2）

信封（Universal Binary Envelope, UBE）是统一封装载荷、鉴权参数与还原凭据的自闭环二进制结构。
除特定格式适配器包装头（大端序）外，UBE 内部所有多字节整数一律采用**小端序（Little-Endian）**。

### 3.1 总体布局

```
+--------------------------------------------------------------------------------+
| 1. 固定头部 (Fixed Header, 112 字节, 8 字节对齐)                               |
|    - 0x00 ~ 0x4F (80 字节): 不可变鉴权区 (Immutable AAD) - 绑定 AES-256-GCM 认证 |
|    - 0x50 ~ 0x6F (32 字节): 物理偏移、尺寸与元数据长度参数                     |
+--------------------------------------------------------------------------------+
| 2. 密码提示块 (Password Hint Block, 可选, 变长 UTF-8, 长度 ≤ 1024 字节)        |
+--------------------------------------------------------------------------------+
| 3. 元数据块 (Metadata Block, 变长: 紧凑二进制 v1 或旧版 JSON, 含 16 字节 GCM Tag) |
+--------------------------------------------------------------------------------+
| 4. 载荷数据流 (Payload Stream, 2MB 分块流式 AEAD, 每块含 4B 长度 + 密文 + 16B Tag) |
+--------------------------------------------------------------------------------+
| 5. 通用定位尾标 (Universal Locator Trailer, 24 字节)                           |
+--------------------------------------------------------------------------------+
```

### 3.2 固定头部字段定义（112 字节）

结构体打包格式（小端）：`<8sBBBB16s12sQ32sQQIIII`。112 字节**没有 padding 字段**——80 字节 AAD 区之后紧接 8+8+4+4+4+4=32 字节可变字段，正好填满。

| 偏移 | 字段名 | 长度 | 类型 | 取值范围与说明 |
| :--- | :--- | :--- | :--- | :--- |
| `0x00` | `magic_header` | 8B | `bytes` | 标准模式：高熵二进制 `b7 54 2c 82 7e 31 1d 6e`（`SHA-256("strhide-standard-header-v2")[..8]`，无 ASCII 特征）；stealth 模式：由口令派生的 8 字节值。**旧版** `89 53 54 52 48 49 44 45`（`\x89STRHIDE`）仅在读取时兼容识别。 |
| `0x08` | `version` | 1B | `uint8` | 协议版本号，当前固定为 `0x02` |
| `0x09` | `flags` | 1B | `uint8` | `bit 0`: **是否使用用户口令密钥**（`0`=内置密钥模式，落盘仍加密，读取无需口令；`1`=用户口令模式，读取需口令）<br>`bit 1`: 是否压缩（`0`=无, `1`=Deflate）<br>`bit 2`: 载荷类型（`0`=文本, `1`=文件）<br>`bit 3`: stealth 模式（`0`=标准, `1`=Stealth，须与 bit0 同时置位）<br>`bit 4`: 含密码提示<br>`bit 5`: 紧凑二进制元数据（`0`=JSON, `1`=紧凑 v1）<br>`bit 6..7`: 保留，填 `0` |
| `0x0A` | `strategy_id` | 1B | `uint8` | `1`=eof, `2`=chunk, `3`=box_uuid, `4`=pre_cd_inject, `5`=app_segment, `6`=incremental, `7`=pe_overlay, `8`=pe_codebits, `9`=pe_slack |
| `0x0B` | `reserved` | 1B | `uint8` | 保留对齐，固定填 `0x00` |
| `0x0C` | `salt` | 16B | `bytes` | CSPRNG 生成的 128 位随机盐（所有模式都随机，不再有"明文模式填全 0"） |
| `0x1C` | `base_nonce` | 12B | `bytes` | CSPRNG 生成的 96 位 Nonce 基础值 |
| `0x28` | `orig_host_size` | 8B | `uint64` | 原始宿主文件的精确字节大小 |
| `0x30` | `orig_host_sha256` | 32B | `bytes` | **原始宿主全量 SHA-256 指纹**，用于还原校验 |
| *(0x00 ~ 0x4F)* | *(AAD 区)* | *80B* | | *上述前 80 字节作为 AES-256-GCM 不可变 AAD 参与完整性鉴权* |
| `0x50` | `inject_offset` | 8B | `uint64` | 宿主文件被修改或切开插入的绝对物理字节偏移 |
| `0x58` | `inject_size` | 8B | `uint64` | 向宿主注入的总字节数（外层格式容器头 + UBE 整体长度） |
| `0x60` | `patch_offset` | 4B | `uint32` | 宿主头部被修改的字段物理偏移（无修改则填 0） |
| `0x64` | `orig_patch_val` | 4B | `uint32` | 被修改字段在注入前的原始 32 位无符号整数值（无修改则填 0） |
| `0x68` | `meta_len` | 4B | `uint32` | 元数据块长度（含 16 字节 GCM Tag） |
| `0x6C` | `hint_len` | 4B | `uint32` | 密码提示文本 UTF-8 字节长度（无提示填 0，最大 1024）；此为头部最后 4 字节，其后不再有 padding |

> **头部敏感字段掩码**：在 stealth 模式（用口令）和标准内置密钥模式（bit0=0）下，`version/flags/strategy/reserved`（0x08..0x0B）以及 `orig_host_size/orig_host_sha256/inject_offset/inject_size/patch_offset/orig_patch_val/meta_len/hint_len`（0x28..0x6F，共 72 字节）会按 §4.2 的 76 字节流密钥做 XOR 掩码；用户口令模式（bit0=1, bit3=0）不做掩码。

### 3.3 密码提示块（Password Hint Block）
* **存储位置**：位于 112 字节固定头部之后、元数据块之前。
* **物理表示**：当 `flags & FLAG_HAS_HINT (0x10)` 时，占用连续的 `hint_len` 字节（UTF-8 编码文本）。
* **约束规则**：
  * 明文存储，长度不超过 1024 字节。
  * 写入前必须执行 Unicode NFC 标准化。
  * **与隐蔽模式互斥**：当 `flags & FLAG_STEALTH (0x08)` 时，`hint_len` 必须为 0。尝试在 `--stealth` 下设置提示会直接报错并终止。

### 3.4 元数据块（Metadata Block）

元数据块有两种物理布局，由 `flags & FLAG_COMPACT_META (0x20)` 选择。读取端必须先看这一位再解码；写入端优先使用紧凑布局，无法表示时回退 JSON。

#### 3.4.1 紧凑二进制布局（v1，当前默认）

| 偏移 | 字段 | 长度 | 说明 |
| :--- | :--- | :--- | :--- |
| `0x00` | `version` | 1B | 固定 `0x01` |
| `0x01` | `name_len` | 2B | 文件名 UTF-8 字节数（LE，≤ 65535） |
| `0x03` | `filename` | `name_len` | UTF-8；读取端强制 UTF-8 校验并做路径净化 |
| ... | `raw_size` | 1~10B | LEB128 变长无符号整数 |
| ... | `raw_sha256` | 32B | 原始载荷全量 SHA-256（二进制，而非 64 字符 hex） |
| ... | `created_at` | 1~10B | LEB128，Unix 秒 |

* **长度**：文件名为 5 字节时整块 **46 字节**（旧 JSON 布局为 137 字节，其中 64 字节完全是 SHA-256 的十六进制文本）。当前实现实测最小信封：无口令内置密钥模式 `MIN_UBE_PLAIN = 178` 字节，用户口令/stealth 模式 `MIN_UBE_ENCRYPTED = 214` 字节（用于容量表下限，`inspect` 不会给出装不下最小信封的容量值）。
* **回退条件**：文件名超过 65535 字节，或 `raw_sha256` 不是 64 个合法十六进制字符 → 写端改用 JSON 布局并**清除**该 flag。
* **兼容性**：不认识 bit 5 的旧版读取端会把紧凑块当 JSON 解析并报 `Corrupted metadata block`（干净失败，不会误读）；当前读取端两种布局都支持。该 flag 属于 AAD（`flags` 字节在 AAD 内），加密模式下元数据布局与密钥/Nonce 绑定，无法被降级篡改。

#### 3.4.2 旧版 JSON 布局（`flags` bit 5 = 0）

* **原始数据**：JSON 字典的无空白 UTF-8 编码字节流：
  ```json
  {"filename":"secret.bin","raw_size":1048576,"raw_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","created_at":1773719840}
  ```

#### 3.4.3 加密参数（两种布局相同）

* 算法：AES-256-GCM。
* 密钥：`meta_key`（32 字节）。
* Nonce：`base_nonce[:8] + ((base_nonce[8:12] 整数) ^ 0xFFFFFFFF).to_bytes(4, "little")`。
* AAD：固定头部前 80 字节（`Immutable AAD`）。
* 密文结构：`密文数据 || 16 字节 GCM Tag`（长度即为 `meta_len`）。

### 3.5 载荷数据流（Payload Stream）
数据流按 **2MB (`2,097,152` 字节)** 分块处理，采用分块 AEAD 封装：I/O 以 64KB 缓冲逐块推进，单块内存占用有界。当前引擎实现在内存中完整缓存载荷（写路径峰值约为载荷的 2~3 倍：压缩/加密缓冲 + 信封组装；读路径为密文缓冲 + 明文缓冲），百 MB 级以上载荷建议关注内存占用，后续版本将演进为全流式管道。

* **分块结构**：
  ```
  +-------------------------+--------------------+---------------------+
  | 4 字节 chunk_len (LE)   | 密文 (长度 ≤ 2MB)  | 16 字节 GCM Tag     |
  +-------------------------+--------------------+---------------------+
  ```
* **分块加密参数**：
  * **Nonce 生成**：
    `chunk_nonce = base_nonce[:8] + ((base_nonce[8:12] 整数) ^ chunk_index).to_bytes(4, "little")`
  * **分块 AAD 构造**（总长 89 字节）：
    `chunk_aad = fixed_header_aad (80B) || chunk_index (8B, uint64_le) || is_last (1B, uint8)`
    （`is_last` 取值：末块为 `1`，非末块为 `0`）。
  * **空载荷边界处理**：
    若载荷流长度为 0，写入单个 `chunk_index=0, is_last=1` 的空加密块（密文长度 0，尾随 16 字节 Tag）。

### 3.6 通用定位尾标（Universal Locator Trailer, 24 字节）
尾标位于 UBE 信封的最末尾，用于实现常数时间 $O(1)$ 的逆向边界定位与损坏探测。
结构体打包格式（Python `struct`）：`<QQI4s`。

| 偏移 | 字段名 | 长度 | 类型 | 取值与说明 |
| :--- | :--- | :--- | :--- | :--- |
| `0x00` | `ube_offset` | 8B | `uint64` | UBE 固定头部在载体文件中的绝对起始物理偏移 |
| `0x08` | `ube_total_size` | 8B | `uint64` | UBE 完整字节长度（`112 + hint_len + meta_len + payload_size + 24`） |
| `0x10` | `trailer_crc32` | 4B | `uint32` | 前 16 字节（`ube_offset` 与 `ube_total_size`）的 CRC32；标准模式为 IEEE 802.3 原值，stealth 模式与 `CRC32(trailer_magic \|\| b"STEA")` 异或掩码 |
| `0x14` | `trailer_magic` | 4B | `bytes` | 标准模式：高熵 `78 e6 66 d2`（`SHA-256("strhide-standard-trailer-v2")[..4]`）；stealth 模式：口令派生的 4 字节魔数。**旧版** `53 54 48 21`（`STH!`）仅在读取时兼容识别。 |

* **双向校验规则**：
  定位成功后，必须验证：
  1. 计算 `expected = CRC32(pack("<QQ", ube_offset, ube_total_size))`；标准模式要求 `trailer_crc32 == expected`；stealth 模式要求 `trailer_crc32 ^ CRC32(trailer_magic || b"STEA") == expected`。
  2. 读取 `ube_offset` 处的头部，验证 `header.magic_header` 与 `trailer.trailer_magic` 模式匹配（标准/stealth/legacy 三类均可识别）。
  3. 验证 `trailer.ube_offset + trailer.ube_total_size` 与载体中实际记录的结构边界严格吻合。

---

## 4. 密码学与密钥派生规范

### 4.1 Unicode NFC 标准化
为消除 macOS（默认 NFD 分解型）与 Windows/Linux（默认 NFC 合造型）在输入包含重音或多语言字符时的底层字节差异，所有密码与文本数据在参与哈希计算前必须执行：
$$\text{password} = \text{unicodedata.normalize}("NFC", \text{password})$$

### 4.2 密钥派生流水线（PBKDF2 + HKDF-SHA256）

所有落盘信封的元数据与载荷流一律经 AES-256-GCM 加密。用户提供口令时口令经 NFC 标准化后作为输入；**未提供口令时使用内置公开字符串 `BUILTIN_DEFAULT_KEY = "strhide::envelope::v2::default::builtin::public::secret"` 走同一条派生流水线**——对用户而言免口令即可读取，对十六进制查看器/YARA 取证而言与真实密文无异。

1. **初始密钥材料（IKM）派生**：
   $$\text{IKM} = \text{PBKDF2\_HMAC\_SHA256}(\text{password}=\text{pwd}_{\text{nfc}}\text{ 或 BUILTIN\_DEFAULT\_KEY}, \text{salt}=\text{信封随机 salt}, \text{iterations}=100000, \text{dklen}=32)$$
2. **伪随机密钥（PRK）提取**：
   $$\text{PRK} = \text{HKDF\_Extract}(\text{salt}=\text{信封 salt}, \text{ikm}=\text{IKM}) = \text{HMAC\_SHA256}(\text{信封 salt}, \text{IKM})$$
3. **分域子密钥扩展**：
   $$\text{Key}_{\text{payload}} = \text{HKDF\_Expand}(\text{PRK}, \text{info}=b"\text{strhide-payload}", \text{length}=32)$$
   $$\text{Key}_{\text{meta}} = \text{HKDF\_Expand}(\text{PRK}, \text{info}=b"\text{strhide-metadata}", \text{length}=32)$$

读取端按"用户口令 → 内置密钥 → 旧版明文信封回退"顺序尝试解密；任一成功即返回。

### 4.3 隐蔽模式动态魔数派生（PBKDF2 + HKDF-SHA256）
隐蔽模式下，魔数不使用固定字符串，而是通过独立域分离盐与口令进行动态确定性派生：
* 固定域分离盐：$b"\text{strhide-stealth-v1}"$
* 迭代计算：
  $$\text{IKM}_{\text{stealth}} = \text{PBKDF2\_HMAC\_SHA256}(\text{password}=\text{pwd}_{\text{nfc}}, \text{salt}=b"\text{strhide-stealth-v1}", \text{iterations}=100000, \text{dklen}=32)$$
  $$\text{PRK}_{\text{stealth}} = \text{HKDF\_Extract}(b"\text{strhide-stealth-v1}", \text{IKM}_{\text{stealth}})$$
  $$\text{magic\_header} = \text{HKDF\_Expand}(\text{PRK}_{\text{stealth}}, \text{info}=b"\text{strhide-stealth-header}", \text{length}=8)$$
  $$\text{trailer\_magic} = \text{HKDF\_Expand}(\text{PRK}_{\text{stealth}}, \text{info}=b"\text{strhide-stealth-trailer}", \text{length}=4)$$

### 4.3b 头部敏感字段流密钥掩码
* 派生：$ \text{mask}_{76} = \text{HKDF\_Expand}(\text{HKDF\_Extract}(\text{信封 salt}, \text{PBKDF2}(\text{pwd}\_\text{nfc}, \text{信封 salt}, 100000)), \text{info}=b"\text{strhide-header-mask-v1}", 76) $。
* 应用：头部打包后，`buf[8..12] ^= mask[0..4]`（version/flags/strategy/reserved），`buf[40..112] ^= mask[4..76]`（orig_host_size 起 72 字节）。
* stealth 模式用用户口令，内置密钥模式用 `BUILTIN_DEFAULT_KEY`；用户口令模式（bit0=1, bit3=0）不掩码。

### 4.3c 尾标 CRC32 掩码
* `mask = CRC32(trailer_magic || b"STEA")`；写入时 `trailer_crc32 = raw_crc ^ mask`，读取时反向。使公开 IEEE CRC32 滑动窗口扫描无法在无口令时定位尾标。

### 4.4 数据压缩机制
* 算法：标准 Raw Deflate（`wbits = -15`, 压缩级别 6）。
* **逆膨胀检测规则**：
  若压缩后字节数 $\ge \text{raw\_size} \times 0.98$（节省空间不足 2%），自动放弃压缩并采用原始未压缩流（置 `FLAG_COMPRESSED = 0`），避免高熵数据（如已有视频、压缩包）压缩后尺寸反而增长。

---

## 5. 格式专用适配器技术规范

系统包含 6 种专用格式适配器（PNG/JPEG/MP4/ZIP/PDF/PE），严格按格式物理规范进行数据放置与结构调整；`EofAdapter` 仅作为各格式 `eof` 降级策略的实现提供者，不参与格式识别（2026-10-18 起，见 §5.7）。

```
                    +---------------------------+
                    |    find_adapter(stream)   |
                    +-------------+-------------+
                                  |
     +------------+------------+--+---------+------------+------------+
     |            |            |            |            |            |
     v            v            v            v            v            v
[PNG 适配器]  [JPEG 适配器]  [MP4 适配器]  [ZIP 适配器]  [PDF 适配器]  [PE 适配器]
 chunk/eof   app_segment/eof box_uuid/eof pre_cd/eof   incremental/eof pe_overlay/eof
```

---

### 5.1 PNG 适配器（`PngAdapter`）
* **特征魔数**：`89 50 4E 47 0D 0A 1A 0A`。
* **支持策略**：`chunk`（默认，`strategy_id = 2`）、`eof`（`strategy_id = 1`）。
* **容错与状态机**：
  1. **尾部脏数据容错（Dirty-Tail Tolerance）**：从文件末尾按 64KB 分块**反向扫描**（相邻块重叠 11 字节，避免标记跨块漏检），取文件序中最后一个完整的 12 字节 IEND 块（`00 00 00 00 49 45 4E 44 AE 42 60 82`），不再限定在固定尾部窗口内。
  2. 记录该 IEND 块的起始物理偏移 `iend_offset`。
  3. 注入数据严格插入在 `iend_offset` 之前；原本跟在 IEND 后面的任何填充字节或脏数据，原样后移写在最终输出文件的末尾。
* **数据包装**：
  * Chunk Type：`prIv`（`0x70 0x72 0x49 0x76`，符合 W3C 私有辅助块命名规则）。
  * 兼容性：`locate` 同时识别当前标准的 `prIv` 与旧版 `stEg` 块。
  * 结构：`[4B length (大端)] + [4B b"prIv"] + [UBE 数据] + [4B CRC32 (大端)]`。
  * CRC 范围：`CRC32(b"prIv" + UBE 数据)`。
* **容量限制与自动降级**：
  PNG 规范单块最大长度为 $2^{31}-1$（2GB）。若 UBE 尺寸超出，在 `auto` 模式下自动降级为 `eof` 策略；显式选择 `--strategy chunk` 时报错。
* **隐蔽模式表现**：
  在未提供正确口令时，stealth 信封的派生魔数不匹配任何标准/legacy 魔数，定位函数返回 `None`（可否认性）；标准模式信封可被内置密钥打开，无需口令。

---

### 5.2 JPEG 适配器（`JpegAdapter`）
* **特征魔数**：起始 `FF D8` (SOI)，结束 `FF D9` (EOI)。
* **支持策略**：`app_segment`（默认，`strategy_id = 5`）、`eof`（`strategy_id = 1`）。
* **标记段扫描状态机**：
  1. 从 `FF D8` 开始遍历标记段。对于独立标记（`SOI`, `RSTm`, `TEM`）跳过单字节；对于普通标记读取 2 字节大端长度并跳过载荷。
  2. 处理多字节 `0xFF` 填充对齐。
  3. 抵达 `FF DA`（SOS，Start of Scan）时停止，获取 SOS 的起始物理偏移 `sos_offset`。
* **数据包装（app_segment 策略）**：
  * 采用 `COM`（Comment Segment，`0xFF 0xFE`）标记段。
  * 插入位置：直接插入在 `sos_offset` 之前（位于所有图像扫描数据之前）。
  * 结构：`[2B 0xFF 0xFE] + [2B segment_len (大端，值为 2 + ube_size)] + [UBE 数据]`。
  * 宿主尾部特征：文件末尾保持为图像真实的 `FF D9`（EOI），末尾 0 附加字节。
* **容量限制与自动降级**：
  JPEG 单标记段最大长度为 65,535 字节，减去 2 字节长度字段后，最大净载荷为 **65,533 字节（约 64KB）**。
  * `auto` 策略：当 UBE 尺寸 $\le 65,533$ 时使用 `app_segment`；$> 65,533$ 时**自动降级**为 `eof`（追加于真实 EOI 之后），并在输出中提示。
  * 显式指定 `--strategy app_segment`：若超过 65,533 字节则直接抛出异常拒绝操作。

---

### 5.3 MP4 / MOV 适配器（`Mp4Adapter`）
* **特征魔数**：文件偏移 4~8 字节为白名单顶层 box：`ftyp`、`styp`、`moov`、`moof`、`mdat`、`sidx`、`emsg`、`free`、`skip`、`wide`、`uuid`、`pdin`（支持 fragmented/CMAF 媒体；仍保持显式白名单，不接受任意 4CC）。
* **支持策略**：`box_uuid`（默认，`strategy_id = 3`）、`eof`（`strategy_id = 1`）。
* **Box 结构规范与 MediaInfo 一致性**：
  采用符合 ISO/IEC 14496-12 规范的顶层 `uuid` Box，追加于文件末尾（EOF），不改变前序音视频 Sample 偏移量（`stco`/`co64` 保持 100% 有效）。
  * **载荷中立 UUID**：采用标准 RFC 4122 v4 UUID：
    `d41a8e9c-4f21-4e87-9a33-5b6d1284ef70`
    （字节序列：`D4 1A 8E 9C 4F 21 4E 87 9A 33 5B 6D 12 84 EF 70`）。向下兼容旧版包含 `\x89STRHIDE` 的测试 UUID。
  * **双模 Box 头设计**：
    * 当 $24 + \text{ube\_size} < 2^{32}-1$（< 4GB）时：
      采用标准 **24 字节 32 位 Box 头**：
      `[4B size (大端)] + [4B b"uuid"] + [16B UUID] + [UBE 数据]`
      （在此模式下 MediaInfo 检测结果为 0 Conformance Errors）。
    * 当 $\ge 4\text{GB}$ 时：
      采用标准 **32 字节 64 位 Large Box 头**：
      `[4B size=1 (大端)] + [4B b"uuid"] + [8B largesize (大端)] + [16B UUID] + [UBE 数据]`。

---

### 5.4 ZIP 归档适配器（`ZipAdapter`）
* **特征魔数**：前 4 字节为 `PK\x03\x04`、`PK\x05\x06` 或 `PK\x07\x08`。
* **支持策略**：`pre_cd_inject`（默认，`strategy_id = 4`）、`eof`（`strategy_id = 1`）。
* **EOCD 状态机与中央目录前置注入**：
  1. 从文件尾部向前 65,558 字节扫描 `PK\x05\x06`（EOCD 记录魔数）。
  2. 读取 EOCD 记录：
     * `cd_size`: 偏移 12 处的 uint32（小端）。
     * `cd_offset`: 偏移 16 处的 uint32（小端）。
  3. **切入点**：在物理偏移 `cd_offset` 处将文件切开，插入 UBE 信封。
  4. **指针修正**：修改 EOCD 记录中的 `cd_offset` 字段：
     $$\text{new\_cd\_offset} = \text{orig\_cd\_offset} + \text{ube\_size}$$
     记录还原凭证：`patch_offset = eocd_pos + 16`，`orig_patch_val = orig_cd_offset`。
  5. 修正后中央目录与各文件实体条目完全保持一致，解压工具解析零警告。
* **容量限制与自动降级**：
  标准 32 位 ZIP 的 `cd_offset` 字段上限为 $2^{32}-1$。若 $\text{orig\_cd\_offset} + \text{ube\_size} \ge 0xFFFFFFFF$，在 `auto` 策略下自动降级为 `eof` 策略。

---

### 5.5 PDF 文档适配器（`PdfAdapter`）
* **特征魔数**：`%PDF-`。
* **支持策略**：`incremental`（默认，`strategy_id = 6`）、`eof`（`strategy_id = 1`）。
* **ISO 32000-1 增量更新（Incremental Update）规范**：
  1. **尾部解析**：按 64KB 分块**反向扫描**（相邻块重叠 4 字节）定位文件序最后一个 `%%EOF`，并以其为中心取尾部窗口解析 `startxref`、`prev_startxref`、对象编号基数与 `/Root`、`/Info` 引用。`/Root` 允许通过 `/Prev` 链继承自早期修订——校验结构时不强制要求尾部直接含 `/Root`；但写入增量更新仍要求当前 trailer 可解析出 `/Root`，否则 `auto` 回退 `eof`。
  2. **构造增量流对象**：
     ```pdf
     <new_obj_num> 0 obj
     << /Type /Metadata /Length <ube_size> >>
     stream
     <UBE 二进制数据>
     endstream
     endobj
     ```
  3. **构造增量交叉引用表（xref）**：
     ```pdf
     xref
     <new_obj_num> 1
     <obj_offset:010d> 00000 n 
     ```
  4. **构造增量 Trailer 与终止符**：
     ```pdf
     trailer
     <<
     /Size <new_obj_num + 1>
     /Root <root_ref>
     /Prev <prev_startxref>
     >>
     startxref
     <xref_offset>
     %%EOF
     ```
  5. 文件以标准 `%%EOF` 终止；若原宿主在最后一个 `%%EOF` 之后携带非标准尾部字节（脏数据），这些字节在最终 `%%EOF` 之后原样保留，确保 100% 逐比特无损还原。
* **O(1) 尾标快速定位**：
  扫描尾部 128KB 窗口，定位 `%%EOF` 前最近的 `endstream`。UBE 尾部的 24 字节 `EnvelopeTrailer` 固定位于 `endstream` 关键字紧邻前部。读取该 24 字节并校验 CRC32 与魔数后，直接根据 `trailer.ube_offset` 跳转并核验开头的 `stream` 关键字，算法复杂度为常数时间 $O(1)$，对大于 128KB 乃至数百 MB 的载荷均具备可靠定位能力。
* **自动降级**：若 PDF 尾部损坏或无法解析出有效 trailer，`auto` 策略自动降级为 `eof`。

---

### 5.6 Windows PE 适配器（`PeAdapter`）
* **特征魔数**：DOS 头 `MZ`（`0x5A4D`）与 NT 签名 `PE\x00\x00`（`0x00004550`）。
* **支持策略**（按 auto 优先级排序）：
  * `pe_codebits`（`strategy_id = 8`）：x86/x64 `.text` 指令 ModR/M 语义位信道，文件尺寸不变；信道头部字段经流密钥掩码。
  * `pe_slack`（`strategy_id = 9`）：信封原地写入节表后的 header padding 与各节尾部零填充区 `[raw_ptr + min(VirtualSize, SizeOfRawData), raw_ptr + SizeOfRawData)`，**文件尺寸严格不变**；还原时清零该区间即可逐比特复原，加载器不映射、CPU 不执行该区域。
  * `pe_overlay`（`strategy_id = 7`）：追加于 PE 镜像末尾（保留已有 overlay）。
  * `eof`（`strategy_id = 1`）：末尾追加（与 pe_overlay 字节结果相同，locate 统一报告为 pe_overlay）。
* **auto 选择顺序**：`pe_codebits → pe_slack → pe_overlay`。两个零增长策略优先，overlay 尺寸增长且留下最明显的 PE stego 痕迹（末节后数据）。`pe_codebits` 可用时 `pe_slack` 必然可用（前者需要更小的零 run）。
* **节表物理边界与 Overlay 隔离**：
  1. 解析 DOS 头偏移 `0x3C` 处的 `e_lfanew`，跳转至 NT 签名。
  2. 读取 COFF 头部字段：节区数 `NumberOfSections`、可选头大小 `SizeOfOptionalHeader`。
  3. 遍历节表（Section Table，每项 40 字节）：
     $$\text{pe\_image\_end} = \max_{i=1}^{N} (\text{PointerToRawData}_i + \text{SizeOfRawData}_i)$$
  4. overlay 注入位置：追加于原始文件末尾（`orig_host_size`），保留已有节区数据与既有 overlay。
  5. 宿主可执行程序的所有节区物理偏移不变，代码、数据与导入表 100% 保持原有执行能力。
* **安全拦截**：解析可选头的数据目录表第 4 项（`IMAGE_DIRECTORY_ENTRY_SECURITY`，证书表），若包含有效签名则直接拒绝修改。`pe_slack` 判定时要求 padding 区先二次校验为零值，防止写入程序数据；`VirtualSize == 0` 的节不作 padding。

---

### 5.7 EOF 策略提供者（`EofAdapter`，2026-10-18 起不再作为格式兜底）
* **定位**：仅作为各格式适配器 `eof` 策略的实现提供者（PNG/JPEG/MP4/ZIP/PDF/PE 在载荷超限或结构降级时委派给它），**不再参与格式识别**。
* **支持策略**：`eof`（`strategy_id = 1`）。
* **行为**：直接将 UBE 信封追加在文件物理末尾。
* **格式拒绝（2026-10-18 起）**：无法识别的文件一律拒绝（`UnsupportedFormat`，错误信息含文件头字节与受支持格式清单），不再静默兜底。理由：向任意文件追加数据可能损坏该文件（尾部校验和、内嵌偏移、签名容器等）。历史影响：此前以通用文件为载体写入的信封将无法再读取/移除。

---

## 6. 策略路由与尽力而为容错机制

策略选择支持三种工作模式：

1. **`auto` 模式（尽力而为自适应）**：
   * 自动探测载体格式匹配最优先的专用适配器。
   * 依据预估信封尺寸核对格式约束：
     * JPEG：若尺寸 $> 65,533$ 字节，自动降级为 `eof`。
     * ZIP：若新中央目录偏移 $\ge 4\text{GB}$，自动降级为 `eof`。
     * PNG：若尺寸 $> 2\text{GB}$，自动降级为 `eof`。
     * PDF：若结构异常无法增量更新，自动降级为 `eof`。
     * PE：按 `pe_codebits → pe_slack → pe_overlay` 顺序尝试；三者均不可行时（如签名 PE）拒绝写入。
   * 降级发生时，终端输出具体的 `[STRATEGY]` 说明通知用户。
2. **显式策略模式（`--strategy <name>`）**：
   * 用户指定策略名称（如 `--strategy app_segment`）。
   * 若载体不支持该策略或载荷超出该策略的物理容量，**严格报错并拒绝执行**，不进行静默降级。
3. **`ask` 模式（交互式挑选）**：
   * 解析载体格式后，输出所有受支持的策略列表供用户选择输入序号。

---

## 7. 100% 逐比特无损还原协议

执行 `strhide remove` 时，必须实现将载体文件恢复至操作前的逐比特精确状态。

```
[输入已隐藏文件]
       |
       v
[定位 UBE 尾标与头部凭证 (Fixed Header)]
       |
       v
[提取还原凭证]
  - orig_host_size: uint64
  - orig_host_sha256: 32 字节哈希
  - inject_offset: uint64
  - inject_size: uint64
  - patch_offset: uint32
  - orig_patch_val: uint32
       |
       v
[逆向物理回滚]
  |-- 尾部追加型 (eof, pe_overlay, box_uuid, incremental):
  |     文件物理截断至 orig_host_size
  |
  |-- 中间切入型 (chunk):
  |     切除 [inject_offset : inject_offset + inject_size]
  |     后续 IEND 块与尾部脏数据前移拼合
  |
  |-- 头字段修正型 (pre_cd_inject):
  |     切除插入数据，中央目录前移
  |     在 patch_offset 处写入 4 字节 orig_patch_val
  |
  |-- 零增长型 (pe_slack):
  |     文件尺寸不变，把信封区间 [inject_offset, inject_offset+inject_size)
  |     清零（该区域本是零填充），逐比特复原节表 padding
  |
  |-- 指令信道型 (pe_codebits):
  |     按信道头部记录的 slack_off 恢复还原 diff，逐比特复原 .text 指令位
       |
       v
[全量 SHA-256 强校验]
  计算还原后临时文件的全量 SHA-256
       |
       +---> SHA-256 == orig_host_sha256 ?
                 |-- 是 -> 原子替换原文件，完成还原
                 |-- 否 -> 抛出 RestoreMismatchError，保留临时文件供排查，严禁覆盖！
```

---

## 8. 操作系统保全、并发与原子操作规范

1. **原子替换保护（Atomic Replacement）**：
   所有写操作与还原操作均先写入临时文件（`<target>.strhide.tmp`），通过自校验后调用操作系统的原子替换接口（`os.replace` / `rename`），防止因电源中断或异常退出产生破损文件。
2. **Windows 文件句柄防死锁**：
   在 Windows 操作系统下，文件句柄被占用时执行 `os.remove` 会触发 `WinError 32`。系统严格保证在跳出 `with open(...)` 语句块、确认句柄关闭后，才在错误处理中清理临时文件。
3. **默认原地备份机制**：
   在未指定 `-o` 的原地模式下执行 `write` 或 `remove` 时，系统在替换前自动将原文件完整复制为 **`<carrier>.bak`**。提供 `--no-backup` 开关显式关闭备份。
4. **属性与时间戳克隆**：
   还原或写入完成后，自动同步原载体的权限模式（`chmod`）与访问/修改时间戳（`os.utime`）。
5. **体积膨胀告警机制**：
   当 UBE 总大小超过宿主原始大小的 **50%** 时，终端输出明显的黄色警告信息，提醒用户大幅度尺寸增加可能降低隐蔽性。
6. **提取路径拒覆盖**：
   `read` 提取载荷落盘时，若目标文件已存在则默认报错拒绝覆盖（防止批量提取同名载荷覆盖用户文件），必须显式传 `--overwrite` 才允许覆盖；`-o <目录>` 与默认当前目录两种落盘路径均受此约束。

---

## 9. 命令行接口规范

统一命令行接口遵循标准 POSIX / GNU 选项风格：

```bash
# 1. 写入隐藏数据 (Write)
strhide write -c <carrier> -d <secret-file> [-o <out>] [-p <pass>] [-H <hint>] [--strategy auto|ask|<name>] [--stealth] [--no-preserve-time] [--no-backup]
strhide write -c <carrier> -t "secret text" [--unescape] [-p <pass>] [-H <hint>]
strhide write -c <carrier> --text-base64 <b64_str> [-p <pass>]
cat secret.bin | strhide write -c <carrier> --stdin -o output.png -p <pass>

# 2. 提取隐藏数据 (Read)
strhide read -c <carrier> [-o <out-dir|out-file>] [-p <pass>] [--overwrite]
strhide read -c <carrier> --stdout [-p <pass>]

# 3. 三级完整性诊断 (Verify)
strhide verify -c <carrier> [-p <pass>] [--json]

# 4. 检视载体与信封信息 (Inspect)
#    输出格式/结构/信封元数据（若有），并追加各策略容量表：
#    精确容量（如 pe_codebits 实测 .text 密度 + 零 slack、pe_slack 实测零填充）、auto 首选、不可用原因
strhide inspect -c <carrier> [-p <pass>] [--json]

# 5. 逐比特无损还原 (Remove)
strhide remove -c <carrier> [<carrier2> ...] [-o <out>] [-p <pass>] [--no-backup]

# 6. 列出全部格式与策略的静态容量参考表 (List)
#    数据由各适配器的 strategy_capacities(None) 生成；载体相关限制用 inspect 实测
strhide list

# 7. 黑盒隐写分析 (Scan)：把文件视为未知对象，报告任意工具留下的结构/统计异常
#    （私有块、尾部高熵数据、罕见标记、overlay、PE 非零填充等），不依赖 strhide 内部知识
strhide scan -c <file-or-dir> [<file-or-dir2> ...] [-r/--recursive] [--json]
```

`write` 与 `remove` 接受一个或多个载体（`-c a.png b.png c.png`）；`read`/`inspect`/`verify` 只接受单个载体。`write` 把同一份载荷写入每个载体；多载体时 `-o` 须为已存在目录，并打印 `[SUMMARY] n/m carriers succeeded` 汇总。

### 策略容量报告（2026-10-18 起）
`HostAdapter::strategy_capacities(Option<&mut dyn SeekRead>)` 是 `inspect` 容量表与 `list` 静态表的唯一数据源，避免两处容量判定漂移：
* `None`：静态能力——常量上限，载体相关项标注 `carrier-dependent` 且不给出具体数字；
* `Some(reader)`：按当前载体实测——PE 实测 `.text` 可改造位数与最长连续零 slack，ZIP 实测 EOCD 偏移，PDF 实测 trailer 可解析性。
返回顺序即推荐优先级（与 `choose_auto_strategy` 的偏好一致）；`available` 表示当前载体结构上是否可用（Authenticode 签名 PE 的全部策略标为不可用，因为写入会使签名失效）。容量统一为"最大 UBE 信封字节数"，与 PNG/JPEG 的固定上限同一把尺子。`choose_auto_strategy` 本轮保持不变（方案 A：零回归），两处共用常量与判定函数。

### 跨平台非交互式通道
* **密码传递**：支持 `STRHIDE_PASSWORD` 环境变量、`--password-file <path>`、`-p <password>` 及终端无回显交互输入。仅当 stdin 与 stdout 同时为 TTY 时才触发交互式提示；非交互环境（管道、CI、重定向）直接报错并提示改用上述非交互通道，避免阻塞。
* **文本传递**：支持 `STRHIDE_TEXT` 环境变量、`--text-base64 <str>`、`-t <str>`，或通过 `--stdin` 从管道读取。
* **二进制流管道**：`--stdin` 与 `--stdout` 走系统标准流缓冲，避开控制台编码代码页干扰。

### 提取路径安全（防目录穿越）
信封元数据中的 `filename` 属于**不可信输入**（字节流可被任意篡改，即便有 AEAD 保护也要按不可信处理）。所有提取落盘路径（`-o <目录>` 与默认当前目录两种模式）必须先将该值净化取末级文件名组件（拒绝空值、`.`、`..` 与绝对路径，非法时回退 `extracted.bin`），确保载荷不可能写出目标目录之外。

### 隐蔽模式强制加密约束
`--stealth` 必须与密码同时提供：其动态魔数由密码派生，无密码时工具**直接报错终止**，不得静默降级为标准明文魔数模式。

### 重复注入防护
写入前执行双层存在性检测：标准魔数扫描 + （提供密码时）派生魔数扫描，两者任一命中即拒绝。对使用未知密码写入的隐蔽信封（魔数不可见），增加结构启发式扫描（过大的私有块 / COM 段 / uuid Box / PE Overlay），命中时输出醒目警告后继续。

### 多信封移除顺序
同一载体允许叠加多个信封时，`remove` 按定位结果剥离单个信封，并以该信封记录的原宿主 SHA-256 强校验。若还原结果仍含其他信封导致校验失败，错误信息中明确提示"按注入逆序移除"。

---

## 10. 数据结构参考（Rust 实现）

Rust 2024 edition 实现（`rust/`）已落地为主力版本。Go 移植未实施，下表仅保留与 Python 的密码学向量对应关系；结构体定义与 Rust 代码一致（**无 `padding` 字段**）。

### 10.1 数据结构映射

#### 固定头部（Fixed Header, 112 字节）
* **Rust 结构体**：
  ```rust
  #[repr(C, packed)]
  pub struct EnvelopeHeader {
      pub magic_header: [u8; 8],
      pub version: u8,
      pub flags: u8,
      pub strategy_id: u8,
      pub reserved: u8,
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
      // 共 112 字节，其后无 padding
  }
  ```

#### 通用定位尾标（Envelope Trailer, 24 字节）
* **Rust 结构体**：
  ```rust
  #[repr(C, packed)]
  pub struct EnvelopeTrailer {
      pub ube_offset: u64,    // 0x00 (LE)
      pub ube_total_size: u64, // 0x08 (LE)
      pub trailer_crc32: u32,  // 0x10 (LE, stealth 模式经掩码)
      pub trailer_magic: [u8; 4], // 0x14
  }
  ```

### 10.2 密码学与标准库对应矩阵

| 功能项 | Python 实现（已冻结参考） | Rust 对应 Crate |
| :--- | :--- | :--- |
| **PBKDF2** | `hashlib.pbkdf2_hmac` | `pbkdf2` |
| **HKDF** | `hmac` + `hashlib.sha256` | `hkdf` |
| **AES-GCM** | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` | `aes-gcm` |
| **CRC32** | `zlib.crc32` | `crc32fast` |
| **Deflate** | `zlib.compressobj(wbits=-15)` | `flate2::write::DeflateEncoder` |
| **Unicode NFC** | `unicodedata.normalize("NFC", s)` | `unicode-normalization` |

---

## 11. 实证测试与质量矩阵

| 指标项 | 统计值 | 详情与覆盖范围 |
| :--- | :--- | :--- |
| **Rust 单元与集成测试（`cargo test --release`）** | **235 / 235 通过 (100%)** | 覆盖信封编解码、PBKDF2/HKDF 跨语言向量、分块加解密、全部 6 类适配器与 9 种策略、CLI 各子命令、安全拦截、stealth 去指纹、`scan` 黑盒检测器、2026-10-19 两轮代码评审回归（`tests/review_20261019.rs`） |
| **语料批量回归（`batch_corpus`，`#[ignore]`）** | **398 / 398 通过 (100%)** | 对 `temp/testfiles` 全语料按 拒绝/明文/加密/stealth × 4 档载荷尺寸（64B/1KiB/8KiB/128KiB）逐格跑 write→inspect→verify(L1/L2/L3)→read→remove，校验 SHA-256 逐比特一致；可用 `STRHIDE_CORPUS` 指定语料路径 |
| **跨语言兼容** | **单向** | Rust 可读取旧 Python 0.2.0 写入的明文信封；Python 读不了 Rust 默认全加密信封与 `pe_slack`/`pe_codebits` 载体（Python 已冻结，不再补齐） |
| **MediaInfo 合规验证** | **0 Conformance Errors** | MP4 载体使用中立 UUID 与 32/64 位 Box 头，MediaInfo 探测一致性错误为 0 |
| **PDF 大载荷定位可靠性** | **100% 可用** | 经 200KB 不可压缩随机数据实证，增量更新尾部常数时间定位无异常 |
| **Windows 文件并发** | **0 句柄锁死异常** | 句柄作用域退出后再执行文件操作，消除了 `WinError 32` 风险 |
