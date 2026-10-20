# UBE v3 架构演进方案与工程可行性分析报告

> **编制日期**：2026-10-20  
> **状态**：方案评估与可行性设计  
> **适用目标**：`strhide` 统一二进制信封 (Universal Byte Envelope) 协议演进

---

## 一、背景与问题诊断 (Diagnosis of UBE v2.2)

`strhide` 目前使用的载体数据封装标准为 **UBE v2.2**（在 `rust/src/envelope.rs` 中定义），其核心入口结构为固定 112 字节的 `EnvelopeHeader`：

```text
+----------------------+  HEADER_SIZE = 112 字节 (固定)
| magic (8B)           |  标准/伪随机魔数
| version/flags/strat  |  版本(1B), 标志(1B), 策略ID(1B), 预留(1B)
| salt (16B)           |  随机盐
| base_nonce (12B)     |  AEAD 基础 Nonce
| orig_host_size (8B)  |  宿主原始大小
| orig_host_sha256(32B)|  宿主原始 SHA-256
| -------------------- |  -- 上述前 80 字节绑定为 AEAD AAD --
| inject_offset (8B)   |  注入物理偏移
| inject_size (8B)     |  注入物理长度
| patch_offset (4B)    |  宿主指针补丁偏移 (如 ZIP Central Directory)
| orig_patch_val (4B)  |  补丁原始值
| meta_len (4B)        |  元数据密文块长度
| hint_len (4B)        |  密码提示明文长度
+----------------------+
```

### 现行设计的核心结构缺陷

1. **硬编码静态偏移（Rigid Struct Layout）**：
   - 字段位置全部写死（例如 `inject_offset` 必须在偏移 80，`meta_len` 必须在偏移 104）；
   - 无法按需扩展：若引入 Argon2id 密码学参数（`m`, `t`, `p`）、数字签名、后量子公钥或自定义标签，112 字节固定空间无法容纳。
2. **职责严重混杂（Overloaded Concerns）**：
   - 将“密码学协商参数”、“物理宿主特征”、“载体补丁参数”与“载荷长度指示”揉入同一结构；
   - **冗余开销大**：像 MP4、PDF、PE 等多数格式根本不需要 `patch_offset` 与 `orig_patch_val`，但每个信封都必须浪费 8 字节填充零值；而需要扩展时却无可用空间。
3. **明密边界倒错**：
   - 宿主文件哈希（32 字节）与宿主大小（8 字节）在非 `--stealth` 模式下直接暴露在 Header 外层明文中；
   - 理想架构下，除启动解密所必需的参数外，所有宿主及载荷信息均应置于 AEAD 密文内部。

---

## 二、UBE v3 核心设计：双层解耦架构 (Two-Layer Architecture)

借鉴现代密码学协议（如 **TLS 1.3、Age 加密工具、OpenPGP v6**）的最佳实践，v3 采用**“外层极简物理封套 + 内层认证清单 (TLV)”**的双层解耦架构：

```text
========================================================================
【Layer 1: 外层极简物理封套 (Cryptographic Shell)】 - 固定 38~40 字节
  仅负责识别协议套件与启动 AEAD 解密，结构极简且永久稳定。
========================================================================
  [Magic (8B)] [Version (1B)] [CipherSuite (2B)] [Flags (1B)]
  [Salt (16B)] [Nonce (12B)]
========================================================================
                       │
                       ▼ (AEAD 解密 + AAD 认证)
========================================================================
【Layer 2: 内层加密认证清单 (Protected Manifest)】 - 动态可变长 (TLV)
  全密文保护！享受 AEAD 认证防篡改，所有业务与载体属性在此按需扩展。
========================================================================
  [Manifest Total Len (2B)]
  ├── Tag 0x01 (HostInfo):      [Size(8B) + Hash(32B)]
  ├── Tag 0x02 (PatchInfo):     [Offset(4B) + Val(4B)]  (仅在 ZIP/RIFF 等出现)
  ├── Tag 0x03 (PayloadMeta):   [Filename, Size, MIME, Timestamp...]
  ├── Tag 0x04 (PasswordHint):  [UTF-8 String]          (仅在有 hint 时出现)
  ├── Tag 0x05 (KDF-Params):    [Argon2id: m, t, p]     (支持参数微调)
  └── Tag 0xFF (FutureExt):     [未来任意自定义特性]
========================================================================
【Layer 3: 分块加密载荷流 (Chunk-Framed Payload Stream)】
========================================================================
【Trailer: 物理尾部 (24B)】 [ube_offset(8B)] [ube_size(8B)] [magic(4B)] [crc(4B)]
========================================================================
```

### 1. 密码学套件化（Cipher Suite Registry）
使用 2 字节的 `cipher_suite: u16` 统一取代零散的算法标志位：
- `0x0001`：`AES-256-GCM + PBKDF2-100k + SHA-256`（兼容 v2 模式）
- `0x0002`：`AES-256-GCM + Argon2id(64M, t=2, p=2) + SHA-256`（**v3 现代基准**）
- `0x0003`：`ChaCha20-Poly1305 + Argon2id(32M, t=2, p=2) + BLAKE3`（跨平台纯软加速套件）
- `0x0004`：`Post-Quantum ML-KEM + AES-GCM`（未来后量子扩展预留）

### 2. 紧凑二进制 TLV 编码与关键位机制（Critical Bit）
每个 Manifest 属性由三元组组成：`[Tag: 1 字节] [Length: 1~2 字节] [Value: Length 字节]`。
- **Critical Bit 规则（最高位 `0x80`）**：
  - 若解密端遇到未知但**未置位 `0x80`** 的 Tag（如文件创建时间、非关键扩展），**安全跳过继续解密**；
  - 若解密端遇到未知且**置位 `0x80`** 的 Tag（关键扩展，如新增了必需的二次前置解码），则明确终止并提示升级客户端；
  - 该机制保障协议长达数十年的向前与向后自适应扩展。

---

## 三、空间占用与载体容量对比测算 (Overhead & Capacity Impact)

在微型载体（如 PE 节间填充、机器指令信道）中，信封自身的开销直接决定了“能否隐藏成功”。

### 1. 封装开销定量对比表

| 组成部分 | 现行 UBE v2.2 | 现代 UBE v3.0 | 空间差值与优化点 |
| :--- | :---: | :---: | :--- |
| **外层 Header** | **112 字节** | **40 字节** | **大幅削减 72 字节** |
| **宿主特征** (`size/sha256`) | 40 字节 (明文暴露) | 移入内层密文 | 外层零宿主指纹泄露 |
| **补丁字段** (`patch_offset/val`)| 8 字节 (强行占满) | 按需 TLV (大多数格式为 0) | MP4/PDF/PE **再省 8 字节** |
| **元数据与 AEAD Tag** | 57 字节 (独立块 + 16B Tag) | 合并为统一 Manifest (单 Tag) | **省去一次 16 字节 Tag 开销** |
| **尾部 Trailer** | 24 字节 | 24 字节 | 保持一致 |
| **最小封装总开销 (Overhead)** | **213 字节** | **约 130 ~ 145 字节** | **整体缩减 70 ~ 85 字节 (-35% ~ -40%)** |

### 2. 对极端受限载体的关键收益
- **`pe_slack`（PE 节填充）**：
  - Windows PE 的节对其空间通常只有 100~500 字节。
  - v2 门槛为 214 字节，大量只有 150~200 字节空闲填充的 PE 节直接被拒；
  - v3 将门槛降至 ~130 字节，**可用节填充数量增加 40% 以上**。
- **`pe_codebits`（PE 指令编码位信道）**：
  - 每嵌入 1 字节需要消耗 8 个 ModR/M 冗余指令。
  - 封装减少 80 字节，直接省下 **640 条指令要求**（从 1712 条降至 1072 条），使原本无法嵌入的中小型可执行文件（30KB~100KB）全面变为可用载体。

---

## 四、密码学实测：PBKDF2 vs Argon2id 性能与选型

为验证 v3 引入 Argon2id 的必要性与性能开销，在真实测试平台（AMD Ryzen / Windows 10 x86_64，Release 优化模式）运行密码学探针评测：

### 1. 实测基准数据对比表

| 算法与配置 | 内存消耗 | 时间轮数 ($t$) | 并发分道 ($p$) | 平均耗时 (Mean) | 相对耗时 (vs PBKDF2-100k) |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **PBKDF2 100k (现行现状)** | **~0 MB** | **100k iters**| **1** | **12.94 ms** | **1.00x (基准)** |
| PBKDF2 600k (OWASP 2023) | ~0 MB | 600k iters | 1 | 76.82 ms | 5.93x (慢 5.9 倍) |
| **Argon2id (16M, t=2, p=2)** | 16 MB | 2 | 2 | **15.61 ms** | **1.21x (基本持平)** |
| **Argon2id (32M, t=2, p=2)** | 32 MB | 2 | 2 | **31.70 ms** | **2.45x (~31 毫秒)** |
| **Argon2id (64M, t=2, p=2)** | 64 MB | 2 | 2 | **69.06 ms** | **5.34x (慢 5.3 倍)** |
| Argon2id (64M, t=3, p=4) | 64 MB | 3 | 4 | **97.64 ms** | 7.54x (慢 7.5 倍) |

### 2. 选型结论
1. **交互无感延迟**：Argon2id (64M, t=2) 耗时约 69 ms，**完全处于人类交互零感知阈值 (< 100 ms)**，肉眼感觉依然秒开；
2. **防 GPU 暴力破解碾压**：PBKDF2 内存消耗为 0，GPU 矿机可每秒尝试上亿次；Argon2id 单次强制占用 32~64MB 显存，使并行暴力破解吞吐量暴跌数万倍；
3. **套件默认推荐**：v3 默认采用 `Argon2id (m=64M, t=2, p=2)` 作为高安全基准，提供 `m=32M` 作为快速选项。

---

## 五、全格式策略与 `--stealth` 模式兼容性评估

### 1. 载体适配器（Adapters）几乎零改动
排查 `adapters/` 目录发现：所有格式适配器（PNG, JPEG, MP4, PDF, ZIP, PE 等）均通过通用 Trait 操作字节流：
```rust
fn inject(&self, host_in, ube_in, out, strategy) -> Result<(inject_offset, inject_size, patch_offset, orig_patch_val)>;
```
适配器仅负责定位与切分载体、注入数据流，**完全不解析 Header 内部结构**。因此升级 v3 不需要修改底层格式编解码逻辑。

### 2. `--stealth` 模式解掩码与版本自适应
在 `--stealth` 模式下，载体表面没有明文魔数或版本号。v3 的定位与提取生命周期如下：
1. **物理定位**：沿用密码与常量盐派生 `trailer_magic` 查找文件尾部，逻辑与 v2 100% 相同；
2. **内存解掩码**：定位到 Header 后，读取前 40 字节，利用派生掩码异或解开第 8 字节（`Version`）：
   - 若解开值为 `0x02`：**平滑进入 v2 解密通道**；
   - 若解开值为 `0x03`：**进入 v3 现代解密通道**；
   - 若解开值非法：表明密码错误，直接安全退出；
3. **零 Oracle 泄漏**：全过程均在内存异或后验证 AEAD Tag，杜绝侧信道泄露。

---

## 六、安全与可靠性保障边界 (Security & Robustness)

1. **AEAD AAD 强绑定（防降级攻击）**：
   - v3 的 Outer Shell 全部字段（`Magic`, `Version`, `CipherSuite`, `Salt`, `Nonce`）全部纳入 AEAD AAD 认证范围；
   - 攻击者无法将文件外层的 `v3` 恶意篡改为 `v2` 或篡改 `CipherSuite`，否则 AEAD Tag 验证立即失败。
2. **防解析炸弹（Safe TLV Limits）**：
   - 内层 TLV 解析器设置硬性防御门限（Tag 数量 $\le 32$，单个属性长度受限，总 Manifest $\le 4\text{KB}$）；
   - 杜绝恶意构造的载荷导致解析死循环或内存耗尽。
3. **统一错误反馈（Unified Error Masking）**：
   - 无论是解密失败还是内部 TLV 格式错误，一律统一对外返回 `Password verification failed`，绝不向终端回显内部语法错误。

---

## 七、工程实施与改动量拆解

| 文件路径 | 影响程度 | 具体改动内容 | 预估代码量 |
| :--- | :---: | :--- | :---: |
| [rust/src/envelope.rs](file:///C:/Home/Projects/strhide/rust/src/envelope.rs) | **高** | 1. 增加 `CipherSuite` 枚举与 `EnvelopeHeaderV3`<br>2. 实现轻量紧凑 TLV 解析器（约 80 行纯 Rust）<br>3. 保留 `unpack_v2` 确保向下兼容读取 | ~250 行 |
| [rust/src/crypto.rs](file:///C:/Home/Projects/strhide/rust/src/crypto.rs) | **中** | 1. 引入 `argon2 = "0.5"` 依赖<br>2. 根据 `CipherSuite` 派发 key 派生逻辑<br>3. AAD 生成逻辑支持 V3 Shell | ~120 行 |
| [rust/src/engine.rs](file:///C:/Home/Projects/strhide/rust/src/engine.rs) | **高** | 1. `write_carrier`：打包流程改用 V3 结构与新空间预算<br>2. `read/extract/restore`：根据版本号自适应分流 v2/v3 解析通道 | ~200 行 |
| `rust/src/adapters/` | **极低** | 仅调整 `pe_codebits` 等处的最小容量校验门槛常量 | ~10 行 |
| `rust/tests/` | **中** | 增加跨版本兼容性测试用例（断言新版 100% 正确读取旧版载体） | ~120 行 |
| **合计** | **可控** | **代码影响高度集中在 3 个文件，改动总量约 700 行** | **可分步实施** |

---

## 八、演进路线规划建议

1. **阶段一（短期，非破坏性）**：
   - 在现行 v2.2 的 `EnvelopeHeader` 中复用 `reserved: u8`（偏移 11）作为 `kdf_type`，低成本引入 Argon2id 支持，不改变 112 字节外形。
2. **阶段二（中长期，大版本演进）**：
   - 全面落地本文档设计的 **UBE v3 双层 TLV 架构**；
   - 写入时默认生成 v3 信封，读取时自动无缝兼容 v2；
   - 彻底解除未来 10 年协议属性扩展与算法迭代的包袱。
