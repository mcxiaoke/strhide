# strhide 结构域库使用者指南

| 项 | 内容 |
| :--- | :--- |
| 文档编号 | `STRUCT-GUIDE-20261025` |
| 基线 | commit `ddb409c`（master，crate 版本 0.7.1）；其后 `d179e1f`（提交路径 fsync/原子写内部实现）与 `3dbdda2`（内容域 PNG 尾部保留）不改变本文所描述的任何结构域接口签名、参数与常量 |
| 范围 | 结构域（structure domain）lib 公开接口与全部参数：`engine` / `facade` / `params` / `envelope` / `errors` / `router` / `rejection` / `adapters` / `commit` / `sniff` 模块 |
| 术语 | **结构域** = 把 UBE 信封注入载体容器结构缝隙的 write/read/restore/inspect/verify 五动词；**内容域** = 像素/DCT/CABAC 隐写（`embed`/`extract`/`probe`），仅在本指南与结构域交界处（`inspect` 容量探测、`Profile` 共享）提及，详见 [`heic_hevc_steganography_guide.md`](heic_hevc_steganography_guide.md) 等内容域文档 |
| 姊妹篇 | 参数一致性评审见 [`structure_domain_params_audit_20261025.md`](structure_domain_params_audit_20261025.md)；健壮性缺陷见 [`structure_domain_code_review_20261025.md`](structure_domain_code_review_20261025.md) |

---

## 目录

1. [三种入口形态](#1-三种入口形态)
2. [write — 注入信封](#2-write--注入信封)
3. [read — 提取载荷](#3-read--提取载荷)
4. [restore / remove — 还原载体](#4-restore--remove--还原载体)
5. [inspect — 只读巡检](#5-inspect--只读巡检)
6. [verify — 三级校验](#6-verify--三级校验)
7. [参数系统：LocalParams 与 Profile](#7-参数系统localparams-与-profile)
8. [载体格式与策略](#8-载体格式与策略)
9. [UBE v2.2 线上格式与公开常量](#9-ube-v22-线上格式与公开常量)
10. [错误处理](#10-错误处理)
11. [预写拒绝检查（rejection）](#11-预写拒绝检查rejection)
12. [CLI ↔ 库参数映射](#12-cli--库参数映射)
13. [场景配方](#13-场景配方)
14. [陷阱与注意事项清单](#14-陷阱与注意事项清单)

---

## 1. 三种入口形态

结构域的同一组操作有三个入口层，行为完全一致（同一套 `write_core` / `read_core` / `remove_core` / `inspect_core` / `verify_core`），区别只在配置如何传入：

| 入口 | 适用 | 特点 |
| :--- | :--- | :--- |
| **`StrHide` 门面**（`facade` 模块） | **推荐**。宿主程序绑定一个私有方言 | 构造时绑定 `Profile` + `LocalParams`，动词是普通方法；`Copy`，`const` 可构造 |
| `engine` 自由函数 | 单次调用、或不依赖门面的场景 | 每次调用显式传 `Profile`（`*_with_profile` / `*_bytes`）或用默认官方方言的便捷版 |
| CLI（`run_cli_from`） | 嵌入方想复用自己的命令行 | `StrHide::run_cli_from(argv)` 返回退出码而不调用 `process::exit` |

feature 门（`Cargo.toml`）：`engine`（默认开）提供 `engine` / `params` / `facade` / `envelope` / `router` / `rejection` / `adapters` / `commit` 模块；`sniff` / `crypto` / `errors` 无门。`facade` 的内容域方法需要 `stego` feature，`run_cli_from` 需要 `cli` feature。

### 1.1 门面方法总表（结构域）

```rust
use strhide::facade::StrHide;

// 官方方言 + 默认写行为
const ENGINE: StrHide = StrHide::new();
// 私有方言（编译期，零运行时开销）
const PRIVATE: StrHide = StrHide::new()
    .with_profile(strhide::params::Profile::new().with_default_secret("my-key"));
```

| 方法（结构域 · 路径） | 签名 | 等价自由函数 |
| :--- | :--- | :--- |
| `write` | `(&self, carrier: &Path, source: PayloadSource<'_>, options: &WriteOptions<'_>) -> Result<WriteResult, StrHideError>` | `write_carrier_with(carrier, source, options, &self.local, &self.profile)` |
| `read` | `(&self, carrier: &Path, output: Option<&Path>, password: Option<&str>) -> Result<ReadResult, StrHideError>` | `read_carrier_with_profile(carrier, output, password, false, &self.profile)` |
| `restore` | `(&self, carrier: &Path, output: Option<&Path>, password: Option<&str>, backup: bool) -> Result<RemoveResult, StrHideError>` | `remove_carrier_with_options(carrier, output, password, backup, &self.profile, false)` |
| `inspect` | `(&self, carrier: &Path, password: Option<&str>) -> Result<InspectResult, StrHideError>` | `inspect_carrier_with(carrier, password, &self.profile)` |
| `verify` | `(&self, carrier: &Path, password: Option<&str>) -> Result<VerifyResult, StrHideError>` | `verify_carrier_with(carrier, password, &self.profile)` |

| 方法（结构域 · 内存字节） | 签名 |
| :--- | :--- |
| `write_bytes` | `(&self, carrier: &[u8], source: PayloadSource<'_>, options: &WriteOptions<'_>) -> Result<(Vec<u8>, WriteResult), StrHideError>` |
| `read_bytes` | `(&self, carrier: &[u8], password: Option<&str>) -> Result<ReadResult, StrHideError>` |
| `restore_bytes` | `(&self, carrier: &[u8], password: Option<&str>) -> Result<(Vec<u8>, RemoveResult), StrHideError>` |
| `inspect_bytes` | `(&self, carrier: &[u8], password: Option<&str>) -> Result<InspectResult, StrHideError>` |
| `verify_bytes` | `(&self, carrier: &[u8], password: Option<&str>) -> Result<VerifyResult, StrHideError>` |

配置访问器：`profile()` / `local_params()`；派生变体：`with_profile(Profile)` / `with_local_params(LocalParams)`（consume `self`，返回新 `StrHide`，原值不变）。

**注意**：门面 `read` / `restore` 把 `overwrite` 固定为 `false`（输出文件已存在时报 `Rejection`）。需要覆盖输出时，用自由函数 `read_carrier_with(…, overwrite = true)` 或 `remove_carrier_with_options(…, overwrite = true)`（见 §3、§4 与评审报告 §P2-5）。

### 1.2 engine 自由函数总表

```rust
use strhide::engine::{self, PayloadSource, WriteOptions};
use strhide::params::{LocalParams, Profile};
```

| 动词 | 便捷版（官方方言 / 默认参数） | 完整版 |
| :--- | :--- | :--- |
| write | `write_carrier(carrier_path, source, options)` | `write_carrier_with(carrier_path, source, options, local, profile)`<br>`write_carrier_bytes(carrier, source, options, local, profile) -> (Vec<u8>, WriteResult)` |
| read | `read_carrier(carrier_path, output_path, password)` | `read_carrier_with(carrier_path, output_path, password, overwrite)`<br>`read_carrier_with_profile(carrier_path, output_path, password, overwrite, profile)`<br>`read_carrier_bytes(carrier, password, profile)` |
| remove/restore | `remove_carrier(carrier_path, output_path, password, backup)` | `remove_carrier_with(carrier_path, output_path, password, backup, profile)`<br>`remove_carrier_with_options(carrier_path, output_path, password, backup, profile, overwrite)`<br>`remove_carrier_bytes(carrier, password, profile)` |
| inspect | `inspect_carrier(carrier_path, password)` | `inspect_carrier_with(carrier_path, password, profile)`<br>`inspect_carrier_bytes(carrier, password, profile)` |
| verify | `verify_carrier(carrier_path, password)` | `verify_carrier_with(carrier_path, password, profile)`<br>`verify_carrier_bytes(carrier, password, profile)` |

其他公开函数：`verify_passed(&VerifyResult) -> bool`、`sanitize_filename(&str) -> String`；re-export：`same_file`、`commit_carrier_bytes`（自 `commit` 模块）、`STEALTH_DOMAIN`（自 `params`）。

**不对称提醒**：路径版有便捷函数（内部用 `Profile::default()` / `LocalParams::default()`）；**内存版（`*_bytes`）没有便捷版**，`Profile` 一律必填（`write_carrier_bytes` 还必填 `LocalParams`），不想私有方言就显式传 `&Profile::default()`（见评审报告 §P3-2）。

---

## 2. write — 注入信封

### 2.1 `PayloadSource`（载荷来源，五选一）

```rust
pub enum PayloadSource<'a> {
    Bytes(&'a [u8]),
    File(&'a Path),
    Text(&'a str),
    Stdin,
    Buffered { data: &'a [u8], filename: &'a str, is_file: bool },
}
```

| 变体 | 载荷字节 | 存储的 metadata 文件名 | `FLAG_IS_FILE` | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `Bytes(&b)` | 直接给定 | `"payload.bin"` | **true** | inline 字节按"文件"标记；读回后 `ReadResult.is_file == true`、`filename == "payload.bin"` |
| `File(&p)` | 读整个文件 | 文件 basename（不可解析时回退 `"payload.bin"`） | true | |
| `Text(&s)` | NFC 归一化后的 UTF-8 | `""`（空） | false | 纯文本语义；读回 `is_file == false` |
| `Stdin` | 读 stdin 至 EOF | `""` | false | **只可消费一次**；批量写载体时先 `into_buffered()` 一次，再逐载体传 `Buffered` |
| `Buffered { .. }` | 调用方给出 | 调用方给出 | 调用方给出 | 批量优化：载荷只物化一次、对每个载体复用；CLI 的 write/embed 内部全部走这个变体 |

`into_buffered(self) -> Result<(Vec<u8>, String, bool), StrHideError>` 是"来源 → (字节, 文件名, is_file)"的唯一物化点。

### 2.2 `WriteOptions`（七个字段）

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteOptions<'a> {
    pub output_path: Option<&'a Path>,
    pub password: Option<&'a str>,
    pub password_hint: Option<&'a str>,
    pub strategy: &'a str,
    pub stealth: bool,
    pub preserve_time: bool,
    pub backup: bool,
}
```

| 字段 | 类型 | 默认 | 行为 |
| :--- | :--- | :--- | :--- |
| `output_path` | `Option<&Path>` | `None` | `None` = **原地覆盖 carrier 本身**（这就是库默认，等价 CLI 的 `--in-place`）；`Some(p)` = 结果写到 `p`，原 carrier 不动。`write_carrier_bytes` 不接受该字段（传 `Some` 直接报 `General` 错误） |
| `password` | `Option<&str>` | `None` | 用户密码：置 `FLAG_ENCRYPTED`，PBKDF2(100k)+HKDF 派生 payload/meta/header-mask 三把子密钥。`None` 时载荷用 `Profile::secret()`（官方方言即内建公开常量）密封——**仍然加密，但人人可解** |
| `password_hint` | `Option<&str>` | `None` | 密码提示，NFC 归一化后 ≤ 1024 字节（超限报 `General`）；置 `FLAG_HAS_HINT`，明文存于信封。**与 `stealth = true` 互斥**（同传报 `General`） |
| `strategy` | `&str` | `"auto"` | 策略名（§8 的注册表）或 `"auto"`。未知名/当前载体不支持时报 `General` |
| `stealth` | `bool` | `false` | 隐匿模式：header/trailer magic、header 掩码、trailer CRC 掩码全部由密码派生，信封不可被 magic 扫描发现。**必须有 `password`**，否则报 `General` |
| `preserve_time` | `bool` | `true` | 把原 carrier 的 atime/mtime 克隆到结果文件上（文件路径版有效；`write_carrier_bytes` 忽略） |
| `backup` | `bool` | `true` | 原地写时先保留 `<carrier>.bak`（已存在则降级 `<carrier>.bak-<unix秒>`，再冲突加 pid/随机后缀）。`write_carrier_bytes` 忽略（原字节本来就在调用方手里） |

**默认语义与 CLI 不同**：库默认 = CLI `--in-place` 的行为（原地覆盖 + `.bak` 备份）。CLI 不带 `--in-place` 时默认写 `<stem>-out.<ext>` 新文件。这是库与 CLI 最重要的默认差异（评审报告 §P2-3）。

**目标覆盖语义**：文件版写路径对 `output_path`（或原地时的 carrier）**不检查目标是否已存在**——`fs::rename` 直接替换。`read` / `restore` 的"拒绝覆盖已存在输出"保护（§3、§4）在写路径上没有对应物；CLI 的 `--overwrite` 确认在 CLI 层实现（评审报告 §P2-5）。

### 2.3 write 的执行流程与行为细节

1. **参数前置校验**：`LocalParams::validate()`；stealth 无密码、hint 与 stealth 并用、hint 超限均在此 fail-fast。
2. **拒绝检查**（仅文件版）：按 `LocalParams.rejection` 档位运行（§11）；bytes 版只跑内容级检查（签名容器拒绝）。
3. **占用检测**：三重 locate 扫描（本方言 magic → 官方 magic（私有方言时）→ 本密码派生的 stealth magic），已含信封报 `General`（"Carrier already contains hidden data"）；均未命中但载体有信封状结构（`suspicious_structures`）时**不拒绝**，只把警告合并进 `WriteResult.warning`。
4. **压缩决策**：`LocalParams.compression` 控制（§7.1）；raw-deflate，仅当节省 ≥ 2% 时保留压缩流（`Auto` 档）。
5. **精确容量预算**：注入前精确计算 UBE 总长（含每 chunk 20 字节开销），auto 策略据此选型；随后与真实密文长度交叉校验，不一致即内部错误。
6. **auto 选型**：单次决策、无自动回退——`choose_auto_strategy` 返回"已验证可注入"的策略（P2/P3 系列修复后各适配器 auto 均考虑 `ube_size` 与可注入性；显式指定策略时无回退）。
7. **注入**：写 `<target>.strhide.tmp`（TmpGuard RAII，中途出错自动清理）；补丁 header/trailer 真实偏移；`finalize`（如 PNG 重算 chunk CRC）。
8. **写后自检**：对产物执行一次 locate 回读，失败即报 `General` 拒绝提交——杜绝"写成功读不回"。
9. **提交**：原地写时先 `.bak`；原子 rename；恢复权限；克隆时间戳（`preserve_time`）。

### 2.4 `WriteResult`

```rust
pub struct WriteResult {
    pub status: String,            // 恒 "success"（Ok 时）
    pub carrier: String,           // 目标路径；内存版为 "<memory>"
    pub format: String,            // "PNG"/"JPEG"/"WebP"/"HEIF"/"MP4"/"WAV"/"MKV"/"ZIP"/"PDF"/"PE"
    pub strategy: String,          // 实际使用的策略名
    pub strategy_note: Option<String>,   // 策略说明（如自动回退 eof 的原因）
    pub raw_size: u64,             // 未压缩载荷大小
    pub ube_size: u64,             // 信封总字节数
    pub is_encrypted: bool,        // 是否用了用户密码（FLAG_ENCRYPTED）
    pub is_stealth: bool,          // 是否 stealth 模式
    pub password_hint: Option<String>,   // 回显写入时的 hint
    pub backup_file: Option<String>,     // 原地写保留的 .bak 路径
    pub warning: Option<String>,   // 非致命警告（信封 > 载体 50% 的膨胀警告；疑似已有 stealth 信封的结构警告；两者可拼接）
}
```

`WriteResult` / `InspectResult` / `VerifyResult` / `RemoveResult` 均 `Serialize`（serde，snake_case 字段名），CLI 的 `--json` 直接输出同一结构。

---

## 3. read — 提取载荷

### 3.1 签名与输出

```rust
pub fn read_carrier(carrier_path: &Path, output_path: Option<&Path>, password: Option<&str>)
    -> Result<ReadResult, StrHideError>;
pub fn read_carrier_with(carrier_path: &Path, output_path: Option<&Path>,
    password: Option<&str>, overwrite: bool) -> Result<ReadResult, StrHideError>;
pub fn read_carrier_bytes(carrier: &[u8], password: Option<&str>, profile: &Profile)
    -> Result<ReadResult, StrHideError>;
```

`output_path` 三态：

| 值 | 行为 |
| :--- | :--- |
| `None` | 只返回内存数据，`written_file == None` |
| `Some(文件)` | 写到该文件；已存在且 `overwrite == false` 时报 `Rejection` |
| `Some(目录)` | 用 metadata 里的文件名（经 `sanitize_filename` 清洗；空名回退 `extracted.bin`）落在目录内 |

### 3.2 密码规则（读侧唯一要记的东西）

- 信封带 `FLAG_ENCRYPTED`（写入时给了密码）→ 必须传同一个密码；缺失时报 `PasswordWithHint`（hint 作为**结构化字段**附带，用 `StrHideError::hint()` 提取，不要从消息文本解析）。
- 信封无 `FLAG_ENCRYPTED` → 不需要密码：解密密钥来自 `Profile::secret()`（官方方言 = 内建公开常量，任何 strhide 都能读；私有方言 = 该 Profile 的 `default_secret`）。
- 密码错误/方言不匹配/无信封三种失败统一表现为 `NoHiddenData` 或 `Password`——**反 oracle 设计**，不可区分"是否有信封"（stealth 信封对无密码读者物理上不可见）。

### 3.3 `ReadResult`

```rust
pub struct ReadResult {
    pub carrier: String,      // 读取来源；内存版 "<memory>"
    pub data: Vec<u8>,        // 解密、解压后的载荷（SHA-256 已对拍）
    pub is_file: bool,        // FLAG_IS_FILE（注意：PayloadSource::Bytes 写入的信封也是 true）
    pub is_encrypted: bool,   // FLAG_ENCRYPTED（用户密码）；false 表示内建/私有 secret 密封
    pub filename: String,     // metadata 文件名；Text/Stdin 载荷为空串
    pub raw_size: u64,        // 未压缩载荷大小
    pub written_file: Option<String>,  // 实际写出的文件路径
}
```

---

## 4. restore / remove — 还原载体

> 库函数名是 `remove_carrier*`，CLI 命令与门面方法名是 `restore`——同一操作：剥离信封并恢复原始载体。

### 4.1 签名

```rust
pub fn remove_carrier(carrier_path: &Path, output_path: Option<&Path>,
    password: Option<&str>, backup: bool) -> Result<RemoveResult, StrHideError>;
pub fn remove_carrier_with(carrier_path: &Path, output_path: Option<&Path>,
    password: Option<&str>, backup: bool, profile: &Profile) -> Result<RemoveResult, StrHideError>;
pub fn remove_carrier_with_options(carrier_path: &Path, output_path: Option<&Path>,
    password: Option<&str>, backup: bool, profile: &Profile, overwrite: bool)
    -> Result<RemoveResult, StrHideError>;
pub fn remove_carrier_bytes(carrier: &[u8], password: Option<&str>, profile: &Profile)
    -> Result<(Vec<u8>, RemoveResult), StrHideError>;
```

| 参数 | 行为 |
| :--- | :--- |
| `output_path` | `None` = 原地还原（carrier 被替换为原始内容）；`Some(p)` = 还原结果写到 `p`，原 carrier 不动 |
| `password` | 仅 stealth 信封需要；非 stealth 信封无论是否给密码都能剥离 |
| `backup` | 原地还原时保留 `<carrier>.bak`（与 write 的备份同一条冲突降级链） |
| `overwrite` | 仅 `remove_carrier_with_options` 有：`output_path` 指向已存在的**不同**文件时，`false` 报 `Rejection` 拒绝（安全默认），`true` 允许替换。原地还原（无 `output_path`）不受此参数影响 |

### 4.2 完整性保证

还原结果先与信封 header 记录的 `orig_host_size` / `orig_host_sha256` 对拍：

- 匹配 → 提交（原子 rename），`verified_identical == true`；
- 不匹配 → 丢弃产物，报 `RestoreMismatch`，消息带诊断：最常见的成因是**同 一载体叠了两个信封**（还原时必须按注入的逆序移除：先移最后写的那个）。诊断逻辑会主动在还原产物里再扫一遍信封以确认。

### 4.3 `RemoveResult`

```rust
pub struct RemoveResult {
    pub status: String,              // "success"
    pub carrier: String,             // 还原结果路径；内存版 "<memory>"
    pub restored_size: u64,          // 还原后大小（== 信封记录的 orig_host_size）
    pub restored_sha256: String,     // 还原后 SHA-256（hex）
    pub verified_identical: bool,    // 恒 true（Ok 路径）
    pub backup_file: Option<String>, // 原地还原保留的 .bak
}
```

---

## 5. inspect — 只读巡检

```rust
pub fn inspect_carrier(carrier_path: &Path, password: Option<&str>)
    -> Result<InspectResult, StrHideError>;
pub fn inspect_carrier_with(carrier_path: &Path, password: Option<&str>, profile: &Profile)
    -> Result<InspectResult, StrHideError>;
pub fn inspect_carrier_bytes(carrier: &[u8], password: Option<&str>, profile: &Profile)
    -> Result<InspectResult, StrHideError>;
```

**永不修改载体**。与 read/restore 不同：**无信封不是错误**，返回 `Ok` 且 `has_hidden_data == false`、其余信封字段为 `None`（方言不匹配的信封同样表现为"无信封"——私有方言对官方读者刻意不可见）。

### 5.1 `InspectResult` 全字段

| 字段 | 类型 | 说明 |
| :--- | :--- | :--- |
| `carrier` | `String` | 巡检对象；内存版 `"<memory>"` |
| `format` | `String` | 侦测到的格式 |
| `has_hidden_data` | `bool` | 是否定位到信封（标准或"该密码的 stealth 信封"） |
| `strategy` | `Option<String>` | 信封写入时的策略（header `strategy_id` 反查；`pe_codebits` 类散布策略以 locate 实际策略为准） |
| `ube_offset` | `Option<u64>` | 信封起始偏移（散布策略为虚拟偏移） |
| `ube_total_size` | `Option<u64>` | 信封总字节数 |
| `is_encrypted` | `Option<bool>` | FLAG_ENCRYPTED |
| `is_compressed` | `Option<bool>` | FLAG_COMPRESSED |
| `is_stealth` | `Option<bool>` | FLAG_STEALTH |
| `password_hint` | `Option<String>` | 信封内存储的密码提示 |
| `orig_host_size` / `orig_host_sha256` | `Option<u64>` / `Option<String>` | 原始载体大小 / SHA-256（hex） |
| `metadata` | `Option<serde_json::Value>` | 解密后的 metadata（filename/raw_size/raw_sha256/created_at）。无密码信封总能解；带密码信封在密码正确时解出、错误时为 `{"error": "Invalid password"}`、未给密码时为 `None` |
| `strategies` | `Vec<StrategyCapacity>` | **恒有值**（含已有信封的载体）：每种策略对当前载体的容量与可用性，按推荐优先序 |
| `content_stego_capacity` | `Option<StegoCapacityInfo>`（`stego` feature） | 内容域（像素/DCT/CABAC）容量探测；PNG/JPEG/HEIF 载体才有，载体 > 512 MiB 时省略（探测需整图解码，有界读取） |

`StrategyCapacity`（`adapters` 模块定义）：

| 字段 | 说明 |
| :--- | :--- |
| `strategy: String` | 策略名 |
| `capacity_bytes: Option<u64>` | 精确上限；`None` 表示无固定上限（文件增长）或载体相关（看 `limit` 文本与 `inspect` 实测） |
| `available: bool` | 当前载体上结构可用（静态查询时为格式能力而非具体载体判定） |
| `limit: String` | 人读的限制描述（如 `"≤ 2,147,483,647 B (2 GiB - 1)"`、`"carrier-dependent (4 GiB - EOCD offset)"`） |
| `note: Option<String>` | 通道行为/回退提示等细节 |

---

## 6. verify — 三级校验

```rust
pub fn verify_carrier(carrier_path: &Path, password: Option<&str>) -> Result<VerifyResult, StrHideError>;
pub fn verify_carrier_with(carrier_path: &Path, password: Option<&str>, profile: &Profile)
    -> Result<VerifyResult, StrHideError>;
pub fn verify_carrier_bytes(carrier: &[u8], password: Option<&str>, profile: &Profile)
    -> Result<VerifyResult, StrHideError>;
pub fn verify_passed(res: &VerifyResult) -> bool;   // 可作为门禁判定
```

| 级别 | 字段 | 内容 | 需要 |
| :--- | :--- | :--- | :--- |
| Level 1 | `level1_host` | 宿主容器结构完好（PNG CRC 链、ZIP 中央目录、PE 头……） | 无 |
| Level 2 | `level2_envelope` | 信封定位 + header 解包 + 字段范围校验 + trailer magic/CRC + 边界自洽 | 方言（Profile）一致；stealth 需密码 |
| Level 3 | `level3_crypto` | 载荷解密 + SHA-256 对拍（流式，≤ 1 GiB 上限，约 4 MiB 内存） | 非 `FLAG_ENCRYPTED`，或给了密码 |

每个级别是一个 `LevelStatus { ok: bool, detail: String, skipped: bool }`：

- `skipped == true` 表示"无法尝试"（Level 3 需要密码但没给）——**不是通过也不是失败**；
- `verify_passed` = L1 且 L2 通过，且 L3 通过**或** skipped。跑过且失败（错密码、载荷损坏）才算失败——这使 verify 可以当门禁用。

无信封的载体：返回 `Ok`，L1 照常报告，L2 = fail（"No envelope found"），L3 = skipped；`verify_passed == false`。

---

## 7. 参数系统：LocalParams 与 Profile

`params` 模块把参数按"**谁必须知道**"分成正交的两类：

| 类 | 类型 | 语义 | 传错后果 |
| :--- | :--- | :--- | :--- |
| **L 类**（writer-only） | `LocalParams` | 只影响写方行为，读方从信封自描述 | 永远安全——随每次 write 随意变化 |
| **P 类**（方言） | `Profile` | 不进信封、读写必须一致的秘密约定 | 刻意的静默失败：表现为 `NoHiddenData`（stealth 场景表现为"看不见"） |

两类都是 `#[non_exhaustive]` + `const fn` builder（下游只能用 `default()`/`new()` 加 `with_*` 链式构造，或逐字段赋值），全部 `Copy`，全字段 `'static` 借用或 `Copy` 值——**整个方言可以声明为 `const`**。

### 7.1 `LocalParams`（三个字段）

```rust
pub struct LocalParams {
    pub chunk_size: usize,                 // 默认 2 MiB（CHUNK_SIZE），最大 64 MiB（MAX_CHUNK_SIZE）
    pub compression: CompressionStrategy,  // 默认 Auto
    pub rejection: RejectionPolicy,        // 默认 Strict
}
```

| 字段 | 取值 | 说明 |
| :--- | :--- | :--- |
| `chunk_size` | `(0, 64 MiB]` | AEAD 分块的明文字节数。读方**不需要**这个值：chunk 自带 4 字节长度前缀，末 chunk 由字节预算界定。每 chunk 固定开销 20 B（4 长度 + 16 tag）。越界（0 或 > 64 MiB）在 `validate()` 报 `General` |
| `compression` | `CompressionStrategy::Auto`（默认，省 ≥ 2% 才压缩，level 6）<br>`CompressionStrategy::Never`<br>`CompressionStrategy::Always { level: u32 }`（0..=9，> 9 报错） | 写方决定；读方只看 `FLAG_COMPRESSED`，永远能解。常量：`DEFAULT_COMPRESSION_LEVEL = 6`、`MAX_COMPRESSION_LEVEL = 9`、`AUTO_COMPRESSION_SAVING_PERCENT = 2`（判定式：`comp_len * 100 < raw_len * 98`） |
| `rejection` | `RejectionPolicy::Strict`（默认，全部检查）<br>`RejectionPolicy::ContentOnly`（仅签名类内容检查，跳过文件系统检查）<br>`RejectionPolicy::Skip`（全关，调用方自负） | 见 §11。**注意**：`write_carrier_bytes` 无法做文件系统检查，`ContentOnly` 与 `Strict` 在该入口行为相同（只有 `Skip` 有差异） |

方法：`new()`（const）、`with_chunk_size` / `with_compression` / `with_rejection`（const builder）、`validate()`。

### 7.2 `Profile`（私有方言，读写必须一致）

```rust
pub struct Profile {
    pub default_secret: Option<&'static str>,      // 结构域：无密码信封的密钥
    pub stealth_domain: Option<&'static [u8]>,     // 结构域：stealth magic 派生的 HKDF 域
    pub magic: Option<MagicPair>,                  // 结构域：自定义 header/trailer magic
    pub stego: StegoProfile,                       // 内容域半区（secret/domain/jpeg/png/hevc）
}
```

| 字段 | 默认 | 影响 |
| :--- | :--- | :--- |
| `default_secret` | `None` → 内建公开常量 `BUILTIN_DEFAULT_KEY` | 无用户密码时信封的密封密钥。设为私有串后，官方二进制读不了你的无密码信封，且**线上格式一个字节都不变**。空字符串视为未设置（回退内建常量）。显式 `password` 永远优先于它 |
| `stealth_domain` | `None` → `STEALTH_DOMAIN`（`b"strhide-stealth-v1"`） | stealth 模式下密码派生 magic 的域分隔串；换掉它同一密码生成不同 magic 对。类型是 `&'static [u8]` |
| `magic` | `None` → 标准高熵 magic | `MagicPair { header: [u8; 8], trailer: [u8; 4] }`。header magic 写进信封（自描述）；trailer magic 是读方搜索锚点——**自定义 trailer magic 使信封对官方 locate 不可见**。stealth 模式忽略此字段（magic 由密码派生）。注意：`MagicPair` 本身**不是** `#[non_exhaustive]`，可直接构造 |
| `stego` | `StegoProfile::new()`（官方） | 内容域半区（`with_stego_secret` / `with_stego_domain` / `with_jpeg_format` / `with_png_format` / `with_hevc_format`）。与结构域 secret 相互独立、互不继承 |

访问器：`secret() -> &str`（无密码密封密钥）、`domain() -> &[u8]`、`header_magic()`、`trailer_magic()`、`is_official()`（全默认 = 官方方言，含内容域半区）。

兼容规则是**全或无**：两端同 Profile 可互读；私有 Profile 与官方 Profile 绝不互读（且失败形态与错密码不可区分）。读写两侧必须传同一个 Profile——这正是门面 `StrHide` 存在的理由：绑定一次，处处一致。

### 7.3 典型用法

```rust
use strhide::params::{LocalParams, MagicPair, Profile};

// 整个私有方言一个 const：
const DIALECT: Profile = Profile::new()
    .with_default_secret("acme-envelope-key-2026")     // 结构域
    .with_stealth_domain(b"acme-stealth-v1")
    .with_magic(MagicPair { header: *b"\xACME\x00\x01\x02\x03", trailer: *b"\xACMT" })
    .with_stego_secret("acme-image-key-2026");         // 内容域（互不影响）

// 写方调优（L 类，读方永远无感）：
const LOCAL: LocalParams = LocalParams::new()
    .with_chunk_size(64 * 1024)
    .with_compression(CompressionStrategy::Never);
```

---

## 8. 载体格式与策略

### 8.1 支持的载体（10 种）与策略

`strategy = "auto"`（默认）按每个适配器的 `choose_auto_strategy` 一次性选型（**无注入失败自动回退**；各适配器的 auto 决策已统一为"只返回验证过可注入的策略"）。显式指定策略时直接使用、失败即报错。

| 格式 | 侦测 | 策略（推荐优先序） | 容量 | auto 行为 |
| :--- | :--- | :--- | :--- | :--- |
| PNG | 8 字节签名 | `chunk`（IEND 前插入 `prIv` 私有块）→ `eof` | `chunk` ≤ 0x7FFFFFFF（2 GiB − 1，常量 `PNG_MAX_CHUNK_LEN`）；`eof` 无上限（文件增长） | `ube ≤ 2 GiB−1` 选 `chunk`，否则 `eof` |
| JPEG | `FF D8` | `app_segment`（SOS 前 APP15 段链）→ `eof` | `app_segment` ≤ 64 MiB（`JPEG_MAX_TOTAL_CAPACITY`；单段 65,533 B；SOS 须在 16 MiB 头扫描窗内）；`eof` 无上限 | 超限或 SOS 不可达 → `eof` |
| WebP | RIFF + `WEBP` | `riff_chunk`（私有 `SHRD` 块）→ `eof` | ≤ 4 GiB RIFF 上限；要求 RIFF 声明边界 == 物理文件尾（不满足直接拒绝 `riff_chunk`） | 边界自洽选 `riff_chunk`，否则 `eof` |
| HEIF / HEIC | `ftyp` brand | `item_hidden`（meta 中未引用私有 item，首选）→ `free_box`（`free` 盒伪装）→ `box_uuid` → `eof` | `item_hidden` / `free_box` ≈ 4 GiB（32 位盒尺寸/iloc 字段硬顶，常量 `ITEM_HIDDEN_MAX_ENVELOPE = u32::MAX − 8`）；`box_uuid` 真无上限（64 位 largesize） | `ube ≤ ~4 GiB` 且 meta 结构可用 → `item_hidden`，否则 `box_uuid`。**`free_box` 不参与 auto**，只能显式指定 |
| MP4 | `ftyp` 4CC 白名单（含分片流） | `box_uuid` → `eof` | 无上限 | `box_uuid` |
| WAV | RIFF + `WAVE` | `riff_chunk` → `eof` | 同 WebP | 同 WebP |
| MKV | EBML | `ebml_void`（合规 Void 元素）→ `eof` | 无上限（受 EBML VINT 编码范围约束） | `ebml_void` |
| ZIP | `PK\x03\x04` 等 | `pre_cd_inject`（中央目录前）→ `eof` | 载体相关：`4 GiB − EOCD 偏移`（32 位补丁字段预算）；`inspect` 给出实测值 | 空档案（CD 偏移 0）或 ZIP64 locator 存在 → `eof` |
| PDF | `%PDF-` | `incremental`（增量更新）→ `eof` | 无上限；要求 trailer 可解析、文档**未加密**、无签名 | trailer 可解析且无 `/Encrypt`/签名 → `incremental`，否则 `eof` |
| Windows PE | `MZ` | `pe_codebits`（x86/x64 指令编码信道，文件大小不变）→ `pe_slack`（节对齐填充，文件大小不变）→ `pe_overlay`（overlay 追加）→ `eof` | `pe_codebits` / `pe_slack` 载体相关（`.text` 指令密度 + 最长零填充 run，`inspect` 实测；最小可用信封 178 B 明文 / 214 B 密文）；ARM64 走 `pe_slack`；`pe_overlay` / `eof` 无上限 | 优先零增长信道：`pe_codebits` → `pe_slack` → `pe_overlay`（按 ube_size 与架构分流） |

`eof`（EOF 追加）是所有格式的最终回退策略：无容量上限、文件增长、可用性最高、隐蔽性最差（追加在物理文件尾）。

### 8.2 策略注册表（`router::STRATEGY_REGISTRY`，名称 ↔ 线上 ID）

| 名称 | ID | 名称 | ID |
| :--- | :--- | :--- | :--- |
| `eof` | 1 | `pe_overlay` | 7 |
| `chunk` | 2 | `pe_codebits` | 8 |
| `box_uuid` | 3 | `pe_slack` | 9 |
| `pre_cd_inject` | 4 | `riff_chunk` | 10 |
| `app_segment` | 5 | `ebml_void` | 11 |
| `incremental` | 6 | `item_hidden` | 12 |
| | | `free_box` | 13 |

辅助函数：`strategy_to_id(&str) -> Result<u8, StrHideError>`、`id_to_strategy(u8) -> &'static str`（未注册返回 `"unknown"`）、`MAX_STRATEGY_ID`（编译期派生 = 13）、`find_adapter` / `find_adapter_or_reject`（格式嗅探，公开的 `ADAPTERS` 表决定优先序）。

### 8.3 扩展接口（`adapters` 模块）

自定义载体支持 = 实现 `HostAdapter` trait（全部方法公开）并加入 `router::ADAPTERS`：

| trait 方法 | 职责 |
| :--- | :--- |
| `format_name` / `detect` | 格式名与 magic 侦测 |
| `supported_strategies` / `choose_auto_strategy` | 策略清单与 auto 选型（必须只返回验证过可注入的策略） |
| `strategy_capacities(Option<reader>)` | 容量表（`None` = 静态口径；`Some` = 对该载体实测） |
| `inject` | 注入，返回 `(inject_offset, inject_size, patch_offset, orig_patch_val)` |
| `locate(expected_trailer_magic)` | 定位信封，返回 `(ube_offset, ube_total_size, strategy_name)` |
| `strip` | 剥离还原（默认实现按三坐标契约做坐标换算，可覆盖） |
| `verify_structure` | Level 1 结构校验 |
| `open_ube_reader` | 信封虚拟读流（链式/散布策略覆盖；`SegmentedSubStream` 公开可用） |
| `envelope_offset_delta` / `trailer_offset` / `finalize` / `is_scattered_strategy` / `strategy_note` / `suspicious_structures` / `supports_content_stego` | 注入坐标修正、后处理、散布标记、说明、结构启发、内容域开关 |

---

## 9. UBE v2.2 线上格式与公开常量

### 9.1 信封布局（`envelope` 模块）

```text
+────────────────────────────+ HEADER_SIZE = 112 B
│ magic_header        8 B    │ ← 标准常量或 stealth/方言派生
│ version      1 B  flags 1 B│ version = 0x02；flags 见下表
│ strategy_id 1 B  reserved 1B
│ salt               16 B    │ PBKDF2 盐（掩码区之外，可先读）
│ base_nonce         12 B    │ AES-256-GCM 基 nonce
│ orig_host_size      8 B    │ 原始载体大小
│ orig_host_sha256   32 B    │ 原始载体哈希（还原对拍依据）
│ inject_offset       8 B    │ ┐ 注入三坐标 + 补丁记录
│ inject_size         8 B    │ │ （注入后回填）
│ patch_offset  4 B          │ │ patch_offset=0 为哨兵（无补丁）
│ orig_patch_val 4 B         │ ┘
│ meta_len      4 B  hint_len 4 B
+────────────────────────────+
│ password hint    hint_len B│ 明文（可选）
│ encrypted metadata meta_len B  ← compact 二进制块 + 16 B GCM tag（AAD = header 前 80 B）
│ encrypted payload          ← 分块 GCM：每块 4 B 长度 + 密文 + 16 B tag
+────────────────────────────+ TRAILER_SIZE = 24 B
│ ube_offset 8 B  ube_total_size 8 B  trailer_crc32 4 B  trailer_magic 4 B │
+────────────────────────────+
```

- **AAD**：header 前 80 字节（`AAD_SIZE`）同时绑定 metadata 与每个 payload chunk 的 GCM 密封——篡改任一 header 字段都会导致认证失败。
- **掩码**：header 的字节 8..12 与 40..112 在"无用户密码"或"stealth"两种模式下用密钥流异或掩蔽（无密码 = `Profile::secret()` 派生；stealth = 用户密码派生）。**带用户密码的非 stealth 信封不掩码**（AEAD 已认证 header）。掩码只影响可读性不影响安全性。
- **trailer**：`trailer_crc32` 对前 16 字节校验；stealth 模式下 CRC 再与密码派生掩码异或，防 IEEE CRC32 扫描定位。

### 9.2 flags 常量

| 常量 | 值 | 含义 |
| :--- | :--- | :--- |
| `FLAG_ENCRYPTED` | 0x01 | **需要用户密码**（false 时载荷仍加密，用 `Profile::secret()`） |
| `FLAG_COMPRESSED` | 0x02 | 载荷 raw-deflate 压缩过 |
| `FLAG_IS_FILE` | 0x04 | 载荷声明为"文件"（`PayloadSource::Bytes` 也是 true） |
| `FLAG_STEALTH` | 0x08 | stealth 模式 |
| `FLAG_HAS_HINT` | 0x10 | 附带密码提示 |
| `FLAG_COMPACT_META` | 0x20 | metadata 为 compact 二进制布局（当前唯一布局；pre-v2 JSON 已不可读） |

### 9.3 公开常量速查

| 常量 | 值 | 出处 |
| :--- | :--- | :--- |
| `HEADER_SIZE` / `TRAILER_SIZE` / `AAD_SIZE` | 112 / 24 / 80 B | `envelope` |
| `MAX_HINT_LEN` | 1024 B | `envelope` |
| `CURRENT_VERSION` | 0x02 | `envelope` |
| `MIN_UBE_PLAIN` / `MIN_UBE_ENCRYPTED` | 178 / 214 B（写方实际能产出的最小信封） | `envelope` |
| `MAX_KNOWN_STRATEGY_ID` | 13 | `envelope` |
| `STANDARD_HEADER_MAGIC` / `STANDARD_TRAILER_MAGIC` | SHA-256("strhide-standard-header-v2")[..8] / trailer-v2[..4] | `params`（`envelope` re-export） |
| `STEALTH_DOMAIN` | `b"strhide-stealth-v1"` | `params`（`engine` re-export） |
| `BUILTIN_DEFAULT_KEY` | 官方无密码密封密钥字符串 | `crypto` |
| `PBKDF2_ITERATIONS` | 100,000（**结构域**；内容域默认 cipher suite 是 200k，勿混用） | `crypto` |
| `CHUNK_SIZE` / `MAX_CHUNK_SIZE` | 2 MiB / 64 MiB | `crypto` |
| `MAX_VERIFY_PAYLOAD_SIZE` | 1 GiB（verify L3 流式上限） | `crypto` |
| `DEFAULT_COMPRESSION_LEVEL` / `MAX_COMPRESSION_LEVEL` / `AUTO_COMPRESSION_SAVING_PERCENT` | 6 / 9 / 2 | `params` |

低层公开类型（一般只有做格式工具或私有构建时才直接用）：`EnvelopeHeader`（`pack` / `pack_masked` / `pack_with_profile` / `unpack` / `unpack_with_password` / `unpack_with_profile` / `unpack_with_secrets` / `salt_of` / `validate_against` / `get_aad` / `is_*`）、`EnvelopeTrailer`（`create` / `create_stealth` / `pack` / `unpack` / `read_from_tail`）、`UnpackSecrets`（跨调用复用 PBKDF2 结果）。`CarrierMetadata`（engine 模块）提供 compact 编解码。

---

## 10. 错误处理

```rust
use strhide::errors::StrHideError;   // 整个 crate 唯一错误类型（thiserror）
```

| 变体 | 语义 | 结构域典型触发 |
| :--- | :--- | :--- |
| `Io(std::io::Error)` | 底层 I/O | 文件不存在、权限、磁盘满 |
| `CorruptedData(String)` | 信封解析/AEAD tag/长度自洽/载荷 SHA-256 失败 | 信封被裁剪、位翻转、chunk 损坏 |
| `Password(String)` | 密码缺失或错误 | 错密码读加密信封（metadata 认证失败归入此变体） |
| `PasswordWithHint { message, hint }` | 需要密码且信封带提示 | 读加密信封未给密码；用 `.hint()` 取提示、`.detail()` 取正文 |
| `Rejection(String)` | 预写拒绝 / 覆盖拒绝 | 签名载体、只读目标、read/restore 输出已存在 |
| `RestoreMismatch(String)` | 还原对拍失败 | 双信封未按逆序移除、载体被第三方修改 |
| `UnsupportedFormat(String)` | 载体不是支持的格式 | 拒绝未知格式（不盲改）；含前 4 字节提示与支持格式列表 |
| `NoHiddenData(String)` | 定位不到可读信封 | 无信封、密码/方言不匹配（反 oracle：三者不可区分）；消息可能附带结构线索 |
| `UnsupportedVersion(String)` | 版本/关键扩展/套件过新 | 更新的构建所写的信封 |
| `General(String)` | 其余：参数错误、策略不支持、目标不可写、内部不变量 | stealth 无密码、hint 超限/与 stealth 并用、策略名不支持、chunk_size 非法、已有信封再写 |
| `TrellisInfeasible { cause, detail }` | 内容域 STC 无可行解 | **结构域不会出现**（枚举共用；`cause: TrellisCause`，内容域专用） |

要点：

- 所有公开函数返回 `Result<T, StrHideError>`；错误可按判别式分支，无需字符串匹配。
- **`NoHiddenData` 是刻意设计的"沉默失败"**：无信封、错密码、错方言三种情况不可区分，避免向攻击者泄露"有信封但口令不对"。
- `PasswordWithHint` 的 hint 是结构化字段（`err.hint()`），CLI 据此打印并提示。
- 写路径的任何失败都不会留下半成品：`TmpGuard` 清理临时文件，原 carrier 保持不动。

---

## 11. 预写拒绝检查（rejection）

`rejection` 模块（全部函数公开，可独立复用）：

| 函数 | 检查 |
| :--- | :--- |
| `check_pe_authenticode` | PE 证书表（Authenticode）存在 → 拒绝 |
| `check_pdf_signature` | PDF `/ByteRange` + `/Sig` → 拒绝（64 KiB 分块 + 1 KiB 重叠扫描） |
| `check_jar_signature` | 任意 ZIP 的中央目录含 `META-INF/*.SF|.RSA|.DSA` → 拒绝（内容判定，改名无用） |
| `check_unsupported_apk` | `.apk` 扩展名 → 拒绝 |
| `check_signature_file` | `.sig` / `.asc` / `.p7s` / `.p7b` → 拒绝 |
| `check_content` | 上面前三个内容级检查的组合（内存载体可跑） |
| `run_rejection_checks(carrier, target, policy)` | 引擎入口；`run_all_rejection_checks` = `Strict` 固定档 |

`RejectionPolicy` 三档（挂在 `LocalParams.rejection`）：

| 档 | 内容级检查（签名容器） | 文件系统检查（只读 carrier、目标目录写探针、`.apk`/`.sig` 文件名） |
| :--- | :--- | :--- |
| `Strict`（默认） | ✅ | ✅ |
| `ContentOnly` | ✅ | ❌ |
| `Skip` | ❌ | ❌（调用方全责） |

另有两个内容级事实：签名载体检查（Authenticode / PDF / JAR）在 `write_carrier_bytes` 上也会运行（除非 `Skip`）；`ContentOnly` 与 `Strict` 在 bytes 入口行为相同。

---

## 12. CLI ↔ 库参数映射

**write**（`strhide write <CARRIER>...` → `write_carrier_with`）：

| CLI | 库 | 备注 |
| :--- | :--- | :--- |
| `<CARRIER>...`（多值） | 每个载体一次调用 | CLI 批量时载荷经 `PayloadSource::Buffered` 复用 |
| `-d FILE` / `-t TEXT` / `--text-file` / `--text-base64` / `--stdin`（互斥） | `PayloadSource::File` / `Text` / `Buffered` | 五源互斥由 clap group 保证；无源时回退 `STRHIDE_TEXT` 环境变量 |
| `-o PATH` / `--in-place` | `WriteOptions.output_path` / `None` | 库默认即 in-place；CLI 默认写 `<stem>-out.<ext>` |
| `--overwrite` | （库无对应） | CLI 层 `check_overwrite` 确认；库层写路径不检查目标存在 |
| `-p` / `--password-file`（互斥）→ `-e` 交互 → `STRHIDE_PASSWORD` → config | `WriteOptions.password` | 库只收 `password: Option<&str>`，凭据链是 CLI 的事 |
| `-H TEXT`（alias `--password-hint`） | `WriteOptions.password_hint` | |
| `-s STRATEGY` | `WriteOptions.strategy` | |
| `--stealth` | `WriteOptions.stealth` | |
| `--no-preserve-time` | `WriteOptions.preserve_time = false` | |
| `--no-backup` | `WriteOptions.backup = false` | config 的 `backup`/`preserve_time` 键也参与合成 |
| `--unescape` | （CLI 层文本转义） | 无库对应 |

**read** → `read_carrier_with_profile`：`-o`/`--stdout` → `output_path`（stdout = `None` + 自行打印）；`--overwrite` → `overwrite`；`-p` → `password`。

**restore** → `remove_carrier_with_options`：`-o`/`--in-place` → `output_path`；`--overwrite` → `overwrite`；`--no-backup` → `backup = false`；`-p` → `password`。

**inspect** / **verify** → `inspect_carrier_with` / `verify_carrier_with`：`-p` → `password`；`-r`/`--json` 是 CLI 批量与输出格式，库无对应（批量循环由调用方自己写）。

---

## 13. 场景配方

### 13.1 最短路径：写一个文本并读回（官方方言）

```rust
use strhide::engine::{write_carrier, read_carrier, PayloadSource, WriteOptions};

// 库默认 = 原地写 photo.png + 保留 photo.png.bak
write_carrier(
    std::path::Path::new("photo.png"),
    PayloadSource::Text("hello"),
    &WriteOptions { password: Some("pw"), ..WriteOptions::default() },
)?;

let read = read_carrier(std::path::Path::new("photo.png"), None, Some("pw"))?;
assert_eq!(read.data, b"hello");
```

### 13.2 写到新文件（等价 CLI 默认行为）

```rust
let opts = WriteOptions {
    output_path: Some(std::path::Path::new("photo-out.png")),
    ..WriteOptions::default()
};
let res = write_carrier(std::path::Path::new("photo.png"), PayloadSource::Text("hi"), &opts)?;
// res.carrier == "photo-out.png"，photo.png 未被改动，无 .bak
```

### 13.3 内存往返（服务场景，无文件系统）

```rust
use strhide::engine::{write_carrier_bytes, read_carrier_bytes, remove_carrier_bytes,
    PayloadSource, WriteOptions};
use strhide::params::{LocalParams, Profile};

let (stego, wrote) = write_carrier_bytes(
    &cover_bytes,
    PayloadSource::Bytes(secret),
    &WriteOptions::default(),
    &LocalParams::default(),
    &Profile::default(),          // bytes 入口必须显式传 Profile
)?;
let read = read_carrier_bytes(&stego, None, &Profile::default())?;
let (restored, removed) = remove_carrier_bytes(&stego, None, &Profile::default())?;
assert_eq!(restored, cover_bytes);        // 位级还原
assert!(removed.verified_identical);
```

### 13.4 门面 + 私有方言 + stealth

```rust
use strhide::facade::StrHide;
use strhide::params::Profile;
use strhide::engine::{PayloadSource, WriteOptions};

const ENGINE: StrHide = StrHide::new()
    .with_profile(Profile::new().with_default_secret("acme-key-2026"));

// stealth：magic 全由密码派生；同方言无密码信封照常读写
let opts = WriteOptions {
    password: Some("deniable"),
    stealth: true,                    // 与 password_hint 互斥；无 password 报错
    ..WriteOptions::default()
};
let res = ENGINE.write(carrier, PayloadSource::Text("msg"), &opts)?;
let read = ENGINE.read(carrier, None, Some("deniable"))?;
```

### 13.5 批量写同一载荷

```rust
// 载荷只物化一次；Stdin 源必须先 buffered 再逐载体复用
let (data, filename, is_file) = source.into_buffered()?;
for carrier in carriers {
    ENGINE.write(
        carrier,
        PayloadSource::Buffered { data: &data, filename: &filename, is_file },
        &options,
    )?;
}
```

### 13.6 巡检 + 按容量选策略

```rust
let info = ENGINE.inspect(carrier, None)?;
for cap in &info.strategies {
    println!("{:>14}  {}  {}", cap.strategy, cap.limit,
        cap.available.then_some("available").unwrap_or("unavailable"));
}
// 显式指定策略写入：
let opts = WriteOptions { strategy: "pe_slack", ..WriteOptions::default() };
```

### 13.7 门禁式校验

```rust
use strhide::engine::verify_passed;

for carrier in carriers {
    let v = ENGINE.verify(carrier, Some("pw"))?;
    if !verify_passed(&v) {
        // L1/L2 失败，或 L3 跑了且失败（L3 因缺密码被跳过不算失败）
    }
}
```

---

## 14. 陷阱与注意事项清单

1. **库默认是原地写**：`WriteOptions::default()` 覆盖 carrier 本身（留 `.bak`）。想要"CLI 式安全默认"必须显式给 `output_path`。
2. **写路径不检查目标已存在**：`fs::rename` 直接替换；`read`/`restore` 则默认拒绝覆盖输出。三个动词的保护口径不同（评审报告 §P2-5）。
3. **`PayloadSource::Bytes` 读回 `is_file == true`、`filename == "payload.bin"`**：inline 字节按文件标记是既有约定。
4. **bytes 系入口必须传 `Profile`**（`write_carrier_bytes` 还要 `LocalParams`）；路径版有免传的便捷函数。不想私有方言就传 `&Profile::default()`。
5. **`Profile` 是读写配对的**：写侧用了私有方言，读侧必须同一个实例（值相等即可）；不匹配统一报 `NoHiddenData`。空字符串 secret/域 视为未设置。
6. **stealth 与 `password_hint` 互斥**；stealth 必须有 `password`；三者校验都在 write 前置 fail-fast。
7. **双信封按注入逆序移除**：先移最后写的。还原对拍失败报 `RestoreMismatch`，消息含"仍有信封"诊断。
8. **`strategy` 是自由字符串**：用 §8.2 注册表的名字；拼错或该载体不支持时报 `General`。`free_box` 只能显式指定，auto 永不选它。
9. **auto 无注入期自动回退**：超大载荷请先 `inspect` 看 `strategies` 容量表再决定（或直接指定 `eof`）。
10. **压缩/chunk 大小/rejection 是 writer-only**（L 类）：改它们不会让已有载体不可读；`Profile`（P 类）才会。
11. **`inspect` 无信封是 `Ok` 不是错误**；`read`/`restore` 无信封是 `Err(NoHiddenData)`。
12. **verify 的 `skipped` ≠ 通过**：门禁判定用 `verify_passed`，不要自己读 `ok` 布尔。
13. **写密码后别改 `Profile`**：无密码信封的解密密钥来自 `Profile::secret()`，换了方言历史信封全部变成"无隐藏数据"。
14. **Windows 路径大小写**：`same_file` 对 NTFS 大小写不敏感（`photo.PNG` 与 `photo.png` 视为同一文件，原地判定成立）。
15. **输出文件名清洗**：读侧把 metadata 文件名清洗为裸文件名（`sanitize_filename`：剥离路径分隔符、拒 `..`/盘符），目录输出不会逃逸。

---

*本文档为纯梳理文档，未改动任何代码。全部签名、字段、常量、行为均对照 commit `ddb409c` 的 `rust/src` 源码逐项核对；已知的不一致与文档缺陷集中记录在姊妹篇评审报告中。*
