# strhide 库定制性：实用落地方案（替代原蓝图 §4）

> **编制日期**：2026-10-20
> **定位**：本文**取代** `library_extensibility_and_public_api_audit_20261020.md` 第 4 节的改造范围。
> 原文档的诊断（哪里写死）基本准确，但**范围判断（哪些被 UBE v2.2 卡死）有明显偏差**，导致蓝图
> 大而全、含大量不必做的项。本文按"库使用者真实需求 + 代码实证"重新划定范围。
> **尚未改动任何代码**，本文为方案稿。

---

## 1. 结论先行

**"UBE v2.2 不改就承载不了很多改动"——这个判断不成立。实测 10 个定制维度里，7 个完全不受 v2.2 线格式约束，
真正的约束是 API 形状（参数没暴露），不是协议。**

受线格式真正卡死的只有 3 项，而且都不是库使用者的首要需求：

| 真受 v2.2 约束 | 原因（为什么"必须写进文件"） |
|---|---|
| 加密算法替换（ChaCha20 等） | 读方无法从信封得知用哪种 AEAD |
| KDF 轮数 | 读方必须先知道轮数才能派生密钥（鸡生蛋） |
| 压缩算法替换（zstd） | `FLAG_COMPRESSED` 只表达"压缩过"，无法区分算法 |

其余 7 项（分块大小、压缩策略、拒绝策略、自定义魔数、Stealth 域、私有默认密钥、自定义元数据）
**只改参数传递路径就能落地，字节级线格式零改动**。原文档把它们和 3 个真约束混在一张表里，才得出"要动协议"的结论。

---

## 2. 判定标准：三类参数，一把尺子

任何"可配置项"先回答一个问题：**读方能不能自己"试"出来？**

- **能试出来 → L 类（Local）**：只影响写侧行为，读侧无需知道。随便加，永不受线格式约束。
- **试不出来，但结果已经落在文件里 → P 类（Profile）**：读方靠调用方提供的同一份约定参数即可，
  不必写进信封。**读写必须同时传入同一份 profile**，否则自己写的自己读不回来。
- **试不出来，且必须由写方告诉读方 → W 类（Wire）**：只有这一类才需要动协议。

按这把尺子，原文档的 `EngineConfig`（写侧）+ `ReadConfig`（读侧）**双结构划分是错的**：
它把 L 类和 P 类混在两个按"读/写"切分的结构里，结果是（a）调用方面积翻倍，
（b）P 类参数天然存在"写侧设了、读侧忘了"的不对称 bug 空间——而原文档 §4 开头自己写的第一条硬约束
就是"读写两侧对称"。**按 L/P 切分而不是按读/写切分，能让"不对称"在类型层面就难以发生。**

---

## 3. 10 项逐一复核（含代码证据）

| # | 维度 | 原文档裁定 | 实际 | 代码证据 |
|---|---|---|:---:|---|
| 1 | 分块大小 chunk_size | ✅ 可落地，但"读侧需放宽 `CHUNK_SIZE+16`" | ✅ **且读侧零配置** | `crypto.rs:348-400` 读侧完全按 4B 长度前缀驱动，`is_last` 由字节预算推出，不假设块长；`crypto.rs:359` 是唯一耦合点 |
| 2 | 压缩策略 | ✅ | ✅ 纯 L 类 | 阈值写死在 `engine.rs:725`；等级写死在 `crypto.rs:417`；解码端只认 raw deflate，与等级无关 |
| 3 | 拒绝策略 | ✅ | ✅ 纯 L 类，不进信封 | `engine.rs:669` 无条件调用 `run_all_rejection_checks`（`rejection.rs:303`） |
| 4 | 自定义魔数 | ✅ 需对称配置 | ✅ **magic 字段本就存任意 8 字节** | `envelope.rs:100` `magic_header: [u8; 8]`；写死的是**读侧的查找入口**，不是格式 |
| 5 | Stealth 派生域 | ✅ 需对称配置 | ✅ 同上，派生输入不进信封 | 6 处字面量 + 1 处常量（`engine.rs:695/765/1398/1692`、`envelope.rs:336`、`crypto.rs:509`），`STEALTH_DOMAIN`（`engine.rs:60`）形同虚设 |
| 6 | **私有默认密钥** | **原文漏项** | ✅ **纯 P 类，价值最高** | 无密码模式统一用公开常量 `BUILTIN_DEFAULT_KEY`（`crypto.rs:57`），读侧靠"用内置密钥试解"识别（`envelope.rs:363-382`）。换成调用方自持密钥后，**装了官方 strhide 也解不开** |
| 7 | 自定义元数据 | ⛔ 暂缓（"定长位置编码无扩展位"） | ✅ **可做，旧读端天然兼容** | `engine.rs:151-191` `decode_compact` **从不校验 `pos == bytes.len()`**，尾部多余字节被静默忽略；JSON 路径 `serde_json` 默认忽略未知字段 |
| 8 | 载体适配器注册 | ✅ 可落地 | ❌ **不做**（见 §6） | `router.rs:25-36` 静态切片；但下沉注册表会牵动 `strategy_id` 共识与 `strip` 语义 |
| 9 | 加密算法 / KDF 轮数 / zstd | ⛔ 暂缓 | ⛔ **确实暂缓**（W 类，见 §7） | 头部无 suite 位；`reserved` 字节被默认模式识别门占用（`envelope.rs:377` `unmasked[11] == 0`） |
| 10 | I/O 流式 | ✅ "需泛型 `Read+Seek`/`Write+Seek`" | ✅ **但方案要改**（见 §5.3） | 适配器层已全部是 `&mut dyn SeekRead` / `&mut dyn Write`（`adapters/mod.rs:140-339`），**真正绑死 `&Path` 的只有 engine 的 ~16 处** |

### 3.1 三个纠偏要点

1. **第 1 项可以更彻底**：原文档要求"读侧同步放宽上限"，其实读侧不需要配置。
   把 `crypto.rs:359` 的界限改为 `min(剩余字节, MAX_CHUNK_ACCEPT=64 MiB)` 后，`chunk_size` 变成**纯写侧旋钮**，
   读侧零参数、零不对称。写侧上限校验为 `chunk_size ≤ 64 MiB` 即可保证不引入 OOM 面。
2. **第 6 项是原文最大的漏判**。对"库"而言，与官方 CLI 工具最本质的差异不是算法选择，而是
   **"我的信封不能被公开工具解开"**。当前无密码模式用公开常量派生一切密钥与头部掩码，
   等于所有无密码信封对任何装了 strhide 的人都是可读的——这在库场景下是设计缺陷，且修复它**不需要动一个字节的格式**。
3. **第 7 项不是"无扩展位"，是"扩展位在尾部"**。定长位置编码限制的是**中间插入**，不是**尾部追加**。
   在 `created_at` 之后追加自描述 TLV 尾，旧读端（`decode_compact`）会静默跳过，新读端解析它。

---

## 4. 最小 API 面

### 4.1 两参数：`LocalParams` + `Profile`

```rust
/// L 类：只影响本次调用，读写不必一致，不进信封。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LocalParams {
    /// 加密分块大小，默认 2 MiB，上限 64 MiB。读侧不需要知道。
    pub chunk_size: usize,
    /// 压缩决策（阈值 / 强制等级 / 关闭）。始终 raw deflate。
    pub compression: CompressionStrategy,
    /// 预写安全检查粒度。默认 Strict。
    pub rejection: RejectionPolicy,
    /// 保留宿主时间戳（内存载体下为空操作）。
    pub preserve_time: bool,
    /// 原地写时保留 .bak 备份（内存载体下为空操作）。
    pub backup: bool,
}

/// P 类：定义"你在说哪种私有方言"。读写必须传同一份，否则互不兼容。
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Profile {
    /// 无密码模式下替代公开内置密钥的自持密钥。None = 官方行为。
    pub default_secret: Option<Cow<'static, str>>,
    /// Stealth 派生域。None = 官方域。
    pub stealth_domain: Option<Cow<'static, [u8]>>,
    /// 自定义信封魔数对。None = 官方标准魔数。
    pub magic: Option<MagicPair>,
    /// 元数据 TLV 扩展尾是否参与解析。None = 不解析（忽略）。
    pub parse_meta_ext: bool,
}
```

要点：

- **`Profile` 是读写共用的单一类型**。调用方构造一次、存一份，读写两侧传同一个引用，
  从类型上消除原蓝图 `EngineConfig` / `ReadConfig` 的漂移空间。
- `default_secret` 用 `Cow<'static, str>` 而非 `&str`：调用方常从配置在运行时拼出密钥。
- 全部 `#[non_exhaustive]`：后续加字段不破坏下游编译。
- **兼容旧入口**：现有 `write_carrier` / `read_carrier_with` 签名保持不变，内部委托
  `LocalParams::default()` + `Profile::default()`。已有调用零改动。

### 4.2 新增入口（不覆盖旧签名）

```rust
pub fn write_carrier_with(carrier: &Path, source: PayloadSource,
                          opts: &WriteOptions, local: &LocalParams, profile: &Profile)
    -> Result<WriteResult, StrHideError>;

pub fn read_carrier_with_profile(carrier: &Path, output: Option<&Path>, password: Option<&str>,
                                 overwrite: bool, profile: &Profile)
    -> Result<ReadResult, StrHideError>;

pub fn remove_carrier_with(carrier: &Path, output: Option<&Path>, password: Option<&str>,
                           profile: &Profile) -> Result<RemoveResult, StrHideError>;

pub fn inspect_carrier_with(carrier: &Path, password: Option<&str>, profile: &Profile)
    -> Result<InspectResult, StrHideError>;
```

命名注意：`read_carrier_with` 已被占用（第 4 参数是 `overwrite`），**不要**复用该名字加参数，
否则是破坏性变更。

---

## 5. 分期落地

### M1：本地参数 + Profile 贯穿（无协议改动，价值最高）

改动点：

| 文件 | 位置 | 改动 |
|---|---|---|
| `crypto.rs` | 417 `Compression::new(6)` | 增加 level 参数 |
| `crypto.rs` | 359 `CHUNK_SIZE + 16` | 改 `min(remaining, MAX_CHUNK_ACCEPT)`；顺带解除读侧耦合 |
| `crypto.rs` | 226 `encrypt_stream_to_chunks` | 增加 `chunk_size` 参数 |
| `engine.rs` | 725 2% 阈值 | 走 `CompressionStrategy` |
| `engine.rs` | 805 `chunk_count` | 用配置的 `chunk_size`（否则 `exact_ube_size` 校验会 fail-fast） |
| `engine.rs` | 669 拒绝检查 | 传 `RejectionPolicy`；`rejection.rs:303` 加 policy 参数 |
| `engine.rs` | 695/765/1398/1692 | 字面量 → `profile.stealth_domain` |
| `envelope.rs` | 336 | 同上 |
| `envelope.rs` | 359-382 | 内置密钥路径改为"按 profile 提供的密钥试解" |
| `engine.rs` | 739/1162 | `BUILTIN_DEFAULT_KEY` → `profile.default_secret` |
| `engine.rs` | 769/770 | `STANDARD_*_MAGIC` → `profile.magic` |

**最高风险点：`envelope.rs::unpack_with_password`（317-385）**。它承担三级识别
（stealth 密码优先 → 内置密钥 → 裸解析），每级都有 `version/flags` 特征门。
改成 profile 驱动时，门的判定条件必须同步（尤其 `envelope.rs:377` 的 `unmasked[11] == 0`）。

**验收**：`{官方 profile, 自定义 profile} × {无密码, 正确密码, 错误密码} × {steadfast, stealth}` 全矩阵
交叉验证——重点断言**跨 profile 必须失败**（官方 profile 读自定义信封要报 `NoHiddenData`，不能解出垃圾）。

### M2：元数据 TLV 尾（协议内兼容）

- `CarrierMetadata` 增加 `ext: Vec<(u16, Vec<u8>)>`（业务标签、版本号、作者等）。
- 紧凑块：`created_at` 之后追加 `[tag: u16][len: varint][bytes]` 序列，末尾无标记（读到 `pos == len` 为止）。
- 解析端：`decode_compact` 在读 `created_at` 后，若 `parse_meta_ext` 且 `pos < len`，按 TLV 继续解析；否则忽略。
- **必须在 `decode_compact` 上加注释固定契约**："尾部字节必须被忽略，不得新增 `pos == bytes.len()` 校验"，
  并加回归测试守护，否则将来一次"更严格"的清理就把兼容性打破。
- 写侧影响：`meta_raw.len()` 变化 → `exact_ube_size`（`engine.rs:803-809`）自动跟随，无需额外改。
- JSON 回退路径无需改动（serde 默认忽略未知字段）。

### M3：内存载体 API（这是库场景最刚需，但不是"参数"）

```rust
pub fn write_carrier_bytes(carrier: &[u8], source: PayloadSource,
                           opts: &WriteOptions, local: &LocalParams, profile: &Profile)
    -> Result<(Vec<u8>, WriteResult), StrHideError>;
pub fn read_carrier_bytes(carrier: &[u8], password: Option<&str>, profile: &Profile)
    -> Result<ReadResult, StrHideError>;
pub fn remove_carrier_bytes(carrier: &[u8], password: Option<&str>, profile: &Profile)
    -> Result<(Vec<u8>, RemoveResult), StrHideError>;
```

实现路径（**不是**原文档的"泛型流"方案）：

- 适配器层已经与 I/O 无关，engine 只需把 `File` 换成 `Cursor<Vec<u8>>`：
  读到的是 `&mut dyn SeekRead`，写出到 `Cursor<Vec<u8>>`（`Write + Seek` 都满足对 header/trailer 回填的要求）。
- 需要抽取 `write_core(host: &mut dyn SeekRead, out: &mut dyn SeekReadWrite, ...)`，
  把 `write_carrier` 第 671-1044 行的主体搬进去；文件层的 `.bak` / rename / 权限 / 时间戳留在外层包装。
- **`rejection` 必须拆分**：内容类检查（PE Authenticode / PDF / JAR）本就是 `R: Read + Seek`
  （`rejection.rs:30/149/219`），可直接跑；路径类检查（只读、目录可写）在内存模式下无意义。
  `run_all_rejection_checks(carrier: &Path, target: &Path)` 需要拆成 `check_content(&mut dyn SeekRead)` +
  `check_paths(...)`，内存模式只跑前者并在文档明示。
- 明确记录三条退化：无原子提交、无 `.bak`、无时间戳克隆。

**不建议**做原文档的"通用 `R: Read+Seek, W: Write+Seek` 流式 API"：`auto` 策略选择需要
**先知道 `exact_ube_size`**（`engine.rs:802-824`），而流式载荷的长度在流结束前不可知，
必然退化成"要么全缓冲、要么两遍扫描"。真要支持 GB 级载荷，正确做法是
**载荷溢写临时文件**（内存有界、单遍、尺寸已知），而不是把复杂度推给调用方。

### M4：文档与测试

- `examples/`: `in_memory.rs`、`private_profile.rs`、`large_payload_spill.rs`。
- wire 兼容矩阵（4 行就够）：官方 profile ↔ 官方 profile 互通；自定义 profile ↔ 自定义 profile 互通；
  自定义 ↔ 官方 **必须互不兼容**；`parse_meta_ext` 关闭 ↔ 开启 **必须可读**（单向兼容）。
- CI：`cargo build --examples`。

---

## 6. 明确不做（附理由，非遗忘）

| 项 | 不做理由 |
|---|---|
| **HostAdapter 动态注册** | 用户明确不需要；且代价被低估：新适配器必须自带 `strip` 反向语义与 `strategy_id`，而 `strategy_id` 是**跨端共识**（`router.rs:90-102`），私有 ID 会撞上 `MAX_KNOWN_STRATEGY_ID`（`envelope.rs:51`）的默认模式识别门 → 私有策略信封在默认模式下不可读。要支持它等于要重做协议，与"实用"背道而驰 |
| 策略 ID 私有段 | 同上；且"官方二进制剥不掉"这点对库使用者是负价值 |
| 通用流式 Read/Write API | 见 §5 M3：尺寸前置需求使其必然退化为全缓冲或两遍扫描 |
| 独立的 `ReadConfig` | 已被 `Profile` 吸收（§4.1） |
| cipher / KDF 轮数 / zstd | 真 W 类约束，见 §7 |

---

## 7. 3 个 W 类项的备选路线（仅在真出需求时启用）

若将来确实需要换 AEAD，有两条路，**代价必须写清楚**：

**路线 A：试解协商（不改协议）**
写侧按 profile 指定 suite；读侧按 profile 给的候选列表逐个试解第一块。
- 优点：零格式改动。
- 代价：① 每块最多 N 次 AEAD 尝试（只第一块，成本可忽略）；
  ② **无法防降级**——攻击者换 suite 仍可能被解开，因为读侧不校验"应该是哪个"；
  ③ 错误信息退化（"密码错"与"suite 不匹配"不可区分）。
- 结论：**只有当 profile 把候选列表固定为 1~2 项时才有意义**，那本质上就是"私有方言"，
  不是"协议演进"。要防降级就必须有位——那就回到 v3。

**路线 B：等 v3 加 suite 位**。当前 v3 已取消，不重启。

`PBKDF2_ITERATIONS` 更特殊：它同时作用于 `derive_keys` / `derive_stealth_magics` / `derive_header_mask`
三处（`crypto.rs:75/100/119`），可配轮数会让读取最坏情况变成 3×N 次 PBKDF2 尝试，
**成本和攻击面都是净负**，且下调轮数本身是安全倒退。维持写死是对的。

---

## 8. 建议实施顺序与取舍

1. **M1 全做**——一次性解决"库使用者最需要的那批参数"，且不动一个字节格式，回归风险最可控。
2. **M3 紧跟**——内存 API 是库场景（Web/微服务）的真门槛，且依赖 M1 抽好的 `LocalParams`。
3. **M2 可选**——自定义元数据是 nice-to-have；若下游没有明确业务标签需求，可以先不做，
   但**要在文档里写明"尾部可扩展"这一契约**，避免将来有人加 `pos == len` 校验把路堵死。
4. §6 / §7 的项**不要排期**，只保留结论与重启条件。

工作量粗估（不含测试设计讨论）：M1 主体集中在 `engine.rs` / `envelope.rs` / `crypto.rs`
约 15 处签名与调用点；M3 是把 `write_carrier` 主体抽成 `write_core` 并换 I/O 类型；
M2 是 `decode_compact` 尾部解析 + 写侧编码，改动面最小但**兼容性契约要单独守护**。

---

## 9. 内容域隐写（embed / extract）的参数化

本文只覆盖结构域（UBE）。内容域隐写（`stego`）的参数化是独立议题，且**泄漏面更严重**
（无密码模式用公开常量密钥、头部槽位完全确定）、难度与顺序也不同，见
`docs/stego_keyed_parameters_plan_20261020.md`。两者的 `default_secret` 概念应对齐，
建议统一收敛到同一个 `Profile`（UBE 字段 + `stego: StegoProfile` 子结构），避免出现两套"默认密钥"。

> **进展（2026-10-20 20:21）**：内容域侧的私有默认密钥已落地，但形态是
> `StegoOptions::default_secret`（P 类参数，`--stego-secret` / `stego_secret` / `STRHIDE_STEGO_SECRET`），
> 尚未并入统一 `Profile`——因为 `Profile` 本身在 M1 里才存在。M1 落地时把该字段迁入
> `StegoProfile.default_secret` 即可，语义与优先级保持一致（显式 password 压过 default_secret）。
