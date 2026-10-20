# stego 侧私有参数：可行性、难度与设计（embed / extract）

> **编制日期**：2026-10-20
> **定位**：`library_api_practical_plan_20261020.md` 的续篇，专门处理内容域隐写（`stego`）的参数化问题。
> 结论基于代码核对 + 本机实测（`rust/target/release/strhide.exe`，commit 43b7059）。
>
> **状态（2026-10-20 21:36 更新）**：本文件的 ①②③ 与第 4 项已全部落地，并经过一轮逐行复核；
> 复核发现的 10 处问题（`docs/CHANGES-20261020.md` 20:41:57 条目）与 JPEG 自检盲区
> （21:23:43 条目，校准式 DCT 检测）均已修复。实测数据、适用边界与遗留项见 §13。
> 仍未处理：真 `±1` matching（需先把选槽改为块级）、UBE 侧 `BUILTIN_DEFAULT_KEY`
> （属 `library_api_practical_plan_20261020.md` 的 M1）。

---

## 1. 结论先行

1. **"公开代码可以检测出来"这个现象成立，但根因不是"参数太通用"，而是三处结构性设计：**
   无密码模式用**公开常量密钥**、32 字节头部放在**完全确定且未置乱的槽位**、嵌入方式是**纯 LSB 替换**而非注释所声称的 LSB matching。
2. **单纯加参数解决不了问题。** 把 `p1_window` / `exclusion_percentile` 改一改，只改变"往哪个像素写"，不改变"别人能不能找到"。真正起作用的是**选槽与头部的密钥化**。
3. **实现难度：中低。** 以现有代码结构，"私有密钥 + 密钥化槽位 + 真 LSB matching"合计约 **1~2 人日**主体改动，不需要动 UBE 协议，也不需要重写引擎。
4. **但有一个必须先修的 bug**：`p1_window + p2_window > 18` 必然 panic（实测）。也就是说，现在暴露给用户的窗口参数**只能调小、不能调大**——"参数已暴露"和"参数可用"是两件事。
5. **对外口径要改**：`README.md` / `README.zh.md` 声称 "LSB Matching (±1)" 与"抗统计隐写分析"，与代码不符（见 §3.3）。这是可被外部验证的过度承诺，应优先修正。

---

## 2. 两种"检测"，难度差一个数量级

问"能不能被检测出来"必须先区分口径，否则方案会跑偏：

| 口径 | 含义 | 当前状态 | 私有参数是否有用 |
|---|---|---|:---:|
| **定向检测 / 可提取性** | 对方知道算法，试图**确认并取出**载荷 | ❌ **无密码时 100% 可提取** | ✅ 决定性作用 |
| **盲检测 / 统计隐写分析** | 对方不知道密钥，只看像素统计（χ²、SPA、RS、SRM） | ✅ 实测 `scan` 给 0/100 CLEAN | ❌ 几乎无用 |

实测（1024×1024 RGBA PNG，5 字节载荷，无密码）：

```text
$ strhide embed file-02.png -t "hello" -o out15.png
[OK] Embedded 5 payload bytes

$ strhide extract out15.png          # 无任何密钥
hello                                # ← 任何人跑官方二进制都能取出来

$ strhide scan out15.png
[CLEAN] risk 0/100                   # ← 统计检测完全看不到
```

**这就是用户描述的"公开代码都能检测"的真身：不是统计检测，是"人人可提取"。**
在低载荷率下，统计侧反而是干净的；定向侧的破口在密钥与槽位。

所以本方案的目标必须写明：**让"不掌握密钥的人无法定向提取、也无法确认载荷存在"，而不是"统计上不可检测"。**
后者取决于载荷率与代价函数质量，不是参数能买到的。

---

## 3. 三个泄漏点（代码证据）

### 3.1 无密码模式使用公开常量密钥

```rust
// src/stego/envelope.rs:55-57
fn default_builtin_key(salt: &[u8]) -> ([u8; 32], [u8; 32]) {
    derive_keys("strhide-default-content-stego-key-2026", salt)
}
```

`src/stego/spatial/engine.rs:318` 与 `jpeg/engine.rs:116`（写入）、`443` / `253`（提取）四处同款字面量。
**任何拿到源码的人都能复现这条密钥派生**——这与结构域 UBE 的 `BUILTIN_DEFAULT_KEY` 是同一个问题，
但内容域更严重：UBE 至少要先找到信封，内容域的槽位算法也是公开的。

### 3.2 头部槽位确定且未置乱（最致命）

```rust
// src/stego/spatial/engine.rs:311-312
// Phase 1: Header slots are the top 256 lowest-cost candidate pixels
let header_slots = &candidate_pixels[..256];
```

- `candidate_pixels` 由公开的 HILL 代价图排序得到（`hill.rs` 用 `& 0xFE` 掩码保证确定性，见 §4.2）；
- 头部 32 字节 = `[16B salt][12B nonce][4B total_len]`（`engine.rs:292-296`）**明文**写入这 256 个槽；
- 全过程**不涉及任何密钥**。

后果：第三方只要实现同一个 HILL 排序，就能读出 salt / nonce / 长度，再用公开默认密钥解出载荷。
即使目标用了密码，这 256 个固定槽位仍是**结构性指纹**：`total_len` 落在 `[49, 64MiB]`
（`engine.rs:426` 的合法性判据）即可作为可疑标记。

顺带一个次生问题：正文槽位集合依赖载荷长度

```rust
// engine.rs:321
let remaining_candidates = &candidate_pixels[256..256 + ciphertext_bits];
```

槽位范围与密文长度耦合，长度因此泄漏到"用了哪些槽"这一层。改为"对全候选集做一次密钥化置换后切段"即可消除。

### 3.3 声称 LSB matching，实际是纯 LSB 替换

```rust
// src/stego/spatial/engine.rs:358-366
fn apply_lsb_matching(val: &mut u8, target_bit: u8, _seed_byte: u8, _slot: usize) {
    if current_lsb != target_bit { *val ^= 1; }   // 2k <-> 2k+1，纯替换
}
```

`_seed_byte` / `_slot` 两个参数**完全未使用**——签名说明原本要实现"按密钥随机选 ±1 方向"的
LSB matching，实现时退化成了替换。JPEG 侧 `apply_dct_matching`（`jpeg/engine.rs:149-162`）同样。

- 经典 LSB 替换正是 χ² 与 SPA 的攻击目标；模块头注释（`spatial/engine.rs:4-6`）声称
  "immunity to Chi-square and sample-pair (SPA) steganalysis" 不成立；
- `README.md:27` / `README.zh.md:27` 的 "LSB Matching（±1）" 与 "抗统计隐写分析" 同样不成立；
- 当前实测 `scan` 仍报 CLEAN，是因为载荷率极低（5B / 1M 像素），**不是因为算法抗检**。
  载荷率上去以后（例如 4KB 级别）这条会立刻显形——建议补一个高载荷率的自检用例来量化。

> **更正（2026-10-20 复核）**：上一版本文件在这里写"改成真 LSB matching 是纯写侧、零兼容成本"，
> **这是错的**。当前提取依赖"按代价精确排序的槽位集合"，而 `±1` 会改变 `val & 0xFE`
> （例：`4 → 3`，掩码由 4 变 2），代价图随之改变、排序错位、提取失败——`^= 1` 的"只能在偶奇对内翻转"
> 恰恰是这个设计下唯一能保持掩码不变的操作。所以 `_seed_byte` 未被使用不是纯粹偷懒，
> 而是滑动到这个设计约束上被迫退让。**要让 `±1` 成立，必须先让槽位选择与精确排序解耦**
> （例如按块级方差选集合，见 §9.2 Stegcore 路线），属于中等改造，不是一行的写侧开关。

---

## 4. 必须先修的两个"参数不可用"问题

### 4.1 `p1_window + p2_window > 18` 直接 panic（实测）

`hill.rs:65` 把对称填充写死为 `let pad = 9`，而 `p1_window` / `p2_window` 是可配的。
推导：`h1 = h + 2*9 - 2`，第二级低通需要 `h2 = h1 - (p1-1) >= h + p2 - 1`，
化简即 **`p1 + p2 <= 18`**（默认 3 + 15 = 18，恰好饱和）。

实测（`strhide embed ... --p1-window X --p2-window Y`）：

| p1 | p2 | 结果 |
|---|---|---|
| 3 | 15 | OK（默认，饱和） |
| 5 | 15 | **PANIC** `hill.rs:119` range end out of range |
| 3 | 31 | **PANIC** `hill.rs:119` |
| 1 | 17 | OK（1+17=18） |
| 2 | 16 | OK（2+16=18） |

`panic` 而非可读报错，且 `--help` 只说 "odd, default 15"。**结论：窗口参数目前只能把总和调小，调大就崩。**
修法：`pad` 由 `(p1-1)/2 + (p2-1)/2` 推出，并在 `params` 上做范围校验返回 `Err` 而非 panic。

### 4.2 自定义代价模型有一条隐含契约：必须对 LSB 不敏感

`hill.rs:43-45/53-55` 先 `& 0xFE` 再去算灰度，注释明确说这是为了让**嵌入前后代价图逐位一致**。
若第三方实现自己的 `SpatialCostModel` 直接用原始像素值，嵌入会改变像素 → 提取时重算的排序错位 →
解不出（表现为 `NoHiddenData`）。

这条契约目前**只写在 HILL 的实现注释里，没写在 trait 文档里**（`traits.rs:27-34` 未提）。
要开放自定义模型，必须补进 `SpatialCostModel::compute_cost` 的文档并加编译期无法守护的测试用例。

---

## 5. 设计：密码派生槽位布局（P 类参数）

### 5.1 先解决"鸡生蛋"

头部里装 salt，密钥由 password+salt 派生——**所以头部位置不能由 salt 派生**。
可行的拆法（把两个派生分开）：

```text
header_perm_seed = HKDF-SHA256(password, info="strhide-stego-hpos-v2")     // 不含 salt
   → 对全部候选槽做一次置换，取前 256 个作为头部槽

body_perm_seed   = HKDF-SHA256(PBKDF2(password, salt), info="strhide-stego-perm-v1")  // 含 salt
   → 剩余候选槽再置换，作为正文槽（保留逐图多样性）
```

- 读方有密码 → 先算 `header_perm_seed` → 定位头部 → 读出 salt → 派生 body seed。闭环成立。
- 无密码时密码位由 `Profile::stego.default_secret` 顶替（私有密钥），布局随之私有化。
- `header_perm_seed` 用 HKDF 而非 PBKDF2：它的作用只是"不知道密码就猜不到位置"，
  安全边界仍由密码强度与 AEAD 承担；多一次 PBKDF2 会让每次读写多付 ~100k 次迭代，不划算。
  **这条权衡要写进文档**，不要让人误以为位置派生提供了额外的抗暴力破解强度。

### 5.2 既有文件怎么办

保留 v1 读取路径：提取时先按 v2 布局试，`total_len` 判据或 AEAD tag 失败后回退 v1 布局。
两种布局的判定都由 AEAD tag 收尾，误判概率可忽略。代价是**旧文件提取多一次尝试**，
建议由配置项 `legacy_layout: bool`（默认 true 一年，之后默认 false）控制，而不是永久隐式回退。

### 5.3 参数归属：并入现有 `Profile`，不要再造一套

这些参数全部是 **P 类**（读写必须一致，否则自己写的自己读不回来），且危险度高于 UBE 侧：
cost 参数不一致时表现为 `NoHiddenData`（静默失败），排查成本很高。
因此**必须与密码/密钥同源保管**，建议并入上一份方案的 `Profile`：

```rust
pub struct Profile {
    // ... UBE 侧字段（default_secret / stealth_domain / magic）...
    pub stego: StegoProfile,
}

#[non_exhaustive]
pub struct StegoProfile {
    /// 无密码模式的私有默认密钥；None = 官方公开常量（保持旧行为）。
    pub default_secret: Option<Cow<'static, str>>,
    /// 密码派生槽位布局（v2）。false = 旧版确定性布局。
    pub keyed_layout: bool,
    /// 是否允许回退读取旧版布局。
    pub legacy_layout: bool,
    /// 真正的 LSB matching（±1 随机方向）；仅影响写入。
    pub lsb_matching: bool,
    /// 代价模型参数（沿用现有 SpatialParams / JpegParams）。
    pub spatial_params: SpatialParams,
    pub jpeg_params: JpegParams,
}
```

要点：`lsb_matching` 是**纯写侧开关**，不影响读取；其余三项都要求读写一致，必须在文档里逐项标注。

---

## 6. 难度评估

| 改动 | 难度 | 改动量 | 主要风险 |
|---|:---:|---|---|
| 修 `p1+p2<=18` panic（`pad` 由参数推导 + 范围校验） | 低 | `hill.rs` 1 处 + 校验 | 改 `pad` 会改变默认参数下的数值结果？**不会**——`(3-1)/2+(15-1)/2=1+7=8`，与现值 9 差 1，需确认等价性，否则代价图微变、旧文件仍能读（因为 `&0xFE` 保证确定性，但排序可能变 → **旧文件提取会失败**）。安全做法：默认路径保持 `pad=9`，仅当参数非默认时按公式推导 |
| 真 LSB matching（写侧 ±1 随机方向） | **中** | 需先改槽位选择（见 §9.2） | 与"按代价精确排序"不兼容：`±1` 破坏 `& 0xFE` 不变性 → 提取排序错位。**不是一行开关** |
| 私有默认密钥（`StegoProfile.default_secret`） | 低 | 4 处字面量替换 + 参数贯穿 | 与结构域 `Profile.default_secret` 语义要对齐，避免两套"默认密钥"概念混淆 |
| 密钥化槽位布局（含头部） | **中** | 两处 `header_slots` / `body_slots` 构造 + 提取侧对称 + 回退逻辑 | 鸡生蛋（§5.1，已解）；旧文件回退顺序；置换范围从"剩余候选"改为"全候选"后**容量计算需同步**（`probe_*` 的 `fixed_overhead_bits` 与 `allowed_count` 假设不变，但槽位集合定义变了） |
| 代价图密钥抖动（在排序中引入密钥化 tie-break） | 中 | `sort_by` 改 `(cost_bucket, prng(i))` | 浮点排序不可复现；必须量化/整数量化后再比较，否则提取侧算不出同一顺序 |
| STC / 综合征编码 | **高** | 新增编码器 + 容量模型重写 | 不是参数问题，是算法换代；本项目当前不需要 |

**总评：把"私有密钥 + 密钥化布局 + 真 matching"做完，约 1~2 人日主体改动 + 等价测试。**
真正花时间的不是写代码，而是**验证"改完之后旧文件还能读"以及"新文件对第三方确实拿不到"**——
后者需要一组"只给算法不给密钥"的黑盒测试，项目里目前没有这类测试设施。

---

## 7. 不建议做的事

| 项 | 理由 |
|---|---|
| 把参数做成"越多越安全" | 参数越多，`NoHiddenData` 的静默失败面越大；stego 侧的失配是隐性的，比 UBE 侧难排查得多 |
| 声称"私有参数 = 无法检测" | 盲检测不看参数，看载荷率与代价函数。过度承诺会被外部复现打脸 |
| 在此之上做"算法名注册表" | `CostModelRegistry` 的 `match` 已够用；动态注册解决不了"提取端必须用同一个模型实例"的固有限制（stego 信封不记算法 ID） |
| 现在就上 STC | 工作量远大于本条讨论的全部收益，且会推翻现有容量模型 |

---

## 8. 建议顺序（已被 §10 取代，保留以记录原始判断）

1. ~~修 `p1+p2` panic~~ → **已修**，见 §10.1。
2. ~~真 LSB matching（写侧独立改动，零兼容风险）~~ → **判断有误**，见 §3.3 更正。
3. **私有默认密钥**（4 处字面量 → `StegoProfile.default_secret`），与结构域改造合并进同一个 `Profile`。
4. **密钥化槽位布局**（本方案的技术核心，需黑盒验证）。
5. 补测试：高载荷率下的自检扫描、"只给算法不给密钥"的黑盒提取失败用例。

> 注：第 4 项一旦落地，"官方二进制能否解开"就取决于 profile 是否泄露。这意味着
> **profile 的保管责任转移给了库调用方**——比"默认公开密钥"安全得多，但也意味着
> 谁把 profile 写进了客户端二进制，谁就重新退回到"人人可解"。这一点必须写进安全文档。

---

## 9. 参考实现到底提供了什么（conseal / Stegcore 逐项核对）

> 背景：项目曾要求 embed/extract 实现"用 conseal 的算法、借鉴 Stegcore 的部分代码"。
> 本节按两个仓库的实际代码逐项核对，判断哪些被用上、哪些有现成实现却没被用。

### 9.1 conseal（Python，研究模拟器）

| conseal 提供 | 位置 | strhide 是否使用 |
|---|---|:---:|
| HILL 代价图（KB 高通 + 3×3 均值 + 15×15 可分离均值） | `hill/_costmap.py` | ✅ 移植，且**额外加了 `& 0xFE` 掩码**（更适合端到端） |
| UERD 代价图（块能量 + 8 邻域 + 量化表加权） | `uerd/_costmap.py` | ✅ 移植 |
| 非对称代价 ρ+1 / ρ−1 分离 + 饱和像素 wet cost | `*_costmap.py: compute_cost_adjusted` | ❌ 未用（strhide 只有单一代价图，0/255 无特殊处理） |
| Gibbs 概率嵌入 + λ 求解器（`probability` / `sample`） | `simulate/_solver.py`, `_objective.py` | ❌ 未用（改成"按代价排序取前 N"的贪心） |
| **STC（综合征网格编码）** | `coding/trellis.py` | — **该文件全文只有 `pass`，没有实现可抄** |
| 汉明矩阵编码 | `coding/hamming.py` | — 只有 `efficiency()` 公式（33 行），**无编码器** |
| 湿纸码 WPC | `coding/wpc.py` | ❌ 未用（101 行，真实实现，主要面向 JPEG） |
| 密码→种子→置换 | `tools/permute.py` | ⚠️ 自写等价物（`StdRng`），思路一致，但只作用于正文 |
| 多通道/彩色联合嵌入 | `lsb/_selection_channel.py`, `color/` | ❌ 未用（固定单通道，RGB 取 G） |

**关键事实**：conseal README 明确写 "The package only **simulates** the embedding… We do
**not** provide any end-to-end steganography method."。它没有提取器，所以它的嵌入策略
（按 Gibbs 分布采样）**本质上不可解码**——采样结果是"改了哪些像素"，不对应一条能解出的比特串。
因此"照抄 conseal 的嵌入方式"在工程上走不通，除非自己补一套综合征编码。

### 9.2 Stegcore（Rust，端到端产品）

| Stegcore 提供 | 位置 | strhide 是否使用 |
|---|---|:---:|
| 块级方差自适应索引集（整数运算、`c >> 1` 屏蔽 LSB） | `engine/src/steg.rs: index_set_adaptive` | ❌ 未用 |
| **全集合置换**（`permute_set`，ChaCha8，passphrase 折叠成种子） | `steg.rs:528` | ❌ 未用（strhide 只置换正文） |
| **头部在置换流最前端**（`extract_bits(pixels, slots, 2)` 读长度） | `steg.rs:753` | ❌ 未用（strhide 头部固定在前 256 槽） |
| 位写入规则 `*p = (*p & 0xFE) | bit` | `steg.rs:622` | ⚠️ **两边都是 LSB 替换**，Stegcore 也没做 matching |
| 分叉双载荷（可否认模式） | `steg.rs:540 bifurcate` | ❌ 未用 |
| SPA / RS / WS 与 Aletheia 对齐的检测闭环 | `engine/src/analysis.rs` | ⚠️ `analysis.rs` 有检测器，但**无 parity 测试** |

### 9.3 结论

| 维度 | conseal | Stegcore | strhide 实际 |
|---|---|---|---|
| 代价图 | 12 种 | 块方差 | HILL + UERD ✅ |
| 非对称 / 湿代价 | ✅ 有实现 | — | ❌ 单一代价 |
| 编码（STC / 矩阵） | 空 stub | 无 | ❌ 无（1 bit / 1 修改） |
| 嵌入规则 | Gibbs 采样 | LSB 替换 | LSB 替换 |
| 槽位与头部位置 | 不涉及（不提取） | 全集置换、头部在流首 | 正文置换、头部固定 ❌ |
| 提取 | ❌ 无 | ✅ | ✅ |

**准确的判断**：抄到的是**代价函数**（工作量大但技术最直白、且有论文可依），
没抄到的是**决定检测率的三件事**——矩阵/STC 编码（减少改动数）、非对称湿代价、全集置换（去指纹）。
其中 STC 在两个参考项目里都没有可抄实现（conseal 是空 stub），所以"没上 STC"不能全算偷懒；
但**非对称湿代价与全集置换都是现成的、明摆着没抄**。而"头部钉死在最前 256 个槽位"不是偷懒的省略，
是**主动选了一个更差的结构**——Stegcore 那半边正好是可用的那半边。

---

## 10. 修正后的实施顺序

### 10.1 已完成（本次）

- **`p1 + p2 > 18` panic 修复**：`hill.rs` 的 `pad` 由硬编码 9 改为
  `1 + (p1 - 1) / 2 + (p2 - 1) / 2`。默认窗口（3, 15）算出来仍是 9，
  **默认参数下输出与原实现完全等价**（已用新旧二进制交叉提取验证）。
- **参数校验**：新增 `SpatialParams::validate()` / `JpegParams::validate()`，
  在 `embed_carrier` / `extract_carrier` / `probe_carrier_capacity` 入口调用。
  偶数窗口、0、>63、非有限数值现在返回可读错误，不再 panic。
- **注释与命名纠偏**：`apply_lsb_matching` → `embed_lsb`（去掉两个从未使用的参数），
  `apply_dct_matching` → `embed_dct_lsb`；模块头注释改为如实描述
  "LSB 替换 + 为什么当前设计下不能用 ±1"。

验证：`cargo fmt` / `cargo clippy --all-targets` / `cargo test --all-targets` 全绿；
`--p1-window 5`、`--p2-window 31`、`--p1-window 21 --p2-window 41` 均可往返提取。

### 10.2 待做（按收益排序）

1. ~~**全集置换 + 头部进流**~~ → **已完成（2026-10-20）**：`derive_header_perm_seed` +
   全候选集置换，见 `docs/CHANGES-20261020.md` 的 20:08:22 条目。
2. ~~**非对称湿代价**~~ → **已按裁剪版完成**：只兑现"排除饱和像素"（`[2, 253]`），
   双代价接口仍欠（在 LSB 替换语义下方向自由度为零，等 `±1` 落地再兑现）。
3. ~~**矩阵编码（汉明）降低改动数**~~ → **已完成**：`stego/coding.rs`，默认 `k = 3`。
4. **私有默认密钥 + profile**（§5.3）：
   - **stego 侧已完成（2026-10-20）**：`StegoOptions::default_secret` + `--stego-secret`
     / `stego_secret` / `STRHIDE_STEGO_SECRET`，四处公开字面量收敛为
     `envelope::PUBLIC_DEFAULT_SECRET`；无密码默认行为与旧二进制双向兼容（已实测交叉提取）。
   - **UBE（结构域）侧仍待做**：`engine.rs` 的 `BUILTIN_DEFAULT_KEY` 走的是同一类问题，
     需要"Profile 贯穿 + magic/stealth 域"整体改造，属于
     `docs/library_api_practical_plan_20261020.md` 的 M1，不在本条范围内。
5. 若仍要真 `±1`：先把槽位选择改为块级（整数方差），再谈。

> **2026-10-20 复核后补充**：本节的 ①②③ 与第 4 项虽已落地，但落地质量存在 10 处问题（测试不断言、
> 正文选槽丢代价序、容量少报 28 字节、边界判据写错等），已全部修复并补上对应断言；
> 逐项清单与实测数据见 §13。**遗留**：JPEG 侧自检盲区（§13.3）未修。


---

## 11. ① ② ③ 的工作量评估

前提：**不做任何兼容**（未发布）。因此三项不是"打补丁"，而是把两个引擎的"槽位映射 + 比特映射"整体重写一遍。
这反而更便宜——省掉双读、版本分支、回退开关。

### 11.1 三项的真实收益排序（先纠正一个直觉）

| 项 | 实际收益 | 说明 |
|---|:---:|---|
| ① 全集置换 + 头部进流 | **高** | 唯一能消除"固定槽位指纹 / 人人可定位头部"的一项 |
| ③ 汉明矩阵编码 | **高** | 唯一能实质降低**盲检测率**的一项：同载荷下改动数降到 1/k |
| ② 非对称湿代价 | **中低** | 见下，只有在引入 `±1` 之后才完全兑现 |

**为什么 ② 的收益打了折扣**：非对称代价（ρ+1 与 ρ−1 分开）的价值在于"**有方向选择的自由**"，
即某个位置 +1 便宜、−1 贵时可以选择。但当前写入规则是 **LSB 替换**，方向由"当前 LSB vs 目标比特"完全决定，
**没有任何方向自由度**——所以非对称代价图在替换语义下几乎用不上。
在替换语义下 ② 真正能兑现的只有一件：**排除饱和像素（0 / 255）**。
饱和像素本身是强显著特征（大面积 0/255 区域是图像统计上的"平坦先验"），
把它们从候选集中剔除是低成本的正收益，但仅此而已。

> 因此 ② 按"**排除饱和像素 + 代价接口预留双图**"来落地即可，约 0.5 人日；
> 不要按"实现完整非对称嵌入"来估工。完整兑现要等 `±1`（那时需要块级选集合，见 §10.2 第 5 条）。

### 11.2 工作量

| 项 | 主要改动点 | 改动量（估） | 风险 | 人日（估） |
|---|---|---|:---:|---|
| ① 全集置换 + 头部进流 | `spatial/engine.rs`（embed/extract 的槽位映射）、`jpeg/engine.rs`（同）、`stego/mod.rs`（容量公式）、`stego/envelope.rs`（头部字段与尺寸） | 约 250~350 行改/删 | **中**：两端必须逐位对称；头部置换种子不能依赖 salt（§5.1 鸡生蛋）；`allow_count` 与头部槽位的互斥需显式处理 | 1.0 ~ 1.5 |
| ② 饱和像素排除 + 双代价接口 | `traits.rs`（返回 `(rho_p1, rho_m1)`）、`hill.rs`、`jpeg/cost/uerd.rs`、两个 engine 的候选集构造 | 约 100~150 行 | 低：纯候选集筛选，符号/边界注意 0 与 255 两端 | 0.5 |
| ③ 汉明矩阵编码 | 新增 `stego/coding.rs`（奇偶校验矩阵生成 + 分块嵌入/提取）、两个 engine 的比特循环、容量换算 | 约 200~250 行新增 | **中**：容量从"bit/槽"变为"k bit/(2^k−1 槽)"，`probe_*` 的 `fixed_overhead_bits` 与 `allowed_count` 全部要重算；块尾不足一块的收尾规则两端必须一致 | 1.0 ~ 1.5 |
| 集成与验证 | `tests/`、`batch_stego.rs` 增加高载荷率样本、与参考实现的结果对拍 | 约 150 行测试 | 中：需要"参考实现 oracle" | 1.0 |
| **合计** | | | | **3.5 ~ 4.5 人日** |

补充说明：

- ① 与 ③ **必须按顺序做**：③ 改变"每比特消耗多少槽"，① 改变"槽位顺序"，先做 ③ 会让 ① 的对称调试翻倍。
  ② 可独立并行。
- ③ 落地后 `bits_per_slot` 从 1 变为 `k/(2^k−1)`：k=3 → 1.714 槽/bit；k=4 → 3.75 槽/bit；k=5 → 8.0 槽/bit。
  k 越大越省改动但失真越集中，**建议开放为参数、默认 k=3**（保守，兼容现有容量观感）。
- 去掉既有兼容代码是**独立清理项**，不占上述估算，可另开一次提交。

### 11.3 验收标准（每项都要能证伪）

| 项 | 验收 |
|---|---|
| ① | ~~给定同图同密码，两次嵌入的头部物理槽位**不同**（salt 随机）~~ → **原判据不成立**：头部装 salt，位置不能由 salt 派生（§5.1）。修正后的判据：**同一密钥 + 同一载体，两次嵌入头部槽位相同、密文不同**；换密钥头部槽位必须改变；按错误密钥解析同一载体必须得不到合法头部（已由 `test_stego_header_slots_are_keyed_and_salt_independent` 断言）；`extract` 用不同密码必须报 `NoHiddenData` |
| ② | 候选集中不再包含 0/1/254/255 值像素，2 与 253 只在其 LSB 对内翻转；`--p1-window`/`--p2-window` 全区间往返；饱和区域图像（大面积纯白）应报容量不足而非崩溃 |
| ③ | 同载荷改动数下降到原来的 ~0.58（实测 0.2917 vs 0.5 每比特，即降 42%，不是"1/3"）；syndrome 往返 100%；块尾不足一块时两端一致 |
| 全局 | 见 §13：满容量时自检标记 11/15（PNG 4/4、JPEG 7/11），50% 容量时只有 9/15，JPEG 侧存在硬盲区。"高载荷必被自己检测器发现"不成立，判据已按实测改写 |

> **复核（2026-10-20）**：上表 ① 与"全局"两行在原方案里不可实现/不成立，已在 §13 按实测改写；
> ② 的边界值在原验收里写成了 0/255，与代码的 `[2,253]` 不一致，已改正。

> ~~最后一行很重要：现在 `batch_stego` 断言"自检 risk < 60"，配的是 5B 级载荷，等于什么都没验证。
> 建议改成**双向断言**：低载荷 stay clean、高载荷必须能被自己的检测器发现——否则这个测试只是在自我安慰。~~
>
> **复核结论**：这条建议的前半段成立（原断言确实等于没验证），后半段**过度乐观**。
> 实测（真实语料 15 张、不可压缩载荷）：50% 容量时自检只标记 9/15，满容量 11/15（PNG 4/4、JPEG 7/11）；
> 漏掉的 4 张全是 JPEG，UERD 把改动摊到全部 AC 系数后，本项目的 DCT chi-square 与像素域 SPA/RS
> 在 ~10–20% 的改动率下都看不到。因此正确的断言是"**多数载体必须被标记 + 漏检必须被记录**"，
> 而不是"必须全部被标记"。`batch_stego` 已按此实现（阈值 60%，实测 73%），并把漏检名单打印出来。

---

## 12. 许可证兼容的参考实现（已核实部分）

### 12.1 已核实的候选

| 项目 | 语言 | 许可证 | 与 Apache-2.0 兼容 | 用途 |
|---|---|:---:|:---:|---|
| [daniellerch/pySTC](https://github.com/daniellerch/pySTC) | Python + C++ | **MIT** | ✅ | STC 端到端参考，`pip install pystcstego`，可直接当 oracle 对拍 |
| [daniellerch/stegolab](https://github.com/daniellerch/stegolab) | Python | **MIT**（`codes/STC.py` 文件头为 MIT 全文） | ✅ | HILL / UERD / STC 的纯 Python 参考实现，适合逐值对拍 |
| [uibk-uncover/conseal](https://github.com/uibk-uncover/conseal) | Python | MPL-2.0 | ⚠️ 文件级 copyleft | 代价图、wet cost、Gibbs/λ 求解器对拍（本机已有） |
| [cgaffga/phasmcore](https://github.com/cgaffga/phasmcore) | Rust | **GPL-3.0**（作者明确选择） | ❌ | **只读参考**：STC + ChaCha20 置换层 + 容量计算。代码结构值得读，**不可复制** |
| [The-Malware-Files/Stegcore] | Rust | AGPL-3.0 | ❌ | 只读参考（全集置换、块级选集合） |

另有 Aletheia（C++，检测器参考）**许可证未核实**，使用前必须自行确认——它的价值是"检测器对拍"，不是代码。

### 12.2 许可证红线

- ✅ **MIT / Apache-2.0 / BSD / CC0**：可参考、可移植、可改，保留版权声明即可。
- ⚠️ **MPL-2.0**：文件级 copyleft。复制某个文件，该文件必须继续以 MPL 授权并公开源码。跨文件混用可行，但要保留声明。
- ❌ **GPL-3.0 / AGPL-3.0**：复制进 Apache-2.0 项目即违规（AGPL 还含网络服务条款）。
  Rust 生态里"能用的实现"很多是 GPL/AGPL（phasmcore、Stegcore 都是），所以**只能读、不能抄**。

**推荐做法**：用 MIT 的 Python 实现对拍数值，Rust 侧按论文自己写。
算法（汉明矩阵、STC 的分块结构、ChaCha20 置换）本身都是公开公式，不含版权。

### 12.3 GitHub 检索关键词

按三项分开给，英文关键词命中率更高：

**① 全集置换 / 头部进流**
```
keyed permutation steganography
Fisher-Yates ChaCha20 steganography permutation
stego key seed permutation LSB
LSB embedding header length prefix
cover selection permutation steganography
```

**② 湿代价 / 哨兵像素 / 非对称代价**
```
wet cost steganography
wet paper codes
asymmetric distortion steganography rho+1 rho-1
embedding cost saturation exclusion
HILL costmap python
```

**③ 矩阵编码 / 嵌入效率**
```
matrix embedding hamming steganography
F5 matrix encoding 1 2^k-1
syndrome coding embedding efficiency
bits per change embedding efficiency
hamming code steganography python
```

**④ 对拍工具（检测器）**
```
SRM rich model steganalysis python
aletheia steganalysis
chi-square attack SPA RS steganalysis
```

**⑤ 若以后要做 STC（不是现在）**
```
syndrome trellis codes STC Filler
stc embedding cost matrix parity check
```

### 12.4 建议的对拍方式（不依赖任何外部代码入包）

1. **HILL / UERD 数值对拍**：用 conseal（已在本机 `temp/github`）或 stegolab 对一张固定 PNG 算代价图，
   与 Rust 侧输出逐值比较（允许 1e-9 相对误差）。这能守住"移植是否等价"，与许可证无关（只是跑它、不复制）。
2. **汉明编码对拍**：不需要外部实现。用性质验证更强——
   ① syndrome 往返 100%；② 每个块的改动数 ∈ {0,1}；③ 同载荷改动数 ≈ 总比特 / k。
3. **置换层对拍**：同样不需要外部实现。验证"同密码同图两次嵌入、头部槽位**相同**（salt 只影响密文，不影响头部位置）、
   错密码必然 `NoHiddenData`"、"槽位无重复、无越界"。
   （原表述写成"头部槽位不同"，与 §5.1 冲突，已改正；实现见 `test_stego_header_slots_are_keyed_and_salt_independent`。）
4. **检测器对拍**：高载荷率下用本仓 `scan` 观察 risk 是否随载荷单调上升（定性），
   需要定量时再引 Aletheia（注意其许可证，只作为独立进程运行，不链接）。
   实测结论：**单调但会有平台**，且 JPEG 侧存在硬盲区，见 §13。

---

## 13. 复核结论（2026-10-20）

对 ①②③ 落地后的未提交代码做逐行复核，并对真实语料做实测。结论：**算法主干成立，验收环节有三处不实**，
已按下面处置。

### 13.1 主干成立的证据（实测）

| 项 | 方法 | 结果 |
|---|---|---|
| ③ 改动率 | 真实 PNG，不可压缩载荷，50% 容量 | 0.2903 / 0.2908 / 0.2913 每比特（理论 0.2917，直接 LSB 为 0.5） |
| 只动 LSB | 逐像素比对 | `max_delta = 1` |
| 代价图可复现 | 代码核对 | HILL 用 `pixel & 0xFE`，UERD 用 `|coeff| & !1`，邻域能量同源 |
| 候选集一致 | 代码核对 | 空间域按值域 `[2,253]`，翻转后仍在域内；JPEG 侧 `min_abs.max(2)` 使 `|c| ≥ 2` 恒成立 |
| 真实语料 | `batch_stego` | 19/19（15 正常 + 4 正确拒绝） |

### 13.2 发现与处置

| # | 问题 | 处置 |
|---|---|---|
| 1 | `batch_stego` 的"高载荷"被 `.clamp(64, 32*1024)` 截到 32 KiB，大载体上实际只有 ~23%；且 `high_scan_score` **只打印不断言** | 去掉截断；加"高载荷 risk 不得低于低载荷"的逐载体断言 + "≥60% 载体必须被标记"的聚合断言；漏检名单打印 |
| 2 | 单测用 `high >= low` 恒真；且"高载荷"载荷为 `vec![0x5A; 2500]`（可压缩，实际载荷极小） | 改为真实照片载体 + 不可压缩载荷 + 满容量，断言"必须产生 findings 且 risk 严格上升" |
| 3 | §11.3 ① 的验收判据"两次嵌入头部槽位不同（salt 随机）"与 §5.1 互相矛盾，永不可满足 | 改写判据并新增 `test_stego_header_slots_are_keyed_and_salt_independent` 锁定真实性质 |
| 4 | 正文槽位取"全量置换后的前 N"，等价随机子集，丢掉 HILL 最小失真前提（实测改动像素中位代价是"最便宜 N 槽"的 4.3 倍） | 改为：头部仍取密钥化随机 256 槽，正文在剩余候选里按代价取前 N 再洗牌；新增 `test_stego_body_slots_follow_cost_order` 守住 |
| 5 | 容量模型扣 `MIN_ENVELOPE_LEN(49)`，但 28 字节 salt/nonce 已由头部槽位支付，恒定少报 28 字节 | 改用 `BODY_OVERHEAD(21)`；新增 `test_stego_capacity_model_is_tight`（报多少就能嵌多少，多 1 字节必须拒绝） |
| 6 | `available_slots` 含 256 头部槽，与"最大载荷"口径不一致 | 改为 body 槽位；CLI 输出改为 `Payload slots` |
| 7 | `coding.rs`：`k` 无校验（k=0 除零、k≥8 越界）、载荷按 1 字节/比特展开（8 倍内存） | 新增 `validate_k`（1..=7）+ `MAX_HAMMING_K`；改为按需取比特；补 k 边界与容量互逆测试 |
| 8 | 密钥错误时错误消息与"无数据"不同（`Invalid stego envelope size` / `Truncated`），构成弱 oracle | 统一为 `No valid payload found`，并在 CLI 测试里断言 |
| 9 | 饱和边界测试只测 0/255，与代码的 `[2,253]` 不符 | 扩展到 0/1/2/253/254/255 六个边界，并断言 2、253 只在本 LSB 对内翻转 |
| 10 | 编码器测试注释称"pseudo-random LSB noise"，实际是 `(i % 2)` 周期模式 | 改用 xorshift32 生成覆盖与载荷 |

### 13.3 已修复：JPEG 校准检测（2026-10-20 21:23）

**原诊断**：满容量下 15 张里只标记 11 张，漏检 4 张全是 JPEG。根因不是"灵敏度不足"，而是
`jsteg_dct_test` 的判据要求 `chi2/df < 0.5`，而真实干净 JPEG 的 `chi2/df` 实测在 **207–2114**（5 张样本），
该分支在任何嵌入率下都不可能触发——是死代码。实测 DCT 域信号其实存在：clean→满容量 `chi2/df` 稳定下降 17–31%。

**落地**：新增 `src/analysis/calibration.rs`，按 Fridrich/Goljan/Hogea 校准法实现（论文公式，非复制代码）：

1. 解码像素 → 裁 4 px 让 8×8 网格与嵌入网格错半块 → 用文件自身 DQT 做前向 DCT + 量化，得到"估计干净版"；
2. 统计量用**成对失衡比**：`rate = 1 - median(|A_even - A_odd| / |C_even - C_odd|)`，
   覆盖 `|c| ∈ [2,11]` 五对 × 全部 63 个 AC 模式，配对计数 < 20 时跳过；
3. 阈值 `0.09` 报警、`0.15` 升 `Likely`（干净语料实测最大 0.062，满容量最小 0.129）。

**为什么不用论文里的 `beta_kl`**：实测干净图 0.02–1.49、满容量前后几乎不变（0.021→0.027）。
`beta` 的灵敏度来自 F5 的 shrinkage（改动 `|c|=0/1` 计数），而本项目的 LSB 替换只在 `|c| ≥ 2` 的成对内翻转、
从不碰 0/1，所以它对我们的嵌入器"按构造无效"。`beta` 作为参考量保留在 `CalibrationEstimate::f5_beta`，不参与判定。

**实测（15 张真实语料，不可压缩载荷）**：

| 指标 | 修复前 | 修复后 |
|---|---:|---:|
| 干净载体被 `dct:calibration` 误报 | — | 0 / 15 |
| 50% 容量被标记 | 9 / 15 | 10 / 15 |
| 满容量被标记 | 11 / 15 | 14 / 15 |

**顺带修掉的两个既有缺陷**：

- `dct-io` 的块内系数实际是自然序（其解码器写 `block[ZIGZAG[k]]`，与其文档不符），而 `uerd.rs` 的
  `STANDARD_LUMA_QT` 按 zigzag 序索引 → 每个频率被套用了别的频率的量化步长。已改为自然序（两端仍对称）。
- `analysis::jsteg_dct_test` 已删除（死代码，见上）；注释里保留诊断结论，避免有人再"修"回来。

**适用边界（明确写死的例外）**：量化表均值 `mean_step < 2`（如 quality-100、全 1 表）直接不适用校准——
校准是对**解码像素**重新量化，此时 IDCT 往返误差与量化步长同量级，参照本身失真。实测在 `temp/real_samples/sample.jpg`
（911×582、全 1 表）上会给出 0.659 的假"66% 嵌入"，因此加了这道门槛；语料里 `bg_320_03_R.jpg` 同为 Q=1，
它就是上面 14/15 里漏掉的那一张。这类载体只剩像素域检测 + "clean 不构成证据"的说明。

**仍然成立的限制**：校准是启发式，不是证明；50% 容量下 5/15 不可见；阈值与这条边界都来自本语料 15 张的实测，
换图源/换编码器需重新标定。硬编码特征算法无法覆盖所有情况，这一点不打算靠调参掩盖。

**另**：`Eof`/structure 域与内容域的 `default_secret` 已统一到同一个 `Profile`
（`Profile::stego.default_secret`，2026-10-20 M1b；UBE 侧 `Profile::default_secret` 仍走
`BUILTIN_DEFAULT_KEY`，两侧派生域不同故字段独立）。实施记录见
`docs/library_api_practical_plan_20261020.md` §10.5。
