# STC-V3 定稿实施方案：固定网格全图三元 STC（单一线格式）

> **编制时间**：2026-10-21 21:28:11
> **前提**：**项目未发布、无历史载体，不做任何向后兼容**。旧 V2 路径直接删除，不保留回退分支、不做格式版本开关、不做迁移工具。
> **取代**：`docs/standard_ternary_permutation_stc_implementation_proposal_20261021.md`（V3 初稿，已挂废止标记）
> **依据**：V3 初稿 + 外部评审 + `docs/review_verification_standard_ternary_stc_proposal_20261021.md`（逐条复核）
> **代码基线**：`rust/`（commit 3f2bbb1 之后的工作树）

---

## 一、威胁模型与设计红线

### 1.1 隐写保护的是"通信行为"，不是"内容"

| | 密码学 | 隐写 |
| :--- | :--- | :--- |
| 保护对象 | 内容机密性 | **"存在隐藏通信"这一事实本身** |
| 失败判据 | 密文被破解 | **载体被判定为"被改过"** |
| 被拿住之后 | 交不交密码是人的问题 | 一旦判定"有东西"，剩下的就是拷问问题 |

所以：**AES-256-GCM 用得多强，对本方案的成败几乎没有影响**；决定成败的是 Phase 3 那条 DCTR 门禁。方案里所有"几何网格 / 真三元 / `u=24` 分散改动"的努力，全部服务于"不被判定为异常"，而不是"更难解密"。

由此推出四条**硬性设计红线**（评审时优先于任何其它指标）：

1. **不允许出现任何"公开可定位的标记"**：没有固定 magic、没有固定偏移的版本号簇、不写 CLI 可开关的格式版本位。判定"是不是 strhide 载体"必须付出与破解同等的代价（口令猜测 = 一次 KDF）。
2. **口令错误 与 非载体 必须返回完全相同的错误**（`NoHiddenData`），且耗时分布一致（都只跑一次套件 KDF）——否则"你这里没藏东西"都会被时间差证伪。
3. **不提供"无口令探测"能力**：`scan` 只做"给口令后验证"，不做格式指纹识别。上游工具做不到的事，下游也不能有。
4. **载荷率是最大变量**：同一算法，4 KB 与 64 KB 的可检测性差一个数量级。安全档位（bpp 上限）必须默认开，且优先于"能塞多少"。

> 关于 `probe` 的准确结论：它**不是**"存在性指纹"——头部位置由口令派生，没有口令连那 4 个字节都读不到。它的真实危害是**把口令猜测的成本从一次 KDF 降到几微秒**（约四个数量级）；只有在口令本身可猜（弱口令/字典命中）时，才等价于"存在性被坐实"。因此修法方向是**把猜测成本抬回 KDF 水平**（§3.4 的头部定位改造），而不是"删掉一个可见标记"——删了也照样能靠结构校验快速判别。

### 1.2 决策：换地基

初稿的三处设计互相依赖，无法单独修：

1. 池定义成 `|c| ≥ 2`（值相关）→ 正文槽位集合在提取端只能靠"值"重建；
2. 为让"改动后池成员不变"，必须加 `|c|=2` 单向锁 → 造出新的单向门（实测池内 24% 槽位被锁死，赤字 4σ~9σ）；
3. 为让槽位集合"不可被无密钥复算"，取全图置换的前 K 槽，而 `K = slots_for(bits)` 使 `R≈1`、改动量被码率锁死 → 自适应失效。

串起来就是：**用"池"承载"不可复算"，再用"锁"维护"池"，最后用"截断"挽救"锁"**。破法是把承载者从"池"换成"几何网格"——网格与像素值无关，提取端永远能重建，锁与截断都不再需要。

由于不做兼容，V2 那一整套（类桶 `dct_move`、代价排序截池、512 槽头 + FeatureWord、回退分支）**直接删除**，代码量净减少。

| | V2（待删） | V3（本方案） |
| :--- | :--- | :--- |
| 槽位集合 | `\|c\|≥2` ∩ 代价排序 ∩ 百分位截断（约 3 万） | 全图 **2,419,200** 个 AC 位置（`k=1..63`） |
| 集合依赖像素值 | 是（提取端必须重建池） | **否**（只依赖几何 + 密钥；头部另用**永不改动的 DC** 作摘要盐） |
| 每槽承载 | 1 比特（二元、单向移动） | 三元（`±1`/`0`，双向） |
| 元/槽比特率 | `R = 1` | `R = 1/24 ~ 1/1`（按载荷自适应） |
| 提取端需要代价图 | **需要**（重算 UERD 排序） | 不需要，且签名层面拿不到 |
| 头部 | 32B 头 + 32B FeatureWord = 512 槽 | 44B 超块（版本 + 套件 + 布局 + 扩展长度）+ 可选 TLV 扩展区 |
| 格式分支 | V2/V3 双轨 | 单一格式 |

---

## 二、代码基线（逐行核对）

| 位置 | 现状 | V3 处置 |
| :--- | :--- | :--- |
| `coding/stc.rs:133-148` | 内核已支持真三元（`Move::Both` 按 `rho_plus/rho_minus` 择廉） | **直接用** |
| `coding/stc.rs:316-334` | `embed` 只回写 `vals`，不返回每槽 delta | 新增 `embed_with_deltas` |
| `coding/stc.rs:206-210` | `u > h` 拒绝；列向量要求线性无关 | 改随机列构造，上限 64 |
| `coding/stc.rs:89` | `cols: [u32; MAX_STC_U as usize]`（3） | 改 `Vec<u32>` |
| `coding/stc.rs:327-334` | 精确填充 `bits ∈ [m, m+8)` | **保留**（布局公式已满足） |
| `coding.rs:311-341` | `dct_move` 按奇偶锁单向 | **删除**，换 `ternary_legal`（仅 `±1023` 单向，见 §3.3） |
| `jpeg/engine.rs:65-139` | `plan_slots`：池 + 代价排序 + 百分位截断 | **整函数删除** |
| `jpeg/engine.rs:294-304` | `moves` 全 `PlusOnly`、`rho_minus` 全 ∞ | 改 `Both` + 非对称代价 |
| `jpeg/engine.rs:329-340` | 比奇偶反推方向，`Move::Both => {}` 空操作 | 改按 delta 写回 |
| `jpeg/engine.rs:241-259` | 32B 头 + 32B FeatureWord | 44B 超块 / 718 槽（+ 可选 TLV 扩展区） |
| `jpeg/engine.rs:354-363` | `embed_dct_lsb`（头部 1 bit/槽） | **删除**（头部改用 STC `u=2`） |
| `envelope.rs:112-128` | `derive_header_perm_seed`（无 salt） | **复用** |
| `prng.rs` | `ChaCha12Stream` + `permute_indices` | **复用** |

内核约 90% 可直接用，真正要写的是「布局契约 + 槽位表示 + 头部」。

---

## 三、V3 架构

### 3.1 槽位契约（唯一正确性前提）

```
Grid      = { (bi, k) | 0 ≤ bi < block_count, 1 ≤ k ≤ 63 }      // N = 63 × block_count
HdrSlots  = permute(Grid, K_hdr)[0 .. 718 + n_ext]               // 超块 718 槽 + 可选扩展区
BodyGrid  = Grid \ HdrSlots                                      // 集合差
BodySlots = permute(BodyGrid, K_body)[0 .. u×(bits+h−1)]         // 正文
```

三条不变量，缺一不可：

1. **值不参与**：`Grid` / `BodySlots` 的选取只依赖 `block_count` 与密钥，**不读任何会被嵌入修改的系数值**。唯一例外是 `cover_digest`（只取 **DC**，用作头部置换的 KDF 盐）——DC 永不参与嵌入，所以嵌入前后恒定，两端可复算。这是"提取端零代价图"与"永不失步"的共同来源。
2. **头部先扣**：头部与正文用两套置换，`BodyGrid` 必须显式去掉 `718 + n_ext` 个头部位置。否则同一系数可能被改两次——正文 trellis 按 cover 值求解，而实际值已被头部改过 → 校验子错。
3. **尾部落选可接受**：`BodySlots` 只取置换序列前 `n` 个，落选约 67%。这是**按密钥均匀随机抽样**，不是"按代价挑剩下"。它只减少可挑选空间，不引入值相关偏差。初稿的错误在于把 `n` 压到 `≈bits`（`R≈1`），使抽样退化为"随机位置上的 50% 翻转"。

**实现契约（防"单测过、跨进程挂"）**：

* 槽位一律用**平坦索引** `idx = bi * 63 + (k - 1)` 表示，`Grid` 按 `idx` 升序枚举；
* `BodyGrid = Grid \ HdrSlots` **必须**用 `bool` bitset 标记头部位置、再按 `idx` 正序收集，**严禁 `HashSet`/`HashMap`**——Rust 的 `SipHash` 每个进程随机种子不同，迭代顺序不稳定，会让 Fisher-Yates 序列两端错位；
* `permute_indices` 的输入顺序因此必须完全由 `idx` 决定，任何"集合迭代"都不得进入这条路径。

### 3.2 布局（`u` 的推导，两端必须一致）

内核要求精确填充 `n = u × (bits + h − 1)`，故：

```
u = max( 1, min( KERNEL_MAX_U(=64),
                 floor( SlotBudget / (bits + h − 1) ),
                 floor( |BodyGrid| / (bits + h − 1) ) ) )
n = u × (bits + h − 1)
```

* `SlotBudget = 800,000`：单次 trellis 规模预算，**纯嵌入端参数**（CLI `--slot-budget`），不是线格式的一部分；
* `KERNEL_MAX_U = 64`：收益上限，再大只增加无解概率；
* `u` 写进头部（§3.5）。提取端**只信头部值**，只做"范围 1..=64 + 容量 `u×(bits+h−1) ≤ |BodyGrid|`"校验，**不比对本地预算推导值**——否则发送方换一次 `--slot-budget`，历史载体就全部报错。

1920×1280（`N = 2,419,200`，超块 718 槽 → `|BodyGrid| = 2,418,482`，`h = 8`，随机不可压载荷）：

| 载荷 | `bits` | `u` | `n` | `R` | 覆盖率 | 状态数 | 转移次数 | 回溯位图 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 KB | 32,936 | 24 | 790,632 | 1/24 | 32.7% | 256 | 4.0×10⁸ | 50.6 MB |
| 16 KB | 131,240 | 6 | 787,482 | 1/6 | 32.6% | 256 | 4.0×10⁸ | 50.4 MB |
| 64 KB | 524,456 | 1 | 524,463 | 1/1 | 21.7% | 128 | 1.3×10⁸ | 16.8 MB |

> 覆盖率与 pySTC 基准一致并非巧合：它把池裁到 `|c|≥2`（29% 的位置），本方案用 `SlotBudget` 裁到 32%。**区别在裁剪依据**——前者按值裁（提取端需重建），后者按密钥随机裁（提取端天然可复算）。

### 3.3 代价与三元合法性（第三轮评审后重定）

**先把被推翻的那一版记下来**：上一版写"`|c| ≥ 2` 才可动、且不得跌破 2"，理由是"不碰零游程 + 在 1/2 之间做闭合边界"。这个理由站不住，而且会直接让嵌入失败。

实测（`temp/check_coeff_hist.py`，`temp/images/jpg/0001.jpg`）：

```
AC 位置总数            2,419,200
|c| >= 2（可动）         702,984   ← 29.1%
|c| ∈ {0, ±1}（不可动）  1,716,216 ← 70.9%
```

正文槽位是全图均匀抽样，所以正文里同样约 **71% 是湿点**。STC 的每一行由 `h` 个 group（`h·u` 个元素）共同决定；若这个窗口里全是湿点，该行的校验子被载体**钉死**，消息位与它不符时该状态下所有路径同时死。定量：

| 场景 | `u` | 行窗口元素数 | 窗口全湿概率 | 钉死后果 |
| :--- | ---: | ---: | ---: | :--- |
| 超块 | 2 | `8×2 = 16` | `0.709¹⁶ ≈ 0.4%` | 352 行 → 约 **50% 的图连头部都嵌不进去** |
| 64 KB 载荷 | 1 | `8×1 = 8` | `0.709⁸ ≈ 6.4%` | 几乎必然在正文断流 |
| 4 KB 载荷 | 24 | `8×24 = 192` | `0.709¹⁹² ≈ 10⁻²⁹` | 这一档反而安全（掩盖了问题） |

所以上一版 §5.1 的"必然有解"论证是**错的**：它假设"每个元素至少有一个合法方向"，而门槛恰好剥夺了 71% 元素的翻转能力。这条评审意见成立。

> 顺带纠正评审的另一处：`c = 2` 只能 `+1` **不是**单向门——`3 → 2` 是允许的，`2 ↔ 3` 双向对称，`1/2` 之间是**闭合**边界（没有净流向，不留赤字）。它的问题是"湿点太多导致无解"，不是"单向流动"。结论一致，机理不同，写清楚免得后续按错误理由改。

**现在的规则（极简，两条）**

1. 所有 AC 位置（含 `0`、`±1`）**双向 `±1` 均可**；
2. 仅在 `|c| = 1023` 处挡一个方向 —— `category(1024) = 11` 超出 baseline AC 的 10 档上限（`dct-io` 的 `category()` 实现已核实）。

```rust
/// 三元合法性：纯嵌入端概念，提取端完全不需要。
fn ternary_legal(c: i16) -> (bool, bool) {          // (允许 +1, 允许 -1)
    (c < 1023, c > -1023)
}
```

`0 ↔ ±1` 的代价由 UERD 自然承担（平滑区的 0 代价极高，Viterbi 不会去动它），不需要任何值门槛。湿点密度因此 ≈ 0，格图不会因为"没有可动元素"而断流——这才是真正的"必然有解"。

**Huffman 符号缺失怎么办（实测后的结论，与上一版不同）**

先给实测（`temp/survey_huffman_coverage.py`，统计 Y 的 AC 表是否覆盖 `(run 0..15, size 1..10)` 共 160 个符号）：

| 语料 | 样本数 | 表不完整 |
| :--- | ---: | ---: |
| `temp/images/jpg`（相机照片） | 80 | **0** |
| `temp/jpeg_huffman/std`（`ffmpeg -huffman 0`） | 3 | 0 |
| `temp/jpeg_huffman/opt`（`ffmpeg` **默认 optimal**） | 3 | **3**（62~67 个符号） |
| `temp/testfiles/file-08.jpg`（6000×4000） | 1 | **1**（66 个符号） |
| `temp/real_samples/sample.jpg` | 1 | **1**（125 个符号） |

再量化"缺符号到底会挡掉多少方向"（`r = run % 16`，ZRL 规则；`±1 → 0` 属于结构变更，单独计）：

| 文件 | 表内符号 | `+1` 被挡 | `-1` 被挡 | 两向都挡（真湿点） |
| :--- | ---: | ---: | ---: | ---: |
| `std/0001.jpg` | 162 | 0.00% | 0.00% | 0.00% |
| `opt/0001.jpg` | 67 | 0.01% | 0.01% | 0.00% |
| `file-08.jpg` | 66 | 0.19% | 0.19% | 0.00% |

**所以"安全模式重试"是错的处方**（上一版已删除）：真湿点几乎为 0，而被挡方向只有 0.1%~0.2%——按 4 KB 载荷约 8k 次改动算，仍有约 16 次会撞上被挡方向，所以**必须精确处理**，但完全不需要牺牲 71% 的位置去"保安全"。

**现在的做法（三段）**：

1. **快速路径（99%）**：自己解析 DHT（`dct-io` 不暴露表，所以自带 ~80 行解析），若 Y 的 AC 表覆盖全部 160 个符号 → 不做任何逐槽检查，`ternary_legal` 只判 `±1023`；
2. **优化表路径**：表不完整时，逐块计算 `run`（zigzag 顺序，`r = run % 16`），对 `|c| ≥ 2` 的目标 `(r, cat)` 查表，缺则不提供该方向（置 ∞）。代价：**0.19% 的方向**，不需要任何"重试"；
3. **结构变更（`±1 ↔ 0`）**：会改变后一个非零系数的 `run`，属于连锁变更，无法在槽位级别判定。这类移动数量极少（改动点里 `|c|=1` 的占比 × 选择概率），改为**写回后校验**：只对被动过的块重放一遍符号序列，若出现表里没有的符号 → 明确报"该 JPEG 的 Huffman 表过优化，请用标准表重新保存"，而不是抛一个看不懂的 `CorruptEntropy`。

> 彻底解法仍是 patch `dct-io` 写标准 Annex K 表（覆盖全符号，三段全部可以删掉）。列为 Phase 4 可选项，**不阻塞主线**：1% 的文件走优化表路径即可正常工作。

* **代价**：复用 `compute_cost()` 对全部系数算 UERD（`engine.rs:81` 已保证长度 = `total_coeffs`）；
* **方向**：`rho_plus` / `rho_minus` 分别给，`Move::Both`（`±1023` 处单向）。维纳极化折价**默认关闭**（`polarize_weight = 1.0`），Phase 3 独立实验；
* **合法性只在嵌入端**：提取端只读奇偶，不判合法性、不读 Huffman 表 → 不影响线格式、不影响两端一致性。

### 3.4 密钥派生分层（头部定位也走 KDF）

独立评审指出 `probe` 是"离线爆破的快速预言机"，这一点成立；但它给的修法（删掉 `probe`、改用结构性字段过滤）**不够**——version/flags/suite/h/u 的联合约束约 40 比特，攻击者每猜一次仍只需一次 HKDF + 718 步部分置换（微秒级），"正确口令通过、错误口令几乎必然失败"本身就是预言机。要害不在"冗余位数"，在**定位头部这一步的成本**。

所以改成：**头部位置由套件 KDF 派生**，让"读头部"必须先付出 KDF 代价。

```
cover_digest = SHA-256("strhide-cover-v1" ‖ u32(block_count) ‖ u32(component_count) ‖ 全部 DC 系数(i16 BE))
              // DC 永不参与嵌入 → 嵌入前后恒定，两端可复算

master_i          = SuiteKDF_i(password, salt = cover_digest)          // 每个候选套件一次
header_perm_seed  = HKDF(master_i, info = "hpos" ‖ domain)             // 定位 718 槽 + 扩展区
enc_key,perm_seed = HKDF(master_i, salt = 超块里的 16B salt, info = "enc"/"perm")
stc_seed          = HKDF(perm_seed, salt = 超块里的 salt, info = "stc-trellis")
```

| 项 | 来源 | 说明 |
| :--- | :--- | :--- |
| `cover_digest` | 尺寸 + 全部 DC 系数 | **格式常量**（冻结）；DC 不得用于嵌入 |
| `master` | `SuiteKDF(password, cover_digest)` | 每个候选套件算一次；这也是反爆破成本的来源 |
| `header_perm_seed` | HKDF(`master`, `"hpos"`‖domain) | 定位超块与扩展区 |
| `enc_key` / `perm_seed` | HKDF(`master`, salt=超块 16B salt) | AEAD 与正文置换/trellis |
| `stc_seed` | HKDF(`perm_seed`, salt) | 正文 trellis 列向量 |

**提取端的套件试枚举**：超块里的 `suite_id` 只有在"用哪套 KDF 定位头部"确定后才能读到，因此解码器按 id 升序**逐个试**（v1 只有 2 个，且都是 PBKDF2 变体）：

1. 用套件 i 的 KDF 算 `master_i` → 定位头部 → 解 352 比特 → 结构校验；
2. 通过且 `suite_id == i` → 采用；不通过 → 试下一个；
3. 全部失败 → `NoHiddenData`（等价于"口令错或非载体"）。

代价与收益：正常情况（载体用默认套件 1）只跑 1 次 KDF；最坏 2 次（约 160 ms）。攻击者的每次口令猜测被锁死在**该载体实际使用的套件 KDF 成本**上——用 Argon2 的载体，拿廉价 PBKDF2 去试只会白跑。这比"删 probe"彻底，且不引入任何明文鉴别字段。

> **备选（若嫌每次尝试一次 KDF 太重）**：保留快速头部定位，接受"微秒级口令预言机"作为已知取舍并写进安全说明。不推荐——它让套件里的高成本 KDF 形同虚设。

`salt` 明文位于超块第 4..20 字节，但**它只用于 HKDF 的分层分化，不再是 KDF 的盐**——KDF 盐是 `cover_digest`，所以"读头 → 拿 salt → 派生正文密钥"的顺序依然成立，而预计算表攻击（跨载体复用）也失效（每个载体的盐都不同）。

### 3.5 头部：三层结构（超块 / 扩展 / 正文）

格式一旦公开就改不动，所以头部不按"当前够用"设计，而按"十年后加东西不改地基"设计：

```
┌─ Superblock（冻结，718 槽 / 44 B / 352 bit）── 版本 + 套件 + 布局 + 扩展长度
├─ Extension（可选，TLV，长度由超块给出）─────── 以后所有新字段都加在这里
└─ Body（正文密文）
```

**超块布局（44 字节 = 352 比特，偏移与语义永久冻结）**

```
off  size  field            说明
0    1     version_major    主版本，不兼容变更才改（当前 1）
1    1     version_minor    次版本，只加可选扩展时改（当前 0）
2    2     flags            全部保留，必须为 0（不得引入"有/无扩展"这类冗余位）
4    16    salt             正文密钥的 HKDF 盐（每载体随机）
20   12    nonce            AEAD nonce
32   4     envelope_len     BE，bit0..26 有效，bit26..32 必须为 0
36   2     suite_id         密码套件 id（BE，见 §3.5.1），须与试枚举出的套件一致
38   1     codec_id         0 = 三元 STC（预留 Hamming = 1）
39   1     h                STC 约束高度 4..10
40   1     u                格宽 1..64
41   1     components_mask  bit0 = Y；预留 Cb/Cr
42   2     ext_bytes        扩展区字节数，0 = 无扩展
```

* 槽位：`h = 8, u = 2` → `n_sb = 2 × (352 + 7) = 718`，`m = 718/2 − 7 = 352` **精确填充**，不触发 `stc.rs:327`；
* `u = 2` 而非 1：给 trellis 2 倍候选位，把约 176 次改动压到低代价位置；
* **没有 `probe`**：那是一个 32 位精确口令预言机，见 §3.4；
* **没有 `has_ext`**：`ext_bytes > 0` 已足够表达，冗余状态只会产生歧义（评审意见，采纳）；
* **AAD = 本格式头部的全部字节**（JPEG 即 44B 超块）：任何头字段被改写都会让 AEAD 校验失败，而不是"能解密但行为诡异"；
* 所有多字节整数统一 **big-endian**；reserved 位/字节必须写 0 且解码时校验为 0（保留空间 = `flags` 2 字节 + `envelope_len.bit26..32`，不设独立保留字节）；
* **解码端字段校验**（任一不满足即拒绝，不猜）：`envelope_len ∈ [49, 2²⁶)`、`suite_id` 等于当前试枚举的套件、`h ∈ 4..=10`、`u ∈ 1..=64`、`components_mask & 0x01 != 0`、`codec_id` 为已知值、`ext_bytes % 1 == 0`（字节粒度天然成立）。

### 3.5.1 密码套件表（一个 id 换一整套密码参数）

`kdf_id` 那种"一个字段锁一种算法"的做法不够用：迭代次数、内存成本、AEAD 算法都会变，逐个加字段只会让超块反复改版。改用**套件 id 索引到代码里写死的参数集**：

| id | 名称 | KDF | AEAD | 说明 |
| ---: | :--- | :--- | :--- | :--- |
| 0 | — | — | — | **无效**：零填充/未设置，一律拒绝 |
| 1 | `pbkdf2-sha256-200k` | PBKDF2-HMAC-SHA256, 200,000 次, 32B | AES-256-GCM, 12B nonce, 16B tag | **v1 默认**（唯一必选实现） |
| 2 | `pbkdf2-sha256-600k` | 同上, 600,000 次 | 同上 | 可选，慢 3 倍；实现成本约 1 行 |
| 3 | `argon2id-m64t2p2` | Argon2id, m=64 MiB, t=2, p=2 | 同上 | **只保留 id，v1 不实现**（无 `argon2` 依赖）。解码遇到 → 明确报"本版本不支持该套件" |
| ≥0x0100 | — | — | — | 实验/第三方，官方解码器默认拒绝 |

> 评审建议"只保留套件 1、不要试枚举循环"，采纳一半：**v1 的套件表只有 1、2 两个 PBKDF2 变体**（都在 200~600k 次、内存 < 1 MB），试枚举最坏 2 次、约 160 ms，不存在"为了盲猜去跑 64 MB Argon2"的问题。Argon2 降级为**保留 id**，等真要引入依赖时再实现，届时试枚举的代价再评估。

```rust
pub struct CipherSuite {
    pub id: u16,
    pub name: &'static str,
    pub kdf: Kdf,
    pub aead: Aead,
}
pub enum Kdf {
    Pbkdf2HmacSha256 { iterations: u32 },
    // Argon2id { m_kib, t, p }  —— id 3 已保留，v1 不实现
}
pub enum Aead { Aes256Gcm }          // 目前唯一；将来 ChaCha20-Poly1305 走新 id

pub const SUITES: &[CipherSuite] = &[ /* id 1..=3 */ ];
```

规则：

1. **只增不改、id 不复用**——套件表是线格式的一部分，改参数就是新 id；
2. 未出现在本机套件表里的 id → 该轮试枚举直接失败；全部套件试完仍无命中 → `NoHiddenData`（**绝不降级猜测、绝不用弱套件兜底**）；
3. **默认套件不要轻易上调**：新套件生成的载体旧版本读不了（密钥派生不同），所以 `--cipher-suite` 作为可选开关，默认值在主版本升级时才动；
4. **提取端必须设资源上限**，防"恶意载体把解码器当矿机"：PBKDF2 迭代 ≤ 2,000,000；Argon2 `m ≤ 256 MiB, t ≤ 8, p ≤ 8`。超限直接拒绝，不执行；
5. 套件决定 **KDF（含头部定位成本）与 AEAD**；不参与正文置换与 trellis 列向量（那两者只由 `master` + 超块 salt 派生）；
6. **试枚举顺序固定为 id 升序**，`suite_id` 只作一致性校验（防实现错位），不作发现依据；
7. **套件必须自带 `salt_len ≤ 16` / `nonce_len ≤ 12` / `tag_len`**——超块给 Salt 与 Nonce 各留了固定 16B / 12B 槽位（AES-GCM、ChaCha20-Poly1305 都是 12B nonce，Argon2 用 16B salt，够用）。若将来某个套件需要更长盐/nonce（如 XChaCha20 的 24B nonce），约定用**一个 critical 扩展 TLV 承载超出部分**，超块字段置零——逃生口先留好，免得临时改版；
8. 套件表是**代码常量**，不是配置文件：一旦发布，参数改动只能新增 id，不能改旧 id 的数值。

### 3.6 扩展机制与冻结约定（发布前定死）

**三层职责**：超块只放"解码正文必须先知道的东西"；其余全部走扩展 TLV；正文只放密文。

**TLV 编码（扩展区内，连续排列至 `ext_bytes` 用尽）**

```
type : u8   （bit7 = critical，bit0..6 = 类型号 0..127）
len  : u8   （0..255，value 字节数）
value: len 字节
```

解码规则（必须严格实现，否则扩展性等于零）：

| 情形 | 行为 |
| :--- | :--- |
| 未知识别号 + `critical=1` | **拒绝**（`UnsupportedVersion`），不能猜 |
| 未知识别号 + `critical=0` | 跳过 `len` 字节继续 |
| `len` 越界 / 超出 `ext_bytes` 剩余 | 拒绝（`CorruptedData`） |
| 扩展区尾部未用完的字节非 0 | 拒绝（防止旧解码器吞掉未来数据） |
| 未知 `flags` 位被置位 | 拒绝（flags 全部保留为 0，新语义一律走扩展区） |
| `version_major != 1` | 拒绝 |
| `version_minor > 本地` | 允许：解析已知 TLV，其余按上表处理 |

**冻结清单（发布后永不变，变了就是新格式）**

1. `cover_digest` 的定义（`"strhide-cover-v1"` ‖ 块数 ‖ 分量数 ‖ 全部 DC 系数）；**DC 系数永不得参与嵌入**；
2. `header_perm_seed = HKDF(SuiteKDF(password, cover_digest), "hpos"‖domain)`——这一步决定了反爆破成本，动它就是新格式；
3. 头部置换算法（ChaCha12 + Fisher-Yates `permute_indices`，两端逐位一致）；
4. 超块槽数 **718**、超块 STC 参数 `(h=8, u=2)`、超块比特数 **352**；
5. 超块字段偏移与语义（新增字段一律走扩展区）；
6. 扩展区起点 = 第 718 槽，扩展区 STC 参数固定 `u=4, h=8`（`n_ext = 4 × (8·ext_bytes + 7)`，恰好承载 `8·ext_bytes` 比特，无残余）；
7. 正文起点 = `718 + n_ext`，正文置换与 trellis 种子派生 label；
8. 密码套件表只增不改、id 不复用、试枚举顺序固定 id 升序。

**以后加字段的决策树**（写进开发规范，避免随手改超块）

```
新需求 → 是否改变密钥派生 / AEAD（算法或成本参数）？
  是 → 加一条套件表项 + 新 suite_id（不动超块、不升版本）
  否 → 是否需要正文解码前就知道？
        否 → 不需要进格式（如代价函数、极化权重：仅嵌入端使用）
        是 → 能否用 1 个可选 TLV 表达？
              能 → 加 TLV，minor +1，critical 按需
              不能（>255B 或必须固定位置）→ 提升 major，超块不动，正文前置声明新布局
```

**已预埋的演进位**（现在不用，但不占额外空间）

* `suite_id`：新增 KDF 家族（scrypt、Argon2i）、提高 PBKDF2 迭代、换 AEAD（ChaCha20-Poly1305）——**全部靠加表项，不动超块**；
* `codec_id`：Hamming、多图层 STC（`pm2`）、极化码；
* `components_mask`：Cb/Cr 通道（`channel_mode` 在空域已有先例）；
* `envelope` 明文 flags 的位分配（**在密文内**，不需要动头部，但现在就定死并校验）：
  `bit0` = deflate 压缩；`bit1..3` = 压缩算法 id（0 = deflate，为 brotli/zstd 预留）；`bit4..7` 必须为 0，非 0 即拒绝——这是"密文内部格式"唯一的演进入口，不定就是给未来挖坑；
* 容量硬上限：超块 `envelope_len` 为 26 位 → 单载体最大信封 **64 MiB**（约合 ≤ 64 MiB − 49 B 载荷），写入格式规范；
* `ext_bytes`：未来任何"多段载荷 / FEC / 签名 / 长盐 long-nonce"类需求都走这里，不需要 `has_ext` 这类冗余标志位。

### 3.7 嵌入流程

```
1. read_coefficients → Grid(N)                                        // 只数块，不看值
2. cover_digest = SHA-256(块数 ‖ 分量数 ‖ 全部 DC 系数)
3. costs = compute_cost(...)                                          // 仅嵌入端需要
4. master = SuiteKDF(password, cover_digest)
   header_perm_seed = HKDF(master, "hpos"‖domain); n_ext = 4×(8·ext_bytes+7)
5. HdrSlots = permute(Grid, header_perm_seed)[0..718 + n_ext]
6. 组 44B 超块（suite_id = 配置套件；salt 随机；AAD = 该超块）
7. 超块：STC(u=2, h=8) 嵌入前 718 槽；扩展区（若有）：STC(u=4, h=8) 紧随其后
8. BodyGrid = Grid − HdrSlots; BodySlots = permute(BodyGrid, perm_seed)[0..n]
9. u = 见 §3.2; n = u×(bits+h−1); bits = 8×(total_len−28)
10. embed_with_deltas(BodySlots, deltas, ternary_legal, rho±, ct)      // ct = envelope[28..]
11. 系数 += deltas（合法性已在第 10 步保证）
12. write_coefficients（无损重编码）
```

### 3.8 提取流程（签名里没有代价图）

```rust
pub fn extract_jpeg(
    carrier_bytes: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    params: &JpegParams,
) -> Result<Vec<u8>, StrHideError>;
```

```
1. read_coefficients → Grid(N); cover_digest = SHA-256(块数 ‖ 分量数 ‖ 全部 DC)
2. for suite in SUITES（id 升序）:
     master = SuiteKDF_suite(password, cover_digest)                  // 每次试枚举付一次 KDF
     HdrSlots = permute(Grid, HKDF(master,"hpos"‖domain))[0..718 + n_ext]
     超块 = STC 提取 352 比特
     结构校验（版本 / 保留位 / suite_id == suite / h / u / codec / len）→ 不通过则试下一个
3. 全部失败 → NoHiddenData（口令错 或 非载体，对外不可区分）
4. 若有扩展区：读 ext_bytes → 解析 TLV（未知 critical → 拒绝）
5. 校验资源上限（PBKDF2 ≤ 2e6；Argon2 m ≤ 256 MiB）→ enc_key/perm_seed = HKDF(master, salt=超块 salt)
6. 校验 u ∈ 1..=64 且 u×(bits+h−1) ≤ |BodyGrid|（**不比对本地预算推导值**，见下）
7. BodyGrid = Grid − HdrSlots → permute → 提取 bits = 8×(total_len−28)
8. unpack_envelope_parts(ct, salt, nonce, aad = 超块 44B)             // 不拼接整信封
```

第 1、7 步只从系数取**奇偶**，值不参与任何集合构造。这是与 V2 的本质区别（V2 的 `plan_slots` 在提取端必须重算 UERD 并排序）。

> **`u` 只信头部，不比对本地推导**：`u` 由嵌入端的 `SlotBudget` 决定，而 `SlotBudget` 是 CLI 性能参数（`--slot-budget`），不是线格式的一部分。若提取端拿自己的预算去 assert，发送方换个预算值，历史载体就全部报错。头部里的 `u` 受 AAD 保护，只需做"范围 + 容量"校验。

---

### 3.9 可配置参数：lib 公开 `FormatProfile` / `Params`

隐写工具的真实用法是"**自己编译一个私有版**"：改掉一切能被上游检测器当作指纹的常量，只给自己用。所以这些参数必须是**公开的库类型**，而不是散落在代码里的 `const`——私有版不该被迫 fork 整个仓库去改一行字面量。

**这不是新增一套框架，而是既有类型的续建**（第三轮评审把它当成"企业级空转"是误判）：

| 现状 | 已有 | V3 只做 |
| :--- | :--- | :--- |
| `params::Profile` | `default_secret`、`stealth_domain`、`magic`、`stego: StegoProfile` | 不动 |
| `params::StegoProfile` | `default_secret`、`stego_domain` | 不动 |
| `stego::params::JpegParams` | `neighbor_weight`、`min_abs_coeff`、`block_exclusion_percentile`、`wet_cost`、`codec`、`stc_h`、`stc_u`… | **加 4 个字段**：`slot_budget`、`cipher_suite`、`polarize_weight`、`extensions` |
| 格式身份 | 散落在 `header.rs` / `envelope.rs` 的字面量里 | 抽成 `FormatProfile`（**首版就要，因为格式要冻结**） |

净增量：1 个 struct（13 个字段）+ 4 个字段 + 1 个 `debug_assert`。既有调用点不用改一行（`DEFAULT_FORMAT` 做默认值）。

**分层原则（一条就够）**：

> **解码前必须知道的 → 编译期格式身份（`FormatProfile`）；头部里能读到的、或只影响嵌入的 → 运行时参数（`JpegParams` 扩展）。**

```rust
/// 格式身份：改了它 = 换了一种格式。两个不同 profile 的二进制互读，表现为 NoHiddenData。
pub struct FormatProfile {
    pub format_major: u8,                 // 1
    pub format_minor: u8,                 // 0
    // 域分隔标签（改这里 → H 矩阵、头部位置、密钥全线重排）
    pub cover_digest_tag: &'static [u8],  // b"strhide-cover-v1"
    pub hpos_label:       &'static [u8],  // b"hpos"
    pub stc_label:        &'static [u8],  // b"stc-trellis"
    pub enc_label:        &'static [u8],  // b"enc"
    pub perm_label:       &'static [u8],  // b"perm"
    // 头部/扩展区几何（解码前必须知道，故只能在这里）
    pub sb_bytes: u8, pub sb_h: u8, pub sb_u: u8,   // 44 / 8 / 2 → 718 槽
    pub ext_h: u8,    pub ext_u: u8,                // 8 / 4
    // 槽位集合规则（每块 k = 1..=63，见 §3.1）
    pub grid_rule: GridRule,
    // 本二进制认可的套件（id 升序）
    pub suites: &'static [CipherSuite],
}
pub const DEFAULT_FORMAT: FormatProfile = /* 上面的值 */;

/// 单次嵌入参数：**既有 `JpegParams` 加 4 个字段**（不是新类型）。
/// 既有字段 `stc_h` / `codec` / `safety_level` / `wet_cost` … 继续用。
pub struct JpegParams {
    /* ……既有字段…… */
    pub slot_budget: usize,      // → 头部 u（默认 800_000）
    pub cipher_suite: u16,       // → 头部（默认 1）
    pub polarize_weight: f64,    // 仅嵌入（默认 1.0）
    pub extensions: Vec<Tlv>,    // → 扩展区
}

/// 提取策略：不影响格式，只影响"愿意为这次提取花多少代价"。
pub struct ExtractParams {
    pub allowed_suites: &'static [u16],   // 默认全表
    pub max_kdf_cost: KdfBudget,          // DoS 上限（PBKDF2 迭代 / Argon2 内存）
}

pub fn embed  (carrier: &[u8], payload: &[u8], pwd: Option<&str>, domain: Option<&str>,
               fmt: &FormatProfile, p: &JpegParams, cost: &dyn JpegCostModel)
               -> Result<Vec<u8>, StrHideError>;
pub fn extract(carrier: &[u8], pwd: Option<&str>, domain: Option<&str>,
               fmt: &FormatProfile, p: &ExtractParams) -> Result<Vec<u8>, StrHideError>;
```

**指纹面清单**（私有版该动哪些、动了发生什么）：

| 参数 | 层 | 改动的效果 | 风险 |
| :--- | :--- | :--- | :--- |
| 5 个域分隔标签 | A | 上游工具完全读不出；`H` 矩阵、头部位置、密钥全部错位 | 自用版本必须一致，否则自己也读不回 |
| `sb` 几何（bytes/h/u） | A | 头部改动点分布改变，按上游假设采样的检测器全部落空 | 必须自洽：`n = u·(8·bytes + 7)`，`m = 8·bytes` |
| `grid` 规则 | A | 改变槽位集合（如只取中频、或跳过低纹理块） | **DC 绝不能进池**，否则 `cover_digest` 随嵌入变化，直接崩 |
| `suites` 白名单 | A | 可裁掉弱套件 | 裁剪后旧载体读不了 |
| `slot_budget` / `h` | B | 覆盖率与改动密度（抗检的主旋钮） | 越大越慢；太小覆盖率下降 |
| `cost_model` | B | 改动落在哪些系数上（UERD 变体） | 换模型必须重新跑 DCTR（Phase 3） |
| `polarize_weight` | B | 改动方向偏置 | 未验证前保持 1.0 |
| `safety`（bpp 上限） | B | 载荷率 = 最灵敏的抗检变量 | 放宽等于自废武功 |

**私有版构建指引**

1. 复制 `DEFAULT_FORMAT` 的字面量，改 A 层的 5 个标签；需要的话再改 `sb` 几何；
2. `cargo build --features private-profile`（或直接把 `DEFAULT_FORMAT` 换掉），**不要做成 CLI 开关**——可切换的格式就是可枚举的格式；
3. **不要分发二进制**：常量会被逆向，私有标签一旦随二进制流出就失去意义。这个设计的正确用法是"自己编译、自己用"；
4. 改完先跑 roundtrip，再跑 DCTR（Phase 3 的脚本可直接复用）。库侧在 `FormatProfile::validate()` 里 `debug_assert` 几何自洽，防止改出无法解码的格式。

> 注意：A 层参数只影响"谁能读、检测器怎么建模"，**不改变抗检上限**——上限仍由载荷率与代价函数决定。改标签能躲过"针对上游 strhide 的定向检测器"，躲不过通用隐写分析（DCTR/SRNet）。这一点不能自我安慰。

---

## 四、删除清单（JPEG 侧）

| 删除项 | 位置 | 替代 |
| :--- | :--- | :--- |
| `dct_move` 及类桶语义 | `coding.rs:311-341` | `ternary_legal`（仅 `±1023` 单向） |
| `plan_slots`（池 + 排序 + 截断） | `jpeg/engine.rs:65-139` | `v3_layout` + 网格遍历 |
| `embed_dct_lsb` | `jpeg/engine.rs:354-363` | 头部改用 STC |
| 512 槽头 + `FeatureWord` 分支 | `jpeg/engine.rs:167-181, 241-259, 412-440` | 44B 超块 / 718 槽 + TLV 扩展区 |
| `HEADER_V2_ESCAPE_H` 的使用 | `jpeg/engine.rs:242` | 直接写 `h` |
| `StegoCodec::Hamming` 的 JPEG 分支 | `jpeg/engine.rs:306-316` | JPEG 固定 STC |
| `auto_select_codec` 的 JPEG 调用 | `jpeg/engine.rs:218-227` | `v3_layout` 的 `u` 公式 |
| `Move::Both => {}` 空操作写回 | `jpeg/engine.rs:337` | delta 写回 |
| `min_abs_coeff` / `block_exclusion_percentile` | `jpeg/engine.rs:90-113`、`params.rs` | 不再需要（无值门槛、无截池） |

**保留给空域**（本期不动空间域）：`FeatureWord`、`V2_TOTAL_HEADER_SLOTS`、`spatial_move_safe`、`hamming_*`、`MAX_STC_U = 3`（空域头部 codec id 语义）。空域沿用 32B 头，属独立议题，理由见 §十。

---

## 五、改造清单

### 5.1 内核 `coding/stc.rs`

| 改动 | 说明 |
| :--- | :--- |
| 新增 `embed_with_deltas(..., out: &mut [i8]) -> Result<usize>` | 在回溯循环（`:451-496`）记录 `Kind → −1/0/+1`；`embed` 保留为薄封装 |
| 列构造放宽 | `u ≤ 64`；`cols: Vec<u32>`；随机 h 位列（**允许相关**），去掉 `add_to_basis` 秩检查；但**必须保留 `x \|= 1; x \|= 1 << (h-1)`** |
| 常量 | 新增 `KERNEL_MAX_U = 64`、`validate_u_wide`；`MAX_STC_U` 保持 3（空域语义） |
| 无解处理 | **不做重试、不换种子**。触发即内部缺陷，返回 `General`（见下方论证）；理由：换了种子提取端不知道轮次，载体直接报废 |
| 不动 | `extract`：只读奇偶与 `H`，与 `u`/`move` 无关 |

> **"必然有解"的正确论证**（上一版这里写错过，按 §3.3 重写）：
> 1. 每个列向量最高位恒为 1（`stc.rs:29-31` 模块文档原文："该位是元素对**本组即将定稿那一行**的影响力，缺了它某些校验子不可达"），因此窗口内**任一可动元素**都能翻转当前行的校验子；
> 2. 合法性只挡 `|c| = 1023` 一侧（§3.3），所以**几乎所有位置都可动**，湿点密度 ≈ 0；
> 3. 二者相乘 → 任意消息位序列都能在每一步被满足。
>
> **上一版的错误**在于第 2 条曾写成"`|c| ≥ 2` 的系数至少保留一个方向"——那等于把 71% 的位置判成湿点，窗口容易全湿、行被钉死。所以不是"重试"错了，是"湿点密度"错了；门槛删掉后，重试确实不必存在。
>
> 保留防御性断言：若仍返回 no feasible solution，说明合法性/代价表接线有 bug，直接报错，不静默换种子（换种子提取端无从得知轮次）。

### 5.2 引擎 `jpeg/`

| 新增/改动 | 说明 |
| :--- | :--- |
| `v3_layout.rs` | `Layout { n_total, hdr_n, u, body_n }` + `compute(...)`；纯函数 |
| `header_v3.rs` | 44B 超块编解码、TLV 扩展解析、保留位零校验、套件试枚举驱动 |
| `embed_jpeg` | §3.7 |
| `extract_jpeg` | §3.8（签名去掉 `cost_model`） |
| 写回 | `for (slot, d) in BodySlots.zip(deltas) { coeff += d }`，`debug_assert!(coeff.abs() <= 1023)`；优化表路径下对被动块做符号序列校验（§3.3 第 3 段） |
| `dht.rs`（新） | 自带 DHT 解析（~80 行），只取 Y 分量的 AC 符号集；`dct-io` 不暴露 Huffman 表，必须自己读 |

### 5.3 参数 `params.rs` → 拆成三层（见 §3.9）

| 类型 | 位置 | 说明 |
| :--- | :--- | :--- |
| `FormatProfile` + `DEFAULT_FORMAT` | `stego/format.rs`（新，`pub`） | 格式身份：5 个标签、头部/扩展几何、grid 规则、套件白名单、版本号；`validate()` 只做 3 条几何断言 |
| `JpegParams`（**扩字段，不新造**） | `stego/params.rs`（已存在） | 加 `slot_budget` / `cipher_suite` / `polarize_weight` / `extensions`；删除 JPEG 侧已无意义的 `min_abs_coeff`、`block_exclusion_percentile` |
| `ExtractParams` | `stego/params.rs`（`pub`，新增） | `allowed_suites` / `max_kdf_cost` |

CLI 只暴露 B/C 层中"安全上无害"的少数项（`--slot-budget`、`--cipher-suite`、`--safety-tier`）。**A 层一律不做 CLI 开关**（可切换的格式 = 可枚举的格式）。

### 5.4 信封 `envelope.rs`

| 改动 | 说明 |
| :--- | :--- |
| KDF 参数化 | `derive_keys` 从"写死 PBKDF2-100k"改为"按 `CipherSuite` 执行"：`suite::derive_master(suite, password, cover_digest) -> [u8;32]`，再由 `keys_from_master(master, salt) -> (enc_key, perm_seed)` 做 HKDF 分层 |
| AAD 扩展 | 由 `salt ∥ nonce` 改为**整个 44B 超块**；`pack_envelope_ext` 需接受 `aad_prefix: &[u8]` |
| 加密顺序 | 必须先定 `plaintext` 长度（`ct_len = plaintext + 16`）→ 算出 `envelope_len` → 组装超块 → 才能以超块为 AAD 加密。所以"打包"拆成两步：`build_plaintext` / `encrypt_with_aad` |
| 解密顺序 | 逐套件试枚举（每次一次 KDF）→ 定位并解出超块 → HKDF 分层 → 用超块作 AAD 解密 |
| flags 校验 | `bit4..7` 非 0 → 拒绝；`bit1..3` 未知压缩 id → 明确报错 |
| 免二次搬运 | 新增 `unpack_envelope_parts(ct, salt, nonce, aad)`，提取端直接传切片，不再把 `[salt\|nonce]` 与 `ct` 拼成一个 `Vec` |

### 5.5 库入口 `lib.rs`

| 项 | 说明 |
| :--- | :--- |
| `pub use stego::format::{FormatProfile, DEFAULT_FORMAT}` | 私有版只需在 `main` 里构造自己的 `FormatProfile`，**不必改库代码** |
| `pub use stego::jpeg::{embed, extract}` | CLI 是薄壳，能力与库一致 |
| `pub use stego::params::{JpegParams, ExtractParams}` | 同上（`JpegParams` 是既有类型，加 4 个字段） |
| 文档 | 每个 `FormatProfile` 字段写清"改它会发生什么"，私有版照抄即可 |
| semver | `FormatProfile` 字段变更视为 **破坏性**（它是格式 API） |

> `envelope.rs` 是 JPEG 与空域共用的，改 AAD 会牵动空域调用点。空域本期不改槽位策略，只做两处适配：传入自己的 AAD（32B 头 + 32B FeatureWord）与套件 id。原则统一为"AAD = 本格式头部全部字节"，两边各管各的。

---

## 六、阶段计划与门禁

### Phase 0：契约层

* [ ] `v3_layout::compute` + 属性测试（1,000 组随机 `(N, bits, h, budget)`，两端结果一致）；
* [ ] `FormatProfile` + `DEFAULT_FORMAT` + `validate()`（几何自洽：`n = u·(8·bytes+7)`、`m = 8·bytes`；标签非空且互不相同）；
* [ ] 容量不足返回明确错误（`Capacity exceeded: need X slots, have Y`），不 panic；
* [ ] **超块编解码单测**：44B 逐字段 roundtrip；`envelope_len` 高位非 0、`flags` 非 0、`suite_id = 0`、`suite_id` 与实际试枚举套件不符、`codec_id` 未知 → 各自报对应错误。
* [ ] **确定性契约测试**：同一 `(cover_digest, password, domain)` 在两个进程（或两次调用、不同 `HashMap` 种子）下产出逐位相同的 `HdrSlots` / `BodySlots` 序列；断言实现里没有无序集合参与。
* [ ] **cover_digest 稳定性**：嵌入后重新读取 stego 图，`cover_digest` 与嵌入前逐字节相同（DC 不受影响）。

### Phase 1：内核

* [ ] `embed_with_deltas` 与 `embed` 一致性测试（delta 与 `vals` 变化逐项对应）；
* [ ] `u ∈ {1,2,3,6,24,64}` roundtrip 单测（含 `u > h`）；
* [ ] `u = 64` 压测：**确认无需重试**（构造 10 组极端代价/边界系数，断言一次即出解）。

### Phase 2：引擎

* [ ] 4 KB / 16 KB / 64 KB × 20 图 roundtrip，逐比特 100%；
* [ ] **不重叠测试**：`HdrSlots ∩ BodySlots == ∅`；
* [ ] **独立性测试**：只改正文不影响头部解码，反之亦然；
* [ ] **自检测试**：人为篡改头部 `u` → 提取报错而非输出垃圾；
* [ ] 错误密码 / 非载体图 → `NoHiddenData`，零 panic；
* [ ] **口令预言机成本门禁**：对同一载体的 100 次错误口令尝试，总耗时必须 ≥ 100 × 一次套件 KDF 的单次耗时（即不存在"绕过 KDF 的快速判别路径"）；同时断言结构校验发生在 KDF **之后**；
* [ ] **湿点密度门禁**：断言正文/超块的可动槽位占比 ≥ 99%（只有 `|c| = 1023` 被单向限制），任何 `u ∈ {1,6,24}` 下 100 张图嵌入零失败；
* [ ] **优化表门禁**：`temp/jpeg_huffman/{std,opt}` 各 3 张 + `file-08.jpg` + `sample.jpg`；`std` 组必须走快速路径且零失败，`opt` 组必须走符号判定路径且零失败；断言优化表路径下被挡方向占比 ≤ 1%；
* [ ] **结构变更校验**：构造 `±1 → 0` 触发链式 run 变化的用例，断言要么正常写入、要么给出明确诊断（不是裸 `CorruptEntropy`）；
* [ ] `c = 1023 / -1023` 构造用例：断言不产生 category-11 写回；
* [ ] **解耦复查**：`extract_jpeg` 签名不含 `cost_model`，也不读 Huffman 表（编译期 + 运行期双证）。

### Phase 2.5：格式扩展性（发布前必须全绿，之后改不动）

* [ ] **扩展 roundtrip**：注入 2 个 TLV（一个 critical、一个非 critical）→ 嵌入 → 提取，未知 TLV 被正确跳过 / 正确拒绝；
* [ ] **未知 critical TLV** → `UnsupportedVersion`，不得静默忽略；
* [ ] **扩展区尾部未用字节非 0** → `CorruptedData`；
* [ ] **`version_minor` 前向兼容**：手工构造 minor+1 的超块（含未知非 critical TLV），当前解码器必须能正常解出载荷；
* [ ] **`version_major` 不同** → 拒绝；
* [ ] **envelope flags 前向兼容**：`bit4..7` 置位 → 拒绝；`bit1..3` 为未知压缩 id → 明确报"不支持的压缩算法"而非解压失败；
* [ ] **字段冻结回归**：断言超块 44B 各偏移与文档一致（一个"文档即测试"的常量表比对）；
* [ ] **套件矩阵**：套件 1 / 2 各自 embed→extract 100%；套件表 id 唯一且升序（防止复用）；
* [ ] **套件拒绝**：`suite_id = 0` → 无效；`suite_id = 9999` → `UnsupportedVersion`；手工把 header 的 `suite_id` 由 2 改成 1 → **AAD 校验失败**（证明头字段被 AAD 绑定）；
* [ ] **资源上限**：伪造 `suite_id` 指向超大成本参数（不在表内则拒绝；表内越限则超限拒绝），解码器不得真的跑满内存；
* [ ] 把 §3.6 的冻结清单与决策树同步进 `docs/`（格式规范单独成篇，代码注释引用它）。

### Phase 3：抗检与预算

* [ ] 80 图 DCTR-8000：V3 vs 现有 V2 的特征漂移净下降（初稿承诺但从未测过的指标）；
* [ ] PSNR / 改动点数 / 输出体积增幅（≤ +8%）；
* [ ] 参数网格 `h ∈ {6,7,8,10}` × `SlotBudget ∈ {4e5, 8e5, 1.2e6}`，按"耗时 ≤ 3 s 且失真最小"定默认；
* [ ] 极化折价 `0.65` 独立 A/B，净收益为正才转正；
* [ ] `cargo test --test batch_corpus -- --ignored`、`--test batch_stego -- --ignored` 全绿。

### Phase 4：收尾

* [ ] `cargo fmt && cargo clippy --all-targets -D warnings && cargo test --all-targets`；
* [ ] `inspect` / `verify` / `scan` / `list` 适配 44B 超块与新容量口径；
* [ ] `docs/wire_format_v1.md` 里加一节「私有版构建」（半页：改哪 5 个标签、可选改头部几何、如何验证、为什么不分发二进制）——不单独开文档；
* [ ] **`docs/wire_format_v1.md` 定稿**：超块逐偏移表、TLV 规则、冻结清单、版本策略——作为唯一事实源，代码注释与测试引用它；
* [ ] README 容量表更新；`docs/CHANGES-20261021.md` 追加摘要。

---

## 七、性能预算

| 环节 | V2 实测 | V3 估算 | 依据 |
| :--- | ---: | ---: | :--- |
| UERD 代价图 | ~0.2 s | ~0.2 s | 同一实现，只算一次 |
| Viterbi 嵌入 | ~20 ms | **0.4~1.5 s** | 4.0×10⁸ 次转移，1~3 ns/次 |
| 置换 | ~5 ms | ~10 ms | 242 万元素 Fisher-Yates |
| 提取 | ~15 ms | **< 0.3 s** | 纯奇偶读取，无 Viterbi、无代价图 |
| 端到端嵌入 | 475 ms | **1.5~2.5 s** | 桌面 CLI 可接受 |

内存峰值 = 回溯位图 `n × states / 4` ≈ **50 MB**（`SlotBudget = 800k`），随预算线性增长，写入 CLI 文档。

---

## 八、风险登记

| 风险 | 影响 | 处置 |
| :--- | :--- | :--- |
| 优化 Huffman 表文件缺 `(run, cat)` 符号 | 写回失败 | 自带 DHT 解析 + 逐槽符号判定（实测只挡 0.19% 方向）；`±1↔0` 的链式 run 变更走写回后校验；彻底解法（patch dct-io 写标准表）列为 Phase 4 可选 |
| 删掉 `\|c\|≥2` 门槛后 0↔±1 变多 | 零游程变化、文件体积略增 | UERD 对平滑区 0 赋高代价；Phase 3 体积门禁 ≤ +8% |
| `cover_digest` 依赖"DC 不参与嵌入" | 若将来往 DC 里写数据，所有历史载体失效 | 写进冻结清单；DC 相关改动一律按主版本处理 |
| 头部定位走 KDF → 每次提取/扫描都要付一次 KDF | 批量 `scan` 变慢（约 +80~100 ms/文件） | 接受：这是换取"无快速口令预言机"的代价；`scan` 可先跑纯图像侧检测 |
| 套件试枚举最坏 3 次 KDF | 非默认套件载体提取慢 | 按 id 升序，默认套件在第 1 位命中 |
| `u > h` 列向量相关理论上可能无解 | 嵌入失败 | 已论证不可能（最高位强制 1 + 每元素至少一个合法方向）；保留内部断言，不做静默重试 |
| 50 MB 回溯位图 | 内存 | `SlotBudget` 可配；`h = 6` 时约 12 MB |
| 头部约 160 次改动落在随机位置 | 局部可见 | `u = 2` 提供选择空间，trellis 按 UERD 选点 |
| 小图/灰度图容量不足 | 无法嵌入 | `u` 下溢时明确报错 |
| 私有版把 `FormatProfile` 打进分发的二进制 | 标签被逆向，"定向检测"重新成立 | 文档写死"自用、不分发"；不提供 CLI 切换 |
| 用户把 `slot_budget` 调得过小 | 覆盖率下降 → 抗检变差 | 设下限（如 ≥ 8×bits），低于则警告 |
| 私有版改动 `grid` 把 DC 纳入 | `cover_digest` 随嵌入变化 → 自己都读不回 | `FormatProfile::validate()` 里 `debug_assert` 禁止 |

---

## 九、对评审意见的处置对照

| 评审条目 | 处置 |
| :--- | :--- |
| P0-1 单向门 | **根治**：值不参与槽位集合，`\|c\|=2` 锁与边界规则整体删除 |
| P0-2 截断毁自适应 | **根治**：`u` 自适应到 24（`R = 1/24`），与 pySTC 的 `u ≈ n/m` 同构 |
| P0-3 基准与落地脱节 | **重建口径**：Phase 3 用本方案参数实测，不引用 pySTC 数字 |
| P1-4 丢 Salt/Nonce | **修复**：超块显式容纳 16B Salt + 12B Nonce |
| P1-5 槽位算术冲突 | **修复**：718 槽 = `2×(352+7)`，精确填充 |
| P2-6 门禁笔误 | **删除**：新门禁为结构断言（两端槽位序列逐项相等） |
| P2-7 破坏 V2 回退 | **不再适用**：无旧载体，V2 路径整条删除 |
| P2-8 空域遗漏 | **显式排除**：本期只做 JPEG 频域；空域是固定像素网格，本就无池失步问题 |
| 补充：写回无法表达三元 | **修复**：`embed_with_deltas` + delta 写回 |
| 补充：`u ≤ h` 硬约束 | **修复**：随机列构造 + `cols: Vec` |
| 补充：基准用均匀代价 | **修正**：Phase 3 一律用真实 UERD 代价 |

### 第二轮独立评审（格式与工程）

| 条目 | 判定 | 处置 |
| :--- | :--- | :--- |
| 1. `probe` 是口令爆破预言机 | **成立，但处方不足** | 已删 `probe`；并进一步把**头部定位**改为走套件 KDF（`cover_digest` 作盐）+ 试枚举。只删 `probe` 不够：结构校验同样是微秒级预言机 |
| 2. "换列种子重试 ≤8 次"会让载体报废 | **成立** | 已删除重试；`bit0/bit(h-1)` 强制为 1 + 每元素至少一个合法方向 → 必然有解（§5.1 论证） |
| 3. `assert u == layout(bits)` 绑死本机预算 | **成立** | 已删除断言；只校验 `u ∈ 1..=64` 与容量，`SlotBudget` 降级为纯嵌入端参数 |
| 4. `±1024` 边界导致 AC 编码溢出 | **成立但不够** | 阈值改 `±1023`（`category(1024)=11`），**并且**补上真正的根因：跨 `2^k` 会升 category，原表可能没有该符号 → 引入 `(run, cat)` 符号覆盖检查 |
| 5. `BodyGrid` 缺确定性遍历顺序 | **成立** | 新增"平坦索引 + bitset、禁 `HashSet`"的实现契约（§3.1）+ 跨进程逐位一致门禁 |
| 6. `has_ext` 与 `ext_bits` 冗余 | **成立** | 改为 `ext_bytes`，删除 `has_ext`，`flags` 全保留为 0 |
| 7. 提取端二次拼接 envelope | **成立（低优先）** | 提供 `unpack_envelope_parts(ct, salt, nonce, aad)`，避免多一次堆分配与拷贝 |

### 第三轮独立评审（简化 vs 失效）

| 条目 | 判定 | 处置 |
| :--- | :--- | :--- |
| 1. `\|c\|≥2` 门槛导致无解 | **成立（关键）** | 实测 AC 中仅 29.1% 满足 `\|c\|≥2` → 71% 湿点；超块 `u=2` 时窗口全湿概率 0.4%×352 行 ≈ 半数图连头部都嵌不进。已删门槛，改为全图 `±1` + 仅 `±1023` 单向 |
| 1b. 该门槛等于单向门 | **不成立** | `3→2` 允许，`2↔3` 对称，`1/2` 是闭合边界，无净流向。它的问题是湿点密度，不是单向流动（结论相同、机理不同，已写进 §3.3 免得后人按错理由改） |
| 2. `FormatProfile` 是过度设计 | **不采纳** | ① 这是项目所有者的明确需求（私有版自定义指纹）；② 不是新框架：`params::Profile` / `StegoProfile` / `JpegParams` 已存在，V3 只加 1 个 13 字段 struct + 4 个字段；③ 格式要冻结，身份常量必须在首版集中，否则散落各处 |
| 3. `HuffmanCoverage` 动态查表是弯路 | **部分成立，结论要改** | 成立的：`dct-io` 不暴露表，原设计实现不了。不成立的：用标准表兜底就够——实测语料里真有优化表（`file-08.jpg` 24MP、ffmpeg 默认输出），被挡方向 0.19% 足以让写回失败。最终：自带 DHT 解析 + **只在表不完整时**逐槽判定，99% 的文件零额外成本 |
| 4. 提取端套件盲试枚举 | **部分采纳** | Argon2 降级为保留 id（v1 不实现，避免 64 MB 盲跑）；v1 只保留套件 1/2 两个 PBKDF2 变体，最坏 2 次约 160 ms。循环保留——否则套件 2 的载体要带外告知口令，等于给审查者递线索 |
| 5. 保留 `cover_digest`、删 `probe`/`has_ext` | **同意** | 已保留/已删除，无需改动 |

---

## 十、未纳入范围

* **空域（PNG/WebP HILL）**：独立议题。它的槽位是固定像素网格，不存在本方案的池失步问题；9σ 赤字由 `spatial_move_safe` 单独处理。两套头部并存（JPEG 44B 超块 + TLV / 空域 32B + FeatureWord）；若要统一，建议走"空域改用同一超块 + `components_mask` 扩展"路线。
* **对抗式嵌入（抗 SRNet）**：决定性变量是载荷率与代价函数，与本次架构迁移正交。
* **多 codec 支持**：V3 固定 STC，但超块已有 `codec_id` 字段，将来加 Hamming/多图层只需加编码器 + 新 id，不动超块布局。
