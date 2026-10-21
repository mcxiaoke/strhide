# 内容域隐写抗检加固：最终实施方案（v2 Header 路线）

> **编制日期**：2026-10-21 15:10
> **文档定位**：**最终版实施总方案**。合并并裁定以下四份材料的全部论断，经逐条代码核对后给出唯一可执行的工程路径。
> **文档状态**：待评审（For Review）
>
> **裁定输入**：
> 1. [`steganalysis_tools_and_countermeasures_memo_20261021.md`](steganalysis_tools_and_countermeasures_memo_20261021.md)（调研备忘，下称 **memo**）
> 2. [`stego_profile_convergence_and_hardening_plan_20261021.md`](stego_profile_convergence_and_hardening_plan_20261021.md)（实施方案 v1，下称 **plan-v1**）
> 3. 本轮会话补充评审（对话，2026-10-21 下午，下称 **评审丙**）
> 4. [`stego_plan_independent_review_20261021_144914.md`](stego_plan_independent_review_20261021_144914.md)（独立评审，下称 **评审丁**）
>
> **变更记录约定**：本文替代 plan-v1 成为实施依据；memo 降级为机制资料，按 §8 勘误后使用。实施期间每阶段落地须按 `AGENTS.md` 在 `docs/CHANGES-YYYYMMDD.md` 顶部追加条目。

---

## 1. 证据等级约定与甄别结论

### 1.1 证据等级（全文档遵循）

| 等级 | 含义 |
|---|---|
| **E1** | 代码/规范中的确定事实，可按文件行号核对 |
| **E2** | 实测数据，附复现方式（评审丁 `temp/stego_probe/`、`docs/stc_capacity_eval_report_20261021.md`） |
| **E3** | 原理推断或文献数量级，**不可作为验收依据** |

### 1.2 四文档论断裁定总表

| # | 论断 | 来源 | 裁定 | 依据 |
|---|---|---|---|---|
| 1 | 防指纹（KDF 域/密钥/通道）与抗检测（载荷率/STC）是两个维度 | memo/plan-v1 | ✅ 采纳 | E1，概念分层成立 |
| 2 | `0xF8` 类掩码是“论文最优配置、绝不可动” | memo §4.2 | ❌ **否决**：它是**项目自研不变式**（保提取端代价图可复现），不是论文结论；且正是 P0-2 指纹的根因 | E1：`coding.rs:343-375`、`hill.rs:194` |
| 3 | 三进制 ±1 使“卡方检出率直接失效” | memo §3.2 | ❌ **否决**：chi2/RS/SPA 对本方案是“前提失配、无检验力”；但**类残差直方图**给出了新的可估计嵌入率的攻击面 | E1（单边 `clamp`，`analysis.rs:860-880`）+ E2（评审丁 §4） |
| 4 | “87.5%→<7.5%”证明抗检提升一个数量级 | memo §4.1 | ❌ **否决为验收依据**：这是自家 `scan` 启发式分数跳变，非 SRM/SRNet \(P_E\)；同一批数据既调阈值又报效果，无留出集 | E1/E2（评审丁 §3） |
| 5 | r≥4.5 是“黄金安全线” | memo/plan-v1/评审丙 | 🔁 **修正**：4.5 是**边界不是余量**（eval 报告：r=4.67 → 风险跳变 3.8%/7.5%；r=9.35 → 0~1.3%）；且 r 跨格式不可比。默认 recommended 上调至 bpp 口径 | E2（`stc_capacity_eval_report_20261021.md` §二） |
| 6 | `stego_domain` 用标签字符串模板化 | plan-v1 §3.1 | ❌ **否决**：五个旧标签前缀族/版本后缀不统一（`stego-` vs `stc-`，v1 vs v2），任何单一 domain 串都无法还原；按示例实现将破坏全部存量文件 | E1：`envelope.rs:75-111`；采纳评审丁的 HKDF 子密钥方案 |
| 7 | 通道固定绿色是“单通道方差峰值指纹” | memo/plan-v1 | 🔁 **修正**：机理应是 **luma 权重**（G=0.587 恰是最差单通道，B=0.114）；“多通道残差比对工具”缺工具侧证据；RgbSpread 总改动量不变，收益未验证 | E1（`hill.rs:53-58`）+ 评审丁 §5.5：降级 P2 实验 |
| 8 | `safety_level=UltraStealth` 容量减半“致盲 SRNet/SRM” | plan-v1 §3.2 | ❌ **否决措辞**：对类边界指纹只把 9σ 降到 ~4.5σ（线性）；对文献 SRNet 也非“致盲”。改为 bpp 三档 + 显式 Enforce | E2（评审丁 §4.4/§7.3） |
| 9 | `ChannelMode` 是 P 类参数 | plan-v1 §2.1/§3.3 | ❌ **否决**：鸡生蛋——header 定位依赖候选集，读端不知 mode 就找不到 header。改为 **F 类**：header 永远用 legacy 设置，mode 记入 v2 feature word | E1：`engine.rs:536-546`、`header.rs:15-45` |
| 10 | API 收敛后仍公开 `stc_h`/`algorithm` | plan-v1 §3.4 | ❌ **否决**：`stc_h` 已 header 自描述；`algorithm` 是 stringly-typed 且实际只有一个模型。删除/下沉 | E1：`registry.rs:21-33`、`header.rs` |
| 11 | 兼容矩阵“与 0.3.x / 0.4.0 完全一致” | plan-v1 §4 | ❌ **否决**：`v0.4.0` tag（2026-10-20）为旧布局（固定 top-256 头槽 + `0xFE` 掩码），`CHANGES-20261020.md:12` 明言本版提不出，且无 legacy 回退。拆分为 wire/source/读旧/写新多行陈述 | E1：`git show v0.4.0:...` + CHANGES |
| 12 | PBKDF2 100k 可接受 | ——（新议题） | ✅ **采纳评审丁**：低于 OWASP 对 PBKDF2-HMAC-SHA256 的 600k 建议；v2 header 加 KDF id，新文件升 600k，旧读取保留 | E1：`envelope.rs:69` |
| 13 | i18n `{kib:.1}` 格式占位符、`--exclusion-rate` 帮助默认值不一、“half of max”过期文案 | ——（新议题） | ✅ **采纳评审丁**：`format_msg` 的 key 解析不剥离 `:spec`，release 下原样输出。顺手修复列入 Phase 4 | E1：`i18n/mod.rs:120-140`、`cli.rs:1333`、`messages.rs:700` |
| 14 | `exclusion_percentile` 是纯写侧 L 类 | plan-v1 §2.2 | ❌ **否决**：提取端重建候选集同样用它（`engine.rs:687-707`），实为读写对称参数。v2 起收入 feature word 自描述，消除对称配置耦合 | E1 |
| 15 | 正文槽位=公开 HILL 代价序最便宜 N（仅头部 256 槽密钥化置换） | ——（新议题） | ⚠️ **记录为已知暴露**：槽位集合可被无密钥复算，scheme-aware 检测器可预测改动位置。属显式取舍（保最小失真），列 P2 研究，不在本期修正 | E1：`engine.rs:541-562` 注释 |

**四文档一致性说明**：评审丙与本轮对话中“三进制结构性免疫 chi2/SPA”的表述，被评审丁 P0-2 修正为“对经典检测器前提失配，但引入类残差攻击面”；评审丙对 RgbSpread 的推荐同步降级为“luma 加权约束下的 P2 实验项”。其余互证一致的结论（domain 兼容缺陷、API 收敛矛盾、`致盲`措辞、0.3.x/0.4.0 声明失实、scan 不作验收）予以合并。

---

## 2. 最终问题总账（去重后，按优先级）

| 编号 | 问题 | 等级 | 证据 | 处置 |
|---|---|---|---|---|
| **P0-A** | 评测证据自指：`scan`（chi2/RS/SPA，均 LSB 替换模型）不能证明抗 SRM/SRNet；阈值无留出集、无图像级 CI | E1/E2 | 评审丁 §3 | Phase 0 建独立评测 |
| **P0-B** | `0xF8` 类边界单向移动 → 类残差直方图赤字，**可线性估计嵌入量**（推荐容量下 9.1σ/9.3σ；N≈16·δ₀，误差 <4%） | E1/E2 | `coding.rs:366-375`；评审丁 §4 | Phase 1 默认排除 r∈{0,7} |
| **P0-C** | header 32 位用满（26 len + 2 codec + 4 h），`ChannelMode`/class rule/KDF id 无处记录；F 类参数影响 header 定位形成鸡生蛋 | E1 | `header.rs:15-25`；`engine.rs:536-546` | Phase 1 落地 v2 header |
| P1-A | `stego_domain` 标签模板化破坏默认兼容 | E1 | `envelope.rs:75-111` | Phase 2 子密钥化 |
| P1-B | 容量口径：r 预算与三通道冲突（3 倍放大）、4.5 是边界、跨格式不可比、Enforce 会破坏现有脚本 | E1/E2 | 评审丁 §7 | Phase 3 bpp 三档 |
| P1-C | KDF 100k 偏弱，无 KDF 版本位 | E1 | `envelope.rs:69` | Phase 3（依赖 P0-C） |
| P1-D | API 收敛自相矛盾：`stc_h`/`algorithm` 仍公开、CLI 七个数学旋钮、删字段 source-breaking 无迁移 | E1 | `cli.rs:335-470`、`stego/params.rs:278-287` | Phase 4 deprecation |
| P1-E | 结构层非绝对“0 风险”：`encode_png` 固定 level 6，遇 level 9/zopfli 来源载体产生 FLEVEL/分块差异；文件 +1.0% | E1/E2 | `engine.rs:309-332`；评审丁 §9.1 | Phase 5 实验 |
| P2-A | RgbSpread 收益未验证（总改动量不变；逐通道 1/3 vs 联合检测器不变） | E1/E3 | 评审丁 §5.5 | Phase 5 对照实验后定 |
| P2-B | 事实性/用户可见：论文归属、i18n 占位符、帮助默认值、"half of max" 文案、4MB 采样截断 | E1 | 评审丁 §10 | Phase 4 顺带 |
| P2-C | 正文槽位成本序可无密钥复算（已知取舍） | E1 | `engine.rs:541-562` | P2 研究，记录不修 |

---

## 3. 最终技术设计

### 3.1 P0-B：类边界单向移动指纹与修复

**机制（E1）**：为保 `val & 0xF8` 不变（提取端重算 HILL 代价图逐位一致），`spatial_move(val)` 规定 `val%8==0` 只能 `+1`、`val%8==7` 只能 `-1`（`coding.rs:366-375`）。嵌入时：

- r=0 像素被改必流向 r=1；r=7 像素被改必流向 r=6；
- 类内像素双向由代价择优，近似均衡；
- 净效应：r=0 与 r=7 各出现净赤字 δ₀、δ₇，r=1/r=6 净盈余，且 **δ ≈ N_changed/16**（r=0 流出 1/8·N、从 r=1 回流 ~1/16·N）。聚合 32 个 8 值类后信噪比进一步升高。

**实测（E2，评审丁 §4.2）**：1920×1280 相机图，45 KiB（推荐容量附近）：r=0 赤字 5,096/315,445 ≈ 9.1σ，改动量估计误差 <4%；100 KiB 44.7σ；188 KiB 83.3σ。`exclusion_percentile`（按代价排除平滑区）不按残差排除边界，**无缓解**；`scan` 因 chi2 单边且方向相反而结构性失明。

**修复（采纳评审丁方案 A，定为本期默认）**：

1. **候选资格收紧为 `val % 8 ∈ [1,6]`**（保持 `[8,247]` 外层值域），单向门彻底消失，类残差赤字趋近噪声级。
2. 代价：候选池约 −25%（自然图残差近似均匀），推荐载荷同比例下降（示例 46,454 B → ≈34,835 B）；同载荷下 `Auto` 可能从 u=3 降 u=2，改动率 0.227→~0.26，r 余量同步重算——**这是“容量换可检测性”的显式取舍，需在 CLI 输出中明示**。
3. **备选（若容量损失不可接受）**：对 r∈{0,7} 槽位加壁代价（wall cost）压低其被选概率而非排除。残余赤字与边界槽占比成正比，**必须**用 Phase 0 的类残差估计器定量验证残余显著性达标（目标 <3σ）后方可采用；默认仍走路径 1。
4. 新旧资格集是**读写对称 + header 定位相关**参数 → 必须由 v2 feature word 自描述（见 3.2），不能靠口头约定。

**拒绝的方案**：keyed class phase（每图仅 8 种相位，≈3 bit 秘密，可穷举）；跨类 ±1（破坏 `& 0xF8` 不变式，提取端排序失同步，评审丁 §4.5 方案 C）。

### 3.2 P0-C：v2 Header 与 P/F/L 三分类

**参数分类改为三类**（替代 plan-v1 的 P/L 二分）：

| 类 | 定义 | 可否影响 header 定位 | 如何到达读端 | 例 |
|---|---|---|---|---|
| **P** | 私有方言/秘密，读写必须一致 | 可以 | Profile 显式配置 | `default_secret`、`stego_domain` |
| **F** | 格式特性 | **不可以** | v2 feature word 自描述 | codec/u/h、class rule、channel mode、KDF id、资格值域/排除比例 |
| **L** | 纯写侧策略 | 不可以 | 无需到达读端 | safety 档位、compression、Enforce 开关 |

**铁律：F 类不得影响 header 定位。** header 288 槽（256 header + 32 feature word）永远用 **legacy 规则**选取：绿色单通道、`[8,247]` 资格、30% 排除、v1 的密钥化置换。F 类只作用于**正文候选池**。旧文件与新文件因此共享同一 header 定位算法，仅靠 h=15 逃逸区分版本。

**v2 线格式**：

```text
word1（32 B，布局不变，前 28 B 仍为 [16B salt][12B nonce]）：
  bit  0..26   envelope 长度（不变）
  bit 26..28   codec id（照常填写，仅冗余，以 feature word 为准）
  bit 28..32   = 15  → v2 逃逸（h 合法值 4..10，11..14 保留）
              ≠ 15  → v1 路径，逐位兼容现有实现

feature word（32 B = 256 bit，读 permuted_candidates[256..288]，同 legacy 规则）：
  bit  0..4    version = 2
  bit  4..6    codec（0=Hamming，1=STC）
  bit  6..9    u（1..3；0 = 随 r 自适应）
  bit  9..13   h（4..10）
  bit 13..15   channel_mode（0=Green 兼容，1=Blue，2=Spread）
  bit 15..17   class_rule（0=legacy r∈[0,7]，1=无边界 r∈[1,6]，默认 1）
  bit 17..19   kdf_id（0=PBKDF2 100k 兼容，1=PBKDF2 600k，2=预留 Argon2id）
  bit 19..27   eligible_min（外层值域下界，默认 8）
  bit 27..35   eligible_max（默认 247）
  bit 35..51   exclusion_permille（0..900，默认 300）
  bit 51..255  reserved（必须为 0；非 0 视为损坏 → NoHiddenData）
```

要点：

1. **旧二进制读 v2 文件**：`validate_stc_h(15)` 拒绝 → 安全折叠 `NoHiddenData`，不会误码（Phase 1 须用真实旧二进制回归此点）。
2. **v2 读端读 v1 文件**：h≠15 → 走 v1 路径，逐位兼容（golden vector 守住）。
3. feature word **无认证**：损坏/未知值一律折叠 `NoHiddenData`，禁止解释性回退（与 `codec_from_header_id` 现有哲学一致）。
4. 容量模型：正文可用槽位 = 正文候选池 − 288（头 + feature word）；`test_stego_capacity_model_is_tight` 同步更新。
5. 从此 **codec/u/h/资格规则/排除比例/通道模式/KDF id 全部自描述**：普通用户不再需要“提取时与嵌入时配置一致”，彻底消除该类静默 `NoHiddenData` 失败面（v1 文件除外）。
6. 文档同步：`docs/api/WIRE_SPEC.md` 新增 v2 feature word 章节；`docs/api/ARCHITECTURE.md` §4.3/§7.3 改写。

### 3.3 P1-A：`stego_domain`（HKDF 子密钥化，零默认路径扰动）

采纳评审丁 §6.2 设计：

```text
若 domain 为 None：五个 HKDF 标签与 salt 一律不动（derive_keys / derive_header_perm_seed / derive_stc_seed 逐位兼容）。
若 domain = Some(d)：
  subkey = HKDF-SHA256(ikm = pbkdf2_key（或 norm_pw，hpos 分支）, info = "strhide-stego-domain-v1" || be64(len(d)) || NFC(d))
  后续 Hkdf::new 的 IKM 换为 subkey，五个标签、两个固定 salt 保持不变。
```

工程约束：

- **NFC 归一化 domain**（今天 13:34 刚为密码补的 NFC，同源问题；macOS NFD vs Windows NFC 必须一致）；
- **长度前缀**防拼接歧义（`"ab"+"c"` vs `"a"+"bc"`），评测丁要求的碰撞测试用例化；
- 空 domain ≡ None（与 `secret()` 空串语义对齐）；
- 命名避开 `Profile::domain()`（UBE stealth domain，`params.rs:354-357`）：`StegoProfile::stego_domain()` / `with_stego_domain()`；
- `StegoProfile::is_official()` 必须同时要求 `secret().is_none() && stego_domain().is_none()`（`params.rs:253-256` 现状只看 secret）；
- CLI/config/env：`--stego-domain` / `stego_domain` / `STRHIDE_STEGO_DOMAIN`；两处 clap 结构体、`resolve_stego_secret` 需扩展为同时返回 domain、`KNOWN_KEYS`、i18n；
- 验收措辞修正：plan-v1 §6 “两次嵌入头部物理像素索引完全不同”是概率断言（256 槽可碰撞），改为“**header seed 不同 + 交叉提取恒定 `NoHiddenData`** + 默认路径 golden vector 逐字节一致”；
- 威胁模型入档：domain 是**密钥域隔离**，不是抗统计检测；对仅有图片的攻击者零像素统计差异；对持有二进制的攻击者是低熵口令（可能被字典枚举）；不列为“防指纹”主要手段，只作跨系统/跨应用隔离。

### 3.4 P1-B：容量与安全等级（bpp 主预算，三档 + 显式 Enforce）

**原则**：r 只作 codec 适配的次级量（`Auto` 选 u），**不作跨格式安全口径**；预算按格式族分别以 bpp 表达：

| 档位 | PNG 预算（bits/pixel） | 近似 r（绿通道） | JPEG | 定位 |
|---|---:|---:|---|---|
| `Balanced` | ≤ 0.15 | ≈ 4.7 | | 边界，历史默认，不作“安全”宣称 |
| `High` | ≤ 0.10 | ≈ 7.0 | JPEG 另表标定（Phase 0） | **新默认 recommended** |
| `Paranoid` | ≤ 0.06 | ≈ 11.7 | JPEG 另表标定 | 极限场景 |

- r↔bpp 换算常数（槽/像素 ≈ 0.65~0.7）须用 Phase 0 留出语料重新标定并写入代码注释。
- **Enforcement**：`Advisory`（默认，超限只警告并报告实际 bpp/r/预估改动率，不破坏现有脚本）/ `Enforced`（显式 opt-in，超限明确拒绝并提示分卷或换大图）；0.6 起默认翻转。plan-v1 “直接拒绝”的表述废止。
- safety 同时约束 codec：显式 `Hamming`（0.29 flips/bit）下达到同等 bpp 不享受 STC 的改动率收益——probe 输出必须标注该 bpp 假设下的 codec 与预期改动率（`estimated_change_rate` 已存在，补齐 Auto 解析后的标注）。
- `max_raw_payload_bytes`（Auto 按 u=1 报）与 `recommended`（按目标档位）口径须在 CLI 输出中分别标注，避免误读。
- Feasibility：bpp 预算换算出 needed_bits 超过正文可用槽位（含 u 约束）→ 明确报错，提示分卷。

### 3.5 P1-C：KDF 升级（依赖 v2 feature word 的 kdf_id）

- v2 新写入默认 `kdf_id=1`：PBKDF2-HMAC-SHA256 **600,000** 轮（OWASP 对齐；无新依赖；实测单次派生 <1s）。
- `kdf_id=2` 预留 Argon2id，列入 Phase 5 评估（需新依赖 + 参数基准 + 两端 benchmark）。
- v1 文件（`kdf_id=0`，100k）读取路径永久保留；**KDF id 属 F 类，不得影响 header 定位**（feature word 在密钥派生前可读）。
- 注意：`derive_header_perm_seed` 不经过 PBKDF2（HKDF 直出，为省 100k 迭代），该处不受轮数影响，保持现状并在文档明示此权衡（评审丁对 plan-v1 §5.1 的同一结论）。

### 3.6 P2-A：通道策略与 RgbSpread（实验先行，不承诺）

- **本期不做 RgbSpread**（plan-v1 Phase 3 废止）。前置条件：color-SRM / 联合 color 检测器对照实验（Phase 5），量化“逐通道密度 1/3”对真实威胁模型是否成立。
- 若实验支持，设计约束（评审丙 + 评审丁合并）：
  - `ChannelMode` 为 **F 类**：header 288 槽永远绿色（legacy），正文 mode 记入 feature word；probe 需感知 mode（`probe_carrier_capacity` 增加 profile/channel 入参——`stego/mod.rs` “probe 不依赖 Profile” 的注释届时正式 revisit）；
  - 通道选择概率按 **luma 权重反比**（G<R<B，`0.299/0.587/0.114`），最小化单位改动的 luma 扰动；均匀 1/3 打散会把 luma 扰动从绿通道 0.587 抬到 0.33，对灰度域检测器劣于蓝色单通道；
  - **RGBA 排除 alpha**（alpha 改动改变透明度，属语义破坏，非隐写）；灰度/调色板优雅降级为通道 0；
  - 预算按 bpp（3.4），r 预算与三通道的 3 倍放大冲突（评审丁 P1-2）由此自动消解。

### 3.7 P1-D：API 收敛与 CLI（deprecation，不在 0.5.x 删除）

- 公开 `StegoOptions` 移除 `algorithm: Option<String>`（格式嗅探已选引擎，每域实际仅一个代价模型：`registry.rs` spatial=hill / jpeg=uerd，“wow/uniward” 已删）、移除 `stc_h`（header/feature word 自描述，内部固定 `DEFAULT_STC_H=8`）。
- `SpatialParams`/`JpegParams` 公开字段 **不直接在 0.5.x 删除**：加 `#[doc(hidden)]` + `#[deprecated]`` 兼容层，0.6  Breaking 移除并出迁移指南；CLI 七个数学旋钮（`--p1-window/--p2-window/--neighbor-weight/--min-abs-coeff/--stc-h/--stc-u/--exclusion-rate`）在 0.5.x 标记 hidden + 使用时警告，0.6 移除；确有高级需求时以语义档位提供（如质地选择性映射排除比例，经 feature word 自描述）。
- v2 起 F 类参数自描述后，普通 API 表面积收缩为：`Profile`（P 类：secret/domain）+ `StegoOptions`（L 类：safety/enforcement/compression），与 plan-v1 目标一致但落地路径改为先建 feature word。

### 3.8 P1-E：结构/编码器指纹（P2 实验，本期只记录）

- `encode_png` 固定 `Compression::default()`（level 6），遇 level 9/zopfli 来源载体会产生 zlib 头（FLEVEL）/IDAT 分块差异；“原图 vs 重编码”二分类器 + 文件 +1.0% 为待验证弱特征（E2/E3）。
- Phase 5：估计并匹配源图 FLEVEL、保持 IDAT 分块与 filter 策略（filter 保持已实现，`engine.rs:304`）；JPEG 侧验证 DHT/DQT/APP 段保持；做语料级结构分类实验后再定默认行为。memo “结构层 0 风险”按评审丁 §9.1 改写为“低风险，需语料级验证”。

---

## 4. 分期实施路线图

> 门禁：每阶段结束 `cargo fmt --check`、`cargo clippy --all-targets -D warnings`、`cargo test --all-targets`、`cargo test --test batch_corpus -- --ignored`、`cargo test --test batch_stego -- --ignored` 全绿，并追加 CHANGES 条目。

### Phase 0：独立评测基座（约 1.0~1.5 人日）
- 交付 `rust/tests/stego_eval.rs`（`--ignored` 手动跑，按 batch_stego 惯例）：
  1. **类残差估计器**：聚合 32 个 8 值类的边界赤字 δ₀/δ₇ → 估计 N≈16·δ₀，与真值比对（目标：clean 载体不显著，rule=1 嵌入后 <3σ）；
  2. **双边 chi2 + 逐通道残差方差**（修 `analysis.rs` 4MB 截断为全图或等距抽样，chi2 按通道分算）；
  3. **槽位可复算性量化**：无密钥复算 HILL 代价序，测量预测改动位置命中率（P2-C 基线）；
  4. SRM（34,671 维）+ FLD 集成的接入评估（引 Aletheia 作独立进程，注意许可证只运行不链接；或先以 scheme-aware 估计器顶替）；
  5. 载荷梯度 0.05/0.10/0.15/0.2 bpp，**留出集** ≥20 张（不用标定集的 80 张），图像级 bootstrap CI。
- 验收：输出 clean/嵌入的 δ₀ 分布与 CI；bpp↔r 标定常数写入 3.4。
- 风险：无（不改生产代码）。

### Phase 1：v2 Header + 类边界修复（约 2.5~3.5 人日）
- `header.rs`：v2 逃逸（h=15）+ feature word 编解码；`engine.rs`（spatial+jpeg 两路）：header 288 槽 legacy 规则、正文按 feature word 重建候选池；容量模型 −288；默认 `class_rule=1`、`kdf_id=0`。
- 修复 P2-B 的 i18n 占位符与文案（`format_msg` key 剥离 `:spec`；“half of max”→bpp/r 口径；`--exclusion-rate` 帮助默认值对齐）。
- 测试：v1 路径 golden vector（与改动前二进制交叉提取）；v2 全语料往返；旧二进制读 v2 → `NoHiddenData` 回归；feature word 未知版本/保留位非零 → `NoHiddenData`；类赤字 <3σ；容量紧容差测试更新。
- 兼容面：**新默认文件 v1 二进制读不出（安全拒绝）**——按项目先例（CHANGES-20261020:12）显式记录；v1 读写路径逐位不变。
- 风险：中。两端对称调试量大；header-legacy 与 body-feature 双池逻辑须逐项对拍。

### Phase 2：`stego_domain` 子密钥化（约 0.5~1.0 人日）
- 按 3.3 落地 + CLI/config/env/i18n + `is_official()` + 命名修正 + 测试（golden vector、同密码异域 `NoHiddenData`、NFC/NFD 一致、长度前缀碰撞、空域≡None）。
- 风险：低（None 路径逐位不变）；注意今天 13:34 的 NFC 改动与本改动在同一函数，须合并回归。

### Phase 3：容量策略 + KDF 升级（约 1.0~1.5 人日）
- SafetyLevel 三档 + Enforcement；bpp↔r 换算与 Phase 0 标定值；probe/embed 接入；`kdf_id=1`（PBKDF2 600k）；probe 增加 profile 入参（为 Phase 5 通道模式预留）；CLI 输出标注 codec 假设与 bpp。
- 测试：三档往返、Advisory 不拒绝/Enforce 拒绝、KDF id=1 嵌入 + id=0 读取互操作、batch 语料全绿。
- 风险：中低。600k 轮使单次派生 ~0.6s，须在 `--help`/文档明示耗时。

### Phase 4：API 收敛与文档同步（约 1.5~2.0 人日，可与 Phase 2/3 并行）
- 3.7 落地；`docs/api/ARCHITECTURE.md`、`docs/api/WIRE_SPEC.md` 全面改写（§1.1/§14.2 标签表、feature word 新章节、stc_h/stc_u 配置位置勘误——今天 13:34 刚写入的内容部分作废，须显式勘误）；memo 按 §8 勘误。
- 风险：低-中（文档与 deprecation 面）。

### Phase 5：实验与可选项（约 1.0~1.5 人日，视结果取舍）
- color-SRM/luma 通道实验 → 决定 ChannelMode 是否落地（若落地按 3.6 约束）；
- 结构指纹（FLEVEL/IDAT/DHT）实验与缓解；
- Argon2id（kdf_id=2）评估；
- P2-C 正文槽位成本序暴露的研究（块级选集合/代价量化抖动/Gibbs 采样）——只出结论，不承诺排期。

---

## 5. 兼容性矩阵（修正版，拆分为 wire / source / 读旧 / 写新）

| 维度 | 场景 | 结论 |
|---|---|---|
| **wire** | 默认 Profile 下 v1 字节流 | 与现行 main **逐位一致**（golden vector）；Phase 2/3 不触碰 None 路径 |
| **wire** | v2 新默认文件 → 现行/旧二进制 | 旧二进制 `validate_stc_h(15)` 拒绝 → 安全 `NoHiddenData`，无误码（Phase 1 用真实旧版二进制回归） |
| **wire** | v1 文件 → v2 读端 | h≠15 走 v1 路径，逐位兼容 |
| **读旧** | 0.3.x / 0.4.0 产出的内容域文件 → 现行任何版本 | **不支持，且无回退**（v0.4.0 为固定头槽 + `0xFE` 布局，`CHANGES-20261020.md:12`）。plan-v1 “与 0.3.x/0.4.0 完全一致”的声明作废；如需支持须单独立项补 legacy 回退 |
| **source** | 库 API 字段删除 | 0.5.x `#[doc(hidden)] + #[deprecated]`，0.6 Breaking + 迁移指南 |
| **配置对称** | F 类参数（codec/u/h/规则/通道/KDF/排除比例） | v2 起 feature word 自描述，**不再要求读写对称配置**；仅 P 类（secret/domain）需对称 |
| **私有隔离** | 异 domain / 异 secret | 恒定 `NoHiddenData`（同错误密码） |

---

## 6. 对原文档的勘误清单（最终版权威结论）

memo 的修改项并入评审丁 §12（论文归属：HILL=Li Bin 等、UERD=Guo 等、Fridrich=SRM/UNIWARD 方向；`0xF8` 改称项目自研不变式；JPEG u=3 改动率 0.24~0.25；“卡方失效”→“前提失配”；“结构 0 风险”→“低风险待验证”；“通道 1/3”→逐通道 1/3、联合检测器不变；RgbSpread 收益待实验；定量结论加 E 级标注并链接复现）。另补：

- memo §3.2 / 评审丙原话“三进制结构性免疫经典检测器”均须加限定：**对 chi2/RS/SPA 前提失配 ≠ 统计免疫**；类残差直方图是新的可估计嵌入率攻击面（P0-B）。
- plan-v1 全文作废项：§3.1 domain 模板化、§3.2 `capacity_divisor=0.5`/“致盲”/直接拒绝、§3.3 RgbSpread 为 P 类、§3.4 保留 `stc_h`/`algorithm`、§4 兼容矩阵首行、§5 Phase 顺序（domain→API→channel 改为 评测/header → domain/容量/KDF → API → channel）、§6 “scan 0 CLEAN”作为唯一验收。

---

## 7. 已知残余暴露（诚实清单，不靠调参掩盖）

1. **正文槽位成本序可无密钥复算**（header 288 槽密钥化、正文按公开 HILL 代价序取最便宜 N）：方案感知攻击者可预测改动位置集合。显式取舍（保最小失真，4.3 倍代价差实测）。P2-C 研究。
2. **文件增长 ≈ +1.0%/45KiB** 与重编码器指纹（FLEVEL/分块）：P1-E 待实验。
3. **domain 是低熵口令**：对持有二进制的攻击者可字典枚举；对仅有图片者无统计差异。
4. **`scan` 自检**降级为自家工具自检，不再作为任何验收标准；其 RS/SPA 对干净相机原图本就假阳性（评分 50）。
5. v1 KDF 100k 轮与 v1 布局的既有弱点：v1 读取路径永久保留，风险随文件自然老化，v2 新文件已缓解。

---

## 8. 附录：代码位置索引（本方案全部论断的可核对锚点）

| 事实 | 位置 |
|---|---|
| 绿色单通道写死（embed/extract/probe 三处） | `stego/spatial/engine.rs:499-500, 687, 845` |
| `[8,247]` 资格 + 30% 排除 + header 置换 + 正文成本序 | `engine.rs:502-562`；提取侧同构 `engine.rs:687-737` |
| 类底/类顶单向门（`PlusOnly`/`MinusOnly`） | `stego/coding.rs:343-375`（`spatial_move`） |
| HILL 亮度权重与 `& 0xF8` 掩码 | `stego/spatial/cost/hill.rs:44-58, 194` |
| header 位布局（26+2+4=32，h 合法 4..10） | `stego/header.rs:15-45`；`stego/coding/stc.rs:64-75` |
| 32 字节头 / 256 槽 / feature word 拟占 [256..288] | `engine.rs:586-600` |
| 推荐容量 r=4.5 公式与 codec 阈值 | `stego/coding.rs:85-124` |
| 五个 HKDF 标签 / PBKDF2 100k | `stego/envelope.rs:69, 75-111` |
| `StegoProfile` / `is_official` / `Profile::domain()` 命名冲突 | `params.rs:228-257, 345-357` |
| `StegoOptions` 公开字段 | `stego/params.rs:277-287` |
| scan 内容检测器（4MB 截断/单边 chi2/RS/SPA） | `analysis.rs:817-880, 964-1058` |
| JPEG 校准自检 | `analysis/calibration.rs` |
| CLI 数学旋钮与 `--capacity` 输出 | `cli.rs:335-470, 1333-1340, 1948-1960` |
| `encode_png` 固定 level 6 / filter 保持 | `engine.rs:304-332` |
| i18n `format_msg` key 解析 | `i18n/mod.rs:120-140` |
| probe 不依赖 Profile 的注释（Phase 5 将 revisit） | `stego/mod.rs:175-186` |
| 0.4.0 内容域不兼容记录 | `docs/CHANGES-20261020.md:12` |
| v0.4.0 tag 旧布局证据 | `git show v0.4.0:rust/src/stego/spatial/engine.rs`（`candidate_pixels[..256]`）+ `hill.rs`（`0xFE`） |
| 评测复现脚本与产物 | `temp/stego_probe/`（评审丁，未入版本控制） |

---

> **一句话结论**：先建证据（Phase 0），再用 v2 header 一次性解决类边界指纹与全部 F 类自描述（Phase 1），随后才是 domain、容量口径、KDF 与 API 收敛（Phase 2~4）；通道打散在对照实验证明收益前不实施（Phase 5）。
