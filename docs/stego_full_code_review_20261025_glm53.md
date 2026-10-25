# strhide 全面代码审查报告 —— 重点：stego 隐写子系统

| 项 | 内容 |
| :--- | :--- |
| 文档编号 | `STEGO-CODE-REVIEW-20261025-GLM53` |
| 审查时间 | 2026-10-25 |
| 审查引擎 | GLM-5.3（ZCode） |
| 范围 | `rust/src/` 全部，重点 `rust/src/stego/`（约 1.2 万行逐行精读），辅以顶层 engine/adapters、crypto、envelope |
| 方法 | 6 路并行子系统深审 + 主审独立复验关键发现（对照参考文献/本地参考实现/手工数学推导）；静态审查，未运行构建 |
| 参考文献 | Filler et al. TIFS 2011（STC）；Holub & Fridrich EURASIP JIS 2014（S-UNIWARD）；Li et al. ICIP 2014（HILL）；Guo et al. TIFS 2015（UERD）；本地参考 `temp/github/stegolab`（HILL/S-UNIWARD/J-UNIWARD）与 `hstego` |
| 结论强度 | 每条发现标注【确认/疑似】；标 ✅ 的条目经主审独立复验（非仅转述子审） |
| 修复状态 | P0/P1 已于审查当日全部修复并提交（8 个提交），逐项状态见 §0.5 与 §7；已修复条目在正文标 【已修复 ✅ 提交号】 并简化 |

---

## 0. 总体结论

1. **核心算法内核质量很高**：STC 的 Viterbi 前向/回溯反演、u=1 快速链、AVX2 内核经独立数学推导逐位对勘**未发现算法错误**；JPEG V3 几何（含 h−1 预热行）、HILL、J-UNIWARD、CABAC journal 重编码管线、嵌入/提取对称性、PRNG（ChaCha12 + 无偏 Fisher-Yates）、chunk 化 AEAD 封装与解压炸弹防护均验证正确。整体工程水准显著高于社区同类实现。
2. **发现 2 个严重级确认缺陷**：
   - **S-UNIWARD 的 suitability 卷积与 residual 卷积同向，差一个核镜像**——实现的不是论文的失真函数（不影响往返，只影响抗检测质量与算法保真度）；
   - **HEVC AnnexB 封面摘要窗口覆盖会被改写的 CABAC 数据**——短 slice header 的流嵌入后摘要漂移，正确口令也无法提取（功能性失败，且该路径零测试覆盖）。
3. **发现 1 个跨引擎的密码学隐患**：`Freshness::Seeded` 模式下 salt 与 nonce 都只由 seed 派生、与载体和载荷零绑定，同一口令+同一 seed 在两个载体上嵌入不同载荷即构成 **AES-GCM 二次本簿**（nonce 重用）。生产默认 `Random` 不受影响，风险集中在专家/回归模式。
4. **主要系统性短板不在算法而在契约承载方式**：关键契约靠错误消息**子串**跨模块耦合（且 `errors.rs` 文档宣称的结构化恰恰不存在）；测试 oracle 有被 `0x5A` 首位巧合掩盖的差一；多处文档/注释与代码事实相反（含直接诱使 S2 的 "never touched" 断言）；wire 格式自描述"做了一半"。
5. **HEVC 外围欠账集中**：2026-10-24 审计（`docs/HEVC-STC-AUDIT-20261024.md`）所列代码级发现在审查时点**全部未修复**，本次又新发现 5 项（含严重 1 项）。（审查当日已清偿其中 2.1/2.2/2.3/4.1–4.4/5.1/5.2/5.4，见 §0.5。）
6. **结构域（次重点）**：写入/提交路径健壮性好，但 `adapters/isobmff.rs` 的 iinf/iloc 解析对恶意文件有确认的 panic 路径；仓库存在三个互不复用的 ISOBMFF 解析器，健壮性纪律没有共享。
7. **内存工程双标**：JPEG 侧为省 16 B/系数精心设计了 bias 向量与闭包，PNG 侧却对每通道分配两张全平面 f64 方向图 + GB 级 SlotPlan 瞬时分配，50 MP 载体单次嵌入峰值 ~2 GB。

---

## 0.5 修复状态（2026-10-25 当日更新）

P0/P1 项已按批次修复并提交（每批均通过 cargo test / fmt / clippy / build --release）：

| 项 | 内容 | 提交 |
| :--- | :--- | :--- |
| S1 | S-UNIWARD 镜像失配（residual 改卷积索引 + 判别性测试，红绿验证） | `85d0bc8` |
| S2 | HEVC AnnexB 摘要窗口（只哈希不可变字节 + 短 header fixture 确定性回归） | `f64b53b` |
| M2 | STC oracle 差一（`row+1>=h` + 首位为 1 的消息，红绿验证） | `f4d352e` |
| M1 | Seeded salt/nonce 绑定封面与载荷（`seeded_binding`，三引擎调用点全迁移） | `9c30e53` |
| M12 部分 | 容量差一（`message_bits` 逆函数）、extract 24/16 常量与守卫、MP4 诚实报错 | `e76aa97` |
| M12 部分 | heif_boxes 4.1–4.4（construction_method / 零推进 DoS / as usize / ipma 选择） | `6d81ec7` |
| M9 + 5.1/5.2/5.4 | thumb_bridge infe v3 偏移、宿主 extent 单次修补、iloc v2 守卫、零推进守卫 | `4853a02` |
| M5 + §3.6 | JPEG delta 断言容忍合法收缩；isobmff iinf/iloc 全部越界读取加门 | `5c4fa2d` |

**仍未修**（P3 与 M12 剩余部分）：M4 UERD 公式对齐（变体已声明，见 §7）、旧审计 2.4（CABAC 双编码，M10 回退后热路径消失）、3.1/3.2（死代码）、§3 剩余轻微项（2026-10-25 晚已关闭一批低风险项，见 §0.6）、thumb_bridge 补丁重映射/子盒尺寸（见附录 A）、§3.5 KDF（用户决定待 argon2id）。**P2 已于 2026-10-25 下午处理完毕**（部分修复、部分按成本收益搁置），明细见 §7 与 [`docs/CHANGES-20261025.md`](CHANGES-20261025.md) 14:25 条目。注意：M11 改变 HEVC trellis seed、M8 升级 PNG FeatureWord v3，旧 HEVC/PNG 产物不再可读（未发布策略允许）；S1/S2/M1 同理影响旧 suniward、AnnexB 与 Seeded 产物。


### 0.6 P3 / M7 修复状态（2026-10-25 晚，7 个提交）

按"改动小、收益大、风险低"分两批实施，明细见 [`docs/CHANGES-20261025.md`](CHANGES-20261025.md) 17:58–18:18 五条记录。

| 提交 | 内容 |
| :--- | :--- |
| `8561404` | HILL 长度守卫、`category` 封顶 15、Hamming `k` 钳位、`slot_positions` u64 乘法、`encode_substream` 上下文越界改 `Err` |
| `40b961a` | STC 位序文档（改按存储形式陈述）、PNG "six of eight" 纠正、`spatial_move_safe` 自封闭、删 `stc_u <= stc_h` 死检查与 `zero_runs`、重复注释 |
| `d179e1f` | `write_bytes_atomic`（fsync + 目录同步），`commit_carrier_bytes` 与 `facade::extract_file` 统一 |
| `3dbdda2` | **M7** PNG 保留 IEND 之后尾部字节（`RawImage::tail`） |
| `e538e68` | `is_hevc_annexb` 补齐定义域 NAL 类型、`thumb_bridge` 支持 64 位 `meta` 盒 |
| `3628bc7` | `layout_for_payload` 改按真实信封口径（收 payload 字节）、`sb_bytes` 真校验 |
| `38a0f91` | HEIF 嵌入/提取方案顺序不对称的原因与已知风险（仅注释 + 记录）；**后续 `0d5cbed` 已按用户决定把写入/读取/容量统一为 Scheme C 优先、桥接兜底，该风险随之关闭** |

已关闭：M7、§3.1#1/#5/#6/#11、§3.2#1/#2/#3、§3.3#1/#4/#8、§3.4#1/#3/#4/#5、§3.5#1/#2、§3.6#3/#4/#5。
仍未做（需评估或含行为变化）：§3.1#2/#3/#4/#7/#8/#9/#10、§3.2#4/#5/#7/#8、§3.3#2/#3/#5/#6、§3.4#6（含 `engine.rs:215` 的 0.25 硬编码）/#7、§3.5#4/#5/#7、M4、M10、KDF/argon2id、thumb_bridge 补丁重映射。

---

## 1. 严重问题

### S1.【已修复 ✅ `85d0bc8`】S-UNIWARD suitability 卷积与 residual 卷积方向镜像失配

**位置**：`rust/src/stego/png/cost/suniward.rs`（residual_pass / suitability_pass）。两个 pass 同朝向采样（相关），而 suitability 权重是 residual 算子的伴随——差一个核镜像，HPDF 前载大抽头（~0.31/0.68/0.59 @ 索引 1..3）配到每条边缘的错误一侧，实现的不是论文的失真函数。不影响往返与类不变性（现有测试因此全部漏过），只影响抗检测质量与算法保真度。

**修复**：`residual_pass` 改为卷积索引（与 stegolab/hstego 参考同构），`suitability_pass` 不动即成精确伴随对；新增判别性测试（红绿验证：镜像取向 near/far≈1.31 → 修复后≈0.73）。**注意：代价图已变，旧 suniward 载体不可读，需重嵌。**

### S2.【已修复 ✅ `f64b53b`】HEVC AnnexB 封面摘要窗口覆盖会被改写的 CABAC 数据

**位置**：`rust/src/stego/hevc/bitstream.rs:192-199`。VCL 分支哈希 NAL 头后 18 字节，断言"前 16 字节是 slice header 永不被改"——短 slice header（单 slice I 帧典型 3-8 字节）时大半是首 CTU 的 CABAC 载荷；翻转落进窗口即摘要漂移，`extract_hevc` 对**隐写后**载体重算摘要 → trellis seed 与 AES key 漂移 → 正确口令也报 `Invalid HEVC stego signature`。该生产路径零测试（matrix bench 只喂 HEIF 载体；且失败是概率事件——12 个 seed 中 2 个，这也是从未暴露的原因）。

**修复**：VCL NAL 只哈希构造上不可变的字节（2 字节 NAL 头 + NAL 长度，Δ=0 保证），与 HEIF 分支（仅参数集）同哲学；新增确定性回归（henc-133 短 header fixture + 固定 seed，修复前稳定失败）、HEIC 重建 AnnexB 端到端往返、摘要绑定/稳定性单元测试。gradient-512 不触发（header 21 字节 > 16）属正常，回归由 henc-133（5 字节）锁定。

---

## 2. 中等问题

> 已修复的条目只保留摘要与修复去向，完整论证见对应提交信息（§0.5 列出提交号）。未修复条目保留全文。

### M1.【已修复 ✅ `9c30e53`】`Freshness::Seeded` 下 salt/nonce 与载体、载荷零绑定 → AES-GCM 二次本簿（跨引擎）

**位置**：`rust/src/stego/envelope.rs`（Freshness::salt / nonce）+ 三引擎 key 派生。Seeded 模式下 salt/nonce 只依赖 (seed, attempt)，而 payload key = f(password, salt)、PNG 更是直接以 salt 作 KDF 盐——同口令+同 seed 在两个不同输入上即重用整个 (key, nonce) 对，不同明文下的 GCM 二次本簿（密文异或泄漏明文异或、GHASH 可构造伪造）。生产默认 `Random` 不受影响，风险集中在专家/回归/批测模式。**修复**：新增 `Freshness::seeded_binding(cover, payload)`（SHA256‖SHA256）并强制全部调用点传入；提取端从载体回读无需重推，可复现性保持；域分隔符升 v2。**注意：旧 Seeded 产物不可复现出新版输出。**

### M2.【已修复 ✅ `f4d352e`】STC 穷举 oracle 的暖行判定差一，被测试消息首位=0 的巧合掩盖

**位置**：`rust/src/stego/coding/stc.rs`（Oracle::matches）。内核约定行 `h-1` 携带消息位 0（extract：消息位 b ↔ 行 b+h−1），oracle 的 `row+1 > h` 却把行 `0..=h-1` 全约束为 0——多锁一行、少验消息位 0，恰被 `0x5A` 首位为 0 掩蔽，最优性验证只覆盖了半个消息空间。**修复**：`row+1 >= h`，测试消息生成改 `0xA5`（首位 1，红：6.25 vs 错误系统的 8）。

### M3.【已修复 ✅ 2026-10-25 P2】跨模块契约靠错误消息子串耦合

**位置**：`rust/src/stego/jpeg/engine.rs:860` ↔ `rust/src/stego/coding/stc.rs:575-577`（u=1 分支）与 `stc.rs:726-728`（u>1 分支）

```rust
// engine.rs:860
if ctx.table.is_some() && e.to_string().contains("no legal element") { … }
```

u>1 分支的消息（"a group has **no legal element** …"）恰好也含该子串——当前两路都能命中，但这是运气不是设计：任何一方改写措辞（如 i18n 本地化——`errors.rs` 已有 i18n 映射）都会静默把"过优化 Huffman 表"的用户诊断降级为裸 `TrellisInfeasible`，且 `retryable` 语义丢失。stc.rs 侧仅靠注释"keep it"防守。**更具讽刺性的是**：`errors.rs:54-57` 对 `TrellisInfeasible` 的文档声称 "Structured so the JPEG engine can recognise … without matching on message text"——该变体只携带 `String`，JPEG 引擎恰恰在匹配消息文本，文档与事实完全相反（同 §5 第 2 类"文档承诺与代码行为"问题的又一例）。

**修复**：给 `TrellisInfeasible` 增加结构化原因（如 `enum TrellisCause { DeadElement, DeadGroup }`），engine 按变体匹配。

### M4.【文档已处理 ✅，公式对齐搁置】UERD 代价公式与论文/官方实现三处保真度偏差

**位置**：`rust/src/stego/jpeg/cost/uerd.rs:145-168`（分子）、`:107-143`（分母平滑）。主审已抽查确认 `cost = q[k] / block_rho`（uerd.rs:163）用 Q 的一次幂。

对照 Guo et al. TIFS 2015 的 `rho = (D·Q_k²)/tempJ`（D=1.5 于块首行/首列模式，否则 1；tempJ = J + 0.25·四邻块能量之和）：

1. 分子是 Q¹ 而非 Q²，且 D_inter/1.5 因子完全缺失——高频模式 Q 可达低频 10 倍以上，Q¹ vs Q² 显著改变模式间代价排序（相对权重差最多一个量级）；
2. 分母是 `J + 0.25·avg(8邻域含对角)` 而非 `J + 0.25·(四邻之和)`——邻域项弱 4 倍且混入对角块；
3. 边界块按实际存在的邻居数取平均，论文按移位求和（边缘补零）。

**影响**：嵌入端专用（V3 槽位是几何的，提取端不算代价），不破坏往返；但隐蔽性层面这不是论文意义上的 UERD 排序，而模块文档声称"Based on … IEEE TIFS 2015"。**修复**：对齐公式，或在 `description()`/模块文档中显式声明这是"UERD-inspired 变体"并给出差异清单。另注：uerd.rs:85-90/150 注释声称 `|c| & !1` 掩码"对 ±1 不变"不成立（|c|=3→4 时 2→4），它只是把奇数幅度贡献减一个台阶——行为无害，注释失实。

### M5.【已修复 ✅ `5c4fa2d`】`apply_deltas` 的 debug_assert 对合法收缩误报（debug 构建可 panic）

**位置**：`rust/src/stego/jpeg/engine.rs`（apply_deltas）。断言 `updated.abs() <= 1023` 拦截一切超界值，但封面经自定义 Huffman 表可合法携带 cat 11–15（|c| 最大 32767），其 MinusOnly 收缩到 1999 之类的值是合法操作，debug 构建却 panic。**修复**：断言只拦"增长穿越 ±1023"（`updated.abs() <= 1023 || updated.abs() < before.abs()`）。

### M6.【已修复 ✅ 2026-10-25 P2】PNG 引擎 `direction_costs` 全平面分配：大图内存峰值失控，且与 JPEG 侧设计自相矛盾

**位置**：`rust/src/stego/traits.rs:47-57`（默认实现 `base.to_vec()`×2）、`rust/src/stego/png/cost/hill.rs:169-185`（HILL 覆写同样两张 w×h f64）、消费端 `png/engine.rs:1266-1291`。

50 MP 载体：基础 cost 图 400 MB + 每通道 800 MB 方向图 + SlotPlan 的 `ranked`(~700 MB) 与 `permuted`(~400 MB) → 单次嵌入峰值 ~2 GB；100 MP 约 4 GB。而 JPEG 侧在 `traits.rs:100-108` 明确以"16 B/系数太贵"为由拒绝了全图方向代价、改用 i8 bias 向量。引擎最终只使用 `needed_body_slots + 512` 个槽的方向代价，HILL 的邻域均值 O(1)/像素可按需计算，S-UNIWARD 对称模型根本不必拷贝。**修复**：trait 改为按槽取值或接受槽切片；对称模型直接复用 base。

### M7.【已修复 ✅ `3dbdda2`】`encode_png` 丢弃 IEND 之后的全部尾部数据

**位置**：`rust/src/stego/png/engine.rs:193-199`（decode 在第一个 IEND 处 break）、`:577-603`（encode 只回放捕获的 chunk）。主审已确认 break 语句。adapters 层（`adapters/png.rs:20-30`）明确支持"PNG 后跟任意字节"并实现了 64 KiB 回扫，而像素域路径静默截掉这些字节——与项目"格式保持、无损"定位冲突。**修复**：decode 记录 IEND 结束偏移，encode 原样追加尾部。

### M8.【已修复 ✅ 2026-10-25 P2，FeatureWord 升 v3】PNG FeatureWord 自描述不完整且含死字段

**位置**：`rust/src/stego/png/engine.rs:1455-1457`（feature word 只覆盖 `exclusion_percentile`）、`rust/src/stego/header.rs:231-242`（`eligible_min/eligible_max/kdf_id` 解码+校验但从未使用）、`engine.rs:1019-1024`（提取端用硬编码 `SPATIAL_ELIGIBLE_MIN/MAX`）。

HILL 的 `p1_window/p2_window/epsilon` 与 S-UNIWARD 的 `sigma` 不随载体走——提取端必须逐字重复嵌入端超参，否则静默 `NoHiddenData`；`eligible_min/max`、`kdf_id` 是解码即弃的死字段，若未来写入非默认值，旧读取器恰好会拿硬编码常量误读。feature word 尚有 bits 51..64 与 bytes 9..32 保留空间。**修复**：把窗口/epsilon/sigma 编入保留区（版本升 v3），或删掉死字段并文档声明。

### M9.【已修复 ✅ `4853a02`】HEIF 桥 `ContainerJpegFallback` 的宿主 item 永不被识别 → iloc extent 长度永不更新

**位置**：`rust/src/stego/heif/thumb_bridge.rs`（reconstruct_heif）。`ContainerJpegFallback => false` 恒假——fallback 找到的 JPEG 必然位于某个 item 的 extent 内（典型是 Exif 缩略图），宿主 item 长度声明不变而内容已变 → 容器静默损坏；与旧审计 5.1（infe v3 偏移，同提交已修）组合触发。**修复**：宿主 = 物理覆盖目标区域的文件偏移 extent 所在 item；iloc 长度 delta 只加在该 extent 一次（顺带修复旧审计 5.2 的"每 extent 各加一次"）；宿主 item 自身后置 extent 一并平移；跨 extent 目标拒绝而非错补。

### M10.【尝试修复后回退 ⏸ 2026-10-25 P2，综述见 `docs/HEVC-WPP-COST-ISSUE-20261025.md`】HEVC WPP 中段子流永远无法 replay（静默容量损失）

**位置**：`rust/src/stego/hevc/engine.rs:609-611`

`encode_substream` 对不以 `Terminate{bit:1}` 结尾的子流无条件补写 terminate(1)+flush。但 WPP 行边界子流的 journal 记录为 `Terminate{bit:0}`（行尾 `more_data=false` 的正确语义），强补后与封面"terminate(0)+00 填充"必然不同 → `replay_matches_cover` 失败 → 全部中段子流每轮白做两次编码后被整体排除。若编码器行尾写 terminate(1)（HM 风格），rust_h265 又会把该行当整个 NAL 结束——两种风格下 WPP 多子流容量都大幅受损。安全网保证"不损坏、只降容量"，iPhone HEIC 网格每 tile 单子流不受影响，故无人察觉。**修复**：按是否为该 slice 的最后子流决定终止写法，中段子流照 journal 原样收尾。

### M11.【已修复 ✅ 2026-10-25 P2】HEVC 的 STC trellis seed 完全公开，与 PNG/JPEG 安全模型不一致

**位置**：`rust/src/stego/hevc/engine.rs:275-276`（seed 仅由公开参数集摘要 + 公开常量派生，主审已复核）对照 `png/engine.rs:1103-1104,1253`（stc_seed 派生自密码派生的 perm_seed）。

任何持有二进制的分析者都能复现槽位 Weyl 置换与 STC 码结构，对翻转位置分布做结构化统计检测；PNG/JPEG 的同类映射是密钥化的。载荷机密性不受影响（GCM），但隐写安全性弱于同仓其他引擎。

**连锁后果（主审补充）**：消息头含**明文 CRC32**（`engine.rs:264-266`，位于 GCM 密文之外）。由于 trellis/槽序公开，无口令者对任意 HEIF/HEVC 载体执行 scan→extract 即可得到候选 40 字节头——对真载体直接读出 `len/crc/nonce/ciphertext`，随后**离线**枚举低熵明文（短文本、已知结构文档）用 CRC32 验证猜测，完全绕开口令与 GCM。高熵载荷不受实际影响。修复 M11（seed 混入 secret）同时关闭此 oracle；或去掉明文 CRC（GCM tag 已提供完整性，CRC 本属冗余）。

**修复**：把 secret（或其派生）混入 trellis seed 派生，提取端对称重推。

### M12.【部分已修复 ✅ `e76aa97` + `6d81ec7`】HEVC 旧审计（2026-10-24）清偿

已修复（见附录 A）：2.1 容量虚报（`message_bits` 逆函数 + 容量可达性回归）；2.2 extract 硬编码 24/16 与 `header_bytes<24` panic（命名常量 + 入口守卫 + 文档更正）；2.3 MP4 嗅探不实现（五入口显式报错）；4.1–4.4 heif_boxes 四项（construction_method / 零推进 DoS / `as usize` / ipma 关联选 hvcC）。**仍未修**：2.4/2.5（子流双重重编码、容器双重解析——性能项，P2）、3.1/3.2（死函数、剩余未用错误变体；`Unsupported`/`TooLarge` 已在本轮投入使用）、5.3/5.5 其余项。

### M13.【已修复 ✅ 2026-10-25 P2 轻量版】PNG/JPEG 提取接口对 cost model 参数的语义不一致

PNG `extract_png` 的 `cost_model` 参数实为 hint（载体自带 algorithm_id 优先），但拼写错误会在读载体前就报错（`stego/mod.rs:210-217`）；JPEG 提取端则明确不取模型。同一 `stego/mod.rs` 内两套哲学并存，且"传错模型也能解出来"增加认知负担。**修复**：PNG 对齐 JPEG（参数改 `Option` 或删除）。

---

## 3. 轻微问题与改进建议（分系统）

### 3.1 STC / coding

| # | 位置 | 问题 | 级别 |
| :--- | :--- | :--- | :--- |
| 1 | `stc.rs:29-34, 59-67, 338-340` | 模块文档三处把"驱动本组行可达性的位"写反：实际是**最低位**（bit 0）保证本组行双向可达、最高位喂 extra 状态位；两端都被强制置 1 所以行为无恙，但误导维护（若有人按文档"修正"成只留 top bit，行 g 可达性静默丢失） | 轻微·文档 |
| 2 | `stc.rs:287-314, 678-691` | `transfer_column` 的 u=1 非 TWO_WAY 分支与 `<true,false>` 调用点是**不可达死代码**（`embed_with_cost_fn` 对 u==1 提前 return）；数学上验证过是正确的，但与长文档一起造成"两条等效路径"的错觉。另 `stc.rs:710-712` 注释已过时（n%u==0 在 :537 强制，无尾部残组） | 轻微·死代码 |
| 3 | `stc.rs:238,264` | NaN 代价被 `is_finite()` 静默当作湿点处理；NaN 应视为上游 bug，建议入口断言或报错 | 轻微·健壮性 |
| 4 | `stc.rs:399-402` | 公开 API `extract` 对 `bits_out > 容量` 静默钳位，返回短于请求的缓冲且无信号 | 建议 |
| 5 | `coding.rs:63,74,120` | 公开 Hamming 容量函数缺 k 校验：`required_slots(bits, 64)` debug 下 `1<<64` 直接 panic、release 下移位回绕静默错；`hamming_embed/extract_block` 对 `block.len() >= n` 仅 debug_assert | 建议 |
| 6 | `coding.rs:341-347` | `spatial_move_safe` 对 r∈{0,7} 返回 `Move::Both` 与自身文档矛盾，靠 PNG 引擎 `engine.rs:1022` 预过滤兜底；建议改 `Option<Move>` 把契约写进类型 | 建议 |
| 7 | `coding.rs:86-110` | `auto_select_codec` 的 2.5/4.5 阈值是饱和裕度政策（有意为之），但常量无注释说明为什么不是 2.0，易被后人"优化"坏 | 建议·文档 |
| 8 | `stc.rs:618` | 回溯位图 h=10 + 大预算可达 256 MB，建议在 `layout_for_payload` 加内存护栏 | 建议 |
| 9 | `stc.rs:444-451` | `embed` 的 `rho_plus`/`rho_minus` 相邻同型切片参数，调用点写反不被发现 | 建议·接口 |
| 10 | `examples/stc_capacity_eval.rs:183-192` | flips/distortion 统计只遍历 G 通道，多通道嵌入的 CSV 行被系统性低估 | 建议·工具 |
| 11 | `stego/params.rs:308-313` | spatial 侧强制 `stc_u <= stc_h` 与内核文档（支持且测试 u>h）矛盾 | 轻微·文档 |

### 3.2 JPEG

| # | 位置 | 问题 | 级别 |
| :--- | :--- | :--- | :--- |
| 1 | `jpeg/dht.rs:189-204` | `zero_runs` 是全仓无引用的死代码，上方还有重复 doc 注释行 | 轻微·死代码 |
| 2 | `jpeg/dht.rs:181-187, 372-377` | `category(i16::MIN)`=16 会使符号字节位溢出污染 run 半字节；当前生产不可达（dct-io 最小 −32767），但函数是 pub，加 category 上界守卫更稳 | 轻微·防御 |
| 3 | `jpeg/engine.rs:1337` | `layout_for_payload` 硬编码 `payload_len + 5 + 16` 且按未压缩框架估算，压缩生效时报告的布局/`u` 与实际嵌入不一致；`+16` 假设 tag 恒为 16B。文档却声称"report the layout the embed will actually use" | 轻微·诊断 |
| 4 | `jpeg/dht.rs:137-146` | 取第一个扫描分量的 AC 表当 Y 表、`jpeg/dqt.rs:105-112` 取文件序第一个 Tq=0 表并假设 Y 用 Tq=0——两个"near-universal convention"，异常文件下用错表（仅影响嵌入端排序/慢路径预判） | 轻微·假设 |
| 5 | `juniward.rs:129-131` vs `uerd.rs:67-73` | 几何不匹配时 juniward 返回全 wet（静默降级、负载藏进最差槽位），uerd 返回空 vec（引擎报错）。建议统一为显式失败 | 建议 |
| 6 | `juniward.rs:449-466` | 边界 clamp（复制填充）vs 参考实现 symmetric 镜像；模块文档已声明有意偏离，仅影响最外圈一个块环的权值 | 轻微·已知偏离 |
| 7 | `engine.rs:95, 1035-1036` | 内存估算少算极化 bias 向量（+6%）与提取端双网格缓冲（最坏 2×1.5 GB）+ 逐 suite 全量 memcpy；仍在 8 GiB 预算松量内，但注释声称的边界不精确 | 轻微 |
| 8 | `engine.rs:1261-1280` | probe 的 grouped 上界未叠加 `check_pipeline_budget` 的 `base_bytes`，极端配置下 probe 广告的容量 embed 会拒绝（方向都是"报告略乐观"） | 轻微 |

### 3.3 PNG

| # | 位置 | 问题 | 级别 |
| :--- | :--- | :--- | :--- |
| 1 | `png/cost/hill.rs:38-41` vs `suniward.rs:79-85` | HILL 缺少 S-UNIWARD 那样的 `pixels.len() < w*h*channels` 长度防护，短输入直接下标 panic；同一 trait 两个实现契约行为不一致 | 轻微·健壮性 |
| 2 | `png/cost/suniward.rs:157,170,200,213` | 边界 clamp vs 参考 symmetric 镜像（HILL 侧倒是正确实现了 symm）；两侧不一致说明非有意统一 | 轻微 |
| 3 | `png/engine.rs:553-573` | 重压缩流比分块边界总长还短时 IDAT 分块数下降（保序尽力而为）；测试靠"重压缩尺寸接近原始"掩盖边界 | 轻微·保真 |
| 4 | `png/engine.rs:21-27` | 模块文档"six of every eight values can move either way"与 class_rule=1 实际行为（仅 r∈[2,5] 双向、r=0/7 整体排除）不符，陈旧描述 | 轻微·文档 |
| 5 | `png/engine.rs:926-959` | `SlotPlan::build` 的 `ranked`+`permuted` 50 MP 上 ~1.1 GB 瞬时；`permuted` 可用 u32 减半、`ranked` 可打包 | 建议·内存 |
| 6 | `png/engine.rs:1155` | 判定走 RGB 模式后 `u` 仍按 green 池比例选 1，牺牲本可负担的 u=2/3 降噪；可在切 RGB 后重选 | 建议 |
| 7 | `stego/header.rs:233` | `kdf_id` 解码后任意 0..3 放行不校验，未来引入新 KDF 时旧读取器拿 PBKDF2-100k 误读 | 建议 |
| 8 | `analysis/calibration.rs:155-168` | "Applicability gate" 注释段落整段重复两次（该文件仅服务 JPEG 检测路径，与 PNG 无关，顺带发现） | 轻微·卫生 |

### 3.4 HEVC / HEIF

| # | 位置 | 问题 | 级别 |
| :--- | :--- | :--- | :--- |
| 1 | `hevc/engine.rs:649-660` | `slot_positions` 的 `i*stride` 无 checked 乘法，32 位平台大 slot 数下 release 回绕（两端一致、提取自洽，但建议 u64 中间量） | 轻微 |
| 2 | `hevc/engine.rs:817` | `record_carrier_state` 无条件整份克隆载体，extract/probe 路径的这份克隆直接被丢弃——每次提取多一次全文件 memcpy（叠加旧审计的重复解析） | 轻微·性能 |
| 3 | `hevc/sniff.rs:92-105` | `is_hevc_annexb` 类型集合过窄（缺 TSA/STSA/RADL/RASL 2..9、BLA 16..18），合法 HEVC 视频流被误报"不支持" | 轻微 |
| 4 | `heif/thumb_bridge.rs:667-668` | `parse_isobmff` 假定 meta 是 8 字节头（`meta_body_start = meta_off + 12`），large-size meta 的子盒遍历错位（罕见但合法） | 轻微 |
| 5 | `hevc/engine.rs:588-591` | `encode_substream` 对 `ctx_idx >= HEVC_CONTEXTS` 的 Decision 静默丢 bin，replay 必失败但无任何痕迹；建议记 warning 或直接 Err | 建议 |
| 6 | `hevc/slot.rs:139-192` | 失真代价仅用 `x_c+y_c` 与 `c_idx`，忽略 qp/trafo_size/transform-skip/lossless——TS 块系数是空域样本，"高频低代价"假设不成立；Phase 2"结合 Q_step"的计划与实现脱节。另 `engine.rs:215` 的 `estimated_change_rate: 0.25` 是硬编码 | 建议·模型 |
| 7 | `heif/thumb_bridge.rs:167-183` | `extract_heif_bridge` 空间路径依赖 `options.algorithm` 取模型而 JPEG 分支不需要——同一函数内不对称 | 建议·接口 |

### 3.5 框架层（主审自审）

| # | 位置 | 问题 | 级别 |
| :--- | :--- | :--- | :--- |
| 1 | `stego/format.rs:318-323` | superblock 自洽性校验恒为真：左式 `sb_u*(sb_h-1)` 恒 ≤ `superblock_slots() = sb_u*(8*sb_bytes+sb_h-1)`（因 `8*sb_bytes ≥ 8`），条件永假；注释描述的"组宽超过 trellis 窗口"检查并未实现，自定义 profile 的配置错误不会被它拦截 | 轻微 |
| 2 | `stego/params.rs:208` vs `:245-247` | `stc_u` 字段文档写 "(default 1)"，实际 `default_stc_u()` 返回 0（= auto）；serde 反序列化缺省同样得 0 | 轻微·文档 |
| 3 | `crypto.rs:92` vs `stego/format.rs:113-130` | 结构域信封 PBKDF2 100k、stego 域默认 200k / 可选 600k——两个域的口令猜测成本不一致，且 100k 低于 OWASP 2023 对 PBKDF2-HMAC-SHA256 的 600k 建议。二者都是 wire 常量，发布前是调齐的最后窗口 | 轻微·密码学 |
| 4 | `crypto.rs:128-136` | `PasswordSecrets` 派生 `Copy` 且无 zeroize：payload/meta key 与 header mask 在内存中长期驻留，进程转储/核心文件可提取。对本地文件隐藏工具威胁模型影响有限，但与"口令派生材料"的敏感级别不匹配 | 建议 |
| 5 | `crypto.rs:97` | `BUILTIN_DEFAULT_KEY` 是源码公开常量：无口令模式只提供混淆、不提供保密（文档已声明"eliminates plaintext leakage"，但值得在用户文档中更直白：任何持源码者可解）。stego 域同理由的 `OFFICIAL_PNG_FORMAT.fallback_secret`（format.rs:434）同理 | 建议·文档 |
| 6 | `envelope.rs:104-114`（顶层） | 加密模式下 `meta_len`/`hint_len`/`inject_offset` 等尾部字段不在 80 字节 AAD 内：篡改会被下游 AEAD 失败间接捕获（metadata chunk 解密必失败），不构成完整性漏洞，但属于"靠下游失败兜底"而非直接认证 | 信息 |
| 7 | `stego/params.rs:443-478` | 自动预算的 4 GiB 回溯位图上限（`MAX_AUTO_BACKTRACK_BYTES`）相当激进：50 MP+ 载体在默认路径即可触发 GB 级分配（与 §3.2#7 的内存估算问题同族）；文档示例还引用了"256 MiB 允许 8.4M 槽"的旧量级，与常量现值 4 GiB 脱节 | 轻微 |

框架层确认正确（主审自查）：chunk nonce 的 XOR 派生方案（`make_chunk_nonce`/`make_meta_nonce`，chunk 间互异、meta 与 chunk 0 以 0xFFFFFFFF 分离，碰撞需 4G chunk——不可达）；`encrypt_stream_to_chunks` 的双缓冲 is_last 判定与读端 `bytes_consumed >= total`（total 经认证）语义一致；`framed_len` 与实际分帧字节一致（有测试锁定）；解压炸弹双层防护（AEAD 保护的 raw_size 硬上限 + verify 的 1 GiB 上限 + `VerifySha256Writer` 流式限长）；顶层 envelope 的 80 字节 AAD、`validate_against` 敌意长度校验、三层 header 识别（stealth 魔数→默认掩码→裸头）与 `UnpackSecrets` 的 PBKDF2 复用；registry 无全局可变状态、wire id 双射有测试；`is_heif_bytes` 跳过 minor_version 字段（i==1）的解析正确符合 ISO-BMFF 规范；`errors.rs` 的变体层次设计合理（`PasswordWithHint` 把 hint 作为字段而非可解析文本、`NoHiddenData`/`Password`/`CorruptedData` 的 oracle 语义区分明确——唯一污点是 M3 所述 `TrellisInfeasible` 的文档宣称）。

### 3.6 顶层引擎与 adapters（结构域，主审自审）

| # | 位置 | 问题 | 级别 |
| :--- | :--- | :--- | :--- |
| 1 | `adapters/isobmff.rs` | 【已修复 ✅ `5c4fa2d`】iinf max-item-id 循环：边界门 `ipos+8 > len` 差一且不覆盖 `[ipos+12..+14/+16]` 读取，截断/恶意 iinf 恒 panic；现按版本计算前置门 | ~~中等~~ 已修 |
| 2 | `adapters/isobmff.rs` | 【已修复 ✅ `5c4fa2d`】iloc 计数读取发生在长度门之前（strip 三处）与 `check_iloc_has_target` 的 v2 门（`>=16` 读 `[14..18]`）；现全部前置门 + 逐长度回归测试 | ~~中等~~ 已修 |
| 3 | `commit.rs:143-145` | tmp 写入 + rename 无 fsync：电力故障/内核崩溃窗口内可能得到"rename 已持久而数据未持久"的截断载体。正常运行无影响，属持久性瑕疵 | 轻微 |
| 4 | `facade.rs:299-326` | `extract_file` 用非原子 `std::fs::write` 直写（其余写路径全走 `commit_carrier_bytes`），目录输出时硬编码 `extracted.bin` | 轻微·一致性 |
| 5 | `router.rs` / `stego/mod.rs` | `embed_carrier` 对 HEIF "先 bridge 后 HEVC" 与 `extract_carrier` "先 HEVC 后 bridge" 回退顺序相反（语义自洽、有注释），但无测试锁定该顺序——被"顺手统一"即静默破坏一侧 | 建议 |

确认正确（主审自查）：`commit.rs` 的原子提交设计（同目录 tmp + rename、备份先行于任何写、`TmpGuard` RAII 清理、Windows 大小写不敏感的 `same_file`）；`pe_codebits.rs:326` 的 `dual.unwrap()` 由 :273-280 的 `None => continue` 局部不变量守护（安全，但 `if let` 更稳）；`engine.rs:887` 的 `stealth_magics.expect` 由 :783 的 password 匹配守护；pdf.rs / pe_codebits.rs / engine.rs 的其余 unwrap/expect 均在测试代码内。**结构域的 panic 面集中在一个文件**：isobmff.rs（39 处 unwrap 中绝大多数是固定长度切片的安全惯用法，真实风险即上述 2 条 iinf/iloc 路径）——与 HEVC 侧 thumb_bridge.rs 的 iloc 问题同根因：仓库里存在三个各自维护的 ISOBMFF 解析器（`adapters/isobmff.rs`、`stego/hevc/heif_boxes.rs`、`stego/heif/thumb_bridge.rs` 内嵌），健壮性互不共享。

---

## 4. 各子系统详评

### 4.1 STC 编码子系统（`stego/coding/stc.rs` 1319 行 + `stego/coding.rs` 682 行）

**结论：核心算法无缺陷；问题集中在契约承载与测试基准。**

独立数学推导逐位对勘确认正确的部分：Viterbi 状态语义（u>1 时 h 位状态 = 行 g..g+h−1 的累积校验子）、accumulate/decide 列转移、回溯反演是前向的精确逆、暖行约束 0 + 自由尾部的终态取 min（Filler et al. 2011 标准处理）、组内列向量去重循环的终止性；u=1 的 O(n) 快速链（`parity = want ^ (state&1)`、移位寄存器更新）恰是约束唯一解链；AVX2 内核与标量路径逐位一致（XOR 换道论证成立、`_CMP_LT_OQ` 同序同 tie-break、跨 CPU 特征确定）；Hamming 数学（Crandall 校验子、MSB-first 打包对称、改变率 7/8/3=0.2917 等）与容量不等式（含尾段 `min(remaining, k−1)`）经手算多组验证正确；边界（n=0、n%u≠0 拒绝、消息长度契约 m ≤ bits < m+8、湿点/饱和代价/平坦覆盖/u=64 敌意输入）全部有测试锁定。

本子系统发现：M2（oracle 差一）、M3（字符串耦合）、3.1 表全部条目。

### 4.2 JPEG 子系统（engine 1267 + juniward 722 + precover 366 + uerd 281 + dht 602 + geometry 192 + header_v3 448 + v3_layout 342）

**结论：未发现影响往返正确性的缺陷；主要欠账是 UERD 公式保真度与一批"注释承诺与代码行为"接缝上的毛刺。**

确认正确（择要）：J-UNIWARD 与 stegolab/hstego 参考逐项一致——KB 核、三频带语义、残差定心与 `scipy.correlate2d(...,'same')` 逐位等价、权重窗起点、`BASIS_SHIFT=15`、σ=2⁻⁶、|c|>1023 禁增、DC wet、去 +128 电平偏移论证；**PNG 侧的镜像失配在此侧不存在**（footprint 由同一残差公式解析推导并被 `footprint_matches_the_real_residual` 测试锁定，含非对称基向量对照）。HEVC 侧的 h−1 容量差一在此侧不存在（`superblock_slots`、`extension_slots`、`max_payload_bits = body−(h−1)`、probe 上界全部一致计入预热行）。V3 几何槽位契约（值不参与排序、DC 永不入格、排序排除建 body grid）使提取端完全免于代价模型复现；对过优化 Huffman 表的四层防御（方向封闭、交叉置零计价 wet×1000、事后全触块重放、换盐重试×6）有实测数据支撑；4:2:0/灰度/重启标记/逐行拒绝（SOF2/SOF3/SOF9 有明确文案）处理完备；DQT 零值三处消费点全部 `.max(1)`。

本子系统发现：M3、M4、M5、3.2 表全部条目。

### 4.3 PNG 子系统（engine 2582 + hill 325 + suniward 332 + wavelet 105）

**结论：对称性设计是全仓最扎实的部分之一，但存在唯一的"实现≠论文"确认缺陷（S1）与内存工程短板（M6）。**

确认正确（择要）：HILL 与 `temp/github/stegolab/HILL/HILL.py` 结构完全吻合（|KB⊛X|→3×3 均值→1/(x+eps)→15×15 均值；pad 推导对全部合法奇数窗口逐项验证无越界；KB 核中心对称故无镜像问题）；wavelet 滤波器组逐值等于参考（HPDF 16 taps、lpdf=(−1)^i·hpdf[15−i]、能带顺序、σ=1）；PNG 编解码全套符合 RFC 2083（含 Paeth/Average 的 floor((a+b)/2)）、inflate 炸弹防护（`take(expected+1)`）、chunk 保序回放、行滤波器保序、IDAT 边界重切、zlib 级别探测；**嵌入/提取对称性**（本子系统最核心的不变量）：八值类不变量 + `val & 0xF8` 代价掩码 + `(cost_bits, idx)` 全序排名，使 header 布局、候选排名、body 槽序列在 stego 上精确重建——header 用非安全 `spatial_move` 产生的 r=0/7 只发生在 body 迭代显式跳过的 512 个保留像素上；小图/退化输入（2×2、1×N）在 `header_fits()` 优雅报错；safety gating 的 embed/probe 公式逐字一致。

本子系统发现：S1、M6、M7、M8、M13、3.3 表全部条目。

### 4.4 HEVC / HEIF 子系统（hevc/* 2267 行 + heif/thumb_bridge 763 行）

**结论：核心 CABAC 隐写管线达到少见的工程质量，但外围欠账严重且与核心形成反差。**

确认正确（择要）：**CABAC journal 重编码管线**是本子系统最大亮点——解码端四条 bin 路径全入账，WPP 上下文继承/tiles 重初始化/dependent slice 状态继承精确捕获，编码端 first-bit 抑制/进位/flush 符合规范且有 roundtrip 测试；**Δ=0 有算法级保证**（翻转 bypass 符号位不改变 range；decision 未翻转则 range 演化相同；bypass 每 bin 恰 1 输出位；flush 位数固定 → 重编码位长严格不变）+ EPB 窗口集合不变 ⇒ NAL 长度不变 + `re_nal.len()==carrier_span.len()` 双保险；replay 安全网把一切建模缺口降级为容量排除而非载体损坏；失败回滚安全（全部 slice 通过才写回）；提取端敌意长度防护（全程 checked 算术）到位；无口令 oracle（空载体/错口令/未嵌错误不可区分）；`heif_boxes.rs` 边界纪律整体优秀（be_u16/u32/u64 + checked_add + usize::try_from 全覆盖）。

本子系统发现：S2、M9、M10、M11、M12、3.4 表全部条目。三类根因：封面摘要/密钥绑定未覆盖所有被改写字节；无测试路径（AnnexB、WPP、v3 容器）默认按最乐观假设工作（AnnexB 的往返与确定性回归已在 `f64b53b` 补齐）；两个 ISOBMFF 解析器各写各的互不复用（`heif_boxes.rs` 正确 vs `thumb_bridge.rs` 错误形成对照）。

### 4.5 框架层（envelope / crypto / format / header / params / registry / traits）——主审自审

**结论：加密与封装的工程质量高，无严重缺陷；欠账是两个域的 KDF 参数不一致与一处恒真校验。**

`crypto.rs` 的分层密钥设计（单次 PBKDF2 → HKDF-Expand 出 payload/meta/header-mask 三个子密钥，并有 `UnpackSecrets`/`derive_all` 消除重复 PBKDF2）、chunk 化 AEAD 流（每 chunk 独立 nonce + index/is_last 进 AAD）、解压炸弹防护（认证的 raw_size 硬上限、verify 1 GiB 上限、`MAX_CHUNK_SIZE` 读写双侧强制）实现正确且有测试锁定；NFC 归一化覆盖所有口令入口（跨平台一致性）。`stego/format.rs` 的 profile 即值的设计（私人构建无需 fork）、suite 表冻结语义、`MAX_PBKDF2_ITERATIONS` 解码侧 DoS 防护、成对标签唯一性校验都体现了对"发布后冻结"约束的认真对待。`header.rs` 的 word1 位域布局向后兼容论证成立；`registry.rs` 无全局可变状态、三张手工表有一致性测试守护。

本层发现：M1（Seeded nonce/salt，跨引擎）、M8（FeatureWord 死字段）、M13（提取接口不一致）、§3.5 表全部条目。

### 4.6 顶层引擎与 adapters（结构域隐藏）——主审自审（次重点）

**结论：写入/提交路径的健壮性设计好；解析敌意 ISOBMFF 的 panic 面集中在 `adapters/isobmff.rs` 的 iinf/iloc 路径。**

`commit.rs` 的原子提交流程（同目录 tmp、RAII 清理、备份先行、权限/时间戳保留、Windows 大小写感知的 `same_file`）是两个域共用的正确基础设施；`router.rs` 的策略注册表与 `MAX_STRATEGY_ID` 由编译期计算绑定（防漂移，有测试）；顶层 `envelope.rs` 的 80 字节 AAD 与三层 header 识别见 §3.5 确认项。pe_codebits 的指令双形式过滤器（F0–F5，含 iced 重编码逐字节比对）不变量成立。

本层发现：§3.6 表全部条目（isobmff 两条中等健壮性问题是本层最需要修的）。本次为次重点审查：engine.rs 的完整读写/还原流程与 pdf/pe/mkv 等 adapter 只做了目标性抽查（unwrap 热点 + 关键不变量），未逐行精读，见附录 B 的覆盖声明。

---

## 5. 跨子系统共性问题

1. **契约靠字符串/注释承载**：M3 的错误消息子串耦合是最典型样本；`spatial_move_safe` 的前置条件靠调用方记忆（3.1#6）；`stc.rs` 的"keep it"注释。类型系统能表达的东西（结构化错误、`Option<Move>`）没有用足。
2. **文档/注释与代码事实相反**：STC 可达性位写反（3.1#1）、UERD 掩码不变性（M4 注）、PNG "six of eight"（3.3#4）、`layout_for_payload` 的声称（3.2#3）、HEVC bitstream.rs 的 "never touched"（S2 的直接诱因）。**S2 本身就是"注释断言了未经验证的不变量"造成的。**
3. **自描述 wire 格式做一半**：PNG feature word 的死字段与缺失超参（M8）；HEVC header 的硬编码 24/16（M12）；两边都在"发布后不能再改"的约束下留了后悔药没吃。
4. **测试断言"性质"而非"数值对拍"**：S-UNIWARD 的镜像失配能通过全部现有测试（形状/正性/平坦>纹理在镜像后照样成立）；STC oracle 差一被消息首位的巧合掩盖（M2）；HEVC 摘要自测只改最后一个字节（S2）。三起事故同一根因：缺少与参考实现的逐值对拍或对抗性构造的用例。
5. **资源工程双标**：JPEG 侧精打细算（bias 向量、闭包、内存预算注释），PNG/HEVC 侧全平面分配、整份克隆、逐 suite memcpy（M6、3.4#2、3.2#7）。
6. **三个各自维护的 ISOBMFF 解析器**：`adapters/isobmff.rs`、`stego/hevc/heif_boxes.rs`（正确）、`stego/heif/thumb_bridge.rs` 内嵌解析器——同一格式三套边界纪律，本次在两套里各发现真问题（isobmff 的 iinf/iloc panic、thumb_bridge 的 infe v3 偏移与 iloc 修补缺口），而正确的那套（heif_boxes）的纪律没有被另外两套继承。
7. **重试/attempt 语义只在 JPEG 完整实现**（换盐重试×6 + retryable 标记）；PNG/HEVC 无重试路径，遇到同类"单次嵌入碰运气失败"时直接报错。

---

## 6. 已验证正确的核心机制（审查过、没问题的）

| 机制 | 验证方式 |
| :--- | :--- |
| STC Viterbi 前向 + 回溯反演（含 u>h、湿点、饱和、敌意输入） | 独立重推状态语义逐位对勘；穷举 oracle（修 M2 后） |
| STC u=1 O(n) 快速链 | 逐位验证为约束唯一解链 |
| AVX2 内核与标量路径等价 | XOR 换道/序保持论证 + 跨构建确定性设计 |
| Hamming 矩阵编码数学与容量不等式 | 手算多组 + 改变率公式核对 |
| PRNG（ChaCha12 + 无偏 Fisher-Yates + 前缀洗牌续流契约） | Strombergson KAT + 均匀性测试 + 续流等价测试 |
| HILL（含窗口 pad 推导、类掩码不变量） | 对照 HILL.py 结构 + 索引界逐项推导 |
| J-UNIWARD（含 JPEG 侧无镜像失配） | 对照 stegolab/hstego 逐项 + footprint 数值测试锁定 |
| JPEG V3 几何（含 h−1 预热行一致性） | format/v3_layout/engine/probe 四处交叉核对 |
| JPEG 过优化 Huffman 表四层防御 | 慢/快路径 4000 随机块对照测试 |
| PNG 嵌入/提取对称性（八值类 + 0xF8 掩码 + 全序排名） | 完整不变量链推演 |
| PNG 容器保真（chunk 回放/滤波器保序/IDAT 重切/zlib 级别） | RFC 2083 对照 + 专项测试 |
| CABAC journal 重编码管线与 Δ=0 位长不变性 | 规范对照 + 位级论证 + roundtrip 测试 |
| HEVC 提取端敌意长度防护 / 无口令 oracle | checked 算术链核对 |
| AEAD oracle 抗性（tag 失败一律 NoHiddenData） | envelope 源码核对 |
| chunk 化 AEAD 流 / 解压炸弹防护 / nonce 派生方案 | crypto.rs 通读 + 测试锁定项核对 |
| 顶层 envelope 80B AAD / 三层 header 识别 / 敌意长度校验 | 逐行核对 |
| commit.rs 原子提交（tmp+rename+RAII+备份先行） | 逐行核对 |
| pe_codebits 指令过滤器不变量（dual.unwrap 有守护） | 定义链核对 |
| registry wire-id 双射 / router MAX_STRATEGY_ID 绑定 | 测试核对 |
| facade 公共 API 设计 | 主审通读 |

---

## 7. 修复优先级路线图

**P0（发布前必须）——✅ 已全部修复（2026-10-25，提交号见 §0.5）**
1. ~~S1 S-UNIWARD 镜像失配~~（`85d0bc8`）
2. ~~S2 HEVC AnnexB 摘要窗口~~（`f64b53b`）
3. ~~M2 STC oracle 差一~~（`f4d352e`）

**P1（尽快）——✅ 已全部修复（2026-10-25）**
4. ~~M1 Seeded nonce/salt 绑定封面与载荷~~（`9c30e53`）
5. ~~M9 fallback iloc 修补 + 旧审计 5.1/5.2/5.4~~（`4853a02`）
6. ~~M12 清偿 2026-10-24 HEVC 审计（容量差一、extract 硬编码/panic、MP4 误认、heif_boxes 四项）~~（`e76aa97` + `6d81ec7`）
7. ~~M5 debug_assert 误报~~（`5c4fa2d`）
8. ~~§3.6 isobmff.rs iinf/iloc 边界检查~~（`5c4fa2d`）

**P2（排期，未修）——✅ 2026-10-25 下午处理完毕（明细见 `docs/CHANGES-20261025.md` 14:25 条目）**
9. ~~M3 TrellisInfeasible 结构化~~（`TrellisCause{DeadElement,DeadGroup,ExhaustedSlots}`，两处子串匹配消灭）；~~M4 UERD 对齐论文或声明变体~~（**选择声明变体**：模块文档列出三处偏差 + description() 同步 + 失实注释更正；公式对齐需检测评估支撑，搁置）
10. ~~M6/M13 PNG 内存与提取接口~~（`direction_costs` 改按槽取值，50MP 方向代价工作集 ~2 GB → 载荷量级；提取不再按 `--algorithm` 前置报错）；~~M8 feature word 收口~~（**升 v3**：超参 epsilon/sigma/窗口自描述入 wire + `wire_quantized()` 两端一致，死字段 `kdf_id`/`eligible_min/max` 删除，连带关闭 §3.3#7）
11. ~~M10 WPP 中段子流终止语义~~（**尝试修复后回退**：flush+前缀校验方案码流层面可行，但暴露 cost 缺 |coeff| 的失真缺陷，治本需 vendor sign/level 顺序改动，成本超收益；综述 `docs/HEVC-WPP-COST-ISSUE-20261025.md`）；~~M11 trellis seed 密钥化~~（`HKDF(key, cover_digest)`，连带关闭明文 CRC32 oracle）；~~M12 剩余 2.5~~（容器单次解析 + 载体克隆删除；2.4 因 M10 回退热路径消失，搁置）
12. ~~§3.5 KDF 参数调齐~~（**搁置**：待后续直接引入 argon2id 一并解决）

**P3（卫生）——2026-10-25 晚完成第一批（低风险组），见 §0.6**
13. ~~文档更正（STC 可达性位、PNG six-of-eight、`stc_u` 默认值、重复注释）、死代码（`zero_runs`、`stc_u <= stc_h` 死检查）、防御性守卫（HILL 长度、`category` 上界、Hamming `k`、`slot_positions` 溢出、`encode_substream` 越界）、`format.rs` 恒真校验、`layout_for_payload` 口径、commit/`extract_file` fsync、`is_hevc_annexb` 类型集合、thumb_bridge 64 位 meta、M7 PNG 尾部~~（`8561404` `40b961a` `d179e1f` `3dbdda2` `e538e68` `3628bc7`）
14. 剩余（需评估/含行为变化）：§3.1#2/#3/#4/#7/#8/#9/#10、§3.2#4/#5/#7/#8、§3.3#2/#3/#5/#6、§3.4#6/#7、§3.5#4/#5/#7、thumb_bridge 补丁重映射

---

## 附录 A：与 `docs/HEVC-STC-AUDIT-20261024.md` 的状态对照

2026-10-25 更新：标 ✓ 的项已在本轮修复（见 §0.5 的提交号）。

| 旧编号 | 摘要 | 当前状态 |
| :--- | :--- | :--- |
| 2.1 | 容量虚报 1 字节（`total_slots/2` 硬编码、漏 h−1） | ✓ 已修复（`e76aa97`，改用 `message_bits` 逆函数 + 容量可达性回归测试） |
| 2.2 | extract 硬编码 24/16；`header_bytes<24` 方言 panic | ✓ 已修复（`e76aa97`，命名常量 + 入口守卫 + 文档更正） |
| 2.3 | MP4 被嗅探认下但未实现 | ✓ 已修复（`e76aa97`，五个入口显式报"remux to HEIF or Annex-B"） |
| 2.4 / 2.5 | 子流双重重编码 / 容器双重解析 | 2.5 ✓ 已修复（2026-10-25 P2：单次解析 + 载体克隆删除）；2.4 未修（M10 回退后中段子流本被排除，热路径消失，搁置） |
| 4.1–4.4 | construction_method / iloc 零推进 DoS / `as usize` / 无 ipma | ✓ 已修复（`6d81ec7`） |
| 5.1 / 5.2 / 5.4 | `infe` v3 偏移 / 多 extent delta×N / iloc v2 panic | ✓ 已修复（`4853a02`） |
| 5.3 / 5.5 其余 | pitm/iref 未解析、补丁坐标重映射、meta 子盒尺寸等 | 5.3 ✓ 已修复（2026-10-25 P2：pitm/iref 解析、主图永不选、thmb 优先、checked 加法、unci 必败分支删除，含回归测试）；5.5 的重映射/子盒尺寸未修（成本高触发面窄，搁置） |
| 3.1 / 3.2 | 死函数 / 未用错误变体 | 未修（注：`Unsupported`/`TooLarge` 变体已在 `6d81ec7`/`e76aa97` 中投入使用） |
| 1.2 / 1.4 | STC 排除不可行 / 死分支 | 1.2 未修；1.4 未修（oracle 差一即本文 M2 已修 `f4d352e`） |

## 附录 B：审查方法与覆盖

- **逐行精读**（子审代理 + 主审抽查）：`stego/` 全部 33 个文件。
- **主审独立精读**：`crypto.rs`、`envelope.rs`（顶层）、`stego/envelope.rs`（关键段）、`stego/format.rs`、`stego/params.rs`、`stego/header.rs`、`stego/registry.rs`、`stego/traits.rs`、`errors.rs`、`router.rs`、`sniff.rs`、`commit.rs`、`facade.rs`；`adapters/isobmff.rs` 的 iinf/iloc 全部可疑路径；`engine.rs` 的关键不变量点（stealth/secrets 派生）；pe_codebits 的过滤器不变量链。
- **主审独立复验 ✅**：S1（对照参考实现推导镜像关系）、S2（提取路径重算摘要确认）、M1（Freshness 派生链 + PNG enc_key 链确认）、M2（extract/oracle 行映射差一确认）、M3（engine.rs:860 原文确认）、M4（uerd.rs:163 Q¹ 确认）、M7（IEND break 确认）、M9（fallback 恒 false 确认）、§3.6 isobmff 两条（索引边界逐项推演确认）。
- **交叉依赖核对**：dct-io 0.1.1、rust_h265 @7387b16、oxideav-h265 @db02660（按 Cargo.lock 锁定版本源码）。
- **参考实现**：`temp/github/stegolab`（HILL / S-UNIWARD / J-UNIWARD）、`temp/github/hstego`。
- **次重点覆盖声明**：结构域的 `engine.rs`（2251 行）只做了目标性抽查（unwrap 热点、stealth/secrets 派生不变量、提交流程），`adapters/pdf.rs`、`pe.rs`、`pe_slack.rs`、`pe_codebits.rs`、`mkv.rs` 等只做 unwrap 热点扫描与关键不变量抽查，未逐行精读；`cli.rs`（2460 行）与 `analysis.rs` 的检测器部分、`i18n`、examples 多数文件、`python/`（已冻结）不在本次范围内。若需要，结构域可另行安排同等深度的一轮。
- **局限**：静态审查，未运行构建与测试；涉及"实际编码器行为"的论断（如 WPP 行尾 terminate 语义）标注了不确定性来源；子审代理报告中未被主审复验的条目均已按代理给出的文件:行号证据收录，可信度依赖该证据链。

---

*报告结束。发现总计：严重 2、中等 15（M1–M13 + isobmff 两条）、轻微/建议 45+。核心算法内核经独立推导验证无误。**P0/P1 已于审查当日修复（8 个提交，§0.5）；P2 于同日下午处理完毕（修复 + 按成本收益搁置，§7）**；剩余 P3 与搁置项见 §0.5"仍未修"。*
