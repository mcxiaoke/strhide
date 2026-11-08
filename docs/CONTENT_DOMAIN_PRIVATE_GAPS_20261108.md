# 内容域私有 Profile 缺口盘点与补齐方案

> 日期：2026-11-08
> 前提：私有参数走 `Profile`（第三方集成场景）；目标是抗定向检测
> 范围：`content-png` / `content-jpeg` / `content-hevc` / `content-audio` 四个引擎 + 共享层
> 关联：`docs/PRIVATE_PROFILE_COSTED_PLAN_20261108.md`（结构域为主）、`docs/PRIVATE_PROFILE_AUDIT_REVIEW_20261108.md`

---

## 0. 三句话结论

1. **内容域的「隔离」今天已经能用**：五个载体各有至少一个公开盐字段（`hpos_salt` / `cover_digest_tag` / `cover_salt`），改一个就让官方二进制读不出。未暴露的那些标签只是「少几个可分隔的域」，属完整性缺口，不是可用性缺口。
2. **真正缺的是「统计面可调性」**：抗定向检测只看嵌入几何与成本模型。PNG 的成本核写死、HEVC 和音频连一个可调参数都没有（`HevcParams {}`、`AudioParams {}` 都是空结构体）。
3. **还缺一层「静态参数基线」**：`PngParams` / `JpegParams` 是运行时的（`--params` / `toml`），私有构建没有编译期手段把它们钉死。这与「单一确定性二进制」的原则直接冲突，是这次要补的第二个大洞。

---

## 1. 内容域私有化的两种价值（先分清，否则排序必错）

| 类型 | 目的 | 有效手段 | 当前状态 |
| :--- | :--- | :--- | :--- |
| **隔离型** | 官方 / 第三方二进制读不出私有载体 | L1/L2 链上任一公开盐或标签 | **已具备**（每引擎至少一个） |
| **统计型** | 定向 steganalysis 判不出有无/长度 | 嵌入几何、成本模型、参数基线 | **大面积缺失** |
| 无效型 | — | 头部明文字段（`version`/`format_id`/CRC）、AAD 前缀 | 见成本评估 §1.1，收益为 0 |

内容域**不存在密钥无关的结构指纹**：头部 512 槽位集合由 `prng.rs:231-234` 的 `j = i + gen_range(n - i)` 从全池抽取，未持密钥连槽位都定位不到。所以内容域的「抗检测」只能靠统计面。

---

## 2. 现状盘点矩阵

图例：`✓` 已可由 Profile 定制；`W` 已可由运行时参数定制（但无静态基线）；`—` 只能改代码

| 维度 | PNG | JPEG | HEVC | 音频 (WAV/FLAC) |
| :--- | :--- | :--- | :--- | :--- |
| L1 公开盐 | `✓` `hpos_salt` | `✓` `cover_digest_tag` | `✓` `cover_salt` | `✓` `hpos_salt` |
| 标签表（domain/hpos/enc/perm/stc） | `✓` `cipher` | `✓` `cipher` | `✓` `cipher` | `✓` `cipher` |
| L2 头种子标签（hdr-stc/ext-stc） | — 写死 | — 写死 | — 写死 | — 写死 |
| AAD 前缀 | — 写死 | — 写死 | — 写死 | — 写死 |
| 引擎独有标签 | — | — | — `session-salt` 写死 | — `flac-body-phase` 写死 |
| 无口令默认密钥 | `✓` `default_secret` | `✓` | `✓` | `✓` |
| 头/扩展 STC 几何 | — 写死 | `✓` `sb_h/sb_u/ext_h/ext_u` | — `HEVC_EXT_STC_H/U` 写死 | — `shape.h/u` 自动 |
| 体 STC 几何 | `W` `stc_h/stc_u` | `✓` `sb_h/sb_u` + `W` | `✓` `stc_h/stc_u` | `W` 自动 |
| 槽位网格 / 选点规则 | — 写死 | `✓` `grid_rule` | — `POOL_SLOTS`/`REF_FLIP` 写死 | — 写死 |
| 成本模型选择 | `W` 3 个（hill/suniward/mipod） | `W` 4 个（uerd/juniward/jmipod/precover） | 无成本模型 | 单一模型 |
| 成本模型参数 | `—` 核写死；`W` p1/p2/eps/excl | `W` neighbor_weight/wet_cost/polarize | — | `—` window/epsilon 写死 |
| 私有成本模型（新算法身份） | — 需扩 `algorithm_id 1..=3` | — | — | — |

**结论**：JPEG 覆盖度最高（几何 + 4 模型 + 参数全可调）；PNG 次之（参数可调，成本核写死）；HEVC 和音频基本是「全部写死」。

---

## 3. 缺口清单

### 3.1 隔离完整性（便宜，但**不改变检测结果**）

| 编号 | 缺口 | 位置 | 改法 | 保持官方默认 |
| :--- | :--- | :--- | :--- | :--- |
| G1 | `hdr_stc_label` / `ext_stc_label` 未在 `WireCipherProfile` 内 | `format.rs:482-483` | 加两个字段，`derive_l2_locator_keys` 改读 `cipher.*`；4 个 official const 填回现值 | 是（值不变） |
| G2 | `V4_AAD_PREFIX` 写死 | `stego/envelope.rs:105`、`build_v4_aad` | 加进 `WireCipherProfile.aad_prefix`，`build_v4_aad` 增加 `cipher` 参数（调用点：png 1741/2183、jpeg 940/1340、hevc 1393/2274、audio 824/957） | 是 |
| G3 | HEVC 会话盐标签写死 | `hevc/engine.rs:454` | `HevcFormatProfile.session_salt_label` | 是 |
| G4 | FLAC 体相位标签写死 | `audio/mod.rs:108` | `AudioFormatProfile.flac_body_phase_label` | 是 |

工时 **1.0–1.5 人日**。检测收益 0；作用是「同一个口令 / 同一套盐下，各派生域仍互不可推」。

### 3.2 静态参数基线（**这是最该补的一条**）

| 编号 | 缺口 | 位置 | 改法 |
| :--- | :--- | :--- | :--- |
| G5 | 内容域参数只能运行时给（`StegoTuning` / `toml`），私有构建无法在编译期钉死 | `stego/params.rs:871` `StegoProfile`；`options.rs` `StegoTuning` | `StegoProfile` 增加 `png_params: Option<&'static PngParams>` / `jpeg_params: Option<&'static JpegParams>` / `hevc_params: Option<&'static HevcParams>` / `audio_params: Option<&'static AudioParams>`；引擎侧解析顺序改为「显式调用参数 > Profile 基线 > 官方默认」 |

要点：

- `PngParams` 含 `BTreeMap<String, f64>`（`algorithm_options`），`BTreeMap::new()` 是 const，`static` 可构造；`JpegParams` 同理。
- 解析优先级必须在代码里写清并由测试锁定，否则私有构建会被配置文件悄悄覆盖。
- 这一条不改变任何 wire 字段：`p1_window`/`p2_window`/`stc_h`/`stc_u`/`sigma` 本来就写进头部，私有值只是「默认值不同」。

工时 **2.0–2.5 人日**。检测收益 **中高**（决定每张载体的改动密度、散布范围、排除区），且是后续所有统计型定制的落点。

### 3.3 统计面可调性

| 编号 | 缺口 | 位置 | 改法 | 工时 |
| :--- | :--- | :--- | :--- | :--- |
| G6 | PNG 成本核写死 3×3，`kernel_id` 被硬拒非 0 | `hill.rs:22`、`header.rs:409`、`png/registry.rs:13-17`、`header.rs:332`（`algorithm_id 1..=3`） | 私有模型注册新 wire id（如 4），核 taps 与两级低通权重做成模型字段；`header` 放行 id 4 并保持 `kernel_id = 0` 语义不变 | 1.5–2.0 |
| G7 | HEVC 无任何可调项：`HevcParams {}` 为空 | `options.rs:230` | 新增 `ext_stc_h/ext_stc_u`（`engine.rs:131-134` 写死）、`pool_slots`（`engine.rs:92` = 2048）、`ref_flip`（`engine.rs:830` = 4）字段；`HevcFormatProfile` 同步扩展非 wire 字段 | 2.0–3.0 |
| G8 | 音频无任何可调项：`AudioParams {}` 为空，`CostParams::default()` 直接取常量 | `stego/params.rs:745`、`audio/core.rs:791`、`audio/cost.rs:39-48` | 把 `window`/`epsilon`/`SILENCE_COST` 与 `CHANGE_PERCENT_*` 提为 `AudioParams` 字段；注意它们已写入头部（自描述），所以只影响统计面、不影响可读性 | 1.0–1.5 |
| G9 | 音频无算法身份可换（`algorithm_id` 必须 0） | `header.rs:350` | 若要与 G8 配套区分载体身份，可新增 audio wire id；**单独做无收益**，建议并入 G8 | — |

工时合计 **4.5–6.5 人日**。

### 3.4 明确不做

| 项 | 理由 |
| :--- | :--- |
| `CONTENT_ENVELOPE_VERSION` / `format_id` 定制 | 头部槽位密钥化散列，未持密钥不可观测（成本评估 §1.1） |
| CRC 掩码 | 同上 |
| `audio/perm.rs` 改读 `cipher.perm_label` | `format.rs:503` 已用 `perm_label` 派生 `perm_seed`，`PERM_LABEL` 只是内层再分隔，前提不成立 |
| `magic_label` 扩到 PNG/JPEG/Audio | `magic4` 仅 HEVC 消费（`hevc/engine.rs:1382/2119`），`format.rs:846` 已断言 "magic label is not per-format" |
| `stego/envelope.rs:266` `strhide-reproducible-v2` | 只服务 seeded/repro 模式，不参与常规写读 |

---

## 4. 工作包与推荐顺序

| 包 | 内容 | 工时 | 检测收益 | 隔离收益 | 风险 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **C1** | G5 静态参数基线（含 `StegoProfile` 扩展 + 优先级测试） | 2.0–2.5 | 中高 | 低 | 低 |
| **C2** | G6 PNG 私有成本模型（核 + 低通权重 + 新 wire id） | 1.5–2.0 | 中高 | 中 | 中（排序路径） |
| **C3** | G8 音频可调（window/epsilon/散布） | 1.0–1.5 | 中 | 低 | 低 |
| **C4** | G7 HEVC 可调（ext stc / pool / ref-flip） | 2.0–3.0 | 中 | 中 | **较高**（窗口与容量核算） |
| **C5** | G1–G4 标签补全 | 1.0–1.5 | 0 | 中 | 低 |
| **C6** | 验收（隔离矩阵 + `*_stress` + baseline） | 0.5 | — | — | — |

推荐顺序：**C1 → C2 → C3 → C5 → C6 → C4**

- C1 先做，因为后面每一项的「私有值」都要靠它落地（否则只能靠 toml）；
- C2/C3 成本低、收益直接，且都只碰单一引擎；
- C5 是纯常量替换，随时可插入；
- C4 放最后，因为 HEVC 的 `pool_slots` / `ref_flip` 会牵动容量核算与首帧窗口推导（`hevc_window_target_slots`，`engine.rs:430-434`），必须单独一轮验证。

内容域完整补齐合计 **8.0–11.0 人日**；只做 C1+C2+C3+C6 的「实用最小集」约 **5.0–6.5 人日**。

---

## 5. 验收口径

每个包都必须过：

```bash
cd rust
cargo build --release --all-features
cargo test --all-features --all-targets
python ../scripts/baseline_hash.py --check          # 官方默认必须逐字节不变
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
python ../scripts/import_lint.py
```

内容域专项：

```bash
cargo run --release --all-features --example png_stress
cargo run --release --all-features --example jpg_stress
cargo run --release --all-features --example hevc_stress
cargo run --release --all-features --example audio_stress
```

新增 `tests/private_content_isolation.rs`，每个包都要往里加断言：

1. 私有写 → 私有读成功；
2. 私有写 → **官方 Profile 读**返回 `NoHiddenData`（不得是「密码错」等可区分错误）；
3. 私有写 → `restore`/无损性不变（PNG/JPEG 像素/系数级、音频采样级）；
4. 私有参数基线生效：不传 `--params`、不读 toml 时，写入的头部字段等于 Profile 基线值（这条是 C1 的专属断言）。

---

## 6. 一个需要权衡的提醒

内容域补齐后，**第三方工具仍然能一眼看到结构域产物**：`prIv` / `stEg` / `SHRD` / `MP4_UUID_NEUTRAL` / APP15 全部明文写在容器树里，`StructureProfile` 至今只有 `default_secret` / `stealth_domain` / `magic` 三个字段，没有一个能改这些 tag。

所以若「第三方集成 + 规避开源指纹」是主诉求，**结构域的 `ContainerTags` 是比内容域任何一项都更大的洞**（2.0–3.0 人日）。内容域优先是合理的（统计面确实是内容域独有），但建议把结构域 S1 与内容域 C1 并行排期，而不是放到内容域全部做完之后。
