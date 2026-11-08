# 内容域来源指纹消除 · 最小改动方案

> 日期：2026-11-08
> 目标：**消除来源指纹**（让别人无法把载体归因到 strhide），**不改嵌入算法**，改动尽量小
> 范围：内容域（PNG / JPEG / HEVC / 音频）＋ 派生链
> 前置结论：结构域本质不可隐身（必然新增容器结构、文件体积变化可测），隐身只能靠内容域 —— 这一点已确认

---

## 0. 结论

1. **内容域的可观测痕迹已经基本干净**：全部定长字段落在密钥化散列的槽位上，未持密钥连槽位都定位不到；四个引擎都刻意保留了原始重编码参数，不给"被某工具处理过"留痕。逐项证据见 §1。
2. **仍然存在的来源暴露只有 3 类**，其中一类是**真缺陷**：HEVC 有 11 个公开入口在"无口令"时直接使用公开常量 `PUBLIC_DEFAULT_SECRET`，**绕过私有 Profile**——用这些入口产出的载体，任何一份 strhide 二进制都能读。
3. 其余两类是派生链上的公开常量（`hdr-stc`/`ext-stc`/AAD 前缀/HEVC 会话盐/FLAC 相位）与各引擎公开盐。**总工作量 1.5–2.0 人日，全部是常量提升与入口收口，不触碰任何算法路径。**

---

## 1. 核实：内容域现在还剩哪些可被归因的痕迹

### 1.1 已经是干净的（有代码依据，不必改）

| 载体 | 事实 | 依据 |
| :--- | :--- | :--- |
| PNG | 重编码时**沿用原始逐行滤波类型**与 **zlib FLEVEL**，只替换 IDAT 数据段，不重写其它 chunk | `png/engine.rs:108-115`（`row_filters`）、`477+`（读 zlib 头）、`715-717`（只替换 IDAT run） |
| JPEG | 调用 `dct_io::write_coefficients(carrier_bytes, …)`，**在原始字节上就地补熵编码**，量化表/Huffman 表/APPn/缩略图原样保留 | `jpeg/engine.rs:1053` |
| HEVC | 只对被改动的 slice NAL 做 CABAC 重编码，其余 NAL 与 `moov`/`mdat` 布局不动，不做整体重封装 | `hevc/engine.rs:1567-1593`、`1830+`（`reencode_slice`） |
| FLAC / WAV | FLAC 保持**每帧原始字节偏移**；WAV 只改采样值 | `audio/mod.rs:30` 模块文档、`audio/core.rs` 写入路径 |
| 头部 / 扩展区 | 64 字节头与 TLV 扩展区虽为明文，但槽位由 `j = i + rng.gen_range(n - i)` 从**整个候选池**抽取，集合与顺序都随密钥 | `prng.rs:231-234`、`png/engine.rs:1205-1209` |
| 官方分析器 | 没有内容域专用识别（不尝试用公开密钥解密），只有 chi²/RS/WS 等通用统计轨 | `analysis.rs`（仅 `track_content_domain` 统计） |

结论：内容域不存在「扫一眼就知道是 strhide」的常量。**唯一可行的归因路径是：拿开源版本 + 已知口令去解。**

### 1.2 仍然存在的来源暴露（按可利用强度排序）

| 编号 | 问题 | 位置 | 强度 |
| :--- | :--- | :--- | :--- |
| **A** | **HEVC 的 11 个公开入口在 `secret == None` 时直接用 `PUBLIC_DEFAULT_SECRET`，完全绕过 `StegoProfile.default_secret`** | `hevc/engine.rs:100-106`（`legacy_credential`）；调用点 `1034 / 1098 / 1148 / 1694 / 1718 / 2002 / 2050 / 2301 / 2418 / 2540 / 2807` | **高（真缺陷）**：第三方集成若走 `stego::hevc::embed_hevc()` 直接调用，产出的无口令载体**任何 strhide 二进制都能读**，私有 Profile 形同虚设 |
| B | 派生链上的 6 个公开常量：`hdr-stc` / `ext-stc`（`format.rs:482-483`）、AAD 前缀（`stego/envelope.rs:105`）、HEVC 会话盐（`hevc/engine.rs:454`）、FLAC 体相位（`audio/mod.rs:108`）、seeded 派生前缀（`stego/envelope.rs:266`） | 见左 | 中：不直接暴露，但「改了几个标签就以为隔离了」的集成方会留缺口 |
| C | 各引擎公开盐：`strhide-stego-hpos-salt-v2` / `strhide-audio-hpos-salt-v1` / `strhide-flac-hpos-salt-v1` / `strhide-cover-v1` / `strhide-hevc-cover-v1`（`format.rs:96-101, 240-300`） | 同左 | 已可配（每引擎一个字段），但**默认值公开**，不主动改就等于没隔离 |
| D | 二进制层字符串（CLI 名、版本、帮助文本、`strhide.toml` 路径） | `cli/`、`build.rs` | 低（载体层无关，属交付层面） |

**A 是本次唯一必须修的代码缺陷**（既影响第三方集成，也影响"消除来源"这个目标本身）。B/C 是配方问题，不是缺陷。

---

## 2. 最小改动集

### M1 收口 HEVC legacy 入口（修 A）

**问题复现路径**（已核对）：`embed_hevc_with_info(carrier, payload, secret: Option<&str>, …, fmt: &HevcFormatProfile, …)` 收到 `fmt` 却不收 `StegoProfile`，`None` 直接落到 `PUBLIC_DEFAULT_SECRET`。注意**主流程不受影响**：facade 走的是 `stego/engine.rs:472/978` 的 `embed_hevc_with_info_v4`（收 `Credential`），无此问题。

两个方案，按「小改动」取前者：

| 方案 | 做法 | 改动点 | 工时 | 副作用 |
| :--- | :--- | :--- | :--- | :--- |
| **a（推荐）** | `legacy_credential` 的 `None` 分支改为返回错误（「HEVC 入口必须显式给出口令或密钥」），内部 3 处调用点补显式值 | 1 个函数 + 3 处内部调用 + 测试 | **0.3–0.5 人日** | 库外若有人依赖「不传口令」会编译通过但运行报错——项目未发布，可接受，且这正是想要的行为 |
| b | 给 11 个入口加 `&StegoProfile` 参数，None 时取 `profile.secret()` | 11 个签名 + 7 处内部调用 | 0.8–1.0 人日 | 与 v4 入口职责重复 |

验收：`stego::hevc::embed_hevc(carrier, payload, None, …)` 必须报错，而不是产出可被公开密钥读取的载体。

### M2 派生链常量私有化（修 B）

| 子项 | 改法 | 改动点 | 工时 |
| :--- | :--- | :--- | :--- |
| `hdr_stc_label` / `ext_stc_label` | 加进 `WireCipherProfile`（`format.rs:308-323`），`derive_l2_locator_keys` 内部改读 `cipher.*`（`format.rs:482-483`） | 结构体 + 4 个 official const + 2 行函数体；**22 个调用点不用改**（`cipher` 已是参数） | 0.2 |
| AAD 前缀 | 新增 `build_v4_aad_with(prefix, …)`，旧 `build_v4_aad` 保留并委派官方前缀（测试无需改）；8 处生产调用点改走新函数 | 1 个新函数 + 8 处调用 | 0.3 |
| HEVC 会话盐 | `HevcFormatProfile.session_salt_label`；`hevc_session_salt(nonce)` 增加 `label` 参数 | 1 字段 + 1 函数 + 1 处调用 + 测试 | 0.15 |
| FLAC 体相位 | `AudioFormatProfile.flac_body_phase_label`；`flac_body_phase` 增加 `label` 参数 | 1 字段 + 1 函数 + 4 处调用 + 测试 | 0.2 |
| seeded 派生前缀 | `derive_seeded` 增加 `prefix` 参数（或并入 `WireCipherProfile`） | 1 函数 + 调用点（仅 seeded 路径） | 0.15 |

小计 **1.0–1.2 人日**。要求：4 个 official const 填回现值，`baseline_hash --check` 必须逐字节不变。

### M3 私有盐配方（修 C，零代码）

不需要改代码：`StegoProfile` 已经有 `png` / `jpeg` / `hevc` / `audio` / `flac` 五个 `Option<FormatProfile>` 和 `domain`。要做的是**在私有构建里真的把它们都填上**，并写进 `docs/PRIVATE_BUILD.md` 与 `examples/private_profile.rs`。

推荐：每个盐独立随机（不要复用），生成方式写进文档（`openssl rand -hex 16`），长度与现值一致以便保持字段对齐习惯。

工时 **0.1 人日**（文档）。

### M4 构建期护栏（防回归）

新增 `tests/private_provenance.rs`，四类断言：

1. 私有 Dialect 写出的 5 种载体，用**官方 `StegoProfile` + 相同口令**读，必须是 `NoHiddenData`（不是别的错误）；
2. 用**官方 `StegoProfile` + `PUBLIC_DEFAULT_SECRET`** 读私有无口令载体，必须 `NoHiddenData`；
3. `stego::hevc::embed_hevc(…, None, …)` 必须返回错误（锁死 M1）；
4. 官方 Dialect 的字节输出与 `baseline_hash` 一致（防止私有化时把默认值改掉）。

工时 **0.3 人日**。

### M5（可选）二进制层脱敏

`cli` 的程序名、版本串、帮助文本、默认配置路径里含 `strhide`。若交付形态要求"连二进制都看不出"，需在 `build.rs`/`cli` 层做可配置品牌串。与载体无关，**0.3–0.5 人日**，可延后。

---

## 3. 明确不做（与前几版文档的差异）

| 先前列入的项 | 现在结论 | 理由 |
| :--- | :--- | :--- |
| PNG 成本核私有化（原 C2/G6） | **不做** | 属"改算法/改统计面"，与本次目标（消除来源指纹）无关 |
| 静态参数基线（原 C1/G5） | **不做** | 同上；它改善的是统计面，不是可归因性 |
| HEVC/音频几何可调（原 C4/G7/G8） | **不做** | 同上，且风险最高 |
| `format_id` / `version` / CRC 掩码 | **不做** | 密钥化散列槽位，未持密钥不可观测（见 `PRIVATE_PROFILE_COSTED_PLAN_20261108.md` §1.1） |
| `magic_label` 扩到 PNG/JPEG/Audio | **不做** | `magic4` 仅 HEVC 消费，加了无人读 |
| `audio/perm.rs` 改读 `perm_label` | **不做** | 前提不成立（`format.rs:503` 已用 `perm_label`） |
| 结构域 `ContainerTags` | **本次不做** | 结构域本就不抗检测，与"隐身"目标不符；仅在需要"第三方静态扫描不认"时另议（2–3 人日） |

---

## 4. 总工时与顺序

| 顺序 | 项 | 工时 | 类型 |
| :--- | :--- | :--- | :--- |
| 1 | **M1** 收口 HEVC legacy 入口 | 0.3–0.5 | 修缺陷 |
| 2 | **M4** 护栏测试（先写骨架，随 M1/M2 增量补断言） | 0.3 | 验收 |
| 3 | **M2** 派生链常量私有化 | 1.0–1.2 | 常量提升 |
| 4 | **M3** 私有盐配方 + 文档/示例 | 0.1 | 文档 |
| | **合计** | **1.5–2.0 人日** | 全部不触碰算法路径 |
| 可选 | **M5** 二进制层脱敏 | 0.3–0.5 | 交付面 |

每步验收固定三条：

```bash
cd rust
cargo test --all-features --all-targets
python ../scripts/baseline_hash.py --check      # 官方默认必须逐字节不变
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
```

---

## 5. 私有内容域的一页配方（M2/M3 完成后即可用）

```rust
// 盐/标签取 16B 随机；`PRIVATE_CIPHER` 见下，5 个字段除 suite 外全部换掉。
const PRIVATE_PNG: PngFormatProfile = PngFormatProfile {
    hpos_salt: b"<16B 随机>",
    cipher: &PRIVATE_PNG_CIPHER,
};

const PRIVATE_WAV: AudioFormatProfile = AudioFormatProfile {
    hpos_salt: b"<16B 随机>",
    cipher: &PRIVATE_AUDIO_CIPHER,
    flac_body_phase_label: b"<私有>",          // M2 之后才有
};

const PRIVATE_FLAC: AudioFormatProfile = AudioFormatProfile {
    hpos_salt: b"<16B 随机，与 WAV 不同>",
    cipher: &PRIVATE_AUDIO_CIPHER,
    flac_body_phase_label: b"<私有>",
};

const PRIVATE_JPEG: JpegFormatProfile = JpegFormatProfile {
    cover_digest_tag: b"<16B 随机>",           // 其余 7 个字段沿用 DEFAULT_JPEG_FORMAT 的值
    cipher: &PRIVATE_JPEG_CIPHER,
    sb_bytes: 44, sb_h: 8, sb_u: 2, ext_h: 8, ext_u: 4,
    grid_rule: DEFAULT_JPEG_FORMAT.grid_rule,
};

const PRIVATE_HEVC: HevcFormatProfile = HevcFormatProfile {
    cipher: &PRIVATE_HEVC_CIPHER,
    magic_label: b"<私有>",
    cover_salt: b"<16B 随机>",
    session_salt_label: b"<私有>",             // M2 之后才有
    stc_h: 7, stc_u: 2,
};

const PRIVATE_DIALECT: Dialect = Dialect::new()
    .with_stego_profile(
        StegoProfile::new()
            .with_default_secret("<32B 随机，绝不能用空>")   // 不设 = 公开密钥，最强来源暴露
            .with_stego_domain("<私有域>")
            .with_png_format(PRIVATE_PNG)
            .with_jpeg_format(PRIVATE_JPEG)
            .with_hevc_format(PRIVATE_HEVC)
            .with_audio_format(PRIVATE_WAV)                 // 注意：WAV 用 audio_format
            .with_flac_format(PRIVATE_FLAC),
    );
```

> 构造器名已核对：`with_default_secret` / `with_stego_domain` / `with_png_format` / `with_jpeg_format` / `with_hevc_format` / `with_audio_format`（WAV）/ `with_flac_format`（`stego/params.rs:932-989`）。五个 `FormatProfile` 没有逐字段 builder，只能写结构体字面量；上例中除注明外，取值与对应 `DEFAULT_*` 常量一致。

关键约束（写进 `docs/PRIVATE_BUILD.md`）：

1. `default_secret` **必须**设置——它是唯一由"无口令"路径使用的密钥；空或不设 = 任何 strhide 二进制可读；
2. 五个盐**必须各不同**——否则跨格式共用一个 `pre_salt`，同一口令下不同格式的载体可互相推断；
3. 不要通过 `stego::hevc::embed_hevc(...)` 这类入口直接调用（M1 后它们会直接报错）；
4. 所有改动都只影响派生，不改嵌入几何——因此对统计检测率**零影响**，这符合本次目标，不要期待它提升抗 steganalysis 能力。

---

## 6. 实施记录（2026-11-08 13:37）

| 项 | 状态 | 落地内容 |
| :--- | :--- | :--- |
| M1 HEVC legacy 入口 | ✅ | `legacy_credential` 改为 `Result`，`None`/`""` 报错；7 处内部调用点补 `?`；主流程不受影响 |
| M2 派生链常量 | ✅（1 项例外） | `WireCipherProfile` 增 `hdr_stc_label`/`ext_stc_label`/`aad_prefix`；`HevcFormatProfile.session_salt_label`；`AudioFormatProfile.flac_body_phase_label`；`build_v4_aad` → `build_v4_aad_with`（旧签名删除） |
| M2 例外 | ⏭️ 未做 | seeded 前缀 `strhide-reproducible-v2` 仅服务 `Freshness::Seeded`（测试/`repro_*` 示例），非生产写入路径 |
| M3 配方与文档 | ✅ | 新增 `docs/PRIVATE_BUILD.md` |
| M4 护栏测试 | ✅ | 新增 `tests/private_provenance.rs`，7 个用例全部通过 |
| M5 二进制层脱敏 | ⏭️ 未做 | 可选项，本次范围外 |

实测更正（写进代码注释与测试）：

- `hdr_stc_label` / `ext_stc_label` **只被 JPEG superblock 与 HEVC superblock 消费**。PNG 与音频的基头由 `read_slot_bytes` 直接读 LSB，不建 trellis，所以对它们而言这两个标签是 no-op —— 改标签表时不要以为 PNG/音频也被这一项隔离了。测试因此改用 JPEG 载体。
- 门禁：`baseline_hash --check` 28/28 identical（官方默认逐字节不变），全量测试 0 failed，`clippy -D warnings` / `import_lint` / `check_feature_matrix`（11 组合）全绿。
