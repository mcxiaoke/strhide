# strhide Rust 核心代码审查报告

> 审查时间：2026-11-03 12:46 (+08:00)
> 审查范围：`rust/` 核心库与 CLI（结构域、内容域、密码学、并发与 I/O、错误处理、测试与示例），并参考 `gui/src-tauri` 的公开接口调用方式。
> 审查方式：静态代码核对（逐文件阅读 + 关键路径交叉验证）；未修改任何 Rust 源码；未执行完整 `cargo test`。
> 基线文档：`AGENTS.md`、`README.md`、`docs/smart_file_data_hiding_design.md`、`docs/api/ARCHITECTURE.md`、`docs/api/STEGO-API.md`、`docs/api/WIRE_SPEC.md`、`docs/CHANGES-20261030.md`～`docs/CHANGES-20261103.md`、`docs/lib_interface_audit_and_refactoring_plan_20261103.md`。
> 边界检查：已运行 `python scripts/import_lint.py`，结果为
> `OK: all architectural boundaries intact (structure !-> stego, stego !-> structure, core !-> {formats, structure, stego, cli})`。

---

## 1. 总体结论

代码整体工程质量较高：两个域的分层边界清晰，统一错误类型、原子提交（临时文件 + fsync + rename）、还原前 SHA-256 强校验、拒绝优先（rejection-first）以及大量边界测试都已经落地。`import_lint.py` 的分层红线当前全部通过。

本次审查发现的主要风险不在“功能是否跑通”，而在以下四类：

1. **安全模型不一致**：HEVC Scheme C 的口令派生没有任何口令拉伸（PBKDF2/Argon2），PNG/WAV/FLAC 的头部槽位置换种子也直接使用原始口令，均可形成低成本的离线口令枚举面。
2. **公共接口契约不完整**：`ExtractParams` 的迭代上限/套件白名单只在 JPEG 提取生效；多个公开入口在非法输入下会 `assert`/`expect`/越界 panic，而 release 构建是 `panic = "abort"`。
3. **格式识别过弱**：JPEG 仅凭 2 字节 SOI、MP4 仅凭偏移 4 的 4CC 就进入写路径，且 auto 策略会回退到 `eof`/`box_uuid`，可能把非载体文件当作载体追加数据。
4. **协议/文档与实现漂移**：HEVC Scheme C 的线格式头部在 `WIRE_SPEC.md` 被写成 40 字节，代码实际是 32 字节 Superblock + 16 字节 GCM Tag = 48 字节；另有多处 API 文档已过期。

### 风险排序（按“影响 × 可利用性 × 修复成本”）

| 排名 | 风险 | 级别 | 一句话说明 |
|---:|---|---|---|
| 1 | HEVC Scheme C 无口令拉伸 | 严重 | 口令即 AES 密钥输入，HKDF 一次即可验证候选口令，弱口令可被离线字典快速恢复 |
| 2 | PNG/音频头部置换种子无口令拉伸 | 高 | 头部/FeatureWord 位置可用原始口令直接计算，形成廉价口令验证 oracle |
| 3 | 弱格式嗅探 + auto 回退 | 高 | 非 JPEG/MP4 文件可能被追加信封/uuid box，违反“未知格式拒绝” |
| 4 | `ExtractParams` 限额只在 JPEG 生效 | 高 | PNG/HEVC/音频的 KDF 上限与套件白名单被静默忽略 |
| 5 | 公开 API 可 panic | 高 | `apply_hevc_patches`、`superblock_positions`、私有 profile 的 `default_suite()` 均可在合法调用下 panic |
| 6 | `.bak` 路径 check-then-create 竞态 | 高 | 并发写入可能互相覆盖备份；`File::create` 还跟随符号链接 |
| 7 | 容量/协议边界错误 | 中 | `MIN_UBE_ENCRYPTED` 与实际最小信封差 1 字节；HEVC 头部尺寸文档错误 |
| 8 | 其余 API/内存/文档问题 | 中/低 | 见 §5、§6 |

---

## 2. 问题统计

| 级别 | 数量 | 编号 |
|---|---:|---|
| 严重 | 1 | S-1 |
| 高 | 5 | H-1 ～ H-5 |
| 中 | 9 | M-1 ～ M-9 |
| 低 | 4 | L-1 ～ L-4 |
| **合计** | **19** | |

按维度分布（一条问题可跨维度，按主维度归类）：

| 维度 | 主要问题 |
|---|---|
| 架构与分层 | 分层红线通过；主要问题是公共类型耦合（`PngFormatProfile`/`AudioFormatProfile` 复用 `JpegFormatProfile`）、全部内部模块 `pub mod`、公共枚举缺少 `#[non_exhaustive]` |
| 库接口/参数设计 | `ExtractParams` 未贯穿所有引擎；`StegoProfile` 单一 `audio` 字段；`FileTarget`/`overwrite` 语义与结构域不一致；`StegoCodec::id()` 与线格式 id 不一致 |
| 代码质量 | `take_varint` 位移截断；`MIN_UBE_*` 常量与注释错误；部分 `expect`/`assert` 在公开路径；多处文档与实现漂移 |
| 算法/性能 | HEVC/PNG/音频 KDF 设计；JPEG 系数整图 clone + 4 GiB 回溯位图；结构域写入峰值内存 |
| 可靠性/稳定性 | 弱格式嗅探、`.bak` 竞态、PDF stealth EOF overlay 诊断、1 GiB 解压上限、公开 panic |
| 正确性/协议 | HEVC 头部 40 vs 48；`MIN_UBE_ENCRYPTED` 213 vs 214；PNG p1/p2 自描述文档过期 |

---

## 3. 严重问题

### S-1 HEVC Scheme C 的口令派生没有口令拉伸，弱口令可被低成本离线验证

**位置：**
- `rust/src/stego/hevc/engine.rs:3281-3308`（`derive_hevc_key`）
- `rust/src/stego/hevc/engine.rs:52-59`（`derive_magic`）
- `rust/src/stego/hevc/engine.rs:3228-3238`（`trellis_seed_from_key`）
- `docs/api/WIRE_SPEC.md:723-731`（协议文档明确写 `key = HKDF-SHA256(ikm, salt = cover_digest, ...)`）

**可复核行为：**

```rust
// rust/src/stego/hevc/engine.rs:3281-3308
let secret_bytes = effective_secret(secret);          // NFC 后的用户口令
let ikm = match derive_domain_subkey_with_label(...) { ... }; // 可选 HKDF 子密钥
let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);       // salt = cover_digest
hk.expand(fmt.kdf_info, &mut key)                     // 直接得到 AES-256-GCM key
```

整个派生链只有 HKDF（以及可选的 HKDF 子密钥化），**没有 PBKDF2、Argon2 或任何迭代工作因子**。`cover_digest` 由文件内公开的参数集计算（`engine.rs:3243-3268`），因此攻击者对每个候选口令只需执行 1 次 HKDF，即可得到候选 `key`；再由 `trellis_seed_from_key` 得到 Superblock 槽位种子，读取候选 Superblock，并用 `derive_magic`（一次 SHA-256）校验 4 字节魔数即可判定口令是否正确。若走到 AEAD 层，一次候选口令也只多一次 AES-GCM 解密。

**为什么是问题：**

- 结构域使用 PBKDF2 100,000 次（`rust/src/core/crypto.rs:96`），JPEG 内容域使用 PBKDF2 200k/600k（`rust/src/stego/format.rs:113-130`），而 HEVC 完全不做拉伸。三个域的“口令保护”强度不在同一数量级。
- WIRE_SPEC 的威胁模型宣称“无凭据者无法定位头部槽位/无法通过魔数比对判定存在性”，但该性质只对**不知道口令**的随机猜测成立；对离线字典攻击，HKDF 速度（微秒级）使弱口令几乎无成本。
- `derive_magic` 只输出 4 字节，若攻击者不定位头部而是全文件猜测魔数，仍有 1/2^32 的误报；但结合 Superblock/FeatureWord 结构校验后误报率远低于此。

**影响面：** 所有 HEIF/HEIC、MP4/MOV、MKV、Annex-B 的 `embed` 载荷；使用弱用户口令的生产载体。

**修复方向（择一或组合）：**

1. 在 `derive_hevc_key` 前增加 PBKDF2-HMAC-SHA256（迭代数与 JPEG 套件表一致，例如 200k），以 `cover_digest` 或 Superblock 内随机 salt 作为 salt；把结果作为 HKDF IKM。协议需要升版本或明确“v2 key 派生”。
2. 若设计上刻意不把用户口令当作强秘密，则在 `WIRE_SPEC`/`STEGO-API` 的威胁模型中明确写出“HEVC 口令只做密钥隔离、不做抗暴力破解”，并要求部署方使用 `StegoProfile.default_secret` 或强口令；同时在 CLI 对手弱口令给出警告。
3. 增加回归测试：固定口令下 `derive_hevc_key` 的单次耗时应包含预期 KDF 成本（可用 `#[ignore]` 基准测试），防止未来再次退化为纯 HKDF。

---

## 4. 高严重级别问题

### H-1 PNG/WAV/FLAC 的头部槽位种子直接使用原始口令，形成廉价口令 oracle

**位置：**
- `rust/src/stego/envelope.rs:135-157`（`derive_header_perm_seed` / `..._with_profile`）
- `rust/src/stego/envelope.rs:183-207`（`derive_header_perm_seed_impl`）
- `rust/src/stego/png/engine.rs:1030-1040`（`header_layout` 调用）
- `rust/src/stego/audio/core.rs:651-653`（音频 `header_seed`）

**可复核行为：**

```rust
// rust/src/stego/envelope.rs:191-206
let pw = password.unwrap_or(fallback_secret);
let norm_pw = normalize_nfc(pw);
let effective_ikm = match derive_domain_subkey_with_label(norm_pw.as_bytes(), domain, domain_label) {
    Some(subkey) => &subkey,
    None => norm_pw.as_bytes(),
};
let hk = Hkdf::<Sha256>::new(Some(hpos_salt), effective_ikm);
hk.expand(hpos_label, &mut header_seed)
```

头部/FeatureWord 的槽位由该 `header_seed` 置换决定（`png/engine.rs:1030-1040`），而 seed 直接来自口令字节，**没有 PBKDF2**。提取端为了在读到 salt 之前定位头部，确实需要“无 salt 可复现”的种子，但可以用固定 salt 的 PBKDF2 实现同样效果（成本可接受），当前实现选择了最快路径。

**为什么是问题：**

- 攻击者拿到一张疑似 PNG/WAV/FLAC 隐写载体后，对每个候选口令执行 1 次 HKDF + 一次 512 槽前缀置换，读取 32 字节 Header 与 32 字节 FeatureWord；`FeatureWord::decode`（`rust/src/stego/header.rs:243-345`）对 version/codec/u/h/window/epsilon/sigma 有严格校验，随机数据通过的概率很低。因此可在 PBKDF2 之外建立一个快速口令验证 oracle。
- 这与 `derive_master`（`rust/src/stego/format.rs:549-573`）的 PBKDF2 成本设计相矛盾：攻击者不必先付 PBKDF2 就能判断口令。

**影响面：** 所有带用户口令的 PNG 空间域与 WAV/FLAC 音频载体。

**修复方向：**
- `derive_header_perm_seed_impl` 改为 `PBKDF2(password, hpos_salt/domain, 固定迭代数)` 得到 IKM，再 HKDF-Expand 出 `header_seed`；`hpos_salt` 已经是固定公开值，满足“读 salt 前可复现”。
- 或把头部种子改为 `HMAC-SHA256(key = 高成本派生 master, message = 固定标签)`，但 master 需要固定 salt 的 KDF，不能是裸口令。
- 待验证项：需要用真实 PNG/WAV/FLAC 载体统计“错误口令通过 FeatureWord/Header 结构校验”的误报率，以量化 oracle 的可利用性；该误报率预计很低，但建议在测试中固定下来。

### H-2 弱格式嗅探 + auto 回退，可能把非载体文件当作 JPEG/MP4 修改

**位置：**
- `rust/src/formats/sniff.rs:210-224`（`is_jpeg_bytes` 仅比较 SOI；`is_mp4_bytes` 仅检查偏移 4 的 4CC）
- `rust/src/structure/adapters/jpeg.rs:204-234`（`detect` 仅 SOI；无 SOS 时 `choose_auto_strategy` 返回 `"eof"`）
- `rust/src/structure/adapters/mp4.rs:25-68`（`detect` 仅 4CC；`choose_auto_strategy` 固定返回 `"box_uuid"`）

**可复核行为：**

```rust
// sniff.rs:210-212
pub fn is_jpeg_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= JPEG_MAGIC.len() && &bytes[..JPEG_MAGIC.len()] == JPEG_MAGIC
}

// jpeg.rs:222-234
fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, ube_size: u64) -> &'static str {
    if ube_size > JPEG_MAX_TOTAL_CAPACITY { return "eof"; }
    if find_jpeg_sos_offset(reader).is_err() { return "eof"; }
    "app_segment"
}
```

写路径 `write_core`（`rust/src/structure/engine.rs:890-905`、`:1067-1080`）只调用 `find_adapter_or_reject` 和 `choose_auto_strategy`；对 JPEG，`choose_auto_strategy` 在找不到 SOS 时**主动选择 `eof`**，随后 `EofAdapter::inject` 把 UBE 追加到文件末尾。MP4 的 `detect` 只要求文件字节 4..8 等于 `ftyp/styp/moov/mdat/.../uuid` 之一；`choose_auto_strategy` 无条件 `box_uuid`，因此一个非 MP4 文件只要偏移 4 的 4 字节是这些 4CC，就会被追加一个 `uuid` box。

**为什么是问题：**

- 与 `docs/smart_file_data_hiding_design.md` §2 和 `ARCHITECTURE.md` 的“无法识别的文件会被拒绝，而不是被静默追加”直接矛盾。
- `write_core` 在写入前没有调用 `adapter.verify_structure`（只做 `locate` 占用扫描），因此不会发现目标并不是合法 JPEG/MP4。
- 对用户而言，操作“成功”返回，但目标文件已被改变，且很可能无法再被原程序识别；这是格式保持工具的破坏性写入风险。

**影响面：** `strhide write` / `sthc write` 的 JPEG/MP4 载体；任何以 `FF D8` 开头或偏移 4 为白名单 4CC 的二进制文件。

**修复方向：**
- JPEG `detect` 至少要求：SOI + 可解析到 SOS + EOI 存在/合理；`choose_auto_strategy` 在 SOS 不可达时应**报错**而不是回退 `eof`（显式 `--strategy eof` 才允许追加）。
- MP4 `detect` 至少要求：首个 box 的 size 合法（`8..=file_len` 或 1+largesize 合法），且存在 `ftyp` 或可识别顶层 box 序列；`choose_auto_strategy` 应调用 `isobmff_verify_structure` 先判定。
- 在 `write_core` 写前增加 `adapter.verify_structure(host)` 的强制检查（或只在 `--force` 下跳过），与“rejection-first”原则一致。

### H-3 `ExtractParams` 的 KDF 上限与套件白名单只在 JPEG 提取生效

**位置：**
- 定义与文档：`rust/src/stego/params.rs:622-658`（`ExtractParams`、`max_pbkdf2_iterations`、`allowed_suites`）
- 构造器：`rust/src/stego/options.rs:864-873`（`with_allowed_suites` / `with_max_pbkdf2_iterations`）
- 唯一执行点：`rust/src/stego/jpeg/engine.rs:1180-1187`
- 未执行点：`rust/src/stego/engine.rs:227-237`（PNG extract 不接收 `limits`）、`:496-521`（HEVC extract）、`:976-1013`（FLAC）、`:1136-1147`（WAV）
- `InspectOptions.limits`：`rust/src/stego/options.rs:1124-1131`，但 `inspect_jpeg_from`（`jpeg/engine.rs:1425-1495`）没有接收/使用它。

**可复核行为：**

```rust
// jpeg/engine.rs:1180-1187（只有这里执行）
for suite in fmt.suites {
    control.check()?;
    if !extract.allows_suite(suite.id) { continue; }
    if suite.cost() > extract.max_pbkdf2_iterations { continue; }
    ...
}
```

PNG 的 `extract_png` 签名是 `(carrier, password, domain, spatial, cost_model, params, control)`（`png/engine.rs:1682-1690`），没有 `ExtractParams`；HEVC 的 `extract_hevc` 同样没有；音频走 `derive_master(suite, secret, &salt)`，只受全局 `MAX_PBKDF2_ITERATIONS` 约束，不受调用方 `limits` 约束。

**为什么是问题：**

- 公开文档把 `ExtractParams` 描述为“KDF 工作上限/允许套件”的读侧策略（`params.rs:627-638`、`STEGO-API.md` §2.2），但 3/4 个载体域会静默忽略它。
- 一个自定义私有 profile 可以把 suite 的 `iterations` 设到 2,000,000（`format.rs:558` 允许上限），调用方即使设置 `with_max_pbkdf2_iterations(1000)` 也无法阻止 PNG/HEVC/音频执行这 200 万次 PBKDF2。
- `InspectOptions.limits` 是死字段：GUI/CLI 传入的 limits 在 `inspect` 路径完全无效。

**影响范围：** 所有需要“限制 KDF 成本/禁用套件”的服务端、GUI、批处理调用；DoS 防护只在 JPEG 生效。

**修复方向：**
- 把 `ExtractParams` 传入 `PngEngine::extract`、`HevcEngine::extract`、`WavEngine::extract`、`FlacEngine::extract`，在各引擎的 suite 循环中先检查 `allows_suite` 与 `cost() <= max_pbkdf2_iterations`，再调用 `derive_master`/`derive_hevc_key`。
- `InspectOptions.limits`/`VerifyOptions.limits` 同样传入 `inspect_*`/`verify_*`；若某引擎确实不支持，应在公开文档中删除该字段或标注“仅 JPEG”。
- 增加跨载体测试：对每种格式设置 `allowed_suites = Some(vec![])`，提取应快速返回 `NoHiddenData`/`UnsupportedVersion`，而不是继续跑 KDF。

### H-4 多个公开入口在合法输入下会 panic，release 构建 `panic = "abort"` 会终止宿主进程

**位置：**
- `rust/src/stego/hevc/engine.rs:202-210`（`pub fn superblock_positions` 内的 `assert!(pool_size >= HEVC_SUPERBLOCK_MIN_SLOTS)`）
- `rust/src/stego/hevc/engine.rs:764-769`（`pub fn apply_hevc_patches` 直接 `carrier[span.clone()].copy_from_slice(re_nal)`）
- `rust/src/stego/format.rs:304-308`（`default_suite()` 内 `.expect("a JpegFormatProfile must list at least one cipher suite")`）
- 调用点：`rust/src/stego/png/engine.rs:1292`、`rust/src/stego/audio/core.rs:546`
- 构建配置：`rust/Cargo.toml:155`（`[profile.release] panic = "abort"`）

**可复核行为：**

```rust
// hevc/engine.rs:202-204
pub fn superblock_positions(pool_size: usize) -> Vec<usize> {
    assert!(pool_size >= HEVC_SUPERBLOCK_MIN_SLOTS);
    ...
}

// hevc/engine.rs:764-769
pub fn apply_hevc_patches(carrier: &mut [u8], patches: &[HevcCarrierPatch]) {
    for (span, re_nal) in patches {
        carrier[span.clone()].copy_from_slice(re_nal);
    }
}

// format.rs:304-308
pub fn default_suite(&self) -> &'static CipherSuite {
    self.suite(DEFAULT_SUITE_ID)
        .or_else(|| self.suites.first())
        .expect("a JpegFormatProfile must list at least one cipher suite")
}
```

`apply_hevc_patches` 是公开 API，调用方可以传入空/越界 `Range<usize>` 或长度不等于 span 的 `re_nal`；`superblock_positions` 的 `assert!` 也是公开入口。`PngFormatProfile`/`AudioFormatProfile` 没有 `validate` 方法，因此一个 `suites: &[]` 的私有 profile 会在 PNG/音频 embed/probe 时通过 `default_suite()` 的 `expect` 直接 panic。

**为什么是问题：**

- `rust/Cargo.toml:155` 的独立 release profile 为 `panic = "abort"`：CLI 与直接使用该 crate 的宿主进程会直接被终止，库层没有 `catch_unwind` 机会；只有 GUI 在 `gui/src-tauri/Cargo.toml:32-33` 覆盖为 `panic = "unwind"`，Tauri 的 `catch_unwind`（`gui/src-tauri/src/state.rs:175-190`）才能捕获。
- 这些不是“内部不变量”，而是公开函数接受的参数问题，属于可误用 API。

**修复方向：**
- `apply_hevc_patches` 改为 `Result<(), StrHideError>`：检查 `span.end <= carrier.len()`、`re_nal.len() == span.len()`、span 不重叠/有序；失败返回 `CorruptedData`/`General`。
- `superblock_positions` 改为返回 `Result<Vec<usize>, StrHideError>`，或在调用方已保证 `pool_size` 时提供 `try_` 版本并保留内部 `debug_assert`。
- 为 `PngFormatProfile`/`AudioFormatProfile` 增加 `validate()`，至少检查 `body.suites` 非空、labels 非空、`hpos_salt/label` 非空；在所有公开入口先调用。`JpegFormatProfile::default_suite` 改为返回 `Result` 或由 `validate` 保证。

### H-5 `.bak` 备份路径的 check-then-create 竞态与符号链接风险

**位置：**
- `rust/src/core/commit.rs:110-137`（`next_backup_path`）
- `rust/src/core/commit.rs:154-163`（`copy_file_durable`）
- 调用点：`rust/src/structure/engine.rs:1386-1390`（write 原地备份）、`:2043-2048`（restore 原地备份）

**可复核行为：**

```rust
// commit.rs:117-136
let base = with_suffix(".bak");
if !base.exists() { return base; }
let candidate = with_suffix(&format!(".bak-{now}"));
if !candidate.exists() { return candidate; }
...
// commit.rs:155-159
let mut output = std::fs::File::create(dst)?;   // truncate + follow symlink
std::io::copy(&mut input, &mut output)?;
```

**为什么是问题：**

- `next_backup_path` 先检查 `exists()` 再返回路径，`copy_file_durable` 再用 `File::create` 打开；两个并发进程（或同一 GUI 的两个任务）可以同时通过存在性检查并选择同一个 `.bak` 路径，后写的进程会截断前一个备份。
- `File::create` 会跟随符号链接。若目标目录可被攻击者写，攻击者可以在 `.bak`/`.bak-<timestamp>` 位置放置符号链接，让备份写入覆盖任意文件（本地共享目录、CI 工作区、用户主目录场景）。
- 失败时（例如符号链接目标不可写）还会留下不完整的备份路径语义，调用方只看到 I/O 错误。

**影响范围：** 所有原地写入且 `backup=true` 的结构域操作；CLI 默认 `backup=true`（`WriteOptions::default`），因此普通用户路径也命中。

**修复方向：**
- 使用 `OpenOptions::new().write(true).create_new(true)`（Unix 再加 `O_NOFOLLOW`）打开备份；`AlreadyExists` 时重新生成随机后缀并重试，最多 N 次。
- 备份文件名加入进程 id + 128-bit 随机数（`temp_path_for` 已有类似实现），而不是仅 `now` 秒级时间戳。
- 在 `copy_file_durable` 内验证 `dst` 不是符号链接（`symlink_metadata`）。

---

## 5. 中严重级别问题

### M-1 `MIN_UBE_ENCRYPTED` 的容量边界比实际最小信封少 1 字节，`MIN_UBE_PLAIN` 命名/语义已失效

**位置：**
- `rust/src/structure/envelope.rs:88-96`
- `rust/src/structure/adapters/pe.rs:256-258`
- `rust/src/structure/adapters/pe_slack.rs:193`

**可复核行为：**

```rust
// envelope.rs:88-96
/// Smallest envelope the writer can currently produce with compact metadata,
/// an empty filename and a 1-byte payload:
/// `header 112 + meta 41 + payload 1 + trailer 24`.
pub const MIN_UBE_ENCRYPTED: u32 = 213;
pub const MIN_UBE_PLAIN: u32 = MIN_UBE_ENCRYPTED;
```

实际写入始终加密（`structure/engine.rs:1057`：`exact_meta_len = meta_raw.len() + AEAD_TAG_LEN`；`:1060`：`framed_len` 每块 20 字节开销）。因此：
- 空载荷：112 + (41+16) + (0+1×20) + 24 = **213**；
- 1 字节载荷：112 + (41+16) + (1+20) + 24 = **214**。

`pe.rs:256-258` 用 `cap >= MIN_UBE_ENCRYPTED` 判定 codebits 可用；`pe_slack.rs:193` 用 `MIN_UBE_PLAIN` 判定 envelope 可接受。一个容量恰好 213 的 PE 通道会被报告为可用，但 1 字节载荷写入需要 214，最终在 `write_core`/`pe_codebits` 阶段失败。

**影响：** PE `pe_codebits`/`pe_slack` 的容量探测与实际写入在 1 字节边界不一致；注释里的 178 字节计算也没有计入 AEAD tag/分块开销。

**修复方向：** 用 `crate::crypto::framed_len` 和 `encode_metadata` 的实际最小输出推导常量，并提供 `min_ube_len(payload_len)` 函数；为 0/1 字节载荷写回归测试。既然写侧始终加密，`MIN_UBE_PLAIN` 要么删除，要么明确表示“未来可能存在的未加密路径”。

### M-2 PDF 的 `find_last_eof` 无法识别 stealth/私有方言的 EOF overlay，导致 verify Level 1 误报损坏

**位置：**
- `rust/src/structure/adapters/pdf.rs:97-139`（`find_last_eof`）
- `rust/src/structure/envelope.rs:594-654`（`EnvelopeTrailer::unpack/read_from_tail`）
- 具体调用：`pdf.rs:108`（`read_from_tail(reader, None)`）

**可复核行为：**

```rust
// pdf.rs:108
let maybe_trailer = EnvelopeTrailer::read_from_tail(reader, None).ok().flatten();
// envelope.rs:615-618
let is_valid_magic = match expected_magic {
    Some(target) => &trailer_magic == target,
    None => trailer_magic == STANDARD_TRAILER_MAGIC,
};
```

`find_last_eof` 只尝试标准 trailer magic；stealth 模式（密码派生 trailer magic）和私有 `StructureProfile::magic` 的 EOF overlay 都不会被识别，`search_end` 退回 `file_size`。而 `MAX_SEARCH_DEPTH` 是 1 MiB，若 overlay 大于 1 MiB，真正的 `%%EOF` 不在窗口内，`parse_pdf_tail_info` 失败；`verify_core` Level 1（`structure/engine.rs:2406`）会把一个可正常读取的 stealth PDF 报成“Corrupted PDF structure”。

`locate_envelope` 的 EOF 回退（`pdf.rs:736-743`）不依赖 `find_last_eof`，所以 `read`/`restore` 仍可能工作，形成“read 成功、verify 报损坏”的不一致。

**修复方向：**
- `find_last_eof` 接收 `locator_magic`/密码派生 magic，或先读取文件末尾 24 字节做“任意 trailer magic + CRC + `ube_offset+ube_total_size==file_size`”检测，再据此收缩搜索窗口。
- 将 `MAX_SEARCH_DEPTH` 改为 `max(1 MiB, trailer.ube_total_size + 64 KiB)`（以实际 overlay 大小为准），并加 stealth/private profile 的 PDF EOF overlay 测试。

### M-3 `PngFormatProfile` / `AudioFormatProfile` 把通用密码层塞进 `JpegFormatProfile`，私有构建被迫填写 JPEG 几何

**位置：**
- `rust/src/stego/format.rs:432-456`（`PngFormatProfile { body: &'static JpegFormatProfile }`）
- `rust/src/stego/format.rs:458-479`（`AudioFormatProfile { body: &'static JpegFormatProfile }`）
- 实际只读取：`rust/src/stego/png/engine.rs:1292,1301`（`default_suite`、`body_keys`）
- 实际只读取：`rust/src/stego/audio/core.rs:546,551`（同上）
- `JpegFormatProfile::validate` 强制 `sb_bytes == 44`（`format.rs:334-339`）

**为什么是问题：**

- 一个音频私有方言必须实例化 `JpegFormatProfile` 并填写 `sb_bytes/sb_h/sb_u/ext_h/ext_u/grid_rule` 等 JPEG 专有字段；这些字段在音频引擎中从未读取。
- `JpegFormatProfile::validate` 的 `sb_bytes==44` 约束使“私有格式身份”名义上可配、实际上必须复制 JPEG 几何，增加下游误配/升级漂移风险。
- 该设计已在 `docs/lib_interface_audit_and_refactoring_plan_20261103.md` §2 中记录，但代码仍未重构。

**修复方向：** 抽出 `WireCipherProfile { format_major/minor, enc_label, perm_label, suites }`，让 `PngFormatProfile`/`AudioFormatProfile` 持有它；`JpegFormatProfile` 保留 JPEG 几何并组合 `WireCipherProfile`；`body_keys` 改为接收 `&WireCipherProfile`。

### M-4 `StegoProfile` 只有一个 `audio` 字段，WAV 与 FLAC 无法独立定制

**位置：**
- `rust/src/stego/params.rs:702-706`（`pub audio: Option<AudioFormatProfile>`）
- `rust/src/stego/params.rs:763-771`（`with_audio_format` 同时覆盖两者）
- `rust/src/stego/params.rs:815-836`（`flac_format` 返回 `OFFICIAL_FLAC_FORMAT`，`audio_format` 返回 `OFFICIAL_WAV_FORMAT`）

**为什么是问题：**

- `with_audio_format(x)` 会让 WAV 和 FLAC 都使用 `x`，无法只私有化其中一种；两种格式的 `hpos_salt`/`hpos_label` 本应独立（`format.rs:504-525`）。
- `audio_format()` 名称泛指，但在未配置时返回 WAV profile，容易误用。

**修复方向：** 拆成 `wav: Option<AudioFormatProfile>` 与 `flac: Option<AudioFormatProfile>`，提供 `with_wav_format`/`wav_format`、`with_flac_format`/`flac_format`；`with_audio_format` 作为同时设置两者的便捷方法保留。

### M-5 公共枚举/选项结构缺少 `#[non_exhaustive]`，且所有内部模块以 `pub mod` 暴露

**位置：**
- `rust/src/core/errors.rs:17-147`（`StrHideError`）、`:307-325`（`ErrorKind`）
- `rust/src/formats/sniff.rs:70-86`（`FileFormat`）
- `rust/src/stego/options.rs:450-471`（`EmbedOptions`）、`:811-823`（`ExtractOptions`）
- `rust/src/stego/params.rs:129-182`（`PngParams`）、`:318-399`（`JpegParams`）
- `rust/src/lib.rs:140-170`（`pub mod core/formats/structure/stego/analysis/cli`）
- `rust/src/structure/mod.rs:20-26`、`rust/src/stego/mod.rs:14-45`（内部子模块全部 `pub mod`）

**为什么是问题：**

- 下游对 `StrHideError`/`ErrorKind`/`FileFormat` 做穷尽 `match` 时，新增变体会导致编译失败；`EmbedOptions`/`ExtractOptions`/`PngParams`/`JpegParams` 的公开字段使下游结构体字面量在新增字段时同样编译失败。
- `ARCHITECTURE.md` §9 声称多个公开枚举/结构体已 `#[non_exhaustive]`，但上述类型实际没有该属性；文档与代码不一致。
- 内部模块（如 `stego::coding`、`stego::envelope`、`structure::adapters`）全部 `pub mod`，下游可以依赖内部细节，未来重构成本高。

**修复方向：**
- 对所有会增长的公共枚举/结构体加 `#[non_exhaustive]`（`StrHideError`、`ErrorKind`、`FileFormat`、`EmbedOptions`、`ExtractOptions`/`ProbeOptions`/`InspectOptions`/`VerifyOptions`、`PngParams`、`JpegParams` 等），并提供 setter/constructor。
- 内部模块改为 `pub(crate)`，或保留 `pub` 但明确 `#[doc(hidden)]` 与“无稳定性承诺”（`STEGO-API.md` 已有三层模型，建议在 `lib.rs` 与 `ARCHITECTURE.md` 对齐）。
- 增加一条 CI 检查：公开类型若新增变体需同时更新 `CHANGES` 与 semver 说明。

### M-6 JPEG 嵌入保持整图系数副本 + 允许 4 GiB 回溯位图，峰值内存可能 OOM

**位置：**
- `rust/src/stego/jpeg/engine.rs:713`（`let mut work = coeffs.clone();`）
- `rust/src/stego/params.rs:438-463`（`MAX_AUTO_BACKTRACK_BYTES: usize = 4 << 30`）
- `rust/src/stego/coding/stc.rs:629-631`（`let mut back = vec![0u64; n * words_per_col];`）

**可复核行为：**

```rust
// jpeg/engine.rs:713
let mut work = coeffs.clone();
// params.rs:453
pub const MAX_AUTO_BACKTRACK_BYTES: usize = 4 << 30; // 4 GiB
// stc.rs:630
let mut back = vec![0u64; n * words_per_col];
```

`coeffs` 在 `embed_jpeg_with_stats` 内仍被 `cover`/`costs` 引用，`work` 是完整副本；对 50 MP 图像，DCT 系数数组本身已很大，复制会接近翻倍。`MAX_AUTO_BACKTRACK_BYTES=4 GiB` 是自动预算的上限，`grouped_body_budget` 也允许 `MAX_GROUPED_BACKTRACK_BYTES=4 GiB`；在 GUI 多任务（capability `WholeFile`）并发时可能触发 OOM。

**影响：** 大图/高负载嵌入的峰值内存与并发稳定性；不是所有机器都适合默认 4 GiB 位图预算。

**修复方向：**
- 默认回溯预算降到可配置的 MB 级（例如 256–512 MiB），把 4 GiB 作为显式 opt-in；在 `StegoCapacityInfo`/`probe` 中报告预计峰值。
- 用“原系数 + 变更日志（applied deltas）”代替完整 `coeffs.clone()`，失败时按 `rollback` 恢复；当前 `rollback` 已经存在，可改为直接在 `coeffs` 上操作并回滚。
- 对 GUI 增加“大图独占执行”或按 `Formats::MemoryProfile` 限制并发（capability 已有 `WholeFile`，但 scheduler 只用于展示）。

### M-7 结构域写入/读取的峰值内存与 1 GiB 解压上限

**位置：**
- `rust/src/structure/engine.rs:952-974`（`compress_stream` 保留 raw + compressed 直到决策）
- `rust/src/structure/engine.rs:1127-1145`（`tmp_ube` + `to_encrypt_bytes` 同时存在）
- `rust/src/structure/engine.rs:1637-1661`（`decrypted_payload` + `decomp` 同时存在）
- `rust/src/core/crypto.rs:618-620`（`MAX_VERIFY_PAYLOAD_SIZE = 1 GiB`）
- `rust/src/structure/engine.rs:1647-1653`（`read_core` 只检查 `raw_size <= 1 GiB`，在完整解密后才检查）

**为什么是问题：**

- 写侧：`compress_stream` 先写 `compressed_buf`，若保留压缩则 `raw.clear()`；在决策前 raw+compressed 同时驻留（最坏 2x payload）。随后 `tmp_ube`（含密文）+ `to_encrypt_bytes`（明文）同时存在（约 2x payload + envelope）。大载荷（数百 MB～GB）容易 OOM。
- 读侧：`decrypt_stream_from_chunks` 先把整个解密载荷写入 `decrypted_payload`，然后 `decompress_stream` 再分配 `decomp`；两者同时存在。且 `raw_size` 上限 1 GiB 对无密码/公开默认密钥信封是可伪造的（攻击者可构造一个小载体声明 1 GiB raw_size），`read` 会实际解压到 1 GiB，构成资源耗尽向量。

**修复方向：**
- 写侧：压缩决策改为“先压缩到临时文件/可复用的 Vec，再决定保留哪一个”，或根据 `payload_raw_bytes.len()` 设置硬上限并提前拒绝。
- 读侧：改为流式“解密 -> 解压 -> SHA-256”单遍管线（`verify_l3_stream` 已有类似实现，可复用）；或在 `ReadOptions` 增加内存/解压上限（默认按载体大小的比例，如 `min(1 GiB, carrier*64)`）。
- 将 `MAX_VERIFY_PAYLOAD_SIZE` 从 `read_core` 的“解密后检查”前移到开始解密前（基于 `ube_total_size`/`meta.raw_size`）。

### M-8 `take_varint` 在 10 字节 LEB128 的最后一字节静默截断高位

**位置：**
- `rust/src/structure/engine.rs:177-194`（`take_varint`）
- `rust/src/structure/engine.rs:169-175`（`put_varint`）

**可复核行为：**

```rust
for _ in 0..10 {
    let byte = ...;
    value |= ((byte & 0x7f) as u64) << shift;   // shift 最大 63
    if byte & 0x80 == 0 { return Ok(value); }
    shift += 7;
}
```

第 10 个字节时 `shift=63`，`(byte & 0x7f) << 63` 只有最低位能保留；若攻击者构造 `0x7F` 作为第 10 字节，高 6 位被静默丢弃，解码得到一个错误但“合法”的 `raw_size`/`created_at`。`decode_compact` 不检查尾随字节，也不拒绝这种 overlong 编码。

**影响：** 紧凑元数据解析的确定性与协议严谨性；由于 `raw_size` 用于解压上限，错误值可能导致解压失败或错误的大小判断，但不会直接越界。

**修复方向：** 在 `take_varint` 中当 `shift >= 64` 或 `shift == 63 && byte & 0x7e != 0` 时返回 `CorruptedData("varint overflows u64")`；同时拒绝 10 字节但值小于 2^63 的非规范编码（可选）。补充 `u64::MAX`、`u64::MAX-1` 与 overlong 的单元测试。

### M-9 GUI 集成层：原地嵌入的 `check_overwrite` 与提取缓存键不完整

**位置：**
- `gui/src-tauri/src/commands/stego.rs:154-162`（`embed_stego_file_impl` 无条件 `check_overwrite(dest, req.overwrite)`，`dest` 默认是 `req.carrier`）
- `gui/src-tauri/src/commands/stego.rs:327-343`（`smart_extract_impl` 缓存键仅 `path + mtime + password`）

**可复核行为：**

```rust
// stego.rs:161-162
let dest = req.output_path.as_deref().unwrap_or(&req.carrier);
check_overwrite(dest, req.overwrite)?;   // 原地嵌入且 overwrite=false 时必然 AlreadyExists

// stego.rs:337-338
if c.path == path && c.mtime == mtime && c.password == password { ... }
```

**为什么是问题：**

- 结构域 `write_carrier_with` 只在 `target != carrier` 时调用 `check_overwrite`（`rust/src/structure/engine.rs:1315-1319`）；GUI 的无条件检查使“原地嵌入”在不勾选 overwrite 时必然失败，语义与 CLI/库不一致。
- `smart_extract` 的缓存键不包含 `domain` 与 `prefer`：同一路径/口令下，先用 `domain=A` 提取、再用 `domain=B` 提取会命中旧结果；`prefer` 影响“双域同时存在时选哪个域”，同样被缓存忽略。缓存也不包含载体内容哈希（仅 mtime），文件被外部修改且 mtime 未变时会返回旧载荷。

**修复方向：**
- GUI 只在 `req.output_path` 与 `req.carrier` 不同时调用 `check_overwrite`，或直接依赖 `FileTarget`/库内 `same_file` 逻辑；`FileTarget` 的 `overwrite` 语义应在 `embed_carrier_file` 内统一。
- 缓存键加入 `domain`、`prefer`、`Dialect`（若可变）与载体内容哈希（或 `(mtime, len)`），并在 `smart_extract` 入口校验。

---

## 6. 低严重级别问题

### L-1 文档与实现漂移（多处，建议集中修正）

| 文档位置 | 文档说法 | 实现事实 |
|---|---|---|
| `docs/api/ARCHITECTURE.md:3` | crate 0.8.3 | `rust/Cargo.toml:3` 为 0.8.5 |
| `docs/api/WIRE_SPEC.md:691-702` | HEVC 固定头部 40 字节：magic(4)+len(4)+crc(4)+nonce(12)+tag(16) | `rust/src/stego/hevc/engine.rs:98-105`：Superblock 32 字节（magic4+version/flags1+stc_u1+window_slices2+total_windows2+reserved2+payload_len4+crc4+nonce12）+ GCM tag 16 = 48；`DEFAULT_HEVC_FORMAT.header_bytes=48`（`format.rs:223`），测试断言 48（`engine.rs:3475`） |
| `docs/api/STEGO-API.md:106-115` | 示例 `header_bytes: 40` | 同上，默认 48 |
| `docs/api/STEGO-API.md:193-196` | PNG 的 `--p1-window/--p2-window` 不自描述，提取端必须重复 | `FeatureWord` 已携带 `p1_window/p2_window/epsilon/sigma/algorithm_id`（`stego/header.rs:138-159`），提取端从 feature word 恢复（`png/engine.rs:1805-1824`） |
| `rust/src/lib.rs:11-40` | 支持六种载体 | README 与 capability 表支持 PNG/JPEG/WebP/HEIF/MP4/MKV/WAV/FLAC/ZIP/PDF/PE/AnnexB 共 12 个 `FileFormat` |
| `rust/src/stego/mod.rs:277-291` | 内容域 `Payload` 的 kind/name “尚未上线，stage 3 再加 micro-header” | `stego/envelope.rs:368-425` 已实现 micro-header，name 会持久化；kind 不会 |
| `rust/src/structure/mod.rs:13-18` | `inspect` 有一个内容域容量例外 | 当前 `structure/` 已无 `crate::stego` 引用；import_lint 也证明无跨域 |
| `docs/smart_file_data_hiding_design.md:76`（UBE 字段表） | `strategy_id` 取值 1..9 | `STRATEGY_REGISTRY` 已到 13（`structure/registry.rs:90-104`） |
| `rust/src/stego/mod.rs:189-207` | 内容域支持格式只列 PNG/JPEG/HEIF/HEVC | 实际还支持 WAV/FLAC/MKV/MP4；错误消息会误导用户 |

**影响：** `WIRE_SPEC.md` 被文档明确称为“权威规范”，第三方实现按 40 字节头部读取会直接解析错位；p1/p2 的说法会让调用方做无意义的参数重复。建议把常量（头部尺寸、魔数、strategy id）改为“文档引用代码常量”或增加文档测试。

### L-2 `derive_hevc_key` / `trellis_seed_from_key` 在 HKDF 失败时返回全零密钥/种子

**位置：** `rust/src/stego/hevc/engine.rs:3300-3307`、`:3230-3238`

```rust
if hk.expand(fmt.kdf_info, &mut key).is_err() {
    return [0u8; 32];
}
```

HKDF-Expand 对 32 字节输出在当前参数下不会失败，但返回零密钥是“fail-open”：若未来 `kdf_info`/hash 长度变化导致失败，所有用户会用同一个全零 AES 密钥，而不是报错。

**修复方向：** 改为 `Result<[u8; 32], StrHideError>` 并向上传播；或 `debug_assert!(false)` + `unreachable!()` 并在 `#[cold]` 分支返回错误。`trellis_seed_from_key` 同理（返回 0 会让槽位选择退化）。

### L-3 `find_iend_offset` 对畸形 chunk 静默 `break`，与 2026-11-03 变更日志的“硬性拒绝”描述不一致

**位置：** `rust/src/structure/adapters/png.rs:64-83`

```rust
if length > PNG_MAX_CHUNK_LEN { break; }
let Some(chunk_total_len) = length.checked_add(12) else { break; };
let Some(next_pos) = pos.checked_add(chunk_total_len) else { break; };
if next_pos > total_size { break; }
```

变更日志（`docs/CHANGES-20261103.md:10-12`）称“遇到畸形长度、越界截断或非标准 Chunk 时即刻报错拒绝”，但代码在畸形长度/越界时只是停止扫描；如果之前已经遇到一个合法 `IEND`，函数会返回该 IEND 并把后续畸形数据当 dirty tail 接受。若没有合法 IEND，才返回 `CorruptedData`。这不会造成越界（后续解析有边界检查），但与“严格拒绝畸形文件”的承诺不符，可能让“合法 IEND + 截断 chunk 尾部”的文件通过。

**修复方向：** 明确区分“IEND 之后的 dirty tail”（允许）与“IEND 之前的畸形 chunk”（拒绝）；在 `break` 处记录 `malformed` 标志，若 `last_iend` 不存在或畸形发生在 IEND 之前则返回错误。补充畸形 chunk 测试。

### L-4 若干小 API/语义问题

| 编号 | 位置 | 问题 | 建议 |
|---|---|---|---|
| L-4.1 | `rust/src/stego/params.rs:42-47` | `StegoCodec::id()` 返回 0/1，而线格式 `header::codec_header_id` 返回 0..3（`stego/header.rs:46-51`）；同名 `id` 语义不同 | 将 `StegoCodec::id()` 改为 `wire_id(stc_u)` 或标记 `#[deprecated]`；统一由 `header` 模块负责线格式 id |
| L-4.2 | `rust/src/stego/hevc/engine.rs:713-718` | `available_slots: total_slots` 包含 32B Superblock，而文档（`stego/mod.rs:335-339`）说“available_slots 是扣除 header 后的槽位” | 改为 `total_slots.saturating_sub(HEVC_SUPERBLOCK_MIN_SLOTS)`，或把字段改名为 `total_slots` |
| L-4.3 | `rust/src/stego/mod.rs:92-101` | `compute_default_threads` 文档说“minimum 4”，实现 `(total/2).max(4).min(total)` 在 total=1/2/3 时返回 1/2/3 | 修正文档或改为 `total.min(4)` 语义 |
| L-4.4 | `rust/src/structure/engine.rs:1397-1400`、`:2053-2054` | `set_permissions`/`set_file_times` 用 `let _ =` 静默忽略失败；权限/时间戳承诺可能未兑现 | 记录 `log::warn!` 或返回结构性 warning；至少在 `WriteResult.warnings` 中暴露 |
| L-4.5 | `rust/src/stego/io.rs:45-48` | `embed_carrier_file` 在 `output_path=Some(carrier)` 时仍 `check_overwrite`，与结构域 `same_file` 逻辑不一致 | 使用 `same_file(dest, carrier_path)` 跳过检查，或把 overwrite 判断下沉到 `FileTarget` |
| L-4.6 | `rust/src/stego/engine.rs:189-207` | 错误消息只列 PNG/JPEG/HEIF/HEVC，遗漏 WAV/FLAC/MKV/MP4 | 从 `supported_formats()` 动态生成消息 |

---

## 7. 分维度展开

### 7.1 架构设计与模块分层

- **通过项**：`import_lint.py` 三项红线全部通过；`structure` 不引用 `stego`，`stego` 不引用 `structure`，`core` 不引用上层。`analysis` 只依赖 `structure`/`formats`，符合第四层定位。
- **耦合问题**：`PngFormatProfile.body`/`AudioFormatProfile.body` 复用 `JpegFormatProfile`（M-3）；`StegoProfile` 单 `audio` 字段（M-4）。
- **公共面问题**：所有模块 `pub mod`、公共枚举/结构缺少 `#[non_exhaustive]`（M-5）；文档声称“内部模块可见但无稳定性承诺”，但类型上没有可执行的约束。
- **重复抽象**：`PayloadSource` 与 `core::Payload` 两套载荷模型（结构域/内容域各一）没有 `From` 转换；这是已知审计项，建议在发布前统一。

### 7.2 库接口与函数/参数设计

- **可误用性**：`apply_hevc_patches`、`superblock_positions`、`default_suite().expect`（H-4）；`ExtractParams` 仅 JPEG（H-3）；`StegoCodec::id()` 与线格式 id 不一致（L-4.1）。
- **类型与错误契约**：`StrHideError`/`ErrorKind` 未 `non_exhaustive`（M-5）；`derive_hevc_key` 失败返回零密钥（L-2）；`MIN_UBE_*` 常量注释与实际不符（M-1）。
- **可选参数/API 一致性**：`FileTarget`/`overwrite` 在结构域、内容域、GUI 三处语义不同（H-2 相关、M-9、L-4.5）；`SmartExtractOptions::PartialEq` 忽略 `pool`（`facade.rs:205-213`），会让测试/缓存比较出现意外。
- **语义模糊处**：`encode_micro_header` 的 `PayloadKind::Text` 不写 tag，而 `Payload::text` 与 `Payload::bytes` 在提取端都变成 `PayloadKind::Bytes`；`core/payload.rs:13-39` 已说明“kind 不往返”，但 `stego/mod.rs:277-291` 仍写成“尚未上线”，需统一。

### 7.3 代码质量

- **重复代码**：`stego::mod.rs` 三个入口共享引擎注册表后已明显收敛；`structure::engine` 的 `write_core`/`read_core` 分层合理。
- **过长函数**：`write_core`（约 450 行）、`embed_hevc_patches_with_factor`（约 300 行）、`embed_png_with_stats`（约 300 行）、`extract_hevc_from_sb_record` 等仍偏长；建议按阶段拆成 `prepare/encrypt/inject/verify` 子函数，降低状态变量密度（`write_core` 当前有 20+ 局部变量）。
- **隐式假设**：`write_core` 的 `expect("every registered adapter maps to a FileFormat")`、`expect("the selected strategy comes from STRATEGY_REGISTRY")` 依赖注册表与适配器永不失配（`structure/engine.rs:1281-1284`）；当前成立，但新增策略时容易漏改。
- **unsafe**：`stc.rs` 与 `juniward.rs` 的 AVX2 入口都有 `is_x86_feature_detected` 保护与边界注释；未发现可确证 UB。`stc.rs:655` 的 `accumulate_xor_avx2` 依赖 `states` 为 4 的倍数、`bits` 长度 `states.div_ceil(64)`，当前调用满足。
- **panic/unwrap**：生产路径的 `expect` 主要在 `write_core` 的两个注册表断言、`jpeg/engine.rs:749` 的 `last_error.expect`、`hevc/engine.rs` 的 `assert!`；前两者在当前不变量下安全，但应改为 `Result` 或 `debug_assert` 以便未来演进。
- **日志与错误信息**：`StrHideError::General` 大量直接英文句子，i18n 只翻译类别前缀；这是有意的（`errors.rs:338-341` 说明 engine 文本不翻译），但 CLI 用户看到中英文混排。可接受，建议在 `ErrorDetail` 中逐步迁移可本地化 detail 的类别。

### 7.4 算法与性能

- **复杂度**：PNG HILL/S-UNIWARD 代价图为整图 `f64`，JPEG UERD 为整图 `f64` + DCT 系数；均与像素/块数线性，符合算法要求。
- **内存拷贝**：JPEG `coeffs.clone()`（M-6）；结构域 `raw+compressed+tmp_ube`（M-7）；PNG `header_pool`/`ranked`/`candidates` 多份 `Vec<usize>`（大图时每份 ~8 bytes/像素），可通过 `Vec::with_capacity` + 复用降低。
- **并行效率**：Rayon 按行/块切分，代价模型内部有 FMA/AVX2；`with_pool` 只在入口 `install`，嵌套并行时 Rayon 会复用当前 pool，设计合理。`compute_default_threads` 取 `(cores/2).max(4)` 对 2 核机器会超配（返回 2，不超；文档表述错误），对 4 核返回 4 而非 2，实际是“至少 4 线程”，与注释“maximum half”不完全一致（L-4.3）。
- **算法参数**：JPEG 自动 slot budget 以 `body_slots/4` 为默认，`MAX_AUTO_BACKTRACK_BYTES=4 GiB` 偏大；PNG `PngParams.exclusion_percentile` 默认 0.30、`stc_h` 8，均与文档一致。HEVC `SafetyLevel::video_budget` 的 `ref_flips_per_picture` 与 WIRE_SPEC §13.11.7 的 110/220/450 一致（`core/params.rs:313-329`）。

### 7.5 可靠性/稳定性

- **边界条件**：多数解析函数使用 `checked_add`/`saturating_add`，`strhide` 的“拒绝优先”总体到位；仍需关注 M-1（容量边界）、M-8（varint）、L-3（PNG 畸形 chunk）。
- **资源泄漏**：`TmpGuard`、`commit_carrier_patches` 的临时文件 guard、`copy_file_durable` 的 fsync 都正确；`next_backup_path` 的竞态是例外（H-5）。
- **并发竞态**：`GuiState` 的 `tasks`/`extract_cache` 使用 `Mutex`，但 `ThrottledChannelProgress` 的 `channel.send` 失败被忽略（GUI 关闭时可能丢事件，可接受）；`extract_cache` 的键不完整（M-9）。
- **超时**：没有操作级超时；KDF 成本控制是唯一相关旋钮，但只在 JPEG 生效（H-3）。
- **破坏性写入**：弱格式嗅探（H-2）、`.bak` 符号链接（H-5）、`set_permissions` 静默失败（L-4.4）是主要风险点。

### 7.6 算法与业务逻辑正确性

- **格式保持/可逆性**：结构域 `write_core` 的 UBE 尺寸预算、`verify_restored` 的 size+SHA-256 校验、`RestoreMismatch` 的 residual envelope 诊断都实现到位；`pe_slack` 的“先验证全零再写入”也正确。
- **容量/载荷边界**：`MIN_UBE_ENCRYPTED`（M-1）；HEVC `available_slots`（L-4.2）；JPEG `BODY_OVERHEAD=21` 与 `build_plaintext`/`unpack_envelope_parts` 的 4+1+1+16 一致（`stego/envelope.rs:76-83`），未发现偏差。
- **KDF/认证流程**：结构域 AEAD AAD、chunk nonce 域分离、metadata nonce 0xFFFFFFFF、trailer CRC mask 均与 WIRE_SPEC 一致；内容域 JPEG/PNG 的 superblock/feature word 作为 AAD 的设计正确。HEVC KDF 的工作因子缺失（S-1）是唯一严重偏差。
- **协议一致性**：HEVC 头部尺寸/字段顺序（L-1）、PNG p1/p2 自描述（L-1）、strategy id 范围（L-1）是主要漂移点。

---

## 8. 优先修复建议（按投入产出排序）

| 优先级 | 修复项 | 预期投入 | 收益 |
|---|---|---|---|
| **P0** | S-1：HEVC 增加 PBKDF2（或明确威胁模型） | 中（协议需升版本/兼容策略） | 消除最严重的口令强度不一致 |
| **P0** | H-1：PNG/音频头部种子改为 PBKDF2/固定 salt | 小-中 | 关闭廉价口令 oracle，保持头部可定位 |
| **P1** | H-2：JPEG/MP4 检测加严格结构校验，写前 `verify_structure` | 小 | 防止非载体文件被追加数据，符合“格式保持”承诺 |
| **P1** | H-3：`ExtractParams` 贯穿 PNG/HEVC/音频/Inspect | 小-中 | 让公开 API 的 KDF 上限真正生效 |
| **P1** | H-4：公开 panic 入口改 `Result`；profile 加 `validate` | 小 | 让 `panic = "abort"` 构建下的库调用更安全 |
| **P1** | H-5：备份文件 `create_new` + 随机后缀 | 小 | 消除并发覆盖/符号链接写入 |
| **P2** | M-1：`MIN_UBE_*` 由 `framed_len`/`encode_metadata` 推导 | 小 | 容量探测与写入边界一致 |
| **P2** | M-2：PDF `find_last_eof` 支持 stealth/私有 trailer | 小-中 | verify 不再误报 stealth PDF |
| **P2** | M-3/M-4：抽 `WireCipherProfile`，拆 WAV/FLAC profile | 中 | 公共 API 解耦，私有构建更安全 |
| **P2** | M-5：公共类型 `#[non_exhaustive]`，内部模块收窄 | 小-中 | 降低下游破坏性升级风险 |
| **P2** | M-6/M-7：JPEG 原地修改 + 降低回溯预算；结构域流式化 | 中 | 降低 OOM 与并发失败 |
| **P2** | M-8/M-9/L-1～L-4：varint、GUI 缓存、文档/小 API 修正 | 小 | 提升确定性与可维护性 |

**建议的落地顺序：** S-1/H-1（安全）→ H-2/H-3/H-4/H-5（公共契约与破坏性写入）→ M-1/M-2（协议边界）→ M-3/M-4/M-5（API 结构）→ M-6/M-7（内存）→ 文档与小问题。

---

## 9. 审查覆盖、未覆盖与待验证项

### 9.1 已重点核对

- 结构域：`structure/engine.rs` 的 write/read/remove/inspect/verify、`envelope.rs`、`crypto.rs`、`commit.rs`、`rejection.rs`、`registry.rs`、`adapters/{png,jpeg,zip,pdf,pe,pe_slack,isobmff,wav,webp,mkv,ebml,riff,eof}.rs`。
- 内容域：`stego/engine.rs`、`options.rs`、`params.rs`、`envelope.rs`、`header.rs`、`format.rs`、`registry.rs`、`io.rs`、`png/engine.rs`、`jpeg/engine.rs`、`v3_layout.rs`、`coding/stc.rs`、`audio/core.rs`、`hevc/engine.rs`、`heif/thumb_bridge.rs`。
- CLI：`cli/{args,helpers,cmd_structure,cmd_stego,cmd_diag,render}.rs` 的关键路径；`core/{config,pipeline,control,payload,media,fs}.rs`。
- GUI 集成：`gui/src-tauri/src/{state,commands/stego}.rs`。

### 9.2 未覆盖/未执行

- 未执行完整 `cargo test --all-features --all-targets`、`local_`/`heavy_` 测试与 `cargo clippy`；本报告不声称测试全绿。
- 未逐行审查 `analysis.rs` 的全部统计算法与 `gui` 前端 TypeScript；`analysis` 只核对了错误处理与 `unwrap` 位置（生产路径未发现明显 panic）。
- 未做运行时性能剖析；性能结论基于代码结构（clone、整图 Vec、位图上限），非实测。

### 9.3 待验证/推测

| 项 | 说明 |
|---|---|
| H-1 的量化可利用性 | “错误口令通过 FeatureWord/Header 结构校验”的误报率未实测；机制已确证，但建议用真实 PNG/WAV/FLAC 统计误报率 |
| S-1 的实际攻击成本 | 取决于用户口令熵与攻击者是否知道 `cover_digest`（参数集公开，通常可知）；未做 GPU/CPU 基准 |
| H-5 的符号链接攻击 | 需要攻击者对目标目录有写权限；机制已确证（`File::create` 跟随符号链接），实际风险取决于部署目录权限 |
| M-7 的 1 GiB 解压 DoS | 需要攻击者能构造无密码/公开默认密钥的合法信封；机制已确证，实际影响取决于服务端是否接受不可信载体 |
| M-9 的 GUI 缓存 | 代码层面已确认键不含 `domain`/`prefer`；未跑 GUI 复现，标注为集成层问题 |

---

## 10. 附录：关键代码/文档索引

- 结构域安全写入与还原：[`rust/src/structure/engine.rs:770-1292`](file:///c:/Home/Projects/strhide/rust/src/structure/engine.rs#L770-L1292)、[`rust/src/structure/engine.rs:1629-2066`](file:///c:/Home/Projects/strhide/rust/src/structure/engine.rs#L1629-L2066)
- UBE 线格式：[`rust/src/structure/envelope.rs:98-270`](file:///c:/Home/Projects/strhide/rust/src/structure/envelope.rs#L98-L270)
- 结构域密码学：[`rust/src/core/crypto.rs:113-233`](file:///c:/Home/Projects/strhide/rust/src/core/crypto.rs#L113-L233)、[`rust/src/core/crypto.rs:311-523`](file:///c:/Home/Projects/strhide/rust/src/core/crypto.rs#L311-L523)
- 内容域信封/微头：[`rust/src/stego/envelope.rs:368-579`](file:///c:/Home/Projects/strhide/rust/src/stego/envelope.rs#L368-L579)
- PNG 引擎：[`rust/src/stego/png/engine.rs:1026-1076`](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1026-L1076)、[`rust/src/stego/png/engine.rs:1258-1350`](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1258-L1350)、[`rust/src/stego/png/engine.rs:1682-1870`](file:///c:/Home/Projects/strhide/rust/src/stego/png/engine.rs#L1682-L1870)
- JPEG 引擎：[`rust/src/stego/jpeg/engine.rs:612-750`](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L612-L750)、[`rust/src/stego/jpeg/engine.rs:1130-1268`](file:///c:/Home/Projects/strhide/rust/src/stego/jpeg/engine.rs#L1130-L1268)
- HEVC 引擎：[`rust/src/stego/hevc/engine.rs:98-186`](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L98-L186)、[`rust/src/stego/hevc/engine.rs:1562-1696`](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L1562-L1696)、[`rust/src/stego/hevc/engine.rs:3228-3308`](file:///c:/Home/Projects/strhide/rust/src/stego/hevc/engine.rs#L3228-L3308)
- STC 求解器：[`rust/src/stego/coding/stc.rs:515-800`](file:///c:/Home/Projects/strhide/rust/src/stego/coding/stc.rs#L515-L800)
- 文档基线：[`docs/api/WIRE_SPEC.md:691-731`](file:///c:/Home/Projects/strhide/docs/api/WIRE_SPEC.md#L691-L731)、[`docs/api/STEGO-API.md:106-196`](file:///c:/Home/Projects/strhide/docs/api/STEGO-API.md#L106-L196)、[`docs/api/ARCHITECTURE.md:1-120`](file:///c:/Home/Projects/strhide/docs/api/ARCHITECTURE.md#L1-L120)

---

**结论重述：** 当前实现的功能完整度与工程化程度较高，但安全模型（HEVC/PNG/音频 KDF）、格式识别与公开 API 的 panic/契约问题在发布前应优先处理；其中 HEVC 的 KDF 设计建议作为发布阻断项（release blocker）。
