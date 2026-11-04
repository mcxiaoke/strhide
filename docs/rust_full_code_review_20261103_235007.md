# strhide `rust/` 全量代码审查报告

> **审查基准**：commit `a1b9467e5a9ac7e09c9e649b86c497f55537d71b`（2026-11-03 23:14:21 +0800，"fix(stego): close the V4 review findings and add the file-key CLI"），工作树干净。
> **审查时间**：2026-11-03 23:03 — 23:50（GMT+8）
> **审查范围**：`rust/src/**/*.rs`（120 个文件 / 70,511 行）、`rust/Cargo.toml`、`rust/build.rs`、`rust/tests/`、`rust/examples/`、`scripts/import_lint.py`、`scripts/baseline_hash.py`
> **审查维度**：代码质量、算法实现、接口与参数、算法效率、可靠性健壮性、功能缺陷、架构设计
> **证据标准**：主表（第 3 章）每条问题均给出 `文件:行号`。标注 `已确认` 的条目附有**逐字原文代码片段**并已回到当前工作树逐条核对；标注 `分组审查提供` 的少数条目由分组深审给出、本次未逐行复核，其验证方向统一列入第 7 章。无法取得任何证据的一律不写入主表。
> **与已有报告的关系**：`docs/stego_content_envelope_v4_review_20261103.md` 与 `..._independent_20261103.md` 是针对 V4 内容信封重构（commit `dfc69f95`）的专项审查，其 Blocking/Major 发现绝大多数已在上述 HEAD 提交中修复（详见 `docs/CHANGES-20261103.md` 23:06:16 条目）。本报告是**修复后状态的全模块横向审查**，不重复列出已修复项；第 6 章单列已剔除的重复/误报。

---

## 0. 执行摘要

### 0.1 总体结论

`rust/` 是一个约 7 万行、双域（结构域容器注入 + 内容域自适应隐写）并行的 Rust 库，工程质量明显高于同类项目：分层克制、注释中保留了大量历史 review 编号与修复理由、密码学构造（PBKDF2→HKDF 三级派生、AEAD AAD、chunk 自描述帧、解压炸弹上限）成体系、945 个 `#[test]`、字节级基线、架构边界脚本、STC 编解码有穷举 oracle 对照。**全部质量门禁在本次审查中实测通过**（见 1.2）。

但门禁全绿不等于没有缺陷：测试主要覆盖「正常路径 + 小载体」，而本项目的风险集中在**跨模块契约**与**不可信输入边界**。本次审查确认的主要系统性风险有三条：

1. **认证边界不完整**：结构域信封的 AEAD AAD 只有 80 字节，header 后 32 字节、trailer 全字段、hint 明文均无密码学完整性；其中 `ube_total_size` 还可被放大成超大分配。这是唯一可被无条件构造输入触发的 P0 链路。
2. **跨端不变量被破坏**：FLAC 把「随嵌入操作本身改变的残差可用性」当成了 embed/extract 共享的槽位选择分母，与该文件自己的注释直接冲突，可造成 embed 成功但 payload 永久不可读。
3. **同一职责存在多套口径**：probe / inspect / verify / embed 在 JPEG 块数、HEVC `has_inter`、音频 STC `u`、安全阈值上各自计算，导致「容量报告」与「实际可嵌入」可能不一致；这类不一致不会触发测试失败，却直接损害 API 可信度。

### 0.2 问题分级统计

| 级别 | 定义 | 条数 | 主表编号 |
| :--- | :--- | :--- | :--- |
| P0 致命 | 可造成数据永久丢失、无条件可触发的完整性/可用性破坏 | 3 | P0-1 ~ P0-3 |
| P1 高 | 明确功能缺陷、安全边界缺口、跨端结论不一致 | 10 | P1-1 ~ P1-10 |
| P2 中 | 特定输入/配置下出错、效率热点、错误语义与文档偏离 | 20 | P2-1 ~ P2-20 |
| P3 低 | 理论触发、文档/命名不一致、技术债、防御性缺口 | 13 | P3-1 ~ P3-13 |
| 待实测 | 分组审查提出、本次未逐行复核代码证据 | 22 | 第 7 章 W-1 ~ W-22 |

### 0.3 最高优先级的五件事

1. 修 FLAC 槽位选择的跨端不变量（P0-1），补「embed→extract 往返 + 补偿链被改写」回归用例。
2. 把结构域信封的 112 字节 header 全文 + trailer + hint 纳入认证，并在所有 adapter `locate` 统一 `ube_offset + ube_total_size == 文件物理结束` 等式（P0-2、P0-3）。
3. 统一 probe / embed / inspect / verify 的「一份载体只有一份池视图」（P1-1 ~ P1-4）。
4. 补齐 PNG 读入端 CRC / 结构约束校验、并行 deflate 大图路径的端到端测试（P1-9、P2-1）。
5. 修正 CLI 配置三态与凭据/明文输出处理（P2-12 ~ P2-15）。

---

## 1. 审查基准、方法与实证

### 1.1 基准稳定性说明（重要）

审查于 23:03 开始时对 `rust/src` 的首次统计为 120 文件 / 70,484 行；审查过程中项目在 **23:14:21 提交了一次 V4 审查修复**（`a1b9467e`，48 个文件），期间 `rust/src/stego/jpeg/header_v3.rs` 被重命名为 `header_v4.rs`。因此：

- 首次目录快照中的 `header_v3.rs` 与后续 `ls` 中的 `header_v4.rs` 是同一文件的重命名，不是代码缺陷（第 6 章列为误报剔除项）；
- 本报告所有行号、代码片段均以 **HEAD `a1b9467e` 之后的当前工作树**（120 文件 / 70,511 行）为准；
- 分组审查中若出现「V4 审查已修复」的发现，第 6 章逐条标注状态，不作为现存缺陷。

### 1.2 实跑门禁结果（全部本次重新执行）

| 检查 | 命令 | 结果 |
| :--- | :--- | :--- |
| 格式化 | `cargo fmt --check` | 0 diff |
| 静态检查 | `cargo clippy --all-targets --all-features -- -D warnings` | 0 warning（`Finished dev profile ... in 5.03s`） |
| 全量测试 | `cargo test --all-features --all-targets` | 全绿；lib 482 passed / 1 ignored；test_cli 132、test_lifecycle 143、test_media 12、test_pe 40、test_regression 101、test_security 18；heavy 5 ignored、local 2 passed / 18 ignored（合计 928 passed / 24 ignored） |
| 架构边界 | `python scripts/import_lint.py` | `OK: all architectural boundaries intact (structure !-> stego, stego !-> structure, core !-> {formats, structure, stego, cli})` |
| 字节基线 | `python scripts/baseline_hash.py --check` | `check OK: 28 cases identical to baseline` |

### 1.3 静态指标（含测试代码，仅作分布参考）

| 指标 | 计数 | 说明 |
| :--- | :--- | :--- |
| `#[test]` / `#[ignore]` | 945 / 24 | 测试密度高；heavy/local 压力测试按 ignore 门控 |
| `.unwrap()` / `.expect()` | 390 / 306 | 大量位于 `#[cfg(test)]`；生产路径的主要 panic 面在第 3 章逐条列出 |
| `panic!` / `unreachable!` / `todo!` | 32 | 多为不可达分支守卫 |
| `unsafe` | 12 | 集中在 SIMD / 位操作，未见跨线程裸指针共享 |
| TODO / FIXME / HACK | 1 | 注释纪律好 |
| 算术索引 `\[i + n\]` | 129 | 需结合边界校验判断，多数位于已校验的解码循环 |

### 1.4 审查方法

1. **分组深审**：按 `core+facade+cli+formats+analysis` / `stego 核心与编码` / `PNG+JPEG 引擎` / `HEVC+HEIF` / `Audio+analysis` / `structure 域` 分 6 组，3 组并发、两轮完成，每组要求「文件:行号 + 原文片段 + 影响 + 方案」，禁止臆测。
2. **交叉复核**：对分组输出的全部「致命/高」及主要「中」条目逐条回源码 `Read` 核对；对相互矛盾的结论（如 audio `body_len` 窗口、Feistel 双射、`--cipher-suite` 校验、文件名是否存在）做独立判定。
3. **误报剔除**：证伪 6 项（第 6 章），降级 3 项（理论触发 / 设计取舍）。
4. **实证门禁**：1.2 全量实跑，避免把「测试通过」当成「无缺陷」的证据。

### 1.5 局限性与诚实声明

- 未做真实恶意样本/畸形容器的 fuzz 实测；第 7 章 22 条明确标注「需构造输入验证」。
- 未跑 release 构建、性能基准、外部解码器（ffmpeg / libpng / mkvmerge）兼容性矩阵。
- 未审查上游 vendor 源码（`F:\Develop\github\strhide-vendor`）与 `gui/`；`dct_io`、`rusty_h265`、`oxideav-h265` 的行为按本项目调用点推断。
- 报告中的 Windows 权限讨论按 Windows ACL 语义表述，未照搬 Unix `0644/umask` 论述。
- 本项目尚未发布（见 `AGENTS.md`），故多数修复方案不要求兼容旧文件，但**凡涉及 wire/AAD/派生的改动仍必须重建 `temp/baseline` 与 golden vectors**。

---

## 2. 分维度总体评价

### 2.1 代码质量

注释密度与「为什么」信息量很高，历史修复编号（review R2/R3/P1-x）可追溯；`clippy -D warnings`、`fmt`、`import_lint` 三重门禁全绿；重复真源问题仍有残留（策略 ID 硬编码、三套 block_count、两份 Authenticode 检测）。主要短板是**文档与实现漂移**：`structure/mod.rs` 仍声称存在 `structure → stego` 例外而代码已无此依赖；`extract_carrier_payload` 文档称 kind/name 不在 wire 上，而 micro-header 早已实现；`estimated_change_rate` 文档以 Hamming 为默认，实际 `Auto` 恒为 STC。这类漂移不会触发测试，却会误导调用方。

### 2.2 算法实现

STC（`coding/stc.rs`）是本库最扎实的模块：网格方向、DECIDE/TWO_WAY、位图回溯、分组码 `u>1`、三元 ±1、穷举 oracle 与 roundtrip 约束测试自洽，本次未发现确凿编解码错误。HILL / S-UNIWARD / MiPOD / UERD / J-UNIWARD / J-MiPOD 的数学实现有详细注释与单测；偏离文献处（UERD 变体）作者在模块文档中自述，但**对外 registry 描述未同步**（P2-6）。跨端一致性是主要风险：FLAC 槽位选择不变量（P0-1）、JPEG/HEVC/音频容量口径（P1-1~P1-4）、`MAX_PLAINTEXT_LEN` 与 `BODY_OVERHEAD` 的单位差（P2-9）。

### 2.3 接口与参数

`EmbedOptions`/`ExtractOptions`/`ProbeOptions`/`StegoTuning`/`SafetyPolicy` 字段多但缺省值合理；问题集中在**同一配置在不同入口的表达能力不同**：`ProbeOptions` 无 `suite_id`/`freshness`/`domain`/`extensions`（P2-11），`inspect_jpeg` 拿不到 `ExtractParams`（P1-1），byte 级公共入口仍是位置参数而文件级已用 Options（P3-10）。CLI 与 config 的布尔合并多为「只能关、不能开」的单向表达式（P2-12）。

### 2.4 算法效率

热点明确且可修：HILL stage-2 低通是 O(p1²) 逐像素重算（P2-16）；音频 cost 每槽重读 33 个样本并构造 4 份全量缓冲（W-14）；PNG 只读路径也复制整文件（W-13）；HEVC embed 同时持有输入、输出全量拷贝、每 slice 完整 RBSP 与 ops journal（P2-17）；单次 `write` 对 host 重复全文件扫描 6 次（W-17）；JPEG 多 APP15 段 `locate` 回溯是 O(n²)（W-18）。这些都是 4K/8K、长音频、GB 级载体下的实际瓶颈。

### 2.5 可靠性健壮性

容器解析大量使用 `checked_add` / `try_from` / `get()`，解压炸弹有 `take(expected+1)` 与 1 GiB `MAX_VERIFY_PAYLOAD_SIZE` 双保险，fail-closed 总体到位。缺口在「最后一公里」：未认证长度字段直接进 `vec![0u8; n]`（P0-2）；`let _ =` 吞掉权限/时间戳/seek 恢复失败（P2-14、P3-11）；`panic = "abort"` 与 `TmpGuard` 的 Drop 清理承诺冲突（P3-8）；`Err(_)` 吞掉取消信号（P1-8、W-8）。

### 2.6 功能缺陷

已确认的功能缺陷集中在跨入口一致性而非单点崩溃：`SpatialAlgorithm::Custom` 任何 embed 都失败（P2-5）；`inspect_jpeg` 与 `extract_jpeg` 对同一 carrier 可得相反结论（P1-1）；MKV CRC 刷新只挂在上层分派，HEVC 层公开 API 产出不可解码容器（P1-7）；FLAC 在非首块 STREAMINFO 上把 MD5 写错位置（P1-5）。

### 2.7 架构设计

分层方向正确且由 `import_lint.py` 强制（structure ↔ stego 互不引用，core 不反向依赖），两个域通过 `facade` 汇聚，注册表/策略 ID 基本单一真源。残留问题：责任上移（MKV CRC、HEIF bridge mode 门禁放在分派层而非引擎层）、同一解析逻辑在四个容器各写一份（VCL NAL 过滤、hvcC 参数集过滤、NAL 长度前缀解析）、`pub` 面过大（`apply_hevc_patches`、`write_bytes_atomic`、`verify_payload_stream` 等把内部不变量暴露给外部调用方）。

---

## 3. 已确认问题清单

> 格式说明：每条含「维度 / 位置 / 状态」；状态 `已确认` = 代码路径可直接推出，`已确认·触发需实测` = 缺陷路径成立但需构造特定输入触发。代码片段均为当前工作树逐字引用。

### P0 致命

#### P0-1 FLAC 把随嵌入变化的 `usable` 用作跨端一致的槽位选择分母，embed 成功但 extract 永久失败

- 维度：算法实现 / 功能缺陷 / 可靠性
- 位置：`rust/src/stego/audio/flac/mod.rs:198-204`、`:239-243`、`:454-469`
- 状态：已确认（触发率需实测，见 W-1）

`flac/mod.rs:198-204` 的字段契约明确禁止该用法：

```rust
    /// Of those, how many can actually move in at least one direction.
    ///
    /// Only the capacity report uses this -- it must never take part in slot
    /// selection, because the compensation chain is computed from residuals
    /// that the embedding itself rewrites, and the reader derives the plan from
    /// the stego file alone.
    pub usable: usize,
```

但 `:239-243` 的 `analyse` 用依赖残差当前值的 `slot_legality_raw` 统计 `usable`：

```rust
        usable += parsed
            .slots
            .iter()
            .filter(|slot| !matches!(slot_legality_raw(slot, &parsed), Move::None))
            .count();
```

而 `:454-469` 的 body 槽位枚举同时用它做 membership 过滤与 `thin_pick` 的 `range`：

```rust
                    if matches!(slot_legality_raw(slot, &parsed), Move::None) {
                        continue;
                    }
                    let index = body_seen;
                    body_seen += 1;
                    if thin_pick(index, total_usable, body_slots, body_phase)
                        && let Some(entry) = make_slot(slot, &parsed, &scale)
                    {
                        body_picks.push(entry);
                    }
```

**分析**：`slot_legality_raw` 经补偿链 `Compensation::accepts` 依赖 comp 残差当前值；`apply` 会写入非零补偿 delta 改写这些值。`analyse` 在 embed 时读 cover、在 extract 时读 stego，因此 `Move::None` 集合与 `total_usable` 都可能改变，选出的 body 槽位整体错位，AEAD tag 校验失败，payload 永久不可提取。order=0 帧补偿链为空、`accepts` 恒真，故现有 FIXED order 2/3 合成帧用例未必覆盖。

**影响**：任何写入非零补偿 delta 且使 `accepts` 判定翻转的 FIXED/LPC 帧；表现为「密钥正确却 `NoHiddenData`」，且写入已落盘。

**解决方案**：body membership 与 `thin_pick` 的 range 改用纯结构量 `analysis.slots`（`collect_slots` 的同 bucket 稳定计数）；`slot_legality_raw` 只保留给 `move_legality` 决定方向；`FlacCarrier::new` 与 `extract_flac` 的容量上界同步改用 `analysis.slots`。补回归用例：构造 order>0 且补偿 delta 非空的 FLAC，断言 embed 前后 `analysis.slots` 不变、`usable` 可变但槽位集合一致，并做完整往返。

---

#### P0-2 结构域信封认证边界缺口：header 后 32 字节 / trailer / hint 未认证，`ube_total_size` 可放大为超大分配

- 维度：安全性 / 可靠性 / 架构设计
- 位置：`rust/src/structure/envelope.rs:98-105`、`:272-295`；`rust/src/structure/engine.rs:1598`、`:2352-2358`；`rust/src/structure/adapters/pe.rs:440-449`、`mkv.rs:113-139`、`isobmff.rs:129-146`
- 状态：已确认·触发需实测（构造伪造 trailer 的 PE/MKV）

`envelope.rs:100-105` 与 `:273-284` 说明 AAD 只有前 80 字节：

```rust
/// The first 80 bytes are exactly the AAD ([`Self::get_aad`]) bound into the
/// AEAD seals of both the metadata block and every payload chunk — tampering
/// with any of them breaks authentication. The trailing 32 bytes
/// (`inject_offset` / `inject_size` / `patch_offset` / `orig_patch_val` /
/// `meta_len` / `hint_len`) are stored after injection because the injector
```

```rust
    pub fn get_aad(&self) -> [u8; AAD_SIZE] {
        let mut aad = [0u8; AAD_SIZE];   // AAD_SIZE = 80
        aad[0..8].copy_from_slice(&self.magic_header);
        ...
        aad[48..80].copy_from_slice(&self.orig_host_sha256);
        aad
    }
```

`engine.rs:2356-2358` 的注释已自认 `inject_size` 在 AAD 之外：

```rust
    // `inject_size == 0`: the size field is inside the header but outside the
    // AEAD's AAD, so accepting a zero there let anyone flip it in a contiguous
    // strategy (`eof`, `chunk`, `box_uuid`) and skip Level 2 entirely.
    if crate::structure::registry::id_to_strategy(header.strategy_id) == "pe_codebits" {
```

而 `engine.rs:1598` 直接用未认证的 `meta_len` 分配：

```rust
    let mut meta_bytes = vec![0u8; header.meta_len as usize];
    ube_stream.read_exact(&mut meta_bytes)?;
```

**分析**：trailer 的 `ube_offset`/`ube_total_size` 仅有 CRC32（非 MAC，可重算）；`pe.rs:440-449` 的 overlay 分支只检查 `ube_offset >= pe_image_end`，`mkv.rs:113-130` 的 `ebml_void` 分支也只按 vint 前缀匹配，**都没有** `ube_offset + ube_total_size == file_size` 等式；对照 `isobmff.rs:129-146` 已专门修过同类攻击（注释即铁证）：

```rust
    // `ube_total_size` is attacker-controlled: the trailer is just 24 bytes at
    // the end of the file and the box header in front of it is equally
    // forgeable. Without this bound a 204-byte MP4 could declare a 1 TiB
    // envelope, and the 112-byte header it "contains" could claim a ~4 GiB
    // metadata block that `read` allocates before discovering the stream is
```

**影响**：几百字节的伪造 PE/MKV 即可在 `read`/`inspect`/`verify` 触发数 GiB 分配（Rust 分配失败为 abort），无需密码；`verify_core` Level 2 的坐标校验变成「用未认证字段校验未认证字段」；trailer/hint/meta_len 均可被篡改而 AEAD 仍通过。

**解决方案**（按优先级）：
1. 所有 adapter `locate` 统一前置 `min_envelope = HEADER_SIZE + TRAILER_SIZE` 下界与 `trailer.ube_offset.checked_add(trailer.ube_total_size) == Some(物理结束位置)` 等式，直接复用 `isobmff.rs` 的实现。
2. `engine.rs:1598` / hint 读取前，用「文件实际长度 − ube_offset」钳制 `meta_len`/`hint_len`，并改 `try_reserve` 以便失败可返回错误。
3. AAD 扩为完整 112 字节 header + trailer + `hint_len` + hint 字节；或单独对 trailer/hint 做带密钥 MAC。坐标校验改由认证字段驱动，删除 `engine.rs:2493` 附近把 `inject_offset` 称为 authenticated 的错误注释。
4. 改 wire/AAD 后必须 `baseline_hash.py --write` 重建 28 例基线与所有 golden vectors。

---

#### P0-3 非 stealth 加密信封的 header 后 32 字节既不 mask 也不认证；hint 明文不受 AAD 保护

- 维度：安全性 / 功能缺陷
- 位置：`rust/src/structure/engine.rs:1006-1013`、`:1128-1131`；`rust/src/structure/envelope.rs:287-295`
- 状态：已确认

```rust
    // The mask only applies when the keying secret is the profile default
    // (no user password) or when stealth mode uses the user password. A
    // non-stealth encrypted header is *not* masked: the AEAD authenticates it.
    let header_mask = if !has_custom_password || stealth {
        Some(secrets.header_mask)
    } else {
        None
    };
```

```rust
    tmp_ube.extend_from_slice(&header.pack_masked(header_mask.as_ref()));
    if !hint_bytes.is_empty() {
        tmp_ube.extend_from_slice(&hint_bytes);
    }
    tmp_ube.extend_from_slice(&meta_block);
```

**分析**：注释称「AEAD authenticates it」，但 `get_aad()` 仅覆盖 0..80；`pack()` 的 80..112 是 `inject_offset`/`inject_size`/`patch_offset`/`orig_patch_val`/`meta_len`/`hint_len`。加密 + 有密码 + 非 stealth 时这 32 字节完全裸奔。hint 位于 header 之后、加密 meta 之前，是纯明文且不进 AAD，只要 `hint_len` 不变，改动 hint 不影响任何偏移与 tag。

**影响**：`inspect`/`read` 展示的 password hint 可被任意篡改（社会工程、终端控制序列，见 P2-15）；定位元数据可被改写以绕过 Level 2；与 P0-2 叠加形成完整伪造链。

**解决方案**：加密模式也必须 mask 或认证后 32 字节；hint 纳入 AAD（或移入加密 meta 块）；`verify` 的 Level 2 与 `read` 统一以认证字段为准。改 AAD 需同步重建基线。

---

### P1 高

#### P1-1 `inspect_jpeg` 不做 header 策略校验，`extract_jpeg` 做：同一 carrier 两个 API 结论相反

- 维度：接口与参数 / 功能缺陷
- 位置：`rust/src/stego/jpeg/engine.rs:1403-1411`、`:1294-1300`
- 状态：已确认

```rust
pub fn inspect_jpeg(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &JpegFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
```

对照 extract 路径：

```rust
    let suite = CipherSuiteId::from_u16(superblock.suite_id).ok_or_else(no_hidden)?;
    if !extract.allows_suite(superblock.suite_id) {
        return Err(no_hidden());
    }
    extract
        .validate_header(superblock.suite_id, superblock.body_len, hdr_n, n_total)
        .map_err(|_| no_hidden())?;
```

**分析**：`inspect_jpeg` 签名没有 `&ExtractParams`，因此不执行 `l1_allowed` / `validate_header` / `allows_suite`，只查版本、CRC 与扩展区就置 `has_hidden_data: true`；PNG 侧 `inspect_png_with_keys` 反而调用了 `limits.validate_header(...)`。收紧 `max_payload_bytes` / `allowed_suites` / `max_pbkdf2_iterations` 后，inspect 报「有密」、extract 返回 `NoHiddenData`，且 inspect 永远先付 200k 次 PBKDF2。`verify_jpeg` Level 2 复用了这个宽松 inspect。

**解决方案**：给 `inspect_jpeg` / `inspect_jpeg_from` 增加 `&ExtractParams`，在 `has_hidden_data = true` 前执行与 extract 完全相同的 `l1_allowed` + `allows_suite` + `validate_header`；把三处校验抽成 `fn header_is_readable(...)` 供 inspect/extract/verify 共用，杜绝再次漂移。

---

#### P1-2 JPEG 容量 probe 的 `block_count` 与 embed 实际槽数来源不一致

- 维度：接口与参数 / 算法实现
- 位置：`rust/src/stego/jpeg/engine.rs:1747-1749`、`:222-224`
- 状态：已确认（特定尺寸/DNL 触发需实测，见 W-2）

```rust
    let geom = crate::stego::jpeg::geometry::component_geometry(info, 0, 0);
    let block_count = geom.grid_w * geom.grid_h;
    let n_total = block_count * fmt.grid_rule.slots_per_block();
```

而 embed 的 `CoverFrame::read`：

```rust
    fn read(fmt: &JpegFormatProfile, coeffs: &JpegCoefficients) -> Self {
        let block_count = coeffs.components[0].blocks.len();
        let n_total = block_count * fmt.grid_rule.slots_per_block();
```

**分析**：probe 用 `info.width/height` 推导的 padded 网格，embed 用 `dct_io` 实际解出的块数；分组审查还发现 `preflight_jpeg` 用第三套 `info.components[].block_count`。SOF 尺寸与 MCU 填充不一致、DNL 覆盖高度、`info.height = 0` 时三者分歧，`available_slots` / `max_raw_payload_bytes` / `tier_limits` 与真实可写槽位不同，probe 甚至会报「carrier grid has 0」。

**解决方案**：`build_jpeg_capacity_info` 改为接收调用方传入的 `block_count`，embed 与 probe 统一传 `coeffs.components[0].blocks.len()`；删除 probe 内按几何推块数的路径；补 DNL / 非 16 倍数尺寸的 probe-vs-embed 一致性测试。

---

#### P1-3 HEVC 流式 inspect 与内存 embed 的 `has_inter` 判定口径分裂

- 维度：算法实现 / 功能缺陷
- 位置：`rust/src/stego/hevc/engine.rs:2515-2529`、`:3414-3420`
- 状态：已确认·触发需实测（4K/8K 样本，见 W-3）

流式路径（CLI 对 MP4 的入口 `inspect_carrier_file` 走此分支）：

```rust
    // Detect if this MP4 stream contains inter-coded frames (P/B). When has_inter is true,
    // IDR/IRAP frames are excluded from the superblock pool to protect prediction stability.
    let mut has_inter = false;
    for &(sample_offset, sample_size) in &target.samples {
        if sample_size < target.length_size + 2 || sample_offset + sample_size > file_len {
            continue;
        }
```

内存路径（embed / probe / 内存 inspect）：

```rust
    let has_inter = candidates.iter().any(|c| !is_irap(c.nal_type));

    let (pictures, band_pictures) = if capture == Capture::Bits {
        (1, [1, 0])
    } else {
        count_pictures(carrier, kind, &candidates, has_inter)
    };
```

**分析**：流式只看每个样本前 `HAS_INTER_PREFIX_BYTES = 1 MiB`，遇到跨边界 NAL 直接放弃；内存路径用全量 `slice_spans`。`has_inter` 决定 `picture_band` 分带，进而决定 `slice_slot_ranges` / `get_body_slot_indices` / `superblock_positions`——两边结论不同则同一 carrier 的 header/body 槽位整体错位，embed 写出的载体被流式 inspect 判为「无密」。`Capture::Bits` 还把 `pictures/band_pictures` 硬编码为 `(1, [1,0])`，与 embed/probe 的真实统计不一致。

**解决方案**：删除 `HAS_INTER_PREFIX_BYTES` 启发式，流式入口复用 `parse_mp4_targets` / `record_carrier_state` 的全量 `has_inter`；三个 capture 级别统一调用 `count_pictures`；补「同一 MP4 分别走流式 inspect 与内存 embed，槽位集合一致」契约测试。

---

#### P1-4 音频 probe 用 `u=1` 计价 `max_raw_payload_bytes`，比 embed 实际使用的 `u` 高估约 2–3 倍

- 维度：接口与参数 / 算法实现
- 位置：`rust/src/stego/audio/core.rs:988-1002`（对照 embed 侧 `:609-612`、`:694`）
- 状态：已确认

```rust
    // Advertise the codec the embedder would pick for a payload that fills the
    // tier: `u` falls as the payload grows, and so does the change rate.
    let (codec, u) = auto_select_codec(available, available.max(1));
    let u = u.max(carrier.min_group());
    let h = DEFAULT_STC_H;
    Ok(capacity_info(
        total,
        header_slots,
        carrier.format_label(),
        level,
        h,
        u,
```

embed 侧（`core.rs:609-612`）用的是真实密文位数：

```rust
    let bits = ciphertext_len.saturating_mul(8);
    let (codec, u) = auto_select_codec(available, bits.max(1));
    let u = u.max(min_u);
    let body_slots = body_slots(bits, codec, h, u)?;
```

**分析**：这里把 `needed_bits` 取成 `available`（相当于 r=1），`auto_select_codec` 必然返回 `u=1`；而 embed 用真实 `bits = ciphertext_len*8`，r 常 ≥2.5 → `u=2/3`。容量折算按 `slots/u` 计算，于是 `u=1` 的上限是实际可装量的 2–3 倍。调用方按 `max_raw_payload_bytes` 选 payload 时，embed 会在 `needed_slots > available` 处拒绝。现有 `audio/tests.rs` 只取 `min(2_000)`，未覆盖该窗口。

**解决方案**：`capacity_info` 内用与 embed 相同的固定点求 `u`（并对三次迭代的振荡做收敛检测，见 W-6）；补「按报告上限 embed 必须成功」的回归测试，对 PNG/JPEG/HEVC/WAV/FLAC 五个引擎各来一条。

---

#### P1-5 FLAC 的 `MD5_OFFSET` 硬编码 26，但解析允许 STREAMINFO 不在首块

- 维度：功能缺陷 / 可靠性
- 位置：`rust/src/stego/audio/flac/mod.rs:60-61`、`:576-578`
- 状态：已确认·触发需实测

```rust
/// Offset of the MD5 field inside the file: `fLaC` + block header + 18 bytes.
const MD5_OFFSET: usize = 8 + 18;
```

```rust
        if MD5_OFFSET + 16 <= self.bytes.len() {
            self.bytes[MD5_OFFSET..MD5_OFFSET + 16].copy_from_slice(&md5);
        }
```

**分析**：`parse_stream_info` 的循环允许 `block_type == 0` 出现在任意 metadata block 位置，但 FLAC 规范强制 STREAMINFO 为首个 block，且写回固定使用偏移 26。畸形但可解析的 FLAC 会把新 MD5 写进第一个 block 的 payload，而真正的 STREAMINFO MD5 未更新；`flac -t` 报损坏，`FlacCarrier::new` 的 `pcm_md5 != info.md5` 校验失败，形成 embed 成功 extract 失败。

**解决方案**：解析时校验 `pos == 4` 且 `block_type == 0`，否则 `CorruptedData`；把 `md5_offset` 作为 `StreamInfo` 字段由解析位置计算，写回前复核该处仍是 STREAMINFO。补非首块 STREAMINFO 的拒绝用例。

---

#### P1-6 release 构建跳过 patch 后带 CRC 的整体复核，debug/release 行为不一致

- 维度：可靠性 / 功能缺陷
- 位置：`rust/src/stego/audio/flac/mod.rs:580-592`
- 状态：已确认

```rust
        // Under debug assertions, verify with full recheck. In release builds,
        // avoid redundant whole-file decoding because frame CRCs and STREAMINFO MD5
        // were just computed and verified from the exact same decoded samples.
        #[cfg(debug_assertions)]
        {
            let recheck = analyse(self.bytes, &self.info)?;
            if recheck.pcm_md5 != md5 {
```

**分析**：`refresh_checksums` 用 `parse_frame_trusted`（`verify_crc = false`）重新解码 patched 文件，再从这些样本计算 CRC-16/MD5 写回；若 patch 使帧解析失步，错误样本产出的校验值自洽。注释「verified from the exact same decoded samples」是循环论证，release 下没有任何带 CRC 的复核，可能产出「能解码但音频已损坏」的 carrier。

**解决方案**：release 也执行一次带 `verify_crc = true` 的 `analyse`（可接受一次额外全量解码，或只对 touched 帧复核）；将该检查移出 `#[cfg(debug_assertions)]`，并补一条「人为制造帧失步 → 必须报错」的测试。

---

#### P1-7 MKV CRC-32 刷新只挂在上层分派，HEVC 层公开 API 产出不可解码容器

- 维度：架构设计 / 功能缺陷
- 位置：`rust/src/stego/engine.rs:948-952`；`rust/src/stego/hevc/engine.rs:1022-1027`
- 状态：已确认

上层唯一调用点：

```rust
        // A Matroska muxer writes a CRC-32 over every element it finalises;
        // the patch invalidates any that covers a modified block.
        crate::stego::hevc::mkv_boxes::refresh_mkv_crcs(carrier, &mut bytes).map_err(|e| {
            StrHideError::CorruptedData(format!("MKV checksum refresh failed: {e}"))
        })?;
```

而 HEVC 层公开导出的 `embed_hevc_with_info_v4` 自行组装输出：

```rust
    let (patches, capacity_info, stats) = embed_hevc_patches_v4(
        carrier, payload, cred, domain, suite_id, extensions, fmt, freshness, safety, control,
    )?;
    let mut out_carrier = carrier.to_vec();
    apply_hevc_patches(&mut out_carrier, &patches);
    Ok((out_carrier, capacity_info, stats))
```

**分析**：CABAC 翻转改的是 Cluster 内 block 字节，Matroska 的 CRC-32 元素覆盖这些字节；`mkv_boxes.rs` 注释明确说留旧 CRC 会被 `mkvmerge`/`ffmpeg` 拒绝。但刷新责任放在 `MkvEngine::embed`，任何直接调用 HEVC 层 `pub` API 或 patches 流式路径处理 MKV 的调用方都拿到不可解码容器。

**解决方案**：把 `refresh_mkv_crcs` 下沉到 `embed_hevc_with_info_v4` / `embed_hevc_patches_v4` 内部，按 `HevcCarrierKind::MkvContainer` 分派；或让 `HevcCarrierPatch` 结构携带「附带 CRC 补丁」并在 `apply_hevc_patches` 统一应用。上层不再重复调用。补一条「直接调用 HEVC 层 API 处理 MKV 后用 CRC 验证工具校验」的测试。

---

#### P1-8 `Err(_)` 吞掉取消 / 凭据 / IO 错误并静默改走另一套引擎

- 维度：可靠性 / 接口与参数
- 位置：`rust/src/stego/engine.rs:534-537`
- 状态：已确认

```rust
    match with_pool(opts.pool.as_ref(), direct) {
        Ok(payload) => Ok(payload),
        #[cfg(feature = "content-heif-bridge")]
        Err(_) => {
            // The bridge reads the same V4 envelope, so it needs the same
            // credential, domain and extension area the writer used. Dropping
```

**分析**：`with_pool` 会把 `Control::Cancelled`、`password` 与 `key` 互斥、容器解析失败等全部吞掉，改为尝试 thumbnail bridge，最终返回 bridge 的 `NoHiddenData` / 「no bridgeable item」，真实原因被掩盖；用户取消操作被伪装成「文件没有隐写数据」。`hevc_embed` 仅对 `SafetyThreshold` 与 `HevcMode::Cabac` 网开一面。

**解决方案**：只把明确的「此载体不是 Scheme C」错误（`NoHiddenData` / 指定的 `UnsupportedFormat`）映射为 bridge 回退；其余（`Cancelled`、`General`、IO、`SafetyThreshold`）原样 `Err(e)` 透传。抽一个 `fn should_try_bridge(&StrHideError) -> bool` 单一真源，embed/probe/extract/inspect/verify 共用。

---

#### P1-9 PNG 读入端完全不校验 chunk CRC，写出端 `data.len() as u32` 无溢出检查

- 维度：可靠性 / 功能缺陷
- 位置：`rust/src/stego/png/engine.rs:165-176`、`:270`、`:902-911`
- 状态：已确认

```rust
        let body = &data[body_start..body_end];
        match ty {
            b"IHDR" => {
                if len < 13 {
                    return Err(StrHideError::CorruptedData("Truncated IHDR".into()));
```

```rust
        pos = body_end + 4; // Skip CRC
```

```rust
fn write_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);

    let mut crc = Crc32::new();
```

**分析**：解码端把 4 字节 CRC 直接跳过、从不验证；`Crc32` 在 `decode_png` 里只用于写出。损坏/篡改 chunk 被当作合法载体接受，而 `png_pre_salt` 把 `chunk.ty/chunk.data` 混入 KDF salt，CRC 错误的载体会派生出另一套 locator key，embed 后输出「CRC 被悄悄修复但身份已变」的文件；标准解码器会拒绝该输入。写出端 `as u32` 对 >4 GiB chunk 静默截断，长度字段与实际字节数不符。此外 IHDR 只查 `len < 13`，未查 `len == 13`、必须首块、compression/filter 必须为 0。

**解决方案**：`decode_png` 在 `:270` 前读 `&data[body_end..body_end+4]` 并比对 `crc32fast::hash(ty || body)`，不符返回 `CorruptedData`；补 IHDR 结构约束（首块、长度恰 13、`body[10]|body[11] == 0`、type 字符合法）；`write_chunk` 返回 `Result`，用 `u32::try_from(data.len())`；给单 chunk 长度设上限（如 256 MiB）。写出大小变化需更新 `baseline`。

---

#### P1-10 输出与凭据处理：payload 直出终端、解出明文写临时文件用默认 ACL、密码经 argv

- 维度：安全性 / 可靠性
- 位置：`rust/src/cli/cmd_structure.rs:404-409`；`rust/src/core/commit.rs:283-298`、`:189-196`；`rust/src/cli/args.rs:305-306` 与 `helpers.rs:94-108`
- 状态：已确认

payload 直出（旁边 `render.rs` 对 password hint 却专门做了 `escape_control_chars`）：

```rust
    } else if args.stdout || !res.is_file {
        if let Ok(text) = std::str::from_utf8(&res.data) {
            print!("{text}");
        } else {
            std::io::stdout().write_all(&res.data)?;
        }
```

临时文件创建与权限恢复：

```rust
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    rename_with_retry(&tmp_path, path)?;
```

```rust
    let _ = std::fs::set_permissions(target_path, orig_permissions);
    if preserve_time {
        let _ = filetime::set_file_times(target_path, orig_atime, orig_mtime);
    }
```

**分析**：`write_bytes_atomic` 是 `pub`，被大量「写出解密后明文 payload」的路径直接调用，临时文件以进程默认 ACL 创建、rename 后不继承原载体 ACL；`set_permissions` 失败被 `let _ =` 吞掉，调用者拿到 `Ok` 却不知道权限/时间戳未恢复。payload 未做控制字符转义，恶意 carrier 可注入 `ESC[` / OSC 52。`-p/--password` 把秘密放进 argv，`--encrypt` 实际只触发密码提示（`helpers.rs:94-108`），无密码时返回 `None` 并使用公开的 `BUILTIN_DEFAULT_KEY`，与「加密」字面语义相反。

**解决方案**：所有面向终端的 payload 分支统一经过 `core::fs::escape_control_chars`；`write_bytes_atomic` 在 rename 前按目标已有 ACL 或 `0o600` 语义收紧，并把 `set_permissions`/`set_file_times` 失败作为结构化 `Warning` 返回；CLI 弱化 `-p`（打印醒目告警、主推 `--password-file` / `STRHIDE_PASSWORD` / TTY 提示）；把 `--encrypt` 重命名为 `--require-password`，或保留但在无密码时输出「仅混淆、无保密性」告警。

---

### P2 中

#### P2-1 PNG 大图并行 deflate 拼接与压缩级别估计模型不一致，且该分支未被单元测试覆盖

- 维度：算法效率 / 可靠性
- 位置：`rust/src/stego/png/engine.rs:412`、`:494`、`:567-605`（对照 `:863` 的 `deflate_len`）
- 状态：已确认·输出可解析性需实测（W-4）

```rust
const MAX_DEFLATE_WORKERS: usize = 8;
const MIN_PARALLEL_SCANLINE_BYTES: usize = 2 * 1024 * 1024;
```

```rust
    if filtered.len() < MIN_PARALLEL_SCANLINE_BYTES || height < num_threads {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
        encoder.write_all(filtered)?;
        return encoder.finish().map_err(Into::into);
    }
    ...
    let compressed_chunks: Result<Vec<Vec<u8>>, StrHideError> = chunk_ranges
        .into_par_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let is_last = i + 1 == n;
            compress_raw_deflate_chunk(chunk, level, is_last)
        })
        .collect();
```

**分析**：`choose_deflate_level` 用单流 `ZlibEncoder` 估计 IDAT 长度选 level，但 ≥2 MiB 且高 ≥8 行时实际走 8 个独立 `Compress` 实例 + Sync 拼接流，每段独立 Huffman 表/字典并额外携带 sync marker，压缩率与单流不同 → 大图 IDAT 可能显著膨胀。现有单测夹具最大 192×192（约 147 KiB），均走单流分支。

**解决方案**：补 `filtered > 2 MiB` 的 embed → 标准解码器（png crate / zlib）roundtrip 测试并记录 `compressed_idat.len()` 与 `orig_len` 的 delta；`choose_deflate_level` 改用与并行路径相同的分段模型，或并行路径改为「单流压缩后按 `idat_sizes` 切分」。

#### P2-2 `encode_png` 只在首个 IDAT 占位写出全部 pieces，IDAT 数量/位置不保真

- 维度：功能缺陷 / 可靠性
- 位置：`rust/src/stego/png/engine.rs:717-725`、`:743-751`
- 状态：已确认（输出合法性需实测，见 W-4）

```rust
    let mut pieces: Vec<&[u8]> = Vec::new();
    if image.idat_sizes.is_empty() {
        pieces.push(&compressed_idat[..]);
    } else {
        let mut off = 0usize;
        for (i, &sz) in image.idat_sizes.iter().enumerate() {
            if off >= compressed_idat.len() {
                break;
            }
```

```rust
    for chunk in &image.chunks {
        if &chunk.ty == b"IDAT" {
            if !idat_written {
                idat_written = true;
                for piece in &pieces {
                    write_chunk(&mut out, b"IDAT", piece);
                }
            }
            continue;
        }
```

**分析**：`pieces` 按原始 `idat_sizes` 切分新压缩流，流变短时提前 break 导致 `pieces.len() < idat_sizes.len()`；回放时只在第一个 IDAT 占位写出所有 pieces，其余占位 `continue` 跳过 → IDAT chunk 数减少。若原 IDAT 之间夹有 ancillary chunk，所有 IDAT 数据被搬到首位，ancillary 落到 IDAT 之后，产生非法 chunk 顺序，与 `:628-635` 的「chunk sequence preserved」注释不符。

**解决方案**：每个 IDAT 占位各输出一个 piece，保证数量与位置一致（空 piece 写空 IDAT 或按 `idat_sizes` 精确对齐）；`decode_png` 拒绝 IDAT 不连续的输入；补多 IDAT + 中间 ancillary 的往返用例。

#### P2-3 PNG 结构约束校验不足（IHDR 位置/长度、PLTE/tRNS 组合、IEND 后 tail 无上限）

- 维度：可靠性 / 代码质量
- 位置：`rust/src/stego/png/engine.rs:180-193`、`:254-270`、`:769`
- 状态：已确认（细节见 W-4）

```rust
    // Producer-appended trailer (signature, vendor index, ...) goes back after
    // IEND exactly where it was found.
    out.extend_from_slice(&image.tail);
```

**分析**：`len < 13` 放过 `len > 13`（见 P1-9 片段）；未要求 IHDR 为首块、未校验 `body[10]/[11]` 为 0；`encode_png` 按 `chunks` 原序回放，输入 IHDR 不在首位则输出也不在首位；IEND 之后的所有字节存为 `tail` 并无长度/内容约束地原样追加。

**解决方案**：`decode_png` 补齐 PNG 规范约束并按 color_type 校验 PLTE/tRNS 合法组合；给 `tail` 设上限（如 64 KiB）或仅白名单已知 vendor trailer。

#### P2-4 `SpatialAlgorithm::Custom` 是空承诺：任何 embed 都失败，且没有「注册 wire id」的接口

- 维度：接口与参数 / 功能缺陷
- 位置：`rust/src/stego/options.rs:74-77`；`rust/src/stego/png/registry.rs:38-45`；`rust/src/stego/png/engine.rs:1542-1549`
- 状态：已确认

```rust
    /// A caller-supplied model. The engine treats it exactly like a built-in
    /// one, but a carrier written with it can only be read back by a build that
    /// registers the same model under a wire id.
    Custom(Arc<dyn PngCostModel>),
```

```rust
pub fn spatial_wire_id(name: &str) -> Option<u8> {
    match name {
        "hill" => Some(SPATIAL_ALGORITHM_HILL),
        "suniward" => Some(SPATIAL_ALGORITHM_SUNIWARD),
        "mipod" => Some(SPATIAL_ALGORITHM_MIPOD),
        _ => None,
    }
}
```

```rust
    let algorithm_id = crate::stego::png::registry::spatial_wire_id(cost_model.id()).ok_or_else(
        || {
            StrHideError::General(format!(
                "PNG cost model '{}' has no wire id; a carrier written with it could not be extracted",
                cost_model.id()
            ))
        },
    )?;
```

**分析**：wire id 是静态 match，`SpatialHeaderV4::decode` 只接受 1..=3，`spatial_model_from_wire_id` 同样走静态表，整个 crate 没有「注册自定义 id」的接口。`Custom` 变体的文档承诺无法实现；`JpegAlgorithm::Custom` 因 JPEG 不写 model id 反而可用，形成不对称。

**解决方案**：删除 `Custom` 变体；或提供真正的注册表（动态分配 wire id + `spatial_model_from_wire_id` 查表 + decode 允许扩展 id 段）并同步修正注释。

#### P2-5 UERD 对外描述为标准实现，模块文档却自认是显著偏离的变体

- 维度：代码质量 / 接口与参数
- 位置：`rust/src/stego/jpeg/registry.rs:33-36`（对照 `rust/src/stego/jpeg/cost/uerd.rs:10-16`）
- 状态：已确认

```rust
        (
            "uerd",
            "JPEG (JPG)",
            "Uniform Embedding Revisited Distortion model (Guo et al., IEEE TIFS 2015)",
        ),
```

**分析**：`uerd.rs` 模块文档列出三处与 Guo et al. 2015 的刻意偏离（Q¹ 而非 Q²、缺少 D=1.5、8 邻域平均），并声明「claims fidelity to the idea, not the arithmetic」；`description()` 也标注 deviates。但 `list()` / `list_stego_algorithms()` / options 文档都写成标准 UERD，CLI/能力表用户据此判断文献符合性会被误导。

**解决方案**：统一改为「UERD-inspired variant (Q¹, 8-neighbour average; deviates from Guo et al. 2015)」，并在 `StegoAlgorithmInfo.desc` 注明未经检测评估对齐。

#### P2-6 默认无 domain 的密码路径完全丢弃 `cipher.domain_label`，与私有方言文档矛盾

- 维度：算法实现 / 安全性
- 位置：`rust/src/stego/format.rs:435-442`；`rust/src/stego/envelope.rs:122`
- 状态：已确认

```rust
        Credential::Password(password) => {
            let normalized = normalize_nfc(password);
            let subkey =
                derive_domain_subkey_with_label(normalized.as_bytes(), domain, cipher.domain_label);
            let effective_ikm: &[u8] = match &subkey {
                Some(subkey) => subkey,
                None => normalized.as_bytes(),
            };
```

```rust
pub fn derive_domain_subkey_with_label(
    ...
) -> Option<[u8; 32]> {
    let d = domain.filter(|s| !s.is_empty())?;
```

**分析**：`domain` 为 `None`/空（默认）时该函数直接返回 `None`，PBKDF2 的 IKM 就是 NFC 密码本身，`cipher.domain_label` 未参与任何运算；而 FileKey 分支始终用 `info_with_domain`。`format.rs` 的字段效应表声称改 `cipher` 会改变 L1/L2/L3 派生——但默认密码路径下只改 `domain_label` 不会改变 L1 master，私有构建无法仅靠标签隔离。

**解决方案**：让 Password 分支无论 domain 是否为空都把 `cipher.domain_label` 掺入派生（作为 HKDF info 或 salt 的一部分）。**注意**：这会改变冻结的 L1 golden vectors，需 `format_major` bump + 新向量 + `baseline --write`，不能静默修改。

#### P2-7 音频写侧缺 `ciphertext_len > HEADER_LEN_MAX` 检查，且明文/密文上限口径差 21 字节

- 维度：接口与参数 / 可靠性
- 位置：`rust/src/stego/audio/core.rs:694`、`:757`；`rust/src/stego/header.rs:16-20`、`:251-256`；`rust/src/stego/envelope.rs:77-86`；对照 `rust/src/stego/png/engine.rs:1538-1540`
- 状态：已确认（**但「约 64 MiB payload 触发」已被证伪，见第 6 章**）

```rust
    let ciphertext_len = plaintext.len() + suite.tag_len();
...
        body_len: ciphertext_len as u32,
```

```rust
/// Largest payload a decoded envelope may expand to (matches the header's
/// 26-bit length field).
pub const MAX_PLAINTEXT_LEN: usize = crate::stego::header::HEADER_LEN_MAX as usize;
```

```rust
pub const BODY_OVERHEAD: usize = 4 + 1 + MICRO_OVERHEAD_MIN + TAG_LEN; // 22 bytes
```

**分析**：`MAX_PLAINTEXT_LEN` 按**明文**设限，`body_len` 存**密文**（明文 + 21 字节 framing/tag），两个上限都取 `2^26-1`，单位不一致；PNG/JPEG 的 embed 另有 `ciphertext_len > HEADER_LEN_MAX` 早拒，音频没有。`SpatialHeaderV4::decode` 必然拒绝超限 body_len。但 `core.rs:725-731` 的 `MAX_WORKING_SET_BYTES = 768 MiB` 工作集上限会在 ciphertext 约 0.8–3.7 MB 时先拒绝 embed，因此**当前参数下该窗口不可达**；这是契约不一致与未来放宽工作集后的回归风险，不是现网故障。

**解决方案**：`core.rs:694` 后补 `if ciphertext_len > HEADER_LEN_MAX as usize { return Err(...) }`；`MAX_PLAINTEXT_LEN` 改为 `HEADER_LEN_MAX - BODY_OVERHEAD`，或让 `build_plaintext` 直接按 `ciphertext.len()` 校验。五个引擎共用同一个 `check_body_len()` 函数，避免再次遗漏。

#### P2-8 `BODY_OVERHEAD = 22` 只计最小 micro-header，容量与 inspect 未计文件名开销

- 维度：接口与参数 / 算法实现
- 位置：`rust/src/stego/envelope.rs:72-82`（对照 `audio/core.rs` 的 `payload_bytes_from_slots` 与 `inspect.payload_len`）
- 状态：已确认

```rust
pub const MICRO_OVERHEAD_MIN: usize = 1;
...
pub const BODY_OVERHEAD: usize = 4 + 1 + MICRO_OVERHEAD_MIN + TAG_LEN; // 22 bytes
```

**分析**：File payload 的 micro-header 是 `2 + name_len`，比最小开销多 `1 + name_len` 字节；容量折算与 `inspect.payload_len` 恒按 22 扣除，带长文件名时高估可用 payload，压缩时又反向低估。不直接导致提取失败，但容量报告与 `SafetyThreshold` 判断偏差。

**解决方案**：容量估算用 `encode_micro_header(payload).len() + 5 + TAG_LEN` 的实际开销；`inspect.payload_len` 明确标注为估计值，或直接从解密后的明文计算真实长度。

#### P2-9 `chi2_suspicion` 不是卡方统计，`*4.0` 与阈值 0.5 无校准依据

- 维度：算法实现 / 代码质量
- 位置：`rust/src/analysis.rs:1876-1895`（对照 `:1705-1708` 阈值）
- 状态：已确认

```rust
fn chi2_suspicion(hist: &[u64; 256]) -> f64 {
    let mut total_imbalance = 0.0;
    let mut count = 0.0;
    for i in (0..256).step_by(2) {
        let total = hist[i] + hist[i + 1];
        if total >= 8 {
            let diff = (hist[i] as f64 - hist[i + 1] as f64).abs();
            total_imbalance += diff / total as f64;
            count += 1.0;
        }
    }
    ...
    (1.0 - avg_imbalance * 4.0).clamp(0.0, 1.0)
}
```

**分析**：文档声称「Westfeld & Pfitzmann 1999 Chi-square attack」「normalised to 0..1」「df≈127」，实现却是「平均对不平衡」的线性映射，没有 χ² 统计量、没有 p-value；`*4.0` 与阈值 `0.5` 未出现在任何校准说明中（对比 `SPATIAL_RATE_THRESHOLD` 与 `CALIBRATION_FLAG_RATE` 都有语料数据）。`aggregate_risk` 每条 `Suspicious` 记 25 分，该 detector 可显著推高 verdict。

**解决方案**：实现真正的 χ² 统计量与 p-value；或改名 `pair_balance_suspicion` 并在 107/216 cover 语料上标定 `*4.0`/`0.5` 的 FPR，把实测误判率写进注释。

#### P2-10 `analysis.rs` 对 WAV/FLAC 不运行任何内容域统计检测器，且免责声明未覆盖音频

- 维度：功能缺陷 / 算法实现
- 位置：`rust/src/analysis.rs:480-490`、`:502-507`
- 状态：已确认（见 W-11）

```rust
        match format {
            Some(FileFormat::Png) => match decode_png_pixels(data) {
                Some((px, width, channels)) if !px.is_empty() => {
                    track_spatial_domain(&px, width, channels, &mut findings, &mut detectors);
                }
                _ => png_stats_skipped = true,
            },
            Some(FileFormat::Jpeg) => {
                track_jpeg_dct_domain(data, &mut findings, &mut detectors, &mut calibrated_signal);
            }
            _ => {}
        }
```

```rust
    if format == Some(FileFormat::Jpeg) && matches!(verdict, "clean" | "low") && !calibrated_signal
    {
        notes.push(
            "JPEG statistical detectors are weak against low-rate DCT embedding: a clean/low verdict is NOT evidence that nothing is hidden".to_string(),
        );
    }
```

**分析**：`track_spatial_domain` / `track_jpeg_dct_domain` 只在 PNG/JPEG 分支调用；本项目自己的 WAV 逐样本 ±1、FLAC 残差 ±1 隐写不留下结构痕迹，故 `scan_file` 对音频 carrier 必然 "clean"，而免责声明只覆盖 JPEG 与 PNG 统计跳过。

**解决方案**：对音频格式追加 "no content-domain audio detector" note；或实现音频 LSB / 残差直方图检测器并给出口径。

#### P2-11 `ProbeOptions` 无法表达 `suite_id` / `freshness` / `domain` / `extensions`，probe 与 embed 配置不对称

- 维度：接口与参数
- 位置：`rust/src/cli/helpers.rs:425-444`
- 状态：已确认

```rust
    let mut embed = EmbedOptions {
        password,
        key,
        suite_id: args.cipher_suite,
        safety,
        tuning: tuning.clone(),
        exact: args.exact,
        ..Default::default()
    };
    if let Some(seed_hex) = args.seed.as_deref() {
        embed.freshness = crate::stego::Freshness::Seeded(parse_seed_hex(seed_hex)?);
    }
    let probe = ProbeOptions {
        password,
        key,
        safety,
        tuning,
        exact: args.exact,
        ..Default::default()
    };
```

**分析**：函数注释声称「一个 builder 同时服务两个调用者」，但 `ProbeOptions` 没有上述四个字段；`domain` 改变 HKDF 域、`extensions` 直接占用 V4 头 TLV 空间并影响可用容量。库调用者用自定义 domain/extensions embed 时，`capacity` 报告与真实 embed 不符。

**解决方案**：`ProbeOptions` 补齐与头布局相关的字段并由同一 builder 同步赋值；或让 capacity 直接从 `EmbedOptions` 派生（`ProbeOptions = EmbedOptions::capacity_view()`），从结构上杜绝漂移。

#### P2-12 CLI/config 布尔合并是「只能关、不能开」的单向表达式

- 维度：接口与参数 / 代码质量
- 位置：`rust/src/cli/cmd_structure.rs:165-166`；`rust/src/cli/helpers.rs:349-359`；`rust/src/cli/cmd_stego.rs:429-437`
- 状态：已确认（另见 W-12）

```rust
    let preserve_time = args.preserve_time && cfg.preserve_time.unwrap_or(true);
    let backup = !args.no_backup && cfg.backup.unwrap_or(true);
```

```rust
        enforcement: if args.enforce_safety
            || cfg
                .stego
                .as_ref()
                .and_then(|s| s.enforce_safety)
                .unwrap_or(false)
        {
            SafetyEnforcement::Enforced
        } else {
            SafetyEnforcement::Advisory
        },
```

```rust
        let file_target = crate::commit::FileTarget {
            output_path: target.as_deref(),
            backup,
            preserve_time: true,
            overwrite: args.overwrite,
        };
```

**分析**：`preserve_time = args.preserve_time && cfg.preserve_time.unwrap_or(true)` 与 `backup = !args.no_backup && cfg.backup.unwrap_or(true)` 中，CLI 只有负向 flag，config 设为 false 后无法重新开启；`enforce_safety` 用 `||` 使 config 的 true 成为不可撤销下限，与同函数 `level` 的「CLI 显式优先」策略不一致；`cmd_stego.rs` 的 `embed` 更把 `preserve_time: true` 写死，完全忽略 config。

**解决方案**：统一改为三态 `Option<bool>` 解析（正向 + 负向 flag 各一），优先级「显式 flag > config > 内置默认」；抽一个 `resolve_bool(cli: Option<bool>, cfg: Option<bool>, default: bool) -> bool` 供全部命令共用；`embed` 改用该结果。

#### P2-13 `--encrypt` 名实不符：它只触发密码提示，不控制是否加密

- 维度：接口与参数 / 安全性
- 位置：`rust/src/cli/args.rs:305-306`；`rust/src/cli/helpers.rs:94-108`；`rust/src/core/crypto.rs:157-161`
- 状态：已确认

```rust
    #[arg(short = 'e', long = "encrypt")]
    pub encrypt: bool,
```

```rust
    if encrypt_flag {
        // Only prompt when a terminal is actually attached; both stdin and
        // stdout must be TTYs ...
        if std::io::IsTerminal::is_terminal(&std::io::stdin())
            && std::io::IsTerminal::is_terminal(&std::io::stdout())
        {
            return Ok(Some(prompt_password(confirm)?));
        }
        return Err(StrHideError::General(
            "Password required but no interactive terminal is available. Use -p/--password, --password-file, or STRHIDE_PASSWORD.",
        ));
    }
    Ok(None)
```

```rust
pub const BUILTIN_DEFAULT_KEY: &str =
    "strhide::structure::envelope::v2::default::builtin::public::secret";
```

**分析**：`WriteOptions` 没有 `encrypt` 字段；flag 唯一作用是让 `resolve_password` 提示输入密码，使 `password` 变为 `Some`。无密码时返回 `None`，信封使用随二进制发布的 `pub const BUILTIN_DEFAULT_KEY` 派生密钥——这是 `lib.rs` 明确记载的「防 hex-view 明文」公开混淆设计，**不是保密性缺陷**（第 6 章），但用户会误以为不传 `-e` 才是「不加密」，且脚本里 `sth write -e` 因非交互终端直接报错。

**解决方案**：重命名为 `--require-password`；或在 `WriteOptions` 增加显式 `credential` 并在无密码路径输出醒目的「仅混淆、无保密性」告警（当前只在「给了密码却未加密」时才告警）。

#### P2-14 `let _ =` 吞掉权限/时间戳恢复失败，注释承诺的 preservation 形同虚设

- 维度：可靠性
- 位置：`rust/src/core/commit.rs:189-196`（`commit_carrier_patches` 同形，见 W-13）
- 状态：已确认

**分析**：`write_bytes_atomic` 已把临时文件权限改为默认 ACL，若随后 `set_permissions`/`filetime::set_file_times` 因只读 FS、ACL、跨卷 rename 失败，调用者拿到 `Ok(backup_path)` 却不知道权限被放大、时间戳丢失；`preserve_time` 参数无效果且无告警。

**解决方案**：把两个调用改为 `?` 传播（或 `map_err` 附加路径上下文）；若确需「尽力而为」，返回结构化 `Warning` 而非静默丢弃。

#### P2-15 `verify_payload_stream` 的「1 GiB 硬上限」退化为调用者可控参数

- 维度：接口与参数 / 可靠性
- 位置：`rust/src/core/crypto.rs:708-727`
- 状态：已确认

```rust
/// Streamingly decrypt and verify payload against `expected_sha256` and `expected_raw_size`,
/// enforcing a hard memory/byte limit of [`MAX_VERIFY_PAYLOAD_SIZE`] (1 GiB) without
/// allocating the full payload in memory.
pub fn verify_payload_stream<R: Read>(
    ...
    limit: u64,
) -> Result<u64, StrHideError> {
    if total_payload_bytes > limit || expected_raw_size > limit {
```

**分析**：文档称 hard limit 1 GiB，但 `limit` 完全由调用者决定，函数内未 `min(MAX_VERIFY_PAYLOAD_SIZE)`。生产路径（`structure/engine.rs:1717`）恰好传常量所以 CLI 安全，但这是 `pub fn`，库调用者传 `u64::MAX` 即可绕过，配合伪造 carrier 声明巨大 `raw_size` 可持续解压至 OOM。

**解决方案**：函数开头 `let limit = limit.min(MAX_VERIFY_PAYLOAD_SIZE);` 并对 `limit == 0` 显式拒绝；文档改为「上限不超过 1 GiB」。压缩路径的 `sha_writer.limit` 同时改为 `expected_raw_size`，与 `decompress_stream` 的炸弹上限口径一致。

#### P2-16 HILL stage-2 低通是 O(p1²) 逐像素重算，且 `epsilon.max(1e-12)` 破坏 wire 量化契约

- 维度：算法效率 / 算法实现
- 位置：`rust/src/stego/png/cost/hill.rs:86-92`、`:120-136`
- 状态：已确认

```rust
        // `p1`/`p2` are validated as positive odd numbers by
        // `PngParams::validate`, so the halving below is exact.
        let p1 = params.p1_window.max(1);
        let p2 = params.p2_window.max(1);
        let pad = 1 + (p1 - 1) / 2 + (p2 - 1) / 2;
```

```rust
        let eps = params.epsilon.max(1e-12);
        i2.par_chunks_mut(w2).enumerate().for_each(|(i, dst_row)| {
            for (j, dst) in dst_row.iter_mut().enumerate() {
                let mut sum = 0.0f64;
                for u in 0..p1 {
                    let row = &i1[(i + u) * w1 + j..(i + u) * w1 + j + p1];
                    sum += row.iter().sum::<f64>();
                }
```

**分析**：stage-3 已用可分离两趟卷积，stage-2 却对每个输出像素重建 `p1` 个行切片并 `sum()`；`p1` 上限 63 → 最坏 3969 次乘加/像素，50 MP 图约 2e11 次操作。`pad` 的整除只对**奇数**窗口成立，而 `compute_cost` 是 `pub trait` 方法、不调用 `PngParams::validate`：偶数窗口（如 `p1=4, p2=15`）可导致 `i2[(i+u)*w2..]` 越界 panic。另外 `eps.max(1e-12)` 把 `quantize_epsilon_k` 允许的 `k>40` 全部抬到 `1e-12`，使 header 里的 `neg_log2_epsilon` 成为哑字段，违背 header.rs:22-28 的「writer/prober/reader 必须跑在完全相同的量化值上」契约。

**解决方案**：stage-2 改为与 stage-3 相同的可分离两趟（或前缀和），复杂度 O(p1)；`compute_cost` 入口对 `p1/p2` 做 `odd && 1..=63` 校验，`pad` 改由恒等式推导；去掉 `.max(1e-12)`，改为在 `quantize_epsilon_k` 侧把 `k` 上限收到 `2^-k >= 1e-12`；补偶数窗口与不同线程数的确定性单测。

#### P2-17 HEVC embed 内存峰值：输入 + 全量输出拷贝 + 每 slice 完整 RBSP/journal + 32 路并行解码器

- 维度：算法效率
- 位置：`rust/src/stego/hevc/engine.rs:1022-1027`（对照 `slot.rs`、`StopCondition::All => 32`）
- 状态：已确认（峰值需实测，见 W-19）

**分析**：`out_carrier = carrier.to_vec()` 是整文件第二份拷贝；`Capture::Full` 的 `SliceContext` 为每个 slice 保留整段 RBSP 与完整 ops journal；`StopCondition::All` 一次并行 32 个 GOP decoder，每个又保有一批 slice 的 journal。4K/8K 长视频峰值可达数 GB。

**解决方案**：embed 走 patches 流式提交（不构造 `out_carrier`）；`SliceContext` 仅保留被 STC 选中的 slice 的 journal，未入选只留 bits；给并行 batch 设显式内存预算上限并用 `try_reserve`。

#### P2-18 结构域 `strategy_id` 数字硬编码 + `pe_codebits` 豁免未做 feature gate 判定

- 维度：架构设计 / 接口与参数
- 位置：`rust/src/structure/engine.rs:2352-2359`；对照 `rust/src/structure/registry.rs:98`、`adapters/mod.rs:34`
- 状态：已确认

```rust
    if crate::structure::registry::id_to_strategy(header.strategy_id) == "pe_codebits" {
        return Ok(());
    }
```

**分析**：`STRATEGY_REGISTRY` 无条件注册 `("pe_codebits", 8)`，`envelope_coordinates_agree` 无条件对 ID 8 跳过 Level 2 全部坐标校验，而 `PeAdapter::supported_strategies` 与实现只在 `structure-pe` feature 下存在。关闭该 feature 的构建无法写出该策略，却仍接受并「免检」一个 `strategy_id=8` 的载体；配合 P0-2 的非认证字段可伪造 ID 绕过 Level 2。分组审查还发现 `zip.rs` / `isobmff.rs` 里 `header.strategy_id == 1` / `== 12` 的硬编码，与注册表形成重复真源。

**解决方案**：豁免条件加 `cfg!(feature = "structure-pe")` 且由 adapter 确认 `is_scattered_strategy`；所有数值比较改为 `id_to_strategy(...) == "eof"` / `StrategyId::from_name(...)`；给注册表 ID 变更加一条断言测试。

#### P2-19 `structure/mod.rs` 声称的跨域例外已不存在，注释与实现相反

- 维度：架构设计 / 代码质量
- 位置：`rust/src/structure/mod.rs:13-18`；`rust/src/lib.rs:113-140`
- 状态：已确认（`import_lint.py` 实测 OK）

**分析**：注释仍写「One exception remains: `inspect` measures content capacity inline behind `#[cfg(feature = "content")]`」，但全 structure 目录检索 `crate::stego` 只出现在文档链接里，`feature = "content"` 只出现在这行注释本身；`inspect_core` 只调 `adapter.strategy_capacities(Some(host))`。分层实际已干净，注释若被后续维护者当作依据「恢复」该逻辑，会重新引入 `structure → stego` 依赖。

**解决方案**：删除该例外描述，改为「无例外，内容容量聚合位于 facade/CLI 层」；把「分层无跨域依赖」写成 `import_lint` 之外的 CI 断言（例如对 `structure/` 全文 grep `crate::stego` 必须为 0）。

#### P2-20 多处 `debug_assert` / 裸索引把不变量交给分散的调用点

- 维度：可靠性 / 代码质量
- 位置：`rust/src/stego/hevc/engine.rs:50-57`（`nal_header_fields`）、`:310-312`（`superblock_positions`）；`rust/src/stego/jpeg/engine.rs:505`（`apply_deltas`）；`rust/src/stego/audio/flac/bits.rs:137-156`（`BitWriter::write`）
- 状态：已确认（分组审查提供，具体触发见 W-20）

**分析**：release 下 `debug_assert!` 被移除，`nal[0]/nal[1]`、`&nal[2..]` 在 `len<2` 时 panic；`superblock_positions` 用 `debug_assert!(count <= pool_size)` 而下游直接 `&header_positions[..524]`；`apply_deltas` 的「AC 系数不得增长越 ±1023」只做 debug 断言，release 静默写回不可 Huffman 编码的值；`BitWriter::write` 越界时 `continue` 跳过写入并返回 `Ok(())`，release 下 parity 未翻转却报告成功。

**解决方案**：把这些函数改为 `Option`/`Result` 返回并在函数内部校验；`BitWriter::write` 返回 `Result<(), BitEof>` 由 `write_remainder` 传播；`apply_deltas` 改运行时 `if` + `CorruptedData`；补 release 模式下的畸形输入测试。

---

### P3 低（理论触发 / 文档 / 技术债）

#### P3-1 `make_chunk_nonce` 把 `chunk_index` 截断为 `u32`，且 meta nonce 与 `chunk_index=0xFFFFFFFF` 冲突

- 位置：`rust/src/core/crypto.rs:305-325`
- 状态：已确认（理论触发）

```rust
pub fn make_chunk_nonce(base_nonce: &[u8; 12], chunk_index: usize) -> [u8; 12] {
    let counter_bytes: [u8; 4] = base_nonce[8..12].try_into().unwrap();
    let counter = u32::from_le_bytes(counter_bytes) ^ (chunk_index as u32);
```

**分析**：注释断言「every resulting nonce is distinct」，但 `chunk_index as u32` 回绕，且 `make_meta_nonce` 用 `^ 0xFFFFFFFF`，恰等于 `chunk_index == 0xFFFFFFFF` 时的 chunk nonce；GCM nonce 重用是灾难性的。触发需 >2^32 个 chunk（小 chunk_size + >4 GiB payload），当前写入侧无总长度硬上限但极难达到。

**解决方案**：`chunk_index` 用 `u64` 并扩展计数器域，或显式在 `chunk_index >= u32::MAX` 时返回 `Err`；meta nonce 改用固定高位前缀做域分离而非 XOR 常量。顺带给 `encrypt_stream_to_chunks` 加总长度上限。

#### P3-2 `derive_channel_header_mask` 用 4 字节公开 magic 作 HKDF 的 IKM，命名/文档误导为「keystream」

- 位置：`rust/src/core/crypto.rs:294-302`
- 状态：已确认（设计取舍）

**分析**：`Hkdf::new(None, magic)` 的输入是写在 carrier 里、公开可定位的 4 字节值，输出完全可离线重算，只是固定替换表，不提供密码学保护；`keystream` / `HKDF` 命名会让调用者误以为有保密性。

**解决方案**：改名为 `obfuscate_channel_header` 并去掉 HKDF 依赖；若需要完整性，把该头纳入 AEAD AAD 而非「掩码」。

#### P3-3 `from_seed_grouped` 的列去重 `while` 无迭代上限

- 位置：`rust/src/stego/coding/stc.rs:356-373`
- 状态：已确认（理论触发，见 W-5）

```rust
        let distinct_patterns = 1u64 << (h - 2);
        let mut cols = Vec::with_capacity(u as usize);
        for s in 0..u as u64 {
            let mut idx = s;
            let mut col = pattern(idx);
            while (cols.len() as u64) < distinct_patterns && cols.contains(&col) {
                idx = idx.wrapping_add(u as u64);
                col = pattern(idx);
            }
            cols.push(col);
        }
```

**分析**：退出全靠找到未出现过的 `col`；若某 `(seed, h, u)` 使 `idx += u` 的步进序列产生的不同模式数少于 `u`，循环不终止且循环内无 `control.check()`。`validate_u_wide` 只限制 `u<=64`，该函数还被 `slots_for_codec` 在 probe/extract 路径调用。

**解决方案**：加迭代上限（如 `distinct_patterns * 4`），耗尽时接受重复列（模块文档明确说重复列不破坏可达性）；补遍历小 `h,u` × 多组 seed 的终止性测试。

#### P3-4 Feistel 置换的 `guard > 64` 回退返回 `i % n`，理论上破坏双射

- 位置：`rust/src/stego/audio/perm.rs:128-145`
- 状态：已确认（回退存在；「常态破坏双射」已被证伪，见第 6 章）

**分析**：cycle walking 在数学上必终止且限制在 `[0,n)` 仍是双射，embed/extract 共用同一 `at()`，正常路径严格一致；回退仅在 Feistel 轨道连续 >64 步落在外部域时触发（随机模型约 2^-65），若触发可能与其它位置的映射碰撞。另 `keys: [u64; 2]` 却声称 6 轮，轮函数只有 2 种。

**解决方案**：删除 guard 回退（或改 `debug_assert!` + 返回错误）；轮密钥改为 `[u64; ROUNDS]` 并修正文档。

#### P3-5 MKV stale CRC 被跳过验证，`refresh_mkv_crcs` 仍返回 `Ok`

- 位置：`rust/src/stego/hevc/mkv_boxes.rs:617-626`
- 状态：已确认

```rust
    for crc in &crcs {
        // Stale checksums are exempt: they were invalid before the embed and
        // are left exactly as the muxer wrote them.
        let Some(endian) = crc.endian else { continue };
```

**分析**：文档承诺「刷新后校验不一致就 fails closed」，但 `endian=None`（原文件 CRC 本就失效或覆盖范围建模错误）时刷新与验证都跳过并返回 `Ok(())`，而 `mkvmerge`/`ffmpeg` 会拒绝该文件。

**解决方案**：embed 前拒绝 `endian=None` 的载体，或明确返回 `Unsupported`；至少不要声称 fails closed。

#### P3-6 HEIF `thmb` 引用解析只读 `from_item_ID`，忽略 `to_item_IDs`

- 位置：`rust/src/stego/heif/thumb_bridge.rs:1104-1125`
- 状态：已确认（方向需按 ISO 23008-12 实测，见 W-9）

```rust
        // Walk the typed reference sub-boxes (thmb/cdsc/...): from_item_ID,
        // reference_count, then that many to_item_IDs.
        ...
                    if ref_type == b"thmb" {
                        thumbnail_ids.push(from_id);
                    }
                    let _ = cnt; // to_item_IDs are not needed for targeting
```

**分析**：注释要求读 `to_item_IDs`，代码却丢弃 `cnt` 并把 `from_id` 当缩略图；若 `thmb` 方向是「主图 → 缩略图」，主图 ID 会被误收进 `thumbnail_ids`，真正缩略图退化到兜底路径。

**解决方案**：按标准确认方向后解析 `cnt` 个 `to_item_ID`；`from`/`to` 都做候选但排除 `primary_item_id`；用真实 iPhone HEIC 验证。

#### P3-7 PNG adapter 的「偏移被移位」分支硬编码标准 header magic

- 位置：`rust/src/structure/adapters/png.rs:267-279`
- 状态：已确认

```rust
                            if stego_in.read_exact(&mut hdr).is_ok() {
                                hdr == crate::params::STANDARD_HEADER_MAGIC
                            } else {
                                false
                            }
```

**分析**：该分支用于内容域重压缩 IDAT 后物理偏移改变的场景，但只接受标准 magic，对 stealth（密码派生 magic）与私有 `StructureProfile.magic` 一律返回 false；`locate` 明明已拿到 `expected_trailer_magic` 却未用于 header 校验，同时是 structure adapter 直接依赖 `crate::params` 常量的跨域残留。

**解决方案**：改为按 dialect 解析 header magic（`unpack_with_profile`），去掉硬编码常量。

#### P3-8 release `panic = "abort"` 与 `TmpGuard` 的 Drop 清理承诺冲突

- 位置：`rust/Cargo.toml:152-157`；`rust/src/core/commit.rs:99-105`
- 状态：已确认

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

**分析**：`control.rs` 注释明确论证过「不能 `std::process::exit`，因为跳过 Drop 会让 commit guard 创建的临时文件残留」，但 release 的 `panic = "abort"` 同样不展开栈、不运行 Drop。生产代码仍有若干可避免的 `unwrap`/`expect`（如 `capability.rs:241`、`batch.rs` 的 `Mutex::lock().unwrap()`、`crypto.rs:301` 的 HKDF `.expect`），任一 panic 落在 guard 存活窗口内即残留 `*.strhide.tmp`，结合 P1-10 其内容可能是解密后明文。

**解决方案**：进程启动时清理遗留 tmp（按 `temp_path_for` 的命名模式登记），或改用显式 `catch_unwind` / scopeguard；消除上述可避免的 `unwrap`/`expect`；在文档中把 `panic = "abort"` 与 guard 承诺对齐。

#### P3-9 i18n 实现是进程全局 `AtomicU8`，文档却称 thread-local

- 位置：`rust/src/core/i18n/mod.rs:3`、`:47-59`
- 状态：已确认

```rust
static CURRENT_LANG: AtomicU8 = AtomicU8::new(0); // 0 = En, 1 = Zh

/// Set the default interface language across threads.
pub fn set_lang(lang: Lang) {
```

**分析**：模块文档写「thread-local language state」，`set_lang` 注释写「across threads」，实现是进程全局且 `Ordering::Relaxed`；`StrHideError::detail_i18n()` 无条件走全局 `lang()`。GUI/服务端在同一进程并发处理不同语言请求时错误文本会互相串扰。

**解决方案**：改为 `thread_local!` 或如实更新文档为「process-global fallback」；让 `detail_i18n()` 明确依赖全局态，并推广 `detail_i18n_with_ctx` 给并发调用方。

#### P3-10 byte 级公共入口仍是位置参数，与文件版 Options 不一致

- 位置：`rust/src/structure/engine.rs:1818`、`:2075`；`rust/src/structure/options.rs:8`
- 状态：已确认

```rust
pub fn read_carrier_bytes(
    carrier: &[u8],
    password: Option<&str>,
    dialect: &StructureProfile,
) -> Result<ReadResult, StrHideError> {
```

**分析**：`read_carrier_bytes(carrier, password: Option<&str>, dialect: &StructureProfile)` 与 `remove_carrier_bytes` 仍是位置参数，`options.rs` 文档宣称的 stage-4 重构未覆盖 bytes 入口；两个相邻引用参数易传反，且无法表达 `ReadOptions`/`RestoreOptions` 的 `overwrite` 等语义。

**解决方案**：提供 `*_with_options(carrier, &ReadOptions, &StructureProfile)`，位置参数版本保留为 `#[deprecated]` 包装。

#### P3-11 `sniff_stream` / `with_restored_position` 用 `let _ =` 吞掉位置恢复失败

- 位置：`rust/src/formats/sniff.rs:331-334`；`rust/src/structure/adapters/io.rs:58`；`rust/src/structure/registry.rs:76`
- 状态：已确认

```rust
        Ok(sniff_bytes(&buf))
    })();
    let _ = reader.seek(SeekFrom::Start(restore));
    outcome
```

**分析**：文档承诺「The position is restored even when the read fails part-way」，但恢复 `seek` 失败时错误被丢弃，函数仍返回 `Ok(Some(format))`，调用者的流已停在错误偏移，后续读取产生难定位的解析错误或数据损坏。

**解决方案**：`let restore_result = reader.seek(...); outcome?; restore_result?;`——先传播探测结果，恢复失败必须返回 `Err`。

#### P3-12 `scan_file` 用单次 `read` 填 1 MiB 前缀，不保证读满

- 位置：`rust/src/analysis.rs:295-298`
- 状态：已确认

```rust
        let mut f = File::open(path)?;
        let mut head = vec![0u8; PREFIX_WINDOW];
        let n = f.read(&mut head)?;
        head.truncate(n);
```

**分析**：`Read::read` 允许短读（管道/网络/特殊文件更常见），后续 `ScanView::windowed` 就以可能很短的前缀做格式识别与全部结构/签名检测；对照 `scan_bytes` 用切片取满前缀，行为不一致。大文件首读短读时报告静默偏 clean。

**解决方案**：循环读至 `PREFIX_WINDOW`/EOF，或改用 `read_exact` + 处理 EOF；与 `sniff.rs:322-329` 的写法统一。

#### P3-13 文档/常量一致性漂移合集

- 位置：`rust/src/stego/mod.rs:280-283`、`:361-365`；`rust/src/stego/coding.rs:307-317`；`rust/src/analysis.rs:139-141`；`rust/src/stego/envelope.rs:340-343`；`rust/src/stego/hevc/bitstream.rs:142`；`rust/src/stego/heif/thumb_bridge.rs:644-647`
- 状态：已确认（最后两项死代码由分组审查提供，见 W-21）

| 位置 | 文档声称 | 实际 |
| :--- | :--- | :--- |
| `stego/mod.rs:280-283` | `kind`/`name` 不在 wire 上，结果恒为 `PayloadKind::Bytes` | `encode_micro_header` 已实现文件名往返 |
| `stego/mod.rs:361-365` | 默认修改率 0.2917（Hamming k=3） | `StegoCodec::Auto` 恒选 STC（0.50/0.265/0.230） |
| `coding.rs:307-317` | `/// - u >= 4: about 0.22 (measured 0.222 ...)` | `match stc_u { 0|1 => 0.50, 2 => 0.265, _ => 0.230 }`，`u=3` 与 `u>=4` 合并 |
| `analysis.rs:139-141` | `/// 0 (clean) .. 10 (very likely hidden).` | `score.min(100)`，verdict 阈值 10/30/60（`:494-499` 实读） |
| `envelope.rs:340-343` | encode 在 `sanitize_filename=None` 时退回无文件名 | `sanitize_filename(name_str).unwrap_or_else(|| "extracted.bin".to_string())` |
| `bitstream.rs:142` / `thumb_bridge.rs:644` | `is_epb_safe_flip`、`DirectSpatial` 分支 | 生产路径无调用点 / 不可达，属死代码 |

**解决方案**：逐条更正文档或删除死分支；把「文档与实现一致性」加入 review checklist；`risk_score` 改为 `0..=100` 并列出各 verdict 分段阈值。

---

## 4. 系统性专题深入分析

### 4.1 认证边界：一条完整的伪造链

结构域的安全模型是「AEAD 保护 header 前 80 字节 + 全部 payload/meta」，但**定位元数据不在保护范围内**：

```
trailer(24B, 仅 CRC32)  →  ube_offset / ube_total_size（未认证）
        ↓
adapter::locate 接受伪造值（PE/MKV 缺文件长度等式，P0-2）
        ↓
header 后 32B（未认证、加密非 stealth 时也不 mask，P0-3）
        ↓
meta_len = u32::MAX → vec![0u8; ~4 GiB]（engine.rs:1598）→ OOM/abort
hint_len + hint 明文 → 任意社会工程文本 / 终端控制序列
inject_size=0 → 跳过 Level 2 坐标校验（engine.rs:2356 注释自认）
strategy_id=8 → feature 关闭的构建仍「免检」（P2-18）
```

`isobmff.rs:129-146` 证明项目已经为同一攻击修过一次，但修复没有横向推广到 PE/MKV。**单一真源**应是：在 `read_carrier_bytes`/`read_core` 入口统一做一次「物理边界 + 认证字段」校验，所有 adapter 只返回候选位置，不再各自决定是否信任 trailer。

### 4.2 容量口径分裂：一份载体应当只有一份池视图

| 引擎 | probe 口径 | embed 口径 | 不一致点 |
| :--- | :--- | :--- | :--- |
| JPEG | `component_geometry(info,0,0).grid_w*grid_h`（P1-2） | `coeffs.components[0].blocks.len()` | SOF/DNL/非 16 倍数尺寸；另有 `preflight` 第三套 |
| HEVC | `scan_hevc_slot_count` 全池 / `probe_hevc_pool` 20% 采样 / `build_hevc_capacity_info` drift ladder | `StopCondition::TargetSlots` 只解码一个窗口 | 三套公式；`recommended_max_bytes` 随 payload 长度变化（W-7） |
| 音频 | `auto_select_codec(available, available)` 恒 `u=1`（P1-4） | `auto_select_codec(available, ciphertext_len*8)` → `u=2/3` | 上限高估 2–3 倍 |
| PNG/JPEG | `BODY_OVERHEAD = 22` 固定（P2-8） | 实际 micro-header `2+name_len` + 压缩 | 带文件名时容量偏差 |
| 结构域 | `strategy_capacities` 恒 `available: true`（W-16） | `choose_auto_strategy` 会回退 eof | inspect 报告与写入策略不符 |

**根因**：capacity 计算被实现为「各入口按自己手头信息重新推一遍」，而不是「从 embed 的真实 plan 反推」。**统一方案**：定义一个 `CarrierPlan { header_slots, body_slots, codec, stc_h, stc_u, tier_limits, change_rate }`，embed 先构造 plan 再写字节，probe 直接复用同一 `plan_for(carrier, payload_len)` 函数，inspect/verify 从 carrier 的自描述字段重建 plan；三者共享一份 `tier_limits`。所有「按报告上限 embed 必须成功」的用例作为契约测试。

### 4.3 容器写入正确性：写回后是否仍是合法文件

| 载体 | 风险 | 证据 |
| :--- | :--- | :--- |
| PNG | 读入不校验 CRC/结构；写出 `as u32` 截断；并行 deflate 拼接；IDAT 数量/位置不保真 | P1-9、P2-1~P2-3 |
| JPEG | `map_dct_error` 靠 `dct_io` 错误文本判断 progressive；DHT 段白名单不全；`can_move_with_slots` 缺对照测试 | W-10 |
| FLAC | 槽位选择跨端不变量（P0-1）；MD5 偏移硬编码；release 无带 CRC 复核 | P1-5、P1-6 |
| HEVC MP4 | `has_inter` 两套口径；`hvcC` 参数集过滤在 MP4/HEIF/MKV 不一致 | P1-3、W-8 |
| MKV | CRC 刷新责任上移；stale CRC 跳过；VCL 过滤不校验 forbidden bit/tid | P1-7、P3-5、W-8 |
| HEIF | `thmb` 方向；`pitm` 缺失默认 item 1；Exif TIFF 内部偏移未随 delta 调整 | P3-6、W-9 |

**建议**：建立「写回合法性」回归矩阵——每个容器 embed 后用至少一个**独立解码器**（png crate / jpeg-decoder / ffmpeg / mkvmerge / flac -t）验证，且覆盖大图、多 IDAT、DNL、带 CRC 的 MKV、真实 HEIC 等非标准输入。当前 `baseline_hash` 只保证字节确定性，不保证第三方可解析。

### 4.4 密码学工程：设计取舍与真实缺口

- **公开默认密钥**：`BUILTIN_DEFAULT_KEY` 是 `pub const`，`lib.rs` 已明示「无密码时统一用内置公钥加密，避免 hex dump 明文」。这是**有意设计**，不是漏洞；但 CLI 必须让用户知道「无密码 = 仅混淆，无保密性」（P2-13）。
- **nonce**：`make_chunk_nonce` 的 `u32` 截断与 meta nonce 域重叠（P3-1）在理论上破坏 GCM 的 nonce 唯一性，应显式拒绝越界而不是依赖注释断言。
- **域分离**：默认无 `--domain` 时 `cipher.domain_label` 不参与 L1 派生（P2-6），使「私有方言」的标签旋钮部分失效；修复涉及 golden vectors，需版本化推进。
- **掩码**：PE channel header 的 HKDF「keystream」只是公开替换表（P3-2），命名应去密码学化，避免误用。
- **KDF 策略门槛**：`verify_payload_stream` 与 `inspect_jpeg` 的 `max_pbkdf2_iterations` 不一致（P1-1、P2-15），收紧策略时有的入口白付 200k 次 PBKDF2。

### 4.5 效率与内存峰值

按影响排序：HILL O(p1²)（P2-16）→ 音频 cost O(33n) 与四份全量缓冲（W-14）→ HEVC 多份全量拷贝 + journal（P2-17）→ 只读路径整文件 `to_vec()`（W-13）→ 单次 write 重复扫描 6 次（W-17）→ JPEG APP15 O(n²)（W-18）。共同模式是「为接口便利（`&mut [u8]`、整文件 Vec）牺牲流式处理」。建议引入只读 `SlotView` trait 与 `HostScan` 缓存结构，把「一次扫描、多处复用」落到 core 层。

---

## 5. 修复路线图与验证方案

### P0（立即，阻断发布）

| 序号 | 动作 | 验证 |
| :--- | :--- | :--- |
| 1 | P0-1：FLAC body membership / `thin_pick` 改用 `analysis.slots`，补跨端不变量测试 | `cargo test --all-features --all-targets` + 新增 FLAC 补偿链用例 + `baseline --check` |
| 2 | P0-2：所有 adapter `locate` 统一物理边界等式；`meta_len`/`hint_len` 按文件实长钳制；AAD 扩至 112B + trailer + hint | 新增「伪造 trailer 的 PE/MKV」拒绝用例（不得 OOM）；`baseline --write` 重建 28 例；golden vectors 全量更新 |
| 3 | P0-3：加密非 stealth 也 mask/认证后 32B；hint 入 AAD | 新增 hint 篡改被拒用例；`verify` 三级一致性用例 |

### P1（本迭代）

统一 `CarrierPlan` 单一真源（P1-1~P1-4）→ 修 FLAC MD5 偏移与 release CRC 复核（P1-5、P1-6）→ MKV CRC 下沉 + `should_try_bridge` 错误白名单（P1-7、P1-8）→ PNG 读入校验（P1-9）→ 输出/凭据处理（P1-10）。每条都要配一条「旧行为会失败、新行为通过」的回归测试；涉及 wire 的改动统一 `baseline --write` + `docs/api/WIRE_SPEC.md` 同步。

### P2（下一迭代）

按「先正确性、后效率」顺序：P2-1~P2-3 PNG 大图路径与结构约束 → P2-4~P2-8 接口/容量/文档契约 → P2-9~P2-10 隐写分析口径 → P2-11~P2-15 参数与错误处理 → P2-16~P2-17 效率热点 → P2-18~P2-20 架构与防御性。建议每个 PR 只动一个引擎，避免 `baseline` 大面积抖动。

### P3（技术债）

集中处理理论触发项、死代码、文档漂移；建议单开一个「文档与契约一致性」提交，不改生产逻辑，仅更新 rustdoc / registry 描述 / 注释，并加 CI 断言（如 `structure/` 不得出现 `crate::stego`）。

### 每次改动后的固定门禁

```bash
cd rust
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --all-targets
cargo test local_ --all-features -- --ignored
cargo test heavy_ --all-features -- --ignored
python ../scripts/import_lint.py
python ../scripts/baseline_hash.py --check   # 改 wire/AAD 时先 --write
```

---

## 6. 误报剔除与存疑项（体现交叉复核）

| 声称 | 核实结论 | 依据 |
| :--- | :--- | :--- |
| 「`audio/core.rs` 缺 `ciphertext_len` 检查，约 64 MiB 不可压缩 payload 时 embed 成功但 extract 永久失败」 | **部分不成立**：缺检查属实（记为 P2-7），但 64 MiB 窗口**不可达**——`core.rs:725-731` 的 `MAX_WORKING_SET_BYTES = 768 MiB` 会在 ciphertext 约 0.8–3.7 MB 时先拒绝 embed | `audio/core.rs:725-731` 实读 |
| 「`audio/perm.rs` 的 `guard > 64` 常态破坏双射，embed/extract 不一致，属致命」 | **不成立**：cycle walking 数学上必终止且保持双射，embed/extract 共用同一 `at()`；回退触发概率约 2^-65 | `perm.rs:128-145` + Feistel 结构；降级为 P3-4 |
| 「`--cipher-suite 999` 会写出自身读不回的信封」 | **不成立**：写侧各引擎均有 `CipherSuiteId::from_u16(suite_id).ok_or_else(...)` 校验 | `jpeg/engine.rs:659-663`、`png/engine.rs:1344`、`hevc/engine.rs:240`、`audio/mod.rs:95`；CLI 层无即时校验仅影响报错时机 |
| 「`jpeg/header_v3.rs` 不存在，审查者臆造文件名」 | **不成立**：审查期间项目提交把 `header_v3.rs` 重命名为 `header_v4.rs` | `git show --stat HEAD` 显示 `rust/src/stego/jpeg/{header_v3.rs => header_v4.rs}` |
| 「`BUILTIN_DEFAULT_KEY` 是密钥泄露缺陷」 | **不成立（设计取舍）**：`lib.rs:28`、`crypto.rs:157-161` 明示为「无密码时统一加密以避免明文」的公开常量，不承诺保密性 | 记为 P2-13 的可读性/告警问题 |
| 「HEIF bridge 提取丢 `FileKey`」「写侧接受 critical TLV」 | **已在 HEAD 修复**，不作为现存缺陷 | `docs/CHANGES-20261103.md` 23:06:16；`engine.rs:538-541` 现有注释已说明修复 |
| 「structure 域仍存在 `structure → stego` 内联容量例外」 | **注释过时，实际无依赖** | 全目录检索 + `import_lint.py` OK；记为 P2-19 |
| 「`parse_extension` 不拒绝 critical TLV，安全契约分散」 | **写侧已修（23:06:16）**；读侧拒绝逻辑仍分散在各引擎，属残留技术债 | `header.rs` 现有 `encode_extension_for_write`；列入 W-21 待实测 |

---

## 7. 待实测验证清单（不作已确认缺陷）

> 以下条目由分组审查提出、代码证据**未在本次交叉复核中逐行确认**，或需要构造特定输入/外部解码器才能判定。列出目的是给出后续验证方向，不应据此直接改代码。

| 编号 | 位置 | 待验证声称 | 建议验证方法 |
| :--- | :--- | :--- | :--- |
| W-1 | `audio/flac/mod.rs:456-468` | `usable` 漂移的实际触发率与 payload 损坏表现 | 构造 order>0 且补偿 delta 非空的 FLAC，embed→extract 往返 + 统计 `analyse` 前后 `usable` |
| W-2 | `jpeg/engine.rs:1747` | DNL / 非 16 倍数尺寸下 probe 与 embed 块数分歧 | 用带 DNL 段、奇数尺寸的 JPEG 对比 `probe.available_slots` 与 `CoverFrame::read.n_total` |
| W-3 | `hevc/engine.rs:2517` | 4K/8K 样本中非 IRAP slice 落在 1 MiB 之后时流式/全量 `has_inter` 分叉 | 同一 MP4 分别走 `inspect_carrier_file` 与内存 embed，比对槽位集合 |
| W-4 | `png/engine.rs:567` | 8 段 Sync 拼接流在 flate2 后端与标准解码器下的可解析性、IDAT 数量保真 | 生成 >2 MiB 载体，embed 后用 `png` crate / `zlib.decompress` 解压并核对 chunk 序列 |
| W-5 | `coding/stc.rs:363-372` | 是否存在不终止的 `(seed, h, u)` 组合 | 遍历 `h∈4..=10, u∈1..=64` × 多组 seed 的终止性测试 |
| W-6 | `audio/core.rs:400-425` | `capacity_info` 三次固定点迭代是否振荡 | 扫描 `(total, budget)` 网格，检测 `u` 在 1↔3 间振荡的区间 |
| W-7 | `hevc/engine.rs:1168-1189` | `enforce_safety` 阈值随 payload 长度变化的循环依赖 | 同一载体用不同 payload 长度触发 `SafetyThreshold`，比对「载体固有容量」 |
| W-8 | `hevc/mkv_boxes.rs:511`、`heif_boxes.rs:221-230`、`mp4_boxes.rs:505` | CRC 覆盖范围假设、VCL 过滤与参数集过滤在四容器不一致 | 用 `mkvmerge`/libavformat 产出的真实带 CRC 文件、真实 iPhone HEIC 验证 |
| W-9 | `heif/thumb_bridge.rs:1104` | `thmb` 的 from/to 方向；Exif TIFF 内部偏移未随 delta 调整 | 按 ISO 23008-12 核对 + 多缩略图 HEIC 实测 |
| W-10 | `jpeg/dht.rs:135-149`、`jpeg/engine.rs:68` | DHT 段白名单不全、`map_dct_error` 依赖错误文本 | 构造带 DNL/DAC 段与 over-optimised 表的 JPEG，替换 dct_io 版本回归 |
| W-11 | `analysis.rs:480-507` | 音频无内容域检测器、`chi2` 阈值缺校准 | 在 107/216 cover 语料上测 FPR；对本工具 WAV/FLAC stego 跑 `scan` 验证是否恒 clean |
| W-12 | `cli/helpers.rs:349-359`、`cmd_structure.rs:165-166` | 三态布尔与 `embed` 硬编码 `preserve_time` | 用 `strhide.toml` 设 false 后分别带/不带正向 flag 跑 CLI 观察行为 |
| W-13 | `audio/mod.rs:228/254/578`、`commit.rs:261` | 只读路径整文件 `to_vec()`、FLAC 复制两次、`commit_carrier_patches` 同样吞恢复失败 | 大文件内存峰值测量 + 只读 API 的 `&[u8]` 重构可行性评估 |
| W-14 | `audio/cost.rs:107-116`、`audio/core.rs:816-824` | cost O(33n) 与四份全量缓冲 | 1 小时立体声 44.1 kHz 的 CPU/内存基准 |
| W-15 | `analysis.rs:295`、`cmd_diag.rs:508` | `scan --json` 丢弃失败文件、单次 read 短读 | 构造不可读文件 + 管道输入，检查 JSON 报告与退出码 |
| W-16 | `adapters/pdf.rs:564`、`jpeg.rs:236`、`heif.rs:70` | `strategy_capacities` 与 `choose_auto_strategy` 判定不一致 | 对每个 adapter 对比 inspect 报告策略与 auto 实际选择 |
| W-17 | `structure/engine.rs:887-1270` | 单次 write 重复全文件/全尾扫描 ≥6 次 | GB 级载体 I/O 计数与耗时剖析 |
| W-18 | `adapters/jpeg.rs:340-372` | 多 APP15 段 `locate` 回溯 O(n²)、段数无上限 | 构造大量微小 APP15 段的 JPEG，测 `locate` 耗时 |
| W-19 | `hevc/engine.rs:3238-3247`、`slot.rs:499-525` | 4K/8K 长视频内存峰值数 GB | 用长视频测 RSS 峰值 |
| W-20 | `hevc/engine.rs:50-57`、`jpeg/engine.rs:505`、`flac/bits.rs:137` | release 下 `debug_assert` 移除后的越界/静默写回 | release 构建 + 畸形输入 fuzz |
| W-21 | `stego/header.rs:115-121` 与各引擎 | critical TLV 读侧拒绝逻辑分散，新 reader 易漏 | 伪造带未知 critical TLV 的载体，逐个入口比对 inspect/verify/extract 结论 |
| W-22 | `rejection.rs:88-110`、`:171-186`、`:260`；`adapters/pdf.rs:225` | Authenticode 检测 fail-open、PDF 签名跨 64 KiB 窗口、JAR EOCD 后附加数据、PDF `from_utf8_lossy` 切片 panic | 构造畸形但可解析的签名 PE/PDF/JAR 实测拒绝行为 |

---

## 附录 A：模块规模与审查覆盖

| 层 | 主要文件（行数） | 审查覆盖 |
| :--- | :--- | :--- |
| `core/` | crypto 1013、i18n/messages 820、control 480、errors 435、pipeline 423、params 408、commit 390、config 316、payload 313、batch 287、fs 238、media 105 | 全量分组审查 + 关键片段复核 |
| `stego/` 核心 | options 1678、engine 1445、coding/stc 1436、format 846、coding 832、envelope 803、spatial_variance 764、header 734、prng 530、cost_calibration 512、registry/io/traits/wavelet | 全量分组审查 + 关键片段复核 |
| `stego/` 格式引擎 | hevc/engine 4551、png/engine 4425、structure/engine 2768（见下）、jpeg/engine 2134、heif/thumb_bridge 1542、audio/flac/mod 1305、audio/core 1168、mp4_boxes 1026、heif_boxes 971、mkv_boxes 949、audio/flac/frame 966、hevc/slot 983 | 全量分组审查 + 关键片段复核 |
| `structure/` | engine 2768、adapters/isobmff 2076、pdf 1176、pe_codebits 1046、pe 810、envelope 678、rejection 460、zip 503、jpeg 522、png 536、riff 407 等 | 全量分组审查 + 关键片段复核 |
| `analysis` / `cli` | analysis 2674、cli/helpers 808、cmd_diag 740、cmd_stego 722、args 680、cmd_structure 515、mod 352 | 全量分组审查 + 关键片段复核 |

## 附录 B：问题维度索引

| 维度 | 主要条目 |
| :--- | :--- |
| 代码质量 | P2-5、P2-19、P2-20、P3-9、P3-13 |
| 算法实现 | P0-1、P1-3、P1-4、P2-6、P2-8、P2-9、P2-16、P3-3、P3-4 |
| 接口与参数 | P1-1、P1-2、P1-4、P2-4、P2-7、P2-11、P2-12、P2-13、P2-15、P3-10 |
| 算法效率 | P2-1、P2-16、P2-17、W-13、W-14、W-17、W-18、W-19 |
| 可靠性健壮性 | P0-2、P1-5~P1-9、P2-3、P2-14、P2-20、P3-1、P3-8、P3-11、P3-12 |
| 功能缺陷 | P0-1、P1-1、P1-5、P1-7、P2-2、P2-4、P2-10 |
| 架构设计 | P0-2、P1-7、P2-18、P2-19、P3-7 |

## 附录 C：本报告引用的关键门禁输出

```
cargo clippy --all-targets --all-features -- -D warnings
  → Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.03s   (0 warning)

cargo fmt --check → fmt_exit=0

cargo test --all-features --all-targets → EXIT=0
  lib: 482 passed; 1 ignored
  test_cli 132 / test_lifecycle 143 / test_media 12 / test_pe 40 /
  test_regression 101 / test_security 18 全绿
  heavy 5 ignored、local 2 passed + 18 ignored

python scripts/import_lint.py
  → OK: all architectural boundaries intact
    (structure !-> stego, stego !-> structure,
     core !-> {formats, structure, stego, cli})

python scripts/baseline_hash.py --check
  → check OK: 28 cases identical to baseline
```

---

*报告结束。本报告只做只读审查，未修改任何生产代码；临时测试输出保存在 `temp/review_test_output.txt`。*
