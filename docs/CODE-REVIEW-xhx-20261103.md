# strhide Rust 代码审查报告（xhx）

> 审查时间：2026-11-03
> 审查对象：`rust/`（crate `strhide` 0.8.5，67,149 行 Rust，220 个 `.rs` 文件）
> 审查方式：文档与代码交叉核对 + 逐文件静态阅读 + 可执行最小复现实证。凡标注「实测」的结论均由本轮实际运行得到，未实测者明确标注为「静态核对」。
> 审查基线：`AGENTS.md`、`docs/api/ARCHITECTURE.md`、`docs/api/WIRE_SPEC.md`、`docs/api/STEGO-API.md`、`docs/smart_file_data_hiding_design.md`、`docs/lib_interface_audit_and_refactoring_plan_20261103.md`、`docs/CHANGES-20261030.md`～`docs/CHANGES-20261103.md`。
> 与既有报告的关系：`docs/CODE-REVIEW-20261103.md` 已覆盖部分结论（HEVC 无口令拉伸、`ExtractParams` 只在 JPEG 生效、`.bak` 竞态、弱嗅探）。本报告**不重复论证**这些条目，只在能给出新证据时引用并标注「已确认」。本报告的新增贡献集中在：结构域写/校验/恢复三端约定不一致、双域复合的实际破损、容量声明与实际可达容量不符、PBKDF2 重复计算的量化、以及可复现的测试/CI 缺口。

---

## 0. 审查环境与可复现前提

| 项 | 值 |
|---|---|
| Rust | `rustc 1.99.1` / `cargo 1.99.1` |
| 命令 | `cargo test --all-features --all-targets`、`cargo clippy --all-targets --all-features`、`python scripts/import_lint.py` |
| 结果 | clippy **0 警告 0 错误**；`import_lint` **通过**；测试 **1 次失败 / 若干次全绿**（见 XH-13，非确定性） |
| 语料 | 仓库自带 `rust/tests/assets/*`（png/jpg/heic/mp4/mkv/wav/flac/webp/zip/pdf） |

静态质量基线本身是好的：`cargo clippy --all-targets --all-features` 零告警，三层架构红线由 `scripts/import_lint.py` 强制，`unsafe` 仅出现在 5 处（i18n Win32 调用、STC AVX2 内核、J-UNIWARD AVX2 内核），且每处都有 SAFETY 注释与运行时 `is_x86_feature_detected!` 门。本报告的问题不在「有没有 lint 告警」，而在**跨端约定、容量声明、以及 CI 覆盖不到的路径**。

---

## 1. 结论摘要

代码的**单域主路径**实现质量高：原子提交（temp + fsync + rename + TmpGuard）、还原前 SHA-256 强制比对、AEAD 覆盖 80 字节 AAD、分块长度自定界、解压上限、非规范输入拒绝，这些都有对应代码与测试。13 种载体（含 4 种 Office 扩展名）的 `write → verify → read → restore` 生命周期实测全部通过、逐字节还原。

问题集中在**跨组件的边界约定**上，且多数属于「两端各自看起来都对，但组合起来不成立」：

1. **结构域与内容域复合后，结构信封失去可校验性与可还原性**（PNG 确定性复现）。文档明确宣称双向顺序无关（`ARCHITECTURE.md` §7.3 第 6 条），实际只有 `Content → Structure` 成立。
2. **同一格式的写入端、定位端、校验端对同一物理布局采用三套不同约定**（RIFF/WAV 末块 pad；PNG 位移 chunk；ISO-BMFF `size == 0`）。
3. **对外声明容量与实际可达容量不符**（JPEG `app_segment` 声明 64 MiB，实测上限 16,776,104 B）。
4. **口令路径的 PBKDF2 被重复计算**：一次 `read` 3 次、一次 `verify` 5 次，其中至少 1～2 次是可证明的纯浪费（实测 30.02 ms vs 理论 19.8 ms；verify 56.16 ms vs 理论 39.6 ms）。
5. **CI 与文档的守护声明不成立**：双域共存矩阵测试是 `#[ignore]`，CI 不跑；文档称 doc test 由 CI 守护，CI 里没有 `--doc`。

### 问题统计

| 级别 | 数量 | 编号 |
|---|---:|---|
| 严重 | 2 | XH-1, XH-2 |
| 高 | 3 | XH-3, XH-4, XH-5 |
| 中 | 5 | XH-6 ～ XH-10 |
| 低 | 5 | XH-11 ～ XH-15 |

### 按维度分布

| 维度 | 条目 |
|---|---|
| 架构设计 | XH-1（域间复合契约缺失）、XH-10（公开模块面全部 `pub`）、XH-14（`structure/mod.rs` 文档描述已删除的跨域例外） |
| 库接口/参数 | XH-6（`StrategyChoice` 静默吞错并成为死 API）、XH-9（`HevcParams` 空结构体却进入公开调优枚举）、XH-5（`ExtractParams` 覆盖面，已确认） |
| 代码质量 | XH-11（varint 非规范编码被接受）、XH-12（`expect` 在公开路径 + `panic = "abort"`）、XH-13（测试自身非确定性） |
| 算法/性能 | XH-7（PBKDF2 重复 + verify 双开）、XH-8（`SegmentedSubStream` O(n²)）、`Auto` 压缩无预检 |
| 可靠性/稳定性 | XH-2（容量声明不可达）、XH-3（写入端不校验宿主结构）、XH-4（解密后才查上限） |
| 文档一致性 | §5 对照表（13 处） |

---

## 2. 严重问题

### XH-1 结构域与内容域复合后，结构信封失去可校验性，且 PNG 无法还原

**级别：严重｜维度：架构 / 可靠性**

**位置**

| 文件 | 行 | 作用 |
|---|---|---|
| `rust/src/structure/adapters/png.rs` | 264-285 | `locate` 对「被内容域压缩后位移」的 `prIv` chunk 的接受分支 |
| `rust/src/structure/engine.rs` | 2346-2394 | `envelope_coordinates_agree`（Level 2 坐标交叉校验） |
| `rust/src/structure/adapters/mod.rs` | 264-320 | `HostAdapter::strip` 默认实现（按 header 的 `inject_offset/size` 切片） |
| `docs/api/ARCHITECTURE.md` | 534-535 | 「双向（Content->Structure 与 Structure->Content）顺序无关性」的宣称 |

**证据（实测）**

对 `tests/assets/small.png`（7,908 B）先做结构域写入，再做内容域嵌入：

```text
cover            = 7908 B
structure write  = strategy=chunk  ube=227  → 8147 B   (prIv chunk 位于 7896..)
content embed    = 8147 B → 6913 B   (IDAT 重压缩，物理尺寸缩短 1234 B)
→ structure read          : Ok("secret-payload")        ← 仍可读
→ structure verify L2     : false
      "Header coordinates disagree with the envelope:
       inject_offset 7896 + delta 8 = 7904, but the envelope sits at 6704"
→ structure restore_bytes : Err(Corrupted data: Unexpected EOF while copying stream)
```

同一流程换成 stealth 或私有 `magic` 方言：

```text
official/plain        → read=OK    verify L2=false   restore=FAIL
official/stealth      → read=FAIL  verify L2=false   restore=FAIL
private-magic/plain   → read=FAIL  verify L2=false   restore=FAIL
private-secret        → read=OK    verify L2=false   restore=FAIL
```

**根因（两处独立缺陷叠加）**

1. `png.rs:267-280` 的「位移补偿」分支把头部魔数硬编码为公开常量：

```rust
// rust/src/structure/adapters/png.rs:267-280
if trailer.ube_total_size == length {
    let is_exact = trailer.ube_offset == chunk_data_offset;
    let is_valid_shifted = if !is_exact {
        stego_in.seek(SeekFrom::Start(chunk_data_offset))?;
        let mut hdr = [0u8; 8];
        if stego_in.read_exact(&mut hdr).is_ok() {
            hdr == crate::params::STANDARD_HEADER_MAGIC      // ← 只认官方魔数
        } else { false }
    } else { false };
```

stealth 的魔数由口令派生、私有方言的魔数由 `StructureProfile::magic` 指定，永远不等于 `STANDARD_HEADER_MAGIC`，因此该分支对这两类信封恒为 `false`，`locate` 只落到 EOF 兜底（而 `prIv` 在文件中段，EOF 兜底也不成立），最终报 `NoHiddenData`。**结果是：一个用 stealth 写入的信封，只要用户对同一张 PNG 做了一次内容域嵌入，就永久读不出来了。**

2. 位移只被 `locate` 容忍，没有被任何写回路径消费。header 中的 `inject_offset/inject_size` 仍是写入时的值，而 `strip` 默认实现严格按这两个值切片：

```rust
// rust/src/structure/adapters/mod.rs（默认 strip）
copy_exact(stego_in, out, header.inject_offset)?;            // 7896，已越过真实信封
let inject_end = header.inject_offset + header.inject_size;  // 8137，已越过文件尾
stego_in.seek(SeekFrom::Start(inject_end))?;                  // → 读到 EOF
copy_stream(stego_in, out)?;
```

`inject_end` 超出文件长度 → `copy_stream` 读 0 字节 → 但前面已经复制了 7896 字节（其中包含 1234 字节不属于「信封之前」的内容），最终 `verify_restored` 的 SHA-256 必然不符；若越界更多则直接 `Unexpected EOF`。`TmpGuard` 保证失败时不落盘，所以不丢数据，但**用户从此无法清理这张图片**，只能手工处理。

**影响面**：所有「先 `write` 后 `embed`」的 PNG 载体；stealth 与私有方言用户命中概率 100%，官方方言用户命中 `verify`/`restore` 失败。GUI 的 `smart_extract` 走 `inspect_any`，会因 `has_hidden_data` 判为 false 而静默选错域。

**修复方向**

- 短期（不改线格式）：把 `is_valid_shifted` 的魔数判据改为「用本次 locate 期望的 trailer 魔数反查」——`locate` 已拿到 `expected_trailer_magic`，其中 stealth 分支由调用方派生，可将其对应的 header 魔数一并传入；私有方言用 `profile.header_magic()`。同时 `strip` 不应盲信 header 坐标，应先用 `locate` 得到的实际 `ube_offset` 重算等价 `inject_offset`，或在 header 未认证字段中无法自洽时拒绝并给出明确诊断（「envelope was displaced by a content-domain rewrite; restore is not possible」）。
- 长期：把「信封物理位置」从 header 移除，改为完全由 `locate` 决定，header 只保留 `orig_host_size/sha256` 与协议字段。header 的 `inject_offset` 不参与 AAD（`AAD_SIZE = 80`，`inject_offset` 位于偏移 80），本来就不是可信字段，把它当作恢复依据本身即设计缺陷。
- 回归测试：`png_structure_then_content_roundtrip`，覆盖 official/stealth/private-magic 三种方言 × `read`/`verify`/`restore` 三个动作，共 9 个断言。当前 `heavy_dual_domain_coexistence_matrix` 只断言「能提取两个载荷」，**不断言 verify/restore**，而且它是 `#[ignore]`（见 XH-13）。

---

### XH-2 JPEG `app_segment` 声明 64 MiB 容量，实际可达上限 16 MiB，且 `auto` 会选中这条不可用路径

**级别：严重｜维度：可靠性 / 接口契约**

**位置**

| 文件 | 行 | 内容 |
|---|---|---|
| `rust/src/structure/adapters/jpeg.rs` | 18 | `MAX_JPEG_HEADER_SCAN = 16 MiB` |
| `rust/src/structure/adapters/jpeg.rs` | 221-233 | `choose_auto_strategy` |
| `rust/src/structure/adapters/jpeg.rs` | 238-246 | `strategy_capacities` 声明 `JPEG_MAX_TOTAL_CAPACITY` |
| `rust/src/structure/adapters/jpeg.rs` | 17 | `JPEG_MAX_TOTAL_CAPACITY = 64 MiB` |
| `rust/src/structure/adapters/jpeg.rs` | 73-75 | `scan_jpeg_markers` 在超过 16 MiB 时返回 `HeaderScanLimit` |

**证据（实测）**

`inspect_carrier` 对 `tests/assets/small.jpg` 的声明：

```text
app_segment  available=true  cap=Some(67108864)  limit="<= 67,108,864 B (64 MiB)"
```

而二分搜索「实际能通过写入自检的最大载荷」：

```text
8  MiB : write=OK   read=OK(true)
15 MiB : write=OK   read=OK(true)
16 MiB : write FAILED: Post-write self-check failed: the envelope written via
         strategy 'app_segment' cannot be located again in the output
17 MiB : write FAILED（同上）
20 MiB : write FAILED（同上）

largest app_segment payload that survives the self-check: 16,776,104 B (16.00 MiB)
```

**根因**

`inject` 把整条 UBE 切成 `ceil(ube/65533)` 个 APP15 段插在 SOS 之前，于是 **SOS 的物理偏移被推到 `原始SOS + ube_size`**。而定位与校验都依赖 `scan_jpeg_markers`，它在 `marker_offset > MAX_JPEG_HEADER_SCAN`（16 MiB）时提前返回 `JpegScanEnd::HeaderScanLimit`，根本走不到 SOS，也走不完全部 APP15 段：

```rust
// rust/src/structure/adapters/jpeg.rs:72-75
let marker_offset = in_reader.stream_position()?;
if marker_offset > MAX_JPEG_HEADER_SCAN {
    return Ok(JpegScanEnd::HeaderScanLimit);
}
```

`choose_auto_strategy` 的判据却是「原始载体能否找到 SOS」＋「ube ≤ 64 MiB」，两者都与注入后的实际布局无关：

```rust
// rust/src/structure/adapters/jpeg.rs:221-233
fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, ube_size: u64) -> &'static str {
    if ube_size > JPEG_MAX_TOTAL_CAPACITY { return "eof"; }
    if find_jpeg_sos_offset(reader).is_err() { return "eof"; }
    "app_segment"
}
```

因此 16 MiB < ube ≤ 64 MiB 的载荷会被 `auto`（默认策略）选中 `app_segment`，注入成功，然后在 `write_core` 的写后自检（`engine.rs:1268-1276`）失败。**用户看到的是一条「写入失败」+ 一条内部自检信息，而 `inspect` 刚刚告诉他这条策略能装 64 MiB。**

这同时是一处**拒绝优先原则的破口**：容量探测（`inspect`）、策略选择（`auto`）、注入（`inject`）、写后自检（`locate`）四个环节对「可用容量」给出了三个不同答案。

**影响面**：所有格式为 JPEG、`strategy=auto`、载荷 16～64 MiB 的写入；`--strategy app_segment` 显式指定时同样命中。`auto` 在该分支里没有二次回退到 `eof`，因此这条路径必然失败。

**修复方向**

- 让 `MAX_JPEG_HEADER_SCAN` 成为容量的**唯一**约束：`capacity_bytes = Some(min(JPEG_MAX_TOTAL_CAPACITY, MAX_JPEG_HEADER_SCAN - 原始SOS偏移 - 段头开销))`，或直接把 `JPEG_MAX_TOTAL_CAPACITY` 降到 ≤ 16 MiB 并同步 `choose_auto_strategy`。
- `choose_auto_strategy` 的判据应从「载体能否解析」改为「`原始SOS + ube_size + 段头 ≤ MAX_JPEG_HEADER_SCAN`」，并在不满足时返回 `eof`（而不是让 `inject` 成功、自检失败）。
- 增加 `jpeg_capacity_matches_reachable_max`：对 2/16/64 MiB 三档断言 `probe` 声明的上限能真正 `write` 成功。

---

## 3. 高严重级别问题

### XH-3 写入路径不校验宿主结构，非载体文件被静默追加/改写

**级别：高｜维度：可靠性 / 违反设计原则**

**位置**

| 文件 | 行 | 内容 |
|---|---|---|
| `rust/src/structure/engine.rs` | 889-936 | `write_core` 只做 `find_adapter_or_reject` + `locate` 占用扫描 |
| `rust/src/structure/engine.rs` | 2406 | `verify_structure` 的唯一调用点（在 `verify_core` 里） |
| `rust/src/structure/adapters/isobmff.rs` | 278-282 | `size == 0` 视为「到文件末尾」 |
| `rust/src/structure/adapters/jpeg.rs` | 221-233 | SOS 不可达时回退 `eof` |

**证据（实测）**

```rust
// 1) 随机字节 + 前两字节 FF D8
fake-jpeg: ACCEPTED strategy=eof len 20002->20216
           verify L1=false "Corrupted JPEG structure: JPEG SOS marker not found"
           read=Ok(1)  restore=Ok(true)

// 2) 随机字节 + 偏移 4 处为 "ftyp"，size 字段 = 0
fake-mp4 : ACCEPTED strategy=box_uuid len 20008->20246
           verify L1=TRUE  "Valid ISO BMFF container (1 top-level boxes)"
           read=Ok(1)  restore=Ok(true)
```

第二例尤其严重：`isobmff_verify_structure` 把 `size == 0` 解释为「该 box 延伸到文件末尾」，于是**任意二进制只要偏移 4..8 是白名单 4CC 且前 4 字节为 0，就被判定为「合法单 box ISO BMFF」**，Level 1 校验直接放行。`box_uuid` 策略随后向其中插入一个 24 字节 uuid box，文件被永久改变。

```rust
// rust/src/structure/adapters/isobmff.rs:278-282
} else if size == 0 {
    (total_size - offset, 8u64)     // ← 无法与「伪造的 8 字节头」区分
}
```

**根因**

1. `write_core` 的检查顺序是「识别格式 → 扫描是否已有信封 → 写入」，**没有** `adapter.verify_structure`。全仓 `verify_structure` 只有一处调用，在 `verify_core`（`engine.rs:2406`）。这与 `ARCHITECTURE.md` §1「拒绝优先（Rejection-first）：在任何字节落盘之前拒绝」以及 `registry.rs` 中 `ADAPTERS` 注释「无法识别的文件会被拒绝，而不是被静默追加」直接矛盾。
2. 格式识别本身是弱判据：JPEG 只比 2 字节 SOI（`detect` 在 `jpeg.rs:204-217`），ISO-BMFF 只比偏移 4 的 4CC。弱判据 + 无结构校验 + `auto` 回退 `eof`/`box_uuid` = 任意文件都可能被改写。
3. ISO-BMFF 的 `size == 0` 语义被当作「合法」，使 L1 校验失去了区分能力。

**修复方向**

- `write_core` 在 `find_adapter_or_reject` 之后、任何写入之前调用 `adapter.verify_structure(host)`，失败即 `Rejection`。这与「拒绝优先」一致，且成本是一次流式遍历（JPEG/PNG/ZIP 的校验实现已是流式）。
- ISO-BMFF 的 L1 校验要求「至少一个 box 的 `size != 0`，且存在 `ftyp`，且 `ftyp` 的 major_brand 属于已知集合或 `ftyp` box 长度 ≥ 8`」。`size == 0` 只允许出现在最后一个 box，且必须已有 ≥ 1 个显式尺寸 box。
- 增加 `write_refuses_a_file_that_only_looks_like_a_jpeg` / `..._mp4` 两个回归测试。

---

### XH-4 `read`/`verify` 在完整解密之后才检查解压上限，公开密钥信封可触发 1 GiB 内存放大

**级别：高｜维度：可靠性 / 资源耗尽**

**位置**

| 文件 | 行 | 内容 |
|---|---|---|
| `rust/src/structure/engine.rs` | 1629-1665 | `read_core`：先 `decrypt_stream_from_chunks` 全量入内存，再检查 `raw_size` |
| `rust/src/core/crypto.rs` | 618-620 | `MAX_VERIFY_PAYLOAD_SIZE = 1 GiB` |
| `rust/src/structure/engine.rs` | 1647-1653 | 检查点位于解密之后 |
| `rust/src/core/crypto.rs` | 564-591 | `decompress_stream` 以 `limit` 为界（这一处是正确的） |

**证据（静态核对 + 代码路径）**

```rust
// rust/src/structure/engine.rs:1637-1653
let mut decrypted_payload = Vec::new();
decrypt_stream_from_chunks(          // ← 先把整个明文载荷读进 Vec
    &mut env.ube_stream, &mut decrypted_payload, ...)?;

let max_safe_size = crate::crypto::MAX_VERIFY_PAYLOAD_SIZE;
if env.meta_obj.raw_size > max_safe_size {     // ← 检查在之后
    return Err(...);
}
let data = if env.header.is_compressed() {
    let mut decomp = Vec::with_capacity(env.meta_obj.raw_size.min(1024*1024) as usize);
    decompress_stream(&mut Cursor::new(&decrypted_payload), &mut decomp, env.meta_obj.raw_size)?;
```

`decrypt_stream_from_chunks` 的分配上界是「认证过的 `total_payload_bytes`」，而该值来自 header 与 `ube_total_size` 的差值——两者都在攻击者控制下。因此攻击链是：

1. 取任意载体，用公开默认密钥（`BUILTIN_DEFAULT_KEY`，源码里就有）构造一个「无密码」信封；
2. 声明 `meta.raw_size = 1 GiB`，载荷写一段 8 KiB 的全零 deflate 流（压缩比 1:1000+）；
3. 载体文件只有几十 KB，`read_core` 会先解出完整明文、再分配最多 1 GiB 解压缓冲。

`verify_l3_stream`（`engine.rs:1708-1718`）走 `verify_payload_stream`，它在开头就检查 `total_payload_bytes/expected_raw_size > limit`，**这条路径是正确的**；但 `read_core` 这条最常用的路径没有。两者行为不一致。

**影响面**：任何把 `strhide` 当库用的服务端（HTTP/GUI 批量处理）——攻击者只需上传一个小文件。CLI 单次调用同样会吃满 1 GiB。

**修复方向**

- 把上限检查前移到 `open_and_authenticate_envelope` 返回之后、`decrypt_stream_from_chunks` 之前：`if env.meta_obj.raw_size > limit || env.total_payload_bytes > limit { return Err(...) }`。
- 更彻底：`read_core` 改为「解密 → 解压 → SHA-256」单遍管线（`verify_l3_stream` 已经是这个形状），让 `read` 与 `verify` 共享同一条流式实现，顺带消掉 XH-7 的重复工作。
- 上限不要用绝对常量，改为 `min(1 GiB, max(64 MiB, carrier_len * 256))`，并允许 `ReadOptions` 覆盖。

---

### XH-5 `ExtractParams` 的 KDF 上限/套件白名单只在 JPEG 生效（已确认，附新增证据）

**级别：高｜维度：接口契约 / 安全策略**

**位置**

| 文件 | 行 | 内容 |
|---|---|---|
| `rust/src/stego/params.rs` | 622-658 | `ExtractParams` / `allows_suite` / `max_pbkdf2_iterations` |
| `rust/src/stego/jpeg/engine.rs` | 1182, 1185 | **唯一**执行点 |
| `rust/src/stego/engine.rs` | 221-236 | PNG `extract` 不接收 `limits` |
| `rust/src/stego/engine.rs` | 517-521 | HEVC `extract` 不接收 `limits` |
| `rust/src/stego/engine.rs` | 1014-1020 | FLAC `extract` 不接收 `limits` |
| `rust/src/stego/engine.rs` | 1136-1147 | WAV `extract` 不接收 |

**新增证据（实测计数）**

```text
$ grep -rn "allows_suite\|max_pbkdf2_iterations" src/ | grep -v params.rs
src/stego/jpeg/engine.rs:1182:        if !extract.allows_suite(suite.id) {
src/stego/jpeg/engine.rs:1185:        if suite.cost() > extract.max_pbkdf2_iterations {
src/stego/options.rs:871:    pub fn with_max_pbkdf2_iterations(mut self, iterations: u32) {
src/stego/options.rs:872:        self.limits.max_pbkdf2_iterations = iterations;
```

除 JPEG 外的 4 个引擎（PNG/HEVC/WAV/FLAC）对这两个字段零引用。`InspectOptions.limits` 同样是死字段（`inspect_jpeg_from` 也不接收它）。

**为什么仍列为「高」**：`with_allowed_suites(vec![])` 在 JPEG 上能让提取立即返回，在 PNG/HEVC/音频上却是**完全无效的公开 API**。一个按文档（`STEGO-API.md` §2.2「读侧：只有凭据与上限」）实现 DoS 防护的服务端，会在 4/5 的格式上被 200 万次 PBKDF2 打满 CPU。这不是「功能缺失」，而是「安全策略静默失效」。

**修复方向**：见既有报告 H-3；补充一点——若短期不改签名，至少在 `ExtractParams` 的文档与 `STEGO-API.md` 上标注「仅 JPEG 生效」，并把 `InspectOptions.limits` 删除或标注为保留字段，避免误用。

---

## 4. 中严重级别问题

### XH-6 `StrategyChoice` 把未知策略名静默降级为 `Auto`，且它是未被使用的死 API

**级别：中｜维度：接口设计**

**位置**：`rust/src/structure/options.rs:36-45`、`:14-31`；`rust/src/lib.rs:189,233`；`rust/src/structure/mod.rs:29`

**证据（静态核对）**

```rust
// rust/src/structure/options.rs:36-45
impl From<&str> for StrategyChoice {
    fn from(s: &str) -> Self {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
            Self::Auto
        } else if let Some(id) = StrategyId::from_name(trimmed) {
            Self::Named(id)
        } else {
            Self::Auto          // ← "chunkk" / "pe_codebit" 一律变成 auto
        }
    }
}
```

对比 `WriteOptions.strategy` 这条真正的入口：`engine.rs:1073-1080` 对未注册名字返回 `General("Strategy '...' not supported by adapter")`，`strategy_to_id` 也返回错误。也就是**两条同义 API 的错误语义相反**：一条严拒，一条静默吞掉。

同时 `grep -rn "StrategyChoice" src/` 显示除定义、`mod.rs` 重导出、`lib.rs` 重导出和它自己的单元测试外，**没有任何调用点**；`WriteOptions::with_strategy_choice` 也只被测试使用。它是一条对外承诺、对内无消费者的第二条真相源。

**影响**：下游若用 `StrategyChoice::from(user_input)` + `with_strategy_choice`，拼写错误会被静默改成 `auto`，进而可能选到 `eof`——把数据追加到文件末尾而不是写进私有 chunk，用户完全无感（`strategy_note` 只在 `auto` 回退时给出说明，且是英文自由文本）。

**修复方向**：把 `From<&str>` 改为 `TryFrom<&str>`（或返回 `Option<Self>`），错误类型复用 `StrategyId::from_name` 的 `None`；或者干脆删除 `StrategyChoice`，让 `WriteOptions.strategy: &str` 成为唯一入口并保留其严格校验。

---

### XH-7 口令路径 PBKDF2 重复计算：`read` 3 次、`verify` 5 次，其中 1～2 次可证明为纯浪费

**级别：中｜维度：算法性能**

**位置**

| 文件 | 行 | 内容 |
|---|---|---|
| `rust/src/structure/envelope.rs` | 491-513 | `unpack_with_secrets` 无条件派生 default mask |
| `rust/src/structure/engine.rs` | 1521-1567 | `open_and_authenticate_envelope` |
| `rust/src/structure/engine.rs` | 2431-2529 | `verify_core` 的 Level 2 独立解包 |
| `rust/src/structure/engine.rs` | 1699-1718 | `verify_l3_stream` 再次 `open_and_authenticate_envelope` |

**证据（实测，release 构建，Windows / x86_64）**

```text
1 × PBKDF2 (derive_keys, 100k 次)      :   9.89 ms   ← 1 个成本单位
read_bytes   (password)                :  30.02 ms   ≈ 3.0 单位
inspect_bytes(password)                :  37.30 ms   ≈ 3.8 单位
verify_bytes (password)                :  56.16 ms   ≈ 5.7 单位
restore_bytes(password)                :  28.62 ms   ≈ 2.9 单位
read_bytes   (stealth, password)       :  18.56 ms   ≈ 1.9 单位
verify_bytes (stealth, password)       :  56.61 ms   ≈ 5.7 单位
```

**根因一（1 次纯浪费）**：`secrets.default` 在「调用方给了密码」时被显式置为 `None`（`engine.rs:1558-1562`），但 `unpack_with_secrets` 对这个 `None` 的解释是「还没算，我来算」：

```rust
// rust/src/structure/envelope.rs:493-496
let default_mask = match &secrets.default {
    Some(s) => Some(s.header_mask),
    None => Some(crate::crypto::derive_header_mask(profile.secret(), &salt)?),   // ← 完整 PBKDF2
};
```

于是**每个带密码、非 stealth 的 `read` 都会额外用公开内置密钥跑一遍 100k 次 PBKDF2**，而它的结果在「密码分支已匹配」时根本不会被使用（该分支在 `:506-512` 的判据里已经要求 `FLAG_ENCRYPTED == 0`，密码信封必然不满足）。这也解释了为什么 stealth 读只要 18.56 ms（≈2 单位：locate 的 magic + `derive_all`），而普通加密读要 30.02 ms（≈3 单位）。

**根因二（verify 双开）**：`verify_core` 的 Level 2 用 `open_ube_reader` + `unpack_with_profile` 独立解包一次（内部 `derive_stealth_magics` + `derive_header_mask` = 2 单位），Level 3 又调用 `verify_l3_stream` → `open_and_authenticate_envelope`（`derive_stealth_magics` + `derive_all` + 上面的 default mask = 3 单位）。合计 5 单位 ≈ 50 ms，与实测 56 ms 吻合。

**影响**：批处理 1000 张带密码的 PNG，`verify` 一项就多花约 46 秒纯 CPU；GUI 单次点击 `verify` 有 ~56 ms 的固定延迟。属于「无正确性风险但可优化的确定性浪费」，且优化路径清晰。

**修复方向**

1. `UnpackSecrets` 增加一个显式布尔 `default_mask_known: bool`（或改成 `Option<Option<PasswordSecrets>>`），让「不需要 default 分支」与「还没算」可区分；`open_and_authenticate_envelope` 在 `password.is_some() && header.is_encrypted()` 时传「不需要」。这一步单独就能砍掉 1/3 的 `read` 成本。
2. `verify_core` 把 Level 2 与 Level 3 合并：复用同一个 `AuthenticatedEnvelope`（它已经持有 `ube_stream`、`header`、`payload_key`），L2 校验坐标与 trailer，L3 直接在同一 `ube_stream` 上做 `verify_payload_stream`。可把 5 单位降到 2～3 单位。
3. 增加一个 `#[ignore]` 的性能回归测试，断言「PBKDF2 调用次数 ≤ 2」，用计数而非时间来断言，避免机器差异。

---

### XH-8 `SegmentedSubStream` 每次 `read` 从头线性扫描段表，整体 O(段数²)

**级别：中｜维度：算法性能**

**位置**：`rust/src/structure/adapters/mod.rs:355-472`（`SegmentedSubStream::read` / `seek`）

**证据（实测 + 复杂度建模）**

`read` 与 `sync_inner_seek` 每次都从 `segments[0]` 开始累减 `rem`，没有缓存当前段索引：

```rust
// rust/src/structure/adapters/mod.rs:407-425
let mut rem = self.logical_pos;
let mut target_seg = None;
for &(start, len) in &self.segments {      // ← 每次 read 都从头扫
    if rem < len { target_seg = Some((start, len, rem)); break; }
    rem -= len;
}
```

按实际读取模式（每次 `read` 最多消费 64 KiB，而段长是 65,533 B）建模，累计比较次数为：

```text
段数= 1,000 (≈64 MiB)   read() 调用= 1,000   累计比较=    500,500
段数=16,000 (≈1.0 GiB)  read() 调用=16,000   累计比较=128,008,000
段数=64,000 (≈3.9 GiB)  read() 调用=64,000   累计比较=2,048,032,000
```

目前唯一的使用者是 JPEG 多段链（`jpeg.rs:444`），其容量被 `JPEG_MAX_TOTAL_CAPACITY` 限制在 64 MiB（≈1,009 段），所以现状是 50 万次比较——可接受。**但这是一个「靠外部常量兜住复杂度」的结构**：一旦 XH-2 把容量上限修到 16 MiB 之外（或将来支持更大的多段载体），就会变成 10⁹ 级比较。同时 `seek` 也是 O(段数)，而 `verify_payload_stream` / `decrypt_stream_from_chunks` 会在每块开始时做一次 `seek`，进一步放大。

**修复方向**：在结构体中缓存 `seg_idx` 与 `seg_start`，`read`/`seek` 只在需要时向前/向后移动，均摊 O(1)；段表本身是单调递增的，可以二分。加一个 `segmented_substream_is_linear_in_segments` 的计数测试。

---

### XH-9 `HevcParams` 是空结构体，却出现在公开的 `StegoTuning` 分支里且被 `resolve()` 完全忽略

**级别：中｜维度：接口设计**

**位置**：`rust/src/stego/options.rs:249-250`、`:281-287`、`:404-406`；`rust/src/stego/mod.rs:78`

**证据（静态核对）**

```rust
// rust/src/stego/options.rs:249-250
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HevcParams {}
```

```rust
// rust/src/stego/options.rs:404-406
#[cfg(feature = "content-hevc")]
StegoTuning::Hevc { mode, .. } => resolved.hevc_mode = *mode,   // ← params 被 .. 丢弃
```

`StegoTuning::Hevc { mode, params }` 的 `params` 字段在 `resolve()` 里被 `..` 吞掉，`ResolvedTuning` 里也没有对应字段。也就是说：**公开 API 让调用方填一个永远为空的参数类型，并承诺它能调优，实际零效果。** 注释（`:240-247`）坦承「The type exists so the StegoTuning arm and the plumbing around it are written once」，但这对调用方是不可见的——GUI 或第三方会以为设置 `HevcParams` 有意义。

**修复方向**：短期在 `HevcParams` 的 doc 上明确写「当前无字段，保留位，传入的任何值都不生效」；中期要么把真实旋钮（drift ladder 上限、WPP 开关、STC `h/u` 覆盖）落进去，要么把 `params` 字段从枚举里删掉（`Hevc { mode }`）。

---

### XH-10 公开模块面：所有内部模块 `pub mod`，`#[doc(hidden)]` 只标了 6 个

**级别：中｜维度：架构 / API 稳定性**

**位置**：`rust/src/lib.rs:139-170`；`rust/src/structure/mod.rs:20-26`；`rust/src/stego/mod.rs:14-45`

**证据（静态核对）**

`structure` 下 7 个子模块全部 `pub mod`（`adapters`、`engine`、`envelope`、`options`、`params`、`registry`、`rejection`）；`stego` 下 20 个子模块里只有 `coding`、`envelope`、`header`、`prng`、`wavelet` 标了 `#[doc(hidden)]`，`jpeg::{dht, geometry, header_v3, v3_layout}`、`hevc::{bitstream, error, heif_boxes, slot, sniff}` 等**没有**。`STEGO-API.md` §1 明确把这批列为「内部面 Internal（无承诺）」，但代码层面没有任何强制，`docs.rs` 也会照常生成文档。

这与 `ARCHITECTURE.md` §3.2 的「可见但不代表稳定 API」是一致说法，但缺少机制：一个下游 crate 写了 `use strhide::stego::jpeg::dht::...` 就能编译通过，之后重构即破坏 semver。

**修复方向**：对 `STEGO-API.md` 列为 Internal 的模块统一加 `#[doc(hidden)]`（不改变可见性，避免破坏现有下游），并在 CI 增加一条脚本检查「新增 `pub mod` 必须出现在白名单里」。

---

## 5. 低严重级别问题

### XH-11 `take_varint` 在第 10 字节静默丢弃高位，非规范编码被当作合法值

**位置**：`rust/src/structure/engine.rs:177-194`

**证据（实测，复刻同逻辑）**

```text
decode([0x80;9] ++ [0x7F]) = Ok(9223372036854775808)   // 2^63，第 10 字节只有 bit0 生效
decode([0xFF;10])           = Err("too long")
```

第 10 次循环时 `shift = 63`，`((byte & 0x7f) as u64) << 63` 只剩最低位，其余 6 位被静默丢弃。`decode_compact`（`:234-273`）也不检查 `pos == bytes.len()`，尾部多余字节被忽略。

**影响**：`raw_size`/`created_at` 可被构造成「解码成功但数值错误」；错误值会传给 `decompress_stream` 的上限，导致误报 `CorruptedData` 而非「元数据非法」。不构成越界（`shift` 不会 ≥ 64），因此定级为低。

**修复**：`shift >= 64` 或 `shift == 63 && (byte & 0x7e) != 0` 时返回 `CorruptedData("varint overflows u64")`；`decode_compact` 末尾校验 `pos == bytes.len()`。

---

### XH-12 `write_core` 结果构造处使用 `expect`，与 `panic = "abort"` 组合会终止宿主进程

**位置**：`rust/src/structure/engine.rs:1280-1292`；`rust/Cargo.toml:151-156`

```rust
// rust/src/structure/engine.rs:1281-1284
format: FileFormat::from_adapter_name(adapter.format_name())
    .expect("every registered adapter maps to a FileFormat"),
strategy: StrategyId::from_name(&selected_strategy)
    .expect("the selected strategy comes from STRATEGY_REGISTRY"),
```

`[profile.release] panic = "abort"`（`Cargo.toml:157`）。这两个 `expect` 依赖「注册表与适配器表一致」，而该不变式由两个独立的 `static` 数组各自维护（`ADAPTERS` 与 `STRATEGY_REGISTRY`），若将来新增适配器忘记同步 `FileFormat::from_adapter_name`，**用户会在一次成功的写入末尾被 abort**（而非返回错误）。同一文件 `:1020` 的 `stealth_magics.expect("stealth requires password")` 也属同类，但该分支有前置 `if stealth && password.is_none() { return Err }` 守卫，风险更低。

**修复**：改为 `ok_or_else(|| StrHideError::General(...))`；或把两个 `expect` 换成 `debug_assert!` + 明确错误，让 release 行为可预期。

---

### XH-13 回归测试 `verify_detects_unsupported_envelope_version` 自身非确定性（实测 0.40% 失败率）

**位置**：`rust/tests/test_regression/p2_protocol.rs:268-284`

**证据（实测）**

全量 `cargo test --all-features --all-targets` 时该测试失败一次：

```text
test p2_protocol::verify_detects_unsupported_envelope_version ... FAILED
thread '...' panicked at tests\test_regression\p2_protocol.rs:275:5
```

随后单独跑 3 次全绿。原因是测试直接写入固定字节：

```rust
// tests/test_regression/p2_protocol.rs:272
patch_header_field(&out, ube_offset, 8, &[0x09]);   // version 字段
```

但无密码信封的 header 是**用公开内置密钥 + 随机 salt 做异或掩码**的（`envelope.rs:305-316`），因此偏移 8 上的实际字节是 `0x02 ^ mask[0]`，随 salt 变化。当 `mask[0] == 0x0B`（概率 1/256）时，写入 `0x09` 是**空操作**，信封未被篡改，L2 自然通过。

实测量化（3,000 次）：

```text
tamper was a no-op (stored byte already 0x09): 12/3000 = 0.40%   (理论 1/256 = 0.39%)
L2 accepted tampered header:                   12/3000 = 0.40%
```

**影响**：`quality` job 有约 0.4% 概率随机失败，会污染「提交前全绿」的判断，也让真正的回归难以与噪声区分。

**修复**：先读回该字节再异或固定值（`b ^= 0xFF` 或 `b = b.wrapping_add(1)`），保证篡改一定生效；更稳妥的做法是断言「原字节 != 目标字节」后再写。

---

### XH-14 `structure/mod.rs` 的模块文档描述了已被删除的跨域例外

**位置**：`rust/src/structure/mod.rs:13-18`

```rust
//! One exception remains: `inspect` measures content capacity inline behind
//! `#[cfg(feature = "content")]`. It now at least asks ...
```

实测：`grep -rn 'feature = "content"' src/structure/` 只命中这一行注释本身，`grep -rn "content_stego_capacity" src/` 命中 **0** 次。也就是说这条例外已被移除（`import_lint` 也通过），但注释仍在，且 `ARCHITECTURE.md:360` 仍在描述 `content_stego_capacity` 字段。读者会据此以为结构域仍反向依赖内容域。

**修复**：删除该段注释；`ARCHITECTURE.md:360` 同步删除 `content_stego_capacity`（该字段已不在 `InspectResult` 中）。

---

### XH-15 `write_core` 硬编码错误标签 `<carrier>`，写入失败永远不指出是哪个文件

**位置**：`rust/src/structure/engine.rs:891`

```rust
let adapter = find_adapter_or_reject(host, "<carrier>")?;
```

对比 `read_core`/`remove_core`/`inspect_core`/`verify_core` 都传真实 `label`（`carrier_path.display()`）。因此 `strhide write a.png` 对一个不支持的格式，错误信息是：

```text
'<carrier>' is not a supported carrier format (file starts with 66 4C 61 43)...
```

批量写入时用户无法定位是哪个文件失败（CLI 会先打印 `[ERROR] <path>`，但库调用方拿不到）。

**修复**：`write_core` 增加 `label: &str` 参数（内部函数，无 API 影响），由 `write_carrier_with` 传路径、`write_carrier_bytes` 传 `"<memory>"`。

---

## 6. 文档与实现一致性核对

以下为逐条核对结果（`旧版本号` 已由 `docs/CODE-REVIEW-20261103.md` 记录，本节只列能做增量确认的项）：

| 文档位置 | 文档说法 | 代码事实 | 结论 |
|---|---|---|---|
| `ARCHITECTURE.md:3` / `WIRE_SPEC.md:3` | crate 0.8.3 | `rust/Cargo.toml:3` = 0.8.5 | 过时 |
| `WIRE_SPEC.md:879` | `BODY_OVERHEAD = 21` | `stego/envelope.rs:81` = `4+1+1+16 = 22` | 错 |
| `WIRE_SPEC.md:880` | `MIN_ENVELOPE_LEN = 49` | `stego/envelope.rs:83` = `28+22 = 50` | 错 |
| `WIRE_SPEC.md:870-871` | `MIN_UBE_PLAIN=178`、`MIN_UBE_ENCRYPTED=214` | `structure/envelope.rs:95-96`：两者都是 **213** | 错（且实测：空载荷 213、1 字节载荷 214） |
| `structure/envelope.rs:88-92` 注释 | `112 + 41 + 1 + 24 = 178` | 同一行下方 `213`；注释未计 AEAD tag 与分块开销 | 自相矛盾 |
| `ARCHITECTURE.md:360` | `inspect` 返回 `content_stego_capacity` | 全仓 0 处引用 | 已删除 |
| `ARCHITECTURE.md:534-535` | 双域「顺序无关性」 | 实测 PNG `Structure→Content` 后 `verify L2=false`、`restore=FAIL` | 过度宣称 |
| `ARCHITECTURE.md:587` | doc 代码块「由 `cargo test --doc` 守护」 | `.github/workflows/ci.yml` 无 `--doc` 步骤 | 仅手工执行 |
| `ARCHITECTURE.md:585` | 多个公开枚举已 `#[non_exhaustive]` | `StrHideError`、`ErrorKind`、`FileFormat` **未标注** | 错 |
| `lib.rs:11-14` | 「六种载体族」 | `formats/capability.rs` 有 12 个 `FileFormat`，`registry::ADAPTERS` 10 个适配器 | 过时 |
| `STEGO-API.md:106-115` | 示例 `header_bytes: 40` | `format.rs:223` 默认 **48**；`HEVC_SUPERBLOCK_BYTES=32` + 16 字节 tag | 错 |
| `STEGO-API.md:193-196` | PNG `--p1-window/--p2-window` 不自描述，提取端必须重复 | `png/engine.rs:1807-1808` 从 `FeatureWord` 恢复；该结构体携带 `p1_window/p2_window/epsilon/sigma/algorithm_id` | 错（会让调用方做无意义重复配置） |
| `WIRE_SPEC.md:395` | `MAX_KNOWN_STRATEGY_ID` 当前 13 | `registry.rs:206` 计算得出 = 13 | 一致 |

**建议**：把上表的常量改为「文档引用代码常量名」而不是字面值，并增加一个 `tests/doc_constants.rs`，用 `include_str!` 解析 `WIRE_SPEC.md` 的常量表与代码常量比对。这类漂移已经发生多次（`CHANGES-20261102` 就是在修同类问题），单靠人工同步不可持续。

---

## 7. 测试与 CI 覆盖缺口

| 缺口 | 证据 | 后果 |
|---|---|---|
| 双域共存矩阵不进 CI | `tests/heavy/heavy_coexistence.rs:462` `#[ignore = "requires testdata/ corpus"]`；`ci.yml` 的 Test 步骤没有 `--ignored` | XH-1 这类「双域复合破缺」在 CI 中永远不可见。**且该测试本身不断言 `verify`/`restore`**（只断言两个载荷能取回），即使跑了也抓不到 XH-1 |
| doc test 不进 CI | `ci.yml` 只有 `cargo test --release --locked --all-features --all-targets` | `lib.rs` / `facade.rs` / `options.rs` 里大量 `no_run` 示例不会被编译验证；`ARCHITECTURE.md:587` 的承诺不成立 |
| 无「容量声明 = 实际可达」测试 | XH-2 实测 64 MiB 声明 vs 16 MiB 可达 | `probe`/`inspect` 的数字无法作为调用方预算依据 |
| 无「写入前拒绝非载体」测试 | XH-3 实测两种伪造文件均被接受 | 违反拒绝优先原则 |
| 无 `strip`/`verify` 与 `locate` 的坐标一致性测试 | XH-1 的 `Unexpected EOF` | 「read 成功但 restore 失败」的状态可长期存在 |
| 无 RIFF 末块 pad 约定的交叉测试 | 见 XH-16（附录 A.3），仓库自带 `tests/assets/small.wav` 即可复现 L1=false | 同格式三端约定不一致 |
| 回归测试自身非确定性 | XH-13，实测 0.40% | CI 噪声 |

---

## 8. 修复优先级建议

| 优先级 | 条目 | 理由 |
|---|---|---|
| P0（发布前必须） | XH-1、XH-2、XH-3 | 分别对应「数据不可恢复」「容量声明不可信」「非载体被改写」，都是用户可见的破坏性后果 |
| P0 | XH-4 | 公开密钥信封的内存放大，服务端可直接被打挂 |
| P1 | XH-5、XH-13 | 安全策略静默失效；CI 噪声会掩盖真实回归 |
| P1 | XH-7 | 纯浪费，改动局部（一个 `Option<Option<..>>` + verify 合并），收益 30%～55% 的固定延迟 |
| P2 | XH-6、XH-9、XH-11、XH-12、XH-15 | 接口语义与防御性，成本低 |
| P2 | XH-8 | 当前被容量上限兜住，但结构上是 O(n²) |
| P3 | XH-10、XH-14、§6 文档表 | 长期可维护性 |

---

## 附录 A：本轮复现实验清单

所有实验均为 `cargo run --release --all-features --example <name>` 形式的独立 main，运行后已删除，未改动 `src/` 任何文件，未提交。

### A.1 双域复合（XH-1）

对 `tests/assets/small.png`：`write_bytes` → `embed_carrier_with_dialect` → `read_bytes` / `verify_bytes` / `restore_bytes`，4 种方言组合。结果见 XH-1「证据」。

### A.2 JPEG 容量可达性（XH-2）

`probe` 声明 + 二分搜索最大可写载荷（8/15/16/17/20 MiB 逐档验证）。

### A.3 RIFF 末块 pad 约定（XH-16）

**级别：中｜维度：格式约定一致性**

**位置**：`rust/src/structure/adapters/riff.rs:85-86`（写入端 pad 计算）、`:105-109`（追加位置）、`:274`（校验端 offset 步进）、`:346-366`（`riff_can_chunk` 判据）

**证据（实测，仓库自带资产）**

```text
$ small.wav: len=7551, RIFF size=7543, len-8=7543
  chunk fmt  @12 size=16   → next 36
  chunk data @36 size=7507 (odd, pad=1) → next 7552   ← 校验端按 pad 步进
  ↑ 文件实际只有 7551 字节，data 块缺 pad 字节

structure write 512B → strategy=riff_chunk, stego=7793
verify L1 = false : "Chunk 'HRD\xEA' at offset 7552 extends past end of file"
（SHRD 被写在 7551，校验端从 7552 开始读，读到 "HRD" + size 低位）
restore  = Ok(true)   ← 恢复本身正确
```

**根因**：三端约定不一致。写入端把 SHRD 追加在 `host_len`（= 7551）；`riff_can_chunk` 用 `host_len == 8 + old_riff_size` 判定可写（对缺 pad 的文件也成立）；校验端 `riff_verify_structure` 严格按「`8 + size + (size%2)`」步进，得到 7552。于是**写入成功、可读、可还原，但 Level 1 永久报损坏**。

**影响**：所有末块为奇数长且缺 pad 的 WAV/WEBP（实践中常见，因为 RIFF 的 pad 规则在写入端经常被省略）。`verify` 是文档承诺的三级门禁之一，用户会得到「文件已损坏」的错误结论。

**修复**：统一为「按 chunk 表步进」的单一实现——`riff_can_chunk` 也做一次完整的 chunk 遍历，要求 `最终 offset ∈ {file_len, file_len+1}` 且最后一个 chunk 是 `data`；`riff_inject` 用遍历得到的 `offset`（而不是 `host_len`）作为追加点，并在必要时补写缺失的 pad 字节。

### A.4 PBKDF2 计数（XH-7）

`derive_keys` 单次基准 + 4 个动词的 5 次取最小耗时。

### A.5 伪造载体接受（XH-3）

`FF D8` 前缀随机字节 / `00 00 00 00 "ftyp"` 前缀随机字节，各 20 KB。

### A.6 varint 非规范编码（XH-11）

复刻 `take_varint` 的循环逻辑，输入 `[0x80;9]++[0x7F]` 与 `[0xFF;10]`。

### A.7 回归测试非确定性（XH-13）

3000 次「写入 → 篡改偏移 8 为 0x09 → verify」，统计「篡改是空操作」的比例。

### A.8 分段流复杂度（XH-8）

按 `SegmentedSubStream::read` 的实际控制流建模，统计段数 1k/16k/64k 时的累计比较次数。

### A.9 压缩策略开销

64 MiB 不可压缩载荷：`Auto` 1,300 ms（含一次被丢弃的完整 deflate）vs `LocalParams::with_compression(Never)` 154 ms。**结论**：`Auto` 在「压缩后仍不划算」时无法避免全量压缩；`engine.rs:952-974` 先 `compress_stream` 到内存再比较阈值，峰值内存为「明文 + 压缩输出」两份。建议先做 64 KiB 采样压缩估算，不划算就直接跳过；或把 `should_compress` 的判据改为「采样比 > 98% 即放弃」。

---

## 附录 B：本轮确认无问题的项（避免误报）

以下为审查中重点怀疑、最终确认实现正确的项，列出以便后续审查不重复投入：

| 怀疑点 | 结论 | 依据 |
|---|---|---|
| AAD 是否真的覆盖 header 敏感字段 | 是 | 实测翻转 `flags`/`strategy_id`/`orig_host_size`/`orig_host_sha256` 均被拒绝；仅 `inject_offset`（偏移 80，AAD 之外）可翻转且被 L2 抓住 |
| 分块流是否可被伪造长度申请巨量内存 | 否 | `decrypt_stream_from_chunks` 以「剩余认证字节」与 `MAX_CHUNK_SIZE+tag` 双重上界 |
| 分块大小是否影响互读 | 否 | 长度前缀自定界；`framed_len` 与 `framed_len` 的一致性测试存在 |
| 密钥/签名安全：AES-GCM nonce 复用 | 实际不可达 | `chunk_index` 为 `usize`，但 `as u32` 截断后需 2³² 个分块（2 MiB/块 → 8 PiB）才会碰撞；属理论边界，非现实缺陷 |
| `.bak` 与原子提交的并发安全 | 部分问题（已由既有报告 H-5 记录） | `next_backup_path` 的 check-then-create 与 `File::create` 跟随符号链接；本轮未复现 |
| `unsafe` 的 SAFETY 契约 | 成立 | 5 处 AVX2/Win32 均有运行时特性检测与边界注释；`iced-x86` 的 overflow-checks 例外在 `Cargo.toml:145-152` 有解释 |
| 归还载体 100% 无损 | 成立 | 13 种载体 `write→read→restore` 全部 `verified_identical=true`、逐字节相等 |
| 容量探测与嵌入是否自洽（单域） | 成立 | PNG `max+1` 被拒（85407 vs 85404 槽）、JPEG `max+1` 被拒（74855 vs 74854 槽）；`recommended` 档可完整往返 |
| 密码/normalize 一致性 | 成立 | 全部凭据入口经 `normalize_nfc`；`test_python_crypto_vector_compatibility` 用 Python 侧向量钉死 |
| `ChaCha12` 可复现性 | 成立 | 内置实现（不依赖 `rand::StdRng`），有 Strombergson TC1 向量与「固定 seed → 固定置换」契约测试 |

---

## 附录 C：一句话总结

**单域实现是可信的，跨域与跨端的「约定」不可信**：结构域写入端、定位端、校验端、恢复端各自都自洽，但两两组合时对「信封在哪、占多长、pad 怎么算、容量有多大」给出不同答案；而这些组合路径恰好不在 CI 覆盖范围内（`#[ignore]` + 无 doc test + 无容量可达性断言）。修复的重点不是重写，而是**把「同一事实的四个副本」收敛为一个来源**，并让 CI 真正跑到组合路径上。
