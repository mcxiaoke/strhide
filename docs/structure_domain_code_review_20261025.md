# strhide 结构域代码审查报告

| 项 | 内容 |
| :--- | :--- |
| 文档编号 | `STRUCT-REVIEW-20261025` |
| 审查时间 | 2026-10-25 |
| 审查引擎 | GLM-5.3（ZCode） |
| 范围 | 结构域全部代码：`rust/src/adapters/`（18 文件，约 7,300 行）逐行精读 + 结构域框架 `engine.rs` / `envelope.rs` / `rejection.rs` / `router.rs` / `sniff.rs` / `commit.rs` / `facade.rs` / `adapters/{mod,io,eof}.rs`（约 3,700 行）逐行精读，`crypto.rs` 仅审与引擎契约相关部分（framing/KDF 入口） |
| 方法 | 主审精读框架层与 PNG/JPEG 适配器；3 路子审分别逐行精读 ISOBMFF 族、PE 族、PDF/ZIP/RIFF 族；全部 P1/P2 发现由主审逐条对照源码复核后才收录；静态审查 + 测试代码交叉核对 |
| 基线 | commit `20f9c96` + 工作区未提交改动（`rust/src/stego/hevc/engine.rs`、`Cargo.toml/lock`，均为内容域 HEVC WPP/seed 重构进行中的代码）；`cargo test --all-targets` 结果见 §0.5 |
| 结论强度 | 每条发现标注【确认】（主审已逐步对照源码验证）或【疑似】（机理成立、影响需运行时验证）；P3 中未经主审逐条复核的仅收录子审给出明确代码证据的条目 |
| 关联文档 | [`stego_full_code_review_20261025_glm53.md`](stego_full_code_review_20261025_glm53.md)（同日全面审查，结构域当时仅为次重点抽查）；本次为结构域专项逐行深审 |

---

## 0. 总体结论

1. **结构域的核心契约层设计正确、实现自洽，是本仓库质量最好的部分之一。** UBE 信封封装（`envelope.rs`）、注入三坐标契约（`inject_offset` / `envelope_offset_delta` / `trailer_offset` / `locate` 四方一致）、默认 `strip` 的坐标换算（stego 坐标 → 还原坐标）、原子提交（`commit.rs` tmp+rename+TmpGuard）、散布策略契约（`is_scattered_strategy` 与 engine 补丁跳过逻辑闭环）均经主审逐行验证无缺陷；上一轮审查（2026-10-25）遗留的 3 项结构域 P3（commit 无 fsync、`facade::extract_file` 非原子写、router 回退顺序无测试锁定）仍然成立且未恶化。
2. **发现 4 个 P1、7 个 P2、22 个 P3；无 P0。** P1 全部是"写成功、读不回"或"破坏宿主文档可用性"类功能缺陷（非内存不安全——结构域全程无 unsafe，所有 panic 均为 Rust 边界检查，release 同样中止进程）：
   - `adapters/isobmff.rs` inject 侧 iloc 头部解析**完全无长度前置门**——这是 `5c4fa2d` 修复"iinf/iloc 越界裸读"时**遗漏的第 4 处**（该提交只修了 strip 侧与 `check_iloc_has_target`，inject 侧同类裸读原样保留）；
   - RIFF（WAV/WebP）在"声明边界 ≠ 物理文件尾"的真实载体（流式 WAV、尾部附加数据的文件）上注入后**约一半载荷不可读回**；
   - PDF 增量更新**不检测加密文档（/Encrypt）**，stego 期间文档对第三方 reader 不可解密；
   - PDF locate 用固定 128 KiB 尾窗扫描而写侧全文件扫描，脏尾 ≥ 128 KiB 的载体写后读不回。
3. **PE 族是质量最高的适配器子系统**（三个文件、2,500+ 行，0 个 P0–P2）：x86 指令编码信道的筛选不变量（F4 逐字节重编码一致 + F5 等长）经反例质疑后闭合，散布信封的原子性与还原契约完整。**ISOBMFF 的 item_hidden 策略则是覆盖与健壮性双弱的高风险路径**：iinf/iloc 补丁核心逻辑（约 500 行）在 CI 中零执行（真实语料往返全部在 `--ignored` 的 local 测试里），且本次 5 个 P1/P2 全部落在这条路径上。
4. **三个系统性短板**（详见 §5）：① 多个适配器的 `choose_auto_strategy` 无视 `ube_size` 或存在未建模的失败条件，而 engine 单选无回退——容量虚报与 auto 硬失败并存（HEIF/WAV/WebP/JPEG 大头、ZIP 空档案）；② 写读扫描不对称——写侧全文件扫描、读侧固定窗口或声明边界走链，产生"写成功读不回"整类问题（PDF/RIFF/PNG 三处同根因）；③ 文档/注释与代码行为漂移（`mod.rs` 两处失实注释、WAV/WebP `strategy_note` 宣称不存在的回退、`MIN_UBE` 相关 capacity 口径）。
5. **恶意输入防线的质量在适配器之间极不均衡**：PE 族所有切片/索引均有前置检查（未发现任何可 panic 路径）；isobmff.rs 虽经 `5c4fa2d` 修复，仍留有 4 处 panic 路径（1×P1 + 3×P2/P3）；PDF/ZIP 无 panic 面但有功能性缺陷。`adapters/mod.rs` 与 `envelope.rs` 的公共防线（`validate_against` 门序、80 字节 AAD、trailer CRC、`SegmentedSubStream`）验证正确。

---

## 0.5 审查基线与质量门状态

- 审查基于工作区当前状态：HEAD = `20f9c96`，另有未提交的内容域改动（`stego/hevc/engine.rs` 的 WPP 中段子流终止语义 + `trellis_seed_from_key` 重构，即旧报告 M10/M11 的修复进行中）。
- `cargo test --all-targets`（2026-10-25 本日）：**结构域相关套件全部通过**——test_cli 115、test_lifecycle 128、test_pe 39、test_regression 72、test_security 17，0 失败；唯一失败套件为 `test_media`（2 个 HEVC 内容域用例：`test_hevc_annexb_short_slice_header_roundtrip`、`test_hevc_capacity_is_reachable`），与上述未提交改动相关，**不属于结构域问题**。
- `cargo fmt --check` 与 `cargo clippy --all-targets -D warnings`（本次审查期间补跑）：**当前均不通过，但失败点全部位于内容域文件**——fmt 差异在 `stego/header.rs:168`，clippy 5 个 error 在 `stego/png/engine.rs`（duplicated attribute :1893、never used :1956、field_reassign :1900）与 `stego/header.rs:276/281`（is_multiple_of）。**结构域文件 0 告警、0 格式差异**。该两项质量门在 `CHANGES-20261025.md` 记录的 12:09 批次时为全绿，说明其后有改动未复跑质量门（与结构域无关，修复责任在内容域在途改动）。
- 恶意输入回归防线现状：本次全部 P1/P2 发现均无现有测试覆盖（见 §7）。

---

## 1. P1 问题（4 项，全部确认）

### P1-1.【确认】`isobmff.rs` inject 侧 iloc 头部解析无任何长度前置门——`5c4fa2d` 漏掉的第 4 处同类裸读

**位置**：`rust/src/adapters/isobmff.rs:717-731`（`heif_item_hidden_inject` 第 4 步）

```rust
let iloc_box = &subboxes[iloc_idx].1;
let iloc_ver = iloc_box[8];                     // 需 len ≥ 9，无门
let off_sz = ((iloc_box[12] >> 4) & 0x0F) as usize;  // 需 len ≥ 13，无门
let len_sz = (iloc_box[12] & 0x0F) as usize;
let base_sz = ((iloc_box[13] >> 4) & 0x0F) as usize; // 需 len ≥ 14，无门
let idx_sz = if iloc_ver >= 1 { (iloc_box[13] & 0x0F) as usize } else { 0 };
let iloc_cnt = if iloc_ver < 2 {
    u16::from_be_bytes(iloc_box[14..16].try_into().unwrap()) as u32  // 需 len ≥ 16
} else {
    u32::from_be_bytes(iloc_box[14..18].try_into().unwrap())        // 需 len ≥ 18
};
```

**机理**：meta 子盒抽取（isobmff.rs:625-636）只要求 `s_size >= s_hlen`，一个 8~17 字节的超短 `iloc` 子盒即可到达此处，`iloc_box[8]` / `[12]` / `[13]` / `[14..16]` / `[14..18]` 依次触发 index-out-of-bounds panic（Rust 边界检查 release 同样生效）。上游 `isobmff_can_item_hidden`（isobmff.rs:449-469）只检查 `iinf`/`iloc` **标签存在**即放行，`HeifAdapter::choose_auto_strategy`（heif.rs:57-63）随即选中 item_hidden——**公开写入路径直接可达，恶意/损坏 HEIF 载体确定性 panic**。

**与 `5c4fa2d` 的关系**：该提交为 strip 侧（isobmff.rs:959-976）与 `check_iloc_has_target`（isobmff.rs:1145-1161）补了逐版本前置门，但 inject 侧 L717-731 的同族读取原样保留——修复不完整。同文件 `check_iloc_has_target` 内已有正确的逐字段门风格（L1171/L1176/L1188）可直接照搬。

**修复**：L717 后加两级门：读 `iloc_ver` 前要求 `iloc_box.len() >= 9`；随后按版本要求 `>= 16`（v0/v1）或 `>= 18`（v2+），不符返回 `CorruptedData`。配超短 iloc 回归测试。

### P1-2.【确认】RIFF（WAV/WebP）：声明边界 ≠ 物理文件尾时注入后约一半载荷不可读回

**位置**：`rust/src/adapters/riff.rs:66-105`（inject）、`riff.rs:124-163`（locate 走链）、`riff.rs:166-174`（EOF 回退）

**机理**：`riff_inject` 把 `SHRD` chunk 无条件追加在**物理文件尾**（`inject_offset = host_len`，riff.rs:88-90），但 RIFF 尺寸补丁按 `old_riff_size + inject_size` 计算——只有当 `host_len == 8 + old_riff_size`（声明边界恰为文件尾）时写读双方才自洽。若载体在声明边界之后有尾随字节（**流式 WAV 的 size=0、尾部附加的 ID3/垃圾数据**等真实存在的形态）：

- `riff_locate` 从 offset 12 按声明尺寸走链，越过原边界后把垃圾字节当 chunk 解析，几乎必然跳过物理尾部的 `SHRD`；
- EOF 回退（riff.rs:166-167）要求信封恰到文件尾——`ube_size` 为**偶数**（pad=0）时恰好成立，读回成功但 strategy 被误标为 `"eof"`；`ube_size` 为**奇数**（pad=1，约 50% 的载荷）时文件尾是 pad 字节，trailer 错位 1 字节 → 读/查/还原全部报 `NoHiddenData`，**数据在文件里但工具不可达**；
- 写侧的 occupied 检查同样失败 → 对同一载体可重复注入叠加信封；
- `riff_verify_structure` 会把该 stego 报为损坏（垃圾被当 chunk 解析）。

**影响**：功能性失败 + 双重注入风险；还原路径本身（默认 strip + patch_offset=4 回写）仍是字节精确的。触发面为真实载体形态，非性能裁剪路径。

**修复**：inject 入口校验 `host_len == 8 + old_riff_size`，不一致时拒绝 `riff_chunk` 并提示改用 eof（或显式把边界外数据作为"声明外尾随"处理并在 locate 侧对称支持）。同时补两类回归：size=0 流式 WAV、尾随垃圾 WAV/WebP（奇偶 ube_size 各一）。

### P1-3.【确认】PDF：加密文档（/Encrypt）无任何拒绝逻辑，增量更新破坏文档解密

**位置**：`rust/src/adapters/pdf.rs:516-527`（新 trailer 构造）；`rg '/Encrypt' rust/src` 无任何命中（写侧、rejection 侧均无检测）

```rust
let mut trailer_str = format!("trailer\n<<\n/Size {}\n", info.new_obj_num + 1);
if let Some(root) = &info.root_ref {
    trailer_str.push_str(&format!("/Root {root}\n"));
}
```

**机理**：ISO 32000-1 Table 20 规定加密文档的 trailer **必须**携带 `/Encrypt`，且主流 reader（pdf.js、mupdf、Acrobat）只从 `startxref` 指向的**最新** trailer 读取 `/Encrypt`，不沿 `/Prev` 链继承。strhide 的增量更新写出的新 trailer 不含 `/Encrypt` → stego 后文档被 reader 判为未加密，而全部 strings/streams 是密文 → **文档不可读**。对比：签名 PDF 有 `rejection.rs:158-216` 的拦截，加密 PDF 完全没有对应防线；有 `/Root` 的 PDF auto 恰好会选 incremental，触发路径是默认路径。

**影响**：对第三方 reader 的文档损坏（strhide 自身 restore 字节精确不受影响）。违反项目"不改变格式、外观或功能"的定位。

**修复**：`parse_pdf_tail_info` 解析 trailer/XRef stream 字典时检测 `/Encrypt`，命中即拒绝 incremental（auto 落 eof，与无 `/Root` 时的处理对齐），并在 `strategy_capacities` 中标记不可用。

### P1-4.【确认】PDF locate 固定 128 KiB 尾窗与"脏尾 ≥ 128 KiB"载体写读断裂

**位置**：`rust/src/adapters/pdf.rs:557-561`（locate 分支 1）、`pdf.rs:77-100`（写侧 `find_last_eof` 全文件反向扫描）

```rust
let scan_len = std::cmp::min(total_size, 128 * 1024);
stego_in.seek(SeekFrom::End(-(scan_len as i64)))?;
```

**机理**：incremental 注入结构为 `[原 PDF]%%EOF[注入的 obj+xref+trailer+%%EOF][脏尾 T]`。当 `|T| ≳ 128 KiB` 时，注入的 `%%EOF` 与 `endstream` 均在 locate 的扫描窗口之外 → 分支 1 落空；EOF 回退读文件最后 24 字节（脏尾尾部）→ 失败 → `None`。写侧 `find_last_eof` 是全文件反向扫描（脏尾被完整保留并注入成功），`verify_structure` 同样全文件扫描——**写成功、读失败的不对称**。现有回归 `pdf_dirty_tail_lossless`（test_regression/fixes.rs:337）的脏尾仅 23 字节，未覆盖此区间。

**影响**：write 报告成功，read/inspect/remove 全部报"无隐藏数据"，注入的 UBE 成为孤儿数据；写侧 occupied 检查随之失效（可叠加注入）。

**修复**：locate 分支 1 改为从文件尾反向按块扫描定位最后一个 `%%EOF`（复用 `find_last_eof` 的分块逻辑），再在其前找 `endstream`；或窗口逐段扩展回退。补"脏尾 ≥ 128 KiB"端到端回归。

---

## 2. P2 问题（7 项）

### P2-1.【确认】`isobmff.rs` iloc 条目 patch-walk 内层 u16 裸读（inject 与 strip 双侧）

**位置**：inject 侧 `isobmff.rs:765-776`；strip 侧 `isobmff.rs:1001-1012`

```rust
let val = u16::from_be_bytes(iloc_buf[cpos..cpos + 2].try_into().unwrap()) & 0x0F; // cm，裸读
...
let e_cnt = u16::from_be_bytes(iloc_buf[cpos..cpos + 2].try_into().unwrap()) as usize; // 裸读
```

**机理**：`5c4fa2d` 的盒级门只保证**头部**字段可读。`iloc_cnt` 声明的条目数、每条目的 `e_cnt` 若超出实际数据，`iloc_buf[cpos..cpos+2]` 切片即 panic（release 同样）。strip 侧 L982 的 `iloc_buf.len() < iloc_item_len` 门只覆盖 1 个条目的长度，不覆盖 `iloc_cnt - 1` 个条目的走查。strip 侧触发需伪造 stego（trailer magic/CRC 为公开常量可构造）；inject 侧与 P1-1 同源可达。**注意**：walk 内 `read_sized_uint` 自带边界检查（isobmff.rs:563-582）返回 Err，patch 位置由前置 read 保证在界内——真正的裸读只有这两处 u16。**修复**：walk 内每步加 `cpos + 2 > buf.len()` 门，风格照搬同文件 `check_iloc_has_target`（L1171-1190）。

### P2-2.【确认】`isobmff.rs` `max_id + 1` 溢出：debug panic / release 生成碰撞 item_id

**位置**：`isobmff.rs:663-688`

```rust
max_id = max_id.max(iid);
...
let new_id = (max_id + 1).max(1);
```

**机理**：`Cargo.toml` 无 `[profile]` 段（已核实，release 默认 `overflow-checks=false`）。crafted infe v3 条目声明 `item_id = 0xFFFFFFFF`（`can_item_hidden` 不校验条目内容）→ debug 构建加法溢出 panic；release 回绕为 0 → `.max(1)` 得 1，与主图 item_id（惯例为 1）**碰撞**，写出含重复 item id 的无效 stego 并可被分发。strip 按位置删除、字节仍可还原，但 stego 结构无效。**修复**：`max_id.checked_add(1)` 失败即拒绝该载体（或直接拒绝 `item_id == u32::MAX` 的条目）。

### P2-3.【确认】`heif_item_hidden_strip` 对 `header.inject_offset` 无交叉校验，伪造 stego 可致 range panic

**位置**：`isobmff.rs:862`（唯一校验 `inject_offset > stego_bytes.len()`，且为 `>` 而非 `>=`）、`isobmff.rs:1086-1088`

```rust
out.write_all(&stego_bytes[..m_off])?;
out.write_all(&restored_meta)?;
out.write_all(&stego_bytes[m_off + m_size..header.inject_offset as usize])?;
```

**机理**：当伪造 header 的 `inject_offset < m_off + m_size` 时，切片 start > end → panic。engine 的 `remove_core` 不校验 `inject_offset` 与 locate 返回的 `ube_offset` 的结构关系（item_hidden 应满足 `ube_offset == inject_offset + 8`）；非加密模式的 header 仅以公开内建密钥掩码、可被完整伪造（加密模式此风险被 AEAD 间接覆盖）。**修复**：strip 入口加 `inject_offset >= m_off + m_size` 与 `inject_offset + 8 + inject_size == stego_bytes.len()` 校验，不符报 `CorruptedData`。

### P2-4.【确认】HEIF item_hidden/free_box 容量虚报 "unlimited" + auto 无 4 GiB 分流

**位置**：`isobmff.rs:390-405`（capacity 表）、`heif.rs:57-63`（`choose_auto_strategy` 忽略 `ube_size`）、`isobmff.rs:841-842`（inject 侧 `u32::try_from(8 + ube_size)` 硬上限）

**机理**：item_hidden 受三重 32-bit 约束（mdat2 盒尺寸、meta/iinf/iloc 尺寸回写 `as u32`、32-bit iloc 字段宽度由 `write_sized_uint` 拒绝），free_box 受 u32 盒尺寸约束——实际封顶约 4 GiB，capacity 却报 `unlimited (file grows)`；auto 对 ≥4 GiB-7 的信封必选 item_hidden 然后 inject 干净报错，而此时 box_uuid（64-bit largesize，真无上限）可用。engine 单选无回退 → 整个写入失败。**修复**：`choose_auto_strategy` 按 `ube_size` 阈值分流 box_uuid；capacity 的 limit/note 注明 4 GiB 上限。与 P3-20（WAV/WebP）、P3-16（JPEG 16 MiB 头）同族，见 §5.1。

### P2-5.【确认】PDF：stealth trailer magic 尾字节为 `\r`/`\n` 时 incremental locate 必然失配（概率约 0.78%）

**位置**：`pdf.rs:566-578`

**机理**：注入后 UBE 尾部紧贴写方追加的 `\nendstream`。locate 的 trim 循环从 `endstream` 前向前吞 `\r`/`\n`：标准 trailer magic 尾字节（0xD2）无碍，但 stealth 模式的 4 字节 magic 由 PBKDF2 均匀派生，尾字节落入 {0x0A, 0x0D} 的概率约 2/256——此时 24 字节 trailer 窗口整体错位 1 字节，magic/CRC 双失败，分支 1 落空且 `ube_offset+size == abs_stream_end` 等式同样被 trim 破坏 → EOF 回退也失败 → 该 stego 不可 read/inspect/remove。**修复**：trim 前先按未 trim 位置尝试校验，失败再试 trim 后位置（两次尝试成本可忽略）；或写方在 UBE 与 `endstream` 之间固定写一个非 EOL 分隔字节并纳入 delta 计算。可用固定派生口令（使 magic 尾字节为 0x0A）构造确定性回归。

### P2-6.【确认】ZIP：空档案（cd_offset=0）注入后 stego 无法被自家 router 识别

**位置**：`zip.rs:57`（放行 `cd_offset==0 && cd_size==0`）、`zip.rs:204`（`inject_offset = cd_offset`）、`zip.rs:87-91`（detect 依赖前 4 字节 `PK..`）

**机理**：22 字节合法空 ZIP 走 pre_cd_inject 时 UBE 写在文件偏移 0，stego 的前 4 字节变成 UBE header magic，`ZipAdapter::detect` 与全部其他 detect 均不命中 → read/inspect/remove 在 `find_adapter_or_reject` 一步即报"不是支持的载体格式"（locate/strip 逻辑本身自洽，卡死在 detect）。无 `--format` 强制指定兜底（已核实 CLI 无此参数）。**修复**：inject 拒绝 `cd_offset == 0`（auto 分流 eof）；或 detect 失败时在 router 层增加"前 8 字节为 UBE header magic + ZIP trailer 自洽"的定向重试。

### P2-7.【确认机理】ZIP64（EOCD64 locator 存在且经典字段非 sentinel）：注入后 locator 失效

**位置**：`zip.rs:14-69`（`find_eocd_offset` 无 ZIP64 感知）、`zip.rs:213-227`（注入不补丁 locator）

**机理**：仅当经典 EOCD 的 cd_offset/cd_size 为 0xFFFFFFFF sentinel 时被拒绝（落 eof，正确）。但存在一类真实 ZIP64 档案：条目数 > 65535（count 字段为 0xFFFF sentinel）而 cd_offset/cd_size 本身 < 4 GiB 保持真实值——`find_eocd_offset` 正常返回，注入把 CD、EOCD64 record、EOCD64 locator、EOCD 整体后移 `ube_size`，但 EOCD64 locator 内的"zip64 EOCD record 偏移"字段不更新 → 依赖 EOCD64 的严格第三方 reader 定位失败（strhide 自身 `verify_structure` 只查经典 EOCD，不会发现）。【确认】代码缺失；损坏影响【疑似】（取决于第三方 reader 对 locator 失效的容错）。**修复**：`find_eocd_offset` 尾部检测到 `PK\x06\x06`/`PK\x06\x07` 即判不支持，auto 落 eof。

---

## 3. P3 问题（22 项，按子系统分组）

### 3.1 ISOBMFF 族

| # | 位置 | 问题 | 确认度 |
| :--- | :--- | :--- | :--- |
| P3-1 | `isobmff.rs:28-53` | `trailing_envelope_len` 只校验 offset/size 自洽、不校验 trailer magic/CRC，verify_structure 可被构造数据提前放行（L1 层理论假阳性；L2/L3 仍拦截） | 确认 |
| P3-2 | `isobmff.rs:828-833, 847` | 64-bit 头（largesize）的 meta 重组被静默归一化为 12 字节头，`inject_offset`/iloc extent 偏移基准错位 8 字节 → 信封补丁落在信封中部、事后不可定位；现实中 libheif 不生成此形态 | 确认机理 |
| P3-3 | `isobmff.rs:1199` | `check_iloc_has_target` 的 `b_off + ext_off` 未用 `checked_add`（crafted 输入 debug panic、release 回绕；对比同文件其他处的谨慎风格） | 确认 |
| P3-4 | `isobmff.rs:625-636, 1074-1083` | meta 末尾 <8 字节残余不进入子盒重组，注入后静默丢失 → restore 报 `RestoreMismatch`（畸形载体） | 确认 |
| P3-5 | `isobmff.rs:683-685` | iinf 条目走查遇畸形条目即 break，`max_id` 不完整 → new_id 可能与断点后条目碰撞（stego 结构无效，字节仍可还原） | 确认 |
| P3-6 | `isobmff.rs:433-437, 1100-1101` | `can_item_hidden`/`has_iloc_item` `read_to_end` 全文件入内存（write 与 read 路径各一次；多 GB 载体 OOM 风险） | 确认 |

### 3.2 PE 族（本子系统无 P1/P2）

| # | 位置 | 问题 | 确认度 |
| :--- | :--- | :--- | :--- |
| P3-7 | `pe.rs:666` | `slack_off as u32` 静默截断：>4 GiB PE 且唯一足够零 run 位于 4 GiB 之外时，信道头记录错误 slack_off → strip 大概率干净拒绝、小概率清零错误 padding 区 | 确认机理 |
| P3-8 | `pe_codebits.rs:650-706` | restore diff 位图无 CRC：padding 中 diff 区损坏 → strip 静默产出错误 .text（engine 层 `orig_host_sha256` 比对兜底检出，adapter 层无告警） | 确认 |
| P3-9 | `pe.rs:414-423, 435-443` | eof 策略信封恒被定位为 `pe_overlay`（eof fallback 分支对自产文件不可达）；strategy 字符串与 header.strategy_id 不一致，仅影响显示/统计 | 确认 |
| P3-10 | `pe.rs:639-653` | codebits 双写防护要求既有信道 slack_off 落在**当前** slack_ranges：节表被第三方改动后防护失效（防御纵深缺口，自产文件不可达） | 确认机理 |
| P3-11 | `pe_codebits.rs:953, 1032` | `pe_geometry` 64 KiB 头窗：节表 >64 KiB（约 >1630 节）时 codebits/slack 同时不可用（overlay 仍可用），与 `parse_pe_headers` 行为不一致（注释已声明取舍） | 确认 |
| P3-12 | `pe_codebits.rs:1068, 259-349` | 对抗性大输入内存放大：`.text` 扫描窗可达整个文件 + 每指令约 32 B 的位置表（locate/strip 均对不可信 stego 执行） | 确认 |
| P3-13 | `pe.rs:520-528` | `suspicious_structures` 的 136 B overlay 阈值对合法大 overlay（调试信息等）误报（方向保守，可接受） | 确认 |

### 3.3 PDF / ZIP / RIFF / EBML 族

| # | 位置 | 问题 | 确认度 |
| :--- | :--- | :--- | :--- |
| P3-14 | `riff.rs:104-105` + `mod.rs:198-204, 236-238` | `old_riff_size == 0` 时返回 `patch_offset=4, orig_patch_val=0`，违反 trait 文档的哨兵约定（`orig==0 ⇒ 无补丁`）；且 `mod.rs` 两处注释失实（"currently only ZIP" 发非零 patch、哨兵语义描述）。engine/默认 strip 实测不受影响，还原仍精确 | 确认 |
| P3-15 | `ebml.rs:13-67` | `encode_vint` 阈值 `(1 << 7) - 1` 使 127/16383 等边界值编为 n+1 字节非最短 VINT（RFC 8794 为 SHOULD）；`val >= 2^56` 分支产出畸形字节（UBE 尺寸不可达，读写共用同一函数故一致性无损） | 确认 |
| P3-16 | `mkv.rs:27-34` | detect 不校验 DocType：任意 EBML 方言（非 matroska/webm）都会被追加 Void/EOF 信封（追加式注入字节精确，风险低） | 确认 |
| P3-17 | `wav.rs:25-27, 88-92`（webp 同构） | `choose_auto_strategy` 恒选 `riff_chunk` 无视 4 GiB 余量，`strategy_note` 宣称的"自动回退 EOF"不存在（对比 ZIP/PDF 的 auto 均真实考虑 ube_size）；容量 note 误导 | 确认 |

### 3.4 PNG / JPEG / 框架层（主审发现）

| # | 位置 | 问题 | 确认度 |
| :--- | :--- | :--- | :--- |
| P3-18 | `png.rs:31-52` | `find_iend_offset` 反向扫描取**最后一个** 12 字节 IEND 完整序列：多 IEND/拼接 PNG（如 PNG 后拼接另一 PNG）时注入点落在非终止 IEND 之后，块注入的 chunk 在 locate 的前向 chunk 走链（首个 IEND 即终止）之外 → 写成功读不回。改为前向 chunk 走链定位（与 locate 同语义）即可根除 | 确认机理 |
| P3-19 | `jpeg.rs:18, 73, 282` | `MAX_JPEG_HEADER_SCAN = 16 MiB`：头部链（EXIF/ICC 等）超过 16 MiB 的 JPEG 无法定位 SOS，auto 选 app_segment 后 inject 干净报错且无 eof 回退（写失败而非读失败，与 P2-4/P3-17 同族） | 确认 |
| P3-20 | `engine.rs:266` | 错误消息内嵌 14 个多余空格（编辑残留）：`"...is malformed;              cannot encode envelope metadata"` | 确认 |
| P3-21 | `adapters/mod.rs:18-19` | 模块文档 "the six supported carriers" 实际 10 个适配器（stale doc） | 确认 |
| P3-22 | `rejection.rs:254-262` | `check_jar_signature` 的 EOCD `rposition` 对"EOCD 之后尾随含 `PK\x05\x06` 的垃圾"会取错记录 → cd_offset 错误 → 签名检测漏报（仅影响拒绝检查的保守性，非注入路径） | 确认机理 |

**上轮遗留、本次复核仍然成立的已知项**（不重复展开）：`commit.rs` tmp+rename 无 fsync（crash 窗口）；`facade.rs:299-326` `extract_file` 非原子写 + 目录输出硬编码 `extracted.bin`；router HEIF "先 bridge 后 HEVC" 回退顺序无测试锁定。

---

## 4. 各子系统详评（确认正确清单）

### 4.1 框架层（engine / envelope / commit / rejection / router / sniff / io / eof / facade）——主审逐行

- **`envelope.rs`**：`validate_against`（L189-211）在所有消费点之前调用且覆盖完整——`hint_len ≤ 1024`、`hint+meta+136 ≤ ube_total_size`，使 engine.rs:1382/1410 的预认证分配与 engine.rs:1422 的减法、engine.rs:2218 的 `ube_total_size - 24` 全部安全（无 DoS、无下溢）；`get_aad` 恰为前 80 字节（不含 inject 字段/meta_len/hint_len），与写入端"AAD 在 meta_len 赋值前捕获"（engine.rs:963 vs 967）的时序严格一致；`pack_masked` 掩码区（bytes 8..12、40..112）与 `salt_of` 的明读区（12..28）划分正确；trailer magic 严格匹配 + CRC32（含 stealth 掩码分支）双验证。
- **`engine.rs` 写路径**：`exact_ube_size` 预计算与实际密文长度的交叉校验（L988-992）将 framing 漂移转化为 fail-fast；occupied 三重扫描（dialect magic → 官方 magic → stealth magic）+ `suspicious_structures` 警告兜底；非散布策略的 header/trailer 补丁与 `finalize` 顺序正确；`write_carrier_bytes` 与文件路径共享同一 `write_core`。
- **`engine.rs` 读/还原路径**：`remove_core` 后强制 `verify_restored`（size+SHA-256 对拍，L1712-1764），双信封给出"逆序移除"诊断；`write_payload_to` 的 `sanitize_filename` 覆盖 `/`、`\`、`:` 与 `.`/`..`；`verify_passed` 对 skipped 级别语义明确。
- **`commit.rs`**：`same_file`（unix dev/ino、Windows canonicalize+大小写折叠）、`TmpGuard` RAII、备份冲突降级链（`.bak` → `.bak-ts` → pid/随机）实现正确。
- **`rejection.rs`**：Authenticode 数据目录偏移 PE32=128/PE32+=144 正确；PDF 签名扫描 64 KiB 分块 + 1 KiB 重叠；JAR 检测基于内容而非扩展名。
- **`router.rs`**：`MAX_STRATEGY_ID` 编译期派生 + 与 `MAX_KNOWN_STRATEGY_ID` 的同步测试；10 适配器嗅探顺序（HEIF 先于 MP4）正确。
- **`sniff.rs` / `adapters/mod.rs`**：`is_heif_bytes` 索引有前置门；`SegmentedSubStream`（JPEG 链式虚拟流）读/寻址逻辑正确（EOF 返回 0、负 seek 拒绝）。
- **`eof.rs`**：locate 要求 `ube_offset+size == file_size` 才命中，防止误吞非信封尾随。

### 4.2 PNG / JPEG 适配器——主审逐行

- **PNG**：`prIv` 命名合规（ancillary/private/safe-to-copy）；CRC 流式累积写（type+data）；2 GiB 上界先拒绝后截断；locate 走链每轮至少前进 12 字节无死循环；`envelope_offset_delta=8`、`finalize` 重算 CRC 的区间（type+data）与 inject 写入一致；`suspicious_structures`/`verify_structure`/locate 三者对 priv/steg 的判定阈值口径一致（≥136）。
- **JPEG**：`scan_jpeg_markers` 状态机（fill bytes、standalone markers、MalformedLength/NonMarkerRun/HeaderScanLimit 终止条件）健壮；`partition_jpeg_payload_lengths` 末段 ≥24 的借位逻辑对边界值（65534/65556）手算验证正确；**多段链的写（inject）→ 定位（locate 逆向走链 + 相邻性校验）→ 读（`open_ube_reader` 用同一确定性分区函数重建段表）三方闭环**，`trailer_offset` 覆写对多段情形的必要性已验证。

### 4.3 ISOBMFF 族（子审 + 主审复核）

- 32/64-bit 盒头切换唯一来源 `calc_prefix_len`（边界单测锁定）；box_uuid 两种表单的 inject/locate/verify/suspicious 全链一致；`5c4fa2d` 已修的四组门（iinf 逐版本、strip 侧 iloc/iinf 三处、`check_iloc_has_target`）验证**正确且完整**（遗漏仅 P1-1 一处）；`write_sized_uint`/`read_sized_uint`/`patch_sized_uint` 的溢出与边界处理正确；infe v2/v3 构造与 strip 识别闭环；item_hidden 的 iloc 补丁语义（base_offset vs extent 二选一、cm≠0 跳过）与 ISO 14496-12 一致。
- heif.rs detect 的 size 门先于切片；mp4.rs 4CC 白名单（含 styp/moof/sidx 分片流）+ auto 恒选 box_uuid 与其真实无上限一致。

### 4.4 PE 族（子审 + 主审抽验）

- **pe.rs**：头解析全部前置检查、u32→u64 提升后运算，未发现可 panic 的畸形 PE 路径；Authenticode 偏移正确且 inject/capacity 双侧拦截；locate 优先级（codebits → overlay → slack → eof）与"末节 padding 信封止于 EOF 仍报 slack"的特判正确；`open_ube_reader` 对散布信封做 `ube.len() == ube_total_size` 交叉校验；`inject_codebits` 的容量/slack 检查全部先于任何输出字节（原子性成立）。
- **pe_slack.rs**：文件尺寸不变承诺兑现（copy_range 前后夹逼）；写入前 `verify_zero_slack` 强制目标区全零 ⇒ strip 按区间补零即字节精确；locate 五重防误报链（magic+CRC+边界闭合+MIN_UBE+单一 range）；ARM64 正确走 slack（codebits 对非 x86 干净退出）。
- **pe_codebits.rs**：指令筛选不变量闭合——F4（decode→re-encode 逐字节一致）天然拒绝全部非规范编码，F5（等长）与 embed 内长度复检双重拦截"翻转丢手动前缀"反例；56 对语义对 + 位序（MSB-first）三方一致；信道头 `validate_header` 的版本白名单与容量防注入；slack 候选的两条安全规则（节支撑跨度全量 subtract、`vsize==0` 不作 padding）有专项测试；encoder 缓冲 `take_buffer()` 陷阱已规避。

### 4.5 PDF / ZIP / RIFF / EBML 族（子审 + 主审复核）

- **PDF**：`find_last_eof` 反向分块扫描语义正确；对象号三级回退（trailer /Size → XRef stream /Size → 尾窗扫描）消除旧硬编码冲突；`/Length = ube_size` 精确定界使密文中的 `endstream`/`%%EOF` 无害；locate 三重绑定（trailer + 流尾边界 + `stream` 前缀）；脏尾保留有回归锁定。
- **ZIP**：EOCD 两遍扫描（恰 EOF → fits-in-file）正确区分伪造 comment（有回归）；`choose_auto_strategy`/`strategy_capacities`/inject 硬校验三者同口径（`patch_limit + ube < 0xFFFFFFFF`）；patch 坐标换算与默认 strip 逐项手推一致；strip 全程 checked 运算。
- **RIFF**：4 GiB checked 拒绝（不回绕）；奇数 chunk pad 读写一致；WAV/WebP 与共享层的分工无重复实现；VP8X flag 确认无需更新（SHRD 为未知私有 chunk）。
- **MKV/EBML**：**只在 EOF 后追加、永不前插**——SeekHead/Cues 偏移保持有效的构造性论证成立；Void 前缀 `encode_vint` 四方（写/delta/locate/suspicious）共用同一实现；verify_structure 对 unknown-size Segment、越界、死循环均有防护。

---

## 5. 跨子系统共性问题

### 5.1 "auto 策略单选无回退" × 容量声明失实（4 个适配器同族）

engine 的 `choose_auto_strategy` 单次决策、inject 失败不重试（engine.rs:934-947）。以下适配器的 auto 决策存在未建模失败条件或容量口径失实：

| 适配器 | auto 决策缺陷 | 容量声明缺陷 | 后果 |
| :--- | :--- | :--- | :--- |
| HEIF（item_hidden） | 忽略 ube_size；meta 内 iloc/iinf 可致 panic（P1-1/P2-1）或 4 GiB 上限未分流（P2-4） | "unlimited"（实际 ~4 GiB） | panic / 写失败 |
| WAV/WebP（riff_chunk） | 忽略 4 GiB 余量（P3-17） | "up to 4GB" + note 宣称不存在的回退 | 大载荷写失败 |
| JPEG（app_segment） | SOS 不可达（>16 MiB 头链）不回退（P3-19） | 64 MiB 上限未计头链限制 | 写失败 |
| ZIP（pre_cd_inject） | 空档案注入点为偏移 0（P2-6）；ZIP64 未检测（P2-7） | 口径一致（本项做得对） | 读不回 / 第三方损坏 |

**建议**：统一约定——`choose_auto_strategy` 必须只返回"已验证可注入"的策略（把 inject 的前置校验前移或共享）；`strategy_capacities` 与 auto 决策共享同一判定函数；或在 engine 层为 auto 增加"inject 失败自动降级 eof"的最后一环。

### 5.2 写读扫描不对称（"写成功读不回"整类根因）

| 场景 | 写侧 | 读侧 | 条目 |
| :--- | :--- | :--- | :--- |
| PDF 脏尾 ≥ 128 KiB | 全文件反向扫描 | 固定 128 KiB 尾窗 | P1-4 |
| RIFF 边界外数据 | 按物理尾追加 | 按声明边界走链 | P1-2 |
| PNG 多 IEND/拼接 | 反向取最后一个 IEND | 前向走链取首个 IEND | P3-18 |

三处同构：**注入点的选择依据与定位点的搜索依据不是同一个函数**。建议为每个适配器建立"注入点定位 = 定位点定位"的单一共享函数（PNG 已有前向走链实现可直接复用；PDF 已有 `find_last_eof` 可直接复用），并加"写入后立即 locate 自检"（write_core 尾部对 `out` 做一次 locate 回读校验，成本为一次流式扫描）——该自检可一次性拦截本类全部问题。

### 5.3 文档/注释与代码行为漂移

`mod.rs:18-19`（"six carriers"）、`mod.rs:198-204/236-238`（"only ZIP" 发 patch、哨兵语义 vs RIFF 实况）、`wav/webp strategy_note`（宣称不存在的回退）、`isobmff.rs` capacity "unlimited"（vs 4 GiB 硬门）、`engine.rs:266` 消息空格。与上一轮报告 §5.2 指出的内容域同类问题（HEVC "never touched" 直接诱发 S2）一脉相承——结构域目前漂移尚未诱发缺陷，但 P1-2 的"协议哨兵"漂移（P3-14）已具备演进为真缺陷的条件。

### 5.4 恶意输入防线的适配器间不均衡

PE 族：零 panic 面（所有切片前置检查）。isobmff.rs：5 处 panic 路径（P1-1、P2-1、P2-2、P2-3、P3-3）。PDF/ZIP：无 panic 面但各有功能性缺陷。建议把 isobmff.rs 的修复模式固定为"每个 `iloc_box[...]` 裸索引都必须先过版本化长度门"并用模糊/对抗 fixture 固化（§7）。

### 5.5 三个 ISOBMFF 解析器并存（上轮已知，重申影响）

`adapters/isobmff.rs`、`stego/hevc/heif_boxes.rs`、`stego/heif/thumb_bridge.rs` 各自维护解析纪律。本轮再次印证：`heif_boxes.rs` 的"be_uN + checked_add + usize::try_from 全覆盖"纪律未被 adapters 侧继承，P1-1/P2-1/P2-2 全部是纪律缺口而非算法难度问题。

---

## 6. 已验证正确的核心机制（审查过、没问题）

| 机制 | 验证方式 |
| :--- | :--- |
| UBE header/trailer 编解码、掩码区划分、`salt_of` 明读区 | 主审逐行 + 与所有调用点对照 |
| `validate_against` 门序覆盖全部预认证分配/减法 | 逐调用点核对（engine/inspect/verify 三路径） |
| 80 字节 AAD 与写入时序（meta_len 后置）一致性 | 写读两侧对照 + 密文 AAD 捕获时序核对 |
| 注入三坐标契约（inject_offset/delta/trailer_offset/locate）在 10 适配器自洽 | 三路子审逐一核 + PNG/JPEG/ZIP 主审手推 |
| 默认 `strip` 的 stego→还原坐标换算（含 patch 三分支） | 主审手推 + ZIP 覆写实现等价性验证 |
| 散布策略契约（pe_codebits）：inject 返回 (0,0,0,0) + engine 补丁跳过 + L2 `0==0` 比较闭环 | engine 与 pe 两侧对照 |
| JPEG 多段链写/定位/虚拟读三方闭环 | 主审手推分区函数确定性 + 边界值验证 |
| x86 指令信道筛选不变量（F4/F5）、MSB-first 位序、embed/extract/apply_diff 一致 | 子审反例质疑 + 既有 roundtrip 测试锁定 |
| pe_slack 零填充区"写前验证全零 ⇒ 清零即还原"闭环 | 子审逐行 + 专项测试 |
| MKV "只在 EOF 追加"对 SeekHead/Cues 的安全性 | 构造性论证（子审），待真实 fixture 测试固化（§7） |
| ZIP patch 坐标换算与默认 strip 等价 | 主审手推 + checked 运算核对 |
| RIFF 4 GiB 拒绝、奇数 pad、WAV/WebP 分工 | 主审逐行 |
| 原子提交（tmp+rename+TmpGuard+备份+时间戳/权限保留） | 主审逐行（上轮已验，本轮复核未发现新问题） |

---

## 7. 测试覆盖评估与缺口

**现状**：结构域的"常规路径"覆盖良好——`test_lifecycle/matrix.rs` 对全部 10 格式 × 显式策略 × 无密码/密码/stealth 做全生命周期矩阵；`test_regression/fixes.rs` 覆盖 ZIP 伪造 EOCD、PDF 小脏尾、header 篡改、双信封逆序移除；`test_pe/` 覆盖三策略全生命周期与几何安全规则。

**关键缺口**（与本次发现一一对应）：

1. **ISOBMFF item_hidden 在 CI 中零执行**：无带 meta（iinf+iloc）的合成 HEIF fixture，iinf/iloc 补丁与还原核心（isobmff.rs:584-1091）只有 `--ignored` 的本地语料测试覆盖——本子系统 5 个 P1/P2 全部无回归防线。建议构造合成 meta-HEIF fixture 进入常规套件。
2. 恶意/畸形输入零覆盖：超短 iloc（P1-1）、iloc 条目数与数据不符（P2-1）、`item_id=u32::MAX`（P2-2）、伪造 `inject_offset`（P2-3）。
3. RIFF 边界不一致载体（P1-2）：size=0 WAV、尾随垃圾、奇偶 ube_size 两种结局。
4. PDF：脏尾 ≥ 128 KiB（P1-4）、加密 PDF（P1-3）、stealth magic 尾字节 0x0A/0x0D（P2-5，可用固定口令做确定性用例）。
5. ZIP：空档案生命周期（P2-6）、ZIP64 两种形态（P2-7）、`patch_offset/inject_offset` 篡改的 strip 拒绝路径。
6. PE：diff 位图损坏的负向测试（P3-8）、`slack_off` u32 边界（P3-7）、REX/高字节寄存器全 Code×寄存器类的 decode→flip→decode→restore property 测试、pe32（0x10B）slack 用例。
7. 写后 locate 自检缺失（§5.2 的系统性对策）：`write_core` 成功路径上对产物做一次 locate 回读，可把本类缺陷全部转化为写入期失败。
8. 带 SeekHead/Cues 的真实 MKV fixture（P3 相关：追加安全性的测试固化）；VP8X 扩展 WebP。

---

## 8. 修复优先级路线图

**P0（建议立即修，均为功能性缺陷且修复成本低）**

1. P1-1 isobmff inject 侧 iloc 门（照搬同文件已有门风格）；
2. P1-2 RIFF 边界校验拒绝；
3. P1-3 PDF /Encrypt 检测拒绝；
4. P1-4 PDF locate 改全文件反向扫描（复用 `find_last_eof`）。

**P1（第二批）**

5. P2-1/P2-2/P2-3 isobmff 三项（与 P1-1 同文件同族，一次修完）；
6. P2-6 ZIP 空档案拒绝；
7. P2-5 PDF trim 双位置尝试。

**P2**

8. P2-4 + P3-17 + P3-19：auto 策略与容量口径统一整改（建议与 §5.1 的机制性方案一并做）；
9. P2-7 ZIP64 检测拒绝；
10. §5.2 的"写后 locate 自检"（一次投入拦截整类问题）。

**P3（随批清理）**：文档漂移批量修正（P3-14/17/20/21）、isobmff 其余四项、PE 防御纵深三项、EBML vint 阈值、rejection EOCD 边缘。

**测试补齐**：按 §7 的 8 项缺口随对应修复落地；优先级最高的是"合成 meta-HEIF fixture 进常规套件"与"写后 locate 自检"。

---

## 附录 A：审查方法与覆盖声明

- **精读（逐行）**：`engine.rs`（2,253 行）、`envelope.rs`、`rejection.rs`、`router.rs`、`sniff.rs`、`commit.rs`、`facade.rs`、`adapters/{mod,io,eof,png,jpeg,riff,zip}.rs` 主审完成；`isobmff.rs`（1,361 行）、`heif.rs`、`mp4.rs`、`pe.rs`、`pe_slack.rs`、`pe_codebits.rs`（1,541 行）、`pdf.rs`（924 行）、`wav.rs`、`webp.rs`、`mkv.rs`、`ebml.rs` 由子审逐行完成、主审对全部 P1/P2 及抽验 P3 复核源码。
- **目标性审读**：`crypto.rs` 仅审 framing/KDF 入口（`framed_len`、`chunk_count`、`derive_all` 语义、PBKDF2 迭代数为 wire 常量）；`params.rs` 仅审 Profile/LocalParams 与 magic/domain 相关访问器。内容域（`stego/`）不在本次范围（见同日全面审查报告）。
- **未做**：动态模糊测试、真实语料批测（`local_*` 为 `--ignored`，本轮未运行）；P1/P2 均未实际构造触发文件（机理经源码逐行验证，触发面分析基于格式规范与真实载体形态）。
- **行号**：全部来自审查时点的工作区（HEAD `20f9c96` + 未提交 hevc 改动；该改动不触及结构域文件）。

## 附录 B：与 2026-10-25 全面审查报告的关系

同日的 [`stego_full_code_review_20261025_glm53.md`](stego_full_code_review_20261025_glm53.md) 以内容域为重点，结构域仅做目标性抽查（其 §3.6/§4.6）。本次为结构域专项逐行深审，关系如下：

- 该报告结构域 5 项发现（isobmff iinf/iloc ×2、commit fsync、facade extract_file、router 顺序测试）状态经本次复核确认无误：前两项已由 `5c4fa2d` 修复**但不完整**（本次 P1-1 即其遗漏第 4 处），后三项仍开放（P3 级）。
- 该报告的非结构域结论（S1/S2/M1-M13 等）不在本次范围，未重新验证。
- 本次全部 33 项发现均为新发现。
