# strhide 代码审查报告（Rust 实现 vs Python 参考实现）

> 审查日期：2026-10-17 ｜ 审查范围：`rust/` 全量源码（10 模块，约 150KB）、`docs/` 全部文档、`python/` 参考实现对照
> 审查方式：全量源码走读 + 双向比对 + 编译/clippy 检查 + 12 项实证测试（含 5 项攻击/故障注入场景）
> 当前状态：Rust `cargo test` 2/2 通过；Python 全量套件 59/59 通过；跨语言套件 17/17 通过

---

## 0. 修复状态（2026-10-17 当日已实施，合并第二份评审 `strhide_rust_implementation_review.md` 的 R1~R9）

下表 P0/P1 全部修复完成并通过回归测试（Python 81/81、Rust 24/24、跨语言 17/17、综合场景 25/25）：

| 编号 | 问题 | 状态 |
| :--- | :--- | :--- |
| 1.1 + R7 部分 | PDF 尾部垃圾数据丢失 | ✅ 已修复：增量块后原样保留尾部字节；Python strip 改切片式；回归 `test_pdf_dirty_tail_lossless` |
| 1.2 + R2 | metadata filename 路径穿越（CWE-22） | ✅ 已修复：`sanitize_filename()` 统一净化（引擎目录输出 + CLI 默认输出 + Python 同）；回归 `test_path_traversal_sanitized` |
| 1.3 + R1 | `--stealth` 无密码静默降级 | ✅ 已修复：直接报错；`is_stealth` 回传实际标志；CLI 仅在 stdin+stdout 均 TTY 时提示密码（修复非交互环境挂起）；回归 3 项 |
| 1.4 + R3 | 隐蔽载体二次注入 / 多信封操作错对象 | ✅ 已修复：派生魔数双层检测（同密码拒绝）；未知密码场景结构启发式警告；locate 密码优先；remove 失败给出"逆序移除"诊断；回归 5 项 |
| 2.1 + R4 | JPEG `auto` 容量预估少算 4B/块 | ✅ 已修复：策略选择前计算**精确** UBE 尺寸（含 4B chunk 前缀与空载荷单块），附落定后一致性校验；回归 `test_auto_capacity_boundary_falls_back_to_eof` |
| 2.2 | ZIP EOCD 反向搜索无校验 | ✅ 已修复：两段式候选扫描（精确 EOF 优先 + 可容纳回退）+ CD 边界校验；修复 eof 策略注入后 EOCD 不再结束于 EOF 导致的定位回归；回归 3 项 |
| 2.3 + R8 | Rust 丢失 chmod 权限克隆 | ✅ 已修复：write/remove 提交后 `set_permissions` 还原；Unix 集成测试断言 mode |
| 2.4 + R9 | `--preserve-time` 无法关闭 | ✅ 已修复：统一为 `--no-preserve-time`（与 Python 一致），文档 §9 同步 |
| R5 | 注入失败残留 `.strhide.tmp` | ✅ 已修复：Rust `TmpGuard` RAII；Python try/except 清理；回归 `test_explicit_oversize_strategy_rejected_without_tmp` |
| R6 | 头部字段无边界校验 / u64 下溢 / chunk_len 无上限 | ✅ 已修复：`validate_against()`（version/hint_len/meta_len 与总量一致性）、`checked_sub`、`chunk_len ≤ CHUNK_SIZE+16`；回归 4 项 |
| R10 | 压缩取舍判据浮点/截断不一致 | ✅ 已修复：双语言统一为整数判据 `comp_len * 100 < raw_size * 98` |
| R11 | ZIP `patch_offset` u32 容量检查不完整 | ✅ 已修复：检查覆盖 `max(cd_offset, eocd_pos+16) + ube_size` |
| R12（部分） | 死代码 | ✅ 已删除 Python `crypto.py` 的半成品桩 `encrypt_stream_chunked`；Rust 死分支与 mod.rs patch 陷阱列为后续清理项 |
| R7（内存部分） | 全内存缓冲与 §3.5 声明矛盾 | ◐ 部分完成：Rust 写路径消除一份冗余拷贝（压缩/原始二选一及时释放、信封组装 move 语义）、读路径压缩时单缓冲；文档 §3.5 已改为诚实声明；全流式管道列为后续演进 |

**P2 级问题（#9–#24）：已于 2026-10-17 分 4 批全部实施**（每批单独提交，逐批全量回归）

| 编号 | 问题 | 状态 |
| :--- | :--- | :--- |
| #9 | 大 `chunk_len` 内存分配 | ✅ 此前已在 R6 修复中闭环（`chunk_len ≤ CHUNK_SIZE+16`） |
| #10 | IO 错误被 `while let Ok(n)` 静默吞掉 | ✅ 双侧修复：Rust 6 个适配器注入路径显式传播 `Err`（含评审漏列的 `pdf.rs`） |
| #11 | `unpack` 不校验 version/字段区间 | ✅ `validate_against()` 已校验；本轮补齐 `verify_carrier` L2 调用（此前仅 read/remove/inspect 调用），并修复 Python `header` 未绑定致 L3 崩溃的存量缺陷 |
| #12 | 默认 strip 的 `patch_offset > 0` 陷阱 | ✅ 按输出流坐标 `patch_offset - inject_size` 回写，坐标系与哨兵语义写入 trait 文档，越界返回 `CorruptedData`（不改线上协议） |
| #13 | ZIP `patch_offset` u32 截断 | ✅ R11 已拒绝 >4GB 场景，截断路径已堵死；本轮补齐协议状态说明 |
| #14 | xref-stream PDF 对象号默认 9999 撞号 | ✅ 双侧尾部扫描 `N G obj` 取最大对象号 + 1，`/Root` 全尾回退查找，找不到即拒绝 incremental；**并修复存量跨语言分歧**（紧凑 trailer 下真实样本 file-11.pdf 现双侧字节一致） |
| #15 | `verify` 恒返回退出码 0 | ✅ 与 Python 对齐：L1/L2 失败返回 1 |
| #16 | 密码重试依赖字符串匹配 | ✅ 新增 `NoHiddenData`/`NoHiddenDataError` 变体，双侧按变体判别；隐蔽载体无密码时给出可执行引导（结构启发式提示提供写入密码），TTY 守卫对齐 |
| #17 | 未检查父目录写权限 | ✅ Rust 补便携写探测（临时探针文件，无 libc 依赖），与 Python `os.access(parent_dir, W_OK)` 对齐 |
| #18 | JAR 签名检查仅认扩展名 | ✅ 双侧改为按 ZIP 魔数 + 中央目录扫描识别，改名 `.zip` 不再绕过 |
| #19 | `unescape` 转义集不全 | ✅ 双侧重写为字符级解码，补全 `\xHH`/`\uXXXX`/代理对/`\UXXXXXXXX`/八进制/`\a\b\f\v`；**并修复 Python 非 ASCII 被 latin-1 破坏的存量缺陷** |
| #20 | `.bak` 静默覆盖 | ✅ 双侧重名时追加 UTC 时间戳（再重名加序号），不再覆盖既有备份 |
| #21 | edition 与文档不符 | ✅ 此前已对齐（文档改为 Rust 2024） |
| #22 | clippy 21 条警告 | ✅ 清零：`cargo clippy --all-targets -- -D warnings` 通过；`write_carrier` 9 参重构为 `WriteOptions` 结构体（含 `Default`），CLI 与 17 处测试调用点同步迁移 |
| #23 | MP4/PNG `verify_structure` 深度不足 | ✅ 双侧遍历完整 box 树 / 全部 chunk，PNG 增加逐 chunk CRC32 验值（此前双侧均不验值），MP4 增加末 box 越界与 ftyp 校验 |
| #24 | `choose_auto_strategy(cf, 0)` 死计算 | ✅ 此前已随 P1-5 精确尺寸重构消除 |

> 验证矩阵（批次 4 收官）：`cargo clippy -D warnings` 0 警告、cargo test 55/55、pytest 105/105、跨语言 17/17、26 样本批量 72/72 全绿。新增回归资产：`rust/tests/p2_fixes.rs`(13)、`rust/tests/p2_protocol.rs`(7)、`rust/tests/p2_cli.rs`(11)、`python/tests/test_p2_engineering_fixes.py`(13)、`python/tests/test_p2_cli_security.py`(11)。
>
> 仍列为后续演进项（不在 P2 范围）：patch_offset u32→u64 协议升级（需双语言同步改二进制布局，留待 v2.3）、全流式管道改造（§5.4）、CI 门禁落地（仓库暂无 `.github/workflows`）。

---

## 0. 总结论

Rust 移植的整体质量高：信封协议、密码学、6+1 适配器与 Python 保持字节级一致，核心链路（write/read/verify/inspect/remove + 原子替换 + SHA-256 强校验）闭合完整，release 产物 1.39MB 无外部依赖。

但审查发现 **24 项问题**，其中 **4 项 P0（已实证）**：

| # | 级别 | 问题 | 状态 |
|---|------|------|------|
| 1 | P0 | PDF 尾部垃圾导致 write 阶段**静默数据丢失**，remove 永久失败 | 已实证 |
| 2 | P0 | 未加密载体 metadata `filename` 字段**路径穿越写文件**（CWE-22） | 已实证 |
| 3 | P0 | `--stealth` 不提供密码时**静默降级为标准模式**，明文魔数+未加密载荷完全暴露 | 已实证 |
| 4 | P0 | 隐蔽载体不可检测 → **二次注入 → 原始文件事实性损坏**，且多信封场景 remove 操作错对象 | 已实证 |
| 5 | P1 | JPEG `auto` 策略容量边界误判（预估少算 4B/块），该降级时反而硬报错 | 已实证 |
| 6 | P1 | ZIP EOCD 反向搜索无记录校验，注释含 `PK\x05\x06` 即误定位/误降级 | 已实证 |
| 7 | P1 | Rust 丢失 `chmod` 权限克隆（Python 有，文档 8.4 节有承诺），Linux 丢执行位 | 代码确认 |
| 8 | P1 | `--preserve-time` 恒为 true 且**无法关闭**（Python 有 `--no-preserve-time`） | 代码确认 |
| 9~24 | P2 | 大 chunk_len 内存分配、IO 错误被吞、头部版本不校验、patch 坐标陷阱、测试覆盖薄、clippy 23 警告等 | 代码确认 |

以下按"问题定位 → 根因 → 实证/证据 → 修复方案"展开。

---

## 1. P0 级问题（已实证，建议立即修复）

### 1.1 PDF 尾部垃圾 → write 阶段静默数据丢失

**位置**：`rust/src/adapters/pdf.rs:18-38`（`parse_pdf_trailer_info` 的 `eof_offset` 计算）、`pdf.rs:161-176`（inject 只复制 `[0, eof_offset)`）；Python `adapters/pdf.py:31-38,127-135` 同样逻辑。

**根因**：`eof_offset` = 最后一个 `%%EOF` + 后续换行符之后的位置。inject 只复制宿主 `[0, eof_offset)` 区间，**`%%EOF` 之后的非换行字节（尾部垃圾）被静默丢弃**。而 remove 按 `orig_host_size` 全量还原 → 必然 SHA 不匹配。

**实证**（dirty.pdf = 标准 PDF + `%%EOF\r\n` 后追加 210 字节垃圾，共 487,248B）：

```
write  -c dirty.pdf -t "hello secret" -o dirty_stego.pdf   → [OK]（输出 487,484B，垃圾已丢）
remove -c dirty_stego.pdf                                    → [ERROR] 100% restore verification failed
                                                               Restored size: 487038 (expected 487248)
```

后果：载体被破坏性修改（尾部数据丢失），且永远无法干净还原，违反"100% 逐比特无损"的核心承诺。

**修复方案**（二选一）：
- **A（推荐）**：inject 改为复制整个宿主至 EOF，将增量更新块插在 `eof_offset` 处，尾部垃圾原样保留在最终 `%%EOF` 之后；同时 `parse_pdf_trailer_info` 增加"尾部垃圾检测"，把垃圾长度纳入 `inject_offset` 计算。
- **B**：`choose_auto_strategy` 检测到尾部垃圾时降级 `eof` 策略并输出 `[STRATEGY]` 说明（eof 策略本身无损）。

### 1.2 未加密载体 metadata filename 路径穿越（CWE-22）

**位置**：`rust/src/engine.rs:651-666`（`read_carrier` 输出分支）；`cli.rs:392-399`（默认输出到 CWD 分支）。两处均未对 `meta_obj.filename` 做净化。

**根因**：未加密信封的 metadata 是明文 JSON，`filename` 字段可被任意篡改；`read -o <目录>` 时 `out_p.join(filename)` 直接拼接，`File::create` 跟随 `..` 逃逸目标目录。

**实证**：将未加密 ZIP 载体 metadata 中 `"filename":"payload.bin"` 等长改写为 `"filename":"../EVIL.txt"`：

```
read -c poc_evil.zip -o outdir  → [OK] Extracted payload to '.\../EVIL.txt'
                                 → 载荷实际落盘于 outdir 上一级（路径穿越成功）
```

注：Python 在 `-o <目录>` 场景有 `os.path.basename` 防护（`engine.py:521-522`），Rust 完全没有；**两个实现在"无 -o 默认输出到当前目录"场景均无防护**。加密载体因需密码才能构造，风险限于密码持有者；未加密载体可被任何人武器化。

**修复方案**：
- Rust：`read_carrier` 与 `cli.rs` 默认输出分支统一增加净化：`Path::new(name).file_name()` 取末级组件，拒绝空/`.`/`..`/含分隔符的名字，非法时回退 `extracted.bin`。
- Python：默认输出分支（`cli.py:153-154`）补 `os.path.basename`。

### 1.3 `--stealth` 不提供密码时静默降级为标准模式

**位置**：`rust/src/engine.rs:262`（`if stealth && is_encrypted`）、`cli.rs:195`（`resolve_password` 的 `encrypt_flag` 只认 `-e`）；Python `engine.py:183` 相同。

**根因**：隐蔽模式的动态魔数派生依赖密码；`--stealth` 未配密码时标志位被静默跳过，信封以**标准明文魔数 + 未加密载荷**写入，CLI 零警告，`WriteResult.is_stealth` 还如实报告 `true`（误导）。

**实证**：

```
write -c file-06.jpg -t "top secret" --stealth -o stealth_test.jpg
→ [OK]（无任何警告）
→ 文件含明文字节 \x89STRHIDE: True，含 STH!: True
→ read -c stealth_test.jpg（无密码）→ 直接输出 "top secret"
```

用户以为启用了隐蔽模式，实际完全暴露——这是比功能缺陷更严重的安全陷阱。

**修复方案**：`--stealth` 与无密码组合时**直接报错终止**（`Stealth mode requires a password`），或让 `resolve_password` 把 `stealth` 纳入 `encrypt_flag` 触发交互式输入（推荐后者，体验更顺）。

### 1.4 隐蔽载体不可检测 → 二次注入 → 原始文件事实性损坏

**位置**：`engine.rs:191`（write 前 `locate(None)` 重复注入检查）、`engine.rs:547-551`（read）、`engine.rs:703-707`（remove）——可否认性设计使 stealth 载体对无密码者不可见。

**问题链**（已实证完整复现）：

1. `write --stealth -p pw1` 成功（COM#1，317B）；
2. 无密码 `inspect` → `Has Hidden Data: false`（设计使然）；
3. 再次 `write -p pw2`（无 stealth）成功注入 COM#2——**"已含隐藏数据"检查被规避**；
4. `remove -p pw1` 报告 `100% verified identical`，但还原到的是"带 COM#1 的中间态"（278,865B ≠ 原始 278,544B）——真正的原始文件已无法干净还原。

**附带 Bug**：`locate(None)` 优先于密码定位。上述场景中 `remove -p pw1` 实际切除的是**第二个标准信封**（COM#2），残留的反而是第一个 stealth 信封——密码参数被无声忽略，操作对象错误。

**修复方案**：
- read/remove/inspect 中若提供了密码，**优先以密码派生魔数 locate**，`None` 结果后再回退标准魔数扫描；
- write 的重复注入检查增加宿主侧启发式：载体大小 > `orig_host_size` 记录不可得，但可扫描"是否存在**任何**格式合规的可疑容器"（如 JPEG SOS 前出现超大 COM 段、ZIP CD 前空隙、PE overlay 高熵区）并警告；
- 文档中明确写入"隐蔽载体不可重复注入检测"的使用约束。

---

## 2. P1 级问题（功能缺陷）

### 2.1 JPEG `auto` 策略容量边界误判

**位置**：`engine.rs:302-308`（`est_payload_len` 公式）；Python `engine.py:215` 相同。

**根因**：预估公式 `to_encrypt_len + ceil(len/2MB)*16` **漏算了每个分块 4 字节的 `chunk_len` 前缀**，实际 UBE 比预估大 `4 × 块数`。当预估恰好 ≤ 65,533 而实际 > 65,533 时，`auto` 选了 `app_segment`，inject 抛硬错误而不是按文档承诺自动降级 `eof`。

**实证**（构造 65,229B 随机载荷，est_ube = 65,533B 恰在上限内）：

```
write -c file-06.jpg --stdin -p testpw < rand.bin
→ [ERROR] Payload size (65537 bytes) exceeds JPEG single segment maximum capacity (65533 bytes).
```

用户得到困惑错误，必须手动 `--strategy eof` 重试。

**修复**：`est_payload_len` 增加 `4 * ceil(to_encrypt_len / 2MB)`；或在 JPEG `choose_auto_strategy` 中预留余量（`ube_size > 65533 - 64` 即降级），双保险。

### 2.2 ZIP EOCD 反向搜索无记录校验

**位置**：`rust/src/adapters/zip.rs:12-34`（`find_eocd_offset`）；Python `zip.py:20-42` 相同。

**根因**：`rposition` 取尾部窗口内最后一个 `PK\x05\x06`，不校验 EOCD 记录自洽性（`eocd_pos + 22 + comment_len == file_size` 且 `cd_offset + cd_size <= eocd_pos`）。注释中混入魔数字节即误定位。

**实证**（zip 注释设为 `PK\x05\x06FAKE-COMMENT-PK\x05\x06`）：

```
verify → Level 1 [FAIL] Corrupted ZIP archive: I/O error: failed to fill whole buffer   （误报，真实 EOCD 完好）
write  → 误判 "Central Directory could not be safely adjusted" 降级 eof（降级理由错误）
```

危险变体：若假 EOCD 的 `+12` 偏移处数据巧合合理，`pre_cd_inject` 会**注入到错误偏移并改写错误的 cd_offset 字段，直接破坏归档**。

**修复**：从尾部向前逐候选校验：`pos + 22 + u16_le(comment_len) == file_size` 且 `cd_offset + cd_size <= pos`，第一个通过者即为真 EOCD；同时把 `read_exact` 失败转换为 `CorruptedData("EOCD record truncated")` 友好错误。

### 2.3 Rust 丢失 chmod / 权限克隆

**位置**：`engine.rs:465-467`（write）、`engine.rs:754`（remove）——仅 `set_file_times`，无任何权限同步。

**证据**：Python `engine.py:356,600` 有 `os.chmod(target_path, orig_mode)`；设计文档 8.4 节明确承诺"自动同步原载体的权限模式（chmod）与访问/修改时间戳（os.utime）"。Linux 上原地写入可执行载体（ELF/脚本/带 +x 的 PE）会**丢失执行位**。

**修复**：写入前 `std::fs::metadata(carrier).permissions()` 暂存，提交后 `std::fs::set_permissions` 还原（Unix 用 `PermissionsExt` 保留 mode 位；Windows 同步只读属性）。

### 2.4 `--preserve-time` 无法关闭

**位置**：`cli.rs:77`（`default_value_t = true`，无对应关闭开关）。

**证据**：Python `cli.py:264` 提供 `--no-preserve-time`。Rust 用户无法选择不保留时间戳，跨语言行为不一致（文档 9 节接口规范亦未体现该差异）。

**修复**：增加 `--no-preserve-time`（`action = SetTrue` 的反向开关），或与 Python 对齐语义。

---

## 3. P2 级问题（健壮性 / 工程质量）

| # | 位置 | 问题 | 建议 |
|---|------|------|------|
| 9 | `crypto.rs:235` | `decrypt_stream_from_chunks` 中 `vec![0u8; chunk_len]`，损坏/恶意信封可触发最高 4GB 分配（OOM DoS） | 校验 `chunk_len <= CHUNK_SIZE + 16`，越界直接 `CorruptedData` |
| 10 | `png.rs:114/128`、`jpeg.rs:153`、`mp4.rs:109`、`zip.rs:124`、`pe.rs:189` | `while let Ok(n) = reader.read(..)` 静默吞 IO 错误，CRC/数据可能写一半而不报错 | 改为 `loop { match read { Ok(0)=>break, Ok(n)=>.., Err(e)=>return Err } }` |
| 11 | `envelope.rs:111-163` | `unpack` 不校验 `version`/`reserved`，未来版本或损坏头部被静默接受 | 校验 `version == CURRENT_VERSION`，未知版本明确报错 |
| 12 | `adapters/mod.rs:80-83` | 默认 `strip` 的 `patch_offset > 0` 判断：合法 patch 在偏移 0 会被跳过；且 patch 坐标按 stego 系写入 out（与 ZIP 专用 strip 差一个 `inject_size`）——当前仅 ZIP 启用 patch 且已重写 strip，属潜在陷阱 | 改用 `Option<u32>` 语义或 `patch_offset != u32::MAX` 哨兵；注释声明坐标系约定 |
| 13 | `zip.rs:148` | `patch_offset = (eocd_pos + 16 + ube_size) as u32`，zip > 4GB（大注释）时截断 → remove 写错位置 | 协议层 `patch_offset` 升 u64（跨语言同步）或超限拒绝 pre_cd_inject |
| 14 | `pdf.rs:52` | xref-stream 型 PDF（无 `trailer` 关键字）时 `new_obj_num` 默认 **9999**，可能撞号；且增量 trailer 缺 `/Root` | 从尾部对象流解析最大对象号；无 `/Root` 时显式警告或拒绝 incremental |
| 15 | `cli.rs:499-513` | `verify` 恒返回退出码 0（即使 Level FAIL）；Python 在 L1/L2 失败时返回 1 | 对齐 Python 退出码语义，便于脚本化 |
| 16 | `cli.rs:369-379` | read 密码重试依赖错误字符串匹配 `"Password required"`；stealth 载体无密码时提示"无隐藏数据"而非引导 | 用错误变体（`StrHideError::Password`）判别，停止字符串匹配 |
| 17 | `rejection.rs:264-270` | 未检查父目录写权限（Python 有 `os.access(parent_dir, W_OK)`）；readonly 属性检查在非 Windows 不可靠 | 补父目录可写探测； Unix 用 access(2) 语义 |
| 18 | `rejection.rs:179-190` | JAR 签名检查仅认 `.jar/.war/.ear` 扩展名，签名 ZIP 改名 `.zip` 可穿透（Python 同样） | 对 ZIP 载体统一扫描 CD 中 `META-INF/*.{SF,RSA,DSA}`，与扩展名解耦 |
| 19 | `cli.rs:536-563` | `unescape_string` 不支持 `\xHH`/`\0`/`\uXXXX`（Python 用 `codecs unicode_escape` 全支持） | 补全或文档注明差异 |
| 20 | `engine.rs:459/748` | `.bak` 备份静默覆盖既有 `.bak`（Python 同样） | 重名追加时间戳，与 SOUL.md 备份规范对齐 |
| 21 | `Cargo.toml:4` | `edition = "2024"` 与设计文档"Rust 2021"不符 | 修正文档或确认版本策略 |
| 22 | 全局 | clippy 23 个警告：16× collapsible_if、5× `unwrap` after `is_some`、1× too_many_arguments（`write_carrier` 9 参）、1× manual_div_ceil | `cargo clippy --fix` + 参数打包为 `WriteOptions` 结构体；CI 加 `-D warnings` |
| 23 | `mp4.rs:187-208`、`png.rs:209-226` | `verify_structure` 深度不足：MP4 只查首个 box 类型（Python 遍历整个 box 树）；PNG 只查尾部 IEND（Python 遍历所有 chunk 并验 CRC） | 补全结构遍历，Level-1 诊断才有意义 |
| 24 | `engine.rs:179-180` | `choose_auto_strategy(cf, 0)` 是死计算（312 行会用 `est_ube_size` 重算），误导读者 | 删除首次调用 |

---

## 4. Rust vs Python 行为分歧清单（跨语言一致性）

| 场景 | Python | Rust | 影响 |
|------|--------|------|------|
| JPEG `eof` 策略 + EOI 后尾部垃圾 | UBE 插在 EOI 后、垃圾前 → **自检失败，写入被拒**（fail-safe 但功能不可用） | UBE 追加到物理末尾 → **完整闭环，实测还原逐比特一致** | Rust 更优；建议 Python 对齐 Rust 行为 |
| MP4/PDF `locate` EOF 回退 | 不校验 `ube_offset + ube_total_size == file_size`，任意合法 trailer 即返回 "eof" | 严格校验边界 | Rust 更优 |
| 权限克隆 | `os.chmod` 恢复 mode | 无 | **Rust 缺失**（见 2.3） |
| `--no-preserve-time` | 支持 | 不支持 | **Rust 缺失**（见 2.4） |
| `-s` 短策略参数 | 支持 | 仅 `--strategy` | 小差异，文档同步即可 |
| `verify` 退出码 | L1/L2 失败返回 1 | 恒 0 | **Rust 偏差**（见 #15） |
| read 时 trailer 边界复验 | 有（`engine.py:500-508`） | 无（仅靠 locate） | 建议 Rust 补深度防御 |
| 重复注入检查 | `locate(cf)` 无密码 | 同 | **共性缺陷**（见 1.4） |

> 结论：分歧中 3 项 Rust 更优、4 项 Rust 缺失/偏差。建议以本文清单为准做一次双向对齐，并把跨语言矩阵测试扩充到上述全部分歧场景（当前 17 项跨语言测试未覆盖尾部垃圾 PDF/JPEG、路径穿越、多信封等）。

---

## 5. 测试与工程化建议

1. **Rust 原生测试几乎空白**：当前仅 2 个 crypto 单元测试，适配器/引擎/CLI 层全靠 Python 跨语言测试间接覆盖。建议在 `rust/tests/` 建立集成测试：7 个适配器 × inject/locate/strip 闭环、engine 五命令、CLI e2e（含备份/原子性/时间戳），把 `test_rust_cross_compat.py` 的场景沉淀为 Rust 侧资产。
2. **CI 门禁**：`cargo clippy -- -D warnings` + `cargo test` + `pytest` + 跨语言矩阵 + 批量样本（26 文件）四层。
3. **错误信息友好化**：`I/O error: failed to fill whole buffer` 这类底层错误应转换为领域语义（如 "EOCD record truncated"）。
4. **内存优化（大载荷场景）**：write 路径存在 4 份全量拷贝（`to_encrypt_bytes` + `compressed_buf` + `payload_cipher_buf` + `tmp_ube`），100MB 载荷约 400MB 内存。可将 `tmp_ube` 组装与 inject 合并为流式管道（适配器接口已支持 `ube_in: &mut dyn SeekRead`，可扩展为双段流）。Python 侧同样问题，可作为跨语言共同优化项。
5. **协议演进预留**：`patch_offset` u32→u64、chunk_len 上限校验、version 分发，建议在 v2.3 一次性升级并保持双向兼容。

## 6. 后续功能演进（来自 docs/strhide_stealth_improvement_analysis.md）

- P0：JPEG `APPn/COM` 多段链（>64KB 载荷合规化，消除 eof 降级的 Trailing-data 破绽）—— ✅ **已于 2026-10-17 实施落地**：Rust 与 Python 双端引入流虚拟化（`SubStream` / `open_ube_reader` / `open_ube_stream`），采用规范合规的应用私有段 `APP15`（`0xFF 0xEF`，物理隔离原图 Comment 与 ExifTool 特征暴露），实现 65534B 借位切片防截断算法与 100% 逐比特无损还原，容量上限由 64KB 跃升至 64MB，读取端双模兼容历史 `COM` 段与 `EOF`；
- P1：PNG `zTXt/iTXt` 标准文本块替换 `prIv`；MP4 `moov.udta.meta` 容器下沉；
- P2：PE/ZIP Slack Hiding（<4KB 文本零膨胀）；
- 新载体候选：RIFF（AVI/WAV/WebP）、GIF、ELF/Mach-O、SQLite、tar/gz（docs/file_format_hex_ascii_characteristics.md 已给出特征分析基础）。

---

## 7. 修复优先级建议

```
第一批（P0，数据安全）：1.1 PDF 尾部垃圾 → 1.2 路径穿越 → 1.3 stealth 降级拦截 → 1.4 多信封定位优先级
第二批（P1，功能正确）：2.1 auto 容量预估 → 2.2 EOCD 校验 → 2.3 chmod → 2.4 --no-preserve-time
第三批（P2，健壮性）：#9~#24 按上表逐项，配合 clippy -D warnings 与 Rust 集成测试补齐
第四批（演进）：第 6 节功能路线 + 跨语言行为对齐
```

每批修复后须回归：`cargo test` + `pytest python/tests` + 26 样本批量 + 跨语言双向矩阵，并在 `docs/CHANGES-YYYYMMDD.md` 顶部追加变更记录。
