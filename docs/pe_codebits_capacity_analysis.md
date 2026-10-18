# pe_codebits 容量实测与开销拆解

> 文档编号：STRHIDE-DOC-20261018-02  
> 状态：完成  
> 涉及模块：核心引擎（`engine.rs` / `envelope.rs`）、PE 适配器（`pe.rs` / `pe_codebits.rs`）  
> 关联变更：`CHANGES-20261018.md`（21:17 64 KiB 截断修复、21:43 信封瘦身）

---

## 1. 背景

用户最初反馈：`pe_codebits` 在 `temp/testapps` 下测试的大部分文件只有 **< 300 B** 可用空间，导致密码加密模式（最小加密信封 310 B）根本装不下。

根因有两处，均已修复：

1. **64 KiB 头窗口截断**（已修复）：`parse_pe_code_layout_streaming` 只读文件前 64 KiB 作为 `head`，却把它交给按"整文件"设计的 `pe_code_layout`，后者用窗口长度 `data.len()`（= 64 KiB）充当 `host_size`，导致 `.text` 扫描被截断、节尾零区（几乎全在 64 KiB 之后）整段丢弃。修复后 19 个未签名 exe 中可容纳 310 B 加密信封者由 0 → 11。
2. **信封元数据过大**（已修复 / A1 方案）：旧元数据用 137 B JSON，其中 64 B 仅是 SHA-256 的十六进制文本。改为紧凑二进制块（`u8 version | u16 name_len | filename | varint raw_size | 32 B SHA-256 | varint created_at`，`FLAG_COMPACT_META = 0x20`）后，最小信封由 274/310 B 降至 **183/219 B**。

本文在以上修复的基础上，对具体载体做实测，回答"8 位密码 / 8 位提示 / stealth 模式分别能放下多少用户字节"。

---

## 2. 实测对象与方法

- **载体**：`temp/testfiles/caffeine64.exe`（PE32+，433,664 B）
- **inspect 口径**：`pe_codebits [auto preference]: ≤ 424 B`，瓶颈同时来自
  - codebits 可用位位置推算出的信封上限 **424 B**
  - 最长零值冗余（slack）连续段 **438 B**（封顶还原 diff）—— 两者取小再扣 14 B 通道头
- **方法**：`temp/probe8_capacity.py` 用随机不可压缩字节（压缩率 < 2% 时引擎跳过压缩）做二分搜索，对每种模式反复 `write → read` 回环校验，取成功写入的最大用户载荷字节数。文件名固定 8 字节 `data.bin`（触发元数据块写入）。
- **密码 / 提示**：统一 8 字符（`12345678` / `abcdefgh`），以对齐用户问题中的"8 位"前提。

---

## 3. 实测结果（caffeine64.exe，pe_codebits）

| 模式 | 密码 | 提示 / 隐身 | 最大用户字节 | 实测信封开销 |
|---|---|---|---|---|
| 明文 | 无 | — | **238 B** | 183 B |
| 加密 | 8 位 | — | **202 B** | 219 B |
| 加密 + 提示 | 8 位 | 8 位提示 | **194 B** | 227 B |
| 隐身（stealth） | 8 位 | stealth | **202 B** | 219 B |

结论（直接回答）：
- 8 位密码（加密）→ **202 用户字节**
- 8 位密码 + 8 位提示 → **194 用户字节**（提示本身固定占 8 B）
- stealth（8 位密码）→ **202 用户字节**（与同参数加密**字节数完全相同**，仅魔数由密码派生，更难被特征扫描）
- 明文无密码 → **238 用户字节**

---

## 4. 信封开销拆解（已用 1 字节载荷标定确认）

以 1 字节载荷写入同一载体标定基准：

| 模式 | 1 B 载荷时 UBE | 固定开销 |
|---|---|---|
| 明文 | 184 B | **183 B** |
| 加密 | 220 B | **219 B** |

拆解（与 `rust/src/envelope.rs`、`engine.rs` 代码一致）：

- **明文基础信封** = `HEADER_SIZE 112` + 紧凑元数据 + `TRAILER_SIZE 24`
  - 紧凑元数据 = `1(version) + 2(name_len u16) + 8(name) + 1(raw_size varint) + 32(sha256) + 3(created_at varint)` = **47 B**（本机时钟下 `created_at` 约 3 字节 varint；若时间为更远的未来会略增）
  - 112 + 47 + 24 = **183 B** ✓
- **加密比明文固定多 +36 B**：
  - 元数据 GCM 认证标签 **16 B**（`exact_meta_len = meta_raw.len() + 16`）
  - 载荷分块封装 **20 B**：每个加密分块 = 4 B 长度 + 密文 + 16 B 标签；小载荷单分块（`chunk_count = max(1, ceil(len/CHUNK_SIZE))`）
  - 183 + 36 = **219 B** ✓
- **8 位提示固定多 +8 B**：提示文本按原文字节直接写入信封（`hint_len` 字段 + 对应字节），与长度无关，1 字符 = 1 B。
- **stealth = 加密尺寸**：仅把 `header_magic` / `trailer_magic` 由 `derive_stealth_magics(password)` 派生，不改变任何字段长度，故容量与同参数加密一致。

因此对任意用户载荷 P（字节）：
- 明文 UBE ≈ 183 + P
- 加密 UBE ≈ 219 + P
- 加密 + 提示 UBE ≈ 227 + P
- 隐身 UBE ≈ 219 + P

实测最大值比"424 上限 − 开销"略小约 3 B，是因为 `pe_codebits` 还要在零值 slack 中预留还原 diff（被改写指令原始字节），该预算与载荷同向增长，策略在边界处多留了余量。

---

## 5. 容量瓶颈说明

- `pe_codebits` 容量公式：`cap = min(usable_positions/8 - 14, max_zero_run - 14)`，14 为通道头长度。
- caffeine64.exe 的两项约束几乎相等（424 vs 438 扣 14），所以信封满打满算约 424 B，减去固定开销后落到上述用户字节数。
- **带 Authenticode 签名的 PE 被设计上拒绝**：改 `.text` 会使签名失效。例如 `d3dcompiler_47.dll` 的 codebits 容量高达 ~3,826 B，但因签名被拒——这是安全/完整性约束，不是容量问题。

---

## 6. 复现

脚本已保留在 `temp/probe8_capacity.py`，可在其他载体上复测同等四模式：

```bash
cd C:/Home/Projects/strhide
# 修改脚本内 CARRIER 指向目标文件后运行
python temp/probe8_capacity.py
```

脚本输出每种模式的最大用户字节数与对应 UBE 大小及开销。二分上界默认 600，可按需调大（当载体容量超过 600 B 时）。

---

## 7. 后续候选（未实施）

- **B 方案（分块 diff）**：把还原 diff 拆成多段塞进多个零 slack 间隙，突破"单连续 438 B"限制，用于 > 500 B 的超大载体。
- **C 方案（mov↔lea 指令编码扩展）**：把更多指令对纳入 codebits 通道，净增益约等于将 slack 由 2 态编码升到 3 态；经分析 A1 已解决 text 受限类载体的瓶颈，且需保证原始文件功能不受影响，故本次未采用。
