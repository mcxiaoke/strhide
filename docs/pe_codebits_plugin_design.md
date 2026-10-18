# PE 代码位信道隐写（pe_codebits）插件设计文档

> 版本：v1.0 ｜ 状态：设计定稿，核心算法已完成原型验证（见 §10.3）｜ 范围：将 steg86 的 x86/x64 指令编码隐写术以自包含插件形式移植进 strhide，首发仅支持 Windows PE32 / PE32+

---

## 1. 背景与目标

### 1.1 背景

strhide 现有的 Windows PE 支持只有 `pe_overlay` 一个策略：把 UBE 信封追加到 PE 镜像边界之后。该策略可靠但有两个固有缺陷：

1. **文件尺寸增大**——追加的信封（最小 183 字节明文 / 219 字节加密，实测见 §10.2）立即可见于文件长度，是对抗尺寸分析时的明显破绽；
2. **结构异常**——镜像边界之后出现的数据块是 `binwalk`、PE 解析器的标准检测目标。

steg86（github.com/woodruffw/steg86，本地分支 v0.2.1）展示了另一条路径：利用 x86 ModR/M 字节的编码冗余，把信息藏进 `.text` 段**既有指令的等价编码形态**里，不改变文件尺寸、不改变指令语义。本设计将该方法移植为 strhide 的 PE 策略插件。

### 1.2 目标

- 新增策略 `pe_codebits`（strategy_id = 8），载体为 PE32/PE32+（x86/x64）；
- **文件尺寸零增长**：嵌入/提取/还原全程不改变宿主文件长度；
- 延续 strhide 核心承诺：**100% 逐比特还原**（remove 后 SHA-256 与原始宿主一致）；
- 完整复用引擎既有能力：加密（AES-256-GCM）、压缩、隐身模式、密码提示、inspect / verify 三级校验、备份与原子写入；
- Rust 与 Python 双实现行为逐比特一致（交叉兼容）。

### 1.3 非目标

- 不兼容 steg86 容器格式（用户已拍板：自有魔数，两工具不互读）；
- 不支持 ARM64 / 其他架构 PE（遇到即回退 `pe_overlay`）；
- 不承诺对抗深度静态取证（反汇编 diff、指令形态分布统计仍可发现痕迹，见 §12.2）；
- 不移植 steg86 的 NOP 滑梯隐写与 add/sub 重写（Hydan 进阶技巧），留作未来扩展（§16）。

---

## 2. 参考实现调研结论（steg86）

对 `C:\Home\github\steg86` 源码（`src/steg86/binary.rs` 等）的调研结论：

| 维度 | steg86 做法 | 移植结论 |
| --- | --- | --- |
| 隐写载体 | 各格式的代码段（ELF `.text` / Mach-O `__text` / PE `.text`），仅取 `virtual_size` | 采用；PE 侧钳位规则见 §4.2 |
| 指令筛选 | 9 类 ALU 双操作数指令（ADD/ADC/AND/OR/XOR/SUB/SBB/MOV/CMP 的 `rm,r` 与 `r,rm` 两形态）+ TEST 交换律 | 原样采用（§4.1） |
| 容量单位 | 每条"寄存器-寄存器"指令 1 比特 | 原样采用 |
| 容器 | 自有 4 字节头（`w` + version + u16 len）+ 载荷；分支版追加 v2 加密容器（HKDF+AES-GCM） | **不采用**：长度上限 16KB、与 strhide UBE 功能重复 |
| 解码器 | iced-x86 1.21（Rust crate） | 采用；Python 侧用同源 PyPI 绑定（§11） |
| 还原能力 | **无**（只写不还原，extract 后二进制保持改性） | **必须自建**（§6），这是移植的真正难点 |
| 嵌入安全性 | 要求两种形态编码等长；跳过 `.text` 内嵌数据（解码 INVALID） | 采用并加强（§4.2 过滤器 F1/F2） |

steg86 已验证的部分（可直接继承）：ModR/M 语义对机制、等长编码约束、无重定位影响（寄存器-寄存器指令不含地址）、线性扫描 + INVALID 跳过的容错。

---

## 3. 总体架构：插件化接入

### 3.1 分层

```
┌─────────────────────────────────────────────────────────────┐
│ strhide 引擎（编排层）                                        │
│  拒绝检查 · 备份 · 原子重命名 · UBE 组装（加密/压缩/隐身）      │
│  read · inspect · verify · remove 编排                       │
└──────────────────────────┬──────────────────────────────────┘
                           │ UBE 字节（不透明载荷，inject_offset=0）
┌──────────────────────────▼──────────────────────────────────┐
│ HostAdapter trait（既有插件接口，零改动）                      │
│  detect · locate · inject · strip · open_ube_reader           │
└──────────────────────────┬──────────────────────────────────┘
                           │ strategy = "pe_codebits"
┌──────────────────────────▼──────────────────────────────────┐
│ pe_codebits 插件（新增，自包含）                               │
│  PE 解析 → .text 定位 · profile（语义对扫描）                  │
│  位信道编解码 · 信道容器（STHC）· 还原 diff                    │
│                         │                                    │
│                    iced-x86 1.21（Rust crate ↔ PyPI 同源）    │
└─────────────────────────────────────────────────────────────┘
```

**传输层与载荷层分离**：插件在传输层完全自带数据结构（§5 信道容器：自有魔数 `STHC`、独立版本号与字段布局），与 UBE 无关、可独立演进；UBE 仅作为一段不透明的 N 字节载荷搭车。这样 `read / inspect / verify` 的引擎通用逻辑（密码提示、元数据、AEAD、三级校验、隐身魔数派生）全部原样复用——若载荷层也另起容器，引擎需为它开第二条 read/inspect/verify 路径，Rust、Python 各写一遍且 CLI 功能缺损（备选论证见 §9）。

### 3.2 模块划分

插件代码按"格式无关核心 + 格式定位器"组织，未来支持 ELF/Mach-O 只需新增定位器：

| 模块 | 职责 | 格式相关性 |
| --- | --- | --- |
| `profile` | 线性扫描、指令筛选、位置序列生成 | 无关（吃 byte range + bitness） |
| `channel` | 容器打包/解包、位序转换 | 无关 |
| `embed / extract` | 位信道写入/读取 | 无关 |
| `restore` | diff 应用、slack 定位与清零 | 无关 |
| `pe_locator` | .text 定位、bitness 判定、slack 扫描 | PE 专属 |

Rust：`rust/src/adapters/pe_codebits.rs`（或 `pe.rs` 内子模块）；Python：`python/strhide/adapters/pe_codebits.py`。

---

## 4. 位信道原理

### 4.1 语义对与交换律

x86 的 ModR/M 字节可编码"寄存器-寄存器"操作，于是同一寄存器间运算存在两种等长编码：

| opcode | 助记符 | 方向 |
| --- | --- | --- |
| `89 /r` | `MOV r/m32, r32` | 存（rm ← reg） |
| `8B /r` | `MOV r32, r/m32` | 取（reg ← rm） |

`mov eax, ebx` 既可编码 `89 D8` 也可编码 `8B C3`，语义完全相同。每条这样的指令承载 1 比特：

- **语义对**（ADD/ADC/AND/OR/XOR/SUB/SBB/MOV/CMP 的 `rmN,rN` ↔ `rN,rmN`，8/16/32/64 位共 32 对）：比特 0 = `rm,r` 形态（tuple.0），比特 1 = `r,rm` 形态（tuple.1）；
- **交换律指令**（TEST 的 `rmN,rN`）：操作数互换不改变语义（`test eax,ebx` 与 `test ebx,eax` 标志位相同），比特 0 = `op0_register < op1_register`，比特 1 = 反之。寄存器序采用 iced `Register` 枚举序（双实现同源，§11）。

操作码集合与 steg86 完全一致（§2），不扩展。

### 4.2 profile 规则（位置序列生成）

对 `.text` 切片 `T`（起点 `pointer_to_raw_data`，长度 `min(virtual_size, size_of_raw_data)`，钳位到文件末尾）做一次 iced 线性扫描，按序收集通过以下全部条件的位置：

```
F0  insn.code != INVALID                     # .text 内嵌数据（跳表/常量）跳过，与 steg86 一致
F1  insn.code ∈ SUPPORTED_OPCODES
F2  op0_kind == REGISTER 且 op1_kind == REGISTER
F3  TEST 且 op0_register == op1_register 时跳过（无可编码信息）
F4  重编码一致：encode(insn) == T[ip : ip+len]      # 挡掉冗余前缀等非最小编码
F5  反向等长：len(encode(other_form(insn))) == len  # 两种形态必须等长
```

- **F4/F5 是本设计相对 steg86 新增的过滤器**，目的是保证"翻过去"和"翻回来"都是字节级精确的：F4 确保该位置的原编码就是最小编码（否则 strip 时重编码无法复现原字节）；F5 确保翻转不改变指令长度（否则破坏后续所有边界）。实测 8 个真实 PE 样本上 F4/F5 **零淘汰**（§10.2），即过滤器正常情况下不损失容量，只作安全网。
- **F0 的安全性**：被记录的候选必须满足"特定双操作数 opcode + modRM ≥ 0xC0"。ASCII 文本、小偏移跳转表等数据不可能造出 `≥0xC0` 的 modRM 搭配，不会把数据误当指令改写。
- 输出位置序列 `P = [(offset, code, r0, r1, bit, len), ...]`，offset 为 `.text` 内偏移，按扫描序严格递增。
- bitness 判定：COFF `Machine` = 0x14C → 32；0x8664 → 64；其他值 → 不支持（回退 overlay）。

### 4.3 位置序列的确定性（关键性质）

所有改写都是**等长原位替换**，指令边界不受影响，因此嵌入后重新扫描得到的位置序列与嵌入前**完全一致**——原型已验证（§10.3 检查项 1）。读取端因此无需存储任何位置表，仅凭"重新 profile"即可定位全部信道比特。

---

## 5. 信道容器格式 v1（STHC）

### 5.1 布局

```
.text 位信道（占用位置序列 P 的前 R 个位置，连续放置）：

  位置 P[0 .. 111]        → 信道头 14 字节（MSB-first 位序）
  位置 P[112 .. 112+8N-1] → UBE 字节 N 字节

  文件零值 slack 区域     → 还原 diff 位图 ceil(R/8) = 14+N 字节（§6）

其中 R = (14 + N) × 8
```

### 5.2 信道头字段（14 字节，小端）

| 偏移 | 字段 | 长度 | 说明 |
| --- | --- | --- | --- |
| 0x00 | `magic` | 4 | 标准模式：`STH!`（与 UBE trailer 魔数一致）；隐身模式：口令派生的 4 字节。**实施机制**：信道魔数直接取 UBE 载荷末尾 4 字节（引擎在调用 `inject` 前已确定 trailer 魔数），适配器因此无需感知隐身/口令；设计定稿时为 `STHC` 占位，实施时按此机制实现（偏差记录见 §9-D1） |
| 0x04 | `version` | 1 | `0x01` |
| 0x05 | `flags` | 1 | `0x00` 保留。bit0 预留：分块 diff（v2，§16） |
| 0x06 | `ube_len` | 4 | u32 LE，载荷 UBE 字节数 N |
| 0x0A | `slack_off` | 4 | u32 LE，还原 diff 在文件中的绝对偏移（PE < 4GB，u32 足够） |

### 5.3 放置与读取规则

- **放置**：信道比特流 = `header(14B) || UBE(NB)` 按 MSB-first 展开；第 i 比特写入位置 `P[i]`。若该位置当前比特与待写比特不同，则把指令改写成相反形态（语义对换 opcode / TEST 换操作数次序），并在 diff 中记录该位置。
- **读取**：重新 profile 得 `P'`（与 `P` 一致，§4.3），顺序读取 `P'[0..R-1]` 的当前比特，拼回字节流；校验 magic / version，取 `ube_len`。
- **定位（locate）**：只需读前 112 比特校验 magic（标准或隐身派生）。随机 `.text` 比特命中 4 字节魔数的概率约 2⁻³²，叠加 version/N 合理性检查，误报可忽略。

### 5.4 与 UBE 的接口

插件把 UBE 视为不透明字节流：不解析、不校验、不改写。UBE 内部的 `inject_offset / inject_size / patch_offset` 对打散信道恒为 0，`trailer.ube_offset` 亦为 0——引擎对打散策略跳过文件偏移回填后（§8.2），这些零值即最终值，语义自洽。

---

## 6. 还原机制：diff 位图 + 零值 slack

### 6.1 问题：为什么必须运输还原信息

strhide 承诺 remove 后宿主**逐比特**还原（SHA-256 校验）。位信道嵌入会翻转约一半信道位置的指令形态（原型实测 52.6%），而这些位置"原来是哪种形态"是宿主自带的 1 比特/位置信息，与信道内容相互独立，**必须随信道运输**，否则 strip 无法还原。steg86 无此机制（它只写不还原），这是移植中唯一必须新建的核心机制。

### 6.2 diff 定义

- diff 是覆盖信道全部 R 个位置的位图：`bit i = 1` 表示位置 `P[i]` 在嵌入时被翻转；
- 长度 = `ceil(R/8)` = **14 + N 字节**（由 N 唯一决定，无循环依赖）；
- 存放在 PE 文件的**零值 slack** 中（§6.3），信道头 `slack_off` 记录其绝对偏移。

### 6.3 slack 选择规则

候选区间（均由 PE 头部结构直接推导，不含文件尾部 overlay 区）：

1. **头部对齐 padding**：`[节表结束, 首个节 PointerToRawData)`；
2. **各节尾部 padding**：对每个节 `[ptr + min(vsize, rawsize), ptr + rawsize)`，钳位到文件末尾。

在每个候选区间内取极大连续零 run。选择规则：**长度 ≥ 14+N 的最短 run；并列取文件偏移最小者**（最小化对文件 padding 结构的改动面）。

安全约束：**写入前逐字节校验整个 run 为零**；strip 时将该区间清零即完成还原——因为写入时它确实是全零。即使某些打包器往 padding 里藏了数据，只要非零就不会被选中，天然防御。

### 6.4 strip 算法

```
prof = profile(stego .text)
channel = 读取 prof[0..R-1] 当前比特拼成字节流
N = channel.ube_len; diff_off = channel.slack_off; diff_len = 14 + N
diff = file[diff_off : diff_off + diff_len]
for i in 0..R-1:
    if diff_bit(diff, i):
        p = prof[i]
        text[p.off : p.off+p.len] = encode(other_form(p))   # 翻回原形态
file[diff_off : diff_off + diff_len] = 0x00 * diff_len      # 清零即还原
```

### 6.5 正确性论证

1. **Region A（.text 信道区）**：diff 完整记录了每个被翻转的位置；过滤器 F4 保证原形态的重编码与原始字节逐字节一致，故翻回即精确还原；
2. **slack 区**：写入前校验全零，strip 清零，逐比特还原；
3. **其余字节**：全程未触碰；
4. 引擎层再以 `orig_host_sha256` 全量校验兜底（§13 错误矩阵）。

---

## 7. 算法伪代码

### 7.1 profile

```
profile(text, bitness) -> positions:
    dec = Decoder(bitness, text, ip=0)
    for insn in dec:
        if insn.code == INVALID: continue                      # F0
        if insn.code not in SUPPORTED: continue                # F1
        if op0_kind != REGISTER or op1_kind != REGISTER: continue   # F2
        r0, r1 = op0_register, op1_register
        if code in COMMUTATIVE and r0 == r1: continue          # F3
        other = other_form(code, r0, r1)
        if encode(insn) != text[ip:ip+len]: continue           # F4
        if len(encode(other)) != len: continue                 # F5
        positions.append(Position(ip, code, r0, r1, bit(code,r0,r1), len))
```

### 7.2 embed

```
prof = profile(text)
R = (14 + N) * 8
if len(prof) < R: Err(CapacityExceeded)                       # §10.1
run = pick_zero_slack_run(14 + N)                             # §6.3，无则 Err(NoSlack)
bits = bits_msb(header || ube)                                # §5.2/5.3
diff = bytearray(ceil(R/8))
for i, b in enumerate(bits):
    p = prof[i]
    if p.bit == b: continue
    nb = encode(other_form(p))
    assert len(nb) == p.len
    text[p.off : p.off+p.len] = nb
    set_diff_bit(diff, i)
file[run.off : run.off + len(diff)] = diff
```

### 7.3 extract（locate 的子集 + 完整读取）

```
prof = profile(text)
if len(prof) < 112: Err(NotFound)
head = bits_to_bytes([prof[i].bit for i in range(112)])[:14]
if head.magic != expected: Err(NotFound)
N = head.ube_len
if len(prof) < (14+N)*8: Err(CorruptedData)
channel = bits_to_bytes([prof[i].bit for i in range((14+N)*8)])
return channel[14:]                                            # UBE 字节
```

### 7.4 strip：见 §6.4。

---

## 8. 适配器与引擎集成

### 8.1 PE 适配器（trait 方法逐条）

| 方法 | 行为 |
| --- | --- |
| `detect` | 不变（MZ + PE 签名） |
| `supported_strategies` | `["pe_codebits", "pe_overlay", "eof"]`（codebits 列首位） |
| `choose_auto_strategy` | 解析 PE → profile → 检查 `usable ≥ (14+N)*8` 且存在长度 ≥ 14+N 的零 run；满足选 `pe_codebits`，否则 `pe_overlay` |
| `inject` | 校验 Authenticode（拒绝，同现有规则）→ 定位 .text → profile → 容量/slack 检查 → embed（§7.2）→ 流式写出：`[0, text_off)` 原样 + 改性 .text + `[text_off+scan_len, EOF)` 原样 → 返回 `(0, 0, 0, 0)` |
| `locate` | 解析 PE → profile → 读 112 比特校验 magic（`expected_trailer_magic` 或标准 `STH!` 对应值）→ 返回 `(0, N, "pe_codebits")`；信道检查先于文件尾 trailer 检查（保证两种信封互不误判） |
| `open_ube_reader` | 重新解码信道（§7.3），返回内存中 UBE 字节的虚拟 SeekRead 流 |
| `strip` | §6.4；忽略 `header` 参数（还原由信道自包含驱动） |
| `verify_structure` | 不变（PE 头部结构校验） |
| `suspicious_structures` | 不变（返回空）。隐身模式下信道不可知，与现有隐身 overlay 行为一致 |

### 8.2 引擎改造点（共 6 处，均不改变现有格式行为）

| # | 位置 | 改动 | 对现有策略的影响 |
| --- | --- | --- | --- |
| 1 | Rust `engine.rs` write（约 L396-427，header/trailer 文件偏移回填） | 打散策略跳过回填（inject 已嵌入最终字节） | 无（仅 `pe_codebits` 分支） |
| 2 | Rust `engine.rs` write 自检（约 L429-444） | 从"按文件偏移回读 header"改为经 `open_ube_reader` 回读 | 行为等价：SubStream 读的就是同一段字节 |
| 3 | Rust `engine.rs` remove_carrier（约 L706-715）与 Python `engine.py` remove_carrier（约 L711-714） | header 从"seek(ube_offset)+read"改为经 `open_ube_stream` 读取 | 行为等价（SubStream 同字节）；对 JPEG 多段链反而更正确 |
| 4 | `router.rs` / `router.py` | `strategy_to_id("pe_codebits") = 8`，反向映射同步 | 纯新增 |
| 5 | `engine.rs` / `engine.py` strategy_note 分支 | `pe_codebits` 说明文案（技术说明 + 文件尺寸不变 + 容量信息） | 纯新增 |
| 6 | `PeAdapter::choose_auto_strategy`（两语言） | 容量 + slack 估算逻辑 | 纯新增 |

Python write 自检本就是 `locate`（约 L438-447），无需改动。

### 8.3 CLI 与策略元数据

- `strhide list -c x.exe` 输出含 `pe_codebits`；
- `-s pe_codebits` 显式指定；`-s ask` 交互列表含该项；
- `inspect` 输出中 `strategy = "pe_codebits"`，`ube_offset = 0`、`ube_total_size = N`（打散信道的语义：偏移 0 表示无连续存储位置，尺寸为虚拟 UBE 长度）；
- 信封头部 `strategy_id = 8` 进入协议表（文档 §3.2 策略 ID 清单同步追加）。

---

## 9. 设计备选与否决记录

| # | 备选方案 | 结论 | 理由 |
| --- | --- | --- | --- |
| A | 载荷层也用插件自有容器（完全脱离 UBE） | 否决 | read/inspect/verify 需开第二条代码路径，Rust/Python 各写一遍；密码提示、元数据、AEAD、三级校验、隐身魔数要么重写要么缺失 |
| B | 兼容 steg86 容器格式（`w` 魔数） | 否决（用户拍板） | 16KB 人工上限、格式约束、双魔数歧义；自有魔数格式干净、容量只受 .text 限制 |
| C | diff 用"自适应零翻转放置"运输（只挑选宿主原比特与待写比特相同的位置放入） | 否决 | **反演不唯一**：读取端仅凭文件无法区分"某位置承载了 diff 比特 d"与"该位置只是被跳过、原样保留"。例：宿主后续比特串为 `01`、diff 长 1 比特时，`d=0`（放第 1 位）与 `d=1`（放第 2 位）均自洽 |
| D | diff 存入 PE overlay（文件尾部） | 否决 | 文件增长量（14+N）与 pe_overlay 策略（N）相当，却仍要改 .text，无净收益 |
| E | strip 时把信道位置一律翻回"0 形态"（规范化还原） | 否决 | 违反 100% 逐比特还原承诺，原宿主非零形态的位置将被改写，SHA 校验必失败 |
| F | diff 存入 .text 信道之后的位置 | 否决 | 那些位置的翻转同样需要还原信息，无限回归 |
| G | diff 分块存入多个 slack run | 推迟 v2 | v1 用单连续 run（选择规则见 §6.3），头部 flags bit0 预留；wininit 类紧凑 PE 会因此回退 overlay（§10.2） |

### 9.1 实施偏差记录（2026-10-18，P2 实施时定稿）

| # | 偏差 | 原因 |
| --- | --- | --- |
| D1 | 标准模式信道魔数由 `STHC` 改为 `STH!`（即 UBE trailer 魔数） | 隐身模式下信道魔数必须是口令派生值才能保住可否认性；让适配器从 UBE 载荷末尾 4 字节取魔数，引擎零新增参数、适配器零隐身感知，且标准/隐身两种模式自动正确。原 `STHC` 仅是占位符，未进入任何已发布格式 |
| D2 | `parse_pe_code_layout_streaming` 曾把 64 KiB 头窗口当成完整宿主：`.text` 扫描被截断到 `0x10000 - text_offset`，且 `rawptr+rawsize > 64 KiB` 的节尾 padding 整段被丢弃 | §4.2/§6.3 的区间计算全部以"整文件"为前提，streaming 包装层却把 `pe_code_layout(&head)` 内 `data.len()` 当 `host_size`。实测 HxD64 的 5.4 MiB `.text` 只扫了 63 KiB、容量报 90 B（真实 458 B）。修复方式：抽出 `pe_code_layout_with_host(data, host_size)`，所有区间按显式宿主大小钳位 |
| D3 | 元数据块由 JSON（137 B）改为紧凑二进制（46 B），信封 274/310 → 183/219 B | 打散策略的容量受 `.text` 位数与连续零 slack 双重限制，而多数 PE 只有 220-490 B；137 B 里 64 B 是 SHA-256 的十六进制文本。用 `FLAG_COMPACT_META` 隔离，读取端两种布局并存，旧信封不受影响（详见 `smart_file_data_hiding_design.md` §3.4） |

---

## 10. 容量模型与实测

### 10.1 公式

```
R            = (14 + N) * 8          信道比特数（N = UBE 字节数）
N_max        = (usable - 112) / 8    该宿主可容纳的最大 UBE
slack_need   = 14 + N                所需连续零值 slack 字节数
```

UBE 构成（实测，2026-10-18 起使用紧凑二进制元数据）：固定头 112 + 元数据约 46（`u8 version + u16 name_len + filename + varint raw_size + 32B SHA-256 + varint created_at`）+ 尾 24 ≈ **183 字节起**（1 字节载荷、无口令）；加密追加 16 字节元数据 tag、4 字节分块长度与 16 字节载荷 tag ≈ **+36 → 219 字节起**。旧版 JSON 元数据为 137 字节（总 274/310），读取端按 `FLAG_COMPACT_META` 分支，两种格式都支持。

### 10.2 实测数据（iced-x86 Python 1.21.0，与本机 steg86 Rust 版 profile 输出逐位一致）

| 样本 | 文件大小 | 架构 | .text 扫描 | 可改造指令(usable) | N_max | slack 最大零 run | 零 run 总数 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| where.exe | 43,008 | PE32+ | 30,128 | 1,496 | 173 B | 496 B (.rsrc-tail) | 42 |
| tasklist.exe | 106,496 | PE32+ | 75,744 | 3,365 | 406 B | 464 B (.reloc-tail) | 42 |
| notepad.exe | 200,704 | PE32+ | 148,623 | 7,427 | 914 B | 376 B (.rdata-tail) | 49 |
| esentutl.exe | 409,600 | PE32+ | 276,180 | 8,207 | 1,011 B | 496 B (.didat-tail) | 49 |
| wininit.exe | 448,408 | PE32+ | 306,587 | 15,376 | 1,908 B | **240 B** (header-pad) | 49 |
| mspaint.exe | 938,496 | PE32+ | 635,228 | 23,692 | 2,947 B | 504 B (.rsrc-tail) | 49 |
| where.exe (SysWOW64) | 33,280 | PE32 | 24,428 | 1,102 | 123 B | 496 B (.rsrc-tail) | 35 |
| tasklist.exe (SysWOW64) | 79,360 | PE32 | 65,168 | 2,438 | 290 B | 368 B (.text-tail) | 35 |

结论：

- **可改造指令密度约 30-50 条/KB .text**；信道容量约 4-6 UBE 字节/KB .text；
- 隐藏一条 219 字节的最小加密信封约需 1,864 个可改造位置 + 233 字节连续零 slack——**约 50-100 KB 以上的典型 PE 才够**，更小的自动回退 `pe_overlay`；
- 过滤器 F4/F5 在全部 8 个样本上零淘汰；
- wininit.exe 类紧凑 PE（最大零 run 仅 240 B）在 v1 会回退 overlay——这是方案 G（分块 diff）要解决的问题；
- **上表的 `N_max` 只反映 `.text` 侧，实际容量是 `min(usable/8-14, max_zero_run-14)`**：本例 8 个样本的 slack 都在 240-504 B，所以真实上限约 226-490 B，加密信封（219 B）刚好落在可用区间内，明文（183 B）余量更大。

### 10.3 原型验证结果

原型脚本（`temp/pe_codebits_probe.py`、`temp/pe_codebits_prototype.py`，实施时应移植进测试套件）在真实 PE 的 `.text` 上完成闭环验证：

| 检查项 | 结果 |
| --- | --- |
| 1. embed 后重新 profile，位置序列不变 | 通过（notepad 200B/900B UBE、SysWOW64 tasklist 250B UBE） |
| 2. extract 读回信道与嵌入内容逐字节一致 | 通过（同上） |
| 3. strip 后 `.text` 与原始字节逐比特一致 | 通过（同上） |
| 4. strip 后 profile 规模稳定（语义保持） | 通过 |
| 5. 翻转率 | 52.6% / 51.6%（符合随机比特预期） |
| 6. 容量不足 | 干净失败（tasklist 500B UBE：需 4,112 位、仅有 3,365） |
| 7. 跨语言一致性 | Python profile 与 steg86 Rust profile 在 8/8 样本上逐位一致 |

### 10.4 性能

- Python 原型对 635KB `.text`（mspaint，23,692 位置）完整 profile 耗时 **92ms**；Rust 快一个量级；
- Rust 实测：9.8 MiB `.text`（WindTerm.exe，391,484 位置）的 `inspect`（完整 profile + slack 扫描）**0.29 s**，5.4 MiB（HxD64）0.11 s——修正 64 KiB 截断后扫描范围扩大到真实 `.text`，仍在交互可接受范围；
- read 流程会 profile 两次（locate + open_ube_reader），大 PE 上约 0.5 s；如需优化可加 (path, size, mtime) 键的缓存，列为后续项（§16）。

---

## 11. 双实现一致性

### 11.1 同源 iced-x86

- Rust：`iced-x86 = { version = "1.21", default-features = false, features = ["std", "decoder", "encoder"] }`（与 steg86 完全相同的裁剪配置）；
- Python：`iced-x86>=1.21.0,<1.22`（PyPI 官方 PyO3 绑定，与 crate 同源代码生成、同版本号，MIT，有 Windows/macOS/Linux 预编译 wheel）；
- 位置序列、opcode 分类、比特定义因此**跨语言逐比特一致**，交叉兼容由构造保证；§10.3 检查项 7 已实证。

不选 capstone 的理由：无同源代码生成的跨语言保证，opcode/寄存器编号体系与 iced 不同，需自建映射并承担漂移风险。

### 11.2 Python 绑定 API 备忘（实施注意）

| Rust crate | Python 绑定 |
| --- | --- |
| `Instruction::with2(code, r0, r1)` | 无此工厂；用 `Instruction.create(code)` + `set_op_kind(0, OpKind.REGISTER)` + `set_op_register(0, r0)` + `set_op_register(1, r1)` 组装 |
| `Code::Mov_rm32_r32` | `Code.MOV_RM32_R32`（枚举为大写常量名） |
| `OpKind::Register` | `OpKind.REGISTER` |
| `insn.op0_register()` | `insn.op0_register`（属性，非方法） |
| `insn.len()` / `insn.ip()` | `insn.len` / `insn.ip`（属性） |
| `Decoder::new(bitness, data, opts)` | `Decoder(bitness, data, ip=0)`，可直接迭代 |
| `encoder.encode(&insn, ip)` + `take_buffer()` | 同名同义 |

### 11.3 交叉测试

纳入既有跨兼容套件（`test_rust_cross_compat.py` / `test_cli_cross_compat.py`）：Python 写 → Rust 读/verify/remove，Rust 写 → Python 读/verify/remove，覆盖标准/隐身/加密/压缩四种组合。

---

## 12. 安全分析

### 12.1 拒绝规则（复用现有预检矩阵）

| 规则 | 处理 |
| --- | --- |
| Authenticode 签名 PE（Security 目录非空） | **拒绝**（改 .text 同样毁签名，与 pe_overlay 一致） |
| 非 x86/x64 Machine 值 | 策略不可用 → auto 回退 pe_overlay；显式指定报错 |
| 无 `.text` 节 / .text 尺寸为 0 | 同上 |
| 文件尾已有 overlay | 不影响（信道只碰 .text 与 slack）；既有信封检测照常 |

### 12.2 检测面与对抗

| 检测手段 | 暴露程度 | 说明 |
| --- | --- | --- |
| 文件尺寸分析 | **免疫** | 零增长是本策略的核心价值 |
| binwalk / PE 结构解析 | 低 | 无异常块、无 overlay；slack 非零可被"与干净样本比对"发现，但单文件结构解析无异常 |
| 反汇编 diff（与干净版比对） | **可发现** | 约一半信道指令的编码形态被改写（语义不变）。这是本方法的理论极限，文档如实声明 |
| 指令形态分布统计 | 可发现 | 信道区的 `89/8B` 等形态比例偏离编译器基线（约 50:50 vs 编译器的自然分布） |
| 熵分析 | 低 | 改写是 1 比特级的形态翻转，不改变字节熵分布 |

### 12.3 已知弱点

1. **AV/EDR 启发式**：对可执行文件 `.text` 的改写可能触发行为告警。工具性质决定，文档注明；
2. **隐身模式双叠加**：与现有隐身 overlay 相同的弱点——以错误口令写入第二个信道不会被发现，且会破坏第一个信道。标准魔数下引擎的既有信封检测可拦截；
3. **slack 语义**：节尾部 padding 理论上可能被非常规打包器利用。零值校验（§6.3）提供防御；非零即不用；
4. **PE 校验和**：改写后校验和字段过期（与 pe_overlay 及一切二进制补丁工具相同）。Windows 普通应用加载不校验；本策略不更新该校验和字段（保证 strip 逐比特还原）。

---

## 13. 错误处理矩阵

| 场景 | 行为 | 错误类型 |
| --- | --- | --- |
| 容量不足（显式指定策略） | 拒绝执行，提示所需/可用比特数，建议 `-s pe_overlay` | `UnsupportedFormat`（策略容量超限） |
| 容量不足（auto） | 静默回退 `pe_overlay`，strategy_note 说明 | — |
| 无足够连续零 slack | 同上（显式则报错） | 同上 |
| 无 .text / 非 x86 | 显式报错；auto 回退 | `UnsupportedFormat` |
| locate 魔数不匹配 | 返回 None（无隐藏数据 / 口令错误时的可否认性） | `NoHiddenDataError`（引擎层） |
| 信道头 version 不支持 | `CorruptedData` | — |
| UBE 层校验失败（trailer/AEAD/SHA） | 复用引擎现有错误链 | `CorruptedData` / `PasswordError` |
| strip 后 SHA-256 不匹配（如宿主在嵌入后被第三方改动） | 拒绝提交，保留现场，`RestoreMismatchError` | 复用现有逻辑 |
| .text 被随机翻转后执行 read/remove | 信道头魔数/N 校验失败 → 干净失败，不产生静默错乱 | `CorruptedData` / `NoHiddenDataError` |

---

## 14. 测试计划

| 编号 | 类别 | 内容 |
| --- | --- | --- |
| T1 | 单元 | profile 过滤器（F0-F5）逐条验证，合成 buffer（`31 C0` 重复、混合形态、内嵌数据） |
| T2 | 单元 | 位定义与编解码往返（语义对两形态、TEST 交换、REX/66 前缀组合） |
| T3 | 单元 | diff 生成/应用/字节级还原（合成 buffer） |
| T4 | 集成 | 真实 PE 样本（§10.2 表中至少 4 个，含 1 个 32 位）全流程：write → read → inspect → verify(三级) → remove，remove 后 SHA-256 逐比特校验 |
| T5 | 集成 | remove 后再次 write（幂等性）；连续 write/remove 多轮 |
| T6 | 集成 | 加密 / 压缩 / 隐身 / 密码提示四种组合的 round-trip |
| T7 | 交叉 | Python ↔ Rust 双向（§11.3） |
| T8 | 边界 | 容量不足回退、slack 不足回退/报错、无 .text、ARM64 PE、签名 PE 拒绝、既有 overlay 共存、既有信封叠加拒绝 |
| T9 | 模糊 | 对嵌入后文件随机翻转 .text 若干比特，read/remove 必须干净失败 |
| T10 | 回归 | 既有全格式测试套件全绿（引擎改动不得影响其他格式） |

---

## 15. 实施计划与工作量

| 阶段 | 内容 | 预估 |
| --- | --- | --- |
| P1 | Rust 核心模块（profile/channel/embed/extract/restore/pe_locator）+ Cargo.toml 加 iced-x86 | ~700 行，1.5 天 |
| P2 | Rust 引擎改造（§8.2 的 1/2/4/5/6）+ PE adapter 接线 | ~80 行，0.5 天 |
| P3 | Rust 测试（T1-T5、T8-T10） | ~350 行，1 天 |
| P4 | Python 对齐（模块 + 引擎 3/4/5/6 + pyproject） | ~650 行，1.5 天 |
| P5 | 交叉测试 + 文档（设计文档并入本文档 §8、CHANGES 记录）+ 全量回归 | 1 天 |
| 合计 | | **约 5 个工作日**（含联调缓冲） |

落地顺序建议：P1 → P3（先在 Rust 侧用合成 + 真实样本跑通 T4）→ P2 → P4 → P5。`temp/` 下两个原型脚本可作为 P1/P3 的起点直接移植。

---

## 16. 未来扩展

1. **分块 diff**（flags bit0，容器 v2）：wininit 类紧凑 PE 的多零 run 利用，消除单连续 run 限制；
2. **ELF / Mach-O 定位器**：核心模块格式无关，新增定位器即可扩展（steg86 原生支持这两种格式）；
3. **多代码段**：除 `.text` 外利用其他可执行节（如 `.init`），需约定确定性节序；
4. **NOP 滑梯隐写**：steg86 的 future work（`OF 1F /0` 多字节 NOP 的空闲字节），进一步提升容量；
5. **profile 缓存**：read 流程的重复解码优化（(path, size, mtime) 键）；
6. **容量报告 CLI**：`strhide profile -c x.exe` 输出可用容量（对齐 steg86 的 profile 子命令）。

---

## 附录 A：术语表

| 术语 | 含义 |
| --- | --- |
| 语义对 | 同一寄存器间运算的两种等长编码形态（如 `89 /r` 与 `8B /r`） |
| profile | 对 .text 线性扫描、生成可改造位置序列的过程 |
| 信道位置 P[i] | profile 产物的第 i 个可改造指令位置 |
| Region A | 信道头 + UBE 占据的连续信道位置区间 |
| diff | 记录 Region A 各位置是否被翻转的位图 |
| slack | PE 头部/节尾部对齐 padding 中的零值区域 |
| UBE | strhide 统一二进制信封（Universal Binary Envelope, v2.2），本插件视之为不透明载荷 |

## 附录 B：验证产物索引

| 文件 | 说明 |
| --- | --- |
| `temp/pe_codebits_probe.py` | 样本测量脚本（profile 计数、过滤器统计、slack 测量） |
| `temp/pe_codebits_prototype.py` | 核心信道闭环原型（embed/extract/strip 四项检查） |

（均为只读实验脚本，不修改任何宿主文件；实施阶段应移植为正式测试。）
