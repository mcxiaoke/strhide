# WAV / FLAC 音频内容载体规范（V4）

导航：[公共信封与 STC](CONTENT-ENVELOPE.md) ｜ [容量](CAPACITY.md) ｜ [密码学](CRYPTO.md) ｜ [总规范](../WIRE_SPEC_CONTENT.md)

本文件定义 WAV 与 FLAC 的 PCM 槽位、布局、`pre_salt`、容量与写侧边界。64B 头、AAD、L1/L2/L3、TLV、STC 矩阵见公共规范，本文不重复。

## 1. 适用范围与稳定性

适用于 RIFF/WAVE 整数 PCM 与原生 FLAC（`fLaC`）。WAV 支持 8/16/24/32-bit（16/24-bit 为主路径）；FLAC 支持 4..=24-bit（实现拒绝 >24-bit）。两者共用 64B 头路径，但 `format_id` 固定为 WAV = 2、FLAC = 3（`rust/src/stego/audio/mod.rs:49-51`）。

| 内容 | 级别 | 依据 |
| :--- | :--- | :--- |
| 槽位定义、槽位计划、`thin_pick`、`pre_salt`、容量预算 | **F** | 改变即读不回既有载体 |
| `hpos_salt` 标签、格式 profile、`format_id` | **D** | 换标签即独立方言 |
| 代价模型、方向盐、重试、并行/SIMD | **I** | 只影响写侧，基线把关 |

音频**只用 STC**。`codec_id = 1` 表示 STC（`rust/src/stego/audio/core.rs:803-807`）；`codec_id = 0`（Hamming）仅为保留值，读到 Hamming 头一律返回 `NoHiddenData`（`:637-653`、`:797-810`）。因此不存在“先试 Hamming、再试 STC”的读取顺序。

## 2. 公共头与槽位预算

使用公共 64B `SpatialHeaderV4`（`rust/src/stego/header.rs:153-156`、`:173-219`）。音频相关字段固定：`algorithm_id = 0`、`channel_mode = 0`、`class_rule = 0`、`p2_window = 1`、`kernel_id = 0`（`rust/src/stego/audio/core.rs:798-821`）。`format_id` 为 2/3；`stc_h`/`stc_u` 在 64B 头中自描述，读取方按头构造 trellis。

基础头固定占 512 槽（`PNG_AUDIO_BASE_SLOTS`），扩展占 `8 * ext_len` 槽，故 `header_slots = 512 + 8 * ext_len`（`rust/src/stego/audio/core.rs:711-714`、`:837-852`）。扩展 TLV 语义见公共信封；`ext_len = 0` 时不写扩展槽。

## 3. WAV

### 3.1 解析与槽定义
- 仅接受 `RIFF/WAVE`、`FORMAT_PCM` 或 PCM 子格式的 `WAVE_FORMAT_EXTENSIBLE`；RF64、浮点、ADPCM 拒绝（`rust/src/stego/audio/wav.rs:102-162`）。
- `block_align` 必须等于 `channels * bytes_per_sample`；`data` 块长度不得越过 EOF（`wav.rs:180-195`）。
- `SampleKind` 为 `U8/U16/I16/I24/I32`（`rust/src/stego/audio/sample.rs:17-26`、`:64-76`）。槽值 0 表示该采样最低位为 0，1 表示最低位为 1；写入就是把最低位取反（16/24-bit 为带符号整数补码，小端存储，24-bit 符号扩展到 i32 后再运算）(`sample.rs:84-126`、`core.rs:288-320`）。

`total_slots = data_len / bytes_per_sample`，直接按文件中的采样/声道交织顺序编号（`rust/src/stego/audio/wav.rs:60-63`）。16-bit 立体声的两个 16-bit 分量、24-bit 的三个字节分量都各自占一个槽，不以 `block_align` 为槽粒度。

### 3.2 槽位计划
WAV 使用 `Mapping::Permuted`：`perm = KeyedPermutation(locate_seed, total_slots)`（`rust/src/stego/audio/core.rs:219-223`、`:711-714`）。位置：

```text
header_i    = perm.at(i)                    i < 512
extension_i = perm.at(512 + i)              i < 8 * ext_len
body_i      = perm.at(512 + 8*ext_len + i)  i < body_slots
```

（`rust/src/stego/audio/core.rs:234-255`）。正文 `body_slots = total_slots - (512 + 8*ext_len)`，即所有未被头/扩展占用的槽都参与正文。头/扩展位置先于正文确定，使读取方在未知 `ext_len` 时仍能只读基础头。

**注意**：这里用 L2 `locate_seed`，不是 L3 `perm_seed`（`core.rs:711-714`）。L3 `perm_seed` 只用于音频代价翻向盐（§6.2）。

## 4. FLAC

### 4.1 解析与两类槽
- STREAMINFO 必须是首个元数据块且长度 34B；只接受 4..=24-bit，`total_samples`、MD5 从 STREAMINFO 读取（`rust/src/stego/audio/flac/mod.rs:122-181`、`:187-212`；`mod.rs:158-174`）。
- 载体必须能完整解码；非零 MD5 与解码 PCM 的 MD5 不符即拒绝（`flac/mod.rs:454-464`）。
- 槽位分两类（`rust/src/stego/audio/flac/frame.rs:700-747`）：
  1. **subframe tail**：每个 subframe 最后一个残差符号，满足 Rice `k >= 1`、`fold >> k >= 1` 且存在合法 ±1 移动；用于头/扩展池。
  2. **body 残差槽**：残差符号具有完整补偿链（`index + order + 1 < len`），移动后可由后续残差整除抵消；用于正文池。合法性是结构性的，不可移动的槽仍保留在池中并由 STC 绕过（`flac/mod.rs:626-641`）。

### 4.2 `thin_pick`
头/扩展的均匀抽稀（逐字，`rust/src/stego/audio/flac/mod.rs:827-841`）：

```text
thin_pick(index, range, wanted, phase):
    if wanted == 0 or range == 0: false
    phase = phase mod range
    before = (u128(index)     * wanted + phase) / range
    after  = (u128(index + 1) * wanted + phase) / range
    return after != before
```

### 4.3 头与扩展的抽取
`pick_tails`（`flac/mod.rs:848-879`）：
- 头：`index` 为全部 tail 的文件顺序，`range = tail_total`，`wanted = 512`，`phase = u64le(locate_seed[0..8])`。
- 扩展：仅对未被头选中的 tail 重新编号 `n`，`range = tail_total - 512`，`wanted = 8 * ext_len`，`phase = u64le(locate_seed[8..16])`。
- 选中项保持原文件顺序，依次装进槽数组前 `512 + 8*ext_len` 项。因此 `header_i = i`、`extension_i = 512 + i`（`core.rs:237-246`）。

### 4.4 正文抽取与置换
`base = u64le(locate_seed[16..24])`（`rust/src/stego/audio/mod.rs:86-91`）。每次嵌入：

```text
body_phase = u64le(SHA-256("strhide-v4-flac-body-phase"
                           ‖ u64le(base) ‖ salt ‖ nonce)[0..8])
```

（`audio/mod.rs:106-114`）。正文在全部结构性残差池（`analysis.slots`）上均匀抽取（`flac/mod.rs:634-640`）：

```text
thin_pick(index, analysis.slots, body_slots, body_phase)
```

选中集合按文件顺序装入槽数组；随后 `perm = KeyedPermutation(locate_seed, body_n)`，`body_i = (512 + 8*ext_len) + perm.at(i)`（`audio/core.rs:224-253`、`:831-855`）。`body_n = body_slots`。**代码使用 L2 `locate_seed`，不是 L3 `perm_seed`**。

### 4.5 重试
最多 6 次（`FLAC_EMBED_ATTEMPTS = 6`，`audio/mod.rs:96`、`:208-245`）。每次从原始载体克隆，重新生成 `salt`/`nonce` 与 `body_phase`；仅在 `DeadGroup`/`DeadElement` 时重试，其他错误立即返回，6 次仍失败返回 `FLAC embedding exhausted its retry budget`（`audio/mod.rs:118-126`、`:256-263`）。每次写入后检查解码波形漂移，`DRIFT_BUDGET = 2` 个存储步长（`flac/mod.rs:91`、`audio/mod.rs:248-254`）。

## 5. `pre_salt`

两者都只摘要嵌入前后不变的公共头信息；PCM 字节/校验和**不进入**摘要。`hpos_salt` 由格式 profile 提供（WAV `b"strhide-audio-hpos-salt-v1"`、FLAC `b"strhide-flac-hpos-salt-v1"`，`rust/src/stego/format.rs:283-300`）。

WAV（`rust/src/stego/audio/mod.rs:58-68`），所有整数大端：

```text
pre_salt = SHA-256(hpos_salt ‖ "wav-v4" ‖ u16be(channels) ‖ u32be(sample_rate)
                   ‖ u16be(block_align) ‖ u16be(bits) ‖ u32be(data_len))
```

FLAC（`:75-83`）：

```text
pre_salt = SHA-256(hpos_salt ‖ "flac-v4" ‖ u32be(sample_rate)
                   ‖ u8(channels) ‖ u8(bits_per_sample) ‖ u64be(total_samples))
```

FLAC 的 MD5 被明确排除，因为嵌入后要重算 MD5；若纳入会让定位密钥在写读两端不同（`:70-83`）。WAV 的 `data_len` 以 u32 参与，RIFF 上限内可逆。

## 6. 容量、代价与 I 级

### 6.1 容量
`capacity_slots` 与计划分母不同，必须分开实现：

- WAV：`total = data_len / bytes`；`available = total - (512 + 8*ext_len)`。
- FLAC：头/扩展从互不相交的 tail 池抽取，**不挤占正文预算**；`body_header_slots = 512`，`capacity_slots = total_usable + 512`，故 `available = total_usable`（可移动残差数），而正文抽取分母仍是结构池 `analysis.slots`（`flac/mod.rs:886-892`、`:566-590`）。槽数组总长为 `512 + 8*ext_len + body_n`。

公共容量换算（`rust/src/stego/audio/core.rs:350-367`）：

```text
ciphertext_bits = u * (slots / u) - (h - 1)   # STC
max_payload     = ciphertext_bits / 8 - 22    # BODY_OVERHEAD
```

`max_body_slots(h,u)` 受 768 MiB 工作集上限约束：`MAX_WORKING_SET_BYTES = 768 * 1024 * 1024`，峰值由载荷而非载体决定，约允许 `h=8` 的 1 MiB 载荷（`core.rs:62-69`、`:371-374`）。安全档位按全部槽的 0.5%/1.5%/3% 变更预算（`:71-88`）。

### 6.2 代价与方向盐（I 级）
每个槽的代价为 `1 / (epsilon + rms + 0.5*d1)`，`rms` 取 ±16 槽窗，`epsilon = 1e-3`，数字静音（`rms < 1e-7` 且 `d1 < 1e-7`）取 `1e6`（`rust/src/stego/audio/cost.rs:31-51`、`:94-129`）。代价只用于写侧 STC，读取端从不重算（`cost.rs:24-29`）。

方向盐取 L3 `perm_seed` 前 8 字节（大端）：`dir_salt = u64be(perm_seed[0..8])`（`core.rs:836`）。基础头用 `dir_salt`，扩展用 `dir_salt ^ 0x5DEE_CE66`，正文用 `dir_salt ^ 0xA5A5_5A5A` 做 `direction_flip`（`core.rs:843-876`、`:280-286`）。翻转方向不影响读取，只影响写侧统计与基线。

### 6.3 写侧 I 级
逐槽 `±1` 写入，WAV 在边界处钳位；FLAC 通过补偿链保证解码波形漂移 ≤2。槽位计划、STC 矩阵、方向选择可并行/SIMD 实现，但必须与标量实现逐位等价；字节级基线是唯一判据。

## 7. 自检与基线

读取方在解码正文前应完成：

1. 64B 头 CRC32、`format_id ∈ {2,3}`、`codec_id = 1`、suite 合法、`body_len ∈ BODY_OVERHEAD..=HEADER_LEN_MAX`；否则返回 `CorruptedData`/`UnsupportedFormat`。
2. WAV：`RIFF/WAVE`、PCM 标签、`block_align = channels * bytes`、`data` 不越界（`wav.rs:102-195`）。
3. FLAC：STREAMINFO 首块且 34B、`bits ≤ 24`、解码 PCM MD5 与 STREAMINFO 一致（`flac/mod.rs:122-181`、`:454-464`）。
4. 嵌入后 FLAC 重解码并刷新 CRC16/MD5；漂移超预算拒绝输出（`flac/mod.rs:760-783`、`audio/mod.rs:248-254`）。

回归判据：`python scripts/baseline_hash.py --check` 全绿；音频压力测试 `cargo run --release --all-features --example audio_stress`。
