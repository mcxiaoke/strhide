# HEVC / HEIF 内容载体规范（V4）

导航：[公共信封与 STC](CONTENT-ENVELOPE.zh.md) ｜ [容量](CAPACITY.zh.md) ｜ [密码学](CRYPTO.zh.md) ｜ [总规范](../WIRE_SPEC_CONTENT.md)

本文只定义 HEVC 视频与 HEIF/HEIC 图像特有的槽位、分带、置换、32B 头、`pre_salt` 与写侧边界。信封、微头、AAD、L1/L2/L3、TLV、STC 定义见公共规范。

## 1. 适用范围与稳定性

适用于 MP4/MOV/MKV 中的 HEVC 视频、Annex-B 裸流，以及 HEIF/HEIC 的主图或 `grid` 瓦片项。HEIF 缩略图桥接不属于 Scheme C，见 §8.5。

**容器解析的防御上限**：读取 MP4/MOV 容器结构（`inspect` 等走 `StegoHeaderInfo` 的路径）时会把整个 `moov` box 读入内存，因此对 `moov` 尺寸设 32 MiB 硬上限，超出即 `UnsupportedFormat("MP4 moov box exceeds 32 MiB")`（`rust/src/stego/hevc/engine.rs:2627-2631`）。该上限只拦异常/恶意容器，正常 `moov`（含 `stsd`/`stbl`）远小于此。

| 内容 | 级别 | 依据 |
| :--- | :--- | :--- |
| 槽位语义、分带、线性置换、32B 头、`pre_salt`、session salt | **F** | 改变即读不回既有载体 |
| `HevcFormatProfile` 的标签与 `stc_h`/`stc_u` | **D** | 换标签或参数即产生独立方言 |
| 重编码、补零、并行、SIMD、防竞争排除策略 | **I** | 只影响写侧字节，由基线把关 |

官方 profile：`magic_label = b"strhide-hevc-magic-v4"`、`cover_salt = b"strhide-hevc-cover-v1"`、`stc_h = 7`、`stc_u = 2`（`rust/src/stego/format.rs:98-105`）。

## 2. 唯一切片/调制点

唯一被修改的语法元素是 TU 内 CABAC bypass `coeff_sign_flag`（非 DC 系数符号）。DC 系数（`x_c == y_c == 0`）永久排除（`rust/src/stego/hevc/slot.rs:581-589`），记录点见 `:615-626`。一个槽位记录为 16B（`rust/src/stego/hevc/slot.rs:143-159`）：

| 字段 | 类型 | 含义 |
| :--- | :--- | :--- |
| `cost` | f32 | 符号翻转的感知失真代价 |
| `op_idx` | u32 | 所属 slice 的 `BinOp` 日志序号 |
| `slice_idx` | u32 | 载体内的 0 基切片号 |
| `substream_idx` | u16 | 切片内的 WPP/tile substream 号 |
| `original_bit` | u8 | 原始符号位：0 = 正，1 = 负（槽值奇偶） |

写侧只把 `original_bit` 取反并按原日志重放同一 CABAC 子流；重编码 NAL 长度必须等于覆盖跨度，否则拒绝（`rust/src/stego/hevc/engine.rs:1909-1920`）。因此码流尺寸、参数集、切片头与解码结果均不变（`rust/src/stego/hevc/bitstream.rs:178-191`）。

## 3. 槽位池与头部定位

候选槽只来自可承载槽位的 VCL 切片（§8.2），按解码顺序追加到记录数组；数组前缀构成头部候选池。

- 头部池大小：`pool_size = min(total_window_slots, 2048)`（`rust/src/stego/hevc/engine.rs:91-92`、`:2236-2237`）。
- 头部槽位数：`524 + ext_slots`，`ext_slots = 2 * (8 * ext_len + 6)`，`ext_len = 0` 时为 0（`rust/src/stego/hevc/engine.rs:94`、`:137-142`）。
- 头部第 `i` 槽：`pos_i = (start + i * stride) mod pool_size`，`i ∈ [0, 524 + ext_slots)`，`band_start = 0`（`rust/src/stego/hevc/engine.rs:304-338`）。

`start`/`stride` 由 L2 `locate_seed` 按 §5 推导。同一置换的前 524 项是基础头，后续项是扩展区，故读取方先解基础头、再按 `ext_len` 续读。`524 = 2 * (256 + 6)` 对应官方 `h = 7, u = 2`；`stc_h` 不存入头中（`rust/src/stego/hevc/engine.rs:148-152`）。

写侧窗口目标：`target_slots = max(524 + ext_slots + desired_body_slots + 128, 2048)`（`rust/src/stego/hevc/engine.rs:430-438`）。第一遍至少记录 2048 槽（`MinSlots`），再按 `TargetSlots(target_slots)` 继续，直到满足正文需求或载体耗尽（`:1229-1257`）。

## 4. 正文分带

分带只依赖 `nal_unit_type` 序列与"载体是否存在帧间图像"，嵌入不改变二者（`rust/src/stego/hevc/engine.rs:4098-4120`）：

- 无任何帧间图像（静态图、全 intra）：所有图像为 band 0。
- 存在帧间图像时：非参考图像为 band 0；参考且非 IRAP 图像为 band 1；IRAP（BLA/IDR/CRA，`16..=23`）与 RASL_N/RASL_R 不承载槽位。

正文池构造（`rust/src/stego/hevc/engine.rs:376-414`）：在 `pool_size` 前缀内剔除全部头部位置；其余槽按解码顺序追加到 band 0 或 band 1；超出 `pool_size` 的槽直接按所属带追加（头部只可能在前缀内）。最终 `bands = [0..band0.len(), band0.len()..total_body]`（`:4014-4026`）。正文第 `i` 槽：

```text
(start, stride) = params(band.len(), perm_seed, band.start)
pos_i = band.start + ((start + i * stride) mod band.len())
```

先耗尽 band 0，未满 `body_n` 才进入 band 1；两个带永不交错（`rust/src/stego/hevc/engine.rs:1955-1988`）。`body_n` 由 `body_len * 8` 经头部 `(stc_h, stc_u)` 的 `slots_for` 求得（`:2248-2251`）。

## 5. 线性置换完整定义

`params(len, perm_seed, band_start)`（`rust/src/stego/hevc/engine.rs:344-373`）：

```text
seed = 0x243F6A8885A308D3
for chunk in perm_seed[0..32] as 4 × u64le:
    seed = splitmix64(seed XOR chunk)
seed ^= band_start * 0x9E3779B97F4A7C15
start  = splitmix64(seed) mod len
stride = splitmix64(seed XOR 0xA5A55A5A3C3CC3C3) mod len
stride = max(stride, 1)
while gcd(stride, len) != 1:
    stride += 1
    if stride >= len: stride = 1; break

splitmix64(x):
    x = x + 0x9E3779B97F4A7C15
    z = (x XOR (x >> 30)) * 0xBF58476D1CE4E5B9
    z = (z XOR (z >> 27)) * 0x94D049BB133111EB
    return z XOR (z >> 31)
```

头部用 L2 `locate_seed`，正文用 L3 32B `perm_seed`。逐 8 字节 `u64le` 折入（不做并行异或），避免低熵种子坍缩（`:345-351`）。边界：`len == 0` 返回空；`len == 1` 时 `start = 0`、`stride = 1`；`stride` 始终与 `len` 互质；前缀项不因请求 `count` 改变（`:327-337`）。乘法在 u64 内完成，避免大 HEIC 的 `usize` 溢出（`:1979-1984`）。

## 6. 32B 基础头

布局/编码见 `rust/src/stego/hevc/engine.rs:148-190`，解码校验见 `:193-278`。

| off | size | 字段 | 说明 |
| :--- | :--- | :--- | :--- |
| 0 | 4 | `magic` | L2 派生 |
| 4 | 1 | `version` | `0x40`（major 4） |
| 5 | 1 | `flags` | `EXT_PRESENT`/`EXT_CRITICAL`，其余位必须 0 |
| 6 | 1 | `stc_u` | 正文字典宽度，1..=64 |
| 7 | 2 | `window_slices` | 写侧主窗口记录的切片数，≥ 1 |
| 9 | 1 | `ext_len` | 扩展 TLV 字节数，0..=64 |
| 10 | 2 | `suite_id` | AEAD 套件 |
| 12 | 4 | `body_len` | 密文长度（含 16B tag） |
| 16 | 12 | `nonce` | AEAD nonce，同时进入 session salt |
| 28 | 4 | CRC32-IEEE | 覆盖 `bytes[0..28]`，大端 |

隐含字段：`format_id = 5`、`total_windows = 1`、`stc_h`（来自 profile，官方 7）。三者不存头中，由 AAD 与 STC 参数绑定（`:148-152`、`:1393`）。

`stc_u` 是 profile 值的冗余副本且自描述：写侧写入 `fmt.stc_u`（`:1385-1390`），读侧校验 `1..=64` 并以头为准构造正文 trellis（`:231-235`、`:2248-2249`）；`stc_h` 只来自 profile，头几何仍按官方 `h=7, u=2` 的 524 槽布局。`flags`/`ext_len` 一致性、suite 合法性、`body_len ∈ BODY_OVERHEAD..=HEADER_LEN_MAX` 均在读正文前拒绝（`:221-257`）。

session salt（F）：`session_salt = SHA-256("strhide-hevc-session-v4" ‖ nonce[0..12])`（`rust/src/stego/hevc/engine.rs:451-456`）。`salt`/`nonce` 的生成与轮换遵循公共信封。

## 7. `pre_salt` 与载体身份

`pre_salt` 只取嵌入前后不变的参数集/切片头信息，写读两端必须得到相同密钥。统一前缀 `salt_prefix = cover_salt ‖ "hevc-v4"`（`rust/src/stego/hevc/engine.rs:4265-4270`）。

容器路径 `DigestInputs::ParameterSets`（`:4272-4287`）：

```text
pre_salt = SHA-256(salt_prefix ‖ u64be(P)
                   ‖ for each ps[0..P]: u64be(len(ps)) ‖ ps)
```

`P` 为 VPS/SPS/PPS 数组项数，`ps` 含 2B NAL 头；非参数集数组（如 SEI）在解析时丢弃（`rust/src/stego/hevc/heif_boxes.rs:515-560`）。

Annex-B 路径调用 `compute_hevc_cover_digest`（`:4289`；定义见 `rust/src/stego/hevc/bitstream.rs:192-211`）：

```text
pre_salt = SHA-256(salt_prefix ‖ u64be(N)
                   ‖ for each physical NAL span:
                       参数集: 完整 NAL 字节（header_offset..end）
                       VCL:    2B NAL 头 ‖ u64be(nal_len))
```

VCL 切片头之后的首个 CABAC 字节可被改写，禁止进入摘要；NAL 长度因长度保持而不变（`bitstream.rs:178-191`）。

## 8. 扩展区、容量、窗口与 HEIF

### 8.1 扩展区与容量
`ext_len ≤ 64`（`rust/src/stego/hevc/engine.rs:123-124`、`:441-448`）；TLV 规则同公共信封；扩展槽固定 `2 * (8 * ext_len + 6)`（`:136-142`）。

```text
hdr_slots   = 524 + ext_slots
body_slots  = total_slots - hdr_slots
max_payload = message_bits(body_slots, stc_h, stc_u) / 8 - BODY_OVERHEAD
```

`BODY_OVERHEAD = 22`；`body_len` 已含 tag，不再额外减 tag（`:468-500`）。`total_slots` 是主窗口记录到的全部候选槽。容量探测与写侧预算用 profile 的 `stc_u`，正文解码用头内值；官方均为 2。

### 8.2 窗口与切片选择
- 候选切片按解码顺序记录；只有 `picture_band` 返回 `Some` 的 VCL 进入槽位池，IRAP 与 RASL 跳过（`:4098-4120`）。
- `window_slices` 写入写窗口实际记录的切片数（`:1364-1370`）。
- 读侧第一遍只记录 `MinSlots(2048)`；若 `recorded_slices < window_slices`，再以 `TargetSlices(window_slices)` 重录（`:2038-2042`、`:2222-2234`）。两遍的 `pool_size` 都取 `min(total_window_slots, 2048)`。

### 8.3 防竞争
写侧最多 24 轮（`:81`、`:1407`）：分别求解头/扩展/正文 STC；仅重编码被翻转的切片/substream；回放须与覆盖逐字节一致（尾部最多 4 个 0，见 §9）。若产生新的 `00 00 xx<=3` EPB 窗口或重编码失败，相关槽加入 `forbidden`，代价加 `FORBIDDEN_SLOT_SURCHARGE = 1e9`，下一轮重解。EPB 冲突排除半径 `8 << min(round, 3)`；无可排除项时排除窗口之前最近的翻转槽；仍无进展则报错（`:1631-1687`）。

### 8.4 HEIF Scheme C
- 主项非 `grid`：目标项 = `pitm` 主项；主项是 `grid`：目标项 = `iref/dimg` 瓦片，无 `dimg` 时退回主项（`rust/src/stego/hevc/heif_boxes.rs:161-184`）。
- `hvcC` 通过 `ipma` 选择目标项真正关联的属性，缺失 `hvcC` 即拒绝；`iloc` 单 extent 拆分 NAL，重叠 extent 拒绝（`:440-488`、`:193-223`）。

### 8.5 HEIF 桥接（独立于 Scheme C）
仅 `FileFormat::Heif` 且直接 Scheme C 失败后尝试。可触发：`NoHiddenData`、`UnsupportedFormat`、`TrellisInfeasible`；`Cancelled`、凭据/策略/版本/容器解析错误不触发；`HevcMode::Cabac` 禁止回退；编译特性 `content-heif-bridge` 未启用时不回退（`rust/src/stego/engine.rs:426-447`、`:497-540`、`:569-597`）。

桥接目标（`rust/src/stego/heif/thumb_bridge.rs:651-741`）：`thmb` 引用的 JPEG 项，或任一非主项单 extent JPEG 项；其次 `Exif` 项内嵌 JPEG 缩略图。主项永久不作为目标并保持逐位不变。`unci`（未压缩）项不支持；错误文案中的 "uncompressed item" 为遗留措辞，实现会拒绝。桥接使用 JPEG 载体自己的 V4 信封（`format_id = 4`），不适用本文件的 32B 头与 HEVC 槽位规则。

## 9. 写侧 I 级实现边界

- **重编码/重打包**：按 `BinOp` 日志重放并重打包 CABAC 子流；上下文初值取 `SubstreamRecord.init_contexts`；中途 substream 按 H.265 §9.3.2.6 补终止位（`rust/src/stego/hevc/engine.rs:1739-1817`）。
- **长度保持**：等长直接替换；短 1–4 字节尾部补 0；更长或其他差值判 `BadSubstream`（`:1858-1880`）。
- **回放校验**：未翻转时重放须与覆盖一致，允许覆盖多最多 4 个尾部 0（`cabac_zero_word`）（`:1924-1934`）。
- **并行**：仅按切片用 rayon 并行重编码，不参与归约（`:1565-1588`）。
- **SIMD**：规范不规定指令集；任何 SIMD 路径须与标量路径逐位等价，基线是唯一判据。
- **基线**：写侧改动后运行 `python scripts/baseline_hash.py --check`；压力测试 `cargo run --release --all-features --example hevc_stress`。
