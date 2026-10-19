# 兼容性实验报告（第 0 步实测结果）

> 日期：2026-10-19　执行：`temp/exp/`
> 对应方案：`docs/format_expansion_plan_20261019.md` §8 第 0 步
> 目的：在写任何 Rust 代码之前，用真实工具链验证解码器对"尾随注入"的容忍度

---

## 0. 测试环境

| 工具 | 版本 | 路径 |
| --- | --- | --- |
| ffmpeg / ffprobe | — | `C:\Home\Apps\ffmpeg\bin\` |
| mkvtoolnix (mkvmerge) | v102.0 | `C:\Home\Apps\mkvtoolnix\` |
| libheif (heif-enc / heif-info) | 1.23.4 | `C:\Home\Tools\libheif\` |
| libwebp (cwebp / dwebp) | 1.6.0 | `C:\Home\Develop\tools\` |
| Pillow | 12.3.0 | `C:\Home\Develop\venv\` |
| strhide | release（14:33 构建） | `rust\target\release\strhide.exe` |

> **ImageMagick 不可用**：`magick identify` 对**原始样本**也报
> `RegistryKeyLookupFailed CoderModulesPath`，属于本地安装问题，与注入无关。
> 已用原始文件做对照实验确认（见 §2.4），后续不再把它计入验收工具。

样本生成脚本与原型注入器：`temp/exp/py/inspect_container.py`、`temp/exp/py/proto_inject.py`
（后者严格按方案文档描述的算法实现，用于在写 Rust 之前先验证方案本身成立）。

---

## 1. 实验一：HEIC / HEIF —— ✅ 通过

**样本**：`heif-enc -q 80` 生成 `sample.heic`（28786 B），另有 `sample_ll.heic`（无损）与 `sample.avif`。

**结构**：
```
@0      ftyp  size=28     major_brand=heic  compatible=mif1,heic,miaf
@28     meta  size=343
@371    mdat  size=28415
```
`mdat` 是最后一个 box，且 `size` 是**正常值**（非 0）——方案 §5.2 担心的 `size==0` 在真实
编码器产物中不出现（该边界见 §5 单独实验）。

**执行**：直接用**现有 strhide 二进制**（HEIC 目前被 MP4 适配器认领，走 `box_uuid`）：
```
[OK] Successfully embedded ... using strategy 'box_uuid'.
     Payload: 32 bytes -> UBE: 245 bytes.
```

**注入后结构**：
```
@0      ftyp   28
@28     meta   343
@371    mdat   28415
@28786  uuid   269      <-- 合法第 4 个顶层 box
```

**验证结果**：

| 工具 | 结果 |
| --- | --- |
| `heif-info` | ✅ 完整解析：640x480, YCbCr 4:2:0, bit depth 8, nclx 色彩信息全在 |
| `ffmpeg` 解码为 rawvideo | ✅ **像素级 SHA-256 与原文件完全一致**（`D37D841D…0D51`） |
| strhide `read` | ✅ 正确提取 32 字节载荷 |
| strhide `remove` | ✅ **逐比特还原**（SHA-256 一致） |

> **附带确认**：本次 `verify` 输出 `Format: MP4`，坐实了方案 §3.1 P0-7 描述的
> "HEIF 被静默当作 MP4" 问题——能力已在，只是报告错误。

---

## 2. 实验二：WEBP / WAV（RIFF）—— ✅ 通过

### 2.1 结构确认

| 样本 | 结构 | RIFF size == size-8 |
| --- | --- | --- |
| `sample.webp` | `VP8 ` | ✅ |
| `sample_ll.webp` | `VP8L` | ✅ |
| `sample_ext.webp` | `VP8X`(10) + `ALPH`(22) + `VP8`(208) | ✅ |
| `sample.wav` | `fmt`(16) + `LIST`(26) + `data`(176400) | ✅ |

### 2.2 注入

严格按方案 §5.3：末尾追加 `SHRD` chunk（载荷 4019 B，补齐后 4020 B），
**RIFF size 在 inject 时一次写对**（`patch_offset = 0`，不使用通用补丁机制）：
```
form=WEBP  chunk_list_end=10992  file_size=10992  trailing=b''
injected 4028 bytes (SHRD payload=4019, padded=4020); RIFF size 10984 -> 15012
```

### 2.3 解码验证（含最难的 VP8X 扩展格式）

| 样本 | libwebp `dwebp` | ffprobe | Pillow | 像素一致 | strip 逐比特 |
| --- | --- | --- | --- | --- | --- |
| `sample.webp` (VP8) | ✅ 640x480 lossy | ✅ webp 640x480 | — | ✅ | ✅ |
| `sample_ll.webp` (VP8L) | ✅ 640x480 lossless | — | — | ✅ | ✅ |
| `sample_ext.webp` (VP8X+ALPH) | ✅ 320x240 **with alpha** | ✅ `pix_fmt=yuva420p` | ✅ `RGBA (320,240)` | ✅ | ✅ |
| `sample.wav` | — | ✅ `pcm_s16le 44100 1ch 2.000000s` | ✅ | — | ✅ |

**WAV 额外用 Python 标准库 `wave` 模块验证**（一个严格的 RIFF 解析器）：
```
channels 1 rate 44100 frames 88200   ✅
```

### 2.4 ImageMagick 对照实验

```
magick identify temp\exp\samples\sample.webp   -> RegistryKeyLookupFailed ...
magick identify temp\exp\out\r_sample.webp     -> RegistryKeyLookupFailed ...
```
**原始文件同样失败** → 本地安装问题，与注入无关。已从验收工具中剔除。

### 2.5 结论

方案 §5.3 的三个关键假设全部成立：
1. RIFF size 一次写对（不依赖通用补丁机制）✅
2. 未知 fourcc chunk 被所有解码器忽略 ✅（含 libwebp 官方工具、Pillow、ffmpeg）
3. `strip` 用 `orig_host_size - 8` 派生原值，逐比特还原 ✅

---

## 3. 实验三：MKV —— ✅ 通过（附一处必须写进设计的细节）

### 3.1 Segment size VINT 宽度实测（4 个变体）

| 变体 | 产生工具 | Segment size VINT 宽度 | 值 |
| --- | --- | --- | --- |
| `v_a_ffmpeg.mkv` | ffmpeg matroska | **8** | 110200 |
| `v_b_mkvmerge.mkv` | mkvtoolnix v102 | **8** | 115167 |
| `v_c_live.mkv` | ffmpeg `-live 1`（流式） | **8** | **unknown** |
| `v_d_rich.mkv` | mkvmerge + 轨道名/语言 | **8** | 115179 |

**两个重要发现**：

1. **ffmpeg 和 mkvmerge 都固定用 8 字节宽度写 Segment size** →
   方案 §5.4 的"宽度 ≥ 4 字节即可原地改值"假设在真实产物上**恒成立**，
   "VINT 太窄需回退 eof" 这条路径在实践中几乎不会触发（保留为防御性分支）。
2. **流式录制（`-live 1`）会产生 unknown-size Segment** →
   方案设计的"unknown → 无需补丁，`patch_offset = 0`"分支是**真实存在的常见场景**，
   不是理论分支。
3. 附带发现：**所有 4 个变体在 Segment 内部本来就有 `Void` 元素**
   （ffmpeg 1 个、mkvmerge 2 个）。这强力佐证了"用 Void 承载载荷"的方案选择——
   这是 muxers 自己就在用的合法填充元素。

### 3.2 注入与验证

在 Segment 末尾追加 `Void` 元素（ID `0xEC` + 4 字节 size VINT + 4019 B 载荷 = 4024 B），
并原地改写 Segment size（同宽度重编码）。

| 变体 | Segment size 变更 | ffprobe | mkvmerge 识别 | mkvmerge 重封装 | 完整解码 | Seek |
| --- | --- | --- | --- | --- | --- | --- |
| `v_a_ffmpeg` | 110200 → 114224 | ✅ h264+aac | ✅ | ✅ | ✅ | ✅ |
| `v_b_mkvmerge` | 115167 → 119191 | ✅ | ✅ | ✅ | ✅ | ✅ |
| `v_c_live` | unknown，**无补丁** | ✅ | ✅ | ✅ | ✅ | ✅ |
| `v_d_rich` | 115179 → 119203 | ✅ | ✅ | ✅ | ✅ | ✅ |

**时长未受影响**：`3.023000`（原始）== `3.023000`（注入后）✅
MKV 的时长来自 `Info/Duration` 显式元素，与文件大小无关——这点与 AAC 形成鲜明对比（见 §4）。

**Seek/Cues 完整性**：对注入后的文件 `-ss 2.0` 抽帧，与原始文件同位置抽帧
**PNG 字节完全一致**（26500 B == 26500 B）✅ 证明 `SeekHead`/`Cues` 中的绝对偏移未失效。

### 3.3 ⚠️ 实测暴露的细节：`inject_size` 必须是元素**总长**

原型脚本第一版 `strip` 写成 `原值 = 当前值 - 载荷长度`，结果：

```
stripped Void@110252(4019) ; Segment size 114224 -> 110205
BIT-EXACT = False          <-- 差 5 字节 = 1( Void ID) + 4(size VINT)
```

修正为减去**元素总长** 4024 后：
```
stripped Void@110252 (element=4024 = 1 ID + 4 sizeVINT + 4019 payload) ; 114224 -> 110200
BIT-EXACT = True           <-- x4 变体全部逐比特还原
```

**这条必须写进设计**：MKV 适配器的 `inject_size` 必须遵循 PNG（`png.rs:167`：
`4 + 4 + ube_size + 4`）和 JPEG（`jpeg.rs:308`：`4 + seg_payload_len`）已有的约定——
**注入区的完整字节数，含容器头**。RIFF 同理（`SHRD` 8 字节 chunk 头必须计入）。
若按载荷长度计算，`remove` 会留下 N 字节残渣，`orig_host_sha256` 校验必然失败。

---

## 4. 实验四：AAC（裸 ADTS）—— ❌ `eof` 方案被否决

### 4.1 现象

对裸 `.aac`（ADTS，18243 B，88 帧）尾部追加**不透明字节**，解码出的 PCM 完全一致，
**但 ffprobe 报告的时长按文件大小线性膨胀**：

| 追加字节 | 文件大小 | ffprobe duration | 相对真值(2.043s) |
| --- | --- | --- | --- |
| 0 | 18243 | 2.015467 | 基准 |
| 1000 | 19243 | 2.125946 | +4.1% |
| 4000 | 22243 | 2.457383 | +20.2% |
| 16000 | 34243 | 3.783130 | **+85.1%** |

**PCM 输出逐比特一致**（`PCM-IDENTICAL = True`）——音频数据本身没坏。

### 4.2 根因

ffprobe 的 ADTS 解复用器在拿不到帧数时用 `文件大小 × 8 / 标称码率` 估算时长。
不透明尾字节被当成音频数据按码率折算成时长，**误差与载荷大小成正比**。

### 4.3 验证替代方案

改为追加**真实的 ADTS 帧**（复制源文件的前 88 帧中的第 1 帧 × 80）：

| 变体 | 文件大小 | ffprobe duration | 真值 | 偏差 |
| --- | --- | --- | --- | --- |
| 原始（88 帧） | 18243 | 2.015467 | 2.043 | -1.4% |
| +16000 不透明字节 | 34243 | 3.783130 | 2.043 | **+85.1%** |
| +80 个真实 ADTS 帧（21200 B） | 39443 | 4.357620 | 3.901 | +11.7% |

追加真实帧时，误差来源变为解复用器**固有的**码率估算偏差（原文件本就有 -1.4%），
**不再随我们的载荷线性放大**。完整解码无报错。

### 4.4 结论

- ❌ **AAC + `eof` 方案否决**：会让播放器显示的时长明显偏长，是用户可感知的元数据损坏，
  违反"不改变宿主可见属性"的承诺。
- ⚠️ **AAC + 合成 ADTS 帧方案可行但成本显著上升**：需要生成合法的 ADTS 帧头
  （采样率索引、声道配置、帧长编码）+ 承载载荷的有效 AAC 载荷（静音 fill element
  或复制真实帧），工作量从方案的 1 人日上升到 **1.5~2 人日**，且仍受检测启发式的风险影响。
- 建议：**AAC 移出本次范围**，或作为独立任务排期。

---

## 5. 实验五：HEIC `mdat size==0` 边界 —— ✅ 可容忍（修正方案表述）

把 `sample.heic` 的 `mdat` size 字段强制改为 0（"延伸到 EOF"），再走完整 strhide 流程：

| 步骤 | 结果 |
| --- | --- |
| strhide `write` | ✅ 成功，`box_uuid` |
| `heif-info` | ✅ 正常解析 |
| ffmpeg 完整解码 | ✅ 无错误 |
| strhide `verify` | ✅ L1/L2/L3 全 PASS |
| strhide `remove` | ✅ **逐比特还原** |

**但 L1 报告为 `Valid ISO BMFF container (3 top-level boxes)`**——
注入的 uuid box 被 `size==0` 的 mdat 声明吞掉了，结构上不再是独立的第 4 个 box。

### 5.1 结论修正

方案 §5.2 原本写"追加的 uuid box 会被 mdat 吞掉"，语气偏向"损坏"。实测表明：

- **不会损坏**：解码完全正常，还原逐比特一致；
- **真实影响**：结构上不可分辨 → `inspect`/`verify` 的结构描述失真，暗藏性下降。

因此 §5.2 的处置建议（把 `box_uuid` 标为 `available: false` 并回退 `eof`）**保留**，
但理由应表述为"结构可分辨性/报告准确性"，而不是"会损坏文件"。

---

## 6. 汇总

| # | 实验 | 方案 | 结论 |
| --- | --- | --- | --- |
| 1 | HEIC 尾随 uuid box | `box_uuid`（复用 id=3） | ✅ **通过** |
| 2 | WEBP/WAV 尾随 `SHRD` chunk + RIFF size 前置写对 | `riff_chunk`（id=9） | ✅ **通过** |
| 3 | MKV Segment 内 `Void` 元素 + Segment size 原地改值 | `ebml_void`（id=10） | ✅ **通过**（附 `inject_size` 语义约束） |
| 4 | AAC 尾部追加 | `eof` | ❌ **否决**（时长失真）；合成帧方案可行但成本翻倍 |
| 5 | HEIC `mdat size==0` | `box_uuid` | ✅ 不损坏，但结构不可分辨（处置建议保留） |

### 需要回写到方案文档的 3 处修改

1. **§2 结论摘要 / §5.5 / §8**：AAC 移出本次范围，`eof` 方案已实测否决；
   若要做需改为"合成 ADTS 帧"，1.5~2 人日。
2. **§5.4**：新增硬性约束——`inject_size` 必须计入容器头（Void ID + size VINT /
   RIFF chunk 头 8 字节），否则 `remove` 残留残渣。
3. **§5.2**：`mdat size==0` 的处置理由改为"结构可分辨性"，并附实测"不损坏"的结论。

### 需要补充到实现期的经验

- MKV：ffmpeg 与 mkvmerge **都**用 8 字节 Segment size VINT，"VINT 太窄需回退 eof"
  是防御性分支而非常规分支；但 **unknown-size（流式录制）是真实常见场景**，
  该分支（无补丁）必须实现且要有测试覆盖。
- 所有主流 muxer **本来就在 Segment 里放 `Void` 元素**，Void 方案零风险。
- WAV/MKV 的时长来自显式字段，追加尾随数据不影响；**只有裸 ADTS 受影响**。