# strhide 载体文件特征分析与隐蔽性增强技术方案

> 文档编号：STRHIDE-DOC-20261017-01  
> 状态：规划与实施中  
> 涉及模块：核心引擎、格式适配器（JPEG, PDF, PNG, MP4, ZIP, PE）、信封协议  

---

## 1. 背景与现状分析

在十六进制编辑器（如 WinHex、010 Editor）中，即便忽略开头的 Magic Header（魔数），各类主流文件（视频、图像、压缩包、PDF、可执行文件）在 ASCII/UTF-8 视图、节区排布与数据熵方面均存在极其鲜明的内生特征。

### 1.1 主流格式的 WinHex 视图宏观特征

1. **Windows PE（EXE / DLL）**：
   * **文本特征**：固定保留历史 DOS Stub 字符串（`This program cannot be run in DOS mode.`），各节区头部以点号开头的标准命名（`.text`、`.rdata`、`.data`、`.rsrc`、`.reloc`），大量 Windows API 导出/导入函数名及 DLL 名（`KERNEL32.dll`），尾部资源节常内嵌明文 XML 清单（Manifest）。
   * **物理特征**：节区之间存在大片因 512/4096 字节物理对齐产生的连续 `00`（在 ASCII 视图表现为大面积点号 `....`）。
2. **ZIP 归档及 Office 文档（DOCX / XLSX / APK / JAR）**：
   * **文本特征**：明文路径贯穿全局（如 Office 的 `word/document.xml`、`[Content_Types].xml`，APK 的 `AndroidManifest.xml` 等）。
   * **物理特征**：无连续 `00` 对齐填充带，数据紧密排布；中央目录（Central Directory）集中复现所有路径列表。
3. **PDF 文档**：
   * **文本特征**：典型的明文与压缩流“夹心”结构，遍布 `obj`、`endobj`、`stream`、`endstream`、`<< /Type ... >>` 关键字，尾部必有交叉引用表 `xref`、`trailer` 和 `%%EOF`。
4. **MP4 / MOV 容器**：
   * **文本特征**：标准 4 字符 Atom/Box 标签串联（`ftyp`、`moov`、`mvhd`、`trak`、`mdat`）。`mdat` 占据 95% 以上体积，表现为极均匀的高熵乱码。
5. **PNG 图像**：
   * **文本特征**：4 字符 Chunk 块名严格依序排列（`IHDR`、`sRGB`、`pHYs`、多个 `IDAT`、末尾固定的 `IEND`）。
6. **JPEG 图像**：
   * **文本特征**：仅文件前部存在短暂 Exif / XMP 元数据，主体为全盘均匀的高熵雪花乱码，Hex 视图频繁出现防止标记冲突的 `FF 00` 字节对。

---

## 2. strhide 现有数据隐藏机制的异常性与破绽诊断

`strhide` 当前定位为**“宿主功能保全型容器隐写（Function-Preserving Container Hiding）”**，在保证载体功能 100% 正常可用且能 100% 逐比特无损还原（Remove）的前提下，在专业取证或 WinHex 分析下存在以下层面的破绽：

### 2.1 默认标准模式（未开启 `--stealth`）
* **明文魔数暴露**：信封头部包含 `\x89STRHIDE`（ASCII 显示 `‰STRHIDE`），尾部包含 `STH!`。通过 `strings` 命令或 WinHex 搜索可秒级定位。
* **明文密码提示**：`--hint` 字符串未经混淆，直接以 UTF-8 存储在头部之后。
* **检出难度**：极易（任何 YARA 规则或杀软静态特征码均可检出）。

### 2.2 隐蔽模式（`--stealth`）下的深层结构异常
虽然消除了静态魔数并将载荷全盘加密为随机密文，但依然存在**宿主格式规范违和**与**统计学异常**：

| 载体格式 | 当前隐藏位置/策略 | WinHex / 逆向工具眼中的异常表现 | 常见检出告警 |
| :--- | :--- | :--- | :--- |
| **JPEG** | `FF D9`（EOI）之后直接追加 | 图像在 EOI 标记后本应彻底结束，尾部却挂着大量数据 | `ExifTool`: *Warning: Trailing data after EOI* |
| **PDF** | `%%EOF` 之后直接追加 | 文档在最终行 `%%EOF` 后出现无主高熵随机数据 | `pdfid`/`pdf-parser`: *Trailer garbage detected* |
| **PE (EXE)** | 最后一个节区之后追加（PE Overlay） | 物理大小超出节区头表定义的范围 | `PE-bear`/`DiE`: *Overlay detected (Entropy 7.99)* |
| **PNG** | `IEND` 前插入自定义 `stEg` Chunk | 出现非官方注册的 4 字母 Chunk 标签 | `pngcheck`: *chunk stEg: private, ancillary* |
| **MP4** | 末尾追加顶层 64 位 `uuid` Box | 尾部挂载非标准/无对应播放业务的巨大扩展 Box | `mp4box`: *Unrecognized user private uuid box* |
| **ZIP** | Central Directory 前插入（`pre_cd_inject`） | 最后一个本地流与中央目录之间存在未索引的空隙区间 | `zipdetails`: *Offset gap between entries and CD* |

此外，AES-256-GCM 密文具备接近理论极限的信息熵（$\approx 7.99\text{ bits/byte}$），在低熵宿主（如 PDF、PE 代码段）中会呈现出极具视觉冲击力的**高熵断层悬崖**。

---

## 3. 隐蔽性渐进式改善技术方案

在坚守“不破坏宿主功能”、“无损可逆还原”两大红线的前提下，采取**“从外挂走向合规内嵌”**的渐进重构路线：

### 方案 1：JPEG 结构合规化 —— `APPn` / `COM` 标记链（优先级：P0）
* **原理**：将隐藏信封切片封装进合法的 `APP13`（Photoshop IRB 扩展段）或 `COM`（Comment 注释标记 `FF FE`）中。
* **规格**：单个 JPEG 标记最大为 65533 字节。当载荷超过 64KB 时，拆分为多个连续的 `APPn`/`COM` 标记段顺序链接。
* **效果**：数据完全处于 `FF D8` 和 `FF D9` 之间，消除 `Trailing data after EOI` 警告，WinHex 视其为合法的图像元数据。

### 方案 2：PDF 规范合规化 —— 增量更新对象流（优先级：P0）
* **原理**：利用 PDF 官方支持的 Incremental Update（增量更新）规范，不将数据裸追加在 `%%EOF` 之后，而是伪装为合法对象流：
  ```pdf
  99 0 obj
  << /Type /Metadata /Length 12345 >>
  stream
  [UBE 信封数据]
  endstream
  endobj
  xref
  ...
  trailer
  << /Root ... /Prev ... >>
  startxref
  ...
  %%EOF
  ```
* **效果**：文件尾行始终是合规的 `%%EOF`，取证工具识别为一次正规的元数据修订，消除“尾部未定义垃圾”警告。

### 方案 3：PNG 伪装化 —— 标准 `zTXt` / `iTXt` 文本块替换（优先级：P1）
* **原理**：彻底移除易引起警觉的 `stEg` 标签，改为 PNG 标准压缩文本块 `zTXt`。
* **伪装**：采用正规的元数据 Keyword（如 `Raw profile type exif`、`Comment`、`Description`）。
* **效果**：完全符合 W3C PNG 规范，解析器自动忽略，消除未知私有块告警。

### 方案 4：MP4 结构下沉 —— 移入 `moov.udta.meta` 容器（优先级：P1）
* **原理**：不将 `uuid` Box 挂在文件最末端，而是嵌套在媒体元数据 `moov.udta` 内部，并使用主流厂商常用的 UUID 命名空间前缀。

### 方案 5：极小文本零膨胀隐藏 —— PE / ZIP 填充空隙（Slack Hiding）（优先级：P2）
* **原理**：针对小于 4KB 的短文本/密钥，直接写入 PE 节区对齐填充的 `00` 空隙（Section Slack）或 ZIP 局部头 Extra Field。
* **效果**：文件总物理大小 0 字节增加，彻底免疫文件大小监控与 Overlay 检测。

---

## 4. 分步实施与验证路线图（严守单项验证原则）

按照“逐个改造、小数据先验、无损强校验通过后再推进下一项”的开发流程：

```
+-------------------------------------------------------------+
| 步骤 1: PNG 适配器优化（stEg -> zTXt/iTXt 标准文本块）      |
|         - 小数据测试 (几十字节) -> 验证 read/verify/remove  |
|         - 确保 100% 逐比特无损还原                          |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 步骤 2: JPEG 适配器优化（EOI 追加 -> APPn/COM 分段链）     |
|         - 验证单段（<64KB）与多段（>64KB）链式状态机         |
|         - 消除 Trailing data after EOI                      |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 步骤 3: PDF 适配器优化（%%EOF 追加 -> 规范增量更新流）      |
|         - 构建合法 xref / trailer / stream 增量链           |
|         - 尾部保证以 %%EOF 闭合，消除 Trailer Garbage       |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 步骤 4: MP4 与其他格式后续精细化演进                        |
+-------------------------------------------------------------+
```
