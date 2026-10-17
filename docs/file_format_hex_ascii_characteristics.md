# 常见文件格式在十六进制（WinHex）ASCII/UTF-8 视图中的特征分析

> 本文总结了在十六进制编辑器（如 WinHex、010 Editor）的 ASCII / UTF-8 视图中，无需依赖开头 Magic Header（魔数），通过文件内部宏观结构、特征字符串分布与数据熵排布快速辨别文件类型的方法。

---

## 1. 结构与容器型格式

这类格式具有严谨的容器规范，文件主体由带名称的标签、分块（Chunk）或原子（Atom）串联而成，在 ASCII 视图中会呈现出高度规律的 4 字符标识。

### 1.1 MP4 / MOV / 3GP（基于 ISO Base Media File Format）
* **ASCII 视图核心特征**：全文每隔一段距离就会出现整齐的 4 字母（大写或小写）Box/Atom 标识符：
  ```text
  ....ftypisom....moov....mvhd....trak....tkhd....mdia....minf....stbl....mdat
  ```
* **宏观分布**：
  * **头部/元数据区**：`ftyp`、`moov`、`mvhd`、`trak`、`udta` 等，伴随少量数字与编码名称（如 `avc1`、`mp4a`、`hvc1`）。
  * **媒体主体区**：`mdat`（Media Data）。该标记之后占据文件 95% 以上体积，在 ASCII 视图中表现为漫长、均匀、无任何可读字符的雪花状高熵乱码。
* **空字节填充**：极少，除部分 Atom 头部对齐外整体紧凑。

### 1.2 PNG 图像文件
* **ASCII 视图核心特征**：由顺序排列的 4 字节大写/混合大小写 Chunk 块名贯穿：
  ```text
  ....IHDR........sRGB........pHYs........IDATx^...IDAT...IDAT........IEND
  ```
* **宏观分布**：
  * 文件头部必定紧随 `IHDR`、`sRGB`、`gAMA`、`pHYs` 等元数据块。
  * 图像数据由一个或多个 `IDAT` 块承载，内部为 zlib 压缩数据（开头常见 `x^`、`x\x9c` 等 zlib 头特征）。
  * 文件尾部严格以 `IEND` 结束（标准为 12 字节：`00 00 00 00 49 45 4E 44 AE 42 60 82`）。

### 1.3 RIFF 容器（AVI 视频 / WAV 音频 / WebP 图像）
* **ASCII 视图核心特征**：包含 `RIFF`、`LIST` 及对应子格式的 FourCC 标识：
  * **AVI**：`RIFF....AVI LIST....hdrlavih....movi....idx1`，视频流帧标记常见 `00dc`（压缩视频）、`01wb`（音频流）。
  * **WAV**：`RIFF....WAVEfmt ....data`。
  * **WebP**：`RIFF....WEBPVP8 ` 或 `VP8X`、`VP8L`。

---

## 2. 混合结构型格式（明文标记 + 压缩流）

### 2.1 PDF 文档
PDF 采用明文对象描述语法与压缩数据流混合的“夹心”架构，特征极具辨识度。
* **ASCII 视图核心特征**：
  * **大量明文关键字**：`obj`、`endobj`、`stream`、`endstream`、`xref`、`trailer`、`startxref`、`%%EOF`。
  * **字典与参数语法**：遍布形如 `<< /Type /Catalog /Pages 2 0 R >>`、`<< /Filter /FlateDecode /Length 1234 >>` 的明文键值对。
  * **夹心结构**：在 `stream` 与 `endstream` 之间是压缩的高熵二进制流（多为 Deflate/zlib 编码），其余部分皆为可读性强的 ASCII 文本。
* **尾部特征**：尾部几乎必然存在纯数字和状态标记排成的交叉引用表（`xref`）以及 `trailer`，末行固定为 `%%EOF`。

---

## 3. 可执行二进制文件（Windows PE / EXE / DLL）

### 3.1 Windows PE 文件
PE 文件内部严格按节区（Sections）组织，在内存与磁盘上均有对齐要求。
* **ASCII 视图核心特征**：
  1. **DOS Stub 残留文本**：文件前部（通常在偏移 `0x40 ~ 0x80` 附近）普遍包含历史遗留文本：
     ```text
     This program cannot be run in DOS mode.
     ```
  2. **节区名称（Section Names）**：在头部之后能清晰看到点号开头的标准节名：
     ```text
     .text...`.rdata...8.data...p.rsrc...P.reloc
     ```
  3. **大段连续空字节对齐带（Padding）**：由于节区按 512 或 4096 字节物理对齐，节区交界处在 ASCII 视图中表现为**大面积规则的点号填充（`00 00 00 ...` -> `.........`）**。
  4. **导入导出 API 与 DLL 字符串**：集中分布在 `.rdata` 节中，可以肉眼辨识出大量的操作系统动态库与函数符号（如 `KERNEL32.dll`、`USER32.dll`、`GetProcAddress`、`VirtualAlloc` 等）。
  5. **清单文件（Manifest）**：资源节（`.rsrc`）附近经常内嵌未压缩的明文 XML 清单：
     ```xml
     <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
     <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
     ```

---

## 4. 压缩包与归档容器（ZIP / Office / APK / JAR）

### 4.1 ZIP 及其衍生格式（DOCX, XLSX, APK, JAR）
* **ASCII 视图核心特征**：
  * **明文路径与文件名贯穿始终**：
    * ZIP 采用局部文件头与中央目录双索引结构，每个子文件的数据前都带有明文文件名，尾部中央目录还会集中汇总一次。
    * **Office 文档**（DOCX/XLSX）：即便不解压，滚屏也能看到 `[Content_Types].xml`、`word/document.xml`、`xl/worksheets/sheet1.xml`、`_rels/.rels` 等固定路径。
    * **APK 包**：必定可见 `AndroidManifest.xml`、`classes.dex`、`resources.arsc`、`res/...` 等。
    * **JAR 包**：必定可见 `META-INF/MANIFEST.MF`。
* **排列特征**：数据流致密紧凑，没有任何大块 `00` 空字节填充带。

---

## 5. 纯高熵压缩图像（JPEG）

### 5.1 JPEG / JPG 文件
* **ASCII 视图核心特征**：
  * **头部元数据区**：仅紧随文件头后的小段区域存在可读字符串（如 `Exif`、`JFIF`、相机型号 `Apple` / `Canon`、软件名 `Adobe Photoshop`、XMP 命名空间 URL 等）。
  * **图像主体区**：经过离散余弦变换（DCT）与霍夫曼/算术编码后的比特流。
  * **视觉表现**：在 ASCII 视图中表现为**全盘最高密度、近乎完全均匀的雪花乱码**，没有任何单词、没有空字节填充带。
  * **十六进制特征伴随**：在 Hex 视图中，为防止熵编码数据与控制标记冲突，频繁出现 `FF 00` 字节对（Byte Stuffing）。

---

## 6. 综合对比速查表

| 格式类型 | ASCII 视图肉眼可见标记 | 连续空字节（`00`）填充 | 典型局部特征 |
| :--- | :--- | :--- | :--- |
| **EXE / DLL** | `.text`、`.rdata`、`KERNEL32.dll`、DOS Stub、XML 清单 | **极多**（节区对齐形成的大片点号） | 结构分界分明，字符聚集在特定节 |
| **ZIP / Office** | 散落在各处的子文件相对路径与文件名 | **无**（紧凑存储） | 局部压缩乱码中穿插明文文件名 |
| **PDF** | `obj`、`endobj`、`stream`、`<< /Type >>`、`xref`、`%%EOF` | 极少 | 结构化明文与高熵数据块严格交替 |
| **MP4 / MOV** | 4 字母小写/大写 Atom 标签（`ftyp`、`moov`、`trak`、`mdat`） | 极少 | 头部标签密集，后续是巨大的 `mdat` 均匀乱码 |
| **PNG** | 4 字母大写 Chunk 标签（`IHDR`、`IDAT`、`IEND`） | 极少 | 规律出现的 `IDAT` 块，末尾为 `IEND` |
| **JPEG** | 仅头部有少量 Exif 文本/设备名，主体全为雪花乱码 | **无**（频繁出现 `FF 00`） | 极高熵，除头部外无任何可读字符 |
