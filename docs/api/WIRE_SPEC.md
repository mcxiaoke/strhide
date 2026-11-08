# strhide 线格式：已拆分（索引）

> **本文件已拆分。** 2026-11-07 起，线格式规范拆为主题文档，位于 [`docs/api/spec/`](./spec/README.md)。
> 本文件只保留为入口，避免外部链接失效；旧内容中的错误描述已在新规范中按代码修正，
> 勘误清单见 [spec/CORRECTIONS.md](./spec/CORRECTIONS.md)。

## 新文档索引

| 主题 | 文档 |
|---|---|
| 总览、术语、字节序、版本策略、稳定性分级 | [spec/README.md](./spec/README.md) |
| 密钥派生与 AEAD（两域） | [spec/CRYPTO.md](./spec/CRYPTO.md) |
| 确定性数学库（影响字节输出的浮点语义） | [spec/DETMATH.md](./spec/DETMATH.md) |
| 容量公式与限额 | [spec/CAPACITY.md](./spec/CAPACITY.md) |
| 内容域公共信封（头、TLV、槽位、置换、STC） | [spec/CONTENT-ENVELOPE.md](./spec/CONTENT-ENVELOPE.md) |
| 内容域 PNG（HILL / S-UNIWARD / MiPOD） | [spec/CONTENT-PNG.md](./spec/CONTENT-PNG.md) |
| 内容域 JPEG（UERD / J-UNIWARD / J-MiPOD） | [spec/CONTENT-JPEG.md](./spec/CONTENT-JPEG.md) |
| 内容域 HEVC / HEIF | [spec/CONTENT-HEVC.md](./spec/CONTENT-HEVC.md) |
| 内容域 WAV / FLAC | [spec/CONTENT-AUDIO.md](./spec/CONTENT-AUDIO.md) |
| 结构域 UBE 信封 | [spec/STRUCTURE-ENVELOPE.md](./spec/STRUCTURE-ENVELOPE.md) |
| 结构域 PNG / JPEG | [spec/STRUCTURE-PNG.md](./spec/STRUCTURE-PNG.md)、[spec/STRUCTURE-JPEG.md](./spec/STRUCTURE-JPEG.md) |
| 结构域 RIFF（WAV/WebP） | [spec/STRUCTURE-RIFF.md](./spec/STRUCTURE-RIFF.md) |
| 结构域 ISO-BMFF（MP4/HEIF） | [spec/STRUCTURE-ISOBMFF.md](./spec/STRUCTURE-ISOBMFF.md) |
| 结构域 ZIP / PDF | [spec/STRUCTURE-ZIP.md](./spec/STRUCTURE-ZIP.md)、[spec/STRUCTURE-PDF.md](./spec/STRUCTURE-PDF.md) |
| 结构域 PE / Matroska | [spec/STRUCTURE-PE.md](./spec/STRUCTURE-PE.md)、[spec/STRUCTURE-MKV.md](./spec/STRUCTURE-MKV.md) |

## 历史文档（已拆分，非规范）

- [WIRE_SPEC_CONTENT.md](./WIRE_SPEC_CONTENT.md)：原内容域 §13，现仅作历史参考，**与实现不一致之处以 `spec/` 为准**。
- [WIRE_SPEC_STRUCTURE.md](./WIRE_SPEC_STRUCTURE.md)：原结构域 §2–§12，同上。

## 两域速览

- **结构域（`write` / `restore`）**：UBE v2，`112B header` + hint + meta + 分块载荷 + `24B trailer`，支持宿主逐字节还原；字节序小端。
- **内容域（`embed` / `extract`）**：按载体变化的密钥化基础头 + 可选 TLV + 单个 AEAD 正文，槽位经密钥置换后由 STC 编码；多字节字段大端；宿主不可还原。

两域派生域隔离、信封不兼容、不能交叉读取。详细对比见 [spec/README.md §1](./spec/README.md)。
