# 旧格式兼容代码盘点（2026-10-20）

> 统计口径：`rust/src/` 全部 `.rs` 文件，按"如果删掉这段代码，新版就无法读取旧版写出的文件"来算。
> 快照时点：`rust/src/` 共 **10,418 行** Rust 代码（含测试）。

## 结论速览

| 类别 | 行数 | 占比 |
|---|---|---|
| 兼容旧格式的生产代码 | ~111 行 | ~1.1% |
| 兼容旧格式的测试代码 | ~140 行 | ~1.3% |
| **合计** | **~251 行** | **~2.4%** |

兼容层**全部在"读"方向**：写路径已经只产出 v2 新格式。唯一例外是文件名过长等 pathological metadata 仍 fallback 到 JSON，目的是让旧 reader 不会读崩。

## 被兼容的旧格式特征

| 旧版本（v0.2/v0.3 Python 时代 + v1 design doc） | 当前 v2（UBE v2.2） |
|---|---|
| Header magic `\x89STRHIDE`（8 字节 ASCII） | 高熵随机 8 字节 `0xB7542C827E311D6E` |
| Trailer magic `STH!`（4 字节 ASCII） | 高熵随机 4 字节 `0x78E666D2` |
| Metadata 用 JSON 序列化（~137 字节） | compact binary（~46 字节） |
| 非加密 envelope 的 metadata/payload 明文存储 | 无密码时也用 `BUILTIN_DEFAULT_KEY` 加密 |
| MP4 用 `\x89STRHIDE\0\0\0\0\0\0\0\1` UUID namespace | 中性随机 UUID `0xD41A...` |
| JPEG 用 COM segment（marker `0xFE`） | APP15（`0xEF`） |
| PE codebits channel magic `STHC` | 跟随 UBE trailer magic |
| PE codebits header 字段不做 masking | header 后 10 字节用 magic 派生 keystream 异或 |

## 逐文件明细

| 文件 | 生产代码 | 测试 | 位置与说明 |
|---|---|---|---|
| `src/envelope.rs` | ~10 | 0 | L14–18 `LEGACY_HEADER_MAGIC` / `LEGACY_TRAILER_MAGIC` 常量；L396–400 `EnvelopeTrailer::unpack` 在 `expected_magic=None` 时同时接受标准与 `STH!` |
| `src/engine.rs` | ~51 | ~25 | L9 `use serde::{Deserialize, Serialize}`；L26 `CarrierMetadata` 派生 serde；L152–157 `encode_metadata` JSON fallback；L160–167 `decode_metadata` JSON 分支；L1108–1132 **legacy plaintext metadata 双路径**（先试 AEAD 解密，失败回退明文解析）；L1148–1160 legacy plaintext payload 直接读字节流不走 chunk 解密 |
| `src/adapters/pe_codebits.rs` | ~19 | ~86 | L40–41 `LEGACY_STHC_MAGIC`；L469–478 `unpack_masked` 中 masked 解码失败后回退 unmasked；L562–568 `read_channel_header` 在无 `expected_magic` 时接受 `STH!`/`STHC` |
| `src/adapters/mp4.rs` | ~5 | 0 | L9–11 `LEGACY_UUID_NAMESPACE` 常量；L226、L250 `locate` 32/64 位 uuid box 检查时 `|| box_uuid == LEGACY_UUID_NAMESPACE` |
| `src/adapters/pe_slack.rs` | ~5 | 0 | L120–126 slack 扫描 magic 列表加入 `LEGACY_TRAILER_MAGIC`；L210–214 header magic 检查同时接受 `LEGACY_HEADER_MAGIC`；L294 `MAGICS` 常量数组 |
| `src/adapters/jpeg.rs` | ~14 | 0 | L350 `com_segments` 声明；L396–398 收集 COM 段；L424–429 trailer magic 检查加 `LEGACY_TRAILER_MAGIC`；L483–486 "Legacy COM segment chain" fallback |
| `src/adapters/png.rs` | ~1 | 0 | L229 trailer magic `|| LEGACY_TRAILER_MAGIC` |
| `src/analysis.rs` | ~6 | 0 | L35 import `LEGACY_HEADER_MAGIC`；L229–232 "strhide (legacy v0)" 签名条目；L552 PE slack 扫描同时试两种 magic |
| `src/crypto.rs` | 0 | ~29 | L426–454 `test_python_crypto_vector_compatibility`（与已冻结的 Python 版对齐 HKDF/AEAD 向量） |
| **合计** | **~111** | **~140** | |

## 隐性成本（不在本仓库行数内）

- **`serde` + `serde_json` 依赖**：为了能读旧版 JSON metadata，`CarrierMetadata` 派生了 `Serialize, Deserialize`，这两个 crate 因此留在依赖树里。若彻底砍掉 JSON 路径，可移除 `serde_json` 依赖，`CarrierMetadata` 也无需 derive serde。
- **read 路径双路径控制流**：`engine.rs` 中"先试解密失败再读明文"的逻辑吞掉一次 AEAD 错误再回退，比纯新格式多一层分支与错误处理。

## 删除兼容层的前提

如果未来决定放弃读旧版文件，需要同步：

1. 移除 `envelope.rs` 中 `LEGACY_*_MAGIC` 常量及 `unpack` 中的 `||` 分支。
2. 移除 `engine.rs` 中 `CarrierMetadata` 的 serde derive、`encode/decode_metadata` 的 JSON 分支、legacy plaintext 双路径。
3. 移除 `pe_codebits.rs` 的 `LEGACY_STHC_MAGIC`、unmasked fallback、`read_channel_header` 中的旧 magic 接受。
4. 移除 `mp4.rs` 的 `LEGACY_UUID_NAMESPACE`、`jpeg.rs` 的 COM segment 收集与 chain fallback、`png.rs`/`pe_slack.rs`/`analysis.rs` 中的 legacy magic 分支。
5. 从 `Cargo.toml` 移除 `serde_json`（确认无其他使用）。
6. 删除对应测试：`engine.rs` JSON legacy 路径测试、`pe_codebits.rs` 两个 legacy 测试、`crypto.rs` Python 向量测试。

预计可净删 ~250 行本仓库代码 + 一个外部依赖。
