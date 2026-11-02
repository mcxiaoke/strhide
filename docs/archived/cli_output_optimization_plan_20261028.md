# CLI 输出格式优化方案 (2026-10-28)

## 1. 目标与设计原则

优化 `strhide` 命令行终端交互体验，解决长耗时命令缺乏进度反馈、输出多行信息松散稀疏、数字单位缺乏人类可读性（冗长纯字节与千万级数字）等问题。

### 设计原则
1. **耗时可视 (Elapsed Time)**：容量探测、隐写嵌入、提取、还原、结构域读写等长耗时操作在完成时统一打印友好耗时（如 `45ms`, `1.34s`, `2m 15s`）。
2. **高信息密度与合理归类**：
   - 容量探测（`capacity` / `embed --capacity`）从原来的 8 行归纳为清晰的 **3 行架构**：
     - **第 1 行（载体媒体层）**：格式、规格/分辨率/时长码率、总元素数（友好计数）。
     - **第 2 行（算法参数层）**：算法名、档位与约束参数、预估修改率。
     - **第 3 行（容量指标层）**：推荐安全容量、最大原始容量、有效载荷槽位；采样模式带预估提示。
3. **内容域算法及参数透明**：
   - 隐写嵌入（`embed`）成功输出行呼应结构域 `[策略: chunk]`，显式标记 `[算法: name (params)]`（例如 `[算法: uerd (stc_h: 7, safety: high)]`、`[算法: HEVC-CABAC-InPlace (safety: high)]`）。
4. **人类友好单位 (Human-Readable Units)**：
   - 大计数（元素数、槽位数）：`<1K` 保留整数，`1K~1M` 显示 `xxx.xxK`，`1M~1G` 显示 `xxx.xxM`，`≥1G` 显示 `xxx.xxG`。
   - 数据容量大小：采用标准二进制单位 `B`, `KiB`, `MiB`, `GiB`，保留 2 位小数。
5. **机器兼容性保证**：
   - `--json` 输出直接序列化 Rust 结构体，字段与数字类型 100% 保持不变，保障自动化工具与脚本（如 `scripts/baseline_hash.py`）无缝兼容。
   - 中英双语（zh/en）对称对齐。

---

## 2. 格式化标准与函数定义

位于 `rust/src/cli/helpers.rs`：
- `format_count(n: usize) -> String`：例如 `71443814400` -> `71.44G`，`559362333` -> `559.36M`。
- `format_size(bytes: usize) -> String`：例如 `34960095` -> `33.34 MiB`，`1500122` -> `1.43 MiB`。
- `format_duration(d: std::time::Duration) -> String`：`<1s` -> `42ms`，`<60s` -> `1.25s`，`≥60s` -> `2m 15s`。
- `describe_stego_algorithm(...) -> String`：解析并提取算法名与参数摘要。

---

## 3. 各命令输出规范

### 3.1 容量探测 (`capacity` / `embed --capacity`)
```text
文件 '.\temp\bighevc\anime-b.mp4' 的自适应隐写容量 (耗时 1.34s):
  载体媒体: MP4/HEVC, 1920x1080, 23.98 fps, 1437.0s (3.1 Mbps), 71.44G 元素
  隐写算法: HEVC-CABAC-InPlace (档位: high, bpp <= 0.10) | 预估修改率 ~0.25
  隐写容量: 推荐安全 1.43 MiB | 最大原始 33.34 MiB (559.36M 槽位)
```

### 3.2 隐写嵌入 (`embed`)
- 原地嵌入：
```text
[OK] 载荷 100.0 KiB 成功原地嵌入 '.\photo.jpg' [算法: uerd (stc_h: 7, safety: high)] (耗时 250ms)
     容量占用: 6.8% (安全 1.43 MiB, 最大 33.34 MiB, 559.36M 槽位)
```
- 输出至目标文件：
```text
[OK] 载荷 100.0 KiB 成功嵌入 '.\photo.jpg' -> '.\out.jpg' [算法: uerd (stc_h: 7, safety: high)] (耗时 250ms)
     容量占用: 6.8% (安全 1.43 MiB, 最大 33.34 MiB, 559.36M 槽位)
```
- 演练模式（`--dry-run`）：
```text
[DRY-RUN] '.\photo.jpg' 演练完成 [算法: uerd (stc_h: 7, safety: high)] (耗时 120ms): 预估大小 1.00 MiB (原 976.6 KiB, +47.4 KiB / +4.86%)
          容量占用: 6.8% (安全 1.43 MiB, 最大 33.34 MiB, 559.36M 槽位)
```

### 3.3 隐写提取 (`extract`)
```text
[OK] 成功提取载荷至 '.\extracted.bin' (1.00 MiB, 耗时 45ms)
```

### 3.4 结构域隐藏 (`write`)
```text
[OK] 成功写入载体 'sample.png' [策略: chunk] (耗时 12ms)
     载荷 12.06 KiB -> 信封 12.11 KiB | 备份: 'sample.png.bak'
```

### 3.5 结构域提取 (`read`)
```text
[OK] 成功提取载荷至 'extracted.bin' (12.06 KiB, 耗时 6ms)
```

### 3.6 结构域还原 (`restore`)
```text
[OK] 成功清除隐藏数据，宿主已还原: 'sample.png' (530.48 KiB, 耗时 18ms)
     SHA-256: e3b0c442... (100% 校验一致) | 备份: 'sample.png.bak'
```

### 3.7 诊断汇总 (`scan` / `verify`)
```text
[SUMMARY] 扫描完成: 12/12 个载体 (干净: 10, 含隐写: 2, 耗时 1.45s)
[SUMMARY] 校验完成: 全部 5 个载体验证通过 (耗时 320ms)
```
