# HEVC 代码归属分析与外部引用改造备忘

- 日期：2026-10-24 19:24
- 背景：梳理 `rust/src/stego/hevc/` 目录下全部代码的来源归属、修改点，并记录将直接复制代码改为通过 path 引用 `C:\Home\Projects\strhide-vendor` 仓库的改造计划。

---

## 1. 整体代码归属全景

`rust/src/stego/hevc` 共有 **36 个文件**，由三部分组成：

```
rust/src/stego/hevc/
├── 根目录 (7 个文件)   ─── strhide 本地原生业务逻辑（无需拆出，主仓保留）
├── cabac/  (7 个文件)   ─── 全部源自 oxideav-h265（核心代码逻辑 0 改动，含 2 个死代码文件）
└── h265/   (22 个文件)  ─── 全部源自 roticv/rust_h265（仅 5 个核心文件有隐写插桩改动，16 个零改动）
```

> **归属说明**：
> 1. `h265/` 下的 22 个文件全部派生自 **`roticv/rust_h265`**（之前文件头误加的 `oxideav-h265` SPDX 头为归属错误）。
> 2. `cabac/` 下的文件源自 **`oxideav-h265`**，用于提供 `rust_h265` 缺失的 CABAC 编码器能力。

---

## 2. 详细文件梳理

### 2.1 `cabac/` 目录（来源：`oxideav-h265`）

| 文件名 | 上游对应文件 (`oxideav-h265`) | 是否修改 | 具体差异说明 |
|---|---|---|---|
| `bitreader.rs` | `src/bitreader.rs` | **零改动** | 100% 一致 |
| `bitwriter.rs` | `src/encoder/bitwriter.rs` | **逻辑零改动** | 仅单元测试中 1 行 `use` 路径改为本地路径 |
| `encoder.rs` | `src/encoder/cabac.rs` | **逻辑零改动** | 仅 4 行 `use` 路径改为本地 `super::` 相对路径 |
| `engine.rs` | `src/cabac.rs` | **逻辑零改动** | 仅 1 行 `use` 路径改为 `super::bitreader` |
| `mod.rs` | *(strhide 胶水代码)* | 本地自建 | 仅声明并 re-export 上述 4 个模块（15 行） |
| `tables.rs` | 抽取自 `src/cabac.rs` | **死代码** | 抽取了状态转移表，但在 `mod.rs` 中**未声明、未被任何代码引用** |
| `ctx.rs` | 抽取自 `src/ctx_init.rs` | **死代码** | 抽取了初始上下文，但在 `mod.rs` 中**未声明、未被任何代码引用** |

### 2.2 `h265/` 目录（来源：`roticv/rust_h265`）

#### 完全无实质逻辑修改的文件（16 个）
仅做了模块导入路径替换（`use crate::...` -> `use crate::stego::hevc::h265::...`）或移除了上游的 `#[cfg(test)]` 测试块：
- `bitstream.rs`
- `cabac_tables.rs`
- `deblock.rs`
- `dpb.rs`
- `error.rs`
- `inter_pred.rs`
- `intra_pred.rs` *(仅格式换行差异)*
- `inverse_transform.rs`
- `pixel.rs`
- `pps.rs`
- `profile_tier_level.rs`
- `sao.rs`
- `scaling_list.rs`
- `slice.rs` *(仅移除测试模块)*
- `sps.rs`
- `vps.rs`

#### 有实质修改的文件（6 个，其中 5 个为核心隐写插桩点）
1. **`mod.rs` (对应上游 `lib.rs`)**：
   - 将私有模块导出为 `pub mod cabac; pub mod cabac_tables; pub mod pps; pub mod slice; pub mod sps; pub mod vps;`。
2. **`nal.rs`**：
   - 为 `NalUnitType` 增加 `pub fn to_u8(self) -> u8` 方法，方便获取 6-bit NAL 类型整数值。
3. **`cabac.rs` (核心隐写侵入点 1)**：
   - `CabacReader` 增加 `recorder: Option<*mut CabacRecorder>` 与 `ctx_base: usize`。
   - 增加 `attach_recorder()` 与 `decode_stego_sign()` 方法。
   - 在 `decode_bin`、`decode_bypass`、`decode_terminate` 中插入 recorder 统计钩子。
4. **`residual_coding.rs` (核心隐写侵入点 2)**：
   - 将 `decode_coeff_sign_flag` 改为 `decode_coeff_sign_flags`，提取非零系数的扫描坐标 `(x_c, y_c)`，并向 `decode_stego_sign` 传入 `qp`、`trafo_size`、`c_idx` 与坐标。
5. **`decoder.rs` (核心隐写侵入点 3)**：
   - `Decoder` 增加 `active_recorder` 字段。
   - 暴露 `active_sps()` 和 `active_pps()` 查询接口。
   - 增加 `decode_nal_with_recorder()` 入口。
   - 在 slice 解码入口、WPP entry point (substream) 以及 slice 结束时通知 recorder。
6. **`cu_tree.rs`**：
   - 仅在 intra 预测模式解析处将 `mpm_idx` 与 `rem` 合并为一个 if 表达式元组返回，无功能变化。

### 2.3 根目录文件（属于 strhide 原生逻辑，主仓保留）
- `bitstream.rs`：Annex-B NAL 切分、防竞争字节 (EPB) 翻转安全性检验、Cover 载体校验哈希。
- `engine.rs`：Scheme C 隐写主引擎（STC 嵌入、提取、加解密）。
- `error.rs`：strhide 的 HEVC 专用错误类型 `HevcError`。
- `heif_boxes.rs`：ISOBMFF / HEIF 容器 box 结构解析与 Primary Item 定位。
- `mod.rs`：HEVC 隐写模块入口。
- `slot.rs`：`CabacRecorder` 与隐写槽位 (Slot) 定义。
- `sniff.rs`：HEVC 载体格式嗅探（HEIF / MP4 / Annex-B）。

---

## 3. 改造方案

1. 在 `C:\Home\Projects\strhide-vendor\rust_h265` 中应用上述 5 个核心文件的修改（Recorder 抽象、`decode_stego_sign` 钩子、`pub mod` 导出）。
2. 在 `rust/Cargo.toml` 中配置 path 依赖引用 `strhide-vendor/rust_h265`（以及 `oxideav-h265`）。
3. 删除 `rust/src/stego/hevc/h265/` 和 `rust/src/stego/hevc/cabac/`。
4. 调整 `rust/src/stego/hevc` 中的代码以引用外部 crate。
5. 本地通过全部构建与回归测试，暂时不提交 git commit。
