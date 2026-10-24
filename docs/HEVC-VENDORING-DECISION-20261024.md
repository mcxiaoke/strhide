# HEVC 第三方代码归属方案评估

- 日期：2026-10-24
- 背景：讨论"是否把 `rust/src/stego/hevc/` 下的第三方代码（`h265/` 16 000 行 + `cabac/` 1 900 行）
  fork 到独立仓库"。本文记录**实测验证**的结论，而非推测。

---

## 0. 结论摘要

| 问题 | 实测结论 |
|---|---|
| `rust_h265` 能否直接用 crates.io 版本？ | ✅ 能，v0.1.0 已发布，零依赖，MIT/Apache 双许可 |
| 只用其**公开 API** 能否完成隐写？ | ❌ **不能**，四项必需能力全部不可得 |
| 把私有 `mod` 改成 `pub mod` 能否解决？ | ✅ **能**，且**零函数体改动**即可编译通过 |
| `rust_h265` 有 CABAC **编码器**吗？ | ❌ **没有**。编码器来自 `oxideav-h265`（已在 crates.io） |
| 我们对 `h265/cabac.rs` 的侵入能否避免？ | ⚠️ 部分可以：`decode_stego_sign` 与上游 `decode_bypass` **逻辑逐行等价**，仅多一次记录 |

**最终建议**：**方案 B' —— 拆成独立仓库，但定位为"strhide 的 HEVC 组件"而非通用库**，
以 **path 依赖**（非 crates.io 发布）引入本仓库。理由见 §4。

---

## 1. 上游现状（实测）

### 1.1 `rust_h265`（roticv）

| 项 | 值 |
|---|---|
| crates.io | ✅ 已发布 v0.1.0，月下载 **115 911**（2026-09-03 周） |
| 许可证 | `MIT OR Apache-2.0` —— 与 strhide 的 Apache-2.0 **兼容** |
| 依赖 | **零**（`[dependencies]` 为空） |
| 本地副本 | `temp/github/rust_h265`，完整 git 仓库，HEAD = `8db4fb4`（trunk 分支） |
| tag | **无**（`git tag -l` 为空）—— crates.io 的 0.1.0 与 trunk 无 tag 对应 |

### 1.2 `oxideav-h265`（OxideAV）

| 项 | 值 |
|---|---|
| crates.io | ✅ 已发布 v0.0.15，MIT |
| 依赖 | `oxideav-core = "0.1"` |
| 本地副本 | `temp/github/oxideav-h265`，完整 git 仓库，HEAD = `db02660` |
| 规模 | 完整解码器 + **编码器**（`src/encoder/` 有 15+ 文件） |

---

## 2. 公开 API 能力检验（决定性实验）

### 2.1 `rust_h265` 的公开面

`src/lib.rs` 的导出：
```rust
pub use decoder::{Decoder, Frame};
pub use error::DecodeError;
pub use nal::{NalUnit, NalUnitType, parse_annex_b, parse_hvcc, parse_nal};
pub use pixel::{Pixel, PixelData};
pub mod decoder;  pub mod error;  pub mod nal;
```

`Decoder` 的**全部**公开方法：`new()` / `decode_nal()` / `flush()`。
`Frame` 的**全部**公开字段：`y` / `u` / `v` / `width` / `height` / `pic_order_cnt` / `bit_depth`。

### 2.2 隐写所需的四项能力 vs 公开 API

| 能力 | 公开 API 可得？ | 说明 |
|---|---|---|
| ① CABAC bin 流（旁路符号位） | ❌ | `mod cabac;` 是**私有模块**，无 observer/callback/hook 机制（`grep observer\|callback\|hook\|listener\|sink\|trace` 命中 0 处） |
| ② substream 边界（WPP） | ❌ | `SliceHeader.entry_point_offsets` 在私有 `mod slice;` 里 |
| ③ `ctx_idx`（上下文索引） | ❌ | `decode_bin(&mut self, state: &mut u8)` 把 ctx 索引**隐式编码在指针位置**里，不在参数中 |
| ④ 系数元数据（QP / TU 尺寸 / x_c,y_c） | ❌ | `Frame` 只有像素；QP 在 `SliceHeader.slice_qp_y`（私有模块） |
| ⑤ NAL 级解析 | ✅ | `NalUnit { nal_unit_type, rbsp, epb_positions, ... }` |

**Cargo.toml 无 `[features]` 段**，无任何 `cfg(feature=...)` 开关 —— 没有"打开观察器"的官方入口。

### 2.3 关键突破：只需翻转模块可见性

`rust_h265` 的解析函数**本身都是 `pub fn`**，只是模块声明是私有的：

```rust
// src/lib.rs（上游原文）
mod sps;          // ← 私有
mod pps;          // ← 私有
mod slice;        // ← 私有
mod cabac;        // ← 私有
```

实测：把 16 个 `mod X;` 改成 `pub mod X;`（+ 2 个 `pub(crate)` → `pub`），
**`cargo build --release` 直接通过，零函数体改动，零警告**。

随后验证四项能力全部可达：
```
[1] CABAC bin stream   : OK  (CabacReader::decode_bin / decode_bypass)
[2] substream boundary : OK  (SliceHeader.entry_point_offsets)
[3] ctx_idx            : OK  (cabac_tables::HEVC_CONTEXTS = 179)
[4] coeff metadata     : PARTIAL — QP via SliceHeader.slice_qp_y,
                         TU size / x_c / y_c live in cu_tree (private fns)
```

**④ 只到 PARTIAL**：TU 尺寸与系数坐标在 `cu_tree` 的**私有函数**里，这部分确实需要改动。

---

## 3. 编码器归属：两个上游可以完全解耦

**`rust_h265` 没有 CABAC 编码器**（只有解码器）。我们的编码器来自 `oxideav-h265`：

```
rust/src/stego/hevc/cabac/encoder.rs
  CabacEncoder::new / reinit
  encode_decision / encode_bypass / encode_bypass_bits / encode_terminate
```

而 `oxideav-h265` 已在 crates.io（v0.0.15，MIT）—— 意味着**编码器可以完全脱离 `rust_h265`**，
单独依赖 `oxideav-h265`。

### 3.1 侵入点可替代性

我们对 `h265/cabac.rs` 的唯一功能侵入是 `decode_stego_sign`。与上游 `decode_bypass`
逐行对比，**算术逻辑完全相同**，只多一次 recorder 记录：

```rust
// 上游 decode_bypass          |  我们的 decode_stego_sign
self.low = self.low.wrapping_add(self.low);   |  ← 相同
if self.low & CABAC_MASK == 0 { self.refill(); }|  ← 相同
let range = self.range << (CABAC_BITS + 1);    |  ← 相同
if self.low < range { 0 } else { self.low -= range; 1 } |  ← 相同
                              |  + if let Some(rec) = self.recorder { rec.record_stego_sign(...) }
```

**但这仍是一个"在解码热路径里插钩子"的侵入**。要避免它，需要一个**独立的 CABAC 解析器**
（strhide 自己实现，只读 bin 流不做重建）—— 这正是 `cabac/` 存在的意义，也是**方案 A 的真正难点**。

---

## 4. 三方案评估

### 方案 A：完全依赖 crates.io 上游（`rust_h265 = "0.1"` + `oxideav-h265 = "0.15"`）

**可行性：❌ 不可行。**

- 公开 API 拿不到 bin 流（§2.2），除非上游加 API。
- 即使上游加了 observer API，仍有两个问题：
  1. `cu_tree` 的 TU 尺寸/坐标是私有函数，需要上游一并暴露；
  2. 上游 `rust_h265` **没有 tag**（crates.io 0.1.0 与 trunk 无对应），将来发 0.2.0 时
     API 变更是无声的破坏 —— 对一个**隐写**工具来说，"解码器行为悄悄变了"是灾难。
- 收益：仓库瘦 18 000 行。

**判断**：不推荐。可以**并行**向上游提 PR 加 observer API（长期方向），但不能等。

### 方案 B：拆成独立仓库（用户提议）

**可行性：✅ 可行，但需明确三点。**

**B1. 定位**：这个仓库**不是通用 HEVC 库**，而是"strhide 的 HEVC 隐写组件"。
因为它包含 recorder 注入、隐写槽位概念、`entry_point_offset` 语义等 strhide 专属概念。
README 第一句就应写明。命名建议 `strhide-h265` 或 `hevc-stego`。

**B2. 引入方式：用 path 依赖，不发 crates.io**
```toml
[dependencies]
strhide-h265 = { git = "https://github.com/<user>/strhide-h265", tag = "v0.1.0" }
# 或
strhide-h265 = { path = "../strhide-h265" }
```
理由：这是**同一个作者的配套仓库**，不是给第三方用的库。发 crates.io 反而要承担
版本兼容、changelog、语义化版本的长期义务。

**B3. fork 的同步义务是真实存在的**，但可控：
- `rust_h265` 上游活跃（本地 HEAD 就在一个 bugfix commit 上）；
- 但我们的侵入**只集中在 5 个文件**（`decoder.rs` +79 / `cabac.rs` +86 /
  `residual_coding.rs` +41 / `cu_tree.rs` +28 / `slice.rs` +10 行），
  **其余 21 个文件零改动** —— rebase 冲突面很小；
- 建议在 fork 里把上游改动**显式 commit 化**（`feat(stego): add CABAC bin recorder`），
  保持 `git log` 清晰，未来 `git rebase upstream/trunk` 的冲突可预期。

**B4. 代价（必须诚实说明）**：
- 构建不再自包含：`strhide` 依赖一个外部仓库的特定 commit。
- 对 `strhide` 的发布（crates.io / release 二进制）意味着**发布时必须保证依赖仓库的
  commit 可达且长期可用**。如果 fork 仓库被删除或 force-push，用户的构建就断了。
  → 缓解：依赖用 **tag 而非 branch**，tag 不 force-push。

### 方案 C：维持现状 + 补齐溯源（已在本轮完成）

- ✅ `THIRD-PARTY-NOTICES.md`（含两个上游的完整许可证文本 + 逐文件改动说明）
- ✅ 29 个派生文件的 SPDX 归属头
- 缺点：仓库重（18 000 行第三方代码），且 `cargo publish` 时这些文件会被打进 crate 包
  （`Cargo.toml` 的 `exclude` 目前只排除了 `/tests`）。

---

## 5. 最终建议

### 推荐：**方案 B'（拆出去，但用 path/tag 依赖 + 明确非通用库定位）**

理由按权重排序：

1. **仓库卫生**：strhide 主仓库回到"自己的代码"，第三方归属清晰，符合用户的直觉。
2. **不牺牲自包含性太多**：用 `tag` 固定版本，避免"拉到什么算什么"。
3. **保留上游可追溯性**：fork 仓库保留 `upstream` remote，随时可对比上游进展。
4. **为方案 A 留门**：如果将来上游接受 observer PR，可以把 fork 逐步瘦身回纯上游。

### 同时保留在 strhide 主仓库的东西

| 留在 strhide | 理由 |
|---|---|
| `slot.rs`（`StegoSlot` / `CabacRecorder`） | 隐写领域概念，与 STC 成本模型耦合 |
| `engine.rs`（embed/extract/probe） | strhide 核心逻辑 |
| `bitstream.rs`（EPB 逻辑、cover digest） | strhide 专属 |
| `heif_boxes.rs`（HEIF 容器解析） | strhide 专属，且**本轮已彻底去 panic** |
| `sniff.rs`（载体识别） | strhide 专属 |

**拆出去的**：`h265/`（上游解码器 + 侵入）、`cabac/`（CABAC 编解码引擎）。

### 迁移动作清单（若采纳 B'）

1. 建仓库 `strhide-h265`，从 `temp/github/rust_h265` 与 `oxideav-h265` 起步，
   **保留 git 历史**（`git subtree` 或 `git filter-repo`），不要重新提交。
2. 把 strhide 对 `h265/` 的侵入**整理为独立 commit**（`feat(stego): CABAC bin recorder`），
   便于与上游 diff。
3. 调整 `h265/` 的 crate 结构：把 `mod X;` 改成 `pub mod X;`（§2.3 已验证可行），
   把 `stego/` 相关的 slot 概念一并搬入。
4. `cabac/` 单独成 crate 或作为 `strhide-h265` 的子模块，依赖 `oxideav-h265 = "0.15"`。
5. strhide 主仓库改为 `strhide-h265 = { git = "...", tag = "v0.1.0" }`。
6. 保留 `docs/HEVC-REVIEW-20261024.md` 与 `THIRD-PARTY-NOTICES.md`（主仓库侧），
   并在 `strhide-h265` 仓库内放一份指向它的链接。
7. 迁移后**必须重跑全部回归**：`cargo test`、`hevc_matrix_bench`（225 组合）、
   `hevc_stress`、`test_hevc_external`（ffmpeg oracle）。

### 不建议的做法

- ❌ **不建议**在 strhide 里用 `git submodule` 引上游 —— submodule 在 crates.io 发布时
  不会被包含，用户 `cargo add strhide` 会直接失败。
- ❌ **不建议**发 crates.io 给这个组件 —— 它是作者的私有配套件，不是生态依赖。
- ❌ **不建议**现在就把 `h265/` 完全替换成 crates.io 版本 —— §2.2 已证明公开 API 不够用。

---

## 6. 附：本次验证的方法与可复现性

所有结论均来自实测，而非阅读推测：

| 实验 | 位置 | 结果 |
|---|---|---|
| crates.io 版本可编译 | 临时 crate 依赖 `rust_h265 = "0.1"` | ✅ 编译通过 |
| 公开 API 能力盘点 | `grep pub fn` / `grep pub struct` 于 `src/lib.rs`、`decoder.rs` | ✅ 四项不可得 |
| 无扩展点确认 | `grep -iE "observer\|callback\|hook\|listener\|sink\|trace"` | ✅ 命中 0 |
| 无 feature 开关 | `grep -A10 "\[features\]" Cargo.toml` | ✅ 无该段 |
| `pub mod` 翻转可行性 | 克隆上游 → 改 18 行 `lib.rs` → `cargo build --release` | ✅ 零警告通过 |
| 四项能力可达性 | 临时 crate 引用 `rust_h265::cabac` / `::slice` / `::sps` | ✅ 全部可达 |
| 编码器缺失 | 临时 crate 探测 `oxideav-h265` | ✅ 确认编码器在 oxideav 侧 |

实验产物（`temp/apiprobe/`、`temp/rust_h265_pub/`）已清理。
