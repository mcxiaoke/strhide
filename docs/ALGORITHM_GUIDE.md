# 算法与档位选型 (Algorithm Guide)

> 面向"我要写进去，但不知道该选哪个算法、哪一档"的使用者。API 参考见 [api/STEGO-API.md](api/STEGO-API.md)，原理与公式见 [api/spec/CONTENT-*.md](api/spec/CONTENT-PNG.md) 与 [api/spec/CAPACITY.md](api/spec/CAPACITY.md)。

---

## 1. 两个正交的选择

| 维度 | 决定什么 | 选项 | 参数 |
| :--- | :--- | :--- | :--- |
| **算法** | 把改动放在**哪里**（空间像素 / DCT 系数 / CABAC 符号位 / PCM 采样 / 残差） | 每个格式 1–3 个 | `-a/--algorithm` |
| **档位**（隐蔽强度） | 允许改**多少**（载荷率上限） | `paranoid` / `high` / `balanced` | `--safety` |

两者互不影响：算法决定改动位置的"自然度"，档位决定改动的"密度"。**密度比算法更影响可检测性**——同一算法从 `high` 提到 `balanced`，改动量翻倍，检测率上升的幅度通常大于换算法的收益。

## 2. 算法清单

以 `sth list` 的输出为准（feature 组合会改变可用集合）。下表的 id 用于 `-a`：

| id | 名称 | 载体 | 默认 | 改动位置与原理 | 适用 |
| :--- | :--- | :--- | :--: | :--- | :--- |
| `hill` | HILL | PNG | ✅ | 空间域，小波域滤波得到代价图 + 三元 STC，改动限制在 `val & 0xF8` 同类内 | 通用首选；纹理复杂的人像/风景都好 |
| `suniward` | S-UNIWARD | PNG | | 空间域，小波域方向性残差作代价（"难以建模即难以检测"） | 想换一种统计指纹时；插画、截图等非自然图像值得一试 |
| `mipod` | MiPOD | PNG | | 空间域，基于检测器方差最小化的代价分配 | 需要更保守的代价分配且能接受更慢时 |
| `uerd` | UERD | JPEG | ✅ | DCT 域，按量化步长与频带位置给代价 + 三元 STC | 通用首选；重压缩过的图也稳 |
| `juniward` | J-UNIWARD | JPEG | | DCT 域，小波域残差代价 | 高质量原图（q 高、噪声低） |
| `jmipod` | J-MiPOD | JPEG | | DCT 域，方差最小化代价 | 想降低结构化检测的命中率 |
| `hevc` | HEVC CABAC | MP4/MOV/MKV/HEIC/Annex-B | ✅ | 只翻转 CABAC bypass 符号位，**文件体积零增长** | 视频与 HEIC；体积比对失效 |
| `wav_pcm` | WAV PCM LSB | WAV | ✅ | PCM 采样域 ±1 LSB，感知代价 + STC | 无损音频 |
| `flac_residual` | FLAC Residual | FLAC | ✅ | 预测残差域匹配，**保持 Rice 码字长度** | 无损压缩音频；最慢 |

选型要点：

- **PNG/JPEG 里没有"最强"算法。** 它们的检测率取决于载体本身；换算法的收益通常小于降一档载荷率的收益。默认值（`hill` / `uerd`）在多数载体上不是最差选择。
- **HEVC 是唯一能保持体积不变的引擎**（Δ=0）。如果对手会比对文件大小，这是唯一有意义的选择。
- **FLAC 的代价是时间**：逐帧解析 + 码字长度保持验证，比 WAV 慢一个数量级（见 [BENCHMARK.md](../BENCHMARK.md)）。
- 算法 id 跨格式不通用。批量处理多种格式时只能选 `auto`，界面与 CLI 都会据此收敛。

## 3. 档位参数

三档不是"感觉"，是写死的数值：

| 参数 | `paranoid` | `high`（默认） | `balanced` | 出处 |
| :--- | ---: | ---: | ---: | :--- |
| 图像载荷率上限 `bpp_limit`（bit/像素） | 0.06 | 0.10 | 0.15 | `core/params.rs` `SafetyLevel::bpp_limit` |
| 候选/消息比 `target_ratio`（槽位 ÷ 比特） | 11.5 | 6.9 | 4.6 | `SafetyLevel::target_ratio`，按 DIV2K 校准 |
| 音频改动百分比 | 0.5 % | 1.5 % | 3.0 % | `stego/audio/core.rs` |
| HEVC 视频：非参考帧改动上限 | 10 % | 20 % | 40 % | `SafetyLevel::video_budget` |
| HEVC 视频：每帧参考帧翻转上限 | 110 | 220 | 450 | 同上 |

理解方式：

- `bpp_limit` 管"总量天花板"，`target_ratio` 管"为了 1 比特消息愿意改多少槽位"——**比值越大越保守**，所以 `paranoid` 的 11.5 比 `balanced` 的 4.6 更安全，容量也更小。
- 音频与 HEVC 用各自的百分比/配额，因为它们没有"像素"这个单位。
- 三档之间不是线性关系：`paranoid → high` 容量约 +67 %，`high → balanced` 再 +50 %，但检测风险的上升不是等比例的，越低档越值得。

## 4. 怎么选：一条决策路径

```text
载体是视频/HEIC？
├─ 是 → hevc（唯一选项），档位 high 起步；对手会看体积时必须用它
└─ 否
   ├─ 需要"原文件能位精确还原"？
   │   └─ 是 → 不是算法问题：用结构域 write（见 CLI_GUIDE），不要走隐写
   ├─ 载体是 FLAC/WAV？
   │   ├─ FLAC 且时间可接受 → flac_residual
   │   └─ 否则转 WAV → wav_pcm
   └─ 图像（PNG/JPEG）
       ├─ 载荷 ≤ 容量的 30 % → 默认算法 + high
       ├─ 载荷吃紧 → 先降载荷或换大图，再考虑 balanced
       └─ 载体是插画/截图等非自然图像 → 可试 suniward，档位不要提；纯色或极平滑图不适合隐写
```

## 5. 容量怎么估

粗估（仅用于判断"这个思路是否可能"，实际以 `capacity` 为准）：

```text
图像：容量字节 ≈ 宽 × 高 × bpp_limit ÷ 8
音频：容量字节 ≈ 采样数 × 声道 × 位深 ÷ 8 × 改动百分比
```

三个必须扣掉的开销：基础头（空间域 64B / JPEG 44B / HEVC 32B）、微头与 AEAD tag（`BODY_OVERHEAD = 22` 起）、文件名（`1 + name_len`）。此外还有工作内存预算这一硬上限，所以 `capacity` 报出的数才是"一定能写成"的数。见 [api/spec/CAPACITY.md](api/spec/CAPACITY.md)。

```bash
sth capacity photo.jpg                              # 默认档位
sth capacity photo.jpg --safety paranoid --json     # 最高安全档，机器可读
sth capacity video.mp4 --exact                      # 长视频默认抽样估算，--exact 全量
```

## 6. 三个常见误区

1. **"选最慢的算法最安全"。** 错。MiPOD 类算法在平滑载体上可能比 HILL 差；真正的变量是载荷率与载体选择。
2. **"同一张图多写几次更隐蔽"。** 错。重复写入会叠加改动，改动密度翻倍，检测率上升远快于容量收益。
3. **"`--enforce-safety` 让写入更安全"。** 它只保证"超限就报错"而不是"写得更隐蔽"；不加它时引擎会按实际容量写，可能悄悄退到更低档位。

## 7. 对检测的现实预期

没有任何档位能保证"检测不到"。可做的是把风险压到与同类工具相当的水平：

- 用纹理复杂的载体，避免大片天空、纯色背景、简单几何图形——改动在平滑区域更容易被统计发现；
- 载荷率停在 `high` 以内；
- 一个载体只写一次，写完不再做任何重编码；
- 需要"看不出是 strhide 写的"时，用 `--stealth`（结构域）或私有方言（[PRIVATE_BUILD.md](PRIVATE_BUILD.md)）——但注意它们**不降低统计检测率**；
- 需要更强的抗检测时，先读 [THREAT_MODEL.md](THREAT_MODEL.md) §7，确认你的对手是否真的在模型内。
