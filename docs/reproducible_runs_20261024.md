# 可复现嵌入

- 日期：2026-10-24
- 一句话：`Freshness::Seeded` 把 salt/nonce 变成可注入的确定值，配上确定性 payload，同一组输入产出同一个 stego 文件。

## 改了什么

| 位置 | 内容 |
| :--- | :--- |
| `stego/envelope.rs` | 新增 `Freshness` 枚举：`Random`（默认）/ `Seeded([u8; 32])`，带 `salt(attempt)` / `nonce(attempt)` |
| `stego/params.rs` | `StegoOptions.freshness` 字段；`JpegParams.deterministic` 字段（`#[serde(skip)]`） |
| `stego/mod.rs` | `embed_carrier` 把 `freshness` 传给引擎，并在 seeded 时置 `deterministic = true` |
| `stego/jpeg/engine.rs` | 新增 `embed_jpeg_with_freshness`；`embed_jpeg` 保持原签名，内部走 `Random` |
| `stego/spatial/engine.rs` | 新增 `embed_spatial_with_profile_and_freshness`；原有两个入口保持不变 |
| `stego/prng.rs` | 新增 `deterministic_payload(len, seed)` |
| `examples/repro_embed.rs` | 单次可复现嵌入 + 往返校验 + 打印 sha256 |
| `examples/repro_suite.rs` | 载体矩阵指纹清单，支持 `--check` 比对基线 |
| `tests/reproducible.rs` | 5 个测试锁住契约（JPEG/PNG 各一、不同 seed 不同、默认仍随机、生成器稳定） |

盐和 nonce 的派生：`HKDF-SHA256(seed, info = label || attempt)`，`label` 是 `"salt"` 或 `"nonce"`。
JPEG 侧一次嵌入最多重试 6 次，每次的 salt 由 `(seed, attempt)` 决定，所以重试序列本身也是确定的。

## 代码里怎么用

```rust
use strhide::stego::{embed_carrier, extract_carrier, Freshness, StegoOptions};
use strhide::stego::prng::deterministic_payload;

let payload = deterministic_payload(4096, 1);   // 4 KiB 固定字节，跨平台一致

let options = StegoOptions {
    freshness: Freshness::Seeded([7u8; 32]),
    ..Default::default()
};
let stego = embed_carrier(&carrier_bytes, &payload, &options)?;

// 提取端不需要知道 seed，salt 在 superblock 里
let back = extract_carrier(&stego, &StegoOptions::default())?;
assert_eq!(back, payload);
```

走底层入口时用新函数：

```rust
jpeg::embed_jpeg_with_freshness(&carrier, &payload, pwd, domain, fmt, &params, &model, freshness)?;
spatial::embed_spatial_with_profile_and_freshness(&png, &payload, pwd, domain, sp, &model, &params, freshness)?;
```

## 命令行怎么用

```bash
# 一次嵌入，打印 stego 的 sha256
cargo run --release --example repro_embed -- temp/testhighres/img24mp.jpg \
  --bytes 4096 --seed 1

# 存下 stego，方便逐字节比较
cargo run --release --example repro_embed -- cover.jpg --algo juniward --out out.jpg

# 打指纹清单（载体 × payload 尺寸 × 算法）
cargo run --release --example repro_suite -- temp/testhighres \
  --sizes 512,1024,16384 --algo uerd,juniward --out baseline.json

# 比对基线，漂移返回非零退出码
cargo run --release --example repro_suite -- temp/testhighres \
  --sizes 512,1024,16384 --algo uerd,juniward --check baseline.json
```

`--check` 输出 `DRIFT / NEW / GONE` 三类差异，逐项打印 baseline 与当前值。

## 排查流程

1. 复现：`repro_embed` 跑一次，记下 sha256。
2. 定范围：`repro_suite` 生成清单，看是单个载体、某种载荷，还是某个算法出问题。
3. 改完再 `--check` 同一份清单，确认只有预期内的条目变了。

比"重跑一次有时候过有时候不过"省事的地方在于：失败会稳定复现，`DRIFT` 清单直接指出影响面。

## 几个需要注意的事实

**seeded 模式会强制标量内核。** AVX2 的 `fmadd` 只舍入一次，标量路径 `mul + add` 舍入两次，
两者在 cost 值的最后一位可能不同，足以让 STC 的近并列项翻向另一边。
`embed_carrier` 在 seeded 时自动设 `JpegParams::deterministic = true`；
直接调 `embed_jpeg_with_freshness` 时要自己设。代价是 JPEG 代价图慢约 3 倍（24 MP 约 0.3 s → 1.1 s），
对测试足够。

**复现范围。** 同一 `git` 版本 + 同一 target triple 内成立。跨架构（x86_64 ↔ aarch64）、
跨版本（改过成本模型、`flate2` 后端、STC 分组策略）都会变，所以清单里带了版本和 git 哈希。

**seeded 只用于测试和回归。** 生产载荷走 `Freshness::Random`。固定 salt 会让同一密钥下的
nonce 复用，GCM 的语义就不成立了。

## 相关文件

```
rust/src/stego/envelope.rs          Freshness, salt/nonce 派生
rust/src/stego/prng.rs              deterministic_payload
rust/src/stego/params.rs            StegoOptions.freshness, JpegParams.deterministic
rust/examples/repro_embed.rs        单次复现
rust/examples/repro_suite.rs        指纹清单与比对
rust/tests/reproducible.rs          契约测试
```
