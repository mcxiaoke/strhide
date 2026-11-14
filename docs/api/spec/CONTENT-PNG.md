# PNG Content Domain: Slots, Costs, and Channels (V4)

This document specifies how PNG carriers (`format_id = 1`) select embedding slots, construct candidate sorting keys across three distinct cost models, and expand payload channels. The common envelope, 64-byte base header, TLVs, `locate_seed` / `perm_seed`, ChaCha12 / Fisher–Yates, and STC are specified in [CONTENT-ENVELOPE.md](CONTENT-ENVELOPE.md) §2–§7; elementary transcendental functions are defined in [DETMATH.md](DETMATH.md) and `rust/src/stego/detmath.rs:3-16`. All occurrences of `exp / ln / ln_1p / cos / log2` throughout this document refer strictly to that deterministic implementation, not host `libm`.

---

## 1. Scope and Stability

- Supported carriers: 8-bit, non-interlaced PNG images with color types 0 (grayscale), 2 (RGB), 4 (grayscale + alpha), or 6 (RGBA); interlaced PNGs, palette-indexed images, APNGs, and 16-bit PNGs are outside the scope of this specification (`rust/src/stego/png/engine.rs:92-95`, `:245-262`).
- **Immediate rejection of color types 0/2 carrying `tRNS` chunks**: For color types 0 and 2, a `tRNS` chunk specifies a single transparent color key (pixels matching this RGB/gray value are rendered fully transparent) rather than an alpha channel. Intra-class $\pm 1$ embedding modifications could unintentionally shift pixels into or out of the color key, turning transparent backgrounds opaque or hollowing out solid pixels. The parsing engine immediately rejects these with `UnsupportedFormat`, prompting users to convert to RGBA / Grayscale+Alpha or use structural domain `write` (`rust/src/stego/png/engine.rs:295-311`). `tRNS` on color types 4/6 represents true alpha values and is unaffected.
- **Bit-for-bit retention of trailing data after `IEND`**: All bytes following the `IEND` chunk (including its 4B CRC) to EOF are treated as non-chunk trailing data, captured into a `tail` buffer and appended byte-for-byte upon re-encoding (`engine.rs:118-121`, `:326-344`, `:794`, `:855`). Trailing data length is bounded by `MAX_TAIL_BYTES = 16 MiB`; exceeding this returns `CorruptedData` (`engine.rs:334-341`). This preserves digital signatures or watermarks appended after `IEND` by certain vendor workflows.
- `algorithm_id` values 1, 2, and 3 are permanently bound to `hill`, `suniward`, and `mipod` respectively; unrecognized IDs MUST NOT fall back to default models (`rust/src/stego/png/registry.rs:13-17`, `:57-64`; `rust/src/stego/png/engine.rs:2049-2050`).

| Tier | PNG Content Domain Scope |
| --- | --- |
| **F** | `format_id = 1`; `algorithm_id` 1/2/3; `channel_mode`, `class_rule`; `p1_window`, `p2_window`, `neg_log2_epsilon`, `exclusion_permille`, `sigma` (or `alpha` under MiPOD); header pool and slot layout; body candidate sorting and truncation; all three cost models and the lower 20-bit mantissa quantization in `fisher_to_costs` |
| **D** | None. This domain contains no extensible fields that readers may ignore; future cost models require new Tier F allocations |
| **I** | Directional costs, parallel / SIMD equivalent implementations, PNG re-encoding filters and Deflate parameters, outer retry loops; readers depend on none of these (§8) |

Prior to 1.0, Tier F specifications remain subject to adjustment; changes require rebuilding baselines via `scripts/baseline_hash.py`.

### 1.1 1.0 Freeze Rules (PNG Specific)

Tier F specifications in the PNG domain are **substantially more rigid** than those in JPEG, HEVC, or Audio, because the extraction engine MUST reconstruct the writer's cost map and candidate ordering bit-for-bit:

| Domain | Reader Reconstructs Cost Map? | Can Cost Models Be Optimized Without Breaking Carriers? |
| --- | --- | --- |
| PNG Spatial Domain | **Yes** (candidate truncation + global sorting) | **No** |
| JPEG Transform Domain | No (`stc_h`/`stc_u` self-describing + seeded permutation) | Yes |
| HEVC Compressed Domain | No (CABAC in-place syntax elements) | Yes |
| WAV / FLAC Audio Domain | No (per-frame parameter addressing) | Yes |

Consequently, upon 1.0 release:

- Every numerical step of `algorithm_id` 1, 2, and 3 (grayscale conversion, three-phase convolution, edge padding, `sigma` / `alpha`, lower 20-bit mantissa quantization in `fisher_to_costs`, and sorting comparison key construction order) is **permanently frozen**. Any numerical change under the guise of "optimization" or "bug fixing" will permanently render existing carriers unrecoverable;
- New cost models MUST only be introduced by allocating **new `algorithm_id`** values, keeping existing model semantics immutable;
- Permissible modifications are strictly limited to equivalent rewrites that **do not alter byte-level output** (SIMD, multi-threading, memory layout), and MUST pass all 28/28 test cases in `python scripts/baseline_hash.py --check` alongside real-carrier round-trip tests.

---

## 2. Input Parameters: Base Header as Authoritative Source

Writers quantize tuning parameters prior to embedding (`rust/src/stego/params.rs:210-236`); readers rely strictly on decoded base header fields, treating caller options as non-binding hints (`rust/src/stego/png/engine.rs:2060-2078`).

| Parameter | Location / Source | Reader Semantics |
| --- | --- | --- |
| `pixels, w, h, channels` | PNG Decoder | Row-major, interleaved channels, `channels ∈ {1, 2, 3, 4}` |
| `format_id` | Header byte 34 | MUST be 1 (`header.rs:271`, `:326-330`) |
| `algorithm_id` | Header byte 35 | 1 (HILL) / 2 (S-UNIWARD) / 3 (MiPOD), constrained to $1 \dots 3$ (`header.rs:332-336`) |
| `channel_mode` | Header byte 41 | 0 (Green) / 1 (RGB); all other values rejected (`header.rs:337-340`) |
| `class_rule` | Header byte 42 | 0 or 1; writer always passes 1, reader evaluates header value (`engine.rs:1721`, `:1359`, `:2141`) |
| `p1_window` / `p2_window` | Header 44:2 / 46:2 | Positive odd integers $1 \dots 63$; default 3 / 15 (`header.rs:280-281`; `params.rs:243-244`) |
| `neg_log2_epsilon` | Header 48:2 | $\text{epsilon} = 2^{-k}$, where $k \in [1, 127]$; default $k = 23$ (`header.rs:30-37`, `:282`; `params.rs:245`) |
| `exclusion_permille` | Header 50:2 | $0 \dots 900$; default 300 (`header.rs:283`; `params.rs:246`) |
| `sigma` | Header 52:4, f32le | Under S-UNIWARD: `sigma` (default 1.0); under MiPOD: `alpha` (default `0.20f32`), clamped by reader to $[0.01, 0.90]$ (`engine.rs:1678-1691`, `:2069-2077`; `mipod.rs:55`) |
| `codec_id / stc_h / stc_u` | Header 38 / 39 / 40 | Determines body slot count and coding; writer defaults to $h=8, u=0 \text{ (auto)}$ (`engine.rs:2107-2122`; `params.rs:247-249`). **$u = 0$ is a writer-only runtime enum value**: prior to header serialization, it MUST resolve to concrete $1 \dots 3$ (selected alongside `codec_id` via `auto_select_codec` against the body candidate pool, written to `wire_u` at `engine.rs:1727`); readers require that when `codec_id = 1`, $stc\_h \in [4, 10]$ and $stc\_u \in [1, 3]$; encountering $u = 0$ triggers `CorruptedData` (`header.rs:365-382`) |
| `locate_seed / perm_seed` | L2 / L3 Derivation | Header / Body permutation seeds ([CONTENT-ENVELOPE.md](CONTENT-ENVELOPE.md) §6) |
| `kernel_id` | Header byte 56 | MUST be 0 (built-in normalized KB filter, `hill.rs:15-22`) |

`p1 / p2` are checked via `PngParams::validate` to reject zero and even numbers (`params.rs:326-332`); direct trait calls also defensively normalize via $\max(1) \mid 1$ (`hill.rs:93-102`).

---

## 3. Pixels, Slots, and Channels

### 3.1 Header Channel `hc`

`hc = 1` when `channels >= 3`, otherwise `0` (`engine.rs:1046-1048`). For `channels = 2` (grayscale + alpha), `hc = 0`; alpha channels never participate in candidate selection.

### 3.2 Header Pool and Layout

The header candidate pool comprises all pixels satisfying $8 \le \text{pixels}[px \times \text{channels} + hc] \le 247$ sorted in ascending pixel order, independently of the cost map (`engine.rs:72-73`, `:1139-1153`). The pool is shuffled via `permute_prefix(pool, 512 + 8 * ext_len, locate_seed)` (`engine.rs:1193-1199`), where $k$ in prefix Fisher–Yates is clamped to $n - 1$ (`rust/src/stego/prng.rs:204-248`).

The base header occupies the first 512 slots; the extension region occupies 8 slots per byte (`header.rs:153-156`; `engine.rs:1281-1316`). Bit $j$ ($j=0$ is MSB) of byte $b$ is embedded into channel $hc$ of `header_slots[b * 8 + j]`; extension bits continue consecutively from index 512 (`engine.rs:1820-1852`). Readers first decode 512 slots with `ext_len = 0`, then resume the identical permutation based on the decoded `ext_len` (`engine.rs:2000-2018`). If $\text{carrier\_slots} < 512$ or $512 + 8 \times \text{ext\_len} > \text{carrier\_slots}$, the reader MUST return `NoHiddenData` (`engine.rs:1995-2013`).

### 3.3 Body Candidate and Slot Expansion

Body candidate pixels MUST first satisfy the identical $hc$ range condition, followed by sorting and truncation according to §4 (`engine.rs:1241-1279`). A slot represents a byte offset $\text{slot} = px \times \text{channels} + c$ (`engine.rs:1320-1326`, `:1354`).

Slots are visited in ascending order of candidate pixels, and within each pixel in ascending order of channels. If channel $hc$ of a pixel was already consumed by the header, that specific channel is skipped, while remaining channels of that pixel remain eligible (`engine.rs:1331-1334`, `:1348-1353`). Each evaluated channel MUST satisfy:

1. Pixel channel value $val \in [8, 247]$;
2. When `class_rule == 1`, $val \bmod 8 \in [1, 6]$.

Otherwise, the slot is skipped (`engine.rs:1354-1361`). Writers always pass `class_rule = 1` (`engine.rs:1721`, `:1742`); readers inspect the header value, where only `0` bypasses rule 2 (`engine.rs:1359`, `:2141`). `class_rule = 1` excludes $r = 0, 7$; $r = 1$ allows $+1$ only; $r = 6$ allows $-1$ only; $r \in [2, 5]$ allows both directions (`rust/src/stego/coding.rs:376-382`).

After gathering the first `needed_body_slots` slots, `permute_indices(body, perm_seed)` is applied; element $i$ of the permuted array represents the $i$-th body slot (`engine.rs:1738-1744`, `:1857-1859`). `needed_body_slots` is determined by $\text{body\_len} \times 8$ and codec parameters `codec / h / u` (`engine.rs:2117-2122`).

### 3.4 Channel Modes

| `channel_mode` | `channels >= 3` | `channels < 3` | Semantics |
| --- | --- | --- | --- |
| 0 (Green) | `[1]` | `[0]` | Single channel ($hc$ only) |
| 1 (RGB) | `[0, 1, 2]` | Unsupported | R/G/B; Alpha is never touched |

(`engine.rs:1050-1091`). Unrecognized or unsupported modes MUST return `NoHiddenData` (`engine.rs:2100-2105`). Writers prioritize Green mode, upgrading to RGB mode only if payload exceeds single-channel capacity and `channels >= 3` (`engine.rs:1562-1636`).

---

## 4. Candidate Sorting and Truncation

```text
eligible = { px | 8 <= pixels[px * channels + hc] <= 247 }       // Sorted by ascending pixel index
ranked   = [(cost[px].to_bits(), px) for px in eligible]
allowed  = len(ranked) * (1000 - exclusion_permille) / 1000       // usize integer division, truncating towards zero
candidates = first allowed elements of ranked, ordered ascendingly by (cost.to_bits(), px)
```

The integer truncation formula is an immutable part of the wire specification; evaluating as floating-point `len * (1.0 - p / 1000.0)` produces off-by-one discrepancies (`engine.rs:1263-1273`). When `allowed < len`, the array is partitioned via `select_nth_unstable(allowed_count)`, truncated, and the prefix is sorted; when `allowed == len`, the entire array is sorted; when `allowed == 0`, candidates are empty (`engine.rs:1274-1279`). The tuple `(cost.to_bits(), px)` defines a total order, ensuring that prefix selection yields bit-for-bit identical results to global sorting; ties are broken by ascending pixel index (`engine.rs:1248-1261`). Costs across all three built-in models are non-negative and finite (inactive MiPOD pixels yield 0); lexicographical ordering of `to_bits()` matches numerical ordering without NaNs (`cost_calibration.rs:202-205`).

---

## 5. HILL (`algorithm_id = 1`)

### 5.1 Grayscale Conversion and Padding

```text
class_value(v) = v & 0xF8
channels == 1 : gray[i] = class_value(pixels[i])
channels >= 3 : r = class_value(pixels[i * channels]); g = class_value(pixels[i * channels + 1])
                b = class_value(pixels[i * channels + 2])
                gray[i] = 0.299 * r + 0.587 * g + 0.114 * b          // Left-associative
channels == 2 : gray[i] = class_value(pixels[i * channels])
```

Reference: `hill.rs:56-77`; `class_value` at `hill.rs:231-237`. All three RGB channels clear their lower 3 bits prior to weighting, ensuring that intra-class $\pm 1$ modifications preserve cost maps bit-for-bit (`hill.rs:56-66`).

```text
pad = 1 + (p1 - 1) / 2 + (p2 - 1) / 2                    // Integer division
reflect_index(t, n): n <= 1 -> 0; period = 2n; t = t.rem_euclid(period)
                     t >= n -> period - 1 - t; otherwise t
X[i][j] = gray[reflect_index(i - pad, h)][reflect_index(j - pad, w)]
```

`pad` reference: `hill.rs:103`; `reflect_index` / `pad_symmetric`: `hill.rs:264-293`. Padded output spans exactly $w \times h$ (`hill.rs:170-178`).

### 5.2 Three-Phase Exact Summation Order

```text
hp = h + 2 * pad, wp = w + 2 * pad, h1 = hp - 2, w1 = wp - 2
K = [-0.25, 0.50, -0.25, 0.50, -1.00, 0.50, -0.25, 0.50, -0.25]

Phase 1: I1[i][j] = | K0 * X[i][j]     + K1 * X[i][j+1]   + K2 * X[i][j+2]
                    + K3 * X[i+1][j]   + K4 * X[i+1][j+1] + K5 * X[i+1][j+2]
                    + K6 * X[i+2][j]   + K7 * X[i+2][j+1] + K8 * X[i+2][j+2] |
                    // Strictly left-to-right K0..K8, followed by abs()

Phase 2: l1 = 1.0 / (p1 * p1); h2 = h1 - (p1 - 1); w2 = w1 - (p1 - 1)
  sum = 0.0
  for u in 0..p1-1: sum += Σ_{v=0..p1-1} I1[i+u][j+v]    // Inner loop v ascending
  avg = sum * l1                                          // Sum first, multiply after
  I2[i][j] = 1.0 / avg.max(eps)
  eps = epsilon (> 0 and finite), otherwise 1e-12

Phase 3: l2 = 1.0 / p2
  Vertical:   T[i][j] = Σ_{u=0..p2-1} ( I2[i+u][j] * l2 )       // Multiply each term first, u ascending
  Horizontal: C[i][j] = ( Σ_{v=0..p2-1} T[i][j+v] ) * l2         // Sum first, v ascending, multiply after
```

Filter kernel $K$ is given in `hill.rs:15-22`; Phase 1 9-term sequence in `hill.rs:112-128`; Phase 2 in `hill.rs:131-151`; Phase 3 asymmetry ("vertical multiply-first, horizontal multiply-after") in `hill.rs:154-176`. This asymmetry is normative; unifying evaluation alters least significant bits and perturbs sorting. Wire `epsilon = 2^-k`, with $k = \text{round}(-\log_2(\text{epsilon}))$ bounded to $1 \dots 127$ (`header.rs:30-37`), defaulting to $2^{-23}$ (`params.rs:245`).

---

## 6. S-UNIWARD (`algorithm_id = 2`)

### 6.1 Plane and Filter Coefficients

Luminance plane derivation matches HILL: single channel $p \& 0\text{xF8}$; RGB channels masked with $\& 0\text{xF8}$ and weighted by $0.299 / 0.587 / 0.114$; two-channel images take the first channel (`suniward.rs:91-110`).

```text
hpdf = [-0.0544158422,  0.3128715909, -0.6756307363,  0.5853546837,
         0.0158291053, -0.2840155430, -0.0004724846,  0.1287474266,
         0.0173693010, -0.0440882539, -0.0139810279,  0.0087460940,
         0.0048703530, -0.0003917404, -0.0006754494, -0.0001174768]
lpdf[i] = (-1)^i * hpdf[15 - i]
bands = [(lpdf, hpdf), (hpdf, lpdf), (hpdf, hpdf)]       // Horizontal, Vertical, Diagonal
```

Filter coefficients: `wavelet.rs:23-40`; `lpdf`: `wavelet.rs:42-53`; `TAPS = 16, HALF = 8`: `wavelet.rs:55-59`; band order: `wavelet.rs:61-68`.

### 6.2 Residuals and Suitability

For each band $(f_1, f_2)$, evaluate horizontally then vertically:

```text
Residual Horizontal:    tmp[y][x] = Σ_{b=0..15} f2[b] * plane[y][clamp(x - b + 8, 0, w - 1)]
Residual Vertical:      R[y][x]   = Σ_{a=0..15} f1[a] * tmp[clamp(y - a + 8, 0, h - 1)][x]
W[y][x] = 1.0 / (|R[y][x]| + sigma)

Suitability Horizontal: tmp2[y][x] = Σ_{b=0..15} |f2[b]| * W[y][clamp(x + b - 8, 0, w - 1)]
Suitability Vertical:   cost[y][x] += Σ_{a=0..15} |f1[a]| * tmp2[clamp(y + a - 8, 0, h - 1)][x]
```

Residual evaluation processes horizontal index $b$ ascendingly; vertical target rows are zeroed first, processing $a$ ascendingly while skipping zero taps (`suniward.rs:159-184`). Suitability processes horizontal $b$ ascendingly; vertical $a$ ascendingly, skipping zero taps and accumulating into `cost` (`suniward.rs:205-230`). Boundaries clamp to edge pixels rather than zero-padding. `sigma = model_option("sigma", 1.0).max(f64::MIN_POSITIVE)` (`suniward.rs:57-62`, `:112-114`); readers extract the f32 from the base header (`engine.rs:2069-2072`). Default is 1.0 (academic literature value of $2^{-6}$ is unsuitable for 8-bit spatial domains). Band accumulation order MUST be $(l, h)$, $(h, l)$, $(h, h)$ (`suniward.rs:122-133`). Residual calculation uses reversed kernels while suitability uses forward kernels; mirroring either prices opposite edges incorrectly (`suniward.rs:139-149`, `:187-195`).

---

## 7. MiPOD (`algorithm_id = 3`)

### 7.1 Plane, Wiener Residual, and Local Variance

Plane preparation matches §6.1 (`mipod.rs:112-136`). Variance pipeline:

1. **Wiener Residual**, fixed window $w = 2$ (`mipod.rs:44-50`). Even window anchors at top-left (`spatial_variance.rs:93-113`):

   ```text
   sum = 0; sum_sq = 0
   for dy in 0..1: sy = y + dy; skip if out of bounds (zero-padding)
     for dx in 0..1: sx = x + dx; skip if out of bounds
       sum += z[sy][sx]; sum_sq += z[sy][sx]^2
   mu = sum / 4; v = max(0, sum_sq / 4 - mu^2)
   ```

   Global noise estimate: $\text{noise} = (\sum_y \sum_x v) / n$, evaluated in row-major order; if $\text{noise} \le 0$, residuals are zeroed (`spatial_variance.rs:117-154`). Final residual: $r = \text{diff} \cdot \min(1, \text{noise}/v)$, implemented as $v > \text{noise} \mathbin{?} (\text{noise}/v) \cdot \text{diff} \mathbin{:} \text{diff}$ (`spatial_variance.rs:159-165`).

2. **Local Cosine Complement Space**, $p = 9, \text{degree} = 9, q = 45, \text{dof} = 81 - 45 = 36$ (`mipod.rs:43-50`; `spatial_variance.rs:396-397`). DCT-II basis:

   ```text
   φ0(a) = sqrt(1/9) * cos(π * 0 * (2a + 1) / 18)
   φk(a) = sqrt(2/9) * cos(π * k * (2a + 1) / 18)
   ```

   (`spatial_variance.rs:79-91`). Horizontal projection: $H[y][x][kv] = \sum_{a=0}^8 \phi_{kv}(a) \cdot r[y][\text{reflect}(x + a - 4, w)]$, with $a$ ascending (`spatial_variance.rs:169-206`). For each $(y, x)$:

   ```text
   norm = 0
   for kv in 0..8:                                  // Ascending
     vals[a] = H[mirror(y + a - 4)][x][kv], a = 0..8
     for ku in max(9 - kv, 0)..8:                   // Ascending, i.e., ku + kv >= 9
       proj = Σ_{a=0..8} φ_ku(a) * vals[a]          // a ascending
       norm += proj^2
   ```

   (`spatial_variance.rs:240-264`). $\sigma^2 = \max(0.01, \text{norm} / \text{dof})$ (`spatial_variance.rs:366-405`).

### 7.2 Fisher Information and 7×7 Smoothing

```text
I[y][x] = 2.0 / (sigma2[y][x] * sigma2[y][x])
smoothed = box_smooth(I, w, h, 7)
```

Reference: `mipod.rs:95-99`. Box filtering applies mirrored indexing, horizontally then vertically with $d \in [-3, 3]$ ascending, summing first before multiplying by $1/7$; when windows exceed dimensions, individual indices reflect symmetrically (`spatial_variance.rs:408-489`).

### 7.3 Fisher Information to Additive Costs

`alpha` represents target embedding payload (bits per pixel), default `0.20f32`, extracted from header `sigma` and clamped to $[0.01, 0.90]$ (`mipod.rs:25-34`, `:101-107`; `engine.rs:2069-2077`). $\text{target\_bits} = \alpha \cdot w \cdot h$ (`mipod.rs:107`).  
`fisher_to_costs` execution pipeline (`cost_calibration.rs:206-338`):

1. $u_n = \ln(I_n)$ when $I_n$ is finite and $> 0$, otherwise $-\infty$; tally `active / min_log / max_log`. If $\text{active} == 0$, $\text{target\_bits} \le 0$, or non-finite $\to$ return all zeros.
2. $\text{capacity} = \text{active} \cdot \text{LN\_3}$; $\text{target} = \min(\text{target\_bits} \cdot \text{LN\_2}, \text{capacity} \cdot 0.999)$; if $\text{target} \le 0 \to$ return all zeros.
3. Histogram over $\text{BINS} = 32768$; $\text{span} = \max(\text{max\_log} - \text{min\_log}, 10^{-12})$, $du = \text{span} / 32768$, $\text{inv\_du} = 1 / du$; bin index is $\min(\lfloor (u - u_{\min}) \cdot \text{inv\_du} \rfloor, 32767)$, tallying finite terms only (`cost_calibration.rs:106-148`).
4. Total entropy evaluated in ascending bin order: $x = \exp(\min(t + \text{center}(i), 690))$, where $\text{center}(i) = u_{\min} + (i + 0.5) \cdot du$, $\rho = \text{solve\_rho}(x)$, $\text{sum} \mathrel{+}= \text{count} \cdot H_3(\rho)$ (`cost_calibration.rs:150-167`).
5. Root bracketing: $t_{\text{lo}} = -\text{max\_log} - 30$, decrementing by 10 while $F \le 0$ up to 100 times; $t_{\text{hi}} = -\text{min\_log} + 5$, incrementing by 10 while $F \ge 0$ up to 100 times; failure returns all zeros (`cost_calibration.rs:259-285`).
6. Illinois method: $\text{tol} = 10^{-12} \cdot \max(\text{target}, 1.0)$, up to 80 iterations; secant estimate $c = (a \cdot f_b - b \cdot f_a) / (f_b - f_a)$ (defaults to midpoint if denominator is zero); clamp $c$ to midpoint if out of bounds; terminate when $|f_c| \le \text{tol}$ or $|b - a| \le 10^{-14} \cdot (1 + \max(|a|, |b|))$; halve opposing function value when step remains on same side (`side == -1` halves $f_a$, `side == 1` halves $f_b$) (`cost_calibration.rs:287-326`).
7. Interpolation table with 32769 entries: $u = u_{\min} + i \cdot du$, $\text{table}[i] = \text{solve\_rho}(\exp(\min(t + u, 690)))$ (`cost_calibration.rs:169-177`). Per-element evaluation: $\text{pos} = (u - u_{\min}) \cdot \text{inv\_du}$; if $\text{pos} \le 0$, take $\text{table}[0]$; $j = \lfloor \text{pos} \rfloor$; if $j \ge 32768$, take $\text{table}[32768]$; otherwise interpolate $\text{table}[j] + (\text{table}[j+1] - \text{table}[j]) \cdot (\text{pos} - j)$ (`cost_calibration.rs:179-192`).
8. Non-finite $u$ receive cost 0; remaining entries are interpolated and quantized (`cost_calibration.rs:328-337`).

```text
solve_rho(x): x = min(x, 1e300); if x <= 0 or NaN -> return 0
  rho = ln_1p(x)
  repeat 32 times:
    e = exp(rho); f = rho * (e + 2) - x; df = e * (1 + rho) + 2
    next = max(rho - f / df, 0)
    if |next - rho| <= 1e-14 * (1 + next) return next; else rho = next

H3(rho): if rho <= 0 -> LN_3 = 1.0986122886681098
  otherwise:
    lm = ln_1p(2 * exp(-rho)); l = rho + lm
    beta = exp(-l); p0 = exp(-lm); H3 = 2 * beta * l + p0 * lm
```

Reference: `solve_rho` in `cost_calibration.rs:63-81`; `H3` in `cost_calibration.rs:90-104`.

### 7.4 Quantization and Cross-Platform Verification

`quantize_cost` clears the lower 20 mantissa bits on finite positive values: `from_bits(bits & !((1 << 20) - 1))`; zero, negative, and non-finite values are returned unmodified (`cost_calibration.rs:340-379`), yielding a relative quantum of $2^{-32}$. Quantization is monotonic, never reversing relative ordering, but may map distinct nearby costs to identical values, broken by pixel index.

Empirical verification (`cost_calibration.rs:340-358`): Windows / UCRT and Ubuntu / glibc match bit-for-bit on $\sigma^2$, $I_n$, and 7×7 smoothed maps. Divergences occur only in post-Newton $\rho$ values up to 255 ulp (relative to $2^{-44}$). Clearing the lower 20 bits brings 12/12 synthetic image matrix tests into bit-for-bit alignment and preserves all 28 real-world baseline test cases. Residual risk: if values cross a bin boundary across platforms, a discrepancy of one quantum may occur (estimated at $\approx 4 \times 10^{-5}$ per element), guarded by cross-platform CI. Modifying mantissa quantization bits alters candidate sets and STC trellis decisions, constituting a Tier F change requiring baseline regeneration.

---

## 8. Writer-Only Non-Normative Implementation Details (Tier I)

The following details govern writer output only and are not evaluated by readers; implementations may substitute them freely, provided they do not alter candidate inputs or sorting results defined in §3–§7.

- **Directional Costs**: HILL computes local 8-neighborhood class-masked average `mean`, weighting requested slots by $\text{base} \cdot (1 + 4 \cdot ((v \pm 1 - \text{mean}) / 255)^2)$ (`hill.rs:181-262`). S-UNIWARD and MiPOD return `(base, base)` (`rust/src/stego/traits.rs:62-76`). Directional costs govern the $\pm 1$ choice only, without affecting candidate sorting (`engine.rs:1746-1756`).
- **Parallel / SIMD Equivalence**: The reference implementation parallelizes row-wise (`hill.rs:112-176`, `suniward.rs:159-230`), writing rows independently in ascending order; SIMD or multi-threaded alternatives MUST reproduce the summation order of §5–§7 exactly to prevent perturbing `to_bits()` order.
- **PNG Re-encoding**: Readers consume decoded pixel arrays only; writers reuse original scanline filter types and select Deflate compression levels targeting original file sizes (`engine.rs:108-115`, `:650-706`), neither of which impacts slot generation or cost maps.
- **Retries**: PNG embedding is single-pass (`engine.rs:1818-1886`); if outer callers re-roll salt/nonce, the entire embedding pipeline is re-evaluated, and readers interpret the final serialized header values.

---

## 9. Self-Verification and Test Vectors

MiPOD stage-by-stage test vectors: `docs/api/cost-vectors.json` defines a 32×32 RGB test input accompanied by five FNV-1a digests (`plane / variance / fisher / smoothed / cost`), specified on lines 1–9 and in `mipod.rs:292-358`; verified via Rust test `cost_vector_digests_are_pinned` (`mipod.rs:360-383`).

```bash
cargo test --all-features --lib cost_vector_digests_are_pinned
python scripts/cost_vectors_check.py            # stage 4 is normative; 0-3 are diagnostic
python scripts/cost_vectors_check.py --strict   # fails if intermediate stages diverge
```

Model invariants and numerical regression checks:

```bash
cargo test --all-features --lib png::cost
cargo test --all-features --lib spatial_variance
cargo test --all-features --lib cost_calibration
python scripts/baseline_hash.py --check
```

- HILL: `cost_map_is_invariant_under_class_internal_moves`, `direction_costs_follow_the_local_mean` (`hill.rs:331-410`).
- S-UNIWARD: `cost_map_is_invariant_under_class_internal_moves`, `suitability_reads_the_side_the_residual_lands_on` (`suniward.rs:333-403`).
- MiPOD: `cost_map_is_invariant_under_class_internal_moves`, `reference_payload_does_not_reorder_costs` (`mipod.rs:197-265`).
- Variance / Smoothing: `separable_complement_equals_explicit_projector`, `box_smooth_matches_naive_reflection_bit_identically` (`spatial_variance.rs:586-762`).
- Calibration: `quantise_cost_is_monotone_and_absorbs_ulp_noise`, `calibration_is_deterministic_across_thread_counts` (`cost_calibration.rs:388-561`).

HILL and S-UNIWARD do not maintain isolated frozen numerical vectors; their conformance is validated by the invariant tests above and the 28 byte-level baseline cases in `scripts/baseline_hash.py`. MiPOD's numerical contract is governed by the five pinned digests in §9.
