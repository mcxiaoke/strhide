# JPEG Content Domain Specification (V4)

This document specifies the slot geometry, ternary STC interface, and three cost models for the JPEG content domain (`format_id = 4`) for independent third-party implementations. Envelopes, header byte layouts, AAD, ChaCha12, Fisher–Yates, STC matrix generation, and KDF are defined in [CONTENT-ENVELOPE.md](CONTENT-ENVELOPE.md); bit-for-bit evaluation rules for DCT transcendental functions are defined in [DETMATH.md](DETMATH.md). This document focuses exclusively on JPEG-specific specifications.

---

## 1. Scope and Stability Tiers

Complete Reader Execution Path: JPEG decode extracts quantized DCT coefficients interleaved across MCUs for each component (`rust/src/stego/jpeg/engine.rs:223-231`) $\to$ component 0 is extracted exclusively to compute the cover digest (`:238-261`) $\to$ locate header slots $\to$ decode 44B superblock $\to$ decode extension region $\to$ derive body slots via keyed permutation $\to$ extract coefficient LSBs for ternary STC syndrome decoding. Cost models, directional bias, re-encoding, and retries play no role in reading.

**Carrier Admission Criteria (Enforced during probing and embedding; violations return `UnsupportedFormat`)**:

- **Baseline JPEG (SOF0) Exclusively**: SOF2 / progressive JPEGs are rejected immediately, prompting conversion to Baseline or routing to structural domain `write` (`engine.rs:68-75`).
- **Component Count MUST be 1 (Grayscale) or 3 (YCbCr)**: 4-component CMYK is rejected because slot grids, luminance cost tables, and `components_mask` assume a single luminance plane or Y/Cb/Cr; otherwise chrominance components would be modulated as luminance (`engine.rs:118-128`).
- **Three Hard Pipeline Limits**: `MAX_JPEG_MCU_COUNT = 1,048,576`, `MAX_JPEG_TOTAL_BLOCKS = 6,291,456`, and pipeline working set `MAX_PIPELINE_BYTES = 8 GiB` (`engine.rs:86-100`, evaluated at `:151-166`). The first two limits are shared identically between capacity probing and embedding to prevent divergent decisions.

| Tier | JPEG Domain Scope |
| :--- | :--- |
| **F** | 44B superblock fields and CRC; base header 718 slots and extension slot formulas; component 0 / MCU block ordering; Grid and flat indexing; prefix Fisher–Yates; body slots $body\_n = u \cdot (bits + h - 1)$; parity mapping $c \& 1$ and carrier $2 \mid parity$; STC syndrome decoding; $codec\_id = 0$ |
| **D** | `JpegFormatProfile` configuration ($sb\_h / sb\_u / ext\_h / ext\_u / grid\_rule$) and KDF labels; official builds fix these to this document's constants; substituting them yields an isolated dialect (`rust/src/stego/format.rs:115-148`, `:238-249`) |
| **I** | Cost model selection and tuning constants; directional bias and `polarize_weight`; re-encoding implementation; deterministic switches; retry attempts; Deflate compression levels; `slot_budget` / capacity policy |

Tier I items govern which coefficients are modified. Any ternary modification set satisfying the identical syndrome equation decodes correctly; third-party writers may utilize alternative cost models or search heuristics. To reproduce repository test baselines bit-for-bit, §§4–8 MUST be implemented verbatim.

---

## 2. Superblock Fields Required for Third-Party Readers (Tier F)

The 44B superblock layout: `rust/src/stego/jpeg/header_v4.rs:1-16`, encoding: `:74-89`, decoding: `:92-169`.

| off:size | Field | Type | Reader Validation |
| :--- | :--- | :--- | :--- |
| 0:1 / 1:1 | version / flags | u8 | major MUST be 4; flags permits bits 0 and 1 only |
| 2:2 | suite_id | u16be | Known AEAD suite (1 or 2) |
| 4:16 / 20:12 | salt / nonce | — | L3 salt; AEAD nonce |
| 32:4 | body_len | u32be | $22 \dots 2^{26}-1$, ciphertext length including 16B tag |
| 36:1 | codec_id | u8 | MUST be 0 (ternary STC) |
| 37:1 | stc_h | u8 | $4 \dots 10$ |
| 38:1 | stc_u | u8 | $1 \dots 64$ (JPEG-specific wide parameter) |
| 39:1 | ext_len | u8 | $0 \dots 255$; MUST match `FLAG_EXT_PRESENT` |
| 40:4 | crc32 | u32be | CRC32-IEEE over bytes[0..40] |

Implicit carrier properties: `format_id = 4`, luminance component modulation only, no Hamming path (`header_v4.rs:43-70`). The superblock is decoded via STC from the first 718 header slots (§3).

---

## 3. Slot Geometry (Tier F)

### 3.1 Blocks and Coefficient Indexing

`block_count = coeffs.components[0].blocks.len()`, which includes MCU padding blocks rather than visible pixel blocks alone (`engine.rs:223-231`). Blocks are ordered in **MCU-interleaved order**, not per-component raster order (`positions` in `rust/src/stego/jpeg/geometry.rs` are generated via MCU iteration). Within each block, coefficients follow natural row-major order: $k = 0$ is DC, and $k = 1 \dots 63$ are AC.

The official `GridRule::ALL_AC` defines $k_{\min} = 1, k_{\max} = 63$ (`format.rs:55-58`). Flat slot index is $idx = bi \times slots\_per\_block + (k - k_{\min})$, where $slots\_per\_block = k_{\max} - k_{\min} + 1$; officially, $Grid = \{ bi \times 63 + (k - 1) \mid 0 \le bi < block\_count, 1 \le k \le 63 \}$ (`rust/src/stego/jpeg/v3_layout.rs:29`, `:134-143`, `:196-200`). DC coefficients never enter the grid: they serve as input to the cover digest for header locating KDF and MUST remain invariant (`format.rs:39-51`).

### 3.2 Header and Extension Slots

$hdr\_n = sb\_u \cdot (sb\_bytes \cdot 8 + sb\_h - 1) + ext\_u \cdot (8 \cdot ext\_len + ext\_h - 1)$. Under official defaults ($sb\_bytes = 44, sb\_h = 8, sb\_u = 2, ext\_h = 8, ext\_u = 4$): base header requires $2 \cdot (352 + 7) = 718$ slots; extension requires $4 \cdot (8 \cdot ext\_len + 7) = 32 \cdot ext\_len + 28$ slots (`format.rs:156-169`, `:238-249`). **Even when $ext\_len = 0$, the extension region occupies 28 slots**, resulting in $hdr\_n = 746$ (general formula $746 + 32 \cdot ext\_len$; `CONTENT-ENVELOPE.md:116`, `engine.rs:833`).

1. `slots_buf = grid_indices(block_count, grid_rule)`, generated in ascending order of flat indices (`v3_layout.rs:134-143`).
2. `permute_prefix(slots_buf, hdr_n, locate_seed)`: Executes the first $hdr\_n$ steps of forward Fisher–Yates over the entire Grid, taking the first $hdr\_n$ entries as header slots (`engine.rs:856-858`; `prng.rs:219-248`). Forward swapping ensures prefix stability, enabling readers to compute $hdr\_min = header\_slots(0)$ to decode the superblock before extending the permutation to actual $hdr\_n$ (`engine.rs:1257-1269`).
3. Header slots $[0, 718)$ carry 352 bits decoded via $\text{STC}(sb\_h = 8, sb\_u = 2)$; $[718, hdr\_n)$ carry $8 \cdot ext\_len$ bits decoded via $\text{STC}(ext\_h = 8, ext\_u = 4)$ (`engine.rs:951-1003`). When $ext\_len = 0$, the trailing 28 slots are unwritten but remain reserved, never allocated to body data.
4. $BodyGrid = Grid \setminus HdrSlots$, constructed in ascending order of flat indices (via sorted exclusion, prohibiting hash-set ordering; `v3_layout.rs:146-193`).
5. $bits = 8 \cdot body\_len$; $window = bits + stc\_h - 1$; $body\_n = u \cdot window$ (`v3_layout.rs:98-108`).
6. `permute_prefix(BodyGrid, body_n, perm_seed)`, then truncated to $body\_n$ (`engine.rs:1007-1008`, `:1330`). This generates a "uniformly random ordered sample of the full BodyGrid", **NOT a selection based on sorted costs**; legacy descriptions suggesting "select $N$ candidates then permute" are incorrect (`v3_layout.rs:22-24`).

Writers select $u = \min(\lfloor body\_grid\_len / window \rfloor, \lfloor slot\_budget / window \rfloor, 64) \ge 1$; `slot_budget` is a Tier I performance tuning knob (`v3_layout.rs:98-107`). Readers evaluate the superblock's `stc_u` directly and verify capacity (`v3_layout.rs:60-68`).

### 3.3 Parity Mapping

```text
parity(c)  = c & 1              // 0 or 1
carrier(c) = 2 | parity(c)      // Writer ternary alphabet 2 or 3
```

Writers submit `2 | parity` into STC encoding, then apply $\delta \in \{-1, 0, +1\}$ modifications to original coefficients (`engine.rs:278-298`, `:482-483`). Readers extract `(c & 1)` directly, without distinguishing between 2 and 3 (`engine.rs:1405-1410`).

---

## 4. Candidates, Sorting, and Ternary STC (Tier F/I)

JPEG features **NO cost-based candidate sorting** and **NO `exclusion_permille`**: the 44B superblock contains no such field, and the engine never parses one. The sequence of body slots is governed strictly by the permutation in §3.2; costs feed exclusively into STC trellis edge weights. Consequently, costs in §§4–7 are Tier I; candidate sorting keys and PNG-style `exclusion_permille` truncation MUST NOT be applied to JPEG.

- The cost array is indexed via $bi \times 64 + k$, allocating 64 entries per block; DC entries are fixed to `wet_cost`.
- `plan_slots` clamps costs to $\min(cost, wet\_cost)$ and splits directional costs: when bias $> 0$, the plus cost is $base \cdot polarize\_weight$ and minus cost is $base$; when bias $< 0$, costs invert (`engine.rs:445-453`).
- Direction selection: if $\rho_{\text{plus}} \le \rho_{\text{minus}}$, pick $+1$; else pick $-1$; ties resolve to $+1$ (`rust/src/stego/coding/stc.rs:147-155`). $0$ signifies no modification.
- If Huffman tables disallow both directions, both costs are set to infinity (`Move::Both`), leaving only "retain unmodified" reachable (`engine.rs:454-478`).

Ternary STC encoding solves $H \cdot (c \bmod 2) = message$ with $\delta \in \{-1, 0, +1\}$ (`stc.rs:515-809`, `:488-514`). Reader syndrome extraction evaluates bit-by-bit:

```text
s(r) = XOR{ (col[si] >> (r - g)) & 1 ? (v[g * u + si] & 1) : 0 }
       for g ∈ [max(0, r - (h - 1)), r], si ∈ [0, u)
bit_b = s(b + h - 1)
```

(`stc.rs:408-449`). The first $h - 1$ rows represent warm-up states. Third-party readers require only `c & 1` and need no knowledge of costs, bias, or `2 | parity`.

---

## 5. UERD Cost Model (Tier I)

Entry point: `UerdCostModel::compute_cost`, `rust/src/stego/jpeg/cost/uerd.rs:94-196`.

**Coefficient Inputs**: Inputs are quantized coefficients $c[b][k]$; luminance quantization table $Q[k]$ is sourced from the file's DQT in natural order, falling back to Annex K defaults if missing, with each entry bounded by $\max(1)$ (`uerd.rs:96`).

**Block Energy**, accumulated for $k = 1 \dots 63$ in ascending order:

```text
E_b = Σ_{k=1}^{63} (|c[b][k]| & ~1) * Q[k]
```

`& ~1` maps quantization contributions into step functions of $|c|$ ($|1|=0, |2|=2, |3|=2, |4|=4$), ensuring a single $\pm 1$ alteration changes at most one step (`uerd.rs:98-116`).

**Block Neighborhood**: Neighborhoods evaluate 8-connected neighbors of component 0 across MCU padding grids, accumulated in fixed order $dr \in \{-1, 0, 1\}, dc \in \{-1, 0, 1\}$, skipping the center; out-of-bounds cells or padding cells lacking corresponding blocks are skipped; zero-energy blocks are tallied. When neighbor count $n > 0$:

```text
Ē_b = E_b + neighbor_weight * (Σ_{neighbors} E_n / n)
```

When $n = 0$, $\bar{E}_b = E_b$ (`uerd.rs:131-167`). Default is $neighbor\_weight = 0.25$ (`rust/src/stego/params.rs:594-604`).

**Cost Assignment**: If smoothed block energy $\le 0$, all AC coefficients in that block receive `wet_cost`; otherwise, for $k = 1 \dots 63$:

```text
ρ[b][k] = min( Q[k] / Ē_b , wet_cost )
```

`wet_cost` defaults to $10^{13}$ (`params.rs:594-604`; `uerd.rs:177-193`). Arithmetic is evaluated in f64 using only $+ - * /$, with no transcendental functions.

---

## 6. J-UNIWARD Cost Model (Tier I)

Entry point: `JuniwardCostModel::compute_cost`, `rust/src/stego/jpeg/cost/juniward.rs:112-179`.

**Preprocessing**: Coefficients are dequantized ($c \cdot Q$) and transformed via $8 \times 8$ IDCT for each block to yield an MCU-padded spatial luminance plane (skipping $+128$ level shift; `precover.rs:185-240`). Quantization steps $Q[k]$ take $\max(1)$ converted to f32 (`juniward.rs:133-137`).

**Directional Wavelet Filters**: Daubechies 8 (DB8) decomposition filter taps are hardcoded to 10 decimal places:

```text
−0.0544158422,  0.3128715909, −0.6756307363,  0.5853546837,
 0.0158291053, −0.2840155430, −0.0004724846,  0.1287474266,
 0.0173693010, −0.0440882539, −0.0139810279,  0.0087460940,
 0.0048703530, −0.0003917404, −0.0006754494, −0.0001174768
```

(`rust/src/stego/wavelet.rs:23-40`). Smoothing filter evaluates $lpdf[i] = (-1)^i \cdot HPDF[15 - i]$ (`:42-53`). The three subbands evaluate in standard literature order: $(l, h)$ = Horizontal, $(h, l)$ = Vertical, $(h, h)$ = Diagonal (`:61-68`).

**Separable Residuals**: For each subband, evaluate horizontal convolution ($f_2$ along x-axis), followed by vertical convolution ($f_1$ along y-axis):

```text
R[y][x] = Σ_{a=0..15} f1[a] * ( Σ_{b=0..15} f2[b] * plane[y + a - 8][x + b - 8] )
```

Boundary indices clamp via $\text{clamp}(0, w - 1)$ / $\text{clamp}(0, h - 1)$; both passes accumulate ascendingly over $a, b$ and $x$ (`juniward.rs:426-472`). Directional weights $1 / (|R| + \sigma)$ form a padded f32 plane, repeating boundary values (`:474-517`).

$\sigma$ defaults to $2^{-6} = 1/64 = 0.015625$, overridable via `params.model_option("sigma", ...)`, bounded by $\max(\text{MIN\_POSITIVE})$ (`juniward.rs:57-58`, `:133-136`).

**Spatial Footprints and Costs**: For block coordinates $(i, j)$, evaluate 23-tap 1D responses against DCT basis $C$:

```text
u_i[ky] = |Σ_a f1[a] * C[ky + a - 15][i]|      // For terms where 0 <= idx < 8
v_j[kx] = |Σ_b f2[b] * C[kx + b - 15][j]|
T_j[ky] = Σ_kx patch[ky][kx] * v_j[kx]
S_i,j   = Σ_ky u_i[ky] * T_j[ky]
ρ[bi][k = i * 8 + j] += Q[k] * S_i,j           // Accumulated per subband
```

Parameters: $\text{SUPPORT} = 8 + 16 - 1 = 23$, $\text{BASIS\_SHIFT} = 15$, $\text{PAD} = 24$; $i, j$ ascending, skipping $k = 0$ (`juniward.rs:61-101`, `:264-306`, `:544-576`). Subbands accumulate in order $(l, h), (h, l), (h, h)$ (`:206-209`). Finally, DC, non-finite, $\le 0$, or $> wet\_cost$ entries are set to $wet\_cost$ (`:167-172`).

**Determinism**: When `params.deterministic == true`, a scalar dot-product loop is enforced (4 accumulation registers, ascending `PAD`, no SIMD); otherwise AVX2+FMA `sweep_avx2` may run on x86 (`juniward.rs:148-152`, `:332-423`). Baselines and cross-platform verification MUST use the deterministic scalar path.

---

## 7. J-MiPOD Cost Model (Tier I)

Entry point: `JmipodCostModel::compute_cost`, `rust/src/stego/jpeg/cost/jmipod.rs:77-160`.

**Spatial Variance**: Evaluates $\text{estimate\_variance}(plane, pw, ph, p=3, degree=3, wiener\_window=2, floor=10^{-6})$; Wiener residuals adhere to Matlab `wiener2` semantics (even window, top-left anchor, zero-padding). With $dof = 3 \times 3 - 3 \times 4 / 2 = 3$, per-pixel $\sigma^2 = \max(10^{-6}, \|P_\perp r\|^2 / dof)$ (`jmipod.rs:48-58`, `rust/src/stego/spatial_variance.rs:371-405`).

**DCT Variance Propagation**:

```text
Var_dct[v, u] = Σ_{y, x} C[y, v]^2 * C[x, u]^2 * σ^2[y, x]
Var_q[k]      = max( Var_dct[k] / Q[k]^2, 1e-5 )
Fisher[k]     = 2 / Var_q[k]^2                  // k = 1..63; DC is inactive
```

(`jmipod.rs:109-131`, `:175-210`). $Q[k]$ uses $\max(1)$ DQT values; $Q^2$ squares term-by-term (`:117`).

**Reference Payload**: $nz\_ac$ counts non-zero AC coefficients in component 0; if 0, falls back to $total\_blocks \times 63$. Target rate $\alpha$ defaults to $0.20$ bits per non-zero AC, overridable within $[0.01, 0.90]$; $target\_bits = \alpha \cdot nz\_ac$ (`jmipod.rs:133-149`).

**Calibration and Quantization**: `fisher_to_costs(fisher, target_bits)` (`rust/src/stego/cost_calibration.rs:206-338`):

1. Compute $\ln(Fisher)$; non-finite / $\le 0$ entries are marked $-\infty$ (inactive); chunked reduction (`REDUCTION_CHUNK = 2^18`) ensures bit-for-bit consistency (`cost_calibration.rs:55-57`, `:214-241`).
2. Ternary capacity evaluates as $active \cdot \ln(3)$; $target = \min(target\_bits \cdot \ln(2), capacity \cdot 0.999)$; $LN\_3 = 1.0986122886681098$ (`:48`, `:249-251`).
3. Construct uniform log-Fisher histogram over $[u_{\min}, u_{\max}]$ with $BINS = 32768$ (`:50-53`, `:106-124`).
4. Root finding for $\rho \cdot (e^\rho + 2) = x$ uses Newton's method: initial value $\ln\_1p(x)$, 32 iterations, termination tolerance $10^{-14} \cdot (1 + |\rho|)$, step clamped to $\rho \ge 0$, $x$ capped at $10^{300}$ (`:59-81`).
5. Lagrange multiplier search uses Illinois method: initial brackets $t_{\text{lo}} = -max\_log - 30, t_{\text{hi}} = -min\_log + 5$, up to 100 expansions by $\pm 10$; 80 iterations, tolerance $10^{-12} \cdot \max(target, 1)$, final interpolation (`:259-326`).
6. `quantize_cost` clears lower 20 mantissa bits (quantum $2^{-32}$); zero, negative, and non-finite values return unmodified (`:340-379`).

Post-calibration: DC, non-finite, $\le 0$, and $> wet\_cost$ entries are forced to $wet\_cost$ (`jmipod.rs:154-158`). Transcendental functions evaluate strictly via `detmath`: DCT basis uses `cos` (§8); calibration uses `ln / ln_1p / exp` (`cost_calibration.rs:214-220`, `:68-72`, `:99-102`). Under J-MiPOD, quantized costs **serve directly as STC trellis edge weights** without candidate sorting; notes in `DETMATH.md` regarding "sorting only" do not apply to JPEG.

**Directional Bias**: Generated via `precover::bias(..., dead_zone=0.0)` only when $polarize\_weight \ne 1.0$; bias is computed from differences in dequantization $\to$ Wiener $3 \times 3 \to$ forward DCT $\to$ requantization (`jmipod.rs:162-172`; `precover.rs:126-150`, `:281-300`).

**Differences from Spatial MiPOD**: JPEG estimates spatial variance on the luminance plane before projecting into the DCT domain and dividing by $Q[k]^2$; Spatial MiPOD operates on pixels directly with $p = 9, l = 9, floor = 0.01$. J-MiPOD uses $p = 3, l = 3, floor = 10^{-6}$; it omits spatial Fisher smoothing entirely (no $3 \times 3$ post-filter); reference rate is bits per non-zero AC (`jmipod.rs:30-34`, `:47-58`), whereas spatial domain uses bits per embeddable pixel.

---

## 8. Precover and DCT Basis (Tier I)

$dct\_basis()[x][u] = 0.5 \cdot c_u \cdot \cos((2x + 1)u\pi / 16)$, where $c_0 = 1/\sqrt{2}$ and $c_u = 1$ otherwise; generated with outer $x$ and inner $u$ ascending (`precover.rs:46-64`). $\cos$ MUST invoke `detmath::cos` (Cody–Waite 3-stage $\pi/2$ reduction + polynomial), never host `libm` (`rust/src/stego/detmath.rs:298-312`; digests in DETMATH.md §6).

- **Hardcoded Constants**: Only the 16 taps of DB8 (§6) are frozen to 10 decimal places; `lpdf` is generated dynamically by reversing and alternating signs. The DCT basis has no hardcoded 64-element table; it is generated dynamically via `detmath::cos`.
- **IDCT**: `idct_block` implements two-pass matrix multiplication $B = C \cdot F \cdot C^T$ (forward is $F = C^T \cdot B \cdot C$), accumulating over $v$ then $u$ ascending (`precover.rs:67-118`). `decompress_luma` dequantizes and evaluates IDCT over all 64 coefficients per block, skipping $+128$ level shifts (`:185-240`).
- **FMA Prohibited**: Scalar and deterministic paths forbid $a \cdot b + c$ contraction, reassociation, and `fp-contract` (DETMATH.md §8). AVX2+FMA in J-UNIWARD is permitted only when `deterministic == false`; baseline checks must run scalar.
- Third parties seeking interoperability without bit-for-bit baseline replication may treat cost models as Tier I and omit this section, provided output coefficients satisfy §4.

---

## 9. Writer-Only Non-Normative Implementation Constraints (Tier I)

- **Model Selection**: Defaults to UERD; J-UNIWARD and J-MiPOD are selected by callers and unrecorded in headers (`engine.rs:1195-1216` read path contains no model parameters).
- **Quality and Table Preservation**: No transcoding or recompression is performed, and no new quality factor is selected. `dct_io::write_coefficients` re-encodes entropy scan segments using the file's original Huffman tables; non-entropy markers (EXIF, ICC, DQT, DHT) are preserved byte-for-byte (`dct-io-0.1.1/src/lib.rs:179-207`; `engine.rs:1057`).
- **"Original JPEG Restoration"**: Non-scan segments match input byte-for-byte; unedited coefficients yield identical pixel values, but rewritten entropy-coded scan bytes **are not guaranteed to match original scan bytes bit-for-bit**. Content domain does not support bit-exact restoration (restoration is exclusive to structural domain, `rust/src/cli/args.rs:93`). Baselines compare full stego SHA-256 (`scripts/baseline_hash.py:368`) and extracted payload text (`:380-382`), not original scan bytes.
- **Determinism**: `Freshness::Seeded` guarantees bit-for-bit reproducibility for identical carriers and parameters; `deterministic` disables SIMD paths (`engine.rs:586-589`). Retries execute attempts 1..6 (`EMBED_ATTEMPTS = 6`, `engine.rs:562`); only missing Huffman symbols trigger retries, rolling back coefficients on failure (`:773-806`, `:1160`). Salt and nonce are derived per attempt, altering header bytes; readers decode actual header bytes independently of retry counts.
- **Deflate**: Compresses payload via Deflate when advantageous, using `Compression::default()` (level 6); used only when strictly smaller; readers always decompress according to flags (`rust/src/stego/envelope.rs:372-401`).
- **Huffman Cross-Zero Penalty**: When Huffman tables exist, repeated zero-crossing runs ($0 \leftrightarrow \pm 1$) are penalized via $CROSS\_ZERO\_REPEAT\_PENALTY = 1000$; duplicate runs within a block receive $wet\_cost \times 1000$ and disallow erasing $\pm 1$ (`engine.rs:303`, `:407-442`). This is a writer heuristic transparent to readers.
- **Extension Region Critical Flag**: Writers reject critical TLVs; readers degrade critical TLVs to `NoHiddenData` (`CONTENT-ENVELOPE.md:107-110`).

---

## 10. Self-Verification

```bash
cd rust
cargo build --release --all-features          # Updates target/release/strhide
cargo test --all-features --all-targets       # Tests JPEG slots, STC, costs, round-trips
cargo test --all-features jpeg                # Runs JPEG-specific test cases
python ../scripts/import_lint.py              # Architecture dependency boundary check
python ../scripts/cost_vectors_check.py       # Validates spatial MiPOD vectors (no JPEG vectors)
python ../scripts/baseline_hash.py --check --only jpg
```

- `cost-vectors`: `docs/api/cost-vectors.json` contains fixed vectors for spatial MiPOD only; JPEG cost models do not maintain external vector files. Third parties replicating bit-for-bit output must verify against formulas, `detmath` digests, and baselines.
- Baseline: `baseline_hash.py` covers JPEG across `uerd` / `juniward` / `jmipod` (`scripts/baseline_hash.py:85-91`); filterable via `--only jpg`.
- Numerical Determinism: `detmath` digests for `exp / ln / cos / ln_1p / log2` MUST match DETMATH.md §9; modifying sampling, permutations, STC, or cost parameters requires rebuilding JPEG baselines.
