# DETMATH — Deterministic Floating-Point Mathematics Specification

**Status**: Normative. This document specifies the exact semantics of all elementary floating-point functions that **affect byte-level output** in `strhide`.  
**Scope**: Cost maps, cost calibration, and `epsilon` quantization across the content domain (PNG / JPEG / WAV / FLAC / HEVC), as well as structural domain capacity reporting.  
**Navigation**: [Specification Overview](./README.md) · [Content Domain Envelope](./CONTENT-ENVELOPE.md) · [Structural Domain Envelope](./STRUCTURE-ENVELOPE.md) · [Capacity Specification](./CAPACITY.md). Precision audit conclusions have been merged into §5 and §9 of this document and are no longer maintained separately.

---

## 1. Normative Declaration

For any floating-point operation affecting byte-level output, **semantics are defined by this document, not by the host `libm`**. Conformance cannot rely on "host `libm` consistency": IEEE-754 mandates exact behavior only for `+ - * /` and `sqrt`; transcendental functions are explicitly excluded. Empirical audits across three languages on 52,153 inputs revealed 20 discrepancies (18 Go NaN payload differences + 2 `cos(±1e15)` boundary issues); when Go enabled FMA, divergence expanded to 2,176/2,397 inputs (Audit §0, §3, §5). Permitted primitives are strictly limited to `+ - * /` and `to_bits` / `from_bits`. Every function MUST be implemented verbatim following the specified evaluation order, number of terms, and constants; precision declarations **do not guarantee correct rounding**.

Call sites (Rust reference implementation):

- `rust/src/stego/cost_calibration.rs:68` (`ln_1p`), `:70` (`exp`), `:87` (`exp`), `:99` (`ln_1p` + `exp`), `:101` (`exp`), `:102` (`exp`), `:163` (`exp`), `:174` (`exp`), `:216` (`ln`).
- `rust/src/stego/spatial_variance.rs:70`, `:86` (`cos`, 8×8 DCT basis); `rust/src/stego/jpeg/cost/precover.rs:61` (`cos`).
- `rust/src/stego/header.rs:34`, `rust/src/stego/audio/core.rs:381` (`log2`, `epsilon` quantization).

The outputs above, after truncating the lower 20 bits via `quantize_cost` (quantum $2^{-32}$, `rust/src/stego/cost_calibration.rs:369-379`), participate in sorting strictly via `f64::to_bits()`. This document locks down every bit of those sorting keys.

---

## 2. Constant Table (Verbatim)

| Constant | Decimal Literal | Bit Pattern |
|---|---|---|
| `LN2_HI` | `6.931_471_803_691_238e-1` | `0x3FE62E42FEE00000` |
| `LN2_LO` | `1.908_214_929_270_587_7e-10` | `0x3DEA39EF35793C76` |
| `INV_LN2` | `LOG2_E = 1.4426950408889634` | `0x3FF71547652B82FE` |
| `PIO2_1` | `1.570_796_326_734_125_6` | `0x3FF921FB54400000` |
| `PIO2_2` | `6.077_100_506_303_966e-11` | `0x3DD0B4611A600000` |
| `PIO2_3` | `2.022_266_248_795_951e-21` | `0x3BA3198A2E037074` |
| `TWO_OVER_PI` | `0.636_619_772_367_581_3` | `0x3FE45F306DC9C882` |
| `SQRT2` | `std::f64::consts::SQRT_2` = `1.4142135623730951` | `0x3FF6A09E667F3BCD` |
| `EXP_HI` | `709.782_712_893_384` | `0x40862E42FEFA39EF` |
| `EXP_LO` | `-745.133_219_101_941_1` | `0xC0874910D52D3051` |

`EXP_C[14]` ($1/1! \dots 1/14!$, all correctly rounded):  
`1.0, 0.5, 1.0/6.0, 1.0/24.0, 1.0/120.0, 1.0/720.0, 1.0/5040.0, 1.0/40320.0, 1.0/362880.0, 1.0/3628800.0, 1.0/39916800.0, 1.0/479001600.0, 1.0/6227020800.0, 1.0/87178291200.0`.

`SIN_C[8]`: `-1/6, 1/120, -1/5040, 1/362880, -1/39916800, 1/6227020800, -1/1307674368000, 1/355687428096000`.  
`COS_C[8]`: `-0.5, 1/24, -1/720, 1/40320, -1/3628800, 1/479001600, -1/87178291200, 1/20922789888000`.  
`LN_3 = 1.098_612_288_668_109_8` (`rust/src/stego/cost_calibration.rs:48`).

---

## 3. `exp(x)`

Reference: `rust/src/stego/detmath.rs:154-176`.  
1. If NaN, return input NaN verbatim (preserving payload); if $x > \text{EXP\_HI} \to +\infty$; if $x < \text{EXP\_LO} \to +0.0$.  
2. $k = \text{round\_i32}(x \cdot \text{INV\_LN2})$; `round_i32` rounds half away from zero: if $x \ge 0$, take $(x+0.5) \text{ as i32}$, else $(x-0.5) \text{ as i32}$ (`detmath.rs:143-151`), where `as i32` is saturating conversion.  
3. $r = (x - k \cdot \text{LN2\_HI}) - k \cdot \text{LN2\_LO}$ (strictly left-associative).  
4. Horner's method: initialize $p = \text{EXP\_C}[13]$; for $i = 12 \dots 1$ sequentially compute $p = \text{EXP\_C}[i] + r \cdot p$; finally $p = \text{EXP\_C}[0] + r \cdot p$.  
5. Return $\text{ldexp}(1.0 + r \cdot p, k)$; `ldexp` multiplies by $2^{1023}$ and subtracts 1023 when $k > 1023$, multiplies by $2^{-1022}$ and adds 1022 when $k < -1022$, and finally multiplies by $\text{from\_bits}((1023 + k) \ll 52)$ (`:105-116`).

Term count is 14; $|r| \le \ln(2)/2$; truncation remainder is $r^{15}/15! \approx 9.5 \times 10^{-20}$. Precision: audit corpus maximum **1.00 ulp**, dense sample maximum **1.1098 ulp**; not correctly rounded.

---

## 4. `ln(x)`

Reference: `detmath.rs:179-210`.  
1. If NaN or $x < 0 \to \text{canonical NaN}$; if $x == 0$ (including $-0.0$) $\to -\infty$; if $+\infty \to +\infty$.  
2. Decompose via `frexp` into $m \in [0.5, 1)$ and $e$; $m \leftarrow m \cdot 2.0; e \leftarrow e - 1$; if $m > \text{SQRT2}$, then $m \leftarrow m \cdot 0.5; e \leftarrow e + 1$.  
3. $s = (m - 1.0) / (m + 1.0)$, $z = s \cdot s$.  
4. Initialize $p = 1.0 / 23.0$; set $d = 21.0$; while $d > 1.0$, iteratively update $p = 1.0/d + z \cdot p; d \leftarrow d - 2.0$ (for $d = 21, 19, \dots, 3$).  
5. $p = 1.0 + z \cdot p$; $\ln\_m = 2.0 \cdot s \cdot p$; $ef = e \text{ as f64}$.  
6. Return $ef \cdot \text{LN2\_HI} + (ef \cdot \text{LN2\_LO} + \ln\_m)$ (strictly following parenthesized order).

The series evaluates up to $z^{11}/23$ (source comment says $z^{10}/21$, off by one term), with truncation error $\approx 1.7 \times 10^{-20}$. Precision: corpus maximum **1.12 ulp**, dense sample maximum **2.74 ulp**; not correctly rounded. `frexp` specification is in `detmath.rs:126-141`: exponent field 0 and $x == 0$ returns $(0.0, 0)$, otherwise multiply by $2^{54}$ recursively and subtract 54; normal numbers masked with `0x800FFFFFFFFFFFFF`, injected with `0x3FE0000000000000`, exponent $\text{exp} - 1022$.

---

## 5. `ln_1p(x)`

Reference: `detmath.rs:213-234`.  
1. If NaN or $x < -1.0 \to \text{canonical NaN}$; if $x == -1.0 \to -\infty$.  
2. If $|x| < 0.0625$: $\text{term} = x$, $\text{sum} = 0.0$, $n = 1.0$; while $n \le 12.0$, check $\text{odd} = ((n \text{ as i32}) \& 1) == 1$, accumulate $\text{sum} \mathrel{+}= \text{odd} \mathbin{?} \text{term}/n \mathbin{:} -(\text{term}/n)$, then $\text{term} \leftarrow \text{term} \cdot x; n \leftarrow n + 1.0$; return $\text{sum}$.  
3. Otherwise return $\ln(1.0 + x)$.

`ln_1p(-0.0)` enters the series branch, yielding **`+0.0`** (not `-0.0`). Precision: audit corpus maximum **6.91 ulp**, project 256-bit dense sample maximum **16.6360 ulp** (fallback branch), significantly worse than older claims of "~1 ulp". This is an empirical precision fact, not a correct rounding contract.

---

## 6. `cos(x)`, `sin_small`, `cos_small`

Reference: `detmath.rs:298-312`, `:238-262`.  
1. Non-finite values $\to \text{canonical NaN}$.  
2. $n = \text{round\_i32}(x \cdot \text{TWO\_OVER\_PI})$, $nf = n \text{ as f64}$.  
3. $r = ((x - nf \cdot \text{PIO2\_1}) - nf \cdot \text{PIO2\_2}) - nf \cdot \text{PIO2\_3}$ (strictly left-associative).  
4. Based on $n \& 3$:  
   - `0` $\to \text{cos\_small}(r)$  
   - `1` $\to -\text{sin\_small}(r)$  
   - `2` $\to -\text{cos\_small}(r)$  
   - `3` $\to \text{sin\_small}(r)$

`sin_small`: $z = r \cdot r$, $p = \text{SIN\_C}[7]$; for $i = 6 \dots 1$ sequentially compute $p = \text{SIN\_C}[i] + z \cdot p$; $p = \text{SIN\_C}[0] + z \cdot p$; return $r \cdot (1.0 + z \cdot p)$.  
`cos_small`: $z = r \cdot r$, $q = COS\_C[7]$; for $i = 6 \dots 1$ sequentially compute $q = \text{COS\_C}[i] + z \cdot q$; $q = \text{COS\_C}[0] + z \cdot q$; return $1.0 + z \cdot q$.

Declared operational domain: $|x| < 2^{20} \cdot \pi/2 \approx 1.65 \times 10^6$ (at which $|n| < 2^{20}$, making $nf \cdot \text{PIO2\_1}$ exact); in pipeline use, calls are strictly within $x \in [0, \pi]$. Precision: $|x| \le \pi$ maximum **1.7633 ulp**, $\le 2^{20} \cdot \pi/2$ maximum **2.24 ulp**. Precision collapses sharply beyond $|x| \ge \sim 10^7$; at $|x| \ge 2^{31} \cdot \pi/2 \approx 3.37 \times 10^9$, `round_i32` saturation causes divergence across languages; implementations MUST NOT rely on out-of-domain results.

---

## 7. `log2(x)`

Reference: `detmath.rs:270-281`.  
1. If NaN or $x < 0 \to \text{canonical NaN}$; if $x == 0$ (including $-0.0$) $\to -\infty$; if $+\infty \to +\infty$.  
2. Return $\ln(x) \cdot \text{LOG2\_E}$ ($\text{LOG2\_E} = \text{INV\_LN2} = 1.4426950408889634$).

Exclusively used for `epsilon` exponential domain quantization, immediately followed by `.round()` and `clamp(1.0, 127.0)` (`rust/src/stego/header.rs:34`, `rust/src/stego/audio/core.rs:381`). Maximum precision error: **1.79 ulp** (dense sample 2.31); lower-bit variations do not affect the rounded integer output unless the value falls precisely on a half-integer boundary.

---

## 8. Evaluation Discipline

- **FMA / Contraction / Reassociation Forbidden**: Never fuse $a \cdot b + c$ into `fma`, never enable `fp-contract`, and do not permit contraction under `--target-cpu=native`. Rust defaults to no contraction; Go emits `FMADDD` under `GOAMD64=v3`/arm64, producing 2,176–2,397 divergences compared to Rust (Audit §3.4, §5.3). Go ports MUST wrap multiplications with `//go:noinline` before addition; Python/CPython does not use FMA, requiring no barriers.
- **Sorting Keys**: After cost quantization, sorting MUST proceed strictly using integer ordering on `f64::to_bits()`; floating-point comparisons MUST NOT be used for total ordering, and NaNs MUST NOT enter candidate sets.
- **NaN Handling**: `exp` preserves input NaN payloads; all other functions return canonical NaN. Go MUST replace `math.NaN()` with `math.Float64frombits(0x7FF8000000000000)` (matching Rust and Python defaults of `0x7FF8000000000000`).
- **No `sqrt`, No libm, No Extended Precision**: 80-bit x87, `f128`, or double-double arithmetic MUST NOT be substituted.

---

## 9. Self-Verification and Digest Values

Digest algorithm: Take `f64::to_bits()` of each output, and compute FNV-1a 64 over little-endian bytes: initial state `0xCBF29CE484222325`, per byte $h \leftarrow h \oplus b; h \leftarrow h \cdot \text{0x00000100000001B3}$ (`rust/src/stego/detmath.rs:353-402`; `scripts/detmath/detmath.py:238-255`, `detmath.go:231-287`). Formatted as a 16-character hexadecimal string with leading zeros.

| Function | Digest |
|---|---|
| `exp` | `68107bf871d53df2` |
| `ln` | `6021ef64db0e27ef` |
| `cos` | `55f3c5acb971153a` |
| `ln_1p` | `23e6e71dccf69b20` |
| `log2` | `d97b86f58ee1dfba` |

Evaluation grids (must match verbatim):  
- `exp`: $i \cdot 0.37$ for $i = -240 \dots 240$, plus $10^{-6} \cdot i$ for $i = 0 \dots 120$;  
- `ln`: $i \cdot 0.71$ for $i = 1 \dots 400$, plus $10^{-12} \cdot (i + 1)$ for $i = 0 \dots 60$;  
- `cos`: $\pi \cdot k \cdot (2a + 1)/18$ for $k = 0 \dots 9, a = 0 \dots 9$;  
- `ln_1p`: $i \cdot 0.003$ for $i = 0 \dots 200$;  
- `log2`: $2^{-k}$ for $k = 1 \dots 60$, plus $i \cdot 0.37$ for $i = 1 \dots 200$.

```bash
cd rust
cargo test --lib detmath          # output_digests_are_pinned
python ../scripts/detmath/detmath.py
go run ../scripts/detmath/detmath.go
```

The script `scripts/detmath/compare.sh` referenced in code comments (`detmath.rs:320`, `:352`) **does not exist** (Audit P0-4); the five digest values in the table above represent the executable closed loop.

---

## 10. Domains Retaining Host libm

The `analysis` module retains `libm`, with its sole active call site being `cos` (DCT basis) at `rust/src/analysis/calibration.rs:90`. Because this belongs to steganalysis and does not participate in payload embedding, slot ordering, authenticated data, or header fields, ulp-level variations cannot alter byte-level output. All transcendental functions within `rust/src/stego/**` that influence output MUST use the implementations in this document; any newly added call sites MUST expand the §9 test grid simultaneously.

---

## 11. Stability Tiers

| Content | Tier | Justification |
|---|---|---|
| §2 Constants, §3–§7 Reductions / Terms / Order | **F** | Any change alters sorting keys and `epsilon`; existing carriers become unreadable; requires rebuilding `baseline_hash.py` baselines |
| §8 FMA / NaN / Ordering Discipline | **F** | Prerequisite for cross-build bit-for-bit reproducibility |
| §9 Digest Values | **F** | Digest drift indicates algorithm drift, permissible only with wire format revision reviews |
| §10 libm Scope Boundary | **I** | Constrains steganalysis only; test-as-modified |
| Function "Observed ulp" | **I** | Empirical observation, not a contract; contract is bit-for-bit reproducibility, not correct rounding |
