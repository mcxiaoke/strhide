#!/usr/bin/env python3
"""Cross-language conformance check for the MiPOD cost pipeline.

`docs/api/cost-vectors.json` pins five stage digests produced by the Rust
implementation. This script re-implements the same pipeline from scratch using
only the Python standard library and checks that each stage lands on the same
bits. It is the cheapest way to answer "would a second implementation agree?"
without porting the whole steganography stack.

What is checked, in pipeline order:

    pixels -> plane (class-masked luminance) -> sigma^2 -> I = 2/sigma^4
           -> 7x7 box smooth -> quantised STC cost

The first four stages only use `+ - * /`, `sqrt` and `cos`; the last one adds
`ln`, `exp` and a Newton solve. `math.*` is whatever libm CPython links, so a
pass here is evidence that the quantisation absorbs libm differences rather
than proof that every libm agrees bit for bit.

Usage:
    python scripts/cost_vectors_check.py
    python scripts/cost_vectors_check.py --vectors docs/api/cost-vectors.json

Exit code 0 means every stage matched. Stage 4 (`cost`) is the contract: it is
what the writer and the reader both consume. Stages 0-3 are diagnostics -- a
mismatch there explains a stage-4 mismatch but is not itself a failure, unless
you pass `--strict`.
"""

from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from pathlib import Path

BINS = 32_768
LOG_X_MAX = 690.0
LN_3 = 1.0986122886681098
LN_2 = 0.6931471805599453
MASK64 = 0xFFFF_FFFF_FFFF_FFFF


# ---------------------------------------------------------------------------
# Digests (must match the Rust helper byte for byte)
# ---------------------------------------------------------------------------


def fnv1a(vals) -> str:
    """FNV-1a over the little-endian bit patterns of `vals`."""
    h = 0xCBF2_9CE4_8422_2325
    for v in vals:
        for b in struct.pack("<d", v):
            h = ((h ^ b) * 0x0000_0100_0000_01B3) & MASK64
    return f"{h:016x}"


# ---------------------------------------------------------------------------
# Stage 0: class-masked luminance
# ---------------------------------------------------------------------------


def class_masked_luminance(pixels: bytes, w: int, h: int, channels: int) -> list[float]:
    """`pixel & 0xF8`, reduced to one plane exactly like `hill.rs` does."""
    n = w * h
    plane = [0.0] * n
    if channels == 1:
        for i in range(n):
            plane[i] = float(pixels[i] & 0xF8)
    elif channels >= 3:
        for i in range(n):
            r = float(pixels[i * channels] & 0xF8)
            g = float(pixels[i * channels + 1] & 0xF8)
            b = float(pixels[i * channels + 2] & 0xF8)
            plane[i] = 0.299 * r + 0.587 * g + 0.114 * b
    else:
        for i in range(n):
            plane[i] = float(pixels[i * channels] & 0xF8)
    return plane


# ---------------------------------------------------------------------------
# Stage 1: Wiener residual + local cosine complement (sigma^2)
# ---------------------------------------------------------------------------


def reflect_index(i: int, n: int) -> int:
    """NumPy `symmetric` mirroring, edge included."""
    if n <= 1:
        return 0
    period = 2 * n
    i %= period
    if i < 0:
        i += period
    return (period - 1 - i) if i >= n else i


def wiener_residual(plane: list[float], w: int, h: int, window: int) -> list[float]:
    """`r = z - wiener2(z)` with zero padding and a top-left anchored window."""
    n = w * h
    anchor = 0 if window % 2 == 0 else window // 2
    area = float(window * window)
    mean = [0.0] * n
    var = [0.0] * n
    for y in range(h):
        for x in range(w):
            s = 0.0
            s2 = 0.0
            for dy in range(window):
                sy = y + dy - anchor
                if sy < 0 or sy >= h:
                    continue
                for dx in range(window):
                    sx = x + dx - anchor
                    if sx < 0 or sx >= w:
                        continue
                    val = plane[sy * w + sx]
                    s += val
                    s2 += val * val
            mu = s / area
            mean[y * w + x] = mu
            v = s2 / area - mu * mu
            var[y * w + x] = v if v > 0.0 else 0.0

    # Row sums in index order, then their sum: same shape as the Rust reduction.
    total = 0.0
    for y in range(h):
        row_sum = 0.0
        for x in range(w):
            row_sum += var[y * w + x]
        total += row_sum
    noise = total / n
    if noise <= 0.0:
        return [0.0] * n

    out = [0.0] * n
    for i in range(n):
        diff = plane[i] - mean[i]
        v = var[i]
        out[i] = (noise / v) * diff if v > noise else diff
    return out


def dct_basis(p: int) -> list[list[float]]:
    scale0 = math.sqrt(1.0 / p)
    scalek = math.sqrt(2.0 / p)
    basis = []
    for k in range(p):
        s = scale0 if k == 0 else scalek
        row = []
        for a in range(p):
            angle = math.pi * k * (2 * a + 1) / (2.0 * p)
            row.append(s * math.cos(angle))
        basis.append(row)
    return basis


def complement_energy(residual: list[float], w: int, h: int, p: int, degree: int) -> list[float]:
    half = p // 2
    stride = w * p
    basis = dct_basis(p)

    # Horizontal projections, laid out [row][x][kv] like the Rust band buffer.
    horiz = [0.0] * ((h + 2 * half) * w * p)
    for bi in range(h + 2 * half):
        sy = reflect_index(bi - half, h)
        src = residual[sy * w : (sy + 1) * w]
        for x in range(w):
            base = (bi * w + x) * p
            if x >= half and x + p - half <= w:
                win = src[x - half : x - half + p]
                for kv in range(p):
                    b = basis[kv]
                    acc = 0.0
                    for a in range(p):
                        acc += b[a] * win[a]
                    horiz[base + kv] = acc
            else:
                for kv in range(p):
                    b = basis[kv]
                    acc = 0.0
                    for a in range(p):
                        acc += b[a] * src[reflect_index(x + a - half, w)]
                    horiz[base + kv] = acc

    energies = [0.0] * (w * h)
    for y in range(h):
        for x in range(w):
            norm_sq = 0.0
            for kv in range(p):
                vals = [horiz[((y + a) * w + x) * p + kv] for a in range(p)]
                for ku in range(max(0, degree - kv), p):
                    b = basis[ku]
                    proj = 0.0
                    for a in range(p):
                        proj += b[a] * vals[a]
                    norm_sq += proj * proj
            energies[y * w + x] = norm_sq
    return energies


def estimate_variance(
    plane: list[float],
    w: int,
    h: int,
    block_p: int,
    degree: int,
    wiener_window: int,
    variance_floor: float,
) -> list[float]:
    residual = wiener_residual(plane, w, h, wiener_window)
    energies = complement_energy(residual, w, h, block_p, degree)
    q = degree * (degree + 1) // 2
    dof = float(block_p * block_p - q)
    return [max(e / dof, variance_floor) for e in energies]


# ---------------------------------------------------------------------------
# Stage 3: 7x7 box smooth with mirror padding
# ---------------------------------------------------------------------------


def box_smooth(plane: list[float], w: int, h: int, window: int) -> list[float]:
    if window <= 1:
        return list(plane)
    half = window // 2
    inv = 1.0 / float(window)

    tmp = [0.0] * (w * h)
    for y in range(h):
        src = plane[y * w : (y + 1) * w]
        row = tmp[y * w : (y + 1) * w]
        for x in range(w):
            s = 0.0
            for d in range(-half, half + 1):
                s += src[reflect_index(x + d, w)]
            row[x] = s * inv
        tmp[y * w : (y + 1) * w] = row

    out = [0.0] * (w * h)
    for y in range(h):
        for x in range(w):
            s = 0.0
            for d in range(-half, half + 1):
                s += tmp[reflect_index(y + d, h) * w + x]
            out[y * w + x] = s * inv
    return out


# ---------------------------------------------------------------------------
# Stage 4: Fisher information -> additive cost (the part that needs libm)
# ---------------------------------------------------------------------------


def solve_rho(x: float) -> float:
    """Solve `rho * (exp(rho) + 2) = x` with monotone Newton from the right."""
    if math.isnan(x) or x <= 0.0:
        return 0.0
    x = min(x, 1e300)
    rho = math.log(1.0 + x)
    for _ in range(32):
        e = math.exp(rho)
        f = rho * (e + 2.0) - x
        df = e * (1.0 + rho) + 2.0
        nxt = max(rho - f / df, 0.0)
        if abs(nxt - rho) <= 1e-14 * (1.0 + nxt):
            rho = nxt
            break
        rho = nxt
    return rho


def ternary_entropy_nats(rho: float) -> float:
    lm = math.log1p(2.0 * math.exp(-rho))
    ell = rho + lm
    beta = math.exp(-ell)
    p0 = math.exp(-lm)
    return 2.0 * beta * ell + p0 * lm


def entropy_at(hist: list[int], u_min: float, du: float, t: float) -> float:
    total = 0.0
    for i, count in enumerate(hist):
        if count == 0:
            continue
        center = u_min + (i + 0.5) * du
        x = min(t + center, LOG_X_MAX)
        total += float(count) * ternary_entropy_nats(solve_rho(math.exp(x)))
    return total


def fisher_to_costs(fisher: list[float], target_bits: float, quantise_bits: int) -> list[float]:
    n = len(fisher)
    if n == 0:
        return fisher

    logs = [math.log(f) if (math.isfinite(f) and f > 0.0) else -math.inf for f in fisher]
    active = sum(1 for v in logs if math.isfinite(v))
    finite = [v for v in logs if math.isfinite(v)]
    if active == 0 or target_bits <= 0.0 or not math.isfinite(target_bits) or not finite:
        return [0.0] * n

    min_log = min(finite)
    max_log = max(finite)

    capacity = float(active) * LN_3
    target = min(target_bits * LN_2, capacity * 0.999)
    if target <= 0.0:
        return [0.0] * n

    span = max(max_log - min_log, 1e-12)
    du = span / float(BINS)
    inv_du = 1.0 / du
    hist = [0] * BINS
    for v in logs:
        if not math.isfinite(v):
            continue
        idx = int((v - min_log) * inv_du)
        if idx > BINS - 1:
            idx = BINS - 1
        hist[idx] += 1

    t_lo = -max_log - 30.0
    f_lo = entropy_at(hist, min_log, du, t_lo) - target
    guard = 0
    while f_lo <= 0.0 and guard < 100:
        t_lo -= 10.0
        f_lo = entropy_at(hist, min_log, du, t_lo) - target
        guard += 1

    t_hi = -min_log + 5.0
    f_hi = entropy_at(hist, min_log, du, t_hi) - target
    guard = 0
    while f_hi >= 0.0 and guard < 100:
        t_hi += 10.0
        f_hi = entropy_at(hist, min_log, du, t_hi) - target
        guard += 1

    tol = 1e-12 * max(target, 1.0)
    a, b, fa, fb = t_lo, t_hi, f_lo, f_hi
    side = 0
    t = 0.5 * (a + b)
    for _ in range(80):
        if abs(fb - fa) > 0.0:
            c = (a * fb - b * fa) / (fb - fa)
        else:
            c = 0.5 * (a + b)
        if not (min(a, b) < c < max(a, b)):
            c = 0.5 * (a + b)
        fc = entropy_at(hist, min_log, du, c) - target
        t = c
        if abs(fc) <= tol or abs(b - a) <= 1e-14 * (1.0 + max(abs(a), abs(b))):
            break
        if fc * fb > 0.0:
            b, fb = c, fc
            if side == -1:
                fa *= 0.5
            side = -1
        else:
            a, fa = c, fc
            if side == 1:
                fb *= 0.5
            side = 1

    table = []
    for i in range(BINS + 1):
        u = min_log + i * du
        table.append(solve_rho(math.exp(min(t + u, LOG_X_MAX))))

    drop = (1 << quantise_bits) - 1
    out = []
    for v in logs:
        if not math.isfinite(v):
            out.append(0.0)
            continue
        pos = (v - min_log) * inv_du
        if pos <= 0.0:
            cost = table[0]
        else:
            j = int(math.floor(pos))
            if j >= BINS:
                cost = table[BINS]
            else:
                frac = pos - j
                base = table[j]
                cost = base + (table[j + 1] - base) * frac
        if not math.isfinite(cost) or cost <= 0.0:
            out.append(cost)
        else:
            bits = struct.unpack("<Q", struct.pack("<d", cost))[0]
            out.append(struct.unpack("<d", struct.pack("<Q", bits & ~drop))[0])
    return out


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--vectors",
        default=str(Path(__file__).resolve().parent.parent / "docs/api/cost-vectors.json"),
    )
    ap.add_argument("--strict", action="store_true", help="treat intermediate mismatches as failure")
    args = ap.parse_args()

    doc = json.loads(Path(args.vectors).read_text(encoding="utf-8"))
    case = doc["case"]
    params = doc["params"]
    w, h, channels = case["w"], case["h"], case["channels"]
    pixels = bytes.fromhex(case["pixels_hex"])

    plane = class_masked_luminance(pixels, w, h, channels)
    var = estimate_variance(
        plane,
        w,
        h,
        params["block_p"],
        params["degree"],
        params["wiener_window"],
        params["variance_floor"],
    )
    fisher = [2.0 / (v * v) for v in var]
    smoothed = box_smooth(fisher, w, h, params["fi_smooth_window"])
    cost = fisher_to_costs(smoothed, params["alpha_f32"] * float(w * h), params["quantise_bits"])

    got = {
        "plane": fnv1a(plane),
        "variance": fnv1a(var),
        "fisher": fnv1a(fisher),
        "smoothed": fnv1a(smoothed),
        "cost": fnv1a(cost),
    }
    want = doc["digests"]

    print(f"vectors: {args.vectors}")
    print(f"case:    {w}x{h}x{channels}, quantise_bits={params['quantise_bits']}")
    print()
    print(f"{'stage':<10} {'rust':<18} {'python':<18} verdict")
    bad_stage = None
    for stage in ("plane", "variance", "fisher", "smoothed", "cost"):
        ok = got[stage] == want[stage]
        if not ok and bad_stage is None:
            bad_stage = stage
        print(f"{stage:<10} {want[stage]:<18} {got[stage]:<18} {'ok' if ok else 'MISMATCH'}")

    head = doc.get("cost_head_bits") or []
    if head:
        py_head = [struct.unpack("<Q", struct.pack("<d", c))[0] for c in cost[: len(head)]]
        same = list(head) == py_head
        print(f"\ncost head: {'ok' if same else 'MISMATCH'} ({len(head)} values)")

    print()
    if bad_stage is None:
        print("PASS: every stage matched.")
        return 0
    print(f"FAIL: first divergence at '{bad_stage}'.")
    print(
        "  - divergence before 'cost' means the arithmetic differs; check the "
        "summation order and the mirror padding."
    )
    print(
        "  - divergence only at 'cost' means the calibration (ln/exp/Newton) "
        "or the quantise width differs."
    )
    if not args.strict and bad_stage != "cost":
        print("  intermediate mismatches are diagnostics unless --strict is passed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
