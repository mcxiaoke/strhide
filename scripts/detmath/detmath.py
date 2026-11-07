#!/usr/bin/env python3
"""Python port of `rust/src/stego/detmath.rs`.

The four functions here must produce **the same bits** as the Rust originals and
the Go port (`detmath.go`) for every input -- that is the whole point. They use
only `+ - * /` on doubles plus bit-level frexp/ldexp, in the same order and with
the same term counts as the Rust version. Accuracy is a couple of ulp; the
contract is reproducibility, not correct rounding.

Run this file directly to print the four digests; they must equal the pinned
constants in the Rust test module:

    exp   0x68107bf871d53df2
    ln    0x6021ef64db0e27ef
    cos   0x55f3c5acb971153a
    ln_1p 0x23e6e71dccf69b20
"""

from __future__ import annotations

import struct
import sys

MASK64 = 0xFFFF_FFFF_FFFF_FFFF

LN2_HI = 6.9314718036912382e-1
LN2_LO = 1.9082149292705877e-10
INV_LN2 = 1.4426950408889634
PIO2_1 = 1.5707963267341256
PIO2_2 = 6.077100506303966e-11
PIO2_3 = 2.022266248795951e-21
TWO_OVER_PI = 0.6366197723675813
SQRT2 = 1.4142135623730951

EXP_HI = 709.782712893384
EXP_LO = -745.1332191019411

EXP_C = (
    1.0,
    0.5,
    1.0 / 6.0,
    1.0 / 24.0,
    1.0 / 120.0,
    1.0 / 720.0,
    1.0 / 5040.0,
    1.0 / 40320.0,
    1.0 / 362880.0,
    1.0 / 3628800.0,
    1.0 / 39916800.0,
    1.0 / 479001600.0,
    1.0 / 6227020800.0,
    1.0 / 87178291200.0,
)

SIN_C = (
    -1.0 / 6.0,
    1.0 / 120.0,
    -1.0 / 5040.0,
    1.0 / 362880.0,
    -1.0 / 39916800.0,
    1.0 / 6227020800.0,
    -1.0 / 1307674368000.0,
    1.0 / 355687428096000.0,
)

COS_C = (
    -0.5,
    1.0 / 24.0,
    -1.0 / 720.0,
    1.0 / 40320.0,
    -1.0 / 3628800.0,
    1.0 / 479001600.0,
    -1.0 / 87178291200.0,
    1.0 / 20922789888000.0,
)


def _bits(x: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def _from_bits(b: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", b & MASK64))[0]


def _ldexp(y: float, k: int) -> float:
    while k > 1023:
        y *= _from_bits(0x7FE0_0000_0000_0000)
        k -= 1023
    while k < -1022:
        y *= _from_bits(0x0010_0000_0000_0000)
        k += 1022
    return y * _from_bits((1023 + k) << 52)


def _frexp(x: float) -> tuple[float, int]:
    bits = _bits(x)
    exp = (bits >> 52) & 0x7FF
    if exp == 0:
        if x == 0.0:
            return (0.0, 0)
        m, e = _frexp(x * _from_bits(0x4350_0000_0000_0000))
        return (m, e - 54)
    return (_from_bits((bits & 0x800F_FFFF_FFFF_FFFF) | 0x3FE0_0000_0000_0000), exp - 1022)


def _round_i32(x: float) -> int:
    # Rust's `as i32` truncates toward zero, Python's int() does the same.
    if x >= 0.0:
        return int(x + 0.5)
    return int(x - 0.5)


def exp(x: float) -> float:
    if x != x:  # NaN
        return x
    if x > EXP_HI:
        return float("inf")
    if x < EXP_LO:
        return 0.0
    k = _round_i32(x * INV_LN2)
    kf = float(k)
    r = (x - kf * LN2_HI) - kf * LN2_LO

    p = EXP_C[13]
    i = 12
    while i > 0:
        p = EXP_C[i] + r * p
        i -= 1
    p = EXP_C[0] + r * p
    return _ldexp(1.0 + r * p, k)


def ln(x: float) -> float:
    if x != x or x < 0.0:
        return float("nan")
    if x == 0.0:
        return float("-inf")
    if x == float("inf"):
        return float("inf")
    m, e = _frexp(x)
    m *= 2.0
    e -= 1
    if m > SQRT2:
        m *= 0.5
        e += 1
    s = (m - 1.0) / (m + 1.0)
    z = s * s
    p = 1.0 / 23.0
    d = 21.0
    while d > 1.0:
        p = 1.0 / d + z * p
        d -= 2.0
    p = 1.0 + z * p
    ln_m = 2.0 * s * p
    ef = float(e)
    return ef * LN2_HI + (ef * LN2_LO + ln_m)


def ln_1p(x: float) -> float:
    if x != x or x < -1.0:
        return float("nan")
    if x == -1.0:
        return float("-inf")
    if abs(x) < 0.0625:
        term = x
        total = 0.0
        n = 1.0
        while n <= 12.0:
            odd = (int(n) & 1) == 1
            total += (term / n) if odd else -(term / n)
            term *= x
            n += 1.0
        return total
    return ln(1.0 + x)


def _sin_small(r: float) -> float:
    z = r * r
    p = SIN_C[-1]
    i = len(SIN_C) - 2
    while i > 0:
        p = SIN_C[i] + z * p
        i -= 1
    p = SIN_C[0] + z * p
    return r * (1.0 + z * p)


def _cos_small(r: float) -> float:
    z = r * r
    q = COS_C[-1]
    i = len(COS_C) - 2
    while i > 0:
        q = COS_C[i] + z * q
        i -= 1
    q = COS_C[0] + z * q
    return 1.0 + z * q


def cos(x: float) -> float:
    if x != x or x in (float("inf"), float("-inf")):
        return float("nan")
    n = _round_i32(x * TWO_OVER_PI)
    nf = float(n)
    r = ((x - nf * PIO2_1) - nf * PIO2_2) - nf * PIO2_3
    q = n & 3
    if q == 0:
        return _cos_small(r)
    if q == 1:
        return -_sin_small(r)
    if q == 2:
        return -_cos_small(r)
    return _sin_small(r)


# ---------------------------------------------------------------------------
# Digest self-check (same grids as the Rust test module)
# ---------------------------------------------------------------------------

_tbl = []
for _i in range(-240, 241):
    _tbl.append(exp(_i * 0.37))
for _i in range(120):
    _tbl.append(exp(1e-6 * _i))


def _fnv(values) -> int:
    h = 0xCBF2_9CE4_8422_2325
    for v in values:
        for b in struct.pack("<d", v):
            h = ((h ^ b) * 0x0000_0100_0000_01B3) & MASK64
    return h


def digests() -> dict[str, int]:
    import math

    d = {}
    d["exp"] = _fnv(_tbl)
    d["ln"] = _fnv([ln(i * 0.71) for i in range(1, 401)] + [ln(1e-12 * (i + 1)) for i in range(60)])
    d["cos"] = _fnv([cos(math.pi * k * (2 * a + 1) / 18.0) for k in range(9) for a in range(9)])
    d["ln_1p"] = _fnv([ln_1p(i * 0.003) for i in range(200)])
    return d


EXPECTED = {
    "exp": 0x68107BF871D53DF2,
    "ln": 0x6021EF64DB0E27EF,
    "cos": 0x55F3C5ACB971153A,
    "ln_1p": 0x23E6E71DCCF69B20,
}


def main() -> int:
    got = digests()
    ok = True
    for name in ("exp", "ln", "cos", "ln_1p"):
        good = got[name] == EXPECTED[name]
        ok = ok and good
        print(f"{name:<7} {got[name]:016x} {'ok' if good else 'MISMATCH'} (rust {EXPECTED[name]:016x})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
