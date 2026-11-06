#!/usr/bin/env python3
"""A second implementation of `strhide embed`'s PNG reader, in Python.

Purpose: prove that the parts of the content envelope that matter for *reading*
are fully specified -- key hierarchy, header location, slot selection, STC
syndrome and the AEAD framing -- and that only the cost model decides how hard
a port is. Everything here is derived from `docs/api/WIRE_SPEC_CONTENT.md`;
nothing is imported from the Rust crate.

Scope (intentionally narrow, this is a demonstration not a product):

* PNG carriers only, 8-bit, non-interlaced (colour type 0/2/4/6).
* `algorithm_id = 1` (HILL) or `3` (MiPOD, via `cost_vectors_check.py`).
  S-UNIWARD is not implemented.
* `codec_id = 1` (STC). Hamming carriers are rejected with a clear message.
* No extension TLVs, suite 1 (AES-256-GCM) only.

Needs one non-stdlib dependency for AES-256-GCM: `cryptography`.
(Pure-Python AES would triple the file for no insight.)

Usage:
    python scripts/spec_extract_png.py stego.png
    python scripts/spec_extract_png.py stego.png --password secret
    python scripts/spec_extract_png.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import math
import os
import struct
import sys
import zlib
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Constants mirrored from the specification
# ---------------------------------------------------------------------------

PUBLIC_DEFAULT_SECRET = "strhide-default-content-stego-key-2026"
AAD_PREFIX = b"strhide-content-envelope-v4\0"
PNG_FORMAT_ID = 1
BASE_HEADER_LEN = 64
BASE_SLOTS = 512

DOMAIN_LABEL = b"strhide-stego-domain-v1"
HPOS_LABEL = b"strhide-stego-hpos-v2"
ENC_LABEL = b"enc"
PERM_LABEL = b"perm"
STC_LABEL = b"strhide-stc-trellis-v1"
MAGIC_LABEL = b"strhide-v4-hdr-magic"
HPOS_SALT = b"strhide-stego-hpos-salt-v2"
L1_ITERATIONS = 200_000

SPATIAL_MIN, SPATIAL_MAX = 8, 247


# ---------------------------------------------------------------------------
# ChaCha12 (12 rounds, 64-bit counter, zero nonce) + Fisher-Yates
# ---------------------------------------------------------------------------

CHACHA_C = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
U32 = 0xFFFF_FFFF


class ChaCha12:
    def __init__(self, seed: bytes):
        assert len(seed) == 32
        key = list(struct.unpack("<8I", seed))
        self.state = list(CHACHA_C) + key + [0, 0, 0, 0]
        self.buf = [0] * 16
        self.idx = 16
        self._block()

    @staticmethod
    def _qr(x, a, b, c, d):
        x[a] = (x[a] + x[b]) & U32
        x[d] ^= x[a]
        x[d] = ((x[d] << 16) | (x[d] >> 16)) & U32
        x[c] = (x[c] + x[d]) & U32
        x[b] ^= x[c]
        x[b] = ((x[b] << 12) | (x[b] >> 20)) & U32
        x[a] = (x[a] + x[b]) & U32
        x[d] ^= x[a]
        x[d] = ((x[d] << 8) | (x[d] >> 24)) & U32
        x[c] = (x[c] + x[d]) & U32
        x[b] ^= x[c]
        x[b] = ((x[b] << 7) | (x[b] >> 25)) & U32

    def _block(self):
        x = list(self.state)
        for _ in range(6):
            self._qr(x, 0, 4, 8, 12)
            self._qr(x, 1, 5, 9, 13)
            self._qr(x, 2, 6, 10, 14)
            self._qr(x, 3, 7, 11, 15)
            self._qr(x, 0, 5, 10, 15)
            self._qr(x, 1, 6, 11, 12)
            self._qr(x, 2, 7, 8, 13)
            self._qr(x, 3, 4, 9, 14)
        self.buf = [(x[i] + self.state[i]) & U32 for i in range(16)]
        # 64-bit block counter lives in state[12..14]
        self.state[12] = (self.state[12] + 1) & U32
        if self.state[12] == 0:
            self.state[13] = (self.state[13] + 1) & U32
        self.idx = 0

    def next_u32(self) -> int:
        if self.idx >= 16:
            self._block()
        v = self.buf[self.idx]
        self.idx += 1
        return v

    def next_u64(self) -> int:
        lo = self.next_u32()
        hi = self.next_u32()
        return lo | (hi << 32)

    def gen_range(self, bound: int) -> int:
        if bound <= 1:
            return 0
        if bound <= U32:
            b = bound
            limit = (1 << 32) - ((1 << 32) % b)
            while True:
                r = self.next_u32()
                if r < limit:
                    return r % b
        b = bound
        limit = (1 << 64) - ((1 << 64) % b)
        while True:
            r = self.next_u64()
            if r < limit:
                return r % b


def permute_prefix(items: list[int], k: int, seed: bytes) -> None:
    n = len(items)
    if n <= 1:
        return
    rng = ChaCha12(seed)
    end = min(k, n - 1)
    for i in range(end):
        j = i + rng.gen_range(n - i)
        items[i], items[j] = items[j], items[i]


def permute_indices(items: list[int], seed: bytes) -> None:
    n = len(items)
    if n <= 1:
        return
    rng = ChaCha12(seed)
    for i in range(n - 1, 0, -1):
        j = rng.gen_range(i + 1)
        items[i], items[j] = items[j], items[i]


# ---------------------------------------------------------------------------
# HKDF / PBKDF2 / NFC
# ---------------------------------------------------------------------------


def hkdf_extract(salt: bytes | None, ikm: bytes) -> bytes:
    if salt is None:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def hkdf(salt: bytes | None, ikm: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def info_with_domain(label: bytes, domain: str | None) -> bytes:
    if not domain:
        return label
    d = domain.encode("utf-8")
    return label + struct.pack(">Q", len(d)) + d


# ---------------------------------------------------------------------------
# PNG decoding (8-bit, non-interlaced)
# ---------------------------------------------------------------------------

PNG_SIG = b"\x89PNG\r\n\x1a\n"
CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


@dataclass
class Image:
    width: int
    height: int
    bit_depth: int
    color_type: int
    channels: int
    pixels: bytes
    chunks: list[tuple[bytes, bytes]]


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def decode_png(data: bytes) -> Image:
    if not data.startswith(PNG_SIG):
        raise ValueError("not a PNG")
    pos = len(PNG_SIG)
    chunks: list[tuple[bytes, bytes]] = []
    idat = bytearray()
    ihdr = None
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        ty = data[pos + 4 : pos + 8]
        body = data[pos + 8 : pos + 8 + length]
        pos += 12 + length
        chunks.append((ty, body))
        if ty == b"IHDR":
            ihdr = body
        elif ty == b"IDAT":
            idat += body
        elif ty == b"IEND":
            break
    if ihdr is None:
        raise ValueError("missing IHDR")
    w, h, depth, ctype, comp, filt, interlace = struct.unpack(">IIBBBBB", ihdr)
    if depth != 8 or interlace != 0:
        raise ValueError(f"unsupported PNG: depth={depth} interlace={interlace}")
    ch = CHANNELS[ctype]
    raw = zlib.decompress(bytes(idat))

    stride = w * ch
    out = bytearray(h * stride)
    prev = bytearray(stride)
    src = 0
    for y in range(h):
        f = raw[src]
        src += 1
        line = bytearray(raw[src : src + stride])
        src += stride
        if f == 0:
            pass
        elif f == 2:  # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif f == 1:  # Sub
            for i in range(ch, stride):
                line[i] = (line[i] + line[i - ch]) & 0xFF
        elif f == 3:  # Average
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif f == 4:  # Paeth
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                c = prev[i - ch] if i >= ch else 0
                line[i] = (line[i] + _paeth(a, prev[i], c)) & 0xFF
        else:
            raise ValueError(f"bad filter {f}")
        out[y * stride : (y + 1) * stride] = line
        prev = line
    return Image(w, h, depth, ctype, ch, bytes(out), chunks)


# ---------------------------------------------------------------------------
# Key hierarchy
# ---------------------------------------------------------------------------


def derive_master(password: str, pre_salt: bytes, domain: str | None) -> bytes:
    ikm = password.encode("utf-8")
    if domain:
        sub = hkdf(None, ikm, info_with_domain(DOMAIN_LABEL, domain), 32)
        ikm = sub
    return hashlib.pbkdf2_hmac("sha256", ikm, pre_salt, L1_ITERATIONS, 32)


def derive_l2(master: bytes, domain: str | None) -> tuple[bytes, bytes, bytes, int]:
    locate = hkdf(None, master, info_with_domain(HPOS_LABEL, domain), 32)
    magic4 = hkdf(None, master, info_with_domain(MAGIC_LABEL, domain), 4)
    hdr_stc = struct.unpack(">Q", hkdf(None, master, b"strhide-v4-hdr-stc", 8))[0]
    ext_stc = struct.unpack(">Q", hkdf(None, master, b"strhide-v4-ext-stc", 8))[0]
    return locate, magic4, hdr_stc, ext_stc


def derive_l3(master: bytes, salt: bytes, suite: int, domain: str | None):
    def one(label: bytes, size: int) -> bytes:
        info = info_with_domain(label, domain) + struct.pack(">H", suite)
        return hkdf(salt, master, info, size)

    return one(ENC_LABEL, 32), one(PERM_LABEL, 32), struct.unpack(">Q", one(STC_LABEL, 8))[0]


def png_pre_salt(img: Image) -> bytes:
    meta = hashlib.sha256()
    for ty, body in img.chunks:
        if ty in (b"IDAT", b"prIv"):
            continue
        meta.update(ty)
        meta.update(struct.pack(">I", len(body)))
        meta.update(body)
    out = hashlib.sha256()
    out.update(HPOS_SALT)
    out.update(b"png-v4")
    out.update(struct.pack(">Q", img.width))
    out.update(struct.pack(">Q", img.height))
    out.update(bytes([img.bit_depth, img.color_type, img.channels]))
    out.update(meta.digest())
    return out.digest()


# ---------------------------------------------------------------------------
# Slots
# ---------------------------------------------------------------------------


def header_channel(img: Image) -> int:
    return 1 if img.channels >= 3 else 0


def header_pool(img: Image) -> list[int]:
    hc = header_channel(img)
    ch = img.channels
    px = img.pixels
    return [i for i in range(img.width * img.height) if SPATIAL_MIN <= px[i * ch + hc] <= SPATIAL_MAX]


def read_bits(pixels: bytes, channels: int, slots: list[int], channel: int, nbits: int) -> bytes:
    out = bytearray(nbits // 8)
    for bit in range(nbits):
        v = pixels[slots[bit] * channels + channel]
        out[bit // 8] |= (v & 1) << (7 - (bit % 8))
    return bytes(out)


# ---------------------------------------------------------------------------
# HILL cost map (verbatim from the specification)
# ---------------------------------------------------------------------------


def hill_costs(img: Image, p1: int, p2: int, eps: float) -> list[float]:
    w, h, ch = img.width, img.height, img.channels
    px = img.pixels
    gray = [0.0] * (w * h)
    if ch == 1:
        gray = [float(px[i] & 0xF8) for i in range(w * h)]
    elif ch >= 3:
        for i in range(w * h):
            r = float(px[i * ch] & 0xF8)
            g = float(px[i * ch + 1] & 0xF8)
            b = float(px[i * ch + 2] & 0xF8)
            gray[i] = 0.299 * r + 0.587 * g + 0.114 * b
    else:
        gray = [float(px[i * ch] & 0xF8) for i in range(w * h)]

    pad = 1 + (p1 - 1) // 2 + (p2 - 1) // 2

    def reflect(i: int, n: int) -> int:
        if n <= 1:
            return 0
        period = 2 * n
        i %= period
        return (period - 1 - i) if i >= n else i

    hp, wp = h + 2 * pad, w + 2 * pad
    x = [0.0] * (hp * wp)
    cols = [reflect(j - pad, w) for j in range(wp)]
    for i in range(hp):
        si = reflect(i - pad, h)
        base_o = i * wp
        base_s = si * w
        for j, jj in enumerate(cols):
            x[base_o + j] = gray[base_s + jj]

    kb = (-0.25, 0.50, -0.25, 0.50, -1.00, 0.50, -0.25, 0.50, -0.25)
    h1, w1 = hp - 2, wp - 2
    i1 = [0.0] * (h1 * w1)
    for i in range(h1):
        r0 = (i + 0) * wp
        r1 = (i + 1) * wp
        r2 = (i + 2) * wp
        for j in range(w1):
            v = (
                kb[0] * x[r0 + j]
                + kb[1] * x[r0 + j + 1]
                + kb[2] * x[r0 + j + 2]
                + kb[3] * x[r1 + j]
                + kb[4] * x[r1 + j + 1]
                + kb[5] * x[r1 + j + 2]
                + kb[6] * x[r2 + j]
                + kb[7] * x[r2 + j + 1]
                + kb[8] * x[r2 + j + 2]
            )
            i1[i * w1 + j] = abs(v)

    l1 = 1.0 / float(p1 * p1)
    h2, w2 = h1 - (p1 - 1), w1 - (p1 - 1)
    i2 = [0.0] * (h2 * w2)
    for i in range(h2):
        for j in range(w2):
            s = 0.0
            for u in range(p1):
                row = i1[(i + u) * w1 + j : (i + u) * w1 + j + p1]
                acc = 0.0
                for v in row:
                    acc += v
                s += acc
            avg = s * l1
            i2[i * w2 + j] = 1.0 / max(avg, eps)

    l2 = 1.0 / float(p2)
    tmp = [0.0] * (h * w2)
    for i in range(h):
        for j in range(w2):
            acc = 0.0
            for u in range(p2):
                acc += i2[(i + u) * w2 + j] * l2
            tmp[i * w2 + j] = acc

    cost = [0.0] * (h * w)
    for i in range(h):
        for j in range(w):
            s = 0.0
            for v in tmp[i * w2 + j : i * w2 + j + p2]:
                s += v
            cost[i * w + j] = s * l2
    return cost


# ---------------------------------------------------------------------------
# STC syndrome
# ---------------------------------------------------------------------------


def splitmix64(x: int) -> int:
    x = (x + 0x9E3779B97F4A7C15) & 0xFFFF_FFFF_FFFF_FFFF
    z = x
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFF_FFFF_FFFF_FFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFF_FFFF_FFFF_FFFF
    return z ^ (z >> 31)


def reverse_low_bits(x: int, h: int) -> int:
    out = 0
    for d in range(h):
        if (x >> d) & 1:
            out |= 1 << (h - 1 - d)
    return out


def stc_columns(seed: int, h: int, u: int) -> list[int]:
    mask = (1 << h) - 1

    def pattern(idx: int) -> int:
        x = splitmix64((seed + idx) & 0xFFFF_FFFF_FFFF_FFFF) & U32
        x &= mask
        x |= 1
        x |= 1 << (h - 1)
        return reverse_low_bits(x, h)

    distinct = 1 << (h - 2)
    cols: list[int] = []
    for s in range(u):
        idx = s
        col = pattern(idx)
        while len(cols) < distinct and col in cols:
            idx += u
            col = pattern(idx)
        cols.append(col)
    return cols


def syndrome(vals: bytes, cols: list[int], h: int, u: int, bits: int) -> bytes:
    out = bytearray((bits + 7) // 8)
    for b in range(bits):
        row = b + (h - 1)
        acc = 0
        for g in range(max(0, row - h + 1), row + 1):
            d = row - g
            for si in range(u):
                if (cols[si] >> d) & 1:
                    acc ^= vals[g * u + si] & 1
        if acc:
            out[b // 8] |= 1 << (7 - (b % 8))
    return bytes(out)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def extract(path: str, password: str | None, domain: str | None) -> bytes:
    data = open(path, "rb").read()
    img = decode_png(data)
    secret = password or PUBLIC_DEFAULT_SECRET

    master = derive_master(secret, png_pre_salt(img), domain)
    locate, _magic4, _hdr_stc, _ext_stc = derive_l2(master, domain)

    # Header: prefix-stable keyed permutation over the cost-free eligible pool.
    pool = header_pool(img)
    if len(pool) < BASE_SLOTS:
        raise SystemExit(f"header pool too small: {len(pool)} eligible pixels")
    permute_prefix(pool, BASE_SLOTS, locate)
    hc = header_channel(img)
    header = read_bits(img.pixels, img.channels, pool[:BASE_SLOTS], hc, BASE_HEADER_LEN * 8)

    crc = struct.unpack(">I", header[60:64])[0]
    if zlib.crc32(header[:60]) & 0xFFFF_FFFF != crc:
        raise SystemExit("header CRC mismatch: wrong password, domain or carrier")

    salt = header[0:16]
    nonce = header[16:28]
    body_len = struct.unpack(">I", header[28:32])[0]
    version = header[32]
    algorithm_id = header[35]
    suite = struct.unpack(">H", header[36:38])[0]
    codec_id = header[38]
    stc_h = header[39]
    stc_u = header[40]
    channel_mode = header[41]
    class_rule = header[42]
    p1 = struct.unpack(">H", header[44:46])[0]
    p2 = struct.unpack(">H", header[46:48])[0]
    eps = 2.0 ** -struct.unpack(">H", header[48:50])[0]
    exclusion = struct.unpack(">H", header[50:52])[0]
    ext_len = struct.unpack(">H", header[58:60])[0]

    print(
        f"header: v{version >> 4}.{version & 0xF} algs={algorithm_id} suite={suite} "
        f"codec={codec_id} h={stc_h} u={stc_u} mode={channel_mode} p1={p1} p2={p2} "
        f"excl={exclusion} body_len={body_len} ext={ext_len}"
    )
    if codec_id != 1:
        raise SystemExit("only STC (codec_id=1) carriers are supported here")
    if ext_len:
        raise SystemExit("extension TLVs are not supported by this demo")
    if algorithm_id not in (1, 3):
        raise SystemExit(f"algorithm {algorithm_id} needs a cost model this demo does not port")
    if suite != 1:
        raise SystemExit("only suite 1 (AES-256-GCM) is supported here")

    enc_key, perm_seed, _stc_seed = derive_l3(master, salt, suite, domain)

    # Candidate ranking. MiPOD reuses the pipeline from cost_vectors_check.py,
    # which is checked against the Rust digests stage by stage -- that is the
    # point of having the vector file.
    w, h = img.width, img.height
    ch = img.channels
    if algorithm_id == 1:
        costs = hill_costs(img, p1, p2, eps)
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        import cost_vectors_check as cv

        alpha = min(max(struct.unpack("<f", header[52:56])[0], 0.01), 0.90)
        plane = cv.class_masked_luminance(img.pixels, w, h, ch)
        var = cv.estimate_variance(plane, w, h, 9, 9, 2, 0.01)
        fisher = [2.0 / (v * v) for v in var]
        smoothed = cv.box_smooth(fisher, w, h, 7)
        costs = cv.fisher_to_costs(smoothed, alpha * float(w * h), 20)
    px = img.pixels
    eligible = [i for i in range(w * h) if SPATIAL_MIN <= px[i * ch + hc] <= SPATIAL_MAX]
    eligible.sort(key=lambda i: (struct.unpack("<Q", struct.pack("<d", costs[i]))[0], i))
    allowed = len(eligible) * (1000 - exclusion) // 1000
    candidates = eligible[:allowed]

    used_by_header = set(pool[:BASE_SLOTS])
    bits = body_len * 8
    needed = stc_u * (bits + stc_h - 1)
    channels = [hc] if channel_mode == 0 else [0, 1, 2]

    body: list[int] = []
    for p in candidates:
        reserved = p in used_by_header
        for c in channels:
            if reserved and c == hc:
                continue
            v = px[p * ch + c]
            if not (SPATIAL_MIN <= v <= SPATIAL_MAX):
                continue
            if class_rule == 1 and not (1 <= v % 8 <= 6):
                continue
            body.append(p * ch + c)
            if len(body) >= needed:
                break
        if len(body) >= needed:
            break
    if len(body) < needed:
        raise SystemExit(f"body pool short: {len(body)} < {needed}")

    permute_indices(body, perm_seed)
    vals = bytes(px[s] & 1 for s in body)
    ciphertext = syndrome(vals, stc_columns(_stc_seed, stc_h, stc_u), stc_h, stc_u, bits)
    if len(ciphertext) != body_len:
        raise SystemExit("syndrome length mismatch")

    aad = AAD_PREFIX + bytes([PNG_FORMAT_ID]) + header
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    plain = AESGCM(enc_key).decrypt(nonce, ciphertext, aad)

    orig_len = struct.unpack(">I", plain[0:4])[0]
    flags = plain[4]
    body_plain = plain[5:]
    if flags & 0x01:
        body_plain = zlib.decompress(body_plain, -15)
    tag = body_plain[0]
    if tag == 0x01:
        nlen = body_plain[1]
        name = body_plain[2 : 2 + nlen]
        print(f"payload: file {name!r}, {len(body_plain) - 2 - nlen} bytes")
        payload = body_plain[2 + nlen :]
    else:
        payload = body_plain[1:]
    # `original_len` counts the micro-header (tag + optional name) plus payload.
    if len(body_plain) != orig_len:
        print(f"warning: original_len={orig_len} but recovered {len(body_plain)} pre-tag bytes")
    return payload


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("carrier", nargs="?")
    ap.add_argument("--password")
    ap.add_argument("--domain")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    if args.self_test:
        # prng.rs contract: seed with first byte 1, first 4 bytes of the stream.
        s = ChaCha12(bytes([1]) + bytes(31))
        stream = b"".join(struct.pack("<I", s.next_u32()) for _ in range(8))
        expect = bytes.fromhex("12056e595d56b0f6eef090f0cd25a209" "49248c2790525d0f930218ff0b4ddd10")
        assert stream == expect, f"chacha KAT failed: {stream.hex()}"
        print("chacha12 KAT ok")
        return 0

    if not args.carrier:
        ap.error("carrier is required unless --self-test is given")
    payload = extract(args.carrier, args.password, args.domain)
    if args.out:
        open(args.out, "wb").write(payload)
        print(f"wrote {args.out} ({len(payload)} bytes)")
    else:
        try:
            print(f"payload ({len(payload)} bytes): {payload.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"payload ({len(payload)} bytes, hex): {payload.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
