#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stego JPEG capacity/reliability and steganalysis matrix runner.

Runs `strhide embed` over a matrix of (carrier x payload size x group-size
mode) and reports, for every cell: success/failure, the failure mode, the
wall-clock time, whether a successful carrier round-trips through
`strhide extract`, and the post-embed steganalysis scan score/verdict
via `strhide scan`. Predictions of the layout (group size `u`, slot budget)
are computed on the Python side with the same arithmetic as
`rust/src/stego/jpeg/v3_layout.rs::compute` +
`JpegParams::effective_slot_budget`, so the table shows what the engine
*should* pick next to what actually happened.

Usage:
    python scripts/stego_capacity_matrix.py                 # default matrix + scan
    python scripts/stego_capacity_matrix.py --no-scan       # disable steganalysis scan
    python scripts/stego_capacity_matrix.py --full          # every combo
    python scripts/stego_capacity_matrix.py --carriers F:/Temp/stegotest/highres \
        --payloads F:/Temp/stegotest --bin rust/target/release/strhide.exe

Outputs (timestamped, never overwritten):
    temp/stego_matrix_<YYYYMMDD_HHMMSS>.md
    temp/stego_matrix_<YYYYMMDD_HHMMSS>.json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import os
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# JPEG container parsing (SOF geometry + luma AC Huffman table coverage)
# ---------------------------------------------------------------------------

SOF0, SOF1, SOF2 = 0xC0, 0xC1, 0xC2
DHT, SOS = 0xC4, 0xDA
STANDALONE = {0xD8, 0xD9, 0x01, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7}


def parse_jpeg(path: str) -> dict:
    """Geometry + luma AC symbol coverage of a baseline JPEG."""
    data = open(path, "rb").read()
    if data[:2] != b"\xff\xd8":
        raise ValueError("not a JPEG")
    i = 2
    dims = None
    ac_tables: dict[int, tuple[tuple[int, ...], bytes]] = {}
    y_ac_id = None
    n = len(data)
    while i + 1 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        while i < n and data[i] == 0xFF:
            i += 1
        if i >= n:
            break
        marker = data[i]
        i += 1
        if marker in STANDALONE:
            continue
        if marker == 0xD9:
            break
        if i + 2 > n:
            break
        seglen = (data[i] << 8) | data[i + 1]
        if seglen < 2 or i + seglen > n:
            break
        seg = data[i + 2 : i + seglen]
        if marker in (SOF0, SOF1):
            h = (seg[1] << 8) | seg[2]
            w = (seg[3] << 8) | seg[4]
            dims = (w, h)
            nf = seg[5] if len(seg) > 5 else 0
            comps = []
            p = 6
            for _ in range(nf):
                if p + 3 > len(seg):
                    break
                hv = seg[p + 1]
                comps.append((hv >> 4, hv & 0x0F))
                p += 3
            if not comps:
                raise ValueError("SOF has no components")
            y_h, y_v = comps[0]
            max_h = max(ch for ch, _ in comps)
            max_v = max(cv for _, cv in comps)
            mcu_cols = (w + max_h * 8 - 1) // (max_h * 8)
            mcu_rows = (h + max_v * 8 - 1) // (max_v * 8)
            mcu_count = mcu_cols * mcu_rows
            y_blocks = (mcu_cols * y_h) * (mcu_rows * y_v)
            total_blocks = sum(mcu_cols * ch * mcu_rows * cv for ch, cv in comps)
            sampling = f"{max_h}x{max_v}"
        elif marker == SOF2:
            raise ValueError("progressive JPEG (SOF2) is not supported")
        elif marker == DHT:
            p = 0
            while p + 17 <= len(seg):
                tc_th = seg[p]
                tc, th = tc_th >> 4, tc_th & 0x0F
                counts = tuple(seg[p + 1 : p + 17])
                total = sum(counts)
                if p + 17 + total > len(seg):
                    break
                if tc == 1:
                    ac_tables[th] = (counts, bytes(seg[p + 17 : p + 17 + total]))
                p += 17 + total
        elif marker == SOS:
            ns = seg[0]
            # First scan component is luma in every baseline file.
            y_ac_id = seg[2] & 0x0F
            break
        i += seglen
    if dims is None or y_ac_id is None or y_ac_id not in ac_tables:
        raise ValueError("unparsable SOF/SOS/DHT")
    counts, syms = ac_tables[y_ac_id]
    have = {(s >> 4, s & 0x0F) for s in syms}
    missing = [
        (r, c)
        for r in range(16)
        for c in range(1, 11)
        if (r, c) not in have
    ]
    has_eob = 0x00 in syms
    has_zrl = 0xF0 in syms
    complete = has_eob and has_zrl and not missing
    return {
        "width": dims[0],
        "height": dims[1],
        "megapixels": round(dims[0] * dims[1] / 1e6, 1),
        "sampling": sampling,
        "mcu_count": mcu_count,
        "y_blocks": y_blocks,
        "total_blocks": total_blocks,
        "ac_symbols": len(have),
        "ac_symbols_complete": complete,
        "ac_missing": len(missing),
        "ac_missing_sample": [f"(r{r},c{c})" for r, c in missing[:6]],
    }


# ---------------------------------------------------------------------------
# Layout prediction (mirrors v3_layout::compute + effective_slot_budget)
# ---------------------------------------------------------------------------

GRID_SLOTS_PER_BLOCK = 63  # GridRule::ALL_AC, k = 1..63
HDR_SLOTS = 746  # superblock 718 + minimum extension area 28
STC_H = 8
DEFAULT_SLOT_BUDGET = 1_200_000
MAX_AUTO_BACKTRACK_BYTES = 4 << 30  # 4 GiB
KERNEL_MAX_U = 64
BODY_OVERHEAD = 21  # 4-byte length + 1 flags + 16-byte tag
MAX_JPEG_MCU_COUNT = 1_048_576
MAX_JPEG_TOTAL_BLOCKS = 6_291_456
MAX_PIPELINE_BYTES = 8 << 30
PIPELINE_BYTES_PER_BLOCK = 128 + 512 + 63 * 4 + 128


def y_blocks(w: int, h: int) -> int:
    return math.ceil(w / 8) * math.ceil(h / 8)


def preflight_skip_reason(info: dict) -> str:
    """Mirror the Rust resource checks so doomed carriers are not invoked."""
    if info["mcu_count"] > MAX_JPEG_MCU_COUNT:
        return f"image too large ({info['mcu_count']} MCUs; max {MAX_JPEG_MCU_COUNT})"
    if info["total_blocks"] > MAX_JPEG_TOTAL_BLOCKS:
        return (f"image too large ({info['total_blocks']} 8x8 blocks; "
                f"max {MAX_JPEG_TOTAL_BLOCKS})")
    estimated = (64 << 20) + info["total_blocks"] * PIPELINE_BYTES_PER_BLOCK
    if estimated > MAX_PIPELINE_BYTES:
        return f"working-memory budget exceeded (~{estimated >> 20} MiB)"
    return ""


def predict_layout(w: int, h: int, payload_len: int, slot_budget: int | None,
                   is_over_optimised: bool = False, blocks: int | None = None) -> dict:
    """What `embed_once` would compute for this carrier/payload/budget."""
    blocks = blocks if blocks is not None else y_blocks(w, h)
    n_total = blocks * GRID_SLOTS_PER_BLOCK
    body_grid = n_total - HDR_SLOTS
    bits = 8 * (payload_len + BODY_OVERHEAD)
    window = bits + STC_H - 1
    if slot_budget is None:
        budget = max(
            DEFAULT_SLOT_BUDGET,
            min(body_grid // 4, MAX_AUTO_BACKTRACK_BYTES // 32),
        )
    else:
        budget = slot_budget

    u_capacity = body_grid // window if window else 0
    u_budget = max(budget // window, 1) if window else 0
    u = min(u_capacity, u_budget, KERNEL_MAX_U) if window else 0

    # On an over-optimised table, u < 3 is lifted to u = 3 (grouped floor)
    # or rejected if u = 3 does not fit.
    if is_over_optimised and u < 3:
        room = min(body_grid, (4 << 30) // 32)
        if window > 0 and room // window >= 3:
            budget = max(budget, 3 * window)
            u_budget = budget // window
            u = min(u_capacity, u_budget, KERNEL_MAX_U)
        else:
            u = 0  # Infeasible for over-optimised carrier

    return {
        "blocks": blocks,
        "n_total": n_total,
        "body_grid": body_grid,
        "bits": bits,
        "window": window,
        "budget": budget,
        "u": u,
        "body_n": u * window,
        "bitmap_mib": round(u * window * 32 / 2**20, 1),
        "grid_fill_pct": round(100.0 * u * window / body_grid, 1) if body_grid else 0.0,
    }


def u1_boundary_payload(w: int, h: int, blocks: int | None = None) -> int:
    """Largest payload the *automatic* budget still carries at u >= 2."""
    blocks = blocks if blocks is not None else y_blocks(w, h)
    body_grid = blocks * GRID_SLOTS_PER_BLOCK - HDR_SLOTS
    budget = max(DEFAULT_SLOT_BUDGET, min(body_grid // 4, MAX_AUTO_BACKTRACK_BYTES // 32))
    return (budget // 2 - (STC_H - 1)) // 8 - BODY_OVERHEAD


# ---------------------------------------------------------------------------
# Matrix execution
# ---------------------------------------------------------------------------

QUICK_PAYLOADS = ["128k", "256k", "512k", "1m"]
QUICK_FORCED = ["512k", "1m"]
FULL_PAYLOADS = ["1k", "8k", "16k", "64k", "128k", "256k", "368k", "512k", "700k", "1m", "2m"]
FULL_FORCED = ["512k", "700k", "1m"]
FORCED_MODES = [2, 3, 4]


def classify(output: str) -> tuple[str, str]:
    """(ok|fail, mode) from the CLI output."""
    if "[OK]" in output:
        return "ok", ""
    if "image too large" in output:
        return "fail", "M:mcu-limit"
    if "working memory" in output or "budget would be exceeded" in output:
        return "fail", "R:resource-limit"
    if "required for this payload size" in output:
        return "fail", "A:u1-infeasible"
    if "cannot encode (run" in output:
        return "fail", "B:missing-symbol"
    if "required for this carrier" in output:
        return "fail", "A:u1-infeasible(header)"
    if "Capacity exceeded" in output:
        return "fail", "C:capacity"
    if "not found" in output:
        return "fail", "X:file-missing"
    if "exceeds safety threshold" in output:
        return "fail", "X:policy"  # only when enforcement blocks it
    return "fail", "Z:other"


def run_embed(binary: str, carrier: str, payload: str, out: str, password: str,
              slot_budget: int | None, timeout: int) -> dict:
    cmd = [binary, "embed", "--overwrite"]
    if slot_budget is not None:
        cmd += ["--slot-budget", str(slot_budget)]
    cmd += ["-d", payload, "-p", password, carrier, "-o", out]
    # Always ask the engine for attempt-level diagnostics; they are stderr-only
    # and let the matrix report how many full re-solves a cell needed.
    env = dict(os.environ, STRHIDE_STEGO_TRACE="1")
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, env=env)
        elapsed = time.monotonic() - t0
        output = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        return {"status": "fail", "mode": "X:timeout", "elapsed_s": round(time.monotonic() - t0, 1),
                "detail": f"timeout after {timeout}s", "attempts": 0}
    status, mode = classify(output)
    attempts = 0
    for line in output.splitlines():
        if line.startswith("[stego] attempt "):
            try:
                attempts = max(attempts, int(line.split()[2].split("/")[0]))
            except (IndexError, ValueError):
                pass
    detail = ""
    for line in output.splitlines():
        if line.startswith("[ERROR]"):
            detail = line.split(":", 1)[-1].strip()[:160]
            break
    return {"status": status, "mode": mode, "elapsed_s": round(elapsed, 1),
            "detail": detail, "attempts": attempts}


def run_extract(binary: str, stego: str, payload: str, out: str, password: str,
                timeout: int) -> str:
    cmd = [binary, "extract", "--overwrite", "-p", password, stego, "-o", out]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        if proc.returncode != 0 or not os.path.exists(out):
            return "extract-failed"
        with open(payload, "rb") as f:
            want = f.read()
        with open(out, "rb") as f:
            got = f.read()
        return "roundtrip-ok" if want == got else "roundtrip-MISMATCH"
    except subprocess.TimeoutExpired:
        return "extract-timeout"


def run_scan(binary: str, stego: str, timeout: int = 60) -> dict:
    """Run `strhide scan --json` to get quantitative steganalysis score."""
    cmd = [binary, "scan", "--json", stego]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        if proc.returncode in (0, 1) and proc.stdout:
            data = json.loads(proc.stdout)
            if isinstance(data, list) and data:
                report = data[0]
                return {
                    "risk_score": report.get("risk_score", 0),
                    "verdict": report.get("verdict", "unknown"),
                }
    except Exception as e:
        return {"risk_score": -1, "verdict": f"err:{e}"}
    return {"risk_score": -1, "verdict": "scan-fail"}


def fmt_cell(r: dict) -> str:
    if r["status"] == "ok":
        mark = "OK"
    else:
        mark = {"A:u1-infeasible": "X", "A:u1-infeasible(header)": "X",
                "B:missing-symbol": "S", "C:capacity": "C",
                "O:opt-table-u3": "O", "G:geometry": "G",
                "M:mcu-limit": "M", "R:resource-limit": "R",
                "X:file-missing": "?", "X:timeout": "T", "X:policy": "P"}.get(r["mode"], "!")
    return f"{mark} {r['elapsed_s']:>5.1f}s"


def md_escape(text: str, limit: int = 160) -> str:
    """Escape a Markdown table cell and truncate it with an ellipsis."""
    text = (text or "-").replace("|", r"\|").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "…"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--carriers", default="F:/Temp/stegotest/highres")
    ap.add_argument("--pattern", default="img*.jpg",
                    help="glob applied inside --carriers (keeps stego outputs out)")
    ap.add_argument("--payloads", default="F:/Temp/stegotest")
    ap.add_argument("--bin", default="rust/target/release/strhide.exe")
    ap.add_argument("--out", default="temp")
    ap.add_argument("--password", default="12345678")
    ap.add_argument("--full", action="store_true", help="run every payload/mode combo")
    ap.add_argument("--scan", action=argparse.BooleanOptionalAction, default=True,
                    help="run steganalysis scan on successful embeds (default: enabled)")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--carrier", action="append", help="restrict to these carrier files")
    args = ap.parse_args()

    binary = os.path.abspath(args.bin)
    if not os.path.exists(binary):
        print(f"binary not found: {binary}", file=sys.stderr)
        return 2

    import fnmatch

    carriers = sorted(
        os.path.join(args.carriers, f)
        for f in os.listdir(args.carriers)
        if fnmatch.fnmatch(f.lower(), args.pattern.lower())
    )
    if args.carrier:
        wanted = {os.path.basename(c) for c in args.carrier}
        carriers = [c for c in carriers if os.path.basename(c) in wanted]

    payload_names = FULL_PAYLOADS if args.full else QUICK_PAYLOADS
    forced_names = FULL_FORCED if args.full else QUICK_FORCED

    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(args.out, exist_ok=True)
    md_path = os.path.join(args.out, f"stego_matrix_{stamp}.md")
    json_path = os.path.join(args.out, f"stego_matrix_{stamp}.json")
    log_path = os.path.join(args.out, f"stego_matrix_{stamp}.log")
    log = open(log_path, "w", encoding="utf-8")

    def say(msg: str) -> None:
        print(msg, flush=True)
        log.write(msg + "\n")
        log.flush()

    say(f"# carriers: {len(carriers)}  payloads(auto): {payload_names}  "
        f"forced: {forced_names} x {FORCED_MODES}  scan: {args.scan}")
    results: list[dict] = []
    for carrier in carriers:
        name = os.path.basename(carrier)
        try:
            info = parse_jpeg(carrier)
        except ValueError as e:
            say(f"[skip] {name}: {e}")
            continue
        w, h = info["width"], info["height"]
        blocks = info["y_blocks"]
        is_opt = not info["ac_symbols_complete"]
        say(f"\n== {name}  {w}x{h} ({info['megapixels']}MP, {info['sampling']})  "
            f"AC symbols {info['ac_symbols']}/162 complete={info['ac_symbols_complete']} "
            f"missing={info['ac_missing']}  blocks={blocks}  MCUs={info['mcu_count']}  "
            f"u1-boundary={u1_boundary_payload(w, h, blocks)} B")

        # Doomed carriers: record every cell instead of launching eight calls that
        # are guaranteed to fail in the decoder's preflight.
        skip_reason = preflight_skip_reason(info)
        if skip_reason:
            mode_class = "R:resource-limit"
            if "too large" in skip_reason:
                mode_class = "M:mcu-limit"
            say(f"   [skip] {skip_reason}")
            cells = [(p, "auto", 0) for p in payload_names]
            cells += [(p, f"u{u}", u) for p in forced_names for u in FORCED_MODES]
            for pname, mode, u in cells:
                results.append({
                    "carrier": name, "payload": pname, "mode": mode,
                    "predicted_u": u, "grid_fill_pct": 0.0, "bitmap_mib": 0.0,
                    "status": "skip", "mode_class": mode_class, "elapsed_s": 0.0,
                    "detail": skip_reason, "roundtrip": "",
                    "scan_risk": -1, "scan_verdict": "", "scan_delta": -1, "attempts": 0,
                })
            continue

        cover_scan = run_scan(binary, carrier, timeout=args.timeout) if args.scan else {
            "risk_score": -1, "verdict": ""
        }
        say(f"   cover scan baseline: {cover_scan['risk_score']}/100 ({cover_scan['verdict']})")

        # ---- automatic budget: every payload size ----
        for pname in payload_names:
            payload = os.path.join(args.payloads, f"payload-{pname}.bin")
            if not os.path.exists(payload):
                say(f"   [skip] payload-{pname}.bin missing")
                continue
            plen = os.path.getsize(payload)
            pred = predict_layout(w, h, plen, None, is_over_optimised=is_opt, blocks=blocks)
            if pred["u"] == 0:
                say(f"   {pname:>5} auto: predicted capacity exceeded (or u>=3 infeasible on opt table), skipping run")
                results.append({"carrier": name, "payload": pname, "mode": "auto",
                                "predicted_u": 0, "grid_fill_pct": 0.0, "bitmap_mib": 0.0,
                                "status": "skip", "mode_class": "O:opt-table-u3" if is_opt else "C:capacity",
                                "elapsed_s": 0.0, "detail": "predicted capacity exceeded",
                                "roundtrip": "", "scan_risk": -1, "scan_verdict": "",
                                "scan_delta": -1, "attempts": 0})
                continue
            out = os.path.join(args.out, f"_matrix_{name}_{pname}_auto.jpg")
            r = run_embed(binary, carrier, payload, out, args.password, None, args.timeout)
            rt = ""
            scan_res = {"risk_score": -1, "verdict": ""}
            if r["status"] == "ok":
                rt_bin = os.path.join(args.out, f"_matrix_{name}_{pname}_auto.bin")
                rt = run_extract(binary, out, payload, rt_bin, args.password, args.timeout)
                if os.path.exists(rt_bin):
                    os.remove(rt_bin)
                if args.scan:
                    scan_res = run_scan(binary, out, timeout=args.timeout)
            delta = (scan_res["risk_score"] - cover_scan["risk_score"]
                     if scan_res["risk_score"] >= 0 and cover_scan["risk_score"] >= 0 else -1)
            scan_info = (f" | scan: {scan_res['risk_score']}/100 (Δ{delta:+d}) "
                         if args.scan and r["status"] == "ok" else "")
            say(f"   {pname:>5} auto u={pred['u']:<2} ({pred['grid_fill_pct']:>4.1f}% grid, "
                f"{pred['bitmap_mib']:>6.1f} MiB): {fmt_cell(r)} {rt}{scan_info}")
            results.append({"carrier": name, "payload": pname, "mode": "auto",
                            "predicted_u": pred["u"], "grid_fill_pct": pred["grid_fill_pct"],
                            "bitmap_mib": pred["bitmap_mib"], "status": r["status"],
                            "mode_class": r["mode"], "elapsed_s": r["elapsed_s"],
                            "detail": r["detail"], "roundtrip": rt,
                            "scan_risk": scan_res["risk_score"], "scan_verdict": scan_res["verdict"],
                            "scan_delta": delta, "attempts": r.get("attempts", 0)})
            if os.path.exists(out):
                os.remove(out)

        # ---- forced group sizes on the stress payloads ----
        for pname in forced_names:
            payload = os.path.join(args.payloads, f"payload-{pname}.bin")
            if not os.path.exists(payload):
                continue
            plen = os.path.getsize(payload)
            for u in FORCED_MODES:
                pred = predict_layout(w, h, plen,
                                      u * (8 * (plen + BODY_OVERHEAD) + STC_H - 1),
                                      is_over_optimised=is_opt, blocks=blocks)
                if pred["u"] != u:
                    say(f"   {pname:>5} u={u}: predicted u={pred['u']} (capped/infeasible), skipping")
                    mode_class = "O:opt-table-u3" if is_opt and u < 3 else "G:geometry"
                    results.append({"carrier": name, "payload": pname, "mode": f"u{u}",
                                    "predicted_u": pred["u"], "grid_fill_pct": pred["grid_fill_pct"],
                                    "bitmap_mib": pred["bitmap_mib"], "status": "skip",
                                    "mode_class": mode_class, "elapsed_s": 0.0,
                                    "detail": "predicted layout is infeasible for the forced group size",
                                    "roundtrip": "", "scan_risk": -1, "scan_verdict": "",
                                    "scan_delta": -1, "attempts": 0})
                    continue
                out = os.path.join(args.out, f"_matrix_{name}_{pname}_u{u}.jpg")
                r = run_embed(binary, carrier, payload, out, args.password,
                              u * (8 * (plen + BODY_OVERHEAD) + STC_H - 1), args.timeout)
                rt = ""
                scan_res = {"risk_score": -1, "verdict": ""}
                if r["status"] == "ok":
                    rt_bin = os.path.join(args.out, f"_matrix_{name}_{pname}_u{u}.bin")
                    rt = run_extract(binary, out, payload, rt_bin, args.password, args.timeout)
                    if os.path.exists(rt_bin):
                        os.remove(rt_bin)
                    if args.scan:
                        scan_res = run_scan(binary, out, timeout=args.timeout)
                delta = (scan_res["risk_score"] - cover_scan["risk_score"]
                         if scan_res["risk_score"] >= 0 and cover_scan["risk_score"] >= 0 else -1)
                scan_info = (f" | scan: {scan_res['risk_score']}/100 (Δ{delta:+d}) "
                             if args.scan and r["status"] == "ok" else "")
                say(f"   {pname:>5} u={u} ({pred['grid_fill_pct']:>4.1f}% grid, "
                    f"{pred['bitmap_mib']:>6.1f} MiB): {fmt_cell(r)} {rt}{scan_info}")
                results.append({"carrier": name, "payload": pname, "mode": f"u{u}",
                                "predicted_u": u, "grid_fill_pct": pred["grid_fill_pct"],
                                "bitmap_mib": pred["bitmap_mib"], "status": r["status"],
                                "mode_class": r["mode"], "elapsed_s": r["elapsed_s"],
                                "detail": r["detail"], "roundtrip": rt,
                                "scan_risk": scan_res["risk_score"], "scan_verdict": scan_res["verdict"],
                                "scan_delta": delta, "attempts": r.get("attempts", 0)})
                if os.path.exists(out):
                    os.remove(out)

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"generated": stamp, "binary": binary, "results": results}, f,
                  ensure_ascii=False, indent=1)

    lines = []
    lines.append(f"# strhide stego matrix ({stamp})")
    lines.append("")
    lines.append(f"binary: `{binary}`  password: `{args.password}`  scan: `{args.scan}`")
    lines.append("")
    lines.append("Cell legend: `OK t` = embedded in t s and round-tripped; "
                 "`X t` = failed, mode A (dead slot / no legal element); "
                 "`S t` = failed, mode B (post-hoc missing Huffman symbol); "
                 "`C` = geometric capacity exceeded; `O` = over-optimised table, "
                 "u>=3 does not fit; `G` = forced group size geometrically infeasible; "
                 "`M` = MCU/block resource limit; `R` = working-memory budget; "
                 "`P` = safety policy; `T` = timeout; `?` = file missing; `!` = unclassified.")
    lines.append("")
    by_carrier: dict[str, list[dict]] = {}
    for r in results:
        by_carrier.setdefault(r["carrier"], []).append(r)
    for name, rows in by_carrier.items():
        info = parse_jpeg(os.path.join(args.carriers, name))
        lines.append(f"## {name} — {info['width']}x{info['height']} "
                     f"({info['megapixels']} MP, {info['sampling']}, "
                     f"{info['y_blocks']} luma blocks, {info['mcu_count']} MCUs)")
        lines.append("")
        lines.append(f"- luma AC table: {info['ac_symbols']}/162 symbols, "
                     f"complete={info['ac_symbols_complete']}, missing={info['ac_missing']}"
                     + (f" (e.g. {', '.join(info['ac_missing_sample'])})" if info['ac_missing'] else ""))
        lines.append(f"- automatic-budget u=1 boundary: payloads above "
                     f"{u1_boundary_payload(info['width'], info['height'], info['y_blocks'])} B fall to u=1")
        lines.append("")
        if args.scan:
            lines.append("| payload | mode | u | scan risk | Δrisk | verdict | round-trip | elapsed | grid fill | bitmap | detail |")
            lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
        else:
            lines.append("| payload | mode | u | round-trip | elapsed | grid fill | bitmap | detail |")
            lines.append("|---|---|---|---|---|---|---|---|")

        for r in rows:
            cell = fmt_cell(r) if r["status"] != "skip" else "skipped"
            scan_col = f"{r['scan_risk']}/100" if r.get("scan_risk", -1) >= 0 else "-"
            delta_col = f"{r['scan_delta']:+d}" if r.get("scan_delta", -1) >= 0 else "-"
            verdict_col = r.get("scan_verdict") or "-"
            detail = md_escape(r["detail"])
            if args.scan:
                lines.append(f"| {r['payload']} | {r['mode']} | {r['predicted_u']} | "
                             f"{scan_col} | {delta_col} | {verdict_col} | "
                             f"{r['roundtrip'] or '-'} | {r['elapsed_s']}s | "
                             f"{r['grid_fill_pct']}% | {r['bitmap_mib']} MiB | {detail} |")
            else:
                lines.append(f"| {r['payload']} | {r['mode']} | {r['predicted_u']} | "
                             f"{r['roundtrip'] or '-'} | {r['elapsed_s']}s | "
                             f"{r['grid_fill_pct']}% | {r['bitmap_mib']} MiB | {detail} |")
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    ok = sum(1 for r in results if r["status"] == "ok")
    fail = sum(1 for r in results if r["status"] == "fail")
    skip = sum(1 for r in results if r["status"] == "skip")
    lines.append(f"- {ok}/{len(results)} cells embedded successfully; "
                 f"{sum(1 for r in results if r['roundtrip'] == 'roundtrip-ok')} round-tripped bit-exact.")
    lines.append(f"- closure: {ok} ok + {fail} failed + {skip} skipped = "
                 f"{ok + fail + skip} (records: {len(results)}).")
    if args.scan and ok > 0:
        clean_count = sum(1 for r in results if r["status"] == "ok" and r.get("scan_delta", -1) <= 0)
        low_count = sum(1 for r in results if r["status"] == "ok" and 0 < r.get("scan_delta", -1) <= 25)
        high_count = sum(1 for r in results if r["status"] == "ok" and r.get("scan_delta", -1) > 25)
        lines.append(f"- Steganalysis Δrisk (successful embeds, vs cover baseline): "
                     f"{clean_count} no increase, {low_count} +1..25, {high_count} >+25.")
        lines.append("- A single clean/low verdict is not evidence of absence: "
                     "the cover baseline and Δrisk are the meaningful numbers.")

    modes: dict[str, int] = {}
    for r in results:
        if r["status"] in ("fail", "skip"):
            modes[r["mode_class"]] = modes.get(r["mode_class"], 0) + 1
    for k, v in sorted(modes.items()):
        lines.append(f"- {k}: {v}")
    lines.append("")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\nwrote {md_path}")
    print(f"wrote {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
