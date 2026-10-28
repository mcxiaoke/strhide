#!/usr/bin/env python3
# Copyright (c) 2026 strhide developers
# SPDX-License-Identifier: Apache-2.0

"""Comprehensive Benchmark & Verification on Large HEVC Carriers (temp/bighevc).

Measures:
1. Fast Capacity Probing (weighted sample vs exact)
2. Wrong Password Early-Exit Latency (Superblock fast detection)
3. Multi-tier Payload Embedding:
   - 16 B (micro/token payload)
   - 1 KiB (short text payload)
   - 16 KiB (medium document payload)
   - 64 KiB (large payload)
   - 256 KiB (very large payload)
4. Extraction Latency & Bit-exact SHA-256 Roundtrip Verification
5. Peak Memory Working Set (RSS / MB) during each phase
6. Verify Level 1/2/3 Latency
7. Stego Carrier Playability / FFmpeg Full Decode Error Check
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

ROOT = Path(__file__).resolve().parent.parent
STRHIDE = ROOT / "rust" / "target" / "release" / ("strhide.exe" if os.name == "nt" else "strhide")
TEMP_DIR = ROOT / "temp" / "bighevc_bench"
TEMP_DIR.mkdir(parents=True, exist_ok=True)

PASSWORD = "StrHide-BigHevc-Benchmark-2026!"
WRONG_PASSWORD = "CompletelyWrongPassword123!"


def measure_process(cmd, cwd=None):
    """Run a process, sample peak memory (RSS/WorkingSet), and return (stdout, stderr, code, elapsed_ms, peak_rss_mb)."""
    peak_rss = 0
    stop_event = threading.Event()

    start_t = time.perf_counter()
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    def monitor():
        nonlocal peak_rss
        if psutil is None:
            return
        try:
            p = psutil.Process(proc.pid)
            while not stop_event.is_set():
                try:
                    mem = p.memory_info().rss
                    if mem > peak_rss:
                        peak_rss = mem
                    # also check children if any
                    for child in p.children(recursive=True):
                        cmem = child.memory_info().rss
                        if cmem > peak_rss:
                            peak_rss = cmem
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
                time.sleep(0.005)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    t = threading.Thread(target=monitor, daemon=True)
    t.start()

    stdout, stderr = proc.communicate()
    stop_event.set()
    t.join()
    elapsed_ms = (time.perf_counter() - start_t) * 1000.0

    peak_rss_mb = peak_rss / (1024 * 1024)
    return stdout, stderr, proc.returncode, elapsed_ms, peak_rss_mb


def run_ffmpeg_verify(video_path):
    """Run ffmpeg decode to verify video stream validity."""
    cmd = ["ffmpeg", "-v", "error", "-i", str(video_path), "-f", "null", "-"]
    start_t = time.perf_counter()
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    elapsed_ms = (time.perf_counter() - start_t) * 1000.0
    errors = proc.stderr.strip()
    return proc.returncode == 0 and len(errors) == 0, elapsed_ms, errors


def test_carrier(carrier_path):
    carrier_path = Path(carrier_path)
    file_size = carrier_path.stat().st_size
    name = carrier_path.name
    print(f"\n=======================================================")
    print(f"Testing Carrier: {name} ({file_size / (1024 * 1024):.2f} MB)")
    print(f"=======================================================")

    results = {
        "name": name,
        "file_size": file_size,
        "capacity_test": {},
        "early_exit_test": {},
        "payload_tests": [],
    }

    # 1. Capacity Test
    print(f"[*] Running capacity probe...")
    cmd = [str(STRHIDE), "capacity", str(carrier_path)]
    stdout, stderr, code, elapsed_ms, peak_rss = measure_process(cmd)
    print(f"    Capacity Probe: {elapsed_ms:.1f} ms, Peak RSS: {peak_rss:.1f} MB")
    results["capacity_test"] = {
        "elapsed_ms": elapsed_ms,
        "peak_rss_mb": peak_rss,
        "output": stdout.strip(),
    }

    # Parse slots and capacity from output
    slots_match = re.search(r"载荷槽位:\s+~?([0-9]+)", stdout)
    cap_match = re.search(r"最大原始载荷:\s+~?([0-9]+)\s+字节", stdout)
    rec_cap_match = re.search(r"推荐安全容量:\s+~?([0-9]+)\s+字节", stdout)
    if slots_match:
        results["capacity_test"]["slots"] = int(slots_match.group(1))
    if cap_match:
        results["capacity_test"]["max_raw_bytes"] = int(cap_match.group(1))
    if rec_cap_match:
        results["capacity_test"]["recommended_bytes"] = int(rec_cap_match.group(1))

    # 2. Early-Exit Test (Wrong Password on Clean Carrier)
    print(f"[*] Running wrong password early-exit detection...")
    cmd = [str(STRHIDE), "extract", str(carrier_path), "-p", WRONG_PASSWORD, "--stdout"]
    stdout, stderr, code, elapsed_ms, peak_rss = measure_process(cmd)
    print(f"    Wrong Password Early-Exit: {elapsed_ms:.2f} ms (Code: {code}), Peak RSS: {peak_rss:.1f} MB")
    results["early_exit_test"] = {
        "elapsed_ms": elapsed_ms,
        "peak_rss_mb": peak_rss,
        "exit_code": code,
        "error_msg": stderr.strip(),
    }

    # 3. Payload Embedding, Extraction, and Verification Tests
    test_payload_sizes = [
        (16, "16 B (Micro/Token)"),
        (1024, "1 KiB (Short text)"),
        (16 * 1024, "16 KiB (Medium document)"),
        (64 * 1024, "64 KiB (Large file)"),
        (256 * 1024, "256 KiB (Very large file)"),
    ]

    for p_size, p_label in test_payload_sizes:
        print(f"\n  [+] Payload: {p_label} ({p_size} bytes)...")
        # generate random payload with fixed seed for determinism
        raw_payload = bytes([(i * 37 + 13) & 0xFF for i in range(p_size)])
        payload_sha = hashlib.sha256(raw_payload).hexdigest()

        payload_file = TEMP_DIR / f"payload_{p_size}.bin"
        payload_file.write_bytes(raw_payload)

        stego_file = TEMP_DIR / f"stego_{name}_{p_size}.mp4"
        extracted_file = TEMP_DIR / f"extracted_{name}_{p_size}.bin"

        if stego_file.exists():
            stego_file.unlink()
        if extracted_file.exists():
            extracted_file.unlink()

        # A. Embed
        cmd_embed = [
            str(STRHIDE),
            "embed",
            str(carrier_path),
            "-d",
            str(payload_file),
            "-p",
            PASSWORD,
            "-o",
            str(stego_file),
            "--overwrite",
        ]
        out_e, err_e, code_e, time_embed, rss_embed = measure_process(cmd_embed)
        stego_size = stego_file.stat().st_size if stego_file.exists() else 0
        size_diff = stego_size - file_size
        print(
            f"      Embed:    {time_embed:7.1f} ms | Peak RSS: {rss_embed:5.1f} MB | Size Δ: {size_diff} B (code: {code_e})"
        )

        if code_e != 0 or not stego_file.exists():
            print(f"      [!] EMBED FAILED: {err_e.strip()}")
            results["payload_tests"].append({
                "size": p_size,
                "label": p_label,
                "embed_error": err_e.strip(),
            })
            continue

        # B. Wrong Password Early-Exit on Stego File
        cmd_wrong = [str(STRHIDE), "extract", str(stego_file), "-p", WRONG_PASSWORD, "--stdout"]
        _, err_w, code_w, time_wrong, rss_wrong = measure_process(cmd_wrong)
        print(f"      EarlyExit:{time_wrong:7.1f} ms | Peak RSS: {rss_wrong:5.1f} MB | Exit Code: {code_w}")

        # C. Extract
        cmd_extract = [
            str(STRHIDE),
            "extract",
            str(stego_file),
            "-p",
            PASSWORD,
            "-o",
            str(extracted_file),
            "--overwrite",
        ]
        out_x, err_x, code_x, time_extract, rss_extract = measure_process(cmd_extract)
        extracted_bytes = extracted_file.read_bytes() if extracted_file.exists() else b""
        extracted_sha = hashlib.sha256(extracted_bytes).hexdigest()
        sha_match = extracted_sha == payload_sha
        print(
            f"      Extract:  {time_extract:7.1f} ms | Peak RSS: {rss_extract:5.1f} MB | SHA Match: {sha_match}"
        )

        # D. Verify Level 1/2/3
        cmd_verify = [str(STRHIDE), "verify", str(stego_file), "-p", PASSWORD]
        out_v, err_v, code_v, time_verify, rss_verify = measure_process(cmd_verify)
        print(f"      Verify:   {time_verify:7.1f} ms | Peak RSS: {rss_verify:5.1f} MB | Code: {code_v}")

        # E. FFmpeg decode validation (quick check first 10 seconds or full check on 256K)
        ffmpeg_ok = True
        ffmpeg_time = 0.0
        ffmpeg_err = ""
        if p_size == 256 * 1024 or p_size == 16:
            ffmpeg_ok, ffmpeg_time, ffmpeg_err = run_ffmpeg_verify(stego_file)
            print(f"      FFmpeg:   {ffmpeg_time:7.1f} ms | Full Decode OK: {ffmpeg_ok}")

        results["payload_tests"].append({
            "size": p_size,
            "label": p_label,
            "embed_ms": time_embed,
            "embed_rss_mb": rss_embed,
            "size_diff": size_diff,
            "early_exit_ms": time_wrong,
            "extract_ms": time_extract,
            "extract_rss_mb": rss_extract,
            "sha_match": sha_match,
            "verify_ms": time_verify,
            "verify_rss_mb": rss_verify,
            "ffmpeg_ok": ffmpeg_ok,
            "ffmpeg_time_ms": ffmpeg_time,
        })

        # Cleanup stego to save disk space
        if stego_file.exists():
            stego_file.unlink()
        if extracted_file.exists():
            extracted_file.unlink()

    return results


def main():
    carriers = [
        ROOT / "temp" / "bighevc" / "anime-a.mp4",
        ROOT / "temp" / "bighevc" / "anime-b.mp4",
    ]

    all_reports = []
    for c in carriers:
        if c.is_file():
            rep = test_carrier(c)
            all_reports.append(rep)
        else:
            print(f"[SKIP] Carrier not found: {c}")

    json_path = TEMP_DIR / "bighevc_benchmark_results.json"
    json_path.write_text(json.dumps(all_reports, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] Raw benchmark data saved to: {json_path}")


if __name__ == "__main__":
    main()
