"""Batch test runner for all files in temp/testfiles.

Tests:
1. Rejection of unsupported files (e.g. APK, Signed PE).
2. Plaintext mode (write -> verify -> read -> remove -> 100% SHA256 match).
3. Encrypted mode (write -> verify -> wrong password check -> read -> remove -> 100% SHA256 match).
4. Stealth mode (write -> inspect -> read -> remove -> 100% SHA256 match).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from typing import Dict, List, Tuple

# Force UTF-8 on Windows stdout
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure strhide is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from strhide.core.crypto import compute_file_sha256
from strhide.core.engine import (
    inspect_carrier,
    read_carrier,
    remove_carrier,
    verify_carrier,
    write_carrier,
)
from strhide.core.rejection import run_all_rejection_checks
from strhide.errors import PasswordError, RejectionError

TESTFILES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "temp", "testfiles"))


def run_batch_tests() -> Tuple[int, int, List[Dict[str, str]]]:
    if not os.path.exists(TESTFILES_DIR):
        print(f"[ERROR] Directory not found: {TESTFILES_DIR}")
        return 0, 1, []

    files = sorted([f for f in os.listdir(TESTFILES_DIR) if os.path.isfile(os.path.join(TESTFILES_DIR, f))])
    print(f"\n=======================================================")
    print(f"Starting batch testing on {len(files)} files in temp/testfiles")
    print(f"=======================================================\n")

    total_tests = 0
    passed_tests = 0
    results_log = []

    for idx, fname in enumerate(files, 1):
        src_path = os.path.join(TESTFILES_DIR, fname)
        file_size = os.path.getsize(src_path)
        size_mb = file_size / (1024 * 1024)
        print(f"[{idx:02d}/{len(files):02d}] Testing '{fname}' ({size_mb:.2f} MB)...")

        # 1. Pre-check for expected rejection (APK, Signed PE, etc.)
        with open(src_path, "rb") as sf:
            expected_rejection = run_all_rejection_checks(sf, src_path)

        if expected_rejection:
            total_tests += 1
            with tempfile.TemporaryDirectory() as tmpdir:
                carrier_copy = os.path.join(tmpdir, fname)
                shutil.copy2(src_path, carrier_copy)
                try:
                    write_carrier(carrier_copy, data_text="payload", password="123")
                    print(f"  [FAIL] Expected rejection, but write_carrier succeeded!")
                    results_log.append({"file": fname, "test": "rejection", "status": "FAIL", "detail": "Not rejected"})
                except RejectionError as e:
                    passed_tests += 1
                    print(f"  [REJECT_OK] Correctly rejected: {e}")
                    results_log.append({"file": fname, "test": "rejection", "status": "PASS", "detail": str(e)})
            continue

        # For supported files, run all 3 modes
        with tempfile.TemporaryDirectory() as tmpdir:
            # --- Test 1: Plaintext Mode ---
            total_tests += 1
            t0 = time.time()
            carrier_plain = os.path.join(tmpdir, "plain_" + fname)
            shutil.copy2(src_path, carrier_plain)
            orig_sha = compute_file_sha256(carrier_plain)
            plain_secret = f"Plaintext secret for {fname} - timestamp {time.time()}"

            try:
                res_w = write_carrier(carrier_plain, data_text=plain_secret, password=None)
                res_v = verify_carrier(carrier_plain)
                if not (res_v["level1_host"]["ok"] and res_v["level2_envelope"]["ok"] and res_v["level3_crypto"]["ok"]):
                    raise RuntimeError(f"Verify failed: {res_v}")
                res_r = read_carrier(carrier_plain)
                if res_r["data"].decode("utf-8") != plain_secret:
                    raise RuntimeError("Plaintext read content mismatch")
                res_rm = remove_carrier(carrier_plain)
                restored_sha = compute_file_sha256(carrier_plain)
                if restored_sha != orig_sha:
                    raise RuntimeError("Restored SHA-256 mismatch")
                passed_tests += 1
                dt = time.time() - t0
                print(f"  [PASS] [PLAIN]   format={res_w['format']:<7} strategy={res_w['strategy']:<14} restore=100% ({dt:.2f}s)")
                results_log.append({"file": fname, "test": "plain", "status": "PASS", "detail": f"{res_w['strategy']}"})
            except Exception as e:
                print(f"  [FAIL] [PLAIN]   FAILED: {e}")
                results_log.append({"file": fname, "test": "plain", "status": "FAIL", "detail": str(e)})

            # --- Test 2: Encrypted Mode ---
            total_tests += 1
            t0 = time.time()
            carrier_enc = os.path.join(tmpdir, "enc_" + fname)
            shutil.copy2(src_path, carrier_enc)
            enc_password = "P@ssw0rd!Secure_2026"
            enc_secret = f"Encrypted secret for {fname} - Key"

            try:
                res_w = write_carrier(carrier_enc, data_text=enc_secret, password=enc_password)
                res_v = verify_carrier(carrier_enc, password=enc_password)
                if not (res_v["level1_host"]["ok"] and res_v["level2_envelope"]["ok"] and res_v["level3_crypto"]["ok"]):
                    raise RuntimeError(f"Verify failed: {res_v}")

                # Test wrong password
                try:
                    read_carrier(carrier_enc, password="WrongPassword!")
                    raise RuntimeError("Expected PasswordError on wrong password!")
                except PasswordError:
                    pass  # Expected!

                res_r = read_carrier(carrier_enc, password=enc_password)
                if res_r["data"].decode("utf-8") != enc_secret:
                    raise RuntimeError("Encrypted read content mismatch")
                res_rm = remove_carrier(carrier_enc)
                restored_sha = compute_file_sha256(carrier_enc)
                if restored_sha != orig_sha:
                    raise RuntimeError("Restored SHA-256 mismatch in encrypted mode")
                passed_tests += 1
                dt = time.time() - t0
                print(f"  [PASS] [ENCRYPT] format={res_w['format']:<7} strategy={res_w['strategy']:<14} restore=100% ({dt:.2f}s)")
                results_log.append({"file": fname, "test": "encrypted", "status": "PASS", "detail": f"{res_w['strategy']}"})
            except Exception as e:
                print(f"  [FAIL] [ENCRYPT] FAILED: {e}")
                results_log.append({"file": fname, "test": "encrypted", "status": "FAIL", "detail": str(e)})

            # --- Test 3: Stealth Mode ---
            total_tests += 1
            t0 = time.time()
            carrier_stl = os.path.join(tmpdir, "stl_" + fname)
            shutil.copy2(src_path, carrier_stl)
            stl_password = "StealthPassword!2026"
            stl_secret = f"Stealth secret for {fname} - Ghost"

            try:
                res_w = write_carrier(carrier_stl, data_text=stl_secret, password=stl_password, stealth=True)
                res_i = inspect_carrier(carrier_stl, password=stl_password)
                if not res_i.get("is_stealth"):
                    raise RuntimeError("Expected is_stealth == True")

                res_r = read_carrier(carrier_stl, password=stl_password)
                if res_r["data"].decode("utf-8") != stl_secret:
                    raise RuntimeError("Stealth read content mismatch")
                res_rm = remove_carrier(carrier_stl, password=stl_password)
                restored_sha = compute_file_sha256(carrier_stl)
                if restored_sha != orig_sha:
                    raise RuntimeError("Restored SHA-256 mismatch in stealth mode")
                passed_tests += 1
                dt = time.time() - t0
                print(f"  [PASS] [STEALTH] format={res_w['format']:<7} strategy={res_w['strategy']:<14} restore=100% ({dt:.2f}s)")
                results_log.append({"file": fname, "test": "stealth", "status": "PASS", "detail": f"{res_w['strategy']}"})
            except Exception as e:
                print(f"  [FAIL] [STEALTH] FAILED: {e}")
                results_log.append({"file": fname, "test": "stealth", "status": "FAIL", "detail": str(e)})

    print(f"\n=======================================================")
    print(f"Batch Test Completed: {passed_tests}/{total_tests} passed ({(passed_tests/total_tests)*100:.1f}%)")
    print(f"=======================================================\n")
    return passed_tests, total_tests, results_log


if __name__ == "__main__":
    passed, total, _ = run_batch_tests()
    sys.exit(0 if passed == total else 1)
