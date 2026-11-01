#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multi-dimensional Steganalysis & Detectability Evaluation Suite for StrHide.

Scheme A Real-World Quantification:
- PNG: Spatial domain, embedding rates 0.1 bpp and 0.4 bpp (bits per pixel, W * H)
- JPEG: Frequency domain, embedding rates 0.1 bpnzAC and 0.4 bpnzAC (bits per non-zero AC coefficient)
- Payloads dynamically calculated per carrier and rounded to the nearest KiB.
- Carriers: 10 verified high-resolution (15.93 MP) DSLR camera photos from DigitalCamera with standard Annex K tables.

Evaluates 6 steganography algorithms:
- PNG: HILL, MiPOD, S-UNIWARD
- JPEG: UERD, J-MiPOD, J-UNIWARD

Dimensions:
1. Fidelity & Physical Modification: Change Rate (%), MSE, MAE (gray level), PSNR (dB), SSIM, MaxAE
2. Classic Statistical Steganalysis: RS Analysis, SPA, Chi-Square, WS, Stego Score (0-100)
3. High-Pass Residual Dynamics: Laplacian Energy, Residual Kurtosis
4. Rich Models & Machine Learning Detectability: SRMQ1 (12,753 dim) + FLD Ensemble P_E
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import jpeglib
import numpy as np
from PIL import Image

REPO_ROOT = Path(__file__).resolve().parents[1]
STRHIDE_EXE = REPO_ROOT / "rust" / "target" / "release" / "strhide.exe"
DEFAULT_OUT_DIR = REPO_ROOT / "temp" / "stego_evaluation"
PASSWORD = "AlgorithmMatrix#2026"
DEFAULT_SEED = 42

# Ensure stego_eval is on sys.path
sys.path.insert(0, str(REPO_ROOT / "scripts" / "stego_eval"))

import sealwatch as sw
from core.lsb_stat import analyze_lsb_statistics
from core.residuals import analyze_residuals
from sealwatch.ensemble_classifier import FldEnsembleTrainer

# 10 verified Annex K standard DigitalCamera carriers (15.93 MP each)
SELECTED_DC_STEMS = [
    "DSC_20241219_152239",
    "DSC_20241219_153841",
    "DSC_20241219_153940",
    "DSC_20250109_111023",
    "DSC_20250109_112414",
    "DSC_20250109_121034",
    "DSC_20250109_124750",
    "DSC_20250109_125037",
    "DSC_20250319_122838",
    "DSC_20250725_180851",
]


def setup_logger(out_dir: Path) -> logging.Logger:
    logger = logging.getLogger("stego_eval_bpp")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    log_file = out_dir / "eval_bpp.log"
    fh = logging.FileHandler(str(log_file), mode="w", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


def deterministic_payload(size: int, seed: int = DEFAULT_SEED) -> bytes:
    state = seed
    data = bytearray(size)
    for i in range(size):
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        data[i] = (state >> 33) & 0xFF
    return bytes(data)


def load_carriers(
    jpg_root: Path, png_root: Path, selected_stems: list[str] = SELECTED_DC_STEMS, logger: logging.Logger = None
) -> tuple[list[Path], list[Path]]:
    sampled_jpgs = []
    sampled_pngs = []
    for stem in selected_stems:
        j_p = jpg_root / "DigitalCamera" / f"{stem}.jpg"
        p_p = png_root / "DigitalCamera" / f"{stem}.png"
        if not j_p.is_file() or not p_p.is_file():
            raise FileNotFoundError(f"Missing carrier pair for {stem}: {j_p} or {p_p}")
        sampled_jpgs.append(j_p)
        sampled_pngs.append(p_p)

    if logger:
        logger.info(f"Loaded {len(sampled_jpgs)} verified DigitalCamera carriers (Standard Annex K tables).")
    return sampled_jpgs, sampled_pngs


def get_image_pixel_count(path: Path) -> int:
    with Image.open(path) as im:
        w, h = im.size
        return w * h


def get_jpeg_nonzero_ac_count(path: Path) -> int:
    dct = jpeglib.read_dct(str(path))
    return int(np.count_nonzero(dct.Y[:, :, 1:]))


def run_embed_task(
    exe: str, cover_str: str, algo: str, payload_str: str, out_str: str, rate: float, kib: int, rate_unit: str
) -> dict:
    cover = Path(cover_str)
    out_file = Path(out_str)
    cmd = [
        exe,
        "embed",
        cover_str,
        "-d",
        payload_str,
        "-a",
        algo,
        "-p",
        PASSWORD,
        "-o",
        out_str,
        "--overwrite",
    ]
    t0 = time.perf_counter()
    res = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    dt = time.perf_counter() - t0

    if res.returncode == 0 and out_file.is_file() and out_file.stat().st_size > 0:
        return {
            "cover": cover_str,
            "stego": out_str,
            "algo": algo,
            "rate": rate,
            "rate_unit": rate_unit,
            "payload_kib": kib,
            "ok": True,
            "time": dt,
            "err": "",
            "size": out_file.stat().st_size,
        }
    else:
        err_msg = (res.stderr or res.stdout).strip()
        return {
            "cover": cover_str,
            "stego": out_str,
            "algo": algo,
            "rate": rate,
            "rate_unit": rate_unit,
            "payload_kib": kib,
            "ok": False,
            "time": dt,
            "err": err_msg or f"Exit code {res.returncode}",
            "size": 0,
        }


def compute_physical_fidelity(cover_path: Path, stego_path: Path) -> dict:
    with Image.open(cover_path) as c_im, Image.open(stego_path) as s_im:
        c_arr = np.asarray(c_im.convert("RGB"), dtype=np.float64)
        s_arr = np.asarray(s_im.convert("RGB"), dtype=np.float64)

    diff = np.abs(c_arr - s_arr)
    diff_mask = diff > 0
    changed_pixels = np.any(diff_mask, axis=2).sum()
    total_pixels = c_arr.shape[0] * c_arr.shape[1]
    pixel_change_rate = float(changed_pixels / total_pixels)

    mae = float(np.mean(diff))
    mse = float(np.mean((c_arr - s_arr) ** 2))
    max_ae = float(np.max(diff))
    psnr = 999.0 if mse == 0 else float(10.0 * np.log10((255.0**2) / mse))

    y_c = 0.299 * c_arr[:, :, 0] + 0.587 * c_arr[:, :, 1] + 0.114 * c_arr[:, :, 2]
    y_s = 0.299 * s_arr[:, :, 0] + 0.587 * s_arr[:, :, 1] + 0.114 * s_arr[:, :, 2]
    mu_c, mu_s = y_c.mean(), y_s.mean()
    sigma_c = y_c.var()
    sigma_s = y_s.var()
    sigma_cs = np.mean((y_c - mu_c) * (y_s - mu_s))
    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2
    ssim = float(
        ((2 * mu_c * mu_s + c1) * (2 * sigma_cs + c2))
        / ((mu_c**2 + mu_s**2 + c1) * (sigma_c + sigma_s + c2))
    )

    return {
        "pixel_change_rate": round(pixel_change_rate * 100.0, 4),
        "mse": round(mse, 4),
        "mae": round(mae, 4),
        "max_ae": round(max_ae, 2),
        "psnr": round(psnr, 2),
        "ssim": round(ssim, 6),
    }


def analyze_classic_and_residuals(stego_path: Path) -> dict:
    with Image.open(stego_path) as img:
        arr_bgr = np.asarray(img.convert("RGB"))[:, :, ::-1]

    lsb_report = analyze_lsb_statistics(arr_bgr)
    res_report = analyze_residuals(arr_bgr)

    return {
        "rs_est_pct": round(lsb_report["avg_rs_rate"] * 100.0, 2),
        "spa_est_pct": round(lsb_report["avg_spa_rate"] * 100.0, 2),
        "ws_est_pct": round(lsb_report["avg_ws_rate"] * 100.0, 2),
        "chi_max_p": round(lsb_report["max_chi_p_value"], 4),
        "laplacian_var": round(res_report["avg_laplacian_variance"], 2),
        "diff_kurtosis": round(res_report["avg_kurtosis"], 2),
        "classic_stego_score": round(lsb_report["lsb_score"], 1),
    }


def extract_single_srmq1(path_str: str, crop: int = 512) -> tuple[str, np.ndarray]:
    p = Path(path_str)
    with Image.open(p) as im:
        gray = im.convert("L")
        w, h = gray.size
        if min(w, h) > crop:
            left, top = (w - crop) // 2, (h - crop) // 2
            gray = gray.crop((left, top, left + crop, top + crop))
        gray_arr = np.asarray(gray, dtype=np.uint8).copy()

    srm_dict = sw.srmq1.extract(gray_arr)
    feat = np.concatenate([np.asarray(v).ravel() for v in srm_dict.values()]).astype(np.float32)
    return path_str, feat


def eval_pe(
    Xc: np.ndarray, Xs: np.ndarray, splits: int = 5, seed: int = DEFAULT_SEED
) -> tuple[float, float]:
    rng = np.random.default_rng(seed)
    n = len(Xc)
    pes = []

    for s in range(splits):
        idx = np.arange(n)
        rng.shuffle(idx)
        n_tr = max(2, int(round(n * 0.7)))
        tr = idx[:n_tr]
        te = idx[n_tr:] if len(idx[n_tr:]) > 0 else idx[:2]

        trainer = FldEnsembleTrainer(
            Xc=np.ascontiguousarray(Xc[tr]),
            Xs=np.ascontiguousarray(Xs[tr]),
            seed=seed + s,
            verbose=0,
            max_num_base_learners=25,
        )
        ens, _ = trainer.train()
        X_test = np.concatenate([Xc[te], Xs[te]])
        y_test = np.concatenate([-np.ones(len(te)), np.ones(len(te))])
        y_pred = np.sign(ens.predict(X_test))
        p_fa = float(np.mean((y_test == -1) & (y_pred == +1)))
        p_md = float(np.mean((y_test == +1) & (y_pred == -1)))
        pes.append(0.5 * (p_fa + p_md))

    return float(np.mean(pes)), float(np.std(pes))


def main():
    parser = argparse.ArgumentParser(
        description="StrHide Multi-Dimensional Steganalysis (Scheme A: PNG bpp, JPEG bpnzAC)"
    )
    parser.add_argument(
        "--jpg-root", default=r"C:\Home\Data\JPG", help="Path to JPG corpus"
    )
    parser.add_argument(
        "--png-root", default=r"C:\Home\Data\PNG", help="Path to PNG corpus"
    )
    parser.add_argument(
        "--rates",
        default="0.1,0.4",
        help="Comma-separated rates (0.1,0.4: bpp for PNG, bpnzAC for JPEG)",
    )
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help="Directory to save stego files and results",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=4,
        help="Number of parallel worker processes",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stego_dir = out_dir / "stegos_bpp"
    stego_dir.mkdir(parents=True, exist_ok=True)
    payload_dir = out_dir / "payloads_bpp"
    payload_dir.mkdir(parents=True, exist_ok=True)

    logger = setup_logger(out_dir)
    rate_list = [float(x.strip()) for x in args.rates.split(",") if x.strip()]

    logger.info("=" * 100)
    logger.info(" StrHide Multi-Dimensional Steganalysis Evaluation: Scheme A Standard Alignment")
    logger.info(" PNG Load Metric:   bpp (bits per pixel, based on W * H)")
    logger.info(" JPEG Load Metric:  bpnzAC (bits per non-zero AC coefficient, based on DCT nzAC)")
    logger.info(f" Carriers:          10 Verified High-Res (15.93 MP) DSLR Camera Photos (DigitalCamera)")
    logger.info(f" Output Directory:  {out_dir}")
    logger.info(f" Target Rates:      {rate_list} (payloads rounded to KiB per carrier)")
    logger.info(f" Workers (Jobs):    {args.jobs}")
    logger.info("=" * 100)

    jpgs, pngs = load_carriers(Path(args.jpg_root), Path(args.png_root), selected_stems=SELECTED_DC_STEMS, logger=logger)

    png_algos = ["hill", "mipod", "suniward"]
    jpg_algos = ["uerd", "jmipod", "juniward"]

    # Calculate carrier capacities and non-zero AC counts
    logger.info("Calculating carrier statistics (pixels for PNG, nzAC for JPEG)...")
    png_pixels = {}
    for p in pngs:
        pix = get_image_pixel_count(p)
        png_pixels[p] = pix

    jpg_nz_ac = {}
    for j in jpgs:
        nz = get_jpeg_nonzero_ac_count(j)
        jpg_nz_ac[j] = nz
        logger.info(f"  [JPEG] {j.name:<25}: nzAC = {nz:,} (42.1% of AC slots)")

    # Pre-generate dynamic payloads rounded to KiB
    payload_map: dict[tuple[Path, float], tuple[Path, int, str]] = {}
    for p, pixels in png_pixels.items():
        for r in rate_list:
            kib = max(1, round(pixels * r / 8 / 1024))
            nbytes = kib * 1024
            pay_path = payload_dir / f"payload_{p.stem}_{r}bpp_{kib}k.bin"
            if not pay_path.is_file() or pay_path.stat().st_size != nbytes:
                pay_path.write_bytes(deterministic_payload(nbytes))
            payload_map[(p, r)] = (pay_path, kib, "bpp")

    for j, nz in jpg_nz_ac.items():
        for r in rate_list:
            kib = max(1, round(nz * r / 8 / 1024))
            nbytes = kib * 1024
            pay_path = payload_dir / f"payload_{j.stem}_{r}bpnzAC_{kib}k.bin"
            if not pay_path.is_file() or pay_path.stat().st_size != nbytes:
                pay_path.write_bytes(deterministic_payload(nbytes))
            payload_map[(j, r)] = (pay_path, kib, "bpnzAC")

    # --- Execution Loop across Rate Gradients ---
    overall_results = {}

    for rate in rate_list:
        logger.info(f"\n==================================================================================")
        logger.info(f" >>> RUNNING EVALUATION SUITE FOR RATE = {rate:.1f} (PNG: {rate} bpp, JPEG: {rate} bpnzAC)")
        logger.info(f"==================================================================================")

        embed_tasks = []
        for p in pngs:
            pay_path, kib, unit = payload_map[(p, rate)]
            for algo in png_algos:
                stego_path = stego_dir / f"{p.stem}_{algo}_{rate}bpp.png"
                embed_tasks.append((str(STRHIDE_EXE), str(p), algo, str(pay_path), str(stego_path), rate, kib, unit))

        for j in jpgs:
            pay_path, kib, unit = payload_map[(j, rate)]
            for algo in jpg_algos:
                stego_path = stego_dir / f"{j.stem}_{algo}_{rate}bpnzAC.jpg"
                embed_tasks.append((str(STRHIDE_EXE), str(j), algo, str(pay_path), str(stego_path), rate, kib, unit))

        logger.info(f"Embedding {len(embed_tasks)} Stego Carriers (30 PNG + 30 JPG) for rate={rate:.1f}...")
        embed_results = []
        t0 = time.perf_counter()

        with ProcessPoolExecutor(max_workers=args.jobs) as executor:
            futures = {executor.submit(run_embed_task, *task): task for task in embed_tasks}
            completed = 0
            for fut in as_completed(futures):
                res = fut.result()
                embed_results.append(res)
                completed += 1
                status = "PASS" if res["ok"] else "FAIL"
                cover_name = Path(res["cover"]).name
                algo = res["algo"]
                kib = res["payload_kib"]
                unit = res["rate_unit"]
                if res["ok"]:
                    size_kb = res["size"] // 1024
                    logger.info(
                        f"  [{completed:>2}/{len(embed_tasks)}] [{status}] {cover_name:<26} {algo:<8} rate={rate}{unit} payload={kib:>4}KB time={res['time']:>5.2f}s size={size_kb:>5}KB"
                    )
                else:
                    logger.error(
                        f"  [{completed:>2}/{len(embed_tasks)}] [{status}] {cover_name:<26} {algo:<8} rate={rate}{unit} payload={kib:>4}KB time={res['time']:>5.2f}s err={res['err'][:80]}"
                    )

        dt_embed = time.perf_counter() - t0
        logger.info(f"Phase 1 embedding completed in {dt_embed:.2f}s.\n")

        # --- Step 2: Physical Fidelity & Classic Steganalysis ---
        logger.info("Computing Physical Fidelity & Classical Steganalysis Metrics...")
        detailed_results = {algo: [] for algo in png_algos + jpg_algos}

        for r in embed_results:
            if not r["ok"]:
                continue
            cover_path = Path(r["cover"])
            stego_path = Path(r["stego"])
            algo = r["algo"]

            try:
                fid = compute_physical_fidelity(cover_path, stego_path)
                classic = analyze_classic_and_residuals(stego_path)
                item = {
                    "cover": cover_path.name,
                    "stego": stego_path.name,
                    "category": cover_path.parent.name,
                    "rate": rate,
                    "rate_unit": r["rate_unit"],
                    "payload_kib": r["payload_kib"],
                    **fid,
                    **classic,
                }
                detailed_results[algo].append(item)
            except Exception as exc:
                logger.error(f"  Error analyzing {stego_path.name}: {exc}")

        # Summary Table for Fidelity & Classic
        logger.info("\n" + "=" * 140)
        logger.info(f"Fidelity & Classic Stego Summary [Rate = {rate:.1f} (PNG bpp / JPEG bpnzAC)]")
        logger.info(
            f"{'Algorithm':<10} | {'Count':<5} | {'Avg Load':<10} | {'Change%':<9} | {'MSE (Ref=0)':<11} | {'MAE (Ref=0)':<11} | {'PSNR (Ref=∞)':<12} | {'SSIM (Ref=1)':<12} | {'RS Est%':<8} | {'StegoScore':<10}"
        )
        logger.info("-" * 140)
        summary_fidelity = {}
        for algo, rows in detailed_results.items():
            if not rows:
                continue
            avg_kib = float(np.mean([x["payload_kib"] for x in rows]))
            chg = float(np.mean([x["pixel_change_rate"] for x in rows]))
            mse = float(np.mean([x["mse"] for x in rows]))
            mae = float(np.mean([x["mae"] for x in rows]))
            psnr = float(np.mean([x["psnr"] for x in rows]))
            ssim = float(np.mean([x["ssim"] for x in rows]))
            rs = float(np.mean([x["rs_est_pct"] for x in rows]))
            score = float(np.mean([x["classic_stego_score"] for x in rows]))
            summary_fidelity[algo] = {
                "count": len(rows),
                "avg_payload_kib": round(avg_kib, 1),
                "change_pct": round(chg, 4),
                "mse": round(mse, 4),
                "mae": round(mae, 4),
                "psnr": round(psnr, 2),
                "ssim": round(ssim, 6),
                "rs_est": round(rs, 2),
                "stego_score": round(score, 1),
            }
            logger.info(
                f"{algo.upper():<10} | {len(rows):>5} | {avg_kib:>7.1f} KB | {chg:>8.4f}% | {mse:>11.4f} | {mae:>11.4f} | {psnr:>10.2f} dB | {ssim:>12.6f} | "
                f"{rs:>7.2f}% | {score:>8.1f} /100"
            )
        logger.info("=" * 140)

        # --- Step 3: SRMQ1 Rich Model Features & FLD Ensemble P_E ---
        logger.info(f"\nExtracting SRMQ1 (12,753 dim) Features & Training FLD Ensemble for rate={rate:.1f}...")
        t_feat = time.perf_counter()

        # Both PNG and JPEG covers
        all_covers = [str(p) for p in pngs] + [str(j) for j in jpgs]
        cover_feats = {}
        with ProcessPoolExecutor(max_workers=args.jobs) as executor:
            futures = [executor.submit(extract_single_srmq1, cp) for cp in all_covers]
            for fut in as_completed(futures):
                cp, feat = fut.result()
                cover_feats[cp] = feat

        Xc_png = np.array([cover_feats[str(p)] for p in pngs], dtype=np.float32)
        Xc_jpg = np.array([cover_feats[str(j)] for j in jpgs], dtype=np.float32)

        pe_results = {}
        # PNG evaluation
        for algo in png_algos:
            stego_paths = [str(stego_dir / f"{p.stem}_{algo}_{rate}bpp.png") for p in pngs if (stego_dir / f"{p.stem}_{algo}_{rate}bpp.png").is_file()]
            if len(stego_paths) < 4:
                continue

            stego_feats = {}
            with ProcessPoolExecutor(max_workers=args.jobs) as executor:
                futures = [executor.submit(extract_single_srmq1, sp) for sp in stego_paths]
                for fut in as_completed(futures):
                    sp, feat = fut.result()
                    stego_feats[sp] = feat

            Xs = np.array([stego_feats[sp] for sp in stego_paths], dtype=np.float32)
            pe_mean, pe_std = eval_pe(Xc_png[: len(Xs)], Xs, splits=5, seed=DEFAULT_SEED)
            pe_results[algo] = {
                "format": "PNG",
                "p_e_mean": round(pe_mean, 4),
                "p_e_std": round(pe_std, 4),
                "p_a_mean": round(1.0 - pe_mean, 4),
            }
            logger.info(
                f"  [SRMQ1 + FLD Ensemble | PNG  | rate={rate:.1f}] {algo.upper():<10} -> P_E = {pe_mean:.4f} +/- {pe_std:.4f}  "
                f"(Detectability P_A = {(1.0 - pe_mean) * 100:.1f}%)"
            )

        # JPEG evaluation
        for algo in jpg_algos:
            stego_paths = [str(stego_dir / f"{j.stem}_{algo}_{rate}bpnzAC.jpg") for j in jpgs if (stego_dir / f"{j.stem}_{algo}_{rate}bpnzAC.jpg").is_file()]
            if len(stego_paths) < 4:
                continue

            stego_feats = {}
            with ProcessPoolExecutor(max_workers=args.jobs) as executor:
                futures = [executor.submit(extract_single_srmq1, sp) for sp in stego_paths]
                for fut in as_completed(futures):
                    sp, feat = fut.result()
                    stego_feats[sp] = feat

            Xs = np.array([stego_feats[sp] for sp in stego_paths], dtype=np.float32)
            pe_mean, pe_std = eval_pe(Xc_jpg[: len(Xs)], Xs, splits=5, seed=DEFAULT_SEED)
            pe_results[algo] = {
                "format": "JPEG",
                "p_e_mean": round(pe_mean, 4),
                "p_e_std": round(pe_std, 4),
                "p_a_mean": round(1.0 - pe_mean, 4),
            }
            logger.info(
                f"  [SRMQ1 + FLD Ensemble | JPEG | rate={rate:.1f}] {algo.upper():<10} -> P_E = {pe_mean:.4f} +/- {pe_std:.4f}  "
                f"(Detectability P_A = {(1.0 - pe_mean) * 100:.1f}%)"
            )

        logger.info(f"Phase 3 completed for rate={rate:.1f} in {time.perf_counter() - t_feat:.2f}s.")

        overall_results[f"rate_{rate}"] = {
            "rate": rate,
            "fidelity_summary": summary_fidelity,
            "rich_model_pe": pe_results,
            "detailed_rows": detailed_results,
        }

    # Save Master JSON Report
    master_report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "methodology": "Scheme A: PNG bpp vs JPEG bpnzAC",
        "sample_counts": {"png": len(pngs), "jpg": len(jpgs)},
        "results_by_rate": overall_results,
    }
    json_path = out_dir / "evaluation_bpp_summary.json"
    json_path.write_text(json.dumps(master_report, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(f"\n[DONE] Full multi-gradient evaluation report saved to: {json_path}")


if __name__ == "__main__":
    main()
