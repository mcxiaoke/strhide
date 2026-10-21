import os
import sys
import time
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Tuple
from concurrent.futures import ThreadPoolExecutor
import cv2 as cv
import numpy as np

SELF_DIR = Path(__file__).resolve().parent
if str(SELF_DIR) not in sys.path:
    sys.path.insert(0, str(SELF_DIR))

try:
    from .core.structure import analyze_file_structure
    from .core.lsb_stat import analyze_lsb_statistics
    from .core.residuals import analyze_residuals
    from .core.jpeg_stat import analyze_jpeg_domain
    from .core.dl_detector import run_dl_detection, get_dl_bridge
    from .core.scoring import compute_composite_verdict
except (ImportError, ValueError):
    from core.structure import analyze_file_structure
    from core.lsb_stat import analyze_lsb_statistics
    from core.residuals import analyze_residuals
    from core.jpeg_stat import analyze_jpeg_domain
    from core.dl_detector import run_dl_detection, get_dl_bridge
    from core.scoring import compute_composite_verdict

class StegoEvaluator:
    """
    Unified Steganography Evaluation Engine for StrHide and general steganalysis.
    
    Can be used:
    1. As a Python library in any Python environment (with cross-Python CUDA acceleration).
    2. Via CLI with directory scanning, file list inputs, and Rich reports.
    """
    def __init__(self, enable_dl: bool = True, cuda_python: Optional[str] = None):
        self.enable_dl = enable_dl
        self.cuda_python = cuda_python
        self.dl_bridge = get_dl_bridge(cuda_python=cuda_python, enable=enable_dl)

    def evaluate_image(self, image_path: Union[str, Path], precomputed_dl: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Evaluate a single image file through all 5 analysis tiers."""
        p = Path(image_path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Target image not found: {p}")

        t0 = time.perf_counter()
        ext = p.suffix.lower()
        is_jpeg = ext in (".jpg", ".jpeg")

        # Tier 1: Container & Structure Integrity
        struct_res = analyze_file_structure(p)

        # Read image matrix via OpenCV (fast BGR uint8)
        img_bgr = cv.imread(str(p), cv.IMREAD_COLOR)
        if img_bgr is None:
            raise ValueError(f"Failed to decode image file: {p}")

        # Tier 2: Spatial LSB Statistics (SIMD RS, SPA, Chi2, WS, Even/Odd)
        lsb_res = analyze_lsb_statistics(img_bgr)

        # Tier 3: High-pass Residual Dynamics
        residual_res = analyze_residuals(img_bgr)

        # Tier 4: Frequency & DCT Domain
        jpeg_res = analyze_jpeg_domain(img_bgr, is_jpeg_file=is_jpeg)

        # Tier 5: Deep Learning (SRNet via CUDA Bridge or precomputed)
        if precomputed_dl is not None:
            dl_res = precomputed_dl
        else:
            dl_res = run_dl_detection(p, enable=self.enable_dl, cuda_python=self.cuda_python)

        # Unified Fusion Verdict
        summary = compute_composite_verdict(struct_res, lsb_res, residual_res, jpeg_res, dl_res)

        total_time_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        summary["processing_time_ms"] = total_time_ms

        return {
            "filepath": str(p),
            "filename": p.name,
            "format": "JPEG" if is_jpeg else "PNG",
            "summary": summary,
            "details": {
                "structure": struct_res,
                "lsb_statistics": lsb_res,
                "residuals": residual_res,
                "jpeg_domain": jpeg_res,
                "deep_learning": dl_res,
            }
        }

    def evaluate_fast_image(self, image_path: Union[str, Path], dl_raw: Dict[str, Any]) -> Dict[str, Any]:
        """Ultra-fast evaluation: Structure + Batched GPU SRNet (skips slow CPU pixel masks)."""
        p = Path(image_path).resolve()
        t0 = time.perf_counter()
        ext = p.suffix.lower()
        is_jpeg = ext in (".jpg", ".jpeg")

        # Quick structure check
        struct_res = analyze_file_structure(p)

        # Format DL res
        preds = dl_raw.get("predictions", {})
        prob = dl_raw.get("prob", 0.0)
        top_tag = max(preds, key=preds.get) if preds else dl_raw.get("device_name", "CUDA")
        tag = f"Ensemble ({dl_raw.get('device_name', 'CUDA')})"
        dl_res = {
            "enabled": True,
            "status": f"Executed ({tag})",
            "dl_score": round(prob * 100.0, 1),
            "predictions": preds if preds else {tag: round(prob, 4)},
            "max_stego_prob": round(prob, 4),
            "avg_stego_prob": dl_raw.get("avg_stego_prob", round(prob, 4)),
            "latency_ms": dl_raw.get("latency_ms", 0.0),
        }

        # Fast verdict fusion
        final_score = round(prob * 100.0, 1)
        suspected = []
        if struct_res.get("has_structural_anomaly", False):
            suspected.append("Structural Anomaly")
            final_score = max(final_score, 75.0)

        if final_score >= 70.0:
            verdict = "HIGH_RISK"
        elif final_score >= 45.0:
            verdict = "SUSPICIOUS"
        elif final_score >= 25.0:
            verdict = "LOW_RISK"
        else:
            verdict = "CLEAN"

        dt_ms = round((time.perf_counter() - t0) * 1000.0 + dl_raw.get("latency_ms", 0.0), 2)
        summary = {
            "stego_score": final_score,
            "verdict": verdict,
            "confidence": "HIGH",
            "estimated_payload_pct": 0.0,
            "tier_scores": {
                "structure": struct_res.get("anomaly_score", 0.0),
                "lsb_stat": 0.0,
                "residuals": 0.0,
                "jpeg_domain": 0.0,
                "deep_learning": final_score,
            },
            "suspected_techniques": suspected,
            "key_reasons": [f"Deep learning max prob: {prob*100:.1f}% ({top_tag})"],
            "processing_time_ms": dt_ms,
        }

        return {
            "filepath": str(p),
            "filename": p.name,
            "format": "JPEG" if is_jpeg else "PNG",
            "summary": summary,
            "details": {
                "structure": struct_res,
                "deep_learning": dl_res,
            }
        }

    def evaluate_batch(self, image_paths: List[Union[str, Path]], mode: str = "full", show_progress: bool = False) -> Dict[str, Any]:
        """
        Evaluate a list of image paths using True Batched GPU execution.
        
        Args:
            image_paths: List of file paths to evaluate.
            mode: 'fast' (pure GPU batch + structure, ~10ms/img) or 'full' (all 5 tiers, ~1-2s/img).
            show_progress: Whether to print console progress.
        """
        paths = [Path(p).resolve() for p in image_paths if Path(p).exists()]
        results = []
        start_time = time.perf_counter()

        # Step 1: Pre-calculate GPU predictions for the ENTIRE batch at once!
        dl_results = []
        if self.enable_dl and paths:
            if show_progress:
                print(f"[StegoEval] Running GPU batched inference for {len(paths)} images...", end="\r", flush=True)
            t_gpu = time.perf_counter()
            dl_results = self.dl_bridge.predict_batch(paths)
            gpu_elapsed = round((time.perf_counter() - t_gpu) * 1000.0, 1)
            if show_progress:
                print(f"[StegoEval] GPU batch finished in {gpu_elapsed} ms ({len(paths)} imgs, {round(len(paths)/(gpu_elapsed/1000), 1)} FPS)   ")

        # Step 2: Assemble results (Parallelized across CPU cores)
        def _process_single(idx: int, p: Path) -> Tuple[int, Dict[str, Any]]:
            dl_raw = dl_results[idx] if idx < len(dl_results) else None
            try:
                if mode == "fast" and dl_raw is not None and dl_raw.get("status") == "ok":
                    res = self.evaluate_fast_image(p, dl_raw)
                else:
                    if dl_raw and dl_raw.get("status") == "ok":
                        preds = dl_raw.get("predictions", {})
                        prob = dl_raw.get("prob", 0.0)
                        tag = f"Ensemble ({dl_raw.get('device_name', 'CUDA')})"
                        pre_dl = {
                            "enabled": True,
                            "status": f"Executed ({tag})",
                            "dl_score": round(prob * 100.0, 1),
                            "predictions": preds if preds else {tag: round(prob, 4)},
                            "max_stego_prob": round(prob, 4),
                            "avg_stego_prob": dl_raw.get("avg_stego_prob", round(prob, 4)),
                            "latency_ms": dl_raw.get("latency_ms", 0.0),
                        }
                    else:
                        pre_dl = None

                    res = self.evaluate_image(p, precomputed_dl=pre_dl)

                return idx, res
            except Exception as e:
                return idx, {
                    "filepath": str(p),
                    "filename": p.name,
                    "error": str(e),
                    "summary": {"verdict": "ERROR", "stego_score": 0.0, "processing_time_ms": 0.0}
                }

        max_workers = min(8, os.cpu_count() or 4) if mode == "full" else 1
        indexed_results = [None] * len(paths)
        if len(paths) <= 1 or max_workers <= 1:
            for idx, p in enumerate(paths):
                if show_progress:
                    print(f"[{idx+1}/{len(paths)}] Analyzing CPU statistics: {p.name}...", end="\r", flush=True)
                _, res = _process_single(idx, p)
                indexed_results[idx] = res
        else:
            completed_count = 0
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(_process_single, idx, p) for idx, p in enumerate(paths)]
                for fut in futures:
                    idx, res = fut.result()
                    indexed_results[idx] = res
                    completed_count += 1
                    if show_progress:
                        print(f"[{completed_count}/{len(paths)}] Analyzing CPU statistics (parallel {max_workers} threads)...", end="\r", flush=True)

        results = indexed_results

        if show_progress:
            print(" " * 65, end="\r")

        total_time_sec = round(time.perf_counter() - start_time, 2)

        # Aggregate Statistics
        total_count = len(results)
        verdict_counts = {"CLEAN": 0, "LOW_RISK": 0, "SUSPICIOUS": 0, "HIGH_RISK": 0, "ERROR": 0}
        total_score = 0.0
        total_ms = 0.0

        for r in results:
            v = r.get("summary", {}).get("verdict", "ERROR")
            verdict_counts[v] = verdict_counts.get(v, 0) + 1
            total_score += r.get("summary", {}).get("stego_score", 0.0)
            total_ms += r.get("summary", {}).get("processing_time_ms", 0.0)

        flagged_count = verdict_counts["SUSPICIOUS"] + verdict_counts["HIGH_RISK"]
        detection_rate = round((flagged_count / total_count * 100.0), 2) if total_count > 0 else 0.0
        avg_score = round(total_score / total_count, 1) if total_count > 0 else 0.0
        avg_ms = round(total_ms / total_count, 1) if total_count > 0 else 0.0

        batch_summary = {
            "total_images": total_count,
            "mode": mode,
            "verdicts": verdict_counts,
            "flagged_images": flagged_count,
            "detection_rate_pct": detection_rate,
            "avg_stego_score": avg_score,
            "avg_latency_ms": avg_ms,
            "total_elapsed_sec": total_time_sec,
            "throughput_fps": round(total_count / max(total_time_sec, 0.001), 1),
            "dl_device": self.dl_bridge.device_info,
        }

        return {
            "summary": batch_summary,
            "results": results,
        }

    def evaluate_dir(self, dir_path: Union[str, Path], mode: str = "full", recursive: bool = False,
                     extensions: Tuple[str, ...] = (".png", ".jpg", ".jpeg", ".bmp")) -> Dict[str, Any]:
        """Scan a directory for images and evaluate them."""
        dp = Path(dir_path).resolve()
        if not dp.is_dir():
            raise NotADirectoryError(f"Directory not found: {dp}")

        pattern = "**/*" if recursive else "*"
        found_paths = [p for p in dp.glob(pattern) if p.suffix.lower() in extensions and p.is_file()]
        found_paths.sort()
        return self.evaluate_batch(found_paths, mode=mode, show_progress=False)

    def close(self):
        self.dl_bridge.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def generate_markdown_report(batch_data: Dict[str, Any], title: str = "StegoEval Comprehensive Report") -> str:
    """Generate a clean GitHub-flavored Markdown report from batch evaluation results."""
    bs = batch_data["summary"]
    results = batch_data["results"]

    lines = [
        f"# {title}",
        f"\n**Evaluation Summary:**",
        f"- **Total Images Analyzed:** {bs['total_images']}",
        f"- **Evaluation Mode:** `{bs.get('mode', 'full').upper()}`",
        f"- **Flagged (Suspicious / High Risk):** {bs['flagged_images']} ({bs['detection_rate_pct']}%)",
        f"- **Clean Count:** {bs['verdicts']['CLEAN']} | **Low Risk:** {bs['verdicts']['LOW_RISK']} | **Suspicious:** {bs['verdicts']['SUSPICIOUS']} | **High Risk:** {bs['verdicts']['HIGH_RISK']}",
        f"- **Average Stego Risk Score:** {bs['avg_stego_score']} / 100",
        f"- **Throughput / Latency:** **{bs.get('throughput_fps', 0.0)} FPS** ({bs['avg_latency_ms']} ms/image)",
        f"- **Deep Learning Device:** `{bs['dl_device']}`",
        f"- **Total Benchmark Wall Time:** {bs['total_elapsed_sec']} s",
        f"\n## Per-Image Diagnostic Details\n",
        "| Filename | Format | Verdict | Score | Estimated Payload | Suspected Vectors | DL (SRNet) | Time |",
        "| :--- | :---: | :---: | :---: | :---: | :--- | :---: | :---: |"
    ]

    for r in results:
        fname = r.get("filename", "Unknown")
        summ = r.get("summary", {})
        det = r.get("details", {})
        verdict = summ.get("verdict", "ERROR")
        score = summ.get("stego_score", 0.0)
        payload = f"{summ.get('estimated_payload_pct', 0.0):.1f}%"
        vectors = ", ".join(summ.get("suspected_techniques", [])) or "None"
        dl_preds = det.get("deep_learning", {}).get("predictions", {})
        if dl_preds:
            top_tag = max(dl_preds, key=dl_preds.get)
            dl_str = f"{dl_preds[top_tag]*100:.1f}% ({top_tag})"
        else:
            dl_str = "N/A"
        t_ms = f"{summ.get('processing_time_ms', 0.0):.1f} ms"
        fmt = r.get("format", "PNG")

        lines.append(f"| `{fname}` | {fmt} | **`[{verdict}]`** | {score:.1f} | {payload} | {vectors} | {dl_str} | {t_ms} |")

    return "\n".join(lines) + "\n"
