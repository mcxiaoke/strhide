"""
Example Script: How to import and use StegoEvaluator in Python.
Works seamlessly in ANY Python environment (even without torch/CUDA),
as it automatically bridges to F:\ai\torch\venv for RTX 4070 GPU acceleration.
"""

import sys
from pathlib import Path

# Add stego_eval to sys.path
STEGO_EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(STEGO_EVAL_DIR))

from api import StegoEvaluator, generate_markdown_report

def main():
    print("Initializing StegoEvaluator...")
    # Optional parameters:
    #   enable_dl=True (default): Activates SRNet deep learning
    #   cuda_python=r"F:\ai\torch\venv\Scripts\python.exe" (auto-detected if None)
    with StegoEvaluator(enable_dl=True) as evaluator:
        print(f"StegoEvaluator ready! Backend: {evaluator.dl_bridge.device_info}\n")

        # -----------------------------------------------------------------
        # 1. Evaluate a Single Image
        # -----------------------------------------------------------------
        test_png = STEGO_EVAL_DIR.parent / "blackbox_experiment" / "stegos" / "png_load_64k.png"
        if test_png.exists():
            print(f"--- 1. Evaluating Single Image: {test_png.name} ---")
            res = evaluator.evaluate_image(test_png)
            summ = res["summary"]
            print(f"File: {res['filename']} ({res['format']})")
            print(f"Verdict: [{summ['verdict']}] (Risk Score: {summ['stego_score']:.1f}/100)")
            print(f"Estimated LSB Payload: {summ['estimated_payload_pct']:.1f}%")
            print(f"Suspected Vectors: {', '.join(summ['suspected_techniques']) or 'None'}")
            print(f"Processing Latency: {summ['processing_time_ms']} ms\n")

        # -----------------------------------------------------------------
        # 2. Evaluate a Batch of Images
        # -----------------------------------------------------------------
        test_batch = [
            STEGO_EVAL_DIR.parent / "blackbox_experiment" / "stegos" / "png_load_4k.png",
            STEGO_EVAL_DIR.parent / "blackbox_experiment" / "stegos" / "png_load_16k.png",
            STEGO_EVAL_DIR.parent / "blackbox_experiment" / "stegos" / "png_load_64k.png",
            STEGO_EVAL_DIR.parent / "blackbox_experiment" / "stegos" / "jpg_1080p_1_load_4k.jpg",
            STEGO_EVAL_DIR.parent / "blackbox_experiment" / "stegos" / "jpg_1080p_1_load_64k.jpg",
        ]
        valid_batch = [p for p in test_batch if p.exists()]

        if valid_batch:
            print(f"--- 2. Evaluating Batch of {len(valid_batch)} Images ---")
            batch_data = evaluator.evaluate_batch(valid_batch, show_progress=True)
            bs = batch_data["summary"]
            print(f"\nBatch Completed in {bs['total_elapsed_sec']}s (Avg: {bs['avg_latency_ms']} ms/img)")
            print(f"Results: {bs['verdicts']}")
            print(f"Flagged Rate: {bs['detection_rate_pct']}%\n")

            # -----------------------------------------------------------------
            # 3. Export Markdown Report
            # -----------------------------------------------------------------
            report_md = generate_markdown_report(batch_data, title="StrHide Quality Evaluation Sample")
            out_md_path = STEGO_EVAL_DIR.parent / "example_report.md"
            with open(out_md_path, "w", encoding="utf-8") as f:
                f.write(report_md)
            print(f"Saved Markdown report to: {out_md_path}")

if __name__ == "__main__":
    main()
