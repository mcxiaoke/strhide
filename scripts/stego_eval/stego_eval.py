#!/usr/bin/env python3
"""
StegoEval - Unified Multi-Tier Steganography Evaluation Suite
Supports CLI invocation (single file, image list, directory scan) and Python API import.
Equipped with transparent cross-Python CUDA acceleration via PyTorch RTX 4070 bridge.
"""

import os
import sys
import json
import glob
from pathlib import Path
from typing import List, Optional
import click

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SELF_DIR = Path(__file__).resolve().parent
if str(SELF_DIR) not in sys.path:
    sys.path.insert(0, str(SELF_DIR))

from api import StegoEvaluator, generate_markdown_report
from core.reporter import console, print_single_report
from rich.table import Table
from rich import box


def print_batch_table(batch_data: dict):
    """Render a clean summary table for batch evaluations."""
    bs = batch_data["summary"]
    results = batch_data["results"]

    table = Table(
        title=f"[bold]StegoEval Batch Summary[/bold] ({bs['total_images']} Images | Device: [cyan]{bs['dl_device']}[/cyan])",
        box=box.ROUNDED,
    )
    table.add_column("No.", justify="right", style="dim", width=4)
    table.add_column("Image File", style="bold", min_width=24)
    table.add_column("Fmt", justify="center", width=5)
    table.add_column("Verdict", justify="center", width=13)
    table.add_column("Risk", justify="right", width=6)
    table.add_column("LSB %", justify="right", width=7)
    table.add_column("DL (SRNet)", justify="right", width=10)
    table.add_column("Suspected Techniques", min_width=22)
    table.add_column("Time", justify="right", width=9)

    for idx, r in enumerate(results, 1):
        summ = r.get("summary", {})
        det = r.get("details", {})
        v = summ.get("verdict", "ERROR")

        if v == "CLEAN":
            v_style = "[green][CLEAN][/green]"
        elif v == "LOW_RISK":
            v_style = "[blue][LOW_RISK][/blue]"
        elif v == "SUSPICIOUS":
            v_style = "[yellow][SUSPICIOUS][/yellow]"
        elif v == "HIGH_RISK":
            v_style = "[bold red][HIGH_RISK][/bold red]"
        else:
            v_style = "[red][ERROR][/red]"

        score = summ.get("stego_score", 0.0)
        payload = f"{summ.get('estimated_payload_pct', 0.0):.1f}%"
        vectors = ", ".join(summ.get("suspected_techniques", [])) or "None"
        dl_preds = det.get("deep_learning", {}).get("predictions", {})
        dl_str = f"{list(dl_preds.values())[0]*100:.1f}%" if dl_preds else "-"
        t_ms = f"{summ.get('processing_time_ms', 0.0):.0f} ms"
        is_jpg = det.get("jpeg_domain", {}).get("is_jpeg", False)
        fmt = "JPG" if is_jpg else "PNG"

        table.add_row(
            str(idx),
            r.get("filename", "Unknown"),
            fmt,
            v_style,
            f"{score:.1f}",
            payload,
            dl_str,
            vectors,
            t_ms,
        )

    console.print(table)

    # Aggregated Summary Banner
    vc = bs["verdicts"]
    console.print(
        f"\n[bold]Detection Summary:[/bold] "
        f"[green]CLEAN: {vc['CLEAN']}[/green] | "
        f"[blue]LOW_RISK: {vc['LOW_RISK']}[/blue] | "
        f"[yellow]SUSPICIOUS: {vc['SUSPICIOUS']}[/yellow] | "
        f"[red]HIGH_RISK: {vc['HIGH_RISK']}[/red] "
        f"(Flagged Rate: [bold cyan]{bs['detection_rate_pct']}%[/bold cyan] | "
        f"Avg Latency: [bold]{bs['avg_latency_ms']} ms[/bold] | "
        f"Wall Time: [bold]{bs['total_elapsed_sec']} s[/bold])"
    )


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("inputs", nargs=-1, type=str)
@click.option("--dir", "-d", "directory", type=click.Path(exists=True, file_okay=False, dir_okay=True), help="Directory to scan.")
@click.option("--recursive", "-r", is_flag=True, default=False, help="Recursively scan subdirectories.")
@click.option("--file-list", "-f", type=click.Path(exists=True, dir_okay=False), help="Text file containing image paths (one per line).")
@click.option("--enable-dl/--no-dl", default=True, help="Toggle deep learning detection (defaults to True with auto CUDA bridge).")
@click.option("--cuda-python", type=click.Path(exists=True, dir_okay=False), default=None, help="Explicit path to Python executable with CUDA PyTorch.")
@click.option("--json", "json_stdout", is_flag=True, default=False, help="Print raw JSON results directly to stdout.")
@click.option("--output-json", "-o", type=click.Path(dir_okay=False), default=None, help="Save detailed results JSON to file.")
@click.option("--report-md", "-m", type=click.Path(dir_okay=False), default=None, help="Generate and save a Markdown summary report.")
def main(
    inputs: tuple,
    directory: Optional[str],
    recursive: bool,
    file_list: Optional[str],
    enable_dl: bool,
    cuda_python: Optional[str],
    json_stdout: bool,
    output_json: Optional[str],
    report_md: Optional[str],
):
    """
    StegoEval: Automated Steganalysis & Algorithm Quality Evaluation Suite.

    Examples:
    \b
      python stego_eval.py image.png
      python stego_eval.py img1.png img2.jpg
      python stego_eval.py --dir C:/path/to/stegos/ -r
      python stego_eval.py --dir C:/path/to/stegos/ -o report.json -m report.md
      python stego_eval.py --file-list list.txt --json
    """
    target_files = []

    # 1. Collect inputs from positional args (files or glob patterns)
    if inputs:
        for inp in inputs:
            matches = glob.glob(inp, recursive=True)
            if matches:
                target_files.extend([Path(m).resolve() for m in matches if Path(m).is_file()])
            elif Path(inp).is_file():
                target_files.append(Path(inp).resolve())

    # 2. Collect from directory
    if directory:
        dp = Path(directory).resolve()
        pat = "**/*" if recursive else "*"
        valid_exts = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}
        dir_files = [p for p in dp.glob(pat) if p.suffix.lower() in valid_exts and p.is_file()]
        target_files.extend(dir_files)

    # 3. Collect from file list
    if file_list:
        with open(file_list, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    p = Path(line).resolve()
                    if p.is_file():
                        target_files.append(p)

    # Deduplicate while preserving order
    seen = set()
    unique_files = []
    for f in target_files:
        if str(f) not in seen:
            seen.add(str(f))
            unique_files.append(f)

    if not unique_files:
        if not json_stdout:
            console.print("[red]Error: No valid image files provided to evaluate.[/red]")
            console.print("Run 'python stego_eval.py --help' for usage examples.")
        else:
            print(json.dumps({"error": "No valid image files provided"}, indent=2))
        sys.exit(1)

    # Initialize evaluator
    with StegoEvaluator(enable_dl=enable_dl, cuda_python=cuda_python) as evaluator:
        # Single image special display
        if len(unique_files) == 1 and not (directory or file_list or output_json or report_md):
            res = evaluator.evaluate_image(unique_files[0])
            if json_stdout:
                print(json.dumps(res, indent=2, ensure_ascii=False))
            else:
                print_single_report(str(unique_files[0]), res)
            return

        # Batch evaluation
        if not json_stdout:
            console.print(f"[bold cyan]🔍 StegoEval: Analyzing {len(unique_files)} images (DL: {enable_dl})...[/bold cyan]")

        batch_data = evaluator.evaluate_batch(unique_files, show_progress=not json_stdout)

        # Output options
        if output_json:
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(batch_data, f, indent=2, ensure_ascii=False)
            if not json_stdout:
                console.print(f"[green]✓ Saved JSON data to: {output_json}[/green]")

        if report_md:
            md_content = generate_markdown_report(batch_data, title="StrHide Steganalysis Quality Evaluation Report")
            with open(report_md, "w", encoding="utf-8") as f:
                f.write(md_content)
            if not json_stdout:
                console.print(f"[green]✓ Saved Markdown report to: {report_md}[/green]")

        if json_stdout:
            print(json.dumps(batch_data, indent=2, ensure_ascii=False))
        else:
            print_batch_table(batch_data)


if __name__ == "__main__":
    main()
