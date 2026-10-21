import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from typing import Dict, Any, List

# Reconfigure stdout for utf-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(legacy_windows=False)


def get_verdict_color(verdict: str) -> str:
    if verdict == "HIGH_RISK":
        return "bold red"
    elif verdict == "SUSPICIOUS":
        return "bold yellow"
    elif verdict == "LOW_RISK":
        return "bold blue"
    else:
        return "bold green"


def print_single_report(filepath: str, evaluation: Dict[str, Any]):
    """Render a comprehensive visual report for a single image."""
    summary = evaluation["summary"]
    details = evaluation["details"]
    verdict = summary["verdict"]
    score = summary["stego_score"]
    v_color = get_verdict_color(verdict)

    # Header Panel
    header_text = Text()
    header_text.append("Target Image: ", style="bold")
    header_text.append(f"{filepath}\n", style="cyan")
    header_text.append("Stego Risk Score: ", style="bold")
    header_text.append(f"{score:.1f} / 100  ", style=v_color)
    header_text.append(f"[{verdict}]  ", style=v_color)
    header_text.append(f"(Confidence: {summary['confidence']})\n", style="dim")
    header_text.append("Estimated LSB Payload: ", style="bold")
    header_text.append(f"{summary['estimated_payload_pct']}%\n", style="magenta")

    if summary["suspected_techniques"]:
        header_text.append("Suspected Vectors: ", style="bold")
        header_text.append(f"{', '.join(summary['suspected_techniques'])}\n", style="yellow")
    if summary["suspected_channels"]:
        header_text.append("Suspected Channels: ", style="bold")
        header_text.append(f"{', '.join(summary['suspected_channels'])}\n", style="yellow")

    console.print(Panel(header_text, title="[StegoEval] Comprehensive Steganalysis Report", border_style="blue"))

    # Table 1: Multi-Tier Breakdown
    tier_table = Table(title="[Scores] Multi-Tier Evaluation", box=box.ROUNDED)
    tier_table.add_column("Analysis Tier", style="bold cyan")
    tier_table.add_column("Tier Score", justify="center")
    tier_table.add_column("Key Findings / Diagnostics", style="dim")

    tiers = summary["tier_scores"]
    struct_detail = details["structure"]
    lsb_detail = details["lsb_statistics"]
    res_detail = details["residuals"]
    jpeg_detail = details["jpeg_domain"]
    dl_detail = details["deep_learning"]

    # Structure
    s_findings = []
    if struct_detail["has_structural_anomaly"]:
        s_findings.append(f"Anomaly detected! {', '.join(struct_detail.get('warnings', []))}")
    else:
        s_findings.append(f"Normal container, entropy: {struct_detail.get('file_entropy', 0.0):.2f}")
    tier_table.add_row("1. Container & Structure", f"{tiers['structure']:.1f}", "; ".join(s_findings))

    # LSB Stats
    lsb_findings = [
        f"RS avg: {lsb_detail['avg_rs_rate']*100:.1f}%",
        f"SPA avg: {lsb_detail['avg_spa_rate']*100:.1f}%",
        f"Chi2 max p: {lsb_detail['max_chi_p_value']:.4f}",
        f"LSB mean: {lsb_detail['avg_lsb_ratio']:.4f}",
    ]
    tier_table.add_row("2. Spatial LSB Statistics", f"{tiers['lsb_stat']:.1f}", ", ".join(lsb_findings))

    # High-Pass Residuals
    res_findings = [
        f"Avg Kurtosis: {res_detail['avg_kurtosis']:.2f}",
        f"Laplacian Var: {res_detail['avg_laplacian_variance']:.2f}",
        f"Zero-res ratio: {res_detail['avg_zero_residual_ratio']:.3f}",
    ]
    tier_table.add_row("3. Residual & Noise Dynamics", f"{tiers['residuals']:.1f}", ", ".join(res_findings))

    # JPEG / DCT
    j_findings = [
        f"Is JPEG: {jpeg_detail['is_jpeg']}",
        f"AC Asymmetry: {jpeg_detail['ac_asymmetry']:.3f}",
        f"Zero AC Ratio: {jpeg_detail['zero_ac_ratio']:.3f}",
    ]
    tier_table.add_row("4. Frequency & DCT Domain", f"{tiers['jpeg_domain']:.1f}", ", ".join(j_findings))

    # DL
    if tiers["deep_learning"] is not None:
        dl_preds = dl_detail.get("predictions", {})
        pred_str = ", ".join([f"{k.split('-')[-1].replace('.h5','')}:{v}" for k, v in dl_preds.items()])
        tier_table.add_row("5. Deep Learning (Aletheia)", f"{tiers['deep_learning']:.1f}", pred_str or "Active")
    else:
        tier_table.add_row("5. Deep Learning", "N/A", dl_detail.get("status", "Disabled"))

    console.print(tier_table)

    # Table 2: Channel-by-Channel Breakdown (if available)
    if "per_channel" in lsb_detail and len(lsb_detail["per_channel"]) > 1:
        ch_table = Table(title="[Channels] Color Channel Breakdown", box=box.SIMPLE_HEAVY)
        ch_table.add_column("Channel", style="bold")
        ch_table.add_column("RS Rate", justify="right")
        ch_table.add_column("SPA Rate", justify="right")
        ch_table.add_column("Chi-Sq p-val", justify="right")
        ch_table.add_column("LSB Ratio", justify="right")
        ch_table.add_column("Even/Odd Dev", justify="right")

        for ch_name, data in lsb_detail["per_channel"].items():
            rs_val = data["rs"]["estimated_rate"] * 100.0
            spa_val = data["spa"]["estimated_rate"] * 100.0
            chi_p = data["chi"]["p_value"]
            lsb_r = data["lsb_ratio"]
            eo_dev = data["even_odd_dev"]

            ch_style = "red" if (rs_val > 20 or chi_p > 0.95) else "white"
            ch_table.add_row(
                f"[{ch_style}]{ch_name}[/{ch_style}]",
                f"{rs_val:.1f}%",
                f"{spa_val:.1f}%",
                f"{chi_p:.4f}",
                f"{lsb_r:.4f}",
                f"{eo_dev:.4f}",
            )
        console.print(ch_table)

    console.print()


def print_batch_row(idx: int, total: int, filepath: str, score: float, verdict: str, payload: float):
    """Print a single compact line for directory batch scans."""
    v_color = get_verdict_color(verdict)
    console.print(
        f"[{idx}/{total}] [cyan]{filepath}[/cyan] -> "
        f"Score: [{v_color}]{score:5.1f}[/{v_color}] | "
        f"Verdict: [{v_color}]{verdict:<9}[/{v_color}] | "
        f"Payload: [magenta]{payload:4.1f}%[/magenta]"
    )

