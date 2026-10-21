from typing import Dict, Any, List


def compute_composite_verdict(
    structure_res: Dict[str, Any],
    lsb_res: Dict[str, Any],
    residual_res: Dict[str, Any],
    jpeg_res: Dict[str, Any],
    dl_res: Dict[str, Any],
    threshold_suspicious: float = 45.0,
    threshold_high: float = 70.0,
) -> Dict[str, Any]:
    """
    Fuse multi-tier steganalysis results into a unified stego risk score and verdict.
    """
    struct_score = structure_res.get("anomaly_score", 0.0)
    lsb_score = lsb_res.get("lsb_score", 0.0)
    res_score = residual_res.get("residual_anomaly_score", 0.0)
    jpeg_score = jpeg_res.get("jpeg_domain_score", 0.0)
    dl_enabled = dl_res.get("enabled", False) and "Executed" in str(dl_res.get("status", ""))
    dl_score = dl_res.get("dl_score", 0.0) if dl_enabled else 0.0

    is_jpeg = jpeg_res.get("is_jpeg", False)

    # Weight distribution (JPEG domain vs Spatial domain)
    if is_jpeg:
        if dl_enabled:
            final_score = (
                0.25 * struct_score +
                0.00 * lsb_score +
                0.15 * res_score +
                0.40 * jpeg_score +
                0.20 * dl_score
            )
        else:
            final_score = (
                0.30 * struct_score +
                0.00 * lsb_score +
                0.20 * res_score +
                0.50 * jpeg_score
            )
    else:
        if dl_enabled:
            final_score = (
                0.20 * struct_score +
                0.35 * lsb_score +
                0.15 * res_score +
                0.10 * jpeg_score +
                0.20 * dl_score
            )
        else:
            final_score = (
                0.30 * struct_score +
                0.45 * lsb_score +
                0.15 * res_score +
                0.10 * jpeg_score
            )

    # Flag overrides (Critical triggers that guarantee high suspicion)
    suspected_techniques = []
    reasons = []

    # 1. Trailing bytes detected
    if structure_res.get("has_structural_anomaly", False):
        if structure_res.get("details", {}).get("has_trailing_data", False):
            suspected_techniques.append("Trailing Bytes / Appended Data")
            reasons.append("Payload appended to file trailer")
            final_score = max(final_score, 75.0)
        if len(structure_res.get("details", {}).get("suspicious_chunks", [])) > 0:
            suspected_techniques.append("Non-standard Container Chunks")
            reasons.append("Unregistered container chunks present")
            final_score = max(final_score, 65.0)

    # 2. RS Analysis & SPA strong signals (Valid for spatial uncompressed images only)
    avg_rs = lsb_res.get("avg_rs_rate", 0.0)
    avg_spa = lsb_res.get("avg_spa_rate", 0.0)
    max_chi_p = lsb_res.get("max_chi_p_value", 0.0)
    est_payload = lsb_res.get("estimated_payload", 0.0)

    if not is_jpeg:
        if est_payload >= 0.25:
            suspected_techniques.append("Spatial LSB Replacement (High payload)")
            reasons.append(f"RS/SPA estimated payload: {est_payload * 100:.1f}%")
            final_score = max(final_score, 75.0)
        elif est_payload >= 0.10:
            suspected_techniques.append("Spatial LSB Modification (Moderate payload)")
            reasons.append(f"RS/SPA estimated payload: {est_payload * 100:.1f}%")
            final_score = max(final_score, 55.0)

        if max_chi_p > 0.99:
            suspected_techniques.append("Sequential LSB (Chi-square PoV equalization)")
            reasons.append(f"Chi-square p-value: {max_chi_p:.4f}")
            final_score = max(final_score, 70.0)

    # 3. Channel breakdown (only valid for spatial domain uncompressed images)
    suspected_channels = []
    if not is_jpeg:
        for ch_name, ch_data in lsb_res.get("per_channel", {}).items():
            ch_rs = ch_data.get("rs", {}).get("estimated_rate", 0.0)
            ch_spa = ch_data.get("spa", {}).get("estimated_rate", 0.0)
            ch_chi_p = ch_data.get("chi", {}).get("p_value", 0.0)
            ch_lsb = ch_data.get("lsb_ratio", 0.5)

            ch_reasons = []
            if ch_rs > 0.15:
                ch_reasons.append(f"RS={ch_rs*100:.1f}%")
            if ch_spa > 0.15:
                ch_reasons.append(f"SPA={ch_spa*100:.1f}%")
            if ch_chi_p > 0.95:
                ch_reasons.append(f"Chi2_p={ch_chi_p:.3f}")
            if abs(ch_lsb - 0.5) < 0.003 and (ch_rs > 0.08 or ch_spa > 0.08):
                ch_reasons.append(f"LSB_mean={ch_lsb:.4f}")

            if ch_reasons:
                suspected_channels.append(f"{ch_name} ({', '.join(ch_reasons)})")

    # 4. Final Verdict classification
    final_score = round(min(100.0, max(0.0, final_score)), 1)

    if final_score >= threshold_high:
        verdict = "HIGH_RISK"
        confidence = "HIGH"
    elif final_score >= threshold_suspicious:
        verdict = "SUSPICIOUS"
        confidence = "MEDIUM"
    elif final_score >= 20.0:
        verdict = "LOW_RISK"
        confidence = "LOW"
    else:
        verdict = "CLEAN"
        confidence = "HIGH"

    return {
        "stego_score": final_score,
        "verdict": verdict,
        "confidence": confidence,
        "estimated_payload_pct": round(est_payload * 100.0, 2),
        "tier_scores": {
            "structure": round(struct_score, 1),
            "lsb_stat": round(lsb_score, 1),
            "residuals": round(res_score, 1),
            "jpeg_domain": round(jpeg_score, 1),
            "deep_learning": round(dl_score, 1) if dl_enabled else None,
        },
        "suspected_techniques": suspected_techniques,
        "suspected_channels": suspected_channels,
        "key_reasons": reasons,
    }
