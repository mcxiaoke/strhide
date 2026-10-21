import numpy as np
from scipy import stats as scipy_stats
from typing import Dict, Any, List, Tuple


def run_rs_analysis_channel(channel: np.ndarray, block_size: int = 4) -> Dict[str, float]:
    """
    Fridrich's RS (Regular-Singular) Analysis on a 2D single channel array.
    Fully vectorized with NumPy SIMD operations for ultra-fast processing.
    Uses masks [0, 1, 1, 0] (horizontal) and evaluates smoothness changes.
    Returns estimated embedding rate alpha in [0.0, 1.0].
    """
    h, w = channel.shape
    arr = channel.astype(np.int32)
    w_valid = w - (w % block_size)
    if w_valid < block_size or h < 1:
        return {"estimated_rate": 0.0, "discrepancy": 0.0, "r_m": 0, "s_m": 0, "r_nm": 0, "s_nm": 0}

    # Reshape all blocks into (N, 4) matrix: Vectorized SIMD operation
    blocks = arr[:, :w_valid].reshape(-1, block_size)
    total_groups = blocks.shape[0]

    # f_orig: sum |x_{i+1} - x_i|
    f_orig = np.sum(np.abs(np.diff(blocks, axis=1)), axis=1)

    # b_m: apply M = [0, 1, 1, 0] with F_1 (flip LSB: XOR 1)
    b_m = blocks.copy()
    b_m[:, 1] ^= 1
    b_m[:, 2] ^= 1
    f_m = np.sum(np.abs(np.diff(b_m, axis=1)), axis=1)

    # b_nm: apply -M = [0, -1, -1, 0] with F_{-1}
    b_nm = blocks.copy()
    b_nm[:, 1] += np.where(b_nm[:, 1] % 2 == 0, -1, 1)
    b_nm[:, 2] += np.where(b_nm[:, 2] % 2 == 0, -1, 1)
    b_nm = np.clip(b_nm, 0, 255)
    f_nm = np.sum(np.abs(np.diff(b_nm, axis=1)), axis=1)

    r_m = int(np.sum(f_m > f_orig))
    s_m = int(np.sum(f_m < f_orig))
    r_nm = int(np.sum(f_nm > f_orig))
    s_nm = int(np.sum(f_nm < f_orig))

    if total_groups == 0:
        return {"estimated_rate": 0.0, "discrepancy": 0.0, "r_m": 0, "s_m": 0, "r_nm": 0, "s_nm": 0}

    # Relative ratios
    r_m_ratio = r_m / total_groups
    s_m_ratio = s_m / total_groups
    r_nm_ratio = r_nm / total_groups
    s_nm_ratio = s_nm / total_groups

    # Discrepancy metric
    discrepancy = abs(r_m_ratio - r_nm_ratio) + abs(s_m_ratio - s_nm_ratio)

    # Simplified embedding rate approximation based on Fridrich's curve
    diff_0 = r_m_ratio - s_m_ratio
    diff_neg0 = r_nm_ratio - s_nm_ratio
    denom = max(1e-6, abs(diff_0) + abs(diff_neg0))
    est_rate = min(1.0, max(0.0, abs(diff_0 - diff_neg0) / denom))

    return {
        "estimated_rate": float(est_rate),
        "discrepancy": float(discrepancy),
        "r_m": float(r_m_ratio),
        "s_m": float(s_m_ratio),
        "r_nm": float(r_nm_ratio),
        "s_nm": float(s_nm_ratio),
    }


def run_spa_channel(channel: np.ndarray) -> Dict[str, float]:
    """
    Sample Pairs Analysis (Dumitrescu et al., 2003).
    Analyzes horizontal adjacent pixel pairs to estimate LSB replacement embedding rate.
    """
    p = channel[:, :-1].astype(np.int32)
    q = channel[:, 1:].astype(np.int32)
    diff = np.abs(p - q)
    close = diff == 1
    if not np.any(close):
        return {"estimated_rate": 0.0, "close_pairs_ratio": 0.0, "even_odd_asym": 0.0}

    u_div = p[close] // 2
    v_div = q[close] // 2
    c1 = int(np.sum(u_div == v_div))
    c2 = int(np.sum(u_div != v_div))
    total_close = c1 + c2
    if total_close == 0:
        return {"estimated_rate": 0.0, "close_pairs_ratio": 0.0, "even_odd_asym": 0.0}

    ratio_close = float(total_close / (channel.shape[0] * (channel.shape[1] - 1)))
    # In clean natural images, c1 approx c2 (asym ~ 0).
    # LSB replacement artificially increases c1 relative to c2.
    asym = (c1 - c2) / total_close
    est_rate = float(np.clip(2.0 * max(0.0, asym), 0.0, 1.0))

    return {
        "estimated_rate": est_rate,
        "close_pairs_ratio": ratio_close,
        "even_odd_asym": float(asym),
    }


def run_chi_square_channel(channel: np.ndarray) -> Dict[str, float]:
    """
    Chi-Square Attack (Westfeld & Pfitzmann).
    Calculates p-value from PoVs (Pairs of Values).
    p-value close to 1.0 indicates strong artificial LSB equalization (high stego likelihood).
    """
    flat = channel.flatten()
    freq, _ = np.histogram(flat, bins=256, range=(0, 256))

    f_even = freq[0::2].astype(np.float64)
    f_odd = freq[1::2].astype(np.float64)
    expected = (f_even + f_odd) / 2.0

    valid_mask = expected >= 5.0
    valid_pairs = int(np.sum(valid_mask))

    if valid_pairs < 10:
        return {"p_value": 0.0, "chi2_stat": 0.0, "valid_pairs": valid_pairs}

    ev = f_even[valid_mask]
    od = f_odd[valid_mask]
    exp = expected[valid_mask]

    chi2 = np.sum(((ev - exp) ** 2) / exp) + np.sum(((od - exp) ** 2) / exp)
    df = valid_pairs - 1
    p_val = float(scipy_stats.chi2.sf(chi2, df))

    return {
        "p_value": p_val,
        "chi2_stat": float(chi2),
        "degrees_of_freedom": df,
    }


def run_ws_analysis_channel(channel: np.ndarray) -> Dict[str, float]:
    """
    Weighted Stego-analysis (WS, Andrew D. Ker, 2005).
    Estimates cover pixel values using 4-neighborhood filtering with local variance weighting.
    """
    arr = channel.astype(np.float64)
    h, w = arr.shape
    if h < 5 or w < 5:
        return {"estimated_rate": 0.0, "residual_correlation": 0.0}

    # 4-neighborhood predictor
    pred = (arr[:-2, 1:-1] + arr[2:, 1:-1] + arr[1:-1, :-2] + arr[1:-1, 2:]) / 4.0
    center = arr[1:-1, 1:-1]
    lsb = (center.astype(np.int32) % 2).astype(np.float64)

    # Local variance estimation to suppress edge false positives
    local_var = (
        (arr[:-2, 1:-1] - pred) ** 2 +
        (arr[2:, 1:-1] - pred) ** 2 +
        (arr[1:-1, :-2] - pred) ** 2 +
        (arr[1:-1, 2:] - pred) ** 2
    ) / 4.0
    weights = 1.0 / (1.0 + local_var)

    res = center - pred
    direction = 1.0 - 2.0 * lsb
    num = np.sum(weights * res * direction)
    denom = np.maximum(np.sum(weights), 1.0)
    raw_est = 2.0 * (num / denom)
    est_rate = float(np.clip(abs(raw_est), 0.0, 1.0))

    return {
        "estimated_rate": est_rate,
        "residual_correlation": float(raw_est / 2.0),
    }


def analyze_lsb_statistics(image_bgr: np.ndarray) -> Dict[str, Any]:
    """
    Run multi-channel comprehensive LSB statistical tests on image (H, W, C) or (H, W).
    """
    if len(image_bgr.shape) == 2:
        channels = [("Gray", image_bgr)]
    else:
        channels = [
            ("Blue", image_bgr[:, :, 0]),
            ("Green", image_bgr[:, :, 1]),
            ("Red", image_bgr[:, :, 2]),
        ]

    per_channel = {}
    rs_rates = []
    spa_rates = []
    ws_rates = []
    chi_pvals = []
    lsb_ratios = []
    even_odd_devs = []

    for name, ch in channels:
        rs_res = run_rs_analysis_channel(ch)
        spa_res = run_spa_channel(ch)
        chi_res = run_chi_square_channel(ch)
        ws_res = run_ws_analysis_channel(ch)

        # LSB ratio (mean of LSB plane)
        lsb_plane = (ch & 1).astype(np.float64)
        lsb_mean = float(np.mean(lsb_plane))

        # Histogram even-odd deviation
        freq, _ = np.histogram(ch.flatten(), bins=256, range=(0, 256))
        even_b = freq[0::2].astype(np.float64)
        odd_b = freq[1::2].astype(np.float64)
        mean_freq = np.mean(freq)
        eo_dev = float(np.mean(np.abs(even_b - odd_b)) / max(mean_freq, 1.0))

        per_channel[name] = {
            "rs": rs_res,
            "spa": spa_res,
            "chi": chi_res,
            "ws": ws_res,
            "lsb_ratio": lsb_mean,
            "even_odd_dev": eo_dev,
        }

        rs_rates.append(rs_res["estimated_rate"])
        spa_rates.append(spa_res["estimated_rate"])
        ws_rates.append(ws_res["estimated_rate"])
        chi_pvals.append(chi_res["p_value"])
        lsb_ratios.append(lsb_mean)
        even_odd_devs.append(eo_dev)

    # Average metrics
    avg_rs = float(np.mean(rs_rates))
    avg_spa = float(np.mean(spa_rates))
    avg_ws = float(np.mean(ws_rates))
    max_chi_p = float(np.max(chi_pvals))
    avg_lsb_ratio = float(np.mean(lsb_ratios))
    avg_eo_dev = float(np.mean(even_odd_devs))

    # Composite LSB payload estimate
    est_payload = float(np.clip(0.45 * avg_rs + 0.35 * avg_spa + 0.20 * avg_ws, 0.0, 1.0))

    # Score calculation for LSB layer (0 to 100)
    score = 0.0
    score += min(50.0, est_payload * 80.0)
    if max_chi_p > 0.95:
        score += 25.0
    elif max_chi_p > 0.70:
        score += 15.0

    # LSB ratio close to 0.500 (within 0.005) is suspicious in natural imagery
    if abs(avg_lsb_ratio - 0.5) < 0.005 and est_payload > 0.05:
        score += 15.0

    # Equalized even/odd bins
    if avg_eo_dev < 0.08 and est_payload > 0.05:
        score += 10.0

    score = min(100.0, score)

    return {
        "per_channel": per_channel,
        "avg_rs_rate": avg_rs,
        "avg_spa_rate": avg_spa,
        "avg_ws_rate": avg_ws,
        "max_chi_p_value": max_chi_p,
        "avg_lsb_ratio": avg_lsb_ratio,
        "avg_even_odd_dev": avg_eo_dev,
        "estimated_payload": est_payload,
        "lsb_score": score,
    }
