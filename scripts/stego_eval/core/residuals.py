import numpy as np
from scipy.ndimage import convolve
from typing import Dict, Any, List


def compute_difference_residuals(channel: np.ndarray) -> Dict[str, float]:
    """
    Compute 1st and 2nd order difference residuals.
    LSB and adaptive steganography perturb high-frequency pixel differences.
    """
    arr = channel.astype(np.float64)

    # 1st order horizontal & vertical differences
    diff_h = np.diff(arr, axis=1)
    diff_v = np.diff(arr, axis=0)

    var_h = float(np.var(diff_h))
    var_v = float(np.var(diff_v))

    # Kurtosis of 1st order differences (natural images have heavy-tailed, high kurtosis distributions)
    # Embedding data broadens the peak and decreases kurtosis
    m4_h = np.mean((diff_h - np.mean(diff_h)) ** 4)
    kurt_h = float(m4_h / max((var_h ** 2), 1e-6))

    # 2nd order differences
    diff2_h = np.diff(arr, n=2, axis=1)
    diff2_v = np.diff(arr, n=2, axis=0)
    var2_h = float(np.var(diff2_h))
    var2_v = float(np.var(diff2_v))

    return {
        "var_1st_h": var_h,
        "var_1st_v": var_v,
        "kurtosis_1st_h": kurt_h,
        "var_2nd_h": var2_h,
        "var_2nd_v": var2_v,
    }


def compute_laplacian_residuals(channel: np.ndarray) -> Dict[str, float]:
    """
    High-pass residual via 3x3 Laplacian kernel.
    Evaluates high-frequency noise variance and local energy concentration.
    """
    arr = channel.astype(np.float64)
    kernel = np.array([[-1, 2, -1],
                       [ 2, -4, 2],
                       [-1, 2, -1]], dtype=np.float64)

    res = convolve(arr, kernel, mode="reflect")
    var_res = float(np.var(res))

    # Residual histogram in range [-10, 10]
    hist, _ = np.histogram(res.flatten(), bins=np.arange(-10, 12))
    hist_norm = hist.astype(np.float64) / max(hist.sum(), 1)
    center_energy = float(hist_norm[10])  # zero-residual bin

    return {
        "laplacian_variance": var_res,
        "zero_residual_ratio": center_energy,
    }


def analyze_residuals(image_bgr: np.ndarray) -> Dict[str, Any]:
    """
    Analyze high-pass residuals across all channels.
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
    kurtosis_list = []
    zero_ratio_list = []
    lap_var_list = []

    for name, ch in channels:
        diff_info = compute_difference_residuals(ch)
        lap_info = compute_laplacian_residuals(ch)

        per_channel[name] = {
            "diff": diff_info,
            "laplacian": lap_info,
        }

        kurtosis_list.append(diff_info["kurtosis_1st_h"])
        zero_ratio_list.append(lap_info["zero_residual_ratio"])
        lap_var_list.append(lap_info["laplacian_variance"])

    avg_kurt = float(np.mean(kurtosis_list))
    avg_zero_ratio = float(np.mean(zero_ratio_list))
    avg_lap_var = float(np.mean(lap_var_list))

    # Natural images typically have kurtosis > 6.0 and higher zero residual concentration
    # Lower kurtosis with moderate/high laplacian variance suggests additive high-frequency noise/payload
    residual_anomaly_score = 0.0
    if avg_kurt < 4.5 and avg_lap_var > 15.0:
        residual_anomaly_score += min(40.0, (5.0 - avg_kurt) * 15.0)

    if avg_zero_ratio < 0.20 and avg_lap_var > 20.0:
        residual_anomaly_score += min(30.0, (0.25 - avg_zero_ratio) * 120.0)

    residual_anomaly_score = min(100.0, residual_anomaly_score)

    return {
        "per_channel": per_channel,
        "avg_kurtosis": avg_kurt,
        "avg_zero_residual_ratio": avg_zero_ratio,
        "avg_laplacian_variance": avg_lap_var,
        "residual_anomaly_score": residual_anomaly_score,
    }
