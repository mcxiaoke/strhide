import numpy as np
import cv2 as cv
from scipy import stats as scipy_stats
from typing import Dict, Any


def block_dct_analysis(channel: np.ndarray) -> Dict[str, float]:
    """
    Perform 8x8 block Discrete Cosine Transform (DCT) on channel and analyze AC coefficient statistics.
    """
    h, w = channel.shape
    h_blocks = h // 8
    w_blocks = w // 8
    if h_blocks < 2 or w_blocks < 2:
        return {"ac_histogram_asymmetry": 0.0, "zero_ac_ratio": 0.0}

    # Crop to multiple of 8
    cropped = channel[:h_blocks * 8, :w_blocks * 8].astype(np.float32) - 128.0

    ac_coeffs = []
    # Process blocks
    for y in range(0, h_blocks * 8, 8):
        for x in range(0, w_blocks * 8, 8):
            block = cropped[y:y+8, x:x+8]
            dct_b = cv.dct(block)
            # Flatten, exclude DC (0,0)
            ac = np.delete(dct_b.flatten(), 0)
            ac_coeffs.extend(ac[np.abs(ac) < 50.0])  # Sample moderate AC coefficients

    if len(ac_coeffs) == 0:
        return {"ac_histogram_asymmetry": 0.0, "zero_ac_ratio": 0.0}

    ac_arr = np.array(ac_coeffs)
    quantized_ac = np.round(ac_arr).astype(np.int32)

    # Histogram of integers around 0: [-10 to 10]
    hist, _ = np.histogram(quantized_ac, bins=np.arange(-10, 12))
    zero_count = float(hist[10])
    total_count = float(len(quantized_ac))
    zero_ratio = zero_count / max(total_count, 1.0)

    # In natural images, positive and negative AC coefficients are symmetric: hist(k) ≈ hist(-k)
    # Some stego tools (like OutGuess/J-Steg) disrupt symmetry or cause uneven shrinkage
    pos_ac = hist[11:16].astype(np.float64)
    neg_ac = hist[5:10][::-1].astype(np.float64)  # Reverse negative bins

    denom = np.maximum(pos_ac + neg_ac, 1.0)
    asymmetry = float(np.mean(np.abs(pos_ac - neg_ac) / denom))

    return {
        "ac_histogram_asymmetry": asymmetry,
        "zero_ac_ratio": zero_ratio,
    }


def analyze_jpeg_domain(image_bgr: np.ndarray, is_jpeg_file: bool = False) -> Dict[str, Any]:
    """
    Analyze frequency/DCT characteristics.
    """
    if len(image_bgr.shape) == 2:
        gray = image_bgr
    else:
        gray = cv.cvtColor(image_bgr, cv.COLOR_BGR2GRAY)

    dct_info = block_dct_analysis(gray)
    asym = dct_info["ac_histogram_asymmetry"]
    zero_ratio = dct_info["zero_ac_ratio"]

    score = 0.0
    if is_jpeg_file:
        if asym > 0.25:
            score += min(50.0, asym * 100.0)
        # F5 shrinkage or aggressive quantization distortion
        if zero_ratio > 0.75:
            score += 20.0
    else:
        # On uncompressed/spatial PNGs, simulated DCT asymmetry gives supplementary texture info
        if asym > 0.35:
            score += 20.0

    score = min(100.0, score)

    return {
        "is_jpeg": is_jpeg_file,
        "ac_asymmetry": asym,
        "zero_ac_ratio": zero_ratio,
        "jpeg_domain_score": score,
    }
