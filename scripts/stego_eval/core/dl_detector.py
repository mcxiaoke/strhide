from pathlib import Path
from typing import Dict, Any, Optional
try:
    from .bridge import DLInferenceBridge
except (ImportError, ValueError):
    from core.bridge import DLInferenceBridge

_GLOBAL_BRIDGE = None

def get_dl_bridge(cuda_python: Optional[str] = None, enable: bool = True) -> DLInferenceBridge:
    global _GLOBAL_BRIDGE
    if _GLOBAL_BRIDGE is None:
        _GLOBAL_BRIDGE = DLInferenceBridge(cuda_python=cuda_python, enable=enable)
    return _GLOBAL_BRIDGE

def run_dl_detection(image_path: Path, models_dir: Optional[Path] = None, enable: bool = False, cuda_python: Optional[str] = None) -> Dict[str, Any]:
    """Run SOTA neural network detection (SRNet) using transparent bridge."""
    if not enable:
        return {
            "enabled": False,
            "status": "Skipped (use --enable-dl to activate)",
            "dl_score": 0.0,
            "predictions": {},
        }

    bridge = get_dl_bridge(cuda_python=cuda_python, enable=enable)
    if bridge.mode in ("disabled", "unavailable", "error"):
        return {
            "enabled": True,
            "status": f"Unavailable: {bridge.device_info}",
            "dl_score": 0.0,
            "predictions": {},
        }

    res = bridge.predict(image_path)
    if res.get("status") == "ok":
        prob = res.get("prob", 0.0)
        preds = res.get("predictions", {})
        tag = f"Ensemble ({res.get('device_name', 'CUDA')})"
        return {
            "enabled": True,
            "status": f"Executed ({tag})",
            "dl_score": round(prob * 100.0, 1),
            "predictions": preds if preds else {tag: round(prob, 4)},
            "max_stego_prob": round(prob, 4),
            "avg_stego_prob": res.get("avg_stego_prob", round(prob, 4)),
            "latency_ms": res.get("latency_ms", 0.0),
        }
    else:
        return {
            "enabled": True,
            "status": f"Inference Error: {res.get('message', 'Unknown')}",
            "dl_score": 0.0,
            "predictions": {},
        }
