import os
import sys
import json
import time
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

SELF_DIR = Path(__file__).resolve().parent
MODELS_DIR = SELF_DIR.parent / "models"
WORKER_SCRIPT = SELF_DIR / "dl_worker.py"
DEFAULT_CUDA_PYTHON = Path(r"F:\ai\torch\venv\Scripts\python.exe")

class DLInferenceBridge:
    """
    Transparent execution bridge for deep learning steganography detection.
    Supports in-process GPU execution (when host Python has torch+CUDA) or
    subprocess bridging to an isolated CUDA Python venv.
    """
    def __init__(self, cuda_python: Optional[str] = None, enable: bool = True):
        self.enable = enable
        self.mode = "disabled"
        self.device_info = "None"
        self._suite = None
        self._worker_proc = None

        if not self.enable:
            return

        # 1. Try In-Process execution
        try:
            import torch
            if torch.cuda.is_available():
                try:
                    from .model_suite import StegoModelSuite
                except (ImportError, ValueError):
                    from core.model_suite import StegoModelSuite
                self._suite = StegoModelSuite(device=torch.device("cuda"), models_dir=MODELS_DIR)
                self.mode = "in_process"
                self.device_info = f"In-Process CUDA ({torch.cuda.get_device_name(0)}) [7 Models]"
                return
        except Exception:
            pass

        # 2. Try Subprocess Bridge to CUDA venv
        candidates = []
        if cuda_python:
            candidates.append(Path(cuda_python))
        if os.environ.get("STEGO_CUDA_PYTHON"):
            candidates.append(Path(os.environ["STEGO_CUDA_PYTHON"]))
        candidates.extend([
            Path(sys.executable),
            Path(r"C:\Home\Develop\venv\Scripts\python.exe"),
            Path(r"F:\ai\torch\venv\Scripts\python.exe")
        ])

        for cand_python in candidates:
            if cand_python.exists() and WORKER_SCRIPT.exists():
                try:
                    self._worker_proc = subprocess.Popen(
                        [str(cand_python), str(WORKER_SCRIPT)],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                        encoding="utf-8"
                    )
                    handshake_raw = self._worker_proc.stdout.readline()
                    handshake = json.loads(handshake_raw.strip())
                    if handshake.get("status") == "ready":
                        self.mode = "subprocess_bridge"
                        self.device_info = f"Bridge ({handshake.get('device_name')}) [7 Models]"
                        return
                except Exception:
                    self._worker_proc = None

        self.mode = "unavailable"
        self.device_info = "PyTorch CUDA runtime not found"

    def predict(self, image_path: Path) -> Dict[str, Any]:
        """Predict single image."""
        if self.mode == "in_process" and self._suite:
            return self._suite.predict_single(image_path)
        elif self.mode == "subprocess_bridge" and self._worker_proc:
            req = {"action": "predict", "image_path": str(image_path.resolve())}
            self._worker_proc.stdin.write(json.dumps(req) + "\n")
            self._worker_proc.stdin.flush()
            line = self._worker_proc.stdout.readline()
            return json.loads(line.strip())
        else:
            return {"status": "error", "message": f"Bridge inactive ({self.mode})"}

    def predict_batch(self, image_paths: List[Path]) -> List[Dict[str, Any]]:
        """Predict batch of images."""
        if not image_paths:
            return []

        if self.mode == "in_process" and self._suite:
            return self._suite.predict_batch(image_paths)
        elif self.mode == "subprocess_bridge" and self._worker_proc:
            req = {"action": "predict_batch", "image_paths": [str(p.resolve()) for p in image_paths]}
            self._worker_proc.stdin.write(json.dumps(req) + "\n")
            self._worker_proc.stdin.flush()
            line = self._worker_proc.stdout.readline()
            resp = json.loads(line.strip())
            return resp.get("results", [])
        else:
            return [{"status": "error", "message": f"Bridge inactive ({self.mode})"} for _ in image_paths]

    def close(self):
        if self._worker_proc:
            try:
                self._worker_proc.stdin.write(json.dumps({"action": "exit"}) + "\n")
                self._worker_proc.stdin.flush()
                self._worker_proc.terminate()
                self._worker_proc.wait(timeout=2)
            except Exception:
                pass
            self._worker_proc = None

    def __del__(self):
        self.close()
