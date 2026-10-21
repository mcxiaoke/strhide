import os
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from PIL import Image
import torch
import torch.nn.functional as F
import timm

SELF_DIR = Path(__file__).resolve().parent
MODELS_DIR = SELF_DIR.parent / "models"
try:
    from .pytorch_srnet import SRNet
except (ImportError, ValueError):
    from core.pytorch_srnet import SRNet

def load_image_tensor(p: Path) -> Optional[torch.Tensor]:
    """Load and center-crop image to (3, 512, 512) float32 tensor."""
    try:
        with Image.open(p) as im:
            im = im.convert("RGB")
            w, h = im.size
            left = max(0, (w - 512) // 2)
            top = max(0, (h - 512) // 2)
            crop_im = im.crop((left, top, left + 512, top + 512))
            arr = np.asarray(crop_im, dtype=np.float32) / 255.0
        return torch.from_numpy(arr).permute(2, 0, 1)
    except Exception:
        return None

class StegoModelSuite:
    """
    Unified Steganalysis Neural Network Suite:
    - 4 Models for JPEG: EffNet-JUNIW, EffNet-JMiPOD, EffNet-Steghide, EffNet-nsF5
    - 3 Models for PNG:  SRNet-HILL, SRNet-SUNIW, EffNet-HILL
    """
    def __init__(self, device: Optional[torch.device] = None, models_dir: Optional[Path] = None):
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.device_name = torch.cuda.get_device_name(0) if self.device.type == "cuda" else "CPU"
        self.models_dir = Path(models_dir or MODELS_DIR).resolve()
        
        self.jpeg_models: Dict[str, torch.nn.Module] = {}
        self.png_models: Dict[str, torch.nn.Module] = {}
        
        # Load JPEG Models (4)
        jpeg_specs = [
            ("EffNet-JUNIW", "effnetb0_juniw.pt"),
            ("EffNet-JMiPOD", "effnetb0_jmipod.pt"),
            ("EffNet-Steghide", "effnetb0_steghide.pt"),
            ("EffNet-nsF5", "effnetb0_nsf5.pt"),
        ]
        for tag, fname in jpeg_specs:
            p = self.models_dir / fname
            if p.exists():
                m = timm.create_model("tf_efficientnet_b0", pretrained=False, num_classes=2)
                m.load_state_dict(torch.load(p, map_location=self.device))
                m.to(self.device).eval()
                self.jpeg_models[tag] = m

        # Load PNG Models (3)
        png_specs = [
            ("SRNet-HILL", "srnet_hill_010.pt", "srnet"),
            ("SRNet-SUNIW", "srnet_suniw_010.pt", "srnet"),
            ("EffNet-HILL", "effnetb0_hill.pt", "effnet"),
        ]
        for tag, fname, mtype in png_specs:
            p = self.models_dir / fname
            if p.exists():
                if mtype == "srnet":
                    m = SRNet(in_channels=3)
                else:
                    m = timm.create_model("tf_efficientnet_b0", pretrained=False, num_classes=2)
                m.load_state_dict(torch.load(p, map_location=self.device))
                m.to(self.device).eval()
                self.png_models[tag] = m

        # Warmup
        all_models = list(self.jpeg_models.values()) + list(self.png_models.values())
        if all_models:
            dummy = torch.randn(1, 3, 512, 512, device=self.device)
            with torch.no_grad():
                for m in all_models:
                    _ = m(dummy)
            if self.device.type == "cuda":
                torch.cuda.synchronize()

    def is_jpeg(self, path: Path) -> bool:
        return path.suffix.lower() in (".jpg", ".jpeg")

    def predict_single(self, image_path: Path) -> Dict[str, Any]:
        """Predict a single image through the corresponding format model suite."""
        t0 = time.perf_counter()
        tensor = load_image_tensor(image_path)
        if tensor is None:
            return {"status": "error", "message": f"Failed to decode image: {image_path}"}

        is_jpg = self.is_jpeg(image_path)
        models = self.jpeg_models if is_jpg else self.png_models
        fmt = "JPEG" if is_jpg else "PNG"

        if not models:
            return {"status": "error", "message": f"No models loaded for format {fmt}"}

        batch_t = tensor.unsqueeze(0).to(self.device)
        predictions = {}
        with torch.no_grad():
            for tag, model in models.items():
                logits = model(batch_t)
                probs = F.softmax(logits, dim=-1)
                stego_p = float(probs[0, 1].item())
                predictions[tag] = round(stego_p, 4)

        if self.device.type == "cuda":
            torch.cuda.synchronize()
        dt_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        max_p = max(predictions.values()) if predictions else 0.0
        avg_p = round(float(sum(predictions.values()) / max(len(predictions), 1)), 4)

        return {
            "status": "ok",
            "format": fmt,
            "prob": max_p,
            "max_stego_prob": max_p,
            "avg_stego_prob": avg_p,
            "predictions": predictions,
            "device_name": self.device_name,
            "latency_ms": dt_ms
        }

    def predict_batch(self, image_paths: List[Path], chunk_size: int = 32, max_workers: int = 8) -> List[Dict[str, Any]]:
        """
        Evaluate a batch of mixed JPEG/PNG images through the corresponding model suites
        using GPU tensor chunking and concurrent multi-threaded decoding.
        """
        t0 = time.perf_counter()
        results: List[Optional[Dict[str, Any]]] = [None] * len(image_paths)

        # 1. Parallel image decoding
        def decode_task(item: Tuple[int, Path]):
            idx, p = item
            t = load_image_tensor(p)
            return idx, p, t

        loaded_items = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for idx, p, tensor in executor.map(decode_task, enumerate(image_paths)):
                if tensor is None:
                    results[idx] = {"status": "error", "message": f"Decode error: {p.name}", "prob": 0.0}
                else:
                    loaded_items.append((idx, p, tensor))

        # 2. Split by format
        jpeg_items = [it for it in loaded_items if self.is_jpeg(it[1])]
        png_items = [it for it in loaded_items if not self.is_jpeg(it[1])]

        # 3. Helper to run inference on a format subset
        def run_format_subset(items: List[Tuple[int, Path, torch.Tensor]], models: Dict[str, torch.nn.Module], fmt_name: str):
            if not items or not models:
                return

            for i in range(0, len(items), chunk_size):
                chunk = items[i:i + chunk_size]
                chunk_tensors = torch.stack([it[2] for it in chunk], dim=0).to(self.device)
                
                # Model predictions matrix: (len(chunk), len(models))
                model_preds: Dict[str, List[float]] = {}
                with torch.no_grad():
                    for tag, model in models.items():
                        logits = model(chunk_tensors)
                        probs = F.softmax(logits, dim=-1)[:, 1].cpu().tolist()
                        model_preds[tag] = probs

                # Assemble for each item in chunk
                for local_idx, (orig_idx, p, _) in enumerate(chunk):
                    preds = {tag: round(model_preds[tag][local_idx], 4) for tag in models}
                    max_p = max(preds.values()) if preds else 0.0
                    avg_p = round(float(sum(preds.values()) / max(len(preds), 1)), 4)
                    results[orig_idx] = {
                        "status": "ok",
                        "format": fmt_name,
                        "prob": max_p,
                        "max_stego_prob": max_p,
                        "avg_stego_prob": avg_p,
                        "predictions": preds,
                        "device_name": self.device_name,
                        "latency_ms": 0.0
                    }

        # Run JPEG and PNG subsets
        run_format_subset(jpeg_items, self.jpeg_models, "JPEG")
        run_format_subset(png_items, self.png_models, "PNG")

        if self.device.type == "cuda":
            torch.cuda.synchronize()

        total_elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        per_img_ms = round(total_elapsed_ms / max(len(image_paths), 1), 2)
        for r in results:
            if r and r.get("status") == "ok":
                r["latency_ms"] = per_img_ms

        return results
