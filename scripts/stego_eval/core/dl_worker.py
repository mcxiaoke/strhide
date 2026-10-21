import os
import sys
import json
import time
from pathlib import Path
import torch

SELF_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SELF_DIR.parent))
from core.model_suite import StegoModelSuite

def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    suite = StegoModelSuite(device=device)

    # Handshake ready signal
    ready_msg = json.dumps({
        "status": "ready",
        "device": str(device),
        "device_name": suite.device_name,
        "jpeg_models": list(suite.jpeg_models.keys()),
        "png_models": list(suite.png_models.keys()),
    })
    sys.stdout.write(ready_msg + "\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            sys.stdout.write(json.dumps({"status": "error", "message": f"Malformed JSON: {e}"}) + "\n")
            sys.stdout.flush()
            continue

        action = req.get("action", "predict")
        if action == "exit":
            sys.stdout.write(json.dumps({"status": "exited"}) + "\n")
            sys.stdout.flush()
            break
        elif action == "ping":
            sys.stdout.write(json.dumps({
                "status": "pong",
                "device": str(device),
                "device_name": suite.device_name
            }) + "\n")
            sys.stdout.flush()
            continue
        elif action == "predict":
            path_str = req.get("image_path")
            p = Path(path_str)
            if not p.exists():
                res = {"status": "error", "message": f"File not found: {path_str}"}
            else:
                res = suite.predict_single(p)
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        elif action == "predict_batch":
            path_strs = req.get("image_paths", [])
            paths = [Path(p) for p in path_strs]
            results = suite.predict_batch(paths)
            sys.stdout.write(json.dumps({"status": "ok", "results": results}) + "\n")
            sys.stdout.flush()
        else:
            sys.stdout.write(json.dumps({"status": "error", "message": f"Unknown action: {action}"}) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
