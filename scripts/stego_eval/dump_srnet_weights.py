import os
import numpy as np
import tensorflow as tf

m_path = r"F:\ai\downloads\aletheia-models\srnet-A-sd-hill-0.10.keras"
print(f"Loading {m_path}...")
model = tf.keras.models.load_model(m_path)

weight_dict = {}
for layer in model.layers:
    weights = layer.get_weights()
    if not weights:
        continue
    for idx, w in enumerate(weights):
        key = f"{layer.name}__{idx}"
        weight_dict[key] = w
        print(f"Stored {key}: shape {w.shape}, dtype {w.dtype}")

out_npz = r"C:\Home\Projects\strhide\temp\stego_eval\models\srnet_hill_010_weights.npz"
np.savez_compressed(out_npz, **weight_dict)
print(f"Saved {len(weight_dict)} weights to {out_npz}")
