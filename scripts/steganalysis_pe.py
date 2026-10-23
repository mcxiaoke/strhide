#!/usr/bin/env python3
"""SRM / SRMQ1 / CRM 特征 + FLD ensemble 的 ``P_E`` 评测。

对标 DDE Lab 的评测协议（Kodovsky et al. 2012 的 ensemble）：

* 特征：``sealwatch``（Univ. Innsbruck，DDE MATLAB 实现的 Python 移植）
* 分类器：FLD ensemble（随机子空间 + bootstrap，超参自动搜索）
* 指标：``P_E = (P_FA + P_MD) / 2``，等先验，多 split 取均值

与文献口径的差异（写在 ``docs/steganalysis_eval_plan_20261023.md``）：

* 载体用本项目自己的语料，不是 BOSSbase —— ``P_E`` 不可与其他论文的数字直接相比，
  只能在本语料内做**方案间相对比较**（HILL vs S-UNIWARD、单通道 vs RGB 等）。
* 每个 cover 只裁一块，且 train/test 按 cover 分组划分，避免同一张图的
  不同裁块跨集合造成泄露。

用法::

    # 1. 生成配对样本（复用现有标定工具）
    python scripts/png_blind_calib.py gen --bin rust/target/release/strhide.exe \\
        --covers-list temp/calib/stego_covers.txt --payloads 4096,full \\
        --out temp/pe_samples

    # 2. 提取特征（多进程；cover 特征首次提取后会落盘缓存）
    python scripts/steganalysis_pe.py features \\
        --manifest temp/pe_samples/manifest.json --payload 4096 \\
        --features srm --crop 512 --jobs 16 \\
        --out temp/pe_features/srm_4096.npz \\
        --cover-cache temp/pe_features/covers_srm512.npz

    # 3. 训练 FLD ensemble 并输出 P_E
    python scripts/steganalysis_pe.py eval \\
        --features temp/pe_features/srm_4096.npz --splits 10 \\
        --out temp/pe_features/srm_4096.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import numpy as np

# sealwatch 只有 SPAM 有 Rust 后端；SRM/CRM/GFR/JRM 是纯 Python，因此必须多进程。
SPATIAL_BACKENDS = ("srm", "srmq1", "crm", "spam")
JPEG_BACKENDS = ("gfr", "jrm")
BACKENDS = SPATIAL_BACKENDS + JPEG_BACKENDS


def _load_gray(path: str, crop: int) -> np.ndarray:
    from PIL import Image

    with Image.open(path) as im:
        gray = im.convert("L")
        if crop and min(gray.size) > crop:
            w, h = gray.size
            left, top = (w - crop) // 2, (h - crop) // 2
            gray = gray.crop((left, top, left + crop, top + crop))
        return np.asarray(gray, dtype=np.uint8).copy()


def _load_rgb(path: str, crop: int) -> np.ndarray:
    from PIL import Image

    with Image.open(path) as im:
        rgb = im.convert("RGB")
        if crop and min(rgb.size) > crop:
            w, h = rgb.size
            left, top = (w - crop) // 2, (h - crop) // 2
            rgb = rgb.crop((left, top, left + crop, top + crop))
        return np.asarray(rgb, dtype=np.uint8).copy()


def _flatten(features) -> np.ndarray:
    if isinstance(features, dict):
        parts = [np.asarray(v).ravel() for v in features.values()]
        return np.concatenate(parts).astype(np.float32)
    return np.asarray(features).ravel().astype(np.float32)


def _extract_one(path: str, backend: str, crop: int, qf: int = 75) -> np.ndarray:
    import sealwatch as sw

    if backend == "srm":
        return _flatten(sw.srm.extract(_load_gray(path, crop)))
    if backend == "srmq1":
        return _flatten(sw.srmq1.extract(_load_gray(path, crop)))
    if backend == "crm":
        # q=1 / Tc=3 is the 5,404-dimension configuration the sealwatch docs
        # quote (the API default Tc=2 gives only 2,073, which is a weaker
        # detector -- see docs/steganalysis_eval_plan_20261023.md).
        return _flatten(sw.crm.extract(_load_rgb(path, crop), q=1, Tc=3))
    if backend == "spam":
        return _flatten(sw.spam.extract(_load_gray(path, crop)))
    if backend == "gfr":
        # GFR quantization steps are only tabulated for QF 75 and 95, so the
        # corpus must be a single quality factor. No cropping: DCT-domain
        # cropping has to stay block-aligned, and re-encoding would change the
        # coefficients we are measuring.
        return np.asarray(sw.gfr.extract_from_file(path, qf=qf)).ravel().astype(np.float32)
    if backend == "jrm":
        return _flatten(sw.jrm.extract_from_file(path))
    raise ValueError(f"unknown backend {backend}")


def _nonzero_ac(path: str) -> int:
    """Non-zero AC coefficients of the luma component -- the bpnzAC denominator."""
    import jpeglib

    dct = jpeglib.read_dct(path)
    return int(np.count_nonzero(dct.Y[:, :, 1:]))


def _job(
    cover: str,
    stegos: list[tuple[str, str]],
    backend: str,
    crop: int,
    need_cover: bool,
    qf: int = 75,
):
    """Extract every feature for one cover; one process handles the whole group."""
    try:
        f_cover = _extract_one(cover, backend, crop, qf) if need_cover else None
        out = {label: _extract_one(p, backend, crop, qf) for label, p in stegos}
        return cover, f_cover, out, None
    except Exception as exc:  # noqa: BLE001 - report, never abort the sweep
        return cover, None, None, f"{type(exc).__name__}: {exc}"


def cmd_features(a: argparse.Namespace) -> int:
    manifest = json.loads(Path(a.manifest).read_text(encoding="utf-8"))
    rows = [r for r in manifest if r.get("ok") and r.get("stego")]

    by_cover: dict[str, list[tuple[str, str]]] = {}
    for r in rows:
        if a.payload and str(r["payload"]) != str(a.payload):
            continue
        if not Path(r["stego"]).is_file():
            print(f"[skip] missing stego: {r['stego']}", file=sys.stderr)
            continue
        by_cover.setdefault(r["cover"], []).append((str(r["payload"]), r["stego"]))

    if not by_cover:
        print("no usable pairs in manifest", file=sys.stderr)
        return 1

    covers = sorted(by_cover)[: a.limit or None]
    print(f"covers={len(covers)} payload={a.payload or 'all'} backend={a.features} crop={a.crop}")
    if a.features in JPEG_BACKENDS:
        print(f"JPEG backend: cropping disabled (DCT domain), qf={a.jpeg_qf}")

    # Cover features are the same for every payload, so they are cached once.
    cache_path = Path(a.cover_cache) if a.cover_cache else None
    cached_cover: dict[str, np.ndarray] = {}
    cache_usable = True
    if cache_path and cache_path.is_file():
        blob = np.load(cache_path, allow_pickle=True)
        # A cache built with another backend or crop size has different
        # dimensions and silently poisons every downstream P_E -- refuse it.
        c_backend = str(blob["backend"]) if "backend" in blob else "?"
        c_crop = int(blob["crop"]) if "crop" in blob else -1
        if c_backend != a.features or c_crop != a.crop:
            print(
                f"cover cache mismatch: built with backend={c_backend} crop={c_crop}, "
                f"requested backend={a.features} crop={a.crop}; ignoring and NOT "
                f"overwriting {cache_path}",
                file=sys.stderr,
            )
            cache_usable = False
        else:
            cached_cover = dict(zip(blob["ids"].tolist(), list(blob["Xc"])))
            print(f"cover cache hit: {len(cached_cover)} entries from {cache_path}")

    Xc: dict[str, np.ndarray] = dict(cached_cover)
    per_payload: dict[str, list[tuple[str, np.ndarray]]] = {}

    def drain(pending: list[str], need_cover: bool) -> None:
        if not pending:
            return
        done = 0
        t0 = time.perf_counter()
        with ProcessPoolExecutor(max_workers=a.jobs) as pool:
            futures = {
                pool.submit(_job, c, by_cover[c], a.features, a.crop, need_cover, a.jpeg_qf): c
                for c in pending
            }
            for fut in as_completed(futures):
                cover, f_cover, feats, err = fut.result()
                done += 1
                if err:
                    print(f"[fail] {cover}: {err}", file=sys.stderr)
                    continue
                if f_cover is not None:
                    Xc[cover] = f_cover
                for label, f in feats.items():
                    per_payload.setdefault(label, []).append((cover, f))
                if done % 20 == 0 or done == len(pending):
                    rate = done / max(time.perf_counter() - t0, 1e-9)
                    eta = (len(pending) - done) / rate if rate else 0
                    print(f"  {done}/{len(pending)}, {rate:.2f}/s, eta {eta/60:.1f} min")

    drain([c for c in covers if c not in cached_cover], need_cover=True)
    drain([c for c in covers if c in cached_cover], need_cover=False)

    if cache_path and cache_usable:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        ids = np.array(list(Xc.keys()), dtype=object)
        np.savez_compressed(
            cache_path,
            ids=ids,
            Xc=np.array([Xc[i] for i in ids], dtype=np.float32),
            backend=np.array(a.features),
            crop=np.array(a.crop),
        )
        print(f"cover cache written: {cache_path}")

    def save(dst: Path, listed: list[tuple[str, np.ndarray]], label: str) -> None:
        listed = [(c, f) for c, f in listed if f is not None]
        if not listed:
            print(f"[skip] {dst}: no usable pairs", file=sys.stderr)
            return
        dst.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(
            dst,
            ids=np.array([c for c, _ in listed], dtype=object),
            Xc=np.array([Xc[c] for c, _ in listed], dtype=np.float32),
            Xs=np.array([f for _, f in listed], dtype=np.float32),
            payload=np.array(label),
            backend=np.array(a.features),
            crop=np.array(a.crop),
            jpeg_qf=np.array(a.jpeg_qf),
        )
        print(f"wrote {dst}  n={len(listed)}  dim={len(listed[0][1])}")

    out = Path(a.out)
    if len(per_payload) == 1:
        label, listed = next(iter(per_payload.items()))
        save(out, listed, label)
    else:
        for label, listed in per_payload.items():
            save(out.with_name(f"{out.stem}_{label}{out.suffix}"), listed, label)
    return 0


def _group_split(ids: list[str], ratio: float, rng: np.random.Generator):
    """Split cover ids, not samples -- one cover must not appear on both sides."""
    order = np.array(sorted(set(ids)))
    rng.shuffle(order)
    n_tr = int(round(len(order) * ratio))
    return set(order[:n_tr].tolist()), set(order[n_tr:].tolist())


def cmd_eval(a: argparse.Namespace) -> int:
    from sealwatch.ensemble_classifier import FldEnsembleTrainer

    blob = np.load(a.features, allow_pickle=True)
    ids = blob["ids"].tolist()
    Xc, Xs = blob["Xc"], blob["Xs"]
    label = str(blob["payload"]) if "payload" in blob else "?"
    backend = str(blob["backend"]) if "backend" in blob else "?"
    crop = int(blob["crop"]) if "crop" in blob else 0
    qf = int(blob["jpeg_qf"]) if "jpeg_qf" in blob else 0
    print(f"loaded {a.features}: n={len(ids)} dim={Xc.shape[1]} payload={label} backend={backend}")

    rng = np.random.default_rng(a.seed)
    results = []
    for s in range(a.splits):
        train_ids, test_ids = _group_split(ids, a.ratio, rng)
        tr = np.array([i for i, c in enumerate(ids) if c in train_ids])
        te = np.array([i for i, c in enumerate(ids) if c in test_ids])
        trainer = FldEnsembleTrainer(
            Xc=np.ascontiguousarray(Xc[tr]),
            Xs=np.ascontiguousarray(Xs[tr]),
            seed=a.seed + s,
            verbose=0,
            max_num_base_learners=a.max_learners,
        )
        t0 = time.perf_counter()
        ens, _ = trainer.train()
        X_test = np.concatenate([Xc[te], Xs[te]])
        y_test = np.concatenate([-np.ones(len(te)), np.ones(len(te))])
        y_pred = np.sign(ens.predict(X_test))
        p_fa = float(np.mean((y_test == -1) & (y_pred == +1)))
        p_md = float(np.mean((y_test == +1) & (y_pred == -1)))
        p_e = 0.5 * (p_fa + p_md)
        results.append({"split": s, "p_e": p_e, "p_fa": p_fa, "p_md": p_md,
                        "n_train": int(len(tr)), "n_test": int(len(te))})
        print(f"  split {s}: P_E={p_e:.4f} (P_FA={p_fa:.4f} P_MD={p_md:.4f})"
              f"  {time.perf_counter()-t0:.0f}s")

    pes = np.array([r["p_e"] for r in results])
    summary = {
        "features": str(a.features),
        "backend": backend,
        "payload": label,
        "crop": crop,
        "jpeg_qf": qf,
        "splits": a.splits,
        "n_covers": len(set(ids)),
        "dim": int(Xc.shape[1]),
        "p_e_mean": float(pes.mean()),
        "p_e_std": float(pes.std(ddof=1)) if len(pes) > 1 else 0.0,
        "p_e_min": float(pes.min()),
        "p_e_max": float(pes.max()),
        "per_split": results,
    }
    print(f"\nP_E = {summary['p_e_mean']:.4f} +/- {summary['p_e_std']:.4f}"
          f"  (min {summary['p_e_min']:.4f}, max {summary['p_e_max']:.4f})")

    if a.out:
        out = Path(a.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"wrote {out}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("features", help="extract rich-model features for a pair set")
    f.add_argument("--manifest", required=True, help="manifest.json from png_blind_calib gen")
    f.add_argument("--payload", default="", help="payload label to use (default: all)")
    f.add_argument("--features", default="srm", choices=BACKENDS)
    f.add_argument("--crop", type=int, default=512, help="centre crop; 0 keeps the full image")
    f.add_argument("--jpeg-qf", type=int, default=75, choices=(75, 95),
                   help="quality factor for GFR quantization (JPEG backends only)")
    f.add_argument("--jobs", type=int, default=8)
    f.add_argument("--limit", type=int, default=0)
    f.add_argument("--cover-cache", default="", help="npz cache of cover features")
    f.add_argument("--out", required=True)
    f.set_defaults(func=cmd_features)

    e = sub.add_parser("eval", help="train FLD ensemble and report P_E")
    e.add_argument("--features", required=True)
    e.add_argument("--splits", type=int, default=10)
    e.add_argument("--ratio", type=float, default=0.5)
    e.add_argument("--seed", type=int, default=12345)
    e.add_argument("--max-learners", type=int, default=500)
    e.add_argument("--out", default="")
    e.set_defaults(func=cmd_eval)

    a = p.parse_args()
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
