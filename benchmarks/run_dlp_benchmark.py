"""Evaluate secret detection on the synthetic corpus (and the legacy hand-written sets).

Usage::

    python -m benchmarks.run_dlp_benchmark --splits development            # while engineering
    python -m benchmarks.run_dlp_benchmark --splits heldout --compare-v3 --out benchmarks/results/dlp_heldout.json

``--compare-v3`` evaluates the v3.2.0 detector on the *same* samples. Its source is read
from the baseline git commit (``b786287``) so the comparison is reproducible from a clone.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import platform
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from benchmarks.corpus import Sample, generate_corpus, manifest_sha256  # noqa: E402

from shadow_ai_gateway import __version__  # noqa: E402
from shadow_ai_gateway.detectors import scan_text_for_secrets  # noqa: E402

BASELINE_COMMIT = "b786287"
Detector = Callable[[str], tuple[bool, str | None]]


def wilson(successes: int, total: int, z: float = 1.96) -> list[float] | None:
    if total == 0:
        return None
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return [round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4)]


def v4_detector(text: str) -> tuple[bool, str | None]:
    findings = scan_text_for_secrets(text)
    return (True, findings[0].detector) if findings else (False, None)


def load_v3_detector() -> Detector | None:
    try:
        source = subprocess.run(
            ["git", "show", f"{BASELINE_COMMIT}:src/proxy_gateway.py"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            text=True,
            encoding="utf-8",
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    path = Path(tempfile.mkdtemp()) / "proxy_gateway_v3.py"
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("proxy_gateway_v3", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    import logging

    spec.loader.exec_module(module)
    logging.getLogger("proxy_gateway").setLevel(logging.ERROR)

    def detect(text: str) -> tuple[bool, str | None]:
        hit, reason = module.inspect_text_for_threats(text, entropy_threshold=4.5)
        return bool(hit), reason

    return detect


def evaluate(samples: list[Sample], detector: Detector) -> dict:
    tp = fp = tn = fn = 0
    per_cat: dict[str, dict] = defaultdict(lambda: {"label": None, "n": 0, "flagged": 0})
    errors: dict[str, list[str]] = {"false_negatives": [], "false_positives": []}
    t0 = time.perf_counter()
    for s in samples:
        hit, _ = detector(s.text)
        cat = per_cat[s.category]
        cat["label"] = "credential" if s.label else "benign"
        cat["n"] += 1
        cat["flagged"] += int(hit)
        if s.label and hit:
            tp += 1
        elif s.label:
            fn += 1
            errors["false_negatives"].append(s.id)
        elif hit:
            fp += 1
            errors["false_positives"].append(s.id)
        else:
            tn += 1
    elapsed = time.perf_counter() - t0
    pos, neg = tp + fn, tn + fp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / pos if pos else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    categories = {}
    for name, c in sorted(per_cat.items()):
        rate = c["flagged"] / c["n"]
        categories[name] = {
            **c,
            ("recall" if c["label"] == "credential" else "false_positive_rate"): round(rate, 4),
            "ci95": wilson(c["flagged"], c["n"]),
        }
    return {
        "n": len(samples),
        "positives": pos,
        "negatives": neg,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "precision_ci95": wilson(tp, tp + fp),
        "recall": round(recall, 4),
        "recall_ci95": wilson(tp, pos),
        "f1": round(f1, 4),
        "specificity": round(tn / neg, 4) if neg else None,
        "specificity_ci95": wilson(tn, neg),
        "false_positive_rate": round(fp / neg, 4) if neg else None,
        "false_negative_rate": round(fn / pos, 4) if pos else None,
        "mean_scan_ms": round(1000 * elapsed / max(1, len(samples)), 4),
        "per_category": categories,
        "errors": {k: v[:200] for k, v in errors.items()},
    }


def legacy_handwritten() -> list[Sample]:
    from benchmarks.dlp_benchmark import CALIBRATION_DATASET, DEVELOPMENT_DATASET, HELD_OUT_EVALUATION_DATASET

    out = []
    for name, ds in (
        ("legacy_dev", DEVELOPMENT_DATASET),
        ("legacy_cal", CALIBRATION_DATASET),
        ("legacy_heldout", HELD_OUT_EVALUATION_DATASET),
    ):
        for item in ds:
            if item["category"] in ("prompt_override", "obfuscated_injection"):
                continue  # secret-detection benchmark only; injection heuristics are evaluated separately
            if item["category"] == "obfuscated_threat" and "instructions" in str(item["text"]):
                continue
            out.append(Sample(str(item["id"]), name, str(item["category"]), bool(item["is_threat"]), str(item["text"])))
    return out


def print_summary(name: str, res: dict) -> None:
    print(f"\n=== {name} (n={res['n']}, positives={res['positives']}) ===")
    print(
        f"precision {res['precision']:.4f} {res['precision_ci95']}  recall {res['recall']:.4f} {res['recall_ci95']}  F1 {res['f1']:.4f}"
    )
    print(
        f"specificity {res['specificity']}  FPR {res['false_positive_rate']}  FNR {res['false_negative_rate']}  mean scan {res['mean_scan_ms']} ms"
    )
    for cat, c in res["per_category"].items():
        metric = "recall" if c["label"] == "credential" else "FPR"
        value = c.get("recall", c.get("false_positive_rate"))
        print(f"   {c['label'][:4]} {cat:28s} n={c['n']:4d} {metric}={value:.3f} ci={c['ci95']}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits", default="development", help="comma list of development,calibration,heldout,legacy")
    ap.add_argument("--compare-v3", action="store_true")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    corpus = generate_corpus()
    detectors: dict[str, Detector] = {f"v{__version__}": v4_detector}
    if args.compare_v3:
        v3 = load_v3_detector()
        if v3 is None:
            print("WARNING: baseline commit not available; skipping v3 comparison", file=sys.stderr)
        else:
            detectors["v3.2.0"] = v3

    report = {
        "generated_unix": int(time.time()),
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "corpus_manifest_sha256": manifest_sha256(corpus),
        "results": {},
    }
    for split in args.splits.split(","):
        samples = legacy_handwritten() if split == "legacy" else corpus[split]
        for det_name, det in detectors.items():
            res = evaluate(samples, det)
            report["results"][f"{split}/{det_name}"] = res
            print_summary(f"{split} / {det_name}", res)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
