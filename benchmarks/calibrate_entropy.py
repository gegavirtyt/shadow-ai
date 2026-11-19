"""Calibrate the entropy margins on the *calibration split only*.

Selection rule (fixed before running): maximise recall subject to a calibration
false-positive rate <= 1%; ties are broken towards smaller margins (more conservative).
The held-out split is never touched by this script.

Usage: ``python -m benchmarks.calibrate_entropy [--out benchmarks/results/calibration.json]``
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from benchmarks.corpus import generate_split  # noqa: E402

from shadow_ai_gateway import detectors  # noqa: E402

GENERIC_GRID = [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50]
CONTEXT_GRID = [0.2, 0.4, 0.6, 0.8, 1.0, 1.2]
MAX_FPR = 0.01


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    samples = generate_split("calibration")
    original = (detectors.GENERIC_ENTROPY_DELTA, detectors.CONTEXT_ENTROPY_DELTA)
    rows = []
    try:
        for g, c in itertools.product(GENERIC_GRID, CONTEXT_GRID):
            detectors.GENERIC_ENTROPY_DELTA, detectors.CONTEXT_ENTROPY_DELTA = g, c
            tp = fp = fn = tn = 0
            for s in samples:
                hit = bool(detectors.scan_text_for_secrets(s.text))
                tp += s.label and hit
                fn += s.label and not hit
                fp += (not s.label) and hit
                tn += (not s.label) and not hit
            rows.append(
                {"generic_delta": g, "context_delta": c, "recall": tp / (tp + fn), "fpr": fp / (fp + tn), "tp": tp, "fp": fp}
            )
    finally:
        detectors.GENERIC_ENTROPY_DELTA, detectors.CONTEXT_ENTROPY_DELTA = original
    feasible = [r for r in rows if r["fpr"] <= MAX_FPR]
    best = max(feasible, key=lambda r: (r["recall"], -(r["generic_delta"] + r["context_delta"])))
    print(f"{'gen_d':>6} {'ctx_d':>6} {'recall':>7} {'fpr':>7}")
    for r in rows:
        mark = " <= selected" if r is best else ""
        print(f"{r['generic_delta']:6.2f} {r['context_delta']:6.2f} {r['recall']:7.4f} {r['fpr']:7.4f}{mark}")
    print(f"\nselected: GENERIC_ENTROPY_DELTA={best['generic_delta']} CONTEXT_ENTROPY_DELTA={best['context_delta']}")
    print(f"currently configured: GENERIC_ENTROPY_DELTA={original[0]} CONTEXT_ENTROPY_DELTA={original[1]}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"rule": f"max recall s.t. FPR<={MAX_FPR}", "selected": best, "grid": rows}, indent=2))


if __name__ == "__main__":
    main()
