"""False-positive rate of the detectors on real (non-synthetic) source code.

Scans the source of widely used, installed third-party packages line by line. These
files are real-world code that contains no credentials, so every flagged line is a
false positive (the few pattern hits are documentation/test fixtures inside those
packages and are listed for manual review). Results depend on the installed versions,
which are recorded in the output.

Usage: ``python -m benchmarks.code_fp_eval [--out benchmarks/results/code_fp.json]``
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from benchmarks.run_dlp_benchmark import wilson  # noqa: E402

from shadow_ai_gateway.detectors import find_high_entropy_tokens, scan_text_for_secrets  # noqa: E402

PACKAGES = ["starlette", "httpx", "httpcore", "fastapi", "anyio", "uvicorn", "pydantic", "_pytest", "hypothesis"]
DISTRIBUTIONS = {"_pytest": "pytest"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    lines = ent = pat = 0
    pattern_hits: list[str] = []
    versions = {}
    for pkg in PACKAGES:
        mod = __import__(pkg)
        base = Path(mod.__file__).parent
        versions[pkg] = md.version(DISTRIBUTIONS.get(pkg, pkg))
        for f in sorted(base.rglob("*.py")):
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if not line.strip():
                    continue
                lines += 1
                ent += bool(find_high_entropy_tokens(line))
                hits = scan_text_for_secrets(line, entropy=False)
                if hits:
                    pat += 1
                    pattern_hits.append(f"{pkg}/{f.relative_to(base)}:{i}: {hits[0].detector}")
    report = {
        "packages": versions,
        "non_empty_lines": lines,
        "entropy_heuristic": {"flagged_lines": ent, "rate": round(ent / lines, 5), "ci95": wilson(ent, lines)},
        "pattern_detectors": {"flagged_lines": pat, "rate": round(pat / lines, 5), "ci95": wilson(pat, lines), "hits": pattern_hits},
        "p_at_least_one_fp_200_line_paste_entropy": round(1 - (1 - ent / lines) ** 200, 3),
    }
    print(json.dumps({k: v for k, v in report.items() if k != "pattern_detectors"} | {"pattern_detectors": {k: v for k, v in report["pattern_detectors"].items() if k != "hits"}}, indent=2))
    for h in pattern_hits:
        print("  pattern hit:", h)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
