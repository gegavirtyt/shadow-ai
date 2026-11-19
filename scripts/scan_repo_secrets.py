"""Repository secret scan using the gateway's own detectors (dogfooding).

Scans every git-tracked text file. Paths that intentionally contain *synthetic*
credential-shaped fixtures are allowlisted below; everything else must be clean.
Exit code 1 if any finding remains. Usage: ``python scripts/scan_repo_secrets.py``
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from shadow_ai_gateway.detectors import scan_text_for_secrets  # noqa: E402

# Files that contain synthetic, non-functional credential fixtures by design.
ALLOWLIST = {
    "benchmarks/dlp_benchmark.py",  # hand-written labelled regression dataset
    "tests/mock_upstream.py",
    "scripts/simulate_attack_defense.py",
}
ALLOWLIST_PREFIXES = ("tests/test_",)
SKIP_SUFFIXES = (".lock", ".png", ".jpg", ".ico", ".pdf")


def main() -> int:
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    problems = 0
    for rel in files:
        if rel in ALLOWLIST or rel.startswith(ALLOWLIST_PREFIXES) or rel.endswith(SKIP_SUFFIXES):
            continue
        try:
            text = (ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            # Pattern detectors only (like gitleaks defaults): the generic entropy heuristic is
            # noisy on source code (measured in benchmarks/code_fp_eval.py).
            for f in scan_text_for_secrets(line, entropy=False):
                problems += 1
                print(f"{rel}:{lineno}: {f.detector} ({f.category}), length {f.length}")
    print(f"scanned {len(files)} tracked files; {problems} finding(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
