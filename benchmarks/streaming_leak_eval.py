"""Measure streaming egress DLP on adversarially segmented streams.

For each trial a secret is embedded in benign prose and the content is cut into SSE
events of random size (1..max_piece characters). We measure, per implementation:

* ``detected``   - the stream ended with a DLP error event,
* ``leaked_any`` - at least one character of the secret reached the client,
* ``leaked_all`` - the complete secret reached the client,
* ``mean_leaked_chars`` - average number of secret characters released.

If the optional baseline git commit (``BASELINE_COMMIT``) is present in the local clone, the
earlier single-module implementation is loaded from it and evaluated on the identical streams
for comparison; otherwise only the current gateway is evaluated. Results for the current
gateway do not depend on whether the baseline is available.

Usage: ``python -m benchmarks.streaming_leak_eval --trials 300 --out benchmarks/results/streaming_leak.json``
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from benchmarks.run_dlp_benchmark import BASELINE_COMMIT, wilson  # noqa: E402
from tests.test_streaming_invariant import SECRET_KINDS, WORDS, make_secret, segment, sse  # noqa: E402

import proxy_gateway as v4  # noqa: E402  (v3-compatible facade over the v4 engine)


def load_v3():
    """Load the baseline implementation from git, or return None if the commit is unavailable."""
    import importlib.util
    import logging
    import subprocess
    import tempfile

    proc = subprocess.run(
        ["git", "show", f"{BASELINE_COMMIT}:src/proxy_gateway.py"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
    )
    if proc.returncode != 0:
        return None
    src = proc.stdout
    path = Path(tempfile.mkdtemp()) / "proxy_gateway_v3.py"
    path.write_text(src, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("proxy_gateway_v3", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    logging.getLogger("proxy_gateway").setLevel(logging.CRITICAL)
    mod.emit_siem_security_log = lambda *a, **k: {}
    return mod


class Upstream:
    def __init__(self, chunks):
        self.chunks = chunks
        self.sent = 0

    async def aiter_bytes(self):
        for c in self.chunks:
            self.sent += 1
            yield c

    async def aclose(self):
        pass


async def run(impl, chunks) -> bytes:
    out = []
    async for b in impl.stream_with_dlp_inspection(Upstream(chunks), delay_window_chars=64):
        out.append(b)
    return b"".join(out)


async def release_lag(impl, chunks) -> float:
    """Mean number of upstream events received but not yet forwarded, sampled at each release."""
    up = Upstream(chunks)
    lags, released = [], 0
    async for b in impl.stream_with_dlp_inspection(up, delay_window_chars=64):
        released += b.count(b"data: ")
        lags.append(up.sent - released)
    return sum(lags) / len(lags) if lags else 0.0


def released_content(output: bytes) -> tuple[str, bool]:
    text, errored = [], False
    for block in output.decode("utf-8", "replace").split("\n\n"):
        if not block.startswith("data: ") or block.strip() == "data: [DONE]":
            continue
        payload = json.loads(block[6:])
        if "error" in payload:
            errored = True
            continue
        delta = payload["choices"][0]["delta"]
        text.append(delta.get("content", ""))
        for call in delta.get("tool_calls", []):
            text.append(call.get("function", {}).get("arguments", ""))
    return "".join(text), errored


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=300)
    ap.add_argument("--seed", type=int, default=20261118)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    baseline = load_v3()
    impls = {"v4": v4} if baseline is None else {"v3.2.0": baseline, "v4": v4}
    if baseline is None:
        print("NOTE: baseline commit not available; evaluating the current gateway only", file=sys.stderr)
    kinds = [k for k in SECRET_KINDS if k not in ("entropy", "keyword_hex", "keyword_spaced")] + ["keyword_hex"]
    results: dict = {}
    cases = [(k, "content") for k in kinds] + [(k, "tool_args") for k in ("aws", "github", "pem", "db", "keyword_hex")]
    for kind, channel in cases:
        rng = random.Random(f"{args.seed}-{kind}-{channel}")
        ch = "tool" if channel == "tool_args" else "content"
        stats = {name: {"detected": 0, "leaked_any": 0, "leaked_all": 0, "leaked_chars": 0} for name in impls}
        for _ in range(args.trials):
            prefix = " ".join(rng.choice(WORDS) for _ in range(rng.randint(0, 40)))
            secret = make_secret(kind, rng)
            full = f"{prefix}{' ' if prefix else ''}{secret} {' '.join(rng.choice(WORDS) for _ in range(rng.randint(0, 15)))}"
            start = full.index(secret)
            chunks = [sse(p, channel=ch) for p in segment(full, rng, rng.choice([1, 2, 3, 5, 8, 17]))] + [b"data: [DONE]\n\n"]
            for name, impl in impls.items():
                released, errored = released_content(asyncio.run(run(impl, chunks)))
                leaked = max(0, min(len(released), start + len(secret)) - start)
                st = stats[name]
                st["detected"] += errored
                st["leaked_any"] += leaked > 0
                st["leaked_all"] += leaked == len(secret)
                st["leaked_chars"] += leaked
        results[f"{kind}/{channel}"] = {
            name: {
                "trials": args.trials,
                "detection_rate": round(st["detected"] / args.trials, 4),
                "leak_any_rate": round(st["leaked_any"] / args.trials, 4),
                "leak_any_ci95": wilson(st["leaked_any"], args.trials),
                "leak_complete_rate": round(st["leaked_all"] / args.trials, 4),
                "mean_leaked_chars": round(st["leaked_chars"] / args.trials, 2),
            }
            for name, st in stats.items()
        }
        row = results[f"{kind}/{channel}"]
        print(
            f"{kind + '/' + channel:22s} "
            + " | ".join(
                f"{name}: detect={r['detection_rate']:.3f} leak_any={r['leak_any_rate']:.3f} leak_all={r['leak_complete_rate']:.3f}"
                for name, r in row.items()
            )
        )
    rng = random.Random(args.seed)
    # Realistic BPE-style tokens carry a leading space (" word").
    benign = [[sse(" " + w) for w in (rng.choice(WORDS) for _ in range(200))] + [b"data: [DONE]\n\n"] for _ in range(50)]
    lag = {}
    for name, impl in impls.items():
        values = [asyncio.run(release_lag(impl, c)) for c in benign]
        lag[name] = round(sum(values) / len(values), 2)
    print(f"mean release lag on benign 200-token streams (events held back): {lag}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        report = {"seed": args.seed, "trials_per_case": args.trials, "results": results, "benign_release_lag_events": lag}
        args.out.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
