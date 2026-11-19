"""Process-isolated latency/throughput/resource benchmark: direct upstream vs gateway.

The mock upstream, the gateway and the load generator run in *separate processes*
(the v3 benchmark ran all three as threads of one interpreter, so GIL contention was
part of the measurement). All traffic is loopback; results characterise gateway
overhead on this host only and say nothing about provider latency.

Scenarios
* JSON completions with prompt sizes 0.5 KB / 5 KB / 50 KB / 500 KB (sequential)
* Streaming: time to first content event (FTL) and total stream time, with the mock
  emitting events back-to-back (0 ms) and at a realistic pace (20 ms/event ~ 50 tok/s)
* Concurrency: fixed request count with N parallel clients (throughput, p50/p95)
* Gateway process CPU time and peak RSS (psutil)

P99 is reported only when n >= 200.

Usage: ``python -m benchmarks.perf_benchmark [--quick] [--out benchmarks/results/perf_results.json]``
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

import httpx
import psutil

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from tests.conftest import free_port  # noqa: E402

WORDS = "Summarise the incident review and list follow-up actions for the platform team. ".split()


def prompt_of(size: int) -> dict:
    text = []
    n = 0
    i = 0
    while n < size:
        w = WORDS[i % len(WORDS)]
        text.append(w)
        n += len(w) + 1
        i += 1
    return {"model": "bench", "messages": [{"role": "user", "content": " ".join(text)[:size]}]}


def start(cmd: list[str], env: dict, port: int) -> subprocess.Popen:
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            httpx.get(f"http://127.0.0.1:{port}/health", timeout=0.5)
            return proc
        except httpx.HTTPError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError(f"server on {port} did not start: {cmd}")


def server_process(pid: int) -> psutil.Process:
    """The process actually running the server.

    On Windows a venv's python.exe is a launcher that spawns the real interpreter as a
    child, so measuring the launcher PID would report a few MiB and ~0 CPU.
    """
    proc = psutil.Process(pid)
    children = proc.children(recursive=True)
    return max([proc, *children], key=lambda p: p.memory_info().rss)


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    k = (len(s) - 1) * q
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def summary(ms: list[float]) -> dict:
    out = {"n": len(ms), "mean_ms": round(statistics.fmean(ms), 3), "p50_ms": round(pct(ms, 0.5), 3), "p95_ms": round(pct(ms, 0.95), 3)}
    if len(ms) >= 200:
        out["p99_ms"] = round(pct(ms, 0.99), 3)
    return out


def sequential(client: httpx.Client, url: str, payload: dict, n: int) -> list[float]:
    for _ in range(min(20, n)):
        client.post(url, json=payload).raise_for_status()
    out = []
    for _ in range(n):
        t = time.perf_counter()
        r = client.post(url, json=payload)
        out.append((time.perf_counter() - t) * 1000)
        r.raise_for_status()
    return out


def streaming(client: httpx.Client, url: str, tokens: int, delay_ms: float, n: int) -> tuple[list[float], list[float]]:
    payload = {"model": "bench", "stream": True, "bench_tokens": tokens, "bench_delay_ms": delay_ms, "messages": [{"role": "user", "content": "hi"}]}
    ftl, total = [], []
    for i in range(n + 3):
        t = time.perf_counter()
        first = None
        with client.stream("POST", url, json=payload) as r:
            r.raise_for_status()
            for chunk in r.iter_raw():
                if first is None and b'"content"' in chunk:
                    first = time.perf_counter()
        end = time.perf_counter()
        if i >= 3:
            ftl.append(((first or end) - t) * 1000)
            total.append((end - t) * 1000)
    return ftl, total


def concurrent_load(url: str, payload: dict, workers: int, total: int) -> dict:
    lat: list[float] = []

    def worker(count: int) -> list[float]:
        out = []
        with httpx.Client(timeout=30) as c:
            for _ in range(count):
                t = time.perf_counter()
                c.post(url, json=payload).raise_for_status()
                out.append((time.perf_counter() - t) * 1000)
        return out

    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(workers) as ex:
        for res in ex.map(worker, [total // workers] * workers):
            lat.extend(res)
    elapsed = time.perf_counter() - t0
    return {"workers": workers, "requests": len(lat), "throughput_rps": round(len(lat) / elapsed, 1), **summary(lat)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="fewer iterations (smoke run)")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    n_small = 60 if args.quick else 300
    up_port, gw_port = free_port(), free_port()
    base_env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(ROOT / "src"), str(ROOT)])}
    up = start([sys.executable, "-m", "uvicorn", "benchmarks.perf_upstream:app", "--port", str(up_port), "--log-level", "warning", "--no-access-log"], base_env, up_port)
    gw_env = {
        **base_env,
        "UPSTREAM_LLM_URL": f"http://127.0.0.1:{up_port}/v1/chat/completions",
        "UPSTREAM_PROVIDER": "generic",
        "ALLOW_LOCAL_MOCK": "true",
        "GATEWAY_AUTH_MODE": "disabled",
        "MAX_REQUEST_BODY_SIZE": str(1_048_576),
        "MAX_CONCURRENT_REQUESTS": "256",
    }
    gw = start(
        [sys.executable, "-m", "uvicorn", "shadow_ai_gateway.app:create_app", "--factory", "--port", str(gw_port), "--log-level", "warning", "--no-access-log"],
        gw_env,
        gw_port,
    )
    gw_ps = server_process(gw.pid)
    direct = f"http://127.0.0.1:{up_port}/v1/chat/completions"
    proxied = f"http://127.0.0.1:{gw_port}/v1/chat/completions"
    report: dict = {
        "environment": {
            "python": platform.python_version(), "platform": platform.platform(), "processor": platform.processor(),
            "logical_cpus": os.cpu_count(), "memory_gib": round(psutil.virtual_memory().total / 2**30, 1),
            "note": "loopback mock upstream; measures gateway overhead only, not provider latency",
        },
        "json": {}, "streaming": {}, "concurrency": {}, "gateway_process": {},
    }
    try:
        rss0 = gw_ps.memory_info().rss
        with httpx.Client(timeout=60) as client:
            for size, n in ((512, n_small), (5_120, n_small), (51_200, max(50, n_small // 3)), (512_000, 30 if args.quick else 60)):
                payload = prompt_of(size)
                cpu0 = sum(gw_ps.cpu_times()[:2])
                d = sequential(client, direct, payload, n)
                p = sequential(client, proxied, payload, n)
                cpu = sum(gw_ps.cpu_times()[:2]) - cpu0
                report["json"][f"{size}B"] = {
                    "direct": summary(d), "gateway": summary(p),
                    "overhead_p50_ms": round(pct(p, 0.5) - pct(d, 0.5), 3),
                    "gateway_cpu_ms_per_request": round(1000 * cpu / (n + min(20, n)), 3),
                }
                print(f"json {size:>7}B  direct p50 {pct(d, .5):7.2f} ms | gateway p50 {pct(p, .5):7.2f} ms p95 {pct(p, .95):7.2f} ms")
            for tokens, delay in ((100, 0.0), (100, 20.0)):
                n = 15 if args.quick else (40 if delay else 100)
                dftl, dtot = streaming(client, direct, tokens, delay, n)
                pftl, ptot = streaming(client, proxied, tokens, delay, n)
                key = f"{tokens}tok_{int(delay)}ms"
                report["streaming"][key] = {
                    "direct_first_token": summary(dftl), "gateway_first_token": summary(pftl),
                    "direct_total": summary(dtot), "gateway_total": summary(ptot),
                    "first_token_overhead_p50_ms": round(pct(pftl, .5) - pct(dftl, .5), 2),
                    "total_overhead_p50_ms": round(pct(ptot, .5) - pct(dtot, .5), 2),
                }
                print(f"stream {key:12s} FTL direct {pct(dftl, .5):7.1f} ms gateway {pct(pftl, .5):7.1f} ms | total direct {pct(dtot, .5):7.1f} gateway {pct(ptot, .5):7.1f}")
        for workers in (8, 32):
            total = 400 if args.quick else 2000
            report["concurrency"][f"{workers}_workers"] = {
                "direct": concurrent_load(direct, prompt_of(512), workers, total),
                "gateway": concurrent_load(proxied, prompt_of(512), workers, total),
            }
            c = report["concurrency"][f"{workers}_workers"]
            print(f"concurrency {workers:>2}: direct {c['direct']['throughput_rps']} rps | gateway {c['gateway']['throughput_rps']} rps p95 {c['gateway']['p95_ms']} ms")
        report["gateway_process"] = {
            "rss_start_mib": round(rss0 / 2**20, 1),
            "rss_end_mib": round(gw_ps.memory_info().rss / 2**20, 1),
            "cpu_seconds_total": round(sum(gw_ps.cpu_times()[:2]), 2),
        }
        print("gateway process", report["gateway_process"])
    finally:
        for proc in (gw, up):
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2))
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
