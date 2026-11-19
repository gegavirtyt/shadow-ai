# Performance Results

Source: `benchmarks/results/perf_results.json`, produced by `python -m benchmarks.perf_benchmark`.

**Environment.** Windows 11, Intel Core (family 6 model 165), 12 logical CPUs, 15.9 GiB,
Python 3.14.4; one uvicorn worker; mock upstream, gateway and load generator in separate
processes on loopback. These numbers measure **gateway overhead on this host**. They say
nothing about provider latency and will differ on Linux servers.

## 1. Buffered (non-streaming) requests, sequential

| Prompt size | n | Direct p50 | Gateway p50 | Gateway p95 | Gateway p99 | Gateway CPU / request |
|---|---|---|---|---|---|---|
| 0.5 KB | 300 | 0.85 ms | 3.62 ms | 4.64 ms | 5.00 ms | 3.0 ms |
| 5 KB | 300 | 0.85 ms | 5.23 ms | 6.00 ms | 6.38 ms | 4.2 ms |
| 50 KB | 100 | 1.08 ms | 22.2 ms | 23.6 ms | – | 20.6 ms |
| 500 KB | 60 | 3.72 ms | 191 ms | 210 ms | – | 189 ms |

Inspection cost is **CPU-bound and linear in prompt size (≈0.37 ms/KB)**: normalization
variants × regex detectors over every JSON string. At the 1 MiB body limit, one request costs
about 0.4 s of CPU. `MAX_CONCURRENT_REQUESTS` bounds the damage but does not remove it
(see LIMITATIONS.md).

## 2. Streaming (100 events)

| Upstream pace | Metric | Direct p50 | Gateway p50 | Gateway p95 | n |
|---|---|---|---|---|---|
| back-to-back | first content event | 1.9 ms | 5.2 ms | 6.3 ms | 100 |
| back-to-back | total | 2.8 ms | 13.8 ms | 15.1 ms | 100 |
| 20 ms/event (≈50 tok/s) | **first content event** | 4.6 ms | **31.3 ms** | 45.6 ms | 40 |
| 20 ms/event | total | 3,204 ms | 3,205 ms | 3,224 ms | 40 |

At a realistic pace the first-token overhead is **≈27 ms**: the token being formed is held
until the next token shows it is complete, which costs about one inter-token interval.
Total stream duration is unaffected. Holding back only from the earliest *possible* secret
prefix, rather than a fixed character window, keeps this cost to one inter-token interval
**without weakening the release invariant** (property-tested; see
[SECURITY_DESIGN.md §3](SECURITY_DESIGN.md#3-streaming-egress-inspection-streamingpy)).

## 3. Concurrency (0.5 KB prompts, single gateway worker)

| Clients | Direct rps | Gateway rps | Gateway p50 | Gateway p95 | Gateway p99 |
|---|---|---|---|---|---|
| 8 | 1,238 | 236 | 21.4 ms | 46.2 ms | 67.5 ms |
| 32 | 776 | 163 | 125.5 ms | 401 ms | 603 ms |

One Python worker saturates at ≈200 rps on this host. Beyond that, requests queue, and p95
grows with concurrency (32 clients) while throughput falls slightly because of contention.
Scale horizontally (replicas) or run several workers per pod; the limits are per process
(DEPLOYMENT.md).

## 4. Resources

Gateway process RSS: 60.9 MiB after start, 85.8 MiB after the full run (≈5,000 requests,
including 500 KB prompts). CPU time for the whole run: 46.5 s.

## 5. Not measured

Real provider latency and TLS handshake costs; Linux; multi-worker or multi-replica
scaling; long-running soak tests for memory growth.
