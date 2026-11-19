# Security Testing

`pytest -q` → **304 passed, 2 skipped** (the skipped tests call the real OpenAI API and run
only with `RUN_LIVE_LLM_TESTS=1` and `CONFIRM_LIVE_BILLING_SPEND=YES_I_AUTHORIZE_SPENDING`).
Verified on Python 3.10, 3.11, 3.12, 3.13 (fresh clone, fresh environments) and 3.14.
Branch coverage of `src/shadow_ai_gateway`: 90%.

Principles: test the real implementation at the level where the property holds (sockets
for transport claims, real servers for lifecycle claims, Hypothesis for invariants); no
broad exception assertions; every security fix has a regression test.

## 1. Suites

| Suite | Tests | Level | What it establishes |
|---|---|---|---|
| `test_streaming_invariant.py` | 6 | property (Hypothesis) | No character of a detected secret is released under arbitrary event *and* transport segmentation, for content and tool-call channels with interleaved noise channels; streaming is never weaker than buffered scanning; benign streams are forwarded byte-identical; hold limit fails closed |
| `test_components.py` | 97 | unit + property | Detector preconditions P1/P2 for the streaming proof; ReDoS timing on 200k-char adversarial inputs; per-detector positives and benign hard negatives; obfuscation decoding; normalization bounds; entropy maths vs Monte Carlo; SSE CR/LF/CRLF, chunk-boundary CR, UTF-8 splits, size limit; channel extraction (OpenAI/Anthropic/Responses); config validation; auth (no early exit); limiters; audit isolation |
| `test_gateway_integration.py` | 42 | real servers | Header hygiene and credential injection (OpenAI, Anthropic); gzip handling; stream-flag bypass; tool-call and error-body leaks; interleaved choices; size, duration and read-timeout limits; client disconnect closes upstream and frees the slot; concurrency and rate limits; chunked and slow bodies; malformed and duplicate-key JSON; authn, rotation, model authz; refusal to start without credentials; audit events contain no secrets; entropy modes |
| `test_ssrf_transport_tls.py` | 46 | sockets + real TLS | IP pinning keeps hostname TLS verification (trustme CA); wrong-host cert and untrusted CA rejected; forbidden DNS answers incl. mixed, IPv4-mapped, NAT64 and IMDS blocked **before any connect**; DNS rebinding between check and use ineffective; transport-level allowlist; env proxies ignored; fallback across validated addresses; 26-case IP policy matrix |
| Compatibility and regression suites (`test_proxy.py`, `test_openai_and_streaming.py`, `test_dlp_*`, `test_sse_parser.py`, `test_ssrf_*`, `test_fuzz_and_properties.py`, …) | 113 (+2 opt-in live-provider tests) | mixed | Regression tests for the module-level API, run against the package through `src/proxy_gateway.py` |

`test_expanded_dlp_benchmark.py` asserts zero false positives on hand-written labelled
datasets. The detector was developed against these, so the test is a **regression check**,
not an evaluation; the unbiased evaluation is in `benchmarks/` (BENCHMARK_METHODOLOGY.md).

## 2. Defects found by this test strategy during development

| Found by | Defect | Fix |
|---|---|---|
| Hypothesis invariant | `api key is: <value>` (word + colon separator) not matched | Separator grammar |
| Hypothesis invariant | Keyword-context validation is statistical (0.1–0.6% miss/value); the test assumed it was deterministic | Test reclassified; rate documented |
| Real-socket fallback test | `::1` classified as *reserved* by Python (`::/8`), blocking IPv6 loopback in mock mode and giving a wrong reason in production | Loopback checked first |
| Integration (`AAAA…AKIA…` fixture) | Word boundaries let concatenated keys evade detection | Boundary-free prefixed tokens |
| Held-out evaluation | Generic token after `=` never evaluated | Boundary fix; new held-out split |
| Attack simulation | URL-encoding + zero-width separators no longer detected (regression) | Shared decoding layer |
| Code review of the above | Variant de-duplication could shift a decoded token into the canonical slot | Explicit variants |
| Open-prefix property test design | GCP detector whitespace bound off by one (24 → 25) | Corrected |
| Ruff `PLE2502` | Literal bidi/invisible characters in source (Trojan-Source class) | Escaped |

## 3. Static and supply-chain analysis

| Check | Command | Result |
|---|---|---|
| Lint | `ruff check src tests benchmarks scripts infra` | clean |
| Format | `ruff format --check` (package + main suites) | clean |
| Types | `mypy` (strict, 14 modules) | no issues |
| SAST | `bandit -q -r src -c pyproject.toml` | 0 issues; 6 B105 false positives (display labels) and 1 B104 (container bind default) annotated |
| Dependencies | `pip-audit --strict --require-hashes -r requirements.lock` | no known vulnerabilities |
| Container | Trivy 0.57.1, `CRITICAL,HIGH`, fixable | 0 findings (Debian 12.15 base) |
| Dockerfile | hadolint 2.12.0 | clean |
| Kubernetes | kubeconform 0.6.7 `-strict`; `infra/lint_k8s.py` | 9/9 resources valid; no violations |
| Secrets | `python scripts/scan_repo_secrets.py` (gateway's pattern detectors) | 0 findings outside allowlisted synthetic fixtures |

## 4. Not verified

* Live provider traffic (opt-in tests exist, not run: no API key / spend authorisation).
* GitHub Actions execution: every workflow step was run locally, the workflow itself was not.
* Behaviour in a real Kubernetes cluster (manifests are schema-validated only).
* Mutation testing was not run on the final code.
