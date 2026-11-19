# Limitations and Residual Risk

The gateway is one layer of defence. This document lists what it cannot do, with the
evidence behind each statement.

## 1. Detection

| Limitation | Evidence | Mitigation |
|---|---|---|
| Random hexadecimal secrets **without a keyword** are not detected | `bare_random_hex` recall 0.000 on all splits; uniform hex cannot be told apart from hashes | Vendor format detectors; secrets managers; keyword context is detected (recall 1.000) |
| Unseen token formats with hex bodies (e.g. `shpat_…`, `dop_v1_…`) | recall 0.067 / 0.000 on held-out | Add format detectors per vendor |
| Random **public** identifiers are flagged (bech32 addresses, Drive file ids, nanoid share URLs, k8s pod hashes) | FPR 0.87–0.98 on held-out-only categories | `ENTROPY_DETECTION=log` |
| Entropy heuristic on source code: 0.21% of lines flagged | 168,548 lines of real library code; ≈34% chance per 200-line paste | `ENTROPY_DETECTION=log` for code-heavy workloads |
| Pattern detectors on code: type annotations of `password` parameters and documentation example DSNs | 0.016% of lines | Accepted; placeholder list can be extended |
| Keyword-context validation misses 0.1–0.6% of random values | Monte Carlo n = 20,000 | Accepted (statistical) |
| Encodings outside the decoder set (ROT13, custom ciphers, encryption, steganography) | By design | Out of scope for pattern-based DLP |
| Base64 tokens longer than 8,192 chars are not decoded; nesting limited to 2 levels | Bounds in `normalization.py` | Prevents decompression-style CPU abuse |
| Synthetic evaluation data; precision depends on prevalence | BENCHMARK_METHODOLOGY.md §8 | Validate on organisation-specific data before relying on numbers |

## 2. Prompt injection

The injection check matches **known override phrasings** (and their encodings) only. It
does not detect semantic, paraphrased, multilingual or indirect (retrieved-document)
injection, and it is not a model-level safety control. Treat it as telemetry or a speed
bump (`PROMPT_INJECTION_MODE=log|block`). Real mitigations are privilege separation for
agents, tool-call authorisation and provider safety features.

## 3. Streaming

* The release guarantee holds **for what the detectors detect**. For statistical detectors
  (entropy, keyword context) the tested claim is weaker: streaming never detects less than
  buffered inspection of the same text.
* With `ENTROPY_DETECTION=log`, the entropy heuristic is **not evaluated** in streams (it is
  logged only for buffered traffic).
* A whitespace-free run longer than `STREAM_MAX_HOLD_CHARS` (default 16,384) terminates
  the stream (fail closed); very long minified outputs can trigger this.
* Events are forwarded whole. A secret blocks the entire stream, and the client receives
  an SSE error event after the text released so far.

## 4. Availability and scaling

* Rate and concurrency limits are **per replica** (no shared state). With N replicas the
  effective limits are N × configured values. Exact global limits would need shared state,
  for example Redis, which was not added because the deployment does not require it.
* Inspection is CPU-bound (≈0.37 ms per KB of prompt). One worker sustains ≈236 rps of
  small requests on the test host.
* Client IP in audit events is the TCP peer; behind an ingress it is the ingress address
  (`X-Forwarded-For` is deliberately not trusted).

## 5. Transport

* IP pinning is not certificate pinning; a compromised public CA could still impersonate
  the provider (use `UPSTREAM_CA_BUNDLE` to restrict trust).
* Only one upstream URL per deployment. AWS Bedrock (SigV4) is **not** supported.

## 6. Verification gaps

* Not exercised against a live provider (opt-in tests exist) or in a real cluster. The CI
  workflow runs on GitHub-hosted Linux runners (Python 3.10–3.14, container build, smoke
  test, container scan and manifest schema validation).
* The base image is tag-pinned, not digest-pinned.
* Performance measured on one Windows workstation.
* During development one background run of the streaming evaluation stalled at ~0 CPU
  in a background shell and was stopped; it did not reproduce in the
  foreground (31 s, identical results). The cause was not identified.
