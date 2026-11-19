# Benchmark Results

All numbers come from files in `benchmarks/results/` and can be regenerated with the
commands in [BENCHMARK_METHODOLOGY.md](BENCHMARK_METHODOLOGY.md). Brackets are 95% Wilson
intervals.

## 1. Headline: blind held-out evaluations

| Evaluation | n | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| `heldout`, frozen detector (blind) | 3,060 | 0.907 [0.891, 0.920] | 0.891 [0.875, 0.906] | 0.899 | 0.095 |
| `heldout2`, after fix (blind) | 3,000 | **0.925** [0.911, 0.937] | **0.924** [0.910, 0.937] | **0.925** | **0.081** |

Other splits: development F1 0.974; calibration 0.977; `heldout` post-hoc (**not blind**)
0.923; hand-written regression sets 1.000 (n = 117; the detector was developed against
these, so treat them as a regression check, not an evaluation).

The drop from development/calibration (F1 ≈ 0.97, FPR 0) to held-out (F1 ≈ 0.92, FPR ≈ 8%)
comes almost entirely from the **held-out-only formats**. On every benign category that
also exists in development, held-out FPR is **0.000** in both held-out splits, despite new
contexts. Generalisation across *contexts* works; generalisation to *unseen random-looking
formats* does not (§3).

## 2. Per-category results (`heldout2`, n = 60 each)

**Credentials (recall).** 1.000 for AWS key id, AWS secret (context), AWS session token,
GitHub classic and fine-grained, GitLab, Slack token and webhook, Google API key, GCP
service-account JSON, OpenAI, Anthropic, Stripe secret, PEM private key, database URL,
keyword hex, keyword generic, password assignment, obfuscated provider tokens, bare random
base62, bare random base64-40, Azure storage connection string (unseen).
Unseen formats: Hugging Face 0.983, Linear 0.983, **Shopify `shpat_`+hex 0.067**.
**Bare random hex: 0.000** (expected; §3).

**Benign (FPR).** 0.000 for hex digests, git SHAs, MD5, UUIDs, ULIDs, image digests,
semver, container ids (unseen), ARNs, URLs, identifiers, code, prose, placeholders,
labelled request ids, SRI hashes, Base64 English, SSH public keys, PEM public material,
publishable keys and placeholder DSNs. Unseen random public identifiers: **bech32 addresses
0.967, Drive file ids 0.983**.

`heldout` (post-hoc) shows the same pattern: unseen k8s pod names 0.867, nanoid share URLs
0.983, npm integrity 0.000 (after the inline-digest fix; 0.800 when frozen), DigitalOcean
`dop_v1_`+hex recall 0.000.

## 3. Error analysis

| Error class | Cause | Status |
|---|---|---|
| Random **hex** secrets without context (recall 0) | Uniform hex is statistically identical to SHA/commit digests; flagging it would make every hash a false positive | Limitation. Detected only with a keyword (`api_key = <hex>`: recall 1.000) |
| Hex-bodied unseen formats (`shpat_`, `dop_v1_`) | Same as above; prefix unknown to the pattern set | Limitation; add format detectors per vendor |
| Random **public** identifiers (bech32, Drive ids, nanoid URLs, pod hashes) | Context-free randomness cannot distinguish public random ids from secret random tokens | Limitation; use `ENTROPY_DETECTION=log` where this matters |
| Keyword-context miss (0.1–0.6% per random value) | Statistical validator with δ = 0.40 (Monte Carlo, n = 20,000) | Documented |
| Frozen detector: tokens after `=` never evaluated | Tokeniser boundary defect found by the first held-out run | Fixed; see §3 of the methodology |

## 4. Streaming leak evaluation

300 trials per case, events of 1–17 characters (`benchmarks/results/streaming_leak.json`).

| Case | Detection rate | Any-character leak rate |
|---|---|---|
| AWS, GitHub, Slack, Google, PEM (2 forms), DB URL in `delta.content` | 1.000 | 0.000 |
| Keyword-context hex secret in `delta.content` | 1.000 | 0.000 |
| AWS / GitHub / PEM / DB / keyword secret in **tool-call arguments** | 1.000 each | 0.000 each |

**0 leaked characters in 3,900 trials** (upper 95% Wilson bound per case: 1.3%). Mean
release lag on benign streams: **0.95 events** (the token currently being formed).

The result file also contains the same measurements for an earlier single-module
implementation that was evaluated on the identical streams as a reference point. The
public documentation reports only the gateway described here.

## 5. False positives on real source code

168,548 non-empty lines of third-party library code (`benchmarks/results/code_fp.json`):

| Detector group | Flagged lines | Rate [95% CI] | P(≥1 FP in a 200-line paste) |
|---|---|---|---|
| Generic entropy heuristic | 352 | 0.209% [0.19%, 0.23%] | **34%** |
| Pattern + keyword detectors | 27 | 0.016% [0.01%, 0.02%] | 3% |

The paste estimate assumes independent lines: 1 − (1 − rate)²⁰⁰.

Entropy false positives are mostly camel-case class names and GitHub comment anchors.
Pattern false positives are type annotations of parameters named `password` (annotation
text is taken as the value) and documentation example DSNs whose password is `pass`. This
is why the entropy heuristic has a `log` mode; it is the main usability limitation for
developer-assistant traffic.
