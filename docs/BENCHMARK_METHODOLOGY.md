# Benchmark Methodology

## 1. Questions

1. How accurately does the detector find credentials in text, per credential type, and how
   often does it flag benign technical content? (`benchmarks/run_dlp_benchmark.py`)
2. Does it generalise to **unseen contexts** and **unseen formats**? (held-out splits)
3. Can a streamed secret reach the client before inspection? (`benchmarks/streaming_leak_eval.py`)
4. What is the false-positive rate on **real** source code? (`benchmarks/code_fp_eval.py`)
5. What does inspection cost in latency, throughput and resources? (`benchmarks/perf_benchmark.py`)

The DLP runner and the streaming evaluation can optionally evaluate an earlier reference
implementation on identical inputs when its git commit is available locally
(`--compare-v3`); the published results for this gateway do not depend on it.

## 2. Corpus (`benchmarks/corpus.py`)

**Ground truth by construction.** A sample is positive iff the generator embedded a
credential, i.e. a value that grants access if leaked. Labels never depend on detector
behaviour, so a sample the detector misses is still a positive.

**Synthetic values.** Format-correct values (correct prefixes, lengths and alphabets) are
generated at runtime from seeded RNGs. No secret-shaped literals are committed, and the
corpus is bit-for-bit reproducible: `python -m benchmarks.corpus` prints
`manifest_sha256 2dcf96f64de05ca71046a70a98b5aa04c281bd14a78bacdcc8834220a310f79a`.

**Categories.** 22 credential categories (provider tokens, PEM keys, DB URLs, keyword and
password assignments, bare random tokens, five obfuscation schemes) and 20 hard-negative
categories (hex digests, git SHAs, UUIDs, ULIDs, image digests, SRI hashes, Base64-encoded
prose, SSH and PEM public keys, publishable keys, placeholders, placeholder DSNs,
identifiers, URLs, ARNs, labelled request ids, code, prose). The set deliberately includes
expected failures (`bare_random_hex`).

**Splits.** Disjoint seeds **and disjoint template pools** (contexts the value is embedded in):

| Split | Seed | n | Templates | Use |
|---|---|---|---|---|
| development | 1101 | 1,260 | chat questions, config snippets, code fences, JSON | engineering detectors and exemptions |
| calibration | 2202 | 1,260 | different phrasings, YAML, XML, shell | choosing entropy margins only |
| heldout | 3303 | 3,060 | log lines, CSV, stack traces, curl, Markdown tables, INI, chat, docker | evaluated after freeze |
| heldout2 | 4404 | 3,000 | Terraform, JSON logs, e-mail, notebooks, SQL, diffs, K8s env, Go | defined and evaluated after a post-hoc fix (§4) |

Each held-out split adds **categories that appear in no other split** (formats never used
during engineering): `heldout`: npm, DigitalOcean, SendGrid, header token; nanoid share
URLs, npm integrity, k8s pod names, AWS request ids, git-lfs pointers. `heldout2`: Hugging
Face, Linear, Shopify, Azure storage connection strings; container ids, semver build
metadata, bech32 addresses, Drive file ids.

Stratification: a fixed number of samples per category and split (30 / 30 / 60 / 60),
de-duplicated by text. Prevalence is ~52% positive; **precision depends on prevalence**, so
per-category FPR is the more transferable number for real traffic, where secrets are rare.

## 3. Protocol

The evaluation followed this order:

1. Development-split engineering complete; margins selected on calibration only
   (rule fixed beforehand: maximise recall subject to calibration FPR ≤ 1%, ties to the
   smaller margin; `benchmarks/results/calibration.json`). **Detector frozen; held-out not
   yet evaluated.**
2. Held-out evaluated **once** → `benchmarks/results/dlp_results_frozen.json`
   (primary blind result).
3. The held-out run exposed a generic tokenisation defect (tokens after `=` were
   never evaluated). It was fixed, together with inline `shaNNN-` digests (same family as an
   existing exemption). Format-specific false positives found on held-out were **not** tuned
   away. Because the first held-out split is no longer blind, `heldout2` was defined and
   committed **before** its first evaluation.
4. `heldout2` evaluated once → `benchmarks/results/dlp_results.json` (second blind result).
   Post-fix numbers on `heldout` are reported as **post-hoc**.

The ordering was recorded in the private development history, which is not part of the
public repository. Readers can verify that the `heldout2`, development, calibration and post-hoc numbers
**reproduce** (the corpus is deterministic and identified by its manifest hash). The frozen
result (`dlp_results_frozen.json`) was produced by the detector before the fix, on an
earlier corpus build (its manifest hash differs), so it cannot be regenerated from the
published code. The **ordering** of the evaluations cannot be verified from the public
repository alone.

## 4. Metrics

Per split and category: TP, FP, TN, FN; precision, recall, F1, specificity, FPR, FNR,
mean scan time. Intervals are 95% Wilson score intervals. A sample counts as detected if
any finding is reported (the gateway blocks on any finding). Prompt-injection samples are
excluded from the secret benchmark; the injection heuristic is covered by tests only.

## 5. Streaming leak evaluation

For each case (8 secret kinds in `delta.content`, 5 in tool-call arguments), 300 trials embed a secret in random prose. The content is cut into events
of 1–17 characters, and we measure detection, whether any secret character reached the
client, whether the whole secret did, and the mean number of leaked characters. Release lag
is measured on 50 benign 200-token streams with BPE-style leading-space tokens (seed
20261118).

## 6. Real-code false positives

Every non-empty line of the installed `starlette`, `httpx`, `httpcore`, `fastapi`, `anyio`,
`uvicorn`, `pydantic`, `pytest` and `hypothesis` sources (versions recorded in the output)
is scanned. This code contains no credentials, so every flagged line is a false positive.

## 7. Performance

Mock upstream, gateway and load generator run as **separate processes** on loopback. The
upstream adds no latency unless asked to (streaming at 0 or 20 ms per event). Prompt sizes
range 0.5 KB–500 KB; n = 300 for small payloads, P99 is reported only for n ≥ 200, there are
20 warm-up requests, and gateway CPU and RSS come from psutil on the real interpreter process.
Results characterise **gateway overhead on one host**, not provider latency.

## 8. Threats to validity

* **Synthetic data.** Generated values follow documented formats but are not real leaked
  credentials; real text is messier. Templates are hand-written.
* **Category overlap.** Held-out splits share most categories with development; unseen
  categories are few (4+5 and 4+4) and n = 60 each.
* **Prevalence.** Corpus prevalence (~52%) is far above real-world prevalence; precision in
  deployment will be lower than reported.
* **Single annotator, labels by construction.** Some negatives are arguable (e.g. nanoid
  share URLs behave like bearer capabilities).
* **Performance on one Windows workstation**, single uvicorn worker, loopback only.
