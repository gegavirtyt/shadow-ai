# Security Design

Each section states the control, the reasoning that it is correct, and where it is tested.

## 1. Secret detection (`detectors.py`, `entropy.py`)

### 1.1 Format detectors
Eighteen detectors: AWS key ids and session tokens, GitHub classic/fine-grained, GitLab,
Slack tokens and webhooks, Google API keys / OAuth secrets / service-account key ids,
OpenAI, Anthropic, Stripe live keys, PEM private-key headers, database URLs with
credentials, keyword assignments (`api_key = …`, `password: …`), and `Bearer` values.

* Tokens with distinctive public prefixes are matched **without word boundaries**: gluing a
  key to adjacent text (`xxxAKIA…`) must not evade detection. The false-positive cost is
  negligible (P(`AKIA`+16×[A-Z0-9]) at a random base64 position ≈ 6×10⁻¹²).
* Placeholders are suppressed (`<token>`, `${VAR}`, `os.getenv(...)`, `********`,
  `your_key_here`, …), and DB URLs with placeholder passwords are not reported.
* Password assignments report any concrete non-placeholder value of ≥ 8 characters,
  because passwords are low-entropy by nature.

### 1.2 Length-aware randomness test
A fixed threshold such as `H > 4.5 bits/char` cannot fire for hexadecimal
(`log2 16 = 4`) or for any token shorter than 23 characters (`log2 22 < 4.5`). It also misses
about a third of random 32-character alphanumeric secrets (E[H] = 4.55, σ ≈ 0.14).

The gateway compares a token's plug-in entropy with the **exact expected entropy of a uniformly
random string of the same length and alphabet**:

```
E[H | n, k] = -k · Σ_{c=1..n} P(Bin(n, 1/k) = c) · (c/n) · log2(c/n)
```

A token "looks random" if `H ≥ E[H] − δ`. The formula is checked against 3,000-sample Monte
Carlo means (`test_expected_entropy_matches_monte_carlo`, error < 0.01 bits). The margins
`δ_generic = 0.25` and `δ_context = 0.40` were selected **on the calibration split only**
(`benchmarks/calibrate_entropy.py`).

Generic (context-free) candidates must also be ≥ 20 characters, not pure hex, mix ≥ 2
character classes, not decode to printable text (encoded content is scanned via
normalization instead), and not be a known public format (PEM public blocks, `ssh-*`
keys, `data:` URIs, ULIDs, `pk_live_`, SRI `shaNNN-` digests, labelled digests/ids). URLs
are evaluated per path/query segment.

### 1.3 Enforcement modes
Pattern and keyword detectors always block. The generic entropy heuristic is configurable
(`ENTROPY_DETECTION=block|log|off`, default `block`) because it has a measured
false-positive rate of 0.21% per line on real source code (BENCHMARK_RESULTS.md §5).

## 2. Normalization (`normalization.py`)

Normalization produces **additional variants**; the forwarded request is always the
original bytes, so normalization can never change the meaning of legitimate content. The
decoding layer applies NFKC, HTML entities, URL decoding (≤ 3 rounds), `\xHH`/`\uHHHH`
escapes and Unicode tag characters. Secret detection then strips invisible characters;
injection matching additionally treats them as word separators and collapses spaced
letters. Base64/hex tokens (16–8192 chars) are decoded when they yield printable text,
recursing at most 2 levels and 64 tokens. All steps are bounded and run only if their
trigger characters are present. ReDoS resistance is tested on 200k-character inputs.

## 3. Streaming egress inspection (`streaming.py`)

**Parser.** Byte-level, WHATWG line rules (CR, LF, CRLF; a trailing CR waits for the next
byte), multi-line `data:` joined with `\n`, BOM-tolerant, events capped by
`STREAM_MAX_EVENT_BYTES`. Splitting on ASCII terminators never cuts a UTF-8 sequence.

**Channels.** Text is accumulated per JSON path, with list positions replaced by the
element's `index` (OpenAI tool-call deltas) and `*index` fields folded in (Anthropic,
Responses API). Interleaved choices or tool calls therefore cannot split a secret across
buffers. Non-content strings (e.g. error messages, tool names) are scanned per event.

**Release rule.** For each channel let `r` be the start of the trailing non-whitespace run
and `W` the window (`STREAM_DLP_WINDOW_SIZE`, ≥ 50). The *cut* is the earliest `s ∈ [r−W, r)`
where `text[s:r]` fullmatches `OPEN_PREFIX_RE`, or `r` if none does. An event is released
only if each of its channel contributions ends at or before that channel's cut.

**Correctness argument.** Preconditions, both property-tested:
(P1) a match either has no whitespace, or its whitespace lies in a prefix ≤ `ws_prefix_bound ≤ W`;
(P2) `OPEN_PREFIX_RE` fullmatches every whitespace-terminated prefix of such a match.
If part of an incomplete match `[s,t)` had been released, some released contribution would
end at `e > s` with `e ≤ cut`. A whitespace-free match lies inside the trailing run, so
`s ≥ r ≥ cut`: contradiction. Otherwise the match covers the whitespace at `r−1`; by (P1)
`s ≥ r−W`, and by (P2) `text[s:r]` fullmatches the grammar, so `cut ≤ s`: contradiction.
Complete matches are found by the scan that precedes every release decision.

**Scope of the guarantee.** It covers what the detectors can detect. Entropy and keyword
validators have *statistical* recall (§1.2), and the guarantee is "streaming is never
weaker than buffered inspection" (tested), not "every secret is caught".

**Fail-closed limits.** Retained text per channel (`STREAM_MAX_HOLD_CHARS`), total bytes,
duration, event size; upstream errors and timeouts discard held events and emit an SSE
error event. The response object always closes the upstream stream and releases its
concurrency slot in a cancellation-shielded `finally`.

## 4. Outbound transport (`ssrf.py`)

1. The destination comes from configuration only; startup refuses non-allowlisted hosts,
   embedded credentials and plaintext HTTP outside mock mode.
2. `SSRFProtectedBackend.connect_tcp` re-checks the host against the allowlist, resolves
   it, validates **every** answer (any forbidden answer rejects the connection), then
   connects to a validated **IP literal**, trying each in turn. No second resolution happens,
   so rebinding between check and use is impossible.
3. httpcore passes the URL hostname to `start_tls` independently of the connect address,
   so SNI and certificate verification remain hostname-based. This is IP pinning, *not*
   certificate pinning. It is proven with real TLS servers (correct cert accepted,
   other-host cert and untrusted CA rejected).
4. IP policy: explicit always-blocked ranges (link-local/IMDS incl. ECS `169.254.170.2`,
   multicast, reserved, unspecified) and private/loopback/CGNAT/documentation ranges outside
   mock mode. Embedded IPv4 in IPv4-mapped, IPv4-compatible, 6to4, Teredo and NAT64
   addresses is extracted and validated too. Loopback is checked before Python's
   `is_reserved` (which classifies `::/8`, containing `::1`, as reserved).
5. `follow_redirects=False`, `trust_env=False` (no `HTTP(S)_PROXY`, no `.netrc`), no retries,
   TLS ≥ 1.2.

## 5. Authentication and authorization (`auth.py`)

* Fail closed: `GATEWAY_AUTH_MODE=required` by default; the gateway does not start without
  credentials. `disabled` must be set explicitly (local development only).
* Per-workload credentials are stored as SHA-256 digests (appropriate for high-entropy
  random keys, not for human passwords). Several digests per workload allow rotation. The
  presented key is compared against every digest with `hmac.compare_digest` without early
  exit (tested). Keys shorter than 24 characters are rejected.
* Least privilege: global and per-workload model allowlists (`fnmatch`); a restricted
  workload that omits `model` is denied.
* The client's `Authorization` header is never forwarded; the provider key is injected
  server-side. Request and response headers are allowlisted.

## 6. Request hardening (`app.py`, `inspection.py`)

Bounded streaming body read with timeout (protects against chunked bodies without
`Content-Length` and against slow bodies); strict JSON with duplicate-key rejection
(prevents parser-differential smuggling); iterative depth check (no `RecursionError`);
API docs, test endpoints and configuration details hidden by default; `X-Request-ID`
sanitised; `nosniff` and `no-store` on all gateway responses.

## 7. Audit logging (`audit.py`)

JSON events: `event_id`, timestamp, type, decision, policy id, request id, workload id,
client IP, path, upstream host and detections (detector, category, length,
`value_fingerprint`). Fingerprints are `HMAC-SHA256(AUDIT_HMAC_KEY, value)[:32]`. Without a
key, a random per-process key is used and the event says `fingerprint_scope: "process"`.
Events never contain request/response content, header values, secret fragments or
tracebacks (tested). A failing log handler cannot break request handling.
