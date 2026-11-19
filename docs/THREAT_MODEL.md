# Threat Model

## 1. Assets

| Asset | Why it matters |
|---|---|
| Credentials in prompts and completions (cloud keys, tokens, DB passwords, private keys) | Direct account compromise if they leave the organisation or reach a less-trusted workload |
| Provider API key held by the gateway | Billing abuse, data access at the provider |
| Internal network and cloud metadata endpoints (IMDS) | SSRF to IMDS yields instance credentials |
| Audit trail | Detection and forensics; must not itself become a secret store |
| Gateway availability | Fail-closed controls turn outages into business impact |

## 2. Adversaries and capabilities

| ID | Adversary | Capabilities assumed |
|---|---|---|
| A1 | Compromised or prompt-injected **AI workload** | Sends arbitrary JSON to the gateway with a valid workload key; may obfuscate (encodings, Unicode tricks, splitting) |
| A2 | Malicious or manipulated **model output** | Controls completion content and streaming segmentation (event boundaries, channels, tool calls) |
| A3 | **Network/DNS attacker** on the gateway's egress path | Controls DNS answers (rebinding, mixed answers), can return redirects |
| A4 | Unauthenticated **in-cluster client** | Can reach the gateway port if network policy allows |
| A5 | Resource-exhaustion attacker (A1/A4) | Large, slow, deeply nested or concurrent requests; slow or endless upstream streams |

Out of scope: a compromised gateway host or Kubernetes control plane; a malicious operator
who controls configuration; a compromised LLM provider beyond A2's output control.

## 3. Trust boundaries

1. Workload → gateway (authenticated, untrusted content).
2. Gateway → provider (TLS, operator-fixed destination; untrusted responses).
3. Gateway → log pipeline (trusted sink; events must contain no secrets).

## 4. Threats and controls (STRIDE)

| Threat | STRIDE | Control | Verification | Residual |
|---|---|---|---|---|
| Credential in prompt (A1) | I | Ingress DLP on all values and keys, normalization variants | `test_components`, DLP benchmark | Random hex without context; unseen formats with low randomness |
| Obfuscated credential (A1) | I | Base64/hex/URL/HTML/escape/zero-width/full-width/tag decoding | `test_obfuscated_secrets_are_detected_via_normalization` | Encodings outside the decoder set (e.g. ROT13, custom ciphers) |
| Secret regurgitation in buffered response (A2) | I | Buffered egress DLP on all status codes, all JSON fields incl. tool calls | integration tests | Same detector limits as ingress |
| Secret split across stream events / channels (A2) | I | `StreamGuard` release invariant, per-channel buffers | Hypothesis property tests, leak evaluation | Statistical recall of entropy/keyword validators |
| Route response around inspection via `stream` flag mismatch (A1/A2) | I | Egress mode from upstream Content-Type | `test_sse_response_to_non_streaming_request_is_still_inspected` | – |
| Known prompt-override phrasing (A1) | T | Structural regex heuristics (block/log/off) | unit tests | **Semantic** injection is not detected |
| SSRF via destination choice | I/E | Destination fixed by operator; no client override | config validation tests | Operator misconfiguration |
| DNS rebinding / mixed answers / IMDS (A3) | I/E | Resolve-validate-pin in transport; all answers validated | `test_ssrf_transport_tls.py` | – |
| Redirect to internal target (A3) | I/E | Redirects never followed | `test_upstream_redirect_to_imds_is_blocked` | – |
| TLS interception (A3) | S/I | Hostname verification with certifi or configured CA; TLS ≥ 1.2 | wrong-cert and untrusted-CA tests | Compromised public CA |
| Unauthenticated use (A4) | S/E | Fail-closed auth, per-workload keys, NetworkPolicy | integration tests | Stolen workload key (rotate) |
| Model misuse / cost escalation (A1) | E | Model allowlists, per-workload rate limits | integration tests | Per-replica limits only |
| Memory/CPU exhaustion (A5) | D | Body/response/event/hold/total-stream limits, timeouts, concurrency cap, depth limit | integration tests | CPU cost of inspecting large prompts (~0.37 ms/KB) |
| Secrets in logs | I | Audit events carry ids, lengths, keyed fingerprints only | audit tests | Operators enabling debug logging of bodies elsewhere |
| Log tampering / repudiation | R | Structured events with ids; integrity is the log pipeline's responsibility | – | No signed logs |

## 5. OWASP Top 10 for LLM Applications (2025) mapping

| Risk | Coverage |
|---|---|
| LLM01 Prompt Injection | **Partial**: known phrasings and encodings only |
| LLM02 Sensitive Information Disclosure | **Primary focus**: bidirectional secret DLP incl. streaming |
| LLM06 Excessive Agency | Partial: tool-call arguments are inspected for secrets; actions are not authorised |
| LLM10 Unbounded Consumption | Partial: size/time/concurrency/rate limits (per replica) |
| Others (supply chain, data poisoning, output handling, vector stores, misinformation) | Not addressed by the gateway |
