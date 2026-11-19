# Security Policy

## Supported versions

Only the current state of the default branch receives security fixes.

## Reporting a vulnerability

Please report privately through the repository host's private vulnerability reporting
(for example, GitHub Security Advisories → "Report a vulnerability"). Do not open public
issues for undisclosed vulnerabilities. Include the affected version or commit,
configuration, reproduction steps or a minimal proof of concept using **synthetic**
credentials, and the impact you observed.

This is a research project maintained on a best-effort basis; there is no guaranteed
response time. Valid reports will be acknowledged, fixed with a regression test, and
credited if you wish.

## Scope

In scope: bypasses of ingress or egress DLP (including streaming release-invariant
violations), SSRF or destination control bypasses, authentication or authorization
bypasses, resource-exhaustion issues that defeat the documented limits, and secret
disclosure through logs or error responses.

Known limitations documented in [docs/LIMITATIONS.md](docs/LIMITATIONS.md) (e.g. context-free hex
secrets, semantic prompt injection) are not vulnerabilities, but improvements are welcome.

## Safe harbour

Good-faith research against your **own** deployment, using synthetic credentials, is
welcome. Do not test against infrastructure you do not own, and do not use real
credentials.

## Synthetic credential fixtures

The test suite and the hand-written regression dataset deliberately contain
credential-*shaped* values, so that the detectors can be tested. They are not real
credentials. The values are patterned (repeated or sequential characters), PEM blocks are
truncated stubs, database URLs point at placeholder or private hosts, and the GitHub-format
tokens fail GitHub's built-in checksum. The main evaluation corpus generates its values at
runtime and commits none.

Secret scanners such as gitleaks and TruffleHog will report these files:
`benchmarks/dlp_benchmark.py`, `scripts/simulate_attack_defense.py` (a demonstration JWT)
and several files under `tests/`. The scanner rules are not suppressed in this repository.
If you find a value that looks like a working credential, please report it as described
above.
