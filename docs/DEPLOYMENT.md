# Deployment

## 1. Configuration reference

All configuration is read from environment variables at startup and **validated**; the
gateway refuses to start on unsafe or inconsistent settings (exit code 3 under uvicorn).

| Variable | Default | Notes |
|---|---|---|
| `UPSTREAM_LLM_URL` (alias `UPSTREAM_TARGET_URL`) | `https://api.openai.com/v1/chat/completions` | Fixed destination; host must be in the allowlist; no userinfo; `http` only with mock mode |
| `UPSTREAM_PROVIDER` | `openai` | `openai` (Bearer), `anthropic` (`x-api-key`, `anthropic-version`), `generic` (no credential) |
| `UPSTREAM_API_KEY` (or `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`) | – | Injected server-side; never accepted from clients |
| `ALLOWED_UPSTREAM_HOSTS` | `api.openai.com,api.anthropic.com` | Also enforced inside the transport |
| `UPSTREAM_CA_BUNDLE` | certifi | Restrict trusted CAs |
| `GATEWAY_AUTH_MODE` | `required` | `disabled` only for local development |
| `GATEWAY_WORKLOADS_FILE` / `GATEWAY_WORKLOADS_JSON` | – | `[{"id": "...", "key_sha256": ["<hex>", ...], "allowed_models": ["gpt-4o-mini"]}]` |
| `GATEWAY_API_KEY` | – | Single legacy workload `default` (≥ 24 chars, no model restriction) |
| `ALLOWED_MODELS` | – (no restriction) | Comma-separated `fnmatch` patterns, applied to all workloads |
| `OPENAI_MODEL` / `DEFAULT_MODEL` | `gpt-4o-mini` | Filled in when an OpenAI request omits `model` |
| `PROMPT_INJECTION_MODE` | `block` | `block`, `log`, `off` |
| `ENTROPY_DETECTION` | `block` | `block`, `log`, `off` (legacy `true`/`false`) |
| `MAX_REQUEST_BODY_SIZE` | 1048576 | bytes (alias `MAX_PAYLOAD_SIZE_BYTES`) |
| `REQUEST_BODY_TIMEOUT` | 30 | seconds to receive the request body |
| `MAX_RESPONSE_BODY_SIZE` | 8388608 | buffered upstream responses |
| `MAX_JSON_DEPTH` | 64 | |
| `MAX_CONCURRENT_REQUESTS` | 64 | per process; 503 when exceeded |
| `RATE_LIMIT_PER_MINUTE` | 0 (off) | per workload, per process |
| `UPSTREAM_CONNECT_TIMEOUT` / `_READ_` / `_WRITE_` / `_POOL_TIMEOUT` | 5 / 60 / 10 / 5 | seconds |
| `UPSTREAM_MAX_CONNECTIONS` / `UPSTREAM_MAX_KEEPALIVE` | 100 / 20 | |
| `STREAM_DLP_WINDOW_SIZE` | 64 | ≥ 50 (validated against detector bounds) |
| `STREAM_MAX_HOLD_CHARS` / `STREAM_MAX_EVENT_BYTES` / `STREAM_MAX_TOTAL_BYTES` / `STREAM_MAX_DURATION` | 16384 / 1 MiB / 32 MiB / 300 s | fail closed |
| `AUDIT_HMAC_KEY` | random per process | Set a ≥ 32-byte random value so fingerprints correlate across replicas and restarts |
| `GATEWAY_HOST` / `GATEWAY_PORT` | `0.0.0.0` / 8080 | |
| `GATEWAY_ACCESS_LOG`, `GATEWAY_LOG_LEVEL`, `GATEWAY_KEEPALIVE_TIMEOUT`, `GATEWAY_SHUTDOWN_TIMEOUT` | `true`, `info`, 5, 20 | |
| `ALLOW_LOCAL_MOCK`, `ENABLE_TEST_ENDPOINTS`, `ENABLE_API_DOCS` | `false` | Development only |

### Creating workload credentials

```bash
KEY=$(python -c "import secrets;print(secrets.token_urlsafe(32))")      # give to the workload
python -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" "$KEY"
```

Put only the digest in `workloads.json`. **Rotation:** add the new digest next to the old
one, roll the workload, then remove the old digest.

## 2. Container

```bash
docker build -t shadow-ai-gateway .
docker run --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e UPSTREAM_API_KEY -e GATEWAY_WORKLOADS_JSON -e AUDIT_HMAC_KEY -p 8080:8080 shadow-ai-gateway
```

Verified locally: the image builds from the hash-pinned `requirements.lock`, runs as UID
10001 with zero effective capabilities on a read-only root filesystem, the Docker
`HEALTHCHECK` reports healthy, it exits when no credentials are configured, and Trivy
reports no fixable HIGH/CRITICAL vulnerabilities. The CI workflow repeats the build, a
hardened smoke run (read-only root filesystem, all capabilities dropped, UID 10001,
`/health`) and the Trivy scan on every push to `main` and every pull request. For
reproducible builds, pin the base image by digest in both `FROM` lines.

Regenerate the lock after changing dependencies:
`uv pip compile pyproject.toml --python-version 3.12 --python-platform linux --generate-hashes -o requirements.lock`.

## 3. Kubernetes

`infra/k8s-gateway.yaml` contains Namespace (Pod Security `restricted`), ServiceAccount
(no token), ConfigMap, Deployment (2 replicas, non-root, read-only rootfs, all capabilities
dropped, RuntimeDefault seccomp, requests/limits, startup/liveness/readiness probes),
Service, PodDisruptionBudget and a NetworkPolicy. The policy admits only
`app: autonomous-ai-worker` pods, and allows egress only to DNS and TCP 443 outside RFC 1918,
CGNAT, loopback and link-local ranges. Secrets are created out of band (see the file
header). `infra/k8s-ai-workload.yaml` points the workload SDK at the gateway via
`OPENAI_BASE_URL`; `infra/k8s-shadow-ai-netpol.yaml` restricts the workload to DNS and the
gateway.

```bash
kubectl apply -f infra/k8s-gateway.yaml -f infra/k8s-shadow-ai-netpol.yaml -f infra/k8s-ai-workload.yaml
```

The manifests are validated with kubeconform (`-strict`) and `infra/lint_k8s.py`; they have
not been applied to a live cluster in this release.

**Scaling.** Limits are per process. To keep an organisation-wide budget, divide it by
replicas × workers. Session affinity is not needed, since the gateway is stateless apart
from those counters.

## 4. Cloud hardening (AWS)

* Enforce IMDSv2 with hop limit 1 on nodes (`aws ec2 modify-instance-metadata-options
  --http-tokens required --http-put-response-hop-limit 1`), and keep `hostNetwork: false`.
* Give the gateway no cloud IAM role unless required (it needs none for OpenAI/Anthropic).
  `infra/iam_*.json` are least-privilege examples for a lab; `infra/provision_lab.ps1`
  and `infra/launch_workload.ps1` take all account-specific ids as parameters.
