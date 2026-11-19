# Shadow AI Defensive Gateway - hardened container image.
#
# * Dependencies are installed from requirements.lock with --require-hashes (supply-chain
#   integrity); no compiler or build tooling is present in the runtime image.
# * Application code is owned by root and not writable by the runtime user, and nothing is
#   written at runtime, so the container runs with a read-only root filesystem.
# * Runs as an unprivileged UID/GID (10001) with no login shell.
# * For fully reproducible builds pin both FROM lines to a digest, e.g.
#   FROM python:3.12-slim-bookworm@sha256:<digest>


FROM python:3.15-slim-bookworm AS builder
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.lock .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.lock

FROM python:3.15-slim-bookworm AS runtime
RUN groupadd --system --gid 10001 gateway \
    && useradd --system --uid 10001 --gid gateway --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gateway
COPY --from=builder /opt/venv /opt/venv
COPY src/shadow_ai_gateway /app/shadow_ai_gateway
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=8080
WORKDIR /app
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["python", "-m", "shadow_ai_gateway"]
