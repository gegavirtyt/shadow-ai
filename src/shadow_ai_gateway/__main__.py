"""Command-line entry point: ``python -m shadow_ai_gateway`` / ``shadow-ai-gateway``."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    uvicorn.run(
        "shadow_ai_gateway.app:create_app",
        factory=True,
        # Container default: listen on all interfaces; restrict with GATEWAY_HOST.
        host=os.getenv("GATEWAY_HOST", "0.0.0.0"),  # noqa: S104  # nosec B104
        port=int(os.getenv("GATEWAY_PORT", "8080")),
        proxy_headers=False,  # X-Forwarded-For is not trusted unless an operator adds a trusted proxy layer
        server_header=False,
        date_header=True,
        timeout_keep_alive=int(os.getenv("GATEWAY_KEEPALIVE_TIMEOUT", "5")),
        timeout_graceful_shutdown=int(os.getenv("GATEWAY_SHUTDOWN_TIMEOUT", "20")),
        log_level=os.getenv("GATEWAY_LOG_LEVEL", "info").lower(),
        access_log=os.getenv("GATEWAY_ACCESS_LOG", "true").lower() in ("1", "true", "yes"),
    )


if __name__ == "__main__":
    main()
