"""Shared pytest configuration.

* Makes ``src/`` importable so tests run from a plain checkout (no install needed).
* Configures the *legacy* v3 test-suite environment: local mock upstreams are
  allowed, the SSRF probe endpoint is enabled and workload authentication is
  disabled. Tests that exercise authentication build their own gateway with
  explicit ``Settings`` instead of relying on these defaults.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for p in (ROOT, ROOT / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

os.environ.setdefault("ALLOW_LOCAL_MOCK", "true")
os.environ.setdefault("GATEWAY_AUTH_MODE", "disabled")
os.environ.setdefault("ENABLE_TEST_ENDPOINTS", "true")
os.environ.setdefault("UPSTREAM_LLM_URL", "http://127.0.0.1:8090/v1/chat/completions")
os.environ.setdefault("UPSTREAM_PROVIDER", "generic")

import uvicorn  # noqa: E402


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _ThreadedServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:  # pragma: no cover - not used in threads
        pass


class RunningServer:
    def __init__(self, app, port: int | None = None, **config_kwargs: object) -> None:
        self.port = port or free_port()
        scheme = "https" if config_kwargs.get("ssl_certfile") else "http"
        self.url = f"{scheme}://127.0.0.1:{self.port}"
        config = uvicorn.Config(
            app=app,
            host="127.0.0.1",
            port=self.port,
            log_level="error",
            lifespan="on",
            **config_kwargs,  # type: ignore[arg-type]
        )
        self.server = _ThreadedServer(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> RunningServer:
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            if not self.thread.is_alive():
                raise RuntimeError("server thread exited during startup (configuration error?)")
            if time.monotonic() > deadline:
                raise RuntimeError("server did not start")
            time.sleep(0.02)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


@pytest.fixture
def run_server() -> Iterator[type[RunningServer]]:
    yield RunningServer


# Hypothesis profiles: "default" for everyday runs, "thorough" for release evidence
# (select with HYPOTHESIS_PROFILE=thorough).
from hypothesis import settings as _hyp_settings  # noqa: E402

_hyp_settings.register_profile("default", max_examples=300, deadline=None)
_hyp_settings.register_profile("thorough", max_examples=5000, deadline=None)
_hyp_settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "default"))
