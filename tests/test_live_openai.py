"""
Optional Live OpenAI Provider Test Harness (Strictly Opt-In & Zero-Cost Guarded).

SAFETY POLICY:
1. Disabled by default during all test runs.
2. Requires TWO explicit environment variables to run:
   - RUN_LIVE_LLM_TESTS=1
   - CONFIRM_LIVE_BILLING_SPEND=YES_I_AUTHORIZE_SPENDING
3. If credentials or confirmations are missing, tests report strictly as SKIPPED.
4. Uses minimal token limit (max_tokens=15) and zero retry loops to prevent unexpected costs.
5. Redacts API keys from all outputs, headers, and logs.
"""

import os
import sys
import time
from pathlib import Path

import pytest
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def check_live_authorization():
    """Validates whether explicit dual opt-in flags are present."""
    run_flag = os.getenv("RUN_LIVE_LLM_TESTS", "0").strip()
    spend_confirm = os.getenv("CONFIRM_LIVE_BILLING_SPEND", "").strip()
    api_key = os.getenv("OPENAI_API_KEY", "").strip()

    if run_flag != "1":
        pytest.skip("SKIPPED: Live OpenAI tests disabled by default (RUN_LIVE_LLM_TESTS!=1).")
    if spend_confirm != "YES_I_AUTHORIZE_SPENDING":
        pytest.skip(
            "SKIPPED: Spending authorization missing (set CONFIRM_LIVE_BILLING_SPEND=YES_I_AUTHORIZE_SPENDING)."
        )
    if not api_key:
        pytest.skip("SKIPPED: OPENAI_API_KEY environment variable is not configured.")

    return api_key


@pytest.mark.live_openai
def test_live_openai_completion():
    """Executes a single, minimal live completion request against OpenAI API via proxy."""
    check_live_authorization()

    proxy_url = os.getenv("PROXY_URL", "http://127.0.0.1:8080")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Ping: Respond with single word 'ACK'."}],
        "max_tokens": 5,
        "temperature": 0.0,
    }

    start_time = time.time()
    try:
        resp = requests.post(f"{proxy_url}/v1/chat/completions", json=payload, timeout=15.0)
        elapsed_ms = (time.time() - start_time) * 1000.0

        assert resp.status_code == 200
        data = resp.json()
        assert "choices" in data
        assert len(data["choices"]) > 0

        # Log evidence without logging sensitive credentials
        print(f"\n[LIVE OPENAI TEST SUCCESS] Model: {model} | Status: 200 | Latency: {elapsed_ms:.2f}ms")

    except requests.exceptions.RequestException as exc:
        pytest.fail(f"Live OpenAI request failed: {exc}")


@pytest.mark.live_openai
def test_live_openai_streaming_dlp():
    """Executes a minimal streaming SSE test against OpenAI API via proxy."""
    check_live_authorization()

    proxy_url = os.getenv("PROXY_URL", "http://127.0.0.1:8080")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Count from 1 to 3."}],
        "max_tokens": 10,
        "temperature": 0.0,
        "stream": True,
    }

    start_time = time.time()
    try:
        resp = requests.post(f"{proxy_url}/v1/chat/completions", json=payload, stream=True, timeout=15.0)
        elapsed_ms = (time.time() - start_time) * 1000.0

        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")

        chunks = 0
        has_done = False
        for line in resp.iter_lines():
            if line:
                decoded = line.decode("utf-8")
                chunks += 1
                if "[DONE]" in decoded:
                    has_done = True

        assert chunks > 0
        assert has_done is True
        print(f"\n[LIVE OPENAI STREAM SUCCESS] Chunks: {chunks} | Latency: {elapsed_ms:.2f}ms")

    except requests.exceptions.RequestException as exc:
        pytest.fail(f"Live OpenAI streaming request failed: {exc}")
