# Contributing

## Setup

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check src tests benchmarks scripts infra
ruff format src/shadow_ai_gateway                 # and any test files you touched
mypy                                              # strict
bandit -q -r src -c pyproject.toml
pytest -q                                         # HYPOTHESIS_PROFILE=thorough for release evidence
python scripts/scan_repo_secrets.py
python -m benchmarks.run_dlp_benchmark --splits development
```

## Rules

1. **Security changes need a regression test** at the level where the property holds
   (unit, property, real server or real socket).
2. **Never weaken, skip or loosen a test to make it pass.** If a test's assumption is
   wrong, explain why in the commit message.
3. **Detector changes and the benchmark.** Engineer on `development`. Choose thresholds on
   `calibration` only. A change made after looking at a held-out split invalidates that
   split as blind evidence: say so in docs/BENCHMARK_RESULTS.md and add a new held-out split
   (new seed and templates), committed before it is first evaluated.
4. **Streaming soundness.** Any detector whose pattern can match whitespace must declare
   `ws_prefix_bound` and an `open_prefix` grammar; the property tests in
   `tests/test_components.py` must pass.
5. **No real credentials anywhere.** Build test values at runtime or use obviously
   synthetic fixtures in allowlisted files (`scripts/scan_repo_secrets.py`).
6. Report numbers only from committed result files, and regenerate them when the code changes.

## Dependencies

Runtime dependencies are declared in `pyproject.toml`. After changing them, regenerate
`requirements.lock` ([docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) §2) and run `pip-audit --require-hashes -r requirements.lock`.
