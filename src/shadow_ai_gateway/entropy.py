"""Entropy and randomness statistics used by the generic secret detector.

Why a length-aware test instead of a fixed threshold
----------------------------------------------------
The plug-in (empirical) Shannon entropy of a string of length ``n`` over an
alphabet of size ``k`` is bounded by ``min(log2 k, log2 n)`` and is *biased low*
for short strings. A fixed threshold such as ``H > 4.5`` therefore:

* can never fire for hexadecimal tokens (``log2 16 = 4``) - the original RND_02
  false negative;
* can never fire for tokens shorter than 23 characters (``log2 22 < 4.5``);
* fires for long random-looking but benign base64 data.

Instead we compare the observed entropy with the *expected* plug-in entropy of a
uniformly random string of the same length and alphabet size, ``E[H | n, k]``,
which is computed exactly from the binomial distribution of symbol counts::

    E[H] = -k * sum_{c=1..n} P(Bin(n, 1/k) = c) * (c/n) * log2(c/n)

A token is "consistent with random generation" when ``H >= E[H] - delta``. The
margin ``delta`` is calibrated on the calibration split of the benchmark (see
``benchmarks/``), never on the held-out split.
"""

from __future__ import annotations

import math
from collections import Counter
from functools import lru_cache

HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def shannon_entropy(data: str) -> float:
    """Plug-in Shannon entropy in bits per character."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


@lru_cache(maxsize=4096)
def expected_random_entropy(n: int, k: int) -> float:
    """Exact expectation of the plug-in entropy of ``n`` iid uniform draws over ``k`` symbols."""
    if n <= 0 or k <= 1:
        return 0.0
    p = 1.0 / k
    log_p = math.log(p)
    log_q = math.log1p(-p)
    total = 0.0
    for c in range(1, n + 1):
        log_prob = math.lgamma(n + 1) - math.lgamma(c + 1) - math.lgamma(n - c + 1) + c * log_p + (n - c) * log_q
        prob = math.exp(log_prob)
        if prob < 1e-300:
            continue
        frac = c / n
        total += prob * frac * math.log2(frac)
    return -k * total


def is_hex(token: str) -> bool:
    return bool(token) and all(ch in HEX_DIGITS for ch in token)


def alphabet_size(token: str) -> int:
    """Size of the smallest common credential alphabet consistent with ``token``."""
    core = token.rstrip("=")
    if is_hex(core):
        return 16
    size = 0
    if any(c.islower() for c in core):
        size += 26
    if any(c.isupper() for c in core):
        size += 26
    if any(c.isdigit() for c in core):
        size += 10
    symbols = {c for c in core if not c.isalnum()}
    size += min(len(symbols), 2) if symbols else 0
    return max(size, 2)


def char_class_count(token: str) -> int:
    return sum(
        (
            any(c.islower() for c in token),
            any(c.isupper() for c in token),
            any(c.isdigit() for c in token),
        )
    )


def randomness_deficit(token: str) -> float:
    """``E[H | n, k] - H(token)``: how far (in bits/char) the token is below a random string.

    Values near or below zero mean the token is statistically indistinguishable
    from uniformly random output over its alphabet.
    """
    core = token.rstrip("=")
    return expected_random_entropy(len(core), alphabet_size(core)) - shannon_entropy(core)


def looks_random(token: str, delta: float) -> bool:
    return randomness_deficit(token) <= delta


# Backward-compatible name used by the original gateway module.
calculate_shannon_entropy = shannon_entropy
