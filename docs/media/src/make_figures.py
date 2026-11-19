# ruff: noqa: PLR0917  (drawing helpers take coordinates positionally)
"""Render the publication figures in docs/media/ from the committed result files.

Usage (from the repository root):  python docs/media/src/make_figures.py

Every number in the table figures is read from benchmarks/results/*.json; nothing is
typed in by hand. The architecture diagram is drawn from the layout below and mirrors
docs/ARCHITECTURE.md. Requires Pillow and the Georgia and Segoe UI fonts (Windows);
set FIGURE_FONT_DIR to a directory containing equivalent .ttf files elsewhere.
"""

from __future__ import annotations

import itertools
import json
import os
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[3]
RESULTS = ROOT / "benchmarks" / "results"
OUT = ROOT / "docs" / "media"
SS = 3  # supersampling factor for anti-aliasing
EXPORT = 2  # exported pixels per logical pixel (retina)

FONT_DIR = Path(os.environ.get("FIGURE_FONT_DIR", "C:/Windows/Fonts"))
FONTS = {
    "title": "georgiab.ttf",
    "serif": "georgia.ttf",
    "sans": "segoeui.ttf",
    "semi": "seguisb.ttf",
    "bold": "segoeuib.ttf",
}

INK = (28, 36, 54)
MUTED = (96, 106, 122)
RULE = (214, 219, 227)
PAPER = (255, 255, 255)
PANEL = (247, 248, 250)
IN_FILL, IN_EDGE = (236, 242, 249), (52, 92, 140)  # request path
OUT_FILL, OUT_EDGE = (234, 245, 243), (36, 120, 112)  # response path
BLOCK = (190, 64, 42)  # failure outcomes
EXT_FILL, EXT_EDGE = (250, 247, 241), (150, 132, 100)  # outside the gateway


def font(kind: str, size: float) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_DIR / FONTS[kind]), int(size * SS))


class Canvas:
    def __init__(self, w: int, h: int) -> None:
        self.w, self.h = w, h
        self.img = Image.new("RGB", (w * SS, h * SS), PAPER)
        self.d = ImageDraw.Draw(self.img)

    def s(self, *v: float) -> list[int]:
        return [round(x * SS) for x in v]

    def box(self, x, y, w, h, fill, edge, r=14, width=2.0, dash=False):
        if dash:
            self.dashed_rect(x, y, w, h, edge, width)
            return
        self.d.rounded_rectangle(self.s(x, y, x + w, y + h), radius=int(r * SS), fill=fill, outline=edge, width=int(width * SS))

    def dashed_rect(self, x, y, w, h, color, width, dash=10, gap=7):
        for x0, y0, x1, y1 in ((x, y, x + w, y), (x + w, y, x + w, y + h), (x, y + h, x + w, y + h), (x, y, x, y + h)):
            length = abs(x1 - x0) + abs(y1 - y0)
            n = 0.0
            while n < length:
                a, b = n, min(n + dash, length)
                if x0 == x1:
                    self.d.line(self.s(x0, y0 + a, x0, y0 + b), fill=color, width=int(width * SS))
                else:
                    self.d.line(self.s(x0 + a, y0, x0 + b, y0), fill=color, width=int(width * SS))
                n += dash + gap

    def text(self, x, y, s, f, color=INK, anchor="la"):
        self.d.text(self.s(x, y), s, font=f, fill=color, anchor=anchor)

    def wrap(self, s: str, f, max_w: float) -> list[str]:
        words, lines, cur = s.split(), [], ""
        for w in words:
            t = (cur + " " + w).strip()
            if self.d.textlength(t, font=f) <= max_w * SS or not cur:
                cur = t
            else:
                lines.append(cur)
                cur = w
        if cur:
            lines.append(cur)
        return lines

    def para(self, x, y, s, f, max_w, color=INK, lh=1.3, size=16):
        for i, line in enumerate(self.wrap(s, f, max_w)):
            self.text(x, y + i * size * lh, line, f, color)
        return y + len(self.wrap(s, f, max_w)) * size * lh

    def arrow(self, pts, color=INK, width=2.4, head=11, dotted=False):
        for (x0, y0), (x1, y1) in itertools.pairwise(pts):
            if dotted:
                self._dotted(x0, y0, x1, y1, color, width)
            else:
                self.d.line(self.s(x0, y0, x1, y1), fill=color, width=int(width * SS))
        (x0, y0), (x1, y1) = pts[-2], pts[-1]
        dx, dy = x1 - x0, y1 - y0
        n = (dx * dx + dy * dy) ** 0.5 or 1
        ux, uy = dx / n, dy / n
        px, py = -uy, ux
        tri = [
            (x1, y1),
            (x1 - ux * head + px * head * 0.55, y1 - uy * head + py * head * 0.55),
            (x1 - ux * head - px * head * 0.55, y1 - uy * head - py * head * 0.55),
        ]
        self.d.polygon([tuple(self.s(*p)) for p in tri], fill=color)

    def _dotted(self, x0, y0, x1, y1, color, width, step=9):
        n = max(abs(x1 - x0), abs(y1 - y0))
        k = 0.0
        while k < n:
            t0, t1 = k / n, min(k + step * 0.55, n) / n
            self.d.line(
                self.s(x0 + (x1 - x0) * t0, y0 + (y1 - y0) * t0, x0 + (x1 - x0) * t1, y0 + (y1 - y0) * t1),
                fill=color,
                width=int(width * SS),
            )
            k += step

    def save(self, name: str) -> Path:
        out = self.img.resize((self.w * EXPORT, self.h * EXPORT), Image.LANCZOS)
        path = OUT / name
        out.save(path, optimize=True)
        return path


# --------------------------------------------------------------------------- diagram
def architecture() -> Path:
    W, H = 1100, 1500
    c = Canvas(W, H)
    c.text(60, 46, "Request and response lifecycle", font("title", 34))
    c.text(60, 92, "Every path through the gateway ends in an inspection step.", font("serif", 19), MUTED)

    # workload (outside, top)
    c.box(300, 140, 500, 74, EXT_FILL, EXT_EDGE, r=16)
    c.text(550, 166, "Internal AI workload", font("semi", 22), anchor="mm")
    c.text(550, 194, "OpenAI-compatible client, gateway key", font("sans", 15), MUTED, anchor="mm")

    # gateway boundary
    gx, gy, gw, gh = 40, 262, 1020, 1000
    c.box(gx, gy, gw, gh, None, (120, 130, 145), dash=True, width=2)
    c.d.rectangle(c.s(gx + 24, gy - 14, gx + 300, gy + 14), fill=PAPER)
    c.text(gx + 34, gy, "GATEWAY PROCESS", font("bold", 16), MUTED, anchor="lm")

    # columns
    lx, lw = 76, 470
    rx, rw = 594, 430
    c.text(lx, 300, "Request path", font("bold", 17), IN_EDGE)
    c.text(rx, 300, "Response path", font("bold", 17), OUT_EDGE)

    stages = [
        ("1", "Authenticate workload", "SHA-256 key digests, constant-time compare", "401"),
        ("2", "Admission control", "Per-workload rate limit, concurrency slot", "429 / 503"),
        ("3", "Bounded body read", "1 MiB cap, timeout, strict JSON, no duplicate keys", "413 / 408 / 400"),
        ("4", "Ingress DLP", "Every string and key; injection heuristics", "403"),
        ("5", "Model allowlist", "Global and per-workload", "403"),
        ("6", "Header allowlist", "Provider key injected server-side", ""),
        (
            "7",
            "SSRF-protected transport",
            "Resolve once, validate every answer, pin IP, hostname TLS, no redirects or env proxies",
            "502 / 504",
        ),
    ]
    y = 334
    tops = []
    for num, title, sub, fail in stages:
        sub_lines = c.wrap(sub, font("sans", 15), lw - 150)
        h = 52 + 20 * len(sub_lines)
        c.box(lx, y, lw, h, IN_FILL, IN_EDGE, r=12, width=1.6)
        c.d.ellipse(c.s(lx + 16, y + 16, lx + 46, y + 46), fill=IN_EDGE)
        c.text(lx + 31, y + 31, num, font("bold", 16), PAPER, anchor="mm")
        c.text(lx + 60, y + 18, title, font("semi", 19))
        for i, line in enumerate(sub_lines):
            c.text(lx + 60, y + 46 + i * 20, line, font("sans", 15), MUTED)
        if fail:
            c.text(lx + lw - 16, y + 30, fail, font("bold", 15), BLOCK, anchor="rm")
        tops.append((y, h))
        if num != "7":
            c.arrow([(lx + lw / 2, y + h), (lx + lw / 2, y + h + 18)], IN_EDGE, width=2, head=8)
        y += h + 18
    last_y, last_h = tops[-1]

    # workload -> stage 1
    c.arrow([(420, 214), (420, 290), (lx + lw / 2, 290), (lx + lw / 2, 334)], IN_EDGE)

    # provider (outside, bottom)
    py = 1310
    c.box(240, py, 620, 74, EXT_FILL, EXT_EDGE, r=16)
    c.text(550, py + 26, "LLM provider", font("semi", 22), anchor="mm")
    c.text(550, py + 54, "one operator-configured endpoint", font("sans", 15), MUTED, anchor="mm")
    c.arrow([(lx + lw / 2, last_y + last_h), (lx + lw / 2, py)], IN_EDGE)
    c.text(lx + lw / 2 + 12, last_y + last_h + 46, "HTTPS, TLS 1.2+", font("sans", 15), MUTED)

    # response path, bottom-up
    cy = 1100
    c.box(rx, cy, rw, 92, PANEL, OUT_EDGE, r=12, width=1.6)
    c.text(rx + rw / 2, cy + 30, "Classify upstream response", font("semi", 19), anchor="mm")
    c.text(rx + rw / 2, cy + 60, "by Content-Type and status, never by the request", font("sans", 15), MUTED, anchor="mm")
    c.arrow([(rx + rw / 2, py), (rx + rw / 2, cy + 92)], OUT_EDGE)

    bw, gap = (rw - 18) / 2, 18
    by, bh = 690, 330
    branches = [
        (
            rx,
            "Streaming inspection",
            "SSE with 2xx",
            [
                "Separate buffer per channel: content, tool-call arguments, each choice",
                "Hold back from the earliest possible secret prefix",
                "Full detector scan before every release",
            ],
        ),
        (
            rx + bw + gap,
            "Buffered inspection",
            "every other response",
            ["Bounded read, 8 MiB cap", "Full detector scan on every status code, including errors"],
        ),
    ]
    for bx, title, cond, bullets in branches:
        c.box(bx, by, bw, bh, OUT_FILL, OUT_EDGE, r=12, width=1.6)
        c.para(bx + 16, by + 16, title, font("semi", 19), bw - 32, size=19, lh=1.2)
        yy = by + 16 + 19 * 1.2 * len(c.wrap(title, font("semi", 19), bw - 32)) + 6
        for b in bullets:
            c.d.ellipse(c.s(bx + 18, yy + 8, bx + 24, yy + 14), fill=OUT_EDGE)
            yy = c.para(bx + 32, yy, b, font("sans", 15), bw - 48, MUTED, size=15, lh=1.32) + 10
        c.arrow([(bx + bw / 2, cy), (bx + bw / 2, by + bh)], OUT_EDGE)
        lf = font("bold", 14)
        tw = c.d.textlength(cond, font=lf) / SS
        mid = (cy + by + bh) / 2
        c.d.rectangle(c.s(bx + bw / 2 - tw / 2 - 6, mid - 12, bx + bw / 2 + tw / 2 + 6, mid + 12), fill=PAPER)
        c.text(bx + bw / 2, mid, cond, lf, OUT_EDGE, anchor="mm")

    ry, rh = 360, 268
    c.box(rx, ry, rw, rh, PANEL, OUT_EDGE, r=12, width=1.6)
    c.text(rx + 18, ry + 20, "Release to the workload", font("semi", 19))
    yy = ry + 60
    rel = [
        ("Clean", "events forwarded unmodified and in order", OUT_EDGE),
        ("Secret found", "held events dropped, SSE error event or 403", BLOCK),
        ("Limit or upstream error", "held events discarded, error returned (fail closed)", BLOCK),
    ]
    for head, body, col in rel:
        c.text(rx + 18, yy, head, font("bold", 16), col)
        yy = c.para(rx + 18, yy + 24, body, font("sans", 15), rw - 36, MUTED, size=15) + 14
    for bx, *_ in branches:
        c.arrow([(bx + bw / 2, by), (bx + bw / 2, ry + rh)], OUT_EDGE)
    c.arrow([(rx + rw / 2, ry), (rx + rw / 2, 290), (680, 290), (680, 214)], OUT_EDGE)

    # audit (outside, bottom right)
    c.box(880, 1310, 180, 74, EXT_FILL, EXT_EDGE, r=14)
    c.text(970, 1336, "Audit log", font("semi", 17), anchor="mm")
    c.text(970, 1362, "JSON events", font("sans", 14), MUTED, anchor="mm")
    c.arrow([(1040, gy + gh), (1040, 1310)], MUTED, width=2, dotted=True)
    c.text(40, 1430, "Matched values are never logged: audit events carry HMAC-keyed fingerprints.", font("serif", 16), MUTED)
    c.text(40, 1460, "Red labels show the response returned when a stage rejects a request.", font("serif", 16), MUTED)
    return c.save("architecture-request-lifecycle.png")


# --------------------------------------------------------------------------- tables
def table(name, title, subtitle, header, rows, footnotes, col_w, row_h=78, emph=None):
    W = sum(col_w) + 96
    probe = Canvas(W, 10)
    note_lines = [ln for n in footnotes for ln in probe.wrap(n, font("serif", 18), W - 96)]
    H = 150 + 64 + row_h * len(rows) + 44 + 30 * len(note_lines)
    c = Canvas(W, H)
    c.text(48, 42, title, font("title", 34))
    c.text(48, 92, subtitle, font("serif", 20), MUTED)
    x0, y = 48, 150
    xs = [x0]
    for w in col_w:
        xs.append(xs[-1] + w)
    c.d.line(c.s(x0, y + 56, xs[-1], y + 56), fill=INK, width=int(2 * SS))
    for i, h in enumerate(header):
        anchor = "ls" if i == 0 else "rs"
        hx = xs[i] + 4 if i == 0 else xs[i + 1] - 8
        c.text(hx, y + 44, h, font("bold", 19), MUTED, anchor=anchor)
    y += 64
    for r, row in enumerate(rows):
        if r % 2 == 1:
            c.d.rectangle(c.s(x0, y, xs[-1], y + row_h), fill=PANEL)
        for i, cell in enumerate(row):
            main, sub = cell if isinstance(cell, tuple) else (cell, "")
            strong = emph and emph(r, i)
            f = font("bold" if strong else ("semi" if i == 0 else "sans"), 26 if i else 23)
            col = BLOCK if strong == "bad" else (OUT_EDGE if strong else INK)
            if i == 0:
                c.text(xs[0] + 4, y + (row_h / 2 - (10 if sub else 0)), main, f, col, anchor="lm")
                if sub:
                    c.text(xs[0] + 4, y + row_h / 2 + 20, sub, font("sans", 18), MUTED, anchor="lm")
            else:
                c.text(xs[i + 1] - 8, y + (row_h / 2 - (10 if sub else 0)), main, f, col, anchor="rm")
                if sub:
                    c.text(xs[i + 1] - 8, y + row_h / 2 + 20, sub, font("sans", 18), MUTED, anchor="rm")
        y += row_h
        c.d.line(c.s(x0, y, xs[-1], y), fill=RULE, width=int(1 * SS))
    y += 34
    for line in note_lines:
        c.text(48, y, line, font("serif", 18), MUTED)
        y += 30
    return c.save(name)


def r3(v: float) -> str:
    """Round half-up to 3 decimals from the stored decimal value (0.9365 -> 0.937)."""
    return str(Decimal(str(v)).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP))


def ci(v):
    return f"[{r3(v[0])}, {r3(v[1])}]"


def dlp_table() -> Path:
    frozen = json.loads((RESULTS / "dlp_results_frozen.json").read_text())["results"]["heldout/v4.0.0"]
    final = json.loads((RESULTS / "dlp_results.json").read_text())["results"]["heldout2/v4.0.0"]

    def fpr_ci(r):
        lo, hi = r["specificity_ci95"]
        return [round(1 - hi, 4), round(1 - lo, 4)]

    rows = []
    for label in ("Precision", "Recall", "F1", "False-positive rate", "TP / FP / TN / FN"):
        row = [label]
        for res in (frozen, final):
            if label == "Precision":
                row.append((r3(res["precision"]), ci(res["precision_ci95"])))
            elif label == "Recall":
                row.append((r3(res["recall"]), ci(res["recall_ci95"])))
            elif label == "F1":
                row.append((r3(res["f1"]), ""))
            elif label == "False-positive rate":
                row.append((r3(res["false_positive_rate"]), ci(fpr_ci(res))))
            else:
                row.append((f"{res['tp']:,} / {res['fp']} / {res['tn']:,} / {res['fn']}", ""))
        rows.append(row)
    header = ["", f"heldout · n = {frozen['n']:,}", f"heldout2 · n = {final['n']:,}"]
    return table(
        "results-dlp-heldout.png",
        "Secret detection on blind held-out data",
        "Synthetic corpus; held-out splits use unseen templates and formats",
        header,
        rows,
        [
            "heldout: detector frozen before its single evaluation. heldout2: corrected detector, evaluated once.",
            "Brackets are 95% Wilson intervals. False-positive rate = benign samples flagged, not alerts that were wrong.",
            f"Positive prevalence is {final['positives'] / final['n']:.0%}, far above real traffic; "
            "deployed precision will be lower.",
        ],
        col_w=[290, 360, 370],
        row_h=92,
    )


def streaming_table() -> Path:
    data = json.loads((RESULTS / "streaming_leak.json").read_text())
    res = {k: v["v4"] for k, v in data["results"].items()}
    groups = [
        (
            "Prefixed and structured secrets",
            "message content, 7 types",
            lambda k: k.endswith("/content") and not k.startswith("keyword"),
        ),
        ("Keyword-context hex secret", "message content, 1 type", lambda k: k.startswith("keyword") and k.endswith("/content")),
        ("Secrets in tool-call arguments", "5 types", lambda k: k.endswith("/tool_args")),
    ]
    rows, total, leaks = [], 0, 0
    for label, sub, pred in groups:
        sel = [v for k, v in res.items() if pred(k)]
        trials = sum(v["trials"] for v in sel)
        det = min(v["detection_rate"] for v in sel)
        leak = sum(round(v["leak_any_rate"] * v["trials"]) for v in sel)
        total += trials
        leaks += leak
        rows.append(
            [
                (label, sub),
                f"{trials:,}",
                f"{det:.3f}" if det == max(v["detection_rate"] for v in sel) else f"≥ {det:.3f}",
                f"{leak}",
            ]
        )
    upper = max(v["leak_any_ci95"][1] for v in res.values())
    lag = data["benign_release_lag_events"]["v4"]
    return table(
        "results-streaming-leakage.png",
        "Streaming leakage under adversarial segmentation",
        f"{len(res)} cases, {data['trials_per_case']} trials each, events of 1 to 17 characters",
        ["Case", "Trials", "Detection", "Trials with a leak"],
        rows,
        [
            f"Zero secret characters leaked in {total:,} trials. The 95% upper bound on the leak rate is {upper:.1%} per case.",
            "This is evidence about these scenarios, not proof that a leak is impossible.",
            f"On benign streams the guard holds back {lag} events on average: the token still being formed.",
        ],
        col_w=[440, 140, 170, 250],
        row_h=92,
        emph=lambda r, i: "good" if i == 3 else None,
    )


def performance_table() -> Path:
    p = json.loads((RESULTS / "perf_results.json").read_text())
    s20 = p["streaming"]["100tok_20ms"]
    rows = []
    for label, sub, key in (("Buffered request", "0.5 KB prompt", "512B"), ("Buffered request", "500 KB prompt", "512000B")):
        r = p["json"][key]
        d, g = r["direct"]["p50_ms"], r["gateway"]["p50_ms"]
        rows.append(
            [
                (label, sub),
                f"{d:.2f} ms",
                f"{g:.2f} ms" if g < 100 else f"{g:.0f} ms",
                f"+{r['overhead_p50_ms']:.1f} ms" if r["overhead_p50_ms"] < 100 else f"+{r['overhead_p50_ms']:.0f} ms",
            ]
        )
    rows.append(
        [
            ("Stream, first content event", "20 ms per event (≈ 50 tokens/s)"),
            f"{s20['direct_first_token']['p50_ms']:.1f} ms",
            f"{s20['gateway_first_token']['p50_ms']:.1f} ms",
            f"+{s20['first_token_overhead_p50_ms']:.0f} ms",
        ]
    )
    rows.append(
        [
            ("Stream, total duration", "100 events"),
            f"{s20['direct_total']['p50_ms']:,.0f} ms",
            f"{s20['gateway_total']['p50_ms']:,.0f} ms",
            f"+{s20['total_overhead_p50_ms']:.1f} ms",
        ]
    )
    env = p["environment"]
    return table(
        "results-performance.png",
        "Gateway overhead (median latency)",
        f"One host, {env['logical_cpus']} logical CPUs, loopback mock upstream, one worker, Python {env['python']}",
        ["Measurement", "Direct", "Gateway", "Added"],
        rows,
        [
            "Measures gateway overhead only, not provider latency. Linux and real providers were not measured.",
            "Inspection is CPU-bound and grows linearly with prompt size.",
        ],
        col_w=[440, 180, 190, 180],
        row_h=92,
    )


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for fn in (architecture, dlp_table, streaming_table, performance_table):
        print("wrote", fn().relative_to(ROOT))
