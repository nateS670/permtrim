#!/usr/bin/env python3
"""Render the permtrim demo output as a terminal-styled PNG (README asset).

Runs `permtrim demo`, captures stdout, wraps it in terminal chrome (macOS
window styling, prompt line), and renders to PNG with Pillow. No external
binaries needed.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "docs" / "demo_screenshot.png"

# Terminal palette
BG = (24, 26, 32)
FG = (204, 208, 218)
GREEN = (140, 220, 140)
YELLOW = (235, 203, 139)
CYAN = (120, 200, 230)
RED = (235, 150, 140)
DIM = (130, 135, 145)
BAR = (55, 58, 66)

WIDTH = 1020
PAD_X = 26
LINE_H = 20
TITLE_H = 40


def classify(line: str) -> tuple:
    """Pick a color and weight for a demo output line."""
    stripped = line.strip()
    if stripped.startswith("==="):
        return DIM, False
    if stripped.startswith("---"):
        return DIM, False
    if stripped.startswith("ANALYZE") or stripped.startswith("TIGHTEN") or stripped.startswith("OUTPUT"):
        return CYAN, True
    if stripped.startswith("result"):
        return GREEN, True
    if "risk=50" in line or "grants" in line:
        return YELLOW, False
    if "verified" in line:
        return GREEN, False
    if "idle" in line:
        return DIM, False
    return FG, False


def main() -> None:
    demo = subprocess.run(
        [sys.executable, "-m", "permtrim", "demo"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=300,
    )
    if demo.returncode != 0:
        print(demo.stderr[-2000:])
        raise SystemExit("demo failed")

    lines = demo.stdout.rstrip("\n").splitlines()
    prompt = ["$ permtrim demo", ""]
    lines = prompt + lines

    height = TITLE_H + PAD_X + LINE_H * len(lines) + PAD_X
    image = Image.new("RGB", (WIDTH, height), BG)
    draw = ImageDraw.Draw(image)

    # --- title bar
    draw.rectangle([0, 0, WIDTH, TITLE_H], fill=BAR)
    for index, color in enumerate([(240, 106, 97), (245, 191, 79), (97, 197, 84)]):
        x = 16 + index * 26
        draw.ellipse([x, TITLE_H // 2 - 6, x + 12, TITLE_H // 2 + 6], fill=color)
    try:
        title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 13)
        body_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 14)
    except OSError:
        title_font = body_font = ImageFont.load_default()
    draw.text((WIDTH // 2 - 60, TITLE_H // 2 - 8), "permtrim — zsh", fill=(210, 214, 224), font=title_font)

    # --- body
    y = TITLE_H + PAD_X
    for line in lines:
        color, bold = classify(line)
        font = body_font
        if line.startswith("$ "):
            draw.text((PAD_X, y), "$", fill=GREEN, font=font)
            draw.text((PAD_X + 18, y), "permtrim demo", fill=FG, font=font)
        else:
            draw.text((PAD_X, y), line, fill=color, font=font)
        y += LINE_H

    OUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUT, optimize=True)
    print(f"wrote {OUT} ({image.size[0]}x{image.size[1]})")


if __name__ == "__main__":
    main()
