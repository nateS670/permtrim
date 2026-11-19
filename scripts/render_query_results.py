"""Render live Neo4j query results as a terminal-styled PNG (README asset).

Runs the 6 showcase queries against the running Neo4j (bolt, auth) and
renders the actual rows in a terminal frame — proof the queries work on a
real database, not just as strings in a file.
"""

from __future__ import annotations

import sys
from pathlib import Path

from neo4j import GraphDatabase
from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from permtrim.graph import QUERIES

OUT = Path("/home/z/my-project/download/permtrim/docs/graph_queries.png")
URI = "bolt://127.0.0.1:7687"

BG = (24, 26, 32)
FG = (204, 208, 218)
GREEN = (152, 195, 121)
YELLOW = (235, 203, 139)
CYAN = (120, 200, 230)
RED = (235, 150, 140)
DIM = (130, 135, 145)
BAR = (55, 58, 66)

WIDTH = 1180
LINE_H = 17
TITLE_H = 40
PAD = 22


def main() -> None:
    driver = GraphDatabase.driver(URI, auth=("neo4j", "permtrim-demo"))
    lines: list[tuple[str, tuple]] = []
    try:
        with driver.session() as session:
            for index, (title, _description, cypher) in enumerate(QUERIES):
                lines.append((title, CYAN))
                records = list(session.run(cypher))
                if not records:
                    lines.append(("  (no rows — healthy for this check)", DIM))
                else:
                    keys = records[0].keys()
                    lines.append(("  " + " | ".join(keys), DIM))
                    shown = records[:4] if index != 3 else records[:3]
                    for record in shown:
                        cells = []
                        for key in keys:
                            value = record[key]
                            if isinstance(value, list) and len(str(value)) > 34:
                                value = f"[{len(value)} policies]"
                            cells.append(str(value)[:34])
                        lines.append(("  " + " | ".join(cells), FG))
                    if len(records) > len(shown):
                        lines.append((f"  ... +{len(records) - len(shown)} more rows", DIM))
                lines.append(("", FG))
    finally:
        driver.close()

    height = TITLE_H + PAD + LINE_H * len(lines) + PAD
    image = Image.new("RGB", (WIDTH, height), BG)
    draw = ImageDraw.Draw(image)

    draw.rectangle([0, 0, WIDTH, TITLE_H], fill=BAR)
    for i, color in enumerate([(240, 106, 97), (245, 191, 79), (97, 197, 84)]):
        x = 16 + i * 26
        draw.ellipse([x, TITLE_H // 2 - 6, x + 12, TITLE_H // 2 + 6], fill=color)
    title_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 12)
    body_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 13)
    draw.text(
        (WIDTH // 2 - 210, TITLE_H // 2 - 8),
        "permtrim @ neo4j — live permission-graph queries",
        fill=(210, 214, 224),
        font=title_font,
    )

    y = TITLE_H + PAD
    for text, color in lines:
        draw.text((PAD, y), text, fill=color, font=body_font)
        y += LINE_H

    OUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUT, optimize=True)
    print(f"wrote {OUT} ({WIDTH}x{height})")


if __name__ == "__main__":
    main()
