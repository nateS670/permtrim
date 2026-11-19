"""Run the 6 permtrim analysis queries against a live Neo4j and print results."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from neo4j import GraphDatabase

from permtrim.graph import QUERIES

URI = "bolt://127.0.0.1:7687"


def main() -> None:
    driver = GraphDatabase.driver(URI, auth=None)
    try:
        with driver.session() as session:
            for title, _description, cypher in QUERIES:
                print("=" * 70)
                print(title)
                print("-" * 70)
                records = list(session.run(cypher))
                if not records:
                    print("  (no rows)")
                    continue
                keys = records[0].keys()
                print("  " + " | ".join(keys))
                for record in records[:10]:
                    values = []
                    for key in keys:
                        value = record[key]
                        if isinstance(value, list) and len(str(value)) > 40:
                            value = f"[{len(value)} items]"
                        values.append(str(value)[:38])
                    print("  " + " | ".join(values))
                if len(records) > 10:
                    print(f"  ... +{len(records) - 10} more rows")
    finally:
        driver.close()


if __name__ == "__main__":
    main()
