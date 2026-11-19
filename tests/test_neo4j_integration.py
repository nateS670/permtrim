"""Neo4j integration tests: real UNWIND ingest against a live database.

Skipped cleanly unless a Neo4j endpoint is provided — in CI the
``neo4j-integration`` job starts one as a service container and exports
``NEO4J_URI``; locally, `docker compose up -d neo4j` (see docker-compose.yml)
before running pytest enables the same tests.

Usage:
    NEO4J_URI=bolt://localhost:7687 NEO4J_USER=neo4j NEO4J_PASSWORD=permtrim \\
        pytest tests/test_neo4j_integration.py -v
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from permtrim.graph import build_graph, ingest_model

pytestmark = pytest.mark.integration

NEO4J_URI = os.environ.get("NEO4J_URI", "")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "permtrim")

SAMPLE = Path(__file__).resolve().parent.parent / "src" / "permtrim" / "data" / "sample_snapshot.json"

requires_neo4j = pytest.mark.skipif(
    not NEO4J_URI,
    reason="no NEO4J_URI configured; run `docker compose up -d neo4j` or set NEO4J_URI",
)


def _driver():
    """Create a real driver (import fails fast when the extra is missing)."""
    from neo4j import GraphDatabase

    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


@pytest.fixture(scope="module")
def ingested_summary():
    """Ingest the bundled AWS sample once; return the summary for asserts.

    Only permtrim's own labels are cleared (``ingest_model(clear=True)``
    matches ``:Principal|Group|Policy|Action``); the test never touches
    unrelated nodes — a shared database must be safe to point the suite at.
    """
    document = json.loads(SAMPLE.read_text(encoding="utf-8"))
    model = build_graph(document)
    summary = ingest_model(model, NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD), clear=True)
    yield summary
    _driver().close()


@requires_neo4j
class TestLiveIngest:
    def test_summary_counts_match_model(self, ingested_summary):
        document = json.loads(SAMPLE.read_text(encoding="utf-8"))
        model = build_graph(document)
        assert ingested_summary["nodes"]["total"] == len(model.nodes)
        assert ingested_summary["edges"]["total"] == len(model.edges)

    def test_principals_queryable(self):
        driver = _driver()
        try:
            with driver.session() as session:
                records = session.run("MATCH (p:Principal) RETURN p.name AS name ORDER BY name").data()
            names = [r["name"] for r in records]
            assert "alice" in names
            assert "deploy-ci" in names
        finally:
            driver.close()

    def test_unused_permission_query(self):
        """The core analysis query: granted-but-unused actions per principal."""
        driver = _driver()
        try:
            with driver.session() as session:
                records = session.run(
                    """MATCH (p:Principal)-[c:CAN_USE]->(a:Action)
                       WHERE c.used = false
                       RETURN p.name AS principal, count(a) AS unused
                       ORDER BY unused DESC"""
                ).data()
            assert records, "expected at least one unused permission"
            assert all(r["unused"] > 0 for r in records)
        finally:
            driver.close()

    def test_attempted_denied_edge_present(self):
        """AccessDenied attempts are ATTEMPTED edges in the graph."""
        driver = _driver()
        try:
            with driver.session() as session:
                records = session.run(
                    "MATCH (:Principal)-[r:ATTEMPTED]->(:Action) RETURN count(r) AS n"
                ).single()
            assert records["n"] >= 1
        finally:
            driver.close()
