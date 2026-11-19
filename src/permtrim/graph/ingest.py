"""Live Neo4j ingest via the official Python driver (Task 3).

The driver is an optional dependency: ``pip install permtrim[graph]`` (or
``pip install neo4j``). Without it the graph layer still works offline
(``permtrim graph render`` / ``export`` need no database). Import errors are
translated to :class:`~permtrim.errors.PermTrimError` so the CLI can print
an actionable message instead of a traceback.

Usage:
    from permtrim.graph import build_graph, ingest_model
    model = build_graph(document)
    summary = ingest_model(model, "bolt://localhost:7687",
                           auth=("neo4j", "password"))
"""

from __future__ import annotations

import logging
from typing import Any

from ..errors import PermTrimError
from .model import GraphModel
from .statements import build_ingest_statements

__all__ = ["ingest_model", "Neo4jIngestSummary"]

LOGGER = logging.getLogger(__name__)


class Neo4jIngestSummary(dict):
    """Ingest outcome as a dict with a pretty ``__str__``."""

    def __str__(self) -> str:  # pragma: no cover — cosmetic
        edges = ", ".join(f"{k}={v}" for k, v in self["edges"].items() if v)
        return (
            f"ingested nodes={self['nodes']['total']} ({self['nodes']['Principal']} principals, "
            f"{self['nodes']['Group']} groups, {self['nodes']['Policy']} policies, "
            f"{self['nodes']['Action']} actions) edges: {edges}"
        )


def ingest_model(
    model: GraphModel,
    uri: str = "bolt://localhost:7687",
    *,
    auth: tuple[str, str] | None = None,
    database: str | None = None,
    clear: bool = False,
) -> Neo4jIngestSummary:
    """Load a graph model into Neo4j (idempotent MERGE on node keys).

    Args:
        model: The graph model to load.
        uri: Bolt URI, e.g. ``bolt://localhost:7687``.
        auth: ``(user, password)``; None for no auth (rare local setups).
        database: Target database name (Neo4j 4+); None = default.
        clear: Wipe :Principal/:Group/:Policy/:Action nodes first.

    Returns:
        A :class:`Neo4jIngestSummary` with node/edge counts actually in the
        database after the load.

    Raises:
        PermTrimError: driver not installed, or connection failed.
    """
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise PermTrimError("The neo4j driver is not installed. Install with: pip install neo4j") from exc

    try:
        driver = GraphDatabase.driver(uri, auth=auth)
    except Exception as exc:  # noqa: BLE001 - driver raises assorted types
        raise PermTrimError(f"Could not create Neo4j driver for {uri}: {exc}") from exc

    kwargs: dict[str, Any] = {"database": database} if database else {}
    try:
        with driver.session(**kwargs) as session:
            if clear:
                session.run("MATCH (n:Principal|Group|Policy|Action) DETACH DELETE n").consume()
            for statement in build_ingest_statements(model):
                session.run(statement[0], **statement[1] or {}).consume()
            return _summarize(session)
    except PermTrimError:
        raise
    except Exception as exc:  # noqa: BLE001 - translate driver errors
        raise PermTrimError(f"Neo4j ingest failed: {exc}") from exc
    finally:
        driver.close()


def _summarize(session: Any) -> Neo4jIngestSummary:
    """Count what is actually in the database after the load."""

    def count(query: str) -> int:
        record = session.run(query).single(strict=True)
        return int(record[0])

    nodes = {
        "Principal": count("MATCH (n:Principal) RETURN count(n)"),
        "Group": count("MATCH (n:Group) RETURN count(n)"),
        "Policy": count("MATCH (n:Policy) RETURN count(n)"),
        "Action": count("MATCH (n:Action) RETURN count(n)"),
    }
    edges = {
        edge_type: count(f"MATCH ()-[r:{edge_type}]->() RETURN count(r)")
        for edge_type in ("MEMBER_OF", "GRANTED", "ALLOWS", "CAN_USE", "INVOKED", "ATTEMPTED")
    }
    nodes["total"] = sum(nodes.values())
    edges["total"] = sum(edges.values())
    return Neo4jIngestSummary(nodes=nodes, edges=edges)
