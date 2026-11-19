"""Graph layer (Task 3): snapshot -> Neo4j permission graph.

Public surface:
    GraphModel / GraphNode / GraphEdge      — the data model
    GraphBuilder / build_graph              — snapshot -> model
    CONSTRAINTS_CYPHER / INGEST_QUERIES     — schema + bulk ingest statements
    build_ingest_statements / write_cypher_script  — Cypher generation
    ingest_model                            — live Neo4j ingest via the official driver
    QUERIES / write_query_script            — analysis Cypher library
    render_graph                            — offline visualization (no DB needed)
"""

from .builder import GraphBuilder, build_graph
from .ingest import ingest_model
from .model import EDGE_TYPES, GraphEdge, GraphModel, GraphNode
from .queries import QUERIES, write_query_script
from .render import render_graph
from .statements import (
    CONSTRAINTS_CYPHER,
    build_ingest_statements,
    write_cypher_script,
)

__all__ = [
    "EDGE_TYPES",
    "GraphEdge",
    "GraphModel",
    "GraphNode",
    "GraphBuilder",
    "build_graph",
    "CONSTRAINTS_CYPHER",
    "build_ingest_statements",
    "write_cypher_script",
    "QUERIES",
    "write_query_script",
    "ingest_model",
    "render_graph",
]
