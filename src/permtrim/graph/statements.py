"""Cypher statement generation: schema, bulk ingest, exportable scripts.

Two output forms share one source of truth:

* **Parameterized** — ``build_ingest_statements(model)`` returns
  ``(query, params)`` pairs using ``UNWIND $rows`` batching, executed by
  :mod:`permtrim.graph.ingest` against a live database.
* **Literal** — ``write_cypher_script`` renders the same statements with all
  parameters inlined, producing a ``.cypher`` file that can be pasted
  straight into Neo4j Browser (``:source`` or copy/paste) with no driver,
  no Python, no parameters. This is the zero-dependency demo path.

Node identity: every node merges on its ``key`` property (uniqueness
constraint created by :data:`CONSTRAINTS_CYPHER`), so repeated ingests are
idempotent.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import EDGE_TYPES, GraphEdge, GraphModel

__all__ = [
    "CONSTRAINTS_CYPHER",
    "build_ingest_statements",
    "write_cypher_script",
    "cypher_literal",
]

CONSTRAINTS_CYPHER = (
    "CREATE CONSTRAINT principal_key IF NOT EXISTS FOR (n:Principal) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT group_key IF NOT EXISTS FOR (n:Group) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT policy_key IF NOT EXISTS FOR (n:Policy) REQUIRE n.key IS UNIQUE",
    "CREATE CONSTRAINT action_key IF NOT EXISTS FOR (n:Action) REQUIRE n.key IS UNIQUE",
)

# One UNWIND statement per (label-tuple, edge-type) shape. Relationship props
# ride along in each row; MERGE on the fixed (type, source, target, pattern)
# signature keeps re-ingests idempotent.
_INGEST_NODES: list[tuple[tuple[str, ...], str]] = [
    (("Principal",), "principal_nodes"),
    (("Group",), "group_nodes"),
    (("Policy",), "policy_nodes"),
    (("Action",), "action_nodes"),
]

_INGEST_EDGES: list[tuple[str, str]] = [
    ("MEMBER_OF", "member_of_edges"),
    ("GRANTED", "granted_edges"),
    ("ALLOWS", "allows_edges"),
    ("CAN_USE", "can_use_edges"),
    ("INVOKED", "invoked_edges"),
    ("ATTEMPTED", "attempted_edges"),
]


def _node_query(labels: tuple[str, ...], param: str) -> str:
    label_expr = ":".join(labels)
    return f"UNWIND ${param} AS row\nMERGE (n:{label_expr} {{key: row.key}})\nSET n += row.props"


def _edge_query(edge_type: str, param: str) -> str:
    return (
        f"UNWIND ${param} AS row\n"
        f"MATCH (a {{key: row.source}}), (b {{key: row.target}})\n"
        f"MERGE (a)-[r:{edge_type}]->(b)\n"
        f"SET r += row.props"
    )


def build_ingest_statements(model: GraphModel, batch_size: int = 500) -> list[tuple[str, dict[str, Any]]]:
    """Parameterized (query, params) pairs that load the whole model.

    Args:
        model: The graph model to load.
        batch_size: Rows per UNWIND batch (keeps parameter payloads small).

    Returns:
        Constraint statements followed by batched ingest statements.
    """
    statements: list[tuple[str, dict[str, Any]]] = [(constraint, {}) for constraint in CONSTRAINTS_CYPHER]

    for labels, param in _INGEST_NODES:
        rows = [
            {"key": node.key, "props": node.props} for node in model.nodes if set(labels) <= set(node.labels)
        ]
        for start in range(0, len(rows), batch_size):
            statements.append((_node_query(labels, param), {param: rows[start : start + batch_size]}))

    by_type: dict[str, list[GraphEdge]] = {
        edge_type: model.edges_by_type(edge_type) for edge_type in EDGE_TYPES
    }
    for edge_type, param in _INGEST_EDGES:
        rows = [
            {"source": edge.source, "target": edge.target, "props": edge.props}
            for edge in by_type.get(edge_type, [])
        ]
        for start in range(0, len(rows), batch_size):
            statements.append((_edge_query(edge_type, param), {param: rows[start : start + batch_size]}))

    return statements


def cypher_literal(value: Any) -> str:
    """Render a Python value as a Cypher literal (maps, lists, scalars)."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(cypher_literal(item) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{ " + ", ".join(f"{_map_key(key)}: {cypher_literal(val)}" for key, val in value.items()) + " }"
        )
    # fall back to a string form for anything exotic
    return cypher_literal(str(value))


def _map_key(key: str) -> str:
    # Cypher map keys with special chars need backticks
    if key and all(char.isalnum() or char == "_" for char in key) and not key[0].isdigit():
        return key
    return "`" + key + "`"


def _literalize(query: str, params: dict[str, Any]) -> str:
    """Replace ``$param`` placeholders with inlined literal values."""
    result = query
    for name, value in params.items():
        rows = ",\n  ".join(cypher_literal(row) for row in value)
        result = result.replace(f"${name}", f"[\n  {rows}\n]")
    return result


def write_cypher_script(model: GraphModel, path: Path, *, include_header: bool = True) -> int:
    """Write a self-contained, parameter-free ``.cypher`` load script.

    The output runs in Neo4j Browser as-is (``:source permtrim_graph.cypher``
    or paste). Multi-statement mode must be enabled in Browser settings for
    pasted scripts; ``:source`` handles it natively.

    Returns:
        Number of statements written.
    """
    lines: list[str] = []
    if include_header:
        lines += [
            "// permtrim permission graph — self-contained load script.",
            "// Usage (Neo4j Browser): :source permtrim_graph.cypher",
            f"// {model.counts()}",
            "",
        ]
    count = 0
    for query, params in build_ingest_statements(model):
        literal = _literalize(query, params) if params else query
        lines.append(literal + ";")
        lines.append("")
        count += 1
    path.write_text("\n".join(lines), encoding="utf-8")
    return count
