"""Graph data model for the IAM permission graph (Task 3).

Node/edge containers shared by the builder, the Cypher statement generator,
the Neo4j ingestor and the offline renderer. Everything is JSON-serializable
so a built model can be inspected (``model.json``) without a database.

Graph shape
-----------
    (:Principal:User|Role)-[:MEMBER_OF]->(:Group)
    (:Principal|Group)-[:GRANTED]->(:Policy:Managed|Inline)
    (:Policy)-[:ALLOWS {pattern}]->(:Action)
    (:Principal)-[:CAN_USE {via_policies, via_groups}]->(:Action)   # effective, deny-aware
    (:Principal)-[:INVOKED {count, error_count}]->(:Action)         # working calls
    (:Principal)-[:ATTEMPTED {count}]->(:Action)                    # every call failed

Design notes:
* ``CAN_USE`` edges come from the analyzer (wildcards expanded, explicit Deny
  applied, group inheritance folded in) — the graph stores the *effective*
  permission, not just policy text.
* ``ALLOWS`` edges are per-policy potential (pattern kept as an edge
  property), so the *path* Principal→Group→Policy→Action can be contrasted
  with effective CAN_USE edges — that comparison is where hidden grant paths
  surface.
* An action whose every observed invocation failed (e.g. ``AccessDenied``)
  becomes ``ATTEMPTED``, not ``INVOKED``: a principal that *tried* to use a
  permission it does not have is a signal, not usage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["GraphNode", "GraphEdge", "GraphModel", "EDGE_TYPES"]


@dataclass
class GraphNode:
    """One graph node; ``key`` uniquely identifies it (MERGE anchor)."""

    key: str
    labels: tuple[str, ...]
    props: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "labels": list(self.labels), "props": self.props}


@dataclass
class GraphEdge:
    """One typed edge between node keys; ``props`` become relationship props."""

    type: str  # MEMBER_OF | GRANTED | ALLOWS | CAN_USE | INVOKED | ATTEMPTED
    source: str
    target: str
    props: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "source": self.source, "target": self.target, "props": self.props}


EDGE_TYPES = ("MEMBER_OF", "GRANTED", "ALLOWS", "CAN_USE", "INVOKED", "ATTEMPTED")


@dataclass
class GraphModel:
    """The whole permission graph for one snapshot."""

    account_id: str | None = None
    lookback_days: int | None = None
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)

    def nodes_by_label(self, label: str) -> list[GraphNode]:
        return [node for node in self.nodes if label in node.labels]

    def edges_by_type(self, edge_type: str) -> list[GraphEdge]:
        return [edge for edge in self.edges if edge.type == edge_type]

    def counts(self) -> dict[str, Any]:
        labels = ("Principal", "Group", "Policy", "Action")
        by_label = {label: len(self.nodes_by_label(label)) for label in labels}
        by_type = {edge_type: len(self.edges_by_type(edge_type)) for edge_type in EDGE_TYPES}
        return {"nodes": {**by_label, "total": len(self.nodes)}, "edges": by_type}

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "lookback_days": self.lookback_days,
            "counts": self.counts(),
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }
