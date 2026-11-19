"""Build the permission graph from a unified snapshot (Task 3).

The builder turns the collector's unified JSON document into the
:class:`~permtrim.graph.model.GraphModel` node/edge containers. Two sources
feed it:

* the snapshot's ``principals[]`` blocks (policies, group memberships,
  observed activity), and
* the analyzer's findings (effective permissions — wildcards expanded,
  explicit Deny applied, group inheritance folded in — plus usage split into
  working calls vs failed attempts).

Graph size control: for a principal with ``*`` the effective CAN_USE edges
number ~20k. Every node/edge list the database actually needs is capped by
``max_edges_per_type``; the *full* effective expansion still exists in
findings — the graph is a lens, not the warehouse. ALLOWS edges keep the
original wildcard pattern as a property (``pattern: "ec2:*"``), so the graph
shows both the pattern and what it expands to.

Label scheme:
    (:Principal:User) / (:Principal:Role) / (:Group) / (:Policy:Managed) /
    (:Policy:Inline) / (:Action {service, access_level})
"""

from __future__ import annotations

import logging
from typing import Any

from ..analyzer.action_registry import ActionRegistry
from ..analyzer.engine import Analyzer
from ..analyzer.findings import AnalysisReport, GrantedAction, PrincipalFinding
from .model import GraphEdge, GraphModel, GraphNode

__all__ = ["GraphBuilder", "build_graph"]

LOGGER = logging.getLogger(__name__)

_PRINCIPAL_KIND_LABEL = {"user": "User", "role": "Role"}
_POLICY_KIND_LABEL = {
    "aws_managed": ("Policy", "Managed", "AWSManaged"),
    "customer_managed": ("Policy", "Managed", "CustomerManaged"),
    "builtin": ("Policy", "Managed", "AzureBuiltIn"),
    "custom": ("Policy", "Managed", "AzureCustom"),
    "inline": ("Policy", "Inline"),
}


class GraphBuilder:
    """Assemble a :class:`GraphModel` from a snapshot document."""

    def __init__(
        self,
        registry: ActionRegistry,
        analyzer: Analyzer | None = None,
        max_edges_per_type: int = 4000,
    ) -> None:
        self._registry = registry
        self._analyzer = analyzer or Analyzer()
        self._max_edges = max_edges_per_type

    def build(self, document: dict[str, Any]) -> GraphModel:
        """Build the graph for one unified snapshot document.

        Provider-aware: an Azure snapshot builds its action registry from
        the snapshot universe (there is no offline Azure dataset), AWS from
        the bundled iam-definition file.
        """
        provider = document.get("meta", {}).get("provider", "aws")
        if provider == "azure" and isinstance(self._registry, ActionRegistry):
            # swap in the snapshot-scoped Azure universe
            from ..analyzer.azure_registry import build_azure_registry

            self._registry = build_azure_registry(document)  # type: ignore[assignment]
        report = self._analyzer.analyze_document(document)
        return self.build_from_report(document, report)

    def build_from_report(self, document: dict[str, Any], report: AnalysisReport) -> GraphModel:
        """Build the graph from a snapshot plus a precomputed analysis report."""
        meta = document.get("meta", {})
        model = GraphModel(
            account_id=meta.get("account_id"),
            lookback_days=meta.get("lookback_days"),
        )
        findings_by_key = {(finding.kind, finding.name): finding for finding in report.findings}

        groups = self._groups(document)
        for entry in document.get("principals", []):
            if entry.get("kind") == "group":
                continue  # handled by _groups
            self._add_principal(model, entry, findings_by_key)
        for group in groups.values():
            self._add_group(model, group)

        self._add_usage_edges(model, document, findings_by_key)
        self._dedupe(model)
        LOGGER.info("Graph built: %s", model.counts())
        return model

    # ------------------------------------------------------------- groups

    @staticmethod
    def _groups(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {
            entry["name"]: entry for entry in document.get("principals", []) if entry.get("kind") == "group"
        }

    def _add_group(self, model: GraphModel, entry: dict[str, Any]) -> None:
        name = entry["name"]
        model.nodes.append(
            GraphNode(
                key=f"group:{name}",
                labels=("Group",),
                props={"name": name, "arn": entry.get("arn")},
            )
        )
        ps = entry.get("permission_sources", {})
        self._add_policies(model, f"group:{name}", ps, via_group=name)

    # --------------------------------------------------------- principals

    def _add_principal(
        self,
        model: GraphModel,
        entry: dict[str, Any],
        findings_by_key: dict[tuple[str, str], PrincipalFinding],
    ) -> None:
        kind, name = entry["kind"], entry["name"]
        finding = findings_by_key.get((kind, name))
        node_key = f"{kind}:{name}"

        props: dict[str, Any] = {
            "name": name,
            "kind": kind,
            "arn": entry.get("arn"),
            "risk_score": round(finding.risk_score, 1) if finding else 0.0,
            "used_count": len(finding.used_actions) if finding else 0,
            "granted_count": finding.granted_count if finding else 0,
            "unused_count": finding.unused_count if finding else 0,
            "idle": bool(finding and finding.is_idle),
        }
        if finding and finding.risk_reasons:
            props["top_risk_reason"] = finding.risk_reasons[0]
        model.nodes.append(
            GraphNode(
                key=node_key,
                labels=("Principal", _PRINCIPAL_KIND_LABEL.get(kind, "User")),
                props=props,
            )
        )

        ps = entry.get("permission_sources", {})
        for group_name in ps.get("via_groups", []) or []:
            model.edges.append(
                GraphEdge(
                    type="MEMBER_OF",
                    source=node_key,
                    target=f"group:{group_name}",
                )
            )
        self._add_policies(model, node_key, ps)

        # effective permissions from the analyzer (wildcards expanded, denies applied)
        if finding is not None:
            self._add_effective_edges(model, node_key, finding)

    def _add_policies(
        self,
        model: GraphModel,
        owner_key: str,
        permission_sources: dict[str, Any],
        via_group: str | None = None,
    ) -> None:
        """GRANTED + ALLOWS edges for inline and attached policies of one owner."""
        for policy_name, doc in (permission_sources.get("inline_policies") or {}).items():
            key = f"policy:inline:{owner_key}:{policy_name}"
            model.nodes.append(
                GraphNode(
                    key=key,
                    labels=_POLICY_KIND_LABEL["inline"],
                    props={"name": policy_name, "owner": owner_key},
                )
            )
            model.edges.append(
                GraphEdge(
                    type="GRANTED",
                    source=owner_key,
                    target=key,
                    props={"via_group": via_group} if via_group else {},
                )
            )
            self._add_allows_edges(model, key, doc)

        for ref in permission_sources.get("attached_managed_policies") or []:
            arn, policy_name = ref.get("arn"), ref.get("name")
            if not arn:
                continue
            key = f"policy:{arn}"
            model.nodes.append(
                GraphNode(
                    key=key,
                    labels=_POLICY_KIND_LABEL.get(ref.get("kind", "customer_managed"), ("Policy", "Managed")),
                    props={
                        "name": policy_name,
                        "arn": arn,
                        "owner": owner_key,
                        "shared": via_group is None and False,
                    },
                )
            )
            model.edges.append(
                GraphEdge(
                    type="GRANTED",
                    source=owner_key,
                    target=key,
                    props={"via_group": via_group} if via_group else {},
                )
            )
            doc = ref.get("document")
            if doc is not None:
                self._add_allows_edges(model, key, doc)

    def _add_allows_edges(self, model: GraphModel, policy_key: str, document: dict[str, Any]) -> None:
        """ALLOWS edges policy -> action, one per statement action pattern.

        Handles both document formats (detected by shape, like the
        analyzer's PolicySet): AWS IAM ``Statement`` lists and Azure RBAC
        ``permissions`` entries (actions / notActions / dataActions).
        """
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        if statements:
            for statement in statements:
                if not isinstance(statement, dict):
                    continue
                if str(statement.get("Effect", "")).lower() != "allow":
                    continue
                actions = statement.get("Action") or []
                if isinstance(actions, str):
                    actions = [actions]
                self._allows_patterns(model, policy_key, actions)
            return

        # Azure role definition: permissions entries (all Allow, no Deny).
        permissions = document.get("permissions") or document.get("Permissions") or []
        if isinstance(permissions, dict):
            permissions = [permissions]
        for permission in permissions:
            if not isinstance(permission, dict):
                continue
            actions = list(permission.get("actions") or permission.get("Actions") or [])
            actions += list(permission.get("dataActions") or permission.get("DataActions") or [])
            self._allows_patterns(model, policy_key, actions)

    def _allows_patterns(self, model: GraphModel, policy_key: str, actions: list) -> None:
        for pattern in actions:
            if not isinstance(pattern, str) or not pattern:
                continue
            lowered = pattern.lower()
            action_key = self._action_key_for_pattern(model, lowered)
            model.edges.append(
                GraphEdge(
                    type="ALLOWS",
                    source=policy_key,
                    target=action_key,
                    props={"pattern": lowered},
                )
            )

    def _action_key_for_pattern(self, model: GraphModel, pattern: str) -> str:
        """Action node for a pattern: concrete name, else the pattern itself."""
        # AWS global wildcard: one representative node for all 20k+ actions.
        if pattern in {"*", "*:*"}:
            self._ensure_action_node(model, "action:*", "*", service="*", wildcard=True)
            return "action:*"
        # AWS full-service wildcard: s3:*
        if pattern.endswith(":*"):
            service = pattern[:-2]
            key = f"action:{service}:*"
            self._ensure_action_node(
                model,
                key,
                pattern,
                service=service,
                access_level=None,
                wildcard=True,
            )
            return key
        # Azure resource-provider / suffix wildcards: microsoft.storage/*, */read
        if ":" not in pattern and "*" in pattern:
            key = f"action:{pattern}"
            self._ensure_action_node(
                model,
                key,
                pattern,
                service=pattern.split("/", 1)[0],
                wildcard=True,
            )
            return key
        # Concrete action (AWS service:name or Azure provider/path/op).
        service = pattern.split(":", 1)[0] if ":" in pattern else pattern.split("/", 1)[0]
        self._ensure_action_node(
            model,
            f"action:{pattern}",
            pattern,
            service=service,
            access_level=self._registry.access_level(pattern),
        )
        return f"action:{pattern}"

    def _ensure_action_node(
        self,
        model: GraphModel,
        key: str,
        action: str,
        *,
        service: str | None,
        access_level: str | None = None,
        wildcard: bool = False,
    ) -> None:
        existing = self._node_index(model).get(key)
        if existing is not None:
            return
        props: dict[str, Any] = {"action": action, "service": service}
        if access_level:
            props["access_level"] = access_level
        if wildcard:
            props["wildcard"] = True
            props["expansion_size"] = self._registry.count_matching(action)
        model.nodes.append(GraphNode(key=key, labels=("Action",), props=props))

    # -------------------------------------------------------- effective + usage

    def _add_effective_edges(self, model: GraphModel, principal_key: str, finding: PrincipalFinding) -> None:
        """CAN_USE edges: analyzer-verified effective permissions (deny-aware)."""
        # Keep the graph readable: cap effective edges per principal, keeping
        # used actions first, then the highest-risk unused ones.
        used = set(finding.used_actions)
        granted = sorted(
            finding.granted_actions,
            key=lambda g: (g.action not in used, g.action),
        )
        for granted_action in granted[: self._max_edges]:
            key = self._concrete_action_node(model, granted_action)
            model.edges.append(
                GraphEdge(
                    type="CAN_USE",
                    source=principal_key,
                    target=key,
                    props={
                        "used": granted_action.used,
                        "error_only": granted_action.error_only,
                        "access_level": granted_action.access_level,
                        "via_policies": granted_action.sources[:5],
                    },
                )
            )

    def _concrete_action_node(self, model: GraphModel, granted: GrantedAction) -> str:
        key = f"action:{granted.action}"
        existing = self._node_index(model).get(key)
        if existing is None:
            existing = GraphNode(
                key=key,
                labels=("Action",),
                props={
                    "action": granted.action,
                    "service": granted.action.split(":", 1)[0],
                    **({"access_level": granted.access_level} if granted.access_level else {}),
                },
            )
            model.nodes.append(existing)
        return key

    def _add_usage_edges(
        self,
        model: GraphModel,
        document: dict[str, Any],
        findings_by_key: dict[tuple[str, str], PrincipalFinding],
    ) -> None:
        """INVOKED (working calls) and ATTEMPTED (all calls failed) edges."""
        for entry in document.get("principals", []):
            kind, name = entry.get("kind"), entry.get("name", "")
            if kind == "group":
                continue
            activity = entry.get("observed_activity") or {}
            action_counts = activity.get("action_counts") or {}
            error_counts = activity.get("error_action_counts") or {}
            principal_key = f"{kind}:{name}"

            for action, count in action_counts.items():
                normalized = self._registry.normalize(action)
                if normalized is None:
                    continue
                errors = error_counts.get(action, 0)
                key = self._concrete_action_node(
                    model,
                    GrantedAction(
                        action=normalized,
                        sources=[],
                        used=True,
                        error_only=False,
                        access_level=self._registry.access_level(normalized),
                    ),
                )
                if errors >= count:
                    model.edges.append(
                        GraphEdge(
                            type="ATTEMPTED",
                            source=principal_key,
                            target=key,
                            props={"count": count, "error_count": errors},
                        )
                    )
                else:
                    model.edges.append(
                        GraphEdge(
                            type="INVOKED",
                            source=principal_key,
                            target=key,
                            props={"count": count, "error_count": errors},
                        )
                    )

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _node_index(model: GraphModel) -> dict[str, GraphNode]:
        return {node.key: node for node in model.nodes}

    @staticmethod
    def _dedupe(model: GraphModel) -> None:
        """First-wins dedupe of nodes and edges (builders may repeat shared policies)."""
        seen_nodes: set[str] = set()
        nodes: list[GraphNode] = []
        for node in model.nodes:
            if node.key in seen_nodes:
                continue
            seen_nodes.add(node.key)
            nodes.append(node)
        model.nodes = nodes

        seen_edges: set[tuple[str, str, str, str]] = set()
        edges: list[GraphEdge] = []
        for edge in model.edges:
            signature = (edge.type, edge.source, edge.target, edge.props.get("pattern", ""))
            if signature in seen_edges:
                continue
            seen_edges.add(signature)
            edges.append(edge)
        model.edges = edges


def build_graph(
    document: dict[str, Any],
    registry: ActionRegistry | None = None,
    max_edges_per_type: int = 4000,
) -> GraphModel:
    """Convenience wrapper: snapshot document -> GraphModel."""
    from ..analyzer import load_default_registry

    registry = registry or load_default_registry()
    return GraphBuilder(registry, max_edges_per_type=max_edges_per_type).build(document)
