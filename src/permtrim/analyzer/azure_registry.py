"""Azure RBAC action registry: the action universe of one snapshot.

Unlike AWS, there is no offline dataset enumerating every Azure action
(thousands of resource-provider operations, versioned per API). permtrim
instead builds the universe **from the snapshot itself**: every action
mentioned anywhere in the collected role definitions, plus every observed
activity-log operation. Wildcard expansion then happens within that
universe — exactly the set of actions that could possibly be relevant for
this account snapshot.

Action shape (kept verbatim, lowercased for matching):
    ``microsoft.compute/virtualmachines/read``
    ``microsoft.storage/storageaccounts/listkeys/action``
Wildcard patterns: ``*``, ``microsoft.storage/*``, ``*/read``.

Access level is derived from the operation suffix (Azure convention):
    ``.../action`` or ``.../write`` or ``.../delete`` → Write
    ``.../read`` → Read
    anything else → None (unknown; weighted like Read in risk scoring)

The registry implements the same interface as the AWS
:class:`~permtrim.analyzer.action_registry.ActionRegistry`, so the analyzer,
graph and guardrail code paths are provider-agnostic.
"""

from __future__ import annotations

import fnmatch
import logging
from collections.abc import Iterable
from typing import Any

__all__ = ["AzureActionRegistry", "build_azure_registry"]

LOGGER = logging.getLogger(__name__)

DATASET_SOURCE = "snapshot action universe (Azure RBAC role definitions + activity log)"

_WRITE_SUFFIXES = ("/action", "/write", "/delete", "/add", "/set", "/create", "/update", "/remove")
_READ_SUFFIXES = ("/read", "/list", "/get")

# Operations that show up in activity logs but are not resource-manager
# RBAC actions (Microsoft.Resources deployment noise); kept as-is, they
# simply exist in the universe if granted.


class AzureActionRegistry:
    """Read-only lookup of the Azure actions present in one snapshot."""

    def __init__(self, actions: Iterable[str]) -> None:
        # lowercase action -> access level
        self._actions: dict[str, str] = {}
        for action in actions:
            self._actions[action.strip().lower()] = _derive_access_level(action)
        self.service_count = len({_provider_of(a) for a in self._actions})
        self.action_count = len(self._actions)

    # ------------------------------------------------------------ existence

    def service_exists(self, service: str) -> bool:
        """True if any known action belongs to resource provider ``service``."""
        return service.lower() in {p for p in map(_provider_of, self._actions)}

    def action_exists(self, action: str) -> bool:
        """True if ``microsoft.x/.../read`` is a known action (case-insensitive)."""
        return action.strip().lower() in self._actions

    def access_level(self, action: str) -> str | None:
        """Derived access level: Write for mutating suffixes, Read for /read."""
        return self._actions.get(action.strip().lower())

    def canonical(self, action: str) -> str | None:
        """Canonical form: lowercase (Azure action casing is not canonicalized)."""
        lowered = action.strip().lower()
        return lowered if lowered in self._actions else None

    # ------------------------------------------------------------ normalization

    def normalize(self, action: str) -> str | None:
        """Normalize an observed activity-log operation name.

        Returns ``None`` for actions without a ``/`` (e.g. sign-in logs are
        not RBAC-governed).
        """
        lowered = action.strip().lower()
        if "/" not in lowered:
            return None
        return lowered

    # ------------------------------------------------------------ wildcards

    def expand(self, pattern: str, limit: int | None = None) -> list[str]:
        """Concrete known actions matching an Azure RBAC pattern.

        Azure wildcard semantics (Microsoft docs, "Understand wildcards"):
        ``*`` matches any character sequence, including ``/`` and ``.`` —
        unlike IAM's per-segment behaviour this is plain glob matching,
        which fnmatch implements directly.
        """
        lowered = pattern.strip().lower()
        matches = sorted(a for a in self._actions if fnmatch.fnmatchcase(a, lowered))
        return matches if limit is None else matches[:limit]

    def count_matching(self, pattern: str) -> int:
        """Number of known concrete actions a pattern covers."""
        return len(self.expand(pattern))

    def unmatched_within(self, pattern: str, used_actions: set[str]) -> list[str]:
        """Concrete actions covered by ``pattern`` but absent from ``used_actions``."""
        return [action for action in self.expand(pattern) if action not in used_actions]

    # ------------------------------------------------------------ reporting

    def dataset_summary(self) -> dict[str, Any]:
        return {
            "source": DATASET_SOURCE,
            "services": self.service_count,
            "actions": self.action_count,
        }


def _derive_access_level(action: str) -> str:
    """Map an Azure operation to an access level by its suffix."""
    lowered = action.strip().lower()
    if lowered.endswith(_WRITE_SUFFIXES):
        return "Write"
    if lowered.endswith(_READ_SUFFIXES):
        return "Read"
    return "Read"  # unknown suffixes lean benign


def _provider_of(action: str) -> str:
    """Resource provider of an action: ``microsoft.compute/vm/read`` -> ``microsoft.compute``."""
    return action.split("/", 1)[0]


def _iter_document_actions(document: dict[str, Any]) -> Iterable[str]:
    """Every action literal mentioned in one policy document (both formats)."""
    if not isinstance(document, dict):
        return
    statements = document.get("Statement")
    if statements is not None:
        items = statements if isinstance(statements, list) else [statements]
        for statement in items:
            if not isinstance(statement, dict):
                continue
            for key in ("Action", "NotAction"):
                values = statement.get(key) or []
                if isinstance(values, str):
                    values = [values]
                yield from (str(v) for v in values)
        return
    permissions = document.get("permissions") or document.get("Permissions") or []
    if isinstance(permissions, dict):
        permissions = [permissions]
    for permission in permissions:
        if not isinstance(permission, dict):
            continue
        for key in (
            "actions",
            "notActions",
            "dataActions",
            "notDataActions",
            "Actions",
            "NotActions",
            "DataActions",
            "NotDataActions",
        ):
            values = permission.get(key) or []
            if isinstance(values, str):
                values = [values]
            yield from (str(v) for v in values)


def build_azure_registry(document: dict[str, Any]) -> AzureActionRegistry:
    """Build the snapshot action universe from a unified Azure document.

    Args:
        document: A unified snapshot produced by
            :class:`~permtrim.collectors.azure_collector.AzureCollector`.

    Returns:
        An :class:`AzureActionRegistry` covering every action literal in the
        role definitions and every observed activity operation.
    """
    universe: set[str] = set()

    for entry in document.get("principals", []):
        sources = entry.get("permission_sources", {}) or {}
        for doc in (sources.get("inline_policies") or {}).values():
            universe.update(_iter_document_actions(doc))
        for ref in sources.get("attached_managed_policies") or []:
            universe.update(_iter_document_actions(ref.get("document") or {}))

    activity = document.get("activity", {}).get("usage", {})
    for summary in activity.values():
        universe.update(summary.get("action_counts", {}))
        universe.update(summary.get("error_action_counts", {}))

    # Wildcards are not universe members; only concrete actions are.
    universe = {action for action in universe if "*" not in action and "?" not in action and action}
    registry = AzureActionRegistry(sorted(universe))
    LOGGER.debug("Azure action universe: %s", registry.dataset_summary())
    return registry
