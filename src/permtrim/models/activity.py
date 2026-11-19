"""Dynamic-side models: observed API activity of cloud principals.

The activity side of the unified snapshot answers one question:
*who actually invoked which ``service:action`` during the analysis window?*

Design notes
------------
* ``PrincipalRef`` is intentionally minimal (kind + name + optional session)
  so that AWS assumed-role sessions can be folded back onto the IAM *role*
  entity, which is what a least-privilege analysis needs to reason about.
* ``UsageSummary`` is keyed by ``(kind, name)`` because IAM users and roles
  live in separate ARN namespaces and may share a name.
* ``is_error`` events (e.g. ``AccessDenied``) are counted separately: a denied
  call proves the permission does *not* work today, which matters when the
  LLM proposes tightened policies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

__all__ = [
    "PrincipalKind",
    "PrincipalRef",
    "ActivityWindow",
    "ActivityEvent",
    "UsageSummary",
    "ActivityLog",
    "summarize_usage",
]


class PrincipalKind(str, Enum):
    """Normalized identity kind, independent of the cloud provider."""

    USER = "user"
    ROLE = "role"
    GROUP = "group"
    ROOT = "root"
    FEDERATED = "federated"
    UNKNOWN = "unknown"


@dataclass
class PrincipalRef:
    """Identity that performed an action, as observed in an audit log.

    ``session`` is set for temporary credentials (e.g. an assumed-role
    session name); the ``name``/``arn`` always point at the *durable*
    entity (the role itself), so usage aggregates join cleanly onto the
    static IAM snapshot.
    """

    kind: PrincipalKind
    name: str
    arn: str | None = None
    session: str | None = None
    account_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "name": self.name,
            "arn": self.arn,
            "session": self.session,
            "account_id": self.account_id,
        }


@dataclass
class ActivityWindow:
    """Time window covered by the dynamic analysis."""

    start: datetime
    end: datetime
    lookback_days: int
    source: str = "cloudtrail:lookup_events"
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "lookback_days": self.lookback_days,
            "source": self.source,
            "truncated": self.truncated,
        }


@dataclass
class ActivityEvent:
    """One observed API call, normalized across providers."""

    event_id: str | None
    time: datetime
    principal: PrincipalRef
    service: str
    action: str
    event_source: str
    event_name: str
    is_error: bool
    error_code: str | None
    read_only: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "time": self.time.isoformat(),
            "principal": self.principal.to_dict(),
            "service": self.service,
            "action": self.action,
            "event_source": self.event_source,
            "event_name": self.event_name,
            "is_error": self.is_error,
            "error_code": self.error_code,
            "read_only": self.read_only,
        }


@dataclass
class UsageSummary:
    """Aggregated activity for one ``(kind, name)`` principal."""

    event_count: int = 0
    error_event_count: int = 0
    action_counts: dict[str, int] = field(default_factory=dict)
    error_action_counts: dict[str, int] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_count": self.event_count,
            "error_event_count": self.error_event_count,
            "action_counts": dict(self.action_counts),
            "error_action_counts": dict(self.error_action_counts),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


@dataclass
class ActivityLog:
    """Result of the dynamic collection stage."""

    window: ActivityWindow
    events: list[ActivityEvent]
    usage: dict[tuple[str, str], UsageSummary] = field(default_factory=dict)

    def to_dict(self, *, include_events: bool = True) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "window": self.window.to_dict(),
            "usage": {
                f"{kind}:{name}": summary.to_dict() for (kind, name), summary in sorted(self.usage.items())
            },
        }
        if include_events:
            doc["events"] = [event.to_dict() for event in self.events]
        else:
            doc["events"] = f"omitted ({len(self.events)} events)"
        return doc


def summarize_usage(events: list[ActivityEvent]) -> dict[tuple[str, str], UsageSummary]:
    """Aggregate raw events into per-principal usage summaries.

    Args:
        events: Parsed activity events from one collection window.

    Returns:
        Mapping of ``(kind, name)`` to the aggregated :class:`UsageSummary`.
    """
    usage: dict[tuple[str, str], UsageSummary] = {}
    for event in events:
        key = (event.principal.kind.value, event.principal.name)
        summary = usage.setdefault(key, UsageSummary())
        summary.event_count += 1
        summary.action_counts[event.action] = summary.action_counts.get(event.action, 0) + 1
        if event.is_error:
            summary.error_event_count += 1
            summary.error_action_counts[event.action] = summary.error_action_counts.get(event.action, 0) + 1
        if summary.first_seen is None or event.time < summary.first_seen:
            summary.first_seen = event.time
        if summary.last_seen is None or event.time > summary.last_seen:
            summary.last_seen = event.time
    return usage
