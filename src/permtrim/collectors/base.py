"""Abstract collector contract shared by every cloud provider adapter.

Adding a new provider (Azure in Task 5) means:

1. Implementing :class:`BaseCollector` (three abstract methods).
2. Registering the class in :mod:`permtrim.collectors.factory`.

Everything else — merging the static IAM snapshot with the dynamic activity
log, building the per-principal view, writing the unified JSON document —
lives here and is inherited as-is. That is the whole point of this module:
downstream stages (analyzer / graph / LLM) only ever see the unified schema,
never a provider-specific shape.
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

from ..models.activity import ActivityLog, UsageSummary
from ..models.iam import IaMSnapshot, ManagedPolicyRef

__all__ = ["SCHEMA_VERSION", "CollectorConfig", "BaseCollector", "write_json_document"]

LOGGER = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0"
"""Version of the unified snapshot schema (bumped on breaking changes)."""


def _utcnow() -> datetime:
    """Timezone-aware now (module-level so dataclass field factories can share it)."""
    return datetime.now(tz=timezone.utc)


@dataclass
class CollectorConfig:
    """Settings shared by every collector implementation.

    ``clock`` is injectable so tests (and future replay features) get
    deterministic timestamps without patching module globals.
    """

    default_lookback_days: int = 30
    include_raw_events: bool = True
    # lambda wrapper: mypy cannot match a bare-function default_factory
    # against a Callable field (known mypy dataclass quirk)
    clock: Callable[[], datetime] = field(default_factory=lambda: _utcnow)


class BaseCollector(ABC):
    """Template-method skeleton for provider collectors.

    Subclasses fill in the three abstract hooks; :meth:`collect` then runs
    the full pipeline:

        collect_iam_snapshot()  ->  collect_activity()  ->  _assemble_unified()

    The returned document is the single artifact consumed by every later
    stage of permtrim (permission analyzer, graph database, LLM remediation).
    """

    provider: ClassVar[str] = "abstract"

    def __init__(self, config: CollectorConfig | None = None) -> None:
        self._config = config or CollectorConfig()
        self._log = logging.getLogger(f"{__name__}.{type(self).__name__}")

    # ------------------------------------------------------------------ API

    def collect(self, *, lookback_days: int | None = None) -> dict[str, Any]:
        """Run the full collection pipeline and return the unified document.

        Args:
            lookback_days: Override for ``config.default_lookback_days``.

        Returns:
            The unified snapshot as a plain dict, ready for
            ``json.dumps`` (see :func:`write_json_document`).
        """
        self._log.info("Collecting static IAM snapshot (%s)", self.provider)
        iam = self.collect_iam_snapshot()
        self._log.info(
            "IAM snapshot: %d users, %d roles, %d groups, %d managed policies",
            len(iam.users),
            len(iam.roles),
            len(iam.groups),
            len(iam.policies),
        )

        self._log.info(
            "Collecting observed activity (last %s days)", lookback_days or self._config.default_lookback_days
        )
        activity = self.collect_activity(lookback_days)
        self._log.info(
            "Activity: %d events over %s, %d distinct principals (truncated=%s)",
            len(activity.events),
            activity.window.to_dict()["source"],
            len(activity.usage),
            activity.window.truncated,
        )

        document = self._assemble_unified(iam, activity)
        self._log.info("Unified snapshot ready (schema %s)", SCHEMA_VERSION)
        return document

    # ---------------------------------------------------- abstract hooks

    @abstractmethod
    def collect_iam_snapshot(self) -> IaMSnapshot:
        """Fetch the static IAM state of the account."""

    @abstractmethod
    def collect_activity(self, lookback_days: int | None = None) -> ActivityLog:
        """Fetch observed API activity within the given lookback window."""

    @abstractmethod
    def _provider_meta(self) -> dict[str, Any]:
        """Provider-specific metadata for the unified document ``meta`` block."""

    # ----------------------------------------------------- unified merge

    def _assemble_unified(self, iam: IaMSnapshot, activity: ActivityLog) -> dict[str, Any]:
        """Merge the static and dynamic sides into one document.

        Layout::

            meta          schema/provider/account/window information
            identities    the raw IAM snapshot (users, roles, groups, policies)
            activity      the activity log (usage summary + optional raw events)
            principals    per-principal merged view: permissions vs. observed use
            unmatched_activity
                          log principals with no matching IAM entity (deleted
                          identities, root usage, cross-account callers)
        """
        generated_at = self._config.clock()
        return {
            "meta": {
                "schema_version": SCHEMA_VERSION,
                "provider": self.provider,
                "generated_at": generated_at.isoformat(),
                "lookback_days": activity.window.lookback_days,
                "window": activity.window.to_dict(),
                **self._provider_meta(),
            },
            "identities": iam.to_dict(),
            "activity": activity.to_dict(include_events=self._config.include_raw_events),
            "principals": self._principal_view(iam, activity),
            "unmatched_activity": self._unmatched_activity(iam, activity),
        }

    def _principal_view(self, iam: IaMSnapshot, activity: ActivityLog) -> list[dict[str, Any]]:
        """Build the merged per-principal records (the analyzer's main input).

        Every record pairs the *permission sources* of an identity with its
        *observed activity* in the same window — the exact delta the
        least-privilege analyzer (Task 2) will turn into findings, and the
        LLM (Task 4) will turn into Terraform.
        """
        records: list[dict[str, Any]] = []

        for user in iam.users:
            records.append(
                {
                    "kind": "user",
                    "name": user.name,
                    "arn": user.arn,
                    "account_id": iam.account_id,
                    "created_at": user.created_at.isoformat() if user.created_at else None,
                    "tags": dict(user.tags),
                    "permission_sources": {
                        "inline_policies": {k: dict(v) for k, v in user.inline_policies.items()},
                        "attached_managed_policies": self._attached_policy_view(iam, user.attached_policies),
                        "via_groups": list(user.groups),
                        "permission_boundary_arn": user.permission_boundary_arn,
                    },
                    "observed_activity": self._activity_view(activity, "user", user.name),
                }
            )

        for role in iam.roles:
            records.append(
                {
                    "kind": "role",
                    "name": role.name,
                    "arn": role.arn,
                    "account_id": iam.account_id,
                    "created_at": role.created_at.isoformat() if role.created_at else None,
                    "tags": dict(role.tags),
                    "trust_policy": dict(role.trust_policy),
                    "permission_sources": {
                        "inline_policies": {k: dict(v) for k, v in role.inline_policies.items()},
                        "attached_managed_policies": self._attached_policy_view(iam, role.attached_policies),
                        "permission_boundary_arn": role.permission_boundary_arn,
                    },
                    "observed_activity": self._activity_view(activity, "role", role.name),
                }
            )

        for group in iam.groups:
            records.append(
                {
                    "kind": "group",
                    "name": group.name,
                    "arn": group.arn,
                    "account_id": iam.account_id,
                    "permission_sources": {
                        "inline_policies": {k: dict(v) for k, v in group.inline_policies.items()},
                        "attached_managed_policies": self._attached_policy_view(iam, group.attached_policies),
                        "members": [user.name for user in iam.users if group.name in user.groups],
                    },
                    "observed_activity": None,  # groups never invoke APIs themselves
                }
            )

        records.sort(key=lambda record: (record["kind"], record["name"]))
        return records

    def _attached_policy_view(self, iam: IaMSnapshot, refs: list[ManagedPolicyRef]) -> list[dict[str, Any]]:
        """Resolve attachment refs against the policy catalog, documents included."""
        view = []
        for ref in refs:
            policy = iam.policies.get(ref.arn)
            view.append(
                {
                    "name": ref.name,
                    "arn": ref.arn,
                    "kind": ref.kind.value,
                    "document": policy.document if policy else None,
                    "document_status": (
                        "available" if policy and policy.document_available else "unavailable"
                    ),
                }
            )
        return view

    def _activity_view(self, activity: ActivityLog, kind: str, name: str) -> UsageSummary | Any:
        """Observed usage for one identity, or an all-zero summary if idle.

        An identity with *no* observed activity is the single most valuable
        finding for least-privilege tightening, so idleness is represented
        explicitly instead of ``None``.
        """
        summary = activity.usage.get((kind, name), UsageSummary())
        return summary.to_dict()

    def _unmatched_activity(self, iam: IaMSnapshot, activity: ActivityLog) -> list[dict[str, Any]]:
        """Report observed principals that no longer exist in the IAM snapshot.

        These are a security signal in their own right: root usage, federated
        access, assumed roles from other accounts, or identities deleted
        between the trail and the snapshot.
        """
        known = {("user", user.name) for user in iam.users}
        known |= {("role", role.name) for role in iam.roles}
        unmatched = [
            {"kind": kind, "name": name, "summary": summary.to_dict()}
            for (kind, name), summary in sorted(activity.usage.items())
            if (kind, name) not in known
        ]
        if unmatched:
            self._log.warning(
                "%d observed principals have no matching IAM entity: %s",
                len(unmatched),
                ", ".join(f"{u['kind']}:{u['name']}" for u in unmatched),
            )
        return unmatched


def write_json_document(document: dict[str, Any], path: str | Path) -> Path:
    """Atomically write a unified snapshot to disk (tmp file + ``os.replace``).

    Args:
        document: Unified snapshot produced by :meth:`BaseCollector.collect`.
        path: Destination file path; parent directories are created.

    Returns:
        The resolved :class:`pathlib.Path` of the written file.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    os.replace(tmp, target)
    LOGGER.info("Unified snapshot written to %s", target)
    return target
