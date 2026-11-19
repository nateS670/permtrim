"""Static-side models: the IAM configuration snapshot.

These models describe *what permissions exist* (as opposed to
``models.activity``, which describes *what permissions are used*).
Policy documents are kept verbatim as ``dict[str, Any]`` — the analyzer
(Task 2) and the graph module (Task 3) need the original statements,
including condition blocks and resource ARNs, so no premature normalization
is applied here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

__all__ = [
    "PolicyKind",
    "ManagedPolicyRef",
    "ManagedPolicy",
    "IAMUser",
    "IAMGroup",
    "IAMRole",
    "IaMSnapshot",
]


class PolicyKind(str, Enum):
    """Where a managed policy lives.

    AWS and Azure naming, one enum: ``aws_managed``/``customer_managed`` are
    the AWS split (AWS-owned vs account-owned policies); ``builtin``/
    ``custom`` are the Azure split (built-in vs custom role definitions).
    """

    CUSTOMER_MANAGED = "customer_managed"
    AWS_MANAGED = "aws_managed"
    BUILTIN = "builtin"  # Azure built-in role definition (e.g. Contributor)
    CUSTOM = "custom"  # Azure custom role definition


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


@dataclass
class ManagedPolicyRef:
    """A policy *attachment* on an identity (the document itself is in the catalog)."""

    name: str
    arn: str
    kind: PolicyKind

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "arn": self.arn, "kind": self.kind.value}


@dataclass
class ManagedPolicy:
    """A managed policy with its default-version document."""

    name: str
    arn: str
    kind: PolicyKind
    default_version_id: str | None
    document: dict[str, Any] | None
    attached_to: list[str] = field(default_factory=list)
    fetch_error: str | None = None

    @property
    def document_available(self) -> bool:
        return self.document is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "arn": self.arn,
            "kind": self.kind.value,
            "default_version_id": self.default_version_id,
            "document": self.document,
            "document_status": "available" if self.document_available else "unavailable",
            "attached_to": list(self.attached_to),
            **({"fetch_error": self.fetch_error} if self.fetch_error else {}),
        }


@dataclass
class IAMUser:
    """An IAM user with every permission source attached to it."""

    name: str
    arn: str
    path: str = ""
    created_at: datetime | None = None
    groups: list[str] = field(default_factory=list)
    inline_policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    attached_policies: list[ManagedPolicyRef] = field(default_factory=list)
    permission_boundary_arn: str | None = None
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "arn": self.arn,
            "path": self.path,
            "created_at": _iso(self.created_at),
            "groups": list(self.groups),
            "inline_policies": {k: dict(v) for k, v in self.inline_policies.items()},
            "attached_managed_policies": [ref.to_dict() for ref in self.attached_policies],
            "permission_boundary_arn": self.permission_boundary_arn,
            "tags": dict(self.tags),
        }


@dataclass
class IAMGroup:
    """An IAM group: a permission container shared by several users."""

    name: str
    arn: str
    created_at: datetime | None = None
    inline_policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    attached_policies: list[ManagedPolicyRef] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "arn": self.arn,
            "created_at": _iso(self.created_at),
            "inline_policies": {k: dict(v) for k, v in self.inline_policies.items()},
            "attached_managed_policies": [ref.to_dict() for ref in self.attached_policies],
        }


@dataclass
class IAMRole:
    """An IAM role, including its trust policy (who may assume it)."""

    name: str
    arn: str
    path: str = ""
    created_at: datetime | None = None
    trust_policy: dict[str, Any] = field(default_factory=dict)
    inline_policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    attached_policies: list[ManagedPolicyRef] = field(default_factory=list)
    permission_boundary_arn: str | None = None
    max_session_duration: int | None = None
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "arn": self.arn,
            "path": self.path,
            "created_at": _iso(self.created_at),
            "trust_policy": dict(self.trust_policy),
            "inline_policies": {k: dict(v) for k, v in self.inline_policies.items()},
            "attached_managed_policies": [ref.to_dict() for ref in self.attached_policies],
            "permission_boundary_arn": self.permission_boundary_arn,
            "max_session_duration": self.max_session_duration,
            "tags": dict(self.tags),
        }


@dataclass
class IaMSnapshot:
    """Full static IAM state of one account, at one point in time."""

    account_id: str
    collector_identity_arn: str
    collected_at: datetime
    users: list[IAMUser] = field(default_factory=list)
    roles: list[IAMRole] = field(default_factory=list)
    groups: list[IAMGroup] = field(default_factory=list)
    policies: dict[str, ManagedPolicy] = field(default_factory=dict)  # keyed by ARN

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "collector_identity_arn": self.collector_identity_arn,
            "collected_at": _iso(self.collected_at),
            "users": [user.to_dict() for user in self.users],
            "roles": [role.to_dict() for role in self.roles],
            "groups": [group.to_dict() for group in self.groups],
            "managed_policies": {arn: policy.to_dict() for arn, policy in sorted(self.policies.items())},
        }
