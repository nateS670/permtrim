"""Shared, provider-neutral data contracts (typed models).

These dataclasses are the *lingua franca* between collectors (AWS today,
Azure later), the permission analyzer (Task 2), the graph module (Task 3)
and the LLM remediation module (Task 4). Keeping them provider-neutral is
what allows a new cloud provider to be added without touching downstream
modules.
"""

from .activity import (
    ActivityEvent,
    ActivityLog,
    ActivityWindow,
    PrincipalKind,
    PrincipalRef,
    UsageSummary,
    summarize_usage,
)
from .iam import (
    IAMGroup,
    IAMRole,
    IaMSnapshot,
    IAMUser,
    ManagedPolicy,
    ManagedPolicyRef,
    PolicyKind,
)

__all__ = [
    "ActivityEvent",
    "ActivityLog",
    "ActivityWindow",
    "PrincipalKind",
    "PrincipalRef",
    "UsageSummary",
    "summarize_usage",
    "IAMGroup",
    "IAMRole",
    "IAMUser",
    "IaMSnapshot",
    "ManagedPolicy",
    "ManagedPolicyRef",
    "PolicyKind",
]
