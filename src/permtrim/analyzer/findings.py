"""Finding model: one analyzable excess-permission record per principal.

Findings are the *contract* between the analyzer (Task 2) and the LLM
remediation stage (Task 4): the tightener consumes
:meth:`PrincipalFinding.to_proposer_payload` and must produce a policy whose
actions re-verify against :meth:`VerifiedPolicy.checklist` in the guardrail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "UNCOVERED_REASON_WILDCARD",
    "UNCOVERED_REASON_NEGATION",
    "UNCOVERED_REASON_MISSED",
    "GrantedAction",
    "PrincipalFinding",
    "AnalysisReport",
]

# Why a used action is not covered by the tightened policy.
UNCOVERED_REASON_WILDCARD = "wildcard_not_expanded"
UNCOVERED_REASON_NEGATION = "excluded_by_deny_or_notaction"
UNCOVERED_REASON_MISSED = "missed_by_proposer"


@dataclass
class GrantedAction:
    """One action a principal is allowed to perform, with provenance."""

    action: str  # lowercase service:name
    sources: list[str]  # policy sources granting it
    used: bool
    error_only: bool  # every observed invocation failed (permission does not work)
    access_level: str | None  # Read/Write/... from the dataset


@dataclass
class PrincipalFinding:
    """Excess-permission analysis for one principal."""

    kind: str  # "user" | "role"
    name: str
    arn: str | None
    used_actions: list[str] = field(default_factory=list)  # normalized, sorted
    granted_actions: list[GrantedAction] = field(default_factory=list)
    unused_actions: list[GrantedAction] = field(default_factory=list)
    wildcard_sources: list[dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    risk_reasons: list[str] = field(default_factory=list)
    provider: str = "aws"  # "aws" | "azure" — shapes the tightened output
    # ARN of the permission boundary (collected, NOT evaluated — see README):
    permission_boundary_arn: str | None = None
    # Resource scopes of the original statements that granted each used
    # action ("" when the snapshot carries no resource provenance, e.g. Azure).
    used_action_resources: dict[str, list[str]] = field(default_factory=dict)
    # Actions whose original Allow statements carried a Condition element
    # (e.g. MFA, source VPC endpoint). permtrim does not evaluate conditions;
    # the tightener refuses to auto-generate replacements for them (the
    # tightened policy would drop the condition and widen effective access).
    conditional_grants: list[str] = field(default_factory=list)
    # Unused-LOOKING grants on the AWS data plane (s3/lambda/dynamodb/qldb):
    # ``lookup_events`` covers management events only, so their usage is not
    # confirmed absent — merely invisible to this collector. Reported
    # separately (never in ``unused_actions``) and the tightener stops for
    # principals that have them.
    unknown_usage_actions: list[str] = field(default_factory=list)

    @property
    def granted_count(self) -> int:
        return len(self.granted_actions)

    @property
    def unused_count(self) -> int:
        return len(self.unused_actions)

    @property
    def is_idle(self) -> bool:
        """No observed activity at all — the strongest least-privilege signal."""
        return not self.used_actions

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "arn": self.arn,
            "used_actions": list(self.used_actions),
            "granted_count": self.granted_count,
            "unused_count": self.unused_count,
            "unused_examples": [
                {"action": g.action, "sources": g.sources, "access_level": g.access_level}
                for g in self.unused_actions[:20]
            ],
            "wildcard_sources": list(self.wildcard_sources),
            "risk_score": round(self.risk_score, 3),
            "risk_reasons": list(self.risk_reasons),
            "is_idle": self.is_idle,
            "permission_boundary_arn": self.permission_boundary_arn,
            "used_action_resources": {k: list(v) for k, v in self.used_action_resources.items()},
            "conditional_grants": list(self.conditional_grants),
            "unknown_usage_actions": list(self.unknown_usage_actions),
        }

    def to_proposer_payload(self) -> dict[str, Any]:
        """Compact payload for the LLM remediation stage.

        The proposed policy must re-allow every action in ``used_actions``
        (that is the guardrail's coverage check); ``unused_examples`` and
        ``wildcard_sources`` give the model context about what to drop.
        ``conditional_grants`` lists used actions whose original grants
        carried a Condition — models must copy the original Condition
        verbatim; permtrim itself does not evaluate conditions.
        """
        return {
            "kind": self.kind,
            "name": self.name,
            "arn": self.arn,
            "provider": self.provider,
            "used_actions": list(self.used_actions),
            "unused_examples": [g.action for g in self.unused_actions[:15]],
            "wildcard_sources": [w.get("pattern") for w in self.wildcard_sources[:10]],
            **(
                {"used_action_resources": {k: list(v) for k, v in self.used_action_resources.items()}}
                if self.used_action_resources
                else {}
            ),
            **({"conditional_grants": list(self.conditional_grants)} if self.conditional_grants else {}),
        }


@dataclass
class AnalysisReport:
    """Analyzer output over a whole snapshot."""

    account_id: str | None
    lookback_days: int | None
    window_truncated: bool
    dataset: dict[str, Any]
    findings: list[PrincipalFinding] = field(default_factory=list)

    @property
    def idle_principals(self) -> list[PrincipalFinding]:
        return [f for f in self.findings if f.is_idle]

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "lookback_days": self.lookback_days,
            "window_truncated": self.window_truncated,
            "dataset": self.dataset,
            "summary": {
                "principals_analyzed": len(self.findings),
                "idle_principals": len(self.idle_principals),
                "total_unused_actions": sum(f.unused_count for f in self.findings),
                "avg_risk_score": (
                    round(sum(f.risk_score for f in self.findings) / len(self.findings), 3)
                    if self.findings
                    else 0.0
                ),
                "top_risk": [
                    {"kind": f.kind, "name": f.name, "risk_score": round(f.risk_score, 3)}
                    for f in sorted(self.findings, key=lambda f: f.risk_score, reverse=True)[:5]
                ],
            },
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class VerifiedPolicy:
    """A tightened policy that passed the guardrail, ready for Terraform."""

    principal: str  # "user:alice" style label
    actions: list[str]  # verified lowercase actions
    used_actions_covered: list[str]
    verified: bool
    attempts: list[str] = field(default_factory=list)  # per-attempt verdict summaries
    proposer: str = "unknown"

    def checklist(self) -> list[str]:
        """Actions the guardrail must find covered before accepting a proposal."""
        return list(self.actions)
