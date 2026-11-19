"""Tightener orchestration: findings -> action-level validated policies (Task 4).

For each finding the tightener runs the propose → validate → retry loop:

    proposer.propose(finding)
        └─ Guardrail.validate(finding, draft)
             ├─ ok      -> accept, render Terraform
             └─ rejected-> retry with feedback (up to max_attempts)
                             └─ still failing -> deterministic fallback

The deterministic fallback (observed-actions policy) is itself validated by
the same guardrail — no code path can emit an unvalidated policy. Principals
with no working usage (idle) get no policy; they are reported as candidates
for access review instead.

Outcome statuses (honest about what was actually validated):

* ``verified`` — passed every guardrail check AND the original resource
  scopes were carried into the tightened policy (no ``Resource: "*"`` guess).
* ``needs_review`` — passed every guardrail check at the ACTION level, but
  the snapshot carried no resource provenance (Azure role assignments,
  older collectors), so resource scoping must be reviewed by a human.
* ``insufficient_data`` — the activity window was truncated (AWS API caps);
  tightening from incomplete usage data could break production, so no policy
  is generated until the window is complete.
* ``idle`` — no working usage in the window; access-review candidate.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ..analyzer.action_registry import ActionRegistry
from ..analyzer.findings import AnalysisReport, PrincipalFinding
from .guardrails import Guardrail
from .proposer import DeterministicProposer, PolicyProposer

__all__ = ["TightenResult", "PrincipalOutcome", "Tightener", "TightenerConfig"]

LOGGER = logging.getLogger(__name__)


@dataclass
class PrincipalOutcome:
    """What happened while tightening one principal."""

    principal: str  # "user:alice"
    # "verified" | "needs_review" | "idle" | "insufficient_data" | "failed"
    status: str
    proposer: str = ""
    attempts: list[str] = field(default_factory=list)
    finding: PrincipalFinding | None = None
    policy: dict[str, Any] | None = None

    @property
    def label(self) -> str:
        return f"{self.status} ({self.proposer})" if self.proposer else self.status


@dataclass
class TightenResult:
    """Aggregate tightener outcome over an analysis report."""

    outcomes: list[PrincipalOutcome] = field(default_factory=list)

    @property
    def verified(self) -> list[PrincipalOutcome]:
        return [o for o in self.outcomes if o.status == "verified"]

    @property
    def validated(self) -> list[PrincipalOutcome]:
        """Guardrail-validated policies: fully verified + needs_review ones."""
        return [o for o in self.outcomes if o.status in {"verified", "needs_review"}]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total": len(self.outcomes),
                "verified": len(self.verified),
                "needs_review": sum(1 for o in self.outcomes if o.status == "needs_review"),
                "idle": sum(1 for o in self.outcomes if o.status == "idle"),
                "insufficient_data": sum(1 for o in self.outcomes if o.status == "insufficient_data"),
                "failed": sum(1 for o in self.outcomes if o.status == "failed"),
            },
            "outcomes": [
                {
                    "principal": o.principal,
                    "status": o.status,
                    "proposer": o.proposer,
                    "attempts": o.attempts,
                    "policy": o.policy,
                }
                for o in self.outcomes
            ],
        }


@dataclass
class TightenerConfig:
    """Tightener tunables."""

    max_attempts: int = 3
    include_idle: bool = False  # idle principals need review, not policies
    # A truncated window means AWS API caps cut the usage data short;
    # tightening from incomplete data risks breaking production. Opt in
    # explicitly (you know the window is representative anyway) to override.
    allow_truncated_window: bool = False


class Tightener:
    """Drive propose/validate/retry for every finding in a report."""

    def __init__(
        self,
        proposer: PolicyProposer,
        registry: ActionRegistry,
        config: TightenerConfig | None = None,
        guardrail: Guardrail | None = None,
    ) -> None:
        self._proposer = proposer
        self._fallback = DeterministicProposer(registry)
        self._config = config or TightenerConfig()
        self._guardrail = guardrail or Guardrail(registry)

    def tighten(self, report: AnalysisReport) -> TightenResult:
        """Tighten every finding in the report.

        Returns:
            A :class:`TightenResult` with one outcome per principal.
        """
        result = TightenResult()
        if report.window_truncated and not self._config.allow_truncated_window:
            LOGGER.warning(
                "Activity window is TRUNCATED (AWS API cap hit) — automatic tightening "
                "disabled; re-collect over a smaller window or pass "
                "allow_truncated_window=True if you know the data is representative"
            )
            for finding in report.findings:
                result.outcomes.append(
                    PrincipalOutcome(
                        principal=f"{finding.kind}:{finding.name}",
                        status="insufficient_data",
                        proposer="none",
                        attempts=[
                            "activity window truncated — usage data is incomplete; "
                            "automatic tightening disabled to avoid breaking production"
                        ],
                        finding=finding,
                    )
                )
            return result
        for finding in report.findings:
            result.outcomes.append(self._tighten_one(finding))
        LOGGER.info(
            "Tightener: %d principals -> %d verified, %d needs_review, %d idle, %d failed",
            len(result.outcomes),
            len(result.verified),
            sum(1 for o in result.outcomes if o.status == "needs_review"),
            sum(1 for o in result.outcomes if o.status == "idle"),
            sum(1 for o in result.outcomes if o.status == "failed"),
        )
        return result

    # ------------------------------------------------------------- internals

    def _tighten_one(self, finding: PrincipalFinding) -> PrincipalOutcome:
        principal = f"{finding.kind}:{finding.name}"
        outcome = PrincipalOutcome(principal=principal, status="failed", finding=finding)

        if not finding.used_actions:
            outcome.status = "idle"
            outcome.proposer = "none"
            outcome.attempts = ["no working usage in window — candidate for access review"]
            return outcome

        # ---- primary proposer with retries
        feedback: str | None = None
        attempts_log: list[str] = []
        for attempt in range(1, self._config.max_attempts + 1):
            draft = self._proposer.propose(finding, feedback)
            if draft is None:
                attempts_log.append(f"attempt {attempt}: proposer returned no draft")
                break
            verdict = self._guardrail.validate(finding, draft)
            if verdict.ok:
                attempts_log.append(f"attempt {attempt}: accepted")
                return PrincipalOutcome(
                    principal=principal,
                    status=self._outcome_status(finding, draft),
                    proposer=self._proposer.name,
                    attempts=attempts_log,
                    finding=finding,
                    policy=draft,
                )
            attempts_log.append(f"attempt {attempt}: rejected — {verdict.feedback}")
            feedback = verdict.feedback
        outcome.attempts = attempts_log

        # ---- deterministic fallback (still guardrail-validated)
        draft = self._fallback.propose(finding)
        if draft is not None:
            verdict = self._guardrail.validate(finding, draft)
            if verdict.ok:
                outcome.status = self._outcome_status(finding, draft)
                outcome.proposer = self._fallback.name
                outcome.attempts.append("fallback: deterministic policy accepted")
                outcome.policy = draft
                return outcome
            outcome.attempts.append(f"fallback rejected (bug!): {verdict.feedback}")
        else:
            outcome.attempts.append("fallback: no used actions to build a policy from")
        return outcome

    @staticmethod
    def _outcome_status(finding: PrincipalFinding, draft: dict[str, Any]) -> str:
        """Honest status: full verification only with resource provenance.

        ``verified`` requires every used action to appear in an Allow
        statement whose Resource entries all come from that action's
        recorded original scopes (no ``"*"`` guess). Without provenance
        (Azure, older snapshots) the checks passed at the action level
        only, and the result is ``needs_review``.
        """
        if not finding.used_action_resources:
            return "needs_review"
        statements = draft.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        provenance = finding.used_action_resources
        for statement in statements:
            if not isinstance(statement, dict) or str(statement.get("Effect", "")).lower() != "allow":
                continue
            actions = statement.get("Action")
            actions = [actions] if isinstance(actions, str) else list(actions or [])
            resources = statement.get("Resource") or "*"
            resources = [resources] if isinstance(resources, str) else list(resources)
            for action in actions:
                allowed_scopes = provenance.get(str(action).lower(), ())
                if any(res not in allowed_scopes for res in resources):
                    return "needs_review"  # includes "*" fallbacks
        return "verified"
