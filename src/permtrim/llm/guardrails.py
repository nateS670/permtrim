"""Guardrails: validate LLM-proposed policies before anyone sees them (Task 4).

An LLM draft is accepted only after passing ALL of these checks:

1. **Structure** — a policy document with at least one Allow statement, and
   nothing but Allow/Deny statements with recognized keys.
2. **Negation elements rejected** — ``NotAction``/``NotResource`` drafts are
   refused outright: a ``NotAction`` Allow grants a huge, hard-to-audit
   action space, and the no-new-permissions check only reasons about
   explicit Action lists. (Azure drafts: ``notActions``/``notDataActions``
   are refused for the same reason.) First version scope: explicitly
   listed Action entries only.
3. **Hallucination check** — every proposed action must exist in the bundled
   AWS action dataset (20,455 actions). Llama-3-class models routinely invent
   plausible-sounding actions (``s3:GetObjekt``, ``ec2:RunInstance``); those
   drafts are rejected with the bogus names quoted back.
4. **Coverage (round-trip)** — the draft is evaluated with the same IAM
   matcher the analyzer uses (wildcards, NotAction, explicit Deny); every
   action the principal actually *used* must still be allowed, else the
   tightened policy would break production.
5. **No new permissions** — the draft must not grant actions the principal
   never had (blocks the classic LLM failure of 'fixing' coverage with
   ``Action: "*"``). Draft wildcards are clamped to the original grants.
6. **Unused removal** — every action the draft allows must be one the
   principal was actually observed using (working) or at least attempting
   (error-only). A draft that re-proposes the old broad grants — e.g.
   ``Action: "*"`` for a principal whose original policy was ``*`` but who
   only ever used one action — is rejected even though it adds no *new*
   permission, because it preserves the excess the tightener exists to
   remove. In AWS drafts this is enforced by refusing wildcard patterns
   outright: a least-privilege replacement lists the concrete actions.
7. **Resource scope no wider than original** — for used actions whose
   original grants carried resource scopes, the draft must not widen them:
   allowing an action on ``"*"`` when the principal only ever had it on
   ``arn:...:bucket/corp-data/*`` is a scope expansion. Drafts that widen
   any resource scope are rejected, not just flagged.
8. **No Deny statements** — AWS drafts containing ``Effect: "Deny"`` are
   rejected outright: coverage is checked over Allow statements only, and an
   explicit Deny silently overrides them in real IAM evaluation (it could
   block a used action while the guardrail sees full coverage). Tightened
   replacement policies are Allow-only by design.
9. **Live simulator (optional)** — when a ``simulator`` callable is wired
   (boto3 ``iam:SimulatePrincipalPolicy``), AWS itself gets the final word
   on the used actions. Offline runs (demo, tests, CI) omit it.

A rejected draft is retried with feedback describing every problem found;
after ``max_attempts`` the tightener falls back to the deterministic
proposer, so the pipeline never surfaces an unverified policy.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..analyzer.action_registry import ActionRegistry
from ..analyzer.findings import PrincipalFinding
from ..analyzer.matcher import PolicySet, as_pattern_list

__all__ = ["GuardrailVerdict", "Guardrail", "SimulatorCallable"]

LOGGER = logging.getLogger(__name__)

SimulatorCallable = Callable[[dict[str, Any], list[str]], list[str]]
"""Optional live simulator hook: (draft_policy, actions) -> actions AWS would DENY."""

_STATEMENT_KEYS = frozenset({"Effect", "Action", "NotAction", "Resource", "NotResource", "Condition", "Sid"})
_NEW_PERMISSION_SAMPLE = 10


def _as_resource_set(value: Any) -> set[str]:
    """Normalize a Resource element (str | list | None) to a set of scopes."""
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    return {str(item) for item in value}


@dataclass
class GuardrailVerdict:
    """Outcome of validating one draft policy."""

    ok: bool
    reasons: list[str] = field(default_factory=list)

    @property
    def feedback(self) -> str:
        """Feedback string for the next proposer retry."""
        if self.ok:
            return ""
        return "- " + "\n- ".join(self.reasons)


class Guardrail:
    """Validates tightened-policy drafts against findings and the action dataset."""

    def __init__(
        self,
        registry: ActionRegistry,
        simulator: SimulatorCallable | None = None,
        allow_new_permissions: bool = False,
    ) -> None:
        self._registry = registry
        self._simulator = simulator
        self._allow_new_permissions = allow_new_permissions

    def validate(self, finding: PrincipalFinding, draft: dict[str, Any] | None) -> GuardrailVerdict:
        """Run every guardrail check on one draft.

        Args:
            finding: The finding the draft is supposed to remediate.
            draft: The proposed policy document (AWS IAM statement form or
                Azure role-definition ``permissions`` form; may be None).

        Returns:
            A :class:`GuardrailVerdict`; ``reasons`` lists every problem found
            (not just the first) so a single retry can fix them all.
        """
        if not isinstance(draft, dict):
            return GuardrailVerdict(False, ["draft is not a JSON object"])

        reasons: list[str] = []
        if draft.get("permissions") is not None:
            statements = self._azure_statements(draft, reasons)
            self._check_azure_categories(finding, draft, reasons)
        else:
            statements = self._check_structure(draft, reasons)
        if not statements:
            return GuardrailVerdict(False, reasons or ["draft has no usable Allow statement"])

        self._check_negation_free(statements, reasons)
        self._check_hallucinations(statements, reasons)
        self._check_coverage(finding, statements, reasons)
        allowed = self._expanded_allowed(statements)
        self._check_no_new_permissions(finding, statements, allowed, reasons)
        self._check_unused_removal(finding, statements, allowed, reasons)
        self._check_resource_scope(finding, statements, reasons)

        if self._simulator is not None and not reasons:
            denied = self._simulator(draft, finding.used_actions)
            if denied:
                reasons.append("policy simulator would DENY these used actions: " + ", ".join(sorted(denied)))
        return GuardrailVerdict(not reasons, reasons)

    def _azure_statements(self, draft: dict[str, Any], reasons: list[str]) -> list[dict[str, Any]]:
        """Azure role-definition drafts: ``permissions`` -> statement dicts.

        Every permissions entry is an Allow (Azure role definitions carry no
        Deny); ``actions``/``dataActions`` map to Action, ``notActions`` /
        ``notDataActions`` to NotAction, so the downstream checks reuse the
        AWS statement vocabulary unchanged.
        """
        permissions = draft.get("permissions")
        if isinstance(permissions, dict):
            permissions = [permissions]
        if not isinstance(permissions, list) or not permissions:
            reasons.append("draft has no permissions list")
            return []
        statements: list[dict[str, Any]] = []
        for index, permission in enumerate(permissions):
            label = f"permission #{index + 1}"
            if not isinstance(permission, dict):
                reasons.append(f"{label} is not an object")
                continue
            actions = list(permission.get("actions") or [])
            actions += list(permission.get("dataActions") or [])
            not_actions = list(permission.get("notActions") or [])
            not_actions += list(permission.get("notDataActions") or [])
            if not_actions:
                # Same rationale as AWS NotAction: negation grants an
                # unbounded space the no-new-permissions check cannot
                # reason about. List actions explicitly instead.
                reasons.append(
                    f"{label} uses notActions/notDataActions — negation is not accepted "
                    "in tightened policies; list actions explicitly instead"
                )
                continue
            if not actions:
                reasons.append(f"{label} has neither actions nor notActions")
                continue
            statements.append({"Effect": "Allow", "Action": actions})
        return statements

    def _check_azure_categories(
        self, finding: PrincipalFinding, draft: dict[str, Any], reasons: list[str]
    ) -> None:
        """The draft must keep Azure's actions vs dataActions split intact.

        Azure role definitions carry two distinct permission axes: management
        operations in ``actions`` and data-plane operations in
        ``dataActions``. Routing a dataAction into ``actions`` (or the other
        way round) changes what the permission actually grants — merging both
        lists for the statement checks below would hide the difference, so
        this check compares every literal draft entry against the ORIGINAL
        grant categories from the analyzer (``GrantedAction.data_plane``). An
        entry that only exists as a dataAction in the original role but was
        written to ``actions`` is rejected, and vice versa. Wildcard entries
        are left to the no-new-permissions check (which limits their
        expansion to the granted union); the deterministic proposer writes
        exact strings only, so the happy path never trips here.
        """
        control = {g.action for g in finding.granted_actions if not g.data_plane}
        data = {g.action for g in finding.granted_actions if g.data_plane}
        if not control and not data:
            return
        permissions = draft.get("permissions")
        if isinstance(permissions, dict):
            permissions = [permissions]
        if not isinstance(permissions, list):
            return
        misplaced: list[str] = []
        for index, permission in enumerate(permissions):
            if not isinstance(permission, dict):
                continue
            label = f"permission #{index + 1}"
            for entry in permission.get("actions") or []:
                action = str(entry).strip().lower()
                if not action or "*" in action or "?" in action:
                    continue
                if action not in control and action in data:
                    misplaced.append(
                        f"{label}: '{entry}' is a dataAction in the original role "
                        "but was written to 'actions'"
                    )
            for entry in permission.get("dataActions") or []:
                action = str(entry).strip().lower()
                if not action or "*" in action or "?" in action:
                    continue
                if action not in data and action in control:
                    misplaced.append(
                        f"{label}: '{entry}' is a control-plane action in the "
                        "original role but was written to 'dataActions'"
                    )
        if misplaced:
            sample = misplaced[:_NEW_PERMISSION_SAMPLE]
            reasons.append(
                "category mismatch — Azure dataActions must stay in dataActions "
                "and control-plane actions in actions: "
                + "; ".join(sample)
                + (
                    f" (+{len(misplaced) - _NEW_PERMISSION_SAMPLE} more)"
                    if len(misplaced) > _NEW_PERMISSION_SAMPLE
                    else ""
                )
            )

    # ------------------------------------------------------------- checks

    def _check_negation_free(self, statements: list[dict[str, Any]], reasons: list[str]) -> None:
        """Reject NotAction/NotResource outright (first-version scope).

        A NotAction Allow grants everything *except* the listed patterns —
        an unbounded space the no-new-permissions check cannot reason about,
        because it only compares explicit Action lists. Until that check
        understands negation semantics end to end, drafts using
        NotAction/NotResource are rejected and the proposer is told to list
        the actions explicitly instead. Azure role drafts hit the same
        rejection via ``notActions``/``notDataActions``.
        """
        offenders: set[str] = set()
        for statement in statements:
            if as_pattern_list(statement.get("NotAction")):
                offenders.add("NotAction")
            if statement.get("NotResource") is not None:
                offenders.add("NotResource")
        if offenders:
            reasons.append(
                "negation elements are not accepted in tightened policies: "
                + ", ".join(sorted(offenders))
                + " — list the actions/resources explicitly instead"
            )

    def _check_structure(self, draft: dict[str, Any], reasons: list[str]) -> list[dict[str, Any]]:
        """Statement-level structural validation; returns the Allow statements.

        AWS drafts must be Allow-only: a ``Deny`` statement is rejected
        outright (coverage is checked over Allows, but a real explicit Deny
        overrides every Allow — see the module docstring, check 8). Azure
        drafts have no Deny concept to begin with.

        AWS drafts must also carry a ``Resource`` element on every Allow
        statement: a missing / empty / wrong-typed Resource would let the
        tightener's ``_outcome_status`` treat the draft as if it allowed
        ``"*"`` (the IAM evaluation default), silently widening the blast
        radius of every action in the statement. We refuse it outright so the
        gap cannot become a "verified" policy. (Azure drafts use the
        ``permissions`` shape and have no Resource element — handled in
        ``_azure_statements``.)
        """
        raw = draft.get("Statement")
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list) or not raw:
            reasons.append("draft has no Statement list")
            return []
        allows: list[dict[str, Any]] = []
        for index, statement in enumerate(raw):
            label = f"statement #{index + 1}"
            if not isinstance(statement, dict):
                reasons.append(f"{label} is not an object")
                continue
            unknown = set(statement) - _STATEMENT_KEYS
            if unknown:
                reasons.append(f"{label} has unknown keys: {sorted(unknown)}")
                continue
            effect = str(statement.get("Effect", "")).lower()
            if effect not in {"allow", "deny"}:
                reasons.append(f"{label} has invalid Effect {statement.get('Effect')!r}")
                continue
            if not (statement.get("Action") or statement.get("NotAction")):
                reasons.append(f"{label} has neither Action nor NotAction")
                continue
            if effect == "deny":
                # A Deny would override the Allows while the coverage check
                # only evaluates Allows — refuse it so the coverage verdict
                # cannot be bypassed (Allow s3:GetObject + Deny s3:GetObject).
                reasons.append(
                    f"{label} is a Deny statement — tightened policies are Allow-only; "
                    "the guardrail validates coverage over Allow statements and a Deny "
                    "would silently override them in real IAM evaluation"
                )
                continue
            resource = statement.get("Resource")
            # Resource must be present, non-empty, and a string or list of
            # strings. ``None`` / ``[]`` / ``""`` / numbers / dicts would all
            # fall back to ``"*"`` in IAM and widen scope — refuse them so a
            # draft cannot slip through as a "verified" widening.
            #
            # NotResource is a separate, earlier failure handled by
            # ``_check_negation_free`` (a negation on the resource axis): if
            # the draft uses NotResource we still record the missing-Resource
            # reason (IAM defaults it to "*"), but we must NOT ``continue``
            # here, or the negation check never runs and the draft is
            # rejected with only half the explanation. So: when NotResource is
            # present, defer to the negation check and let the statement
            # through structure validation (the negation check will reject it).
            has_not_resource = statement.get("NotResource") is not None
            if not has_not_resource:
                if resource is None:
                    reasons.append(
                        f"{label} has no Resource element — AWS IAM defaults a missing "
                        "Resource to '*', widening the scope of every action in the "
                        "statement; tightened policies must state the Resource explicitly"
                    )
                    continue
                if isinstance(resource, str):
                    if not resource.strip():
                        reasons.append(f"{label} has an empty Resource string")
                        continue
                elif isinstance(resource, list):
                    if not resource:
                        reasons.append(f"{label} has an empty Resource list")
                        continue
                    if any(not isinstance(item, str) or not str(item).strip() for item in resource):
                        reasons.append(f"{label} has a Resource list with non-string or empty entries")
                        continue
                else:
                    reasons.append(
                        f"{label} has a Resource of type {type(resource).__name__} — "
                        "expected a string or list of strings"
                    )
                    continue
            allows.append(statement)
        return allows

    def _check_hallucinations(self, statements: list[dict[str, Any]], reasons: list[str]) -> None:
        """Every literal action must exist in the AWS action dataset."""
        bogus: set[str] = set()
        for statement in statements:
            for pattern in as_pattern_list(statement.get("Action")):
                if "*" in pattern or "?" in pattern:
                    continue
                if not self._registry.action_exists(pattern):
                    bogus.add(pattern)
        if bogus:
            reasons.append(
                "hallucinated actions (do not exist in the AWS action dataset): " + ", ".join(sorted(bogus))
            )

    def _check_coverage(
        self, finding: PrincipalFinding, statements: list[dict[str, Any]], reasons: list[str]
    ) -> None:
        """Round-trip: the matcher must allow every used action through the draft."""
        policy_set = PolicySet()
        for index, statement in enumerate(statements):
            policy_set.add_policy_document({"Statement": statement}, f"draft:{index + 1}")
        denied = [action for action in finding.used_actions if not policy_set.evaluate(action)[0]]
        if denied:
            reasons.append("coverage failure — used actions the draft no longer allows: " + ", ".join(denied))

    def _expanded_allowed(self, statements: list[dict[str, Any]]) -> set[str]:
        """Concrete actions the draft's Allow statements cover (wildcards expanded)."""
        allowed: set[str] = set()
        for statement in statements:
            for pattern in as_pattern_list(statement.get("Action")):
                if "*" in pattern or "?" in pattern:
                    allowed.update(self._registry.expand(pattern))
                else:
                    allowed.add(pattern)
        return allowed

    def _check_resource_scope(
        self, finding: PrincipalFinding, statements: list[dict[str, Any]], reasons: list[str]
    ) -> None:
        """The draft must not widen resource scopes of the original grants.

        When the analyzer recorded the resource scopes a used action was
        originally granted on, a draft statement that allows the same action
        on ``"*"`` (or any resource outside those scopes) is a scope
        expansion — the action count may shrink while the blast radius on
        each surviving action grows. Widening drafts are rejected; when no
        resource provenance was recorded (Azure, older snapshots), the
        outcome is downgraded to ``needs_review`` by the tightener instead.
        """
        if not finding.used_action_resources:
            return
        original: dict[str, set[str]] = {
            action: set(scopes) for action, scopes in finding.used_action_resources.items()
        }
        widened: list[str] = []
        for statement in statements:
            resources = _as_resource_set(statement.get("Resource"))
            for pattern in as_pattern_list(statement.get("Action")):
                covered = (
                    set(self._registry.expand(pattern)) if "*" in pattern or "?" in pattern else {pattern}
                )
                for action in covered:
                    scopes = original.get(action)
                    if not scopes:
                        continue
                    # a draft scope is a widening unless the original grants
                    # already carried it ("*" original => "*" draft is fine)
                    if any(res not in scopes for res in resources):
                        widened.append(f"{action}: {sorted(resources)} vs original {sorted(scopes)}")
        if widened:
            sample = widened[:_NEW_PERMISSION_SAMPLE]
            reasons.append(
                "resource scope wider than the original grants: "
                + "; ".join(sample)
                + (f" (+{len(widened) - len(sample)} more)" if len(widened) > len(sample) else "")
            )

    def _check_no_new_permissions(
        self,
        finding: PrincipalFinding,
        statements: list[dict[str, Any]],
        allowed: set[str],
        reasons: list[str],
    ) -> None:
        """The draft must not grant actions the principal never had.

        Every wildcard pattern in the draft must expand to a SUBSET of the
        principal's current grants: a draft ``*`` or ``s3:*`` that reaches
        beyond them is a new permission and rejected. Literal actions are
        checked the same way (an unknown-to-the-principal literal action is
        trivially new). This blocks the classic LLM failure of 'fixing'
        coverage with ``Action: "*"``.
        """
        if self._allow_new_permissions:
            return
        granted = {g.action for g in finding.granted_actions}
        new_permissions: set[str] = set()
        for statement in statements:
            for pattern in as_pattern_list(statement.get("Action")):
                if "*" in pattern or "?" in pattern:
                    expansion = set(self._registry.expand(pattern))
                else:
                    expansion = {pattern}
                new_permissions |= expansion - granted
        if new_permissions:
            sample = sorted(new_permissions)[:_NEW_PERMISSION_SAMPLE]
            reasons.append(
                "new permissions not present in the original grants: "
                + ", ".join(sample)
                + (
                    f" (+{len(new_permissions) - len(sample)} more)"
                    if len(new_permissions) > len(sample)
                    else ""
                )
            )

    def _check_unused_removal(
        self,
        finding: PrincipalFinding,
        statements: list[dict[str, Any]],
        allowed: set[str],
        reasons: list[str],
    ) -> None:
        """The draft must actually REMOVE the unused excess permissions.

        "No new permissions" alone is not enough: a draft that re-proposes
        the principal's ORIGINAL grants adds nothing new yet keeps every
        unused permission the tightener exists to remove. The extreme case:
        original policy ``Action: "*"`` + one used action + an LLM that
        proposes ``Action: "*"`` back — no-new-permissions passes (the
        wildcard's expansion is a subset of the original grants) and
        coverage passes, so without this check the old blast radius would
        ship as a "validated" least-privilege policy.

        Baseline: actions with observed usage (working) or attempts
        (error-only — the principal may need them, and the tightener keeps
        attempted actions conservative). The draft's allowed set must be a
        subset of that baseline. A draft that allows nothing from the
        baseline fails coverage upstream, so no empty-policy hole exists.

        AWS drafts: wildcard Action patterns are refused outright — a
        least-privilege replacement lists concrete actions (the deterministic
        fallback does exactly that and remains valid). Azure drafts
        (``permissions`` shape): wildcards stay allowed because the whole
        point is re-scoping e.g. ``microsoft.storage/*`` down to the used
        data-plane slice; the subset check still applies to their expansion.
        """
        wildcards: set[str] = set()
        for statement in statements:
            for pattern in as_pattern_list(statement.get("Action")):
                if "*" in pattern or "?" in pattern:
                    wildcards.add(pattern)
        if wildcards and finding.provider != "azure":
            sample = sorted(wildcards)[:_NEW_PERMISSION_SAMPLE]
            reasons.append(
                "wildcard Action patterns are not accepted in tightened AWS policies "
                "(they re-grant unused permissions): "
                + ", ".join(sample)
                + " — list the concrete actions instead"
            )
            return  # the subset check below would only duplicate the noise

        baseline = set(finding.used_actions) | {g.action for g in finding.granted_actions if g.error_only}
        if not baseline:
            return  # idle: coverage already demanded nothing; drafts with actions fail
        excess = allowed - baseline
        if excess:
            sample = sorted(excess)[:_NEW_PERMISSION_SAMPLE]
            reasons.append(
                "draft keeps actions with no observed usage — a tightened policy must "
                "only contain used (or attempted) actions: "
                + ", ".join(sample)
                + (f" (+{len(excess) - len(sample)} more)" if len(excess) > len(sample) else "")
            )
