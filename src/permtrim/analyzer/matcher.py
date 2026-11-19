"""IAM statement evaluation: wildcard patterns, NotAction, explicit Deny.

IAM action matching semantics implemented here (AWS docs, "IAM JSON policy
elements: Action"):

* matching is **case-insensitive**,
* ``*`` matches any sequence of characters and ``?`` exactly one,
* ``NotAction`` inverts the pattern list,
* an explicit ``Deny`` always wins over any ``Allow``.

``Resource`` and ``Condition`` are deliberately NOT evaluated: the audit log
view we collect is action-level (who called what), not resource-level.
Resource scoping is preserved verbatim when generating tightened policies,
and full-fidelity checking is delegated to ``iam:SimulatePrincipalPolicy``
(Task 4 guardrail). This limitation is documented in the findings output.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Statement", "PolicySet", "as_pattern_list"]


@dataclass(frozen=True)
class Statement:
    """One policy statement, reduced to action-matching semantics.

    AWS IAM rules (AWS docs, "IAM JSON policy elements: Action"): matching
    is case-insensitive, ``*`` matches any sequence and ``?`` exactly one,
    ``NotAction`` inverts the pattern list, explicit ``Deny`` always wins.

    Azure RBAC roles may carry ``actions`` AND ``notActions`` in the same
    permission entry (Contributor = ``*`` minus ``Microsoft.Authorization/*/Write``);
    there, ``notActions`` subtracts from the ``actions`` grants. ``matches``
    implements both: an action is covered when an ``actions`` pattern hits
    (or there are none) AND no ``not_actions`` pattern hits.
    """

    effect: str  # "allow" | "deny" (lowercased)
    actions: tuple[str, ...]  # lowercase patterns, empty when NotAction is used
    not_actions: tuple[str, ...]
    resources: tuple[str, ...]
    condition: bool = False  # True when the statement carries a Condition element
    source: str = ""  # provenance label, e.g. "managed:AdministratorAccess@user/alice"
    # True when the statement came from an Azure ``dataActions`` clause (or,
    # on AWS, was classified by the analyzer as data-plane). Carried end to
    # end so the engine can mark data-plane grants whose usage is invisible
    # to lookup_events / Activity Log as ``unknown_usage_actions``.
    data_plane: bool = False

    def matches(self, action: str) -> bool:
        """Does this statement's Action/NotAction element cover ``action``?"""
        if self.actions:
            if not any(fnmatch.fnmatchcase(action, pattern) for pattern in self.actions):
                return False
            # actions matched; Azure-style notActions still subtract
            # (two-step form kept for readability; noqa: SIM103)
            if self.not_actions and any(  # noqa: SIM103 - two-step form documents the semantics
                fnmatch.fnmatchcase(action, pattern) for pattern in self.not_actions
            ):
                return False
            return True
        if self.not_actions:
            return not any(fnmatch.fnmatchcase(action, pattern) for pattern in self.not_actions)
        return False


def as_pattern_list(value: Any) -> list[str]:
    """Normalize an Action/NotAction element (str | list | None) to lowercase patterns."""
    if value is None:
        return []
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple)):
        values = list(value)
    else:
        return []
    return [str(item).strip().lower() for item in values if str(item).strip()]


def _as_resource_list(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


@dataclass
class PolicySet:
    """All statements that apply to one principal, from every source.

    Two policy document formats are understood, detected by shape:

    * AWS IAM — ``{"Statement": [{"Effect": ..., "Action": [...], ...}]}``
    * Azure RBAC role definitions —
      ``{"roleName": ..., "permissions": [{"actions": [...], "notActions":
      [...], "dataActions": [...], "notDataActions": [...]}]}`` (there is no
      Deny in Azure role definitions; every permission entry is an Allow,
      ``notActions``/``notDataActions`` are subtractive exclusions).
    """

    statements: list[Statement] = field(default_factory=list)

    def add_policy_document(self, document: dict[str, Any], source: str) -> None:
        """Extract statements from one policy document (inline or managed)."""
        if not isinstance(document, dict):
            return
        if document.get("Statement") is not None:
            self._add_aws_document(document, source)
        elif document.get("permissions") is not None or document.get("Permissions") is not None:
            self._add_azure_document(document, source)

    def _add_aws_document(self, document: dict[str, Any], source: str) -> None:
        """AWS IAM policy: a Statement list with Effect/Action/NotAction."""
        raw = document.get("Statement", [])
        statements = raw if isinstance(raw, list) else [raw]
        for statement in statements:
            if not isinstance(statement, dict):
                continue
            effect = str(statement.get("Effect", "")).strip().lower()
            if effect not in {"allow", "deny"}:
                continue
            self.statements.append(
                Statement(
                    effect=effect,
                    actions=tuple(as_pattern_list(statement.get("Action"))),
                    not_actions=tuple(as_pattern_list(statement.get("NotAction"))),
                    resources=_as_resource_list(statement.get("Resource")),
                    condition=bool(statement.get("Condition")),
                    source=source,
                )
            )

    def _add_azure_document(self, document: dict[str, Any], source: str) -> None:
        """Azure RBAC role definition: ``permissions`` entries, all Allow.

        ``actions`` and ``dataActions`` are KEPT as separate statements (not
        merged): the ``data_plane`` flag on the data-plane statement lets the
        analyzer classify those grants as ``unknown_usage_actions``, because
        Azure Activity Log records control-plane operations only — data-plane
        usage (Blob reads/writes, Key Vault gets, ...) lives in the resource's
        diagnostic settings, a pipeline this collector does not ingest. Merging
        them would lose the distinction and let a data-plane grant be dropped
        as "unused" when it is merely invisible. ``notActions`` / ``notDataActions``
        attach to their matching control / data-plane statement respectively.
        """
        permissions = document.get("permissions") or document.get("Permissions") or []
        if isinstance(permissions, dict):
            permissions = [permissions]
        for index, permission in enumerate(permissions):
            if not isinstance(permission, dict):
                continue
            control_actions = as_pattern_list(permission.get("actions") or permission.get("Actions"))
            data_actions = as_pattern_list(permission.get("dataActions") or permission.get("DataActions"))
            control_not_actions = as_pattern_list(
                permission.get("notActions") or permission.get("NotActions")
            )
            data_not_actions = as_pattern_list(
                permission.get("notDataActions") or permission.get("NotDataActions")
            )
            perm_label = f"{source}#perm{index + 1}"
            if control_actions or control_not_actions:
                self.statements.append(
                    Statement(
                        effect="allow",
                        actions=tuple(control_actions),
                        not_actions=tuple(control_not_actions),
                        resources=(),  # scope is on the role assignment, not the definition
                        condition=False,  # Azure role definitions carry no Condition element
                        source=perm_label,
                        data_plane=False,
                    )
                )
            if data_actions or data_not_actions:
                self.statements.append(
                    Statement(
                        effect="allow",
                        actions=tuple(data_actions),
                        not_actions=tuple(data_not_actions),
                        resources=(),
                        condition=False,
                        source=perm_label + "#dataActions",
                        data_plane=True,
                    )
                )

    @property
    def allow_statements(self) -> list[Statement]:
        return [statement for statement in self.statements if statement.effect == "allow"]

    @property
    def deny_statements(self) -> list[Statement]:
        return [statement for statement in self.statements if statement.effect == "deny"]

    def evaluate(self, action: str) -> tuple[bool, Statement | None]:
        """Would ``action`` be permitted?

        Returns:
            ``(allowed, granting_statement)`` — the granting statement is the
            first Allow that matches (``None`` when denied or not granted).
            Explicit Deny always wins, mirroring IAM evaluation order.
        """
        if any(deny.matches(action) for deny in self.deny_statements):
            return False, None
        for allow in self.allow_statements:
            if allow.matches(action):
                return True, allow
        return False, None


def statements_from_policy_documents(documents: Iterable[tuple[dict[str, Any], str]]) -> PolicySet:
    """Build a :class:`PolicySet` from ``(document, source_label)`` pairs."""
    policy_set = PolicySet()
    for document, source in documents:
        policy_set.add_policy_document(document, source)
    return policy_set
