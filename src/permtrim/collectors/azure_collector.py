"""Azure RBAC collector: role assignments + definitions + activity log (Task 5).

Pipeline
--------
1. **Static side** — ``role_assignments.list_for_scope()`` over the
   subscription, then ``role_definitions.get_by_id()`` for every distinct
   role; AAD principals are resolved through an injectable
   ``principal_resolver`` (Microsoft Graph in production, a plain mapping in
   tests — the collector never talks to Graph itself).
2. **Dynamic side** — ``monitor.event_categories`` / activity log
   ``list()`` over the window; the ``caller`` of each record is folded onto
   the matching principal (user UPN, service principal display name, group
   display name, or raw GUID when unresolved).
3. **Merge** — :meth:`BaseCollector._assemble_unified`, the same unified
   schema the AWS collector emits.

Concept mapping (user-facing docs repeat this table)
----------------------------------------------------
======================  ==================  ==============================
Azure AD object         unified ``kind``    rationale
======================  ==================  ==============================
User                    ``user``            human sign-in (UPN as name)
Service Principal       ``role``            workload identity (app + managed
/ Managed Identity                         identities behave like AWS roles)
Group                   ``group``           permission container
======================  ==================  ==============================

Role definitions become managed policies (``kind: builtin | custom``), with
their ``permissions`` document (``actions`` / ``notActions`` /
``dataActions`` / ``notDataActions``) kept verbatim for the analyzer's
Azure-aware matcher. Assignment scope (the closest analogue to an AWS
policy's Resource) is NOT yet carried into the analysis: the analyzer works
at the action level, so tightened Azure roles are marked ``needs_review``
for scope review instead of ``verified``.

Operational limits of the Azure Activity Log
--------------------------------------------
* Retention is **90 days** (same bound as CloudTrail lookup_events).
* ``list()`` pages by ``$skipToken`` up to ``max_events`` records; hitting
  the cap marks the window ``truncated``.
* The classic deployment provider emits coarse operations
  (``Microsoft.Resources/deployments/write``); those are kept verbatim —
  Azure's audit surface is what it is.

Required Azure RBAC permissions (read-only)
-------------------------------------------
``Microsoft.Authorization/roleAssignments/read``,
``Microsoft.Authorization/roleDefinitions/read``,
``Microsoft.Insights/eventcategories/read``,
``Microsoft.Insights/read`` (activity log).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar, Protocol

from ..errors import (
    AuthenticationError,
    CollectorConfigError,
    CollectorError,
    CollectorOperationError,
    ThrottlingError,
)
from ..models.activity import (
    ActivityEvent,
    ActivityLog,
    ActivityWindow,
    PrincipalKind,
    PrincipalRef,
    summarize_usage,
)
from ..models.iam import (
    IAMGroup,
    IAMRole,
    IaMSnapshot,
    IAMUser,
    ManagedPolicy,
    ManagedPolicyRef,
    PolicyKind,
)
from .base import BaseCollector, CollectorConfig

__all__ = [
    "AzureCollectorConfig",
    "AzureCollector",
    "PrincipalResolver",
    "StaticPrincipalResolver",
    "AZURE_ACTIVITY_LOG_MAX_LOOKBACK_DAYS",
]

LOGGER = logging.getLogger(__name__)

AZURE_ACTIVITY_LOG_MAX_LOOKBACK_DAYS = 90
"""Azure Activity Log retention bound (export to Log Analytics for longer)."""

ACTIVITY_PAGE_SIZE = 100
"""Records requested per activity-log page."""

_AZURE_AUTH_ERROR_CODES = frozenset(
    {
        "AuthorizationFailed",
        "ExpiredAuthenticationToken",
        "InvalidAuthenticationToken",
        "InvalidAuthenticationTokenAudience",
        "AuthenticationFailed",
        "InteractionRequired",
    }
)
_AZURE_THROTTLE_CODES = frozenset(
    {
        "TooManyRequests",
        "RequestThrottled",
        "SubscriptionOperationBlocked",
    }
)

_ROLE_DEF_ID_PATTERN = re.compile(r"/roleDefinitions/([0-9a-fA-F-]{36})$")


class PrincipalResolver(Protocol):
    """Resolves AAD object IDs to display names + principal types.

    Production wires Microsoft Graph (``GET /v1.0/directoryObjects/{id}``);
    tests wire :class:`StaticPrincipalResolver` with a plain mapping. The
    collector treats resolution failure as non-fatal: the GUID is kept as
    the name and ``principal_type`` is unknown.
    """

    def resolve(self, object_id: str) -> tuple[str, str] | None:
        """Return ``(display_name, principal_type)`` or ``None`` if unknown.

        ``principal_type`` is one of ``User``/``ServicePrincipal``/``Group``
        (Microsoft Graph vocabulary).
        """
        ...


class StaticPrincipalResolver:
    """Test/fallback resolver backed by a fixed ``{object_id: (name, type)}`` map."""

    def __init__(self, mapping: dict[str, tuple[str, str]]) -> None:
        self._mapping = dict(mapping)

    def resolve(self, object_id: str) -> tuple[str, str] | None:
        return self._mapping.get(object_id)


GroupMembershipProvider = Callable[[str], list[str]]
"""Maps an AAD object id -> display names of its transitive groups.

Production wires Microsoft Graph ``transitiveMemberOf``; tests wire a plain
``lambda object_id: [...]``. Returning ``[]`` simply means "no groups"."""


# Principal type (Graph) -> unified kind
_PRINCIPAL_KIND = {
    "user": PrincipalKind.USER,
    "serviceprincipal": PrincipalKind.ROLE,
    "service principal": PrincipalKind.ROLE,
    "group": PrincipalKind.GROUP,
}


def _unified_kind(principal_type: str | None) -> PrincipalKind:
    """Map a Microsoft Graph principal type onto the unified ``kind``."""
    if not principal_type:
        return PrincipalKind.UNKNOWN
    return _PRINCIPAL_KIND.get(principal_type.strip().lower().replace(" ", ""), PrincipalKind.UNKNOWN)


@dataclass
class AzureCollectorConfig(CollectorConfig):
    """Settings for :class:`AzureCollector`.

    Attributes:
        subscription_id: Target subscription (all scopes are derived from it).
        tenant_id: Optional tenant override for the credential.
        client_id / client_secret: Optional service-principal credential;
            ``None`` uses :class:`DefaultAzureCredential` (az login, managed
            identity, environment, ...).
        max_events: Stop after this many activity-log records.
    """

    subscription_id: str = ""
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    max_events: int = 10_000

    def __post_init__(self) -> None:
        if not 1 <= self.default_lookback_days <= AZURE_ACTIVITY_LOG_MAX_LOOKBACK_DAYS:
            raise CollectorConfigError(
                f"default_lookback_days must be within 1..{AZURE_ACTIVITY_LOG_MAX_LOOKBACK_DAYS} "
                f"(Azure Activity Log retention limit); got {self.default_lookback_days}"
            )
        if self.max_events < 1:
            raise CollectorConfigError(f"max_events must be >= 1; got {self.max_events}")


class AzureCollector(BaseCollector):
    """Azure implementation of the collector contract (RBAC + activity log)."""

    provider: ClassVar[str] = "azure"

    def __init__(
        self,
        config: AzureCollectorConfig | None = None,
        *,
        authorization_client: Any = None,
        monitor_client: Any = None,
        principal_resolver: PrincipalResolver | None = None,
        group_memberships: GroupMembershipProvider | None = None,
    ) -> None:
        super().__init__(config or AzureCollectorConfig())
        self._azure_config: AzureCollectorConfig = self._config  # type: ignore[assignment]
        self._authorization_client = authorization_client
        self._monitor_client = monitor_client
        self._principal_resolver = principal_resolver
        self._group_memberships = group_memberships
        self._caller_index: dict[str, tuple[PrincipalKind, str]] | None = None
        self._snapshot_names: list[tuple[PrincipalKind, str]] = []

    # ------------------------------------------------------------- plumbing

    def _get_authorization_client(self) -> Any:
        """Lazily create (or return the injected) AuthorizationManagementClient."""
        if self._authorization_client is None:
            self._authorization_client = self._make_authorization_client()
        return self._authorization_client

    def _get_monitor_client(self) -> Any:
        """Lazily create (or return the injected) MonitorManagementClient."""
        if self._monitor_client is None:
            self._monitor_client = self._make_monitor_client()
        return self._monitor_client

    def _make_authorization_client(self) -> Any:
        """Create the authorization client with the configured credential."""
        try:
            from azure.mgmt.authorization import AuthorizationManagementClient
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise CollectorConfigError(
                "Azure SDK not installed. Install with: pip install permtrim[azure]"
            ) from exc
        return AuthorizationManagementClient(
            credential=self._make_credential(),
            subscription_id=self._require_subscription_id(),
        )

    def _make_monitor_client(self) -> Any:
        """Create the monitor client with the configured credential."""
        try:
            from azure.mgmt.monitor import MonitorManagementClient
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise CollectorConfigError(
                "Azure SDK not installed. Install with: pip install permtrim[azure]"
            ) from exc
        return MonitorManagementClient(
            credential=self._make_credential(),
            subscription_id=self._require_subscription_id(),
        )

    def _make_credential(self) -> Any:
        """Credential from explicit SP settings, else DefaultAzureCredential."""
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise CollectorConfigError(
                "azure-identity not installed. Install with: pip install permtrim[azure]"
            ) from exc
        if self._azure_config.client_id and self._azure_config.client_secret and self._azure_config.tenant_id:
            return ClientSecretCredential(
                tenant_id=self._azure_config.tenant_id,
                client_id=self._azure_config.client_id,
                client_secret=self._azure_config.client_secret,
            )
        return DefaultAzureCredential()

    def _require_subscription_id(self) -> str:
        """Subscription id from config or AZURE_SUBSCRIPTION_ID."""
        import os

        subscription = self._azure_config.subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
        if not subscription:
            raise CollectorConfigError(
                "No Azure subscription id — pass AzureCollectorConfig(subscription_id=...) "
                "or set AZURE_SUBSCRIPTION_ID."
            )
        return subscription

    def _call_api(self, operation: str, fetch: Callable[[], Any]) -> Any:
        """Invoke an SDK call with uniform error translation."""
        self._log.debug("azure %s", operation)
        try:
            return fetch()
        except Exception as exc:  # noqa: BLE001 - SDK raises assorted types
            raise self._translate_sdk_error(exc, operation) from exc

    @staticmethod
    def _translate_sdk_error(exc: Exception, operation: str) -> CollectorError:
        """Map azure-core/ARM errors onto the provider-neutral hierarchy."""
        code = getattr(exc, "error_code", None) or getattr(exc, "status_code", None)
        # HttpResponseError carries the AAD/ARM error code in .error.code
        error = getattr(exc, "error", None)
        if error is not None and getattr(error, "code", None):
            code = error.code
        detail = f"Azure API call {operation!r} failed ({code or type(exc).__name__}): {exc}"
        if str(code) in _AZURE_AUTH_ERROR_CODES or isinstance(exc, PermissionError):
            return AuthenticationError(detail)
        if str(code) in _AZURE_THROTTLE_CODES:
            return ThrottlingError(detail + " — retries exhausted")
        return CollectorOperationError(detail)

    # ------------------------------------------------------ BaseCollector API

    def collect_iam_snapshot(self) -> IaMSnapshot:
        """Fetch role assignments + definitions and map them onto the models."""
        authorization = self._get_authorization_client()
        subscription = self._require_subscription_id()
        scope = f"/subscriptions/{subscription}"

        assignments = self._call_api(
            "role_assignments.list_for_scope",
            lambda: list(authorization.role_assignments.list_for_scope(scope)),
        )

        # Distinct role definition ids -> fetch each definition once.
        role_ids = sorted({a.role_definition_id for a in assignments if a.role_definition_id})
        definitions: dict[str, Any] = {}
        for role_id in role_ids:
            short_id = role_id.rsplit("/", 1)[-1]

            def _fetch_role(rid: str = role_id) -> Any:
                return authorization.role_definitions.get_by_id(rid)

            definition = self._call_api(f"role_definitions.get_by_id({short_id})", _fetch_role)
            definitions[role_id] = definition

        snapshot = self._build_iam_snapshot(subscription, assignments, definitions)
        # Remember (kind, display name) pairs so activity-log callers (which
        # carry display names or UPNs, not object ids) fold onto principals.
        self._snapshot_names = (
            [(PrincipalKind.USER, user.name) for user in snapshot.users]
            + [(PrincipalKind.ROLE, role.name) for role in snapshot.roles]
            + [(PrincipalKind.GROUP, group.name) for group in snapshot.groups]
        )
        self._caller_index = None  # rebuilt lazily on first activity record
        self._log.info(
            "Azure snapshot: %d assignments over %d role definitions (%d principals)",
            len(assignments),
            len(definitions),
            len(snapshot.users) + len(snapshot.roles) + len(snapshot.groups),
        )
        return snapshot

    def collect_activity(self, lookback_days: int | None = None) -> ActivityLog:
        """Fetch observed API activity from the Azure Activity Log."""
        monitor = self._get_monitor_client()
        days = lookback_days if lookback_days is not None else self._azure_config.default_lookback_days
        end = self._config.clock()
        start = end - timedelta(days=days)

        # The filter grammar: eventTimestamp ge start and le end.
        time_format = "%Y-%m-%dT%H:%M:%S.%fZ"
        filter_text = (
            f"eventTimestamp ge '{start.strftime(time_format)}' "
            f"and eventTimestamp le '{end.strftime(time_format)}'"
        )
        select = "eventTimestamp,operationName,caller,status,resourceId,eventDataId"

        events: list[ActivityEvent] = []
        truncated = False
        fetched = 0

        def _fetch() -> Any:
            return monitor.activity_logs.list(filter=filter_text, select=select)

        for record in self._call_api("activity_logs.list", _fetch):
            if fetched >= self._azure_config.max_events:
                truncated = True
                break
            parsed = self._parse_activity_record(record)
            if parsed is not None:
                events.append(parsed)
            fetched += 1

        window = ActivityWindow(
            start=start,
            end=end,
            lookback_days=days,
            source="azure:activity_logs",
            truncated=truncated,
        )
        self._log.info(
            "Activity log: %d records, %d parsed, window %s..%s (truncated=%s)",
            fetched,
            len(events),
            start.isoformat(),
            end.isoformat(),
            truncated,
        )
        return ActivityLog(window=window, events=events, usage=summarize_usage(events))

    def _provider_meta(self) -> dict[str, Any]:
        return {
            "account_id": self._require_subscription_id(),
            "region": None,  # Azure RBAC is subscription-global
            "collector_identity_arn": None,
            "subscription_id": self._require_subscription_id(),
        }

    # --------------------------------------------------------- IAM internals

    def _build_iam_snapshot(
        self,
        subscription: str,
        assignments: list[Any],
        definitions: dict[str, Any],
    ) -> IaMSnapshot:
        """Map assignments + definitions onto the neutral IAM models."""
        resolver = self._principal_resolver or StaticPrincipalResolver({})

        users: list[IAMUser] = []
        roles: list[IAMRole] = []
        groups: list[IAMGroup] = []
        policies: dict[str, ManagedPolicy] = {}

        # Role definitions -> managed policy catalog.
        for role_id, definition in definitions.items():
            document = self._role_definition_document(definition)
            name = getattr(definition, "role_name", None) or self._role_name_from_id(role_id)
            kind = (
                PolicyKind.BUILTIN
                if str(getattr(definition, "type", "")).lower() == "builtinrole"
                else PolicyKind.CUSTOM
            )
            policies[role_id] = ManagedPolicy(
                name=name,
                arn=role_id,  # the unified schema's policy key: role definition id
                kind=kind,
                default_version_id=None,
                document=document,
            )

        # Assignments -> principals with attached "policies".
        # (principal_id -> the identity; role_definition_id -> the policy)
        by_principal: dict[str, list[Any]] = {}
        for assignment in assignments:
            principal_id = getattr(assignment, "principal_id", None)
            if principal_id:
                by_principal.setdefault(principal_id, []).append(assignment)

        for principal_id, principal_assignments in sorted(by_principal.items()):
            resolved = resolver.resolve(principal_id) or (principal_id, None)
            display_name: str = str(resolved[0])
            principal_type: str | None = resolved[1]
            principal_kind = _unified_kind(principal_type)

            refs: list[ManagedPolicyRef] = []
            for assignment in principal_assignments:
                assignment_role_id: str | None = getattr(assignment, "role_definition_id", None)
                if assignment_role_id is None:
                    continue
                policy = policies.get(assignment_role_id)
                refs.append(
                    ManagedPolicyRef(
                        name=policy.name if policy else self._role_name_from_id(assignment_role_id),
                        arn=assignment_role_id,
                        kind=policy.kind if policy else PolicyKind.BUILTIN,
                    )
                )

            memberships = self._group_memberships(principal_id) if self._group_memberships else []
            if principal_kind is PrincipalKind.USER:
                users.append(
                    IAMUser(
                        name=display_name,
                        arn=f"azure:object/{principal_id}",
                        created_at=None,
                        groups=memberships,
                        tags={"principalId": principal_id},
                        attached_policies=refs,
                    )
                )
            elif principal_kind is PrincipalKind.GROUP:
                groups.append(
                    IAMGroup(
                        name=display_name,
                        arn=f"azure:object/{principal_id}",
                        created_at=None,
                        inline_policies={},
                        attached_policies=refs,
                    )
                )
            elif principal_kind is PrincipalKind.ROLE:
                # Service principal / managed identity: workload identity.
                sp_type = (
                    "managedIdentity"
                    if self._looks_like_managed_identity(principal_type, display_name)
                    else "servicePrincipal"
                )
                roles.append(
                    IAMRole(
                        name=display_name,
                        arn=f"azure:object/{principal_id}",
                        created_at=None,
                        trust_policy={},  # who may authenticate as this SP (out of scope)
                        tags={"principalId": principal_id, "azurePrincipalType": sp_type},
                        attached_policies=refs,
                    )
                )
            else:
                # Unresolved GUID (deleted object, guest, cross-tenant): keep
                # as a role-shaped workload record so the grant is not lost.
                self._log.warning(
                    "Unresolved Azure principal %s (type=%s) — recorded with GUID name",
                    principal_id,
                    principal_type,
                )
                roles.append(
                    IAMRole(
                        name=principal_id,
                        arn=f"azure:object/{principal_id}",
                        tags={"principalId": principal_id, "azurePrincipalType": "unknown"},
                        attached_policies=refs,
                    )
                )

        # Reverse attachment index (used by the policy catalog view).
        all_principals: list[IAMUser | IAMRole | IAMGroup] = [*users, *roles, *groups]
        for principal in all_principals:
            for ref in principal.attached_policies:
                if ref.arn in policies:
                    policies[ref.arn].attached_to.append(principal.name)

        return IaMSnapshot(
            account_id=subscription,
            collector_identity_arn=f"azure:subscription/{subscription}",
            collected_at=self._config.clock(),
            users=users,
            roles=roles,
            groups=groups,
            policies=policies,
        )

    # -------------------------------------------------------- helpers

    @staticmethod
    def _role_definition_document(definition: Any) -> dict[str, Any] | None:
        """Normalized role-definition document for the unified snapshot.

        The SDK hands permissions back as model objects; the unified document
        keeps a plain-JSON shape consumable by the analyzer and the graph.
        """
        permissions = getattr(definition, "permissions", None) or []
        entries = []
        for permission in permissions:
            if isinstance(permission, dict):
                entries.append(permission)
                continue
            entry: dict[str, Any] = {}
            for key in ("actions", "not_actions", "data_actions", "not_data_actions"):
                value = getattr(permission, key, None)
                if key != "actions":
                    json_key = {
                        "not_actions": "notActions",
                        "data_actions": "dataActions",
                        "not_data_actions": "notDataActions",
                    }[key]
                else:
                    json_key = "actions"
                if value:
                    entry[json_key] = list(value)
            if entry:
                entries.append(entry)
        if not entries:
            return None
        document: dict[str, Any] = {
            "roleName": getattr(definition, "role_name", None) or "",
            "type": getattr(definition, "type", "") or "",
            "permissions": entries,
        }
        description = getattr(definition, "description", None)
        if description:
            document["description"] = description
        return document

    @staticmethod
    def _role_name_from_id(role_id: str) -> str:
        """Best-effort role name from a definition id (GUID tail)."""
        match = _ROLE_DEF_ID_PATTERN.search(role_id or "")
        return match.group(1) if match else role_id

    @staticmethod
    def _looks_like_managed_identity(principal_type: str | None, display_name: str) -> bool:
        """Managed identities surface as service principals with telltale names."""
        if principal_type and "managed" in principal_type.lower():
            return True
        lowered = (display_name or "").lower()
        return lowered.startswith(("mi-", "id-")) or "managedidentity" in lowered.replace(" ", "")

    # ------------------------------------------------------- activity parsing

    def _parse_activity_record(self, record: Any) -> ActivityEvent | None:
        """Normalize one activity-log record into an :class:`ActivityEvent`.

        Records whose operation is not RBAC-governed (e.g. control-plane
        administrative actions without a resource provider) are dropped.
        """
        operation = self._attr(record, "operation_name")
        if not operation or "/" not in operation:
            return None  # sign-in / audit-category noise
        operation = operation.strip().lower()

        caller = (self._attr(record, "caller") or "").strip()
        if not caller:
            return None  # service-internal events

        status = self._attr(record, "status") or {}
        if isinstance(status, dict):
            status_value = str(status.get("value", "")).lower()
        else:
            status_value = str(getattr(status, "value", "") or "").lower()
        is_error = status_value not in {"succeeded", ""}

        timestamp = self._attr(record, "event_timestamp")
        if isinstance(timestamp, datetime):
            when = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)
        elif isinstance(timestamp, str):
            when = _parse_iso_utc(timestamp) or self._config.clock()
        else:
            when = self._config.clock()

        # Fold the caller onto the durable principal: UPN/email -> user,
        # display name -> whatever kind the resolver knows, else GUID/UPN raw.
        principal = self._resolve_caller(caller)
        service = operation.split("/", 1)[0]

        return ActivityEvent(
            event_id=self._attr(record, "event_data_id"),
            time=when,
            principal=principal,
            service=service,
            action=operation,
            event_source=service,
            event_name=operation.rsplit("/", 1)[-1],
            is_error=is_error,
            error_code=str(status.get("value")) if isinstance(status, dict) and status.get("value") else None,
            read_only=operation.endswith("/read"),
        )

    def _resolve_caller(self, caller: str) -> PrincipalRef:
        """Map an activity-log ``caller`` onto a durable principal ref.

        The caller field carries whatever identity Azure recorded: a user
        UPN, a GUID, or (for managed identities) the SP display name. The
        static snapshot's principal map is consulted first so display names
        fold onto the right kind; the injected principal resolver backs this
        up when activity is collected standalone. Unresolved callers stay
        UNKNOWN and surface as unmatched activity.
        """
        subscription = self._azure_config.subscription_id or ""
        if self._caller_index is None:
            # name (lowercase) -> (kind, canonical name), from the snapshot
            index: dict[str, tuple[PrincipalKind, str]] = {}
            for kind, name in self._snapshot_names:
                index[name.lower()] = (kind, name)
            # resolver display names fold in too (kind from principal_type)
            if self._principal_resolver is not None and isinstance(
                self._principal_resolver, StaticPrincipalResolver
            ):
                for _object_id, (name, principal_type) in self._principal_resolver._mapping.items():
                    if name:
                        index.setdefault(name.lower(), (_unified_kind(principal_type), name))
            self._caller_index = index
        resolved = self._caller_index.get(caller.lower())
        if resolved is not None:
            return PrincipalRef(kind=resolved[0], name=resolved[1], arn=None, account_id=subscription)
        if "@" in caller:
            return PrincipalRef(kind=PrincipalKind.USER, name=caller, arn=None, account_id=subscription)
        if re.fullmatch(r"[0-9a-fA-F-]{36}", caller):
            return PrincipalRef(kind=PrincipalKind.UNKNOWN, name=caller, arn=None, account_id=subscription)
        return PrincipalRef(kind=PrincipalKind.UNKNOWN, name=caller, arn=None, account_id=subscription)

    @staticmethod
    def _attr(record: Any, name: str) -> Any:
        """Read an SDK model attribute defensively (model or dict)."""
        if isinstance(record, dict):
            return record.get(name)
        return getattr(record, name, None)


def _parse_iso_utc(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp to aware UTC (Azure sends ``...Z``)."""
    candidate = value.strip()
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
