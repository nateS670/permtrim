"""Shared Azure fixtures: mock SDK clients built from real SDK model classes.

No Azure account is needed. The fake clients return genuine
``azure.mgmt.authorization`` / ``azure.mgmt.monitor`` model instances
(RoleAssignment, RoleDefinition, Permission, EventData, ...), so the
collector's attribute access is exercised exactly as against live SDK
objects — mirroring the botocore Stubber approach of the AWS tests.

Sample story (parallel to the AWS fixtures, Azure-flavored):

* ``zeynep@contoso.com`` (user) — Contributor (``*`` minus
  ``Microsoft.Authorization/*/Write``) + custom BlobReader; only uses
  storage-account reads and blob reads.
* ``deploy-agent`` (service principal) — custom VMManager; idle.
* ``platform-team`` (group) — built-in Reader (``*/read``).
* ``backup-job`` (managed identity) — StorageAccountKeyOperator; every
  ``listkeys`` call is denied (role definition changed under it) — the
  ATTEMPTED-edge scenario.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

from permtrim.collectors.azure_collector import (
    AzureCollector,
    AzureCollectorConfig,
    StaticPrincipalResolver,
)

FIXED_NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
SUBSCRIPTION_ID = "00000000-1111-2222-3333-444444444444"
TENANT = "contoso.com"

WINDOW_START_30D = FIXED_NOW - timedelta(days=30)

# ---------------------------------------------------------------- AAD objects
GUID_ZEYNEP = "aaaaaaaa-0000-0000-0000-000000000001"
GUID_DEPLOY_AGENT = "bbbbbbbb-0000-0000-0000-000000000002"
GUID_PLATFORM_TEAM = "cccccccc-0000-0000-0000-000000000003"
GUID_BACKUP_JOB = "dddddddd-0000-0000-0000-000000000004"

PRINCIPALS: dict[str, tuple[str, str]] = {
    GUID_ZEYNEP: ("zeynep@contoso.com", "User"),
    GUID_DEPLOY_AGENT: ("deploy-agent", "ServicePrincipal"),
    GUID_PLATFORM_TEAM: ("platform-team", "Group"),
    GUID_BACKUP_JOB: ("mi-backup-job", "ServicePrincipal"),
}

# ---------------------------------------------------------------- role defs
GUID_CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"  # real GUID
GUID_READER = "acdd72a7-3385-48f9-8fd7-018f2369c0a4"  # real GUID
GUID_BLOB_READER = "2a2b9908-6ea1-4ae2-b6a1-4a886027ee6c"  # custom (invented GUID, fixture-only)
GUID_VM_MANAGER = "11111111-2222-3333-4444-555555555555"  # custom (invented)
GUID_KEY_OPERATOR = "66666666-7777-8888-9999-000000000000"  # custom (invented)

ROLE_DEF_ID = f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/{{guid}}"

from azure.mgmt.authorization.models import (  # noqa: E402
    Permission,
    RoleAssignment,
    RoleDefinition,
)


def _permission(
    actions: list[str], not_actions: list[str] | None = None, data_actions: list[str] | None = None
) -> Permission:
    return Permission(
        actions=actions,
        not_actions=not_actions or [],
        data_actions=data_actions or [],
        not_data_actions=[],
    )


def _role_definition(guid: str, name: str, kind: str, permissions: list[Permission]) -> RoleDefinition:
    # ``type`` is a readonly attribute on the SDK model: the constructor
    # silently drops it, so it is assigned after construction instead.
    definition = RoleDefinition(
        role_name=name,
        type=kind,
        permissions=permissions,
    )
    definition.type = kind
    return definition


ROLE_DEFINITIONS: dict[str, RoleDefinition] = {
    ROLE_DEF_ID.format(guid=GUID_CONTRIBUTOR): _role_definition(
        GUID_CONTRIBUTOR,
        "Contributor",
        "BuiltInRole",
        [_permission(["*"], ["microsoft.authorization/*/write"])],
    ),
    ROLE_DEF_ID.format(guid=GUID_READER): _role_definition(
        GUID_READER,
        "Reader",
        "BuiltInRole",
        [_permission(["*/read"])],
    ),
    ROLE_DEF_ID.format(guid=GUID_BLOB_READER): _role_definition(
        GUID_BLOB_READER,
        "BlobReader",
        "CustomRole",
        [
            _permission(
                ["microsoft.storage/storageaccounts/read"],
                data_actions=[
                    "microsoft.storage/blob/containers/read",
                    "microsoft.storage/blob/containers/blobs/read",
                ],
            )
        ],
    ),
    ROLE_DEF_ID.format(guid=GUID_VM_MANAGER): _role_definition(
        GUID_VM_MANAGER,
        "VMManager",
        "CustomRole",
        [
            _permission(
                [
                    "microsoft.compute/virtualmachines/read",
                    "microsoft.compute/virtualmachines/start/action",
                    "microsoft.compute/virtualmachines/deallocate/action",
                ]
            )
        ],
    ),
    ROLE_DEF_ID.format(guid=GUID_KEY_OPERATOR): _role_definition(
        GUID_KEY_OPERATOR,
        "StorageAccountKeyOperator",
        "CustomRole",
        [_permission(["microsoft.storage/storageaccounts/listkeys/action"])],
    ),
}

ROLE_ASSIGNMENTS: list[RoleAssignment] = [
    RoleAssignment(
        principal_id=GUID_ZEYNEP,
        role_definition_id=ROLE_DEF_ID.format(guid=GUID_CONTRIBUTOR),
        principal_type="User",
    ),
    RoleAssignment(
        principal_id=GUID_ZEYNEP,
        role_definition_id=ROLE_DEF_ID.format(guid=GUID_BLOB_READER),
        principal_type="User",
    ),
    RoleAssignment(
        principal_id=GUID_DEPLOY_AGENT,
        role_definition_id=ROLE_DEF_ID.format(guid=GUID_VM_MANAGER),
        principal_type="ServicePrincipal",
    ),
    RoleAssignment(
        principal_id=GUID_PLATFORM_TEAM,
        role_definition_id=ROLE_DEF_ID.format(guid=GUID_READER),
        principal_type="Group",
    ),
    RoleAssignment(
        principal_id=GUID_BACKUP_JOB,
        role_definition_id=ROLE_DEF_ID.format(guid=GUID_KEY_OPERATOR),
        principal_type="ServicePrincipal",
    ),
]

# ---------------------------------------------------------------- activity log
from azure.mgmt.monitor.models import EventData  # noqa: E402


def _event(
    caller: str, operation: str, status: str = "Succeeded", when: datetime | None = None, data_id: str = ""
) -> EventData:
    # operation_name / caller / status / event_timestamp are readonly on the
    # SDK model (constructor drops them silently) — assign after construction.
    event = EventData()
    event.operation_name = operation
    event.caller = caller
    event.status = {"value": status, "localizedValue": status}
    event.event_timestamp = when or FIXED_NOW - timedelta(days=3)
    event.event_data_id = data_id or f"evt-{operation}-{caller}-{status}".replace("/", "-").replace("@", "-")
    event.resource_id = ""
    return event


ACTIVITY_EVENTS: list[EventData] = [
    # zeynep reads storage accounts (working usage, twice)
    _event(
        "zeynep@contoso.com", "Microsoft.Storage/storageAccounts/read", when=FIXED_NOW - timedelta(days=5)
    ),
    _event(
        "zeynep@contoso.com", "Microsoft.Storage/storageAccounts/read", when=FIXED_NOW - timedelta(days=4)
    ),
    # zeynep lists blob containers (working data-plane usage)
    _event(
        "zeynep@contoso.com", "Microsoft.Storage/blob/containers/read", when=FIXED_NOW - timedelta(days=4)
    ),
    # zeynep tried to grant a role: denied (Contributor excludes
    # Microsoft.Authorization/*/Write via notActions)
    _event(
        "zeynep@contoso.com",
        "Microsoft.Authorization/roleAssignments/write",
        status="Failed",
        when=FIXED_NOW - timedelta(days=3),
    ),
    # backup-job tries to list keys; every call fails (ATTEMPTED scenario)
    _event(
        "mi-backup-job",
        "Microsoft.Storage/storageAccounts/listKeys/action",
        status="Failed",
        when=FIXED_NOW - timedelta(days=2),
    ),
    # deploy-agent: silent (idle)
    # a sign-in-style record without "/" in operation: must be dropped
    _event("zeynep@contoso.com", "Sign-in", when=FIXED_NOW - timedelta(days=6)),
    # an unknown caller GUID (deleted SP): unmatched activity
    _event(
        "eeeeeeee-0000-0000-0000-000000000005",
        "Microsoft.Resources/subscriptions/read",
        when=FIXED_NOW - timedelta(days=7),
    ),
]


# ---------------------------------------------------------------- fakes


class FakeRoleAssignmentsOperations:
    """Replays ROLE_ASSIGNMENTS for list_for_scope."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def list_for_scope(self, scope: str, **kwargs: Any) -> list[RoleAssignment]:
        self.calls.append(scope)
        return list(ROLE_ASSIGNMENTS)


class FakeRoleDefinitionsOperations:
    """Replays ROLE_DEFINITIONS for get_by_id."""

    def __init__(self) -> None:
        self.requested: list[str] = []

    def get_by_id(self, role_id: str, **kwargs: Any) -> RoleDefinition:
        self.requested.append(role_id)
        try:
            return ROLE_DEFINITIONS[role_id]
        except KeyError:
            raise KeyError(f"role definition not found: {role_id}") from None


class FakeAuthorizationClient:
    def __init__(self) -> None:
        self.role_assignments = FakeRoleAssignmentsOperations()
        self.role_definitions = FakeRoleDefinitionsOperations()


class FakeActivityLogsOperations:
    """Iterates ACTIVITY_EVENTS, asserting the filter shape."""

    def __init__(self) -> None:
        self.filters: list[str] = []
        self.selects: list[str] = []

    def list(self, filter: str, select: str = "", **kwargs: Any) -> Iterator[EventData]:
        self.filters.append(filter)
        self.selects.append(select)
        return iter(list(ACTIVITY_EVENTS))


class FakeMonitorClient:
    def __init__(self) -> None:
        self.activity_logs = FakeActivityLogsOperations()


# ---------------------------------------------------------------- fixtures


def azure_config_fixture() -> AzureCollectorConfig:
    """Construct the standard config (exposed for conftest)."""
    return AzureCollectorConfig(
        subscription_id=SUBSCRIPTION_ID,
        clock=lambda: FIXED_NOW,
        default_lookback_days=30,
    )


def azure_collector_fixture() -> AzureCollector:
    """Construct the collector with mock clients (exposed for conftest)."""
    return AzureCollector(
        azure_config_fixture(),
        authorization_client=FakeAuthorizationClient(),
        monitor_client=FakeMonitorClient(),
        principal_resolver=StaticPrincipalResolverMapping(),
        group_memberships=lambda object_id: ["platform-team"] if object_id == GUID_ZEYNEP else [],
    )


class StaticPrincipalResolverMapping(StaticPrincipalResolver):
    """Dict-backed resolver matching the PRINCIPALS mapping.

    Extends StaticPrincipalResolver so the collector can fold display names
    onto principals when activity is collected standalone (before the IAM
    snapshot ran) — it reads the public mapping through ``_mapping``.
    """

    def __init__(self) -> None:
        super().__init__(PRINCIPALS)
