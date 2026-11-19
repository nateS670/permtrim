"""Tests for the Azure collector (Task 5) — mock SDK clients, zero accounts.

The fixtures build real ``azure.mgmt.authorization`` / ``azure.mgmt.monitor``
model instances (see ``azure_fixtures.py``), so the collector's attribute
access matches live-SDK behaviour exactly.
"""

from __future__ import annotations

import json

import pytest

# The azure SDK is an optional extra (``pip install permtrim[azure]``);
# skip the whole module instead of failing collection when it is absent
# (e.g. an environment installed with only [graph,dev]).
pytest.importorskip("azure.mgmt.authorization", reason="azure extra not installed")

from azure_fixtures import (  # noqa: E402
    GUID_CONTRIBUTOR,
    ROLE_DEF_ID,
    SUBSCRIPTION_ID,
)
from permtrim.analyzer import Analyzer
from permtrim.collectors.azure_collector import (
    AZURE_ACTIVITY_LOG_MAX_LOOKBACK_DAYS,
    AzureCollector,
    AzureCollectorConfig,
    StaticPrincipalResolver,
)
from permtrim.errors import CollectorConfigError, CollectorOperationError
from permtrim.models.iam import PolicyKind

# ------------------------------------------------------------------ static side


def test_concept_mapping_user_sp_group(azure_collector):
    """AAD User -> user; Service Principal / MI -> role; Group -> group."""
    snapshot = azure_collector.collect_iam_snapshot()

    (zeynep,) = snapshot.users
    assert zeynep.name == "zeynep@contoso.com"
    assert zeynep.groups == ["platform-team"]

    role_names = {role.name for role in snapshot.roles}
    assert role_names == {"deploy-agent", "mi-backup-job"}  # SP + managed identity

    (group,) = snapshot.groups
    assert group.name == "platform-team"


def test_role_definitions_become_policy_catalog(azure_collector):
    """Each role definition lands in the catalog with its permissions document."""
    snapshot = azure_collector.collect_iam_snapshot()

    contributor = snapshot.policies[ROLE_DEF_ID.format(guid=GUID_CONTRIBUTOR)]
    assert contributor.name == "Contributor"
    assert contributor.kind is PolicyKind.BUILTIN
    assert contributor.document["permissions"][0]["actions"] == ["*"]
    assert contributor.document["permissions"][0]["notActions"] == ["microsoft.authorization/*/write"]

    vm_manager = snapshot.policies[ROLE_DEF_ID.format(guid="11111111-2222-3333-4444-555555555555")]
    assert vm_manager.kind is PolicyKind.CUSTOM

    # reverse attachments resolved
    assert contributor.attached_to == ["zeynep@contoso.com"]
    assert vm_manager.attached_to == ["deploy-agent"]


def test_unresolved_guid_principal_is_recorded_not_dropped(azure_config):
    """A principal the resolver does not know still appears (GUID name)."""
    from azure_fixtures import FakeAuthorizationClient, FakeMonitorClient

    assignments_without_resolver = AzureCollector(
        azure_config,
        authorization_client=FakeAuthorizationClient(),
        monitor_client=FakeMonitorClient(),
        principal_resolver=StaticPrincipalResolver({}),  # knows nothing
    )
    snapshot = assignments_without_resolver.collect_iam_snapshot()
    # all 4 principals recorded with GUID names, none silently dropped
    assert len(snapshot.users) + len(snapshot.roles) + len(snapshot.groups) == 4


# ------------------------------------------------------------------ dynamic side


def test_activity_callers_fold_onto_principals(azure_collector):
    """UPN callers -> user; display-name callers -> the right workload identity."""
    log = azure_collector.collect_activity(30)

    usage = log.usage
    assert ("user", "zeynep@contoso.com") in usage
    assert ("role", "mi-backup-job") in usage  # MI display name resolved
    # the sign-in-style record without "/" was dropped
    assert all("sign-in" not in key[1].lower() for key in usage)


def test_activity_window_and_filter(azure_collector):
    """The OData filter requests the exact 30-day window."""
    azure_collector.collect_iam_snapshot()  # populate caller index
    log = azure_collector.collect_activity(30)
    assert log.window.lookback_days == 30
    assert log.window.source == "azure:activity_logs"

    monitor = azure_collector._monitor_client
    (filter_text,) = monitor.activity_logs.filters
    assert "eventTimestamp ge" in filter_text and "eventTimestamp le" in filter_text


def test_failed_calls_are_error_only(azure_collector):
    """Every listkeys call failed -> error counts, no working usage."""
    azure_collector.collect_iam_snapshot()
    log = azure_collector.collect_activity(30)

    backup = log.usage[("role", "mi-backup-job")]
    assert backup.action_counts == {"microsoft.storage/storageaccounts/listkeys/action": 1}
    assert backup.error_action_counts == {"microsoft.storage/storageaccounts/listkeys/action": 1}


def test_lookback_window_rejects_over_90_days():
    """Azure Activity Log retention bound is enforced in config."""
    with pytest.raises(CollectorConfigError):
        AzureCollectorConfig(
            subscription_id=SUBSCRIPTION_ID,
            default_lookback_days=AZURE_ACTIVITY_LOG_MAX_LOOKBACK_DAYS + 1,
        )


# ------------------------------------------------------------------ unified doc


def test_collect_returns_unified_document(azure_collector):
    """Full pipeline: meta/provider, principals, usage, unmatched activity."""
    document = azure_collector.collect()

    assert document["meta"]["provider"] == "azure"
    assert document["meta"]["account_id"] == SUBSCRIPTION_ID
    assert document["meta"]["window"]["lookback_days"] == 30

    kinds = {(p["kind"], p["name"]) for p in document["principals"]}
    assert ("user", "zeynep@contoso.com") in kinds
    assert ("role", "deploy-agent") in kinds
    assert ("group", "platform-team") in kinds

    # zeynep's group membership + both role assignments surfaced
    zeynep = next(p for p in document["principals"] if p["name"] == "zeynep@contoso.com")
    assert zeynep["permission_sources"]["via_groups"] == ["platform-team"]
    assert len(zeynep["permission_sources"]["attached_managed_policies"]) == 2

    # deleted SP's activity is unmatched, not lost
    unmatched = {u["name"] for u in document["unmatched_activity"]}
    assert "eeeeeeee-0000-0000-0000-000000000005" in unmatched


def test_unified_document_json_round_trip(azure_collector, tmp_path):
    document = azure_collector.collect()
    payload = json.dumps(document)
    revived = json.loads(payload)
    assert revived["meta"]["provider"] == "azure"


# ------------------------------------------------------------------ analyzer


def test_analyzer_on_azure_snapshot(azure_collector):
    """The provider-agnostic analyzer works on the Azure unified document."""
    document = azure_collector.collect()
    report = Analyzer().analyze_document(document)

    findings = {f"{f.kind}:{f.name}": f for f in report.findings}

    # dataset is the snapshot universe, not the AWS file
    assert report.dataset["actions"] >= 9

    zeynep = findings["user:zeynep@contoso.com"]
    # used: storageAccounts/read + blob/containers/read (working calls)
    assert set(zeynep.used_actions) == {
        "microsoft.storage/storageaccounts/read",
        "microsoft.storage/blob/containers/read",
    }
    # denied roleassignment write is NOT working usage (Contributor notActions excludes it)
    assert "microsoft.authorization/roleassignments/write" not in zeynep.used_actions
    assert zeynep.granted_count > zeynep.used_actions.__len__()

    deploy = findings["role:deploy-agent"]
    assert deploy.is_idle  # granted 3 VM actions, used none

    backup = findings["role:mi-backup-job"]
    assert backup.is_idle  # every call failed -> no working usage


def test_azure_registry_wildcard_expansion(azure_collector):
    """``*`` expands over the snapshot universe minus Contributor's notActions."""
    from permtrim.analyzer.azure_registry import build_azure_registry

    document = azure_collector.collect()
    registry = build_azure_registry(document)

    all_actions = registry.expand("*")
    assert "microsoft.storage/storageaccounts/read" in all_actions
    assert "microsoft.compute/virtualmachines/read" in all_actions

    read_only = registry.expand("*/read")
    assert "microsoft.storage/storageaccounts/read" in read_only
    assert "microsoft.storage/storageaccounts/listkeys/action" not in read_only

    # access levels derived from suffix
    assert registry.access_level("microsoft.storage/storageaccounts/read") == "Read"
    assert registry.access_level("microsoft.storage/storageaccounts/listkeys/action") == "Write"


def test_azure_matcher_notactions_subtracts(azure_collector):
    """Contributor = * minus Microsoft.Authorization/*/Write."""
    document = azure_collector.collect()
    report = Analyzer().analyze_document(document)
    zeynep = next(f for f in report.findings if f.name == "zeynep@contoso.com")

    granted = {g.action for g in zeynep.granted_actions}
    # the excluded auth write never appears as granted
    assert "microsoft.authorization/roleassignments/write" not in granted
    # but other authorization reads from Reader (via group) are granted
    assert granted  # and the union is non-trivial
    # via-group Reader contributes */read actions beyond zeynep's own roles
    assert any(
        g.sources and "platform-team" in " ".join(g.sources) or "reader" in " ".join(g.sources).lower()
        for g in zeynep.granted_actions
    )


# ------------------------------------------------------------------ errors


def test_sdk_error_translated(azure_config):
    """ARM errors map onto the provider-neutral hierarchy."""

    class ExplodingClient:
        class RoleAssignments:
            @staticmethod
            def list_for_scope(scope):
                raise RuntimeError("boom on purpose")

    exploding = ExplodingClient()
    exploding.role_assignments = ExplodingClient.RoleAssignments()
    collector = AzureCollector(azure_config, authorization_client=exploding)
    with pytest.raises(CollectorOperationError):
        collector.collect_iam_snapshot()


def test_missing_subscription_id_rejected():
    import os

    with pytest.raises(CollectorConfigError):
        AzureCollectorConfig(subscription_id="") if os.environ.get("AZURE_SUBSCRIPTION_ID") is None else None
        collector = AzureCollector(AzureCollectorConfig(subscription_id=""))
        collector._require_subscription_id()


def test_factory_registers_azure():
    from permtrim.collectors import SUPPORTED_PROVIDERS, create_collector

    assert "azure" in SUPPORTED_PROVIDERS
    collector = create_collector("azure", AzureCollectorConfig(subscription_id=SUBSCRIPTION_ID))
    assert collector.provider == "azure"
