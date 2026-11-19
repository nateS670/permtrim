"""Unit tests for the AWS collector (Task 1), using botocore Stubber.

No AWS account is needed: every boto3 call is replayed from canned
responses, and the frozen clock in ``conftest.FIXED_NOW`` makes the
CloudTrail lookup window deterministic.
"""

from __future__ import annotations

import json

import pytest

from conftest import (
    ACCOUNT_ID,
    ADMIN_DOC,
    ADMIN_DOC_STRING,
    EC2_READ_DOC,
    FIXED_NOW,
    INLINE_S3_EXTRA,
    RAW_EVENTS,
    TRUST_DOC,
    WINDOW_END,
    WINDOW_START_30D,
    stub_client,
)
from permtrim.collectors.aws_collector import (
    CLOUDTRAIL_MAX_LOOKBACK_DAYS,
    AWSCollector,
    AWSCollectorConfig,
    _coerce_policy_document,
    _service_from_event_source,
)
from permtrim.errors import AuthenticationError, CollectorConfigError
from permtrim.models.iam import PolicyKind

# --------------------------------------------------------------------- IAM


def test_iam_snapshot_maps_all_permission_sources(collector, stubbed_iam):
    """Static snapshot: inline policies, attachments, boundaries, tags, trust."""
    collector._client_cache["iam"] = stubbed_iam[0]
    collector._client_cache["sts"] = stubbed_iam[2]

    snapshot = collector.collect_iam_snapshot()

    assert snapshot.account_id == ACCOUNT_ID
    assert snapshot.collected_at == FIXED_NOW
    assert snapshot.collector_identity_arn.endswith("permtrim-runner")

    (alice,) = snapshot.users
    assert alice.name == "alice"
    assert alice.groups == ["devs"]
    assert alice.inline_policies == {"s3-extra": INLINE_S3_EXTRA}
    assert alice.permission_boundary_arn.endswith("boundary-poc")
    assert alice.tags == {"team": "platform"}
    assert alice.attached_policies[0].kind is PolicyKind.AWS_MANAGED

    (deploy_ci,) = snapshot.roles
    assert deploy_ci.trust_policy == TRUST_DOC
    assert deploy_ci.max_session_duration is None  # not part of authorization details

    (devs,) = snapshot.groups
    assert devs.attached_policies[0].kind is PolicyKind.CUSTOMER_MANAGED


def test_policy_catalog_resolves_documents_and_reverse_attachments(collector, stubbed_iam):
    """AWS-managed documents are fetched on demand; attached_to is cross-referenced."""
    collector._client_cache["iam"] = stubbed_iam[0]
    collector._client_cache["sts"] = stubbed_iam[2]

    snapshot = collector.collect_iam_snapshot()

    admin = snapshot.policies["arn:aws:iam::aws:policy/AdministratorAccess"]
    assert admin.document == ADMIN_DOC  # parsed from the JSON-string form
    assert admin.attached_to == ["alice"]

    ec2_read = snapshot.policies[f"arn:aws:iam::{ACCOUNT_ID}:policy/EC2-Read"]
    assert ec2_read.document == EC2_READ_DOC  # default version, not v0
    assert ec2_read.attached_to == ["devs"]


def test_aws_managed_fetch_failure_degrades_instead_of_raising(collector, aws_config):
    """A failed get_policy leaves the attachment recorded with document=None."""
    iam_client, iam_stubber = stub_client("iam")
    sts_client, sts_stubber = stub_client("sts")
    from conftest import GET_CALLER_IDENTITY, auth_details_payload

    sts_stubber.add_response("get_caller_identity", GET_CALLER_IDENTITY, expected_params={})
    iam_stubber.add_response("get_account_authorization_details", auth_details_payload(), expected_params={})
    iam_stubber.add_client_error(
        "get_policy",
        service_error_code="AccessDenied",
        http_status_code=403,
    )
    sts_stubber.activate()
    iam_stubber.activate()
    collector._client_cache["iam"] = iam_client
    collector._client_cache["sts"] = sts_client

    snapshot = collector.collect_iam_snapshot()

    admin = snapshot.policies["arn:aws:iam::aws:policy/AdministratorAccess"]
    assert admin.document is None
    assert admin.fetch_error is not None
    assert admin.attached_to == ["alice"]  # attachment still recorded


# ---------------------------------------------------------------- activity


def test_activity_events_are_normalized_per_principal(collector, stubbed_cloudtrail):
    """Events become (principal, service:action); errors counted separately."""
    collector._client_cache["cloudtrail"] = stubbed_cloudtrail[0]

    log = collector.collect_activity(30)

    assert log.window.start == WINDOW_START_30D
    assert log.window.end == WINDOW_END
    assert log.window.lookback_days == 30
    assert log.window.truncated is False

    assert len(log.events) == 4  # the AwsServiceEvent entry is filtered out

    alice = log.usage[("user", "alice")]
    assert alice.action_counts == {"s3:GetObject": 2}
    assert alice.error_event_count == 0
    assert alice.first_seen is not None and alice.last_seen is not None

    ci = log.usage[("role", "deploy-ci")]  # assumed-role session folded onto the role
    assert ci.action_counts == {"ec2:RunInstances": 1}
    assert ci.error_action_counts == {"ec2:RunInstances": 1}
    (ci_event,) = [e for e in log.events if e.action == "ec2:RunInstances"]
    assert ci_event.is_error is True
    assert ci_event.error_code == "Client.UnauthorizedOperation"
    assert ci_event.principal.session == "gh-actions"
    assert ci_event.principal.arn.endswith("role/deploy-ci")

    root = log.usage[("root", "root")]
    assert root.action_counts == {"iam:CreateUser": 1}


def test_activity_window_rejects_over_90_days(collector):
    """lookup_events cannot look back further than 90 days."""
    with pytest.raises(CollectorConfigError, match="90"):
        collector.collect_activity(CLOUDTRAIL_MAX_LOOKBACK_DAYS + 1)


def test_activity_truncation_flag_when_cap_is_hit(aws_config):
    """max_events cuts the scan and marks the window as truncated."""
    small = AWSCollectorConfig(
        region=aws_config.region,
        clock=aws_config.clock,
        default_lookback_days=30,
        max_events=1,
        lookup_page_size=50,
    )
    small_collector = AWSCollector(small)
    ct_client, ct_stubber = stub_client("cloudtrail")
    ct_stubber.add_response(
        "lookup_events",
        {"Events": RAW_EVENTS},
        expected_params={"StartTime": WINDOW_START_30D, "EndTime": WINDOW_END, "MaxResults": 50},
    )
    ct_stubber.activate()
    small_collector._client_cache["cloudtrail"] = ct_client

    log = small_collector.collect_activity(30)

    assert log.window.truncated is True
    assert len(log.events) == 1


# ------------------------------------------------------------------ unified


def test_collect_returns_merged_unified_document(collector, stubbed_iam, stubbed_cloudtrail):
    """End-to-end: static IAM + dynamic activity merged per principal."""
    collector._client_cache["iam"] = stubbed_iam[0]
    collector._client_cache["sts"] = stubbed_iam[2]
    collector._client_cache["cloudtrail"] = stubbed_cloudtrail[0]

    document = collector.collect(lookback_days=30)

    assert document["meta"]["schema_version"] == "1.0"
    assert document["meta"]["provider"] == "aws"
    assert document["meta"]["account_id"] == ACCOUNT_ID
    assert document["meta"]["region"] == "eu-west-1"
    assert document["meta"]["lookback_days"] == 30

    principals = {p["kind"] + ":" + p["name"]: p for p in document["principals"]}
    alice = principals["user:alice"]
    assert alice["permission_sources"]["inline_policies"] == {"s3-extra": INLINE_S3_EXTRA}
    assert alice["permission_sources"]["via_groups"] == ["devs"]
    (admin_ref,) = alice["permission_sources"]["attached_managed_policies"]
    assert admin_ref["document"] == ADMIN_DOC
    assert admin_ref["document_status"] == "available"
    assert alice["observed_activity"]["action_counts"] == {"s3:GetObject": 2}

    ci = principals["role:deploy-ci"]
    assert ci["observed_activity"]["error_action_counts"] == {"ec2:RunInstances": 1}

    group = principals["group:devs"]
    assert group["permission_sources"]["members"] == ["alice"]

    # root has no IAM entity -> reported under unmatched_activity
    unmatched = {entry["kind"] + ":" + entry["name"] for entry in document["unmatched_activity"]}
    assert unmatched == {"root:root"}

    # the whole document must be JSON-serializable (datetimes already ISO strings)
    payload = json.dumps(document)
    assert '"schema_version": "1.0"' in payload


def test_unified_document_json_round_trip_via_write(collector, stubbed_iam, stubbed_cloudtrail, tmp_path):
    """write_json_document produces a file that parses back cleanly."""
    from permtrim.collectors import write_json_document

    collector._client_cache["iam"] = stubbed_iam[0]
    collector._client_cache["sts"] = stubbed_iam[2]
    collector._client_cache["cloudtrail"] = stubbed_cloudtrail[0]

    document = collector.collect()
    target = write_json_document(document, tmp_path / "snapshots" / "aws.json")

    reloaded = json.loads(target.read_text(encoding="utf-8"))
    assert reloaded["meta"]["provider"] == "aws"
    assert not target.with_suffix(".json.tmp").exists()


# -------------------------------------------------------------------- errors


def test_auth_failure_is_translated(collector):
    """ClientError AuthFailure surfaces as AuthenticationError."""
    sts_client, sts_stubber = stub_client("sts")
    sts_stubber.add_client_error(
        "get_caller_identity",
        service_error_code="AuthFailure",
        http_status_code=401,
    )
    sts_stubber.activate()
    collector._client_cache["sts"] = sts_client

    with pytest.raises(AuthenticationError, match="get_caller_identity"):
        collector.collect()


def test_config_validation_ranges():
    """Out-of-range config values fail fast with actionable messages."""
    with pytest.raises(CollectorConfigError, match="default_lookback_days"):
        AWSCollectorConfig(default_lookback_days=120)
    with pytest.raises(CollectorConfigError, match="lookup_page_size"):
        AWSCollectorConfig(lookup_page_size=500)
    with pytest.raises(CollectorConfigError, match="max_events"):
        AWSCollectorConfig(max_events=0)


# -------------------------------------------------------------------- units


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("s3.amazonaws.com", "s3"),
        ("ec2.amazonaws.com", "ec2"),
        ("signin.amazonaws.com", "signin"),
        ("s3.amazonaws.com.cn", "s3"),
    ],
)
def test_service_name_mapping(source, expected):
    assert _service_from_event_source(source) == expected


def test_coerce_policy_document_accepts_all_shapes():
    context = "unit-test"
    assert _coerce_policy_document({"Version": "2012-10-17"}, context) == {"Version": "2012-10-17"}
    assert _coerce_policy_document(ADMIN_DOC_STRING, context) == ADMIN_DOC
    assert _coerce_policy_document("%7B%22Version%22%3A%20%222012-10-17%22%7D", context) == {
        "Version": "2012-10-17"
    }
    assert _coerce_policy_document(None, context) is None
    assert _coerce_policy_document("not-json", context) is None
