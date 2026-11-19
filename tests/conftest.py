"""Shared fixtures: deterministic clock, stubbed boto3 clients, sample payloads."""

from __future__ import annotations

import copy
import json
import urllib.parse
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from botocore.stub import Stubber

from permtrim.collectors.aws_collector import AWSCollector, AWSCollectorConfig

FIXED_NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
ACCOUNT_ID = "111122223333"

# The collector computes: end = now - 15min, start = end - days.
WINDOW_END = FIXED_NOW - timedelta(minutes=15)
WINDOW_START_30D = WINDOW_END - timedelta(days=30)

REGION = "eu-west-1"

TRUST_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

INLINE_S3_EXTRA = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::corp-data/*"}],
}

EC2_READ_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["ec2:Describe*", "ec2:Get*"], "Resource": "*"}],
}

ADMIN_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
# get_policy_version hands documents back as a (possibly URL-encoded) JSON string.
ADMIN_DOC_STRING = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
)


def _wire(doc: dict) -> str:
    """Policy/trust documents on the wire: URL-encoded JSON strings."""
    return urllib.parse.quote(json.dumps(doc))


# Same wire shape as the real get_account_authorization_details response:
# *PolicyList keys, URL-encoded documents, required ID fields.
AUTH_DETAILS = {
    "UserDetailList": [
        {
            "Path": "/",
            "UserName": "alice",
            "UserId": "AIDAEXAMPLEALICE",
            "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/alice",
            "CreateDate": datetime(2024, 3, 1, tzinfo=timezone.utc),
            "GroupList": ["devs"],
            "AttachedManagedPolicies": [
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                },
            ],
            "UserPolicyList": [{"PolicyName": "s3-extra", "PolicyDocument": _wire(INLINE_S3_EXTRA)}],
            "PermissionsBoundary": {
                "PermissionsBoundaryType": "Policy",
                "PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT_ID}:policy/boundary-poc",
            },
            "Tags": [{"Key": "team", "Value": "platform"}],
        }
    ],
    "GroupDetailList": [
        {
            "Path": "/",
            "GroupName": "devs",
            "GroupId": "AGIAPLATFORMEXAMPLE",
            "Arn": f"arn:aws:iam::{ACCOUNT_ID}:group/devs",
            "CreateDate": datetime(2024, 3, 2, tzinfo=timezone.utc),
            "GroupPolicyList": [],
            "AttachedManagedPolicies": [
                {"PolicyName": "EC2-Read", "PolicyArn": f"arn:aws:iam::{ACCOUNT_ID}:policy/EC2-Read"},
            ],
        }
    ],
    "RoleDetailList": [
        {
            "Path": "/",
            "RoleName": "deploy-ci",
            "RoleId": "AROAEXAMPLEDEPLOY",
            "Arn": f"arn:aws:iam::{ACCOUNT_ID}:role/deploy-ci",
            "CreateDate": datetime(2024, 5, 10, tzinfo=timezone.utc),
            "AssumeRolePolicyDocument": _wire(TRUST_DOC),
            "RolePolicyList": [],
            "AttachedManagedPolicies": [],
            "RoleLastUsed": {},
            "Tags": [],
        }
    ],
    "Policies": [
        {
            "PolicyName": "EC2-Read",
            "PolicyId": "ANPAEXAMPLEEC2READ",
            "Arn": f"arn:aws:iam::{ACCOUNT_ID}:policy/EC2-Read",
            "Path": "/",
            "DefaultVersionId": "v1",
            "PolicyVersionList": [
                {"VersionId": "v1", "IsDefaultVersion": True, "Document": _wire(EC2_READ_DOC)},
                {
                    "VersionId": "v0",
                    "IsDefaultVersion": False,
                    "Document": _wire({"Version": "2012-10-17", "Statement": []}),
                },
            ],
            "IsAttachable": True,
        }
    ],
    "IsTruncated": False,
}


def auth_details_payload() -> dict:
    """Fresh deep copy of AUTH_DETAILS for each stubbed response.

    botocore's IAM handler decodes URL-encoded policy documents in place
    (handlers.decode_quoted_jsondoc), and Stubber stores responses by
    reference — a shared dict would be silently turned into decoded dicts
    after the first call and fail schema validation for later tests.
    """
    return copy.deepcopy(AUTH_DETAILS)


GET_CALLER_IDENTITY = {
    "Account": ACCOUNT_ID,
    "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/permtrim-runner",
    "UserId": "AIDARUNNEREXAMPLE",
}


def _cloud_trail_payload(identity_block: dict, **overrides: str) -> str:
    """Build the embedded CloudTrailEvent JSON string for a raw lookup entry."""
    import json

    payload = {
        "eventVersion": "1.09",
        "userIdentity": identity_block,
        "eventTime": overrides.get("event_time", "2026-11-05T10:00:00Z"),
        "eventSource": overrides.get("event_source", "s3.amazonaws.com"),
        "eventName": overrides.get("event_name", "GetObject"),
        "eventType": overrides.get("event_type", "AwsApiCall"),
    }
    if "error_code" in overrides:
        payload["errorCode"] = overrides["error_code"]
        payload["errorMessage"] = "The requested operation is not authorized."
    return json.dumps(payload)


ALICE_IDENTITY = {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLEALICE",
    "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/alice",
    "accountId": ACCOUNT_ID,
    "userName": "alice",
}

DEPLOY_CI_IDENTITY = {
    "type": "AssumedRole",
    "principalId": "AROAEXAMPLE:gh-actions",
    "arn": f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/deploy-ci/gh-actions",
    "accountId": ACCOUNT_ID,
    "sessionContext": {
        "sessionIssuer": {
            "type": "Role",
            "principalId": "AROAEXAMPLE",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/deploy-ci",
            "userName": "deploy-ci",
        }
    },
}

ROOT_IDENTITY = {
    "type": "Root",
    "principalId": ACCOUNT_ID,
    "arn": f"arn:aws:iam::{ACCOUNT_ID}:root",
    "accountId": ACCOUNT_ID,
}

RAW_EVENTS = [
    {  # alice reads an object twice (two successful calls)
        "EventId": "evt-alice-1",
        "EventName": "GetObject",
        "EventSource": "s3.amazonaws.com",
        "EventTime": datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc),
        "Username": "alice",
        "ReadOnly": "true",
        "CloudTrailEvent": _cloud_trail_payload(ALICE_IDENTITY),
    },
    {
        "EventId": "evt-alice-2",
        "EventName": "GetObject",
        "EventSource": "s3.amazonaws.com",
        "EventTime": datetime(2026, 11, 6, 11, 30, tzinfo=timezone.utc),
        "Username": "alice",
        "ReadOnly": "true",
        "CloudTrailEvent": _cloud_trail_payload(ALICE_IDENTITY, event_time="2026-11-06T11:30:00Z"),
    },
    {  # CI role tries to launch an instance without permission -> denied call
        "EventId": "evt-ci-1",
        "EventName": "RunInstances",
        "EventSource": "ec2.amazonaws.com",
        "EventTime": datetime(2026, 11, 6, 9, 30, tzinfo=timezone.utc),
        "Username": "gh-actions",
        "ReadOnly": "false",
        "CloudTrailEvent": _cloud_trail_payload(
            DEPLOY_CI_IDENTITY,
            event_time="2026-11-06T09:30:00Z",
            event_source="ec2.amazonaws.com",
            event_name="RunInstances",
            error_code="Client.UnauthorizedOperation",
        ),
    },
    {  # root performed a management action (no IAM entity -> unmatched)
        "EventId": "evt-root-1",
        "EventName": "CreateUser",
        "EventSource": "iam.amazonaws.com",
        "EventTime": datetime(2026, 11, 7, 8, 0, tzinfo=timezone.utc),
        "Username": "root",
        "ReadOnly": "false",
        "CloudTrailEvent": _cloud_trail_payload(
            ROOT_IDENTITY,
            event_time="2026-11-07T08:00:00Z",
            event_source="iam.amazonaws.com",
            event_name="CreateUser",
        ),
    },
    {  # service event: not a principal action, must be filtered out
        "EventId": "evt-svc-1",
        "EventName": "TestServiceEvent",
        "EventSource": "cloudtrail.amazonaws.com",
        "EventTime": datetime(2026, 11, 8, 6, 0, tzinfo=timezone.utc),
        "Username": "",
        "ReadOnly": "false",
        "CloudTrailEvent": _cloud_trail_payload(
            ROOT_IDENTITY,
            event_time="2026-11-08T06:00:00Z",
            event_source="cloudtrail.amazonaws.com",
            event_name="TestServiceEvent",
            event_type="AwsServiceEvent",
        ),
    },
]


def stub_client(service: str) -> tuple[object, Stubber]:
    """Create a real boto3 client paired with a Stubber (dummy credentials)."""
    client = boto3.Session(region_name=REGION).client(
        service,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )
    return client, Stubber(client)


@pytest.fixture
def aws_config() -> AWSCollectorConfig:
    """Config with a frozen clock for deterministic lookup windows."""
    return AWSCollectorConfig(
        region=REGION,
        clock=lambda: FIXED_NOW,
        default_lookback_days=30,
        max_events=200,
        lookup_page_size=50,
    )


@pytest.fixture
def collector(aws_config: AWSCollectorConfig) -> AWSCollector:
    """Collector instance without any stubbed API wired in yet."""
    return AWSCollector(aws_config)


@pytest.fixture
def stubbed_iam():
    """IAM + STS clients stubbed with a happy-path authorization snapshot."""
    iam_client, iam_stubber = stub_client("iam")
    sts_client, sts_stubber = stub_client("sts")

    sts_stubber.add_response(
        "get_caller_identity",
        GET_CALLER_IDENTITY,
        expected_params={},
    )
    iam_stubber.add_response(
        "get_account_authorization_details",
        auth_details_payload(),
        expected_params={},
    )
    iam_stubber.add_response(
        "get_policy",
        {
            "Policy": {
                "PolicyName": "AdministratorAccess",
                "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "DefaultVersionId": "v1",
            }
        },
        expected_params={"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    )
    iam_stubber.add_response(
        "get_policy_version",
        {"PolicyVersion": {"Document": ADMIN_DOC_STRING, "VersionId": "v1", "IsDefaultVersion": True}},
        expected_params={"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "VersionId": "v1"},
    )

    sts_stubber.activate()
    iam_stubber.activate()
    yield iam_client, iam_stubber, sts_client, sts_stubber
    sts_stubber.deactivate()
    iam_stubber.deactivate()


@pytest.fixture
def stubbed_cloudtrail():
    """CloudTrail client stubbed with the RAW_EVENTS page (single page, no NextToken)."""
    ct_client, ct_stubber = stub_client("cloudtrail")
    ct_stubber.add_response(
        "lookup_events",
        {"Events": RAW_EVENTS},
        expected_params={"StartTime": WINDOW_START_30D, "EndTime": WINDOW_END, "MaxResults": 50},
    )
    ct_stubber.activate()
    yield ct_client, ct_stubber
    ct_stubber.deactivate()


# ------------------------------------------------------------------ Azure (Task 5)
# Mock SDK fixtures: real azure-mgmt model instances, zero accounts.

from azure_fixtures import (  # noqa: E402
    GUID_ZEYNEP,
    FakeAuthorizationClient,
    FakeMonitorClient,
    StaticPrincipalResolverMapping,
)
from azure_fixtures import (  # noqa: E402 - appended Azure section
    SUBSCRIPTION_ID as AZURE_SUBSCRIPTION_ID,
)
from permtrim.collectors.azure_collector import (  # noqa: E402
    AzureCollector,
    AzureCollectorConfig,
)


@pytest.fixture
def azure_config() -> AzureCollectorConfig:
    """Config with a frozen clock, pointed at the mock subscription."""
    from azure_fixtures import FIXED_NOW as AZURE_FIXED_NOW

    return AzureCollectorConfig(
        subscription_id=AZURE_SUBSCRIPTION_ID,
        clock=lambda: AZURE_FIXED_NOW,
        default_lookback_days=30,
    )


@pytest.fixture
def azure_collector(azure_config: AzureCollectorConfig) -> AzureCollector:
    """Collector with mock SDK clients + static principal resolver wired in.

    zeynep is a transitive member of platform-team — the Azure analogue of
    alice's devs-group membership in the AWS fixtures.
    """
    return AzureCollector(
        azure_config,
        authorization_client=FakeAuthorizationClient(),
        monitor_client=FakeMonitorClient(),
        principal_resolver=StaticPrincipalResolverMapping(),
        group_memberships=lambda object_id: ["platform-team"] if object_id == GUID_ZEYNEP else [],
    )
