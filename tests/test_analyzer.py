"""Tests for the analyzer (Task 2): registry, matcher, engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from permtrim.analyzer import (
    Analyzer,
    PolicySet,
    Statement,
    load_default_registry,
)

SAMPLE = Path(__file__).resolve().parent.parent / "src" / "permtrim" / "data" / "sample_snapshot.json"


@pytest.fixture(scope="module")
def registry():
    return load_default_registry()


# ------------------------------------------------------------------ registry


class TestActionRegistry:
    def test_dataset_is_bundled_and_sized(self, registry):
        assert registry.service_count > 400
        assert registry.action_count > 20000

    def test_action_existence_case_insensitive(self, registry):
        assert registry.action_exists("s3:GetObject")
        assert registry.action_exists("S3:GETOBJECT")

    def test_unknown_action_does_not_exist(self, registry):
        assert not registry.action_exists("s3:GetObjekt")  # classic LLM hallucination
        assert not registry.action_exists("ec2:RunInstance")  # singular hallucination
        assert not registry.action_exists("not-a-service:Something")

    def test_wildcard_expansion(self, registry):
        assert "s3:getobject" in registry.expand("s3:Get*")
        assert registry.count_matching("s3:Get*") > 10
        ec2_all = registry.expand("ec2:*")
        assert len(ec2_all) > 500
        assert all(action.startswith("ec2:") for action in ec2_all)

    def test_normalize_maps_event_name_exceptions(self, registry):
        # CloudTrail logs the ListBuckets event, IAM authorizes ListAllMyBuckets
        assert registry.normalize("s3:ListBuckets") == "s3:listallmybuckets"
        assert registry.normalize("s3:GetObject") == "s3:getobject"

    def test_normalize_drops_non_iam_actions(self, registry):
        assert registry.normalize("signin:ConsoleLogin") is None
        assert registry.normalize("no-prefix") is None

    def test_access_levels(self, registry):
        assert registry.access_level("iam:CreateUser") == "Permissions management"
        assert registry.access_level("s3:GetObject") == "Read"

    def test_canonical_casing(self, registry):
        assert registry.canonical("s3:getobject") == "s3:GetObject"
        assert registry.canonical("s3:getobjekt") is None


# ------------------------------------------------------------------- matcher


class TestMatcher:
    def test_wildcard_matching(self):
        statement = Statement(
            effect="allow", actions=("s3:get*",), not_actions=(), resources=("*",), source="t"
        )
        assert statement.matches("s3:getobject")
        assert statement.matches("s3:getbucketpolicy")
        assert not statement.matches("s3:putobject")
        assert not statement.matches("ec2:getinstance")

    def test_single_char_wildcard(self):
        statement = Statement(
            effect="allow", actions=("ec2:describeinstance?",), not_actions=(), resources=("*",), source="t"
        )
        assert statement.matches("ec2:describeinstances")
        assert not statement.matches("ec2:describeinstancestatus")

    def test_not_action_inverts(self):
        statement = Statement(
            effect="allow", actions=(), not_actions=("iam:*",), resources=("*",), source="t"
        )
        assert statement.matches("s3:getobject")
        assert not statement.matches("iam:createuser")

    def test_explicit_deny_wins(self):
        policy_set = PolicySet()
        policy_set.add_policy_document(
            {
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"},
                    {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
                ]
            },
            "test",
        )
        allowed, _ = policy_set.evaluate("s3:getobject")
        assert allowed
        allowed, _ = policy_set.evaluate("iam:createuser")
        assert not allowed


# -------------------------------------------------------------------- engine


@pytest.fixture(scope="module")
def sample_report():
    return Analyzer().analyze_document(json.loads(SAMPLE.read_text(encoding="utf-8")))


class TestAnalyzerOnSample:
    """The bundled sample snapshot: alice has AdministratorAccess + inline
    s3:Get* and only uses s3:GetObject; deploy-ci has no identity policies."""

    def test_alice_grant_expansion(self, sample_report):
        alice = next(f for f in sample_report.findings if f.name == "alice")
        # AdministratorAccess '*' grants every action in the dataset (20455);
        # inline s3:Get* and the group's EC2 policies are subsets of it.
        assert alice.granted_count == 20455
        assert alice.used_actions == ["s3:getobject"]
        assert alice.unused_count == alice.granted_count - 1

    def test_alice_wildcards_reported(self, sample_report):
        alice = next(f for f in sample_report.findings if f.name == "alice")
        patterns = {w["pattern"] for w in alice.wildcard_sources}
        assert "*" in patterns
        assert "ec2:describe*" in patterns  # from the devs group EC2-Read policy

    def test_alice_risk_scored(self, sample_report):
        alice = next(f for f in sample_report.findings if f.name == "alice")
        assert alice.risk_score > 0
        assert any("unused" in reason for reason in alice.risk_reasons)

    def test_deploy_ci_no_identity_policies(self, sample_report):
        ci = next(f for f in sample_report.findings if f.name == "deploy-ci")
        assert ci.granted_count == 0
        assert ci.risk_reasons == ["no_identity_policies"]

    def test_report_is_json_serializable(self, sample_report):
        payload = json.dumps(sample_report.to_dict())
        assert '"principals_analyzed"' in payload


class TestAnalyzerGroupInheritance:
    def test_group_policies_fold_into_user(self):
        from datetime import datetime, timezone

        from permtrim.analyzer.engine import Analyzer
        from permtrim.models.activity import (
            ActivityLog,
            ActivityWindow,
            UsageSummary,
        )
        from permtrim.models.iam import (
            IAMGroup,
            IaMSnapshot,
            IAMUser,
            ManagedPolicy,
            ManagedPolicyRef,
            PolicyKind,
        )

        now = datetime.now(timezone.utc)
        ec2_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["ec2:Describe*"], "Resource": "*"}],
        }
        policy_arn = "arn:aws:iam::111122223333:policy/EC2-Read"
        iam = IaMSnapshot(
            account_id="111122223333",
            collector_identity_arn="arn:test",
            collected_at=now,
            users=[
                IAMUser(
                    name="bob",
                    arn="arn:u",
                    groups=["ops"],
                    attached_policies=[ManagedPolicyRef("EC2-Read", policy_arn, PolicyKind.CUSTOMER_MANAGED)],
                )
            ],
            roles=[],
            groups=[
                IAMGroup(
                    name="ops",
                    arn="arn:g",
                    attached_policies=[ManagedPolicyRef("EC2-Read", policy_arn, PolicyKind.CUSTOMER_MANAGED)],
                )
            ],
            policies={
                policy_arn: ManagedPolicy("EC2-Read", policy_arn, PolicyKind.CUSTOMER_MANAGED, "v1", ec2_doc)
            },
        )
        usage = UsageSummary(action_counts={"ec2:DescribeInstances": 3})
        activity = ActivityLog(
            window=ActivityWindow(start=now, end=now, lookback_days=30),
            events=[],
            usage={("user", "bob"): usage},
        )
        report = Analyzer().analyze(iam, activity)
        bob = report.findings[0]
        assert bob.granted_count > 100  # ec2:Describe* expanded
        assert bob.used_actions == ["ec2:describeinstances"]
        assert "ec2:describeinstances" not in [g.action for g in bob.unused_actions]


class TestErrorOnlyUsage:
    def test_error_only_actions_are_not_working_usage(self):
        from datetime import datetime, timezone

        from permtrim.analyzer.engine import Analyzer
        from permtrim.models.activity import (
            ActivityLog,
            ActivityWindow,
            UsageSummary,
        )
        from permtrim.models.iam import IaMSnapshot, IAMUser

        now = datetime.now(timezone.utc)
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["ec2:*"], "Resource": "*"}],
        }
        iam = IaMSnapshot(
            account_id="1",
            collector_identity_arn="arn",
            collected_at=now,
            users=[IAMUser(name="u", arn="arn:u", inline_policies={"broad": doc})],
            roles=[],
            groups=[],
            policies={},
        )
        # every observed RunInstances call failed -> not working usage
        usage = UsageSummary(
            action_counts={"ec2:RunInstances": 2}, error_action_counts={"ec2:RunInstances": 2}
        )
        activity = ActivityLog(
            window=ActivityWindow(start=now, end=now, lookback_days=30),
            events=[],
            usage={("user", "u"): usage},
        )
        report = Analyzer().analyze(iam, activity)
        finding = next(f for f in report.findings if f.name == "u")
        assert finding.used_actions == []
        granted = {g.action: g for g in finding.granted_actions}
        assert granted["ec2:runinstances"].error_only is True
