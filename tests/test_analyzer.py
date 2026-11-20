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
        # data-EVENT grants (per-action classification) have UNKNOWN usage —
        # lookup_events cannot see data events — so they are excluded from
        # the unused count and reported separately instead. Management-event
        # grants (s3:CreateBucket, sns:Subscribe, ...) are analyzed normally.
        unknown = len(alice.unknown_usage_actions)
        assert unknown == sum(1 for g in alice.granted_actions if not g.used and g.data_plane)
        assert unknown > 100  # every documented data event of the '*' grant
        assert alice.unused_count == alice.granted_count - 1 - unknown
        assert "s3:getobject" not in alice.unknown_usage_actions  # used ones stay used
        # explicit uncertainty: the subset the classification table could not
        # place; it must be a subset of the unknown-usage set (never of the
        # unused set)
        assert alice.unclassified_actions
        assert set(alice.unclassified_actions) <= set(alice.unknown_usage_actions)
        # the over-inclusion fix on the real sample: management s3 actions
        # are removable, data events are not
        unused_names = {g.action for g in alice.unused_actions}
        assert "s3:createbucket" in unused_names
        assert "s3:getobject" not in unused_names
        assert "s3:getobject" in set(alice.used_actions)

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


class TestDataPlaneClassification:
    """P1-AWS: data-plane classification is per ACTION, not per service.

    CloudTrail data events are invisible to lookup_events, management events
    are not — so within one service (S3: GetObject vs CreateBucket) the two
    categories must separate. Documented data events and documented
    management events each come from the transcribed tables; an action of a
    mixed service that is in NEITHER table classifies as "unclassified" and
    defaults to the conservative side (data-plane: unknown usage, surfaced on
    the finding, never silently removable).
    """

    def test_is_data_plane_helper_aws(self):
        from permtrim.analyzer.engine import is_data_plane_action

        # documented data events
        assert is_data_plane_action("s3:getobject", provider="aws") is True
        assert is_data_plane_action("s3:listbucket", provider="aws") is True  # ListObjects APIs
        assert is_data_plane_action("lambda:invokefunction", provider="aws") is True
        assert is_data_plane_action("dynamodb:getitem", provider="aws") is True
        assert is_data_plane_action("sns:publish", provider="aws") is True  # was the P1 gap
        assert is_data_plane_action("sns:publishbatch", provider="aws") is True
        assert is_data_plane_action("sqs:sendmessage", provider="aws") is True
        assert is_data_plane_action("ebs:getsnapshotblock", provider="aws") is True
        # documented management events — no manual-review noise for these
        assert is_data_plane_action("s3:createbucket", provider="aws") is False
        assert is_data_plane_action("sns:subscribe", provider="aws") is False
        assert is_data_plane_action("sqs:createqueue", provider="aws") is False
        assert is_data_plane_action("dynamodb:createtable", provider="aws") is False
        assert is_data_plane_action("qldb:executestatement", provider="aws") is False
        assert is_data_plane_action("ec2:runinstances", provider="aws") is False
        assert is_data_plane_action("iam:createuser", provider="aws") is False

    def test_classify_returns_three_states(self):
        from permtrim.analyzer.engine import classify_aws_data_plane

        assert classify_aws_data_plane("s3:getobject") == "data"
        assert classify_aws_data_plane("s3:CreateBucket".lower()) == "management"
        assert classify_aws_data_plane("s3-object-lambda:getobjectversion") == "unclassified"
        assert classify_aws_data_plane("s3:getdataaccess") == "unclassified"
        # services outside the data-event set have no data events at all
        assert classify_aws_data_plane("ec2:runinstances") == "management"
        # P0-A: a service the bundled dataset does not know is NEVER
        # management — its data-plane usage would be invisible to
        # lookup_events, so classification fails closed to unclassified
        assert classify_aws_data_plane("brandnewservice:getwidget") == "unclassified"

    def test_unclassified_action_defaults_conservative(self):
        """An action of a mixed service missing from both tables must never
        be droppable as unused: it is data-plane for the tightener AND
        explicitly surfaced as unclassified."""
        from permtrim.analyzer.engine import is_data_plane_action, is_unclassified_aws_action

        for action in ("s3:getdataaccess", "s3-object-lambda:getobjectversion"):
            assert is_unclassified_aws_action(action) is True
            assert is_data_plane_action(action, provider="aws") is True

    def test_unknown_service_is_unclassified_fail_closed(self):
        """P0-A: a brand-new AWS service (or a typo'd prefix) the bundled
        dataset does not know must never classify as management — the
        classifier cannot verify it contributes no data events, and an
        unused-looking grant of it may simply have invisible data-plane
        usage. Fail closed: unclassified."""
        from permtrim.analyzer.engine import (
            classify_aws_data_plane,
            is_data_plane_action,
            is_unclassified_aws_action,
        )

        for action in ("brandnewservice:getwidget", "brandnewservice:*", "typoservice:listthingies"):
            assert classify_aws_data_plane(action) == "unclassified"
            assert is_unclassified_aws_action(action) is True
            assert is_data_plane_action(action, provider="aws") is True

    def test_unknown_service_classification_with_custom_registry(self):
        """The fail-closed default consults the registry: with a registry
        that DOES know the service (and the data-event table not listing
        it), the action is verified management again — the check is
        "positively known to contribute no data events", not a hardcoded
        service list."""
        from permtrim.analyzer.action_registry import ActionRegistry
        from permtrim.analyzer.engine import classify_aws_data_plane

        custom = ActionRegistry(
            {
                "brandnew": {
                    "prefix": "brandnew",
                    "privileges": {"getwidget": {"privilege": "GetWidget", "access_level": "Read"}},
                }
            }
        )
        assert custom.service_exists("brandnew") is True
        assert classify_aws_data_plane("brandnew:getwidget", registry=custom) == "management"
        # the default (bundled) registry does not know it -> fail closed
        assert classify_aws_data_plane("brandnew:getwidget") == "unclassified"

    def test_unknown_service_grant_is_unknown_usage_not_unused(self):
        """P0-A end to end: a principal granted actions of a service the
        dataset does not know, with no observed usage, gets them reported
        as unknown usage + unclassified — never as removable unused, so the
        tightener stops instead of silently stripping them."""
        from datetime import datetime, timezone

        from permtrim.analyzer.engine import Analyzer
        from permtrim.models.activity import ActivityLog, ActivityWindow, UsageSummary
        from permtrim.models.iam import IaMSnapshot, IAMUser

        now = datetime.now(timezone.utc)
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    # the literal action AND a wildcard the registry cannot
                    # expand (kept verbatim by the scanner) — both paths
                    "Action": ["brandnewservice:getwidget", "brandnewservice:*"],
                    "Resource": "*",
                }
            ],
        }
        iam = IaMSnapshot(
            account_id="1",
            collector_identity_arn="arn",
            collected_at=now,
            users=[IAMUser(name="u", arn="arn:u", inline_policies={"brandnew": doc})],
            roles=[],
            groups=[],
            policies={},
        )
        activity = ActivityLog(
            window=ActivityWindow(start=now, end=now, lookback_days=30),
            events=[],
            usage={("user", "u"): UsageSummary(action_counts={})},
        )
        report = Analyzer().analyze(iam, activity)
        finding = next(f for f in report.findings if f.name == "u")
        assert finding.unused_count == 0
        assert finding.unused_actions == []
        assert finding.unknown_usage_actions == ["brandnewservice:*", "brandnewservice:getwidget"]
        assert finding.unclassified_actions == ["brandnewservice:*", "brandnewservice:getwidget"]
        granted = {g.action: g for g in finding.granted_actions}
        assert granted["brandnewservice:getwidget"].data_plane is True
        assert granted["brandnewservice:*"].data_plane is True

    def test_is_data_plane_helper_azure_is_noop(self):
        """On Azure the matcher carries the flag from dataActions; the helper
        is not consulted there."""
        from permtrim.analyzer.engine import is_data_plane_action

        assert is_data_plane_action("microsoft.storage/blob/containers/read", provider="azure") is False

    def test_known_data_plane_unused_goes_to_unknown_not_unused(self):
        """An s3 grant with no observed usage -> unknown_usage_actions, NOT
        unused_actions, and NOT counted in unused_count."""
        from datetime import datetime, timezone

        from permtrim.analyzer.engine import Analyzer
        from permtrim.models.activity import ActivityLog, ActivityWindow, UsageSummary
        from permtrim.models.iam import IaMSnapshot, IAMUser

        now = datetime.now(timezone.utc)
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:getobject"], "Resource": "*"}],
        }
        iam = IaMSnapshot(
            account_id="1",
            collector_identity_arn="arn",
            collected_at=now,
            users=[IAMUser(name="u", arn="arn:u", inline_policies={"s3only": doc})],
            roles=[],
            groups=[],
            policies={},
        )
        activity = ActivityLog(
            window=ActivityWindow(start=now, end=now, lookback_days=30),
            events=[],
            usage={("user", "u"): UsageSummary(action_counts={})},
        )
        report = Analyzer().analyze(iam, activity)
        finding = next(f for f in report.findings if f.name == "u")
        assert finding.unknown_usage_actions == ["s3:getobject"]
        assert finding.unused_count == 0
        assert finding.used_actions == []
        # the granted action carries the data_plane flag the analyzer set
        granted = {g.action: g for g in finding.granted_actions}
        assert granted["s3:getobject"].data_plane is True

    def test_management_grant_unused_is_removed_not_unknown(self):
        """The over-inclusion fix: s3:CreateBucket is a MANAGEMENT event —
        visible to lookup_events — so an unused grant of it is confirmed
        excess (unused_actions), not manual-review noise."""
        from datetime import datetime, timezone

        from permtrim.analyzer.engine import Analyzer
        from permtrim.models.activity import ActivityLog, ActivityWindow, UsageSummary
        from permtrim.models.iam import IaMSnapshot, IAMUser

        now = datetime.now(timezone.utc)
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:CreateBucket"], "Resource": "*"}],
        }
        iam = IaMSnapshot(
            account_id="1",
            collector_identity_arn="arn",
            collected_at=now,
            users=[IAMUser(name="u", arn="arn:u", inline_policies={"s3bucket": doc})],
            roles=[],
            groups=[],
            policies={},
        )
        activity = ActivityLog(
            window=ActivityWindow(start=now, end=now, lookback_days=30),
            events=[],
            usage={("user", "u"): UsageSummary(action_counts={})},
        )
        report = Analyzer().analyze(iam, activity)
        finding = next(f for f in report.findings if f.name == "u")
        assert finding.unknown_usage_actions == []
        assert finding.unclassified_actions == []
        assert finding.unused_count == 1

    def test_unlisted_service_is_management(self):
        """Services that contribute NO CloudTrail data events (per the
        resource-type table) classify every action as management — as long
        as the bundled dataset positively knows the service. That is the
        P0-A fail-closed rule: ``management`` (the removable side) requires
        verification (dataset knows the service + it is absent from the
        data-event table); an unknown service is unclassified instead, and
        a NEW data-event service AWS introduces later must be added to
        ``_AWS_DATA_EVENT_SERVICES`` (see README) — until then its actions
        classify as unclassified, never as silently-removable management."""
        from permtrim.analyzer.action_registry import load_default_registry
        from permtrim.analyzer.engine import _AWS_DATA_EVENT_SERVICES, classify_aws_data_plane

        assert "secretsmanager" not in _AWS_DATA_EVENT_SERVICES
        assert "glue" not in _AWS_DATA_EVENT_SERVICES
        assert "qldb" not in _AWS_DATA_EVENT_SERVICES  # no data events at all
        registry = load_default_registry()
        # the positive-verification side of the rule: known services not in
        # the data-event table are verified management
        assert registry.service_exists("secretsmanager")
        assert registry.service_exists("glue")
        assert classify_aws_data_plane("secretsmanager:getsecretvalue") == "management"
        assert classify_aws_data_plane("glue:getjob") == "management"
