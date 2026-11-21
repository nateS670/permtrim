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
        """The fail-closed rule does not soften for a custom registry: the
        check is "verified by the CloudTrail data-event tables", not "known
        to the IAM catalog". A registry that DOES know the service still
        yields unclassified unless the transcribed tables verify it."""
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
        # catalog presence is NOT event-visibility evidence (the AppConfig
        # lesson: appconfig sat in the catalog while its data events were
        # invisible to lookup_events)
        assert classify_aws_data_plane("brandnew:getwidget", registry=custom) == "unclassified"
        # the default (bundled) registry does not know it either -> fail closed
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
        """``management`` — the removable side — requires positive
        verification: the service's IAM prefix must appear in NO row of the
        CloudTrail data-event resource-type table
        (``_AWS_MANAGEMENT_ONLY_SERVICES``). Secrets Manager and QLDB pass
        that bar; Glue does NOT (AWS::Glue::Table is a data-event row), so
        its actions are unclassified rather than management — the AppConfig
        lesson applied table-wide."""
        from permtrim.analyzer.engine import (
            _AWS_DATA_EVENT_SERVICES,
            _AWS_MANAGEMENT_ONLY_SERVICES,
            classify_aws_data_plane,
        )

        assert "secretsmanager" not in _AWS_DATA_EVENT_SERVICES
        assert "secretsmanager" in _AWS_MANAGEMENT_ONLY_SERVICES
        assert "qldb" in _AWS_MANAGEMENT_ONLY_SERVICES  # no data events at all
        assert "glue" in _AWS_DATA_EVENT_SERVICES  # AWS::Glue::Table row
        # the positive-verification side of the rule: services absent from
        # every data-event row are verified management
        assert classify_aws_data_plane("secretsmanager:getsecretvalue") == "management"
        assert classify_aws_data_plane("qldb:executestatement") == "management"
        # Glue contributes data events but has no transcribed action table
        # yet: every glue action stays unclassified (safe side)
        assert classify_aws_data_plane("glue:getjob") == "unclassified"

    def test_appconfig_data_events(self):
        """P0-A regression: AWS AppConfig has had CloudTrail DATA events
        since 2024-01 (GetLatestConfiguration, StartConfigurationSession —
        invisible to lookup_events) while every other appconfig action is
        control plane. Before the fix, appconfig was 'known to the IAM
        catalog but absent from the data-event service list', so its
        retrieval grants classified as management and could be silently
        removed."""
        from permtrim.analyzer.engine import classify_aws_data_plane, is_data_plane_action

        assert classify_aws_data_plane("appconfig:getlatestconfiguration") == "data"
        assert classify_aws_data_plane("appconfig:startconfigurationsession") == "data"
        assert is_data_plane_action("appconfig:getlatestconfiguration", provider="aws") is True
        assert is_data_plane_action("appconfig:startconfigurationsession", provider="aws") is True
        # the closed-set control plane: no manual-review noise
        assert classify_aws_data_plane("appconfig:getconfiguration") == "management"
        assert classify_aws_data_plane("appconfig:createapplication") == "management"
        assert classify_aws_data_plane("appconfig:startdeployment") == "management"

    def test_swf_data_events(self):
        """Amazon SWF logs workflow/task/decision activity as DATA events
        (AWS::SWF::Domain, since 2024-02) and its control plane (domain,
        activity-type, workflow-type, tag operations) as management
        events. Both tables are transcribed; together they cover the
        bundled swf service completely."""
        from permtrim.analyzer.engine import classify_aws_data_plane

        for action in (
            "swf:pollfordecisiontask",
            "swf:pollforactivitytask",
            "swf:startworkflowexecution",
            "swf:responddecisiontaskcompleted",
            "swf:signalworkflowexecution",
            "swf:recordmarker",
            "swf:starttimer",
        ):
            assert classify_aws_data_plane(action) == "data", action
        for action in (
            "swf:registerdomain",
            "swf:describeworkflowtype",
            "swf:listactivitytypes",
            "swf:tagresource",
        ):
            assert classify_aws_data_plane(action) == "management", action

    def test_data_api_services_are_data_events(self):
        """The RDS Data API (AWS::RDS::DBCluster), the Redshift Data API
        (AWS::Redshift::Cluster) and CloudTrail partner ingestion
        (AWS::CloudTrail::Channel) are DATA events — data-plane SQL/audit
        activity invisible to lookup_events by default."""
        from permtrim.analyzer.engine import classify_aws_data_plane

        assert classify_aws_data_plane("rds-data:executestatement") == "data"
        assert classify_aws_data_plane("rds-data:batchexecutestatement") == "data"
        assert classify_aws_data_plane("redshift-data:executestatement") == "data"
        assert classify_aws_data_plane("redshift-data:getstatementresult") == "data"
        assert classify_aws_data_plane("cloudtrail-data:putauditevents") == "data"

    def test_data_event_service_without_action_table_is_unclassified(self):
        """Services whose data events exist but whose per-action split is
        not transcribed yet (Glue, SageMaker, Timestream, ...) classify
        every action as unclassified — never as silently-removable
        management. This is the fail-closed default for the 97-service
        data-event table."""
        from permtrim.analyzer.engine import classify_aws_data_plane

        for action in (
            "glue:gettable",
            "sagemaker:invokeendpoint",
            "timestream:select",
            "kinesis:putrecord",
            "states:startexecution",
        ):
            assert classify_aws_data_plane(action) == "unclassified", action

    def test_greengrass_is_data_event_service(self):
        """P0 regression (Greengrass): the CloudTrail data-event table lists
        AWS::GreengrassV2::ComponentVersion and AWS::GreengrassV2::Deployment,
        and IoT Greengrass V2's IAM prefix is plain ``greengrass`` — the two
        ROW_MAP rows must map to it, never to None. Before the fix the
        service sat in _AWS_MANAGEMENT_ONLY_SERVICES (the None comment
        wrongly claimed the prefix was missing from the dataset), so
        greengrass:GetComponentVersionArtifact — a data event invisible to
        lookup_events — could be flagged as unused and auto-removed."""
        from permtrim.analyzer.engine import (
            _AWS_DATA_EVENT_SERVICES,
            _AWS_MANAGEMENT_ONLY_SERVICES,
        )

        assert "greengrass" in _AWS_DATA_EVENT_SERVICES
        assert "greengrass" not in _AWS_MANAGEMENT_ONLY_SERVICES

    def test_greengrass_actions_are_not_management(self):
        """The Greengrass data-event mapping is service-level only: no
        per-action table is transcribed, so every greengrass action stays
        unclassified (the safe side) instead of management. The artifact
        download call of a core device is the canonical LookupEvents-blind
        case: it must never look unused/removable."""
        from permtrim.analyzer.engine import classify_aws_data_plane

        assert classify_aws_data_plane("greengrass:GetComponentVersionArtifact") == "unclassified"
        for action in (
            "greengrass:GetDeployment",
            "greengrass:GetCoreDevice",
            "greengrass:CreateDeployment",
            "greengrass:GetConnectivityInfo",
        ):
            assert classify_aws_data_plane(action) == "unclassified", action

    def test_bedrock_mantle_is_data_event_service(self):
        """P0 regression (Bedrock Mantle): AWS::BedrockMantle::Project is a
        row of the CloudTrail data-event table and the dataset has the
        ``bedrock-mantle`` IAM prefix, so the ROW_MAP row must map to it,
        never to None. Before the fix the None row left the prefix in
        _AWS_MANAGEMENT_ONLY_SERVICES, so bedrock-mantle:CreateInference —
        a data event invisible to lookup_events — classified as management
        and could be flagged as unused and auto-removed."""
        from permtrim.analyzer.engine import (
            _AWS_DATA_EVENT_SERVICES,
            _AWS_MANAGEMENT_ONLY_SERVICES,
        )

        assert "bedrock-mantle" in _AWS_DATA_EVENT_SERVICES
        assert "bedrock-mantle" not in _AWS_MANAGEMENT_ONLY_SERVICES

    def test_bedrock_mantle_action_level_classification(self):
        """The per-action CloudTrail split is transcribed for bedrock-mantle
        (bedrock user guide, 'Monitor bedrock-mantle API calls'): 9
        inference/file operations are data events, 11 model/fine-tuning/
        project operations are management events. The IAM-only extras
        (customized model, reservation, retention, tagging, bearer token)
        have no documented category, so they stay unclassified — inventory
        presence alone never proves management."""
        from permtrim.analyzer.engine import classify_aws_data_plane

        for action in (
            "bedrock-mantle:CreateInference",
            "bedrock-mantle:GetInference",
            "bedrock-mantle:CancelInference",
            "bedrock-mantle:DeleteInference",
            "bedrock-mantle:CountTokens",
            "bedrock-mantle:ListFiles",
            "bedrock-mantle:CreateFile",
            "bedrock-mantle:GetFile",
            "bedrock-mantle:DeleteFile",
        ):
            assert classify_aws_data_plane(action) == "data", action
        for action in (
            "bedrock-mantle:ListModels",
            "bedrock-mantle:GetModel",
            "bedrock-mantle:CreateFineTuningJob",
            "bedrock-mantle:CreateProject",
            "bedrock-mantle:ArchiveProject",
        ):
            assert classify_aws_data_plane(action) == "management", action
        for action in (
            "bedrock-mantle:CreateReservation",
            "bedrock-mantle:CreateCustomizedModel",
            "bedrock-mantle:TagResource",
            "bedrock-mantle:CallWithBearerToken",
        ):
            assert classify_aws_data_plane(action) == "unclassified", action

    def test_health_agent_is_data_event_service(self):
        """P0 regression (Amazon Connect Health / HealthAgent): the doc
        table lists five AWS::HealthAgent::* data-event rows and the dataset
        has the ``health-agent`` prefix; the five None rows used to leave
        the service in _AWS_MANAGEMENT_ONLY_SERVICES, so
        health-agent:CreateSubscription classified as management and could
        be flagged as unused and auto-removed."""
        from permtrim.analyzer.engine import (
            _AWS_DATA_EVENT_SERVICES,
            _AWS_MANAGEMENT_ONLY_SERVICES,
        )

        assert "health-agent" in _AWS_DATA_EVENT_SERVICES
        assert "health-agent" not in _AWS_MANAGEMENT_ONLY_SERVICES

    def test_health_agent_create_subscription_is_management(self):
        """Amazon Connect Health's CloudTrail example shows CreateSubscription
        with ``eventCategory: Management`` / ``managementEvent: true`` even
        though AWS::HealthAgent::Subscription is a data-event resource type —
        the resource type alone does not classify the action. Only
        CreateSubscription is documented so far: the rest of the transcribed
        inventory (and anything AWS adds later) stays unclassified, never
        management."""
        from permtrim.analyzer.engine import classify_aws_data_plane

        assert classify_aws_data_plane("health-agent:CreateSubscription") == "management"
        for action in (
            "health-agent:GetDomainAnalytics",
            "health-agent:StartMedicalCodingJob",
            "health-agent:CreateDomain",
            "health-agent:ActivateSubscription",
        ):
            assert classify_aws_data_plane(action) == "unclassified", action
        # a brand-new action AWS has not documented yet
        assert classify_aws_data_plane("health-agent:BrandNewFutureAction") == "unclassified"

    def test_nova_act_is_data_event_service(self):
        """P0 regression (Nova Act): AWS::NovaAct::WorkflowDefinition and
        AWS::NovaAct::WorkflowRun are doc-table data-event rows and the
        dataset has the ``nova-act`` prefix; the two None rows used to leave
        the service in _AWS_MANAGEMENT_ONLY_SERVICES, so nova-act:CreateAct
        classified as management and could be flagged as unused and
        auto-removed."""
        from permtrim.analyzer.engine import (
            _AWS_DATA_EVENT_SERVICES,
            _AWS_MANAGEMENT_ONLY_SERVICES,
        )

        assert "nova-act" in _AWS_DATA_EVENT_SERVICES
        assert "nova-act" not in _AWS_MANAGEMENT_ONLY_SERVICES

    def test_nova_act_action_level_classification(self):
        """Nova Act's CloudTrail page splits the service: CreateSession,
        CreateAct, UpdateAct, InvokeActStep are data events; nine
        workflow-definition/run/list operations are management events. The
        IAM reference adds CreateWorkflowRun, DeleteWorkflowRun and
        UpdateWorkflowRun with NO CloudTrail category — they stay
        unclassified instead of being guessed into the removable side."""
        from permtrim.analyzer.engine import classify_aws_data_plane

        for action in (
            "nova-act:CreateSession",
            "nova-act:CreateAct",
            "nova-act:UpdateAct",
            "nova-act:InvokeActStep",
        ):
            assert classify_aws_data_plane(action) == "data", action
        for action in (
            "nova-act:CreateWorkflowDefinition",
            "nova-act:GetWorkflowRun",
            "nova-act:ListWorkflowRuns",
            "nova-act:DeleteWorkflowDefinition",
        ):
            assert classify_aws_data_plane(action) == "management", action
        for action in (
            "nova-act:CreateWorkflowRun",
            "nova-act:DeleteWorkflowRun",
            "nova-act:UpdateWorkflowRun",
        ):
            assert classify_aws_data_plane(action) == "unclassified", action

    def test_engine_tables_match_generated_artifact(self):
        """CI gap fix: engine.py embeds the five service tables the build
        script emits into scripts/engine_tables.generated.py, and until now
        nothing verified the two stay identical — a hand-edit of either
        side could drift silently. CI runs scripts/build_engine_tables.py
        --check against the committed artifact; this test pins the engine
        copy to that same artifact."""
        import importlib.util

        import permtrim.analyzer.engine as engine

        path = Path(__file__).resolve().parents[1] / "scripts" / "engine_tables.generated.py"
        assert path.exists()
        spec = importlib.util.spec_from_file_location("engine_tables_generated", path)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert engine._AWS_DATA_EVENT_SERVICES == mod._AWS_DATA_EVENT_SERVICES
        assert engine._AWS_MANAGEMENT_ONLY_SERVICES == mod._AWS_MANAGEMENT_ONLY_SERVICES
        assert engine._AWS_ACTION_LEVEL_SERVICES == mod._AWS_ACTION_LEVEL_SERVICES
        assert engine._AWS_ACTION_LEVEL_CLASSIFICATIONS == mod._AWS_ACTION_LEVEL_CLASSIFICATIONS
        assert engine._AWS_SERVICE_ACTIONS == mod._AWS_SERVICE_ACTIONS

    def test_action_level_data_grant_without_usage_is_unknown_usage(self):
        """End-to-end safety property: a granted, DOCUMENTED data-event
        action (bedrock-mantle:CreateInference — invisible to lookup_events)
        with zero usage records must land in unknown_usage_actions, never in
        unused. Before the action-level layer it classified as unclassified
        (still safe); before the service-level fix it was 'management' and
        removable."""
        from datetime import datetime, timezone

        from permtrim.analyzer.engine import Analyzer
        from permtrim.models.activity import ActivityLog, ActivityWindow, UsageSummary
        from permtrim.models.iam import IaMSnapshot, IAMUser

        now = datetime.now(timezone.utc)
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["bedrock-mantle:CreateInference"], "Resource": "*"}],
        }
        iam = IaMSnapshot(
            account_id="1",
            collector_identity_arn="arn",
            collected_at=now,
            users=[IAMUser(name="u", arn="arn:u", inline_policies={"mantle": doc})],
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
        assert finding.unknown_usage_actions == ["bedrock-mantle:createinference"]
        assert finding.unused_count == 0
        granted = {g.action: g for g in finding.granted_actions}
        assert granted["bedrock-mantle:createinference"].data_plane is True

    def test_action_level_management_grant_unused_is_removed(self):
        """The flip side of the feature: health-agent:CreateSubscription is a
        documented management event (Connect Health's own CloudTrail
        example) — visible to lookup_events — so an unused grant of it is
        confirmed excess (unused_count 1), not manual-review noise."""
        from datetime import datetime, timezone

        from permtrim.analyzer.engine import Analyzer
        from permtrim.models.activity import ActivityLog, ActivityWindow, UsageSummary
        from permtrim.models.iam import IaMSnapshot, IAMUser

        now = datetime.now(timezone.utc)
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["health-agent:CreateSubscription"], "Resource": "*"}
            ],
        }
        iam = IaMSnapshot(
            account_id="1",
            collector_identity_arn="arn",
            collected_at=now,
            users=[IAMUser(name="u", arn="arn:u", inline_policies={"health": doc})],
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

    def test_action_level_unclassified_grant_is_protected(self):
        """nova-act:CreateWorkflowRun exists in the IAM reference but no
        CloudTrail doc puts it in a category — it must stay unknown-usage /
        unclassified (never unused), the fail-closed default."""
        from datetime import datetime, timezone

        from permtrim.analyzer.engine import Analyzer
        from permtrim.models.activity import ActivityLog, ActivityWindow, UsageSummary
        from permtrim.models.iam import IaMSnapshot, IAMUser

        now = datetime.now(timezone.utc)
        doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["nova-act:CreateWorkflowRun"], "Resource": "*"}],
        }
        iam = IaMSnapshot(
            account_id="1",
            collector_identity_arn="arn",
            collected_at=now,
            users=[IAMUser(name="u", arn="arn:u", inline_policies={"nova": doc})],
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
        assert finding.unclassified_actions == ["nova-act:createworkflowrun"]
        granted = {g.action: g for g in finding.granted_actions}
        assert granted["nova-act:createworkflowrun"].data_plane is True

    def test_action_level_tsvs_are_consistent(self):
        """The two action-level TSVs were inert data until the build script
        learned to consume them, so a bad row could land silently. These are
        the build's fail-closed checks re-run in the test matrix: unique
        service+action rows, lowercase actions, a valid classification on
        every inventory row, filled access levels, event-source URLs only
        where a category is documented, every action-level service inside
        the resource-type mapping, and the data-event TSV equal to the
        inventory's classification=data rows per service."""
        from permtrim.analyzer.engine import _AWS_DATA_EVENT_SERVICES

        root = Path(__file__).resolve().parents[1]
        doc_lines = (
            (root / "data" / "aws_data_event_actions_2026-11.tsv").read_text(encoding="utf-8").splitlines()
        )
        inv_lines = (
            (root / "data" / "aws_service_actions_2026-11.tsv").read_text(encoding="utf-8").splitlines()
        )

        doc_data: dict[str, set[str]] = {}
        seen: set[tuple[str, str]] = set()
        for line in doc_lines[1:]:
            svc, action, _src = line.split("\t")
            assert (svc, action) not in seen, line
            seen.add((svc, action))
            assert action == action.lower(), line
            doc_data.setdefault(svc, set()).add(action)

        inventory: dict[str, dict[str, str]] = {}
        for line in inv_lines[1:]:
            svc, action, cls, level, _iam_url, ev_url = line.split("\t")
            assert action == action.lower(), line
            assert cls in {"data", "management", "unclassified"}, line
            assert level, line
            if cls == "unclassified":
                assert ev_url == "", line
            else:
                assert ev_url, line
            assert action not in inventory.get(svc, {}), line
            inventory.setdefault(svc, {})[action] = cls

        for svc in inventory:
            assert svc in _AWS_DATA_EVENT_SERVICES, svc
        for svc in set(doc_data) | set(inventory):
            inv = inventory.get(svc, {})
            assert doc_data.get(svc, set()) <= set(inv), svc
            data_rows = {a for a, c in inv.items() if c == "data"}
            assert data_rows == doc_data.get(svc, set()), svc
