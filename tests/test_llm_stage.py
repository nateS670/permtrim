"""Tests for the LLM stage (Task 4): guardrails, tightener, Terraform.

The centerpiece is ``TestHallucinationLoop``: a scripted fake LLM that
behaves like a misbehaving Llama-3 — it invents actions, then 'fixes' them
once told — proving the guardrail rejects bad drafts and the feedback loop
converges instead of leaking an unverified policy.
"""

from __future__ import annotations

from typing import Any

import pytest

from permtrim.analyzer.action_registry import load_default_registry
from permtrim.analyzer.findings import GrantedAction, PrincipalFinding
from permtrim.llm import (
    DeterministicProposer,
    Guardrail,
    Tightener,
    TightenerConfig,
    policy_to_hcl,
)
from permtrim.llm.proposer import OllamaProposer, _extract_json_object


@pytest.fixture(scope="module")
def registry():
    return load_default_registry()


def make_finding() -> PrincipalFinding:
    """alice: granted s3:Get*/s3:Put* (wildcards) + iam:CreateUser, uses GetObject only.

    The used action's original resource scope was "*" (the Admin managed
    policy grants everything on "*"), so a draft with Resource "*" is NOT a
    widening for this principal.
    """
    doc_grants = {
        "s3:getobject": GrantedAction("s3:getobject", ["managed:Admin@user/alice"], True, False, "Read"),
        "s3:putobject": GrantedAction("s3:putobject", ["managed:Admin@user/alice"], False, False, "Write"),
        "s3:listbucket": GrantedAction("s3:listbucket", ["managed:Admin@user/alice"], False, False, "List"),
        "iam:createuser": GrantedAction(
            "iam:createuser", ["inline:x@user/alice"], False, False, "Permissions management"
        ),
    }
    return PrincipalFinding(
        kind="user",
        name="alice",
        arn="arn:aws:iam::1:user/alice",
        used_actions=["s3:getobject"],
        granted_actions=sorted(doc_grants.values(), key=lambda g: g.action),
        unused_actions=[g for g in doc_grants.values() if not g.used],
        wildcard_sources=[{"pattern": "s3:*", "concrete_action_count": 168, "unused_examples": []}],
        risk_score=42.0,
        used_action_resources={"s3:getobject": ["*"]},
    )


# ------------------------------------------------------------------ guardrail


class TestGuardrail:
    def test_valid_draft_passes(self, registry):
        finding = make_finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert verdict.ok, verdict.reasons

    def test_hallucinated_action_rejected(self, registry):
        finding = make_finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:GetObjekt"],  # typo'd hallucination
                    "Resource": "*",
                }
            ],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("hallucinated" in reason for reason in verdict.reasons)
        assert "s3:getobjekt" in verdict.feedback.lower()

    def test_missing_coverage_rejected(self, registry):
        finding = make_finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "*"}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("coverage" in reason for reason in verdict.reasons)

    def test_wildcard_fix_coverage_rejected_as_new_permissions(self, registry):
        """The classic LLM cheat: fix coverage with Action '*'."""
        finding = make_finding()
        draft = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("new permissions" in reason for reason in verdict.reasons)

    def test_wildcard_within_original_grants_passes(self, registry):
        """A draft wildcard is fine if it stays within the original grants."""
        finding = PrincipalFinding(
            kind="user",
            name="carol",
            arn=None,
            used_actions=["s3:getobject"],
            granted_actions=[
                GrantedAction("s3:getobject", ["m"], True, False, "Read"),
                GrantedAction("s3:listbucket", ["m"], False, False, "List"),
            ],
        )
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:Get*", "s3:ListBucket"], "Resource": "*"}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        # s3:Get* expands to actions carol never had (e.g. s3:GetBucketPolicy)
        # -> those are new permissions; only within-grant coverage survives.
        # This draft SHOULD fail: s3:Get* exceeds grants.
        assert not verdict.ok
        assert any("new permissions" in reason for reason in verdict.reasons)

    def test_notaction_draft_rejected(self, registry):
        """NotAction Allow grants a huge implicit space — must be refused.

        Regression test: the no-new-permissions check only reasons about
        explicit Action lists, so a NotAction draft could smuggle in
        permissions the principal never had (e.g. everything except s3).
        """
        finding = make_finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "NotAction": ["s3:PutObject"], "Resource": "*"}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("NotAction" in reason for reason in verdict.reasons)

    def test_notresource_draft_rejected(self, registry):
        """NotResource is the same negation hazard on the resource axis."""
        finding = make_finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "NotResource": ["arn:aws:s3:::secret/*"]}
            ],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("NotResource" in reason for reason in verdict.reasons)

    def test_azure_notactions_draft_rejected(self, registry):
        """Azure drafts using notActions hit the same negation refusal."""
        finding = PrincipalFinding(
            kind="role",
            name="mi-backup",
            arn=None,
            provider="azure",
            used_actions=["microsoft.storage/storageaccounts/listkeys/action"],
            granted_actions=[
                GrantedAction("microsoft.storage/storageaccounts/listkeys/action", ["m"], True, False, None)
            ],
        )
        draft = {
            "Name": "permtrim-role-mi-backup",
            "permissions": [{"actions": ["*"], "notActions": ["microsoft.authorization/*/write"]}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("notActions" in reason for reason in verdict.reasons)

    def test_resource_scope_widening_rejected(self, registry):
        """Draft allows a used action on '*' but the original grant was scoped.

        Alice used s3:GetObject, but only ever had it on
        arn:aws:s3:::corp-data/* — an unscoped draft widens the blast radius
        even though the action count shrinks. Must be rejected.
        """
        finding = make_finding()
        finding.used_action_resources = {"s3:getobject": ["arn:aws:s3:::corp-data/*"]}
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("resource scope" in reason for reason in verdict.reasons)

    def test_resource_scope_preserved_passes(self, registry):
        """Same action, resource scopes carried from the original grant -> ok."""
        finding = make_finding()
        finding.used_action_resources = {"s3:getobject": ["arn:aws:s3:::corp-data/*"]}
        draft = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::corp-data/*"]}
            ],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert verdict.ok, verdict.reasons

    def test_original_star_scope_draft_star_ok(self, registry):
        """Original grant was Resource '*' — a '*' draft is NOT a widening."""
        finding = make_finding()
        finding.used_action_resources = {"s3:getobject": ["*"]}
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert verdict.ok, verdict.reasons

    def test_structural_failures(self, registry):
        finding = make_finding()
        guardrail = Guardrail(registry)
        assert not guardrail.validate(finding, None).ok
        assert not guardrail.validate(finding, "not a dict").ok
        assert not guardrail.validate(finding, {"Statement": []}).ok
        bogus_key = {
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*", "Typo": 1}]
        }
        assert not guardrail.validate(finding, bogus_key).ok

    def test_simulator_hook_can_reject(self, registry):
        def deny_everything(draft, actions):
            return list(actions)

        finding = make_finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
        }
        verdict = Guardrail(registry, simulator=deny_everything).validate(finding, draft)
        assert not verdict.ok
        assert any("simulator" in reason for reason in verdict.reasons)


class TestUnusedRemoval:
    """Regression: an LLM may preserve the old broad grants verbatim.

    A principal with Action "*" who used ONE action, and an LLM that
    proposes "*" back: no-new-permissions passes (the expansion is a subset
    of the original grants) and coverage passes — the old blast radius would
    ship as "validated". Both holes are pinned shut here.
    """

    @staticmethod
    def _admin_finding(registry) -> PrincipalFinding:
        """granted = the full '*' expansion (20455 actions); used = 1."""
        every = registry.expand("*")
        return PrincipalFinding(
            kind="user",
            name="dave",
            arn=None,
            used_actions=["s3:getobject"],
            granted_actions=[
                GrantedAction(a, ["managed:Admin@user/dave"], a == "s3:getobject", False, "Read")
                for a in every
            ],
            used_action_resources={"s3:getobject": ["*"]},
        )

    def test_star_draft_for_admin_principal_rejected(self, registry):
        """THE regression test: original policy '*', one used action, LLM
        proposes '*' back — must be rejected, not validated."""
        finding = self._admin_finding(registry)
        draft = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("wildcard Action patterns" in reason for reason in verdict.reasons)

    def test_literal_regrant_of_unused_actions_rejected(self, registry):
        """Draft keeps unused actions as literals — still no unused removal."""
        finding = self._admin_finding(registry)
        draft = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "ec2:RunInstances"], "Resource": "*"}
            ],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("no observed usage" in reason for reason in verdict.reasons)

    def test_attempted_error_only_actions_stay_allowed(self, registry):
        """Error-only (attempted) actions are legitimate policy content:
        the principal demonstrably needs them, the calls just failed."""
        finding = PrincipalFinding(
            kind="user",
            name="erin",
            arn=None,
            used_actions=["s3:getobject"],
            granted_actions=[
                GrantedAction("s3:getobject", ["m"], True, False, "Read"),
                GrantedAction("ec2:runinstances", ["m"], False, True, "Write"),  # error_only
            ],
            used_action_resources={"s3:getobject": ["*"]},
        )
        draft = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "ec2:RunInstances"], "Resource": "*"}
            ],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert verdict.ok, verdict.reasons


class TestDenyStatementRejected:
    """Regression: Allow + Deny could bypass the coverage check.

    The guardrail evaluates coverage over Allow statements only, but real
    IAM lets an explicit Deny override every Allow — a draft pairing
    Allow(s3:GetObject) with Deny(s3:GetObject) would "pass" coverage while
    breaking the principal in production. Deny statements are refused.
    """

    def test_allow_plus_deny_same_action_rejected(self, registry):
        finding = make_finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::corp-data/*"},
                {"Effect": "Deny", "Action": ["s3:GetObject"], "Resource": "*"},
            ],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("Deny statement" in reason for reason in verdict.reasons)

    def test_deny_only_draft_rejected(self, registry):
        finding = make_finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": ["s3:*"], "Resource": "*"}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok


# --------------------------------------------------------- hallucination loop


class ScriptedLLM:
    """Fake proposer returning queued drafts — a misbehaving-LLM stand-in."""

    name = "scripted-llm"

    def __init__(self, drafts: list[dict[str, Any] | None]) -> None:
        self._drafts = list(drafts)
        self.calls: list[str | None] = []  # feedback received per call

    def propose(self, finding, feedback=None):
        self.calls.append(feedback)
        return self._drafts.pop(0) if self._drafts else None


class TestHallucinationLoop:
    def test_llm_rejected_then_corrected(self, registry):
        """Attempt 1 hallucinates, attempt 2 fixes it after feedback -> verified."""
        finding = make_finding()
        llm = ScriptedLLM(
            [
                {
                    "Statement": [
                        {"Effect": "Allow", "Action": ["s3:GetObject", "ec2:RunInstance"], "Resource": "*"}
                    ]
                },
                {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]},
            ]
        )
        tightener = Tightener(llm, registry, TightenerConfig(max_attempts=3))
        result = tightener.tighten(_report_with(finding))
        outcome = result.outcomes[0]
        assert outcome.status == "verified"
        assert outcome.proposer == "scripted-llm"
        assert outcome.attempts[0].startswith("attempt 1: rejected")
        assert "ec2:runinstance" in outcome.attempts[0]
        assert outcome.attempts[1] == "attempt 2: accepted"
        # the LLM saw its own hallucination quoted in the feedback
        assert "hallucinated" in (llm.calls[1] or "")

    def test_persistent_llm_falls_back_to_deterministic(self, registry):
        """LLM never converges -> deterministic fallback, still guardrail-verified."""
        finding = make_finding()
        llm = ScriptedLLM(
            [
                {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObjekt"], "Resource": "*"}]},
                {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObjekt2"], "Resource": "*"}]},
                {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObjekt3"], "Resource": "*"}]},
            ]
        )
        tightener = Tightener(llm, registry, TightenerConfig(max_attempts=3))
        result = tightener.tighten(_report_with(finding))
        outcome = result.outcomes[0]
        assert outcome.status == "verified"
        assert outcome.proposer == "deterministic"
        assert len([a for a in outcome.attempts if a.startswith("attempt")]) == 3
        assert outcome.policy["Statement"][0]["Action"] == ["s3:GetObject"]

    def test_idle_principal_gets_no_policy(self, registry):
        finding = PrincipalFinding(
            kind="role",
            name="idle-role",
            arn=None,
            used_actions=[],
            granted_actions=[GrantedAction("s3:getobject", ["m"], False, False, "Read")],
        )
        llm = ScriptedLLM([])
        result = Tightener(llm, registry).tighten(_report_with(finding))
        assert result.outcomes[0].status == "idle"
        assert result.outcomes[0].policy is None


class TestInsufficientDataGuard:
    """window.truncated=True => no policies, honest insufficient_data status.

    Tightening from a window the AWS API cut short risks removing a
    permission that was simply not observed yet — the review explicitly
    called this out, so it is pinned by tests.
    """

    def test_truncated_window_blocks_tightening(self, registry):
        finding = make_finding()
        llm = ScriptedLLM([{"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}])
        result = Tightener(llm, registry, TightenerConfig(max_attempts=3)).tighten(
            _report_with(finding, window_truncated=True)
        )
        outcome = result.outcomes[0]
        assert outcome.status == "insufficient_data"
        assert outcome.policy is None
        assert llm.calls == []  # the proposer was never even asked
        assert "truncated" in outcome.attempts[0].lower()

    def test_truncated_window_override_opt_in(self, registry):
        finding = make_finding()
        llm = ScriptedLLM([{"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}])
        result = Tightener(
            llm, registry, TightenerConfig(max_attempts=3, allow_truncated_window=True)
        ).tighten(_report_with(finding, window_truncated=True))
        assert result.outcomes[0].status in {"verified", "needs_review"}
        assert result.outcomes[0].policy is not None


class TestConditionalGrantsGuard:
    """Original grants carrying Condition elements must not be auto-replaced.

    permtrim does not evaluate conditions (MFA, VPC endpoint, ...): a
    generated replacement without the Condition would silently WIDEN
    effective access. The tightener refuses and flags manual review.
    """

    @staticmethod
    def _conditional_finding() -> PrincipalFinding:
        return PrincipalFinding(
            kind="user",
            name="mallory",
            arn=None,
            used_actions=["s3:getobject"],
            granted_actions=[GrantedAction("s3:getobject", ["inline:mfa@user/mallory"], True, False, "Read")],
            used_action_resources={"s3:getobject": ["*"]},
            conditional_grants=["s3:getobject"],
        )

    def test_conditional_grant_stops_tightener(self, registry):
        finding = self._conditional_finding()
        llm = ScriptedLLM([{"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}])
        result = Tightener(llm, registry).tighten(_report_with(finding))
        outcome = result.outcomes[0]
        assert outcome.status == "manual_review"
        assert outcome.policy is None
        assert llm.calls == []  # proposer never even asked
        assert "Condition" in outcome.attempts[0]

    def test_end_to_end_engine_detects_condition(self):
        """The analyzer flags Condition-carrying grants end to end."""
        from datetime import datetime, timezone

        from permtrim.analyzer.engine import Analyzer
        from permtrim.models.activity import ActivityLog, ActivityWindow, UsageSummary
        from permtrim.models.iam import IaMSnapshot, IAMUser

        now = datetime.now(timezone.utc)
        mfa_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                }
            ],
        }
        iam = IaMSnapshot(
            account_id="1",
            collector_identity_arn="arn",
            collected_at=now,
            users=[IAMUser(name="mallory", arn="arn:u", inline_policies={"mfa": mfa_doc})],
            roles=[],
            groups=[],
            policies={},
        )
        activity = ActivityLog(
            window=ActivityWindow(start=now, end=now, lookback_days=30),
            events=[],
            usage={("user", "mallory"): UsageSummary(action_counts={"s3:GetObject": 5})},
        )
        report = Analyzer().analyze(iam, activity)
        finding = report.findings[0]
        assert finding.conditional_grants == ["s3:getobject"]
        assert "s3:getobject" in finding.to_dict()["conditional_grants"]


class TestUnknownDataPlaneUsageGuard:
    """Unused-LOOKING data-plane grants: usage is invisible, not absent.

    lookup_events returns management events only; s3/lambda/dynamodb/qldb
    usage never shows up. The tightener must refuse to strip such grants
    unless the operator explicitly opts in.
    """

    @staticmethod
    def _data_plane_finding() -> PrincipalFinding:
        return PrincipalFinding(
            kind="user",
            name="frank",
            arn=None,
            used_actions=["ec2:describeinstances"],
            granted_actions=[
                GrantedAction("ec2:describeinstances", ["m"], True, False, "Read"),
                GrantedAction("s3:getobject", ["m"], False, False, "Read"),  # data plane, unused-looking
            ],
            used_action_resources={"ec2:describeinstances": ["*"]},
            unknown_usage_actions=["s3:getobject"],
        )

    def test_unknown_data_plane_stops_tightener(self, registry):
        finding = self._data_plane_finding()
        llm = ScriptedLLM(
            [{"Statement": [{"Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": "*"}]}]
        )
        result = Tightener(llm, registry).tighten(_report_with(finding))
        outcome = result.outcomes[0]
        assert outcome.status == "manual_review"
        assert outcome.policy is None
        assert llm.calls == []
        assert "data events" in outcome.attempts[0] or "DATA-PLANE" in outcome.attempts[0]

    def test_opt_in_flag_allows_tightening(self, registry):
        finding = self._data_plane_finding()
        llm = ScriptedLLM(
            [{"Statement": [{"Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": "*"}]}]
        )
        result = Tightener(llm, registry, TightenerConfig(allow_unknown_data_plane_usage=True)).tighten(
            _report_with(finding)
        )
        outcome = result.outcomes[0]
        assert outcome.status == "verified"
        assert outcome.policy is not None

    def test_used_data_plane_actions_do_not_block(self, registry):
        """A data-plane action that WAS observed used is not unknown usage."""
        finding = PrincipalFinding(
            kind="user",
            name="gina",
            arn=None,
            used_actions=["s3:getobject"],
            granted_actions=[GrantedAction("s3:getobject", ["m"], True, False, "Read")],
            used_action_resources={"s3:getobject": ["*"]},
            unknown_usage_actions=[],
        )
        llm = ScriptedLLM([{"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}])
        result = Tightener(llm, registry).tighten(_report_with(finding))
        assert result.outcomes[0].status == "verified"


class TestIdleVsUnknownOrdering:
    """P2: unknown-usage and conditional-grants guards run BEFORE the idle guard.

    A principal with only invisible-to-lookup_events data-plane grants and no
    observed usage is "unknown usage" (manual_review), not "idle" — the
    reviewer needs to know the real reason. Likewise a principal whose only
    grant carried a Condition and was never observed is "conditional_grants",
    not "idle".
    """

    def test_data_plane_only_no_usage_is_manual_review_not_idle(self, registry):
        finding = PrincipalFinding(
            kind="user",
            name="hank",
            arn=None,
            used_actions=[],  # no observed usage at all
            granted_actions=[GrantedAction("s3:getobject", ["m"], False, False, "Read", data_plane=True)],
            used_action_resources={},
            unknown_usage_actions=["s3:getobject"],
        )
        llm = ScriptedLLM([])
        result = Tightener(llm, registry).tighten(_report_with(finding))
        outcome = result.outcomes[0]
        assert outcome.status == "manual_review"
        assert outcome.review_reason == "unknown_data_plane_usage"
        assert outcome.policy is None
        # the generic idle note must NOT appear; the data-plane reason must
        assert "no working usage" not in " ".join(outcome.attempts)
        assert "data events" in " ".join(outcome.attempts) or "DATA-PLANE" in " ".join(outcome.attempts)

    def test_conditional_only_no_usage_is_manual_review_not_idle(self, registry):
        finding = PrincipalFinding(
            kind="user",
            name="iris",
            arn=None,
            used_actions=[],  # no observed usage at all
            granted_actions=[GrantedAction("s3:getobject", ["m"], False, False, "Read")],
            used_action_resources={},
            conditional_grants=["s3:getobject"],
            unknown_usage_actions=[],
        )
        llm = ScriptedLLM([])
        result = Tightener(llm, registry).tighten(_report_with(finding))
        outcome = result.outcomes[0]
        assert outcome.status == "manual_review"
        assert outcome.review_reason == "conditional_grants"
        assert outcome.policy is None
        assert "no working usage" not in " ".join(outcome.attempts)
        assert "Condition" in " ".join(outcome.attempts)

    def test_no_usage_no_unknown_no_conditional_is_idle(self, registry):
        """The idle branch still fires when there is genuinely nothing to flag."""
        finding = PrincipalFinding(
            kind="user",
            name="jane",
            arn=None,
            used_actions=[],
            granted_actions=[GrantedAction("ec2:describeinstances", ["m"], False, False, "Read")],
            used_action_resources={},
            conditional_grants=[],
            unknown_usage_actions=[],
        )
        llm = ScriptedLLM([])
        result = Tightener(llm, registry).tighten(_report_with(finding))
        outcome = result.outcomes[0]
        assert outcome.status == "idle"
        assert outcome.review_reason is None

    def test_unused_sns_publish_stops_tightener(self, registry):
        """P1-AWS: sns:Publish is a CloudTrail DATA event (invisible to
        lookup_events) — an unused-looking grant of it must stop the
        tightener exactly like the s3 case, not fall through to idle."""
        finding = PrincipalFinding(
            kind="user",
            name="hal",
            arn=None,
            used_actions=[],
            granted_actions=[GrantedAction("sns:publish", ["m"], False, False, "Write", data_plane=True)],
            used_action_resources={},
            conditional_grants=[],
            unknown_usage_actions=["sns:publish"],
        )
        llm = ScriptedLLM([])
        result = Tightener(llm, registry).tighten(_report_with(finding))
        outcome = result.outcomes[0]
        assert outcome.status == "manual_review"
        assert outcome.review_reason == "unknown_data_plane_usage"
        assert "sns:publish" in " ".join(outcome.attempts)
        assert outcome.policy is None

    def test_unused_management_action_does_not_stop_tightener(self, registry):
        """P1-AWS over-inclusion fix: s3:CreateBucket is a management event —
        lookup_events WOULD have seen its usage — so an unused grant of it is
        confirmed excess and does not trigger the unknown-usage guard (the
        principal is just idle / removable, not manual-review noise)."""
        finding = PrincipalFinding(
            kind="user",
            name="kai",
            arn=None,
            used_actions=[],
            granted_actions=[GrantedAction("s3:createbucket", ["m"], False, False, "Write")],
            used_action_resources={},
            conditional_grants=[],
            unknown_usage_actions=[],  # the analyzer did NOT flag it
        )
        llm = ScriptedLLM([])
        result = Tightener(llm, registry).tighten(_report_with(finding))
        outcome = result.outcomes[0]
        assert outcome.status == "idle"
        assert outcome.review_reason is None


class TestResourceElementRequired:
    """P2: AWS drafts must carry a non-empty Resource on every Allow statement.

    A missing / empty / wrong-typed Resource would let IAM default it to "*",
    widening the blast radius. The guardrail rejects it so a draft cannot
    slip through as a "verified" widening. (NotResource is handled by the
    negation check and still rejected with its own reason.)
    """

    def _finding(self) -> PrincipalFinding:
        return make_finding()

    def test_missing_resource_rejected(self, registry):
        finding = self._finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"]}],  # no Resource key
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("no Resource element" in r for r in verdict.reasons)

    def test_empty_string_resource_rejected(self, registry):
        finding = self._finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ""}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("empty Resource string" in r for r in verdict.reasons)

    def test_empty_list_resource_rejected(self, registry):
        finding = self._finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": []}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("empty Resource list" in r for r in verdict.reasons)

    def test_wrong_type_resource_rejected(self, registry):
        finding = self._finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": {"arn": "x"}}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("Resource of type" in r for r in verdict.reasons)

    def test_list_with_non_string_entry_rejected(self, registry):
        finding = self._finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::ok", 42]}
            ],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("non-string or empty entries" in r for r in verdict.reasons)

    def test_valid_resource_still_accepted(self, registry):
        finding = self._finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert verdict.ok, verdict.reasons

    def test_notresource_still_rejected_with_its_own_reason(self, registry):
        """A NotResource draft is rejected for negation, not just missing Resource."""
        finding = self._finding()
        draft = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "NotResource": ["arn:aws:s3:::secret/*"]}
            ],
        }
        verdict = Guardrail(registry).validate(finding, draft)
        assert not verdict.ok
        assert any("NotResource" in r for r in verdict.reasons)


class TestResourceScopeProvenance:
    """Resource scopes flow from the finding into the tightened policy."""

    def test_deterministic_proposer_preserves_original_resources(self, registry):
        finding = make_finding()
        finding.used_action_resources = {"s3:getobject": ["arn:aws:s3:::corp-data/*"]}
        draft = DeterministicProposer(registry).propose(finding)
        assert draft["Statement"][0]["Resource"] == ["arn:aws:s3:::corp-data/*"]

    def test_deterministic_proposer_splits_distinct_scopes(self, registry):
        """Two used actions with different scopes become two statements."""
        finding = make_finding()
        finding.used_actions = ["s3:getobject", "s3:listbucket"]
        finding.used_action_resources = {
            "s3:getobject": ["arn:aws:s3:::corp-data/*"],
            "s3:listbucket": ["arn:aws:s3:::corp-data"],
        }
        draft = DeterministicProposer(registry).propose(finding)
        by_action = {tuple(stmt["Action"]): stmt["Resource"] for stmt in draft["Statement"]}
        assert by_action[("s3:GetObject",)] == ["arn:aws:s3:::corp-data/*"]
        assert by_action[("s3:ListBucket",)] == ["arn:aws:s3:::corp-data"]

    def test_no_provenance_falls_back_to_star_and_needs_review(self, registry):
        finding = make_finding()
        finding.used_action_resources = {}  # Azure-style: no resource provenance
        llm = ScriptedLLM([{"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}])
        result = Tightener(llm, registry).tighten(_report_with(finding))
        outcome = result.outcomes[0]
        assert outcome.status == "needs_review"
        assert outcome.policy is not None

    def test_full_provenance_yields_verified(self, registry):
        finding = make_finding()
        finding.used_action_resources = {"s3:getobject": ["arn:aws:s3:::corp-data/*"]}
        draft = DeterministicProposer(registry).propose(finding)
        llm = ScriptedLLM([draft])
        result = Tightener(llm, registry).tighten(_report_with(finding))
        outcome = result.outcomes[0]
        assert outcome.status == "verified"
        assert outcome.policy["Statement"][0]["Resource"] == ["arn:aws:s3:::corp-data/*"]


def _report_with(finding, window_truncated: bool = False):
    from permtrim.analyzer.findings import AnalysisReport

    return AnalysisReport(
        account_id="1", lookback_days=30, window_truncated=window_truncated, dataset={}, findings=[finding]
    )


# ------------------------------------------------------------------- proposer


class TestProposers:
    def test_deterministic_proposer_covers_usage_with_canonical_casing(self, registry):
        finding = make_finding()
        draft = DeterministicProposer(registry).propose(finding)
        assert draft["Statement"][0]["Action"] == ["s3:GetObject"]

    def test_azure_role_routes_data_plane_from_finding_classification(self, registry):
        """P1-Azure: the data-plane split comes from the finding, not a prefix.

        A used action the analyzer tagged ``data_plane=True`` (here, a Key
        Vault data-plane action ``microsoft.keyvault/vaults/secrets/getSecret``
        — NOT under ``microsoft.storage/blob/``) must land in ``dataActions``,
        and a control-plane used action in ``actions``. The old hardcoded
        ``microsoft.storage/blob/`` prefix would have put the Key Vault action
        in ``actions``, re-granting a data-plane permission on the control
        plane.
        """
        finding = PrincipalFinding(
            kind="role",
            name="kv-reader@contoso.com",
            arn=None,
            provider="azure",
            used_actions=[
                "microsoft.storage/storageaccounts/read",
                "microsoft.keyvault/vaults/secrets/getsecret",
            ],
            granted_actions=[
                GrantedAction(
                    "microsoft.storage/storageaccounts/read", ["m"], True, False, "Read", data_plane=False
                ),
                GrantedAction(
                    "microsoft.keyvault/vaults/secrets/getsecret", ["m"], True, False, "Read", data_plane=True
                ),
            ],
            used_action_resources={},
            unknown_usage_actions=[],
        )
        proposer = DeterministicProposer(registry, azure_subscription="sub-1")
        draft = proposer.propose(finding)
        permissions = draft["permissions"][0]
        assert permissions["actions"] == ["microsoft.storage/storageaccounts/read"]
        # Key Vault data-plane action routed to dataActions from the finding's
        # own data_plane flag, not from a microsoft.storage/blob/ prefix match.
        assert permissions["dataActions"] == ["microsoft.keyvault/vaults/secrets/getsecret"]

    def test_azure_role_no_data_actions_when_no_used_data_plane(self, registry):
        """A finding with only control-plane used actions has no dataActions key."""
        finding = PrincipalFinding(
            kind="role",
            name="vm-user@contoso.com",
            arn=None,
            provider="azure",
            used_actions=["microsoft.compute/virtualmachines/read"],
            granted_actions=[
                GrantedAction(
                    "microsoft.compute/virtualmachines/read", ["m"], True, False, "Read", data_plane=False
                )
            ],
            used_action_resources={},
            unknown_usage_actions=[],
        )
        proposer = DeterministicProposer(registry, azure_subscription="sub-1")
        draft = proposer.propose(finding)
        permissions = draft["permissions"][0]
        assert permissions == {"actions": ["microsoft.compute/virtualmachines/read"]}

    def test_json_extraction_from_noisy_model_output(self):
        assert _extract_json_object('{"a": 1}') == {"a": 1}
        assert _extract_json_object('```json\n{"a": 1}\n```') == {"a": 1}
        assert _extract_json_object('Sure! Here is the policy:\n{"a": {"b": 2}} hope it helps') == {
            "a": {"b": 2}
        }
        assert _extract_json_object('{"unterminated": true') is None
        assert _extract_json_object("") is None

    def test_ollama_unreachable_returns_none(self):
        proposer = OllamaProposer(host="http://127.0.0.1:1", timeout_s=1)
        assert proposer.propose(make_finding()) is None


# ------------------------------------------------------------------ terraform


class TestTerraformRendering:
    def test_hcl_contains_verified_policy(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
        }
        hcl = policy_to_hcl("user:alice", policy)
        assert 'resource "aws_iam_policy" "permtrim_user_alice"' in hcl
        assert "ACTION-LEVEL VALIDATED" in hcl
        assert '"s3:GetObject"' in hcl
        assert "<<-EOT" in hcl and hcl.rstrip().endswith("}")

    def test_name_sanitization(self):
        from permtrim.llm.terraform import terraform_sanitize_name

        assert terraform_sanitize_name("deploy-ci") == "deploy_ci"
        assert terraform_sanitize_name("1team") == "p_1team"
