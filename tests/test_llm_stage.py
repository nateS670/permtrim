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
