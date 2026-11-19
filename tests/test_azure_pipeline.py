"""Azure end-to-end coverage: graph builder, guardrail, tightener (Task 5).

Uses the bundled sample_azure_snapshot.json — the same document real users
feed to the CLI — so these tests pin the whole provider pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from permtrim.analyzer import Analyzer
from permtrim.analyzer.azure_registry import build_azure_registry
from permtrim.graph import build_graph
from permtrim.llm import DeterministicProposer, Tightener, TightenerConfig
from permtrim.llm.guardrails import Guardrail

SAMPLE = Path(__file__).resolve().parent.parent / "src" / "permtrim" / "data" / "sample_azure_snapshot.json"


@pytest.fixture(scope="module")
def document() -> dict:
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def report(document):
    return Analyzer().analyze_document(document)


# ------------------------------------------------------------------- graph


class TestGraphOnAzure:
    def test_provider_aware_registry_swap(self, document):
        model = build_graph(document)
        # 4 principals in the sample (1 user, 2 roles, 1 group)
        counts = model.counts()
        assert counts["nodes"]["Principal"] == 3
        assert counts["nodes"]["Group"] == 1
        assert counts["nodes"]["Policy"] == 5  # 2 builtin + 3 custom roles

    def test_azure_policy_labels(self, document):
        model = build_graph(document)
        policies = model.nodes_by_label("Policy")
        labels = {p.props["name"]: p.labels for p in policies}
        assert "Contributor" in labels and "AzureBuiltIn" in labels["Contributor"]
        assert "VMManager" in labels and "AzureCustom" in labels["VMManager"]

    def test_allows_edges_cover_azure_patterns(self, document):
        model = build_graph(document)
        patterns = {e.props["pattern"] for e in model.edges_by_type("ALLOWS")}
        assert "*" in patterns  # Contributor
        assert "*/read" in patterns  # Reader (via group)
        assert "microsoft.storage/storageaccounts/listkeys/action" in patterns

    def test_attempted_edge_for_denied_listkeys(self, document):
        model = build_graph(document)
        attempted = [(e.source, e.target) for e in model.edges_by_type("ATTEMPTED")]
        assert ("role:mi-backup-job", "action:microsoft.storage/storageaccounts/listkeys/action") in attempted
        # zeynep's denied role-assignment write is ATTEMPTED too
        assert (
            "user:zeynep@contoso.com",
            "action:microsoft.authorization/roleassignments/write",
        ) in attempted

    def test_member_of_edge_for_group(self, document):
        model = build_graph(document)
        member_of = [(e.source, e.target) for e in model.edges_by_type("MEMBER_OF")]
        assert ("user:zeynep@contoso.com", "group:platform-team") in member_of


# ---------------------------------------------------------------- guardrail


class TestGuardrailOnAzure:
    def _registry(self, document):
        return build_azure_registry(document)

    def test_valid_custom_role_draft_passes(self, document, report):
        guardrail = Guardrail(self._registry(document))
        zeynep = next(f for f in report.findings if f.name == "zeynep@contoso.com")
        draft = {
            "Name": "permtrim-user-zeynep",
            "IsCustom": True,
            "permissions": [
                {
                    "actions": ["microsoft.storage/storageaccounts/read"],
                    "dataActions": ["microsoft.storage/blob/containers/read"],
                }
            ],
        }
        verdict = guardrail.validate(zeynep, draft)
        assert verdict.ok, verdict.feedback

    def test_hallucinated_azure_action_rejected(self, document, report):
        guardrail = Guardrail(self._registry(document))
        zeynep = next(f for f in report.findings if f.name == "zeynep@contoso.com")
        draft = {
            "permissions": [
                {
                    "actions": ["microsoft.storage/storageaccounts/reed"],  # typo
                }
            ],
        }
        verdict = guardrail.validate(zeynep, draft)
        assert not verdict.ok
        assert "hallucinated" in " ".join(verdict.reasons).lower()

    def test_coverage_failure_lists_denied_actions(self, document, report):
        guardrail = Guardrail(self._registry(document))
        zeynep = next(f for f in report.findings if f.name == "zeynep@contoso.com")
        # Azure '*' crosses '/' — */read covers every read incl. data plane.
        # So the draft covers usage but over-reaches; the converse case:
        draft = {"permissions": [{"actions": ["microsoft.compute/*"]}]}
        verdict = guardrail.validate(zeynep, draft)
        assert not verdict.ok
        assert "coverage failure" in " ".join(verdict.reasons)

    def test_wildcard_overreach_rejected(self, document, report):
        guardrail = Guardrail(self._registry(document))
        zeynep = next(f for f in report.findings if f.name == "zeynep@contoso.com")
        draft = {"permissions": [{"actions": ["*"]}]}
        verdict = guardrail.validate(zeynep, draft)
        assert not verdict.ok
        assert "new permissions" in " ".join(verdict.reasons)


# ---------------------------------------------------------------- tightener


class TestTightenerOnAzure:
    def test_verified_custom_role_shape(self, document, report):
        registry = build_azure_registry(document)
        tightener = Tightener(
            proposer=DeterministicProposer(
                registry, azure_subscription="00000000-1111-2222-3333-444444444444"
            ),
            registry=registry,
            config=TightenerConfig(),
        )
        result = tightener.tighten(report)

        zeynep = next(o for o in result.outcomes if "zeynep" in o.principal)
        # Azure role assignments carry no resource-scope provenance into the
        # analysis (scope lives on the assignment, not the definition), so
        # even a guardrail-clean draft is honestly needs_review, not verified.
        assert zeynep.status == "needs_review"
        policy = zeynep.policy
        assert policy["IsCustom"] is True
        assert policy["AssignableScopes"] == ["/subscriptions/00000000-1111-2222-3333-444444444444"]
        permissions = policy["permissions"][0]
        assert permissions["actions"] == ["microsoft.storage/storageaccounts/read"]
        assert permissions["dataActions"] == ["microsoft.storage/blob/containers/read"]

    def test_idle_workloads_get_no_policy(self, document, report):
        registry = build_azure_registry(document)
        tightener = Tightener(
            proposer=DeterministicProposer(registry),
            registry=registry,
            config=TightenerConfig(),
        )
        result = tightener.tighten(report)
        statuses = {o.principal: o.status for o in result.outcomes}
        assert statuses["role:deploy-agent"] == "idle"
        assert statuses["role:mi-backup-job"] == "idle"  # every call failed


# ---------------------------------------------------------------- matcher unit


class TestMatcherAzureSemantics:
    def test_actions_plus_notactions_subtract(self):
        from permtrim.analyzer.matcher import PolicySet

        policy_set = PolicySet()
        policy_set.add_policy_document(
            {
                "roleName": "Contributor",
                "permissions": [{"actions": ["*"], "notActions": ["microsoft.authorization/*/write"]}],
            },
            "managed:Contributor@user/zeynep",
        )
        statement = policy_set.allow_statements[0]

        assert statement.matches("microsoft.storage/storageaccounts/read")
        assert not statement.matches("microsoft.authorization/roleassignments/write")

    def test_data_actions_merge_with_actions(self):
        from permtrim.analyzer.matcher import PolicySet

        policy_set = PolicySet()
        policy_set.add_policy_document(
            {
                "permissions": [
                    {
                        "actions": ["microsoft.storage/storageaccounts/read"],
                        "dataActions": ["microsoft.storage/blob/containers/read"],
                    }
                ],
            },
            "managed:BlobReader@user/zeynep",
        )

        evaluate = policy_set.evaluate
        assert evaluate("microsoft.storage/storageaccounts/read")[0]
        assert evaluate("microsoft.storage/blob/containers/read")[0]
        assert not evaluate("microsoft.storage/storageaccounts/listkeys/action")[0]
