"""Tests for the graph layer (Task 3): builder, statements, queries, ingest, render."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from permtrim.graph import (
    CONSTRAINTS_CYPHER,
    QUERIES,
    build_graph,
    build_ingest_statements,
    ingest_model,
    render_graph,
    write_cypher_script,
    write_query_script,
)
from permtrim.graph.model import EDGE_TYPES

SAMPLE = Path(__file__).resolve().parent.parent / "src" / "permtrim" / "data" / "sample_snapshot.json"


@pytest.fixture(scope="module")
def document():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def model(document):
    return build_graph(document)


# -------------------------------------------------------------------- builder


class TestBuilder:
    def test_node_counts(self, model):
        counts = model.counts()
        assert counts["nodes"]["Principal"] == 2  # user:alice, role:deploy-ci
        assert counts["nodes"]["Group"] == 1  # devs
        assert counts["nodes"]["Policy"] == 3  # s3-extra, AdministratorAccess, EC2-Read
        assert counts["nodes"]["Action"] > 100  # expanded permissions

    def test_principal_labels_and_props(self, model):
        nodes = {n.key: n for n in model.nodes}
        alice = nodes["user:alice"]
        assert "Principal" in alice.labels and "User" in alice.labels
        assert alice.props["risk_score"] == 50.0
        assert alice.props["granted_count"] == 20455
        assert alice.props["used_count"] == 1
        deploy = nodes["role:deploy-ci"]
        assert "Role" in deploy.labels
        assert deploy.props["idle"] is True

    def test_member_of_edge(self, model):
        member_of = model.edges_by_type("MEMBER_OF")
        assert [(e.source, e.target) for e in member_of] == [("user:alice", "group:devs")]

    def test_granted_edges_include_via_group_provenance(self, model):
        granted = {(e.source, e.target): e for e in model.edges_by_type("GRANTED")}
        # alice's own two policies (inline + managed)
        assert ("user:alice", "policy:inline:user:alice:s3-extra") in granted
        assert ("user:alice", "policy:arn:aws:iam::aws:policy/AdministratorAccess") in granted
        # the group's policy, granted TO THE GROUP with via_group provenance
        group_edge = granted[("group:devs", "policy:arn:aws:iam::111122223333:policy/EC2-Read")]
        assert group_edge.props["via_group"] == "devs"

    def test_allows_edges_keep_pattern(self, model):
        allows = model.edges_by_type("ALLOWS")
        patterns = {e.props["pattern"] for e in allows}
        assert patterns == {"s3:getobject", "*", "ec2:describe*", "ec2:get*"}
        # wildcard policies collapse to representative nodes
        targets = {e.target for e in allows}
        assert "action:*" in targets
        assert "action:ec2:describe*" in targets

    def test_wildcard_node_carries_expansion_size(self, model):
        nodes = {n.key: n for n in model.nodes}
        star = nodes["action:*"]
        assert star.props["expansion_size"] == 20455
        assert star.props["wildcard"] is True

    def test_invoked_and_attempted_edges(self, model):
        invoked = model.edges_by_type("INVOKED")
        attempted = model.edges_by_type("ATTEMPTED")
        # alice's working usage
        assert [(e.source, e.target, e.props["count"]) for e in invoked] == [
            ("user:alice", "action:s3:getobject", 2)
        ]
        # deploy-ci tried RunInstances but every call failed -> ATTEMPTED, not INVOKED
        assert [(e.source, e.target) for e in attempted] == [("role:deploy-ci", "action:ec2:runinstances")]

    def test_can_use_edges_are_effective_permissions(self, model):
        can_use = model.edges_by_type("CAN_USE")
        assert len(can_use) == 4000  # capped per principal for graph readability
        # every used action is CAN_USE with used=true
        used = [e for e in can_use if e.props["used"]]
        assert {(e.source, e.target) for e in used} == {("user:alice", "action:s3:getobject")}
        # deploy-ci has no identity policies -> no CAN_USE edges at all
        assert not any(e.source == "role:deploy-ci" for e in can_use)

    def test_model_is_json_serializable(self, model):
        payload = json.dumps(model.to_dict())
        assert '"MEMBER_OF"' in payload


# ------------------------------------------------------------------ statements


class TestStatements:
    def test_constraints_first_and_parameterized(self, model):
        statements = build_ingest_statements(model)
        assert statements[0][0] == CONSTRAINTS_CYPHER[0]
        assert statements[0][1] == {}
        # node statements use UNWIND with parameters
        principal_stmt = next(q for q, p in statements if "$principal_nodes" in q)
        assert (
            "MERGE (n:Principal:User {key: row.key})" in principal_stmt
            or "MERGE (n:Principal {key: row.key})" in principal_stmt
        )

    def test_batches_are_bounded(self, model):
        for _query, params in build_ingest_statements(model, batch_size=500):
            for rows in params.values():
                assert len(rows) <= 500

    def test_literal_cypher_script_round_trip(self, model, tmp_path):
        """The Browser-ready script must contain the same data, inlined."""
        count = write_cypher_script(model, tmp_path / "graph.cypher", include_header=False)
        script = (tmp_path / "graph.cypher").read_text(encoding="utf-8")
        assert count > 20
        # no parameters survive inlining
        assert "$" not in script
        # key data points present as literals
        assert "'user:alice'" in script
        assert "risk_score: 50.0" in script  # inlined map entry (not a param name)
        assert "* (ALL" not in script  # labels are data, not rendered captions
        assert "MERGE (n:Principal {key: row.key})" in script
        # every statement ends with a semicolon
        statements = [s for s in script.split(";") if s.strip()]
        assert len(statements) == count

    def test_literalizer_escapes_strings(self):
        from permtrim.graph.statements import cypher_literal

        assert cypher_literal("it's") == "'it\\'s'"
        assert cypher_literal(True) == "true"
        assert cypher_literal(None) == "null"
        assert cypher_literal(["a", 1]) == "['a', 1]"
        assert cypher_literal({"used": False}) == "{ used: false }"


# -------------------------------------------------------------------- queries


class TestQueries:
    def test_query_library_covers_the_pitches(self):
        titles = " ".join(title for title, _, _ in QUERIES)
        for keyword in (
            "Hidden grants",
            "intersection",
            "ranking",
            "Dangerous unused",
            "Denied attempts",
            "blast radius",
        ):
            assert keyword in titles, f"missing query family: {keyword}"

    def test_queries_only_use_modeled_elements(self, model):
        """Every relationship type referenced in queries exists in the model schema."""
        for _, _, cypher in QUERIES:
            for token in ("MEMBER_OF", "GRANTED", "ALLOWS", "CAN_USE", "INVOKED", "ATTEMPTED"):
                if f":{token}" in cypher:
                    assert token in EDGE_TYPES

    def test_write_query_script(self, tmp_path):
        count = write_query_script(tmp_path / "queries.cypher")
        script = (tmp_path / "queries.cypher").read_text(encoding="utf-8")
        assert count == len(QUERIES)
        assert script.count("// ") >= count  # every query documented


# --------------------------------------------------------------------- ingest


class TestIngestWithFakeDriver:
    def test_ingest_uses_official_driver_and_summarizes(self, model, monkeypatch):

        class FakeResult:
            def __init__(self, value):
                self._value = value

            def single(self, strict=False):
                return self._value

            def consume(self):
                return None

        class FakeSession:
            def __init__(self):
                self.queries = []

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def run(self, query, **params):
                self.queries.append((query, params))
                # summary counts: every count query returns 1
                if "RETURN count(" in query:
                    return FakeResult([1])
                return FakeResult(None)

        class FakeDriver:
            def __init__(self, uri=None, auth=None):
                self.uri, self.auth = uri, auth

            def session(self, **kwargs):
                return FakeSession()

            def close(self):
                pass

        captured = {}

        class FakeGraphDatabase:
            @staticmethod
            def driver(uri, auth=None):
                captured["uri"], captured["auth"] = uri, auth
                return FakeDriver()

        class FakeModule:
            GraphDatabase = FakeGraphDatabase

        import sys

        monkeypatch.setitem(sys.modules, "neo4j", FakeModule())
        summary = ingest_model(model, "bolt://x:7687", auth=("neo4j", "pw"), clear=True)

        assert captured["uri"] == "bolt://x:7687"
        assert captured["auth"] == ("neo4j", "pw")
        # sessions are per-call; queries recorded inside each fake
        assert summary["nodes"]["total"] >= 4
        assert summary["edges"]["MEMBER_OF"] == 1

    def test_ingest_clears_when_asked(self, model, monkeypatch):

        seen = {"clear": False}

        class FakeResult:
            def single(self, strict=False):
                return [0]

            def consume(self):
                return None

        class FakeSession:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def run(self, query, **params):
                if "DETACH DELETE" in query:
                    seen["clear"] = True
                return FakeResult()

        class FakeDriver:
            def session(self, **kwargs):
                return FakeSession()

            def close(self):
                pass

        class FakeModule:
            class GraphDatabase:
                @staticmethod
                def driver(uri, auth=None):
                    return FakeDriver()

        monkeypatch.setitem(__import__("sys").modules, "neo4j", FakeModule())
        ingest_model(model, "bolt://x", auth=None, clear=True)
        assert seen["clear"] is True

    def test_ingest_without_driver_raises_friendly(self, model, monkeypatch):
        import sys

        monkeypatch.setitem(sys.modules, "neo4j", None)  # force import failure
        from permtrim.errors import PermTrimError

        with pytest.raises(PermTrimError) as excinfo:
            ingest_model(model, "bolt://x")
        assert "pip install neo4j" in str(excinfo.value)


# --------------------------------------------------------------------- render


class TestRender:
    def test_render_provides_non_blank_png(self, model, tmp_path):
        from PIL import Image

        out = render_graph(model, tmp_path / "graph.png")
        assert out.exists() and out.stat().st_size > 30_000
        image = Image.open(out)
        assert image.size[0] >= 1000
        gray = image.convert("L").histogram()
        # dark background + colored nodes -> most pixels not white
        assert 1 - gray[255] / sum(gray) > 0.9

    def test_short_label_stays_single_line(self):
        from permtrim.graph.render import _wrap_action_label

        assert _wrap_action_label("s3:GetObject") == "s3:GetObject"
        assert _wrap_action_label("microsoft.storage/read") == "microsoft.storage/read"

    def test_long_azure_label_wraps_at_namespace(self):
        from permtrim.graph.render import _wrap_action_label

        wrapped = _wrap_action_label("microsoft.storage/storageaccounts/listkeys/action")
        assert wrapped == "microsoft.storage/\nstorageaccounts/listkeys/action"
        # the operation line stays well under the right lane / figure edge
        # (calibrated: 30 chars ≈ 2.0 x-units < 2.1 lane gap)
        assert len(wrapped.split("\n")[1]) <= 32

    def test_long_aws_label_wraps_at_colon(self):
        from permtrim.graph.render import _wrap_action_label

        wrapped = _wrap_action_label("a4b:associatecontactwithaddressbookandxxxx")
        assert wrapped == "a4b:\nassociatecontactwithaddressbookandxxxx"

    def test_wildcard_count_label_breaks_at_space(self):
        from permtrim.graph.render import _wrap_action_label

        wrapped = _wrap_action_label("microsoft.storage/*/read  (42,353 actions)")
        assert wrapped.count("\n") == 1
        # the count survives wrapping intact
        assert "42,353 actions" in wrapped.replace("\n", " ")

    def test_single_long_token_hyphenates(self):
        from permtrim.graph.render import _wrap_action_label

        wrapped = _wrap_action_label("averyveryverylongsinglestringwithoutbreaks")
        assert wrapped.count("\n") == 1
        # break at limit-1 chars plus a hyphen
        assert wrapped == "averyveryverylongsinglest-\nringwithoutbreaks"

    def test_already_wrapped_label_untouched(self):
        from permtrim.graph.render import _wrap_action_label

        prewrapped = "head/\nvery long tail beyond the limit"
        assert _wrap_action_label(prewrapped) == prewrapped
