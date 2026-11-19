"""Tests for the standalone HTML report (``permtrim report``)."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from permtrim.analyzer import Analyzer
from permtrim.analyzer.action_registry import ActionRegistry
from permtrim.analyzer.azure_registry import build_azure_registry
from permtrim.llm import DeterministicProposer, Tightener, TightenerConfig
from permtrim.report import generate_report

if TYPE_CHECKING:
    from permtrim.analyzer.findings import AnalysisReport
    from permtrim.llm.tightener import TightenResult

AWS_SAMPLE = Path(__file__).resolve().parent.parent / "src" / "permtrim" / "data" / "sample_snapshot.json"
AZURE_SAMPLE = (
    Path(__file__).resolve().parent.parent / "src" / "permtrim" / "data" / "sample_azure_snapshot.json"
)


def _prepare(document: dict) -> tuple[dict, AnalysisReport, TightenResult]:
    from typing import cast

    report = Analyzer().analyze_document(document)
    provider = document.get("meta", {}).get("provider", "aws")
    if provider == "azure":
        registry = build_azure_registry(document)
        subscription = document.get("meta", {}).get("subscription_id") or document.get("meta", {}).get(
            "account_id", ""
        )
        proposer = DeterministicProposer(
            cast("ActionRegistry | None", registry), azure_subscription=subscription
        )
        tightener = Tightener(proposer, cast("ActionRegistry", registry), TightenerConfig())
    else:
        from permtrim.analyzer import load_default_registry

        registry = load_default_registry()
        tightener = Tightener(DeterministicProposer(registry), registry, TightenerConfig())
    return document, report, tightener.tighten(report)


def test_aws_report_is_self_contained(tmp_path: Path) -> None:
    document, report, tighten_result = _prepare(json.loads(AWS_SAMPLE.read_text(encoding="utf-8")))
    out = generate_report(
        document, report, output=tmp_path / "aws.html", graph_png=None, tighten_result=tighten_result
    )
    html_text = out.read_text(encoding="utf-8")

    # self-contained: no external references
    assert "http://" not in html_text and "https://" not in html_text
    assert "<script src" not in html_text and "<link" not in html_text

    # header metadata
    assert "111122223333" in html_text
    assert "provider" in html_text

    # one card row (6 cards), risk table, principal details, policy blocks
    assert html_text.count('class="card"') == 6
    assert "alice" in html_text and "deploy-ci" in html_text
    assert "aws_iam_policy" in html_text  # Terraform remediation block

    # valid HTML basics: one <html>, closed </html>
    assert html_text.count("<html") == 1 and html_text.count("</html>") == 1


def test_azure_report_renders_role_json(tmp_path: Path) -> None:
    document, report, tighten_result = _prepare(json.loads(AZURE_SAMPLE.read_text(encoding="utf-8")))
    out = generate_report(
        document, report, output=tmp_path / "azure.html", graph_png=None, tighten_result=tighten_result
    )
    html_text = out.read_text(encoding="utf-8")

    # Azure provider header + custom role remediation shape
    assert "provider" in html_text
    assert "azure" in html_text
    assert "AssignableScopes" in html_text  # custom role JSON block
    assert "dataActions" in html_text

    # idle workloads carry the access-review note instead of a policy
    assert "access review candidate" in html_text


def test_graph_png_embedded_as_data_uri(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When a graph PNG is provided it is inlined base64, not linked."""
    # 1x1 transparent PNG
    png = tmp_path / "graph.png"
    png.write_bytes(
        base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
        )
    )
    document, report, tighten_result = _prepare(json.loads(AWS_SAMPLE.read_text(encoding="utf-8")))
    out = generate_report(
        document, report, output=tmp_path / "embedded.html", graph_png=png, tighten_result=tighten_result
    )
    html_text = out.read_text(encoding="utf-8")
    assert 'src="data:image/png;base64,' in html_text
    assert 'src="graph.png"' not in html_text  # never a relative link


def test_no_graph_flag_omits_image(tmp_path: Path) -> None:
    document, report, tighten_result = _prepare(json.loads(AWS_SAMPLE.read_text(encoding="utf-8")))
    out = generate_report(
        document, report, output=tmp_path / "nograph.html", graph_png=None, tighten_result=tighten_result
    )
    assert 'img class="graph"' not in out.read_text(encoding="utf-8")


def test_html_escaping_of_principal_names(tmp_path: Path) -> None:
    """A principal name with HTML metacharacters cannot inject markup."""
    document = json.loads(AWS_SAMPLE.read_text(encoding="utf-8"))
    # mutate the *user* entry (a group name never reaches the findings table)
    user = next(p for p in document["principals"] if p["kind"] == "user")
    user["name"] = "alice<script>alert(1)</script>"
    document.setdefault("meta", {})["account_id"] = "111122223333"
    report = Analyzer().analyze_document(document)
    assert any("script" in f.name for f in report.findings)  # guard: mutation took effect
    out = generate_report(document, report, output=tmp_path / "escaped.html")
    html_text = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html_text
    assert "&lt;script&gt;" in html_text


def test_risk_table_rows_ordered_by_risk(tmp_path: Path) -> None:
    document, report, tighten_result = _prepare(json.loads(AWS_SAMPLE.read_text(encoding="utf-8")))
    out = generate_report(
        document, report, output=tmp_path / "ordered.html", graph_png=None, tighten_result=tighten_result
    )
    html_text = out.read_text(encoding="utf-8")
    pattern = r"class='badge'[^>]*>(\d+) (?:critical|high|elevated|moderate|low)"
    scores = [float(m) for m in re.findall(pattern, html_text)]
    assert scores == sorted(scores, reverse=True)
