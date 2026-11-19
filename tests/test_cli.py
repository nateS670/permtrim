"""CLI integration tests: analyze / tighten / demo (offline paths only)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE = REPO_ROOT / "src" / "permtrim" / "data" / "sample_snapshot.json"


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "permtrim", *args],
        capture_output=True,
        text=True,
        cwd=cwd or REPO_ROOT,
        timeout=180,
    )


@pytest.fixture(scope="module")
def sample_copy(tmp_path_factory):
    """Sample snapshot in a temp dir so analyze outputs land there."""
    target = tmp_path_factory.mktemp("cli") / "snapshot.json"
    target.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    return target


class TestAnalyzeCommand:
    def test_analyze_writes_findings(self, sample_copy):
        result = run_cli("analyze", str(sample_copy))
        assert result.returncode == 0, result.stderr
        assert "ANALYSIS SUMMARY" in result.stdout
        assert "alice" in result.stdout
        findings = sample_copy.with_name("snapshot_findings.json")
        assert findings.exists()
        doc = json.loads(findings.read_text(encoding="utf-8"))
        assert doc["summary"]["principals_analyzed"] == 2
        assert doc["summary"]["total_unused_actions"] > 5000


class TestTightenCommand:
    def test_tighten_deterministic_produces_verified_terraform(self, sample_copy, tmp_path):
        output = tmp_path / "tightened"
        result = run_cli(
            "tighten",
            str(sample_copy),
            "--proposer",
            "deterministic",
            "--output",
            str(output),
        )
        assert result.returncode == 0, result.stderr
        assert "user:alice" in result.stdout
        assert "verified" in result.stdout

        tf = output / "tightened_policies.tf"
        assert tf.exists()
        hcl = tf.read_text(encoding="utf-8")
        assert 'resource "aws_iam_policy" "permtrim_user_alice"' in hcl
        assert '"s3:GetObject"' in hcl
        assert "ACTION-LEVEL VALIDATED" in hcl
        # original resource provenance is preserved, not widened to "*"
        assert '"arn:aws:s3:::corp-data/*"' in hcl
        # the header no longer claims it replaces anything
        assert "replaces" not in hcl.lower()

        result_doc = json.loads((output / "tightening_result.json").read_text(encoding="utf-8"))
        assert result_doc["summary"]["verified"] == 1
        assert result_doc["summary"]["needs_review"] == 0
        assert result_doc["summary"]["idle"] == 1

    def test_tighten_truncated_window_refuses(self, sample_copy, tmp_path):
        """A truncated activity window must block automatic tightening."""
        document = json.loads(sample_copy.read_text(encoding="utf-8"))
        document["meta"]["window"]["truncated"] = True
        truncated = tmp_path / "truncated_snapshot.json"
        truncated.write_text(json.dumps(document), encoding="utf-8")
        output = tmp_path / "tightened_truncated"
        result = run_cli(
            "tighten",
            str(truncated),
            "--proposer",
            "deterministic",
            "--output",
            str(output),
        )
        assert result.returncode == 0, result.stderr
        assert "insufficient_data" in result.stdout
        assert not (output / "tightened_policies.tf").exists()
        result_doc = json.loads((output / "tightening_result.json").read_text(encoding="utf-8"))
        assert result_doc["summary"]["insufficient_data"] == 2

        # --allow-truncated-window is the explicit human override
        output2 = tmp_path / "tightened_truncated_ok"
        result2 = run_cli(
            "tighten",
            str(truncated),
            "--proposer",
            "deterministic",
            "--output",
            str(output2),
            "--allow-truncated-window",
        )
        assert result2.returncode == 0, result2.stderr
        assert "verified" in result2.stdout
        assert (output2 / "tightened_policies.tf").exists()

    def test_tighten_auto_falls_back_when_ollama_down(self, sample_copy, tmp_path):
        # --ollama-host pointing at a dead port: auto mode must fall back
        # to the deterministic proposer without failing.
        output = tmp_path / "tightened_auto"
        result = run_cli(
            "tighten",
            str(sample_copy),
            "--proposer",
            "auto",
            "--ollama-host",
            "http://127.0.0.1:1",
            "--output",
            str(output),
        )
        assert result.returncode == 0, result.stderr
        assert "verified" in result.stdout


class TestDemoCommand:
    def test_demo_runs_offline_end_to_end(self, tmp_path):
        result = run_cli("demo", cwd=tmp_path)
        assert result.returncode == 0, result.stderr
        assert "ANALYZE" in result.stdout
        assert "TIGHTEN" in result.stdout
        assert "s3:GetObject" in result.stdout
        assert (tmp_path / "data" / "demo" / "tightened_policies.tf").exists()


class TestErrorPaths:
    def test_missing_file_exits_nonzero(self, tmp_path):
        result = run_cli("analyze", str(tmp_path / "nope.json"))
        assert result.returncode == 1

    def test_invalid_json_exits_nonzero(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        result = run_cli("analyze", str(bad))
        assert result.returncode == 1
