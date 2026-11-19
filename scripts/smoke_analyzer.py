"""Quick smoke check of the analyzer against the bundled sample snapshot."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from permtrim.analyzer import Analyzer, load_default_registry

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_snapshot.json"


def main() -> None:
    registry = load_default_registry()
    print("registry:", registry.dataset_summary())

    # sanity: known / unknown / wildcard counting
    assert registry.action_exists("s3:GetObject")
    assert not registry.action_exists("s3:GetObjekt")
    assert registry.action_exists("iam:CreateUser")
    print("s3:Get* expands to", registry.count_matching("s3:Get*"), "actions")
    print("ec2:* expands to", registry.count_matching("ec2:*"), "actions")

    document = json.loads(SAMPLE.read_text(encoding="utf-8"))
    report = Analyzer().analyze_document(document)

    summary = report.to_dict()["summary"]
    print(json.dumps(summary, indent=2))
    for finding in report.findings:
        print(
            f"- {finding.kind}:{finding.name} risk={finding.risk_score:.1f} "
            f"granted={finding.granted_count} unused={finding.unused_count} "
            f"used={finding.used_actions} idle={finding.is_idle}"
        )
        for w in finding.wildcard_sources[:3]:
            print(
                f"    wildcard {w['pattern']} -> {w['concrete_action_count']} actions, "
                f"e.g. unused {w['unused_examples'][:3]}"
            )


if __name__ == "__main__":
    main()
