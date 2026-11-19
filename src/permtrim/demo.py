"""Offline end-to-end demo: bundled snapshot -> analysis -> verified Terraform.

This is the "see it work in 10 seconds" entry point: no AWS account, no
Ollama, no network. It runs the full pipeline on the sample snapshot:

    collect (pre-baked, Stubber-generated) -> analyze -> tighten -> render

and prints a compact report that doubles as the README demo screenshot.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .analyzer import Analyzer, load_default_registry
from .llm import DeterministicProposer, Tightener, TightenerConfig, policy_to_hcl

_SAMPLE = Path(__file__).parent / "data" / "sample_snapshot.json"


def _load_sample() -> dict[str, Any]:
    """Load the bundled sample snapshot (shipped as package data)."""
    return json.loads(_SAMPLE.read_text(encoding="utf-8"))


def run_demo() -> int:
    """Run the offline pipeline and print a compact, screenshot-friendly report."""
    document = _load_sample()
    meta = document["meta"]
    print("permtrim demo — offline end-to-end (no AWS, no LLM required)")
    print("=" * 64)
    print(
        f"snapshot : provider={meta['provider']} account={meta['account_id']} window={meta['lookback_days']}d"
    )

    registry = load_default_registry()
    print(f"dataset  : {registry.action_count} IAM actions across {registry.service_count} services")

    # ---- analyze
    report = Analyzer().analyze_document(document)
    print("-" * 64)
    print("ANALYZE  : permission-vs-usage findings")
    for finding in report.findings:
        print(
            f"  {finding.kind}:{finding.name}".ljust(22)
            + f"granted={finding.granted_count:<6}"
            + f"used={len(finding.used_actions):<4}"
            + f"unused={finding.unused_count:<6}"
            + f"risk={finding.risk_score:.0f}"
        )
        for wildcard in finding.wildcard_sources[:2]:
            print(f"      wildcard {wildcard['pattern']} grants {wildcard['concrete_action_count']} actions")

    # ---- tighten (deterministic proposer keeps the demo offline; the guardrail
    #      still runs, exactly as it would against LLM drafts)
    print("-" * 64)
    print("TIGHTEN  : propose -> guardrail -> action-level validated policies")
    tightener = Tightener(
        proposer=DeterministicProposer(registry),
        registry=registry,
        config=TightenerConfig(),
    )
    result = tightener.tighten(report)
    for outcome in result.outcomes:
        print(f"  {outcome.principal:<22} {outcome.label}")
        if outcome.policy:
            statements = outcome.policy.get("Statement", [])
            actions = [a for s in statements if isinstance(s, dict) for a in s.get("Action", [])]
            print(
                f"      -> allows {len(actions)} action(s): {', '.join(actions[:6])}"
                + (" ..." if len(actions) > 6 else "")
            )

    # ---- render
    print("-" * 64)
    print("OUTPUT   : action-level validated Terraform")
    tf_parts = [
        policy_to_hcl(o.principal, o.policy)
        for o in result.outcomes
        if o.status in {"verified", "needs_review"} and o.policy
    ]
    if tf_parts:
        target = Path("data/demo/tightened_policies.tf")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n\n".join(tf_parts) + "\n", encoding="utf-8")
        summary = result.to_dict()["summary"]
        print(f"  wrote {target} ({summary['verified']} verified + {summary['needs_review']} needs_review)")
        first_resource = tf_parts[0].splitlines()
        for line in first_resource:
            if "resource" in line or "name " in line or line.strip().startswith('"s3') or "EOT" in line:
                print(f"    {line.rstrip()}")
    print("=" * 64)
    summary = result.to_dict()["summary"]
    print(
        f"result   : {summary['verified']} verified / {summary['needs_review']} needs_review"
        f" / {summary['idle']} idle / {summary['failed']} failed"
    )
    return 0 if summary["failed"] == 0 else 1
