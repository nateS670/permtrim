"""Command-line interface: ``permtrim collect|analyze|tighten|demo``.

Examples:
    permtrim collect --days 30 --output data/aws_snapshot.json
    permtrim analyze data/aws_snapshot.json --output data/findings.json
    permtrim tighten data/aws_snapshot.json --output data/tightened
    permtrim demo                      # offline end-to-end on bundled fixtures
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from .analyzer import Analyzer, load_default_registry
from .analyzer.action_registry import ActionRegistry
from .analyzer.azure_registry import AzureActionRegistry
from .collectors import AWSCollectorConfig, create_collector, write_json_document
from .errors import PermTrimError
from .graph import build_graph, ingest_model, render_graph, write_cypher_script, write_query_script
from .llm import DeterministicProposer, OllamaProposer, Tightener, TightenerConfig, policy_to_hcl

__all__ = ["main", "build_parser"]

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``permtrim`` CLI."""
    parser = argparse.ArgumentParser(
        prog="permtrim",
        description="LLM-powered multi-cloud IAM least-privilege detector and auto-tightener.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect = subparsers.add_parser(
        "collect", help="Collect a unified IAM + activity snapshot from a cloud provider."
    )
    collect.add_argument(
        "--provider",
        default="aws",
        choices=["aws", "azure"],
        help="Cloud provider to collect from. Default: aws.",
    )
    collect.add_argument(
        "--days",
        type=int,
        default=None,
        help="Activity lookback window in days, 1..90 (CloudTrail history limit). Default: 30.",
    )
    collect.add_argument("--region", default=None, help="AWS region (event history is regional).")
    collect.add_argument("--profile", default=None, help="Named AWS profile from ~/.aws/config.")
    collect.add_argument(
        "--subscription-id",
        default=None,
        help="Azure subscription id (or AZURE_SUBSCRIPTION_ID env; provider=azure).",
    )
    collect.add_argument(
        "--tenant-id", default=None, help="Azure tenant id for service-principal auth (provider=azure)."
    )
    collect.add_argument(
        "--client-id",
        default=None,
        help="Azure service-principal client id (provider=azure; default: az login credential).",
    )
    collect.add_argument(
        "--client-secret",
        default=None,
        help="Azure service-principal secret (provider=azure; prefer env AZURE_CLIENT_SECRET).",
    )
    collect.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON path. Default: data/<provider>_snapshot_<UTC timestamp>.json",
    )
    collect.add_argument(
        "--no-raw-events",
        action="store_true",
        help="Omit the raw event list from the snapshot (keeps only usage summaries).",
    )
    collect.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity. Default: INFO.",
    )

    analyze = subparsers.add_parser("analyze", help="Detect excess permissions in a unified snapshot.")
    analyze.add_argument("snapshot", type=Path, help="Unified snapshot JSON (from `collect`).")
    analyze.add_argument("--output", type=Path, default=None, help="Findings JSON output path.")
    analyze.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity. Default: INFO.",
    )

    tighten = subparsers.add_parser(
        "tighten", help="Generate guardrail-verified least-privilege policies + Terraform."
    )
    tighten.add_argument("snapshot", type=Path, help="Unified snapshot JSON (from `collect`).")
    tighten.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output directory for findings.json and .tf files. Default: data/tightened",
    )
    tighten.add_argument(
        "--proposer",
        default="auto",
        choices=["auto", "ollama", "deterministic"],
        help="Policy drafting backend. 'auto' uses Ollama when reachable, else deterministic.",
    )
    tighten.add_argument("--ollama-model", default="llama3.2", help="Ollama model name.")
    tighten.add_argument("--ollama-host", default="http://127.0.0.1:11434", help="Ollama API host.")
    tighten.add_argument("--max-attempts", type=int, default=3, help="LLM retries before fallback.")
    tighten.add_argument(
        "--allow-truncated-window",
        action="store_true",
        help="Tighten even when the activity window was truncated by an AWS API cap "
        "(default: refuse — incomplete usage data can break production).",
    )
    tighten.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity. Default: INFO.",
    )

    graph = subparsers.add_parser("graph", help="Export / ingest / render the IAM permission graph (Task 3).")
    graph.add_argument("snapshot", type=Path, help="Unified snapshot JSON (from `collect`).")
    graph.add_argument(
        "--mode",
        default="export",
        choices=["export", "ingest", "render", "all"],
        help=(
            "export: write .cypher scripts; ingest: load into Neo4j; "
            "render: offline PNG; all: everything. Default: export."
        ),
    )
    graph.add_argument(
        "--output-dir", type=Path, default=None, help="Directory for graph artifacts. Default: data/graph"
    )
    graph.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j Bolt URI (ingest).")
    graph.add_argument("--neo4j-user", default="neo4j", help="Neo4j user (ingest).")
    graph.add_argument(
        "--neo4j-password", default=None, help="Neo4j password (ingest; or NEO4J_PASSWORD env)."
    )
    graph.add_argument("--neo4j-database", default=None, help="Neo4j database name (ingest).")
    graph.add_argument("--clear", action="store_true", help="Wipe permtrim nodes before ingest.")
    graph.add_argument(
        "--max-edges",
        type=int,
        default=4000,
        help="Cap on CAN_USE edges per principal in the graph. Default: 4000.",
    )
    graph.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity. Default: INFO.",
    )

    report = subparsers.add_parser(
        "report",
        help="Generate a standalone single-file HTML audit report (summary, graph, findings, remediation).",
    )
    report.add_argument("snapshot", type=Path, help="Unified snapshot JSON (from `collect`).")
    report.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output .html path. Default: data/permtrim_report_<account>.html",
    )
    report.add_argument(
        "--no-graph",
        action="store_true",
        help="Skip the embedded permission-graph image (smaller file).",
    )
    report.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity. Default: INFO.",
    )

    demo = subparsers.add_parser(
        "demo",
        help="Offline end-to-end run on the bundled sample snapshot (no AWS, no LLM).",
    )
    demo.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity. Default: INFO.",
    )
    return parser


def _default_output(provider: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("data") / f"{provider}_snapshot_{stamp}.json"


def _format_summary(document: dict[str, Any]) -> str:
    """Human-readable one-liner block printed after a successful collection."""
    identities = document["identities"]
    activity = document["activity"]
    meta = document["meta"]
    events = activity.get("events", [])
    events_count = len(events) if isinstance(events, list) else events
    lines = [
        f"provider            : {meta['provider']}  (account {meta.get('account_id')}, "
        f"region {meta.get('region')})",
        f"identities          : {len(identities['users'])} users, "
        f"{len(identities['roles'])} roles, "
        f"{len(identities['groups'])} groups, "
        f"{len(identities['managed_policies'])} managed policies",  # noqa: E501
        f"activity window     : {meta['lookback_days']} days, "
        f"{events_count} events, "
        f"{len(activity['usage'])} distinct principals"
        + (" [TRUNCATED]" if activity["window"]["truncated"] else ""),
        f"unmatched principals : {len(document['unmatched_activity'])} "
        "(root usage / deleted identities / cross-account callers)",
    ]
    return "\n".join(lines)


def _cmd_collect(args: argparse.Namespace) -> int:
    config: AWSCollectorConfig | AzureCollectorConfig
    if args.provider == "azure":
        from .collectors import AzureCollectorConfig

        config = AzureCollectorConfig(
            subscription_id=args.subscription_id or "",
            tenant_id=args.tenant_id,
            client_id=args.client_id,
            client_secret=args.client_secret,
            default_lookback_days=args.days or 30,
            include_raw_events=not args.no_raw_events,
        )
    else:
        config = AWSCollectorConfig(
            region=args.region,
            profile=args.profile,
            default_lookback_days=args.days or 30,
            include_raw_events=not args.no_raw_events,
        )
    collector = create_collector(args.provider, config)
    document = collector.collect(lookback_days=args.days)
    output = args.output or _default_output(args.provider)
    write_json_document(document, output)
    print(_format_summary(document))
    print(f"saved -> {output}")
    return 0


def _print_analysis(report_doc: dict[str, Any]) -> None:
    summary = report_doc["summary"]
    print(f"\n=== ANALYSIS SUMMARY ({summary['principals_analyzed']} principals) ===")
    print(f"idle principals      : {summary['idle_principals']}")
    print(f"total unused actions : {summary['total_unused_actions']}")
    print(f"average risk score   : {summary['avg_risk_score']}")
    print("top risk:")
    for entry in summary["top_risk"]:
        print(f"  - {entry['kind']}:{entry['name']}  risk={entry['risk_score']}")


def _cmd_analyze(args: argparse.Namespace) -> int:
    document = json.loads(args.snapshot.read_text(encoding="utf-8"))
    report = Analyzer().analyze_document(document)
    report_doc = report.to_dict()
    _print_analysis(report_doc)
    output = args.output or args.snapshot.with_name(args.snapshot.stem + "_findings.json")
    write_json_document(report_doc, output)
    print(f"saved -> {output}")
    return 0


def _ollama_reachable(host: str) -> bool:
    import urllib.error
    import urllib.request

    try:
        request = urllib.request.Request(host.rstrip("/") + "/api/tags", method="GET")
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _build_proposer(args: argparse.Namespace, registry: Any) -> Any:
    if args.proposer == "deterministic":
        return DeterministicProposer(registry)
    ollama = OllamaProposer(model=args.ollama_model, host=args.ollama_host)
    if args.proposer == "ollama":
        return ollama
    if _ollama_reachable(args.ollama_host):
        LOGGER.info("Ollama reachable at %s — using model %s", args.ollama_host, args.ollama_model)
        return ollama
    LOGGER.info("Ollama not reachable at %s — using deterministic proposer", args.ollama_host)
    return DeterministicProposer()


def _cmd_tighten(args: argparse.Namespace) -> int:
    document = json.loads(args.snapshot.read_text(encoding="utf-8"))
    provider = document.get("meta", {}).get("provider", "aws")
    registry: ActionRegistry | AzureActionRegistry
    if provider == "azure":
        from .analyzer.azure_registry import build_azure_registry

        registry = build_azure_registry(document)
    else:
        registry = load_default_registry()
    report = Analyzer().analyze_document(document)

    proposer = _build_proposer(args, registry)
    if provider == "azure":
        # custom roles need a real AssignableScopes value
        subscription = document.get("meta", {}).get("subscription_id") or document.get("meta", {}).get(
            "account_id", ""
        )
        proposer = DeterministicProposer(
            cast("ActionRegistry | None", registry), azure_subscription=subscription
        )
    tightener = Tightener(
        proposer=proposer,
        registry=cast("ActionRegistry", registry),
        config=TightenerConfig(
            max_attempts=args.max_attempts,
            allow_truncated_window=getattr(args, "allow_truncated_window", False),
        ),
    )
    result = tightener.tighten(report)

    output_dir = args.output or Path("data/tightened")
    output_dir.mkdir(parents=True, exist_ok=True)

    write_json_document(result.to_dict(), output_dir / "tightening_result.json")

    provider = document.get("meta", {}).get("provider", "aws")
    summary = result.to_dict()["summary"]
    print(f"\n=== TIGHTENING ({summary['total']} principals, proposer={proposer.name}) ===")
    for outcome in result.outcomes:
        note = ""
        if outcome.status == "insufficient_data":
            note = " — re-run collect with a narrower window, or --allow-truncated-window"
        print(f"  {outcome.principal:<28} {outcome.label}{note}")

    validated = result.validated
    if provider == "azure":
        # Azure remediation: one custom-role JSON per principal + the
        # az commands that install them and swap the assignments.
        az_parts: list[str] = []
        for outcome in validated:
            slug = outcome.principal.replace(":", "-").replace("@", "-").replace("/", "-")
            role_path = output_dir / f"role_{slug}.json"
            role_path.write_text(json.dumps(outcome.policy, indent=2) + "\n", encoding="utf-8")
            az_parts.append(
                f"# {outcome.principal}: least-privilege custom role from observed usage\n"
                f"az role definition create --role-definition {role_path.name}"
            )
        if az_parts:
            apply_path = output_dir / "apply_roles.sh"
            apply_path.write_text(
                "#!/usr/bin/env bash\nset -euo pipefail\n\n" + "\n".join(az_parts) + "\n", encoding="utf-8"
            )
            apply_path.chmod(0o755)
            print(f"saved -> {len(az_parts)} role_*.json + apply_roles.sh (az role definition create)")
    else:
        tf_parts: list[str] = []
        for outcome in validated:
            if outcome.policy is not None:
                tf_parts.append(policy_to_hcl(outcome.principal, outcome.policy))
        if tf_parts:
            tf_path = output_dir / "tightened_policies.tf"
            tf_path.write_text("\n\n".join(tf_parts) + "\n", encoding="utf-8")
            print(
                f"saved -> {tf_path} "
                f"({summary.get('verified', 0)} verified + "
                f"{summary.get('needs_review', 0)} needs_review — action-level validated)"
            )
    print(f"saved -> {output_dir / 'tightening_result.json'}")
    return 0


def _cmd_graph(args: argparse.Namespace) -> int:
    import os

    document = json.loads(args.snapshot.read_text(encoding="utf-8"))
    output_dir = args.output_dir or Path("data/graph")
    output_dir.mkdir(parents=True, exist_ok=True)

    model = build_graph(document, max_edges_per_type=args.max_edges)
    counts = model.counts()
    print(
        f"graph built: {counts['nodes']['total']} nodes "
        f"({counts['nodes']['Principal']} principals, {counts['nodes']['Group']} groups, "
        f"{counts['nodes']['Policy']} policies, {counts['nodes']['Action']} actions)"
    )

    if args.mode in ("export", "all"):
        n = write_cypher_script(model, output_dir / "permtrim_graph.cypher")
        q = write_query_script(output_dir / "queries.cypher")
        model_path = output_dir / "graph_model.json"
        model_path.write_text(json.dumps(model.to_dict(), indent=2), encoding="utf-8")
        print(
            f"exported -> {output_dir / 'permtrim_graph.cypher'} ({n} statements, paste into Neo4j Browser)"
        )
        print(f"exported -> {output_dir / 'queries.cypher'} ({q} analysis queries)")
        print(f"exported -> {model_path}")

    if args.mode in ("render", "all"):
        png = render_graph(model, output_dir / "permission_graph.png")
        print(f"rendered -> {png}")

    if args.mode in ("ingest", "all"):
        password = args.neo4j_password or os.environ.get("NEO4J_PASSWORD")
        auth = (args.neo4j_user, password) if password else None
        summary = ingest_model(
            model,
            args.neo4j_uri,
            auth=auth,
            database=args.neo4j_database,
            clear=args.clear,
        )
        print(f"ingested -> {args.neo4j_uri}: {summary}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """Standalone HTML report: analyze + tighten + embed the rendered graph."""
    from .analyzer import Analyzer
    from .graph import build_graph, render_graph
    from .llm import DeterministicProposer, Tightener, TightenerConfig
    from .report import generate_report

    document = json.loads(args.snapshot.read_text(encoding="utf-8"))
    provider = document.get("meta", {}).get("provider", "aws")
    report = Analyzer().analyze_document(document)

    # Remediations (deterministic: offline, reproducible; same guardrails).
    from .analyzer.azure_registry import build_azure_registry

    if provider == "azure":
        azure_registry = build_azure_registry(document)
        subscription = document.get("meta", {}).get("subscription_id") or document.get("meta", {}).get(
            "account_id", ""
        )
        proposer = DeterministicProposer(
            cast("ActionRegistry | None", azure_registry), azure_subscription=subscription
        )
        tightener = Tightener(proposer, cast("ActionRegistry", azure_registry), TightenerConfig())
    else:
        from .analyzer import load_default_registry

        registry = load_default_registry()
        proposer = DeterministicProposer(registry)
        tightener = Tightener(proposer, registry, TightenerConfig())
    tighten_result = tightener.tighten(report)

    # Embedded graph image (best-effort: skip when rendering is unavailable).
    graph_png: Path | None = None
    if not args.no_graph:
        try:
            model = build_graph(document)
            default_out = Path("data/graph")
            graph_png = render_graph(model, default_out / "permission_graph.png")
        except Exception as exc:  # noqa: BLE001 - rendering is optional decoration
            LOGGER.warning("Graph rendering skipped (%s); report continues without it", exc)

    account = document.get("meta", {}).get("account_id", "unknown")
    output = args.output or Path(f"data/permtrim_report_{account}.html")
    generate_report(document, report, output=output, graph_png=graph_png, tighten_result=tighten_result)
    print(f"saved -> {output} (open in any browser; fully self-contained)")
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    """Offline end-to-end: sample snapshot -> analysis -> tightened Terraform."""
    from .demo import run_demo

    return run_demo()


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code (0 on success, 1 on failure)."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    try:
        if args.command == "collect":
            return _cmd_collect(args)
        if args.command == "analyze":
            return _cmd_analyze(args)
        if args.command == "tighten":
            return _cmd_tighten(args)
        if args.command == "graph":
            return _cmd_graph(args)
        if args.command == "report":
            return _cmd_report(args)
        if args.command == "demo":
            return _cmd_demo(args)
        return 1
    except PermTrimError as exc:
        LOGGER.error("%s: %s", type(exc).__name__, exc)
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.error("%s: %s", type(exc).__name__, exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
