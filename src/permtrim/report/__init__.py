"""Standalone single-file HTML audit report (``permtrim report``).

One self-contained ``.html`` file a security team can open, archive or
email: no web server, no external assets, no CDN — every style, script and
image is inlined. The embedded graph PNG is base64; the interactive bits
(sortable table, collapsible principal sections, copy buttons) are plain
vanilla JS.

Sections
--------
1. Header — provider, account, window, generated timestamp.
2. Summary cards — principals, idle count, total unused actions, avg risk,
   verified tightened policies.
3. Embedded permission graph (rendered by the existing graph module).
4. Risk table — one row per principal, sortable, risk-colored.
5. Per-principal detail — collapsible cards with used/unused action tables
   and the tightened policy (Terraform for AWS, custom role JSON for Azure)
   with a copy-to-clipboard button.
"""

from __future__ import annotations

import base64
import html
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..analyzer.findings import AnalysisReport, PrincipalFinding
from ..llm import DeterministicProposer, Tightener, TightenerConfig, policy_to_hcl

__all__ = ["generate_report"]

LOGGER = logging.getLogger(__name__)

_RISK_COLORS = [
    (80, "#e5484d", "critical"),
    (60, "#e5732f", "high"),
    (40, "#d6a12d", "elevated"),
    (20, "#4ba0d0", "moderate"),
    (0, "#3fb26b", "low"),
]


def _risk_style(score: float) -> tuple[str, str]:
    for threshold, color, label in _RISK_COLORS:
        if score >= threshold:
            return color, label
    return _RISK_COLORS[-1][1], _RISK_COLORS[-1][2]


def _embed_png(path: Path) -> str:
    """Read the rendered graph PNG and inline it as a data URI."""
    data = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{data}"


def _action_table(rows: list[tuple[str, str, list[str]]], empty_text: str) -> str:
    """Render a small action table: (action, access_level, sources)."""
    if not rows:
        return f'<p class="muted">{html.escape(empty_text)}</p>'
    body = "".join(
        f"<tr><td><code>{html.escape(action)}</code></td>"
        f"<td>{html.escape(level or '—')}</td>"
        f"<td class='src'>{html.escape(', '.join(sources[:3]))}</td></tr>"
        for action, level, sources in rows
    )
    return (
        "<table class='actions'><thead><tr><th>Action</th><th>Access</th>"
        f"<th>Via</th></tr></thead><tbody>{body}</tbody></table>"
    )


def _detail_section(
    finding: PrincipalFinding, remediation: str, index: int, *, is_fully_verified: bool = False
) -> str:
    color, label = _risk_style(finding.risk_score)
    principal_id = f"p{index}"
    used_rows: list[tuple[str, str, list[str]]] = [(a, "", []) for a in finding.used_actions]
    unused_rows = [(g.action, g.access_level or "", g.sources) for g in finding.unused_actions[:30]]
    wildcards = (
        "".join(
            f"<li><code>{html.escape(str(w.get('pattern')))}</code> — "
            f"{w.get('concrete_action_count', '?')} concrete actions</li>"
            for w in finding.wildcard_sources
        )
        or "<li class='muted'>none</li>"
    )
    reasons = (
        "".join(f"<li>{html.escape(reason)}</li>" for reason in finding.risk_reasons)
        or "<li class='muted'>no risk drivers</li>"
    )
    boundary = (
        f"<p class='muted'>Permission boundary: <code>"
        f"{html.escape(finding.permission_boundary_arn)}</code> "
        "(collected; NOT evaluated — effective permissions are the intersection)</p>"
        if finding.permission_boundary_arn
        else ""
    )
    validation_note = (
        "action-level validated, full verification"
        if is_fully_verified
        else "action-level validated, needs review"
    )
    return f"""
<details class="principal" id="{principal_id}">
  <summary>
    <span class="badge" style="background:{color}">{finding.risk_score:.0f} {label}</span>
    <strong>{html.escape(finding.kind)}:{html.escape(finding.name)}</strong>
    <span class="muted">{finding.granted_count} granted · {finding.unused_count} unused ·
    {len(finding.used_actions)} used</span>
  </summary>
  <div class="principal-body">
    {boundary}
    <div class="cols">
      <div>
        <h4>Used in window ({len(used_rows)})</h4>
        {_action_table(used_rows, "No observed activity — idle principal.")}
      </div>
      <div>
        <h4>Unused grants (top {min(len(unused_rows), 30)})</h4>
        {_action_table(unused_rows, "No unused grants.")}
      </div>
    </div>
    <h4>Wildcard blast radius</h4>
    <ul class="wildcards">{wildcards}</ul>
    <h4>Why this score</h4>
    <ul class="reasons">{reasons}</ul>
    <h4>Tightened policy ({validation_note})</h4>
    <div class="policy-block">
      <button class="copy" data-target="{principal_id}-policy">Copy</button>
      <pre id="{principal_id}-policy"><code>{html.escape(remediation)}</code></pre>
    </div>
  </div>
</details>"""


def _summary_cards(report: AnalysisReport, tighten_summary: dict[str, Any]) -> str:
    findings = report.findings
    avg_risk = sum(f.risk_score for f in findings) / len(findings) if findings else 0.0
    validated_count = tighten_summary.get("verified", 0) + tighten_summary.get("needs_review", 0)
    cards = [
        ("Principals", str(len(findings)), "#4ba0d0"),
        ("Idle (no usage)", str(len(report.idle_principals)), "#e5484d"),
        ("Unused grants", str(sum(f.unused_count for f in findings)), "#e5732f"),
        ("Avg risk score", f"{avg_risk:.1f}", "#d6a12d"),
        ("Validated policies", str(validated_count), "#3fb26b"),
        ("… needs review", str(tighten_summary.get("needs_review", 0)), "#d6a12d"),
    ]
    return "".join(
        f'<div class="card"><div class="card-value" style="color:{color}">{value}</div>'
        f'<div class="card-label">{html.escape(label)}</div></div>'
        for label, value, color in cards
    )


def _risk_table_rows(findings: list[PrincipalFinding]) -> str:
    rows = []
    for index, finding in enumerate(sorted(findings, key=lambda f: f.risk_score, reverse=True)):
        color, label = _risk_style(finding.risk_score)
        rows.append(
            f"<tr data-target='p{index}' class='rowlink'>"
            f"<td><span class='badge' style='background:{color}'>{finding.risk_score:.0f}</span></td>"
            f"<td>{html.escape(finding.kind)}</td>"
            f"<td>{html.escape(finding.name)}</td>"
            f"<td data-sort='{finding.granted_count}'>{finding.granted_count}</td>"
            f"<td data-sort='{finding.unused_count}'>{finding.unused_count}</td>"
            f"<td data-sort='{len(finding.used_actions)}'>{len(finding.used_actions)}</td>"
            f"<td>{'yes' if finding.is_idle else 'no'}</td></tr>"
        )
    return "".join(rows)


def generate_report(
    document: dict[str, Any],
    report: AnalysisReport,
    *,
    output: Path,
    graph_png: Path | None = None,
    tighten_result: Any = None,
) -> Path:
    """Render the standalone HTML audit report.

    Args:
        document: Unified snapshot (for header metadata).
        report: Analyzer findings for the snapshot.
        output: Destination ``.html`` path.
        graph_png: Rendered graph image to embed (rendered on demand when
            the matplotlib extra chain is importable and no path is given).
        tighten_result: Optional ``TightenResult``; when absent the
            deterministic proposer is run so every principal still shows a
            remediation block.

    Returns:
        The output path (for the CLI to print).
    """
    meta = document.get("meta", {})
    provider = meta.get("provider", "aws")
    account = meta.get("account_id", "unknown")
    lookback = meta.get("lookback_days", "?")
    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Remediations: run the tightener when the caller did not.
    if tighten_result is None:
        from typing import cast

        from ..analyzer.action_registry import ActionRegistry
        from ..analyzer.azure_registry import build_azure_registry

        if provider == "azure":
            azure_registry = build_azure_registry(document)
            subscription = meta.get("subscription_id") or meta.get("account_id", "")
            proposer = DeterministicProposer(
                cast("ActionRegistry | None", azure_registry),
                azure_subscription=subscription,
            )
            tighten_result = Tightener(
                proposer, cast("ActionRegistry", azure_registry), TightenerConfig()
            ).tighten(report)
        else:
            from ..analyzer import load_default_registry

            registry = load_default_registry()
            proposer = DeterministicProposer(registry)
            tighten_result = Tightener(proposer, registry, TightenerConfig()).tighten(report)

    remediations: dict[str, str] = {}
    fully_verified_principals: set[str] = set()
    for outcome in tighten_result.outcomes:
        if outcome.status in {"verified", "needs_review"} and outcome.policy is not None:
            if provider == "azure":
                text = json.dumps(outcome.policy, indent=2)
            else:
                text = policy_to_hcl(outcome.principal, outcome.policy)
            remediations[outcome.principal] = text
            if outcome.status == "verified":
                fully_verified_principals.add(outcome.principal)
        else:
            remediations[outcome.principal] = (
                f"// {outcome.status}: no policy generated\n"
                "// (idle principal — access review candidate, "
                "see risk reasons in the section above)"
            )

    graph_html = ""
    if graph_png is not None and graph_png.exists():
        graph_html = (
            f'<img class="graph" src="{_embed_png(graph_png)}" '
            'alt="IAM permission graph: principals, policies, actions; '
            'usage-colored" />'
        )

    findings = sorted(report.findings, key=lambda f: f.risk_score, reverse=True)
    sections = "".join(
        _detail_section(
            finding,
            remediations.get(f"{finding.kind}:{finding.name}", ""),
            index,
            is_fully_verified=f"{finding.kind}:{finding.name}" in fully_verified_principals,
        )
        for index, finding in enumerate(findings)
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>permtrim report — {html.escape(str(account))}</title>
<style>
  :root {{ --bg:#0f1216; --panel:#171b21; --line:#2a3038; --fg:#d7dde4; --muted:#8b95a1; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font:15px/1.55 -apple-system, "Segoe UI", Roboto, sans-serif;
         background:var(--bg); color:var(--fg); }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 80px; }}
  h1 {{ font-size: 26px; margin:0 0 4px; }}
  h2 {{ font-size: 19px; margin: 36px 0 12px; border-bottom:1px solid var(--line); padding-bottom:8px; }}
  h4 {{ margin: 18px 0 8px; color: var(--muted); font-size: 13px;
       text-transform: uppercase; letter-spacing:.04em; }}
  .sub {{ color: var(--muted); margin-bottom: 28px; }}
  .cards {{ display:flex; gap:14px; flex-wrap:wrap; }}
  .card {{ flex:1 1 150px; background:var(--panel); border:1px solid var(--line);
          border-radius:10px; padding:16px; }}
  .card-value {{ font-size:30px; font-weight:700; }}
  .card-label {{ color:var(--muted); font-size:12.5px; margin-top:2px; }}
  img.graph {{ width:100%; border:1px solid var(--line); border-radius:10px; margin-top:8px; }}
  table {{ border-collapse: collapse; width:100%; font-size:13.5px; }}
  th, td {{ text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); }}
  th {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em;
       cursor:pointer; user-select:none; }}
  th:hover {{ color:var(--fg); }}
  .rowlink {{ cursor:pointer; }}
  .rowlink:hover {{ background:#1c222a; }}
  .badge {{ display:inline-block; padding:2px 9px; border-radius:20px; color:#fff;
           font-size:12px; font-weight:600; }}
  details.principal {{ background:var(--panel); border:1px solid var(--line);
                      border-radius:10px; margin:10px 0; }}
  details.principal summary {{ cursor:pointer; padding:13px 16px; display:flex;
                              gap:12px; align-items:center; flex-wrap:wrap; list-style:none; }}
  details.principal summary::-webkit-details-marker {{ display:none; }}
  .principal-body {{ padding: 4px 18px 18px; }}
  .cols {{ display:flex; gap:20px; flex-wrap:wrap; }}
  .cols > div {{ flex:1 1 340px; }}
  table.actions td.src {{ color:var(--muted); font-size:12px; }}
  code {{ font:12.5px/1.5 "SF Mono", Consolas, monospace; background:#10141a;
         padding:1px 5px; border-radius:4px; }}
  ul.wildcards, ul.reasons {{ margin:4px 0; padding-left:20px; }}
  .muted {{ color:var(--muted); }}
  .policy-block {{ position:relative; }}
  .policy-block pre {{ background:#10141a; border:1px solid var(--line); border-radius:8px;
                      padding:14px; overflow:auto; font-size:12.5px; }}
  .copy {{ position:absolute; top:10px; right:10px; background:#232a33; color:var(--fg);
          border:1px solid var(--line); border-radius:6px; padding:4px 12px; cursor:pointer;
          font-size:12px; }}
  .copy:hover {{ background:#2d3642; }}
  footer {{ margin-top:48px; color:var(--muted); font-size:12.5px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>permtrim — IAM audit report</h1>
  <div class="sub">
    provider <strong>{html.escape(provider)}</strong> ·
    account <strong>{html.escape(str(account))}</strong> ·
    window <strong>{lookback} days</strong> ·
    generated {generated} · schema {html.escape(str(document.get("schema_version", "1.0")))}
  </div>

  <h2>Summary</h2>
  <div class="cards">{_summary_cards(report, tighten_result.to_dict()["summary"])}</div>

  {f"<h2>Permission graph</h2>{graph_html}" if graph_html else ""}

  <h2>Risk ranking</h2>
  <table class="risk" id="risk-table">
    <thead><tr>
      <th data-key="risk">Risk</th><th>Kind</th><th>Principal</th>
      <th data-key="granted">Granted</th>
      <th data-key="unused">Unused</th>
      <th data-key="used">Used</th><th>Idle</th>
    </tr></thead>
    <tbody>{_risk_table_rows(findings)}</tbody>
  </table>

  <h2>Principal detail</h2>
  {sections}

  <footer>
    Generated by permtrim · findings are action-level (Resource/Condition scoping is
    preserved in the tightened policies) · this file is self-contained and safe to archive.
  </footer>
</div>
<script>
(function () {{
  // Sortable risk table: click a header, toggle asc/desc.
  var table = document.getElementById('risk-table');
  var tbody = table.tBodies[0];
  Array.prototype.forEach.call(table.tHead.rows[0].cells, function (th, col) {{
    th.addEventListener('click', function () {{
      var dir = th.getAttribute('data-dir') === 'asc' ? -1 : 1;
      Array.prototype.forEach.call(table.tHead.rows[0].cells, function (h) {{
        h.removeAttribute('data-dir');
      }});
      th.setAttribute('data-dir', dir === 1 ? 'asc' : 'desc');
      var rows = Array.prototype.slice.call(tbody.rows);
      rows.sort(function (a, b) {{
        var av = a.cells[col].getAttribute('data-sort') !== null
          ? parseFloat(a.cells[col].getAttribute('data-sort'))
          : a.cells[col].textContent.trim();
        var bv = b.cells[col].getAttribute('data-sort') !== null
          ? parseFloat(b.cells[col].getAttribute('data-sort'))
          : b.cells[col].textContent.trim();
        if (av < bv) return -1 * dir;
        if (av > bv) return 1 * dir;
        return 0;
      }});
      rows.forEach(function (r) {{ tbody.appendChild(r); }});
    }});
  }});

  // Row click -> open the matching principal card.
  Array.prototype.forEach.call(document.querySelectorAll('.rowlink'), function (row) {{
    row.addEventListener('click', function () {{
      var target = document.getElementById(row.getAttribute('data-target'));
      if (target) {{ target.open = true; target.scrollIntoView({{behavior:'smooth'}}); }}
    }});
  }});

  // Copy-to-clipboard for policy blocks.
  Array.prototype.forEach.call(document.querySelectorAll('.copy'), function (button) {{
    button.addEventListener('click', function () {{
      var text = document.getElementById(button.getAttribute('data-target')).textContent;
      navigator.clipboard.writeText(text).then(function () {{
        button.textContent = 'Copied';
        setTimeout(function () {{ button.textContent = 'Copy'; }}, 1500);
      }});
    }});
  }});
}})();
</script>
</body>
</html>
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html_doc, encoding="utf-8")
    LOGGER.info("HTML report written to %s (%.1f KiB)", output, output.stat().st_size / 1024)
    return output
