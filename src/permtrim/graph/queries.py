"""Ready-to-run Cypher analysis queries over the permission graph.

Each entry is ``(title, description, cypher)``. ``write_query_script``
renders them into ``queries.cypher`` for Neo4j Browser; the same strings are
available to Python via :data:`QUERIES`.

The queries are written for the sample snapshot's story but generalize to
any ingested account:

1. **hidden paths** — effective permissions that reach the principal only
   through a GROUP (the indirect grant the user's own policy list hides).
2. **cross-policy intersection** — actions allowed by two or more different
   policies of one principal (defense-in-depth violations / drift).
3. **privilege ranking** — principals by effective-but-unused breadth,
   weighted by access level (the "who to tighten first" board).
4. **dangerous unused** — permissions-management actions granted but never
   used (the classic breach pivot).
5. **denied attempts** — ATTEMPTED edges: principals trying to use
   permissions they do not have (breakage evidence for access review).
6. **wildcard blast radius** — policies whose ALLOWS pattern expands widest.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["QUERIES", "write_query_script"]

QUERIES: list[tuple[str, str, str]] = [
    (
        "1. Hidden grants via groups (indirect permission paths)",
        "Effective permissions a principal only has because of group membership — "
        "the path a user's own policy list does not show.",
        """MATCH (p:Principal)-[:MEMBER_OF]->(g:Group)-[:GRANTED]->(pol:Policy)
MATCH (pol)-[:ALLOWS]->(a:Action)
WHERE NOT (p)-[:GRANTED]->(:Policy)-[:ALLOWS]->(a)
RETURN p.name AS principal, p.kind AS kind, g.name AS via_group,
       pol.name AS policy, a.action AS action
ORDER BY principal, action""",
    ),
    (
        "2. Cross-policy intersection (actions allowed by 2+ policies)",
        "Actions covered by more than one policy of the same principal — "
        "redundant grants that survive partial cleanups.",
        """MATCH (p:Principal)-[:GRANTED]->(pol:Policy)-[:ALLOWS]->(a:Action)
WITH p, a, collect(DISTINCT pol.name) AS policies
WHERE size(policies) > 1
RETURN p.name AS principal, a.action AS action, policies
ORDER BY size(policies) DESC, principal, action
LIMIT 50""",
    ),
    (
        "3. Privilege ranking — effective-unused breadth, access-level weighted",
        "Principals ranked by least-privilege gap: how many effective permissions are unused, weighted by access level.",  # noqa: E501 - Cypher one-liners stay readable unsplit
        """MATCH (p:Principal)-[c:CAN_USE]->(a:Action)
WHERE c.used = false
WITH p,
     count(a) AS unused_actions,
     sum(CASE coalesce(a.access_level, 'Read')
         WHEN 'Permissions management' THEN 3
         WHEN 'Write' THEN 2
         WHEN 'Tagging' THEN 1
         WHEN 'Read' THEN 0.5
         WHEN 'List' THEN 0.25
         ELSE 0.5 END) AS weighted_risk
RETURN p.name AS principal, p.kind AS kind,
       p.risk_score AS permtrim_risk, unused_actions, round(weighted_risk, 1) AS weighted_risk
ORDER BY weighted_risk DESC
LIMIT 20""",
    ),
    (
        "4. Dangerous unused — permissions management, never used",
        "Granted but never-used permissions-management actions: the exact actions an attacker wants and the principal never needed.",  # noqa: E501 - Cypher one-liners stay readable unsplit
        """MATCH (p:Principal)-[c:CAN_USE]->(a:Action)
WHERE c.used = false AND a.access_level = 'Permissions management'
RETURN p.name AS principal, a.action AS action, c.via_policies AS granted_by
ORDER BY principal, action
LIMIT 50""",
    ),
    (
        "5. Denied attempts — tried but not permitted",
        "ATTEMPTED edges: calls where every invocation failed (e.g. AccessDenied) — evidence of either breakage or someone probing for more access.",  # noqa: E501 - Cypher one-liners stay readable unsplit
        """MATCH (p:Principal)-[t:ATTEMPTED]->(a:Action)
RETURN p.name AS principal, a.action AS action,
       t.count AS calls, t.error_count AS errors
ORDER BY calls DESC, principal""",
    ),
    (
        "6. Wildcard blast radius — widest policy patterns",
        "Policies ranked by how many concrete actions their wildcard patterns expand to (expansion_size is computed from the bundled AWS dataset).",  # noqa: E501 - Cypher one-liners stay readable unsplit
        """MATCH (:Principal)-[:GRANTED]->(pol:Policy)-[al:ALLOWS]->(a:Action)
WHERE a.wildcard = true
RETURN pol.name AS policy, al.pattern AS pattern,
       a.expansion_size AS concrete_actions
ORDER BY concrete_actions DESC
LIMIT 20""",
    ),
]


def write_query_script(path: Path) -> int:
    """Render :data:`QUERIES` into a Browser-ready ``queries.cypher``."""
    lines: list[str] = [
        "// permtrim — permission-graph analysis queries.",
        "// Run in Neo4j Browser after ingesting a snapshot.",
        "",
    ]
    for title, description, cypher in QUERIES:
        lines.append(f"// {title}")
        wrapped = " // ".join(description.splitlines())
        lines.append(f"// {wrapped}")
        lines.append(cypher)
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return len(QUERIES)
