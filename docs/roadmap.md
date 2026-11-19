# permtrim — Roadmap

As of v1.0.0 the chain runs end to end on two providers: Tasks 1–5 are
complete — Collector → Analyzer → Graph → LLM Tightener + Guardrail for
AWS **and** Azure. The items below are independent stages that operate on
the unified snapshot schema.

## Status summary

| Task | Module | Status |
| --- | --- | --- |
| 1 | AWS IAM + CloudTrail collection (`collectors/aws_collector.py`) | ✅ Complete (0.1.0) |
| 2 | Least-privilege analyzer | ✅ Complete (0.2.0) |
| 3 | Graph database processing (Neo4j) | ✅ Complete (0.5.0) |
| 4 | Terraform generation with LLM + guardrail (Ollama / Llama-3) | ✅ Complete (0.2.0) |
| 5 | Azure integration (`collectors/azure_collector.py`) | ✅ Complete (1.0.0) |

## Post-v1.0.0 ideas

- A third provider (GCP IAM) — follow the "adding a new provider" guide in
  `CONTRIBUTING.md`.
- Live guardrail verification based on `iam:SimulatePrincipalPolicy`.
- A comparison mode that tracks permission bloat (drift) over time.

## Task 2 — Least-privilege analyzer (`analyzer/`) — ✅ COMPLETE

Input: the unified snapshot (`principals[]`). Output: `findings[]` — per
principal, the sets of "granted but unused" permissions.

- Parse policy documents statement by statement (Effect, Action,
  NotAction, Resource, Condition, wildcard expansion of `s3:Get*`).
- Fold permissions arriving through groups into the member; intersect with
  the permission boundary.
- Classify unused permissions: never used / error-only (`error_action_counts`
  > 0 and `action_counts` == 0 → the permission never actually works) /
  ambitious wildcards.
- Risk score: wildcard ratio × usage frequency.

## Task 3 — Graph database (`graph/`) — ✅ COMPLETE

The model as implemented (builder, `graph/builder.py`):
`(:Principal:User|Role)`, `(:Group)`, `(:Policy:Managed|Inline)`,
`(:Action {service, access_level, wildcard, expansion_size})`;
edges `MEMBER_OF`, `GRANTED {via_group}`, `ALLOWS {pattern}`,
`CAN_USE {used, access_level, via_policies}` (effective permission from the
analyzer), `INVOKED {count}`, `ATTEMPTED {count, error_count}` (attempts
where every call got AccessDenied).

Paths:
- **ingest**: official neo4j driver, UNWIND bulk loading, idempotent MERGE
  (key constraints), `--clear` (4,010 nodes live in < 10 s);
- **export**: driver-free literal `permtrim_graph.cypher` (can be pasted
  into the Browser with `:source`) + `queries.cypher` (6 queries);
- **render**: database-free PNG (the README image).

Ready-made queries (`graph/queries.py`): hidden permission paths via
groups, cross-policy intersection, weighted excess-permission ranking,
unused permissions-management, denied attempts, wildcard blast radius.
One command with Docker: `docker compose up -d` + `permtrim graph
<snapshot> --mode ingest`.

## Task 4 — Terraform generation with an LLM (`llm/`) — ✅ COMPLETE

Local inference (Ollama, default `llama3.2`; data never leaves the machine).
Flow: findings → LLM draft → **guardrail** (hallucination check, coverage,
no-new-permissions, structure) → on rejection the error is fed back
(3 attempts) → deterministic fallback if still failing. Accepted drafts are
converted into `aws_iam_policy` HCL (heredoc JSON). The
`Guardrail(simulator=...)` hook is ready to take a boto3
SimulatePrincipalPolicy wrapper; skipped in offline mode. Tested scenarios:
an LLM that hallucinates gets rejected and fixes itself with feedback; an
LLM that tries to "fix" coverage with `Action: "*"` gets rejected;
deterministic fallback for a stubborn LLM.

## Task 5 — Azure RBAC (`collectors/azure_collector.py`) — ✅ COMPLETE

Concept mapping: User→`user`, Service Principal/Managed Identity→`role`,
Group→`group`; role definitions land in the managed-policy catalog
(`builtin`/`custom`). Clients are injectable through the constructor (in
tests, fake clients built from the real `azure-mgmt` model classes — no
account needed); AAD resolution goes through the `PrincipalResolver`
protocol.

Analyzer: `PolicySet` reads both formats (AWS `Statement` + Azure
`permissions`/`notActions`/`dataActions`); `AzureActionRegistry` builds the
snapshot universe; in the risk score, `Microsoft.Authorization/*` operations
count as permissions-management. The guardrail verifies Azure drafts too;
DeterministicProposer produces custom role JSON (applied with
`az role definition create`).

Sample data: `data/sample_azure_snapshot.json` (generated from the mock SDK
chain: `scripts/make_azure_sample.py`).

## Task 6 — CI & quality pipeline — ✅ COMPLETE (first slice)

`.github/workflows/ci.yml`: a lint job (ruff check + format check + mypy,
0 errors), a Python 3.10–3.12 test matrix (pytest + `permtrim demo` smoke),
and an integration job with a Neo4j service container
(`tests/test_neo4j_integration.py` — clean skip without `NEO4J_URI`). The
local quality pipeline uses the same commands: `ruff check`,
`ruff format --check`, `mypy`, `pytest`.

Also in this slice: `permtrim report` — a single-file standalone HTML audit
report (summary cards, embedded graph, sortable risk table, principal
details, guardrail-verified policy blocks; AWS Terraform / Azure custom
role JSON).

## Task 6 remaining candidates (per feedback)

- CloudTrail → S3 → Athena pipeline (to go beyond the 90-day lookup limit).
- Pre-verification with the IAM Policy Simulator (could be part of Task 4).
- CI: GitHub Actions — pytest + ruff + mypy; Neo4j with testcontainers.
- `permtrim report` command: HTML report generation.
