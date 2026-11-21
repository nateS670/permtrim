
# permtrim

**LLM-Powered Multi-Cloud IAM Least-Privilege Detector & Automatic Tightener**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![CI](https://github.com/nateS670/permtrim/actions/workflows/ci.yml/badge.svg)](https://github.com/nateS670/permtrim/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-190%20passed-brightgreen)](https://github.com/nateS670/permtrim/actions/workflows/ci.yml)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-checked-blue)](http://mypy-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

> **Status:** Tasks 1–5 complete — AWS **and** Azure run end to end
> (Collector → Analyzer → Graph → LLM Tightener + Guardrail). For a working
> demo: `permtrim demo` (see below); the roadmap lives in `docs/roadmap.md`.

## Working demo

`permtrim demo` — runs end to end on the sample snapshot bundled with the
package, with no AWS account, LLM, or network required.

Sample scenario: user **alice** has `AdministratorAccess` (a `*` that expands
to 20,455 actions) plus an inline `s3:Get*`; within a 30-day CloudTrail
window only `s3:GetObject` was ever used. permtrim detects the 20,454 unused
permissions and produces a single-action policy that passes the guardrail
(status `verified`: the original `Resource` scopes of the used action are
carried into the tightened policy, not widened to `"*"`).

## Azure RBAC support (Task 5)

permtrim now keeps the "multi-cloud" promise in its name: the same unified
schema, the same analyzer, the same graph, and the same guardrail chain work
for Azure subscriptions too.

| Azure AD object        | unified `kind` | rationale                                        |
| ---------------------- | -------------- | ------------------------------------------------ |
| User                   | `user`         | human sign-in (UPN as the name)                  |
| Service Principal / MI | `role`         | workload identity (the counterpart of AWS roles) |
| Group                  | `group`        | permission container (for hidden paths via groups) |

```bash
# Collect (az login or a service principal):
permtrim collect --provider azure --subscription-id $SUB_ID --days 30

# Analyze, visualize, tighten — the same commands:
permtrim analyze azure_snapshot_*.json
permtrim graph azure_snapshot_*.json --mode render
permtrim tighten azure_snapshot_*.json --proposer auto
#   -> role_<principal>.json (custom role definitions) + apply_roles.sh
#      (az role definition create commands — it CREATES the role definitions
#      only; switching assignments to the new roles and deleting old ones
#      stay manual review steps)
#   note: Azure ignores --proposer (LLM drafting is not supported for Azure
#   yet); the CLI logs a warning and uses the deterministic proposer
```

Azure-specific details:

* **Permission format**: operations in the form
  `Microsoft.Compute/virtualMachines/read` and the `Microsoft.Storage/*`,
  `*/read` wildcards; `notActions`/`notDataActions` subtractions in role
  definitions are applied by the analyzer (Contributor = `*` −
  `Microsoft.Authorization/*/Write`).
* **Action universe**: since there is no offline dataset like AWS's, the
  registry is built from the snapshot itself (role definitions + activity
  log) — wildcard expansion happens over that universe.
* **Screenshot**: a sample Azure subscription graph
  (`docs/permission_graph_azure.png`); the orange node is `mi-backup-job`'s
  `listKeys` attempt that was denied on every call, and the big red node is
  Contributor's `*`.

## Single-file HTML audit report

`permtrim report` produces a **single-file, fully self-contained** HTML audit
report for security teams and managers — no server, no external assets,
archivable (you can email it):

```bash
permtrim report data/sample_snapshot.json --output audit.html
```

What's inside: summary cards (principals / idle / unused / average risk /
verified policy count), the permission graph **embedded as base64**, a
risk table that **sorts when you click a column header**, per-principal
expandable detail cards (used/unused action tables, wildcard blast radius,
risk rationale), and **tightened policy blocks** that can be copied with one
click (AWS: Terraform, Azure: custom role JSON). The same command works for
AWS and Azure snapshots. Sample outputs are bundled under `docs/`:
`sample_report_aws.html` and `sample_report_azure.html`.

```bash
# The same command for an Azure snapshot:
permtrim report data/sample_azure_snapshot.json --output azure_audit.html
```

## Continuous integration (CI)

The GitHub Actions pipeline (`.github/workflows/ci.yml`) consists of four jobs:

1. **lint** — `ruff check` + `ruff format --check` + `mypy` (full static type checking).
2. **tables** — regenerates the CloudTrail-doc-derived service tables from
   `data/cloudtrail_data_events_2026-11.tsv` + `data/iam_dataset_prefixes.txt`
   via `scripts/build_engine_tables.py --check` (no write) and fails on drift;
   the build also fails on any residual-scan suspect that is not a reviewed
   exception, so a service can never silently fall into
   `_AWS_MANAGEMENT_ONLY_SERVICES`.
3. **test** — pytest on a Python 3.10/3.11/3.12 matrix + a `permtrim demo` CLI smoke test.
4. **neo4j-integration** — UNWIND bulk-loading integration tests against a real
   Neo4j instance started as a service container
   (these tests skip cleanly locally when `NEO4J_URI` is not set).

The tests require no accounts: the whole chain (collect → analyze → graph →
tighten) over mocked clients built on the `azure-mgmt-*` SDK models is pinned
in `tests/test_azure_collector.py` and `tests/test_azure_pipeline.py`.

## Permission graph (Neo4j, Task 3)

The unified snapshot is turned into a **permission graph** — who can access
which actions through which policy (including via groups), and what they
actually use:

```
(:Principal)-[:MEMBER_OF]->(:Group)-[:GRANTED]->(:Policy)-[:ALLOWS]->(:Action)
(:Principal)-[:GRANTED]->(:Policy)                # direct policy
(:Principal)-[:CAN_USE]->(:Action)                # effective permission (deny-aware, expanded)
(:Principal)-[:INVOKED]->(:Action)                # call that ran
(:Principal)-[:ATTEMPTED]->(:Action)              # every call was AccessDenied
```

In the rendered graph (`--mode render`), green nodes are used actions, red
nodes are granted-but-never-used permissions, orange nodes are
attempted-but-denied calls, and purple edges reveal **hidden permission
paths** arriving via groups.

```bash
# 1) Local Neo4j (a single command with Docker):
docker compose up -d                    # neo4j/permtrim-demo @ localhost:7474

# 2) Load the graph (ingest + queries + visual):
permtrim graph data/sample_snapshot.json --mode all     --neo4j-password permtrim-demo

# 3) Run the ready-made queries in Neo4j Browser (http://localhost:7474):
#    :source data/graph/queries.cypher
```

`--mode ingest` loads with the official `neo4j` Python driver (UNWIND bulk
loading, idempotent MERGE, ~4,010 nodes / ~4,009 edges < 10 s); `--mode
export` requires no driver — it produces `permtrim_graph.cypher` with
literals you can paste into the Browser. `--mode render` produces that PNG
with no database at all.

### Hidden permission paths in a single query

Six ready-made Cypher queries (produced as `data/graph/queries.cypher` by
`permtrim graph <snapshot> --mode export`; sources in
`src/permtrim/graph/queries.py`)
capture permissions arriving indirectly through groups, the intersection of
multiple policies, an access-level-weighted excess-permission ranking,
never-used *permissions-management* actions, denied attempts, and wildcard
blast radius — all captured from **a real Neo4j 5.26 instance**.

Example output: alice's hidden `EC2-Read` path coming from the `devs` group,
3,999 unused effective permissions (weighted risk 5,052), 50 dangerous
permissions-management actions, `deploy-ci`'s denied `ec2:RunInstances`
attempt, and `AdministratorAccess`'s 20,455-action blast radius — each in a
single query.

## What does it do?

It compares the IAM permissions in a cloud account (static) with the API
calls the account actually makes (dynamic) to detect **least-privilege
violations**, then produces **action-level validated** tightened Terraform
code with a local LLM (Ollama / Llama-3):

```
 ┌────────────┐  static IAM       ┌──────────────┐  unified JSON  ┌─────────────┐
 │  AWS IAM   │──policy snapshot─▶│              │───────────────▶│  Analyzer   │─┐
 │ (boto3)    │                   │  collectors  │                │ (Task 2 ✅) │ │ excess
 └────────────┘                   │ (Task 1 ✅) │                └─────────────┘ │ perms
 ┌────────────┐  CloudTrail       │              │                ┌─────────────┐ ▼
 │ CloudTrail │──activity logs───▶│              │                │  Graph DB   │ findings
 │ lookup     │                   └──────────────┘                │  (Task 3)   │
 └────────────┘                          ▲                       └─────────────┘
 ┌────────────┐  Azure RBAC              │ providers pluggable   ┌─────────────┐
 │ Azure (Task│──────────────────────────┘ via factory           │ LLM +       │ tightened
 │     5)     │                                                  │ GUARDRAIL ✅│──▶ Terraform
 └────────────┘                                                  │  (Task 4)  │  (action-level
                                                                 └─────────────┘   validated)
```

### Why is this "a real security product" and not an LLM wrapper?

1. **Wildcard matching is dataset-backed.** Patterns in IAM policies such as
   `s3:Get*` / `ec2:*` cannot be matched against singular action names in
   CloudTrail (GetObject, RunInstances). permtrim bundles the
   **iam-definition.json** dataset that
   [policy_sentry](https://github.com/salesforce/policy_sentry) generates
   from the AWS Service Authorization Reference (445 services / 20,455
   actions + access levels), so it knows a pattern like `ec2:*` actually
   corresponds to 780 actions. CloudTrail↔IAM name exceptions are handled
   too (the `s3:ListBuckets` event is actually authorized by the
   `s3:ListAllMyBuckets` action). The dataset is pinned in
   `src/permtrim/analyzer/data/iam-definition.json.gz` (provenance recorded
   in `action_registry.py::DATASET_SOURCE`); it is a snapshot of the AWS
   service catalog, so brand-new services are unknown to it until the
   dataset is regenerated with policy_sentry.

2. **LLM output is never handed to the user directly.** Llama-3-class models
   invent non-existent actions (`s3:GetObjekt`, `ec2:RunInstance`). The
   guardrail layer runs every draft through these checks:
   - **Structure**: valid IAM policy syntax with recognized statement keys.
   - **Negation-free**: `NotAction`/`NotResource` (and Azure
     `notActions`/`notDataActions`) drafts are rejected outright — a
     `NotAction` Allow grants a huge implicit space the new-permission check
     cannot reason about. First-version scope: explicitly listed actions.
   - **Hallucination check**: does every action exist in the 20,455-action dataset?
   - **Coverage**: is every action the principal used still allowed?
     (otherwise the tightening breaks production)
   - **No new permissions**: does the draft introduce a permission the
     principal never had? (blocks the LLM from "fixing" coverage with
     `Action: "*"`)
   - **Resource scope**: when the original grants recorded resource scopes,
     a draft that widens them (e.g. `"*"` where the principal only ever had
     `arn:aws:s3:::corp-data/*`) is rejected — shrinking the action count
     must not grow the blast radius per action.
   A rejected draft is fed back to the LLM with its error; after 3 attempts
   a deterministic fallback (the observed actions themselves) kicks in —
   **no code path ever produces an unvalidated policy**. The output status is
   honest about the level of validation: `verified` (action + resource
   scopes) vs `needs_review` (action-level only, e.g. Azure where role
   definitions carry no resource scopes). A **truncated activity window**
   (AWS API cap hit) stops automatic tightening entirely
   (`insufficient_data`) — removing permissions based on incomplete usage
   data is how tightening breaks production.

3. **The simulator hook is ready.** Once a boto3 `iam:SimulatePrincipalPolicy`
   wrapper is attached via `Guardrail(simulator=...)`, AWS's own evaluation
   gets the final say too (skipped in offline mode).

## Installation

```bash
git clone https://github.com/nateS670/permtrim.git
cd permtrim
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[graph,azure,dev]"
pytest          # 190 tests — NO AWS ACCOUNT / LLM REQUIRED
```

AWS authentication uses the standard boto3 chain. The **read-only** IAM
permissions needed for the collection account:

```
sts:GetCallerIdentity
iam:GetAccountAuthorizationDetails
iam:GetPolicy
iam:GetPolicyVersion
cloudtrail:LookupEvents
```

## Usage

```bash
# 0) See it immediately: offline end-to-end demo (no AWS/LLM needed)
permtrim demo

# 1) Collect: static IAM + CloudTrail activity in one unified JSON
permtrim collect --profile prod --region eu-west-1 --days 30

# 2) Analyze: per-principal excess permissions + risk score
permtrim analyze data/aws_snapshot_*.json

# 3) Tighten: action-level validated policy + Terraform
permtrim tighten data/aws_snapshot_*.json --proposer auto
#    (uses llama3.2 if Ollama is running, otherwise the deterministic proposer)
#    statuses: verified / needs_review / idle / insufficient_data
#    (a truncated activity window blocks tightening by default;
#     --allow-truncated-window is the explicit override)

# 4) Visualize: load the permission graph into Neo4j / render a PNG
permtrim graph data/aws_snapshot_*.json --mode all --neo4j-password permtrim-demo

# With an LLM (local):
ollama pull llama3.2 && ollama serve
permtrim tighten data/snapshot.json --proposer ollama --ollama-model llama3.2
```

Python API:

```python
from permtrim.collectors import AWSCollector, AWSCollectorConfig, write_json_document
from permtrim.analyzer import Analyzer
from permtrim.llm import Tightener, TightenerConfig, OllamaProposer, policy_to_hcl
from permtrim.analyzer import load_default_registry

collector = AWSCollector(AWSCollectorConfig(region="eu-west-1", profile="prod"))
document = collector.collect(lookback_days=30)  # unified static + dynamic document
write_json_document(document, "snapshot.json")

report = Analyzer().analyze_document(document)  # findings: excess permissions
registry = load_default_registry()  # the 20,455-action dataset

tightener = Tightener(OllamaProposer(), registry, TightenerConfig(max_attempts=3))
result = tightener.tighten(report)  # propose → guardrail → retry
for outcome in result.validated:  # verified + needs_review
    print(policy_to_hcl(outcome.principal, outcome.policy))
```

## Unified snapshot schema (v1.0)

The JSON document produced by `collect()` is the single input to all later
stages (see the bundled example `data/sample_snapshot.json`):

```jsonc
{
  "meta":       { "schema_version": "1.0", "provider": "aws", "account_id": "…",
                  "lookback_days": 30, "window": {"truncated": false} },
  "identities": { "users": […], "roles": […], "groups": […], "managed_policies": {…} },
  "activity":   { "usage": { "user:alice": { "action_counts": {"s3:GetObject": 2},
                                              "error_action_counts": {} } } },
  "principals": [ { "kind": "user", "name": "alice",
                    "permission_sources": { "inline_policies": {…},
                                            "attached_managed_policies": [documents included],
                                            "via_groups": ["devs"] },
                    "observed_activity": { "action_counts": {"s3:GetObject": 2} } } ],
  "unmatched_activity": [ … ]   // root, deleted identities, cross-account calls
}
```

## Analyzer output

For every principal: the expanded **granted** action set (wildcards are
opened against the dataset, group permissions are folded into members,
explicit Deny is dropped), the **used** actions (only calls that ran — an
action where every call errored is flagged `error_only`), the unused ones,
wildcard sources, and a **risk score** between 0–100 (idle principal +40,
access-level-weighted unused permissions ≤30, wildcards ≤20,
permissions-management ≤10).

The risk score is a **prioritization score, not a probability of
compromise**: it ranks which principal to tighten first (idle accounts with
broad unused grants score highest), and says nothing about whether an attack
is likely. Permission boundary ARNs are collected and surfaced in the
report; effective permissions (identity policies ∩ boundary) are **not**
evaluated — the analysis scope is identity-based policies only (no SCPs,
session policies, or resource-based policies either).

## Limitations (deliberate design decisions)

| Limitation | Why | Plan |
| --- | --- | --- |
| CloudTrail `lookup_events` covers the **last 90 days** only | AWS API limit | S3 → Athena pipeline (backlog) |
| At most **10,000 events**; `window.truncated=true` when cut off — and the tightener then **refuses to run** (`insufficient_data`) | AWS API limit | Same; `--allow-truncated-window` is the explicit override |
| Event history is **regional** | AWS API limit | Sample per region; merge |
| `lookup_events` returns **management events only** — data-plane calls (e.g. `s3:GetObject` on objects, `sns:Publish`, `appconfig:GetLatestConfiguration`) are **never visible to permtrim**, even when a trail records data events (those go to S3 / CloudTrail Lake, a different pipeline) | AWS API design (LookupEvents does not search data events) | CloudTrail Lake / S3→Athena ingestion (backlog); until then unused-looking data-plane grants are reported as **unknown usage**, excluded from `unused_actions`, and the tightener **stops** for principals holding them (`--allow-unknown-data-plane-usage` overrides). Classification is per **ACTION**, not per service (transcribed from the CloudTrail data-event docs into `engine.py`: the complete resource-type table — 276 rows / 170 services — mapped to IAM prefixes), and **fail-closed**: documented data events (S3 object ops, `sns:Publish`, Lambda `Invoke`, DynamoDB item ops, SQS messaging, EBS direct APIs, AppConfig retrieval, SWF workflow activity, the RDS/Redshift Data APIs, Greengrass V2 core-device calls, Bedrock Mantle project inference calls, Nova Act workflow calls, Amazon Connect Health data-plane calls, ...) get the unknown-usage protection, documented management events (`s3:CreateBucket`, `sns:Subscribe`, ... ) are analyzed normally, and anything the classifier cannot **positively verify** — an action of a mixed service in **neither** table, a service in neither verification set (a brand-new AWS service, a typo'd prefix, a catalog service the tables do not cover) — defaults to the safe side: unknown usage, **explicitly listed** in `unclassified_actions` so a reviewer can tell "invisible by documentation" from "the table did not know this action". `management` — the removable side — is never inferred from IAM-catalog presence alone: AWS AppConfig sat in the catalog while its data events (since 2024-01) were invisible to `lookup_events`, so a service is only management-verified when its IAM prefix appears in **no** row of the complete data-event resource-type table. Residual limitation: actions of the ~90 data-event services without a transcribed per-action split (Glue, SageMaker, Timestream, ...) stay `unclassified` until their tables are added — manual-review noise, never a silently-removable grant |
| Azure Activity Log records **control-plane** operations only; data-plane calls (Blob reads/writes, Key Vault `get`, Cosmos DB item ops, ...) live in each resource's diagnostic settings, a pipeline permtrim does not ingest | Azure API design (Activity Log is control-plane) | Resource diagnostic-settings ingestion (backlog); until then Azure data-plane grants are kept in a **separate statement** (the matcher splits `actions` vs `dataActions` and the engine carries `Statement.data_plane` end to end), reported as **unknown usage**, and the tightener **stops** — the deterministic proposer routes the *used* data-plane actions back into `dataActions` from the finding's own classification (not a hardcoded prefix), so a data-plane grant stays on the data plane for every resource provider |
| The analyzer does **not** evaluate Resource/Condition (action-level audit view); resource scopes of the original grants are preserved where recorded and widening drafts are rejected, but unknown scope ⇒ `needs_review`, never silently `"*"` | Scoping decisions need resource-level usage data | `Resource` carried from original policies; simulator hook for full fidelity. AWS drafts must also carry a non-empty `Resource` element (the guardrail rejects a missing / empty / wrong-typed `Resource` so IAM's `"*"` default cannot widen the blast radius) |
| Permission boundaries / SCPs / session policies / resource-based policies are **not** evaluated | Effective-permission evaluation is out of scope for v1 | Identity-based policies only (documented here); boundary ARNs surfaced in the report |
| Azure: the action universe is built from the snapshot itself (role definitions + activity log), so `*` expansion is a lower bound, not the full Azure operation set; tightened Azure roles are therefore always `needs_review` | No offline Azure action dataset exists | Future: vendored Azure operations catalog |
| Works without an LLM too | By design | The deterministic proposer is the reference implementation |

## Architecture: a new cloud provider = one new class

Everything provider-specific is encapsulated under `collectors/`; the
Analyzer / Guardrail / LLM modules see only the unified schema. To add
Azure (Task 5): implement the three abstract methods of `BaseCollector` +
add an `"azure"` entry in `factory.py`. The merge, the per-principal view,
and JSON writing are handled by the base class.

## Development

```bash
pip install -e ".[graph,azure,dev]"
pytest                          # 190 tests: Stubber-based collector, analyzer,
                                # guardrail (incl. a fake LLM that hallucinates), CLI
pytest --cov=permtrim           # coverage report
ruff check . && mypy            # lint + type checking
```

A highlight of the test suite: `TestHallucinationLoop` — verifies end to end
that a scripted fake LLM that hallucinates gets rejected by the guardrail,
that the error message is fed back to the model, and that it either fixes
itself on the second attempt or falls back to the deterministic proposer.

### What the tests actually guarantee

Rather than a raw count, these are the security properties pinned by
regression tests (each names its test):

* A draft using `NotAction`/`NotResource` (or Azure `notActions`) is
  rejected — negation cannot smuggle in permissions the no-new-permissions
  check cannot see. (`test_notaction_draft_rejected`,
  `test_notresource_draft_rejected`, `test_azure_notactions_draft_rejected`)
* A draft widening resource scopes (`"*"` where the original grant was
  `arn:aws:s3:::corp-data/*`) is rejected; the deterministic proposer
  preserves original scopes and splits distinct scopes into separate
  statements. (`test_resource_scope_widening_rejected`,
  `test_deterministic_proposer_preserves_original_resources`)
* A truncated activity window stops automatic tightening before the proposer
  is even consulted. (`test_truncated_window_blocks_tightening`,
  `test_tighten_truncated_window_refuses`)
* Without resource provenance the output says `needs_review`, never
  "verified". (`test_no_provenance_falls_back_to_star_and_needs_review`)
* `Action: "*"` fixes for coverage are rejected as new permissions;
  hallucinated actions are quoted back to the model for the retry.
  (`test_wildcard_fix_coverage_rejected_as_new_permissions`,
  `test_hallucinated_action_rejected`)
* Unused actions cannot be re-granted: an LLM that proposes the old broad
  grant (literal or wildcard) back is rejected. (`TestUnusedRemoval` —
  `test_star_draft_for_admin_principal_rejected`,
  `test_literal_regrant_of_unused_actions_rejected`)
* A `Deny` statement cannot ride along in a tightened policy (it would
  override the validated Allows outside the coverage check).
  (`TestDenyStatementRejected` — `test_allow_plus_deny_same_action_rejected`,
  `test_deny_only_draft_rejected`)
* Used actions originally granted under a `Condition` element are never
  auto-replaced; the tightener reports `manual_review` with the real reason
  instead of "idle". (`TestIdleVsUnknownOrdering` —
  `test_conditional_only_no_usage_is_manual_review_not_idle`)
* AWS data-plane classification is per action **and fail-closed**:
  documented data events (`sns:Publish`, `s3:GetObject`, ...) with no
  observed usage stop the tightener (`unknown_data_plane_usage`),
  documented management events (`s3:GetObject`'s neighbors like
  `s3:CreateBucket`, `sns:Subscribe`, ...) are removable without review
  noise, and anything the classifier cannot **positively verify** — an
  action of a mixed service missing from both tables, or a service in
  neither verification set (a brand-new AWS service, a typo'd prefix, a
  catalog service the transcribed tables do not cover) — classifies as
  `unclassified`, is treated as data-plane (unknown usage, never silently
  removed) and is listed in `unclassified_actions`. `management` is never
  the default assumption and never follows from IAM-catalog presence
  alone (the AppConfig lesson: `appconfig:GetLatestConfiguration` has
  been a data event since 2024-01 while the service sat in the IAM
  catalog all along); it requires the transcribed CloudTrail tables to
  positively verify the service contributes no data events.
  (`TestDataPlaneClassification` — incl.
  `test_unknown_service_is_unclassified_fail_closed`,
  `test_unknown_service_classification_with_custom_registry`,
  `test_appconfig_data_events`,
  `test_data_event_service_without_action_table_is_unclassified`,
  `test_unknown_service_grant_is_unknown_usage_not_unused`,
  `test_unused_sns_publish_stops_tightener`,
  `test_unused_management_action_does_not_stop_tightener`,
  `test_greengrass_is_data_event_service` / `test_greengrass_actions_are_not_management`
  — the Greengrass V2 regression: `AWS::GreengrassV2::ComponentVersion` /
  `AWS::GreengrassV2::Deployment` rows must map to the `greengrass` IAM
  prefix, so `greengrass:GetComponentVersionArtifact` (a core-device data
  call, invisible to `lookup_events`) can never classify as removable
  management; per-action tables are still untranscribed, so every
  greengrass action stays `unclassified` — the safe side)
* Every AWS Allow statement must carry a non-empty `Resource` of the right
  shape, so IAM's implicit `"*"` default cannot widen the blast radius.
  (`TestResourceElementRequired`)
* Azure `dataActions` cannot be smuggled into `actions` (or the reverse) —
  the guardrail validates the category split against the original role for
  every resource provider, not just Blob, **including wildcard entries**:
  `Microsoft.Storage/*` in `actions` is rejected when it matches any
  data-only grant of the original role (real Azure RBAC grants data-plane
  operations from `dataActions` only, so such a draft silently drops
  working data access), and the converse wildcard misroute is rejected
  symmetrically; a wildcard that stays inside its own category passes.
  (`TestAzureCategoryMismatch` — Key Vault and Cosmos DB cases, the
  feedback-loop test, and the `Microsoft.Storage/*` wildcard trio
  `test_wildcard_in_actions_covering_data_grant_rejected`,
  `test_wildcard_in_dataactions_covering_control_grant_rejected`,
  `test_category_clean_wildcard_passes`)
* Azure data-plane grants land in `unknown_usage_actions` and the
  deterministic proposer routes used data-plane actions back into
  `dataActions` by the finding's own classification, not a storage prefix.
  (`TestAzureDataPlaneUnknownUsage`,
  `test_opt_in_routes_used_data_plane_to_data_actions`)

## License

Apache-2.0 — see the `LICENSE` file. The bundled IAM action dataset
(generated from the AWS Service Authorization Reference by the
[policy_sentry](https://github.com/salesforce/policy_sentry) project) is
distributed under the same license.
