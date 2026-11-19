# Contributing

Thanks for contributing! permtrim is an audit tool that reduces multi-cloud
IAM permissions to least privilege. Read this guide before contributing —
especially the **adding a new cloud provider** section: every layer of the
project branches by provider, and skipping one spot leads to silent bugs.

## General flow

1. Fork the repo and open a feature branch:
   `git checkout -b feat/gcp-collector`
2. Make your change (following the architecture notes below).
3. All quality gates must be green:
   ```bash
   ruff check .            # lint
   ruff format --check .   # format
   mypy src/               # type checking (disallow_untyped_defs = true)
   pytest                  # 115 tests + 4 integration skips
   ```
4. Open a PR. Keep the title short and imperative (`Add GCP collector`,
   not `I added...`).

## PR rules

- **One PR does one job.** Do not send a new feature + an unrelated refactor
  in the same PR.
- **Tests are mandatory.** A new code path is not merged without tests. For
  collector changes, a test written with a stub/fake client must come with a
  CLI smoke test (without injecting the stub into the real factory —
  injection can mask real paths like `session.client(...)`).
- **Test fixtures must be defined in `conftest.py`.** `@pytest.fixture`
  objects in an accompanying module (e.g. `azure_fixtures.py`) are not seen
  by pytest; data/fakes can live there, but fixture objects belong in
  conftest.
- **Fixtures must return factories.** Stubber responses are mutated in
  place; a module-level fixture shared across tests lets tests pollute each
  other. The pattern:
  ```python
  @pytest.fixture
  def auth_details_payload():
      return lambda: copy.deepcopy(_BASE_PAYLOAD)  # a fresh copy per call
  ```
- **Docstrings and README stay in sync.** If user-visible behavior changes,
  update README + `docs/roadmap.md`.
- **Do not touch the version number.** Versions are cut by maintainers at
  release time.
- **No merge before CI is green.** CI runs lint + mypy + tests + integration
  (Neo4j service container) on a Python 3.10–3.12 matrix.
- **Commit messages** follow the conventional style: `feat:`, `fix:`,
  `docs:`, `test:`, `refactor:`.

## Architecture: how the data flows

```
Collector (provider-specific)        → unified JSON snapshot
Analyzer (provider-aware)            → findings[] (risk score, unused permissions)
Graph builder / render (per-provider registry) → Neo4j + PNG
Tightener + Guardrail (LLM output)   → verified Terraform
```

All layers share a single schema: `principals[]`, `meta.provider`, activity
records. Contributions must not break this schema.

## Adding a new cloud provider

Example: GCP IAM support. The complete list of touch points (drawn from the
Azure integration — miss one and you get silent bugs where AWS datasets try
to validate Azure actions):

1. **Collector** — `src/permtrim/collectors/gcp_collector.py`:
   inherit from `BaseCollector` and implement the three abstract methods:
   `collect_iam_snapshot()`, `collect_activity(lookback_days)`,
   `_provider_meta()`. Make **read-only** API calls only.
   Watch out for readonly fields on SDK models: **instantiate first, assign
   readonly fields afterwards** (readonly fields passed to the constructor
   are silently dropped).
2. **Factory** — `src/permtrim/collectors/factory.py`: register the provider
   in `SUPPORTED_PROVIDERS`; also add it to the `choices=["aws", "azure"]`
   list in `cli.py`.
3. **Action registry** — if there is no offline action dataset for GCP,
   build the registry from the snapshot itself (action literals in role
   definitions + operations from activity records). Azure's
   `SnapshotActionRegistry` is the reference implementation of this pattern.
4. **Analyzer** — `src/permtrim/analyzer/engine.py`: if there is a branch on
   `meta.provider` (see the `provider == "azure"` case), add the new
   provider. **Careful:** in AWS, Action/NotAction cannot coexist in one
   statement; in Azure, `actions` + `notActions` do live together in the
   same role definition (Contributor: `*` minus
   `Microsoft.Authorization/*/Write`). The matcher must always **match
   actions first, then subtract notActions**.
5. **Graph** — `src/permtrim/graph/builder.py`: per-provider registry
   selection (see the `provider == "azure"` branch). Wildcard semantics can
   differ: in Azure, `*` crosses `/` separators; match the whole string with
   `fnmatch`, do not split on `:`/`/` and match parts.
6. **Tightener** — the `provider == "azure"` branches in `cli.py` and the
   templates under `tightener/`: adapt them to the new provider's policy DSL
   (IAM bindings for GCP). **The guardrail is never skipped.**
7. **Sample data** — add `src/permtrim/data/sample_gcp_snapshot.json`;
   `permtrim demo` and the CLI smoke tests must run with this file.
8. **Tests** — fake clients must hold instance attributes in `__init__`
   (NOT class attributes — that leaks state between tests):
   ```python
   class FakeClient:  # wrong: class Ops: filters = []
       def __init__(self):
           self.activity = FakeOps()  # right: a fresh instance per test
   ```
   Add a provider-specific test file for analyzer/graph/tightener; the
   existing `tests/test_azure*.py` files can be used as templates.
9. **Docs** — the provider section in README, the status table in
   `docs/roadmap.md`, and a `docs/sample_report_gcp.html` example.

## Code style

- `ruff` (line-length 110, rules E/F/I/N/UP/B/SIM) and `ruff format` are
  the contract; they are not up for debate.
- All functions are typed (`disallow_untyped_defs`). Public API docstrings
  follow the Google style: Args / Returns / Raises.
- Comments and docstrings are in English; user-facing docs (README) are
  English too. When unsure, follow the language of the file you are editing.
- `# noqa` only when unavoidable, and **on the offending line**.

## Questions / discussion

If something is unclear, open an issue; for architectural decisions, write
a short design note in the issue (problem, alternatives, proposal).
