# Security Policy

permtrim is a security tool that audits cloud IAM environments, so the
project itself must be held to the same standard.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | ✅ |
| < 1.0   | ❌ |

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

If you found a security vulnerability:

1. Use GitHub's **"Report a vulnerability"** form: **Security** tab on the
   repository page → **Report a vulnerability**.
   (Direct link: `https://github.com/nateS670/permtrim/security/advisories/new`)
2. If the GitHub form is unavailable, open a **private** issue with the same
   information and prefix the title with `[SECURITY]`; maintainers will keep
   the issue private.

Please include the following in your report:

- The module/file and line range where the vulnerability lives
- An impact assessment (e.g. sensitive data disclosure, privilege escalation,
  a false-negative analysis bug)
- Reproduction steps or a proof-of-concept
- Your suggested fix, if any

## Response time targets

- **First response:** within 3 business days
- **Triage and classification:** within 7 days
- **Critical fix:** within 30 days (published together with a security
  advisory and a patch release)

## Scope

**In scope:**

- All code under `src/permtrim/` (collectors, analyzer, graph, tightener,
  guardrail, report, CLI)
- Injection surfaces of the generated outputs: the HTML report (`report/`),
  Neo4j Cypher scripts (`graph/`), Terraform files (`tightener/`)

**Out of scope:**

- Misconfigurations in the user's own cloud account
- Vulnerabilities in the AWS/Azure APIs themselves (report those to the
  provider's process)
- Vulnerabilities in third-party dependencies pulled by `pip install`
  (still report them — we will forward them upstream)

## Security principles (for contributors)

- Dynamic values (principal names, policy documents) must **always** be
  escaped when written into outputs — `html.escape()` in the HTML report,
  parameterized queries in Cypher scripts. This is why the tests run with
  real `<script>` payloads; if you add a new output surface, you must add a
  similar injection test (see `tests/test_report.py`).
- Collectors make **read-only** API calls only; a new provider collector
  must not break this principle.
- LLM output is never written into Terraform unverified: the guardrail layer
  cannot be bypassed (see `src/permtrim/tightener/guardrail.py`).
