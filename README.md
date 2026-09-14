# AutoRemediate (`cibi-dev/auto-remediate`)

Autonomous CLI remediation engine that fixes static vulnerabilities (CWE-78 subprocess injection, missing timeouts) under strict guardrails.

## Highlights
- **Agentic Safety Guardrails:** Hard-blocks modifications on authentication, cryptography, or database migration files.
- **Deterministic AST Fixers:** Guarantees syntax integrity and pre-commit test validation.
- **Zero Hallucinated Fixes:** All proposals must compile and pass tests before branch creation.

## Quickstart
```bash
pip install -e ".[dev]"
auto-remediate --help
pytest -v
```
