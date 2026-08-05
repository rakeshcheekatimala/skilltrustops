# Contributing

Open an issue before changing a public schema, verdict, policy profile, or rule
meaning. Every rule change needs positive and benign fixtures, redacted evidence,
remediation text, and a changelog entry. Do not weaken bounds on untrusted files.

Run:

```bash
uv sync --extra dev
uv run pytest --cov=skilltrustops --cov-report=term-missing
uv run ruff check .
uv run mypy src
uv build
```

Contributions must be Apache-2.0 compatible and must not add copied third-party
skill bodies without documented redistribution rights.
