# Git hooks

Use local hooks for fast feedback and protected-branch CI for enforcement. Local
hooks can be skipped with Git options, so they are not a security boundary.

Add this repository to `.pre-commit-config.yaml` at an immutable release tag:

```yaml
repos:
  - repo: https://github.com/rakeshcheekatimala/skilltrustops
    rev: v0.1.0
    hooks:
      - id: skilltrustops
        args: [hook, path/to/skills, --policy, skilltrustops.yaml]
        stages: [pre-commit, pre-push]
```

Install both stages:

```bash
pre-commit install
pre-commit install --hook-type pre-push
```

The hook scans complete packages and returns the same exit codes as CI. Code `1`
stops the Git operation for findings, and code `2` stops it because the result is
unreliable. Run the same command in required CI and upload SARIF there.
