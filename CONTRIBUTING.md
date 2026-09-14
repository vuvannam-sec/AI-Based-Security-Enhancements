# Contributing

This project favors small, reviewable changes that improve correctness, observability, or the safety of the local research workflow.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

Before opening a pull request, run:

```bash
python -m compileall -q src shared
ruff check src shared
pytest -q
```

## Conventions

- Keep privileged behavior isolated in `src/enforcer/`.
- Keep service defaults bound to loopback.
- Do not weaken control-token checks to simplify a demo.
- Add validation at API boundaries before values reach OS primitives.
- Prefer deterministic tests with mocks over tests that modify real processes or cgroups.
- Keep stress workloads and behavioral demos under `scripts/`, not in pytest modules.
- Distinguish measured behavior from assumptions in documentation; synthetic-model metrics are not real-world detection benchmarks.
- Do not commit generated data, model artifacts, credentials, or machine-specific state.

Changes to security-sensitive behavior should include tests for both the allowed path and the rejected path.
