# Contributing

Changes should keep the project useful as a small, reproducible Linux security prototype rather than expanding it into a collection of unrelated demos.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Run the automated checks before opening a pull request:

```bash
python -m compileall -q src shared
pytest -q
```

## Change guidelines

- Keep privileged behavior explicit. New enforcement actions must not become remotely reachable by default.
- Prefer deterministic tests over long-running system demonstrations.
- Put manual stress, network, or attack-simulation utilities under `tools/`, not under pytest collection paths.
- Keep generated datasets, trained models, local logs, credentials, and machine-specific configuration out of Git.
- Document what a detector actually observes. Avoid claiming syscall, network, or eBPF visibility when the implementation only infers behavior from `/proc`.
- Add tests for bug fixes and for code that changes enforcement decisions.
- Do not silently broaden the default privilege or network exposure of the stack.

## Pull requests

A focused pull request should explain:

1. the problem being solved;
2. the behavior before and after the change;
3. how it was tested;
4. any privilege, data-handling, or network-exposure impact.

Security-sensitive changes should also note their failure mode and safe default.
