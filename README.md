# AI-Based Security Enhancements

A Linux host-behavior monitoring prototype that combines `/proc` telemetry, lightweight machine-learning classification, rule-based signals, and cgroup-backed response.

The project is designed for local security research, operating-systems experimentation, and reproducible demonstrations. It is **not** an endpoint-protection product and should not be treated as a production security boundary.

## Architecture

```text
                  read-only telemetry
                       /proc
                         |
                         v
                    +---------+
                    | Sensor  |
                    +----+----+
                         |
               event     |      prediction
                         +-----------> +------------+
                         |             | ML service |
                         |             +------------+
                         |
                         v
                  +-------------+
                  | Orchestrator|
                  +------+------+
                         |
                         | authenticated control request
                         v
                    +---------+
                    |Enforcer |
                    +----+----+
                         |
                    cgroup / signal
                         |
                         v
                   Linux processes

              Streamlit UI -> local service APIs
```

The Sensor and ML service produce decisions; the Enforcer is the privileged control plane. Mutating endpoints require a shared bearer token, and the bundled launcher binds every service to loopback by default.

A deeper description of the data flow and trust boundaries is in [`docs/architecture.md`](docs/architecture.md).

## Current scope

Implemented:

- Linux process sampling from `/proc`;
- normalized event records and CSV export;
- RandomForest training and inference over generated data;
- rule-assisted detection for selected host behaviors;
- CPU and memory throttling through cgroups;
- explicit process termination through the Enforcer;
- local dashboard, service status, detection history, and manual controls;
- authenticated local control operations;
- automated syntax, lint, and unit/service tests in GitHub Actions.

Not implemented or not production-ready:

- eBPF event collection;
- production-quality training data or calibrated detection metrics;
- TLS, user accounts, RBAC, or remote multi-host management;
- tamper resistance or isolation from a compromised root account;
- a hardened deployment model for Internet-facing use.

The generated training set is useful for exercising the pipeline, not for making claims about real-world detection accuracy.

## Requirements

- Linux with `/proc` available (Ubuntu 22.04+ is a practical baseline);
- Python 3.10+;
- cgroup v2 preferred, with a limited cgroup v1 fallback;
- `sudo` for the Enforcer service.

## Quick start

```bash
git clone https://github.com/vuvannam-sec/AI-Based-Security-Enhancements.git
cd AI-Based-Security-Enhancements
chmod +x scripts/*.sh
./scripts/setup_and_train.sh
./scripts/run_all.sh
```

The launcher generates an ephemeral `AISEC_CONTROL_TOKEN` when one is not already set, exports it to the local services, and does not print it. Services bind to `127.0.0.1` unless explicitly overridden.

Local endpoints:

| Component | Endpoint |
| --- | --- |
| Dashboard | `http://127.0.0.1:8501` |
| Orchestrator | `http://127.0.0.1:8000/status` |
| Sensor | `http://127.0.0.1:8001/sensor/status` |
| Enforcer | `http://127.0.0.1:8002/enforcer/status` |
| ML service | `http://127.0.0.1:8003/ml/status` |

To run services manually, set one shared token first:

```bash
export AISEC_CONTROL_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

Mutating API calls use:

```text
Authorization: Bearer <AISEC_CONTROL_TOKEN>
```

The token is a local control-plane guard, not a substitute for TLS or network isolation. Do not bind the privileged Enforcer to an untrusted interface. See [`SECURITY.md`](SECURITY.md).

## Detection pipeline

The current pipeline intentionally combines two mechanisms:

1. **ML scoring** — the model classifies normalized process events and returns an attack score and action recommendation.
2. **Rule fallback** — a small set of explicit behavioral signals catches cases such as sustained high CPU, selected sensitive-file access, suspicious execution paths, and shell/network combinations.

Automatic enforcement is considered only after the Sensor's pre-filter, protected-process checks, cooldown, and final detection decision. The Enforcer independently validates the target PID and resource limits before changing process state.

## Demo scenarios

Manual demos live outside the pytest suite so CI never runs stress or process-behavior simulations accidentally.

```bash
python3 scripts/demo_scenarios.py cpu --duration 20
python3 scripts/demo_scenarios.py sensitive-file --duration 10
python3 scripts/demo_scenarios.py suspicious-exec --duration 10
python3 scripts/demo_scenarios.py suspicious-network --duration 10
```

The network demo opens a loopback TCP connection to a flagged port; it does **not** create a shell. Run demos only on systems you own or are authorized to test.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m compileall -q src shared
ruff check src shared
pytest -q
```

Pytest is deliberately scoped to `src/`. Manual workload generators under `scripts/` are not tests.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for project conventions.

## Repository layout

```text
shared/                  shared contracts and control-auth helpers
src/sensor/              /proc collection, detection, event export
src/ml/                  synthetic data, training, inference API
src/enforcer/            process/cgroup control plane
src/integration/         orchestration API and Streamlit UI
scripts/                 setup, launcher, manual demo scenarios
docs/                    architecture and design notes
.github/                  CI and dependency-update configuration
```

Generated datasets, model artifacts, virtual environments, local secrets, private keys, logs, and coverage output are excluded from version control.

## Security and responsible use

The Enforcer can change resource limits and terminate processes. Keep the project on an isolated development machine or lab VM, leave the default loopback bindings in place, and review [`SECURITY.md`](SECURITY.md) before changing the deployment model.

If you find a vulnerability in the project itself, do not publish exploit details in a public issue before the problem can be assessed.

## References

- [Linux `/proc` filesystem](https://man7.org/linux/man-pages/man5/proc.5.html)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [scikit-learn ensemble methods](https://scikit-learn.org/stable/modules/ensemble.html)
- [FastAPI](https://fastapi.tiangolo.com/)
- [Streamlit](https://streamlit.io/)
