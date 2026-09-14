# AI-Based Security Enhancements

A Linux host-monitoring prototype that combines process telemetry, lightweight machine-learning classification, policy-based detection, and cgroup-based response.

The project is intended for local experimentation and operating-systems/security coursework. It is not a production endpoint-protection product.

## What it does

The system is split into five small services:

- **Sensor** — samples process activity from Linux `/proc` and produces a shared event schema.
- **ML service** — classifies events with a scikit-learn pipeline trained on generated data.
- **Enforcer** — applies CPU/memory limits through Linux cgroups or terminates a selected process.
- **Orchestrator** — sends events through classification and optional enforcement.
- **Dashboard** — exposes service status, detections, and demo controls through Streamlit.

```text
/proc
  |
  v
Sensor ---> ML service ---> Orchestrator ---> Enforcer
  |                                |
  +--------------------------------+----> Dashboard
```

## Project status

This repository is a working research/teaching prototype. The current implementation uses `/proc` polling and synthetic training data. Detection quality therefore should not be interpreted as a real-world security benchmark.

Known limitations:

- process telemetry is sampled rather than event-driven;
- the training set is synthetic;
- there is no authentication layer between local services;
- enforcement requires elevated privileges;
- data-exfiltration detection and eBPF collection are not implemented yet.

## Requirements

- Linux with `/proc` available (Ubuntu 22.04+ recommended)
- Python 3.10+
- cgroup v2 preferred; limited cgroup v1 fallback is included
- `sudo` for the Enforcer service

The default launcher binds services to `127.0.0.1`. Do not expose the privileged Enforcer API to an untrusted network.

## Setup

```bash
git clone https://github.com/vuvannam-sec/AI-Based-Security-Enhancements.git
cd AI-Based-Security-Enhancements
chmod +x scripts/*.sh
./scripts/setup_and_train.sh
```

Setup creates a local virtual environment, generates synthetic events, and trains the classifier. Generated datasets and model artifacts are intentionally excluded from Git.

## Run

```bash
./scripts/run_all.sh
```

Local endpoints:

| Component | Endpoint |
| --- | --- |
| Dashboard | `http://127.0.0.1:8501` |
| Orchestrator | `http://127.0.0.1:8000/status` |
| Sensor | `http://127.0.0.1:8001/sensor/status` |
| Enforcer | `http://127.0.0.1:8002/enforcer/status` |
| ML service | `http://127.0.0.1:8003/ml/status` |

To bind to a different interface for an isolated lab environment, set `HOST` and/or `UI_HOST` explicitly. Review the security implications first.

## Demo scenarios

The repository includes local test workloads for exercising the detection pipeline:

```bash
python3 tests/test_scripts/test_attacks.py cpu_abuse 30
python3 tests/test_scripts/test_attacks.py sensitive_file
python3 tests/test_scripts/test_attacks.py suspicious_exec
python3 tests/test_scripts/test_attacks.py reverse_shell 30
```

These are lab simulations. Run them only on systems you own or are authorized to test.

## Detection coverage

| Scenario | Current signal | Status |
| --- | --- | --- |
| Sustained CPU abuse | process metrics + ML/rules | implemented |
| Sensitive-file access | rule/feature signal | implemented |
| Execution from suspicious paths | rule signal | implemented |
| Reverse-shell-like behavior | network/behavior rule | prototype |
| Large outbound exfiltration | planned eBPF telemetry | not implemented |

## Development

Install dependencies and run the tests:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

The CI workflow performs a syntax check and runs the test suite on supported Python versions.

## Repository layout

```text
shared/                 shared schemas and service contracts
src/sensor/             process collection and event export
src/ml/                 data generation, training, and inference
src/enforcer/           cgroup/process enforcement
src/integration/        API orchestration and Streamlit UI
tests/                  integration/demo test workloads
scripts/                local setup and launcher scripts
```

## Security

The Enforcer can modify cgroups and terminate processes, so its API is intentionally treated as a privileged local control plane. See [`SECURITY.md`](SECURITY.md) before changing bind addresses or deploying the project outside an isolated lab.

If you discover a security issue in the repository itself, please avoid publishing exploit details in a public issue.

## References

- [Linux `/proc` filesystem](https://man7.org/linux/man-pages/man5/proc.5.html)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [scikit-learn ensemble methods](https://scikit-learn.org/stable/modules/ensemble.html)
- [FastAPI](https://fastapi.tiangolo.com/)
- [Streamlit](https://streamlit.io/)
