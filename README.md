# AI-Based Security Enhancements

A Linux host-monitoring prototype that combines `/proc` telemetry, lightweight machine-learning classification, rule-based detection, and cgroup-based response.

The project is intended for local research, lab exercises, and defensive experimentation. It is **not** a production EDR, antivirus, or host intrusion-prevention product.

## What it does

The runtime is split into small services:

- **Sensor** — polls Linux process state from `/proc`, enriches process events, and keeps a recent in-memory event buffer.
- **ML service** — trains and serves a scikit-learn classifier using the shared event schema.
- **Enforcer** — throttles processes with cgroups or terminates a selected PID.
- **Orchestrator** — sends events through prediction and, when enabled, forwards malicious decisions to the enforcer.
- **Dashboard** — provides a Streamlit view for service state, detections, and demo controls.

```text
/proc
  |
  v
Sensor -----> ML service
  |              |
  |              v
  +--------> detection decision
                  |
                  v
              Enforcer
                  |
                  v
             cgroup / signal

Dashboard <----> services
Orchestrator ---> ML ---> Enforcer
```

## Current scope

| Capability | Status | Notes |
| --- | --- | --- |
| Process telemetry | Implemented | `/proc` polling; Linux only |
| CPU / memory heuristics | Implemented | Rule-based fallback in the sensor |
| Sensitive-file heuristic | Implemented | Based on observable open files and configured paths |
| Suspicious execution heuristic | Implemented | Includes temporary execution paths |
| Suspicious-port heuristic | Implemented | Intended for lab/demo detection, not full network inspection |
| ML classification | Implemented | scikit-learn pipeline trained from generated data |
| Process throttling | Implemented | cgroup v2 with a cgroup v1 fallback |
| Process termination | Implemented | Sends `SIGKILL` to an explicitly selected PID |
| eBPF telemetry | Planned | Not part of the current collector |
| Production-grade exfiltration detection | Not implemented | Requires stronger network/event telemetry |

## Security boundary

The enforcer is the most sensitive component: it can run with elevated privileges and can terminate or throttle processes. `scripts/run_all.sh` therefore binds services to `127.0.0.1` by default.

Do not expose the enforcer or the combined service stack directly to an untrusted network. The project currently does not provide production authentication, authorization, tenant isolation, or transport security.

If you deliberately change the bind address, place the services behind an appropriate security boundary and understand the impact of exposing privileged control endpoints.

See [SECURITY.md](SECURITY.md) for reporting and operational guidance.

## Requirements

- Linux with `/proc`
- Ubuntu 22.04+ recommended
- Python 3.10+
- cgroup v2 preferred
- `sudo` for enforcement operations

VirtualBox/VM environments are suitable for demonstrations. cgroup behavior can differ under containers, WSL, and restricted VMs.

## Quick start

```bash
git clone https://github.com/vuvannam-sec/AI-Based-Security-Enhancements.git
cd AI-Based-Security-Enhancements
chmod +x scripts/*.sh
./scripts/setup_and_train.sh
./scripts/run_all.sh
```

The setup script creates a virtual environment, installs dependencies, generates synthetic training data, and trains the initial model.

Generated artifacts are kept under `data/` and are intentionally ignored by Git.

### Local endpoints

When started with the default configuration:

| Service | Endpoint |
| --- | --- |
| Dashboard | `http://127.0.0.1:8501` |
| Orchestrator | `http://127.0.0.1:8000/status` |
| Sensor | `http://127.0.0.1:8001/sensor/status` |
| Enforcer | `http://127.0.0.1:8002/enforcer/status` |
| ML service | `http://127.0.0.1:8003/ml/status` |

## Safe demo workflow

Start the stack, enable auto-detection from the dashboard, and run one simulator explicitly from a second terminal:

```bash
python3 tools/attack_simulator.py cpu_abuse 20
python3 tools/attack_simulator.py sensitive_file 10
python3 tools/attack_simulator.py suspicious_exec 10
python3 tools/attack_simulator.py reverse_shell 10
```

These are **local lab simulations**, not exploit tooling. They intentionally create observable behaviors such as CPU load, access to standard Linux security files, execution from `/tmp`, or a localhost connection to a suspicious demo port.

Review recent enforcement decisions with:

```bash
curl -s 'http://127.0.0.1:8001/sensor/enforcement_history?limit=10' \
  | python3 -m json.tool
```

## Development

Create an environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Run the automated test suite:

```bash
pytest -q
```

The manual attack simulator is kept outside pytest's test paths so a normal test run cannot accidentally launch stress or network demo activity.

## Repository layout

```text
shared/                 Shared contracts and event schema
src/sensor/             /proc collection and detection loop
src/ml/                 Data generation, training, inference, API
src/enforcer/           cgroup and process-control service
src/integration/api/    Orchestrator API
src/integration/ui/     Streamlit dashboard
scripts/                Setup and local service launcher
tools/                  Explicitly invoked lab/demo utilities
```

## Known limitations

- Training data is synthetic and should not be treated as representative of real enterprise telemetry.
- `/proc` polling can miss short-lived activity and does not provide syscall-level fidelity.
- Several detections are deliberately simple heuristics for demonstration and evaluation.
- The services do not yet implement authentication or encrypted service-to-service transport.
- Enforcement requires elevated OS privileges and should be used only in an isolated environment you control.
- The current design is not hardened against a hostile local administrator or kernel-level adversary.

## Direction

Useful next steps are evidence-driven rather than feature-count driven:

1. Replace or complement polling with eBPF event collection.
2. Add authenticated control-plane calls before supporting remote deployment.
3. Build a reproducible labeled dataset and measure false-positive/false-negative rates.
4. Add process identity checks so enforcement decisions remain valid across PID reuse.
5. Separate policy decisions from enforcement mechanics and add an audit trail.
6. Add packaging and deployment profiles for lab, container, and VM environments.

## References

- [Linux `/proc` filesystem](https://man7.org/linux/man-pages/man5/proc.5.html)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [scikit-learn Random Forest](https://scikit-learn.org/stable/modules/ensemble.html)
- [FastAPI](https://fastapi.tiangolo.com/)
- [Streamlit](https://streamlit.io/)
