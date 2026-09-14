# Enforcer service

The Enforcer is the project's privileged process-control component. It applies cgroup resource limits or terminates one validated PID.

## Endpoints

- `GET /enforcer/status` — engine and controller status; read-only.
- `POST /enforcer/action` — `throttle` or `kill`; requires the control token.
- `POST /enforcer/release` — remove active resource limits for a managed PID; requires the control token.

Mutating requests must include `Authorization: Bearer <AISEC_CONTROL_TOKEN>`.

## Safety checks

The API contract requires a PID greater than 2, validates `cpu.max`-style values and positive memory limits, and the service refuses to target its own PID or parent PID. These are guardrails for local lab use, not permission to expose the service publicly.

The launcher binds the service to `127.0.0.1:8002` and starts it with elevated privileges. See the root `SECURITY.md` before changing that boundary.

## cgroup behavior

For cgroup v2, managed processes are placed under `/sys/fs/cgroup/ai-sec/<pid>/`. CPU and memory limits are written through `cpu.max` and `memory.max`. Releasing a process resets those limits without moving a live process into an internal parent cgroup, which avoids cgroup-v2 delegation differences across systemd/VM environments.

A limited cgroup v1 fallback is retained for older lab environments.
