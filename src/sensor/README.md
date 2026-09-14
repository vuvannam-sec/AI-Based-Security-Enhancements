# Sensor service

The Sensor collects process observations from Linux `/proc`, normalizes them into the shared event schema, maintains a bounded recent-event buffer, and optionally runs the detection/enforcement pipeline.

## Collection

The current implementation supports `/proc` polling only. It reads process CPU/memory information, I/O counters, open file descriptors, and TCP socket metadata where available. eBPF collection is a planned extension and is rejected by the current API rather than exposed as a partially working mode.

## Endpoints

Read-only endpoints such as `/sensor/status`, `/sensor/events/latest`, `/sensor/stats`, and enforcement history are available locally without a token. State-changing endpoints (`start`, `stop`, whitelist changes, and auto-detect configuration) require `AISEC_CONTROL_TOKEN`.

When automatic enforcement is enabled, the Sensor forwards the same control token to the Enforcer. Detection uses a bounded worker pool, per-PID in-flight protection, cooldowns, and explicit protected-process checks before an action is submitted.
