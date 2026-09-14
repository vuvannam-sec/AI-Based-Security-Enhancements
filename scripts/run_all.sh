#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

BIND_HOST="${AISEC_BIND_HOST:-127.0.0.1}"
ALLOW_REMOTE="${AISEC_ALLOW_REMOTE:-0}"
RUNTIME_DIR="${AISEC_RUNTIME_DIR:-.runtime}"

SENSOR_PORT=8001
ENFORCER_PORT=8002
ML_PORT=8003
ORCHESTRATOR_PORT=8000
UI_PORT=8501

if [[ ! -d ".venv" ]]; then
    echo "[error] .venv not found. Run ./scripts/setup_and_train.sh first." >&2
    exit 1
fi

if [[ "$BIND_HOST" != "127.0.0.1" && "$BIND_HOST" != "localhost" ]]; then
    if [[ "$ALLOW_REMOTE" != "1" ]]; then
        echo "[error] Refusing to expose privileged services on $BIND_HOST." >&2
        echo "        Keep the default loopback binding, or set AISEC_ALLOW_REMOTE=1 only" >&2
        echo "        after placing the stack behind an appropriate security boundary." >&2
        exit 1
    fi
    echo "[warning] Remote binding enabled on $BIND_HOST. The enforcer is privileged and unauthenticated."
fi

source .venv/bin/activate
mkdir -p "$RUNTIME_DIR"

PIDS=()
NAMES=()

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    set +e

    if (( ${#PIDS[@]} > 0 )); then
        echo
        echo "[stop] shutting down services"
    fi

    for i in "${!PIDS[@]}"; do
        pid="${PIDS[$i]}"
        name="${NAMES[$i]}"
        if kill -0 "$pid" 2>/dev/null; then
            echo "[stop] $name (pid $pid)"
            kill "$pid" 2>/dev/null || sudo kill "$pid" 2>/dev/null || true
        fi
    done

    wait 2>/dev/null || true
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

check_port_free() {
    local port=$1
    python - "$BIND_HOST" "$port" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

if host == "localhost":
    host = "127.0.0.1"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind((host, port))
except OSError as exc:
    print(f"[error] port {port} is unavailable on {host}: {exc}", file=sys.stderr)
    raise SystemExit(1)
finally:
    sock.close()
PY
}

for port in "$ORCHESTRATOR_PORT" "$SENSOR_PORT" "$ENFORCER_PORT" "$ML_PORT" "$UI_PORT"; do
    check_port_free "$port"
done

echo "[info] validating sudo access for the enforcer"
sudo -v

start_service() {
    local name=$1
    shift
    local log_file="$RUNTIME_DIR/${name}.log"

    echo "[start] $name -> $log_file"
    "$@" >"$log_file" 2>&1 &
    local pid=$!
    PIDS+=("$pid")
    NAMES+=("$name")

    sleep 1
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[error] $name exited during startup" >&2
        tail -n 40 "$log_file" >&2 || true
        exit 1
    fi
}

start_service sensor \
    .venv/bin/uvicorn src.sensor.sensor_service:app --host "$BIND_HOST" --port "$SENSOR_PORT"

start_service enforcer \
    sudo -E .venv/bin/uvicorn src.enforcer.enforcer_service:app --host "$BIND_HOST" --port "$ENFORCER_PORT"

start_service ml \
    .venv/bin/uvicorn src.ml.ml_service:app --host "$BIND_HOST" --port "$ML_PORT"

start_service orchestrator \
    .venv/bin/uvicorn src.integration.api.main:app --host "$BIND_HOST" --port "$ORCHESTRATOR_PORT"

check_service() {
    local name=$1
    local url=$2

    if curl --fail --silent --show-error --max-time 3 "$url" >/dev/null; then
        echo "[ok] $name"
    else
        echo "[error] $name did not pass its health check: $url" >&2
        exit 1
    fi
}

sleep 2
check_service sensor "http://127.0.0.1:${SENSOR_PORT}/sensor/status"
check_service enforcer "http://127.0.0.1:${ENFORCER_PORT}/enforcer/status"
check_service ml "http://127.0.0.1:${ML_PORT}/ml/status"
check_service orchestrator "http://127.0.0.1:${ORCHESTRATOR_PORT}/status"

start_service dashboard \
    .venv/bin/streamlit run src/integration/ui/app.py \
        --server.address "$BIND_HOST" \
        --server.port "$UI_PORT" \
        --server.headless true

sleep 1
check_service dashboard "http://127.0.0.1:${UI_PORT}"

cat <<EOF

AI security monitor is running locally.

  Dashboard:    http://127.0.0.1:${UI_PORT}
  Orchestrator: http://127.0.0.1:${ORCHESTRATOR_PORT}/status
  Sensor:       http://127.0.0.1:${SENSOR_PORT}/sensor/status
  Enforcer:     http://127.0.0.1:${ENFORCER_PORT}/enforcer/status
  ML:           http://127.0.0.1:${ML_PORT}/ml/status

Logs: ${RUNTIME_DIR}/
Press Ctrl+C to stop the processes started by this script.
EOF

# Exit the stack if any managed service exits unexpectedly.
set +e
wait -n "${PIDS[@]}"
status=$?
set -e

echo "[error] a managed service exited (status $status); stopping the stack" >&2
exit "$status"
