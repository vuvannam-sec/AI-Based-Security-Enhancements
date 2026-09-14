#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

HOST="${HOST:-127.0.0.1}"
UI_HOST="${UI_HOST:-127.0.0.1}"
PIDS=()

cleanup() {
    if ((${#PIDS[@]})); then
        echo
        echo "Stopping services..."
        kill "${PIDS[@]}" 2>/dev/null || true
        wait "${PIDS[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

if [ ! -d ".venv" ]; then
    echo "Virtual environment not found. Run ./scripts/setup_and_train.sh first."
    exit 1
fi

source .venv/bin/activate

port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN
    elif command -v lsof >/dev/null 2>&1; then
        lsof -iTCP:"$port" -sTCP:LISTEN -t >/dev/null 2>&1
    else
        return 1
    fi
}

for port in 8000 8001 8002 8003 8501; do
    if port_in_use "$port"; then
        echo "Port $port is already in use. Stop the existing service and retry."
        exit 1
    fi
done

start_service() {
    local name="$1"
    shift
    echo "Starting $name..."
    "$@" &
    PIDS+=("$!")
}

start_service "Sensor (8001)" \
    .venv/bin/uvicorn src.sensor.sensor_service:app --host "$HOST" --port 8001

start_service "Enforcer (8002, privileged)" \
    sudo -E .venv/bin/uvicorn src.enforcer.enforcer_service:app --host "$HOST" --port 8002

start_service "ML service (8003)" \
    .venv/bin/uvicorn src.ml.ml_service:app --host "$HOST" --port 8003

start_service "Orchestrator (8000)" \
    .venv/bin/uvicorn src.integration.api.main:app --host "$HOST" --port 8000

sleep 3

check_service() {
    local name="$1"
    local url="$2"
    if curl --fail --silent --show-error --max-time 3 "$url" >/dev/null; then
        printf '  %-14s ready\n' "$name"
    else
        printf '  %-14s unavailable\n' "$name"
        return 1
    fi
}

echo
echo "Service check"
check_service "Sensor" "http://127.0.0.1:8001/sensor/status"
check_service "Enforcer" "http://127.0.0.1:8002/enforcer/status"
check_service "ML" "http://127.0.0.1:8003/ml/status"
check_service "Orchestrator" "http://127.0.0.1:8000/status"

echo
echo "Dashboard: http://127.0.0.1:8501"
echo "APIs are bound to $HOST by default. Do not expose the privileged Enforcer API to untrusted networks."
echo "Press Ctrl+C to stop all services."
echo

.venv/bin/streamlit run src/integration/ui/app.py \
    --server.address "$UI_HOST" \
    --server.port 8501 \
    --server.headless true
