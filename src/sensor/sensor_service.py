from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Literal, Set

import httpx
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from shared.contracts.sensor_contracts import (
    SensorLatestEventsResponse,
    SensorStartRequest,
    SensorStatusResponse,
)
from shared.security import control_auth_configured, control_headers, require_control_token
from src.sensor.exporter.csv_exporter import CsvExporter
from src.sensor.loader.collector import ProcCollector

logger = logging.getLogger("sensor")
app = FastAPI(title="Sensor Service", version="1.1")

PROTECTED_COMMS = {
    "streamlit",
    "uvicorn",
    "sudo",
    "systemd",
    "sshd",
    "polkitd",
    "login",
    "cron",
}
KERNEL_THREADS = {
    "init",
    "kthreadd",
    "kworker",
    "ksoftirqd",
    "migration",
    "watchdog",
    "rcu_sched",
    "rcu_bh",
    "rcu_preempt",
}
SENSITIVE_FILES = (
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh",
    "/root/.ssh",
)
SUSPICIOUS_PATHS = ("/tmp/", "/dev/shm/", "/var/tmp/")
SUSPICIOUS_PORTS = {4444, 5555, 6666, 1234, 1337, 9001, 9999, 31337, 12345}
SHELL_COMMANDS = {"bash", "sh", "zsh", "dash", "fish", "tcsh", "csh"}

ML_URL = os.getenv("ML_URL", "http://127.0.0.1:8003").rstrip("/")
ENFORCER_URL = os.getenv("ENFORCER_URL", "http://127.0.0.1:8002").rstrip("/")
CPU_THRESHOLD = 80.0
MEMORY_THRESHOLD = 500 * 1024 * 1024
SUBMIT_COOLDOWN_SEC = 0.5
CPU_STREAK_REQUIRED = 2

_running = False
_mode = "proc"
_thread: threading.Thread | None = None
_exporter: CsvExporter | None = None
_last_event_ts: float | None = None
_buffer: deque[Dict[str, Any]] = deque(maxlen=1000)
_state_lock = threading.Lock()
_inflight_pids: Set[int] = set()
_last_submit_ts: Dict[int, float] = {}
_cpu_high_streak: Dict[int, int] = {}
_auto_detect = False
_auto_action = "throttle"
_events_scanned = 0
_threats_detected = 0
_processes_blocked = 0
_blocked_pids: Set[int] = set()
_whitelisted_pids: Dict[int, str] = {}
_enforcement_history: deque[Dict[str, Any]] = deque(maxlen=200)
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="sensor-detect")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return default


def _whitelist_pid(pid: int, name: str) -> None:
    with _state_lock:
        _whitelisted_pids[pid] = name


def _unwhitelist_pid(pid: int) -> None:
    with _state_lock:
        _whitelisted_pids.pop(pid, None)


def _is_whitelisted(pid: int, comm: str) -> bool:
    normalized = comm.strip().lower()
    if pid <= 2 or pid == os.getpid():
        return True
    if pid in _whitelisted_pids:
        return True
    if normalized in PROTECTED_COMMS or normalized in KERNEL_THREADS:
        return True
    return False


def _rule_detection(event: Dict[str, Any]) -> str | None:
    cpu = _safe_float(event.get("cpu_percent"))
    memory = _safe_int(event.get("memory_bytes"))
    file_path = str(event.get("file_path") or "")
    exe_path = str(event.get("exe_path") or "")
    cmdline = str(event.get("cmdline") or "")
    comm = str(event.get("comm") or "").lower()
    dst_port = _safe_int(event.get("dst_port"))
    io_write_delta = _safe_int(event.get("io_write_delta"))

    if cpu > CPU_THRESHOLD:
        return "high_cpu_usage"
    if memory > MEMORY_THRESHOLD:
        return "high_memory_usage"
    if file_path and any(path in file_path for path in SENSITIVE_FILES):
        return "sensitive_file_access"
    if dst_port in SUSPICIOUS_PORTS:
        return "reverse_shell"
    if event.get("is_exfiltration") or (event.get("has_network") and io_write_delta > 10 * 1024 * 1024):
        return "data_exfiltration"
    if comm in SHELL_COMMANDS and dst_port > 0:
        return "reverse_shell"
    if any(path in exe_path or path in cmdline for path in SUSPICIOUS_PATHS):
        return "suspicious_exec"
    return None


def _ml_detection(event: Dict[str, Any]) -> tuple[str | None, float, int]:
    try:
        with httpx.Client(timeout=2.0) as client:
            response = client.post(f"{ML_URL}/ml/predict", json={"event": event})
        if response.status_code != 200:
            return None, 0.0, 0
        result = response.json()
        if not result.get("ok"):
            return None, 0.0, 0
        score = _safe_float(result.get("score"))
        label = _safe_int(result.get("label"))
        action = str(result.get("action") or "allow").lower()
        if action == "block":
            return str(result.get("threat_type") or "ml_detected"), score, label
        return None, score, label
    except httpx.HTTPError:
        logger.debug("ML service unavailable", exc_info=True)
        return None, 0.0, 0


def _enforce(pid: int, action: str) -> tuple[bool, str | None]:
    payload: Dict[str, Any] = {"pid": pid, "action": action}
    if action == "throttle":
        payload.update(cpu_max="5000 100000", memory_max=128 * 1024 * 1024)

    try:
        with httpx.Client(timeout=3.0) as client:
            response = client.post(
                f"{ENFORCER_URL}/enforcer/action",
                json=payload,
                headers=control_headers(),
            )
        if response.status_code == 200:
            return True, None
        return False, f"enforcer returned HTTP {response.status_code}"
    except httpx.HTTPError as exc:
        return False, type(exc).__name__


def _do_auto_detect(event: Dict[str, Any]) -> None:
    global _events_scanned, _threats_detected, _processes_blocked

    pid = _safe_int(event.get("pid"), default=-1)
    if pid <= 2:
        return
    comm = str(event.get("comm") or "")

    with _state_lock:
        if _is_whitelisted(pid, comm) or pid in _blocked_pids or pid in _inflight_pids:
            return
        _inflight_pids.add(pid)
        _events_scanned += 1

    try:
        threat_type, ml_score, ml_label = _ml_detection(event)
        method = "ml" if threat_type else None
        if not threat_type:
            threat_type = _rule_detection(event)
            method = "rule" if threat_type else None
        if not threat_type:
            return

        with _state_lock:
            _threats_detected += 1

        success, error = _enforce(pid, _auto_action)
        entry = {
            "timestamp": time.time(),
            "pid": pid,
            "comm": comm,
            "exe_path": str(event.get("exe_path") or ""),
            "cmdline": str(event.get("cmdline") or "")[:100],
            "cpu_percent": round(_safe_float(event.get("cpu_percent")), 1),
            "memory_bytes": _safe_int(event.get("memory_bytes")),
            "file_path": str(event.get("file_path") or ""),
            "syscall_name": str(event.get("syscall_name") or ""),
            "dst_port": _safe_int(event.get("dst_port")),
            "threat_type": threat_type,
            "detection_method": method,
            "ml_score": round(ml_score, 3),
            "ml_label": ml_label,
            "enforcer_action": _auto_action,
            "status": "success" if success else "failed",
            "error": error,
        }
        _enforcement_history.append(entry)

        if success:
            with _state_lock:
                _processes_blocked += 1
                _blocked_pids.add(pid)
                _cpu_high_streak.pop(pid, None)
                _last_submit_ts.pop(pid, None)
            logger.warning("%s PID %s (%s): %s", _auto_action, pid, comm, threat_type)
    finally:
        with _state_lock:
            _inflight_pids.discard(pid)


def _process_event(event: Dict[str, Any]) -> None:
    global _last_event_ts

    _last_event_ts = _safe_float(event.get("timestamp"), time.time())
    _buffer.append(event)
    if _exporter:
        _exporter.append(event)
    if not _auto_detect:
        return

    pid = _safe_int(event.get("pid"), default=-1)
    if pid <= 2:
        return

    cpu = _safe_float(event.get("cpu_percent"))
    memory = _safe_int(event.get("memory_bytes"))
    file_path = str(event.get("file_path") or "")
    exe_path = str(event.get("exe_path") or "")
    cmdline = str(event.get("cmdline") or "")
    dst_port = _safe_int(event.get("dst_port"))
    comm = str(event.get("comm") or "").lower()

    with _state_lock:
        _cpu_high_streak[pid] = _cpu_high_streak.get(pid, 0) + 1 if cpu > CPU_THRESHOLD else 0
        cpu_sustained = _cpu_high_streak[pid] >= CPU_STREAK_REQUIRED

    suspicious = (
        cpu_sustained
        or memory > MEMORY_THRESHOLD
        or any(path in file_path for path in SENSITIVE_FILES)
        or any(path in exe_path or path in cmdline for path in SUSPICIOUS_PATHS)
        or dst_port in SUSPICIOUS_PORTS
        or (comm in SHELL_COMMANDS and dst_port > 0)
        or bool(event.get("is_exfiltration"))
    )
    if not suspicious:
        return

    now = time.time()
    with _state_lock:
        if now - _last_submit_ts.get(pid, 0.0) < SUBMIT_COOLDOWN_SEC:
            return
        _last_submit_ts[pid] = now
    _executor.submit(_do_auto_detect, event.copy())


def _runner_proc(sample_interval: float) -> None:
    global _running
    collector = ProcCollector(sample_interval=sample_interval)
    for event in collector.stream():
        if not _running:
            break
        _process_event(event)


@app.on_event("startup")
def _on_startup() -> None:
    _whitelist_pid(os.getpid(), "sensor_service")
    logger.info("sensor service started with /proc collector support")


@app.on_event("shutdown")
def _on_shutdown() -> None:
    global _running
    _running = False


@app.get("/sensor/status", response_model=SensorStatusResponse)
def status() -> SensorStatusResponse:
    return SensorStatusResponse(
        running=_running,
        mode=_mode,
        output_file=_exporter.file_path if _exporter else None,
        last_event_ts=_last_event_ts,
        auto_action=_auto_action,
        auto_detect=_auto_detect,
        events_scanned=_events_scanned,
        threats_detected=_threats_detected,
        processes_blocked=_processes_blocked,
    )


@app.get("/sensor/security")
def security_status() -> Dict[str, Any]:
    return {"control_auth_configured": control_auth_configured()}


@app.post("/sensor/start", dependencies=[Depends(require_control_token)])
def start(req: SensorStartRequest) -> Dict[str, Any]:
    global _running, _mode, _thread, _exporter, _auto_detect, _auto_action
    global _events_scanned, _threats_detected, _processes_blocked

    if _running:
        return {"ok": True, "message": "already running"}

    _mode = req.mode
    _auto_detect = req.auto_detect
    _auto_action = req.auto_action
    _events_scanned = 0
    _threats_detected = 0
    _processes_blocked = 0
    _blocked_pids.clear()
    _cpu_high_streak.clear()
    _last_submit_ts.clear()
    _exporter = CsvExporter(out_dir="data/raw")
    _running = True
    _thread = threading.Thread(target=_runner_proc, args=(req.sample_interval,), daemon=True)
    _thread.start()

    return {
        "ok": True,
        "mode": _mode,
        "output_file": _exporter.file_path,
        "auto_detect": _auto_detect,
        "auto_action": _auto_action,
        "sample_interval": req.sample_interval,
    }


@app.post("/sensor/stop", dependencies=[Depends(require_control_token)])
def stop() -> Dict[str, Any]:
    global _running
    _running = False
    if _thread and _thread.is_alive():
        _thread.join(timeout=2.0)
    return {
        "ok": True,
        "events_scanned": _events_scanned,
        "threats_detected": _threats_detected,
        "processes_blocked": _processes_blocked,
    }


@app.get("/sensor/events/latest", response_model=SensorLatestEventsResponse)
def get_latest_events(limit: int = 100) -> SensorLatestEventsResponse:
    limit = max(1, min(limit, 1000))
    return SensorLatestEventsResponse(events=list(_buffer)[-limit:])


@app.get("/sensor/stats")
def get_stats() -> Dict[str, Any]:
    return {
        "running": _running,
        "auto_detect": _auto_detect,
        "auto_action": _auto_action,
        "events_scanned": _events_scanned,
        "threats_detected": _threats_detected,
        "processes_blocked": _processes_blocked,
        "blocked_pids": sorted(_blocked_pids),
        "buffer_size": len(_buffer),
    }


class WhitelistRequest(BaseModel):
    pid: int = Field(gt=2)
    name: str = Field(default="unknown", min_length=1, max_length=80)
    action: Literal["add", "remove"] = "add"


@app.get("/sensor/whitelist")
def get_whitelist() -> Dict[str, Any]:
    with _state_lock:
        whitelist = _whitelisted_pids.copy()
    return {
        "whitelisted_pids": whitelist,
        "kernel_threads": sorted(KERNEL_THREADS),
        "sensor_pid": os.getpid(),
    }


@app.post("/sensor/whitelist", dependencies=[Depends(require_control_token)])
def manage_whitelist(req: WhitelistRequest) -> Dict[str, Any]:
    if req.action == "add":
        _whitelist_pid(req.pid, req.name)
        return {"ok": True, "action": "added", "pid": req.pid, "name": req.name}
    _unwhitelist_pid(req.pid)
    return {"ok": True, "action": "removed", "pid": req.pid}


class AutoDetectRequest(BaseModel):
    enabled: bool
    action: Literal["kill", "throttle"] = "throttle"


@app.post("/sensor/auto_detect", dependencies=[Depends(require_control_token)])
def set_auto_detect(req: AutoDetectRequest) -> Dict[str, Any]:
    global _auto_detect, _auto_action
    changed = req.enabled != _auto_detect
    _auto_detect = req.enabled
    _auto_action = req.action
    return {
        "ok": True,
        "auto_detect": _auto_detect,
        "auto_action": _auto_action,
        "changed": changed,
    }


@app.get("/sensor/enforcement_history")
def get_enforcement_history(limit: int = 50) -> Dict[str, Any]:
    limit = max(1, min(limit, _enforcement_history.maxlen or 200))
    history = list(reversed(list(_enforcement_history)[-limit:]))
    return {
        "ok": True,
        "count": len(history),
        "total": len(_enforcement_history),
        "history": history,
    }


@app.post("/sensor/analyze")
def analyze_event(event: Dict[str, Any]) -> Dict[str, Any]:
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.post(f"{ML_URL}/ml/predict", json={"event": event})
        if response.status_code == 200:
            return response.json()
        return {"ok": False, "error": f"ML returned HTTP {response.status_code}"}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": type(exc).__name__}
