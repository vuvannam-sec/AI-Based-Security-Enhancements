from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import requests
import streamlit as st


class APIClient:
    def __init__(self, sensor_url: str, enforcer_url: str, ml_url: str | None = None, orch_api_url: str | None = None):
        self.sensor_url = sensor_url.rstrip("/")
        self.enforcer_url = enforcer_url.rstrip("/")
        self.ml_url = ml_url.rstrip("/") if ml_url else None
        self.orch_api_url = orch_api_url.rstrip("/") if orch_api_url else None
        self.control_token = os.getenv("AISEC_CONTROL_TOKEN", "").strip()

    def _make_request(self, method: str, url: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
        headers = dict(kwargs.pop("headers", {}) or {})
        if self.control_token and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.control_token}"
        try:
            response = requests.request(method, url, timeout=5, headers=headers, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError:
            st.error(f"Cannot connect to {url}")
        except requests.exceptions.Timeout:
            st.error(f"Request timed out: {url}")
        except requests.exceptions.HTTPError as exc:
            detail = exc.response.text[:300] if exc.response is not None else str(exc)
            st.error(f"HTTP request failed: {detail}")
        except (ValueError, requests.RequestException) as exc:
            st.error(f"Request failed: {exc}")
        return None

    @st.cache_data(ttl=3, show_spinner=False)
    def get_sensor_status_cached(_self) -> Optional[Dict[str, Any]]:
        return _self._make_request("GET", f"{_self.sensor_url}/sensor/status")

    @st.cache_data(ttl=2, show_spinner=False)
    def get_latest_events_cached(_self, limit: int = 100) -> List[Dict[str, Any]]:
        result = _self._make_request("GET", f"{_self.sensor_url}/sensor/events/latest?limit={limit}")
        return result.get("events", []) if result else []

    @st.cache_data(ttl=5, show_spinner=False)
    def get_enforcer_status_cached(_self) -> Optional[Dict[str, Any]]:
        return _self._make_request("GET", f"{_self.enforcer_url}/enforcer/status")

    def get_sensor_status(self) -> Optional[Dict[str, Any]]:
        return self._make_request("GET", f"{self.sensor_url}/sensor/status")

    def start_sensor(
        self,
        mode: str = "proc",
        sample_interval: float = 1.0,
        auto_detect: bool = False,
        auto_action: str = "throttle",
    ) -> Optional[Dict[str, Any]]:
        self.get_sensor_status_cached.clear()
        return self._make_request(
            "POST",
            f"{self.sensor_url}/sensor/start",
            json={
                "mode": mode,
                "sample_interval": sample_interval,
                "auto_detect": auto_detect,
                "auto_action": auto_action,
            },
        )

    def stop_sensor(self) -> Optional[Dict[str, Any]]:
        self.get_sensor_status_cached.clear()
        return self._make_request("POST", f"{self.sensor_url}/sensor/stop")

    def get_latest_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        result = self._make_request("GET", f"{self.sensor_url}/sensor/events/latest?limit={limit}")
        return result.get("events", []) if result else []

    def get_enforcer_status(self) -> Optional[Dict[str, Any]]:
        return self._make_request("GET", f"{self.enforcer_url}/enforcer/status")

    def enforce_action(
        self,
        pid: int,
        action: str,
        cpu_max: str | None = None,
        memory_max: int | None = None,
    ) -> Optional[Dict[str, Any]]:
        data: Dict[str, Any] = {"pid": pid, "action": action}
        if cpu_max:
            data["cpu_max"] = cpu_max
        if memory_max is not None:
            data["memory_max"] = memory_max
        self.get_enforcer_status_cached.clear()
        return self._make_request("POST", f"{self.enforcer_url}/enforcer/action", json=data)

    def release_process(self, pid: int) -> Optional[Dict[str, Any]]:
        self.get_enforcer_status_cached.clear()
        return self._make_request("POST", f"{self.enforcer_url}/enforcer/release", json={"pid": pid})

    def set_auto_detect(self, enabled: bool, action: str = "throttle") -> Optional[Dict[str, Any]]:
        self.get_sensor_status_cached.clear()
        return self._make_request(
            "POST",
            f"{self.sensor_url}/sensor/auto_detect",
            json={"enabled": enabled, "action": action},
        )

    def get_enforcement_history(self, limit: int = 50) -> Optional[Dict[str, Any]]:
        return self._make_request("GET", f"{self.sensor_url}/sensor/enforcement_history?limit={limit}")


def detect_suspicious_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    suspicious: List[Dict[str, Any]] = []
    for event in events:
        reasons: List[str] = []
        if event.get("syscall_name") in {"setuid", "setgid", "setresuid", "setresgid"}:
            reasons.append("Privilege-related syscall")
        if event.get("syscall_name") in {"execve", "clone", "fork"}:
            reasons.append("Process creation")
        try:
            cpu = float(event.get("cpu_percent", 0) or 0)
            if cpu > 80:
                reasons.append(f"High CPU usage: {cpu}%")
        except (ValueError, TypeError):
            pass
        try:
            memory = int(event.get("memory_bytes", 0) or 0)
            if memory > 1024**3:
                reasons.append(f"High memory usage: {memory / (1024**3):.1f}GB")
        except (ValueError, TypeError):
            pass
        file_path = str(event.get("file_path") or "")
        if any(path in file_path for path in ("/etc/passwd", "/etc/shadow", "/root/.ssh")):
            reasons.append("Sensitive file access")
        if reasons:
            alert = event.copy()
            alert["alert_reasons"] = reasons
            alert["severity"] = "HIGH" if len(reasons) > 1 else "MEDIUM"
            suspicious.append(alert)
    return suspicious


def format_memory_size(bytes_value: Any) -> str:
    try:
        value = float(int(bytes_value or 0))
        if value == 0:
            return "0 B"
        for unit in ("B", "KB", "MB", "GB"):
            if value < 1024:
                return f"{value:.1f} {unit}"
            value /= 1024
        return f"{value:.1f} TB"
    except (ValueError, TypeError):
        return "N/A"


def format_timestamp(timestamp: Any) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(timestamp)))
    except (ValueError, TypeError):
        return "N/A"


def init_session_state() -> None:
    defaults = {
        "last_sensor_status": None,
        "last_enforcer_status": None,
        "last_events": [],
        "last_update_time": 0,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def get_cached_or_fetch(api_client: APIClient, data_type: str, fetch_func: Any, *args: Any, **kwargs: Any):
    try:
        new_data = fetch_func(*args, **kwargs)
        if new_data is not None:
            st.session_state[f"last_{data_type}"] = new_data
            st.session_state.last_update_time = time.time()
            return new_data, True
    except Exception:
        pass
    return st.session_state.get(f"last_{data_type}"), False
