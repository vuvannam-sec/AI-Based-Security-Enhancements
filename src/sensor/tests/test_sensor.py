from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import src.sensor.sensor_service as service

TOKEN = "test-control-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
client = TestClient(service.app)


class _FakeExporter:
    file_path = "data/raw/test.csv"

    def __init__(self, out_dir: str):
        self.out_dir = Path(out_dir)

    def append(self, event: dict) -> None:
        return None


class _FakeCollector:
    def __init__(self, sample_interval: float):
        self.sample_interval = sample_interval

    def stream(self):
        return iter(())


@pytest.fixture(autouse=True)
def reset_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISEC_CONTROL_TOKEN", TOKEN)
    monkeypatch.setattr(service, "CsvExporter", _FakeExporter)
    monkeypatch.setattr(service, "ProcCollector", _FakeCollector)
    service._running = False
    service._thread = None
    service._exporter = None
    service._auto_detect = False
    service._blocked_pids.clear()
    service._cpu_high_streak.clear()
    service._last_submit_ts.clear()


def test_status_is_readable_without_control_token() -> None:
    response = client.get("/sensor/status")
    assert response.status_code == 200
    assert response.json()["mode"] == "proc"


def test_start_requires_control_token() -> None:
    response = client.post("/sensor/start", json={"mode": "proc", "sample_interval": 0.5})
    assert response.status_code == 401


def test_unimplemented_ebpf_mode_is_rejected_without_changing_state() -> None:
    response = client.post(
        "/sensor/start",
        headers=HEADERS,
        json={"mode": "ebpf", "sample_interval": 0.5},
    )
    assert response.status_code == 422
    assert service._running is False


def test_start_and_stop_with_control_token() -> None:
    start = client.post(
        "/sensor/start",
        headers=HEADERS,
        json={"mode": "proc", "sample_interval": 0.5},
    )
    assert start.status_code == 200
    assert start.json()["ok"] is True

    stop = client.post("/sensor/stop", headers=HEADERS)
    assert stop.status_code == 200
    assert stop.json()["ok"] is True
    assert service._running is False


def test_rule_detection_does_not_flag_arbitrary_file_access() -> None:
    event = {
        "pid": 4242,
        "comm": "python",
        "file_path": "/home/user/notes.txt",
        "cpu_percent": 1.0,
        "memory_bytes": 10_000,
    }
    assert service._rule_detection(event) is None


def test_rule_detection_flags_sensitive_file_access() -> None:
    event = {
        "pid": 4242,
        "comm": "python",
        "file_path": "/etc/passwd",
        "cpu_percent": 1.0,
        "memory_bytes": 10_000,
    }
    assert service._rule_detection(event) == "sensitive_file_access"
