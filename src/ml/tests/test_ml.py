from __future__ import annotations

import pandas as pd
import pytest
from fastapi.testclient import TestClient

import src.ml.ml_service as service
from src.ml.training.train_pipeline import engineer_features, get_feature_columns

TOKEN = "test-control-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
client = TestClient(service.app)


@pytest.fixture(autouse=True)
def control_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISEC_CONTROL_TOKEN", TOKEN)


def _event() -> dict:
    return {
        "timestamp": 1_700_000_000.0,
        "event_id": "test-event",
        "event_type": "process",
        "pid": 4242,
        "ppid": 1000,
        "uid": 1000,
        "gid": 1000,
        "comm": "python3",
        "exe_path": "/usr/bin/python3",
        "syscall_nr": 0,
        "syscall_name": "",
        "syscall_ret": 0,
        "src_ip": "",
        "dst_ip": "",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "",
        "bytes_sent": 0,
        "bytes_recv": 0,
        "file_path": "",
        "file_op": "",
        "file_flags": 0,
        "cpu_percent": 2.0,
        "memory_bytes": 20_000_000,
        "io_read_bytes": 0,
        "io_write_bytes": 0,
    }


def test_status_has_stable_shape() -> None:
    response = client.get("/ml/status")
    assert response.status_code == 200
    body = response.json()
    assert {"ready", "model_path", "feature_count", "supported_threats"} <= body.keys()


def test_generate_requires_control_token() -> None:
    response = client.post(
        "/ml/generate",
        json={"n_normal": 50, "n_attack": 50, "output_path": "data/synthetic/test.csv"},
    )
    assert response.status_code == 401


def test_data_path_cannot_escape_configured_data_directory() -> None:
    response = client.post(
        "/ml/generate",
        headers=HEADERS,
        json={"n_normal": 50, "n_attack": 50, "output_path": "../../outside.csv"},
    )
    assert response.status_code == 400


def test_batch_size_is_bounded() -> None:
    response = client.post("/ml/predict/batch", json={"events": []})
    assert response.status_code == 422


def test_feature_engineering_marks_sensitive_access() -> None:
    event = _event()
    event["file_path"] = "/etc/shadow"
    frame = engineer_features(pd.DataFrame([event]))
    assert frame.loc[0, "is_sensitive_file"] == 1
    assert set(get_feature_columns()).issubset(frame.columns)
