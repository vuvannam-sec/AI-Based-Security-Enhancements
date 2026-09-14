from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import src.integration.api.main as api

TOKEN = "test-control-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
client = TestClient(api.app)


@pytest.fixture(autouse=True)
def control_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISEC_CONTROL_TOKEN", TOKEN)


def test_pipeline_requires_control_token() -> None:
    response = client.post("/pipeline/process", json={"event": {"pid": 4242}})
    assert response.status_code == 401


def test_pipeline_rejects_reserved_pid_before_upstream_calls() -> None:
    response = client.post(
        "/pipeline/process",
        headers=HEADERS,
        json={"event": {"pid": 1}},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "event.pid must be greater than 2"
