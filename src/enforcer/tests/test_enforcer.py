from __future__ import annotations

from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

import src.enforcer.enforcer_service as service

TOKEN = "test-control-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
client = TestClient(service.app)


@pytest.fixture(autouse=True)
def control_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISEC_CONTROL_TOKEN", TOKEN)


def test_status_is_readable_without_control_token() -> None:
    response = client.get("/enforcer/status")
    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_mutation_requires_control_token() -> None:
    response = client.post("/enforcer/action", json={"pid": 99999, "action": "kill"})
    assert response.status_code == 401


def test_pid_must_be_greater_than_two() -> None:
    response = client.post(
        "/enforcer/action",
        headers=HEADERS,
        json={"pid": -1, "action": "kill"},
    )
    assert response.status_code == 422


def test_cpu_limit_is_validated_at_api_boundary() -> None:
    response = client.post(
        "/enforcer/action",
        headers=HEADERS,
        json={"pid": 99999, "action": "throttle", "cpu_max": "not-a-limit"},
    )
    assert response.status_code == 422


def test_kill_action_targets_only_validated_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    kill_mock = Mock()
    monkeypatch.setattr(service, "_assert_safe_target", lambda pid, **kwargs: None)
    monkeypatch.setattr(service.os, "kill", kill_mock)

    response = client.post(
        "/enforcer/action",
        headers=HEADERS,
        json={"pid": 4242, "action": "kill"},
    )

    assert response.status_code == 200
    kill_mock.assert_called_once_with(4242, service.signal.SIGKILL)
