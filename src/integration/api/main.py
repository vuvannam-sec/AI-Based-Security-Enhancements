from __future__ import annotations

import os
from typing import Any, Dict, Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from shared.security import control_headers, require_control_token


def _env_url(name: str, default: str) -> str:
    return os.getenv(name, default).rstrip("/")


SENSOR_URL = _env_url("SENSOR_URL", "http://127.0.0.1:8001")
ENFORCER_URL = _env_url("ENFORCER_URL", "http://127.0.0.1:8002")
ML_URL = _env_url("ML_URL", "http://127.0.0.1:8003")

app = FastAPI(title="Integration Orchestrator", version="0.2")


class PipelineProcessRequest(BaseModel):
    event: Dict[str, Any] = Field(..., description="Event object using the shared event schema")
    enforce_if_malicious: bool = True
    enforcer_action: Literal["throttle", "kill"] = "throttle"
    cpu_max: str | None = "20000 100000"
    memory_max: int | None = Field(default=268_435_456, gt=0)


class PipelineProcessResponse(BaseModel):
    ok: bool
    ml_result: Dict[str, Any]
    enforcer_result: Dict[str, Any] | None = None


async def _get_json(client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
    response = await client.get(url, timeout=5)
    response.raise_for_status()
    return response.json()


async def _post_json(
    client: httpx.AsyncClient,
    url: str,
    payload: Dict[str, Any],
    *,
    headers: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    response = await client.post(url, json=payload, headers=headers, timeout=10)
    response.raise_for_status()
    return response.json()


@app.get("/status")
async def status() -> Dict[str, Any]:
    async with httpx.AsyncClient() as client:
        services: Dict[str, Dict[str, Any]] = {}
        for name, url in (
            ("sensor", f"{SENSOR_URL}/sensor/status"),
            ("ml", f"{ML_URL}/ml/status"),
            ("enforcer", f"{ENFORCER_URL}/enforcer/status"),
        ):
            try:
                await _get_json(client, url)
                services[name] = {"url": url.rsplit("/", 1)[0], "ok": True, "error": None}
            except Exception as exc:  # health endpoint must report partial failures
                services[name] = {"url": url.rsplit("/", 1)[0], "ok": False, "error": str(exc)}

    return {"ok": True, "services": services}


@app.post(
    "/pipeline/process",
    response_model=PipelineProcessResponse,
    dependencies=[Depends(require_control_token)],
)
async def pipeline_process(req: PipelineProcessRequest) -> PipelineProcessResponse:
    pid = req.event.get("pid")
    try:
        pid_int = int(pid)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="event.pid must be an integer") from exc
    if pid_int <= 2:
        raise HTTPException(status_code=400, detail="event.pid must be greater than 2")

    async with httpx.AsyncClient() as client:
        try:
            ml_result = await _post_json(client, f"{ML_URL}/ml/predict", {"event": req.event})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="ML service unavailable") from exc

        if not ml_result.get("ok"):
            return PipelineProcessResponse(ok=False, ml_result=ml_result)

        is_malicious = (
            ml_result.get("label") == 1
            or str(ml_result.get("action") or "").lower() == "block"
        )

        enforcer_result: Dict[str, Any] | None = None
        if req.enforce_if_malicious and is_malicious:
            payload: Dict[str, Any] = {"pid": pid_int, "action": req.enforcer_action}
            if req.enforcer_action == "throttle":
                if req.cpu_max:
                    payload["cpu_max"] = req.cpu_max
                if req.memory_max is not None:
                    payload["memory_max"] = req.memory_max

            try:
                enforcer_result = await _post_json(
                    client,
                    f"{ENFORCER_URL}/enforcer/action",
                    payload,
                    headers=control_headers(),
                )
            except httpx.HTTPError as exc:
                raise HTTPException(status_code=502, detail="Enforcer service unavailable") from exc

        return PipelineProcessResponse(
            ok=True,
            ml_result=ml_result,
            enforcer_result=enforcer_result,
        )
