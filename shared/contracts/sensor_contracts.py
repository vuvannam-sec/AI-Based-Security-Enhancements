from __future__ import annotations

from typing import Any, Dict, List, Literal

from pydantic import BaseModel, Field


class SensorStartRequest(BaseModel):
    mode: Literal["proc"] = "proc"
    sample_interval: float = Field(default=0.5, ge=0.1, le=60.0)
    auto_detect: bool = False
    auto_action: Literal["kill", "throttle"] = "throttle"


class SensorStatusResponse(BaseModel):
    running: bool
    mode: str
    output_file: str | None = None
    last_event_ts: float | None = None
    auto_detect: bool = False
    auto_action: str = "throttle"
    events_scanned: int = 0
    threats_detected: int = 0
    processes_blocked: int = 0


class SensorLatestEventsResponse(BaseModel):
    events: List[Dict[str, Any]]
