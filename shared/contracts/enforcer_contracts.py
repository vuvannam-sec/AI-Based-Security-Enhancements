from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class EnforcerActionRequest(BaseModel):
    pid: int = Field(gt=2, description="Target Linux PID; PID 1/2 and non-positive values are rejected")
    action: Literal["throttle", "kill"]
    cpu_max: str | None = None
    memory_max: int | None = Field(default=None, gt=0)

    @field_validator("cpu_max")
    @classmethod
    def validate_cpu_max(cls, value: str | None) -> str | None:
        if value is None:
            return value

        parts = value.split()
        if len(parts) != 2:
            raise ValueError('cpu_max must use "<quota> <period>"')

        try:
            quota = int(parts[0])
            period = int(parts[1])
        except ValueError as exc:
            raise ValueError("cpu_max quota and period must be integers") from exc

        if quota <= 0:
            raise ValueError("cpu_max quota must be greater than zero")
        if not 1_000 <= period <= 1_000_000:
            raise ValueError("cpu_max period must be between 1000 and 1000000 microseconds")

        return f"{quota} {period}"


class EnforcerReleaseRequest(BaseModel):
    pid: int = Field(gt=2)
