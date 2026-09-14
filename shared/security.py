from __future__ import annotations

import os
import secrets
from typing import Dict

from fastapi import Header, HTTPException, status

CONTROL_TOKEN_ENV = "AISEC_CONTROL_TOKEN"


def get_control_token() -> str:
    """Return the configured control-plane bearer token, if any."""
    return os.getenv(CONTROL_TOKEN_ENV, "").strip()


def control_auth_configured() -> bool:
    return bool(get_control_token())


def control_headers() -> Dict[str, str]:
    """Build an Authorization header for service-to-service control calls."""
    token = get_control_token()
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def require_control_token(
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> None:
    """Protect endpoints that can mutate host or service state."""
    expected = get_control_token()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{CONTROL_TOKEN_ENV} is not configured",
        )

    scheme, separator, supplied = (authorization or "").partition(" ")
    valid = (
        separator == " "
        and scheme.lower() == "bearer"
        and bool(supplied)
        and secrets.compare_digest(supplied.strip(), expected)
    )
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing control token",
            headers={"WWW-Authenticate": "Bearer"},
        )
