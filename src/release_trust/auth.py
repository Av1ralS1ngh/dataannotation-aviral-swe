"""Header-token authentication for write and operational endpoints."""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status

from .config import get_settings


def _check_token(observed: str | None, expected: str) -> None:
    if not observed or not secrets.compare_digest(observed, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid service token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_publisher_token(
    x_release_token: str | None = Header(default=None),
) -> None:
    _check_token(x_release_token, get_settings().publisher_token)


def require_admin_token(
    authorization: str | None = Header(default=None),
) -> None:
    prefix = "Bearer "
    observed = (
        authorization[len(prefix) :]
        if authorization and authorization.startswith(prefix)
        else None
    )
    _check_token(observed, get_settings().admin_token)
