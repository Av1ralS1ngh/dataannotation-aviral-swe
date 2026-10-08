"""Narrow gateway between admission replicas and the etcd trust journal."""

from __future__ import annotations

import base64
import json
import logging
import secrets

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool

from .config import get_settings
from .logging_config import configure_logging

configure_logging()
LOGGER = logging.getLogger(__name__)
app = FastAPI(title="Trust Coordination Gateway", version="0.1.0")
JOURNAL_KEY = "artifact-trust/authority"


def _decoded_key(value: str) -> str:
    try:
        return base64.b64decode(value, validate=True).decode()
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid journal key") from exc


def _validate_request(path: str, payload: dict) -> None:
    if path == "kv/range":
        keys = [payload.get("key")]
    else:
        keys = [item.get("key") for item in payload.get("compare", [])]
        for operation in payload.get("success", []):
            request_put = operation.get("request_put")
            if request_put is None:
                raise HTTPException(
                    status_code=400,
                    detail="unsupported journal transaction operation",
                )
            keys.append(request_put.get("key"))
        if payload.get("failure"):
            raise HTTPException(
                status_code=400,
                detail="journal transactions cannot include failure operations",
            )
    if not keys or any(
        not isinstance(key, str) or _decoded_key(key) != JOURNAL_KEY
        for key in keys
    ):
        raise HTTPException(
            status_code=403,
            detail="coordination access is limited to the authority journal",
        )


@app.get("/healthz")
def healthz():
    try:
        response = requests.get(
            f"{get_settings().etcd_url}/health",
            timeout=2,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(status_code=503, detail="etcd unavailable") from exc
    return {"ok": True}


@app.api_route("/v3/{path:path}", methods=["POST"])
async def proxy_etcd(
    path: str,
    request: Request,
    x_coordination_token: str | None = Header(default=None),
):
    if path not in {"kv/range", "kv/txn"}:
        raise HTTPException(status_code=404, detail="unsupported coordination route")
    expected = get_settings().coordination_token
    if not x_coordination_token or not secrets.compare_digest(
        x_coordination_token, expected
    ):
        raise HTTPException(status_code=401, detail="invalid coordination token")
    try:
        payload = json.loads(await request.body())
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="invalid JSON body") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid request body")
    _validate_request(path, payload)

    def forward() -> requests.Response:
        return requests.post(
            f"{get_settings().etcd_url}/v3/{path}",
            json=payload,
            timeout=90,
        )

    try:
        response = await run_in_threadpool(forward)
    except requests.RequestException as exc:
        LOGGER.warning("coordination request failed", exc_info=True)
        raise HTTPException(
            status_code=503, detail="coordination journal unavailable"
        ) from exc
    return Response(
        content=response.content,
        status_code=response.status_code,
        media_type=response.headers.get("content-type", "application/json"),
    )
