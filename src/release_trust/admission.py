"""Admission API for exact, signed OCI release decisions."""

from __future__ import annotations

import json
import logging
import uuid
from contextlib import asynccontextmanager

import requests
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from . import audit, oci, trust
from .auth import require_admin_token
from .config import get_settings
from .db import get_session, init_database
from .logging_config import configure_logging
from .models import AdmissionDecision

configure_logging()
LOGGER = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_database()
    yield


app = FastAPI(title="Release Trust Admission", version="0.1.0", lifespan=lifespan)


@app.get("/healthz")
def healthz():
    """Process liveness; dependency readiness is checked by service operations."""
    return {"ok": True}


def _failure_status(exc: Exception) -> tuple[int, str]:
    if isinstance(exc, oci.VerificationError | trust.TrustError):
        return 403, "verification_failed"
    if isinstance(exc, requests.RequestException):
        return 503, "dependency_unavailable"
    if isinstance(exc, KeyError | TypeError | ValueError):
        return 422, "invalid_release_data"
    return 500, "internal_error"


@app.get("/admit")
def admit(
    repository: str = Query(max_length=255, pattern=r"^[a-z0-9._/-]+$"),
    channel: str = Query(
        default="stable", max_length=80, pattern=r"^[a-z0-9._-]+$"
    ),
    platform: str = Query(
        default="linux/amd64",
        max_length=80,
        pattern=r"^[a-z0-9._-]+/[a-z0-9._-]+$",
    ),
    x_request_id: str | None = Header(default=None, max_length=64),
    session: Session = Depends(get_session),
):
    request_id = x_request_id or uuid.uuid4().hex
    decision: AdmissionDecision | None = None
    release: dict | None = None
    stage = "audit"
    try:
        settings = get_settings()
        decision = audit.begin_decision(
            session,
            request_id=request_id,
            replica_id=settings.replica_id,
            repository=repository,
            channel=channel,
            platform=platform,
        )
        policy_path = settings.operator_dir / "policy.json"
        policy = json.loads(policy_path.read_text())
        stage = "metadata"
        release, trusted_state_update = trust.current_release(channel)
        audit.record_event(session, decision, "metadata", "passed")
        if release["repository"] != repository:
            raise oci.VerificationError(
                "release target belongs to another repository"
            )

        stage = "oci_index"
        index, observed_index_digest = oci.get_manifest(
            repository, release["index_digest"]
        )
        if observed_index_digest != release["index_digest"]:
            raise oci.VerificationError(
                "registry returned a different index digest"
            )
        platforms = oci.validate_platform_closure(
            index, policy["required_platforms"]
        )
        if platform not in platforms:
            raise oci.VerificationError(
                f"platform {platform!r} is not authorized by policy"
            )
        audit.record_event(session, decision, "oci_index", "passed")

        stage = "provenance"
        statements = {}
        checkpoints = {}
        for platform_name, descriptor in platforms.items():
            _manifest, config_revision = oci.verify_child_manifest(
                repository, descriptor, platform_name
            )
            if config_revision != release["source_revision"]:
                raise oci.VerificationError(
                    "OCI image config revision contradicts the authorized release"
                )
            envelope = oci.load_attestation(descriptor["digest"])
            statements[platform_name], checkpoints[platform_name] = (
                oci.verify_attestation(
                    envelope,
                    policy,
                    repository,
                    descriptor["digest"],
                    release["source_revision"],
                    release["index_digest"],
                    release["release_epoch"],
                )
            )
        audit.record_event(session, decision, "provenance", "passed")

        checkpoint_bundles = list(checkpoints.values())
        if not checkpoint_bundles or any(
            checkpoint != checkpoint_bundles[0]
            for checkpoint in checkpoint_bundles[1:]
        ):
            raise oci.VerificationError(
                "platform attestations disagree on transparency history"
            )
        stage = "authorization_commit"
        trust.commit_authorization(trusted_state_update, checkpoint_bundles[0])
        audit.record_event(session, decision, "authorization_commit", "passed")

        child = platforms[platform]
        statement = statements[platform]
        revision = statement["predicate"]["source"]["digest"]["sha1"]
        audit.complete_decision(
            session,
            decision,
            allowed=True,
            index_digest=release["index_digest"],
            manifest_digest=child["digest"],
            source_revision=revision,
        )
        LOGGER.info(
            "release admitted",
            extra={
                "request_id": request_id,
                "decision_id": decision.id,
                "repository": repository,
                "channel": channel,
            },
        )
        return {
            "allowed": True,
            "decision_id": decision.id,
            "request_id": request_id,
            "repository": repository,
            "channel": channel,
            "platform": platform,
            "authorized_index_digest": release["index_digest"],
            "observed_index_digest": observed_index_digest,
            "manifest_digest": child["digest"],
            "source_revision": revision,
        }
    except Exception as exc:
        status_code, error_code = _failure_status(exc)
        session.rollback()
        if decision is not None:
            try:
                audit.record_event(session, decision, stage, "failed", str(exc))
                audit.complete_decision(
                    session,
                    decision,
                    allowed=False,
                    index_digest=release.get("index_digest") if release else None,
                    error_code=error_code,
                    message=str(exc),
                )
            except Exception:
                session.rollback()
                LOGGER.error(
                    "could not persist failed admission audit",
                    extra={"request_id": request_id},
                    exc_info=True,
                )
        LOGGER.warning(
            "release denied",
            extra={
                "request_id": request_id,
                "decision_id": decision.id if decision else None,
                "repository": repository,
                "channel": channel,
            },
            exc_info=status_code == 500,
        )
        public_message = (
            str(exc)
            if status_code in {403, 422}
            else "a required service is unavailable"
            if status_code == 503
            else "admission could not be completed"
        )
        raise HTTPException(
            status_code=status_code,
            detail={
                "code": error_code,
                "message": public_message,
                "decision_id": decision.id if decision else None,
            },
        ) from exc


@app.get("/decisions/{decision_id}", dependencies=[Depends(require_admin_token)])
def get_decision(
    decision_id: str,
    session: Session = Depends(get_session),
):
    decision = session.scalar(
        select(AdmissionDecision)
        .where(AdmissionDecision.id == decision_id)
        .options(selectinload(AdmissionDecision.events))
    )
    if decision is None:
        raise HTTPException(status_code=404, detail="decision not found")
    return audit.serialize_decision(decision)
