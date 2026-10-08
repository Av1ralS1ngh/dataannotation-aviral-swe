"""Admission audit helpers kept separate from verification logic."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from .models import AdmissionDecision, ValidationEvent


def begin_decision(
    session: Session,
    *,
    request_id: str,
    replica_id: str,
    repository: str,
    channel: str,
    platform: str,
) -> AdmissionDecision:
    decision = AdmissionDecision(
        request_id=request_id,
        replica_id=replica_id,
        repository=repository,
        channel=channel,
        platform=platform,
    )
    session.add(decision)
    session.commit()
    return decision


def record_event(
    session: Session,
    decision: AdmissionDecision,
    stage: str,
    outcome: str,
    detail: str | None = None,
) -> None:
    session.add(
        ValidationEvent(
            decision_id=decision.id,
            stage=stage,
            outcome=outcome,
            detail=detail,
        )
    )
    session.commit()


def complete_decision(
    session: Session,
    decision: AdmissionDecision,
    *,
    allowed: bool,
    index_digest: str | None = None,
    manifest_digest: str | None = None,
    source_revision: str | None = None,
    error_code: str | None = None,
    message: str | None = None,
) -> None:
    decision.allowed = allowed
    decision.index_digest = index_digest
    decision.manifest_digest = manifest_digest
    decision.source_revision = source_revision
    decision.error_code = error_code
    decision.message = message
    decision.completed_at = datetime.now(UTC)
    session.add(decision)
    session.commit()


def serialize_decision(decision: AdmissionDecision) -> dict:
    return {
        "id": decision.id,
        "request_id": decision.request_id,
        "replica_id": decision.replica_id,
        "repository": decision.repository,
        "channel": decision.channel,
        "platform": decision.platform,
        "index_digest": decision.index_digest,
        "manifest_digest": decision.manifest_digest,
        "source_revision": decision.source_revision,
        "allowed": decision.allowed,
        "error_code": decision.error_code,
        "message": decision.message,
        "created_at": decision.created_at,
        "completed_at": decision.completed_at,
        "events": [
            {
                "stage": event.stage,
                "outcome": event.outcome,
                "detail": event.detail,
                "created_at": event.created_at,
            }
            for event in decision.events
        ],
    }
