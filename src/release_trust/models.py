"""Relational audit models for admission decisions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class AdmissionDecision(Base):
    __tablename__ = "admission_decisions"
    __table_args__ = (
        Index("ix_decision_repository_channel", "repository", "channel"),
        Index("ix_decision_created_allowed", "created_at", "allowed"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    replica_id: Mapped[str] = mapped_column(String(80))
    repository: Mapped[str] = mapped_column(String(255))
    channel: Mapped[str] = mapped_column(String(80))
    platform: Mapped[str] = mapped_column(String(80))
    index_digest: Mapped[str | None] = mapped_column(String(80), nullable=True)
    manifest_digest: Mapped[str | None] = mapped_column(String(80), nullable=True)
    source_revision: Mapped[str | None] = mapped_column(String(64), nullable=True)
    allowed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    events: Mapped[list[ValidationEvent]] = relationship(
        back_populates="decision",
        cascade="all, delete-orphan",
        order_by="ValidationEvent.id",
    )


class ValidationEvent(Base):
    __tablename__ = "validation_events"
    __table_args__ = (Index("ix_event_stage_outcome", "stage", "outcome"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(
        ForeignKey("admission_decisions.id", ondelete="CASCADE"), index=True
    )
    stage: Mapped[str] = mapped_column(String(80))
    outcome: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )

    decision: Mapped[AdmissionDecision] = relationship(back_populates="events")
