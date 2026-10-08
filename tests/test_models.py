from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from release_trust import audit
from release_trust.models import AdmissionDecision, Base


def test_decision_keeps_ordered_validation_events():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine, expire_on_commit=False) as session:
        decision = audit.begin_decision(
            session,
            request_id="request-1",
            replica_id="admission-test",
            repository="acme/release-api",
            channel="stable",
            platform="linux/amd64",
        )
        audit.record_event(session, decision, "metadata", "passed")
        audit.record_event(session, decision, "provenance", "passed")
        audit.complete_decision(
            session,
            decision,
            allowed=True,
            index_digest="sha256:" + "a" * 64,
        )

        stored = session.scalar(
            select(AdmissionDecision).where(AdmissionDecision.id == decision.id)
        )
        assert stored is not None
        assert stored.allowed is True
        assert [event.stage for event in stored.events] == [
            "metadata",
            "provenance",
        ]


def test_audit_tables_expose_query_indexes():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    inspector = inspect(engine)

    decision_indexes = {
        index["name"] for index in inspector.get_indexes("admission_decisions")
    }
    event_indexes = {
        index["name"] for index in inspector.get_indexes("validation_events")
    }
    assert "ix_decision_repository_channel" in decision_indexes
    assert "ix_decision_created_allowed" in decision_indexes
    assert "ix_event_stage_outcome" in event_indexes
