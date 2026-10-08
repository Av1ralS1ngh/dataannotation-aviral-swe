import pytest
from pydantic import ValidationError

from release_trust import publisher


def test_promotion_rejects_mutable_or_malformed_digest():
    with pytest.raises(ValidationError):
        publisher.Promotion(
            repository="acme/release-api",
            index_digest="stable",
            source_revision="8f7c2e1",
            release_epoch=1,
        )


def test_immutable_put_accepts_existing_identical_bytes(monkeypatch):
    monkeypatch.setattr(publisher, "_transaction", lambda *_args: False)
    monkeypatch.setattr(publisher, "_get", lambda _path: (b"same", 7))

    assert publisher._put_immutable("targets/release.json", b"same") is True
    assert publisher._put_immutable("targets/release.json", b"different") is False


def test_promotion_requires_positive_epoch():
    with pytest.raises(ValidationError):
        publisher.Promotion(
            repository="acme/release-api",
            index_digest="sha256:" + "a" * 64,
            source_revision="8f7c2e1",
            release_epoch=0,
        )
