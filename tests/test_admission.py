import json

from fastapi.testclient import TestClient


def configure_policy(tmp_path):
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "policy.json").write_text(
        json.dumps(
            {
                "required_platforms": ["linux/amd64", "linux/arm64"],
                "builder_id": "builder",
            }
        )
    )


def test_admission_records_successful_decision(
    isolated_settings,
    monkeypatch,
):
    configure_policy(isolated_settings)
    from release_trust import admission

    digest = "sha256:" + "a" * 64
    descriptors = {
        "linux/amd64": {"digest": "sha256:" + "b" * 64},
        "linux/arm64": {"digest": "sha256:" + "c" * 64},
    }
    release = {
        "repository": "acme/release-api",
        "index_digest": digest,
        "source_revision": "8f7c2e1",
        "release_epoch": 1,
    }
    statement = {
        "predicate": {"source": {"digest": {"sha1": "8f7c2e1"}}}
    }
    checkpoint = {"body": {"tree_size": 1}}

    monkeypatch.setattr(
        admission.trust,
        "current_release",
        lambda _channel: (release, {"journal_available": True}),
    )
    monkeypatch.setattr(
        admission.oci,
        "get_manifest",
        lambda _repository, _reference: ({"schemaVersion": 2}, digest),
    )
    monkeypatch.setattr(
        admission.oci,
        "validate_platform_closure",
        lambda _index, _required: descriptors,
    )
    monkeypatch.setattr(
        admission.oci,
        "verify_child_manifest",
        lambda _repository, _descriptor, _platform: ({}, "8f7c2e1"),
    )
    monkeypatch.setattr(admission.oci, "load_attestation", lambda _digest: {})
    monkeypatch.setattr(
        admission.oci,
        "verify_attestation",
        lambda *_args: (statement, checkpoint),
    )
    monkeypatch.setattr(
        admission.trust,
        "commit_authorization",
        lambda *_args: None,
    )

    with TestClient(admission.app) as client:
        response = client.get(
            "/admit",
            params={
                "repository": "acme/release-api",
                "platform": "linux/amd64",
            },
            headers={"x-request-id": "request-123"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["allowed"] is True
        assert body["request_id"] == "request-123"

        audit_response = client.get(
            f"/decisions/{body['decision_id']}",
            headers={"authorization": "Bearer test-admin"},
        )
        assert audit_response.status_code == 200
        assert [event["stage"] for event in audit_response.json()["events"]] == [
            "metadata",
            "oci_index",
            "provenance",
            "authorization_commit",
        ]


def test_verification_failure_has_structured_error(
    isolated_settings,
    monkeypatch,
):
    configure_policy(isolated_settings)
    from release_trust import admission

    monkeypatch.setattr(
        admission.trust,
        "current_release",
        lambda _channel: (_ for _ in ()).throw(
            admission.trust.TrustError("metadata rollback")
        ),
    )

    with TestClient(admission.app) as client:
        response = client.get(
            "/admit",
            params={"repository": "acme/release-api"},
        )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "verification_failed"
    assert response.json()["detail"]["decision_id"]
