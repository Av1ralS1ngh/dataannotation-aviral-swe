import hashlib
import json

import pytest

from release_trust import oci


class Response:
    def __init__(self, body: bytes, digest: str):
        self.content = body
        self.headers = {"Docker-Content-Digest": digest}

    def raise_for_status(self):
        return None


def descriptor(architecture: str, digest_char: str = "a") -> dict:
    return {
        "mediaType": oci.OCI_MANIFEST,
        "digest": "sha256:" + digest_char * 64,
        "size": 123,
        "platform": {"os": "linux", "architecture": architecture},
    }


def test_platform_closure_requires_exact_set():
    index = {
        "schemaVersion": 2,
        "mediaType": oci.OCI_INDEX,
        "manifests": [descriptor("amd64"), descriptor("arm64", "b")],
    }
    found = oci.validate_platform_closure(
        index,
        ["linux/amd64", "linux/arm64"],
    )
    assert set(found) == {"linux/amd64", "linux/arm64"}


def test_platform_closure_rejects_duplicate_descriptor():
    index = {
        "schemaVersion": 2,
        "mediaType": oci.OCI_INDEX,
        "manifests": [descriptor("amd64"), descriptor("amd64", "b")],
    }
    with pytest.raises(oci.VerificationError, match="duplicate"):
        oci.validate_platform_closure(index, ["linux/amd64"])


def test_platform_closure_rejects_unexpected_platform():
    index = {
        "schemaVersion": 2,
        "mediaType": oci.OCI_INDEX,
        "manifests": [descriptor("amd64"), descriptor("s390x", "c")],
    }
    with pytest.raises(oci.VerificationError, match="unexpected"):
        oci.validate_platform_closure(index, ["linux/amd64"])


def test_index_body_must_match_registry_digest(monkeypatch):
    body = json.dumps({"schemaVersion": 2}).encode()
    digest = f"sha256:{hashlib.sha256(body).hexdigest()}"
    monkeypatch.setattr(
        oci.requests,
        "get",
        lambda *_args, **_kwargs: Response(body, digest),
    )
    manifest, observed = oci.get_manifest("acme/release-api", digest)
    assert manifest["schemaVersion"] == 2
    assert observed == digest

    monkeypatch.setattr(
        oci.requests,
        "get",
        lambda *_args, **_kwargs: Response(body, "sha256:" + "0" * 64),
    )
    with pytest.raises(oci.VerificationError, match="reported digest"):
        oci.get_manifest("acme/release-api", digest)
