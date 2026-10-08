"""OCI registry and exact provenance verification helpers."""

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime
from urllib.parse import quote

import requests
from securesystemslib.signer import Signature, SSlibKey

from . import rfc6962, workload_identity
from .config import get_settings

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
}
class VerificationError(Exception):
    pass


def get_manifest(repository, reference):
    registry = get_settings().registry_url
    url = f"{registry}/v2/{repository}/manifests/{quote(reference, safe=':')}"
    response = requests.get(
        url,
        headers={"Accept": f"{OCI_INDEX}, {OCI_MANIFEST}"},
        timeout=10,
    )
    response.raise_for_status()
    observed = response.headers.get("Docker-Content-Digest")
    computed = f"sha256:{hashlib.sha256(response.content).hexdigest()}"
    if observed != computed:
        raise VerificationError(
            "registry index bytes do not match the reported digest"
        )
    try:
        manifest = json.loads(response.content)
    except (TypeError, ValueError) as exc:
        raise VerificationError("registry index is not valid JSON") from exc
    return manifest, observed


def validate_platform_closure(index, required_platforms):
    if index.get("schemaVersion") != 2 or index.get("mediaType") != OCI_INDEX:
        raise VerificationError("authorized artifact is not an OCI image index")
    required = set(required_platforms)
    found = {}
    for descriptor in index.get("manifests", []):
        platform = descriptor.get("platform") or {}
        name = f"{platform.get('os')}/{platform.get('architecture')}"
        if name not in required:
            raise VerificationError(f"unexpected platform descriptor {name!r}")
        if name in found:
            raise VerificationError(f"duplicate platform descriptor {name!r}")
        if descriptor.get("mediaType") != OCI_MANIFEST:
            raise VerificationError(f"platform {name} is not an OCI image manifest")
        if not str(descriptor.get("digest", "")).startswith("sha256:"):
            raise VerificationError(f"platform {name} has no sha256 digest")
        found[name] = descriptor
    missing = required - set(found)
    if missing:
        raise VerificationError(f"missing required platforms: {sorted(missing)}")
    return found


def _fetch_blob(repository, descriptor, *, expected_media_types):
    registry = get_settings().registry_url
    if not isinstance(descriptor, dict):
        raise VerificationError("OCI blob descriptor is absent")
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    media_type = descriptor.get("mediaType")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise VerificationError("OCI blob descriptor has no sha256 digest")
    if not isinstance(size, int) or size < 0:
        raise VerificationError("OCI blob descriptor has an invalid size")
    if media_type not in expected_media_types:
        raise VerificationError(f"unsupported OCI blob media type {media_type!r}")
    response = requests.get(
        f"{registry}/v2/{repository}/blobs/{quote(digest, safe=':')}", timeout=10
    )
    if response.status_code != 200:
        raise VerificationError(f"required OCI blob {digest} is unavailable")
    body = response.content
    if f"sha256:{hashlib.sha256(body).hexdigest()}" != digest:
        raise VerificationError("OCI blob bytes do not match the descriptor digest")
    if len(body) != size:
        raise VerificationError("OCI blob bytes do not match the descriptor size")
    return body


def verify_child_manifest(repository, descriptor, platform_name):
    """Verify a child's manifest and the complete runnable OCI content graph."""
    registry = get_settings().registry_url
    digest = descriptor["digest"]
    response = requests.get(
        f"{registry}/v2/{repository}/manifests/{quote(digest, safe=':')}",
        headers={"Accept": OCI_MANIFEST},
        timeout=10,
    )
    if response.status_code != 200:
        raise VerificationError(f"required child manifest {digest} is unavailable")
    body = response.content
    observed = f"sha256:{hashlib.sha256(body).hexdigest()}"
    if observed != digest:
        raise VerificationError("required child bytes do not match the descriptor digest")
    if descriptor.get("size") != len(body):
        raise VerificationError("required child bytes do not match the descriptor size")
    try:
        manifest = json.loads(body)
    except Exception as exc:
        raise VerificationError(f"required child is not valid JSON: {exc}") from exc
    if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") != OCI_MANIFEST:
        raise VerificationError("required child is not an OCI image manifest")

    config_bytes = _fetch_blob(
        repository, manifest.get("config"), expected_media_types={OCI_CONFIG}
    )
    layers = manifest.get("layers")
    if not isinstance(layers, list):
        raise VerificationError("OCI image manifest has no layer descriptor list")
    for layer in layers:
        _fetch_blob(repository, layer, expected_media_types=OCI_LAYER_TYPES)
    try:
        config = json.loads(config_bytes)
    except Exception as exc:
        raise VerificationError(f"OCI image config is not valid JSON: {exc}") from exc
    expected_os, expected_architecture = platform_name.split("/", 1)
    if config.get("os") != expected_os or config.get("architecture") != expected_architecture:
        raise VerificationError("OCI image config contradicts its platform descriptor")
    revision = (
        ((config.get("config") or {}).get("Labels") or {}).get(
            "org.opencontainers.image.revision"
        )
    )
    if not isinstance(revision, str) or not revision:
        raise VerificationError("OCI image config has no embedded source revision")
    return manifest, revision


def load_attestation(manifest_digest):
    metadata_url = get_settings().metadata_url
    digest = manifest_digest.removeprefix("sha256:")
    response = requests.get(f"{metadata_url}/attestations/{digest}.json", timeout=10)
    response.raise_for_status()
    return response.json()


def _verify_signing_identity(envelope, policy, payload, checkpoint_entry):
    try:
        workload_identity.verify_code_signing_envelope(
            envelope["certificate"],
            policy["builder_ca_pem"],
            policy["builder_id"],
            checkpoint_entry["integrated_time"],
            checkpoint_entry.get("signer_fingerprint"),
            envelope.get("signatures") or [],
            payload,
        )
    except Exception as exc:
        raise VerificationError(f"invalid builder signing identity: {exc}") from exc
    integrated_time = datetime.fromisoformat(
        checkpoint_entry["integrated_time"].replace("Z", "+00:00")
    ).astimezone(UTC)
    fingerprint = checkpoint_entry["signer_fingerprint"]
    for revocation in policy.get("builder_certificate_revocations", []):
        if revocation.get("fingerprint") != fingerprint:
            continue
        try:
            effective_at = datetime.fromisoformat(
                revocation["effective_at"].replace("Z", "+00:00")
            ).astimezone(UTC)
        except (KeyError, TypeError, ValueError) as exc:
            raise VerificationError(
                "builder certificate revocation policy is malformed"
            ) from exc
        if integrated_time >= effective_at:
            raise VerificationError(
                "builder certificate was revoked at log integration time"
            )


def verify_attestation(
    envelope,
    policy,
    repository,
    manifest_digest,
    expected_revision,
    expected_index_digest,
    expected_release_epoch,
):
    try:
        if envelope.get("payloadType") != "application/vnd.in-toto+json":
            raise ValueError("unexpected payload type")
        payload = base64.b64decode(envelope["payload"], validate=True)
        statement = json.loads(payload)
    except Exception as exc:
        raise VerificationError(f"invalid provenance envelope: {exc}") from exc

    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise VerificationError("not an in-toto v1 statement")
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise VerificationError("not a SLSA provenance statement")
    predicate = statement.get("predicate") or {}
    builder = (predicate.get("builder") or {}).get("id")
    if builder != policy["builder_id"]:
        raise VerificationError(f"unapproved builder identity {builder!r}")
    revision = ((predicate.get("source") or {}).get("digest") or {}).get("sha1")
    if revision != expected_revision:
        raise VerificationError(
            f"provenance revision {revision!r} does not match authorized revision"
        )
    subjects = statement.get("subject") or []
    expected_subject = {
        "name": repository,
        "digest": {"sha256": manifest_digest.removeprefix("sha256:")},
    }
    if expected_subject not in subjects:
        raise VerificationError("provenance subject does not bind this repository and digest")

    try:
        checkpoint = envelope["checkpoint"]
        body = checkpoint["body"]
        entry = checkpoint["entry"]
        if entry["index_digest"] != expected_index_digest:
            raise ValueError("checkpoint authorizes another OCI index")
        if entry.get("release_epoch") != expected_release_epoch:
            raise ValueError("checkpoint belongs to another release-policy epoch")
        rfc6962.verify_inclusion(
            json.dumps(entry, sort_keys=True, separators=(",", ":")).encode(),
            checkpoint["leaf_index"],
            body["tree_size"],
            checkpoint.get("inclusion_proof") or [],
            body["root_hash"],
        )
        signatures = checkpoint.get("signatures") or {}
        if set(signatures) != {"transparency-log", "witness-a", "witness-b"}:
            raise ValueError("checkpoint lacks the exact log and witness quorum")
        signed = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        for name, key_info in policy["checkpoint_keys"].items():
            key = SSlibKey.from_dict(
                key_info["keyid"], copy.deepcopy(key_info["key"])
            )
            key.verify_signature(
                Signature.from_dict(copy.deepcopy(signatures[name])), signed
            )
    except Exception as exc:
        raise VerificationError(f"invalid witnessed checkpoint: {exc}") from exc
    _verify_signing_identity(envelope, policy, payload, entry)
    return statement, checkpoint
