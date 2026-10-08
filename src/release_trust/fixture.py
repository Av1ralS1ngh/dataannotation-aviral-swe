"""Supply-chain fixture helpers used by local bootstrap and integration tests."""

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from securesystemslib.signer import CryptoSigner, SSlibKey
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)

REGISTRY = os.environ.get("REGISTRY_URL", "http://registry:5000")
ETCD = os.environ.get("ETCD_URL", "http://etcd:2379")
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


@dataclass
class SigningIdentity:
    private_key: ed25519.Ed25519PrivateKey
    certificate_pem: str

    @property
    def fingerprint(self):
        certificate = x509.load_pem_x509_certificate(self.certificate_pem.encode())
        return certificate.fingerprint(hashes.SHA256()).hex()

    def sign(self, payload):
        return {"sig": self.private_key.sign(payload).hex()}


def _encoded(value):
    if isinstance(value, str):
        value = value.encode()
    return base64.b64encode(value).decode()


def _store_key(key):
    return f"release/{key}"


def clear_bucket():
    response = requests.post(
        f"{ETCD}/v3/kv/range",
        json={"key": _encoded("release/"), "range_end": _encoded("release0")},
        timeout=10,
    )
    response.raise_for_status()
    for item in response.json().get("kvs", []):
        deleted = requests.post(
            f"{ETCD}/v3/kv/deleterange", json={"key": item["key"]}, timeout=10
        )
        deleted.raise_for_status()


def object_put(key, data):
    response = requests.post(
        f"{ETCD}/v3/kv/put",
        json={"key": _encoded(_store_key(key)), "value": _encoded(data)},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def object_get(key):
    response = requests.post(
        f"{ETCD}/v3/kv/range",
        json={"key": _encoded(_store_key(key))},
        timeout=10,
    )
    response.raise_for_status()
    values = response.json().get("kvs", [])
    if not values:
        raise FileNotFoundError(key)
    item = values[0]
    return base64.b64decode(item["value"]), str(item["mod_revision"])


def object_delete(key):
    response = requests.post(
        f"{ETCD}/v3/kv/deleterange",
        json={"key": _encoded(_store_key(key))},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _largest_power_of_two_less_than(value):
    return 1 << ((value - 1).bit_length() - 1)


def merkle_leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def merkle_node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return merkle_leaf_hash(leaves[0])
    split = _largest_power_of_two_less_than(len(leaves))
    return merkle_node_hash(
        merkle_root(leaves[:split]), merkle_root(leaves[split:])
    )


def merkle_inclusion_proof(leaves, index):
    if index < 0 or index >= len(leaves):
        raise ValueError("leaf index is outside the tree")
    if len(leaves) == 1:
        return []
    split = _largest_power_of_two_less_than(len(leaves))
    if index < split:
        return merkle_inclusion_proof(leaves[:split], index) + [
            merkle_root(leaves[split:])
        ]
    return merkle_inclusion_proof(leaves[split:], index - split) + [
        merkle_root(leaves[:split])
    ]


def _consistency_subproof(old_size, leaves, complete_subtree):
    if old_size == len(leaves):
        return [] if complete_subtree else [merkle_root(leaves)]
    split = _largest_power_of_two_less_than(len(leaves))
    if old_size <= split:
        return _consistency_subproof(old_size, leaves[:split], complete_subtree) + [
            merkle_root(leaves[split:])
        ]
    return _consistency_subproof(old_size - split, leaves[split:], False) + [
        merkle_root(leaves[:split])
    ]


def merkle_consistency_proof(old_size, leaves):
    if old_size < 0 or old_size > len(leaves):
        raise ValueError("old tree size is outside the new tree")
    if old_size == 0 or old_size == len(leaves):
        return []
    return _consistency_subproof(old_size, leaves, True)


def wait_for(url, attempts=60):
    for _ in range(attempts):
        try:
            if requests.get(url, timeout=2).status_code < 500:
                return
        except requests.RequestException:
            pass
        import time

        time.sleep(1)
    raise RuntimeError(f"service never became ready: {url}")


def upload_blob(repository, data):
    dgst = digest(data)
    start = requests.post(f"{REGISTRY}/v2/{repository}/blobs/uploads/", timeout=10)
    start.raise_for_status()
    location = urljoin(REGISTRY, start.headers["Location"])
    separator = "&" if "?" in location else "?"
    done = requests.put(f"{location}{separator}digest={dgst}", data=data, timeout=20)
    done.raise_for_status()
    return dgst


def put_manifest(repository, reference, document, media_type):
    data = canonical(document)
    response = requests.put(
        f"{REGISTRY}/v2/{repository}/manifests/{reference}",
        data=data,
        headers={"Content-Type": media_type},
        timeout=20,
    )
    response.raise_for_status()
    return response.headers.get("Docker-Content-Digest", digest(data)), len(data)


def push_child(
    repository,
    architecture,
    revision,
    label,
    *,
    config_revision=None,
    return_graph=False,
):
    config_revision = config_revision or revision
    config_data = canonical(
        {
            "architecture": architecture,
            "os": "linux",
            "config": {
                "Labels": {"org.opencontainers.image.revision": config_revision}
            },
            "rootfs": {"type": "layers", "diff_ids": []},
        }
    )
    layer_data = f"artifact:{label}:{architecture}:{revision}".encode()
    config_digest = upload_blob(repository, config_data)
    layer_digest = upload_blob(repository, layer_data)
    manifest = {
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": {"mediaType": OCI_CONFIG, "digest": config_digest, "size": len(config_data)},
        "layers": [{"mediaType": OCI_LAYER, "digest": layer_digest, "size": len(layer_data)}],
        "annotations": {"org.opencontainers.image.revision": revision},
    }
    manifest_digest, size = put_manifest(repository, digest(canonical(manifest)), manifest, OCI_MANIFEST)
    descriptor = {"mediaType": OCI_MANIFEST, "digest": manifest_digest, "size": size}
    if return_graph:
        return descriptor, {"config": config_digest, "layer": layer_digest}
    return descriptor


def push_index(repository, children, reference):
    descriptors = []
    for architecture, child in children:
        descriptor = dict(child)
        descriptor["platform"] = {"os": "linux", "architecture": architecture}
        descriptors.append(descriptor)
    index = {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": descriptors}
    index_digest, size = put_manifest(repository, reference, index, OCI_INDEX)
    return index_digest, size, index


def write_signer(directory, name):
    directory.mkdir(parents=True, exist_ok=True)
    signer = CryptoSigner.generate_ed25519(keyid=name)
    private_name = f"{name}.pem"
    (directory / private_name).write_bytes(signer.private_bytes)
    os.chmod(directory / private_name, 0o600)
    return signer, {
        "keyid": signer.public_key.keyid,
        "key": signer.public_key.to_dict(),
        "private": private_name,
    }


def load_signer(directory, info):
    key = SSlibKey.from_dict(info["keyid"], info["key"])
    return CryptoSigner.from_priv_key_uri(f"file2:{directory / info['private']}", key)


def write_builder_ca(directory, name="builder-ca"):
    directory.mkdir(parents=True, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key, algorithm=None)
    )
    private_name = f"{name}.pem"
    certificate_name = f"{name}.crt"
    (directory / private_name).write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (directory / certificate_name).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return {
        "private": private_name,
        "certificate": certificate_name,
    }


def load_builder_ca(directory, info):
    private_key = serialization.load_pem_private_key(
        (directory / info["private"]).read_bytes(), password=None
    )
    certificate = x509.load_pem_x509_certificate((directory / info["certificate"]).read_bytes())
    return private_key, certificate


def issue_signing_identity(ca_private_key, ca_certificate, builder_id, not_before, not_after):
    private_key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "release builder")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(builder_id)]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False
        )
        .sign(ca_private_key, algorithm=None)
    )
    return SigningIdentity(
        private_key=private_key,
        certificate_pem=certificate.public_bytes(serialization.Encoding.PEM).decode(),
    )


def write_signing_identity(directory, name, identity):
    private_name = f"{name}.pem"
    certificate_name = f"{name}.crt"
    (directory / private_name).write_bytes(
        identity.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (directory / certificate_name).write_text(identity.certificate_pem)
    return {"private": private_name, "certificate": certificate_name}


def load_signing_identity(directory, info):
    return SigningIdentity(
        private_key=serialization.load_pem_private_key(
            (directory / info["private"]).read_bytes(), password=None
        ),
        certificate_pem=(directory / info["certificate"]).read_text(),
    )


def make_checkpoint(
    signers,
    index_digest,
    identity,
    log_origin="release-log",
    integrated_time=None,
    release_epoch=1,
    prior_leaves=None,
    filler_count=0,
):
    integrated_time = integrated_time or datetime.now(UTC)
    entry = {
        "index_digest": index_digest,
        "integrated_time": integrated_time.isoformat().replace("+00:00", "Z"),
        "signer_fingerprint": identity.fingerprint,
        "release_epoch": release_epoch,
    }
    prior_leaves = list(prior_leaves or [])
    fillers = [
        canonical(
            {
                "filler": hashlib.sha256(
                    canonical(entry) + index.to_bytes(4, "big")
                ).hexdigest()
            }
        )
        for index in range(filler_count)
    ]
    leaves = prior_leaves + fillers + [canonical(entry)]
    leaf_index = len(leaves) - 1
    body = {
        "log_origin": log_origin,
        "tree_size": len(leaves),
        "root_hash": merkle_root(leaves).hex(),
    }
    payload = canonical(body)
    return (
        {
            "body": body,
            "entry": entry,
            "leaf_index": leaf_index,
            "inclusion_proof": [
                item.hex() for item in merkle_inclusion_proof(leaves, leaf_index)
            ],
            "consistency_proof": [
                item.hex()
                for item in merkle_consistency_proof(len(prior_leaves), leaves)
            ],
            "signatures": {
                name: signer.sign(payload).to_dict() for name, signer in signers.items()
            },
        },
        leaves,
    )


def make_attestation(identity, repository, manifest_digest, builder_id, revision, checkpoint):
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": repository, "digest": {"sha256": manifest_digest.removeprefix("sha256:")}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "builder": {"id": builder_id},
            "source": {
                "uri": "git+https://code.acme.example/release-api",
                "digest": {"sha1": revision},
            },
        },
    }
    payload = canonical(statement)
    signature = identity.sign(payload)
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(payload).decode(),
        "signatures": [signature],
        "certificate": identity.certificate_pem,
        "checkpoint": checkpoint,
    }


def write_attestation(manifest_digest, envelope):
    key = f"attestations/{manifest_digest.removeprefix('sha256:')}.json"
    object_put(key, canonical(envelope))


def expiry(days):
    return datetime.now(UTC) + timedelta(days=days)


def build_release_metadata(version, release, signers):
    target_path = (
        f"releases/{release['repository']}/"
        f"{release['index_digest'].removeprefix('sha256:')}.json"
    )
    target_data = canonical(release)
    targets = Metadata(
        Targets(
            version=version,
            expires=expiry(30),
            targets={target_path: TargetFile.from_data(target_path, target_data, ["sha256"])},
            unrecognized_fields={"channels": {"stable": target_path}},
        )
    )
    targets.sign(signers["targets"])
    targets_bytes = targets.to_bytes()

    snapshot = Metadata(
        Snapshot(
            version=version,
            expires=expiry(7),
            meta={"targets.json": MetaFile.from_data(version, targets_bytes, ["sha256"])},
        )
    )
    snapshot.sign(signers["snapshot"])
    snapshot_bytes = snapshot.to_bytes()

    timestamp = Metadata(
        Timestamp(
            version=version,
            expires=expiry(1),
            snapshot_meta=MetaFile.from_data(version, snapshot_bytes, ["sha256"]),
        )
    )
    timestamp.sign(signers["timestamp"])
    return target_path, target_data, targets_bytes, snapshot_bytes, timestamp.to_bytes()


def publish_release_metadata(version, release, signers):
    target_path, target_data, targets, snapshot, timestamp = build_release_metadata(
        version, release, signers
    )
    object_put(f"targets/{target_path}", target_data)
    object_put(f"metadata/{version}.targets.json", targets)
    object_put(f"metadata/{version}.snapshot.json", snapshot)
    object_put("metadata/timestamp.json", timestamp)
    return timestamp
