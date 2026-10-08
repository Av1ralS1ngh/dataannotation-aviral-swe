import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tuf.api.metadata import Metadata, Root

from .fixture import (
    canonical,
    clear_bucket,
    expiry,
    issue_signing_identity,
    load_builder_ca,
    make_attestation,
    make_checkpoint,
    object_get,
    object_put,
    publish_release_metadata,
    push_child,
    push_index,
    wait_for,
    write_attestation,
    write_builder_ca,
    write_signer,
    write_signing_identity,
)

OPERATOR = Path("/operator")
ROOT_KEYS = Path("/root-keys")
PUBLISHER_KEYS = Path("/publisher-keys")
BOOTSTRAP_SECRETS = Path("/bootstrap-secrets")
MARKER = OPERATOR / ".initialized"
BUILDER_ID = "https://ci.acme.example/workflows/release.yml@refs/heads/main"
REVISION = "8f7c2e1a46bd91a73f852c0f48dd8de3ac3ed410"
ROGUE_REVISION = "deadc0de00000000000000000000000000000000"


def reset(path):
    if path.exists():
        for child in path.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    path.mkdir(parents=True, exist_ok=True)


def add_role(root, signer, role):
    root.signed.add_key(signer.public_key, role)


def main():
    scenario = os.getenv("SEED_SCENARIO", "healthy")
    if scenario not in {"healthy", "incident"}:
        raise ValueError("SEED_SCENARIO must be 'healthy' or 'incident'")
    wait_for("http://registry:5000/v2/")
    if MARKER.exists():
        try:
            object_get("metadata/timestamp.json")
        except FileNotFoundError as exc:
            raise RuntimeError(
                "trust material exists but release metadata is missing; "
                "reset all Compose volumes before bootstrapping"
            ) from exc
        print("release trust bootstrap already initialized")
        return
    clear_bucket()
    for path in (OPERATOR, ROOT_KEYS, PUBLISHER_KEYS, BOOTSTRAP_SECRETS):
        reset(path)

    root_signers = {}
    operator_keyring = {}
    for name in (
        "root-old-a",
        "root-old-b",
        "root-compromised",
        "root-new-a",
        "root-new-b",
        "root-new-c",
    ):
        signer, info = write_signer(ROOT_KEYS / "keys", name)
        root_signers[name] = signer
        operator_keyring[name] = info

    online_signers = {}
    online_keyring = {}
    for role in ("targets", "snapshot", "timestamp"):
        signer, info = write_signer(PUBLISHER_KEYS, role)
        online_signers[role] = signer
        online_keyring[role] = info
    ca_info = write_builder_ca(BOOTSTRAP_SECRETS)
    ca_private_key, ca_certificate = load_builder_ca(
        BOOTSTRAP_SECRETS, ca_info
    )
    now = datetime.now(UTC)
    builder = issue_signing_identity(
        ca_private_key,
        ca_certificate,
        BUILDER_ID,
        now - timedelta(days=1),
        now + timedelta(days=30),
    )
    revoked_builder = issue_signing_identity(
        ca_private_key,
        ca_certificate,
        BUILDER_ID,
        now - timedelta(days=7),
        now + timedelta(days=30),
    )
    revoked_at = now.replace(microsecond=0)
    write_signing_identity(BOOTSTRAP_SECRETS, "builder-approved", builder)
    write_signing_identity(
        BOOTSTRAP_SECRETS, "builder-revoked", revoked_builder
    )
    checkpoint_signers = {}
    for name in ("transparency-log", "witness-a", "witness-b"):
        signer, _info = write_signer(BOOTSTRAP_SECRETS, name)
        checkpoint_signers[name] = signer
    (PUBLISHER_KEYS / "keyring.json").write_text(
        json.dumps(online_keyring, indent=2)
    )
    (ROOT_KEYS / "keyring.json").write_text(
        json.dumps(operator_keyring, indent=2)
    )

    root1 = Metadata(Root(version=1, expires=expiry(365)))
    for name in ("root-old-a", "root-old-b", "root-compromised"):
        add_role(root1, root_signers[name], "root")
    root1.signed.roles["root"].threshold = 2
    for role in ("targets", "snapshot", "timestamp"):
        add_role(root1, online_signers[role], role)
        root1.signed.roles[role].threshold = 1
    root1.sign(root_signers["root-old-a"])
    root1.sign(root_signers["root-old-b"], append=True)

    root2 = Metadata(Root(version=2, expires=expiry(365)))
    for name in ("root-new-a", "root-new-b", "root-new-c"):
        add_role(root2, root_signers[name], "root")
    root2.signed.roles["root"].threshold = 2
    for role in ("targets", "snapshot", "timestamp"):
        add_role(root2, online_signers[role], role)
        root2.signed.roles[role].threshold = 1
    if scenario == "incident":
        root2.sign(root_signers["root-new-a"])
        root2.sign(root_signers["root-new-b"], append=True)
    else:
        root2.sign(root_signers["root-old-a"])
        root2.sign(root_signers["root-old-b"], append=True)
        root2.sign(root_signers["root-new-a"], append=True)
        root2.sign(root_signers["root-new-b"], append=True)

    (OPERATOR / "client").mkdir(parents=True, exist_ok=True)
    root1.to_file(str(OPERATOR / "client/1.root.json"))
    object_put("metadata/1.root.json", root1.to_bytes())
    object_put("metadata/2.root.json", root2.to_bytes())
    object_put("metadata/root-index.json", canonical({"versions": [1, 2]}))

    repository = "acme/release-api"
    amd = push_child(repository, "amd64", REVISION, "approved-amd")
    arm = push_child(repository, "arm64", REVISION, "approved-arm")
    bad_arm = push_child(repository, "arm64", ROGUE_REVISION, "poisoned-arm")
    approved_index, _, _ = push_index(
        repository, [("amd64", amd), ("arm64", arm)], "approved"
    )
    stable_arm = bad_arm if scenario == "incident" else arm
    stable_index, _, _ = push_index(
        repository, [("amd64", amd), ("arm64", stable_arm)], "stable"
    )

    checkpoint, _log_leaves = make_checkpoint(
        checkpoint_signers,
        approved_index,
        builder,
        log_origin="incident-log",
        release_epoch=1,
    )

    for child, revision in ((amd, REVISION), (arm, REVISION), (bad_arm, ROGUE_REVISION)):
        envelope = make_attestation(
            builder, repository, child["digest"], BUILDER_ID, revision, checkpoint
        )
        write_attestation(child["digest"], envelope)

    release = {
        "repository": repository,
        "index_digest": approved_index,
        "source_revision": REVISION,
        "builder_id": BUILDER_ID,
        "required_platforms": ["linux/amd64", "linux/arm64"],
        "release_epoch": 1,
    }
    publish_release_metadata(1, release, online_signers)

    policy = {
        "builder_id": BUILDER_ID,
        "builder_ca_pem": (
            BOOTSTRAP_SECRETS / ca_info["certificate"]
        ).read_text(),
        "builder_certificate_revocations": [
            {
                "fingerprint": revoked_builder.fingerprint,
                "effective_at": revoked_at.isoformat().replace("+00:00", "Z"),
            }
        ],
        "required_platforms": ["linux/amd64", "linux/arm64"],
        "checkpoint_keys": {
            name: {"keyid": signer.public_key.keyid, "key": signer.public_key.to_dict()}
            for name, signer in checkpoint_signers.items()
        },
    }
    (OPERATOR / "policy.json").write_text(json.dumps(policy, indent=2))
    (OPERATOR / "incident.json").write_text(
        json.dumps(
            {
                "compromised_keyid": root_signers["root-compromised"].public_key.keyid,
                "compromised_key_name": "root-compromised",
                "approved_revision": REVISION,
                "approved_index_digest": approved_index,
                "mutable_stable_digest": stable_index,
                "seed_scenario": scenario,
            },
            indent=2,
        )
    )
    MARKER.write_text(json.dumps({"scenario": scenario}))
    print("release trust bootstrap ready")


if __name__ == "__main__":
    main()
