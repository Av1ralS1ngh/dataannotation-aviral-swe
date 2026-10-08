"""Linearizable, interruption-safe TUF publication through etcd transactions."""

import base64
import json
import os
import time
from datetime import UTC, datetime, timedelta

import requests
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from securesystemslib.signer import CryptoSigner, SSlibKey
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)

from .auth import require_publisher_token
from .config import get_settings
from .logging_config import configure_logging

SETTINGS = get_settings()
ETCD = SETTINGS.etcd_url
KEYS = SETTINGS.online_keys_dir
PUBLISHER_ID = os.environ.get("PUBLISHER_ID", "publisher")
configure_logging()
app = FastAPI(title="Release Metadata Publisher", version="0.1.0")


class Promotion(BaseModel):
    channel: str = Field(default="stable", pattern=r"^[a-z0-9._-]+$")
    repository: str = Field(pattern=r"^[a-z0-9._/-]+$")
    index_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    source_revision: str = Field(min_length=7, max_length=64)
    release_epoch: int = Field(ge=1)


def _encoded(value):
    if isinstance(value, str):
        value = value.encode()
    return base64.b64encode(value).decode()


def _key(path):
    return f"release/{path}"


def _get(path):
    response = requests.post(
        f"{ETCD}/v3/kv/range", json={"key": _encoded(_key(path))}, timeout=10
    )
    response.raise_for_status()
    values = response.json().get("kvs", [])
    if not values:
        raise FileNotFoundError(path)
    item = values[0]
    return base64.b64decode(item["value"]), int(item["mod_revision"])


def _transaction(compare, success):
    response = requests.post(
        f"{ETCD}/v3/kv/txn",
        json={"compare": compare, "success": success, "failure": []},
        timeout=10,
    )
    response.raise_for_status()
    return bool(response.json().get("succeeded"))


def _put_immutable(path, data):
    key = _encoded(_key(path))
    created = _transaction(
        [{"key": key, "target": "CREATE", "result": "EQUAL", "create_revision": "0"}],
        [{"request_put": {"key": key, "value": _encoded(data)}}],
    )
    if created:
        return True
    existing, _revision = _get(path)
    return existing == data


def _compare_and_put(path, expected_revision, data):
    key = _encoded(_key(path))
    return _transaction(
        [
            {
                "key": key,
                "target": "MOD",
                "result": "EQUAL",
                "mod_revision": str(expected_revision),
            }
        ],
        [{"request_put": {"key": key, "value": _encoded(data)}}],
    )


def _load_signer(role):
    info = json.loads((KEYS / "keyring.json").read_text())[role]
    key = SSlibKey.from_dict(info["keyid"], info["key"])
    return CryptoSigner.from_priv_key_uri(f"file2:{KEYS / info['private']}", key)


def _expires(days):
    today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    return today + timedelta(days=days + 1)


def _current_targets(timestamp_bytes):
    timestamp = Metadata.from_bytes(timestamp_bytes)
    snapshot_bytes, _revision = _get(
        f"metadata/{timestamp.signed.snapshot_meta.version}.snapshot.json"
    )
    snapshot = Metadata.from_bytes(snapshot_bytes)
    targets_link = snapshot.signed.meta["targets.json"]
    targets_bytes, _revision = _get(f"metadata/{targets_link.version}.targets.json")
    return Metadata.from_bytes(targets_bytes)


def _build_metadata(promotion, version, previous_targets):
    target_path = (
        f"releases/{promotion.repository}/"
        f"{promotion.index_digest.removeprefix('sha256:')}.json"
    )
    target_data = json.dumps(
        {
            "repository": promotion.repository,
            "index_digest": promotion.index_digest,
            "source_revision": promotion.source_revision,
            "release_epoch": promotion.release_epoch,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    target_files = dict(previous_targets.signed.targets)
    target_files[target_path] = TargetFile.from_data(target_path, target_data, ["sha256"])
    channels = dict(previous_targets.signed.unrecognized_fields.get("channels", {}))
    channels[promotion.channel] = target_path
    targets = Metadata(
        Targets(
            version=version,
            expires=_expires(30),
            targets=target_files,
            unrecognized_fields={"channels": channels},
        )
    )
    targets.sign(_load_signer("targets"))
    targets_bytes = targets.to_bytes()
    snapshot = Metadata(
        Snapshot(
            version=version,
            expires=_expires(7),
            meta={"targets.json": MetaFile.from_data(version, targets_bytes, ["sha256"])},
        )
    )
    snapshot.sign(_load_signer("snapshot"))
    snapshot_bytes = snapshot.to_bytes()
    timestamp = Metadata(
        Timestamp(
            version=version,
            expires=_expires(1),
            snapshot_meta=MetaFile.from_data(version, snapshot_bytes, ["sha256"]),
        )
    )
    timestamp.sign(_load_signer("timestamp"))
    return target_path, target_data, targets_bytes, snapshot_bytes, timestamp.to_bytes()


@app.get("/healthz")
def healthz():
    return {"ok": True, "publisher": PUBLISHER_ID}


@app.post("/promote")
def promote(
    promotion: Promotion,
    _authorized: None = Depends(require_publisher_token),
):
    try:
        candidate_floor = 0
        for _attempt in range(40):
            current, revision = _get("metadata/timestamp.json")
            version = max(
                Metadata.from_bytes(current).signed.version + 1,
                candidate_floor,
            )
            previous_targets = _current_targets(current)
            target_path, target_data, targets, snapshot, timestamp = _build_metadata(
                promotion, version, previous_targets
            )

            if not _put_immutable(f"targets/{target_path}", target_data):
                raise RuntimeError("immutable release target conflicts with existing bytes")
            if not _put_immutable(f"metadata/{version}.targets.json", targets):
                candidate_floor = version + 1
                time.sleep(0.05)
                continue
            if not _put_immutable(f"metadata/{version}.snapshot.json", snapshot):
                candidate_floor = version + 1
                time.sleep(0.05)
                continue

            if _compare_and_put("metadata/timestamp.json", revision, timestamp):
                return {"publisher": PUBLISHER_ID, "version": version, "target": target_path}
            candidate_floor = 0
            time.sleep(0.05)
        raise RuntimeError("publication could not win a consistent etcd transaction")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
