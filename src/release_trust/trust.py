"""TUF verification with a shared journal and per-replica durable mirror."""

import base64
import copy
import fcntl
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime

import requests
from tuf.api.metadata import Metadata, Root

from . import rfc6962
from .config import get_settings

SETTINGS = get_settings()
REPOSITORY = SETTINGS.metadata_url
COORDINATION = SETTINGS.coordination_url
PINNED_ROOT = SETTINGS.operator_dir / "client/1.root.json"
INCIDENT = SETTINGS.operator_dir / "incident.json"
MIRROR = SETTINGS.state_dir / "trusted-state.json"
MIRROR_LOCK = SETTINGS.state_dir / "trusted-state.lock"
JOURNAL_KEY = "artifact-trust/authority"


class TrustError(Exception):
    pass


class CoordinationUnavailable(Exception):
    pass


def _encoded(value):
    if isinstance(value, str):
        value = value.encode()
    return base64.b64encode(value).decode()


def _empty_state():
    return {
        "commit_seq": 0,
        "ancestors": {},
        "roots": {},
        "roles": {},
        "origins": {},
    }


def _get(path, *, missing_ok=False):
    response = requests.get(f"{REPOSITORY}/{path}", timeout=10)
    if missing_ok and response.status_code == 404:
        return None
    response.raise_for_status()
    return response.content


def _root_identity(root):
    return hashlib.sha256(root.signed_bytes).hexdigest()


def _metadata_identity(metadata):
    return hashlib.sha256(metadata.signed_bytes).hexdigest()


def _key_material_identity(key):
    return hashlib.sha256(
        json.dumps(key.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _state_digest(state):
    return hashlib.sha256(
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _is_descendant(newer, older):
    newer_seq = newer.get("commit_seq", 0)
    older_seq = older.get("commit_seq", 0)
    if newer_seq == older_seq:
        return _state_digest(newer) == _state_digest(older)
    if newer_seq < older_seq:
        return False
    return (
        newer.get("ancestors", {}).get(str(older_seq))
        == _state_digest(older)
    )


def _journal_read():
    try:
        response = requests.post(
            f"{COORDINATION}/v3/kv/range",
            json={"key": _encoded(JOURNAL_KEY)},
            headers={"x-coordination-token": SETTINGS.coordination_token},
            timeout=3,
        )
        if response.status_code != 200:
            raise CoordinationUnavailable(
                f"coordination journal returned HTTP {response.status_code}"
            )
        values = response.json().get("kvs", [])
        if not values:
            return _empty_state(), 0
        item = values[0]
        state = json.loads(base64.b64decode(item["value"]))
        return state, int(item["mod_revision"])
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        raise CoordinationUnavailable(str(exc)) from exc


def _journal_compare_and_put(revision, state):
    key = _encoded(JOURNAL_KEY)
    if revision == 0:
        compare = [
            {
                "key": key,
                "target": "CREATE",
                "result": "EQUAL",
                "create_revision": "0",
            }
        ]
    else:
        compare = [
            {
                "key": key,
                "target": "MOD",
                "result": "EQUAL",
                "mod_revision": str(revision),
            }
        ]
    try:
        response = requests.post(
            f"{COORDINATION}/v3/kv/txn",
            json={
                "compare": compare,
                "success": [
                    {
                        "request_put": {
                            "key": key,
                            "value": _encoded(
                                json.dumps(
                                    state, sort_keys=True, separators=(",", ":")
                                )
                            ),
                        }
                    }
                ],
                "failure": [],
            },
            headers={"x-coordination-token": SETTINGS.coordination_token},
            timeout=90,
        )
        if response.status_code != 200:
            raise CoordinationUnavailable(
                f"coordination journal returned HTTP {response.status_code}"
            )
        return bool(response.json().get("succeeded"))
    except (requests.RequestException, ValueError) as exc:
        raise CoordinationUnavailable(str(exc)) from exc


def _load_mirror():
    try:
        return json.loads(MIRROR.read_text())
    except FileNotFoundError as exc:
        raise TrustError(
            "coordination journal is unavailable and this replica has no durable trust mirror"
        ) from exc
    except (OSError, ValueError) as exc:
        raise TrustError(f"durable trust mirror is unusable: {exc}") from exc


def _load_mirror_if_present():
    try:
        return json.loads(MIRROR.read_text())
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise TrustError(f"durable trust mirror is unusable: {exc}") from exc


def _write_mirror(state):
    MIRROR.parent.mkdir(parents=True, exist_ok=True)
    MIRROR_LOCK.touch(exist_ok=True)
    with MIRROR_LOCK.open("r+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            current = json.loads(MIRROR.read_text())
        except (FileNotFoundError, ValueError):
            current = _empty_state()
        if current.get("commit_seq", 0) > state.get("commit_seq", 0):
            return
        temporary = MIRROR.with_suffix(f".{os.getpid()}.{uuid.uuid4().hex}.tmp")
        temporary.write_text(json.dumps(state, sort_keys=True))
        os.replace(temporary, MIRROR)


def _read_authority():
    try:
        for _attempt in range(30):
            state, revision = _journal_read()
            mirror = _load_mirror_if_present()
            if mirror is not None:
                journal_seq = state.get("commit_seq", 0)
                mirror_seq = mirror.get("commit_seq", 0)
                if mirror_seq > journal_seq:
                    if not _is_descendant(mirror, state):
                        raise TrustError(
                            "coordination journal rollback does not match the "
                            "replica's committed history"
                        )
                    if _journal_compare_and_put(revision, mirror):
                        _write_mirror(mirror)
                        return mirror, revision, True
                    continue
                if (
                    journal_seq > mirror_seq
                    and not _is_descendant(state, mirror)
                ):
                    raise TrustError(
                        "coordination journal does not descend from the "
                        "replica's committed history"
                    )
                if (
                    mirror_seq == journal_seq
                    and _state_digest(mirror) != _state_digest(state)
                ):
                    raise TrustError(
                        "coordination journal conflicts with the replica's "
                        "committed history"
                    )
            _write_mirror(state)
            return state, revision, True
        raise TrustError("coordination journal rollback recovery did not converge")
    except CoordinationUnavailable:
        return _load_mirror(), None, False


def _mutate_journal(mutator):
    """Apply one linearizable journal mutation and refresh this replica's mirror."""
    for _attempt in range(30):
        state, revision = _journal_read()
        parent_digest = _state_digest(state)
        candidate = copy.deepcopy(state)
        changed = mutator(candidate)
        if not changed:
            _write_mirror(state)
            return state
        candidate.setdefault("ancestors", {})[
            str(state.get("commit_seq", 0))
        ] = parent_digest
        candidate["commit_seq"] = state.get("commit_seq", 0) + 1
        if _journal_compare_and_put(revision, candidate):
            _write_mirror(candidate)
            return candidate
    raise TrustError("coordination journal did not converge after concurrent updates")


def _root_record(metadata, envelope):
    return {
        "signed_hash": _root_identity(metadata),
        "envelope": base64.b64encode(envelope).decode(),
    }


def _recorded_root(record):
    raw = base64.b64decode(record["envelope"])
    root = Metadata[Root].from_bytes(raw)
    if _root_identity(root) != record["signed_hash"]:
        raise TrustError("accepted root recovery material is internally inconsistent")
    return root


def _commit_root_step(version, record, journal_available):
    if not journal_available:
        raise TrustError(
            f"root {version} requires trust advancement while coordination is unavailable"
        )

    def mutate(state):
        roots = state.setdefault("roots", {})
        existing = roots.get(str(version))
        if existing is not None:
            if existing["signed_hash"] != record["signed_hash"]:
                raise TrustError(
                    f"root {version} conflicts with its accepted signed policy"
                )
            return False
        earlier = sorted(int(item) for item in roots)
        expected = (earlier[-1] + 1) if earlier else 1
        if version != expected:
            raise TrustError(
                f"root {version} cannot advance journal root {expected - 1}"
            )
        roots[str(version)] = record
        return True

    return _mutate_journal(mutate)


def _validate_root_transition(previous, candidate, compromised, compromised_material):
    version = candidate.signed.version
    try:
        previous.signed.verify_delegate(
            "root", candidate.signed_bytes, candidate.signatures
        )
        candidate.signed.verify_delegate(
            "root", candidate.signed_bytes, candidate.signatures
        )
    except Exception as exc:
        raise TrustError(f"root {version} transition failed: {exc}") from exc
    if candidate.signed.is_expired():
        raise TrustError(f"root {version} is expired")
    if (
        candidate.signed.roles["root"].threshold
        < previous.signed.roles["root"].threshold
    ):
        raise TrustError(f"root {version} lowers the accepted root-role threshold")
    root_role = candidate.signed.roles["root"]
    material_identities = set()
    for keyid in root_role.keyids:
        key = candidate.signed.keys.get(keyid)
        if key is None:
            raise TrustError(f"root {version} references an unknown root key")
        material_identity = _key_material_identity(key)
        material_identities.add(material_identity)
        if keyid == compromised or material_identity == compromised_material:
            raise TrustError(
                f"root {version} restores the compromised signing material"
            )
    if len(material_identities) < root_role.threshold:
        raise TrustError(
            f"root {version} has fewer independent key materials than its threshold"
        )


def _verified_root(initial_state, journal_available):
    state = initial_state
    trusted = Metadata[Root].from_file(str(PINNED_ROOT))
    if trusted.signed.is_expired():
        raise TrustError("pinned root metadata is expired")
    compromised = json.loads(INCIDENT.read_text())["compromised_keyid"]
    compromised_key = trusted.signed.keys.get(compromised)
    if compromised_key is None:
        raise TrustError("the incident's compromised key is absent from the pinned root")
    compromised_material = _key_material_identity(compromised_key)

    pinned_record = _root_record(trusted, PINNED_ROOT.read_bytes())
    recorded_pinned = state.get("roots", {}).get("1")
    if recorded_pinned is None:
        state = _commit_root_step(1, pinned_record, journal_available)
        journal_available = True
    elif recorded_pinned["signed_hash"] != pinned_record["signed_hash"]:
        raise TrustError("pinned root conflicts with the accepted journal policy")

    observed_pinned = _get("metadata/1.root.json", missing_ok=True)
    if observed_pinned is not None:
        observed = Metadata[Root].from_bytes(observed_pinned)
        if observed.signed.version != 1:
            raise TrustError("repository pinned-root version is invalid")
        try:
            observed.signed.verify_delegate(
                "root", observed.signed_bytes, observed.signatures
            )
        except Exception as exc:
            raise TrustError(f"repository pinned-root signature failed: {exc}") from exc
        if _root_identity(observed) != pinned_record["signed_hash"]:
            raise TrustError("repository pinned root conflicts with the accepted policy")

    next_version = 2
    while True:
        accepted = state.get("roots", {}).get(str(next_version))
        observed_raw = _get(f"metadata/{next_version}.root.json", missing_ok=True)
        if accepted is not None:
            accepted_root = _recorded_root(accepted)
            if observed_raw is not None:
                observed = Metadata[Root].from_bytes(observed_raw)
                if observed.signed.version != next_version:
                    raise TrustError("root versions are not sequential")
                if _root_identity(observed) != accepted["signed_hash"]:
                    raise TrustError(
                        f"root {next_version} conflicts with its accepted signed policy"
                    )
            _validate_root_transition(
                trusted, accepted_root, compromised, compromised_material
            )
            trusted = accepted_root
            next_version += 1
            continue

        if observed_raw is None:
            break
        candidate = Metadata[Root].from_bytes(observed_raw)
        if candidate.signed.version != next_version:
            raise TrustError("root versions are not sequential")
        _validate_root_transition(
            trusted, candidate, compromised, compromised_material
        )
        state = _commit_root_step(
            next_version,
            _root_record(candidate, observed_raw),
            journal_available,
        )
        journal_available = True
        trusted = candidate
        next_version += 1
    return trusted, state, journal_available


def _verify(role, metadata, root):
    try:
        root.signed.verify_delegate(role, metadata.signed_bytes, metadata.signatures)
    except Exception as exc:
        raise TrustError(f"{role} metadata signature failed: {exc}") from exc
    if metadata.signed.is_expired():
        raise TrustError(f"{role} metadata is expired")


def _check_role(state, role, metadata):
    accepted = state.get("roles", {}).get(role)
    if accepted is None:
        return
    observed = metadata.signed.version
    if observed < accepted["version"]:
        raise TrustError(
            f"{role} rollback: version {observed} is older than "
            f"trusted version {accepted['version']}"
        )
    if (
        observed == accepted["version"]
        and _metadata_identity(metadata) != accepted["signed_hash"]
    ):
        raise TrustError(
            f"{role} {observed} conflicts with its accepted signed body"
        )


def current_release(channel="stable"):
    state, _revision, journal_available = _read_authority()
    root, state, journal_available = _verified_root(state, journal_available)

    timestamp = Metadata.from_bytes(_get("metadata/timestamp.json"))
    _verify("timestamp", timestamp, root)
    _check_role(state, "timestamp", timestamp)

    snapshot_link = timestamp.signed.snapshot_meta
    snapshot_bytes = _get(f"metadata/{snapshot_link.version}.snapshot.json")
    try:
        snapshot_link.verify_length_and_hashes(snapshot_bytes)
    except Exception as exc:
        raise TrustError(f"snapshot metadata link failed: {exc}") from exc
    snapshot = Metadata.from_bytes(snapshot_bytes)
    if snapshot.signed.version != snapshot_link.version:
        raise TrustError("snapshot version does not match timestamp")
    _verify("snapshot", snapshot, root)
    _check_role(state, "snapshot", snapshot)

    targets_link = snapshot.signed.meta["targets.json"]
    targets_bytes = _get(f"metadata/{targets_link.version}.targets.json")
    try:
        targets_link.verify_length_and_hashes(targets_bytes)
    except Exception as exc:
        raise TrustError(f"targets metadata link failed: {exc}") from exc
    targets = Metadata.from_bytes(targets_bytes)
    if targets.signed.version != targets_link.version:
        raise TrustError("targets version does not match snapshot")
    _verify("targets", targets, root)
    _check_role(state, "targets", targets)

    channels = targets.signed.unrecognized_fields.get("channels", {})
    target_path = channels.get(channel)
    if not target_path or target_path not in targets.signed.targets:
        raise TrustError(f"trusted channel {channel!r} is absent")
    target_bytes = _get(f"targets/{target_path}")
    try:
        targets.signed.targets[target_path].verify_length_and_hashes(target_bytes)
    except Exception as exc:
        raise TrustError(f"release target verification failed: {exc}") from exc

    proposal = {
        "root_version": root.signed.version,
        "root_signed_hash": _root_identity(root),
        "roles": {
            "timestamp": {
                "version": timestamp.signed.version,
                "signed_hash": _metadata_identity(timestamp),
            },
            "snapshot": {
                "version": snapshot.signed.version,
                "signed_hash": _metadata_identity(snapshot),
            },
            "targets": {
                "version": targets.signed.version,
                "signed_hash": _metadata_identity(targets),
            },
        },
        "journal_available": journal_available,
    }
    return json.loads(target_bytes), proposal


def _apply_roles(state, proposal):
    changed = False
    roots = state.get("roots", {})
    accepted_root_version = max((int(item) for item in roots), default=0)
    if proposal["root_version"] < accepted_root_version:
        raise TrustError(
            f"root rollback: version {proposal['root_version']} is older than "
            f"trusted version {accepted_root_version}"
        )
    if proposal["root_version"] == accepted_root_version:
        accepted = roots.get(str(accepted_root_version))
        if accepted and accepted["signed_hash"] != proposal["root_signed_hash"]:
            raise TrustError("current root conflicts with the accepted signed policy")

    roles = state.setdefault("roles", {})
    for name, candidate in proposal["roles"].items():
        accepted = roles.get(name)
        if accepted is not None:
            if candidate["version"] < accepted["version"]:
                raise TrustError(
                    f"{name} rollback: version {candidate['version']} is older than "
                    f"trusted version {accepted['version']}"
                )
            if (
                candidate["version"] == accepted["version"]
                and candidate["signed_hash"] != accepted["signed_hash"]
            ):
                raise TrustError(
                    f"{name} {candidate['version']} conflicts with its accepted signed body"
                )
        if accepted is None or candidate["version"] > accepted["version"]:
            roles[name] = candidate
            changed = True
    return changed


def _apply_checkpoint(state, checkpoint):
    body = checkpoint["body"]
    entry = checkpoint["entry"]
    origin = body["log_origin"]
    origins = state.setdefault("origins", {})
    accepted = origins.get(origin)
    if accepted is None:
        if body["tree_size"] != 1 or checkpoint.get("consistency_proof"):
            raise TrustError("first checkpoint does not start a log history")
        if entry.get("release_epoch", 0) < 1:
            raise TrustError("first checkpoint has an invalid release epoch")
    else:
        if entry["release_epoch"] < accepted["release_epoch"]:
            raise TrustError(
                "release-policy epoch moved backward with log history"
            )
        integrated = datetime.fromisoformat(
            entry["integrated_time"].replace("Z", "+00:00")
        ).astimezone(UTC)
        previous = datetime.fromisoformat(
            accepted["integrated_time"].replace("Z", "+00:00")
        ).astimezone(UTC)
        if integrated < previous:
            raise TrustError("log integration time moved backward")
    if accepted is not None and body["tree_size"] < accepted["tree_size"]:
        raise TrustError("checkpoint tree size moved backward")
    if accepted is not None and body["tree_size"] == accepted["tree_size"]:
        if body["root_hash"] != accepted["root_hash"]:
            raise TrustError("checkpoint equivocation at the accepted tree size")
        return False
    if accepted is not None:
        if not rfc6962.verify_consistency(
            accepted["tree_size"],
            body["tree_size"],
            accepted["root_hash"],
            body["root_hash"],
            checkpoint.get("consistency_proof") or [],
        ):
            raise TrustError(
                "checkpoint does not extend the latest accepted frontier"
            )
    origins[origin] = {
        "tree_size": body["tree_size"],
        "root_hash": body["root_hash"],
        "release_epoch": entry["release_epoch"],
        "integrated_time": entry["integrated_time"],
    }
    return True


def commit_authorization(proposal, checkpoint):
    """Atomically bind TUF role bodies and the transparency frontier."""

    def mutate(state):
        roles_changed = _apply_roles(state, proposal)
        frontier_changed = _apply_checkpoint(state, checkpoint)
        return roles_changed or frontier_changed

    if not proposal["journal_available"]:
        state = _load_mirror()
        candidate = copy.deepcopy(state)
        if mutate(candidate):
            raise TrustError(
                "authorization requires trust advancement while coordination is unavailable"
            )
        return
    try:
        _mutate_journal(mutate)
    except CoordinationUnavailable as exc:
        state = _load_mirror()
        candidate = copy.deepcopy(state)
        if mutate(candidate):
            raise TrustError(
                "authorization requires trust advancement while coordination is unavailable"
            ) from exc
