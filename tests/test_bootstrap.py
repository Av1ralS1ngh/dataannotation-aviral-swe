from tuf.api.metadata import Metadata, Root

from release_trust import bootstrap


def test_healthy_bootstrap_builds_dual_signed_root(tmp_path, monkeypatch):
    operator = tmp_path / "operator"
    monkeypatch.setattr(bootstrap, "OPERATOR", operator)
    monkeypatch.setattr(bootstrap, "ROOT_KEYS", tmp_path / "root-keys")
    monkeypatch.setattr(
        bootstrap, "PUBLISHER_KEYS", tmp_path / "publisher-keys"
    )
    monkeypatch.setattr(
        bootstrap, "BOOTSTRAP_SECRETS", tmp_path / "bootstrap-secrets"
    )
    monkeypatch.setattr(bootstrap, "MARKER", operator / ".initialized")
    monkeypatch.setenv("SEED_SCENARIO", "healthy")

    stored = {}
    monkeypatch.setattr(bootstrap, "wait_for", lambda _url: None)
    monkeypatch.setattr(bootstrap, "clear_bucket", lambda: None)
    monkeypatch.setattr(
        bootstrap,
        "object_put",
        lambda path, data: stored.__setitem__(path, data),
    )
    monkeypatch.setattr(
        bootstrap,
        "push_child",
        lambda _repository, architecture, _revision, _tag: {
            "digest": "sha256:" + architecture[0] * 64
        },
    )
    monkeypatch.setattr(
        bootstrap,
        "push_index",
        lambda *_args: ("sha256:" + "d" * 64, 1, {}),
    )
    monkeypatch.setattr(
        bootstrap,
        "make_checkpoint",
        lambda *_args, **_kwargs: ({}, []),
    )
    monkeypatch.setattr(bootstrap, "make_attestation", lambda *_args: {})
    monkeypatch.setattr(bootstrap, "write_attestation", lambda *_args: None)
    monkeypatch.setattr(
        bootstrap, "publish_release_metadata", lambda *_args: None
    )

    bootstrap.main()

    root1 = Metadata[Root].from_file(str(operator / "client/1.root.json"))
    root2 = Metadata[Root].from_bytes(stored["metadata/2.root.json"])
    root1.signed.verify_delegate(
        "root", root2.signed_bytes, root2.signatures
    )
    root2.signed.verify_delegate(
        "root", root2.signed_bytes, root2.signatures
    )
    assert bootstrap.MARKER.exists()
