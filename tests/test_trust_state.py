import copy

from release_trust import trust


def test_descendant_requires_recorded_parent_digest():
    older = trust._empty_state()
    newer = copy.deepcopy(older)
    newer["ancestors"]["0"] = trust._state_digest(older)
    newer["commit_seq"] = 1

    assert trust._is_descendant(newer, older)
    newer["ancestors"]["0"] = "not-the-parent"
    assert not trust._is_descendant(newer, older)


def test_checkpoint_genesis_is_idempotent():
    state = trust._empty_state()
    checkpoint = {
        "body": {
            "log_origin": "release-log",
            "tree_size": 1,
            "root_hash": "ab" * 32,
        },
        "entry": {
            "release_epoch": 1,
            "integrated_time": "2026-01-01T00:00:00Z",
        },
        "consistency_proof": [],
    }

    assert trust._apply_checkpoint(state, checkpoint) is True
    assert trust._apply_checkpoint(state, checkpoint) is False


def test_checkpoint_rejects_non_genesis_first_observation():
    state = trust._empty_state()
    checkpoint = {
        "body": {
            "log_origin": "release-log",
            "tree_size": 2,
            "root_hash": "ab" * 32,
        },
        "entry": {
            "release_epoch": 1,
            "integrated_time": "2026-01-01T00:00:00Z",
        },
        "consistency_proof": [],
    }

    try:
        trust._apply_checkpoint(state, checkpoint)
    except trust.TrustError as exc:
        assert "first checkpoint" in str(exc)
    else:
        raise AssertionError("non-genesis checkpoint was accepted")


def test_same_tree_replay_cannot_rewind_release_epoch():
    state = trust._empty_state()
    state["origins"]["release-log"] = {
        "tree_size": 1,
        "root_hash": "ab" * 32,
        "release_epoch": 2,
        "integrated_time": "2026-01-02T00:00:00Z",
    }
    replay = {
        "body": {
            "log_origin": "release-log",
            "tree_size": 1,
            "root_hash": "ab" * 32,
        },
        "entry": {
            "release_epoch": 1,
            "integrated_time": "2026-01-01T00:00:00Z",
        },
        "consistency_proof": [],
    }

    try:
        trust._apply_checkpoint(state, replay)
    except trust.TrustError as exc:
        assert "epoch moved backward" in str(exc)
    else:
        raise AssertionError("same-tree rollback was accepted")
