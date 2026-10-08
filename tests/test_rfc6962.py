import pytest

from release_trust import rfc6962


def test_single_leaf_inclusion_requires_no_proof():
    leaf = b"release"
    root = rfc6962._leaf_hash(leaf).hex()
    rfc6962.verify_inclusion(leaf, 0, 1, [], root)


def test_two_leaf_inclusion_rejects_wrong_sibling():
    left = b"release-a"
    right = b"release-b"
    root = rfc6962._node_hash(
        rfc6962._leaf_hash(left),
        rfc6962._leaf_hash(right),
    ).hex()
    rfc6962.verify_inclusion(
        left,
        0,
        2,
        [rfc6962._leaf_hash(right).hex()],
        root,
    )
    with pytest.raises(ValueError, match="expected root"):
        rfc6962.verify_inclusion(left, 0, 2, ["00" * 32], root)


def test_equal_tree_consistency_is_idempotent():
    root = "ab" * 32
    assert rfc6962.verify_consistency(3, 3, root, root, [])
    assert not rfc6962.verify_consistency(3, 3, root, "cd" * 32, [])
