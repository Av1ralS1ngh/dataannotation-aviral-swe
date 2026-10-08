"""Small RFC 6962 SHA-256 proof verifier shared by admission components."""

import hashlib


def _largest_power_of_two_less_than(value):
    return 1 << ((value - 1).bit_length() - 1)


def _leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion(leaf_data, leaf_index, tree_size, proof, expected_root):
    """Raise ValueError unless leaf_data is included at leaf_index."""
    if tree_size < 1 or leaf_index < 0 or leaf_index >= tree_size:
        raise ValueError("invalid inclusion coordinates")
    try:
        nodes = iter(bytes.fromhex(item) for item in proof)

        def rebuild(index, size):
            if size == 1:
                return _leaf_hash(leaf_data)
            split = _largest_power_of_two_less_than(size)
            if index < split:
                return _node_hash(rebuild(index, split), next(nodes))
            right = rebuild(index - split, size - split)
            return _node_hash(next(nodes), right)

        root = rebuild(leaf_index, tree_size)
    except (StopIteration, TypeError, ValueError) as exc:
        raise ValueError("malformed or incomplete inclusion proof") from exc
    try:
        next(nodes)
    except StopIteration:
        pass
    else:
        raise ValueError("inclusion proof has unused nodes")
    if root.hex() != expected_root:
        raise ValueError("inclusion proof does not match the expected root")


def verify_consistency(old_size, new_size, old_root, new_root, proof):
    """Return whether proof extends the old RFC 6962 tree into the new tree."""
    if old_size == 0:
        return not proof
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size > new_size or not proof:
        return False

    first = old_size - 1
    second = new_size - 1
    while first & 1:
        first >>= 1
        second >>= 1

    try:
        nodes = [bytes.fromhex(item) for item in proof]
        if first == 0:
            old_hash = new_hash = bytes.fromhex(old_root)
            position = 0
        else:
            old_hash = new_hash = nodes[0]
            position = 1

        for node in nodes[position:]:
            if second == 0:
                return False
            if first & 1 or first == second:
                old_hash = _node_hash(node, old_hash)
                new_hash = _node_hash(node, new_hash)
                while first and not first & 1:
                    first >>= 1
                    second >>= 1
            else:
                new_hash = _node_hash(new_hash, node)
            first >>= 1
            second >>= 1
    except (IndexError, TypeError, ValueError):
        return False

    return second == 0 and old_hash.hex() == old_root and new_hash.hex() == new_root
