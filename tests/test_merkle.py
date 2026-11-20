"""Exhaustive checks for the domain-separated Merkle proof primitives."""

from hashlib import sha256

import pytest

from coldhandoff import merkle as M


def raw_leaves(count):
    return [sha256(f"leaf-{i}".encode()).digest() for i in range(count)]


def test_empty_and_single_leaf_roots_are_distinct_and_deterministic():
    tags = M.DomainTags()
    empty = M.mth([], tags)
    assert len(empty) == 32
    assert M.MerkleTree([]).root == empty
    assert empty != M.MerkleTree(raw_leaves(1)).root
    assert M.mth(raw_leaves(1)) == raw_leaves(1)[0]
    assert M.mth(raw_leaves(1)) == M.mth(raw_leaves(1))


def test_domain_tags_change_leaf_and_node_hashes():
    payload = M.source_leaf("src-1", "aa" * 32, "1")
    a = M.DomainTags(leaf=b"tag-a", node=b"node-a")
    b = M.DomainTags(leaf=b"tag-b", node=b"node-a")
    assert a.leaf_hash(payload) != b.leaf_hash(payload)
    (leaf,) = [a.leaf_hash(payload)]
    c = M.DomainTags(leaf=b"tag-a", node=b"node-c")
    assert a.node_hash(leaf, leaf) != c.node_hash(leaf, leaf)
    assert a.empty_root != c.empty_root
    with pytest.raises(M.MerkleError):
        M.DomainTags(leaf=b"same", node=b"same")


def test_leaf_binds_identity_bytes_and_import_version():
    base = M.source_leaf("src-1", "aa" * 32, "1")
    assert M.source_leaf("src-2", "aa" * 32, "1")["source_id"] == "src-2"
    tags = M.DomainTags()
    variants = [
        M.source_leaf("src-1", "aa" * 32, "1"),
        M.source_leaf("src-2", "aa" * 32, "1"),
        M.source_leaf("src-1", "bb" * 32, "1"),
        M.source_leaf("src-1", "aa" * 32, "2"),
    ]
    hashes = {tags.leaf_hash(v) for v in variants}
    assert len(hashes) == 4
    assert tags.leaf_hash(M.source_leaf("src-1", "aa" * 32, "1")) == tags.leaf_hash(base)
    with pytest.raises(M.MerkleError):
        M.source_leaf("", "aa" * 32, "1")
    with pytest.raises(M.MerkleError):
        M.source_leaf("src-1", "not-a-digest", "1")


def test_leaf_encoding_is_canonical_regardless_of_key_order():
    tags = M.DomainTags()
    a = {"v": 1, "kind": "source", "source_id": "s", "bytes_sha256": "ab" * 32, "import_version": "1"}
    b = {k: a[k] for k in reversed(list(a))}
    assert tags.leaf_hash(a) == tags.leaf_hash(b)


@pytest.mark.parametrize("size", range(0, 18))
def test_inclusion_paths_verify_for_every_size_and_index(size):
    tags = M.DomainTags()
    leaves = raw_leaves(size)
    tree = M.MerkleTree(leaves, tags)
    assert tree.size == size
    for index in range(size):
        proof = tree.inclusion(index)
        assert M.verify_inclusion(leaves[index], index, size, proof, tree.root, tags)
        assert M.verify_inclusion(leaves[index].hex(), index, size,
                                  [p.hex() for p in proof], tree.root.hex(), tags)
        # wrong leaf, wrong index and tampered path must all fail
        assert not M.verify_inclusion(sha256(b"other").digest(), index, size, proof, tree.root, tags)
        assert not M.verify_inclusion(leaves[index], (index + 1) % size, size,
                                      proof, tree.root, tags) if size > 1 else True
        if proof:
            broken = list(proof)
            broken[0] = sha256(b"tampered").digest()
            assert not M.verify_inclusion(leaves[index], index, size, broken, tree.root, tags)
            assert not M.verify_inclusion(leaves[index], index, size, proof[:-1], tree.root, tags)


@pytest.mark.parametrize("new_size", range(0, 18))
def test_consistency_verifies_for_every_old_prefix(new_size):
    tags = M.DomainTags()
    leaves = raw_leaves(new_size)
    new_tree = M.MerkleTree(leaves, tags)
    for old_size in range(new_size + 1):
        old_root = M.mth(leaves[:old_size], tags)
        proof = new_tree.consistency(old_size)
        assert M.verify_consistency(old_size, new_size, old_root, new_tree.root, proof, tags)
        # empty proof is only legitimate for equal sizes or an empty old tree
        if old_size not in (0, new_size):
            assert proof


def test_consistency_rejects_replaced_prefix():
    tags = M.DomainTags()
    leaves = raw_leaves(9)
    old_root = M.mth(leaves[:4], tags)
    new_root = M.mth(leaves, tags)
    proof = M.MerkleTree(leaves, tags).consistency(4)

    swapped = list(leaves)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert not M.verify_consistency(4, 9, old_root, M.mth(swapped, tags), proof, tags)

    dropped = leaves[1:]
    assert not M.verify_consistency(4, 8, old_root, M.mth(dropped, tags), M.MerkleTree(dropped, tags).consistency(4), tags)

    replaced = [sha256(b"rewritten").digest()] + leaves[1:]
    assert not M.verify_consistency(4, 9, old_root, M.mth(replaced, tags), M.MerkleTree(replaced, tags).consistency(4), tags)


def test_truncated_or_malformed_proofs_are_rejected():
    tags = M.DomainTags()
    leaves = raw_leaves(11)
    old_root = M.mth(leaves[:5], tags)
    new_root = M.mth(leaves, tags)
    proof = M.MerkleTree(leaves, tags).consistency(5)
    assert M.verify_consistency(5, 11, old_root, new_root, proof, tags)
    assert not M.verify_consistency(5, 11, old_root, new_root, proof[:-1], tags)
    assert not M.verify_consistency(5, 11, old_root, new_root, proof + [b"\x00" * 32], tags)
    broken = list(proof)
    broken[-1] = b"\x00" * 32
    assert not M.verify_consistency(5, 11, old_root, new_root, broken, tags)
    assert not M.verify_consistency(5, 11, old_root, new_root, ["not-hex"], tags)
    assert not M.verify_consistency(6, 5, old_root, new_root, proof, tags)
    # equal sizes require equal roots and no proof
    assert M.verify_consistency(11, 11, new_root, new_root, [], tags)
    assert not M.verify_consistency(11, 11, old_root, new_root, [], tags)
    assert not M.verify_consistency(11, 11, new_root, new_root, proof, tags)
    # empty old tree
    assert M.verify_consistency(0, 11, tags.empty_root, new_root, [], tags)
    assert not M.verify_consistency(0, 11, b"\x00" * 32, new_root, [], tags)
    assert not M.verify_consistency(0, 11, tags.empty_root, new_root, proof, tags)


def test_inclusion_rejects_out_of_range_and_empty_tree():
    tags = M.DomainTags()
    leaves = raw_leaves(3)
    root = M.mth(leaves, tags)
    proof = M.MerkleTree(leaves, tags).inclusion(0)
    assert not M.verify_inclusion(leaves[0], 3, 3, proof, root, tags)
    assert not M.verify_inclusion(leaves[0], -1, 3, proof, root, tags)
    assert not M.verify_inclusion(leaves[0], 0, 0, proof, M.DomainTags().empty_root, tags)
    with pytest.raises(M.MerkleError):
        M.MerkleTree([]).inclusion(0)
    with pytest.raises(M.MerkleError):
        M.MerkleTree(leaves, tags).consistency(4)


def test_tree_rejects_bad_leaves():
    with pytest.raises(M.MerkleError):
        M.MerkleTree([b"short"])
    with pytest.raises(M.MerkleError):
        M.MerkleTree.from_payloads([{"kind": "source"}])


def test_reordered_and_foreign_proofs_are_rejected():
    tags = M.DomainTags()
    leaves = raw_leaves(8)
    tree = M.MerkleTree(leaves, tags)
    old_root = M.mth(leaves[:3], tags)

    proof = tree.consistency(3)
    assert M.verify_consistency(3, 8, old_root, tree.root, proof, tags)
    assert not M.verify_consistency(3, 8, old_root, tree.root, list(reversed(proof)), tags)

    # An inclusion path from a different leaf does not verify for this leaf.
    path_for_2 = tree.inclusion(2)
    assert not M.verify_inclusion(leaves[5], 5, 8, path_for_2, tree.root, tags)
    # Nor does a path built for a different tree size.
    smaller = M.MerkleTree(leaves[:4], tags)
    assert not M.verify_inclusion(leaves[0], 0, 8, smaller.inclusion(0), tree.root, tags)
    assert not M.verify_inclusion(leaves[0], 0, 4, smaller.inclusion(0), tree.root, tags)


def test_consistency_proof_from_wrong_tree_size_is_rejected():
    tags = M.DomainTags()
    leaves = raw_leaves(9)
    new_root = M.mth(leaves, tags)
    old_root = M.mth(leaves[:5], tags)
    proof = M.MerkleTree(leaves, tags).consistency(5)
    # Claiming the old size is 4 or 6 must not verify with a size-5 proof.
    assert not M.verify_consistency(4, 9, M.mth(leaves[:4], tags), new_root, proof, tags)
    assert not M.verify_consistency(6, 9, M.mth(leaves[:6], tags), new_root, proof, tags)


def test_corrections_are_new_leaves_and_never_mutate_the_prefix():
    tags = M.DomainTags()
    original = M.source_leaf("src-1", "aa" * 32, "1")
    revoke = M.revocation_leaf("src-1-r1", "src-1", "bad thermometer", "1")
    replace = M.replacement_leaf("src-1-r2", "src-1", "bb" * 32, "1", "re-scan")
    before = M.MerkleTree.from_payloads([original], tags)
    after = M.MerkleTree.from_payloads([original, revoke, replace], tags)
    assert after.leaves[0] == before.leaves[0]
    assert M.verify_consistency(1, 3, before.root, after.root, after.consistency(1), tags)
    with pytest.raises(M.MerkleError):
        M.revocation_leaf("src-1", "src-1", "self", "1")
    with pytest.raises(M.MerkleError):
        M.validate_leaf({**revoke, "kind": "unknown"})
