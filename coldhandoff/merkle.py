"""Domain-separated, append-only Merkle tree over anchored source leaves.

The tree shape and the proof algorithms follow RFC 6962 (Certificate
Transparency): the root commits to the whole ordered leaf list, an
inclusion proof shows a leaf sits at a position in a tree of a given
size, and a consistency proof shows the size-``m`` tree is a prefix of
the size-``n`` tree.  Leaves and interior nodes are hashed with the
contract's domain tags instead of bare SHA-256, so an anchor commitment
can never be confused with the digest of anything else.

The consistency proof is what makes the log append-only: deleting an old
leaf and recomputing the whole tree still yields a self-consistent root,
but that root can never be consistency-proven against the root that was
delivered earlier, because the verifier only needs the two roots, the
two tree sizes and the proof itself.
"""
import json
from hashlib import sha256

LEAF_TAG = 'cold-source-v1'
NODE_TAG = 'cold-node-v1'
LEAF_VERSION = '1'

EMPTY_ROOT = sha256((NODE_TAG + ':empty').encode('utf-8')).hexdigest()


def canonical(obj):
    """Deterministic encoding for leaf payloads and sign requests."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def leaf_payload(kind, source_id, source_sha256, version=LEAF_VERSION, supersedes=None, note=None):
    """The committed leaf content: non-reusable source id, original bytes
    SHA-256 and import version, plus optional correction metadata."""
    obj = {'kind': kind, 'sha256': source_sha256, 'source_id': source_id, 'version': version}
    if supersedes is not None:
        obj['supersedes'] = supersedes
    if note is not None:
        obj['note'] = note
    return obj


def leaf_hash(kind, source_id, source_sha256, version=LEAF_VERSION, supersedes=None, note=None):
    payload = canonical(leaf_payload(kind, source_id, source_sha256, version, supersedes, note))
    return sha256(LEAF_TAG.encode('utf-8') + b'\x00' + payload).hexdigest()


def node_hash(left_hex, right_hex):
    return sha256(NODE_TAG.encode('utf-8') + b'\x01' + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()


def _split(n):
    """Largest power of two strictly smaller than ``n`` (n >= 2)."""
    k = 1 << (n.bit_length() - 1)
    return k >> 1 if k == n else k


def root(leaf_hashes):
    hashes = list(leaf_hashes)
    if not hashes:
        return EMPTY_ROOT
    return _root(hashes)


def _root(hashes):
    if len(hashes) == 1:
        return hashes[0]
    k = _split(len(hashes))
    return node_hash(_root(hashes[:k]), _root(hashes[k:]))


def inclusion_path(leaf_hashes, index):
    """Sibling hashes proving ``leaf_hashes[index]`` is in the tree."""
    hashes = list(leaf_hashes)
    if not 0 <= index < len(hashes):
        raise ValueError('index_out_of_range')
    return _path(hashes, index)


def _path(hashes, index):
    if len(hashes) == 1:
        return []
    k = _split(len(hashes))
    if index < k:
        return _path(hashes[:k], index) + [_root(hashes[k:])]
    return _path(hashes[k:], index - k) + [_root(hashes[:k])]


def verify_inclusion(leaf, index, size, path, expected_root):
    """Check that ``leaf`` sits at ``index`` in a tree of ``size`` leaves
    whose root is ``expected_root``.  Needs no access to the leaf store."""
    if size <= 0 or not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for sibling in path:
        if sn == 0:
            return False  # path longer than the tree allows
        if fn % 2 == 1 or fn == sn:
            r = node_hash(sibling, r)
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            r = node_hash(r, sibling)
        fn //= 2
        sn //= 2
    return sn == 0 and r == expected_root


def consistency_proof(leaf_hashes, m):
    """Proof that the first ``m`` leaves are a prefix of the full tree."""
    hashes = list(leaf_hashes)
    n = len(hashes)
    if not 0 <= m <= n:
        raise ValueError('invalid_checkpoint_size')
    if m == 0 or m == n:
        return []
    return _subproof(hashes, m, True)


def _subproof(hashes, m, complete):
    n = len(hashes)
    if m == n:
        return [] if complete else [_root(hashes)]
    k = _split(n)
    if m <= k:
        return _subproof(hashes[:k], m, complete) + [_root(hashes[k:])]
    return _subproof(hashes[k:], m - k, False) + [_root(hashes[:k])]


def verify_consistency(old_root, old_size, new_root, new_size, proof):
    """Verify the size-``old_size`` tree is a prefix of the size-``new_size``
    tree.  The verifier holds only the two roots, the two sizes and the
    proof, so a recomputed tree with a dropped or reordered prefix fails."""
    proof = list(proof)
    if old_size < 0 or new_size < 0:
        return False
    if old_size == 0:
        return proof == []
    if old_size > new_size or new_size == 0:
        return False
    if old_size == new_size:
        return proof == [] and old_root == new_root
    if old_size & (old_size - 1) == 0:  # exact power of two
        proof.insert(0, old_root)
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if not proof:
        return False
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root
