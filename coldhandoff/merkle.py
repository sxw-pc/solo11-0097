"""Domain-separated Merkle tree for append-only source checkpoints.

The tree follows the RFC 6962 shape (the shape used by Certificate
Transparency) with two explicit domain tags taken from the anchor contract:

* leaf  = SHA256(leaf_tag  || 0x00 || canonical_json(payload))
* node  = SHA256(node_tag  || 0x00 || left_hash || right_hash)
* empty = SHA256(node_tag  || 0x00)          (no left/right bytes)

Leaves are addressed by their append position.  ``MerkleTree`` builds the
root, inclusion paths and consistency proofs.  ``verify_inclusion`` and
``verify_consistency`` are standalone: they only need the roots, the tree
sizes and the proof, exactly what an independent auditor receives.

No file bytes are hashed here.  A leaf binds the caller supplied source
identity, the SHA-256 of the original bytes and the import version.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterable, Sequence

DEFAULT_LEAF_TAG = b"cold-source-v1"
DEFAULT_NODE_TAG = b"cold-node-v1"

_LEAF_KINDS = {"source", "revoke", "replace"}


class MerkleError(ValueError):
    """Raised for malformed leaves, sizes, indices or proofs."""


def canonical_json(value: Any) -> bytes:
    """Stable encoding used both for leaves and for witness receipts."""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _sha256(data: bytes) -> bytes:
    return sha256(data).digest()


def _as_bytes(value: bytes | str, field: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError as exc:  # pragma: no cover - defensive
            raise MerkleError(f"{field} is not hex") from exc
    raise MerkleError(f"{field} must be bytes or hex")


def _check_digest(value: str, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise MerkleError(f"{field} must be a 64 character sha256 hex digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise MerkleError(f"{field} must be hex") from exc
    return value.lower()


@dataclass(frozen=True)
class DomainTags:
    """The two contract supplied domain separation tags."""

    leaf: bytes = DEFAULT_LEAF_TAG
    node: bytes = DEFAULT_NODE_TAG

    def __post_init__(self) -> None:
        if not self.leaf or not self.node:
            raise MerkleError("domain tags must be non-empty")
        if self.leaf == self.node:
            raise MerkleError("leaf and node domain tags must differ")
        for value in (self.leaf, self.node):
            if b"\x00" in value:
                raise MerkleError("domain tags must not contain NUL")

    @classmethod
    def from_contract(cls, contract: dict) -> "DomainTags":
        tags = contract.get("domain_tags") or {}
        leaf = tags.get("leaf", DEFAULT_LEAF_TAG.decode())
        node = tags.get("node", DEFAULT_NODE_TAG.decode())
        if not isinstance(leaf, str) or not isinstance(node, str):
            raise MerkleError("domain tags must be strings")
        return cls(leaf=leaf.encode("utf-8"), node=node.encode("utf-8"))

    def leaf_hash(self, payload: dict) -> bytes:
        return _sha256(self.leaf + b"\x00" + canonical_json(payload))

    def node_hash(self, left: bytes, right: bytes) -> bytes:
        if len(left) != 32 or len(right) != 32:
            raise MerkleError("node children must be 32 byte hashes")
        return _sha256(self.node + b"\x00" + left + right)

    @property
    def empty_root(self) -> bytes:
        return _sha256(self.node + b"\x00")


# ---------------------------------------------------------------------------
# Leaf payloads
# ---------------------------------------------------------------------------


def source_leaf(
    source_id: str, bytes_sha256: str, import_version: str
) -> dict:
    """A leaf for one original source byte stream.

    ``source_id`` is the durable, non-reusable anchor identity.  It is not a
    filename and it is distinct from the byte digest so two imports with the
    same bytes still occupy two unambiguous leaves.
    """

    if not isinstance(source_id, str) or not source_id:
        raise MerkleError("source_id is required")
    return {
        "v": 1,
        "kind": "source",
        "source_id": source_id,
        "bytes_sha256": _check_digest(bytes_sha256, "bytes_sha256"),
        "import_version": str(import_version),
    }


def revocation_leaf(
    source_id: str, target_source_id: str, reason: str, import_version: str
) -> dict:
    """An append-only correction.  The target leaf is never modified."""

    if not source_id or not target_source_id:
        raise MerkleError("source_id and target_source_id are required")
    if source_id == target_source_id:
        raise MerkleError("a revocation needs its own new source_id")
    return {
        "v": 1,
        "kind": "revoke",
        "source_id": source_id,
        "target_source_id": target_source_id,
        "reason": str(reason),
        "import_version": str(import_version),
    }


def replacement_leaf(
    source_id: str,
    target_source_id: str,
    bytes_sha256: str,
    import_version: str,
    reason: str = "",
) -> dict:
    """An append-only replacement leaf pointing at a superseded source."""

    if not source_id or not target_source_id:
        raise MerkleError("source_id and target_source_id are required")
    if source_id == target_source_id:
        raise MerkleError("a replacement needs its own new source_id")
    return {
        "v": 1,
        "kind": "replace",
        "source_id": source_id,
        "target_source_id": target_source_id,
        "bytes_sha256": _check_digest(bytes_sha256, "bytes_sha256"),
        "import_version": str(import_version),
        "reason": str(reason),
    }


def validate_leaf(payload: dict) -> dict:
    kind = payload.get("kind") if isinstance(payload, dict) else None
    if kind not in _LEAF_KINDS:
        raise MerkleError("unknown leaf kind")
    if payload.get("v") != 1:
        raise MerkleError("unsupported leaf version")
    if not isinstance(payload.get("source_id"), str) or not payload["source_id"]:
        raise MerkleError("source_id is required")
    if kind in {"source", "replace"}:
        _check_digest(payload.get("bytes_sha256"), "bytes_sha256")
    if kind in {"revoke", "replace"}:
        target = payload.get("target_source_id")
        if not isinstance(target, str) or not target:
            raise MerkleError("target_source_id is required")
        if target == payload["source_id"]:
            raise MerkleError("correction must reference a previous leaf")
    if not isinstance(payload.get("import_version"), str):
        raise MerkleError("import_version is required")
    return payload


# ---------------------------------------------------------------------------
# Tree construction
# ---------------------------------------------------------------------------


def _largest_power_of_two_less_than(n: int) -> int:
    """Largest power of two strictly less than ``n`` (n must be > 1)."""
    if n <= 1:
        raise MerkleError("no split for a tree smaller than two leaves")
    return 1 << ((n - 1).bit_length() - 1)


class MerkleTree:
    """An immutable list of leaf hashes in append order."""

    __slots__ = ("_leaves", "tags")

    def __init__(
        self, leaves: Iterable[bytes | str], tags: DomainTags | None = None
    ):
        self.tags = tags or DomainTags()
        self._leaves: tuple[bytes, ...] = tuple(
            _as_bytes(leaf, "leaf") for leaf in leaves
        )
        for leaf in self._leaves:
            if len(leaf) != 32:
                raise MerkleError("leaves must be 32 byte hashes")

    @classmethod
    def from_payloads(
        cls, payloads: Sequence[dict], tags: DomainTags | None = None
    ) -> "MerkleTree":
        tags = tags or DomainTags()
        for payload in payloads:
            validate_leaf(payload)
        return cls([tags.leaf_hash(p) for p in payloads], tags=tags)

    @property
    def leaves(self) -> tuple[bytes, ...]:
        return self._leaves

    @property
    def size(self) -> int:
        return len(self._leaves)

    @property
    def root(self) -> bytes:
        return mth(self._leaves, self.tags)

    def inclusion(self, index: int) -> list[bytes]:
        return inclusion_proof(self._leaves, index, self.tags)

    def consistency(self, old_size: int) -> list[bytes]:
        return consistency_proof(self._leaves, old_size, self.tags)


def _require_size(n: int) -> None:
    if not isinstance(n, int) or n < 0:
        raise MerkleError("tree size must be a non-negative integer")


def mth(leaves: Sequence[bytes], tags: DomainTags | None = None) -> bytes:
    """Merkle tree hash of ``leaves`` in order."""

    tags = tags or DomainTags()
    _require_size(len(leaves))
    if not leaves:
        return tags.empty_root
    if len(leaves) == 1:
        return leaves[0]
    k = _largest_power_of_two_less_than(len(leaves))
    return tags.node_hash(mth(leaves[:k], tags), mth(leaves[k:], tags))


def inclusion_proof(
    leaves: Sequence[bytes], index: int, tags: DomainTags | None = None
) -> list[bytes]:
    """Bottom-up sibling path for ``leaves[index]``."""

    tags = tags or DomainTags()
    if not leaves:
        raise MerkleError("an empty tree has no inclusion path")
    if not isinstance(index, int) or not 0 <= index < len(leaves):
        raise MerkleError("leaf index out of range")

    def walk(tree: Sequence[bytes], offset: int) -> list[bytes]:
        if len(tree) == 1:
            return []
        k = _largest_power_of_two_less_than(len(tree))
        if index - offset < k:
            return walk(tree[:k], offset) + [mth(tree[k:], tags)]
        return walk(tree[k:], offset + k) + [mth(tree[:k], tags)]

    return walk(leaves, 0)


def consistency_proof(
    leaves: Sequence[bytes], old_size: int, tags: DomainTags | None = None
) -> list[bytes]:
    """Proof that the old prefix is still a prefix of this tree."""

    tags = tags or DomainTags()
    _require_size(old_size)
    if old_size > len(leaves):
        raise MerkleError("old size is larger than the current tree")
    if old_size in (0, len(leaves)):
        return []

    def subproof(size: int, tree: Sequence[bytes], complete: bool) -> list[bytes]:
        if size == len(tree):
            # A complete subtree is omitted when the caller already knows the
            # old root, but must be sent when it is an interior node of the
            # path so the verifier can rebuild the old root.
            return [] if complete else [mth(tree, tags)]
        k = _largest_power_of_two_less_than(len(tree))
        if size <= k:
            return subproof(size, tree[:k], complete) + [mth(tree[k:], tags)]
        return subproof(size - k, tree[k:], False) + [mth(tree[:k], tags)]

    return subproof(old_size, leaves, True)


# ---------------------------------------------------------------------------
# Standalone verification (roots + sizes + proof only)
# ---------------------------------------------------------------------------


def verify_inclusion(
    leaf_hash: bytes | str,
    index: int,
    tree_size: int,
    proof: Sequence[bytes | str],
    root: bytes | str,
    tags: DomainTags | None = None,
) -> bool:
    """Verify an inclusion path without any tree or source bytes."""

    tags = tags or DomainTags()
    try:
        leaf = _as_bytes(leaf_hash, "leaf_hash")
        expected = _as_bytes(root, "root")
        path = [_as_bytes(item, "proof") for item in proof]
    except MerkleError:
        return False
    _require_size(tree_size)
    if tree_size == 0 or not isinstance(index, int) or not 0 <= index < tree_size:
        return False
    if len(leaf) != 32 or len(expected) != 32:
        return False
    if any(len(item) != 32 for item in path):
        return False
    fn = index
    sn = tree_size - 1
    running = leaf
    for sibling in path:
        if fn & 1 or fn == sn:
            running = tags.node_hash(sibling, running)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            running = tags.node_hash(running, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and running == expected


def verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes | str,
    new_root: bytes | str,
    proof: Sequence[bytes | str],
    tags: DomainTags | None = None,
) -> bool:
    """Verify that the ``old_size`` prefix is unchanged in ``new_size``.

    The verifier holds only the two roots, the two tree sizes and the proof.
    A deleted or rewritten first source cannot satisfy this check against the
    previously delivered root.
    """

    tags = tags or DomainTags()
    try:
        old = _as_bytes(old_root, "old_root")
        new = _as_bytes(new_root, "new_root")
        path = [_as_bytes(item, "proof") for item in proof]
    except MerkleError:
        return False
    _require_size(old_size)
    _require_size(new_size)
    if len(old) != 32 or len(new) != 32:
        return False
    if any(len(item) != 32 for item in path):
        return False
    if old_size > new_size:
        return False
    if old_size == new_size:
        return not path and old == new
    if old_size == 0:
        return not path and old == tags.empty_root
    if not path:
        return False

    fn = old_size - 1
    sn = new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    if fn == 0:
        # The old tree is a complete subtree; the verifier already has its
        # root so the proof starts with a sibling.
        first = old
        fr = sr = old
    else:
        first = path[0]
        fr = sr = first
        path = path[1:]

    for child in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = tags.node_hash(child, fr)
            sr = tags.node_hash(child, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = tags.node_hash(sr, child)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old and sr == new


def root_from_leaves(leaves: Sequence[bytes | str], tags: DomainTags | None = None) -> bytes:
    tags = tags or DomainTags()
    return mth([_as_bytes(leaf, "leaf") for leaf in leaves], tags)
