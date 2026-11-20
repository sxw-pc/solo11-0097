"""Append-only, cross-source tamper-evidence for cold-chain handoff imports.

The module builds on :mod:`coldhandoff.merkle` and keeps every durable fact
in SQLite:

``anchor_leaf``
    One row per committed leaf, keyed by ``(case_id, leaf_index)``.  A leaf
    binds a non-reusable ``source_id``, the SHA-256 of the original source
    bytes and the import version.  Rows are never updated or deleted.
``anchor_source``
    The durable source registry.  A ``source_id`` can never be reused, even
    after it has been revoked or replaced.
``anchor_checkpoint``
    An immutable ``(tree_size, root, snapshot_sha256)`` tuple with a
    monotonically increasing case-local number.  ``UNIQUE(case_id, tree_size)``
    means a size can never gain a second, competing history.
``anchor_witness_request`` / ``anchor_witness_receipt``
    The signing protocol.  A retry must repeat the exact root, tree size and
    snapshot digest of its request; a different root for the same checkpoint
    number is recorded as a fork instead of overwriting anything.
``anchor_leaf`` + checkpoint + pending witness requests are committed in one
SQLite transaction, so a crash cannot expose a checkpoint whose leaves or
signing requests are missing.

All timestamps are UTC ISO-8601 strings.  Only synthetic local sources and
simulated witnesses are used; nothing here talks to a network.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from .merkle import (
    DomainTags,
    MerkleError,
    canonical_json,
    consistency_proof,
    inclusion_proof,
    mth,
    source_leaf,
    revocation_leaf,
    replacement_leaf,
    validate_leaf,
    verify_consistency,
    verify_inclusion,
)
from .store import connect

IMPORT_VERSION = "1"
SCHEMA_VERSION = 1

_DDL = """
CREATE TABLE IF NOT EXISTS anchor_case(
  id TEXT PRIMARY KEY, contract_sha256 TEXT NOT NULL,
  contract_json TEXT NOT NULL, source_snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS anchor_key(
  case_id TEXT NOT NULL, key_id TEXT NOT NULL, secret_hex TEXT NOT NULL,
  PRIMARY KEY(case_id, key_id)
);
CREATE TABLE IF NOT EXISTS anchor_leaf(
  case_id TEXT NOT NULL, leaf_index INTEGER NOT NULL,
  source_id TEXT NOT NULL, kind TEXT NOT NULL,
  payload_json TEXT NOT NULL, leaf_hash TEXT NOT NULL,
  import_version TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY(case_id, leaf_index),
  UNIQUE(case_id, source_id)
);
CREATE TABLE IF NOT EXISTS anchor_source(
  case_id TEXT NOT NULL, source_id TEXT NOT NULL,
  bytes_sha256 TEXT, import_version TEXT NOT NULL,
  first_leaf_index INTEGER NOT NULL, status TEXT NOT NULL,
  PRIMARY KEY(case_id, source_id)
);
CREATE TABLE IF NOT EXISTS anchor_checkpoint(
  case_id TEXT NOT NULL, number INTEGER NOT NULL,
  tree_size INTEGER NOT NULL, root TEXT NOT NULL,
  snapshot_sha256 TEXT NOT NULL, state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(case_id, number),
  UNIQUE(case_id, tree_size)
);
CREATE TABLE IF NOT EXISTS anchor_witness_request(
  case_id TEXT NOT NULL, checkpoint_number INTEGER NOT NULL,
  witness_id TEXT NOT NULL, witness_role TEXT NOT NULL,
  root TEXT NOT NULL, tree_size INTEGER NOT NULL,
  snapshot_sha256 TEXT NOT NULL, state TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY(case_id, checkpoint_number, witness_id)
);
CREATE TABLE IF NOT EXISTS anchor_witness_receipt(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL, checkpoint_number INTEGER NOT NULL,
  witness_id TEXT NOT NULL, witness_role TEXT NOT NULL,
  root TEXT NOT NULL, tree_size INTEGER NOT NULL,
  snapshot_sha256 TEXT NOT NULL, payload_json TEXT NOT NULL,
  signature TEXT NOT NULL, signed_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  UNIQUE(case_id, checkpoint_number, witness_id)
);
CREATE TABLE IF NOT EXISTS anchor_delivery(
  case_id TEXT NOT NULL, checkpoint_number INTEGER NOT NULL,
  policy TEXT NOT NULL, state TEXT NOT NULL,
  payload_json TEXT NOT NULL, signature TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(case_id, checkpoint_number, policy)
);
CREATE TABLE IF NOT EXISTS anchor_event(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL, kind TEXT NOT NULL,
  checkpoint_number INTEGER, detail_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS anchor_event_kind ON anchor_event(case_id, kind);
"""

POLICIES = ("local_signed", "dual_witness")


class AnchorError(ValueError):
    """Base class for audit anchor failures."""


class InjectedFault(RuntimeError):
    """Raised by the deterministic crash-injection hooks.

    ``stage`` names the point at which the simulated process stopped and
    ``detail`` describes what *did* reach durable storage.
    """

    def __init__(self, stage: str, detail: dict | None = None):
        self.stage = stage
        self.detail = detail or {}
        super().__init__(f"injected_fault:{stage}")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> str:
    return canonical_json(value).decode("utf-8")


@contextmanager
def _immediate(db):
    """A single ``BEGIN IMMEDIATE`` write transaction.

    ``BEGIN IMMEDIATE`` takes the SQLite write lock up front, so two
    concurrent importers serialize and cannot both claim the same leaf index.
    """

    db.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        db.rollback()
        raise
    else:
        db.commit()


def _ensure_schema(db) -> None:
    db.executescript(_DDL)


def _open(db_path) -> Any:
    db = connect(db_path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=15000")
    _ensure_schema(db)
    return db


def _key_id(case_id: str, kind: str, name: str) -> str:
    return f"{kind}:{case_id}:{name}"


def _secret(db, case_id: str, key_id: str, *, create: bool = False) -> str | None:
    row = db.execute(
        "SELECT secret_hex FROM anchor_key WHERE case_id=? AND key_id=?",
        (case_id, key_id),
    ).fetchone()
    if row:
        return row["secret_hex"]
    if not create:
        return None
    value = secrets.token_hex(32)
    db.execute(
        "INSERT INTO anchor_key VALUES (?,?,?)", (case_id, key_id, value)
    )
    return value


def _sign(secret_hex: str, payload: bytes) -> str:
    return hmac.new(
        bytes.fromhex(secret_hex), payload, hashlib.sha256
    ).hexdigest()


def _load_contract(contract_path) -> tuple[dict, bytes, str]:
    raw = Path(contract_path).read_bytes()
    try:
        contract = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AnchorError("contract_not_json") from exc
    if not isinstance(contract, dict) or not contract.get("case_id"):
        raise AnchorError("contract_missing_case_id")
    return contract, raw, _sha256_hex(raw)


def _registered_case(db, contract: dict, contract_sha: str) -> dict:
    row = db.execute(
        "SELECT * FROM anchor_case WHERE id=?", (contract["case_id"],)
    ).fetchone()
    if not row:
        raise AnchorError("case_not_registered")
    if row["contract_sha256"] != contract_sha:
        raise AnchorError("contract_mismatch")
    return dict(row)


def _tags(contract: dict) -> DomainTags:
    tags = contract.get("domain_tags") or {}
    leaf = tags.get("leaf", "cold-source-v1")
    node = tags.get("node", "cold-node-v1")
    if not isinstance(leaf, str) or not isinstance(node, str):
        raise AnchorError("domain_tags_must_be_strings")
    return DomainTags(leaf=leaf.encode("utf-8"), node=node.encode("utf-8"))


def _witnesses(contract: dict) -> list[dict]:
    witnesses = contract.get("witnesses")
    if not isinstance(witnesses, list) or not witnesses:
        raise AnchorError("contract_requires_witnesses")
    seen = set()
    out = []
    for item in witnesses:
        if not isinstance(item, dict) or not item.get("id"):
            raise AnchorError("witness_requires_id")
        wid = str(item["id"])
        if wid in seen:
            raise AnchorError("duplicate_witness_id")
        seen.add(wid)
        out.append({"id": wid, "role": str(item.get("role", "external"))})
    return out


def _log(db, case_id: str, kind: str, checkpoint: int | None, detail: dict) -> None:
    db.execute(
        "INSERT INTO anchor_event(case_id,kind,checkpoint_number,detail_json,created_at)"
        " VALUES (?,?,?,?,?)",
        (case_id, kind, checkpoint, _canonical(detail), _now()),
    )


def _leaf_rows(db, case_id: str, limit: int | None = None) -> list[dict]:
    sql = (
        "SELECT leaf_index,source_id,kind,payload_json,leaf_hash,import_version"
        " FROM anchor_leaf WHERE case_id=? ORDER BY leaf_index"
    )
    rows = [dict(r) for r in db.execute(sql, (case_id,))]
    if limit is not None:
        rows = rows[:limit]
    return rows


def _leaf_hashes(rows: Sequence[dict]) -> list[bytes]:
    return [bytes.fromhex(r["leaf_hash"]) for r in rows]


def _snapshot_digest(rows: Sequence[dict]) -> str:
    return _sha256_hex(
        canonical_json(
            [
                {"index": r["leaf_index"], "source_id": r["source_id"], "hash": r["leaf_hash"]}
                for r in rows
            ]
        )
    )


def _checkpoint_row(db, case_id: str, number: int) -> dict:
    row = db.execute(
        "SELECT * FROM anchor_checkpoint WHERE case_id=? AND number=?",
        (case_id, number),
    ).fetchone()
    if not row:
        raise AnchorError("checkpoint_not_found")
    return dict(row)


def _checkpoint_by_size(db, case_id: str, size: int) -> dict | None:
    row = db.execute(
        "SELECT * FROM anchor_checkpoint WHERE case_id=? AND tree_size=?",
        (case_id, size),
    ).fetchone()
    return dict(row) if row else None


def _receipt_payload(
    contract: dict,
    checkpoint: dict,
    witness: dict,
    tags: DomainTags,
) -> dict:
    return {
        "type": "coldhandoff.source-anchor.witness-receipt",
        "case_id": contract["case_id"],
        "witness_id": witness["id"],
        "witness_role": witness["role"],
        "checkpoint_number": checkpoint["number"],
        "tree_size": checkpoint["tree_size"],
        "root": checkpoint["root"],
        "snapshot_sha256": checkpoint["snapshot_sha256"],
        "leaf_tag": tags.leaf.decode("utf-8"),
        "node_tag": tags.node.decode("utf-8"),
    }


# ---------------------------------------------------------------------------
# Case registration and key material
# ---------------------------------------------------------------------------


def register(db_path, contract_path) -> str:
    """Freeze the ingested source identities and the audit contract.

    This is the original entry point and keeps its original return value and
    ``anchor_case`` contents.  It additionally provisions a local signing key
    and one simulated signing key per contract witness so later checkpoints
    have credential material available.
    """

    contract, raw, contract_sha = _load_contract(contract_path)
    db = _open(db_path)
    rows = [
        {"id": r["id"], "hash": r["hash"]}
        for r in db.execute("SELECT id,hash FROM source_file ORDER BY id")
    ]
    if len(rows) < 2:
        raise AnchorError("needs_two_sources")
    _tags(contract)
    _witnesses(contract)
    try:
        with _immediate(db):
            db.execute(
                "INSERT INTO anchor_case VALUES (?,?,?,?)",
                (
                    contract["case_id"],
                    contract_sha,
                    raw.decode("utf-8"),
                    json.dumps(rows, sort_keys=True),
                ),
            )
            _secret(db, contract["case_id"], _key_id(contract["case_id"], "local", "audit"), create=True)
            for witness in _witnesses(contract):
                _secret(
                    db,
                    contract["case_id"],
                    _key_id(contract["case_id"], "witness", witness["id"]),
                    create=True,
                )
            _log(
                db,
                contract["case_id"],
                "case_registered",
                None,
                {"contract_sha256": contract_sha, "source_snapshot": rows},
            )
    finally:
        db.close()
    return contract["case_id"]


def export_keyring(db_path, contract_path) -> dict:
    """Return ``{key_id: secret_hex}`` for an independent verifier.

    Only used by the synthetic tests and local audit tooling; witness secrets
    are never placed in a delivery bundle.
    """

    contract, _raw, _sha = _load_contract(contract_path)
    db = _open(db_path)
    try:
        _registered_case(db, contract, _sha)
        return {
            r["key_id"]: r["secret_hex"]
            for r in db.execute(
                "SELECT key_id,secret_hex FROM anchor_key WHERE case_id=?",
                (contract["case_id"],),
            )
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Appending leaves
# ---------------------------------------------------------------------------


def _prepare_leaf(
    contract: dict,
    source_id: str,
    bytes_sha256: str | None,
    import_version: str,
    kind: str,
    target_source_id: str | None,
    reason: str,
) -> dict:
    if kind == "source":
        if not bytes_sha256:
            raise AnchorError("bytes_sha256_required")
        return source_leaf(source_id, bytes_sha256, import_version)
    if kind == "revoke":
        if not target_source_id:
            raise AnchorError("target_source_id_required")
        return revocation_leaf(source_id, target_source_id, reason, import_version)
    if kind == "replace":
        if not target_source_id or not bytes_sha256:
            raise AnchorError("target_and_bytes_required")
        return replacement_leaf(
            source_id, target_source_id, bytes_sha256, import_version, reason
        )
    raise AnchorError("unknown_leaf_kind")


def append_sources(
    db_path,
    contract_path,
    entries: Iterable[dict],
    *,
    idempotent: bool = False,
) -> dict:
    """Append one or more leaves atomically.

    Each entry is a dict with ``source_id``, ``bytes_sha256`` and optionally
    ``import_version``, ``kind`` (``source``/``revoke``/``replace``),
    ``target_source_id`` and ``reason``.  The whole batch shares one
    ``BEGIN IMMEDIATE`` transaction, so either all leaves and their durable
    sequence numbers are committed or none are.

    With ``idempotent=True`` an existing leaf whose payload is identical is
    skipped instead of rejected; a reused identity with different content is
    still an error.  This lets concurrent ``append_from_ingest`` runs converge
    on exactly one leaf per source.
    """

    contract, _raw, contract_sha = _load_contract(contract_path)
    entries = list(entries)
    if not entries:
        return {"appended": [], "tree_size": None}
    db = _open(db_path)
    try:
        _registered_case(db, contract, contract_sha)
        with _immediate(db):
            appended = _append_locked(
                db, contract, contract_sha, entries, idempotent=idempotent
            )
    finally:
        db.close()
    return {
        "appended": appended,
        "tree_size": appended[-1]["leaf_index"] + 1 if appended else None,
    }


def _append_locked(
    db, contract: dict, contract_sha: str, entries: list[dict], *, idempotent: bool
) -> list[dict]:
    """Append leaves inside the caller's ``BEGIN IMMEDIATE`` transaction."""

    tags = _tags(contract)
    prepared = []
    for entry in entries:
        source_id = str(entry.get("source_id") or "")
        if not source_id:
            raise AnchorError("source_id_required")
        try:
            payload = _prepare_leaf(
                contract,
                source_id,
                entry.get("bytes_sha256"),
                str(entry.get("import_version", IMPORT_VERSION)),
                str(entry.get("kind", "source")),
                entry.get("target_source_id"),
                str(entry.get("reason", "")),
            )
            validate_leaf(payload)
        except MerkleError as exc:
            raise AnchorError(str(exc)) from exc
        prepared.append((source_id, payload, tags.leaf_hash(payload)))

    row = db.execute(
        "SELECT COALESCE(MAX(leaf_index),-1) AS m FROM anchor_leaf WHERE case_id=?",
        (contract["case_id"],),
    ).fetchone()
    index = int(row["m"]) + 1
    appended = []
    for source_id, payload, leaf_hash in prepared:
        existing_leaf = db.execute(
            "SELECT payload_json,leaf_hash FROM anchor_leaf"
            " WHERE case_id=? AND source_id=?",
            (contract["case_id"], source_id),
        ).fetchone()
        if existing_leaf:
            if (
                idempotent
                and existing_leaf["payload_json"] == _canonical(payload)
                and existing_leaf["leaf_hash"] == leaf_hash.hex()
            ):
                continue
            raise AnchorError(f"source_id_reused:{source_id}")
        if payload["kind"] in {"revoke", "replace"}:
            target = db.execute(
                "SELECT status FROM anchor_source WHERE case_id=? AND source_id=?",
                (contract["case_id"], payload["target_source_id"]),
            ).fetchone()
            if not target:
                raise AnchorError("target_source_not_found")
        created = _now()
        db.execute(
            "INSERT INTO anchor_leaf VALUES (?,?,?,?,?,?,?,?)",
            (
                contract["case_id"],
                index,
                source_id,
                payload["kind"],
                _canonical(payload),
                leaf_hash.hex(),
                payload["import_version"],
                created,
            ),
        )
        db.execute(
            "INSERT INTO anchor_source VALUES (?,?,?,?,?,?)",
            (
                contract["case_id"],
                source_id,
                payload.get("bytes_sha256"),
                payload["import_version"],
                index,
                "active" if payload["kind"] == "source" else "correction",
            ),
        )
        if payload["kind"] in {"revoke", "replace"}:
            db.execute(
                "UPDATE anchor_source SET status=? WHERE case_id=? AND source_id=?",
                (
                    "revoked" if payload["kind"] == "revoke" else "replaced",
                    contract["case_id"],
                    payload["target_source_id"],
                ),
            )
        _log(
            db,
            contract["case_id"],
            "leaf_appended",
            None,
            {"leaf_index": index, "source_id": source_id, "kind": payload["kind"]},
        )
        appended.append(
            {"leaf_index": index, "source_id": source_id, "leaf_hash": leaf_hash.hex()}
        )
        index += 1
    return appended


def append_source(
    db_path,
    contract_path,
    source_id: str,
    bytes_sha256: str,
    import_version: str = IMPORT_VERSION,
) -> dict:
    return append_sources(
        db_path,
        contract_path,
        [
            {
                "source_id": source_id,
                "bytes_sha256": bytes_sha256,
                "import_version": import_version,
            }
        ],
    )


def append_correction(
    db_path,
    contract_path,
    source_id: str,
    target_source_id: str,
    *,
    kind: str = "revoke",
    bytes_sha256: str | None = None,
    reason: str = "",
    import_version: str = IMPORT_VERSION,
) -> dict:
    """Append a revocation or replacement leaf; old leaves stay untouched."""

    return append_sources(
        db_path,
        contract_path,
        [
            {
                "source_id": source_id,
                "target_source_id": target_source_id,
                "kind": kind,
                "bytes_sha256": bytes_sha256,
                "reason": reason,
                "import_version": import_version,
            }
        ],
    )


def durable_source_id(case_id: str, source_id: int | str) -> str:
    """The ledger identity for a row of ``source_file``.

    It is derived from the frozen case and the durable ``source_file`` row,
    never from a filename, so two identical byte streams still get two
    distinct, non-reusable identities.
    """

    try:
        numeric = int(source_id)
    except (TypeError, ValueError) as exc:
        raise AnchorError("source_file_id_must_be_integer") from exc
    return f"{case_id}:source:{numeric:06d}"


def append_from_ingest(
    db_path,
    contract_path,
    *,
    import_version: str = IMPORT_VERSION,
) -> dict:
    """Turn every ingested ``source_file`` into an append-only leaf.

    The order is the frozen ``source_file.id`` order, so re-running this is
    idempotent (already present identities are skipped) and never reorders an
    already published prefix.
    """

    contract, _raw, contract_sha = _load_contract(contract_path)
    db = _open(db_path)
    appended = []
    try:
        _registered_case(db, contract, contract_sha)
        # Read the ingested identities under the same lock that appends, so
        # two concurrent callers cannot interleave a stale "known" set.
        with _immediate(db):
            rows = [
                dict(r)
                for r in db.execute("SELECT id,hash FROM source_file ORDER BY id")
            ]
            known = {
                r["source_id"]
                for r in db.execute(
                    "SELECT source_id FROM anchor_leaf WHERE case_id=?",
                    (contract["case_id"],),
                )
            }
            entries = []
            for row in rows:
                sid = durable_source_id(contract["case_id"], row["id"])
                if sid in known:
                    continue
                entries.append(
                    {
                        "source_id": sid,
                        "bytes_sha256": row["hash"],
                        "import_version": import_version,
                    }
                )
            if entries:
                appended = _append_locked(
                    db, contract, contract_sha, entries, idempotent=True
                )
    finally:
        db.close()
    return {
        "appended": appended,
        "tree_size": appended[-1]["leaf_index"] + 1 if appended else None,
    }


# ---------------------------------------------------------------------------
# Checkpoints, signing requests and deliveries
# ---------------------------------------------------------------------------


def _current_root(db, case_id: str, tags: DomainTags, size: int | None = None):
    rows = _leaf_rows(db, case_id, size)
    root = mth(_leaf_hashes(rows), tags)
    return rows, root, len(rows)


def _request_dispatch(db, case_id: str, number: int) -> list[str]:
    """Move pending signing requests to ``sent``; return the witness ids."""

    pending = [
        dict(r)
        for r in db.execute(
            "SELECT witness_id FROM anchor_witness_request"
            " WHERE case_id=? AND checkpoint_number=? AND state='pending'"
            " ORDER BY witness_id",
            (case_id, number),
        )
    ]
    for row in pending:
        db.execute(
            "UPDATE anchor_witness_request SET state='sent',updated_at=?"
            " WHERE case_id=? AND checkpoint_number=? AND witness_id=?",
            (_now(), case_id, number, row["witness_id"]),
        )
        _log(
            db,
            case_id,
            "witness_request_sent",
            number,
            {"witness_id": row["witness_id"]},
        )
    return [row["witness_id"] for row in pending]


def _local_delivery_payload(
    contract: dict,
    checkpoint: dict,
    rows: Sequence[dict],
    tags: DomainTags,
) -> dict:
    inclusions = {}
    leaves = _leaf_hashes(rows)
    for position, row in enumerate(rows):
        path = inclusion_proof(leaves, position, tags)
        inclusions[row["source_id"]] = {
            "leaf_index": row["leaf_index"],
            "leaf_hash": row["leaf_hash"],
            "kind": row["kind"],
            "path": [p.hex() for p in path],
            "tree_size": checkpoint["tree_size"],
            "root": checkpoint["root"],
        }
    return {
        "type": "coldhandoff.source-anchor.local-signed",
        "case_id": contract["case_id"],
        "checkpoint_number": checkpoint["number"],
        "tree_size": checkpoint["tree_size"],
        "root": checkpoint["root"],
        "snapshot_sha256": checkpoint["snapshot_sha256"],
        "leaf_tag": tags.leaf.decode("utf-8"),
        "node_tag": tags.node.decode("utf-8"),
        "inclusions": inclusions,
        "issued_at": _now(),
    }


def publish_checkpoint(
    db_path,
    contract_path,
    *,
    policy: str = "local_signed",
    fault: str | None = None,
    dispatch: bool = True,
) -> dict:
    """Create (or reuse) the checkpoint for the current leaf set.

    The leaf set, root, checkpoint and every pending witness request commit in
    one transaction.  ``fault`` deterministically stops the simulated process:

    ``after_root_compute``
        The root was computed but nothing was persisted.
    ``after_checkpoint_persist``
        Checkpoint and requests are durable, but no request was dispatched.
    ``after_first_witness_receipt``
        One witness signed, then the process stopped.
    """

    if policy not in POLICIES:
        raise AnchorError("unknown_policy")
    contract, _raw, contract_sha = _load_contract(contract_path)
    tags = _tags(contract)
    witnesses = _witnesses(contract)
    db = _open(db_path)
    try:
        _registered_case(db, contract, contract_sha)
        with _immediate(db):
            # Read and compute under the write lock so the root is derived
            # from exactly the leaf prefix this checkpoint commits.
            rows, root, size = _current_root(db, contract["case_id"], tags)
            snapshot = _snapshot_digest(rows)
            if fault == "after_root_compute":
                raise InjectedFault(
                    "after_root_compute",
                    {"tree_size": size, "root": root.hex(), "persisted": False},
                )
            existing = _checkpoint_by_size(db, contract["case_id"], size)
            if existing and existing["root"] != root.hex():
                # The committed leaves no longer reproduce the published root.
                # Nothing is overwritten; the conflict is durable and raised.
                _log(
                    db,
                    contract["case_id"],
                    "checkpoint_root_conflict",
                    existing["number"],
                    {"expected": existing["root"], "computed": root.hex()},
                )
                db.commit()
                raise AnchorError("checkpoint_root_conflict")
            if existing:
                number = existing["number"]
            else:
                row = db.execute(
                    "SELECT COALESCE(MAX(number),0)+1 AS n FROM anchor_checkpoint WHERE case_id=?",
                    (contract["case_id"],),
                ).fetchone()
                number = int(row["n"])
                db.execute(
                    "INSERT INTO anchor_checkpoint VALUES (?,?,?,?,?,?,?)",
                    (
                        contract["case_id"],
                        number,
                        size,
                        root.hex(),
                        snapshot,
                        "persisted",
                        _now(),
                    ),
                )
            for witness in witnesses:
                db.execute(
                    "INSERT OR IGNORE INTO anchor_witness_request VALUES"
                    " (?,?,?,?,?,?,?,?,?,?)",
                    (
                        contract["case_id"],
                        number,
                        witness["id"],
                        witness["role"],
                        root.hex(),
                        size,
                        snapshot,
                        "pending",
                        _now(),
                        _now(),
                    ),
                )
            checkpoint = _checkpoint_row(db, contract["case_id"], number)
            existing_delivery = db.execute(
                "SELECT 1 FROM anchor_delivery WHERE case_id=? AND checkpoint_number=? AND policy='local_signed'",
                (contract["case_id"], number),
            ).fetchone()
            if not existing_delivery:
                # The local package is always issued immediately at publish
                # time; the dual-witness package can only follow later.
                payload = _local_delivery_payload(contract, checkpoint, rows, tags)
                secret = _secret(
                    db,
                    contract["case_id"],
                    _key_id(contract["case_id"], "local", "audit"),
                )
                signature = _sign(secret, canonical_json(payload))
                db.execute(
                    "INSERT INTO anchor_delivery VALUES (?,?,?,?,?,?,?)",
                    (
                        contract["case_id"],
                        number,
                        "local_signed",
                        "signed",
                        _canonical(payload),
                        signature,
                        _now(),
                    ),
                )
                _log(
                    db,
                    contract["case_id"],
                    "local_delivery_signed",
                    number,
                    {"payload_sha256": _sha256_hex(canonical_json(payload))},
                )
        if fault == "after_checkpoint_persist":
            raise InjectedFault(
                "after_checkpoint_persist",
                {
                    "checkpoint_number": number,
                    "tree_size": size,
                    "root": root.hex(),
                    "requests_state": "pending",
                },
            )
        if dispatch:
            with _immediate(db):
                _request_dispatch(db, contract["case_id"], number)
        if fault == "after_first_witness_receipt":
            first = witnesses[0]
            simulate_witness_ack(
                db_path,
                contract_path,
                number,
                first["id"],
                _db=None,
            )
            raise InjectedFault(
                "after_first_witness_receipt",
                {
                    "checkpoint_number": number,
                    "tree_size": size,
                    "root": root.hex(),
                    "witness_acked": first["id"],
                    "witness_pending": [w["id"] for w in witnesses[1:]],
                },
            )
        return _checkpoint_summary(db, contract["case_id"], number, tags)
    finally:
        db.close()


def _checkpoint_summary(db, case_id: str, number: int, tags: DomainTags) -> dict:
    checkpoint = _checkpoint_row(db, case_id, number)
    rows = _leaf_rows(db, case_id, checkpoint["tree_size"])
    requests = [
        dict(r)
        for r in db.execute(
            "SELECT witness_id,witness_role,state,root,tree_size FROM anchor_witness_request"
            " WHERE case_id=? AND checkpoint_number=? ORDER BY witness_id",
            (case_id, number),
        )
    ]
    receipts = [
        dict(r)
        for r in db.execute(
            "SELECT witness_id,witness_role,root,tree_size,snapshot_sha256,signature,signed_at"
            " FROM anchor_witness_receipt WHERE case_id=? AND checkpoint_number=?"
            " ORDER BY witness_id",
            (case_id, number),
        )
    ]
    return {
        "case_id": case_id,
        "checkpoint_number": number,
        "tree_size": checkpoint["tree_size"],
        "root": checkpoint["root"],
        "snapshot_sha256": checkpoint["snapshot_sha256"],
        "state": checkpoint["state"],
        "leaf_tag": tags.leaf.decode("utf-8"),
        "node_tag": tags.node.decode("utf-8"),
        "leaves": [
            {
                "leaf_index": r["leaf_index"],
                "source_id": r["source_id"],
                "kind": r["kind"],
                "leaf_hash": r["leaf_hash"],
                "import_version": r["import_version"],
            }
            for r in rows
        ],
        "requests": requests,
        "receipts": receipts,
    }


# ---------------------------------------------------------------------------
# Witness protocol
# ---------------------------------------------------------------------------


def _snapshot_for(db, case_id: str, size: int) -> str:
    return _snapshot_digest(_leaf_rows(db, case_id, size))


def _record_fork(
    db,
    case_id: str,
    number: int,
    witness: dict,
    observed_root: str,
    observed_size: int,
    expected: dict,
) -> None:
    db.execute(
        "UPDATE anchor_witness_request SET state='diverged',updated_at=?"
        " WHERE case_id=? AND checkpoint_number=? AND witness_id=?",
        (_now(), case_id, number, witness["id"]),
    )
    _log(
        db,
        case_id,
        "witness_fork",
        number,
        {
            "witness_id": witness["id"],
            "observed_root": observed_root,
            "observed_tree_size": observed_size,
            "expected_root": expected["root"],
            "expected_tree_size": expected["tree_size"],
        },
    )


def _delivery_state_after_ack(db, contract: dict, number: int) -> str:
    checkpoint = _checkpoint_row(db, contract["case_id"], number)
    witnesses = _witnesses(contract)
    receipts = {
        r["witness_id"]: dict(r)
        for r in db.execute(
            "SELECT * FROM anchor_witness_receipt WHERE case_id=? AND checkpoint_number=?",
            (contract["case_id"], number),
        )
    }
    diverged = db.execute(
        "SELECT count(*) AS c FROM anchor_witness_request"
        " WHERE case_id=? AND checkpoint_number=? AND state='diverged'",
        (contract["case_id"], number),
    ).fetchone()["c"]
    if diverged:
        state = "pending_verification"
    elif len(receipts) < len(witnesses) or any(w["id"] not in receipts for w in witnesses):
        state = "awaiting_witness"
    else:
        same = all(
            r["root"] == checkpoint["root"]
            and r["tree_size"] == checkpoint["tree_size"]
            and r["snapshot_sha256"] == checkpoint["snapshot_sha256"]
            for r in receipts.values()
        )
        state = "witnessed" if same else "pending_verification"
    db.execute(
        "UPDATE anchor_checkpoint SET state=? WHERE case_id=? AND number=?",
        (state, contract["case_id"], number),
    )
    return state


def witness_ack(
    db_path,
    contract_path,
    checkpoint_number: int,
    witness_id: str,
    *,
    observed_root: str | None = None,
    observed_size: int | None = None,
    signature: str | None = None,
    signed_at: str | None = None,
    _db=None,
) -> dict:
    """Record one witness signature for a checkpoint number.

    Retries must bind the exact same root, tree size and snapshot digest.  A
    witness that reports a different root is recorded as a fork: the
    checkpoint root is never rewritten, the dual-witness package stays
    ``pending_verification``, and the local package keeps verifying against
    its original root.
    """

    contract, _raw, contract_sha = _load_contract(contract_path)
    tags = _tags(contract)
    witnesses = {w["id"]: w for w in _witnesses(contract)}
    if witness_id not in witnesses:
        raise AnchorError("witness_not_contracted")
    witness = witnesses[witness_id]
    owns_db = _db is None
    db = _db or _open(db_path)
    try:
        _registered_case(db, contract, contract_sha)
        checkpoint = _checkpoint_row(db, contract["case_id"], checkpoint_number)
        request = db.execute(
            "SELECT * FROM anchor_witness_request"
            " WHERE case_id=? AND checkpoint_number=? AND witness_id=?",
            (contract["case_id"], checkpoint_number, witness_id),
        ).fetchone()
        if not request:
            raise AnchorError("witness_request_missing")
        request = dict(request)
        # Every retry is bound to the originally requested identity.
        if request["root"] != checkpoint["root"] or request["tree_size"] != checkpoint["tree_size"]:
            raise AnchorError("witness_request_binding_corrupt")
        snapshot = _snapshot_for(db, contract["case_id"], checkpoint["tree_size"])
        if snapshot != checkpoint["snapshot_sha256"]:
            raise AnchorError("checkpoint_snapshot_mismatch")

        if observed_root is not None or observed_size is not None:
            reported_root = observed_root or checkpoint["root"]
            reported_size = (
                observed_size if observed_size is not None else checkpoint["tree_size"]
            )
            if reported_root != checkpoint["root"] or reported_size != checkpoint["tree_size"]:
                with _immediate(db):
                    _record_fork(
                        db,
                        contract["case_id"],
                        checkpoint_number,
                        witness,
                        reported_root,
                        reported_size,
                        checkpoint,
                    )
                    state = _delivery_state_after_ack(
                        db, contract, checkpoint_number
                    )
                return {
                    "accepted": False,
                    "fork": True,
                    "checkpoint_number": checkpoint_number,
                    "witness_id": witness_id,
                    "state": state,
                    "observed_root": reported_root,
                    "expected_root": checkpoint["root"],
                }

        existing = db.execute(
            "SELECT * FROM anchor_witness_receipt"
            " WHERE case_id=? AND checkpoint_number=? AND witness_id=?",
            (contract["case_id"], checkpoint_number, witness_id),
        ).fetchone()
        if existing:
            existing = dict(existing)
            if (
                existing["root"] != checkpoint["root"]
                or existing["tree_size"] != checkpoint["tree_size"]
            ):
                raise AnchorError("receipt_root_conflict")
            if signature is not None and not hmac.compare_digest(
                signature, existing["signature"]
            ):
                # A retry must repeat the same signature for the same
                # checkpoint number; a different one is a competing claim.
                raise AnchorError("receipt_signature_conflict")
            with _immediate(db):
                _log(
                    db,
                    contract["case_id"],
                    "witness_ack_duplicate",
                    checkpoint_number,
                    {"witness_id": witness_id},
                )
                state = _delivery_state_after_ack(db, contract, checkpoint_number)
            return {
                "accepted": True,
                "duplicate": True,
                "fork": False,
                "checkpoint_number": checkpoint_number,
                "witness_id": witness_id,
                "signature": existing["signature"],
                "state": state,
            }

        payload = _receipt_payload(contract, checkpoint, witness, tags)
        payload_bytes = canonical_json(payload)
        secret = _secret(
            db,
            contract["case_id"],
            _key_id(contract["case_id"], "witness", witness_id),
        )
        if not secret:
            raise AnchorError("witness_key_missing")
        if signature is None:
            signature = _sign(secret, payload_bytes)
        else:
            if not hmac.compare_digest(signature, _sign(secret, payload_bytes)):
                raise AnchorError("witness_signature_invalid")
        receipt_time = signed_at or _now()
        with _immediate(db):
            # Re-check under the write lock: concurrent retries may have won.
            again = db.execute(
                "SELECT * FROM anchor_witness_receipt"
                " WHERE case_id=? AND checkpoint_number=? AND witness_id=?",
                (contract["case_id"], checkpoint_number, witness_id),
            ).fetchone()
            if again:
                if again["root"] != checkpoint["root"]:
                    raise AnchorError("receipt_root_conflict")
            else:
                db.execute(
                    "INSERT INTO anchor_witness_receipt"
                    " (case_id,checkpoint_number,witness_id,witness_role,root,"
                    "  tree_size,snapshot_sha256,payload_json,signature,signed_at,received_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        contract["case_id"],
                        checkpoint_number,
                        witness_id,
                        witness["role"],
                        checkpoint["root"],
                        checkpoint["tree_size"],
                        checkpoint["snapshot_sha256"],
                        payload_bytes.decode("utf-8"),
                        signature,
                        receipt_time,
                        _now(),
                    ),
                )
                db.execute(
                    "UPDATE anchor_witness_request SET state='acked',updated_at=?"
                    " WHERE case_id=? AND checkpoint_number=? AND witness_id=?",
                    (_now(), contract["case_id"], checkpoint_number, witness_id),
                )
                _log(
                    db,
                    contract["case_id"],
                    "witness_receipt_recorded",
                    checkpoint_number,
                    {
                        "witness_id": witness_id,
                        "root": checkpoint["root"],
                        "tree_size": checkpoint["tree_size"],
                    },
                )
            state = _delivery_state_after_ack(db, contract, checkpoint_number)
        return {
            "accepted": True,
            "duplicate": False,
            "fork": False,
            "checkpoint_number": checkpoint_number,
            "witness_id": witness_id,
            "signature": signature,
            "state": state,
        }
    finally:
        if owns_db:
            db.close()


def simulate_witness_ack(
    db_path,
    contract_path,
    checkpoint_number: int,
    witness_id: str,
    *,
    observed_root: str | None = None,
    observed_size: int | None = None,
    signed_at: str | None = None,
    _db=None,
) -> dict:
    """Generate the simulated witness credential and record it."""

    return witness_ack(
        db_path,
        contract_path,
        checkpoint_number,
        witness_id,
        observed_root=observed_root,
        observed_size=observed_size,
        signed_at=signed_at,
        _db=_db,
    )


def verify_receipt(receipt: dict, secret_hex: str) -> bool:
    payload = receipt.get("payload_json")
    signature = receipt.get("signature")
    if not isinstance(payload, str) or not isinstance(signature, str):
        return False
    try:
        return hmac.compare_digest(
            signature, _sign(secret_hex, payload.encode("utf-8"))
        )
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Consistency between checkpoints
# ---------------------------------------------------------------------------


def inclusion_for(
    db_path, contract_path, source_id: str, checkpoint_number: int | None = None
) -> dict:
    """Return the inclusion path for one source in the current (or named) tree.

    The document contains the leaf hash, its index, the tree size, the root
    and the sibling path, so :func:`verify_inclusion` can check it without
    access to the database or the original bytes.
    """

    contract, _raw, contract_sha = _load_contract(contract_path)
    tags = _tags(contract)
    db = _open(db_path)
    try:
        _registered_case(db, contract, contract_sha)
        if checkpoint_number is None:
            row = db.execute(
                "SELECT COALESCE(MAX(leaf_index),-1) AS m FROM anchor_leaf WHERE case_id=?",
                (contract["case_id"],),
            ).fetchone()
            size = int(row["m"]) + 1
            rows = _leaf_rows(db, contract["case_id"], size)
            root = mth(_leaf_hashes(rows), tags)
            number = None
        else:
            checkpoint = _checkpoint_row(db, contract["case_id"], checkpoint_number)
            rows = _leaf_rows(db, contract["case_id"], checkpoint["tree_size"])
            root = bytes.fromhex(checkpoint["root"])
            number = checkpoint_number
        leaves = _leaf_hashes(rows)
        position = next(
            (i for i, r in enumerate(rows) if r["source_id"] == source_id), None
        )
        if position is None:
            raise AnchorError("source_not_in_tree")
        path = inclusion_proof(leaves, position, tags)
        return {
            "case_id": contract["case_id"],
            "checkpoint_number": number,
            "source_id": source_id,
            "leaf_index": position,
            "leaf_hash": rows[position]["leaf_hash"],
            "tree_size": len(rows),
            "root": root.hex(),
            "proof": [p.hex() for p in path],
            "verified": verify_inclusion(
                rows[position]["leaf_hash"], position, len(rows), path, root, tags
            ),
        }
    finally:
        db.close()


def consistency_between(
    db_path, contract_path, old_number: int, new_number: int
) -> dict:

    contract, _raw, contract_sha = _load_contract(contract_path)
    tags = _tags(contract)
    db = _open(db_path)
    try:
        _registered_case(db, contract, contract_sha)
        old = _checkpoint_row(db, contract["case_id"], old_number)
        new = _checkpoint_row(db, contract["case_id"], new_number)
        if old["tree_size"] > new["tree_size"]:
            raise AnchorError("old_checkpoint_after_new")
        rows = _leaf_rows(db, contract["case_id"], new["tree_size"])
        leaves = _leaf_hashes(rows)
        # The current prefix must still reproduce the old checkpoint root.
        old_prefix_root = mth(leaves[: old["tree_size"]], tags).hex()
        if old_prefix_root != old["root"]:
            raise AnchorError("old_prefix_replaced")
        proof = consistency_proof(leaves, old["tree_size"], tags)
        return {
            "case_id": contract["case_id"],
            "old_checkpoint": old_number,
            "new_checkpoint": new_number,
            "old_tree_size": old["tree_size"],
            "new_tree_size": new["tree_size"],
            "old_root": old["root"],
            "new_root": new["root"],
            "proof": [p.hex() for p in proof],
            "verified": verify_consistency(
                old["tree_size"],
                new["tree_size"],
                old["root"],
                new["root"],
                proof,
                tags,
            ),
        }
    finally:
        db.close()


def verify_consistency_document(document: dict, leaf_tag=None, node_tag=None) -> bool:
    tags = DomainTags(
        leaf=(leaf_tag or document.get("leaf_tag", "cold-source-v1")).encode(),
        node=(node_tag or document.get("node_tag", "cold-node-v1")).encode(),
    )
    try:
        return verify_consistency(
            int(document["old_tree_size"]),
            int(document["new_tree_size"]),
            document["old_root"],
            document["new_root"],
            document["proof"],
            tags,
        )
    except (KeyError, TypeError, ValueError, MerkleError):
        return False


# ---------------------------------------------------------------------------
# Deliveries and audit bundles
# ---------------------------------------------------------------------------


def _delivery_row(db, case_id: str, number: int, policy: str) -> dict | None:
    row = db.execute(
        "SELECT * FROM anchor_delivery WHERE case_id=? AND checkpoint_number=? AND policy=?",
        (case_id, number, policy),
    ).fetchone()
    return dict(row) if row else None


def build_delivery(
    db_path, contract_path, checkpoint_number: int, policy: str
) -> dict:
    """Return the contract delivery for ``policy``.

    ``local_signed`` is emitted at publish time and is always available.
    ``dual_witness`` becomes complete only when every contracted witness has
    signed the same checkpoint number, tree size, root and source snapshot.
    """

    if policy not in POLICIES:
        raise AnchorError("unknown_policy")
    contract, _raw, contract_sha = _load_contract(contract_path)
    tags = _tags(contract)
    witnesses = _witnesses(contract)
    db = _open(db_path)
    try:
        _registered_case(db, contract, contract_sha)
        checkpoint = _checkpoint_row(db, contract["case_id"], checkpoint_number)
        if policy == "local_signed":
            row = _delivery_row(db, contract["case_id"], checkpoint_number, policy)
            if not row:
                raise AnchorError("local_delivery_missing")
            payload = json.loads(row["payload_json"])
            return {
                "policy": "local_signed",
                "status": "complete" if row["state"] == "signed" else row["state"],
                "checkpoint_number": checkpoint_number,
                "tree_size": checkpoint["tree_size"],
                "root": checkpoint["root"],
                "snapshot_sha256": checkpoint["snapshot_sha256"],
                "leaf_tag": tags.leaf.decode(),
                "node_tag": tags.node.decode(),
                "inclusions": payload.get("inclusions", {}),
                "local_signature": {
                    "key_id": _key_id(contract["case_id"], "local", "audit"),
                    "algorithm": "hmac-sha256",
                    "signature": row["signature"],
                    "payload_sha256": _sha256_hex(
                        canonical_json(payload)
                    ),
                },
                "issued_at": payload.get("issued_at"),
            }

        receipts = [
            dict(r)
            for r in db.execute(
                "SELECT * FROM anchor_witness_receipt"
                " WHERE case_id=? AND checkpoint_number=? ORDER BY witness_id",
                (contract["case_id"], checkpoint_number),
            )
        ]
        by_id = {r["witness_id"]: r for r in receipts}
        forks = [
            dict(r)
            for r in db.execute(
                "SELECT detail_json,created_at FROM anchor_event"
                " WHERE case_id=? AND checkpoint_number=? AND kind='witness_fork'"
                " ORDER BY id",
                (contract["case_id"], checkpoint_number),
            )
        ]
        complete = all(w["id"] in by_id for w in witnesses) and not forks
        same_snapshot = all(
            r["root"] == checkpoint["root"]
            and r["tree_size"] == checkpoint["tree_size"]
            and r["snapshot_sha256"] == checkpoint["snapshot_sha256"]
            for r in receipts
        )
        status = "complete" if complete and same_snapshot else "pending_verification"
        return {
            "policy": "dual_witness",
            "status": status,
            "checkpoint_number": checkpoint_number,
            "tree_size": checkpoint["tree_size"],
            "root": checkpoint["root"],
            "snapshot_sha256": checkpoint["snapshot_sha256"],
            "leaf_tag": tags.leaf.decode(),
            "node_tag": tags.node.decode(),
            "required_witnesses": [w["id"] for w in witnesses],
            "receipts": [
                {
                    "witness_id": r["witness_id"],
                    "witness_role": r["witness_role"],
                    "checkpoint_number": r["checkpoint_number"],
                    "tree_size": r["tree_size"],
                    "root": r["root"],
                    "snapshot_sha256": r["snapshot_sha256"],
                    "signature": r["signature"],
                    "signed_at": r["signed_at"],
                    "received_at": r["received_at"],
                    "payload_json": r["payload_json"],
                }
                for r in receipts
            ],
            "forks": [
                {"detail": json.loads(r["detail_json"]), "at": r["created_at"]}
                for r in forks
            ],
        }
    finally:
        db.close()


def audit_bundle(
    db_path,
    contract_path,
    checkpoint_number: int,
    *,
    consistency_from: int | None = None,
) -> dict:
    """A self-contained audit package for one checkpoint.

    Contains the root, tree size, every inclusion path, an optional
    consistency proof from an older checkpoint, both contract deliveries,
    receipt details and all fork/recovery records.
    """

    contract, _raw, contract_sha = _load_contract(contract_path)
    tags = _tags(contract)
    db = _open(db_path)
    try:
        _registered_case(db, contract, contract_sha)
        checkpoint = _checkpoint_row(db, contract["case_id"], checkpoint_number)
        rows = _leaf_rows(db, contract["case_id"], checkpoint["tree_size"])
        leaves = _leaf_hashes(rows)
        rebuilt = mth(leaves, tags).hex()
        if rebuilt != checkpoint["root"]:
            # Refuse to package a tree whose committed prefix no longer
            # reproduces the published root; record the evidence durably.
            with _immediate(db):
                _log(
                    db,
                    contract["case_id"],
                    "bundle_root_mismatch",
                    checkpoint_number,
                    {"stored": checkpoint["root"], "recomputed": rebuilt},
                )
            raise AnchorError("checkpoint_root_mismatch")
        inclusions = {}
        for position, row in enumerate(rows):
            path = inclusion_proof(leaves, position, tags)
            inclusions[row["source_id"]] = {
                "leaf_index": row["leaf_index"],
                "leaf_hash": row["leaf_hash"],
                "kind": row["kind"],
                "tree_size": checkpoint["tree_size"],
                "root": checkpoint["root"],
                "path": [p.hex() for p in path],
            }
        consistency = None
        if consistency_from is not None:
            old = _checkpoint_row(db, contract["case_id"], consistency_from)
            if old["tree_size"] > checkpoint["tree_size"]:
                raise AnchorError("old_checkpoint_after_new")
            if mth(leaves[: old["tree_size"]], tags).hex() != old["root"]:
                raise AnchorError("old_prefix_replaced")
            proof = consistency_proof(leaves, old["tree_size"], tags)
            consistency = {
                "old_checkpoint": consistency_from,
                "new_checkpoint": checkpoint_number,
                "old_tree_size": old["tree_size"],
                "new_tree_size": checkpoint["tree_size"],
                "old_root": old["root"],
                "new_root": checkpoint["root"],
                "proof": [p.hex() for p in proof],
            }
        events = [
            dict(r)
            for r in db.execute(
                "SELECT kind,checkpoint_number,detail_json,created_at FROM anchor_event"
                " WHERE case_id=? ORDER BY id",
                (contract["case_id"],),
            )
        ]
        deliveries = {}
        for policy in POLICIES:
            try:
                deliveries[policy] = build_delivery(
                    db_path, contract_path, checkpoint_number, policy
                )
            except AnchorError as exc:
                deliveries[policy] = {"policy": policy, "status": f"unavailable:{exc}"}
        bundle = {
            "type": "coldhandoff.source-anchor.bundle",
            "schema_version": SCHEMA_VERSION,
            "case_id": contract["case_id"],
            "generated_at": _now(),
            "checkpoint": {
                "number": checkpoint["number"],
                "tree_size": checkpoint["tree_size"],
                "root": checkpoint["root"],
                "snapshot_sha256": checkpoint["snapshot_sha256"],
                "state": checkpoint["state"],
                "created_at": checkpoint["created_at"],
            },
            "leaf_tag": tags.leaf.decode(),
            "node_tag": tags.node.decode(),
            "leaves": [
                {
                    "leaf_index": r["leaf_index"],
                    "source_id": r["source_id"],
                    "kind": r["kind"],
                    "payload": json.loads(r["payload_json"]),
                    "leaf_hash": r["leaf_hash"],
                    "import_version": r["import_version"],
                }
                for r in rows
            ],
            "inclusions": inclusions,
            "consistency": consistency,
            "deliveries": deliveries,
            "events": [
                {
                    "kind": e["kind"],
                    "checkpoint_number": e["checkpoint_number"],
                    "detail": json.loads(e["detail_json"]),
                    "at": e["created_at"],
                }
                for e in events
            ],
            "verify": {
                "command": (
                    "python3 -m coldhandoff anchor-verify --bundle "
                    f"{bundle_path or '<bundle.json>'} [--keyring <keyring.json>]"
                ),
                "keyring_option": "--keyring <keyring.json> (optional, for signatures)",
            },
        }
        return bundle
    finally:
        db.close()


def verify_bundle(bundle: dict, keyring: dict | None = None) -> dict:
    """Independently verify a bundle.

    Tree checks use only the embedded roots, sizes, leaf payloads and proofs.
    Signature checks run when a keyring is supplied; otherwise they are
    reported as ``None`` (not verified, not failed).
    """

    checks: list[dict] = []

    def add(name: str, ok: bool | None, detail: str = "") -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    try:
        leaf_tag = bundle.get("leaf_tag", "cold-source-v1").encode()
        node_tag = bundle.get("node_tag", "cold-node-v1").encode()
        tags = DomainTags(leaf=leaf_tag, node=node_tag)
        checkpoint = bundle["checkpoint"]
        size = int(checkpoint["tree_size"])
        root = checkpoint["root"]
        leaves_doc = bundle.get("leaves", [])
        computed = [tags.leaf_hash(validate_leaf(row["payload"])) for row in leaves_doc]
        computed_hex = [h.hex() for h in computed]
        add("leaf_count_matches_size", len(computed) == size, f"{len(computed)} vs {size}")
        add(
            "leaf_hash_matches_payload",
            all(
                row.get("leaf_hash") == h
                for row, h in zip(leaves_doc, computed_hex)
            ),
        )
        rebuilt_root = mth(computed, tags).hex()
        add("root_rebuilt_from_leaves", rebuilt_root == root, f"{rebuilt_root} vs {root}")
        snapshot = _snapshot_digest(
            [
                {"leaf_index": row["leaf_index"], "source_id": row["source_id"], "leaf_hash": row["leaf_hash"]}
                for row in leaves_doc
            ]
        )
        add(
            "snapshot_matches",
            snapshot == checkpoint.get("snapshot_sha256"),
            f"{snapshot} vs {checkpoint.get('snapshot_sha256')}",
        )
        inclusions_ok = True
        inclusions_bound = True
        for row in leaves_doc:
            doc = bundle.get("inclusions", {}).get(row["source_id"])
            if not doc:
                inclusions_ok = False
                break
            # An RFC 6962 inclusion path can also verify under a different
            # claimed size, so bind the document to this checkpoint rather
            # than trusting the document's own size and root fields.
            if int(doc["tree_size"]) != size or doc["root"] != root:
                inclusions_bound = False
            if int(doc["leaf_index"]) != int(row["leaf_index"]):
                inclusions_bound = False
            if not verify_inclusion(
                row["leaf_hash"],
                int(doc["leaf_index"]),
                int(doc["tree_size"]),
                doc["path"],
                doc["root"],
                tags,
            ):
                inclusions_ok = False
                break
        add("inclusions_verify", inclusions_ok)
        add(
            "inclusions_bound_to_checkpoint",
            inclusions_bound,
            "" if inclusions_bound else "inclusion document cites a different tree",
        )
        consistency = bundle.get("consistency")
        if consistency:
            add("consistency_verifies", verify_consistency_document(consistency))
        else:
            add("consistency_verifies", None, "no consistency proof requested")

        deliveries = bundle.get("deliveries", {})
        local = deliveries.get("local_signed")
        if local:
            add(
                "local_delivery_matches_checkpoint",
                local.get("root") == root
                and int(local.get("tree_size", -1)) == size
                and local.get("snapshot_sha256") == checkpoint.get("snapshot_sha256"),
            )
            local_inclusions = local.get("inclusions") or {}
            add(
                "local_inclusions_verify",
                set(local_inclusions) == set(bundle.get("inclusions", {}))
                and all(
                    verify_inclusion(
                        bundle["inclusions"][sid]["leaf_hash"],
                        int(item["leaf_index"]),
                        int(item["tree_size"]),
                        item["path"],
                        item["root"],
                        tags,
                    )
                    for sid, item in local_inclusions.items()
                ),
            )
            sig = local.get("local_signature") or {}
            secret = (keyring or {}).get(sig.get("key_id"))
            if secret and sig.get("signature"):
                # Rebuild exactly what was signed: the delivery view is a
                # subset of the stored signed payload, field for field.
                signed = {
                    "type": "coldhandoff.source-anchor.local-signed",
                    "case_id": bundle["case_id"],
                    "checkpoint_number": local["checkpoint_number"],
                    "tree_size": local["tree_size"],
                    "root": local["root"],
                    "snapshot_sha256": local["snapshot_sha256"],
                    "leaf_tag": local["leaf_tag"],
                    "node_tag": local["node_tag"],
                    "inclusions": local["inclusions"],
                    "issued_at": local["issued_at"],
                }
                add(
                    "local_signature_valid",
                    hmac.compare_digest(
                        sig["signature"], _sign(secret, canonical_json(signed))
                    ),
                )
            else:
                add("local_signature_valid", None, "no keyring")

        dual = deliveries.get("dual_witness")
        if dual:
            required = dual.get("required_witnesses") or []
            by_id = {r["witness_id"]: r for r in dual.get("receipts", [])}
            complete = all(w in by_id for w in required)
            dual_status = dual.get("status")
            # An incomplete dual package is an explicit pending state, not a
            # failure of the checkpoint or of the local package.
            add(
                "dual_has_all_receipts",
                complete if dual_status == "complete" else None,
                f"{sorted(by_id)} vs {required}",
            )
            same = bool(by_id) and all(
                r["root"] == root
                and int(r["tree_size"]) == size
                and r["snapshot_sha256"] == checkpoint.get("snapshot_sha256")
                for r in by_id.values()
            )
            add(
                "dual_receipts_bind_same_snapshot",
                same if complete else None,
                "" if complete else "incomplete receipts",
            )
            expected_complete = complete and same and not dual.get("forks")
            add(
                "dual_status_matches",
                (dual_status == "complete") == expected_complete,
                str(dual_status),
            )
            if keyring:
                sig_ok = True
                for r in by_id.values():
                    secret = keyring.get(
                        f"witness:{bundle['case_id']}:{r['witness_id']}"
                    )
                    if not secret or not verify_receipt(r, secret):
                        sig_ok = False
                add("dual_signatures_valid", sig_ok)
            else:
                add("dual_signatures_valid", None, "no keyring")
        return {"ok": all(c["ok"] is not False for c in checks), "checks": checks}
    except (KeyError, TypeError, ValueError, MerkleError) as exc:
        add("bundle_malformed", False, str(exc))
        return {"ok": False, "checks": checks}


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------


def recover(
    db_path, contract_path, *, advance: bool = False, policy: str = "local_signed"
) -> dict:
    """Resume after a crash without creating a competing history.

    * Incomplete checkpoints are re-bound to their original leaves, roots and
      sizes.  Pending signing requests are dispatched again.
    * A checkpoint is never renumbered or rewritten.  If new leaves arrived,
      a *new* checkpoint number is allocated at the larger size.
    """

    contract, _raw, contract_sha = _load_contract(contract_path)
    tags = _tags(contract)
    db = _open(db_path)
    actions: list[dict] = []
    try:
        _registered_case(db, contract, contract_sha)
        rows, current_root, current_size = _current_root(db, contract["case_id"], tags)
        checkpoints = [
            dict(r)
            for r in db.execute(
                "SELECT * FROM anchor_checkpoint WHERE case_id=? ORDER BY number",
                (contract["case_id"],),
            )
        ]
        for checkpoint in checkpoints:
            prefix = mth(_leaf_hashes(rows[: checkpoint["tree_size"]]), tags).hex()
            if prefix != checkpoint["root"]:
                with _immediate(db):
                    _log(
                        db,
                        contract["case_id"],
                        "recovery_prefix_mismatch",
                        checkpoint["number"],
                        {"stored": checkpoint["root"], "recomputed": prefix},
                    )
                    db.execute(
                        "UPDATE anchor_checkpoint SET state='forked'"
                        " WHERE case_id=? AND number=?",
                        (contract["case_id"], checkpoint["number"]),
                    )
                actions.append(
                    {
                        "action": "mark_forked",
                        "checkpoint_number": checkpoint["number"],
                        "reason": "stored root is not the committed prefix root",
                    }
                )
                continue
            if checkpoint["state"] in {
                "persisted",
                "awaiting_witness",
                "pending_verification",
            }:
                pending = [
                    r["witness_id"]
                    for r in db.execute(
                        "SELECT witness_id FROM anchor_witness_request"
                        " WHERE case_id=? AND checkpoint_number=?"
                        "   AND state IN ('pending','sent') ORDER BY witness_id",
                        (contract["case_id"], checkpoint["number"]),
                    )
                ]
                with _immediate(db):
                    sent = _request_dispatch(db, contract["case_id"], checkpoint["number"])
                    if not sent and pending:
                        # Requests were already ``sent`` but no receipt arrived:
                        # the ACK may have been lost.  Re-dispatch the same
                        # bound request rather than inventing a new one.
                        for witness_id in pending:
                            db.execute(
                                "UPDATE anchor_witness_request SET updated_at=?"
                                " WHERE case_id=? AND checkpoint_number=? AND witness_id=?",
                                (_now(), contract["case_id"], checkpoint["number"], witness_id),
                            )
                        _log(
                            db,
                            contract["case_id"],
                            "witness_retry",
                            checkpoint["number"],
                            {"witnesses": pending},
                        )
                        sent = pending
                if sent:
                    actions.append(
                        {
                            "action": "dispatch_pending_requests",
                            "checkpoint_number": checkpoint["number"],
                            "witnesses": sent,
                        }
                    )
                state = db.execute(
                    "SELECT state FROM anchor_checkpoint WHERE case_id=? AND number=?",
                    (contract["case_id"], checkpoint["number"]),
                ).fetchone()["state"]
                actions.append(
                    {
                        "action": "continue_checkpoint",
                        "checkpoint_number": checkpoint["number"],
                        "tree_size": checkpoint["tree_size"],
                        "state": state,
                    }
                )
        latest = checkpoints[-1] if checkpoints else None
        published = None
        # ``advance`` adds another checkpoint only when nothing is waiting on
        # witnesses; resuming one delivers what ``recover`` reports instead.
        if advance and (latest is None or latest["tree_size"] < current_size):
            published = publish_checkpoint(
                db_path, contract_path, policy=policy, dispatch=False
            )
            with _immediate(db):
                _request_dispatch(db, contract["case_id"], published["checkpoint_number"])
            latest = _checkpoint_row(db, contract["case_id"], published["checkpoint_number"])
            actions.append(
                {
                    "action": "publish_next_checkpoint",
                    "checkpoint_number": published["checkpoint_number"],
                    "tree_size": published["tree_size"],
                    "root": published["root"],
                }
            )
        return {
            "case_id": contract["case_id"],
            "current_tree_size": current_size,
            "current_root": current_root.hex(),
            "latest_checkpoint": latest["number"] if latest else None,
            "latest_tree_size": latest["tree_size"] if latest else None,
            "actions": actions,
            "published": published,
        }
    finally:
        db.close()


def list_forks(db_path, contract_path) -> list[dict]:
    contract, _raw, contract_sha = _load_contract(contract_path)
    db = _open(db_path)
    try:
        _registered_case(db, contract, contract_sha)
        return [
            {
                "checkpoint_number": r["checkpoint_number"],
                "kind": r["kind"],
                "detail": json.loads(r["detail_json"]),
                "at": r["created_at"],
            }
            for r in db.execute(
                "SELECT checkpoint_number,kind,detail_json,created_at FROM anchor_event"
                " WHERE case_id=? AND kind IN ('witness_fork','checkpoint_root_conflict',"
                " 'recovery_prefix_mismatch','bundle_root_mismatch') ORDER BY id",
                (contract["case_id"],),
            )
        ]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Human-facing report
# ---------------------------------------------------------------------------


def _markdown(bundle: dict, verification: dict | None = None) -> str:
    checkpoint = bundle["checkpoint"]
    lines = [
        "# 来源锚定审计报告",
        "",
        f"- 案件：`{bundle['case_id']}`",
        f"- 检查点：#{checkpoint['number']}",
        f"- 树大小：{checkpoint['tree_size']}",
        f"- 根：`{checkpoint['root']}`",
        f"- 来源快照：`{checkpoint['snapshot_sha256']}`",
        f"- 域标签：leaf=`{bundle['leaf_tag']}` node=`{bundle['node_tag']}`",
        "",
        "## 叶子（导入顺序）",
        "",
        "| # | source_id | 类型 | 叶哈希 | 导入版本 |",
        "|---|---|---|---|---|",
    ]
    for row in bundle["leaves"]:
        lines.append(
            f"| {row['leaf_index']} | `{row['source_id']}` | {row['kind']} | "
            f"`{row['leaf_hash'][:16]}…` | {row['import_version']} |"
        )
    consistency = bundle.get("consistency")
    if consistency:
        lines += [
            "",
            "## 一致性证明",
            "",
            f"- 旧检查点：#{consistency['old_checkpoint']}（{consistency['old_tree_size']} 叶）",
            f"- 新检查点：#{consistency['new_checkpoint']}（{consistency['new_tree_size']} 叶）",
            f"- 旧根：`{consistency['old_root']}`",
            f"- 新根：`{consistency['new_root']}`",
            f"- 证明节点数：{len(consistency['proof'])}",
        ]
    lines += ["", "## 交付", ""]
    for policy, delivery in bundle["deliveries"].items():
        lines.append(f"- {policy}: `{delivery.get('status')}`")
        if policy == "dual_witness":
            for receipt in delivery.get("receipts", []):
                lines.append(
                    f"  - {receipt['witness_id']}（{receipt['witness_role']}）"
                    f" 于 {receipt['signed_at']} 签收根 `{receipt['root'][:16]}…`"
                )
            for fork in delivery.get("forks", []):
                lines.append(f"  - 分叉：`{json.dumps(fork['detail'], ensure_ascii=False)}`")
    lines += ["", "## 恢复/分叉记录", ""]
    interesting = [
        e
        for e in bundle.get("events", [])
        if e["kind"]
        in {
            "witness_fork",
            "checkpoint_root_conflict",
            "recovery_prefix_mismatch",
            "leaf_appended",
            "witness_request_sent",
            "witness_receipt_recorded",
        }
    ]
    if not interesting:
        lines.append("- 无")
    for event in interesting:
        lines.append(
            f"- {event['at']} {event['kind']} "
            f"#{event['checkpoint_number']} `{json.dumps(event['detail'], ensure_ascii=False)}`"
        )
    lines += ["", "## 验证命令", "", "```bash", bundle["verify"]["command"], "```", ""]
    if verification:
        lines += ["## 独立验证结果", ""]
        for check in verification["checks"]:
            mark = "通过" if check["ok"] is True else ("不适用" if check["ok"] is None else "失败")
            lines.append(f"- {check['check']}: {mark} {check['detail']}".rstrip())
        lines += ["", f"总体：{'通过' if verification['ok'] else '失败'}", ""]
    return "\n".join(lines)


def write_bundle(bundle: dict, out_path, verification: dict | None = None):
    """Write the JSON bundle and a Markdown companion; return both paths."""

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    md = out.with_suffix(".md")
    md.write_text(_markdown(bundle, verification), encoding="utf-8")
    return out, md
