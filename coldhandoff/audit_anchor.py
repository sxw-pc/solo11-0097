"""Append-only, tamper-evident anchoring across ingested source files.

`ingest` hashes each `source_file` so a report can re-check that file's
bytes, but per-file hashes cannot show that an old source was dropped,
reordered or replaced between two imports.  This module commits every
source to a single append-only Merkle tree (see `coldhandoff.merkle`):

* leaves bind the non-reusable source id, the SHA-256 of the original
  bytes and the import version under the contract's domain tags, in
  stable import order;
* new sources only ever append at the end of the tree — a correction
  adds a revocation/supersede leaf and never rewrites an old leaf;
* any source gets an inclusion proof against the current root, and any
  two checkpoints (old size n, new size m) get a consistency proof that
  an auditor holding only the two roots, the sizes and the proof can
  verify independently.

Two checkpoint policies exist.  ``local_signed`` issues immediately with
a local signature for internal audit.  ``dual_witness`` stays pending
until both contract witnesses sign the *same* size/root/snapshot; a
witness that signs a different root forks the checkpoint, which then
stays pending and displays the fork instead of being silently rewritten,
while an already issued local package keeps verifying with its original
root.

Leaf allocation, the checkpoint row and its pending sign request commit
as one SQLite transaction (BEGIN IMMEDIATE), so concurrent imports can
never take the same leaf position.  Witness receipts may be duplicated,
delayed or lost: retries bind the exact same root/size, and a receipt
that signs a different root for an already numbered checkpoint is
rejected and recorded as a fork.  After a crash, `recover` resumes
pending checkpoints or the caller opens the next one — never two
conflicting histories at the same checkpoint number.

Signatures are HMAC-SHA256 over the canonical sign request with a
simulated keyring; `SimulatedWitness` is a test double, not a real
remote witness.
"""
import hmac
import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from . import merkle
from .store import connect

POLICIES = ('local_signed', 'dual_witness')
LOCAL_SIGNER = 'local'
# Simulated keyring: the witnesses in tests are local test doubles, so
# HMAC-SHA256 with these keys stands in for their signatures.
KEYRING = {
    LOCAL_SIGNER: b'coldhandoff-local-audit-key-v1',
    'W1': b'coldhandoff-witness-w1-key-v1',
    'W2': b'coldhandoff-witness-w2-key-v1',
}

# Test-only crash injection points.
FAULT_ROOT_NOT_PERSISTED = 'after_root_computed_before_persist'
FAULT_BEFORE_WITNESS_RECEIPT = 'after_checkpoint_persist_before_witness_receipt'
FAULT_AFTER_FIRST_ACK = 'after_first_witness_ack'

ANCHOR_SCHEMA = """
CREATE TABLE IF NOT EXISTS anchor_case(
  id TEXT PRIMARY KEY, contract_sha256 TEXT NOT NULL,
  contract_json TEXT NOT NULL, source_snapshot TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS anchor_leaf(
  seq INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  source_id INTEGER NOT NULL,
  source_sha256 TEXT NOT NULL,
  version TEXT NOT NULL,
  supersedes INTEGER,
  note TEXT,
  leaf_hash TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS anchor_checkpoint(
  size INTEGER NOT NULL,
  policy TEXT NOT NULL,
  root TEXT NOT NULL,
  snapshot_sha256 TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  sign_request TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  issued_at TEXT,
  PRIMARY KEY(size, policy)
);
CREATE TABLE IF NOT EXISTS anchor_receipt(
  size INTEGER NOT NULL,
  policy TEXT NOT NULL,
  signer TEXT NOT NULL,
  root TEXT NOT NULL,
  signature TEXT NOT NULL,
  received_at TEXT NOT NULL,
  PRIMARY KEY(size, policy, signer)
);
CREATE TABLE IF NOT EXISTS anchor_event(
  id INTEGER PRIMARY KEY,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  size INTEGER,
  policy TEXT,
  detail TEXT NOT NULL
);
"""


class AnchorError(Exception):
    """The anchor store is inconsistent or the request is invalid."""


class InjectedFault(Exception):
    """Raised at a test-only fault injection point to simulate a crash."""


def _connect(db_path):
    db = connect(db_path)
    db.isolation_level = None  # explicit BEGIN IMMEDIATE / COMMIT control
    db.execute('PRAGMA busy_timeout=30000')
    db.executescript(ANCHOR_SCHEMA)
    return db


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def _sign(signer, payload):
    return hmac.new(KEYRING[signer], merkle.canonical(payload), sha256).hexdigest()


def verify_signature(signer, payload, signature):
    key = KEYRING.get(signer)
    if key is None:
        return False
    expected = hmac.new(key, merkle.canonical(payload), sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _event_tx(db, kind, detail, size=None, policy=None):
    db.execute('INSERT INTO anchor_event(at,kind,size,policy,detail) VALUES (?,?,?,?,?)',
               (_now(), kind, size, policy, detail))


def _case_tx(db):
    row = db.execute('SELECT * FROM anchor_case ORDER BY rowid DESC LIMIT 1').fetchone()
    if row is None:
        raise AnchorError('no_anchor_case')
    return {'case_id': row['id'], 'contract_sha256': row['contract_sha256'],
            'contract': json.loads(row['contract_json'])}


def _sync_leaves_tx(db):
    """Append leaves for sources not yet anchored.  Append-only: existing
    leaves are never reordered, renumbered or rewritten."""
    have = {r['source_id'] for r in db.execute("SELECT source_id FROM anchor_leaf WHERE kind='source'")}
    seq = db.execute('SELECT COALESCE(MAX(seq)+1,0) FROM anchor_leaf').fetchone()[0]
    added = []
    for row in db.execute('SELECT id, hash FROM source_file ORDER BY id'):
        if row['id'] in have:
            continue
        lh = merkle.leaf_hash('source', row['id'], row['hash'])
        db.execute('INSERT INTO anchor_leaf(seq,kind,source_id,source_sha256,version,supersedes,note,leaf_hash) VALUES (?,?,?,?,?,?,?,?)',
                   (seq, 'source', row['id'], row['hash'], merkle.LEAF_VERSION, None, None, lh))
        added.append(seq)
        seq += 1
    return added


def _leaves_tx(db):
    return [dict(r) for r in db.execute('SELECT * FROM anchor_leaf ORDER BY seq')]


def _snapshot_entry(leaf):
    return {'seq': leaf['seq'], 'kind': leaf['kind'], 'source_id': leaf['source_id'],
            'sha256': leaf['source_sha256'], 'version': leaf['version'],
            'supersedes': leaf['supersedes'], 'note': leaf['note'], 'leaf_hash': leaf['leaf_hash']}


def _leaf_payload_of(leaf):
    return {'kind': leaf['kind'], 'source_id': leaf['source_id'], 'sha256': leaf['source_sha256'],
            'version': leaf['version'], 'supersedes': leaf['supersedes'], 'note': leaf['note']}


def _conflicting_checkpoints_tx(db, hashes):
    """Delivered checkpoints whose stored root no longer matches the leaf
    store prefix — the signature of a dropped/reordered/rewritten source."""
    conflicts = []
    for cp in db.execute('SELECT size, policy, root FROM anchor_checkpoint'):
        if cp['size'] > len(hashes) or merkle.root(hashes[:cp['size']]) != cp['root']:
            conflicts.append({'size': cp['size'], 'policy': cp['policy'], 'root': cp['root']})
    return conflicts


def _record_conflicts_tx(db, conflicts):
    for cp in conflicts:
        _event_tx(db, 'corruption',
                  f"checkpoint {cp['size']}/{cp['policy']} root {cp['root'][:16]}… no longer matches the leaf store",
                  cp['size'], cp['policy'])


def _checkpoint_view_tx(db, size, policy):
    cp = dict(db.execute('SELECT * FROM anchor_checkpoint WHERE size=? AND policy=?', (size, policy)).fetchone())
    receipts = [dict(r) for r in db.execute(
        'SELECT signer, root, signature, received_at FROM anchor_receipt WHERE size=? AND policy=? ORDER BY signer',
        (size, policy))]
    return {'size': cp['size'], 'policy': cp['policy'], 'root': cp['root'], 'status': cp['status'],
            'snapshot_sha256': cp['snapshot_sha256'], 'sign_request': json.loads(cp['sign_request']),
            'created_at': cp['created_at'], 'issued_at': cp['issued_at'], 'receipts': receipts}


def register(db_path, contract_path):
    """Freeze the contract and the real ingested sources, then anchor every
    existing source as a leaf of the append-only commitment tree."""
    raw = Path(contract_path).read_bytes()
    contract = json.loads(raw)
    db = _connect(db_path)
    try:
        rows = [{'id': r['id'], 'hash': r['hash']} for r in db.execute('SELECT id, hash FROM source_file ORDER BY id')]
        if len(rows) < 2:
            raise ValueError('needs_two_sources')
        db.execute('BEGIN IMMEDIATE')
        try:
            db.execute('INSERT INTO anchor_case VALUES (?,?,?,?)',
                       (contract['case_id'], sha256(raw).hexdigest(), raw.decode(), json.dumps(rows, sort_keys=True)))
            added = _sync_leaves_tx(db)
            _event_tx(db, 'register',
                      f"case {contract['case_id']}: anchored {len(rows)} source(s), {len(added)} leaf(s) appended")
            db.commit()
        except Exception:
            db.rollback()
            raise
        return contract['case_id']
    finally:
        db.close()


def sync_sources(db_path):
    """Append leaves for any sources ingested since the last sync."""
    db = _connect(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        try:
            added = _sync_leaves_tx(db)
            size = db.execute('SELECT COUNT(*) FROM anchor_leaf').fetchone()[0]
            db.commit()
        except Exception:
            db.rollback()
            raise
        return {'added': added, 'size': size}
    finally:
        db.close()


def append_correction(db_path, source_id, reason, replacement=None):
    """Correct an old source by appending a revocation/supersede leaf.

    The old leaf is never modified: the correction is itself a new leaf at
    the end of the tree.  ``replacement`` may name the superseding source
    as ``{'source_id': …, 'sha256': …}``; without it the leaf is a plain
    revocation of ``source_id``.
    """
    db = _connect(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        try:
            _sync_leaves_tx(db)
            old = db.execute("SELECT * FROM anchor_leaf WHERE kind='source' AND source_id=?", (source_id,)).fetchone()
            if old is None:
                raise AnchorError('unknown_source')
            seq = db.execute('SELECT COALESCE(MAX(seq)+1,0) FROM anchor_leaf').fetchone()[0]
            if replacement:
                kind, ref_id, ref_sha = 'supersede', int(replacement['source_id']), str(replacement['sha256'])
            else:
                kind, ref_id, ref_sha = 'revoke', old['source_id'], old['source_sha256']
            lh = merkle.leaf_hash(kind, ref_id, ref_sha, supersedes=source_id, note=reason)
            db.execute('INSERT INTO anchor_leaf(seq,kind,source_id,source_sha256,version,supersedes,note,leaf_hash) VALUES (?,?,?,?,?,?,?,?)',
                       (seq, kind, ref_id, ref_sha, merkle.LEAF_VERSION, source_id, reason, lh))
            _event_tx(db, 'correction', f'{kind} leaf {seq} for source {source_id}: {reason}')
            db.commit()
        except Exception:
            db.rollback()
            raise
        return {'seq': seq, 'kind': kind, 'leaf_hash': lh}
    finally:
        db.close()


def checkpoint(db_path, policy, fault_at=None):
    """Commit a checkpoint of the current tree under ``policy``.

    Leaf allocation, the checkpoint row and its sign request commit as a
    single transaction; ``local_signed`` also issues its local receipt in
    the same boundary.  Re-checkpointing an unchanged tree is idempotent
    and returns the delivered checkpoint.  ``fault_at`` is a test-only
    crash injection point.
    """
    if policy not in POLICIES:
        raise ValueError('unknown_policy')
    db = _connect(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        try:
            _sync_leaves_tx(db)
            case = _case_tx(db)
            leaves = _leaves_tx(db)
            hashes = [l['leaf_hash'] for l in leaves]
            conflicts = _conflicting_checkpoints_tx(db, hashes)
            if conflicts:
                _record_conflicts_tx(db, conflicts)
                db.commit()
                raise AnchorError('checkpoint_root_conflict')
            size = len(hashes)
            root = merkle.root(hashes)
            if fault_at == FAULT_ROOT_NOT_PERSISTED:
                raise InjectedFault(fault_at)  # crash: nothing below persists
            existing = db.execute('SELECT root FROM anchor_checkpoint WHERE size=? AND policy=?', (size, policy)).fetchone()
            if existing is not None:
                if existing['root'] != root:
                    _event_tx(db, 'corruption', f'checkpoint {size}/{policy} recomputed to a different root', size, policy)
                    db.commit()
                    raise AnchorError('checkpoint_root_conflict')
                view = _checkpoint_view_tx(db, size, policy)
                db.commit()
                return view
            clash = db.execute('SELECT root FROM anchor_checkpoint WHERE size=?', (size,)).fetchone()
            if clash is not None and clash['root'] != root:
                _event_tx(db, 'corruption', f'size {size} already delivered with a different root', size, policy)
                db.commit()
                raise AnchorError('checkpoint_root_conflict')
            snapshot = [_snapshot_entry(l) for l in leaves]
            snapshot_json = merkle.canonical(snapshot).decode('utf-8')
            snap_sha = sha256(snapshot_json.encode('utf-8')).hexdigest()
            sign_request = {'case_id': case['case_id'], 'policy': policy, 'size': size,
                            'root': root, 'snapshot_sha256': snap_sha}
            now = _now()
            db.execute('INSERT INTO anchor_checkpoint VALUES (?,?,?,?,?,?,?,?,?)',
                       (size, policy, root, snap_sha, snapshot_json,
                        merkle.canonical(sign_request).decode('utf-8'), 'pending', now, None))
            if policy == 'local_signed':
                signature = _sign(LOCAL_SIGNER, sign_request)
                db.execute('INSERT INTO anchor_receipt VALUES (?,?,?,?,?,?)',
                           (size, policy, LOCAL_SIGNER, root, signature, now))
                db.execute("UPDATE anchor_checkpoint SET status='issued', issued_at=? WHERE size=? AND policy=?",
                           (now, size, policy))
            view = _checkpoint_view_tx(db, size, policy)
            _event_tx(db, 'checkpoint', f"{policy} checkpoint at size {size}, root {root[:16]}…, status {view['status']}", size, policy)
            db.commit()
        except Exception:
            db.rollback()
            raise
        if fault_at == FAULT_BEFORE_WITNESS_RECEIPT:
            raise InjectedFault(fault_at)  # crash: checkpoint persisted, sign request never dispatched
        return view
    finally:
        db.close()


def record_ack(db_path, ack, fault_at=None):
    """Record a witness receipt for a checkpoint.

    Retries bind the exact same root/size: a receipt signing a different
    root for an already numbered checkpoint is rejected and recorded as a
    fork, and the checkpoint stays pending (status ``forked``) instead of
    being silently rewritten.  Identical duplicate receipts are
    idempotent.  ``fault_at`` is a test-only crash injection point.
    """
    db = _connect(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        try:
            payload = ack.get('payload') or {}
            signer = ack.get('signer', '')
            size, policy = payload.get('size'), payload.get('policy')
            cp = None
            if size is not None and policy is not None:
                cp = db.execute('SELECT * FROM anchor_checkpoint WHERE size=? AND policy=?', (size, policy)).fetchone()
            if cp is None:
                _event_tx(db, 'reject', f'ack from {signer or "?"} references unknown checkpoint {size}/{policy}', size, policy)
                db.commit()
                return {'accepted': False, 'reason': 'unknown_checkpoint'}
            if (ack.get('size'), ack.get('policy'), ack.get('root')) != (size, policy, payload.get('root')):
                _event_tx(db, 'reject', f'malformed ack from {signer} on {size}/{policy}', size, policy)
                db.commit()
                return {'accepted': False, 'reason': 'malformed_ack'}
            if not verify_signature(signer, payload, ack.get('signature', '')):
                _event_tx(db, 'reject', f'invalid signature from {signer} on {size}/{policy}', size, policy)
                db.commit()
                return {'accepted': False, 'reason': 'bad_signature'}
            if payload.get('root') != cp['root'] or payload.get('snapshot_sha256') != cp['snapshot_sha256']:
                _event_tx(db, 'fork', json.dumps(
                    {'signer': signer, 'signed_root': payload.get('root'), 'expected_root': cp['root'],
                     'signature': ack.get('signature')}, ensure_ascii=False), size, policy)
                db.execute("UPDATE anchor_checkpoint SET status='forked' WHERE size=? AND policy=? AND status='pending'",
                           (size, policy))
                db.commit()
                return {'accepted': False, 'reason': 'root_mismatch', 'fork': True}
            prior = db.execute('SELECT * FROM anchor_receipt WHERE size=? AND policy=? AND signer=?',
                               (size, policy, signer)).fetchone()
            if prior is not None:
                if prior['signature'] == ack.get('signature'):
                    db.commit()
                    return {'accepted': True, 'duplicate': True, 'status': cp['status']}
                _event_tx(db, 'fork', json.dumps(
                    {'signer': signer, 'detail': 'conflicting re-signature of the same checkpoint',
                     'signature': ack.get('signature')}, ensure_ascii=False), size, policy)
                db.execute("UPDATE anchor_checkpoint SET status='forked' WHERE size=? AND policy=? AND status='pending'",
                           (size, policy))
                db.commit()
                return {'accepted': False, 'reason': 'conflicting_receipt', 'fork': True}
            db.execute('INSERT INTO anchor_receipt VALUES (?,?,?,?,?,?)',
                       (size, policy, signer, cp['root'], ack['signature'], _now()))
            status, issued = cp['status'], False
            if policy == 'dual_witness' and status == 'pending':
                required = {w['id'] for w in _case_tx(db)['contract'].get('witnesses', [])}
                got = {r['signer'] for r in db.execute(
                    'SELECT signer FROM anchor_receipt WHERE size=? AND policy=?', (size, policy))}
                if required and required <= got:
                    status, issued = 'issued', True
                    db.execute("UPDATE anchor_checkpoint SET status='issued', issued_at=? WHERE size=? AND policy=?",
                               (_now(), size, policy))
                    _event_tx(db, 'issued', f'dual-witness checkpoint {size} issued by {sorted(required)}', size, policy)
            db.commit()
        except Exception:
            db.rollback()
            raise
        if fault_at == FAULT_AFTER_FIRST_ACK:
            raise InjectedFault(fault_at)  # crash: receipt persisted, process died before any follow-up
        return {'accepted': True, 'issued': issued, 'status': status}
    finally:
        db.close()


def checkpoint_view(db_path, size, policy):
    """Read back a delivered checkpoint without creating a new one."""
    db = _connect(db_path)
    try:
        row = db.execute('SELECT 1 FROM anchor_checkpoint WHERE size=? AND policy=?', (size, policy)).fetchone()
        if row is None:
            raise AnchorError('unknown_checkpoint')
        return _checkpoint_view_tx(db, size, policy)
    finally:
        db.close()


def recover(db_path):
    """Resume after a crash: re-sync leaves and re-emit the sign requests of
    pending checkpoints so they can be (re)sent to witnesses.  Delivered
    checkpoints are never rewritten; corrupted ones are reported, not
    resumed.  The caller may then continue the old checkpoint or open the
    next one — never two conflicting histories at the same number."""
    db = _connect(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        try:
            _sync_leaves_tx(db)
            leaves = _leaves_tx(db)
            hashes = [l['leaf_hash'] for l in leaves]
            conflicts = _conflicting_checkpoints_tx(db, hashes)
            _record_conflicts_tx(db, conflicts)
            resumed = []
            for row in db.execute("SELECT * FROM anchor_checkpoint WHERE status='pending' ORDER BY size, policy"):
                if any(c['size'] == row['size'] and c['policy'] == row['policy'] for c in conflicts):
                    continue
                resumed.append(json.loads(row['sign_request']))
            if resumed or conflicts:
                _event_tx(db, 'recovery', f'resumed {len(resumed)} pending checkpoint(s), {len(conflicts)} corrupted')
            db.commit()
        except Exception:
            db.rollback()
            raise
        return {'resumed_sign_requests': resumed,
                'corrupted': [f"{c['size']}/{c['policy']}" for c in conflicts]}
    finally:
        db.close()


def _read_tree(db_path):
    """Sync leaves, verify every delivered checkpoint against the leaf store,
    and return (case, leaves, hashes)."""
    db = _connect(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        try:
            _sync_leaves_tx(db)
            case = _case_tx(db)
            leaves = _leaves_tx(db)
            hashes = [l['leaf_hash'] for l in leaves]
            conflicts = _conflicting_checkpoints_tx(db, hashes)
            if conflicts:
                _record_conflicts_tx(db, conflicts)
                db.commit()
                raise AnchorError('checkpoint_root_conflict')
            db.commit()
        except Exception:
            db.rollback()
            raise
        return case, leaves, hashes
    finally:
        db.close()


def inclusion_proof(db_path, source_id):
    """Inclusion proof of ``source_id`` in the current tree."""
    case, leaves, hashes = _read_tree(db_path)
    target = [l for l in leaves if l['kind'] == 'source' and l['source_id'] == source_id]
    if not target:
        raise AnchorError('unknown_source')
    leaf = target[0]
    return {
        'case_id': case['case_id'],
        'source_id': source_id,
        'leaf_index': leaf['seq'],
        'tree_size': len(hashes),
        'root': merkle.root(hashes),
        'leaf_hash': leaf['leaf_hash'],
        'leaf': _leaf_payload_of(leaf),
        'path': merkle.inclusion_path(hashes, leaf['seq']),
        'verify_command': 'python -m coldhandoff anchor-verify-inclusion <proof.json>',
    }


def verify_inclusion_proof(proof):
    """Standalone check of an inclusion proof: recompute the leaf from its
    bound fields and fold the path up to the announced root."""
    leaf = proof.get('leaf') or {}
    recomputed = merkle.leaf_hash(leaf.get('kind'), leaf.get('source_id'), leaf.get('sha256'),
                                  leaf.get('version', merkle.LEAF_VERSION),
                                  leaf.get('supersedes'), leaf.get('note'))
    if recomputed != proof.get('leaf_hash'):
        return False
    return merkle.verify_inclusion(recomputed, proof.get('leaf_index', -1),
                                   proof.get('tree_size', 0), proof.get('path', []),
                                   proof.get('root', ''))


def consistency_proof(db_path, old_size, new_size=None):
    """Append-only consistency proof from the ``old_size`` checkpoint to the
    ``new_size`` (default: current) checkpoint."""
    case, leaves, hashes = _read_tree(db_path)
    new_size = len(hashes) if new_size is None else new_size
    if not 0 <= old_size <= new_size <= len(hashes):
        raise AnchorError('invalid_size_range')
    return {
        'case_id': case['case_id'],
        'old_size': old_size,
        'old_root': merkle.root(hashes[:old_size]),
        'new_size': new_size,
        'new_root': merkle.root(hashes[:new_size]),
        'proof': merkle.consistency_proof(hashes[:new_size], old_size),
        'verify_command': 'python -m coldhandoff anchor-verify-consistency <proof.json>',
    }


def verify_consistency_proof(proof):
    """Standalone check of a consistency proof given only the two roots, the
    two sizes and the proof."""
    return merkle.verify_consistency(proof.get('old_root', ''), proof.get('old_size', -1),
                                     proof.get('new_root', ''), proof.get('new_size', -1),
                                     proof.get('proof', []))


def export_package(db_path, size, policy, out):
    """Export a self-contained audit package (JSON + Markdown) for the
    checkpoint ``size``/``policy``: root, source snapshot, per-source
    inclusion proofs, the consistency proof from the previous checkpoint,
    per-witness receipts, fork/recovery records and verify commands."""
    db = _connect(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        try:
            _sync_leaves_tx(db)
            case = _case_tx(db)
            leaves = _leaves_tx(db)
            hashes = [l['leaf_hash'] for l in leaves]
            conflicts = _conflicting_checkpoints_tx(db, hashes)
            if conflicts:
                _record_conflicts_tx(db, conflicts)
                db.commit()
                raise AnchorError('checkpoint_root_conflict')
            row = db.execute('SELECT * FROM anchor_checkpoint WHERE size=? AND policy=?', (size, policy)).fetchone()
            if row is None:
                raise AnchorError('unknown_checkpoint')
            cp = dict(row)
            receipts = [dict(r) for r in db.execute(
                'SELECT signer, root, signature, received_at FROM anchor_receipt WHERE size=? AND policy=? ORDER BY signer',
                (size, policy))]
            events = [dict(r) for r in db.execute(
                'SELECT at, kind, detail FROM anchor_event WHERE size IS NULL OR (size=? AND (policy IS NULL OR policy=?)) ORDER BY id',
                (size, policy))]
            prev = db.execute('SELECT size, root FROM anchor_checkpoint WHERE size<? ORDER BY size DESC, policy LIMIT 1',
                              (size,)).fetchone()
            db.commit()
        except Exception:
            db.rollback()
            raise
    finally:
        db.close()
    snapshot = json.loads(cp['snapshot_json'])
    snap_hashes = [e['leaf_hash'] for e in snapshot]
    proofs = []
    for entry in snapshot:
        if entry['kind'] != 'source':
            continue
        proofs.append({
            'source_id': entry['source_id'],
            'leaf_index': entry['seq'],
            'tree_size': size,
            'root': cp['root'],
            'leaf_hash': entry['leaf_hash'],
            'leaf': {'kind': entry['kind'], 'source_id': entry['source_id'], 'sha256': entry['sha256'],
                     'version': entry['version'], 'supersedes': entry['supersedes'], 'note': entry['note']},
            'path': merkle.inclusion_path(snap_hashes, entry['seq']),
        })
    if prev is None:
        consistency = {'old_size': 0, 'old_root': merkle.EMPTY_ROOT,
                       'new_size': size, 'new_root': cp['root'], 'proof': []}
    else:
        consistency = {'old_size': prev['size'], 'old_root': prev['root'],
                       'new_size': size, 'new_root': cp['root'],
                       'proof': merkle.consistency_proof(hashes[:size], prev['size'])}
    if policy == 'local_signed':
        required = [LOCAL_SIGNER]
    else:
        required = [w['id'] for w in case['contract'].get('witnesses', [])]
    package = {
        'format': 'coldhandoff-anchor-package/1',
        'case_id': case['case_id'],
        'policy': policy,
        'status': 'issued' if cp['status'] == 'issued' else 'pending_verification',
        'checkpoint_status': cp['status'],
        'size': size,
        'root': cp['root'],
        'snapshot_sha256': cp['snapshot_sha256'],
        'snapshot': snapshot,
        'sign_request': json.loads(cp['sign_request']),
        'required_signers': required,
        'receipts': receipts,
        'inclusion_proofs': proofs,
        'consistency': consistency,
        'events': events,
        'created_at': cp['created_at'],
        'issued_at': cp['issued_at'],
        'verify_commands': [
            'python -m coldhandoff anchor-verify-package <package.json>',
            'python -m coldhandoff anchor-verify-inclusion <inclusion-proof.json>',
            'python -m coldhandoff anchor-verify-consistency <consistency-proof.json>',
        ],
    }
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(package, ensure_ascii=False, indent=2), encoding='utf-8')
    out.with_suffix('.md').write_text(_package_markdown(package), encoding='utf-8')
    return package


def verify_package(package):
    """Independent audit of an exported package: recompute every leaf, the
    root, the inclusion and consistency proofs, and every receipt, using
    only the package itself."""
    checks = []

    def check(name, ok, detail=''):
        checks.append({'name': name, 'ok': bool(ok), 'detail': detail})

    snap = package.get('snapshot') or []
    recomputed = [merkle.leaf_hash(e.get('kind'), e.get('source_id'), e.get('sha256'),
                                   e.get('version', merkle.LEAF_VERSION),
                                   e.get('supersedes'), e.get('note')) for e in snap]
    check('leaf_hashes_match_snapshot', recomputed == [e.get('leaf_hash') for e in snap])
    check('leaf_positions_sequential', [e.get('seq') for e in snap] == list(range(len(snap))))
    check('root_matches_leaf_set', merkle.root(recomputed) == package.get('root'))
    check('snapshot_digest_matches',
          sha256(merkle.canonical(snap)).hexdigest() == package.get('snapshot_sha256'))
    check('tree_size_matches_snapshot', package.get('size') == len(snap))
    for p in package.get('inclusion_proofs') or []:
        check(f"inclusion_source_{p.get('source_id')}",
              verify_inclusion_proof(p) and p.get('root') == package.get('root')
              and p.get('tree_size') == package.get('size'))
    cons = package.get('consistency')
    if cons is not None:
        check('consistency_proof',
              cons.get('new_root') == package.get('root') and cons.get('new_size') == package.get('size')
              and merkle.verify_consistency(cons.get('old_root', ''), cons.get('old_size', -1),
                                            package.get('root', ''), package.get('size', -1),
                                            cons.get('proof', [])))
    req = package.get('sign_request') or {}
    check('sign_request_binds_root',
          req.get('root') == package.get('root') and req.get('size') == package.get('size')
          and req.get('snapshot_sha256') == package.get('snapshot_sha256'))
    got = set()
    for r in package.get('receipts') or []:
        ok = (r.get('root') == package.get('root')
              and verify_signature(r.get('signer', ''), req, r.get('signature', '')))
        check(f"receipt_{r.get('signer')}", ok)
        if ok:
            got.add(r.get('signer'))
    required = set(package.get('required_signers') or [])
    check('required_receipts_present', required <= got,
          '' if required <= got else f"missing: {','.join(sorted(required - got))}")
    forks = [e for e in package.get('events') or [] if e.get('kind') in ('fork', 'corruption')]
    check('no_fork_or_corruption', not forks,
          '; '.join(e.get('detail', '')[:80] for e in forks))
    check('status_issued', package.get('status') == 'issued', str(package.get('status')))
    return {'ok': all(c['ok'] for c in checks), 'status': package.get('status'), 'checks': checks}


def _package_markdown(pkg):
    lines = [
        f"# 来源防篡改证明包 {pkg['case_id']}",
        '',
        f"- 策略: `{pkg['policy']}`",
        f"- 状态: **{pkg['status']}**",
        f"- 树大小: {pkg['size']}",
        f"- Merkle 根: `{pkg['root']}`",
        f"- 快照摘要: `{pkg['snapshot_sha256']}`",
        f"- 签发时间: {pkg.get('issued_at') or '未签发'}",
        '',
        '## 来源快照',
        '',
        '| 叶序号 | 类型 | source_id | 原字节 SHA-256(前16) |',
        '|---|---|---|---|',
    ]
    for e in pkg['snapshot']:
        lines.append(f"| {e['seq']} | {e['kind']} | {e['source_id']} | `{e['sha256'][:16]}…` |")
    lines += ['', '## 签收回执', '', '| 签收方 | 根(前16) | 签名(前16) | 时间 |', '|---|---|---|---|']
    if pkg['receipts']:
        for r in pkg['receipts']:
            lines.append(f"| {r['signer']} | `{r['root'][:16]}…` | `{r['signature'][:16]}…` | {r['received_at']} |")
    else:
        lines.append('| (无) |  |  |  |')
    lines += ['', '## 包含证明', '', '| source_id | 叶序号 | 路径长度 |', '|---|---|---|']
    for p in pkg['inclusion_proofs']:
        lines.append(f"| {p['source_id']} | {p['leaf_index']} | {len(p['path'])} |")
    c = pkg['consistency']
    lines += ['', '## 一致性证明', '',
              f"- 旧检查点: {c['old_size']} 叶, 根 `{c['old_root']}`",
              f"- 新检查点: {c['new_size']} 叶, 根 `{c['new_root']}`",
              f"- 证明节点数: {len(c['proof'])}",
              '', '## 分叉/恢复记录', '']
    if pkg['events']:
        for e in pkg['events']:
            lines.append(f"- [{e['at']}] {e['kind']}: {e['detail']}")
    else:
        lines.append('- (无)')
    lines += ['', '## 独立验证命令', '', '```bash']
    lines += pkg['verify_commands']
    lines += ['```', '']
    return '\n'.join(lines)


class SimulatedWitness:
    """Test double for an independent witness.

    An honest witness signs the sign request as-is; ``fork=True``
    simulates a witness that was shown a different tree and signs that
    root instead, which the anchor must reject and record as a fork.
    """

    def __init__(self, witness_id, fork=False):
        self.witness_id = witness_id
        self.fork = fork

    def sign(self, sign_request):
        payload = dict(sign_request)
        if self.fork:
            payload['root'] = sha256(('forked-view:' + payload['root']).encode('utf-8')).hexdigest()
        return {
            'signer': self.witness_id,
            'policy': payload['policy'],
            'size': payload['size'],
            'root': payload['root'],
            'signature': _sign(self.witness_id, payload),
            'payload': payload,
        }
