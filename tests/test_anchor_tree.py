import json
import sqlite3
import threading
import time
from hashlib import sha256
from pathlib import Path

import pytest

from coldhandoff import merkle
from coldhandoff.__main__ import init, main
from coldhandoff.audit_anchor import (
    AnchorError, InjectedFault, SimulatedWitness,
    FAULT_AFTER_FIRST_ACK, FAULT_BEFORE_WITNESS_RECEIPT, FAULT_ROOT_NOT_PERSISTED,
    append_correction, checkpoint, checkpoint_view, consistency_proof, export_package,
    inclusion_proof, record_ack, recover, register,
    verify_consistency_proof, verify_inclusion_proof, verify_package,
)
from coldhandoff.ingest import ingest
from coldhandoff.store import connect

FIXTURES = Path(__file__).parents[1] / 'fixtures'
CONTRACT = FIXTURES / 'anchor-contract.json'


def seeded_db(tmp_path):
    db = tmp_path / 'cold.db'
    for box in ('A', 'B'):
        init(db, 'batch-1', box)
    ingest(FIXTURES / 'source-one.jsonl', db)
    ingest(FIXTURES / 'source-two.jsonl', db)
    assert register(db, CONTRACT) == 'source-anchor-2030-06-09'
    return db


def fake_leaves(n):
    return [merkle.leaf_hash('source', i + 1, sha256(f'bytes-{i}'.encode()).hexdigest()) for i in range(n)]


def add_source(db, name, raw):
    for _ in range(50):
        try:
            con = connect(db)
            with con:
                con.execute('INSERT INTO source_file(name,hash,raw) VALUES (?,?,?)',
                            (name, sha256(raw).hexdigest(), raw))
            con.close()
            return
        except sqlite3.OperationalError:
            time.sleep(0.02)
    raise AssertionError('could not insert source')


# --- Merkle tree unit behaviour -------------------------------------------

def test_empty_tree_semantics():
    assert merkle.root([]) == merkle.EMPTY_ROOT
    assert merkle.verify_consistency(merkle.EMPTY_ROOT, 0, merkle.root(fake_leaves(5)), 5, [])
    assert merkle.verify_consistency(merkle.EMPTY_ROOT, 0, merkle.EMPTY_ROOT, 0, [])
    with pytest.raises(ValueError):
        merkle.inclusion_path([], 0)


def test_single_leaf_tree():
    leaf, = fake_leaves(1)
    assert merkle.root([leaf]) == leaf
    assert merkle.inclusion_path([leaf], 0) == []
    assert merkle.verify_inclusion(leaf, 0, 1, [], leaf)
    assert not merkle.verify_inclusion(leaf, 0, 1, ['0' * 64], leaf)
    assert merkle.verify_consistency(leaf, 1, leaf, 1, [])


def test_leaf_hash_is_domain_separated():
    raw_sha = sha256(b'payload').hexdigest()
    leaf = merkle.leaf_hash('source', 7, raw_sha)
    assert leaf != raw_sha
    assert leaf != merkle.leaf_hash('revoke', 7, raw_sha)
    assert leaf != merkle.leaf_hash('source', 8, raw_sha)  # source id is bound
    assert merkle.node_hash(leaf, leaf) != leaf


@pytest.mark.parametrize('n', list(range(1, 17)) + [31, 32, 33])
def test_inclusion_roundtrip_all_sizes(n):
    leaves = fake_leaves(n)
    root = merkle.root(leaves)
    for i in range(n):
        path = merkle.inclusion_path(leaves, i)
        assert merkle.verify_inclusion(leaves[i], i, n, path, root)
        assert not merkle.verify_inclusion(leaves[i], i, n, path, '0' * 64)
        if n > 1:
            wrong = (i + 1) % n
            assert not merkle.verify_inclusion(leaves[i], wrong, n, path, root)


@pytest.mark.parametrize('n', list(range(1, 20)) + [64])
def test_consistency_roundtrip_all_pairs(n):
    leaves = fake_leaves(n)
    new_root = merkle.root(leaves)
    for m in range(0, n + 1):
        proof = merkle.consistency_proof(leaves, m)
        old_root = merkle.root(leaves[:m])
        assert merkle.verify_consistency(old_root, m, new_root, n, proof), (m, n)
        if m:
            assert not merkle.verify_consistency('0' * 64, m, new_root, n, proof)
        if m < n:
            assert not merkle.verify_consistency(new_root, n, old_root, m, proof)


def test_prefix_replacement_fails_consistency():
    leaves = fake_leaves(3)
    delivered_root = merkle.root(leaves)  # delivered yesterday at size 3
    # attacker drops the first source and recomputes a self-consistent tree
    attacker = leaves[1:] + [merkle.leaf_hash('source', 99, sha256(b'replacement').hexdigest())]
    attacker_root = merkle.root(attacker)
    assert attacker_root != delivered_root
    # same-size claim with empty proof: roots differ, rejected
    assert not merkle.verify_consistency(delivered_root, 3, attacker_root, 3, [])
    # a "proof" built from the attacker's leaves cannot chain to the delivered prefix
    attacker_proof = merkle.consistency_proof(attacker, 2)
    assert not merkle.verify_consistency(merkle.root(leaves[:2]), 2, attacker_root, 3, attacker_proof)
    # the honest append of the same new leaf passes against the delivered root
    honest = leaves + [merkle.leaf_hash('source', 4, sha256(b'replacement').hexdigest())]
    proof = merkle.consistency_proof(honest, 3)
    assert merkle.verify_consistency(delivered_root, 3, merkle.root(honest), 4, proof)


# --- Anchoring over real ingested sources ---------------------------------

def test_register_appends_leaves_in_import_order(tmp_path):
    db = seeded_db(tmp_path)
    con = connect(db)
    sources = [dict(r) for r in con.execute('SELECT id, hash FROM source_file ORDER BY id')]
    leaves = [dict(r) for r in con.execute('SELECT * FROM anchor_leaf ORDER BY seq')]
    con.close()
    assert [l['seq'] for l in leaves] == [0, 1]
    for leaf, source in zip(leaves, sources):
        assert leaf['kind'] == 'source'
        assert leaf['source_id'] == source['id']
        assert leaf['source_sha256'] == source['hash']
        assert leaf['version'] == merkle.LEAF_VERSION
        assert leaf['leaf_hash'] == merkle.leaf_hash('source', source['id'], source['hash'])
        assert leaf['leaf_hash'] != source['hash']  # domain separated


def test_local_signed_checkpoint_issues_immediately(tmp_path):
    db = seeded_db(tmp_path)
    view = checkpoint(db, 'local_signed')
    assert view['status'] == 'issued' and view['size'] == 2
    assert view['issued_at']
    assert [r['signer'] for r in view['receipts']] == ['local']
    # idempotent: re-checkpointing an unchanged tree returns the same root
    assert checkpoint(db, 'local_signed')['root'] == view['root']
    pkg = export_package(db, 2, 'local_signed', tmp_path / 'local.json')
    result = verify_package(pkg)
    assert result['ok'], result
    assert (tmp_path / 'local.md').exists()


def test_dual_witness_checkpoint_needs_both_witnesses(tmp_path):
    db = seeded_db(tmp_path)
    local = checkpoint(db, 'local_signed')
    dual = checkpoint(db, 'dual_witness')
    assert dual['status'] == 'pending' and dual['root'] == local['root']
    req = dual['sign_request']
    assert record_ack(db, SimulatedWitness('W1').sign(req))['accepted']
    assert checkpoint_view(db, 2, 'dual_witness')['status'] == 'pending'
    assert record_ack(db, SimulatedWitness('W2').sign(req))['issued']
    local_pkg = export_package(db, 2, 'local_signed', tmp_path / 'local.json')
    dual_pkg = export_package(db, 2, 'dual_witness', tmp_path / 'dual.json')
    # two real packages over the same original bytes: same root/snapshot,
    # different trust subjects, receipts and publication moments
    assert local_pkg['root'] == dual_pkg['root']
    assert local_pkg['snapshot_sha256'] == dual_pkg['snapshot_sha256']
    assert local_pkg['required_signers'] == ['local']
    assert dual_pkg['required_signers'] == ['W1', 'W2']
    assert {r['signer'] for r in dual_pkg['receipts']} == {'W1', 'W2'}
    assert local_pkg['issued_at'] and dual_pkg['issued_at']
    assert verify_package(local_pkg)['ok']
    assert verify_package(dual_pkg)['ok']


def test_second_witness_fork_stays_pending_and_local_package_intact(tmp_path):
    db = seeded_db(tmp_path)
    local = checkpoint(db, 'local_signed')
    dual = checkpoint(db, 'dual_witness')
    req = dual['sign_request']
    assert record_ack(db, SimulatedWitness('W1').sign(req))['accepted']
    forked = record_ack(db, SimulatedWitness('W2', fork=True).sign(req))
    assert not forked['accepted'] and forked['fork']
    assert checkpoint_view(db, 2, 'dual_witness')['status'] == 'forked'
    dual_pkg = export_package(db, 2, 'dual_witness', tmp_path / 'dual.json')
    assert dual_pkg['status'] == 'pending_verification'
    assert any(e['kind'] == 'fork' for e in dual_pkg['events'])
    result = verify_package(dual_pkg)
    assert not result['ok']
    failed = {c['name'] for c in result['checks'] if not c['ok']}
    assert {'required_receipts_present', 'no_fork_or_corruption', 'status_issued'} <= failed
    # the local package delivered earlier still verifies with its original root
    local_pkg = export_package(db, 2, 'local_signed', tmp_path / 'local.json')
    assert local_pkg['root'] == local['root']
    assert verify_package(local_pkg)['ok']


def test_conflicting_same_number_signature_rejected_then_next_checkpoint(tmp_path):
    db = seeded_db(tmp_path)
    dual = checkpoint(db, 'dual_witness')
    req = dual['sign_request']
    assert record_ack(db, SimulatedWitness('W1').sign(req))['accepted']
    # a retry bound to a different root for the same checkpoint number is rejected
    bad = record_ack(db, SimulatedWitness('W1', fork=True).sign(req))
    assert not bad['accepted'] and bad['fork']
    assert checkpoint_view(db, 2, 'dual_witness')['status'] == 'forked'
    # recovery may open the next checkpoint, never rewrite the forked one
    add_source(db, 'third.jsonl', b'{"kind":"dispatch"}')
    nxt = checkpoint(db, 'dual_witness')
    assert nxt['size'] == 3 and nxt['status'] == 'pending'
    assert record_ack(db, SimulatedWitness('W1').sign(nxt['sign_request']))['accepted']
    assert record_ack(db, SimulatedWitness('W2').sign(nxt['sign_request']))['issued']
    con = connect(db)
    rows = con.execute('SELECT size, COUNT(DISTINCT root) FROM anchor_checkpoint GROUP BY size').fetchall()
    con.close()
    assert all(r[1] == 1 for r in rows)  # no two conflicting histories at one number
    assert verify_consistency_proof(consistency_proof(db, 2, 3))


def test_late_ack_binds_original_root_after_newer_sources(tmp_path):
    db = seeded_db(tmp_path)
    dual = checkpoint(db, 'dual_witness')  # size 2
    add_source(db, 'late.jsonl', b'{"kind":"arrival"}')
    local3 = checkpoint(db, 'local_signed')  # tree grows to 3 before receipts arrive
    assert local3['size'] == 3 and local3['root'] != dual['root']
    assert record_ack(db, SimulatedWitness('W1').sign(dual['sign_request']))['accepted']
    assert record_ack(db, SimulatedWitness('W2').sign(dual['sign_request']))['issued']
    again = checkpoint_view(db, 2, 'dual_witness')
    assert again['root'] == dual['root'] and again['status'] == 'issued'
    proof = consistency_proof(db, 2, 3)
    assert proof['old_root'] == dual['root'] and proof['new_root'] == local3['root']
    assert verify_consistency_proof(proof)


# --- Crash injection and recovery ------------------------------------------

def test_fault_after_root_computed_before_persist(tmp_path):
    db = seeded_db(tmp_path)
    with pytest.raises(InjectedFault):
        checkpoint(db, 'local_signed', fault_at=FAULT_ROOT_NOT_PERSISTED)
    con = connect(db)
    assert con.execute('SELECT COUNT(*) FROM anchor_checkpoint').fetchone()[0] == 0
    con.close()
    assert recover(db)['resumed_sign_requests'] == []
    view = checkpoint(db, 'local_signed')  # restart recomputes the same root
    assert view['status'] == 'issued' and view['size'] == 2


def test_fault_after_checkpoint_persist_before_witness_receipt(tmp_path):
    db = seeded_db(tmp_path)
    with pytest.raises(InjectedFault):
        checkpoint(db, 'dual_witness', fault_at=FAULT_BEFORE_WITNESS_RECEIPT)
    con = connect(db)
    row = con.execute("SELECT status, size FROM anchor_checkpoint WHERE policy='dual_witness'").fetchone()
    con.close()
    assert row['status'] == 'pending' and row['size'] == 2
    resumed = recover(db)['resumed_sign_requests']
    assert len(resumed) == 1 and resumed[0]['size'] == 2
    assert record_ack(db, SimulatedWitness('W1').sign(resumed[0]))['accepted']
    assert record_ack(db, SimulatedWitness('W2').sign(resumed[0]))['issued']


def test_fault_crash_after_first_witness_ack(tmp_path):
    db = seeded_db(tmp_path)
    req = checkpoint(db, 'dual_witness')['sign_request']
    with pytest.raises(InjectedFault):
        record_ack(db, SimulatedWitness('W1').sign(req), fault_at=FAULT_AFTER_FIRST_ACK)
    resumed = recover(db)['resumed_sign_requests']
    assert len(resumed) == 1  # W1 receipt survived the crash, still pending
    dup = record_ack(db, SimulatedWitness('W1').sign(req))  # delayed duplicate retry
    assert dup['accepted'] and dup['duplicate']
    assert record_ack(db, SimulatedWitness('W2').sign(req))['issued']


# --- Append-only structure --------------------------------------------------

def test_correction_appends_revocation_leaf_without_rewriting(tmp_path):
    db = seeded_db(tmp_path)
    before = checkpoint(db, 'local_signed')
    old_proof = inclusion_proof(db, 1)
    con = connect(db)
    old_leaf = dict(con.execute('SELECT * FROM anchor_leaf WHERE seq=0').fetchone())
    con.close()
    correction = append_correction(db, 1, 'device mislabeled; source superseded')
    assert correction['seq'] == 2 and correction['kind'] == 'revoke'
    sup = append_correction(db, 2, 'replaced by re-import',
                            replacement={'source_id': 2, 'sha256': old_leaf['source_sha256']})
    assert sup['kind'] == 'supersede' and sup['seq'] == 3
    after = checkpoint(db, 'local_signed')
    assert after['size'] == 4 and after['root'] != before['root']
    con = connect(db)
    assert dict(con.execute('SELECT * FROM anchor_leaf WHERE seq=0').fetchone()) == old_leaf
    con.close()
    assert verify_inclusion_proof(old_proof)  # old root still proves the old leaf
    new_proof = inclusion_proof(db, 1)
    assert new_proof['tree_size'] == 4 and verify_inclusion_proof(new_proof)
    assert verify_consistency_proof(consistency_proof(db, 2, 4))


def test_duplicate_bytes_different_source_ids(tmp_path):
    db = seeded_db(tmp_path)
    con = connect(db)
    sha1 = con.execute('SELECT hash FROM source_file WHERE id=1').fetchone()[0]
    con.close()
    # identical bytes re-imported under a new, non-reusable source id are
    # anchored as a supersede leaf: same original bytes, different source id
    append_correction(db, 1, 'identical bytes re-imported as source 3',
                      replacement={'source_id': 3, 'sha256': sha1})
    view = checkpoint(db, 'local_signed')
    assert view['size'] == 3  # non-power-of-two tree
    con = connect(db)
    leaves = [dict(r) for r in con.execute('SELECT * FROM anchor_leaf ORDER BY seq')]
    con.close()
    assert leaves[0]['source_sha256'] == leaves[2]['source_sha256']  # same original bytes
    assert leaves[0]['source_id'] != leaves[2]['source_id']
    assert leaves[0]['leaf_hash'] != leaves[2]['leaf_hash']          # source id is bound
    hashes = [l['leaf_hash'] for l in leaves]
    root = merkle.root(hashes)
    for i, leaf in enumerate(leaves):
        assert merkle.verify_inclusion(leaf['leaf_hash'], i, 3, merkle.inclusion_path(hashes, i), root)
    assert verify_inclusion_proof(inclusion_proof(db, 1))


def test_concurrent_imports_never_share_a_leaf_position(tmp_path):
    db = seeded_db(tmp_path)
    barrier = threading.Barrier(5)
    errors = []

    def worker(i):
        try:
            barrier.wait(timeout=10)
            add_source(db, f'extra-{i}.jsonl', f'extra-source-{i}'.encode())
            checkpoint(db, 'local_signed')
        except Exception as exc:  # noqa: BLE001 - collected and asserted below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    barrier.wait(timeout=10)
    for t in threads:
        t.join(30)
    assert not errors
    con = connect(db)
    seqs = [r[0] for r in con.execute('SELECT seq FROM anchor_leaf ORDER BY seq')]
    assert seqs == list(range(6))  # persistent sequence, no shared/lost positions
    roots = {}
    for size, root in con.execute('SELECT size, root FROM anchor_checkpoint'):
        assert roots.setdefault(size, root) == root  # one root per checkpoint number
    leaves = [r[0] for r in con.execute('SELECT leaf_hash FROM anchor_leaf ORDER BY seq')]
    con.close()
    assert merkle.root(leaves) == checkpoint(db, 'local_signed')['root']
    ordered = sorted(roots)
    for old, new in zip(ordered, ordered[1:]):
        assert verify_consistency_proof(consistency_proof(db, old, new))


def test_out_of_order_and_truncated_proofs_are_rejected(tmp_path):
    db = seeded_db(tmp_path)
    add_source(db, 'third.jsonl', b'third')
    checkpoint(db, 'local_signed')  # size 3, non-power-of-two
    proof = inclusion_proof(db, 1)
    assert proof['tree_size'] == 3 and len(proof['path']) == 2
    assert verify_inclusion_proof(proof)
    assert not verify_inclusion_proof({**proof, 'path': list(reversed(proof['path']))})
    assert not verify_inclusion_proof({**proof, 'path': proof['path'][:-1]})
    assert not verify_inclusion_proof({**proof, 'path': proof['path'] + [proof['path'][0]]})
    assert not verify_inclusion_proof({**proof, 'root': '0' * 64})
    assert not verify_inclusion_proof({**proof, 'leaf_index': 1})
    cons = consistency_proof(db, 2, 3)
    assert verify_consistency_proof(cons)
    assert not verify_consistency_proof({**cons, 'proof': cons['proof'][:-1]})
    assert not verify_consistency_proof({**cons, 'proof': cons['proof'] + [cons['proof'][0]]})
    assert not verify_consistency_proof({**cons, 'old_root': '0' * 64})
    assert not verify_consistency_proof({**cons, 'new_root': '0' * 64})


def test_deleted_leaf_breaks_delivered_checkpoint_verification(tmp_path):
    db = seeded_db(tmp_path)
    delivered = checkpoint(db, 'local_signed')
    con = connect(db)
    with con:
        con.execute('DELETE FROM anchor_leaf WHERE seq=0')  # drop the first source leaf
    con.close()
    with pytest.raises(AnchorError):
        checkpoint(db, 'local_signed')
    recovery = recover(db)
    assert recovery['corrupted'] == ['2/local_signed']
    con = connect(db)
    assert con.execute("SELECT COUNT(*) FROM anchor_event WHERE kind='corruption'").fetchone()[0] >= 1
    # the delivered root is never rewritten to match the tampered store
    assert con.execute('SELECT root FROM anchor_checkpoint WHERE size=2').fetchone()[0] == delivered['root']
    con.close()


def test_export_chains_consistency_from_previous_checkpoint(tmp_path):
    db = seeded_db(tmp_path)
    first = checkpoint(db, 'local_signed')
    add_source(db, 'third.jsonl', b'third')
    second = checkpoint(db, 'local_signed')
    assert (first['size'], second['size']) == (2, 3)
    pkg = export_package(db, 3, 'local_signed', tmp_path / 'pkg.json')
    assert pkg['consistency']['old_size'] == 2
    assert pkg['consistency']['old_root'] == first['root']
    assert verify_package(pkg)['ok']
    md = (tmp_path / 'pkg.md').read_text(encoding='utf-8')
    assert second['root'] in md and '一致性证明' in md and '签收回执' in md


def test_unknown_source_and_checkpoint_errors(tmp_path):
    db = seeded_db(tmp_path)
    with pytest.raises(AnchorError):
        inclusion_proof(db, 99)
    with pytest.raises(AnchorError):
        export_package(db, 7, 'local_signed', tmp_path / 'nope.json')
    assert record_ack(db, {'signer': 'W1', 'size': 9, 'policy': 'dual_witness',
                           'root': '0' * 64, 'signature': 'x',
                           'payload': {'size': 9, 'policy': 'dual_witness', 'root': '0' * 64}})['reason'] == 'unknown_checkpoint'
    with pytest.raises(AnchorError):
        append_correction(db, 99, 'no such source')


def test_checkpoint_requires_registered_case(tmp_path):
    db = tmp_path / 'empty.db'
    init(db, 'b', 'x')
    with pytest.raises(AnchorError):
        checkpoint(db, 'local_signed')


# --- CLI end to end ----------------------------------------------------------

def test_cli_anchor_end_to_end(tmp_path, capsys):
    db = seeded_db(tmp_path)
    capsys.readouterr()
    main(['anchor-checkpoint', '--db', str(db), '--policy', 'dual_witness'])
    req = json.loads(capsys.readouterr().out)['sign_request']
    req_file = tmp_path / 'req.json'
    req_file.write_text(json.dumps(req), encoding='utf-8')
    for witness in ('W1', 'W2'):
        ack = tmp_path / f'ack-{witness}.json'
        main(['anchor-witness', '--request', str(req_file), '--witness', witness, '--out', str(ack)])
        main(['anchor-ack', '--db', str(db), '--ack', str(ack)])
        capsys.readouterr()
    pkg = tmp_path / 'pkg.json'
    main(['anchor-export', '--db', str(db), '--size', '2', '--policy', 'dual_witness', '--out', str(pkg)])
    capsys.readouterr()
    main(['anchor-verify-package', str(pkg)])
    assert json.loads(capsys.readouterr().out)['ok']
    assert (tmp_path / 'pkg.md').exists()
    inc = tmp_path / 'inc.json'
    main(['anchor-inclusion', '--db', str(db), '--source-id', '1', '--out', str(inc)])
    capsys.readouterr()
    main(['anchor-verify-inclusion', str(inc)])
    assert json.loads(capsys.readouterr().out)['ok']
    cons = tmp_path / 'cons.json'
    main(['anchor-consistency', '--db', str(db), '--old-size', '0', '--out', str(cons)])
    capsys.readouterr()
    main(['anchor-verify-consistency', str(cons)])
    assert json.loads(capsys.readouterr().out)['ok']
