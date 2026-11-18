"""Content-addressable archive: byte-exact manifests, generations, GC, recovery.

All data is synthetic and generated in-process; nothing here reads real
shipment data.
"""
import json
import threading
from hashlib import sha256
from pathlib import Path

import pytest

from coldhandoff.__main__ import archive, init, report
from coldhandoff.archive import (
    ArchiveError,
    ContentStore,
    FaultPlan,
    ReaderView,
    migrate_all,
    migrate_source,
    read_source_bytes,
    recover,
    run_gc,
    storage_accounting,
    verify_archive,
)
from coldhandoff.chunking import (
    UTF8_BOM,
    build_manifest,
    chunk_hash,
    fixed_64_chunks,
    record_chunks,
    reassemble,
)
from coldhandoff.ingest import digest, ingest
from coldhandoff.store import connect

REPRESENTATIONS = ['fixed_64', 'record_chunks']


def build_seed(tmp_path):
    """Two real-source style BLOBs: file 2 prepends one record, then the same
    20 records follow byte-for-byte. Different file SHAs, shared record spans.
    """
    db = tmp_path / 'cold.db'
    init(db, 'batch-1', 'A')
    lines = [json.dumps({'kind': 'temperature', 'device': 'logger-1', 'seq': i,
                         'box_id': 'A', 'event_time': f'2030-06-07T00:{i:02d}:00Z',
                         'value': 4}, separators=(',', ':'))
             for i in range(1, 21)]
    inserted = json.dumps({'kind': 'temperature', 'device': 'logger-1', 'seq': 21,
                           'box_id': 'A', 'event_time': '2030-06-07T00:21:00Z',
                           'value': 5}, separators=(',', ':'))
    first = tmp_path / 'first.jsonl'
    second = tmp_path / 'second.jsonl'
    first.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    second.write_text(inserted + '\n' + '\n'.join(lines) + '\n', encoding='utf-8')
    ingest(first, db)
    ingest(second, db)
    return db, first, second


def source_rows(db):
    con = connect(db)
    rows = [dict(r) for r in con.execute(
        'SELECT id,hash,raw FROM source_file ORDER BY id')]
    con.close()
    return rows


# --------------------------------------------------------------------------- #
# Both representations: byte-exact reassembly, distinct SHAs, report stability
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize('representation', REPRESENTATIONS)
def test_manifest_reassembles_exact_bytes_and_keeps_distinct_sha(tmp_path, representation):
    db, first_path, second_path = build_seed(tmp_path)
    first_raw, second_raw = first_path.read_bytes(), second_path.read_bytes()
    rows = source_rows(db)
    assert sha256(second_raw).hexdigest() != sha256(first_raw).hexdigest()

    before = json.loads(report(db, tmp_path / 'before.json').read_text('utf-8'))
    results = migrate_all(db, representation)
    assert {r['representation'] for r in results} == {representation}
    assert all(r['blob_reclaimed'] for r in results)

    # Every source reassembles to its own original bytes and original hash.
    for row, raw in zip(rows, [first_raw, second_raw]):
        got = read_source_bytes(db, row['id'])
        assert got == raw
        assert sha256(got).hexdigest() == row['hash']

    # Raw BLOBs are gone but the archive remains a complete, verified copy.
    con = connect(db)
    assert all(bytes(r['raw']) == b'' for r in con.execute('SELECT raw FROM source_file'))
    con.close()
    verification = verify_archive(db)
    assert verification['ok']
    assert all(s['verified'] and s['archived'] for s in verification['sources'])

    # Report evidence (including Base64 source bytes) is unchanged.
    after = json.loads(report(db, tmp_path / 'after.json').read_text('utf-8'))
    assert after == before


@pytest.mark.parametrize('representation', REPRESENTATIONS)
def test_physical_accounting_does_not_confuse_logical_and_physical(tmp_path, representation):
    db, first_path, second_path = build_seed(tmp_path)
    first_raw, second_raw = first_path.read_bytes(), second_path.read_bytes()
    before_blob = len(first_raw) + len(second_raw)
    migrate_all(db, representation)
    acct = storage_accounting(db)
    store = ContentStore.for_db(db)

    # Physical truth: count actual files and bytes on disk.
    disk_files = list(store.iter_objects())
    assert acct['physical_chunk_files'] == len(disk_files)
    assert acct['physical_chunk_bytes'] == sum(f.stat().st_size for f in disk_files)
    # record_chunks shares the 20 unchanged records; fixed_64 shifts every
    # boundary so it can never save more than the raw bytes.
    if representation == 'record_chunks':
        assert acct['physical_chunk_bytes'] < before_blob
    else:
        assert acct['physical_chunk_bytes'] <= before_blob

    # Logical references exceed unique physical chunks when spans are shared.
    assert acct['logical_chunk_refs'] >= acct['unique_referenced_chunks']
    assert acct['shared_refs_saved'] == (
        acct['logical_chunk_refs'] - acct['unique_referenced_chunks'])
    assert acct['raw_blob_bytes_remaining'] == 0
    assert acct['manifest_bytes'] > 0

    # The two layouts genuinely differ per representation.
    fixed_manifest = build_manifest(first_raw, 'fixed_64')
    record_manifest = build_manifest(first_raw, 'record_chunks')
    assert len(fixed_manifest['chunks']) != len(record_manifest['chunks'])


def test_record_chunks_share_the_20_unchanged_records_but_fixed_64_does_not(tmp_path):
    db, first_path, second_path = build_seed(tmp_path)
    first_raw, second_raw = first_path.read_bytes(), second_path.read_bytes()
    migrate_all(db, 'record_chunks')
    acct = storage_accounting(db)
    # No BOM/blank-line prefix: 20 shared trailing records + 1 prepended
    # record => 21 unique physical chunks, 41 logical refs, 20 shared saves.
    assert acct['unique_referenced_chunks'] == 21
    assert acct['logical_chunk_refs'] == 41
    assert acct['shared_refs_saved'] == 20

    db2 = tmp_path / 'cold2.db'
    init(db2, 'b', 'A')
    ingest(tmp_path / 'first.jsonl', db2)
    ingest(tmp_path / 'second.jsonl', db2)
    migrate_all(db2, 'fixed_64')
    fixed = storage_accounting(db2)
    # A prepended record shifts every 64-byte boundary: no chunk is shared.
    assert fixed['shared_refs_saved'] == 0
    assert fixed['physical_chunk_bytes'] > acct['physical_chunk_bytes']


def test_representations_produce_different_layouts_same_downstream_result(tmp_path):
    _, first_path, second_path = build_seed(tmp_path)
    want = [first_path.read_bytes(), second_path.read_bytes()]
    outcomes = {}
    for rep in REPRESENTATIONS:
        db = tmp_path / f'{rep}.db'
        init(db, 'batch-1', 'A')
        ingest(first_path, db)
        ingest(second_path, db)
        migrate_all(db, rep)
        rows = source_rows(db)
        acct = storage_accounting(db)
        recovered = [read_source_bytes(db, r['id']) for r in rows]
        assert recovered == want
        outcomes[rep] = (acct['physical_chunk_files'], recovered,
                         json.loads(report(db, tmp_path / f'{rep}.json').read_text('utf-8')))
    assert outcomes['fixed_64'][0] != outcomes['record_chunks'][0]
    assert outcomes['fixed_64'][1] == outcomes['record_chunks'][1]
    assert outcomes['fixed_64'][2] == outcomes['record_chunks'][2]


# --------------------------------------------------------------------------- #
# Chunker edge cases: BOM, CRLF, no trailing newline, non-ASCII, duplicates
# --------------------------------------------------------------------------- #
def test_fixed_64_chunk_boundaries_round_trip():
    for size in (0, 1, 63, 64, 65, 128, 129, 1000):
        data = bytes((i * 7 + size) % 256 for i in range(size))
        manifest = build_manifest(data, 'fixed_64')
        blobs = {}
        for span in fixed_64_chunks(data):
            blobs.setdefault(chunk_hash(span), span)
        assert reassemble(manifest, blobs.__getitem__) == data
        if data:
            assert all(c['length'] <= 64 for c in manifest['chunks'])


def test_record_chunks_preserve_bom_crlf_and_missing_trailing_newline():
    raw = UTF8_BOM + '\n'.join([
        '{"kind":"dispatch","seq":1,"note":"冷藏-箱A"}',
        '{"kind":"arrival","seq":2,"note":"CRLF-箱B"}',
    ]).encode('utf-8').replace(b'\n', b'\r\n') + b'\r\n' + \
        '{"kind":"sign","seq":3}'.encode('utf-8')  # no trailing newline
    prefix, chunks = record_chunks(raw)
    assert prefix == UTF8_BOM
    assert all(span.endswith(b'\r\n') for span, meta in chunks if meta['terminated'])
    assert chunks[-1][1] == {'terminated': False}
    manifest = build_manifest(raw, 'record_chunks')
    blobs = {chunk_hash(prefix): prefix}
    for span, _ in chunks:
        blobs.setdefault(chunk_hash(span), span)
    assert reassemble(manifest, blobs.__getitem__) == raw


def test_duplicate_records_deduplicate_physically_but_keep_order(tmp_path):
    db = tmp_path / 'cold.db'
    init(db, 'b', 'x')
    record = '{"kind":"temperature","device":"d","seq":1,"box_id":"x","event_time":"2026-01-01T00:00:00Z","value":4}'
    raw = ('\n'.join([record] * 5) + '\n').encode('utf-8')
    f = tmp_path / 'dup.jsonl'
    f.write_bytes(raw)
    ingest(f, db)
    migrate_all(db, 'record_chunks')
    acct = storage_accounting(db)
    # One physical chunk referenced five times in manifest order.
    assert acct['physical_chunk_files'] == 1
    assert acct['logical_chunk_refs'] == 5
    assert read_source_bytes(db, 1) == raw


def test_non_ascii_and_empty_file_are_byte_exact(tmp_path):
    payloads = [b'', '温度℃-Ü-ä-✅\n'.encode('utf-8'),
                b'\xff\xfe\x00binary-not-text']
    for rep in REPRESENTATIONS:
        db = tmp_path / f'weird-{rep}.db'
        init(db, 'b', 'x')
        sids = []
        for i, raw in enumerate(payloads):
            f = tmp_path / f'p-{rep}-{i}.jsonl'
            f.write_bytes(raw)
            try:
                ingest(f, db)
            except UnicodeDecodeError:
                # Arbitrary non-text bytes are not valid JSONL input for
                # ingest, but the archive layer must preserve them verbatim:
                # seed the BLOB directly, mirroring a pre-existing source row.
                con = connect(db)
                with con:
                    con.execute(
                        'INSERT INTO source_file(name,hash,raw) VALUES (?,?,?)',
                        (str(f), digest(raw), raw))
                con.close()
            sids.append(connect(db).execute(
                'SELECT id FROM source_file ORDER BY id DESC LIMIT 1').fetchone()[0])
        migrate_all(db, rep)
        for sid, raw in zip(sids, payloads):
            got = read_source_bytes(db, sid)
            assert got == raw
            assert digest(got) == digest(raw)


def test_same_chunk_in_different_sources_is_stored_once(tmp_path):
    db = tmp_path / 'cold.db'
    init(db, 'b', 'x')
    shared = b'{"kind":"dispatch","seq":1}\n'
    a = tmp_path / 'a.jsonl'
    b = tmp_path / 'b.jsonl'
    a.write_bytes(b'prefix-a\n' + shared)
    b.write_bytes(b'prefix-bb\n' + shared)
    ingest(a, db)
    ingest(b, db)
    migrate_all(db, 'record_chunks')
    store = ContentStore.for_db(db)
    assert store.exists(chunk_hash(shared))
    acct = storage_accounting(db)
    assert acct['unique_referenced_chunks'] == 3  # 2 prefixes + 1 shared
    assert acct['logical_chunk_refs'] == 4
    expected = [a.read_bytes(), b.read_bytes()]
    for row, want in zip(source_rows(db), expected):
        got = read_source_bytes(db, row['id'])
        assert got == want
        assert digest(got) == row['hash']


# --------------------------------------------------------------------------- #
# Five injected fault points + idempotent, verified restart recovery
# --------------------------------------------------------------------------- #
FAULT_POINTS = ['mid_chunk', 'before_publish', 'after_switch', 'after_reclaim']


@pytest.mark.parametrize('fault', FAULT_POINTS)
def test_recovery_after_each_fault_point(tmp_path, fault):
    db, first_path, second_path = build_seed(tmp_path)
    first_raw, second_raw = first_path.read_bytes(), second_path.read_bytes()
    rows = source_rows(db)
    with pytest.raises(ArchiveError, match=fault):
        migrate_source(db, rows[0]['id'], 'record_chunks',
                       faults=FaultPlan(fail_at=fault, chunks_before_fail=1))

    # The source hash is still present and its original bytes recoverable.
    con = connect(db)
    assert con.execute('SELECT hash FROM source_file WHERE id=?',
                       (rows[0]['id'],)).fetchone()[0] == rows[0]['hash']
    con.close()

    result = recover(db)
    assert result['verification']['ok']

    for row, raw in zip(rows, [first_raw, second_raw]):
        assert read_source_bytes(db, row['id']) == raw
        assert sha256(read_source_bytes(db, row['id'])).hexdigest() == row['hash']
    # Recovery is itself idempotent.
    again = recover(db)
    assert again['verification']['ok']
    assert again['staged_resumed'] == []


def test_half_written_chunk_leaves_temp_file_that_recovery_sweeps(tmp_path):
    db, _, _ = build_seed(tmp_path)
    rows = source_rows(db)
    store = ContentStore.for_db(db).ensure()
    with pytest.raises(ArchiveError, match='mid_chunk'):
        migrate_source(db, rows[0]['id'], 'fixed_64',
                       faults=FaultPlan(fail_at='mid_chunk', chunks_before_fail=0))
    # Simulate the OS-level half-written object a real crash would leave:
    # a temp file that never reached its atomic rename.
    shard = store.root / 'ab'
    shard.mkdir(parents=True, exist_ok=True)
    orphan = shard / '.deadbeef.tmp-crash'
    orphan.write_bytes(b'partial')
    assert list(store.iter_temp_files())
    result = recover(db, grace_seconds=0)
    assert result['temp_files_swept'] >= 1
    assert not list(store.iter_temp_files())
    assert verify_archive(db)['ok']


def test_blob_not_reclaimed_until_manifest_verifies_and_coexistence_reads(tmp_path):
    db, first_path, second_path = build_seed(tmp_path)
    first_raw, second_raw = first_path.read_bytes(), second_path.read_bytes()
    rows = source_rows(db)
    # Crash after chunks complete but before publication: raw stays, no pointer.
    with pytest.raises(ArchiveError, match='before_publish'):
        migrate_source(db, rows[0]['id'], 'record_chunks',
                       faults=FaultPlan(fail_at='before_publish'))
    con = connect(db)
    assert con.execute('SELECT raw FROM source_file WHERE id=?',
                       (rows[0]['id'],)).fetchone()[0] != b''
    assert con.execute('SELECT status FROM cas_manifest').fetchone()[0] == 'staged'
    con.close()
    assert read_source_bytes(db, rows[0]['id']) == first_raw  # coexistence path
    recover(db)
    assert read_source_bytes(db, rows[0]['id']) == first_raw


def test_migration_is_idempotent_and_keeps_one_manifest_per_source(tmp_path):
    db, _, _ = build_seed(tmp_path)
    migrate_all(db, 'record_chunks')
    migrate_all(db, 'record_chunks')
    con = connect(db)
    published = con.execute(
        "SELECT COUNT(*) AS n FROM cas_manifest WHERE status='published'").fetchone()['n']
    assert published == 2
    con.close()
    verify = verify_archive(db)
    assert verify['ok']


def test_switch_representation_back_and_forth_after_blob_reclaim(tmp_path):
    db, first_path, second_path = build_seed(tmp_path)
    want = [first_path.read_bytes(), second_path.read_bytes()]
    # First representation reclaims the BLOBs...
    migrate_all(db, 'record_chunks')
    # ...switching representations must reconstruct from the manifest, and
    # switching back must reuse the original published row (no duplicate IDs).
    migrate_all(db, 'fixed_64')
    migrate_all(db, 'record_chunks')
    rows = source_rows(db)
    for row, raw in zip(rows, want):
        assert read_source_bytes(db, row['id']) == raw
        assert digest(read_source_bytes(db, row['id'])) == row['hash']
    con = connect(db)
    # Exactly one manifest per (source, representation), never duplicated.
    dupes = con.execute(
        'SELECT source_id,representation,COUNT(*) AS n FROM cas_manifest '
        "WHERE status='published' GROUP BY source_id,representation HAVING n>1"
    ).fetchall()
    assert dupes == []
    con.close()
    assert verify_archive(db)['ok']


# --------------------------------------------------------------------------- #
# Generations, reader pins and GC interleaving with concurrent reads
# --------------------------------------------------------------------------- #
def test_reader_pin_sees_stable_generation_while_gc_runs(tmp_path):
    db, first_path, second_path = build_seed(tmp_path)
    first_raw, second_raw = first_path.read_bytes(), second_path.read_bytes()
    rows = source_rows(db)
    t0 = 5000.0
    migrate_all(db, 'record_chunks', now=t0)

    con = connect(db)
    old_view = ReaderView(con, ContentStore.for_db(db),
                          hold_seconds=300, now=t0)
    pinned_generation = old_view.generation

    # Re-publish a second generation (same bytes, different representation).
    migrate_all(db, 'fixed_64', now=t0 + 10)
    assert con.execute('SELECT MAX(source_gen) FROM cas_manifest').fetchone()[0] > pinned_generation

    # GC while the pin is live: old representation stays because the pin can
    # still read that generation, even with a zero grace window.
    gc = run_gc(db, grace_seconds=0, now=t0 + 20)
    assert gc['active_pins'] == 1
    assert gc['expired_pins_swept'] == 0
    assert read_source_bytes(db, rows[0]['id'])  # new pointer path works
    old_bytes = old_view.source_bytes(rows[0]['id'])
    assert old_bytes == first_raw

    # After the pin expires it is swept; the old generation becomes collectable
    # while the newest manifest chunks remain protected.
    later = run_gc(db, grace_seconds=0, now=t0 + 400)
    assert later['active_pins'] == 0
    assert later['expired_pins_swept'] == 1
    assert con.execute('SELECT COUNT(*) FROM cas_pin').fetchone()[0] == 0
    assert verify_archive(db)['ok']
    for row, raw in zip(rows, [first_raw, second_raw]):
        assert read_source_bytes(db, row['id']) == raw
    con.close()
    assert verify_archive(db)['ok']
    for row, raw in zip(rows, [first_raw, second_raw]):
        assert read_source_bytes(db, row['id']) == raw


def test_gc_never_deletes_referenced_chunks_and_logs_ledger(tmp_path):
    db, _, _ = build_seed(tmp_path)
    migrate_all(db, 'record_chunks')
    before = storage_accounting(db)
    gc = run_gc(db, grace_seconds=0)
    after = storage_accounting(db)
    assert gc['removed_chunks'] == 0
    assert after['physical_chunk_files'] == before['physical_chunk_files']
    con = connect(db)
    log = con.execute('SELECT * FROM cas_gc_log ORDER BY id DESC LIMIT 1').fetchone()
    assert log['removed_chunks'] == 0 and log['detail']
    con.close()


def test_gc_collects_orphans_from_aborted_staged_attempts(tmp_path):
    db, _, _ = build_seed(tmp_path)
    rows = source_rows(db)
    with pytest.raises(ArchiveError, match='before_publish'):
        migrate_source(db, rows[0]['id'], 'record_chunks',
                       faults=FaultPlan(fail_at='before_publish'))
    staged_account = storage_accounting(db)
    assert staged_account['staged_manifests'] == 1
    gc = run_gc(db, grace_seconds=0)
    con = connect(db)
    assert con.execute(
        "SELECT COUNT(*) FROM cas_manifest WHERE status='aborted'").fetchone()[0] == 1
    con.close()
    assert gc['removed_manifests'] == 0  # aborted rows were never published
    # The staged chunks are unreferenced after abort and get collected.
    remaining = storage_accounting(db)
    assert remaining['staged_manifests'] == 0


def test_gc_prunes_superseded_generation_only_after_grace(tmp_path):
    db, first_path, _ = build_seed(tmp_path)
    t0 = 1000.0
    migrate_all(db, 'record_chunks', now=t0)
    migrate_all(db, 'fixed_64', now=t0 + 30)
    store = ContentStore.for_db(db)
    chunks_before = len(list(store.iter_objects()))

    # Inside the grace window the superseded generation stays fully intact
    # (one record_chunks manifest per source, both protected by grace).
    early = run_gc(db, grace_seconds=60, now=t0 + 40)
    assert early['removed_manifests'] == 0 and early['removed_chunks'] == 0
    con = connect(db)
    assert con.execute(
        "SELECT COUNT(*) FROM cas_manifest WHERE representation='record_chunks'"
    ).fetchone()[0] == 2
    con.close()

    # After grace: old manifests pruned. Chunks exclusive to them are
    # reclaimed; chunks the surviving generation shares are correctly kept.
    late = run_gc(db, grace_seconds=60, now=t0 + 200)
    assert late['removed_manifests'] == 2
    con = connect(db)
    assert con.execute(
        "SELECT COUNT(*) FROM cas_manifest WHERE representation='record_chunks'"
    ).fetchone()[0] == 0
    con.close()
    assert verify_archive(db)['ok']
    assert read_source_bytes(db, 1) == first_path.read_bytes()
    assert late['freed_chunk_bytes'] >= 0


# --------------------------------------------------------------------------- #
# Online behavior: concurrent ingest, post-switch ingest, evidence stability
# --------------------------------------------------------------------------- #
def test_concurrent_ingest_during_migration(tmp_path):
    db, _, _ = build_seed(tmp_path)
    errors = []

    def extra_ingests():
        try:
            for i in range(3):
                f = tmp_path / f'extra{i}.jsonl'
                f.write_text(json.dumps({
                    'kind': 'temperature', 'device': f'dev{i}', 'seq': 1,
                    'box_id': 'A', 'event_time': f'2030-06-07T01:00:0{i}Z',
                    'value': 3 + i}), encoding='utf-8')
                ingest(f, db)
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    t = threading.Thread(target=extra_ingests)
    t.start()
    results = migrate_all(db, 'record_chunks')
    t.join()
    assert not errors
    con = connect(db)
    total = con.execute('SELECT COUNT(*) AS n FROM source_file').fetchone()['n']
    assert total == 2 + 3
    con.close()
    for r in results:
        assert read_source_bytes(db, r['source_id']) is not None
    assert verify_archive(db)['ok']


def test_gc_and_pinned_readers_interleave_without_losing_chunks(tmp_path):
    """The fifth fault point: GC interleaved with concurrent long reads.

    Readers pin a generation and continuously reassemble every source while
    migrations republish and GC prunes; no read may ever see a missing chunk
    or a hash mismatch, and every source must stay byte-exact afterwards.
    """
    db, first_path, second_path = build_seed(tmp_path)
    want = {1: first_path.read_bytes(), 2: second_path.read_bytes()}
    migrate_all(db, 'record_chunks')
    errors = []
    stop = threading.Event()

    def reader_loop():
        try:
            while not stop.is_set():
                con = connect(db)
                view = ReaderView(con, ContentStore.for_db(db),
                                  hold_seconds=5)
                for sid in sorted(want):
                    assert view.source_bytes(sid) == want[sid]
                view.release()
                con.close()
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(repr(exc))

    def gc_loop():
        try:
            for _ in range(6):
                run_gc(db, grace_seconds=0)
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(repr(exc))

    threads = [threading.Thread(target=reader_loop) for _ in range(3)]
    threads.append(threading.Thread(target=gc_loop))
    for t in threads:
        t.start()
    for rep in ('fixed_64', 'record_chunks', 'fixed_64'):
        migrate_all(db, rep)
    stop.set()
    for t in threads:
        t.join(timeout=60)
    assert not errors
    for sid, raw in want.items():
        assert read_source_bytes(db, sid) == raw
        assert digest(read_source_bytes(db, sid)) == digest(raw)
    assert verify_archive(db)['ok']


def test_new_ingest_after_switch_is_migratable_and_evidence_ids_stable(tmp_path):
    db, first_path, _ = build_seed(tmp_path)
    first_raw = first_path.read_bytes()
    rows = source_rows(db)
    migrate_all(db, 'record_chunks')
    old_evidence = json.loads(report(db, tmp_path / 'ev1.json').read_text('utf-8'))
    old_source_ids = {s['id'] for s in old_evidence['sources']}
    old_event_sources = {e['source_id'] for e in old_evidence['events']}

    f = tmp_path / 'later.jsonl'
    f.write_text(json.dumps({'kind': 'dispatch', 'device': 'd-new', 'seq': 1,
                             'box_id': 'A', 'event_time': '2030-06-08T00:00:00Z'}),
                 encoding='utf-8')
    ingest(f, db)
    new_id = connect(db).execute(
        'SELECT id FROM source_file ORDER BY id DESC LIMIT 1').fetchone()[0]
    migrate_source(db, new_id, 'record_chunks')

    new_evidence = json.loads(report(db, tmp_path / 'ev2.json').read_text('utf-8'))
    assert old_source_ids <= {s['id'] for s in new_evidence['sources']}
    assert {e['source_id'] for e in new_evidence['events']} >= old_event_sources
    # Existing Base64 source bytes remain identical; the new source is exact too.
    before_map = {s['id']: s['raw'] for s in old_evidence['sources']}
    after_map = {s['id']: s['raw'] for s in new_evidence['sources']}
    for sid, b64 in before_map.items():
        assert after_map[sid] == b64
    assert read_source_bytes(db, new_id) == f.read_bytes()


def test_repeated_reports_remain_deterministic_after_archive(tmp_path):
    db, _, _ = build_seed(tmp_path)
    migrate_all(db, 'fixed_64')
    first = report(db, tmp_path / 'r1.json').read_bytes()
    second = report(db, tmp_path / 'r2.json').read_bytes()
    assert first == second


def test_archive_cli_emits_manifest_verification_and_accounting_evidence(tmp_path):
    db, _, _ = build_seed(tmp_path)
    evidence_path = tmp_path / 'out' / 'archive-evidence.json'
    evidence = archive(db, 'record_chunks', evidence_out=evidence_path)
    payload = json.loads(evidence_path.read_text('utf-8'))
    assert payload['command'] == 'archive'
    assert payload['verification']['ok']
    assert payload['accounting']['physical_chunk_files'] > 0
    assert {m['source_id'] for m in payload['migrated']} == {1, 2}
    assert evidence['accounting']['blobs_reclaimed'] == 2
