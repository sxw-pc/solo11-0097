import json
from hashlib import sha256
from pathlib import Path

import pytest

from coldhandoff.__main__ import init, report
from coldhandoff.archive import (
    ContentStore,
    migrate_all,
    read_source_bytes,
    recover,
    register as archive_register,
    run_gc,
    storage_accounting,
    verify_archive,
)
from coldhandoff.ingest import ingest
from coldhandoff.store import connect

CONTRACT = Path(__file__).parents[1] / 'fixtures' / 'archive-contract.json'
REPRESENTATIONS = ['fixed_64', 'record_chunks']


def seed(tmp_path, db_name='cold.db'):
    """Freeze the two overlapping real-source style BLOBs and return paths."""
    db = tmp_path / db_name
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


def test_archive_case_freezes_shifted_overlapping_raw_sources(tmp_path):
    db, _, _ = seed(tmp_path)
    assert archive_register(db, CONTRACT) == 'cold-sources-2030-06-07'
    con = connect(db)
    rows = list(con.execute('SELECT raw FROM source_file ORDER BY id'))
    assert len(rows) == 2 and rows[1]['raw'].endswith(rows[0]['raw'])
    assert con.execute('SELECT source_digest FROM archive_case').fetchone()[0]
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0] == 0
    con.close()


@pytest.mark.parametrize('representation', REPRESENTATIONS)
def test_both_representations_restore_real_blobs_and_keep_distinct_sha(tmp_path, representation):
    db, first, second = seed(tmp_path, f'{representation}.db')
    originals = [first.read_bytes(), second.read_bytes()]
    original_shas = [sha256(b).hexdigest() for b in originals]
    assert original_shas[0] != original_shas[1]  # whole-file dedup would miss this

    migrate_all(db, representation)
    con = connect(db)
    rows = list(con.execute('SELECT id,hash FROM source_file ORDER BY id'))
    con.close()
    for row, raw, sha in zip(rows, originals, original_shas):
        restored = read_source_bytes(db, row['id'])
        assert restored == raw                       # byte-exact reassembly
        assert sha256(restored).hexdigest() == sha   # original source_file.hash
        assert row['hash'] == sha
    assert verify_archive(db)['ok']


@pytest.mark.parametrize('representation', REPRESENTATIONS)
def test_report_output_identical_before_and_after_archive(tmp_path, representation):
    db, _, _ = seed(tmp_path, f'{representation}.db')
    before_path = report(db, tmp_path / f'{representation}-before.json')
    before = before_path.read_bytes()
    migrate_all(db, representation)
    after = report(db, tmp_path / f'{representation}-after.json').read_bytes()
    assert after == before  # Base64 source bytes and every evidence row stable


def test_register_works_before_and_after_migration_with_same_digest(tmp_path):
    db_a, _, _ = seed(tmp_path, 'a.db')
    archive_register(db_a, CONTRACT)
    before = connect(db_a).execute(
        'SELECT source_digest FROM archive_case').fetchone()[0]

    db_b, _, _ = seed(tmp_path, 'b.db')
    migrate_all(db_b, 'record_chunks')
    archive_register(db_b, CONTRACT)
    after = connect(db_b).execute(
        'SELECT source_digest FROM archive_case').fetchone()[0]
    assert before == after


def test_coexistence_then_reclaim_ledger(tmp_path):
    db, first, second = seed(tmp_path)
    raw_total = len(first.read_bytes()) + len(second.read_bytes())

    # Switch pointers while keeping the old BLOBs (coexistence window).
    migrate_all(db, 'record_chunks', reclaim=False)
    during = storage_accounting(db)
    assert during['raw_blob_bytes_remaining'] == raw_total
    assert during['blobs_reclaimed'] == 0
    assert during['physical_chunk_files'] > 0
    assert during['manifest_bytes'] > 0
    # Both copies verify against each other before anything is deleted.
    verification = verify_archive(db)
    assert all(s.get('raw_matches_archive') for s in verification['sources'])

    # GC reclaims the redundant BLOBs; the chunks remain the single copy.
    run_gc(db, grace_seconds=0)
    after = storage_accounting(db)
    assert after['raw_blob_bytes_remaining'] == 0
    assert after['blobs_reclaimed'] == 2
    assert after['physical_chunk_files'] == during['physical_chunk_files']
    con = connect(db)
    for row in con.execute('SELECT id FROM source_file ORDER BY id'):
        assert read_source_bytes(db, row['id'])  # still fully recoverable
    con.close()


def test_two_file_shas_differ_but_record_chunks_physically_shared(tmp_path):
    db, first, second = seed(tmp_path)
    migrate_all(db, 'record_chunks')
    acct = storage_accounting(db)
    # The 20 unchanged trailing records exist on disk once even though the
    # file-level SHAs differ, so whole-file dedup cannot achieve this.
    assert acct['shared_refs_saved'] == 20
    assert acct['unique_referenced_chunks'] < acct['logical_chunk_refs']
    fixed_db, _, _ = seed(tmp_path, 'fixed.db')
    migrate_all(fixed_db, 'fixed_64')
    fixed = storage_accounting(fixed_db)
    assert fixed['shared_refs_saved'] == 0  # boundary shift defeats sharing


def test_recover_after_crash_during_seed_migration(tmp_path):
    db, first, second = seed(tmp_path)
    from coldhandoff.archive import ArchiveError, FaultPlan, migrate_source
    with pytest.raises(ArchiveError, match='mid_chunk'):
        migrate_source(db, 1, 'fixed_64',
                       faults=FaultPlan(fail_at='mid_chunk', chunks_before_fail=1))
    result = recover(db)
    assert result['verification']['ok']
    originals = [first.read_bytes(), second.read_bytes()]
    for sid, raw in enumerate(originals, 1):
        assert read_source_bytes(db, sid) == raw
