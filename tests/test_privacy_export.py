"""Tests for tiered external evidence-package export.

The acceptance scanner below walks *every* artifact of an external package
(recursively through JSON text, Markdown and Base64-decoded bytes) to make
sure the partner package can never carry the private collector identity or
the original source path, while the regulator package stays byte-faithful.
"""
import base64
import json
import shutil
import sqlite3
import threading
from pathlib import Path

import pytest

from coldhandoff.__main__ import init
from coldhandoff.ingest import ingest
from coldhandoff.rules import evaluate
from coldhandoff import privacy_export as pe
from coldhandoff.store import connect

FIXTURES = Path(__file__).parents[1] / 'fixtures'
CONTRACT = FIXTURES / 'export-contract.json'
PRIVATE = 'MIRA-PRIVATE'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed(db, box='A'):
    init(db, 'batch-1', box)
    ingest(FIXTURES / 'privacy-events.jsonl', db)
    evaluate(db)
    return pe.register(db, CONTRACT)


def _publish(db, case, kind, out, recipient=None, key_id=None):
    handle = pe.stage_export(db, case, kind, out,
                             recipient_id=recipient, key_id=key_id)
    return pe.confirm_export(db, handle['package_id'], out)


def _all_bytes(root):
    return {str(p.relative_to(root)): p.read_bytes()
            for p in Path(root).rglob('*') if p.is_file()}


def _collect_pseudonyms(root):
    import re
    found = set()
    for blob in _all_bytes(root).values():
        found.update(re.findall(rb'PN-[A-F0-9]{12}', blob))
    return {x.decode() for x in found}


def _assert_no_private(root, source_paths):
    """Recursive acceptance scan over JSON, Markdown and decoded BLOBs."""
    forbidden = [PRIVATE] + source_paths + [Path(p).name for p in source_paths]
    findings = pe.scan_package(root, [PRIVATE], source_paths)
    assert findings == [], findings
    blobs = _all_bytes(root)
    for rel, blob in blobs.items():
        for needle in forbidden:
            assert needle.encode() not in blob, (rel, needle)
        # every Base64-looking leaf gets decoded and re-scanned
        if rel.endswith('.json'):
            data = json.loads(blob.decode('utf-8'))
            assert not pe._recursive_scan(data, forbidden)


def _write_jsonl(path, rows):
    path.write_text('\n'.join(json.dumps(r, ensure_ascii=False) for r in rows),
                    encoding='utf-8')


# ---------------------------------------------------------------------------
# End-to-end contract behaviour on the frozen batch-1 fixture
# ---------------------------------------------------------------------------

def test_two_packages_have_different_audience_bytes_and_hashes(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    reg = _publish(db, case, pe.REGULATOR, out)
    par = _publish(db, case, pe.PARTNER, out)

    rv = pe.verify_package(reg['package_dir'], db_path=db)
    pv = pe.verify_package(par['package_dir'], db_path=db)
    assert rv['ok'] and pv['ok']

    reg_src = json.loads((Path(reg['package_dir']) / 'sources.json').read_text())[0]
    par_src = json.loads((Path(par['package_dir']) / 'sources.json').read_text())[0]
    # regulator sees the original SHA; partner gets a recomputed export SHA
    assert len(reg_src['hash']) == 64 and 'export_hash' not in reg_src
    assert 'export_hash' in par_src and 'hash' not in par_src
    assert reg_src['hash'] != par_src['export_hash']
    # the original source SHA must not appear anywhere in the partner package
    blob = b''.join(_all_bytes(par['package_dir']).values())
    assert reg_src['hash'].encode() not in blob


def test_regulator_package_is_byte_faithful(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    reg = _publish(db, case, pe.REGULATOR, out)
    root = Path(reg['package_dir'])
    con = connect(db)
    for row in con.execute('SELECT * FROM source_file'):
        raw = bytes(row['raw'])
        on_disk = next((root / s['file']).read_bytes()
                       for s in json.loads((root / 'sources.json').read_text())
                       if s['original_id'] == row['id'])
        assert on_disk == raw
        assert pe._sha256(raw) == row['hash']
        assert PRIVATE.encode() in raw
    con.close()
    assert PRIVATE.encode() in b''.join(_all_bytes(root).values())


def test_partner_package_has_no_identity_path_or_blob_leak(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    con = connect(db)
    source_paths = [r['name'] for r in con.execute('SELECT name FROM source_file')]
    con.close()
    par = _publish(db, case, pe.PARTNER, out)
    _assert_no_private(par['package_dir'], source_paths)
    # no private mapping / key material inside the external package
    names = '\n'.join(str(p) for p in Path(par['package_dir']).rglob('*'))
    assert 'id_map' not in names and 'pseudonym_key' not in names


def test_partner_keeps_box_chain_and_decision(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    par = _publish(db, case, pe.PARTNER, out)
    root = Path(par['package_dir'])
    decisions = json.loads((root / 'decisions.json').read_text())
    assert [d['box_id'] for d in decisions] == ['A']
    detail = json.loads(decisions[0]['detail'])
    event_ids = {e['export_id'] for e in
                 json.loads((root / 'events.json').read_text())}
    assert detail['events'] and set(detail['events']) <= event_ids
    # event order (seq) and issue codes survive
    events = json.loads((root / 'events.json').read_text())
    assert [e['seq'] for e in events] == [1, 2, 3, 4, 5, 6]
    # source -> event -> evidence -> decision graph is closed
    v = pe.verify_package(root, db_path=db)
    assert all(c['ok'] for c in v['checks'] if c['name'] == 'reference_graph_closed')


def test_same_identity_gets_one_stable_pseudonym_across_events(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    par = _publish(db, case, pe.PARTNER, out)
    pseudonyms = _collect_pseudonyms(par['package_dir'])
    assert len(pseudonyms) == 1
    # internal mapping keeps original -> pseudonym for audit re-identification
    con = connect(db)
    rows = con.execute(
        "SELECT original_id,export_id FROM export_id_map "
        "WHERE package_id=? AND object_kind='identity'",
        (par['package_id'],)).fetchall()
    con.close()
    assert len(rows) == 1
    assert rows[0]['original_id'] == PRIVATE
    assert rows[0]['export_id'] == next(iter(pseudonyms))


def test_pseudonyms_are_unlinkable_across_recipients(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    p1 = _publish(db, case, pe.PARTNER, out, recipient='carrier-alpha')
    p2 = _publish(db, case, pe.PARTNER, out, recipient='carrier-beta')
    a = _collect_pseudonyms(p1['package_dir'])
    b = _collect_pseudonyms(p2['package_dir'])
    assert a and b and a.isdisjoint(b)
    s1 = json.loads((Path(p1['package_dir']) / 'sources.json').read_text())[0]['export_hash']
    s2 = json.loads((Path(p2['package_dir']) / 'sources.json').read_text())[0]['export_hash']
    assert s1 != s2
    # both still resolve the same box A decision independently
    for pkg in (p1, p2):
        dec = json.loads((Path(pkg['package_dir']) / 'decisions.json').read_text())
        assert dec[0]['box_id'] == 'A'
        assert pe.verify_package(pkg['package_dir'], db_path=db)['ok']


# ---------------------------------------------------------------------------
# Nested fields, BLOB/attachment dark leaks, exception detail, reference keys
# ---------------------------------------------------------------------------

def _rich_rows():
    blob = base64.b64encode(b'signed by MIRA-PRIVATE at depot').decode()
    return [
        {'kind': 'clock_anchor', 'device': 'logger-1', 'seq': 1,
         'event_time': '2030-06-08T07:59:00Z', 'offset_seconds': 0, 'actor': PRIVATE},
        {'kind': 'dispatch', 'device': 'logger-1', 'seq': 2, 'box_id': 'A',
         'event_time': '2030-06-08T08:00:00Z', 'actor': PRIVATE,
         'meta': {'collector': PRIVATE,
                  'nested': {'handover_actor': PRIVATE, 'ref': 'ticket:MIRA-PRIVATE/7'},
                  'signed_blob_b64': blob,
                  'attachment': {'name': 'note.md',
                                 'content': '# handover\ncaptured by MIRA-PRIVATE'}},
         'error_detail': 'ValueError raised for MIRA-PRIVATE'},
        {'kind': 'temperature', 'device': 'logger-1', 'seq': 3, 'box_id': 'A',
         'event_time': '2030-06-08T08:00:00Z', 'value': 4, 'actor': PRIVATE},
        {'kind': 'temperature', 'device': 'logger-1', 'seq': 4, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'value': 4, 'actor': PRIVATE},
        {'kind': 'arrival', 'device': 'logger-1', 'seq': 5, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'actor': PRIVATE},
        {'kind': 'sign', 'device': 'logger-1', 'seq': 6, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'actor': PRIVATE},
    ]


def test_nested_payload_base64_attachment_and_exception_are_scrubbed(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    init(db, 'batch-1', 'A')
    src = tmp_path / 'rich.jsonl'
    _write_jsonl(src, _rich_rows())
    ingest(src, db)
    evaluate(db)
    case = pe.register(db, CONTRACT)
    par = _publish(db, case, pe.PARTNER, out)
    _assert_no_private(par['package_dir'], [str(src)])

    root = Path(par['package_dir'])
    dispatch = next(e for e in json.loads((root / 'events.json').read_text())
                    if e['seq'] == 2)
    payload = dispatch['payload']
    # identity keys keep a pseudonym handle; raw identity values are gone
    assert 'actor' not in payload or payload.get('actor', '').startswith('PN-')
    assert payload['meta'].get('collector', '').startswith('PN-')
    assert PRIVATE not in json.dumps(payload)
    assert 'MIRA-PRIVATE' not in payload['meta']['nested']['ref']
    assert PRIVATE not in payload['error_detail']
    assert PRIVATE not in payload['meta']['attachment']['content']
    # the Base64 BLOB is decoded, transformed and re-encoded
    decoded = base64.b64decode(payload['meta']['signed_blob_b64'])
    assert PRIVATE.encode() not in decoded
    assert b'PN-' in decoded
    # rebuilt source bytes carry the same transformed line
    source_file = json.loads((root / 'sources.json').read_text())[0]
    line = next(l for l in (root / source_file['file']).read_text().splitlines()
                if '"seq":2' in l)
    assert pe._canonical(payload) == line
    assert pe.verify_package(root, db_path=db)['ok']


def test_markdown_attachment_inside_base64_is_scrubbed(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    init(db, 'batch-1', 'A')
    md = '# 交接单\n负责人 MIRA-PRIVATE\n路径 /secret/MIRA-PRIVATE/log.jsonl'
    rows = [
        {'kind': 'clock_anchor', 'device': 'l', 'seq': 1,
         'event_time': '2030-06-08T07:59:00Z', 'offset_seconds': 0, 'actor': PRIVATE},
        {'kind': 'dispatch', 'device': 'l', 'seq': 2, 'box_id': 'A',
         'event_time': '2030-06-08T08:00:00Z', 'actor': PRIVATE,
         'attach_md_b64': base64.b64encode(md.encode()).decode()},
        {'kind': 'temperature', 'device': 'l', 'seq': 3, 'box_id': 'A',
         'event_time': '2030-06-08T08:00:00Z', 'value': 4, 'actor': PRIVATE},
        {'kind': 'temperature', 'device': 'l', 'seq': 4, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'value': 4, 'actor': PRIVATE},
        {'kind': 'arrival', 'device': 'l', 'seq': 5, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'actor': PRIVATE},
        {'kind': 'sign', 'device': 'l', 'seq': 6, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'actor': PRIVATE},
    ]
    src = tmp_path / 'MIRA-PRIVATE.jsonl'
    _write_jsonl(src, rows)
    ingest(src, db)
    evaluate(db)
    case = pe.register(db, CONTRACT)
    par = _publish(db, case, pe.PARTNER, out)
    root = Path(par['package_dir'])
    assert pe.scan_package(root, [PRIVATE, '/secret/MIRA-PRIVATE/log.jsonl'],
                           [str(src)]) == []
    dispatch = next(e for e in json.loads((root / 'events.json').read_text())
                    if e['seq'] == 2)
    decoded = base64.b64decode(dispatch['payload']['attach_md_b64']).decode()
    assert PRIVATE not in decoded and 'PN-' in decoded


def test_raw_blob_field_is_dropped_not_copied(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    init(db, 'batch-1', 'A')
    rows = _rich_rows()
    rows[1]['raw_original_bytes'] = base64.b64encode(b'RAW MIRA-PRIVATE BLOB').decode()
    src = tmp_path / 'blob.jsonl'
    _write_jsonl(src, rows)
    ingest(src, db)
    evaluate(db)
    case = pe.register(db, CONTRACT)
    par = _publish(db, case, pe.PARTNER, out)
    _assert_no_private(par['package_dir'], [str(src)])
    dumped = b''.join(_all_bytes(par['package_dir']).values())
    assert b'RAW MIRA-PRIVATE' not in dumped
    assert b'raw_original_bytes' not in dumped


# ---------------------------------------------------------------------------
# Duplicate events and empty issue sets
# ---------------------------------------------------------------------------

def test_duplicate_events_remain_consistent(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    init(db, 'batch-1', 'A')
    src = tmp_path / 'dup.jsonl'
    rows = _rich_rows()
    _write_jsonl(src, rows)
    ingest(src, db)
    # re-ingesting the identical file is a duplicate and must not add events
    again = ingest(src, db)
    assert again['duplicate_file'] is True
    evaluate(db)
    case = pe.register(db, CONTRACT)
    par = _publish(db, case, pe.PARTNER, out)
    root = Path(par['package_dir'])
    events = json.loads((root / 'events.json').read_text())
    assert [e['seq'] for e in events] == [1, 2, 3, 4, 5, 6]
    assert len({e['export_hash'] for e in events}) == len(events)
    assert pe.verify_package(root, db_path=db)['ok']


def test_empty_issue_set_packages_cleanly(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)  # fixture is a complete chain -> no issues
    par = _publish(db, case, pe.PARTNER, out)
    root = Path(par['package_dir'])
    assert json.loads((root / 'issues.json').read_text()) == []
    md = (root / 'report.md').read_text(encoding='utf-8')
    assert '无 issue' in md
    assert pe.verify_package(root, db_path=db)['ok']


# ---------------------------------------------------------------------------
# Source hash changes, immutability and versioning
# ---------------------------------------------------------------------------

def test_source_change_freezes_old_and_requires_new_lineage(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    par = _publish(db, case, pe.PARTNER, out)
    v1_dir = par['package_dir']
    v1_hash = json.loads((Path(v1_dir) / 'sources.json').read_text())[0]['export_hash']

    new_source = tmp_path / 'more.jsonl'
    new_source.write_text(json.dumps({
        'kind': 'dispatch', 'device': 'd9', 'seq': 1, 'box_id': 'A',
        'event_time': '2030-06-09T00:00:00Z'}), encoding='utf-8')
    ingest(new_source, db)
    with pytest.raises(pe.FrozenDigestMismatch):
        pe.stage_export(db, case, pe.PARTNER, out, recipient_id='r-new')
    with pytest.raises(pe.FrozenDigestMismatch):
        pe.register(db, CONTRACT)
    # old delivered package is untouched and still verifies
    assert pe.verify_package(v1_dir)['ok']
    assert json.loads((Path(v1_dir) / 'sources.json').read_text())[0]['export_hash'] == v1_hash

    contract2 = json.loads(CONTRACT.read_text())
    contract2['case_id'] = 'evidence-export-2030-06-09'
    c2 = tmp_path / 'contract2.json'
    c2.write_text(json.dumps(contract2), encoding='utf-8')
    case2 = pe.register(db, c2)
    h2 = _publish(db, case2, pe.PARTNER, out, recipient='r-new')
    assert h2['version'] == 1 and pe.verify_package(h2['package_dir'], db_path=db)['ok']


def test_delivered_packages_and_mappings_are_never_overwritten(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    first = _publish(db, case, pe.PARTNER, out)
    first_bytes = {rel: blob for rel, blob in _all_bytes(first['package_dir']).items()}
    # identical request is idempotent, never creates another version
    again = pe.stage_export(db, case, pe.PARTNER, out)
    assert again['reused'] is True and again['version'] == 1
    con = connect(db)
    assert con.execute("SELECT count(*) FROM export_package").fetchone()[0] == 1
    maps_before = con.execute(
        "SELECT count(*) FROM export_id_map WHERE package_id=?",
        (first['package_id'],)).fetchone()[0]
    con.close()
    assert maps_before > 0
    # confirming twice is idempotent and leaves every byte untouched
    pe.confirm_export(db, first['package_id'], out)
    assert _all_bytes(first['package_dir']) == first_bytes
    con = connect(db)
    assert con.execute("SELECT count(*) FROM export_package").fetchone()[0] == 1
    assert con.execute("SELECT count(*) FROM export_id_map").fetchone()[0] == maps_before
    con.close()


def test_key_rotation_versions_new_package_but_keeps_old_verifiable(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    v1 = _publish(db, case, pe.PARTNER, out)
    pn_v1 = _collect_pseudonyms(v1['package_dir'])
    new_key = pe.rotate_key(db, 'synthetic-key-2')
    assert new_key == 'synthetic-key-2'
    h2 = pe.stage_export(db, case, pe.PARTNER, out)
    assert h2['version'] == 2 and h2['key_id'] == 'synthetic-key-2'
    v2 = pe.confirm_export(db, h2['package_id'], out)
    pn_v2 = _collect_pseudonyms(v2['package_dir'])
    assert pn_v1.isdisjoint(pn_v2)
    # old package remains independently verifiable with its own references
    assert pe.verify_package(v1['package_dir'], db_path=db)['ok']
    assert pe.verify_package(v2['package_dir'], db_path=db)['ok']
    # the two packages cannot be linked through hashes either
    h1 = json.loads((Path(v1['package_dir']) / 'sources.json').read_text())[0]['export_hash']
    h2h = json.loads((Path(v2['package_dir']) / 'sources.json').read_text())[0]['export_hash']
    assert h1 != h2h


# ---------------------------------------------------------------------------
# Concurrency, crash recovery and staging safety
# ---------------------------------------------------------------------------

def test_concurrent_exports_bind_one_frozen_snapshot(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    errors, handles = [], []

    def worker():
        try:
            handles.append(pe.stage_export(db, case, pe.PARTNER, out))
        except Exception as exc:  # pragma: no cover - concurrency guard
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    con = connect(db)
    assert con.execute(
        "SELECT count(*) FROM export_package WHERE contract_kind=?",
        (pe.PARTNER,)).fetchone()[0] == 1
    con.close()
    assert len({h['package_id'] for h in handles}) == 1


def test_resume_after_crash_between_stage_and_confirm(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    for kind, recipient in ((pe.REGULATOR, 'regulator-primary'),
                            (pe.PARTNER, 'partner-primary')):
        h = pe.stage_export(db, case, kind, out)
        staging, final = Path(h['staging_dir']), Path(h['package_dir'])
        assert staging.exists() and not final.exists()
        rec = pe.resume_export(db, case, kind, recipient, out)
        assert rec['status'] == 'confirmed'
        assert final.exists() and not staging.exists()
        assert pe.verify_package(final, db_path=db)['ok']


def test_resume_rebuilds_lost_staging_bytes_without_private_leak(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    h = pe.stage_export(db, case, pe.PARTNER, out, recipient_id='carrier-x')
    shutil.rmtree(h['staging_dir'])
    con = connect(db)
    source_paths = [r['name'] for r in con.execute('SELECT name FROM source_file')]
    con.close()
    rec = pe.resume_export(db, case, pe.PARTNER, 'carrier-x', out)
    assert rec['status'] == 'confirmed'
    v = pe.verify_package(rec['package_dir'], db_path=db)
    assert v['ok'] and not v['leak_findings']
    _assert_no_private(rec['package_dir'], source_paths)


def test_staging_with_private_text_is_never_delivered(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    h = pe.stage_export(db, case, pe.PARTNER, out)
    staging = Path(h['staging_dir'])
    # a staging dir by construction contains only rebuilt bytes; prove the
    # private word is absent even before confirmation
    assert PRIVATE.encode() not in b''.join(_all_bytes(staging).values())
    # and tampering with staging makes confirmation fail closed
    (staging / 'tamper.txt').write_text(PRIVATE, encoding='utf-8')
    with pytest.raises(pe.LeakDetected):
        pe.confirm_export(db, h['package_id'], out)
    con = connect(db)
    status = con.execute('SELECT status FROM export_package WHERE id=?',
                         (h['package_id'],)).fetchone()[0]
    con.close()
    assert status == 'failed'
    assert not Path(h['package_dir']).exists()


# ---------------------------------------------------------------------------
# Manifest, receipt and Markdown artefacts
# ---------------------------------------------------------------------------

def test_manifest_receipt_and_verification_report_are_present(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    reg = _publish(db, case, pe.REGULATOR, out)
    par = _publish(db, case, pe.PARTNER, out)
    for pkg in (reg, par):
        root = Path(pkg['package_dir'])
        manifest = json.loads((root / 'manifest.json').read_text())
        assert manifest['package_id'] == pkg['package_id']
        assert manifest['content_digest'] and len(manifest['files']) >= 7
        receipt = json.loads((root / 'receipt.json').read_text())
        assert receipt['recipient_id'] == manifest['recipient_id']
        report = json.loads((root / 'verify' / 'verification.json').read_text())
        assert report['ok']
        assert (root / 'report.md').read_text(encoding='utf-8').startswith('# 冷链交接证据包')
    # partner manifest hides the real frozen digest, regulator exposes it
    p_man = json.loads((Path(par['package_dir']) / 'manifest.json').read_text())
    r_man = json.loads((Path(reg['package_dir']) / 'manifest.json').read_text())
    assert p_man['frozen_source_digest'] is None
    assert p_man['source_digest_commitment']
    assert r_man['frozen_source_digest']
    assert p_man['source_digest_commitment'] != r_man['frozen_source_digest']


def test_private_mapping_lives_only_in_local_database(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    par = _publish(db, case, pe.PARTNER, out)
    con = sqlite3.connect(db)
    tables = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {'export_package', 'export_id_map', 'pseudonym_key'} <= tables
    n = con.execute('SELECT count(*) FROM export_id_map').fetchone()[0]
    con.close()
    assert n > 0
    for blob in _all_bytes(par['package_dir']).values():
        assert b'export_id_map' not in blob and b'pseudonym_key' not in blob


def test_standalone_verification_detects_tampering(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    reg = _publish(db, case, pe.REGULATOR, out)
    root = Path(reg['package_dir'])
    sources = json.loads((root / 'sources.json').read_text())
    target = root / sources[0]['file']
    target.write_bytes(target.read_bytes() + b'\nTAMPERED\n')
    report = pe.verify_package(root)
    assert report['ok'] is False
    assert any(not c['ok'] and c['name'].startswith('file_hash:')
               for c in report['checks'])


def test_regulator_reference_graph_is_fully_closed(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    reg = _publish(db, case, pe.REGULATOR, out)
    root = Path(reg['package_dir'])
    report = pe.verify_package(root, db_path=db)
    assert report['ok']
    graph = next(c for c in report['checks'] if c['name'] == 'reference_graph_closed')
    assert graph['ok']
    # regulator keeps original hashes and raw base64 on every source
    for s in json.loads((root / 'sources.json').read_text()):
        assert s['hash'] and s['raw_base64']
        assert base64.b64decode(s['raw_base64']) == (root / s['file']).read_bytes()


def test_multiple_distinct_identities_each_get_stable_pseudonym(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    init(db, 'batch-1', 'A')
    rows = [
        {'kind': 'clock_anchor', 'device': 'l', 'seq': 1,
         'event_time': '2030-06-08T07:59:00Z', 'offset_seconds': 0,
         'actor': 'MIRA-PRIVATE'},
        {'kind': 'dispatch', 'device': 'l', 'seq': 2, 'box_id': 'A',
         'event_time': '2030-06-08T08:00:00Z', 'actor': 'MIRA-PRIVATE'},
        {'kind': 'temperature', 'device': 'l', 'seq': 3, 'box_id': 'A',
         'event_time': '2030-06-08T08:00:00Z', 'value': 4,
         'actor': 'SECOND-OPERATOR'},
        {'kind': 'temperature', 'device': 'l', 'seq': 4, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'value': 4,
         'actor': 'MIRA-PRIVATE'},
        {'kind': 'arrival', 'device': 'l', 'seq': 5, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'actor': 'SECOND-OPERATOR'},
        {'kind': 'sign', 'device': 'l', 'seq': 6, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'actor': 'MIRA-PRIVATE'},
    ]
    src = tmp_path / 'two-actors.jsonl'
    _write_jsonl(src, rows)
    ingest(src, db)
    evaluate(db)
    contract = json.loads(CONTRACT.read_text())
    contract['sensitive_tokens'] = ['MIRA-PRIVATE', 'SECOND-OPERATOR']
    cpath = tmp_path / 'contract.json'
    cpath.write_text(json.dumps(contract), encoding='utf-8')
    case = pe.register(db, cpath)
    par = _publish(db, case, pe.PARTNER, out)
    root = Path(par['package_dir'])
    findings = pe.scan_package(root, ['MIRA-PRIVATE', 'SECOND-OPERATOR'], [str(src)])
    assert findings == []
    actors = [e['payload']['actor'] for e in
             json.loads((root / 'events.json').read_text()) if 'actor' in e['payload']]
    # each identity collapses to exactly one pseudonym; mapping covers both
    assert len(set(actors)) == 2
    con = connect(db)
    id_rows = con.execute(
        "SELECT original_id FROM export_id_map WHERE package_id=? AND object_kind='identity'",
        (par['package_id'],)).fetchall()
    con.close()
    assert {r['original_id'] for r in id_rows} == {'MIRA-PRIVATE', 'SECOND-OPERATOR'}


def test_csv_sources_are_rebuilt_and_scrubbed(tmp_path):
    import csv as _csv
    import io as _io
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    init(db, 'batch-1', 'A')
    src = tmp_path / 'MIRA-PRIVATE-log.csv'
    buf = _io.StringIO()
    writer = _csv.DictWriter(
        buf, fieldnames=['kind', 'device', 'seq', 'box_id',
                        'event_time', 'value', 'actor'])
    writer.writeheader()
    writer.writerows([
        {'kind': 'clock_anchor', 'device': 'l', 'seq': 1, 'box_id': '',
         'event_time': '2030-06-08T07:59:00Z', 'value': '', 'actor': 'MIRA-PRIVATE'},
        {'kind': 'dispatch', 'device': 'l', 'seq': 2, 'box_id': 'A',
         'event_time': '2030-06-08T08:00:00Z', 'value': '', 'actor': 'MIRA-PRIVATE'},
        {'kind': 'temperature', 'device': 'l', 'seq': 3, 'box_id': 'A',
         'event_time': '2030-06-08T08:00:00Z', 'value': '4', 'actor': 'MIRA-PRIVATE'},
        {'kind': 'temperature', 'device': 'l', 'seq': 4, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'value': '4', 'actor': 'MIRA-PRIVATE'},
        {'kind': 'arrival', 'device': 'l', 'seq': 5, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'value': '', 'actor': 'MIRA-PRIVATE'},
        {'kind': 'sign', 'device': 'l', 'seq': 6, 'box_id': 'A',
         'event_time': '2030-06-08T08:20:00Z', 'value': '', 'actor': 'MIRA-PRIVATE'},
    ])
    src.write_text(buf.getvalue(), encoding='utf-8')
    ingest(src, db)
    evaluate(db)
    case = pe.register(db, CONTRACT)
    par = _publish(db, case, pe.PARTNER, out)
    root = Path(par['package_dir'])
    assert pe.scan_package(root, [PRIVATE], [str(src)]) == []
    source = json.loads((root / 'sources.json').read_text())[0]
    rebuilt = (root / source['file']).read_text()
    assert 'MIRA-PRIVATE-log' not in rebuilt and PRIVATE not in rebuilt
    assert source['export_hash'] == pe._sha256(rebuilt.encode('utf-8'))
    assert pe.verify_package(root, db_path=db)['ok']


def test_partner_package_cannot_claim_original_source_sha(tmp_path):
    db = tmp_path / 'cold.db'
    out = tmp_path / 'packages'
    case = _seed(db)
    reg = _publish(db, case, pe.REGULATOR, out)
    par = _publish(db, case, pe.PARTNER, out)
    original = json.loads((Path(reg['package_dir']) / 'sources.json').read_text())[0]['hash']
    partner_blob = b''.join(_all_bytes(par['package_dir']).values())
    # the 64-hex original SHA appears nowhere in the partner package
    assert original.encode() not in partner_blob
    manifest = json.loads((Path(par['package_dir']) / 'manifest.json').read_text())
    assert manifest['frozen_source_digest'] is None
