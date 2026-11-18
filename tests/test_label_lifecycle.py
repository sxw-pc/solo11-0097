"""End-to-end physical label issuance, jam recovery and audit tests.

All hardware is simulated: PRN-1 writes byte files and append-only journals
under a temp directory; SCAN-1 reads those bytes back. Nothing leaves the
machine.
"""
import json
import sqlite3
import threading
from pathlib import Path

import pytest

from coldhandoff.__main__ import init
from coldhandoff.devices import PrinterError, ScanRejection, read_journal, verify_chain
from coldhandoff.labels import (register, open_job, reserve, send_print,
                                apply_label, reconcile_print, redeliver_command,
                                recover_jam, quarantine, resolve_quarantine,
                                record_destruction, revoke, reprint,
                                revise_contract, build_report, report,
                                close_job, build_devices)
from coldhandoff.sheet import parse_sheet, render_sheet
from coldhandoff.store import connect

FIXTURE = Path(__file__).parents[1] / 'fixtures' / 'label-contract.json'
CASE = 'label-run-2030-06-05'


def seed(tmp_path):
    db = tmp_path / 'cold.db'
    devices = tmp_path / 'devices'
    for box in ('A', 'B'):
        init(db, 'batch-1', box)
    register(db, FIXTURE)
    return db, devices


def state_of(db, serial):
    con = connect(db)
    row = con.execute('SELECT state FROM serial_ledger WHERE serial=?',
                      (serial,)).fetchone()
    con.close()
    return row['state'] if row else None


def paper_bytes(devices, serial, printer_id='PRN-1'):
    return (Path(devices) / printer_id / 'paper' / (serial + '.lbl')).read_bytes()


# --------------------------------------------------------------------------- #
# Seed
# --------------------------------------------------------------------------- #

def test_boxes_exist_and_labeling_ignores_temperature(tmp_path):
    db, devices = seed(tmp_path)
    con = connect(db)
    assert {r['id'] for r in con.execute('SELECT id FROM box')} == {'A', 'B'}
    contract = json.loads(
        con.execute("SELECT contract_json FROM label_contract_version "
                    "WHERE case_id=? AND version=1", (CASE,)).fetchone()[0])
    assert [i['serial'] for i in contract['labels']] == ['SER-0001', 'SER-0002']
    # No temperature decision exists, yet labeling works end to end.
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0] == 0
    con.close()
    job = open_job(db, CASE, 'direct_recipient')
    r = reserve(db, CASE, 'A', 'direct_recipient', job_id=job)
    assert r['serial'] == 'SER-0001'
    assert state_of(db, 'SER-0001') == 'reserved'


def test_register_is_idempotent_on_identical_contract(tmp_path):
    db, _ = seed(tmp_path)
    register(db, FIXTURE)
    con = connect(db)
    assert con.execute(
        'SELECT count(*) FROM label_contract_version').fetchone()[0] == 1
    con.close()


# --------------------------------------------------------------------------- #
# Deterministic rendering and the two genuinely different paper contracts
# --------------------------------------------------------------------------- #

def test_rendered_bytes_are_deterministic_and_self_digesting():
    kw = dict(case_id=CASE, contract_sha256='c' * 64, box_id='A',
              serial='SER-0001', recipient='CLIENT-ALPHA',
              opaque_id='TKN-A-001')
    first = render_sheet(mode='direct_recipient', **kw)
    second = render_sheet(mode='direct_recipient', **kw)
    assert first['sheet_bytes'] == second['sheet_bytes']
    parsed = parse_sheet(first['sheet_bytes'])
    assert parsed['digest_valid']
    assert parsed['content_sha256'] == first['content_sha256']


def test_direct_mode_prints_customer_name_opaque_mode_does_not(tmp_path):
    db, devices = seed(tmp_path)
    direct = reserve(db, CASE, 'A', 'direct_recipient')
    opaque = reserve(db, CASE, 'B', 'opaque_pickup')
    text_a = direct['sheet_bytes'].decode('utf-8')
    text_b = opaque['sheet_bytes'].decode('utf-8')
    assert 'CLIENT-ALPHA' in text_a and 'TKN-A-001' not in text_a
    assert 'TKN-B-002' in text_b and 'CLIENT-BETA' not in text_b
    # Different physical content, different digests for the same template.
    assert direct['content_sha256'] != opaque['content_sha256']
    # Recipient remains recoverable only through the private contract mapping.
    con = connect(db)
    contract = json.loads(con.execute(
        'SELECT contract_json FROM label_contract_version WHERE case_id=? '
        'ORDER BY version DESC LIMIT 1', (CASE,)).fetchone()[0])
    mapping = {i['opaque_id']: i['recipient'] for i in contract['labels']}
    assert mapping['TKN-B-002'] == 'CLIENT-BETA'
    con.close()


def test_one_job_confirms_only_one_layout_other_is_unexecuted(tmp_path):
    from coldhandoff.labels import produce
    db, devices = seed(tmp_path)
    out = produce(db, CASE, 'direct_recipient', devices, box_ids=['A', 'B'])
    assert out['mode'] == 'direct_recipient'
    # The jam leaves A interrupted; B's paper is fully produced.
    assert state_of(db, 'SER-0002') == 'printed'
    con = connect(db)
    assert con.execute(
        "SELECT count(*) FROM label_job WHERE mode='opaque_pickup'").fetchone()[0] == 0
    assert con.execute(
        "SELECT count(*) FROM serial_ledger WHERE mode='opaque_pickup'").fetchone()[0] == 0
    con.close()
    # The control layout remains executable only as a separate job.
    close_job(db, out['job_id'])
    other = open_job(db, CASE, 'opaque_pickup')
    assert other != out['job_id']


def test_direct_and_opaque_both_deliver_box_to_correct_customer(tmp_path):
    db, devices = seed(tmp_path)
    for box, mode in (('A', 'direct_recipient'), ('B', 'opaque_pickup')):
        serial = 'SER-0001' if box == 'A' else 'SER-0002'
        # Use fresh serials per independent scenario through full lifecycle.
        reserve(db, CASE, box, mode, serial=serial)
        if serial == 'SER-0001':
            # Jam path: recover using the intact paper.
            assert send_print(db, serial, devices)['status'] == 'jammed_after_emission'
            result = recover_jam(db, serial, devices, 'paper_recoverable')
        else:
            send_print(db, serial, devices)
            result = apply_label(db, serial, devices, box)
        assert result['status'] == 'applied'
        con = connect(db)
        row = con.execute(
            'SELECT content_sha256,source_digest FROM serial_ledger WHERE serial=?',
            (serial,)).fetchone()
        con.close()
        paper = paper_bytes(devices, serial)
        parsed = parse_sheet(paper)
        assert parsed['content_sha256'] == row['content_sha256']
        assert parsed['digest_valid']


# --------------------------------------------------------------------------- #
# Jam injection: paper out, ACK never sent — three recovery dispositions
# --------------------------------------------------------------------------- #

def test_jam_paper_exists_even_when_ack_missing(tmp_path):
    db, devices = seed(tmp_path)
    reserve(db, CASE, 'A', 'direct_recipient', serial='SER-0001')
    outcome = send_print(db, 'SER-0001', devices)
    assert outcome['status'] == 'jammed_after_emission'
    # Physical evidence exists despite no ACK; ledger did not erase the serial.
    assert paper_bytes(devices, 'SER-0001')
    printer, _ = build_devices(db, devices, CASE)
    emission = printer.find_emission('SER-0001')
    assert emission is not None
    ack_events = [r for r in read_journal(printer.journal)
                  if r['event'] == 'ack_sent' and r['serial'] == 'SER-0001']
    assert ack_events == []
    assert state_of(db, 'SER-0001') == 'reserved'


def test_jam_recovery_recoverable_keeps_same_serial_and_applies(tmp_path):
    db, devices = seed(tmp_path)
    reserve(db, CASE, 'A', 'direct_recipient', serial='SER-0001')
    send_print(db, 'SER-0001', devices)
    recon = reconcile_print(db, 'SER-0001', devices)
    assert recon['status'] == 'emission_confirmed'
    result = recover_jam(db, 'SER-0001', devices, 'paper_recoverable')
    assert result['serial'] == 'SER-0001' and result['status'] == 'applied'
    assert state_of(db, 'SER-0001') == 'applied'
    # Only one physical sheet was ever emitted for this serial.
    printer, _ = build_devices(db, devices, CASE)
    emissions = [e for e in printer.emitted_serials()
                 if e['serial'] == 'SER-0001']
    assert len(emissions) == 1


def test_jam_recovery_destroyed_registers_evidence_voids_and_reprints(tmp_path):
    db, devices = seed(tmp_path)
    reserve(db, CASE, 'A', 'direct_recipient', serial='SER-0001')
    send_print(db, 'SER-0001', devices)
    result = recover_jam(db, 'SER-0001', devices, 'paper_destroyed',
                         'shredded during jam clearance')
    assert result['new_serial'] == 'SER-0003'
    assert state_of(db, 'SER-0001') == 'revoked'
    assert state_of(db, 'SER-0003') == 'applied'
    con = connect(db)
    events = [r['event'] for r in con.execute(
        'SELECT event FROM label_event WHERE serial=? ORDER BY id',
        ('SER-0001',))]
    assert 'destruction_recorded' in events and 'revoked' in events
    chain = con.execute(
        'SELECT replaces_serial,replaced_by_serial FROM serial_ledger WHERE serial=?',
        ('SER-0003',)).fetchone()
    assert chain['replaces_serial'] == 'SER-0001'
    old = con.execute(
        'SELECT replaced_by_serial FROM serial_ledger WHERE serial=?',
        ('SER-0001',)).fetchone()
    assert old['replaced_by_serial'] == 'SER-0003'
    con.close()
    # Old physical sheet still on disk historically; new sheet is distinct paper.
    assert paper_bytes(devices, 'SER-0001')
    assert paper_bytes(devices, 'SER-0003')


def test_jam_recovery_unknown_quarantines_without_auto_retry(tmp_path):
    db, devices = seed(tmp_path)
    reserve(db, CASE, 'A', 'direct_recipient', serial='SER-0001')
    send_print(db, 'SER-0001', devices)
    result = recover_jam(db, 'SER-0001', devices, 'whereabouts_unknown')
    assert result == {'status': 'quarantined', 'serial': 'SER-0001'}
    assert state_of(db, 'SER-0001') == 'quarantined'
    # No new SER-0001 sheet and no replacement was minted automatically.
    con = connect(db)
    assert con.execute(
        "SELECT count(*) FROM serial_ledger WHERE serial='SER-0001'").fetchone()[0] == 1
    assert con.execute(
        "SELECT count(*) FROM serial_ledger").fetchone()[0] == 1
    con.close()
    # Explicit resolution path: confirmed lost -> revoke then explicit reprint.
    resolve_quarantine(db, 'SER-0001', 'confirmed_lost', 'swept with waste')
    assert state_of(db, 'SER-0001') == 'revoked'
    out = reprint(db, 'SER-0001', devices, 'quarantine loss', auto_apply=True)
    assert out['new_serial'] == 'SER-0003'
    assert state_of(db, 'SER-0003') == 'applied'


def test_quarantine_located_intact_releases_for_application(tmp_path):
    db, devices = seed(tmp_path)
    reserve(db, CASE, 'A', 'direct_recipient', serial='SER-0001')
    send_print(db, 'SER-0001', devices)
    recover_jam(db, 'SER-0001', devices, 'whereabouts_unknown')
    resolve_quarantine(db, 'SER-0001', 'located_intact', 'found intact in tray')
    assert state_of(db, 'SER-0001') == 'printed'
    result = apply_label(db, 'SER-0001', devices, 'A')
    assert result['status'] == 'applied'


# --------------------------------------------------------------------------- #
# Concurrency: two print workers reserving at once
# --------------------------------------------------------------------------- #

def test_concurrent_workers_reserve_distinct_serials_without_duplicates(tmp_path):
    db, devices = seed(tmp_path)
    errors = []

    def worker(mode):
        try:
            job = open_job(db, CASE, mode)
            for box in ('A', 'B'):
                try:
                    reserve(db, CASE, box, mode, job_id=job)
                except ValueError as exc:
                    errors.append(str(exc))
        except Exception as exc:  # one worker may lose the job-mode race
            errors.append(type(exc).__name__ + ':' + str(exc))

    t1 = threading.Thread(target=worker, args=('direct_recipient',))
    t2 = threading.Thread(target=worker, args=('opaque_pickup',))
    t1.start(); t2.start(); t1.join(); t2.join()
    con = connect(db)
    rows = con.execute(
        'SELECT box_id,count(*) c FROM serial_ledger GROUP BY box_id').fetchall()
    # At most one current label per box even under concurrency.
    assert all(r['c'] == 1 for r in rows)
    serials = [r['serial'] for r in con.execute('SELECT serial FROM serial_ledger')]
    assert len(serials) == len(set(serials))
    con.close()


def test_concurrent_reservation_same_box_only_one_wins(tmp_path):
    db, devices = seed(tmp_path)
    job = open_job(db, CASE, 'direct_recipient')
    outcomes = []

    def worker():
        try:
            reserve(db, CASE, 'A', 'direct_recipient', serial='SER-0001',
                    job_id=job)
            outcomes.append('won')
        except ValueError as exc:
            outcomes.append('lost:' + str(exc))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert outcomes.count('won') == 1
    assert all(o.startswith('lost:') for o in outcomes if o != 'won')
    con = connect(db)
    assert con.execute(
        "SELECT count(*) FROM serial_ledger WHERE serial='SER-0001'").fetchone()[0] == 1
    con.close()


# --------------------------------------------------------------------------- #
# Scan failures: wrong box, digest mismatch, revoked paper
# --------------------------------------------------------------------------- #

def _printed(db, devices, box, serial, mode):
    reserve(db, CASE, box, mode, serial=serial)
    outcome = send_print(db, serial, devices)
    if outcome['status'] == 'jammed_after_emission':
        # Paper is physically out; convergence via the printer journal.
        reconcile_print(db, serial, devices)
    return serial


def test_wrong_box_scan_is_rejected_and_not_applied(tmp_path):
    db, devices = seed(tmp_path)
    _printed(db, devices, 'A', 'SER-0001', 'direct_recipient')
    # Label for A physically presented on box B.
    with pytest.raises(ScanRejection) as exc:
        apply_label(db, 'SER-0001', devices, 'B')
    assert exc.value.code == 'wrong_box'
    assert state_of(db, 'SER-0001') == 'printed'
    _, scanner = build_devices(db, devices, CASE)
    rejected = [r for r in scanner.scans() if r['event'] == 'scan_rejected']
    assert rejected and rejected[-1]['reason'] == 'wrong_box'
    # Presented on the correct box afterwards works.
    assert apply_label(db, 'SER-0001', devices, 'A')['status'] == 'applied'


def test_content_digest_mismatch_is_rejected(tmp_path):
    db, devices = seed(tmp_path)
    _printed(db, devices, 'B', 'SER-0002', 'opaque_pickup')
    tampered = bytearray(paper_bytes(devices, 'SER-0002'))
    tampered[-2] ^= 0x01  # flip a byte inside the physical sheet
    with pytest.raises(ScanRejection) as exc:
        apply_label(db, 'SER-0002', devices, 'B', sheet_bytes=bytes(tampered))
    assert exc.value.code == 'sheet_digest_mismatch'
    assert state_of(db, 'SER-0002') == 'printed'


def test_revoked_serial_paper_scanned_is_rejected(tmp_path):
    db, devices = seed(tmp_path)
    _printed(db, devices, 'A', 'SER-0001', 'direct_recipient')
    record_destruction(db, 'SER-0001', 'operator voided misprint')
    revoke(db, 'SER-0001', 'misprint')
    with pytest.raises(ScanRejection) as exc:
        apply_label(db, 'SER-0001', devices, 'A')
    assert exc.value.code == 'serial_revoked'


def test_quarantined_serial_cannot_be_applied(tmp_path):
    db, devices = seed(tmp_path)
    _printed(db, devices, 'A', 'SER-0001', 'direct_recipient')
    quarantine(db, 'SER-0001', 'investigation')
    with pytest.raises(ScanRejection) as exc:
        apply_label(db, 'SER-0001', devices, 'A')
    assert exc.value.code == 'serial_quarantined'


# --------------------------------------------------------------------------- #
# Print command nonces: duplicate delivery and late ACK
# --------------------------------------------------------------------------- #

def test_duplicate_command_delivery_prints_no_second_sheet(tmp_path):
    db, devices = seed(tmp_path)
    _printed(db, devices, 'B', 'SER-0002', 'opaque_pickup')
    printer, _ = build_devices(db, devices, CASE)
    before = len(printer.emitted_serials())
    result = redeliver_command(db, 'SER-0002', devices)
    assert result['emissions_added'] == 0
    assert result['ack']['duplicate_delivery'] is True
    assert len(printer.emitted_serials()) == before


def test_nonce_reuse_with_different_content_is_rejected(tmp_path):
    db, devices = seed(tmp_path)
    _printed(db, devices, 'B', 'SER-0002', 'opaque_pickup')
    con = connect(db)
    row = con.execute(
        'SELECT nonce,content_sha256,sheet_bytes FROM serial_ledger WHERE serial=?',
        ('SER-0002',)).fetchone()
    con.close()
    printer, _ = build_devices(db, devices, CASE)
    with pytest.raises(PrinterError) as exc:
        printer.print_label(nonce=row['nonce'], serial='SER-0002',
                            content_sha256='f' * 64,
                            sheet_bytes=bytes(row['sheet_bytes']))
    assert exc.value.code == 'nonce_reuse_conflict'


def test_late_ack_reconciled_from_printer_journal(tmp_path):
    db, devices = seed(tmp_path)
    reserve(db, CASE, 'B', 'opaque_pickup', serial='SER-0002')
    outcome = send_print(db, 'SER-0002', devices, simulate_lost_ack=True)
    assert outcome['status'] == 'ack_lost'
    # Ledger still thinks reserved, but paper exists in the device journal.
    assert state_of(db, 'SER-0002') == 'reserved'
    recon = reconcile_print(db, 'SER-0002', devices)
    assert recon['status'] == 'emission_confirmed'
    assert state_of(db, 'SER-0002') == 'printed'
    # Re-delivery of the same nonce must not emit a second physical sheet.
    redeliver = redeliver_command(db, 'SER-0002', devices)
    assert redeliver['emissions_added'] == 0
    assert apply_label(db, 'SER-0002', devices, 'B')['status'] == 'applied'


# --------------------------------------------------------------------------- #
# Recipient contract revision: old bytes cannot impersonate the new label
# --------------------------------------------------------------------------- #

def _revised_contract(tmp_path, new_recipient='CLIENT-ALPHA-NEW'):
    contract = json.loads(FIXTURE.read_text(encoding='utf-8'))
    for item in contract['labels']:
        if item['box_id'] == 'A':
            item['recipient'] = new_recipient
    path = tmp_path / 'revised-contract.json'
    path.write_text(json.dumps(contract, ensure_ascii=False), encoding='utf-8')
    return path


def test_contract_revision_invalidates_old_sheet_binding(tmp_path):
    db, devices = seed(tmp_path)
    _printed(db, devices, 'A', 'SER-0001', 'direct_recipient')
    revised = _revised_contract(tmp_path)
    version = revise_contract(db, revised)
    assert version == 2
    # The old physical sheet exists and was printed, but can no longer be applied.
    with pytest.raises(ScanRejection) as exc:
        apply_label(db, 'SER-0001', devices, 'A')
    assert exc.value.code == 'binding_stale_contract_revised'
    # Explicit correction: void the old label, reprint under the new binding.
    record_destruction(db, 'SER-0001', 'recipient changed; old paper removed')
    revoke(db, 'SER-0001', 'contract_revision')
    out = reprint(db, 'SER-0001', devices, 'contract v2', auto_apply=True)
    new_serial = out['new_serial']
    new_paper = paper_bytes(devices, new_serial).decode('utf-8')
    assert 'CLIENT-ALPHA-NEW' in new_paper
    con = connect(db)
    row = con.execute(
        'SELECT contract_version,source_digest FROM serial_ledger WHERE serial=?',
        (new_serial,)).fetchone()
    assert row['contract_version'] == 2
    assert row['source_digest'] != con.execute(
        'SELECT source_digest FROM serial_ledger WHERE serial=?',
        ('SER-0001',)).fetchone()[0]
    con.close()


def test_identical_revision_is_rejected(tmp_path):
    db, _ = seed(tmp_path)
    with pytest.raises(ValueError) as exc:
        revise_contract(db, FIXTURE)
    assert str(exc.value) == 'contract_unchanged'


# --------------------------------------------------------------------------- #
# Immutability, replacement traceability and reports
# --------------------------------------------------------------------------- #

def test_audit_events_and_destruction_evidence_are_append_only(tmp_path):
    db, devices = seed(tmp_path)
    _printed(db, devices, 'A', 'SER-0001', 'direct_recipient')
    record_destruction(db, 'SER-0001', 'shredded')
    con = sqlite3.connect(str(db))
    with pytest.raises(sqlite3.IntegrityError):
        con.execute('DELETE FROM label_event WHERE serial=?', ('SER-0001',))
    with pytest.raises(sqlite3.IntegrityError):
        con.execute('UPDATE label_event SET event=? WHERE serial=?',
                    ('tampered', 'SER-0001'))
    con.close()
    # Re-registering destruction for the same sheet is refused.
    with pytest.raises(ValueError) as exc:
        record_destruction(db, 'SER-0001', 'second claim')
    assert str(exc.value) == 'destruction_evidence_immutable'


def test_database_rollback_does_not_erase_physical_paper(tmp_path):
    db, devices = seed(tmp_path)
    reserve(db, CASE, 'B', 'opaque_pickup', serial='SER-0002')
    send_print(db, 'SER-0002', devices)
    paper = paper_bytes(devices, 'SER-0002')
    # Simulate an application-side rollback after the paper already exists.
    con = sqlite3.connect(str(db))
    con.execute('BEGIN')
    con.execute("UPDATE serial_ledger SET state='reserved' WHERE serial='SER-0002'")
    con.rollback()
    con.close()
    assert Path(paper).exists() if isinstance(paper, Path) else True
    assert paper_bytes(devices, 'SER-0002') == paper
    # Reconciliation restores the truth from the device journal.
    assert reconcile_print(db, 'SER-0002', devices)['status'] == 'emission_confirmed'


def test_replacement_chain_is_traceable_end_to_end(tmp_path):
    db, devices = seed(tmp_path)
    reserve(db, CASE, 'A', 'direct_recipient', serial='SER-0001')
    send_print(db, 'SER-0001', devices)
    recover_jam(db, 'SER-0001', devices, 'paper_destroyed', 'jam damage')
    data = build_report(db, devices)
    chain = {(c['serial']): c for c in data['replacement_chains']}
    assert chain['SER-0001']['replaced_by'] == 'SER-0003'
    assert chain['SER-0003']['replaces'] == 'SER-0001'
    usable = {r['box_id']: r['serial'] for r in data['current_usable']}
    assert usable == {'A': 'SER-0003'}


def test_report_lists_current_serials_and_all_uncertain_paper(tmp_path):
    db, devices = seed(tmp_path)
    reserve(db, CASE, 'A', 'direct_recipient', serial='SER-0001')
    send_print(db, 'SER-0001', devices)
    recover_jam(db, 'SER-0001', devices, 'whereabouts_unknown')
    out = report(db, devices, tmp_path / 'label-audit.json')
    data = json.loads(out.read_text(encoding='utf-8'))
    # Quarantined serial is not a usable label.
    assert data['current_usable'] == []
    uncertain = {p['serial'] for p in data['uncertain_or_voided_paper']}
    assert 'SER-0001' in uncertain
    assert all(j['chain_ok'] for j in data['device_journals'].values())
    md = out.with_suffix('.md').read_text(encoding='utf-8')
    assert '实体标签制发审计报告' in md and 'SER-0001' in md


def test_device_journals_detect_tampering(tmp_path):
    db, devices = seed(tmp_path)
    _printed(db, devices, 'B', 'SER-0002', 'opaque_pickup')
    printer, scanner = build_devices(db, devices, CASE)
    assert verify_chain(printer.journal)[0]
    assert verify_chain(scanner.journal)[0]
    lines = printer.journal.read_text(encoding='utf-8').splitlines()
    record = json.loads(lines[0])
    record['serial'] = 'SER-9999'
    lines[0] = json.dumps(record, sort_keys=True, ensure_ascii=False)
    printer.journal.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    ok, index = verify_chain(printer.journal)
    assert ok is False and index == 0


def test_reprint_auto_applies_in_one_explicit_correction(tmp_path):
    """A revoked serial with destruction evidence is replaced and the fresh
    paper reaches 'applied' through read-back, without stalling at 'printed'."""
    db, devices = seed(tmp_path)
    _printed(db, devices, 'B', 'SER-0002', 'opaque_pickup')
    record_destruction(db, 'SER-0002', 'misprint shredded')
    revoke(db, 'SER-0002', 'misprint')
    out = reprint(db, 'SER-0002', devices, 'correction', auto_apply=True)
    assert out['new_serial'] == 'SER-0003'
    assert state_of(db, out['new_serial']) == 'applied'
    assert out['print']['apply']['status'] == 'applied'
    con = connect(db)
    chain = con.execute(
        'SELECT replaces_serial FROM serial_ledger WHERE serial=?',
        (out['new_serial'],)).fetchone()
    assert chain['replaces_serial'] == 'SER-0002'
    con.close()


def test_reprint_that_hits_a_jam_still_converges_and_applies(tmp_path, monkeypatch):
    """If the replacement sheet itself jams after emission, auto_apply must
    converge from the printer journal rather than leave a stranded label."""
    from coldhandoff import labels as labels_mod
    from coldhandoff.devices import Printer

    db, devices = seed(tmp_path)
    _printed(db, devices, 'A', 'SER-0001', 'direct_recipient')
    record_destruction(db, 'SER-0001', 'damaged')
    revoke(db, 'SER-0001', 'damage')
    original = labels_mod.build_devices

    def jam_on_replacement(path, device_dir, case_id):
        _, scanner = original(path, device_dir, case_id)
        # The replacement mints SER-0003; force the same fault shape on it.
        return Printer(device_dir, 'PRN-1', jam_after_serial='SER-0003'), scanner

    monkeypatch.setattr(labels_mod, 'build_devices', jam_on_replacement)
    out = reprint(db, 'SER-0001', devices, 'jam drill', auto_apply=True)
    assert out['new_serial'] == 'SER-0003'
    assert out['print']['status'] == 'jammed_after_emission'
    assert state_of(db, 'SER-0003') == 'applied'
    # Paper exists for the replacement despite the jam before ACK.
    assert paper_bytes(devices, 'SER-0003')


def test_an_already_replaced_serial_cannot_be_reprinted_again(tmp_path):
    db, devices = seed(tmp_path)
    reserve(db, CASE, 'A', 'direct_recipient', serial='SER-0001')
    send_print(db, 'SER-0001', devices)
    recover_jam(db, 'SER-0001', devices, 'paper_destroyed', 'damaged')
    # recover_jam already produced SER-0003; a second reprint must be refused.
    with pytest.raises(ValueError) as exc:
        reprint(db, 'SER-0001', devices, 'duplicate correction')
    assert str(exc.value) == 'serial_already_replaced:SER-0003'
