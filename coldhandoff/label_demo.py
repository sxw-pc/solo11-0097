"""Offline demonstration of physical label production (synthetic data only).

Produces both authorised layouts as separate jobs and exercises the full
lifecycle — reservation, nonce-bound printing, the PRN-1 jam injection,
three-way recovery, scan verification, destruction evidence and reprint —
then writes JSON/Markdown audit reports and the physical label byte files.
No real hardware is contacted.
"""
import json
from pathlib import Path

from .devices import verify_chain
from .labels import (register, open_job, reserve, send_print, apply_label,
                     reconcile_print, record_destruction, revoke, reprint,
                     report, current_usable, _latest_contract, _contract_item)
from .sheet import render_sheet
from .store import connect

CASE = 'label-run-2030-06-05'
FIXTURE = Path(__file__).resolve().parents[1] / 'fixtures' / 'label-contract.json'


def _init_box(db_path, batch_id, box_id):
    db = connect(db_path)
    with db:
        db.execute('INSERT OR IGNORE INTO batch VALUES (?,?,?,?)',
                   (batch_id, 2.0, 8.0, 10))
        db.execute('INSERT OR IGNORE INTO box VALUES (?,?)',
                   (box_id, batch_id))
    db.close()


def label_demo(workdir):
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    db = workdir / 'coldhandoff.db'
    devices = workdir / 'devices'
    for box in ('A', 'B'):
        _init_box(db, 'batch-1', box)
    register(db, FIXTURE)

    # Layout 1 (authorised, confirmed): direct recipient names on paper.
    job = open_job(db, CASE, 'direct_recipient')
    reserve(db, CASE, 'A', 'direct_recipient', serial='SER-0001', job_id=job)
    jammed = send_print(db, 'SER-0001', devices)
    assert jammed['status'] == 'jammed_after_emission'
    # Recovery starts from the immutable printer emission journal.
    reconcile_print(db, 'SER-0001', devices)
    apply_label(db, 'SER-0001', devices, 'A')
    reserve(db, CASE, 'B', 'direct_recipient', serial='SER-0002', job_id=job)
    send_print(db, 'SER-0002', devices)
    apply_label(db, 'SER-0002', devices, 'B')

    # Correction workflow on box A: void an applied label and reprint.
    record_destruction(db, 'SER-0001', 'demo: first sheet removed for reprint drill')
    revoke(db, 'SER-0001', 'demo_reprint_drill')
    reprint(db, 'SER-0001', devices, 'demo drill', auto_apply=True)

    # Layout 2 (the unexecuted control): render the opaque bytes as a paperless
    # plan. Nothing is sent to PRN-1 and no ledger serial is created, so the
    # one-active-label-per-box invariant is untouched.
    con = connect(db)
    contract = _latest_contract(con, CASE)
    item_a = _contract_item(contract, 'A')
    control_sheet = render_sheet(
        case_id=CASE, contract_sha256=contract['contract_sha256'],
        box_id='A', serial='SER-CONTROL-NOT-ISSUED', mode='opaque_pickup',
        recipient=item_a['recipient'], opaque_id=item_a['opaque_id'])
    con.close()
    control_path = workdir / 'control-opaque-A.unprinted.lbl'
    control_path.write_bytes(control_sheet['sheet_bytes'])
    control = {'serial': 'SER-CONTROL-NOT-ISSUED',
               'sheet_bytes': control_sheet['sheet_bytes'],
               'content_sha256': control_sheet['content_sha256']}

    out = report(db, devices, workdir / 'label-audit.json')
    summary = {
        'case_id': CASE,
        'current_usable': current_usable(db),
        'unexecuted_control_layout': {'mode': 'opaque_pickup',
                                      'serial': control['serial'],
                                      'content_sha256': control['content_sha256'],
                                      'rendered_but_not_printed': True,
                                      'path': str(control_path)},
        'report_json': str(out),
        'report_markdown': str(out.with_suffix('.md')),
        'paper_dir': str(devices / 'PRN-1' / 'paper'),
    }
    (workdir / 'label-demo-summary.json').write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    con = connect(db)
    chains = {str(p): verify_chain(p)[0]
              for p in (devices / 'PRN-1').glob('*.jsonl')}
    chains.update({str(p): verify_chain(p)[0]
                   for p in (devices / 'SCAN-1').glob('*.jsonl')})
    con.close()
    assert all(chains.values())
    return out
