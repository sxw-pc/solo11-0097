"""Seed contract tests: real business boxes A/B exist and labeling starts
from raw intake only — never from a temperature decision."""
from pathlib import Path

from coldhandoff.__main__ import init
from coldhandoff.labels import register, reserve, build_report
from coldhandoff.store import connect

CONTRACT = Path(__file__).parents[1] / 'fixtures' / 'label-contract.json'
CASE = 'label-run-2030-06-05'


def test_label_case_binds_boxes_without_temperature_decisions(tmp_path):
    db = tmp_path / 'cold.db'
    for box in ('A', 'B'):
        init(db, 'batch-1', box)
    assert register(db, CONTRACT) == CASE
    con = connect(db)
    row = con.execute('SELECT * FROM label_case').fetchone()
    assert row['box_digest'] and row['contract_sha256']
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0] == 0
    con.close()


def test_real_business_boxes_a_and_b_exist_before_labeling(tmp_path):
    db = tmp_path / 'cold.db'
    for box in ('A', 'B'):
        init(db, 'batch-1', box)
    register(db, CONTRACT)
    con = connect(db)
    boxes = {r['id'] for r in con.execute('SELECT id FROM box')}
    assert boxes == {'A', 'B'}
    # Both boxes belong to the same real batch in the business store.
    assert {r['batch_id'] for r in con.execute('SELECT batch_id FROM box')} == {'batch-1'}
    # The frozen contract assigns one unique serial per real box.
    import json
    contract = json.loads(con.execute(
        'SELECT contract_json FROM label_contract_version '
        'WHERE case_id=? AND version=1', (CASE,)).fetchone()[0])
    pairs = {(i['box_id'], i['serial']) for i in contract['labels']}
    assert pairs == {('A', 'SER-0001'), ('B', 'SER-0002')}
    con.close()


def test_unknown_box_contract_is_refused(tmp_path):
    db = tmp_path / 'cold.db'
    init(db, 'batch-1', 'A')
    import json
    bad = tmp_path / 'bad-contract.json'
    contract = json.loads(CONTRACT.read_text(encoding='utf-8'))
    contract['labels'][1]['box_id'] = 'GHOST'
    bad.write_text(json.dumps(contract), encoding='utf-8')
    try:
        register(db, bad)
    except ValueError as exc:
        assert str(exc) == 'unknown_box'
    else:  # pragma: no cover
        raise AssertionError('unknown box must be refused')


def test_label_reservation_works_without_any_temperature_run(tmp_path):
    db = tmp_path / 'cold.db'
    devices = tmp_path / 'devices'
    for box in ('A', 'B'):
        init(db, 'batch-1', box)
    register(db, CONTRACT)
    reserved = reserve(db, CASE, 'A', 'direct_recipient')
    assert reserved['serial'] == 'SER-0001'
    report = build_report(db, devices)
    con = connect(db)
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0] == 0
    con.close()
    # The ledger pins deterministic rendered bytes even with no decision data.
    assert report['serials'][0]['content_sha256'] == reserved['content_sha256']
