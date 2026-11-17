from pathlib import Path
from coldhandoff.__main__ import init
from coldhandoff.labels import register
from coldhandoff.store import connect


def test_label_case_binds_boxes_without_temperature_decisions(tmp_path):
    db = tmp_path / 'cold.db'
    for box in ('A', 'B'):
        init(db, 'batch-1', box)
    contract = Path(__file__).parents[1] / 'fixtures' / 'label-contract.json'
    assert register(db, contract) == 'label-run-2030-06-05'
    con = connect(db)
    row = con.execute('SELECT * FROM label_case').fetchone()
    assert row['box_digest'] and row['contract_sha256']
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0] == 0
    con.close()
