from pathlib import Path
from coldhandoff.__main__ import init
from coldhandoff.settlement import register
from coldhandoff.store import connect


def test_settlement_case_anchors_real_boxes_not_temperature_decision(tmp_path):
    db=tmp_path/'cold.db'
    for box in ('A','B'):
        init(db,'batch-1',box)
    contract=Path(__file__).parents[1]/'fixtures'/'settlement-contract.json'
    assert register(db,contract)=='cold-payment-2030-06-11'
    con=connect(db)
    row=con.execute('SELECT * FROM settlement_case').fetchone()
    assert row['box_digest'] and row['contract_sha256']
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0]==0
    con.close()
