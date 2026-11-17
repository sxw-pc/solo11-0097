from pathlib import Path
from coldhandoff.__main__ import init
from coldhandoff.assets import register
from coldhandoff.store import connect


def test_asset_cycle_binds_existing_boxes(tmp_path):
    db = tmp_path / 'cold.db'
    for box in 'ABCD':
        init(db, 'batch-1', box)
    contract = Path(__file__).parents[1] / 'fixtures' / 'asset-cycle.json'
    assert register(db, contract) == 'asset-cycle-2030-06-02'
    con = connect(db)
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0] == 0
    assert con.execute('SELECT box_digest FROM asset_case').fetchone()[0]
    con.close()
