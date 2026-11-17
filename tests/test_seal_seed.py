from pathlib import Path
from coldhandoff.__main__ import init
from coldhandoff.ingest import ingest
from coldhandoff.seal_registry import register
from coldhandoff.store import connect


def test_seal_case_binds_two_actual_scans(tmp_path):
    db = tmp_path / 'cold.db'
    for box in ('A', 'B'):
        init(db, 'batch-1', box)
    fixtures = Path(__file__).parents[1] / 'fixtures'
    ingest(fixtures / 'seal-events.jsonl',db)
    assert register(db, fixtures / 'seal-ledger.json') == 'seal-S42-2030-06-06'
    con = connect(db)
    row = con.execute('SELECT * FROM seal_case').fetchone()
    assert row['serial']=='S-42' and row['observed_digest']
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0]==0
    con.close()
