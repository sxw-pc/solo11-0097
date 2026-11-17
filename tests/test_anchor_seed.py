from pathlib import Path
from coldhandoff.__main__ import init
from coldhandoff.ingest import ingest
from coldhandoff.audit_anchor import register
from coldhandoff.store import connect


def test_anchor_case_uses_two_real_ingested_sources(tmp_path):
    db=tmp_path/'cold.db'
    for box in ('A','B'):
        init(db,'batch-1',box)
    fixtures=Path(__file__).parents[1]/'fixtures'
    ingest(fixtures/'source-one.jsonl',db)
    ingest(fixtures/'source-two.jsonl',db)
    assert register(db,fixtures/'anchor-contract.json')=='source-anchor-2030-06-09'
    con=connect(db)
    assert con.execute('SELECT count(*) FROM source_file').fetchone()[0]==2
    assert con.execute('SELECT source_snapshot FROM anchor_case').fetchone()[0]
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0]==0
    con.close()
