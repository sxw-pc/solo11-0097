import json
from pathlib import Path
from coldhandoff.__main__ import init
from coldhandoff.archive import register
from coldhandoff.ingest import ingest
from coldhandoff.store import connect


def test_archive_case_freezes_shifted_overlapping_raw_sources(tmp_path):
    db = tmp_path / 'cold.db'
    init(db, 'batch-1', 'A')
    lines = [json.dumps({'kind':'temperature','device':'logger-1','seq':i,
                         'box_id':'A','event_time':f'2030-06-07T00:{i:02d}:00Z','value':4},
                        separators=(',',':')) for i in range(1,21)]
    inserted = json.dumps({'kind':'temperature','device':'logger-1','seq':21,
                           'box_id':'A','event_time':'2030-06-07T00:21:00Z','value':5},
                          separators=(',',':'))
    first = tmp_path / 'first.jsonl'
    second = tmp_path / 'second.jsonl'
    first.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    second.write_text(inserted+'\n'+'\n'.join(lines)+'\n',encoding='utf-8')
    ingest(first,db)
    ingest(second,db)
    contract = Path(__file__).parents[1] / 'fixtures' / 'archive-contract.json'
    assert register(db, contract) == 'cold-sources-2030-06-07'
    con = connect(db)
    rows = list(con.execute('SELECT raw FROM source_file ORDER BY id'))
    assert len(rows) == 2 and rows[1]['raw'].endswith(rows[0]['raw'])
    assert con.execute('SELECT source_digest FROM archive_case').fetchone()[0]
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0] == 0
    con.close()
