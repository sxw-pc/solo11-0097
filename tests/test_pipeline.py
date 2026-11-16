import json
from pathlib import Path
from coldhandoff.__main__ import demo,init
from coldhandoff.ingest import ingest
from coldhandoff.rules import evaluate
from coldhandoff.store import connect

def test_demo(tmp_path):
    path=demo(tmp_path)
    data=json.loads(path.read_text(encoding='utf-8'))
    assert data['decisions'][0]['result']=='完整'
    assert len(data['sources'])==1

def test_duplicate_and_conflict(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    event={'kind':'dispatch','device':'d','seq':1,'box_id':'x','event_time':'2026-01-01T00:00:00Z'}
    a=tmp_path/'a.jsonl';a.write_text(json.dumps(event),encoding='utf-8')
    assert ingest(a,db)['imported']==1
    assert ingest(a,db)['duplicate_file']
    event['kind']='arrival';b=tmp_path/'b.jsonl';b.write_text(json.dumps(event),encoding='utf-8')
    ingest(b,db)
    con=connect(db)
    assert con.execute("SELECT count(*) FROM issue WHERE code='identity_conflict'").fetchone()[0]==1

def test_missing_evidence_never_complete(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    assert evaluate(db)['x']=='证据不足'

def test_unknown_box_is_isolated(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    p=tmp_path/'x.jsonl';p.write_text(json.dumps({'kind':'dispatch','device':'d','seq':1,'box_id':'other','event_time':'2026-01-01T00:00:00Z'}),encoding='utf-8')
    ingest(p,db)
    c=connect(db)
    assert c.execute("SELECT count(*) FROM issue WHERE code='unknown_box'").fetchone()[0]==1
