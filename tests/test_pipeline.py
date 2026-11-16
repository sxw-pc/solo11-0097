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


def emit(tmp_path, rows, db):
    f=tmp_path/'extra.jsonl'
    f.write_text('\n'.join(json.dumps(row) for row in rows),encoding='utf-8')
    ingest(f,db)

def ev(kind,seq,ts='2026-01-01T00:00:00Z',**kwargs):
    return {'kind':kind,'device':'d','seq':seq,'box_id':'x','event_time':ts,**kwargs}

def test_bad_transition_and_seal(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[ev('arrival',1),ev('dispatch',2,'2026-01-01T00:01:00Z'),ev('open',3,'2026-01-01T00:02:00Z',seal='a'),ev('reseal',4,'2026-01-01T00:03:00Z',seal='b')],db)
    assert evaluate(db)['x']=='异常'
    c=connect(db)
    assert c.execute("SELECT count(*) FROM issue WHERE code='seal_mismatch'").fetchone()[0]

def test_clock_drift_and_gap(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[ev('clock_anchor',1,offset_seconds=0),ev('clock_anchor',3,'2026-01-01T00:10:00Z',offset_seconds=300)],db)
    evaluate(db)
    c=connect(db)
    assert c.execute("SELECT count(*) FROM issue WHERE code='clock_drift'").fetchone()[0]
    assert c.execute("SELECT count(*) FROM issue WHERE code='sequence_gap'").fetchone()[0]

def test_excursion_is_not_average(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[ev('dispatch',1),ev('temperature',2,value=12),ev('temperature',3,'2026-01-01T00:11:00Z',value=12),ev('arrival',4,'2026-01-01T00:11:00Z'),ev('sign',5,'2026-01-01T00:11:00Z')],db)
    assert evaluate(db)['x']=='异常'
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='temperature_excursion'").fetchone()[0]

def test_gap_is_unknown(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[ev('dispatch',1),ev('temperature',2,value=4),ev('arrival',3,'2026-01-01T01:00:00Z'),ev('sign',4,'2026-01-01T01:00:00Z')],db)
    assert evaluate(db)['x']=='证据不足'
