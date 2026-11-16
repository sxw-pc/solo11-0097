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

def test_demo_repeat_is_deterministic(tmp_path):
    first=demo(tmp_path).read_bytes()
    second=demo(tmp_path).read_bytes()
    assert first==second

def test_source_hash_and_event_chain(tmp_path):
    data=json.loads(demo(tmp_path).read_text(encoding='utf-8'))
    assert len(data['sources'][0]['hash'])==64
    assert len(data['events'])==7
    assert json.loads(data['decisions'][0]['detail'])['events']
def test_no_clock_anchor_is_untrusted(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[ev('dispatch',1)],db);evaluate(db)
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='clock_untrusted'").fetchone()[0]
def test_matching_seal_does_not_create_mismatch(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[ev('open',1,seal='A'),ev('reseal',2,'2026-01-01T00:01:00Z',seal='A')],db);evaluate(db)
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='seal_mismatch'").fetchone()[0]==0
def test_overlap_retains_both_raw_events(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[ev('temperature',1,value=4),ev('temperature',2,value=5)],db);evaluate(db)
    assert connect(db).execute("SELECT count(*) FROM raw_event WHERE kind='temperature'").fetchone()[0]==2
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='temperature_overlap'").fetchone()[0]==1
def test_bad_time_is_isolated(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[ev('dispatch',1,ts='bad')],db)
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='parse_error'").fetchone()[0]==1
def test_init_is_idempotent(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x');init(db,'b','x')
    assert connect(db).execute('SELECT count(*) FROM box').fetchone()[0]==1
def test_markdown_report_exists(tmp_path):
    path=demo(tmp_path)
    assert path.with_suffix('.md').exists()

def test_evidence_and_run_are_persisted(tmp_path):
    data=json.loads(demo(tmp_path).read_text(encoding='utf-8'))
    assert data["runs"]
    assert data['evidence']
    assert all(e['run_id'] for e in data['evidence'])

def test_unknown_box_replays_after_registration(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    event=ev('dispatch',1);event['box_id']='later';emit(tmp_path,[event],db)
    init(db,'b','later')
    assert json.loads(connect(db).execute("SELECT payload FROM raw_event WHERE box_id='later'").fetchone()[0])['kind']=='dispatch'
    assert 'later' in evaluate(db)
def test_clock_offset_from_anchor_pair(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    one=ev('clock_anchor',1,device_time='2026-01-01T00:00:00Z',reference_time='2026-01-01T00:00:10Z')
    two=ev('clock_anchor',2,'2026-01-01T00:10:00Z',device_time='2026-01-01T00:10:00Z',reference_time='2026-01-01T00:10:10Z')
    emit(tmp_path,[one,two,ev('dispatch',3,'2026-01-01T00:11:00Z')],db);evaluate(db)
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='clock_drift'").fetchone()[0]==0
def test_decision_links_run_and_evidence(tmp_path):
    data=json.loads(demo(tmp_path).read_text(encoding='utf-8'))
    assert data['decisions'][0]['run_id']==data['runs'][0]['id']
    assert set(json.loads(data['decisions'][0]['detail'])['events']) <= {e['object_id'] for e in data['evidence']}
