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

def test_raw_source_is_retained_after_input_changes(tmp_path):
    path=demo(tmp_path)
    before=path.read_bytes()
    db=tmp_path/"coldhandoff.db"
    con=connect(db)
    row=con.execute("SELECT path,raw FROM source_file LIMIT 1").fetchone() if "source_file"!='source_file' else con.execute('SELECT name AS path,raw FROM source_file LIMIT 1').fetchone()
    from pathlib import Path
    preserved=bytes(row['raw'])
    Path(row['path']).write_bytes(b'changed after import')
    assert bytes(con.execute("SELECT raw FROM source_file LIMIT 1").fetchone()[0])==preserved
    assert before and preserved


# --- 温度时间校正策略 ---
# 共享 fixture：同一设备跨越两个锚点（08:00 偏移 0s，08:30 偏移 -600s），
# 交接事件 dispatch 08:00 / arrival 08:12 / sign 08:12，两条 12°C 高温样本 08:00 与 08:12。
# 阶梯规则下偏移恒为 0，暴露 = 12 分钟 ≥ 阈值 10 → 异常；
# 线性规则下 08:12 插值偏移 -240s → 校正为 08:08，暴露 = 8 分钟 < 10 → 完整。
from coldhandoff.ingest import parse_time
from coldhandoff.__main__ import report

def correction_fixture(tmp_path,db):
    rows=[
        {'kind':'clock_anchor','device':'d','seq':1,'box_id':'','event_time':'2026-01-01T08:00:00Z','offset_seconds':0},
        {'kind':'clock_anchor','device':'d','seq':2,'box_id':'','event_time':'2026-01-01T08:30:00Z','offset_seconds':-600},
        {'kind':'dispatch','device':'d','seq':3,'box_id':'x','event_time':'2026-01-01T08:00:00Z'},
        {'kind':'temperature','device':'d','seq':4,'box_id':'x','event_time':'2026-01-01T08:00:00Z','value':12},
        {'kind':'temperature','device':'d','seq':5,'box_id':'x','event_time':'2026-01-01T08:12:00Z','value':12},
        {'kind':'arrival','device':'d','seq':6,'box_id':'x','event_time':'2026-01-01T08:12:00Z'},
        {'kind':'sign','device':'d','seq':7,'box_id':'x','event_time':'2026-01-01T08:12:00Z'},
    ]
    emit(tmp_path,rows,db)

def test_step_rule_flags_twelve_minute_excursion(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x',correction='step',max_clock_drift_s=900)
    correction_fixture(tmp_path,db)
    assert evaluate(db)['x']=='异常'
    con=connect(db)
    assert con.execute("SELECT count(*) FROM issue WHERE code='temperature_excursion'").fetchone()[0]==1
    detail=json.loads(con.execute("SELECT detail FROM decision WHERE box_id='x'").fetchone()[0])
    assert detail['correction_rule']=='step'
    assert detail['exposure']['threshold_min']==10
    assert detail['exposure']['max_min']==12.0
    assert '12.0min' in detail['exposure']['formula']

def test_linear_rule_interpolates_exposure_below_threshold(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x',correction='linear',max_clock_drift_s=900)
    correction_fixture(tmp_path,db)
    assert evaluate(db)['x']=='完整'
    con=connect(db)
    detail=json.loads(con.execute("SELECT detail FROM decision WHERE box_id='x'").fetchone()[0])
    assert detail['correction_rule']=='linear'
    assert detail['exposure']['max_min']==8.0
    assert '8.0min' in detail['exposure']['formula']
    rows=con.execute("SELECT * FROM time_correction WHERE status='ok'").fetchall()
    assert len(rows)==5
    late=[r for r in rows if r['raw_time']=='2026-01-01T08:12:00Z']
    assert late and all(parse_time(r['corrected_time'])==parse_time('2026-01-01T08:08:00Z') for r in late)

def test_same_fixture_step_abnormal_linear_complete(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x',correction='step',max_clock_drift_s=900)
    correction_fixture(tmp_path,db)
    assert evaluate(db)['x']=='异常'
    con=connect(db);con.execute("UPDATE batch SET correction='linear' WHERE id='b'");con.commit();con.close()
    assert evaluate(db)['x']=='完整'

def test_report_carries_raw_corrected_anchor_evidence_and_formula(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x',correction='linear',max_clock_drift_s=900)
    correction_fixture(tmp_path,db);evaluate(db)
    data=json.loads(report(db,tmp_path/'report.json').read_text(encoding='utf-8'))
    assert data['corrections'] and data['batches'][0]['correction']=='linear'
    anchors={e['id'] for e in data['events'] if e['kind']=='clock_anchor'}
    ok=[c for c in data['corrections'] if c['status']=='ok']
    assert ok and all(c['raw_time'] and c['corrected_time'] and c['formula'] for c in ok)
    assert {c['anchor_before'] for c in ok} <= anchors
    assert {c['anchor_after'] for c in ok} <= anchors
    detail=json.loads(data['decisions'][0]['detail'])
    assert detail['window']['formula'] and detail['exposure']['formula']
    assert all(c['raw_time'] and c['corrected_time'] for c in detail['corrections'])

def test_dual_anchor_linear_interpolation(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x',correction='linear',max_clock_drift_s=900)
    emit(tmp_path,[
        {'kind':'clock_anchor','device':'d','seq':1,'box_id':'','event_time':'2026-01-01T08:00:00Z','offset_seconds':0},
        {'kind':'clock_anchor','device':'d','seq':2,'box_id':'','event_time':'2026-01-01T08:30:00Z','offset_seconds':-600},
        {'kind':'dispatch','device':'d','seq':3,'box_id':'x','event_time':'2026-01-01T08:15:00Z'}],db)
    evaluate(db)
    con=connect(db)
    cor=con.execute("SELECT * FROM time_correction WHERE status='ok'").fetchone()
    assert parse_time(cor['corrected_time'])==parse_time('2026-01-01T08:10:00Z')
    assert cor['uncertainty_seconds']==300.0
    anchor_ids={r['id'] for r in con.execute("SELECT id FROM raw_event WHERE kind='clock_anchor'")}
    assert {cor['anchor_before'],cor['anchor_after']}==anchor_ids
    assert 'linear' in cor['formula'] and '-300.0s' in cor['formula']

def test_step_boundary_applies_anchor_at_exact_time(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[
        {'kind':'clock_anchor','device':'d','seq':1,'box_id':'','event_time':'2026-01-01T08:00:00Z','offset_seconds':0},
        {'kind':'clock_anchor','device':'d','seq':2,'box_id':'','event_time':'2026-01-01T08:30:00Z','offset_seconds':60},
        {'kind':'temperature','device':'d','seq':3,'box_id':'x','event_time':'2026-01-01T08:29:59Z','value':4},
        {'kind':'temperature','device':'d','seq':4,'box_id':'x','event_time':'2026-01-01T08:30:00Z','value':4}],db)
    evaluate(db)
    rows=connect(db).execute("SELECT raw_time,corrected_time FROM time_correction WHERE status='ok' ORDER BY raw_time").fetchall()
    assert parse_time(rows[0]['corrected_time'])==parse_time('2026-01-01T08:29:59Z')
    assert parse_time(rows[1]['corrected_time'])==parse_time('2026-01-01T08:31:00Z')

def test_drift_exceeded_never_falls_back_silently(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[
        {'kind':'clock_anchor','device':'d','seq':1,'box_id':'','event_time':'2026-01-01T08:00:00Z','offset_seconds':0},
        {'kind':'clock_anchor','device':'d','seq':2,'box_id':'','event_time':'2026-01-01T08:30:00Z','offset_seconds':300},
        ev('dispatch',3,'2026-01-01T08:00:00Z'),ev('temperature',4,'2026-01-01T08:00:00Z',value=4),
        ev('arrival',5,'2026-01-01T08:10:00Z'),ev('sign',6,'2026-01-01T08:10:00Z')],db)
    assert evaluate(db)['x']=='证据不足'
    con=connect(db)
    assert con.execute("SELECT count(*) FROM issue WHERE code='clock_drift'").fetchone()[0]==1
    assert con.execute("SELECT count(*) FROM issue WHERE code='clock_untrusted'").fetchone()[0]
    rows=con.execute("SELECT * FROM time_correction").fetchall()
    assert rows and all(r['status']=='raw_fallback' and r['corrected_time'] is None for r in rows)

def test_anchor_disorder_blocks_correction(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[
        {'kind':'clock_anchor','device':'d','seq':1,'box_id':'','event_time':'2026-01-01T08:30:00Z','offset_seconds':0},
        {'kind':'clock_anchor','device':'d','seq':2,'box_id':'','event_time':'2026-01-01T08:00:00Z','offset_seconds':0},
        ev('dispatch',3,'2026-01-01T08:40:00Z')],db)
    assert evaluate(db)['x']=='证据不足'
    con=connect(db)
    assert con.execute("SELECT count(*) FROM issue WHERE code='clock_anchor_disorder'").fetchone()[0]==1
    assert con.execute("SELECT count(*) FROM time_correction WHERE status='raw_fallback'").fetchone()[0]==1

def test_missing_anchor_coverage_is_not_silent(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x',correction='linear')
    emit(tmp_path,[
        {'kind':'clock_anchor','device':'d','seq':1,'box_id':'','event_time':'2026-01-01T08:00:00Z','offset_seconds':0},
        ev('dispatch',2,'2026-01-01T08:05:00Z')],db)
    assert evaluate(db)['x']=='证据不足'
    con=connect(db)
    assert con.execute("SELECT count(*) FROM issue WHERE code='clock_uncorrectable'").fetchone()[0]==1
    row=con.execute("SELECT * FROM time_correction").fetchone()
    assert row['status']=='raw_fallback' and row['corrected_time'] is None and 'need_two_anchors' in row['formula']

def test_step_before_first_anchor_is_uncorrectable(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[
        {'kind':'clock_anchor','device':'d','seq':1,'box_id':'','event_time':'2026-01-01T08:30:00Z','offset_seconds':0},
        ev('dispatch',2,'2026-01-01T08:00:00Z')],db)
    assert evaluate(db)['x']=='证据不足'
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='clock_uncorrectable'").fetchone()[0]==1

def test_corrected_stage_order_flip_is_detected(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x')
    emit(tmp_path,[
        {'kind':'clock_anchor','device':'a','seq':1,'box_id':'','event_time':'2026-01-01T07:00:00Z','offset_seconds':600},
        {'kind':'dispatch','device':'a','seq':2,'box_id':'x','event_time':'2026-01-01T08:00:00Z'},
        {'kind':'clock_anchor','device':'b','seq':1,'box_id':'','event_time':'2026-01-01T07:00:00Z','offset_seconds':0},
        {'kind':'arrival','device':'b','seq':2,'box_id':'x','event_time':'2026-01-01T08:05:00Z'},
        {'kind':'sign','device':'b','seq':3,'box_id':'x','event_time':'2026-01-01T08:06:00Z'}],db)
    raw=[r['kind'] for r in connect(db).execute("SELECT kind FROM raw_event WHERE box_id='x' ORDER BY event_time,id")]
    assert raw==['dispatch','arrival','sign']
    assert evaluate(db)['x']=='异常'
    assert connect(db).execute("SELECT count(*) FROM issue WHERE code='bad_transition'").fetchone()[0]==1

def test_cross_box_isolation(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x');init(db,'b2','y')
    emit(tmp_path,[
        {'kind':'clock_anchor','device':'a','seq':1,'box_id':'','event_time':'2026-01-01T07:59:00Z','offset_seconds':0},
        {'kind':'dispatch','device':'a','seq':2,'box_id':'x','event_time':'2026-01-01T08:00:00Z'},
        {'kind':'temperature','device':'a','seq':3,'box_id':'x','event_time':'2026-01-01T08:00:00Z','value':4},
        {'kind':'temperature','device':'a','seq':4,'box_id':'x','event_time':'2026-01-01T08:20:00Z','value':4},
        {'kind':'temperature','device':'a','seq':5,'box_id':'x','event_time':'2026-01-01T08:40:00Z','value':4},
        {'kind':'arrival','device':'a','seq':6,'box_id':'x','event_time':'2026-01-01T08:40:00Z'},
        {'kind':'sign','device':'a','seq':7,'box_id':'x','event_time':'2026-01-01T08:40:00Z'},
        {'kind':'dispatch','device':'b','seq':1,'box_id':'y','event_time':'2026-01-01T08:00:00Z'}],db)
    out=evaluate(db)
    assert out['x']=='完整' and out['y']=='证据不足'
    con=connect(db)
    assert json.loads(con.execute("SELECT detail FROM decision WHERE box_id='x'").fetchone()[0])['problems']==[]
    assert con.execute("SELECT count(*) FROM issue WHERE code='clock_untrusted' AND detail='y'").fetchone()[0]==1
    assert con.execute("SELECT count(*) FROM issue WHERE detail='x'").fetchone()[0]==0

def test_raw_time_is_immutable_after_correction(tmp_path):
    db=tmp_path/'x.db';init(db,'b','x',correction='linear',max_clock_drift_s=900)
    correction_fixture(tmp_path,db)
    before={r['id']:r['event_time'] for r in connect(db).execute('SELECT id,event_time FROM raw_event')}
    evaluate(db)
    con=connect(db)
    after={r['id']:r['event_time'] for r in con.execute('SELECT id,event_time FROM raw_event')}
    assert before==after
    rows=con.execute("SELECT * FROM time_correction WHERE status='ok'").fetchall()
    assert rows and all(r['raw_time']==after[r['event_id']] for r in rows)
    assert any(parse_time(r['corrected_time'])!=parse_time(r['raw_time']) for r in rows)
