import json
from collections import defaultdict
from datetime import timedelta

from .ingest import parse_time
from .store import connect

VERSION='1'

def evaluate(db_path):
    db=connect(db_path)
    output={}
    with db:
        db.execute('DELETE FROM decision')
        db.execute("DELETE FROM issue WHERE code IN ('sequence_gap','clock_drift','bad_transition','seal_mismatch','temperature_gap','temperature_excursion','missing_stage')")
        batches={r['id']:r for r in db.execute('SELECT * FROM batch')}
        all_events=[dict(r) for r in db.execute('SELECT * FROM raw_event ORDER BY event_time,id')]
        by_box=defaultdict(list); by_device=defaultdict(list)
        for event in all_events:
            by_box[event['box_id']].append(event)
            by_device[event['device']].append(event)
        bad_device=set()
        for device,events in by_device.items():
            seqs=sorted({e['seq'] for e in events})
            if seqs and seqs[-1]-seqs[0]+1!=len(seqs):
                bad_device.add(device)
                db.execute('INSERT INTO issue(code,detail) VALUES (?,?)',('sequence_gap',device))
            anchors=[e for e in events if e['kind']=='clock_anchor']
            for a,b in zip(anchors,anchors[1:]):
                pa,pb=json.loads(a['payload']),json.loads(b['payload'])
                if abs(float(pa.get('offset_seconds',0))-float(pb.get('offset_seconds',0)))>120:
                    bad_device.add(device)
                    db.execute('INSERT INTO issue(code,detail) VALUES (?,?)',('clock_drift',device))
        for box in db.execute('SELECT * FROM box'):
            events=by_box[box['id']]
            problems=[]
            stages=[e for e in events if e['kind'] in {'dispatch','arrival','sign'}]
            actual=[e['kind'] for e in stages]
            if actual!=['dispatch','arrival','sign']:
                problems.append('bad_transition' if len(actual)!=len(set(actual)) or actual!=sorted(actual,key={'dispatch':0,'arrival':1,'sign':2}.get) else 'missing_stage')
            seals=[]
            for e in events:
                if e['kind']=='open': seals.append(json.loads(e['payload']).get('seal'))
                if e['kind']=='reseal':
                    seal=json.loads(e['payload']).get('seal')
                    if not seals or seals.pop()!=seal: problems.append('seal_mismatch')
            if seals: problems.append('seal_mismatch')
            temps=[e for e in events if e['kind']=='temperature']
            temps.sort(key=lambda e:parse_time(e['event_time']))
            spec=batches[box['batch_id']]
            if stages and temps:
                start=parse_time(stages[0]['event_time']); end=parse_time(stages[-1]['event_time'])
                times=[parse_time(e['event_time']) for e in temps]
                if times[0]>start or times[-1]<end or any(b-a>timedelta(minutes=30) for a,b in zip(times,times[1:])):
                    problems.append('temperature_gap')
            else: problems.append('temperature_gap')
            bad_start=None
            for e in temps:
                t=parse_time(e['event_time']); value=float(json.loads(e['payload']).get('value',0))
                if value<spec['min_temp'] or value>spec['max_temp']:
                    if bad_start is None: bad_start=t
                    if (t-bad_start).total_seconds()>=60*spec['max_excursion_min']:
                        problems.append('temperature_excursion')
                else: bad_start=None
            if any(e['device'] in bad_device for e in events): problems.append('sequence_gap')
            for code in sorted(set(problems)):
                db.execute('INSERT INTO issue(code,detail) VALUES (?,?)',(code,box['id']))
            result='异常' if any(p in problems for p in ('bad_transition','seal_mismatch','temperature_excursion')) else ('证据不足' if problems else '完整')
            detail=json.dumps({'events':[e['id'] for e in events],'problems':sorted(set(problems))},ensure_ascii=False)
            db.execute('INSERT INTO decision VALUES (?,?,?,?)',(box['id'],result,detail,VERSION))
            output[box['id']]=result
    db.close()
    return output
