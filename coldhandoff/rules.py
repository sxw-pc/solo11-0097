import json
from hashlib import sha256
from collections import defaultdict
from datetime import timedelta

from .ingest import parse_time
from .store import connect

VERSION='2'
CORRECTION_RULES=('step','linear')
DEFAULT_MAX_CLOCK_DRIFT_S=120
MAX_TEMP_GAP=timedelta(minutes=30)
STAGE_ORDER={'dispatch':0,'arrival':1,'sign':2}
RESET_ISSUES=('sequence_gap','clock_drift','bad_transition','seal_mismatch','temperature_gap',
    'temperature_excursion','temperature_overlap','clock_untrusted','missing_stage',
    'clock_uncorrectable','clock_anchor_disorder')

class Uncorrectable(Exception):
    """Anchor evidence cannot produce a corrected time; callers must not silently reuse raw time."""

def anchor_state(event):
    """Return (device_time, offset_seconds) of a clock anchor. offset = reference - device."""
    payload=json.loads(event['payload'])
    if 'device_time' in payload and 'reference_time' in payload:
        device=parse_time(payload['device_time'])
        return device,(parse_time(payload['reference_time'])-device).total_seconds()
    return parse_time(event['event_time']),float(payload['offset_seconds'])

def correct_time(t,anchors,rule):
    """Correct device time t under the given rule.

    anchors: [{'id','device_time','offset'}] sorted by device_time.
    Returns (corrected, uncertainty_seconds, anchor_lo, anchor_hi, formula).
    Raises Uncorrectable when anchor evidence does not cover t.
    """
    if not anchors: raise Uncorrectable('no_anchor')
    if rule=='step':
        lo=None
        for a in anchors:
            if a['device_time']<=t: lo=a
            else: break
        if lo is None: raise Uncorrectable('before_first_anchor')
        hi=next((a for a in anchors if a['device_time']>t),None)
        offset=lo['offset']
        unc=abs(hi['offset']-lo['offset']) if hi else 0.0
        formula=f"step: corrected=raw+({offset}s) from anchor#{lo['id']}@{lo['device_time'].isoformat()}"
        if hi: formula+=f"; next anchor#{hi['id']} offset={hi['offset']}s => uncertainty ±{unc}s"
        return t+timedelta(seconds=offset),unc,lo,hi,formula
    if rule=='linear':
        if len(anchors)<2: raise Uncorrectable('need_two_anchors')
        if t<anchors[0]['device_time'] or t>anchors[-1]['device_time']:
            raise Uncorrectable('outside_anchor_span')
        for lo,hi in zip(anchors,anchors[1:]):
            if lo['device_time']<=t<=hi['device_time']:
                span=(hi['device_time']-lo['device_time']).total_seconds()
                ratio=0.0 if span==0 else (t-lo['device_time']).total_seconds()/span
                offset=lo['offset']+(hi['offset']-lo['offset'])*ratio
                unc=abs(hi['offset']-lo['offset'])/2
                formula=(f"linear: offset={offset}s = {lo['offset']}+({hi['offset']}-{lo['offset']})*{ratio:.6f} "
                         f"between anchors #{lo['id']}@{lo['device_time'].isoformat()} and #{hi['id']}@{hi['device_time'].isoformat()}")
                return t+timedelta(seconds=offset),unc,lo,hi,formula
    raise Uncorrectable('unknown_rule')

def evaluate(db_path):
    db=connect(db_path)
    output={}
    with db:
        db.execute('DELETE FROM decision')
        db.execute('DELETE FROM time_correction')
        db.execute('DELETE FROM issue WHERE code IN (%s)'%','.join('?'*len(RESET_ISSUES)),RESET_ISSUES)
        batches={r['id']:dict(r) for r in db.execute('SELECT * FROM batch')}
        boxes=[dict(r) for r in db.execute('SELECT * FROM box')]
        box_batch={b['id']:b['batch_id'] for b in boxes}
        all_events=[dict(r) for r in db.execute('SELECT * FROM raw_event ORDER BY event_time,id')]
        source_digest=sha256('|'.join(r['hash'] for r in db.execute('SELECT hash FROM source_file ORDER BY hash')).encode()).hexdigest()
        run_id=sha256((VERSION+':'+source_digest).encode()).hexdigest()
        db.execute('INSERT OR IGNORE INTO run VALUES (?,?,?)',(run_id,VERSION,source_digest))
        for event in all_events:
            db.execute('INSERT OR REPLACE INTO evidence VALUES (?,?,?,?,?,?,?)',(event['hash'],run_id,event['box_id'] or '__clock__',event['source_id'],'raw_event',event['id'],event['hash']))
        by_box=defaultdict(list); by_device=defaultdict(list)
        for event in all_events:
            by_box[event['box_id']].append(event)
            by_device[event['device']].append(event)
        device_limits=defaultdict(set)
        for event in all_events:
            batch=box_batch.get(event['box_id'])
            if batch: device_limits[event['device']].add(batches[batch]['max_clock_drift_s'])
        device_anchors={}; device_drift={}; device_bad=set()
        for device,events in by_device.items():
            seqs=sorted({e['seq'] for e in events})
            if seqs and seqs[-1]-seqs[0]+1!=len(seqs):
                device_bad.add(device)
                db.execute('INSERT INTO issue(code,detail) VALUES (?,?)',('sequence_gap',device))
            anchors=[]
            for e in sorted((e for e in events if e['kind']=='clock_anchor'),key=lambda e:(e['seq'],e['id'])):
                device_time,offset=anchor_state(e)
                anchors.append({'id':e['id'],'device_time':device_time,'offset':offset})
            if any(b['device_time']<a['device_time'] for a,b in zip(anchors,anchors[1:])):
                device_bad.add(device)
                db.execute('INSERT INTO issue(code,detail) VALUES (?,?)',('clock_anchor_disorder',device))
            drift=max((abs(b['offset']-a['offset']) for a,b in zip(anchors,anchors[1:])),default=0.0)
            device_drift[device]=drift
            limits=device_limits.get(device) or {DEFAULT_MAX_CLOCK_DRIFT_S}
            if drift>min(limits):
                db.execute('INSERT INTO issue(code,detail) VALUES (?,?)',('clock_drift',device))
            device_anchors[device]=sorted(anchors,key=lambda a:(a['device_time'],a['id']))
            if not anchors and any(e['kind']!='clock_anchor' for e in events):
                device_bad.add(device)
                db.execute('INSERT INTO issue(code,detail) VALUES (?,?)',('clock_untrusted',device))
        insert_correction='INSERT INTO time_correction(run_id,event_id,device,rule,status,raw_time,corrected_time,uncertainty_seconds,anchor_before,anchor_after,formula) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
        for box in boxes:
            spec=batches[box['batch_id']]
            rule=spec['correction']
            if rule not in CORRECTION_RULES: raise ValueError(f'unknown correction rule: {rule}')
            limit=spec['max_clock_drift_s']
            events=by_box[box['id']]
            problems=[]
            untrusted=set()
            for device in {e['device'] for e in events}:
                if device in device_bad or device_drift.get(device,0.0)>limit: untrusted.add(device)
            corrected={}
            for e in events:
                raw=parse_time(e['event_time'])
                if e['device'] in untrusted:
                    corrected[e['id']]={'time':raw,'status':'raw_fallback'}
                    db.execute(insert_correction,(run_id,e['id'],e['device'],rule,'raw_fallback',e['event_time'],None,None,None,None,
                        f"device {e['device']} untrusted; raw device time kept explicitly, never as a trusted correction"))
                    continue
                try:
                    new,unc,lo,hi,formula=correct_time(raw,device_anchors.get(e['device'],[]),rule)
                    corrected[e['id']]={'time':new,'status':'ok'}
                    db.execute(insert_correction,(run_id,e['id'],e['device'],rule,'ok',e['event_time'],new.isoformat(),unc,
                        lo['id'] if lo else None,hi['id'] if hi else None,formula))
                except Uncorrectable as exc:
                    corrected[e['id']]={'time':raw,'status':'raw_fallback'}
                    problems.append('clock_uncorrectable')
                    db.execute(insert_correction,(run_id,e['id'],e['device'],rule,'raw_fallback',e['event_time'],None,None,None,None,
                        f"uncorrectable:{exc}; raw device time kept explicitly, never as a trusted correction"))
            ordered=sorted(events,key=lambda e:(corrected[e['id']]['time'],e['id']))
            stages=[e for e in ordered if e['kind'] in STAGE_ORDER]
            actual=[e['kind'] for e in stages]
            if actual!=['dispatch','arrival','sign']:
                problems.append('bad_transition' if len(actual)!=len(set(actual)) or actual!=sorted(actual,key=STAGE_ORDER.get) else 'missing_stage')
            seals=[]
            for e in ordered:
                if e['kind']=='open': seals.append(json.loads(e['payload']).get('seal'))
                if e['kind']=='reseal':
                    seal=json.loads(e['payload']).get('seal')
                    if not seals or seals.pop()!=seal: problems.append('seal_mismatch')
            if seals: problems.append('seal_mismatch')
            candidates=[e for e in ordered if e['kind']=='temperature']
            by_time=defaultdict(list)
            for e in candidates: by_time[corrected[e['id']]['time']].append(e)
            temps=[]
            for stamp,group in sorted(by_time.items(),key=lambda item:item[0]):
                trusted=[e for e in group if e['device'] not in untrusted]
                options=trusted or group
                values={json.loads(e['payload']).get('value') for e in options}
                if len(values)>1: problems.append('temperature_overlap')
                temps.append(sorted(options,key=lambda e:e['id'])[0])
            window=None
            if stages and temps:
                start=corrected[stages[0]['id']]['time']; end=corrected[stages[-1]['id']]['time']
                times=[corrected[e['id']]['time'] for e in temps]
                window={'start':start.isoformat(),'end':end.isoformat(),
                        'formula':f"[{stages[0]['kind']} {start.isoformat()} .. {stages[-1]['kind']} {end.isoformat()}] (corrected,{rule})"}
                if times[0]>start or times[-1]<end or any(b-a>MAX_TEMP_GAP for a,b in zip(times,times[1:])):
                    problems.append('temperature_gap')
            else: problems.append('temperature_gap')
            bad_start=None; max_exposure=0.0; exposure_formula=None
            for e in temps:
                t=corrected[e['id']]['time']; value=float(json.loads(e['payload']).get('value',0))
                if value<spec['min_temp'] or value>spec['max_temp']:
                    if bad_start is None: bad_start=t
                    dur=(t-bad_start).total_seconds()/60
                    if dur>max_exposure:
                        max_exposure=dur
                        exposure_formula=f"{t.isoformat()} - {bad_start.isoformat()} = {dur}min (corrected,{rule})"
                    if dur>=spec['max_excursion_min']:
                        problems.append('temperature_excursion')
                else: bad_start=None
            if any(e['device'] in untrusted for e in events): problems.append('clock_untrusted')
            for code in sorted(set(problems)):
                db.execute('INSERT INTO issue(code,detail) VALUES (?,?)',(code,box['id']))
            result='异常' if any(p in problems for p in ('bad_transition','seal_mismatch','temperature_excursion')) else ('证据不足' if problems else '完整')
            detail=json.dumps({'events':[e['id'] for e in ordered],'problems':sorted(set(problems)),
                'correction_rule':rule,'window':window,
                'exposure':{'max_min':max_exposure,'threshold_min':spec['max_excursion_min'],'formula':exposure_formula},
                'corrections':[{'event_id':e['id'],'raw_time':e['event_time'],
                                'corrected_time':corrected[e['id']]['time'].isoformat(),
                                'status':corrected[e['id']]['status']} for e in ordered]},
                ensure_ascii=False)
            db.execute('INSERT INTO decision VALUES (?,?,?,?,?)',(box['id'],result,detail,VERSION,run_id))
            output[box['id']]=result
    db.close()
    return output
