"""Freeze synthetic ambient trace and package thermal profiles."""
import hashlib,json,math
from pathlib import Path
from .ingest import parse_time
from .store import connect

def register(db_path,case_id,fixture):
    if not case_id:raise ValueError('missing_thermal_case_id')
    source=Path(fixture).resolve();raw=source.read_bytes();doc=json.loads(raw)
    if not doc.get('box_id') or not doc.get('package_profiles') or doc.get('core_limit') is None:
        raise ValueError('bad_thermal_contract')
    db=connect(db_path)
    try:
        with db:
            if not db.execute('SELECT 1 FROM box WHERE id=?',(doc['box_id'],)).fetchone():raise ValueError('unknown_thermal_box')
            rows=[dict(r) for r in db.execute("SELECT id,event_time,payload,hash FROM raw_event WHERE box_id=? AND kind='temperature' ORDER BY event_time,id",(doc['box_id'],))]
            if len(rows)!=doc['sample_count']:raise ValueError('thermal_sample_gap')
            for i,row in enumerate(rows):
                value=json.loads(row['payload']).get('value')
                if value is None or not math.isfinite(float(value)):raise ValueError('bad_ambient_value')
                if i and parse_time(row['event_time'])<=parse_time(rows[i-1]['event_time']):raise ValueError('thermal_time_order')
            payload=json.dumps({'fixture':str(source),'digest':hashlib.sha256(raw).hexdigest(),'doc':doc,
                                'points':[(r['id'],r['event_time'],r['hash']) for r in rows]},sort_keys=True,separators=(',',':'))
            old=db.execute('SELECT payload FROM thermal_case WHERE id=?',(case_id,)).fetchone()
            if old and old['payload']!=payload:raise ValueError('thermal_case_conflict')
            db.execute('INSERT OR IGNORE INTO thermal_case VALUES (?,?)',(case_id,payload))
    finally:db.close()
    return {'case_id':case_id,'digest':hashlib.sha256(raw).hexdigest(),'sample_count':len(rows)}
