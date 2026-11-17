"""Freeze a second-leg loading tender for already decided cold-chain boxes."""
import hashlib,json
from pathlib import Path
from .ingest import parse_time
from .store import connect

def register(db_path,case_id,fixture):
    if not case_id:raise ValueError('missing_loading_case_id')
    source=Path(fixture).resolve();raw=source.read_bytes();doc=json.loads(raw)
    if not doc.get('boxes') or not doc.get('vehicles') or len({b['id'] for b in doc['boxes']})!=len(doc['boxes']):
        raise ValueError('bad_loading_contract')
    for vehicle in doc['vehicles']:
        parse_time(vehicle['departure'])
        if vehicle['capacity_units']<=0:raise ValueError('bad_vehicle_capacity')
    db=connect(db_path)
    try:
        with db:
            decisions=[]
            for box in doc['boxes']:
                parse_time(box['deadline'])
                if box['size_units']<=0 or box['value_units']<=0:raise ValueError('bad_box_tender')
                row=db.execute('SELECT box_id,result,detail,rules_version,run_id FROM decision WHERE box_id=?',(box['id'],)).fetchone()
                if not row or row['result']!='完整':raise ValueError('box_not_loading_eligible')
                decisions.append(dict(row))
            payload=json.dumps({'fixture':str(source),'digest':hashlib.sha256(raw).hexdigest(),
                                'doc':doc,'decisions':decisions},sort_keys=True,separators=(',',':'))
            old=db.execute('SELECT payload FROM loading_case WHERE id=?',(case_id,)).fetchone()
            if old and old['payload']!=payload:raise ValueError('loading_case_conflict')
            db.execute('INSERT OR IGNORE INTO loading_case VALUES (?,?)',(case_id,payload))
    finally:db.close()
    return {'case_id':case_id,'digest':hashlib.sha256(raw).hexdigest(),'eligible_boxes':len(decisions)}
