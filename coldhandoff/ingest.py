import csv
import hashlib
import io
import json
from datetime import datetime
from pathlib import Path

from .store import connect

KINDS={'dispatch','arrival','sign','open','reseal','temperature','clock_anchor'}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def parse_time(s):
    dt=datetime.fromisoformat(s.replace('Z','+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timezone_required')
    return dt

def rows(path):
    path=Path(path)
    raw=path.read_bytes()
    if path.suffix=='.csv':
        reader=csv.DictReader(io.StringIO(raw.decode('utf-8-sig')))
    elif path.suffix=='.jsonl':
        reader=[]
        for line in raw.decode('utf-8-sig').splitlines():
            if not line.strip():continue
            try:reader.append(json.loads(line))
            except json.JSONDecodeError:reader.append({'_parse_error':line})
    else:
        raise ValueError('unsupported_file')
    return raw,list(reader)

def ingest(path,db_path):
    raw,records=rows(path)
    h=digest(raw)
    db=connect(db_path)
    if db.execute('SELECT id FROM source_file WHERE hash=?',(h,)).fetchone():
        return {'imported':0,'duplicate_file':True}
    imported=0
    with db:
        sid=db.execute('INSERT INTO source_file(name,hash,raw) VALUES (?,?,?)',(str(path),h,raw)).lastrowid
        for line_no,row in enumerate(records,1):
            try:
                if '_parse_error' in row:raise ValueError('malformed_json:'+row['_parse_error'])
                kind=str(row['kind'])
                if kind not in KINDS: raise ValueError('unknown_kind')
                device=str(row['device'])
                seq=int(row['seq'])
                box=str(row.get('box_id') or '')
                ts=str(row['event_time'])
                parse_time(ts)
                if kind!='clock_anchor' and not box: raise ValueError('box_required')
                event_hash=digest(json.dumps(row,sort_keys=True,ensure_ascii=False).encode())
                old=db.execute('SELECT hash FROM raw_event WHERE device=? AND seq=? LIMIT 1',(device,seq)).fetchone()
                if old:
                    if old['hash']!=event_hash:
                        db.execute('INSERT INTO issue(code,detail) VALUES (?,?)',('identity_conflict',f'{device}:{seq}'))
                    continue
                cur=db.execute('INSERT INTO raw_event(source_id,line_no,kind,device,seq,box_id,event_time,payload,hash) VALUES (?,?,?,?,?,?,?,?,?)',
                    (sid,line_no,kind,device,seq,box,ts,json.dumps(row,ensure_ascii=False),event_hash))
                imported+=1
                if kind!='clock_anchor' and not db.execute('SELECT 1 FROM box WHERE id=?',(box,)).fetchone():
                    db.execute('INSERT INTO issue(event_id,code,detail) VALUES (?,?,?)',(cur.lastrowid,'unknown_box',box))
            except (KeyError,ValueError,TypeError) as exc:
                db.execute('INSERT INTO issue(code,detail) VALUES (?,?)',('parse_error',f'line {line_no}: {exc}'))
    db.close()
    return {'imported':imported,'duplicate_file':False}
