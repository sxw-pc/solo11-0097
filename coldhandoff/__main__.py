import argparse
import base64
import json
import tempfile
from pathlib import Path

from .ingest import ingest
from .rules import evaluate
from .store import connect
from . import privacy_export as pe

def init(db_path,batch_id,box_id):
    db=connect(db_path)
    with db:
        db.execute('INSERT OR IGNORE INTO batch VALUES (?,?,?,?)',(batch_id,2.0,8.0,10))
        db.execute('INSERT OR IGNORE INTO box VALUES (?,?)',(box_id,batch_id))
    db.close()

def report(db_path,out):
    db=connect(db_path)
    data={'decisions':[dict(r) for r in db.execute('SELECT * FROM decision ORDER BY box_id')],
          'issues':[dict(r) for r in db.execute('SELECT * FROM issue ORDER BY id')],
          'events':[dict(r) for r in db.execute('SELECT * FROM raw_event ORDER BY id')],
          'runs':[dict(r) for r in db.execute('SELECT * FROM run ORDER BY id')],
          'evidence':[dict(r) for r in db.execute('SELECT * FROM evidence ORDER BY id')],
          'sources':[dict(r) for r in db.execute('SELECT * FROM source_file ORDER BY id')]}
    for row in data['issues']:row.pop('id',None)
    out=Path(out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(data,ensure_ascii=False,indent=2,default=lambda v:{'base64':base64.b64encode(v).decode('ascii')}),encoding='utf-8')
    out.with_suffix('.md').write_text('# 冷链交接结论\n\n'+'\n'.join(f"- {d['box_id']}: {d['result']}（规则 {d['rules_version']}）" for d in data['decisions'])+'\n',encoding='utf-8')
    db.close(); return out

def demo(workdir):
    workdir=Path(workdir);workdir.mkdir(parents=True,exist_ok=True)
    db=workdir/'coldhandoff.db'; init(db,'batch-1','box-1')
    events=[('clock_anchor','2026-01-01T07:59:00+00:00',None),('dispatch','2026-01-01T08:00:00+00:00',None),('temperature','2026-01-01T08:00:00+00:00',4),
            ('temperature','2026-01-01T08:20:00+00:00',4),('temperature','2026-01-01T08:40:00+00:00',4),
            ('arrival','2026-01-01T08:40:00+00:00',None),('sign','2026-01-01T08:40:00+00:00',None)]
    src=workdir/'events.jsonl'
    src.write_text('\n'.join(json.dumps({'kind':kind,'device':'d1','seq':i,'box_id':'' if kind=='clock_anchor' else 'box-1','event_time':time,'value':value,'offset_seconds':0 if kind=='clock_anchor' else None}) for i,(kind,time,value) in enumerate(events,1)),encoding='utf-8')
    ingest(src,db); evaluate(db)
    return report(db,workdir/'report.json')

def export_contract(db, contract, out_root, kind, recipient=None, key_id=None):
    handle = pe.stage_export(db, contract, kind, out_root,
                             recipient_id=recipient, key_id=key_id)
    if handle['status'] != pe.CONFIRMED:
        handle = pe.confirm_export(db, handle['package_id'], out_root)
    return handle

def export_verify(path, db=None):
    return pe.verify_package(path, db_path=db)

def main():
    p=argparse.ArgumentParser(description='离线冷链交接证据采录')
    sub=p.add_subparsers(dest='command',required=True)
    d=sub.add_parser('demo');d.add_argument('--workdir')
    i=sub.add_parser('init');i.add_argument('--db',required=True);i.add_argument('--batch',required=True);i.add_argument('--box',required=True)
    a=sub.add_parser('ingest');a.add_argument('file');a.add_argument('--db',required=True)
    e=sub.add_parser('evaluate');e.add_argument('--db',required=True)
    r=sub.add_parser('report');r.add_argument('--db',required=True);r.add_argument('--out',required=True)
    x=sub.add_parser('inspect');x.add_argument('--db',required=True);x.add_argument('--box',required=True)
    cr=sub.add_parser('contract-register');cr.add_argument('--db',required=True);cr.add_argument('--contract',required=True)
    kr=sub.add_parser('key-rotate');kr.add_argument('--db',required=True);kr.add_argument('--key-id')
    sp=sub.add_parser('export-stage');sp.add_argument('--db',required=True);sp.add_argument('--case',required=True)
    sp.add_argument('--contract-kind',required=True,choices=list(pe.KNOWN_CONTRACTS))
    sp.add_argument('--out-root',required=True);sp.add_argument('--recipient');sp.add_argument('--key-id')
    cf=sub.add_parser('export-confirm');cf.add_argument('--db',required=True);cf.add_argument('--package-id',required=True)
    cf.add_argument('--out-root',required=True)
    rs=sub.add_parser('export-resume');rs.add_argument('--db',required=True);rs.add_argument('--case',required=True)
    rs.add_argument('--contract-kind',required=True,choices=list(pe.KNOWN_CONTRACTS))
    rs.add_argument('--recipient',required=True);rs.add_argument('--out-root',required=True)
    vf=sub.add_parser('export-verify');vf.add_argument('path');vf.add_argument('--db')
    args=p.parse_args()
    if args.command=='demo': print(demo(args.workdir or tempfile.mkdtemp(prefix='coldhandoff-')))
    elif args.command=='init': init(args.db,args.batch,args.box)
    elif args.command=='ingest': print(ingest(args.file,args.db))
    elif args.command=='evaluate': print(evaluate(args.db))
    elif args.command=='report': print(report(args.db,args.out))
    elif args.command=='inspect':
        db=connect(args.db); print(json.dumps({'decision':[dict(r) for r in db.execute('SELECT * FROM decision WHERE box_id=?',(args.box,))],'events':[dict(r) for r in db.execute('SELECT * FROM raw_event WHERE box_id=? ORDER BY event_time,id',(args.box,))]},ensure_ascii=False));db.close()
    elif args.command=='contract-register': print(pe.register(args.db,args.contract))
    elif args.command=='key-rotate': print(pe.rotate_key(args.db,args.key_id))
    elif args.command=='export-stage': print(json.dumps(pe.stage_export(args.db,args.case,args.contract_kind,args.out_root,recipient_id=args.recipient,key_id=args.key_id),ensure_ascii=False))
    elif args.command=='export-confirm': print(json.dumps(pe.confirm_export(args.db,args.package_id,args.out_root),ensure_ascii=False))
    elif args.command=='export-resume': print(json.dumps(pe.resume_export(args.db,args.case,args.contract_kind,args.recipient,args.out_root),ensure_ascii=False))
    elif args.command=='export-verify': print(json.dumps(export_verify(args.path,args.db),ensure_ascii=False))
if __name__=='__main__': main()
