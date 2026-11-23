import argparse
import base64
import json
import tempfile
from pathlib import Path

from . import audit_anchor
from .ingest import ingest
from .rules import evaluate
from .store import connect

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

def _emit(obj,out):
    text=json.dumps(obj,ensure_ascii=False,indent=2)
    if out:
        out=Path(out);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(text,encoding='utf-8');print(out)
    else: print(text)

def main(argv=None):
    p=argparse.ArgumentParser(description='离线冷链交接证据采录')
    sub=p.add_subparsers(dest='command',required=True)
    d=sub.add_parser('demo');d.add_argument('--workdir')
    i=sub.add_parser('init');i.add_argument('--db',required=True);i.add_argument('--batch',required=True);i.add_argument('--box',required=True)
    a=sub.add_parser('ingest');a.add_argument('file');a.add_argument('--db',required=True)
    e=sub.add_parser('evaluate');e.add_argument('--db',required=True)
    r=sub.add_parser('report');r.add_argument('--db',required=True);r.add_argument('--out',required=True)
    x=sub.add_parser('inspect');x.add_argument('--db',required=True);x.add_argument('--box',required=True)
    ar=sub.add_parser('anchor-register');ar.add_argument('--db',required=True);ar.add_argument('--contract',required=True)
    sy=sub.add_parser('anchor-sync');sy.add_argument('--db',required=True)
    ac=sub.add_parser('anchor-checkpoint');ac.add_argument('--db',required=True);ac.add_argument('--policy',required=True,choices=audit_anchor.POLICIES)
    aw=sub.add_parser('anchor-witness');aw.add_argument('--request',required=True);aw.add_argument('--witness',required=True);aw.add_argument('--out',required=True);aw.add_argument('--fork',action='store_true')
    aa=sub.add_parser('anchor-ack');aa.add_argument('--db',required=True);aa.add_argument('--ack',required=True)
    rc=sub.add_parser('anchor-recover');rc.add_argument('--db',required=True)
    ai=sub.add_parser('anchor-inclusion');ai.add_argument('--db',required=True);ai.add_argument('--source-id',type=int,required=True);ai.add_argument('--out')
    co=sub.add_parser('anchor-consistency');co.add_argument('--db',required=True);co.add_argument('--old-size',type=int,required=True);co.add_argument('--new-size',type=int);co.add_argument('--out')
    ae=sub.add_parser('anchor-export');ae.add_argument('--db',required=True);ae.add_argument('--size',type=int,required=True);ae.add_argument('--policy',required=True,choices=audit_anchor.POLICIES);ae.add_argument('--out',required=True)
    av=sub.add_parser('anchor-verify-package');av.add_argument('package')
    avi=sub.add_parser('anchor-verify-inclusion');avi.add_argument('proof')
    avc=sub.add_parser('anchor-verify-consistency');avc.add_argument('proof')
    args=p.parse_args(argv)
    if args.command=='demo': print(demo(args.workdir or tempfile.mkdtemp(prefix='coldhandoff-')))
    elif args.command=='init': init(args.db,args.batch,args.box)
    elif args.command=='ingest': print(ingest(args.file,args.db))
    elif args.command=='evaluate': print(evaluate(args.db))
    elif args.command=='report': print(report(args.db,args.out))
    elif args.command=='inspect':
        db=connect(args.db); print(json.dumps({'decision':[dict(r) for r in db.execute('SELECT * FROM decision WHERE box_id=?',(args.box,))],'events':[dict(r) for r in db.execute('SELECT * FROM raw_event WHERE box_id=? ORDER BY event_time,id',(args.box,))]},ensure_ascii=False));db.close()
    elif args.command=='anchor-register': print(audit_anchor.register(args.db,args.contract))
    elif args.command=='anchor-sync': print(json.dumps(audit_anchor.sync_sources(args.db),ensure_ascii=False))
    elif args.command=='anchor-checkpoint': print(json.dumps(audit_anchor.checkpoint(args.db,args.policy),ensure_ascii=False,indent=2))
    elif args.command=='anchor-witness':
        req=json.loads(Path(args.request).read_text(encoding='utf-8'))
        ack=audit_anchor.SimulatedWitness(args.witness,fork=args.fork).sign(req)
        Path(args.out).write_text(json.dumps(ack,ensure_ascii=False,indent=2),encoding='utf-8'); print(args.out)
    elif args.command=='anchor-ack': print(json.dumps(audit_anchor.record_ack(args.db,json.loads(Path(args.ack).read_text(encoding='utf-8'))),ensure_ascii=False))
    elif args.command=='anchor-recover': print(json.dumps(audit_anchor.recover(args.db),ensure_ascii=False,indent=2))
    elif args.command=='anchor-inclusion': _emit(audit_anchor.inclusion_proof(args.db,args.source_id),args.out)
    elif args.command=='anchor-consistency': _emit(audit_anchor.consistency_proof(args.db,args.old_size,args.new_size),args.out)
    elif args.command=='anchor-export': audit_anchor.export_package(args.db,args.size,args.policy,args.out); print(args.out)
    elif args.command=='anchor-verify-package': print(json.dumps(audit_anchor.verify_package(json.loads(Path(args.package).read_text(encoding='utf-8'))),ensure_ascii=False,indent=2))
    elif args.command=='anchor-verify-inclusion': print(json.dumps({'ok':audit_anchor.verify_inclusion_proof(json.loads(Path(args.proof).read_text(encoding='utf-8')))}))
    elif args.command=='anchor-verify-consistency': print(json.dumps({'ok':audit_anchor.verify_consistency_proof(json.loads(Path(args.proof).read_text(encoding='utf-8')))}))
if __name__=='__main__': main()
