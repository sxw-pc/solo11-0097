import argparse
import base64
import json
import sys
import tempfile
from pathlib import Path

from . import audit_anchor as anchor
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

def main():
    p=argparse.ArgumentParser(description='离线冷链交接证据采录')
    sub=p.add_subparsers(dest='command',required=True)
    d=sub.add_parser('demo');d.add_argument('--workdir')
    i=sub.add_parser('init');i.add_argument('--db',required=True);i.add_argument('--batch',required=True);i.add_argument('--box',required=True)
    a=sub.add_parser('ingest');a.add_argument('file');a.add_argument('--db',required=True)
    e=sub.add_parser('evaluate');e.add_argument('--db',required=True)
    r=sub.add_parser('report');r.add_argument('--db',required=True);r.add_argument('--out',required=True)
    x=sub.add_parser('inspect');x.add_argument('--db',required=True);x.add_argument('--box',required=True)

    ast=sub.add_parser('anchor-status');ast.add_argument('--db',required=True);ast.add_argument('--contract',required=True)
    aa=sub.add_parser('anchor-append');aa.add_argument('--db',required=True);aa.add_argument('--contract',required=True)
    aa.add_argument('--from-ingest',action='store_true')
    aa.add_argument('--source-id');aa.add_argument('--bytes-sha256');aa.add_argument('--import-version',default=anchor.IMPORT_VERSION)
    ac=sub.add_parser('anchor-correction');ac.add_argument('--db',required=True);ac.add_argument('--contract',required=True)
    ac.add_argument('--source-id',required=True);ac.add_argument('--target-source-id',required=True)
    ac.add_argument('--kind',choices=('revoke','replace'),default='revoke')
    ac.add_argument('--bytes-sha256');ac.add_argument('--reason',default='')
    ap=sub.add_parser('anchor-publish');ap.add_argument('--db',required=True);ap.add_argument('--contract',required=True)
    ap.add_argument('--policy',choices=anchor.POLICIES,default='local_signed')
    ap.add_argument('--fault',choices=('after_root_compute','after_checkpoint_persist','after_first_witness_receipt'))
    aw=sub.add_parser('anchor-witness-ack');aw.add_argument('--db',required=True);aw.add_argument('--contract',required=True)
    aw.add_argument('--checkpoint',required=True,type=int);aw.add_argument('--witness',required=True)
    aw.add_argument('--observed-root');aw.add_argument('--observed-size',type=int);aw.add_argument('--signed-at')
    ar=sub.add_parser('anchor-recover');ar.add_argument('--db',required=True);ar.add_argument('--contract',required=True)
    ar.add_argument('--advance',action='store_true');ar.add_argument('--policy',choices=anchor.POLICIES,default='local_signed')
    ab=sub.add_parser('anchor-bundle');ab.add_argument('--db',required=True);ab.add_argument('--contract',required=True)
    ab.add_argument('--checkpoint',required=True,type=int);ab.add_argument('--consistency-from',type=int)
    ab.add_argument('--out',required=True);ab.add_argument('--keyring')
    av=sub.add_parser('anchor-verify');av.add_argument('--bundle',required=True);av.add_argument('--keyring')
    ai=sub.add_parser('anchor-inclusion');ai.add_argument('--db',required=True);ai.add_argument('--contract',required=True)
    ai.add_argument('--source-id',required=True);ai.add_argument('--checkpoint',type=int)
    ak=sub.add_parser('anchor-keyring');ak.add_argument('--db',required=True);ak.add_argument('--contract',required=True);ak.add_argument('--out',required=True)

    args=p.parse_args()
    if args.command=='demo': print(demo(args.workdir or tempfile.mkdtemp(prefix='coldhandoff-')))
    elif args.command=='init': init(args.db,args.batch,args.box)
    elif args.command=='ingest': print(ingest(args.file,args.db))
    elif args.command=='evaluate': print(evaluate(args.db))
    elif args.command=='report': print(report(args.db,args.out))
    elif args.command=='inspect':
        db=connect(args.db); print(json.dumps({'decision':[dict(r) for r in db.execute('SELECT * FROM decision WHERE box_id=?',(args.box,))],'events':[dict(r) for r in db.execute('SELECT * FROM raw_event WHERE box_id=? ORDER BY event_time,id',(args.box,))]},ensure_ascii=False));db.close()
    elif args.command=='anchor-status':
        _anchor_status(args)
    elif args.command=='anchor-append':
        if args.from_ingest:
            print(json.dumps(anchor.append_from_ingest(args.db,args.contract,import_version=args.import_version),ensure_ascii=False))
        else:
            if not (args.source_id and args.bytes_sha256):
                p.error('anchor-append needs --from-ingest or --source-id and --bytes-sha256')
            print(json.dumps(anchor.append_source(args.db,args.contract,args.source_id,args.bytes_sha256,args.import_version),ensure_ascii=False))
    elif args.command=='anchor-correction':
        print(json.dumps(anchor.append_correction(args.db,args.contract,args.source_id,args.target_source_id,
              kind=args.kind,bytes_sha256=args.bytes_sha256,reason=args.reason),ensure_ascii=False))
    elif args.command=='anchor-publish':
        try:
            print(json.dumps(anchor.publish_checkpoint(args.db,args.contract,policy=args.policy,fault=args.fault),ensure_ascii=False))
        except anchor.InjectedFault as fault:
            print(json.dumps({'injected_fault':fault.stage,**fault.detail},ensure_ascii=False));sys.exit(2)
    elif args.command=='anchor-witness-ack':
        print(json.dumps(anchor.simulate_witness_ack(args.db,args.contract,args.checkpoint,args.witness,
              observed_root=args.observed_root,observed_size=args.observed_size,signed_at=args.signed_at),ensure_ascii=False))
    elif args.command=='anchor-recover':
        print(json.dumps(anchor.recover(args.db,args.contract,advance=args.advance,policy=args.policy),ensure_ascii=False))
    elif args.command=='anchor-bundle':
        bundle=anchor.audit_bundle(args.db,args.contract,args.checkpoint,consistency_from=args.consistency_from)
        keyring=json.loads(Path(args.keyring).read_text(encoding='utf-8')) if args.keyring else None
        verification=anchor.verify_bundle(bundle,keyring)
        out,md=anchor.write_bundle(bundle,args.out,verification)
        print(json.dumps({'json':str(out),'markdown':str(md),'verified':verification['ok']},ensure_ascii=False))
    elif args.command=='anchor-verify':
        bundle=json.loads(Path(args.bundle).read_text(encoding='utf-8'))
        keyring=json.loads(Path(args.keyring).read_text(encoding='utf-8')) if args.keyring else None
        result=anchor.verify_bundle(bundle,keyring)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        sys.exit(0 if result['ok'] else 1)
    elif args.command=='anchor-keyring':
        out=Path(args.out);out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(anchor.export_keyring(args.db,args.contract),ensure_ascii=False,indent=2),encoding='utf-8')
        print(out)
    elif args.command=='anchor-inclusion':
        print(json.dumps(anchor.inclusion_for(args.db,args.contract,args.source_id,args.checkpoint),ensure_ascii=False,indent=2))


def _anchor_status(args):
    contract=json.loads(Path(args.contract).read_text(encoding='utf-8'))
    db=connect(args.db)
    try:
        case=db.execute('SELECT id,contract_sha256,source_snapshot FROM anchor_case WHERE id=?',(contract['case_id'],)).fetchone()
        if not case:
            print(json.dumps({'registered':False,'case_id':contract['case_id']},ensure_ascii=False));return
        checkpoints=[dict(r) for r in db.execute('SELECT number,tree_size,root,state,created_at FROM anchor_checkpoint WHERE case_id=? ORDER BY number',(contract['case_id'],))]
        leaves=[dict(r) for r in db.execute('SELECT leaf_index,source_id,kind,leaf_hash FROM anchor_leaf WHERE case_id=? ORDER BY leaf_index',(contract['case_id'],))]
        sources=[dict(r) for r in db.execute('SELECT source_id,status,first_leaf_index FROM anchor_source WHERE case_id=? ORDER BY source_id',(contract['case_id'],))]
        forks=anchor.list_forks(args.db,args.contract)
        print(json.dumps({'registered':True,'case_id':case['id'],'contract_sha256':case['contract_sha256'],
            'leaves':leaves,'sources':sources,'checkpoints':checkpoints,'forks':forks},ensure_ascii=False,indent=2))
    finally:
        db.close()


if __name__=='__main__': main()
