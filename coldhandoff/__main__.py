import argparse
import base64
import json
import tempfile
from pathlib import Path

from .ingest import ingest
from .label_demo import label_demo
from .labels import (register as label_register, produce as label_produce,
                     apply_label, reconcile_print, redeliver_command,
                     recover_jam, quarantine, resolve_quarantine,
                     record_destruction, revoke, reprint, close_job,
                     revise_contract, report as label_report)
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
    ld=sub.add_parser('label-demo');ld.add_argument('--workdir')
    i=sub.add_parser('init');i.add_argument('--db',required=True);i.add_argument('--batch',required=True);i.add_argument('--box',required=True)
    a=sub.add_parser('ingest');a.add_argument('file');a.add_argument('--db',required=True)
    e=sub.add_parser('evaluate');e.add_argument('--db',required=True)
    r=sub.add_parser('report');r.add_argument('--db',required=True);r.add_argument('--out',required=True)
    x=sub.add_parser('inspect');x.add_argument('--db',required=True);x.add_argument('--box',required=True)
    def label_parser(name, **kw):
        p=sub.add_parser(name);p.add_argument('--db',required=True);p.add_argument('--devices',required=True,**kw);return p
    lr=sub.add_parser('label-register');lr.add_argument('--db',required=True);lr.add_argument('contract')
    lc=sub.add_parser('label-revise');lc.add_argument('--db',required=True);lc.add_argument('contract')
    lp=label_parser('label-produce');lp.add_argument('--case',required=True);lp.add_argument('--mode',required=True,choices=('direct_recipient','opaque_pickup'));lp.add_argument('--box',action='append')
    la=label_parser('label-apply');la.add_argument('--serial',required=True);la.add_argument('--box',required=True)
    lrec=label_parser('label-reconcile');lrec.add_argument('--serial',required=True)
    lred=label_parser('label-redeliver');lred.add_argument('--serial',required=True)
    lj=label_parser('label-recover');lj.add_argument('--serial',required=True);lj.add_argument('--disposition',required=True,choices=('paper_recoverable','paper_destroyed','whereabouts_unknown'));lj.add_argument('--note',default='')
    lq=label_parser('label-quarantine');lq.add_argument('--serial',required=True);lq.add_argument('--reason',required=True)
    lqr=label_parser('label-quarantine-resolve');lqr.add_argument('--serial',required=True);lqr.add_argument('--decision',required=True,choices=('located_intact','confirmed_lost'));lqr.add_argument('--note',default='')
    ldest=sub.add_parser('label-destroy');ldest.add_argument('--db',required=True);ldest.add_argument('--serial',required=True);ldest.add_argument('--note',required=True)
    lrev=sub.add_parser('label-revoke');lrev.add_argument('--db',required=True);lrev.add_argument('--serial',required=True);lrev.add_argument('--reason',required=True);lrev.add_argument('--note',default='')
    lrp=label_parser('label-reprint');lrp.add_argument('--serial',required=True);lrp.add_argument('--reason',required=True)
    lclose=sub.add_parser('label-close');lclose.add_argument('--db',required=True);lclose.add_argument('--job',required=True)
    lreport=label_parser('label-report');lreport.add_argument('--out',required=True)
    args=p.parse_args()
    if args.command=='demo': print(demo(args.workdir or tempfile.mkdtemp(prefix='coldhandoff-')))
    elif args.command=='label-demo': print(label_demo(args.workdir or tempfile.mkdtemp(prefix='coldlabel-')))
    elif args.command=='init': init(args.db,args.batch,args.box)
    elif args.command=='ingest': print(ingest(args.file,args.db))
    elif args.command=='evaluate': print(evaluate(args.db))
    elif args.command=='report': print(report(args.db,args.out))
    elif args.command=='inspect':
        db=connect(args.db); print(json.dumps({'decision':[dict(r) for r in db.execute('SELECT * FROM decision WHERE box_id=?',(args.box,))],'events':[dict(r) for r in db.execute('SELECT * FROM raw_event WHERE box_id=? ORDER BY event_time,id',(args.box,))]},ensure_ascii=False));db.close()
    elif args.command=='label-register': print(label_register(args.db,args.contract))
    elif args.command=='label-revise': print(revise_contract(args.db,args.contract))
    elif args.command=='label-produce': print(json.dumps(label_produce(args.db,args.case,args.mode,args.devices,box_ids=args.box),ensure_ascii=False))
    elif args.command=='label-apply': print(json.dumps(apply_label(args.db,args.serial,args.devices,args.box),ensure_ascii=False))
    elif args.command=='label-reconcile': print(json.dumps(reconcile_print(args.db,args.serial,args.devices),ensure_ascii=False))
    elif args.command=='label-redeliver': print(json.dumps(redeliver_command(args.db,args.serial,args.devices),ensure_ascii=False,default=str))
    elif args.command=='label-recover': print(json.dumps(recover_jam(args.db,args.serial,args.devices,args.disposition,args.note),ensure_ascii=False,default=str))
    elif args.command=='label-quarantine': quarantine(args.db,args.serial,args.reason)
    elif args.command=='label-quarantine-resolve': resolve_quarantine(args.db,args.serial,args.decision,args.note)
    elif args.command=='label-destroy': record_destruction(args.db,args.serial,args.note)
    elif args.command=='label-revoke': revoke(args.db,args.serial,args.reason,args.note)
    elif args.command=='label-reprint': print(json.dumps(reprint(args.db,args.serial,args.devices,args.reason),ensure_ascii=False,default=str))
    elif args.command=='label-close': close_job(args.db,args.job)
    elif args.command=='label-report': print(label_report(args.db,args.devices,args.out))
if __name__=='__main__': main()
