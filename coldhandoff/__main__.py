import argparse
import base64
import json
import tempfile
from pathlib import Path

from .ingest import ingest
from .rules import evaluate
from .store import connect
from . import tariffs

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

def tariff_register(args):
    print(json.dumps(tariffs.register(args.db, args.case, args.contract, args.source_dir),
                     ensure_ascii=False))


def tariff_build(args):
    print(json.dumps({'version_id': tariffs.build_version(args.db, args.case, args.authority)},
                     ensure_ascii=False))


def tariff_publish(args):
    endpoint = tariffs.MockRateMaster(lose_ack=bool(args.lose_ack),
                                      partial_services=bool(args.partial_services))
    print(json.dumps(tariffs.publish(args.db, args.case, args.authority, endpoint),
                     ensure_ascii=False))


def tariff_quote(args):
    print(json.dumps(tariffs.quote(args.db, args.case), ensure_ascii=False, indent=2))


def tariff_report(args):
    print(json.dumps(tariffs.write_reports(args.db, args.case, args.out),
                     ensure_ascii=False, indent=2))


def main():
    p=argparse.ArgumentParser(description='离线冷链交接证据采录')
    sub=p.add_subparsers(dest='command',required=True)
    d=sub.add_parser('demo');d.add_argument('--workdir')
    i=sub.add_parser('init');i.add_argument('--db',required=True);i.add_argument('--batch',required=True);i.add_argument('--box',required=True)
    a=sub.add_parser('ingest');a.add_argument('file');a.add_argument('--db',required=True)
    e=sub.add_parser('evaluate');e.add_argument('--db',required=True)
    r=sub.add_parser('report');r.add_argument('--db',required=True);r.add_argument('--out',required=True)
    x=sub.add_parser('inspect');x.add_argument('--db',required=True);x.add_argument('--box',required=True)
    t=sub.add_parser('tariff-register');t.add_argument('--db',required=True);t.add_argument('--case',required=True);t.add_argument('--contract',required=True);t.add_argument('--source-dir',required=True);t.set_defaults(func=tariff_register)
    b=sub.add_parser('tariff-build');b.add_argument('--db',required=True);b.add_argument('--case',required=True);b.add_argument('--authority',required=True,choices=list(tariffs.ALLOWED_AUTHORITIES));b.set_defaults(func=tariff_build)
    pu=sub.add_parser('tariff-publish');pu.add_argument('--db',required=True);pu.add_argument('--case',required=True);pu.add_argument('--authority',required=True,choices=list(tariffs.ALLOWED_AUTHORITIES));pu.add_argument('--lose-ack',action='store_true');pu.add_argument('--partial-services',action='store_true');pu.set_defaults(func=tariff_publish)
    q=sub.add_parser('tariff-quote');q.add_argument('--db',required=True);q.add_argument('--case',required=True);q.set_defaults(func=tariff_quote)
    tr=sub.add_parser('tariff-report');tr.add_argument('--db',required=True);tr.add_argument('--case',required=True);tr.add_argument('--out',required=True);tr.set_defaults(func=tariff_report)
    args=p.parse_args()
    if args.command=='demo': print(demo(args.workdir or tempfile.mkdtemp(prefix='coldhandoff-')))
    elif args.command=='init': init(args.db,args.batch,args.box)
    elif args.command=='ingest': print(ingest(args.file,args.db))
    elif args.command=='evaluate': print(evaluate(args.db))
    elif args.command=='report': print(report(args.db,args.out))
    elif args.command=='inspect':
        db=connect(args.db); print(json.dumps({'decision':[dict(r) for r in db.execute('SELECT * FROM decision WHERE box_id=?',(args.box,))],'events':[dict(r) for r in db.execute('SELECT * FROM raw_event WHERE box_id=? ORDER BY event_time,id',(args.box,))]},ensure_ascii=False));db.close()
    else:
        args.func(args)
if __name__=='__main__': main()
