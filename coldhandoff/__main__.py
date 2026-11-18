import argparse
import base64
import json
import tempfile
from pathlib import Path

from . import assets as asset_mod
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

def asset_report(db_path, plan_id, out):
    """Write JSON + Markdown allocation report for a confirmed/draft plan."""
    plan = asset_mod.get_plan(db_path, plan_id)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(plan, ensure_ascii=False, indent=2),
                   encoding='utf-8')
    lines = [
        f"# 周转资产领用计划 {plan['case_id']}（策略 {plan['policy']}）", '',
        '## 需求领用来源', '',
        '| 需求 | 业务箱 | 截止时刻 | 派给容器 | 来源 | 实际发出 | 准时 | 迟到(分) | 罚金(分) |',
        '| --- | --- | --- | --- | --- | --- | --- | --- | --- |']
    for a in plan['assignments']:
        lines.append(
            f"| {a['need_id']} | {a['box_id']} | {a['deadline']} | "
            f"{a['asset_id']} | {a['source']} | {a['dispatched_at']} | "
            f"{'准时' if a['on_time'] else '逾期'} | {a['late_minutes']} | {a['late_cents']} |")
        if not a['on_time']:
            lines.append(f"| | | | | | | | | {a['late_note']} |")
    if plan['unmet_needs']:
        lines += ['', '## 未满足需求', '']
        lines += [f"- {u['need_id']}（业务箱 {u['box_id']}，截止 {u['deadline']}）"
                  for u in plan['unmet_needs']]
    lines += ['', '## 容器作业/保管时间线', '']
    for c in plan['containers']:
        lines.append(f"### {c['asset_id']}（{c['kind']}，状态 {c['state']}"
                     + (f"，来源盒 {c['origin_box']}" if c['origin_box'] else '，采购')
                     + '）')
        for t in c['timeline']:
            equip = f" @ {t['equipment']}" if t['equipment'] else ''
            lines.append(f"- {t['at']} {t['stage']}{equip}（证据 {t['source_ref']}）")
    inv = plan['inventory']
    lines += ['', '## 库存', '',
              f"- 剩余就绪：{', '.join(inv['remaining_ready']) or '无'}",
              f"- 占用/已发出：{', '.join(inv['occupied']) or '无'}",
              f"- 未处理归还：{', '.join(inv['unprocessed_returned']) or '无'}",
              f"- 待检隔离：{', '.join(inv['quarantine']) or '无'}",
              f"- 污染未过：{', '.join(inv['contaminated']) or '无'}",
              f"- 采购额度：已用 {inv['purchase_quota_used']} / 剩余 {inv['purchase_quota_remaining']}"]
    cost = plan['costs']
    lines += ['', '## 费用（分）', '',
              f"- 洗消：{cost['wash_count']} 只 × 单价 = {cost['wash_cents']}",
              f"- 采购：{cost['purchase_count']} 只 = {cost['purchase_cents']}",
              f"- 迟到罚金：{cost['late_need_count']} 单 = {cost['late_cents']}",
              f"- 合计：{cost['total_cents']}",
              '', '## 来源证据', '']
    lines += [f"- {e['subject']} [{e['object_kind']}] {e['object_ref']}：{e['detail']}"
              for e in plan['evidence']]
    lines.append(f"\n计划摘要：`{plan['digest']}`")
    out.with_suffix('.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return out


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
    g=sub.add_parser('asset-register');g.add_argument('contract');g.add_argument('--db',required=True)
    pp=sub.add_parser('asset-plan');pp.add_argument('--db',required=True);pp.add_argument('--case',required=True)
    pp.add_argument('--policy',required=True,choices=asset_mod.POLICIES);pp.add_argument('--version',type=int)
    cf=sub.add_parser('asset-confirm');cf.add_argument('--db',required=True);cf.add_argument('--plan',required=True)
    rv=sub.add_parser('asset-recover');rv.add_argument('--db',required=True);rv.add_argument('--case',required=True);rv.add_argument('--version',type=int)
    st=sub.add_parser('asset-status');st.add_argument('--db',required=True);st.add_argument('--case',required=True);st.add_argument('--version',type=int)
    ar=sub.add_parser('asset-report');ar.add_argument('--db',required=True);ar.add_argument('--plan',required=True);ar.add_argument('--out',required=True)
    args=p.parse_args()
    if args.command=='demo': print(demo(args.workdir or tempfile.mkdtemp(prefix='coldhandoff-')))
    elif args.command=='init': init(args.db,args.batch,args.box)
    elif args.command=='ingest': print(ingest(args.file,args.db))
    elif args.command=='evaluate': print(evaluate(args.db))
    elif args.command=='report': print(report(args.db,args.out))
    elif args.command=='inspect':
        db=connect(args.db); print(json.dumps({'decision':[dict(r) for r in db.execute('SELECT * FROM decision WHERE box_id=?',(args.box,))],'events':[dict(r) for r in db.execute('SELECT * FROM raw_event WHERE box_id=? ORDER BY event_time,id',(args.box,))]},ensure_ascii=False));db.close()
    elif args.command=='asset-register': print(json.dumps(asset_mod.register_versioned(args.db,args.contract),ensure_ascii=False))
    elif args.command=='asset-plan': print(json.dumps(asset_mod.plan(args.db,args.case,args.policy,args.version),ensure_ascii=False))
    elif args.command=='asset-confirm': print(json.dumps(asset_mod.confirm(args.db,args.plan),ensure_ascii=False))
    elif args.command=='asset-recover': print(json.dumps(asset_mod.recover(args.db,args.case,args.version),ensure_ascii=False))
    elif args.command=='asset-status': print(json.dumps(asset_mod.case_status(args.db,args.case,args.version),ensure_ascii=False))
    elif args.command=='asset-report': print(asset_report(args.db,args.plan,args.out))
if __name__=='__main__': main()
