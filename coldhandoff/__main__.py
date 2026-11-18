import argparse
import base64
import json
import tempfile
from pathlib import Path

from .ingest import ingest
from .rules import evaluate
from .store import connect
from .archive import (
    ContentStore,
    ReaderView,
    migrate_all,
    recover,
    run_gc,
    storage_accounting,
    verify_archive,
)


def init(db_path, batch_id, box_id):
    db = connect(db_path)
    with db:
        db.execute('INSERT OR IGNORE INTO batch VALUES (?,?,?,?)', (batch_id, 2.0, 8.0, 10))
        db.execute('INSERT OR IGNORE INTO box VALUES (?,?)', (box_id, batch_id))
    db.close()


def report(db_path, out):
    db = connect(db_path)
    store = ContentStore.for_db(db_path)
    # Pin one published generation for the entire report so a concurrent
    # migration/GC cannot change the bytes underneath a long-running read.
    view = ReaderView(db, store)
    try:
        data = {'decisions': [dict(r) for r in db.execute('SELECT * FROM decision ORDER BY box_id')],
                'issues': [dict(r) for r in db.execute('SELECT * FROM issue ORDER BY id')],
                'events': [dict(r) for r in db.execute('SELECT * FROM raw_event ORDER BY id')],
                'runs': [dict(r) for r in db.execute('SELECT * FROM run ORDER BY id')],
                'evidence': [dict(r) for r in db.execute('SELECT * FROM evidence ORDER BY id')],
                'sources': [dict(r) for r in db.execute('SELECT * FROM source_file ORDER BY id')]}
        for row in data['issues']:
            row.pop('id', None)
        # Single source read path: raw BLOB before migration, manifest
        # reassembly after; identical bytes, identical Base64 evidence.
        for row in data['sources']:
            row['raw'] = view.source_bytes(row['id'])
        out = Path(out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=lambda v: {'base64': base64.b64encode(v).decode('ascii')}), encoding='utf-8')
        out.with_suffix('.md').write_text('# 冷链交接结论\n\n' + '\n'.join(f"- {d['box_id']}: {d['result']}（规则 {d['rules_version']}）" for d in data['decisions']) + '\n', encoding='utf-8')
    finally:
        view.release()
        db.close()
    return out


def archive(db_path, representation, evidence_out=None):
    results = migrate_all(db_path, representation)
    evidence = {
        'command': 'archive',
        'representation': representation,
        'migrated': results,
        'verification': verify_archive(db_path),
        'accounting': storage_accounting(db_path),
    }
    if evidence_out:
        p = Path(evidence_out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(evidence, ensure_ascii=False, indent=2),
                     encoding='utf-8')
    return evidence


def demo(workdir):
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    db = workdir / 'coldhandoff.db'
    init(db, 'batch-1', 'box-1')
    events = [('clock_anchor', '2026-01-01T07:59:00+00:00', None), ('dispatch', '2026-01-01T08:00:00+00:00', None), ('temperature', '2026-01-01T08:00:00+00:00', 4),
              ('temperature', '2026-01-01T08:20:00+00:00', 4), ('temperature', '2026-01-01T08:40:00+00:00', 4),
              ('arrival', '2026-01-01T08:40:00+00:00', None), ('sign', '2026-01-01T08:40:00+00:00', None)]
    src = workdir / 'events.jsonl'
    src.write_text('\n'.join(json.dumps({'kind': kind, 'device': 'd1', 'seq': i, 'box_id': '' if kind == 'clock_anchor' else 'box-1', 'event_time': time, 'value': value, 'offset_seconds': 0 if kind == 'clock_anchor' else None}) for i, (kind, time, value) in enumerate(events, 1)), encoding='utf-8')
    ingest(src, db)
    evaluate(db)
    return report(db, workdir / 'report.json')


def main():
    p = argparse.ArgumentParser(description='离线冷链交接证据采录')
    sub = p.add_subparsers(dest='command', required=True)
    d = sub.add_parser('demo'); d.add_argument('--workdir')
    n = sub.add_parser('init'); n.add_argument('--db', required=True); n.add_argument('--batch', required=True); n.add_argument('--box', required=True)
    i = sub.add_parser('ingest'); i.add_argument('file'); i.add_argument('--db', required=True)
    e = sub.add_parser('evaluate'); e.add_argument('--db', required=True)
    r = sub.add_parser('report'); r.add_argument('--db', required=True); r.add_argument('--out', required=True)
    x = sub.add_parser('inspect'); x.add_argument('--db', required=True); x.add_argument('--box', required=True)
    a = sub.add_parser('archive')
    a.add_argument('--db', required=True)
    a.add_argument('--representation', required=True, choices=['fixed_64', 'record_chunks'])
    a.add_argument('--evidence-out')
    v = sub.add_parser('verify-archive'); v.add_argument('--db', required=True); v.add_argument('--out')
    g = sub.add_parser('gc')
    g.add_argument('--db', required=True); g.add_argument('--grace', type=float, default=60)
    g.add_argument('--vacuum', action='store_true')
    c = sub.add_parser('recover'); c.add_argument('--db', required=True); c.add_argument('--grace', type=float, default=60)
    s = sub.add_parser('storage-account'); s.add_argument('--db', required=True); s.add_argument('--out')
    args = p.parse_args()
    if args.command == 'demo':
        print(demo(args.workdir or tempfile.mkdtemp(prefix='coldhandoff-')))
    elif args.command == 'init':
        init(args.db, args.batch, args.box)
    elif args.command == 'init':
        init(args.db, args.batch, args.box)
    elif args.command == 'ingest':
        print(ingest(args.file, args.db))
    elif args.command == 'evaluate':
        print(evaluate(args.db))
    elif args.command == 'report':
        print(report(args.db, args.out))
    elif args.command == 'inspect':
        db = connect(args.db)
        print(json.dumps({'decision': [dict(r) for r in db.execute('SELECT * FROM decision WHERE box_id=?', (args.box,))], 'events': [dict(r) for r in db.execute('SELECT * FROM raw_event WHERE box_id=? ORDER BY event_time,id', (args.box,))]}, ensure_ascii=False))
        db.close()
    elif args.command == 'archive':
        print(json.dumps(archive(args.db, args.representation, args.evidence_out), ensure_ascii=False))
    elif args.command == 'verify-archive':
        payload = verify_archive(args.db)
        if args.out:
            Path(args.out).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(payload, ensure_ascii=False))
    elif args.command == 'gc':
        print(json.dumps(run_gc(args.db, grace_seconds=args.grace, vacuum=args.vacuum), ensure_ascii=False))
    elif args.command == 'recover':
        print(json.dumps(recover(args.db, grace_seconds=args.grace), ensure_ascii=False))
    elif args.command == 'storage-account':
        payload = storage_accounting(args.db)
        if args.out:
            Path(args.out).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(payload, ensure_ascii=False))


if __name__ == '__main__':
    main()
