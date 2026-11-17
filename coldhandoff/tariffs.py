"""Freeze real box context and offline carrier tariff sources; do not quote or publish."""
import hashlib
import json
from pathlib import Path
from .store import connect


def register(db_path, case_id, contract_path, source_dir):
    contract_path = Path(contract_path).resolve()
    source_dir = Path(source_dir).resolve()
    raw = contract_path.read_bytes()
    contract = json.loads(raw)
    if not case_id or not contract.get('source_pages') or not contract.get('publish_target'):
        raise ValueError('tariff_contract_invalid')
    sources = []
    for name in contract['source_pages']:
        path = (source_dir / name).resolve()
        if path.parent != source_dir or path.suffix not in {'.html', '.csv', '.json'}:
            raise ValueError('tariff_source_invalid')
        body = path.read_bytes()
        sources.append({'name': name, 'sha256': hashlib.sha256(body).hexdigest(), 'body': body.decode('utf-8')})
    db = connect(db_path)
    try:
        box = db.execute('SELECT id,batch_id FROM box WHERE id=?', (contract['box_id'],)).fetchone()
        event = db.execute("SELECT e.id,s.hash AS source_sha FROM raw_event e JOIN source_file s ON s.id=e.source_id WHERE e.box_id=? AND e.device=? AND e.kind='arrival' ORDER BY e.id LIMIT 1", (contract['box_id'], contract['device'])).fetchone()
        if box is None or event is None:
            raise ValueError('tariff_box_arrival_missing')
        payload = json.dumps({'contract': contract, 'contract_sha256': hashlib.sha256(raw).hexdigest(),
                              'box': dict(box), 'arrival': dict(event), 'sources': sources},
                             sort_keys=True, separators=(',', ':'))
        with db:
            old = db.execute('SELECT payload FROM tariff_case WHERE id=?', (case_id,)).fetchone()
            if old and old['payload'] != payload:
                raise ValueError('tariff_case_conflict')
            db.execute('INSERT OR IGNORE INTO tariff_case VALUES (?,?)', (case_id, payload))
    finally:
        db.close()
    return {'case_id': case_id, 'sources': len(sources)}
