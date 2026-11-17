"""Local post-handoff cooler endpoint; control planning is intentionally absent."""

import hashlib
import json
from pathlib import Path

from .store import connect


def register(db_path, case_id, fixture):
    raw = Path(fixture).read_bytes()
    doc = json.loads(raw)
    if not case_id or not doc.get('boxes') or not doc.get('periods') or not isinstance(doc.get('coolant_cycles'), int):
        raise ValueError('bad_hold_case')
    db = connect(db_path)
    try:
        with db:
            for spec in doc['boxes']:
                decision = db.execute('SELECT result FROM decision WHERE box_id=?', (spec['id'],)).fetchone()
                if not decision or decision['result'] != '完整':
                    raise ValueError('box_not_handoff_complete')
                row = db.execute(
                    '''SELECT r.payload,s.hash FROM raw_event r JOIN source_file s ON s.id=r.source_id
                       WHERE r.box_id=? AND r.kind='temperature' ORDER BY r.event_time DESC,r.id DESC LIMIT 1''',
                    (spec['id'],),
                ).fetchone()
                if not row or row['hash'] != spec['source_hash'] or float(json.loads(row['payload'])['value']) != spec['initial_temperature']:
                    raise ValueError('hold_temperature_source_mismatch')
            digest = hashlib.sha256(raw).hexdigest()
            old = db.execute('SELECT digest FROM hold_case WHERE id=?', (case_id,)).fetchone()
            if old and old['digest'] != digest:
                raise ValueError('hold_case_conflict')
            db.execute('INSERT OR IGNORE INTO hold_case VALUES (?,?,?)',
                       (case_id, json.dumps(doc, sort_keys=True), digest))
            db.execute('INSERT OR IGNORE INTO hold_cooler VALUES (?,?)',
                       (case_id, doc['coolant_cycles']))
            for spec in doc['boxes']:
                db.execute('INSERT OR IGNORE INTO hold_box VALUES (?,?,?,0)',
                           (case_id, spec['id'], spec['initial_temperature']))
    finally:
        db.close()
    return {'case_id': case_id, 'digest': digest, 'boxes': len(doc['boxes'])}


def state(db_path, case_id):
    db = connect(db_path)
    try:
        rows = [dict(x) for x in db.execute(
            'SELECT box_id,temperature,period FROM hold_box WHERE case_id=? ORDER BY box_id',
            (case_id,),
        )]
        if not rows:
            raise ValueError('unknown_hold_case')
        return rows
    finally:
        db.close()


def cooler_state(db_path, case_id):
    db = connect(db_path)
    try:
        row = db.execute('SELECT remaining_cycles FROM hold_cooler WHERE case_id=?', (case_id,)).fetchone()
        if not row:
            raise ValueError('unknown_hold_case')
        return row['remaining_cycles']
    finally:
        db.close()


def actuate(db_path, case_id, period, cooled_box, operation_id):
    db = connect(db_path)
    try:
        with db:
            old = db.execute('SELECT result FROM hold_action WHERE id=?', (operation_id,)).fetchone()
            if old:
                return {'status': 'replayed', 'record': json.loads(old['result'])}
            row = db.execute('SELECT payload FROM hold_case WHERE id=?', (case_id,)).fetchone()
            if not row:
                raise ValueError('unknown_hold_case')
            doc = json.loads(row['payload'])
            if period < 0 or period >= len(doc['periods']):
                raise ValueError('period_out_of_range')
            boxes = {x['id']: x for x in doc['boxes']}
            if cooled_box is not None and cooled_box not in boxes:
                raise ValueError('unknown_cooled_box')
            actual = [dict(x) for x in db.execute(
                'SELECT box_id,temperature,period FROM hold_box WHERE case_id=? ORDER BY box_id',
                (case_id,),
            )]
            if any(x['period'] != period for x in actual):
                raise ValueError('period_sequence_conflict')
            remaining = db.execute('SELECT remaining_cycles FROM hold_cooler WHERE case_id=?', (case_id,)).fetchone()['remaining_cycles']
            if cooled_box is not None and remaining < 1:
                raise ValueError('coolant_exhausted')
            window = doc['periods'][period]
            result_boxes = {}
            for before in actual:
                spec = boxes[before['box_id']]
                after = before['temperature'] + window['ambient_gain'][before['box_id']]
                if before['box_id'] == cooled_box:
                    after -= spec['cooling']
                if after < spec['minimum_temperature']:
                    raise ValueError('overcooling')
                exposure = max(0, after - spec['hold_max_temperature'])
                result_boxes[before['box_id']] = {'temperature': after, 'exposure': exposure}
                db.execute('UPDATE hold_box SET temperature=?,period=? WHERE case_id=? AND box_id=?',
                           (after, period + 1, case_id, before['box_id']))
            result = {'status': 'applied', 'period': period, 'cooled_box': cooled_box,
                      'energy_cents': window['cooling_price_cents'] if cooled_box else 0,
                      'boxes': result_boxes}
            db.execute('INSERT INTO hold_action VALUES (?,?,?,?,?)',
                       (operation_id, case_id, period, cooled_box, json.dumps(result, sort_keys=True)))
            if cooled_box is not None:
                db.execute('UPDATE hold_cooler SET remaining_cycles=remaining_cycles-1 WHERE case_id=?', (case_id,))
            return result
    finally:
        db.close()


def observe(db_path, case_id, fixture):
    """Accept an actual sensor reading after a period, without changing the action log."""
    raw = Path(fixture).read_bytes()
    obs = json.loads(raw)
    db = connect(db_path)
    try:
        with db:
            prior = db.execute('SELECT id FROM hold_observation WHERE id=?', (obs['id'],)).fetchone()
            if prior:
                return {'status': 'replayed', 'id': obs['id']}
            if not db.execute('SELECT 1 FROM hold_action WHERE case_id=? AND period=?',
                              (case_id, obs['period'])).fetchone():
                raise ValueError('hold_period_not_executed')
            row = db.execute('SELECT temperature,period FROM hold_box WHERE case_id=? AND box_id=?',
                             (case_id, obs['box_id'])).fetchone()
            if not row or row['period'] != obs['period'] + 1:
                raise ValueError('observation_not_current')
            db.execute('INSERT INTO hold_observation VALUES (?,?,?,?,?,?)',
                       (obs['id'], case_id, obs['box_id'], obs['period'],
                        obs['actual_temperature'], hashlib.sha256(raw).hexdigest()))
            db.execute('UPDATE hold_box SET temperature=? WHERE case_id=? AND box_id=?',
                       (obs['actual_temperature'], case_id, obs['box_id']))
            return {'status': 'observed', 'box_id': obs['box_id'],
                    'predicted_temperature': row['temperature'],
                    'actual_temperature': obs['actual_temperature'],
                    'remaining_cycles': db.execute('SELECT remaining_cycles FROM hold_cooler WHERE case_id=?',
                                                   (case_id,)).fetchone()['remaining_cycles']}
    finally:
        db.close()
