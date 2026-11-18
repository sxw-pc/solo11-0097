"""Versioned intake, planning, transactional confirmation and recovery
for reusable insulated containers.

The module never reads temperature ``decision`` rows and never mutates the
cold-chain tables. Asset data lives in versioned ``asset_*`` tables: a
corrected contract or source box creates a new case version while the old
inventory and operation audit stay intact.
"""
import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from .ingest import parse_time
from .planner import POLICIES, STATE_ORDER, build_plan
from .store import connect


class AssetError(ValueError):
    """Asset lifecycle or transaction violation."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _load_case_row(db, case_id, version=None):
    if version is None:
        row = db.execute(
            'SELECT * FROM asset_case WHERE id=? ORDER BY version DESC LIMIT 1',
            (case_id,)).fetchone()
    else:
        row = db.execute(
            'SELECT * FROM asset_case WHERE id=? AND version=?',
            (case_id, version)).fetchone()
    if row is None:
        raise AssetError(f'unknown_case:{case_id}')
    return row


def _latest_version(db, case_id):
    row = db.execute(
        'SELECT COALESCE(MAX(version),0) FROM asset_case WHERE id=?',
        (case_id,)).fetchone()
    return row[0]


def _materialize(db, case_id, version, contract):
    """Freeze the contract into versioned container/need/equipment rows."""
    for idx, item in enumerate(contract['returns']):
        condition = item.get('condition', 'wash_required')
        if condition == 'contaminated':
            state, blocked = 'contaminated', 'contaminated'
        elif condition == 'quarantine' and item.get('inspection', 'pending') != 'passed':
            state, blocked = 'quarantine', (
                'inspection_failed' if item.get('inspection') == 'failed'
                else 'inspection_pending')
        else:
            state, blocked = 'returned', None
        release = item.get('inspection_release')
        db.execute(
            'INSERT INTO asset_container VALUES (?,?,?,?,?,?,?,?,?,?)',
            (item['asset_id'], case_id, version, 'returned',
             'box', item['from_box'], state, item['available'],
             blocked, release))
    for item in contract['needs']:
        db.execute('INSERT INTO asset_need VALUES (?,?,?,?,?)',
                   (item['id'], case_id, version, item['box_id'],
                    item['dispatch_by']))
    for key, role in (('washer', 'wash'), ('freezer', 'recharge')):
        items = contract.get(key + 's', [])
        if not items and key in contract:
            items = [contract[key]]
        for item in items:
            db.execute('INSERT INTO asset_equipment VALUES (?,?,?,?,?,?,?,?)',
                       (item['id'], case_id, version, role,
                        item['start'], item['end'],
                        int(item['minutes_per_asset']),
                        int(item.get('capacity', 1))))


def register_versioned(db_path, contract_path):
    """Like :func:`register` but returns ``{case_id, version, reused}``."""
    raw = Path(contract_path).read_bytes()
    contract = json.loads(raw)
    contract_hash = sha256(raw).hexdigest()
    db = connect(db_path)
    try:
        for item in contract['returns']:
            if db.execute('SELECT 1 FROM box WHERE id=?',
                          (item['from_box'],)).fetchone() is None:
                raise AssetError(f"unknown_return_box:{item['from_box']}")
        boxes = [dict(r) for r in db.execute(
            'SELECT * FROM box WHERE id IN (%s) ORDER BY id'
            % ','.join('?' for _ in contract['returns']),
            tuple(item['from_box'] for item in contract['returns']))]
        box_digest = sha256(json.dumps(
            boxes, sort_keys=True).encode()).hexdigest()
        with db:
            identical = db.execute(
                'SELECT version FROM asset_case WHERE id=? AND contract_sha256=?',
                (contract['case_id'], contract_hash)).fetchone()
            if identical is not None:
                return {'case_id': contract['case_id'],
                        'version': identical['version'], 'reused': True}
            previous = _latest_version(db, contract['case_id'])
            version = previous + 1
            db.execute(
                'INSERT INTO asset_case VALUES (?,?,?,?,?,?,?)',
                (contract['case_id'], version, contract_hash,
                 raw.decode(), box_digest,
                 previous if previous else None, _now()))
            _materialize(db, contract['case_id'], version, contract)
        return {'case_id': contract['case_id'], 'version': version,
                'reused': False}
    finally:
        db.close()


def register(db_path, contract_path):
    """Register (or version-correct) an asset case from a contract file.

    Returns the case id string for backward compatibility. Re-registering an
    identical contract is idempotent. Any byte change creates a new version
    referencing the previous one; old rows and audit history are preserved.
    Use :func:`register_versioned` to obtain the allocated version number.
    """
    return register_versioned(db_path, contract_path)['case_id']


def _contract_of(db, case_id, version):
    row = _load_case_row(db, case_id, version)
    return json.loads(row['contract_json']), row


def plan(db_path, case_id, policy, version=None):
    """Compute a deterministic, globally feasible plan (not yet confirmed)."""
    if policy not in POLICIES:
        raise AssetError(f'unknown_policy:{policy}')
    db = connect(db_path)
    try:
        contract, row = _contract_of(db, case_id, version)
        version = row['version']
        result = build_plan(contract, policy)
        plan_id = sha256(
            f"{case_id}:{version}:{policy}:{result['digest']}".encode()
        ).hexdigest()[:16]
        with db:
            existing = db.execute(
                'SELECT plan_id, confirmed FROM asset_plan WHERE case_id=? AND case_version=? AND policy=?',
                (case_id, version, policy)).fetchone()
            if existing is not None:
                if existing['confirmed']:
                    return {'plan_id': existing['plan_id'], 'confirmed': True,
                            'reused': True}
                db.execute('DELETE FROM asset_plan WHERE plan_id=?',
                           (existing['plan_id'],))
                db.execute('DELETE FROM asset_assignment WHERE plan_id=?',
                           (existing['plan_id'],))
                db.execute('DELETE FROM asset_purchase WHERE plan_id=?',
                           (existing['plan_id'],))
                db.execute('DELETE FROM asset_slot_lock WHERE plan_id=?',
                           (existing['plan_id'],))
            db.execute('INSERT INTO asset_plan VALUES (?,?,?,?,?,?,?,?)',
                       (plan_id, case_id, version, policy,
                        result['digest'], json.dumps(result, ensure_ascii=False),
                        0, None))
            for a in result['assignments']:
                db.execute(
                    'INSERT INTO asset_assignment(plan_id,need_id,asset_id,source,dispatched_at,on_time,late_minutes,late_cents) VALUES (?,?,?,?,?,?,?,?)',
                    (plan_id, a['need_id'], a['asset_id'], a['source'],
                     a['dispatched_at'], int(a['on_time']),
                     a['late_minutes'], a['late_cents']))
            for p in result['purchases']:
                db.execute('INSERT INTO asset_purchase VALUES (?,?,?,?,?)',
                           (f"{plan_id}:{p['asset_id']}", plan_id,
                            p['asset_id'], p['unit_cents'],
                            p['available_at']))
            for slot in result['slot_locks']:
                lock_id = sha256(
                    f"{plan_id}:{slot['equipment']}:{slot['asset_id']}:{slot['start']}".encode()
                ).hexdigest()[:16]
                db.execute('INSERT OR IGNORE INTO asset_slot_lock VALUES (?,?,?,?,?,?,?,?)',
                           (lock_id, plan_id, case_id, version,
                            slot['equipment'], slot['asset_id'],
                            slot['start'], slot['end']))
        return {'plan_id': plan_id, 'confirmed': False, 'reused': False,
                'digest': result['digest']}
    finally:
        db.close()


def _assert_transition(db, case_id, version, asset_id, expected, target):
    row = db.execute(
        'SELECT state FROM asset_container WHERE asset_id=? AND case_id=? AND case_version=?',
        (asset_id, case_id, version)).fetchone()
    if row is None:
        raise AssetError(f'unknown_asset:{asset_id}')
    current = row['state']
    if current == target:
        return False
    if current != expected:
        raise AssetError(
            f'illegal_transition:{asset_id}:{current}->{target} (want {expected})')
    if target in STATE_ORDER and expected in STATE_ORDER:
        if STATE_ORDER.index(target) <= STATE_ORDER.index(expected):
            raise AssetError(f'non_forward_transition:{asset_id}:{target}')
    return True


def _record_history(db, case_id, version, asset_id, frm, to, reason):
    hist_id = sha256(
        f'{case_id}:{version}:{asset_id}:{to}:{_now()}:{reason}'.encode()
    ).hexdigest()[:16]
    db.execute('INSERT INTO asset_state_history VALUES (?,?,?,?,?,?,?,?)',
               (hist_id, case_id, version, asset_id, frm, to, _now(), reason))


def confirm(db_path, plan_id):
    """Transactionally bind asset version, equipment slots and need identities.

    Idempotent: confirming an already-confirmed plan never re-dispatches or
    re-purchases. The whole lifecycle (operations, slot occupation, reserve,
    dispatch) is applied in one transaction, so a crash between wash and
    dispatch leaves either the full plan applied or nothing.
    """
    db = connect(db_path)
    try:
        plan_row = db.execute(
            'SELECT * FROM asset_plan WHERE plan_id=?', (plan_id,)).fetchone()
        if plan_row is None:
            raise AssetError(f'unknown_plan:{plan_id}')
        if plan_row['confirmed']:
            return {'plan_id': plan_id, 'confirmed': True, 'idempotent': True}
        case_id, version, policy = (plan_row['case_id'],
                                    plan_row['case_version'], plan_row['policy'])
        result = json.loads(plan_row['plan_json'])
        with db:
            # 需求身份排他：同一案例版本上，每个需求最多一份已确认领用
            for a in result['assignments']:
                clash = db.execute(
                    '''SELECT p.plan_id FROM asset_assignment a
                       JOIN asset_plan p ON p.plan_id=a.plan_id
                       WHERE p.case_id=? AND p.case_version=? AND p.confirmed=1
                         AND a.need_id=?''',
                    (case_id, version, a['need_id'])).fetchone()
                if clash is not None:
                    raise AssetError(
                        f"need_already_confirmed:{a['need_id']}:{clash['plan_id']}")
            # 设备时段排他：洗消台容量 1、蓄冷槽位占用直到完成。
            # 按带时区绝对时刻比较，避免不同 UTC 偏移下 ISO 字符串字典序失真。
            existing_locks = db.execute(
                '''SELECT l.lock_id, l.equip_id, l.start_at, l.end_at, l.asset_id
                   FROM asset_slot_lock l JOIN asset_plan p ON p.plan_id=l.plan_id
                   WHERE p.case_id=? AND p.case_version=? AND p.confirmed=1''',
                (case_id, version)).fetchall()
            for slot in result['slot_locks']:
                new_start = parse_time(slot['start'])
                new_end = parse_time(slot['end'])
                for row in existing_locks:
                    if row['equip_id'] != slot['equipment'] \
                            or row['asset_id'] == slot['asset_id']:
                        continue
                    if parse_time(row['start_at']) < new_end \
                            and new_start < parse_time(row['end_at']):
                        raise AssetError(
                            f"equipment_slot_conflict:{slot['equipment']}:{row['lock_id']}")
            # 容器实物排他：一只容器最多发给一个需求
            assigned = [a for a in result['assignments']]
            assets_used = [a['asset_id'] for a in assigned]
            if len(set(assets_used)) != len(assets_used):
                raise AssetError('asset_double_reservation')
            for asset_id in assets_used:
                clash = db.execute(
                    '''SELECT a.need_id FROM asset_assignment a
                       JOIN asset_plan p ON p.plan_id=a.plan_id
                       WHERE p.case_id=? AND p.case_version=? AND p.confirmed=1
                         AND a.asset_id=?''',
                    (case_id, version, asset_id)).fetchone()
                if clash is not None:
                    raise AssetError(
                        f'asset_already_dispatched:{asset_id}:{clash["need_id"]}')

            # 应用真实作业顺序 returned->washed->recharging->recharged->ready
            for c in result['containers']:
                if c['kind'] != 'returned' or c['operations'] is None:
                    continue
                aid = c['asset_id']
                src = f"{case_id}/{plan_id}"
                ops = c['operations']
                _assert_transition(db, case_id, version, aid,
                                   'returned', 'washed')
                db.execute(
                    'INSERT INTO asset_operation VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (sha256(f'{plan_id}:{aid}:wash'.encode()).hexdigest()[:16],
                     case_id, version, aid, 'wash', ops['wash']['equipment'],
                     src, ops['wash']['start'], ops['wash']['end'], 'washed'))
                db.execute(
                    'UPDATE asset_container SET state=? WHERE asset_id=? AND case_id=? AND case_version=?',
                    ('washed', aid, case_id, version))
                _record_history(db, case_id, version, aid, 'returned',
                                'washed', f"plan={plan_id}")
                _assert_transition(db, case_id, version, aid,
                                   'washed', 'recharging')
                db.execute(
                    'INSERT INTO asset_operation VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (sha256(f'{plan_id}:{aid}:recharge'.encode()).hexdigest()[:16],
                     case_id, version, aid, 'recharge',
                     ops['recharge']['equipment'], src,
                     ops['recharge']['start'], ops['recharge']['end'],
                     'recharged'))
                db.execute(
                    'UPDATE asset_container SET state=? WHERE asset_id=? AND case_id=? AND case_version=?',
                    ('recharging', aid, case_id, version))
                _record_history(db, case_id, version, aid, 'washed',
                                'recharging', f"plan={plan_id}")
                db.execute(
                    'UPDATE asset_container SET state=? WHERE asset_id=? AND case_id=? AND case_version=?',
                    ('recharged', aid, case_id, version))
                _record_history(db, case_id, version, aid, 'recharging',
                                'recharged', f"plan={plan_id}")
                db.execute(
                    'UPDATE asset_container SET state=? WHERE asset_id=? AND case_id=? AND case_version=?',
                    ('ready', aid, case_id, version))
                _record_history(db, case_id, version, aid, 'recharged',
                                'ready', f"plan={plan_id}")

            # 采购新容器按合同到货时间进入可用库存
            for p in result['purchases']:
                db.execute(
                    'INSERT OR IGNORE INTO asset_container VALUES (?,?,?,?,?,?,?,?,?,?)',
                    (p['asset_id'], case_id, version, 'purchased',
                     'purchase', plan_id, 'ready', p['available_at'],
                     None, None))
                _record_history(db, case_id, version, p['asset_id'], None,
                                'ready', f"purchase={plan_id}")

            # 预留 -> 发出（每只容器最多一个需求，每个需求最多一只）
            for a in assigned:
                aid = a['asset_id']
                _assert_transition(db, case_id, version, aid,
                                   'ready', 'reserved')
                db.execute(
                    'UPDATE asset_container SET state=? WHERE asset_id=? AND case_id=? AND case_version=?',
                    ('reserved', aid, case_id, version))
                _record_history(db, case_id, version, aid, 'ready',
                                'reserved', f"need={a['need_id']}")
                _assert_transition(db, case_id, version, aid,
                                   'reserved', 'dispatched')
                db.execute(
                    'UPDATE asset_container SET state=? WHERE asset_id=? AND case_id=? AND case_version=?',
                    ('dispatched', aid, case_id, version))
                _record_history(db, case_id, version, aid, 'reserved',
                                'dispatched',
                                f"need={a['need_id']} at={a['dispatched_at']}")

            db.execute(
                'UPDATE asset_plan SET confirmed=1, confirmed_at=? WHERE plan_id=?',
                (_now(), plan_id))
        return {'plan_id': plan_id, 'confirmed': True, 'idempotent': False,
                'assignments': len(assigned),
                'purchases': len(result['purchases'])}
    finally:
        db.close()


def recover(db_path, case_id, version=None):
    """Detect and compensate interrupted asset operations.

    A confirmed plan is applied atomically, so the normal crash modes are an
    *unconfirmed* plan holding draft slot locks, or container rows left in a
    transient ``recharging`` state by a partial manual update. Draft locks are
    released; transient containers without a matching confirmed operation are
    rolled back to their last durable state. Confirmed dispatches are never
    rewritten.
    """
    db = connect(db_path)
    try:
        row = _load_case_row(db, case_id, version)
        version = row['version']
        actions = []
        with db:
            # 未确认草案的槽位锁不构成实物占用，直接释放
            draft_locks = db.execute(
                '''SELECT l.lock_id FROM asset_slot_lock l
                   JOIN asset_plan p ON p.plan_id=l.plan_id
                   WHERE p.case_id=? AND p.case_version=? AND p.confirmed=0''',
                (case_id, version)).fetchall()
            for l in draft_locks:
                db.execute('DELETE FROM asset_slot_lock WHERE lock_id=?',
                           (l['lock_id'],))
                actions.append(f"release_draft_lock:{l['lock_id']}")
            # 卡在中间态且无对应已确认操作的容器，回滚到上一持久态
            for c in db.execute(
                    'SELECT * FROM asset_container WHERE case_id=? AND case_version=?',
                    (case_id, version)):
                if c['state'] not in ('recharging', 'reserved'):
                    continue
                confirmed_op = db.execute(
                    '''SELECT 1 FROM asset_operation o
                       WHERE o.asset_id=? AND o.case_id=? AND o.case_version=?
                         AND EXISTS (SELECT 1 FROM asset_plan p
                                     WHERE p.confirmed=1
                                       AND o.source_ref LIKE p.case_id || '/' || p.plan_id)
                       LIMIT 1''',
                    (c['asset_id'], case_id, version)).fetchone()
                if confirmed_op:
                    continue
                fallback = 'washed' if c['state'] == 'recharging' else 'ready'
                db.execute(
                    'UPDATE asset_container SET state=? WHERE asset_id=? AND case_id=? AND case_version=?',
                    (fallback, c['asset_id'], case_id, version))
                _record_history(db, case_id, version, c['asset_id'],
                                c['state'], fallback, 'crash_recovery')
                actions.append(
                    f"rollback:{c['asset_id']}:{c['state']}->{fallback}")
        return {'case_id': case_id, 'version': version, 'actions': actions}
    finally:
        db.close()


def get_plan(db_path, plan_id):
    db = connect(db_path)
    try:
        row = db.execute('SELECT * FROM asset_plan WHERE plan_id=?',
                         (plan_id,)).fetchone()
        if row is None:
            raise AssetError(f'unknown_plan:{plan_id}')
        return json.loads(row['plan_json'])
    finally:
        db.close()


def case_status(db_path, case_id, version=None):
    """Read-only inventory / operation / confirmation view for reports."""
    db = connect(db_path)
    try:
        row = _load_case_row(db, case_id, version)
        version = row['version']
        data = {
            'case_id': case_id, 'version': version,
            'contract_sha256': row['contract_sha256'],
            'supersedes_version': row['supersedes_version'],
            'containers': [dict(r) for r in db.execute(
                'SELECT * FROM asset_container WHERE case_id=? AND case_version=? ORDER BY asset_id',
                (case_id, version))],
            'needs': [dict(r) for r in db.execute(
                'SELECT * FROM asset_need WHERE case_id=? AND case_version=? ORDER BY id',
                (case_id, version))],
            'equipment': [dict(r) for r in db.execute(
                'SELECT * FROM asset_equipment WHERE case_id=? AND case_version=? ORDER BY equip_id',
                (case_id, version))],
            'operations': [dict(r) for r in db.execute(
                'SELECT * FROM asset_operation WHERE case_id=? AND case_version=? ORDER BY start_at,asset_id',
                (case_id, version))],
            'history': [dict(r) for r in db.execute(
                'SELECT * FROM asset_state_history WHERE case_id=? AND case_version=? ORDER BY at_time,hist_id',
                (case_id, version))],
            'plans': [dict(r) for r in db.execute(
                'SELECT plan_id,policy,confirmed,confirmed_at,plan_digest FROM asset_plan WHERE case_id=? AND case_version=? ORDER BY policy',
                (case_id, version))],
        }
        return data
    finally:
        db.close()
