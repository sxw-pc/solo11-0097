"""Tests for reusable insulated-container recycle/re-dispatch cycle."""
import copy
import json
from pathlib import Path

import pytest

from coldhandoff.__main__ import asset_report, init
from coldhandoff.assets import (AssetError, case_status, confirm, plan,
                                recover, register, register_versioned)
from coldhandoff.planner import (LIMITS, PlannerError, build_plan, normalize)
from coldhandoff.store import connect

FIXTURE = Path(__file__).parents[1] / 'fixtures' / 'asset-cycle.json'
TZ = '+08:00'


def load_contract():
    return json.loads(FIXTURE.read_text(encoding='utf-8'))


def seed_boxes(db, boxes='ABCD'):
    for box in boxes:
        init(db, 'batch-1', box)


# --------------------------------------------------------------------------
# 题面给定的精确解
# --------------------------------------------------------------------------
def test_fixture_reuse_first_exact_solution():
    plan_ = build_plan(load_contract(), 'reuse_first')
    by_need = {a['need_id']: a for a in plan_['assignments']}
    assert by_need['N1']['asset_id'] == 'T-A'
    assert by_need['N1']['on_time'] is True
    assert by_need['N2']['asset_id'] == 'T-B'
    assert by_need['N2']['on_time'] is False
    assert by_need['N2']['late_minutes'] == 30
    assert by_need['N2']['late_cents'] == 3000
    costs = plan_['costs']
    assert costs['wash_cents'] == 2000
    assert costs['purchase_count'] == 0
    assert costs['late_cents'] == 3000
    assert costs['total_cents'] == 5000
    ops = {c['asset_id']: c['operations'] for c in plan_['containers']}
    assert ops['T-A']['wash']['start'][11:16] == '08:00'
    assert ops['T-A']['wash']['end'][11:16] == '08:30'
    assert ops['T-A']['recharge']['start'][11:16] == '08:30'
    assert ops['T-A']['recharge']['end'][11:16] == '10:00'
    assert ops['T-B']['wash']['start'][11:16] == '08:30'
    assert ops['T-B']['recharge']['end'][11:16] == '10:30'


def test_fixture_deadline_first_buys_one_new_container():
    plan_ = build_plan(load_contract(), 'deadline_first')
    by_need = {a['need_id']: a for a in plan_['assignments']}
    assert by_need['N1']['asset_id'] == 'T-A'
    assert by_need['N1']['on_time'] is True
    assert by_need['N2']['source'] == 'purchased'
    assert by_need['N2']['on_time'] is True
    assert by_need['N2']['dispatched_at'][11:16] == '09:00'
    costs = plan_['costs']
    assert costs['wash_cents'] == 1000
    assert costs['purchase_count'] == 1
    assert costs['purchase_cents'] == 12000
    assert costs['late_cents'] == 0
    assert costs['total_cents'] == 13000
    # 两方案都完整可执行，却改变实物来源、库存与交付时间
    assert plan_['inventory']['unprocessed_returned'] == ['T-B']


def test_two_policies_differ_in_physical_source():
    reuse = build_plan(load_contract(), 'reuse_first')
    deadline = build_plan(load_contract(), 'deadline_first')
    r_src = {a['need_id']: a['asset_id'] for a in reuse['assignments']}
    d_src = {a['need_id']: a['need_id'] and a['asset_id']
             for a in deadline['assignments']}
    assert r_src != d_src


# --------------------------------------------------------------------------
# 作业顺序与隔离
# --------------------------------------------------------------------------
def test_lifecycle_order_is_returned_to_dispatched():
    plan_ = build_plan(load_contract(), 'reuse_first')
    expected = ['returned', 'wash_start', 'washed', 'recharge_start',
                'recharging', 'recharged', 'ready', 'dispatched']
    for c in plan_['containers']:
        if c['state'] != 'dispatched':
            continue
        stages = [t['stage'] for t in c['timeline']]
        ordered = [s for s in expected if s in stages]
        assert ordered == expected


def test_quarantine_pending_blocks_wash_and_dispatch():
    contract = load_contract()
    contract['returns'].append({
        'asset_id': 'T-Q', 'from_box': 'A',
        'available': f'2030-06-02T08:00:00{TZ}',
        'condition': 'quarantine', 'inspection': 'pending'})
    plan_ = build_plan(contract, 'reuse_first')
    tq = next(c for c in plan_['containers'] if c['asset_id'] == 'T-Q')
    assert tq['state'] == 'quarantine'
    assert tq['operations'] is None
    assert tq['asset_id'] not in [a['asset_id'] for a in plan_['assignments']]
    assert 'T-Q' in plan_['inventory']['quarantine']


def test_contaminated_container_never_skips_wash():
    contract = load_contract()
    contract['returns'].append({
        'asset_id': 'T-X', 'from_box': 'B',
        'available': f'2030-06-02T08:00:00{TZ}',
        'condition': 'contaminated'})
    plan_ = build_plan(contract, 'deadline_first')
    tx = next(c for c in plan_['containers'] if c['asset_id'] == 'T-X')
    assert tx['state'] == 'contaminated'
    assert tx['operations'] is None
    assert 'T-X' in plan_['inventory']['contaminated']


def test_quarantine_released_after_inspection_becomes_eligible():
    contract = load_contract()
    # T-A 待检后放行；T-B 污染不可用，使 T-A 成为唯一可复用箱
    contract['returns'][0] = {
        'asset_id': 'T-A', 'from_box': 'A',
        'available': f'2030-06-02T08:00:00{TZ}',
        'condition': 'quarantine', 'inspection': 'passed',
        'inspection_release': f'2030-06-02T08:10:00{TZ}'}
    contract['returns'][1]['condition'] = 'contaminated'
    contract['needs'] = [contract['needs'][0]]
    plan_ = build_plan(contract, 'reuse_first')
    ta = next(c for c in plan_['containers'] if c['asset_id'] == 'T-A')
    assert ta['operations'] is not None
    assert ta['operations']['wash']['start'][11:16] >= '08:10'
    assert plan_['assignments'][0]['asset_id'] == 'T-A'


# --------------------------------------------------------------------------
# 有限设备：洗消冲突与蓄冷容量
# --------------------------------------------------------------------------
def test_single_washer_cannot_process_two_containers_at_once():
    contract = load_contract()
    plan_ = build_plan(contract, 'reuse_first')
    washes = [s for s in plan_['slot_locks'] if s['stage'] == 'wash']
    for i, a in enumerate(washes):
        for b in washes[i + 1:]:
            if a['equipment'] != b['equipment']:
                continue
            assert a['end'] <= b['start'] or b['end'] <= a['start']


def test_freezer_capacity_respected_for_overlapping_slots():
    # 两台洗消台、一个容量 1 的蓄冷柜：蓄冷必须串行
    contract = load_contract()
    contract['freezer'] = {
        'id': 'F1', 'start': f'2030-06-02T08:00:00{TZ}',
        'end': f'2030-06-02T14:00:00{TZ}', 'capacity': 1,
        'minutes_per_asset': 90}
    plan_ = build_plan(contract, 'reuse_first')
    rec = [s for s in plan_['slot_locks'] if s['stage'] == 'recharge']
    for i, a in enumerate(rec):
        for b in rec[i + 1:]:
            if a['equipment'] != b['equipment']:
                continue
            assert a['end'] <= b['start'] or b['end'] <= a['start']


def test_recharge_cannot_start_before_wash_completes():
    plan_ = build_plan(load_contract(), 'reuse_first')
    for c in plan_['containers']:
        if c['operations'] is None:
            continue
        assert c['operations']['recharge']['start'] >= c['operations']['wash']['end']


def test_washer_window_boundary_enforced():
    contract = load_contract()
    # 窗口只够洗一只（30 分钟），第二只无法在窗口内完成
    contract['washer']['end'] = f'2030-06-02T08:30:00{TZ}'
    plan_ = build_plan(contract, 'reuse_first')
    washed = [c for c in plan_['containers'] if c['operations'] is not None]
    assert len(washed) == 1


# --------------------------------------------------------------------------
# 到货边界与晚领罚则
# --------------------------------------------------------------------------
def test_purchase_enters_inventory_at_contract_arrival():
    plan_ = build_plan(load_contract(), 'deadline_first')
    bought = [p for p in plan_['purchases']]
    assert bought and bought[0]['available_at'][11:16] == '09:00'
    new_box = next(c for c in plan_['containers'] if c['kind'] == 'purchased')
    assert new_box['available'][11:16] == '09:00'


def test_purchase_arrival_after_deadline_is_marked_late_explicitly():
    contract = load_contract()
    contract['purchase']['available'] = f'2030-06-02T10:30:00{TZ}'
    plan_ = build_plan(contract, 'deadline_first')
    late = [a for a in plan_['assignments'] if a['source'] == 'purchased']
    assert all(a['late_minutes'] == 30 and a['late_cents'] == 3000
               and a['late_note'] for a in late)


def test_late_fee_ceil_in_30_minute_units():
    contract = load_contract()
    # 让 T-B 晚 45 分钟：罚金按 2 个 30 分钟单位计
    contract['freezer']['minutes_per_asset'] = 105
    plan_ = build_plan(contract, 'reuse_first')
    tb = next(a for a in plan_['assignments'] if a['asset_id'] == 'T-B')
    assert tb['late_minutes'] == 45
    assert tb['late_cents'] == 6000


# --------------------------------------------------------------------------
# 需求/容器一对一与稳定裁定
# --------------------------------------------------------------------------
def test_one_container_max_one_need_and_need_max_one_container():
    for policy in ('reuse_first', 'deadline_first'):
        plan_ = build_plan(load_contract(), policy)
        assets = [a['asset_id'] for a in plan_['assignments']]
        needs = [a['need_id'] for a in plan_['assignments']]
        assert len(assets) == len(set(assets))
        assert len(needs) == len(set(needs))


def test_tie_break_stable_by_id_and_deterministic():
    contract = load_contract()
    first = build_plan(contract, 'deadline_first')
    second = build_plan(contract, 'deadline_first')
    assert first['digest'] == second['digest']
    # 并列时低 ID 复用箱优先发给低 ID 需求
    assert first['assignments'][0]['asset_id'] == 'T-A'


def test_unknown_policy_rejected():
    with pytest.raises(PlannerError):
        build_plan(load_contract(), 'whatever_first')


def test_scale_limits_enforced():
    contract = load_contract()
    contract['returns'] = [{
        'asset_id': f'T{i}', 'from_box': 'A',
        'available': f'2030-06-02T08:00:00{TZ}',
        'condition': 'wash_required'} for i in range(LIMITS['returns'] + 1)]
    with pytest.raises(PlannerError):
        normalize(contract)


def test_max_scale_solves_exactly_within_budget():
    # 上限规模 10 归还 / 8 需求 / 3 洗消台 / 3 蓄冷柜，精确求解且自洽
    contract = load_contract()
    contract['returns'] = [{
        'asset_id': f'T-{i:02d}', 'from_box': 'A',
        'available': f'2030-06-02T08:00:00{TZ}',
        'condition': 'wash_required'} for i in range(10)]
    contract['needs'] = [{
        'id': f'N{i}', 'box_id': f'D{i}',
        'dispatch_by': f'2030-06-02T12:00:00{TZ}'} for i in range(8)]
    contract['washers'] = [{
        'id': f'W{i}', 'start': f'2030-06-02T08:00:00{TZ}',
        'end': f'2030-06-02T12:00:00{TZ}', 'minutes_per_asset': 30}
        for i in range(3)]
    contract.pop('washer')
    contract['freezers'] = [{
        'id': f'F{i}', 'start': f'2030-06-02T08:00:00{TZ}',
        'end': f'2030-06-02T14:00:00{TZ}', 'capacity': 2,
        'minutes_per_asset': 90} for i in range(3)]
    contract.pop('freezer')
    plan_ = build_plan(contract, 'reuse_first')
    assert len(plan_['assignments']) == 8
    # 无设备时段重叠冲突
    washes = [s for s in plan_['slot_locks'] if s['stage'] == 'wash']
    by_equip = {}
    for s in washes:
        by_equip.setdefault(s['equipment'], []).append(s)
    for slots in by_equip.values():
        slots.sort(key=lambda x: x['start'])
        for a, b in zip(slots, slots[1:]):
            assert a['end'] <= b['start']


# --------------------------------------------------------------------------
# 持久化、事务、版本化与恢复
# --------------------------------------------------------------------------
def _registered_db(tmp_path, contract=None):
    db = tmp_path / 'cold.db'
    seed_boxes(db)
    cid = register(db, FIXTURE if contract is None else _write(tmp_path, contract))
    return db, cid


def _write(tmp_path, contract):
    p = tmp_path / 'contract.json'
    p.write_text(json.dumps(contract, ensure_ascii=False), encoding='utf-8')
    return p


def test_register_is_idempotent_and_versioned(tmp_path):
    db, cid = _registered_db(tmp_path)
    again = register_versioned(db, FIXTURE)
    assert again['reused'] is True and again['version'] == 1


def test_contract_correction_creates_new_version_keeps_audit(tmp_path):
    db, cid = _registered_db(tmp_path)
    plan_id = plan(db, cid, 'reuse_first')['plan_id']
    confirm(db, plan_id)
    changed = load_contract()
    changed['wash_cents_per_asset'] = 1234
    path = _write(tmp_path, changed)
    info = register_versioned(db, path)
    assert info['version'] == 2 and info['reused'] is False
    con = connect(db)
    # 旧版本库存/审计保留
    old = con.execute(
        'SELECT state FROM asset_container WHERE case_version=1 AND asset_id=?',
        ('T-A',)).fetchone()
    assert old['state'] == 'dispatched'
    new = con.execute(
        'SELECT state FROM asset_container WHERE case_version=2 AND asset_id=?',
        ('T-A',)).fetchone()
    assert new['state'] == 'returned'
    con.close()


def test_confirm_binds_version_slots_and_needs_transactionally(tmp_path):
    db, cid = _registered_db(tmp_path)
    plan_id = plan(db, cid, 'reuse_first')['plan_id']
    confirm(db, plan_id)
    con = connect(db)
    assert con.execute(
        'SELECT confirmed FROM asset_plan WHERE plan_id=?', (plan_id,)
    ).fetchone()[0] == 1
    states = {r['asset_id']: r['state']
              for r in con.execute('SELECT asset_id,state FROM asset_container')}
    assert states == {'T-A': 'dispatched', 'T-B': 'dispatched'}
    # 洗消与蓄冷操作可追溯到时段与来源
    ops = con.execute(
        'SELECT stage,equip_id,start_at,end_at,source_ref FROM asset_operation ORDER BY start_at'
    ).fetchall()
    assert len(ops) == 4
    assert all(o['source_ref'].endswith(plan_id) for o in ops)
    con.close()


def test_repeat_confirm_does_not_redispatch_or_repurchase(tmp_path):
    db, cid = _registered_db(tmp_path)
    plan_id = plan(db, cid, 'deadline_first')['plan_id']
    first = confirm(db, plan_id)
    second = confirm(db, plan_id)
    assert first['idempotent'] is False and second['idempotent'] is True
    con = connect(db)
    assert con.execute(
        'SELECT count(*) FROM asset_purchase').fetchone()[0] == 1
    assert con.execute(
        'SELECT count(*) FROM asset_operation').fetchone()[0] == 2
    con.close()


def test_two_mutually_exclusive_plans_cannot_share_need(tmp_path):
    db, cid = _registered_db(tmp_path)
    reuse_pid = plan(db, cid, 'reuse_first')['plan_id']
    deadline_pid = plan(db, cid, 'deadline_first')['plan_id']
    confirm(db, reuse_pid)
    with pytest.raises(AssetError, match='need_already_confirmed'):
        confirm(db, deadline_pid)
    # 被拒事务不留半成品：采购箱未入库
    con = connect(db)
    assert con.execute(
        "SELECT count(*) FROM asset_container WHERE kind='purchased'"
    ).fetchone()[0] == 0
    con.close()


def test_confirm_detects_equipment_slot_overlap(tmp_path):
    db, cid = _registered_db(tmp_path)
    plan_id = plan(db, cid, 'reuse_first')['plan_id']
    # 先塞入一条同案例版本的“已确认”幽灵锁，占用与 T-A 洗消重叠的时段
    con = connect(db)
    con.execute(
        "INSERT INTO asset_plan VALUES ('ghost',?,1,'deadline_first','d','{}',1,?)",
        (cid, '2030-06-02T08:00:00+08:00'))
    con.execute(
        "INSERT INTO asset_slot_lock VALUES ('g1','ghost',?,1,'W1','T-G',?,?)",
        (cid, '2030-06-02T08:15:00+08:00', '2030-06-02T08:45:00+08:00'))
    con.commit()
    con.close()
    with pytest.raises(AssetError, match='equipment_slot_conflict'):
        confirm(db, plan_id)


def test_confirmed_assignment_cannot_be_overwritten(tmp_path):
    db, cid = _registered_db(tmp_path)
    plan_id = plan(db, cid, 'reuse_first')['plan_id']
    confirm(db, plan_id)
    # 重新出计划只返回已确认草案，不产生新领用
    again = plan(db, cid, 'reuse_first')
    assert again['confirmed'] is True and again['plan_id'] == plan_id


def test_recovery_rolls_back_interrupted_container_and_releases_locks(tmp_path):
    db, cid = _registered_db(tmp_path)
    plan(db, cid, 'reuse_first')  # 未确认草案，带槽位锁
    con = connect(db)
    con.execute(
        "UPDATE asset_container SET state='recharging' WHERE asset_id='T-A'")
    con.commit()
    con.close()
    result = recover(db, cid)
    assert any('release_draft_lock' in a for a in result['actions'])
    assert any('rollback:T-A' in a for a in result['actions'])
    con = connect(db)
    assert con.execute(
        "SELECT state FROM asset_container WHERE asset_id='T-A'"
    ).fetchone()[0] == 'washed'
    assert con.execute('SELECT count(*) FROM asset_slot_lock').fetchone()[0] == 0
    con.close()


def test_recovery_never_touches_confirmed_dispatch(tmp_path):
    db, cid = _registered_db(tmp_path)
    plan_id = plan(db, cid, 'reuse_first')['plan_id']
    confirm(db, plan_id)
    result = recover(db, cid)
    assert result['actions'] == []
    con = connect(db)
    assert con.execute(
        "SELECT state FROM asset_container WHERE asset_id='T-A'"
    ).fetchone()[0] == 'dispatched'
    con.close()


def test_illegal_state_transition_rejected(tmp_path):
    db, cid = _registered_db(tmp_path)
    plan_id = plan(db, cid, 'reuse_first')['plan_id']
    con = connect(db)
    # 直接把容器跳到 dispatched，跳过洗消蓄冷
    con.execute(
        "UPDATE asset_container SET state='dispatched' WHERE asset_id='T-A'")
    con.commit()
    con.close()
    with pytest.raises(AssetError, match='illegal_transition'):
        confirm(db, plan_id)


def test_unknown_return_box_rejected(tmp_path):
    db = tmp_path / 'cold.db'
    seed_boxes(db)
    bad = load_contract()
    bad['returns'][0]['from_box'] = 'ZZZ'
    path = _write(tmp_path, bad)
    with pytest.raises(AssetError, match='unknown_return_box'):
        register(db, path)


def test_asset_module_never_reads_temperature_decision(tmp_path):
    db, cid = _registered_db(tmp_path)
    plan_id = plan(db, cid, 'reuse_first')['plan_id']
    confirm(db, plan_id)
    con = connect(db)
    # 资产流程不写冷链判定表
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0] == 0
    con.close()


def test_report_writes_json_and_markdown(tmp_path):
    db, cid = _registered_db(tmp_path)
    plan_id = plan(db, cid, 'reuse_first')['plan_id']
    confirm(db, plan_id)
    out = asset_report(db, plan_id, tmp_path / 'allocation.json')
    data = json.loads(out.read_text(encoding='utf-8'))
    assert data['case_id'] == cid
    md = out.with_suffix('.md').read_text(encoding='utf-8')
    assert '晚领 30 分钟' in md and 'T-A' in md and '来源证据' in md


def test_status_exposes_timeline_inventory_and_evidence(tmp_path):
    db, cid = _registered_db(tmp_path)
    plan_id = plan(db, cid, 'reuse_first')['plan_id']
    confirm(db, plan_id)
    status = case_status(db, cid)
    assert len(status['operations']) == 4
    assert status['plans'][0]['confirmed'] == 1
    assert any(h['state_to'] == 'dispatched' for h in status['history'])


def test_source_box_correction_changes_origin_evidence(tmp_path):
    db, cid = _registered_db(tmp_path)
    init(db, 'batch-1', 'E')
    changed = load_contract()
    changed['returns'][0]['from_box'] = 'E'
    path = _write(tmp_path, changed)
    register_versioned(db, path)
    con = connect(db)
    row = con.execute(
        'SELECT origin_id FROM asset_container WHERE case_version=2 AND asset_id=?',
        ('T-A',)).fetchone()
    assert row['origin_id'] == 'E'
    con.close()
