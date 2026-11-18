"""Exact offline scheduling engine for reusable insulated containers.

Pure functions over a normalized contract: no database, no wall clock, so the
same contract always yields the same plan.

Model
-----
Each eligible returned container is a two-operation job:
wash (washer, capacity 1) -> recharge (freezer slot, held for the whole
recharge). A freezer of capacity c is expanded into c identical slot machines,
so the whole shop becomes a set of capacity-1 machines whose state is a single
next-free minute offset. Time is discretized to integer minutes relative to a
fixed base instant.

The scheduler runs a layer-by-layer frontier DP over containers in stable ID
order. Within an identical processed-mask layer, states that are no earlier on
every machine and no earlier on every ready time are dominated and dropped;
identical machines are broken by symmetry (earliest index wins). Assignment to
needs is then solved by a memoized DFS with the caller-selected policy, and is
cached per distinct ready-time vector.
"""
import json
import math
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256

from .ingest import parse_time

# 真实作业顺序（state machine 与排程共同依赖）
STATE_ORDER = ('returned', 'washed', 'recharging', 'recharged', 'ready',
               'reserved', 'dispatched')
# 隔离/污染终态不允许跳过洗消
BLOCKED_STATES = ('quarantine', 'contaminated')
POLICIES = ('reuse_first', 'deadline_first')
# 离线精确规模上限
LIMITS = {'returns': 10, 'needs': 8, 'washers': 3, 'freezers': 3}
INF = 10 ** 9


class PlannerError(ValueError):
    """Invalid contract or infeasible planner input."""


@dataclass(frozen=True)
class Machine:
    index: int
    role: str                 # 'wash' | 'recharge'
    equip_id: str             # 洗消台或蓄冷柜 ID
    slot: int                 # 蓄冷柜槽位号；洗消台为 0
    win_start: int
    win_end: int
    duration: int


def _iso(dt):
    return dt.isoformat()


def _equipment_list(contract, single_key, list_key):
    if list_key in contract:
        items = contract[list_key]
    elif single_key in contract:
        items = [contract[single_key]]
    else:
        raise PlannerError(f'missing_equipment:{single_key}')
    if len(items) > LIMITS[list_key]:
        raise PlannerError(f'equipment_limit_exceeded:{list_key}')
    return items


def normalize(contract):
    """Parse and validate a contract dict into engine-ready structures."""
    if contract.get('case_id') is None:
        raise PlannerError('case_id_required')
    returns = contract.get('returns', [])
    needs = contract.get('needs', [])
    if len(returns) > LIMITS['returns']:
        raise PlannerError('returns_limit_exceeded')
    if len(needs) > LIMITS['needs']:
        raise PlannerError('needs_limit_exceeded')
    if len({r['asset_id'] for r in returns}) != len(returns):
        raise PlannerError('duplicate_asset_id')
    if len({n['id'] for n in needs}) != len(needs):
        raise PlannerError('duplicate_need_id')

    washers, freezers = [], []
    for item in _equipment_list(contract, 'washer', 'washers'):
        washers.append({'id': item['id'], 'start': parse_time(item['start']),
                        'end': parse_time(item['end']),
                        'minutes': int(item['minutes_per_asset']),
                        'capacity': 1})
    for item in _equipment_list(contract, 'freezer', 'freezers'):
        freezers.append({'id': item['id'], 'start': parse_time(item['start']),
                         'end': parse_time(item['end']),
                         'minutes': int(item['minutes_per_asset']),
                         'capacity': int(item['capacity'])})
    for w in washers + freezers:
        if w['end'] <= w['start'] or w['minutes'] <= 0:
            raise PlannerError(f"bad_window:{w['id']}")

    eligible, blocked = [], []
    for idx, item in enumerate(returns):
        available = parse_time(item['available'])
        condition = item.get('condition', 'wash_required')
        ref = f"returns[{idx}]"
        record = {'asset_id': item['asset_id'], 'from_box': item['from_box'],
                  'available': available, 'ref': ref}
        if condition == 'wash_required':
            eligible.append(record)
        elif condition == 'quarantine':
            inspection = item.get('inspection', 'pending')
            release = item.get('inspection_release')
            if inspection == 'passed' and release:
                record['inspection_release'] = parse_time(release)
                record['available'] = max(available, parse_time(release))
                eligible.append(record)
            else:
                record['blocked_reason'] = (
                    'inspection_failed' if inspection == 'failed'
                    else 'inspection_pending')
                blocked.append(record)
        elif condition == 'contaminated':
            record['blocked_reason'] = 'contaminated'
            blocked.append(record)
        else:
            raise PlannerError(f"unknown_condition:{condition}")

    parsed_needs = []
    for idx, item in enumerate(needs):
        parsed_needs.append({'id': item['id'], 'box_id': item['box_id'],
                             'deadline': parse_time(item['dispatch_by']),
                             'ref': f"needs[{idx}]"})
    purchase = contract.get('purchase') or {}
    purchase = {
        'available': parse_time(purchase['available']) if purchase.get('available') else None,
        'unit_cents': int(purchase.get('unit_cents', 0)),
        'max_units': int(purchase.get('max_units', 0)),
    }
    fees = {
        'wash_cents_per_asset': int(contract.get('wash_cents_per_asset', 0)),
        'late_cents_per_30_minutes': int(contract.get('late_cents_per_30_minutes', 0)),
    }
    return {
        'case_id': contract['case_id'],
        'eligible': tuple(sorted(eligible, key=lambda r: r['asset_id'])),
        'blocked': tuple(sorted(blocked, key=lambda r: r['asset_id'])),
        'needs': tuple(sorted(parsed_needs, key=lambda r: r['id'])),
        'washers': tuple(sorted(washers, key=lambda w: w['id'])),
        'freezers': tuple(sorted(freezers, key=lambda f: f['id'])),
        'purchase': purchase,
        'fees': fees,
    }


def _build_integer_model(ctx):
    """Discretize datetimes to minute offsets and expand freezer slots."""
    instants = []
    for w in ctx['washers']:
        instants += [w['start'], w['end']]
    for f in ctx['freezers']:
        instants += [f['start'], f['end']]
    for r in ctx['eligible']:
        instants.append(r['available'])
    for n in ctx['needs']:
        instants.append(n['deadline'])
    if ctx['purchase']['available'] is not None:
        instants.append(ctx['purchase']['available'])
    base = min(instants)

    def off(dt):
        return int((dt - base).total_seconds() // 60)

    machines, wash_idx, recharge_idx = [], [], []
    for w in ctx['washers']:
        m = Machine(len(machines), 'wash', w['id'], 0,
                    off(w['start']), off(w['end']), w['minutes'])
        wash_idx.append(m.index)
        machines.append(m)
    for f in ctx['freezers']:
        for slot in range(f['capacity']):
            m = Machine(len(machines), 'recharge', f['id'], slot,
                        off(f['start']), off(f['end']), f['minutes'])
            recharge_idx.append(m.index)
            machines.append(m)
    jobs = [{'asset_id': r['asset_id'], 'from_box': r['from_box'],
             'release': off(r['available']), 'ref': r['ref'],
             'inspection_release': r.get('inspection_release')}
            for r in ctx['eligible']]
    needs = [{'id': n['id'], 'box_id': n['box_id'],
              'deadline': off(n['deadline']), 'ref': n['ref']}
             for n in ctx['needs']]
    purchase = dict(ctx['purchase'])
    if purchase['available'] is not None:
        purchase['available'] = off(purchase['available'])
    return {'base': base, 'machines': tuple(machines),
            'wash_idx': tuple(wash_idx),
            'recharge_idx': tuple(recharge_idx),
            'jobs': jobs, 'needs': needs, 'purchase': purchase,
            'fees': ctx['fees']}


@dataclass(frozen=True)
class _WashState:
    free: tuple           # 各洗消台下一空闲分钟（按设备 ID 固定顺序）
    ops: tuple            # (asset_index, wash_equip_id, ws, we)


def _enumerate_wash_schedules(model):
    """阶段一：枚举全部可行的洗消排程（仅洗消台，容量 1）。

    按资产 ID 顺序分层 DFS；同洗消台组合下用组件支配剪枝（每台机器都不
    更晚的状态支配其余）。返回去重后的 (free, ops) 列表。
    """
    jobs = model['jobs']
    washers = [m for m in model['machines'] if m.role == 'wash']
    initial = tuple(m.win_start for m in washers)
    frontier = {initial: _WashState(initial, ())}

    for i, job in enumerate(jobs):
        nxt = {}

        def _wash_key(ops):
            # 先保留更多已洗消资产，再让前序（低 ID）资产的洗消结束更早，
            # 未洗消位用 INF 占位，保证同机器状态下 T-A 先于 T-B。
            ends = [INF] * len(jobs)
            for (idx, _e, _ws, we) in ops:
                ends[idx] = we
            return (-len(ops), tuple(ends))

        def accept(free, ops):
            old = nxt.get(free)
            if old is None or _wash_key(ops) < _wash_key(old.ops):
                nxt[free] = _WashState(free, ops)

        for free, st in frontier.items():
            # 跳过本只容器
            accept(free, st.ops)
            for wi, wm in enumerate(washers):
                ws = max(free[wi], job['release'], wm.win_start)
                we = ws + wm.duration
                if we > wm.win_end:
                    continue
                new_free = list(free)
                new_free[wi] = we
                accept(tuple(new_free),
                       st.ops + ((i, wm.equip_id, ws, we),))

        # 组件支配剪枝：A 的每台洗消台空闲都不晚于 B 且洗消数不少于 B
        keys = sorted(nxt)
        kept = []
        for k in keys:
            dominated = False
            for kk in kept:
                if all(kk[j] <= k[j] for j in range(len(k))) and \
                        len(nxt[kk].ops) >= len(nxt[k].ops):
                    dominated = True
                    break
            if not dominated:
                kept = [kk for kk in kept
                        if not (all(k[j] <= kk[j] for j in range(len(k)))
                                and len(nxt[k].ops) >= len(nxt[kk].ops))]
                kept.append(k)
        frontier = {k: nxt[k] for k in kept}
    return washers, list(frontier.values())


def _recharge_plan(model, wash_ops):
    """阶段二：给定洗消完成时间，求每只容器的最早可行蓄冷排程。

    蓄冷柜按容量展开为槽位，按资产 ID 顺序、每只选“能最早完成”的柜槽
    （并列取柜 ID、槽位最小者，保证确定性与稳定裁定）。任何一只无法在
    窗口内完成则该洗消排程不可行，返回 None。
    """
    jobs = model['jobs']
    freezers = [m for m in model['machines'] if m.role == 'recharge']
    # 槽位空闲时间；同柜槽位可互换，记录 (equip_id, slot)
    slot_free = {m.index: m.win_start for m in freezers}
    slot_meta = {m.index: (m.equip_id, m.slot, m.win_start, m.win_end,
                           m.duration) for m in freezers}
    by_equip = {}
    for m in freezers:
        by_equip.setdefault(m.equip_id, []).append(m.index)
    rec_ops = {}
    for (i, w_id, ws, we) in wash_ops:
        best = None  # (re_end, equip_id, slot, rs, machine_index)
        for equip_id, indices in sorted(by_equip.items()):
            for mi in sorted(indices, key=lambda x: slot_meta[x][1]):
                _eid, slot, win_start, win_end, duration = slot_meta[mi]
                rs = max(slot_free[mi], we, win_start)
                re_ = rs + duration
                if re_ > win_end:
                    continue
                cand = (re_, equip_id, slot, rs, mi)
                if best is None or cand[:3] < best[:3]:
                    best = cand
        if best is None:
            return None
        re_, equip_id, slot, rs, mi = best
        slot_free[mi] = re_
        rec_ops[i] = (equip_id, rs, re_)
    return rec_ops


def enumerate_schedules(ctx):
    """Two-phase exact wash->recharge enumeration.

    Phase 1 enumerates feasible washer schedules (small: capacity-1 washers
    only). Phase 2 deterministically expands each into its earliest feasible
    slotted recharge plan, so resource contention on the finite freezer is
    solved globally rather than by greedily handing out visible containers.
    Each item: {'job_ops', 'ready', 'mask'}.
    """
    model = _build_integer_model(ctx)
    jobs = model['jobs']
    _washers, wash_states = _enumerate_wash_schedules(model)

    seen, schedules = set(), []
    for wst in wash_states:
        rec_ops = _recharge_plan(model, wst.ops)
        if rec_ops is None:
            continue
        job_ops, ready, mask = {}, {}, 0
        for (i, w_id, ws, we) in wst.ops:
            r_id, rs, re_ = rec_ops[i]
            job_ops[i] = (w_id, ws, we, r_id, rs, re_)
            ready[jobs[i]['asset_id']] = re_
            mask |= 1 << i
        sig = tuple(sorted(ready.items()))
        if sig in seen:
            continue
        seen.add(sig)
        schedules.append({'job_ops': job_ops, 'ready': ready, 'mask': mask})
    schedules.sort(key=lambda s: tuple(sorted(
        (aid, t) for aid, t in s['ready'].items())))
    return model, schedules


def _late_fee_minutes(dispatch_min, deadline_min, fee_per_30):
    late_min = max(0, dispatch_min - deadline_min)
    if late_min == 0:
        return 0, 0
    return late_min, math.ceil(late_min / 30) * fee_per_30


def best_assignment(model, ready_map, policy):
    """Least-cost assignment of needs to ready returned + purchased units.

    Memoized DFS over (need index, returned bitmask, purchased count). Fee
    matrices are precomputed so each transition is O(1); fully tied records are
    decided deterministically by the per-need source vector (R=0, P=1, Z=2).
    """
    needs = model['needs']
    purchase = model['purchase']
    fee = model['fees']['late_cents_per_30_minutes']
    returned_ids = tuple(sorted(ready_map))
    n_returned = len(returned_ids)
    max_units = purchase['max_units']
    arrival = purchase['available']
    unit_cents = purchase['unit_cents']
    all_mask = (1 << n_returned) - 1

    # 预计算：每个需求 × 每只复用箱 / 采购箱的（迟到分钟，罚金）
    ret_fee = [[0] * n_returned for _ in needs]
    for i, need in enumerate(needs):
        for j, cid in enumerate(returned_ids):
            ret_fee[i][j] = _late_fee_minutes(
                ready_map[cid], need['deadline'], fee)
    buy_fee = [_late_fee_minutes(arrival, n['deadline'], fee)
               if arrival is not None else (0, 0) for n in needs]

    memo = {}
    empty = ((), (), 0, 0, 0, 0, 0, 0)  # labels, assignments, cover, ontime,
    #                                    purchases, purchase_cents, late_cents, late_min

    def dfs(i, used_mask, used_p):
        key = (i, used_mask, used_p)
        cached = memo.get(key)
        if cached is not None:
            return cached
        if i == len(needs):
            memo[key] = empty
            return empty
        candidates = []
        # 跳过本需求（稳定标签 Z 排在 R/P 之后）
        candidates.append((2, '', None, dfs(i + 1, used_mask, used_p)))
        avail = all_mask ^ (used_mask & all_mask)
        m = avail
        while m:
            bit = m & -m
            j = bit.bit_length() - 1
            m -= bit
            cid = returned_ids[j]
            late_min, late_cents = ret_fee[i][j]
            suffix = dfs(i + 1, used_mask | bit, used_p)
            candidates.append((0, cid, {
                'need_idx': i, 'asset_id': cid, 'source': 'returned',
                'dispatch': ready_map[cid], 'late_minutes': late_min,
                'late_cents': late_cents}, suffix))
        if used_p < max_units and arrival is not None:
            new_id = f"T-NEW-{used_p + 1}"
            late_min, late_cents = buy_fee[i]
            suffix = dfs(i + 1, used_mask, used_p + 1)
            candidates.append((1, new_id, {
                'need_idx': i, 'asset_id': new_id, 'source': 'purchased',
                'dispatch': arrival, 'late_minutes': late_min,
                'late_cents': late_cents}, suffix))

        records = []
        for code, cid, assignment, suffix in candidates:
            labels, assignments, cover, ontime, purchases, pcents, lcents, lmin = suffix
            if assignment is None:
                records.append(((('Z', ''),) + labels, assignments, cover,
                                ontime, purchases, pcents, lcents, lmin))
            else:
                is_buy = code == 1
                records.append((
                    ((('R' if code == 0 else 'P'), cid),) + labels,
                    (assignment,) + assignments, cover + 1,
                    ontime + (1 if assignment['late_minutes'] == 0 else 0),
                    purchases + (1 if is_buy else 0),
                    pcents + (unit_cents if is_buy else 0),
                    lcents + assignment['late_cents'],
                    lmin + assignment['late_minutes']))

        def rank(rec):
            labels = rec[0]
            reuse_vector = tuple(
                0 if lab[0] == 'R' else (1 if lab[0] == 'P' else 2)
                for lab in labels)
            cover, ontime, purchases, pcents, lcents = rec[2], rec[3], rec[4], rec[5], rec[6]
            if policy == 'reuse_first':
                return (-cover, purchases, pcents + lcents, -ontime,
                        reuse_vector, labels)
            return (-cover, -ontime, pcents + lcents, purchases,
                    reuse_vector, labels)

        best = min(records, key=rank)
        memo[key] = best
        return best

    labels, assignments, cover, ontime, purchases, pcents, lcents, _lmin = \
        dfs(0, 0, 0)
    return {'labels': labels, 'assignments': assignments, 'coverage': cover,
            'ontime': ontime, 'purchases': purchases,
            'purchase_cents': pcents, 'late_cents': lcents,
            'late_minutes': sum(a['late_minutes'] for a in assignments)}

def _timeline_for_returned(record, op, final_state, source_ref):
    timeline = [{'stage': 'returned', 'at': _iso(record['available']),
                 'equipment': None, 'source_ref': source_ref}]
    if record.get('inspection_release'):
        timeline.append({'stage': 'quarantine_released',
                         'at': _iso(record['inspection_release']),
                         'equipment': None, 'source_ref': source_ref})
    if op is None:
        return timeline
    timeline += [
        {'stage': 'wash_start', 'at': _iso(op['wash_start']),
         'equipment': op['washer'], 'source_ref': source_ref},
        {'stage': 'washed', 'at': _iso(op['wash_end']),
         'equipment': op['washer'], 'source_ref': source_ref},
        {'stage': 'recharge_start', 'at': _iso(op['recharge_start']),
         'equipment': op['freezer'], 'source_ref': source_ref},
        {'stage': 'recharging', 'at': _iso(op['recharge_start']),
         'equipment': op['freezer'], 'source_ref': source_ref},
        {'stage': 'recharged', 'at': _iso(op['recharge_end']),
         'equipment': op['freezer'], 'source_ref': source_ref},
        {'stage': 'ready', 'at': _iso(op['ready']),
         'equipment': None, 'source_ref': source_ref},
    ]
    if final_state == 'reserved':
        timeline.append({'stage': 'reserved', 'at': _iso(op['ready']),
                         'equipment': None, 'source_ref': source_ref})
    if final_state == 'dispatched':
        timeline.append({'stage': 'dispatched', 'at': _iso(op['ready']),
                         'equipment': None, 'source_ref': source_ref})
    return timeline


def build_plan(contract, policy):
    if policy not in POLICIES:
        raise PlannerError(f'unknown_policy:{policy}')
    ctx = normalize(contract)
    if not ctx['washers'] or not ctx['freezers']:
        raise PlannerError('equipment_required')
    model, schedules = enumerate_schedules(ctx)
    base = model['base']

    def back(minute):
        return base + timedelta(minutes=minute)

    wash_fee = ctx['fees']['wash_cents_per_asset']
    assignment_cache = {}
    candidates = []
    for sched in schedules:
        cache_key = tuple(sorted(sched['ready'].items()))
        if cache_key not in assignment_cache:
            assignment_cache[cache_key] = best_assignment(
                model, sched['ready'], policy)
        rec = assignment_cache[cache_key]
        wash_count = bin(sched['mask']).count('1')
        wash_cents = wash_count * wash_fee
        total = wash_cents + rec['purchase_cents'] + rec['late_cents']
        candidates.append((sched, rec, wash_count, wash_cents, total, cache_key))

    def global_rank(item):
        sched, rec, wash_count, wash_cents, total, cache_key = item
        reuse_vector = tuple(0 if lab[0] == 'R' else (1 if lab[0] == 'P' else 2)
                             for lab in rec['labels'])
        schedule_vector = tuple(sorted(
            (aid, t) for aid, t in sched['ready'].items()))
        if policy == 'reuse_first':
            return (-rec['coverage'], rec['purchases'], total,
                    -rec['ontime'], reuse_vector, rec['labels'],
                    schedule_vector)
        return (-rec['coverage'], -rec['ontime'], total, rec['purchases'],
                reuse_vector, rec['labels'], schedule_vector)

    sched, rec, wash_count, wash_cents, total, _ = min(candidates, key=global_rank)

    assigned_assets = {a['asset_id'] for a in rec['assignments']}
    containers, slot_locks, evidence = [], [], []
    job_index = {j['asset_id']: idx for idx, j in enumerate(model['jobs'])}
    for record in ctx['eligible']:
        cid = record['asset_id']
        source_ref = f"{ctx['case_id']}/{model['jobs'][job_index[cid]]['ref']}"
        int_op = sched['job_ops'].get(job_index[cid])
        op = None
        if int_op is not None:
            w_id, ws, we, r_id, rs, re_ = int_op
            op = {'washer': w_id,
                  'wash_start': back(ws), 'wash_end': back(we),
                  'freezer': r_id,
                  'recharge_start': back(rs), 'recharge_end': back(re_),
                  'ready': back(re_)}
        if cid in assigned_assets:
            final_state = 'dispatched'
        elif op is not None:
            final_state = 'ready'
        else:
            final_state = 'returned'
        containers.append({
            'asset_id': cid, 'kind': 'returned', 'origin_box': record['from_box'],
            'state': final_state, 'available': _iso(record['available']),
            'operations': None if op is None else {
                'wash': {'equipment': op['washer'],
                         'start': _iso(op['wash_start']),
                         'end': _iso(op['wash_end'])},
                'recharge': {'equipment': op['freezer'],
                             'start': _iso(op['recharge_start']),
                             'end': _iso(op['recharge_end'])},
                'ready_at': _iso(op['ready'])},
            'timeline': _timeline_for_returned(record, op, final_state, source_ref),
        })
        if op is not None:
            slot_locks += [
                {'equipment': op['washer'], 'asset_id': cid,
                 'start': _iso(op['wash_start']), 'end': _iso(op['wash_end']),
                 'stage': 'wash'},
                {'equipment': op['freezer'], 'asset_id': cid,
                 'start': _iso(op['recharge_start']),
                 'end': _iso(op['recharge_end']), 'stage': 'recharge'}]
        evidence.append({'subject': cid, 'object_kind': 'contract_return',
                         'object_ref': source_ref,
                         'detail': f"from_box={record['from_box']} "
                                   f"available={_iso(record['available'])}"})
    for record in ctx['blocked']:
        cid = record['asset_id']
        source_ref = f"{ctx['case_id']}/{record['ref']}"
        state = ('contaminated' if record['blocked_reason'] == 'contaminated'
                 else 'quarantine')
        containers.append({
            'asset_id': cid, 'kind': 'returned', 'origin_box': record['from_box'],
            'state': state, 'available': _iso(record['available']),
            'blocked_reason': record['blocked_reason'], 'operations': None,
            'timeline': [{'stage': state, 'at': _iso(record['available']),
                          'equipment': None, 'source_ref': source_ref}]})
        evidence.append({'subject': cid, 'object_kind': 'contract_return',
                         'object_ref': source_ref,
                         'detail': f"blocked={record['blocked_reason']}"})

    purchases = []
    need_by_idx = {idx: n for idx, n in enumerate(ctx['needs'])}
    assignments = []
    for a in rec['assignments']:
        need = need_by_idx[a['need_idx']]
        if a['source'] == 'purchased':
            purchases.append({'asset_id': a['asset_id'],
                              'unit_cents': ctx['purchase']['unit_cents'],
                              'available_at': _iso(ctx['purchase']['available'])})
            containers.append({
                'asset_id': a['asset_id'], 'kind': 'purchased',
                'origin_box': None, 'state': 'dispatched',
                'available': _iso(ctx['purchase']['available']),
                'operations': None,
                'timeline': [
                    {'stage': 'ready',
                     'at': _iso(ctx['purchase']['available']),
                     'equipment': None,
                     'source_ref': f"{ctx['case_id']}/purchase"},
                    {'stage': 'dispatched', 'at': _iso(back(a['dispatch'])),
                     'equipment': None,
                     'source_ref': f"{ctx['case_id']}/purchase"}]})
            evidence.append({'subject': a['asset_id'],
                             'object_kind': 'purchase_contract',
                             'object_ref': f"{ctx['case_id']}/purchase",
                             'detail': f"arrival={_iso(ctx['purchase']['available'])}"})
        on_time = a['late_minutes'] == 0
        assignments.append({
            'need_id': need['id'], 'box_id': need['box_id'],
            'deadline': _iso(need['deadline']), 'asset_id': a['asset_id'],
            'source': a['source'],
            'dispatched_at': _iso(back(a['dispatch'])),
            'on_time': on_time, 'late_minutes': a['late_minutes'],
            'late_cents': a['late_cents'],
            'late_note': None if on_time else _late_note(need, a)})
    assigned_need_ids = {a['need_id'] for a in assignments}
    unmet = [{'need_id': n['id'], 'box_id': n['box_id'],
              'deadline': _iso(n['deadline'])}
             for n in ctx['needs'] if n['id'] not in assigned_need_ids]

    for n in ctx['needs']:
        evidence.append({'subject': n['id'], 'object_kind': 'contract_need',
                         'object_ref': f"{ctx['case_id']}/{n['ref']}",
                         'detail': f"box_id={n['box_id']} deadline={_iso(n['deadline'])}"})
    for w in ctx['washers']:
        evidence.append({'subject': w['id'], 'object_kind': 'equipment_window',
                         'object_ref': f"{ctx['case_id']}/washer",
                         'detail': f"{_iso(w['start'])}~{_iso(w['end'])} minutes={w['minutes']}"})
    for f in ctx['freezers']:
        evidence.append({'subject': f['id'], 'object_kind': 'equipment_window',
                         'object_ref': f"{ctx['case_id']}/freezer",
                         'detail': f"{_iso(f['start'])}~{_iso(f['end'])} cap={f['capacity']} minutes={f['minutes']}"})

    occupied = sorted(c['asset_id'] for c in containers
                      if c['state'] in ('reserved', 'dispatched'))
    plan = {
        'case_id': ctx['case_id'],
        'policy': policy,
        'limits': dict(LIMITS),
        'containers': containers,
        'assignments': sorted(assignments, key=lambda a: a['need_id']),
        'unmet_needs': unmet,
        'purchases': purchases,
        'slot_locks': sorted(slot_locks,
                             key=lambda x: (x['start'], x['equipment'], x['asset_id'])),
        'inventory': {
            'remaining_ready': sorted(c['asset_id'] for c in containers
                                      if c['state'] == 'ready'),
            'occupied': occupied,
            'unprocessed_returned': sorted(
                c['asset_id'] for c in containers
                if c['kind'] == 'returned' and c['state'] == 'returned'),
            'quarantine': sorted(
                c['asset_id'] for c in containers if c['state'] == 'quarantine'),
            'contaminated': sorted(
                c['asset_id'] for c in containers if c['state'] == 'contaminated'),
            'purchase_quota_used': rec['purchases'],
            'purchase_quota_remaining': max(
                0, ctx['purchase']['max_units'] - rec['purchases']),
        },
        'costs': {
            'wash_count': wash_count,
            'wash_cents': wash_cents,
            'purchase_count': rec['purchases'],
            'purchase_cents': rec['purchase_cents'],
            'late_need_count': sum(1 for a in assignments if not a['on_time']),
            'late_cents': rec['late_cents'],
            'total_cents': total,
        },
        'evidence': evidence,
    }
    plan['digest'] = sha256(json.dumps(
        plan, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return plan


def _late_note(need, assignment):
    return (f"晚领 {assignment['late_minutes']} 分钟，"
            f"罚金 {assignment['late_cents']} 分，"
            f"实际派给 {assignment['asset_id']}（来源 {assignment['source']}）")
