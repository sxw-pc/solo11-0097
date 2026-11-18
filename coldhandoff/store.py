import sqlite3
from pathlib import Path

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS source_file(id INTEGER PRIMARY KEY, name TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, raw BLOB NOT NULL DEFAULT X'');
CREATE TABLE IF NOT EXISTS batch(id TEXT PRIMARY KEY, min_temp REAL NOT NULL, max_temp REAL NOT NULL, max_excursion_min INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS box(id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batch(id));
CREATE TABLE IF NOT EXISTS raw_event(id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL REFERENCES source_file(id), line_no INTEGER NOT NULL, kind TEXT NOT NULL, device TEXT NOT NULL, seq INTEGER NOT NULL, box_id TEXT, event_time TEXT NOT NULL, payload TEXT NOT NULL, hash TEXT NOT NULL, UNIQUE(source_id,line_no));
CREATE TABLE IF NOT EXISTS issue(id INTEGER PRIMARY KEY, event_id INTEGER REFERENCES raw_event(id), code TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run(id TEXT PRIMARY KEY, rules_version TEXT NOT NULL, source_digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES run(id), subject_id TEXT NOT NULL, source_id INTEGER REFERENCES source_file(id), object_kind TEXT NOT NULL, object_id INTEGER NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS decision(box_id TEXT PRIMARY KEY REFERENCES box(id), result TEXT NOT NULL, detail TEXT NOT NULL, rules_version TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES run(id));

-- 可复用保温周转箱：台账版本化，合同/源盒更正生成新版本而不覆盖旧审计
CREATE TABLE IF NOT EXISTS asset_case(id TEXT NOT NULL, version INTEGER NOT NULL, contract_sha256 TEXT NOT NULL, contract_json TEXT NOT NULL, box_digest TEXT NOT NULL, supersedes_version INTEGER, created_at TEXT NOT NULL, PRIMARY KEY(id,version));
CREATE TABLE IF NOT EXISTS asset_container(asset_id TEXT NOT NULL, case_id TEXT NOT NULL, case_version INTEGER NOT NULL, kind TEXT NOT NULL, origin_kind TEXT NOT NULL, origin_id TEXT NOT NULL, state TEXT NOT NULL, available_at TEXT, blocked_reason TEXT, inspection_release_at TEXT, PRIMARY KEY(asset_id,case_id,case_version));
CREATE TABLE IF NOT EXISTS asset_need(id TEXT NOT NULL, case_id TEXT NOT NULL, case_version INTEGER NOT NULL, box_id TEXT NOT NULL, dispatch_by TEXT NOT NULL, PRIMARY KEY(id,case_id,case_version));
CREATE TABLE IF NOT EXISTS asset_equipment(equip_id TEXT NOT NULL, case_id TEXT NOT NULL, case_version INTEGER NOT NULL, kind TEXT NOT NULL, window_start TEXT NOT NULL, window_end TEXT NOT NULL, minutes_per_asset INTEGER NOT NULL, capacity INTEGER NOT NULL, PRIMARY KEY(equip_id,case_id,case_version));
CREATE TABLE IF NOT EXISTS asset_operation(op_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, case_version INTEGER NOT NULL, asset_id TEXT NOT NULL, stage TEXT NOT NULL, equip_id TEXT, source_ref TEXT NOT NULL, start_at TEXT NOT NULL, end_at TEXT NOT NULL, state_after TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS asset_state_history(hist_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, case_version INTEGER NOT NULL, asset_id TEXT NOT NULL, state_from TEXT, state_to TEXT NOT NULL, at_time TEXT NOT NULL, reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS asset_plan(plan_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, case_version INTEGER NOT NULL, policy TEXT NOT NULL, plan_digest TEXT NOT NULL, plan_json TEXT NOT NULL, confirmed INTEGER NOT NULL DEFAULT 0, confirmed_at TEXT, UNIQUE(case_id,case_version,policy));
CREATE TABLE IF NOT EXISTS asset_assignment(id INTEGER PRIMARY KEY AUTOINCREMENT, plan_id TEXT NOT NULL REFERENCES asset_plan(plan_id), need_id TEXT NOT NULL, asset_id TEXT, source TEXT NOT NULL, dispatched_at TEXT, on_time INTEGER NOT NULL, late_minutes INTEGER NOT NULL, late_cents INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS asset_purchase(purchase_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES asset_plan(plan_id), asset_id TEXT NOT NULL, unit_cents INTEGER NOT NULL, available_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS asset_slot_lock(lock_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, case_id TEXT NOT NULL, case_version INTEGER NOT NULL, equip_id TEXT NOT NULL, asset_id TEXT NOT NULL, start_at TEXT NOT NULL, end_at TEXT NOT NULL, UNIQUE(equip_id,start_at,end_at,asset_id));
CREATE INDEX IF NOT EXISTS idx_slot_plan ON asset_slot_lock(plan_id);
-- 同一需求在同一案例版本上只允许一份已确认领用（跨表条件由 confirm 事务校验）
CREATE INDEX IF NOT EXISTS idx_assignment_need ON asset_assignment(plan_id,need_id);
"""

def connect(path):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(path)
    db.row_factory=sqlite3.Row
    db.executescript(SCHEMA)
    db.execute('PRAGMA foreign_keys=ON')
    return db
