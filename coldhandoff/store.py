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
CREATE TABLE IF NOT EXISTS thermal_case(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
"""

def connect(path):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(path)
    db.row_factory=sqlite3.Row
    db.executescript(SCHEMA)
    return db
